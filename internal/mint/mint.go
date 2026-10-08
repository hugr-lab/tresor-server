// Package mint obtains tokens for a caller at its identity provider (specs/010): RFC 8693 token exchange of
// the caller's token for a downstream audience, and refreshes. It never logs or returns a token in an error.
//
// Taken over from tresor's reference server at 6133d0d (MIT, the same owner; see NOTICE). specs/NNN here are
// tresor's specs; spec NNN (with a space) are this repository's.
package mint

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/hugr-lab/tresor-server/internal/telemetry"
)

// sharedHTTP is every mint's client: one connection pool, bounded requests.
var sharedHTTP = &http.Client{Timeout: timeout}

const (
	accessTokenType  = "urn:ietf:params:oauth:token-type:access_token"
	refreshTokenType = "urn:ietf:params:oauth:token-type:refresh_token"
	timeout          = 15 * time.Second
)

// Client is the service's own confidential client at one issuer's token endpoint.
type Client struct {
	TokenURL string
	Auth     ClientAuth // how the client logs in: a secret, or an assertion (spec 006)
	// Grant is the exchange's grant: token_exchange (RFC 8693, the default) or on_behalf_of (Entra; spec 013)
	Grant string
	HTTP  *http.Client // nil: a client bounded by the timeout
	Now   func() time.Time
}

// ClientAuth puts the client's authentication into a token request's form.
type ClientAuth interface {
	Apply(ctx context.Context, form url.Values, tokenURL string) error
}

// SecretAuth is client_secret_post, as every tresor flow.
type SecretAuth struct{ ID, Secret string }

func (a SecretAuth) Apply(_ context.Context, form url.Values, _ string) error {
	form.Set("client_id", a.ID)
	form.Set("client_secret", a.Secret)
	return nil
}

// AssertionAuth is a client assertion (RFC 7523, jwt-bearer): a platform identity's token, or a JWT the
// service signs (spec 006). Assertion makes one per request; tokenURL is there for an IdP that wants it as the
// assertion's audience.
type AssertionAuth struct {
	ID        string
	Assertion func(ctx context.Context, tokenURL string) (string, error)
	// OmitID leaves client_id out of the request (RFC 7523 makes it optional): Keycloak's federated client
	// authentication refuses one that is not the assertion's sub, a ServiceAccount's name
	OmitID bool
}

func (a AssertionAuth) Apply(ctx context.Context, form url.Values, tokenURL string) error {
	assertion, err := a.Assertion(ctx, tokenURL)
	if err != nil {
		return err
	}
	if !a.OmitID {
		form.Set("client_id", a.ID)
	}
	form.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	form.Set("client_assertion", assertion)
	return nil
}

// Token is a minted access token, and the refresh token that renews it when one was asked for.
type Token struct {
	Access  string
	Refresh string
	Expiry  time.Time // zero: the IdP named none
}

// Error is the IdP's refusal: its code (invalid_grant: the user's session is over) and a description with
// no token in it.
type Error struct {
	Code        string
	Description string
	Status      int // the HTTP status; 0 when the IdP did not answer (Code "unreachable")
}

// Transient: the IdP did not answer, or failed (5xx) - worth another try, unlike a refusal.
func (e *Error) Transient() bool { return e.Status == 0 || e.Status >= 500 }

func (e *Error) Error() string {
	if e.Description == "" {
		return e.Code
	}
	return e.Code + ": " + e.Description
}

// ClientRefused: the IdP does not accept the service's own client (spec 017) - a secret wrong or expired, a
// federated credential that does not match, an app not found or not allowed to exchange. The operator's to fix:
// it says nothing of the user.
func (e *Error) ClientRefused() bool {
	return e.Code == "invalid_client" || e.Code == "unauthorized_client"
}

// IsClientRefused: err is the IdP refusing the service's own client.
func IsClientRefused(err error) bool {
	var e *Error
	return errors.As(err, &e) && e.ClientRefused()
}

// IsInvalidGrant: the refresh token (or the subject token) is dead - the user's IdP session ended.
func IsInvalidGrant(err error) bool {
	var e *Error
	return errors.As(err, &e) && e.Code == "invalid_grant"
}

// IsUnsupported: the IdP does not issue refresh tokens by exchange - Keycloak names requested_token_type,
// ZITADEL answers TypeNotSupported (spec 006). The service then mints access tokens only.
func IsUnsupported(err error) bool {
	var e *Error
	if !errors.As(err, &e) {
		return false
	}
	switch e.Code {
	case "unsupported_token_type":
		return true
	case "invalid_request":
		return strings.Contains(e.Description, "requested_token_type") || strings.Contains(e.Description, "TypeNotSupported")
	}
	return false
}

// Exchange trades `subject` (an access token issued for this service) for one meant for `audience`; with
// `withRefresh` a refresh token too (Keycloak issues one only when asked with requested_token_type).
func (c *Client) Exchange(ctx context.Context, subject, audience, scope string, withRefresh bool) (*Token, error) {
	if subject == "" || audience == "" {
		return nil, &Error{Code: "invalid_request", Description: "a subject token and an audience are required"}
	}
	if c.Grant == "on_behalf_of" {
		return c.onBehalfOf(ctx, subject, audience, scope, withRefresh)
	}
	requested := accessTokenType
	if withRefresh {
		requested = refreshTokenType
	}
	form := url.Values{
		"grant_type":           {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"subject_token":        {subject},
		"subject_token_type":   {accessTokenType},
		"requested_token_type": {requested},
		"audience":             {audience},
	}
	if scope != "" {
		form.Set("scope", scope)
	}
	return c.post(ctx, form, subject, withRefresh)
}

// onBehalfOf is Entra's exchange (spec 013): the caller's token as a JWT bearer assertion, for a scope - the
// secret's, or the audience's .default; offline_access when a refresh token is wanted.
func (c *Client) onBehalfOf(ctx context.Context, subject, audience, scope string, withRefresh bool) (*Token, error) {
	scope = oboScope(audience, scope, withRefresh)
	form := url.Values{
		"grant_type":          {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":           {subject},
		"requested_token_use": {"on_behalf_of"},
		"scope":               {scope},
	}
	return c.post(ctx, form, subject, withRefresh)
}

// oboScope is what an OBO request, and its refresh, ask for: the secret's scope or the audience's .default, with
// offline_access for a refresh token.
func oboScope(audience, scope string, withRefresh bool) string {
	if scope == "" {
		scope = strings.TrimSuffix(audience, "/") + "/.default"
	}
	if withRefresh && !slices.Contains(strings.Fields(scope), "offline_access") {
		scope += " offline_access"
	}
	return scope
}

// aadsts is an Entra error's code, at the start of its description.
var aadsts = regexp.MustCompile(`^AADSTS\d{4,8}`)

// Refresh renews a token from its refresh token; a rotated refresh token comes back, or the old one stays. An
// OBO token's refresh names its scope again (spec 013): an Entra refresh token covers every resource consented,
// and the scope says which one the new token is for.
func (c *Client) Refresh(ctx context.Context, refresh, audience, scope string) (*Token, error) {
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}}
	if c.Grant == "on_behalf_of" {
		form.Set("scope", oboScope(audience, scope, true))
	}
	token, err := c.post(ctx, form, refresh, true)
	if err == nil && token.Refresh == "" {
		token.Refresh = refresh // RFC 6749 §6: the IdP may keep the old one
	}
	return token, err
}

func (c *Client) post(ctx context.Context, form url.Values, presented string, keepRefresh bool) (_ *Token, err error) {
	// spec 005: the IdP's time, under tresor's trace; never a token, never the error's text
	ctx, span := telemetry.Tracer().Start(ctx, "idp.token", trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(attribute.String("tresor.grant_type", form.Get("grant_type"))))
	defer func() {
		if err != nil {
			span.SetStatus(codes.Error, "failed")
		}
		span.End()
	}()
	if c.Auth == nil {
		return nil, &Error{Code: "client_auth", Description: "no client authentication is configured"}
	}
	if err := c.Auth.Apply(ctx, form, c.TokenURL); err != nil {
		// no assertion, no request: never a fallback to no authentication. The cause names a source, never an
		// assertion or a key (clientauth's errors)
		return nil, &Error{Code: "client_auth", Description: bounded("the service could not authenticate to the identity provider: "+err.Error(), 300)}
	}
	httpClient := c.HTTP
	if httpClient == nil {
		httpClient = sharedHTTP
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("the token endpoint: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	res, err := httpClient.Do(req)
	if err != nil {
		// the transport's error could name the URL only: a fixed text
		return nil, &Error{Code: "unreachable", Description: "the identity provider is not reachable"}
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	var answer struct {
		AccessToken     string `json:"access_token"`
		RefreshToken    string `json:"refresh_token"`
		ExpiresIn       int64  `json:"expires_in"`
		IssuedTokenType string `json:"issued_token_type"`
		TokenType       string `json:"token_type"`
		Error           string `json:"error"`
		ErrorDesc       string `json:"error_description"`
	}
	_ = json.Unmarshal(body, &answer)
	if res.StatusCode/100 != 2 {
		code := answer.Error
		if code == "" {
			code = fmt.Sprintf("http_%d", res.StatusCode)
		}
		// redacted before it is cut: a cut must not leave part of the token behind
		desc := answer.ErrorDesc
		if m := aadsts.FindString(desc); m != "" {
			desc = m // Entra's code is what to look up; the rest of its message (trace ids, names) is not kept
		} else if c.Grant == "on_behalf_of" {
			desc = "" // from Entra with no code: its message may name a person or an app
		}
		return nil, &Error{Code: bounded(code, 64), Description: bounded(redact(desc, presented), 300),
			Status: res.StatusCode}
	}
	// only an access token is taken for one: RFC 8693's strict shape (a refresh token in access_token,
	// token_type N_A), or any other issued type, is refused
	typeOK := answer.IssuedTokenType == "" || answer.IssuedTokenType == accessTokenType ||
		(keepRefresh && answer.IssuedTokenType == refreshTokenType && answer.RefreshToken != "" &&
			answer.RefreshToken != answer.AccessToken)
	if answer.AccessToken == "" || !typeOK || strings.EqualFold(answer.TokenType, "N_A") {
		return nil, &Error{Code: "invalid_token_type", Description: "the identity provider answered with no access token",
			Status: res.StatusCode}
	}
	now := time.Now
	if c.Now != nil {
		now = c.Now
	}
	token := &Token{Access: answer.AccessToken}
	if keepRefresh {
		token.Refresh = answer.RefreshToken
	}
	if answer.ExpiresIn > 0 {
		if answer.ExpiresIn > 366*24*3600 {
			answer.ExpiresIn = 366 * 24 * 3600
		}
		token.Expiry = now().Add(time.Duration(answer.ExpiresIn) * time.Second)
	}
	return token, nil
}

// bounded keeps an IdP's text printable and short.
func bounded(text string, max int) string {
	var out strings.Builder
	for _, r := range text {
		if out.Len() >= max {
			break
		}
		if r < 0x20 || r == 0x7f {
			r = '?'
		}
		out.WriteRune(r)
	}
	return out.String()
}

// redact keeps a credential the caller presented out of an error, even when the IdP quotes it back.
func redact(text, presented string) string {
	if len(presented) < 8 { // no credential is this short; a short value would cut ordinary words apart
		return text
	}
	return strings.ReplaceAll(text, presented, "<redacted>")
}

// Audiences reads a JWT's `aud` without verifying it (the token came from the IdP over its own channel) - to
// check where a minted token is meant to go; isJWT false for an opaque token.
func Audiences(token string) (auds []string, isJWT bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, false
	}
	data, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, false
	}
	var claims struct {
		Aud any `json:"aud"`
	}
	if json.Unmarshal(data, &claims) != nil {
		return nil, false
	}
	switch aud := claims.Aud.(type) {
	case string:
		return []string{aud}, true
	case []any:
		for _, a := range aud {
			if s, ok := a.(string); ok {
				auds = append(auds, s)
			}
		}
	}
	return auds, true
}
