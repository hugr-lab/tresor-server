// Package login logs the service in to another service (spec 023, `tresor_service_login`): with a user and a
// password, an OAuth2 client, or any login and refresh a jq mapping describes - and keeps what it gets, so a
// secret serves one field of it (an access token, a session id), never the rest. Nothing it reads or sends is
// logged or put in an error: an error names the step and the status, never a value.
package login

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/itchyny/gojq"
)

// Type is the secret type of a login: never served to a lookup.
const Type = "tresor_service_login"

const (
	callTimeout = 10 * time.Second
	maxBody     = 1 << 20 // a response's body, at most
	jqTimeout   = 100 * time.Millisecond
	defaultTTL  = 10 * time.Minute // a result that names no expiry
)

// Flows a login may use.
const (
	FlowBasic             = "basic"
	FlowClientCredentials = "oauth2_client_credentials"
	FlowPassword          = "oauth2_password"
	FlowCustom            = "custom"
)

// Hidden are fields never served: what renews a login stays in the service.
var Hidden = map[string]bool{"refresh_token": true}

// inputs are the parameters that may hold a secret (a reference, or written sealed): resolved before a login.
var inputs = []string{"username", "password", "client_id", "client_secret"}

// Spec is a login, from its secret's params and scope.
type Spec struct {
	Flow                                       string
	Scope                                      []string // base URLs: where it calls, and where its fields may go
	Username, Password, ClientID, ClientSecret string
	TokenURL, OAuthScope                       string
	LoginURL, LoginMethod, LoginRequest        string
	LoginResponse, ContentType                 string
	RefreshURL, RefreshMethod                  string
	RefreshRequest, RefreshResponse            string
	TTL                                        time.Duration
	Subject                                    string // a login for one user: their subject: principal
}

// Parse reads a login's params (strings; references resolved already, or placeholders at a write).
func Parse(params map[string]string, scope []string) (*Spec, error) {
	s := &Spec{Flow: params["flow"], Scope: scope, Username: params["username"], Password: params["password"],
		ClientID: params["client_id"], ClientSecret: params["client_secret"], TokenURL: params["token_url"],
		OAuthScope: params["scope"], LoginURL: params["login_url"], LoginMethod: strings.ToUpper(params["login_method"]),
		LoginRequest: params["login_request"], LoginResponse: params["login_response"],
		ContentType: params["content_type"], RefreshURL: params["refresh_url"],
		RefreshMethod: strings.ToUpper(params["refresh_method"]), RefreshRequest: params["refresh_request"],
		RefreshResponse: params["refresh_response"], Subject: params["subject"]}
	known := map[string]bool{"flow": true, "username": true, "password": true, "client_id": true,
		"client_secret": true, "token_url": true, "scope": true, "login_url": true, "login_method": true,
		"login_request": true, "login_response": true, "content_type": true, "refresh_url": true,
		"refresh_method": true, "refresh_request": true, "refresh_response": true, "ttl": true, "subject": true}
	for k := range params {
		if !known[k] {
			return nil, fmt.Errorf("a login has no parameter %q", k)
		}
	}
	if len(scope) == 0 {
		return nil, errors.New("a login's scope names the base URLs it may call")
	}
	for _, base := range scope {
		if u, err := url.Parse(base); err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
			return nil, errors.New("a login's scope is base URLs (https://host[/path])")
		}
	}
	if t := params["ttl"]; t != "" {
		d, err := time.ParseDuration(t)
		if err != nil || d <= 0 || d > 24*time.Hour {
			return nil, errors.New("a login's ttl is a duration up to 24h")
		}
		s.TTL = d
	}
	if s.Subject != "" && !strings.HasPrefix(s.Subject, "subject:") {
		return nil, errors.New("a login's subject is a user's subject: principal")
	}
	switch s.Flow {
	case FlowBasic:
		if s.Username == "" || s.Password == "" {
			return nil, errors.New("a basic login has a username and a password")
		}
	case FlowClientCredentials:
		if s.TokenURL == "" || s.ClientID == "" || s.ClientSecret == "" {
			return nil, errors.New("an oauth2_client_credentials login has a token_url, a client_id and a client_secret")
		}
	case FlowPassword:
		if s.TokenURL == "" || s.Username == "" || s.Password == "" {
			return nil, errors.New("an oauth2_password login has a token_url, a username and a password")
		}
	case FlowCustom:
		if s.LoginURL == "" || s.LoginResponse == "" {
			return nil, errors.New("a custom login has a login_url and a login_response")
		}
		for _, m := range []string{s.LoginMethod, s.RefreshMethod} {
			if m != "" && m != http.MethodPost && m != http.MethodGet && m != http.MethodPut {
				return nil, errors.New("a login's method is POST, GET or PUT")
			}
		}
		if (s.RefreshURL == "") != (s.RefreshResponse == "") {
			return nil, errors.New("a login's refresh has a refresh_url and a refresh_response")
		}
		for _, src := range []string{s.LoginRequest, s.LoginResponse, s.RefreshRequest, s.RefreshResponse} {
			if src == "" {
				continue
			}
			if _, err := compile(src); err != nil {
				return nil, fmt.Errorf("a login's jq does not parse: %v", err)
			}
		}
	case "":
		return nil, errors.New("a login names its flow (basic, oauth2_client_credentials, oauth2_password, custom)")
	default:
		return nil, fmt.Errorf("a login's flow %q is not one of basic, oauth2_client_credentials, oauth2_password, custom", s.Flow)
	}
	if s.ContentType != "" && s.ContentType != "json" && s.ContentType != "form" {
		return nil, errors.New("a login's content_type is json or form")
	}
	return s, nil
}

// Inputs are the parameters that may hold a secret: a reference, or a claim's interpolation.
func Inputs() []string { return inputs }

// URLs are the URLs a login calls.
func (s *Spec) URLs() []string {
	var out []string
	for _, u := range []string{s.TokenURL, s.LoginURL, s.RefreshURL} {
		if u != "" {
			out = append(out, u)
		}
	}
	return out
}

// Covers says whether a secret's scope is within the login's: every entry under one of its base URLs.
func (s *Spec) Covers(scope []string) bool {
	if len(scope) == 0 {
		return false
	}
	for _, sc := range scope {
		if !s.under(sc) {
			return false
		}
	}
	return true
}

func (s *Spec) under(target string) bool {
	for _, base := range s.Scope {
		b := strings.TrimRight(base, "/")
		if target == b || strings.HasPrefix(target, b+"/") || strings.HasPrefix(target, b+"?") {
			return true
		}
	}
	return false
}

// Result is what a login gave: its fields (text), when they expire.
type Result struct {
	Fields map[string]string
	Expiry time.Time
}

// Error is a login that failed: Refused when the other service said no (a lasting refusal), an outage
// otherwise. It never carries a value.
type Error struct {
	Refused bool
	Msg     string
}

func (e *Error) Error() string { return e.Msg }

func refused(format string, a ...any) error {
	return &Error{Refused: true, Msg: fmt.Sprintf(format, a...)}
}
func outage(format string, a ...any) error { return &Error{Msg: fmt.Sprintf(format, a...)} }

// Client logs in: within its hosts, never following a redirect.
type Client struct {
	Hosts []string // dynamic.login_hosts: a host, or *.domain
	HTTP  *http.Client
	Now   func() time.Time
}

// CheckURL resolves a login's URL against its scope and checks it: within the scope, https (http only to this
// machine), its host in the allowlist.
func (c *Client) CheckURL(s *Spec, raw string) (string, error) {
	target := raw
	if strings.HasPrefix(raw, "/") {
		target = strings.TrimRight(s.Scope[0], "/") + raw
	}
	u, err := url.Parse(target)
	if err != nil || u.Host == "" {
		return "", errors.New("a login's URL is a path under its scope, or an absolute URL within it")
	}
	if !s.under(target) {
		return "", errors.New("a login's URL is outside its scope")
	}
	host := u.Hostname()
	if u.Scheme != "https" && !(u.Scheme == "http" && isLoopback(host)) {
		return "", errors.New("a login calls https (http only to this machine)")
	}
	if !c.allowed(host) {
		return "", fmt.Errorf("the host %q is not in dynamic.login_hosts", host)
	}
	return target, nil
}

func (c *Client) allowed(host string) bool {
	host = strings.ToLower(host)
	for _, h := range c.Hosts {
		h = strings.ToLower(h)
		if suffix, ok := strings.CutPrefix(h, "*."); ok {
			if strings.HasSuffix(host, "."+suffix) {
				return true
			}
		} else if host == h {
			return true
		}
	}
	return false
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Login logs in.
func (c *Client) Login(ctx context.Context, s *Spec) (*Result, map[string]string, error) {
	switch s.Flow {
	case FlowBasic:
		auth := "Basic " + base64.StdEncoding.EncodeToString([]byte(s.Username+":"+s.Password))
		ttl := s.TTL
		if ttl == 0 {
			ttl = defaultTTL
		}
		return &Result{Fields: map[string]string{"authorization": auth}, Expiry: c.Now().Add(ttl)}, nil, nil
	case FlowClientCredentials, FlowPassword:
		form := url.Values{}
		if s.Flow == FlowPassword {
			form.Set("grant_type", "password")
			form.Set("username", s.Username)
			form.Set("password", s.Password)
		} else {
			form.Set("grant_type", "client_credentials")
		}
		if s.OAuthScope != "" {
			form.Set("scope", s.OAuthScope)
		}
		return c.oauth(ctx, s, form)
	case FlowCustom:
		return c.custom(ctx, s, s.LoginURL, s.LoginMethod, s.LoginRequest, s.LoginResponse, nil)
	}
	return nil, nil, refused("a login of an unknown flow")
}

// Refresh renews a login from what it kept (its refresh_token): an OAuth2 refresh, or a custom one. ok is false
// when the login has no way to refresh: a new login then.
func (c *Client) Refresh(ctx context.Context, s *Spec, kept map[string]string) (*Result, map[string]string, bool, error) {
	if kept["refresh_token"] == "" {
		return nil, nil, false, nil
	}
	switch s.Flow {
	case FlowClientCredentials, FlowPassword:
		form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {kept["refresh_token"]}}
		res, next, err := c.oauth(ctx, s, form)
		return res, next, true, err
	case FlowCustom:
		if s.RefreshURL == "" {
			return nil, nil, false, nil
		}
		res, next, err := c.custom(ctx, s, s.RefreshURL, s.RefreshMethod, s.RefreshRequest, s.RefreshResponse, kept)
		return res, next, true, err
	}
	return nil, nil, false, nil
}

// oauth is a token request (RFC 6749): the client authenticated by HTTP Basic when it has a secret.
func (c *Client) oauth(ctx context.Context, s *Spec, form url.Values) (*Result, map[string]string, error) {
	target, err := c.CheckURL(s, s.TokenURL)
	if err != nil {
		return nil, nil, refused("%v", err)
	}
	if s.ClientSecret == "" && s.ClientID != "" {
		form.Set("client_id", s.ClientID)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, nil, refused("the login's request could not be made")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if s.ClientSecret != "" {
		req.SetBasicAuth(url.QueryEscape(s.ClientID), url.QueryEscape(s.ClientSecret))
	}
	resp, err := c.call(req)
	if err != nil {
		return nil, nil, err
	}
	var body map[string]any
	dec := json.NewDecoder(bytes.NewReader(resp.body))
	dec.UseNumber()
	if dec.Decode(&body) != nil {
		return nil, nil, outage("the token endpoint did not answer JSON")
	}
	fields := textFields(body)
	if fields["access_token"] == "" {
		return nil, nil, refused("the token endpoint gave no access_token")
	}
	return c.result(s, fields)
}

// custom: a request made by jq over the inputs, a response mapped by jq from {status, headers, cookies, body}.
func (c *Client) custom(ctx context.Context, s *Spec, rawURL, method, request, response string,
	kept map[string]string) (*Result, map[string]string, error) {
	target, err := c.CheckURL(s, rawURL)
	if err != nil {
		return nil, nil, refused("%v", err)
	}
	vars := map[string]any{"username": s.Username, "password": s.Password, "client_id": s.ClientID,
		"client_secret": s.ClientSecret, "refresh_token": kept["refresh_token"]}
	if method == "" {
		method = http.MethodPost
	}
	var body io.Reader
	contentType := ""
	if request != "" {
		out, err := runJQ(ctx, request, map[string]any{}, vars)
		if err != nil {
			return nil, nil, refused("the login's request mapping failed: %v", err)
		}
		if s.ContentType == "form" {
			obj, ok := out.(map[string]any)
			if !ok {
				return nil, nil, refused("the login's request mapping gave no object for a form")
			}
			form := url.Values{}
			for k, v := range obj {
				form.Set(k, text(v))
			}
			body, contentType = strings.NewReader(form.Encode()), "application/x-www-form-urlencoded"
		} else {
			b, err := json.Marshal(out)
			if err != nil {
				return nil, nil, refused("the login's request mapping gave no JSON")
			}
			body, contentType = bytes.NewReader(b), "application/json"
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		return nil, nil, refused("the login's request could not be made")
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.call(req)
	if err != nil {
		return nil, nil, err
	}
	in := map[string]any{"status": resp.status, "headers": resp.headers, "cookies": resp.cookies}
	var parsed any
	dec := json.NewDecoder(bytes.NewReader(resp.body))
	dec.UseNumber()
	if dec.Decode(&parsed) != nil {
		parsed = string(resp.body)
	}
	in["body"] = parsed
	out, err := runJQ(ctx, response, normalize(in), vars)
	if err != nil {
		return nil, nil, refused("the login's response mapping failed: %v", err)
	}
	obj, ok := out.(map[string]any)
	if !ok {
		return nil, nil, refused("the login's response mapping gave no object")
	}
	return c.result(s, textFields(obj))
}

// result: the fields, their expiry (expires_in seconds, or expires_at RFC 3339 / Unix seconds; else ttl, else
// 10m), and what is kept for a refresh.
func (c *Client) result(s *Spec, fields map[string]string) (*Result, map[string]string, error) {
	now := c.Now()
	expiry := time.Time{}
	if v := fields["expires_in"]; v != "" {
		if n, err := strconv.ParseFloat(v, 64); err == nil && n > 0 {
			expiry = now.Add(time.Duration(n * float64(time.Second)))
		}
	} else if v := fields["expires_at"]; v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			expiry = t
		} else if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			expiry = time.Unix(n, 0)
		}
	}
	if expiry.IsZero() {
		ttl := s.TTL
		if ttl == 0 {
			ttl = defaultTTL
		}
		expiry = now.Add(ttl)
	}
	kept := map[string]string{"refresh_token": fields["refresh_token"]}
	served := map[string]string{}
	for k, v := range fields {
		if !Hidden[k] && k != "expires_in" && k != "expires_at" {
			served[k] = v
		}
	}
	return &Result{Fields: served, Expiry: expiry}, kept, nil
}

type response struct {
	status  int
	headers map[string]string
	cookies map[string]string
	body    []byte
}

// call sends a request: no redirect followed, a time limit, a bounded body; 4xx a refusal, anything else not
// 2xx an outage.
func (c *Client) call(req *http.Request) (*response, error) {
	client := c.HTTP
	if client == nil {
		client = &http.Client{}
	}
	cl := *client
	cl.Timeout = callTimeout
	cl.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := cl.Do(req)
	if err != nil {
		return nil, outage("the login's service did not answer")
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return nil, outage("the login's service's answer did not read")
	}
	if len(b) > maxBody {
		return nil, outage("the login's service answered more than 1 MiB")
	}
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		return nil, refused("the login's service redirected (%d): not followed", resp.StatusCode)
	case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
		return nil, outage("the login's service answered %d", resp.StatusCode)
	default:
		return nil, refused("the login's service refused (%d)", resp.StatusCode)
	}
	out := &response{status: resp.StatusCode, headers: map[string]string{}, cookies: map[string]string{}, body: b}
	for k, v := range resp.Header {
		if len(v) > 0 {
			out.headers[strings.ToLower(k)] = v[0]
		}
	}
	for _, ck := range resp.Cookies() {
		out.cookies[ck.Name] = ck.Value
	}
	return out, nil
}

// textFields are an object's scalar fields as text: a string as it is, a number or a boolean as its JSON text.
func textFields(obj map[string]any) map[string]string {
	out := map[string]string{}
	for k, v := range obj {
		switch v.(type) {
		case string, json.Number, bool, int, float64:
			if t := text(v); t != "" {
				out[k] = t
			}
		}
	}
	return out
}

func text(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case json.Number:
		return t.String()
	case bool:
		return strconv.FormatBool(t)
	case int:
		return strconv.Itoa(t)
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case nil:
		return ""
	}
	b, _ := json.Marshal(v)
	return string(b)
}

// normalize turns json.Number into what gojq reads (float64 or int).
func normalize(v any) any {
	switch t := v.(type) {
	case json.Number:
		if i, err := t.Int64(); err == nil {
			return int(i)
		}
		f, _ := t.Float64()
		return f
	case map[string]any:
		for k, item := range t {
			t[k] = normalize(item)
		}
		return t
	case []any:
		for i, item := range t {
			t[i] = normalize(item)
		}
		return t
	case map[string]string:
		out := make(map[string]any, len(t))
		for k, s := range t {
			out[k] = s
		}
		return out
	}
	return v
}

var jqVars = []string{"$username", "$password", "$client_id", "$client_secret", "$refresh_token"}

func compile(src string) (*gojq.Code, error) {
	q, err := gojq.Parse(src)
	if err != nil {
		return nil, err
	}
	return gojq.Compile(q, gojq.WithVariables(jqVars))
}

// runJQ runs a mapping once, under a time limit: its first output. The error is jq's, never the input.
func runJQ(ctx context.Context, src string, input any, vars map[string]any) (any, error) {
	code, err := compile(src)
	if err != nil {
		return nil, errors.New("does not parse")
	}
	ctx, cancel := context.WithTimeout(ctx, jqTimeout)
	defer cancel()
	values := make([]any, len(jqVars))
	for i, name := range jqVars {
		values[i] = vars[strings.TrimPrefix(name, "$")]
	}
	iter := code.RunWithContext(ctx, input, values...)
	v, ok := iter.Next()
	if !ok {
		return nil, errors.New("gave no output")
	}
	if err, isErr := v.(error); isErr {
		if ctx.Err() != nil {
			return nil, errors.New("ran out of time")
		}
		var halt *gojq.HaltError
		if errors.As(err, &halt) {
			return nil, errors.New("halted")
		}
		return nil, errors.New("failed")
	}
	return v, nil
}
