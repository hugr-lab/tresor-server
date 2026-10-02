// Package vault is a thin client of OpenBao and HashiCorp Vault (spec 007): the same API for both. It logs in
// with no static secret of the service's own - the Kubernetes auth method, the JWT auth method (a projected
// token), or a token file a Vault Agent keeps - and calls the few endpoints the service needs. No token, no
// value read and no request body is ever logged or put in an error.
package vault

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// Config is where Vault is and how the service logs in.
type Config struct {
	Address   string
	Namespace string // a Vault Enterprise or OpenBao namespace; "" for none
	CAFile    string // a private CA; the system's roots otherwise
	Auth      Auth
}

// Auth is a login with no static secret.
type Auth struct {
	Method    string // kubernetes | jwt | token_file
	Mount     string // the auth method's mount (kubernetes, jwt)
	Role      string
	JWTFile   string // the token to log in with; kubernetes defaults to the pod's ServiceAccount token
	TokenFile string // token_file: the token a Vault Agent writes
}

// podToken is a pod's ServiceAccount token: the Kubernetes auth method's default.
const podToken = "/var/run/secrets/kubernetes.io/serviceaccount/token"

// Client is safe for concurrent use.
type Client struct {
	base *url.URL
	ns   string
	auth Auth
	http *http.Client

	mu        sync.Mutex
	token     string
	renewAt   time.Time // a login's token is replaced by a new login from then on (two thirds of its lease)
	expiresAt time.Time // the token's own end: until then it serves when a new login fails
	fileMod   time.Time // token_file: the file's time when it was read
}

// Error is Vault's answer to a call: its status and what it said (Vault's errors name a path or a permission,
// never a value), or none when it did not answer.
type Error struct {
	Status int
	Msg    string
}

func (e *Error) Error() string {
	if e.Status == 0 {
		return "Vault: " + e.Msg
	}
	return fmt.Sprintf("Vault answered %d: %s", e.Status, e.Msg)
}

// New checks the configuration: https unless the address is this machine's.
func New(cfg Config) (*Client, error) {
	u, err := url.Parse(strings.TrimRight(cfg.Address, "/"))
	if err != nil || u.Host == "" || (u.Scheme != "https" && !(u.Scheme == "http" && loopback(u.Hostname()))) ||
		u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("vault.address: an https URL (http only to this machine)")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if cfg.CAFile != "" {
		pem, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("vault.ca_file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("vault.ca_file: no certificate in it")
		}
		transport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	switch cfg.Auth.Method {
	case "kubernetes", "jwt":
		if cfg.Auth.Role == "" {
			return nil, errors.New("vault.auth.role is required")
		}
		if cfg.Auth.Mount == "" {
			cfg.Auth.Mount = cfg.Auth.Method
		}
		if cfg.Auth.JWTFile == "" {
			if cfg.Auth.Method == "jwt" {
				return nil, errors.New("vault.auth.jwt_file is required for jwt")
			}
			cfg.Auth.JWTFile = podToken
		}
	case "token_file":
		if cfg.Auth.TokenFile == "" {
			return nil, errors.New("vault.auth.token_file is required")
		}
	default:
		return nil, errors.New("vault.auth.method is kubernetes, jwt or token_file")
	}
	return &Client{base: u, ns: cfg.Namespace, auth: cfg.Auth,
		http: &http.Client{Transport: transport, Timeout: 15 * time.Second,
			// never followed: X-Vault-Token and the body (a data key's plaintext) would go wherever a redirect
			// says, http included (a standby's redirect is answered as an error)
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

func loopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Do calls /v1/<path> with body (JSON) and decodes the answer's data into out. A token Vault refused is replaced
// by a new login, once.
func (c *Client) Do(ctx context.Context, method, path string, body, out any) error {
	for attempt := 0; ; attempt++ {
		token, err := c.currentToken(ctx)
		if err != nil {
			return err
		}
		err = c.call(ctx, method, path, token, body, out)
		var ve *Error
		if attempt == 0 && errors.As(err, &ve) && ve.Status == http.StatusForbidden && c.forget(ctx, token) {
			continue // a token revoked or expired early: log in again (or read the file again)
		}
		return err
	}
}

func (c *Client) call(ctx context.Context, method, path, token string, body, out any) error {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base.String()+"/v1/"+strings.TrimLeft(path, "/"), reader)
	if err != nil {
		return err
	}
	if token != "" {
		req.Header.Set("X-Vault-Token", token)
	}
	if c.ns != "" {
		req.Header.Set("X-Vault-Namespace", c.ns)
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := c.http.Do(req)
	if err != nil {
		return &Error{Msg: "it did not answer"} // the transport's text names the URL only, at best
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if res.StatusCode/100 != 2 {
		var answer struct {
			Errors []string `json:"errors"`
		}
		_ = json.Unmarshal(raw, &answer)
		msg := strings.Join(answer.Errors, "; ")
		if r := []rune(msg); len(r) > 200 {
			msg = string(r[:200])
		}
		return &Error{Status: res.StatusCode, Msg: msg}
	}
	if out == nil || len(raw) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return &Error{Status: res.StatusCode, Msg: "an answer that does not read"}
	}
	return nil
}

// forget drops a token Vault refused, so the next call logs in again (or reads the token file again): true when
// it did. Vault answers 403 for a dead token and for a missing right alike: the token is looked up first, and a
// live one is kept - a missing right costs no login, only the lookup.
func (c *Client) forget(ctx context.Context, token string) bool {
	if c.call(ctx, http.MethodGet, "auth/token/lookup-self", token, nil, nil) == nil {
		return false // the token lives: the refusal is the policy's
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != token {
		return true // already replaced by another caller
	}
	if c.auth.Method == "token_file" {
		c.fileMod = time.Time{} // read the file again, whatever its time says
		return true
	}
	c.token, c.renewAt, c.expiresAt = "", time.Time{}, time.Time{}
	return true
}

// currentToken is the token to call with: from the file (read again when it changes), or a login's (replaced at
// two thirds of its lease).
func (c *Client) currentToken(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.auth.Method == "token_file" {
		info, err := os.Stat(c.auth.TokenFile)
		if err != nil {
			return "", fmt.Errorf("vault.auth.token_file: %w", err)
		}
		if c.token == "" || !info.ModTime().Equal(c.fileMod) {
			raw, err := os.ReadFile(c.auth.TokenFile)
			if err != nil {
				return "", fmt.Errorf("vault.auth.token_file: %w", err)
			}
			c.token, c.fileMod = strings.TrimSpace(string(raw)), info.ModTime()
			if c.token == "" {
				return "", errors.New("vault.auth.token_file is empty")
			}
		}
		return c.token, nil
	}
	if c.token != "" && time.Now().Before(c.renewAt) {
		return c.token, nil
	}
	token, err := c.login(ctx)
	if err != nil {
		if c.token != "" && time.Now().Before(c.expiresAt) {
			return c.token, nil // the old token lives on: a blip of the auth backend is no outage
		}
		return "", err
	}
	return token, nil
}

// login logs in with the role and the token file (held: c.mu).
func (c *Client) login(ctx context.Context) (string, error) {
	jwt, err := os.ReadFile(c.auth.JWTFile)
	if err != nil {
		return "", fmt.Errorf("vault.auth: the token to log in with: %w", err)
	}
	var answer struct {
		Auth struct {
			ClientToken   string `json:"client_token"`
			LeaseDuration int64  `json:"lease_duration"`
		} `json:"auth"`
	}
	err = c.call(ctx, http.MethodPost, "auth/"+c.auth.Mount+"/login", "",
		map[string]string{"role": c.auth.Role, "jwt": strings.TrimSpace(string(jwt))}, &answer)
	if err != nil {
		return "", fmt.Errorf("the login (%s): %w", c.auth.Method, err)
	}
	if answer.Auth.ClientToken == "" {
		return "", errors.New("the login gave no token")
	}
	lease := time.Duration(answer.Auth.LeaseDuration) * time.Second
	if lease <= 0 {
		lease = time.Hour // a token with no lease (root): logged in again hourly all the same
	}
	now := time.Now()
	c.token, c.renewAt, c.expiresAt = answer.Auth.ClientToken, now.Add(lease*2/3), now.Add(lease)
	return c.token, nil
}
