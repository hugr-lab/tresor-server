// Package config reads and validates the service's configuration: the reference server's (tresor specs/003,
// taken over from tresor under its MIT license) plus state: (spec 002).
package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"
)

// Config is the whole server configuration.
type Config struct {
	Listen    string   `yaml:"listen"`
	PublicURL string   `yaml:"public_url"`
	TLS       TLS      `yaml:"tls"`
	State     State    `yaml:"state"`
	Keys      Keys     `yaml:"keys"`
	Azure     Azure    `yaml:"azure"`
	Issuers   []Issuer `yaml:"issuers"`
	Policy    Policy   `yaml:"policy"`
	// Store is the reference server's encrypted file: kept only to refuse a config that still has it (an
	// empty `store:` too: see load)
	Store any `yaml:"store"`
}

// TLS names the certificate the server serves with; empty means plain http (loopback only).
type TLS struct {
	Cert string `yaml:"cert"`
	Key  string `yaml:"key"`
}

// State says where the service keeps what it knows (spec 002).
type State struct {
	// Kind is the store: memory (lost when the process ends), sqlite (one replica), postgres or sqlserver
	// (several).
	Kind string `yaml:"kind"`
	// Path is the SQLite database's file.
	Path string `yaml:"path"`
	// DSN names a database server, the database and the user - never a password.
	DSN string `yaml:"dsn"`
	// Auth is how the service logs in to the database: entra (its Azure identity's token) or password
	// (PasswordEnv or PasswordFile, read again for each new connection).
	Auth         string `yaml:"auth"`
	PasswordEnv  string `yaml:"password_env"`
	PasswordFile string `yaml:"password_file"`
	MaxOpenConns int    `yaml:"max_open_conns"`
}

// StateKinds are the stores this build knows.
var StateKinds = []string{"memory", "sqlite", "postgres", "sqlserver"}

// Keys is the KEK the params are sealed under (spec 002): local, a 32-byte key from the environment or a
// file; or azurekeyvault, a key in Key Vault or Managed HSM.
type Keys struct {
	Kind    string `yaml:"kind"`
	KeyEnv  string `yaml:"key_env"`
	KeyFile string `yaml:"key_file"`
	// Key is the azurekeyvault key's URL, https://<vault>/keys/<name>, with no version.
	Key string `yaml:"key"`
	// DataKeyMaxAge: a data key older than this is replaced for new values (default 30 days).
	DataKeyMaxAge time.Duration `yaml:"data_key_max_age"`
	// CacheTTL: how long an unwrapped data key stays in memory (default 5 minutes).
	CacheTTL time.Duration `yaml:"cache_ttl"`
}

// KeyKinds are the KEKs this build knows.
var KeyKinds = []string{"local", "azurekeyvault"}

// Azure is the service's identity on Azure (spec 002): managed (a managed identity; ClientID names a
// user-assigned one) or default (DefaultAzureCredential: the az CLI for development).
type Azure struct {
	Identity string `yaml:"identity"`
	ClientID string `yaml:"client_id"`
}

// Issuer is one identity provider the server accepts tokens from.
type Issuer struct {
	Issuer       string   `yaml:"issuer"`
	Audience     string   `yaml:"audience"`
	ClientID     string   `yaml:"client_id"`
	Scopes       []string `yaml:"scopes"`
	HumanFlows   []string `yaml:"human_flows"`
	ServiceFlows []string `yaml:"service_flows"`
	// AudienceParameter asks clients to send `audience=<audience>` on the IdP's requests: an IdP that picks a
	// token's audience from that parameter rather than its configuration (Auth0; tresor specs/013).
	AudienceParameter bool     `yaml:"audience_parameter"`
	RolesClaim        string   `yaml:"roles_claim"`
	GroupsClaim       string   `yaml:"groups_claim"`
	Algorithms        []string `yaml:"algorithms"`
	// Service says how this issuer's client-credentials tokens are told apart from people's. Without
	// it every caller of the issuer is a person: no claim is a service marker by convention (RFC 9068
	// puts client_id into every access token, a person's included).
	Service *ServiceRule `yaml:"service"`
	// Exchange is the service's own confidential client at this issuer (specs/010): with it the service
	// mints `token_exchange` secrets - a token for the caller - by RFC 8693 token exchange.
	Exchange *ExchangeClient `yaml:"exchange"`
}

// ExchangeClient names the service's client at an issuer; its secret comes from the environment, never
// from the file.
type ExchangeClient struct {
	ClientID        string `yaml:"client_id"`
	ClientSecretEnv string `yaml:"client_secret_env"`
	ClientSecret    string `yaml:"-"` // read from ClientSecretEnv at load
}

// ServiceRule marks a token as a service's: Claim is present (and equals Equals, when set); the
// client's name is ClientClaim (default azp).
type ServiceRule struct {
	Claim       string `yaml:"claim"`
	Equals      string `yaml:"equals"`
	ClientClaim string `yaml:"client_claim"`
}

// Policy is the service-level part of the permissions (specs/009): the admins, who alone manage secrets
// and grant their use, and the servers allowed to act for users.
type Policy struct {
	Admins []string `yaml:"admins"`
	// Actors are the servers allowed to act for users (delegation grants). Under a grant `use` is the actor's
	// own (what an admin granted the server); a management verb listed here passes through the server only for
	// a user who is an admin themselves - administration through a duckdb-acl node (specs/009).
	Actors []ActorRule `yaml:"actors"`
	// Create is gone (specs/009): kept only to refuse a config that still has it, with a word on why
	Create any `yaml:"create"`
}

// ActorRule lets a service (a client: principal) act for users with the verbs listed: `use` (its own grants),
// and the management verbs and `create` it may pass on for admins. Issuer, when set, pins the actor to the
// issuer its token must come from: a client: name is not issuer-qualified, and a same-named client of another
// configured issuer must not pass for it.
type ActorRule struct {
	Principal string   `yaml:"principal"`
	Issuer    string   `yaml:"issuer"`
	Verbs     []string `yaml:"verbs"`
}

var allowedAlgorithms = map[string]bool{
	"RS256": true, "RS384": true, "RS512": true,
	"PS256": true, "PS384": true, "PS512": true,
	"ES256": true, "ES384": true, "ES512": true, "EdDSA": true,
}

// the per-secret verbs (specs/009): `use`, granted to roles and groups; the rest are the admins'
var knownVerbs = map[string]bool{
	"use": true, "update": true, "delete": true, "annotate": true, "grant": true,
}

// KnownVerb says whether v is one of the protocol's per-secret verbs.
func KnownVerb(v string) bool { return knownVerbs[v] }

func (c *Config) validate() error {
	if c.Listen == "" {
		return errors.New("listen is required")
	}
	host, _, err := net.SplitHostPort(c.Listen)
	if err != nil {
		return errors.New("listen must be host:port")
	}
	if (c.TLS.Cert == "") != (c.TLS.Key == "") {
		return errors.New("tls needs both cert and key")
	}
	if c.TLS.Cert == "" && !IsLoopback(host) {
		return errors.New("plain http is allowed only on a loopback listen address - configure tls")
	}
	u, err := url.Parse(c.PublicURL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return errors.New("public_url must be an absolute http(s) URL")
	}
	if u.Scheme == "http" && !IsLoopback(u.Hostname()) {
		return errors.New("public_url: http only for a loopback host")
	}
	if c.Store != nil {
		return errors.New("store: is the reference server's encrypted file - this service keeps its state as " +
			"state: names it (state: {kind: memory})")
	}
	if c.State.Kind == "" {
		return errors.New("state.kind is required: " + strings.Join(StateKinds, " | "))
	}
	if !slices.Contains(StateKinds, c.State.Kind) {
		return fmt.Errorf("state.kind is none of %s", strings.Join(StateKinds, " | "))
	}
	if c.State.Kind == "sqlite" && c.State.Path == "" {
		return errors.New("state.path is required for sqlite")
	}
	if err := c.State.validateServer(c.Azure.Identity); err != nil {
		return err
	}
	if err := c.Keys.validate(c.State.Kind != "memory"); err != nil {
		return err
	}
	if c.Keys.Kind == "azurekeyvault" && c.Azure.Identity == "" {
		return errors.New("keys: azurekeyvault needs azure.identity: managed | default")
	}
	if c.Azure.Identity != "" && c.Azure.Identity != "managed" && c.Azure.Identity != "default" {
		return errors.New("azure.identity is managed or default")
	}
	if c.Azure.ClientID != "" && c.Azure.Identity != "managed" {
		return errors.New("azure.client_id names a user-assigned managed identity: azure.identity: managed")
	}
	if len(c.Issuers) == 0 {
		return errors.New("at least one issuer is required")
	}
	seen := map[string]bool{}
	for i := range c.Issuers {
		is := &c.Issuers[i]
		// kept verbatim: an issuer identifier is compared exactly (RFC 8414), and some end in '/'
		// (Auth0, Entra v1); only the lookup key is normalised (IssuerKey)
		if is.Issuer == "" || is.Audience == "" {
			return fmt.Errorf("issuers[%d]: issuer and audience are required", i)
		}
		iu, err := url.Parse(is.Issuer)
		if err != nil || iu.Host == "" || (iu.Scheme != "https" && !(iu.Scheme == "http" && IsLoopback(iu.Hostname()))) {
			// its discovery and JWKS are fetched from here: over plain http anyone on the path could
			// substitute the signing keys
			return fmt.Errorf("issuers[%d]: issuer must be https (http only for a loopback host)", i)
		}
		if seen[IssuerKey(is.Issuer)] {
			return fmt.Errorf("issuers[%d]: the issuer is listed twice", i)
		}
		seen[IssuerKey(is.Issuer)] = true
		if len(is.HumanFlows) > 0 && is.ClientID == "" {
			return fmt.Errorf("issuers[%d]: human_flows need the public client_id people log in with", i)
		}
		if is.Service != nil {
			if is.Service.Claim == "" {
				return fmt.Errorf("issuers[%d]: service.claim is required", i)
			}
			if is.Service.ClientClaim == "" {
				is.Service.ClientClaim = "azp"
			}
		}
		if ex := is.Exchange; ex != nil {
			if ex.ClientID == "" || ex.ClientSecretEnv == "" {
				return fmt.Errorf("issuers[%d]: exchange needs client_id and client_secret_env", i)
			}
			if IsSettingVariable(ex.ClientSecretEnv) {
				return fmt.Errorf("issuers[%d]: exchange.client_secret_env names %s, which is read as configuration - "+
					"give the secret a variable of its own", i, ex.ClientSecretEnv)
			}
			if ex.ClientSecret = os.Getenv(ex.ClientSecretEnv); ex.ClientSecret == "" {
				return fmt.Errorf("issuers[%d]: exchange: the environment variable %s is empty", i, ex.ClientSecretEnv)
			}
		}
		if len(is.Algorithms) == 0 {
			is.Algorithms = []string{"RS256", "ES256"}
		}
		for j, alg := range is.Algorithms {
			if !allowedAlgorithms[alg] {
				return fmt.Errorf("issuers[%d].algorithms[%d] is not allowed (asymmetric only)", i, j)
			}
		}
	}
	if c.Policy.Create != nil {
		return errors.New("policy.create is gone (tresor specs/009): only admins create secrets - list them in " +
			"policy.admins")
	}
	for i, p := range c.Policy.Admins {
		if err := checkPrincipal(p); err != nil {
			return fmt.Errorf("policy.admins[%d]: %w", i, err)
		}
	}
	for i, a := range c.Policy.Actors {
		if !strings.HasPrefix(a.Principal, "client:") || len(a.Principal) <= len("client:") {
			return fmt.Errorf("policy.actors[%d]: an actor is a service, client:<id>", i)
		}
		if len(a.Verbs) == 0 {
			return fmt.Errorf("policy.actors[%d] lists no verbs - leave it out instead", i)
		}
		for j, v := range a.Verbs {
			if !KnownVerb(v) && v != "create" {
				return fmt.Errorf("policy.actors[%d].verbs[%d] is not a verb", i, j)
			}
		}
	}
	return nil
}

// validateServer checks a database server's settings (postgres, sqlserver).
func (s *State) validateServer(identity string) error {
	if s.Kind != "postgres" && s.Kind != "sqlserver" {
		if s.DSN != "" || s.Auth != "" || s.PasswordEnv != "" || s.PasswordFile != "" || s.MaxOpenConns != 0 {
			return fmt.Errorf("state: dsn, auth, password_env, password_file, max_open_conns are for a database server, not %s", s.Kind)
		}
		return nil
	}
	switch {
	case s.DSN == "":
		return errors.New("state.dsn is required: the server, the database and the user")
	case DSNHasPassword(s.DSN):
		return errors.New("state.dsn carries no password: it comes from state.auth")
	case s.MaxOpenConns < 0:
		return errors.New("state.max_open_conns is positive")
	}
	switch s.Auth {
	case "entra":
		if identity == "" {
			return errors.New("state.auth: entra logs in with the service's Azure identity: azure.identity is required")
		}
		if s.PasswordEnv != "" || s.PasswordFile != "" {
			return errors.New("state.auth: entra takes no password")
		}
	case "password":
		if (s.PasswordEnv == "") == (s.PasswordFile == "") {
			return errors.New("state.auth: password comes from password_env or password_file - one of them")
		}
		if s.PasswordEnv != "" && IsSettingVariable(s.PasswordEnv) {
			return fmt.Errorf("state.password_env names %s, which is read as configuration - give the password a "+
				"variable of its own", s.PasswordEnv)
		}
	default:
		return errors.New("state.auth is entra or password")
	}
	return nil
}

// dsnPasswordKey is a password in a keyword DSN (key=value pairs, spaces allowed around =).
var dsnPasswordKey = regexp.MustCompile(`(?i)(^|[\s;&])(password|pwd)\s*=`)

// DSNHasPassword says whether a DSN carries a password - a URL's user info or query, or a keyword - never
// allowed: the password comes from state.auth. A name that merely contains the word does not count.
func DSNHasPassword(dsn string) bool {
	if u, err := url.Parse(dsn); err == nil && u.Scheme != "" && u.Host != "" {
		if u.User != nil {
			if _, set := u.User.Password(); set {
				return true
			}
		}
		// a query's parameters, split at & or ; (SQL Server's URLs use both)
		return dsnPasswordKey.MatchString(u.RawQuery)
	}
	return dsnPasswordKey.MatchString(dsn)
}

func (k *Keys) validate(required bool) error {
	if k.Kind == "" {
		if required {
			return errors.New("keys: is required with a state store on disk - material is sealed at rest " +
				"(keys: {kind: local, key_env: ...})")
		}
		return nil
	}
	if !slices.Contains(KeyKinds, k.Kind) {
		return fmt.Errorf("keys.kind is none of %s", strings.Join(KeyKinds, " | "))
	}
	switch k.Kind {
	case "local":
		if (k.KeyEnv == "") == (k.KeyFile == "") || k.Key != "" {
			return errors.New("keys: a local KEK comes from key_env or key_file - one of them")
		}
	case "azurekeyvault":
		if k.Key == "" || k.KeyEnv != "" || k.KeyFile != "" {
			return errors.New("keys: an azurekeyvault KEK is keys.key, https://<vault>/keys/<name> - nothing else")
		}
		if !strings.HasPrefix(k.Key, "https://") {
			return errors.New("keys.key: an https key URL")
		}
	}
	if k.KeyEnv != "" && IsSettingVariable(k.KeyEnv) {
		return fmt.Errorf("keys.key_env names %s, which is read as configuration - give the KEK a variable of "+
			"its own", k.KeyEnv)
	}
	if k.DataKeyMaxAge < 0 || k.CacheTTL < 0 {
		return errors.New("keys: data_key_max_age and cache_ttl are positive")
	}
	return nil
}

func checkPrincipal(p string) error {
	for _, prefix := range []string{"role:", "group:", "subject:", "client:"} {
		if strings.HasPrefix(p, prefix) && len(p) > len(prefix) {
			return nil
		}
	}
	return errors.New("role:, group:, subject: or client: expected")
}

// IssuerKey is how an issuer is looked up by a token's iss: without a trailing '/'.
func IssuerKey(issuer string) string { return strings.TrimRight(issuer, "/") }

// IsLoopback says whether host (a name or an IP) is this machine.
func IsLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
