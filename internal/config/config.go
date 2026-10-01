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
	Material  Material `yaml:"material"`
	Issuers   []Issuer `yaml:"issuers"`
	Policy    Policy   `yaml:"policy"`
	// Audit and Telemetry are spec 005's: what the audit records, and whether spans continue tresor's trace.
	Audit     Audit     `yaml:"audit"`
	Telemetry Telemetry `yaml:"telemetry"`
	// Store is the reference server's encrypted file: kept only to refuse a config that still has it (an
	// empty `store:` too: see load)
	Store any `yaml:"store"`
}

// TLS names the certificate the server serves with; empty means plain http (loopback only) - unless TLS ends
// at the platform's ingress (Offload: Container Apps, an ingress controller), which forwards plain http.
type TLS struct {
	Cert string `yaml:"cert"`
	Key  string `yaml:"key"`
	// Offload: TLS ends before this process; it listens with plain http on any address, public_url is https,
	// and the port must be reachable only through the ingress.
	Offload bool `yaml:"offload"`
}

// State says where the service keeps what it knows (spec 002).
type State struct {
	// Kind is the store: memory (lost when the process ends), sqlite (one replica), postgres, sqlserver or
	// kubernetes (several).
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
	// PasswordRef is a reference to the password (ref+k8s:// or ref+azkv://), read for each new connection. It
	// must be outside material's allowlists: an administrator must not be able to read it.
	PasswordRef  string `yaml:"password_ref"`
	MaxOpenConns int    `yaml:"max_open_conns"`
	// Namespace is where the kubernetes store keeps its resources: the pod's own by default; outside a pod
	// (KUBECONFIG) required.
	Namespace string `yaml:"namespace"`
	// Instance names the installation in the kubernetes store's MACs (spec 003): the namespace by default.
	// Kept stable, so a restore still verifies.
	Instance string `yaml:"instance"`
}

// Audit is what the audit records (spec 005): all (the default), changes (no successful read) or off.
type Audit struct {
	Level string `yaml:"level"`
}

// Telemetry: OpenTelemetry takes its standard environment (OTEL_*); only what the service decides is here.
type Telemetry struct {
	// Traces: spans under tresor's trace (the default); false leaves the audit's trace_id only.
	Traces *bool `yaml:"traces"`
}

// TracesOn says whether spans are made: on unless set false.
func (t Telemetry) TracesOn() bool { return t.Traces == nil || *t.Traces }

// StateKinds are the stores this build knows.
// k8sPrefix is how a Kubernetes Secret's name may start.
var k8sPrefix = regexp.MustCompile(`^[a-z0-9][-a-z0-9.]*$`)

var StateKinds = []string{"memory", "sqlite", "postgres", "sqlserver", "kubernetes"}

// dnsLabel is a Kubernetes namespace's name.
var dnsLabel = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)

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

// Material is where references (ref+...) may read (spec 002).
type Material struct {
	AzKV AzKV `yaml:"azkv"`
	K8s  K8s  `yaml:"k8s"`
}

// K8s lets ref+k8s://<namespace>/<secret>/<key> read Kubernetes Secrets (spec 003): only in the namespaces and
// under the name prefixes listed, with the service's ServiceAccount.
type K8s struct {
	Allow []K8sAllow `yaml:"allow"`
}

// K8sAllow is one namespace, and the prefixes its Secrets' names must start with (none: all).
type K8sAllow struct {
	Namespace string   `yaml:"namespace"`
	Prefixes  []string `yaml:"prefixes"`
}

// AzKV lets ref+azkv://<vault>/<secret> read Key Vault secrets: only in the vaults and under the name prefixes
// listed, with the service's identity (Key Vault Secrets User).
type AzKV struct {
	Allow []AzKVAllow `yaml:"allow"`
	// CacheTTL keeps a value read for this long (default 0: read at every fetch).
	CacheTTL time.Duration `yaml:"cache_ttl"`
	// DNSSuffix is another cloud's (default .vault.azure.net).
	DNSSuffix string `yaml:"dns_suffix"`
}

// AzKVAllow is one vault, and the prefixes its secrets' names must start with (none: all).
type AzKVAllow struct {
	Vault    string   `yaml:"vault"`
	Prefixes []string `yaml:"prefixes"`
}

var (
	azkvVault = regexp.MustCompile(`^[0-9A-Za-z-]{3,24}$`)
	dnsSuffix = regexp.MustCompile(`^(\.[a-z0-9-]+)+$`)
)

// Azure is the service's identity on Azure (specs 002, 003): managed (a managed identity; ClientID names a
// user-assigned one), workload (AKS workload identity; ClientID overrides the webhook's) or default
// (DefaultAzureCredential: the az CLI for development).
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
	// ClientAuth is how the service logs in (spec 006): secret (the default), azure (its Azure identity's token,
	// for Entra's federated credential), file (AssertionFile: a projected ServiceAccount token), keyvault
	// (a JWT signed with Key in Key Vault), key_file (a JWT signed with KeyFile: ZITADEL's, or a PEM key).
	ClientAuth    string `yaml:"client_auth"`
	AssertionFile string `yaml:"assertion_file"`
	Key           string `yaml:"key"`
	KeyFile       string `yaml:"key_file"`
	KID           string `yaml:"kid"`
	// AssertionAudience is a signed JWT's aud: issuer (the default; ZITADEL, Keycloak) or token_endpoint (Entra).
	AssertionAudience string `yaml:"assertion_audience"`
}

// ClientAuthKinds are the ways the service logs in at a token endpoint.
var ClientAuthKinds = []string{"secret", "azure", "file", "keyvault", "key_file"}

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
	if c.TLS.Offload && c.TLS.Cert != "" {
		return errors.New("tls.offload: TLS ends at the ingress - no cert and key here")
	}
	if c.TLS.Cert == "" && !c.TLS.Offload && !IsLoopback(host) {
		return errors.New("plain http is allowed only on a loopback listen address - configure tls, or tls.offload " +
			"when TLS ends at the platform's ingress")
	}
	u, err := url.Parse(c.PublicURL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return errors.New("public_url must be an absolute http(s) URL")
	}
	if u.Scheme == "http" && !IsLoopback(u.Hostname()) {
		return errors.New("public_url: http only for a loopback host")
	}
	if c.TLS.Offload && u.Scheme != "https" {
		return errors.New("public_url: https with tls.offload - clients reach the service through the ingress's TLS")
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
	if c.State.Kind != "kubernetes" && (c.State.Namespace != "" || c.State.Instance != "") {
		return fmt.Errorf("state: namespace and instance are for kubernetes, not %s", c.State.Kind)
	}
	if c.State.Namespace != "" && !dnsLabel.MatchString(c.State.Namespace) {
		return errors.New("state.namespace is a namespace's name (a DNS label)")
	}
	if err := c.Keys.validate(c.State.Kind != "memory"); err != nil {
		return err
	}
	if c.Keys.Kind == "azurekeyvault" && c.Azure.Identity == "" {
		return errors.New("keys: azurekeyvault needs azure.identity: managed | workload | default")
	}
	if c.Azure.Identity != "" && c.Azure.Identity != "managed" && c.Azure.Identity != "workload" && c.Azure.Identity != "default" {
		return errors.New("azure.identity is managed, workload or default")
	}
	if c.Azure.ClientID != "" && c.Azure.Identity != "managed" && c.Azure.Identity != "workload" {
		return errors.New("azure.client_id names a user-assigned managed identity (managed) or the federated one (workload)")
	}
	if kv := c.Material.AzKV; len(kv.Allow) > 0 || kv.CacheTTL != 0 || kv.DNSSuffix != "" {
		if len(kv.Allow) == 0 {
			return errors.New("material.azkv: allow lists the vaults references may read - none, no references")
		}
		if c.Azure.Identity == "" {
			return errors.New("material.azkv reads with the service's Azure identity: azure.identity is required")
		}
		for i, a := range kv.Allow {
			if !azkvVault.MatchString(a.Vault) {
				return fmt.Errorf("material.azkv.allow[%d].vault: a vault's name, 3 to 24 letters, digits or dashes", i)
			}
		}
		if kv.CacheTTL < 0 || kv.CacheTTL > 5*time.Minute {
			return errors.New("material.azkv.cache_ttl is 0 to 5m: the longest a value may be read stale")
		}
		if kv.DNSSuffix != "" && !dnsSuffix.MatchString(kv.DNSSuffix) {
			return errors.New("material.azkv.dns_suffix is a domain's suffix (.vault.azure.net)")
		}
	}
	for i, a := range c.Material.K8s.Allow {
		if !dnsLabel.MatchString(a.Namespace) {
			return fmt.Errorf("material.k8s.allow[%d].namespace: a namespace's name (a DNS label)", i)
		}
		for _, p := range a.Prefixes {
			if !k8sPrefix.MatchString(p) {
				return fmt.Errorf("material.k8s.allow[%d].prefixes: a Secret's name starts so - lower-case letters, "+
					"digits, dashes and dots", i)
			}
		}
	}
	if strings.HasPrefix(c.State.PasswordRef, "ref+azkv://") && c.Azure.Identity == "" {
		return errors.New("state.password_ref reads Key Vault with the service's Azure identity: azure.identity is required")
	}
	if c.State.PasswordRef != "" && c.Material.admits(c.State.PasswordRef) {
		return errors.New("state.password_ref is within material's allowlist: an administrator could read the " +
			"database's password through a reference - keep it in a namespace, a vault or a name no allowlist admits")
	}
	switch c.Audit.Level {
	case "", "all", "changes", "off":
	default:
		return errors.New("audit.level is all, changes or off")
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
			if err := ex.validate(c.Azure.Identity); err != nil {
				return fmt.Errorf("issuers[%d]: %w", i, err)
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
		if s.DSN != "" || s.Auth != "" || s.PasswordEnv != "" || s.PasswordFile != "" || s.PasswordRef != "" || s.MaxOpenConns != 0 {
			return fmt.Errorf("state: dsn, auth, password_env, password_file, password_ref, max_open_conns are for a database server, not %s", s.Kind)
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
		if s.PasswordEnv != "" || s.PasswordFile != "" || s.PasswordRef != "" {
			return errors.New("state.auth: entra takes no password")
		}
	case "password":
		n := 0
		for _, v := range []string{s.PasswordEnv, s.PasswordFile, s.PasswordRef} {
			if v != "" {
				n++
			}
		}
		if n != 1 {
			return errors.New("state.auth: password comes from password_env, password_file or password_ref - one of them")
		}
		if s.PasswordRef != "" && !strings.HasPrefix(s.PasswordRef, "ref+k8s://") && !strings.HasPrefix(s.PasswordRef, "ref+azkv://") {
			return errors.New("state.password_ref is a ref+k8s:// or ref+azkv:// reference")
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

// admits says whether a reference's place is within an allowlist, as the sources compare: Kubernetes names
// exactly, Key Vault names without case. A reference that does not parse is admitted by none.
func (m Material) admits(ref string) bool {
	if rest, ok := strings.CutPrefix(ref, "ref+k8s://"); ok {
		parts := strings.Split(rest, "/")
		for _, a := range m.K8s.Allow {
			if len(parts) == 3 && a.Namespace == parts[0] && (len(a.Prefixes) == 0 ||
				slices.ContainsFunc(a.Prefixes, func(p string) bool { return strings.HasPrefix(parts[1], p) })) {
				return true
			}
		}
	}
	if rest, ok := strings.CutPrefix(ref, "ref+azkv://"); ok {
		parts := strings.Split(rest, "/")
		for _, a := range m.AzKV.Allow {
			if len(parts) >= 2 && strings.EqualFold(a.Vault, parts[0]) && (len(a.Prefixes) == 0 ||
				slices.ContainsFunc(a.Prefixes, func(p string) bool {
					return strings.HasPrefix(strings.ToLower(parts[1]), strings.ToLower(p))
				})) {
				return true
			}
		}
	}
	return false
}

// validate checks an exchange client's login: one way, and what that way needs - nothing of another.
func (ex *ExchangeClient) validate(identity string) error {
	if ex.ClientAuth == "" {
		ex.ClientAuth = "secret"
	}
	if !slices.Contains(ClientAuthKinds, ex.ClientAuth) {
		return fmt.Errorf("exchange.client_auth is %s", strings.Join(ClientAuthKinds, " | "))
	}
	if ex.ClientID == "" && ex.ClientAuth != "key_file" {
		return errors.New("exchange needs client_id")
	}
	set := map[string]bool{"client_secret_env": ex.ClientSecretEnv != "", "assertion_file": ex.AssertionFile != "",
		"key": ex.Key != "", "key_file": ex.KeyFile != "", "kid": ex.KID != "", "assertion_audience": ex.AssertionAudience != ""}
	allowed := map[string][]string{
		"secret":   {"client_secret_env"},
		"azure":    {},
		"file":     {"assertion_file"},
		"keyvault": {"key", "kid", "assertion_audience"},
		"key_file": {"key_file", "kid", "assertion_audience"},
	}[ex.ClientAuth]
	for name, on := range set {
		if on && !slices.Contains(allowed, name) {
			return fmt.Errorf("exchange.%s is not for client_auth: %s", name, ex.ClientAuth)
		}
	}
	switch ex.ClientAuth {
	case "secret":
		if ex.ClientSecretEnv == "" {
			return errors.New("exchange needs client_secret_env, or another client_auth (spec 006)")
		}
		if IsSettingVariable(ex.ClientSecretEnv) {
			return fmt.Errorf("exchange.client_secret_env names %s, which is read as configuration - "+
				"give the secret a variable of its own", ex.ClientSecretEnv)
		}
		if ex.ClientSecret = os.Getenv(ex.ClientSecretEnv); ex.ClientSecret == "" {
			return fmt.Errorf("exchange: the environment variable %s is empty", ex.ClientSecretEnv)
		}
	case "azure":
		if identity != "managed" && identity != "workload" {
			return errors.New("exchange.client_auth: azure is the service's managed or workload identity (azure.identity)")
		}
	case "file":
		if ex.AssertionFile == "" {
			return errors.New("exchange.client_auth: file reads assertion_file (a projected ServiceAccount token)")
		}
	case "keyvault":
		if ex.Key == "" || ex.KID == "" {
			return errors.New("exchange.client_auth: keyvault signs with key (a Key Vault key URL) as kid")
		}
		if identity == "" {
			return errors.New("exchange.client_auth: keyvault signs with the service's Azure identity: azure.identity is required")
		}
	case "key_file":
		if ex.KeyFile == "" {
			return errors.New("exchange.client_auth: key_file signs with key_file (ZITADEL's key file, or a PEM key)")
		}
	}
	switch ex.AssertionAudience {
	case "", "issuer", "token_endpoint":
	default:
		return errors.New("exchange.assertion_audience is issuer or token_endpoint")
	}
	return nil
}
