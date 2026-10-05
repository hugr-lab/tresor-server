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

	"github.com/hugr-lab/tresor-server/internal/material"
)

// Config is the whole server configuration.
type Config struct {
	Listen    string   `yaml:"listen"`
	PublicURL string   `yaml:"public_url"`
	TLS       TLS      `yaml:"tls"`
	State     State    `yaml:"state"`
	Keys      Keys     `yaml:"keys"`
	Azure     Azure    `yaml:"azure"`
	Vault     Vault    `yaml:"vault"`
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
	// PasswordRef is a reference to the password (ref+k8s://, ref+azkv:// or ref+vault://), read for each new
	// connection. It
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
	// Key is the azurekeyvault key's URL, https://<vault>/keys/<name>, with no version; or the vault KEK's
	// Transit key name.
	Key string `yaml:"key"`
	// Mount is the vault KEK's Transit mount (default transit).
	Mount string `yaml:"mount"`
	// DataKeyMaxAge: a data key older than this is replaced for new values (default 30 days).
	DataKeyMaxAge time.Duration `yaml:"data_key_max_age"`
	// CacheTTL: how long an unwrapped data key stays in memory (default 5 minutes).
	CacheTTL time.Duration `yaml:"cache_ttl"`
}

// KeyKinds are the KEKs this build knows.
var KeyKinds = []string{"local", "azurekeyvault", "vault"}

// Vault is OpenBao or HashiCorp Vault (spec 007): where it is, and how the service logs in with no static
// secret.
type Vault struct {
	Address   string    `yaml:"address"`
	Namespace string    `yaml:"namespace"`
	CAFile    string    `yaml:"ca_file"`
	Auth      VaultAuth `yaml:"auth"`
}

// VaultAuth: kubernetes (the pod's ServiceAccount token, or JWTFile), jwt (JWTFile: a projected token), or
// token_file (a token a Vault Agent writes).
type VaultAuth struct {
	Method    string `yaml:"method"`
	Mount     string `yaml:"mount"`
	Role      string `yaml:"role"`
	JWTFile   string `yaml:"jwt_file"`
	TokenFile string `yaml:"token_file"`
}

// used: a Vault is configured.
func (v Vault) used() bool { return v.Address != "" }

func (v Vault) validate() error {
	if !v.used() {
		if v.Namespace != "" || v.CAFile != "" || v.Auth != (VaultAuth{}) {
			return errors.New("vault: address is required")
		}
		return nil
	}
	switch v.Auth.Method {
	case "kubernetes", "jwt":
		if v.Auth.Role == "" || v.Auth.TokenFile != "" {
			return fmt.Errorf("vault.auth: %s logs in with a role (and jwt_file), no token_file", v.Auth.Method)
		}
		if v.Auth.Method == "jwt" && v.Auth.JWTFile == "" {
			return errors.New("vault.auth: jwt logs in with jwt_file (a projected ServiceAccount token)")
		}
	case "token_file":
		if v.Auth.TokenFile == "" || v.Auth.Role != "" || v.Auth.JWTFile != "" || v.Auth.Mount != "" {
			return errors.New("vault.auth: token_file reads token_file, and nothing else")
		}
	default:
		return errors.New("vault.auth.method is kubernetes, jwt or token_file")
	}
	return nil
}

// Material is where references (ref+...) may read (spec 002).
type Material struct {
	AzKV  AzKV       `yaml:"azkv"`
	K8s   K8s        `yaml:"k8s"`
	Vault VaultAllow `yaml:"vault"`
	// Sources are named sources (spec 008): more instances of a kind, ref+<name>://, each with its own
	// connection and allowlist.
	Sources []NamedSource `yaml:"sources"`
}

// NamedSource is one named source (spec 008): its name is the references' scheme.
type NamedSource struct {
	Name string `yaml:"name"`
	Kind string `yaml:"kind"` // vault | azkv
	// Vault (kind vault) and Azure (kind azkv) are the source's own connection; unset, the top-level one.
	Vault     *Vault        `yaml:"vault"`
	Azure     *Azure        `yaml:"azure"`
	Allow     []SourceAllow `yaml:"allow"`
	CacheTTL  time.Duration `yaml:"cache_ttl"`
	DNSSuffix string        `yaml:"dns_suffix"` // azkv
}

// SourceAllow is one place a named source may read: a KV v2 mount (vault) or a Key Vault (azkv), and the
// prefixes there.
type SourceAllow struct {
	Mount    string   `yaml:"mount"`
	Vault    string   `yaml:"vault"`
	Prefixes []string `yaml:"prefixes"`
}

// NamedSourceKinds are the kinds a named source may be: k8s is not one (another cluster would need a kubeconfig
// with credentials).
var NamedSourceKinds = []string{"vault", "azkv"}

// Source is a source with its connection resolved: a built-in section's (its name is its kind) or a named
// one's, with the top-level vault: or azure: when it has none of its own.
type Source struct {
	Name, Kind string
	Named      bool
	Vault      Vault      // kind vault: the connection
	Azure      Azure      // kind azkv: the identity
	VaultAllow VaultAllow // kind vault: the allowlist, the cache
	AzKV       AzKV       // kind azkv: the allowlist, the cache, the cloud
	K8s        K8s        // kind k8s
}

// Source is the source references of a scheme read from (configured or not: state.password_ref reads outside
// every allowlist); false for a name no source has.
func (c *Config) Source(scheme string) (Source, bool) {
	for _, n := range c.Material.Sources {
		if n.Name != scheme {
			continue
		}
		s := Source{Name: n.Name, Kind: n.Kind, Named: true, Vault: c.Vault, Azure: c.Azure}
		if n.Vault != nil {
			s.Vault = *n.Vault
		}
		if n.Azure != nil {
			s.Azure = *n.Azure
		}
		for _, a := range n.Allow {
			switch n.Kind {
			case "vault":
				s.VaultAllow.Allow = append(s.VaultAllow.Allow, VaultMount{Mount: a.Mount, Prefixes: a.Prefixes})
			case "azkv":
				s.AzKV.Allow = append(s.AzKV.Allow, AzKVAllow{Vault: a.Vault, Prefixes: a.Prefixes})
			}
		}
		s.VaultAllow.CacheTTL, s.AzKV.CacheTTL, s.AzKV.DNSSuffix = n.CacheTTL, n.CacheTTL, n.DNSSuffix
		return s, true
	}
	switch scheme {
	case "vault":
		return Source{Name: scheme, Kind: scheme, Vault: c.Vault, VaultAllow: c.Material.Vault}, true
	case "azkv":
		return Source{Name: scheme, Kind: scheme, Azure: c.Azure, AzKV: c.Material.AzKV}, true
	case "k8s":
		return Source{Name: scheme, Kind: scheme, K8s: c.Material.K8s}, true
	}
	return Source{}, false
}

// Sources are the sources references may read from: the built-in sections with an allowlist, then the named.
func (c *Config) Sources() []Source {
	var out []Source
	for _, kind := range []string{"azkv", "k8s", "vault"} {
		if s, _ := c.Source(kind); !s.Named && s.allows() {
			out = append(out, s)
		}
	}
	for _, n := range c.Material.Sources {
		s, _ := c.Source(n.Name)
		out = append(out, s)
	}
	return out
}

// allows: the source has an allowlist.
func (s Source) allows() bool {
	return len(s.VaultAllow.Allow) > 0 || len(s.AzKV.Allow) > 0 || len(s.K8s.Allow) > 0
}

// VaultAllow lets ref+vault://<mount>/<path>#<field> read KV v2 secrets (spec 007): only in the mounts and under
// the path prefixes listed, with the service's Vault login.
type VaultAllow struct {
	Allow []VaultMount `yaml:"allow"`
	// CacheTTL keeps a value read for this long (default 0: read at every fetch), at most 5 minutes.
	CacheTTL time.Duration `yaml:"cache_ttl"`
}

// VaultMount is one KV v2 mount, and the prefixes its secrets' paths must start with (none: all).
type VaultMount struct {
	Mount    string   `yaml:"mount"`
	Prefixes []string `yaml:"prefixes"`
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
	// TenantID is another tenant's (workload, in a named source: spec 008); the webhook's otherwise.
	TenantID string `yaml:"tenant_id"`
}

// validate checks an identity; where names it in errors.
func (a Azure) validate(where string, tenant bool) error {
	if a.Identity != "managed" && a.Identity != "workload" && a.Identity != "default" {
		return fmt.Errorf("%s.identity is managed, workload or default", where)
	}
	if a.ClientID != "" && a.Identity != "managed" && a.Identity != "workload" {
		return fmt.Errorf("%s.client_id names a user-assigned managed identity (managed) or the federated one (workload)", where)
	}
	if a.TenantID != "" && (!tenant || a.Identity != "workload") {
		return fmt.Errorf("%s.tenant_id is a named source's, with identity workload", where)
	}
	return nil
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
	// X5T is the certificate's thumbprint in the JWT's header, for an IdP that knows a key by it (Entra).
	X5T string `yaml:"x5t"`
	// AssertionAudience is a signed JWT's aud: issuer (the default; ZITADEL, Keycloak) or token_endpoint (Entra).
	AssertionAudience string `yaml:"assertion_audience"`
}

// ClientAuthKinds are the ways the service logs in at a token endpoint.
var ClientAuthKinds = []string{"secret", "azure", "file", "keyvault", "key_file", "vault"}

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
	if err := c.Vault.validate(); err != nil {
		return err
	}
	if mv := c.Material.Vault; len(mv.Allow) > 0 || mv.CacheTTL != 0 {
		if err := mv.validate("material.vault", c.Vault.used()); err != nil {
			return err
		}
	}
	if c.Keys.Kind == "vault" && !c.Vault.used() {
		return errors.New("keys: a vault KEK needs vault: (address, auth)")
	}
	if c.Keys.Kind == "azurekeyvault" && c.Azure.Identity == "" {
		return errors.New("keys: azurekeyvault needs azure.identity: managed | workload | default")
	}
	if c.Azure != (Azure{}) {
		if err := c.Azure.validate("azure", false); err != nil {
			return err
		}
	}
	if kv := c.Material.AzKV; len(kv.Allow) > 0 || kv.CacheTTL != 0 || kv.DNSSuffix != "" {
		if c.Azure.Identity == "" {
			return errors.New("material.azkv reads with the service's Azure identity: azure.identity is required")
		}
		if err := kv.validate("material.azkv"); err != nil {
			return err
		}
	}
	if err := c.validateSources(); err != nil {
		return err
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
	if ref := c.State.PasswordRef; strings.HasPrefix(ref, "ref+") {
		scheme, _, _ := strings.Cut(strings.TrimPrefix(ref, "ref+"), "://")
		s, ok := c.Source(scheme)
		switch {
		case !ok:
			return fmt.Errorf("state.password_ref: no source is named %s (material.sources)", scheme)
		case s.Kind == "vault" && !s.Vault.used():
			return errors.New("state.password_ref reads Vault: vault: is required")
		case s.Kind == "azkv" && s.Azure.Identity == "":
			return errors.New("state.password_ref reads Key Vault with the service's Azure identity: azure.identity is required")
		}
	}
	if c.State.PasswordRef != "" && c.admits(c.State.PasswordRef) {
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
			if err := ex.validate(c.Azure.Identity, c.Vault.used()); err != nil {
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
		if s.PasswordRef != "" {
			scheme, _, ok := strings.Cut(strings.TrimPrefix(s.PasswordRef, "ref+"), "://")
			if !ok || !strings.HasPrefix(s.PasswordRef, "ref+") || !material.SchemeName(scheme) {
				return errors.New("state.password_ref is a reference: ref+k8s://, ref+azkv://, ref+vault:// or a named source's")
			}
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
		if (k.KeyEnv == "") == (k.KeyFile == "") || k.Key != "" || k.Mount != "" {
			return errors.New("keys: a local KEK comes from key_env or key_file - one of them")
		}
	case "vault":
		if k.Key == "" || k.KeyEnv != "" || k.KeyFile != "" || strings.Contains(k.Key, "/") {
			return errors.New("keys: a vault KEK is keys.key, a Transit key's name (and keys.mount, default transit)")
		}
		if k.Mount == "" {
			k.Mount = "transit"
		}
	case "azurekeyvault":
		if k.Mount != "" {
			return errors.New("keys.mount is a vault KEK's")
		}
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

// validate checks a vault allowlist; where names it in errors.
func (mv VaultAllow) validate(where string, vaultUsed bool) error {
	if len(mv.Allow) == 0 || !vaultUsed {
		return fmt.Errorf("%s: allow lists the KV mounts references may read, with vault: configured", where)
	}
	for i, a := range mv.Allow {
		if !vaultMount.MatchString(a.Mount) || slices.Contains([]string{"sys", "auth", "identity", "cubbyhole"}, a.Mount) {
			return fmt.Errorf("%s.allow[%d].mount: a KV v2 mount's name, one segment", where, i)
		}
	}
	if mv.CacheTTL < 0 || mv.CacheTTL > 5*time.Minute {
		return fmt.Errorf("%s.cache_ttl is 0 to 5m: the longest a value may be read stale", where)
	}
	return nil
}

// validate checks a Key Vault allowlist; where names it in errors.
func (kv AzKV) validate(where string) error {
	if len(kv.Allow) == 0 {
		return fmt.Errorf("%s: allow lists the vaults references may read - none, no references", where)
	}
	for i, a := range kv.Allow {
		if !azkvVault.MatchString(a.Vault) {
			return fmt.Errorf("%s.allow[%d].vault: a vault's name, 3 to 24 letters, digits or dashes", where, i)
		}
	}
	if kv.CacheTTL < 0 || kv.CacheTTL > 5*time.Minute {
		return fmt.Errorf("%s.cache_ttl is 0 to 5m: the longest a value may be read stale", where)
	}
	if kv.DNSSuffix != "" && !dnsSuffix.MatchString(kv.DNSSuffix) {
		return fmt.Errorf("%s.dns_suffix is a domain's suffix (.vault.azure.net)", where)
	}
	return nil
}

// validateSources checks the named sources (spec 008): a name of their own, a kind, a connection, an allowlist.
func (c *Config) validateSources() error {
	builtin := map[string]bool{
		"azkv":  len(c.Material.AzKV.Allow) > 0,
		"k8s":   len(c.Material.K8s.Allow) > 0,
		"vault": len(c.Material.Vault.Allow) > 0,
	}
	seen := map[string]bool{}
	for i, n := range c.Material.Sources {
		where := fmt.Sprintf("material.sources[%d]", i)
		switch {
		case !material.SchemeName(n.Name):
			return fmt.Errorf("%s.name: the references' scheme - a lower-case letter, then letters, digits or dashes, 16 at most", where)
		case seen[n.Name]:
			return fmt.Errorf("%s.name: %s is named twice", where, n.Name)
		case builtin[n.Name]:
			return fmt.Errorf("%s.name: %s is material.%s's - name the source otherwise", where, n.Name, n.Name)
		case n.Kind == "k8s":
			return fmt.Errorf("%s.kind: k8s reads this cluster only (material.k8s): another would need a kubeconfig's credentials", where)
		case !slices.Contains(NamedSourceKinds, n.Kind):
			return fmt.Errorf("%s.kind is %s", where, strings.Join(NamedSourceKinds, " | "))
		}
		seen[n.Name] = true
		where = "material.sources[" + n.Name + "]"
		s, _ := c.Source(n.Name)
		for i, a := range n.Allow {
			if (n.Kind == "vault") != (a.Mount != "") || (n.Kind == "azkv") != (a.Vault != "") {
				return fmt.Errorf("%s.allow[%d]: a %s source's entries name a %s", where, i, n.Kind,
					map[string]string{"vault": "mount", "azkv": "vault"}[n.Kind])
			}
		}
		switch n.Kind {
		case "vault":
			if n.Azure != nil || n.DNSSuffix != "" {
				return fmt.Errorf("%s: azure and dns_suffix are an azkv source's", where)
			}
			if n.Vault != nil {
				if !n.Vault.used() {
					return fmt.Errorf("%s.vault.address is required", where)
				}
				if err := n.Vault.validate(); err != nil {
					return fmt.Errorf("%s.%w", where, err)
				}
			}
			if err := s.VaultAllow.validate(where, s.Vault.used()); err != nil {
				return err
			}
		case "azkv":
			if n.Vault != nil {
				return fmt.Errorf("%s: vault is a vault source's", where)
			}
			if n.Azure != nil {
				if err := n.Azure.validate(where+".azure", true); err != nil {
					return err
				}
			} else if c.Azure.Identity == "" {
				return fmt.Errorf("%s reads with the service's Azure identity: azure.identity (or its own azure:) is required", where)
			}
			if err := s.AzKV.validate(where); err != nil {
				return err
			}
		}
	}
	return nil
}

// vaultMount is a Vault mount's name: one segment.
var vaultMount = regexp.MustCompile(`^[A-Za-z0-9_-][A-Za-z0-9_.-]{0,127}$`)

// admits says whether a reference's place is within an allowlist, as the sources compare: Kubernetes and Vault
// names exactly, Key Vault names without case. It errs toward admitting: a reference that does not parse may be
// said admitted, and the service refuses it at start anyway.
func (c *Config) admits(ref string) bool {
	scheme, rest, ok := strings.Cut(strings.TrimPrefix(ref, "ref+"), "://")
	if !ok || !strings.HasPrefix(ref, "ref+") {
		return false
	}
	s, ok := c.Source(scheme)
	if !ok {
		return false
	}
	switch s.Kind {
	case "k8s":
		parts := strings.Split(rest, "/")
		for _, a := range s.K8s.Allow {
			if len(parts) == 3 && a.Namespace == parts[0] && (len(a.Prefixes) == 0 ||
				slices.ContainsFunc(a.Prefixes, func(p string) bool { return strings.HasPrefix(parts[1], p) })) {
				return true
			}
		}
	case "vault":
		where, _, _ := strings.Cut(rest, "#")
		mount, path, _ := strings.Cut(where, "/")
		for _, a := range s.VaultAllow.Allow {
			if a.Mount == mount && (len(a.Prefixes) == 0 ||
				slices.ContainsFunc(a.Prefixes, func(p string) bool { return strings.HasPrefix(path, p) })) {
				return true
			}
		}
	case "azkv":
		parts := strings.Split(rest, "/")
		for _, a := range s.AzKV.Allow {
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
func (ex *ExchangeClient) validate(identity string, vaultUsed bool) error {
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
		"key": ex.Key != "", "key_file": ex.KeyFile != "", "kid": ex.KID != "", "x5t": ex.X5T != "",
		"assertion_audience": ex.AssertionAudience != ""}
	allowed := map[string][]string{
		"secret":   {"client_secret_env"},
		"azure":    {},
		"file":     {"assertion_file"},
		"keyvault": {"key", "kid", "x5t", "assertion_audience"},
		"key_file": {"key_file", "kid", "x5t", "assertion_audience"},
		"vault":    {"key", "kid", "x5t", "assertion_audience"},
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
		if ex.Key == "" || (ex.KID == "" && ex.X5T == "") {
			return errors.New("exchange.client_auth: keyvault signs with key (a Key Vault key URL), named by kid or x5t")
		}
		if identity == "" {
			return errors.New("exchange.client_auth: keyvault signs with the service's Azure identity: azure.identity is required")
		}
	case "vault":
		if mount, key, ok := strings.Cut(ex.Key, "/"); !ok || !vaultMount.MatchString(mount) || !vaultMount.MatchString(key) ||
			(ex.KID == "" && ex.X5T == "") {
			return errors.New("exchange.client_auth: vault signs with key (<mount>/<key>: a Transit key, each one segment), named by kid or x5t")
		}
		if !vaultUsed {
			return errors.New("exchange.client_auth: vault signs in Vault: vault: is required")
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
