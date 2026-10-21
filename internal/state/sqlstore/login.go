package sqlstore

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/aws/aws-sdk-go-v2/aws"
	rdsauth "github.com/aws/aws-sdk-go-v2/feature/rds/auth"
	"golang.org/x/oauth2"

	"github.com/hugr-lab/tresor-server/internal/config"
)

// Login is how the service logs in to its database, asked again for each new connection (spec 002): a
// rotated password or a renewed token needs no restart.
type Login interface {
	Password(ctx context.Context) (string, error)
}

// The Entra token scopes of the Azure databases.
const (
	ScopePostgres  = "https://ossrdbms-aad.database.windows.net/.default"
	ScopeSQLServer = "https://database.windows.net/.default"
)

// EntraLogin is the service's Entra token as the password (Azure Database for PostgreSQL, Azure SQL): its
// managed identity, no secret at all.
type EntraLogin struct {
	Credential azcore.TokenCredential
	Scope      string
}

func (l EntraLogin) Password(ctx context.Context) (string, error) {
	token, err := l.Credential.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{l.Scope}})
	if err != nil {
		return "", errors.New("the database login: the service's Azure credential did not get a token")
	}
	return token.Token, nil
}

// PasswordLogin reads a password from an environment variable or a file, each time.
type PasswordLogin struct {
	Env  string
	File string
}

func (l PasswordLogin) Password(context.Context) (string, error) {
	if l.Env != "" {
		if pw := os.Getenv(l.Env); pw != "" {
			return pw, nil
		}
		return "", fmt.Errorf("the database login: %s is empty", l.Env)
	}
	data, err := os.ReadFile(l.File)
	if err != nil {
		return "", fmt.Errorf("the database login: %w", err)
	}
	if pw := strings.TrimRight(string(data), "\r\n"); pw != "" {
		return pw, nil
	}
	return "", fmt.Errorf("the database login: %s is empty", l.File)
}

// RefLogin reads the password a reference names (state.password_ref: a Kubernetes Secret, a Key Vault secret),
// each time.
type RefLogin struct {
	Resolve func(ctx context.Context) (string, error)
}

func (l RefLogin) Password(ctx context.Context) (string, error) {
	pw, err := l.Resolve(ctx)
	if err != nil {
		return "", fmt.Errorf("the database login: %w", err)
	}
	if pw == "" {
		return "", errors.New("the database login: state.password_ref names an empty value")
	}
	return pw, nil
}

// dsnHasPassword says whether a DSN carries a password: never allowed - the password comes from the Login.
func dsnHasPassword(dsn string) bool { return config.DSNHasPassword(dsn) }

// AWSLogin is an RDS IAM authentication token as the password (RDS, Aurora PostgreSQL; spec 012): made by the
// service's AWS identity for each new connection, valid 15 minutes, never stored. TLS is required by RDS for it.
type AWSLogin struct {
	Endpoint    string // host:port, as the DSN names the server
	Region      string
	User        string
	Credentials aws.CredentialsProvider
}

func (l AWSLogin) Password(ctx context.Context) (string, error) {
	token, err := rdsauth.BuildAuthToken(ctx, l.Endpoint, l.Region, l.User, l.Credentials)
	if err != nil {
		return "", fmt.Errorf("the database login: the service's AWS identity did not sign an RDS token: %w", err)
	}
	return token, nil
}

// ScopeCloudSQL is the scope of a Cloud SQL IAM database login's token.
const ScopeCloudSQL = "https://www.googleapis.com/auth/sqlservice.login"

// GCPLogin is the service account's OAuth token as the password (Cloud SQL for PostgreSQL, IAM database
// authentication; spec 012): the token source renews it, nothing is stored.
type GCPLogin struct {
	Tokens oauth2.TokenSource
}

func (l GCPLogin) Password(context.Context) (string, error) {
	t, err := l.Tokens.Token()
	if err != nil {
		return "", errors.New("the database login: the service's GCP identity did not get a token")
	}
	return t.AccessToken, nil
}

// UserLogin is a login that names the user too, for each new connection (a database secrets engine's: spec 027).
type UserLogin interface {
	Login
	Credentials(ctx context.Context) (user, password string, err error)
}

// ConnLifetime is a connection's longest life: a login's credentials must outlive the connections made with them.
const ConnLifetime = 30 * time.Minute

// vaultMargin: new credentials are fetched this long before a connection made with the current ones could outlive
// their lease.
const vaultMargin = 2 * time.Minute

// VaultCredentials are a lease of a database secrets engine: a user, a password, and how long they live.
type VaultCredentials struct {
	User, Password string
	Lease          time.Duration
}

// VaultLogin logs in with a database secrets engine's credentials (spec 027): a user and a password Vault made for
// this service, used for every new connection while a connection made with them ends (ConnLifetime) before their
// lease does; then new ones. Old leases are left to expire: a connection still open with them keeps working. The
// credentials are never logged.
type VaultLogin struct {
	Fetch func(ctx context.Context) (VaultCredentials, error)
	Now   func() time.Time

	mu      sync.Mutex
	current VaultCredentials
	until   time.Time // new connections take the current credentials until then
}

func (l *VaultLogin) Credentials(ctx context.Context) (string, string, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.Now()
	if l.current.User != "" && now.Before(l.until) {
		return l.current.User, l.current.Password, nil
	}
	c, err := l.Fetch(ctx)
	if err != nil {
		return "", "", fmt.Errorf("the database login: Vault gave no credentials: %w", err)
	}
	if c.User == "" || c.Password == "" {
		return "", "", errors.New("the database login: Vault gave no user or no password")
	}
	usable := c.Lease - ConnLifetime - vaultMargin
	if usable <= 0 {
		return "", "", fmt.Errorf("the database login: the role's credentials live %s - more than %s is needed (the "+
			"connections live %s): raise the role's default_ttl", c.Lease, ConnLifetime+vaultMargin, ConnLifetime)
	}
	l.current, l.until = c, now.Add(usable)
	return c.User, c.Password, nil
}

func (l *VaultLogin) Password(ctx context.Context) (string, error) {
	_, pw, err := l.Credentials(ctx)
	return pw, err
}
