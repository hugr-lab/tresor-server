package sqlstore

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"

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
