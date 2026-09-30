package sqlstore

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"time"

	mssql "github.com/microsoft/go-mssqldb"
	"github.com/microsoft/go-mssqldb/msdsn"

	"github.com/hugr-lab/tresor-server/internal/config"
	"github.com/hugr-lab/tresor-server/internal/keys"
)

// OpenSQLServer opens a SQL Server or Azure SQL database (spec 002): several replicas. The DSN names the
// server and the database (and a user for a password login), never a password: login gives it, for each new
// connection - on Azure SQL an Entra access token (managed identity), no password at all.
func OpenSQLServer(ctx context.Context, dsn string, login Login, maxOpen int, wrapper keys.KeyWrapper, opts Options) (*Store, error) {
	if dsnHasPassword(dsn) {
		return nil, errors.New("state.dsn: a DSN carries no password - it comes from state.auth")
	}
	cfg, err := msdsn.Parse(dsn)
	if err != nil {
		return nil, errors.New("state.dsn: not a SQL Server DSN") // its text may hold what it should not
	}
	// the login - a password or an Entra token - goes over this connection: off this machine, only encrypted,
	// with the server's certificate checked
	if !config.IsLoopback(cfg.Host) && (cfg.Encryption != msdsn.EncryptionRequired && cfg.Encryption != msdsn.EncryptionStrict ||
		cfg.TLSConfig == nil || cfg.TLSConfig.InsecureSkipVerify) {
		return nil, errors.New("state.dsn: encrypt=true (or strict) and no trustservercertificate are required for a server off this machine")
	}
	var connector driver.Connector
	if entra, ok := login.(EntraLogin); ok {
		connector, err = mssql.NewConnectorWithAccessTokenProvider(dsn, entra.Password)
		if err != nil {
			return nil, errors.New("state.dsn: not a SQL Server DSN")
		}
	} else {
		connector = &passwordConnector{cfg: cfg, login: login}
	}
	db := sql.OpenDB(connector)
	if maxOpen <= 0 {
		maxOpen = 10
	}
	db.SetMaxOpenConns(maxOpen)
	db.SetMaxIdleConns(maxOpen)
	db.SetConnMaxLifetime(30 * time.Minute) // a connection's token expires; a new one logs in afresh
	pingCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := db.PingContext(pingCtx); err != nil {
		db.Close()
		return nil, fmt.Errorf("state: the SQL Server database: %w", err)
	}
	s, err := open(ctx, db, SQLServer, wrapper, opts)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("state: %w", err)
	}
	return s, nil
}

// passwordConnector logs in with the password the login gives at each new connection: a rotation needs no
// restart.
type passwordConnector struct {
	cfg   msdsn.Config
	login Login
}

func (c *passwordConnector) Connect(ctx context.Context) (driver.Conn, error) {
	pw, err := c.login.Password(ctx)
	if err != nil {
		return nil, err
	}
	cfg := c.cfg
	cfg.Password = pw
	return mssql.NewConnectorConfig(cfg).Connect(ctx)
}

func (c *passwordConnector) Driver() driver.Driver { return &mssql.Driver{} }
