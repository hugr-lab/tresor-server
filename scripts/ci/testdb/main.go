// testdb is conformance's database helper (scripts/ci/conformance.sh), not shipped:
//
//	testdb create <kind> <admin dsn>          a fresh database; prints its DSN
//	testdb drop <kind> <admin dsn> <dsn>      drops it
//	testdb clear <kind> <dsn> <text>          fails when any column of any table holds text in the clear
//
// kind is postgres or sqlserver. The password is in TRESOR_TEST_POSTGRES_PASSWORD or
// TRESOR_TEST_SQLSERVER_PASSWORD, never in a DSN.
package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log"
	"net/url"
	"os"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	mssql "github.com/microsoft/go-mssqldb"
	"github.com/microsoft/go-mssqldb/msdsn"
)

func open(kind, dsn string) *sql.DB {
	switch kind {
	case "postgres":
		cfg, err := pgx.ParseConfig(dsn)
		if err != nil {
			log.Fatalf("testdb: %v", err)
		}
		cfg.Password = os.Getenv("TRESOR_TEST_POSTGRES_PASSWORD")
		return stdlib.OpenDB(*cfg)
	case "sqlserver":
		cfg, err := msdsn.Parse(dsn)
		if err != nil {
			log.Fatalf("testdb: %v", err)
		}
		cfg.Password = os.Getenv("TRESOR_TEST_SQLSERVER_PASSWORD")
		return sql.OpenDB(mssql.NewConnectorConfig(cfg))
	}
	log.Fatalf("testdb: no kind %s", kind)
	return nil
}

// withDatabase is dsn naming another database.
func withDatabase(kind, dsn, name string) string {
	u, err := url.Parse(dsn)
	if err != nil {
		log.Fatalf("testdb: %v", err)
	}
	if kind == "postgres" {
		u.Path = "/" + name
	} else {
		q := u.Query()
		q.Set("database", name)
		u.RawQuery = q.Encode()
	}
	return u.String()
}

func databaseOf(kind, dsn string) string {
	u, err := url.Parse(dsn)
	if err != nil {
		log.Fatalf("testdb: %v", err)
	}
	if kind == "postgres" {
		return strings.TrimPrefix(u.Path, "/")
	}
	return u.Query().Get("database")
}

func main() {
	if len(os.Args) < 4 {
		log.Fatal("usage: testdb create <kind> <admin dsn> | drop <kind> <admin dsn> <dsn> | clear <kind> <dsn> <text>")
	}
	ctx := context.Background()
	command, kind := os.Args[1], os.Args[2]
	switch command {
	case "create":
		raw := make([]byte, 6)
		_, _ = rand.Read(raw)
		name := "tresor_conformance_" + hex.EncodeToString(raw)
		db := open(kind, os.Args[3])
		defer db.Close()
		if _, err := db.ExecContext(ctx, `CREATE DATABASE `+name); err != nil {
			log.Fatalf("testdb: %v", err)
		}
		fmt.Println(withDatabase(kind, os.Args[3], name))
	case "drop":
		name := databaseOf(kind, os.Args[4])
		if !strings.HasPrefix(name, "tresor_conformance_") {
			log.Fatalf("testdb: %s is not a database testdb made", name)
		}
		db := open(kind, os.Args[3])
		defer db.Close()
		drop := `DROP DATABASE IF EXISTS ` + name + ` WITH (FORCE)`
		if kind == "sqlserver" {
			drop = `ALTER DATABASE ` + name + ` SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE ` + name
		}
		if _, err := db.ExecContext(ctx, drop); err != nil {
			log.Fatalf("testdb: %v", err)
		}
	case "clear":
		db := open(kind, os.Args[3])
		defer db.Close()
		if err := clear(ctx, kind, db, os.Args[4]); err != nil {
			log.Fatalf("testdb: %v", err)
		}
	default:
		log.Fatalf("testdb: no command %s", command)
	}
}

// clear looks for text in every column of every table, as text and as bytes.
func clear(ctx context.Context, kind string, db *sql.DB, text string) error {
	schema := "public"
	if kind == "sqlserver" {
		schema = "dbo"
	}
	rows, err := db.QueryContext(ctx, `SELECT table_name, column_name, data_type FROM information_schema.columns
		WHERE table_schema = '`+schema+`'`)
	if err != nil {
		return err
	}
	type column struct{ table, name, typ string }
	var columns []column
	for rows.Next() {
		var c column
		if err := rows.Scan(&c.table, &c.name, &c.typ); err != nil {
			return err
		}
		columns = append(columns, c)
	}
	rows.Close()
	if len(columns) == 0 {
		return fmt.Errorf("no tables: nothing was written")
	}
	for _, c := range columns {
		var query string
		switch {
		case kind == "postgres" && c.typ == "bytea":
			query = fmt.Sprintf(`SELECT count(*) FROM %q WHERE position(convert_to($1, 'UTF8') in %q) > 0`, c.table, c.name)
		case kind == "postgres":
			query = fmt.Sprintf(`SELECT count(*) FROM %q WHERE strpos(%q::text, $1) > 0`, c.table, c.name)
		case c.typ == "varbinary":
			// the parameter comes as NVARCHAR (UTF-16): its bytes are the stored ones only as VARCHAR (UTF-8/ASCII)
			query = fmt.Sprintf(`SELECT count(*) FROM [%s] WHERE CHARINDEX(CAST(CAST(@p1 AS VARCHAR(MAX)) AS VARBINARY(MAX)), [%s]) > 0`, c.table, c.name)
		default:
			query = fmt.Sprintf(`SELECT count(*) FROM [%s] WHERE CHARINDEX(@p1, CAST([%s] AS NVARCHAR(MAX))) > 0`, c.table, c.name)
		}
		var n int
		if err := db.QueryRowContext(ctx, query, text).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			return fmt.Errorf("%s.%s holds it in the clear", c.table, c.name)
		}
	}
	return nil
}
