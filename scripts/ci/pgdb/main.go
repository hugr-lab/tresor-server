// pgdb is conformance's PostgreSQL helper (scripts/ci/conformance.sh), not shipped:
//
//	pgdb create <admin dsn>            a fresh database; prints its DSN
//	pgdb drop <admin dsn> <dsn>        drops it
//	pgdb clear <dsn> <text>            fails when any column of any table holds text in the clear
//
// The password is in TRESOR_TEST_POSTGRES_PASSWORD, never in a DSN.
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
)

func open(dsn string) *sql.DB {
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		log.Fatalf("pgdb: %v", err)
	}
	cfg.Password = os.Getenv("TRESOR_TEST_POSTGRES_PASSWORD")
	return stdlib.OpenDB(*cfg)
}

func dbName(dsn string) string {
	u, err := url.Parse(dsn)
	if err != nil {
		log.Fatalf("pgdb: %v", err)
	}
	return strings.TrimPrefix(u.Path, "/")
}

func main() {
	if len(os.Args) < 3 {
		log.Fatal("usage: pgdb create <admin dsn> | drop <admin dsn> <dsn> | clear <dsn> <text>")
	}
	ctx := context.Background()
	switch os.Args[1] {
	case "create":
		raw := make([]byte, 6)
		_, _ = rand.Read(raw)
		name := "tresor_conformance_" + hex.EncodeToString(raw)
		db := open(os.Args[2])
		defer db.Close()
		if _, err := db.ExecContext(ctx, `CREATE DATABASE `+name); err != nil {
			log.Fatalf("pgdb: %v", err)
		}
		u, _ := url.Parse(os.Args[2])
		u.Path = "/" + name
		fmt.Println(u.String())
	case "drop":
		name := dbName(os.Args[3])
		if !strings.HasPrefix(name, "tresor_conformance_") {
			log.Fatalf("pgdb: %s is not a database pgdb made", name)
		}
		db := open(os.Args[2])
		defer db.Close()
		if _, err := db.ExecContext(ctx, `DROP DATABASE IF EXISTS `+name+` WITH (FORCE)`); err != nil {
			log.Fatalf("pgdb: %v", err)
		}
	case "clear":
		db := open(os.Args[2])
		defer db.Close()
		if err := clear(ctx, db, os.Args[3]); err != nil {
			log.Fatalf("pgdb: %v", err)
		}
	default:
		log.Fatalf("pgdb: no command %s", os.Args[1])
	}
}

// clear looks for text in every column of every table of the public schema, as text and as bytes.
func clear(ctx context.Context, db *sql.DB, text string) error {
	rows, err := db.QueryContext(ctx, `SELECT table_name, column_name, data_type FROM information_schema.columns
		WHERE table_schema = 'public'`)
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
		expr := fmt.Sprintf(`strpos(%q::text, $1) > 0`, c.name)
		if c.typ == "bytea" {
			expr = fmt.Sprintf(`position(convert_to($1, 'UTF8') in %q) > 0`, c.name)
		}
		var n int
		if err := db.QueryRowContext(ctx, fmt.Sprintf(`SELECT count(*) FROM %q WHERE %s`, c.table, expr), text).
			Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			return fmt.Errorf("%s.%s holds it in the clear", c.table, c.name)
		}
	}
	return nil
}
