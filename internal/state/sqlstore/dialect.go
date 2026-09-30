package sqlstore

import (
	"embed"
	"errors"

	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

//go:embed migrations
var migrations embed.FS

// Dialect is what differs between the databases (spec 002): the driver, the placeholders, the migrations'
// DDL, which errors mean what, and whether the database allows several writers.
type Dialect struct {
	Name string
	// Rebind turns a query written with `?` into the database's placeholders.
	Rebind func(query string) string
	// Unique says whether err is a unique (or primary key) violation: another writer created the row first.
	Unique func(err error) bool
	// SingleWriter: one replica only, held by the lease row (SQLite).
	SingleWriter bool
}

// SQLite is modernc.org/sqlite: pure Go, one writer.
var SQLite = Dialect{
	Name:   "sqlite",
	Rebind: func(q string) string { return q },
	Unique: func(err error) bool {
		var se *sqlite.Error
		if !errors.As(err, &se) {
			return false
		}
		return se.Code() == sqlite3.SQLITE_CONSTRAINT_UNIQUE || se.Code() == sqlite3.SQLITE_CONSTRAINT_PRIMARYKEY
	},
	SingleWriter: true,
}
