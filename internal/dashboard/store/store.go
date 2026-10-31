// Package store keeps the dashboard's state in a single SQLite file.
package store

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"os"
	"time"

	_ "modernc.org/sqlite"
)

var (
	ErrNotFound        = errors.New("not found")
	ErrCodeInvalid     = errors.New("enrolment code is unknown")
	ErrCodeUsed        = errors.New("enrolment code has already been used")
	ErrCodeExpired     = errors.New("enrolment code has expired")
	ErrAlreadyEnrolled = errors.New("this agent key is already enrolled")
	ErrStaleSequence   = errors.New("sequence number already used, or agent revoked")
)

type Store struct {
	db   *sql.DB
	path string
}

// Open opens or creates the database and brings its schema up to date.
func Open(ctx context.Context, path string) (*Store, error) {
	// The database maps every vulnerable package on every server. SQLite gives
	// its journal files the same permissions.
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	f.Close()

	dsn := "file:" + url.PathEscape(path) +
		"?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// Writes are serialised anyway; one connection avoids "database is locked".
	db.SetMaxOpenConns(1)

	s := &Store{db: db, path: path}
	if err := s.migrate(ctx, migrationFiles); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) tx(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}

func unix(t time.Time) int64 { return t.UTC().Unix() }

func fromUnix(v sql.NullInt64) *time.Time {
	if !v.Valid {
		return nil
	}
	t := time.Unix(v.Int64, 0).UTC()
	return &t
}
