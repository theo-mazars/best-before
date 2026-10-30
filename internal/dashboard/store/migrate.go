package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"embed"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path"
	"regexp"
	"sort"
	"strconv"
	"time"
)

// Released migrations must never be edited: their checksums are recorded and
// checked at every start. Fix a released migration with a new one.
//
//go:embed migrations/*.sql
var migrationFiles embed.FS

const (
	createMigrationsTable = `CREATE TABLE IF NOT EXISTS schema_migrations (
		version    INTEGER NOT NULL PRIMARY KEY,
		name       TEXT    NOT NULL,
		checksum   TEXT    NOT NULL,
		applied_at INTEGER NOT NULL
	) STRICT`
	selectMigrations = `SELECT version, checksum FROM schema_migrations`
	insertMigration  = `INSERT INTO schema_migrations (version, name, checksum, applied_at) VALUES (?, ?, ?, ?)`
	backupInto       = `VACUUM INTO ?`
)

var migrationName = regexp.MustCompile(`^(\d{4})_([a-z0-9_]+)\.sql$`)

type migration struct {
	version  int
	name     string
	sql      string
	checksum string
}

func loadMigrations(fsys fs.FS) ([]migration, error) {
	entries, err := fs.ReadDir(fsys, "migrations")
	if err != nil {
		return nil, err
	}
	var migs []migration
	for _, e := range entries {
		m := migrationName.FindStringSubmatch(e.Name())
		if m == nil {
			return nil, fmt.Errorf("migration %q: name must look like 0001_description.sql", e.Name())
		}
		data, err := fs.ReadFile(fsys, path.Join("migrations", e.Name()))
		if err != nil {
			return nil, err
		}
		version, _ := strconv.Atoi(m[1])
		sum := sha256.Sum256(data)
		migs = append(migs, migration{version: version, name: e.Name(), sql: string(data), checksum: hex.EncodeToString(sum[:])})
	}
	sort.Slice(migs, func(i, j int) bool { return migs[i].version < migs[j].version })
	for i, m := range migs {
		if m.version != i+1 {
			return nil, fmt.Errorf("migration %s: expected number %04d; migrations must be numbered from 0001 without gaps or duplicates", m.name, i+1)
		}
	}
	return migs, nil
}

// migrate applies pending migrations, backing up a non-empty database first.
func (s *Store) migrate(ctx context.Context, fsys fs.FS) error {
	migs, err := loadMigrations(fsys)
	if err != nil {
		return err
	}

	if _, err := s.db.ExecContext(ctx, createMigrationsTable); err != nil {
		return err
	}

	applied := map[int]string{}
	rows, err := s.db.QueryContext(ctx, selectMigrations)
	if err != nil {
		return err
	}
	for rows.Next() {
		var v int
		var sum string
		if err := rows.Scan(&v, &sum); err != nil {
			rows.Close()
			return err
		}
		applied[v] = sum
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	for v, sum := range applied {
		if v > len(migs) {
			return fmt.Errorf("the database has migration %04d, which this version of the dashboard does not know; was it opened by a newer version?", v)
		}
		if migs[v-1].checksum != sum {
			return fmt.Errorf("migration %s has changed since it was applied; released migrations must never be edited", migs[v-1].name)
		}
	}

	pending := migs[len(applied):]
	if len(pending) == 0 {
		return nil
	}
	if len(applied) > 0 {
		if err := s.backup(ctx, fmt.Sprintf("before-%04d", pending[0].version)); err != nil {
			return fmt.Errorf("backing up before migrating: %w", err)
		}
	}
	for _, m := range pending {
		err := s.tx(ctx, func(tx *sql.Tx) error {
			if _, err := tx.ExecContext(ctx, m.sql); err != nil { // sqlconst:trusted
				return err
			}
			_, err := tx.ExecContext(ctx, insertMigration, m.version, m.name, m.checksum, unix(time.Now()))
			return err
		})
		if err != nil {
			return fmt.Errorf("migration %s: %w", m.name, err)
		}
	}
	return nil
}

func (s *Store) backup(ctx context.Context, label string) error {
	dest := fmt.Sprintf("%s.%s.%s.bak", s.path, label, time.Now().UTC().Format("20060102T150405Z"))
	if _, err := s.db.ExecContext(ctx, backupInto, dest); err != nil {
		return err
	}
	return os.Chmod(dest, 0o600)
}
