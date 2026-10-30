package store

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
)

func files(migs ...string) fstest.MapFS {
	fsys := fstest.MapFS{}
	for i := 0; i < len(migs); i += 2 {
		fsys["migrations/"+migs[i]] = &fstest.MapFile{Data: []byte(migs[i+1])}
	}
	return fsys
}

// rawStore opens a database without applying the embedded migrations.
func rawStore(t *testing.T, path string) *Store {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	return &Store{db: db, path: path}
}

func tables(t *testing.T, s *Store) string {
	t.Helper()
	rows, err := s.db.Query(`SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var n string
		rows.Scan(&n)
		names = append(names, n)
	}
	return strings.Join(names, ",")
}

func TestEmbeddedMigrationsAreValid(t *testing.T) {
	migs, err := loadMigrations(migrationFiles)
	if err != nil {
		t.Fatal(err)
	}
	if len(migs) == 0 || migs[0].name != "0001_initial.sql" {
		t.Errorf("migrations: %+v", migs)
	}
}

func TestMigrateAppliesInOrderOnce(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "test.db")
	s := rawStore(t, path)

	v1 := files("0001_a.sql", "CREATE TABLE a (x);")
	if err := s.migrate(ctx, v1); err != nil {
		t.Fatal(err)
	}
	// Running again changes nothing and makes no backup.
	if err := s.migrate(ctx, v1); err != nil {
		t.Fatal(err)
	}
	if backups, _ := filepath.Glob(path + ".*.bak"); len(backups) != 0 {
		t.Errorf("backup made with nothing to apply: %v", backups)
	}

	v2 := files("0001_a.sql", "CREATE TABLE a (x);", "0002_b.sql", "CREATE TABLE b (y); INSERT INTO a VALUES (1);")
	if err := s.migrate(ctx, v2); err != nil {
		t.Fatal(err)
	}
	if got := tables(t, s); got != "a,b,schema_migrations" {
		t.Errorf("tables: %s", got)
	}

	// Upgrading a database with data backs it up first, privately.
	backups, _ := filepath.Glob(path + ".before-0002.*.bak")
	if len(backups) != 1 {
		t.Fatalf("backups: %v", backups)
	}
	info, err := os.Stat(backups[0])
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("backup mode %v, err %v", info.Mode().Perm(), err)
	}
	if got := tables(t, rawStore(t, backups[0])); got != "a,schema_migrations" {
		t.Errorf("backup holds %s, want the schema before migration 0002", got)
	}
}

func TestMigrateRefusals(t *testing.T) {
	ctx := context.Background()
	base := files("0001_a.sql", "CREATE TABLE a (x);", "0002_b.sql", "CREATE TABLE b (y);")

	for name, tc := range map[string]struct {
		files fstest.MapFS
		want  string
	}{
		"edited migration": {files("0001_a.sql", "CREATE TABLE a (x, z);", "0002_b.sql", "CREATE TABLE b (y);"), "has changed"},
		"older dashboard":  {files("0001_a.sql", "CREATE TABLE a (x);"), "does not know"},
	} {
		t.Run(name, func(t *testing.T) {
			s := rawStore(t, filepath.Join(t.TempDir(), "test.db"))
			if err := s.migrate(ctx, base); err != nil {
				t.Fatal(err)
			}
			if err := s.migrate(ctx, tc.files); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("got %v, want an error containing %q", err, tc.want)
			}
		})
	}
}

func TestLoadMigrationsRejectsBadSets(t *testing.T) {
	for name, fsys := range map[string]fstest.MapFS{
		"gap":          files("0001_a.sql", "", "0003_c.sql", ""),
		"duplicate":    files("0001_a.sql", "", "0001_b.sql", ""),
		"starts at 2":  files("0002_b.sql", ""),
		"bad name":     files("1_a.sql", ""),
		"not sql":      files("0001_a.txt", ""),
		"capital name": files("0001_Add.sql", ""),
	} {
		if _, err := loadMigrations(fsys); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestFailedMigrationLeavesNoTrace(t *testing.T) {
	ctx := context.Background()
	s := rawStore(t, filepath.Join(t.TempDir(), "test.db"))
	bad := files("0001_a.sql", "CREATE TABLE a (x); THIS IS NOT SQL;")
	if err := s.migrate(ctx, bad); err == nil {
		t.Fatal("broken migration applied")
	}
	if got := tables(t, s); got != "schema_migrations" {
		t.Errorf("tables after failed migration: %s", got)
	}

	// Once fixed, it applies cleanly.
	if err := s.migrate(ctx, files("0001_a.sql", "CREATE TABLE a (x);")); err != nil {
		t.Fatal(err)
	}
}
