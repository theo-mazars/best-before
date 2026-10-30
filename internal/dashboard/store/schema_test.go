package store

import (
	"context"
	"strings"
	"testing"
	"time"
)

// These tests check that the schema itself refuses bad data, independently
// of the Go code in front of it.

const insertUserRow = `INSERT INTO users (id, email, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?)`

func TestSchemaUsers(t *testing.T) {
	ctx := context.Background()
	s, _ := openTest(t)
	now := unix(time.Now())

	if _, err := s.db.ExecContext(ctx, insertUserRow, newID(), "theo@example.org", "$argon2id$…", "admin", now); err != nil {
		t.Fatal(err)
	}

	for name, tc := range map[string]struct {
		query string
		args  []any
		want  string
	}{
		"no role": {
			`INSERT INTO users (id, email, password_hash, created_at) VALUES (?, ?, ?, ?)`,
			[]any{newID(), "a@example.org", "x", now}, "NOT NULL",
		},
		"unknown role":    {insertUserRow, []any{newID(), "b@example.org", "x", "superadmin", now}, "CHECK"},
		"email by case":   {insertUserRow, []any{newID(), "THEO@example.org", "x", "user", now}, "UNIQUE"},
		"not an email":    {insertUserRow, []any{newID(), "theo", "x", "user", now}, "CHECK"},
		"short ID":        {insertUserRow, []any{"abc", "c@example.org", "x", "user", now}, "CHECK"},
		"NULL ID":         {insertUserRow, []any{nil, "d@example.org", "x", "user", now}, "NOT NULL"},
		"wrong type":      {insertUserRow, []any{newID(), "e@example.org", "x", "user", "yesterday"}, "cannot store TEXT value in INTEGER column"},
		"short TOTP seed": {`UPDATE users SET totp_secret = ?`, []any{[]byte("short")}, "CHECK"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := s.db.ExecContext(ctx, tc.query, tc.args...)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("got %v, want an error containing %q", err, tc.want)
			}
		})
	}

	// Both roles are accepted when set explicitly.
	if _, err := s.db.ExecContext(ctx, insertUserRow, newID(), "f@example.org", "x", "user", now); err != nil {
		t.Errorf("user role: %v", err)
	}
}

func TestNewIDs(t *testing.T) {
	seen := map[string]bool{}
	for range 1000 {
		id := newID()
		if len(id) != 26 || strings.ToLower(id) != id || seen[id] {
			t.Fatalf("bad or repeated ID %q", id)
		}
		seen[id] = true
	}
}
