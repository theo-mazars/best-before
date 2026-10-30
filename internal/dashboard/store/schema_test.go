package store

import (
	"context"
	"strings"
	"testing"
	"time"
)

// These tests check that the schema itself refuses bad data, independently
// of the Go code in front of it.

const insertUser = `INSERT INTO users (id, email, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?)`

func TestSchemaUsers(t *testing.T) {
	ctx := context.Background()
	s, _ := openTest(t)
	now := unix(time.Now())

	if _, err := s.db.ExecContext(ctx, insertUser, newID(), "theo@example.org", "$argon2id$…", "admin", now); err != nil {
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
		"unknown role":    {insertUser, []any{newID(), "b@example.org", "x", "superadmin", now}, "CHECK"},
		"email by case":   {insertUser, []any{newID(), "THEO@example.org", "x", "user", now}, "UNIQUE"},
		"not an email":    {insertUser, []any{newID(), "theo", "x", "user", now}, "CHECK"},
		"short ID":        {insertUser, []any{"abc", "c@example.org", "x", "user", now}, "CHECK"},
		"NULL ID":         {insertUser, []any{nil, "d@example.org", "x", "user", now}, "NOT NULL"},
		"wrong type":      {insertUser, []any{newID(), "e@example.org", "x", "user", "yesterday"}, "cannot store TEXT value in INTEGER column"},
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
	if _, err := s.db.ExecContext(ctx, insertUser, newID(), "f@example.org", "x", "user", now); err != nil {
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
