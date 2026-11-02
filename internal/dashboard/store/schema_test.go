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

func TestSchemaAlerts(t *testing.T) {
	ctx := context.Background()
	s, _ := openTest(t)
	now := time.Now()
	agentID := newID()
	if _, err := s.db.ExecContext(ctx, insertAgent, agentID, []byte(newKey(t)), "web-01", "v1", unix(now), "10.0.0.1"); err != nil {
		t.Fatal(err)
	}

	for name, tc := range map[string]struct {
		query string
		args  []any
		want  string
	}{
		"stale with a vulnerability": {insertAlert, []any{agentID, "stale", "CVE-2026-0001", unix(now)}, "CHECK"},
		"emergency without one":      {insertAlert, []any{agentID, "emergency", "", unix(now)}, "CHECK"},
		"unknown kind":               {insertAlert, []any{agentID, "panic", "CVE-2026-0001", unix(now)}, "CHECK"},
		"second settings row":        {`INSERT INTO alert_settings SELECT 2, emergency_known_exploited, emergency_min_cvss, reminder_days, digest_weekday, digest_minute, digest_timezone, digest_sent_at, digest_emergencies, digest_stale, digest_updates, digest_new_min_severity, digest_accepted, digest_all_clear FROM alert_settings`, nil, "CHECK"},
		"CVSS above 10":              {`UPDATE alert_settings SET emergency_min_cvss = 10.5`, nil, "CHECK"},
		"unknown severity":           {`UPDATE alert_settings SET digest_new_min_severity = 'unknown'`, nil, "CHECK"},
		"digest at 24:00":            {`UPDATE alert_settings SET digest_minute = 1440`, nil, "CHECK"},
		"unknown channel type":       {insertChannel, []any{newID(), "fax", "Fax", "{}", []byte{1}, 1, 0, unix(now), unix(now)}, "CHECK"},
		"settings not an object":     {insertChannel, []any{newID(), "email", "Mail", "[]", []byte{1}, 1, 0, unix(now), unix(now)}, "CHECK"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := s.db.ExecContext(ctx, tc.query, tc.args...)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("got %v, want an error containing %q", err, tc.want)
			}
		})
	}

	// An alert is raised once.
	al := &Alert{AgentID: agentID, Kind: AlertEmergency, Vulnerability: "CVE-2026-0001", RaisedAt: now}
	s.RaiseAlert(ctx, al)
	s.RaiseAlert(ctx, &Alert{AgentID: agentID, Kind: AlertEmergency, Vulnerability: "CVE-2026-0001", RaisedAt: now.Add(time.Hour)})
	if got, _ := s.Alerts(ctx); len(got) != 1 || !got[0].RaisedAt.Equal(time.Unix(unix(now), 0)) || got[0].NotifiedAt != nil {
		t.Errorf("alerts: %+v", got)
	}
}
