package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestAcceptedRisks(t *testing.T) {
	ctx := context.Background()
	s, _ := openTest(t)
	now := time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC)
	agentID := newID()
	if _, err := s.db.ExecContext(ctx, insertAgent, agentID, []byte(newKey(t)), "web-01", "v1", unix(now), "10.0.0.1"); err != nil {
		t.Fatal(err)
	}
	u, err := s.CreateUser(ctx, "theo@example.org", "x", RoleAdmin, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	if u.MinSeverity != DefaultMinSeverity {
		t.Errorf("new user's threshold: %q", u.MinSeverity)
	}

	expires := now.Add(90 * 24 * time.Hour)
	if err := s.AcceptRisk(ctx, agentID, "host", "CVE-2026-0001", "Not reachable", u.ID, now, expires); err != nil {
		t.Fatal(err)
	}
	// Accepting again replaces the reason and the expiry.
	later := now.Add(time.Hour)
	if err := s.AcceptRisk(ctx, agentID, "host", "CVE-2026-0001", "Behind the VPN", u.ID, later, expires.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	got, err := s.AcceptedRisks(ctx, agentID)
	if err != nil || len(got) != 1 {
		t.Fatalf("risks: %+v %v", got, err)
	}
	r := got[0]
	if r.Reason != "Behind the VPN" || r.AcceptedBy != "theo@example.org" || !r.AcceptedAt.Equal(later) ||
		!r.ExpiresAt.Equal(expires.Add(time.Hour)) || r.Target != "host" {
		t.Errorf("risk: %+v", r)
	}
	if !r.Active(expires) || r.Active(expires.Add(time.Hour)) {
		t.Error("active at the wrong times")
	}

	// The acceptance outlives whoever made it.
	other, _ := s.CreateUser(ctx, "other@example.org", "x", RoleAdmin, nil, now)
	if err := s.DeleteUser(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.AcceptedRisks(ctx, agentID); len(got) != 1 || got[0].AcceptedBy != "" {
		t.Errorf("after deleting its author: %+v", got)
	}

	if err := s.WithdrawRisk(ctx, agentID, "host", "CVE-2026-0001"); err != nil {
		t.Fatal(err)
	}
	if err := s.WithdrawRisk(ctx, agentID, "host", "CVE-2026-0001"); !errors.Is(err, ErrNotFound) {
		t.Errorf("withdrawn twice: %v", err)
	}

	for name, tc := range map[string]struct {
		query string
		args  []any
		want  string
	}{
		"no reason":          {upsertRisk, []any{agentID, "host", "CVE-2026-0002", "", nil, unix(now), unix(expires)}, "CHECK"},
		"expired at once":    {upsertRisk, []any{agentID, "host", "CVE-2026-0002", "x", nil, unix(now), unix(now)}, "CHECK"},
		"unknown server":     {upsertRisk, []any{newID(), "host", "CVE-2026-0002", "x", nil, unix(now), unix(expires)}, "FOREIGN KEY"},
		"no vulnerability":   {upsertRisk, []any{agentID, "host", "", "x", nil, unix(now), unix(expires)}, "CHECK"},
		"unknown threshold":  {updateMinSeverity, []any{"unknown", other.ID}, "CHECK"},
		"reason of 1001 chr": {upsertRisk, []any{agentID, "host", "CVE-2026-0002", strings.Repeat("x", 1001), nil, unix(now), unix(expires)}, "CHECK"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := s.db.ExecContext(ctx, tc.query, tc.args...)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("got %v, want an error containing %q", err, tc.want)
			}
		})
	}
}

func TestMinSeverity(t *testing.T) {
	ctx := context.Background()
	s, _ := openTest(t)
	now := time.Now()
	u, _ := s.CreateUser(ctx, "theo@example.org", "x", RoleAdmin, nil, now)
	tok := []byte(strings.Repeat("t", 32))
	s.CreateSession(ctx, tok, u.ID, now, now.Add(time.Hour))

	if err := s.SetMinSeverity(ctx, u.ID, "high"); err != nil {
		t.Fatal(err)
	}
	// The user stays logged in.
	sess, err := s.TouchSession(ctx, tok, now, time.Hour)
	if err != nil || sess.User.MinSeverity != "high" {
		t.Errorf("session: %+v %v", sess, err)
	}
	if err := s.SetMinSeverity(ctx, newID(), "high"); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown user: %v", err)
	}
}
