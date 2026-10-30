package store

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"
)

func TestUsers(t *testing.T) {
	ctx := context.Background()
	s, _ := openTest(t)
	now := time.Now()

	u, err := s.CreateUser(ctx, "theo@example.org", "$argon2id$x", RoleAdmin, bytes.Repeat([]byte{1}, 20), now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateUser(ctx, "Theo@Example.org", "x", RoleUser, nil, now); !errors.Is(err, ErrEmailTaken) {
		t.Errorf("same email, other case: %v", err)
	}

	got, err := s.UserByEmail(ctx, "THEO@example.org")
	if err != nil || got.ID != u.ID || got.Role != RoleAdmin || len(got.TOTPSecret) != 20 {
		t.Errorf("by email: %+v, %v", got, err)
	}
	if _, err := s.UserByEmail(ctx, "nobody@example.org"); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown email: %v", err)
	}

	if err := s.UseTOTPStep(ctx, u.ID, 100); err != nil {
		t.Fatal(err)
	}
	for _, step := range []uint64{100, 99} {
		if err := s.UseTOTPStep(ctx, u.ID, step); !errors.Is(err, ErrTOTPReplayed) {
			t.Errorf("step %d reused: %v", step, err)
		}
	}
	if err := s.UseTOTPStep(ctx, u.ID, 101); err != nil {
		t.Error(err)
	}
}

func TestSessions(t *testing.T) {
	ctx := context.Background()
	s, _ := openTest(t)
	now := time.Now()
	u, _ := s.CreateUser(ctx, "theo@example.org", "x", RoleAdmin, nil, now)
	token := bytes.Repeat([]byte{7}, 32)
	idle := time.Hour

	if err := s.CreateSession(ctx, token, u.ID, now, now.Add(12*time.Hour)); err != nil {
		t.Fatal(err)
	}
	sess, err := s.TouchSession(ctx, token, now.Add(30*time.Minute), idle)
	if err != nil || sess.User.ID != u.ID {
		t.Fatalf("session: %+v, %v", sess, err)
	}
	// Activity at 30 minutes keeps it alive at 80 minutes.
	if _, err := s.TouchSession(ctx, token, now.Add(80*time.Minute), idle); err != nil {
		t.Errorf("active session expired: %v", err)
	}
	if _, err := s.TouchSession(ctx, token, now.Add(3*time.Hour), idle); !errors.Is(err, ErrNotFound) {
		t.Errorf("idle session still valid: %v", err)
	}

	other := bytes.Repeat([]byte{8}, 32)
	s.CreateSession(ctx, other, u.ID, now, now.Add(time.Hour))
	for i := 1; i <= 2; i++ {
		s.TouchSession(ctx, other, now.Add(time.Duration(i)*25*time.Minute), idle)
	}
	if _, err := s.TouchSession(ctx, other, now.Add(61*time.Minute), idle); !errors.Is(err, ErrNotFound) {
		t.Errorf("session past its absolute expiry still valid: %v", err)
	}

	third := bytes.Repeat([]byte{9}, 32)
	s.CreateSession(ctx, third, u.ID, now, now.Add(time.Hour))
	if err := s.DeleteSession(ctx, third); err != nil {
		t.Fatal(err)
	}
	if _, err := s.TouchSession(ctx, third, now, idle); !errors.Is(err, ErrNotFound) {
		t.Errorf("deleted session still valid: %v", err)
	}
}

func TestUserChangesEndSessions(t *testing.T) {
	ctx := context.Background()
	s, _ := openTest(t)
	now := time.Now()
	admin, _ := s.CreateUser(ctx, "admin@example.org", "x", RoleAdmin, nil, now)
	other, _ := s.CreateUser(ctx, "other@example.org", "x", RoleAdmin, nil, now)

	for name, change := range map[string]func() error{
		"role":     func() error { return s.SetUserRole(ctx, other.ID, RoleUser) },
		"password": func() error { return s.SetPasswordHash(ctx, other.ID, "y") },
		"totp":     func() error { return s.SetTOTP(ctx, other.ID, bytes.Repeat([]byte{2}, 20), 5) },
	} {
		token := bytes.Repeat([]byte{byte(len(name))}, 32)
		s.CreateSession(ctx, token, other.ID, now, now.Add(time.Hour))
		if err := change(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if _, err := s.TouchSession(ctx, token, now, time.Hour); !errors.Is(err, ErrNotFound) {
			t.Errorf("%s change left the session valid: %v", name, err)
		}
	}
	got, _ := s.UserByID(ctx, other.ID)
	if got.Role != RoleUser || got.PasswordHash != "y" || got.TOTPSecret[0] != 2 {
		t.Errorf("changes not applied: %+v", got)
	}

	if err := s.SetUserRole(ctx, admin.ID, "owner"); err == nil {
		t.Error("unknown role accepted")
	}
	if err := s.SetPasswordHash(ctx, "no-such-user-id-0000000000", "x"); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown user: %v", err)
	}
}

func TestLastAdminIsKept(t *testing.T) {
	ctx := context.Background()
	s, _ := openTest(t)
	now := time.Now()
	admin, _ := s.CreateUser(ctx, "admin@example.org", "x", RoleAdmin, nil, now)
	user, _ := s.CreateUser(ctx, "user@example.org", "x", RoleUser, nil, now)

	if err := s.SetUserRole(ctx, admin.ID, RoleUser); !errors.Is(err, ErrLastAdmin) {
		t.Errorf("demoting the last admin: %v", err)
	}
	if err := s.DeleteUser(ctx, admin.ID); !errors.Is(err, ErrLastAdmin) {
		t.Errorf("deleting the last admin: %v", err)
	}
	if err := s.DeleteUser(ctx, user.ID); err != nil {
		t.Errorf("deleting a user: %v", err)
	}

	second, _ := s.CreateUser(ctx, "second@example.org", "x", RoleAdmin, nil, now)
	if err := s.DeleteUser(ctx, admin.ID); err != nil {
		t.Errorf("deleting an admin when another exists: %v", err)
	}
	if err := s.SetUserRole(ctx, second.ID, RoleUser); !errors.Is(err, ErrLastAdmin) {
		t.Errorf("demoting the new last admin: %v", err)
	}
}

func TestDeletedUserKeepsHistory(t *testing.T) {
	ctx := context.Background()
	s, _ := openTest(t)
	now := time.Now()
	s.CreateUser(ctx, "keeper@example.org", "x", RoleAdmin, nil, now)
	gone, _ := s.CreateUser(ctx, "gone@example.org", "x", RoleAdmin, nil, now)

	if err := s.CreateEnrolmentCode(ctx, [32]byte{1}, gone.ID, now, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	a, err := s.RedeemEnrolmentCode(ctx, [32]byte{1}, NewAgent{PublicKey: newKey(t), Hostname: "web-01"}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeAgent(ctx, a.ID, gone.ID, now); err != nil {
		t.Fatal(err)
	}

	if err := s.DeleteUser(ctx, gone.ID); err != nil {
		t.Fatalf("user referenced by history cannot be deleted: %v", err)
	}
	got, _ := s.AgentByID(ctx, a.ID)
	if !got.Revoked() {
		t.Error("agent's revocation lost with the user")
	}
}
