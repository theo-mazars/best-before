package store

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func openTest(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	s, err := Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, path
}

func newKey(t *testing.T) ed25519.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

func TestReopenKeepsData(t *testing.T) {
	ctx := context.Background()
	s, path := openTest(t)
	now := time.Now()
	if err := s.CreateEnrolmentCode(ctx, [32]byte{1}, "", now, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	s.Close()

	s2, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if _, err := s2.RedeemEnrolmentCode(ctx, [32]byte{1}, NewAgent{PublicKey: newKey(t), Hostname: "web-01"}, now); err != nil {
		t.Errorf("code lost after reopening: %v", err)
	}
}

func TestEnrolmentCodes(t *testing.T) {
	ctx := context.Background()
	s, _ := openTest(t)
	now := time.Now()
	s.CreateEnrolmentCode(ctx, [32]byte{1}, "", now, now.Add(time.Hour))
	s.CreateEnrolmentCode(ctx, [32]byte{2}, "", now, now.Add(time.Hour))
	s.CreateEnrolmentCode(ctx, [32]byte{3}, "", now.Add(-2*time.Hour), now.Add(-time.Hour))

	key := newKey(t)
	a, err := s.RedeemEnrolmentCode(ctx, [32]byte{1}, NewAgent{PublicKey: key, Hostname: "web-01", AgentVersion: "v1", EnrolledFromIP: "10.0.0.5"}, now)
	if err != nil {
		t.Fatal(err)
	}
	if a.Hostname != "web-01" || !a.PublicKey.Equal(key) || a.Revoked() || a.LastSequence != 0 {
		t.Errorf("agent: %+v", a)
	}

	for name, tc := range map[string]struct {
		hash [32]byte
		key  ed25519.PublicKey
		want error
	}{
		"used code":       {[32]byte{1}, newKey(t), ErrCodeUsed},
		"unknown code":    {[32]byte{9}, newKey(t), ErrCodeInvalid},
		"expired code":    {[32]byte{3}, newKey(t), ErrCodeExpired},
		"key re-enrolled": {[32]byte{2}, key, ErrAlreadyEnrolled},
	} {
		if _, err := s.RedeemEnrolmentCode(ctx, tc.hash, NewAgent{PublicKey: tc.key, Hostname: "x"}, now); !errors.Is(err, tc.want) {
			t.Errorf("%s: got %v, want %v", name, err, tc.want)
		}
	}

	// A failed redemption must not consume the code.
	if _, err := s.RedeemEnrolmentCode(ctx, [32]byte{2}, NewAgent{PublicKey: newKey(t), Hostname: "web-02"}, now); err != nil {
		t.Errorf("code consumed by a failed attempt: %v", err)
	}
}

func TestRecordReport(t *testing.T) {
	ctx := context.Background()
	s, _ := openTest(t)
	now := time.Now()
	s.CreateEnrolmentCode(ctx, [32]byte{1}, "", now, now.Add(time.Hour))
	a, err := s.RedeemEnrolmentCode(ctx, [32]byte{1}, NewAgent{PublicKey: newKey(t), Hostname: "web-01"}, now)
	if err != nil {
		t.Fatal(err)
	}

	if err := s.RecordReport(ctx, a.ID, 5, requestID(5), now, []byte(`{"n":5}`)); err != nil {
		t.Fatal(err)
	}
	for _, seq := range []uint64{5, 4} {
		if err := s.RecordReport(ctx, a.ID, seq, requestID(9), now, []byte(`{}`)); !errors.Is(err, ErrStaleSequence) {
			t.Errorf("sequence %d: got %v", seq, err)
		}
	}
	if err := s.RecordReport(ctx, a.ID, 6, requestID(6), now, []byte(`{"n":6}`)); err != nil {
		t.Fatal(err)
	}
	body, err := s.LatestReport(ctx, a.ID)
	if err != nil || string(body) != `{"n":6}` {
		t.Errorf("latest report %s, err %v", body, err)
	}
	got, _ := s.AgentByID(ctx, a.ID)
	if got.LastSequence != 6 || !bytes.Equal(got.LastRequestID, requestID(6)) || got.LastReportAt == nil {
		t.Errorf("agent after reports: %+v", got)
	}

	if err := s.RevokeAgent(ctx, a.ID, "", now); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordReport(ctx, a.ID, 7, requestID(7), now, []byte(`{}`)); !errors.Is(err, ErrStaleSequence) {
		t.Errorf("report after revocation: got %v", err)
	}
	if err := s.RevokeAgent(ctx, a.ID, "", now); !errors.Is(err, ErrNotFound) {
		t.Errorf("second revocation: got %v", err)
	}
}

func TestDatabaseIsPrivate(t *testing.T) {
	_, path := openTest(t)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("database mode %v, want 0600", perm)
	}
}

func requestID(n byte) []byte { return bytes.Repeat([]byte{n}, 32) }
