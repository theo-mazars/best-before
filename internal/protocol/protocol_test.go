package protocol

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

type testPayload struct {
	Hello string `json:"hello"`
}

func keys(t *testing.T) (*DashboardKey, *AgentKey) {
	t.Helper()
	d, err := GenerateDashboardKey()
	if err != nil {
		t.Fatal(err)
	}
	a, err := GenerateAgentKey()
	if err != nil {
		t.Fatal(err)
	}
	return d, a
}

func seal(t *testing.T, a *AgentKey, d *DashboardKey, seq uint64, now time.Time) []byte {
	t.Helper()
	msg, err := Seal(a, d.Public(), KindReport, seq, now, testPayload{Hello: "world"})
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

func TestEnvelopeRoundTrip(t *testing.T) {
	d, a := keys(t)
	now := time.Now()
	msg := seal(t, a, d, 7, now)

	e, err := ParseEnvelope(msg)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(e.AgentKey, a.Public()) || e.Sequence != 7 || e.Kind != KindReport {
		t.Errorf("envelope: %+v", e)
	}
	if err := e.CheckTime(now); err != nil {
		t.Error(err)
	}
	if err := e.CheckSequence(6); err != nil {
		t.Error(err)
	}
	var p testPayload
	if err := e.Open(d, &p); err != nil || p.Hello != "world" {
		t.Errorf("payload %+v, err %v", p, err)
	}
}

func TestEnvelopePayloadIsEncrypted(t *testing.T) {
	d, a := keys(t)
	msg, err := Seal(a, d.Public(), KindReport, 1, time.Now(), testPayload{Hello: "very-secret-package-list"})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(msg, []byte("very-secret")) {
		t.Error("payload visible in the envelope")
	}
}

// TestEnvelopeTampering changes every field in turn and checks that the
// signature no longer verifies.
func TestEnvelopeTampering(t *testing.T) {
	d, a := keys(t)
	_, other := keys(t)
	msg := seal(t, a, d, 7, time.Now())

	tamper := map[string]func(m map[string]any){
		"kind":      func(m map[string]any) { m["kind"] = string(KindEnrol) },
		"sequence":  func(m map[string]any) { m["sequence"] = 8 },
		"timestamp": func(m map[string]any) { m["timestamp"] = m["timestamp"].(float64) + 1 },
		"payload": func(m map[string]any) {
			p := []byte(m["payload"].(string))
			p[10] ^= 1
			m["payload"] = string(p)
		},
		"agent key": func(m map[string]any) { m["agent_key"] = other.Public() },
	}
	for name, change := range tamper {
		t.Run(name, func(t *testing.T) {
			var m map[string]any
			if err := json.Unmarshal(msg, &m); err != nil {
				t.Fatal(err)
			}
			change(m)
			changed, _ := json.Marshal(m)
			if _, err := ParseEnvelope(changed); err == nil {
				t.Error("tampered envelope accepted")
			}
		})
	}
}

func TestEnvelopeWrongDashboardCannotOpen(t *testing.T) {
	d, a := keys(t)
	impostor, _ := keys(t)
	e, err := ParseEnvelope(seal(t, a, d, 1, time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	var p testPayload
	if err := e.Open(impostor, &p); err == nil {
		t.Error("payload opened with the wrong dashboard key")
	}
}

// TestEnvelopePayloadBoundToHeader moves a validly encrypted payload into a
// new envelope, re-signed by the same agent with a different sequence number.
// The signature is valid, but decryption must fail.
func TestEnvelopePayloadBoundToHeader(t *testing.T) {
	d, a := keys(t)
	e, err := ParseEnvelope(seal(t, a, d, 1, time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	moved := *e
	moved.Sequence = 2
	moved.Signature = nil
	var p testPayload
	if err := moved.Open(d, &p); err == nil {
		t.Error("payload decrypted under a different header")
	}
}

func TestReplayProtection(t *testing.T) {
	d, a := keys(t)
	now := time.Now()
	e, err := ParseEnvelope(seal(t, a, d, 5, now))
	if err != nil {
		t.Fatal(err)
	}

	for _, last := range []uint64{5, 6, 100} {
		if err := e.CheckSequence(last); !errors.Is(err, ErrReplay) {
			t.Errorf("last %d: got %v, want ErrReplay", last, err)
		}
	}
	if err := e.CheckTime(now.Add(MaxAge + time.Second)); !errors.Is(err, ErrTooOld) {
		t.Errorf("old message: got %v", err)
	}
	if err := e.CheckTime(now.Add(-MaxClockSkew - time.Second)); !errors.Is(err, ErrFromFuture) {
		t.Errorf("future message: got %v", err)
	}
	if err := e.CheckTime(now.Add(MaxAge - time.Minute)); err != nil {
		t.Errorf("retry within the window rejected: %v", err)
	}
}

func TestParseEnvelopeStrict(t *testing.T) {
	d, a := keys(t)
	msg := seal(t, a, d, 1, time.Now())

	extraField := bytes.Replace(msg, []byte(`{"version"`), []byte(`{"command":"rm -rf /","version"`), 1)
	trailing := append(append([]byte{}, msg...), []byte(`{}`)...)
	for name, data := range map[string][]byte{"unknown field": extraField, "trailing data": trailing} {
		if _, err := ParseEnvelope(data); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := ParseEnvelope(make([]byte, MaxEnvelopeSize+1)); err == nil {
		t.Error("oversized envelope accepted")
	}
}

func TestReply(t *testing.T) {
	d, _ := keys(t)
	impostor, _ := keys(t)
	request := []byte("the request")

	reply, err := SignReply(d, request, Rejected, "unknown agent\x1b[31m\n")
	if err != nil {
		t.Fatal(err)
	}
	r, err := VerifyReply(d.Public(), request, reply)
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != Rejected || r.Reason != "unknown agent[31m" {
		t.Errorf("reply %+v: control characters must be stripped", r)
	}

	if _, err := VerifyReply(impostor.Public(), request, reply); err == nil {
		t.Error("reply verified with another dashboard's key")
	}
	if _, err := VerifyReply(d.Public(), []byte("another request"), reply); err == nil {
		t.Error("reply accepted for a different request")
	}

	forged, _ := SignReply(d, request, Status("run-command"), "")
	if _, err := VerifyReply(d.Public(), request, forged); err == nil {
		t.Error("unknown status accepted")
	}
}

func TestEnrolmentCode(t *testing.T) {
	d, _ := keys(t)
	c, err := NewEnrolmentCode("https://dashboard.vpn:8443", d.Public())
	if err != nil {
		t.Fatal(err)
	}
	s := c.String()
	if !strings.HasPrefix(s, "bb1_") {
		t.Errorf("code %q", s)
	}

	parsed, err := ParseEnrolmentCode("  " + s + "\n")
	if err != nil {
		t.Fatal(err)
	}
	if *parsed != *c {
		t.Errorf("round trip: %+v != %+v", parsed, c)
	}
	if !SecretMatches(parsed.Secret, c.SecretHash()) {
		t.Error("secret does not match its own hash")
	}
	parsed.Secret[0] ^= 1
	if SecretMatches(parsed.Secret, c.SecretHash()) {
		t.Error("wrong secret matches")
	}

	for _, bad := range []string{"", "bb1_", "bb1_!!!", "xx1_" + s[4:], s[:40]} {
		if _, err := ParseEnrolmentCode(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	for _, u := range []string{"http://dashboard.vpn", "https://user:pw@dashboard.vpn", "https://", "ftp://x"} {
		if _, err := NewEnrolmentCode(u, d.Public()); err == nil {
			t.Errorf("accepted URL %q", u)
		}
	}
}

func TestKeySerialisation(t *testing.T) {
	d, a := keys(t)

	db, err := d.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	d2, err := ParseDashboardKey(db)
	if err != nil {
		t.Fatal(err)
	}
	if !d2.Public().Equal(d.Public()) {
		t.Error("dashboard key changed in round trip")
	}

	pub, err := ParseDashboardPublicKey([]byte(d.Public().String()))
	if err != nil {
		t.Fatal(err)
	}
	if pub.Fingerprint() != d.Public().Fingerprint() {
		t.Error("fingerprint changed in round trip")
	}

	ab, _ := a.MarshalBinary()
	a2, err := ParseAgentKey(ab)
	if err != nil || !bytes.Equal(a2.Public(), a.Public()) {
		t.Errorf("agent key round trip: %v", err)
	}

	// A message sealed with the reloaded keys still works end to end.
	e, err := ParseEnvelope(seal(t, a2, d, 1, time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	var p testPayload
	if err := e.Open(d2, &p); err != nil {
		t.Error(err)
	}

	for _, bad := range [][]byte{nil, ab, db[:len(db)-1]} {
		if _, err := ParseDashboardKey(bad); err == nil {
			t.Errorf("accepted bad dashboard key of %d bytes", len(bad))
		}
	}
}

// FuzzParseEnvelope feeds arbitrary bytes to the dashboard's first parser of
// untrusted input. It must never panic, and must never accept a forgery.
func FuzzParseEnvelope(f *testing.F) {
	d, err := GenerateDashboardKey()
	if err != nil {
		f.Fatal(err)
	}
	// Fuzzing runs in several processes, so the agent key must be the same
	// in all of them: derive it from a fixed seed.
	a := &AgentKey{priv: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))}
	valid, err := Seal(a, d.Public(), KindReport, 1, time.Now(), testPayload{Hello: "seed"})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"version":1,"kind":"report"}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		e, err := ParseEnvelope(data)
		if err != nil {
			return
		}
		// Anything that parses must carry a signature that genuinely
		// verifies, so the only way through is the agent's own key.
		if !bytes.Equal(e.AgentKey, a.Public()) {
			t.Fatalf("accepted an envelope from an unknown key: %x", e.AgentKey)
		}
		var p testPayload
		_ = e.Open(d, &p)
	})
}
