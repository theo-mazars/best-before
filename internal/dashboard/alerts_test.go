package dashboard

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/theo-mazars/best-before/internal/dashboard/notify"
	"github.com/theo-mazars/best-before/internal/dashboard/store"
	"github.com/theo-mazars/best-before/internal/dashboard/vulns"
	"github.com/theo-mazars/best-before/internal/protocol"
)

var update = flag.Bool("update", false, "rewrite golden files")

// hook is a webhook channel that records what it receives.
type hook struct {
	mu     sync.Mutex
	got    []map[string]any
	status int
	srv    *httptest.Server
}

func newHook(t *testing.T) *hook {
	h := &hook{status: http.StatusOK}
	h.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		h.mu.Lock()
		defer h.mu.Unlock()
		if h.status == http.StatusOK {
			h.got = append(h.got, body)
		}
		w.WriteHeader(h.status)
	}))
	t.Cleanup(h.srv.Close)
	return h
}

// take returns what was received since the last call.
func (h *hook) take() []map[string]any {
	h.mu.Lock()
	defer h.mu.Unlock()
	got := h.got
	h.got = nil
	return got
}

func titles(msgs []map[string]any) []string {
	var out []string
	for _, m := range msgs {
		out = append(out, m["title"].(string))
	}
	return out
}

type alertTest struct {
	t     *testing.T
	ctx   context.Context
	store *store.Store
	al    *alerter
	now   time.Time
	agent *store.Agent
	hook  *hook
}

func newAlertTest(t *testing.T) *alertTest {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	key, _ := protocol.GenerateDashboardKey()
	at := &alertTest{t: t, ctx: ctx, store: st, now: time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC)}
	cfg := Config{PublicURL: "https://dashboard.example.vpn", StaleAfter: 48 * time.Hour}
	at.al = newAlerter(st, newSealer(key), cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), func() time.Time { return at.now })

	st.CreateEnrolmentCode(ctx, [32]byte{1}, "", at.now, at.now.Add(time.Hour))
	agentKey, _ := protocol.GenerateAgentKey()
	if at.agent, err = st.RedeemEnrolmentCode(ctx, [32]byte{1}, store.NewAgent{PublicKey: agentKey.Public(), Hostname: "web-01"}, at.now); err != nil {
		t.Fatal(err)
	}
	at.hook = newHook(t)
	return at
}

func (at *alertTest) addHook(emergencies, digest bool) {
	at.t.Helper()
	c := &store.Channel{ID: store.NewChannelID(), Type: "webhook", Name: "hook", Settings: []byte("{}"), Emergencies: emergencies, Digest: digest}
	var err error
	if c.Secrets, err = at.al.sealer.seal(c.ID, notify.Values{"url": at.hook.srv.URL}); err != nil {
		at.t.Fatal(err)
	}
	if err := at.store.CreateChannel(at.ctx, c, at.now); err != nil {
		at.t.Fatal(err)
	}
}

// report records a report from the agent, matched with these findings.
func (at *alertTest) report(seq uint64, findings ...vulns.Finding) {
	at.t.Helper()
	body, _ := json.Marshal(testServerReport())
	if err := at.store.RecordReport(at.ctx, at.agent.ID, seq, bytes.Repeat([]byte{byte(seq)}, 32), at.now, body); err != nil {
		at.t.Fatal(err)
	}
	m := newMatching(fakeDB{findings: findings}, at.store, at.al.log, func() time.Time { return at.now })
	m.match(at.ctx, at.agent.ID)
	if a, err := at.store.AgentByID(at.ctx, at.agent.ID); err == nil {
		at.agent = a
	}
}

func (at *alertTest) check() []map[string]any {
	at.t.Helper()
	if err := at.al.check(at.ctx); err != nil {
		at.t.Fatal(err)
	}
	return at.hook.take()
}

var (
	kevInImage = vulns.Finding{Target: testImage, Package: "libc6", Version: "2.36-9", Kind: vulns.KindPackage,
		Vulnerability: "CVE-2026-1000", Severity: "high", CVSS: 7.8, FixVersions: []string{"2.36-9+deb12u7"}, KnownExploited: true,
		URL: "https://security-tracker.debian.org/tracker/CVE-2026-1000"}
	criticalOnHost = vulns.Finding{Target: vulns.TargetHost, Package: "openssl", Version: "3.0.13-0ubuntu3.5", Kind: vulns.KindPackage,
		Vulnerability: "CVE-2026-2000", Severity: "critical", CVSS: 9.8, FixVersions: []string{"3.0.13-0ubuntu3.6"},
		URL: "https://ubuntu.com/security/CVE-2026-2000"}
	highOnHost = vulns.Finding{Target: vulns.TargetHost, Package: "curl", Version: "8.5.0-2ubuntu10.5", Kind: vulns.KindPackage,
		Vulnerability: "CVE-2026-3000", Severity: "high", CVSS: 7.5, FixVersions: []string{"8.5.0-2ubuntu10.6"}}
	unfixedKEV = vulns.Finding{Target: vulns.TargetHost, Package: "bash", Version: "5.2", Kind: vulns.KindPackage,
		Vulnerability: "CVE-2026-4000", Severity: "critical", CVSS: 9.9, KnownExploited: true}
)

func TestEmergencies(t *testing.T) {
	at := newAlertTest(t)
	at.addHook(true, false)
	at.report(1, kevInImage, criticalOnHost, highOnHost, unfixedKEV)

	// Known exploited, or CVSS 9.0 or more, with a fix: one message for the
	// server. A high finding is for the digest; an unfixed one is silent.
	got := at.check()
	if len(got) != 1 || got[0]["title"] != "Emergency on web-01: 2 vulnerabilities to fix now" || got[0]["event"] != "emergency" {
		t.Fatalf("got %v", titles(got))
	}
	text := got[0]["text"].(string)
	for _, want := range []string{
		"CVE-2026-1000 in libc6 2.36-9 (image node:22-slim): known exploited, high, CVSS 7.8, fixed in 2.36-9+deb12u7",
		"CVE-2026-2000 in openssl 3.0.13-0ubuntu3.5 (host): critical, CVSS 9.8, fixed in 3.0.13-0ubuntu3.6",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("text lacks %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "CVE-2026-3000") || strings.Contains(text, "CVE-2026-4000") {
		t.Errorf("text has more than the emergencies:\n%s", text)
	}
	if got[0]["url"] != "https://dashboard.example.vpn/servers/"+at.agent.ID {
		t.Errorf("url: %v", got[0]["url"])
	}
	if vs := got[0]["details"].(map[string]any)["vulnerabilities"].([]any); len(vs) != 2 {
		t.Errorf("details: %v", vs)
	}

	// Sent once, even when the next report has them again.
	at.now = at.now.Add(24 * time.Hour)
	at.report(2, kevInImage, criticalOnHost, highOnHost, unfixedKEV)
	if got := at.check(); len(got) != 0 {
		t.Errorf("sent again: %v", titles(got))
	}

	// A fix for the exploited bash vulnerability makes it an emergency.
	fixed := unfixedKEV
	fixed.FixVersions = []string{"5.2-2"}
	at.now = at.now.Add(time.Hour)
	at.report(3, kevInImage, criticalOnHost, fixed)
	if got := at.check(); len(got) != 1 || got[0]["title"] != "Emergency on web-01: 1 vulnerability to fix now" ||
		!strings.Contains(got[0]["text"].(string), "CVE-2026-4000") {
		t.Errorf("after a fix appeared: %v", titles(got))
	}

	// Seven days after the first message, a reminder for what is still open.
	at.now = time.Date(2026, 11, 9, 10, 0, 0, 0, time.UTC)
	at.report(4, kevInImage, fixed)
	got = at.check()
	if len(got) != 1 || got[0]["title"] != "Still open on web-01: 1 emergency" || got[0]["event"] != "reminder" ||
		!strings.Contains(got[0]["text"].(string), "CVE-2026-1000") {
		t.Errorf("reminder: %v", titles(got))
	}

	// Fixed, then back: sent again.
	at.now = at.now.Add(time.Hour)
	at.report(5)
	at.check()
	at.report(6, criticalOnHost)
	if got := at.check(); len(got) != 1 || !strings.Contains(got[0]["text"].(string), "CVE-2026-2000") {
		t.Errorf("returning emergency: %v", titles(got))
	}
}

// Alerts found while no channel is set up are dropped, not sent once one
// is: the dashboard shows them. Alerts a channel failed to take are tried
// again.
func TestAlertsWithoutChannels(t *testing.T) {
	at := newAlertTest(t)
	at.report(1, criticalOnHost)
	at.check()
	at.addHook(true, false)
	if got := at.check(); len(got) != 0 {
		t.Errorf("dropped alert sent later: %v", titles(got))
	}

	at.now = at.now.Add(time.Hour)
	at.hook.status = http.StatusInternalServerError
	at.report(2, criticalOnHost, kevInImage)
	at.check()
	// Held back for a while after a failure.
	at.hook.status = http.StatusOK
	at.now = at.now.Add(time.Minute)
	if got := at.check(); len(got) != 0 {
		t.Errorf("sent while held back: %v", titles(got))
	}
	at.now = at.now.Add(alertRetry)
	if got := at.check(); len(got) != 1 || !strings.Contains(got[0]["text"].(string), "CVE-2026-1000") ||
		strings.Contains(got[0]["text"].(string), "CVE-2026-2000") {
		t.Errorf("after the failure: %v", got)
	}
	if got := at.check(); len(got) != 0 {
		t.Errorf("sent twice: %v", titles(got))
	}
}

// The settings decide what an emergency is.
func TestEmergencyRules(t *testing.T) {
	at := newAlertTest(t)
	at.addHook(true, false)
	s, _ := at.store.AlertSettings(at.ctx)
	s.EmergencyKnownExploited = false
	seven := 7.0
	s.EmergencyMinCVSS = &seven
	if err := at.store.SetAlertSettings(at.ctx, s); err != nil {
		t.Fatal(err)
	}

	// The exploited libc6 (CVSS 7.8) and curl (7.5) count by score alone.
	low := highOnHost
	low.Vulnerability, low.CVSS = "CVE-2026-5000", 6.9
	at.report(1, kevInImage, highOnHost, low)
	got := at.check()
	if len(got) != 1 || got[0]["title"] != "Emergency on web-01: 2 vulnerabilities to fix now" ||
		strings.Contains(got[0]["text"].(string), "CVE-2026-5000") {
		t.Fatalf("got %v", got)
	}

	// With no rule at all, nothing is an emergency, and open ones close.
	s.EmergencyMinCVSS = nil
	at.store.SetAlertSettings(at.ctx, s)
	at.now = at.now.Add(30 * 24 * time.Hour)
	at.report(2, kevInImage, highOnHost, criticalOnHost)
	if got := at.check(); len(got) != 0 {
		t.Errorf("no rule: %v", titles(got))
	}
	if open, _ := at.store.Alerts(at.ctx); len(open) != 0 {
		t.Errorf("still open: %+v", open)
	}
}

func TestStaleServerAlerts(t *testing.T) {
	at := newAlertTest(t)
	at.addHook(true, false)
	at.report(1)
	if got := at.check(); len(got) != 0 {
		t.Fatalf("got %v", titles(got))
	}

	at.now = at.now.Add(49 * time.Hour)
	got := at.check()
	if len(got) != 1 || got[0]["title"] != "web-01 has stopped reporting" || got[0]["event"] != "stale" ||
		!strings.Contains(got[0]["text"].(string), "No report since 2 Nov 2026, 10:00 UTC") {
		t.Fatalf("stale: %v", got)
	}
	at.now = at.now.Add(24 * time.Hour)
	if got := at.check(); len(got) != 0 {
		t.Errorf("stale sent twice: %v", titles(got))
	}

	at.report(2)
	if got := at.check(); len(got) != 1 || got[0]["title"] != "web-01 is reporting again" {
		t.Errorf("recovered: %v", titles(got))
	}

	// Revoking a server closes its alerts, and it never goes stale.
	at.store.RevokeAgent(at.ctx, at.agent.ID, "", at.now)
	at.now = at.now.Add(72 * time.Hour)
	if got := at.check(); len(got) != 0 {
		t.Errorf("revoked: %v", titles(got))
	}
}

func TestDigestSchedule(t *testing.T) {
	monday := time.Monday
	s := &store.AlertSettings{DigestWeekday: &monday, DigestMinute: 8 * 60, DigestTimezone: "Europe/Paris"}
	for now, want := range map[string]string{
		"2026-11-02T06:59:00Z": "2026-10-26T07:00:00Z", // Monday, before 08:00 in Paris (UTC+1)
		"2026-11-02T07:00:00Z": "2026-11-02T07:00:00Z",
		"2026-11-05T12:00:00Z": "2026-11-02T07:00:00Z",
		"2026-10-26T06:30:00Z": "2026-10-19T06:00:00Z", // the day after the clocks went back
	} {
		n, _ := time.Parse(time.RFC3339, now)
		got, on := lastDigestSlot(s, n)
		if !on || got.UTC().Format(time.RFC3339) != want {
			t.Errorf("at %s: %v, want %s", now, got.UTC(), want)
		}
	}
	if _, on := lastDigestSlot(&store.AlertSettings{DigestTimezone: "UTC"}, time.Now()); on {
		t.Error("digest on without a day")
	}
}

func TestDigestSentWeekly(t *testing.T) {
	at := newAlertTest(t)
	at.addHook(false, true)
	at.check() // a new dashboard only notes the time
	if s, _ := at.store.AlertSettings(at.ctx); s.DigestSentAt == nil {
		t.Fatal("no starting time")
	}

	at.now = time.Date(2026, 11, 9, 7, 59, 0, 0, time.UTC)
	if got := at.check(); len(got) != 0 {
		t.Errorf("too early: %v", titles(got))
	}
	at.now = at.now.Add(time.Minute)
	got := at.check()
	if len(got) != 1 || got[0]["event"] != "digest" {
		t.Fatalf("got %v", titles(got))
	}
	if got := at.check(); len(got) != 0 {
		t.Errorf("sent twice: %v", titles(got))
	}
}

// The digest's text and HTML are checked against golden files; run the tests
// with -update after changing them on purpose.
func TestDigestGolden(t *testing.T) {
	at := newAlertTest(t)
	at.report(1, kevInImage, highOnHost, unfixedKEV)
	// A server that has gone quiet.
	at.store.CreateEnrolmentCode(at.ctx, [32]byte{2}, "", at.now, at.now.Add(time.Hour))
	k, _ := protocol.GenerateAgentKey()
	quiet, _ := at.store.RedeemEnrolmentCode(at.ctx, [32]byte{2}, store.NewAgent{PublicKey: k.Public(), Hostname: "db-<01>"}, at.now.Add(-72*time.Hour))
	ids := strings.NewReplacer(at.agent.ID, "web-01-id", quiet.ID, "db-01-id")

	settings, _ := at.store.AlertSettings(at.ctx)
	d, err := at.al.buildDigest(at.ctx, settings, at.now.Add(-7*24*time.Hour), at.now)
	if err != nil {
		t.Fatal(err)
	}
	m, err := d.message()
	if err != nil {
		t.Fatal(err)
	}
	if m.Title != "Best Before weekly digest: 1 emergency, 1 stale server, 1 server with security updates, 1 new vulnerability" {
		t.Errorf("title: %q", m.Title)
	}
	golden(t, "digest.txt", ids.Replace(m.Text))
	golden(t, "digest.html", ids.Replace(m.HTML))

	empty := &digest{Since: at.now.Add(-7 * 24 * time.Hour), Until: at.now}
	m, _ = empty.message()
	if m.Title != "Best Before weekly digest: all clear" {
		t.Errorf("title: %q", m.Title)
	}
	golden(t, "digest-all-clear.txt", m.Text)
}

// The digest says only what the settings ask for, and keeps quiet when
// there is nothing to say if asked to.
func TestDigestSections(t *testing.T) {
	at := newAlertTest(t)
	at.addHook(false, true)
	at.report(1, kevInImage, highOnHost)
	s, _ := at.store.AlertSettings(at.ctx)
	s.DigestStale, s.DigestUpdates, s.DigestNewMinSeverity, s.DigestAllClear = false, false, "critical", false
	at.store.SetAlertSettings(at.ctx, s)
	s, _ = at.store.AlertSettings(at.ctx)

	d, err := at.al.buildDigest(at.ctx, s, at.now.Add(-7*24*time.Hour), at.now)
	if err != nil {
		t.Fatal(err)
	}
	// The high curl vulnerability is below the threshold; the security
	// update and the stale section are off.
	if len(d.Emergencies) != 1 || len(d.New)+len(d.Updates)+len(d.Stale) != 0 {
		t.Errorf("digest: %+v", d)
	}
	m, _ := d.message()
	if !strings.Contains(m.Text, "With a fix available, and known exploited, or CVSS 9.0 or more.") {
		t.Errorf("text:\n%s", m.Text)
	}

	// Nothing left to say: not sent, but its turn is used up.
	s.DigestEmergencies = false
	at.store.SetAlertSettings(at.ctx, s)
	at.check()
	at.now = time.Date(2026, 11, 9, 8, 0, 0, 0, time.UTC)
	if got := at.check(); len(got) != 0 {
		t.Errorf("empty digest sent: %v", titles(got))
	}
	if s, _ := at.store.AlertSettings(at.ctx); !s.DigestSentAt.Equal(at.now) {
		t.Errorf("digest_sent_at: %v", s.DigestSentAt)
	}
	// Asked for, it is sent anyway.
	if sent, tried, err := at.al.sendDigestNow(at.ctx); err != nil || sent != 1 || tried != 1 {
		t.Errorf("send now: %d of %d, %v", sent, tried, err)
	}
	if got := at.hook.take(); len(got) != 1 || got[0]["title"] != "Best Before weekly digest: all clear" {
		t.Errorf("send now: %v", titles(got))
	}
}

func golden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		os.MkdirAll("testdata", 0o755)
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v; run go test -update to create it", err)
	}
	if got != string(want) {
		t.Errorf("%s differs; run go test -update if the change is intended.\ngot:\n%s", name, got)
	}
}

func TestSealer(t *testing.T) {
	key, _ := protocol.GenerateDashboardKey()
	s := newSealer(key)
	sealed, err := s.seal("channel-a", notify.Values{"password": "hunter2"})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte("hunter2")) {
		t.Fatal("secret in clear")
	}
	if v, err := s.open("channel-a", sealed); err != nil || v["password"] != "hunter2" {
		t.Errorf("open: %v %v", v, err)
	}
	if _, err := s.open("channel-b", sealed); err == nil {
		t.Error("secrets moved to another channel")
	}
	other, _ := protocol.GenerateDashboardKey()
	if _, err := newSealer(other).open("channel-a", sealed); err == nil {
		t.Error("opened with another key")
	}
}
