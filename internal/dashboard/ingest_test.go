package dashboard

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/theo-mazars/best-before/internal/dashboard/store"
	"github.com/theo-mazars/best-before/internal/protocol"
	"github.com/theo-mazars/best-before/internal/report"
)

type testDashboard struct {
	t     *testing.T
	in    *ingest
	mux   *http.ServeMux
	now   time.Time
	logs  *bytes.Buffer
	store *store.Store
}

func newTestDashboard(t *testing.T) *testDashboard {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	key, err := protocol.GenerateDashboardKey()
	if err != nil {
		t.Fatal(err)
	}
	identity, _ := protocol.NewIdentity(key, nil)

	d := &testDashboard{t: t, mux: http.NewServeMux(), now: time.Now(), logs: &bytes.Buffer{}, store: st}
	clock := func() time.Time { return d.now }
	d.in = &ingest{
		store:    st,
		key:      key,
		identity: identity,
		log:      slog.New(slog.NewTextHandler(d.logs, nil)),
		now:      clock,
		perIP:    newRateLimiter(1000, time.Millisecond, clock),
		perAgent: newRateLimiter(1000, time.Millisecond, clock),
	}
	d.in.routes(d.mux)
	return d
}

// newCode creates an enrolment code valid for an hour.
func (d *testDashboard) newCode() *protocol.EnrolmentCode {
	d.t.Helper()
	c, err := protocol.NewEnrolmentCode("https://dashboard.test", d.in.key.Public())
	if err != nil {
		d.t.Fatal(err)
	}
	if err := d.store.CreateEnrolmentCode(context.Background(), c.SecretHash(), "", d.now, d.now.Add(time.Hour)); err != nil {
		d.t.Fatal(err)
	}
	return c
}

// send posts a message and returns the verified reply and HTTP status.
func (d *testDashboard) send(path string, msg []byte) (*protocol.Reply, int) {
	d.t.Helper()
	rec := httptest.NewRecorder()
	d.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, bytes.NewReader(msg)))
	reply, err := protocol.VerifyReply(d.in.key.Public(), msg, rec.Body.Bytes())
	if err != nil {
		return nil, rec.Code
	}
	return reply, rec.Code
}

func (d *testDashboard) enrol(a *protocol.AgentKey, secret []byte) *protocol.Reply {
	d.t.Helper()
	msg, err := protocol.Seal(a, d.in.key.Public(), protocol.KindEnrol, 0, d.now,
		protocol.EnrolRequest{Secret: secret, Hostname: "web-01", AgentVersion: "v0.1.0"})
	if err != nil {
		d.t.Fatal(err)
	}
	r, _ := d.send("/api/v1/enrol", msg)
	return r
}

func (d *testDashboard) sealReport(a *protocol.AgentKey, seq uint64, payload any) []byte {
	d.t.Helper()
	msg, err := protocol.Seal(a, d.in.key.Public(), protocol.KindReport, seq, d.now, payload)
	if err != nil {
		d.t.Fatal(err)
	}
	return msg
}

func validReport() report.Report {
	return report.Report{SchemaVersion: report.SchemaVersion, AgentVersion: "v0.1.0", GeneratedAt: time.Now().UTC(),
		Host: report.Host{Hostname: "web-01", RebootRequiredPackages: []string{}, Errors: []string{}}}
}

func newAgentKey(t *testing.T) *protocol.AgentKey {
	t.Helper()
	k, err := protocol.GenerateAgentKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func expect(t *testing.T, what string, r *protocol.Reply, status protocol.Status, reason string) {
	t.Helper()
	if r == nil {
		t.Fatalf("%s: no verifiable reply", what)
	}
	if r.Status != status || !strings.Contains(r.Reason, reason) {
		t.Errorf("%s: got %s %q, want %s containing %q", what, r.Status, r.Reason, status, reason)
	}
}

func TestEnrolAndReport(t *testing.T) {
	d := newTestDashboard(t)
	agent := newAgentKey(t)
	code := d.newCode()

	expect(t, "enrol", d.enrol(agent, code.Secret[:]), protocol.Accepted, "")

	msg := d.sealReport(agent, 1, validReport())
	r, status := d.send("/api/v1/reports", msg)
	expect(t, "report", r, protocol.Accepted, "")
	if status != http.StatusOK {
		t.Errorf("HTTP status %d", status)
	}

	a, _ := d.store.AgentByKey(context.Background(), agent.Public())
	body, err := d.store.LatestReport(context.Background(), a.ID)
	if err != nil || !bytes.Contains(body, []byte(`"hostname":"web-01"`)) {
		t.Errorf("stored report %s, err %v", body, err)
	}

	// The very same message again, as after a lost reply: accepted, once.
	r, _ = d.send("/api/v1/reports", msg)
	expect(t, "identical retry", r, protocol.Accepted, "")

	// A new message with an old sequence number: a replay.
	r, _ = d.send("/api/v1/reports", d.sealReport(agent, 1, validReport()))
	expect(t, "replayed sequence", r, protocol.Rejected, "sequence")

	r, _ = d.send("/api/v1/reports", d.sealReport(agent, 2, validReport()))
	expect(t, "next report", r, protocol.Accepted, "")
}

func TestEnrolRejections(t *testing.T) {
	d := newTestDashboard(t)
	code := d.newCode()
	expect(t, "first use", d.enrol(newAgentKey(t), code.Secret[:]), protocol.Accepted, "")

	expect(t, "reused code", d.enrol(newAgentKey(t), code.Secret[:]), protocol.Rejected, "already been used")
	expect(t, "wrong secret", d.enrol(newAgentKey(t), make([]byte, 32)), protocol.Rejected, "unknown")
	expect(t, "short secret", d.enrol(newAgentKey(t), []byte("short")), protocol.Rejected, "invalid enrolment code")

	expired := d.newCode()
	d.now = d.now.Add(2 * time.Hour)
	expect(t, "expired code", d.enrol(newAgentKey(t), expired.Secret[:]), protocol.Rejected, "expired")
}

func TestReportRejections(t *testing.T) {
	d := newTestDashboard(t)
	agent := newAgentKey(t)
	expect(t, "enrol", d.enrol(agent, d.newCode().Secret[:]), protocol.Accepted, "")

	r, _ := d.send("/api/v1/reports", d.sealReport(newAgentKey(t), 1, validReport()))
	expect(t, "unknown agent", r, protocol.Rejected, "unknown agent")

	// An enrolment message sent to the reports endpoint.
	enrolMsg, _ := protocol.Seal(agent, d.in.key.Public(), protocol.KindEnrol, 1, d.now, protocol.EnrolRequest{})
	r, _ = d.send("/api/v1/reports", enrolMsg)
	expect(t, "wrong kind", r, protocol.Rejected, "kind")

	// Payloads are decoded strictly against the schema.
	withExtra := map[string]any{"schema_version": 1, "host": map[string]any{}, "run": "rm -rf /"}
	r, _ = d.send("/api/v1/reports", d.sealReport(agent, 1, withExtra))
	expect(t, "unknown field", r, protocol.Rejected, "invalid report")

	future := validReport()
	future.SchemaVersion = 99
	r, _ = d.send("/api/v1/reports", d.sealReport(agent, 2, future))
	expect(t, "schema version", r, protocol.Rejected, "schema version")

	old := d.sealReport(agent, 3, validReport())
	d.now = d.now.Add(protocol.MaxAge + time.Minute)
	r, _ = d.send("/api/v1/reports", old)
	expect(t, "too old", r, protocol.Rejected, "too old")

	a, _ := d.store.AgentByKey(context.Background(), agent.Public())
	d.store.RevokeAgent(context.Background(), a.ID, "", d.now)
	r, _ = d.send("/api/v1/reports", d.sealReport(agent, 4, validReport()))
	expect(t, "revoked", r, protocol.Rejected, "revoked")

	// Every rejection is logged with its reason.
	if n := strings.Count(d.logs.String(), "rejected message"); n != 6 {
		t.Errorf("%d rejections logged, want 6:\n%s", n, d.logs)
	}
}

func TestUnparseableAndOversized(t *testing.T) {
	d := newTestDashboard(t)

	r, _ := d.send("/api/v1/reports", []byte("not json"))
	expect(t, "garbage", r, protocol.Rejected, "malformed")

	_, status := d.send("/api/v1/reports", make([]byte, protocol.MaxEnvelopeSize+1))
	if status != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized message: HTTP %d", status)
	}
}

func TestPerAgentRateLimit(t *testing.T) {
	d := newTestDashboard(t)
	d.in.perAgent = newRateLimiter(2, time.Hour, func() time.Time { return d.now })
	agent := newAgentKey(t)
	expect(t, "enrol", d.enrol(agent, d.newCode().Secret[:]), protocol.Accepted, "")

	r, _ := d.send("/api/v1/reports", d.sealReport(agent, 1, validReport()))
	expect(t, "within limit", r, protocol.Accepted, "")
	r, _ = d.send("/api/v1/reports", d.sealReport(agent, 2, validReport()))
	expect(t, "over limit", r, protocol.Rejected, "rate limited")
}

func TestIdentityEndpoint(t *testing.T) {
	d := newTestDashboard(t)
	rec := httptest.NewRecorder()
	d.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/identity", nil))
	body, _ := io.ReadAll(rec.Body)
	pub, _, err := protocol.VerifyIdentity(body, d.in.key.Public().Fingerprint())
	if err != nil || !pub.Equal(d.in.key.Public()) {
		t.Errorf("identity: %v", err)
	}
	var doc map[string]any
	json.Unmarshal(body, &doc)
	if _, ok := doc["tls_key"]; ok {
		t.Error("no TLS key statement expected without builtin TLS")
	}
}
