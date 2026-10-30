package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/theo-mazars/best-before/internal/dashboard"
	"github.com/theo-mazars/best-before/internal/dashboard/store"
	"github.com/theo-mazars/best-before/internal/protocol"
)

// A real dashboard and the real agent, talking over the network.

type e2e struct {
	t     *testing.T
	url   string
	pub   *protocol.DashboardPublicKey
	store *store.Store
	logs  *bytes.Buffer
}

func startDashboard(t *testing.T, scheme string) *e2e {
	t.Helper()
	retryDelays = nil
	t.Cleanup(func() { retryDelays = []time.Duration{10 * time.Second, 30 * time.Second, 2 * time.Minute} })

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()

	dir := t.TempDir()
	tlsMode := "builtin"
	if scheme == "http" {
		tlsMode = "off"
	}
	url := scheme + "://" + addr
	conf := filepath.Join(dir, "dashboard.conf")
	os.WriteFile(conf, []byte(fmt.Sprintf("listen = %s\npublic_url = %s\ndata_dir = %s\ntls = %s\n", addr, url, dir, tlsMode)), 0o600)
	cfg, err := dashboard.LoadConfig(conf)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	logs := &bytes.Buffer{}
	done := make(chan error, 1)
	go func() { done <- dashboard.Run(ctx, cfg, slog.New(slog.NewTextHandler(logs, nil))) }()
	t.Cleanup(func() { cancel(); <-done })

	client := &http.Client{Timeout: time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	var body []byte
	for i := 0; ; i++ {
		resp, err := client.Get(url + "/api/v1/identity")
		if err == nil {
			body, _ = io.ReadAll(resp.Body)
			resp.Body.Close()
			break
		}
		if i == 50 {
			t.Fatalf("dashboard did not start: %v\n%s", err, logs)
		}
		time.Sleep(100 * time.Millisecond)
	}
	var id protocol.Identity
	json.Unmarshal(body, &id)
	pub, err := protocol.ParseDashboardPublicKey([]byte(id.PublicKey))
	if err != nil {
		t.Fatal(err)
	}

	st, err := store.Open(context.Background(), filepath.Join(dir, "bestbefore.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return &e2e{t: t, url: url, pub: pub, store: st, logs: logs}
}

func (e *e2e) newCode() string {
	e.t.Helper()
	c, err := protocol.NewEnrolmentCode(e.url, e.pub)
	if err != nil {
		e.t.Fatal(err)
	}
	now := time.Now()
	if err := e.store.CreateEnrolmentCode(context.Background(), c.SecretHash(), "", now, now.Add(time.Hour)); err != nil {
		e.t.Fatal(err)
	}
	return c.String()
}

type testAgent struct {
	config, state string
	out           *bytes.Buffer
}

func newTestAgent(t *testing.T) *testAgent {
	dir := t.TempDir()
	return &testAgent{config: filepath.Join(dir, "agent.conf"), state: filepath.Join(dir, "state"), out: &bytes.Buffer{}}
}

func (a *testAgent) enrol(code string) error {
	return Enrol(context.Background(), EnrolOptions{Code: code, Docker: DockerOff, ConfigPath: a.config, StateDir: a.state, Out: a.out})
}

func (a *testAgent) run() error {
	return Run(context.Background(), Options{ConfigPath: a.config, StateDir: a.state, Out: a.out})
}

func TestEndToEnd(t *testing.T) {
	ctx := context.Background()
	e := startDashboard(t, "https")
	a := newTestAgent(t)
	code := e.newCode()

	if err := a.enrol(code); err != nil {
		t.Fatalf("enrol: %v\n%s", err, e.logs)
	}
	cfg, err := LoadConfig(a.config)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DashboardTLSKey == nil || !cfg.DashboardKey.Equal(e.pub) || cfg.Docker != DockerOff {
		t.Errorf("config after enrolment: %+v", cfg)
	}
	if info, _ := os.Stat(filepath.Join(a.state, "agent.key")); info == nil || info.Mode().Perm() != 0o600 {
		t.Error("agent key missing or not private")
	}

	for i := 1; i <= 2; i++ {
		if err := a.run(); err != nil {
			t.Fatalf("report %d: %v\n%s", i, err, e.logs)
		}
	}
	agents, _ := e.store.Agents(ctx)
	if len(agents) != 1 || agents[0].LastSequence != 2 {
		t.Fatalf("agents: %+v", agents)
	}
	if body, err := e.store.LatestReport(ctx, agents[0].ID); err != nil || !bytes.Contains(body, []byte(`"schema_version":1`)) {
		t.Errorf("stored report: %s, %v", body, err)
	}

	if err := newTestAgent(t).enrol(code); err == nil || !strings.Contains(err.Error(), "already been used") {
		t.Errorf("reused code: %v", err)
	}
	if err := a.enrol(e.newCode()); err == nil || !strings.Contains(err.Error(), "already enrolled") {
		t.Errorf("second enrolment without --force: %v", err)
	}

	// A code naming another dashboard: refused before the secret is sent.
	other, _ := protocol.GenerateDashboardKey()
	foreign, _ := protocol.NewEnrolmentCode(e.url, other.Public())
	if err := newTestAgent(t).enrol(foreign.String()); err == nil || !strings.Contains(err.Error(), "not the dashboard") {
		t.Errorf("foreign code: %v", err)
	}

	// A dashboard presenting a different TLS key: refused.
	pinned, _ := os.ReadFile(a.config)
	wrongPin := strings.Replace(string(pinned), "dashboard_tls_key = "+protocol.EncodeTLSKeyHash(cfg.DashboardTLSKey),
		"dashboard_tls_key = "+protocol.EncodeTLSKeyHash(make([]byte, 32)), 1)
	os.WriteFile(a.config, []byte(wrongPin), 0o644)
	if err := a.run(); err == nil || !strings.Contains(err.Error(), "pinned") {
		t.Errorf("wrong TLS pin: %v", err)
	}
	os.WriteFile(a.config, pinned, 0o644)

	if err := e.store.RevokeAgent(ctx, agents[0].ID, "", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := a.run(); err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Errorf("revoked agent: %v", err)
	}
}

func TestEndToEndPlainHTTP(t *testing.T) {
	e := startDashboard(t, "http")
	a := newTestAgent(t)
	if err := a.enrol(e.newCode()); err != nil {
		t.Fatalf("enrol: %v\n%s", err, e.logs)
	}
	if !strings.Contains(a.out.String(), "plain HTTP") {
		t.Error("no warning about plain HTTP")
	}
	if err := a.run(); err != nil {
		t.Fatalf("report: %v\n%s", err, e.logs)
	}
}
