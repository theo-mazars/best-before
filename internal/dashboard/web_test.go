package dashboard

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/theo-mazars/best-before/internal/dashboard/auth"
	"github.com/theo-mazars/best-before/internal/dashboard/store"
	"github.com/theo-mazars/best-before/internal/protocol"
)

const testPassword = "a long enough passphrase"

type testWeb struct {
	t      *testing.T
	w      *web
	mux    *http.ServeMux
	store  *store.Store
	now    time.Time
	secret []byte
}

func newTestWeb(t *testing.T, publicURL string) *testWeb {
	t.Helper()
	tw := newEmptyTestWeb(t, publicURL)
	tw.addUser("admin@example.org", store.RoleAdmin)
	return tw
}

// newEmptyTestWeb is a dashboard without users, as at first start.
func newEmptyTestWeb(t *testing.T, publicURL string) *testWeb {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	key, _ := protocol.GenerateDashboardKey()

	tw := &testWeb{t: t, mux: http.NewServeMux(), store: st, now: time.Now()}
	clock := func() time.Time { return tw.now }
	cfg := Config{PublicURL: publicURL, TLS: TLSBuiltin, StaleAfter: 48 * time.Hour}
	tw.w, err = newWeb(st, fakeDB{}, key, cfg, nil, slog.New(slog.NewTextHandler(io.Discard, nil)), clock)
	if err != nil {
		t.Fatal(err)
	}
	tw.w.alerts = newAlerter(st, tw.w.sealer, cfg, tw.w.log, clock)
	tw.w.routes(tw.mux)

	tw.secret, _ = auth.NewTOTPSecret()
	return tw
}

func (tw *testWeb) addUser(email, role string) {
	tw.t.Helper()
	hash, _ := auth.HashPassword(testPassword)
	if _, err := tw.store.CreateUser(context.Background(), email, hash, role, tw.secret, tw.now); err != nil {
		tw.t.Fatal(err)
	}
}

func (tw *testWeb) do(method, path string, form url.Values, cookie *http.Cookie, header ...string) *httptest.ResponseRecorder {
	tw.t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req := httptest.NewRequest(method, "https://dashboard.test"+path, body)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for i := 0; i+1 < len(header); i += 2 {
		req.Header.Set(header[i], header[i+1])
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	tw.mux.ServeHTTP(rec, req)
	return rec
}

// json sends v as a JSON body.
func (tw *testWeb) json(method, path string, v any, cookie *http.Cookie) *httptest.ResponseRecorder {
	tw.t.Helper()
	body, _ := json.Marshal(v)
	req := httptest.NewRequest(method, "https://dashboard.test"+path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	tw.mux.ServeHTTP(rec, req)
	return rec
}

// login goes through both steps, stopping at the first refused one.
func (tw *testWeb) login(email, password, code string) *httptest.ResponseRecorder {
	rec := tw.json(http.MethodPost, "/api/ui/login", map[string]string{"email": email, "password": password}, nil)
	if rec.Code != http.StatusNoContent {
		return rec
	}
	return tw.json(http.MethodPost, "/api/ui/login/code", map[string]string{"code": code}, rec.Result().Cookies()[0])
}

// session logs in and returns the session cookie, moving the clock on so
// that each login uses a fresh TOTP step.
func (tw *testWeb) session(email string) *http.Cookie {
	tw.t.Helper()
	tw.now = tw.now.Add(30 * time.Second)
	rec := tw.login(email, testPassword, auth.TOTPCodeAt(tw.secret, tw.now))
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookie {
			return c
		}
	}
	tw.t.Fatalf("no session cookie: %d %s", rec.Code, rec.Body)
	return nil
}

func TestLogin(t *testing.T) {
	tw := newTestWeb(t, "")
	code := auth.TOTPCodeAt(tw.secret, tw.now)

	for name, rec := range map[string]*httptest.ResponseRecorder{
		"unknown email":  tw.login("nobody@example.org", testPassword, code),
		"wrong password": tw.login("admin@example.org", "not the password", code),
		"wrong code":     tw.login("admin@example.org", testPassword, "000000"),
	} {
		if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), "incorrect") {
			t.Errorf("%s: HTTP %d", name, rec.Code)
		}
		if len(rec.Result().Cookies()) != 0 {
			t.Errorf("%s: cookie set", name)
		}
	}

	rec := tw.login("admin@example.org", testPassword, code)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("login: HTTP %d", rec.Code)
	}
	var c *http.Cookie
	for _, k := range rec.Result().Cookies() {
		if k.Name == sessionCookie {
			c = k
		}
	}
	if c == nil || c.Name != sessionCookie || !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.Path != "/" {
		t.Errorf("cookie: %+v", c)
	}

	if rec := tw.login("admin@example.org", testPassword, code); rec.Code != http.StatusUnauthorized {
		t.Errorf("reused TOTP code accepted: HTTP %d", rec.Code)
	}
}

func TestLoginRateLimit(t *testing.T) {
	tw := newTestWeb(t, "")
	for range 5 {
		tw.login("admin@example.org", "wrong", "000000")
	}
	if rec := tw.login("admin@example.org", testPassword, auth.TOTPCodeAt(tw.secret, tw.now)); rec.Code != http.StatusUnauthorized {
		t.Errorf("correct login allowed after too many attempts: HTTP %d", rec.Code)
	}
}

func TestPagesNeedAdminSession(t *testing.T) {
	tw := newTestWeb(t, "")
	tw.addUser("user@example.org", store.RoleUser)

	forged := &http.Cookie{Name: sessionCookie, Value: "made-up"}
	for _, path := range []string{"/api/ui/overview", "/api/ui/agents", "/api/ui/settings"} {
		if rec := tw.do(http.MethodGet, path, nil, nil); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s without session: HTTP %d", path, rec.Code)
		}
		if rec := tw.do(http.MethodGet, path, nil, forged); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s with forged session: HTTP %d", path, rec.Code)
		}
		if rec := tw.do(http.MethodGet, path, nil, tw.session("user@example.org")); rec.Code != http.StatusForbidden {
			t.Errorf("%s for user role: HTTP %d", path, rec.Code)
		}
	}

	admin := tw.session("admin@example.org")
	rec := tw.do(http.MethodGet, "/api/ui/agents", nil, admin)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"agents":[]`) {
		t.Errorf("admin: HTTP %d %s", rec.Code, rec.Body)
	}
	if csp := tw.do(http.MethodGet, "/", nil, admin).Header().Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'none'") {
		t.Errorf("CSP: %q", csp)
	}

	if rec := tw.json(http.MethodPost, "/api/ui/logout", nil, admin); rec.Code != http.StatusNoContent {
		t.Errorf("logout: HTTP %d %s", rec.Code, rec.Body)
	}
	if rec := tw.do(http.MethodGet, "/api/ui/agents", nil, admin); rec.Code != http.StatusUnauthorized {
		t.Errorf("session still valid after logout: HTTP %d", rec.Code)
	}
}

func TestEnrolmentCodePage(t *testing.T) {
	tw := newTestWeb(t, "")
	if rec := tw.json(http.MethodPost, "/api/ui/agents/codes", nil, tw.session("admin@example.org")); rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "public_url") {
		t.Errorf("without public_url: HTTP %d %s", rec.Code, rec.Body)
	}

	tw = newTestWeb(t, "https://dashboard.test:8443")
	rec := tw.json(http.MethodPost, "/api/ui/agents/codes", nil, tw.session("admin@example.org"))
	var v struct {
		Command   string
		ExpiresAt time.Time
	}
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &v) != nil {
		t.Fatalf("code: HTTP %d %s", rec.Code, rec.Body)
	}
	raw, ok := strings.CutPrefix(v.Command, "sudo bestbefore-agent enrol ")
	if !ok || !v.ExpiresAt.Equal(tw.now.Add(codeLifetime)) {
		t.Fatalf("code: %+v", v)
	}
	code, err := protocol.ParseEnrolmentCode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if code.URL != "https://dashboard.test:8443" || code.Fingerprint != tw.w.key.Public().Fingerprint() {
		t.Errorf("code: %+v", code)
	}
	admin := tw.session("admin@example.org")
	var list agentsView
	json.Unmarshal(tw.do(http.MethodGet, "/api/ui/agents", nil, admin).Body.Bytes(), &list)
	if len(list.Codes) != 1 || list.Codes[0].CreatedBy != "admin@example.org" || !list.CanEnrol {
		t.Fatalf("active codes: %+v", list)
	}

	key, _ := protocol.GenerateAgentKey()
	if _, err := tw.store.RedeemEnrolmentCode(context.Background(), code.SecretHash(),
		store.NewAgent{PublicKey: key.Public(), Hostname: "web-01"}, tw.now); err != nil {
		t.Errorf("code from the page does not redeem: %v", err)
	}
	json.Unmarshal(tw.do(http.MethodGet, "/api/ui/agents", nil, admin).Body.Bytes(), &list)
	if len(list.Codes) != 0 {
		t.Errorf("used code still active: %+v", list.Codes)
	}
}

func TestRevokeEnrolmentCode(t *testing.T) {
	tw := newTestWeb(t, "https://dashboard.test")
	admin := tw.session("admin@example.org")
	rec := tw.json(http.MethodPost, "/api/ui/agents/codes", nil, admin)
	var v struct{ Command string }
	json.Unmarshal(rec.Body.Bytes(), &v)
	code, err := protocol.ParseEnrolmentCode(strings.TrimPrefix(v.Command, "sudo bestbefore-agent enrol "))
	if err != nil {
		t.Fatal(err)
	}
	var list agentsView
	json.Unmarshal(tw.do(http.MethodGet, "/api/ui/agents", nil, admin).Body.Bytes(), &list)
	if len(list.Codes) != 1 {
		t.Fatalf("codes: %+v", list.Codes)
	}

	path := "/api/ui/agents/codes/" + list.Codes[0].ID
	if rec := tw.json(http.MethodDelete, path, nil, admin); rec.Code != http.StatusNoContent {
		t.Fatalf("revoke code: HTTP %d", rec.Code)
	}
	if rec := tw.json(http.MethodDelete, path, nil, admin); rec.Code != http.StatusNotFound {
		t.Errorf("revoke code twice: HTTP %d", rec.Code)
	}
	key, _ := protocol.GenerateAgentKey()
	if _, err := tw.store.RedeemEnrolmentCode(context.Background(), code.SecretHash(),
		store.NewAgent{PublicKey: key.Public(), Hostname: "web-01"}, tw.now); !errors.Is(err, store.ErrCodeInvalid) {
		t.Errorf("revoked code redeems: %v", err)
	}
}

func TestCrossSiteRequestsRefused(t *testing.T) {
	tw := newTestWeb(t, "https://dashboard.test")
	admin := tw.session("admin@example.org")
	for _, path := range []string{"/api/ui/agents/codes", "/api/ui/logout"} {
		if rec := tw.do(http.MethodPost, path, nil, admin, "Sec-Fetch-Site", "cross-site", "Content-Type", "application/json"); rec.Code != http.StatusForbidden {
			t.Errorf("cross-site POST %s: HTTP %d", path, rec.Code)
		}
	}
	if rec := tw.do(http.MethodGet, "/api/ui/agents", nil, admin); rec.Code != http.StatusOK {
		t.Errorf("session ended by a cross-site logout: HTTP %d", rec.Code)
	}
}

func TestAgentsAndRevoke(t *testing.T) {
	tw := newTestWeb(t, "")
	ctx := context.Background()
	tw.store.CreateEnrolmentCode(ctx, [32]byte{1}, "", tw.now, tw.now.Add(time.Hour))
	key, _ := protocol.GenerateAgentKey()
	a, err := tw.store.RedeemEnrolmentCode(ctx, [32]byte{1},
		store.NewAgent{PublicKey: key.Public(), Hostname: "web-01", AgentVersion: "v1", EnrolledFromIP: "10.0.0.5"}, tw.now)
	if err != nil {
		t.Fatal(err)
	}

	admin := tw.session("admin@example.org")
	var v agentsView
	rec := tw.do(http.MethodGet, "/api/ui/agents", nil, admin)
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil || len(v.Agents) != 1 {
		t.Fatalf("agents: HTTP %d %s", rec.Code, rec.Body)
	}
	got := v.Agents[0]
	if got.ID != a.ID || got.Hostname != "web-01" || got.Status != "waiting" || got.EnrolledFrom != "10.0.0.5" ||
		got.Fingerprint != shortFingerprint(key.Public()) || got.RevokedAt != nil || v.CanEnrol {
		t.Errorf("agent: %+v, canEnrol %v", got, v.CanEnrol)
	}

	if rec := tw.json(http.MethodPost, "/api/ui/agents/"+a.ID+"/revoke", nil, admin); rec.Code != http.StatusNoContent {
		t.Fatalf("revoke: HTTP %d", rec.Code)
	}
	if a, _ := tw.store.AgentByID(ctx, a.ID); !a.Revoked() {
		t.Error("agent not revoked")
	}
	if rec := tw.json(http.MethodPost, "/api/ui/agents/"+a.ID+"/revoke", nil, admin); rec.Code != http.StatusNotFound {
		t.Errorf("revoke twice: HTTP %d", rec.Code)
	}
	if rec := tw.json(http.MethodPost, "/api/ui/agents/nope/revoke", nil, admin); rec.Code != http.StatusNotFound {
		t.Errorf("revoke unknown: HTTP %d", rec.Code)
	}
	json.Unmarshal(tw.do(http.MethodGet, "/api/ui/agents", nil, admin).Body.Bytes(), &v)
	if v.Agents[0].Status != "revoked" || v.Agents[0].RevokedAt == nil {
		t.Errorf("after revoke: %+v", v.Agents[0])
	}
}

func TestAgentStatus(t *testing.T) {
	now := time.Now()
	stale := 48 * time.Hour
	ago := func(d time.Duration) *time.Time { t := now.Add(-d); return &t }

	for want, a := range map[string]store.Agent{
		"reporting": {EnrolledAt: now.Add(-100 * time.Hour), LastReportAt: ago(time.Hour)},
		"stale":     {EnrolledAt: now.Add(-100 * time.Hour), LastReportAt: ago(49 * time.Hour)},
		"waiting":   {EnrolledAt: now.Add(-time.Hour)},
		"revoked":   {EnrolledAt: now.Add(-time.Hour), RevokedAt: ago(time.Minute)},
	} {
		if got := agentStatus(&a, now, stale); got != want {
			t.Errorf("got %s, want %s", got, want)
		}
	}
	silent := store.Agent{EnrolledAt: now.Add(-49 * time.Hour)}
	if got := agentStatus(&silent, now, stale); got != "stale" {
		t.Errorf("never reported since enrolment: got %s, want stale", got)
	}
}

func TestLoginCodeStep(t *testing.T) {
	tw := newTestWeb(t, "")
	step := func(c *http.Cookie, code string) *httptest.ResponseRecorder {
		return tw.json(http.MethodPost, "/api/ui/login/code", map[string]string{"code": code}, c)
	}
	pending := func() *http.Cookie {
		rec := tw.json(http.MethodPost, "/api/ui/login", map[string]string{"email": "admin@example.org", "password": testPassword}, nil)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("password step: HTTP %d", rec.Code)
		}
		return rec.Result().Cookies()[0]
	}

	if rec := step(nil, "000000"); rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), `"field":"expired"`) {
		t.Errorf("code without password: HTTP %d %s", rec.Code, rec.Body)
	}

	c := pending()
	for range pendingAttempts {
		if rec := step(c, "000000"); !strings.Contains(rec.Body.String(), `"field":"code"`) {
			t.Fatalf("wrong code: %s", rec.Body)
		}
	}
	if rec := step(c, auth.TOTPCodeAt(tw.secret, tw.now)); rec.Code != http.StatusUnauthorized {
		t.Errorf("right code accepted after too many attempts: HTTP %d", rec.Code)
	}

	c = pending()
	tw.now = tw.now.Add(pendingLifetime + time.Minute)
	if rec := step(c, auth.TOTPCodeAt(tw.secret, tw.now)); rec.Code != http.StatusUnauthorized {
		t.Errorf("expired login accepted: HTTP %d", rec.Code)
	}
}
