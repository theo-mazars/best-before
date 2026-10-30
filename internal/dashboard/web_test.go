package dashboard

import (
	"context"
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
	tw.w, err = newWeb(st, key, cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), clock)
	if err != nil {
		t.Fatal(err)
	}
	tw.w.routes(tw.mux)

	tw.secret, _ = auth.NewTOTPSecret()
	tw.addUser("admin@example.org", store.RoleAdmin)
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

func (tw *testWeb) login(email, password, code string) *httptest.ResponseRecorder {
	return tw.do(http.MethodPost, "/login", url.Values{"email": {email}, "password": {password}, "code": {code}}, nil)
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
		if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), "Email, password or code is incorrect") {
			t.Errorf("%s: HTTP %d", name, rec.Code)
		}
		if len(rec.Result().Cookies()) != 0 {
			t.Errorf("%s: cookie set", name)
		}
	}

	rec := tw.login("admin@example.org", testPassword, code)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/agents" {
		t.Fatalf("login: HTTP %d", rec.Code)
	}
	c := rec.Result().Cookies()[0]
	if c.Name != sessionCookie || !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.Path != "/" {
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

	if rec := tw.do(http.MethodGet, "/agents", nil, nil); rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login" {
		t.Errorf("no session: HTTP %d", rec.Code)
	}
	forged := &http.Cookie{Name: sessionCookie, Value: "made-up"}
	if rec := tw.do(http.MethodGet, "/agents", nil, forged); rec.Code != http.StatusSeeOther {
		t.Errorf("forged session: HTTP %d", rec.Code)
	}
	if rec := tw.do(http.MethodGet, "/agents", nil, tw.session("user@example.org")); rec.Code != http.StatusForbidden {
		t.Errorf("user role: HTTP %d", rec.Code)
	}

	admin := tw.session("admin@example.org")
	rec := tw.do(http.MethodGet, "/agents", nil, admin)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "The fridge is empty") {
		t.Errorf("admin: HTTP %d", rec.Code)
	}
	if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'none'") {
		t.Errorf("CSP: %q", csp)
	}

	tw.do(http.MethodPost, "/logout", url.Values{}, admin)
	if rec := tw.do(http.MethodGet, "/agents", nil, admin); rec.Code != http.StatusSeeOther {
		t.Errorf("session still valid after logout: HTTP %d", rec.Code)
	}
}

func TestEnrolmentCodePage(t *testing.T) {
	tw := newTestWeb(t, "")
	if rec := tw.do(http.MethodPost, "/agents/codes", url.Values{}, tw.session("admin@example.org")); rec.Code != http.StatusConflict {
		t.Errorf("without public_url: HTTP %d", rec.Code)
	}

	tw = newTestWeb(t, "https://dashboard.test:8443")
	rec := tw.do(http.MethodPost, "/agents/codes", url.Values{}, tw.session("admin@example.org"))
	i := strings.Index(rec.Body.String(), "bb1_")
	if rec.Code != http.StatusOK || i < 0 {
		t.Fatalf("code page: HTTP %d", rec.Code)
	}
	raw := rec.Body.String()[i:]
	code, err := protocol.ParseEnrolmentCode(raw[:strings.IndexAny(raw, "<\n ")])
	if err != nil {
		t.Fatal(err)
	}
	if code.URL != "https://dashboard.test:8443" || code.Fingerprint != tw.w.key.Public().Fingerprint() {
		t.Errorf("code: %+v", code)
	}
	key, _ := protocol.GenerateAgentKey()
	if _, err := tw.store.RedeemEnrolmentCode(context.Background(), code.SecretHash(),
		store.NewAgent{PublicKey: key.Public(), Hostname: "web-01"}, tw.now); err != nil {
		t.Errorf("code from the page does not redeem: %v", err)
	}
}

func TestCrossSiteRequestsRefused(t *testing.T) {
	tw := newTestWeb(t, "https://dashboard.test")
	rec := tw.do(http.MethodPost, "/agents/codes", url.Values{}, tw.session("admin@example.org"), "Sec-Fetch-Site", "cross-site")
	if rec.Code != http.StatusForbidden {
		t.Errorf("cross-site POST: HTTP %d", rec.Code)
	}
}

func TestAgentsPageEscapesAndRevokes(t *testing.T) {
	tw := newTestWeb(t, "")
	ctx := context.Background()
	tw.store.CreateEnrolmentCode(ctx, [32]byte{1}, "", tw.now, tw.now.Add(time.Hour))
	key, _ := protocol.GenerateAgentKey()
	a, err := tw.store.RedeemEnrolmentCode(ctx, [32]byte{1},
		store.NewAgent{PublicKey: key.Public(), Hostname: `<script>alert("pwned")</script>`, AgentVersion: "v1", EnrolledFromIP: "10.0.0.5"}, tw.now)
	if err != nil {
		t.Fatal(err)
	}

	admin := tw.session("admin@example.org")
	body := tw.do(http.MethodGet, "/agents", nil, admin).Body.String()
	if strings.Contains(body, "<script>") || !strings.Contains(body, "&lt;script&gt;") {
		t.Error("hostname not escaped")
	}

	if rec := tw.do(http.MethodPost, "/agents/"+a.ID+"/revoke", url.Values{}, admin); rec.Code != http.StatusSeeOther {
		t.Fatalf("revoke: HTTP %d", rec.Code)
	}
	got, _ := tw.store.AgentByID(ctx, a.ID)
	if !got.Revoked() {
		t.Error("agent not revoked")
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
