package dashboard

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/theo-mazars/best-before/internal/dashboard/auth"
	"github.com/theo-mazars/best-before/internal/dashboard/store"
)

func trustedProxies(t *testing.T, s string) *proxies {
	t.Helper()
	p, err := parseTrustedProxies(s)
	if err != nil {
		t.Fatal(err)
	}
	return &proxies{trusted: p}
}

func request(peer string, headers ...string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "http://dashboard.vpn/", nil)
	r.RemoteAddr = peer
	for i := 0; i+1 < len(headers); i += 2 {
		r.Header.Add(headers[i], headers[i+1])
	}
	return r
}

func TestClientIP(t *testing.T) {
	p := trustedProxies(t, "10.0.1.0/24, 192.168.5.7")
	for name, tc := range map[string]struct {
		r    *http.Request
		want string
	}{
		"direct":                     {request("10.8.0.4:5000"), "10.8.0.4"},
		"untrusted peer, faked hop":  {request("10.8.0.4:5000", "X-Forwarded-For", "1.2.3.4"), "10.8.0.4"},
		"through the proxy":          {request("10.0.1.9:5000", "X-Forwarded-For", "10.8.0.4"), "10.8.0.4"},
		"client fakes the left hop":  {request("10.0.1.9:5000", "X-Forwarded-For", "6.6.6.6, 10.8.0.4"), "10.8.0.4"},
		"two trusted proxies":        {request("10.0.1.9:5000", "X-Forwarded-For", "10.8.0.4, 192.168.5.7"), "10.8.0.4"},
		"split headers":              {request("10.0.1.9:5000", "X-Forwarded-For", "10.8.0.4", "X-Forwarded-For", "10.0.1.3"), "10.8.0.4"},
		"proxy without header":       {request("10.0.1.9:5000"), "10.0.1.9"},
		"garbage after a real hop":   {request("10.0.1.9:5000", "X-Forwarded-For", "10.8.0.4, not-an-ip"), "10.0.1.9"},
		"every hop trusted":          {request("10.0.1.9:5000", "X-Forwarded-For", "10.0.1.3, 192.168.5.7"), "10.0.1.3"},
		"IPv6 client through proxy":  {request("10.0.1.9:5000", "X-Forwarded-For", "fd00::5"), "fd00::5"},
		"no trust configured at all": {request("10.0.1.9:5000", "X-Forwarded-For", "1.2.3.4"), "10.0.1.9"},
	} {
		trust := p
		if name == "no trust configured at all" {
			trust = nil
		}
		if got := trust.clientIP(tc.r); got != tc.want {
			t.Errorf("%s: got %s, want %s", name, got, tc.want)
		}
	}
}

func TestForwardedHTTPS(t *testing.T) {
	p := trustedProxies(t, "10.0.1.0/24")
	if !p.https(request("10.0.1.9:5000", "X-Forwarded-Proto", "https")) {
		t.Error("trusted proxy's HTTPS not believed")
	}
	if p.https(request("10.8.0.4:5000", "X-Forwarded-Proto", "https")) {
		t.Error("untrusted client's claim of HTTPS believed")
	}
	if p.https(request("10.0.1.9:5000", "X-Forwarded-Proto", "http")) {
		t.Error("plain HTTP taken for HTTPS")
	}
}

func TestParseTrustedProxies(t *testing.T) {
	for _, bad := range []string{"10.0.1.0/33", "proxy.local", "10.0.1"} {
		if _, err := parseTrustedProxies(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	p, err := parseTrustedProxies("10.0.1.7/24, ::1")
	if err != nil || len(p) != 2 || p[0].String() != "10.0.1.0/24" {
		t.Errorf("parsed %v, %v", p, err)
	}
}

func TestProxyModeConfig(t *testing.T) {
	load := func(content string) (Config, error) {
		path := filepath.Join(t.TempDir(), "dashboard.conf")
		os.WriteFile(path, []byte(content), 0o600)
		return LoadConfig(path)
	}
	if _, err := load("listen = 0.0.0.0:8443\ntls = proxy\ntrusted_proxies = 10.0.1.0/24\n"); err != nil {
		t.Errorf("proxy mode on all interfaces: %v", err)
	}
	if _, err := load("listen = 0.0.0.0:8443\ntls = proxy\n"); err != nil {
		t.Errorf("proxy mode without trusted proxies must still start: %v", err)
	}
	if _, err := load("trusted_proxies = 10.0.1.0/24\n"); err == nil {
		t.Error("trusted_proxies accepted without tls = proxy")
	}
	if _, err := load("listen = 0.0.0.0:8443\ntls = off\n"); err == nil {
		t.Error("tls = off accepted on all interfaces")
	}
}

// Logging in through a proxy over plain HTTP must work, with a cookie the
// browser accepts on HTTP; through HTTPS, the cookie must stay strict.
func TestLoginBehindProxy(t *testing.T) {
	tw := newEmptyTestWeb(t, "")
	tw.w.proxies = trustedProxies(t, "10.0.1.0/24")
	tw.addUser("admin@example.org", store.RoleAdmin)

	login := func(proto string) *http.Cookie {
		form := url.Values{"email": {"admin@example.org"}, "password": {testPassword}, "code": {auth.TOTPCodeAt(tw.secret, tw.now)}}
		req := httptest.NewRequest(http.MethodPost, "http://dashboard.vpn/login", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = "10.0.1.9:40000"
		req.Header.Set("X-Forwarded-For", "10.8.0.4")
		req.Header.Set("X-Forwarded-Proto", proto)
		rec := httptest.NewRecorder()
		tw.mux.ServeHTTP(rec, req)
		cookies := rec.Result().Cookies()
		if rec.Code != http.StatusSeeOther || len(cookies) != 1 {
			t.Fatalf("login over %s: HTTP %d, cookies %v", proto, rec.Code, cookies)
		}
		if hsts := rec.Header().Get("Strict-Transport-Security"); (hsts != "") != (proto == "https") {
			t.Errorf("over %s: HSTS %q", proto, hsts)
		}
		tw.now = tw.now.Add(30 * 1e9)
		return cookies[0]
	}

	plain := login("http")
	if plain.Name != plainSessionCookie || plain.Secure || !plain.HttpOnly || plain.SameSite != http.SameSiteStrictMode {
		t.Errorf("plain HTTP cookie: %+v", plain)
	}
	page := httptest.NewRequest(http.MethodGet, "http://dashboard.vpn/agents", nil)
	page.RemoteAddr = "10.0.1.9:40000"
	page.Header.Set("X-Forwarded-Proto", "http")
	page.AddCookie(plain)
	rec := httptest.NewRecorder()
	tw.mux.ServeHTTP(rec, page)
	if rec.Code != http.StatusOK {
		t.Errorf("agents page with the plain cookie: HTTP %d", rec.Code)
	}

	strict := login("https")
	if strict.Name != sessionCookie || !strict.Secure {
		t.Errorf("HTTPS cookie: %+v", strict)
	}

	if _, err := tw.store.UserByEmail(context.Background(), "admin@example.org"); err != nil {
		t.Fatal(err)
	}
}
