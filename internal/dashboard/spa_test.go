package dashboard

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"strings"
	"testing"
)

func TestSPA(t *testing.T) {
	tw := newTestWeb(t, "")

	rec := tw.do(http.MethodGet, "/servers/x/y", nil, nil)
	if rec.Code != http.StatusOK || rec.Body.String() != string(tw.w.spa.index) || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("app route: HTTP %d, cache %q", rec.Code, rec.Header().Get("Cache-Control"))
	}
	csp := rec.Header().Get("Content-Security-Policy")
	if strings.Contains(csp, "unsafe-inline") || !strings.Contains(csp, "script-src 'self'") {
		t.Errorf("CSP: %q", csp)
	}
	for _, m := range inlineScript.FindAllSubmatch(tw.w.spa.index, -1) {
		h := sha256.Sum256(m[1])
		if !strings.Contains(csp, "'sha256-"+base64.StdEncoding.EncodeToString(h[:])+"'") {
			t.Errorf("inline script not allowed by the CSP: %q", csp)
		}
	}

	for _, path := range []string{"/api/ui/nope", "/api/v1/nope"} {
		if rec := tw.do(http.MethodGet, path, nil, nil); rec.Code != http.StatusNotFound {
			t.Errorf("%s: HTTP %d", path, rec.Code)
		}
	}
	if rec := tw.do(http.MethodPost, "/api/ui/login", nil, nil, "Content-Type", "text/plain"); rec.Code != http.StatusUnsupportedMediaType {
		t.Errorf("login without JSON: HTTP %d", rec.Code)
	}
}

func TestSessionShowsNoSecrets(t *testing.T) {
	tw := newTestWeb(t, "")
	rec := tw.do(http.MethodGet, "/api/ui/session", nil, tw.session("admin@example.org"))
	body := rec.Body.String()
	if rec.Code != http.StatusOK || !strings.Contains(body, `"email":"admin@example.org"`) {
		t.Fatalf("session: HTTP %d %s", rec.Code, body)
	}
	for _, s := range []string{"PasswordHash", "TOTPSecret", "passwordHash", "totp"} {
		if strings.Contains(body, s) {
			t.Errorf("session shows %s", s)
		}
	}
}
