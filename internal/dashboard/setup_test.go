package dashboard

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/theo-mazars/best-before/internal/dashboard/auth"
	"github.com/theo-mazars/best-before/internal/dashboard/store"
)

func TestSetup(t *testing.T) {
	ctx := context.Background()
	tw := newEmptyTestWeb(t, "https://dashboard.test")
	code, err := tw.w.setup.start(ctx, tw.store)
	if err != nil || !regexp.MustCompile(`^[A-Z2-7]{4}(-[A-Z2-7]{4}){3}$`).MatchString(code) {
		t.Fatalf("setup code %q, %v", code, err)
	}

	if rec := tw.do(http.MethodGet, "/login", nil, nil); rec.Header().Get("Location") != "/setup" {
		t.Errorf("login before setup: HTTP %d to %q", rec.Code, rec.Header().Get("Location"))
	}
	page := tw.do(http.MethodGet, "/setup", nil, nil).Body.String()
	if !strings.Contains(page, "<svg class=\"qr\"") {
		t.Error("no QR code on the setup page")
	}
	secret := regexp.MustCompile(`name="totp_secret" value="([A-Z2-7]+)"`).FindStringSubmatch(page)[1]
	key, _ := auth.DecodeTOTPSecret(secret)

	form := func(setupCode, password, totp string) url.Values {
		return url.Values{"setup_code": {setupCode}, "email": {"owner@example.org"}, "password": {password},
			"password_again": {password}, "totp_secret": {secret}, "code": {totp}}
	}
	totp := auth.TOTPCodeAt(key, tw.now)

	for name, f := range map[string]url.Values{
		"wrong setup code": form("AAAA-BBBB-CCCC-DDDD", testPassword, totp),
		"short password":   form(code, "short", totp),
		"wrong TOTP":       form(code, testPassword, "000000"),
	} {
		if rec := tw.do(http.MethodPost, "/setup", f, nil); rec.Code == http.StatusSeeOther {
			t.Errorf("%s: accepted", name)
		}
	}
	if n, _ := tw.store.CountUsers(ctx); n != 0 {
		t.Fatalf("%d users created by refused attempts", n)
	}

	lower := strings.ToLower(strings.ReplaceAll(code, "-", " "))
	if rec := tw.do(http.MethodPost, "/setup", form(lower, testPassword, totp), nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("setup: HTTP %d\n%s", rec.Code, rec.Body)
	}
	u, err := tw.store.UserByEmail(ctx, "owner@example.org")
	if err != nil || u.Role != store.RoleAdmin {
		t.Fatalf("admin: %+v, %v", u, err)
	}

	// Setup is gone for good, even with the right code.
	if rec := tw.do(http.MethodPost, "/setup", form(code, testPassword, totp), nil); rec.Header().Get("Location") != "/login" {
		t.Errorf("second setup: HTTP %d", rec.Code)
	}
	if rec := tw.do(http.MethodGet, "/login", nil, nil); rec.Code != http.StatusOK {
		t.Errorf("login after setup: HTTP %d", rec.Code)
	}
	if n, _ := tw.store.CountUsers(ctx); n != 1 {
		t.Errorf("%d users", n)
	}
}

func TestNoSetupWhenUsersExist(t *testing.T) {
	tw := newTestWeb(t, "")
	if code, _ := tw.w.setup.start(context.Background(), tw.store); code != "" {
		t.Errorf("setup code issued with an admin present: %s", code)
	}
	if rec := tw.do(http.MethodGet, "/setup", nil, nil); rec.Header().Get("Location") != "/login" {
		t.Errorf("setup page: HTTP %d", rec.Code)
	}
}
