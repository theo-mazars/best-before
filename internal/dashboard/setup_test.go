package dashboard

import (
	"context"
	"encoding/json"
	"net/http"
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

	var s sessionView
	json.Unmarshal(tw.do(http.MethodGet, "/api/ui/session", nil, nil).Body.Bytes(), &s)
	if !s.Setup {
		t.Error("session does not ask for setup")
	}
	var v setupView
	if rec := tw.do(http.MethodGet, "/api/ui/setup", nil, nil); rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &v) != nil || v.QRPath == "" {
		t.Fatalf("setup info: HTTP %d %s", rec.Code, rec.Body)
	}
	key, _ := auth.DecodeTOTPSecret(v.Secret)

	form := func(setupCode, password, totp string) map[string]string {
		return map[string]string{"setupCode": setupCode, "email": "owner@example.org", "password": password,
			"passwordAgain": password, "secret": v.Secret, "code": totp}
	}
	totp := auth.TOTPCodeAt(key, tw.now)

	for name, c := range map[string]struct {
		form  map[string]string
		field string
	}{
		"wrong setup code": {form("AAAA-BBBB-CCCC-DDDD", testPassword, totp), "setupCode"},
		"short password":   {form(code, "short", totp), "password"},
		"wrong TOTP":       {form(code, testPassword, "000000"), "code"},
	} {
		rec := tw.json(http.MethodPost, "/api/ui/setup", c.form, nil)
		var e apiError
		json.Unmarshal(rec.Body.Bytes(), &e)
		if rec.Code == http.StatusNoContent || e.Field != c.field {
			t.Errorf("%s: HTTP %d, field %q", name, rec.Code, e.Field)
		}
	}
	if n, _ := tw.store.CountUsers(ctx); n != 0 {
		t.Fatalf("%d users created by refused attempts", n)
	}

	lower := strings.ToLower(strings.ReplaceAll(code, "-", " "))
	if rec := tw.json(http.MethodPost, "/api/ui/setup", form(lower, testPassword, totp), nil); rec.Code != http.StatusNoContent {
		t.Fatalf("setup: HTTP %d\n%s", rec.Code, rec.Body)
	}
	u, err := tw.store.UserByEmail(ctx, "owner@example.org")
	if err != nil || u.Role != store.RoleAdmin {
		t.Fatalf("admin: %+v, %v", u, err)
	}

	// Setup is gone for good, even with the right code.
	if rec := tw.json(http.MethodPost, "/api/ui/setup", form(code, testPassword, totp), nil); rec.Code != http.StatusConflict {
		t.Errorf("second setup: HTTP %d", rec.Code)
	}
	if rec := tw.do(http.MethodGet, "/api/ui/session", nil, nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("session after setup: HTTP %d", rec.Code)
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
	if rec := tw.do(http.MethodGet, "/api/ui/setup", nil, nil); rec.Code != http.StatusConflict {
		t.Errorf("setup info: HTTP %d", rec.Code)
	}
}
