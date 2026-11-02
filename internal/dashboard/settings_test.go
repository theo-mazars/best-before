package dashboard

import (
	"bytes"
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/theo-mazars/best-before/internal/dashboard/store"
)

func TestChannelSettings(t *testing.T) {
	tw := newTestWeb(t, "https://dashboard.example.vpn")
	admin := tw.session("admin@example.org")
	ctx := context.Background()
	h := newHook(t)
	const secretURL = "/hook?token=s3cret-token"

	page := tw.do(http.MethodGet, "/settings", nil, admin).Body.String()
	for _, want := range []string{"No channels yet", "No channel receives emergencies", `href="/settings/channels/new?type=discord"`} {
		if !strings.Contains(page, want) {
			t.Errorf("settings page lacks %q", want)
		}
	}
	if rec := tw.do(http.MethodGet, "/settings/channels/new?type=gopher", nil, admin); rec.Code != http.StatusNotFound {
		t.Errorf("unknown kind: HTTP %d", rec.Code)
	}

	// Refused with the reason, keeping what was typed but the secret.
	rec := tw.do(http.MethodPost, "/settings/channels", url.Values{
		"type": {"webhook"}, "name": {"<b>Ops</b>"}, "field_url": {"ftp://example.org" + secretURL}, "emergencies": {"on"},
	}, admin)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "URL must be an https:// URL") ||
		!strings.Contains(rec.Body.String(), `value="&lt;b&gt;Ops&lt;/b&gt;"`) || strings.Contains(rec.Body.String(), "s3cret") {
		t.Errorf("invalid channel: HTTP %d\n%s", rec.Code, rec.Body)
	}

	rec = tw.do(http.MethodPost, "/settings/channels", url.Values{
		"type": {"webhook"}, "name": {"Ops"}, "field_url": {h.srv.URL + secretURL}, "field_authorization": {"Bearer abc"},
		"emergencies": {"on"}, "digest": {"on"},
	}, admin)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("create: HTTP %d\n%s", rec.Code, rec.Body)
	}
	chans, _ := tw.store.Channels(ctx)
	if len(chans) != 1 || chans[0].Name != "Ops" || !chans[0].Emergencies || !chans[0].Digest {
		t.Fatalf("channels: %+v", chans)
	}
	c := chans[0]
	// Secrets never reach the database, or the browser, in clear.
	if bytes.Contains(c.Secrets, []byte("s3cret")) || bytes.Contains(c.Settings, []byte("s3cret")) || bytes.Contains(c.Secrets, []byte("Bearer")) {
		t.Errorf("secret stored in clear: %s / %q", c.Settings, c.Secrets)
	}
	page = tw.do(http.MethodGet, "/settings/channels/"+c.ID, nil, admin).Body.String()
	if strings.Contains(page, "s3cret") || strings.Contains(page, "Bearer abc") || !strings.Contains(page, "saved; leave empty to keep") {
		t.Errorf("channel page:\n%s", page)
	}

	// Saving without the secrets keeps them; removing an optional one works.
	rec = tw.do(http.MethodPost, "/settings/channels/"+c.ID, url.Values{"name": {"Ops team"}, "remove_authorization": {"on"}, "emergencies": {"on"}}, admin)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("update: HTTP %d\n%s", rec.Code, rec.Body)
	}
	stored, _ := tw.store.Channel(ctx, c.ID)
	ch := tw.w.sealer.channel(*stored)
	if ch.Name != "Ops team" || ch.values["url"] != h.srv.URL+secretURL || ch.values["authorization"] != "" || ch.Digest || ch.Problem != "" {
		t.Errorf("after update: %+v %v", ch.Channel, ch.values)
	}

	rec = tw.do(http.MethodPost, "/settings/channels/"+c.ID+"/test", nil, admin)
	if got := h.take(); rec.Code != http.StatusOK || len(got) != 1 || got[0]["event"] != "test" ||
		!strings.Contains(rec.Body.String(), "Test notification sent to Ops team.") {
		t.Errorf("test: HTTP %d %v", rec.Code, got)
	}
	h.status = http.StatusUnauthorized
	if rec := tw.do(http.MethodPost, "/settings/channels/"+c.ID+"/test", nil, admin); rec.Code != http.StatusBadGateway ||
		!strings.Contains(rec.Body.String(), "401") {
		t.Errorf("failed test: HTTP %d", rec.Code)
	}

	if rec := tw.do(http.MethodPost, "/settings/channels/"+c.ID+"/delete", nil, admin); rec.Code != http.StatusSeeOther {
		t.Errorf("delete: HTTP %d", rec.Code)
	}
	if chans, _ := tw.store.Channels(ctx); len(chans) != 0 {
		t.Errorf("not deleted: %+v", chans)
	}
}

func TestAlertSettingsForm(t *testing.T) {
	tw := newTestWeb(t, "")
	admin := tw.session("admin@example.org")
	form := func(change ...string) url.Values {
		v := url.Values{"weekday": {"1"}, "time": {"08:00"}, "timezone": {"UTC"}, "reminder_days": {"7"},
			"emergency_known_exploited": {"on"}, "emergency_cvss": {"9.0"}, "digest_new_min_severity": {"medium"}}
		for i := 0; i+1 < len(change); i += 2 {
			v.Set(change[i], change[i+1])
		}
		return v
	}
	for name, tc := range map[string]struct {
		form url.Values
		want string
	}{
		"bad day":       {form("weekday", "8"), "Choose a day"},
		"bad time":      {form("time", "8 o'clock"), "must look like 08:00"},
		"bad time zone": {form("timezone", "Mars/Olympus"), "Unknown time zone"},
		"bad reminder":  {form("reminder_days", "0"), "every 1 to 365 days"},
		"bad score":     {form("emergency_cvss", "11"), "from 0.1 to 10"},
		"bad severity":  {form("digest_new_min_severity", "unknown"), "Choose a severity"},
	} {
		rec := tw.do(http.MethodPost, "/settings/alerts", tc.form, admin)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), tc.want) {
			t.Errorf("%s: HTTP %d", name, rec.Code)
		}
	}

	// Unticked boxes are off; an empty score means none.
	f := form("weekday", "5", "time", "17:30", "timezone", "Europe/London", "reminder_days", "3",
		"emergency_cvss", "", "digest_new_min_severity", "high", "digest_updates", "on")
	rec := tw.do(http.MethodPost, "/settings/alerts", f, admin)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `<option value="5" selected>Friday</option>`) ||
		!strings.Contains(rec.Body.String(), "vulnerabilities with a fix, known exploited.") {
		t.Errorf("save: HTTP %d\n%s", rec.Code, rec.Body)
	}
	s, _ := tw.store.AlertSettings(context.Background())
	if s.DigestWeekday == nil || *s.DigestWeekday != 5 || s.DigestMinute != 17*60+30 || s.DigestTimezone != "Europe/London" ||
		s.ReminderDays != 3 || !s.EmergencyKnownExploited || s.EmergencyMinCVSS != nil || s.DigestNewMinSeverity != "high" ||
		!s.DigestUpdates || s.DigestStale || s.DigestEmergencies || s.DigestAllClear {
		t.Errorf("settings: %+v", s)
	}

	tw.do(http.MethodPost, "/settings/alerts", form("weekday", "off", "emergency_known_exploited", "", "emergency_cvss", ""), admin)
	page := tw.do(http.MethodGet, "/settings", nil, admin).Body.String()
	if !strings.Contains(page, "No digest is sent.") || !strings.Contains(page, "<strong>none</strong>, as no rule below") {
		t.Errorf("settings page:\n%s", page)
	}
}

// Settings are for admins only.
func TestSettingsNeedAdmin(t *testing.T) {
	tw := newTestWeb(t, "")
	tw.addUser("user@example.org", store.RoleUser)
	user := tw.session("user@example.org")
	for _, path := range []string{"/settings", "/settings/channels/new?type=email"} {
		if rec := tw.do(http.MethodGet, path, nil, user); rec.Code != http.StatusForbidden {
			t.Errorf("%s: HTTP %d", path, rec.Code)
		}
	}
	if rec := tw.do(http.MethodPost, "/settings/digest", nil, user); rec.Code != http.StatusForbidden {
		t.Errorf("send digest: HTTP %d", rec.Code)
	}
}
