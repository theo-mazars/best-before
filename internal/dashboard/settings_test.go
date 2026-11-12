package dashboard

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/theo-mazars/best-before/internal/dashboard/store"
)

// settingsPage returns the settings, as cookie's user sees them, and the raw
// body.
func (tw *testWeb) settingsPage(cookie *http.Cookie) (settingsView, string) {
	tw.t.Helper()
	rec := tw.do(http.MethodGet, "/api/ui/settings", nil, cookie)
	var v settingsView
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &v) != nil {
		tw.t.Fatalf("settings: HTTP %d\n%s", rec.Code, rec.Body)
	}
	return v, rec.Body.String()
}

func apiErrorOf(t *testing.T, body []byte) apiError {
	t.Helper()
	var e apiError
	if err := json.Unmarshal(body, &e); err != nil {
		t.Fatalf("not an API error: %s", body)
	}
	return e
}

func TestChannelSettings(t *testing.T) {
	tw := newTestWeb(t, "https://dashboard.example.vpn")
	admin := tw.session("admin@example.org")
	ctx := context.Background()
	h := newHook(t)
	const secretURL = "/hook?token=s3cret-token"
	const chans = "/api/ui/settings/channels"

	v, _ := tw.settingsPage(admin)
	if len(v.Channels) != 0 || slices.ContainsFunc(v.Channels, func(c channelView) bool { return c.Emergencies }) {
		t.Errorf("channels at first: %+v", v.Channels)
	}
	if !slices.ContainsFunc(v.Types, func(c channelType) bool { return c.Name == "discord" }) {
		t.Errorf("no Discord channel offered: %+v", v.Types)
	}
	if rec := tw.json(http.MethodPost, chans, channelForm{Type: "gopher", Name: "Gophers"}, admin); rec.Code != http.StatusBadRequest ||
		apiErrorOf(t, rec.Body.Bytes()).Field != "type" {
		t.Errorf("unknown kind: HTTP %d %s", rec.Code, rec.Body)
	}

	// Refused with the reason, never echoing the secret, storing nothing.
	rec := tw.json(http.MethodPost, chans, channelForm{
		Type: "webhook", Name: "<b>Ops</b>", Values: map[string]string{"url": "ftp://example.org" + secretURL}, Emergencies: true,
	}, admin)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "URL must be an https:// URL") || strings.Contains(rec.Body.String(), "s3cret") {
		t.Errorf("invalid channel: HTTP %d\n%s", rec.Code, rec.Body)
	}
	if rec := tw.json(http.MethodPost, chans, channelForm{Type: "webhook", Name: " ", Values: map[string]string{"url": h.srv.URL}}, admin); rec.Code != http.StatusBadRequest ||
		apiErrorOf(t, rec.Body.Bytes()).Field != "name" {
		t.Errorf("no name: HTTP %d %s", rec.Code, rec.Body)
	}
	if got, _ := tw.store.Channels(ctx); len(got) != 0 {
		t.Fatalf("refused channel stored: %+v", got)
	}

	rec = tw.json(http.MethodPost, chans, channelForm{
		Type: "webhook", Name: "Ops", Values: map[string]string{"url": h.srv.URL + secretURL, "authorization": "Bearer abc"},
		Emergencies: true, Digest: true,
	}, admin)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: HTTP %d\n%s", rec.Code, rec.Body)
	}
	stored, _ := tw.store.Channels(ctx)
	if len(stored) != 1 || stored[0].Name != "Ops" || !stored[0].Emergencies || !stored[0].Digest {
		t.Fatalf("channels: %+v", stored)
	}
	c := stored[0]
	if !strings.Contains(rec.Body.String(), c.ID) {
		t.Errorf("create answer lacks the ID: %s", rec.Body)
	}
	// Secrets never reach the database, or the browser, in clear.
	if bytes.Contains(c.Secrets, []byte("s3cret")) || bytes.Contains(c.Settings, []byte("s3cret")) || bytes.Contains(c.Secrets, []byte("Bearer")) {
		t.Errorf("secret stored in clear: %s / %q", c.Settings, c.Secrets)
	}
	v, body := tw.settingsPage(admin)
	if strings.Contains(body, "s3cret") || strings.Contains(body, "Bearer abc") || len(v.Channels) != 1 ||
		!slices.Equal(v.Channels[0].Saved, []string{"url", "authorization"}) {
		t.Errorf("settings:\n%s", body)
	}

	// Saving without the secrets keeps them; removing an optional one works.
	rec = tw.json(http.MethodPut, chans+"/"+c.ID, channelForm{Name: "Ops team", Remove: []string{"authorization"}, Emergencies: true}, admin)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("update: HTTP %d\n%s", rec.Code, rec.Body)
	}
	one, _ := tw.store.Channel(ctx, c.ID)
	ch := tw.w.sealer.channel(*one)
	if ch.Name != "Ops team" || ch.values["url"] != h.srv.URL+secretURL || ch.values["authorization"] != "" || ch.Digest || ch.Problem != "" {
		t.Errorf("after update: %+v %v", ch.Channel, ch.values)
	}
	if rec := tw.json(http.MethodPut, chans+"/nope", channelForm{Name: "Ops"}, admin); rec.Code != http.StatusNotFound {
		t.Errorf("update unknown: HTTP %d", rec.Code)
	}

	rec = tw.do(http.MethodPost, chans+"/"+c.ID+"/test", nil, admin)
	if got := h.take(); rec.Code != http.StatusNoContent || len(got) != 1 || got[0]["event"] != "test" {
		t.Errorf("test: HTTP %d %v", rec.Code, got)
	}
	h.status = http.StatusUnauthorized
	if rec := tw.do(http.MethodPost, chans+"/"+c.ID+"/test", nil, admin); rec.Code != http.StatusBadGateway ||
		!strings.Contains(rec.Body.String(), "401") || !strings.Contains(rec.Body.String(), "Ops team") {
		t.Errorf("failed test: HTTP %d %s", rec.Code, rec.Body)
	}

	if rec := tw.do(http.MethodDelete, chans+"/"+c.ID, nil, admin); rec.Code != http.StatusNoContent {
		t.Errorf("delete: HTTP %d", rec.Code)
	}
	if got, _ := tw.store.Channels(ctx); len(got) != 0 {
		t.Errorf("not deleted: %+v", got)
	}
	if rec := tw.do(http.MethodDelete, chans+"/"+c.ID, nil, admin); rec.Code != http.StatusNotFound {
		t.Errorf("delete again: HTTP %d", rec.Code)
	}
}

func TestAlertSettingsForm(t *testing.T) {
	tw := newTestWeb(t, "")
	admin := tw.session("admin@example.org")
	score, monday := 9.0, 1
	form := func(change func(*alertsForm)) alertsForm {
		f := alertsForm{DigestWeekday: &monday, DigestTime: "08:00", DigestTimezone: "UTC", ReminderDays: 7,
			EmergencyKnownExploited: true, EmergencyMinCVSS: &score, DigestNewMinSeverity: "medium"}
		if change != nil {
			change(&f)
		}
		return f
	}
	eight, eleven := 8, 11.0
	for name, tc := range map[string]struct {
		form  alertsForm
		field string
		want  string
	}{
		"bad day":       {form(func(f *alertsForm) { f.DigestWeekday = &eight }), "digestWeekday", "Choose a day"},
		"bad time":      {form(func(f *alertsForm) { f.DigestTime = "8 o'clock" }), "digestTime", "must look like 08:00"},
		"bad time zone": {form(func(f *alertsForm) { f.DigestTimezone = "Mars/Olympus" }), "digestTimezone", "Unknown time zone"},
		"bad reminder":  {form(func(f *alertsForm) { f.ReminderDays = 0 }), "reminderDays", "every 1 to 365 days"},
		"bad score":     {form(func(f *alertsForm) { f.EmergencyMinCVSS = &eleven }), "emergencyMinCvss", "from 0.1 to 10"},
		"bad severity":  {form(func(f *alertsForm) { f.DigestNewMinSeverity = "unknown" }), "digestNewMinSeverity", "Choose a severity"},
	} {
		rec := tw.json(http.MethodPut, "/api/ui/settings/alerts", tc.form, admin)
		if e := apiErrorOf(t, rec.Body.Bytes()); rec.Code != http.StatusBadRequest || e.Field != tc.field || !strings.Contains(e.Error, tc.want) {
			t.Errorf("%s: HTTP %d %+v", name, rec.Code, e)
		}
	}

	// Unset boxes are off; no score means none.
	friday := 5
	f := form(func(f *alertsForm) {
		f.DigestWeekday, f.DigestTime, f.DigestTimezone, f.ReminderDays = &friday, "17:30", "Europe/London", 3
		f.EmergencyMinCVSS, f.DigestNewMinSeverity, f.DigestUpdates = nil, "high", true
	})
	if rec := tw.json(http.MethodPut, "/api/ui/settings/alerts", f, admin); rec.Code != http.StatusNoContent {
		t.Errorf("save: HTTP %d\n%s", rec.Code, rec.Body)
	}
	v, _ := tw.settingsPage(admin)
	if v.Alerts.DigestWeekday == nil || *v.Alerts.DigestWeekday != 5 || v.EmergencyRule != "known exploited" || v.NextDigestAt == nil {
		t.Errorf("after save: %+v", v)
	}
	s, _ := tw.store.AlertSettings(context.Background())
	if s.DigestWeekday == nil || *s.DigestWeekday != 5 || s.DigestMinute != 17*60+30 || s.DigestTimezone != "Europe/London" ||
		s.ReminderDays != 3 || !s.EmergencyKnownExploited || s.EmergencyMinCVSS != nil || s.DigestNewMinSeverity != "high" ||
		!s.DigestUpdates || s.DigestStale || s.DigestEmergencies || s.DigestAllClear {
		t.Errorf("settings: %+v", s)
	}

	tw.json(http.MethodPut, "/api/ui/settings/alerts", form(func(f *alertsForm) {
		f.DigestWeekday, f.EmergencyKnownExploited, f.EmergencyMinCVSS = nil, false, nil
	}), admin)
	if v, _ := tw.settingsPage(admin); v.NextDigestAt != nil || v.EmergencyRule != "" {
		t.Errorf("no digest, no emergency: %+v", v)
	}
}

// Settings are for admins only.
func TestSettingsNeedAdmin(t *testing.T) {
	tw := newTestWeb(t, "")
	tw.addUser("user@example.org", store.RoleUser)
	user := tw.session("user@example.org")
	if rec := tw.do(http.MethodGet, "/api/ui/settings", nil, user); rec.Code != http.StatusForbidden {
		t.Errorf("settings: HTTP %d", rec.Code)
	}
	if rec := tw.json(http.MethodPost, "/api/ui/settings/channels", channelForm{Type: "email", Name: "Mail"}, user); rec.Code != http.StatusForbidden {
		t.Errorf("new channel: HTTP %d", rec.Code)
	}
	if rec := tw.do(http.MethodPost, "/api/ui/settings/digest", nil, user); rec.Code != http.StatusForbidden {
		t.Errorf("send digest: HTTP %d", rec.Code)
	}
}
