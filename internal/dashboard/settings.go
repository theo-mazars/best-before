package dashboard

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/theo-mazars/best-before/internal/dashboard/notify"
	"github.com/theo-mazars/best-before/internal/dashboard/store"
)

var weekdays = []time.Weekday{time.Monday, time.Tuesday, time.Wednesday, time.Thursday, time.Friday, time.Saturday, time.Sunday}

// weekdayOption is an option of a select.
type weekdayOption struct {
	Value    string
	Label    string
	Selected bool
}

func (w *web) settingsPage(rw http.ResponseWriter, r *http.Request, u *store.User) {
	w.renderSettings(rw, r, u, http.StatusOK, "", "")
}

func (w *web) renderSettings(rw http.ResponseWriter, r *http.Request, u *store.User, status int, message, problem string) {
	s, err := w.store.AlertSettings(r.Context())
	if err != nil {
		w.fail(rw, r, err)
		return
	}
	chans, err := w.sealer.channels(r.Context(), w.store)
	if err != nil {
		w.fail(rw, r, err)
		return
	}
	days := []weekdayOption{{Value: "off", Label: "Never", Selected: s.DigestWeekday == nil}}
	for _, d := range weekdays {
		days = append(days, weekdayOption{Value: strconv.Itoa(int(d)), Label: d.String(), Selected: s.DigestWeekday != nil && *s.DigestWeekday == d})
	}
	var next *time.Time
	if last, on := lastDigestSlot(s, w.now()); on {
		n := last.AddDate(0, 0, 7)
		next = &n
	}
	emergencies, digests := 0, 0
	for _, c := range chans {
		if c.Emergencies {
			emergencies++
		}
		if c.Digest {
			digests++
		}
	}
	digestSeverities := []weekdayOption{{Value: "", Label: "none: leave this section out", Selected: s.DigestNewMinSeverity == ""}}
	var viewSeverities []weekdayOption
	for _, sev := range severities {
		digestSeverities = append(digestSeverities, weekdayOption{Value: sev, Label: sev + " or worse", Selected: s.DigestNewMinSeverity == sev})
		label := sev + " or worse"
		if sev == "negligible" {
			label = "everything"
		}
		viewSeverities = append(viewSeverities, weekdayOption{Value: sev, Label: label, Selected: u.MinSeverity == sev})
	}
	cvss := ""
	if s.EmergencyMinCVSS != nil {
		cvss = strconv.FormatFloat(*s.EmergencyMinCVSS, 'f', 1, 64)
	}
	w.render(rw, status, "settings", map[string]any{
		"User":              u,
		"Settings":          s,
		"EmergencyRule":     emergencyRule(s),
		"EmergencyCVSS":     cvss,
		"Severities":        digestSeverities,
		"ViewSeverities":    viewSeverities,
		"Weekdays":          days,
		"DigestTime":        fmt.Sprintf("%02d:%02d", s.DigestMinute/60, s.DigestMinute%60),
		"NextDigest":        next,
		"Channels":          chans,
		"Types":             notify.Types,
		"EmergencyChannels": emergencies,
		"DigestChannels":    digests,
		"PublicURLMissing":  w.cfg.PublicURL == "",
		"Message":           message,
		"Error":             problem,
	})
}

func (w *web) saveAlertSettings(rw http.ResponseWriter, r *http.Request, u *store.User) {
	r.Body = http.MaxBytesReader(rw, r.Body, maxFormBytes)
	s := &store.AlertSettings{
		DigestTimezone:          strings.TrimSpace(r.PostFormValue("timezone")),
		EmergencyKnownExploited: r.PostFormValue("emergency_known_exploited") == "on",
		DigestEmergencies:       r.PostFormValue("digest_emergencies") == "on",
		DigestStale:             r.PostFormValue("digest_stale") == "on",
		DigestUpdates:           r.PostFormValue("digest_updates") == "on",
		DigestAccepted:          r.PostFormValue("digest_accepted") == "on",
		DigestAllClear:          r.PostFormValue("digest_all_clear") == "on",
		DigestNewMinSeverity:    r.PostFormValue("digest_new_min_severity"),
	}
	if v := strings.TrimSpace(r.PostFormValue("emergency_cvss")); v != "" {
		score, err := strconv.ParseFloat(v, 64)
		if err != nil || score < 0.1 || score > 10 {
			w.renderSettings(rw, r, u, http.StatusBadRequest, "", "The CVSS score for emergencies must be from 0.1 to 10, or empty for none.")
			return
		}
		s.EmergencyMinCVSS = &score
	}
	if s.DigestNewMinSeverity != "" && !slices.Contains(severities, s.DigestNewMinSeverity) {
		w.renderSettings(rw, r, u, http.StatusBadRequest, "", "Choose a severity for new vulnerabilities in the digest.")
		return
	}
	if day := r.PostFormValue("weekday"); day != "off" {
		n, err := strconv.Atoi(day)
		if err != nil || n < 0 || n > 6 {
			w.renderSettings(rw, r, u, http.StatusBadRequest, "", "Choose a day for the digest.")
			return
		}
		d := time.Weekday(n)
		s.DigestWeekday = &d
	}
	at, err := time.Parse("15:04", r.PostFormValue("time"))
	if err != nil {
		w.renderSettings(rw, r, u, http.StatusBadRequest, "", "The digest time must look like 08:00.")
		return
	}
	s.DigestMinute = at.Hour()*60 + at.Minute()
	if s.DigestTimezone == "" {
		s.DigestTimezone = "UTC"
	}
	if _, err := time.LoadLocation(s.DigestTimezone); err != nil || len(s.DigestTimezone) > 64 {
		w.renderSettings(rw, r, u, http.StatusBadRequest, "", "Unknown time zone. Use a name such as Europe/London or UTC.")
		return
	}
	if s.ReminderDays, err = strconv.Atoi(r.PostFormValue("reminder_days")); err != nil || s.ReminderDays < 1 || s.ReminderDays > 365 {
		w.renderSettings(rw, r, u, http.StatusBadRequest, "", "Reminders must be every 1 to 365 days.")
		return
	}
	if err := w.store.SetAlertSettings(r.Context(), s); err != nil {
		w.fail(rw, r, err)
		return
	}
	w.log.Info("alert settings changed", "by", u.Email)
	w.alerts.poke()
	w.renderSettings(rw, r, u, http.StatusOK, "Saved.", "")
}

// saveView changes the lowest severity the user's own pages show.
func (w *web) saveView(rw http.ResponseWriter, r *http.Request, u *store.User) {
	r.Body = http.MaxBytesReader(rw, r.Body, maxFormBytes)
	sev := r.PostFormValue("min_severity")
	if !slices.Contains(severities, sev) {
		w.renderSettings(rw, r, u, http.StatusBadRequest, "", "Choose the lowest severity to show.")
		return
	}
	if err := w.store.SetMinSeverity(r.Context(), u.ID, sev); err != nil {
		w.fail(rw, r, err)
		return
	}
	u.MinSeverity = sev
	w.renderSettings(rw, r, u, http.StatusOK, "Saved.", "")
}

// fieldView is one field of a channel's form. A secret's value is never sent
// back to the browser.
type fieldView struct {
	notify.Field
	Value string
	Saved bool // a secret is stored
}

func (w *web) newChannelPage(rw http.ResponseWriter, r *http.Request, u *store.User) {
	t := notify.TypeByName(r.URL.Query().Get("type"))
	if t == nil {
		w.render(rw, http.StatusNotFound, "error", map[string]any{"User": u, "Message": "No such kind of channel."})
		return
	}
	w.renderChannel(rw, u, http.StatusOK, t, nil, notify.Values{}, "", true, t.Digest, "")
}

func (w *web) channelPage(rw http.ResponseWriter, r *http.Request, u *store.User) {
	c, ok := w.loadChannel(rw, r, u)
	if !ok {
		return
	}
	w.renderChannel(rw, u, http.StatusOK, c.Type, c, c.values, c.Name, c.Emergencies, c.Digest, c.Problem)
}

func (w *web) loadChannel(rw http.ResponseWriter, r *http.Request, u *store.User) (*channel, bool) {
	stored, err := w.store.Channel(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		w.render(rw, http.StatusNotFound, "error", map[string]any{"User": u, "Message": "No such channel."})
		return nil, false
	}
	if err != nil {
		w.fail(rw, r, err)
		return nil, false
	}
	c := w.sealer.channel(*stored)
	if c.Type == nil {
		w.render(rw, http.StatusNotFound, "error", map[string]any{"User": u, "Message": c.Problem})
		return nil, false
	}
	return &c, true
}

func (w *web) renderChannel(rw http.ResponseWriter, u *store.User, status int, t *notify.Type, c *channel, v notify.Values, name string, emergencies, digest bool, problem string) {
	fields := make([]fieldView, 0, len(t.Fields))
	for _, f := range t.Fields {
		fv := fieldView{Field: f}
		if f.Secret {
			fv.Saved = c != nil && c.values[f.Name] != ""
		} else {
			fv.Value = v[f.Name]
		}
		fields = append(fields, fv)
	}
	w.render(rw, status, "channel", map[string]any{
		"User": u, "Type": t, "Channel": c, "Fields": fields, "Name": name,
		"Emergencies": emergencies, "Digest": digest, "Error": problem,
	})
}

func (w *web) createChannel(rw http.ResponseWriter, r *http.Request, u *store.User) {
	r.Body = http.MaxBytesReader(rw, r.Body, maxFormBytes)
	t := notify.TypeByName(r.PostFormValue("type"))
	if t == nil {
		w.render(rw, http.StatusBadRequest, "error", map[string]any{"User": u, "Message": "No such kind of channel."})
		return
	}
	c := &channel{Channel: store.Channel{ID: store.NewChannelID(), Type: t.Name}, Type: t, values: notify.Values{}}
	w.saveChannel(rw, r, u, c, true)
}

func (w *web) updateChannel(rw http.ResponseWriter, r *http.Request, u *store.User) {
	r.Body = http.MaxBytesReader(rw, r.Body, maxFormBytes)
	c, ok := w.loadChannel(rw, r, u)
	if !ok {
		return
	}
	w.saveChannel(rw, r, u, c, false)
}

// saveChannel checks the form and stores the channel. A secret left empty
// keeps its saved value, unless asked to remove it.
func (w *web) saveChannel(rw http.ResponseWriter, r *http.Request, u *store.User, c *channel, create bool) {
	name := strings.TrimSpace(r.PostFormValue("name"))
	emergencies := r.PostFormValue("emergencies") == "on"
	digest := r.PostFormValue("digest") == "on" && c.Type.Digest
	v := notify.Values{}
	for _, f := range c.Type.Fields {
		val := strings.TrimSpace(r.PostFormValue("field_" + f.Name))
		if f.Secret && val == "" && r.PostFormValue("remove_"+f.Name) != "on" {
			val = c.values[f.Name]
		}
		v[f.Name] = val
	}
	var cur *channel
	if !create {
		cur = c
	}
	refuse := func(msg string) {
		w.renderChannel(rw, u, http.StatusBadRequest, c.Type, cur, v, name, emergencies, digest, msg)
	}
	if name == "" || len(name) > 100 || strings.ContainsFunc(name, func(r rune) bool { return r < ' ' }) {
		refuse("Give the channel a name of up to 100 characters.")
		return
	}
	if _, err := c.Type.New(v); err != nil {
		refuse(err.Error() + ".")
		return
	}
	settings, secrets := c.Type.Split(v)
	var err error
	if c.Settings, err = jsonObject(settings); err != nil {
		w.fail(rw, r, err)
		return
	}
	if c.Secrets, err = w.sealer.seal(c.ID, secrets); err != nil {
		w.fail(rw, r, err)
		return
	}
	c.Name, c.Emergencies, c.Digest = name, emergencies, digest
	if create {
		err = w.store.CreateChannel(r.Context(), &c.Channel, w.now())
	} else {
		err = w.store.UpdateChannel(r.Context(), &c.Channel, w.now())
	}
	if err != nil {
		w.fail(rw, r, err)
		return
	}
	w.log.Info("notification channel saved", "channel", name, "type", c.Type.Name, "by", u.Email)
	w.alerts.poke() // alerts waiting for a channel
	http.Redirect(rw, r, "/settings", http.StatusSeeOther)
}

func (w *web) deleteChannel(rw http.ResponseWriter, r *http.Request, u *store.User) {
	id := r.PathValue("id")
	if err := w.store.DeleteChannel(r.Context(), id); err != nil && !errors.Is(err, store.ErrNotFound) {
		w.fail(rw, r, err)
		return
	}
	w.log.Info("notification channel deleted", "channel", id, "by", u.Email)
	http.Redirect(rw, r, "/settings", http.StatusSeeOther)
}

func (w *web) testChannel(rw http.ResponseWriter, r *http.Request, u *store.User) {
	c, ok := w.loadChannel(rw, r, u)
	if !ok {
		return
	}
	if c.sender == nil {
		w.renderSettings(rw, r, u, http.StatusConflict, "", c.Name+" cannot send: "+c.Problem)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Minute)
	defer cancel()
	err := c.sender.Send(ctx, &notify.Message{
		Event:   notify.EventTest,
		Title:   "Best Before test notification",
		Text:    "This channel works. Best Before will use it for " + c.uses() + ".",
		URL:     w.cfg.PublicURL,
		Details: map[string]any{"channel": c.Name},
	})
	if err != nil {
		w.log.Warn("test notification failed", "channel", c.Name, "error", err)
		w.renderSettings(rw, r, u, http.StatusBadGateway, "", "The test notification to "+c.Name+" failed: "+err.Error())
		return
	}
	w.renderSettings(rw, r, u, http.StatusOK, "Test notification sent to "+c.Name+".", "")
}

func (c *channel) uses() string {
	switch {
	case c.Emergencies && c.Digest:
		return "emergencies and the weekly digest"
	case c.Emergencies:
		return "emergencies"
	case c.Digest:
		return "the weekly digest"
	}
	return "nothing yet: choose emergencies or the digest in its settings"
}

func (w *web) sendDigest(rw http.ResponseWriter, r *http.Request, u *store.User) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	sent, tried, err := w.alerts.sendDigestNow(ctx)
	switch {
	case err != nil:
		w.fail(rw, r, err)
	case tried == 0:
		w.renderSettings(rw, r, u, http.StatusConflict, "", "No channel receives the digest.")
	case sent < tried:
		w.renderSettings(rw, r, u, http.StatusBadGateway, "", fmt.Sprintf("The digest went to %d of %d channels; the dashboard's log says why.", sent, tried))
	default:
		w.renderSettings(rw, r, u, http.StatusOK, "Digest sent. The next one is still sent on schedule.", "")
	}
}
