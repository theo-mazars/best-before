package dashboard

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/theo-mazars/best-before/internal/dashboard/notify"
	"github.com/theo-mazars/best-before/internal/dashboard/store"
)

// settingsView is the settings page: what is worth sending, when, and
// through which channels.
type settingsView struct {
	Alerts           alertsForm    `json:"alerts"`
	EmergencyRule    string        `json:"emergencyRule"` // empty when nothing is an emergency
	NextDigestAt     *time.Time    `json:"nextDigestAt"`  // nil when no digest is sent
	LastDigestAt     *time.Time    `json:"lastDigestAt"`
	Channels         []channelView `json:"channels"`
	Types            []channelType `json:"types"`
	PublicURLMissing bool          `json:"publicUrlMissing"`
}

// alertsForm holds the alert settings, as shown and as saved.
type alertsForm struct {
	EmergencyKnownExploited bool     `json:"emergencyKnownExploited"`
	EmergencyMinCVSS        *float64 `json:"emergencyMinCvss"` // nil for none
	ReminderDays            int      `json:"reminderDays"`
	DigestWeekday           *int     `json:"digestWeekday"` // 0 is Sunday; nil for no digest
	DigestTime              string   `json:"digestTime"`    // HH:MM
	DigestTimezone          string   `json:"digestTimezone"`
	DigestEmergencies       bool     `json:"digestEmergencies"`
	DigestStale             bool     `json:"digestStale"`
	DigestUpdates           bool     `json:"digestUpdates"`
	DigestNewMinSeverity    string   `json:"digestNewMinSeverity"` // empty to leave them out
	DigestAccepted          bool     `json:"digestAccepted"`
	DigestAllClear          bool     `json:"digestAllClear"`
}

// channelView is a channel as the browser sees it. A secret's value is never
// sent back: Saved only names the secrets that hold one.
type channelView struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Type        string            `json:"type"`
	TypeLabel   string            `json:"typeLabel"`
	Emergencies bool              `json:"emergencies"`
	Digest      bool              `json:"digest"`
	Problem     string            `json:"problem,omitempty"`
	UpdatedAt   time.Time         `json:"updatedAt"`
	Values      map[string]string `json:"values"`
	Saved       []string          `json:"saved"`
}

type channelType struct {
	Name   string         `json:"name"`
	Label  string         `json:"label"`
	Help   string         `json:"help"`
	Digest bool           `json:"digest"`
	Fields []channelField `json:"fields"`
}

type channelField struct {
	Name     string   `json:"name"`
	Label    string   `json:"label"`
	Help     string   `json:"help,omitempty"`
	Secret   bool     `json:"secret"`
	Required bool     `json:"required"`
	Default  string   `json:"default,omitempty"`
	Options  []string `json:"options,omitempty"`
}

// channelForm creates or changes a channel. A secret left empty keeps its
// saved value, unless Remove names it.
type channelForm struct {
	Type        string            `json:"type,omitempty"` // when creating
	Name        string            `json:"name"`
	Emergencies bool              `json:"emergencies"`
	Digest      bool              `json:"digest"`
	Values      map[string]string `json:"values"`
	Remove      []string          `json:"remove"`
}

var channelTypes = func() []channelType {
	out := make([]channelType, 0, len(notify.Types))
	for _, t := range notify.Types {
		ct := channelType{Name: t.Name, Label: t.Label, Help: t.Help, Digest: t.Digest, Fields: []channelField{}}
		for _, f := range t.Fields {
			ct.Fields = append(ct.Fields, channelField{
				Name: f.Name, Label: f.Label, Help: f.Help, Secret: f.Secret,
				Required: f.Required, Default: f.Default, Options: f.Options,
			})
		}
		out = append(out, ct)
	}
	return out
}()

func (w *web) settings(rw http.ResponseWriter, r *http.Request, _ *store.User) {
	s, err := w.store.AlertSettings(r.Context())
	if err != nil {
		w.apiFail(rw, r, err)
		return
	}
	chans, err := w.sealer.channels(r.Context(), w.store)
	if err != nil {
		w.apiFail(rw, r, err)
		return
	}
	v := settingsView{
		Alerts:           alertsFormOf(s),
		EmergencyRule:    emergencyRule(s),
		LastDigestAt:     s.DigestSentAt,
		Channels:         make([]channelView, 0, len(chans)),
		Types:            channelTypes,
		PublicURLMissing: w.cfg.PublicURL == "",
	}
	if last, on := lastDigestSlot(s, w.now()); on {
		n := last.AddDate(0, 0, 7)
		v.NextDigestAt = &n
	}
	for i := range chans {
		v.Channels = append(v.Channels, chans[i].view())
	}
	writeJSON(rw, http.StatusOK, v)
}

func alertsFormOf(s *store.AlertSettings) alertsForm {
	f := alertsForm{
		EmergencyKnownExploited: s.EmergencyKnownExploited,
		EmergencyMinCVSS:        s.EmergencyMinCVSS,
		ReminderDays:            s.ReminderDays,
		DigestTime:              fmt.Sprintf("%02d:%02d", s.DigestMinute/60, s.DigestMinute%60),
		DigestTimezone:          s.DigestTimezone,
		DigestEmergencies:       s.DigestEmergencies,
		DigestStale:             s.DigestStale,
		DigestUpdates:           s.DigestUpdates,
		DigestNewMinSeverity:    s.DigestNewMinSeverity,
		DigestAccepted:          s.DigestAccepted,
		DigestAllClear:          s.DigestAllClear,
	}
	if s.DigestWeekday != nil {
		d := int(*s.DigestWeekday)
		f.DigestWeekday = &d
	}
	return f
}

func (c *channel) view() channelView {
	v := channelView{
		ID: c.ID, Name: c.Name, Type: c.Channel.Type, TypeLabel: c.Channel.Type,
		Emergencies: c.Emergencies, Digest: c.Digest, Problem: c.Problem, UpdatedAt: c.UpdatedAt,
		Values: map[string]string{}, Saved: []string{},
	}
	if c.Type == nil {
		return v
	}
	v.TypeLabel = c.Type.Label
	for _, f := range c.Type.Fields {
		switch {
		case f.Secret && c.values[f.Name] != "":
			v.Saved = append(v.Saved, f.Name)
		case !f.Secret:
			v.Values[f.Name] = c.values[f.Name]
		}
	}
	return v
}

func (w *web) saveAlertSettings(rw http.ResponseWriter, r *http.Request, u *store.User) {
	var f alertsForm
	if !readJSON(rw, r, &f) {
		return
	}
	s := &store.AlertSettings{
		EmergencyKnownExploited: f.EmergencyKnownExploited,
		DigestTimezone:          strings.TrimSpace(f.DigestTimezone),
		DigestEmergencies:       f.DigestEmergencies,
		DigestStale:             f.DigestStale,
		DigestUpdates:           f.DigestUpdates,
		DigestAccepted:          f.DigestAccepted,
		DigestAllClear:          f.DigestAllClear,
		DigestNewMinSeverity:    f.DigestNewMinSeverity,
		ReminderDays:            f.ReminderDays,
	}
	if f.EmergencyMinCVSS != nil {
		if score := *f.EmergencyMinCVSS; score < 0.1 || score > 10 {
			writeError(rw, http.StatusBadRequest, "emergencyMinCvss", "The CVSS score for emergencies must be from 0.1 to 10, or empty for none.")
			return
		}
		s.EmergencyMinCVSS = f.EmergencyMinCVSS
	}
	if s.DigestNewMinSeverity != "" && !slices.Contains(severities, s.DigestNewMinSeverity) {
		writeError(rw, http.StatusBadRequest, "digestNewMinSeverity", "Choose a severity for new vulnerabilities in the digest.")
		return
	}
	if f.DigestWeekday != nil {
		n := *f.DigestWeekday
		if n < 0 || n > 6 {
			writeError(rw, http.StatusBadRequest, "digestWeekday", "Choose a day for the digest.")
			return
		}
		d := time.Weekday(n)
		s.DigestWeekday = &d
	}
	at, err := time.Parse("15:04", f.DigestTime)
	if err != nil {
		writeError(rw, http.StatusBadRequest, "digestTime", "The digest time must look like 08:00.")
		return
	}
	s.DigestMinute = at.Hour()*60 + at.Minute()
	if s.DigestTimezone == "" {
		s.DigestTimezone = "UTC"
	}
	if _, err := time.LoadLocation(s.DigestTimezone); err != nil || len(s.DigestTimezone) > 64 {
		writeError(rw, http.StatusBadRequest, "digestTimezone", "Unknown time zone. Use a name such as Europe/London or UTC.")
		return
	}
	if s.ReminderDays < 1 || s.ReminderDays > 365 {
		writeError(rw, http.StatusBadRequest, "reminderDays", "Reminders must be every 1 to 365 days.")
		return
	}
	if err := w.store.SetAlertSettings(r.Context(), s); err != nil {
		w.apiFail(rw, r, err)
		return
	}
	w.log.Info("alert settings changed", "by", u.Email)
	w.alerts.poke()
	rw.WriteHeader(http.StatusNoContent)
}

// savePreferences changes the lowest severity the user's own pages show.
func (w *web) savePreferences(rw http.ResponseWriter, r *http.Request, u *store.User) {
	var f struct {
		MinSeverity string `json:"minSeverity"`
	}
	if !readJSON(rw, r, &f) {
		return
	}
	if !slices.Contains(severities, f.MinSeverity) {
		writeError(rw, http.StatusBadRequest, "minSeverity", "Choose the lowest severity to show.")
		return
	}
	if err := w.store.SetMinSeverity(r.Context(), u.ID, f.MinSeverity); err != nil {
		w.apiFail(rw, r, err)
		return
	}
	rw.WriteHeader(http.StatusNoContent)
}

// loadChannel reads the channel of the request's path, or answers why not.
func (w *web) loadChannel(rw http.ResponseWriter, r *http.Request) (*channel, bool) {
	stored, err := w.store.Channel(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeError(rw, http.StatusNotFound, "", "This channel does not exist.")
		return nil, false
	}
	if err != nil {
		w.apiFail(rw, r, err)
		return nil, false
	}
	c := w.sealer.channel(*stored)
	if c.Type == nil {
		writeError(rw, http.StatusNotFound, "", c.Problem)
		return nil, false
	}
	return &c, true
}

func (w *web) createChannel(rw http.ResponseWriter, r *http.Request, u *store.User) {
	var f channelForm
	if !readJSON(rw, r, &f) {
		return
	}
	t := notify.TypeByName(f.Type)
	if t == nil {
		writeError(rw, http.StatusBadRequest, "type", "No such kind of channel.")
		return
	}
	c := &channel{Channel: store.Channel{ID: store.NewChannelID(), Type: t.Name}, Type: t, values: notify.Values{}}
	if w.saveChannel(rw, r, u, c, &f, true) {
		writeJSON(rw, http.StatusCreated, map[string]string{"id": c.ID})
	}
}

func (w *web) updateChannel(rw http.ResponseWriter, r *http.Request, u *store.User) {
	var f channelForm
	if !readJSON(rw, r, &f) {
		return
	}
	c, ok := w.loadChannel(rw, r)
	if !ok {
		return
	}
	if f.Type != "" && f.Type != c.Type.Name {
		writeError(rw, http.StatusBadRequest, "type", "A channel's kind cannot change.")
		return
	}
	if w.saveChannel(rw, r, u, c, &f, false) {
		rw.WriteHeader(http.StatusNoContent)
	}
}

// saveChannel checks the form and stores the channel, or answers why not.
func (w *web) saveChannel(rw http.ResponseWriter, r *http.Request, u *store.User, c *channel, f *channelForm, create bool) bool {
	name := strings.TrimSpace(f.Name)
	v := notify.Values{}
	for _, field := range c.Type.Fields {
		val := strings.TrimSpace(f.Values[field.Name])
		if field.Secret && val == "" && !slices.Contains(f.Remove, field.Name) {
			val = c.values[field.Name]
		}
		v[field.Name] = val
	}
	if name == "" || len(name) > 100 || strings.ContainsFunc(name, func(r rune) bool { return r < ' ' }) {
		writeError(rw, http.StatusBadRequest, "name", "Give the channel a name of up to 100 characters.")
		return false
	}
	if _, err := c.Type.New(v); err != nil {
		writeError(rw, http.StatusBadRequest, "", err.Error()+".")
		return false
	}
	settings, secrets := c.Type.Split(v)
	var err error
	if c.Settings, err = jsonObject(settings); err != nil {
		w.apiFail(rw, r, err)
		return false
	}
	if c.Secrets, err = w.sealer.seal(c.ID, secrets); err != nil {
		w.apiFail(rw, r, err)
		return false
	}
	c.Name, c.Emergencies, c.Digest = name, f.Emergencies, f.Digest && c.Type.Digest
	if create {
		err = w.store.CreateChannel(r.Context(), &c.Channel, w.now())
	} else {
		err = w.store.UpdateChannel(r.Context(), &c.Channel, w.now())
	}
	if err != nil {
		w.apiFail(rw, r, err)
		return false
	}
	w.log.Info("notification channel saved", "channel", name, "type", c.Type.Name, "by", u.Email)
	w.alerts.poke() // alerts waiting for a channel
	return true
}

func (w *web) deleteChannel(rw http.ResponseWriter, r *http.Request, u *store.User) {
	id := r.PathValue("id")
	err := w.store.DeleteChannel(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(rw, http.StatusNotFound, "", "This channel does not exist.")
		return
	}
	if err != nil {
		w.apiFail(rw, r, err)
		return
	}
	w.log.Info("notification channel deleted", "channel", id, "by", u.Email)
	rw.WriteHeader(http.StatusNoContent)
}

func (w *web) testChannel(rw http.ResponseWriter, r *http.Request, _ *store.User) {
	c, ok := w.loadChannel(rw, r)
	if !ok {
		return
	}
	if c.sender == nil {
		writeError(rw, http.StatusConflict, "", c.Name+" cannot send: "+c.Problem)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Minute)
	defer cancel()
	err := c.sender.Send(ctx, &notify.Message{
		Event:   notify.EventTest,
		Title:   "Best Before test notification",
		Summary: "This channel works. Best Before will use it for " + c.uses() + ".",
		URL:     w.cfg.PublicURL,
		Details: map[string]any{"channel": c.Name},
	})
	if err != nil {
		w.log.Warn("test notification failed", "channel", c.Name, "error", err)
		writeError(rw, http.StatusBadGateway, "", "The test notification to "+c.Name+" failed: "+err.Error())
		return
	}
	rw.WriteHeader(http.StatusNoContent)
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

func (w *web) sendDigest(rw http.ResponseWriter, r *http.Request, _ *store.User) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	sent, tried, err := w.alerts.sendDigestNow(ctx)
	switch {
	case err != nil:
		w.apiFail(rw, r, err)
	case tried == 0:
		writeError(rw, http.StatusConflict, "", "No channel receives the digest.")
	case sent < tried:
		writeError(rw, http.StatusBadGateway, "", fmt.Sprintf("The digest went to %d of %d channels; the dashboard's log says why.", sent, tried))
	default:
		rw.WriteHeader(http.StatusNoContent)
	}
}
