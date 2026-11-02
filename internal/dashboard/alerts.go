package dashboard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/theo-mazars/best-before/internal/dashboard/notify"
	"github.com/theo-mazars/best-before/internal/dashboard/store"
	"github.com/theo-mazars/best-before/internal/dashboard/vulns"
	"github.com/theo-mazars/best-before/internal/report"
)

const (
	// How often the alerter looks for something to send, besides being woken
	// after each match.
	alertInterval = time.Minute
	// How long to wait before trying again when no channel accepted a
	// message.
	alertRetry = 15 * time.Minute
)

// alerter sends emergencies as soon as they are found, says when a server
// goes stale and when it comes back, and sends the weekly digest. What it
// has sent is recorded in the database, so that each alert is sent once.
type alerter struct {
	store  *store.Store
	sealer *sealer
	cfg    Config
	log    *slog.Logger
	now    func() time.Time

	wake chan struct{}
	// Until when to hold back after no channel accepted a message.
	alertsHeld time.Time
	digestHeld time.Time
}

func newAlerter(st *store.Store, s *sealer, cfg Config, log *slog.Logger, now func() time.Time) *alerter {
	return &alerter{store: st, sealer: s, cfg: cfg, log: log, now: now, wake: make(chan struct{}, 1)}
}

// poke asks for a check soon, e.g. after a report has been matched.
func (a *alerter) poke() {
	if a == nil {
		return
	}
	select {
	case a.wake <- struct{}{}:
	default:
	}
}

func (a *alerter) run(ctx context.Context) {
	t := time.NewTicker(alertInterval)
	defer t.Stop()
	for {
		if err := a.check(ctx); err != nil && ctx.Err() == nil {
			a.log.Error("checking for alerts", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-a.wake:
		case <-t.C:
		}
	}
}

// isEmergency says whether a finding is sent at once: a fix exists, and the
// vulnerability is known to be exploited or scores enough, as the settings
// say. Findings without a fix are silent until one appears.
func isEmergency(f *store.Finding, s *store.AlertSettings) bool {
	if !f.Fixable() {
		return false
	}
	return (s.EmergencyKnownExploited && f.KnownExploited) || (s.EmergencyMinCVSS != nil && f.CVSS >= *s.EmergencyMinCVSS)
}

type alertKey struct{ agent, kind, vuln string }

func keyOf(a *store.Alert) alertKey { return alertKey{a.AgentID, a.Kind, a.Vulnerability} }

// outgoing is a message, and the alerts to mark as sent once it is.
type outgoing struct {
	msg    *notify.Message
	alerts []store.Alert
}

func (a *alerter) check(ctx context.Context) error {
	now := a.now()
	settings, err := a.store.AlertSettings(ctx)
	if err != nil {
		return err
	}
	agents, err := a.store.Agents(ctx)
	if err != nil {
		return err
	}
	stored, err := a.store.Alerts(ctx)
	if err != nil {
		return err
	}
	open := map[alertKey]store.Alert{}
	for _, al := range stored {
		open[keyOf(&al)] = al
	}

	var out []outgoing
	for i := range agents {
		ag := &agents[i]
		msgs, err := a.checkAgent(ctx, ag, open, settings, now)
		if err != nil {
			return fmt.Errorf("%s: %w", ag.Hostname, err)
		}
		out = append(out, msgs...)
	}

	chans, err := a.sealer.channels(ctx, a.store)
	if err != nil {
		return err
	}
	if len(out) > 0 && !now.Before(a.alertsHeld) {
		forAlerts := func(c *channel) bool { return c.Emergencies }
		for _, o := range out {
			sent, tried := send(ctx, chans, forAlerts, o.msg, a.log)
			switch {
			case tried == 0:
				// Nowhere to send: dropped, not kept for a channel added
				// later. The dashboard shows the server's state anyway.
				if err := a.store.AlertsNotified(ctx, o.alerts, now); err != nil {
					return err
				}
			case sent == 0:
				a.log.Error("no channel accepted an alert; trying again later", "title", o.msg.Title, "retry_in", alertRetry)
				a.alertsHeld = now.Add(alertRetry)
				return a.digest(ctx, chans, settings, now)
			default:
				if err := a.store.AlertsNotified(ctx, o.alerts, now); err != nil {
					return err
				}
			}
		}
	}
	return a.digest(ctx, chans, settings, now)
}

// checkAgent raises and closes one server's alerts, and returns the
// messages due about it.
func (a *alerter) checkAgent(ctx context.Context, ag *store.Agent, open map[alertKey]store.Alert, settings *store.AlertSettings, now time.Time) ([]outgoing, error) {
	mine := func(kind string) []store.Alert {
		var out []store.Alert
		for k, al := range open {
			if k.agent == ag.ID && k.kind == kind {
				out = append(out, al)
			}
		}
		slices.SortFunc(out, func(x, y store.Alert) int { return strings.Compare(x.Vulnerability, y.Vulnerability) })
		return out
	}
	if ag.Revoked() {
		for _, al := range append(mine(store.AlertStale), mine(store.AlertEmergency)...) {
			if err := a.store.CloseAlert(ctx, &al); err != nil {
				return nil, err
			}
		}
		return nil, nil
	}

	var out []outgoing
	server := a.serverURL(ag.ID)
	staleKey := alertKey{ag.ID, store.AlertStale, ""}
	staleAlert, wasStale := open[staleKey]
	if agentStatus(ag, now, a.cfg.StaleAfter) == "stale" {
		if !wasStale {
			staleAlert = store.Alert{AgentID: ag.ID, Kind: store.AlertStale, RaisedAt: now}
			if err := a.store.RaiseAlert(ctx, &staleAlert); err != nil {
				return nil, err
			}
		}
		if staleAlert.NotifiedAt == nil {
			out = append(out, outgoing{msg: a.staleMessage(ag, server), alerts: []store.Alert{staleAlert}})
		}
	} else if wasStale {
		if err := a.store.CloseAlert(ctx, &staleAlert); err != nil {
			return nil, err
		}
		if staleAlert.NotifiedAt != nil {
			out = append(out, outgoing{msg: &notify.Message{
				Event:   notify.EventRecovered,
				Title:   notify.Clean(ag.Hostname) + " is reporting again",
				Text:    "Last report " + formatDate(ag.LastReportAt) + ".",
				URL:     server,
				Details: map[string]any{"server": serverDetails(ag)},
			}})
		}
	}

	findings, err := a.store.Findings(ctx, ag.ID)
	if err != nil {
		return nil, err
	}
	current := map[string][]store.Finding{}
	for _, f := range findings {
		if isEmergency(&f, settings) {
			current[f.Vulnerability] = append(current[f.Vulnerability], f)
		}
	}
	var fresh, reminders []store.Alert
	for _, al := range mine(store.AlertEmergency) {
		if _, still := current[al.Vulnerability]; !still {
			if err := a.store.CloseAlert(ctx, &al); err != nil {
				return nil, err
			}
			continue
		}
		switch {
		case al.NotifiedAt == nil:
			fresh = append(fresh, al)
		case now.Sub(*al.NotifiedAt) >= time.Duration(settings.ReminderDays)*24*time.Hour:
			reminders = append(reminders, al)
		}
	}
	for vuln := range current {
		if _, known := open[alertKey{ag.ID, store.AlertEmergency, vuln}]; known {
			continue
		}
		al := store.Alert{AgentID: ag.ID, Kind: store.AlertEmergency, Vulnerability: vuln, RaisedAt: now}
		if err := a.store.RaiseAlert(ctx, &al); err != nil {
			return nil, err
		}
		fresh = append(fresh, al)
	}
	if len(fresh) == 0 && len(reminders) == 0 {
		return out, nil
	}

	names, err := a.imageNames(ctx, ag.ID)
	if err != nil {
		return nil, err
	}
	if len(fresh) > 0 {
		slices.SortFunc(fresh, func(x, y store.Alert) int { return strings.Compare(x.Vulnerability, y.Vulnerability) })
		m := emergencyMessage(ag, fresh, current, names, server)
		m.Event = notify.EventEmergency
		m.Title = fmt.Sprintf("Emergency on %s: %s to fix now", notify.Clean(ag.Hostname), plural(len(fresh), "vulnerability", "vulnerabilities"))
		out = append(out, outgoing{msg: m, alerts: fresh})
	}
	if len(reminders) > 0 {
		m := emergencyMessage(ag, reminders, current, names, server)
		m.Event = notify.EventReminder
		m.Title = fmt.Sprintf("Still open on %s: %s", notify.Clean(ag.Hostname), plural(len(reminders), "emergency", "emergencies"))
		out = append(out, outgoing{msg: m, alerts: reminders})
	}
	return out, nil
}

func (a *alerter) staleMessage(ag *store.Agent, server string) *notify.Message {
	since := "No report since " + formatDate(ag.LastReportAt)
	if ag.LastReportAt == nil {
		since = "No report since it was enrolled on " + formatDate(ag.EnrolledAt)
	}
	return &notify.Message{
		Event: notify.EventStale,
		Title: notify.Clean(ag.Hostname) + " has stopped reporting",
		Text: since + " (stale after " + a.cfg.StaleAfter.String() + "). The server may be down, or its agent may have stopped. " +
			"Until it reports again, its vulnerabilities are unknown.",
		URL:     server,
		Details: map[string]any{"server": serverDetails(ag), "last_report_at": ag.LastReportAt},
	}
}

// vulnDetails is a finding as webhooks receive it.
type vulnDetails struct {
	ID             string   `json:"id"`
	Package        string   `json:"package"`
	Version        string   `json:"version"`
	Where          string   `json:"where"`
	Severity       string   `json:"severity"`
	CVSS           float64  `json:"cvss"`
	KnownExploited bool     `json:"known_exploited"`
	FixedIn        []string `json:"fixed_in"`
	URL            string   `json:"url,omitempty"`
}

func emergencyMessage(ag *store.Agent, alerts []store.Alert, current map[string][]store.Finding, names imageLabels, server string) *notify.Message {
	var lines []string
	var details []vulnDetails
	for _, al := range alerts {
		for _, f := range current[al.Vulnerability] {
			where := names.where(f.Target)
			lines = append(lines, findingLine(&f, where))
			details = append(details, vulnDetails{
				ID: f.Vulnerability, Package: f.Package, Version: f.Version, Where: where, Severity: f.Severity,
				CVSS: f.CVSS, KnownExploited: f.KnownExploited, FixedIn: f.FixVersions, URL: f.URL,
			})
		}
	}
	return &notify.Message{
		Text:    strings.Join(lines, "\n"),
		URL:     server,
		Details: map[string]any{"server": serverDetails(ag), "vulnerabilities": details},
	}
}

// findingLine describes a finding on one line of plain text.
func findingLine(f *store.Finding, where string) string {
	var why []string
	if f.KnownExploited {
		why = append(why, "known exploited")
	}
	why = append(why, f.Severity)
	if f.CVSS > 0 {
		why = append(why, fmt.Sprintf("CVSS %.1f", f.CVSS))
	}
	return notify.Clean(fmt.Sprintf("%s in %s %s (%s): %s, fixed in %s",
		f.Vulnerability, f.Package, f.Version, where, strings.Join(why, ", "), strings.Join(f.FixVersions, ", ")))
}

func serverDetails(ag *store.Agent) map[string]string {
	return map[string]string{"id": ag.ID, "hostname": ag.Hostname}
}

func (a *alerter) serverURL(agentID string) string {
	if a.cfg.PublicURL == "" {
		return ""
	}
	return strings.TrimSuffix(a.cfg.PublicURL, "/") + "/servers/" + agentID
}

// imageLabels name an agent's images as its containers refer to them.
type imageLabels map[string]string

func (n imageLabels) where(target string) string {
	if target == vulns.TargetHost {
		return "host"
	}
	if name := n[target]; name != "" {
		return "image " + name
	}
	return "image " + shortImageID(target)
}

func (a *alerter) imageNames(ctx context.Context, agentID string) (imageLabels, error) {
	rep, err := a.store.Report(ctx, agentID)
	if errors.Is(err, store.ErrNotFound) {
		return imageLabels{}, nil
	}
	if err != nil {
		return nil, err
	}
	var body report.Report
	if err := json.Unmarshal(rep.Body, &body); err != nil {
		return nil, err
	}
	return imageNamesOf(&body), nil
}

func imageNamesOf(body *report.Report) imageLabels {
	names := imageLabels{}
	if body.Docker != nil {
		for _, c := range body.Docker.Containers {
			if names[c.ImageID] == "" {
				names[c.ImageID] = c.Image
			}
		}
	}
	return names
}
