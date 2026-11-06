package dashboard

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	htmltemplate "html/template"
	"strings"
	"text/template"
	"time"
	_ "time/tzdata" // digest time zones, even without tzdata on the system

	"github.com/theo-mazars/best-before/internal/dashboard/notify"
	"github.com/theo-mazars/best-before/internal/dashboard/store"
	"github.com/theo-mazars/best-before/internal/report"
)

var (
	digestText = template.Must(template.New("digest.txt").Funcs(template.FuncMap{"date": formatDate}).
			ParseFS(webFiles, "web/mail/digest.txt"))
	digestHTML = htmltemplate.Must(htmltemplate.New("digest.html").Funcs(htmltemplate.FuncMap{"date": formatDate}).
			ParseFS(webFiles, "web/mail/digest.html"))
)

// digest is what the weekly digest says, in the order of plan 6.2. Every
// value from agents is cleaned for plain text; the HTML version escapes it
// as well.
type digest struct {
	Since, Until time.Time
	DashboardURL string
	// EmergencyRule and MinSeverity say what the settings let through.
	EmergencyRule string
	MinSeverity   string
	Emergencies   []digestServer
	Stale         []staleServer
	Updates       []updatesServer
	New           []digestServer
	Accepted      []digestServer
}

type digestServer struct {
	Hostname string
	URL      string
	Findings []digestFinding
}

type digestFinding struct {
	Line string // the finding on one line of text
	Note string // more about it, e.g. why it was accepted
	URL  string // its advisory
}

type staleServer struct {
	Hostname     string
	URL          string
	LastReportAt *time.Time
}

type updatesServer struct {
	Hostname       string
	URL            string
	Packages       []string // "openssl 3.0.13-0ubuntu3.5 → 3.0.13-0ubuntu3.6"
	RebootRequired bool
}

func (d *digest) AllClear() bool {
	return len(d.Emergencies)+len(d.Stale)+len(d.Updates)+len(d.New)+len(d.Accepted) == 0
}

func (d *digest) title() string {
	if d.AllClear() {
		return "Best Before weekly digest: all clear"
	}
	var parts []string
	count := func(servers []digestServer) (n int) {
		for _, s := range servers {
			n += len(s.Findings)
		}
		return n
	}
	if n := count(d.Emergencies); n > 0 {
		parts = append(parts, plural(n, "emergency", "emergencies"))
	}
	if n := len(d.Stale); n > 0 {
		parts = append(parts, plural(n, "stale server", "stale servers"))
	}
	if n := len(d.Updates); n > 0 {
		parts = append(parts, plural(n, "server", "servers")+" with security updates")
	}
	if n := count(d.New); n > 0 {
		parts = append(parts, plural(n, "new vulnerability", "new vulnerabilities"))
	}
	if n := count(d.Accepted); n > 0 {
		parts = append(parts, plural(n, "accepted risk", "accepted risks")+" expiring")
	}
	return "Best Before weekly digest: " + strings.Join(parts, ", ")
}

// buildDigest gathers what has happened since the last digest, in the
// sections the settings ask for.
func (a *alerter) buildDigest(ctx context.Context, s *store.AlertSettings, since, now time.Time) (*digest, error) {
	d := &digest{Since: since, Until: now, DashboardURL: a.cfg.PublicURL, EmergencyRule: emergencyRule(s), MinSeverity: s.DigestNewMinSeverity}
	agents, err := a.store.Agents(ctx)
	if err != nil {
		return nil, err
	}
	for i := range agents {
		ag := &agents[i]
		if ag.Revoked() {
			continue
		}
		host := notify.Clean(ag.Hostname)
		url := a.serverURL(ag.ID)
		if s.DigestStale && agentStatus(ag, now, a.cfg.StaleAfter) == "stale" {
			d.Stale = append(d.Stale, staleServer{Hostname: host, URL: url, LastReportAt: ag.LastReportAt})
		}

		names := imageLabels{}
		rep, err := a.store.Report(ctx, ag.ID)
		switch {
		case errors.Is(err, store.ErrNotFound):
		case err != nil:
			return nil, err
		default:
			var body report.Report
			if err := json.Unmarshal(rep.Body, &body); err != nil {
				return nil, err
			}
			names = imageNamesOf(&body)
			u := updatesServer{Hostname: host, URL: url, RebootRequired: body.Host.RebootRequired}
			for _, p := range body.Host.APT.Upgradable {
				if p.Security {
					u.Packages = append(u.Packages, notify.Clean(p.Name+" "+p.CurrentVersion+" → "+p.CandidateVersion))
				}
			}
			if s.DigestUpdates && len(u.Packages) > 0 {
				d.Updates = append(d.Updates, u)
			}
		}

		findings, err := loadFindings(ctx, a.store, ag.ID)
		if err != nil {
			return nil, err
		}
		rs, err := loadRisks(ctx, a.store, ag.ID)
		if err != nil {
			return nil, err
		}
		emergencies := digestServer{Hostname: host, URL: url}
		fresh := digestServer{Hostname: host, URL: url}
		expiring := digestServer{Hostname: host, URL: url}
		var current []store.Finding
		for _, f := range findings {
			if !f.OldKernel {
				current = append(current, f)
			}
		}
		// One line per vulnerability on a host or image, naming the packages
		// that make it worth a line.
		for _, group := range groupByCVE(current) {
			where := names.where(group[0].Target)
			pick := func(ok func(f *store.Finding) bool) []store.Finding {
				var out []store.Finding
				for _, f := range group {
					if ok(&f) {
						out = append(out, f)
					}
				}
				return out
			}
			first := &group[0]
			// An acceptance that ended since the last digest, or ends within
			// a week, is worth a look; one without a fix stays silent.
			if r, ok := rs.of(first); ok && s.DigestAccepted &&
				r.ExpiresAt.After(since) && !r.ExpiresAt.After(now.Add(7*24*time.Hour)) {
				if fixable := pick((*store.Finding).Fixable); len(fixable) > 0 {
					expiring.Findings = append(expiring.Findings,
						digestFinding{Line: findingLine(fixable, where), Note: acceptedNote(&r, now), URL: first.URL})
				}
			}
			if rs.active(first, now) != nil {
				continue // accepted: neither an emergency nor new until it expires
			}
			// Emergencies are sent when found; never repeated as new.
			if urgent := pick(func(f *store.Finding) bool { return isEmergency(f, s) }); len(urgent) > 0 {
				if s.DigestEmergencies {
					emergencies.Findings = append(emergencies.Findings, digestFinding{Line: findingLine(urgent, where), URL: first.URL})
				}
				continue
			}
			news := pick(func(f *store.Finding) bool {
				return s.DigestNewMinSeverity != "" && f.Fixable() && severityRank(f.Severity) >= severityRank(s.DigestNewMinSeverity) &&
					(!f.FirstSeenAt.Before(since) || !f.FixableSince.Before(since))
			})
			if len(news) > 0 {
				fresh.Findings = append(fresh.Findings, digestFinding{Line: findingLine(news, where), URL: first.URL})
			}
		}
		if len(emergencies.Findings) > 0 {
			d.Emergencies = append(d.Emergencies, emergencies)
		}
		if len(fresh.Findings) > 0 {
			d.New = append(d.New, fresh)
		}
		if len(expiring.Findings) > 0 {
			d.Accepted = append(d.Accepted, expiring)
		}
	}
	return d, nil
}

// acceptedNote says when an acceptance ends, who made it and why.
func acceptedNote(r *store.AcceptedRisk, now time.Time) string {
	when := "Expires " + formatDate(r.ExpiresAt)
	if !r.Active(now) {
		when = "Expired " + formatDate(r.ExpiresAt) + ", counts again"
	}
	by := ""
	if r.AcceptedBy != "" {
		by = " by " + r.AcceptedBy
	}
	return notify.Clean(fmt.Sprintf("%s. Accepted%s: %s", when, by, r.Reason))
}

// emergencyRule describes which vulnerabilities with a fix are emergencies,
// or is empty when none are.
func emergencyRule(s *store.AlertSettings) string {
	var rules []string
	if s.EmergencyKnownExploited {
		rules = append(rules, "known exploited")
	}
	if s.EmergencyMinCVSS != nil {
		rules = append(rules, fmt.Sprintf("CVSS %.1f or more", *s.EmergencyMinCVSS))
	}
	return strings.Join(rules, ", or ")
}

func (d *digest) message() (*notify.Message, error) {
	var text, html bytes.Buffer
	if err := digestText.Execute(&text, d); err != nil {
		return nil, err
	}
	if err := digestHTML.Execute(&html, d); err != nil {
		return nil, err
	}
	return &notify.Message{
		Event:   notify.EventDigest,
		Title:   d.title(),
		Text:    text.String(),
		HTML:    html.String(),
		URL:     d.DashboardURL,
		Details: d,
	}, nil
}

// lastDigestSlot is when the latest digest was due, if digests are on.
func lastDigestSlot(s *store.AlertSettings, now time.Time) (time.Time, bool) {
	if s.DigestWeekday == nil {
		return time.Time{}, false
	}
	loc, err := time.LoadLocation(s.DigestTimezone)
	if err != nil {
		loc = time.UTC
	}
	n := now.In(loc)
	back := (int(n.Weekday()) - int(*s.DigestWeekday) + 7) % 7
	slot := func(daysBack int) time.Time {
		return time.Date(n.Year(), n.Month(), n.Day()-daysBack, s.DigestMinute/60, s.DigestMinute%60, 0, 0, loc)
	}
	t := slot(back)
	if t.After(now) {
		t = slot(back + 7)
	}
	return t, true
}

// digest sends the weekly digest when it is due. The first time, it only
// notes the time, so that a new dashboard does not send one at once.
func (a *alerter) digest(ctx context.Context, chans []channel, s *store.AlertSettings, now time.Time) error {
	slot, on := lastDigestSlot(s, now)
	switch {
	case !on:
		return nil
	case s.DigestSentAt == nil:
		return a.store.SetDigestSent(ctx, now)
	case !s.DigestSentAt.Before(slot), now.Before(a.digestHeld):
		return nil
	}
	sent, tried, err := a.sendDigest(ctx, chans, s, *s.DigestSentAt, now, false)
	if err != nil {
		return err
	}
	if tried > 0 && sent == 0 {
		a.log.Error("no channel accepted the digest; trying again later", "retry_in", alertRetry)
		a.digestHeld = now.Add(alertRetry)
		return nil
	}
	return a.store.SetDigestSent(ctx, now)
}

// sendDigest sends a digest to the channels that take it. With nothing to
// say, it is only sent if the settings ask for "all clear", or if forced.
func (a *alerter) sendDigest(ctx context.Context, chans []channel, s *store.AlertSettings, since, now time.Time, force bool) (sent, tried int, err error) {
	d, err := a.buildDigest(ctx, s, since, now)
	if err != nil {
		return 0, 0, err
	}
	if d.AllClear() && !s.DigestAllClear && !force {
		return 0, 0, nil
	}
	m, err := d.message()
	if err != nil {
		return 0, 0, err
	}
	sent, tried = send(ctx, chans, func(c *channel) bool { return c.Digest }, m, a.log)
	return sent, tried, nil
}

// sendDigestNow sends a digest covering the time since the last one,
// without changing when the next is due.
func (a *alerter) sendDigestNow(ctx context.Context) (sent, tried int, err error) {
	s, err := a.store.AlertSettings(ctx)
	if err != nil {
		return 0, 0, err
	}
	now := a.now()
	since := now.AddDate(0, 0, -7)
	if s.DigestSentAt != nil {
		since = *s.DigestSentAt
	}
	chans, err := a.sealer.channels(ctx, a.store)
	if err != nil {
		return 0, 0, err
	}
	return a.sendDigest(ctx, chans, s, since, now, true)
}
