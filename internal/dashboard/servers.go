package dashboard

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/theo-mazars/best-before/internal/dashboard/store"
	"github.com/theo-mazars/best-before/internal/dashboard/vulns"
	"github.com/theo-mazars/best-before/internal/report"
)

// serverSummary is one server on the overview. Counts only include
// fixable findings the user sees and has not accepted: the others are
// silent.
type serverSummary struct {
	ID              string
	Hostname        string
	Status          string
	LastReportAt    *time.Time
	Critical        int
	High            int
	Medium          int
	KnownExploited  int
	NoFixYet        int
	Accepted        int
	SecurityUpdates int
	Updates         int
	RebootRequired  bool
	Images          int
	NotChecked      int
	// Problems are gaps in the report, which are never mistaken for a
	// clean server.
	Problems []string
}

// Server statuses, worst first.
const (
	statusCritical  = "critical"
	statusStale     = "stale"
	statusUnchecked = "not checked yet"
	statusWaiting   = "waiting for first report"
	statusAttention = "attention"
	statusOK        = "OK"
)

func (s *serverSummary) count(findings []store.Finding, rs risks, min string, now time.Time) {
	for _, f := range findings {
		switch place(&f, rs, min, now) {
		case placeAccepted:
			s.Accepted++
			continue
		case placeBelow:
			continue
		case placeNoFix:
			s.NoFixYet++
			continue
		}
		if f.KnownExploited {
			s.KnownExploited++
		}
		switch f.Severity {
		case "critical":
			s.Critical++
		case "high":
			s.High++
		case "medium":
			s.Medium++
		}
	}
}

func (s *serverSummary) read(r *report.Report) {
	for _, u := range r.Host.APT.Upgradable {
		s.Updates++
		if u.Security {
			s.SecurityUpdates++
		}
	}
	s.RebootRequired = r.Host.RebootRequired
	for _, e := range r.Host.Errors {
		s.Problems = append(s.Problems, "Host: "+e)
	}
	if d := r.Docker; d != nil {
		if !d.Available {
			s.Problems = append(s.Problems, "Docker: "+d.Error)
		}
		s.Images = len(d.Images)
		for _, img := range d.Images {
			if img.System == nil {
				s.NotChecked++
			}
		}
	}
}

// notChecked counts what matching could not check, e.g. a distribution the
// vulnerability database has no data for.
func (s *serverSummary) notChecked(rep *store.Report, r *report.Report) {
	if !rep.Matched {
		return
	}
	if why := rep.Unchecked[vulns.TargetHost]; why != "" {
		s.Problems = append(s.Problems, "Host packages not checked: "+why)
	}
	if r.Docker == nil {
		return
	}
	for _, img := range r.Docker.Images {
		if img.System != nil && rep.Unchecked[img.ID] != "" {
			s.NotChecked++
		}
	}
}

// status decides how a server is shown. Silence, an unchecked report or a
// gap is never shown as OK.
func (s *serverSummary) status(agent string, rep *store.Report) string {
	switch {
	case agent == "stale":
		return statusStale
	case rep == nil:
		return statusWaiting
	case s.Critical > 0 || s.KnownExploited > 0:
		return statusCritical
	case !rep.Matched:
		return statusUnchecked
	case s.High > 0 || s.Medium > 0 || s.SecurityUpdates > 0 || s.RebootRequired || s.NotChecked > 0 || len(s.Problems) > 0:
		return statusAttention
	}
	return statusOK
}

var statusOrder = map[string]int{statusCritical: 0, statusStale: 1, statusUnchecked: 2, statusWaiting: 3, statusAttention: 4, statusOK: 5}

func (w *web) overview(rw http.ResponseWriter, r *http.Request, u *store.User) {
	agents, err := w.store.Agents(r.Context())
	if err != nil {
		w.fail(rw, r, err)
		return
	}
	now := w.now()
	var servers []serverSummary
	for _, a := range agents {
		if a.Revoked() {
			continue
		}
		s, _, err := w.summary(r, &a, u, now)
		if err != nil {
			w.fail(rw, r, err)
			return
		}
		servers = append(servers, *s)
	}
	sort.SliceStable(servers, func(i, j int) bool { return statusOrder[servers[i].Status] < statusOrder[servers[j].Status] })
	w.render(rw, http.StatusOK, "overview", map[string]any{"User": u, "Servers": servers, "DB": w.db.Status()})
}

// serverState is what is known about one server.
type serverState struct {
	rep      *store.Report
	body     *report.Report
	findings []store.Finding
	risks    risks
}

// summary loads what is known about one server, as user u sees it. The
// state is nil before the first report arrives.
func (w *web) summary(r *http.Request, a *store.Agent, u *store.User, now time.Time) (*serverSummary, *serverState, error) {
	s := &serverSummary{ID: a.ID, Hostname: a.Hostname, LastReportAt: a.LastReportAt}
	rep, err := w.store.Report(r.Context(), a.ID)
	if errors.Is(err, store.ErrNotFound) {
		s.Status = s.status(agentStatus(a, now, w.cfg.StaleAfter), nil)
		return s, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	st := &serverState{rep: rep, body: &report.Report{}}
	if err := json.Unmarshal(rep.Body, st.body); err != nil {
		return nil, nil, err
	}
	if st.findings, err = w.store.Findings(r.Context(), a.ID); err != nil {
		return nil, nil, err
	}
	if st.risks, err = loadRisks(r.Context(), w.store, a.ID); err != nil {
		return nil, nil, err
	}
	s.read(st.body)
	s.notChecked(rep, st.body)
	s.count(st.findings, st.risks, u.MinSeverity, now)
	s.Status = s.status(agentStatus(a, now, w.cfg.StaleAfter), rep)
	return s, st, nil
}

type imageView struct {
	ID         string
	References []string // as written by the containers using it
	Containers []string
	OS         string
	NotChecked string
	// Checked says what matching covers, e.g. "142 Debian GNU/Linux 12
	// (bookworm) packages (dpkg)" or "node 22.11.0 (by version)". Empty when
	// the image has nothing Best Before can check, which must not pass for
	// clean.
	Checked []string
	// Imprecise are known runtimes whose version is too vague to match,
	// e.g. "redis 7".
	Imprecise []string
	Findings  []findingView
	NoFixYet  int
}

// NothingChecked is true for an image that was read, but holds no package
// records and no known runtime, e.g. a static binary FROM scratch. What
// such an image contains is its developers' responsibility, so it is shown,
// but does not change the server's status.
func (v *imageView) NothingChecked() bool { return v.NotChecked == "" && len(v.Checked) == 0 }

// findingView is a finding on a server's page.
type findingView struct {
	Where     string
	AcceptURL string
	// Risk is the finding's acceptance, if running.
	Risk *store.AcceptedRisk
	store.Finding
}

func riskURL(agentID string, f *store.Finding) string {
	return "/servers/" + agentID + "/risks/new?" + url.Values{"target": {f.Target}, "vulnerability": {f.Vulnerability}}.Encode()
}

func (w *web) serverPage(rw http.ResponseWriter, r *http.Request, u *store.User) {
	a, err := w.store.AgentByID(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		w.render(rw, http.StatusNotFound, "error", map[string]any{"User": u, "Message": "No such server."})
		return
	}
	if err != nil {
		w.fail(rw, r, err)
		return
	}
	now := w.now()
	s, st, err := w.summary(r, a, u, now)
	if err != nil {
		w.fail(rw, r, err)
		return
	}
	data := map[string]any{"User": u, "Server": s, "Agent": a, "DB": w.db.Status()}
	if st == nil {
		w.render(rw, http.StatusOK, "server", data)
		return
	}
	rep, body := st.rep, st.body
	data["Report"] = rep

	upgradable := slices.Clone(body.Host.APT.Upgradable)
	sort.SliceStable(upgradable, func(i, j int) bool { return upgradable[i].Security && !upgradable[j].Security })

	images := map[string]*imageView{}
	var order []*imageView
	if body.Docker != nil {
		for _, img := range body.Docker.Images {
			v := &imageView{ID: img.ID, NotChecked: img.SystemError}
			if why := rep.Unchecked[img.ID]; why != "" && rep.Matched {
				v.NotChecked = why
			}
			if img.System != nil {
				v.OS = img.System.OS.Name
				if v.OS == "" {
					v.OS = strings.TrimSpace(img.System.OS.ID + " " + img.System.OS.VersionID)
				}
				// Any reason not to check concerns the packages.
				if m := img.System.PackageManager; m != "" && v.NotChecked == "" {
					v.Checked = append(v.Checked, strings.Join(strings.Fields(fmt.Sprintf("%d %s packages (%s)", len(img.System.Packages), v.OS, m)), " "))
				}
			} else if v.NotChecked == "" {
				v.NotChecked = "not read"
			}
			software, imprecise := vulns.Software(img.Versions)
			for _, sw := range software {
				v.Checked = append(v.Checked, sw+" (by version)")
			}
			v.Imprecise = imprecise
			images[img.ID] = v
			order = append(order, v)
		}
		for _, c := range body.Docker.Containers {
			if v := images[c.ImageID]; v != nil {
				v.Containers = append(v.Containers, c.Name)
				if !slices.Contains(v.References, c.Image) {
					v.References = append(v.References, c.Image)
				}
			}
		}
	}

	var hostFindings, unfixed, below, accepted []findingView
	for _, f := range st.findings {
		where := "host"
		if v := images[f.Target]; v != nil && len(v.References) > 0 {
			where = v.References[0]
		} else if f.Target != vulns.TargetHost {
			where = shortImageID(f.Target)
		}
		fv := findingView{Where: where, AcceptURL: riskURL(a.ID, &f), Risk: st.risks.active(&f, now), Finding: f}
		switch place(&f, st.risks, u.MinSeverity, now) {
		case placeAccepted:
			accepted = append(accepted, fv)
		case placeBelow:
			below = append(below, fv)
		case placeNoFix:
			unfixed = append(unfixed, fv)
			if v := images[f.Target]; v != nil {
				v.NoFixYet++
			}
		default:
			switch {
			case f.Target == vulns.TargetHost:
				hostFindings = append(hostFindings, fv)
			case images[f.Target] != nil:
				images[f.Target].Findings = append(images[f.Target].Findings, fv)
			}
		}
	}
	// Images with the most urgent findings first.
	sort.SliceStable(order, func(i, j int) bool { return worst(order[i].Findings) < worst(order[j].Findings) })

	data["Body"] = body
	data["Upgradable"] = upgradable
	data["HostFindings"] = hostFindings
	data["Images"] = order
	data["Unfixed"] = unfixed
	data["Below"] = below
	data["Accepted"] = accepted
	w.render(rw, http.StatusOK, "server", data)
}

// worst ranks a list of findings, already sorted most urgent first.
func worst(fs []findingView) int {
	switch {
	case len(fs) == 0:
		return 99
	case fs[0].KnownExploited:
		return 0
	}
	if rank, ok := map[string]int{"critical": 1, "high": 2, "medium": 3, "low": 4, "negligible": 5}[fs[0].Severity]; ok {
		return rank
	}
	return 6
}

func shortImageID(id string) string {
	id = strings.TrimPrefix(id, "sha256:")
	if len(id) > 12 {
		id = id[:12]
	}
	return id
}
