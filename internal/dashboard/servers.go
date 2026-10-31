package dashboard

import (
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/theo-mazars/best-before/internal/dashboard/store"
	"github.com/theo-mazars/best-before/internal/dashboard/vulns"
	"github.com/theo-mazars/best-before/internal/report"
)

// serverSummary is one server on the overview. Counts only include
// fixable findings: the others are silent.
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

func (s *serverSummary) count(findings []store.Finding) {
	for _, f := range findings {
		if !f.Fixable() {
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
		s, _, _, _, err := w.summary(r, &a, now)
		if err != nil {
			w.fail(rw, r, err)
			return
		}
		servers = append(servers, *s)
	}
	sort.SliceStable(servers, func(i, j int) bool { return statusOrder[servers[i].Status] < statusOrder[servers[j].Status] })
	w.render(rw, http.StatusOK, "overview", map[string]any{"User": u, "Servers": servers, "DB": w.db.Status()})
}

// summary loads what is known about one server. The report is nil before
// the first one arrives.
func (w *web) summary(r *http.Request, a *store.Agent, now time.Time) (*serverSummary, *store.Report, *report.Report, []store.Finding, error) {
	s := &serverSummary{ID: a.ID, Hostname: a.Hostname, LastReportAt: a.LastReportAt}
	rep, err := w.store.Report(r.Context(), a.ID)
	if errors.Is(err, store.ErrNotFound) {
		s.Status = s.status(agentStatus(a, now, w.cfg.StaleAfter), nil)
		return s, nil, nil, nil, nil
	}
	if err != nil {
		return nil, nil, nil, nil, err
	}
	var body report.Report
	if err := json.Unmarshal(rep.Body, &body); err != nil {
		return nil, nil, nil, nil, err
	}
	findings, err := w.store.Findings(r.Context(), a.ID)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	s.read(&body)
	s.notChecked(rep, &body)
	s.count(findings)
	s.Status = s.status(agentStatus(a, now, w.cfg.StaleAfter), rep)
	return s, rep, &body, findings, nil
}

type imageView struct {
	ID         string
	References []string // as written by the containers using it
	Containers []string
	OS         string
	NotChecked string
	Software   []string // e.g. "node 22.11.0"
	Findings   []store.Finding
	NoFixYet   int
}

type unfixedView struct {
	Where string
	store.Finding
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
	s, rep, body, findings, err := w.summary(r, a, w.now())
	if err != nil {
		w.fail(rw, r, err)
		return
	}
	data := map[string]any{"User": u, "Server": s, "Agent": a, "Report": rep, "DB": w.db.Status()}
	if body == nil {
		w.render(rw, http.StatusOK, "server", data)
		return
	}

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
			} else if v.NotChecked == "" {
				v.NotChecked = "not read"
			}
			for _, vv := range img.Versions {
				if sw, ok := vulns.SoftwareName(vv.Name); ok {
					v.Software = append(v.Software, sw+" "+vv.Value)
				}
			}
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

	var hostFindings []store.Finding
	var unfixed []unfixedView
	for _, f := range findings {
		where := "host"
		if v := images[f.Target]; v != nil && len(v.References) > 0 {
			where = v.References[0]
		} else if f.Target != vulns.TargetHost {
			where = shortImageID(f.Target)
		}
		switch {
		case !f.Fixable():
			unfixed = append(unfixed, unfixedView{Where: where, Finding: f})
			if v := images[f.Target]; v != nil {
				v.NoFixYet++
			}
		case f.Target == vulns.TargetHost:
			hostFindings = append(hostFindings, f)
		case images[f.Target] != nil:
			images[f.Target].Findings = append(images[f.Target].Findings, f)
		}
	}
	// Images with the most urgent findings first.
	sort.SliceStable(order, func(i, j int) bool { return worst(order[i].Findings) < worst(order[j].Findings) })

	data["Body"] = body
	data["Upgradable"] = upgradable
	data["HostFindings"] = hostFindings
	data["Images"] = order
	data["Unfixed"] = unfixed
	w.render(rw, http.StatusOK, "server", data)
}

// worst ranks a list of findings, already sorted most urgent first.
func worst(fs []store.Finding) int {
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
