package dashboard

import (
	"encoding/json"
	"errors"
	"net/http"
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
	ID              string     `json:"id"`
	Hostname        string     `json:"hostname"`
	Status          string     `json:"status"`
	LastReportAt    *time.Time `json:"lastReportAt"`
	Critical        int        `json:"critical"`
	High            int        `json:"high"`
	Medium          int        `json:"medium"`
	KnownExploited  int        `json:"knownExploited"`
	NoFixYet        int        `json:"noFixYet"`
	Accepted        int        `json:"accepted"`
	SecurityUpdates int        `json:"securityUpdates"`
	Updates         int        `json:"updates"`
	RebootRequired  bool       `json:"rebootRequired"`
	Images          int        `json:"images"`
	NotChecked      int        `json:"notChecked"`
	// Severities counts every finding by severity: open ones count towards
	// the status, muted ones have no fix, are accepted or are below the
	// user's threshold.
	Severities map[string]*severityCount `json:"severities"`
	// Problems are gaps in the report, which are never mistaken for a
	// clean server.
	Problems []string `json:"problems"`
}

type severityCount struct {
	Open  int `json:"open"`
	Muted int `json:"muted"`
}

// stripSeverity is the strip box a severity goes in.
func stripSeverity(s string) string {
	switch s {
	case "critical", "high", "medium", "low":
		return s
	}
	return "unknown"
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
		p := place(&f, rs, min, now)
		c := s.Severities[stripSeverity(f.Severity)]
		if p == placeOpen {
			c.Open++
		} else {
			c.Muted++
		}
		switch p {
		case placeAccepted:
			s.Accepted++
			continue
		case placeBelow, placeOldKernel:
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

type dbView struct {
	Ready     bool       `json:"ready"`
	Built     *time.Time `json:"built,omitempty"`
	LastError string     `json:"lastError,omitempty"`
}

type overviewView struct {
	DB      dbView          `json:"db"`
	Servers []serverSummary `json:"servers"`
}

func (w *web) overview(rw http.ResponseWriter, r *http.Request, u *store.User) {
	agents, err := w.store.Agents(r.Context())
	if err != nil {
		w.apiFail(rw, r, err)
		return
	}
	now := w.now()
	servers := []serverSummary{}
	for _, a := range agents {
		if a.Revoked() {
			continue
		}
		s, _, err := w.summary(r, &a, u, now)
		if err != nil {
			w.apiFail(rw, r, err)
			return
		}
		servers = append(servers, *s)
	}
	sort.SliceStable(servers, func(i, j int) bool { return statusOrder[servers[i].Status] < statusOrder[servers[j].Status] })
	db := w.db.Status()
	v := overviewView{DB: dbView{Ready: db.Ready, LastError: db.LastError}, Servers: servers}
	if db.Ready {
		v.DB.Built = &db.Built
	}
	writeJSON(rw, http.StatusOK, v)
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
	s := &serverSummary{ID: a.ID, Hostname: a.Hostname, LastReportAt: a.LastReportAt, Problems: []string{}, Severities: newSeverities()}
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

func shortImageID(id string) string {
	id = strings.TrimPrefix(id, "sha256:")
	if len(id) > 12 {
		id = id[:12]
	}
	return id
}
