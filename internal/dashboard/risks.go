package dashboard

import (
	"errors"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/theo-mazars/best-before/internal/dashboard/store"
)

const (
	// How long a risk is accepted unless said otherwise (plan 7), and at
	// most, so that every acceptance is looked at again.
	riskLifetime    = 90 * 24 * time.Hour
	maxRiskLifetime = 366 * 24 * time.Hour
	maxReasonLength = 1000
	dateLayout      = "2006-01-02"
)

// riskTarget finds a vulnerability in the server's latest findings, or
// answers 404.
func (w *web) riskTarget(rw http.ResponseWriter, r *http.Request, target, vuln string) (*store.Agent, bool) {
	a, err := w.store.AgentByID(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeError(rw, http.StatusNotFound, "", "No such server.")
		return nil, false
	}
	if err != nil {
		w.apiFail(rw, r, err)
		return nil, false
	}
	findings, err := w.store.Findings(r.Context(), a.ID)
	if err != nil {
		w.apiFail(rw, r, err)
		return nil, false
	}
	for _, f := range findings {
		if f.Target == target && f.Vulnerability == vuln {
			return a, true
		}
	}
	writeError(rw, http.StatusNotFound, "", "This vulnerability is not in the server's latest report.")
	return nil, false
}

// acceptRisk accepts a vulnerability on a server's host or image, with a
// reason, until the start of the day chosen (UTC). Accepting again replaces
// the reason and the date.
func (w *web) acceptRisk(rw http.ResponseWriter, r *http.Request, u *store.User) {
	var in struct{ Target, Vulnerability, Reason, Expires string }
	if !readJSON(rw, r, &in) {
		return
	}
	a, ok := w.riskTarget(rw, r, in.Target, in.Vulnerability)
	if !ok {
		return
	}
	reason := strings.TrimSpace(strings.ReplaceAll(in.Reason, "\r\n", "\n"))
	if reason == "" || utf8.RuneCountInString(reason) > maxReasonLength ||
		strings.ContainsFunc(reason, func(r rune) bool { return r < ' ' && r != '\n' && r != '\t' }) {
		writeError(rw, http.StatusBadRequest, "reason", "Say why the risk is acceptable, in up to 1000 characters.")
		return
	}
	now := w.now()
	expires, err := time.ParseInLocation(dateLayout, in.Expires, time.UTC)
	if err != nil || !expires.After(now) || expires.After(now.Add(maxRiskLifetime)) {
		writeError(rw, http.StatusBadRequest, "expires", "Choose an expiry date from tomorrow to a year from now.")
		return
	}
	if err := w.store.AcceptRisk(r.Context(), a.ID, in.Target, in.Vulnerability, reason, u.ID, now, expires); err != nil {
		w.apiFail(rw, r, err)
		return
	}
	w.log.Info("risk accepted", "server", a.Hostname, "target", in.Target, "vulnerability", in.Vulnerability,
		"expires", expires, "by", u.Email)
	w.alerts.poke() // its emergency closes
	rw.WriteHeader(http.StatusNoContent)
}

// withdrawRisk ends an acceptance at once: the vulnerability counts again,
// and is sent as an emergency if it is one.
func (w *web) withdrawRisk(rw http.ResponseWriter, r *http.Request, u *store.User) {
	var in struct{ Target, Vulnerability string }
	if !readJSON(rw, r, &in) {
		return
	}
	id := r.PathValue("id")
	if err := w.store.WithdrawRisk(r.Context(), id, in.Target, in.Vulnerability); err != nil && !errors.Is(err, store.ErrNotFound) {
		w.apiFail(rw, r, err)
		return
	}
	w.log.Info("accepted risk withdrawn", "server", id, "target", in.Target, "vulnerability", in.Vulnerability, "by", u.Email)
	w.alerts.poke()
	rw.WriteHeader(http.StatusNoContent)
}
