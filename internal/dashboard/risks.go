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

// riskForm is the page accepting one vulnerability on a server's host or
// image.
type riskForm struct {
	User          *store.User
	Agent         *store.Agent
	Target        string
	Vulnerability string
	Where         string
	Findings      []store.Finding
	// Risk is the current acceptance, running or expired, if any.
	Risk     *store.AcceptedRisk
	Reason   string
	Expires  string // a date, as the form shows it
	Min, Max string
	Error    string
}

// loadRisk finds what the form is about: a vulnerability in the server's
// latest findings. It renders the error page itself when there is none.
func (w *web) loadRisk(rw http.ResponseWriter, r *http.Request, u *store.User, target, vuln string) (*riskForm, bool) {
	a, err := w.store.AgentByID(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		w.render(rw, http.StatusNotFound, "error", map[string]any{"User": u, "Message": "No such server."})
		return nil, false
	}
	if err != nil {
		w.fail(rw, r, err)
		return nil, false
	}
	findings, err := w.store.Findings(r.Context(), a.ID)
	if err != nil {
		w.fail(rw, r, err)
		return nil, false
	}
	f := &riskForm{User: u, Agent: a, Target: target, Vulnerability: vuln}
	for _, fd := range findings {
		if fd.Target == target && fd.Vulnerability == vuln {
			f.Findings = append(f.Findings, fd)
		}
	}
	if len(f.Findings) == 0 {
		w.render(rw, http.StatusNotFound, "error", map[string]any{"User": u, "Message": "This vulnerability is not in the server's latest report."})
		return nil, false
	}
	names, err := w.alerts.imageNames(r.Context(), a.ID)
	if err != nil {
		w.fail(rw, r, err)
		return nil, false
	}
	f.Where = names.where(target)
	rs, err := loadRisks(r.Context(), w.store, a.ID)
	if err != nil {
		w.fail(rw, r, err)
		return nil, false
	}
	if risk, ok := rs.of(&f.Findings[0]); ok {
		f.Risk = &risk
	}
	now := w.now()
	f.Min = now.AddDate(0, 0, 1).UTC().Format(dateLayout)
	f.Max = now.Add(maxRiskLifetime).UTC().Format(dateLayout)
	return f, true
}

func (w *web) riskPage(rw http.ResponseWriter, r *http.Request, u *store.User) {
	q := r.URL.Query()
	f, ok := w.loadRisk(rw, r, u, q.Get("target"), q.Get("vulnerability"))
	if !ok {
		return
	}
	f.Expires = w.now().Add(riskLifetime).UTC().Format(dateLayout)
	if f.Risk != nil && f.Risk.Active(w.now()) {
		f.Reason = f.Risk.Reason
		f.Expires = f.Risk.ExpiresAt.Format(dateLayout)
	}
	w.render(rw, http.StatusOK, "risk", f)
}

// acceptRisk accepts a vulnerability on a server's host or image, with a
// reason, until the start of the day chosen (UTC).
func (w *web) acceptRisk(rw http.ResponseWriter, r *http.Request, u *store.User) {
	r.Body = http.MaxBytesReader(rw, r.Body, maxFormBytes)
	f, ok := w.loadRisk(rw, r, u, r.PostFormValue("target"), r.PostFormValue("vulnerability"))
	if !ok {
		return
	}
	f.Reason = strings.TrimSpace(strings.ReplaceAll(r.PostFormValue("reason"), "\r\n", "\n"))
	f.Expires = r.PostFormValue("expires")
	refuse := func(msg string) {
		f.Error = msg
		w.render(rw, http.StatusBadRequest, "risk", f)
	}
	if f.Reason == "" || utf8.RuneCountInString(f.Reason) > maxReasonLength ||
		strings.ContainsFunc(f.Reason, func(r rune) bool { return r < ' ' && r != '\n' && r != '\t' }) {
		refuse("Say why the risk is acceptable, in up to 1000 characters.")
		return
	}
	now := w.now()
	expires, err := time.ParseInLocation(dateLayout, f.Expires, time.UTC)
	if err != nil || !expires.After(now) || expires.After(now.Add(maxRiskLifetime)) {
		refuse("Choose an expiry date from tomorrow to a year from now.")
		return
	}
	if err := w.store.AcceptRisk(r.Context(), f.Agent.ID, f.Target, f.Vulnerability, f.Reason, u.ID, now, expires); err != nil {
		w.fail(rw, r, err)
		return
	}
	w.log.Info("risk accepted", "server", f.Agent.Hostname, "target", f.Target, "vulnerability", f.Vulnerability,
		"expires", expires, "by", u.Email)
	w.alerts.poke() // its emergency closes
	http.Redirect(rw, r, "/servers/"+f.Agent.ID, http.StatusSeeOther)
}

// withdrawRisk ends an acceptance at once: the vulnerability counts again,
// and is sent as an emergency if it is one.
func (w *web) withdrawRisk(rw http.ResponseWriter, r *http.Request, u *store.User) {
	r.Body = http.MaxBytesReader(rw, r.Body, maxFormBytes)
	id, target, vuln := r.PathValue("id"), r.PostFormValue("target"), r.PostFormValue("vulnerability")
	if err := w.store.WithdrawRisk(r.Context(), id, target, vuln); err != nil && !errors.Is(err, store.ErrNotFound) {
		w.fail(rw, r, err)
		return
	}
	w.log.Info("accepted risk withdrawn", "server", id, "target", target, "vulnerability", vuln, "by", u.Email)
	w.alerts.poke()
	http.Redirect(rw, r, "/servers/"+id, http.StatusSeeOther)
}
