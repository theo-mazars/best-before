package dashboard

import (
	"bytes"
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/theo-mazars/best-before/internal/dashboard/store"
	"github.com/theo-mazars/best-before/internal/dashboard/vulns"
	"github.com/theo-mazars/best-before/internal/protocol"
)

//go:embed web
var webFiles embed.FS

const (
	// The strict __Host- cookie needs HTTPS; over plain HTTP behind a proxy,
	// browsers would refuse it and login would silently fail.
	sessionCookie      = "__Host-bestbefore_session"
	plainSessionCookie = "bestbefore_session"
	sessionLifetime    = 12 * time.Hour
	sessionIdle        = time.Hour
	codeLifetime       = time.Hour
	maxFormBytes       = 64 << 10
)

type web struct {
	proxies    *proxies
	store      *store.Store
	db         interface{ Status() vulns.Status }
	key        *protocol.DashboardKey
	cfg        Config
	log        *slog.Logger
	now        func() time.Time
	loginIP    *rateLimiter
	loginEmail *rateLimiter
	pages      map[string]*template.Template
	spa        *spa
	pending    pendingLogins
	setup      setup
	sealer     *sealer
	alerts     *alerter
}

func newWeb(st *store.Store, db interface{ Status() vulns.Status }, key *protocol.DashboardKey, cfg Config, trust *proxies, log *slog.Logger, now func() time.Time) (*web, error) {
	w := &web{
		proxies:    trust,
		store:      st,
		db:         db,
		key:        key,
		cfg:        cfg,
		log:        log,
		now:        now,
		loginIP:    newRateLimiter(10, 30*time.Second, now),
		loginEmail: newRateLimiter(5, 5*time.Minute, now),
		pages:      map[string]*template.Template{},
		sealer:     newSealer(key),
	}
	var err error
	if w.spa, err = newSPA(); err != nil {
		return nil, err
	}
	funcs := template.FuncMap{"date": formatDate, "join": strings.Join, "duration": formatDuration}
	for _, page := range []string{"agents", "code", "error", "server", "risk", "settings", "channel"} {
		t, err := template.New("layout.html").Funcs(funcs).ParseFS(webFiles, "web/templates/layout.html", "web/templates/"+page+".html")
		if err != nil {
			return nil, err
		}
		w.pages[page] = t
	}
	return w, nil
}

func (w *web) routes(mux *http.ServeMux) {
	static, _ := fs.Sub(webFiles, "web/static")
	csrf := http.NewCrossOriginProtection()
	page := func(h http.Handler) http.Handler { return w.headers(csrf.Handler(h)) }

	mux.Handle("GET /static/", w.headers(http.StripPrefix("/static/", http.FileServerFS(static))))
	mux.Handle("GET /", w.headers(w.spa))
	mux.Handle("GET /api/ui/session", page(http.HandlerFunc(w.session)))
	mux.Handle("POST /api/ui/login", page(http.HandlerFunc(w.login)))
	mux.Handle("POST /api/ui/login/code", page(http.HandlerFunc(w.loginCode)))
	mux.Handle("POST /api/ui/logout", page(http.HandlerFunc(w.apiLogout)))
	mux.Handle("GET /api/ui/setup", page(http.HandlerFunc(w.setupInfo)))
	mux.Handle("POST /api/ui/setup", page(http.HandlerFunc(w.completeSetup)))
	mux.Handle("GET /api/ui/overview", page(w.apiAdmin(w.overview)))
	for _, m := range []string{"GET", "POST", "PUT", "DELETE"} {
		mux.Handle(m+" /api/ui/", page(http.HandlerFunc(w.apiNotFound)))
	}
	mux.Handle("POST /logout", page(http.HandlerFunc(w.logout)))
	mux.Handle("GET /servers/{id}", page(w.admin(w.serverPage)))
	mux.Handle("GET /servers/{id}/risks/new", page(w.admin(w.riskPage)))
	mux.Handle("POST /servers/{id}/risks", page(w.admin(w.acceptRisk)))
	mux.Handle("POST /servers/{id}/risks/withdraw", page(w.admin(w.withdrawRisk)))
	mux.Handle("GET /agents", page(w.admin(w.agentsPage)))
	mux.Handle("POST /agents/codes", page(w.admin(w.createCode)))
	mux.Handle("POST /agents/{id}/revoke", page(w.admin(w.revoke)))
	mux.Handle("GET /settings", page(w.admin(w.settingsPage)))
	mux.Handle("POST /settings/alerts", page(w.admin(w.saveAlertSettings)))
	mux.Handle("POST /settings/digest", page(w.admin(w.sendDigest)))
	mux.Handle("POST /settings/view", page(w.admin(w.saveView)))
	mux.Handle("GET /settings/channels/new", page(w.admin(w.newChannelPage)))
	mux.Handle("POST /settings/channels", page(w.admin(w.createChannel)))
	mux.Handle("GET /settings/channels/{id}", page(w.admin(w.channelPage)))
	mux.Handle("POST /settings/channels/{id}", page(w.admin(w.updateChannel)))
	mux.Handle("POST /settings/channels/{id}/delete", page(w.admin(w.deleteChannel)))
	mux.Handle("POST /settings/channels/{id}/test", page(w.admin(w.testChannel)))
}

func (w *web) headers(h http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		hd := rw.Header()
		hd.Set("Content-Security-Policy", w.spa.csp)
		hd.Set("X-Content-Type-Options", "nosniff")
		hd.Set("X-Frame-Options", "DENY")
		hd.Set("Referrer-Policy", "no-referrer")
		hd.Set("Cache-Control", "no-store")
		if w.proxies.https(r) {
			hd.Set("Strict-Transport-Security", "max-age=31536000")
		}
		h.ServeHTTP(rw, r)
	})
}

// admin requires a session of a user with the admin role.
func (w *web) admin(h func(http.ResponseWriter, *http.Request, *store.User)) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		u, err := w.currentUser(rw, r)
		if err != nil {
			w.fail(rw, r, err)
			return
		}
		if u == nil {
			http.Redirect(rw, r, "/login", http.StatusSeeOther)
			return
		}
		if u.Role != store.RoleAdmin {
			w.render(rw, http.StatusForbidden, "error", map[string]any{"Message": "This page is for administrators only."})
			return
		}
		h(rw, r, u)
	})
}

func (w *web) logout(rw http.ResponseWriter, r *http.Request) {
	if err := w.endSession(rw, r); err != nil {
		w.fail(rw, r, err)
		return
	}
	http.Redirect(rw, r, "/login", http.StatusSeeOther)
}

func (w *web) cookieName(r *http.Request) string {
	if w.proxies.https(r) {
		return sessionCookie
	}
	return plainSessionCookie
}

func (w *web) clearSession(rw http.ResponseWriter, r *http.Request) {
	http.SetCookie(rw, &http.Cookie{Name: w.cookieName(r), Path: "/", Secure: w.proxies.https(r), HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1})
}

type agentRow struct {
	ID           string
	Hostname     string
	Status       string
	StatusLabel  string
	Fingerprint  string
	AgentVersion string
	EnrolledAt   time.Time
	EnrolledFrom string
	LastReportAt *time.Time
	Revoked      bool
}

func (w *web) agentsPage(rw http.ResponseWriter, r *http.Request, u *store.User) {
	w.renderAgents(rw, r, u, http.StatusOK, "")
}

func (w *web) renderAgents(rw http.ResponseWriter, r *http.Request, u *store.User, status int, message string) {
	agents, err := w.store.Agents(r.Context())
	if err != nil {
		w.fail(rw, r, err)
		return
	}
	now := w.now()
	rows := make([]agentRow, 0, len(agents))
	for _, a := range agents {
		rows = append(rows, agentRow{
			ID:           a.ID,
			Hostname:     a.Hostname,
			Status:       agentStatus(&a, now, w.cfg.StaleAfter),
			StatusLabel:  statusLabels[agentStatus(&a, now, w.cfg.StaleAfter)],
			Fingerprint:  shortFingerprint(a.PublicKey),
			AgentVersion: a.AgentVersion,
			EnrolledAt:   a.EnrolledAt,
			EnrolledFrom: a.EnrolledFromIP,
			LastReportAt: a.LastReportAt,
			Revoked:      a.Revoked(),
		})
	}
	w.render(rw, status, "agents", map[string]any{"User": u, "Agents": rows, "Error": message})
}

// agentStatus treats an agent that never reported like a stale one: silence
// is a problem, never a clean server.
func agentStatus(a *store.Agent, now time.Time, staleAfter time.Duration) string {
	switch {
	case a.Revoked():
		return "revoked"
	case a.LastReportAt == nil && now.Sub(a.EnrolledAt) > staleAfter:
		return "stale"
	case a.LastReportAt == nil:
		return "waiting"
	case now.Sub(*a.LastReportAt) > staleAfter:
		return "stale"
	}
	return "reporting"
}

var statusLabels = map[string]string{
	"revoked":   "revoked",
	"stale":     "stale",
	"waiting":   "waiting for first report",
	"reporting": "reporting",
}

func (w *web) createCode(rw http.ResponseWriter, r *http.Request, u *store.User) {
	if w.cfg.PublicURL == "" {
		w.renderAgents(rw, r, u, http.StatusConflict, "Set public_url in the dashboard configuration before creating enrolment codes: agents need to know where to reach the dashboard.")
		return
	}
	code, err := protocol.NewEnrolmentCode(w.cfg.PublicURL, w.key.Public())
	if err != nil {
		w.fail(rw, r, err)
		return
	}
	now := w.now()
	expires := now.Add(codeLifetime)
	if err := w.store.CreateEnrolmentCode(r.Context(), code.SecretHash(), u.ID, now, expires); err != nil {
		w.fail(rw, r, err)
		return
	}
	w.log.Info("enrolment code created", "by", u.Email, "expires", expires)
	w.render(rw, http.StatusOK, "code", map[string]any{"User": u, "Code": code.String(), "ExpiresAt": expires})
}

func (w *web) revoke(rw http.ResponseWriter, r *http.Request, u *store.User) {
	id := r.PathValue("id")
	err := w.store.RevokeAgent(r.Context(), id, u.ID, w.now())
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		w.fail(rw, r, err)
		return
	}
	w.log.Info("agent revoked", "agent", id, "by", u.Email)
	http.Redirect(rw, r, "/agents", http.StatusSeeOther)
}

// render builds the whole page before sending it, so that a template error
// never sends half a page.
func (w *web) render(rw http.ResponseWriter, status int, page string, data any) {
	var buf bytes.Buffer
	if err := w.pages[page].Execute(&buf, data); err != nil {
		w.log.Error("rendering page", "page", page, "error", err)
		http.Error(rw, "Something went wrong on the dashboard. The details are in its log.", http.StatusInternalServerError)
		return
	}
	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	rw.WriteHeader(status)
	rw.Write(buf.Bytes())
}

func (w *web) fail(rw http.ResponseWriter, r *http.Request, err error) {
	w.log.Error("request failed", "path", r.URL.Path, "error", err)
	w.render(rw, http.StatusInternalServerError, "error", map[string]any{"Message": failMessage})
}

func (w *web) cleanSessions(ctx context.Context) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		if err := w.store.DeleteExpiredSessions(ctx, w.now(), sessionIdle); err != nil && ctx.Err() == nil {
			w.log.Error("deleting expired sessions", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func hashToken(token string) []byte {
	h := sha256.Sum256([]byte(token))
	return h[:]
}

func shortFingerprint(key []byte) string {
	h := sha256.Sum256(key)
	s := hex.EncodeToString(h[:8])
	return s[:4] + " " + s[4:8] + " " + s[8:12] + " " + s[12:]
}

func formatDate(t any) string {
	switch t := t.(type) {
	case time.Time:
		return t.UTC().Format("2 Jan 2006, 15:04 UTC")
	case *time.Time:
		if t == nil {
			return "never"
		}
		return t.UTC().Format("2 Jan 2006, 15:04 UTC")
	}
	return ""
}

// formatDuration shows an uptime in days and hours.
func formatDuration(seconds int64) string {
	d := time.Duration(seconds) * time.Second
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	if days == 0 {
		return fmt.Sprintf("%d h", hours)
	}
	return fmt.Sprintf("%d d %d h", days, hours)
}
