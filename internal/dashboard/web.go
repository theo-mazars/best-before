package dashboard

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/theo-mazars/best-before/internal/dashboard/auth"
	"github.com/theo-mazars/best-before/internal/dashboard/store"
	"github.com/theo-mazars/best-before/internal/protocol"
)

//go:embed web
var webFiles embed.FS

const (
	sessionCookie   = "__Host-bestbefore_session"
	sessionLifetime = 12 * time.Hour
	sessionIdle     = time.Hour
	codeLifetime    = time.Hour
	maxFormBytes    = 64 << 10
)

type web struct {
	store      *store.Store
	key        *protocol.DashboardKey
	cfg        Config
	log        *slog.Logger
	now        func() time.Time
	loginIP    *rateLimiter
	loginEmail *rateLimiter
	pages      map[string]*template.Template
	setup      setup
}

func newWeb(st *store.Store, key *protocol.DashboardKey, cfg Config, log *slog.Logger, now func() time.Time) (*web, error) {
	w := &web{
		store:      st,
		key:        key,
		cfg:        cfg,
		log:        log,
		now:        now,
		loginIP:    newRateLimiter(10, 30*time.Second, now),
		loginEmail: newRateLimiter(5, 5*time.Minute, now),
		pages:      map[string]*template.Template{},
	}
	funcs := template.FuncMap{"date": formatDate}
	for _, page := range []string{"login", "setup", "agents", "code", "error"} {
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
	mux.Handle("GET /setup", page(http.HandlerFunc(w.setupPage)))
	mux.Handle("POST /setup", page(http.HandlerFunc(w.completeSetup)))
	mux.Handle("GET /login", page(http.HandlerFunc(w.loginPage)))
	mux.Handle("POST /login", page(http.HandlerFunc(w.login)))
	mux.Handle("POST /logout", page(http.HandlerFunc(w.logout)))
	mux.Handle("GET /{$}", page(w.admin(func(rw http.ResponseWriter, r *http.Request, _ *store.User) {
		http.Redirect(rw, r, "/agents", http.StatusSeeOther)
	})))
	mux.Handle("GET /agents", page(w.admin(w.agentsPage)))
	mux.Handle("POST /agents/codes", page(w.admin(w.createCode)))
	mux.Handle("POST /agents/{id}/revoke", page(w.admin(w.revoke)))
}

func (w *web) headers(h http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		hd := rw.Header()
		hd.Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		hd.Set("X-Content-Type-Options", "nosniff")
		hd.Set("X-Frame-Options", "DENY")
		hd.Set("Referrer-Policy", "no-referrer")
		hd.Set("Cache-Control", "no-store")
		if w.cfg.TLS != TLSOff {
			hd.Set("Strict-Transport-Security", "max-age=31536000")
		}
		h.ServeHTTP(rw, r)
	})
}

// admin requires a session of a user with the admin role.
func (w *web) admin(h func(http.ResponseWriter, *http.Request, *store.User)) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(sessionCookie)
		if err != nil {
			http.Redirect(rw, r, "/login", http.StatusSeeOther)
			return
		}
		sess, err := w.store.TouchSession(r.Context(), hashToken(c.Value), w.now(), sessionIdle)
		if errors.Is(err, store.ErrNotFound) {
			w.clearSession(rw)
			http.Redirect(rw, r, "/login", http.StatusSeeOther)
			return
		}
		if err != nil {
			w.fail(rw, r, err)
			return
		}
		if sess.User.Role != store.RoleAdmin {
			w.render(rw, http.StatusForbidden, "error", map[string]any{"Message": "This page is for administrators only."})
			return
		}
		h(rw, r, &sess.User)
	})
}

func (w *web) loginPage(rw http.ResponseWriter, r *http.Request) {
	if w.setup.active() {
		http.Redirect(rw, r, "/setup", http.StatusSeeOther)
		return
	}
	w.render(rw, http.StatusOK, "login", nil)
}

func (w *web) login(rw http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(rw, r.Body, maxFormBytes)
	email := strings.TrimSpace(r.PostFormValue("email"))
	password := r.PostFormValue("password")
	code := strings.TrimSpace(r.PostFormValue("code"))
	ip := remoteIP(r)

	refuse := func(reason string) {
		w.log.Warn("login refused", "reason", reason, "email", email, "remote", ip)
		w.render(rw, http.StatusUnauthorized, "login", map[string]any{
			"Email": email,
			"Error": "Email, password or code is incorrect, or there have been too many attempts. Try again in a few minutes.",
		})
	}
	if !w.loginIP.allow(ip) || !w.loginEmail.allow(strings.ToLower(email)) {
		refuse("rate limited")
		return
	}

	u, err := w.store.UserByEmail(r.Context(), email)
	if errors.Is(err, store.ErrNotFound) {
		auth.SpendVerificationTime(password)
		refuse("unknown email")
		return
	}
	if err != nil {
		w.fail(rw, r, err)
		return
	}
	if err := auth.VerifyPassword(password, u.PasswordHash); err != nil {
		refuse("wrong password")
		return
	}
	step, ok := auth.VerifyTOTP(u.TOTPSecret, code, w.now())
	if !ok || len(u.TOTPSecret) == 0 {
		refuse("wrong code")
		return
	}
	if err := w.store.UseTOTPStep(r.Context(), u.ID, step); err != nil {
		refuse("code reused")
		return
	}

	token := rand.Text()
	now := w.now()
	if err := w.store.CreateSession(r.Context(), hashToken(token), u.ID, now, now.Add(sessionLifetime)); err != nil {
		w.fail(rw, r, err)
		return
	}
	http.SetCookie(rw, &http.Cookie{
		Name: sessionCookie, Value: token, Path: "/",
		Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode,
		MaxAge: int(sessionLifetime.Seconds()),
	})
	w.log.Info("logged in", "email", u.Email, "remote", ip)
	http.Redirect(rw, r, "/agents", http.StatusSeeOther)
}

func (w *web) logout(rw http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		if err := w.store.DeleteSession(r.Context(), hashToken(c.Value)); err != nil {
			w.fail(rw, r, err)
			return
		}
	}
	w.clearSession(rw)
	http.Redirect(rw, r, "/login", http.StatusSeeOther)
}

func (w *web) clearSession(rw http.ResponseWriter) {
	http.SetCookie(rw, &http.Cookie{Name: sessionCookie, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1})
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
	w.render(rw, http.StatusInternalServerError, "error", map[string]any{"Message": "Something went wrong on the dashboard. The details are in its log."})
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
