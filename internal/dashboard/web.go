package dashboard

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/theo-mazars/best-before/internal/dashboard/store"
	"github.com/theo-mazars/best-before/internal/dashboard/vulns"
	"github.com/theo-mazars/best-before/internal/protocol"
)

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
		sealer:     newSealer(key),
	}
	var err error
	if w.spa, err = newSPA(); err != nil {
		return nil, err
	}
	return w, nil
}

func (w *web) routes(mux *http.ServeMux) {
	csrf := http.NewCrossOriginProtection()
	page := func(h http.Handler) http.Handler { return w.headers(csrf.Handler(h)) }

	mux.Handle("GET /", w.headers(w.spa))
	mux.Handle("GET /api/ui/session", page(http.HandlerFunc(w.session)))
	mux.Handle("POST /api/ui/login", page(http.HandlerFunc(w.login)))
	mux.Handle("POST /api/ui/login/code", page(http.HandlerFunc(w.loginCode)))
	mux.Handle("POST /api/ui/logout", page(http.HandlerFunc(w.apiLogout)))
	mux.Handle("GET /api/ui/setup", page(http.HandlerFunc(w.setupInfo)))
	mux.Handle("POST /api/ui/setup", page(http.HandlerFunc(w.completeSetup)))
	mux.Handle("GET /api/ui/overview", page(w.apiAdmin(w.overview)))
	mux.Handle("GET /api/ui/servers/{id}", page(w.apiAdmin(w.serverPage)))
	mux.Handle("PUT /api/ui/servers/{id}/risk", page(w.apiAdmin(w.acceptRisk)))
	mux.Handle("DELETE /api/ui/servers/{id}/risk", page(w.apiAdmin(w.withdrawRisk)))
	mux.Handle("GET /api/ui/agents", page(w.apiAdmin(w.agents)))
	mux.Handle("POST /api/ui/agents/codes", page(w.apiAdmin(w.createCode)))
	mux.Handle("DELETE /api/ui/agents/codes/{id}", page(w.apiAdmin(w.revokeCode)))
	mux.Handle("POST /api/ui/agents/{id}/revoke", page(w.apiAdmin(w.revoke)))
	mux.Handle("GET /api/ui/settings", page(w.apiAdmin(w.settings)))
	mux.Handle("PUT /api/ui/settings/alerts", page(w.apiAdmin(w.saveAlertSettings)))
	mux.Handle("POST /api/ui/settings/digest", page(w.apiAdmin(w.sendDigest)))
	mux.Handle("POST /api/ui/settings/channels", page(w.apiAdmin(w.createChannel)))
	mux.Handle("PUT /api/ui/settings/channels/{id}", page(w.apiAdmin(w.updateChannel)))
	mux.Handle("DELETE /api/ui/settings/channels/{id}", page(w.apiAdmin(w.deleteChannel)))
	mux.Handle("POST /api/ui/settings/channels/{id}/test", page(w.apiAdmin(w.testChannel)))
	mux.Handle("PUT /api/ui/preferences", page(w.apiAdmin(w.savePreferences)))
	for _, m := range []string{"GET", "POST", "PUT", "DELETE"} {
		mux.Handle(m+" /api/ui/", page(http.HandlerFunc(w.apiNotFound)))
	}
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
	ID           string     `json:"id"`
	Hostname     string     `json:"hostname"`
	Status       string     `json:"status"`
	Fingerprint  string     `json:"fingerprint"`
	AgentVersion string     `json:"agentVersion"`
	EnrolledAt   time.Time  `json:"enrolledAt"`
	EnrolledFrom string     `json:"enrolledFrom"`
	LastReportAt *time.Time `json:"lastReportAt"`
	RevokedAt    *time.Time `json:"revokedAt"`
}

type codeRow struct {
	ID        string    `json:"id"`
	CreatedBy string    `json:"createdBy"`
	CreatedAt time.Time `json:"createdAt"`
	ExpiresAt time.Time `json:"expiresAt"`
}

type agentsView struct {
	Agents   []agentRow `json:"agents"`
	Codes    []codeRow  `json:"codes"`
	CanEnrol bool       `json:"canEnrol"`
}

func (w *web) agents(rw http.ResponseWriter, r *http.Request, u *store.User) {
	agents, err := w.store.Agents(r.Context())
	if err != nil {
		w.apiFail(rw, r, err)
		return
	}
	now := w.now()
	active, err := w.store.ActiveEnrolmentCodes(r.Context(), now)
	if err != nil {
		w.apiFail(rw, r, err)
		return
	}
	codes := make([]codeRow, 0, len(active))
	for _, c := range active {
		codes = append(codes, codeRow(c))
	}
	rows := make([]agentRow, 0, len(agents))
	for _, a := range agents {
		rows = append(rows, agentRow{
			ID:           a.ID,
			Hostname:     a.Hostname,
			Status:       agentStatus(&a, now, w.cfg.StaleAfter),
			Fingerprint:  shortFingerprint(a.PublicKey),
			AgentVersion: a.AgentVersion,
			EnrolledAt:   a.EnrolledAt,
			EnrolledFrom: a.EnrolledFromIP,
			LastReportAt: a.LastReportAt,
			RevokedAt:    a.RevokedAt,
		})
	}
	writeJSON(rw, http.StatusOK, agentsView{Agents: rows, Codes: codes, CanEnrol: w.cfg.PublicURL != ""})
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

type enrolmentCodeView struct {
	Command   string    `json:"command"`
	ExpiresAt time.Time `json:"expiresAt"`
}

func (w *web) createCode(rw http.ResponseWriter, r *http.Request, u *store.User) {
	if w.cfg.PublicURL == "" {
		writeError(rw, http.StatusConflict, "", "Set public_url in the dashboard configuration before creating enrolment codes: agents need to know where to reach the dashboard.")
		return
	}
	code, err := protocol.NewEnrolmentCode(w.cfg.PublicURL, w.key.Public())
	if err != nil {
		w.apiFail(rw, r, err)
		return
	}
	now := w.now()
	expires := now.Add(codeLifetime)
	if err := w.store.CreateEnrolmentCode(r.Context(), code.SecretHash(), u.ID, now, expires); err != nil {
		w.apiFail(rw, r, err)
		return
	}
	w.log.Info("enrolment code created", "by", u.Email, "expires", expires)
	writeJSON(rw, http.StatusOK, enrolmentCodeView{Command: "sudo bestbefore-agent enrol " + code.String(), ExpiresAt: expires})
}

func (w *web) revokeCode(rw http.ResponseWriter, r *http.Request, u *store.User) {
	id := r.PathValue("id")
	err := w.store.RevokeEnrolmentCode(r.Context(), id, w.now())
	if errors.Is(err, store.ErrNotFound) {
		writeError(rw, http.StatusNotFound, "", "This code was already used, revoked or expired.")
		return
	}
	if err != nil {
		w.apiFail(rw, r, err)
		return
	}
	w.log.Info("enrolment code revoked", "code", id, "by", u.Email)
	rw.WriteHeader(http.StatusNoContent)
}

func (w *web) revoke(rw http.ResponseWriter, r *http.Request, u *store.User) {
	id := r.PathValue("id")
	err := w.store.RevokeAgent(r.Context(), id, u.ID, w.now())
	if errors.Is(err, store.ErrNotFound) {
		writeError(rw, http.StatusNotFound, "", "This agent does not exist or is already revoked.")
		return
	}
	if err != nil {
		w.apiFail(rw, r, err)
		return
	}
	w.log.Info("agent revoked", "agent", id, "by", u.Email)
	rw.WriteHeader(http.StatusNoContent)
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
