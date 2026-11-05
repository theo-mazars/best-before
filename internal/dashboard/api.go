package dashboard

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"rsc.io/qr"

	"github.com/theo-mazars/best-before/internal/dashboard/auth"
	"github.com/theo-mazars/best-before/internal/dashboard/store"
)

const failMessage = "Something went wrong on the dashboard. The details are in its log."

type apiError struct {
	Error string `json:"error"`
	Field string `json:"field,omitempty"`
}

func writeJSON(rw http.ResponseWriter, status int, v any) {
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(status)
	json.NewEncoder(rw).Encode(v)
}

func writeError(rw http.ResponseWriter, status int, field, message string) {
	writeJSON(rw, status, apiError{Error: message, Field: field})
}

func (w *web) apiFail(rw http.ResponseWriter, r *http.Request, err error) {
	w.log.Error("request failed", "path", r.URL.Path, "error", err)
	writeError(rw, http.StatusInternalServerError, "", failMessage)
}

// readJSON decodes a request body, or answers the error and returns false.
func readJSON(rw http.ResponseWriter, r *http.Request, v any) bool {
	if t, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); t != "application/json" {
		writeError(rw, http.StatusUnsupportedMediaType, "", "Send JSON.")
		return false
	}
	dec := json.NewDecoder(http.MaxBytesReader(rw, r.Body, maxFormBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeError(rw, http.StatusBadRequest, "", "The request is not valid JSON.")
		return false
	}
	return true
}

// currentUser returns the user of the request's session, or nil if there is
// none.
func (w *web) currentUser(rw http.ResponseWriter, r *http.Request) (*store.User, error) {
	c, err := r.Cookie(w.cookieName(r))
	if err != nil {
		return nil, nil
	}
	sess, err := w.store.TouchSession(r.Context(), hashToken(c.Value), w.now(), sessionIdle)
	if errors.Is(err, store.ErrNotFound) {
		w.clearSession(rw, r)
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &sess.User, nil
}

// apiAdmin requires a session of a user with the admin role.
func (w *web) apiAdmin(h func(http.ResponseWriter, *http.Request, *store.User)) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		u, err := w.currentUser(rw, r)
		switch {
		case err != nil:
			w.apiFail(rw, r, err)
		case u == nil:
			writeError(rw, http.StatusUnauthorized, "", "Log in first.")
		case u.Role != store.RoleAdmin:
			writeError(rw, http.StatusForbidden, "", "This page is for administrators only.")
		default:
			h(rw, r, u)
		}
	})
}

type sessionView struct {
	Setup       bool   `json:"setup,omitempty"`
	Email       string `json:"email,omitempty"`
	Role        string `json:"role,omitempty"`
	MinSeverity string `json:"minSeverity,omitempty"`
	Now         string `json:"now"`
	Zone        string `json:"zone"`
}

func (w *web) session(rw http.ResponseWriter, r *http.Request) {
	now := w.now().In(time.Local)
	zone, _ := now.Zone()
	v := sessionView{Now: now.Format(time.RFC3339), Zone: zone}
	if w.setup.active() {
		v.Setup = true
		writeJSON(rw, http.StatusOK, v)
		return
	}
	u, err := w.currentUser(rw, r)
	if err != nil {
		w.apiFail(rw, r, err)
		return
	}
	if u == nil {
		writeError(rw, http.StatusUnauthorized, "", "Log in first.")
		return
	}
	v.Email, v.Role, v.MinSeverity = u.Email, u.Role, u.MinSeverity
	writeJSON(rw, http.StatusOK, v)
}

const (
	pendingLifetime = 5 * time.Minute
	pendingAttempts = 5
	maxPending      = 1000
)

// pendingLogins are logins whose password was right, waiting for their
// authenticator code. They are only in memory: a restart asks for the
// password again.
type pendingLogins struct {
	mu sync.Mutex
	m  map[string]*pendingLogin
}

type pendingLogin struct {
	userID   string
	expires  time.Time
	attempts int
}

func (p *pendingLogins) add(userID string, now time.Time) (string, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.m == nil {
		p.m = map[string]*pendingLogin{}
	}
	for k, v := range p.m {
		if now.After(v.expires) {
			delete(p.m, k)
		}
	}
	if len(p.m) >= maxPending {
		return "", false
	}
	token := rand.Text()
	p.m[string(hashToken(token))] = &pendingLogin{userID: userID, expires: now.Add(pendingLifetime)}
	return token, true
}

// attempt counts a code attempt on a pending login and returns its user, or
// false if there is no such login, it expired or it had too many attempts.
func (p *pendingLogins) attempt(token string, now time.Time) (string, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	k := string(hashToken(token))
	v, ok := p.m[k]
	if !ok || now.After(v.expires) || v.attempts >= pendingAttempts {
		delete(p.m, k)
		return "", false
	}
	v.attempts++
	return v.userID, true
}

func (p *pendingLogins) remove(token string) {
	p.mu.Lock()
	delete(p.m, string(hashToken(token)))
	p.mu.Unlock()
}

func (w *web) pendingCookieName(r *http.Request) string {
	if w.proxies.https(r) {
		return "__Host-bestbefore_login"
	}
	return "bestbefore_login"
}

func (w *web) setCookie(rw http.ResponseWriter, r *http.Request, name, value string, maxAge time.Duration) {
	age := int(maxAge.Seconds())
	if maxAge < 0 {
		age = -1
	}
	http.SetCookie(rw, &http.Cookie{
		Name: name, Value: value, Path: "/",
		Secure: w.proxies.https(r), HttpOnly: true, SameSite: http.SameSiteStrictMode,
		MaxAge: age,
	})
}

// login checks the email and password, then waits for the authenticator code
// in loginCode.
func (w *web) login(rw http.ResponseWriter, r *http.Request) {
	var in struct{ Email, Password string }
	if !readJSON(rw, r, &in) {
		return
	}
	email := strings.TrimSpace(in.Email)
	ip := w.proxies.clientIP(r)

	refuse := func(reason string) {
		w.log.Warn("login refused", "reason", reason, "email", email, "remote", ip)
		writeError(rw, http.StatusUnauthorized, "", "Email or password is incorrect, or there have been too many attempts. Try again in a few minutes.")
	}
	if !w.loginIP.allow(ip) || !w.loginEmail.allow(strings.ToLower(email)) {
		refuse("rate limited")
		return
	}
	u, err := w.store.UserByEmail(r.Context(), email)
	if errors.Is(err, store.ErrNotFound) {
		auth.SpendVerificationTime(in.Password)
		refuse("unknown email")
		return
	}
	if err != nil {
		w.apiFail(rw, r, err)
		return
	}
	if err := auth.VerifyPassword(in.Password, u.PasswordHash); err != nil {
		refuse("wrong password")
		return
	}
	if len(u.TOTPSecret) == 0 {
		refuse("no authenticator")
		return
	}
	token, ok := w.pending.add(u.ID, w.now())
	if !ok {
		refuse("too many pending logins")
		return
	}
	w.setCookie(rw, r, w.pendingCookieName(r), token, pendingLifetime)
	rw.WriteHeader(http.StatusNoContent)
}

func (w *web) loginCode(rw http.ResponseWriter, r *http.Request) {
	var in struct{ Code string }
	if !readJSON(rw, r, &in) {
		return
	}
	ip := w.proxies.clientIP(r)
	expired := func(reason string) {
		w.log.Warn("login refused", "reason", reason, "remote", ip)
		w.setCookie(rw, r, w.pendingCookieName(r), "", -1)
		writeError(rw, http.StatusUnauthorized, "expired", "The login expired. Enter your email and password again.")
	}
	c, err := r.Cookie(w.pendingCookieName(r))
	if err != nil {
		expired("no pending login")
		return
	}
	uid, ok := w.pending.attempt(c.Value, w.now())
	if !ok || !w.loginIP.allow(ip) {
		w.pending.remove(c.Value)
		expired("pending login expired or rate limited")
		return
	}
	u, err := w.store.UserByID(r.Context(), uid)
	if errors.Is(err, store.ErrNotFound) {
		w.pending.remove(c.Value)
		expired("user deleted")
		return
	}
	if err != nil {
		w.apiFail(rw, r, err)
		return
	}
	step, ok := auth.VerifyTOTP(u.TOTPSecret, strings.TrimSpace(in.Code), w.now())
	if ok {
		ok = w.store.UseTOTPStep(r.Context(), u.ID, step) == nil
	}
	if !ok {
		w.log.Warn("login refused", "reason", "wrong or reused code", "email", u.Email, "remote", ip)
		writeError(rw, http.StatusUnauthorized, "code", "The code is incorrect.")
		return
	}
	w.pending.remove(c.Value)

	token := rand.Text()
	now := w.now()
	if err := w.store.CreateSession(r.Context(), hashToken(token), u.ID, now, now.Add(sessionLifetime)); err != nil {
		w.apiFail(rw, r, err)
		return
	}
	w.setCookie(rw, r, w.pendingCookieName(r), "", -1)
	w.setCookie(rw, r, w.cookieName(r), token, sessionLifetime)
	w.log.Info("logged in", "email", u.Email, "remote", ip)
	rw.WriteHeader(http.StatusNoContent)
}

func (w *web) endSession(rw http.ResponseWriter, r *http.Request) error {
	if c, err := r.Cookie(w.cookieName(r)); err == nil {
		if err := w.store.DeleteSession(r.Context(), hashToken(c.Value)); err != nil {
			return err
		}
	}
	w.clearSession(rw, r)
	return nil
}

func (w *web) apiLogout(rw http.ResponseWriter, r *http.Request) {
	if err := w.endSession(rw, r); err != nil {
		w.apiFail(rw, r, err)
		return
	}
	rw.WriteHeader(http.StatusNoContent)
}

type setupView struct {
	Secret string `json:"secret"`
	Key    string `json:"key"`
	QRSize int    `json:"qrSize"`
	QRPath string `json:"qrPath"`
}

func (w *web) setupInfo(rw http.ResponseWriter, r *http.Request) {
	if !w.setup.active() {
		writeError(rw, http.StatusConflict, "", "The dashboard is already set up.")
		return
	}
	secret, err := auth.NewTOTPSecret()
	if err != nil {
		w.apiFail(rw, r, err)
		return
	}
	v := setupView{Secret: auth.EncodeTOTPSecret(secret), Key: groupKey(auth.EncodeTOTPSecret(secret))}
	label := "dashboard"
	if u, err := url.Parse(w.cfg.PublicURL); err == nil && u.Hostname() != "" {
		label = u.Hostname()
	}
	if code, err := qr.Encode(auth.TOTPURI("Best Before", label, secret), qr.M); err == nil {
		v.QRSize, v.QRPath = code.Size+8, qrPath(code)
	}
	writeJSON(rw, http.StatusOK, v)
}

func (w *web) completeSetup(rw http.ResponseWriter, r *http.Request) {
	if !w.setup.active() {
		writeError(rw, http.StatusConflict, "", "The dashboard is already set up.")
		return
	}
	var in struct{ Secret, SetupCode, Email, Password, PasswordAgain, Code string }
	if !readJSON(rw, r, &in) {
		return
	}
	email := strings.TrimSpace(in.Email)
	secret, err := auth.DecodeTOTPSecret(in.Secret)
	if err != nil {
		writeError(rw, http.StatusBadRequest, "", "The setup form was damaged. Reload the page and start again.")
		return
	}
	if !w.loginIP.allow(w.proxies.clientIP(r)) {
		writeError(rw, http.StatusTooManyRequests, "", "Too many attempts. Wait a few minutes.")
		return
	}
	if !w.setup.matches(in.SetupCode) {
		w.log.Warn("setup refused", "reason", "wrong setup code", "remote", w.proxies.clientIP(r))
		writeError(rw, http.StatusUnauthorized, "setupCode", "The setup code is not the one in the dashboard's log.")
		return
	}
	if !validEmail(email) {
		writeError(rw, http.StatusBadRequest, "email", "Enter a valid email address.")
		return
	}
	if err := auth.CheckPasswordPolicy(in.Password); err != nil {
		writeError(rw, http.StatusBadRequest, "password", "The "+err.Error()+".")
		return
	}
	if in.Password != in.PasswordAgain {
		writeError(rw, http.StatusBadRequest, "passwordAgain", "The passwords do not match.")
		return
	}
	step, ok := auth.VerifyTOTP(secret, strings.TrimSpace(in.Code), w.now())
	if !ok {
		writeError(rw, http.StatusBadRequest, "code", "The authenticator code does not match. Check the app and the device's clock.")
		return
	}

	hash, err := auth.HashPassword(in.Password)
	if err != nil {
		w.apiFail(rw, r, err)
		return
	}
	err = w.store.CreateFirstAdmin(r.Context(), email, hash, secret, step, w.now())
	if err != nil && !errors.Is(err, store.ErrSetupDone) {
		w.apiFail(rw, r, err)
		return
	}
	w.setup.finish()
	if err == nil {
		w.log.Info("first admin created", "email", email, "remote", w.proxies.clientIP(r))
	}
	rw.WriteHeader(http.StatusNoContent)
}

func (w *web) apiNotFound(rw http.ResponseWriter, r *http.Request) {
	writeError(rw, http.StatusNotFound, "", "Not found.")
}
