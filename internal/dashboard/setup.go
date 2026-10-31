package dashboard

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"net/mail"
	"net/url"
	"strings"
	"sync"

	"rsc.io/qr"

	"github.com/theo-mazars/best-before/internal/dashboard/auth"
	"github.com/theo-mazars/best-before/internal/dashboard/store"
)

// setup lets the first admin be created from the browser. It needs a code
// printed in the dashboard's log, so only someone with access to the host can
// complete it, however early someone else reaches the page.
type setup struct {
	mu   sync.Mutex
	code string // empty once an admin exists
}

// start prepares setup if the dashboard has no users, and returns the code to
// print, or "" if setup is not needed.
func (s *setup) start(ctx context.Context, st *store.Store) (string, error) {
	n, err := st.CountUsers(ctx)
	if err != nil || n > 0 {
		return "", err
	}
	code := strings.ToUpper(rand.Text()[:16])
	s.mu.Lock()
	s.code = code
	s.mu.Unlock()
	return code[0:4] + "-" + code[4:8] + "-" + code[8:12] + "-" + code[12:16], nil
}

func (s *setup) active() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.code != ""
}

func (s *setup) matches(entered string) bool {
	entered = strings.ToUpper(strings.NewReplacer("-", "", " ", "").Replace(entered))
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.code != "" && subtle.ConstantTimeCompare([]byte(entered), []byte(s.code)) == 1
}

func (s *setup) finish() {
	s.mu.Lock()
	s.code = ""
	s.mu.Unlock()
}

type setupForm struct {
	User      *store.User // always nil: no one is logged in during setup
	Email     string
	Secret    string
	SecretKey string
	QRSize    int
	QRPath    string
	Error     string
}

func (w *web) setupPage(rw http.ResponseWriter, r *http.Request) {
	if !w.setup.active() {
		http.Redirect(rw, r, "/login", http.StatusSeeOther)
		return
	}
	secret, err := auth.NewTOTPSecret()
	if err != nil {
		w.fail(rw, r, err)
		return
	}
	w.renderSetup(rw, http.StatusOK, "", secret, "")
}

func (w *web) completeSetup(rw http.ResponseWriter, r *http.Request) {
	if !w.setup.active() {
		http.Redirect(rw, r, "/login", http.StatusSeeOther)
		return
	}
	r.Body = http.MaxBytesReader(rw, r.Body, maxFormBytes)
	email := strings.TrimSpace(r.PostFormValue("email"))
	secret, err := auth.DecodeTOTPSecret(r.PostFormValue("totp_secret"))
	if err != nil {
		w.render(rw, http.StatusBadRequest, "error", map[string]any{"Message": "The setup form was damaged. Reload the page and start again."})
		return
	}
	retry := func(status int, message string) {
		w.renderSetup(rw, status, email, secret, message)
	}

	if !w.loginIP.allow(w.proxies.clientIP(r)) {
		retry(http.StatusTooManyRequests, "Too many attempts. Wait a few minutes.")
		return
	}
	if !w.setup.matches(r.PostFormValue("setup_code")) {
		w.log.Warn("setup refused", "reason", "wrong setup code", "remote", w.proxies.clientIP(r))
		retry(http.StatusUnauthorized, "The setup code is not the one in the dashboard's log.")
		return
	}
	if !validEmail(email) {
		retry(http.StatusBadRequest, "Enter a valid email address.")
		return
	}
	password := r.PostFormValue("password")
	if err := auth.CheckPasswordPolicy(password); err != nil {
		retry(http.StatusBadRequest, "The "+err.Error()+".")
		return
	}
	if password != r.PostFormValue("password_again") {
		retry(http.StatusBadRequest, "The passwords do not match.")
		return
	}
	step, ok := auth.VerifyTOTP(secret, strings.TrimSpace(r.PostFormValue("code")), w.now())
	if !ok {
		retry(http.StatusBadRequest, "The authenticator code does not match. Check the app and the device's clock.")
		return
	}

	hash, err := auth.HashPassword(password)
	if err != nil {
		w.fail(rw, r, err)
		return
	}
	err = w.store.CreateFirstAdmin(r.Context(), email, hash, secret, step, w.now())
	if err != nil && !errors.Is(err, store.ErrSetupDone) {
		w.fail(rw, r, err)
		return
	}
	w.setup.finish()
	if err == nil {
		w.log.Info("first admin created", "email", email, "remote", w.proxies.clientIP(r))
	}
	http.Redirect(rw, r, "/login", http.StatusSeeOther)
}

func (w *web) renderSetup(rw http.ResponseWriter, status int, email string, secret []byte, message string) {
	form := setupForm{Email: email, Secret: auth.EncodeTOTPSecret(secret), SecretKey: groupKey(auth.EncodeTOTPSecret(secret)), Error: message}
	label := "dashboard"
	if u, err := url.Parse(w.cfg.PublicURL); err == nil && u.Hostname() != "" {
		label = u.Hostname()
	}
	if code, err := qr.Encode(auth.TOTPURI("Best Before", label, secret), qr.M); err == nil {
		form.QRSize, form.QRPath = code.Size+8, qrPath(code)
	}
	w.render(rw, status, "setup", form)
}

// qrPath draws a QR code as one SVG path, so it is part of the page and needs
// no image source in the Content Security Policy.
func qrPath(c *qr.Code) string {
	var b strings.Builder
	for y := 0; y < c.Size; y++ {
		for x := 0; x < c.Size; x++ {
			if c.Black(x, y) {
				fmt.Fprintf(&b, "M%d %dh1v1h-1z", x, y)
			}
		}
	}
	return b.String()
}

// groupKey splits a key in groups of four, for typing it into an app.
func groupKey(key string) string {
	var groups []string
	for len(key) > 4 {
		groups = append(groups, key[:4])
		key = key[4:]
	}
	return strings.Join(append(groups, key), " ")
}

func validEmail(email string) bool {
	addr, err := mail.ParseAddress(email)
	return err == nil && addr.Address == email && addr.Name == ""
}
