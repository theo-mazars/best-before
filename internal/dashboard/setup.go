package dashboard

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"net/mail"
	"strings"
	"sync"

	"rsc.io/qr"

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
