package store

import (
	"crypto/rand"
	"strings"
)

const idLength = 26

// newID returns 130 random bits as lowercase base32. rand.Text may return
// longer strings in future Go versions; 26 characters are enough.
func newID() string {
	return strings.ToLower(rand.Text()[:idLength])
}
