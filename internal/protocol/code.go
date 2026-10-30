package protocol

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/url"
	"strings"
)

// codePrefix marks an enrolment code, and its version.
const codePrefix = "bb1_"

// EnrolmentCode is what the owner copies from the dashboard to a server. It
// carries everything the agent needs to enrol, with nothing to compare by
// hand:
//
//   - the dashboard's address;
//   - the fingerprint of the dashboard's identity, so that the agent refuses
//     to talk to anything else;
//   - a one-time secret, which proves to the dashboard that the owner
//     authorised this server. The dashboard only stores its hash.
type EnrolmentCode struct {
	URL         string
	Fingerprint [32]byte
	Secret      [32]byte
}

// NewEnrolmentCode creates a code with a fresh random secret.
func NewEnrolmentCode(dashboardURL string, id *DashboardPublicKey) (*EnrolmentCode, error) {
	if err := checkDashboardURL(dashboardURL); err != nil {
		return nil, err
	}
	c := &EnrolmentCode{URL: dashboardURL, Fingerprint: id.Fingerprint()}
	if _, err := rand.Read(c.Secret[:]); err != nil {
		return nil, err
	}
	return c, nil
}

// SecretHash is what the dashboard stores and looks codes up by.
func (c *EnrolmentCode) SecretHash() [32]byte {
	return HashSecret(c.Secret)
}

// HashSecret hashes an enrolment secret.
func HashSecret(secret [32]byte) [32]byte {
	return sha256.Sum256(append([]byte("bestbefore-enrolment-secret-v1"), secret[:]...))
}

// SecretMatches compares a secret with a stored hash in constant time.
func SecretMatches(secret, hash [32]byte) bool {
	h := HashSecret(secret)
	return subtle.ConstantTimeCompare(h[:], hash[:]) == 1
}

// String encodes the code for copying, e.g. "bb1_Zm9v…".
func (c *EnrolmentCode) String() string {
	raw := make([]byte, 0, 64+len(c.URL))
	raw = append(raw, c.Fingerprint[:]...)
	raw = append(raw, c.Secret[:]...)
	raw = append(raw, c.URL...)
	return codePrefix + base64.RawURLEncoding.EncodeToString(raw)
}

// ParseEnrolmentCode reads a code produced by String. Surrounding white space
// is ignored, since codes are pasted.
func ParseEnrolmentCode(s string) (*EnrolmentCode, error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, codePrefix) {
		return nil, errors.New("not a Best Before enrolment code")
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(s, codePrefix))
	if err != nil || len(raw) <= 64 {
		return nil, errors.New("enrolment code is damaged; copy it again from the dashboard")
	}
	c := &EnrolmentCode{URL: string(raw[64:])}
	copy(c.Fingerprint[:], raw[:32])
	copy(c.Secret[:], raw[32:64])
	if err := checkDashboardURL(c.URL); err != nil {
		return nil, err
	}
	return c, nil
}

func checkDashboardURL(s string) error {
	if len(s) > 2048 {
		return errors.New("dashboard URL is too long")
	}
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("dashboard URL must be of the form https://host[:port][/path]")
	}
	return nil
}
