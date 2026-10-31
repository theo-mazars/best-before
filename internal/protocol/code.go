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

const codePrefix = "bb1_"

// EnrolmentCode is copied from the dashboard to a server. The fingerprint
// stops the agent talking to anything else; the one-time secret proves the
// owner authorised the server. The dashboard stores only the secret's hash.
type EnrolmentCode struct {
	URL         string
	Fingerprint [32]byte
	Secret      [32]byte
}

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

func (c *EnrolmentCode) SecretHash() [32]byte {
	return HashSecret(c.Secret)
}

func HashSecret(secret [32]byte) [32]byte {
	return sha256.Sum256(append([]byte("bestbefore-enrolment-secret-v1"), secret[:]...))
}

func SecretMatches(secret, hash [32]byte) bool {
	h := HashSecret(secret)
	return subtle.ConstantTimeCompare(h[:], hash[:]) == 1
}

func (c *EnrolmentCode) String() string {
	raw := make([]byte, 0, 64+len(c.URL))
	raw = append(raw, c.Fingerprint[:]...)
	raw = append(raw, c.Secret[:]...)
	raw = append(raw, c.URL...)
	return codePrefix + base64.RawURLEncoding.EncodeToString(raw)
}

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
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("dashboard URL must be of the form https://host[:port][/path]")
	}
	return nil
}
