package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"time"
)

// RFC 6238 with the parameters every authenticator app supports.
const (
	TOTPSecretLen = 20
	totpPeriod    = 30
	totpDigits    = 6
	// totpSkew accepts the previous and next code, for clock drift.
	totpSkew = 1
)

var secretEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

func NewTOTPSecret() ([]byte, error) {
	s := make([]byte, TOTPSecretLen)
	_, err := rand.Read(s)
	return s, err
}

// EncodeTOTPSecret formats a secret for typing into an authenticator app.
func EncodeTOTPSecret(secret []byte) string {
	return secretEncoding.EncodeToString(secret)
}

func TOTPURI(issuer, account string, secret []byte) string {
	v := url.Values{}
	v.Set("secret", EncodeTOTPSecret(secret))
	v.Set("issuer", issuer)
	v.Set("algorithm", "SHA1")
	v.Set("digits", fmt.Sprint(totpDigits))
	v.Set("period", fmt.Sprint(totpPeriod))
	return "otpauth://totp/" + url.PathEscape(issuer+":"+account) + "?" + v.Encode()
}

// TOTPCodeAt returns the code an authenticator app would show at t.
func TOTPCodeAt(secret []byte, t time.Time) string {
	return totpCode(secret, uint64(t.Unix())/totpPeriod)
}

func totpCode(secret []byte, step uint64) string {
	mac := hmac.New(sha1.New, secret)
	mac.Write(binary.BigEndian.AppendUint64(nil, step))
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	n := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%0*d", totpDigits, n%1_000_000)
}

// VerifyTOTP returns the time step a code belongs to. Callers must refuse a
// step that is not greater than the last one used, so that a code cannot be
// replayed.
func VerifyTOTP(secret []byte, code string, now time.Time) (step uint64, ok bool) {
	if len(code) != totpDigits {
		return 0, false
	}
	current := uint64(now.Unix()) / totpPeriod
	for d := -totpSkew; d <= totpSkew; d++ {
		s := current + uint64(d)
		if subtle.ConstantTimeCompare([]byte(totpCode(secret, s)), []byte(code)) == 1 {
			return s, true
		}
	}
	return 0, false
}
