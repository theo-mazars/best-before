// Package auth hashes passwords and checks TOTP codes.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters, above the OWASP minimum. They are stored in each hash,
// so they can be raised later without invalidating existing passwords.
const (
	argonTime    = 3
	argonMemory  = 64 * 1024
	argonThreads = 2
	argonKeyLen  = 32
	saltLen      = 16
)

const (
	MinPasswordLength = 12
	MaxPasswordLength = 1024
)

var ErrPasswordMismatch = errors.New("password does not match")

func CheckPasswordPolicy(password string) error {
	n := utf8.RuneCountInString(password)
	switch {
	case n < MinPasswordLength:
		return fmt.Errorf("password must be at least %d characters", MinPasswordLength)
	case len(password) > MaxPasswordLength:
		return fmt.Errorf("password must be at most %d bytes", MaxPasswordLength)
	}
	return nil
}

// HashPassword returns a PHC-format Argon2id record.
func HashPassword(password string) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	enc := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads, enc.EncodeToString(salt), enc.EncodeToString(key)), nil
}

func VerifyPassword(password, record string) error {
	if len(password) > MaxPasswordLength {
		return ErrPasswordMismatch
	}
	parts := strings.Split(record, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return errors.New("unsupported password record")
	}
	var version int
	var memory, time uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return errors.New("unsupported argon2 version")
	}
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &time, &threads); err != nil {
		return errors.New("malformed password record")
	}
	enc := base64.RawStdEncoding
	salt, err1 := enc.DecodeString(parts[4])
	want, err2 := enc.DecodeString(parts[5])
	if err1 != nil || err2 != nil {
		return errors.New("malformed password record")
	}
	got := argon2.IDKey([]byte(password), salt, time, memory, threads, uint32(len(want)))
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return ErrPasswordMismatch
	}
	return nil
}

// dummyRecord is verified against when the email is unknown, so that the
// response takes as long as for a real account.
var dummyRecord, _ = HashPassword("not a real password, only spends time")

func SpendVerificationTime(password string) {
	_ = VerifyPassword(password, dummyRecord)
}
