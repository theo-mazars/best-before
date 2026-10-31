package auth

import (
	"strings"
	"testing"
	"time"
)

// RFC 6238 appendix B, SHA-1, truncated to the 6 digits we use.
func TestTOTPVectors(t *testing.T) {
	secret := []byte("12345678901234567890")
	for unix, want := range map[int64]string{
		59:          "287082",
		1111111109:  "081804",
		1111111111:  "050471",
		1234567890:  "005924",
		2000000000:  "279037",
		20000000000: "353130",
	} {
		if got := totpCode(secret, uint64(unix)/totpPeriod); got != want {
			t.Errorf("time %d: got %s, want %s", unix, got, want)
		}
	}
}

func TestVerifyTOTP(t *testing.T) {
	secret := []byte("12345678901234567890")
	now := time.Unix(1111111111, 0)
	code := totpCode(secret, uint64(now.Unix())/totpPeriod)

	step, ok := VerifyTOTP(secret, code, now)
	if !ok || step != uint64(now.Unix())/totpPeriod {
		t.Fatalf("current code rejected")
	}
	if _, ok := VerifyTOTP(secret, code, now.Add(totpPeriod*time.Second)); !ok {
		t.Error("code from the previous period rejected")
	}
	if _, ok := VerifyTOTP(secret, code, now.Add(3*totpPeriod*time.Second)); ok {
		t.Error("code from three periods ago accepted")
	}
	for _, bad := range []string{"", "12345", "1234567", "abcdef"} {
		if _, ok := VerifyTOTP(secret, bad, now); ok {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestTOTPURI(t *testing.T) {
	uri := TOTPURI("Best Before", "theo@example.org", []byte("12345678901234567890"))
	if !strings.HasPrefix(uri, "otpauth://totp/Best%20Before:theo@example.org?") ||
		!strings.Contains(uri, "secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ") {
		t.Errorf("uri %s", uri)
	}
}

func TestPassword(t *testing.T) {
	record, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(record, "$argon2id$v=19$m=65536,t=3,p=2$") {
		t.Errorf("record %s", record)
	}
	if err := VerifyPassword("correct horse battery staple", record); err != nil {
		t.Error(err)
	}
	if err := VerifyPassword("correct horse battery stapler", record); err != ErrPasswordMismatch {
		t.Errorf("wrong password: %v", err)
	}
	other, _ := HashPassword("correct horse battery staple")
	if other == record {
		t.Error("two hashes of the same password are identical: salt missing")
	}
	for _, bad := range []string{"", "$argon2i$v=19$m=1,t=1,p=1$AA$AA", "$argon2id$v=19$garbage$AA$AA"} {
		if err := VerifyPassword("x", bad); err == nil {
			t.Errorf("accepted record %q", bad)
		}
	}
}

func TestPasswordPolicy(t *testing.T) {
	if CheckPasswordPolicy("short") == nil {
		t.Error("short password accepted")
	}
	if CheckPasswordPolicy(strings.Repeat("a", MaxPasswordLength+1)) == nil {
		t.Error("overlong password accepted")
	}
	if err := CheckPasswordPolicy("a long enough passphrase"); err != nil {
		t.Error(err)
	}
}
