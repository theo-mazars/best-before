package protocol

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
)

// Identity is served at /api/v1/identity. With the builtin self-signed
// certificate, it also vouches for the TLS key, which agents pin. Behind a
// reverse proxy the TLS fields are empty and a CA-valid certificate is needed.
type Identity struct {
	PublicKey       string `json:"public_key"`
	TLSKey          []byte `json:"tls_key,omitempty"`
	TLSKeySignature []byte `json:"tls_key_signature,omitempty"`
}

// TLSKeyHash is the SHA-256 of the SubjectPublicKeyInfo, as in HPKP.
func TLSKeyHash(cert *x509.Certificate) []byte {
	h := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return h[:]
}

func NewIdentity(k *DashboardKey, tlsCert *x509.Certificate) ([]byte, error) {
	id := Identity{PublicKey: k.Public().String()}
	if tlsCert != nil {
		id.TLSKey = TLSKeyHash(tlsCert)
		id.TLSKeySignature = ed25519.Sign(k.sign, join("bestbefore-tls-key-v1", id.TLSKey))
	}
	return json.Marshal(id)
}

// VerifyIdentity returns the TLS key hash only if the dashboard vouches for
// one.
func VerifyIdentity(data []byte, fingerprint [32]byte) (*DashboardPublicKey, []byte, error) {
	if len(data) > MaxReplySize {
		return nil, nil, errors.New("identity document too large")
	}
	var id Identity
	if err := decodeStrict(data, &id); err != nil {
		return nil, nil, err
	}
	pub, err := ParseDashboardPublicKey([]byte(id.PublicKey))
	if err != nil {
		return nil, nil, err
	}
	if pub.Fingerprint() != fingerprint {
		return nil, nil, errors.New("this is not the dashboard the enrolment code was created by")
	}
	if len(id.TLSKey) == 0 {
		return pub, nil, nil
	}
	if len(id.TLSKey) != sha256.Size || !ed25519.Verify(pub.Sign, join("bestbefore-tls-key-v1", id.TLSKey), id.TLSKeySignature) {
		return nil, nil, errors.New("the dashboard's TLS key statement does not verify")
	}
	return pub, id.TLSKey, nil
}

func EncodeTLSKeyHash(h []byte) string { return base64.RawURLEncoding.EncodeToString(h) }

func DecodeTLSKeyHash(s string) ([]byte, error) {
	h, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(h) != sha256.Size {
		return nil, errors.New("malformed TLS key hash")
	}
	return h, nil
}
