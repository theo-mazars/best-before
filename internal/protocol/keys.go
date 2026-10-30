// Package protocol defines how agents and the dashboard trust each other and
// exchange messages. It is shared by both binaries.
//
// The dashboard has a long-term identity made of two keys: an Ed25519 key
// that signs its replies (and serves as its built-in TLS key), and a hybrid
// post-quantum HPKE key (ML-KEM-768 + X25519) to which agents encrypt
// everything they send. Agents pin this identity at enrolment, so trust does
// not depend on TLS certificates, and a reverse proxy in between only ever
// sees ciphertext.
//
// Each agent has an Ed25519 key that signs every message it sends.
package protocol

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hpke"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
)

// Ciphersuite. Changing any of these is a protocol version change.
var (
	kem  = hpke.MLKEM768X25519()
	kdf  = hpke.HKDFSHA256()
	aead = hpke.ChaCha20Poly1305()
)

const (
	dashboardPublicKeyTag  = "bestbefore-dashboard-public-v1"
	dashboardPrivateKeyTag = "bestbefore-dashboard-private-v1"
	agentPrivateKeyTag     = "bestbefore-agent-private-v1"
)

// DashboardKey is the dashboard's private identity. It never leaves the
// dashboard.
type DashboardKey struct {
	sign ed25519.PrivateKey
	kem  hpke.PrivateKey
}

// GenerateDashboardKey creates a new dashboard identity.
func GenerateDashboardKey() (*DashboardKey, error) {
	_, sign, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	k, err := kem.GenerateKey()
	if err != nil {
		return nil, err
	}
	return &DashboardKey{sign: sign, kem: k}, nil
}

// MarshalBinary serialises the private key for storage.
func (k *DashboardKey) MarshalBinary() ([]byte, error) {
	kemBytes, err := k.kem.Bytes()
	if err != nil {
		return nil, err
	}
	return join(dashboardPrivateKeyTag, k.sign.Seed(), kemBytes), nil
}

// ParseDashboardKey reads a key written by MarshalBinary.
func ParseDashboardKey(data []byte) (*DashboardKey, error) {
	parts, err := split(dashboardPrivateKeyTag, data, 2)
	if err != nil {
		return nil, fmt.Errorf("dashboard key: %w", err)
	}
	if len(parts[0]) != ed25519.SeedSize {
		return nil, errors.New("dashboard key: bad signing key")
	}
	k, err := kem.NewPrivateKey(parts[1])
	if err != nil {
		return nil, fmt.Errorf("dashboard key: %w", err)
	}
	return &DashboardKey{sign: ed25519.NewKeyFromSeed(parts[0]), kem: k}, nil
}

// Public returns the dashboard's public identity.
func (k *DashboardKey) Public() *DashboardPublicKey {
	return &DashboardPublicKey{
		Sign: k.sign.Public().(ed25519.PublicKey),
		kem:  k.kem.PublicKey(),
	}
}

// Signer returns the Ed25519 key, for the dashboard's built-in TLS
// certificate.
func (k *DashboardKey) Signer() ed25519.PrivateKey {
	return k.sign
}

// DashboardPublicKey is the dashboard's public identity, as pinned by agents.
type DashboardPublicKey struct {
	Sign ed25519.PublicKey
	kem  hpke.PublicKey
}

// Bytes serialises the public identity. Its SHA-256 is the fingerprint.
func (p *DashboardPublicKey) Bytes() []byte {
	return join(dashboardPublicKeyTag, p.Sign, p.kem.Bytes())
}

// Fingerprint identifies the dashboard. It is carried in enrolment codes.
func (p *DashboardPublicKey) Fingerprint() [32]byte {
	return sha256.Sum256(p.Bytes())
}

// String returns the public identity in a form fit for config files.
func (p *DashboardPublicKey) String() string {
	return base64.RawURLEncoding.EncodeToString(p.Bytes())
}

// ParseDashboardPublicKey reads the output of Bytes or String.
func ParseDashboardPublicKey(data []byte) (*DashboardPublicKey, error) {
	if raw, err := base64.RawURLEncoding.DecodeString(string(data)); err == nil {
		data = raw
	}
	parts, err := split(dashboardPublicKeyTag, data, 2)
	if err != nil {
		return nil, fmt.Errorf("dashboard public key: %w", err)
	}
	if len(parts[0]) != ed25519.PublicKeySize {
		return nil, errors.New("dashboard public key: bad signing key")
	}
	pk, err := kem.NewPublicKey(parts[1])
	if err != nil {
		return nil, fmt.Errorf("dashboard public key: %w", err)
	}
	return &DashboardPublicKey{Sign: ed25519.PublicKey(parts[0]), kem: pk}, nil
}

// Equal reports whether two public identities are the same.
func (p *DashboardPublicKey) Equal(other *DashboardPublicKey) bool {
	return other != nil && bytes.Equal(p.Bytes(), other.Bytes())
}

// AgentKey is an agent's private key. It never leaves the server.
type AgentKey struct {
	priv ed25519.PrivateKey
}

// GenerateAgentKey creates a new agent key.
func GenerateAgentKey() (*AgentKey, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &AgentKey{priv: priv}, nil
}

// MarshalBinary serialises the private key for storage.
func (k *AgentKey) MarshalBinary() ([]byte, error) {
	return join(agentPrivateKeyTag, k.priv.Seed()), nil
}

// ParseAgentKey reads a key written by MarshalBinary.
func ParseAgentKey(data []byte) (*AgentKey, error) {
	parts, err := split(agentPrivateKeyTag, data, 1)
	if err != nil || len(parts[0]) != ed25519.SeedSize {
		return nil, errors.New("agent key: malformed")
	}
	return &AgentKey{priv: ed25519.NewKeyFromSeed(parts[0])}, nil
}

// Public returns the agent's public key, which identifies it to the dashboard.
func (k *AgentKey) Public() ed25519.PublicKey {
	return k.priv.Public().(ed25519.PublicKey)
}

// join encodes a tag and fields with length prefixes, so that no two
// different inputs share an encoding. Used both for serialising keys and for
// building the exact bytes that get signed.
func join(tag string, fields ...[]byte) []byte {
	var b bytes.Buffer
	writeField(&b, []byte(tag))
	for _, f := range fields {
		writeField(&b, f)
	}
	return b.Bytes()
}

func writeField(b *bytes.Buffer, f []byte) {
	n := uint32(len(f))
	b.Write([]byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)})
	b.Write(f)
}

// split reverses join, checking the tag and the number of fields.
func split(tag string, data []byte, count int) ([][]byte, error) {
	var fields [][]byte
	for len(data) > 0 {
		if len(data) < 4 {
			return nil, errors.New("truncated")
		}
		n := int(data[0])<<24 | int(data[1])<<16 | int(data[2])<<8 | int(data[3])
		data = data[4:]
		if n > len(data) {
			return nil, errors.New("truncated")
		}
		fields = append(fields, data[:n])
		data = data[n:]
	}
	if len(fields) != count+1 || string(fields[0]) != tag {
		return nil, errors.New("unexpected format")
	}
	return fields[1:], nil
}
