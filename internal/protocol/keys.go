// Package protocol defines how agents and the dashboard trust each other.
//
// The dashboard's identity is an Ed25519 signing key and a post-quantum
// hybrid HPKE key (ML-KEM-768 + X25519) that agents encrypt to. Agents pin it
// at enrolment, so trust does not depend on TLS and a reverse proxy only sees
// ciphertext. Each agent signs its messages with its own Ed25519 key.
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

// Changing the ciphersuite is a protocol version change.
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

type DashboardKey struct {
	sign ed25519.PrivateKey
	kem  hpke.PrivateKey
}

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

func (k *DashboardKey) MarshalBinary() ([]byte, error) {
	kemBytes, err := k.kem.Bytes()
	if err != nil {
		return nil, err
	}
	return join(dashboardPrivateKeyTag, k.sign.Seed(), kemBytes), nil
}

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

func (k *DashboardKey) Public() *DashboardPublicKey {
	return &DashboardPublicKey{
		Sign: k.sign.Public().(ed25519.PublicKey),
		kem:  k.kem.PublicKey(),
	}
}

type DashboardPublicKey struct {
	Sign ed25519.PublicKey
	kem  hpke.PublicKey
}

func (p *DashboardPublicKey) Bytes() []byte {
	return join(dashboardPublicKeyTag, p.Sign, p.kem.Bytes())
}

func (p *DashboardPublicKey) Fingerprint() [32]byte {
	return sha256.Sum256(p.Bytes())
}

func (p *DashboardPublicKey) String() string {
	return base64.RawURLEncoding.EncodeToString(p.Bytes())
}

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

func (p *DashboardPublicKey) Equal(other *DashboardPublicKey) bool {
	return other != nil && bytes.Equal(p.Bytes(), other.Bytes())
}

type AgentKey struct {
	priv ed25519.PrivateKey
}

func GenerateAgentKey() (*AgentKey, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &AgentKey{priv: priv}, nil
}

func (k *AgentKey) MarshalBinary() ([]byte, error) {
	return join(agentPrivateKeyTag, k.priv.Seed()), nil
}

func ParseAgentKey(data []byte) (*AgentKey, error) {
	parts, err := split(agentPrivateKeyTag, data, 1)
	if err != nil || len(parts[0]) != ed25519.SeedSize {
		return nil, errors.New("agent key: malformed")
	}
	return &AgentKey{priv: ed25519.NewKeyFromSeed(parts[0])}, nil
}

func (k *AgentKey) Public() ed25519.PublicKey {
	return k.priv.Public().(ed25519.PublicKey)
}

// join length-prefixes every field, so no two inputs share an encoding.
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
