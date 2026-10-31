package protocol

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hpke"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode"
)

type Kind string

const (
	KindEnrol  Kind = "enrol"
	KindReport Kind = "report"
)

const (
	MaxEnvelopeSize = 32 << 20
	MaxReplySize    = 8 << 10
	MaxReasonLength = 500

	// MaxAge leaves room for retries; anything older may be a replay.
	MaxAge       = 15 * time.Minute
	MaxClockSkew = 5 * time.Minute
)

var (
	ErrBadSignature = errors.New("signature does not verify")
	ErrReplay       = errors.New("sequence number already used")
	ErrTooOld       = errors.New("message is too old")
	ErrFromFuture   = errors.New("message timestamp is in the future")
)

// Envelope carries every agent message: the payload is encrypted to the
// dashboard, and the whole envelope is signed by the agent, so it can be
// checked before the payload is touched.
type Envelope struct {
	Version   int    `json:"version"`
	Kind      Kind   `json:"kind"`
	AgentKey  []byte `json:"agent_key"`
	Sequence  uint64 `json:"sequence"`
	Timestamp int64  `json:"timestamp"` // Unix seconds
	Payload   []byte `json:"payload"`
	Signature []byte `json:"signature"`
}

type EnrolRequest struct {
	Secret       []byte `json:"secret"`
	Hostname     string `json:"hostname"`
	AgentVersion string `json:"agent_version"`
}

// header is the HPKE "info", so a payload cannot move to another envelope.
func (e *Envelope) header() []byte {
	return join("bestbefore-envelope-v1",
		[]byte(e.Kind), e.AgentKey, u64(e.Sequence), u64(uint64(e.Timestamp)))
}

func (e *Envelope) signedBytes() []byte {
	return join("bestbefore-envelope-signature-v1", e.header(), e.Payload)
}

func Seal(k *AgentKey, to *DashboardPublicKey, kind Kind, seq uint64, now time.Time, payload any) ([]byte, error) {
	plaintext, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	e := &Envelope{
		Version:   1,
		Kind:      kind,
		AgentKey:  k.Public(),
		Sequence:  seq,
		Timestamp: now.Unix(),
	}
	if e.Payload, err = hpke.Seal(to.kem, kdf, aead, e.header(), plaintext); err != nil {
		return nil, err
	}
	e.Signature = ed25519.Sign(k.priv, e.signedBytes())
	out, err := json.Marshal(e)
	if err != nil {
		return nil, err
	}
	if len(out) > MaxEnvelopeSize {
		return nil, fmt.Errorf("message is %d bytes, more than the %d allowed", len(out), MaxEnvelopeSize)
	}
	return out, nil
}

// ParseEnvelope verifies the signature only. Callers must then check the
// agent, CheckTime and CheckSequence before calling Open.
func ParseEnvelope(data []byte) (*Envelope, error) {
	if len(data) > MaxEnvelopeSize {
		return nil, errors.New("message too large")
	}
	var e Envelope
	if err := decodeStrict(data, &e); err != nil {
		return nil, err
	}
	switch {
	case e.Version != 1:
		return nil, fmt.Errorf("unsupported version %d", e.Version)
	case e.Kind != KindEnrol && e.Kind != KindReport:
		return nil, errors.New("unknown message kind")
	case len(e.AgentKey) != ed25519.PublicKeySize:
		return nil, errors.New("malformed agent key")
	case len(e.Signature) != ed25519.SignatureSize:
		return nil, errors.New("malformed signature")
	case len(e.Payload) == 0:
		return nil, errors.New("empty payload")
	}
	if !ed25519.Verify(e.AgentKey, e.signedBytes(), e.Signature) {
		return nil, ErrBadSignature
	}
	return &e, nil
}

func (e *Envelope) CheckTime(now time.Time) error {
	t := time.Unix(e.Timestamp, 0)
	switch {
	case now.Sub(t) > MaxAge:
		return ErrTooOld
	case t.Sub(now) > MaxClockSkew:
		return ErrFromFuture
	}
	return nil
}

func (e *Envelope) CheckSequence(last uint64) error {
	if e.Sequence <= last {
		return ErrReplay
	}
	return nil
}

func (e *Envelope) Open(k *DashboardKey, out any) error {
	plaintext, err := hpke.Open(k.kem, kdf, aead, e.header(), e.Payload)
	if err != nil {
		return errors.New("payload does not decrypt")
	}
	return decodeStrict(plaintext, out)
}

type Status string

const (
	Accepted Status = "accepted"
	Rejected Status = "rejected"
)

// Reply has no room for instructions: the agent acts on Status and only
// logs Reason.
type Reply struct {
	Status  Status `json:"status"`
	Reason  string `json:"reason,omitempty"`
	Request []byte `json:"request"`
}

type signedReply struct {
	Body      []byte `json:"body"`
	Signature []byte `json:"signature"`
}

func RequestID(request []byte) []byte {
	h := sha256.Sum256(request)
	return h[:]
}

func SignReply(k *DashboardKey, request []byte, status Status, reason string) ([]byte, error) {
	if len(reason) > MaxReasonLength {
		reason = reason[:MaxReasonLength]
	}
	body, err := json.Marshal(Reply{Status: status, Reason: reason, Request: RequestID(request)})
	if err != nil {
		return nil, err
	}
	return json.Marshal(signedReply{
		Body:      body,
		Signature: ed25519.Sign(k.sign, join("bestbefore-reply-v1", body)),
	})
}

// VerifyReply strips control characters from Reason, which ends up in
// terminals.
func VerifyReply(dashboard *DashboardPublicKey, request, data []byte) (*Reply, error) {
	if len(data) > MaxReplySize {
		return nil, errors.New("reply too large")
	}
	var sr signedReply
	if err := decodeStrict(data, &sr); err != nil {
		return nil, fmt.Errorf("malformed reply: %w", err)
	}
	if !ed25519.Verify(dashboard.Sign, join("bestbefore-reply-v1", sr.Body), sr.Signature) {
		return nil, errors.New("reply is not signed by the enrolled dashboard")
	}
	var r Reply
	if err := decodeStrict(sr.Body, &r); err != nil {
		return nil, fmt.Errorf("malformed reply: %w", err)
	}
	if !bytes.Equal(r.Request, RequestID(request)) {
		return nil, errors.New("reply answers a different request")
	}
	if r.Status != Accepted && r.Status != Rejected {
		return nil, errors.New("reply has an unknown status")
	}
	r.Reason = sanitise(r.Reason)
	return &r, nil
}

func sanitise(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsPrint(r) {
			return r
		}
		return -1
	}, s)
	if len(s) > MaxReasonLength {
		s = s[:MaxReasonLength]
	}
	return s
}

func decodeStrict(data []byte, out any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("unexpected data after JSON value")
	}
	return nil
}

func u64(v uint64) []byte {
	return binary.BigEndian.AppendUint64(nil, v)
}
