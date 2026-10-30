package dashboard

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math"
	"net"
	"net/http"
	"time"
	"unicode"

	"github.com/theo-mazars/best-before/internal/dashboard/store"
	"github.com/theo-mazars/best-before/internal/protocol"
	"github.com/theo-mazars/best-before/internal/report"
)

// ingest receives messages from agents. Everything they send is untrusted.
type ingest struct {
	store    *store.Store
	key      *protocol.DashboardKey
	identity []byte
	log      *slog.Logger
	now      func() time.Time
	perIP    *rateLimiter
	perAgent *rateLimiter
}

// rejection is a reason safe to tell the agent.
type rejection struct{ reason string }

func (r rejection) Error() string { return r.reason }

func reject(reason string) error { return rejection{reason} }

func (in *ingest) routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/identity", in.serveIdentity)
	mux.HandleFunc("POST /api/v1/enrol", in.handle(protocol.KindEnrol, in.enrol))
	mux.HandleFunc("POST /api/v1/reports", in.handle(protocol.KindReport, in.report))
}

// serveIdentity needs no protection: agents check it against the fingerprint
// in their enrolment code.
func (in *ingest) serveIdentity(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write(in.identity)
}

func (in *ingest) handle(kind protocol.Kind, fn func(context.Context, *protocol.Envelope, []byte, string) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := remoteIP(r)
		if !in.perIP.allow(ip) {
			in.log.Warn("rejected message", "reason", "rate limited", "kind", kind, "remote", ip)
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}

		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, protocol.MaxEnvelopeSize))
		if err != nil {
			in.log.Warn("rejected message", "reason", "too large or unreadable", "kind", kind, "remote", ip)
			http.Error(w, "message too large", http.StatusRequestEntityTooLarge)
			return
		}

		err = in.process(r.Context(), kind, raw, ip, fn)
		var rej rejection
		switch {
		case err == nil:
			in.reply(w, raw, protocol.Accepted, "", http.StatusOK)
		case errors.As(err, &rej):
			in.log.Warn("rejected message", "reason", rej.reason, "kind", kind, "remote", ip, "agent", fingerprint(raw))
			in.reply(w, raw, protocol.Rejected, rej.reason, http.StatusForbidden)
		default:
			in.log.Error("failed to process message", "error", err, "kind", kind, "remote", ip)
			in.reply(w, raw, protocol.Rejected, "internal error on the dashboard; try again later", http.StatusInternalServerError)
		}
	}
}

func (in *ingest) process(ctx context.Context, kind protocol.Kind, raw []byte, ip string, fn func(context.Context, *protocol.Envelope, []byte, string) error) error {
	e, err := protocol.ParseEnvelope(raw)
	if err != nil {
		return reject("malformed or unsigned message: " + err.Error())
	}
	if e.Kind != kind {
		return reject("wrong message kind for this endpoint")
	}
	// The agent key is genuine from here on.
	if !in.perAgent.allow(string(e.AgentKey)) {
		return reject("rate limited")
	}
	if err := e.CheckTime(in.now()); err != nil {
		return reject(err.Error() + "; check the server's clock")
	}
	if e.Sequence > math.MaxInt64 {
		return reject("sequence number out of range")
	}
	return fn(ctx, e, raw, ip)
}

func (in *ingest) enrol(ctx context.Context, e *protocol.Envelope, raw []byte, ip string) error {
	var req protocol.EnrolRequest
	if err := e.Open(in.key, &req); err != nil {
		return reject("invalid enrolment request: " + err.Error())
	}
	if len(req.Secret) != 32 {
		return reject("invalid enrolment code")
	}
	if !printable(req.Hostname, 253) || req.Hostname == "" || !printable(req.AgentVersion, 64) {
		return reject("invalid hostname or agent version")
	}

	var secret [32]byte
	copy(secret[:], req.Secret)
	a, err := in.store.RedeemEnrolmentCode(ctx, protocol.HashSecret(secret), store.NewAgent{
		PublicKey:      e.AgentKey,
		Hostname:       req.Hostname,
		AgentVersion:   req.AgentVersion,
		EnrolledFromIP: ip,
	}, in.now())
	switch {
	case errors.Is(err, store.ErrCodeInvalid), errors.Is(err, store.ErrCodeUsed),
		errors.Is(err, store.ErrCodeExpired), errors.Is(err, store.ErrAlreadyEnrolled):
		return reject(err.Error())
	case err != nil:
		return err
	}
	in.log.Info("agent enrolled", "hostname", a.Hostname, "agent", fingerprint(raw), "remote", ip)
	return nil
}

func (in *ingest) report(ctx context.Context, e *protocol.Envelope, raw []byte, ip string) error {
	a, err := in.store.AgentByKey(ctx, e.AgentKey)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return reject("unknown agent; enrol it first")
	case err != nil:
		return err
	case a.Revoked():
		return reject("agent has been revoked")
	}

	// A retry after a lost reply.
	if bytes.Equal(a.LastRequestID, protocol.RequestID(raw)) {
		return nil
	}
	if err := e.CheckSequence(a.LastSequence); err != nil {
		return reject(err.Error())
	}

	var rep report.Report
	if err := e.Open(in.key, &rep); err != nil {
		return reject("invalid report: " + err.Error())
	}
	if rep.SchemaVersion != report.SchemaVersion {
		return reject("unsupported report schema version; update the agent or the dashboard")
	}
	body, err := json.Marshal(rep)
	if err != nil {
		return err
	}

	err = in.store.RecordReport(ctx, a.ID, e.Sequence, protocol.RequestID(raw), in.now(), body)
	if errors.Is(err, store.ErrStaleSequence) {
		return reject("sequence number already used, or agent revoked")
	}
	return err
}

func (in *ingest) reply(w http.ResponseWriter, raw []byte, status protocol.Status, reason string, code int) {
	body, err := protocol.SignReply(in.key, raw, status, reason)
	if err != nil {
		in.log.Error("signing reply", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(body)
}

// fingerprint labels the agent key of a raw envelope in logs.
func fingerprint(raw []byte) string {
	var e struct {
		AgentKey []byte `json:"agent_key"`
	}
	if json.Unmarshal(raw, &e) != nil || len(e.AgentKey) == 0 {
		return "unknown"
	}
	h := sha256.Sum256(e.AgentKey)
	return hex.EncodeToString(h[:6])
}

// remoteIP ignores forwarded headers until trusted proxies can be configured.
func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func printable(s string, max int) bool {
	if len(s) > max {
		return false
	}
	for _, r := range s {
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}
