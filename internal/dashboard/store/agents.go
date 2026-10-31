package store

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"errors"
	"strings"
	"time"
)

type Agent struct {
	ID             string
	PublicKey      ed25519.PublicKey
	Hostname       string
	AgentVersion   string
	EnrolledAt     time.Time
	EnrolledFromIP string
	RevokedAt      *time.Time
	LastSequence   uint64
	LastRequestID  []byte
	LastReportAt   *time.Time
}

func (a *Agent) Revoked() bool { return a.RevokedAt != nil }

type NewAgent struct {
	PublicKey      ed25519.PublicKey
	Hostname       string
	AgentVersion   string
	EnrolledFromIP string
}

// Queries must stay constants: see sqlconst_test.go.
const (
	insertEnrolmentCode = `INSERT INTO enrolment_codes (id, secret_hash, created_by, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?)`
	selectEnrolmentCode = `SELECT id, expires_at, used_at FROM enrolment_codes WHERE secret_hash = ?`
	useEnrolmentCode    = `UPDATE enrolment_codes SET used_at = ?, agent_id = ? WHERE id = ?`

	insertAgent = `INSERT INTO agents (id, public_key, hostname, agent_version, enrolled_at, enrolled_from_ip)
		VALUES (?, ?, ?, ?, ?, ?)`
	selectAgents = `SELECT id, public_key, hostname, agent_version, enrolled_at, enrolled_from_ip,
		revoked_at, last_sequence, last_request_id, last_report_at FROM agents`
	selectAgentByID  = selectAgents + ` WHERE id = ?`
	selectAgentByKey = selectAgents + ` WHERE public_key = ?`
	selectAllAgents  = selectAgents + ` ORDER BY hostname, enrolled_at`
	revokeAgent      = `UPDATE agents SET revoked_at = ?, revoked_by = ? WHERE id = ? AND revoked_at IS NULL`

	// One statement, so two concurrent reports cannot both be accepted.
	advanceAgent = `UPDATE agents SET last_sequence = ?, last_request_id = ?, last_report_at = ?
		WHERE id = ? AND last_sequence < ? AND revoked_at IS NULL`
	upsertLatestReport = `INSERT INTO latest_reports (agent_id, received_at, sequence, body) VALUES (?, ?, ?, ?)
		ON CONFLICT (agent_id) DO UPDATE SET received_at = excluded.received_at,
		sequence = excluded.sequence, body = excluded.body`
	selectLatestReport = `SELECT body FROM latest_reports WHERE agent_id = ?`
)

// CreateEnrolmentCode stores the hash of a code's secret. createdBy is "" for
// codes created from the command line.
func (s *Store) CreateEnrolmentCode(ctx context.Context, secretHash [32]byte, createdBy string, now, expires time.Time) error {
	_, err := s.db.ExecContext(ctx, insertEnrolmentCode,
		newID(), secretHash[:], nullString(createdBy), unix(now), unix(expires))
	return err
}

// RedeemEnrolmentCode enrols an agent. A code works once, and a failed
// attempt does not use it up.
func (s *Store) RedeemEnrolmentCode(ctx context.Context, secretHash [32]byte, a NewAgent, now time.Time) (*Agent, error) {
	agentID := newID()
	err := s.tx(ctx, func(tx *sql.Tx) error {
		var codeID string
		var expires int64
		var used sql.NullInt64
		err := tx.QueryRowContext(ctx, selectEnrolmentCode, secretHash[:]).Scan(&codeID, &expires, &used)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return ErrCodeInvalid
		case err != nil:
			return err
		case used.Valid:
			return ErrCodeUsed
		case unix(now) >= expires:
			return ErrCodeExpired
		}

		_, err = tx.ExecContext(ctx, insertAgent,
			agentID, []byte(a.PublicKey), a.Hostname, a.AgentVersion, unix(now), a.EnrolledFromIP)
		if err != nil {
			if strings.Contains(err.Error(), "UNIQUE constraint failed: agents.public_key") {
				return ErrAlreadyEnrolled
			}
			return err
		}
		_, err = tx.ExecContext(ctx, useEnrolmentCode, unix(now), agentID, codeID)
		return err
	})
	if err != nil {
		return nil, err
	}
	return s.AgentByID(ctx, agentID)
}

func (s *Store) AgentByKey(ctx context.Context, key ed25519.PublicKey) (*Agent, error) {
	return s.oneAgent(s.db.QueryRowContext(ctx, selectAgentByKey, []byte(key)))
}

func (s *Store) AgentByID(ctx context.Context, id string) (*Agent, error) {
	return s.oneAgent(s.db.QueryRowContext(ctx, selectAgentByID, id))
}

// Agents lists every agent, revoked ones included.
func (s *Store) Agents(ctx context.Context) ([]Agent, error) {
	rows, err := s.db.QueryContext(ctx, selectAllAgents)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var agents []Agent
	for rows.Next() {
		a, err := scanAgent(rows)
		if err != nil {
			return nil, err
		}
		agents = append(agents, *a)
	}
	return agents, rows.Err()
}

// RecordReport stores an agent's latest report. It fails with
// ErrStaleSequence on a replayed sequence number or a revoked agent.
func (s *Store) RecordReport(ctx context.Context, agentID string, seq uint64, requestID []byte, now time.Time, body []byte) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, advanceAgent, seq, requestID, unix(now), agentID, seq)
		if err != nil {
			return err
		}
		if n, err := res.RowsAffected(); err != nil {
			return err
		} else if n == 0 {
			return ErrStaleSequence
		}
		_, err = tx.ExecContext(ctx, upsertLatestReport, agentID, unix(now), seq, string(body))
		return err
	})
}

func (s *Store) LatestReport(ctx context.Context, agentID string) ([]byte, error) {
	var body string
	err := s.db.QueryRowContext(ctx, selectLatestReport, agentID).Scan(&body)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return []byte(body), err
}

// RevokeAgent takes effect on the agent's next message. by is "" from the
// command line.
func (s *Store) RevokeAgent(ctx context.Context, id, by string, now time.Time) error {
	res, err := s.db.ExecContext(ctx, revokeAgent, unix(now), nullString(by), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) oneAgent(row *sql.Row) (*Agent, error) {
	a, err := scanAgent(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return a, err
}

func scanAgent(row interface{ Scan(...any) error }) (*Agent, error) {
	var a Agent
	var key []byte
	var enrolled int64
	var revoked, lastReport sql.NullInt64
	err := row.Scan(&a.ID, &key, &a.Hostname, &a.AgentVersion, &enrolled, &a.EnrolledFromIP,
		&revoked, &a.LastSequence, &a.LastRequestID, &lastReport)
	if err != nil {
		return nil, err
	}
	a.PublicKey = ed25519.PublicKey(key)
	a.EnrolledAt = time.Unix(enrolled, 0).UTC()
	a.RevokedAt = fromUnix(revoked)
	a.LastReportAt = fromUnix(lastReport)
	return &a, nil
}

func nullString(s string) sql.NullString {
	return sql.NullString{String: s, Valid: s != ""}
}
