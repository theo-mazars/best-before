package store

import (
	"context"
	"time"
)

// AcceptedRisk is a vulnerability accepted on one server's host or image,
// until ExpiresAt.
type AcceptedRisk struct {
	AgentID       string
	Target        string // "host" or an image ID
	Vulnerability string
	Reason        string
	// AcceptedBy is the email of whoever accepted it, empty once they are
	// deleted.
	AcceptedBy string
	AcceptedAt time.Time
	ExpiresAt  time.Time
}

// Active says whether the risk is still accepted at now.
func (r *AcceptedRisk) Active(now time.Time) bool { return now.Before(r.ExpiresAt) }

const (
	selectRisks = `SELECT r.agent_id, r.target, r.vulnerability, r.reason, coalesce(u.email, ''), r.accepted_at,
		r.expires_at FROM accepted_risks r LEFT JOIN users u ON u.id = r.accepted_by WHERE r.agent_id = ?`
	// Accepting again replaces the reason and the expiry.
	upsertRisk = `INSERT INTO accepted_risks (agent_id, target, vulnerability, reason, accepted_by, accepted_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (agent_id, target, vulnerability) DO UPDATE SET reason = excluded.reason,
			accepted_by = excluded.accepted_by, accepted_at = excluded.accepted_at, expires_at = excluded.expires_at`
	deleteRisk = `DELETE FROM accepted_risks WHERE agent_id = ? AND target = ? AND vulnerability = ?`
)

// AcceptedRisks lists an agent's accepted risks, expired ones included.
func (s *Store) AcceptedRisks(ctx context.Context, agentID string) ([]AcceptedRisk, error) {
	rows, err := s.db.QueryContext(ctx, selectRisks, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AcceptedRisk
	for rows.Next() {
		var r AcceptedRisk
		var accepted, expires int64
		if err := rows.Scan(&r.AgentID, &r.Target, &r.Vulnerability, &r.Reason, &r.AcceptedBy, &accepted, &expires); err != nil {
			return nil, err
		}
		r.AcceptedAt = time.Unix(accepted, 0).UTC()
		r.ExpiresAt = time.Unix(expires, 0).UTC()
		out = append(out, r)
	}
	return out, rows.Err()
}

// AcceptRisk accepts a vulnerability on an agent's target until expires,
// replacing any earlier acceptance of it.
func (s *Store) AcceptRisk(ctx context.Context, agentID, target, vulnerability, reason, userID string, now, expires time.Time) error {
	_, err := s.db.ExecContext(ctx, upsertRisk, agentID, target, vulnerability, reason, nullString(userID), unix(now), unix(expires))
	return err
}

// WithdrawRisk ends the acceptance of a vulnerability at once.
func (s *Store) WithdrawRisk(ctx context.Context, agentID, target, vulnerability string) error {
	return oneRow(s.db.ExecContext(ctx, deleteRisk, agentID, target, vulnerability))
}
