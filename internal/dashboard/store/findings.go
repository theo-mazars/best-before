package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// Finding is one vulnerability in one package of an agent's host or images.
type Finding struct {
	Target         string // "host" or an image ID
	Package        string
	Version        string
	Kind           string // "package" or "software"
	Vulnerability  string
	Severity       string
	CVSS           float64
	FixVersions    []string // empty when no fix exists
	KnownExploited bool
	URL            string
	// OldKernel is set by the dashboard, not stored: the package is a
	// kernel installed but not running.
	OldKernel    bool
	FirstSeenAt  time.Time
	FixableSince *time.Time
}

func (f *Finding) Fixable() bool { return len(f.FixVersions) > 0 }

// Report is an agent's latest report, and whether its findings are current.
type Report struct {
	AgentID    string
	ReceivedAt time.Time
	Sequence   uint64
	Body       []byte
	// MatchedAt is nil until the report's inventory has been matched.
	MatchedAt      *time.Time
	MatchedDBBuilt *time.Time
	Matched        bool // the findings come from this report
	// Unchecked says, by target, why packages could not be checked.
	Unchecked map[string]string
}

const (
	selectReports = `SELECT agent_id, received_at, sequence, body, matched_sequence, matched_at, matched_db_built,
		unchecked FROM latest_reports`
	selectReport    = selectReports + ` WHERE agent_id = ?`
	selectKernel    = `SELECT coalesce(json_extract(body, '$.host.kernel'), '') FROM latest_reports WHERE agent_id = ?`
	selectAgentSeqs = `SELECT r.agent_id, r.sequence FROM latest_reports r
		JOIN agents a ON a.id = r.agent_id WHERE a.revoked_at IS NULL`

	selectFindingHistory = `SELECT target, package, vulnerability, first_seen_at, fixable_since
		FROM findings WHERE agent_id = ?`
	deleteFindings = `DELETE FROM findings WHERE agent_id = ?`
	insertFinding  = `INSERT INTO findings (agent_id, target, package, version, kind, vulnerability, severity,
		cvss, fix_versions, known_exploited, url, first_seen_at, fixable_since)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	markMatched = `UPDATE latest_reports SET matched_sequence = ?, matched_at = ?, matched_db_built = ?,
		unchecked = ? WHERE agent_id = ? AND sequence = ?`
	selectFindings = `SELECT target, package, version, kind, vulnerability, severity, cvss, fix_versions,
		known_exploited, url, first_seen_at, fixable_since FROM findings WHERE agent_id = ?
		ORDER BY fix_versions = '', known_exploited DESC,
		CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3
			WHEN 'negligible' THEN 4 ELSE 5 END, cvss DESC, package, vulnerability`
)

// LatestReports returns every agent's latest report.
func (s *Store) LatestReports(ctx context.Context) ([]Report, error) {
	rows, err := s.db.QueryContext(ctx, selectReports)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Report
	for rows.Next() {
		r, err := scanReport(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *r)
	}
	return out, rows.Err()
}

func (s *Store) Report(ctx context.Context, agentID string) (*Report, error) {
	r, err := scanReport(s.db.QueryRowContext(ctx, selectReport, agentID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return r, err
}

func scanReport(row interface{ Scan(...any) error }) (*Report, error) {
	var r Report
	var body string
	var received int64
	var matchedSeq, matchedAt, built sql.NullInt64
	var unchecked sql.NullString
	if err := row.Scan(&r.AgentID, &received, &r.Sequence, &body, &matchedSeq, &matchedAt, &built, &unchecked); err != nil {
		return nil, err
	}
	if unchecked.Valid {
		if err := json.Unmarshal([]byte(unchecked.String), &r.Unchecked); err != nil {
			return nil, err
		}
	}
	r.Body = []byte(body)
	r.ReceivedAt = time.Unix(received, 0).UTC()
	r.MatchedAt = fromUnix(matchedAt)
	r.MatchedDBBuilt = fromUnix(built)
	r.Matched = matchedSeq.Valid && uint64(matchedSeq.Int64) == r.Sequence
	return &r, nil
}

// RunningKernel returns the kernel release in the agent's latest report,
// e.g. 6.8.0-60-generic, or "" before the first report.
func (s *Store) RunningKernel(ctx context.Context, agentID string) (string, error) {
	var k string
	err := s.db.QueryRowContext(ctx, selectKernel, agentID).Scan(&k)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return k, err
}

// ReportSequences lists the latest report of every agent not revoked, for
// matching them all again.
func (s *Store) ReportSequences(ctx context.Context) (map[string]uint64, error) {
	rows, err := s.db.QueryContext(ctx, selectAgentSeqs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]uint64{}
	for rows.Next() {
		var id string
		var seq uint64
		if err := rows.Scan(&id, &seq); err != nil {
			return nil, err
		}
		out[id] = seq
	}
	return out, rows.Err()
}

// ReplaceFindings records the findings of the agent's report seq, and the
// targets that could not be checked, keeping when each finding was first
// seen and first fixable. It does nothing if a newer
// report has arrived meanwhile: that one will be matched instead.
func (s *Store) ReplaceFindings(ctx context.Context, agentID string, seq uint64, dbBuilt time.Time, findings []Finding, unchecked map[string]string, now time.Time) error {
	if unchecked == nil {
		unchecked = map[string]string{}
	}
	uncheckedJSON, err := json.Marshal(unchecked)
	if err != nil {
		return err
	}
	return s.tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, markMatched, seq, unix(now), unix(dbBuilt), string(uncheckedJSON), agentID, seq)
		if err != nil {
			return err
		}
		if n, err := res.RowsAffected(); err != nil || n == 0 {
			return err
		}

		type history struct {
			firstSeen    int64
			fixableSince sql.NullInt64
		}
		previous := map[string]history{}
		rows, err := tx.QueryContext(ctx, selectFindingHistory, agentID)
		if err != nil {
			return err
		}
		for rows.Next() {
			var target, pkg, vuln string
			var h history
			if err := rows.Scan(&target, &pkg, &vuln, &h.firstSeen, &h.fixableSince); err != nil {
				rows.Close()
				return err
			}
			previous[target+"\x00"+pkg+"\x00"+vuln] = h
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}

		if _, err := tx.ExecContext(ctx, deleteFindings, agentID); err != nil {
			return err
		}
		for _, f := range findings {
			h, seen := previous[f.Target+"\x00"+f.Package+"\x00"+f.Vulnerability]
			if !seen {
				h.firstSeen = unix(now)
			}
			fixableSince := h.fixableSince
			switch {
			case !f.Fixable():
				fixableSince = sql.NullInt64{}
			case !fixableSince.Valid:
				fixableSince = sql.NullInt64{Int64: unix(now), Valid: true}
			}
			_, err := tx.ExecContext(ctx, insertFinding, agentID, f.Target, f.Package, f.Version, f.Kind,
				f.Vulnerability, f.Severity, f.CVSS, strings.Join(f.FixVersions, ", "), f.KnownExploited,
				f.URL, h.firstSeen, fixableSince)
			if err != nil {
				return err
			}
		}
		return nil
	})
}

// Findings lists an agent's findings, most urgent first: fixable before
// unfixed, known exploited first, then by severity and CVSS score.
func (s *Store) Findings(ctx context.Context, agentID string) ([]Finding, error) {
	rows, err := s.db.QueryContext(ctx, selectFindings, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Finding
	for rows.Next() {
		var f Finding
		var fixes string
		var firstSeen int64
		var fixable sql.NullInt64
		if err := rows.Scan(&f.Target, &f.Package, &f.Version, &f.Kind, &f.Vulnerability, &f.Severity, &f.CVSS,
			&fixes, &f.KnownExploited, &f.URL, &firstSeen, &fixable); err != nil {
			return nil, err
		}
		if fixes != "" {
			f.FixVersions = strings.Split(fixes, ", ")
		}
		f.FirstSeenAt = time.Unix(firstSeen, 0).UTC()
		f.FixableSince = fromUnix(fixable)
		out = append(out, f)
	}
	return out, rows.Err()
}
