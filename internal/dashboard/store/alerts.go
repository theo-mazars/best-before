package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// Channel is where alerts and digests are sent. Settings is a JSON object;
// Secrets is sealed by the dashboard and opaque here.
type Channel struct {
	ID          string
	Type        string
	Name        string
	Settings    []byte
	Secrets     []byte
	Emergencies bool
	Digest      bool
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// AlertSettings decide what is worth sending: which vulnerabilities are
// emergencies, and what the digest says and when.
type AlertSettings struct {
	EmergencyKnownExploited bool
	// EmergencyMinCVSS is nil when no score alone makes an emergency.
	EmergencyMinCVSS *float64
	ReminderDays     int

	// DigestWeekday is nil when no digest is sent.
	DigestWeekday  *time.Weekday
	DigestMinute   int // after midnight
	DigestTimezone string
	DigestSentAt   *time.Time
	// The digest's sections.
	DigestEmergencies bool
	DigestStale       bool
	DigestUpdates     bool
	// DigestNewMinSeverity is the lowest severity of the new vulnerabilities
	// listed, empty for none.
	DigestNewMinSeverity string
	// DigestAllClear sends a digest even with nothing to say.
	DigestAllClear bool
}

// Kinds of alert.
const (
	AlertEmergency = "emergency"
	AlertStale     = "stale"
)

// Alert is an alert raised about a server. Vulnerability is empty for a
// stale server.
type Alert struct {
	AgentID       string
	Kind          string
	Vulnerability string
	RaisedAt      time.Time
	// NotifiedAt is nil until a channel has accepted the alert.
	NotifiedAt *time.Time
}

const (
	selectChannels = `SELECT id, type, name, settings, secrets, emergencies, digest, created_at, updated_at
		FROM channels`
	selectChannel     = selectChannels + ` WHERE id = ?`
	selectAllChannels = selectChannels + ` ORDER BY name, created_at`
	insertChannel     = `INSERT INTO channels (id, type, name, settings, secrets, emergencies, digest, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
	updateChannel = `UPDATE channels SET name = ?, settings = ?, secrets = ?, emergencies = ?, digest = ?,
		updated_at = ? WHERE id = ?`
	deleteChannel = `DELETE FROM channels WHERE id = ?`

	selectAlertSettings = `SELECT emergency_known_exploited, emergency_min_cvss, reminder_days, digest_weekday,
		digest_minute, digest_timezone, digest_sent_at, digest_emergencies, digest_stale, digest_updates,
		digest_new_min_severity, digest_all_clear FROM alert_settings WHERE id = 1`
	updateAlertSettings = `UPDATE alert_settings SET emergency_known_exploited = ?, emergency_min_cvss = ?,
		reminder_days = ?, digest_weekday = ?, digest_minute = ?, digest_timezone = ?, digest_emergencies = ?,
		digest_stale = ?, digest_updates = ?, digest_new_min_severity = ?, digest_all_clear = ? WHERE id = 1`
	updateDigestSent = `UPDATE alert_settings SET digest_sent_at = ? WHERE id = 1`

	selectAlerts = `SELECT agent_id, kind, vulnerability, raised_at, notified_at FROM alerts
		ORDER BY agent_id, kind, vulnerability`
	insertAlert = `INSERT INTO alerts (agent_id, kind, vulnerability, raised_at) VALUES (?, ?, ?, ?)
		ON CONFLICT DO NOTHING`
	updateAlertNotified = `UPDATE alerts SET notified_at = ? WHERE agent_id = ? AND kind = ? AND vulnerability = ?`
	deleteAlert         = `DELETE FROM alerts WHERE agent_id = ? AND kind = ? AND vulnerability = ?`
)

// NewChannelID returns an ID for a channel about to be created: its secrets
// are sealed to it.
func NewChannelID() string { return newID() }

func (s *Store) Channels(ctx context.Context) ([]Channel, error) {
	rows, err := s.db.QueryContext(ctx, selectAllChannels)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Channel
	for rows.Next() {
		c, err := scanChannel(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *c)
	}
	return out, rows.Err()
}

func (s *Store) Channel(ctx context.Context, id string) (*Channel, error) {
	c, err := scanChannel(s.db.QueryRowContext(ctx, selectChannel, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return c, err
}

func scanChannel(row interface{ Scan(...any) error }) (*Channel, error) {
	var c Channel
	var settings string
	var created, updated int64
	if err := row.Scan(&c.ID, &c.Type, &c.Name, &settings, &c.Secrets, &c.Emergencies, &c.Digest, &created, &updated); err != nil {
		return nil, err
	}
	c.Settings = []byte(settings)
	c.CreatedAt = time.Unix(created, 0).UTC()
	c.UpdatedAt = time.Unix(updated, 0).UTC()
	return &c, nil
}

// CreateChannel stores a new channel; its ID comes from NewChannelID.
func (s *Store) CreateChannel(ctx context.Context, c *Channel, now time.Time) error {
	_, err := s.db.ExecContext(ctx, insertChannel, c.ID, c.Type, c.Name, string(c.Settings), c.Secrets,
		c.Emergencies, c.Digest, unix(now), unix(now))
	return err
}

// UpdateChannel changes everything but a channel's type.
func (s *Store) UpdateChannel(ctx context.Context, c *Channel, now time.Time) error {
	res, err := s.db.ExecContext(ctx, updateChannel, c.Name, string(c.Settings), c.Secrets, c.Emergencies,
		c.Digest, unix(now), c.ID)
	return oneRow(res, err)
}

func (s *Store) DeleteChannel(ctx context.Context, id string) error {
	return oneRow(s.db.ExecContext(ctx, deleteChannel, id))
}

func oneRow(res sql.Result, err error) error {
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) AlertSettings(ctx context.Context) (*AlertSettings, error) {
	var a AlertSettings
	var cvss sql.NullFloat64
	var weekday, sent sql.NullInt64
	var severity sql.NullString
	err := s.db.QueryRowContext(ctx, selectAlertSettings).Scan(&a.EmergencyKnownExploited, &cvss, &a.ReminderDays,
		&weekday, &a.DigestMinute, &a.DigestTimezone, &sent, &a.DigestEmergencies, &a.DigestStale, &a.DigestUpdates,
		&severity, &a.DigestAllClear)
	if err != nil {
		return nil, err
	}
	if cvss.Valid {
		a.EmergencyMinCVSS = &cvss.Float64
	}
	if weekday.Valid {
		d := time.Weekday(weekday.Int64)
		a.DigestWeekday = &d
	}
	a.DigestSentAt = fromUnix(sent)
	a.DigestNewMinSeverity = severity.String
	return &a, nil
}

// SetAlertSettings changes the settings, but not when the last digest was
// sent.
func (s *Store) SetAlertSettings(ctx context.Context, a *AlertSettings) error {
	var cvss sql.NullFloat64
	if a.EmergencyMinCVSS != nil {
		cvss = sql.NullFloat64{Float64: *a.EmergencyMinCVSS, Valid: true}
	}
	var weekday sql.NullInt64
	if a.DigestWeekday != nil {
		weekday = sql.NullInt64{Int64: int64(*a.DigestWeekday), Valid: true}
	}
	_, err := s.db.ExecContext(ctx, updateAlertSettings, a.EmergencyKnownExploited, cvss, a.ReminderDays, weekday,
		a.DigestMinute, a.DigestTimezone, a.DigestEmergencies, a.DigestStale, a.DigestUpdates,
		nullString(a.DigestNewMinSeverity), a.DigestAllClear)
	return err
}

func (s *Store) SetDigestSent(ctx context.Context, at time.Time) error {
	_, err := s.db.ExecContext(ctx, updateDigestSent, unix(at))
	return err
}

func (s *Store) Alerts(ctx context.Context) ([]Alert, error) {
	rows, err := s.db.QueryContext(ctx, selectAlerts)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Alert
	for rows.Next() {
		var a Alert
		var raised int64
		var notified sql.NullInt64
		if err := rows.Scan(&a.AgentID, &a.Kind, &a.Vulnerability, &raised, &notified); err != nil {
			return nil, err
		}
		a.RaisedAt = time.Unix(raised, 0).UTC()
		a.NotifiedAt = fromUnix(notified)
		out = append(out, a)
	}
	return out, rows.Err()
}

// RaiseAlert records an alert, unless it is already open.
func (s *Store) RaiseAlert(ctx context.Context, a *Alert) error {
	_, err := s.db.ExecContext(ctx, insertAlert, a.AgentID, a.Kind, a.Vulnerability, unix(a.RaisedAt))
	return err
}

// AlertsNotified records that alerts were sent, or dropped for want of a
// channel, at the given time.
func (s *Store) AlertsNotified(ctx context.Context, alerts []Alert, at time.Time) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		for _, a := range alerts {
			if _, err := tx.ExecContext(ctx, updateAlertNotified, unix(at), a.AgentID, a.Kind, a.Vulnerability); err != nil {
				return err
			}
		}
		return nil
	})
}

// CloseAlert deletes an alert whose cause has gone away.
func (s *Store) CloseAlert(ctx context.Context, a *Alert) error {
	_, err := s.db.ExecContext(ctx, deleteAlert, a.AgentID, a.Kind, a.Vulnerability)
	return err
}
