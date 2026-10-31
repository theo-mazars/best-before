package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

const (
	RoleAdmin = "admin"
	RoleUser  = "user"
)

var (
	ErrEmailTaken   = errors.New("a user with this email already exists")
	ErrTOTPReplayed = errors.New("this code has already been used")
	ErrLastAdmin    = errors.New("this is the last admin; add another admin first")
	ErrSetupDone    = errors.New("the dashboard already has users")
)

type User struct {
	ID           string
	Email        string
	PasswordHash string
	TOTPSecret   []byte
	Role         string
	CreatedAt    time.Time
}

type Session struct {
	User      User
	ExpiresAt time.Time
}

const (
	insertUser = `INSERT INTO users (id, email, password_hash, totp_secret, role, created_at)
		VALUES (?, ?, ?, ?, ?, ?)`
	selectUsers       = `SELECT id, email, password_hash, totp_secret, role, created_at FROM users`
	selectUserByEmail = selectUsers + ` WHERE email = ?`
	selectUserByID    = selectUsers + ` WHERE id = ?`
	selectAllUsers    = selectUsers + ` ORDER BY email`
	countUsers        = `SELECT count(*) FROM users`
	countOtherAdmins  = `SELECT count(*) FROM users WHERE role = 'admin' AND id != ?`
	updateUserRole    = `UPDATE users SET role = ? WHERE id = ?`
	updatePassword    = `UPDATE users SET password_hash = ? WHERE id = ?`
	updateTOTP        = `UPDATE users SET totp_secret = ?, totp_last_step = ? WHERE id = ?`
	deleteUser        = `DELETE FROM users WHERE id = ?`
	deleteUserSession = `DELETE FROM sessions WHERE user_id = ?`
	// One statement, so the same code cannot pass twice concurrently.
	useTOTPStep = `UPDATE users SET totp_last_step = ? WHERE id = ? AND totp_last_step < ?`

	insertSession = `INSERT INTO sessions (token_hash, user_id, created_at, last_seen_at, expires_at)
		VALUES (?, ?, ?, ?, ?)`
	// The idle timeout is checked against last_seen_at; expires_at is absolute.
	touchSession = `UPDATE sessions SET last_seen_at = ?
		WHERE token_hash = ? AND expires_at > ? AND last_seen_at > ?
		RETURNING user_id, expires_at`
	deleteSession         = `DELETE FROM sessions WHERE token_hash = ?`
	deleteExpiredSessions = `DELETE FROM sessions WHERE expires_at <= ? OR last_seen_at <= ?`
)

func (s *Store) CreateUser(ctx context.Context, email, passwordHash, role string, totpSecret []byte, now time.Time) (*User, error) {
	u := User{ID: newID(), Email: email, PasswordHash: passwordHash, TOTPSecret: totpSecret, Role: role, CreatedAt: now.UTC().Truncate(time.Second)}
	_, err := s.db.ExecContext(ctx, insertUser, u.ID, u.Email, u.PasswordHash, u.TOTPSecret, u.Role, unix(now))
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed: users.email") {
			return nil, ErrEmailTaken
		}
		return nil, err
	}
	return &u, nil
}

func (s *Store) CountUsers(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, countUsers).Scan(&n)
	return n, err
}

// CreateFirstAdmin creates the first user, as an admin with a confirmed TOTP
// step. The check that no user exists is in the same transaction, so two
// concurrent setups cannot both succeed.
func (s *Store) CreateFirstAdmin(ctx context.Context, email, passwordHash string, totpSecret []byte, step uint64, now time.Time) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		var n int
		if err := tx.QueryRowContext(ctx, countUsers).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			return ErrSetupDone
		}
		id := newID()
		if _, err := tx.ExecContext(ctx, insertUser, id, email, passwordHash, totpSecret, RoleAdmin, unix(now)); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, useTOTPStep, step, id, step)
		return err
	})
}

func (s *Store) UserByEmail(ctx context.Context, email string) (*User, error) {
	return scanUser(s.db.QueryRowContext(ctx, selectUserByEmail, email))
}

func (s *Store) UserByID(ctx context.Context, id string) (*User, error) {
	return scanUser(s.db.QueryRowContext(ctx, selectUserByID, id))
}

// UseTOTPStep records a verified code's time step, refusing one already used.
func (s *Store) UseTOTPStep(ctx context.Context, userID string, step uint64) error {
	res, err := s.db.ExecContext(ctx, useTOTPStep, step, userID, step)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrTOTPReplayed
	}
	return nil
}

func (s *Store) CreateSession(ctx context.Context, tokenHash []byte, userID string, now, expires time.Time) error {
	_, err := s.db.ExecContext(ctx, insertSession, tokenHash, userID, unix(now), unix(now), unix(expires))
	return err
}

// TouchSession returns the session's user if the session is neither expired
// nor idle for longer than idle, and records the activity.
func (s *Store) TouchSession(ctx context.Context, tokenHash []byte, now time.Time, idle time.Duration) (*Session, error) {
	var userID string
	var expires int64
	err := s.db.QueryRowContext(ctx, touchSession, unix(now), tokenHash, unix(now), unix(now.Add(-idle))).Scan(&userID, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	u, err := s.UserByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	return &Session{User: *u, ExpiresAt: time.Unix(expires, 0).UTC()}, nil
}

func (s *Store) DeleteSession(ctx context.Context, tokenHash []byte) error {
	_, err := s.db.ExecContext(ctx, deleteSession, tokenHash)
	return err
}

func (s *Store) DeleteExpiredSessions(ctx context.Context, now time.Time, idle time.Duration) error {
	_, err := s.db.ExecContext(ctx, deleteExpiredSessions, unix(now), unix(now.Add(-idle)))
	return err
}

func (s *Store) Users(ctx context.Context) ([]User, error) {
	rows, err := s.db.QueryContext(ctx, selectAllUsers)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, *u)
	}
	return users, rows.Err()
}

// The changes below also end every session of the user, so that they take
// effect at once.

func (s *Store) SetUserRole(ctx context.Context, id, role string) error {
	return s.changeUser(ctx, id, role != RoleAdmin, func(tx *sql.Tx) (sql.Result, error) {
		return tx.ExecContext(ctx, updateUserRole, role, id)
	})
}

func (s *Store) SetPasswordHash(ctx context.Context, id, hash string) error {
	return s.changeUser(ctx, id, false, func(tx *sql.Tx) (sql.Result, error) {
		return tx.ExecContext(ctx, updatePassword, hash, id)
	})
}

func (s *Store) SetTOTP(ctx context.Context, id string, secret []byte, step uint64) error {
	return s.changeUser(ctx, id, false, func(tx *sql.Tx) (sql.Result, error) {
		return tx.ExecContext(ctx, updateTOTP, secret, step, id)
	})
}

func (s *Store) DeleteUser(ctx context.Context, id string) error {
	return s.changeUser(ctx, id, true, func(tx *sql.Tx) (sql.Result, error) {
		return tx.ExecContext(ctx, deleteUser, id)
	})
}

// changeUser applies change to one user and ends their sessions. If
// removesAdmin, it refuses to leave the dashboard without an admin; the check
// is in the same transaction as the change.
func (s *Store) changeUser(ctx context.Context, id string, removesAdmin bool, change func(*sql.Tx) (sql.Result, error)) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		if removesAdmin {
			var others int
			if err := tx.QueryRowContext(ctx, countOtherAdmins, id).Scan(&others); err != nil {
				return err
			}
			u, err := scanUser(tx.QueryRowContext(ctx, selectUserByID, id))
			if err != nil {
				return err
			}
			if u.Role == RoleAdmin && others == 0 {
				return ErrLastAdmin
			}
		}
		res, err := change(tx)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotFound
		}
		_, err = tx.ExecContext(ctx, deleteUserSession, id)
		return err
	})
}

func scanUser(row interface{ Scan(...any) error }) (*User, error) {
	var u User
	var created int64
	err := row.Scan(&u.ID, &u.Email, &u.PasswordHash, &u.TOTPSecret, &u.Role, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	u.CreatedAt = time.Unix(created, 0).UTC()
	return &u, nil
}
