-- Conventions: STRICT tables, random 26-character IDs, NOT NULL primary keys
-- (SQLite allows NULL otherwise), times in Unix seconds (UTC), and no
-- privileged defaults.

CREATE TABLE users (
	id            TEXT    NOT NULL PRIMARY KEY CHECK (length(id) = 26),
	email         TEXT    NOT NULL UNIQUE COLLATE NOCASE CHECK (length(email) BETWEEN 3 AND 254 AND instr(email, '@') > 1),
	password_hash TEXT    NOT NULL,
	totp_secret   BLOB    CHECK (totp_secret IS NULL OR length(totp_secret) = 20),
	role          TEXT    NOT NULL CHECK (role IN ('admin', 'user')),
	created_at    INTEGER NOT NULL
) STRICT;

CREATE TABLE agents (
	id               TEXT    NOT NULL PRIMARY KEY CHECK (length(id) = 26),
	public_key       BLOB    NOT NULL UNIQUE CHECK (length(public_key) = 32),
	hostname         TEXT    NOT NULL CHECK (length(hostname) BETWEEN 1 AND 253),
	agent_version    TEXT    NOT NULL CHECK (length(agent_version) <= 64),
	enrolled_at      INTEGER NOT NULL,
	enrolled_from_ip TEXT    NOT NULL,
	revoked_at       INTEGER,
	revoked_by       TEXT    REFERENCES users (id),
	last_sequence    INTEGER NOT NULL DEFAULT 0 CHECK (last_sequence >= 0),
	last_request_id  BLOB    CHECK (last_request_id IS NULL OR length(last_request_id) = 32),
	last_report_at   INTEGER,
	CHECK (revoked_by IS NULL OR revoked_at IS NOT NULL)
) STRICT;

CREATE TABLE enrolment_codes (
	id          TEXT    NOT NULL PRIMARY KEY CHECK (length(id) = 26),
	secret_hash BLOB    NOT NULL UNIQUE CHECK (length(secret_hash) = 32),
	created_by  TEXT    REFERENCES users (id),
	created_at  INTEGER NOT NULL,
	expires_at  INTEGER NOT NULL CHECK (expires_at > created_at),
	used_at     INTEGER,
	agent_id    TEXT    UNIQUE REFERENCES agents (id),
	CHECK ((used_at IS NULL) = (agent_id IS NULL))
) STRICT;

CREATE TABLE latest_reports (
	agent_id    TEXT    NOT NULL PRIMARY KEY REFERENCES agents (id),
	received_at INTEGER NOT NULL,
	sequence    INTEGER NOT NULL CHECK (sequence > 0),
	body        TEXT    NOT NULL CHECK (json_valid(body))
) STRICT;
