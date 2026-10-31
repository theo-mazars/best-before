-- Conventions: STRICT tables, random 26-character IDs, NOT NULL primary keys
-- (SQLite allows NULL otherwise), times in Unix seconds (UTC), and no
-- privileged defaults.

CREATE TABLE users (
	id             TEXT    NOT NULL PRIMARY KEY CHECK (length(id) = 26),
	email          TEXT    NOT NULL UNIQUE COLLATE NOCASE CHECK (length(email) BETWEEN 3 AND 254 AND instr(email, '@') > 1),
	password_hash  TEXT    NOT NULL,
	totp_secret    BLOB    CHECK (totp_secret IS NULL OR length(totp_secret) = 20),
	totp_last_step INTEGER NOT NULL DEFAULT 0,
	role           TEXT    NOT NULL CHECK (role IN ('admin', 'user')),
	created_at     INTEGER NOT NULL
) STRICT;

-- Only the hash of a session token is stored.
CREATE TABLE sessions (
	token_hash   BLOB    NOT NULL PRIMARY KEY CHECK (length(token_hash) = 32),
	user_id      TEXT    NOT NULL REFERENCES users (id) ON DELETE CASCADE,
	created_at   INTEGER NOT NULL,
	last_seen_at INTEGER NOT NULL,
	expires_at   INTEGER NOT NULL CHECK (expires_at > created_at)
) STRICT;

CREATE INDEX sessions_user_id ON sessions (user_id);
CREATE INDEX sessions_expires_at ON sessions (expires_at);

CREATE TABLE agents (
	id               TEXT    NOT NULL PRIMARY KEY CHECK (length(id) = 26),
	public_key       BLOB    NOT NULL UNIQUE CHECK (length(public_key) = 32),
	hostname         TEXT    NOT NULL CHECK (length(hostname) BETWEEN 1 AND 253),
	agent_version    TEXT    NOT NULL CHECK (length(agent_version) <= 64),
	enrolled_at      INTEGER NOT NULL,
	enrolled_from_ip TEXT    NOT NULL,
	revoked_at       INTEGER,
	revoked_by       TEXT    REFERENCES users (id) ON DELETE SET NULL,
	last_sequence    INTEGER NOT NULL DEFAULT 0 CHECK (last_sequence >= 0),
	last_request_id  BLOB    CHECK (last_request_id IS NULL OR length(last_request_id) = 32),
	last_report_at   INTEGER,
	CHECK (revoked_by IS NULL OR revoked_at IS NOT NULL)
) STRICT;

CREATE TABLE enrolment_codes (
	id          TEXT    NOT NULL PRIMARY KEY CHECK (length(id) = 26),
	secret_hash BLOB    NOT NULL UNIQUE CHECK (length(secret_hash) = 32),
	created_by  TEXT    REFERENCES users (id) ON DELETE SET NULL,
	created_at  INTEGER NOT NULL,
	expires_at  INTEGER NOT NULL CHECK (expires_at > created_at),
	used_at     INTEGER,
	agent_id    TEXT    UNIQUE REFERENCES agents (id),
	CHECK ((used_at IS NULL) = (agent_id IS NULL))
) STRICT;

-- matched_sequence is the report whose inventory the findings below come
-- from; a report is "not checked yet" until it equals sequence.
CREATE TABLE latest_reports (
	agent_id         TEXT    NOT NULL PRIMARY KEY REFERENCES agents (id),
	received_at      INTEGER NOT NULL,
	sequence         INTEGER NOT NULL CHECK (sequence > 0),
	body             TEXT    NOT NULL CHECK (json_valid(body)),
	matched_sequence INTEGER,
	matched_at       INTEGER,
	matched_db_built INTEGER,
	-- Targets whose packages could not be checked, as a JSON object of
	-- target to reason.
	unchecked        TEXT    CHECK (unchecked IS NULL OR json_valid(unchecked)),
	CHECK ((matched_sequence IS NULL) = (matched_at IS NULL))
) STRICT;

-- The vulnerabilities in each agent's latest report. target is 'host' or an
-- image ID. fix_versions is empty when no fix exists: such findings are
-- silent. first_seen_at and fixable_since survive re-matching, so that a new
-- finding, or a fix becoming available, can be told apart.
CREATE TABLE findings (
	agent_id        TEXT    NOT NULL REFERENCES agents (id) ON DELETE CASCADE,
	target          TEXT    NOT NULL CHECK (length(target) BETWEEN 1 AND 128),
	package         TEXT    NOT NULL,
	version         TEXT    NOT NULL,
	kind            TEXT    NOT NULL CHECK (kind IN ('package', 'software')),
	vulnerability   TEXT    NOT NULL,
	severity        TEXT    NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'negligible', 'unknown')),
	cvss            REAL    NOT NULL CHECK (cvss BETWEEN 0 AND 10),
	fix_versions    TEXT    NOT NULL,
	known_exploited INTEGER NOT NULL CHECK (known_exploited IN (0, 1)),
	url             TEXT    NOT NULL,
	first_seen_at   INTEGER NOT NULL,
	fixable_since   INTEGER,
	CHECK ((fixable_since IS NULL) = (fix_versions = '')),
	PRIMARY KEY (agent_id, target, package, vulnerability)
) STRICT;
