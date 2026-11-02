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
	-- The lowest severity the user's pages show; less severe findings are
	-- still stored, and listed apart.
	min_severity   TEXT    NOT NULL DEFAULT 'low' CHECK (min_severity IN ('critical', 'high', 'medium', 'low', 'negligible')),
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

-- Vulnerabilities the owner has accepted on one server's host or image, with
-- a reason, until expires_at. An accepted finding does not count towards the
-- server's status and raises no emergency; once expired, it counts again.
-- Rows outlive the findings, so that a finding that comes back is still
-- accepted.
CREATE TABLE accepted_risks (
	agent_id      TEXT    NOT NULL REFERENCES agents (id) ON DELETE CASCADE,
	target        TEXT    NOT NULL CHECK (length(target) BETWEEN 1 AND 128),
	vulnerability TEXT    NOT NULL CHECK (length(vulnerability) BETWEEN 1 AND 128),
	reason        TEXT    NOT NULL CHECK (length(reason) BETWEEN 1 AND 1000),
	accepted_by   TEXT    REFERENCES users (id) ON DELETE SET NULL,
	accepted_at   INTEGER NOT NULL,
	expires_at    INTEGER NOT NULL CHECK (expires_at > accepted_at),
	PRIMARY KEY (agent_id, target, vulnerability)
) STRICT;

-- Where alerts and digests go. settings holds the channel's ordinary fields as
-- a JSON object; secrets holds its passwords, tokens and secret URLs, sealed
-- with a key derived from the dashboard's identity key, never in plain text.
CREATE TABLE channels (
	id          TEXT    NOT NULL PRIMARY KEY CHECK (length(id) = 26),
	type        TEXT    NOT NULL CHECK (type IN ('email', 'ntfy', 'discord', 'slack', 'webhook')),
	name        TEXT    NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
	settings    TEXT    NOT NULL CHECK (json_valid(settings) AND json_type(settings) = 'object'),
	secrets     BLOB    NOT NULL,
	emergencies INTEGER NOT NULL CHECK (emergencies IN (0, 1)),
	digest      INTEGER NOT NULL CHECK (digest IN (0, 1)),
	created_at  INTEGER NOT NULL,
	updated_at  INTEGER NOT NULL
) STRICT;

-- The one row of alert settings, which decide what is worth sending.
--
-- A vulnerability with a fix is an emergency when it is known to be
-- exploited (if emergency_known_exploited), or when its CVSS score reaches
-- emergency_min_cvss (NULL: never by score).
--
-- digest_weekday is 0 (Sunday) to 6, or NULL for no digest; digest_minute is
-- minutes after midnight in digest_timezone. digest_sent_at is NULL until the
-- first digest is due. The digest_* flags choose its sections;
-- digest_new_min_severity is the lowest severity of the new vulnerabilities
-- it lists, NULL for none. digest_accepted lists the accepted risks that
-- expired since the last digest or expire within a week. Without
-- digest_all_clear, a digest with nothing to say is not sent.
CREATE TABLE alert_settings (
	id                        INTEGER NOT NULL PRIMARY KEY CHECK (id = 1),
	emergency_known_exploited INTEGER NOT NULL CHECK (emergency_known_exploited IN (0, 1)),
	emergency_min_cvss        REAL    CHECK (emergency_min_cvss BETWEEN 0.1 AND 10),
	reminder_days             INTEGER NOT NULL CHECK (reminder_days BETWEEN 1 AND 365),
	digest_weekday            INTEGER CHECK (digest_weekday BETWEEN 0 AND 6),
	digest_minute             INTEGER NOT NULL CHECK (digest_minute BETWEEN 0 AND 1439),
	digest_timezone           TEXT    NOT NULL CHECK (length(digest_timezone) BETWEEN 1 AND 64),
	digest_sent_at            INTEGER,
	digest_emergencies        INTEGER NOT NULL CHECK (digest_emergencies IN (0, 1)),
	digest_stale              INTEGER NOT NULL CHECK (digest_stale IN (0, 1)),
	digest_updates            INTEGER NOT NULL CHECK (digest_updates IN (0, 1)),
	digest_new_min_severity   TEXT    CHECK (digest_new_min_severity IN ('critical', 'high', 'medium', 'low', 'negligible')),
	digest_accepted           INTEGER NOT NULL CHECK (digest_accepted IN (0, 1)),
	digest_all_clear          INTEGER NOT NULL CHECK (digest_all_clear IN (0, 1))
) STRICT;

INSERT INTO alert_settings (id, emergency_known_exploited, emergency_min_cvss, reminder_days,
	digest_weekday, digest_minute, digest_timezone,
	digest_emergencies, digest_stale, digest_updates, digest_new_min_severity, digest_accepted, digest_all_clear)
VALUES (1, 1, 9.0, 7, 1, 480, 'UTC', 1, 1, 1, 'medium', 1, 1);

-- The alerts raised, so that each is sent once: an emergency per (server,
-- vulnerability), or a server gone stale (vulnerability ''). notified_at is
-- NULL until it has been sent, or dropped for want of a channel, and moves on
-- with each reminder. A row is deleted when its cause goes away.
CREATE TABLE alerts (
	agent_id      TEXT    NOT NULL REFERENCES agents (id) ON DELETE CASCADE,
	kind          TEXT    NOT NULL CHECK (kind IN ('emergency', 'stale')),
	vulnerability TEXT    NOT NULL,
	raised_at     INTEGER NOT NULL,
	notified_at   INTEGER,
	CHECK ((kind = 'stale') = (vulnerability = '')),
	PRIMARY KEY (agent_id, kind, vulnerability)
) STRICT;
