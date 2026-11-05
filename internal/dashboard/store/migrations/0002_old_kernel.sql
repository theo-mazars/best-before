-- old_kernel marks a finding in a kernel package installed on the host but
-- not running, e.g. linux-image-6.8.0-50-generic while 6.8.0-60 runs. Such
-- findings are shown muted and count towards nothing: no status, no alert,
-- no digest.
ALTER TABLE findings ADD COLUMN old_kernel INTEGER NOT NULL DEFAULT 0 CHECK (old_kernel IN (0, 1));
