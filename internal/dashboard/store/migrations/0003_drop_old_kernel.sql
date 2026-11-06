-- Whether a finding is in a kernel installed but not running is now decided
-- when findings are read, from the latest report's running kernel, so that a
-- reboot counts at once and no new matching is needed.
ALTER TABLE findings DROP COLUMN old_kernel;
