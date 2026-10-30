package host

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/theo-mazars/best-before/internal/report"
)

func TestParseDpkgStatus(t *testing.T) {
	const status = `Package: libc6
Status: install ok installed
Priority: optional
Architecture: arm64
Multi-Arch: same
Source: glibc
Version: 2.39-0ubuntu8.4
Description: GNU C Library: Shared libraries
 Contains the standard libraries that are used by nearly all programs on
 the system.

Package: removed-but-configured
Status: deinstall ok config-files
Architecture: arm64
Version: 1.0

Package: libssl3t64
Status: hold ok installed
Architecture: arm64
Source: openssl (3.0.13-0ubuntu3.5)
Version: 3.0.13-0ubuntu3.5

Package: bash
Status: install ok installed
Architecture: arm64
Version: 5.2.21-2ubuntu4
Conffiles:
 /etc/bash.bashrc 89269e1298235f1b12b4c16e4065ad0d
`
	got, err := parseDpkgStatus(strings.NewReader(status))
	if err != nil {
		t.Fatal(err)
	}
	want := []report.InstalledPackage{
		{Name: "bash", Version: "5.2.21-2ubuntu4", Architecture: "arm64", Source: "bash", SourceVersion: "5.2.21-2ubuntu4"},
		{Name: "libc6", Version: "2.39-0ubuntu8.4", Architecture: "arm64", Source: "glibc", SourceVersion: "2.39-0ubuntu8.4"},
		{Name: "libssl3t64", Version: "3.0.13-0ubuntu3.5", Architecture: "arm64", Source: "openssl", SourceVersion: "3.0.13-0ubuntu3.5"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got  %+v\nwant %+v", got, want)
	}
}

func TestParseSimulation(t *testing.T) {
	const out = `Reading package lists...
Building dependency tree...
Calculating upgrade...
The following packages will be upgraded:
  base-files libc6 linux-image-generic
3 upgraded, 1 newly installed, 0 to remove and 0 not upgraded.
Inst base-files [13ubuntu10.1] (13ubuntu10.2 Ubuntu:24.04/noble-updates [arm64])
Inst libc6 [2.39-0ubuntu8.3] (2.39-0ubuntu8.4 Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security [arm64])
Inst linux-image-6.8.0-60-generic (6.8.0-60.63 Ubuntu:24.04/noble-updates [arm64])
Inst libfoo:i386 [1.0] (1.1 UbuntuESMApps:24.04/noble-apps-security [i386]) []
Conf base-files (13ubuntu10.2 Ubuntu:24.04/noble-updates [arm64])
`
	got, err := parseSimulation(strings.NewReader(out))
	if err != nil {
		t.Fatal(err)
	}
	want := []report.UpgradablePackage{
		{Name: "libc6", Architecture: "arm64", CurrentVersion: "2.39-0ubuntu8.3", CandidateVersion: "2.39-0ubuntu8.4",
			Origins: []string{"Ubuntu:24.04/noble-updates", "Ubuntu:24.04/noble-security"}, Security: true},
		{Name: "libfoo", Architecture: "i386", CurrentVersion: "1.0", CandidateVersion: "1.1",
			Origins: []string{"UbuntuESMApps:24.04/noble-apps-security"}, Security: true},
		{Name: "base-files", Architecture: "arm64", CurrentVersion: "13ubuntu10.1", CandidateVersion: "13ubuntu10.2",
			Origins: []string{"Ubuntu:24.04/noble-updates"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got  %+v\nwant %+v", got, want)
	}
}

func TestReadOSRelease(t *testing.T) {
	path := writeFile(t, "os-release", `PRETTY_NAME="Ubuntu 24.04.3 LTS"
NAME="Ubuntu"
VERSION_ID="24.04"
VERSION_CODENAME=noble
ID=ubuntu
# a comment
`)
	got, err := readOSRelease(path)
	if err != nil {
		t.Fatal(err)
	}
	want := report.OS{ID: "ubuntu", Name: "Ubuntu 24.04.3 LTS", VersionID: "24.04", Codename: "noble"}
	if got != want {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

// TestCollectReportsGaps checks that missing data is reported as an error
// rather than silently left empty.
func TestCollectReportsGaps(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing")
	p := Paths{
		OSRelease:          writeFile(t, "os-release", "ID=ubuntu\n"),
		KernelRelease:      writeFile(t, "osrelease", "6.8.0-60-generic\n"),
		Uptime:             writeFile(t, "uptime", "12345.67 54321.00\n"),
		RebootRequired:     writeFile(t, "reboot-required", "*** System restart required ***\n"),
		RebootRequiredPkgs: writeFile(t, "reboot-required.pkgs", "linux-base\nlibc6\nlinux-base\n"),
		DpkgStatus:         missing,
		APTListsDir:        dir,
		APTGet:             missing,
	}
	h := Collect(context.Background(), p)

	if h.Kernel != "6.8.0-60-generic" || h.UptimeSeconds != 12345 {
		t.Errorf("kernel %q, uptime %d", h.Kernel, h.UptimeSeconds)
	}
	if !h.RebootRequired || !reflect.DeepEqual(h.RebootRequiredPackages, []string{"linux-base", "libc6"}) {
		t.Errorf("reboot required %v, packages %v", h.RebootRequired, h.RebootRequiredPackages)
	}
	if h.APT.ListsPublishedAt != nil {
		t.Errorf("lists published at %v, want nil", h.APT.ListsPublishedAt)
	}
	for _, prefix := range []string{"dpkg status:", "apt lists:", "apt upgradable:"} {
		if !hasErrorWithPrefix(h.Errors, prefix) {
			t.Errorf("no %q error in %q", prefix, h.Errors)
		}
	}
	if h.APT.Installed == nil || h.APT.Upgradable == nil {
		t.Error("package lists must be empty, not nil, so that they encode as []")
	}
}

func TestAPTListsPublishedAt(t *testing.T) {
	dir := t.TempDir()
	older := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	newer := time.Date(2026, 10, 28, 6, 0, 0, 0, time.UTC)
	touch(t, filepath.Join(dir, "archive.ubuntu.com_ubuntu_dists_noble_InRelease"), older)
	touch(t, filepath.Join(dir, "security.ubuntu.com_ubuntu_dists_noble-security_InRelease"), newer)
	touch(t, filepath.Join(dir, "unrelated_Packages"), newer.Add(time.Hour))

	got := aptListsPublishedAt(dir)
	if got == nil || !got.Equal(newer) {
		t.Errorf("got %v, want %v", got, newer)
	}
}

func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func touch(t *testing.T, path string, mtime time.Time) {
	t.Helper()
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, mtime, mtime); err != nil {
		t.Fatal(err)
	}
}

func hasErrorWithPrefix(errs []string, prefix string) bool {
	for _, e := range errs {
		if strings.HasPrefix(e, prefix) {
			return true
		}
	}
	return false
}
