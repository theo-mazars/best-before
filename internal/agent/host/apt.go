package host

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/theo-mazars/best-before/internal/report"
)

// simulateUpgrade asks apt which installed packages have a newer candidate.
//
// It runs "apt-get dist-upgrade" in simulation mode, which installs nothing.
// Locking, the binary caches and the solver log are all disabled, so the
// command writes nothing to disk and works on a read-only file system.
// It does not refresh the package lists; that is left to the system's own
// apt-daily timer.
func simulateUpgrade(ctx context.Context, aptGet string) ([]report.UpgradablePackage, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, aptGet,
		"--simulate",
		"--quiet",
		"-o", "Debug::NoLocking=true",
		"-o", "Dir::Cache::pkgcache=",
		"-o", "Dir::Cache::srcpkgcache=",
		"-o", "Dir::Log::Planner=/dev/null",
		"-o", "APT::Get::Show-User-Simulation-Note=false",
		"dist-upgrade",
	)
	cmd.Env = []string{"LC_ALL=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("%v: %s", err, strings.TrimSpace(stderr.String()))
	}
	return parseSimulation(bytes.NewReader(out))
}

// inst matches a simulated upgrade, for example:
//
//	Inst libc6 [2.39-0ubuntu8.3] (2.39-0ubuntu8.4 Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security [arm64])
//
// Lines without a bracketed current version are new packages pulled in as
// dependencies, not upgrades, and are ignored.
var inst = regexp.MustCompile(`^Inst (\S+) \[([^\]]+)\] \((\S+) (.+) \[([^\]]+)\]\)`)

func parseSimulation(r io.Reader) ([]report.UpgradablePackage, error) {
	pkgs := []report.UpgradablePackage{}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		m := inst.FindStringSubmatch(sc.Text())
		if m == nil {
			continue
		}
		name, arch, _ := strings.Cut(m[1], ":") // multi-arch: "libfoo:i386"
		if a := m[5]; a != "" {
			arch = a
		}
		p := report.UpgradablePackage{
			Name:             name,
			Architecture:     arch,
			CurrentVersion:   m[2],
			CandidateVersion: m[3],
			Origins:          []string{},
		}
		for origin := range strings.SplitSeq(m[4], ",") {
			origin = strings.TrimSpace(origin)
			p.Origins = append(p.Origins, origin)
			if isSecurityOrigin(origin) {
				p.Security = true
			}
		}
		pkgs = append(pkgs, p)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}

	// Security updates first, then by name.
	sort.SliceStable(pkgs, func(i, j int) bool {
		if pkgs[i].Security != pkgs[j].Security {
			return pkgs[i].Security
		}
		return pkgs[i].Name < pkgs[j].Name
	})
	return pkgs, nil
}

// isSecurityOrigin reports whether an origin such as
// "Ubuntu:24.04/noble-security" or "UbuntuESMApps:24.04/noble-apps-security"
// is a security pocket.
func isSecurityOrigin(origin string) bool {
	_, archive, _ := strings.Cut(origin, "/")
	return strings.HasSuffix(archive, "-security")
}

// aptListsPublishedAt returns the publication time of the newest Release
// file in the package lists. apt sets each file's modification time to the
// archive's Last-Modified date, not to the time of download.
//
// The modification time of the lists directory is deliberately not used:
// apt touches it on every run, whether or not anything new was downloaded,
// so it cannot tell a working update from a failing one.
func aptListsPublishedAt(listsDir string) *time.Time {
	var newest time.Time
	for _, pattern := range []string{"*_InRelease", "*_Release"} {
		matches, _ := filepath.Glob(filepath.Join(listsDir, pattern))
		for _, m := range matches {
			if info, err := os.Stat(m); err == nil && info.ModTime().After(newest) {
				newest = info.ModTime()
			}
		}
	}
	if newest.IsZero() {
		return nil
	}
	newest = newest.UTC()
	return &newest
}
