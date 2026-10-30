// Package host collects information about the server itself: operating
// system, kernel, uptime, reboot status and APT packages.
//
// Everything here is read-only. Files are only read, and apt-get is only run
// in simulation mode with locking and cache writes disabled.
package host

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strconv"
	"strings"

	"github.com/theo-mazars/best-before/internal/report"
)

// Paths lists the files the collector reads. Tests point them elsewhere.
type Paths struct {
	OSRelease          string
	KernelRelease      string
	Uptime             string
	RebootRequired     string
	RebootRequiredPkgs string
	DpkgStatus         string
	APTListsDir        string
	APTGet             string
}

// DefaultPaths are the standard locations on Ubuntu.
var DefaultPaths = Paths{
	OSRelease:          "/etc/os-release",
	KernelRelease:      "/proc/sys/kernel/osrelease",
	Uptime:             "/proc/uptime",
	RebootRequired:     "/var/run/reboot-required",
	RebootRequiredPkgs: "/var/run/reboot-required.pkgs",
	DpkgStatus:         "/var/lib/dpkg/status",
	APTListsDir:        "/var/lib/apt/lists",
	APTGet:             "/usr/bin/apt-get",
}

// Collect gathers host information. It never fails as a whole: anything that
// cannot be read is recorded in Host.Errors so that the gap is visible.
func Collect(ctx context.Context, p Paths) report.Host {
	h := report.Host{
		RebootRequiredPackages: []string{},
		Errors:                 []string{},
		APT: report.APT{
			Installed:  []report.InstalledPackage{},
			Upgradable: []report.UpgradablePackage{},
		},
	}
	fail := func(what string, err error) {
		h.Errors = append(h.Errors, fmt.Sprintf("%s: %v", what, err))
	}

	var err error
	if h.Hostname, err = os.Hostname(); err != nil {
		fail("hostname", err)
	}
	if h.OS, err = readOSRelease(p.OSRelease); err != nil {
		fail("os-release", err)
	}
	if h.Kernel, err = readFirstLine(p.KernelRelease); err != nil {
		fail("kernel", err)
	}
	if h.UptimeSeconds, err = readUptime(p.Uptime); err != nil {
		fail("uptime", err)
	}

	if _, err := os.Stat(p.RebootRequired); err == nil {
		h.RebootRequired = true
		pkgs, err := readLines(p.RebootRequiredPkgs)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			fail("reboot-required packages", err)
		}
		h.RebootRequiredPackages = append(h.RebootRequiredPackages, dedupe(pkgs)...)
	} else if !errors.Is(err, fs.ErrNotExist) {
		fail("reboot-required", err)
	}

	if h.APT.Installed, err = readDpkgStatus(p.DpkgStatus); err != nil {
		fail("dpkg status", err)
		h.APT.Installed = []report.InstalledPackage{}
	}
	h.APT.ListsPublishedAt = aptListsPublishedAt(p.APTListsDir)
	if h.APT.ListsPublishedAt == nil {
		fail("apt lists", errors.New("package lists have never been downloaded; run apt-get update"))
	}
	if h.APT.Upgradable, err = simulateUpgrade(ctx, p.APTGet); err != nil {
		fail("apt upgradable", err)
		h.APT.Upgradable = []report.UpgradablePackage{}
	}

	return h
}

func readOSRelease(path string) (report.OS, error) {
	f, err := os.Open(path)
	if err != nil {
		return report.OS{}, err
	}
	defer f.Close()

	fields := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		key, value, ok := strings.Cut(strings.TrimSpace(sc.Text()), "=")
		if !ok || strings.HasPrefix(key, "#") {
			continue
		}
		if v, err := strconv.Unquote(value); err == nil {
			value = v
		}
		fields[key] = value
	}
	if err := sc.Err(); err != nil {
		return report.OS{}, err
	}
	return report.OS{
		ID:        fields["ID"],
		Name:      fields["PRETTY_NAME"],
		VersionID: fields["VERSION_ID"],
		Codename:  fields["VERSION_CODENAME"],
	}, nil
}

func readUptime(path string) (int64, error) {
	line, err := readFirstLine(path)
	if err != nil {
		return 0, err
	}
	first, _, _ := strings.Cut(line, " ")
	seconds, err := strconv.ParseFloat(first, 64)
	if err != nil {
		return 0, fmt.Errorf("unexpected format %q", line)
	}
	return int64(seconds), nil
}

func readFirstLine(path string) (string, error) {
	lines, err := readLines(path)
	if err != nil {
		return "", err
	}
	if len(lines) == 0 {
		return "", errors.New("file is empty")
	}
	return lines[0], nil
}

// readLines returns the non-empty, trimmed lines of a file.
func readLines(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var lines []string
	for line := range strings.Lines(string(data)) {
		if line = strings.TrimSpace(line); line != "" {
			lines = append(lines, line)
		}
	}
	return lines, nil
}

func dedupe(items []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, item := range items {
		if !seen[item] {
			seen[item] = true
			out = append(out, item)
		}
	}
	return out
}
