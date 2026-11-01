// Package pkgdb reads the records package managers keep of what they
// installed, for the host and for the inside of images alike.
package pkgdb

import (
	"bufio"
	"io"
	"sort"
	"strings"

	"github.com/theo-mazars/best-before/internal/report"
)

// ParseDpkgStatus parses the dpkg status database (deb822 stanzas separated
// by blank lines) and returns the packages that are actually installed.
func ParseDpkgStatus(r io.Reader) ([]report.InstalledPackage, error) {
	return parseDpkg(r, true)
}

// ParseDpkgStatusD parses one file of /var/lib/dpkg/status.d, where
// distroless images record their packages, one file per package. These
// records have no Status field: everything listed is installed.
func ParseDpkgStatusD(r io.Reader) ([]report.InstalledPackage, error) {
	return parseDpkg(r, false)
}

func parseDpkg(r io.Reader, hasStatus bool) ([]report.InstalledPackage, error) {
	pkgs := []report.InstalledPackage{}
	fields := map[string]string{}

	flush := func() {
		defer clear(fields)
		if fields["Package"] == "" {
			return
		}
		// Status is "<want> <flag> <state>"; only "installed" counts.
		status := strings.Fields(fields["Status"])
		if hasStatus && (len(status) != 3 || status[2] != "installed") {
			return
		}
		p := report.InstalledPackage{
			Name:          fields["Package"],
			Version:       fields["Version"],
			Architecture:  fields["Architecture"],
			Source:        fields["Package"],
			SourceVersion: fields["Version"],
		}
		// Source is "name" or "name (version)" when it differs from the
		// binary package's version.
		if src := fields["Source"]; src != "" {
			name, version, hasVersion := strings.Cut(src, " ")
			p.Source = name
			if hasVersion {
				p.SourceVersion = strings.Trim(strings.TrimSpace(version), "()")
			}
		}
		pkgs = append(pkgs, p)
	}

	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "":
			flush()
		case line[0] == ' ' || line[0] == '\t':
			// Continuation of a multi-line field (Description, Conffiles…);
			// none of the fields we keep span several lines.
		default:
			key, value, ok := strings.Cut(line, ":")
			if ok {
				fields[key] = strings.TrimSpace(value)
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	flush()

	Sort(pkgs)
	return pkgs, nil
}

// Sort orders packages by name, then architecture.
func Sort(pkgs []report.InstalledPackage) {
	sort.Slice(pkgs, func(i, j int) bool {
		if pkgs[i].Name != pkgs[j].Name {
			return pkgs[i].Name < pkgs[j].Name
		}
		return pkgs[i].Architecture < pkgs[j].Architecture
	})
}
