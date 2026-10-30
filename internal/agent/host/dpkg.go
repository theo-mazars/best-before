package host

import (
	"bufio"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/theo-mazars/best-before/internal/report"
)

func readDpkgStatus(path string) ([]report.InstalledPackage, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parseDpkgStatus(f)
}

// parseDpkgStatus parses the dpkg status database (deb822 stanzas separated
// by blank lines) and returns the packages that are actually installed.
func parseDpkgStatus(r io.Reader) ([]report.InstalledPackage, error) {
	pkgs := []report.InstalledPackage{}
	fields := map[string]string{}

	flush := func() {
		defer clear(fields)
		// Status is "<want> <flag> <state>"; only "installed" counts.
		status := strings.Fields(fields["Status"])
		if fields["Package"] == "" || len(status) != 3 || status[2] != "installed" {
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

	sort.Slice(pkgs, func(i, j int) bool {
		if pkgs[i].Name != pkgs[j].Name {
			return pkgs[i].Name < pkgs[j].Name
		}
		return pkgs[i].Architecture < pkgs[j].Architecture
	})
	return pkgs, nil
}
