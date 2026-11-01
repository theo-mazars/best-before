package pkgdb

import (
	"bufio"
	"io"
	"strings"

	"github.com/theo-mazars/best-before/internal/report"
)

// ParseApkInstalled parses Alpine's /lib/apk/db/installed: one stanza per
// installed package, separated by blank lines, each line a one-letter key, a
// colon and a value. The origin (o:) is the source package Alpine's security
// data refers to.
func ParseApkInstalled(r io.Reader) ([]report.InstalledPackage, error) {
	pkgs := []report.InstalledPackage{}
	var p report.InstalledPackage

	flush := func() {
		if p.Name != "" {
			if p.Source == "" {
				p.Source = p.Name
			}
			p.SourceVersion = p.Version
			pkgs = append(pkgs, p)
		}
		p = report.InstalledPackage{}
	}

	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			flush()
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch key {
		case "P":
			p.Name = value
		case "V":
			p.Version = value
		case "A":
			p.Architecture = value
		case "o":
			p.Source = value
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	flush()

	Sort(pkgs)
	return pkgs, nil
}
