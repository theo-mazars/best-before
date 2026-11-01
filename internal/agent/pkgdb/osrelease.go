package pkgdb

import (
	"bufio"
	"io"
	"strconv"
	"strings"

	"github.com/theo-mazars/best-before/internal/report"
)

// ParseOSRelease parses an os-release file (KEY=value lines, values
// optionally quoted).
func ParseOSRelease(r io.Reader) (report.OS, error) {
	fields := map[string]string{}
	sc := bufio.NewScanner(r)
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
