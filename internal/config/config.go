// Package config reads "key = value" files. Inline comments need white space
// before '#'. Unknown and repeated keys are errors, so a typo never silently
// falls back to a default.
package config

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
)

type Values map[string]string

func Load(path string, allowed ...string) (Values, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	v, err := Parse(f, allowed...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return v, nil
}

func Parse(r io.Reader, allowed ...string) (Values, error) {
	known := map[string]bool{}
	for _, k := range allowed {
		known[k] = true
	}

	v := Values{}
	sc := bufio.NewScanner(r)
	for n := 1; sc.Scan(); n++ {
		line := sc.Text()
		if i := strings.Index(line, "#"); i == 0 || (i > 0 && (line[i-1] == ' ' || line[i-1] == '\t')) {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		switch {
		case !ok || key == "":
			return nil, fmt.Errorf("line %d: expected key = value", n)
		case !known[key]:
			return nil, fmt.Errorf("line %d: unknown setting %q", n, key)
		}
		if _, seen := v[key]; seen {
			return nil, fmt.Errorf("line %d: %q is set twice", n, key)
		}
		v[key] = value
	}
	return v, sc.Err()
}

func (v Values) Get(key, def string) string {
	if s, ok := v[key]; ok && s != "" {
		return s
	}
	return def
}
