package docker

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// goBinary builds the start of an ELF file with a build information block at
// offset (16-aligned), as Go 1.18 and later write it, or the older layout
// when version is "".
func goBinary(version string, offset int) []byte {
	b := append([]byte("\x7fELF"), make([]byte, offset-4)...)
	hdr := make([]byte, goBuildInfoHeader)
	copy(hdr, goBuildInfoMagic)
	hdr[14] = 8
	if version != "" {
		hdr[15] = goFlagVersionInl
	}
	b = append(b, hdr...)
	if version != "" {
		b = binary.AppendUvarint(b, uint64(len(version)))
		b = append(b, version...)
		b = binary.AppendUvarint(b, 0)
	}
	return append(b, make([]byte, 100)...)
}

// constantThenBlock is a program with the magic as a constant, aligned, then
// its real build information block.
func constantThenBlock() []byte {
	b := goBinary("go1.25.3", 4096)
	copy(b[32:], append(goBuildInfoMagic, "garbage follows the constant"...))
	return b
}

func TestGoVersionSynthetic(t *testing.T) {
	// The magic as a constant in the program's data: not followed by a
	// valid header, so it does not count.
	constant := append([]byte("\x7fELF"), make([]byte, 28)...)
	constant = append(constant, goBuildInfoMagic...)
	constant = append(constant, "garbage follows the constant"...)

	for name, tc := range map[string]struct {
		data []byte
		want string
		err  error
	}{
		"Go 1.23":             {goBinary("go1.23.4", 4096), "go1.23.4", nil},
		"FIPS build":          {goBinary("go1.24.2 X:boringcrypto", 64), "go1.24.2 X:boringcrypto", nil},
		"before Go 1.18":      {goBinary("", 4096), "", nil},
		"across a chunk":      {goBinary("go1.22.0", goChunk-16), "go1.22.0", nil},
		"just past a chunk":   {goBinary("go1.22.0", goChunk+16), "go1.22.0", nil},
		"constant then block": {constantThenBlock(), "go1.25.3", nil},
		"unaligned":           {append([]byte("\x7fELF\x00\x00\x00"), goBinary("go1.23.4", 4096)[4:]...), "", errNotGo},
		"not a version":       {goBinary("hello", 4096), "", errNotGo},
		"C program":           {append([]byte("\x7fELF"), make([]byte, 5000)...), "", errNotGo},
		"constant only":       {constant, "", errNotGo},
	} {
		v, err := goVersion(bytes.NewReader(tc.data))
		if v != tc.want || !errors.Is(err, tc.err) {
			t.Errorf("%s: got %q, %v; want %q, %v", name, v, err, tc.want, tc.err)
		}
	}
}

// TestGoVersionRealPrograms reads real Go programs: this test binary, and
// the go command, which contains the magic as a constant too.
func TestGoVersionRealPrograms(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	programs := []string{self}
	if goCmd, err := exec.LookPath("go"); err == nil {
		// The toolchain actually in use, which may differ from the one on
		// PATH when go.mod asks for a newer one.
		out, _ := exec.Command(goCmd, "env", "GOROOT").Output()
		programs = append(programs, filepath.Join(strings.TrimSpace(string(out)), "bin", "go"))
	}
	for _, p := range programs {
		f, err := os.Open(p)
		if err != nil {
			t.Fatal(err)
		}
		v, err := goVersion(f)
		f.Close()
		// On macOS these are Mach-O rather than ELF; goVersion does not
		// mind, only the layer reader checks for ELF.
		if err != nil || !strings.HasPrefix(v, "go1.") {
			t.Errorf("%s: got %q, %v", p, v, err)
		}
		if p == self && v != runtime.Version() {
			t.Errorf("test binary: got %q, want %q", v, runtime.Version())
		}
	}
}

func TestGoProgramsInLayers(t *testing.T) {
	traefik := goBinary("go1.23.4", 4096)
	base := tarOf(t,
		entry{name: "usr/local/bin/traefik", body: string(traefik), mode: 0o755},
		entry{name: "usr/local/bin/gosu", body: string(goBinary("go1.24.6", 4096)), mode: 0o755},
		entry{name: "usr/local/bin/old", body: string(goBinary("", 4096)), mode: 0o755},
		entry{name: "usr/local/bin/tool", body: string(goBinary("go1.20.1", 4096)), mode: 0o755},
		// Not executable: a Go program's file sitting in the image is not run.
		entry{name: "srv/data.bin", body: string(goBinary("go1.21.0", 4096)), mode: 0o644},
		entry{name: "usr/bin/ls", body: "\x7fELF" + strings.Repeat("\x00", 2000), mode: 0o755},
	)
	upper := tarOf(t,
		// Removed, and replaced by a C program.
		entry{name: "usr/local/bin/.wh.gosu"},
		entry{name: "usr/local/bin/tool", body: "\x7fELF" + strings.Repeat("\x00", 2000), mode: 0o755},
	)
	data := exportOf(t, map[string][]byte{"blobs/sha256/l1": base, "blobs/sha256/l2": upper}, nil,
		manifest{Layers: []string{"blobs/sha256/l1", "blobs/sha256/l2"}})
	s, err := readTestExport(t, data, amd64)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, p := range s.GoPrograms {
		got = append(got, p.Path+"="+p.GoVersion)
	}
	want := []string{"/usr/local/bin/old=", "/usr/local/bin/traefik=go1.23.4"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("got %v, want %v", got, want)
	}
}

func FuzzGoVersion(f *testing.F) {
	f.Add(goBinary("go1.23.4", 64))
	f.Add(goBinary("", 64))
	f.Fuzz(func(t *testing.T, data []byte) {
		v, err := goVersion(bytes.NewReader(data))
		if err == nil && v != "" && !goVersionPattern.MatchString(v) {
			t.Errorf("invalid version %q accepted", v)
		}
	})
}
