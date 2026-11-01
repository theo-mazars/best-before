package docker

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/theo-mazars/best-before/internal/report"
)

// entry is one file in a test archive: a regular file (mode 0644 unless
// set), or a symbolic link when link is set.
type entry struct {
	name, body, link string
	mode             int64
}

func tarOf(t *testing.T, entries ...entry) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		mode := e.mode
		if mode == 0 {
			mode = 0o644
		}
		h := &tar.Header{Name: e.name, Mode: mode, Size: int64(len(e.body)), Typeflag: tar.TypeReg}
		if e.link != "" {
			h = &tar.Header{Name: e.name, Mode: 0o777, Linkname: e.link, Typeflag: tar.TypeSymlink}
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(e.body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func gzipped(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write(data)
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

type manifest struct {
	Config string
	Layers []string
}

// exportOf builds a docker save archive. Layers and configs come first and
// manifest.json last, as Docker writes them.
func exportOf(t *testing.T, blobs map[string][]byte, links map[string]string, manifests ...manifest) []byte {
	t.Helper()
	var entries []entry
	for name, data := range blobs {
		entries = append(entries, entry{name: name, body: string(data)})
	}
	for name, target := range links {
		entries = append(entries, entry{name: name, link: target})
	}
	m, err := json.Marshal(manifests)
	if err != nil {
		t.Fatal(err)
	}
	entries = append(entries, entry{name: "manifest.json", body: string(m)})
	return tarOf(t, entries...)
}

func dpkgStanza(name, version string) string {
	return "Package: " + name + "\nStatus: install ok installed\nArchitecture: amd64\nVersion: " + version + "\n\n"
}

func names(pkgs []report.InstalledPackage) []string {
	var out []string
	for _, p := range pkgs {
		out = append(out, p.Name+"="+p.Version)
	}
	return out
}

func readTestExport(t *testing.T, data []byte, want platform) (*report.ImageSystem, error) {
	t.Helper()
	got, err := readExport(bytes.NewReader(data), want)
	if err != nil {
		return nil, err
	}
	return parseSystem(got)
}

var amd64 = platform{"linux", "amd64"}

// TestReadExportLayers covers the legacy layout (a <id>/layer.tar link to the
// blob), gzip-compressed and empty layers, a later layer replacing a file,
// and /etc/os-release replaced by a symbolic link.
func TestReadExportLayers(t *testing.T) {
	base := tarOf(t,
		entry{name: "etc/os-release", body: "ID=ubuntu\nVERSION_ID=\"22.04\"\n"},
		entry{name: "var/lib/dpkg/status", body: dpkgStanza("libc6", "2.35") + dpkgStanza("openssl", "3.0.2")},
		entry{name: "usr/bin/node", body: "not kept"},
	)
	upper := gzipped(t, tarOf(t,
		entry{name: "./var/lib/dpkg/status", body: dpkgStanza("libc6", "2.36") + dpkgStanza("openssl", "3.0.2") + dpkgStanza("curl", "7.88")},
		entry{name: "./etc/os-release", link: "../usr/lib/os-release"},
		entry{name: "./usr/lib/os-release", body: "ID=debian\nVERSION_ID=\"12\"\nVERSION_CODENAME=bookworm\n"},
	))
	data := exportOf(t,
		map[string][]byte{
			"blobs/sha256/l1":  base,
			"blobs/sha256/l2":  upper,
			"blobs/sha256/l3":  make([]byte, 1024), // an empty layer
			"blobs/sha256/cfg": []byte(`{"os":"linux","architecture":"amd64"}`),
		},
		map[string]string{"abc/layer.tar": "../blobs/sha256/l1"},
		manifest{Config: "blobs/sha256/cfg", Layers: []string{"abc/layer.tar", "blobs/sha256/l2", "blobs/sha256/l3"}},
	)

	s, err := readTestExport(t, data, amd64)
	if err != nil {
		t.Fatal(err)
	}
	if s.OS.ID != "debian" || s.OS.VersionID != "12" || s.OS.Codename != "bookworm" {
		t.Errorf("os: %+v", s.OS)
	}
	if s.PackageManager != report.PackageManagerDpkg {
		t.Errorf("package manager %q", s.PackageManager)
	}
	if got, want := names(s.Packages), []string{"curl=7.88", "libc6=2.36", "openssl=3.0.2"}; !reflect.DeepEqual(got, want) {
		t.Errorf("packages %v, want %v", got, want)
	}
}

func TestReadExportWhiteouts(t *testing.T) {
	apk := "P:musl\nV:1.2.5-r0\nA:x86_64\no:musl\n\nP:libcrypto3\nV:3.3.2-r0\nA:x86_64\no:openssl\n\n"
	base := tarOf(t,
		entry{name: "etc/os-release", body: "ID=alpine\nVERSION_ID=3.20.3\n"},
		entry{name: "lib/apk/db/installed", body: apk},
		entry{name: "var/lib/dpkg/status", body: dpkgStanza("leftover", "1")},
	)
	tests := []struct {
		name    string
		upper   []entry
		manager string
		want    []string
	}{
		{"whiteout removes a directory", []entry{{name: "var/lib/.wh.dpkg"}},
			report.PackageManagerApk, []string{"libcrypto3=3.3.2-r0", "musl=1.2.5-r0"}},
		{"opaque directory hides lower files", []entry{{name: "var/lib/dpkg/.wh.status"}, {name: "lib/apk/db/.wh..wh..opq"}},
			"", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := exportOf(t,
				map[string][]byte{"blobs/sha256/l1": base, "blobs/sha256/l2": tarOf(t, tt.upper...)},
				nil,
				manifest{Layers: []string{"blobs/sha256/l1", "blobs/sha256/l2"}},
			)
			s, err := readTestExport(t, data, amd64)
			if err != nil {
				t.Fatal(err)
			}
			if s.PackageManager != tt.manager || !reflect.DeepEqual(names(s.Packages), tt.want) {
				t.Errorf("%q %v, want %q %v", s.PackageManager, names(s.Packages), tt.manager, tt.want)
			}
			if s.Packages == nil {
				t.Error("packages must be empty, not nil")
			}
		})
	}
	// Without the whiteouts the image is ambiguous, and that is reported.
	data := exportOf(t, map[string][]byte{"blobs/sha256/l1": base}, nil, manifest{Layers: []string{"blobs/sha256/l1"}})
	if _, err := readTestExport(t, data, amd64); err == nil || !strings.Contains(err.Error(), "several package managers") {
		t.Errorf("both package managers: %v", err)
	}
}

func TestReadExportDistroless(t *testing.T) {
	layer := tarOf(t,
		entry{name: "etc/os-release", body: "ID=debian\nVERSION_ID=\"12\"\n"},
		entry{name: "var/lib/dpkg/status.d/libssl3", body: "Package: libssl3\nVersion: 3.0.15-1\nArchitecture: amd64\nSource: openssl\n"},
		entry{name: "var/lib/dpkg/status.d/libssl3.md5sums", body: "0123 usr/lib/libssl.so.3\n"},
		entry{name: "var/lib/dpkg/status.d/base-files", body: "Package: base-files\nVersion: 12.4\nArchitecture: amd64\n"},
	)
	data := exportOf(t, map[string][]byte{"blobs/sha256/l1": layer}, nil, manifest{Layers: []string{"blobs/sha256/l1"}})
	s, err := readTestExport(t, data, amd64)
	if err != nil {
		t.Fatal(err)
	}
	want := []report.InstalledPackage{
		{Name: "base-files", Version: "12.4", Architecture: "amd64", Source: "base-files", SourceVersion: "12.4"},
		{Name: "libssl3", Version: "3.0.15-1", Architecture: "amd64", Source: "openssl", SourceVersion: "3.0.15-1"},
	}
	if s.PackageManager != report.PackageManagerDpkg || !reflect.DeepEqual(s.Packages, want) {
		t.Errorf("%q %+v", s.PackageManager, s.Packages)
	}
}

// An image built FROM scratch has no package records: that is not an error.
func TestReadExportScratch(t *testing.T) {
	data := exportOf(t, map[string][]byte{"blobs/sha256/l1": tarOf(t, entry{name: "app", body: "binary"})}, nil,
		manifest{Layers: []string{"blobs/sha256/l1"}})
	s, err := readTestExport(t, data, amd64)
	if err != nil {
		t.Fatal(err)
	}
	if s.PackageManager != "" || len(s.Packages) != 0 || s.OS != (report.OS{}) {
		t.Errorf("%+v", s)
	}
}

func TestReadExportPlatforms(t *testing.T) {
	arm := tarOf(t, entry{name: "etc/os-release", body: "ID=arm\n"})
	x86 := tarOf(t, entry{name: "etc/os-release", body: "ID=x86\n"})
	data := exportOf(t,
		map[string][]byte{
			"blobs/sha256/arm": arm, "blobs/sha256/armcfg": []byte(`{"os":"linux","architecture":"arm64"}`),
			"blobs/sha256/x86": x86, "blobs/sha256/x86cfg": []byte(`{"os":"linux","architecture":"amd64"}`),
		},
		nil,
		manifest{Config: "blobs/sha256/armcfg", Layers: []string{"blobs/sha256/arm"}},
		manifest{Config: "blobs/sha256/x86cfg", Layers: []string{"blobs/sha256/x86"}},
		// Listed, but its layers are not on this server.
		manifest{Config: "blobs/sha256/x86cfg", Layers: []string{"blobs/sha256/missing"}},
	)
	s, err := readTestExport(t, data, amd64)
	if err != nil {
		t.Fatal(err)
	}
	if s.OS.ID != "x86" {
		t.Errorf("read the %s image, want x86", s.OS.ID)
	}
}

func TestReadExportFailures(t *testing.T) {
	zstd := append([]byte{0x28, 0xb5, 0x2f, 0xfd}, make([]byte, 600)...)
	tests := []struct {
		name string
		data []byte
		want string
	}{
		{"no manifest", tarOf(t, entry{name: "blobs/sha256/l1", body: "x"}), "no manifest.json"},
		{"missing layer", exportOf(t, nil, nil, manifest{Layers: []string{"blobs/sha256/l1"}}), "does not contain"},
		{"zstd layer", exportOf(t, map[string][]byte{"blobs/sha256/l1": zstd}, nil, manifest{Layers: []string{"blobs/sha256/l1"}}), "zstd"},
		{"not an archive", []byte("garbage"), "unexpected EOF"},
		{"damaged RPM database", exportOf(t, map[string][]byte{"blobs/sha256/l1": tarOf(t,
			entry{name: "etc/os-release", body: "ID=ol\n"},
			entry{name: "usr/lib/sysimage/rpm/rpmdb.sqlite", body: "SQLite format 3"},
		)}, nil, manifest{Layers: []string{"blobs/sha256/l1"}}), "/usr/lib/sysimage/rpm/rpmdb.sqlite: RPM database: not an SQLite database"},
		{"unwritten SQLite changes", exportOf(t, map[string][]byte{"blobs/sha256/l1": tarOf(t,
			entry{name: "var/lib/rpm/rpmdb.sqlite", body: "SQLite format 3"},
			entry{name: "var/lib/rpm/rpmdb.sqlite-wal", body: "pending"},
		)}, nil, manifest{Layers: []string{"blobs/sha256/l1"}}), "not yet written"},
		{"several package managers", exportOf(t, map[string][]byte{"blobs/sha256/l1": tarOf(t,
			entry{name: "var/lib/dpkg/status", body: dpkgStanza("bash", "5")},
			entry{name: "var/lib/rpm/Packages", body: "x"},
		)}, nil, manifest{Layers: []string{"blobs/sha256/l1"}}), "several package managers"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := readTestExport(t, tt.data, amd64)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("got %v, want an error containing %q", err, tt.want)
			}
		})
	}
}
