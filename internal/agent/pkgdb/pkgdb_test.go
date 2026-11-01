package pkgdb

import (
	"reflect"
	"strings"
	"testing"

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
	got, err := ParseDpkgStatus(strings.NewReader(status))
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

func TestParseApkInstalled(t *testing.T) {
	const db = `C:Q1abc=
P:musl
V:1.2.5-r0
A:x86_64
o:musl
F:lib

P:libcrypto3
V:3.3.2-r0
A:x86_64
o:openssl
R:libcrypto.so.3
`
	got, err := ParseApkInstalled(strings.NewReader(db))
	if err != nil {
		t.Fatal(err)
	}
	want := []report.InstalledPackage{
		{Name: "libcrypto3", Version: "3.3.2-r0", Architecture: "x86_64", Source: "openssl", SourceVersion: "3.3.2-r0"},
		{Name: "musl", Version: "1.2.5-r0", Architecture: "x86_64", Source: "musl", SourceVersion: "1.2.5-r0"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got  %+v\nwant %+v", got, want)
	}
}
