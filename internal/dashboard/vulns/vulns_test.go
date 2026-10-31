package vulns

import (
	"context"
	"io"
	"log/slog"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"

	"github.com/theo-mazars/best-before/internal/report"
)

func TestSoftwareVersion(t *testing.T) {
	for value, want := range map[string]string{
		"22.11.0":                "22.11.0",
		"v2.11.7":                "2.11.7",
		"jdk-21.0.13+9":          "21.0.13",
		"9.7.0-1.el9":            "9.7.0",
		"1:11.4.2+maria~ubu2404": "11.4.2",
		"17.6-1.pgdg120+1":       "17.6",
		"8":                      "",
		"latest":                 "",
	} {
		got, ok := softwareVersion(value)
		if got != want || ok != (want != "") {
			t.Errorf("%q: got %q %v, want %q", value, got, ok, want)
		}
	}
}

func testReport() *report.Report {
	return &report.Report{
		Host: report.Host{
			OS: report.OS{ID: "ubuntu", VersionID: "24.04"},
			APT: report.APT{Installed: []report.InstalledPackage{
				{Name: "libssl3t64", Version: "3.0.13-0ubuntu3.5", Source: "openssl", SourceVersion: "3.0.13-0ubuntu3.5"},
				{Name: "bash", Version: "5.2.21-2ubuntu4", Source: "bash", SourceVersion: "5.2.21-2ubuntu4"},
			}},
		},
		Docker: &report.Docker{Images: []report.Image{
			{
				ID:       "sha256:node",
				Versions: []report.VersionVariable{{Name: "NODE_VERSION", Value: "22.0.0"}, {Name: "YARN_VERSION", Value: "1.22.22"}, {Name: "PHP_VERSION", Value: "8"}},
				System: &report.ImageSystem{OS: report.OS{ID: "debian", VersionID: "12"}, PackageManager: report.PackageManagerDpkg,
					Packages: []report.InstalledPackage{{Name: "libc6", Version: "2.36-9+deb12u13", Source: "glibc", SourceVersion: "2.36-9+deb12u13"}}},
			},
			// RPM-based: no packages, but MySQL itself is still checked.
			{ID: "sha256:mysql", Versions: []report.VersionVariable{{Name: "MYSQL_VERSION", Value: "9.0.0-1.el9"}}, SystemError: "RPM-based images are not supported yet"},
		}},
	}
}

func TestTargets(t *testing.T) {
	ts := targets(testReport())
	if len(ts) != 3 {
		t.Fatalf("%d targets", len(ts))
	}
	host, node, mysql := ts[0], ts[1], ts[2]

	if host.id != TargetHost || host.context.Distro == nil || host.context.Distro.Name() != "ubuntu" || len(host.packages) != 2 {
		t.Errorf("host: %+v", host)
	}
	ssl := host.packages[0]
	if ssl.Upstreams[0].Name != "openssl" || ssl.Distro == nil {
		t.Errorf("libssl3t64 must be matched through its source package: %+v", ssl)
	}
	if bash := host.packages[1]; len(bash.Upstreams) != 0 {
		t.Errorf("bash is its own source: %+v", bash.Upstreams)
	}

	// libc6, plus node by CPE; YARN is not checked, PHP has no usable version.
	if len(node.packages) != 2 || node.kinds[node.packages[1].ID] != KindSoftware {
		t.Fatalf("node image: %+v", node.packages)
	}
	if sw := node.packages[1]; sw.Name != "node" || sw.Version != "22.0.0" || sw.CPEs[0].Attributes.Product != "node.js" {
		t.Errorf("node: %+v", sw)
	}
	if len(mysql.packages) != 1 || mysql.packages[0].Version != "9.0.0" || mysql.context.Distro != nil {
		t.Errorf("mysql image: %+v", mysql.packages)
	}
}

func TestFindingsMergeAndPreferDistributionData(t *testing.T) {
	tg := target{id: "sha256:img", kinds: map[pkg.ID]string{"0": KindPackage, "1": KindSoftware}}
	libc := pkg.Package{ID: "0", Name: "libc6", Version: "2.36"}
	node := pkg.Package{ID: "1", Name: "node", Version: "22.0.0"}
	vuln := func(id, severity string, cvss float64, fixes ...string) vulnerability.Vulnerability {
		v := vulnerability.Vulnerability{
			Reference: vulnerability.Reference{ID: id},
			Metadata:  &vulnerability.Metadata{Severity: severity, Cvss: []vulnerability.Cvss{{Metrics: vulnerability.CvssMetrics{BaseScore: cvss}}}},
		}
		if len(fixes) > 0 {
			v.Fix = vulnerability.Fix{State: vulnerability.FixStateFixed, Versions: fixes}
		}
		return v
	}
	got := tg.findings([]match.Match{
		{Package: libc, Vulnerability: vuln("CVE-1", "Medium", 5)},
		// node matched twice (two CPEs): merged, worst wins, fixes combined.
		{Package: node, Vulnerability: vuln("CVE-2", "High", 7.5, "22.4.1")},
		{Package: node, Vulnerability: vuln("CVE-2", "Critical", 9.8, "20.15.1", "22.4.1")},
		// Also found through the distribution's data: that one is kept.
		{Package: node, Vulnerability: vuln("CVE-1", "Low", 3)},
	})
	want := []Finding{
		{Target: "sha256:img", Package: "libc6", Version: "2.36", Kind: KindPackage, Vulnerability: "CVE-1", Severity: "medium", CVSS: 5},
		{Target: "sha256:img", Package: "node", Version: "22.0.0", Kind: KindSoftware, Vulnerability: "CVE-2", Severity: "critical", CVSS: 9.8,
			FixVersions: []string{"20.15.1", "22.4.1"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got  %+v\nwant %+v", got, want)
	}
	if got[0].Fixable() || !got[1].Fixable() {
		t.Error("Fixable")
	}
}

func TestMatchNotReady(t *testing.T) {
	db := Open(t.TempDir(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if _, err := db.Match(context.Background(), testReport()); err != ErrNotReady {
		t.Errorf("got %v", err)
	}
	if db.Status().Ready {
		t.Error("ready without a database")
	}
}

// TestMatchRealDatabase runs against a downloaded Grype database (3.5 GB),
// so only when BESTBEFORE_GRYPE_DB names its directory.
func TestMatchRealDatabase(t *testing.T) {
	dir := os.Getenv("BESTBEFORE_GRYPE_DB")
	if dir == "" {
		t.Skip("set BESTBEFORE_GRYPE_DB to a Grype database directory")
	}
	db := Open(dir, slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer db.Close()
	if !db.Status().Ready {
		t.Fatal("database not loaded")
	}
	res, err := db.Match(context.Background(), testReport())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Unchecked) != 0 {
		t.Errorf("unchecked: %v", res.Unchecked)
	}
	seen := map[string]int{}
	for _, f := range res.Findings {
		seen[f.Target+" "+f.Package]++
	}
	for _, want := range []string{"host libssl3t64", "sha256:node libc6", "sha256:node node", "sha256:mysql mysql"} {
		if seen[want] == 0 {
			t.Errorf("no findings for %s; got %v", want, seen)
		}
	}
}

// TestUncheckedRealDatabase checks that a distribution without security data
// is reported, not passed as clean; software is still checked.
func TestUncheckedRealDatabase(t *testing.T) {
	dir := os.Getenv("BESTBEFORE_GRYPE_DB")
	if dir == "" {
		t.Skip("set BESTBEFORE_GRYPE_DB to a Grype database directory")
	}
	db := Open(dir, slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer db.Close()
	r := &report.Report{Docker: &report.Docker{Images: []report.Image{
		{ID: "sha256:leap", Versions: []report.VersionVariable{{Name: "NODE_VERSION", Value: "22.0.0"}},
			System: &report.ImageSystem{OS: report.OS{ID: "opensuse-leap", VersionID: "15.6"}, PackageManager: report.PackageManagerRPM,
				Packages: []report.InstalledPackage{{Name: "openssl", Version: "1.1.1d-1.1"}}}},
		{ID: "sha256:rocky", System: &report.ImageSystem{OS: report.OS{ID: "rocky", VersionID: "9.3"}, PackageManager: report.PackageManagerRPM,
			Packages: []report.InstalledPackage{{Name: "openssl-libs", Version: "1:3.0.7-24.el9", Source: "openssl", SourceVersion: "3.0.7-24.el9"}}}},
	}}}
	res, err := db.Match(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Unchecked["sha256:leap"], "no security data") || res.Unchecked["sha256:rocky"] != "" {
		t.Errorf("unchecked: %v", res.Unchecked)
	}
	seen := map[string]bool{}
	for _, f := range res.Findings {
		seen[f.Target+" "+f.Package] = true
	}
	if !seen["sha256:leap node"] || seen["sha256:leap openssl"] || !seen["sha256:rocky openssl-libs"] {
		t.Errorf("findings: %v", seen)
	}
}

func TestNoOSRelease(t *testing.T) {
	r := &report.Report{Docker: &report.Docker{Images: []report.Image{{ID: "sha256:x",
		System: &report.ImageSystem{PackageManager: report.PackageManagerDpkg, Packages: []report.InstalledPackage{{Name: "bash", Version: "5"}}}}}}}
	if ts := targets(r); ts[1].unchecked == "" || len(ts[1].packages) != 0 {
		t.Errorf("image without os-release: %+v", ts[1])
	}
}
