package dashboard

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/theo-mazars/best-before/internal/dashboard/store"
	"github.com/theo-mazars/best-before/internal/dashboard/vulns"
	"github.com/theo-mazars/best-before/internal/protocol"
	"github.com/theo-mazars/best-before/internal/report"
)

// fakeDB stands in for the Grype database.
type fakeDB struct {
	findings  []vulns.Finding
	unchecked map[string]string
	notReady  bool
}

func (f fakeDB) Update(context.Context) (bool, error) { return false, nil }
func (f fakeDB) Status() vulns.Status {
	return vulns.Status{Ready: !f.notReady, Built: time.Date(2026, 10, 31, 6, 0, 0, 0, time.UTC)}
}
func (f fakeDB) Match(context.Context, *report.Report) (*vulns.Result, error) {
	if f.notReady {
		return nil, vulns.ErrNotReady
	}
	return &vulns.Result{Findings: f.findings, Unchecked: f.unchecked}, nil
}

const testImage = "sha256:1111111111111111111111111111111111111111111111111111111111111111"

func testServerReport() report.Report {
	return report.Report{
		SchemaVersion: report.SchemaVersion,
		AgentVersion:  "v0.3.0",
		Host: report.Host{
			Hostname: "web-01",
			OS:       report.OS{ID: "ubuntu", Name: "Ubuntu 24.04.3 LTS", VersionID: "24.04"},
			APT: report.APT{
				Installed: []report.InstalledPackage{},
				Upgradable: []report.UpgradablePackage{
					{Name: "curl", CurrentVersion: "8.5.0-2ubuntu10.5", CandidateVersion: "8.5.0-2ubuntu10.6"},
					{Name: "openssl", CurrentVersion: "3.0.13-0ubuntu3.5", CandidateVersion: "3.0.13-0ubuntu3.6", Security: true},
				},
			},
			Errors: []string{},
		},
		Docker: &report.Docker{
			Available: true,
			Containers: []report.Container{
				{ID: "c1", Name: `<img src=x onerror=alert(1)>`, Image: "node:22-slim", ImageID: testImage},
			},
			Images: []report.Image{{
				ID:       testImage,
				Versions: []report.VersionVariable{{Name: "NODE_VERSION", Value: "22.0.0"}, {Name: "YARN_VERSION", Value: "1.22.22"}},
				System:   &report.ImageSystem{OS: report.OS{ID: "debian", Name: "Debian GNU/Linux 12 (bookworm)"}, PackageManager: "dpkg", Packages: []report.InstalledPackage{}},
			}},
		},
	}
}

// overview returns the servers on the overview, as cookie's user sees them.
func (tw *testWeb) overview(cookie *http.Cookie) []serverSummary {
	tw.t.Helper()
	rec := tw.do(http.MethodGet, "/api/ui/overview", nil, cookie)
	var v overviewView
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &v) != nil || len(v.Servers) != 1 {
		tw.t.Fatalf("overview: HTTP %d\n%s", rec.Code, rec.Body)
	}
	return v.Servers
}

// server returns a server's page, as cookie's user sees it.
func (tw *testWeb) server(cookie *http.Cookie, id string) serverView {
	tw.t.Helper()
	rec := tw.do(http.MethodGet, "/api/ui/servers/"+id, nil, cookie)
	var v serverView
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &v) != nil {
		tw.t.Fatalf("server page: HTTP %d\n%s", rec.Code, rec.Body)
	}
	return v
}

// cve finds a vulnerability of a package on a server's page.
func (v *serverView) cve(pkg, id string) *cveView {
	for _, p := range v.Packages {
		for _, c := range p.CVEs {
			if p.Package == pkg && c.ID == id {
				return c
			}
		}
	}
	return nil
}

func (v *serverView) image(where string) *imageView {
	for _, iv := range v.Images {
		if iv.Where == where {
			return iv
		}
	}
	return nil
}

func TestOverviewAndServerPage(t *testing.T) {
	tw := newTestWeb(t, "")
	ctx := context.Background()
	tw.store.CreateEnrolmentCode(ctx, [32]byte{1}, "", tw.now, tw.now.Add(time.Hour))
	key, _ := protocol.GenerateAgentKey()
	a, err := tw.store.RedeemEnrolmentCode(ctx, [32]byte{1}, store.NewAgent{PublicKey: key.Public(), Hostname: "web-01"}, tw.now)
	if err != nil {
		t.Fatal(err)
	}
	admin := tw.session("admin@example.org")

	// Before the first report.
	if s := tw.overview(admin)[0]; s.Status != statusWaiting {
		t.Errorf("overview before the first report: %q", s.Status)
	}

	body, _ := json.Marshal(testServerReport())
	if err := tw.store.RecordReport(ctx, a.ID, 1, make([]byte, 32), tw.now, "v0.1.0", body); err != nil {
		t.Fatal(err)
	}
	// Received but not matched yet: never OK.
	if s := tw.overview(admin)[0]; s.Status != statusUnchecked {
		t.Errorf("overview before matching: %q", s.Status)
	}

	db := fakeDB{findings: []vulns.Finding{
		{Target: testImage, Package: "node", Version: "22.0.0", Kind: vulns.KindSoftware, Vulnerability: "CVE-2026-0002",
			Severity: "critical", CVSS: 9.8, FixVersions: []string{"22.4.1"}, KnownExploited: true, URL: "https://nvd.nist.gov/vuln/detail/CVE-2026-0002"},
		{Target: vulns.TargetHost, Package: "openssl", Version: "3.0.13-0ubuntu3.5", Kind: vulns.KindPackage, Vulnerability: "CVE-2026-0001",
			Severity: "high", CVSS: 7.5, FixVersions: []string{"3.0.13-0ubuntu3.6"}},
		{Target: vulns.TargetHost, Package: "bash", Version: "5.2", Kind: vulns.KindPackage, Vulnerability: "CVE-2026-0003",
			Severity: "critical", URL: "javascript:alert(1)"},
	}}
	m := newMatching(db, tw.store, slog.New(slog.NewTextHandler(io.Discard, nil)), func() time.Time { return tw.now })
	m.match(ctx, a.ID)

	// One fixable critical, one fixable high, one known exploited; the
	// unfixed critical is silent.
	s := tw.overview(admin)[0]
	if s.ID != a.ID || s.Hostname != "web-01" || s.Status != statusCritical ||
		s.Critical != 1 || s.High != 1 || s.Medium != 0 || s.KnownExploited != 1 ||
		s.SecurityUpdates != 1 || s.Updates != 2 {
		t.Errorf("overview: %+v", s)
	}
	if c, h := s.Severities["critical"], s.Severities["high"]; *c != (severityCount{Open: 1, Muted: 1}) || *h != (severityCount{Open: 1}) {
		t.Errorf("severities: critical %+v, high %+v", c, h)
	}

	v := tw.server(admin, a.ID)
	if v.Host == nil || v.Host.OS != "Ubuntu 24.04.3 LTS" || v.Report == nil || !v.Report.Matched || v.Server.Status != statusCritical {
		t.Errorf("server page: host %+v, report %+v, status %q", v.Host, v.Report, v.Server.Status)
	}
	img := v.image("node:22-slim")
	if img == nil || strings.Join(img.Checked, "; ") != "0 Debian GNU/Linux 12 (bookworm) packages (dpkg); node 22.0.0 (by version)" ||
		len(img.Containers) != 1 || img.Containers[0] != "<img src=x onerror=alert(1)>" || *img.Severities["critical"] != (severityCount{Open: 1}) {
		t.Errorf("image: %+v", img)
	}
	// The exploited node package comes first, the unfixed bash one last.
	if len(v.Packages) != 3 || v.Packages[0].Package != "node" || v.Packages[0].Kind != vulns.KindSoftware ||
		v.Packages[0].UpdateTo != "22.4.1" || v.Packages[0].Where != "node:22-slim" || !v.Packages[0].KnownExploited ||
		v.Packages[2].Package != "bash" || !v.Packages[2].Muted {
		t.Errorf("packages: %+v", v.Packages)
	}
	if c := v.cve("bash", "CVE-2026-0003"); c == nil || c.State != "noFix" {
		t.Errorf("unfixed: %+v", c)
	}
	if c := v.cve("openssl", "CVE-2026-0001"); c == nil || c.State != "open" || c.FixVersions[0] != "3.0.13-0ubuntu3.6" {
		t.Errorf("openssl: %+v", c)
	}
	raw := tw.do(http.MethodGet, "/api/ui/servers/"+a.ID, nil, admin).Body.String()
	if strings.Contains(raw, "YARN") {
		t.Error("server page lists a variable that is not a known runtime")
	}
	// Security updates come first.
	if len(v.Upgradable) != 2 || v.Upgradable[0].Name != "openssl" || !v.Upgradable[0].Security {
		t.Errorf("updates: %+v", v.Upgradable)
	}

	if rec := tw.do(http.MethodGet, "/api/ui/servers/nope", nil, admin); rec.Code != http.StatusNotFound ||
		!strings.Contains(rec.Body.String(), "No such server.") {
		t.Errorf("unknown server: HTTP %d %s", rec.Code, rec.Body)
	}
	// The page itself is the web interface's.
	if rec := tw.do(http.MethodGet, "/servers/"+a.ID, nil, admin); rec.Code != http.StatusOK {
		t.Errorf("SPA page: HTTP %d", rec.Code)
	}
}

// A user's threshold and accepted risks take findings out of the counts and
// the status, but never out of sight.
func TestThresholdAndAcceptedRisks(t *testing.T) {
	tw := newTestWeb(t, "")
	ctx := context.Background()
	tw.store.CreateEnrolmentCode(ctx, [32]byte{1}, "", tw.now, tw.now.Add(time.Hour))
	key, _ := protocol.GenerateAgentKey()
	a, _ := tw.store.RedeemEnrolmentCode(ctx, [32]byte{1}, store.NewAgent{PublicKey: key.Public(), Hostname: "web-01"}, tw.now)
	r := testServerReport()
	r.Host.APT.Upgradable = nil
	body, _ := json.Marshal(r)
	tw.store.RecordReport(ctx, a.ID, 1, make([]byte, 32), tw.now, "v0.1.0", body)
	db := fakeDB{findings: []vulns.Finding{
		{Target: vulns.TargetHost, Package: "openssl", Version: "3.0.13", Kind: vulns.KindPackage, Vulnerability: "CVE-2026-0001",
			Severity: "critical", CVSS: 9.8, FixVersions: []string{"3.0.14"}},
		{Target: vulns.TargetHost, Package: "libssl3", Version: "3.0.13", Kind: vulns.KindPackage, Vulnerability: "CVE-2026-0001",
			Severity: "critical", CVSS: 9.8, FixVersions: []string{"3.0.14"}},
		{Target: vulns.TargetHost, Package: "curl", Version: "8.5.0", Kind: vulns.KindPackage, Vulnerability: "CVE-2026-0002",
			Severity: "medium", CVSS: 5.3, FixVersions: []string{"8.5.1"}},
		{Target: testImage, Package: "zlib", Version: "1.2", Kind: vulns.KindPackage, Vulnerability: "CVE-2026-0003",
			Severity: "low", FixVersions: []string{"1.3"}, KnownExploited: true},
	}}
	newMatching(db, tw.store, slog.New(slog.NewTextHandler(io.Discard, nil)), func() time.Time { return tw.now }).match(ctx, a.ID)
	admin := tw.session("admin@example.org")
	risk := "/api/ui/servers/" + a.ID + "/risk"

	// From high up, the medium curl finding is hidden; the exploited zlib
	// one is not, whatever its severity.
	if rec := tw.do(http.MethodPost, "/settings/view", url.Values{"min_severity": {"high"}}, admin); rec.Code != http.StatusOK {
		t.Fatalf("threshold: HTTP %d", rec.Code)
	}
	if rec := tw.do(http.MethodPost, "/settings/view", url.Values{"min_severity": {"unknown"}}, admin); rec.Code != http.StatusBadRequest {
		t.Errorf("unknown threshold: HTTP %d", rec.Code)
	}
	v := tw.server(admin, a.ID)
	if c := v.cve("curl", "CVE-2026-0002"); c == nil || c.State != "below" || c.FixVersions[0] != "8.5.1" {
		t.Errorf("below the threshold: %+v", c)
	}
	if v.Risk.Default != tw.now.Add(riskLifetime).UTC().Format(dateLayout) {
		t.Errorf("risk limits: %+v", v.Risk)
	}

	// Accepting the critical openssl finding leaves the exploited zlib one.
	type acceptance struct{ Target, Vulnerability, Reason, Expires string }
	month := tw.now.AddDate(0, 1, 0).Format(dateLayout)
	for name, bad := range map[string]struct {
		in            acceptance
		field, errMsg string
	}{
		"no reason":     {acceptance{Reason: "  ", Expires: month}, "reason", "Say why"},
		"control chars": {acceptance{Reason: "a\x1b[2J", Expires: month}, "reason", "Say why"},
		"past":          {acceptance{Reason: "x", Expires: tw.now.AddDate(0, 0, -1).Format(dateLayout)}, "expires", "Choose an expiry date"},
		"too far":       {acceptance{Reason: "x", Expires: tw.now.AddDate(1, 0, 2).Format(dateLayout)}, "expires", "Choose an expiry date"},
	} {
		bad.in.Target, bad.in.Vulnerability = vulns.TargetHost, "CVE-2026-0001"
		var e apiError
		rec := tw.json(http.MethodPut, risk, bad.in, admin)
		if json.Unmarshal(rec.Body.Bytes(), &e); rec.Code != http.StatusBadRequest || e.Field != bad.field || !strings.HasPrefix(e.Error, bad.errMsg) {
			t.Errorf("%s: HTTP %d %s", name, rec.Code, rec.Body)
		}
	}
	if rec := tw.json(http.MethodPut, risk, acceptance{vulns.TargetHost, "CVE-2026-9999", "x", month}, admin); rec.Code != http.StatusNotFound {
		t.Errorf("vulnerability not on the server: HTTP %d", rec.Code)
	}
	if rec := tw.do(http.MethodPut, risk, url.Values{"target": {vulns.TargetHost}}, admin); rec.Code != http.StatusUnsupportedMediaType {
		t.Errorf("form body: HTTP %d", rec.Code)
	}
	accept := acceptance{vulns.TargetHost, "CVE-2026-0001", "Not exposed: <b>internal</b> only", month}
	if rec := tw.json(http.MethodPut, risk, accept, admin); rec.Code != http.StatusNoContent {
		t.Fatalf("accept: HTTP %d\n%s", rec.Code, rec.Body)
	}
	v = tw.server(admin, a.ID)
	for _, pkg := range []string{"openssl", "libssl3"} {
		if c := v.cve(pkg, "CVE-2026-0001"); c == nil || c.State != "accepted" || c.Risk == nil ||
			c.Risk.Reason != "Not exposed: <b>internal</b> only" || c.Risk.AcceptedBy != "admin@example.org" {
			t.Errorf("%s accepted: %+v", pkg, c)
		}
	}
	if v.Server.Status != statusCritical || v.Server.Accepted != 2 {
		t.Errorf("after accepting openssl: %+v", v.Server)
	}

	// With zlib accepted too, nothing the user sees is left: OK.
	accept.Target, accept.Vulnerability = testImage, "CVE-2026-0003"
	tw.json(http.MethodPut, risk, accept, admin)
	if s := tw.overview(admin)[0]; s.Status != statusOK {
		t.Errorf("overview: %q", s.Status)
	}

	// Withdrawn, openssl counts again.
	withdraw := map[string]string{"target": vulns.TargetHost, "vulnerability": "CVE-2026-0001"}
	if rec := tw.json(http.MethodDelete, risk, withdraw, admin); rec.Code != http.StatusNoContent {
		t.Fatalf("withdraw: HTTP %d", rec.Code)
	}
	if s := tw.overview(admin)[0]; s.Status != statusCritical {
		t.Errorf("overview after withdrawing: %q", s.Status)
	}
}

// A report matched before the database is ready stays "not checked yet".
func TestMatchingWaitsForDatabase(t *testing.T) {
	tw := newTestWeb(t, "")
	ctx := context.Background()
	tw.store.CreateEnrolmentCode(ctx, [32]byte{1}, "", tw.now, tw.now.Add(time.Hour))
	key, _ := protocol.GenerateAgentKey()
	a, _ := tw.store.RedeemEnrolmentCode(ctx, [32]byte{1}, store.NewAgent{PublicKey: key.Public(), Hostname: "web-01"}, tw.now)
	body, _ := json.Marshal(testServerReport())
	tw.store.RecordReport(ctx, a.ID, 1, make([]byte, 32), tw.now, "v0.1.0", body)

	m := newMatching(fakeDB{notReady: true}, tw.store, slog.New(slog.NewTextHandler(io.Discard, nil)), time.Now)
	m.match(ctx, a.ID)
	if r, _ := tw.store.Report(ctx, a.ID); r.Matched {
		t.Error("report marked as checked without a database")
	}
}

func TestMatchingQueue(t *testing.T) {
	tw := newTestWeb(t, "")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tw.store.CreateEnrolmentCode(ctx, [32]byte{1}, "", tw.now, tw.now.Add(time.Hour))
	key, _ := protocol.GenerateAgentKey()
	a, _ := tw.store.RedeemEnrolmentCode(ctx, [32]byte{1}, store.NewAgent{PublicKey: key.Public(), Hostname: "web-01"}, tw.now)

	m := newMatching(fakeDB{}, tw.store, slog.New(slog.NewTextHandler(io.Discard, nil)), time.Now)
	go m.run(ctx)
	body, _ := json.Marshal(testServerReport())
	tw.store.RecordReport(ctx, a.ID, 1, make([]byte, 32), tw.now, "v0.1.0", body)
	m.enqueue(a.ID)

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if r, _ := tw.store.Report(ctx, a.ID); r != nil && r.Matched {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Error("queued report never matched")
}

// An image whose distribution has no security data is never shown as clean.
func TestUncheckedImageNeedsAttention(t *testing.T) {
	tw := newTestWeb(t, "")
	ctx := context.Background()
	tw.store.CreateEnrolmentCode(ctx, [32]byte{1}, "", tw.now, tw.now.Add(time.Hour))
	key, _ := protocol.GenerateAgentKey()
	a, _ := tw.store.RedeemEnrolmentCode(ctx, [32]byte{1}, store.NewAgent{PublicKey: key.Public(), Hostname: "web-01"}, tw.now)
	r := testServerReport()
	r.Host.APT.Upgradable = nil
	body, _ := json.Marshal(r)
	tw.store.RecordReport(ctx, a.ID, 1, make([]byte, 32), tw.now, "v0.1.0", body)

	db := fakeDB{unchecked: map[string]string{testImage: "the vulnerability database has no security data for opensuse-leap 15.6"}}
	newMatching(db, tw.store, slog.New(slog.NewTextHandler(io.Discard, nil)), func() time.Time { return tw.now }).match(ctx, a.ID)

	admin := tw.session("admin@example.org")
	if s := tw.overview(admin)[0]; s.Status != statusAttention || s.NotChecked != 1 {
		t.Errorf("overview: %+v", s)
	}
	v := tw.server(admin, a.ID)
	if img := v.image("node:22-slim"); img == nil ||
		img.NotChecked != "the vulnerability database has no security data for opensuse-leap 15.6" {
		t.Errorf("image: %+v", img)
	}
}

// Each image says what was checked, so that an image with nothing Best
// Before can read never passes for clean.
func TestWhatWasChecked(t *testing.T) {
	tw := newTestWeb(t, "")
	ctx := context.Background()
	tw.store.CreateEnrolmentCode(ctx, [32]byte{1}, "", tw.now, tw.now.Add(time.Hour))
	key, _ := protocol.GenerateAgentKey()
	a, _ := tw.store.RedeemEnrolmentCode(ctx, [32]byte{1}, store.NewAgent{PublicKey: key.Public(), Hostname: "web-01"}, tw.now)

	const (
		static = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
		leap   = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
	)
	r := testServerReport()
	r.Docker.Containers = append(r.Docker.Containers,
		report.Container{ID: "c2", Name: "proxy", Image: "example/static:1", ImageID: static},
		report.Container{ID: "c3", Name: "legacy", Image: "example/leap:1", ImageID: leap})
	r.Docker.Images[0].Versions = append(r.Docker.Images[0].Versions, report.VersionVariable{Name: "REDIS_VERSION", Value: "7"})
	r.Docker.Images = append(r.Docker.Images,
		report.Image{ID: static, System: &report.ImageSystem{Packages: []report.InstalledPackage{}}},
		report.Image{ID: leap, System: &report.ImageSystem{
			OS: report.OS{ID: "opensuse-leap", Name: "openSUSE Leap 15.6"}, PackageManager: "rpm",
			Packages: []report.InstalledPackage{{Name: "bash", Version: "4.4"}}}})
	body, _ := json.Marshal(r)
	tw.store.RecordReport(ctx, a.ID, 1, make([]byte, 32), tw.now, "v0.1.0", body)
	db := fakeDB{unchecked: map[string]string{leap: "the vulnerability database has no security data for opensuse-leap 15.6"}}
	newMatching(db, tw.store, slog.New(slog.NewTextHandler(io.Discard, nil)), func() time.Time { return tw.now }).match(ctx, a.ID)

	v := tw.server(tw.session("admin@example.org"), a.ID)
	if img := v.image("node:22-slim"); img == nil ||
		strings.Join(img.Checked, "; ") != "0 Debian GNU/Linux 12 (bookworm) packages (dpkg); node 22.0.0 (by version)" ||
		strings.Join(img.Imprecise, ", ") != "redis 7" || img.NothingChecked {
		t.Errorf("node image: %+v", img)
	}
	if img := v.image("example/static:1"); img == nil || !img.NothingChecked || len(img.Checked) != 0 || img.NotChecked != "" {
		t.Errorf("static image: %+v", img)
	}
	// The packages of a distribution without security data are not
	// claimed as checked.
	if img := v.image("example/leap:1"); img == nil || img.NothingChecked || len(img.Checked) != 0 ||
		img.NotChecked != "the vulnerability database has no security data for opensuse-leap 15.6" {
		t.Errorf("leap image: %+v", img)
	}
}
