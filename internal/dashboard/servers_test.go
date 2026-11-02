package dashboard

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
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
	if body := tw.do(http.MethodGet, "/", nil, admin).Body.String(); !strings.Contains(body, statusWaiting) {
		t.Errorf("overview before the first report:\n%s", body)
	}

	body, _ := json.Marshal(testServerReport())
	if err := tw.store.RecordReport(ctx, a.ID, 1, make([]byte, 32), tw.now, body); err != nil {
		t.Fatal(err)
	}
	// Received but not matched yet: never OK.
	if body := tw.do(http.MethodGet, "/", nil, admin).Body.String(); !strings.Contains(body, statusUnchecked) {
		t.Errorf("overview before matching:\n%s", body)
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

	rec := tw.do(http.MethodGet, "/", nil, admin)
	page := rec.Body.String()
	// One fixable critical, one fixable high, one known exploited; the
	// unfixed critical is silent.
	for _, want := range []string{
		`<a href="/servers/` + a.ID + `">web-01</a>`, "<td>" + statusCritical + "</td>",
		"<td>1</td>\n\t\t\t<td>1</td>\n\t\t\t<td>0</td>\n\t\t\t<td>1</td>", "1 of 2",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("overview lacks %q:\n%s", want, page)
		}
	}

	rec = tw.do(http.MethodGet, "/servers/"+a.ID, nil, admin)
	page = rec.Body.String()
	if rec.Code != http.StatusOK {
		t.Fatalf("server page: HTTP %d\n%s", rec.Code, page)
	}
	for _, want := range []string{
		"Ubuntu 24.04.3 LTS", "node:22-slim", "Checked: 0 Debian GNU/Linux 12 (bookworm) packages (dpkg); node 22.0.0 (by version)",
		"22.4.1", "(by version)", "No fix yet (1)", "CVE-2026-0003", "&lt;img src=x onerror=alert(1)&gt;",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("server page lacks %q", want)
		}
	}
	if strings.Contains(page, "YARN") || strings.Contains(page, "<img") || strings.Contains(page, "javascript:") {
		t.Errorf("server page shows something it must not:\n%s", page)
	}
	// Security updates come first.
	if strings.Index(page, "<td>openssl</td>") > strings.Index(page, "<td>curl</td>") {
		t.Error("security update not listed first")
	}

	if rec := tw.do(http.MethodGet, "/servers/nope", nil, admin); rec.Code != http.StatusNotFound {
		t.Errorf("unknown server: HTTP %d", rec.Code)
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
	tw.store.RecordReport(ctx, a.ID, 1, make([]byte, 32), tw.now, body)

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
	tw.store.RecordReport(ctx, a.ID, 1, make([]byte, 32), tw.now, body)
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
	tw.store.RecordReport(ctx, a.ID, 1, make([]byte, 32), tw.now, body)

	db := fakeDB{unchecked: map[string]string{testImage: "the vulnerability database has no security data for opensuse-leap 15.6"}}
	newMatching(db, tw.store, slog.New(slog.NewTextHandler(io.Discard, nil)), func() time.Time { return tw.now }).match(ctx, a.ID)

	admin := tw.session("admin@example.org")
	overview := tw.do(http.MethodGet, "/", nil, admin).Body.String()
	if !strings.Contains(overview, "<td>"+statusAttention+"</td>") || !strings.Contains(overview, "(1 not checked)") {
		t.Errorf("overview:\n%s", overview)
	}
	page := tw.do(http.MethodGet, "/servers/"+a.ID, nil, admin).Body.String()
	if !strings.Contains(page, "not checked: the vulnerability database has no security data for opensuse-leap 15.6") {
		t.Errorf("server page:\n%s", page)
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
	tw.store.RecordReport(ctx, a.ID, 1, make([]byte, 32), tw.now, body)
	db := fakeDB{unchecked: map[string]string{leap: "the vulnerability database has no security data for opensuse-leap 15.6"}}
	newMatching(db, tw.store, slog.New(slog.NewTextHandler(io.Discard, nil)), func() time.Time { return tw.now }).match(ctx, a.ID)

	page := tw.do(http.MethodGet, "/servers/"+a.ID, nil, tw.session("admin@example.org")).Body.String()
	for _, want := range []string{
		"Checked: 0 Debian GNU/Linux 12 (bookworm) packages (dpkg); node 22.0.0 (by version)",
		"Not checked, as the image does not give a precise version: redis 7",
		"example/static:1:\n\t\t0 with a fix, 0 without, nothing to check",
		"Checked: nothing. The image has no package records",
		// The packages of a distribution without security data are not
		// claimed as checked.
		"not checked: the vulnerability database has no security data for opensuse-leap 15.6",
		"Checked: nothing</li>",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("server page lacks %q:\n%s", want, page)
		}
	}
	if strings.Contains(page, "openSUSE Leap 15.6 packages") {
		t.Error("packages without security data shown as checked")
	}
}
