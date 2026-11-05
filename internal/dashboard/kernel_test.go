package dashboard

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/theo-mazars/best-before/internal/dashboard/store"
	"github.com/theo-mazars/best-before/internal/dashboard/vulns"
	"github.com/theo-mazars/best-before/internal/protocol"
)

func TestOldKernelRule(t *testing.T) {
	for _, tc := range []struct{ kernel, abi string }{
		{"6.8.0-60-generic", "6.8.0-60"},
		{"6.1.0-28-amd64", "6.1.0-28"},
		{"6.8.0", ""},
		{"", ""},
	} {
		if got := kernelABI(tc.kernel); got != tc.abi {
			t.Errorf("kernelABI(%q) = %q, want %q", tc.kernel, got, tc.abi)
		}
	}
	for _, tc := range []struct {
		pkg, target, kind, running string
		old                        bool
	}{
		{"linux-image-6.8.0-50-generic", vulns.TargetHost, vulns.KindPackage, "6.8.0-60", true},
		{"linux-modules-extra-6.8.0-50-generic", vulns.TargetHost, vulns.KindPackage, "6.8.0-60", true},
		{"linux-headers-6.8.0-50", vulns.TargetHost, vulns.KindPackage, "6.8.0-60", true},
		{"linux-hwe-6.8-headers-6.8.0-50", vulns.TargetHost, vulns.KindPackage, "6.8.0-60", true},
		{"linux-image-6.1.0-25-amd64", vulns.TargetHost, vulns.KindPackage, "6.1.0-28", true},
		{"linux-headers-7.0.0-38", vulns.TargetHost, vulns.KindPackage, "7.0.0-42", true},
		{"linux-headers-7.0.0-38-generic", vulns.TargetHost, vulns.KindPackage, "7.0.0-42", true},
		{"linux-modules-7.0.0-38-generic", vulns.TargetHost, vulns.KindPackage, "7.0.0-42", true},
		{"linux-tools-7.0.0-38", vulns.TargetHost, vulns.KindPackage, "7.0.0-42", true},
		{"linux-tools-7.0.0-38-generic", vulns.TargetHost, vulns.KindPackage, "7.0.0-42", true},
		{"linux-image-6.8.0-60-generic", vulns.TargetHost, vulns.KindPackage, "6.8.0-60", false},
		{"linux-headers-6.8.0-60", vulns.TargetHost, vulns.KindPackage, "6.8.0-60", false},
		{"linux-image-generic", vulns.TargetHost, vulns.KindPackage, "6.8.0-60", false},
		{"linux-libc-dev", vulns.TargetHost, vulns.KindPackage, "6.8.0-60", false},
		{"linux-image-6.8.0-50-generic", vulns.TargetHost, vulns.KindPackage, "", false},
		{"linux-image-6.8.0-50-generic", testImage, vulns.KindPackage, "6.8.0-60", false},
		{"libfoo-6.8.0-50", vulns.TargetHost, vulns.KindPackage, "6.8.0-60", false},
	} {
		f := store.Finding{Target: tc.target, Package: tc.pkg, Kind: tc.kind}
		if got := oldKernel(&f, tc.running); got != tc.old {
			t.Errorf("oldKernel(%s on %s, running %q) = %v", tc.pkg, tc.target, tc.running, got)
		}
	}
}

// A kernel installed but not running is muted: no status, no alert, no
// digest. The running kernel counts as any other package.
func TestOldKernelIsQuiet(t *testing.T) {
	at := newAlertTest(t)
	at.kernel = "6.8.0-60-generic"
	at.addHook(true, false)
	old := vulns.Finding{Target: vulns.TargetHost, Package: "linux-image-6.8.0-50-generic", Version: "6.8.0-50.51",
		Kind: vulns.KindPackage, Vulnerability: "CVE-2026-5000", Severity: "critical", CVSS: 9.8,
		FixVersions: []string{"6.8.0-51.52"}, KnownExploited: true}
	at.report(1, old)

	fs, err := loadFindings(at.ctx, at.store, at.agent.ID)
	if err != nil || len(fs) != 1 || !fs[0].OldKernel {
		t.Fatalf("findings: %+v, %v", fs, err)
	}
	s := &serverSummary{Severities: map[string]*severityCount{"critical": {}}}
	s.count(fs, risks{}, "low", at.now)
	if s.Critical+s.KnownExploited != 0 || *s.Severities["critical"] != (severityCount{Muted: 1}) {
		t.Errorf("summary: %+v, critical %+v", s, s.Severities["critical"])
	}
	if got := at.check(); len(got) != 0 {
		t.Errorf("alerted: %v", titles(got))
	}
	settings, _ := at.store.AlertSettings(at.ctx)
	d, err := at.al.buildDigest(at.ctx, settings, at.now.Add(-7*24*time.Hour), at.now)
	if err != nil || len(d.Emergencies)+len(d.New)+len(d.Accepted) != 0 {
		t.Errorf("digest: %+v, %v", d, err)
	}

	// After a reboot into 6.8.0-50, it is the running kernel and counts.
	at.kernel = "6.8.0-50-generic"
	at.now = at.now.Add(time.Hour)
	at.report(2, old)
	if fs, _ := loadFindings(at.ctx, at.store, at.agent.ID); len(fs) != 1 || fs[0].OldKernel {
		t.Fatalf("after reboot: %+v", fs)
	}
	if got := at.check(); len(got) != 1 {
		t.Errorf("running kernel not alerted: %v", titles(got))
	}
}

func TestOldKernelOnServerPage(t *testing.T) {
	tw := newTestWeb(t, "")
	ctx := context.Background()
	tw.store.CreateEnrolmentCode(ctx, [32]byte{1}, "", tw.now, tw.now.Add(time.Hour))
	key, _ := protocol.GenerateAgentKey()
	a, _ := tw.store.RedeemEnrolmentCode(ctx, [32]byte{1}, store.NewAgent{PublicKey: key.Public(), Hostname: "web-01"}, tw.now)
	r := testServerReport()
	r.Host.APT.Upgradable = nil
	r.Host.Kernel = "6.8.0-60-generic"
	body, _ := json.Marshal(r)
	tw.store.RecordReport(ctx, a.ID, 1, make([]byte, 32), tw.now, "v0.1.0", body)
	finding := func(pkg, cve string) vulns.Finding {
		return vulns.Finding{Target: vulns.TargetHost, Package: pkg, Version: "1", Kind: vulns.KindPackage, Vulnerability: cve,
			Severity: "high", CVSS: 7.8, FixVersions: []string{"2"}}
	}
	db := fakeDB{findings: []vulns.Finding{
		finding("linux-image-6.8.0-50-generic", "CVE-2026-1"), finding("linux-modules-6.8.0-50-generic", "CVE-2026-1"),
		finding("linux-image-6.8.0-50-generic", "CVE-2026-2"),
	}}
	newMatching(db, tw.store, slog.New(slog.NewTextHandler(io.Discard, nil)), func() time.Time { return tw.now }).match(ctx, a.ID)

	v := tw.server(tw.session("admin@example.org"), a.ID)
	if len(v.OldKernels) != 1 || v.OldKernels[0].ABI != "6.8.0-50" || v.OldKernels[0].Vulnerabilities != 2 || len(v.OldKernels[0].Packages) != 2 {
		t.Errorf("old kernels: %+v", v.OldKernels)
	}
	if v.Server.Status != statusOK || len(v.Packages) != 2 || !v.Packages[0].Muted || v.Packages[0].CVEs[0].State != "oldKernel" {
		t.Errorf("status %q, packages %+v", v.Server.Status, v.Packages)
	}
}
