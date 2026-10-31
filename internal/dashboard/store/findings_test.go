package store

import (
	"context"
	"testing"
	"time"
)

func TestReplaceFindings(t *testing.T) {
	ctx := context.Background()
	s, _ := openTest(t)
	day1 := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
	day2, day3 := day1.AddDate(0, 0, 1), day1.AddDate(0, 0, 2)
	s.CreateEnrolmentCode(ctx, [32]byte{1}, "", day1, day1.Add(time.Hour))
	a, err := s.RedeemEnrolmentCode(ctx, [32]byte{1}, NewAgent{PublicKey: newKey(t), Hostname: "web-01"}, day1)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.RecordReport(ctx, a.ID, 1, requestID(1), day1, []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	if r, _ := s.Report(ctx, a.ID); r.Matched || r.MatchedAt != nil {
		t.Fatalf("a new report must not count as checked: %+v", r)
	}

	unfixed := Finding{Target: "host", Package: "openssl", Version: "3.0.13", Kind: "package",
		Vulnerability: "CVE-2026-0001", Severity: "high", CVSS: 7.5, URL: "https://example.org"}
	other := Finding{Target: "sha256:abc", Package: "node", Version: "22.0.0", Kind: "software",
		Vulnerability: "CVE-2026-0002", Severity: "critical", CVSS: 9.8, FixVersions: []string{"22.4.1"}, KnownExploited: true}
	if err := s.ReplaceFindings(ctx, a.ID, 1, day1, []Finding{unfixed, other}, nil, day1); err != nil {
		t.Fatal(err)
	}

	// Day 2: a database update brings a fix for the openssl finding.
	fixed := unfixed
	fixed.FixVersions = []string{"3.0.13-0ubuntu3.6", "3.0.14"}
	if err := s.ReplaceFindings(ctx, a.ID, 1, day2, []Finding{fixed, other}, nil, day2); err != nil {
		t.Fatal(err)
	}
	got, err := s.Findings(ctx, a.ID)
	if err != nil || len(got) != 2 {
		t.Fatalf("findings %+v, err %v", got, err)
	}
	// Known exploited and critical first.
	node, ssl := got[0], got[1]
	if node.Vulnerability != "CVE-2026-0002" || !node.KnownExploited || node.CVSS != 9.8 || node.Kind != "software" {
		t.Errorf("node: %+v", node)
	}
	if !ssl.FirstSeenAt.Equal(day1) || ssl.FixableSince == nil || !ssl.FixableSince.Equal(day2) ||
		len(ssl.FixVersions) != 2 || ssl.FixVersions[1] != "3.0.14" {
		t.Errorf("openssl: first seen %v, fixable since %v, fixes %v", ssl.FirstSeenAt, ssl.FixableSince, ssl.FixVersions)
	}
	if r, _ := s.Report(ctx, a.ID); !r.Matched || !r.MatchedDBBuilt.Equal(day2) {
		t.Errorf("report after matching: %+v", r)
	}

	// A newer report arrives while the old one is being matched: the late
	// result is dropped, and the new report counts as not checked.
	if err := s.RecordReport(ctx, a.ID, 2, requestID(2), day3, []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	if err := s.ReplaceFindings(ctx, a.ID, 1, day3, nil, nil, day3); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Findings(ctx, a.ID); len(got) != 2 {
		t.Errorf("late result replaced findings: %+v", got)
	}
	if r, _ := s.Report(ctx, a.ID); r.Matched {
		t.Error("new report shown as checked")
	}

	// Resolved findings disappear.
	if err := s.ReplaceFindings(ctx, a.ID, 2, day3, []Finding{other}, map[string]string{"sha256:suse": "no data"}, day3); err != nil {
		t.Fatal(err)
	}
	if r, _ := s.Report(ctx, a.ID); r.Unchecked["sha256:suse"] != "no data" {
		t.Errorf("unchecked targets: %v", r.Unchecked)
	}
	if got, _ := s.Findings(ctx, a.ID); len(got) != 1 || !got[0].FirstSeenAt.Equal(day1) {
		t.Errorf("after resolution: %+v", got)
	}

	seqs, err := s.ReportSequences(ctx)
	if err != nil || seqs[a.ID] != 2 {
		t.Errorf("sequences %v, err %v", seqs, err)
	}
}
