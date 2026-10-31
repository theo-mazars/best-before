// Package vulns matches the inventories agents report against the Grype
// vulnerability database, which the dashboard downloads and keeps current.
//
// Host and image packages are matched against their distribution's own
// security data (Ubuntu, Debian, Alpine), so that backported fixes are
// recognised. Software reported through *_VERSION variables is matched by
// CPE against the NVD's data, which is noisier.
package vulns

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/anchore/clio"
	"github.com/anchore/grype/grype"
	v6 "github.com/anchore/grype/grype/db/v6"
	v6dist "github.com/anchore/grype/grype/db/v6/distribution"
	v6inst "github.com/anchore/grype/grype/db/v6/installation"
	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/matcher"
	"github.com/anchore/grype/grype/matcher/stock"
	"github.com/anchore/grype/grype/vulnerability"

	"github.com/theo-mazars/best-before/internal/report"
	"github.com/theo-mazars/best-before/internal/version"
)

// TargetHost is the target of findings on the server itself; image findings
// use the image ID.
const TargetHost = "host"

// Kinds of finding.
const (
	KindPackage  = "package"  // from a package manager's records
	KindSoftware = "software" // from a *_VERSION variable
)

// Finding is one vulnerability in one package of one target.
type Finding struct {
	Target         string
	Package        string
	Version        string
	Kind           string
	Vulnerability  string
	Severity       string // critical, high, medium, low, negligible or unknown
	CVSS           float64
	FixVersions    []string
	KnownExploited bool
	URL            string
}

// Fixable reports whether a fixed version exists. Findings without one are
// silent: shown, but never counted in a server's status or alerted on.
func (f Finding) Fixable() bool { return len(f.FixVersions) > 0 }

// ErrNotReady is returned before a database has been downloaded.
var ErrNotReady = errors.New("the vulnerability database is not ready yet")

// Status describes the database in use.
type Status struct {
	Ready bool
	// Built is when Anchore built the database in use.
	Built time.Time
	// LastError is the last failure to update or load, cleared on success.
	LastError string
}

// DB is the vulnerability database. It is safe for concurrent use, and can
// be updated while matching continues on the previous version.
type DB struct {
	dir string
	log *slog.Logger

	mu       sync.RWMutex
	provider vulnerability.Provider
	reader   v6.Reader // to ask which distributions the database covers
	status   Status
}

// Open uses the database in dir, if one has been downloaded. It never
// touches the network; call Update for that.
func Open(dir string, log *slog.Logger) *DB {
	db := &DB{dir: dir, log: log}
	if err := db.reload(); err != nil && !errors.Is(err, v6.ErrDBDoesNotExist) {
		db.log.Warn("vulnerability database unusable; it will be downloaded again", "error", err)
	}
	return db
}

func (db *DB) configs() (v6dist.Config, v6inst.Config) {
	id := clio.Identification{Name: "bestbefore", Version: version.Version}
	dist := v6dist.DefaultConfig()
	dist.ID = id
	inst := v6inst.DefaultConfig(id)
	inst.DBRootDir = db.dir
	// Checks are scheduled by the dashboard, not throttled by Grype.
	inst.UpdateCheckMaxFrequency = 0
	return dist, inst
}

// Update downloads a newer database if there is one and switches to it. It
// reports whether the database changed. Matching continues on the previous
// database while the new one downloads.
func (db *DB) Update(ctx context.Context) (bool, error) {
	dist, inst := db.configs()
	client, err := v6dist.NewClient(dist)
	if err != nil {
		return false, db.failed(err)
	}
	cur, err := v6inst.NewCurator(inst, client)
	if err != nil {
		return false, db.failed(err)
	}
	updated, err := cur.Update()
	if err != nil {
		return false, db.failed(fmt.Errorf("updating the vulnerability database: %w", err))
	}
	if !updated && db.Status().Ready {
		db.mu.Lock()
		db.status.LastError = ""
		db.mu.Unlock()
		return false, nil
	}
	if err := db.reload(); err != nil {
		return false, db.failed(err)
	}
	return true, nil
}

func (db *DB) failed(err error) error {
	db.mu.Lock()
	db.status.LastError = err.Error()
	db.mu.Unlock()
	return err
}

// reload opens the database on disk and replaces the one in use.
func (db *DB) reload() error {
	dist, inst := db.configs()
	client, err := v6dist.NewClient(dist)
	if err != nil {
		return err
	}
	cur, err := v6inst.NewCurator(inst, client)
	if err != nil {
		return err
	}
	// Status checks the database's age and integrity.
	status := cur.Status()
	if status.Error != nil {
		return status.Error
	}
	reader, err := cur.Reader()
	if err != nil {
		return fmt.Errorf("opening the vulnerability database: %w", err)
	}
	db.mu.Lock()
	old := db.provider
	db.provider = v6.NewVulnerabilityProvider(reader)
	db.reader = reader
	db.status = Status{Ready: true, Built: status.Built.UTC()}
	db.mu.Unlock()
	if old != nil {
		old.Close()
	}
	return nil
}

// covers reports whether the database has security data for a
// distribution, directly or through an alias (e.g. Rocky Linux uses RHEL's).
// Without it, matching finds nothing, which must not pass for "clean".
func (db *DB) covers(d *distro.Distro) (bool, error) {
	oss, err := db.reader.GetOperatingSystems(v6.OSSpecifier{
		Name:             d.Name(),
		MajorVersion:     d.MajorVersion(),
		MinorVersion:     d.MinorVersion(),
		RemainingVersion: d.RemainingVersion(),
		LabelVersion:     d.LabelVersion(),
	})
	if errors.Is(err, v6.ErrMissingOSIdentification) {
		return false, nil
	}
	return len(oss) > 0, err
}

func (db *DB) Status() Status {
	db.mu.RLock()
	defer db.mu.RUnlock()
	return db.status
}

func (db *DB) Close() error {
	db.mu.Lock()
	defer db.mu.Unlock()
	if db.provider == nil {
		return nil
	}
	err := db.provider.Close()
	db.provider = nil
	db.reader = nil
	db.status.Ready = false
	return err
}

// Result is what matching found in a report.
type Result struct {
	Findings []Finding
	// Unchecked says why a target's packages could not be checked, by
	// target. Such a target is never shown as clean.
	Unchecked map[string]string
}

// Match returns the vulnerabilities in a report: its host packages and, for
// each image, its packages and known software.
func (db *DB) Match(ctx context.Context, r *report.Report) (*Result, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()
	if db.provider == nil {
		return nil, ErrNotReady
	}
	m := grype.VulnerabilityMatcher{
		VulnerabilityProvider: db.provider,
		Matchers:              matcher.NewDefaultMatchers(matcher.Config{Stock: stock.MatcherConfig{UseCPEs: true}}),
		NormalizeByCVE:        true,
	}

	res := &Result{Findings: []Finding{}, Unchecked: map[string]string{}}
	for _, t := range targets(r) {
		if t.unchecked == "" && t.context.Distro != nil && t.hasKind(KindPackage) {
			ok, err := db.covers(t.context.Distro)
			if err != nil {
				return nil, err
			}
			if !ok {
				t.unchecked = "the vulnerability database has no security data for " + t.context.Distro.String()
				t.keepOnly(KindSoftware)
			}
		}
		if t.unchecked != "" {
			res.Unchecked[t.id] = t.unchecked
		}
		if len(t.packages) == 0 {
			continue
		}
		matches, _, err := m.FindMatchesContext(ctx, t.packages, t.context)
		if err != nil {
			return nil, fmt.Errorf("matching %s: %w", t.id, err)
		}
		res.Findings = append(res.Findings, t.findings(matches.Sorted())...)
	}
	return res, nil
}

func (t target) findings(matches []match.Match) []Finding {
	byKey := map[string]Finding{}
	fromPackages := map[string]bool{}
	for _, m := range matches {
		kind := t.kinds[m.Package.ID]
		f := Finding{
			Target:        t.id,
			Package:       m.Package.Name,
			Version:       m.Package.Version,
			Kind:          kind,
			Vulnerability: m.Vulnerability.ID,
			Severity:      "unknown",
		}
		if m.Vulnerability.Fix.State == vulnerability.FixStateFixed {
			f.FixVersions = slices.Compact(slices.Sorted(slices.Values(m.Vulnerability.Fix.Versions)))
		}
		if md := m.Vulnerability.Metadata; md != nil {
			if s := strings.ToLower(md.Severity); s != "" {
				f.Severity = s
			}
			for _, c := range md.Cvss {
				f.CVSS = max(f.CVSS, c.Metrics.BaseScore)
			}
			f.KnownExploited = len(md.KnownExploited) > 0
			f.URL = md.DataSource
		}
		key := f.Package + "\x00" + f.Vulnerability
		if prev, ok := byKey[key]; ok {
			f = merge(prev, f)
		}
		byKey[key] = f
		if kind == KindPackage {
			fromPackages[f.Vulnerability] = true
		}
	}

	out := make([]Finding, 0, len(byKey))
	for _, f := range byKey {
		// A distribution's data beats a CPE match for the same vulnerability.
		if f.Kind == KindSoftware && fromPackages[f.Vulnerability] {
			continue
		}
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Package != out[j].Package {
			return out[i].Package < out[j].Package
		}
		return out[i].Vulnerability < out[j].Vulnerability
	})
	return out
}

// merge combines two matches of one vulnerability in one package, e.g. by
// two CPEs: the worse assessment wins, and every fix is kept.
func merge(a, b Finding) Finding {
	a.CVSS = max(a.CVSS, b.CVSS)
	a.KnownExploited = a.KnownExploited || b.KnownExploited
	if severityRank[b.Severity] > severityRank[a.Severity] {
		a.Severity = b.Severity
	}
	a.FixVersions = slices.Compact(slices.Sorted(slices.Values(append(a.FixVersions, b.FixVersions...))))
	if a.URL == "" {
		a.URL = b.URL
	}
	return a
}

var severityRank = map[string]int{"unknown": 0, "negligible": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
