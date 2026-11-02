package dashboard

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/theo-mazars/best-before/internal/dashboard/store"
	"github.com/theo-mazars/best-before/internal/dashboard/vulns"
	"github.com/theo-mazars/best-before/internal/report"
)

// How often the dashboard looks for a newer vulnerability database. Anchore
// publishes one a day; a check costs one small request.
const (
	dbCheckInterval = 6 * time.Hour
	dbRetryInterval = 30 * time.Minute
)

// vulnDB is the part of vulns.DB the dashboard uses, replaced in tests.
type vulnDB interface {
	Update(ctx context.Context) (bool, error)
	Match(ctx context.Context, r *report.Report) (*vulns.Result, error)
	Status() vulns.Status
}

// matching matches each new report, and every report again whenever the
// vulnerability database changes, so that a vulnerability published today is
// found in an inventory sent last week. Reports are queued, never matched
// while the agent waits for its reply.
type matching struct {
	db    vulnDB
	store *store.Store
	log   *slog.Logger
	now   func() time.Time
	// matched, if set, is called after an agent's findings change.
	matched func()

	mu      sync.Mutex
	pending map[string]bool
	wake    chan struct{}
}

func newMatching(db vulnDB, st *store.Store, log *slog.Logger, now func() time.Time) *matching {
	return &matching{db: db, store: st, log: log, now: now, pending: map[string]bool{}, wake: make(chan struct{}, 1)}
}

// enqueue asks for an agent's latest report to be matched.
func (m *matching) enqueue(agentID string) {
	m.mu.Lock()
	m.pending[agentID] = true
	m.mu.Unlock()
	select {
	case m.wake <- struct{}{}:
	default:
	}
}

// enqueueAll asks for every report to be matched again.
func (m *matching) enqueueAll(ctx context.Context) {
	seqs, err := m.store.ReportSequences(ctx)
	if err != nil {
		m.log.Error("listing reports to match", "error", err)
		return
	}
	for id := range seqs {
		m.enqueue(id)
	}
}

// run matches queued reports until ctx ends.
func (m *matching) run(ctx context.Context) {
	m.enqueueAll(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-m.wake:
		}
		for {
			m.mu.Lock()
			var id string
			for id = range m.pending {
				break
			}
			delete(m.pending, id)
			m.mu.Unlock()
			if id == "" || ctx.Err() != nil {
				break
			}
			m.match(ctx, id)
		}
	}
}

func (m *matching) match(ctx context.Context, agentID string) {
	rep, err := m.store.Report(ctx, agentID)
	if err != nil {
		m.log.Error("loading report to match", "agent", agentID, "error", err)
		return
	}
	var r report.Report
	if err := json.Unmarshal(rep.Body, &r); err != nil {
		m.log.Error("decoding stored report", "agent", agentID, "error", err)
		return
	}
	status := m.db.Status()
	res, err := m.db.Match(ctx, &r)
	if errors.Is(err, vulns.ErrNotReady) {
		return // matched once the database is ready
	}
	if err != nil {
		m.log.Error("matching report", "agent", agentID, "error", err)
		return
	}
	findings := make([]store.Finding, 0, len(res.Findings))
	for _, f := range res.Findings {
		findings = append(findings, store.Finding{
			Target: f.Target, Package: f.Package, Version: f.Version, Kind: f.Kind,
			Vulnerability: f.Vulnerability, Severity: f.Severity, CVSS: f.CVSS, FixVersions: f.FixVersions,
			KnownExploited: f.KnownExploited, URL: f.URL,
		})
	}
	if err := m.store.ReplaceFindings(ctx, agentID, rep.Sequence, status.Built, findings, res.Unchecked, m.now()); err != nil {
		m.log.Error("storing findings", "agent", agentID, "error", err)
		return
	}
	if m.matched != nil {
		m.matched()
	}
}

// updateLoop keeps the database current, and matches everything again after
// each update. The first download takes a minute or two.
func (m *matching) updateLoop(ctx context.Context) {
	for {
		if !m.db.Status().Ready {
			m.log.Info("downloading the vulnerability database (about 200 MB; 3.5 GB once unpacked)")
		}
		next := dbCheckInterval
		updated, err := m.db.Update(ctx)
		switch {
		case err != nil:
			m.log.Error("vulnerability database update failed; matching continues with the current one if any", "error", err)
			// Grype may not wrap the TLS error, hence the text as well.
			if errors.As(err, new(x509.UnknownAuthorityError)) || strings.Contains(err.Error(), "certificate signed by unknown authority") {
				m.log.Error("this system does not trust grype.anchore.io's certificate: install CA certificates (e.g. the ca-certificates package), or, behind a proxy that inspects HTTPS, point SSL_CERT_FILE to a bundle that includes the proxy's CA")
			}
			next = dbRetryInterval
		case updated:
			m.log.Info("vulnerability database updated; matching every report again", "built", m.db.Status().Built)
			m.enqueueAll(ctx)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(next):
		}
	}
}
