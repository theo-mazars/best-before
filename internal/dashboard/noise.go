package dashboard

import (
	"context"
	"time"

	"github.com/theo-mazars/best-before/internal/dashboard/store"
)

// severities are the thresholds offered, most severe first.
var severities = []string{"critical", "high", "medium", "low", "negligible"}

func severityRank(s string) int {
	return map[string]int{"negligible": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}[s]
}

// shown says whether a user whose threshold is min sees a finding. Known
// exploited findings, and those of unknown severity, are always shown:
// neither can safely be called minor.
func shown(f *store.Finding, min string) bool {
	rank := severityRank(f.Severity)
	return f.KnownExploited || rank == 0 || rank >= severityRank(min)
}

type riskKey struct{ target, vuln string }

// risks are a server's accepted risks, expired ones included.
type risks map[riskKey]store.AcceptedRisk

func loadRisks(ctx context.Context, st *store.Store, agentID string) (risks, error) {
	list, err := st.AcceptedRisks(ctx, agentID)
	if err != nil {
		return nil, err
	}
	out := risks{}
	for _, r := range list {
		out[riskKey{r.Target, r.Vulnerability}] = r
	}
	return out, nil
}

// of returns the risk recorded for a finding, expired or not.
func (rs risks) of(f *store.Finding) (store.AcceptedRisk, bool) {
	r, ok := rs[riskKey{f.Target, f.Vulnerability}]
	return r, ok
}

// active returns the acceptance of a finding still running at now, or nil.
func (rs risks) active(f *store.Finding, now time.Time) *store.AcceptedRisk {
	if r, ok := rs.of(f); ok && r.Active(now) {
		return &r
	}
	return nil
}

// Where a finding goes on a user's pages.
const (
	placeOpen      = iota // counts towards the server's status
	placeNoFix            // silent until a fix appears
	placeBelow            // below the user's threshold
	placeAccepted         // accepted, until it expires
	placeOldKernel        // in a kernel installed but not running
)

// place sorts a finding for a user whose threshold is min. An accepted risk
// is shown as such whatever its severity, unless the kernel is not running.
func place(f *store.Finding, rs risks, min string, now time.Time) int {
	switch {
	case f.OldKernel:
		return placeOldKernel
	case rs.active(f, now) != nil:
		return placeAccepted
	case !shown(f, min):
		return placeBelow
	case !f.Fixable():
		return placeNoFix
	}
	return placeOpen
}

// groupByCVE groups findings by host or image and vulnerability, in the
// order they first appear. A vulnerability in several packages built from
// the same source, e.g. openssl and libssl3, is one thing to fix there.
func groupByCVE(fs []store.Finding) [][]store.Finding {
	var out [][]store.Finding
	at := map[riskKey]int{}
	for _, f := range fs {
		k := riskKey{f.Target, f.Vulnerability}
		i, ok := at[k]
		if !ok {
			i = len(out)
			at[k] = i
			out = append(out, nil)
		}
		out[i] = append(out[i], f)
	}
	return out
}

// emergency says whether a vulnerability on a host or image is an open
// emergency, as alerts see it: whatever the user's threshold, unless
// accepted, and not in an old kernel.
func emergency(group []store.Finding, rs risks, s *store.AlertSettings, now time.Time) bool {
	if rs.active(&group[0], now) != nil {
		return false
	}
	for i := range group {
		if !group[i].OldKernel && isEmergency(&group[i], s) {
			return true
		}
	}
	return false
}

// placeUrgency orders places, most urgent first.
var placeUrgency = map[int]int{placeOpen: 0, placeNoFix: 1, placeBelow: 2, placeAccepted: 3, placeOldKernel: 4}

// placeCVE places a vulnerability on a host or image by its most urgent
// package, e.g. open if one package has a fix and another not, or if it is
// in the running kernel as well as an old one. It returns that package's
// finding.
func placeCVE(group []store.Finding, rs risks, min string, now time.Time) (int, *store.Finding) {
	best, at := placeOldKernel, 0
	for i := range group {
		if p := place(&group[i], rs, min, now); i == 0 || placeUrgency[p] < placeUrgency[best] {
			best, at = p, i
		}
	}
	return best, &group[at]
}
