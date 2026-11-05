package dashboard

import (
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/anchore/grype/grype/version"

	"github.com/theo-mazars/best-before/internal/dashboard/store"
	"github.com/theo-mazars/best-before/internal/dashboard/vulns"
)

// serverView is a server's page.
type serverView struct {
	Server     *serverSummary  `json:"server"`
	DB         dbView          `json:"db"`
	Report     *reportView     `json:"report"` // nil before the first report
	Host       *hostView       `json:"host"`
	OldKernels []oldKernelView `json:"oldKernels"`
	Upgradable []updateView    `json:"upgradable"`
	Packages   []*packageView  `json:"packages"`
	Images     []*imageView    `json:"images"`
	Risk       riskLimits      `json:"risk"`
}

type reportView struct {
	ReceivedAt time.Time `json:"receivedAt"`
	// Matched is false until the report is checked against the database.
	Matched   bool       `json:"matched"`
	MatchedAt *time.Time `json:"matchedAt"`
	DBBuilt   *time.Time `json:"dbBuilt"`
}

type hostView struct {
	OS               string     `json:"os"`
	Kernel           string     `json:"kernel"`
	UptimeSeconds    int64      `json:"uptimeSeconds"`
	RebootRequired   bool       `json:"rebootRequired"`
	RebootPackages   []string   `json:"rebootPackages"`
	ListsPublishedAt *time.Time `json:"listsPublishedAt"`
	AgentVersion     string     `json:"agentVersion"`
}

// oldKernelView is a kernel installed but not running, with vulnerabilities.
type oldKernelView struct {
	ABI             string   `json:"abi"`
	Packages        []string `json:"packages"`
	Vulnerabilities int      `json:"vulnerabilities"`
}

type updateView struct {
	Name      string `json:"name"`
	Current   string `json:"current"`
	Candidate string `json:"candidate"`
	Security  bool   `json:"security"`
}

// packageView is one package, at one version, on the host or in an image,
// with all its vulnerabilities.
type packageView struct {
	Where          string                    `json:"where"`
	Target         string                    `json:"target"`
	Package        string                    `json:"package"`
	Version        string                    `json:"version"`
	Kind           string                    `json:"kind"`
	Severities     map[string]*severityCount `json:"severities"`
	KnownExploited bool                      `json:"knownExploited"`
	MaxCVSS        float64                   `json:"maxCvss"`
	// UpdateTo is the highest fixed version, which fixes every vulnerability
	// with a fix; empty when none has one, or the versions don't compare.
	UpdateTo string `json:"updateTo"`
	// Muted is true when no vulnerability counts towards the status.
	Muted bool       `json:"muted"`
	CVEs  []*cveView `json:"cves"`

	format  version.Format
	openKEV bool
}

// Finding states on a server's page.
var placeNames = map[int]string{placeOpen: "open", placeNoFix: "noFix", placeBelow: "below", placeAccepted: "accepted", placeOldKernel: "oldKernel"}

type cveView struct {
	ID             string    `json:"id"`
	URL            string    `json:"url"`
	Severity       string    `json:"severity"`
	CVSS           float64   `json:"cvss"`
	KnownExploited bool      `json:"knownExploited"`
	FixVersions    []string  `json:"fixVersions"`
	FirstSeenAt    time.Time `json:"firstSeenAt"`
	State          string    `json:"state"`
	Risk           *riskView `json:"risk"`
}

type riskView struct {
	Reason     string    `json:"reason"`
	AcceptedBy string    `json:"acceptedBy"`
	AcceptedAt time.Time `json:"acceptedAt"`
	ExpiresAt  time.Time `json:"expiresAt"`
}

type imageView struct {
	ID         string   `json:"id"`
	References []string `json:"references"` // as written by the containers using it
	Containers []string `json:"containers"`
	OS         string   `json:"os"`
	NotChecked string   `json:"notChecked"`
	// Checked says what matching covers, e.g. "142 Debian GNU/Linux 12
	// (bookworm) packages (dpkg)" or "node 22.11.0 (by version)". Empty when
	// the image has nothing Best Before can check, which must not pass for
	// clean.
	Checked []string `json:"checked"`
	// Imprecise are known runtimes whose version is too vague to match,
	// e.g. "redis 7".
	Imprecise []string `json:"imprecise"`
	// NothingChecked is true for an image that was read, but holds no
	// package records and no known runtime, e.g. a static binary FROM
	// scratch. What such an image contains is its developers'
	// responsibility, so it is shown, but does not change the server's
	// status.
	NothingChecked bool                      `json:"nothingChecked"`
	Where          string                    `json:"where"`
	Severities     map[string]*severityCount `json:"severities"`

	format version.Format
}

// riskLimits are the expiry dates an acceptance may have, as YYYY-MM-DD.
type riskLimits struct {
	Min     string `json:"min"`
	Max     string `json:"max"`
	Default string `json:"default"`
}

func newSeverities() map[string]*severityCount {
	m := map[string]*severityCount{}
	for _, k := range []string{"critical", "high", "medium", "low", "unknown"} {
		m[k] = &severityCount{}
	}
	return m
}

func packageFormat(manager string) version.Format {
	switch manager {
	case "dpkg":
		return version.DebFormat
	case "apk":
		return version.ApkFormat
	case "rpm":
		return version.RpmFormat
	}
	return version.UnknownFormat
}

func (w *web) serverPage(rw http.ResponseWriter, r *http.Request, u *store.User) {
	a, err := w.store.AgentByID(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeError(rw, http.StatusNotFound, "", "No such server.")
		return
	}
	if err != nil {
		w.apiFail(rw, r, err)
		return
	}
	now := w.now()
	s, st, err := w.summary(r, a, u, now)
	if err != nil {
		w.apiFail(rw, r, err)
		return
	}
	db := w.db.Status()
	v := serverView{
		Server: s, DB: dbView{Ready: db.Ready, LastError: db.LastError},
		OldKernels: []oldKernelView{}, Upgradable: []updateView{}, Packages: []*packageView{}, Images: []*imageView{},
		Risk: riskLimits{
			Min:     now.AddDate(0, 0, 1).UTC().Format(dateLayout),
			Max:     now.Add(maxRiskLifetime).UTC().Format(dateLayout),
			Default: now.Add(riskLifetime).UTC().Format(dateLayout),
		},
	}
	if db.Ready {
		v.DB.Built = &db.Built
	}
	if st == nil {
		writeJSON(rw, http.StatusOK, v)
		return
	}
	rep, body := st.rep, st.body
	v.Report = &reportView{ReceivedAt: rep.ReceivedAt, Matched: rep.Matched, MatchedAt: rep.MatchedAt, DBBuilt: rep.MatchedDBBuilt}
	h := body.Host
	v.Host = &hostView{OS: h.OS.Name, Kernel: h.Kernel, UptimeSeconds: h.UptimeSeconds, RebootRequired: h.RebootRequired,
		RebootPackages: h.RebootRequiredPackages, ListsPublishedAt: h.APT.ListsPublishedAt, AgentVersion: body.AgentVersion}
	if v.Host.RebootPackages == nil {
		v.Host.RebootPackages = []string{}
	}
	for _, p := range h.APT.Upgradable {
		v.Upgradable = append(v.Upgradable, updateView{Name: p.Name, Current: p.CurrentVersion, Candidate: p.CandidateVersion, Security: p.Security})
	}
	sort.SliceStable(v.Upgradable, func(i, j int) bool { return v.Upgradable[i].Security && !v.Upgradable[j].Security })

	images := map[string]*imageView{}
	if body.Docker != nil {
		for _, img := range body.Docker.Images {
			iv := &imageView{ID: img.ID, NotChecked: img.SystemError, References: []string{}, Containers: []string{},
				Checked: []string{}, Severities: newSeverities()}
			if why := rep.Unchecked[img.ID]; why != "" && rep.Matched {
				iv.NotChecked = why
			}
			if img.System != nil {
				iv.OS = img.System.OS.Name
				if iv.OS == "" {
					iv.OS = strings.TrimSpace(img.System.OS.ID + " " + img.System.OS.VersionID)
				}
				iv.format = packageFormat(img.System.PackageManager)
				// Any reason not to check concerns the packages.
				if m := img.System.PackageManager; m != "" && iv.NotChecked == "" {
					iv.Checked = append(iv.Checked, strings.Join(strings.Fields(fmt.Sprintf("%d %s packages (%s)", len(img.System.Packages), iv.OS, m)), " "))
				}
			} else if iv.NotChecked == "" {
				iv.NotChecked = "not read"
			}
			software, imprecise := vulns.Software(img.Versions)
			for _, sw := range software {
				iv.Checked = append(iv.Checked, sw+" (by version)")
			}
			iv.Imprecise = imprecise
			if iv.Imprecise == nil {
				iv.Imprecise = []string{}
			}
			iv.NothingChecked = iv.NotChecked == "" && len(iv.Checked) == 0
			images[img.ID] = iv
			v.Images = append(v.Images, iv)
		}
		for _, c := range body.Docker.Containers {
			if iv := images[c.ImageID]; iv != nil {
				iv.Containers = append(iv.Containers, c.Name)
				if !slices.Contains(iv.References, c.Image) {
					iv.References = append(iv.References, c.Image)
				}
			}
		}
		for _, iv := range v.Images {
			iv.Where = shortImageID(iv.ID)
			if len(iv.References) > 0 {
				iv.Where = iv.References[0]
			}
		}
	}

	packages := map[string]*packageView{}
	kernels := map[string]*oldKernelView{}
	kernelCVEs := map[string]map[string]bool{}
	for _, f := range st.findings {
		pl := place(&f, st.risks, u.MinSeverity, now)
		key := f.Target + "\x00" + f.Package + "\x00" + f.Version
		p := packages[key]
		if p == nil {
			p = &packageView{Where: "host", Target: f.Target, Package: f.Package, Version: f.Version, Kind: f.Kind,
				Severities: newSeverities(), Muted: true, CVEs: []*cveView{}, format: version.DebFormat}
			if iv := images[f.Target]; iv != nil {
				p.Where, p.format = iv.Where, iv.format
			} else if f.Target != vulns.TargetHost {
				p.Where, p.format = shortImageID(f.Target), version.UnknownFormat
			}
			if f.Kind == vulns.KindSoftware {
				p.format = version.SemanticFormat
			}
			packages[key] = p
			v.Packages = append(v.Packages, p)
		}
		c := &cveView{ID: f.Vulnerability, URL: f.URL, Severity: f.Severity, CVSS: f.CVSS, KnownExploited: f.KnownExploited,
			FixVersions: f.FixVersions, FirstSeenAt: f.FirstSeenAt, State: placeNames[pl]}
		if c.FixVersions == nil {
			c.FixVersions = []string{}
		}
		if risk := st.risks.active(&f, now); risk != nil && pl == placeAccepted {
			c.Risk = &riskView{Reason: risk.Reason, AcceptedBy: risk.AcceptedBy, AcceptedAt: risk.AcceptedAt, ExpiresAt: risk.ExpiresAt}
		}
		p.CVEs = append(p.CVEs, c)
		sev := stripSeverity(f.Severity)
		counts := []map[string]*severityCount{p.Severities}
		if iv := images[f.Target]; iv != nil {
			counts = append(counts, iv.Severities)
		}
		for _, m := range counts {
			if pl == placeOpen {
				m[sev].Open++
			} else {
				m[sev].Muted++
			}
		}
		if pl == placeOpen {
			p.Muted = false
			p.openKEV = p.openKEV || f.KnownExploited
		}
		p.KnownExploited = p.KnownExploited || f.KnownExploited
		p.MaxCVSS = max(p.MaxCVSS, f.CVSS)
		if pl == placeOldKernel {
			abi := kernelABI(f.Package)
			k := kernels[abi]
			if k == nil {
				k = &oldKernelView{ABI: abi, Packages: []string{}}
				kernels[abi], kernelCVEs[abi] = k, map[string]bool{}
			}
			if !slices.Contains(k.Packages, f.Package) {
				k.Packages = append(k.Packages, f.Package)
			}
			kernelCVEs[abi][f.Vulnerability] = true
		}
	}
	for abi, k := range kernels {
		k.Vulnerabilities = len(kernelCVEs[abi])
		v.OldKernels = append(v.OldKernels, *k)
	}
	sort.Slice(v.OldKernels, func(i, j int) bool { return v.OldKernels[i].ABI < v.OldKernels[j].ABI })
	for _, p := range v.Packages {
		p.UpdateTo = highestFix(p)
	}
	sort.SliceStable(v.Packages, func(i, j int) bool {
		a, b := urgency(v.Packages[i]), urgency(v.Packages[j])
		return slices.Compare(a[:], b[:]) < 0
	})
	// Images with the most urgent findings first.
	sort.SliceStable(v.Images, func(i, j int) bool {
		a, b := imageUrgency(v.Images[i]), imageUrgency(v.Images[j])
		return slices.Compare(a[:], b[:]) < 0
	})
	writeJSON(rw, http.StatusOK, v)
}

// highestFix returns the highest version fixing one of a package's
// vulnerabilities, or "" when none has a fix or two fixes don't compare.
func highestFix(p *packageView) string {
	var best *version.Version
	for _, c := range p.CVEs {
		for _, fix := range c.FixVersions {
			fv := version.New(fix, p.format)
			if best == nil {
				best = fv
				continue
			}
			cmp, err := fv.Compare(best)
			if err != nil {
				return ""
			}
			if cmp > 0 {
				best = fv
			}
		}
	}
	if best == nil {
		return ""
	}
	return best.Raw
}

// urgency orders packages: muted ones last, then known exploited first,
// then by count of open critical, high, medium and low vulnerabilities.
func urgency(p *packageView) [6]int {
	s := p.Severities
	kev := 1
	if p.openKEV {
		kev = 0
	}
	muted := 0
	if p.Muted {
		muted = 1
	}
	return [6]int{muted, kev, -s["critical"].Open, -s["high"].Open, -s["medium"].Open, -s["low"].Open}
}

func imageUrgency(iv *imageView) [4]int {
	s := iv.Severities
	return [4]int{-s["critical"].Open, -s["high"].Open, -s["medium"].Open, -s["low"].Open}
}
