package vulns

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/syft/syft/cpe"
	syftPkg "github.com/anchore/syft/syft/pkg"

	"github.com/theo-mazars/best-before/internal/report"
)

// target is one set of packages matched together: the host, or one image.
type target struct {
	id       string
	context  pkg.Context
	packages []pkg.Package
	kinds    map[pkg.ID]string
	// unchecked says why the target's packages cannot be checked.
	unchecked string
}

func (t *target) hasKind(kind string) bool {
	for _, k := range t.kinds {
		if k == kind {
			return true
		}
	}
	return false
}

// keepOnly drops the packages of other kinds.
func (t *target) keepOnly(kind string) {
	kept := t.packages[:0]
	for _, p := range t.packages {
		if t.kinds[p.ID] == kind {
			kept = append(kept, p)
		}
	}
	t.packages = kept
}

func targets(r *report.Report) []target {
	host := newTarget(TargetHost, r.Host.OS)
	host.addPackages(report.PackageManagerDpkg, r.Host.APT.Installed)
	out := []target{host}

	if r.Docker == nil {
		return out
	}
	for _, img := range r.Docker.Images {
		var t target
		if img.System != nil {
			t = newTarget(img.ID, img.System.OS)
			t.addPackages(img.System.PackageManager, img.System.Packages)
		} else {
			t = newTarget(img.ID, report.OS{})
		}
		t.addSoftware(img.Versions)
		out = append(out, t)
	}
	return out
}

func newTarget(id string, os report.OS) target {
	t := target{id: id, kinds: map[pkg.ID]string{}}
	if os.ID != "" {
		t.context.Distro = distro.NewFromNameVersion(os.ID, os.VersionID)
	}
	return t
}

func (t *target) add(p pkg.Package, kind string) {
	p.ID = pkg.ID(fmt.Sprintf("%d", len(t.packages)))
	t.packages = append(t.packages, p)
	t.kinds[p.ID] = kind
}

func (t *target) addPackages(manager string, pkgs []report.InstalledPackage) {
	var typ syftPkg.Type
	switch manager {
	case report.PackageManagerDpkg:
		typ = syftPkg.DebPkg
	case report.PackageManagerApk:
		typ = syftPkg.ApkPkg
	case report.PackageManagerRPM:
		typ = syftPkg.RpmPkg
	default:
		return
	}
	// Without a distribution, distribution data cannot be used.
	if t.context.Distro == nil {
		if len(pkgs) > 0 {
			t.unchecked = "packages found, but no os-release to tell which distribution's security data applies"
		}
		return
	}
	for _, p := range pkgs {
		gp := pkg.Package{Name: p.Name, Version: p.Version, Type: typ, Distro: t.context.Distro}
		// Security data is mostly published per source package.
		if p.Source != "" && (p.Source != p.Name || p.SourceVersion != p.Version) {
			gp.Upstreams = []pkg.UpstreamPackage{{Name: p.Source, Version: p.SourceVersion}}
		}
		if typ == syftPkg.RpmPkg {
			gp.Metadata = rpmMetadata(p)
		}
		t.add(gp, KindPackage)
	}
}

func (t *target) addSoftware(vars []report.VersionVariable) {
	for _, v := range vars {
		sw, ok := softwareByVariable[v.Name]
		if !ok {
			continue
		}
		ver, ok := softwareVersion(v.Value)
		if !ok {
			continue
		}
		var cpes []cpe.CPE
		for _, vp := range sw.cpes {
			c, err := cpe.New("cpe:2.3:a:"+vp+":"+ver+":*:*:*:*:*:*:*", cpe.DeclaredSource)
			if err == nil {
				cpes = append(cpes, c)
			}
		}
		if len(cpes) > 0 {
			t.add(pkg.Package{Name: sw.name, Version: ver, Type: syftPkg.BinaryPkg, CPEs: cpes}, KindSoftware)
		}
	}
}

// rpmMetadata carries what RPM matching needs beyond name and version: the
// epoch, also applied to the source package, and the module stream, which
// decides which advisories apply on RHEL 8 and 9.
func rpmMetadata(p report.InstalledPackage) pkg.RpmMetadata {
	m := pkg.RpmMetadata{Arch: p.Architecture}
	if e, _, ok := strings.Cut(p.Version, ":"); ok {
		if n, err := strconv.Atoi(e); err == nil {
			m.Epoch = &n
		}
	}
	if p.Module != "" {
		m.ModularityLabel = &p.Module
	}
	return m
}
