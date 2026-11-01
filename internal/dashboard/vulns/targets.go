package vulns

import (
	"fmt"
	"maps"
	"path"
	"slices"
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
	// names replace a package's name in findings, e.g. "go (traefik)" for
	// the Go standard library in the traefik program.
	names map[pkg.ID]string
	// unchecked says why some of the target's packages cannot be checked.
	unchecked string
}

func (t *target) uncheckable(why string) {
	if t.unchecked != "" {
		t.unchecked += "; "
	}
	t.unchecked += why
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
		var programs []report.GoProgram
		if img.System != nil {
			programs = img.System.GoPrograms
		}
		t.addGo(programs, img.Versions)
		out = append(out, t)
	}
	return out
}

func newTarget(id string, os report.OS) target {
	t := target{id: id, kinds: map[pkg.ID]string{}, names: map[pkg.ID]string{}}
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
			t.uncheckable("packages found, but no os-release to tell which distribution's security data applies")
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
		if !ok || len(sw.cpes) == 0 {
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

// addGo adds Go's standard library once per Go version found in the image,
// named after the programs built with it, and matched against Go's own
// vulnerability data. GOLANG_VERSION (golang images and those built FROM
// them) counts as a program named go.
func (t *target) addGo(programs []report.GoProgram, vars []report.VersionVariable) {
	byVersion := map[string][]string{}
	old := 0
	for _, p := range programs {
		if IgnoredGoProgram(p.Path) {
			continue
		}
		if p.GoVersion == "" {
			old++
			continue
		}
		// "go1.24.2 X:boringcrypto" is Go 1.24.2.
		v, _, _ := strings.Cut(p.GoVersion, " ")
		byVersion[v] = append(byVersion[v], path.Base(p.Path))
	}
	for _, vv := range vars {
		if vv.Name != "GOLANG_VERSION" {
			continue
		}
		if v, ok := softwareVersion(vv.Value); ok && !slices.Contains(byVersion["go"+v], "go") {
			byVersion["go"+v] = append(byVersion["go"+v], "go")
		}
	}
	for _, v := range slices.Sorted(maps.Keys(byVersion)) {
		names := slices.Compact(slices.Sorted(slices.Values(byVersion[v])))
		// The go command first, as golang images have dozens of tools.
		if i := slices.Index(names, "go"); i > 0 {
			names = append([]string{"go"}, slices.Delete(names, i, i+1)...)
		}
		label := strings.Join(names[:min(3, len(names))], ", ")
		if len(names) > 3 {
			label += ", …"
		}
		t.add(pkg.Package{Name: "stdlib", Version: v, Type: syftPkg.GoModulePkg, Language: syftPkg.Go}, KindSoftware)
		t.names[t.packages[len(t.packages)-1].ID] = "go (" + label + ")"
	}
	if old > 0 {
		t.uncheckable(fmt.Sprintf("%d Go program(s) built before Go 1.18, whose Go version the agent cannot read; such old versions are unsupported", old))
	}
}

// ignoredGoPrograms are Go programs whose findings are noise rather than
// risk, by the owner's decision. gosu, in the official postgres, mysql and
// other images, only drops privileges for a moment at container start and
// takes no input, so it cannot reach the vulnerable parts of Go its version
// matches; its maintainers make the same case.
var ignoredGoPrograms = map[string]bool{"gosu": true}

// IgnoredGoProgram reports whether a Go program is left out of matching.
func IgnoredGoProgram(programPath string) bool {
	return ignoredGoPrograms[path.Base(programPath)]
}
