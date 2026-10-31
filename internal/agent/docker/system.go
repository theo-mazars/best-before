package docker

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/theo-mazars/best-before/internal/agent/pkgdb"
	"github.com/theo-mazars/best-before/internal/report"
)

// SystemReaderVersion changes whenever readSystem would read an image
// differently, so that cached results from an older agent are read again.
const SystemReaderVersion = 2

// The files read from inside images, relative to the image's root as they
// appear in layer archives. Nothing else in an image is kept.
const (
	pathOSRelease    = "etc/os-release"
	pathOSReleaseLib = "usr/lib/os-release"
	pathDpkgStatus   = "var/lib/dpkg/status"
	dirDpkgStatusD   = "var/lib/dpkg/status.d" // distroless images
	pathApkInstalled = "lib/apk/db/installed"
)

const (
	maxSystemFile  = 16 << 20  // one dpkg or apk database
	maxRPMFile     = 128 << 20 // one RPM database, which holds whole headers
	maxSystemTotal = 192 << 20 // everything kept from one image
	maxSmallBlob   = 1 << 20   // manifest.json and image configurations
	exportTimeout  = 10 * time.Minute
)

// rpmDatabases are where RPM keeps its database, in each of its formats.
// Fedora and SUSE moved it to /usr/lib/sysimage/rpm; some images have a
// database in both places, so all are read.
var rpmDatabases = map[string]pkgdb.RPMFormat{
	"var/lib/rpm/rpmdb.sqlite":          pkgdb.RPMSQLite,
	"usr/lib/sysimage/rpm/rpmdb.sqlite": pkgdb.RPMSQLite,
	"var/lib/rpm/Packages":              pkgdb.RPMBerkeleyDB,
	"usr/lib/sysimage/rpm/Packages":     pkgdb.RPMBerkeleyDB,
	"var/lib/rpm/Packages.db":           pkgdb.RPMNDB,
	"usr/lib/sysimage/rpm/Packages.db":  pkgdb.RPMNDB,
}

// sqliteWAL is SQLite's write-ahead log. Its contents are never read; a
// non-empty one means changes the database file does not have yet.
func sqliteWAL(p string) bool {
	db, ok := strings.CutSuffix(p, "-wal")
	return ok && rpmDatabases[db] == pkgdb.RPMSQLite && strings.HasSuffix(db, ".sqlite")
}

func wanted(p string) bool {
	if _, ok := rpmDatabases[p]; ok || sqliteWAL(p) {
		return true
	}
	switch p {
	case pathOSRelease, pathOSReleaseLib, pathDpkgStatus, pathApkInstalled:
		return true
	}
	return path.Dir(p) == dirDpkgStatusD && !strings.HasSuffix(p, ".md5sums")
}

// readSystem reads the package records of an image through the image export
// endpoint, which streams the image as an archive. The image is read, never
// pulled, and only the files listed above are kept.
func readSystem(ctx context.Context, c *Client, id string, want platform) (*report.ImageSystem, error) {
	ctx, cancel := context.WithTimeout(ctx, exportTimeout)
	defer cancel()
	body, err := c.open(ctx, "/images/"+url.PathEscape(id)+"/get")
	if errors.Is(err, errNotFound) {
		return nil, errors.New("the image was removed while the agent was reading it")
	}
	if err != nil {
		return nil, err
	}
	defer body.Close()

	files, err := readExport(body, want)
	if err != nil {
		return nil, fmt.Errorf("reading the image: %w", err)
	}
	return parseSystem(files)
}

type platform struct {
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
}

// An export is the archive written by docker save. Both of its formats
// (Docker before 25, and OCI layouts since) include a manifest.json listing
// each image's layers in order, but it may come after the layers, so every
// layer is read as it streams past and the result assembled at the end.
type export struct {
	files       map[string]bool   // every regular file in the archive
	links       map[string]string // symbolic and hard links in the archive
	layers      map[string]*layer
	small       map[string][]byte
	unsupported map[string]error
	kept        int
}

// layer is what one layer does to the files we want.
type layer struct {
	files   map[string][]byte // a nil value replaces the file with something else
	deleted []string          // whiteouts: paths removed from lower layers
	opaque  []string          // directories whose lower contents are hidden
}

var (
	gzipMagic = []byte{0x1f, 0x8b}
	zstdMagic = []byte{0x28, 0xb5, 0x2f, 0xfd}
)

func readExport(r io.Reader, want platform) (map[string][]byte, error) {
	e := &export{
		files:       map[string]bool{},
		links:       map[string]string{},
		layers:      map[string]*layer{},
		small:       map[string][]byte{},
		unsupported: map[string]error{},
	}
	tr := tar.NewReader(r)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		name := cleanPath(h.Name)
		switch h.Typeflag {
		case tar.TypeSymlink:
			e.links[name] = cleanPath(path.Join(path.Dir(name), h.Linkname))
		case tar.TypeLink:
			e.links[name] = cleanPath(h.Linkname)
		case tar.TypeReg:
			e.files[name] = true
			if err := e.readEntry(name, h.Size, tr); err != nil {
				return nil, fmt.Errorf("%s: %w", name, err)
			}
		}
	}
	return e.assemble(want)
}

func (e *export) readEntry(name string, size int64, r io.Reader) error {
	br := bufio.NewReaderSize(r, 64<<10)
	head, _ := br.Peek(512)
	var rd io.Reader = br
	switch {
	case bytes.HasPrefix(head, gzipMagic):
		zr, err := gzip.NewReader(br)
		if err != nil {
			return err
		}
		defer zr.Close()
		zbr := bufio.NewReaderSize(zr, 64<<10)
		if head, _ = zbr.Peek(512); !isTar(head) {
			return nil // compressed, but not a layer: nothing we need
		}
		rd = zbr
	case bytes.HasPrefix(head, zstdMagic):
		e.unsupported[name] = errors.New("zstd-compressed layers are not supported yet")
		return nil
	}

	if isTar(head) {
		l, err := e.readLayer(tar.NewReader(rd))
		e.layers[name] = l
		return err
	}
	if size <= maxSmallBlob {
		data, err := io.ReadAll(rd)
		e.small[name] = data
		return err
	}
	return nil
}

// isTar recognises the POSIX and GNU tar magic in a header block.
func isTar(head []byte) bool {
	return len(head) >= 262 && bytes.Equal(head[257:262], []byte("ustar"))
}

func (e *export) readLayer(tr *tar.Reader) (*layer, error) {
	l := &layer{files: map[string][]byte{}}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return l, nil
		}
		if err != nil {
			return nil, err
		}
		p := cleanPath(h.Name)
		dir, base := path.Dir(p), path.Base(p)
		if dir == "." {
			dir = ""
		}
		switch {
		case base == ".wh..wh..opq":
			l.opaque = append(l.opaque, dir)
		case strings.HasPrefix(base, ".wh."):
			l.deleted = append(l.deleted, path.Join(dir, strings.TrimPrefix(base, ".wh.")))
		case !wanted(p):
		case h.Typeflag == tar.TypeReg && sqliteWAL(p):
			if h.Size > 0 {
				l.files[p] = []byte{} // present and not empty; never read
			} else {
				l.files[p] = nil
			}
		case h.Typeflag == tar.TypeReg:
			limit := int64(maxSystemFile)
			if _, ok := rpmDatabases[p]; ok {
				limit = maxRPMFile
			}
			if h.Size > limit {
				return nil, fmt.Errorf("/%s is %d bytes, more than the %d the agent reads", p, h.Size, limit)
			}
			if e.kept += int(h.Size); e.kept > maxSystemTotal {
				return nil, fmt.Errorf("package records exceed the %d bytes the agent reads per image", maxSystemTotal)
			}
			data, err := io.ReadAll(tr)
			if err != nil {
				return nil, err
			}
			l.files[p] = data
		case h.Typeflag == tar.TypeLink && l.files[cleanPath(h.Linkname)] != nil:
			l.files[p] = l.files[cleanPath(h.Linkname)]
		default:
			// A symbolic link or directory hides any lower file of that
			// name. A symlinked /etc/os-release falls back to
			// /usr/lib/os-release, its usual target.
			l.files[p] = nil
		}
	}
}

// assemble finds the image's layers and applies them in order, as Docker
// does when it creates a container's filesystem.
func (e *export) assemble(want platform) (map[string][]byte, error) {
	raw, ok := e.small["manifest.json"]
	if !ok {
		return nil, errors.New("the export has no manifest.json")
	}
	var manifests []struct {
		Config string
		Layers []string
	}
	if err := json.Unmarshal(raw, &manifests); err != nil {
		return nil, fmt.Errorf("manifest.json: %w", err)
	}

	// An export can list platforms whose layers are not on this server.
	var complete []int
	for i, m := range manifests {
		if e.hasAll(m.Layers) {
			complete = append(complete, i)
		}
	}
	if len(complete) > 1 {
		var matching []int
		for _, i := range complete {
			var p platform
			if json.Unmarshal(e.small[e.resolve(manifests[i].Config)], &p) == nil && p == want {
				matching = append(matching, i)
			}
		}
		complete = matching
	}
	switch len(complete) {
	case 0:
		return nil, errors.New("the export does not contain the image's layers")
	case 1:
	default:
		return nil, errors.New("the export contains several images for this platform")
	}

	files := map[string][]byte{}
	for _, name := range manifests[complete[0]].Layers {
		name = e.resolve(name)
		if err := e.unsupported[name]; err != nil {
			return nil, err
		}
		l := e.layers[name]
		if l == nil {
			continue // an empty layer
		}
		for _, dir := range l.opaque {
			removeUnder(files, dir, false)
		}
		for _, p := range l.deleted {
			removeUnder(files, p, true)
		}
		for p, data := range l.files {
			if data == nil {
				delete(files, p)
			} else {
				files[p] = data
			}
		}
	}
	return files, nil
}

func (e *export) hasAll(layers []string) bool {
	for _, name := range layers {
		if !e.files[e.resolve(name)] {
			return false
		}
	}
	return len(layers) > 0
}

// resolve follows links inside the archive: legacy exports link each
// <id>/layer.tar to the blob holding it.
func (e *export) resolve(name string) string {
	name = cleanPath(name)
	for range 8 {
		target, ok := e.links[name]
		if !ok {
			break
		}
		name = target
	}
	return name
}

// removeUnder deletes the files below dir and, if self is set, dir itself.
func removeUnder(files map[string][]byte, dir string, self bool) {
	for p := range files {
		if (self && p == dir) || strings.HasPrefix(p, dir+"/") || dir == "" {
			delete(files, p)
		}
	}
}

// cleanPath turns archive names such as "./etc/os-release" or
// "/etc/os-release" into "etc/os-release".
func cleanPath(name string) string {
	return strings.TrimPrefix(path.Clean("/"+name), "/")
}

func parseSystem(files map[string][]byte) (*report.ImageSystem, error) {
	s := &report.ImageSystem{Packages: []report.InstalledPackage{}}

	osRelease, ok := files[pathOSRelease]
	if !ok {
		osRelease, ok = files[pathOSReleaseLib]
	}
	if ok {
		var err error
		if s.OS, err = pkgdb.ParseOSRelease(bytes.NewReader(osRelease)); err != nil {
			return nil, fmt.Errorf("os-release: %w", err)
		}
	}

	var statusD []string
	for p := range files {
		if path.Dir(p) == dirDpkgStatusD {
			statusD = append(statusD, p)
		}
	}
	sort.Strings(statusD)
	status, hasDpkg := files[pathDpkgStatus]
	apk, hasApk := files[pathApkInstalled]
	hasDpkg = hasDpkg || len(statusD) > 0

	var rpmDBs []string
	for p := range rpmDatabases {
		if _, ok := files[p]; ok {
			rpmDBs = append(rpmDBs, p)
		}
	}
	sort.Strings(rpmDBs)
	hasRPM := len(rpmDBs) > 0

	managers := 0
	for _, has := range []bool{hasDpkg, hasApk, hasRPM} {
		if has {
			managers++
		}
	}

	switch {
	case managers > 1:
		return nil, errors.New("the image has the package records of several package managers")
	case hasRPM:
		s.PackageManager = report.PackageManagerRPM
		seen := map[report.InstalledPackage]bool{}
		for _, p := range rpmDBs {
			if _, ok := files[p+"-wal"]; ok {
				return nil, fmt.Errorf("/%s has changes not yet written to it (a non-empty -wal file); it cannot be read reliably", p)
			}
			pkgs, err := pkgdb.ParseRPMDB(files[p], rpmDatabases[p])
			if err != nil {
				return nil, fmt.Errorf("/%s: %w", p, err)
			}
			for _, pkg := range pkgs {
				if !seen[pkg] {
					seen[pkg] = true
					s.Packages = append(s.Packages, pkg)
				}
			}
		}
		pkgdb.Sort(s.Packages)
	case hasApk:
		s.PackageManager = report.PackageManagerApk
		pkgs, err := pkgdb.ParseApkInstalled(bytes.NewReader(apk))
		if err != nil {
			return nil, fmt.Errorf("/%s: %w", pathApkInstalled, err)
		}
		s.Packages = pkgs
	case hasDpkg:
		s.PackageManager = report.PackageManagerDpkg
		if status != nil {
			pkgs, err := pkgdb.ParseDpkgStatus(bytes.NewReader(status))
			if err != nil {
				return nil, fmt.Errorf("/%s: %w", pathDpkgStatus, err)
			}
			s.Packages = append(s.Packages, pkgs...)
		}
		for _, p := range statusD {
			pkgs, err := pkgdb.ParseDpkgStatusD(bytes.NewReader(files[p]))
			if err != nil {
				return nil, fmt.Errorf("/%s: %w", p, err)
			}
			s.Packages = append(s.Packages, pkgs...)
		}
		pkgdb.Sort(s.Packages)
	}
	return s, nil
}
