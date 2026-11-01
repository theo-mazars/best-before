package pkgdb

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/theo-mazars/best-before/internal/report"
)

// RPM keeps one header per installed package in its database, in one of
// three formats: SQLite (RHEL 9, Fedora, Amazon Linux 2023), BerkeleyDB
// (RHEL 8 and earlier, Amazon Linux 2) or its own NDB (SUSE). The readers in
// this package only read what is needed to list the headers, check every
// offset, and never follow a page twice: image contents are untrusted.

// RPMFormat names an RPM database format.
type RPMFormat int

const (
	RPMSQLite RPMFormat = iota
	RPMBerkeleyDB
	RPMNDB
)

// ParseRPMDB returns the packages recorded in an RPM database file.
func ParseRPMDB(data []byte, format RPMFormat) ([]report.InstalledPackage, error) {
	var headers [][]byte
	var err error
	switch format {
	case RPMSQLite:
		headers, err = sqlitePackageBlobs(data)
	case RPMBerkeleyDB:
		headers, err = bdbValues(data)
	case RPMNDB:
		headers, err = ndbBlobs(data)
	default:
		err = errors.New("unknown RPM database format")
	}
	if err != nil {
		return nil, err
	}

	pkgs := []report.InstalledPackage{}
	for _, h := range headers {
		p, err := parseRPMHeader(h)
		if err != nil {
			return nil, err
		}
		// The keys rpm trusts are recorded as pseudo-packages.
		if p.Name == "" || p.Name == "gpg-pubkey" {
			continue
		}
		pkgs = append(pkgs, p)
	}
	Sort(pkgs)
	return pkgs, nil
}

// RPM header tags and types used here.
const (
	rpmTagName            = 1000
	rpmTagVersion         = 1001
	rpmTagRelease         = 1002
	rpmTagEpoch           = 1003
	rpmTagArch            = 1022
	rpmTagSourceRPM       = 1044
	rpmTagModularityLabel = 5096

	rpmTypeInt32       = 4
	rpmTypeString      = 6
	rpmTypeI18NString  = 9
	rpmMaxIndexEntries = 0xffff
)

// parseRPMHeader reads a header as stored in the database: an index of
// (tag, type, offset, count) entries followed by the data they point into.
func parseRPMHeader(b []byte) (report.InstalledPackage, error) {
	var p report.InstalledPackage
	if len(b) < 8 {
		return p, errors.New("RPM header too short")
	}
	il := binary.BigEndian.Uint32(b[0:])
	dl := binary.BigEndian.Uint32(b[4:])
	if il > rpmMaxIndexEntries || uint64(dl) > uint64(len(b)) {
		return p, errors.New("RPM header has impossible sizes")
	}
	start := 8 + 16*uint64(il)
	end := start + uint64(dl)
	if end > uint64(len(b)) {
		return p, errors.New("RPM header is truncated")
	}
	index, data := b[8:start], b[start:end]

	var name, version, release, arch, source, module string
	var epoch *uint32
	for i := 0; i < int(il); i++ {
		e := index[16*i:]
		tag := binary.BigEndian.Uint32(e[0:])
		typ := binary.BigEndian.Uint32(e[4:])
		off := binary.BigEndian.Uint32(e[8:])
		if uint64(off) >= uint64(len(data)) {
			continue
		}
		str := func() string {
			if typ != rpmTypeString && typ != rpmTypeI18NString {
				return ""
			}
			s := data[off:]
			if i := bytes.IndexByte(s, 0); i >= 0 {
				s = s[:i]
			}
			return string(s)
		}
		switch tag {
		case rpmTagName:
			name = str()
		case rpmTagVersion:
			version = str()
		case rpmTagRelease:
			release = str()
		case rpmTagArch:
			arch = str()
		case rpmTagSourceRPM:
			source = str()
		case rpmTagModularityLabel:
			module = str()
		case rpmTagEpoch:
			if typ == rpmTypeInt32 && uint64(off)+4 <= uint64(len(data)) {
				v := binary.BigEndian.Uint32(data[off:])
				epoch = &v
			}
		}
	}

	p.Name = name
	p.Architecture = arch
	p.Module = module
	p.Version = version + "-" + release
	if epoch != nil {
		p.Version = strconv.FormatUint(uint64(*epoch), 10) + ":" + p.Version
	}
	p.Source, p.SourceVersion = name, p.Version
	if n, v, ok := parseSourceRPM(source); ok {
		p.Source, p.SourceVersion = n, v
	}
	return p, nil
}

// parseSourceRPM splits "openssl-3.0.7-27.el9.src.rpm" into its name and
// version-release.
func parseSourceRPM(s string) (name, version string, ok bool) {
	s, ok = strings.CutSuffix(s, ".src.rpm")
	if !ok {
		if s, ok = strings.CutSuffix(s, ".nosrc.rpm"); !ok {
			return "", "", false
		}
	}
	i := strings.LastIndexByte(s, '-')
	if i <= 0 {
		return "", "", false
	}
	j := strings.LastIndexByte(s[:i], '-')
	if j <= 0 {
		return "", "", false
	}
	return s[:j], s[j+1:], true
}

func errAt(what string, args ...any) error {
	return fmt.Errorf("RPM database: "+what, args...)
}
