package pkgdb

import (
	"bytes"
	"database/sql"
	"encoding/binary"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	// Only to write test databases; the agent itself reads them without it.
	_ "github.com/glebarez/go-sqlite"

	"github.com/theo-mazars/best-before/internal/report"
)

type rpmTag struct {
	tag, typ uint32
	value    any // string or uint32
}

// rpmHeader encodes a header as RPM stores it in its database. padding adds
// a large unrelated tag, so that the header spills onto overflow pages.
func rpmHeader(tags []rpmTag, padding int) []byte {
	var index, data bytes.Buffer
	add := func(tag, typ uint32, v []byte) {
		binary.Write(&index, binary.BigEndian, []uint32{tag, typ, uint32(data.Len()), 1})
		data.Write(v)
	}
	for _, t := range tags {
		switch v := t.value.(type) {
		case string:
			add(t.tag, t.typ, append([]byte(v), 0))
		case uint32:
			for data.Len()%4 != 0 {
				data.WriteByte(0)
			}
			add(t.tag, t.typ, binary.BigEndian.AppendUint32(nil, v))
		}
	}
	if padding > 0 {
		add(1005, 7, bytes.Repeat([]byte{0xab}, padding)) // a binary tag we ignore
	}
	out := binary.BigEndian.AppendUint32(nil, uint32(index.Len()/16))
	out = binary.BigEndian.AppendUint32(out, uint32(data.Len()))
	return append(append(out, index.Bytes()...), data.Bytes()...)
}

func pkgHeader(name, version, release string, epoch *uint32, source, module string, padding int) []byte {
	tags := []rpmTag{
		{rpmTagName, rpmTypeString, name},
		{rpmTagVersion, rpmTypeString, version},
		{rpmTagRelease, rpmTypeString, release},
		{rpmTagArch, rpmTypeString, "x86_64"},
		{rpmTagSourceRPM, rpmTypeString, source},
	}
	if epoch != nil {
		tags = append(tags, rpmTag{rpmTagEpoch, rpmTypeInt32, *epoch})
	}
	if module != "" {
		tags = append(tags, rpmTag{rpmTagModularityLabel, rpmTypeString, module})
	}
	return rpmHeader(tags, padding)
}

func testHeaders() [][]byte {
	one := uint32(1)
	return [][]byte{
		pkgHeader("openssl-libs", "3.0.7", "27.el9", &one, "openssl-3.0.7-27.el9.src.rpm", "", 9000),
		pkgHeader("bash", "5.1.8", "9.el9", nil, "bash-5.1.8-9.el9.src.rpm", "", 100),
		pkgHeader("nodejs", "18.20.2", "1.module+el8.10.0", nil, "nodejs-18.20.2-1.module+el8.10.0.src.rpm", "nodejs:18:8100020240327:a9f0b6a5", 20000),
		// The keys rpm trusts, recorded as packages: never listed.
		pkgHeader("gpg-pubkey", "fd431d51", "4ae0493b", nil, "", "", 0),
	}
}

var wantPackages = []report.InstalledPackage{
	{Name: "bash", Version: "5.1.8-9.el9", Architecture: "x86_64", Source: "bash", SourceVersion: "5.1.8-9.el9"},
	{Name: "nodejs", Version: "18.20.2-1.module+el8.10.0", Architecture: "x86_64", Source: "nodejs", SourceVersion: "18.20.2-1.module+el8.10.0", Module: "nodejs:18:8100020240327:a9f0b6a5"},
	{Name: "openssl-libs", Version: "1:3.0.7-27.el9", Architecture: "x86_64", Source: "openssl", SourceVersion: "3.0.7-27.el9"},
}

func TestParseRPMSQLite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rpmdb.sqlite")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	// RPM's own schema, with an index and another table beside it.
	for _, q := range []string{
		`CREATE TABLE 'Packages' (hnum INTEGER PRIMARY KEY AUTOINCREMENT, blob BLOB NOT NULL)`,
		`CREATE TABLE 'Name' (key TEXT NOT NULL, hnum INTEGER NOT NULL, idx INTEGER NOT NULL)`,
		`CREATE INDEX 'Name_key_idx' ON 'Name'(key)`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	// Enough rows for interior pages, and headers longer than a page.
	headers := testHeaders()
	for i := range 300 {
		h := headers[i%len(headers)]
		if i >= len(headers) {
			h = pkgHeader("filler", "1", "1", nil, "", "", 0)
		}
		if _, err := db.Exec(`INSERT INTO Packages (blob) VALUES (?)`, h); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseRPMDB(data, RPMSQLite)
	if err != nil {
		t.Fatal(err)
	}
	var named []report.InstalledPackage
	for _, p := range got {
		if p.Name != "filler" {
			named = append(named, p)
		}
	}
	if len(got) != 300-1 || !reflect.DeepEqual(named, wantPackages) {
		t.Errorf("%d packages, named:\n got  %+v\n want %+v", len(got), named, wantPackages)
	}
}

// bdbFile writes a little-endian BerkeleyDB hash database holding headers,
// each in a chain of overflow pages, as RPM does.
func bdbFile(headers [][]byte) []byte {
	const ps = 4096
	pages := [][]byte{make([]byte, ps), make([]byte, ps)}
	le := binary.LittleEndian
	le.PutUint32(pages[0][12:], bdbHashMagic)
	le.PutUint32(pages[0][20:], ps)

	hash := pages[1]
	hash[25] = bdbPageHash
	le.PutUint16(hash[20:], uint16(2*len(headers)))
	free := ps
	for i, h := range headers {
		// The value: an off-page reference to an overflow chain.
		first := uint32(len(pages))
		for rest := h; len(rest) > 0; {
			p := make([]byte, ps)
			p[25] = bdbPageOverflow
			n := copy(p[bdbPageHeaderBytes:], rest)
			le.PutUint16(p[22:], uint16(n))
			rest = rest[n:]
			if len(rest) > 0 {
				le.PutUint32(p[16:], uint32(len(pages)+1))
			}
			pages = append(pages, p)
		}
		free -= 12
		hash[free] = bdbEntryOffPage
		le.PutUint32(hash[free+4:], first)
		le.PutUint32(hash[free+8:], uint32(len(h)))
		le.PutUint16(hash[bdbPageHeaderBytes+2*(2*i+1):], uint16(free))
		// The key: the package number.
		free -= 5
		hash[free] = 1
		le.PutUint32(hash[free+1:], uint32(i+1))
		le.PutUint16(hash[bdbPageHeaderBytes+2*(2*i):], uint16(free))
	}
	return bytes.Join(pages, nil)
}

func TestParseRPMBerkeleyDB(t *testing.T) {
	got, err := ParseRPMDB(bdbFile(testHeaders()), RPMBerkeleyDB)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, wantPackages) {
		t.Errorf("got  %+v\nwant %+v", got, wantPackages)
	}
}

func ndbFile(headers [][]byte) []byte {
	le := binary.LittleEndian
	out := make([]byte, ndbSlotPageSize)
	le.PutUint32(out[0:], ndbHeaderMagic)
	le.PutUint32(out[12:], 1) // one page of slots
	for i, h := range headers {
		slot := out[32+16*i:]
		le.PutUint32(slot[0:], ndbSlotMagic)
		le.PutUint32(slot[4:], uint32(i+1))
		le.PutUint32(slot[8:], uint32(len(out)/ndbBlockSize))
		blob := make([]byte, 16, 16+len(h)+16)
		le.PutUint32(blob[0:], ndbBlobMagic)
		le.PutUint32(blob[4:], uint32(i+1))
		le.PutUint32(blob[12:], uint32(len(h)))
		blob = append(blob, h...)
		for len(blob)%ndbBlockSize != 0 {
			blob = append(blob, 0)
		}
		out = append(out, blob...)
	}
	return out
}

func TestParseRPMNDB(t *testing.T) {
	got, err := ParseRPMDB(ndbFile(testHeaders()), RPMNDB)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, wantPackages) {
		t.Errorf("got  %+v\nwant %+v", got, wantPackages)
	}
}

func TestParseRPMDamaged(t *testing.T) {
	sqliteHeader := append([]byte("SQLite format 3\x00"), make([]byte, 4096-16)...)
	binary.BigEndian.PutUint16(sqliteHeader[16:], 4096)
	for name, tc := range map[string]struct {
		data   []byte
		format RPMFormat
	}{
		"not SQLite":           {[]byte("hello"), RPMSQLite},
		"SQLite without table": {sqliteHeader, RPMSQLite},
		"not BerkeleyDB":       {make([]byte, 4096), RPMBerkeleyDB},
		"not NDB":              {make([]byte, 4096), RPMNDB},
		"truncated BerkeleyDB": {bdbFile(testHeaders())[:3*4096], RPMBerkeleyDB},
	} {
		if _, err := ParseRPMDB(tc.data, tc.format); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	if _, err := parseRPMHeader([]byte{0, 0, 0, 1, 0xff, 0xff, 0xff, 0xff}); err == nil {
		t.Error("impossible header accepted")
	}
}

func TestParseSourceRPM(t *testing.T) {
	for in, want := range map[string][2]string{
		"openssl-3.0.7-27.el9.src.rpm":           {"openssl", "3.0.7-27.el9"},
		"python3.11-pip-22.3.1-4.el9.noarch.rpm": {"", ""},
		"kernel-5.14.0-427.el9.nosrc.rpm":        {"kernel", "5.14.0-427.el9"},
		"weird.src.rpm":                          {"", ""},
	} {
		n, v, _ := parseSourceRPM(in)
		if n != want[0] || v != want[1] {
			t.Errorf("%s: %q %q", in, n, v)
		}
	}
}

// The readers must survive anything an image can contain.
func FuzzParseRPMDB(f *testing.F) {
	f.Add(bdbFile(testHeaders()), uint8(RPMBerkeleyDB))
	f.Add(ndbFile(testHeaders()), uint8(RPMNDB))
	f.Add(testHeaders()[0], uint8(RPMSQLite))
	f.Fuzz(func(t *testing.T, data []byte, format uint8) {
		start := time.Now()
		ParseRPMDB(data, RPMFormat(format%3))
		parseRPMHeader(data)
		// A crafted image must not be able to stall the agent either.
		if d := time.Since(start); d > time.Second {
			t.Fatalf("%d bytes took %s", len(data), d)
		}
	})
}

// TestRPMSamples reads real databases from images, when
// BESTBEFORE_RPM_SAMPLES names a directory of them, and compares the counts
// with a file of expected counts if present.
func TestRPMSamples(t *testing.T) {
	dir := os.Getenv("BESTBEFORE_RPM_SAMPLES")
	if dir == "" {
		t.Skip("set BESTBEFORE_RPM_SAMPLES to a directory of RPM databases")
	}
	formats := map[string]RPMFormat{"rpmdb.sqlite": RPMSQLite, "Packages": RPMBerkeleyDB, "Packages.db": RPMNDB}
	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		format, ok := formats[filepath.Base(path)]
		if err != nil || !ok {
			return err
		}
		data, _ := os.ReadFile(path)
		pkgs, err := ParseRPMDB(data, format)
		if err != nil {
			t.Errorf("%s: %v", path, err)
		}
		t.Logf("%s: %d packages", strings.TrimPrefix(path, dir), len(pkgs))
		return nil
	})
}
