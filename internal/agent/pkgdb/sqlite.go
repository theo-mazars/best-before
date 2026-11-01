package pkgdb

import (
	"encoding/binary"
)

// A read-only reader for just enough of the SQLite file format to list the
// rows of one table: https://www.sqlite.org/fileformat2.html. RPM stores
// each package as a row of Packages (hnum INTEGER PRIMARY KEY, blob BLOB).

type sqliteFile struct {
	data     []byte
	pageSize int
	usable   int
	pages    int
}

func openSQLite(data []byte) (*sqliteFile, error) {
	if len(data) < 100 || string(data[:16]) != "SQLite format 3\x00" {
		return nil, errAt("not an SQLite database")
	}
	ps := int(binary.BigEndian.Uint16(data[16:]))
	if ps == 1 {
		ps = 65536
	}
	if ps < 512 || ps&(ps-1) != 0 {
		return nil, errAt("invalid SQLite page size %d", ps)
	}
	usable := ps - int(data[20])
	if usable < 480 {
		return nil, errAt("invalid SQLite reserved space")
	}
	return &sqliteFile{data: data, pageSize: ps, usable: usable, pages: len(data) / ps}, nil
}

func (f *sqliteFile) page(n uint32) ([]byte, error) {
	if n < 1 || int64(n) > int64(f.pages) {
		return nil, errAt("SQLite page %d out of range", n)
	}
	start := int(n-1) * f.pageSize
	return f.data[start : start+f.pageSize], nil
}

// rows calls fn with the record of every row of the table rooted at root.
func (f *sqliteFile) rows(root uint32, fn func(record []byte) error) error {
	visited := map[uint32]bool{}
	stack := []uint32{root}
	for len(stack) > 0 {
		n := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if visited[n] {
			return errAt("SQLite page %d is linked twice", n)
		}
		visited[n] = true
		p, err := f.page(n)
		if err != nil {
			return err
		}
		h := 0
		if n == 1 {
			h = 100 // the file header comes first
		}
		if h+12 > len(p) {
			return errAt("SQLite page %d too short", n)
		}
		cells := int(binary.BigEndian.Uint16(p[h+3:]))
		switch p[h] {
		case 0x05: // interior table page
			ptrs := h + 12
			if ptrs+2*cells > len(p) {
				return errAt("SQLite page %d has too many cells", n)
			}
			for i := range cells {
				off := int(binary.BigEndian.Uint16(p[ptrs+2*i:]))
				if off+4 > len(p) {
					return errAt("SQLite cell out of page %d", n)
				}
				stack = append(stack, binary.BigEndian.Uint32(p[off:]))
			}
			stack = append(stack, binary.BigEndian.Uint32(p[h+8:]))
		case 0x0d: // leaf table page
			ptrs := h + 8
			if ptrs+2*cells > len(p) {
				return errAt("SQLite page %d has too many cells", n)
			}
			for i := range cells {
				off := int(binary.BigEndian.Uint16(p[ptrs+2*i:]))
				if off >= len(p) {
					return errAt("SQLite cell out of page %d", n)
				}
				size, a := sqliteVarint(p[off:])
				_, b := sqliteVarint(p[off+a:]) // rowid
				if a == 0 || b == 0 {
					return errAt("SQLite cell damaged on page %d", n)
				}
				rec, err := f.payload(p, off+a+b, size, visited)
				if err != nil {
					return err
				}
				if err := fn(rec); err != nil {
					return err
				}
			}
		default:
			return errAt("SQLite page %d is not a table page", n)
		}
	}
	return nil
}

// payload returns a cell's payload, following overflow pages if it spills.
func (f *sqliteFile) payload(p []byte, start int, size uint64, visited map[uint32]bool) ([]byte, error) {
	if size > uint64(len(f.data)) || start > len(p) {
		return nil, errAt("SQLite payload too large")
	}
	u := f.usable
	total := int(size)
	local := total
	if maxLocal := u - 35; total > maxLocal {
		minLocal := (u-12)*32/255 - 23
		local = minLocal + (total-minLocal)%(u-4)
		if local > maxLocal {
			local = minLocal
		}
	}
	if start+local > len(p) {
		return nil, errAt("SQLite payload out of page")
	}
	out := append(make([]byte, 0, total), p[start:start+local]...)
	if local == total {
		return out, nil
	}
	if start+local+4 > len(p) {
		return nil, errAt("SQLite overflow pointer out of page")
	}
	next := binary.BigEndian.Uint32(p[start+local:])
	for len(out) < total {
		if visited[next] {
			return nil, errAt("SQLite page %d is linked twice", next)
		}
		visited[next] = true
		op, err := f.page(next)
		if err != nil {
			return nil, err
		}
		take := min(u-4, total-len(out))
		out = append(out, op[4:4+take]...)
		next = binary.BigEndian.Uint32(op)
	}
	return out, nil
}

// sqliteVarint decodes SQLite's big-endian variable-length integer. It
// returns 0 bytes read if b is too short.
func sqliteVarint(b []byte) (uint64, int) {
	var v uint64
	for i := 0; i < 9; i++ {
		if i >= len(b) {
			return 0, 0
		}
		if i == 8 {
			return v<<8 | uint64(b[i]), 9
		}
		v = v<<7 | uint64(b[i]&0x7f)
		if b[i]&0x80 == 0 {
			return v, i + 1
		}
	}
	return v, 9
}

// sqliteColumn is one value of a record: text and blobs as bytes, integers
// as int.
type sqliteColumn struct {
	null  bool
	bytes []byte
	int   int64
}

func sqliteRecord(rec []byte) ([]sqliteColumn, error) {
	hdrLen, n := sqliteVarint(rec)
	if n == 0 || hdrLen > uint64(len(rec)) || hdrLen < uint64(n) {
		return nil, errAt("SQLite record damaged")
	}
	var types []uint64
	for pos := n; pos < int(hdrLen); {
		t, k := sqliteVarint(rec[pos:int(hdrLen)])
		if k == 0 {
			return nil, errAt("SQLite record damaged")
		}
		types = append(types, t)
		pos += k
	}
	cols := make([]sqliteColumn, 0, len(types))
	body := rec[hdrLen:]
	for _, t := range types {
		var size uint64
		switch {
		case t == 0, t == 8, t == 9:
			size = 0
		case t >= 1 && t <= 4:
			size = t
		case t == 5:
			size = 6
		case t == 6, t == 7:
			size = 8
		case t >= 12:
			size = (t - 12) / 2
		default:
			return nil, errAt("SQLite record has reserved type %d", t)
		}
		if size > uint64(len(body)) {
			return nil, errAt("SQLite record truncated")
		}
		v, rest := body[:size], body[size:]
		body = rest
		c := sqliteColumn{}
		switch {
		case t == 0:
			c.null = true
		case t == 8:
			c.int = 0
		case t == 9:
			c.int = 1
		case t >= 1 && t <= 6:
			var x int64
			for _, b := range v {
				x = x<<8 | int64(b)
			}
			// Sign-extend.
			shift := 64 - 8*len(v)
			c.int = x << shift >> shift
		case t >= 12:
			c.bytes = v
		}
		cols = append(cols, c)
	}
	return cols, nil
}

// sqlitePackageBlobs returns the blob of every row of RPM's Packages table.
func sqlitePackageBlobs(data []byte) ([][]byte, error) {
	f, err := openSQLite(data)
	if err != nil {
		return nil, err
	}
	var root uint32
	err = f.rows(1, func(rec []byte) error {
		cols, err := sqliteRecord(rec)
		if err != nil {
			return err
		}
		// sqlite_schema: type, name, tbl_name, rootpage, sql
		if len(cols) >= 4 && string(cols[0].bytes) == "table" && string(cols[1].bytes) == "Packages" {
			if cols[3].int <= 0 || cols[3].int > int64(f.pages) {
				return errAt("Packages table has an invalid root page")
			}
			root = uint32(cols[3].int)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if root == 0 {
		return nil, errAt("no Packages table")
	}
	var blobs [][]byte
	err = f.rows(root, func(rec []byte) error {
		cols, err := sqliteRecord(rec)
		if err != nil {
			return err
		}
		if len(cols) < 2 || cols[1].bytes == nil {
			return errAt("Packages row without a header")
		}
		blobs = append(blobs, cols[1].bytes)
		return nil
	})
	return blobs, err
}
