package pkgdb

import (
	"encoding/binary"
)

// A read-only reader for BerkeleyDB hash databases, as RPM used before
// SQLite. Every value of the database is returned; for RPM's Packages file,
// each one is a package header, too large to fit on the hash page, so stored
// in a chain of overflow pages.

const (
	bdbHashMagic       = 0x061561
	bdbPageHash        = 13 // P_HASH
	bdbPageHashUnsort  = 2  // P_HASH_UNSORTED
	bdbPageOverflow    = 7  // P_OVERFLOW
	bdbEntryOffPage    = 3  // H_OFFPAGE
	bdbPageHeaderBytes = 26
)

func bdbValues(data []byte) ([][]byte, error) {
	if len(data) < 512 {
		return nil, errAt("BerkeleyDB file too short")
	}
	// The metadata page says which byte order the file was written in.
	var order binary.ByteOrder = binary.LittleEndian
	if order.Uint32(data[12:]) != bdbHashMagic {
		order = binary.BigEndian
		if order.Uint32(data[12:]) != bdbHashMagic {
			return nil, errAt("not a BerkeleyDB hash database")
		}
	}
	ps := int(order.Uint32(data[20:]))
	if ps < 512 || ps > 65536 || ps&(ps-1) != 0 {
		return nil, errAt("invalid BerkeleyDB page size %d", ps)
	}
	if data[24] != 0 {
		return nil, errAt("encrypted BerkeleyDB databases are not supported")
	}
	pages := len(data) / ps
	page := func(n uint32) []byte {
		if n == 0 || int64(n) >= int64(pages) {
			return nil
		}
		return data[int(n)*ps : int(n+1)*ps]
	}

	var values [][]byte
	used := map[uint32]bool{}
	for n := 1; n < pages; n++ {
		p := page(uint32(n))
		if t := p[25]; t != bdbPageHash && t != bdbPageHashUnsort {
			continue
		}
		entries := int(order.Uint16(p[20:]))
		if bdbPageHeaderBytes+2*entries > len(p) {
			return nil, errAt("BerkeleyDB page %d has too many entries", n)
		}
		// Entries alternate key, value.
		for i := 1; i < entries; i += 2 {
			off := int(order.Uint16(p[bdbPageHeaderBytes+2*i:]))
			if off+12 > len(p) || p[off] != bdbEntryOffPage {
				continue
			}
			next := order.Uint32(p[off+4:])
			length := int(order.Uint32(p[off+8:]))
			if length > len(data) {
				return nil, errAt("BerkeleyDB value too large")
			}
			v := make([]byte, 0, length)
			for len(v) < length {
				if used[next] {
					return nil, errAt("BerkeleyDB page %d is linked twice", next)
				}
				used[next] = true
				op := page(next)
				if op == nil || op[25] != bdbPageOverflow {
					return nil, errAt("BerkeleyDB overflow chain broken")
				}
				// For overflow pages, the free-area offset holds the length
				// of the data on the page.
				n := int(order.Uint16(op[22:]))
				if bdbPageHeaderBytes+n > len(op) {
					return nil, errAt("BerkeleyDB overflow page damaged")
				}
				v = append(v, op[bdbPageHeaderBytes:bdbPageHeaderBytes+min(n, length-len(v))]...)
				next = order.Uint32(op[16:])
				if next == 0 {
					break
				}
			}
			if len(v) != length {
				return nil, errAt("BerkeleyDB value truncated")
			}
			values = append(values, v)
		}
	}
	return values, nil
}
