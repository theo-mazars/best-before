package pkgdb

import (
	"encoding/binary"
)

// A reader for RPM's own NDB format (Packages.db, used by SUSE): a header,
// then pages of 16-byte slots, each pointing to a blob holding one package
// header. NDB is always little-endian.

const (
	ndbHeaderMagic  = 'R' | 'p'<<8 | 'm'<<16 | 'P'<<24
	ndbSlotMagic    = 'S' | 'l'<<8 | 'o'<<16 | 't'<<24
	ndbBlobMagic    = 'B' | 'l'<<8 | 'b'<<16 | 'S'<<24
	ndbSlotPageSize = 4096
	ndbBlockSize    = 16
)

func ndbBlobs(data []byte) ([][]byte, error) {
	le := binary.LittleEndian
	if len(data) < 32 || le.Uint32(data) != ndbHeaderMagic {
		return nil, errAt("not an NDB database")
	}
	if v := le.Uint32(data[4:]); v != 0 {
		return nil, errAt("unsupported NDB version %d", v)
	}
	slotPages := uint64(le.Uint32(data[12:]))
	end := slotPages * ndbSlotPageSize
	if end > uint64(len(data)) {
		return nil, errAt("NDB slot pages beyond the end of the file")
	}

	var blobs [][]byte
	// The header takes the first two slots.
	for off := uint64(32); off+16 <= end; off += 16 {
		s := data[off:]
		pkg := le.Uint32(s[4:])
		if le.Uint32(s) != ndbSlotMagic || pkg == 0 {
			continue
		}
		at := uint64(le.Uint32(s[8:])) * ndbBlockSize
		if at+16 > uint64(len(data)) {
			return nil, errAt("NDB slot points beyond the end of the file")
		}
		b := data[at:]
		if le.Uint32(b) != ndbBlobMagic || le.Uint32(b[4:]) != pkg {
			return nil, errAt("NDB blob for package %d damaged", pkg)
		}
		n := uint64(le.Uint32(b[12:]))
		if at+16+n > uint64(len(data)) {
			return nil, errAt("NDB blob truncated")
		}
		blobs = append(blobs, data[at+16:at+16+n])
	}
	return blobs, nil
}
