package docker

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"regexp"
)

// Go copies its standard library into every program it builds, so a Go
// program is only as safe as the Go version that built it. Go records that
// version in a build information block: a 32-byte header starting with
// goBuildInfoMagic, 16-byte aligned, followed since Go 1.18 by the version
// as a length-prefixed string. Older programs point to it with memory
// addresses instead, which only a full executable parser can resolve; they
// are reported with an empty version.
//
// goVersion scans a program as it streams past, holding at most one chunk,
// since Go programs can be hundreds of megabytes. The magic also appears as a
// constant in programs that read build information themselves, such as the go
// command, so a candidate only counts if what follows it is valid.

var goBuildInfoMagic = []byte("\xff Go buildinf:")

const (
	goBuildInfoHeader = 32
	goBuildInfoAlign  = 16
	goFlagVersionInl  = 2  // the version is stored inline (Go 1.18 and later)
	goMaxVersionLen   = 64 // e.g. "go1.23.4 X:boringcrypto"
	goChunk           = 256 << 10
	// Enough bytes after a candidate to read the header and the version.
	goLookahead = goBuildInfoHeader + binary.MaxVarintLen64 + goMaxVersionLen
)

var goVersionPattern = regexp.MustCompile(`^go1\.\d+(\.\d+)?((rc|beta)\d+)?( X:[a-z0-9,]+)?$`)

var errNotGo = errors.New("not a Go program")

// goVersion returns the Go version a program was built with, "" for a Go
// program built before Go 1.18, or errNotGo.
func goVersion(r io.Reader) (string, error) {
	buf := make([]byte, 0, goChunk+goLookahead)
	var base int64 // file offset of buf[0]
	old := false
	eof := false
	for {
		if !eof {
			n, err := io.ReadFull(r, buf[len(buf):cap(buf)])
			buf = buf[:len(buf)+n]
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				eof = true
			} else if err != nil {
				return "", err
			}
		}
		// Every candidate whose lookahead is complete (or the file ends).
		limit := len(buf)
		if !eof {
			limit = len(buf) - goLookahead
		}
		for i := 0; i < limit; {
			j := bytes.Index(buf[i:], goBuildInfoMagic)
			if j < 0 || i+j >= limit {
				break
			}
			at := i + j
			i = at + 1
			if (base+int64(at))%goBuildInfoAlign != 0 {
				continue
			}
			switch v, ok := parseGoBuildInfo(buf[at:]); {
			case ok && v != "":
				return v, nil
			case ok:
				old = true // keep looking: a newer-style block wins
			}
		}
		if eof {
			if old {
				return "", nil
			}
			return "", errNotGo
		}
		// Keep the tail, where a candidate may still be completed.
		keep := buf[limit:]
		base += int64(limit)
		buf = append(buf[:0], keep...)
	}
}

// parseGoBuildInfo checks a candidate header. It returns the version, or ""
// with ok for a valid header of a Go version before 1.18.
func parseGoBuildInfo(b []byte) (string, bool) {
	if len(b) < goBuildInfoHeader {
		return "", false
	}
	ptrSize, flags := b[14], b[15]
	if ptrSize != 4 && ptrSize != 8 || flags&^3 != 0 {
		return "", false
	}
	if flags&goFlagVersionInl == 0 {
		return "", true
	}
	n, k := binary.Uvarint(b[goBuildInfoHeader:])
	if k <= 0 || n == 0 || n > goMaxVersionLen || uint64(len(b)) < uint64(goBuildInfoHeader+k)+n {
		return "", false
	}
	v := string(b[goBuildInfoHeader+k : goBuildInfoHeader+k+int(n)])
	if !goVersionPattern.MatchString(v) {
		return "", false
	}
	return v, true
}

// isELF reports whether a file starts like a Linux executable.
func isELF(head []byte) bool {
	return len(head) >= 4 && string(head[:4]) == "\x7fELF"
}
