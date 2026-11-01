package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/theo-mazars/best-before/internal/report"
)

func TestImageCache(t *testing.T) {
	c := imageCache{dir: filepath.Join(t.TempDir(), "images")}
	a := "sha256:" + strings.Repeat("a", 64)
	b := "sha256:" + strings.Repeat("b", 64)
	sys := &report.ImageSystem{OS: report.OS{ID: "alpine"}, PackageManager: "apk", Packages: []report.InstalledPackage{}}

	if c.Get(a) != nil {
		t.Fatal("empty cache returned an entry")
	}
	c.Put(a, sys)
	c.Put(b, sys)
	if got := c.Get(a); got == nil || got.OS.ID != "alpine" {
		t.Fatalf("got %+v", got)
	}

	// Entries from another version of the reader are read again.
	path, _ := c.path(a)
	os.WriteFile(path, []byte(`{"reader":0,"system":{"os":{"id":"old"}}}`), 0o600)
	if c.Get(a) != nil {
		t.Error("entry from an older reader was used")
	}

	// IDs that are not image digests never become file names.
	c.Put("sha256:../../agent", sys)
	if _, ok := c.path("sha256:../../agent"); ok {
		t.Error("invalid image ID accepted")
	}

	c.keepOnly([]report.Image{{ID: b}})
	entries, _ := os.ReadDir(c.dir)
	if len(entries) != 1 || c.Get(b) == nil {
		t.Errorf("after keepOnly: %v", entries)
	}
}
