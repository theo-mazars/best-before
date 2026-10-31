package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/theo-mazars/best-before/internal/agent/docker"
	"github.com/theo-mazars/best-before/internal/report"
)

// imageCache keeps what was read inside each image in the state directory,
// one file per image ID, so that an image is exported once rather than on
// every run. Failing to use it only makes the run slower, so its errors are
// ignored.
type imageCache struct {
	dir string
}

type cachedImage struct {
	Reader int                 `json:"reader"`
	System *report.ImageSystem `json:"system"`
}

var imageIDPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

func (c imageCache) path(imageID string) (string, bool) {
	if !imageIDPattern.MatchString(imageID) {
		return "", false
	}
	return filepath.Join(c.dir, strings.TrimPrefix(imageID, "sha256:")+".json"), true
}

func (c imageCache) Get(imageID string) *report.ImageSystem {
	p, ok := c.path(imageID)
	if !ok {
		return nil
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return nil
	}
	var entry cachedImage
	if json.Unmarshal(data, &entry) != nil || entry.Reader != docker.SystemReaderVersion || entry.System == nil {
		return nil
	}
	return entry.System
}

func (c imageCache) Put(imageID string, s *report.ImageSystem) {
	p, ok := c.path(imageID)
	if !ok {
		return
	}
	data, err := json.Marshal(cachedImage{Reader: docker.SystemReaderVersion, System: s})
	if err != nil || os.MkdirAll(c.dir, 0o700) != nil {
		return
	}
	writeFileAtomic(p, data, 0o600)
}

// keepOnly forgets images that are no longer in use.
func (c imageCache) keepOnly(images []report.Image) {
	keep := map[string]bool{}
	for _, img := range images {
		if p, ok := c.path(img.ID); ok {
			keep[filepath.Base(p)] = true
		}
	}
	entries, err := os.ReadDir(c.dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !keep[e.Name()] {
			os.Remove(filepath.Join(c.dir, e.Name()))
		}
	}
}
