package docker

import (
	"context"
	"errors"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/theo-mazars/best-before/internal/report"
)

const (
	labelComposeProject = "com.docker.compose.project"
	labelComposeService = "com.docker.compose.service"
)

// Cache keeps what was read inside images between runs. Image contents never
// change for a given image ID, so each image only needs reading once.
type Cache interface {
	Get(imageID string) *report.ImageSystem
	Put(imageID string, s *report.ImageSystem)
}

type noCache struct{}

func (noCache) Get(string) *report.ImageSystem  { return nil }
func (noCache) Put(string, *report.ImageSystem) {}

// Collect lists running containers and the images they use, and reads each
// image's package records. If listing fails, it reports Docker as
// unavailable with the reason rather than returning a partial list that
// could pass for a complete one. An image that cannot be read is reported
// with the reason, and the others are still read. cache may be nil.
func Collect(ctx context.Context, c *Client, cache Cache) report.Docker {
	if cache == nil {
		cache = noCache{}
	}
	d, err := collect(ctx, c, cache)
	if err != nil {
		return report.Docker{
			Available:  false,
			Error:      err.Error(),
			Containers: []report.Container{},
			Images:     []report.Image{},
		}
	}
	return d
}

func collect(ctx context.Context, c *Client, cache Cache) (report.Docker, error) {
	d := report.Docker{
		Available:  true,
		Containers: []report.Container{},
		Images:     []report.Image{},
	}

	var version struct{ Version string }
	if err := c.get(ctx, "/version", &version); err != nil {
		return d, err
	}
	d.EngineVersion = version.Version

	// Without ?all=1 only running containers are listed.
	var list []struct {
		ID string `json:"Id"`
	}
	if err := c.get(ctx, "/containers/json", &list); err != nil {
		return d, err
	}

	imageIDs := map[string]bool{}
	for _, item := range list {
		var inspect struct {
			ID      string `json:"Id"`
			Name    string
			Image   string
			Created string
			Config  struct {
				Image  string
				Labels map[string]string
			}
		}
		err := c.get(ctx, "/containers/"+url.PathEscape(item.ID)+"/json", &inspect)
		if errors.Is(err, errNotFound) {
			continue // stopped and removed since we listed it
		}
		if err != nil {
			return d, err
		}
		d.Containers = append(d.Containers, report.Container{
			ID:             inspect.ID,
			Name:           strings.TrimPrefix(inspect.Name, "/"),
			Image:          inspect.Config.Image,
			ImageID:        inspect.Image,
			CreatedAt:      parseTime(inspect.Created),
			ComposeProject: inspect.Config.Labels[labelComposeProject],
			ComposeService: inspect.Config.Labels[labelComposeService],
		})
		imageIDs[inspect.Image] = true
	}

	for id := range imageIDs {
		var inspect struct {
			ID           string `json:"Id"`
			RepoTags     []string
			RepoDigests  []string
			Created      string
			Os           string
			Architecture string
			Config       struct{ Env []string }
		}
		err := c.get(ctx, "/images/"+url.PathEscape(id)+"/json", &inspect)
		if errors.Is(err, errNotFound) {
			continue // removed after the container was created; nothing to scan
		}
		if err != nil {
			return d, err
		}
		img := report.Image{
			ID:           inspect.ID,
			RepoTags:     orEmpty(inspect.RepoTags),
			RepoDigests:  orEmpty(inspect.RepoDigests),
			CreatedAt:    parseTime(inspect.Created),
			OS:           inspect.Os,
			Architecture: inspect.Architecture,
			Versions:     versionVariables(inspect.Config.Env),
			System:       cache.Get(inspect.ID),
		}
		if img.System == nil {
			img.System, err = readSystem(ctx, c, inspect.ID, platform{inspect.Os, inspect.Architecture})
			if err != nil {
				if ctx.Err() != nil {
					return d, ctx.Err()
				}
				img.SystemError = err.Error()
			} else {
				cache.Put(inspect.ID, img.System)
			}
		}
		d.Images = append(d.Images, img)
	}

	sort.Slice(d.Containers, func(i, j int) bool { return d.Containers[i].Name < d.Containers[j].Name })
	sort.Slice(d.Images, func(i, j int) bool { return d.Images[i].ID < d.Images[j].ID })
	return d, nil
}

// Limits on what versionVariables keeps from an image.
const (
	maxVersionVariables = 32
	maxVersionLength    = 128
)

var versionName = regexp.MustCompile(`^[A-Z][A-Z0-9_]*_VERSION$`)

// versionVariables returns the image's environment variables named
// *_VERSION, such as NODE_VERSION=22.11.0. Official images set them for
// software installed without the package manager (Node, Python, PHP, Redis
// and others built from source or downloaded), which the package list cannot
// show. Images built FROM them inherit the variables. Other variables are
// never read, as they may hold secrets.
func versionVariables(env []string) []report.VersionVariable {
	vars := []report.VersionVariable{}
	for _, kv := range env {
		name, value, ok := strings.Cut(kv, "=")
		if !ok || !versionName.MatchString(name) || value == "" || !printable(value, maxVersionLength) {
			continue
		}
		vars = append(vars, report.VersionVariable{Name: name, Value: value})
	}
	sort.Slice(vars, func(i, j int) bool { return vars[i].Name < vars[j].Name })
	if len(vars) > maxVersionVariables {
		vars = vars[:maxVersionVariables]
	}
	return vars
}

func printable(s string, max int) bool {
	if len(s) > max {
		return false
	}
	for _, r := range s {
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

func orEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// parseTime reads Docker's RFC 3339 timestamps. Some images carry no creation
// date at all; that is not worth failing the collection over.
func parseTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}
