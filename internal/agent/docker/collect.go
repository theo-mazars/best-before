package docker

import (
	"context"
	"errors"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/theo-mazars/best-before/internal/report"
)

const (
	labelComposeProject = "com.docker.compose.project"
	labelComposeService = "com.docker.compose.service"
)

// Collect lists running containers and the images they use. If anything
// fails, it reports Docker as unavailable with the reason rather than
// returning a partial list that could pass for a complete one.
func Collect(ctx context.Context, c *Client) report.Docker {
	d, err := collect(ctx, c)
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

func collect(ctx context.Context, c *Client) (report.Docker, error) {
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
		}
		err := c.get(ctx, "/images/"+url.PathEscape(id)+"/json", &inspect)
		if errors.Is(err, errNotFound) {
			continue // removed after the container was created; nothing to scan
		}
		if err != nil {
			return d, err
		}
		d.Images = append(d.Images, report.Image{
			ID:           inspect.ID,
			RepoTags:     orEmpty(inspect.RepoTags),
			RepoDigests:  orEmpty(inspect.RepoDigests),
			CreatedAt:    parseTime(inspect.Created),
			OS:           inspect.Os,
			Architecture: inspect.Architecture,
		})
	}

	sort.Slice(d.Containers, func(i, j int) bool { return d.Containers[i].Name < d.Containers[j].Name })
	sort.Slice(d.Images, func(i, j int) bool { return d.Images[i].ID < d.Images[j].ID })
	return d, nil
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
