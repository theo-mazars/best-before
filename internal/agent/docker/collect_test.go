package docker

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeEngine serves canned Docker API responses and records every method used.
func fakeEngine(t *testing.T) (*httptest.Server, func() []string) {
	t.Helper()
	responses := map[string]string{
		"/version":         `{"Version":"29.7.2","ApiVersion":"1.55"}`,
		"/containers/json": `[{"Id":"c1"},{"Id":"c2"},{"Id":"gone"}]`,
		"/containers/c1/json": `{"Id":"c1","Name":"/web","Image":"sha256:img1","Created":"2026-10-01T10:00:00.123456789Z",
			"Config":{"Image":"node:22-alpine","Labels":{"com.docker.compose.project":"shop","com.docker.compose.service":"web"}}}`,
		"/containers/c2/json": `{"Id":"c2","Name":"/db","Image":"sha256:img2","Created":"2026-09-01T10:00:00Z",
			"Config":{"Image":"mysql:8.0.36","Labels":null}}`,
		"/images/sha256:img1/json": `{"Id":"sha256:img1","RepoTags":["node:22-alpine"],"RepoDigests":["node@sha256:aaa"],
			"Created":"2026-09-20T00:00:00Z","Os":"linux","Architecture":"arm64"}`,
		"/images/sha256:img2/json": `{"Id":"sha256:img2","RepoTags":null,"RepoDigests":null,"Created":"","Os":"linux","Architecture":"arm64"}`,
	}

	var mu sync.Mutex
	var methods []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		methods = append(methods, r.Method+" "+r.URL.Path)
		mu.Unlock()
		body, ok := responses[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)

	return srv, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), methods...)
	}
}

func newTestClient(t *testing.T, srv *httptest.Server) *Client {
	t.Helper()
	c, err := NewClient("tcp://" + strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestCollect(t *testing.T) {
	srv, _ := fakeEngine(t)
	d := Collect(context.Background(), newTestClient(t, srv))

	if !d.Available || d.Error != "" || d.EngineVersion != "29.7.2" {
		t.Fatalf("available %v, error %q, version %q", d.Available, d.Error, d.EngineVersion)
	}
	// "gone" returned 404 on inspect and is skipped; output is sorted by name.
	if len(d.Containers) != 2 || d.Containers[0].Name != "db" || d.Containers[1].Name != "web" {
		t.Fatalf("containers: %+v", d.Containers)
	}
	web := d.Containers[1]
	if web.Image != "node:22-alpine" || web.ImageID != "sha256:img1" ||
		web.ComposeProject != "shop" || web.ComposeService != "web" ||
		!web.CreatedAt.Equal(time.Date(2026, 10, 1, 10, 0, 0, 123456789, time.UTC)) {
		t.Errorf("web: %+v", web)
	}
	if len(d.Images) != 2 {
		t.Fatalf("images: %+v", d.Images)
	}
	if got := d.Images[0].RepoDigests; len(got) != 1 || got[0] != "node@sha256:aaa" {
		t.Errorf("img1 digests: %v", got)
	}
	local := d.Images[1]
	if local.RepoDigests == nil || local.RepoTags == nil || !local.CreatedAt.IsZero() {
		t.Errorf("img2 (local build, no date): %+v", local)
	}
}

func TestCollectUnavailable(t *testing.T) {
	srv, _ := fakeEngine(t)
	c := newTestClient(t, srv)
	srv.Close()

	d := Collect(context.Background(), c)
	if d.Available || d.Error == "" {
		t.Errorf("available %v, error %q: an unreachable daemon must be reported", d.Available, d.Error)
	}
	if d.Containers == nil || d.Images == nil {
		t.Error("lists must be empty, not nil")
	}
}

func TestAnyExists(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing")
	if anyExists([]string{missing}) {
		t.Error("missing file reported as existing")
	}
	if !anyExists([]string{missing, dir}) {
		t.Error("existing path not found")
	}
}
