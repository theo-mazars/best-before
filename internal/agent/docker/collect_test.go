package docker

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/theo-mazars/best-before/internal/report"
)

var (
	containerWeb  = strings.Repeat("c1", 32)
	containerDB   = strings.Repeat("c2", 32)
	containerGone = strings.Repeat("d0", 32)
	imageWeb      = "sha256:" + strings.Repeat("a1", 32)
	imageDB       = "sha256:" + strings.Repeat("a2", 32)
)

// fakeEngine serves canned Docker API responses and records every method used.
func fakeEngine(t *testing.T) (*httptest.Server, func() []string) {
	t.Helper()
	fixtures := map[string]string{
		"/version":         `{"Version":"29.7.2","ApiVersion":"1.55"}`,
		"/containers/json": `[{"Id":"{c1}"},{"Id":"{c2}"},{"Id":"{gone}"}]`,
		"/containers/{c1}/json": `{"Id":"{c1}","Name":"/web","Image":"{img1}","Created":"2026-10-01T10:00:00.123456789Z",
			"Config":{"Image":"node:22-alpine","Labels":{"com.docker.compose.project":"shop","com.docker.compose.service":"web"}}}`,
		"/containers/{c2}/json": `{"Id":"{c2}","Name":"/db","Image":"{img2}","Created":"2026-09-01T10:00:00Z",
			"Config":{"Image":"mysql:8.0.36","Labels":null}}`,
		"/images/{img1}/json": `{"Id":"{img1}","RepoTags":["node:22-alpine"],"RepoDigests":["node@sha256:aaa"],
			"Created":"2026-09-20T00:00:00Z","Os":"linux","Architecture":"arm64",
			"Config":{"Env":["PATH=/usr/local/bin","NODE_VERSION=22.11.0","YARN_VERSION=1.22.22"]}}`,
		"/images/{img2}/json": `{"Id":"{img2}","RepoTags":null,"RepoDigests":null,"Created":"","Os":"linux","Architecture":"arm64"}`,
		// img2 has no export: it was removed while being read.
		"/images/{img1}/get": string(exportOf(t,
			map[string][]byte{"blobs/sha256/l1": tarOf(t,
				entry{name: "etc/os-release", body: "ID=alpine\nVERSION_ID=3.20.3\n"},
				entry{name: "lib/apk/db/installed", body: "P:musl\nV:1.2.5-r0\nA:aarch64\no:musl\n"},
			)},
			nil,
			manifest{Layers: []string{"blobs/sha256/l1"}},
		)),
	}

	// IDs have Docker's shape, as the client refuses any other.
	ids := strings.NewReplacer("{c1}", containerWeb, "{c2}", containerDB, "{gone}", containerGone, "{img1}", imageWeb, "{img2}", imageDB)
	responses := map[string]string{}
	for path, body := range fixtures {
		responses[ids.Replace(path)] = ids.Replace(body)
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
	d := Collect(context.Background(), newTestClient(t, srv), nil)

	if !d.Available || d.Error != "" || d.EngineVersion != "29.7.2" {
		t.Fatalf("available %v, error %q, version %q", d.Available, d.Error, d.EngineVersion)
	}
	// "gone" returned 404 on inspect and is skipped; output is sorted by name.
	if len(d.Containers) != 2 || d.Containers[0].Name != "db" || d.Containers[1].Name != "web" {
		t.Fatalf("containers: %+v", d.Containers)
	}
	web := d.Containers[1]
	if web.Image != "node:22-alpine" || web.ImageID != imageWeb ||
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
	if sys := d.Images[0].System; sys == nil || sys.OS.ID != "alpine" || sys.PackageManager != "apk" ||
		len(sys.Packages) != 1 || sys.Packages[0].Name != "musl" || d.Images[0].SystemError != "" {
		t.Errorf("img1 system: %+v, error %q", sys, d.Images[0].SystemError)
	}
	if got := d.Images[0].Versions; len(got) != 2 || got[0] != (report.VersionVariable{Name: "NODE_VERSION", Value: "22.11.0"}) {
		t.Errorf("img1 versions: %+v", got)
	}
	local := d.Images[1]
	if local.RepoDigests == nil || local.RepoTags == nil || !local.CreatedAt.IsZero() {
		t.Errorf("img2 (local build, no date): %+v", local)
	}
	// An image that cannot be read is reported, without failing the rest.
	if local.System != nil || !strings.Contains(local.SystemError, "removed") {
		t.Errorf("img2 system: %+v, error %q", local.System, local.SystemError)
	}
}

type mapCache map[string]*report.ImageSystem

func (m mapCache) Get(id string) *report.ImageSystem    { return m[id] }
func (m mapCache) Put(id string, s *report.ImageSystem) { m[id] = s }

// TestCollectCache checks that an image is exported once, and that failures
// are not cached, so that they are retried on the next run.
func TestCollectCache(t *testing.T) {
	srv, methods := fakeEngine(t)
	c := newTestClient(t, srv)
	cache := mapCache{}

	Collect(context.Background(), c, cache)
	if len(cache) != 1 || cache[imageWeb] == nil {
		t.Fatalf("cache after the first run: %v", cache)
	}
	d := Collect(context.Background(), c, cache)
	if d.Images[0].System == nil {
		t.Error("cached system not reported")
	}

	exports := map[string]int{}
	for _, call := range methods() {
		if strings.HasSuffix(call, "/get") {
			exports[call]++
		}
	}
	if exports["GET /images/"+imageWeb+"/get"] != 1 || exports["GET /images/"+imageDB+"/get"] != 2 {
		t.Errorf("exports: %v", exports)
	}
}

func TestCollectUnavailable(t *testing.T) {
	srv, _ := fakeEngine(t)
	c := newTestClient(t, srv)
	srv.Close()

	d := Collect(context.Background(), c, nil)
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

func TestVersionVariables(t *testing.T) {
	got := versionVariables([]string{
		"PYTHON_VERSION=3.12.7",
		"PATH=/usr/local/bin:/usr/bin",
		"DB_PASSWORD=hunter2",       // never kept: not a version
		"node_version=22",           // official images use upper case
		"GPG_KEY_VERSION",           // no value
		"EMPTY_VERSION=",            // empty
		"BAD_VERSION=1.0\nrm -rf /", // control characters
		"LONG_VERSION=" + strings.Repeat("9", maxVersionLength+1),
		"JAVA_VERSION=jdk-21.0.5+11",
	})
	want := []report.VersionVariable{{Name: "JAVA_VERSION", Value: "jdk-21.0.5+11"}, {Name: "PYTHON_VERSION", Value: "3.12.7"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v, want %+v", got, want)
	}
	if got := versionVariables(nil); got == nil {
		t.Error("must be empty, not nil")
	}
}
