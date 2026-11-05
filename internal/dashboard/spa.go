package dashboard

import (
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"errors"
	"io/fs"
	"net/http"
	"regexp"
	"strings"
)

// webui/dist is the built Svelte app (make ui); without it, the fallback page
// is served.
//
//go:embed all:webui
var uiFiles embed.FS

type spa struct {
	files fs.FS
	index []byte
	csp   string
}

var inlineScript = regexp.MustCompile(`(?s)<script>(.*?)</script>`)

func newSPA() (*spa, error) {
	files, _ := fs.Sub(uiFiles, "webui/dist")
	index, err := fs.ReadFile(files, "index.html")
	if errors.Is(err, fs.ErrNotExist) {
		files, _ = fs.Sub(uiFiles, "webui/fallback")
		index, err = fs.ReadFile(files, "index.html")
	}
	if err != nil {
		return nil, err
	}
	// SvelteKit starts the app with an inline script: allow it by its hash
	// rather than allowing inline scripts.
	scripts := "'self'"
	for _, m := range inlineScript.FindAllSubmatch(index, -1) {
		h := sha256.Sum256(m[1])
		scripts += " 'sha256-" + base64.StdEncoding.EncodeToString(h[:]) + "'"
	}
	csp := "default-src 'none'; script-src " + scripts + "; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
	return &spa{files: files, index: index, csp: csp}, nil
}

// ServeHTTP serves the app's files, and its page for any other path so that
// the app's own routes load.
func (s *spa) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/")
	if strings.HasPrefix(name, "api/") {
		http.NotFound(rw, r)
		return
	}
	if name != "" && name != "index.html" {
		if f, err := fs.Stat(s.files, name); err == nil && !f.IsDir() {
			if strings.HasPrefix(name, "_app/immutable/") {
				rw.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
			}
			http.ServeFileFS(rw, r, s.files, name)
			return
		}
	}
	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	rw.Write(s.index)
}
