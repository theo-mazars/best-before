package docker

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The agent must only ever issue GET requests to the Docker API (plan §4.3).
// These tests enforce that three ways: at runtime against a fake engine, at
// the transport level, and by inspecting this package's source.

func TestCollectOnlyUsesGET(t *testing.T) {
	srv, methods := fakeEngine(t)
	Collect(context.Background(), newTestClient(t, srv))

	calls := methods()
	if len(calls) == 0 {
		t.Fatal("no requests recorded")
	}
	for _, call := range calls {
		if !strings.HasPrefix(call, "GET ") {
			t.Errorf("non-GET Docker API call: %s", call)
		}
	}
}

func TestTransportRefusesNonGET(t *testing.T) {
	srv, methods := fakeEngine(t)
	c := newTestClient(t, srv)

	for _, method := range []string{
		http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete,
		http.MethodHead, http.MethodOptions, http.MethodConnect, http.MethodTrace,
	} {
		req, err := http.NewRequest(method, c.base+"/containers/c1/kill", nil)
		if err != nil {
			t.Fatal(err)
		}
		if resp, err := c.http.Do(req); err == nil {
			resp.Body.Close()
			t.Errorf("%s was allowed through", method)
		}
	}
	if calls := methods(); len(calls) != 0 {
		t.Errorf("requests reached the engine: %v", calls)
	}
}

// TestSourceOnlyUsesGET fails if this package's code names any HTTP method
// other than GET, or builds a request whose method is not http.MethodGet.
func TestSourceOnlyUsesGET(t *testing.T) {
	forbiddenConsts := map[string]bool{
		"MethodPost": true, "MethodPut": true, "MethodPatch": true, "MethodDelete": true,
		"MethodHead": true, "MethodOptions": true, "MethodConnect": true, "MethodTrace": true,
	}
	forbiddenStrings := map[string]bool{
		"POST": true, "PUT": true, "PATCH": true, "DELETE": true,
		"HEAD": true, "OPTIONS": true, "CONNECT": true, "TRACE": true,
	}
	// Convenience helpers on http.Client and package http that send non-GET requests.
	forbiddenCalls := map[string]bool{"Post": true, "PostForm": true, "Head": true}

	for _, path := range sourceFiles(t) {
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.SelectorExpr:
				if forbiddenConsts[n.Sel.Name] || forbiddenCalls[n.Sel.Name] {
					t.Errorf("%s: uses %s; the agent may only send GET requests to Docker", fset.Position(n.Pos()), n.Sel.Name)
				}
			case *ast.BasicLit:
				if s, err := strconv.Unquote(n.Value); err == nil && n.Kind == token.STRING && forbiddenStrings[strings.ToUpper(s)] {
					t.Errorf("%s: string %s looks like an HTTP method; the agent may only send GET requests to Docker", fset.Position(n.Pos()), n.Value)
				}
			case *ast.CallExpr:
				sel, ok := n.Fun.(*ast.SelectorExpr)
				if !ok || (sel.Sel.Name != "NewRequest" && sel.Sel.Name != "NewRequestWithContext") {
					return true
				}
				methodArg := 0
				if sel.Sel.Name == "NewRequestWithContext" {
					methodArg = 1
				}
				if len(n.Args) <= methodArg || !isHTTPMethodGet(n.Args[methodArg]) {
					t.Errorf("%s: %s must be called with http.MethodGet", fset.Position(n.Pos()), sel.Sel.Name)
				}
			}
			return true
		})
	}
}

func isHTTPMethodGet(e ast.Expr) bool {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && pkg.Name == "http" && sel.Sel.Name == "MethodGet"
}

// sourceFiles returns the non-test Go files of this package.
func sourceFiles(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	var files []string
	for _, e := range entries {
		name := e.Name()
		if strings.HasSuffix(name, ".go") && !strings.HasSuffix(name, "_test.go") {
			files = append(files, filepath.Join(".", name))
		}
	}
	if len(files) == 0 {
		t.Fatal("no source files found")
	}
	return files
}
