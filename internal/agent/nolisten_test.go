package agent

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The agent must never open a listening socket (plan §4.1). This test finds
// every package of this module compiled into bestbefore-agent for Linux and
// fails if any of them refers to a listen or serve function.

const agentPackage = "github.com/theo-mazars/best-before/cmd/bestbefore-agent"

func TestAgentNeverListens(t *testing.T) {
	files := agentSourceFiles(t)
	if len(files) < 3 {
		t.Fatalf("found only %d source files; the package listing is probably broken", len(files))
	}
	for _, path := range files {
		for _, finding := range findListenCalls(t, path, nil) {
			t.Errorf("%s: the agent must never open a listening socket", finding)
		}
	}
}

// TestFindListenCalls checks that the detector itself works.
func TestFindListenCalls(t *testing.T) {
	const src = `package bad

import (
	"net"
	"net/http"
	sys "golang.org/x/sys/unix"
	"syscall"
)

func a() { net.Listen("tcp", ":8080") }
func b() { net.ListenPacket("udp", ":53") }
func c() { http.ListenAndServe(":80", nil) }
func d(s *http.Server, l net.Listener) { s.Serve(l) }
func e() { syscall.Bind(0, nil) }
func f() { sys.Listen(0, 1) }
func g() { var lc net.ListenConfig; _ = lc }
`
	got := findListenCalls(t, "bad.go", []byte(src))
	if len(got) != 8 {
		t.Errorf("found %d of 8 listen calls:\n%s", len(got), strings.Join(got, "\n"))
	}

	const clean = `package good

import "net"

func dial() { net.Dial("tcp", "dashboard:443") }
`
	if got := findListenCalls(t, "good.go", []byte(clean)); len(got) != 0 {
		t.Errorf("false positives: %v", got)
	}
}

// findListenCalls reports every reference that could open a listening socket:
// any identifier containing "Listen" (net.Listen, net.Listener,
// http.ListenAndServe…), Serve/ServeTLS, and Bind/Listen on syscall packages.
func findListenCalls(t *testing.T, path string, src any) []string {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, src, 0)
	if err != nil {
		t.Fatal(err)
	}

	syscallPkgs := map[string]bool{}
	for _, imp := range file.Imports {
		p, _ := strconv.Unquote(imp.Path.Value)
		if p != "syscall" && p != "golang.org/x/sys/unix" {
			continue
		}
		name := filepath.Base(p)
		if imp.Name != nil {
			name = imp.Name.Name
		}
		syscallPkgs[name] = true
	}

	var findings []string
	ast.Inspect(file, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		name := sel.Sel.Name
		bad := strings.Contains(name, "Listen") || name == "Serve" || name == "ServeTLS"
		if x, ok := sel.X.(*ast.Ident); ok && syscallPkgs[x.Name] && name == "Bind" {
			bad = true
		}
		if bad {
			findings = append(findings, fset.Position(sel.Pos()).String()+": "+name)
		}
		return true
	})
	return findings
}

// agentSourceFiles lists the non-test Go files, built for Linux, of every
// package in this module that the agent binary imports.
func agentSourceFiles(t *testing.T) []string {
	t.Helper()
	module := strings.TrimSuffix(agentPackage, "/cmd/bestbefore-agent")
	format := `{{if .Module}}{{if eq .Module.Path "` + module + `"}}{{$dir := .Dir}}{{range .GoFiles}}{{$dir}}/{{.}}
{{end}}{{range .CgoFiles}}{{$dir}}/{{.}}
{{end}}{{end}}{{end}}`

	cmd := exec.Command("go", "list", "-deps", "-f", format, agentPackage)
	cmd.Env = append(os.Environ(), "GOOS=linux", "CGO_ENABLED=0")
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			t.Fatalf("go list: %v\n%s", err, ee.Stderr)
		}
		t.Fatalf("go list: %v", err)
	}
	var files []string
	for line := range strings.Lines(string(out)) {
		if line = strings.TrimSpace(line); line != "" {
			files = append(files, line)
		}
	}
	return files
}
