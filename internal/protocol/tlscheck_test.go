package protocol

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoUncheckedTLS fails if any non-test code in the repository turns off
// TLS certificate checks. The only exceptions replace them with something
// stricter (pinning a key, checking a signed identity), and are marked
// "tlscheck:replaced" on their line, which makes every one visible in review.
func TestNoUncheckedTLS(t *testing.T) {
	root := filepath.Join("..", "..")
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == ".git" || d.Name() == ".dev" || d.Name() == "bin") {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if err != nil {
			return err
		}
		marked := map[int]bool{}
		for _, cg := range f.Comments {
			for _, c := range cg.List {
				if strings.Contains(c.Text, "tlscheck:replaced") {
					marked[fset.Position(c.Pos()).Line] = true
				}
			}
		}
		ast.Inspect(f, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok && id.Name == "InsecureSkipVerify" {
				if pos := fset.Position(id.Pos()); !marked[pos.Line] {
					t.Errorf("%s: InsecureSkipVerify turns off certificate checks; replace them with a stricter check and mark the line tlscheck:replaced", pos)
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
