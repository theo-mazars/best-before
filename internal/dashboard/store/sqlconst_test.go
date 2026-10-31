package store

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// Every SQL query in this package must be a compile-time constant, so that
// values can only ever reach the database through placeholders and SQL
// injection is ruled out by construction. A query that cannot be a constant
// (the migration files) must be marked "sqlconst:trusted" on its line, which
// makes every exception visible in review.

// queryMethods maps database/sql methods to the position of their query
// argument.
var queryMethods = map[string]int{
	"Exec": 0, "Query": 0, "QueryRow": 0, "Prepare": 0,
	"ExecContext": 1, "QueryContext": 1, "QueryRowContext": 1, "PrepareContext": 1,
}

func TestQueriesAreConstants(t *testing.T) {
	findings, err := nonConstantQueries(".", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		t.Errorf("%s: SQL query is not a constant; use a const and ? placeholders", f)
	}
}

// TestNonConstantQueriesDetected checks that the detector itself works.
func TestNonConstantQueriesDetected(t *testing.T) {
	const src = `package bad

const ok = "SELECT 1 WHERE id = ?"
const alsoOK = ok + " AND x = ?"

func f(db DB, name, trusted string) {
	db.ExecContext(ctx, ok, name)                       // fine
	db.QueryRowContext(ctx, alsoOK, name)               // fine
	db.Exec("DELETE FROM t WHERE id = ?", name)         // fine
	db.ExecContext(ctx, "SELECT * FROM t WHERE name = '" + name + "'")
	db.Query(fmt.Sprintf("SELECT %s", name))
	db.QueryContext(ctx, ok + name)
	q := ok
	db.Exec(q)
	db.Exec(trusted) // sqlconst:trusted
}
`
	findings, err := nonConstantQueries("", map[string]string{"bad.go": src})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 4 {
		t.Errorf("found %d of 4 non-constant queries:\n%s", len(findings), strings.Join(findings, "\n"))
	}
}

// nonConstantQueries parses the non-test Go files in dir (or the given
// sources) and reports query arguments that are not constants.
func nonConstantQueries(dir string, sources map[string]string) ([]string, error) {
	fset := token.NewFileSet()
	files := map[string]*ast.File{}
	if sources == nil {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return nil, err
		}
		sources = map[string]string{}
		for _, e := range entries {
			n := e.Name()
			if strings.HasSuffix(n, ".go") && !strings.HasSuffix(n, "_test.go") {
				data, err := os.ReadFile(n)
				if err != nil {
					return nil, err
				}
				sources[n] = string(data)
			}
		}
	}
	for name, src := range sources {
		f, err := parser.ParseFile(fset, name, src, parser.ParseComments)
		if err != nil {
			return nil, err
		}
		files[name] = f
	}

	// Package-level constants, across all files.
	consts := map[string]bool{}
	for _, f := range files {
		for _, decl := range f.Decls {
			if gd, ok := decl.(*ast.GenDecl); ok && gd.Tok == token.CONST {
				for _, spec := range gd.Specs {
					for _, name := range spec.(*ast.ValueSpec).Names {
						consts[name.Name] = true
					}
				}
			}
		}
	}

	var isConst func(ast.Expr) bool
	isConst = func(e ast.Expr) bool {
		switch e := e.(type) {
		case *ast.BasicLit:
			return e.Kind == token.STRING
		case *ast.Ident:
			return consts[e.Name]
		case *ast.ParenExpr:
			return isConst(e.X)
		case *ast.BinaryExpr:
			return e.Op == token.ADD && isConst(e.X) && isConst(e.Y)
		}
		return false
	}

	var findings []string
	for _, f := range files {
		trusted := map[int]bool{}
		for _, cg := range f.Comments {
			for _, c := range cg.List {
				if strings.Contains(c.Text, "sqlconst:trusted") {
					trusted[fset.Position(c.Pos()).Line] = true
				}
			}
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			idx, ok := queryMethods[sel.Sel.Name]
			if !ok || len(call.Args) <= idx {
				return true
			}
			pos := fset.Position(call.Pos())
			if !isConst(call.Args[idx]) && !trusted[pos.Line] {
				findings = append(findings, pos.String())
			}
			return true
		})
	}
	return findings, nil
}
