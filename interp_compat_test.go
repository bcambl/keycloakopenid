package keycloakopenid

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// TestProductionCodeAvoidsMultiValueCaseClauses guards the Traefik/Yaegi
// runtime: Yaegi v0.16.1 evaluates only the first expression of a
// comma-separated case clause, so production switches must use one expression
// per case.
func TestProductionCodeAvoidsMultiValueCaseClauses(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("filepath.Glob returned error: %v", err)
	}
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		fset := token.NewFileSet()
		parsed, err := parser.ParseFile(fset, file, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", file, err)
		}
		ast.Inspect(parsed, func(node ast.Node) bool {
			clause, ok := node.(*ast.CaseClause)
			if ok && len(clause.List) > 1 {
				t.Errorf("%s: case clause has %d expressions; use one expression per case", fset.Position(clause.Pos()), len(clause.List))
			}
			return true
		})
	}
}
