package architecture

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate architecture test")
	}
	return filepath.Dir(filepath.Dir(filename))
}

func parseFile(t *testing.T, filename string) (*token.FileSet, *ast.File) {
	t.Helper()
	set := token.NewFileSet()
	file, err := parser.ParseFile(set, filename, nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse %s: %v", filename, err)
	}
	return set, file
}

func importViolation(file *ast.File, forbidden []string) bool {
	for _, spec := range file.Imports {
		path := strings.Trim(spec.Path.Value, `"`)
		for _, prefix := range forbidden {
			if path == prefix || strings.HasPrefix(path, prefix+"/") {
				return true
			}
		}
	}
	return false
}

func hasStringLiteral(file *ast.File, value string) bool {
	found := false
	ast.Inspect(file, func(node ast.Node) bool {
		literal, ok := node.(*ast.BasicLit)
		if ok && literal.Kind == token.STRING && strings.Trim(literal.Value, `"`) == value {
			found = true
			return false
		}
		return !found
	})
	return found
}

func hasIdentifier(file *ast.File, name string) bool {
	found := false
	ast.Inspect(file, func(node ast.Node) bool {
		identifier, ok := node.(*ast.Ident)
		if ok && identifier.Name == name {
			found = true
			return false
		}
		return !found
	})
	return found
}

func callPosition(set *token.FileSet, file *ast.File, name string) token.Position {
	var position token.Position
	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if ok && selector.Sel.Name == name {
			position = set.Position(call.Pos())
			return false
		}
		identifier, ok := call.Fun.(*ast.Ident)
		if ok && identifier.Name == name {
			position = set.Position(call.Pos())
			return false
		}
		return true
	})
	return position
}

func TestAdapterAPIBoundary(t *testing.T) {
	root := repositoryRoot(t)
	files, err := filepath.Glob(filepath.Join(root, "adapterapi", "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, filename := range files {
		_, file := parseFile(t, filename)
		if importViolation(file, []string{"Scardice-core/dice", "Scardice-core/endpoint", "Scardice-core/eventstore", "github.com/labstack/echo", "gorm.io"}) {
			t.Fatalf("adapterapi imports a forbidden owner: %s", filename)
		}
	}
}

func TestNewAdminSurfaceHasNoLegacyRouteOrQueryToken(t *testing.T) {
	root := repositoryRoot(t)
	files, err := filepath.Glob(filepath.Join(root, "api", "endpoints*.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, filename := range files {
		_, file := parseFile(t, filename)
		if hasIdentifier(file, "QueryParam") {
			t.Fatalf("new admin surface reads query parameters: %s", filename)
		}
	}
	set, file := parseFile(t, filepath.Join(root, "api", "api_bind.go"))
	_ = set
	if hasStringLiteral(file, "/sd-api/im_connections/list") {
		t.Fatal("legacy connection route is still registered")
	}
}

func TestStartupGatePrecedesBootstrapAndLegacyLauncherIsGone(t *testing.T) {
	root := repositoryRoot(t)
	set, file := parseFile(t, filepath.Join(root, "main.go"))
	gate := callPosition(set, file, "ValidateStartupReadiness")
	bootstrap := callPosition(set, file, "NewBootstrap")
	if gate.Line == 0 || bootstrap.Line == 0 || gate.Line >= bootstrap.Line {
		t.Fatalf("startup gate=%v bootstrap=%v", gate, bootstrap)
	}
	if hasIdentifier(file, "diceServe") || hasIdentifier(file, "LoadDice") {
		t.Fatal("legacy runtime launcher/loader remains in main")
	}
}

func TestBoundaryChecksCatchNegativeFixtures(t *testing.T) {
	set := token.NewFileSet()
	for name, source := range map[string]string{
		"forbidden import": `package fixture; import _ "Scardice-core/eventstore"`,
		"legacy route":     `package fixture; var _ = "/sd-api/im_connections/list"`,
		"legacy launcher":  `package fixture; func f(){ diceServe() }`,
	} {
		t.Run(name, func(t *testing.T) {
			file, err := parser.ParseFile(set, name+".go", source, 0)
			if err != nil {
				t.Fatal(err)
			}
			switch name {
			case "forbidden import":
				if !importViolation(file, []string{"Scardice-core/eventstore"}) {
					t.Fatal("forbidden import was not detected")
				}
			case "legacy route":
				if !hasStringLiteral(file, "/sd-api/im_connections/list") {
					t.Fatal("legacy route was not detected")
				}
			case "legacy launcher":
				if !hasIdentifier(file, "diceServe") {
					t.Fatal("legacy launcher was not detected")
				}
			}
		})
	}
}

func TestRepositoryRootIsReadable(t *testing.T) {
	root := repositoryRoot(t)
	if _, err := os.Stat(root); err != nil {
		t.Fatal(err)
	}
}
