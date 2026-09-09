package adapterapi

import (
	"bytes"
	"go/parser"
	"go/token"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestAdapterAPIRemainsDependencyLeaf(t *testing.T) {
	root, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}
	entries, err := filepath.Glob(filepath.Join(root, "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	stdlib, err := standardLibraryImports()
	if err != nil {
		t.Fatalf("go list std: %v", err)
	}
	for _, filename := range entries {
		if strings.HasSuffix(filename, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), filename, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", filename, err)
		}
		for _, spec := range file.Imports {
			path := strings.Trim(spec.Path.Value, `"`)
			if !allowedProductionImport(path, stdlib) {
				t.Fatalf("production file %s imports non-standard package %q", filepath.Base(filename), path)
			}
		}
	}

	cmd := exec.Command("go", "list", "-deps", ".")
	output, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list -deps .: %v", err)
	}
	for _, dependency := range strings.Split(string(output), "\n") {
		if strings.HasPrefix(dependency, "Scardice-core/") && dependency != "Scardice-core/adapterapi" {
			t.Fatalf("adapterapi dependency graph contains local non-leaf package %q", dependency)
		}
	}
	for _, forbidden := range []string{
		"Scardice-core/dice",
		"Scardice-core/api",
		"Scardice-core/utils",
		"Scardice-core/eventstore",
		"github.com/labstack/echo",
		"gorm.io/",
		"sdk",
		"/provider",
	} {
		if bytes.Contains(output, []byte(forbidden)) {
			t.Fatalf("adapterapi dependency graph contains forbidden package %q", forbidden)
		}
	}
}

func standardLibraryImports() (map[string]bool, error) {
	output, err := exec.Command("go", "list", "std").Output()
	if err != nil {
		return nil, err
	}
	standard := make(map[string]bool)
	for _, path := range strings.Fields(string(output)) {
		standard[path] = true
	}
	return standard, nil
}

func allowedProductionImport(path string, standard map[string]bool) bool {
	return standard[path]
}

func TestImportBoundaryRejectsKnownNonStandardPaths(t *testing.T) {
	standard, err := standardLibraryImports()
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"sdk", "example/provider", "Scardice-core/dice", "github.com/labstack/echo/v4", "gorm.io/gorm"} {
		if allowedProductionImport(path, standard) {
			t.Fatalf("non-standard import %q was treated as standard", path)
		}
	}
}
