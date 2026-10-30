package architecture

import (
	"go/ast"
	"go/parser"
	"go/token"
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

func directAdapterCallPosition(set *token.FileSet, file *ast.File, names map[string]struct{}) token.Position {
	var position token.Position
	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		method, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if _, forbidden := names[method.Sel.Name]; !forbidden {
			return true
		}
		owner, ok := method.X.(*ast.SelectorExpr)
		if ok && owner.Sel.Name == "Adapter" {
			position = set.Position(call.Pos())
			return false
		}
		return true
	})
	return position
}

type fileSendAdapterCallSite struct {
	method          string
	function        string
	position        token.Position
	boundaryChecked bool
}

func directAdapterMethod(call *ast.CallExpr) (string, bool) {
	method, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return "", false
	}
	owner, ok := method.X.(*ast.SelectorExpr)
	return method.Sel.Name, ok && owner.Sel.Name == "Adapter"
}

func hasCallNamed(node ast.Node, name string) bool {
	found := false
	ast.Inspect(node, func(candidate ast.Node) bool {
		call, ok := candidate.(*ast.CallExpr)
		if !ok {
			return !found
		}
		switch function := call.Fun.(type) {
		case *ast.Ident:
			found = function.Name == name
		case *ast.SelectorExpr:
			found = function.Sel.Name == name
		}
		return !found
	})
	return found
}

func hasReturnStatement(node ast.Node) bool {
	found := false
	ast.Inspect(node, func(candidate ast.Node) bool {
		if _, ok := candidate.(*ast.ReturnStmt); ok {
			found = true
			return false
		}
		return true
	})
	return found
}

func fileSendBoundaryGuardEnd(function *ast.FuncDecl) token.Pos {
	if function.Body == nil {
		return token.NoPos
	}
	for _, statement := range function.Body.List {
		guard, ok := statement.(*ast.IfStmt)
		if ok && guard.Init != nil && hasCallNamed(guard.Init, "fileSendBoundaryError") && hasReturnStatement(guard.Body) {
			return guard.End()
		}
	}
	return token.NoPos
}

func fileSendAdapterCallSites(set *token.FileSet, file *ast.File) []fileSendAdapterCallSite {
	var sites []fileSendAdapterCallSite
	seen := make(map[*ast.CallExpr]struct{})
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Body == nil {
			continue
		}
		guardEnd := fileSendBoundaryGuardEnd(function)
		ast.Inspect(function.Body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			method, ok := directAdapterMethod(call)
			if !ok || (method != "SendFileToPerson" && method != "SendFileToGroup") {
				return true
			}
			seen[call] = struct{}{}
			sites = append(sites, fileSendAdapterCallSite{
				method:          method,
				function:        function.Name.Name,
				position:        set.Position(call.Pos()),
				boundaryChecked: guardEnd != token.NoPos && guardEnd < call.Pos(),
			})
			return true
		})
	}
	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		method, ok := directAdapterMethod(call)
		if !ok || (method != "SendFileToPerson" && method != "SendFileToGroup") {
			return true
		}
		if _, accountedFor := seen[call]; !accountedFor {
			sites = append(sites, fileSendAdapterCallSite{
				method:   method,
				position: set.Position(call.Pos()),
			})
		}
		return true
	})
	return sites
}

func fileSendAdapterCallViolations(set *token.FileSet, file *ast.File) []token.Position {
	expectedFunction := map[string]string{
		"SendFileToPerson": "SendFileToPersonRaw",
		"SendFileToGroup":  "SendFileToGroupRaw",
	}
	var violations []token.Position
	for _, site := range fileSendAdapterCallSites(set, file) {
		if site.function != expectedFunction[site.method] || !site.boundaryChecked {
			violations = append(violations, site.position)
		}
	}
	return violations
}

func exportedDynamicTypePosition(set *token.FileSet, file *ast.File) token.Position {
	var position token.Position
	hasDynamicType := func(node ast.Node) bool {
		if node == nil {
			return false
		}
		found := false
		ast.Inspect(node, func(candidate ast.Node) bool {
			identifier, ok := candidate.(*ast.Ident)
			if ok && identifier.Name == "any" {
				found = true
				return false
			}
			return !found
		})
		return found
	}
	for _, declaration := range file.Decls {
		switch typed := declaration.(type) {
		case *ast.FuncDecl:
			paramsDynamic := typed.Type.Params != nil && hasDynamicType(typed.Type.Params)
			resultsDynamic := typed.Type.Results != nil && hasDynamicType(typed.Type.Results)
			if typed.Name.IsExported() && (paramsDynamic || resultsDynamic) {
				return set.Position(typed.Pos())
			}
		case *ast.GenDecl:
			for _, spec := range typed.Specs {
				typeSpec, ok := spec.(*ast.TypeSpec)
				if ok && typeSpec.Name.IsExported() && hasDynamicType(typeSpec.Type) {
					position = set.Position(typeSpec.Pos())
					return position
				}
			}
		}
	}
	return position
}

func identifierPosition(set *token.FileSet, file *ast.File, name string) token.Position {
	var position token.Position
	ast.Inspect(file, func(node ast.Node) bool {
		identifier, ok := node.(*ast.Ident)
		if ok && identifier.Name == name {
			position = set.Position(identifier.Pos())
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

func TestFileAdapterCallsOnlyUseGuardedRawHelpers(t *testing.T) {
	root := repositoryRoot(t)
	files, err := filepath.Glob(filepath.Join(root, "dice", "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	callCount := 0
	for _, filename := range files {
		if strings.HasSuffix(filename, "_test.go") || strings.HasPrefix(filepath.Base(filename), "platform_adapter") {
			continue
		}
		set, file := parseFile(t, filename)
		sites := fileSendAdapterCallSites(set, file)
		callCount += len(sites)
		if violations := fileSendAdapterCallViolations(set, file); len(violations) > 0 {
			t.Fatalf("file send bypasses its guarded raw helper: violations=%v sites=%#v", violations, sites)
		}
	}
	if callCount != 2 {
		t.Fatalf("core direct file adapter call sites = %d, want exactly the person/group raw helper dispatches", callCount)
	}
}

func TestFileAdapterCallPolicyRejectsUnprotectedFixtures(t *testing.T) {
	tests := []struct {
		name       string
		source     string
		wantErrors int
	}{
		{
			name: "guarded person and group helpers",
			source: `package fixture
type Context struct { EndPoint *Endpoint }
type Endpoint struct { Adapter *Adapter }
type Adapter struct {}
func SendFileToPersonRaw(ctx *Context) {
	if err := fileSendBoundaryError(ctx); err != nil { return }
	ctx.EndPoint.Adapter.SendFileToPerson()
}
func SendFileToGroupRaw(ctx *Context) {
	if err := fileSendBoundaryError(ctx); err != nil { return }
	ctx.EndPoint.Adapter.SendFileToGroup()
}`,
		},
		{
			name: "unrelated helper calls both file methods",
			source: `package fixture
type Context struct { EndPoint *Endpoint }
type Endpoint struct { Adapter *Adapter }
type Adapter struct {}
func sendFiles(ctx *Context) {
	ctx.EndPoint.Adapter.SendFileToPerson()
	ctx.EndPoint.Adapter.SendFileToGroup()
}`,
			wantErrors: 2,
		},
		{
			name: "raw helper sends wrong target",
			source: `package fixture
type Context struct { EndPoint *Endpoint }
type Endpoint struct { Adapter *Adapter }
type Adapter struct {}
func SendFileToPersonRaw(ctx *Context) {
	if err := fileSendBoundaryError(ctx); err != nil { return }
	ctx.EndPoint.Adapter.SendFileToGroup()
}`,
			wantErrors: 1,
		},
		{
			name: "boundary check occurs after dispatch",
			source: `package fixture
type Context struct { EndPoint *Endpoint }
type Endpoint struct { Adapter *Adapter }
type Adapter struct {}
func SendFileToPersonRaw(ctx *Context) {
	ctx.EndPoint.Adapter.SendFileToPerson()
	if err := fileSendBoundaryError(ctx); err != nil { return }
}`,
			wantErrors: 1,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			set := token.NewFileSet()
			file, err := parser.ParseFile(set, test.name+".go", test.source, 0)
			if err != nil {
				t.Fatal(err)
			}
			sites := fileSendAdapterCallSites(set, file)
			if got := len(fileSendAdapterCallViolations(set, file)); got != test.wantErrors {
				t.Fatalf("file-send architecture violations = %d, want %d; sites=%#v", got, test.wantErrors, sites)
			}
		})
	}
}

func TestEndpointCompositionPublicAPIIsStronglyTyped(t *testing.T) {
	root := repositoryRoot(t)
	files, err := filepath.Glob(filepath.Join(root, "endpoint", "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, filename := range files {
		if strings.HasSuffix(filename, "_test.go") {
			continue
		}
		set, file := parseFile(t, filename)
		if position := exportedDynamicTypePosition(set, file); position.Line != 0 {
			t.Fatalf("endpoint public API exposes a dynamic type: %s", position)
		}
	}
}

func TestEndpointCompatibilityEntrypointsDoNotReturn(t *testing.T) {
	root := repositoryRoot(t)
	for directory, names := range map[string][]string{
		"api": {
			"RegisterEndpointService",
			"RegisterEndpointActionExecutor",
		},
		"endpoint": {
			"NewDescriptorRegistry",
			"NewEndpointRepository",
			"EndpointRepository",
			"NewEndpointService",
			"NewEndpointSupervisor",
			"NewEndpointBootstrap",
			"NewEndpointStartup",
			"WithDescriptorRegistry",
			"EndpointState",
			"EndpointAggregate",
			"Aggregate",
			"EndpointCommand",
			"EndpointEvent",
			"EndpointEffect",
			"OperationStatus",
			"EndpointProjection",
			"CommandResult",
			"RegisterEndpointProjections",
		},
	} {
		files, err := filepath.Glob(filepath.Join(root, directory, "*.go"))
		if err != nil {
			t.Fatal(err)
		}
		for _, filename := range files {
			if strings.HasSuffix(filename, "_test.go") {
				continue
			}
			set, file := parseFile(t, filename)
			for _, name := range names {
				if position := identifierPosition(set, file, name); position.Line != 0 {
					t.Fatalf("obsolete endpoint entrypoint %s remains at %s", name, position)
				}
			}
		}
	}
}

func TestBoundaryChecksCatchNegativeFixtures(t *testing.T) {
	set := token.NewFileSet()
	for name, source := range map[string]string{
		"forbidden import":    `package fixture; import _ "Scardice-core/eventstore"`,
		"legacy route":        `package fixture; var _ = "/sd-api/im_connections/list"`,
		"legacy launcher":     `package fixture; func f(){ diceServe() }`,
		"direct adapter call": `package fixture; func f(ctx *Context){ ctx.EndPoint.Adapter.MemberBan("group", "user", 1) }`,
		"dynamic public API":  `package fixture; func NewService(registry any) {}`,
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
			case "direct adapter call":
				if directAdapterCallPosition(set, file, map[string]struct{}{"MemberBan": {}}).Line == 0 {
					t.Fatal("direct adapter call was not detected")
				}
			case "dynamic public API":
				if exportedDynamicTypePosition(set, file).Line == 0 {
					t.Fatal("dynamic public API was not detected")
				}
			}
		})
	}
}
