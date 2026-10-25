package architecture

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"
)

const mcpBackendSource = "internal/composition/mcp_backend.go"

func importNamespace(imported, root string) bool {
	return imported == root || strings.HasPrefix(imported, root+"/")
}

// walkOwnershipSources deliberately includes inactive and ignore-tagged files.
// The older general dependency check retains its separate build-ignore policy.
func walkOwnershipSources(files fs.FS, visit func(string, *ast.File) error) error {
	return fs.WalkDir(files, ".", func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if entry.Name() == ".git" || entry.Name() == "vendor" {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		source, err := fs.ReadFile(files, path)
		if err != nil {
			return err
		}
		// Keep the parser's ordinary object resolution for lexical shadowing.
		file, err := parser.ParseFile(token.NewFileSet(), path, source, parser.ParseComments)
		if err != nil {
			return fmt.Errorf("%s: parse source: %w", path, err)
		}
		return visit(path, file)
	})
}

func establishedOwnershipViolations(files fs.FS) ([]string, error) {
	var violations []string
	err := walkOwnershipSources(files, func(path string, file *ast.File) error {
		for _, spec := range file.Imports {
			imported, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				return err
			}
			if strings.HasPrefix(path, "internal/app/") {
				for _, outward := range []string{"adapters", "builtin", "entrypoint", "composition"} {
					if importNamespace(imported, modulePath+"internal/"+outward) {
						violations = append(violations, path+": app-outward: "+strconv.Quote(imported))
					}
				}
			}
			if strings.HasPrefix(path, "internal/ports/") {
				for _, outward := range []string{"app", "adapters", "entrypoint", "composition"} {
					if importNamespace(imported, modulePath+"internal/"+outward) {
						violations = append(violations, path+": ports-outward: "+strconv.Quote(imported))
					}
				}
			}
			if (strings.HasPrefix(path, "internal/app/") || strings.HasPrefix(path, "internal/domain/")) && imported == "os/user" {
				violations = append(violations, path+": native-account-capability: "+strconv.Quote(imported))
			}
		}
		return nil
	})
	return violations, err
}

func ownershipImportBindings(file *ast.File) (map[string]string, error) {
	bindings := make(map[string]string)
	for _, spec := range file.Imports {
		imported, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			return nil, err
		}
		name := imported[strings.LastIndex(imported, "/")+1:]
		if spec.Name != nil {
			name = spec.Name.Name
		}
		if name == "." || name == "_" {
			continue
		}
		if _, exists := bindings[name]; exists {
			return nil, fmt.Errorf("ambiguous import qualifier %q", name)
		}
		bindings[name] = imported
	}
	return bindings, nil
}

func ownershipUnparen(expression ast.Expr) ast.Expr {
	for {
		parenthesized, ok := expression.(*ast.ParenExpr)
		if !ok {
			return expression
		}
		expression = parenthesized.X
	}
}

// ownershipDirectValue follows direct parentheses, dereference and address-of wrappers.
// Other expressions stop the walk; qualifiers and types use separate matchers.
func ownershipDirectValue(expression ast.Expr) ast.Expr {
	for {
		switch value := expression.(type) {
		case *ast.ParenExpr:
			expression = value.X
		case *ast.StarExpr:
			expression = value.X
		case *ast.UnaryExpr:
			if value.Op != token.AND {
				return expression
			}
			expression = value.X
		default:
			return expression
		}
	}
}

func ownershipQualifier(expression ast.Expr, bindings map[string]string) string {
	identifier, ok := ownershipUnparen(expression).(*ast.Ident)
	if !ok || identifier.Obj != nil {
		return ""
	}
	return bindings[identifier.Name]
}

func typedReviewRequestViolations(files fs.FS) ([]string, error) {
	var violations []string
	declarations := 0
	err := walkOwnershipSources(files, func(path string, file *ast.File) error {
		relative, inside := strings.CutPrefix(path, "internal/entrypoint/mulgae/")
		if !inside || strings.Contains(relative, "/") || file.Name.Name != "mulgae" {
			return nil
		}
		bindings, err := ownershipImportBindings(file)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		for _, declaration := range file.Decls {
			group, ok := declaration.(*ast.GenDecl)
			if !ok || group.Tok != token.TYPE {
				continue
			}
			for _, spec := range group.Specs {
				typeSpec := spec.(*ast.TypeSpec)
				if typeSpec.Name.Name != "ReviewRequest" {
					continue
				}
				declarations++
				target, qualified := ownershipUnparen(typeSpec.Type).(*ast.SelectorExpr)
				if !typeSpec.Assign.IsValid() || !qualified || target.Sel.Name != "Request" || ownershipQualifier(target.X, bindings) != modulePath+"internal/app/reviewrun" {
					violations = append(violations, path+": request-alias: expected direct application reviewrun.Request alias")
				}
			}
		}
		return nil
	})
	if err == nil && declarations != 1 {
		violations = append(violations, fmt.Sprintf("internal/entrypoint/mulgae: request-alias: expected one declaration, found %d", declarations))
	}
	return violations, err
}

func cliApplicationType(expression ast.Expr, bindings map[string]string) bool {
	expression = ownershipUnparen(expression)
	if pointer, ok := expression.(*ast.StarExpr); ok {
		expression = ownershipUnparen(pointer.X)
	}
	qualified, ok := expression.(*ast.SelectorExpr)
	return ok && qualified.Sel.Name == "Application" && ownershipQualifier(qualified.X, bindings) == modulePath+"internal/entrypoint/mulgae"
}

// mcpBackendParserViolations covers direct syntax only. Assignment aliases,
// interfaces and wrappers require the existing typed-pipeline tests and review.
func mcpBackendParserViolations(file *ast.File) ([]string, error) {
	bindings, err := ownershipImportBindings(file)
	if err != nil {
		return nil, err
	}
	var violations []string
	for _, spec := range file.Imports {
		imported, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			return nil, err
		}
		if spec.Name != nil && spec.Name.Name == "." && imported == modulePath+"internal/entrypoint/mulgae" {
			violations = append(violations, mcpBackendSource+": cli-dot-import")
		}
	}
	// A dot import cannot establish the selected qualified field structure.
	if len(violations) != 0 {
		return violations, nil
	}
	var backend *ast.TypeSpec
	for _, declaration := range file.Decls {
		group, ok := declaration.(*ast.GenDecl)
		if !ok || group.Tok != token.TYPE {
			continue
		}
		for _, spec := range group.Specs {
			typeSpec := spec.(*ast.TypeSpec)
			if typeSpec.Name.Name == "mcpBackend" {
				if backend != nil {
					return nil, fmt.Errorf("ambiguous mcpBackend declaration")
				}
				backend = typeSpec
			}
		}
	}
	if backend == nil {
		return nil, fmt.Errorf("missing mcpBackend struct")
	}
	structure, ok := backend.Type.(*ast.StructType)
	if !ok || backend.Assign.IsValid() {
		return nil, fmt.Errorf("expected mcpBackend struct")
	}
	applicationFields := make(map[string]bool)
	for _, field := range structure.Fields.List {
		pointer, ok := ownershipUnparen(field.Type).(*ast.StarExpr)
		if !ok || !cliApplicationType(pointer.X, bindings) {
			continue
		}
		if len(field.Names) == 0 {
			applicationFields["Application"] = true
		}
		for _, name := range field.Names {
			applicationFields[name.Name] = true
		}
	}
	if len(applicationFields) == 0 {
		return nil, fmt.Errorf("missing CLI Application field in mcpBackend")
	}
	backendObjects := make(map[*ast.Object]bool)
	ast.Inspect(file, func(node ast.Node) bool {
		field, ok := node.(*ast.Field)
		if !ok {
			return true
		}
		expression := ownershipUnparen(field.Type)
		if pointer, ok := expression.(*ast.StarExpr); ok {
			expression = ownershipUnparen(pointer.X)
		}
		identifier, ok := expression.(*ast.Ident)
		if ok && identifier.Obj != nil && identifier.Obj == backend.Name.Obj {
			for _, name := range field.Names {
				if name.Obj != nil {
					backendObjects[name.Obj] = true
				}
			}
		}
		return true
	})
	ast.Inspect(file, func(node ast.Node) bool {
		selector, ok := node.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if (selector.Sel.Name == "Parse" || selector.Sel.Name == "ParseResolved") && ownershipQualifier(selector.X, bindings) == modulePath+"internal/entrypoint/mulgae" {
			violations = append(violations, mcpBackendSource+": cli-parser: "+selector.Sel.Name)
		}
		if selector.Sel.Name != "Run" {
			return true
		}
		if cliApplicationType(selector.X, bindings) {
			violations = append(violations, mcpBackendSource+": cli-run: Application.Run")
			return true
		}
		field, ok := ownershipDirectValue(selector.X).(*ast.SelectorExpr)
		if !ok || !applicationFields[field.Sel.Name] {
			return true
		}
		receiver, ok := ownershipDirectValue(field.X).(*ast.Ident)
		if ok && receiver.Obj != nil && backendObjects[receiver.Obj] {
			violations = append(violations, mcpBackendSource+": cli-run: Application.Run")
		}
		return true
	})
	return violations, nil
}

func mcpParserRouteViolations(files fs.FS) ([]string, error) {
	var violations []string
	foundBackend := false
	err := walkOwnershipSources(files, func(path string, file *ast.File) error {
		if strings.HasPrefix(path, "internal/entrypoint/mcp/") {
			for _, spec := range file.Imports {
				imported, err := strconv.Unquote(spec.Path.Value)
				if err != nil {
					return err
				}
				if importNamespace(imported, modulePath+"internal/entrypoint/mulgae") {
					violations = append(violations, path+": mcp-cli-import: "+strconv.Quote(imported))
				}
			}
		}
		if path == mcpBackendSource {
			foundBackend = true
			found, err := mcpBackendParserViolations(file)
			if err != nil {
				return fmt.Errorf("%s: %w", path, err)
			}
			violations = append(violations, found...)
		}
		return nil
	})
	if err == nil && !foundBackend {
		err = fmt.Errorf("%s: missing protected source", mcpBackendSource)
	}
	return violations, err
}

func TestEstablishedOwnershipDependencyDirection(t *testing.T) {
	violations, err := establishedOwnershipViolations(os.DirFS(repositoryRoot(t)))
	requireOwnershipViolations(t, violations, err)
}

func TestTypedReviewRequestOwnership(t *testing.T) {
	violations, err := typedReviewRequestViolations(os.DirFS(repositoryRoot(t)))
	requireOwnershipViolations(t, violations, err)
}

func TestMCPParserRouteOwnership(t *testing.T) {
	violations, err := mcpParserRouteViolations(os.DirFS(repositoryRoot(t)))
	requireOwnershipViolations(t, violations, err)
}

func requireOwnershipViolations(t *testing.T, got []string, err error, want ...string) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(got)
	sort.Strings(want)
	if !slices.Equal(got, want) {
		t.Fatalf("ownership violations = %q, want %q", got, want)
	}
}

func ownershipImportFixture(path, header, alias, imported string) fstest.MapFS {
	return fstest.MapFS{path: {Data: []byte(header + "package example\nimport " + alias + " " + strconv.Quote(imported) + "\n")}}
}

func TestEstablishedOwnershipDependencyControls(t *testing.T) {
	for _, owner := range []string{"app", "ports"} {
		outward := []string{"adapters", "builtin", "entrypoint", "composition"}
		if owner == "ports" {
			outward = []string{"app", "adapters", "entrypoint", "composition"}
		}
		for _, target := range outward {
			for _, suffix := range []string{"", "/selected"} {
				for _, alias := range []string{"", "renamed", "_", "."} {
					name := owner + "/" + target + suffix + "/" + alias
					t.Run(name, func(t *testing.T) {
						path := "internal/" + owner + "/selected.go"
						positive := ownershipImportFixture(path, "", alias, "context")
						got, err := establishedOwnershipViolations(positive)
						requireOwnershipViolations(t, got, err)
						imported := modulePath + "internal/" + target + suffix
						got, err = establishedOwnershipViolations(ownershipImportFixture(path, "", alias, imported))
						requireOwnershipViolations(t, got, err, path+": "+owner+"-outward: "+strconv.Quote(imported))
					})
				}
			}
		}
	}
	for _, owner := range []string{"app", "domain"} {
		t.Run(owner+"/native-account", func(t *testing.T) {
			path := "internal/" + owner + "/account.go"
			got, err := establishedOwnershipViolations(ownershipImportFixture(path, "", "_", "context"))
			requireOwnershipViolations(t, got, err)
			got, err = establishedOwnershipViolations(ownershipImportFixture(path, "", "_", "os/user"))
			requireOwnershipViolations(t, got, err, path+": native-account-capability: \"os/user\"")
		})
	}
	for _, header := range []string{"//go:build ignore\n\n", "//go:build windows\n\n"} {
		t.Run(header, func(t *testing.T) {
			path := "internal/app/tagged_windows.go"
			got, err := establishedOwnershipViolations(ownershipImportFixture(path, header, "_", "context"))
			requireOwnershipViolations(t, got, err)
			imported := modulePath + "internal/composition"
			got, err = establishedOwnershipViolations(ownershipImportFixture(path, header, "_", imported))
			requireOwnershipViolations(t, got, err, path+": app-outward: "+strconv.Quote(imported))
		})
	}
	for _, test := range []struct{ path, imported string }{
		{"internal/app/selected.go", modulePath + "internal/ports"},
		{"internal/app/selected.go", modulePath + "internal/app/reviewrun"},
		{"internal/app/selected.go", "net/url"},
		{"internal/app/selected.go", "io/fs"},
		{"internal/app/selected.go", "path/filepath"},
		{"internal/app/selected.go", modulePath + "internal/compositionish"},
		{"internal/app/selected.go", "example.org/internal/composition"},
		{"internal/app/selected_test.go", modulePath + "internal/adapters/filesystem"},
		{"internal/adapters/environment/account.go", "os/user"},
		{"internal/adapters/filesystem/selected.go", modulePath + "internal/adapters/workspace"},
		{"internal/ports/selected.go", modulePath + "internal/domain"},
		{"internal/appish/selected.go", modulePath + "internal/adapters"},
	} {
		t.Run(test.path+"/"+test.imported, func(t *testing.T) {
			got, err := establishedOwnershipViolations(ownershipImportFixture(test.path, "", "_", test.imported))
			requireOwnershipViolations(t, got, err)
		})
	}
}

func TestTypedReviewRequestOwnershipControls(t *testing.T) {
	const path = "internal/entrypoint/mulgae/moved_request.go"
	valid := "package mulgae\nimport owned " + strconv.Quote(modulePath+"internal/app/reviewrun") + "\ntype ReviewRequest = owned.Request\n"
	for _, test := range []struct {
		name, source string
		want         []string
	}{
		{"alias in another file", valid, nil},
		{"default qualifier", strings.Replace(strings.ReplaceAll(valid, "owned", "reviewrun"), "import reviewrun ", "import ", 1), nil},
		{"defined type", strings.Replace(valid, " = ", " ", 1), []string{path + ": request-alias: expected direct application reviewrun.Request alias"}},
		{"wrong owner", strings.Replace(valid, "internal/app/reviewrun", "internal/entrypoint/other", 1), []string{path + ": request-alias: expected direct application reviewrun.Request alias"}},
		{"wrong type", strings.Replace(valid, "owned.Request", "owned.RequestInput", 1), []string{path + ": request-alias: expected direct application reviewrun.Request alias"}},
		{"additional alias", valid + "type Other = owned.Request\n", nil},
		{"local alias target", strings.Replace(valid, "= owned.Request", "= Other", 1) + "type Other = owned.Request\n", []string{path + ": request-alias: expected direct application reviewrun.Request alias"}},
		{"dot alias target", strings.Replace(strings.Replace(valid, "import owned ", "import . ", 1), "owned.Request", "Request", 1), []string{path + ": request-alias: expected direct application reviewrun.Request alias"}},
		{"only a comment", "package mulgae\n// type ReviewRequest = reviewrun.Request\n", []string{"internal/entrypoint/mulgae: request-alias: expected one declaration, found 0"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := typedReviewRequestViolations(fstest.MapFS{path: {Data: []byte(valid)}})
			requireOwnershipViolations(t, got, err)
			got, err = typedReviewRequestViolations(fstest.MapFS{path: {Data: []byte(test.source)}})
			requireOwnershipViolations(t, got, err, test.want...)
		})
	}
	t.Run("duplicate", func(t *testing.T) {
		files := fstest.MapFS{path: {Data: []byte(valid)}}
		got, err := typedReviewRequestViolations(files)
		requireOwnershipViolations(t, got, err)
		files["internal/entrypoint/mulgae/duplicate.go"] = &fstest.MapFile{Data: []byte(valid)}
		got, err = typedReviewRequestViolations(files)
		requireOwnershipViolations(t, got, err, "internal/entrypoint/mulgae: request-alias: expected one declaration, found 2")
	})
	t.Run("test declaration excluded", func(t *testing.T) {
		got, err := typedReviewRequestViolations(fstest.MapFS{path: {Data: []byte(valid)}})
		requireOwnershipViolations(t, got, err)
		got, err = typedReviewRequestViolations(fstest.MapFS{"internal/entrypoint/mulgae/request_test.go": {Data: []byte(valid)}})
		requireOwnershipViolations(t, got, err, "internal/entrypoint/mulgae: request-alias: expected one declaration, found 0")
	})
	t.Run("nested package excluded", func(t *testing.T) {
		files := fstest.MapFS{
			path: {Data: []byte(valid)},
			"internal/entrypoint/mulgae/nested/request.go": {Data: []byte("package mulgae\ntype ReviewRequest struct{}\n")},
		}
		got, err := typedReviewRequestViolations(files)
		requireOwnershipViolations(t, got, err)
	})
	t.Run("ambiguous alias import", func(t *testing.T) {
		files := fstest.MapFS{path: {Data: []byte(valid)}}
		got, err := typedReviewRequestViolations(files)
		requireOwnershipViolations(t, got, err)
		files[path].Data = []byte(strings.Replace(valid, "type ReviewRequest", "import owned \"context\"\ntype ReviewRequest", 1))
		got, err = typedReviewRequestViolations(files)
		if err == nil || err.Error() != path+": ambiguous import qualifier \"owned\"" || len(got) != 0 {
			t.Fatalf("inspection = %q, %v; want ambiguous alias import only", got, err)
		}
	})
	for _, header := range []string{"//go:build ignore\n\n", "//go:build windows\n\n"} {
		t.Run("tagged alias/"+header, func(t *testing.T) {
			got, err := typedReviewRequestViolations(fstest.MapFS{path: {Data: []byte(header + valid)}})
			requireOwnershipViolations(t, got, err)
			invalid := strings.Replace(valid, " = ", " ", 1)
			got, err = typedReviewRequestViolations(fstest.MapFS{path: {Data: []byte(header + invalid)}})
			requireOwnershipViolations(t, got, err, path+": request-alias: expected direct application reviewrun.Request alias")
		})
	}
}

func mcpParserFixture(qualifier, field, body string) fstest.MapFS {
	binding := qualifier
	if binding == "" {
		binding = "mulgae"
	}
	source := fmt.Sprintf(`package composition
import %s %q
type mcpBackend struct { %s *%s.Application }
func (backend *mcpBackend) review() {
    _ = backend.%s.PreflightReview
    _ = backend.%s.StartReviewRun
    %s
}
`, qualifier, modulePath+"internal/entrypoint/mulgae", field, binding, field, field, body)
	return fstest.MapFS{mcpBackendSource: {Data: []byte(source)}}
}

func TestMCPParserRouteControls(t *testing.T) {
	for _, qualifier := range []string{"", "renamed"} {
		binding := qualifier
		if binding == "" {
			binding = "mulgae"
		}
		for _, field := range []string{"application", "driver"} {
			for _, test := range []struct {
				name, body, diagnostic string
			}{
				{"parse call", "_, _ = Q.Parse(nil, \"/fixture\", \"id\")", "cli-parser: Parse"},
				{"parse value", "_ = Q.Parse", "cli-parser: Parse"},
				{"resolved call", "_, _ = Q.ParseResolved(nil, nil, \"/fixture\", \"id\", nil)", "cli-parser: ParseResolved"},
				{"resolved value", "_ = Q.ParseResolved", "cli-parser: ParseResolved"},
				{"run call", "_ = backend.F.Run(nil, nil, \"/fixture\")", "cli-run: Application.Run"},
				{"run value", "_ = (backend.F).Run", "cli-run: Application.Run"},
				{"run method expression", "_ = (*Q.Application).Run", "cli-run: Application.Run"},
			} {
				t.Run(qualifier+"/"+field+"/"+test.name, func(t *testing.T) {
					got, err := mcpParserRouteViolations(mcpParserFixture(qualifier, field, ""))
					requireOwnershipViolations(t, got, err)
					body := strings.ReplaceAll(strings.ReplaceAll(test.body, "Q.", binding+"."), ".F", "."+field)
					got, err = mcpParserRouteViolations(mcpParserFixture(qualifier, field, body))
					requireOwnershipViolations(t, got, err, mcpBackendSource+": "+test.diagnostic)
				})
			}
			for _, receiverMode := range []string{"receiver", "parameter"} {
				for _, form := range []struct{ name, expression string }{
					{"backend dereference", "(*%s).%s"},
					{"field dereference", "(*%s.%s)"},
					{"combined dereference", "(*(*%s).%s)"},
					{"backend address dereference", "(&*%s).%s"},
					{"field address dereference", "(&*%s.%s)"},
					{"backend dereference address", "(*&%s).%s"},
					{"field dereference address", "(*&%s.%s)"},
					{"combined address dereference", "(&*(&*%s).%s)"},
					{"combined dereference address", "(*&(*&%s).%s)"},
					{"mixed backend wrappers", "(*(&*%s)).%s"},
					{"mixed field wrappers", "(*(&*%s.%s))"},
					{"value backend address", "(&%s).%s"},
				} {
					for _, use := range []string{"value", "call"} {
						t.Run("dereference/"+binding+"/"+field+"/"+receiverMode+"/"+form.name+"/"+use, func(t *testing.T) {
							receiver := "backend"
							if receiverMode == "parameter" {
								receiver = "b"
							}
							target := fmt.Sprintf(form.expression, receiver, field)
							valueBackend := form.name == "value backend address"
							body := func(method string) string {
								if use == "value" {
									return "_ = " + target + "." + method
								}
								if method == "Run" {
									return "_ = " + target + ".Run(nil, nil, \"/fixture\")"
								}
								return "_, _ = " + target + "." + method + "(nil, request, root)"
							}
							fixture := func(statement string) fstest.MapFS {
								methodBody := statement
								if receiverMode == "parameter" {
									methodBody = ""
								}
								files := mcpParserFixture(qualifier, field, methodBody)
								source := string(files[mcpBackendSource].Data)
								source = strings.Replace(source, "type mcpBackend", "import ports "+strconv.Quote(modulePath+"internal/ports")+"\ntype mcpBackend", 1)
								parameters := "request " + binding + ".ReviewRequest, root ports.AnchoredRoot"
								if receiverMode == "parameter" {
									backendType := "*mcpBackend"
									if valueBackend {
										backendType = "mcpBackend"
									}
									source += "func invoke(b " + backendType + ", " + parameters + ") { " + statement + " }\n"
								} else {
									source = strings.Replace(source, "review()", "review("+parameters+")", 1)
									if valueBackend {
										source = strings.Replace(source, "(backend *mcpBackend)", "(backend mcpBackend)", 1)
									}
								}
								files[mcpBackendSource].Data = []byte(source)
								return files
							}
							for _, method := range []string{"StartReviewRun", "PreflightReview"} {
								t.Run("typed/"+method, func(t *testing.T) {
									got, err := mcpParserRouteViolations(fixture(body(method)))
									requireOwnershipViolations(t, got, err)
								})
							}
							shadowType := "*struct{ " + field + " *struct{ Run func(any, []string, string) " + binding + ".Result } }"
							for _, shadow := range []string{"local pointer", "parameter pointer"} {
								t.Run("shadow/"+shadow, func(t *testing.T) {
									shadowBody := body("Run")
									if valueBackend {
										shadowBody = strings.ReplaceAll(shadowBody, "(&"+receiver+").", "(&*"+receiver+").")
									}
									statement := "{ " + receiver + " := &" + strings.TrimPrefix(shadowType, "*") + "{}; " + shadowBody + " }"
									if shadow == "parameter pointer" {
										statement = "func(" + receiver + " " + shadowType + ") { " + shadowBody + " }(nil)"
									}
									got, err := mcpParserRouteViolations(fixture(statement))
									requireOwnershipViolations(t, got, err)
								})
							}
							t.Run("run", func(t *testing.T) {
								got, err := mcpParserRouteViolations(fixture(body("Run")))
								requireOwnershipViolations(t, got, err, mcpBackendSource+": cli-run: Application.Run")
							})
						})
					}
				}
			}
		}
	}
	for _, test := range []struct{ name, body string }{
		{"qualifier variable shadow", "renamed := struct{ Parse func() }{}; _ = renamed.Parse"},
		{"qualifier parameter shadow", "func(renamed struct{ ParseResolved func() }) { _ = renamed.ParseResolved }(struct{ ParseResolved func() }{})"},
		{"qualifier pointer shadow value", "renamed := &struct{ Parse func(); ParseResolved func() }{}; _ = (*renamed).Parse; _ = (*renamed).ParseResolved"},
		{"qualifier pointer shadow call", "func(renamed *struct{ Parse func(); ParseResolved func() }) { (*renamed).Parse(); (*renamed).ParseResolved() }(nil)"},
		{"qualifier address shadow value", "renamed := &struct{ Parse func(); ParseResolved func() }{}; _ = (&*renamed).Parse; _ = (*&renamed).ParseResolved"},
		{"qualifier address shadow call", "func(renamed *struct{ Parse func(); ParseResolved func() }) { (&*renamed).Parse(); (*&renamed).ParseResolved() }(nil)"},
		{"receiver shadow", "func(backend struct{ driver struct{ Run func() } }) { _ = backend.driver.Run }(struct{ driver struct{ Run func() } }{})"},
		{"receiver local shadow", "{ backend := struct{ driver struct{ Run func() } }{}; _ = backend.driver.Run }"},
		{"unrelated methods", "other := struct{ Parse func(); Run func() }{}; _ = other.Parse; _ = other.Run"},
		{"nonmatching imported selector", "_ = renamed.NewApplication"},
		{"comment and string", "// renamed.Parse and backend.driver.Run\n_ = \"renamed.ParseResolved\""},
		{"call expression boundary", "_ = (func() *mcpBackend { return backend })().driver.Run"},
		{"index expression boundary", "_ = ([]*mcpBackend{backend})[0].driver.Run"},
		{"type assertion boundary", "_ = any(backend).(*mcpBackend).driver.Run"},
		{"receive expression boundary", "_ = (<-make(chan *mcpBackend)).driver.Run"},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := mcpParserRouteViolations(mcpParserFixture("renamed", "driver", test.body))
			requireOwnershipViolations(t, got, err)
		})
	}
	t.Run("explicit backend parameter", func(t *testing.T) {
		files := mcpParserFixture("cli", "driver", "")
		positive := append([]byte(nil), files[mcpBackendSource].Data...)
		files[mcpBackendSource].Data = append(positive, []byte("func invoke(b *mcpBackend) { _ = b.driver.StartReviewRun }\n")...)
		got, err := mcpParserRouteViolations(files)
		requireOwnershipViolations(t, got, err)
		files[mcpBackendSource].Data = append(positive, []byte("func invoke(b *mcpBackend) { _ = b.driver.Run }\n")...)
		got, err = mcpParserRouteViolations(files)
		requireOwnershipViolations(t, got, err, mcpBackendSource+": cli-run: Application.Run")
	})
	for _, alias := range []string{"", "renamed", "_", "."} {
		for _, suffix := range []string{"", "/selected"} {
			t.Run("MCP import/"+alias+suffix, func(t *testing.T) {
				files := mcpParserFixture("cli", "driver", "")
				path := "internal/entrypoint/mcp/request.go"
				files[path] = ownershipImportFixture(path, "", alias, "context")[path]
				got, err := mcpParserRouteViolations(files)
				requireOwnershipViolations(t, got, err)
				imported := modulePath + "internal/entrypoint/mulgae" + suffix
				files[path] = ownershipImportFixture(path, "", alias, imported)[path]
				got, err = mcpParserRouteViolations(files)
				requireOwnershipViolations(t, got, err, path+": mcp-cli-import: "+strconv.Quote(imported))
			})
		}
	}
	t.Run("protected backend dot import", func(t *testing.T) {
		files := mcpParserFixture("cli", "driver", "")
		got, err := mcpParserRouteViolations(files)
		requireOwnershipViolations(t, got, err)
		files[mcpBackendSource].Data = []byte("package composition\nimport . " + strconv.Quote(modulePath+"internal/entrypoint/mulgae") + "\ntype mcpBackend struct{ driver *Application }\nfunc invoke(b *mcpBackend) { _ = Parse; _ = b.driver.Run }\n")
		got, err = mcpParserRouteViolations(files)
		requireOwnershipViolations(t, got, err, mcpBackendSource+": cli-dot-import")
	})
	t.Run("legitimate composition dispatch", func(t *testing.T) {
		files := mcpParserFixture("cli", "driver", "")
		files["internal/composition/run.go"] = &fstest.MapFile{Data: []byte("package composition\nimport cli " + strconv.Quote(modulePath+"internal/entrypoint/mulgae") + "\nimport mcp " + strconv.Quote(modulePath+"internal/entrypoint/mcp") + "\nfunc dispatch(a *cli.Application) { _ = cli.Parse; _ = a.Run; _ = mcp.Parse }\n")}
		got, err := mcpParserRouteViolations(files)
		requireOwnershipViolations(t, got, err)
	})
	for _, header := range []string{"//go:build ignore\n\n", "//go:build windows\n\n"} {
		t.Run("tagged MCP/"+header, func(t *testing.T) {
			files := mcpParserFixture("cli", "driver", "")
			path := "internal/entrypoint/mcp/request_windows.go"
			files[path] = ownershipImportFixture(path, header, "_", "context")[path]
			got, err := mcpParserRouteViolations(files)
			requireOwnershipViolations(t, got, err)
			imported := modulePath + "internal/entrypoint/mulgae"
			files[path] = ownershipImportFixture(path, header, "_", imported)[path]
			got, err = mcpParserRouteViolations(files)
			requireOwnershipViolations(t, got, err, path+": mcp-cli-import: "+strconv.Quote(imported))
		})
	}
	t.Run("MCP test import excluded", func(t *testing.T) {
		files := mcpParserFixture("cli", "driver", "")
		path := "internal/entrypoint/mcp/request_test.go"
		files[path] = ownershipImportFixture(path, "", "_", modulePath+"internal/entrypoint/mulgae")[path]
		got, err := mcpParserRouteViolations(files)
		requireOwnershipViolations(t, got, err)
	})
}

func TestOwnershipInspectionFailures(t *testing.T) {
	for _, test := range []struct{ name, source, want string }{
		{"missing source", "", mcpBackendSource + ": missing protected source"},
		{"missing backend", "package composition\n", mcpBackendSource + ": missing mcpBackend struct"},
		{"wrong backend", "package composition\ntype mcpBackend int\n", mcpBackendSource + ": expected mcpBackend struct"},
		{"missing application", "package composition\ntype mcpBackend struct{}\n", mcpBackendSource + ": missing CLI Application field in mcpBackend"},
		{"ambiguous backend", "package composition\ntype mcpBackend struct{}\ntype mcpBackend struct{}\n", mcpBackendSource + ": ambiguous mcpBackend declaration"},
		{"ambiguous import", "package composition\nimport same \"context\"\nimport same \"fmt\"\n", mcpBackendSource + ": ambiguous import qualifier \"same\""},
	} {
		t.Run(test.name, func(t *testing.T) {
			files := mcpParserFixture("cli", "driver", "")
			got, err := mcpParserRouteViolations(files)
			requireOwnershipViolations(t, got, err)
			if test.source == "" {
				delete(files, mcpBackendSource)
			} else {
				files[mcpBackendSource].Data = []byte(test.source)
			}
			got, err = mcpParserRouteViolations(files)
			if err == nil || err.Error() != test.want || len(got) != 0 {
				t.Fatalf("inspection = %q, %v; want only %q", got, err, test.want)
			}
		})
	}
	for _, scan := range []struct {
		name string
		run  func(fs.FS) ([]string, error)
	}{
		{"dependencies", establishedOwnershipViolations},
		{"request", typedReviewRequestViolations},
		{"MCP", mcpParserRouteViolations},
	} {
		t.Run("malformed/"+scan.name, func(t *testing.T) {
			files := mcpParserFixture("cli", "driver", "")
			files["internal/entrypoint/mulgae/request.go"] = &fstest.MapFile{Data: []byte("package mulgae\nimport r " + strconv.Quote(modulePath+"internal/app/reviewrun") + "\ntype ReviewRequest = r.Request\n")}
			got, err := scan.run(files)
			requireOwnershipViolations(t, got, err)
			files["bad.go"] = &fstest.MapFile{Data: []byte("package")}
			got, err = scan.run(files)
			if err == nil || !strings.HasPrefix(err.Error(), "bad.go: parse source: ") || len(got) != 0 {
				t.Fatalf("inspection = %q, %v; want malformed-source error only", got, err)
			}
		})
	}
}
