//go:build darwin && arm64

package composition

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/adapters/environment"
	"github.com/irootkernel/mulgae/internal/adapters/filesystem"
	"github.com/irootkernel/mulgae/internal/adapters/gittarget"
	"github.com/irootkernel/mulgae/internal/adapters/jsonschema"
	"github.com/irootkernel/mulgae/internal/app/reviewrun"
	"github.com/irootkernel/mulgae/internal/builtin"
	mcpentry "github.com/irootkernel/mulgae/internal/entrypoint/mcp"
	mulgaeentry "github.com/irootkernel/mulgae/internal/entrypoint/mulgae"
	"github.com/irootkernel/mulgae/internal/ports"
)

const requirementsFixture = `{"schema_version":"mulgae-requirements-input.v1","requirements":[{"id":"R","text":"Private requirement phrase.","acceptance_criteria":["Private criterion phrase."],"owner_role":"logic"}]}`

func requirementsProject(t *testing.T, emptyCommit bool) (ports.AnchoredRoot, *gittarget.Adapter) {
	t.Helper()
	path := canonicalTestTempDir(t)
	git := func(args ...string) {
		t.Helper()
		cmd := exec.Command("/usr/bin/git", append([]string{"-C", path}, args...)...)
		if raw, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git fixture: %v %s", err, raw)
		}
	}
	git("init", "--quiet")
	if emptyCommit {
		git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "--allow-empty", "--quiet", "-m", "Empty")
	}
	if err := os.Mkdir(filepath.Join(path, ".mulgae"), 0700); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string]string{"config.yaml": compositionProjectConfig, "local.yaml": compositionLocalConfig} {
		if err := os.WriteFile(filepath.Join(path, ".mulgae", name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	reader, err := gittarget.New(gittarget.NewExecRunner())
	if err != nil {
		t.Fatal(err)
	}
	root, _ := ports.NewAnchoredRoot(path)
	return root, reader
}

func requirementsPreflight(t *testing.T, root ports.AnchoredRoot, reader ports.TrustedProjectReader, selector []string, extra ...string) (mulgaeentry.ReviewPreflightResult, error) {
	t.Helper()
	argv := append([]string{"review"}, selector...)
	argv = append(argv, "--roles", "logic", "--preflight", "--requirements", "requirements.json")
	invocation, err := mulgaeentry.Parse(append(argv, extra...), root.String(), rejectionRequestID)
	if err != nil {
		return mulgaeentry.ReviewPreflightResult{}, err
	}
	service, err := composeReviewPreflight(context.Background(), builtin.NewCatalog(), root, reader)
	if err != nil {
		return mulgaeentry.ReviewPreflightResult{}, err
	}
	request, _ := invocation.Review()
	return service.PreflightReview(context.Background(), request, root)
}

func TestRequirementsPreflightAdmitsInputBeforeEveryNoChangeBranch(t *testing.T) {
	for _, unborn := range []bool{false, true} {
		root, reader := requirementsProject(t, !unborn)
		selectors := [][]string{{"--workspace"}, {"--stage"}}
		if !unborn {
			selectors = append(selectors, []string{"--head"}, []string{"--commit", "HEAD"}, []string{"--diff", "HEAD..HEAD"}, []string{"--diff", "HEAD...HEAD"})
		}
		for _, selector := range selectors {
			t.Run(strings.Join(selector, " "), func(t *testing.T) {
				if _, err := requirementsPreflight(t, root, reader, selector); err == nil {
					t.Fatal("missing input bypassed admission on empty target")
				}
			})
		}
		if err := os.WriteFile(filepath.Join(root.String(), "requirements.json"), []byte(requirementsFixture), 0644); err != nil {
			t.Fatal(err)
		}
		for _, selector := range selectors {
			result, err := requirementsPreflight(t, root, reader, selector, "--objective", "Preserve behavior.")
			if err != nil {
				t.Fatalf("valid local input %v: %v", selector, err)
			}
			if result.Requirements == nil || result.Requirements.SelectedCount != 1 || result.Requirements.EvaluationStatus != "not_run" || result.Requirements.ExecutionAvailable || result.Requirements.ExtractionPolicy != "disabled" {
				t.Fatalf("invalid admission summary: %+v", result.Requirements)
			}
			if selector[0] != "--workspace" && result.Status != "no_change" {
				t.Fatalf("selected empty tree changed: %v %s", selector, result.Status)
			}
		}
		entries, err := os.ReadDir(filepath.Join(root.String(), ".mulgae"))
		if err != nil || len(entries) != 2 {
			t.Fatal("provider-free admission created run/publication state")
		}
	}
}

func TestRequirementsPreflightRejectsStrictInputAndBinding(t *testing.T) {
	root, reader := requirementsProject(t, true)
	path := filepath.Join(root.String(), "requirements.json")
	for _, raw := range []string{`{}`, requirementsFixture + `{}`, strings.Replace(requirementsFixture, `"id":"R"`, `"id":"R","id":"S"`, 1), strings.Replace(requirementsFixture, `"logic"`, `"security"`, 1), strings.Replace(requirementsFixture, `Private requirement phrase.`, `\ud800`, 1)} {
		if err := os.WriteFile(path, []byte(raw), 0644); err != nil {
			t.Fatal(err)
		}
		if _, err := requirementsPreflight(t, root, reader, []string{"--head"}); err == nil {
			t.Fatal("invalid requirements admitted on empty-tree HEAD")
		}
	}
	if err := os.WriteFile(path, []byte(requirementsFixture), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := requirementsPreflight(t, root, reader, []string{"--stage"}, "--expected-project-binding", "sha256:"+strings.Repeat("a", 64)); !errors.Is(err, reviewrun.ErrProjectBindingMismatch) {
		t.Fatalf("binding guard changed: %v", err)
	}
	configPath := filepath.Join(root.String(), ".mulgae", "config.yaml")
	configured := strings.Replace(compositionProjectConfig, "validation:\n", "validation:\n  extraction: {enabled: true}\n", 1)
	if err := os.WriteFile(configPath, []byte(configured), 0600); err != nil {
		t.Fatal(err)
	}
	result, err := requirementsPreflight(t, root, reader, []string{"--stage"})
	if err != nil || result.Requirements.ExtractionPolicy != "enabled" {
		t.Fatalf("configured extraction projection: %+v %v", result.Requirements, err)
	}
}

func TestRequirementsPreflightKeepsUntrackedInputOutsideSelectedGitEvidence(t *testing.T) {
	root, reader := requirementsProject(t, false)
	git := func(args ...string) {
		t.Helper()
		cmd := exec.Command("/usr/bin/git", append([]string{"-C", root.String()}, args...)...)
		if raw, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git fixture: %v %s", err, raw)
		}
	}
	code := filepath.Join(root.String(), "code.txt")
	if err := os.WriteFile(code, []byte("committed\n"), 0644); err != nil {
		t.Fatal(err)
	}
	git("add", "code.txt")
	git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "--quiet", "-m", "Code")
	if err := os.WriteFile(code, []byte("index\n"), 0644); err != nil {
		t.Fatal(err)
	}
	git("add", "code.txt")
	if err := os.WriteFile(code, []byte("worktree\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root.String(), "requirements.json"), []byte(requirementsFixture), 0644); err != nil {
		t.Fatal(err)
	}
	for _, selector := range [][]string{{"--stage"}, {"--head"}, {"--commit", "HEAD"}, {"--diff", "HEAD..HEAD"}} {
		result, err := requirementsPreflight(t, root, reader, selector)
		if err != nil {
			t.Fatalf("local requirements with %v: %v", selector, err)
		}
		if result.Requirements == nil || result.Requirements.Items[0].RequirementID != "R" {
			t.Fatal("untracked local input was lost")
		}
		for _, read := range result.ReadPlan {
			if read.Path == "requirements.json" || read.Side == "worktree" {
				t.Fatal("local input widened selected Git evidence")
			}
		}
	}
	if raw, err := os.ReadFile(code); err != nil || string(raw) != "worktree\n" {
		t.Fatal("preflight changed caller source")
	}
}

type requirementsWriter struct {
	ports.SecureFileWriter
	ensures, writes int
}

func (writer *requirementsWriter) EnsurePrivateDir(root ports.AnchoredRoot, path ports.SafeRelativePath) error {
	writer.ensures++
	return writer.SecureFileWriter.EnsurePrivateDir(root, path)
}
func (writer *requirementsWriter) Write(ctx context.Context, request ports.SecureWriteRequest) (ports.SecureWriteReceipt, *ports.DropMetadata, error) {
	writer.writes++
	return writer.SecureFileWriter.Write(ctx, request)
}

func TestIntegrationRequirementsPreflightCLIAndMCPRemainProviderFree(t *testing.T) {
	root, reader := requirementsProject(t, true)
	if err := os.WriteFile(filepath.Join(root.String(), "requirements.json"), []byte(requirementsFixture), 0644); err != nil {
		t.Fatal(err)
	}
	prepared := 0
	runs := newDeferredReviewRunServiceWithPreflight(func(context.Context, ports.AnchoredRoot) (mulgaeentry.ReviewRunService, error) {
		prepared++
		return nil, errors.New("provider preparation must not run")
	}, func(ctx context.Context, root ports.AnchoredRoot) (mulgaeentry.ReviewPreflightService, error) {
		return composeReviewPreflight(ctx, builtin.NewCatalog(), root, reader)
	})
	writer := &requirementsWriter{SecureFileWriter: filesystem.NewSecureWriter()}
	catalog := builtin.NewCatalog()
	validator, err := jsonschema.New(context.Background(), catalog)
	if err != nil {
		t.Fatal(err)
	}
	application, err := mulgaeentry.NewApplication(mulgaeentry.Dependencies{Clock: mcpTestClock{}, RequestIDGenerator: mcpTestRequestIDs{}, Catalog: catalog, JSONSchemaValidator: validator, SecureWriter: writer, TrustedProjectReader: reader, EnvironmentInspector: environment.NewInspector(), ReviewRuns: runs, ProjectContexts: inspectionContexts(), PublicationQueries: &mcpQueryFake{}, PublicationReports: &mcpReportFake{}})
	if err != nil {
		t.Fatal(err)
	}
	args := []string{"review", "--stage", "--roles", "logic", "--requirements", "requirements.json", "--objective", "Preserve behavior.", "--output", "json"}
	cli := application.Run(context.Background(), append(append([]string(nil), args...), "--preflight"), root.String())
	if cli.ExitCode() != 0 {
		t.Fatalf("CLI preflight: %s %s", cli.Stdout(), cli.Stderr())
	}
	var envelope struct {
		SchemaVersion string `json:"schema_version"`
		Result        struct {
			Preflight mulgaeentry.ReviewPreflightResult `json:"preflight"`
		} `json:"result"`
	}
	if err := json.Unmarshal(cli.Stdout(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.SchemaVersion != "mulgae-command-result.v22" || bytes.Contains(cli.Stdout(), []byte("Private requirement")) || bytes.Contains(cli.Stdout(), []byte("Private criterion")) {
		t.Fatal("preflight leaked prose or used obsolete envelope")
	}
	artifact, _ := ports.NewAnchoredRoot(filepath.Join(root.String(), ".mulgae"))
	backend, err := newMCPBoundTestBackend(root, artifact, application, &mcpQueryFake{}, &mcpDiagnosticQueryFake{}, &mcpReportFake{}, filesystem.NewRunSelector())
	if err != nil {
		t.Fatal(err)
	}
	path := "requirements.json"
	input := mcpentry.RunReviewInput{Target: mcpentry.ReviewTarget{Kind: "stage"}, Roles: []string{"logic"}, Objective: "Preserve behavior.", RequirementsPath: &path}
	mcp, err := backend.PreflightReview(context.Background(), rejectionRequestID, input)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := json.Marshal(envelope.Result.Preflight.Requirements)
	got, _ := json.Marshal(mcp.Data["requirements"])
	if !bytes.Equal(got, want) {
		t.Fatalf("CLI/MCP admission metadata differs: %s / %s", got, want)
	}
	if err := os.Remove(filepath.Join(root.String(), path)); err != nil {
		t.Fatal(err)
	}
	failed := application.Run(context.Background(), append(append([]string(nil), args...), "--preflight"), root.String())
	var failureEnvelope struct {
		SchemaVersion string `json:"schema_version"`
		Result        struct {
			Kind          string `json:"kind"`
			SchemaVersion string `json:"schema_version"`
			Eligible      bool   `json:"eligible"`
		} `json:"result"`
	}
	if err := json.Unmarshal(failed.Stdout(), &failureEnvelope); err != nil {
		t.Fatal(err)
	}
	if failed.ExitCode() == 0 || failureEnvelope.SchemaVersion != "mulgae-command-result.v22" || failureEnvelope.Result.Kind != "review_preflight_failed" || failureEnvelope.Result.SchemaVersion != "mulgae-review-preflight.v10" || failureEnvelope.Result.Eligible {
		t.Fatalf("preflight failure version projection: %s", failed.Stdout())
	}
	if _, err := backend.PreflightReview(context.Background(), rejectionRequestID, input); err == nil {
		t.Fatal("MCP preflight admitted missing input")
	}
	if _, err := backend.RunReview(context.Background(), rejectionRequestID, input); !errors.Is(err, reviewrun.ErrContractUnsupported) {
		t.Fatalf("MCP activated requirements execution: %v", err)
	}
	if result := application.Run(context.Background(), args, root.String()); result.ExitCode() == 0 {
		t.Fatal("CLI activated requirements execution")
	}
	if prepared != 0 || writer.ensures != 0 || writer.writes != 0 {
		t.Fatalf("provider/publication effects: prepare=%d ensure=%d write=%d", prepared, writer.ensures, writer.writes)
	}
}
