//go:build darwin && arm64

package composition

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/adapters/environment"
	"github.com/irootkernel/mulgae/internal/adapters/filesystem"
	"github.com/irootkernel/mulgae/internal/adapters/gittarget"
	"github.com/irootkernel/mulgae/internal/adapters/jsonschema"
	adapterruntime "github.com/irootkernel/mulgae/internal/adapters/runtime"
	"github.com/irootkernel/mulgae/internal/app/publication"
	"github.com/irootkernel/mulgae/internal/app/query"
	"github.com/irootkernel/mulgae/internal/app/report"
	"github.com/irootkernel/mulgae/internal/app/reviewrun"
	"github.com/irootkernel/mulgae/internal/app/validation"
	"github.com/irootkernel/mulgae/internal/builtin"
	mcpentry "github.com/irootkernel/mulgae/internal/entrypoint/mcp"
	mulgaeentry "github.com/irootkernel/mulgae/internal/entrypoint/mulgae"
	"github.com/irootkernel/mulgae/internal/ports"
)

type requirementsNeutralHome struct {
	ports.ReviewerHome
	root ports.AnchoredRoot
}

func (home requirementsNeutralHome) Root() ports.AnchoredRoot { return home.root }
func (home requirementsNeutralHome) Revalidate() error        { return nil }

type requirementsNoProvider struct{ calls int }

func (factory *requirementsNoProvider) NewQualifiedLiveRun(context.Context, ports.LiveReviewExecution, reviewrun.RunSelection) (reviewrun.RunAuthority, error) {
	factory.calls++
	return nil, errors.New("unexpected qualification on a rejected or empty target")
}

// This graph uses the production admission, source, validation, writer,
// publication and inspection owners. Only qualification is replaced by a
// counter: every request below must finish before reaching that boundary.
func requirementsExecutionApplication(t *testing.T, root ports.AnchoredRoot, reader ports.TrustedProjectReader) (*mulgaeentry.Application, *mcpBackend, *requirementsWriter, *requirementsNoProvider) {
	t.Helper()
	ctx := context.Background()
	catalog := builtin.NewCatalog()
	schema, err := jsonschema.New(ctx, catalog)
	if err != nil {
		t.Fatal(err)
	}
	preflight, err := composeReviewPreflight(ctx, catalog, root, reader)
	if err != nil {
		t.Fatal(err)
	}
	policy := preflight.(*productionReviewPreflightService)
	writer := &requirementsWriter{SecureFileWriter: filesystem.NewSecureWriter()}
	ids := adapterruntime.NewUUIDv7Generator()
	store, err := filesystem.NewPublicationStore(schema, mcpTestClock{}, ids, writer)
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := publication.NewService(store, schema, mcpTestClock{}, ports.PublicationStructuredMemberMaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	diagnostics, err := filesystem.NewDiagnosticStoreFactory(writer, mcpTestClock{})
	if err != nil {
		t.Fatal(err)
	}
	schemaID, _ := ports.ParseAssetID(validation.ProviderReviewSchemaID)
	validator, err := validation.NewReviewValidator(schema, schemaID)
	if err != nil {
		t.Fatal(err)
	}
	templates, err := reviewrun.LoadDefaultTemplateSet(ctx, catalog)
	if err != nil {
		t.Fatal(err)
	}
	common, err := reviewrun.LoadLiveReviewCommon(ctx, catalog)
	if err != nil {
		t.Fatal(err)
	}
	requirements, err := reviewrun.LoadRequirementsPrompt(ctx, catalog)
	if err != nil {
		t.Fatal(err)
	}
	neutral, _ := ports.NewAnchoredRoot(canonicalTestTempDir(t))
	credentials, _ := ports.NewAnchoredRoot(canonicalTestTempDir(t))
	factory := &requirementsNoProvider{}
	live, err := reviewrun.NewLiveService(reviewrun.LiveDependencies{
		Sources: policy.sources, ReviewerHome: requirementsNeutralHome{root: neutral}, CredentialRoots: []ports.AnchoredRoot{credentials},
		Admission: productionLiveRequestAdmission{policy: policy.policy}, Clock: mcpTestClock{}, IDs: ids,
		Build:     reviewrun.BuildIdentity{Product: "mulgae", Version: "test", Module: "github.com/irootkernel/mulgae", VCSRevision: "fixture"},
		Authority: factory, Validator: validator, Publication: publisher, PublicationWriter: writer, Templates: templates, Common: common, RequirementsPrompt: requirements,
		Diagnostics: diagnostics, Detector: filesystem.NewContentDetector(),
	})
	if err != nil {
		t.Fatal(err)
	}
	runs := newDeferredReviewRunServiceWithPreflight(func(context.Context, ports.AnchoredRoot) (mulgaeentry.ReviewRunService, error) {
		return mulgaeentry.NewLiveReviewRunService(live), nil
	}, func(context.Context, ports.AnchoredRoot) (mulgaeentry.ReviewPreflightService, error) {
		return preflight, nil
	})
	queries, err := query.NewService(store, schema, nil, ports.PublicationStructuredMemberMaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	reports, err := report.NewService(queries)
	if err != nil {
		t.Fatal(err)
	}
	queryAdapter := mulgaeentry.NewPublicationQueryService(queries)
	reportAdapter := mulgaeentry.NewPublicationReportService(reports)
	contexts, err := query.NewProjectContextService(gittarget.ProjectBindingObserver{})
	if err != nil {
		t.Fatal(err)
	}
	application, err := mulgaeentry.NewApplication(mulgaeentry.Dependencies{Clock: mcpTestClock{}, RequestIDGenerator: mcpTestRequestIDs{}, Catalog: catalog, JSONSchemaValidator: schema, SecureWriter: writer, TrustedProjectReader: reader, EnvironmentInspector: environment.NewInspector(), ReviewRuns: runs, ProjectContexts: contexts, PublicationQueries: queryAdapter, PublicationReports: reportAdapter})
	if err != nil {
		t.Fatal(err)
	}
	artifact, _ := ports.NewAnchoredRoot(filepath.Join(root.String(), ".mulgae"))
	backend, err := newMCPBackend(root, artifact, application, queryAdapter, &mcpDiagnosticQueryFake{}, reportAdapter, filesystem.NewRunSelector())
	if err != nil {
		t.Fatal(err)
	}
	backend.projectContexts = contexts
	lease, err := contexts.Open(ctx, root)
	if err == nil {
		backend.contextLease = lease
		t.Cleanup(func() { _ = lease.Close() })
	} else {
		backend.contextError = err
		workspace, workspaceErr := gittarget.OpenUnboundWorkspaceRoot(ctx, root)
		if workspaceErr == nil {
			backend.workspaceLease = workspace
			t.Cleanup(func() { _ = workspace.Close() })
		}
	}
	return application, backend, writer, factory
}

func TestRequirementsPublicAdmissionRejectsBeforeEveryPublicationEffect(t *testing.T) {
	for _, kind := range []string{"workspace", "stage", "head", "commit", "diff"} {
		t.Run(kind, func(t *testing.T) {
			root, reader := requirementsProject(t, true)
			application, backend, writer, factory := requirementsExecutionApplication(t, root, reader)
			target := mcpentry.ReviewTarget{Kind: kind}
			args := []string{"review", "--" + kind}
			if kind == "commit" {
				target.Value = "HEAD"
				args = append(args, "HEAD")
			}
			if kind == "diff" {
				target.Value = "HEAD..HEAD"
				args = append(args, "HEAD..HEAD")
			}
			args = append(args, "--roles", "logic", "--requirements", "requirements.json", "--output", "json")
			path := "requirements.json"
			for name, body := range map[string]string{"missing": "", "symlink": requirementsFixture, "malformed": "{}", "wrong-owner": strings.Replace(requirementsFixture, `"logic"`, `"security"`, 1), "invalid-unicode": strings.Replace(requirementsFixture, "Private requirement phrase.", `\u0000`, 1)} {
				t.Run(name, func(t *testing.T) {
					destination := filepath.Join(root.String(), path)
					if err := os.Remove(destination); err != nil && !errors.Is(err, os.ErrNotExist) {
						t.Fatal(err)
					}
					if name == "symlink" {
						outside := filepath.Join(canonicalTestTempDir(t), "requirements.json")
						if err := os.WriteFile(outside, []byte(body), 0644); err != nil {
							t.Fatal(err)
						}
						if err := os.Symlink(outside, destination); err != nil {
							t.Fatal(err)
						}
					} else if name != "missing" {
						if err := os.WriteFile(destination, []byte(body), 0644); err != nil {
							t.Fatal(err)
						}
					}
					result := application.Run(context.Background(), args, root.String())
					if result.ExitCode() == 0 {
						t.Fatalf("CLI accepted rejected input: %s", result.Stdout())
					}
					if _, err := backend.RunReview(context.Background(), rejectionRequestID, mcpentry.RunReviewInput{Target: target, Roles: []string{"logic"}, RequirementsPath: &path}); err == nil {
						t.Fatal("MCP accepted rejected input")
					}
					if writer.ensures != 0 || writer.writes != 0 || factory.calls != 0 {
						t.Fatalf("rejected input had effects: ensures=%d writes=%d qualification=%d", writer.ensures, writer.writes, factory.calls)
					}
					entries, err := os.ReadDir(filepath.Join(root.String(), ".mulgae"))
					if err != nil || len(entries) != 2 {
						t.Fatalf("rejected input allocated private state: %v %v", entries, err)
					}
				})
			}
		})
	}
}

func TestRequirementsPublicNoChangePublishesInspectableRowsWithoutProviders(t *testing.T) {
	for _, kind := range []string{"stage", "head", "commit", "diff"} {
		t.Run(kind, func(t *testing.T) {
			root, reader := requirementsProject(t, true)
			input := filepath.Join(root.String(), "requirements.json")
			if err := os.WriteFile(input, []byte(requirementsFixture), 0644); err != nil {
				t.Fatal(err)
			}
			application, backend, writer, factory := requirementsExecutionApplication(t, root, reader)
			args := []string{"review", "--" + kind}
			if kind == "commit" {
				args = append(args, "HEAD")
			}
			if kind == "diff" {
				args = append(args, "HEAD..HEAD")
			}
			args = append(args, "--roles", "logic", "--requirements", "requirements.json", "--output", "json")
			result := application.Run(context.Background(), args, root.String())
			if result.ExitCode() != 0 {
				t.Fatalf("no-change publication: %s %s", result.Stdout(), result.Stderr())
			}
			var envelope struct {
				Result struct {
					RunID string `json:"run_id"`
				} `json:"result"`
			}
			if err := json.Unmarshal(result.Stdout(), &envelope); err != nil || envelope.Result.RunID == "" {
				t.Fatalf("run identity: %s %v", result.Stdout(), err)
			}
			inspection := application.Run(context.Background(), []string{"inspect", "--run", envelope.Result.RunID, "--output", "json"}, root.String())
			if inspection.ExitCode() != 0 || !strings.Contains(string(inspection.Stdout()), `"reason":"no_change_target"`) {
				t.Fatalf("inspect no-change assessment: %s %s", inspection.Stdout(), inspection.Stderr())
			}
			chunk := application.Run(context.Background(), []string{"read-report", "--run", envelope.Result.RunID, "--requirement", "R", "--output", "json"}, root.String())
			if chunk.ExitCode() != 0 || !strings.Contains(string(chunk.Stdout()), `"requirement_id":"R"`) {
				t.Fatalf("read no-change content: %s %s", chunk.Stdout(), chunk.Stderr())
			}
			mcp, err := backend.ListFindings(context.Background(), mcpentry.ListFindingsInput{RunID: envelope.Result.RunID})
			if err != nil || mcp["requirements"] == nil {
				t.Fatalf("MCP no-change assessment: %v %v", mcp, err)
			}
			if factory.calls != 0 || writer.ensures == 0 || writer.writes == 0 {
				t.Fatalf("no-change effects: provider=%d ensure=%d write=%d", factory.calls, writer.ensures, writer.writes)
			}
			raw, err := os.ReadFile(input)
			if err != nil || string(raw) != requirementsFixture {
				t.Fatal("publication changed invocation input")
			}
		})
	}
}

func TestRequirementsNonGitEligibilityPreservesObjectiveOnlyExecution(t *testing.T) {
	root, reader := requirementsProject(t, false)
	if err := os.RemoveAll(filepath.Join(root.String(), ".git")); err != nil {
		t.Fatal(err)
	}
	inputPath := filepath.Join(root.String(), "requirements.json")
	if err := os.WriteFile(inputPath, []byte(requirementsFixture), 0644); err != nil {
		t.Fatal(err)
	}
	application, backend, writer, factory := requirementsExecutionApplication(t, root, reader)
	args := []string{"review", "--workspace", "--roles", "logic", "--requirements", "requirements.json", "--output", "json"}
	preflight := application.Run(context.Background(), append(append([]string{}, args...), "--preflight"), root.String())
	if preflight.ExitCode() != 0 {
		t.Fatalf("non-Git preflight: %s %s", preflight.Stdout(), preflight.Stderr())
	}
	var envelope struct {
		Result struct {
			Preflight mulgaeentry.ReviewPreflightResult `json:"preflight"`
		} `json:"result"`
	}
	if err := json.Unmarshal(preflight.Stdout(), &envelope); err != nil {
		t.Fatal(err)
	}
	p := envelope.Result.Preflight
	if p.ProjectBinding != "" || p.Capabilities.RequirementsAssessment != "" || p.Requirements == nil || p.Requirements.ExecutionAvailable {
		t.Fatalf("unavailable execution advertised: %+v", p)
	}
	path := "requirements.json"
	input := mcpentry.RunReviewInput{Target: mcpentry.ReviewTarget{Kind: "workspace"}, Roles: []string{"logic"}, RequirementsPath: &path}
	mcp, err := backend.PreflightReview(context.Background(), rejectionRequestID, input)
	if err != nil || mcp.Data["requirements"].(*mulgaeentry.RequirementsPreflightSummary).ExecutionAvailable {
		t.Fatalf("MCP non-Git preflight: %+v %v", mcp, err)
	}
	rejected := application.Run(context.Background(), args, root.String())
	if rejected.ExitCode() == 0 || !bytes.Contains(rejected.Stdout(), []byte("contract_unsupported")) {
		t.Fatalf("CLI non-Git rejection: %s %s", rejected.Stdout(), rejected.Stderr())
	}
	if _, err := backend.RunReview(context.Background(), rejectionRequestID, input); !errors.Is(err, reviewrun.ErrContractUnsupported) {
		t.Fatalf("MCP non-Git rejection: %v", err)
	}
	if writer.ensures != 0 || writer.writes != 0 || factory.calls != 0 {
		t.Fatalf("unsupported execution had effects: %d/%d/%d", writer.ensures, writer.writes, factory.calls)
	}
	if err := os.Remove(inputPath); err != nil {
		t.Fatal(err)
	}
	objective := application.Run(context.Background(), []string{"review", "--workspace", "--roles", "logic", "--objective", "Preserve behavior.", "--output", "json"}, root.String())
	if objective.ExitCode() != 0 {
		t.Fatalf("objective-only non-Git no-change rejected: %s %s", objective.Stdout(), objective.Stderr())
	}
	var result struct {
		Result struct {
			URI string `json:"review_artifact_uri"`
		} `json:"result"`
	}
	if err := json.Unmarshal(objective.Stdout(), &result); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root.String(), filepath.FromSlash(result.Result.URI)))
	if err != nil {
		t.Fatal(err)
	}
	var final map[string]any
	if err := json.Unmarshal(raw, &final); err != nil {
		t.Fatal(err)
	}
	support, present := final["requirements_support"]
	if final["schema_version"] != "mulgae-review-artifact.v4" || !present || support != nil || factory.calls != 0 {
		t.Fatalf("new objective-only publication lost v4/null semantics: %s", raw)
	}
}
