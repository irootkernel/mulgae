//go:build darwin && arm64

package reviewrun

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
	"time"

	"github.com/irootkernel/mulgae/internal/adapters/filesystem"
	"github.com/irootkernel/mulgae/internal/adapters/gittarget"
	adapterruntime "github.com/irootkernel/mulgae/internal/adapters/runtime"
	"github.com/irootkernel/mulgae/internal/app/publication"
	"github.com/irootkernel/mulgae/internal/app/query"
	"github.com/irootkernel/mulgae/internal/app/report"
	"github.com/irootkernel/mulgae/internal/app/review"
	"github.com/irootkernel/mulgae/internal/app/validation"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

type requirementsLiveSource struct {
	*integratedLiveSource
	inputReads int
	readErr    error
	driftInput bool
}

func (s *requirementsLiveSource) Read(ctx context.Context, side domain.LiveSourceSide, path ports.SafeRelativePath) (ports.LiveSourceFile, error) {
	if s.readErr != nil {
		return ports.LiveSourceFile{}, s.readErr
	}
	return s.integratedLiveSource.Read(ctx, side, path)
}

func (s *requirementsLiveSource) ReadRequirementsInput(ctx context.Context, path ports.SafeRelativePath) ([]byte, error) {
	s.inputReads++
	raw, err := s.LiveSourceReader.(ports.RequirementsInputReader).ReadRequirementsInput(ctx, path)
	if err == nil && s.driftInput && s.inputReads > 1 {
		raw = bytes.ReplaceAll(raw, []byte("LOGIC_ONLY_REQUIREMENT"), []byte("CHANGED_REQUIREMENT"))
	}
	return raw, err
}

type requirementsLiveOpener struct{ source *requirementsLiveSource }

func (o requirementsLiveOpener) OpenLiveSource(context.Context, ports.AnchoredRoot, ports.LiveSourceSelector) (ports.LiveSourceReader, error) {
	return o.source, nil
}

type requirementsObservedProvider struct {
	t          *testing.T
	side       string
	calls      int
	mode       string
	logicCalls int
	packets    [][]byte
}

func (p *requirementsObservedProvider) Observe(_ context.Context, invocation ports.ProviderInvocation) (ports.ProviderExecutionObservation, error) {
	p.calls++
	p.packets = append(p.packets, invocation.Packet().Bytes())
	if _, ok := invocation.LiveExecution(); !ok {
		p.t.Fatal("missing original-source execution")
	}
	if _, copied := invocation.ExecutionWorkspace(); copied {
		p.t.Fatal("source was copied")
	}
	packet := invocation.Packet().Bytes()
	logic := invocation.Role() == domain.RoleLogic
	if logic {
		p.logicCalls++
	}
	if bytes.Contains(packet, []byte("LOGIC_ONLY_REQUIREMENT")) != logic || bytes.Contains(packet, []byte("SECURITY_ONLY_REQUIREMENT")) == logic {
		p.t.Fatal("requirements crossed assigned roles")
	}
	if !bytes.Contains(packet, []byte("grant no tool")) {
		p.t.Fatal("missing untrusted requirements permission boundary")
	}
	row := map[string]any{"requirement_id": "A", "verdict": "met", "rationale": "The selected implementation supports the obligation.", "evidence": []any{map[string]any{"current": map[string]any{"path": "source.go", "side": p.side, "line_start": 1, "line_end": 1, "quote": "observed\n"}}}, "examined_scope": "Selected source.go", "limitations": []string{"No tests were run by this reviewer."}, "reason": ""}
	if !logic {
		row["requirement_id"] = "B"
		row["verdict"] = "unverified"
		row["reason"] = "insufficient_evidence"
		row["evidence"] = []any{}
	}
	if logic && p.mode == "large-content" {
		row["rationale"] = strings.Repeat("r", 9<<20)
		row["limitations"] = []string{strings.Repeat("l", 9<<20)}
	}
	if logic && p.mode == "unmet" {
		row["verdict"] = "unmet"
		row["evidence"] = []any{}
	}
	if logic && p.mode == "protected-owner" {
		row["origin"] = "provider"
	}
	findings := any([]any{})
	if logic && p.mode == "invalid-peer" {
		findings = "invalid"
	}
	raw, _ := json.Marshal(map[string]any{"schema_version": validation.RequirementsProviderOutputVersion, "summary": "Primary report.", "completeness": "complete", "limitations": []string{}, "findings": findings, "requirements": map[string]any{"schema_version": "mulgae-provider-requirements.v1", "assessments": []any{row}}})
	if p.mode == "free-form" {
		raw = []byte("# Accepted primary role report\n\nProse only.\n")
	}
	if logic && (p.mode == "malformed" || p.mode == "reformat") {
		if p.logicCalls == 1 {
			raw = []byte(`{"schema_version":"mulgae-provider-review-output.v3","requirements":{`)
		} else if p.mode == "malformed" {
			raw = []byte("Unable to reformat.")
		}
	}
	receipt, _ := ports.NewStdinWriteReceipt(int64(invocation.InputIdentity().ByteLength()), int64(invocation.InputIdentity().ByteLength()), invocation.CompleteStdinSHA256(), true)
	code := 0
	start := time.Now().UTC()
	process, _ := ports.NewProcessObservation(raw, nil, &code, ports.ProcessTerminationExited, receipt, start, start.Add(time.Millisecond))
	result, _ := ports.NewProviderResultForInput(raw, invocation.InputIdentity())
	return ports.NewSuccessfulProviderExecutionObservation(invocation, result, process)
}

func TestIntegrationRequirementsLiveServicePublishesOrdinaryAndEveryNoChange(t *testing.T) {
	for _, mode := range []string{"stage", "head", "commit", "diff", "empty-stage", "empty-head", "empty-commit", "empty-diff", "empty-triple-diff", "unborn-stage", "empty-workspace-missing", "unborn-workspace-missing", "empty-head-missing", "empty-stage-missing", "empty-commit-missing", "empty-diff-missing", "empty-triple-diff-missing", "unborn-stage-missing", "empty-head-owner", "empty-head-binding", "free-form", "invalid-peer", "malformed", "reformat", "unmet", "protected-source", "protected-owner", "large-content", "input-drift"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			directory, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			root, _ := ports.NewAnchoredRoot(directory)
			git := func(args ...string) string {
				command := exec.Command("git", append([]string{"-C", directory, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false"}, args...)...)
				raw, err := command.CombinedOutput()
				if err != nil {
					t.Fatalf("fixture Git: %v %s", err, raw)
				}
				return strings.TrimSpace(string(raw))
			}
			git("init", "-q")
			unborn := strings.HasPrefix(mode, "unborn-")
			empty := strings.HasPrefix(mode, "empty-") || unborn
			missing := strings.HasSuffix(mode, "-missing")
			invalidOwner := mode == "empty-head-owner"
			wrongBinding := strings.HasSuffix(mode, "-binding")
			if !unborn {
				if !empty {
					if err := os.WriteFile(filepath.Join(directory, "source.go"), []byte("baseline\n"), 0600); err != nil {
						t.Fatal(err)
					}
					git("add", "source.go")
				}
				git("commit", "-q", "--allow-empty", "-m", "Baseline")
			}
			base := ""
			if !unborn {
				base = git("rev-parse", "HEAD")
			}
			if !empty {
				if err := os.WriteFile(filepath.Join(directory, "source.go"), []byte("observed\n"), 0600); err != nil {
					t.Fatal(err)
				}
				git("add", "source.go")
				if mode == "head" || mode == "commit" || mode == "diff" {
					git("commit", "-qm", "Observed")
				}
				if err := os.WriteFile(filepath.Join(directory, "source.go"), []byte("different worktree\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			scope := domain.LiveSourceStage
			operand := ""
			side := "index"
			switch {
			case strings.Contains(mode, "workspace"):
				scope = domain.LiveSourceWorkspace
				side = "worktree"
			case strings.Contains(mode, "head"):
				scope = domain.LiveSourceHead
				side = "head"
			case strings.Contains(mode, "commit"):
				scope = domain.LiveSourceCommit
				operand = "HEAD"
				side = "head"
			case strings.Contains(mode, "diff"):
				scope = domain.LiveSourceDiff
				operand = base + "..HEAD"
				side = "head"
				if strings.Contains(mode, "triple") {
					operand = base + "...HEAD"
				}
			}
			raw := []byte(`{"schema_version":"mulgae-requirements-input.v1","requirements":[{"id":"A","text":"LOGIC_ONLY_REQUIREMENT","acceptance_criteria":["criterion"],"owner_role":"logic"},{"id":"B","text":"SECURITY_ONLY_REQUIREMENT","acceptance_criteria":["criterion"],"owner_role":"security"},{"id":"C","text":"LOGIC_OMITTED_REQUIREMENT","acceptance_criteria":["criterion"],"owner_role":"logic"}]}`)
			if invalidOwner {
				raw = bytes.ReplaceAll(raw, []byte(`"owner_role":"logic"`), []byte(`"owner_role":"artist"`))
			}
			if !missing {
				if err := os.WriteFile(filepath.Join(directory, "requirements.json"), raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
			selector, _ := ports.NewLiveSourceSelector(scope, operand)
			opener, _ := gittarget.NewLiveSourceAdapter(gittarget.ExecRunner{}, nil)
			reader, err := opener.OpenLiveSource(ctx, root, selector)
			if err != nil {
				t.Fatal(err)
			}
			source := &requirementsLiveSource{integratedLiveSource: &integratedLiveSource{LiveSourceReader: reader}, driftInput: mode == "input-drift"}
			if mode == "protected-source" {
				source.readErr = ports.NewLiveSourceError(ports.LiveSourceUnavailable, errors.New("isolated source unavailable"))
			}
			defer source.Close()
			if source.Target().NoChange() != empty {
				t.Fatalf("fixture selection mismatch: %s", mode)
			}
			neutral, _ := ports.NewAnchoredRoot(t.TempDir())
			credential, _ := ports.NewAnchoredRoot(t.TempDir())
			artifacts, _ := ports.NewAnchoredRoot(t.TempDir())
			catalog, schema := mustSharedReviewRunTestAssets(t)
			ids := adapterruntime.NewUUIDv7Generator()
			clock := adapterruntime.SystemClock{}
			store, err := filesystem.NewPublicationStore(schema, clock, ids, filesystem.NewSecureWriter())
			if err != nil {
				t.Fatal(err)
			}
			publisherService, _ := publication.NewService(store, schema, clock, 8<<20)
			roles := []domain.Role{domain.RoleLogic, domain.RoleSecurity}
			plan := reviewRunPlan(t, roles)
			if mode == "large-content" {
				// Allow race-instrumented validation of the full prose before the next role.
				limits, err := review.NewInvocationLimits(time.Minute)
				if err != nil {
					t.Fatal(err)
				}
				for i, budget := range plan.Budgets {
					route, err := review.NewRouteBudget(budget.Primary().Route(), limits)
					if err != nil {
						t.Fatal(err)
					}
					plan.Budgets[i], err = review.NewRoleBudget(budget.Role(), route)
					if err != nil {
						t.Fatal(err)
					}
				}
			}
			plan.Threshold = domain.SeverityHigh
			plan.Ceilings = review.DefaultHarnessCeilings()
			plan.MaxWorkers = 1
			plan.Extraction = false
			build := BuildIdentity{Product: "mulgae", Version: "1.0.0", Module: "github.com/irootkernel/mulgae", VCSRevision: strings.Repeat("a", 40)}
			provider := &requirementsObservedProvider{t: t, side: side, mode: mode}
			terminal := serviceQualifiedTerminal(t)
			for i := range terminal.providers {
				terminal.providers[i].identity.ExecutableSHA256 = "sha256:" + strings.Repeat("b", 64)
				terminal.providers[i].identity.LauncherSHA256 = "sha256:" + strings.Repeat("c", 64)
				terminal.providers[i].qualificationReceiptIDs = []string{"qualification:v1:" + strings.Repeat("d", 64)}
				terminal.providers[i].packetTransportReceiptIDs = []string{"transport:v1:" + strings.Repeat("e", 64)}
			}
			authority := &integratedLiveAuthority{provider: provider, plan: plan, build: build, terminal: terminal}
			factory := &integratedLiveFactory{authority: authority}
			publisher := &integratedLivePublisher{t: t, source: source.integratedLiveSource, authority: authority, service: publisherService}
			wire, _ := ports.ParseAssetID(validation.ProviderReviewSchemaID)
			validator, _ := validation.NewReviewValidator(schema, wire)
			common, _ := LoadLiveReviewCommon(ctx, catalog)
			contract, contractErr := LoadRequirementsPrompt(ctx, catalog)
			if contractErr != nil {
				t.Fatal(contractErr)
			}
			calls := []string{}
			diagnostics := &serviceDiagnosticFactory{calls: &calls}
			service, err := NewLiveService(LiveDependencies{Coordination: testLiveCoordination(t), Sources: requirementsLiveOpener{source}, ReviewerHome: promptLiveHome{root: neutral}, CredentialRoots: []ports.AnchoredRoot{credential}, Admission: serviceLiveAdmission{plan}, Clock: clock, IDs: ids, Build: build, Authority: factory, Validator: validator, Publication: publisher, Templates: mustServiceTemplates(t), Common: common, RequirementsPrompt: contract, Diagnostics: diagnostics, Detector: filesystem.NewContentDetector()})
			if err != nil {
				t.Fatal(err)
			}
			selection, _ := NewRunSelection(roles, nil)
			request := LiveRequest{ProjectRoot: root, ArtifactRoot: artifacts, Target: selector, Selection: selection, HasRequirements: true, RequirementsPath: "requirements.json"}
			if wrongBinding {
				request.ExpectedProjectBinding, _ = domain.ParseProjectBinding("sha256:" + strings.Repeat("f", 64))
			}
			result, err := service.Execute(ctx, request)
			if mode == "input-drift" {
				var failure *domain.Failure
				if err == nil || !errors.As(err, &failure) || failure.Class() != domain.FailureSecurityPolicy || source.inputReads != 2 || factory.calls != 0 || provider.calls != 0 || publisher.calls != 0 || !source.closed {
					t.Fatalf("requirements drift after grant crossed provider/publication boundary: %v", err)
				}
				return
			}
			if mode == "protected-source" || mode == "protected-owner" {
				var failure *domain.Failure
				want := domain.FailureArtifact
				if mode == "protected-owner" {
					want = domain.FailureSecurityPolicy
				}
				if err == nil || !errors.As(err, &failure) || failure.Class() != want || provider.calls != 1 || factory.calls != 1 || publisher.calls != 0 {
					t.Fatalf("protected failure executed/published or lost class: %v", err)
				}
				finals, _ := filepath.Glob(filepath.Join(artifacts.String(), "*", "*", "review_*.json"))
				if len(finals) != 0 {
					t.Fatal("protected failure published final")
				}
				return
			}
			if missing || invalidOwner || wrongBinding {
				if err == nil || factory.calls != 0 || provider.calls != 0 || publisher.calls != 0 || len(diagnostics.inputs) != 0 {
					t.Fatalf("invalid input allocated or executed: %v", err)
				}
				entries, _ := os.ReadDir(artifacts.String())
				if len(entries) != 0 {
					t.Fatal("invalid input published artifacts")
				}
				return
			}
			if err != nil {
				for cause := err; cause != nil; {
					t.Logf("%T: %v", cause, cause)
					type unwrapper interface{ Unwrap() error }
					u, ok := cause.(unwrapper)
					if !ok {
						break
					}
					cause = u.Unwrap()
				}
				t.Fatal(err)
			}
			expectedInputReads := 1
			if !empty {
				expectedInputReads = 2
			} // Revalidate the admitted requirements after grant acquisition.
			if source.inputReads != expectedInputReads || !source.closed || publisher.calls != 1 {
				t.Fatalf("requirements admission/revalidation or publication closure: reads=%d want=%d closed=%v publications=%d", source.inputReads, expectedInputReads, source.closed, publisher.calls)
			}
			expectedCalls := 2
			if mode == "malformed" || mode == "reformat" {
				expectedCalls = 3
			}
			if empty {
				expectedCalls = 0
			}
			if provider.calls != expectedCalls || empty && factory.calls != 0 || !empty && factory.calls != 1 {
				t.Fatalf("provider/qualification calls: %d/%d", provider.calls, factory.calls)
			}
			prefix := filepath.Join(artifacts.String(), result.SessionID().String(), result.RunID().String())
			retained, err := os.ReadFile(filepath.Join(prefix, "requirements", "input.json"))
			if err != nil || !bytes.Equal(retained, raw) {
				t.Fatal("exact input lost")
			}
			support, err := os.ReadFile(filepath.Join(prefix, "requirements", "support.json"))
			if err != nil {
				t.Fatal(err)
			}
			admitted, _ := validation.DecodeRequirementsInput(raw, roles)
			evaluation, refs, err := publication.DecodeRequirementsSupport(ctx, schema, support, retained, admitted.Requirements(), empty)
			if err != nil {
				t.Fatal(err)
			}
			selected, evaluated, _ := evaluation.Counts()
			want := 2
			if mode == "free-form" {
				want = 0
			}
			if mode == "malformed" {
				want = 1
			}
			if empty {
				want = 0
			}
			if selected != 3 || evaluated != want || len(refs) != 3 {
				t.Fatal("dishonest selected/evaluated counts")
			}
			// A fresh query service consumes the actual committed store after
			// the execution source lease has closed. Requirement inspection
			// remains available independently of finding extraction outcomes.
			queries, queryErr := query.NewService(store, schema, nil, ports.PublicationStructuredMemberMaxBytes)
			if queryErr != nil {
				t.Fatal(queryErr)
			}
			contexts, queryErr := query.NewProjectContextService(gittarget.ProjectBindingObserver{})
			if queryErr != nil {
				t.Fatal(queryErr)
			}
			observed, queryErr := contexts.Read(ctx, root)
			if queryErr != nil {
				t.Fatal(queryErr)
			}
			binding, queryErr := domain.ParseProjectBinding(observed.ProjectBinding)
			if queryErr != nil {
				t.Fatal(queryErr)
			}
			run, queryErr := ports.NewPublicationRun(artifacts, result.SessionID(), result.RunID())
			if queryErr != nil {
				t.Fatal(queryErr)
			}
			page, queryErr := queries.Inspect(ctx, run, binding, query.InspectionRequest{QueryKind: "inspect", RequirementsLimit: 1, MinimumSeverity: domain.SeverityBlocker})
			if queryErr != nil {
				t.Fatal(queryErr)
			}
			if page.Requirements == nil || *page.Requirements.SelectedCount != selected || *page.Requirements.EvaluatedCount != evaluated || page.Requirements.Items[0].RequirementID != "A" || page.Requirements.NextCursor == nil {
				t.Fatal("verified public reader lost requirements counts/order")
			}
			for _, id := range []string{"A", "B", "C"} {
				chunk, readErr := queries.ReadRequirement(ctx, run, binding, id, query.ContentContinuation{PublicationReceipt: page.PublicationReceipt})
				if readErr != nil || chunk.RequirementID != id || chunk.MediaType != "application/json" || chunk.ReturnedBytes > query.MaxVerifiedContentChunkBytes {
					t.Fatalf("verified content %s: %v", id, readErr)
				}
				if mode == "large-content" && id == "A" && (chunk.TotalBytes <= 18<<20 || chunk.NextOffset == nil) {
					t.Fatal("public large content clipped")
				}
			}
			renderer, queryErr := report.NewService(queries)
			if queryErr != nil {
				t.Fatal(queryErr)
			}
			rendered, queryErr := renderer.Render(ctx, run)
			if queryErr != nil {
				t.Fatal(queryErr)
			}
			if !bytes.Contains(rendered.Bytes(), []byte("Requirements assessment")) || !bytes.Contains(rendered.Bytes(), []byte("C — unverified")) {
				t.Fatal("rendered report hid missing owner answer")
			}
			if mode == "large-content" && len(rendered.Bytes()) <= 18<<20 {
				t.Fatal("renderer clipped unbounded rationale/limitations")
			}
			for i, row := range evaluation.Assessments() {
				body, err := os.ReadFile(filepath.Join(prefix, refs[i].Path()))
				if err != nil || !refs[i].Matches(body) {
					t.Fatal("content binding lost")
				}
				if mode == "large-content" && i == 0 && len(body) <= 18<<20 {
					t.Fatal("large retained content was clipped")
				}
				if empty && (row.Reason() != domain.AssessmentNoChangeTarget || row.Origin() != domain.AssessmentDerived) {
					t.Fatal("no-change fabricated provider answer")
				}
			}
			manifestRaw, err := os.ReadFile(filepath.Join(prefix, "manifest.json"))
			if err != nil {
				t.Fatal(err)
			}
			var manifest struct {
				SchemaVersion string            `json:"schema_version"`
				Attempts      []json.RawMessage `json:"attempts"`
				Reports       []json.RawMessage `json:"role_reports"`
			}
			if json.Unmarshal(manifestRaw, &manifest) != nil || manifest.SchemaVersion != "mulgae-run-manifest.v4" || empty && (len(manifest.Attempts) != 0 || len(manifest.Reports) != 0 || source.reads != 0) {
				t.Fatal("no-change fabricated work")
			}

			if !empty && result.TerminalExit().Code() != domain.ExitCommittedPass {
				t.Fatal("assessment verdict changed operational exit")
			}
			if mode == "free-form" || mode == "invalid-peer" || mode == "malformed" {
				for _, rawAttempt := range manifest.Attempts {
					var attempt struct {
						Role       string `json:"role"`
						Parse      string `json:"parse_state"`
						Validation string `json:"validation_state"`
					}
					if err := json.Unmarshal(rawAttempt, &attempt); err != nil {
						t.Fatal(err)
					}
					wantParse, wantValidation := domain.ParseValid, domain.ValidationValid
					if mode == "free-form" {
						wantParse, wantValidation = domain.ParseNotStarted, domain.ValidationNotStarted
					}
					if mode == "invalid-peer" && attempt.Role == "logic" {
						wantValidation = domain.ValidationInvalid
					}
					if mode == "malformed" && attempt.Role == "logic" {
						wantParse, wantValidation = domain.ParseInvalidJSON, domain.ValidationRepairExhausted
					}
					if attempt.Parse != string(wantParse) || attempt.Validation != string(wantValidation) {
						t.Fatalf("manifest extraction states for %s: %s/%s", attempt.Role, attempt.Parse, attempt.Validation)
					}
				}
			}
			finals, _ := filepath.Glob(filepath.Join(prefix, "review_*.json"))
			if len(finals) != 1 {
				t.Fatal("more than one final")
			}
		})
	}
}
