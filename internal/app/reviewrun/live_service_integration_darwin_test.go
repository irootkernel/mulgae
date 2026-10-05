//go:build darwin && arm64

package reviewrun

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/adapters/filesystem"
	"github.com/irootkernel/mulgae/internal/adapters/gittarget"
	"github.com/irootkernel/mulgae/internal/adapters/jsonschema"
	adapterruntime "github.com/irootkernel/mulgae/internal/adapters/runtime"
	"github.com/irootkernel/mulgae/internal/app/publication"
	"github.com/irootkernel/mulgae/internal/app/query"
	"github.com/irootkernel/mulgae/internal/app/report"
	"github.com/irootkernel/mulgae/internal/app/review"
	"github.com/irootkernel/mulgae/internal/app/validation"
	"github.com/irootkernel/mulgae/internal/builtin"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

type integratedLiveSource struct {
	ports.LiveSourceReader
	closed bool
	reads  int
}

func (source *integratedLiveSource) Close() error {
	source.closed = true
	return source.LiveSourceReader.Close()
}

func (source *integratedLiveSource) Read(ctx context.Context, side domain.LiveSourceSide, path ports.SafeRelativePath) (ports.LiveSourceFile, error) {
	source.reads++
	return source.LiveSourceReader.Read(ctx, side, path)
}

type integratedLiveOpener struct{ source *integratedLiveSource }

func (opener integratedLiveOpener) OpenLiveSource(context.Context, ports.AnchoredRoot, ports.LiveSourceSelector) (ports.LiveSourceReader, error) {
	return opener.source, nil
}

type integratedLivePlanner struct{ plan ExecutionPlan }

func (planner integratedLivePlanner) PlanSelectedRoles(context.Context, []domain.Role) (ExecutionPlan, error) {
	return planner.plan.clone(), nil
}

type integratedLiveAuthority struct {
	provider ports.ObservedReviewProvider
	plan     ExecutionPlan
	build    BuildIdentity
	terminal QualifiedRunTerminalReceipt
	drained  bool
}

func (authority *integratedLiveAuthority) Provider() ports.ObservedReviewProvider {
	return authority.provider
}
func (authority *integratedLiveAuthority) Planner() ExecutionPlanner {
	return integratedLivePlanner{authority.plan}
}
func (authority *integratedLiveAuthority) BuildIdentity() BuildIdentity { return authority.build }
func (authority *integratedLiveAuthority) QualificationObservations() []ProviderQualificationObservation {
	observations := make([]ProviderQualificationObservation, 0, len(authority.plan.Assignments))
	for _, assignment := range authority.plan.Assignments {
		observations = append(observations, ProviderQualificationObservation{providerInstance: assignment.ProviderInstance(), outcome: qualificationOutcomeQualified})
	}
	return observations
}
func (authority *integratedLiveAuthority) DrainTerminal(ctx context.Context) (QualifiedRunTerminalReceipt, error) {
	if ctx.Err() != nil {
		return QualifiedRunTerminalReceipt{}, ctx.Err()
	}
	authority.drained = true
	return authority.terminal, nil
}

type integratedLiveFactory struct {
	authority *integratedLiveAuthority
	calls     int
}

func (factory *integratedLiveFactory) NewQualifiedLiveRun(context.Context, ports.LiveReviewExecution, RunSelection) (RunAuthority, error) {
	factory.calls++
	return factory.authority, nil
}

type integratedLiveProvider struct {
	t             *testing.T
	root, neutral ports.AnchoredRoot
	side          domain.LiveSourceSide
	calls         int
	mode          string
}

func (provider *integratedLiveProvider) Observe(_ context.Context, invocation ports.ProviderInvocation) (ports.ProviderExecutionObservation, error) {
	provider.calls++
	execution, live := invocation.LiveExecution()
	if !live || execution.SourceReader().Root() != provider.root || execution.ReviewerHome().Root() != provider.neutral {
		provider.t.Fatal("provider lost original-source or neutral-home authority")
	}
	if _, captured := invocation.ExecutionWorkspace(); captured {
		provider.t.Fatal("provider received captured workspace authority")
	}
	if bytes.Contains(invocation.Packet().Bytes(), []byte("observed\n")) {
		provider.t.Fatal("source content was copied into the prompt")
	}
	raw := []byte(fmt.Sprintf(`{"schema_version":"mulgae-provider-review-output.v1","summary":"A live observation.","completeness":"complete","limitations":[],"findings":[{"severity":"low","title":"Observed defect","description":"The selected source contains the cited statement.","evidence":[{"current":{"path":"source.go","side":%q,"line_start":1,"line_end":1,"quote":"observed\n"}}],"recommendation":"Correct the statement.","confidence":"high"}]}`, map[domain.LiveSourceSide]string{domain.LiveSourceWorktree: "worktree", domain.LiveSourceIndex: "index", domain.LiveSourceAfter: "head"}[provider.side]))
	if provider.calls == 1 {
		switch provider.mode {
		case "extraction":
			raw = []byte("# Live observation\n\nThe source.go statement needs correction.\n")
		case "repair":
			raw = bytes.Replace(raw, []byte(`"recommendation":"Correct the statement."`), []byte(`"recommendation":""`), 1)
		}
	} else if provider.mode == "repair" {
		raw = []byte(`{"schema_version":"mulgae-repair-patch.v1","repairs":[{"path":"/findings/0/recommendation","value":"Correct the statement."}]}`)
	}
	receipt, err := ports.NewStdinWriteReceipt(int64(invocation.InputIdentity().ByteLength()), int64(invocation.InputIdentity().ByteLength()), invocation.CompleteStdinSHA256(), true)
	if err != nil {
		return ports.ProviderExecutionObservation{}, err
	}
	code := 0
	started := time.Now().UTC()
	process, err := ports.NewProcessObservation(raw, nil, &code, ports.ProcessTerminationExited, receipt, started, started.Add(time.Millisecond))
	if err != nil {
		return ports.ProviderExecutionObservation{}, err
	}
	result, err := ports.NewProviderResultForInput(raw, invocation.InputIdentity())
	if err != nil {
		return ports.ProviderExecutionObservation{}, err
	}
	return ports.NewSuccessfulProviderExecutionObservation(invocation, result, process)
}

type integratedLivePublisher struct {
	t         *testing.T
	source    *integratedLiveSource
	authority *integratedLiveAuthority
	service   *publication.Service
	calls     int
}

func (publisher *integratedLivePublisher) PublishLiveNextObserved(ctx context.Context, root ports.AnchoredRoot, candidate publication.PreparedLiveCandidate, observer publication.LifecycleObserver) (publication.PublicationResult, error) {
	publisher.calls++
	if !publisher.source.closed || !publisher.source.Target().NoChange() && !publisher.authority.drained {
		publisher.t.Fatal("publication preceded source/provider closure")
	}
	return publisher.service.PublishLiveNextObserved(ctx, root, candidate, observer)
}

func TestIntegrationLiveServicePublishesVerifiedOriginalSourceAndNoChange(t *testing.T) {
	for _, scope := range []domain.LiveSourceScope{domain.LiveSourceWorkspace, domain.LiveSourceStage, domain.LiveSourceHead, domain.LiveSourceCommit, domain.LiveSourceDiff, "empty-stage", "extraction", "repair", "non-git-workspace", "qualification-sink-failure"} {
		t.Run(string(scope), func(t *testing.T) {
			mode := ""
			nonGit := scope == "non-git-workspace"
			qualificationSinkFailure := scope == "qualification-sink-failure"
			if nonGit || qualificationSinkFailure {
				scope = domain.LiveSourceWorkspace
			}
			if scope == "extraction" || scope == "repair" {
				mode, scope = string(scope), domain.LiveSourceWorkspace
			}
			ctx := context.Background()
			root, _ := ports.NewAnchoredRoot(t.TempDir())
			git := func(args ...string) string {
				command := exec.Command("git", append([]string{"-C", root.String(), "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false"}, args...)...)
				raw, err := command.CombinedOutput()
				if err != nil {
					t.Fatalf("fixture Git: %v: %s", err, raw)
				}
				return strings.TrimSpace(string(raw))
			}
			base := ""
			if !nonGit {
				git("init", "-q")
				if err := os.WriteFile(filepath.Join(root.String(), "source.go"), []byte("baseline\n"), 0600); err != nil {
					t.Fatal(err)
				}
				git("add", "source.go")
				git("commit", "-qm", "Baseline")
				base = git("rev-parse", "HEAD")
			}
			value := ""
			if scope != "empty-stage" {
				if err := os.WriteFile(filepath.Join(root.String(), "source.go"), []byte("observed\n"), 0600); err != nil {
					t.Fatal(err)
				}
				if !nonGit {
					git("add", "source.go")
				}
				if scope == domain.LiveSourceHead || scope == domain.LiveSourceCommit || scope == domain.LiveSourceDiff {
					git("commit", "-qm", "Observed")
				}
			} else {
				scope = domain.LiveSourceStage
			}
			if scope == domain.LiveSourceCommit {
				value = "HEAD"
			}
			if scope == domain.LiveSourceDiff {
				value = base + "..HEAD"
			}
			selector, _ := ports.NewLiveSourceSelector(scope, value)
			opener, _ := gittarget.NewLiveSourceAdapter(gittarget.ExecRunner{}, nil)
			reader, err := opener.OpenLiveSource(ctx, root, selector)
			if err != nil {
				t.Fatal(err)
			}
			source := &integratedLiveSource{LiveSourceReader: reader}
			defer source.Close()
			neutral, _ := ports.NewAnchoredRoot(t.TempDir())
			credential, _ := ports.NewAnchoredRoot(t.TempDir())
			artifacts, _ := ports.NewAnchoredRoot(t.TempDir())
			catalog := builtin.NewCatalog()
			schema, err := jsonschema.New(ctx, catalog)
			if err != nil {
				t.Fatal(err)
			}
			ids := adapterruntime.NewUUIDv7Generator()
			clock := adapterruntime.SystemClock{}
			store, err := filesystem.NewPublicationStore(schema, clock, ids, filesystem.NewSecureWriter())
			if err != nil {
				t.Fatal(err)
			}
			publicationService, _ := publication.NewService(store, schema, clock, ports.PublicationStructuredMemberMaxBytes)
			plan := reviewRunPlan(t, []domain.Role{domain.RoleLogic})
			plan.Threshold = domain.SeverityHigh
			plan.Ceilings = review.DefaultHarnessCeilings()
			plan.Extraction = mode == "extraction"
			build := BuildIdentity{Product: "mulgae", Version: "1.0.0", Module: "github.com/irootkernel/mulgae", VCSRevision: strings.Repeat("a", 40)}
			side := domain.LiveSourceAfter
			if scope == domain.LiveSourceWorkspace {
				side = domain.LiveSourceWorktree
			}
			if scope == domain.LiveSourceStage {
				side = domain.LiveSourceIndex
			}
			provider := &integratedLiveProvider{t: t, root: root, neutral: neutral, side: side, mode: mode}
			terminal := serviceQualifiedTerminal(t)
			for index := range terminal.providers {
				terminal.providers[index].identity.ExecutableSHA256 = "sha256:" + strings.Repeat("b", 64)
				terminal.providers[index].identity.LauncherSHA256 = "sha256:" + strings.Repeat("c", 64)
				terminal.providers[index].qualificationReceiptIDs = []string{"qualification:v1:" + strings.Repeat("d", 64)}
				terminal.providers[index].packetTransportReceiptIDs = []string{"transport:v1:" + strings.Repeat("e", 64)}
			}
			authority := &integratedLiveAuthority{provider: provider, plan: plan, build: build, terminal: terminal}
			factory := &integratedLiveFactory{authority: authority}
			publisher := &integratedLivePublisher{t: t, source: source, authority: authority, service: publicationService}
			wire, _ := ports.ParseAssetID(validation.ProviderReviewSchemaID)
			validator, _ := validation.NewReviewValidator(schema, wire)
			common, _ := LoadLiveReviewCommon(ctx, catalog)
			calls := []string{}
			diagnostics := &serviceDiagnosticFactory{calls: &calls}
			if qualificationSinkFailure {
				diagnostics.refuseEvent, diagnostics.refusal = domain.DiagnosticQualificationSucceeded, errors.New("private diagnostic storage failure")
			}
			service, err := NewLiveService(LiveDependencies{Sources: integratedLiveOpener{source}, ReviewerHome: promptLiveHome{root: neutral}, CredentialRoots: []ports.AnchoredRoot{credential}, Admission: serviceLiveAdmission{plan}, Clock: clock, IDs: ids, Build: build, Authority: factory, Validator: validator, Publication: publisher, Templates: mustServiceTemplates(t), Common: common, Diagnostics: diagnostics, Detector: filesystem.NewContentDetector()})
			if err != nil {
				t.Fatal(err)
			}
			selection, _ := NewRunSelection([]domain.Role{domain.RoleLogic}, nil)
			result, err := service.Execute(ctx, LiveRequest{ProjectRoot: root, ArtifactRoot: artifacts, Target: selector, Selection: selection})
			if qualificationSinkFailure {
				if !runtimeDiagnosticPersistenceFailure(err) || !source.closed || !authority.drained || publisher.calls != 0 || provider.calls != 0 || source.reads != 0 || result.Final().Valid() || diagnostics.refusals != 1 {
					t.Fatalf("qualification persistence failure granted review/publication or lost cleanup: %v", err)
				}
				return
			}
			if err != nil {
				for cause := err; cause != nil; cause = errors.Unwrap(cause) {
					t.Logf("%T: %v", cause, cause)
				}
				t.Fatal(err)
			}
			if !source.closed || publisher.calls != 1 || !result.Final().Valid() || result.SourceIdentitySHA256() == "" {
				t.Fatal("missing terminal P2/source authority")
			}
			qualificationEvents := []domain.RuntimeDiagnosticEventCode{}
			for _, input := range diagnostics.inputs {
				switch input.Event {
				case domain.DiagnosticQualificationStarted, domain.DiagnosticQualificationSucceeded, domain.DiagnosticQualificationRejected:
					qualificationEvents = append(qualificationEvents, input.Event)
				case domain.DiagnosticQualificationCandidateChecked:
					qualificationEvents = append(qualificationEvents, input.Event)
					if input.Provider != plan.Assignments[0].ProviderInstance() || input.Outcome != qualificationOutcomeQualified {
						t.Fatalf("qualification observation lost provider outcome: %+v", input)
					}
				}
			}
			wantQualification := []domain.RuntimeDiagnosticEventCode{}
			if !source.Target().NoChange() {
				wantQualification = []domain.RuntimeDiagnosticEventCode{domain.DiagnosticQualificationStarted, domain.DiagnosticQualificationCandidateChecked, domain.DiagnosticQualificationSucceeded}
			}
			if !slices.Equal(qualificationEvents, wantQualification) {
				t.Fatalf("qualification lifecycle = %v, want %v", qualificationEvents, wantQualification)
			}
			if nonGit && result.LiveProjectBinding().String() != "" {
				t.Fatal("non-Git workspace fabricated a Git binding")
			}
			run, _ := ports.NewPublicationRun(artifacts, result.SessionID(), result.RunID())
			queries, _ := query.NewService(store, schema, nil, ports.PublicationStructuredMemberMaxBytes)
			status, err := queries.ReadRunStatus(ctx, run)
			if err != nil || status.PublicationStatus() != domain.PublicationCommitted {
				t.Fatalf("verified P2: %v / %v", status, err)
			}
			renderer, err := report.NewService(queries)
			if err != nil {
				t.Fatal(err)
			}
			rendered, err := renderer.Render(ctx, run)
			if err != nil {
				for cause := err; cause != nil; cause = errors.Unwrap(cause) {
					t.Logf("%T: %v", cause, cause)
				}
				t.Fatalf("render retained live evidence after source closure: %v", err)
			}
			if !bytes.Contains(rendered.Bytes(), []byte(result.SourceIdentitySHA256())) || bytes.Contains(rendered.Bytes(), []byte("Current target SHA-256")) {
				t.Fatal("rendered live report lost source selection identity")
			}
			if reader.Target().NoChange() {
				if factory.calls != 0 || provider.calls != 0 || source.reads != 0 {
					t.Fatal("empty selection acquired provider/source-content authority")
				}
			} else {
				expectedCalls := 1
				if mode != "" {
					expectedCalls = 2
				}
				if factory.calls != 1 || provider.calls != expectedCalls || source.reads == 0 {
					t.Fatal("changed source bypassed provider/evidence verification")
				}
			}
			if _, err := os.Stat(filepath.Join(artifacts.String(), result.SessionID().String(), result.RunID().String(), "source", "capture.json")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("new publication retained a captured archive")
			}
		})
	}
}
