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
	"sync"
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/adapters/filesystem"
	"github.com/irootkernel/mulgae/internal/adapters/gittarget"
	"github.com/irootkernel/mulgae/internal/adapters/haepari"
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
	"github.com/irootkernel/mulgae/internal/testsupport/haeparifixture"
)

var (
	sharedReviewRunAssetsOnce   sync.Once
	sharedReviewRunTestCatalog  *builtin.Catalog
	sharedReviewRunValidator    *jsonschema.Validator
	sharedReviewRunValidatorErr error
)

func sharedReviewRunTestAssets() (*builtin.Catalog, *jsonschema.Validator, error) {
	sharedReviewRunAssetsOnce.Do(func() {
		sharedReviewRunTestCatalog = builtin.NewCatalog()
		sharedReviewRunValidator, sharedReviewRunValidatorErr = jsonschema.New(context.Background(), sharedReviewRunTestCatalog)
	})
	return sharedReviewRunTestCatalog, sharedReviewRunValidator, sharedReviewRunValidatorErr
}

func mustSharedReviewRunTestAssets(t *testing.T) (*builtin.Catalog, *jsonschema.Validator) {
	t.Helper()
	catalog, validator, err := sharedReviewRunTestAssets()
	if err != nil {
		t.Fatal(err)
	}
	return catalog, validator
}

type integratedLiveSource struct {
	ports.LiveSourceReader
	mu       sync.Mutex
	closed   bool
	reads    int
	closeErr error
}

func (source *integratedLiveSource) Close() error {
	if source.closeErr != nil {
		return source.closeErr
	}
	source.mu.Lock()
	source.closed = true
	source.mu.Unlock()
	return source.LiveSourceReader.Close()
}

func (source *integratedLiveSource) Read(ctx context.Context, side domain.LiveSourceSide, path ports.SafeRelativePath) (ports.LiveSourceFile, error) {
	source.mu.Lock()
	source.reads++
	source.mu.Unlock()
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
	provider   ports.ObservedReviewProvider
	plan       ExecutionPlan
	build      BuildIdentity
	terminal   QualifiedRunTerminalReceipt
	drained    bool
	drainErr   error
	drainCheck func()
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
	if authority.drainCheck != nil {
		authority.drainCheck()
	}
	if ctx.Err() != nil {
		return QualifiedRunTerminalReceipt{}, ctx.Err()
	}
	if authority.drainErr != nil {
		return QualifiedRunTerminalReceipt{}, authority.drainErr
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
	mu            sync.Mutex
	t             *testing.T
	root, neutral ports.AnchoredRoot
	side          domain.LiveSourceSide
	calls         int
	mode          string
	cancel        context.CancelFunc
}

func (provider *integratedLiveProvider) Observe(ctx context.Context, invocation ports.ProviderInvocation) (ports.ProviderExecutionObservation, error) {
	provider.mu.Lock()
	provider.calls++
	callIndex := provider.calls
	provider.mu.Unlock()
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
	if provider.mode == "cancel-execution" {
		provider.cancel()
		return ports.ProviderExecutionObservation{}, ctx.Err()
	}
	if provider.mode == "wait-context-done" {
		<-ctx.Done()
		return ports.ProviderExecutionObservation{}, ctx.Err()
	}
	if provider.mode == "partial-role-failure" && invocation.Role() == domain.RoleSecurity {
		failure, _ := domain.NewFailure("review.provider", domain.FailureConfiguration, "fixture refusal", nil)
		return ports.ProviderExecutionObservation{}, failure
	}
	if provider.mode == "operational-partial-role" && invocation.Role() == domain.RoleSecurity {
		return ports.ProviderExecutionObservation{}, context.DeadlineExceeded
	}
	raw := []byte(fmt.Sprintf(`{"schema_version":"mulgae-provider-review-output.v1","summary":"A live observation.","completeness":"complete","limitations":[],"findings":[{"severity":"low","title":"Observed defect","description":"The selected source contains the cited statement.","evidence":[{"current":{"path":"source.go","side":%q,"line_start":1,"line_end":1,"quote":"observed\n"}}],"recommendation":"Correct the statement.","confidence":"high"}]}`, map[domain.LiveSourceSide]string{domain.LiveSourceWorktree: "worktree", domain.LiveSourceIndex: "index", domain.LiveSourceAfter: "head"}[provider.side]))
	if callIndex == 1 {
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
	for _, scope := range []domain.LiveSourceScope{domain.LiveSourceWorkspace, domain.LiveSourceStage, domain.LiveSourceHead, domain.LiveSourceCommit, domain.LiveSourceDiff, "empty-stage", "extraction", "repair", "non-git-workspace", "qualification-sink-failure", "disposition-failure", "disposition-protocol-failure", "cancel-execution", "partial-role-failure", "provider-drain-failure", "source-close-failure"} {
		t.Run(string(scope), func(t *testing.T) {
			mode := ""
			nonGit := scope == "non-git-workspace"
			qualificationSinkFailure := scope == "qualification-sink-failure"
			dispositionFailure := scope == "disposition-failure"
			unsafeDisposition := scope == "disposition-protocol-failure"
			terminalFailure := scope == "cancel-execution" || scope == "partial-role-failure" || scope == "provider-drain-failure" || scope == "source-close-failure"
			if terminalFailure {
				mode, scope = string(scope), domain.LiveSourceWorkspace
			}
			if nonGit || qualificationSinkFailure || dispositionFailure || unsafeDisposition {
				scope = domain.LiveSourceWorkspace
			}
			if scope == "extraction" || scope == "repair" {
				mode, scope = string(scope), domain.LiveSourceWorkspace
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			rootPath, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			root, _ := ports.NewAnchoredRoot(rootPath)
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
			catalog, schema := mustSharedReviewRunTestAssets(t)
			ids := adapterruntime.NewUUIDv7Generator()
			clock := adapterruntime.SystemClock{}
			store, err := filesystem.NewPublicationStore(schema, clock, ids, filesystem.NewSecureWriter())
			if err != nil {
				t.Fatal(err)
			}
			publicationService, _ := publication.NewService(store, schema, clock, ports.PublicationStructuredMemberMaxBytes)
			roles := []domain.Role{domain.RoleLogic}
			if mode == "partial-role-failure" {
				roles = append(roles, domain.RoleSecurity)
			}
			plan := reviewRunPlan(t, roles)
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
			provider := &integratedLiveProvider{t: t, root: root, neutral: neutral, side: side, mode: mode, cancel: cancel}
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
			coordination, intentStore, transport := newOwnerTestCoordinator(t)
			if terminalFailure {
				authority.drainCheck = func() {
					transport.mu.Lock()
					defer transport.mu.Unlock()
					intentStore.mu.Lock()
					defer intentStore.mu.Unlock()
					if transport.releases != 0 || source.closed || intentStore.record.LocalDrainState != ports.ReviewLocalDrainUnverified {
						t.Fatal("grant or source was released before provider drain")
					}
				}
				transport.releaseCheck = func() {
					intentStore.mu.Lock()
					defer intentStore.mu.Unlock()
					if !source.closed || !authority.drained || intentStore.record.LocalDrainState != ports.ReviewLocalDrainVerified {
						t.Fatal("Release preceded verified provider drain and source close")
					}
				}
				if mode == "provider-drain-failure" {
					authority.drainErr = errors.New("provider drain remains unknown")
				}
				if mode == "source-close-failure" {
					source.closeErr = errors.New("source close remains unknown")
				}
			}
			if dispositionFailure {
				transport.releaseErr = errors.New("private controller disposition failure")
			}
			if unsafeDisposition {
				transport.releaseErr = coordinationError(ports.ReviewCoordinationReasonProtocolIncompatible, ports.ReviewLockOperationRelease, true, errors.New("private identity mismatch"))
			}
			service, err := NewLiveService(LiveDependencies{Coordination: coordination, Sources: integratedLiveOpener{source}, ReviewerHome: promptLiveHome{root: neutral}, CredentialRoots: []ports.AnchoredRoot{credential}, Admission: serviceLiveAdmission{plan}, Clock: clock, IDs: ids, Build: build, Authority: factory, Validator: validator, Publication: publisher, Templates: mustServiceTemplates(t), Common: common, Diagnostics: diagnostics, Detector: filesystem.NewContentDetector()})
			if err != nil {
				t.Fatal(err)
			}
			selection, _ := NewRunSelection(roles, nil)
			result, err := service.Execute(ctx, LiveRequest{ProjectRoot: root, ArtifactRoot: artifacts, Target: selector, Selection: selection})
			if terminalFailure {
				if err == nil || publisher.calls != 0 || result.Final().Valid() || factory.calls != 1 || transport.acquires != 1 || transport.cancels != 0 {
					t.Fatalf("failed protected execution published or changed acquisition identity: %v", err)
				}
				unknown := mode == "provider-drain-failure" || mode == "source-close-failure"
				if unknown {
					cleanup, retained := LiveCleanupFromError(err)
					if !retained || transport.releases != 0 || intentStore.record.LocalDrainState != ports.ReviewLocalDrainUnverified || source.closed {
						t.Fatalf("unknown termination lost ownership or proof: %v", err)
					}
					authority.drainErr, source.closeErr = nil, nil
					if retryErr := cleanup.DrainAndClose(ctx); retryErr != nil {
						t.Fatal(retryErr)
					}
				}
				if transport.releases != 1 || !authority.drained || !source.closed || intentStore.record.LocalDrainState != ports.ReviewLocalDrainVerified || intentStore.record.ObservedRequest.State != ports.ReviewLockStateReleased {
					t.Fatalf("verified terminal cleanup did not settle the original grant: %v", err)
				}
				if mode == "cancel-execution" && (ctx.Err() != context.Canceled || runtimeDiagnosticFailureClass(err) != domain.FailureCancelled || provider.calls != 1) {
					t.Fatalf("cancellation did not reach admitted provider execution: class=%s calls=%d error=%v", runtimeDiagnosticFailureClass(err), provider.calls, err)
				}
				if mode == "partial-role-failure" {
					completed := 0
					for _, input := range diagnostics.inputs {
						if input.Event == domain.DiagnosticRoleCompleted && input.Role == domain.RoleLogic {
							completed++
						}
					}
					if completed != 1 || provider.calls != 2 {
						t.Fatal("partial role failure lost accepted work or repeated a provider")
					}
				}
				return
			}
			if unsafeDisposition {
				if err == nil || publisher.calls != 0 || !source.closed || !authority.drained || intentStore.record.LocalDrainState != ports.ReviewLocalDrainVerified || result.Final().Valid() {
					t.Fatalf("protocol/identity failure was downgraded to operational disposition: %v", err)
				}
				return
			}
			if dispositionFailure {
				sessionID, runID, allocated := RuntimeDiagnosticIdentityFromError(err)
				if err == nil || !allocated || publisher.calls != 1 || !source.closed || !authority.drained || intentStore.record.LocalDrainState != ports.ReviewLocalDrainVerified {
					t.Fatalf("operational disposition revoked valid protected completion: %v", err)
				}
				run, _ := ports.NewPublicationRun(artifacts, sessionID, runID)
				queries, _ := query.NewService(store, schema, nil, ports.PublicationStructuredMemberMaxBytes)
				status, queryErr := queries.ReadRunStatus(context.Background(), run)
				if queryErr != nil || status.PublicationStatus() != domain.PublicationCommitted {
					t.Fatalf("committed P2 unavailable after disposition failure: %v", queryErr)
				}
				if len(diagnostics.finalizeRequests) != 1 {
					t.Fatal("missing disposition diagnostics")
				}
				finalized := diagnostics.finalizeRequests[0].Status()
				publishedState, hasState := status.RunState()
				if _, ok := finalized.P2URI(); !ok || !hasState || finalized.State() != publishedState {
					t.Fatal("disposition diagnostics lost actual P2 identity or state")
				}
				if summary, ok := finalized.DiagnosticSummary(); !ok || summary.Component() != "coordination" || summary.InvariantID() != string(domain.DiagnosticCauseCoordinationDispositionFailed) {
					t.Fatal("missing bounded disposition summary")
				}
				return
			}
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

func TestIntegrationLiveServiceOperationalPartialRoleAndBorrowedLifecycle(t *testing.T) {
	setupProject := func(t *testing.T) (ports.AnchoredRoot, ports.LiveSourceSelector) {
		t.Helper()
		rootPath, err := filepath.EvalSymlinks(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		root, _ := ports.NewAnchoredRoot(rootPath)
		git := func(args ...string) {
			command := exec.Command("git", append([]string{"-C", root.String(), "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false"}, args...)...)
			if raw, err := command.CombinedOutput(); err != nil {
				t.Fatalf("fixture Git: %v: %s", err, raw)
			}
		}
		git("init", "-q")
		if err := os.WriteFile(filepath.Join(root.String(), "source.go"), []byte("baseline\n"), 0600); err != nil {
			t.Fatal(err)
		}
		git("add", "source.go")
		git("commit", "-qm", "Baseline")
		if err := os.WriteFile(filepath.Join(root.String(), "source.go"), []byte("observed\n"), 0600); err != nil {
			t.Fatal(err)
		}
		git("add", "source.go")
		git("commit", "-qm", "Observed")
		selector, _ := ports.NewLiveSourceSelector(domain.LiveSourceHead, "")
		return root, selector
	}

	t.Run("operational-partial-role-publishes-incomplete-retains-report-and-unblocks-waiter", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		controller := haeparifixture.New(t)
		unblockRelease := controller.PauseNextRelease()
		defer unblockRelease()

		catalog, schema := mustSharedReviewRunTestAssets(t)
		ids := adapterruntime.NewUUIDv7Generator()
		clock := adapterruntime.SystemClock{}
		secureWriter := filesystem.NewSecureWriter()
		store1 := &ownerTestStore{}
		store2 := &ownerTestStore{}
		store3 := &ownerTestStore{}
		transport := haepari.NewClient(haepari.Config{RawHome: controller.Home})
		coordinator1, err := NewReviewCoordinator(store1, transport, clock, "", false)
		if err != nil {
			t.Fatal(err)
		}
		coordinator2, err := NewReviewCoordinator(store2, transport, clock, "", false)
		if err != nil {
			t.Fatal(err)
		}
		coordinator3, err := NewReviewCoordinator(store3, transport, clock, "", false)
		if err != nil {
			t.Fatal(err)
		}

		root1, selector := setupProject(t)
		root2, _ := setupProject(t)
		opener, _ := gittarget.NewLiveSourceAdapter(gittarget.ExecRunner{}, nil)

		prepareRunOn := func(coord *ReviewCoordinator, projectRoot ports.AnchoredRoot, artifactRoot ports.AnchoredRoot, roles []domain.Role, mode string, onProviderStart func()) func() (Result, int, error) {
			neutral, _ := ports.NewAnchoredRoot(t.TempDir())
			credential, _ := ports.NewAnchoredRoot(t.TempDir())
			plan := reviewRunPlan(t, roles)
			plan.Threshold = domain.SeverityHigh
			plan.Ceilings = review.DefaultHarnessCeilings()
			terminal := serviceQualifiedTerminal(t)
			for index := range terminal.providers {
				terminal.providers[index].identity.ExecutableSHA256 = "sha256:" + strings.Repeat("b", 64)
				terminal.providers[index].identity.LauncherSHA256 = "sha256:" + strings.Repeat("c", 64)
				terminal.providers[index].qualificationReceiptIDs = []string{"qualification:v1:" + strings.Repeat("d", 64)}
				terminal.providers[index].packetTransportReceiptIDs = []string{"transport:v1:" + strings.Repeat("e", 64)}
			}
			templates := mustServiceTemplates(t)
			return func() (Result, int, error) {
				reader, err := opener.OpenLiveSource(ctx, projectRoot, selector)
				if err != nil {
					return Result{}, 0, err
				}
				source := &integratedLiveSource{LiveSourceReader: reader}
				defer source.Close()
				pubStore, err := filesystem.NewPublicationStore(schema, clock, ids, secureWriter)
				if err != nil {
					return Result{}, 0, err
				}
				pubService, _ := publication.NewService(pubStore, schema, clock, ports.PublicationStructuredMemberMaxBytes)
				build := BuildIdentity{Product: "mulgae", Version: "1.0.0", Module: "github.com/irootkernel/mulgae", VCSRevision: strings.Repeat("a", 40)}
				provider := &integratedLiveProvider{t: t, root: projectRoot, neutral: neutral, side: domain.LiveSourceAfter, mode: mode}
				var observedProvider ports.ObservedReviewProvider = provider
				if onProviderStart != nil {
					observedProvider = &notifyingLiveProvider{inner: provider, onFirstCall: onProviderStart}
				}
				authority := &integratedLiveAuthority{provider: observedProvider, plan: plan, build: build, terminal: terminal}
				factory := &integratedLiveFactory{authority: authority}
				publisher := &integratedLivePublisher{t: t, source: source, authority: authority, service: pubService}
				wire, _ := ports.ParseAssetID(validation.ProviderReviewSchemaID)
				validator, _ := validation.NewReviewValidator(schema, wire)
				common, _ := LoadLiveReviewCommon(ctx, catalog)
				calls := []string{}
				diagnostics := &serviceDiagnosticFactory{calls: &calls}
				service, err := NewLiveService(LiveDependencies{
					Coordination:    coord,
					Sources:         integratedLiveOpener{source},
					ReviewerHome:    promptLiveHome{root: neutral},
					CredentialRoots: []ports.AnchoredRoot{credential},
					Admission:       serviceLiveAdmission{plan},
					Clock:           clock,
					IDs:             ids,
					Build:           build,
					Authority:       factory,
					Validator:       validator,
					Publication:     publisher,
					Templates:       templates,
					Common:          common,
					Diagnostics:     diagnostics,
					Detector:        filesystem.NewContentDetector(),
				})
				if err != nil {
					return Result{}, 0, err
				}
				selection, _ := NewRunSelection(roles, nil)
				res, runErr := service.Execute(ctx, LiveRequest{ProjectRoot: projectRoot, ArtifactRoot: artifactRoot, Target: selector, Selection: selection})
				provider.mu.Lock()
				totalCalls := provider.calls
				provider.mu.Unlock()
				return res, totalCalls, runErr
			}
		}

		artifacts1, _ := ports.NewAnchoredRoot(t.TempDir())
		artifacts2, _ := ports.NewAnchoredRoot(t.TempDir())

		type runOutcome struct {
			res   Result
			calls int
			err   error
		}
		firstDone := make(chan runOutcome, 1)
		secondDone := make(chan runOutcome, 1)
		secondProviderStarted := make(chan struct{}, 1)

		runFirst := prepareRunOn(coordinator1, root1, artifacts1, []domain.Role{domain.RoleLogic, domain.RoleSecurity}, "operational-partial-role", nil)
		runSecond := prepareRunOn(coordinator2, root2, artifacts2, []domain.Role{domain.RoleLogic}, "", func() {
			select {
			case secondProviderStarted <- struct{}{}:
			default:
			}
		})
		runThird := prepareRunOn(coordinator3, root1, artifacts1, []domain.Role{domain.RoleLogic, domain.RoleSecurity}, "", nil)

		go func() {
			res, calls, err := runFirst()
			firstDone <- runOutcome{res, calls, err}
		}()

		releasePending := make(chan error, 1)
		go func() {
			releasePending <- controller.WaitFor(ctx, "release_pending:grant-1")
		}()
		select {
		case err := <-releasePending:
			if err != nil {
				t.Fatal(err)
			}
		case early := <-firstDone:
			t.Fatalf("first run exited before release_pending:grant-1: err=%v (unwrap=%v) calls=%d", early.err, errors.Unwrap(early.err), early.calls)
		}

		// Start unrelated second waiter while first run holds grant-1 at release boundary.
		go func() {
			res, calls, err := runSecond()
			secondDone <- runOutcome{res, calls, err}
		}()

		if err := controller.WaitFor(ctx, "queued:request-2"); err != nil {
			t.Fatal(err)
		}
		if err := controller.WaitFor(ctx, "wait:request-2"); err != nil {
			t.Fatal(err)
		}
		select {
		case <-secondProviderStarted:
			t.Fatal("unrelated waiter dispatched provider before first run drained and released grant-1")
		default:
		}

		unblockRelease()

		first := <-firstDone
		if first.err != nil {
			t.Fatalf("operational partial-role run should publish incomplete P2, got error: %v", first.err)
		}
		if first.calls != 2 {
			t.Fatalf("expected exactly 2 role invocations (no role rerun), got %d", first.calls)
		}
		if !first.res.Final().Valid() || first.res.Coordinator().Outcomes().CoverageStatus() != domain.CoverageIncomplete || first.res.Coordinator().Outcomes().CIDecision() != domain.CIFail {
			t.Fatalf("expected published P2 with incomplete coverage and CI fail axes, got final=%v outcomes=%+v", first.res.Final().Valid(), first.res.Coordinator().Outcomes())
		}
		// Verify accepted logic role report bytes remain readable on disk under original SessionID/RunID.
		reports := first.res.RoleReportURIs()
		if len(reports) != 1 || reports[0].Role != string(domain.RoleLogic) {
			t.Fatalf("expected readable logic role report URI in partial result, got %+v", reports)
		}
		reportRel := strings.TrimPrefix(reports[0].URI, ".mulgae/")
		reportBytes, err := os.ReadFile(filepath.Join(artifacts1.String(), reportRel))
		if err != nil || !bytes.Contains(reportBytes, []byte("Observed defect")) {
			t.Fatalf("accepted logic role report unreadable or missing finding content: err=%v bytes=%s", err, reportBytes)
		}

		second := <-secondDone
		if second.err != nil || second.calls != 1 || !second.res.Final().Valid() {
			t.Fatalf("second waiter failed after first run released: err=%v calls=%d", second.err, second.calls)
		}

		// Third separately invoked full review on root1 gets a fresh RunID, fresh request_key, and fresh FIFO position (request-3 / grant-3).
		thirdRes, thirdCalls, thirdErr := runThird()
		if thirdErr != nil || thirdCalls != 2 || !thirdRes.Final().Valid() {
			t.Fatalf("third fresh review failed: err=%v calls=%d", thirdErr, thirdCalls)
		}
		if thirdRes.RunID() == first.res.RunID() || thirdRes.Coordinator().Outcomes().CoverageStatus() != domain.CoverageComplete {
			t.Fatalf("expected fresh RunID and complete coverage on rerun, got runID=%s coverage=%s", thirdRes.RunID(), thirdRes.Coordinator().Outcomes().CoverageStatus())
		}
		if err := controller.WaitFor(ctx, "granted:request-3"); err != nil {
			t.Fatalf("expected fresh FIFO request-3 granted, got events %v", controller.Events())
		}
	})

	t.Run("borrowed-live-service-execution-and-cleanup", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		controller := haeparifixture.New(t)
		parentClient := haepari.NewClient(haepari.Config{RawHome: controller.Home})
		parentSession, _ := domain.ParseSessionID("s_019f596a-cf80-7c67-b265-f37053d51ccf")
		parentRun, _ := domain.ParseRunID("r_019f596a-cfe4-7c9c-b82e-7149158243ba")
		parentPayload, _ := ports.NewReviewLockRequestPayload(parentSession, parentRun, nil)
		parentReply, err := parentClient.Acquire(ctx, parentPayload.CanonicalJSON)
		if err != nil || parentReply.Current.State != ports.ReviewLockStateGranted {
			t.Fatalf("parent acquire: %v / %+v", err, parentReply)
		}
		rawGrant := controller.ActiveGrantJSON()
		eventsBeforeChild := len(controller.Events())

		catalog, schema := mustSharedReviewRunTestAssets(t)
		ids := adapterruntime.NewUUIDv7Generator()
		clock := adapterruntime.SystemClock{}
		secureWriter := filesystem.NewSecureWriter()
		childStore := &ownerTestStore{}
		childTransport := haepari.NewClient(haepari.Config{
			RawHome:      controller.Home,
			RawLockGrant: rawGrant,
			HasLockGrant: true,
		})
		childCoord, err := NewReviewCoordinator(childStore, childTransport, clock, rawGrant, true)
		if err != nil {
			t.Fatal(err)
		}

		projectRoot, selector := setupProject(t)
		opener, _ := gittarget.NewLiveSourceAdapter(gittarget.ExecRunner{}, nil)
		reader, err := opener.OpenLiveSource(ctx, projectRoot, selector)
		if err != nil {
			t.Fatal(err)
		}
		source := &integratedLiveSource{LiveSourceReader: reader}
		defer source.Close()
		neutral, _ := ports.NewAnchoredRoot(t.TempDir())
		credential, _ := ports.NewAnchoredRoot(t.TempDir())
		artifacts, _ := ports.NewAnchoredRoot(t.TempDir())
		pubStore, _ := filesystem.NewPublicationStore(schema, clock, ids, secureWriter)
		pubService, _ := publication.NewService(pubStore, schema, clock, ports.PublicationStructuredMemberMaxBytes)
		roles := []domain.Role{domain.RoleLogic}
		plan := reviewRunPlan(t, roles)
		plan.Threshold = domain.SeverityHigh
		plan.Ceilings = review.DefaultHarnessCeilings()
		build := BuildIdentity{Product: "mulgae", Version: "1.0.0", Module: "github.com/irootkernel/mulgae", VCSRevision: strings.Repeat("a", 40)}
		provider := &integratedLiveProvider{t: t, root: projectRoot, neutral: neutral, side: domain.LiveSourceAfter}
		terminal := serviceQualifiedTerminal(t)
		for index := range terminal.providers {
			terminal.providers[index].identity.ExecutableSHA256 = "sha256:" + strings.Repeat("b", 64)
			terminal.providers[index].identity.LauncherSHA256 = "sha256:" + strings.Repeat("c", 64)
			terminal.providers[index].qualificationReceiptIDs = []string{"qualification:v1:" + strings.Repeat("d", 64)}
			terminal.providers[index].packetTransportReceiptIDs = []string{"transport:v1:" + strings.Repeat("e", 64)}
		}
		authority := &integratedLiveAuthority{provider: provider, plan: plan, build: build, terminal: terminal}
		factory := &integratedLiveFactory{authority: authority}
		publisher := &integratedLivePublisher{t: t, source: source, authority: authority, service: pubService}
		wire, _ := ports.ParseAssetID(validation.ProviderReviewSchemaID)
		validator, _ := validation.NewReviewValidator(schema, wire)
		common, _ := LoadLiveReviewCommon(ctx, catalog)
		calls := []string{}
		diagnostics := &serviceDiagnosticFactory{calls: &calls}
		service, err := NewLiveService(LiveDependencies{
			Coordination:    childCoord,
			Sources:         integratedLiveOpener{source},
			ReviewerHome:    promptLiveHome{root: neutral},
			CredentialRoots: []ports.AnchoredRoot{credential},
			Admission:       serviceLiveAdmission{plan},
			Clock:           clock,
			IDs:             ids,
			Build:           build,
			Authority:       factory,
			Validator:       validator,
			Publication:     publisher,
			Templates:       mustServiceTemplates(t),
			Common:          common,
			Diagnostics:     diagnostics,
			Detector:        filesystem.NewContentDetector(),
		})
		if err != nil {
			t.Fatal(err)
		}
		selection, _ := NewRunSelection(roles, nil)
		res, err := service.Execute(ctx, LiveRequest{ProjectRoot: projectRoot, ArtifactRoot: artifacts, Target: selector, Selection: selection})
		if err != nil || !res.Final().Valid() {
			t.Fatalf("borrowed child LiveService failed: %v (unwrap=%v)", err, errors.Unwrap(err))
		}
		// Verify child persisted a v3 record with verified local drain and performed zero parent mutations.
		childRecord, found, err := childStore.LoadIntent(ctx, artifacts, res.SessionID(), res.RunID())
		if err != nil || !found || childRecord.SchemaVersion != "mulgae-haepari-lock-intent.v3" || childRecord.LocalDrainState != ports.ReviewLocalDrainVerified {
			t.Fatalf("expected verified v3 child record, got found=%v record=%+v err=%v", found, childRecord, err)
		}
		for _, event := range controller.Events()[eventsBeforeChild:] {
			if strings.HasPrefix(event, "queued:") || strings.HasPrefix(event, "granted:") || strings.HasPrefix(event, "wait:") || strings.HasPrefix(event, "renew:") || strings.HasPrefix(event, "release:") || strings.HasPrefix(event, "cancel:") {
				t.Fatalf("borrowed child mutated parent lock state: %s", event)
			}
		}
		// Parent remains live and can still renew and release its own grant.
		if _, err := parentClient.Renew(ctx, parentReply.Current.GrantID); err != nil {
			t.Fatalf("expected parent grant still live after borrowed child completed, got %v", err)
		}
		if _, err := parentClient.Release(ctx, parentReply.Current.GrantID); err != nil {
			t.Fatalf("expected parent release to succeed, got %v", err)
		}
	})

	t.Run("uncertain-acquire-and-controller-disconnect-restart-over-unix-socket", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		controller := haeparifixture.New(t)
		client := haepari.NewClient(haepari.Config{RawHome: controller.Home})
		clock := adapterruntime.SystemClock{}

		// 1. Uncertain first Acquire over real Unix socket -> automatic exact-payload replay and Release settlement.
		controller.DropNextAcquireResponse()
		uStore := &ownerTestStore{}
		uCoord, err := NewReviewCoordinator(uStore, client, clock, "", false)
		if err != nil {
			t.Fatal(err)
		}
		uReq := ownerTestRequest(t)
		_, uErr := uCoord.startOwnedReview(ctx, uReq, time.Minute)
		if uErr == nil || runtimeDiagnosticFailureClass(uErr) != domain.FailureArtifact {
			t.Fatalf("expected FailureArtifact from uncertain Unix-socket Acquire reconciliation, got %v", uErr)
		}
		if cause, ok := CoordinationFailureReason(uErr); !ok || cause != domain.DiagnosticCauseCoordinationProtectionLost {
			t.Fatalf("expected haepari_protection_lost from uncertain Unix-socket Acquire, got (%q, %v)", cause, ok)
		}
		if uStore.record.LocalDrainState != ports.ReviewLocalDrainNotStarted || uStore.record.ObservedRequest == nil || uStore.record.ObservedRequest.State != ports.ReviewLockStateReleased || uStore.record.SessionID != uReq.SessionID || uStore.record.RunID != uReq.RunID {
			t.Fatalf("expected settled Released observation and LocalDrainNotStarted under original run identity, got %+v", uStore.record)
		}
		if err := controller.WaitFor(ctx, "replay:request-1"); err != nil {
			t.Fatalf("expected exact-payload replay on controller, events=%v", controller.Events())
		}
		if err := controller.WaitFor(ctx, "release:grant-1"); err != nil {
			t.Fatalf("expected unused grant-1 released on controller, events=%v", controller.Events())
		}

		// 2. Controller disconnect during active LiveService execution and restart preserving InstallationID and persisted rows.
		store := &ownerTestStore{}
		coord, err := NewReviewCoordinator(store, client, clock, "", false)
		if err != nil {
			t.Fatal(err)
		}
		created := make(chan ownerControlledTimer, 8)
		coord.timer = func(delay time.Duration) (<-chan time.Time, func()) {
			tick := make(chan time.Time, 1)
			created <- ownerControlledTimer{delay, tick}
			return tick, func() {}
		}

		projectRoot, selector := setupProject(t)
		opener, _ := gittarget.NewLiveSourceAdapter(gittarget.ExecRunner{}, nil)
		reader, err := opener.OpenLiveSource(ctx, projectRoot, selector)
		if err != nil {
			t.Fatal(err)
		}
		source := &integratedLiveSource{LiveSourceReader: reader}
		defer source.Close()
		neutral, _ := ports.NewAnchoredRoot(t.TempDir())
		credential, _ := ports.NewAnchoredRoot(t.TempDir())
		artifacts, _ := ports.NewAnchoredRoot(t.TempDir())
		catalog, schema := mustSharedReviewRunTestAssets(t)
		ids := adapterruntime.NewUUIDv7Generator()
		secureWriter := filesystem.NewSecureWriter()
		pubStore, _ := filesystem.NewPublicationStore(schema, clock, ids, secureWriter)
		pubService, _ := publication.NewService(pubStore, schema, clock, ports.PublicationStructuredMemberMaxBytes)
		roles := []domain.Role{domain.RoleLogic}
		plan := reviewRunPlan(t, roles)
		plan.Threshold = domain.SeverityHigh
		plan.Ceilings = review.DefaultHarnessCeilings()
		build := BuildIdentity{Product: "mulgae", Version: "1.0.0", Module: "github.com/irootkernel/mulgae", VCSRevision: strings.Repeat("a", 40)}
		terminal := serviceQualifiedTerminal(t)
		for index := range terminal.providers {
			terminal.providers[index].identity.ExecutableSHA256 = "sha256:" + strings.Repeat("b", 64)
			terminal.providers[index].identity.LauncherSHA256 = "sha256:" + strings.Repeat("c", 64)
			terminal.providers[index].qualificationReceiptIDs = []string{"qualification:v1:" + strings.Repeat("d", 64)}
			terminal.providers[index].packetTransportReceiptIDs = []string{"transport:v1:" + strings.Repeat("e", 64)}
		}
		baseProvider := &integratedLiveProvider{t: t, root: projectRoot, neutral: neutral, side: domain.LiveSourceAfter, mode: "wait-context-done"}
		provider := &notifyingLiveProvider{
			inner: baseProvider,
			onFirstCall: func() {
				first, second := <-created, <-created
				renewTimer := first
				if second.delay < renewTimer.delay {
					renewTimer = second
				}
				controller.Disconnect()
				renewTimer.tick <- clock.Now()
			},
		}
		authority := &integratedLiveAuthority{
			provider: provider,
			plan:     plan,
			build:    build,
			terminal: terminal,
			drainErr: errors.New("provider drain still in flight"),
		}
		factory := &integratedLiveFactory{authority: authority}
		publisher := &integratedLivePublisher{t: t, source: source, authority: authority, service: pubService}
		wire, _ := ports.ParseAssetID(validation.ProviderReviewSchemaID)
		validator, _ := validation.NewReviewValidator(schema, wire)
		common, _ := LoadLiveReviewCommon(ctx, catalog)
		calls := []string{}
		diagnostics := &serviceDiagnosticFactory{calls: &calls}
		service, err := NewLiveService(LiveDependencies{
			Coordination:    coord,
			Sources:         integratedLiveOpener{source},
			ReviewerHome:    promptLiveHome{root: neutral},
			CredentialRoots: []ports.AnchoredRoot{credential},
			Admission:       serviceLiveAdmission{plan},
			Clock:           clock,
			IDs:             ids,
			Build:           build,
			Authority:       factory,
			Validator:       validator,
			Publication:     publisher,
			Templates:       mustServiceTemplates(t),
			Common:          common,
			Diagnostics:     diagnostics,
			Detector:        filesystem.NewContentDetector(),
		})
		if err != nil {
			t.Fatal(err)
		}
		selection, _ := NewRunSelection(roles, nil)
		res, runErr := service.Execute(ctx, LiveRequest{ProjectRoot: projectRoot, ArtifactRoot: artifacts, Target: selector, Selection: selection})
		if runErr == nil || res.Final().Valid() || publisher.calls != 0 || factory.calls != 1 || baseProvider.calls != 1 || store.record.LocalDrainState != ports.ReviewLocalDrainUnverified {
			t.Fatalf("expected disconnect during active execution to fail without publication or duplicate provider dispatch: err=%v final=%v factory=%d provider=%d state=%q", runErr, res.Final().Valid(), factory.calls, baseProvider.calls, store.record.LocalDrainState)
		}
		if cause, ok := CoordinationFailureReason(runErr); !ok || cause != domain.DiagnosticCauseCoordinationDrainUnverified {
			t.Fatalf("expected haepari_drain_unverified while local drain is unproven, got (%q, %v)", cause, ok)
		}

		// Restart controller on the same Home -> preserves InstallationID and all persisted lock rows (request-1 released, request-2/grant-2 granted).
		controller.Restart(t)
		hello, err := client.Hello(ctx)
		if err != nil || hello.InstallationID != "fixture-installation" {
			t.Fatalf("expected same InstallationID after restart, got %+v / %v", hello, err)
		}
		listAfterRestart, err := client.ListLocks(ctx, ports.HaepariReviewResourceID, "", 100)
		if err != nil || len(listAfterRestart.Requests) != 2 || listAfterRestart.Requests[1].RequestID != "request-2" || listAfterRestart.Requests[1].GrantID != "grant-2" || listAfterRestart.Requests[1].Generation != 2 || listAfterRestart.Requests[1].State != ports.ReviewLockStateGranted {
			t.Fatalf("expected persisted lock rows retained after controller restart, got %+v / %v", listAfterRestart, err)
		}

		// Replay on the unverified run must be refused without releasing grant-2 or dispatching providers.
		_, replayErr := coord.startOwnedReview(ctx, ReviewAcquireRequest{Root: artifacts, SessionID: store.record.SessionID, RunID: store.record.RunID}, time.Minute)
		if cause, ok := CoordinationFailureReason(replayErr); !ok || cause != domain.DiagnosticCauseCoordinationProtectionLost {
			t.Fatalf("expected replay refusal with haepari_protection_lost while LocalDrainUnverified, got (%q, %v)", cause, ok)
		}

		// Deferred local drain verification after restart settles grant-2 once.
		cleanup, retained := LiveCleanupFromError(runErr)
		if !retained {
			t.Fatal("expected retained cleanup handle from unverified drain error")
		}
		authority.drainErr = nil
		cleanupErr := cleanup.DrainAndClose(ctx)
		if cause, ok := CoordinationFailureReason(cleanupErr); !ok || cause != domain.DiagnosticCauseCoordinationProtectionLost {
			t.Fatalf("deferred cleanup must preserve the original protection loss, got (%q, %v): %v", cause, ok, cleanupErr)
		}
		if summary, ok := coordinationDiagnosticSummary(cleanupErr); !ok || summary.Phase() != "renew" {
			t.Fatalf("active renewal loss must retain renew phase after cleanup, got %+v (%v)", summary, ok)
		}
		if !cleanup.providerDrained || !cleanup.sourceClosed || !source.closed || store.record.LocalDrainState != ports.ReviewLocalDrainVerified || store.record.ObservedRequest.State != ports.ReviewLockStateReleased || store.record.ObservedReceipt.Operation != ports.ReviewLockReceiptOperationRelease || baseProvider.calls != 1 || factory.calls != 1 || publisher.calls != 0 {
			t.Fatalf("expected verified physical drain and Released grant-2 without replay or publication: cleanup=%+v record=%+v", cleanup, store.record)
		}
	})
}

type notifyingLiveProvider struct {
	inner       ports.ObservedReviewProvider
	once        sync.Once
	onFirstCall func()
}

func (p *notifyingLiveProvider) Observe(ctx context.Context, invocation ports.ProviderInvocation) (ports.ProviderExecutionObservation, error) {
	p.once.Do(func() {
		if p.onFirstCall != nil {
			p.onFirstCall()
		}
	})
	return p.inner.Observe(ctx, invocation)
}
