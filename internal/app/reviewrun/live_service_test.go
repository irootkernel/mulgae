package reviewrun

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/app/publication"
	"github.com/irootkernel/mulgae/internal/app/review"
	"github.com/irootkernel/mulgae/internal/app/validation"
	"github.com/irootkernel/mulgae/internal/builtin"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

type serviceLiveSource struct {
	promptLiveReader
	closed   bool
	closeErr error
}

func (source *serviceLiveSource) Close() error {
	source.closed = true
	return source.closeErr
}

type serviceLiveOpener struct{ source *serviceLiveSource }

func (opener serviceLiveOpener) OpenLiveSource(context.Context, ports.AnchoredRoot, ports.LiveSourceSelector) (ports.LiveSourceReader, error) {
	return opener.source, nil
}

type serviceLiveAdmission struct{ plan ExecutionPlan }

type serviceFailingLiveOpener struct {
	calls int
	err   error
}

func (opener *serviceFailingLiveOpener) OpenLiveSource(context.Context, ports.AnchoredRoot, ports.LiveSourceSelector) (ports.LiveSourceReader, error) {
	opener.calls++
	return nil, opener.err
}

func TestLiveServiceSourceAdmissionFailurePreservesTypedPolicyBeforeAllocation(t *testing.T) {
	for _, test := range []struct {
		name  string
		code  ports.LiveSourceErrorCode
		class domain.FailureClass
		cause error
	}{
		{name: "invalid", code: ports.LiveSourceInvalid, class: domain.FailureConfiguration},
		{name: "unsafe", code: ports.LiveSourceUnsafe, class: domain.FailureSecurityPolicy},
		{name: "conflict", code: ports.LiveSourceConflict, class: domain.FailureConfiguration},
		{name: "revision", code: ports.LiveSourceRevision, class: domain.FailureConfiguration},
		{name: "merge base", code: ports.LiveSourceNoMergeBase, class: domain.FailureConfiguration},
		{name: "unavailable", code: ports.LiveSourceUnavailable, class: domain.FailureArtifact},
		{name: "unsupported", code: ports.LiveSourceUnsupported, class: domain.FailureConfiguration},
		{name: "cancellation", cause: context.Canceled},
		{name: "deadline", cause: context.DeadlineExceeded},
	} {
		t.Run(test.name, func(t *testing.T) {
			cause := test.cause
			if cause == nil {
				cause = errors.New("private source cause")
			}
			opener := &serviceFailingLiveOpener{err: cause}
			if test.code != "" {
				opener.err = ports.NewLiveSourceError(test.code, cause)
			}
			root, _ := ports.NewAnchoredRoot("/project")
			neutral, _ := ports.NewAnchoredRoot("/neutral")
			credential, _ := ports.NewAnchoredRoot("/credentials")
			selector, _ := ports.NewLiveSourceSelector(domain.LiveSourceWorkspace, "")
			selection, _ := NewRunSelection([]domain.Role{domain.RoleLogic}, nil)
			calls := []string{}
			factory := &serviceLiveAuthority{}
			publisher := &serviceLivePublisher{t: t, stop: errors.New("unexpected publication")}
			common, err := LoadLiveReviewCommon(context.Background(), builtin.NewCatalog())
			if err != nil {
				t.Fatal(err)
			}
			service, err := NewLiveService(LiveDependencies{Sources: opener, ReviewerHome: promptLiveHome{root: neutral}, CredentialRoots: []ports.AnchoredRoot{credential}, Admission: serviceLiveAdmission{}, Clock: serviceClock{}, IDs: &serviceIDs{calls: &calls}, Build: BuildIdentity{Product: "mulgae", Version: "1.0.0", Module: "github.com/irootkernel/mulgae", VCSRevision: "abc123"}, Authority: factory, Validator: &validation.ReviewValidator{}, Publication: publisher, Templates: mustServiceTemplates(t), Common: common, Diagnostics: &serviceDiagnosticFactory{calls: &calls}, Detector: &packetDetectorFake{}})
			if err != nil {
				t.Fatal(err)
			}
			result, err := service.Execute(context.Background(), LiveRequest{ProjectRoot: root, ArtifactRoot: root, Target: selector, Selection: selection})
			if !errors.Is(err, opener.err) || !errors.Is(err, cause) {
				t.Fatalf("source admission lost its original error: %v", err)
			}
			var failure *domain.Failure
			if test.code != "" {
				var sourceError *ports.LiveSourceError
				if !errors.As(err, &failure) || failure.Stage() != "review.source" || failure.Class() != test.class || !errors.As(err, &sourceError) || sourceError.Code() != test.code {
					t.Fatalf("source admission changed its stage, class or code: %v", err)
				}
			} else if err != cause || errors.As(err, &failure) {
				t.Fatalf("source admission wrapped cancellation or deadline: %v", err)
			}
			if _, retained := LiveCleanupFromError(err); retained {
				t.Fatal("failed source open retained nonexistent cleanup authority")
			}
			if !reflect.DeepEqual(result, Result{}) || opener.calls != 1 || len(calls) != 0 || factory.calls != 0 || publisher.calls != 0 {
				t.Fatalf("failed source open allocated, executed or published: result=%+v source=%d calls=%v authority=%d publication=%d", result, opener.calls, calls, factory.calls, publisher.calls)
			}
		})
	}
}

func (admission serviceLiveAdmission) AdmitLive(context.Context, LiveRequest, ports.LiveSourceReader, domain.ProjectBinding) (ExecutionPlan, error) {
	return admission.plan.clone(), nil
}

type serviceLiveAuthority struct {
	calls      int
	authority  RunAuthority
	err        error
	nilSuccess bool
}

func (factory *serviceLiveAuthority) NewQualifiedLiveRun(context.Context, ports.LiveReviewExecution, RunSelection) (RunAuthority, error) {
	factory.calls++
	if factory.authority != nil || factory.err != nil || factory.nilSuccess {
		return factory.authority, factory.err
	}
	return nil, errors.New("empty selection must not qualify providers")
}

type serviceLiveGuardAuthority struct {
	*serviceAuthority
	provider ports.ObservedReviewProvider
	planner  ExecutionPlanner
}

func (authority *serviceLiveGuardAuthority) Provider() ports.ObservedReviewProvider {
	return authority.provider
}

func (authority *serviceLiveGuardAuthority) Planner() ExecutionPlanner { return authority.planner }

type serviceLiveGuardPlanner struct {
	servicePlanner
	err error
}

func (planner serviceLiveGuardPlanner) PlanSelectedRoles(ctx context.Context, roles []domain.Role) (ExecutionPlan, error) {
	plan, err := planner.servicePlanner.PlanSelectedRoles(ctx, roles)
	if planner.err != nil {
		return ExecutionPlan{}, planner.err
	}
	return plan, err
}

func TestLiveServiceQualificationGuardsRejectBeforeExecution(t *testing.T) {
	selector, _ := ports.NewLiveSourceSelector(domain.LiveSourceWorkspace, "")
	path, _ := ports.NewSafeRelativePath("source.go")
	target, _ := ports.NewLiveSourceTarget(selector, ports.GitObjectID{}, ports.GitObjectID{}, false, []ports.LiveSourceChange{{Kind: "included", After: path}})
	root, _ := ports.NewAnchoredRoot("/project")
	git, _ := ports.NewAnchoredRoot("/project/.git")
	neutral, _ := ports.NewAnchoredRoot("/neutral")
	credential, _ := ports.NewAnchoredRoot("/credentials")
	binding := ports.ProjectBindingObservation{Root: root, GitDirectory: git, CommonDirectory: git, RootIdentity: ports.ProjectDirectoryIdentity{Device: 1, Inode: 2}, GitIdentity: ports.ProjectDirectoryIdentity{Device: 1, Inode: 3}, CommonIdentity: ports.ProjectDirectoryIdentity{Device: 1, Inode: 3}}
	for _, test := range []struct {
		name            string
		nilAuthority    bool
		typedNil        bool
		invalidProvider bool
		missingPlanner  bool
		mismatchedPlan  bool
		plannerFailure  bool
		wantError       string
	}{
		{name: "nil authority", nilAuthority: true, wantError: "malformed qualified authority"},
		{name: "typed nil authority", typedNil: true, wantError: "malformed qualified authority"},
		{name: "invalid provider authority", invalidProvider: true, wantError: "malformed qualified authority"},
		{name: "unavailable planner", missingPlanner: true, wantError: "qualified role planner unavailable"},
		{name: "qualified plan mismatch", mismatchedPlan: true, wantError: "qualified plan differs from admitted plan"},
		{name: "typed planner failure", plannerFailure: true, wantError: "qualified plan differs from admitted plan"},
	} {
		t.Run(test.name, func(t *testing.T) {
			source := &serviceLiveSource{promptLiveReader: promptLiveReader{target: target, binding: binding}}
			calls := []string{}
			plan := reviewRunPlan(t, []domain.Role{domain.RoleLogic})
			plan.Ceilings = review.DefaultHarnessCeilings()
			qualifiedPlan := plan.clone()
			if test.mismatchedPlan {
				qualifiedPlan.MaxWorkers++
			}
			provider := &observedProviderFake{}
			base := &serviceAuthority{calls: &calls, terminal: serviceQualifiedTerminal(t)}
			base.drainCheck = func(ctx context.Context) {
				if source.closed || ctx.Err() != nil {
					t.Fatal("rejected authority lost its source lease before provider drain")
				}
				if _, bounded := ctx.Deadline(); !bounded {
					t.Fatal("rejected authority drain is unbounded")
				}
			}
			planner := serviceLiveGuardPlanner{servicePlanner: servicePlanner{calls: &calls, plan: &qualifiedPlan}}
			var typedFailure *domain.Failure
			if test.plannerFailure {
				var err error
				typedFailure, err = domain.NewFailure("qualification.plan", domain.FailureConfiguration, "qualified planning rejected", errors.New("planner cause"))
				if err != nil {
					t.Fatal(err)
				}
				planner.err = typedFailure
			}
			authority := &serviceLiveGuardAuthority{serviceAuthority: base, provider: provider, planner: planner}
			if test.invalidProvider {
				authority.provider = nil
			}
			if test.missingPlanner {
				authority.planner = nil
			}
			factory := &serviceLiveAuthority{authority: authority}
			if test.nilAuthority {
				factory.authority, factory.nilSuccess = nil, true
			} else if test.typedNil {
				factory.authority = (*serviceLiveGuardAuthority)(nil)
			}
			diagnostics := &serviceDiagnosticFactory{calls: &calls}
			publisher := &serviceLivePublisher{t: t, source: source, stop: errors.New("unexpected publication")}
			common, err := LoadLiveReviewCommon(context.Background(), builtin.NewCatalog())
			if err != nil {
				t.Fatal(err)
			}
			service, err := NewLiveService(LiveDependencies{Sources: serviceLiveOpener{source}, ReviewerHome: promptLiveHome{root: neutral}, CredentialRoots: []ports.AnchoredRoot{credential}, Admission: serviceLiveAdmission{plan}, Clock: serviceClock{}, IDs: &serviceIDs{}, Build: base.BuildIdentity(), Authority: factory, Validator: &validation.ReviewValidator{}, Publication: publisher, Templates: mustServiceTemplates(t), Common: common, Diagnostics: diagnostics, Detector: &packetDetectorFake{}})
			if err != nil {
				t.Fatal(err)
			}
			selection, _ := NewRunSelection([]domain.Role{domain.RoleLogic}, nil)
			result, err := service.Execute(context.Background(), LiveRequest{ProjectRoot: root, ArtifactRoot: root, Target: selector, Selection: selection})
			var diagnosticReference *RuntimeDiagnosticReferenceError
			if !errors.As(err, &diagnosticReference) || !strings.Contains(diagnosticReference.Unwrap().Error(), test.wantError) {
				t.Fatalf("qualification guard lost its original rejection: %v", err)
			}
			if typedFailure != nil {
				var retained *domain.Failure
				if !errors.Is(err, typedFailure) || !errors.As(err, &retained) || retained != typedFailure {
					t.Fatalf("qualification guard replaced the typed planner failure: %v", err)
				}
			}
			if !reflect.DeepEqual(result, Result{}) || factory.calls != 1 || source.reads != 0 || provider.calls != 0 || publisher.calls != 0 || !source.closed {
				t.Fatalf("rejected qualification executed, published, retained a result, or left its source open: result=%+v calls=%v reads=%d provider=%d publication=%d closed=%v", result, calls, source.reads, provider.calls, publisher.calls, source.closed)
			}
			wantCalls := []string{"sink"}
			if test.mismatchedPlan || test.plannerFailure {
				wantCalls = append(wantCalls, "plan")
			}
			wantDrains := 0
			if !test.nilAuthority && !test.typedNil {
				wantCalls = append(wantCalls, "drain")
				wantDrains = 1
			}
			if !reflect.DeepEqual(calls, wantCalls) || base.drains != wantDrains {
				t.Fatalf("qualification rejection crossed its planning or cleanup boundary: calls=%v drains=%d", calls, base.drains)
			}
			wantEvents := []domain.RuntimeDiagnosticEventCode{domain.DiagnosticCommandAccepted, domain.DiagnosticRuntimeOpened, domain.DiagnosticSessionCreated, domain.DiagnosticRunCreated, domain.DiagnosticQualificationStarted, domain.DiagnosticQualificationRejected}
			if !reflect.DeepEqual(diagnostics.events, wantEvents) {
				t.Fatalf("qualification rejection event sequence changed: %v", diagnostics.events)
			}
			if len(diagnostics.finalizeRequests) != 1 || diagnostics.finalizeRequests[0].State() != domain.RunFailed {
				t.Fatal("qualification rejection lost its failed diagnostic terminal state")
			}
			if _, _, allocated := RuntimeDiagnosticIdentityFromError(err); !allocated {
				t.Fatal("qualification rejection lost its allocated diagnostic identity")
			}
			if _, installed := RuntimeDiagnosticURIFromError(err); !installed {
				t.Fatal("qualification rejection lost its installed diagnostic reference")
			}
		})
	}
}

func TestLiveServiceRetainsSourceUntilProviderDrainAndAllowsCleanupRetry(t *testing.T) {
	selector, _ := ports.NewLiveSourceSelector(domain.LiveSourceWorkspace, "")
	path, _ := ports.NewSafeRelativePath("source.go")
	target, _ := ports.NewLiveSourceTarget(selector, ports.GitObjectID{}, ports.GitObjectID{}, false, []ports.LiveSourceChange{{Kind: "included", After: path}})
	root, _ := ports.NewAnchoredRoot("/project")
	git, _ := ports.NewAnchoredRoot("/project/.git")
	neutral, _ := ports.NewAnchoredRoot("/neutral")
	credential, _ := ports.NewAnchoredRoot("/credentials")
	binding := ports.ProjectBindingObservation{Root: root, GitDirectory: git, CommonDirectory: git, RootIdentity: ports.ProjectDirectoryIdentity{Device: 1, Inode: 2}, GitIdentity: ports.ProjectDirectoryIdentity{Device: 1, Inode: 3}, CommonIdentity: ports.ProjectDirectoryIdentity{Device: 1, Inode: 3}}
	for _, persistent := range []bool{false, true} {
		t.Run(map[bool]string{false: "detached cancellation cleanup", true: "retained cleanup retry"}[persistent], func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.WithValue(context.Background(), serviceContextKey{}, "preserved"))
			defer cancel()
			source := &serviceLiveSource{promptLiveReader: promptLiveReader{target: target, binding: binding}}
			calls := []string{}
			plan := reviewRunPlan(t, []domain.Role{domain.RoleLogic})
			plan.Ceilings = review.DefaultHarnessCeilings()
			cleanupFailure := errors.New("terminal namespace drain failed")
			authority := &serviceAuthority{calls: &calls, terminal: serviceQualifiedTerminal(t), invalidProvider: persistent, plan: &plan, cancelPlan: cancel, drainErrors: []error{cleanupFailure, cleanupFailure}}
			if !persistent {
				authority.drainErrors = []error{cleanupFailure, nil}
			}
			authority.drainCheck = func(drainCtx context.Context) {
				if source.closed || drainCtx.Err() != nil || drainCtx.Value(serviceContextKey{}) != "preserved" {
					t.Fatal("provider drain lost the source lease or detached context")
				}
				if _, bounded := drainCtx.Deadline(); !bounded {
					t.Fatal("provider drain is unbounded")
				}
			}
			factory := &serviceLiveAuthority{authority: authority}
			diagnostics := &serviceDiagnosticFactory{calls: &calls}
			publisher := &serviceLivePublisher{t: t, source: source, stop: errors.New("unexpected publication")}
			common, err := LoadLiveReviewCommon(ctx, builtin.NewCatalog())
			if err != nil {
				t.Fatal(err)
			}
			service, err := NewLiveService(LiveDependencies{Sources: serviceLiveOpener{source}, ReviewerHome: promptLiveHome{root: neutral}, CredentialRoots: []ports.AnchoredRoot{credential}, Admission: serviceLiveAdmission{plan}, Clock: serviceClock{}, IDs: &serviceIDs{}, Build: authority.BuildIdentity(), Authority: factory, Validator: &validation.ReviewValidator{}, Publication: publisher, Templates: mustServiceTemplates(t), Common: common, Diagnostics: diagnostics, Detector: &packetDetectorFake{}})
			if err != nil {
				t.Fatal(err)
			}
			selection, _ := NewRunSelection([]domain.Role{domain.RoleLogic}, nil)
			_, err = service.Execute(ctx, LiveRequest{ProjectRoot: root, ArtifactRoot: root, Target: selector, Selection: selection})
			if err == nil || publisher.calls != 0 || len(diagnostics.finalizeRequests) != 1 {
				t.Fatalf("failed execution granted publication or lost diagnostics: %v", err)
			}
			if persistent {
				cleanup, retained := LiveCleanupFromError(err)
				if !retained || cleanup.source != source || cleanup.provider != authority || source.closed || !errors.Is(err, cleanupFailure) {
					t.Fatalf("incomplete provider drain lost cleanup authority: %v", err)
				}
				if err := cleanup.DrainAndClose(ctx); err != nil {
					t.Fatal(err)
				}
				if !source.closed || !cleanup.providerDrained || !cleanup.sourceClosed {
					t.Fatal("cleanup retry did not drain before closing the exact source lease")
				}
			} else if !errors.Is(err, context.Canceled) || !source.closed || authority.drains != 2 {
				t.Fatalf("cancelled execution did not complete detached cleanup: %v", err)
			}
		})
	}
}

type serviceLivePublisher struct {
	t      *testing.T
	source *serviceLiveSource
	calls  int
	stop   error
}

func (publisher *serviceLivePublisher) PublishLiveNextObserved(_ context.Context, _ ports.AnchoredRoot, candidate publication.PreparedLiveCandidate, _ publication.LifecycleObserver) (publication.PublicationResult, error) {
	publisher.calls++
	if !publisher.source.closed || !candidate.Valid() {
		publisher.t.Fatal("unclosed or invalid source reached publication")
	}
	return publication.PublicationResult{}, publisher.stop
}

func TestLiveServiceEmptySelectionClosesBeforePublicationWithoutProviderAuthority(t *testing.T) {
	for _, test := range []struct {
		name         string
		closeFailure bool
		wrongBinding bool
	}{
		{name: "provider-free publication"},
		{name: "source close failure", closeFailure: true},
		{name: "binding mismatch", wrongBinding: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			selector, _ := ports.NewLiveSourceSelector(domain.LiveSourceStage, "")
			base, _ := ports.ParseGitObjectID(strings.Repeat("a", 40))
			target, _ := ports.NewLiveSourceTarget(selector, base, ports.GitObjectID{}, false, nil)
			root, _ := ports.NewAnchoredRoot("/project")
			git, _ := ports.NewAnchoredRoot("/project/.git")
			neutral, _ := ports.NewAnchoredRoot("/neutral")
			credential, _ := ports.NewAnchoredRoot("/credentials")
			binding := ports.ProjectBindingObservation{Root: root, GitDirectory: git, CommonDirectory: git, RootIdentity: ports.ProjectDirectoryIdentity{Device: 1, Inode: 2}, GitIdentity: ports.ProjectDirectoryIdentity{Device: 1, Inode: 3}, CommonIdentity: ports.ProjectDirectoryIdentity{Device: 1, Inode: 3}}
			source := &serviceLiveSource{promptLiveReader: promptLiveReader{target: target, binding: binding}}
			if test.closeFailure {
				source.closeErr = errors.New("source descriptor close failed")
			}
			factory := &serviceLiveAuthority{}
			publisher := &serviceLivePublisher{t: t, source: source, stop: errors.New("publication boundary reached")}
			plan := reviewRunPlan(t, []domain.Role{domain.RoleLogic})
			plan.Ceilings = review.DefaultHarnessCeilings()
			selection, _ := NewRunSelection([]domain.Role{domain.RoleLogic}, nil)
			calls := []string{}
			common, err := LoadLiveReviewCommon(context.Background(), builtin.NewCatalog())
			if err != nil {
				t.Fatal(err)
			}
			service, err := NewLiveService(LiveDependencies{Sources: serviceLiveOpener{source}, ReviewerHome: promptLiveHome{root: neutral}, CredentialRoots: []ports.AnchoredRoot{credential}, Admission: serviceLiveAdmission{plan}, Clock: serviceClock{}, IDs: &serviceIDs{}, Build: BuildIdentity{Product: "mulgae", Version: "1.0.0", Module: "github.com/irootkernel/mulgae", VCSRevision: "abc123"}, Authority: factory, Validator: &validation.ReviewValidator{}, Publication: publisher, Templates: mustServiceTemplates(t), Common: common, Diagnostics: &serviceDiagnosticFactory{calls: &calls}, Detector: &packetDetectorFake{}})
			if err != nil {
				t.Fatal(err)
			}
			request := LiveRequest{ProjectRoot: root, ArtifactRoot: root, Target: selector, Selection: selection}
			if test.wrongBinding {
				request.ExpectedProjectBinding, err = NewProjectBinding(root, git, git, ports.ProjectDirectoryIdentity{Device: 1, Inode: 9}, binding.GitIdentity, binding.CommonIdentity)
				if err != nil {
					t.Fatal(err)
				}
			}
			_, err = service.Execute(context.Background(), request)
			if err == nil || !source.closed || source.reads != 0 || factory.calls != 0 {
				t.Fatalf("empty selection lifecycle: closed=%t reads=%d provider=%d error=%v", source.closed, source.reads, factory.calls, err)
			}
			if test.closeFailure || test.wrongBinding {
				if publisher.calls != 0 {
					t.Fatal("failed source admission/closure reached publication")
				}
			} else if publisher.calls != 1 || !errors.Is(err, publisher.stop) {
				t.Fatalf("empty selection did not reach the verified publication boundary: %v", err)
			}
		})
	}
}

func TestLiveServiceDiagnosticAndLoginFailuresRetainSafeIdentity(t *testing.T) {
	for _, test := range []struct {
		name                        string
		open, emit, finalize, login bool
		qualificationRefusal        domain.RuntimeDiagnosticEventCode
	}{
		{name: "diagnostic open", open: true},
		{name: "diagnostic admission event", emit: true},
		{name: "diagnostic finalization", finalize: true},
		{name: "provider login", login: true},
		{name: "qualification admission persistence", login: true, qualificationRefusal: domain.DiagnosticQualificationStarted},
		{name: "qualification candidate persistence", login: true, qualificationRefusal: domain.DiagnosticQualificationCandidateChecked},
		{name: "qualification rejection persistence", login: true, qualificationRefusal: domain.DiagnosticQualificationRejected},
	} {
		t.Run(test.name, func(t *testing.T) {
			selector, _ := ports.NewLiveSourceSelector(domain.LiveSourceStage, "")
			base, _ := ports.ParseGitObjectID(strings.Repeat("a", 40))
			changes := []ports.LiveSourceChange(nil)
			if test.login {
				path, _ := ports.NewSafeRelativePath("source.go")
				changes = append(changes, ports.LiveSourceChange{Kind: "modified", Before: path, After: path})
			}
			target, _ := ports.NewLiveSourceTarget(selector, base, ports.GitObjectID{}, false, changes)
			root, _ := ports.NewAnchoredRoot("/project")
			git, _ := ports.NewAnchoredRoot("/project/.git")
			neutral, _ := ports.NewAnchoredRoot("/neutral")
			credential, _ := ports.NewAnchoredRoot("/credentials")
			source := &serviceLiveSource{promptLiveReader: promptLiveReader{target: target, binding: ports.ProjectBindingObservation{Root: root, GitDirectory: git, CommonDirectory: git, RootIdentity: ports.ProjectDirectoryIdentity{Device: 1, Inode: 2}, GitIdentity: ports.ProjectDirectoryIdentity{Device: 1, Inode: 3}, CommonIdentity: ports.ProjectDirectoryIdentity{Device: 1, Inode: 3}}}}
			calls := []string{}
			diagnostics := &serviceDiagnosticFactory{calls: &calls}
			cause := errors.New("private diagnostic storage path")
			if test.open {
				diagnostics.openErr = cause
			}
			if test.emit {
				diagnostics.refuseEvent, diagnostics.refusal = domain.DiagnosticCommandAccepted, cause
			}
			if test.finalize {
				diagnostics.finalizeErr = cause
			}
			if test.qualificationRefusal != "" {
				diagnostics.refuseEvent, diagnostics.refusal = test.qualificationRefusal, cause
			}
			factory := &serviceLiveAuthority{}
			if test.login {
				loginErr := NewProviderLoginRequiredError([]string{"provider.logic"}, ports.ErrProviderLoginRequired)
				observation, err := newQualificationObservation("provider.logic", qualificationOutcomeRejected, string(domain.FailureAuthentication), qualificationMitigationLogin, domain.DiagnosticCauseLoginRequired)
				if err != nil {
					t.Fatal(err)
				}
				factory.err = withQualificationObservations(loginErr, []ProviderQualificationObservation{observation})
			}
			publisher := &serviceLivePublisher{t: t, source: source, stop: errors.New("publication stopped")}
			plan := reviewRunPlan(t, []domain.Role{domain.RoleLogic})
			plan.Ceilings = review.DefaultHarnessCeilings()
			common, err := LoadLiveReviewCommon(context.Background(), builtin.NewCatalog())
			if err != nil {
				t.Fatal(err)
			}
			service, err := NewLiveService(LiveDependencies{Sources: serviceLiveOpener{source}, ReviewerHome: promptLiveHome{root: neutral}, CredentialRoots: []ports.AnchoredRoot{credential}, Admission: serviceLiveAdmission{plan}, Clock: serviceClock{}, IDs: &serviceIDs{}, Build: BuildIdentity{Product: "mulgae", Version: "1.0.0", Module: "github.com/irootkernel/mulgae", VCSRevision: "abc123"}, Authority: factory, Validator: &validation.ReviewValidator{}, Publication: publisher, Templates: mustServiceTemplates(t), Common: common, Diagnostics: diagnostics, Detector: &packetDetectorFake{}})
			if err != nil {
				t.Fatal(err)
			}
			selection, _ := NewRunSelection([]domain.Role{domain.RoleLogic}, nil)
			result, err := service.Execute(context.Background(), LiveRequest{ProjectRoot: root, ArtifactRoot: root, Target: selector, Selection: selection})
			if err == nil || !source.closed || source.reads != 0 || result.RunID().String() != "" || strings.Contains(err.Error(), cause.Error()) {
				t.Fatalf("failed review lost source closure, returned a result or leaked private diagnostics: %v", err)
			}
			if _, _, allocated := RuntimeDiagnosticIdentityFromError(err); !allocated {
				t.Fatal("failure lost allocated run identity")
			}
			if test.open || test.emit {
				if publisher.calls != 0 || factory.calls != 0 {
					t.Fatal("diagnostic admission failure granted publication or qualification")
				}
			} else if len(diagnostics.finalizeRequests) != 1 {
				t.Fatal("failure was not finalized exactly once")
			}
			if test.qualificationRefusal != "" {
				wantCalls := 1
				if test.qualificationRefusal == domain.DiagnosticQualificationStarted {
					wantCalls = 0
				}
				if diagnostics.refusals != 1 || factory.calls != wantCalls || publisher.calls != 0 || !runtimeDiagnosticPersistenceFailure(err) {
					t.Fatalf("qualification persistence failure granted authority or lost classification: %v", err)
				}
			} else if test.login {
				providers, login := ProviderLoginRequiredProvidersFromError(err)
				if !login || len(providers) != 1 || providers[0] != "provider.logic" || publisher.calls != 0 || factory.calls != 1 || diagnostics.finalizeRequests[0].Cause() != domain.DiagnosticCauseLoginRequired {
					t.Fatalf("login failure lost typed attribution: %v", err)
				}
				if _, installed := RuntimeDiagnosticURIFromError(err); !installed {
					t.Fatal("login failure lost installed diagnostic reference")
				}
				var qualificationEvents []domain.RuntimeDiagnosticEventCode
				for _, input := range diagnostics.inputs {
					if input.Component == "qualification" {
						qualificationEvents = append(qualificationEvents, input.Event)
						if input.Event == domain.DiagnosticQualificationCandidateChecked && (input.Provider != "provider.logic" || input.Outcome != qualificationOutcomeRejected || input.Cause != domain.DiagnosticCauseLoginRequired) {
							t.Fatalf("qualification rejection lost typed attribution: %+v", input)
						}
					}
				}
				if len(qualificationEvents) != 3 || qualificationEvents[0] != domain.DiagnosticQualificationStarted || qualificationEvents[1] != domain.DiagnosticQualificationCandidateChecked || qualificationEvents[2] != domain.DiagnosticQualificationRejected {
					t.Fatalf("qualification rejection lifecycle = %v", qualificationEvents)
				}
			}
		})
	}
}
