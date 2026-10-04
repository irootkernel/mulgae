package reviewrun

import (
	"context"
	"errors"
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

func (admission serviceLiveAdmission) AdmitLive(context.Context, LiveRequest, ports.LiveSourceReader, domain.ProjectBinding) (ExecutionPlan, error) {
	return admission.plan.clone(), nil
}

type serviceLiveAuthority struct {
	calls     int
	authority RunAuthority
	err       error
}

func (factory *serviceLiveAuthority) NewQualifiedLiveRun(context.Context, ports.LiveReviewExecution, RunSelection) (RunAuthority, error) {
	factory.calls++
	if factory.authority != nil || factory.err != nil {
		return factory.authority, factory.err
	}
	return nil, errors.New("empty selection must not qualify providers")
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
	}{
		{name: "diagnostic open", open: true},
		{name: "diagnostic admission event", emit: true},
		{name: "diagnostic finalization", finalize: true},
		{name: "provider login", login: true},
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
			factory := &serviceLiveAuthority{}
			if test.login {
				factory.err = NewProviderLoginRequiredError([]string{"provider.logic"}, ports.ErrProviderLoginRequired)
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
			if test.login {
				providers, login := ProviderLoginRequiredProvidersFromError(err)
				if !login || len(providers) != 1 || providers[0] != "provider.logic" || publisher.calls != 0 || factory.calls != 1 || diagnostics.finalizeRequests[0].Cause() != domain.DiagnosticCauseLoginRequired {
					t.Fatalf("login failure lost typed attribution: %v", err)
				}
				if _, installed := RuntimeDiagnosticURIFromError(err); !installed {
					t.Fatal("login failure lost installed diagnostic reference")
				}
			}
		})
	}
}
