package reviewrun

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"time"

	"github.com/irootkernel/mulgae/internal/app/evidence"
	"github.com/irootkernel/mulgae/internal/app/prompt"
	"github.com/irootkernel/mulgae/internal/app/publication"
	"github.com/irootkernel/mulgae/internal/app/review"
	"github.com/irootkernel/mulgae/internal/app/validation"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

type LiveRequest struct {
	ProjectRoot            ports.AnchoredRoot
	ArtifactRoot           ports.AnchoredRoot
	Target                 ports.LiveSourceSelector
	Selection              RunSelection
	Objective              []byte
	HasObjective           bool
	ExpectedProjectBinding domain.ProjectBinding
	ArtistInputs           ports.ArtistReviewInputs
	HasArtistInputs        bool
}

type LiveRunAuthorityFactory interface {
	NewQualifiedLiveRun(context.Context, ports.LiveReviewExecution, RunSelection) (RunAuthority, error)
}

type LiveRequestAdmission interface {
	AdmitLive(context.Context, LiveRequest, ports.LiveSourceReader, domain.ProjectBinding) (ExecutionPlan, error)
}

type LivePublicationCommitter interface {
	PublishLiveNextObserved(context.Context, ports.AnchoredRoot, publication.PreparedLiveCandidate, publication.LifecycleObserver) (publication.PublicationResult, error)
}

type LiveDependencies struct {
	Sources         ports.LiveSourceOpener
	ReviewerHome    ports.ReviewerHome
	CredentialRoots []ports.AnchoredRoot
	Admission       LiveRequestAdmission
	Clock           ports.Clock
	IDs             review.IdentityGenerator
	Build           BuildIdentity
	Authority       LiveRunAuthorityFactory
	Validator       *validation.ReviewValidator
	Publication     LivePublicationCommitter
	Templates       review.TemplateSet
	Common          prompt.TrustedLayer
	Diagnostics     ports.RuntimeDiagnosticSinkFactory
	Detector        ports.ReviewInputContentDetector
	ProjectContext  []byte
}

type LiveService struct{ dependencies LiveDependencies }

func NewLiveService(dependencies LiveDependencies) (*LiveService, error) {
	if nilInterface(dependencies.Sources) || nilInterface(dependencies.ReviewerHome) || len(dependencies.CredentialRoots) == 0 || nilInterface(dependencies.Admission) || nilInterface(dependencies.Clock) || nilInterface(dependencies.IDs) || !dependencies.Build.Valid() || nilInterface(dependencies.Authority) || dependencies.Validator == nil || nilInterface(dependencies.Publication) || dependencies.Templates.Common().ID() == "" || dependencies.Common.ID() == "" || nilInterface(dependencies.Diagnostics) || nilInterface(dependencies.Detector) {
		return nil, fmt.Errorf("live review: invalid dependencies")
	}
	dependencies.CredentialRoots = append([]ports.AnchoredRoot(nil), dependencies.CredentialRoots...)
	dependencies.ProjectContext = append([]byte(nil), dependencies.ProjectContext...)
	return &LiveService{dependencies: dependencies}, nil
}

// Execute retains the original-source lease until every provider has drained
// and evidence has been verified. Publication follows successful source closure.
func (service *LiveService) Execute(ctx context.Context, request LiveRequest) (result Result, err error) {
	if service == nil || ctx == nil || !request.ProjectRoot.Valid() || !request.ArtifactRoot.Valid() || !request.Target.Valid() || !request.Selection.Valid() || !request.HasObjective && len(request.Objective) != 0 {
		return Result{}, fmt.Errorf("live review: malformed request")
	}
	artistSelected := false
	for _, role := range request.Selection.Roles() {
		artistSelected = artistSelected || role == domain.RoleArtist
	}
	if artistSelected != request.HasArtistInputs || request.HasArtistInputs && !request.ArtistInputs.Valid() {
		return Result{}, fmt.Errorf("live review: artist inputs do not match role selection")
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if request.HasObjective {
		if err := prompt.NewObjective(request.Objective).Lint().Err(); err != nil {
			return Result{}, guardFailure(err)
		}
	}
	source, err := service.dependencies.Sources.OpenLiveSource(ctx, request.ProjectRoot, request.Target)
	if err != nil {
		return Result{}, liveSourceAdmissionFailure(err)
	}
	if nilInterface(source) {
		return Result{}, projectAdmissionFailure(fmt.Errorf("missing source lease"))
	}
	sourceClosed := false
	var qualified RunAuthority
	providersDrained := false
	var diagnostics *runtimeDiagnosticLifecycle
	var coordinated review.CoordinatorResult
	defer func() {
		cleanup := &LiveRunCleanup{source: source, provider: qualified, providerDrained: providersDrained, sourceClosed: sourceClosed}
		if !nilInterface(qualified) && !providersDrained {
			_, drainErr := DrainRunAuthorityTerminal(ctx, qualified)
			err = errors.Join(err, drainErr)
			cleanup.providerDrained = drainErr == nil
		}
		if cleanup.providerDrained || nilInterface(qualified) {
			err = errors.Join(err, cleanup.DrainAndClose(ctx))
		}
		if !cleanup.sourceClosed {
			err = &liveCleanupError{cause: err, cleanup: cleanup}
		}
		if err != nil {
			result = Result{}
		}
		if diagnostics == nil {
			return
		}
		state, cause, phase := runtimeDiagnosticTerminalDecision(ctx, result, err)
		uri, uriErr := runtimeDiagnosticP2URI(result, err)
		err = errors.Join(err, uriErr)
		finalized, finalizeErr := diagnostics.finalize(ctx, state, cause, phase, uri, coordinated)
		if finalizeErr != nil {
			result = Result{}
			err = NewAllocatedRunIdentityError(diagnostics.identity.sessionID, diagnostics.identity.runID, errors.Join(err, finalizeErr))
			return
		}
		if err != nil {
			projectURI, uriErr := ports.NewSafeRelativePath(".mulgae/" + finalized.URI().String())
			if uriErr != nil {
				err = errors.Join(err, uriErr)
				return
			}
			err = NewRuntimeDiagnosticReferenceErrorWithIdentity(projectURI, diagnostics.identity.sessionID, diagnostics.identity.runID, err)
			return
		}
		result.diagnostic = finalized.URI()
	}()
	observation, err := source.RevalidateExecution(ctx)
	if err != nil {
		return Result{}, projectAdmissionFailure(err)
	}
	if source.Root() != request.ProjectRoot {
		return Result{}, projectAdmissionFailure(fmt.Errorf("canonical source root mismatch"))
	}
	binding, err := AdmitLiveProjectBinding(observation, request.Target, request.ExpectedProjectBinding)
	if err != nil {
		return Result{}, err
	}
	plan, err := service.dependencies.Admission.AdmitLive(ctx, request, source, binding)
	if err != nil {
		return Result{}, err
	}
	receipt, err := validatePlan(plan, request.Selection.Roles())
	if err != nil {
		return Result{}, err
	}
	identity, err := issueRootRunIdentity(service.dependencies.Clock, service.dependencies.IDs, request.Selection)
	if err != nil {
		return Result{}, err
	}
	diagnostics, err = openRuntimeDiagnosticLifecycle(ctx, service.dependencies.Diagnostics, request.ArtifactRoot, identity, request.Selection.Roles(), service.dependencies.Clock)
	if err != nil {
		return Result{}, NewAllocatedRunIdentityError(identity.sessionID, identity.runID, err)
	}
	ctx = qualificationDiagnosticContext(ctx, diagnostics, service.dependencies.IDs)
	sourceIdentity, err := evidence.NewLiveSourceIdentity(source.Target())
	if err != nil {
		return Result{}, err
	}
	var terminal QualifiedRunTerminalReceipt
	var attempts []publication.AttemptArtifactInput
	var artist liveArtistContext
	if request.HasArtistInputs && !source.Target().NoChange() {
		artist, err = prepareLiveArtistContext(ctx, source, request.ArtistInputs)
		if err != nil {
			return Result{}, projectAdmissionFailure(err)
		}
	}
	if !source.Target().NoChange() {
		execution, err := ports.NewLiveReviewExecution(ctx, source, service.dependencies.ReviewerHome, service.dependencies.CredentialRoots)
		if err != nil {
			return Result{}, projectAdmissionFailure(err)
		}
		if err := diagnostics.observeRunEvent(ctx, domain.DiagnosticQualificationStarted, "qualification", "admit", ""); err != nil {
			return Result{}, err
		}
		qualified, err = service.dependencies.Authority.NewQualifiedLiveRun(ctx, execution, request.Selection)
		if nilInterface(qualified) {
			if owner, ok := CleanupOwnerFromError(err); ok {
				qualified = owner
			} else if owner, ok := RunAuthorityFromError(err); ok {
				qualified = owner
			}
		}
		if err != nil {
			for _, observation := range qualificationObservationsFromError(err) {
				if diagnosticErr := diagnostics.observeQualificationCandidate(ctx, observation); diagnosticErr != nil {
					return Result{}, diagnosticErr
				}
			}
			if diagnosticErr := diagnostics.observeRunEvent(ctx, domain.DiagnosticQualificationRejected, "qualification", "admit", ""); diagnosticErr != nil {
				return Result{}, diagnosticErr
			}
			return Result{}, err
		}
		if nilInterface(qualified) || nilInterface(qualified.Provider()) || qualified.BuildIdentity() != service.dependencies.Build {
			if err := diagnostics.observeRunEvent(ctx, domain.DiagnosticQualificationRejected, "qualification", "admit", ""); err != nil {
				return Result{}, err
			}
			return Result{}, fmt.Errorf("live review: malformed qualified authority")
		}
		if source, ok := qualified.(interface {
			QualificationObservations() []ProviderQualificationObservation
		}); ok {
			for _, observation := range source.QualificationObservations() {
				if err := diagnostics.observeQualificationCandidate(ctx, observation); err != nil {
					return Result{}, err
				}
			}
		}
		planner := qualified.Planner()
		if nilInterface(planner) {
			if err := diagnostics.observeRunEvent(ctx, domain.DiagnosticQualificationRejected, "qualification", "admit", ""); err != nil {
				return Result{}, err
			}
			return Result{}, fmt.Errorf("live review: qualified role planner unavailable")
		}
		qualifiedPlan, err := planner.PlanSelectedRoles(ctx, request.Selection.Roles())
		if err != nil || !reflect.DeepEqual(qualifiedPlan, plan) {
			if diagnosticErr := diagnostics.observeRunEvent(ctx, domain.DiagnosticQualificationRejected, "qualification", "admit", ""); diagnosticErr != nil {
				return Result{}, diagnosticErr
			}
			return Result{}, errors.Join(fmt.Errorf("live review: qualified plan differs from admitted plan"), err)
		}
		if err := diagnostics.observeRunEvent(ctx, domain.DiagnosticQualificationSucceeded, "qualification", "admit", ""); err != nil {
			return Result{}, err
		}
		runIDs, err := newRunIdentityAuthority(service.dependencies.Clock, service.dependencies.IDs)
		if err != nil {
			return Result{}, err
		}
		prompts, err := newLivePromptSource(execution, service.dependencies.Templates, service.dependencies.Common, request.Objective, request.HasObjective, invocationIDs{ids: runIDs, clock: service.dependencies.Clock}, func() (prompt.RoleTaskID, error) {
			value, err := runIDs.NewRoleTaskID(time.Time{})
			if err != nil {
				return prompt.RoleTaskID{}, err
			}
			return prompt.ParseRoleTaskID(value)
		})
		if err != nil {
			return Result{}, classifyReviewPreparationFailure(ctx, diagnostics, ReviewPreparationPromptSource, err)
		}
		prompts.artist, prompts.projectContext = artist, append([]byte(nil), service.dependencies.ProjectContext...)
		screened := &packetScreeningProvider{provider: qualified.Provider(), detector: service.dependencies.Detector}
		runtime, err := review.NewObservedProviderInvocationRuntimeInLiveSource(screened, prompts, execution, service.dependencies.Validator, diagnostics)
		if err != nil {
			return Result{}, classifyReviewPreparationFailure(ctx, diagnostics, ReviewPreparationProviderRuntime, err)
		}
		if request.HasArtistInputs {
			if err := runtime.BindLiveArtistEvidence(artist.images, artist.ready); err != nil {
				return Result{}, err
			}
		}
		defer runtime.DrainRuntimeArtifactsForRun(identity.runID)
		defer runtime.DiscardInitialInputsForRun(identity.runID)
		coordinator, err := review.NewCoordinatorWithRuntimeDiagnostics(service.dependencies.Clock, runIDs, runtime, plan.MaxWorkers, receipt, diagnostics.Sink())
		if err != nil {
			return Result{}, classifyReviewPreparationFailure(ctx, diagnostics, ReviewPreparationCoordinator, err)
		}
		if plan.Extraction {
			if err := coordinator.AdmitStructuredExtraction(); err != nil {
				return Result{}, err
			}
		}
		runTarget, err := sourceIdentity.RunTarget()
		if err != nil {
			return Result{}, err
		}
		run, err := newRootReviewRun(identity, runTarget, plan.Assignments)
		if err != nil {
			return Result{}, err
		}
		coordinated, err = coordinator.ExecuteRun(ctx, &run, plan.Assignments, plan.Threshold, plan.Policy)
		if err != nil {
			return Result{}, classifyCoordinatorExecutionFailure(ctx, diagnostics, err)
		}
		if err := screened.DetectorError(); err != nil {
			return Result{}, err
		}
		if screened.Blocked() {
			return Result{}, projectAdmissionFailure(fmt.Errorf("provider packet rejected"))
		}
		if err := CoordinatorExecutionFailure(coordinated); err != nil {
			return Result{}, err
		}
		for _, capture := range runtime.DrainCaptures() {
			for _, artifact := range capture.Artifacts() {
				attempts = append(attempts, publication.AttemptArtifactInput{AttemptID: capture.AttemptID(), InvocationSequence: capture.Sequence(), Artifact: artifact})
			}
		}
		terminal, err = DrainRunAuthorityTerminal(ctx, qualified)
		if err != nil {
			return Result{}, err
		}
		providersDrained = true
		if err := execution.Revalidate(context.WithoutCancel(ctx)); err != nil {
			return Result{}, projectAdmissionFailure(err)
		}
	}
	if _, err := source.RevalidateExecution(context.WithoutCancel(ctx)); err != nil {
		return Result{}, projectAdmissionFailure(err)
	}
	closeErr := source.Close()
	sourceClosed = closeErr == nil
	if closeErr != nil {
		return Result{}, projectAdmissionFailure(closeErr)
	}
	provenance := liveProductionProvenance(service.dependencies.Build, request, sourceIdentity, binding, identity, terminal)
	var candidate publication.PreparedLiveCandidate
	if source.Target().NoChange() {
		roles := request.Selection.Roles()
		sort.Slice(roles, func(i, j int) bool { return roleOrdinal(roles[i]) < roleOrdinal(roles[j]) })
		candidate, err = publication.PrepareLiveNoChangeCandidate(identity.sessionID, identity.runID, source.Target(), roles, plan.Threshold, provenance)
	} else {
		candidate, err = publication.PrepareLiveCandidate(publication.LiveCandidateInput{Result: coordinated, Target: source.Target(), SeverityThreshold: plan.Threshold, Provenance: provenance, AttemptArtifacts: attempts, BinaryEvidence: artist.images})
	}
	if err != nil {
		return Result{}, publicationCandidateFailure(err)
	}
	published, err := service.dependencies.Publication.PublishLiveNextObserved(ctx, request.ArtifactRoot, candidate, diagnostics)
	if err != nil {
		return Result{}, err
	}
	final, hasFinal := published.Final()
	snapshot, hasSnapshot := published.Snapshot()
	exit, hasExit := published.TerminalExit()
	if published.Decision().Authority() != domain.PublicationAuthorityP2 || !hasFinal || !hasSnapshot || !hasExit {
		return Result{}, fmt.Errorf("live review: incomplete P2 authority")
	}
	reports, err := projectRoleReportURIs(published)
	if err != nil {
		return Result{}, err
	}
	result, err = newResult(identity.sessionID, identity.runID, coordinated, final, snapshot, reports, exit)
	if err == nil {
		result.projectBinding, result.sourceIdentity = binding, sourceIdentity.SHA256()
		result.guarded = request.ExpectedProjectBinding.String() != ""
	}
	return result, err
}

func liveProductionProvenance(build BuildIdentity, request LiveRequest, source evidence.LiveSourceIdentity, binding domain.ProjectBinding, run rootRunIdentity, terminal QualifiedRunTerminalReceipt) publication.LiveProductionProvenance {
	closure := sha256.Sum256([]byte("mulgae-source-terminal/v1\x00" + run.sessionID.String() + "\x00" + run.runID.String() + "\x00" + binding.String() + "\x00" + source.SHA256()))
	value := publication.LiveProductionProvenance{BuildProduct: build.Product, BuildVersion: build.Version, BuildCommit: build.ImmutableReference(), HasObjective: request.HasObjective, SourceIdentitySHA256: source.SHA256(), SourceTerminalReceipt: "source-terminal:v1:sha256:" + hex.EncodeToString(closure[:])}
	if request.HasObjective {
		digest := sha256.Sum256(request.Objective)
		value.ObjectiveSHA256 = "sha256:" + hex.EncodeToString(digest[:])
	}
	for _, provider := range terminal.Providers() {
		identity := provider.Identity()
		value.Providers = append(value.Providers, publication.ProductionProviderProvenance{Family: string(identity.Family), Instance: identity.Instance, Version: identity.Version, Executable: identity.Executable, ExecutableSHA256: identity.ExecutableSHA256, Launcher: identity.Launcher, LauncherSHA256: identity.LauncherSHA256, ProfileGeneration: identity.ProfileGeneration, AdapterProfile: identity.AdapterProfile, QualificationReceiptIDs: provider.QualificationReceiptIDs(), PacketTransportReceiptIDs: provider.PacketTransportReceiptIDs(), NamespaceTerminalReceipt: provider.NamespaceTerminalReceiptID()})
	}
	return value
}
