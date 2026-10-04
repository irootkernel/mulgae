//go:build darwin && arm64

package composition

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	adapterconfig "github.com/irootkernel/mulgae/internal/adapters/config"
	"github.com/irootkernel/mulgae/internal/adapters/providercli"
	appconfig "github.com/irootkernel/mulgae/internal/app/config"
	"github.com/irootkernel/mulgae/internal/app/prompt"
	"github.com/irootkernel/mulgae/internal/app/review"
	"github.com/irootkernel/mulgae/internal/app/reviewrun"
	"github.com/irootkernel/mulgae/internal/app/validation"
	"github.com/irootkernel/mulgae/internal/builtin"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/entrypoint/mulgae"
	"github.com/irootkernel/mulgae/internal/ports"
)

const (
	reviewWorkspacePrefix = "mulgae-review-workspaces-"
	reviewNamespacePrefix = "mulgae-review-namespaces-"
)

type reviewRunComposer func(context.Context, ports.AnchoredRoot) (mulgae.ReviewRunService, error)
type reviewPreflightComposer func(context.Context, ports.AnchoredRoot) (mulgae.ReviewPreflightService, error)

// deferredReviewRunService keeps repository configuration outside startup and
// offline commands. The review graph is composed only after a review request
// has reached the independent review boundary.
type deferredReviewRunService struct {
	compose          reviewRunComposer
	composePreflight reviewPreflightComposer
}

func newDeferredReviewRunService(compose reviewRunComposer) mulgae.ReviewRunService {
	if compose == nil {
		return mulgae.NewUnavailableReviewRunService(errors.New("review composition is unavailable"))
	}
	return &deferredReviewRunService{compose: compose}
}

func newDeferredReviewRunServiceWithPreflight(compose reviewRunComposer, preflight reviewPreflightComposer) mulgae.ReviewRunService {
	if compose == nil || preflight == nil {
		return mulgae.NewUnavailableReviewRunService(errors.New("review composition is unavailable"))
	}
	return &deferredReviewRunService{compose: compose, composePreflight: preflight}
}

func (service *deferredReviewRunService) StartReviewRun(ctx context.Context, request mulgae.ReviewRequest, root ports.AnchoredRoot) (mulgae.ReviewRunResult, error) {
	composed, err := service.PrepareReviewRun(ctx, root)
	if err != nil {
		return mulgae.ReviewRunResult{}, err
	}
	return composed.StartReviewRun(ctx, request, root)
}

func (service *deferredReviewRunService) PreflightReview(ctx context.Context, request mulgae.ReviewRequest, root ports.AnchoredRoot) (mulgae.ReviewPreflightResult, error) {
	if service == nil || service.composePreflight == nil {
		return mulgae.ReviewPreflightResult{}, errors.New("review preflight composition is unavailable")
	}
	composed, err := service.composePreflight(ctx, root)
	if err != nil {
		return mulgae.ReviewPreflightResult{}, err
	}
	if composed == nil {
		return mulgae.ReviewPreflightResult{}, errors.New("review preflight composition returned no service")
	}
	return composed.PreflightReview(ctx, request, root)
}

func (service *deferredReviewRunService) PrepareReviewRun(ctx context.Context, root ports.AnchoredRoot) (mulgae.ReviewRunService, error) {
	if service == nil || service.compose == nil {
		return nil, errors.New("review composition is unavailable")
	}
	composed, err := service.compose(ctx, root)
	if err != nil {
		unavailable := mulgae.NewUnavailableReviewRunService(err)
		if unavailable == nil {
			return nil, err
		}
		return unavailable, nil
	}
	if composed == nil {
		return nil, errors.New("review composition returned no service")
	}
	return composed, nil
}

// composeReviewRuns constructs the independent review authority. Its failure is
// deliberately local to review readiness: callers can still expose offline
// commands from the already-composed application graph.
func composeReviewRuns(
	ctx context.Context,
	build reviewrun.BuildIdentity,
	root ports.AnchoredRoot,
	catalog *builtin.Catalog,
	validator validation.SchemaValidator,
	projectReader ports.TrustedProjectReader,
	clock ports.Clock,
	ids review.IdentityGenerator,
	writer ports.SecureFileWriter,
	publicationStore ports.PublicationStore,
) (mulgae.ReviewRunService, error) {
	if !build.Valid() {
		return nil, unavailableBuildMetadata(nil)
	}
	if ctx == nil || !root.Valid() || catalog == nil || validator == nil || projectReader == nil || clock == nil || ids == nil || writer == nil || publicationStore == nil {
		return nil, fmt.Errorf("review composition: invalid dependencies")
	}

	graph, err := composeProductionRuntimeGraph(ctx, build, root, catalog, validator, projectReader, clock, ids, writer, publicationStore)
	if err != nil {
		return nil, err
	}
	if err := graph.openLiveReview(ctx, catalog); err != nil {
		return nil, errors.Join(err, graph.cleanupRoots())
	}
	service, err := reviewrun.NewLiveService(reviewrun.LiveDependencies{
		Sources: graph.liveSources, ReviewerHome: graph.reviewerHome, CredentialRoots: graph.credentialRoots,
		Admission: productionLiveRequestAdmission{policy: graph.policy}, Clock: clock, IDs: ids, Build: build,
		Authority: graph.authority, Validator: graph.reviewValidator, Publication: graph.publisher,
		Templates: graph.templates, Common: graph.liveCommon, Diagnostics: graph.diagnostics, Detector: graph.detector, ProjectContext: []byte(graph.policy.config.Project.Context),
	})
	if err != nil {
		return nil, errors.Join(fmt.Errorf("review composition: service: %w", err), graph.cleanupRoots())
	}
	var reviewService mulgae.ReviewRunService
	if inputs := graph.policy.config.Roles.Artist.Inputs; graph.policy.config.Project.Kind == appconfig.ProjectKindUI && inputs != nil {
		artistInputs, inputErr := ports.NewArtistReviewInputs(inputs.TaskPath, inputs.DesignSpecGlobs)
		if inputErr != nil {
			return nil, errors.Join(fmt.Errorf("review composition: artist inputs: %w", inputErr), graph.cleanupRoots())
		}
		reviewService = mulgae.NewPolicyReviewRunServiceWithArtistInputs(mulgae.NewLiveReviewRunService(service), graph.policy.requiredRoles, graph.policy.enabledRoles, artistInputs)
	} else {
		reviewService = mulgae.NewPolicyReviewRunService(mulgae.NewLiveReviewRunService(service), graph.policy.requiredRoles, graph.policy.enabledRoles)
	}
	return &rootCleaningReviewRunService{inner: reviewService, graph: graph}, nil
}

type rootCleaningReviewRunService struct {
	inner mulgae.ReviewRunService
	graph *productionRuntimeGraph
}

type rootCleaningReviewPreflightService struct {
	inner         mulgae.ReviewPreflightService
	workspaceRoot ports.AnchoredRoot
}

func (service *rootCleaningReviewPreflightService) PreflightReview(ctx context.Context, request mulgae.ReviewRequest, root ports.AnchoredRoot) (result mulgae.ReviewPreflightResult, err error) {
	if service == nil || service.inner == nil || !service.workspaceRoot.Valid() {
		return mulgae.ReviewPreflightResult{}, fmt.Errorf("review preflight composition: unavailable service")
	}
	defer func() {
		if cleanupErr := os.RemoveAll(service.workspaceRoot.String()); cleanupErr != nil {
			err = errors.Join(err, fmt.Errorf("review preflight composition: remove temporary root: %w", cleanupErr))
		}
	}()
	return service.inner.PreflightReview(ctx, request, root)
}

type productionReviewPreflightService struct {
	sources ports.LiveSourceOpener
	policy  productionRunPolicy
}

func composeReviewPreflight(ctx context.Context, catalog ports.ContractCatalog, root ports.AnchoredRoot, projectReader ports.TrustedProjectReader) (mulgae.ReviewPreflightService, error) {
	if ctx == nil || !root.Valid() || projectReader == nil || catalog == nil {
		return nil, fmt.Errorf("review preflight composition: invalid dependencies")
	}
	policy, err := resolveProductionRunPolicy(ctx, root, projectReader)
	if err != nil {
		return nil, err
	}
	sources, _, err := productionLiveSources(policy.config, root)
	if err != nil {
		return nil, err
	}
	return &productionReviewPreflightService{sources: sources, policy: policy}, nil
}

func (service *productionReviewPreflightService) PreflightReview(ctx context.Context, request mulgae.ReviewRequest, root ports.AnchoredRoot) (result mulgae.ReviewPreflightResult, err error) {
	if service == nil || ctx == nil || !root.Valid() || service.sources == nil {
		return result, fmt.Errorf("review preflight: invalid service")
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	roles, artistInputs, hasArtistInputs, err := resolvePreflightSelection(request, service.policy)
	if err != nil {
		return result, err
	}
	selection, err := reviewrun.NewRunSelection(roles, nil)
	if err != nil {
		return result, err
	}
	selector, err := ports.NewLiveSourceSelector(domain.LiveSourceScope(request.Target().Kind()), request.Target().Value())
	if err != nil {
		return result, err
	}
	if objective, present := request.Objective(); present {
		if err := prompt.NewObjective([]byte(objective)).Lint().Err(); err != nil {
			return result, err
		}
	}
	source, err := service.sources.OpenLiveSource(ctx, root, selector)
	if err != nil {
		return result, err
	}
	if source == nil {
		return result, fmt.Errorf("review preflight: missing original source")
	}
	defer func() {
		_, terminalErr := source.RevalidateExecution(context.WithoutCancel(ctx))
		err = errors.Join(err, terminalErr, source.Close())
		if err != nil {
			result = mulgae.ReviewPreflightResult{}
		}
	}()
	observed, err := source.RevalidateExecution(ctx)
	if err != nil {
		return result, err
	}
	var expected domain.ProjectBinding
	if value := request.ExpectedProjectBinding(); value != "" {
		expected, err = domain.ParseProjectBinding(value)
		if err != nil {
			return result, err
		}
	}
	binding, err := reviewrun.AdmitLiveProjectBinding(observed, selector, expected)
	if err != nil {
		return result, err
	}
	admission := productionLiveRequestAdmission{policy: service.policy}
	_, err = admission.AdmitLive(ctx, reviewrun.LiveRequest{ProjectRoot: root, Target: selector, Selection: selection}, source, binding)
	if err != nil {
		return result, err
	}
	if hasArtistInputs && !source.Target().NoChange() {
		if err := reviewrun.ValidateLiveArtistInputs(ctx, source, artistInputs); err != nil {
			return result, reviewCompositionFailure(domain.FailureConfiguration, "artist inputs are unavailable", err)
		}
	}
	reads, err := ports.LiveSourceReadPlan(ctx, source)
	if err != nil {
		return result, err
	}
	plan, budget, err := reviewrun.PreflightConfiguredPlan(service.policy.planner, service.policy.providerTimeouts, roles)
	if err != nil {
		return result, err
	}
	return mulgae.NewLiveReviewPreflightResult(source.Target(), binding, service.policy.configurationSHA256, reads, plan, budget)
}

func resolvePreflightSelection(request mulgae.ReviewRequest, policy productionRunPolicy) ([]domain.Role, ports.ArtistReviewInputs, bool, error) {
	var defaults ports.ArtistReviewInputs
	hasDefaults := false
	if inputs := policy.config.Roles.Artist.Inputs; inputs != nil {
		var err error
		defaults, err = ports.NewArtistReviewInputs(inputs.TaskPath, inputs.DesignSpecGlobs)
		if err != nil {
			return nil, ports.ArtistReviewInputs{}, false, err
		}
		hasDefaults = true
	}
	resolved, err := mulgae.ResolveReviewPolicyRequest(request, policy.enabledRoles, defaults, hasDefaults)
	if err != nil {
		return nil, ports.ArtistReviewInputs{}, false, err
	}
	rawRoles := resolved.Roles()
	roles := make([]domain.Role, len(rawRoles))
	artist := false
	for index, raw := range rawRoles {
		roles[index] = domain.Role(raw)
		artist = artist || roles[index] == domain.RoleArtist
	}
	if !artist {
		return roles, ports.ArtistReviewInputs{}, false, nil
	}
	brief, _ := resolved.ArtistBrief()
	var inputs ports.ArtistReviewInputs
	if resolved.ArtistAutomatic() {
		inputs, err = ports.NewAutomaticArtistReviewInputs(brief, resolved.ArtistDesignSpecs())
	} else {
		inputs, err = ports.NewArtistReviewInputs(brief, resolved.ArtistDesignSpecs())
	}
	return roles, inputs, err == nil, err
}

func (service *rootCleaningReviewRunService) StartReviewRun(ctx context.Context, request mulgae.ReviewRequest, root ports.AnchoredRoot) (result mulgae.ReviewRunResult, err error) {
	if service == nil || service.inner == nil || service.graph == nil {
		return mulgae.ReviewRunResult{}, fmt.Errorf("review composition: unavailable composed service")
	}
	defer func() {
		if _, retained := reviewrun.LiveCleanupFromError(err); retained {
			return
		}
		err = errors.Join(err, service.graph.cleanupRoots())
	}()
	return service.inner.StartReviewRun(ctx, request, root)
}
func cleanupReviewCompositionRoots(cleanup bool, namespaceRoot, workspaceRoot ports.AnchoredRoot) error {
	if !cleanup {
		return nil
	}
	var cleanupErr error
	for _, root := range []ports.AnchoredRoot{namespaceRoot, workspaceRoot} {
		if !root.Valid() {
			continue
		}
		if err := os.RemoveAll(root.String()); err != nil {
			cleanupErr = errors.Join(cleanupErr, fmt.Errorf("remove private root: %w", err))
		}
	}
	return cleanupErr
}

type productionRunPolicy struct {
	configurationSHA256 string
	bindingUnsupported  bool
	planner             reviewrun.PlannerPolicy
	requiredRoles       []domain.Role
	enabledRoles        map[domain.Role]bool
	providerTimeouts    map[reviewrun.Family]time.Duration
	config              adapterconfig.Config
	source              *adapterconfig.LocalConfigSource
	attestor            ports.ConfigLocalityAttestor
	localityRequest     ports.ConfigLocalityRequest
	locality            ports.ConfigLocalityContext
}

// resolveProductionRunPolicy admits the sole project-local configuration before
// provider discovery. The returned values are copied into downstream authorities.
func resolveProductionRunPolicy(ctx context.Context, root ports.AnchoredRoot, reader ports.TrustedProjectReader) (productionRunPolicy, error) {
	bindingUnsupported := false
	attestor, ok := reader.(ports.ConfigLocalityAttestor)
	if !ok {
		return productionRunPolicy{}, reviewCompositionFailure(domain.FailureInternal, "config locality attestor unavailable", nil)
	}
	if _, err := os.Lstat(filepath.Join(root.String(), ".git")); os.IsNotExist(err) {
		bindingUnsupported = true
		attestor = adapterconfig.NewFilesystemLocalityAttestor()
	} else if err != nil {
		return productionRunPolicy{}, reviewCompositionFailure(domain.FailureSecurityPolicy, "project locality unavailable", err)
	}
	source, err := adapterconfig.NewLocalConfigSource(root, false)
	if err != nil {
		return productionRunPolicy{}, reviewCompositionFailure(domain.FailureConfiguration, "local configuration unavailable", err)
	}
	proof, err := source.Observation().Proof()
	if err != nil {
		return productionRunPolicy{}, reviewCompositionFailure(domain.FailureSecurityPolicy, "local configuration unsafe", err)
	}
	request, err := ports.NewConfigLocalityRequest(root, proof, nil, nil)
	if err != nil {
		return productionRunPolicy{}, reviewCompositionFailure(domain.FailureInternal, "config locality request invalid", err)
	}
	locality, err := attestor.Attest(ctx, request)
	if err != nil {
		return productionRunPolicy{}, reviewCompositionFailure(domain.FailureSecurityPolicy, "config locality rejected", err)
	}
	if err := revalidateProductionLocality(ctx, source, attestor, request, locality); err != nil {
		return productionRunPolicy{}, reviewCompositionFailure(domain.FailureSecurityPolicy, "config locality drifted", err)
	}
	resolution, err := appconfig.NewService(adapterconfig.YAMLCodec{}).Resolve(ctx, appconfig.ResolveRequest{Source: source})
	if err != nil {
		return productionRunPolicy{}, productionConfigResolutionFailure(err)
	}
	if err := revalidateProductionLocality(ctx, source, attestor, request, locality); err != nil {
		return productionRunPolicy{}, reviewCompositionFailure(domain.FailureSecurityPolicy, "config locality drifted", err)
	}
	policy, err := deriveProductionRunPolicy(resolution.Config())
	if err != nil {
		return productionRunPolicy{}, err
	}
	policy.source, policy.attestor, policy.localityRequest, policy.locality = source, attestor, request, locality
	policy.configurationSHA256 = resolution.SHA256()
	policy.bindingUnsupported = bindingUnsupported
	return policy, nil
}

func productionConfigResolutionFailure(cause error) error {
	if admission, ok := adapterconfig.AsAdmissionError(cause); ok && (admission.Reason() == adapterconfig.ReasonCredentialKeyDetected || admission.Reason() == adapterconfig.ReasonCredentialValueDetected) {
		return reviewCompositionFailure(domain.FailureSecurityPolicy, string(admission.Reason()), cause)
	}
	return reviewCompositionFailure(domain.FailureConfiguration, "local configuration rejected", cause)
}

type reviewLocalityBinding struct {
	source   *adapterconfig.LocalConfigSource
	attestor ports.ConfigLocalityAttestor
	request  ports.ConfigLocalityRequest
	expected ports.ConfigLocalityContext
}

type reviewLocalityContextKey struct{}

type localitySpawnVerifier struct {
	inner    providercli.SpawnVerifier
	source   *adapterconfig.LocalConfigSource
	attestor ports.ConfigLocalityAttestor
	request  ports.ConfigLocalityRequest
	expected ports.ConfigLocalityContext
}

func (verifier localitySpawnVerifier) VerifyProviderSpawn(ctx context.Context, definition providercli.RuntimeDefinition) error {
	if verifier.inner == nil || verifier.source == nil || verifier.attestor == nil {
		return fmt.Errorf("provider spawn locality verifier unavailable")
	}
	if err := revalidateProductionLocality(ctx, verifier.source, verifier.attestor, verifier.request, verifier.expected); err != nil {
		return fmt.Errorf("provider spawn locality drift: %w", err)
	}
	return verifier.inner.VerifyProviderSpawn(ctx, definition)
}

type contextLocalitySpawnVerifier struct{ inner providercli.SpawnVerifier }

func (verifier contextLocalitySpawnVerifier) VerifyProviderSpawn(ctx context.Context, definition providercli.RuntimeDefinition) error {
	bound, err := boundLocalitySpawnVerifier(ctx, verifier.inner)
	if err != nil {
		return err
	}
	return bound.VerifyProviderSpawn(ctx, definition)
}

func boundLocalitySpawnVerifier(ctx context.Context, inner providercli.SpawnVerifier) (providercli.SpawnVerifier, error) {
	if ctx == nil || inner == nil {
		return nil, fmt.Errorf("provider spawn locality verifier unavailable")
	}
	binding, ok := ctx.Value(reviewLocalityContextKey{}).(reviewLocalityBinding)
	if !ok || binding.source == nil || binding.attestor == nil {
		return nil, fmt.Errorf("provider spawn target locality unavailable")
	}
	return localitySpawnVerifier{inner: inner, source: binding.source, attestor: binding.attestor, request: binding.request, expected: binding.expected}, nil
}

type configuredProductionCandidateSource struct {
	inspector        ports.EnvironmentInspector
	config           adapterconfig.Config
	policyIdentities map[reviewrun.Family]string
	providerTimeouts map[reviewrun.Family]time.Duration
	source           *adapterconfig.LocalConfigSource
	attestor         ports.ConfigLocalityAttestor
	staticRequest    ports.ConfigLocalityRequest
	staticContext    ports.ConfigLocalityContext
}

func (source *configuredProductionCandidateSource) bindSyntheticQualifiedRunContext(ctx context.Context) (context.Context, error) {
	if source == nil || ctx == nil || source.source == nil || source.attestor == nil {
		return nil, fmt.Errorf("configured provider locality: invalid synthetic request")
	}
	if err := revalidateProductionLocality(ctx, source.source, source.attestor, source.staticRequest, source.staticContext); err != nil {
		return nil, fmt.Errorf("configured provider locality: synthetic request drift: %w", err)
	}
	binding := reviewLocalityBinding{
		source: source.source, attestor: source.attestor,
		request: source.staticRequest, expected: source.staticContext,
	}
	return context.WithValue(ctx, reviewLocalityContextKey{}, binding), nil
}

func (source *configuredProductionCandidateSource) BindLiveQualifiedRunContext(ctx context.Context, execution ports.LiveReviewExecution) (context.Context, error) {
	if source == nil || ctx == nil || !execution.Valid() {
		return nil, fmt.Errorf("configured provider locality: invalid live request")
	}
	if err := execution.Revalidate(ctx); err != nil {
		return nil, err
	}
	commits := make([]ports.GitObjectID, 0, 2)
	if base := execution.Target().Base(); base.Valid() {
		commits = append(commits, base)
	}
	if head := execution.Target().Head(); head.Valid() {
		commits = append(commits, head)
	}
	bound, err := bindProductionLocality(ctx, source.source, source.attestor, source.staticRequest, source.staticContext, source.config, commits, nil)
	if err != nil {
		return nil, err
	}
	return context.WithValue(ctx, reviewLocalityContextKey{}, bound), nil
}

func bindProductionTargetLocality(ctx context.Context, source *adapterconfig.LocalConfigSource, attestor ports.ConfigLocalityAttestor, staticRequest ports.ConfigLocalityRequest, staticContext ports.ConfigLocalityContext, config adapterconfig.Config, target ports.CapturedReviewTarget) (reviewLocalityBinding, error) {
	if !target.Valid() {
		return reviewLocalityBinding{}, fmt.Errorf("configured provider locality: invalid request")
	}
	commits := make([]ports.GitObjectID, 0, 2)
	if base, ok := target.BaseObjectID(); ok {
		commits = append(commits, base)
	}
	if head, ok := target.HeadObjectID(); ok {
		commits = append(commits, head)
	}
	return bindProductionLocality(ctx, source, attestor, staticRequest, staticContext, config, commits, target.Bytes())
}

func bindProductionLocality(ctx context.Context, source *adapterconfig.LocalConfigSource, attestor ports.ConfigLocalityAttestor, staticRequest ports.ConfigLocalityRequest, staticContext ports.ConfigLocalityContext, config adapterconfig.Config, commits []ports.GitObjectID, target []byte) (reviewLocalityBinding, error) {
	if ctx == nil || source == nil || attestor == nil {
		return reviewLocalityBinding{}, fmt.Errorf("configured provider locality: invalid request")
	}
	if err := revalidateProductionLocality(ctx, source, attestor, staticRequest, staticContext); err != nil {
		return reviewLocalityBinding{}, fmt.Errorf("configured provider locality: checkout drift: %w", err)
	}
	data, _, err := source.Read()
	if err != nil {
		return reviewLocalityBinding{}, fmt.Errorf("configured provider locality: config read: %w", err)
	}
	decoded, err := adapterconfig.Decode(data)
	if err != nil || !reflect.DeepEqual(decoded, config) {
		return reviewLocalityBinding{}, fmt.Errorf("configured provider locality: admitted config drift")
	}
	proof, err := source.Proof()
	if err != nil {
		return reviewLocalityBinding{}, fmt.Errorf("configured provider locality: config proof: %w", err)
	}
	request, err := ports.NewConfigLocalityRequest(staticRequest.Root(), proof, commits, target)
	if err != nil {
		return reviewLocalityBinding{}, fmt.Errorf("configured provider locality: target request: %w", err)
	}
	expected, err := attestor.Attest(ctx, request)
	if err != nil {
		return reviewLocalityBinding{}, fmt.Errorf("configured provider locality: target rejected: %w", err)
	}
	if err := revalidateProductionLocality(ctx, source, attestor, request, expected); err != nil {
		return reviewLocalityBinding{}, fmt.Errorf("configured provider locality: target drift: %w", err)
	}
	return reviewLocalityBinding{source: source, attestor: attestor, request: request, expected: expected}, nil
}

func revalidateProductionLocality(ctx context.Context, source *adapterconfig.LocalConfigSource, attestor ports.ConfigLocalityAttestor, request ports.ConfigLocalityRequest, expected ports.ConfigLocalityContext) error {
	if source == nil || attestor == nil {
		return fmt.Errorf("config locality unavailable")
	}
	if err := source.Revalidate(); err != nil {
		return err
	}
	if err := attestor.Revalidate(ctx, request, expected); err != nil {
		return err
	}
	return source.Revalidate()
}

func (source *configuredProductionCandidateSource) NewLiveQualifiedRunCandidates(ctx context.Context, target ports.LiveSourceTarget, selection reviewrun.RunSelection) ([]reviewrun.QualifiedRunCandidate, error) {
	if source == nil || source.inspector == nil || ctx == nil {
		return nil, fmt.Errorf("configured provider discovery unavailable")
	}
	if _, ok := ctx.Value(reviewLocalityContextKey{}).(reviewLocalityBinding); !ok {
		return nil, fmt.Errorf("configured provider live locality unavailable")
	}
	production, err := source.productionCandidateSource(ctx)
	if err != nil {
		return nil, err
	}
	candidates, err := production.NewLiveQualifiedRunCandidates(target, selection)
	if err != nil {
		return nil, err
	}
	return source.filterAssignedCandidates(candidates, selection)
}

func (source *configuredProductionCandidateSource) filterAssignedCandidates(candidates []reviewrun.QualifiedRunCandidate, selection reviewrun.RunSelection) ([]reviewrun.QualifiedRunCandidate, error) {
	filtered := make([]reviewrun.QualifiedRunCandidate, 0, len(candidates))
	for _, candidate := range candidates {
		roles, base := configuredQualificationRoles(source.config.Roles, selection.Roles(), reviewrun.Family(candidate.Definition.Family()))
		roles = intersectConfiguredCandidateRoles(roles, candidate.SupportedRoles)
		if len(roles) == 0 {
			continue
		}
		if !rolePresent(roles, base) {
			base = roles[0]
		}
		candidate.SupportedRoles = roles
		candidate.BaseRole = base
		filtered = append(filtered, candidate)
	}
	if len(filtered) == 0 {
		return nil, fmt.Errorf("configured provider discovery produced no assigned candidate")
	}
	return filtered, nil
}

func (source *configuredProductionCandidateSource) productionCandidateSource(ctx context.Context) (*reviewrun.ProductionQualifiedRunCandidateSource, error) {
	configured := make(map[reviewrun.Family][]string, source.config.Providers.Count())
	if provider := source.config.Providers.ZCode; provider != nil {
		configured[reviewrun.FamilyZCode] = []string{provider.AppBundle}
	}
	if provider := source.config.Providers.Grok; provider != nil {
		configured[reviewrun.FamilyGrok] = []string{provider.Executable}
	}
	if provider := source.config.Providers.Codex; provider != nil {
		configured[reviewrun.FamilyCodex] = []string{provider.Executable}
	}
	profiles, err := reviewrun.DiscoverConfiguredProviderProfiles(ctx, source.inspector, configured)
	if err != nil {
		return nil, err
	}
	zcodeModel, zcodeReasoningEffort, grokModel, grokReasoningEffort, codexModel, codexReasoningEffort := source.providerSettings()
	return reviewrun.NewProductionQualifiedRunCandidateSourceWithPolicyIdentitiesAndAllProviderSettingsAndTimeouts(
		providercli.RuntimeBuilder{}, profiles, source.policyIdentities,
		zcodeModel, zcodeReasoningEffort,
		grokModel, grokReasoningEffort,
		codexModel, codexReasoningEffort,
		configuredCodexCredentialProfiles(source.config),
		cloneProviderTimeouts(source.providerTimeouts),
	)
}

func (source *configuredProductionCandidateSource) providerSettings() (zcodeModel, zcodeReasoningEffort, grokModel, grokReasoningEffort, codexModel, codexReasoningEffort string) {
	if source == nil {
		return "", "", "", "", "", ""
	}
	if provider := source.config.Providers.ZCode; provider != nil {
		zcodeModel, zcodeReasoningEffort = provider.Model, provider.ReasoningEffort
	}
	if provider := source.config.Providers.Grok; provider != nil {
		grokModel, grokReasoningEffort = provider.Model, provider.ReasoningEffort
	}
	if provider := source.config.Providers.Codex; provider != nil {
		codexModel, codexReasoningEffort = provider.Model, provider.ReasoningEffort
	}
	return zcodeModel, zcodeReasoningEffort, grokModel, grokReasoningEffort, codexModel, codexReasoningEffort
}

func (source *configuredProductionCandidateSource) newHeartbeatCandidate(ctx context.Context, workspace ports.WorkspaceSnapshotIdentity, family reviewrun.Family, credentialProfile string) (reviewrun.QualifiedRunCandidate, error) {
	if source == nil || ctx == nil || !workspace.Valid() || !family.Valid() || !source.config.Providers.HasFamily(string(family)) {
		return reviewrun.QualifiedRunCandidate{}, fmt.Errorf("heartbeat provider is not configured")
	}
	if err := revalidateProductionLocality(ctx, source.source, source.attestor, source.staticRequest, source.staticContext); err != nil {
		return reviewrun.QualifiedRunCandidate{}, err
	}
	selection, err := reviewrun.NewRunSelection(domain.FixedRoleOrder(), nil)
	if err != nil {
		return reviewrun.QualifiedRunCandidate{}, err
	}
	heartbeatSource := *source
	heartbeatSource.providerTimeouts = cloneProviderTimeouts(source.providerTimeouts)
	for configuredFamily, configuredTimeout := range heartbeatSource.providerTimeouts {
		if configuredTimeout > time.Minute {
			heartbeatSource.providerTimeouts[configuredFamily] = time.Minute
		}
	}
	production, err := heartbeatSource.productionCandidateSource(ctx)
	if err != nil {
		return reviewrun.QualifiedRunCandidate{}, err
	}
	candidates, err := production.NewSyntheticQualifiedRunCandidates(workspace, selection)
	if err != nil {
		return reviewrun.QualifiedRunCandidate{}, err
	}
	wantCodexPrefix := "codex-" + credentialProfile + "-"
	for _, candidate := range candidates {
		if reviewrun.Family(candidate.Definition.Family()) != family {
			continue
		}
		if family == reviewrun.FamilyCodex && credentialProfile != "" && !strings.HasPrefix(candidate.Definition.Instance(), wantCodexPrefix) {
			continue
		}
		candidate.SupportedRoles = []domain.Role{candidate.BaseRole}
		return candidate, nil
	}
	return reviewrun.QualifiedRunCandidate{}, fmt.Errorf("heartbeat provider identity is unavailable")
}

func intersectConfiguredCandidateRoles(configured, supported []domain.Role) []domain.Role {
	supportedSet := make(map[domain.Role]struct{}, len(supported))
	for _, role := range supported {
		supportedSet[role] = struct{}{}
	}
	result := make([]domain.Role, 0, len(configured))
	for _, role := range configured {
		if _, ok := supportedSet[role]; ok {
			result = append(result, role)
		}
	}
	return result
}

func rolePresent(roles []domain.Role, expected domain.Role) bool {
	for _, role := range roles {
		if role == expected {
			return true
		}
	}
	return false
}

func configuredQualificationRoles(config adapterconfig.RolesConfig, selected []domain.Role, family reviewrun.Family) ([]domain.Role, domain.Role) {
	selectedSet := make(map[domain.Role]struct{}, len(selected))
	for _, role := range selected {
		selectedSet[role] = struct{}{}
	}
	configured := config.Ordered()
	roles := make([]domain.Role, 0, len(selected))
	var primaryBase domain.Role
	for index, role := range domain.FixedRoleOrder() {
		if _, ok := selectedSet[role]; !ok || index >= len(configured) {
			continue
		}
		assignment := configured[index]
		if !assignment.Enabled {
			continue
		}
		if reviewrun.Family(assignment.PrimaryProvider) != family {
			continue
		}
		roles = append(roles, role)
		if primaryBase == "" && reviewrun.Family(assignment.PrimaryProvider) == family {
			primaryBase = role
		}
	}
	if primaryBase == "" && len(roles) > 0 {
		primaryBase = roles[0]
	}
	return roles, primaryBase
}

func configuredCodexCredentialProfiles(config adapterconfig.Config) map[domain.Role]string {
	if config.Providers.Codex == nil || config.Providers.Codex.DefaultCredentialProfile == "" {
		return nil
	}
	profiles := make(map[domain.Role]string)
	for index, role := range domain.FixedRoleOrder() {
		configured := config.Roles.Ordered()[index]
		if configured.PrimaryProvider != "codex" {
			continue
		}
		profile := configured.CredentialProfile
		if profile == "" {
			profile = config.Providers.Codex.DefaultCredentialProfile
		}
		profiles[role] = profile
	}
	return profiles
}

func deriveProductionRunPolicy(resolved appconfig.ResolvedConfig) (productionRunPolicy, error) {
	requestChanges := resolved.RequestChangesOn()
	if len(requestChanges) == 0 {
		return productionRunPolicy{}, reviewCompositionFailure(domain.FailureConfiguration, "production policy has no review threshold", nil)
	}
	defaults := review.DefaultHarnessCeilings()
	ceilings, err := review.NewHarnessCeilings(
		defaults.MaxTimeout(),
		defaults.MaxRolePathDeadline(), defaults.MaxRunDeadline(),
		resolved.RoleMaxInvocations(), resolved.RunMaxInvocations(),
	)
	if err != nil {
		return productionRunPolicy{}, reviewCompositionFailure(domain.FailureConfiguration, "production limits are invalid", err)
	}
	enabled := make(map[domain.Role]bool, len(domain.FixedRoleOrder()))
	assignments := make([]reviewrun.RoleProviderAssignment, 0, len(domain.FixedRoleOrder()))
	for _, role := range domain.FixedRoleOrder() {
		definition, present := resolved.Role(role)
		if !present {
			return productionRunPolicy{}, reviewCompositionFailure(domain.FailureConfiguration, "production role policy is incomplete", nil)
		}
		enabled[role] = definition.Enabled()
		if !definition.Enabled() {
			continue
		}
		if role == domain.RoleArtist && reviewrun.Family(definition.PrimaryProvider()) == reviewrun.FamilyGrok {
			return productionRunPolicy{}, reviewCompositionFailure(domain.FailureProviderUnavailable, "provider_capability_unsupported", nil)
		}
		assignment, err := reviewrun.NewRoleProviderAssignmentWithCredentialProfile(role, reviewrun.Family(definition.PrimaryProvider()), definition.CredentialProfile())
		if err != nil {
			return productionRunPolicy{}, reviewCompositionFailure(domain.FailureConfiguration, "production role provider assignment is invalid", err)
		}
		assignments = append(assignments, assignment)
	}
	ci := domain.CIPolicy{
		RequestChangesFails:   true,
		DegradedReviewFails:   resolved.DegradedReviewFails(),
		IncompleteReviewFails: true,
	}
	providerTimeouts := make(map[reviewrun.Family]time.Duration, len(reviewrun.Families()))
	for _, family := range reviewrun.Families() {
		providerTimeouts[family] = appconfig.DefaultProviderTimeout
		if timeout, ok := resolved.ProviderTimeout(string(family)); ok {
			providerTimeouts[family] = timeout
		}
	}
	return productionRunPolicy{
		planner: reviewrun.PlannerPolicy{
			Ceilings: ceilings, Threshold: requestChanges[0], Policy: &ci, MaxWorkers: resolved.Runtime().MaxActiveLanes, Assignments: assignments, RequiredRoles: resolved.RequiredRoles(),
			Extraction: resolved.ExtractionEnabled(),
		},
		requiredRoles:    resolved.RequiredRoles(),
		enabledRoles:     enabled,
		providerTimeouts: providerTimeouts,
		config:           resolved.Raw(),
	}, nil
}

func cloneProviderTimeouts(timeouts map[reviewrun.Family]time.Duration) map[reviewrun.Family]time.Duration {
	cloned := make(map[reviewrun.Family]time.Duration, len(timeouts))
	for family, timeout := range timeouts {
		cloned[family] = timeout
	}
	return cloned
}

func reviewCompositionFailure(class domain.FailureClass, reason string, cause error) error {
	if localityReason, ok := ports.ConfigLocalityReasonFromError(cause); ok {
		reason = string(localityReason)
	}
	failure, err := domain.NewFailure("review.composition", class, reason, cause)
	if err != nil {
		return fmt.Errorf("review composition failure")
	}
	return failure
}

func unavailableBuildMetadata(cause error) error {
	return reviewCompositionFailure(domain.FailureArtifact, "production build provenance is unavailable", cause)
}

func startupTempRoot() (string, error) {
	tempRoot := os.Getenv("TMPDIR")
	if tempRoot == "" {
		return "", nil
	}
	resolved, err := filepath.EvalSymlinks(filepath.Clean(tempRoot))
	if err != nil {
		return "", err
	}
	return filepath.Clean(resolved), nil
}

func privateReviewRoot(tempRoot, prefix string) (ports.AnchoredRoot, error) {
	path, err := os.MkdirTemp(tempRoot, prefix)
	if err != nil {
		return ports.AnchoredRoot{}, fmt.Errorf("review composition: create private root: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		_ = os.RemoveAll(path)
		return ports.AnchoredRoot{}, fmt.Errorf("review composition: resolve private root: %w", err)
	}
	root, err := ports.NewAnchoredRoot(filepath.Clean(resolved))
	if err != nil {
		_ = os.RemoveAll(path)
		return ports.AnchoredRoot{}, fmt.Errorf("review composition: anchor private root: %w", err)
	}
	return root, nil
}
