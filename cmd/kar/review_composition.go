//go:build darwin && arm64

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"

	adapterconfig "github.com/irootkernel/kkachi-agent-review/internal/adapters/config"
	"github.com/irootkernel/kkachi-agent-review/internal/adapters/providercli"
	appconfig "github.com/irootkernel/kkachi-agent-review/internal/app/config"
	"github.com/irootkernel/kkachi-agent-review/internal/app/review"
	"github.com/irootkernel/kkachi-agent-review/internal/app/reviewrun"
	"github.com/irootkernel/kkachi-agent-review/internal/app/validation"
	"github.com/irootkernel/kkachi-agent-review/internal/builtin"
	"github.com/irootkernel/kkachi-agent-review/internal/domain"
	"github.com/irootkernel/kkachi-agent-review/internal/entrypoint/kar"
	"github.com/irootkernel/kkachi-agent-review/internal/ports"
)

const (
	reviewWorkspacePrefix = "kar-review-workspaces-"
	reviewNamespacePrefix = "kar-review-namespaces-"
)

type reviewRunComposer func(context.Context, ports.AnchoredRoot) (kar.ReviewRunService, error)

// deferredReviewRunService keeps repository configuration outside startup and
// offline commands. The review graph is composed only after a review request
// has reached the independent review boundary.
type deferredReviewRunService struct {
	compose reviewRunComposer
}

func newDeferredReviewRunService(compose reviewRunComposer) kar.ReviewRunService {
	if compose == nil {
		return kar.NewUnavailableReviewRunService(errors.New("review composition is unavailable"))
	}
	return &deferredReviewRunService{compose: compose}
}

func (service *deferredReviewRunService) StartReviewRun(ctx context.Context, request kar.ReviewRequest, root ports.AnchoredRoot) (kar.ReviewRunResult, error) {
	composed, err := service.PrepareReviewRun(ctx, root)
	if err != nil {
		return kar.ReviewRunResult{}, err
	}
	return composed.StartReviewRun(ctx, request, root)
}

func (service *deferredReviewRunService) PrepareReviewRun(ctx context.Context, root ports.AnchoredRoot) (kar.ReviewRunService, error) {
	if service == nil || service.compose == nil {
		return nil, errors.New("review composition is unavailable")
	}
	composed, err := service.compose(ctx, root)
	if err != nil {
		unavailable := kar.NewUnavailableReviewRunService(err)
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
	stdin ports.CapturedStdinStore,
) (kar.ReviewRunService, error) {
	if !build.Valid() {
		return nil, unavailableBuildMetadata(nil)
	}
	if ctx == nil || !root.Valid() || catalog == nil || validator == nil || projectReader == nil || clock == nil || ids == nil || writer == nil || publicationStore == nil || stdin == nil {
		return nil, fmt.Errorf("review composition: invalid dependencies")
	}

	graph, err := composeProductionRuntimeGraph(ctx, build, root, catalog, validator, projectReader, clock, ids, writer, publicationStore, stdin)
	if err != nil {
		return nil, err
	}
	service, err := reviewrun.NewService(reviewrun.Dependencies{
		Clock: clock, IDs: ids, Build: build, RunAuthorityFactory: graph.authority, Validator: graph.reviewValidator, Locker: graph.locker, Publication: graph.publisher, Templates: graph.templates, Diagnostics: graph.diagnostics,
	})
	if err != nil {
		graph.cleanupRoots()
		return nil, fmt.Errorf("review composition: service: %w", err)
	}
	var reviewService kar.ReviewRunService
	if inputs := graph.policy.config.Roles.Artist.Inputs; graph.policy.config.Project.Kind == appconfig.ProjectKindUI && inputs != nil {
		artistInputs, inputErr := ports.NewArtistReviewInputs(inputs.TaskPath, inputs.DesignSpecGlobs)
		if inputErr != nil {
			graph.cleanupRoots()
			return nil, fmt.Errorf("review composition: artist inputs: %w", inputErr)
		}
		reviewService = kar.NewPolicyReviewRunServiceWithArtistInputs(kar.NewReviewRunService(service, graph.inputs), graph.policy.requiredRoles, graph.policy.enabledRoles, artistInputs)
	} else {
		reviewService = kar.NewPolicyReviewRunService(kar.NewReviewRunService(service, graph.inputs), graph.policy.requiredRoles, graph.policy.enabledRoles)
	}
	return &rootCleaningReviewRunService{inner: reviewService, graph: graph}, nil
}

type rootCleaningReviewRunService struct {
	inner kar.ReviewRunService
	graph *productionRuntimeGraph
}

func (service *rootCleaningReviewRunService) StartReviewRun(ctx context.Context, request kar.ReviewRequest, root ports.AnchoredRoot) (kar.ReviewRunResult, error) {
	if service == nil || service.inner == nil || service.graph == nil {
		return kar.ReviewRunResult{}, fmt.Errorf("review composition: unavailable composed service")
	}
	defer service.graph.cleanupRoots()
	return service.inner.StartReviewRun(ctx, request, root)
}
func cleanupReviewCompositionRoots(cleanup bool, namespaceRoot, workspaceRoot ports.AnchoredRoot) {
	if !cleanup {
		return
	}
	_ = os.RemoveAll(namespaceRoot.String())
	_ = os.RemoveAll(workspaceRoot.String())
}

type productionRunPolicy struct {
	planner           reviewrun.PlannerPolicy
	requiredRoles     []domain.Role
	enabledRoles      map[domain.Role]bool
	agyPermissionMode string
	config            adapterconfig.Config
	source            *adapterconfig.LocalConfigSource
	attestor          ports.ConfigLocalityAttestor
	localityRequest   ports.ConfigLocalityRequest
	locality          ports.ConfigLocalityContext
}

// resolveProductionRunPolicy admits the sole project-local configuration before
// provider discovery. The returned values are copied into downstream authorities.
func resolveProductionRunPolicy(ctx context.Context, root ports.AnchoredRoot, reader ports.TrustedProjectReader) (productionRunPolicy, error) {
	attestor, ok := reader.(ports.ConfigLocalityAttestor)
	if !ok {
		return productionRunPolicy{}, reviewCompositionFailure(domain.FailureInternal, "config locality attestor unavailable", nil)
	}
	if _, err := os.Lstat(filepath.Join(root.String(), ".git")); os.IsNotExist(err) {
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
	inspector         ports.EnvironmentInspector
	config            adapterconfig.Config
	policyIdentities  map[reviewrun.Family]string
	agyPermissionMode string
	source            *adapterconfig.LocalConfigSource
	attestor          ports.ConfigLocalityAttestor
	staticRequest     ports.ConfigLocalityRequest
	staticContext     ports.ConfigLocalityContext
}

func (source *configuredProductionCandidateSource) BindQualifiedRunContext(ctx context.Context, captured reviewrun.CapturedRunInput) (context.Context, error) {
	if source == nil || ctx == nil || source.source == nil || source.attestor == nil || !captured.Input().Target().Valid() {
		return nil, fmt.Errorf("configured provider locality: invalid request")
	}
	if err := revalidateProductionLocality(ctx, source.source, source.attestor, source.staticRequest, source.staticContext); err != nil {
		return nil, fmt.Errorf("configured provider locality: checkout drift: %w", err)
	}
	data, _, err := source.source.Read()
	if err != nil {
		return nil, fmt.Errorf("configured provider locality: config read: %w", err)
	}
	decoded, err := adapterconfig.Decode(data)
	if err != nil || !reflect.DeepEqual(decoded, source.config) {
		return nil, fmt.Errorf("configured provider locality: admitted config drift")
	}
	proof, err := source.source.Proof()
	if err != nil {
		return nil, fmt.Errorf("configured provider locality: config proof: %w", err)
	}
	target := captured.Input().Target()
	commits := make([]ports.GitObjectID, 0, 2)
	if base, ok := target.BaseObjectID(); ok {
		commits = append(commits, base)
	}
	if head, ok := target.HeadObjectID(); ok {
		commits = append(commits, head)
	}
	request, err := ports.NewConfigLocalityRequest(source.staticRequest.Root(), proof, commits, target.Bytes())
	if err != nil {
		return nil, fmt.Errorf("configured provider locality: target request: %w", err)
	}
	expected, err := source.attestor.Attest(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("configured provider locality: target rejected: %w", err)
	}
	if err := revalidateProductionLocality(ctx, source.source, source.attestor, request, expected); err != nil {
		return nil, fmt.Errorf("configured provider locality: target drift: %w", err)
	}
	binding := reviewLocalityBinding{source: source.source, attestor: source.attestor, request: request, expected: expected}
	return context.WithValue(ctx, reviewLocalityContextKey{}, binding), nil
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

func (source *configuredProductionCandidateSource) NewQualifiedRunCandidates(ctx context.Context, captured reviewrun.CapturedRunInput, selection reviewrun.RunSelection) ([]reviewrun.QualifiedRunCandidate, error) {
	if source == nil || source.inspector == nil || ctx == nil {
		return nil, fmt.Errorf("configured provider discovery unavailable")
	}
	if _, ok := ctx.Value(reviewLocalityContextKey{}).(reviewLocalityBinding); !ok {
		return nil, fmt.Errorf("configured provider target locality unavailable")
	}
	configured := make(map[reviewrun.Family][]string, source.config.Providers.Count())
	if provider := source.config.Providers.Kimi; provider != nil {
		configured[reviewrun.FamilyKimi] = []string{provider.Executable}
	}
	if provider := source.config.Providers.ZCode; provider != nil {
		configured[reviewrun.FamilyZCode] = []string{provider.NodeExecutable, provider.Launcher}
	}
	if provider := source.config.Providers.AGY; provider != nil {
		configured[reviewrun.FamilyAGY] = []string{provider.Executable}
	}
	profiles, err := reviewrun.DiscoverConfiguredProviderProfiles(ctx, source.inspector, configured)
	if err != nil {
		return nil, err
	}
	kimiModel := adapterconfig.DefaultKimiModel
	if provider := source.config.Providers.Kimi; provider != nil {
		kimiModel = provider.Model
	}
	production, err := reviewrun.NewProductionQualifiedRunCandidateSourceWithPolicyIdentitiesAndRuntimeSettings(providercli.RuntimeBuilder{}, profiles, source.policyIdentities, source.agyPermissionMode, kimiModel)
	if err != nil {
		return nil, err
	}
	candidates, err := production.NewQualifiedRunCandidates(ctx, captured, selection)
	if err != nil {
		return nil, err
	}
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
		if reviewrun.Family(assignment.PrimaryProvider) != family && reviewrun.Family(assignment.FallbackProvider) != family {
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

func deriveProductionRunPolicy(resolved appconfig.ResolvedConfig) (productionRunPolicy, error) {
	requestChanges := resolved.RequestChangesOn()
	if len(requestChanges) == 0 {
		return productionRunPolicy{}, reviewCompositionFailure(domain.FailureConfiguration, "production policy has no review threshold", nil)
	}
	defaults := review.DefaultHarnessCeilings()
	timeout, stdout, stderr := defaults.MaxTimeout(), defaults.MaxStdoutBytes(), defaults.MaxStderrBytes()
	ceilings, err := review.NewHarnessCeilings(
		timeout, stdout, stderr, resolved.RunTotalOutputCapBytes(),
		defaults.MaxLaneDeadline(), defaults.MaxRunDeadline(),
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
		fallback, _ := definition.FallbackProvider()
		assignment, err := reviewrun.NewRoleProviderAssignment(role, reviewrun.Family(definition.PrimaryProvider()), reviewrun.Family(fallback))
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
	agyPermissionMode := adapterconfig.DefaultAGYPermissionMode
	if providers := resolved.Providers(); providers.AGY != nil {
		agyPermissionMode = providers.AGY.PermissionMode
	}
	return productionRunPolicy{
		planner: reviewrun.PlannerPolicy{
			Ceilings: ceilings, Threshold: requestChanges[0], Policy: &ci, MaxLanes: resolved.Runtime().MaxActiveLanes, Assignments: assignments, RequiredRoles: resolved.RequiredRoles(),
		},
		requiredRoles:     resolved.RequiredRoles(),
		enabledRoles:      enabled,
		agyPermissionMode: agyPermissionMode,
		config:            resolved.Raw(),
	}, nil
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
