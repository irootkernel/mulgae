//go:build darwin && arm64

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"reflect"
	"strconv"

	adapterconfig "github.com/irootkernel/kkachi-agent-review/internal/adapters/config"
	"github.com/irootkernel/kkachi-agent-review/internal/adapters/environment"
	"github.com/irootkernel/kkachi-agent-review/internal/adapters/filesystem"
	"github.com/irootkernel/kkachi-agent-review/internal/adapters/gittarget"
	"github.com/irootkernel/kkachi-agent-review/internal/adapters/lanelock"
	processadapter "github.com/irootkernel/kkachi-agent-review/internal/adapters/process"
	"github.com/irootkernel/kkachi-agent-review/internal/adapters/providercli"
	"github.com/irootkernel/kkachi-agent-review/internal/adapters/reviewinput"
	"github.com/irootkernel/kkachi-agent-review/internal/adapters/workspace"
	appconfig "github.com/irootkernel/kkachi-agent-review/internal/app/config"
	"github.com/irootkernel/kkachi-agent-review/internal/app/publication"
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

	installedUser, err := user.Current()
	if err != nil || installedUser == nil || !filepath.IsAbs(installedUser.HomeDir) || filepath.Clean(installedUser.HomeDir) != installedUser.HomeDir {
		return nil, fmt.Errorf("review composition: installed user home")
	}
	installedUID, err := strconv.ParseUint(installedUser.Uid, 10, 32)
	if err != nil || int(installedUID) != os.Geteuid() {
		return nil, fmt.Errorf("review composition: installed user identity")
	}
	home := installedUser.HomeDir
	tempRoot, err := startupTempRoot()
	if err != nil {
		return nil, fmt.Errorf("review composition: startup temp root: %w", err)
	}
	productionPolicy, err := resolveProductionRunPolicy(ctx, root, projectReader)
	if err != nil {
		return nil, err
	}
	if productionPolicy.config.NativeUser.Home != installedUser.HomeDir {
		return nil, reviewCompositionFailure(domain.FailureSecurityPolicy, "configured native home does not match installed user", nil)
	}
	nativeHomes := make(map[string]string)
	inspector := environment.NewInspector()
	workspaceRoot, err := privateReviewRoot(tempRoot, reviewWorkspacePrefix)
	if err != nil {
		return nil, err
	}
	policies := map[reviewrun.Family]providercli.RuntimeSafetyPolicy{}
	for _, family := range []struct {
		reviewFamily     reviewrun.Family
		credentialFamily providercli.CredentialSourceFamily
	}{
		{reviewrun.FamilyKimi, providercli.CredentialSourceKimi},
		{reviewrun.FamilyZCode, providercli.CredentialSourceZCode},
	} {
		policy, err := providercli.RuntimeSafetyPolicyForFamily(family.credentialFamily)
		if err != nil {
			_ = os.RemoveAll(workspaceRoot.String())
			return nil, fmt.Errorf("review composition: %s runtime safety policy: %w", family.reviewFamily, err)
		}
		policies[family.reviewFamily] = policy
	}
	agyPolicy, err := providercli.RuntimeSafetyPolicyForFamily(providercli.CredentialSourceAGY)
	if err != nil {
		_ = os.RemoveAll(workspaceRoot.String())
		return nil, fmt.Errorf("review composition: AGY runtime safety policy: %w", err)
	}
	policies[reviewrun.FamilyAGY] = agyPolicy
	policyIdentities := make(map[reviewrun.Family]string, len(policies))
	for family, policy := range policies {
		policyIdentities[family] = policy.Identity()
	}
	candidates := &configuredProductionCandidateSource{
		inspector: inspector, config: productionPolicy.config,
		policyIdentities: policyIdentities, agyPermissionMode: productionPolicy.agyPermissionMode,
		source: productionPolicy.source, attestor: productionPolicy.attestor,
		staticRequest: productionPolicy.localityRequest, staticContext: productionPolicy.locality,
	}

	namespaceRoot, err := privateReviewRoot(tempRoot, reviewNamespacePrefix)
	if err != nil {
		_ = os.RemoveAll(workspaceRoot.String())
		return nil, err
	}
	cleanupRoots := true
	defer func() {
		cleanupReviewCompositionRoots(cleanupRoots, namespaceRoot, workspaceRoot)
	}()

	detector := filesystem.NewContentDetector()
	materializer, err := workspace.NewMaterializer(workspaceRoot, detector)
	if err != nil {
		return nil, fmt.Errorf("review composition: workspace materializer: %w", err)
	}
	capturer, err := gittarget.NewReviewTargetCapturer(gittarget.NewExecRunner(), stdin, detector)
	if err != nil {
		return nil, fmt.Errorf("review composition: review target capturer: %w", err)
	}
	inputs, err := reviewinput.NewImmutableInputSourceFactory(capturer, detector, materializer)
	if err != nil {
		return nil, fmt.Errorf("review composition: immutable input source factory: %w", err)
	}
	runner, err := processadapter.NewRunner(clock)
	if err != nil {
		return nil, fmt.Errorf("review composition: process runner: %w", err)
	}
	namespaces, err := providercli.NewNamespaceFactory(namespaceRoot.String())
	if err != nil {
		return nil, fmt.Errorf("review composition: provider namespaces: %w", err)
	}
	instanceFamilies := make(map[string]providercli.CredentialSourceFamily)
	instancePolicies := make(map[string]providercli.RuntimeSafetyPolicy)
	sourceRoots := make(map[string]string)
	if provider := productionPolicy.config.Providers.Kimi; provider != nil {
		instanceFamilies["kimi-default"] = providercli.CredentialSourceKimi
		instancePolicies["kimi-default"] = policies[reviewrun.FamilyKimi]
		sourceRoots["kimi-default"] = provider.DataHome
	}
	if productionPolicy.config.Providers.ZCode != nil {
		instanceFamilies["zcode-default"] = providercli.CredentialSourceZCode
		instancePolicies["zcode-default"] = policies[reviewrun.FamilyZCode]
	}
	if productionPolicy.config.Providers.AGY != nil {
		instanceFamilies["agy-default"] = providercli.CredentialSourceAGY
		instancePolicies["agy-default"] = policies[reviewrun.FamilyAGY]
		nativeHomes["agy-default"] = installedUser.HomeDir
	}
	projectedNamespaces, err := providercli.NewCredentialProjectingNamespaceFactoryWithConfiguredSourceRoots(namespaces, home, instanceFamilies, instancePolicies, nativeHomes, sourceRoots)
	if err != nil {
		return nil, fmt.Errorf("review composition: credential namespaces: %w", err)
	}
	fixtures, err := providercli.NewProbeFixtureLeaseFactory(materializer, providercli.SecureProbeNonceGenerator{})
	if err != nil {
		return nil, fmt.Errorf("review composition: probe fixtures: %w", err)
	}
	baseSpawnVerifier := environment.NewSpawnVerifier()
	probeVerifier := contextLocalitySpawnVerifier{inner: baseSpawnVerifier}
	probe, err := providercli.NewCurrentProbe(runner, probeVerifier)
	if err != nil {
		return nil, fmt.Errorf("review composition: current probe: %w", err)
	}
	probePort, err := providercli.NewQualificationProbeAdapter(probe, providercli.NativeProbeInvocation{})
	if err != nil {
		return nil, fmt.Errorf("review composition: current probe adapter: %w", err)
	}
	fixturePort, err := providercli.NewQualificationFixtureFactoryAdapter(fixtures)
	if err != nil {
		return nil, fmt.Errorf("review composition: qualification fixture adapter: %w", err)
	}
	current, err := reviewrun.NewProviderCurrentQualifier(probePort, fixturePort)
	if err != nil {
		return nil, fmt.Errorf("review composition: current qualifier: %w", err)
	}
	registries, err := providercli.NewQualificationRegistryFactory(
		runner, projectedNamespaces, nil,
		func(ctx context.Context) (providercli.SpawnVerifier, error) {
			return boundLocalitySpawnVerifier(ctx, baseSpawnVerifier)
		},
	)
	if err != nil {
		return nil, fmt.Errorf("review composition: qualification registry factory: %w", err)
	}
	qualified, err := reviewrun.NewQualifiedRunFactory(current, registries, clock)
	if err != nil {
		return nil, fmt.Errorf("review composition: qualified run factory: %w", err)
	}
	authority, err := reviewrun.NewRunAuthorityAdapter(
		// The planner receives the one immutable B→G→P reduction rather than
		// independently selected defaults.
		qualified, candidates, productionPolicy.planner, build,
	)
	if err != nil {
		return nil, fmt.Errorf("review composition: run authority: %w", err)
	}
	reviewSchema, err := ports.ParseAssetID(validation.ProviderReviewSchemaID)
	if err != nil {
		return nil, fmt.Errorf("review composition: review schema ID: %w", err)
	}
	reviewValidator, err := validation.NewReviewValidator(validator, reviewSchema)
	if err != nil {
		return nil, fmt.Errorf("review composition: review validator: %w", err)
	}
	publisher, err := publication.NewService(publicationStore, validator, clock, 8<<20)
	if err != nil {
		return nil, fmt.Errorf("review composition: publication service: %w", err)
	}
	locker, err := lanelock.New(root, writer)
	if err != nil {
		return nil, fmt.Errorf("review composition: lane locker: %w", err)
	}
	templates, err := reviewrun.LoadDefaultTemplateSet(ctx, catalog)
	if err != nil {
		return nil, fmt.Errorf("review composition: templates: %w", err)
	}
	service, err := reviewrun.NewService(reviewrun.Dependencies{
		Clock: clock, IDs: ids, Build: build, RunAuthorityFactory: authority, Validator: reviewValidator, Locker: locker, Publication: publisher, Templates: templates,
	})
	if err != nil {
		return nil, fmt.Errorf("review composition: service: %w", err)
	}
	reviewService := kar.NewPolicyReviewRunService(kar.NewReviewRunService(service, inputs), productionPolicy.requiredRoles, productionPolicy.enabledRoles)
	cleanupRoots = false
	return reviewService, nil
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
	return production.NewQualifiedRunCandidates(ctx, captured, selection)
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
	for _, role := range domain.FixedRoleOrder() {
		definition, present := resolved.Role(role)
		if !present {
			return productionRunPolicy{}, reviewCompositionFailure(domain.FailureConfiguration, "production role policy is incomplete", nil)
		}
		enabled[role] = definition.Enabled()
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
			Ceilings: ceilings, Threshold: requestChanges[0], Policy: &ci, MaxLanes: resolved.Runtime().MaxActiveLanes,
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
