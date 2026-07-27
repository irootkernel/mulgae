//go:build darwin && arm64

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"

	"github.com/irootkernel/kkachi-agent-review/internal/adapters/environment"
	"github.com/irootkernel/kkachi-agent-review/internal/adapters/filesystem"
	"github.com/irootkernel/kkachi-agent-review/internal/adapters/gittarget"
	"github.com/irootkernel/kkachi-agent-review/internal/adapters/lanelock"
	processadapter "github.com/irootkernel/kkachi-agent-review/internal/adapters/process"
	"github.com/irootkernel/kkachi-agent-review/internal/adapters/providercli"
	"github.com/irootkernel/kkachi-agent-review/internal/adapters/reviewinput"
	"github.com/irootkernel/kkachi-agent-review/internal/adapters/workspace"
	"github.com/irootkernel/kkachi-agent-review/internal/app/publication"
	"github.com/irootkernel/kkachi-agent-review/internal/app/review"
	"github.com/irootkernel/kkachi-agent-review/internal/app/reviewrun"
	"github.com/irootkernel/kkachi-agent-review/internal/app/validation"
	"github.com/irootkernel/kkachi-agent-review/internal/builtin"
	"github.com/irootkernel/kkachi-agent-review/internal/domain"
	"github.com/irootkernel/kkachi-agent-review/internal/ports"
)

type productionRuntimeGraph struct {
	build           reviewrun.BuildIdentity
	root            ports.AnchoredRoot
	policy          productionRunPolicy
	workspaceRoot   ports.AnchoredRoot
	namespaceRoot   ports.AnchoredRoot
	detector        ports.ReviewInputContentDetector
	inputs          *reviewinput.Factory
	authority       *reviewrun.RunAuthorityAdapter
	qualified       *reviewrun.QualifiedRunFactory
	candidates      *configuredProductionCandidateSource
	reviewValidator *validation.ReviewValidator
	publisher       *publication.Service
	diagnostics     ports.RuntimeDiagnosticSinkFactory
	locker          ports.LaneLocker
	templates       review.TemplateSet
	clock           ports.Clock
	ids             review.IdentityGenerator
}

func (graph *productionRuntimeGraph) cleanupRoots() error {
	if graph == nil {
		return nil
	}
	if err := cleanupReviewCompositionRoots(true, graph.namespaceRoot, graph.workspaceRoot); err != nil {
		return reviewCompositionFailure(domain.FailureArtifact, "production temporary root cleanup failed", err)
	}
	return nil
}

func composeProductionRuntimeGraph(
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
) (_ *productionRuntimeGraph, err error) {
	if !build.Valid() || ctx == nil || !root.Valid() || catalog == nil || validator == nil || projectReader == nil || clock == nil || ids == nil || writer == nil || publicationStore == nil || stdin == nil {
		return nil, fmt.Errorf("production graph: invalid dependencies")
	}
	installedUser, err := user.Current()
	if err != nil || installedUser == nil || !filepath.IsAbs(installedUser.HomeDir) || filepath.Clean(installedUser.HomeDir) != installedUser.HomeDir {
		return nil, fmt.Errorf("production graph: installed user home")
	}
	installedUID, err := strconv.ParseUint(installedUser.Uid, 10, 32)
	if err != nil || int(installedUID) != os.Geteuid() {
		return nil, fmt.Errorf("production graph: installed user identity")
	}
	policy, err := resolveProductionRunPolicy(ctx, root, projectReader)
	if err != nil {
		return nil, err
	}
	if policy.config.NativeUser.Home != installedUser.HomeDir {
		return nil, reviewCompositionFailure(domain.FailureSecurityPolicy, "configured native home does not match installed user", nil)
	}
	tempRoot, err := startupTempRoot()
	if err != nil {
		return nil, fmt.Errorf("production graph: startup temp root: %w", err)
	}
	workspaceRoot, err := privateReviewRoot(tempRoot, reviewWorkspacePrefix)
	if err != nil {
		return nil, err
	}
	namespaceRoot, err := privateReviewRoot(tempRoot, reviewNamespacePrefix)
	if err != nil {
		cleanupErr := cleanupReviewCompositionRoots(true, ports.AnchoredRoot{}, workspaceRoot)
		if cleanupErr != nil {
			cleanupErr = reviewCompositionFailure(domain.FailureArtifact, "production temporary root cleanup failed", cleanupErr)
		}
		return nil, errors.Join(err, cleanupErr)
	}
	graph := &productionRuntimeGraph{build: build, root: root, policy: policy, workspaceRoot: workspaceRoot, namespaceRoot: namespaceRoot, clock: clock, ids: ids}
	defer func() {
		if err != nil {
			err = errors.Join(err, graph.cleanupRoots())
		}
	}()

	policies := make(map[reviewrun.Family]providercli.RuntimeSafetyPolicy, 3)
	for _, item := range []struct {
		family     reviewrun.Family
		credential providercli.CredentialSourceFamily
	}{{reviewrun.FamilyKimi, providercli.CredentialSourceKimi}, {reviewrun.FamilyZCode, providercli.CredentialSourceZCode}, {reviewrun.FamilyAGY, providercli.CredentialSourceAGY}} {
		value, policyErr := providercli.RuntimeSafetyPolicyForFamily(item.credential)
		if policyErr != nil {
			return nil, fmt.Errorf("production graph: %s runtime safety policy: %w", item.family, policyErr)
		}
		policies[item.family] = value
	}
	identities := make(map[reviewrun.Family]string, len(policies))
	for family, value := range policies {
		identities[family] = value.Identity()
	}
	candidates := &configuredProductionCandidateSource{
		inspector: environment.NewInspector(), config: policy.config, policyIdentities: identities,
		agyPermissionMode: policy.agyPermissionMode, source: policy.source, attestor: policy.attestor,
		staticRequest: policy.localityRequest, staticContext: policy.locality,
	}
	detector := filesystem.NewContentDetector()
	materializer, err := workspace.NewMaterializer(workspaceRoot, detector)
	if err != nil {
		return nil, fmt.Errorf("production graph: workspace materializer: %w", err)
	}
	capturer, err := gittarget.NewReviewTargetCapturer(gittarget.NewExecRunner(), stdin, detector)
	if err != nil {
		return nil, fmt.Errorf("production graph: target capturer: %w", err)
	}
	inputs, err := reviewinput.NewImmutableInputSourceFactory(capturer, detector, materializer)
	if err != nil {
		return nil, fmt.Errorf("production graph: input source: %w", err)
	}
	runner, err := processadapter.NewRunner(clock)
	if err != nil {
		return nil, fmt.Errorf("production graph: process runner: %w", err)
	}
	namespaces, err := providercli.NewNamespaceFactory(namespaceRoot.String())
	if err != nil {
		return nil, fmt.Errorf("production graph: namespaces: %w", err)
	}
	instanceFamilies := make(map[string]providercli.CredentialSourceFamily)
	instancePolicies := make(map[string]providercli.RuntimeSafetyPolicy)
	nativeHomes := make(map[string]string)
	sourceRoots := make(map[string]string)
	configuredRoles := policy.config.Roles.Ordered()
	for index, role := range domain.FixedRoleOrder() {
		configured := configuredRoles[index]
		if !configured.Enabled {
			continue
		}
		families := []string{configured.PrimaryProvider}
		if configured.FallbackProvider != "" {
			families = append(families, configured.FallbackProvider)
		}
		for _, familyName := range families {
			family := reviewrun.Family(familyName)
			instance := familyName + "-" + string(role)
			switch family {
			case reviewrun.FamilyKimi:
				provider := policy.config.Providers.Kimi
				instanceFamilies[instance], instancePolicies[instance], sourceRoots[instance] = providercli.CredentialSourceKimi, policies[family], provider.DataHome
			case reviewrun.FamilyZCode:
				instanceFamilies[instance], instancePolicies[instance] = providercli.CredentialSourceZCode, policies[family]
			case reviewrun.FamilyAGY:
				instanceFamilies[instance], instancePolicies[instance], nativeHomes[instance] = providercli.CredentialSourceAGY, policies[family], installedUser.HomeDir
			default:
				return nil, fmt.Errorf("production graph: invalid configured provider family %q", familyName)
			}
		}
	}
	projected, err := providercli.NewCredentialProjectingNamespaceFactoryWithConfiguredSourceRoots(namespaces, installedUser.HomeDir, instanceFamilies, instancePolicies, nativeHomes, sourceRoots)
	if err != nil {
		return nil, fmt.Errorf("production graph: credential namespaces: %w", err)
	}
	fixtures, err := providercli.NewProbeFixtureLeaseFactory(materializer, providercli.SecureProbeNonceGenerator{})
	if err != nil {
		return nil, fmt.Errorf("production graph: probe fixtures: %w", err)
	}
	baseSpawnVerifier := environment.NewSpawnVerifier()
	probe, err := providercli.NewCurrentProbe(runner, contextLocalitySpawnVerifier{inner: baseSpawnVerifier})
	if err != nil {
		return nil, fmt.Errorf("production graph: current probe: %w", err)
	}
	probePort, err := providercli.NewQualificationProbeAdapter(probe, providercli.NativeProbeInvocation{})
	if err != nil {
		return nil, fmt.Errorf("production graph: probe adapter: %w", err)
	}
	fixturePort, err := providercli.NewQualificationFixtureFactoryAdapter(fixtures)
	if err != nil {
		return nil, fmt.Errorf("production graph: fixture adapter: %w", err)
	}
	current, err := reviewrun.NewProviderCurrentQualifier(probePort, fixturePort)
	if err != nil {
		return nil, fmt.Errorf("production graph: qualifier: %w", err)
	}
	registries, err := providercli.NewQualificationRegistryFactory(runner, projected, nil, func(ctx context.Context) (providercli.SpawnVerifier, error) {
		return boundLocalitySpawnVerifier(ctx, baseSpawnVerifier)
	})
	if err != nil {
		return nil, fmt.Errorf("production graph: registry factory: %w", err)
	}
	var qualified *reviewrun.QualifiedRunFactory
	if provider := policy.config.Providers.Kimi; provider != nil {
		login, loginErr := providercli.NewKimiLoginAuthenticator(runner, baseSpawnVerifier, installedUser.HomeDir, provider.DataHome)
		if loginErr != nil {
			return nil, fmt.Errorf("production graph: Kimi login authenticator: %w", loginErr)
		}
		qualified, err = reviewrun.NewQualifiedRunFactoryWithLoginAuthenticator(current, registries, clock, login)
	} else {
		qualified, err = reviewrun.NewQualifiedRunFactory(current, registries, clock)
	}
	if err != nil {
		return nil, fmt.Errorf("production graph: qualified run factory: %w", err)
	}
	authority, err := reviewrun.NewRunAuthorityAdapter(qualified, candidates, policy.planner, build)
	if err != nil {
		return nil, fmt.Errorf("production graph: run authority: %w", err)
	}
	reviewSchema, err := ports.ParseAssetID(validation.ProviderReviewSchemaID)
	if err != nil {
		return nil, err
	}
	reviewValidator, err := validation.NewReviewValidator(validator, reviewSchema)
	if err != nil {
		return nil, fmt.Errorf("production graph: review validator: %w", err)
	}
	publisher, err := publication.NewService(publicationStore, validator, clock, 8<<20)
	if err != nil {
		return nil, fmt.Errorf("production graph: publisher: %w", err)
	}
	diagnostics, err := filesystem.NewDiagnosticStoreFactory(writer, clock)
	if err != nil {
		return nil, fmt.Errorf("production graph: diagnostics: %w", err)
	}
	locker, err := lanelock.New(root, writer)
	if err != nil {
		return nil, fmt.Errorf("production graph: lane locker: %w", err)
	}
	templates, err := reviewrun.LoadDefaultTemplateSet(ctx, catalog)
	if err != nil {
		return nil, fmt.Errorf("production graph: templates: %w", err)
	}
	graph.detector, graph.inputs, graph.authority, graph.qualified, graph.candidates, graph.reviewValidator = detector, inputs, authority, qualified, candidates, reviewValidator
	graph.publisher, graph.diagnostics, graph.locker, graph.templates = publisher, diagnostics, locker, templates
	return graph, nil
}

func (graph *productionRuntimeGraph) sourceBoundAuthority(role domain.Role, providerInstance string) (*reviewrun.RunAuthorityAdapter, error) {
	if graph == nil || graph.qualified == nil || graph.candidates == nil || !role.Valid() {
		return nil, fmt.Errorf("production graph: source-bound authority is unavailable")
	}
	family := reviewrun.Family("")
	for _, candidate := range []reviewrun.Family{reviewrun.FamilyKimi, reviewrun.FamilyZCode, reviewrun.FamilyAGY} {
		current := string(candidate) + "-" + string(role)
		if providerInstance == current || legacyProviderInstanceFamily(providerInstance) == candidate {
			family = candidate
			break
		}
	}
	if !family.Valid() || !graph.policy.config.Providers.HasFamily(string(family)) {
		return nil, fmt.Errorf("production graph: source provider %q is not currently configured", providerInstance)
	}
	policy := graph.policy.planner
	policy.Assignments = nil
	for _, configuredRole := range reviewrun.SupportedProductionRoles(family) {
		assignment, err := reviewrun.NewRoleProviderAssignment(configuredRole, family, "")
		if err != nil {
			return nil, err
		}
		policy.Assignments = append(policy.Assignments, assignment)
	}
	return reviewrun.NewRunAuthorityAdapter(graph.qualified, graph.candidates, policy, graph.build)
}

func legacyProviderInstanceFamily(instance string) reviewrun.Family {
	switch instance {
	case "kimi-default":
		return reviewrun.FamilyKimi
	case "zcode-default", "zcode-secondary", "zcode-third", "zcode-fourth":
		return reviewrun.FamilyZCode
	case "agy-default":
		return reviewrun.FamilyAGY
	default:
		return ""
	}
}
