//go:build darwin && arm64

package composition

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/irootkernel/mulgae/internal/adapters/environment"
	"github.com/irootkernel/mulgae/internal/adapters/filesystem"
	processadapter "github.com/irootkernel/mulgae/internal/adapters/process"
	"github.com/irootkernel/mulgae/internal/adapters/providercli"
	"github.com/irootkernel/mulgae/internal/adapters/workspace"
	"github.com/irootkernel/mulgae/internal/app/prompt"
	"github.com/irootkernel/mulgae/internal/app/publication"
	"github.com/irootkernel/mulgae/internal/app/review"
	"github.com/irootkernel/mulgae/internal/app/reviewrun"
	"github.com/irootkernel/mulgae/internal/app/validation"
	"github.com/irootkernel/mulgae/internal/builtin"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

type productionRuntimeGraph struct {
	build           reviewrun.BuildIdentity
	root            ports.AnchoredRoot
	policy          productionRunPolicy
	workspaceRoot   ports.AnchoredRoot
	namespaceRoot   ports.AnchoredRoot
	detector        ports.ReviewInputContentDetector
	liveSources     ports.LiveSourceOpener
	reviewerHome    ports.ReviewerHome
	credentialRoots []ports.AnchoredRoot
	liveCommon      prompt.TrustedLayer
	authority       *reviewrun.RunAuthorityAdapter
	qualified       *reviewrun.QualifiedRunFactory
	candidates      *configuredProductionCandidateSource
	fixtures        *providercli.ProbeFixtureLeaseFactory
	reviewValidator *validation.ReviewValidator
	publisher       *publication.Service
	diagnostics     ports.RuntimeDiagnosticSinkFactory
	templates       review.TemplateSet
	clock           ports.Clock
	ids             review.IdentityGenerator
}

func (graph *productionRuntimeGraph) cleanupRoots() error {
	if graph == nil {
		return nil
	}
	var homeErr error
	if graph.reviewerHome != nil {
		homeErr = graph.reviewerHome.Close()
		graph.reviewerHome = nil
	}
	if err := errors.Join(homeErr, cleanupReviewCompositionRoots(true, graph.namespaceRoot, graph.workspaceRoot)); err != nil {
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
) (_ *productionRuntimeGraph, err error) {
	if !build.Valid() || ctx == nil || !root.Valid() || catalog == nil || validator == nil || projectReader == nil || clock == nil || ids == nil || writer == nil || publicationStore == nil {
		return nil, fmt.Errorf("production graph: invalid dependencies")
	}
	if err := ports.ValidateResourceLimits(); err != nil {
		return nil, fmt.Errorf("production graph: %w", err)
	}
	installedUser, err := environment.InstalledUser()
	if err != nil || installedUser == nil || !filepath.IsAbs(installedUser.HomeDir) || filepath.Clean(installedUser.HomeDir) != installedUser.HomeDir {
		return nil, fmt.Errorf("production graph: installed user home")
	}
	installedUID, err := strconv.ParseUint(installedUser.Uid, 10, 32)
	if err != nil || int(installedUID) != os.Geteuid() {
		return nil, fmt.Errorf("production graph: installed user identity")
	}
	nativeHome := installedUser.HomeDir
	policy, err := resolveProductionRunPolicy(ctx, root, projectReader)
	if err != nil {
		return nil, err
	}
	if policy.config.NativeUser.Home != nativeHome {
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
	policies := make(map[reviewrun.Family]providercli.RuntimeSafetyPolicy, len(reviewrun.Families()))
	for _, item := range []struct {
		family     reviewrun.Family
		credential providercli.CredentialSourceFamily
	}{{reviewrun.FamilyZCode, providercli.CredentialSourceZCode}, {reviewrun.FamilyGrok, providercli.CredentialSourceGrok}, {reviewrun.FamilyCodex, providercli.CredentialSourceCodex}} {
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
		providerTimeouts: cloneProviderTimeouts(policy.providerTimeouts), source: policy.source, attestor: policy.attestor,
		staticRequest: policy.localityRequest, staticContext: policy.locality,
	}
	detector := filesystem.NewContentDetector()
	materializer, err := workspace.NewMaterializer(workspaceRoot, detector)
	if err != nil {
		return nil, fmt.Errorf("production graph: workspace materializer: %w", err)
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
		familyName := configured.PrimaryProvider
		family := reviewrun.Family(familyName)
		instance := familyName + "-" + string(role)
		credentialProfile := ""
		if family == reviewrun.FamilyCodex && policy.config.Providers.Codex != nil && policy.config.Providers.Codex.DefaultCredentialProfile != "" {
			credentialProfile = configured.CredentialProfile
			if credentialProfile == "" {
				credentialProfile = policy.config.Providers.Codex.DefaultCredentialProfile
			}
			instance = familyName + "-" + credentialProfile + "-" + string(role)
		}
		switch family {
		case reviewrun.FamilyZCode:
			instanceFamilies[instance], instancePolicies[instance] = providercli.CredentialSourceZCode, policies[family]
		case reviewrun.FamilyGrok:
			instanceFamilies[instance], instancePolicies[instance] = providercli.CredentialSourceGrok, policies[family]
		case reviewrun.FamilyCodex:
			instanceFamilies[instance], instancePolicies[instance] = providercli.CredentialSourceCodex, policies[family]
			if credentialProfile != "" {
				sourceRoots[instance], _ = policy.config.Providers.Codex.CredentialHome(credentialProfile)
			}
		default:
			return nil, fmt.Errorf("production graph: invalid configured provider family %q", familyName)
		}
	}
	projected, err := providercli.NewCredentialProjectingNamespaceFactoryWithProjectRoot(namespaces, nativeHome, root.String(), instanceFamilies, instancePolicies, nativeHomes, sourceRoots)
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
	qualified, err := reviewrun.NewQualifiedRunFactory(current, registries, clock)
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
	publisher, err := publication.NewService(publicationStore, validator, clock, ports.PublicationStructuredMemberMaxBytes)
	if err != nil {
		return nil, fmt.Errorf("production graph: publisher: %w", err)
	}
	diagnostics, err := filesystem.NewDiagnosticStoreFactory(writer, clock)
	if err != nil {
		return nil, fmt.Errorf("production graph: diagnostics: %w", err)
	}
	templates, err := reviewrun.LoadDefaultTemplateSet(ctx, catalog)
	if err != nil {
		return nil, fmt.Errorf("production graph: templates: %w", err)
	}
	graph.detector, graph.authority, graph.qualified, graph.candidates, graph.fixtures, graph.reviewValidator = detector, authority, qualified, candidates, fixtures, reviewValidator
	graph.publisher, graph.diagnostics, graph.templates = publisher, diagnostics, templates
	return graph, nil
}

func (graph *productionRuntimeGraph) openLiveReview(ctx context.Context, catalog ports.ContractCatalog) error {
	guide, err := reviewrun.LoadDefaultReviewerGuide(ctx, catalog)
	if err != nil {
		return err
	}
	operatorHome, err := ports.NewAnchoredRoot(graph.policy.config.NativeUser.Home)
	if err != nil {
		return err
	}
	graph.reviewerHome, err = providercli.OpenReviewerHome(operatorHome, guide)
	if err != nil {
		return reviewCompositionFailure(domain.FailureSecurityPolicy, "neutral reviewer home unavailable", err)
	}
	graph.liveSources, graph.credentialRoots, err = productionLiveSources(graph.policy.config, graph.root, graph.workspaceRoot, graph.namespaceRoot)
	if err != nil {
		return err
	}
	graph.liveCommon, err = reviewrun.LoadLiveReviewCommon(ctx, catalog)
	return err
}
