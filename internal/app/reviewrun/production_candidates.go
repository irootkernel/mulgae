package reviewrun

import (
	"context"
	"fmt"
	"reflect"
	"time"

	"github.com/irootkernel/mulgae/internal/app/review"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

const (
	productionProfileGeneration            = "reviewrun-production-candidates-v1"
	productionWorkingDirectory             = "/private/var/empty"
	productionDefaultProviderTimeout       = 15 * time.Minute
	productionMinimumProviderTimeout       = time.Minute
	productionMaximumProviderTimeout       = 60 * time.Minute
	productionOutputCap              int64 = 256 << 10
)

type productionCandidateTemplate struct {
	family                      Family
	instance                    string
	profileID                   string
	runtimeSafetyPolicyIdentity string
	baseArgv                    []string
	environment                 []ports.EnvironmentVariable
	transportChannel            ports.ProviderPacketChannel
	transportArgvIndex          int
	transportReference          string
	concurrencyKey              ports.ConcurrencyKey
	limits                      review.InvocationLimits
	lifecycle                   *ports.BoundedPostOutputLifecycle
	kimiModel                   string
	supportedRoles              []domain.Role
}

// ProductionQualifiedRunCandidateSource binds startup-frozen identity-only
// discovery to the fixed production runtime templates. It has no process,
// credential, environment, or configuration authority.
type ProductionQualifiedRunCandidateSource struct {
	profiles               []DiscoveredProviderProfile
	frozenProfiles         []DiscoveredProviderProfile
	policyIdentities       map[Family]string
	frozenPolicyIdentities map[Family]string
	templates              []productionCandidateTemplate
	builder                ports.ProviderRuntimeBuilder
}

// NewProductionQualifiedRunCandidateSource constructs the production candidate
// source from the identity-only profiles captured at startup. Profiles are
// retained by value; their caller-owned argv slices are cloned.
func NewProductionQualifiedRunCandidateSource(builder ports.ProviderRuntimeBuilder, profiles []DiscoveredProviderProfile) (*ProductionQualifiedRunCandidateSource, error) {
	identities, err := defaultProductionPolicyIdentities(builder)
	if err != nil {
		return nil, fmt.Errorf("review run: default production policy identities: %w", err)
	}
	return NewProductionQualifiedRunCandidateSourceWithPolicyIdentities(builder, profiles, identities)
}

// NewProductionQualifiedRunCandidateSourceWithPolicyIdentities constructs the
// production candidate source using the exact policies installed into provider
// credential namespaces for this composition.
func NewProductionQualifiedRunCandidateSourceWithPolicyIdentities(builder ports.ProviderRuntimeBuilder, profiles []DiscoveredProviderProfile, identities map[Family]string) (*ProductionQualifiedRunCandidateSource, error) {
	return NewProductionQualifiedRunCandidateSourceWithPolicyIdentitiesAndAGYPermissionMode(builder, profiles, identities, "safe")
}

func NewProductionQualifiedRunCandidateSourceWithPolicyIdentitiesAndAGYPermissionMode(builder ports.ProviderRuntimeBuilder, profiles []DiscoveredProviderProfile, identities map[Family]string, agyPermissionMode string) (*ProductionQualifiedRunCandidateSource, error) {
	return NewProductionQualifiedRunCandidateSourceWithPolicyIdentitiesAndRuntimeSettings(builder, profiles, identities, agyPermissionMode, "kimi-code/kimi-for-coding")
}

// NewProductionQualifiedRunCandidateSourceWithPolicyIdentitiesAndRuntimeSettings
// binds operator-admitted family settings to every probe and production
// invocation. Kimi's model is explicit here; callers pass the canonical
// default only when the configuration omitted the field.
func NewProductionQualifiedRunCandidateSourceWithPolicyIdentitiesAndRuntimeSettings(builder ports.ProviderRuntimeBuilder, profiles []DiscoveredProviderProfile, identities map[Family]string, agyPermissionMode, kimiModel string) (*ProductionQualifiedRunCandidateSource, error) {
	return NewProductionQualifiedRunCandidateSourceWithPolicyIdentitiesAndRuntimeSettingsAndTimeouts(
		builder, profiles, identities, agyPermissionMode, kimiModel, defaultProductionProviderTimeouts(),
	)
}

// NewProductionQualifiedRunCandidateSourceWithPolicyIdentitiesAndRuntimeSettingsAndTimeouts
// binds a complete family timeout policy to every role-specific production
// candidate and its adapter-built runtime definition.
func NewProductionQualifiedRunCandidateSourceWithPolicyIdentitiesAndRuntimeSettingsAndTimeouts(builder ports.ProviderRuntimeBuilder, profiles []DiscoveredProviderProfile, identities map[Family]string, agyPermissionMode, kimiModel string, providerTimeouts map[Family]time.Duration) (*ProductionQualifiedRunCandidateSource, error) {
	if nilInterface(builder) {
		return nil, fmt.Errorf("review run: provider runtime builder is required")
	}
	if err := validateProductionPolicyIdentities(identities); err != nil {
		return nil, fmt.Errorf("review run: invalid production policy identities: %w", err)
	}
	templates, err := productionCandidateTemplatesWithRuntimeSettingsAndTimeouts(identities, agyPermissionMode, kimiModel, providerTimeouts)
	if err != nil {
		return nil, fmt.Errorf("review run: construct production candidate templates: %w", err)
	}
	cloned := cloneDiscoveredProviderProfiles(profiles)
	if err := validateStartupProfiles(cloned); err != nil {
		return nil, err
	}
	clonedIdentities := cloneProductionPolicyIdentities(identities)
	return &ProductionQualifiedRunCandidateSource{
		profiles: cloned, frozenProfiles: cloneDiscoveredProviderProfiles(cloned),
		policyIdentities: clonedIdentities, frozenPolicyIdentities: cloneProductionPolicyIdentities(clonedIdentities),
		templates: templates, builder: builder,
	}, nil
}

// NewQualifiedRunCandidates creates candidate descriptions only. Current
// version, capability, security, and role authorization remain admission work.
func (source *ProductionQualifiedRunCandidateSource) NewQualifiedRunCandidates(_ context.Context, captured CapturedRunInput, selection RunSelection) ([]QualifiedRunCandidate, error) {
	if source == nil || !selection.Valid() || captured.WorkspaceLease() == nil {
		return nil, fmt.Errorf("review run: invalid production candidate request")
	}
	workspace := captured.WorkspaceLease().WorkspaceSnapshotIdentity()
	if !workspace.Valid() {
		return nil, fmt.Errorf("review run: invalid production candidate workspace")
	}
	if !reflect.DeepEqual(source.profiles, source.frozenProfiles) {
		return nil, fmt.Errorf("review run: startup provider profile drift")
	}
	if err := validateStartupProfiles(source.profiles); err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(source.policyIdentities, source.frozenPolicyIdentities) {
		return nil, fmt.Errorf("review run: startup provider policy identity drift")
	}
	if err := validateProductionCandidateTemplatesWithPolicyIdentities(source.templates, source.policyIdentities); err != nil {
		return nil, fmt.Errorf("review run: invalid production candidate templates: %w", err)
	}
	roles := canonicalSelectedRoles(selection.Roles())
	if len(roles) == 0 {
		return nil, fmt.Errorf("review run: invalid production candidate roles")
	}
	profiles := make(map[Family]DiscoveredProviderProfile, len(source.profiles))
	for _, profile := range source.profiles {
		profiles[profile.Family()] = profile
	}
	candidates := make([]QualifiedRunCandidate, 0, len(source.templates))
	for _, template := range source.templates {
		profile, ok := profiles[template.family]
		if !ok || profileMissingOperationalIdentity(profile) {
			continue
		}
		supportedRoles := intersectCanonicalRoles(roles, template.supportedRoles)
		if len(supportedRoles) == 0 {
			continue
		}
		base := qualificationBaseRole(supportedRoles)
		definition, err := template.definition(source.builder, profile)
		if err != nil {
			return nil, fmt.Errorf("review run: construct %s production candidate: %w", template.family, err)
		}
		candidates = append(candidates, QualifiedRunCandidate{
			Profile:          cloneDiscoveredProviderProfile(profile),
			Definition:       definition,
			SnapshotManifest: workspace.ManifestSHA256(),
			SupportedRoles:   supportedRoles,
			BaseRole:         base,
			Limits:           template.limits,
		})
	}
	if len(candidates) == 0 {
		failure, _ := domain.NewFailure("reviewrun.production_candidates", domain.FailureProviderUnavailable, "no startup-discovered provider is operationally available", nil)
		return nil, failure
	}
	return candidates, nil
}

func (template productionCandidateTemplate) definition(builder ports.ProviderRuntimeBuilder, profile DiscoveredProviderProfile) (ports.ProviderRuntimeDefinition, error) {
	baseArgv := append([]string{profile.Executable()}, template.baseArgv...)
	if template.family == FamilyZCode {
		baseArgv = []string{profile.Executable(), profile.Launcher()}
		baseArgv = append(baseArgv, template.baseArgv...)
	}
	if nilInterface(builder) {
		return nil, fmt.Errorf("provider runtime builder is required")
	}
	var lifecycle ports.BoundedPostOutputLifecycle
	hasLifecycle := template.lifecycle != nil
	if hasLifecycle {
		lifecycle = *template.lifecycle
	}
	return builder.BuildProductionRuntime(ports.ProviderRuntimeSpec{
		Family: string(template.family), Instance: template.instance, Executable: profile.Executable(), ExecutableSHA256: profile.SHA256(),
		Launcher: profile.Launcher(), LauncherSHA256: profile.LauncherSHA256(), ConcurrencyKey: template.concurrencyKey,
		ProfileID: template.profileID, ProfileGeneration: productionProfileGeneration, RuntimeSafetyPolicyIdentity: template.runtimeSafetyPolicyIdentity,
		KimiModel: template.kimiModel, BaseArgv: baseArgv, TransportChannel: template.transportChannel,
		TransportArgvIndex: template.transportArgvIndex, TransportReference: template.transportReference,
		Environment: append([]ports.EnvironmentVariable(nil), template.environment...), WorkingDirectory: productionWorkingDirectory,
		Timeout: template.limits.Timeout(), MaxStdoutBytes: template.limits.MaxStdoutBytes(), MaxStderrBytes: template.limits.MaxStderrBytes(),
		PostOutputLifecycle: lifecycle, HasPostOutputLifecycle: hasLifecycle,
	})
}

func trustedProductionCandidateTemplates(builder ports.ProviderRuntimeBuilder) ([]productionCandidateTemplate, error) {
	identities, err := defaultProductionPolicyIdentities(builder)
	if err != nil {
		return nil, err
	}
	return productionCandidateTemplates(identities)
}

func defaultProductionPolicyIdentities(builder ports.ProviderRuntimeBuilder) (map[Family]string, error) {
	if nilInterface(builder) {
		return nil, fmt.Errorf("provider runtime builder is required")
	}
	identities := make(map[Family]string, len(Families()))
	for _, family := range Families() {
		identity, err := builder.RuntimeSafetyPolicyIdentity(string(family))
		if err != nil {
			return nil, err
		}
		identities[family] = identity
	}
	return identities, nil
}

func productionCandidateTemplates(identities map[Family]string) ([]productionCandidateTemplate, error) {
	return productionCandidateTemplatesWithAGYPermissionMode(identities, "safe")
}

func productionCandidateTemplatesWithAGYPermissionMode(identities map[Family]string, agyPermissionMode string) ([]productionCandidateTemplate, error) {
	return productionCandidateTemplatesWithRuntimeSettings(identities, agyPermissionMode, "kimi-code/kimi-for-coding")
}

func productionCandidateTemplatesWithRuntimeSettings(identities map[Family]string, agyPermissionMode, kimiModel string) ([]productionCandidateTemplate, error) {
	return productionCandidateTemplatesWithRuntimeSettingsAndTimeouts(identities, agyPermissionMode, kimiModel, defaultProductionProviderTimeouts())
}

func productionCandidateTemplatesWithRuntimeSettingsAndTimeouts(identities map[Family]string, agyPermissionMode, kimiModel string, providerTimeouts map[Family]time.Duration) ([]productionCandidateTemplate, error) {
	if err := validateProductionPolicyIdentities(identities); err != nil {
		return nil, err
	}
	if err := validateProductionProviderTimeouts(providerTimeouts); err != nil {
		return nil, err
	}
	if agyPermissionMode != "safe" && agyPermissionMode != "dangerously-skip-permissions" {
		return nil, fmt.Errorf("invalid AGY permission mode")
	}
	if kimiModel == "" {
		return nil, fmt.Errorf("invalid Kimi model")
	}
	agyArgvIndex := 12
	if agyPermissionMode == "dangerously-skip-permissions" {
		agyArgvIndex = 13
	}
	lifecycle, err := ports.NewBoundedPostOutputLifecycle(ports.ProcessOutputFramingTerminalJSONObject, time.Second, time.Second)
	if err != nil {
		return nil, err
	}
	agyEnvironment, err := ports.NewEnvironmentVariable("AGY_CLI_DISABLE_AUTO_UPDATE", "true")
	if err != nil {
		return nil, err
	}
	templates := make([]productionCandidateTemplate, 0, len(Families())*len(domain.FixedRoleOrder())-1)
	for _, family := range Families() {
		for _, role := range productionRolesForFamily(family) {
			route, limits, routeErr := productionRouteAndLimits(family, role, providerTimeouts)
			if routeErr != nil {
				return nil, routeErr
			}
			instance := route.ProviderInstance()
			template := productionCandidateTemplate{
				family: family, instance: instance, profileID: instance,
				runtimeSafetyPolicyIdentity: identities[family], transportChannel: ports.ProviderPacketChannelArgvLiteral,
				concurrencyKey: route.ConcurrencyKey(), limits: limits, supportedRoles: []domain.Role{role},
			}
			switch family {
			case FamilyKimi:
				template.kimiModel, template.transportArgvIndex = kimiModel, 4
			case FamilyZCode:
				template.transportArgvIndex = 6
			case FamilyAGY:
				template.transportArgvIndex, template.lifecycle = agyArgvIndex, &lifecycle
				template.environment = []ports.EnvironmentVariable{agyEnvironment}
			}
			templates = append(templates, template)
		}
	}
	return templates, nil
}

func productionRouteAndLimits(family Family, role domain.Role, providerTimeouts map[Family]time.Duration) (ports.ProviderRoute, review.InvocationLimits, error) {
	if !family.Valid() || !role.Valid() {
		return ports.ProviderRoute{}, review.InvocationLimits{}, fmt.Errorf("review run: invalid production route")
	}
	instance := string(family) + "-" + string(role)
	key, err := ports.ParseConcurrencyKey(instance)
	if err != nil {
		return ports.ProviderRoute{}, review.InvocationLimits{}, err
	}
	route, err := ports.NewProviderRoute(instance, key)
	if err != nil {
		return ports.ProviderRoute{}, review.InvocationLimits{}, err
	}
	limits, err := review.NewInvocationLimits(providerTimeouts[family], productionOutputCap, productionOutputCap)
	if err != nil {
		return ports.ProviderRoute{}, review.InvocationLimits{}, err
	}
	return route, limits, nil
}

func defaultProductionProviderTimeouts() map[Family]time.Duration {
	timeouts := make(map[Family]time.Duration, len(Families()))
	for _, family := range Families() {
		timeouts[family] = productionDefaultProviderTimeout
	}
	return timeouts
}

func validateProductionProviderTimeouts(timeouts map[Family]time.Duration) error {
	if len(timeouts) != len(Families()) {
		return fmt.Errorf("provider timeout family coverage")
	}
	for _, family := range Families() {
		timeout, ok := timeouts[family]
		if !ok {
			return fmt.Errorf("missing provider timeout for %q", family)
		}
		if timeout < productionMinimumProviderTimeout || timeout > productionMaximumProviderTimeout {
			return fmt.Errorf("provider timeout for %q must be between %s and %s", family, productionMinimumProviderTimeout, productionMaximumProviderTimeout)
		}
	}
	for family := range timeouts {
		if !family.Valid() {
			return fmt.Errorf("unknown provider timeout family %q", family)
		}
	}
	return nil
}

func validateProductionCandidateTemplates(templates []productionCandidateTemplate) error {
	if len(templates) != len(Families())*len(domain.FixedRoleOrder())-1 {
		return fmt.Errorf("template count")
	}
	seenInstances := make(map[string]struct{}, len(templates))
	seenKeys := make(map[string]struct{}, len(templates))
	roleCoverage := make(map[Family]map[domain.Role]int, len(Families()))
	for _, template := range templates {
		if len(template.supportedRoles) != 1 {
			return fmt.Errorf("template role cardinality")
		}
		role := template.supportedRoles[0]
		wantInstance := string(template.family) + "-" + string(role)
		if !template.limits.Valid() || template.limits.Timeout() < productionMinimumProviderTimeout || template.limits.Timeout() > productionMaximumProviderTimeout {
			return fmt.Errorf("invalid template timeout")
		}
		if !template.family.Valid() || template.runtimeSafetyPolicyIdentity == "" ||
			template.transportChannel != ports.ProviderPacketChannelArgvLiteral || template.transportArgvIndex < 0 || template.transportReference != "" ||
			template.instance != wantInstance || template.profileID != template.instance || !template.concurrencyKey.Valid() ||
			template.concurrencyKey.String() != template.instance || len(template.supportedRoles) == 0 {
			return fmt.Errorf("invalid template policy identity")
		}
		if _, duplicate := seenInstances[template.instance]; duplicate {
			return fmt.Errorf("duplicate template instance %q", template.instance)
		}
		seenInstances[template.instance] = struct{}{}
		if _, duplicate := seenKeys[template.concurrencyKey.String()]; duplicate {
			return fmt.Errorf("duplicate template concurrency key")
		}
		seenKeys[template.concurrencyKey.String()] = struct{}{}
		if roleCoverage[template.family] == nil {
			roleCoverage[template.family] = make(map[domain.Role]int)
		}
		for _, role := range template.supportedRoles {
			if !role.Valid() {
				return fmt.Errorf("invalid template role")
			}
			roleCoverage[template.family][role]++
		}
		if template.family == FamilyAGY && (template.lifecycle == nil || !template.lifecycle.Valid()) {
			return fmt.Errorf("invalid agy lifecycle")
		}
		if template.family != FamilyAGY && template.lifecycle != nil {
			return fmt.Errorf("unexpected lifecycle")
		}
	}
	for _, family := range Families() {
		for _, role := range domain.FixedRoleOrder() {
			want := 1
			if family == FamilyKimi && role == domain.RoleArtist {
				want = 0
			}
			if roleCoverage[family][role] != want {
				return fmt.Errorf("invalid template role coverage for %q", family)
			}
		}
	}
	return nil
}

func productionRolesForFamily(family Family) []domain.Role {
	roles := domain.FixedRoleOrder()
	if family != FamilyKimi {
		return roles
	}
	return append([]domain.Role(nil), roles[:len(roles)-1]...)
}

// SupportedProductionRoles returns the closed role capability matrix for one family.
func SupportedProductionRoles(family Family) []domain.Role {
	if !family.Valid() {
		return nil
	}
	return productionRolesForFamily(family)
}

func intersectCanonicalRoles(left, right []domain.Role) []domain.Role {
	rightSet := make(map[domain.Role]struct{}, len(right))
	for _, role := range right {
		rightSet[role] = struct{}{}
	}
	result := make([]domain.Role, 0, len(left))
	for _, role := range canonicalSelectedRoles(left) {
		if _, ok := rightSet[role]; ok {
			result = append(result, role)
		}
	}
	return result
}

func qualificationBaseRole(roles []domain.Role) domain.Role {
	for _, role := range roles {
		if role == domain.RoleLogic {
			return role
		}
	}
	if len(roles) == 0 {
		return ""
	}
	return roles[0]
}

func validateProductionPolicyIdentities(identities map[Family]string) error {
	if len(identities) != len(Families()) {
		return fmt.Errorf("policy family coverage")
	}
	for _, family := range Families() {
		if identities[family] == "" {
			return fmt.Errorf("missing policy identity for %q", family)
		}
	}
	for family := range identities {
		if !family.Valid() {
			return fmt.Errorf("unknown policy family %q", family)
		}
	}
	return nil
}
func validateProductionCandidateTemplatesWithPolicyIdentities(templates []productionCandidateTemplate, identities map[Family]string) error {
	if err := validateProductionPolicyIdentities(identities); err != nil {
		return err
	}
	if err := validateProductionCandidateTemplates(templates); err != nil {
		return err
	}
	for _, template := range templates {
		if template.runtimeSafetyPolicyIdentity != identities[template.family] {
			return fmt.Errorf("template policy identity drift")
		}
	}
	return nil
}

func cloneProductionPolicyIdentities(identities map[Family]string) map[Family]string {
	cloned := make(map[Family]string, len(identities))
	for family, identity := range identities {
		cloned[family] = identity
	}
	return cloned
}

func validateStartupProfiles(profiles []DiscoveredProviderProfile) error {
	seen := make(map[Family]struct{}, len(profiles))
	for _, profile := range profiles {
		if !profile.Family().Valid() {
			return fmt.Errorf("review run: invalid startup provider family")
		}
		if _, duplicate := seen[profile.Family()]; duplicate {
			return fmt.Errorf("review run: duplicate startup provider family %q", profile.Family())
		}
		seen[profile.Family()] = struct{}{}
		if profile.Version() != "" || profile.Classification() != "" || profile.Available() {
			return fmt.Errorf("review run: startup profile is not identity-only")
		}
		if profileMissingOperationalIdentity(profile) {
			switch {
			case profile.Executable() == "":
				if profile.Launcher() != "" || profile.SHA256() != "" || profile.LauncherSHA256() != "" || len(profile.Argv()) != 0 || profile.Reason() != "executable_not_found" {
					return fmt.Errorf("review run: malformed unavailable startup profile")
				}
			case !canonicalAbsolute(profile.Executable()) || profile.SHA256() == "" || !reflect.DeepEqual(profile.Argv(), []string{profile.Executable()}) || profile.Reason() != "launcher_not_found":
				return fmt.Errorf("review run: malformed unavailable startup profile")
			}
			continue
		}
		if profile.Reason() != "unqualified_discovery" || !canonicalAbsolute(profile.Executable()) || !canonicalAbsolute(profile.Launcher()) || profile.SHA256() == "" || profile.LauncherSHA256() == "" {
			return fmt.Errorf("review run: unsafe startup provider provenance")
		}
		want := []string{profile.Executable()}
		if profile.Family() == FamilyZCode {
			want = append(want, profile.Launcher())
		}
		if !reflect.DeepEqual(profile.Argv(), want) {
			return fmt.Errorf("review run: startup provider argv drift")
		}
		if profile.Family() != FamilyZCode && (profile.Launcher() != profile.Executable() || profile.LauncherSHA256() != profile.SHA256()) {
			return fmt.Errorf("review run: direct provider launcher provenance drift")
		}
	}
	return nil
}

func profileMissingOperationalIdentity(profile DiscoveredProviderProfile) bool {
	return profile.Executable() == "" || profile.Launcher() == ""
}

func canonicalSelectedRoles(selected []domain.Role) []domain.Role {
	set := make(map[domain.Role]struct{}, len(selected))
	for _, role := range selected {
		set[role] = struct{}{}
	}
	roles := make([]domain.Role, 0, len(selected))
	for _, role := range domain.FixedRoleOrder() {
		if _, ok := set[role]; ok {
			roles = append(roles, role)
		}
	}
	return roles
}

func cloneDiscoveredProviderProfile(profile DiscoveredProviderProfile) DiscoveredProviderProfile {
	profile.argv = append([]string(nil), profile.argv...)
	return profile
}

func cloneDiscoveredProviderProfiles(profiles []DiscoveredProviderProfile) []DiscoveredProviderProfile {
	cloned := make([]DiscoveredProviderProfile, len(profiles))
	for index := range profiles {
		cloned[index] = cloneDiscoveredProviderProfile(profiles[index])
	}
	return cloned
}
