package reviewrun

import (
	"context"
	"fmt"
	"reflect"
	"time"

	"github.com/irootkernel/kkachi-agent-review/internal/adapters/providercli"
	"github.com/irootkernel/kkachi-agent-review/internal/app/review"
	"github.com/irootkernel/kkachi-agent-review/internal/domain"
	"github.com/irootkernel/kkachi-agent-review/internal/ports"
)

const (
	productionProfileGeneration       = "reviewrun-production-candidates-v1"
	productionWorkingDirectory        = "/private/var/empty"
	productionTimeout                 = 2 * time.Minute
	productionOutputCap         int64 = 256 << 10
)

type productionCandidateTemplate struct {
	family                      Family
	instance                    string
	profileID                   string
	runtimeSafetyPolicyIdentity string
	baseArgv                    []string
	environment                 []ports.EnvironmentVariable
	transport                   providercli.RuntimeTransport
	concurrencyKey              ports.ConcurrencyKey
	limits                      review.InvocationLimits
	lifecycle                   *ports.BoundedPostOutputLifecycle
	kimiModel                   string
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
}

// NewProductionQualifiedRunCandidateSource constructs the production candidate
// source from the identity-only profiles captured at startup. Profiles are
// retained by value; their caller-owned argv slices are cloned.
func NewProductionQualifiedRunCandidateSource(profiles []DiscoveredProviderProfile) (*ProductionQualifiedRunCandidateSource, error) {
	identities, err := defaultProductionPolicyIdentities()
	if err != nil {
		return nil, fmt.Errorf("review run: default production policy identities: %w", err)
	}
	return NewProductionQualifiedRunCandidateSourceWithPolicyIdentities(profiles, identities)
}

// NewProductionQualifiedRunCandidateSourceWithPolicyIdentities constructs the
// production candidate source using the exact policies installed into provider
// credential namespaces for this composition.
func NewProductionQualifiedRunCandidateSourceWithPolicyIdentities(profiles []DiscoveredProviderProfile, identities map[Family]string) (*ProductionQualifiedRunCandidateSource, error) {
	return NewProductionQualifiedRunCandidateSourceWithPolicyIdentitiesAndAGYPermissionMode(profiles, identities, "safe")
}

func NewProductionQualifiedRunCandidateSourceWithPolicyIdentitiesAndAGYPermissionMode(profiles []DiscoveredProviderProfile, identities map[Family]string, agyPermissionMode string) (*ProductionQualifiedRunCandidateSource, error) {
	return NewProductionQualifiedRunCandidateSourceWithPolicyIdentitiesAndRuntimeSettings(profiles, identities, agyPermissionMode, "kimi-code/k3")
}

// NewProductionQualifiedRunCandidateSourceWithPolicyIdentitiesAndRuntimeSettings
// binds operator-admitted family settings to every probe and production
// invocation. Kimi's model is explicit here; callers pass the canonical K3
// default only when the configuration omitted the field.
func NewProductionQualifiedRunCandidateSourceWithPolicyIdentitiesAndRuntimeSettings(profiles []DiscoveredProviderProfile, identities map[Family]string, agyPermissionMode, kimiModel string) (*ProductionQualifiedRunCandidateSource, error) {
	if err := validateProductionPolicyIdentities(identities); err != nil {
		return nil, fmt.Errorf("review run: invalid production policy identities: %w", err)
	}
	templates, err := productionCandidateTemplatesWithRuntimeSettings(identities, agyPermissionMode, kimiModel)
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
		templates: templates,
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
	base := roles[0]
	for _, role := range roles {
		if role == domain.RoleLogic {
			base = domain.RoleLogic
			break
		}
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
		definition, err := template.definition(profile)
		if err != nil {
			return nil, fmt.Errorf("review run: construct %s production candidate: %w", template.family, err)
		}
		candidates = append(candidates, QualifiedRunCandidate{
			Profile:          cloneDiscoveredProviderProfile(profile),
			Definition:       definition,
			SnapshotManifest: workspace.ManifestSHA256(),
			SupportedRoles:   append([]domain.Role(nil), roles...),
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

func (template productionCandidateTemplate) definition(profile DiscoveredProviderProfile) (providercli.RuntimeDefinition, error) {
	baseArgv := append([]string{profile.Executable()}, template.baseArgv...)
	if template.family == FamilyZCode {
		baseArgv = []string{profile.Executable(), profile.Launcher()}
		baseArgv = append(baseArgv, template.baseArgv...)
	}
	if template.lifecycle != nil {
		return providercli.NewProductionRuntimeDefinitionWithTransportAndSafetyPolicyAndPostOutputLifecycle(
			string(template.family), template.instance, "", profile.Executable(), profile.SHA256(), profile.Launcher(), profile.LauncherSHA256(),
			template.concurrencyKey, template.profileID, productionProfileGeneration, template.runtimeSafetyPolicyIdentity,
			baseArgv, template.transport, *template.lifecycle, append([]ports.EnvironmentVariable(nil), template.environment...), productionWorkingDirectory,
			template.limits.Timeout(), template.limits.MaxStdoutBytes(), template.limits.MaxStderrBytes(),
		)
	}
	if template.family == FamilyKimi {
		return providercli.NewProductionKimiRuntimeDefinitionWithTransportAndSafetyPolicy(
			string(template.family), template.instance, "", profile.Executable(), profile.SHA256(), profile.Launcher(), profile.LauncherSHA256(),
			template.concurrencyKey, template.profileID, productionProfileGeneration, template.runtimeSafetyPolicyIdentity, template.kimiModel,
			baseArgv, template.transport, append([]ports.EnvironmentVariable(nil), template.environment...), productionWorkingDirectory,
			template.limits.Timeout(), template.limits.MaxStdoutBytes(), template.limits.MaxStderrBytes(),
		)
	}
	return providercli.NewProductionRuntimeDefinitionWithTransportAndSafetyPolicy(
		string(template.family), template.instance, "", profile.Executable(), profile.SHA256(), profile.Launcher(), profile.LauncherSHA256(),
		template.concurrencyKey, template.profileID, productionProfileGeneration, template.runtimeSafetyPolicyIdentity,
		baseArgv, template.transport, append([]ports.EnvironmentVariable(nil), template.environment...), productionWorkingDirectory,
		template.limits.Timeout(), template.limits.MaxStdoutBytes(), template.limits.MaxStderrBytes(),
	)
}

func trustedProductionCandidateTemplates() ([]productionCandidateTemplate, error) {
	identities, err := defaultProductionPolicyIdentities()
	if err != nil {
		return nil, err
	}
	return productionCandidateTemplates(identities)
}

func defaultProductionPolicyIdentities() (map[Family]string, error) {
	families := map[Family]providercli.CredentialSourceFamily{
		FamilyKimi:  providercli.CredentialSourceKimi,
		FamilyZCode: providercli.CredentialSourceZCode,
		FamilyAGY:   providercli.CredentialSourceAGY,
	}
	identities := make(map[Family]string, len(families))
	for family, credentialFamily := range families {
		policy, err := providercli.RuntimeSafetyPolicyForFamily(credentialFamily)
		if err != nil {
			return nil, err
		}
		identities[family] = policy.Identity()
	}
	return identities, nil
}

func productionCandidateTemplates(identities map[Family]string) ([]productionCandidateTemplate, error) {
	return productionCandidateTemplatesWithAGYPermissionMode(identities, "safe")
}

func productionCandidateTemplatesWithAGYPermissionMode(identities map[Family]string, agyPermissionMode string) ([]productionCandidateTemplate, error) {
	return productionCandidateTemplatesWithRuntimeSettings(identities, agyPermissionMode, "kimi-code/k3")
}

func productionCandidateTemplatesWithRuntimeSettings(identities map[Family]string, agyPermissionMode, kimiModel string) ([]productionCandidateTemplate, error) {
	if err := validateProductionPolicyIdentities(identities); err != nil {
		return nil, err
	}
	if agyPermissionMode != "safe" && agyPermissionMode != "dangerously-skip-permissions" {
		return nil, fmt.Errorf("invalid AGY permission mode")
	}
	if kimiModel == "" {
		return nil, fmt.Errorf("invalid Kimi model")
	}
	limits, err := review.NewInvocationLimits(productionTimeout, productionOutputCap, productionOutputCap)
	if err != nil {
		return nil, err
	}
	kimiKey, err := ports.ParseConcurrencyKey("kimi-default")
	if err != nil {
		return nil, err
	}
	zcodeKey, err := ports.ParseConcurrencyKey("zcode-default")
	if err != nil {
		return nil, err
	}
	agyKey, err := ports.ParseConcurrencyKey("agy-default")
	if err != nil {
		return nil, err
	}
	kimiTransport, err := providercli.NewRuntimeTransport(ports.ProviderPacketChannelArgvLiteral, 4, "")
	if err != nil {
		return nil, err
	}
	zcodeTransport, err := providercli.NewRuntimeTransport(ports.ProviderPacketChannelArgvLiteral, 6, "")
	if err != nil {
		return nil, err
	}
	agyArgvIndex := 10
	if agyPermissionMode == "dangerously-skip-permissions" {
		agyArgvIndex = 11
	}
	agyTransport, err := providercli.NewRuntimeTransport(ports.ProviderPacketChannelArgvLiteral, agyArgvIndex, "")
	if err != nil {
		return nil, err
	}
	lifecycle, err := ports.NewBoundedPostOutputLifecycle(ports.ProcessOutputFramingStrictJSON, time.Second, time.Second)
	if err != nil {
		return nil, err
	}
	agyEnvironment, err := ports.NewEnvironmentVariable("AGY_CLI_DISABLE_AUTO_UPDATE", "true")
	if err != nil {
		return nil, err
	}
	return []productionCandidateTemplate{
		{family: FamilyKimi, instance: "kimi-default", profileID: "kimi-default", runtimeSafetyPolicyIdentity: identities[FamilyKimi], kimiModel: kimiModel, transport: kimiTransport, concurrencyKey: kimiKey, limits: limits},
		{family: FamilyZCode, instance: "zcode-default", profileID: "zcode-default", runtimeSafetyPolicyIdentity: identities[FamilyZCode], transport: zcodeTransport, concurrencyKey: zcodeKey, limits: limits},
		{family: FamilyAGY, instance: "agy-default", profileID: "agy-default", runtimeSafetyPolicyIdentity: identities[FamilyAGY], transport: agyTransport, concurrencyKey: agyKey, limits: limits, lifecycle: &lifecycle, environment: []ports.EnvironmentVariable{agyEnvironment}},
	}, nil
}

func validateProductionCandidateTemplates(templates []productionCandidateTemplate) error {
	if len(templates) != len(Families()) {
		return fmt.Errorf("template count")
	}
	seen := make(map[Family]struct{}, len(templates))
	for _, template := range templates {
		if !template.family.Valid() || template.runtimeSafetyPolicyIdentity == "" {
			return fmt.Errorf("invalid template policy identity")
		}
		if _, duplicate := seen[template.family]; duplicate {
			return fmt.Errorf("duplicate template family %q", template.family)
		}
		seen[template.family] = struct{}{}
		if template.family == FamilyAGY && (template.lifecycle == nil || !template.lifecycle.Valid()) {
			return fmt.Errorf("invalid agy lifecycle")
		}
		if template.family != FamilyAGY && template.lifecycle != nil {
			return fmt.Errorf("unexpected lifecycle")
		}
	}
	for _, family := range Families() {
		if _, ok := seen[family]; !ok {
			return fmt.Errorf("missing template family %q", family)
		}
	}
	return nil
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
