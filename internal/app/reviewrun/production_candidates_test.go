package reviewrun

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/adapters/providercli"
	"github.com/irootkernel/mulgae/internal/app/evidence"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

const (
	testZCodeExecutable                = "/Applications/ZCode.app/Contents/MacOS/ZCode"
	testZCodeLauncher                  = "/Applications/ZCode.app/Contents/Resources/glm/zcode.cjs"
	testZCodeProviderConfig            = "/Applications/ZCode.app/Contents/Resources/config/provider/zcode-builtin.json"
	testZCodeProviderConfigSHA256      = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testZCodeApplicationMetadata       = "/Applications/ZCode.app/Contents/Info.plist"
	testZCodeApplicationMetadataSHA256 = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func TestProductionCandidateTemplatesAreCanonicalAndBounded(t *testing.T) {
	templates, err := trustedProductionCandidateTemplates(providercli.RuntimeBuilder{})
	if err != nil {
		t.Fatal(err)
	}
	if err := validateProductionCandidateTemplates(templates); err != nil {
		t.Fatal(err)
	}
	offset := 0
	for _, family := range Families() {
		for _, role := range productionRolesForFamily(family) {
			template := templates[offset]
			offset++
			wantInstance := string(family) + "-" + string(role)
			if template.family != family || template.instance != wantInstance || template.profileID != wantInstance || !reflect.DeepEqual(template.supportedRoles, []domain.Role{role}) {
				t.Fatalf("template %s/%s = %#v", family, role, template)
			}
			if family == FamilyZCode && (template.transportChannel != ports.ProviderPacketChannelProtocol || template.transportArgvIndex != -1) {
				t.Fatalf("ZCode template %s = %#v", role, template)
			}
			if template.limits.Timeout() != productionDefaultProviderTimeout {
				t.Fatalf("%s template timeout = %s, want %s", family, template.limits.Timeout(), productionDefaultProviderTimeout)
			}
			if template.lifecycle != nil {
				t.Fatalf("%s template %s has unexpected lifecycle", family, role)
			}
		}
	}
}

func TestProductionCandidateTemplatesSeparateCodexCredentialProfiles(t *testing.T) {
	identities, err := defaultProductionPolicyIdentities(providercli.RuntimeBuilder{})
	if err != nil {
		t.Fatal(err)
	}
	profiles := map[domain.Role]string{domain.RoleLogic: "personal", domain.RoleSecurity: "work"}
	templates, err := productionCandidateTemplatesWithCodexSettingsAndTimeouts(identities, "", "", profiles, defaultProductionProviderTimeouts())
	if err != nil {
		t.Fatal(err)
	}
	seen := map[domain.Role]productionCandidateTemplate{}
	for _, template := range templates {
		if template.family == FamilyCodex {
			seen[template.supportedRoles[0]] = template
		}
	}
	if seen[domain.RoleLogic].instance != "codex-personal-logic" || seen[domain.RoleLogic].profileID != "codex-personal" {
		t.Fatalf("logic template = %#v", seen[domain.RoleLogic])
	}
	if seen[domain.RoleSecurity].instance != "codex-work-security" || seen[domain.RoleSecurity].profileID != "codex-work" {
		t.Fatalf("security template = %#v", seen[domain.RoleSecurity])
	}
}

func TestProductionCandidateTemplatesBindDistinctFamilyTimeoutsToLimitsAndRuntimeDefinitions(t *testing.T) {
	profiles := []DiscoveredProviderProfile{
		{family: FamilyZCode, executable: testZCodeExecutable, launcher: testZCodeLauncher, argv: []string{testZCodeExecutable, testZCodeLauncher}, sha256: "runtime-sha", launcherSHA256: "launcher-sha", providerConfig: testZCodeProviderConfig, providerConfigSHA256: testZCodeProviderConfigSHA256, applicationVersion: "3.12.3", applicationVersionClassification: VersionGreen, applicationMetadata: testZCodeApplicationMetadata, applicationMetadataSHA256: testZCodeApplicationMetadataSHA256, reason: "unqualified_discovery"},
		{family: FamilyGrok, executable: "/private/bin/grok", launcher: "/private/bin/grok", argv: []string{"/private/bin/grok"}, sha256: "grok-sha", launcherSHA256: "grok-sha", reason: "unqualified_discovery"},
		{family: FamilyCodex, executable: "/private/bin/codex", launcher: "/private/bin/codex", argv: []string{"/private/bin/codex"}, sha256: "codex-sha", launcherSHA256: "codex-sha", reason: "unqualified_discovery"},
	}
	identities := map[Family]string{FamilyZCode: "zcode-policy", FamilyGrok: "grok-policy", FamilyCodex: "codex-policy"}
	timeouts := map[Family]time.Duration{FamilyZCode: 30 * time.Minute, FamilyGrok: 25 * time.Minute, FamilyCodex: 20 * time.Minute}
	source, err := NewProductionQualifiedRunCandidateSourceWithPolicyIdentitiesAndCodexSettingsAndTimeouts(
		providercli.RuntimeBuilder{}, profiles, identities, "", "", nil, timeouts,
	)
	if err != nil {
		t.Fatal(err)
	}
	selection, err := NewRunSelection(domain.FixedRoleOrder(), nil)
	if err != nil {
		t.Fatal(err)
	}
	candidates, err := source.NewLiveQualifiedRunCandidates(authorityLiveExecution(t).Target(), selection)
	if err != nil {
		t.Fatal(err)
	}
	wantCandidateCount := len(Families())*len(domain.FixedRoleOrder()) - 1
	if len(candidates) != wantCandidateCount {
		t.Fatalf("candidate count = %d, want %d", len(candidates), wantCandidateCount)
	}
	for _, candidate := range candidates {
		family := Family(candidate.Definition.Family())
		want := timeouts[family]
		if got := candidate.Limits.Timeout(); got != want {
			t.Errorf("%s candidate timeout = %s, want %s", family, got, want)
		}
		if got := candidate.Definition.Timeout(); got != want {
			t.Errorf("%s runtime definition timeout = %s, want %s", family, got, want)
		}
	}
}

func TestProductionProviderTimeoutsRequireExactBoundedFamilyCoverage(t *testing.T) {
	valid := map[Family]time.Duration{FamilyZCode: 30 * time.Minute, FamilyGrok: 25 * time.Minute, FamilyCodex: 20 * time.Minute}
	if err := validateProductionProviderTimeouts(valid); err != nil {
		t.Fatal(err)
	}
	for name, invalid := range map[string]map[Family]time.Duration{
		"missing":       {FamilyZCode: time.Minute, FamilyGrok: time.Minute},
		"unknown":       {FamilyZCode: time.Minute, FamilyGrok: time.Minute, FamilyCodex: time.Minute, Family("other"): time.Minute},
		"zero":          {FamilyZCode: 0, FamilyGrok: time.Minute, FamilyCodex: time.Minute},
		"below minimum": {FamilyZCode: time.Minute - time.Second, FamilyGrok: time.Minute, FamilyCodex: time.Minute},
		"above maximum": {FamilyZCode: 60*time.Minute + time.Second, FamilyGrok: time.Minute, FamilyCodex: time.Minute},
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateProductionProviderTimeouts(invalid); err == nil {
				t.Fatal("invalid provider timeout policy was accepted")
			}
		})
	}
}

func TestProductionCandidatesShardZCodeRolesAcrossSevenInstances(t *testing.T) {
	profiles := []DiscoveredProviderProfile{{
		family: FamilyZCode, executable: testZCodeExecutable, launcher: testZCodeLauncher,
		argv: []string{testZCodeExecutable, testZCodeLauncher}, sha256: "runtime-sha", launcherSHA256: "launcher-sha", providerConfig: testZCodeProviderConfig, providerConfigSHA256: testZCodeProviderConfigSHA256, applicationVersion: "3.12.3", applicationVersionClassification: VersionGreen, applicationMetadata: testZCodeApplicationMetadata, applicationMetadataSHA256: testZCodeApplicationMetadataSHA256, reason: "unqualified_discovery",
	}}
	source, err := NewProductionQualifiedRunCandidateSource(providercli.RuntimeBuilder{}, profiles)
	if err != nil {
		t.Fatal(err)
	}
	selection, err := NewRunSelection(domain.FixedRoleOrder(), nil)
	if err != nil {
		t.Fatal(err)
	}
	candidates, err := source.NewLiveQualifiedRunCandidates(authorityLiveExecution(t).Target(), selection)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 7 {
		t.Fatalf("ZCode candidate count = %d, want 7", len(candidates))
	}
	want := map[string][]domain.Role{
		"zcode-logic": {domain.RoleLogic}, "zcode-security": {domain.RoleSecurity},
		"zcode-maintainability": {domain.RoleMaintainability}, "zcode-product": {domain.RoleProduct},
		"zcode-documentation": {domain.RoleDocumentation}, "zcode-testing": {domain.RoleTesting},
		"zcode-artist": {domain.RoleArtist},
	}
	for _, candidate := range candidates {
		instance := candidate.Definition.Instance()
		if !reflect.DeepEqual(candidate.SupportedRoles, want[instance]) || candidate.Definition.Executable() != testZCodeExecutable || candidate.Definition.Launcher() != testZCodeLauncher {
			t.Fatalf("ZCode candidate %s = roles %v definition %#v", instance, candidate.SupportedRoles, candidate.Definition)
		}
		if candidate.Limits.Timeout() != productionDefaultProviderTimeout || candidate.Definition.Timeout() != productionDefaultProviderTimeout {
			t.Fatalf("ZCode candidate %s default timeouts = %s/%s, want %s", instance, candidate.Limits.Timeout(), candidate.Definition.Timeout(), productionDefaultProviderTimeout)
		}
	}
}
func TestProductionCandidatesUseInjectedPolicyIdentitiesWithClosedCoverage(t *testing.T) {
	profiles := []DiscoveredProviderProfile{
		{family: FamilyZCode, executable: testZCodeExecutable, launcher: testZCodeLauncher, argv: []string{testZCodeExecutable, testZCodeLauncher}, sha256: "runtime-sha", launcherSHA256: "launcher-sha", providerConfig: testZCodeProviderConfig, providerConfigSHA256: testZCodeProviderConfigSHA256, applicationVersion: "3.12.3", applicationVersionClassification: VersionGreen, applicationMetadata: testZCodeApplicationMetadata, applicationMetadataSHA256: testZCodeApplicationMetadataSHA256, reason: "unqualified_discovery"},
		{family: FamilyGrok, executable: "/private/bin/grok", launcher: "/private/bin/grok", argv: []string{"/private/bin/grok"}, sha256: "grok-sha", launcherSHA256: "grok-sha", reason: "unqualified_discovery"},
		{family: FamilyCodex, executable: "/private/bin/codex", launcher: "/private/bin/codex", argv: []string{"/private/bin/codex"}, sha256: "codex-sha", launcherSHA256: "codex-sha", reason: "unqualified_discovery"},
	}
	identities := map[Family]string{
		FamilyZCode: "zcode-policy",
		FamilyGrok:  "grok-policy",
		FamilyCodex: "codex-policy",
	}
	source, err := NewProductionQualifiedRunCandidateSourceWithPolicyIdentities(providercli.RuntimeBuilder{}, profiles, identities)
	if err != nil {
		t.Fatal(err)
	}
	selection, err := NewRunSelection([]domain.Role{domain.RoleLogic}, nil)
	if err != nil {
		t.Fatal(err)
	}
	candidates, err := source.NewLiveQualifiedRunCandidates(authorityLiveExecution(t).Target(), selection)
	if err != nil {
		t.Fatal(err)
	}
	for _, candidate := range candidates {
		family := Family(candidate.Definition.Family())
		if got, want := candidate.Definition.RuntimeSafetyPolicyIdentity(), identities[family]; got != want {
			t.Fatalf("%s policy identity = %q, want %q", family, got, want)
		}
	}

	for name, invalid := range map[string]map[Family]string{
		"missing": {
			FamilyZCode: "zcode-policy", FamilyGrok: "grok-policy",
		},
		"empty": {
			FamilyZCode: "zcode-policy", FamilyGrok: "grok-policy", FamilyCodex: "",
		},
		"unknown": {
			FamilyZCode: "zcode-policy", FamilyGrok: "grok-policy", FamilyCodex: "codex-policy", Family("other"): "other-policy",
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewProductionQualifiedRunCandidateSourceWithPolicyIdentities(providercli.RuntimeBuilder{}, profiles, invalid); err == nil {
				t.Fatal("invalid policy coverage was accepted")
			}
		})
	}
}

func TestProductionCandidatesBindConfiguredCodexRuntimeSettings(t *testing.T) {
	profiles := []DiscoveredProviderProfile{{
		family: FamilyCodex, executable: "/private/bin/codex", launcher: "/private/bin/codex",
		argv: []string{"/private/bin/codex"}, sha256: "codex-sha", launcherSHA256: "codex-sha", reason: "unqualified_discovery",
	}}
	identities := map[Family]string{FamilyZCode: "zcode-policy", FamilyGrok: "grok-policy", FamilyCodex: "codex-policy"}
	timeouts := map[Family]time.Duration{FamilyZCode: 15 * time.Minute, FamilyGrok: 15 * time.Minute, FamilyCodex: 20 * time.Minute}
	source, err := NewProductionQualifiedRunCandidateSourceWithPolicyIdentitiesAndCodexSettingsAndTimeouts(
		providercli.RuntimeBuilder{}, profiles, identities, "gpt-5.3-codex", "high", nil, timeouts,
	)
	if err != nil {
		t.Fatal(err)
	}
	selection, err := NewRunSelection([]domain.Role{domain.RoleArtist}, nil)
	if err != nil {
		t.Fatal(err)
	}
	candidates, err := source.NewLiveQualifiedRunCandidates(authorityLiveExecution(t).Target(), selection)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 1 {
		t.Fatalf("configured Codex settings were not bound: %#v", candidates)
	}
	definition, ok := candidates[0].Definition.(providercli.RuntimeDefinition)
	if !ok || definition.CodexModel() != "gpt-5.3-codex" || definition.CodexReasoningEffort() != "high" {
		t.Fatalf("configured Codex settings were not bound: %#v", candidates)
	}
	if definition.Transport().Channel() != ports.ProviderPacketChannelProtocol || definition.Transport().ArgvIndex() != -1 {
		t.Fatalf("Codex transport = %#v", definition.Transport())
	}
}

func TestProductionCandidatesBindConfiguredGrokRuntimeSettings(t *testing.T) {
	profiles := []DiscoveredProviderProfile{{
		family: FamilyGrok, executable: "/private/bin/grok", launcher: "/private/bin/grok",
		argv: []string{"/private/bin/grok"}, sha256: "grok-sha", launcherSHA256: "grok-sha", reason: "unqualified_discovery",
	}}
	identities := map[Family]string{FamilyZCode: "zcode-policy", FamilyGrok: "grok-policy", FamilyCodex: "codex-policy"}
	timeouts := map[Family]time.Duration{FamilyZCode: 15 * time.Minute, FamilyGrok: 20 * time.Minute, FamilyCodex: 15 * time.Minute}
	source, err := NewProductionQualifiedRunCandidateSourceWithPolicyIdentitiesAndProviderSettingsAndTimeouts(
		providercli.RuntimeBuilder{}, profiles, identities, "grok-4.5", "low", "", "", nil, timeouts,
	)
	if err != nil {
		t.Fatal(err)
	}
	selection, err := NewRunSelection([]domain.Role{domain.RoleLogic}, nil)
	if err != nil {
		t.Fatal(err)
	}
	candidates, err := source.NewLiveQualifiedRunCandidates(authorityLiveExecution(t).Target(), selection)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 1 {
		t.Fatalf("configured Grok settings were not bound: %#v", candidates)
	}
	definition, ok := candidates[0].Definition.(providercli.RuntimeDefinition)
	if !ok || definition.GrokModel() != "grok-4.5" || definition.GrokReasoningEffort() != "low" || definition.GrokSettingsIdentity() == "" {
		t.Fatalf("configured Grok settings were not bound: %#v", candidates)
	}
}

func TestCanonicalSelectedRolesUsesFixedOrderAndLogicBasePriority(t *testing.T) {
	roles := canonicalSelectedRoles([]domain.Role{domain.RoleTesting, domain.RoleLogic, domain.RoleSecurity})
	want := []domain.Role{domain.RoleLogic, domain.RoleSecurity, domain.RoleTesting}
	if !reflect.DeepEqual(roles, want) {
		t.Fatalf("roles = %v, want %v", roles, want)
	}
}

func TestValidateStartupProfilesRejectsMalformedAndCopiesArgv(t *testing.T) {
	profile := DiscoveredProviderProfile{
		family: FamilyGrok, executable: "/private/bin/grok", launcher: "/private/bin/grok",
		argv: []string{"/private/bin/grok"}, sha256: "sha", launcherSHA256: "sha", reason: "unqualified_discovery",
	}
	if err := validateStartupProfiles([]DiscoveredProviderProfile{profile}); err != nil {
		t.Fatal(err)
	}
	source, err := NewProductionQualifiedRunCandidateSource(providercli.RuntimeBuilder{}, []DiscoveredProviderProfile{profile})
	if err != nil {
		t.Fatal(err)
	}
	profile.argv[0] = "tampered"
	if got := source.profiles[0].Argv(); !reflect.DeepEqual(got, []string{"/private/bin/grok"}) {
		t.Fatalf("source retained caller argv: %v", got)
	}
	profile.reason = "tampered"
	if err := validateStartupProfiles([]DiscoveredProviderProfile{profile}); err == nil {
		t.Fatal("tampered profile was accepted")
	}
	zcodeBelowMinimum := DiscoveredProviderProfile{
		family: FamilyZCode, executable: testZCodeExecutable, launcher: testZCodeLauncher,
		argv: []string{testZCodeExecutable, testZCodeLauncher}, sha256: "runtime-sha", launcherSHA256: "launcher-sha",
		providerConfig: testZCodeProviderConfig, providerConfigSHA256: testZCodeProviderConfigSHA256,
		applicationVersion: "3.12.2", applicationVersionClassification: VersionRed,
		applicationMetadata: testZCodeApplicationMetadata, applicationMetadataSHA256: testZCodeApplicationMetadataSHA256,
		reason: "application_version_ineligible",
	}
	if err := validateStartupProfiles([]DiscoveredProviderProfile{zcodeBelowMinimum}); err != nil {
		t.Fatalf("below-minimum ZCode profile did not reach typed qualification: %v", err)
	}
	zcodeMalformed := zcodeBelowMinimum
	zcodeMalformed.applicationVersion = "garbage"
	zcodeMalformed.applicationVersionClassification = VersionUnknown
	zcodeMalformed.reason = "application_version_malformed"
	if err := validateStartupProfiles([]DiscoveredProviderProfile{zcodeMalformed}); err != nil {
		t.Fatalf("malformed ZCode profile did not reach typed qualification: %v", err)
	}
	partialZCode := DiscoveredProviderProfile{
		family: FamilyZCode, launcher: testZCodeLauncher, launcherSHA256: "launcher-sha",
		providerConfig: testZCodeProviderConfig, providerConfigSHA256: testZCodeProviderConfigSHA256,
		applicationVersion: "3.12.3", applicationVersionClassification: VersionGreen,
		applicationMetadata: testZCodeApplicationMetadata, applicationMetadataSHA256: testZCodeApplicationMetadataSHA256,
		reason: "executable_not_found",
	}
	if _, err := NewProductionQualifiedRunCandidateSource(providercli.RuntimeBuilder{}, []DiscoveredProviderProfile{partialZCode, {
		family: FamilyGrok, executable: "/private/bin/grok", launcher: "/private/bin/grok",
		argv: []string{"/private/bin/grok"}, sha256: "grok-sha", launcherSHA256: "grok-sha", reason: "unqualified_discovery",
	}}); err != nil {
		t.Fatalf("partial ZCode bundle blocked another usable provider: %v", err)
	}
}
func TestProductionCandidatesBindCurrentProfilesAndLiveSource(t *testing.T) {
	profiles := []DiscoveredProviderProfile{
		{family: FamilyZCode, executable: testZCodeExecutable, launcher: testZCodeLauncher, argv: []string{testZCodeExecutable, testZCodeLauncher}, sha256: "runtime-sha", launcherSHA256: "launcher-sha", providerConfig: testZCodeProviderConfig, providerConfigSHA256: testZCodeProviderConfigSHA256, applicationVersion: "3.12.3", applicationVersionClassification: VersionGreen, applicationMetadata: testZCodeApplicationMetadata, applicationMetadataSHA256: testZCodeApplicationMetadataSHA256, reason: "unqualified_discovery"},
		{family: FamilyGrok, executable: "/private/bin/grok", launcher: "/private/bin/grok", argv: []string{"/private/bin/grok"}, sha256: "grok-sha", launcherSHA256: "grok-sha", reason: "unqualified_discovery"},
		{family: FamilyCodex, executable: "/private/bin/codex", launcher: "/private/bin/codex", argv: []string{"/private/bin/codex"}, sha256: "codex-sha", launcherSHA256: "codex-sha", reason: "unqualified_discovery"},
	}
	source, err := NewProductionQualifiedRunCandidateSource(providercli.RuntimeBuilder{}, profiles)
	if err != nil {
		t.Fatal(err)
	}
	selection, err := NewRunSelection([]domain.Role{domain.RoleTesting, domain.RoleSecurity}, nil)
	if err != nil {
		t.Fatal(err)
	}
	target := authorityLiveExecution(t).Target()
	identity, err := evidence.NewLiveSourceIdentity(target)
	if err != nil {
		t.Fatal(err)
	}
	candidates, err := source.NewLiveQualifiedRunCandidates(target, selection)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 6 {
		t.Fatalf("candidate count = %d, want 6", len(candidates))
	}
	wantRoles := map[string][]domain.Role{
		"zcode-security": {domain.RoleSecurity}, "zcode-testing": {domain.RoleTesting},
		"grok-security": {domain.RoleSecurity}, "grok-testing": {domain.RoleTesting},
		"codex-security": {domain.RoleSecurity}, "codex-testing": {domain.RoleTesting},
	}
	for _, candidate := range candidates {
		if candidate.Definition.Version() != "" || candidate.ExecutionTargetIdentity != identity.SHA256() {
			t.Fatalf("candidate = %#v", candidate)
		}
		want := wantRoles[candidate.Definition.Instance()]
		if !reflect.DeepEqual(candidate.SupportedRoles, want) || candidate.BaseRole != want[0] {
			t.Fatalf("candidate roles/base = %v/%q", candidate.SupportedRoles, candidate.BaseRole)
		}
		environment := candidate.Definition.Environment()
		if Family(candidate.Definition.Family()) == FamilyZCode {
			if candidate.Definition.ProfileGeneration() == productionProfileGeneration || !strings.HasPrefix(candidate.Definition.ProfileGeneration(), zcodeProductionProfileGeneration+":") {
				t.Fatalf("ZCode profile generation did not bind provider config: %q", candidate.Definition.ProfileGeneration())
			}
			if len(environment) != 2 || environment[0].Name() != "ZCODE_BUILTIN_PROVIDER_CONFIG_FILE" || environment[0].Value() != testZCodeProviderConfig || environment[1].Name() != "ELECTRON_RUN_AS_NODE" || environment[1].Value() != "1" {
				t.Fatalf("ZCode environment = %v", environment)
			}
		} else {
			if candidate.Definition.ProfileGeneration() != productionProfileGeneration {
				t.Fatalf("%s profile generation = %q, want unchanged %q", candidate.Definition.Family(), candidate.Definition.ProfileGeneration(), productionProfileGeneration)
			}
			if len(environment) != 0 {
				t.Fatalf("%s environment = %v, want none", candidate.Definition.Family(), environment)
			}
		}
	}
	for _, candidate := range candidates {
		if Family(candidate.Definition.Family()) == FamilyZCode {
			if got := candidate.Definition.BaseArgv(); !reflect.DeepEqual(got, []string{testZCodeExecutable, testZCodeLauncher}) {
				t.Fatalf("ZCode argv = %v", got)
			}
			break
		}
	}
}
