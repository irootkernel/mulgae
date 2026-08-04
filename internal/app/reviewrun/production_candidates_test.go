package reviewrun

import (
	"reflect"
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/adapters/providercli"
	"github.com/irootkernel/mulgae/internal/app/review"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

func TestProductionCandidateTemplatesAreCanonicalAndAGYIsBounded(t *testing.T) {
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
			if template.family != family || template.instance != wantInstance || template.profileID != wantInstance || template.concurrencyKey.String() != wantInstance || !reflect.DeepEqual(template.supportedRoles, []domain.Role{role}) {
				t.Fatalf("template %s/%s = %#v", family, role, template)
			}
			if family == FamilyZCode && template.transportArgvIndex != 6 {
				t.Fatalf("ZCode template %s = %#v", role, template)
			}
			if template.limits.Timeout() != productionDefaultProviderTimeout {
				t.Fatalf("%s template timeout = %s, want %s", family, template.limits.Timeout(), productionDefaultProviderTimeout)
			}
			if family == FamilyAGY {
				if template.transportArgvIndex != 13 || template.lifecycle == nil || !template.lifecycle.Valid() {
					t.Fatalf("AGY template %s lifecycle = %#v", role, template)
				}
			} else if template.lifecycle != nil {
				t.Fatalf("%s template %s has unexpected lifecycle", family, role)
			}
		}
	}
}

func TestProductionCandidateTemplatesBindDistinctFamilyTimeoutsToLimitsAndRuntimeDefinitions(t *testing.T) {
	profiles := []DiscoveredProviderProfile{
		{family: FamilyKimi, executable: "/private/bin/kimi", launcher: "/private/bin/kimi", argv: []string{"/private/bin/kimi"}, sha256: "kimi-sha", launcherSHA256: "kimi-sha", reason: "unqualified_discovery"},
		{family: FamilyZCode, executable: "/private/bin/node", launcher: ZCodeLauncher, argv: []string{"/private/bin/node", ZCodeLauncher}, sha256: "node-sha", launcherSHA256: "launcher-sha", reason: "unqualified_discovery"},
		{family: FamilyAGY, executable: "/private/bin/agy", launcher: "/private/bin/agy", argv: []string{"/private/bin/agy"}, sha256: "agy-sha", launcherSHA256: "agy-sha", reason: "unqualified_discovery"},
	}
	identities := map[Family]string{FamilyKimi: "kimi-policy", FamilyZCode: "zcode-policy", FamilyAGY: "agy-policy"}
	timeouts := map[Family]time.Duration{FamilyKimi: 10 * time.Minute, FamilyZCode: 30 * time.Minute, FamilyAGY: 15 * time.Minute}
	source, err := NewProductionQualifiedRunCandidateSourceWithPolicyIdentitiesAndRuntimeSettingsAndTimeouts(
		providercli.RuntimeBuilder{}, profiles, identities, "safe", "operator/model-v1", timeouts,
	)
	if err != nil {
		t.Fatal(err)
	}
	selection, err := NewRunSelection(domain.FixedRoleOrder(), nil)
	if err != nil {
		t.Fatal(err)
	}
	candidates, err := source.NewQualifiedRunCandidates(nil, authorityCaptured(t), selection)
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
	valid := map[Family]time.Duration{FamilyKimi: time.Minute, FamilyZCode: 30 * time.Minute, FamilyAGY: 60 * time.Minute}
	if err := validateProductionProviderTimeouts(valid); err != nil {
		t.Fatal(err)
	}
	for name, invalid := range map[string]map[Family]time.Duration{
		"missing":       {FamilyKimi: time.Minute, FamilyZCode: time.Minute},
		"unknown":       {FamilyKimi: time.Minute, FamilyZCode: time.Minute, FamilyAGY: time.Minute, Family("other"): time.Minute},
		"zero":          {FamilyKimi: 0, FamilyZCode: time.Minute, FamilyAGY: time.Minute},
		"below minimum": {FamilyKimi: time.Minute - time.Second, FamilyZCode: time.Minute, FamilyAGY: time.Minute},
		"above maximum": {FamilyKimi: time.Minute, FamilyZCode: 60*time.Minute + time.Second, FamilyAGY: time.Minute},
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateProductionProviderTimeouts(invalid); err == nil {
				t.Fatal("invalid provider timeout policy was accepted")
			}
		})
	}
}

func TestProductionCandidateTemplatesBindAGYPermissionMode(t *testing.T) {
	identities, err := defaultProductionPolicyIdentities(providercli.RuntimeBuilder{})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		mode string
		want int
	}{{"safe", 12}, {"dangerously-skip-permissions", 13}} {
		templates, err := productionCandidateTemplatesWithAGYPermissionMode(identities, test.mode)
		if err != nil {
			t.Fatal(err)
		}
		agyOffset := len(productionRolesForFamily(FamilyKimi)) + len(productionRolesForFamily(FamilyZCode))
		if got := templates[agyOffset].transportArgvIndex; got != test.want {
			t.Fatalf("AGY %s argv index = %d, want %d", test.mode, got, test.want)
		}
	}
}

func TestProductionCandidatesShardZCodeRolesAcrossSevenInstances(t *testing.T) {
	profiles := []DiscoveredProviderProfile{{
		family: FamilyZCode, executable: "/private/bin/node", launcher: ZCodeLauncher,
		argv: []string{"/private/bin/node", ZCodeLauncher}, sha256: "node-sha", launcherSHA256: "launcher-sha", reason: "unqualified_discovery",
	}}
	source, err := NewProductionQualifiedRunCandidateSource(providercli.RuntimeBuilder{}, profiles)
	if err != nil {
		t.Fatal(err)
	}
	selection, err := NewRunSelection(domain.FixedRoleOrder(), nil)
	if err != nil {
		t.Fatal(err)
	}
	candidates, err := source.NewQualifiedRunCandidates(nil, authorityCaptured(t), selection)
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
		if !reflect.DeepEqual(candidate.SupportedRoles, want[instance]) || candidate.Definition.Executable() != "/private/bin/node" || candidate.Definition.Launcher() != ZCodeLauncher || candidate.Definition.ConcurrencyKey().String() != instance {
			t.Fatalf("ZCode candidate %s = roles %v definition %#v", instance, candidate.SupportedRoles, candidate.Definition)
		}
		if candidate.Limits.Timeout() != productionDefaultProviderTimeout || candidate.Definition.Timeout() != productionDefaultProviderTimeout {
			t.Fatalf("ZCode candidate %s default timeouts = %s/%s, want %s", instance, candidate.Limits.Timeout(), candidate.Definition.Timeout(), productionDefaultProviderTimeout)
		}
	}
}
func TestProductionCandidatesUseInjectedPolicyIdentitiesWithClosedCoverage(t *testing.T) {
	profiles := []DiscoveredProviderProfile{
		{family: FamilyKimi, executable: "/private/bin/kimi", launcher: "/private/bin/kimi", argv: []string{"/private/bin/kimi"}, sha256: "kimi-sha", launcherSHA256: "kimi-sha", reason: "unqualified_discovery"},
		{family: FamilyZCode, executable: "/private/bin/node", launcher: ZCodeLauncher, argv: []string{"/private/bin/node", ZCodeLauncher}, sha256: "node-sha", launcherSHA256: "launcher-sha", reason: "unqualified_discovery"},
		{family: FamilyAGY, executable: "/private/bin/agy", launcher: "/private/bin/agy", argv: []string{"/private/bin/agy"}, sha256: "agy-sha", launcherSHA256: "agy-sha", reason: "unqualified_discovery"},
	}
	identities := map[Family]string{
		FamilyKimi:  "kimi-policy",
		FamilyZCode: "zcode-policy",
		FamilyAGY:   "agy-workspace-policy",
	}
	source, err := NewProductionQualifiedRunCandidateSourceWithPolicyIdentities(providercli.RuntimeBuilder{}, profiles, identities)
	if err != nil {
		t.Fatal(err)
	}
	selection, err := NewRunSelection([]domain.Role{domain.RoleLogic}, nil)
	if err != nil {
		t.Fatal(err)
	}
	candidates, err := source.NewQualifiedRunCandidates(nil, authorityCaptured(t), selection)
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
			FamilyKimi: "kimi-policy", FamilyZCode: "zcode-policy",
		},
		"empty": {
			FamilyKimi: "kimi-policy", FamilyZCode: "zcode-policy", FamilyAGY: "",
		},
		"unknown": {
			FamilyKimi: "kimi-policy", FamilyZCode: "zcode-policy", FamilyAGY: "agy-policy", Family("other"): "other-policy",
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewProductionQualifiedRunCandidateSourceWithPolicyIdentities(providercli.RuntimeBuilder{}, profiles, invalid); err == nil {
				t.Fatal("invalid policy coverage was accepted")
			}
		})
	}
}

func TestProductionCandidatesBindConfiguredKimiModel(t *testing.T) {
	profiles := []DiscoveredProviderProfile{{
		family: FamilyKimi, executable: "/private/bin/kimi", launcher: "/private/bin/kimi",
		argv: []string{"/private/bin/kimi"}, sha256: "kimi-sha", launcherSHA256: "kimi-sha", reason: "unqualified_discovery",
	}}
	source, err := NewProductionQualifiedRunCandidateSourceWithPolicyIdentitiesAndRuntimeSettings(
		providercli.RuntimeBuilder{}, profiles, map[Family]string{FamilyKimi: "kimi-policy", FamilyZCode: "zcode-policy", FamilyAGY: "agy-policy"},
		"safe", "operator/model-v1",
	)
	if err != nil {
		t.Fatal(err)
	}
	selection, err := NewRunSelection([]domain.Role{domain.RoleLogic}, nil)
	if err != nil {
		t.Fatal(err)
	}
	candidates, err := source.NewQualifiedRunCandidates(nil, authorityCaptured(t), selection)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 1 || candidates[0].Definition.KimiModel() != "operator/model-v1" {
		t.Fatalf("configured Kimi model was not bound: %#v", candidates)
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
		family: FamilyKimi, executable: "/private/bin/kimi", launcher: "/private/bin/kimi",
		argv: []string{"/private/bin/kimi"}, sha256: "sha", launcherSHA256: "sha", reason: "unqualified_discovery",
	}
	if err := validateStartupProfiles([]DiscoveredProviderProfile{profile}); err != nil {
		t.Fatal(err)
	}
	source, err := NewProductionQualifiedRunCandidateSource(providercli.RuntimeBuilder{}, []DiscoveredProviderProfile{profile})
	if err != nil {
		t.Fatal(err)
	}
	profile.argv[0] = "tampered"
	if got := source.profiles[0].Argv(); !reflect.DeepEqual(got, []string{"/private/bin/kimi"}) {
		t.Fatalf("source retained caller argv: %v", got)
	}
	profile.reason = "tampered"
	if err := validateStartupProfiles([]DiscoveredProviderProfile{profile}); err == nil {
		t.Fatal("tampered profile was accepted")
	}
}
func TestProductionCandidatesBindCurrentProfilesAndCapturedManifest(t *testing.T) {
	profiles := []DiscoveredProviderProfile{
		{family: FamilyKimi, executable: "/private/bin/kimi", launcher: "/private/bin/kimi", argv: []string{"/private/bin/kimi"}, sha256: "kimi-sha", launcherSHA256: "kimi-sha", reason: "unqualified_discovery"},
		{family: FamilyZCode, executable: "/private/bin/node", launcher: ZCodeLauncher, argv: []string{"/private/bin/node", ZCodeLauncher}, sha256: "node-sha", launcherSHA256: "launcher-sha", reason: "unqualified_discovery"},
		{family: FamilyAGY, executable: "/private/bin/agy", launcher: "/private/bin/agy", argv: []string{"/private/bin/agy"}, sha256: "agy-sha", launcherSHA256: "agy-sha", reason: "unqualified_discovery"},
	}
	source, err := NewProductionQualifiedRunCandidateSource(providercli.RuntimeBuilder{}, profiles)
	if err != nil {
		t.Fatal(err)
	}
	selection, err := NewRunSelection([]domain.Role{domain.RoleTesting, domain.RoleSecurity}, nil)
	if err != nil {
		t.Fatal(err)
	}
	candidates, err := source.NewQualifiedRunCandidates(nil, authorityCaptured(t), selection)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 6 {
		t.Fatalf("candidate count = %d, want 6", len(candidates))
	}
	ceilings := review.DefaultHarnessCeilings()
	wantRoles := map[string][]domain.Role{
		"kimi-security": {domain.RoleSecurity}, "kimi-testing": {domain.RoleTesting},
		"zcode-security": {domain.RoleSecurity}, "zcode-testing": {domain.RoleTesting},
		"agy-security": {domain.RoleSecurity}, "agy-testing": {domain.RoleTesting},
	}
	for _, candidate := range candidates {
		if candidate.Definition.Version() != "" || candidate.SnapshotManifest != "sha256:"+qualifierTestSHA {
			t.Fatalf("candidate = %#v", candidate)
		}
		if candidate.Limits.MaxStdoutBytes() > ceilings.MaxStdoutBytes() || candidate.Limits.MaxStderrBytes() > ceilings.MaxStderrBytes() {
			t.Fatalf("%s output limits = %d/%d, exceed default ceilings %d/%d",
				candidate.Definition.Family(), candidate.Limits.MaxStdoutBytes(), candidate.Limits.MaxStderrBytes(),
				ceilings.MaxStdoutBytes(), ceilings.MaxStderrBytes())
		}
		want := wantRoles[candidate.Definition.Instance()]
		if !reflect.DeepEqual(candidate.SupportedRoles, want) || candidate.BaseRole != want[0] {
			t.Fatalf("candidate roles/base = %v/%q", candidate.SupportedRoles, candidate.BaseRole)
		}
		environment := candidate.Definition.Environment()
		switch Family(candidate.Definition.Family()) {
		case FamilyAGY:
			if len(environment) != 1 || environment[0].Name() != "AGY_CLI_DISABLE_AUTO_UPDATE" || environment[0].Value() != "true" {
				t.Fatalf("AGY environment = %v, want only AGY_CLI_DISABLE_AUTO_UPDATE=true", environment)
			}
			environment[0] = ports.EnvironmentVariable{}
			if got := candidate.Definition.Environment(); len(got) != 1 || got[0].Name() != "AGY_CLI_DISABLE_AUTO_UPDATE" || got[0].Value() != "true" {
				t.Fatalf("AGY definition environment was mutable: %v", got)
			}
		default:
			if len(environment) != 0 {
				t.Fatalf("%s environment = %v, want none", candidate.Definition.Family(), environment)
			}
		}
	}
	for _, candidate := range candidates {
		if Family(candidate.Definition.Family()) == FamilyZCode {
			if got := candidate.Definition.BaseArgv(); !reflect.DeepEqual(got, []string{"/private/bin/node", ZCodeLauncher}) {
				t.Fatalf("ZCode argv = %v", got)
			}
			break
		}
	}
}
