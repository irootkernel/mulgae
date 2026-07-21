package reviewrun

import (
	"reflect"
	"testing"

	"github.com/irootkernel/kkachi-agent-review/internal/adapters/providercli"
	"github.com/irootkernel/kkachi-agent-review/internal/app/review"
	"github.com/irootkernel/kkachi-agent-review/internal/domain"
	"github.com/irootkernel/kkachi-agent-review/internal/ports"
)

func TestProductionCandidateTemplatesAreCanonicalAndAGYIsBounded(t *testing.T) {
	templates, err := trustedProductionCandidateTemplates(providercli.RuntimeBuilder{})
	if err != nil {
		t.Fatal(err)
	}
	if err := validateProductionCandidateTemplates(templates); err != nil {
		t.Fatal(err)
	}
	if got := []Family{templates[0].family, templates[1].family, templates[2].family}; !reflect.DeepEqual(got, Families()) {
		t.Fatalf("template family order = %v, want %v", got, Families())
	}
	if templates[0].lifecycle != nil || templates[1].lifecycle != nil || templates[2].lifecycle == nil || !templates[2].lifecycle.Valid() {
		t.Fatal("AGY lifecycle binding is not exclusive and valid")
	}
	if templates[1].transportArgvIndex != 6 {
		t.Fatalf("ZCode transport argv index = %d, want 6", templates[1].transportArgvIndex)
	}
	if templates[2].transportArgvIndex != 10 {
		t.Fatalf("default AGY transport argv index = %d, want safe-mode index 10", templates[2].transportArgvIndex)
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
	}{{"safe", 10}, {"dangerously-skip-permissions", 11}} {
		templates, err := productionCandidateTemplatesWithAGYPermissionMode(identities, test.mode)
		if err != nil {
			t.Fatal(err)
		}
		if got := templates[2].transportArgvIndex; got != test.want {
			t.Fatalf("AGY %s argv index = %d, want %d", test.mode, got, test.want)
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
	if len(candidates) != 3 {
		t.Fatalf("candidate count = %d, want 3", len(candidates))
	}
	ceilings := review.DefaultHarnessCeilings()
	for _, candidate := range candidates {
		if candidate.Definition.Version() != "" || candidate.SnapshotManifest != "sha256:"+qualifierTestSHA {
			t.Fatalf("candidate = %#v", candidate)
		}
		if candidate.Limits.MaxStdoutBytes() > ceilings.MaxStdoutBytes() || candidate.Limits.MaxStderrBytes() > ceilings.MaxStderrBytes() {
			t.Fatalf("%s output limits = %d/%d, exceed default ceilings %d/%d",
				candidate.Definition.Family(), candidate.Limits.MaxStdoutBytes(), candidate.Limits.MaxStderrBytes(),
				ceilings.MaxStdoutBytes(), ceilings.MaxStderrBytes())
		}
		if !reflect.DeepEqual(candidate.SupportedRoles, []domain.Role{domain.RoleSecurity, domain.RoleTesting}) || candidate.BaseRole != domain.RoleSecurity {
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
	if got := candidates[1].Definition.BaseArgv(); !reflect.DeepEqual(got, []string{"/private/bin/node", ZCodeLauncher}) {
		t.Fatalf("ZCode argv = %v", got)
	}
}
