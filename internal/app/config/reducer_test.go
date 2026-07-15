package config

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	adapterconfig "github.com/irootkernel/kkachi-agent-review/internal/adapters/config"
	"github.com/irootkernel/kkachi-agent-review/internal/builtin"
	"github.com/irootkernel/kkachi-agent-review/internal/domain"
	"github.com/irootkernel/kkachi-agent-review/internal/ports"
)

func TestResolveConfigurationAppliesEveryStrengtheningOperation(t *testing.T) {
	global := testGlobalConfig()
	global.Execution.WorkspaceAccess = string(WorkspaceProject)
	global.Roles.Maintainability.Enabled = false
	project := testProjectConfig()
	project.Execution = &adapterconfig.ProjectExecutionConfig{WorkspaceAccess: testString(string(WorkspaceNone))}
	project.Review = &adapterconfig.ProjectReviewConfig{
		RequiredRoles:    testStrings("maintainability"),
		RequestChangesOn: testStrings("medium", "high", "critical", "blocker"),
	}
	project.Roles = &adapterconfig.ProjectRolesConfig{
		Maintainability: &adapterconfig.ProjectRoleConfig{Enabled: testBool(true)},
	}
	project.Validation = &adapterconfig.ProjectValidationConfig{
		Evidence: &adapterconfig.ProjectEvidenceConfig{RequireVerifiedFor: testStrings("medium")},
	}
	project.Resources = &adapterconfig.ProjectResourcesConfig{
		RoleMaxInvocations: testInt(3),
		RunMaxInvocations:  testInt(18),
		RunTotalOutputCap:  testString("48MiB"),
	}
	project.CI = &adapterconfig.ProjectCIConfig{
		FailOnSeverity:      testStrings("medium", "high", "critical", "blocker"),
		DegradedReviewFails: testBool(true),
	}

	resolved, err := ResolveConfiguration(global, &project)
	if err != nil {
		t.Fatalf("ResolveConfiguration() error = %v", err)
	}

	if got, want := resolved.WorkspaceAccess(), WorkspaceNone; got != want {
		t.Errorf("WorkspaceAccess() = %q, want %q", got, want)
	}
	if got, want := resolved.RequiredRoles(), []domain.Role{domain.RoleLogic, domain.RoleSecurity, domain.RoleMaintainability}; !reflect.DeepEqual(got, want) {
		t.Errorf("RequiredRoles() = %v, want %v", got, want)
	}
	maintainability, exists := resolved.Role(domain.RoleMaintainability)
	if !exists || !maintainability.Enabled() || maintainability.Guide() != builtinRoleGuide(domain.RoleMaintainability) {
		t.Errorf("maintainability role = %#v, exists = %t", maintainability, exists)
	}
	if got, want := resolved.RequestChangesOn(), testSeverities(domain.SeverityMedium, domain.SeverityHigh, domain.SeverityCritical, domain.SeverityBlocker); !reflect.DeepEqual(got, want) {
		t.Errorf("RequestChangesOn() = %v, want %v", got, want)
	}
	if got, want := resolved.RequireVerifiedFor(), testSeverities(domain.SeverityMedium, domain.SeverityHigh, domain.SeverityCritical, domain.SeverityBlocker); !reflect.DeepEqual(got, want) {
		t.Errorf("RequireVerifiedFor() = %v, want %v", got, want)
	}
	if got, want := resolved.RoleMaxInvocations(), 3; got != want {
		t.Errorf("RoleMaxInvocations() = %d, want %d", got, want)
	}
	if got, want := resolved.RunMaxInvocations(), 18; got != want {
		t.Errorf("RunMaxInvocations() = %d, want %d", got, want)
	}
	if got, want := resolved.RunTotalOutputCapBytes(), int64(48<<20); got != want {
		t.Errorf("RunTotalOutputCapBytes() = %d, want %d", got, want)
	}
	if got, want := resolved.CIFailOnSeverity(), testSeverities(domain.SeverityMedium, domain.SeverityHigh, domain.SeverityCritical, domain.SeverityBlocker); !reflect.DeepEqual(got, want) {
		t.Errorf("CIFailOnSeverity() = %v, want %v", got, want)
	}
	if !resolved.DegradedReviewFails() {
		t.Error("DegradedReviewFails() = false, want true")
	}
	if got, ok := resolved.Provenance().Source("policy.roles.maintainability.enabled"); !ok || got != SourceProject {
		t.Errorf("maintainability provenance = %q, %t; want project, true", got, ok)
	}
}

func TestResolveConfigurationRejectsEachWeakening(t *testing.T) {
	global := testGlobalConfig()
	global.Execution.WorkspaceAccess = string(WorkspaceReadonlySnapshot)

	for _, role := range domain.FixedRoleOrder() {
		role := role
		t.Run("disable_"+string(role), func(t *testing.T) {
			project := testProjectConfig()
			project.Roles = disabledRoleProposal(role)
			assertAtomicReductionFailure(t, global, project)
		})
	}

	cases := []struct {
		name   string
		adjust func(*adapterconfig.ProjectConfig)
	}{
		{
			name: "expand_workspace",
			adjust: func(project *adapterconfig.ProjectConfig) {
				project.Execution = &adapterconfig.ProjectExecutionConfig{WorkspaceAccess: testString(string(WorkspaceProject))}
			},
		},
		{
			name: "weaken_request_changes_threshold",
			adjust: func(project *adapterconfig.ProjectConfig) {
				project.Review = &adapterconfig.ProjectReviewConfig{RequestChangesOn: testStrings("critical", "blocker")}
			},
		},
		{
			name: "noncanonical_request_changes_list",
			adjust: func(project *adapterconfig.ProjectConfig) {
				project.Review = &adapterconfig.ProjectReviewConfig{RequestChangesOn: testStrings("high", "blocker")}
			},
		},
		{
			name: "increase_role_invocations",
			adjust: func(project *adapterconfig.ProjectConfig) {
				project.Resources = &adapterconfig.ProjectResourcesConfig{RoleMaxInvocations: testInt(5)}
			},
		},
		{
			name: "increase_run_invocations",
			adjust: func(project *adapterconfig.ProjectConfig) {
				project.Resources = &adapterconfig.ProjectResourcesConfig{RunMaxInvocations: testInt(25)}
			},
		},
		{
			name: "increase_output_cap",
			adjust: func(project *adapterconfig.ProjectConfig) {
				project.Resources = &adapterconfig.ProjectResourcesConfig{RunTotalOutputCap: testString("65MiB")}
			},
		},
		{
			name: "weaken_ci_threshold",
			adjust: func(project *adapterconfig.ProjectConfig) {
				project.CI = &adapterconfig.ProjectCIConfig{FailOnSeverity: testStrings("critical", "blocker")}
			},
		},
		{
			name: "noncanonical_ci_list",
			adjust: func(project *adapterconfig.ProjectConfig) {
				project.CI = &adapterconfig.ProjectCIConfig{FailOnSeverity: testStrings("high", "blocker")}
			},
		},
		{
			name: "disable_degraded_review_enforcement",
			adjust: func(project *adapterconfig.ProjectConfig) {
				project.CI = &adapterconfig.ProjectCIConfig{DegradedReviewFails: testBool(false)}
			},
		},
		{
			name: "untrusted_base",
			adjust: func(project *adapterconfig.ProjectConfig) {
				project.TrustedBase = false
			},
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			project := testProjectConfig()
			testCase.adjust(&project)
			assertAtomicReductionFailure(t, global, project)
		})
	}
}

func TestResolveConfigurationRejectsMixedProposalAtomically(t *testing.T) {
	global := testGlobalConfig()
	project := testProjectConfig()
	project.Resources = &adapterconfig.ProjectResourcesConfig{
		RoleMaxInvocations: testInt(3),
		RunMaxInvocations:  testInt(25),
	}

	resolved, err := ResolveConfiguration(global, &project)
	if err == nil {
		t.Fatal("ResolveConfiguration() error = nil, want atomic rejection")
	}
	var reductionError *ReductionError
	if !errors.As(err, &reductionError) {
		t.Fatalf("error type = %T, want *ReductionError", err)
	}
	if len(reductionError.Diagnostics()) == 0 {
		t.Fatal("ReductionError has no typed diagnostics")
	}
	if !reflect.DeepEqual(resolved, ResolvedConfig{}) {
		t.Errorf("resolved = %#v, want zero value after atomic rejection", resolved)
	}
}

func TestResolveConfigurationCanonicalizesSetOrder(t *testing.T) {
	globalA := testGlobalConfig()
	globalA.Trust.RequiredRoles = []string{"testing", "logic", "security"}
	globalA.Validation.Evidence.RequireVerifiedFor = []string{"blocker", "high", "critical"}
	globalB := testGlobalConfig()
	globalB.Trust.RequiredRoles = []string{"security", "logic", "testing"}
	globalB.Validation.Evidence.RequireVerifiedFor = []string{"critical", "blocker", "high"}

	projectA := testProjectConfig()
	projectA.Review = &adapterconfig.ProjectReviewConfig{RequiredRoles: testStrings("documentation", "product")}
	projectA.Validation = &adapterconfig.ProjectValidationConfig{
		Evidence: &adapterconfig.ProjectEvidenceConfig{RequireVerifiedFor: testStrings("medium", "low")},
	}
	projectB := testProjectConfig()
	projectB.Review = &adapterconfig.ProjectReviewConfig{RequiredRoles: testStrings("product", "documentation")}
	projectB.Validation = &adapterconfig.ProjectValidationConfig{
		Evidence: &adapterconfig.ProjectEvidenceConfig{RequireVerifiedFor: testStrings("low", "medium")},
	}

	resolvedA, err := ResolveConfiguration(globalA, &projectA)
	if err != nil {
		t.Fatalf("first resolution error = %v", err)
	}
	resolvedB, err := ResolveConfiguration(globalB, &projectB)
	if err != nil {
		t.Fatalf("second resolution error = %v", err)
	}
	if got, want := resolvedA.RequiredRoles(), resolvedB.RequiredRoles(); !reflect.DeepEqual(got, want) {
		t.Errorf("required roles differ by input ordering: %v != %v", got, want)
	}
	if got, want := resolvedA.RequireVerifiedFor(), resolvedB.RequireVerifiedFor(); !reflect.DeepEqual(got, want) {
		t.Errorf("evidence requirements differ by input ordering: %v != %v", got, want)
	}
}

func TestParseOutputCapExactIECValues(t *testing.T) {
	valid := map[string]int64{
		"1KiB":    1 << 10,
		"1024KiB": 1 << 20,
		"64MiB":   64 << 20,
		"1GiB":    1 << 30,
	}
	for input, want := range valid {
		got, err := ParseOutputCap(input)
		if err != nil || got != want {
			t.Errorf("ParseOutputCap(%q) = %d, %v; want %d, nil", input, got, err, want)
		}
	}
	for _, input := range []string{"0KiB", "01KiB", "1KB", "1.5MiB", "2GiB", " 1MiB", "1MiB "} {
		if _, err := ParseOutputCap(input); err == nil {
			t.Errorf("ParseOutputCap(%q) error = nil, want rejection", input)
		}
	}
}

func TestResolveConfigurationPreservesFixedFloor(t *testing.T) {
	global := testGlobalConfig()
	resolved, err := ResolveConfiguration(global, nil)
	if err != nil {
		t.Fatalf("ResolveConfiguration() error = %v", err)
	}
	if got, want := resolved.RequiredRoles(), []domain.Role{domain.RoleLogic, domain.RoleSecurity}; !reflect.DeepEqual(got, want) {
		t.Errorf("RequiredRoles() = %v, want %v", got, want)
	}
	if got, want := resolved.Provenance().Sources("policy.roles.logic.required"), []FieldSource{SourceBuiltin, SourceGlobal}; !reflect.DeepEqual(got, want) {
		t.Errorf("logic required provenance = %v, want %v", got, want)
	}
	for _, role := range domain.FixedRoleOrder() {
		if got, want := resolved.Provenance().Sources("policy.roles."+string(role)+".enabled"), []FieldSource{SourceBuiltin, SourceGlobal}; !reflect.DeepEqual(got, want) {
			t.Errorf("%s enabled provenance = %v, want %v", role, got, want)
		}
	}

	global.Trust.RequiredRoles = nil
	assertGlobalReductionFailure(t, global)

	global = testGlobalConfig()
	global.Roles.Logic.Enabled = false
	assertGlobalReductionFailure(t, global)
}

func TestResolveConfigurationValidatesRequiredRolesAtEachReductionBoundary(t *testing.T) {
	t.Run("global_required_role_cannot_be_repaired_by_project", func(t *testing.T) {
		global := testGlobalConfig()
		global.Roles.Maintainability.Enabled = false
		global.Trust.RequiredRoles = append(global.Trust.RequiredRoles, string(domain.RoleMaintainability))
		project := testProjectConfig()
		project.Roles = &adapterconfig.ProjectRolesConfig{
			Maintainability: &adapterconfig.ProjectRoleConfig{Enabled: testBool(true)},
		}

		_, err := ResolveConfiguration(global, &project)
		assertReductionDiagnostic(t, err, adapterconfig.LayerGlobal, "$.trust.required_roles", "required_role_disabled")
	})
	t.Run("global_required_role_restatement_is_not_misattributed_to_project", func(t *testing.T) {
		global := testGlobalConfig()
		global.Roles.Maintainability.Enabled = false
		global.Trust.RequiredRoles = append(global.Trust.RequiredRoles, string(domain.RoleMaintainability))
		project := testProjectConfig()
		project.Review = &adapterconfig.ProjectReviewConfig{
			RequiredRoles: testStrings(string(domain.RoleMaintainability)),
		}

		_, err := ResolveConfiguration(global, &project)
		assertReductionDiagnostic(t, err, adapterconfig.LayerGlobal, "$.trust.required_roles", "required_role_disabled")
		assertNoReductionDiagnostic(t, err, adapterconfig.LayerProject, "$.review.required_roles", "required_role_disabled")
	})

	t.Run("project_added_required_role_is_checked_after_project_application", func(t *testing.T) {
		global := testGlobalConfig()
		global.Roles.Maintainability.Enabled = false
		project := testProjectConfig()
		project.Review = &adapterconfig.ProjectReviewConfig{
			RequiredRoles: testStrings(string(domain.RoleMaintainability)),
		}

		_, err := ResolveConfiguration(global, &project)
		assertReductionDiagnostic(t, err, adapterconfig.LayerProject, "$.review.required_roles", "required_role_disabled")
	})
}

func TestGlobalWorkspaceMayExpandBuiltinNoneAndProjectOnlyIntersects(t *testing.T) {
	// WorkspaceNone is the B default. G deliberately establishes its own
	// ceiling, while P may only intersect that global ceiling.
	for _, globalAccess := range []WorkspaceAccess{WorkspaceNone, WorkspaceReadonlySnapshot, WorkspaceProject} {
		for _, projectAccess := range []WorkspaceAccess{WorkspaceNone, WorkspaceReadonlySnapshot, WorkspaceProject} {
			t.Run(string(globalAccess)+"_"+string(projectAccess), func(t *testing.T) {
				global := testGlobalConfig()
				global.Execution.WorkspaceAccess = string(globalAccess)
				project := testProjectConfig()
				project.Execution = &adapterconfig.ProjectExecutionConfig{WorkspaceAccess: testString(string(projectAccess))}
				resolved, err := ResolveConfiguration(global, &project)
				if projectAccess.Rank() > globalAccess.Rank() {
					if err == nil {
						t.Fatal("ResolveConfiguration() error = nil, want workspace-expansion rejection")
					}
					if !reflect.DeepEqual(resolved, ResolvedConfig{}) {
						t.Errorf("resolved = %#v, want zero value", resolved)
					}
					return
				}
				if err != nil {
					t.Fatalf("ResolveConfiguration() error = %v", err)
				}
				want, err := globalAccess.Intersect(projectAccess)
				if err != nil {
					t.Fatalf("Intersect() error = %v", err)
				}
				if got := resolved.WorkspaceAccess(); got != want {
					t.Errorf("WorkspaceAccess() = %q, want %q", got, want)
				}
			})
		}
	}
}

func TestProvidersAndViewsAreDefensivelyCopied(t *testing.T) {
	optional := true
	global := testGlobalConfig()
	global.Providers = adapterconfig.ProvidersConfig{
		"kimi-main": {
			Driver:         "kimi",
			Status:         "unverified",
			Bin:            "/private/bin/kimi",
			Args:           []string{"--token", "do-not-copy"},
			ConcurrencyKey: "kimi-main",
		},
		"codex-optional": {
			Driver:         "codex",
			Status:         "unverified",
			Optional:       &optional,
			Bin:            "codex",
			ConcurrencyKey: "codex-optional",
		},
	}
	resolved, err := ResolveConfiguration(global, nil)
	if err != nil {
		t.Fatalf("ResolveConfiguration() error = %v", err)
	}

	global.Providers["kimi-main"] = adapterconfig.ProviderConfig{Status: "promoted"}
	providers := resolved.Providers()
	provider := providers["kimi-main"]
	provider.Args[0] = "mutated"
	providers["kimi-main"] = provider

	stored, exists := resolved.Provider("kimi-main")
	if !exists {
		t.Fatal("Provider(kimi-main) does not exist")
	}
	if got, want := stored.Status, "unverified"; got != want {
		t.Errorf("stored provider status = %q, want %q", got, want)
	}
	if got, want := stored.Args[0], "--token"; got != want {
		t.Errorf("stored provider args = %q, want %q", got, want)
	}
	optionalProvider, exists := resolved.Provider("codex-optional")
	if !exists || optionalProvider.Optional == nil || !*optionalProvider.Optional {
		t.Errorf("optional provider = %#v, exists = %t; want explicit optional true", optionalProvider, exists)
	}
	if exists && optionalProvider.Optional != nil {
		*optionalProvider.Optional = false
		storedOptional, storedExists := resolved.Provider("codex-optional")
		if !storedExists || storedOptional.Optional == nil || !*storedOptional.Optional {
			t.Error("mutating returned optional pointer changed resolved provider")
		}
	}
	promoted := testGlobalConfig()
	promoted.Providers = adapterconfig.ProvidersConfig{
		"kimi-main": {Driver: "kimi", Status: "ready", ConcurrencyKey: "kimi-main"},
	}
	if _, err := ResolveConfiguration(promoted, nil); err == nil {
		t.Error("ResolveConfiguration() accepted configuration-only provider readiness promotion")
	}
	invalidID := testGlobalConfig()
	invalidID.Providers = adapterconfig.ProvidersConfig{
		"Bad ID": {Driver: "kimi", Status: "unverified", ConcurrencyKey: "kimi-main"},
	}
	if _, err := ResolveConfiguration(invalidID, nil); err == nil {
		t.Error("ResolveConfiguration() accepted a noncanonical provider ID")
	}
	nonOptional := testGlobalConfig()
	nonOptional.Providers = adapterconfig.ProvidersConfig{
		"claude-main": {Driver: "claude", Status: "unverified", ConcurrencyKey: "claude-main"},
	}
	if _, err := ResolveConfiguration(nonOptional, nil); err == nil {
		t.Error("ResolveConfiguration() accepted a non-optional claude provider")
	}
}
func TestResolveConfigurationRejectsNoncanonicalTypedConcurrencyKeys(t *testing.T) {
	t.Run("accepts_canonical_64_byte_key", func(t *testing.T) {
		global := testGlobalConfig()
		global.Providers = adapterconfig.ProvidersConfig{
			"kimi-main": {Driver: "kimi", Status: "unverified", ConcurrencyKey: strings.Repeat("a", 64)},
		}
		if _, err := ResolveConfiguration(global, nil); err != nil {
			t.Fatalf("ResolveConfiguration() error = %v", err)
		}
	})

	for _, testCase := range []struct {
		name string
		key  string
	}{
		{name: "path_separator", key: "lane/other"},
		{name: "control_character", key: "lane\nother"},
		{name: "noncanonical_uppercase", key: "Kimi-Main"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			global := testGlobalConfig()
			global.Providers = adapterconfig.ProvidersConfig{
				"kimi-main": {Driver: "kimi", Status: "unverified", ConcurrencyKey: testCase.key},
			}

			_, err := ResolveConfiguration(global, nil)
			assertReductionDiagnostic(t, err, adapterconfig.LayerGlobal, "$.providers.kimi-main.concurrency_key", "invalid_concurrency_key")
		})
	}
}

func TestProvenanceRecordsBuiltinGlobalAndProject(t *testing.T) {
	global := testGlobalConfig()
	project := testProjectConfig()
	project.Review = &adapterconfig.ProjectReviewConfig{RequiredRoles: testStrings("testing")}
	project.Roles = &adapterconfig.ProjectRolesConfig{
		Testing: &adapterconfig.ProjectRoleConfig{Enabled: testBool(true)},
	}
	project.Resources = &adapterconfig.ProjectResourcesConfig{RunMaxInvocations: testInt(20)}

	resolved, err := ResolveConfiguration(global, &project)
	if err != nil {
		t.Fatalf("ResolveConfiguration() error = %v", err)
	}
	provenance := resolved.Provenance()
	if got, ok := provenance.Source("policy.roles.logic.required"); !ok || got != SourceGlobal {
		t.Errorf("logic required provenance = %q, %t; want global, true", got, ok)
	}
	if got, ok := provenance.Source("policy.roles.testing.required"); !ok || got != SourceProject {
		t.Errorf("testing required provenance = %q, %t; want project, true", got, ok)
	}
	if got, ok := provenance.Source("policy.roles.testing.enabled"); !ok || got != SourceProject {
		t.Errorf("testing enabled provenance = %q, %t; want project, true", got, ok)
	}
	if got, ok := provenance.Source("policy.run_max_invocations"); !ok || got != SourceProject {
		t.Errorf("run limit provenance = %q, %t; want project, true", got, ok)
	}
	if sources := provenance.Sources("policy.roles.logic.required"); !reflect.DeepEqual(sources, []FieldSource{SourceBuiltin, SourceGlobal}) {
		t.Errorf("logic sources = %v, want [builtin global]", sources)
	}
}
func TestResolveConfigurationRejectsIncompleteOrWeakerGlobalPolicy(t *testing.T) {
	cases := []struct {
		name   string
		adjust func(*adapterconfig.GlobalConfig)
	}{
		{
			name: "omitted_request_changes_threshold",
			adjust: func(global *adapterconfig.GlobalConfig) {
				global.Review.RequestChangesOn = nil
			},
		},
		{
			name: "weaker_request_changes_threshold",
			adjust: func(global *adapterconfig.GlobalConfig) {
				global.Review.RequestChangesOn = []string{"critical", "blocker"}
			},
		},
		{
			name: "omitted_verified_evidence",
			adjust: func(global *adapterconfig.GlobalConfig) {
				global.Validation.Evidence.RequireVerifiedFor = nil
			},
		},
		{
			name: "weaker_verified_evidence",
			adjust: func(global *adapterconfig.GlobalConfig) {
				global.Validation.Evidence.RequireVerifiedFor = []string{"critical", "blocker"}
			},
		},
		{
			name: "omitted_ci_threshold",
			adjust: func(global *adapterconfig.GlobalConfig) {
				global.CI.FailOnSeverity = nil
			},
		},
		{
			name: "weaker_ci_threshold",
			adjust: func(global *adapterconfig.GlobalConfig) {
				global.CI.FailOnSeverity = []string{"critical", "blocker"}
			},
		},
		{
			name: "missing_security_required_role",
			adjust: func(global *adapterconfig.GlobalConfig) {
				global.Trust.RequiredRoles = []string{"logic"}
			},
		},
		{
			name: "disabled_strict_validation",
			adjust: func(global *adapterconfig.GlobalConfig) {
				global.Validation.RejectUnknownFields = false
			},
		},
		{
			name: "disabled_secret_redaction",
			adjust: func(global *adapterconfig.GlobalConfig) {
				global.Safety.RedactSecrets = false
			},
		},
		{
			name: "nonblocking_secret_output",
			adjust: func(global *adapterconfig.GlobalConfig) {
				global.Safety.SecretOutputPolicy = "redact"
			},
		},
		{
			name: "disabled_mutation_detection",
			adjust: func(global *adapterconfig.GlobalConfig) {
				global.Safety.MutationDetection = false
			},
		},
		{
			name: "project_prompt_override",
			adjust: func(global *adapterconfig.GlobalConfig) {
				global.Trust.ProjectPromptOverrides = true
			},
		},
		{
			name: "unsupported_project_prompt_source",
			adjust: func(global *adapterconfig.GlobalConfig) {
				global.Trust.ProjectPromptSource = "working_tree"
			},
		},
		{
			name: "project_provider_command",
			adjust: func(global *adapterconfig.GlobalConfig) {
				global.Trust.AllowProjectProviderCommands = true
			},
		},
		{
			name: "project_shell",
			adjust: func(global *adapterconfig.GlobalConfig) {
				global.Trust.AllowProjectShell = true
			},
		},
		{
			name: "role_limit_above_ceiling",
			adjust: func(global *adapterconfig.GlobalConfig) {
				global.Resources.RoleMaxInvocations = builtinRoleMaxInvocations + 1
			},
		},
		{
			name: "run_limit_above_ceiling",
			adjust: func(global *adapterconfig.GlobalConfig) {
				global.Resources.RunMaxInvocations = builtinRunMaxInvocations + 1
			},
		},
		{
			name: "output_cap_above_ceiling",
			adjust: func(global *adapterconfig.GlobalConfig) {
				global.Resources.RunTotalOutputCap = "65MiB"
			},
		},
		{
			name: "degraded_reviews_do_not_fail",
			adjust: func(global *adapterconfig.GlobalConfig) {
				global.CI.DegradedReviewFails = false
			},
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			global := testGlobalConfig()
			testCase.adjust(&global)
			assertGlobalReductionFailure(t, global)
		})
	}
}

func TestResolveConfigurationAcceptsStrongerGlobalPolicy(t *testing.T) {
	global := testGlobalConfig()
	global.Execution.WorkspaceAccess = string(WorkspaceProject)
	global.Review.RequestChangesOn = []string{"medium", "high", "critical", "blocker"}
	global.Validation.Evidence.RequireVerifiedFor = []string{"medium", "high", "critical", "blocker"}
	global.Resources.RoleMaxInvocations = 3
	global.Resources.RunMaxInvocations = 20
	global.Resources.RunTotalOutputCap = "48MiB"
	global.CI.FailOnSeverity = []string{"medium", "high", "critical", "blocker"}

	resolved, err := ResolveConfiguration(global, nil)
	if err != nil {
		t.Fatalf("ResolveConfiguration() error = %v", err)
	}
	if got, want := resolved.WorkspaceAccess(), WorkspaceProject; got != want {
		t.Errorf("WorkspaceAccess() = %q, want %q", got, want)
	}
	if got, want := resolved.RequestChangesOn(), testSeverities(domain.SeverityMedium, domain.SeverityHigh, domain.SeverityCritical, domain.SeverityBlocker); !reflect.DeepEqual(got, want) {
		t.Errorf("RequestChangesOn() = %v, want %v", got, want)
	}
	if got, want := resolved.RequireVerifiedFor(), testSeverities(domain.SeverityMedium, domain.SeverityHigh, domain.SeverityCritical, domain.SeverityBlocker); !reflect.DeepEqual(got, want) {
		t.Errorf("RequireVerifiedFor() = %v, want %v", got, want)
	}
	if got, want := resolved.RoleMaxInvocations(), 3; got != want {
		t.Errorf("RoleMaxInvocations() = %d, want %d", got, want)
	}
	if got, want := resolved.RunMaxInvocations(), 20; got != want {
		t.Errorf("RunMaxInvocations() = %d, want %d", got, want)
	}
	if got, want := resolved.RunTotalOutputCapBytes(), int64(48<<20); got != want {
		t.Errorf("RunTotalOutputCapBytes() = %d, want %d", got, want)
	}
	if got, want := resolved.CIFailOnSeverity(), testSeverities(domain.SeverityMedium, domain.SeverityHigh, domain.SeverityCritical, domain.SeverityBlocker); !reflect.DeepEqual(got, want) {
		t.Errorf("CIFailOnSeverity() = %v, want %v", got, want)
	}
}

func TestResolveConfigurationRejectsGuideReplacementAndAcceptsBuiltinNoOp(t *testing.T) {
	t.Run("replacement", func(t *testing.T) {
		global := testGlobalConfig()
		project := testProjectConfig()
		project.Roles = &adapterconfig.ProjectRolesConfig{
			Logic: &adapterconfig.ProjectRoleConfig{Guide: testString("guides/logic.md")},
		}
		assertAtomicReductionFailure(t, global, project)
	})

	t.Run("builtin_no_op", func(t *testing.T) {
		global := testGlobalConfig()
		project := testProjectConfig()
		project.Roles = &adapterconfig.ProjectRolesConfig{
			Logic: &adapterconfig.ProjectRoleConfig{Guide: testString(builtinRoleGuide(domain.RoleLogic))},
		}
		resolved, err := ResolveConfiguration(global, &project)
		if err != nil {
			t.Fatalf("ResolveConfiguration() error = %v", err)
		}
		role, exists := resolved.Role(domain.RoleLogic)
		if !exists || role.Guide() != builtinRoleGuide(domain.RoleLogic) {
			t.Errorf("logic role = %#v, exists = %t", role, exists)
		}
		if sources := resolved.Provenance().Sources("policy.roles.logic.guide"); sources != nil {
			t.Errorf("guide provenance = %v, want absent", sources)
		}
	})
}

func TestResolveConfigurationUsesExactBuiltInCeilings(t *testing.T) {
	resolved, err := ResolveConfiguration(testGlobalConfig(), nil)
	if err != nil {
		t.Fatalf("ResolveConfiguration() error = %v", err)
	}
	if got, want := resolved.RoleMaxInvocations(), builtinRoleMaxInvocations; got != want {
		t.Errorf("RoleMaxInvocations() = %d, want %d", got, want)
	}
	if got, want := resolved.RunMaxInvocations(), builtinRunMaxInvocations; got != want {
		t.Errorf("RunMaxInvocations() = %d, want %d", got, want)
	}
	if got, want := resolved.RunTotalOutputCapBytes(), int64(builtinRunTotalOutputCapBytes); got != want {
		t.Errorf("RunTotalOutputCapBytes() = %d, want %d", got, want)
	}
}

func TestResolveConfigurationRecordsBaselineProvenanceInOrder(t *testing.T) {
	global := testGlobalConfig()
	project := testProjectConfig()
	project.Execution = &adapterconfig.ProjectExecutionConfig{WorkspaceAccess: testString(string(WorkspaceNone))}
	project.Review = &adapterconfig.ProjectReviewConfig{
		RequiredRoles:    testStrings("logic"),
		RequestChangesOn: testStrings("medium", "high", "critical", "blocker"),
	}
	project.Roles = &adapterconfig.ProjectRolesConfig{
		Logic: &adapterconfig.ProjectRoleConfig{Enabled: testBool(true)},
	}
	project.Validation = &adapterconfig.ProjectValidationConfig{
		Evidence: &adapterconfig.ProjectEvidenceConfig{RequireVerifiedFor: testStrings("medium")},
	}
	project.Resources = &adapterconfig.ProjectResourcesConfig{
		RoleMaxInvocations: testInt(3),
		RunMaxInvocations:  testInt(20),
		RunTotalOutputCap:  testString("48MiB"),
	}
	project.CI = &adapterconfig.ProjectCIConfig{
		FailOnSeverity:      testStrings("medium", "high", "critical", "blocker"),
		DegradedReviewFails: testBool(true),
	}

	resolved, err := ResolveConfiguration(global, &project)
	if err != nil {
		t.Fatalf("ResolveConfiguration() error = %v", err)
	}
	for _, field := range []string{
		"policy.roles.logic.enabled",
		"policy.roles.logic.required",
		"policy.required_roles",
		"policy.workspace_access",
		"policy.request_changes_on",
		"policy.require_verified_for",
		"policy.role_max_invocations",
		"policy.run_max_invocations",
		"policy.run_total_output_cap_bytes",
		"policy.ci_fail_on_severity",
		"policy.degraded_review_fails",
	} {
		if got, want := resolved.Provenance().Sources(field), []FieldSource{SourceBuiltin, SourceGlobal, SourceProject}; !reflect.DeepEqual(got, want) {
			t.Errorf("Provenance().Sources(%q) = %v, want %v", field, got, want)
		}
	}
}

func TestResolveConfigurationAcceptsAuthoritativeEmbeddedGlobal(t *testing.T) {
	catalog := builtin.NewCatalog()
	id, err := ports.ParseAssetID("defaults:global-config")
	if err != nil {
		t.Fatal(err)
	}
	_, raw, err := catalog.Read(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	global, err := adapterconfig.DecodeGlobal("defaults:global-config", raw)
	if err != nil {
		t.Fatalf("DecodeGlobal(authoritative default) error = %v", err)
	}
	resolved, err := ResolveConfiguration(global, nil)
	if err != nil {
		t.Fatalf("ResolveConfiguration(authoritative default) error = %v", err)
	}
	for _, id := range []string{"codex-optional", "claude-optional"} {
		provider, exists := resolved.Provider(id)
		if !exists || provider.Optional == nil || !*provider.Optional || provider.Status != "" {
			t.Errorf("Provider(%q) = %#v, exists = %t; want optional unassigned definition", id, provider, exists)
		}
		if got, want := resolved.Provenance().Sources("providers."+id+".status"), []FieldSource{SourceGlobal}; !reflect.DeepEqual(got, want) {
			t.Errorf("provider provenance = %v, want %v", got, want)
		}
	}
}

func assertAtomicReductionFailure(t *testing.T, global adapterconfig.GlobalConfig, project adapterconfig.ProjectConfig) {
	t.Helper()
	resolved, err := ResolveConfiguration(global, &project)
	if err == nil {
		t.Fatal("ResolveConfiguration() error = nil, want rejection")
	}
	var reductionError *ReductionError
	if !errors.As(err, &reductionError) {
		t.Fatalf("error type = %T, want *ReductionError", err)
	}
	if len(reductionError.Diagnostics()) == 0 {
		t.Fatal("ReductionError has no diagnostics")
	}
	if !reflect.DeepEqual(resolved, ResolvedConfig{}) {
		t.Errorf("resolved = %#v, want zero value", resolved)
	}
}
func assertGlobalReductionFailure(t *testing.T, global adapterconfig.GlobalConfig) {
	t.Helper()
	resolved, err := ResolveConfiguration(global, nil)
	if err == nil {
		t.Fatal("ResolveConfiguration() error = nil, want rejection")
	}
	var reductionError *ReductionError
	if !errors.As(err, &reductionError) {
		t.Fatalf("error type = %T, want *ReductionError", err)
	}
	if len(reductionError.Diagnostics()) == 0 {
		t.Fatal("ReductionError has no diagnostics")
	}
	if !reflect.DeepEqual(resolved, ResolvedConfig{}) {
		t.Errorf("resolved = %#v, want zero value", resolved)
	}
}
func assertReductionDiagnostic(t *testing.T, err error, layer adapterconfig.Layer, path, code string) {
	t.Helper()
	reductionError, ok := AsReductionError(err)
	if !ok {
		t.Fatalf("error = %v, want *ReductionError", err)
	}
	for _, diagnostic := range reductionError.Diagnostics() {
		if diagnostic.Layer == layer && diagnostic.Path == path && diagnostic.Code == code {
			return
		}
	}
	t.Errorf("diagnostics = %#v, want %s %s [%s]", reductionError.Diagnostics(), layer, path, code)
}
func assertNoReductionDiagnostic(t *testing.T, err error, layer adapterconfig.Layer, path, code string) {
	t.Helper()
	reductionError, ok := AsReductionError(err)
	if !ok {
		t.Fatalf("error = %v, want *ReductionError", err)
	}
	for _, diagnostic := range reductionError.Diagnostics() {
		if diagnostic.Layer == layer && diagnostic.Path == path && diagnostic.Code == code {
			t.Errorf("diagnostics = %#v, did not want %s %s [%s]", reductionError.Diagnostics(), layer, path, code)
			return
		}
	}
}

func disabledRoleProposal(role domain.Role) *adapterconfig.ProjectRolesConfig {
	disabled := &adapterconfig.ProjectRoleConfig{Enabled: testBool(false)}
	switch role {
	case domain.RoleLogic:
		return &adapterconfig.ProjectRolesConfig{Logic: disabled}
	case domain.RoleSecurity:
		return &adapterconfig.ProjectRolesConfig{Security: disabled}
	case domain.RoleMaintainability:
		return &adapterconfig.ProjectRolesConfig{Maintainability: disabled}
	case domain.RoleProduct:
		return &adapterconfig.ProjectRolesConfig{Product: disabled}
	case domain.RoleDocumentation:
		return &adapterconfig.ProjectRolesConfig{Documentation: disabled}
	case domain.RoleTesting:
		return &adapterconfig.ProjectRolesConfig{Testing: disabled}
	default:
		return nil
	}
}

func testGlobalConfig() adapterconfig.GlobalConfig {
	return adapterconfig.GlobalConfig{
		Version: 1,
		Runtime: adapterconfig.RuntimeConfig{
			Home:           "/Users/tester",
			Path:           adapterconfig.RuntimePathConfig{Inherit: true, Prepend: []string{"/opt/bin"}, Append: []string{"/usr/bin"}},
			EnvAllowlist:   []string{"HOME", "PATH"},
			MaxActiveLanes: 3,
		},
		Execution: adapterconfig.ExecutionConfig{
			Strategy:             "primary_with_fallback",
			WorkspaceAccess:      string(WorkspaceReadonlySnapshot),
			CrossProcessLaneLock: true,
		},
		Roles: adapterconfig.RolesConfig{
			Logic:           adapterconfig.RoleConfig{Enabled: true},
			Security:        adapterconfig.RoleConfig{Enabled: true},
			Maintainability: adapterconfig.RoleConfig{Enabled: true},
			Product:         adapterconfig.RoleConfig{Enabled: true},
			Documentation:   adapterconfig.RoleConfig{Enabled: true},
			Testing:         adapterconfig.RoleConfig{Enabled: true},
		},
		Review: adapterconfig.ReviewConfig{RequestChangesOn: []string{"high", "critical", "blocker"}},
		Validation: adapterconfig.ValidationConfig{
			RejectUnknownFields:     true,
			RejectEmptyStrings:      true,
			RejectPlaceholderValues: true,
			Evidence:                adapterconfig.EvidenceConfig{RequireVerifiedFor: []string{"high", "critical", "blocker"}},
			Repair:                  adapterconfig.RepairConfig{Enabled: true, MaxAttempts: 1, SameProvider: true},
		},
		Trust: adapterconfig.TrustConfig{
			RequiredRoles:                []string{"logic", "security"},
			ProjectConfig:                "trusted_base_only",
			ProjectPromptOverrides:       false,
			ProjectPromptSource:          "target_base",
			AllowProjectProviderCommands: false,
			AllowProjectShell:            false,
		},
		Resources: adapterconfig.ResourcesConfig{
			PrimaryRepairAttempts:  1,
			FallbackRepairAttempts: 1,
			RoleMaxInvocations:     4,
			RunMaxInvocations:      24,
			RunTotalOutputCap:      "64MiB",
		},
		CI: adapterconfig.CIConfig{FailOnSeverity: []string{"high", "critical", "blocker"}, DegradedReviewFails: true},
		Artifacts: adapterconfig.ArtifactsConfig{
			Root:              ".kar",
			DirectoryMode:     "0700",
			FileMode:          "0600",
			PreserveRawOutput: true,
		},
		Safety: adapterconfig.SafetyConfig{RedactSecrets: true, SecretOutputPolicy: "block", MutationDetection: true},
	}
}

func testProjectConfig() adapterconfig.ProjectConfig {
	return adapterconfig.ProjectConfig{
		Version:     1,
		TrustedBase: true,
		Project: adapterconfig.ProjectMetadata{
			Name:    "test-project",
			Root:    ".",
			Context: ".kar/context.md",
		},
	}
}

func testBool(value bool) *bool { return &value }

func testInt(value int) *int { return &value }

func testString(value string) *string { return &value }

func testStrings(values ...string) *[]string { return &values }

func testSeverities(values ...domain.Severity) []domain.Severity { return values }
