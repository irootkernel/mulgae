package doctor

import (
	"testing"
	"time"
)

func TestLocalDoctorResultValidateEnforcesOfflineReadiness(t *testing.T) {
	valid := validLocalDoctorResult()
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid projection rejected: %v", err)
	}

	tests := map[string]func(*LocalDoctorResult){
		"noncanonical configured IDs":     func(result *LocalDoctorResult) { result.ConfiguredProviderIDs = []string{"grok", "zcode"} },
		"configured identity mismatch":    func(result *LocalDoctorResult) { result.ProviderInventory[0].Configured = false },
		"eligible without compatible CLI": func(result *LocalDoctorResult) { result.ProviderInventory[0].CLICompatible.Eligibility = "ineligible" },
		"assignment readiness mismatch": func(result *LocalDoctorResult) {
			result.Readiness = LocalReadiness{State: "unverified", ExitCode: 4, ReasonCodes: []string{"provider_offline_readiness_failed"}}
		},
		"diagnostic mismatch": func(result *LocalDoctorResult) {
			result.Diagnostics = []LocalDiagnostic{{Code: "provider_unavailable", Category: "readiness", Message: "Unavailable.", Redacted: true}}
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			candidate.ConfiguredProviderIDs = append([]string(nil), valid.ConfiguredProviderIDs...)
			candidate.ProviderInventory = append([]LocalProviderInventoryRow(nil), valid.ProviderInventory...)
			candidate.Readiness.ReasonCodes = append([]string(nil), valid.Readiness.ReasonCodes...)
			candidate.Diagnostics = append([]LocalDiagnostic(nil), valid.Diagnostics...)
			mutate(&candidate)
			if err := candidate.Validate(); err == nil {
				t.Fatal("invalid cross-state projection was accepted")
			}
		})
	}
}

func TestLocalDoctorResultRequiresEveryConfiguredProvider(t *testing.T) {
	result := validLocalDoctorResult()
	result.ConfiguredProviderIDs = []string{"zcode", "grok"}
	result.ProviderInventory[1] = LocalProviderInventoryRow{
		Family: "grok", Configured: true, ReferencedByRoles: []string{}, State: "unavailable", Reason: "provider_cli_version_below_minimum",
		BinaryAvailable:       LocalDiagnosticCheck{Status: "verified", ReasonCodes: []string{}},
		CLICompatible:         LocalCLICompatibility{Status: "failed", ObservedVersion: "1.1.18", Eligibility: "ineligible", Compatibility: "below_minimum", MinimumVersion: "1.1.19", VerifiedLatest: "1.1.19", ReasonCode: "provider_cli_version_below_minimum"},
		ApplicationCompatible: LocalCLICompatibility{Status: "not_applicable", Eligibility: "not_evaluated", Compatibility: "not_observed"},
	}
	result.Assignment = LocalAssignmentProjection{State: "unavailable", Resilience: "unavailable"}
	result.Readiness = LocalReadiness{State: "unverified", ExitCode: 4, ReasonCodes: []string{"provider_offline_readiness_failed"}}
	result.ConfiguredReadiness = result.Readiness
	result.Diagnostics = []LocalDiagnostic{{Code: "provider_offline_readiness_failed", Category: "readiness", Message: "Provider failed.", Redacted: true}}
	if err := result.Validate(); err != nil {
		t.Fatalf("partial provider failure rejected: %v", err)
	}
}

func validLocalDoctorResult() LocalDoctorResult {
	notConfigured := func(family string) LocalProviderInventoryRow {
		return LocalProviderInventoryRow{Family: family, ReferencedByRoles: []string{}, State: "not_configured", Reason: "not_configured", BinaryAvailable: LocalDiagnosticCheck{Status: "not_applicable", ReasonCodes: []string{}}, CLICompatible: LocalCLICompatibility{Status: "not_applicable", Eligibility: "not_evaluated", Compatibility: "not_observed"}, ApplicationCompatible: LocalCLICompatibility{Status: "not_applicable", Eligibility: "not_evaluated", Compatibility: "not_observed"}}
	}
	return LocalDoctorResult{
		SchemaVersion: LocalSchemaVersion, CheckedAt: time.Date(2026, 7, 20, 0, 0, 0, 0, time.UTC), ProjectRootURI: ".",
		Config:   LocalConfigProjection{Status: "ready", URI: ".mulgae/config.yaml", SHA256: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Authority: "project_local", Locality: "verified", CheckoutHeadOID: "head", IndexEntriesSHA256: "sha256:index", TargetCommitOIDs: []string{"head"}, NativeHomeIdentity: "verified", ProvenanceState: "accepted", ReasonCodes: []string{}},
		ConfigV3: LocalDiagnosticCheck{Status: "verified", ReasonCodes: []string{}}, LocalConfiguration: LocalDiagnosticCheck{Status: "verified", ReasonCodes: []string{}}, ProviderIdentity: LocalDiagnosticCheck{Status: "verified", ReasonCodes: []string{}},
		ConfiguredProviderIDs: []string{"zcode"},
		ProviderInventory: []LocalProviderInventoryRow{
			{Family: "zcode", Configured: true, ReferencedByRoles: []string{"logic"}, State: "eligible", Reason: "zcode_application_version_supported", BinaryAvailable: LocalDiagnosticCheck{Status: "verified", ReasonCodes: []string{}}, CLICompatible: LocalCLICompatibility{Status: "verified", ObservedVersion: "0.16.5", Eligibility: "eligible", Compatibility: "verified", MinimumVersion: "0.16.5", VerifiedLatest: "0.16.5", ReasonCode: "provider_cli_version_supported"}, ApplicationCompatible: LocalCLICompatibility{Status: "verified", ObservedVersion: "3.12.3", Eligibility: "eligible", Compatibility: "verified", MinimumVersion: "3.12.3", VerifiedLatest: "3.12.3", ReasonCode: "zcode_application_version_supported"}},
			notConfigured("grok"), notConfigured("codex"),
		},
		Assignment: LocalAssignmentProjection{State: "ready", Resilience: "ready"}, PlatformEvidence: []LocalPlatformEvidence{{Cell: "darwin-arm64", Native: true}}, ToolsLock: LocalToolsLock{State: "not_observed"},
		Readiness: LocalReadiness{State: "ready", ExitCode: 0, ReasonCodes: []string{}}, ConfiguredReadiness: LocalReadiness{State: "ready", ExitCode: 0, ReasonCodes: []string{}}, RoleRouteReadiness: LocalReadiness{State: "ready", ExitCode: 0, ReasonCodes: []string{}}, Diagnostics: []LocalDiagnostic{},
	}
}

func TestLocalDoctorResultValidatesEmptyCheckoutIdentity(t *testing.T) {
	for _, test := range []struct {
		name, head string
		commits    []string
		valid      bool
	}{
		{"committed", "head", []string{"head"}, true},
		{"verified unborn", "", []string{}, true},
		{"nil commits", "", nil, false},
		{"unborn with fabricated commit", "", []string{"head"}, false},
		{"committed without applicable commit", "head", []string{}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := validLocalDoctorResult()
			result.Config.CheckoutHeadOID, result.Config.TargetCommitOIDs = test.head, test.commits
			if err := result.Validate(); (err == nil) != test.valid {
				t.Fatalf("valid = %t, want %t; error = %v", err == nil, test.valid, err)
			}
		})
	}
}
