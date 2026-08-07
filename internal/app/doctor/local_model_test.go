package doctor

import (
	"testing"
	"time"
)

func TestLocalDoctorResultValidateEnforcesCrossStateProjection(t *testing.T) {
	valid := LocalDoctorResult{
		SchemaVersion:  LocalSchemaVersion,
		CheckedAt:      time.Date(2026, 7, 20, 0, 0, 0, 0, time.UTC),
		ProjectRootURI: ".",
		Config: LocalConfigProjection{
			Status: "ready", URI: ".mulgae/config.yaml", SHA256: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			Authority: "project_local", Locality: "verified", CheckoutHeadOID: "head", IndexEntriesSHA256: "sha256:index",
			TargetCommitOIDs: []string{"head"}, NativeHomeIdentity: "verified", ProvenanceState: "accepted", ReasonCodes: []string{},
		},
		ConfiguredProviderIDs: []string{"kimi"},
		ProviderInventory: []LocalProviderInventoryRow{
			{Family: "kimi", State: "eligible", Reason: "identity_admitted"},
			{Family: "zcode", State: "not_configured", Reason: "not_configured"},
			{Family: "agy", State: "not_configured", Reason: "not_configured"},
		},
		Assignment:       LocalAssignmentProjection{State: "ready", Resilience: "ready"},
		PlatformEvidence: []LocalPlatformEvidence{{Cell: "darwin-arm64", Native: true}},
		ToolsLock:        LocalToolsLock{State: "not_observed"},
		Readiness:        LocalReadiness{State: "ready", ExitCode: 0, ReasonCodes: []string{}},
		Diagnostics:      []LocalDiagnostic{},
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid projection rejected: %v", err)
	}

	tests := map[string]func(*LocalDoctorResult){
		"noncanonical configured IDs": func(result *LocalDoctorResult) {
			result.ConfiguredProviderIDs = []string{"agy", "kimi"}
		},
		"omitted provider observed": func(result *LocalDoctorResult) {
			result.ProviderInventory[1] = LocalProviderInventoryRow{Family: "zcode", State: "eligible", Reason: "identity_admitted"}
		},
		"assignment readiness mismatch": func(result *LocalDoctorResult) {
			result.Readiness = LocalReadiness{State: "unverified", ExitCode: 4, ReasonCodes: []string{"provider_static_admission_unverified"}}
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

// TestLocalDoctorResultIsReadyWithOneOfTwoConfiguredProvidersEligible proves a
// single eligible family is a complete configuration. Every role runs on exactly
// one provider, so there is no resilience axis left to degrade.
func TestLocalDoctorResultIsReadyWithOneOfTwoConfiguredProvidersEligible(t *testing.T) {
	result := LocalDoctorResult{
		SchemaVersion:  LocalSchemaVersion,
		CheckedAt:      time.Date(2026, 7, 20, 0, 0, 0, 0, time.UTC),
		ProjectRootURI: ".",
		Config: LocalConfigProjection{
			Status: "ready", URI: ".mulgae/config.yaml", SHA256: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			Authority: "project_local", Locality: "verified", CheckoutHeadOID: "head", IndexEntriesSHA256: "sha256:index",
			TargetCommitOIDs: []string{"head"}, NativeHomeIdentity: "verified", ProvenanceState: "accepted", ReasonCodes: []string{},
		},
		ConfiguredProviderIDs: []string{"kimi", "agy"},
		ProviderInventory: []LocalProviderInventoryRow{
			{Family: "kimi", State: "unavailable", Reason: "configured_identity_unavailable"},
			{Family: "zcode", State: "not_configured", Reason: "not_configured"},
			{Family: "agy", State: "eligible", Reason: "identity_admitted"},
		},
		Assignment:       LocalAssignmentProjection{State: "ready", Resilience: "ready"},
		PlatformEvidence: []LocalPlatformEvidence{{Cell: "darwin-arm64", Native: true}},
		ToolsLock:        LocalToolsLock{State: "not_observed"},
		Readiness:        LocalReadiness{State: "ready", ExitCode: 0, ReasonCodes: []string{}},
		Diagnostics:      []LocalDiagnostic{},
	}
	if err := result.Validate(); err != nil {
		t.Fatalf("single-eligible-family projection rejected: %v", err)
	}
}
