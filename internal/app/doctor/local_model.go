package doctor

import (
	"fmt"
	"reflect"
	"time"
)

const LocalSchemaVersion = "mulgae-doctor-result.v2"

type LocalConfigProjection struct {
	Status             string   `json:"status"`
	URI                string   `json:"uri"`
	SHA256             string   `json:"sha256"`
	Authority          string   `json:"authority"`
	Locality           string   `json:"locality"`
	CheckoutHeadOID    string   `json:"checkout_head_oid"`
	IndexEntriesSHA256 string   `json:"index_entries_sha256"`
	TargetCommitOIDs   []string `json:"target_commit_oids"`
	NativeHomeIdentity string   `json:"native_home_identity"`
	ProvenanceState    string   `json:"provenance_state"`
	ReasonCodes        []string `json:"reason_codes"`
}

type LocalProviderInventoryRow struct {
	Family string `json:"family"`
	State  string `json:"state"`
	Reason string `json:"reason"`
}

type LocalAssignmentProjection struct {
	State      string `json:"state"`
	Resilience string `json:"resilience"`
}

type LocalPlatformEvidence struct {
	Cell   string `json:"cell"`
	Native bool   `json:"native"`
}

type LocalToolsLock struct {
	State string `json:"state"`
}

type LocalReadiness struct {
	State       string   `json:"state"`
	ExitCode    int      `json:"exit_code"`
	ReasonCodes []string `json:"reason_codes"`
}

type LocalDiagnostic struct {
	Code     string `json:"code"`
	Category string `json:"category"`
	Message  string `json:"message"`
	Redacted bool   `json:"redacted"`
}

// LocalDoctorResult is the project-local doctor v2 artifact. Field order is
// part of the machine contract.
type LocalDoctorResult struct {
	SchemaVersion         string                      `json:"schema_version"`
	CheckedAt             time.Time                   `json:"checked_at"`
	ProjectRootURI        string                      `json:"project_root_uri"`
	Config                LocalConfigProjection       `json:"config"`
	ConfiguredProviderIDs []string                    `json:"configured_provider_ids"`
	ProviderInventory     []LocalProviderInventoryRow `json:"provider_inventory"`
	Assignment            LocalAssignmentProjection   `json:"assignment"`
	PlatformEvidence      []LocalPlatformEvidence     `json:"platform_evidence"`
	ToolsLock             LocalToolsLock              `json:"tools_lock"`
	Readiness             LocalReadiness              `json:"readiness"`
	Diagnostics           []LocalDiagnostic           `json:"diagnostics"`
}

func (result LocalDoctorResult) Validate() error {
	if result.SchemaVersion != LocalSchemaVersion || result.CheckedAt.IsZero() || result.ProjectRootURI != "." || result.Config.URI != ".mulgae/config.yaml" || result.Config.Authority != "project_local" {
		return fmt.Errorf("local doctor result: invalid identity")
	}
	if len(result.ProviderInventory) != 3 || result.ProviderInventory[0].Family != "kimi" || result.ProviderInventory[1].Family != "zcode" || result.ProviderInventory[2].Family != "agy" {
		return fmt.Errorf("local doctor result: invalid provider inventory")
	}
	if !canonicalProviderIDs(result.ConfiguredProviderIDs) || len(result.PlatformEvidence) != 1 || result.PlatformEvidence[0].Cell == "" || result.ToolsLock.State != "not_observed" {
		return fmt.Errorf("local doctor result: invalid fixed projection")
	}
	if err := validateConfigProjection(result.Config); err != nil {
		return err
	}
	if err := validateDiagnostics(result.Readiness, result.Diagnostics); err != nil {
		return err
	}
	if result.Config.Status != "ready" {
		if len(result.ConfiguredProviderIDs) != 0 || result.Assignment != (LocalAssignmentProjection{State: "not_observed", Resilience: "not_observed"}) {
			return fmt.Errorf("local doctor result: non-ready config observed providers")
		}
		for _, row := range result.ProviderInventory {
			if row.State != "not_observed" || row.Reason != "config_not_ready" {
				return fmt.Errorf("local doctor result: non-ready config has provider observation")
			}
		}
		wantState, wantExit := "unverified", 4
		if result.Config.Status == "unsafe" || result.Config.Status == "drifted" {
			wantState, wantExit = "unsafe", 8
		}
		if result.Readiness.State != wantState || result.Readiness.ExitCode != wantExit || !reflect.DeepEqual(result.Readiness.ReasonCodes, result.Config.ReasonCodes) {
			return fmt.Errorf("local doctor result: config and readiness disagree")
		}
		return nil
	}
	return validateReadyProviderProjection(result)
}

func validateConfigProjection(config LocalConfigProjection) error {
	switch config.Status {
	case "missing":
		if config.Locality != "not_observed" || !reflect.DeepEqual(config.ReasonCodes, []string{"config_missing"}) {
			return fmt.Errorf("local doctor result: invalid missing config")
		}
	case "invalid":
		if config.Locality != "verified" || !reflect.DeepEqual(config.ReasonCodes, []string{"config_yaml_invalid"}) {
			return fmt.Errorf("local doctor result: invalid rejected config")
		}
	case "unsafe":
		if config.Locality != "rejected" && config.Locality != "verified" || len(config.ReasonCodes) != 1 {
			return fmt.Errorf("local doctor result: invalid unsafe config")
		}
	case "drifted":
		if config.Locality != "drifted" || !reflect.DeepEqual(config.ReasonCodes, []string{"config_locality_drifted"}) {
			return fmt.Errorf("local doctor result: invalid drifted config")
		}
	case "ready":
		if config.Locality != "verified" || config.SHA256 == "" || config.CheckoutHeadOID == "" || config.IndexEntriesSHA256 == "" || len(config.TargetCommitOIDs) == 0 || config.NativeHomeIdentity != "verified" || config.ProvenanceState != "accepted" || len(config.ReasonCodes) != 0 {
			return fmt.Errorf("local doctor result: invalid ready config")
		}
	default:
		return fmt.Errorf("local doctor result: invalid config status")
	}
	return nil
}

func validateReadyProviderProjection(result LocalDoctorResult) error {
	if len(result.ConfiguredProviderIDs) == 0 {
		return fmt.Errorf("local doctor result: ready config has no providers")
	}
	eligible := 0
	unsafe := false
	for _, row := range result.ProviderInventory {
		configured := containsProviderID(result.ConfiguredProviderIDs, row.Family)
		if !configured {
			if row.State != "not_configured" || row.Reason != "not_configured" {
				return fmt.Errorf("local doctor result: omitted provider was observed")
			}
			continue
		}
		switch row.State {
		case "eligible":
			if row.Reason != "identity_admitted" {
				return fmt.Errorf("local doctor result: invalid eligible provider")
			}
			eligible++
		case "unavailable":
			if row.Reason != "configured_identity_unavailable" && row.Reason != "provider_admission_unverified" && row.Reason != "provider_security_admission_failed" {
				return fmt.Errorf("local doctor result: invalid unavailable provider")
			}
			unsafe = unsafe || row.Reason == "provider_security_admission_failed"
		default:
			return fmt.Errorf("local doctor result: configured provider was not classified")
		}
	}
	switch {
	case unsafe:
		return requireDoctorOutcome(result, LocalAssignmentProjection{State: "unavailable", Resilience: "unavailable"}, "unsafe", 8, []string{"provider_security_admission_failed"})
	case eligible == 0:
		return requireDoctorOutcome(result, LocalAssignmentProjection{State: "unavailable", Resilience: "unavailable"}, "unverified", 4, []string{"provider_unavailable"})
	case eligible == 1:
		return requireDoctorOutcome(result, LocalAssignmentProjection{State: "degraded_resilience", Resilience: "degraded"}, "degraded", 0, []string{"provider_resilience_degraded"})
	default:
		return requireDoctorOutcome(result, LocalAssignmentProjection{State: "ready", Resilience: "ready"}, "ready", 0, []string{})
	}
}

func requireDoctorOutcome(result LocalDoctorResult, assignment LocalAssignmentProjection, state string, exit int, reasons []string) error {
	if result.Assignment != assignment || result.Readiness.State != state || result.Readiness.ExitCode != exit || !reflect.DeepEqual(result.Readiness.ReasonCodes, reasons) {
		return fmt.Errorf("local doctor result: invalid provider outcome")
	}
	return nil
}

func validateDiagnostics(readiness LocalReadiness, diagnostics []LocalDiagnostic) error {
	if len(diagnostics) != len(readiness.ReasonCodes) {
		return fmt.Errorf("local doctor result: diagnostics disagree with reasons")
	}
	for index, reason := range readiness.ReasonCodes {
		diagnostic := diagnostics[index]
		if diagnostic.Code != reason || diagnostic.Message == "" || !diagnostic.Redacted {
			return fmt.Errorf("local doctor result: invalid diagnostic")
		}
		switch diagnostic.Category {
		case "configuration", "readiness", "artifact", "security":
		default:
			return fmt.Errorf("local doctor result: invalid diagnostic category")
		}
	}
	return nil
}

func canonicalProviderIDs(ids []string) bool {
	position := -1
	order := []string{"kimi", "zcode", "agy"}
	for _, id := range ids {
		found := -1
		for index, family := range order {
			if id == family {
				found = index
				break
			}
		}
		if found <= position {
			return false
		}
		position = found
	}
	return true
}

func containsProviderID(ids []string, family string) bool {
	for _, id := range ids {
		if id == family {
			return true
		}
	}
	return false
}
