package providers

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/app/doctor"
)

type fakeDiagnoser struct {
	result doctor.DoctorResult
	err    error
}

func (fake fakeDiagnoser) DiagnoseEnvironment(context.Context) (doctor.DoctorResult, error) {
	return fake.result, fake.err
}

func TestListProviderProfilesCanonicalOrderAndMetadata(t *testing.T) {
	service := newTestService(t, fakeDiagnoser{result: diagnosis(
		evidence("kimi", doctor.EvidenceStatePass, doctor.AssignmentEligible),
		evidence("zcode", doctor.EvidenceStateFail, doctor.AssignmentIneligible),
		evidence("agy", doctor.EvidenceStateInconclusive, doctor.AssignmentIneligible),
	)})

	result, err := service.ListProviderProfiles(context.Background(), true)
	if err != nil {
		t.Fatalf("ListProviderProfiles() error = %v", err)
	}
	profiles := result.Profiles()
	if got, want := len(profiles), 3; got != want {
		t.Fatalf("profiles length = %d, want %d", got, want)
	}
	want := []struct {
		family  Family
		id      string
		prompt  PromptTransport
		output  ResultTransport
		support SupportState
	}{
		{FamilyKimi, "kimi-default", PromptTransportArgv, ResultTransportKimiStreamJSONAssistantContent, SupportSupported},
		{FamilyZCode, "zcode-default", PromptTransportArgv, ResultTransportStrictJSON, SupportUnsupported},
		{FamilyAGY, "agy-default", PromptTransportArgv, ResultTransportStrictJSON, SupportUnsupported},
	}
	for index, expected := range want {
		profile := profiles[index]
		if profile.Family() != expected.family || profile.ID() != expected.id || profile.PromptTransport() != expected.prompt || profile.ResultTransport() != expected.output || profile.Support() != expected.support {
			t.Fatalf("profile[%d] = %#v, want family=%q id=%q prompt=%q output=%q support=%q", index, profile, expected.family, expected.id, expected.prompt, expected.output, expected.support)
		}
	}
}

func TestListProviderProfilesEvidenceProjectionAndFiltering(t *testing.T) {
	service := newTestService(t, fakeDiagnoser{result: diagnosis(
		evidence("kimi", doctor.EvidenceStatePass, doctor.AssignmentEligible),
		evidence("zcode", doctor.EvidenceStateFail, doctor.AssignmentIneligible),
		evidence("agy", doctor.EvidenceStateUnverified, doctor.AssignmentIntendedButUnverified),
	)})

	all, err := service.ListProviderProfiles(context.Background(), true)
	if err != nil {
		t.Fatalf("all profiles error = %v", err)
	}
	if got, want := profileSupports(all.Profiles()), []SupportState{SupportSupported, SupportUnsupported, SupportUnverified}; !reflect.DeepEqual(got, want) {
		t.Fatalf("support states = %v, want %v", got, want)
	}
	filtered, err := service.ListProviderProfiles(context.Background(), false)
	if err != nil {
		t.Fatalf("filtered profiles error = %v", err)
	}
	if got, want := profileFamilies(filtered.Profiles()), []Family{FamilyKimi, FamilyZCode}; !reflect.DeepEqual(got, want) {
		t.Fatalf("filtered families = %v, want %v", got, want)
	}
}

func TestListProviderProfilesDoesNotPromoteInvalidEvidence(t *testing.T) {
	service := newTestService(t, fakeDiagnoser{result: diagnosis(
		evidence("kimi", doctor.EvidenceStatePass, doctor.AssignmentIneligible),
	)})
	if _, err := service.ListProviderProfiles(context.Background(), true); err == nil {
		t.Fatal("ListProviderProfiles() error = nil, want fail-closed error")
	}
}

func TestListProviderProfilesAbsentEvidenceIsUnverified(t *testing.T) {
	service := newTestService(t, fakeDiagnoser{result: diagnosis(evidence("kimi", doctor.EvidenceStatePass, doctor.AssignmentEligible))})
	result, err := service.ListProviderProfiles(context.Background(), true)
	if err != nil {
		t.Fatalf("ListProviderProfiles() error = %v", err)
	}
	profiles := result.Profiles()
	if got, want := profileSupports(profiles), []SupportState{SupportSupported, SupportUnverified, SupportUnverified}; !reflect.DeepEqual(got, want) {
		t.Fatalf("support states = %v, want %v", got, want)
	}
	if got := profiles[1].AssignmentState(); got != doctor.AssignmentIntendedButUnverified {
		t.Fatalf("absent assignment state = %q", got)
	}
}

func TestListProviderProfilesRejectsMalformedProviderInventories(t *testing.T) {
	tests := []struct {
		name   string
		result doctor.DoctorResult
	}{
		{"duplicate evidence", diagnosis(evidence("kimi", doctor.EvidenceStatePass, doctor.AssignmentEligible), evidence("kimi", doctor.EvidenceStatePass, doctor.AssignmentEligible))},
		{"unknown evidence", diagnosis(evidence("codex", doctor.EvidenceStatePass, doctor.AssignmentEligible))},
		{"out of order evidence", diagnosis(evidence("zcode", doctor.EvidenceStatePass, doctor.AssignmentEligible), evidence("kimi", doctor.EvidenceStatePass, doctor.AssignmentEligible))},
		{"duplicate intended", doctor.DoctorResult{IntendedProviderIDs: []string{"kimi", "kimi"}}},
		{"unknown unverified", doctor.DoctorResult{UnverifiedProviderIDs: []string{"claude"}}},
		{"out of order intended", doctor.DoctorResult{IntendedProviderIDs: []string{"zcode", "kimi"}}},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			service := newTestService(t, fakeDiagnoser{result: testCase.result})
			if _, err := service.ListProviderProfiles(context.Background(), true); err == nil {
				t.Fatal("ListProviderProfiles() error = nil, want fail-closed error")
			}
		})
	}
}
func TestListProviderProfilesRejectsInvalidDoctorResultsBeforeProjection(t *testing.T) {
	newPassDiagnosis := func() doctor.DoctorResult {
		return diagnosis(evidence("kimi", doctor.EvidenceStatePass, doctor.AssignmentEligible))
	}
	tests := []struct {
		name   string
		mutate func(*doctor.DoctorResult)
	}{
		{
			name: "eligible pass missing evidence URI",
			mutate: func(result *doctor.DoctorResult) {
				result.ProviderEvidence[0].EvidenceURI = nil
			},
		},
		{
			name: "eligible pass missing evidence SHA256",
			mutate: func(result *doctor.DoctorResult) {
				result.ProviderEvidence[0].EvidenceSHA256 = nil
			},
		},
		{
			name: "invalid readiness",
			mutate: func(result *doctor.DoctorResult) {
				result.Readiness = doctor.Readiness{State: doctor.ReadinessReady, ExitCode: 0}
			},
		},
		{
			name: "invalid platform inventory",
			mutate: func(result *doctor.DoctorResult) {
				result.PlatformEvidence = result.PlatformEvidence[:3]
			},
		},
		{
			name: "out of order evidence",
			mutate: func(result *doctor.DoctorResult) {
				*result = diagnosis(
					evidence("zcode", doctor.EvidenceStatePass, doctor.AssignmentEligible),
					evidence("kimi", doctor.EvidenceStatePass, doctor.AssignmentEligible),
				)
			},
		},
		{
			name: "invalid schema version",
			mutate: func(result *doctor.DoctorResult) {
				result.SchemaVersion = "mulgae-doctor-result.v0"
			},
		},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			result := newPassDiagnosis()
			testCase.mutate(&result)
			service := newTestService(t, fakeDiagnoser{result: result})
			profiles, err := service.ListProviderProfiles(context.Background(), true)
			if err == nil {
				t.Fatalf("ListProviderProfiles() profiles = %#v, want fail-closed error", profiles)
			}
		})
	}
}

func TestListProviderProfilesPropagatesDiagnosticError(t *testing.T) {
	service := newTestService(t, fakeDiagnoser{err: errors.New("diagnosis unavailable")})
	if _, err := service.ListProviderProfiles(context.Background(), true); err == nil || !strings.Contains(err.Error(), "diagnosis unavailable") {
		t.Fatalf("ListProviderProfiles() error = %v", err)
	}
}

func TestResultJSONAndRenderAreDefensiveAndRedacted(t *testing.T) {
	uri := "https://evidence.example/providers/kimi"
	digest := "sha256:" + strings.Repeat("a", 64)
	row := evidence("kimi", doctor.EvidenceStatePass, doctor.AssignmentEligible)
	row.EvidenceURI = &uri
	row.EvidenceSHA256 = &digest
	doctorResult := diagnosis(row)
	doctorResult.ProjectRoot = "/private/secret/project"
	service := newTestService(t, fakeDiagnoser{result: doctorResult})
	result, err := service.ListProviderProfiles(context.Background(), true)
	if err != nil {
		t.Fatalf("ListProviderProfiles() error = %v", err)
	}

	first := result.Profiles()
	first[0] = Profile{}
	if got := result.Profiles()[0].Family(); got != FamilyKimi {
		t.Fatalf("Profiles leaked mutable backing storage: %q", got)
	}
	projection := result.JSON()
	*projection.Profiles[0].EvidenceURI = "mutated"
	if got, _ := result.Profiles()[0].EvidenceURI(); got != uri {
		t.Fatalf("JSON leaked evidence URI: %q", got)
	}
	if got := RenderHuman(result); got != RenderHuman(result) {
		t.Fatalf("RenderHuman() is nondeterministic: %q", got)
	} else {
		for _, forbidden := range []string{"/private/secret/project", "credential=secret", "resolved_path", "environment", "prompt"} {
			if strings.Contains(got, forbidden) {
				t.Fatalf("RenderHuman() leaked %q: %q", forbidden, got)
			}
		}
		if !strings.Contains(got, "evidence_uri="+uri) || !strings.Contains(got, "evidence_sha256="+digest) {
			t.Fatalf("RenderHuman() omitted redacted evidence metadata: %q", got)
		}
	}
}

func newTestService(t *testing.T, diagnoser Diagnoser) *Service {
	t.Helper()
	service, err := NewService(diagnoser)
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	return service
}

func diagnosis(rows ...doctor.ProviderEvidence) doctor.DoctorResult {
	intended := make([]string, 0, len(rows))
	unverified := make([]string, 0, len(rows))
	for _, row := range rows {
		if !row.Intended {
			continue
		}
		intended = append(intended, row.ProviderID)
		if row.EvidenceState != doctor.EvidenceStatePass {
			unverified = append(unverified, row.ProviderID)
		}
	}
	return doctor.DoctorResult{
		SchemaVersion:         doctor.SchemaVersion,
		CheckedAt:             time.Date(2026, time.July, 14, 12, 0, 0, 0, time.UTC),
		ProjectRoot:           "/project",
		IntendedProviderIDs:   intended,
		UnverifiedProviderIDs: unverified,
		ProviderEvidence:      rows,
		PlatformEvidence: []doctor.PlatformEvidence{
			{Cell: doctor.PlatformLinuxAMD64, EvidenceState: doctor.EvidenceStateUnverified, ReasonCodes: []string{"intended_future", "not_supported", "release_ineligible"}},
			{Cell: doctor.PlatformLinuxARM64, EvidenceState: doctor.EvidenceStateUnverified, ReasonCodes: []string{"intended_future", "not_supported", "release_ineligible"}},
			{Cell: doctor.PlatformDarwinAMD64, EvidenceState: doctor.EvidenceStateUnverified, ReasonCodes: []string{"intended_future", "not_supported", "release_ineligible"}},
			{Cell: doctor.PlatformDarwinARM64, EvidenceState: doctor.EvidenceStateUnverified, ReasonCodes: []string{"platform_evidence_not_run"}},
		},
		ToolsLock: doctor.ToolsLock{State: doctor.ToolsLockMissing},
		Readiness: doctor.Readiness{State: doctor.ReadinessUnverified, ExitCode: 4, ReasonCodes: []string{"provider_evidence_not_run"}},
		Diagnostics: []doctor.Diagnostic{
			{Code: "remote_provider_transmission_risk", Category: doctor.DiagnosticSecurity, Message: "Providers may transmit prompts and targets to remote services; select providers appropriate for your data policy.", Redacted: true},
			{Code: "snapshot_not_mathematical_sandbox", Category: doctor.DiagnosticSecurity, Message: "Mutation detection and read-only snapshots reduce risk but are not a mathematical sandbox.", Redacted: true},
		},
	}
}

func evidence(id string, state doctor.EvidenceState, assignment doctor.AssignmentState) doctor.ProviderEvidence {
	uri := "https://evidence.example/providers/" + id
	sha256 := "sha256:" + strings.Repeat("a", 64)
	row := doctor.ProviderEvidence{
		ProviderID:      id,
		Intended:        true,
		EvidenceState:   state,
		AssignmentState: assignment,
	}
	switch assignment {
	case doctor.AssignmentEligible:
		row.EvidenceURI = &uri
		row.EvidenceSHA256 = &sha256
	case doctor.AssignmentIneligible:
		row.EvidenceURI = &uri
		row.EvidenceSHA256 = &sha256
		if state == doctor.EvidenceStateFail {
			row.ReasonCodes = []string{"provider_evidence_failed"}
		} else if state == doctor.EvidenceStateInconclusive {
			row.ReasonCodes = []string{"provider_evidence_inconclusive"}
		}
	case doctor.AssignmentIntendedButUnverified:
		row.ReasonCodes = []string{"provider_evidence_not_run"}
	}
	return row
}

func profileSupports(profiles []Profile) []SupportState {
	states := make([]SupportState, 0, len(profiles))
	for _, profile := range profiles {
		states = append(states, profile.Support())
	}
	return states
}

func profileFamilies(profiles []Profile) []Family {
	families := make([]Family, 0, len(profiles))
	for _, profile := range profiles {
		families = append(families, profile.Family())
	}
	return families
}
