package doctor

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestDoctorResultJSONRoundTripAndSchemaShape(t *testing.T) {
	result := readyModelResult(t)
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	var shape map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &shape); err != nil {
		t.Fatal(err)
	}
	wantKeys := map[string]struct{}{
		"schema_version": {}, "checked_at": {}, "project_root": {}, "intended_provider_ids": {},
		"unverified_provider_ids": {}, "provider_evidence": {}, "platform_evidence": {}, "tools_lock": {},
		"readiness": {}, "diagnostics": {},
	}
	if len(shape) != len(wantKeys) {
		t.Fatalf("top-level key count = %d, want %d: %s", len(shape), len(wantKeys), encoded)
	}
	for key := range wantKeys {
		if _, exists := shape[key]; !exists {
			t.Errorf("missing JSON key %q", key)
		}
	}
	if !strings.Contains(string(shape["checked_at"]), "Z\"") {
		t.Fatalf("checked_at is not UTC JSON: %s", shape["checked_at"])
	}
	var roundTrip DoctorResult
	if err := json.Unmarshal(encoded, &roundTrip); err != nil {
		t.Fatal(err)
	}
	if err := roundTrip.Validate(); err != nil {
		t.Fatalf("round-trip result is invalid: %v", err)
	}
}

func TestDoctorResultRejectsFuturePlatformPassAndHiddenEvidenceURI(t *testing.T) {
	result := readyModelResult(t)
	result.PlatformEvidence[0].Native = true
	result.PlatformEvidence[0].EvidenceState = EvidenceStatePass
	uri := "https://evidence.example/future"
	digest := "sha256:" + strings.Repeat("c", 64)
	result.PlatformEvidence[0].EvidenceURI = &uri
	result.PlatformEvidence[0].EvidenceSHA256 = &digest
	result.PlatformEvidence[0].ReasonCodes = []string{}
	if err := result.Validate(); err == nil {
		t.Fatal("future platform PASS was accepted")
	}

	result = readyModelResult(t)
	result.ProviderEvidence[0].EvidenceURI = stringPointer(".gjc/session/evidence/provider.json")
	if err := result.Validate(); err == nil {
		t.Fatal("hidden evidence URI was accepted")
	}
}
func TestDoctorResultRejectsContradictoryProviderRows(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*DoctorResult)
	}{
		{
			name: "eligible fail",
			mutate: func(result *DoctorResult) {
				row := &result.ProviderEvidence[0]
				row.EvidenceState = EvidenceStateFail
				row.ReasonCodes = []string{"provider_evidence_failed"}
			},
		},
		{
			name: "ineligible pass",
			mutate: func(result *DoctorResult) {
				row := &result.ProviderEvidence[0]
				row.AssignmentState = AssignmentIneligible
			},
		},
		{
			name: "unverified pass",
			mutate: func(result *DoctorResult) {
				row := &result.ProviderEvidence[0]
				row.AssignmentState = AssignmentIntendedButUnverified
				row.EvidenceURI = nil
				row.EvidenceSHA256 = nil
				row.ReasonCodes = []string{"provider_evidence_unavailable"}
			},
		},
		{
			name: "eligible not intended",
			mutate: func(result *DoctorResult) {
				result.ProviderEvidence[0].Intended = false
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := readyModelResult(t)
			test.mutate(&result)
			if err := result.Validate(); err == nil {
				t.Fatalf("%s contradictory provider row was accepted", test.name)
			}
		})
	}
}
func TestDoctorResultRejectsProviderIntendedMembershipMismatches(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*DoctorResult)
	}{
		{
			name: "intended id projected false",
			mutate: func(result *DoctorResult) {
				row := &result.ProviderEvidence[0]
				row.Intended = false
				row.AssignmentState = AssignmentIneligible
				row.EvidenceState = EvidenceStateFail
				row.ReasonCodes = []string{"provider_evidence_failed"}
			},
		},
		{
			name: "unintended id projected true",
			mutate: func(result *DoctorResult) {
				row := result.ProviderEvidence[0]
				row.ProviderID = "outside"
				result.ProviderEvidence = append(result.ProviderEvidence, row)
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := readyModelResult(t)
			test.mutate(&result)
			if err := result.Validate(); err == nil {
				t.Fatalf("%s mismatch was accepted", test.name)
			}
		})
	}
}

func TestDoctorResultValidatesCanonicalEvidenceReferences(t *testing.T) {
	for _, test := range []struct {
		name  string
		uri   string
		valid bool
	}{
		{name: "canonical HTTPS", uri: "https://evidence.example/records/provider.json", valid: true},
		{name: "neighboring path name", uri: "https://evidence.example/.gjc-cache/record", valid: true},
		{name: "local artifact", uri: ".mulgae/evidence/provider.json", valid: true},
		{name: "query", uri: "https://evidence.example/records?path=record"},
		{name: "fragment", uri: "https://evidence.example/records#record"},
		{name: "credential-bearing userinfo", uri: "https://alice:hunter2@evidence.example/record"},
		{name: "raw hidden path segment", uri: "https://evidence.example/.gjc/record"},
		{name: "encoded hidden path segment", uri: "https://evidence.example/%2Egjc/record"},
		{name: "double encoded path segment", uri: "https://evidence.example/%252Egjc/record"},
		{name: "raw traversal", uri: "https://evidence.example/records/../secret"},
		{name: "encoded traversal", uri: "https://evidence.example/records/%2E%2E/secret"},
		{name: "malformed path encoding", uri: "https://evidence.example/%ZZgjc/record"},
		{name: "HTTP scheme", uri: "http://evidence.example/record"},
		{name: "file scheme", uri: "file:///tmp/record"},
		{name: "data scheme", uri: "data:text/plain,record"},
		{name: "opaque scheme", uri: "artifact:record"},
		{name: "local traversal", uri: ".mulgae/../secret"},
		{name: "local encoded traversal", uri: ".mulgae/%2e%2e/secret"},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := readyModelResult(t)
			result.ProviderEvidence[0].EvidenceURI = stringPointer(test.uri)
			err := result.Validate()
			if (err == nil) != test.valid {
				t.Fatalf("URI %q validity = %t, want %t (error: %v)", test.uri, err == nil, test.valid, err)
			}
		})
	}
}

func TestDoctorResultRejectsSecretBearingDiagnosticMessage(t *testing.T) {
	result := readyModelResult(t)
	result.Diagnostics[0].Message = "password=hunter2"
	if err := result.Validate(); err == nil {
		t.Fatal("secret-bearing diagnostic message was accepted")
	}
}

func TestDoctorResultAllowsNonIntendedEvidenceInReadyProjection(t *testing.T) {
	result := readyModelResult(t)
	uri := "https://evidence.example/providers/claude"
	digest := "sha256:" + strings.Repeat("f", 64)
	result.ProviderEvidence = append(result.ProviderEvidence, ProviderEvidence{
		ProviderID:      "claude",
		Intended:        false,
		AssignmentState: AssignmentIneligible,
		EvidenceState:   EvidenceStateInconclusive,
		EvidenceURI:     &uri,
		EvidenceSHA256:  &digest,
		ReasonCodes:     []string{"provider_evidence_inconclusive"},
	})
	if err := result.Validate(); err != nil {
		t.Fatalf("ready result with accurately non-intended evidence is invalid: %v", err)
	}
}

func TestDoctorResultRejectsHiddenPlatformAndToolsLockURIs(t *testing.T) {
	for _, uri := range []string{
		"https://evidence.example/.gjc/record",
		"https://evidence.example/%2Egjc/record",
		"https://alice:hunter2@evidence.example/record",
	} {
		t.Run("platform_"+uri, func(t *testing.T) {
			result := readyModelResult(t)
			result.PlatformEvidence[3].EvidenceURI = stringPointer(uri)
			if err := result.Validate(); err == nil {
				t.Fatalf("platform evidence URI %q was accepted", uri)
			}
		})
		t.Run("tools_lock_"+uri, func(t *testing.T) {
			result := readyModelResult(t)
			result.ToolsLock.URI = stringPointer(uri)
			if err := result.Validate(); err == nil {
				t.Fatalf("tools-lock URI %q was accepted", uri)
			}
		})
	}
}

func TestDoctorResultRejectsHiddenOrEmptyToolPaths(t *testing.T) {
	for _, path := range []string{"/.gjc/tools/git", ".gjc", `.gjc\tools\git`, `/private\var\.gjc\tools\git`, `/private/var\.gjc/tools/git`, ""} {
		t.Run(path, func(t *testing.T) {
			result := readyModelResult(t)
			result.ToolsLock.Tools[0].ResolvedPath = path
			if err := result.Validate(); err == nil {
				t.Fatalf("tool path %q was accepted", path)
			}
		})
	}
}

func TestDoctorResultRejectsReadyWithAuthorityBlockers(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*DoctorResult)
	}{
		{
			name: "provider",
			mutate: func(result *DoctorResult) {
				row := &result.ProviderEvidence[0]
				row.AssignmentState = AssignmentIneligible
				row.EvidenceState = EvidenceStateFail
				row.ReasonCodes = []string{"provider_evidence_failed"}
				result.UnverifiedProviderIDs = []string{"kimi"}
			},
		},
		{
			name: "platform",
			mutate: func(result *DoctorResult) {
				for index := range result.PlatformEvidence {
					if result.PlatformEvidence[index].Cell == PlatformDarwinARM64 {
						result.PlatformEvidence[index].EvidenceState = EvidenceStateFail
						result.PlatformEvidence[index].ReasonCodes = []string{"platform_evidence_failed"}
					}
				}
			},
		},
		{
			name: "tools",
			mutate: func(result *DoctorResult) {
				result.ToolsLock = ToolsLock{State: ToolsLockMissing, Tools: []Tool{}}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := readyModelResult(t)
			test.mutate(&result)
			if err := result.Validate(); err == nil {
				t.Fatalf("ready result with %s blocker was accepted", test.name)
			}
		})
	}
}

func readyModelResult(t *testing.T) DoctorResult {
	t.Helper()
	providerURI := "https://evidence.example/providers"
	providerSHA := "sha256:" + strings.Repeat("a", 64)
	platformURI := "https://evidence.example/platforms"
	platformSHA := "sha256:" + strings.Repeat("b", 64)
	lockURI := "https://evidence.example/tools-lock"
	lockSHA := "sha256:" + strings.Repeat("c", 64)
	return DoctorResult{
		SchemaVersion:         SchemaVersion,
		CheckedAt:             time.Date(2026, time.July, 14, 12, 0, 0, 0, time.UTC),
		ProjectRoot:           "/project",
		IntendedProviderIDs:   []string{"kimi", "zcode", "agy", "codex"},
		UnverifiedProviderIDs: []string{},
		ProviderEvidence: []ProviderEvidence{
			{ProviderID: "kimi", Intended: true, AssignmentState: AssignmentEligible, EvidenceState: EvidenceStatePass, EvidenceURI: &providerURI, EvidenceSHA256: &providerSHA, ReasonCodes: []string{}},
			{ProviderID: "zcode", Intended: true, AssignmentState: AssignmentEligible, EvidenceState: EvidenceStatePass, EvidenceURI: &providerURI, EvidenceSHA256: &providerSHA, ReasonCodes: []string{}},
			{ProviderID: "agy", Intended: true, AssignmentState: AssignmentEligible, EvidenceState: EvidenceStatePass, EvidenceURI: &providerURI, EvidenceSHA256: &providerSHA, ReasonCodes: []string{}},
			{ProviderID: "codex", Intended: true, AssignmentState: AssignmentEligible, EvidenceState: EvidenceStatePass, EvidenceURI: &providerURI, EvidenceSHA256: &providerSHA, ReasonCodes: []string{}},
		},
		PlatformEvidence: []PlatformEvidence{
			{Cell: PlatformLinuxAMD64, Native: false, EvidenceState: EvidenceStateUnverified, ReasonCodes: []string{"intended_future", "not_supported", "release_ineligible"}},
			{Cell: PlatformLinuxARM64, Native: false, EvidenceState: EvidenceStateUnverified, ReasonCodes: []string{"intended_future", "not_supported", "release_ineligible"}},
			{Cell: PlatformDarwinAMD64, Native: false, EvidenceState: EvidenceStateUnverified, ReasonCodes: []string{"intended_future", "not_supported", "release_ineligible"}},
			{Cell: PlatformDarwinARM64, Native: true, EvidenceState: EvidenceStatePass, EvidenceURI: &platformURI, EvidenceSHA256: &platformSHA, ReasonCodes: []string{}},
		},
		ToolsLock: ToolsLock{
			State:  ToolsLockLocked,
			URI:    &lockURI,
			SHA256: &lockSHA,
			Tools: []Tool{
				{Name: "python3", ResolvedPath: "/usr/bin/python3", Version: "Python 3.12.0", SHA256: "sha256:" + strings.Repeat("d", 64)},
				{Name: "git", ResolvedPath: "/usr/bin/git", Version: "git version 2.45.0", SHA256: "sha256:" + strings.Repeat("e", 64)},
			},
		},
		Readiness:   Readiness{State: ReadinessReady, ExitCode: 0, ReasonCodes: []string{}},
		Diagnostics: diagnosticsFor(nil),
	}
}

func stringPointer(value string) *string {
	return &value
}
