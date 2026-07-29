package doctor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/ports"
)

func TestDiagnoseEnvironmentDarwinWithoutEvidenceIsUnverified(t *testing.T) {
	service, _, _ := readyFixture(t, nil)
	result := diagnose(t, service)
	if result.Readiness.State != ReadinessUnverified || result.Readiness.ExitCode != 4 {
		t.Fatalf("readiness = %#v, want unverified/4", result.Readiness)
	}
	if len(result.UnverifiedProviderIDs) != len(intendedProviderIDs) {
		t.Fatalf("unverified providers = %v", result.UnverifiedProviderIDs)
	}
	for _, row := range result.ProviderEvidence {
		if row.EvidenceState != EvidenceStateUnverified || row.AssignmentState != AssignmentIntendedButUnverified {
			t.Fatalf("provider row promoted without evidence: %#v", row)
		}
	}
	if row := platformRow(t, result, PlatformDarwinARM64); row.EvidenceState != EvidenceStateUnverified || row.Native {
		t.Fatalf("darwin row without evidence = %#v", row)
	}
}

func TestDiagnoseEnvironmentUnsupportedHostCannotPassPlatform(t *testing.T) {
	evidence := readyEvidence()
	service, inspector, _ := readyFixture(t, evidence)
	inspector.platform = mustPlatform(t, "linux", "arm64")
	result := diagnose(t, service)
	if result.Readiness.State != ReadinessUnverified || !contains(result.Readiness.ReasonCodes, "host_platform_not_supported") {
		t.Fatalf("unsupported host readiness = %#v", result.Readiness)
	}
	if row := platformRow(t, result, PlatformDarwinARM64); row.EvidenceState != EvidenceStateUnverified || row.Native {
		t.Fatalf("darwin row was promoted on unsupported host: %#v", row)
	}
}

func TestDiagnoseEnvironmentBinaryPresenceDoesNotPromoteProvider(t *testing.T) {
	service, inspector, _ := readyFixture(t, nil)
	for _, providerID := range intendedProviderIDs {
		inspector.executables[providerID] = mustExecutable(t, providerID, true, "/opt/bin/"+providerID, "token=not-reported", "sha256:"+rawDigest("a"))
	}
	result := diagnose(t, service)
	for _, row := range result.ProviderEvidence {
		if row.EvidenceState == EvidenceStatePass || row.AssignmentState != AssignmentIntendedButUnverified {
			t.Fatalf("provider binary fabricated authority evidence: %#v", row)
		}
	}
}
func TestDiagnoseEnvironmentAbsentOrErroredExecutablesBlockReady(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*fakeInspector)
	}{
		{
			name: "all absent",
			mutate: func(inspector *fakeInspector) {
				inspector.executables = make(map[string]ports.ExecutableObservation)
			},
		},
		{
			name: "lookup error",
			mutate: func(inspector *fakeInspector) {
				inspector.execErr["kimi"] = errors.New("lookup failed")
			},
		},
		{
			name: "missing provenance hash",
			mutate: func(inspector *fakeInspector) {
				inspector.executables["kimi"] = mustExecutable(t, "kimi", true, "/opt/bin/kimi", "", "")
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			service, inspector, _ := readyFixture(t, readyEvidence())
			test.mutate(inspector)
			result := diagnose(t, service)
			if result.Readiness.State != ReadinessUnverified || !contains(result.Readiness.ReasonCodes, "executable_observation_invalid") {
				t.Fatalf("%s readiness = %#v", test.name, result.Readiness)
			}
		})
	}
}
func TestDiagnoseEnvironmentAllAbsentProviderEvidenceIsUnverified(t *testing.T) {
	evidence := readyEvidence()
	evidence.providers = make(map[string]ProviderEvidenceRecord)
	service, _, _ := readyFixture(t, evidence)
	result := diagnose(t, service)
	for _, providerID := range intendedProviderIDs {
		row := providerRow(t, result, providerID)
		if row.EvidenceState != EvidenceStateUnverified ||
			row.AssignmentState != AssignmentIntendedButUnverified ||
			!contains(row.ReasonCodes, "provider_evidence_unavailable") {
			t.Fatalf("absent provider %q = %#v", providerID, row)
		}
	}
}

func TestDiagnoseEnvironmentErrorsAndNotRunEvidenceRemainUnverified(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*fakeEvidence)
		row    func(*testing.T, DoctorResult) EvidenceState
		reason string
	}{
		{
			name: "provider error",
			mutate: func(evidence *fakeEvidence) {
				evidence.providerErr["kimi"] = errors.New("evidence unavailable")
			},
			row: func(t *testing.T, result DoctorResult) EvidenceState {
				return providerRow(t, result, "kimi").EvidenceState
			},
			reason: "provider_evidence_unavailable",
		},
		{
			name: "provider not run",
			mutate: func(evidence *fakeEvidence) {
				record := evidence.providers["kimi"]
				record.Probes[0].Status = EvidenceStatusNotRun
				evidence.providers["kimi"] = record
			},
			row: func(t *testing.T, result DoctorResult) EvidenceState {
				return providerRow(t, result, "kimi").EvidenceState
			},
			reason: "provider_evidence_not_run",
		},
		{
			name: "platform error",
			mutate: func(evidence *fakeEvidence) {
				evidence.platformErr = errors.New("evidence unavailable")
			},
			row: func(t *testing.T, result DoctorResult) EvidenceState {
				return platformRow(t, result, PlatformDarwinARM64).EvidenceState
			},
			reason: "platform_evidence_unavailable",
		},
		{
			name: "platform not run",
			mutate: func(evidence *fakeEvidence) {
				evidence.platform.Probes[0].Status = EvidenceStatusNotRun
			},
			row: func(t *testing.T, result DoctorResult) EvidenceState {
				return platformRow(t, result, PlatformDarwinARM64).EvidenceState
			},
			reason: "platform_evidence_not_run",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			evidence := readyEvidence()
			test.mutate(evidence)
			service, _, _ := readyFixture(t, evidence)
			result := diagnose(t, service)
			if result.Readiness.State != ReadinessUnverified ||
				test.row(t, result) != EvidenceStateUnverified ||
				!contains(result.Readiness.ReasonCodes, test.reason) {
				t.Fatalf("%s result = %#v", test.name, result)
			}
		})
	}
}

func TestDiagnoseEnvironmentUnsupportedEvidenceSchemasAreUnverified(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*fakeEvidence)
		row    func(*testing.T, DoctorResult) EvidenceState
		reason string
	}{
		{
			name: "provider",
			mutate: func(evidence *fakeEvidence) {
				record := evidence.providers["kimi"]
				record.SchemaID = "https://mulgae.local/schemas/mulgae-provider-contract-evidence.v3.schema.json"
				evidence.providers["kimi"] = record
			},
			row: func(t *testing.T, result DoctorResult) EvidenceState {
				return providerRow(t, result, "kimi").EvidenceState
			},
			reason: "provider_evidence_unsupported_schema",
		},
		{
			name: "platform",
			mutate: func(evidence *fakeEvidence) {
				evidence.platform.SchemaID = "https://mulgae.local/schemas/mulgae-platform-contract-evidence.v3.schema.json"
			},
			row: func(t *testing.T, result DoctorResult) EvidenceState {
				return platformRow(t, result, PlatformDarwinARM64).EvidenceState
			},
			reason: "platform_evidence_unsupported_schema",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			evidence := readyEvidence()
			test.mutate(evidence)
			service, _, _ := readyFixture(t, evidence)
			result := diagnose(t, service)
			if result.Readiness.State != ReadinessUnverified ||
				test.row(t, result) != EvidenceStateUnverified ||
				!contains(result.Readiness.ReasonCodes, test.reason) {
				t.Fatalf("%s result = %#v", test.name, result)
			}
		})
	}
}

func TestDiagnoseEnvironmentAllV1EvidenceReady(t *testing.T) {
	service, _, _ := readyFixture(t, readyEvidence())
	result := diagnose(t, service)
	if result.Readiness.State != ReadinessReady || result.Readiness.ExitCode != 0 || len(result.Readiness.ReasonCodes) != 0 {
		t.Fatalf("readiness = %#v", result.Readiness)
	}
	if len(result.UnverifiedProviderIDs) != 0 {
		t.Fatalf("unverified providers = %v", result.UnverifiedProviderIDs)
	}
	if row := platformRow(t, result, PlatformDarwinARM64); row.EvidenceState != EvidenceStatePass || !row.Native {
		t.Fatalf("darwin authority row = %#v", row)
	}
	if result.ToolsLock.State != ToolsLockLocked {
		t.Fatalf("tools lock = %#v", result.ToolsLock)
	}
}

func TestDiagnoseEnvironmentFailedAndInconclusiveEvidenceRemainUnverified(t *testing.T) {
	for _, test := range []struct {
		name  string
		state EvidenceStatus
		want  EvidenceState
	}{
		{name: "failed", state: EvidenceStatusFail, want: EvidenceStateFail},
		{name: "inconclusive", state: EvidenceStatusInconclusive, want: EvidenceStateInconclusive},
	} {
		t.Run(test.name, func(t *testing.T) {
			evidence := readyEvidence()
			record := evidence.providers["kimi"]
			record.Probes[0].Status = test.state
			evidence.providers["kimi"] = record
			service, _, _ := readyFixture(t, evidence)
			result := diagnose(t, service)
			row := providerRow(t, result, "kimi")
			if result.Readiness.State != ReadinessUnverified || row.EvidenceState != test.want || row.AssignmentState != AssignmentIneligible {
				t.Fatalf("%s record = readiness %#v provider %#v", test.name, result.Readiness, row)
			}
		})
	}
}

func TestDiagnoseEnvironmentFutureCellsAreFixedAndNonBlocking(t *testing.T) {
	evidence := readyEvidence()
	service, _, _ := readyFixture(t, evidence)
	result := diagnose(t, service)
	if result.Readiness.State != ReadinessReady {
		t.Fatalf("future inventory blocked ready result: %#v", result.Readiness)
	}
	if len(result.PlatformEvidence) != 4 {
		t.Fatalf("platform row count = %d", len(result.PlatformEvidence))
	}
	if evidence.platformRead != 1 {
		t.Fatalf("platform evidence reads = %d, want only darwin-arm64", evidence.platformRead)
	}
	for _, cell := range []PlatformCell{PlatformLinuxAMD64, PlatformLinuxARM64, PlatformDarwinAMD64} {
		row := platformRow(t, result, cell)
		if row.Native || row.EvidenceState != EvidenceStateUnverified || !containsAll(row.ReasonCodes, "intended_future", "not_supported", "release_ineligible") {
			t.Fatalf("future row %q = %#v", cell, row)
		}
	}
}

func TestDiagnoseEnvironmentCatalogRootAndToolsFailuresAreIndependent(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*fakeInspector, *fakeCatalog, *fakeEvidence)
		reason string
	}{
		{
			name: "catalog",
			mutate: func(_ *fakeInspector, catalog *fakeCatalog, _ *fakeEvidence) {
				catalog.assets = catalog.assets[:2]
			},
			reason: "contract_catalog_invalid",
		},
		{
			name: "private root",
			mutate: func(inspector *fakeInspector, _ *fakeCatalog, _ *fakeEvidence) {
				inspector.permission = mustPermission(t, false, true, true)
			},
			reason: "private_root_permission_invalid",
		},
		{
			name: "tools lock",
			mutate: func(_ *fakeInspector, _ *fakeCatalog, evidence *fakeEvidence) {
				evidence.tools = ToolsLockObservation{State: ToolsLockMissing}
			},
			reason: "tools_lock_missing",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			evidence := readyEvidence()
			service, inspector, catalog := readyFixture(t, evidence)
			test.mutate(inspector, catalog, evidence)
			result := diagnose(t, service)
			if result.Readiness.State != ReadinessUnverified || !contains(result.Readiness.ReasonCodes, test.reason) {
				t.Fatalf("%s readiness = %#v", test.name, result.Readiness)
			}
		})
	}
}
func TestDiagnoseEnvironmentRequiresEachLockedTool(t *testing.T) {
	for _, missing := range []string{"git", "python3"} {
		t.Run(missing, func(t *testing.T) {
			evidence := readyEvidence()
			tools := make([]ToolObservation, 0, len(evidence.tools.Tools)-1)
			for _, tool := range evidence.tools.Tools {
				if tool.Name != missing {
					tools = append(tools, tool)
				}
			}
			evidence.tools.Tools = tools
			service, _, _ := readyFixture(t, evidence)
			result := diagnose(t, service)
			if result.ToolsLock.State != ToolsLockMismatch ||
				result.Readiness.State != ReadinessUnverified ||
				!contains(result.Readiness.ReasonCodes, "tools_lock_invalid") {
				t.Fatalf("missing %s result = %#v", missing, result)
			}
		})
	}
}
func TestDiagnoseEnvironmentRejectsHiddenOrEmptyToolPath(t *testing.T) {
	for _, path := range []string{"/.gjc/tools/python3", ""} {
		t.Run(path, func(t *testing.T) {
			evidence := readyEvidence()
			evidence.tools.Tools[0].ResolvedPath = path
			service, _, _ := readyFixture(t, evidence)
			result := diagnose(t, service)
			if result.ToolsLock.State != ToolsLockMismatch ||
				result.Readiness.State != ReadinessUnverified ||
				!contains(result.Readiness.ReasonCodes, "tools_lock_invalid") {
				t.Fatalf("tool path %q result = %#v", path, result)
			}
		})
	}
}

func TestDiagnoseEnvironmentReasonsAreSortedUniqueAndDiagnosticsRedacted(t *testing.T) {
	evidence := readyEvidence()
	for _, providerID := range intendedProviderIDs {
		record := evidence.providers[providerID]
		record.SchemaID = "https://mulgae.local/schemas/mulgae-provider-contract-evidence.v1.schema.json"
		evidence.providers[providerID] = record
	}
	evidence.platform.SchemaID = "https://mulgae.local/schemas/mulgae-platform-contract-evidence.v1.schema.json"
	evidence.tools = ToolsLockObservation{State: ToolsLockMissing}
	service, inspector, catalog := readyFixture(t, evidence)
	inspector.platform = mustPlatform(t, "linux", "amd64")
	inspector.permission = mustPermission(t, false, false, false)
	catalog.assets = catalog.assets[:2]
	result := diagnose(t, service)
	if !sort.StringsAreSorted(result.Readiness.ReasonCodes) {
		t.Fatalf("reasons are not sorted: %v", result.Readiness.ReasonCodes)
	}
	for index := 1; index < len(result.Readiness.ReasonCodes); index++ {
		if result.Readiness.ReasonCodes[index-1] == result.Readiness.ReasonCodes[index] {
			t.Fatalf("duplicate readiness reasons: %v", result.Readiness.ReasonCodes)
		}
	}
	for _, diagnostic := range result.Diagnostics {
		if !diagnostic.Redacted || diagnostic.CredentialBytesPersisted || diagnostic.ArtifactURI != nil {
			t.Fatalf("diagnostic is not redacted: %#v", diagnostic)
		}
	}
	if !containsDiagnostic(result.Diagnostics, remoteTransmissionRiskCode) || !containsDiagnostic(result.Diagnostics, snapshotSandboxCode) {
		t.Fatalf("mandatory safety diagnostics missing: %#v", result.Diagnostics)
	}
}

func TestDiagnoseEnvironmentRedactsHiddenEvidenceAndObservationSecrets(t *testing.T) {
	evidence := readyEvidence()
	for _, providerID := range intendedProviderIDs {
		record := evidence.providers[providerID]
		record.URI = ".gjc/session/evidence/TOKEN=provider"
		evidence.providers[providerID] = record
	}
	evidence.platform.URI = ".gjc/session/evidence/TOKEN=platform"
	evidence.tools = ToolsLockObservation{
		State:  ToolsLockLocked,
		URI:    "https://evidence.example/tools-lock",
		SHA256: rawDigest("a"),
		Tools: []ToolObservation{{
			Name:         "python3",
			ResolvedPath: "/usr/bin/python3",
			Version:      "PATH=/private TOKEN=tools",
			SHA256:       rawDigest("b"),
		}},
	}
	service, _, _ := readyFixture(t, evidence)
	result := diagnose(t, service)
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{".gjc", "TOKEN=", "PATH=/private"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("doctor output leaked %q: %s", secret, encoded)
		}
	}
}

type fakeClock struct{ now time.Time }

func (clock fakeClock) Now() time.Time { return clock.now }

type fakeCatalogAsset struct {
	metadata ports.AssetMetadata
	contents []byte
}

type fakeCatalog struct {
	assets  []fakeCatalogAsset
	listErr error
	readErr error
}

func (catalog *fakeCatalog) List(context.Context) ([]ports.AssetMetadata, error) {
	if catalog.listErr != nil {
		return nil, catalog.listErr
	}
	assets := make([]ports.AssetMetadata, len(catalog.assets))
	for index, asset := range catalog.assets {
		assets[index] = asset.metadata
	}
	return assets, nil
}

func (catalog *fakeCatalog) Read(_ context.Context, id ports.AssetID) (ports.AssetMetadata, []byte, error) {
	if catalog.readErr != nil {
		return ports.AssetMetadata{}, nil, catalog.readErr
	}
	for _, asset := range catalog.assets {
		if asset.metadata.ID().String() == id.String() {
			return asset.metadata, append([]byte(nil), asset.contents...), nil
		}
	}
	return ports.AssetMetadata{}, nil, errors.New("asset not found")
}

type fakeInspector struct {
	platform    ports.PlatformObservation
	platformErr error
	permission  ports.PermissionObservation
	permitErr   error
	executables map[string]ports.ExecutableObservation
	execErr     map[string]error
}

func (inspector *fakeInspector) ObservePlatform(context.Context) (ports.PlatformObservation, error) {
	return inspector.platform, inspector.platformErr
}

func (inspector *fakeInspector) ObserveExecutable(_ context.Context, name string) (ports.ExecutableObservation, error) {
	if err := inspector.execErr[name]; err != nil {
		return ports.ExecutableObservation{}, err
	}
	if observation, exists := inspector.executables[name]; exists {
		return observation, nil
	}
	return mustExecutable(nil, name, false, "", "", ""), nil
}
func (inspector *fakeInspector) ObserveExecutableIdentity(ctx context.Context, name string) (ports.ExecutableObservation, error) {
	return inspector.ObserveExecutable(ctx, name)
}
func (*fakeInspector) ObserveReadableFileIdentity(_ context.Context, name string) (ports.FileIdentityObservation, error) {
	return ports.NewFileIdentityObservation(name, false, "", "")
}

func (*fakeInspector) ObserveNativeHomeIdentity(context.Context, string) (ports.NativeHomeLaunchAuthority, error) {
	return ports.NativeHomeLaunchAuthority{}, nil
}

func (inspector *fakeInspector) ObservePermission(context.Context, ports.AnchoredRoot, ports.SafeRelativePath) (ports.PermissionObservation, error) {
	return inspector.permission, inspector.permitErr
}

type fakeEvidence struct {
	providers    map[string]ProviderEvidenceRecord
	providerErr  map[string]error
	platform     PlatformEvidenceRecord
	platformErr  error
	tools        ToolsLockObservation
	toolsErr     error
	platformRead int
}

func (evidence *fakeEvidence) ProviderEvidence(_ context.Context, providerID string) (ProviderEvidenceRecord, error) {
	if err := evidence.providerErr[providerID]; err != nil {
		return ProviderEvidenceRecord{}, err
	}
	return evidence.providers[providerID], nil
}

func (evidence *fakeEvidence) PlatformEvidence(_ context.Context, _ PlatformCell) (PlatformEvidenceRecord, error) {
	evidence.platformRead++
	return evidence.platform, evidence.platformErr
}

func (evidence *fakeEvidence) ToolsLock(context.Context) (ToolsLockObservation, error) {
	return evidence.tools, evidence.toolsErr
}

func readyFixture(t *testing.T, evidence *fakeEvidence) (*Service, *fakeInspector, *fakeCatalog) {
	t.Helper()
	root, err := ports.NewAnchoredRoot("/project")
	if err != nil {
		t.Fatal(err)
	}
	inspector := &fakeInspector{
		platform:    mustPlatform(t, "darwin", "arm64"),
		permission:  mustPermission(t, true, true, true),
		executables: make(map[string]ports.ExecutableObservation),
		execErr:     make(map[string]error),
	}
	for _, providerID := range intendedProviderIDs {
		inspector.executables[providerID] = mustExecutable(t, providerID, true, "/opt/bin/"+providerID, "", "sha256:"+rawDigest("f"))
	}
	catalog := completeCatalog(t)
	service, err := NewService(fakeClock{now: time.Date(2026, time.July, 14, 12, 0, 0, 0, time.UTC)}, catalog, inspector, evidence, root)
	if err != nil {
		t.Fatal(err)
	}
	return service, inspector, catalog
}

func readyEvidence() *fakeEvidence {
	providers := make(map[string]ProviderEvidenceRecord, len(intendedProviderIDs))
	for _, providerID := range intendedProviderIDs {
		providers[providerID] = ProviderEvidenceRecord{
			SchemaID:                providerEvidenceSchemaID,
			ProviderID:              providerID,
			URI:                     "https://evidence.example/providers/" + providerID,
			SHA256:                  rawDigest("a"),
			Probes:                  passingProbes(providerProbeIDs),
			SecureWriterIndexStatus: EvidenceStatusPass,
			AssignmentStatus:        EvidenceStatusPass,
		}
	}
	return &fakeEvidence{
		providers:   providers,
		providerErr: make(map[string]error),
		platform: PlatformEvidenceRecord{
			SchemaID: platformEvidenceSchemaID,
			Cell:     PlatformDarwinARM64,
			URI:      "https://evidence.example/platforms/darwin-arm64",
			SHA256:   rawDigest("b"),
			Native:   true,
			Probes:   passingProbes(platformProbeIDs),
		},
		tools: ToolsLockObservation{
			State:  ToolsLockLocked,
			URI:    "https://evidence.example/tools-lock",
			SHA256: rawDigest("c"),
			Tools: []ToolObservation{
				{Name: "python3", ResolvedPath: "/usr/bin/python3", Version: "Python 3.12.0", SHA256: rawDigest("d")},
				{Name: "git", ResolvedPath: "/usr/bin/git", Version: "git version 2.45.0", SHA256: rawDigest("e")},
			},
		},
	}
}

func completeCatalog(t *testing.T) *fakeCatalog {
	t.Helper()
	assets := make([]fakeCatalogAsset, 0, len(requiredCatalogSchemaIDs))
	for index, idText := range requiredCatalogSchemaIDs {
		id, err := ports.ParseAssetID(idText)
		if err != nil {
			t.Fatal(err)
		}
		source, err := ports.NewSafeRelativePath("schemas/doctor-" + string(rune('a'+index)) + ".json")
		if err != nil {
			t.Fatal(err)
		}
		contents := []byte(idText)
		metadata, err := ports.NewAssetMetadata(id, ports.AssetKindSchema, source, "application/schema+json", digest(contents), int64(len(contents)))
		if err != nil {
			t.Fatal(err)
		}
		assets = append(assets, fakeCatalogAsset{metadata: metadata, contents: contents})
	}
	sort.Slice(assets, func(left, right int) bool {
		return assets[left].metadata.ID().String() < assets[right].metadata.ID().String()
	})
	return &fakeCatalog{assets: assets}
}

func diagnose(t *testing.T, service *Service) DoctorResult {
	t.Helper()
	result, err := service.DiagnoseEnvironment(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func passingProbes(ids []string) []ProbeObservation {
	probes := make([]ProbeObservation, len(ids))
	for index, id := range ids {
		probes[index] = ProbeObservation{ID: id, Status: EvidenceStatusPass}
	}
	return probes
}

func mustPlatform(t *testing.T, operatingSystem, architecture string) ports.PlatformObservation {
	if t != nil {
		t.Helper()
	}
	observation, err := ports.NewPlatformObservation(operatingSystem, architecture)
	if err != nil {
		if t != nil {
			t.Fatal(err)
		}
		panic(err)
	}
	return observation
}

func mustPermission(t *testing.T, readable, writable, executable bool) ports.PermissionObservation {
	if t != nil {
		t.Helper()
	}
	path, err := ports.NewSafeRelativePath(privateRootPath)
	if err != nil {
		t.Fatal(err)
	}
	observation, err := ports.NewPermissionObservation(path, readable, writable, executable)
	if err != nil {
		t.Fatal(err)
	}
	return observation
}

func mustExecutable(t *testing.T, name string, found bool, resolvedPath, version, sha256 string) ports.ExecutableObservation {
	if t != nil {
		t.Helper()
	}
	observation, err := ports.NewExecutableObservation(name, found, resolvedPath, version, sha256)
	if err != nil {
		if t != nil {
			t.Fatal(err)
		}
		panic(err)
	}
	return observation
}

func rawDigest(character string) string {
	return strings.Repeat(character, 64)
}

func digest(contents []byte) string {
	sum := sha256.Sum256(contents)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func providerRow(t *testing.T, result DoctorResult, providerID string) ProviderEvidence {
	t.Helper()
	for _, row := range result.ProviderEvidence {
		if row.ProviderID == providerID {
			return row
		}
	}
	t.Fatalf("provider row %q was not found", providerID)
	return ProviderEvidence{}
}

func platformRow(t *testing.T, result DoctorResult, cell PlatformCell) PlatformEvidence {
	t.Helper()
	for _, row := range result.PlatformEvidence {
		if row.Cell == cell {
			return row
		}
	}
	t.Fatalf("platform row %q was not found", cell)
	return PlatformEvidence{}
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func containsDiagnostic(diagnostics []Diagnostic, code string) bool {
	for _, diagnostic := range diagnostics {
		if diagnostic.Code == code {
			return true
		}
	}
	return false
}
