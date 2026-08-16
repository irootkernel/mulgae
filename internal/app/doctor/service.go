package doctor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"reflect"
	"sort"
	"strings"

	"github.com/irootkernel/mulgae/internal/ports"
)

const privateRootPath = ".mulgae"

var requiredCatalogSchemaIDs = []string{
	providerEvidenceSchemaID,
	platformEvidenceSchemaID,
}

// Service observes doctor readiness through injected inward ports. It never
// imports adapters or performs a provider/platform probe.
type Service struct {
	clock       ports.Clock
	catalog     ports.ContractCatalog
	inspector   ports.EnvironmentInspector
	evidence    EvidenceReader
	projectRoot ports.AnchoredRoot
}

// NewService constructs a doctor service. Evidence is deliberately optional:
// a nil reader is reported as unverified authority evidence rather than being
// replaced with a probe or fabricated PASS result.
func NewService(clock ports.Clock, catalog ports.ContractCatalog, inspector ports.EnvironmentInspector, evidence EvidenceReader, projectRoot ports.AnchoredRoot) (*Service, error) {
	if nilInterface(clock) {
		return nil, fmt.Errorf("doctor: nil clock")
	}
	if nilInterface(catalog) {
		return nil, fmt.Errorf("doctor: nil contract catalog")
	}
	if nilInterface(inspector) {
		return nil, fmt.Errorf("doctor: nil environment inspector")
	}
	if !projectRoot.Valid() {
		return nil, fmt.Errorf("doctor: invalid project root")
	}
	return &Service{
		clock:       clock,
		catalog:     catalog,
		inspector:   inspector,
		evidence:    evidence,
		projectRoot: projectRoot,
	}, nil
}

// DiagnoseEnvironment returns a complete redacted doctor result. Operational
// observations that cannot be obtained remain readiness failures in the
// result, allowing users to see all independently observed blockers at once.
func (service *Service) DiagnoseEnvironment(ctx context.Context) (DoctorResult, error) {
	var zero DoctorResult
	if ctx == nil {
		return zero, fmt.Errorf("doctor: nil context")
	}
	if service == nil || nilInterface(service.clock) || nilInterface(service.catalog) || nilInterface(service.inspector) || !service.projectRoot.Valid() {
		return zero, fmt.Errorf("doctor: invalid service dependencies")
	}
	if err := ctx.Err(); err != nil {
		return zero, fmt.Errorf("doctor: context: %w", err)
	}
	checkedAt := service.clock.Now().UTC()
	if checkedAt.IsZero() {
		return zero, fmt.Errorf("doctor: clock returned zero time")
	}

	reasons := make([]string, 0, 16)
	addReason := func(code string) {
		reasons = append(reasons, code)
	}
	if !validateCatalog(ctx, service.catalog) {
		addReason("contract_catalog_invalid")
	}
	if !validateIntendedProviderIDs() {
		addReason("intended_provider_ids_invalid")
	}

	hostIsDarwinARM64 := service.observePlatform(ctx, addReason)
	service.observePrivateRoot(ctx, addReason)
	providerRows := make([]ProviderEvidence, 0, len(intendedProviderIDs))
	unverifiedProviders := make([]string, 0, len(intendedProviderIDs))
	for _, providerID := range intendedProviderIDs {
		row := service.providerEvidence(ctx, providerID)
		providerRows = append(providerRows, row)
		if row.EvidenceState != EvidenceStatePass {
			unverifiedProviders = append(unverifiedProviders, providerID)
			addReason(row.ReasonCodes[0])
		}
	}

	platformRows := futurePlatformRows()
	darwinRow := service.darwinEvidence(ctx, hostIsDarwinARM64)
	platformRows = append(platformRows, darwinRow)
	if darwinRow.EvidenceState != EvidenceStatePass {
		addReason(darwinRow.ReasonCodes[0])
	}

	lock, lockReason := service.toolsLock(ctx)
	if lockReason != "" {
		addReason(lockReason)
	}

	reasons = sortedUnique(reasons)
	readiness := Readiness{State: ReadinessReady, ExitCode: 0, ReasonCodes: []string{}}
	if len(reasons) != 0 {
		readiness = Readiness{State: ReadinessUnverified, ExitCode: 4, ReasonCodes: reasons}
	}
	result := DoctorResult{
		SchemaVersion:         SchemaVersion,
		CheckedAt:             checkedAt,
		ProjectRoot:           service.projectRoot.String(),
		IntendedProviderIDs:   append([]string(nil), intendedProviderIDs...),
		UnverifiedProviderIDs: unverifiedProviders,
		ProviderEvidence:      providerRows,
		PlatformEvidence:      platformRows,
		ToolsLock:             lock,
		Readiness:             readiness,
		Diagnostics:           diagnosticsFor(reasons),
	}
	if err := result.Validate(); err != nil {
		return zero, fmt.Errorf("doctor: result invariant: %w", err)
	}
	return result, nil
}

func (service *Service) observePlatform(ctx context.Context, addReason func(string)) bool {
	observation, err := service.inspector.ObservePlatform(ctx)
	if err != nil || observation.OperatingSystem() == "" || observation.Architecture() == "" {
		addReason("platform_observation_invalid")
		return false
	}
	if observation.OperatingSystem() != "darwin" || observation.Architecture() != "arm64" {
		addReason("host_platform_not_supported")
		return false
	}
	return true
}

func (service *Service) observePrivateRoot(ctx context.Context, addReason func(string)) {
	path, err := ports.NewSafeRelativePath(privateRootPath)
	if err != nil {
		addReason("private_root_permission_invalid")
		return
	}
	observation, err := service.inspector.ObservePermission(ctx, service.projectRoot, path)
	if err != nil || observation.Path().String() != privateRootPath || !observation.Readable() || !observation.Writable() || !observation.Executable() {
		addReason("private_root_permission_invalid")
	}
}

func (service *Service) providerEvidence(ctx context.Context, providerID string) ProviderEvidence {
	unverified := func(reason string) ProviderEvidence {
		return ProviderEvidence{
			ProviderID:      providerID,
			Intended:        true,
			AssignmentState: AssignmentIntendedButUnverified,
			EvidenceState:   EvidenceStateUnverified,
			ReasonCodes:     []string{reason},
		}
	}
	if nilInterface(service.evidence) {
		return unverified("provider_evidence_unavailable")
	}
	record, err := service.evidence.ProviderEvidence(ctx, providerID)
	if err != nil || record.SchemaID == "" {
		return unverified("provider_evidence_unavailable")
	}
	if record.SchemaID != providerEvidenceSchemaID {
		return unverified("provider_evidence_unsupported_schema")
	}
	if err := validateProviderRecord(record, providerID); err != nil {
		return unverified("provider_evidence_invalid")
	}
	state := aggregateStatuses(record.Probes, record.SecureWriterIndexStatus, record.AssignmentStatus)
	uri := record.URI
	digest := "sha256:" + record.SHA256
	switch state {
	case EvidenceStatusPass:
		return ProviderEvidence{
			ProviderID:      providerID,
			Intended:        true,
			AssignmentState: AssignmentEligible,
			EvidenceState:   EvidenceStatePass,
			EvidenceURI:     &uri,
			EvidenceSHA256:  &digest,
			ReasonCodes:     []string{},
		}
	case EvidenceStatusFail:
		return ProviderEvidence{
			ProviderID:      providerID,
			Intended:        true,
			AssignmentState: AssignmentIneligible,
			EvidenceState:   EvidenceStateFail,
			EvidenceURI:     &uri,
			EvidenceSHA256:  &digest,
			ReasonCodes:     []string{"provider_evidence_failed"},
		}
	case EvidenceStatusInconclusive:
		return ProviderEvidence{
			ProviderID:      providerID,
			Intended:        true,
			AssignmentState: AssignmentIneligible,
			EvidenceState:   EvidenceStateInconclusive,
			EvidenceURI:     &uri,
			EvidenceSHA256:  &digest,
			ReasonCodes:     []string{"provider_evidence_inconclusive"},
		}
	default:
		return unverified("provider_evidence_not_run")
	}
}

func (service *Service) darwinEvidence(ctx context.Context, hostIsDarwinARM64 bool) PlatformEvidence {
	unverified := func(reason string) PlatformEvidence {
		return PlatformEvidence{
			Cell:          PlatformDarwinARM64,
			Native:        false,
			EvidenceState: EvidenceStateUnverified,
			ReasonCodes:   []string{reason},
		}
	}
	if !hostIsDarwinARM64 {
		return unverified("host_platform_not_supported")
	}
	if nilInterface(service.evidence) {
		return unverified("platform_evidence_unavailable")
	}
	record, err := service.evidence.PlatformEvidence(ctx, PlatformDarwinARM64)
	if err != nil || record.SchemaID == "" {
		return unverified("platform_evidence_unavailable")
	}
	if record.SchemaID != platformEvidenceSchemaID {
		return unverified("platform_evidence_unsupported_schema")
	}
	if err := validatePlatformRecord(record); err != nil {
		return unverified("platform_evidence_invalid")
	}
	uri := record.URI
	digest := "sha256:" + record.SHA256
	switch aggregateStatuses(record.Probes) {
	case EvidenceStatusPass:
		return PlatformEvidence{
			Cell:           PlatformDarwinARM64,
			Native:         true,
			EvidenceState:  EvidenceStatePass,
			EvidenceURI:    &uri,
			EvidenceSHA256: &digest,
			ReasonCodes:    []string{},
		}
	case EvidenceStatusFail:
		return PlatformEvidence{
			Cell:           PlatformDarwinARM64,
			Native:         true,
			EvidenceState:  EvidenceStateFail,
			EvidenceURI:    &uri,
			EvidenceSHA256: &digest,
			ReasonCodes:    []string{"platform_evidence_failed"},
		}
	case EvidenceStatusInconclusive:
		return PlatformEvidence{
			Cell:           PlatformDarwinARM64,
			Native:         true,
			EvidenceState:  EvidenceStateInconclusive,
			EvidenceURI:    &uri,
			EvidenceSHA256: &digest,
			ReasonCodes:    []string{"platform_evidence_inconclusive"},
		}
	default:
		return unverified("platform_evidence_not_run")
	}
}

func (service *Service) toolsLock(ctx context.Context) (ToolsLock, string) {
	missing := func(reason string) (ToolsLock, string) {
		return ToolsLock{State: ToolsLockMissing, Tools: []Tool{}}, reason
	}
	if nilInterface(service.evidence) {
		return missing("tools_lock_unavailable")
	}
	observation, err := service.evidence.ToolsLock(ctx)
	if err != nil {
		return missing("tools_lock_unavailable")
	}
	switch observation.State {
	case ToolsLockMissing:
		return missing("tools_lock_missing")
	case ToolsLockMismatch:
		return ToolsLock{State: ToolsLockMismatch, Tools: []Tool{}}, "tools_lock_mismatch"
	case ToolsLockLocked:
		if err := validateToolsLockObservation(observation); err != nil {
			return ToolsLock{State: ToolsLockMismatch, Tools: []Tool{}}, "tools_lock_invalid"
		}
		uri := observation.URI
		digest := "sha256:" + observation.SHA256
		tools := make([]Tool, len(observation.Tools))
		for index, tool := range observation.Tools {
			tools[index] = Tool{
				Name:         tool.Name,
				ResolvedPath: tool.ResolvedPath,
				Version:      tool.Version,
				SHA256:       "sha256:" + tool.SHA256,
			}
		}
		return ToolsLock{State: ToolsLockLocked, URI: &uri, SHA256: &digest, Tools: tools}, ""
	default:
		return ToolsLock{State: ToolsLockMismatch, Tools: []Tool{}}, "tools_lock_invalid"
	}
}

func futurePlatformRows() []PlatformEvidence {
	reasons := []string{"intended_future", "not_supported", "release_ineligible"}
	rows := make([]PlatformEvidence, 0, 3)
	for _, cell := range platformCells[:3] {
		rows = append(rows, PlatformEvidence{
			Cell:          cell,
			Native:        false,
			EvidenceState: EvidenceStateUnverified,
			ReasonCodes:   append([]string(nil), reasons...),
		})
	}
	return rows
}

func validateCatalog(ctx context.Context, catalog ports.ContractCatalog) bool {
	assets, err := catalog.List(ctx)
	if err != nil || len(assets) == 0 {
		return false
	}
	required := make(map[string]struct{}, len(requiredCatalogSchemaIDs))
	for _, id := range requiredCatalogSchemaIDs {
		required[id] = struct{}{}
	}
	seen := make(map[string]struct{}, len(assets))
	previous := ""
	for _, metadata := range assets {
		id := metadata.ID().String()
		if !metadata.ID().Valid() || !metadata.Kind().Valid() || !metadata.Source().Valid() || metadata.MediaType() == "" || !validPrefixedDigest(metadata.SHA256()) || metadata.ByteLength() < 0 || id <= previous {
			return false
		}
		if _, duplicate := seen[id]; duplicate {
			return false
		}
		if _, requiredSchema := required[id]; requiredSchema && metadata.Kind() != ports.AssetKindSchema {
			return false
		}
		seen[id] = struct{}{}
		previous = id
		readMetadata, contents, err := catalog.Read(ctx, metadata.ID())
		if err != nil || readMetadata != metadata || int64(len(contents)) != metadata.ByteLength() || !matchesDigest(contents, metadata.SHA256()) {
			return false
		}
	}
	for _, id := range requiredCatalogSchemaIDs {
		if _, exists := seen[id]; !exists {
			return false
		}
	}
	return true
}

func validateIntendedProviderIDs() bool {
	if len(intendedProviderIDs) != 4 {
		return false
	}
	seen := make(map[string]struct{}, len(intendedProviderIDs))
	for _, providerID := range intendedProviderIDs {
		if !validProviderID(providerID) {
			return false
		}
		if _, duplicate := seen[providerID]; duplicate {
			return false
		}
		seen[providerID] = struct{}{}
	}
	return true
}

func validateProviderRecord(record ProviderEvidenceRecord, providerID string) error {
	if record.ProviderID != providerID || !safeEvidenceURI(record.URI) || !validRawSHA256(record.SHA256) {
		return fmt.Errorf("identity, URI, or SHA-256 is invalid")
	}
	if !validProbeSet(record.Probes, providerProbeIDs) || !record.SecureWriterIndexStatus.valid() || !record.AssignmentStatus.valid() {
		return fmt.Errorf("provider evidence predicates are incomplete")
	}
	return nil
}

func validatePlatformRecord(record PlatformEvidenceRecord) error {
	if record.Cell != PlatformDarwinARM64 || !record.Native || !safeEvidenceURI(record.URI) || !validRawSHA256(record.SHA256) {
		return fmt.Errorf("identity, native state, URI, or SHA-256 is invalid")
	}
	if !validProbeSet(record.Probes, platformProbeIDs) {
		return fmt.Errorf("platform evidence predicates are incomplete")
	}
	return nil
}

func validateToolsLockObservation(observation ToolsLockObservation) error {
	if !safeEvidenceURI(observation.URI) || !validRawSHA256(observation.SHA256) || !validToolObservationSet(observation.Tools) {
		return fmt.Errorf("tools lock identity is invalid")
	}
	return nil
}

func validProbeSet(probes []ProbeObservation, expected []string) bool {
	if len(probes) != len(expected) {
		return false
	}
	for index, expectedID := range expected {
		if probes[index].ID != expectedID || !probes[index].Status.valid() {
			return false
		}
	}
	return true
}

func aggregateStatuses(probes []ProbeObservation, additional ...EvidenceStatus) EvidenceStatus {
	statuses := make([]EvidenceStatus, 0, len(probes)+len(additional))
	for _, probe := range probes {
		statuses = append(statuses, probe.Status)
	}
	statuses = append(statuses, additional...)
	if len(statuses) == 0 {
		return EvidenceStatusNotRun
	}
	for _, status := range statuses {
		if status == EvidenceStatusFail {
			return EvidenceStatusFail
		}
	}
	for _, status := range statuses {
		if status == EvidenceStatusInconclusive {
			return EvidenceStatusInconclusive
		}
	}
	for _, status := range statuses {
		if status != EvidenceStatusPass {
			return EvidenceStatusNotRun
		}
	}
	return EvidenceStatusPass
}

func diagnosticsFor(reasons []string) []Diagnostic {
	diagnostics := []Diagnostic{
		{
			Code:                     remoteTransmissionRiskCode,
			Category:                 DiagnosticSecurity,
			Message:                  remoteTransmissionRiskMessage,
			Redacted:                 true,
			CredentialBytesPersisted: false,
		},
		{
			Code:                     snapshotSandboxCode,
			Category:                 DiagnosticSecurity,
			Message:                  snapshotSandboxMessage,
			Redacted:                 true,
			CredentialBytesPersisted: false,
		},
	}
	for _, reason := range reasons {
		diagnostics = append(diagnostics, Diagnostic{
			Code:                     reason,
			Category:                 diagnosticCategory(reason),
			Message:                  diagnosticMessage(reason),
			Redacted:                 true,
			CredentialBytesPersisted: false,
		})
	}
	sort.Slice(diagnostics, func(left, right int) bool {
		return diagnostics[left].Code < diagnostics[right].Code
	})
	return diagnostics
}

func diagnosticCategory(reason string) DiagnosticCategory {
	switch reason {
	case "contract_catalog_invalid", "intended_provider_ids_invalid":
		return DiagnosticConfiguration
	case "private_root_permission_invalid":
		return DiagnosticSecurity
	default:
		return DiagnosticReadiness
	}
}

func diagnosticMessage(reason string) string {
	switch reason {
	case "contract_catalog_invalid":
		return "The embedded contract catalog is incomplete or failed integrity verification."
	case "private_root_permission_invalid":
		return "The private project root does not have the required read, write, and execute permissions."
	case "host_platform_not_supported":
		return "The observed host is not the required darwin-arm64 platform."
	case "provider_evidence_unsupported_schema", "platform_evidence_unsupported_schema":
		return "Only the version 1 evidence contract can establish readiness; the observed schema is unsupported."
	case "tools_lock_missing", "tools_lock_unavailable":
		return "A complete tools lock observation is required for readiness."
	default:
		return "Readiness remains unverified because required authority evidence or observations are incomplete."
	}
}

func safeEvidenceURI(value string) bool {
	return value != "" && redactedText(value, 4096) && !hiddenReference(value)
}

func validPrefixedDigest(value string) bool {
	return strings.HasPrefix(value, "sha256:") && validRawSHA256(strings.TrimPrefix(value, "sha256:"))
}

func matchesDigest(contents []byte, expected string) bool {
	sum := sha256.Sum256(contents)
	return bytes.Equal([]byte(expected), []byte("sha256:"+hex.EncodeToString(sum[:])))
}

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflectValue := reflect.ValueOf(value)
	switch reflectValue.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return reflectValue.IsNil()
	default:
		return false
	}
}
