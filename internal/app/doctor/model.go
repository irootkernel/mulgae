// Package doctor reports redacted, evidence-backed environment readiness.
package doctor

import (
	"fmt"
	"net/url"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	// SchemaVersion is the fixed doctor-result contract version.
	SchemaVersion = "mulgae-doctor-result.v1"

	remoteTransmissionRiskCode    = "remote_provider_transmission_risk"
	remoteTransmissionRiskMessage = "Providers may transmit prompts and targets to remote services; select providers appropriate for your data policy."
	snapshotSandboxCode           = "snapshot_not_mathematical_sandbox"
	snapshotSandboxMessage        = "Mutation detection and read-only snapshots reduce risk but are not a mathematical sandbox."
)

// EvidenceState is the normalized result of an authority evidence record.
type EvidenceState string

const (
	EvidenceStatePass         EvidenceState = "pass"
	EvidenceStateInconclusive EvidenceState = "inconclusive"
	EvidenceStateFail         EvidenceState = "fail"
	EvidenceStateUnverified   EvidenceState = "unverified"
)

// AssignmentState reports whether an intended provider can currently join an
// assignment. Intended providers without authority evidence remain unverified.
type AssignmentState string

const (
	AssignmentIntendedButUnverified AssignmentState = "intended_but_unverified"
	AssignmentEligible              AssignmentState = "eligible"
	AssignmentIneligible            AssignmentState = "ineligible"
)

// PlatformCell is one fixed platform inventory cell.
type PlatformCell string

const (
	PlatformLinuxAMD64  PlatformCell = "linux-amd64"
	PlatformLinuxARM64  PlatformCell = "linux-arm64"
	PlatformDarwinAMD64 PlatformCell = "darwin-amd64"
	PlatformDarwinARM64 PlatformCell = "darwin-arm64"
)

// ToolsLockState is the state of the observed tool-lock record.
type ToolsLockState string

const (
	ToolsLockLocked   ToolsLockState = "locked"
	ToolsLockMissing  ToolsLockState = "missing"
	ToolsLockMismatch ToolsLockState = "mismatch"
)

// ReadinessState is the process-readiness projection.
type ReadinessState string

const (
	ReadinessReady      ReadinessState = "ready"
	ReadinessUnverified ReadinessState = "unverified"
)

// DiagnosticCategory classifies a redacted doctor diagnostic.
type DiagnosticCategory string

const (
	DiagnosticConfiguration DiagnosticCategory = "configuration"
	DiagnosticReadiness     DiagnosticCategory = "readiness"
	DiagnosticArtifact      DiagnosticCategory = "artifact"
	DiagnosticSecurity      DiagnosticCategory = "security"
)

// DoctorResult is the mulgae-doctor-result.v1 JSON document.
type DoctorResult struct {
	SchemaVersion         string             `json:"schema_version"`
	CheckedAt             time.Time          `json:"checked_at"`
	ProjectRoot           string             `json:"project_root"`
	IntendedProviderIDs   []string           `json:"intended_provider_ids"`
	UnverifiedProviderIDs []string           `json:"unverified_provider_ids"`
	ProviderEvidence      []ProviderEvidence `json:"provider_evidence"`
	PlatformEvidence      []PlatformEvidence `json:"platform_evidence"`
	ToolsLock             ToolsLock          `json:"tools_lock"`
	Readiness             Readiness          `json:"readiness"`
	Diagnostics           []Diagnostic       `json:"diagnostics"`
}

// ProviderEvidence is the redacted readiness projection for one provider.
type ProviderEvidence struct {
	ProviderID      string          `json:"provider_id"`
	Intended        bool            `json:"intended"`
	AssignmentState AssignmentState `json:"assignment_state"`
	EvidenceState   EvidenceState   `json:"evidence_state"`
	EvidenceURI     *string         `json:"evidence_uri"`
	EvidenceSHA256  *string         `json:"evidence_sha256"`
	ReasonCodes     []string        `json:"reason_codes"`
}

// PlatformEvidence is the redacted readiness projection for one platform cell.
type PlatformEvidence struct {
	Cell           PlatformCell  `json:"cell"`
	Native         bool          `json:"native"`
	EvidenceState  EvidenceState `json:"evidence_state"`
	EvidenceURI    *string       `json:"evidence_uri"`
	EvidenceSHA256 *string       `json:"evidence_sha256"`
	ReasonCodes    []string      `json:"reason_codes"`
}

// ToolsLock records the checked tool-lock observation without environment data.
type ToolsLock struct {
	State  ToolsLockState `json:"state"`
	URI    *string        `json:"uri"`
	SHA256 *string        `json:"sha256"`
	Tools  []Tool         `json:"tools"`
}

// Tool records one locked tool identity.
type Tool struct {
	Name         string `json:"name"`
	ResolvedPath string `json:"resolved_path"`
	Version      string `json:"version"`
	SHA256       string `json:"sha256"`
}

// Readiness is the terminal doctor readiness result and CLI exit projection.
type Readiness struct {
	State       ReadinessState `json:"state"`
	ExitCode    int            `json:"exit_code"`
	ReasonCodes []string       `json:"reason_codes"`
}

// Diagnostic is a redacted user-facing explanation. It intentionally does not
// carry arbitrary observation errors or environment/configuration bytes.
type Diagnostic struct {
	Code                     string             `json:"code"`
	Category                 DiagnosticCategory `json:"category"`
	Message                  string             `json:"message"`
	Redacted                 bool               `json:"redacted"`
	CredentialBytesPersisted bool               `json:"credential_bytes_persisted"`
	ArtifactURI              *string            `json:"artifact_uri"`
}

// Validate checks the semantic invariants that supplement the JSON contract.
func (result DoctorResult) Validate() error {
	if result.SchemaVersion != SchemaVersion {
		return fmt.Errorf("doctor result: schema version %q is invalid", result.SchemaVersion)
	}
	if result.CheckedAt.IsZero() || result.CheckedAt.Location() != time.UTC {
		return fmt.Errorf("doctor result: checked_at must be a non-zero UTC time")
	}
	if !validText(result.ProjectRoot, 4096) || result.ProjectRoot == "" {
		return fmt.Errorf("doctor result: project_root is invalid")
	}
	if err := validateProviderIDs(result.IntendedProviderIDs, true); err != nil {
		return fmt.Errorf("doctor result: intended_provider_ids: %w", err)
	}
	if err := validateProviderIDs(result.UnverifiedProviderIDs, false); err != nil {
		return fmt.Errorf("doctor result: unverified_provider_ids: %w", err)
	}
	intended := stringSet(result.IntendedProviderIDs)
	unverified := stringSet(result.UnverifiedProviderIDs)
	for providerID := range unverified {
		if _, exists := intended[providerID]; !exists {
			return fmt.Errorf("doctor result: unverified provider %q is not intended", providerID)
		}
	}
	if len(result.ProviderEvidence) == 0 || len(result.ProviderEvidence) > 32 {
		return fmt.Errorf("doctor result: provider_evidence has invalid length")
	}
	providers := make(map[string]ProviderEvidence, len(result.ProviderEvidence))
	for _, evidence := range result.ProviderEvidence {
		if err := evidence.validate(); err != nil {
			return err
		}
		_, expectedIntended := intended[evidence.ProviderID]
		if evidence.Intended != expectedIntended {
			return fmt.Errorf("doctor result: provider %q intended projection does not match intended_provider_ids", evidence.ProviderID)
		}
		if _, duplicate := providers[evidence.ProviderID]; duplicate {
			return fmt.Errorf("doctor result: duplicate provider evidence for %q", evidence.ProviderID)
		}
		providers[evidence.ProviderID] = evidence
	}
	for providerID := range intended {
		evidence, exists := providers[providerID]
		if !exists || !evidence.Intended {
			return fmt.Errorf("doctor result: intended provider %q has no intended evidence row", providerID)
		}
		_, shouldBeUnverified := unverified[providerID]
		if shouldBeUnverified == (evidence.EvidenceState == EvidenceStatePass) {
			return fmt.Errorf("doctor result: provider %q unverified projection does not match evidence", providerID)
		}
	}
	if err := validatePlatformEvidence(result.PlatformEvidence); err != nil {
		return err
	}
	if err := result.ToolsLock.validate(); err != nil {
		return err
	}
	if err := result.Readiness.validate(); err != nil {
		return err
	}
	if result.Readiness.State == ReadinessReady {
		if err := validateReadyProjection(providers, result.PlatformEvidence, result.ToolsLock); err != nil {
			return err
		}
	}
	if len(result.Diagnostics) > 256 {
		return fmt.Errorf("doctor result: diagnostics has invalid length")
	}
	diagnosticCodes := make(map[string]struct{}, len(result.Diagnostics))
	for _, diagnostic := range result.Diagnostics {
		if err := diagnostic.validate(); err != nil {
			return err
		}
		if _, duplicate := diagnosticCodes[diagnostic.Code]; duplicate {
			return fmt.Errorf("doctor result: duplicate diagnostic code %q", diagnostic.Code)
		}
		diagnosticCodes[diagnostic.Code] = struct{}{}
		switch diagnostic.Code {
		case remoteTransmissionRiskCode:
			if diagnostic.Category != DiagnosticSecurity || diagnostic.Message != remoteTransmissionRiskMessage {
				return fmt.Errorf("doctor result: remote provider transmission diagnostic is invalid")
			}
		case snapshotSandboxCode:
			if diagnostic.Category != DiagnosticSecurity || diagnostic.Message != snapshotSandboxMessage {
				return fmt.Errorf("doctor result: snapshot sandbox diagnostic is invalid")
			}
		}
	}
	if _, exists := diagnosticCodes[remoteTransmissionRiskCode]; !exists {
		return fmt.Errorf("doctor result: remote provider transmission diagnostic is required")
	}
	if _, exists := diagnosticCodes[snapshotSandboxCode]; !exists {
		return fmt.Errorf("doctor result: snapshot sandbox diagnostic is required")
	}
	return nil
}

func validateReadyProjection(providers map[string]ProviderEvidence, platforms []PlatformEvidence, lock ToolsLock) error {
	for providerID, evidence := range providers {
		if !evidence.Intended {
			continue
		}
		if evidence.AssignmentState != AssignmentEligible || evidence.EvidenceState != EvidenceStatePass {
			return fmt.Errorf("doctor result: ready state has provider blocker %q", providerID)
		}
	}
	for _, platform := range platforms {
		if platform.Cell == PlatformDarwinARM64 && (!platform.Native || platform.EvidenceState != EvidenceStatePass) {
			return fmt.Errorf("doctor result: ready state has darwin-arm64 platform blocker")
		}
	}
	if lock.State != ToolsLockLocked {
		return fmt.Errorf("doctor result: ready state has tools lock blocker")
	}
	return nil
}
func (evidence ProviderEvidence) validate() error {
	if !validProviderID(evidence.ProviderID) {
		return fmt.Errorf("doctor result: provider evidence provider_id %q is invalid", evidence.ProviderID)
	}
	if !evidence.AssignmentState.valid() || !evidence.EvidenceState.valid() {
		return fmt.Errorf("doctor result: provider %q has an invalid state", evidence.ProviderID)
	}
	if err := validateReasonCodes(evidence.ReasonCodes, 32, false); err != nil {
		return fmt.Errorf("doctor result: provider %q reason_codes: %w", evidence.ProviderID, err)
	}
	switch evidence.AssignmentState {
	case AssignmentEligible:
		if !evidence.Intended ||
			evidence.EvidenceState != EvidenceStatePass ||
			!validAuthorityMetadata(evidence.EvidenceURI, evidence.EvidenceSHA256) ||
			len(evidence.ReasonCodes) != 0 {
			return fmt.Errorf("doctor result: eligible provider %q has an invalid projection", evidence.ProviderID)
		}
	case AssignmentIneligible:
		if !validAuthorityMetadata(evidence.EvidenceURI, evidence.EvidenceSHA256) {
			return fmt.Errorf("doctor result: ineligible provider %q has invalid authority metadata", evidence.ProviderID)
		}
		switch evidence.EvidenceState {
		case EvidenceStateFail:
			if !exactReasonCodes(evidence.ReasonCodes, "provider_evidence_failed") {
				return fmt.Errorf("doctor result: failed provider %q has invalid reasons", evidence.ProviderID)
			}
		case EvidenceStateInconclusive:
			if !exactReasonCodes(evidence.ReasonCodes, "provider_evidence_inconclusive") {
				return fmt.Errorf("doctor result: inconclusive provider %q has invalid reasons", evidence.ProviderID)
			}
		default:
			return fmt.Errorf("doctor result: ineligible provider %q has an invalid evidence state", evidence.ProviderID)
		}
	case AssignmentIntendedButUnverified:
		if !evidence.Intended ||
			evidence.EvidenceState != EvidenceStateUnverified ||
			evidence.EvidenceURI != nil ||
			evidence.EvidenceSHA256 != nil ||
			!validProviderUnverifiedReasonCodes(evidence.ReasonCodes) {
			return fmt.Errorf("doctor result: intended unverified provider %q has an invalid projection", evidence.ProviderID)
		}
	}
	return nil
}

func validatePlatformEvidence(rows []PlatformEvidence) error {
	if len(rows) != 4 {
		return fmt.Errorf("doctor result: platform_evidence must contain four cells")
	}
	seen := make(map[PlatformCell]struct{}, len(rows))
	for _, row := range rows {
		if !row.Cell.valid() {
			return fmt.Errorf("doctor result: platform evidence cell %q is invalid", row.Cell)
		}
		if _, duplicate := seen[row.Cell]; duplicate {
			return fmt.Errorf("doctor result: duplicate platform cell %q", row.Cell)
		}
		seen[row.Cell] = struct{}{}
		if !row.EvidenceState.valid() {
			return fmt.Errorf("doctor result: platform %q has an invalid evidence state", row.Cell)
		}
		if err := validateReasonCodes(row.ReasonCodes, 32, false); err != nil {
			return fmt.Errorf("doctor result: platform %q reason_codes: %w", row.Cell, err)
		}
		if row.Cell != PlatformDarwinARM64 {
			if row.Native ||
				row.EvidenceState != EvidenceStateUnverified ||
				row.EvidenceURI != nil ||
				row.EvidenceSHA256 != nil ||
				!exactReasonCodes(row.ReasonCodes, "intended_future", "not_supported", "release_ineligible") {
				return fmt.Errorf("doctor result: future platform %q is not a fixed unsupported row", row.Cell)
			}
			continue
		}
		switch row.EvidenceState {
		case EvidenceStatePass:
			if !row.Native || !validAuthorityMetadata(row.EvidenceURI, row.EvidenceSHA256) || len(row.ReasonCodes) != 0 {
				return fmt.Errorf("doctor result: darwin-arm64 pass evidence is invalid")
			}
		case EvidenceStateFail:
			if !row.Native || !validAuthorityMetadata(row.EvidenceURI, row.EvidenceSHA256) || !exactReasonCodes(row.ReasonCodes, "platform_evidence_failed") {
				return fmt.Errorf("doctor result: darwin-arm64 failed evidence is invalid")
			}
		case EvidenceStateInconclusive:
			if !row.Native || !validAuthorityMetadata(row.EvidenceURI, row.EvidenceSHA256) || !exactReasonCodes(row.ReasonCodes, "platform_evidence_inconclusive") {
				return fmt.Errorf("doctor result: darwin-arm64 inconclusive evidence is invalid")
			}
		case EvidenceStateUnverified:
			if row.Native ||
				row.EvidenceURI != nil ||
				row.EvidenceSHA256 != nil ||
				!validPlatformUnverifiedReasonCodes(row.ReasonCodes) {
				return fmt.Errorf("doctor result: darwin-arm64 unverified evidence is invalid")
			}
		}
	}
	for _, cell := range platformCells {
		if _, exists := seen[cell]; !exists {
			return fmt.Errorf("doctor result: platform cell %q is missing", cell)
		}
	}
	return nil
}

func (lock ToolsLock) validate() error {
	if !lock.State.valid() {
		return fmt.Errorf("doctor result: tools_lock state %q is invalid", lock.State)
	}
	switch lock.State {
	case ToolsLockLocked:
		if !validAuthorityMetadata(lock.URI, lock.SHA256) || !validToolSet(lock.Tools) {
			return fmt.Errorf("doctor result: locked tools_lock is incomplete")
		}
	case ToolsLockMissing, ToolsLockMismatch:
		if lock.URI != nil || lock.SHA256 != nil || len(lock.Tools) != 0 {
			return fmt.Errorf("doctor result: %s tools_lock has data", lock.State)
		}
	}
	return nil
}

func (readiness Readiness) validate() error {
	if !readiness.State.valid() {
		return fmt.Errorf("doctor result: readiness state %q is invalid", readiness.State)
	}
	if err := validateReasonCodes(readiness.ReasonCodes, 64, readiness.State == ReadinessUnverified); err != nil {
		return fmt.Errorf("doctor result: readiness reason_codes: %w", err)
	}
	if readiness.State == ReadinessReady {
		if readiness.ExitCode != 0 || len(readiness.ReasonCodes) != 0 {
			return fmt.Errorf("doctor result: ready state must have exit 0 and no reasons")
		}
		return nil
	}
	if readiness.ExitCode != 4 {
		return fmt.Errorf("doctor result: unverified state must have exit 4")
	}
	return nil
}

func (diagnostic Diagnostic) validate() error {
	if !validReasonCode(diagnostic.Code) || !diagnostic.Category.valid() || !redactedText(diagnostic.Message, 1024) || diagnostic.Message == "" {
		return fmt.Errorf("doctor result: diagnostic is invalid")
	}
	if !diagnostic.Redacted || diagnostic.CredentialBytesPersisted {
		return fmt.Errorf("doctor result: diagnostic %q is not redacted", diagnostic.Code)
	}
	if diagnostic.ArtifactURI != nil && !validURI(diagnostic.ArtifactURI) {
		return fmt.Errorf("doctor result: diagnostic %q artifact_uri is invalid", diagnostic.Code)
	}
	return nil
}

func validateProviderIDs(ids []string, required bool) error {
	if required && (len(ids) == 0 || len(ids) > 32) {
		return fmt.Errorf("has invalid length")
	}
	if !required && len(ids) > 32 {
		return fmt.Errorf("has invalid length")
	}
	seen := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		if !validProviderID(id) {
			return fmt.Errorf("contains invalid provider %q", id)
		}
		if _, duplicate := seen[id]; duplicate {
			return fmt.Errorf("contains duplicate provider %q", id)
		}
		seen[id] = struct{}{}
	}
	return nil
}

func validateReasonCodes(codes []string, maximum int, required bool) error {
	if len(codes) > maximum || required && len(codes) == 0 {
		return fmt.Errorf("has invalid length")
	}
	seen := make(map[string]struct{}, len(codes))
	for index, code := range codes {
		if !validReasonCode(code) {
			return fmt.Errorf("contains invalid reason %q", code)
		}
		if _, duplicate := seen[code]; duplicate {
			return fmt.Errorf("contains duplicate reason %q", code)
		}
		if index > 0 && codes[index-1] >= code {
			return fmt.Errorf("is not sorted")
		}
		seen[code] = struct{}{}
	}
	return nil
}

func validProviderID(value string) bool {
	if len(value) == 0 || len(value) > 64 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, character := range value[1:] {
		if !(character >= 'a' && character <= 'z') && !(character >= '0' && character <= '9') && character != '.' && character != '_' && character != '-' {
			return false
		}
	}
	return true
}

func validReasonCode(value string) bool {
	if len(value) == 0 || len(value) > 64 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, character := range value[1:] {
		if !(character >= 'a' && character <= 'z') && !(character >= '0' && character <= '9') && character != '_' {
			return false
		}
	}
	return true
}

func validText(value string, maximum int) bool {
	return len(value) <= maximum && !strings.ContainsAny(value, "\x00\r\n")
}

func validURI(value *string) bool {
	if value == nil || *value == "" || !redactedText(*value, 4096) {
		return false
	}
	raw := *value
	if strings.HasPrefix(raw, ".mulgae/") {
		return validLocalArtifactReference(raw)
	}
	parsed, err := url.Parse(raw)
	if err != nil ||
		parsed.Scheme != "https" ||
		parsed.Host == "" ||
		parsed.User != nil ||
		parsed.Opaque != "" ||
		parsed.RawQuery != "" ||
		parsed.Fragment != "" ||
		parsed.ForceQuery {
		return false
	}
	return validCanonicalURIPath(parsed.EscapedPath())
}

func validLocalArtifactReference(raw string) bool {
	if strings.ContainsAny(raw, "\\?#%") || path.Clean(raw) != raw {
		return false
	}
	components := strings.Split(raw, "/")
	if len(components) < 2 || components[0] != ".mulgae" {
		return false
	}
	for _, component := range components[1:] {
		if component == "" || component == "." || component == ".." || strings.EqualFold(component, ".gjc") {
			return false
		}
	}
	return true
}

func validCanonicalURIPath(raw string) bool {
	if raw == "" || !strings.HasPrefix(raw, "/") || strings.Contains(raw, "\\") {
		return false
	}
	decoded, err := url.PathUnescape(raw)
	if err != nil || strings.Contains(decoded, "%") || path.Clean(decoded) != decoded {
		return false
	}
	for _, component := range strings.Split(decoded, "/") {
		if component == "." || component == ".." || strings.EqualFold(component, ".gjc") {
			return false
		}
	}
	return true
}

func hiddenReference(value string) bool {
	return hiddenFilesystemPath(value)
}

func hiddenFilesystemPath(value string) bool {
	normalized := strings.ReplaceAll(strings.ToLower(value), "\\", "/")
	for _, component := range strings.Split(normalized, "/") {
		if component == ".gjc" {
			return true
		}
	}
	return false
}

func redactedText(value string, maximum int) bool {
	if !validText(value, maximum) {
		return false
	}
	lower := strings.ToLower(value)
	for _, marker := range []string{"api_key", "apikey", "authorization", "bearer ", "credential", "password", "secret=", "token="} {
		if strings.Contains(lower, marker) {
			return false
		}
	}
	return true
}

func validRawSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, character := range value {
		if !(character >= '0' && character <= '9') && !(character >= 'a' && character <= 'f') {
			return false
		}
	}
	return true
}

func validPrefixedSHA256(value *string) bool {
	return value != nil && strings.HasPrefix(*value, "sha256:") && validRawSHA256(strings.TrimPrefix(*value, "sha256:"))
}
func exactReasonCodes(codes []string, expected ...string) bool {
	if len(codes) != len(expected) {
		return false
	}
	for index, code := range expected {
		if codes[index] != code {
			return false
		}
	}
	return true
}

func validProviderUnverifiedReasonCodes(codes []string) bool {
	if len(codes) != 1 {
		return false
	}
	switch codes[0] {
	case "provider_evidence_unavailable",
		"provider_evidence_v1_not_authoritative",
		"provider_evidence_unsupported_schema",
		"provider_evidence_invalid",
		"provider_evidence_not_run":
		return true
	default:
		return false
	}
}

func validPlatformUnverifiedReasonCodes(codes []string) bool {
	if len(codes) != 1 {
		return false
	}
	switch codes[0] {
	case "host_platform_not_supported",
		"platform_evidence_unavailable",
		"platform_evidence_v1_not_authoritative",
		"platform_evidence_unsupported_schema",
		"platform_evidence_invalid",
		"platform_evidence_not_run":
		return true
	default:
		return false
	}
}

func validAuthorityMetadata(uri, sha256 *string) bool {
	return validURI(uri) && validPrefixedSHA256(sha256)
}

func validToolSet(tools []Tool) bool {
	if len(tools) != 2 {
		return false
	}
	seen := make(map[string]struct{}, len(tools))
	for _, tool := range tools {
		if !validToolIdentity(tool.Name, tool.ResolvedPath, tool.Version) || !validToolOutputDigest(tool.SHA256) {
			return false
		}
		if _, duplicate := seen[tool.Name]; duplicate {
			return false
		}
		seen[tool.Name] = struct{}{}
	}
	return validToolNameSet(seen)
}

func validToolObservationSet(tools []ToolObservation) bool {
	if len(tools) != 2 {
		return false
	}
	seen := make(map[string]struct{}, len(tools))
	for _, tool := range tools {
		if !validToolIdentity(tool.Name, tool.ResolvedPath, tool.Version) || !validToolDigest(tool.SHA256) {
			return false
		}
		if _, duplicate := seen[tool.Name]; duplicate {
			return false
		}
		seen[tool.Name] = struct{}{}
	}
	return validToolNameSet(seen)
}

func validToolIdentity(name, resolvedPath, version string) bool {
	return validToolName(name) &&
		validResolvedExecutablePath(resolvedPath) &&
		version != "" &&
		redactedText(version, 256)
}

func validToolName(name string) bool {
	return name == "git" || name == "python3"
}

func validToolNameSet(names map[string]struct{}) bool {
	_, hasGit := names["git"]
	_, hasPython3 := names["python3"]
	return hasGit && hasPython3
}

func validToolDigest(value string) bool {
	return validRawSHA256(value)
}

func validToolOutputDigest(value string) bool {
	return strings.HasPrefix(value, "sha256:") && validToolDigest(strings.TrimPrefix(value, "sha256:"))
}

func validResolvedExecutablePath(value string) bool {
	return value != "" &&
		filepath.IsAbs(value) &&
		filepath.Clean(value) == value &&
		redactedText(value, 4096) &&
		!hiddenFilesystemPath(value)
}

func containsAll(values []string, required ...string) bool {
	set := stringSet(values)
	for _, value := range required {
		if _, exists := set[value]; !exists {
			return false
		}
	}
	return true
}

func stringSet(values []string) map[string]struct{} {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		set[value] = struct{}{}
	}
	return set
}

func sortedUnique(values []string) []string {
	set := stringSet(values)
	result := make([]string, 0, len(set))
	for value := range set {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func (state EvidenceState) valid() bool {
	switch state {
	case EvidenceStatePass, EvidenceStateInconclusive, EvidenceStateFail, EvidenceStateUnverified:
		return true
	default:
		return false
	}
}

func (state AssignmentState) valid() bool {
	switch state {
	case AssignmentIntendedButUnverified, AssignmentEligible, AssignmentIneligible:
		return true
	default:
		return false
	}
}

func (cell PlatformCell) valid() bool {
	switch cell {
	case PlatformLinuxAMD64, PlatformLinuxARM64, PlatformDarwinAMD64, PlatformDarwinARM64:
		return true
	default:
		return false
	}
}

func (state ToolsLockState) valid() bool {
	switch state {
	case ToolsLockLocked, ToolsLockMissing, ToolsLockMismatch:
		return true
	default:
		return false
	}
}

func (state ReadinessState) valid() bool {
	return state == ReadinessReady || state == ReadinessUnverified
}

func (category DiagnosticCategory) valid() bool {
	switch category {
	case DiagnosticConfiguration, DiagnosticReadiness, DiagnosticArtifact, DiagnosticSecurity:
		return true
	default:
		return false
	}
}
