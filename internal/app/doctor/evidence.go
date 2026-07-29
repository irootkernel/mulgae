package doctor

import "context"

const (
	providerEvidenceV2SchemaID = "https://mulgae.local/schemas/mulgae-provider-contract-evidence.v2.schema.json"
	platformEvidenceV2SchemaID = "https://mulgae.local/schemas/mulgae-platform-contract-evidence.v2.schema.json"
)

var (
	intendedProviderIDs = []string{"kimi", "zcode", "agy"}
	platformCells       = []PlatformCell{PlatformLinuxAMD64, PlatformLinuxARM64, PlatformDarwinAMD64, PlatformDarwinARM64}
	providerProbeIDs    = []string{
		"PV-VERSION",
		"PV-NONINTERACTIVE",
		"PV-PROMPT-TRANSPORT",
		"PV-JSON-ONLY",
		"PV-STDOUT-STDERR",
		"PV-CANCELLATION",
		"PV-OUTPUT-CAP",
		"PV-AUTH-CACHE-CONCURRENCY",
		"PV-EXIT-CLASSIFICATION",
		"PV-CWD-ISOLATION",
		"PV-ROLE-FIT-logic",
		"PV-ROLE-FIT-security",
		"PV-ROLE-FIT-maintainability",
		"PV-ROLE-FIT-product",
		"PV-ROLE-FIT-documentation",
		"PV-ROLE-FIT-testing",
	}
	platformProbeIDs = []string{
		"PL-IDENTITY-NATIVE",
		"PL-LOCAL-FS",
		"PL-SAME-DEVICE",
		"PL-PROCESS-GROUP",
		"PL-LOCK-STALE",
		"PL-PERMISSION",
		"PL-SYMLINK",
		"PL-RENAME",
		"PL-FILE-FSYNC",
		"PL-DIR-FSYNC",
		"PL-RECOVERY",
	}
)

// EvidenceReader is the consumer-owned boundary for recorded authority
// evidence. It only returns observations; doctor never executes probes,
// substitutes executables, or reads a hidden evidence/session directory.
type EvidenceReader interface {
	ProviderEvidence(context.Context, string) (ProviderV2Evidence, error)
	PlatformEvidence(context.Context, PlatformCell) (PlatformV2Evidence, error)
	ToolsLock(context.Context) (ToolsLockObservation, error)
}

// EvidenceStatus is the status of one recorded authority predicate.
type EvidenceStatus string

const (
	EvidenceStatusPass         EvidenceStatus = "PASS"
	EvidenceStatusFail         EvidenceStatus = "FAIL"
	EvidenceStatusInconclusive EvidenceStatus = "INCONCLUSIVE"
	EvidenceStatusNotRun       EvidenceStatus = "NOT_RUN"
)

// ProbeObservation is the compact, redaction-safe projection of one required
// predicate. Its ID must be one of the fixed IDs for the evidence document.
type ProbeObservation struct {
	ID     string
	Status EvidenceStatus
}

// ProviderV2Evidence is a provider-contract-evidence.v2 observation. SHA256
// is the unprefixed document digest used by v2; doctor emits sha256:<digest>.
type ProviderV2Evidence struct {
	SchemaID                string
	ProviderID              string
	URI                     string
	SHA256                  string
	Probes                  []ProbeObservation
	SecureWriterIndexStatus EvidenceStatus
	AssignmentStatus        EvidenceStatus
}

// PlatformV2Evidence is one darwin-arm64 row observed from a
// platform-contract-evidence.v2 record. Future inventory cells are never read
// because they cannot become current support evidence.
type PlatformV2Evidence struct {
	SchemaID string
	Cell     PlatformCell
	URI      string
	SHA256   string
	Native   bool
	Probes   []ProbeObservation
}

// ToolsLockObservation is the compact observation of the checked tools lock.
// SHA256 is the unprefixed observed document digest.
type ToolsLockObservation struct {
	State  ToolsLockState
	URI    string
	SHA256 string
	Tools  []ToolObservation
}

// ToolObservation records one locked executable without exposing PATH or an
// environment snapshot.
type ToolObservation struct {
	Name         string
	ResolvedPath string
	Version      string
	SHA256       string
}

func (status EvidenceStatus) valid() bool {
	switch status {
	case EvidenceStatusPass, EvidenceStatusFail, EvidenceStatusInconclusive, EvidenceStatusNotRun:
		return true
	default:
		return false
	}
}
