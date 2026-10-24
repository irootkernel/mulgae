package artifactwire

import (
	"fmt"
	"strings"
)

// Path spelling is lexical only. Callers validate identities, choose kinds and
// construct safe paths; no helper cleans or validates its arguments.
const (
	ManifestPath           = "manifest.json"
	JournalPath            = "publication/journal.json"
	StatusPath             = "status.json"
	SupportIndexPath       = "support/index.json"
	ValidatedCandidatePath = "validation/final-candidate.json"
	RecoveryManifestPath   = "recovery/manifest.json"
	CompositeSupportPath   = "support/composite.json"
)

func RunPath(session, run, relative string) string { return session + "/" + run + "/" + relative }
func FinalName(review string) string               { return "review_" + review + ".json" }
func FinalPath(session, run, review string) string { return RunPath(session, run, FinalName(review)) }
func StagedFinalPath(session, run, review string) string {
	return RunPath(session, run, "publication/staged/"+FinalName(review)+".tmp")
}
func LineageEdgePath(review string) string { return "store/lineage-edges/e_" + review + ".json" }
func EpochPath(epoch uint64) string        { return fmt.Sprintf("store/epochs/epoch_%020d.json", epoch) }
func PreparedCompositePath(session, run, name string) string {
	return RunPath(session, run, "publication/staged/"+name+".json.tmp")
}
func CorruptionDiagnosticPath(session, run string, epoch uint64) string {
	return RunPath(session, run, fmt.Sprintf("recovery/diagnostics/publication-corrupt_%d.json", epoch))
}
func PromptBase(sequence uint64, purpose string) string {
	return fmt.Sprintf("%03d-%s", sequence, purpose)
}
func PromptPath(attempt string, sequence uint64, purpose, suffix string) string {
	return "prompts/" + attempt + "/" + PromptBase(sequence, purpose) + suffix
}
func AttemptPath(attempt, member string) string { return "attempts/" + attempt + "/" + member }
func CandidateName(kind string, ordinal int) string {
	return fmt.Sprintf("candidate.%s.%03d.json", kind, ordinal)
}
func InvocationPath(sequence uint64, purpose, stream string) string {
	return "invocations/" + PromptBase(sequence, purpose) + "/" + stream + ".raw"
}
func EvidenceExcerptName(finding string, position int) string {
	return fmt.Sprintf("%s_%d.md", finding, position)
}
func FindingName(finding string) string { return finding + ".json" }
func RoleReportPath(role string) string { return "role-reports/" + role + ".md" }
func RecoveryBlobPath(digest string) string {
	return "recovery/blobs/sha256-" + strings.TrimPrefix(digest, "sha256:")
}
func CapturedBlobPath(digest string) string {
	return "blobs/sha256-" + strings.TrimPrefix(digest, "sha256:")
}
func CompositeSourcePrefix(role string) string   { return "support/sources/" + role + "/target/" }
func CompositeFindingPath(finding string) string { return "support/findings/" + FindingName(finding) }

func CanonicalExcerptName(name string) bool {
	if strings.Contains(name, "/") || !strings.HasPrefix(name, "F") {
		return false
	}
	stem := strings.TrimPrefix(name, "F")
	if strings.HasSuffix(stem, ".json") {
		return DecimalDigits(strings.TrimSuffix(stem, ".json"), 1)
	}
	finding, position, ok := strings.Cut(stem, "_")
	return ok && strings.HasSuffix(position, ".md") &&
		DecimalDigits(finding, 1) &&
		DecimalDigits(strings.TrimSuffix(position, ".md"), 1)
}

func CanonicalInvocationDirectory(value string) bool {
	sequence, purpose, ok := strings.Cut(value, "-")
	return ok && DecimalIdentifier(sequence, 3) &&
		(purpose == "initial" || purpose == "retry" || purpose == "repair" || purpose == "extract")
}

func DecimalIdentifier(value string, minimumWidth int) bool {
	if len(value) < minimumWidth || value == "" {
		return false
	}
	nonZero := false
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
		nonZero = nonZero || character != '0'
	}
	return nonZero && (value[0] != '0' || len(value) == minimumWidth)
}

func DecimalDigits(value string, minimumWidth int) bool {
	if len(value) < minimumWidth {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}
