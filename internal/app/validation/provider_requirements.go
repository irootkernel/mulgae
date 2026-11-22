package validation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"unicode/utf8"

	"github.com/irootkernel/mulgae/internal/app/evidence"
	"github.com/irootkernel/mulgae/internal/artifactwire"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

const RequirementsProviderOutputVersion = "mulgae-provider-review-output.v3"

// SplitRequirementsResponse parses the whole document before separating sections.
// The findings projection alone enters the existing bounded envelope validator.
// It also reports whether the top-level "requirements" and "findings" keys were
// present in the decoded provider response.
func SplitRequirementsResponse(raw []byte) ([]byte, []byte, bool, bool, error) {
	object, err := decodeJSONObject(raw, "requirements response")
	if err != nil {
		return nil, nil, false, false, wrapRuntimeError(err, domain.DiagnosticCauseOutputDecodeFailed)
	}
	section, present := object["requirements"]
	delete(object, "requirements")
	_, findingsHasKey := object["findings"]
	if object["schema_version"] == RequirementsProviderOutputVersion {
		object["schema_version"] = "mulgae-provider-review-output.v1"
	} else if present {
		return nil, nil, true, findingsHasKey, wrapRuntimeError(fmt.Errorf("requirements response: wrong version"), domain.DiagnosticCauseCandidateValidationFailed)
	}
	findings, err := json.Marshal(object)
	if err != nil {
		return nil, nil, present, findingsHasKey, err
	}
	if !present {
		return findings, nil, false, findingsHasKey, nil
	}
	sectionRaw, err := json.Marshal(section)
	return findings, sectionRaw, true, findingsHasKey, err
}

var (
	requirementsSectionAllowedKeys = map[string]struct{}{
		"schema_version": {},
		"assessments":    {},
	}
	requirementsSectionProtectedKeys = map[string]struct{}{
		"owner":                   {},
		"owner_role":              {},
		"origin":                  {},
		"counts":                  {},
		"selected_count":          {},
		"evaluated_count":         {},
		"availability":            {},
		"input_path":              {},
		"input_sha256":            {},
		"input_digest":            {},
		"input_byte_length":       {},
		"verification":            {},
		"publication_status":      {},
		"review_id":               {},
		"run_id":                  {},
		"session_id":              {},
		"attempt_id":              {},
		"invocation_id":           {},
		"execution_invocation_id": {},
		"source_identity_sha256":  {},
		"target_sha256":           {},
	}
	requirementsAssessmentAllowedKeys = map[string]struct{}{
		"requirement_id": {},
		"verdict":        {},
		"rationale":      {},
		"evidence":       {},
		"examined_scope": {},
		"limitations":    {},
		"reason":         {},
	}
	requirementsAssessmentProtectedKeys = map[string]struct{}{
		"owner":                   {},
		"owner_role":              {},
		"origin":                  {},
		"counts":                  {},
		"input_digest":            {},
		"input_sha256":            {},
		"verification":            {},
		"publication_status":      {},
		"review_id":               {},
		"run_id":                  {},
		"session_id":              {},
		"attempt_id":              {},
		"invocation_id":           {},
		"execution_invocation_id": {},
		"source_identity_sha256":  {},
		"target_sha256":           {},
		"content_path":            {},
		"content_sha256":          {},
		"content_byte_length":     {},
	}
	requirementsEvidenceAllowedKeys = map[string]struct{}{
		"current": {},
		"visual":  {},
	}
	requirementsEvidenceProtectedKeys = map[string]struct{}{
		"verification":           {},
		"owner":                  {},
		"owner_role":             {},
		"origin":                 {},
		"source_identity_sha256": {},
		"target_sha256":          {},
		"current_excerpt_sha256": {},
		"excerpt_sha256":         {},
	}
	requirementsCurrentAllowedKeys = map[string]struct{}{
		"path":       {},
		"side":       {},
		"line_start": {},
		"line_end":   {},
		"quote":      {},
	}
	requirementsCurrentProtectedKeys = map[string]struct{}{
		"verification":           {},
		"source_identity_sha256": {},
		"target_sha256":          {},
		"current_excerpt_sha256": {},
		"excerpt_sha256":         {},
		"owner":                  {},
		"owner_role":             {},
		"origin":                 {},
		"review_id":              {},
		"run_id":                 {},
		"session_id":             {},
		"attempt_id":             {},
	}
	requirementsVisualAllowedKeys = map[string]struct{}{
		"path":   {},
		"sha256": {},
		"bbox":   {},
	}
	requirementsVisualProtectedKeys = map[string]struct{}{
		"verification":           {},
		"owner":                  {},
		"owner_role":             {},
		"origin":                 {},
		"source_identity_sha256": {},
		"target_sha256":          {},
	}
)

// findProtectedRequirementsKey scans every key in object and returns the
// lexicographically smallest unexpected Mulgae-owned key violation, if any.
func findProtectedRequirementsKey(object map[string]any, location string, allowed, protected map[string]struct{}) error {
	var protectedKey string
	hasProtected := false
	for key := range object {
		if _, ok := allowed[key]; ok {
			continue
		}
		if _, ok := protected[key]; ok {
			if !hasProtected || key < protectedKey {
				protectedKey = key
				hasProtected = true
			}
		}
	}
	if hasProtected {
		return &ownershipViolation{err: fmt.Errorf("review validation: provider supplied system-owned field %s.%s", location, protectedKey)}
	}
	return nil
}

// scanRequirementsOwnershipViolations performs a complete deterministic pre-pass
// over the decoded requirements JSON tree so an untrusted provider cannot mask a
// nested or later-row Mulgae-owned key behind an earlier ordinary unknown key or
// content validation failure.
func scanRequirementsOwnershipViolations(object map[string]any) error {
	if err := findProtectedRequirementsKey(object, "requirements", requirementsSectionAllowedKeys, requirementsSectionProtectedKeys); err != nil {
		return err
	}
	rows, ok := object["assessments"].([]any)
	if !ok {
		return nil
	}
	for _, value := range rows {
		row, ok := value.(map[string]any)
		if !ok {
			continue
		}
		if err := findProtectedRequirementsKey(row, "assessment", requirementsAssessmentAllowedKeys, requirementsAssessmentProtectedKeys); err != nil {
			return err
		}
		items, ok := row["evidence"].([]any)
		if !ok {
			continue
		}
		for _, v := range items {
			item, ok := v.(map[string]any)
			if !ok {
				continue
			}
			if err := findProtectedRequirementsKey(item, "evidence", requirementsEvidenceAllowedKeys, requirementsEvidenceProtectedKeys); err != nil {
				return err
			}
			if current, ok := item["current"].(map[string]any); ok {
				if err := findProtectedRequirementsKey(current, "current", requirementsCurrentAllowedKeys, requirementsCurrentProtectedKeys); err != nil {
					return err
				}
			}
			if visual, ok := item["visual"].(map[string]any); ok {
				if err := findProtectedRequirementsKey(visual, "visual", requirementsVisualAllowedKeys, requirementsVisualProtectedKeys); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// validateRequirementsObjectKeys scans every key in object before classifying
// so protected Mulgae-owned fields deterministically take precedence over
// ordinary unknown keys regardless of Go map iteration order.
func validateRequirementsObjectKeys(object map[string]any, location string, allowed, protected map[string]struct{}) error {
	if err := findProtectedRequirementsKey(object, location, allowed, protected); err != nil {
		return err
	}
	var unknownKey string
	hasUnknown := false
	for key := range object {
		if _, ok := allowed[key]; ok {
			continue
		}
		if !hasUnknown || key < unknownKey {
			unknownKey = key
			hasUnknown = true
		}
	}
	if hasUnknown {
		return fmt.Errorf("review validation: provider supplied unknown field %s.%s", location, unknownKey)
	}
	return nil
}

// ValidatedRequirementAnswer retains only content verified while the original
// source lease is open. Its zero value cannot be published as a provider row.
type ValidatedRequirementAnswer struct {
	requirement domain.Requirement
	assessment  domain.RequirementAssessment
	content     []byte
	source      string
}

func (answer ValidatedRequirementAnswer) Assessment() domain.RequirementAssessment {
	return answer.assessment
}
func (answer ValidatedRequirementAnswer) Content() []byte {
	return append([]byte(nil), answer.content...)
}

// ProviderRequirementsDecodeResult separates verified answers from per-item
// invalid requirement IDs when the outer requirements section is structurally
// valid and free of protected/source failures.
type ProviderRequirementsDecodeResult struct {
	Answers    []ValidatedRequirementAnswer
	InvalidIDs map[string]bool
	ItemErr    error
}

func isCitationLiveSourceError(source *ports.LiveSourceError) bool {
	return source != nil && (source.ProviderCitation() || source.Code() == ports.LiveSourceInvalid || source.Code() == ports.LiveSourceUnsupported)
}

func isForbiddenRequirementsSourceNode(node error) bool {
	if node == nil {
		return false
	}
	if node == context.Canceled || node == context.DeadlineExceeded {
		return true
	}
	switch typed := node.(type) {
	case *ports.LiveSourceError:
		return !isCitationLiveSourceError(typed)
	case *domain.Failure:
		return typed != nil && typed.Class() != domain.FailureInvalidOutput
	case *RuntimeError:
		return typed != nil && (typed.Cause() == domain.DiagnosticCauseProviderOwnershipViolation || typed.Cause() == domain.DiagnosticCauseObservationMismatch)
	case *ownershipViolation:
		return true
	}
	if diagnostic, ok := node.(interface{ DocumentViolation() bool }); ok && !diagnostic.DocumentViolation() {
		return true
	}
	return false
}

func containsForbiddenRequirementsSourceNode(err error) bool {
	if err == nil {
		return false
	}
	if isForbiddenRequirementsSourceNode(err) {
		return true
	}
	switch nested := err.(type) {
	case interface{ Unwrap() []error }:
		for _, child := range nested.Unwrap() {
			if containsForbiddenRequirementsSourceNode(child) {
				return true
			}
		}
	case interface{ Unwrap() error }:
		return containsForbiddenRequirementsSourceNode(nested.Unwrap())
	}
	return false
}

func isPureRequirementsCitationErrorNode(err error) bool {
	if err == nil || isForbiddenRequirementsSourceNode(err) {
		return false
	}
	if source, ok := err.(*ports.LiveSourceError); ok {
		return isCitationLiveSourceError(source) && !containsForbiddenRequirementsSourceNode(source.Unwrap())
	}
	switch nested := err.(type) {
	case interface{ Unwrap() []error }:
		seen := false
		for _, child := range nested.Unwrap() {
			if child == nil {
				continue
			}
			seen = true
			if !isPureRequirementsCitationErrorNode(child) {
				return false
			}
		}
		return seen
	case interface{ Unwrap() error }:
		return isPureRequirementsCitationErrorNode(nested.Unwrap())
	default:
		return false
	}
}

// IsPureRequirementsCitationError reports whether err is composed solely of
// bounded provider citation LiveSourceError leaves with no forbidden context,
// ownership, real source drift, or infrastructure nodes anywhere in its tree,
// while ctx remains active.
func IsPureRequirementsCitationError(ctx context.Context, err error) bool {
	if ctx == nil || ctx.Err() != nil || err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	return isPureRequirementsCitationErrorNode(err)
}

// DecodeProviderRequirements is the unbounded provider-content boundary. It
// validates ownership and section structure fail-closed, isolates ordinary
// per-item content/evidence/citation failures to the offending requirement_id,
// and aborts fail-closed on any protected or real live-source failure.
func DecodeProviderRequirements(ctx context.Context, raw []byte, selected []domain.Requirement, role domain.Role, identity evidence.LiveSourceIdentity, verifier *evidence.Verifier, visuals map[string]string, inputPath, inputSHA256 string) (ProviderRequirementsDecodeResult, error) {
	if ctx == nil || !role.Valid() || !identity.Valid() || verifier == nil {
		return ProviderRequirementsDecodeResult{}, wrapValidatorInvariant(fmt.Errorf("requirements: invalid verification authority"))
	}
	if err := ctx.Err(); err != nil {
		return ProviderRequirementsDecodeResult{}, requirementsSourceFailure(err)
	}
	object, err := decodeJSONObject(raw, "provider requirements")
	if err != nil {
		return ProviderRequirementsDecodeResult{}, err
	}
	if err := scanRequirementsOwnershipViolations(object); err != nil {
		return ProviderRequirementsDecodeResult{}, wrapRuntimeError(err, domain.DiagnosticCauseCandidateValidationFailed)
	}
	if err := validateRequirementsObjectKeys(object, "requirements", requirementsSectionAllowedKeys, requirementsSectionProtectedKeys); err != nil {
		return ProviderRequirementsDecodeResult{}, wrapRuntimeError(err, domain.DiagnosticCauseCandidateValidationFailed)
	}
	if !requirementObjectFields(object, "schema_version", "assessments") || object["schema_version"] != "mulgae-provider-requirements.v1" {
		return ProviderRequirementsDecodeResult{}, fmt.Errorf("requirements: invalid section")
	}
	rows, ok := object["assessments"].([]any)
	if !ok || len(rows) > domain.MaxRequirements {
		return ProviderRequirementsDecodeResult{}, fmt.Errorf("requirements: invalid answer count")
	}
	assigned := make(map[string]domain.Requirement)
	for _, r := range selected {
		if r.OwnerRole() == role {
			assigned[r.ID()] = r
		}
	}
	// Section-wide structural and ID pre-pass across all rows before any
	// per-item verification: reject the whole section on non-object rows or
	// missing, unknown, foreign, wrong-owner, or duplicate requirement IDs.
	type indexedRequirementRow struct {
		id  string
		req domain.Requirement
		row map[string]any
	}
	parsedRows := make([]indexedRequirementRow, 0, len(rows))
	seen := make(map[string]bool, len(rows))
	for _, value := range rows {
		row, ok := value.(map[string]any)
		if !ok {
			return ProviderRequirementsDecodeResult{}, fmt.Errorf("requirements: invalid answer")
		}
		id, ok := row["requirement_id"].(string)
		if !ok {
			return ProviderRequirementsDecodeResult{}, fmt.Errorf("requirements: missing answer requirement_id")
		}
		r, ok := assigned[id]
		if !ok || seen[id] {
			return ProviderRequirementsDecodeResult{}, fmt.Errorf("requirements: duplicate, foreign or wrong-owner ID")
		}
		seen[id] = true
		parsedRows = append(parsedRows, indexedRequirementRow{id: id, req: r, row: row})
	}

	answers := make([]ValidatedRequirementAnswer, 0, len(parsedRows))
	invalidIDs := make(map[string]bool)
	var firstItemErr error
	for _, entry := range parsedRows {
		if err := ctx.Err(); err != nil {
			return ProviderRequirementsDecodeResult{}, requirementsSourceFailure(err)
		}
		answer, rowErr, abort := decodeProviderRequirementRow(ctx, entry.req, entry.row, role, identity, verifier, visuals, inputPath, inputSHA256)
		if abort {
			return ProviderRequirementsDecodeResult{}, rowErr
		}
		if rowErr != nil {
			invalidIDs[entry.id] = true
			if firstItemErr == nil {
				firstItemErr = rowErr
			}
			continue
		}
		answers = append(answers, answer)
	}
	return ProviderRequirementsDecodeResult{
		Answers:    answers,
		InvalidIDs: invalidIDs,
		ItemErr:    firstItemErr,
	}, nil
}

func decodeProviderRequirementRow(
	ctx context.Context,
	r domain.Requirement,
	row map[string]any,
	role domain.Role,
	identity evidence.LiveSourceIdentity,
	verifier *evidence.Verifier,
	visuals map[string]string,
	inputPath, inputSHA256 string,
) (ValidatedRequirementAnswer, error, bool) {
	if err := validateRequirementsObjectKeys(row, "assessment", requirementsAssessmentAllowedKeys, requirementsAssessmentProtectedKeys); err != nil {
		wrapped := wrapRuntimeError(err, domain.DiagnosticCauseCandidateValidationFailed)
		if cause, ok := RuntimeCause(wrapped); ok && cause == domain.DiagnosticCauseProviderOwnershipViolation {
			return ValidatedRequirementAnswer{}, wrapped, true
		}
		return ValidatedRequirementAnswer{}, wrapped, false
	}
	if !requirementObjectFields(row, "requirement_id", "verdict", "rationale", "evidence", "examined_scope", "limitations", "reason") {
		return ValidatedRequirementAnswer{}, wrapRuntimeError(fmt.Errorf("requirements: missing answer field"), domain.DiagnosticCauseCandidateValidationFailed), false
	}
	id := r.ID()
	verdict, _ := row["verdict"].(string)
	reason, reasonOK := row["reason"].(string)
	if !reasonOK {
		return ValidatedRequirementAnswer{}, wrapRuntimeError(fmt.Errorf("requirements: invalid reason"), domain.DiagnosticCauseCandidateValidationFailed), false
	}
	assessment, err := domain.NewRequirementAssessment(r, domain.RequirementVerdict(verdict), domain.AssessmentProvider, domain.AssessmentReason(reason))
	if err != nil {
		return ValidatedRequirementAnswer{}, wrapRuntimeError(err, domain.DiagnosticCauseCandidateValidationFailed), false
	}
	content := RequirementContent{SchemaVersion: RequirementContentVersion, RequirementID: id, Evidence: make([]RequirementContentEvidence, 0)}
	var ok bool
	content.Rationale, ok = row["rationale"].(string)
	if !ok {
		return ValidatedRequirementAnswer{}, wrapRuntimeError(fmt.Errorf("requirements: invalid rationale"), domain.DiagnosticCauseCandidateValidationFailed), false
	}
	content.ExaminedScope, ok = row["examined_scope"].(string)
	if !ok {
		return ValidatedRequirementAnswer{}, wrapRuntimeError(fmt.Errorf("requirements: invalid examined scope"), domain.DiagnosticCauseCandidateValidationFailed), false
	}
	limitations, ok := row["limitations"].([]any)
	if !ok || len(limitations) > 20 {
		return ValidatedRequirementAnswer{}, wrapRuntimeError(fmt.Errorf("requirements: invalid limitations"), domain.DiagnosticCauseCandidateValidationFailed), false
	}
	content.Limitations = make([]string, len(limitations))
	for i, v := range limitations {
		content.Limitations[i], ok = v.(string)
		if !ok {
			return ValidatedRequirementAnswer{}, wrapRuntimeError(fmt.Errorf("requirements: invalid limitation"), domain.DiagnosticCauseCandidateValidationFailed), false
		}
	}
	items, ok := row["evidence"].([]any)
	if !ok || len(items) > 32 {
		return ValidatedRequirementAnswer{}, wrapRuntimeError(fmt.Errorf("requirements: invalid evidence"), domain.DiagnosticCauseCandidateValidationFailed), false
	}
	for _, v := range items {
		item, ok := v.(map[string]any)
		if !ok {
			return ValidatedRequirementAnswer{}, wrapRuntimeError(fmt.Errorf("requirements: invalid evidence item"), domain.DiagnosticCauseCandidateValidationFailed), false
		}
		if err := validateRequirementsObjectKeys(item, "evidence", requirementsEvidenceAllowedKeys, requirementsEvidenceProtectedKeys); err != nil {
			wrapped := wrapRuntimeError(err, domain.DiagnosticCauseCandidateValidationFailed)
			if cause, ok := RuntimeCause(wrapped); ok && cause == domain.DiagnosticCauseProviderOwnershipViolation {
				return ValidatedRequirementAnswer{}, wrapped, true
			}
			return ValidatedRequirementAnswer{}, wrapped, false
		}
		current, ok := item["current"].(map[string]any)
		if !ok {
			return ValidatedRequirementAnswer{}, wrapRuntimeError(fmt.Errorf("requirements: missing current evidence"), domain.DiagnosticCauseCandidateValidationFailed), false
		}
		if err := validateRequirementsObjectKeys(current, "current", requirementsCurrentAllowedKeys, requirementsCurrentProtectedKeys); err != nil {
			wrapped := wrapRuntimeError(err, domain.DiagnosticCauseCandidateValidationFailed)
			if cause, ok := RuntimeCause(wrapped); ok && cause == domain.DiagnosticCauseProviderOwnershipViolation {
				return ValidatedRequirementAnswer{}, wrapped, true
			}
			return ValidatedRequirementAnswer{}, wrapped, false
		}
		if !requirementObjectFields(current, "path", "side", "line_start", "line_end", "quote") {
			return ValidatedRequirementAnswer{}, wrapRuntimeError(fmt.Errorf("requirements: invalid current fields"), domain.DiagnosticCauseCandidateValidationFailed), false
		}
		encoded, _ := json.Marshal(current)
		var wire struct {
			Path  string `json:"path"`
			Side  string `json:"side"`
			Start int    `json:"line_start"`
			End   int    `json:"line_end"`
			Quote string `json:"quote"`
		}
		if json.Unmarshal(encoded, &wire) != nil || utf8.RuneCountInString(wire.Path) > 4096 || utf8.RuneCountInString(wire.Quote) > 8000 {
			return ValidatedRequirementAnswer{}, wrapRuntimeError(fmt.Errorf("requirements: invalid evidence bounds"), domain.DiagnosticCauseCandidateValidationFailed), false
		}
		if !identity.SupportsSide(evidence.Side(wire.Side)) {
			return ValidatedRequirementAnswer{}, wrapRuntimeError(fmt.Errorf("requirements: input prose or unselected source side is not evidence"), domain.DiagnosticCauseCandidateValidationFailed), false
		}
		claim, err := evidence.NewLiveClaim(identity, evidence.Side(wire.Side), wire.Path, wire.Start, wire.End, wire.Quote)
		if err != nil {
			return ValidatedRequirementAnswer{}, wrapRuntimeError(err, domain.DiagnosticCauseCandidateValidationFailed), false
		}
		receipt, err := verifier.VerifyCurrent(ctx, claim)
		if err != nil {
			if IsPureRequirementsCitationError(ctx, err) {
				return ValidatedRequirementAnswer{}, wrapRuntimeError(err, domain.DiagnosticCauseCandidateValidationFailed), false
			}
			if ctxErr := ctx.Err(); ctxErr != nil && !errors.Is(err, ctxErr) {
				err = errors.Join(err, ctxErr)
			}
			return ValidatedRequirementAnswer{}, requirementsSourceFailure(err), true
		}
		if wire.Path == inputPath && receipt.SourceFileSHA256() == inputSHA256 {
			return ValidatedRequirementAnswer{}, wrapRuntimeError(fmt.Errorf("requirements: invocation prose is not implementation evidence"), domain.DiagnosticCauseCandidateValidationFailed), false
		}
		if receipt.Status() != evidence.ReceiptVerified {
			return ValidatedRequirementAnswer{}, wrapRuntimeError(fmt.Errorf("requirements: unsupported evidence"), domain.DiagnosticCauseCandidateValidationFailed), false
		}
		normalized := RequirementContentEvidence{Current: RequirementCurrentEvidence{SourceIdentitySHA256: identity.SHA256(), CurrentExcerptSHA256: receipt.ExcerptSHA256(), Side: CurrentEvidenceSide(wire.Side), Path: wire.Path, LineStart: wire.Start, LineEnd: wire.End, Quote: string(receipt.Excerpt()), Verification: "verified"}}
		if visual, present := item["visual"]; present {
			object, ok := visual.(map[string]any)
			if !ok {
				return ValidatedRequirementAnswer{}, wrapRuntimeError(fmt.Errorf("requirements: invalid visual"), domain.DiagnosticCauseCandidateValidationFailed), false
			}
			if err := validateRequirementsObjectKeys(object, "visual", requirementsVisualAllowedKeys, requirementsVisualProtectedKeys); err != nil {
				wrapped := wrapRuntimeError(err, domain.DiagnosticCauseCandidateValidationFailed)
				if cause, ok := RuntimeCause(wrapped); ok && cause == domain.DiagnosticCauseProviderOwnershipViolation {
					return ValidatedRequirementAnswer{}, wrapped, true
				}
				return ValidatedRequirementAnswer{}, wrapped, false
			}
			bbox, ok := object["bbox"].(map[string]any)
			if !ok || !requirementObjectFields(bbox, "x", "y", "width", "height") {
				return ValidatedRequirementAnswer{}, wrapRuntimeError(fmt.Errorf("requirements: invalid visual bounds"), domain.DiagnosticCauseCandidateValidationFailed), false
			}
			encoded, _ := json.Marshal(object)
			var image artifactwire.VisualEvidence
			if json.Unmarshal(encoded, &image) != nil || role != domain.RoleArtist || visuals[wire.Side+"\x00"+image.Path] != image.SHA256 {
				return ValidatedRequirementAnswer{}, wrapRuntimeError(fmt.Errorf("requirements: unverified visual"), domain.DiagnosticCauseCandidateValidationFailed), false
			}
			image.Verification = "verified"
			normalized.Visual = &image
		}
		content.Evidence = append(content.Evidence, normalized)
	}
	encoded, err := json.Marshal(content)
	if err != nil {
		return ValidatedRequirementAnswer{}, wrapRuntimeError(err, domain.DiagnosticCauseCandidateValidationFailed), false
	}
	if _, err = DecodeRequirementContent(encoded, assessment, identity.SHA256()); err != nil {
		return ValidatedRequirementAnswer{}, wrapRuntimeError(err, domain.DiagnosticCauseCandidateValidationFailed), false
	}
	return ValidatedRequirementAnswer{requirement: r, assessment: assessment, content: encoded, source: identity.SHA256()}, nil, false
}

type requirementsEvidenceFailure struct{ err error }

func (failure *requirementsEvidenceFailure) Error() string {
	return "requirements source evidence verification failed"
}
func (failure *requirementsEvidenceFailure) Unwrap() error { return failure.err }
func requirementsSourceFailure(err error) error            { return &requirementsEvidenceFailure{err: err} }

// RequirementsSourceFailure preserves the typed source cause for the existing
// runtime failure reducer. Provider-document errors do not carry this marker.
func RequirementsSourceFailure(err error) (error, bool) {
	var failure *requirementsEvidenceFailure
	if errors.As(err, &failure) {
		return failure.err, true
	}
	return nil, false
}

// RequirementResults is the complete immutable selected set. Publication reuses
// its exact input/content without consulting current source after lease closure.
type RequirementResults struct {
	input      RequirementsInput
	evaluation domain.RequirementEvaluation
	content    [][]byte
	source     string
}

func (result RequirementResults) Input() RequirementsInput                 { return result.input }
func (result RequirementResults) Evaluation() domain.RequirementEvaluation { return result.evaluation }
func (result RequirementResults) SourceIdentitySHA256() string             { return result.source }
func (result RequirementResults) Contents() [][]byte {
	out := make([][]byte, len(result.content))
	for i, b := range result.content {
		out[i] = append([]byte(nil), b...)
	}
	return out
}
func (result RequirementResults) Valid() bool {
	selected, _, known := result.evaluation.Counts()
	return known && selected > 0 && selected == len(result.input.Requirements()) && selected == len(result.content) && result.source != ""
}

func NormalizeRequirements(input RequirementsInput, answers []ValidatedRequirementAnswer, reasons map[string]domain.AssessmentReason, identity string, noChange bool) (RequirementResults, error) {
	selected := input.Requirements()
	if len(selected) == 0 {
		return RequirementResults{}, fmt.Errorf("requirements: no admitted input")
	}
	accepted := make(map[string]ValidatedRequirementAnswer)
	for _, answer := range answers {
		id := answer.assessment.RequirementID()
		if answer.source != identity || len(answer.content) == 0 || accepted[id].source != "" {
			return RequirementResults{}, fmt.Errorf("requirements: invalid verified answer binding")
		}
		accepted[id] = answer
	}
	rows := make([]domain.RequirementAssessment, len(selected))
	content := make([][]byte, len(selected))
	for i, r := range selected {
		answer, ok := accepted[r.ID()]
		if ok && !noChange {
			if answer.assessment.OwnerRole() != r.OwnerRole() || !reflect.DeepEqual(answer.requirement, r) {
				return RequirementResults{}, fmt.Errorf("requirements: wrong answer owner")
			}
			rows[i] = answer.assessment
			content[i] = answer.Content()
			delete(accepted, r.ID())
			continue
		}
		reason := reasons[r.ID()]
		if noChange {
			reason = domain.AssessmentNoChangeTarget
		}
		if reason == "" {
			reason = domain.AssessmentAnswerOmitted
		}
		var err error
		rows[i], err = domain.NewRequirementAssessment(r, domain.RequirementUnverified, domain.AssessmentDerived, reason)
		if err != nil {
			return RequirementResults{}, err
		}
		content[i], err = json.Marshal(RequirementContent{SchemaVersion: RequirementContentVersion, RequirementID: r.ID(), Rationale: "No admissible provider assessment: " + string(reason) + ".", Evidence: []RequirementContentEvidence{}, Limitations: []string{}})
		if err != nil {
			return RequirementResults{}, err
		}
	}
	if len(accepted) != 0 {
		return RequirementResults{}, fmt.Errorf("requirements: foreign normalized answer")
	}
	availability := domain.AssessmentEvaluated
	if noChange {
		availability = domain.AssessmentNotRun
	}
	evaluation, err := domain.NewRequirementEvaluation(availability, selected, rows)
	if err != nil {
		return RequirementResults{}, err
	}
	return RequirementResults{input: input, evaluation: evaluation, content: content, source: identity}, nil
}

// RequirementsReformatPlan reuses the existing malformed-document repair form;
// it does not validate a prose-bearing body through the bounded schema adapter.
func RequirementsReformatPlan(raw []byte) *RepairPlan {
	if len(raw) == 0 {
		return nil
	}
	if _, err := decodeJSONObject(raw, "requirements response"); err != nil {
		return newRepairPlan(RepairModeReformatOnly, raw, nil)
	}
	return nil
}

// NormalizedRequirementsOutput is the trusted in-memory provider-output.v3
// composition. Partial section failures stay separate and never manufacture a
// complete finding envelope. Serialization is optional and remains unbounded.
type NormalizedRequirementsOutput struct {
	findings ValidatedReview
	answers  []ValidatedRequirementAnswer
	scope    ReviewValidationScope
}

func (output NormalizedRequirementsOutput) SchemaVersion() string {
	if output.findings.Summary() == "" {
		return ""
	}
	return RequirementsProviderOutputVersion
}
func ComposeRequirementsOutput(findings ValidatedReview, answers []ValidatedRequirementAnswer, scope ReviewValidationScope) (NormalizedRequirementsOutput, error) {
	if _, err := validateScope(scope); err != nil || !scope.LiveSource.Valid() || findings.Summary() == "" {
		return NormalizedRequirementsOutput{}, fmt.Errorf("requirements output: invalid trusted composition")
	}
	for _, answer := range answers {
		if answer.source != scope.LiveSource.SHA256() || answer.assessment.OwnerRole() != scope.Role || len(answer.content) == 0 {
			return NormalizedRequirementsOutput{}, fmt.Errorf("requirements output: wrong source or owner")
		}
	}
	return NormalizedRequirementsOutput{findings: findings, answers: append([]ValidatedRequirementAnswer(nil), answers...), scope: scope}, nil
}
func (output NormalizedRequirementsOutput) Bytes() ([]byte, error) {
	if output.SchemaVersion() == "" {
		return nil, fmt.Errorf("requirements output: absent composition")
	}
	object, err := decodeJSONObject(output.findings.OriginalRaw(), "validated findings projection")
	if err != nil {
		return nil, err
	}
	object, _ = projectProviderReview(object)
	target, err := validateScope(output.scope)
	if err != nil {
		return nil, err
	}
	object, err = injectTrustedCurrentIdentity(object, target, true)
	if err != nil {
		return nil, err
	}
	object["schema_version"] = RequirementsProviderOutputVersion
	rows := make([]map[string]any, 0, len(output.answers))
	for _, answer := range output.answers {
		var row map[string]any
		if err := json.Unmarshal(answer.content, &row); err != nil {
			return nil, err
		}
		delete(row, "schema_version")
		row["verdict"] = answer.assessment.Verdict()
		row["reason"] = answer.assessment.Reason()
		rows = append(rows, row)
	}
	object["requirements"] = map[string]any{"schema_version": "mulgae-provider-requirements.v1", "assessments": rows}
	return json.Marshal(object)
}
