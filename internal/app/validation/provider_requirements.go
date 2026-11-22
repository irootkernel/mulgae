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
)

const RequirementsProviderOutputVersion = "mulgae-provider-review-output.v3"

// SplitRequirementsResponse parses the whole document before separating sections.
// The findings projection alone enters the existing bounded envelope validator.
func SplitRequirementsResponse(raw []byte) ([]byte, []byte, bool, error) {
	object, err := decodeJSONObject(raw, "requirements response")
	if err != nil {
		return nil, nil, false, wrapRuntimeError(err, domain.DiagnosticCauseOutputDecodeFailed)
	}
	section, present := object["requirements"]
	delete(object, "requirements")
	if object["schema_version"] == RequirementsProviderOutputVersion {
		object["schema_version"] = "mulgae-provider-review-output.v1"
	} else if present {
		return nil, nil, true, wrapRuntimeError(fmt.Errorf("requirements response: wrong version"), domain.DiagnosticCauseCandidateValidationFailed)
	}
	findings, err := json.Marshal(object)
	if err != nil {
		return nil, nil, present, err
	}
	if !present {
		return findings, nil, false, nil
	}
	sectionRaw, err := json.Marshal(section)
	return findings, sectionRaw, true, err
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

// DecodeProviderRequirements is the unbounded provider-content boundary. It
// validates ownership and verifies every source claim, without a schema adapter
// over the complete prose-bearing section.
func DecodeProviderRequirements(ctx context.Context, raw []byte, selected []domain.Requirement, role domain.Role, identity evidence.LiveSourceIdentity, verifier *evidence.Verifier, visuals map[string]string, inputPath, inputSHA256 string) ([]ValidatedRequirementAnswer, error) {
	if ctx == nil || !role.Valid() || !identity.Valid() || verifier == nil {
		return nil, fmt.Errorf("requirements: invalid verification authority")
	}
	object, err := decodeJSONObject(raw, "provider requirements")
	if err != nil {
		return nil, err
	}
	if err := scanRequirementsOwnershipViolations(object); err != nil {
		return nil, wrapRuntimeError(err, domain.DiagnosticCauseCandidateValidationFailed)
	}
	if err := validateRequirementsObjectKeys(object, "requirements", requirementsSectionAllowedKeys, requirementsSectionProtectedKeys); err != nil {
		return nil, wrapRuntimeError(err, domain.DiagnosticCauseCandidateValidationFailed)
	}
	if !requirementObjectFields(object, "schema_version", "assessments") || object["schema_version"] != "mulgae-provider-requirements.v1" {
		return nil, fmt.Errorf("requirements: invalid section")
	}
	rows, ok := object["assessments"].([]any)
	if !ok || len(rows) > domain.MaxRequirements {
		return nil, fmt.Errorf("requirements: invalid answer count")
	}
	assigned := make(map[string]domain.Requirement)
	for _, r := range selected {
		if r.OwnerRole() == role {
			assigned[r.ID()] = r
		}
	}
	seen := make(map[string]bool)
	answers := make([]ValidatedRequirementAnswer, 0, len(rows))
	for _, value := range rows {
		row, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("requirements: invalid answer")
		}
		if err := validateRequirementsObjectKeys(row, "assessment", requirementsAssessmentAllowedKeys, requirementsAssessmentProtectedKeys); err != nil {
			return nil, wrapRuntimeError(err, domain.DiagnosticCauseCandidateValidationFailed)
		}
		if !requirementObjectFields(row, "requirement_id", "verdict", "rationale", "evidence", "examined_scope", "limitations", "reason") {
			return nil, fmt.Errorf("requirements: missing answer field")
		}
		id, _ := row["requirement_id"].(string)
		r, ok := assigned[id]
		if !ok || seen[id] {
			return nil, fmt.Errorf("requirements: duplicate, foreign or wrong-owner ID")
		}
		seen[id] = true
		verdict, _ := row["verdict"].(string)
		reason, reasonOK := row["reason"].(string)
		if !reasonOK {
			return nil, fmt.Errorf("requirements: invalid reason")
		}
		assessment, err := domain.NewRequirementAssessment(r, domain.RequirementVerdict(verdict), domain.AssessmentProvider, domain.AssessmentReason(reason))
		if err != nil {
			return nil, err
		}
		content := RequirementContent{SchemaVersion: RequirementContentVersion, RequirementID: id, Evidence: make([]RequirementContentEvidence, 0)}
		content.Rationale, ok = row["rationale"].(string)
		if !ok {
			return nil, fmt.Errorf("requirements: invalid rationale")
		}
		content.ExaminedScope, ok = row["examined_scope"].(string)
		if !ok {
			return nil, fmt.Errorf("requirements: invalid examined scope")
		}
		limitations, ok := row["limitations"].([]any)
		if !ok || len(limitations) > 20 {
			return nil, fmt.Errorf("requirements: invalid limitations")
		}
		content.Limitations = make([]string, len(limitations))
		for i, v := range limitations {
			content.Limitations[i], ok = v.(string)
			if !ok {
				return nil, fmt.Errorf("requirements: invalid limitation")
			}
		}
		items, ok := row["evidence"].([]any)
		if !ok || len(items) > 32 {
			return nil, fmt.Errorf("requirements: invalid evidence")
		}
		for _, v := range items {
			item, ok := v.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("requirements: invalid evidence item")
			}
			if err := validateRequirementsObjectKeys(item, "evidence", requirementsEvidenceAllowedKeys, requirementsEvidenceProtectedKeys); err != nil {
				return nil, wrapRuntimeError(err, domain.DiagnosticCauseCandidateValidationFailed)
			}
			current, ok := item["current"].(map[string]any)
			if !ok {
				return nil, fmt.Errorf("requirements: missing current evidence")
			}
			if err := validateRequirementsObjectKeys(current, "current", requirementsCurrentAllowedKeys, requirementsCurrentProtectedKeys); err != nil {
				return nil, wrapRuntimeError(err, domain.DiagnosticCauseCandidateValidationFailed)
			}
			if !requirementObjectFields(current, "path", "side", "line_start", "line_end", "quote") {
				return nil, fmt.Errorf("requirements: invalid current fields")
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
				return nil, fmt.Errorf("requirements: invalid evidence bounds")
			}
			if !identity.SupportsSide(evidence.Side(wire.Side)) {
				return nil, fmt.Errorf("requirements: input prose or unselected source side is not evidence")
			}
			claim, err := evidence.NewLiveClaim(identity, evidence.Side(wire.Side), wire.Path, wire.Start, wire.End, wire.Quote)
			if err != nil {
				return nil, err
			}
			receipt, err := verifier.VerifyCurrent(ctx, claim)
			if err != nil {
				return nil, requirementsSourceFailure(err)
			}
			if wire.Path == inputPath && receipt.SourceFileSHA256() == inputSHA256 {
				return nil, fmt.Errorf("requirements: invocation prose is not implementation evidence")
			}
			if receipt.Status() != evidence.ReceiptVerified {
				return nil, fmt.Errorf("requirements: unsupported evidence")
			}
			normalized := RequirementContentEvidence{Current: RequirementCurrentEvidence{SourceIdentitySHA256: identity.SHA256(), CurrentExcerptSHA256: receipt.ExcerptSHA256(), Side: CurrentEvidenceSide(wire.Side), Path: wire.Path, LineStart: wire.Start, LineEnd: wire.End, Quote: string(receipt.Excerpt()), Verification: "verified"}}
			if visual, present := item["visual"]; present {
				object, ok := visual.(map[string]any)
				if !ok {
					return nil, fmt.Errorf("requirements: invalid visual")
				}
				if err := validateRequirementsObjectKeys(object, "visual", requirementsVisualAllowedKeys, requirementsVisualProtectedKeys); err != nil {
					return nil, wrapRuntimeError(err, domain.DiagnosticCauseCandidateValidationFailed)
				}
				bbox, ok := object["bbox"].(map[string]any)
				if !ok || !requirementObjectFields(bbox, "x", "y", "width", "height") {
					return nil, fmt.Errorf("requirements: invalid visual bounds")
				}
				encoded, _ := json.Marshal(object)
				var image artifactwire.VisualEvidence
				if json.Unmarshal(encoded, &image) != nil || role != domain.RoleArtist || visuals[wire.Side+"\x00"+image.Path] != image.SHA256 {
					return nil, fmt.Errorf("requirements: unverified visual")
				}
				image.Verification = "verified"
				normalized.Visual = &image
			}
			content.Evidence = append(content.Evidence, normalized)
		}
		encoded, err := json.Marshal(content)
		if err != nil {
			return nil, err
		}
		if _, err = DecodeRequirementContent(encoded, assessment, identity.SHA256()); err != nil {
			return nil, err
		}
		answers = append(answers, ValidatedRequirementAnswer{requirement: r, assessment: assessment, content: encoded, source: identity.SHA256()})
	}
	return answers, nil
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

func NormalizeRequirements(input RequirementsInput, answers []ValidatedRequirementAnswer, reasons map[domain.Role]domain.AssessmentReason, identity string, noChange bool) (RequirementResults, error) {
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
		reason := reasons[r.OwnerRole()]
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
