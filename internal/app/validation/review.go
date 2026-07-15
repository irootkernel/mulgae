// Package validation validates untrusted provider review output before it enters
// the domain model. It deliberately has no provider, evidence lookup, or
// publication dependencies.
package validation

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/irootkernel/kkachi-agent-review/internal/domain"
	"github.com/irootkernel/kkachi-agent-review/internal/ports"
	"golang.org/x/text/unicode/norm"
)

const (
	// ProviderReviewSchemaID is the sole authoritative provider review schema.
	ProviderReviewSchemaID = "https://kar.local/schemas/kar-provider-review-output.v2.schema.json"
	repairPatchSchemaID    = "urn:kar:schema:repair-patch:v1"
	maxRepairOperations    = 100
)

// SchemaValidator is owned by this consumer boundary. The JSON Schema adapter
// satisfies it without making validation depend on that adapter package.
type SchemaValidator interface {
	Validate(context.Context, ports.AssetID, []byte) error
}

// providerDocumentViolation is an adapter-independent structural classification
// for errors caused by provider document bytes.
type providerDocumentViolation interface {
	DocumentViolation() bool
}

func isProviderDocumentViolation(err error) bool {
	var violation providerDocumentViolation
	return errors.As(err, &violation) && violation.DocumentViolation()
}

// ReviewValidationScope contains only trusted execution identity. Provider
// output never supplies any of these values.
type ReviewValidationScope struct {
	TargetSHA256     string
	Role             domain.Role
	ProviderInstance string
	// SourceBearing is false for a root review. Source identity is not accepted
	// from providers in either mode; source-bearing validation needs a later,
	// trusted source-identity reducer and is intentionally out of this slice.
	SourceBearing bool
}

// RepairMode describes the only two bounded provider repair forms.
type RepairMode string

const (
	RepairModeReformatOnly      RepairMode = "reformat_only"
	RepairModeFillMissingFields RepairMode = "fill_missing_fields"
)

// RepairPlan binds an eligible repair to the exact original bytes. Its getters
// expose copies so callers cannot alter a plan after classification.
type RepairPlan struct {
	mode           RepairMode
	allowedPaths   []string
	originalSHA256 [sha256.Size]byte
}

func (plan RepairPlan) Mode() RepairMode { return plan.mode }

// AllowedPaths returns the exact JSON Pointer paths that a patch may change.
func (plan RepairPlan) AllowedPaths() []string {
	return append([]string(nil), plan.allowedPaths...)
}

// OriginalSHA256 returns the raw lowercase hexadecimal digest of the original
// provider stdout to which this plan is bound.
func (plan RepairPlan) OriginalSHA256() string {
	return hex.EncodeToString(plan.originalSHA256[:])
}

func (plan RepairPlan) valid() bool {
	if plan.mode != RepairModeReformatOnly && plan.mode != RepairModeFillMissingFields {
		return false
	}
	if plan.mode == RepairModeReformatOnly {
		return len(plan.allowedPaths) == 0
	}
	return len(plan.allowedPaths) > 0 &&
		len(plan.allowedPaths) <= maxRepairOperations &&
		sort.StringsAreSorted(plan.allowedPaths) &&
		uniqueStrings(plan.allowedPaths)
}

// ValidatedReview is the immutable normalized result of one provider review.
// Findings contain trusted role/provider identity and unverified evidence
// state; evidence lookup and state transitions are deliberately elsewhere.
type ValidatedReview struct {
	summary        string
	completeness   string
	limitations    []string
	findings       []domain.Finding
	evidenceClaims []FindingEvidenceClaims
	originalRaw    []byte
	repairedRaw    []byte
}

func (review ValidatedReview) Summary() string      { return review.summary }
func (review ValidatedReview) Completeness() string { return review.completeness }
func (review ValidatedReview) Limitations() []string {
	return append([]string(nil), review.limitations...)
}
func (review ValidatedReview) Findings() []domain.Finding {
	return append([]domain.Finding(nil), review.findings...)
}
func (review ValidatedReview) OriginalRaw() []byte { return append([]byte(nil), review.originalRaw...) }
func (review ValidatedReview) RepairedRaw() []byte { return append([]byte(nil), review.repairedRaw...) }
func (review ValidatedReview) EvidenceClaims() []FindingEvidenceClaims {
	return cloneFindingEvidenceClaims(review.evidenceClaims)
}
func (review ValidatedReview) Repaired() bool { return review.repairedRaw != nil }

// ReviewValidator validates provider-only JSON and injects trusted current
// target identity before invoking the authoritative v2 schema.
type ReviewValidator struct {
	schemaValidator SchemaValidator
	schemaID        ports.AssetID
}

// NewReviewValidator creates a validator for the one authoritative v2 review
// schema. Supplying a different schema is rejected rather than silently
// weakening this boundary.
func NewReviewValidator(schemaValidator SchemaValidator, schemaID ports.AssetID) (*ReviewValidator, error) {
	if nilSchemaValidator(schemaValidator) {
		return nil, fmt.Errorf("review validation: nil schema validator")
	}
	if !schemaID.Valid() || schemaID.String() != ProviderReviewSchemaID {
		return nil, fmt.Errorf("review validation: schema ID must be %q", ProviderReviewSchemaID)
	}
	return &ReviewValidator{schemaValidator: schemaValidator, schemaID: schemaID}, nil
}

// Validate parses exactly one provider JSON object, rejects system-owned
// fields, injects trusted target identity, then runs schema validation before
// semantic validation. An error with a non-nil RepairPlan is eligible for at
// most one caller-owned repair attempt.
func (validator *ReviewValidator) Validate(ctx context.Context, raw []byte, scope ReviewValidationScope) (ValidatedReview, *RepairPlan, error) {
	return validator.validate(ctx, raw, scope, raw, nil, true)
}

func (validator *ReviewValidator) validate(ctx context.Context, raw []byte, scope ReviewValidationScope, originalRaw, repairedRaw []byte, classifyRepair bool) (ValidatedReview, *RepairPlan, error) {
	if validator == nil {
		return ValidatedReview{}, nil, fmt.Errorf("review validation: nil validator")
	}
	if ctx == nil {
		return ValidatedReview{}, nil, fmt.Errorf("review validation: nil context")
	}
	if err := ctx.Err(); err != nil {
		return ValidatedReview{}, nil, fmt.Errorf("review validation: context: %w", err)
	}
	if nilSchemaValidator(validator.schemaValidator) || !validator.schemaID.Valid() || validator.schemaID.String() != ProviderReviewSchemaID {
		return ValidatedReview{}, nil, fmt.Errorf("review validation: invalid validator configuration")
	}
	trustedTarget, err := validateScope(scope)
	if err != nil {
		return ValidatedReview{}, nil, err
	}
	if scope.SourceBearing {
		return ValidatedReview{}, nil, fmt.Errorf("review validation: source-bearing reviews require a trusted source-identity reducer")
	}

	provider, err := decodeJSONObject(raw, "provider output")
	if err != nil {
		if classifyRepair {
			return ValidatedReview{}, newRepairPlan(RepairModeReformatOnly, raw, nil), err
		}
		return ValidatedReview{}, nil, err
	}
	if err := guardProviderReview(provider); err != nil {
		return ValidatedReview{}, nil, err
	}

	candidate, err := injectTrustedCurrentTarget(provider, trustedTarget)
	if err != nil {
		return ValidatedReview{}, nil, err
	}
	candidateRaw, err := json.Marshal(candidate)
	if err != nil {
		return ValidatedReview{}, nil, fmt.Errorf("review validation: marshal injected candidate: %w", err)
	}
	if err := validator.schemaValidator.Validate(ctx, validator.schemaID, candidateRaw); err != nil {
		inspection := inspectReview(provider, trustedTarget)
		schemaErr := fmt.Errorf("review validation: schema: %w", err)
		if inspection.hasFatal() {
			return ValidatedReview{}, nil, errors.Join(schemaErr, inspection.error())
		}
		if classifyRepair && isProviderDocumentViolation(err) && inspection.repairOnly() {
			plan, planErr := newFillRepairPlan(raw, inspection.repairable)
			if planErr != nil {
				return ValidatedReview{}, nil, errors.Join(schemaErr, inspection.error(), planErr)
			}
			return ValidatedReview{}, plan, schemaErr
		}
		return ValidatedReview{}, nil, schemaErr
	}

	inspection := inspectReview(provider, trustedTarget)
	if inspection.hasFatal() || len(inspection.repairable) > 0 {
		if classifyRepair && inspection.repairOnly() {
			plan, planErr := newFillRepairPlan(raw, inspection.repairable)
			if planErr != nil {
				return ValidatedReview{}, nil, errors.Join(inspection.error(), planErr)
			}
			return ValidatedReview{}, plan, inspection.error()
		}
		return ValidatedReview{}, nil, inspection.error()
	}

	findings, evidenceClaims, err := normalizeFindings(inspection.review.findings, scope, trustedTarget)
	if err != nil {
		return ValidatedReview{}, nil, err
	}
	return ValidatedReview{
		summary:        inspection.review.summary,
		completeness:   inspection.review.completeness,
		limitations:    append([]string(nil), inspection.review.limitations...),
		findings:       findings,
		evidenceClaims: evidenceClaims,
		originalRaw:    append([]byte(nil), originalRaw...),
		repairedRaw:    cloneOptionalBytes(repairedRaw),
	}, nil, nil
}

func validateScope(scope ReviewValidationScope) (string, error) {
	if !scope.Role.Valid() {
		return "", fmt.Errorf("review validation: invalid trusted role %q", scope.Role)
	}
	if strings.TrimSpace(scope.ProviderInstance) == "" {
		return "", fmt.Errorf("review validation: trusted provider instance is required")
	}
	return canonicalTargetSHA256(scope.TargetSHA256)
}

func canonicalTargetSHA256(value string) (string, error) {
	digest := value
	if strings.HasPrefix(digest, "sha256:") {
		digest = strings.TrimPrefix(digest, "sha256:")
	}
	if len(digest) != sha256.Size*2 {
		return "", fmt.Errorf("review validation: trusted target SHA-256 must be lowercase hexadecimal")
	}
	for _, character := range digest {
		if !(character >= '0' && character <= '9') && !(character >= 'a' && character <= 'f') {
			return "", fmt.Errorf("review validation: trusted target SHA-256 must be lowercase hexadecimal")
		}
	}
	return "sha256:" + digest, nil
}

func injectTrustedCurrentTarget(provider map[string]any, targetSHA256 string) (map[string]any, error) {
	candidate, err := cloneJSONObject(provider)
	if err != nil {
		return nil, err
	}
	findings, ok := candidate["findings"].([]any)
	if !ok {
		return candidate, nil
	}
	for findingIndex, findingValue := range findings {
		finding, ok := findingValue.(map[string]any)
		if !ok {
			continue
		}
		evidence, ok := finding["evidence"].([]any)
		if !ok {
			continue
		}
		for evidenceIndex, evidenceValue := range evidence {
			evidenceObject, ok := evidenceValue.(map[string]any)
			if !ok {
				continue
			}
			current, ok := evidenceObject["current"].(map[string]any)
			if !ok {
				continue
			}
			if _, supplied := current["target_sha256"]; supplied {
				return nil, fmt.Errorf("review validation: provider supplied system-owned target SHA-256 at findings[%d].evidence[%d]", findingIndex, evidenceIndex)
			}
			if _, supplied := current["verification"]; supplied {
				return nil, fmt.Errorf("review validation: provider supplied system-owned verification at findings[%d].evidence[%d]", findingIndex, evidenceIndex)
			}
			current["target_sha256"] = targetSHA256
			current["verification"] = "claimed"
		}
	}
	return candidate, nil
}

func cloneJSONObject(value map[string]any) (map[string]any, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("review validation: clone JSON: %w", err)
	}
	return decodeJSONObject(raw, "provider candidate")
}

// decodeJSONObject rejects empty input, non-UTF-8 input, non-object roots,
// duplicate keys, and any second JSON value.
func decodeJSONObject(raw []byte, subject string) (map[string]any, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, fmt.Errorf("review validation: %s is empty", subject)
	}
	if !utf8.Valid(raw) {
		return nil, fmt.Errorf("review validation: %s is not valid UTF-8", subject)
	}
	if err := rejectUnpairedJSONSurrogates(raw); err != nil {
		return nil, fmt.Errorf("review validation: %s: %w", subject, err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, fmt.Errorf("review validation: %s must be one JSON object: %w", subject, err)
	}
	var additional any
	if err := decoder.Decode(&additional); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("review validation: %s contains multiple JSON values", subject)
		}
		return nil, fmt.Errorf("review validation: %s must contain no trailing content: %w", subject, err)
	}
	if err := rejectDuplicateJSONKeys(raw); err != nil {
		return nil, fmt.Errorf("review validation: %s: %w", subject, err)
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("review validation: %s must be a JSON object", subject)
	}
	return object, nil
}

func rejectDuplicateJSONKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := consumeJSONValue(decoder); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("contains multiple JSON values")
		}
		return err
	}
	return nil
}

func consumeJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		keys := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf("object key is not a string")
			}
			if _, duplicate := keys[key]; duplicate {
				return fmt.Errorf("contains duplicate key %q", key)
			}
			keys[key] = struct{}{}
			if err := consumeJSONValue(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil {
			return err
		}
		if end != json.Delim('}') {
			return fmt.Errorf("object is not closed")
		}
	case '[':
		for decoder.More() {
			if err := consumeJSONValue(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil {
			return err
		}
		if end != json.Delim(']') {
			return fmt.Errorf("array is not closed")
		}
	default:
		return fmt.Errorf("invalid JSON delimiter %q", delimiter)
	}
	return nil
}

func rejectUnpairedJSONSurrogates(raw []byte) error {
	inString := false
	for index := 0; index < len(raw); index++ {
		switch raw[index] {
		case '"':
			inString = !inString
		case '\\':
			if !inString {
				continue
			}
			index++
			if index >= len(raw) {
				return fmt.Errorf("unterminated JSON escape")
			}
			if raw[index] != 'u' {
				continue
			}
			codePoint, err := parseJSONHexEscape(raw, index)
			if err != nil {
				return err
			}
			index += 4
			switch {
			case codePoint >= 0xd800 && codePoint <= 0xdbff:
				if index+6 >= len(raw) || raw[index+1] != '\\' || raw[index+2] != 'u' {
					return fmt.Errorf("unpaired high UTF-16 surrogate escape")
				}
				low, err := parseJSONHexEscape(raw, index+2)
				if err != nil || low < 0xdc00 || low > 0xdfff {
					return fmt.Errorf("unpaired high UTF-16 surrogate escape")
				}
				index += 6
			case codePoint >= 0xdc00 && codePoint <= 0xdfff:
				return fmt.Errorf("unpaired low UTF-16 surrogate escape")
			}
		}
	}
	return nil
}

func parseJSONHexEscape(raw []byte, marker int) (uint64, error) {
	if marker+4 >= len(raw) {
		return 0, fmt.Errorf("truncated UTF-16 escape")
	}
	value, err := strconv.ParseUint(string(raw[marker+1:marker+5]), 16, 16)
	if err != nil {
		return 0, fmt.Errorf("invalid UTF-16 escape")
	}
	return value, nil
}

// guardProviderReview is an ownership guard, not just a convenience schema
// check. It rejects all system-owned identity, transition, outcome, hash, and
// orchestration fields before they can influence normalized data.
func guardProviderReview(provider map[string]any) error {
	if err := requireOnlyKeys(provider, "provider output", "schema_version", "summary", "completeness", "limitations", "findings"); err != nil {
		return err
	}
	findings, ok := provider["findings"].([]any)
	if !ok {
		return nil
	}
	for findingIndex, findingValue := range findings {
		finding, ok := findingValue.(map[string]any)
		if !ok {
			continue
		}
		findingPath := fmt.Sprintf("findings[%d]", findingIndex)
		if err := requireOnlyKeys(finding, findingPath, "severity", "title", "description", "evidence", "recommendation", "confidence"); err != nil {
			return err
		}
		evidence, ok := finding["evidence"].([]any)
		if !ok {
			continue
		}
		for evidenceIndex, evidenceValue := range evidence {
			evidenceObject, ok := evidenceValue.(map[string]any)
			if !ok {
				continue
			}
			evidencePath := fmt.Sprintf("%s.evidence[%d]", findingPath, evidenceIndex)
			if err := requireOnlyKeys(evidenceObject, evidencePath, "current"); err != nil {
				return err
			}
			current, ok := evidenceObject["current"].(map[string]any)
			if !ok {
				continue
			}
			if err := requireOnlyKeys(current, evidencePath+".current", "path", "line_start", "line_end", "side", "quote"); err != nil {
				return err
			}
		}
	}
	return nil
}

func requireOnlyKeys(object map[string]any, location string, allowed ...string) error {
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, key := range allowed {
		allowedSet[key] = struct{}{}
	}
	for key := range object {
		if _, ok := allowedSet[key]; !ok {
			return fmt.Errorf("review validation: provider supplied system-owned or unknown field %s.%s", location, key)
		}
	}
	return nil
}

type providerReview struct {
	summary      string
	completeness string
	limitations  []string
	findings     []providerFinding
}

type providerFinding struct {
	severity       domain.Severity
	title          string
	description    string
	recommendation string
	confidence     domain.Confidence
	evidence       []providerEvidence
}

type providerEvidence struct {
	path      string
	lineStart int
	lineEnd   int
	side      string
	quote     string
}

type reviewInspection struct {
	review     providerReview
	repairable []string
	fatal      []string
}

func (inspection *reviewInspection) addRepair(path string) {
	inspection.repairable = append(inspection.repairable, path)
}

func (inspection *reviewInspection) addFatal(format string, arguments ...any) {
	inspection.fatal = append(inspection.fatal, fmt.Sprintf(format, arguments...))
}

func (inspection reviewInspection) hasFatal() bool { return len(inspection.fatal) > 0 }
func (inspection reviewInspection) repairOnly() bool {
	return !inspection.hasFatal() && len(inspection.repairable) > 0
}
func (inspection reviewInspection) error() error {
	issues := append([]string(nil), inspection.fatal...)
	for _, path := range sortedUnique(inspection.repairable) {
		issues = append(issues, "missing, empty, or placeholder provider value at "+path)
	}
	if len(issues) == 0 {
		return nil
	}
	return fmt.Errorf("review validation: %s", strings.Join(issues, "; "))
}

// inspectReview performs semantic validation after schema validation. It also
// identifies the exact conservative subset of provider paths that can be
// repaired without replacing meaningful data.
func inspectReview(provider map[string]any, trustedTargetSHA256 string) reviewInspection {
	inspection := reviewInspection{}
	requiredConstant(provider, "schema_version", "/schema_version", "kar-provider-review-output.v2", &inspection)
	inspection.review.summary = requiredText(provider, "summary", "/summary", 4000, &inspection)
	inspection.review.completeness = requiredEnum(provider, "completeness", "/completeness", []string{"complete", "incomplete"}, &inspection)
	limitations, repairableLimitations := requiredLimitations(provider, &inspection)
	inspection.review.limitations = limitations
	completenessIssues := reviewCompletenessIssues(ValidateReviewCompleteness(inspection.review.completeness, inspection.review.limitations))
	for _, issue := range completenessIssues {
		switch issue.kind {
		case reviewCompletenessTooManyLimitations, reviewCompletenessLimitationTooLong, reviewCompletenessDuplicateLimitation:
			inspection.addFatal("%s", issue.message)
		case reviewCompletenessMeaninglessLimitation:
			if repairableLimitations[issue.index] {
				inspection.addRepair("/limitations/" + strconv.Itoa(issue.index))
			} else {
				inspection.addFatal("/limitations/%d must be a string", issue.index)
			}
		}
	}

	findings, exists := provider["findings"]
	if !exists || findings == nil {
		inspection.addFatal("findings is required and cannot be repaired without changing finding count")
		return inspection
	}
	array, ok := findings.([]any)
	if !ok {
		inspection.addFatal("findings must be an array")
		return inspection
	}
	if len(array) > 200 {
		inspection.addFatal("findings exceeds 200 items")
		return inspection
	}
	inspection.review.findings = make([]providerFinding, 0, len(array))
	for index, value := range array {
		finding, ok := value.(map[string]any)
		if !ok {
			inspection.addFatal("/findings/%d must be an object", index)
			continue
		}
		inspection.review.findings = append(inspection.review.findings, inspectFinding(finding, index, &inspection))
	}

	for _, issue := range completenessIssues {
		switch issue.kind {
		case reviewCompletenessIncompleteWithoutLimitation:
			if !hasRepairableLimitation(inspection.repairable) {
				inspection.addFatal("%s", issue.message)
			}
		case reviewCompletenessMaterialScopeUnreadable:
			inspection.addFatal("%s", issue.message)
		}
	}
	if len(inspection.review.findings) > 0 && claimsNoFindings(inspection.review.summary) {
		inspection.addFatal("summary claims no findings while findings are present")
	}
	if !inspection.hasFatal() && len(inspection.repairable) == 0 && duplicateNormalizedFinding(inspection.review.findings, trustedTargetSHA256) {
		inspection.addFatal("duplicate normalized finding content")
	}
	inspection.repairable = sortedUnique(inspection.repairable)
	return inspection
}

func inspectFinding(finding map[string]any, index int, inspection *reviewInspection) providerFinding {
	base := "/findings/" + strconv.Itoa(index)
	severity := requiredEnum(finding, "severity", base+"/severity", []string{"info", "low", "medium", "high", "critical", "blocker"}, inspection)
	result := providerFinding{
		severity:       domain.Severity(severity),
		title:          requiredText(finding, "title", base+"/title", 300, inspection),
		description:    requiredText(finding, "description", base+"/description", 12000, inspection),
		recommendation: requiredText(finding, "recommendation", base+"/recommendation", 12000, inspection),
		confidence:     domain.Confidence(requiredEnum(finding, "confidence", base+"/confidence", []string{"low", "medium", "high"}, inspection)),
	}
	result.evidence = requiredEvidence(finding, base, inspection)
	if result.severity.Rank() >= domain.SeverityHigh.Rank() && len(result.evidence) == 0 && !inspection.repairOnly() {
		inspection.addFatal("%s requires evidence", base)
	}
	return result
}

func requiredLimitations(provider map[string]any, inspection *reviewInspection) ([]string, map[int]bool) {
	value, exists := provider["limitations"]
	if !exists || value == nil {
		inspection.addRepair("/limitations")
		return nil, nil
	}
	limitations, ok := value.([]any)
	if !ok {
		if repairableInvalidScalar(value) {
			inspection.addRepair("/limitations")
		} else {
			inspection.addFatal("limitations must be an array")
		}
		return nil, nil
	}

	result := make([]string, len(limitations))
	repairable := make(map[int]bool, len(limitations))
	for index, value := range limitations {
		text, ok := value.(string)
		if ok {
			result[index] = text
			repairable[index] = true
			continue
		}
		if repairableInvalidScalar(value) {
			repairable[index] = true
		}
	}
	return result, repairable
}

func requiredEvidence(finding map[string]any, base string, inspection *reviewInspection) []providerEvidence {
	value, exists := finding["evidence"]
	if !exists || value == nil {
		inspection.addRepair(base + "/evidence")
		return nil
	}
	evidence, ok := value.([]any)
	if !ok {
		if repairableInvalidScalar(value) {
			inspection.addRepair(base + "/evidence")
		} else {
			inspection.addFatal("%s/evidence must be an array", base)
		}
		return nil
	}
	if len(evidence) == 0 {
		inspection.addFatal("%s/evidence must not be empty", base)
		return nil
	}
	if len(evidence) > 20 {
		inspection.addFatal("%s/evidence exceeds 20 items", base)
		return nil
	}
	result := make([]providerEvidence, 0, len(evidence))
	for index, value := range evidence {
		evidenceObject, ok := value.(map[string]any)
		if !ok {
			inspection.addFatal("%s/evidence/%d must be an object", base, index)
			continue
		}
		currentValue, exists := evidenceObject["current"]
		if !exists || currentValue == nil {
			inspection.addRepair(base + "/evidence/" + strconv.Itoa(index) + "/current")
			continue
		}
		current, ok := currentValue.(map[string]any)
		if !ok {
			if repairableInvalidScalar(currentValue) {
				inspection.addRepair(base + "/evidence/" + strconv.Itoa(index) + "/current")
			} else {
				inspection.addFatal("%s/evidence/%d/current must be an object", base, index)
			}
			continue
		}
		currentPath := base + "/evidence/" + strconv.Itoa(index) + "/current"
		item := providerEvidence{
			path:      requiredText(current, "path", currentPath+"/path", 4096, inspection),
			lineStart: requiredPositiveInteger(current, "line_start", currentPath+"/line_start", inspection),
			lineEnd:   requiredPositiveInteger(current, "line_end", currentPath+"/line_end", inspection),
			side:      requiredEnum(current, "side", currentPath+"/side", []string{"base", "head", "worktree"}, inspection),
			quote:     requiredText(current, "quote", currentPath+"/quote", 0, inspection),
		}
		if item.path != "" && (!utf8.ValidString(item.path) || norm.NFC.String(item.path) != item.path) {
			inspection.addFatal("%s/path must be UTF-8 NFC", currentPath)
		}
		if item.path != "" {
			if _, err := ports.NewSafeRelativePath(item.path); err != nil {
				inspection.addFatal("%s/path is not canonical: %v", currentPath, err)
			}
		}
		if item.lineStart > 0 && item.lineEnd > 0 && item.lineEnd < item.lineStart {
			inspection.addFatal("%s line_end precedes line_start", currentPath)
		}
		result = append(result, item)
	}
	return result
}

func requiredText(object map[string]any, key, path string, maxRunes int, inspection *reviewInspection) string {
	value, exists := object[key]
	if !exists || value == nil {
		inspection.addRepair(path)
		return ""
	}
	text, ok := value.(string)
	if !ok {
		if repairableInvalidScalar(value) {
			inspection.addRepair(path)
		} else {
			inspection.addFatal("%s must be a string", path)
		}
		return ""
	}
	if !meaningfulText(text) {
		inspection.addRepair(path)
		return ""
	}
	if maxRunes > 0 && utf8.RuneCountInString(text) > maxRunes {
		inspection.addFatal("%s exceeds maximum length", path)
		return ""
	}
	return text
}

func requiredEnum(object map[string]any, key, path string, allowed []string, inspection *reviewInspection) string {
	value, exists := object[key]
	if !exists || value == nil {
		inspection.addRepair(path)
		return ""
	}
	text, ok := value.(string)
	if !ok {
		if repairableInvalidScalar(value) {
			inspection.addRepair(path)
		} else {
			inspection.addFatal("%s must be a string", path)
		}
		return ""
	}
	if !meaningfulText(text) {
		inspection.addRepair(path)
		return ""
	}
	for _, candidate := range allowed {
		if text == candidate {
			return text
		}
	}
	inspection.addRepair(path)
	return ""
}

func requiredPositiveInteger(object map[string]any, key, path string, inspection *reviewInspection) int {
	value, exists := object[key]
	if !exists || value == nil {
		inspection.addRepair(path)
		return 0
	}
	number, ok := value.(json.Number)
	if !ok {
		if repairableInvalidScalar(value) {
			inspection.addRepair(path)
		} else {
			inspection.addFatal("%s must be an integer", path)
		}
		return 0
	}
	text := number.String()
	if strings.ContainsAny(text, ".eE") {
		inspection.addRepair(path)
		return 0
	}
	parsed, err := strconv.ParseInt(text, 10, 0)
	if err != nil || parsed < 1 {
		inspection.addRepair(path)
		return 0
	}
	return int(parsed)
}
func requiredConstant(object map[string]any, key, path, expected string, inspection *reviewInspection) {
	value, exists := object[key]
	if !exists || value == nil {
		inspection.addRepair(path)
		return
	}
	text, ok := value.(string)
	if !ok {
		if repairableInvalidScalar(value) {
			inspection.addRepair(path)
		} else {
			inspection.addFatal("%s must be a string", path)
		}
		return
	}
	if !meaningfulText(text) {
		inspection.addRepair(path)
		return
	}
	if text != expected {
		inspection.addFatal("%s must equal %q", path, expected)
	}
}

func repairableInvalidScalar(value any) bool {
	switch value.(type) {
	case nil, string, json.Number, bool:
		return true
	default:
		return false
	}
}

func meaningfulText(value string) bool {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return false
	}
	switch strings.ToLower(trimmed) {
	case "n/a", "tbd", "todo", "unknown", "none", "-":
		return false
	default:
		return true
	}
}

type reviewCompletenessIssueKind uint8

const (
	reviewCompletenessInvalidValue reviewCompletenessIssueKind = iota
	reviewCompletenessTooManyLimitations
	reviewCompletenessMeaninglessLimitation
	reviewCompletenessLimitationTooLong
	reviewCompletenessDuplicateLimitation
	reviewCompletenessIncompleteWithoutLimitation
	reviewCompletenessMaterialScopeUnreadable
)

type reviewCompletenessIssue struct {
	kind    reviewCompletenessIssueKind
	index   int
	message string
}

type reviewCompletenessError struct {
	issues []reviewCompletenessIssue
}

func (err *reviewCompletenessError) Error() string {
	messages := make([]string, len(err.issues))
	for index, issue := range err.issues {
		messages[index] = issue.message
	}
	return strings.Join(messages, "; ")
}

// ValidateReviewCompleteness validates provider-declared review completeness and
// its limitations without consulting any runtime, provider, or evidence state.
func ValidateReviewCompleteness(completeness string, limitations []string) error {
	issues := make([]reviewCompletenessIssue, 0)
	switch completeness {
	case "complete", "incomplete":
	default:
		issues = append(issues, reviewCompletenessIssue{
			kind:    reviewCompletenessInvalidValue,
			message: fmt.Sprintf("invalid completeness %q", completeness),
		})
	}

	if len(limitations) > 20 {
		issues = append(issues, reviewCompletenessIssue{
			kind:    reviewCompletenessTooManyLimitations,
			message: "limitations exceeds 20 items",
		})
	}

	accepted := make([]string, 0, len(limitations))
	seen := make(map[string]struct{}, len(limitations))
	for index, limitation := range limitations {
		if !meaningfulText(limitation) {
			issues = append(issues, reviewCompletenessIssue{
				kind:    reviewCompletenessMeaninglessLimitation,
				index:   index,
				message: fmt.Sprintf("/limitations/%d must be meaningful", index),
			})
			continue
		}
		if utf8.RuneCountInString(limitation) > 2000 {
			issues = append(issues, reviewCompletenessIssue{
				kind:    reviewCompletenessLimitationTooLong,
				index:   index,
				message: fmt.Sprintf("/limitations/%d exceeds 2000 characters", index),
			})
			continue
		}
		if _, duplicate := seen[limitation]; duplicate {
			issues = append(issues, reviewCompletenessIssue{
				kind:    reviewCompletenessDuplicateLimitation,
				message: "limitations contains duplicate value",
			})
			continue
		}
		seen[limitation] = struct{}{}
		accepted = append(accepted, limitation)
	}

	if completeness == "incomplete" && len(accepted) == 0 {
		issues = append(issues, reviewCompletenessIssue{
			kind:    reviewCompletenessIncompleteWithoutLimitation,
			message: "incomplete review requires at least one limitation",
		})
	}
	if completeness == "complete" {
		for _, limitation := range accepted {
			if materialScopeUnreadable(limitation) {
				issues = append(issues, reviewCompletenessIssue{
					kind:    reviewCompletenessMaterialScopeUnreadable,
					message: "complete review cannot state that material scope was unreadable",
				})
				break
			}
		}
	}
	if len(issues) == 0 {
		return nil
	}
	return &reviewCompletenessError{issues: issues}
}

func reviewCompletenessIssues(err error) []reviewCompletenessIssue {
	var completenessErr *reviewCompletenessError
	if !errors.As(err, &completenessErr) {
		return nil
	}
	return append([]reviewCompletenessIssue(nil), completenessErr.issues...)
}

func claimsNoFindings(summary string) bool {
	normalized := strings.ToLower(strings.Join(strings.Fields(summary), " "))
	normalized = strings.TrimRight(normalized, ".!?")
	switch normalized {
	case "no findings",
		"no findings found",
		"no findings were found",
		"no findings were identified",
		"no findings were identified in the reviewed scope",
		"no issues",
		"no issues found",
		"no issues were found",
		"no issues were identified",
		"no issues were identified in the reviewed scope":
		return true
	default:
		return false
	}
}

func materialScopeUnreadable(limitation string) bool {
	normalized := strings.ToLower(limitation)
	words := strings.FieldsFunc(normalized, func(runeValue rune) bool {
		return !unicode.IsLetter(runeValue)
	})

	hasMaterialScope := false
	hasAccessibilityFailure := false
	hasReviewVerb := false
	hasNegation := strings.Contains(normalized, "could not") ||
		strings.Contains(normalized, "couldn't") ||
		strings.Contains(normalized, "cannot") ||
		strings.Contains(normalized, "can't")

	for _, word := range words {
		switch word {
		case "material", "scope", "target", "file", "files":
			hasMaterialScope = true
		case "unreadable", "inaccessible":
			hasAccessibilityFailure = true
		case "not", "unable", "failed":
			hasNegation = true
		}
		if strings.HasPrefix(word, "read") ||
			strings.HasPrefix(word, "access") ||
			strings.HasPrefix(word, "inspect") ||
			strings.HasPrefix(word, "review") ||
			strings.HasPrefix(word, "load") {
			hasReviewVerb = true
		}
	}
	return hasMaterialScope && (hasAccessibilityFailure || (hasNegation && hasReviewVerb))
}

func duplicateNormalizedFinding(findings []providerFinding, trustedTargetSHA256 string) bool {
	seen := make(map[string]struct{}, len(findings))
	for _, finding := range findings {
		claims, err := normalizeCurrentEvidenceClaims(finding.evidence, trustedTargetSHA256)
		if err != nil {
			return false
		}
		parts := []string{
			normalizeContent(finding.title),
			normalizeContent(finding.description),
			normalizeContent(finding.recommendation),
		}
		for _, claim := range claims {
			parts = append(parts, evidenceKey(claim))
		}
		key := strings.Join(parts, "\x00")
		if _, duplicate := seen[key]; duplicate {
			return true
		}
		seen[key] = struct{}{}
	}
	return false
}

type normalizedFindingEvidence struct {
	finding  domain.Finding
	identity normalizedFindingIdentity
	claims   []CurrentEvidenceClaim
}

type normalizedFindingIdentity struct {
	fingerprint              string
	severity                 domain.Severity
	path                     string
	lineStart                int
	role                     domain.Role
	providerInstance         string
	title                    string
	description              string
	recommendation           string
	confidence               domain.Confidence
	lifecycle                domain.FindingLifecycle
	evidenceState            domain.EvidenceState
	normalizedRuleCategory   string
	normalizedEvidenceRegion string
}

func normalizeFindings(input []providerFinding, scope ReviewValidationScope, trustedTargetSHA256 string) ([]domain.Finding, []FindingEvidenceClaims, error) {
	normalized := make([]normalizedFindingEvidence, 0, len(input))
	for index, finding := range input {
		if len(finding.evidence) == 0 {
			return nil, nil, fmt.Errorf("review validation: finding %d has no evidence", index)
		}
		claims, err := normalizeCurrentEvidenceClaims(finding.evidence, trustedTargetSHA256)
		if err != nil {
			return nil, nil, fmt.Errorf("review validation: normalize finding %d evidence: %w", index, err)
		}
		regionParts := make([]string, 0, len(claims))
		for _, claim := range claims {
			regionParts = append(regionParts, evidenceKey(claim))
		}
		findingValue, err := domain.NewFinding(domain.FindingInput{
			Severity:                 finding.severity,
			Path:                     claims[0].Path().String(),
			LineStart:                claims[0].LineStart(),
			Role:                     scope.Role,
			ProviderInstance:         strings.TrimSpace(scope.ProviderInstance),
			Title:                    finding.title,
			Description:              finding.description,
			Recommendation:           finding.recommendation,
			Confidence:               finding.confidence,
			Lifecycle:                domain.FindingOpen,
			EvidenceState:            domain.EvidenceUnverified,
			NormalizedRuleCategory:   finding.title,
			NormalizedEvidenceRegion: strings.Join(regionParts, " | "),
		})
		if err != nil {
			return nil, nil, fmt.Errorf("review validation: normalize finding %d: %w", index, err)
		}
		normalized = append(normalized, normalizedFindingEvidence{
			finding:  findingValue,
			identity: normalizedFindingIdentityFor(findingValue),
			claims:   claims,
		})
	}
	if err := validateUniqueFindingIdentities(normalized); err != nil {
		return nil, nil, err
	}

	findings := make([]domain.Finding, len(normalized))
	for index := range normalized {
		findings[index] = normalized[index].finding
	}
	ordered, err := domain.OrderAndAssignFindings(findings)
	if err != nil {
		return nil, nil, fmt.Errorf("review validation: order findings: %w", err)
	}
	evidenceClaims := make([]FindingEvidenceClaims, len(ordered))
	for orderedIndex, finding := range ordered {
		identity := normalizedFindingIdentityFor(finding)
		matchIndex := -1
		for candidateIndex := range normalized {
			if normalized[candidateIndex].identity != identity {
				continue
			}
			if matchIndex >= 0 {
				return nil, nil, fmt.Errorf("review validation: ambiguous finding evidence correlation for %q", finding.ID())
			}
			matchIndex = candidateIndex
		}
		if matchIndex < 0 {
			return nil, nil, fmt.Errorf("review validation: missing finding evidence correlation for %q", finding.ID())
		}
		if finding.ID() == "" {
			return nil, nil, fmt.Errorf("review validation: ordered finding has no assigned ID")
		}
		evidenceGroup, err := newFindingEvidenceClaims(finding, normalized[matchIndex].claims, trustedTargetSHA256)
		if err != nil {
			return nil, nil, fmt.Errorf("review validation: finding %q evidence proof: %w", finding.ID(), err)
		}
		evidenceClaims[orderedIndex] = evidenceGroup
	}
	return ordered, evidenceClaims, nil
}

func normalizeCurrentEvidenceClaims(input []providerEvidence, trustedTargetSHA256 string) ([]CurrentEvidenceClaim, error) {
	claims := make([]CurrentEvidenceClaim, len(input))
	for index, evidence := range input {
		path, err := ports.NewSafeRelativePath(evidence.path)
		if err != nil {
			return nil, fmt.Errorf("claim %d path: %w", index, err)
		}
		side := CurrentEvidenceSide(evidence.side)
		if !side.Valid() {
			return nil, fmt.Errorf("claim %d has invalid side %q", index, evidence.side)
		}
		if evidence.lineStart < 1 || evidence.lineEnd < evidence.lineStart {
			return nil, fmt.Errorf("claim %d has invalid line range", index)
		}
		claims[index] = CurrentEvidenceClaim{
			targetSHA256: trustedTargetSHA256,
			path:         path,
			lineStart:    evidence.lineStart,
			lineEnd:      evidence.lineEnd,
			side:         side,
			quote:        []byte(evidence.quote),
		}
	}
	sortCurrentEvidenceClaims(claims)
	return claims, nil
}

func normalizedFindingIdentityFor(finding domain.Finding) normalizedFindingIdentity {
	return normalizedFindingIdentity{
		fingerprint:              finding.Fingerprint(),
		severity:                 finding.Severity(),
		path:                     finding.Path(),
		lineStart:                finding.LineStart(),
		role:                     finding.Role(),
		providerInstance:         finding.ProviderInstance(),
		title:                    finding.Title(),
		description:              finding.Description(),
		recommendation:           finding.Recommendation(),
		confidence:               finding.Confidence(),
		lifecycle:                finding.Lifecycle(),
		evidenceState:            finding.EvidenceState(),
		normalizedRuleCategory:   finding.NormalizedRuleCategory(),
		normalizedEvidenceRegion: finding.NormalizedEvidenceRegion(),
	}
}

func validateUniqueFindingIdentities(findings []normalizedFindingEvidence) error {
	for left := 0; left < len(findings); left++ {
		for right := left + 1; right < len(findings); right++ {
			if findings[left].identity == findings[right].identity {
				return fmt.Errorf("review validation: finding evidence correlation collision between normalized findings %d and %d", left, right)
			}
		}
	}
	return nil
}

func sortCurrentEvidenceClaims(claims []CurrentEvidenceClaim) {
	sort.Slice(claims, func(left, right int) bool {
		return CompareCurrentEvidenceClaims(claims[left], claims[right]) < 0
	})
}

func evidenceKey(claim CurrentEvidenceClaim) string {
	return strings.Join([]string{
		claim.path.String(),
		strconv.Itoa(claim.lineStart),
		strconv.Itoa(claim.lineEnd),
		string(claim.side),
		normalizeContent(string(claim.quote)),
	}, "\x00")
}

func normalizeContent(value string) string {
	return strings.ToLower(strings.Join(strings.Fields(value), " "))
}

func newRepairPlan(mode RepairMode, raw []byte, allowedPaths []string) *RepairPlan {
	plan := &RepairPlan{mode: mode, originalSHA256: sha256.Sum256(raw)}
	if mode == RepairModeFillMissingFields {
		plan.allowedPaths = sortedUnique(allowedPaths)
	}
	return plan
}

func newFillRepairPlan(raw []byte, allowedPaths []string) (*RepairPlan, error) {
	paths := sortedUnique(allowedPaths)
	if len(paths) > maxRepairOperations {
		return nil, fmt.Errorf(
			"review validation: repair requires %d paths, exceeding the maximum of %d",
			len(paths),
			maxRepairOperations,
		)
	}
	return newRepairPlan(RepairModeFillMissingFields, raw, paths), nil
}

func sortedUnique(values []string) []string {
	copyValues := append([]string(nil), values...)
	sort.Strings(copyValues)
	result := copyValues[:0]
	for _, value := range copyValues {
		if len(result) == 0 || result[len(result)-1] != value {
			result = append(result, value)
		}
	}
	return result
}

func uniqueStrings(values []string) bool {
	for index := 1; index < len(values); index++ {
		if values[index-1] == values[index] {
			return false
		}
	}
	return true
}

func hasRepairableLimitation(paths []string) bool {
	for _, path := range paths {
		if path == "/limitations" || strings.HasPrefix(path, "/limitations/") {
			return true
		}
	}
	return false
}

func cloneOptionalBytes(value []byte) []byte {
	if value == nil {
		return nil
	}
	return append([]byte(nil), value...)
}

func nilSchemaValidator(validator SchemaValidator) bool {
	if validator == nil {
		return true
	}
	value := reflect.ValueOf(validator)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}
