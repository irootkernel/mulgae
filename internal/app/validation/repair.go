package validation

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/irootkernel/kkachi-agent-review/internal/domain"
	"github.com/irootkernel/kkachi-agent-review/internal/ports"
)

// ApplyRepair applies one already-classified repair response. It never retries,
// invokes a provider, or owns repair budget. A reformat repair revalidates a
// replacement review; a fill-missing-fields repair accepts only the bounded
// kar-repair-patch.v1 pointer set from its RepairPlan.
func (validator *ReviewValidator) ApplyRepair(ctx context.Context, originalRaw, repairRaw []byte, scope ReviewValidationScope, plan RepairPlan) (ValidatedReview, error) {
	review, _, err := validator.ApplyRepairCandidate(ctx, originalRaw, repairRaw, scope, plan)
	return review, err
}

// ApplyRepairCandidate applies a repair and returns the exact validated provider
// review candidate. For a patch repair, candidate is the reconstructed JSON;
// repairRaw remains the distinct provider patch stream in ValidatedReview.
func (validator *ReviewValidator) ApplyRepairCandidate(ctx context.Context, originalRaw, repairRaw []byte, scope ReviewValidationScope, plan RepairPlan) (ValidatedReview, []byte, error) {
	review, candidate, err := validator.applyRepairCandidate(ctx, originalRaw, repairRaw, scope, plan)
	if err != nil {
		return ValidatedReview{}, nil, wrapRuntimeError(err, domain.DiagnosticCauseCandidateRepairPlanInvalid)
	}
	return review, candidate, nil
}

func (validator *ReviewValidator) applyRepairCandidate(ctx context.Context, originalRaw, repairRaw []byte, scope ReviewValidationScope, plan RepairPlan) (ValidatedReview, []byte, error) {
	if validator == nil {
		return ValidatedReview{}, nil, fmt.Errorf("review repair: nil validator")
	}
	if ctx == nil {
		return ValidatedReview{}, nil, fmt.Errorf("review repair: nil context")
	}
	if err := ctx.Err(); err != nil {
		return ValidatedReview{}, nil, fmt.Errorf("review repair: context: %w", err)
	}
	if nilSchemaValidator(validator.schemaValidator) || !validator.schemaID.Valid() || validator.schemaID.String() != ProviderReviewSchemaID {
		return ValidatedReview{}, nil, fmt.Errorf("review repair: invalid validator configuration")
	}
	if _, err := validateScope(scope); err != nil {
		return ValidatedReview{}, nil, err
	}
	if scope.SourceBearing {
		return ValidatedReview{}, nil, fmt.Errorf("review repair: source-bearing reviews require a trusted source-identity reducer")
	}
	if !plan.valid() {
		return ValidatedReview{}, nil, fmt.Errorf("review repair: invalid repair plan")
	}
	if sha256.Sum256(originalRaw) != plan.originalSHA256 {
		return ValidatedReview{}, nil, fmt.Errorf("review repair: original output does not match repair plan")
	}

	switch plan.mode {
	case RepairModeReformatOnly:
		review, _, err := validator.validate(ctx, repairRaw, scope, originalRaw, repairRaw, false)
		if err != nil {
			return ValidatedReview{}, nil, fmt.Errorf("review repair: reformat candidate: %w", err)
		}
		return review, append([]byte(nil), repairRaw...), nil
	case RepairModeFillMissingFields:
		return validator.applyPatchRepairCandidate(ctx, originalRaw, repairRaw, scope, plan, false)
	case RepairModeExactEvidence:
		return validator.applyPatchRepairCandidate(ctx, originalRaw, repairRaw, scope, plan, true)
	default:
		return ValidatedReview{}, nil, fmt.Errorf("review repair: unsupported mode %q", plan.mode)
	}
}

func (validator *ReviewValidator) applyPatchRepairCandidate(ctx context.Context, originalRaw, repairRaw []byte, scope ReviewValidationScope, plan RepairPlan, allowMeaningfulEvidenceQuote bool) (ValidatedReview, []byte, error) {
	original, err := decodeJSONObject(originalRaw, "original provider output")
	if err != nil {
		return ValidatedReview{}, nil, err
	}
	if err := guardProviderReview(original); err != nil {
		return ValidatedReview{}, nil, err
	}
	originalCount, err := findingCount(original)
	if err != nil {
		return ValidatedReview{}, nil, err
	}
	originalSeverity, err := findingSeverities(original)
	if err != nil {
		return ValidatedReview{}, nil, err
	}

	patch, err := validator.decodeRepairPatch(ctx, repairRaw)
	if err != nil {
		return ValidatedReview{}, nil, err
	}
	allowed := make(map[string]struct{}, len(plan.allowedPaths))
	for _, path := range plan.allowedPaths {
		allowed[path] = struct{}{}
	}
	for _, operation := range patch.repairs {
		if _, ok := allowed[operation.path]; !ok {
			return ValidatedReview{}, nil, fmt.Errorf("review repair: path %q is not allowed", operation.path)
		}
		if err := setRepairValue(original, operation.path, operation.value, allowMeaningfulEvidenceQuote); err != nil {
			return ValidatedReview{}, nil, fmt.Errorf("review repair: path %q: %w", operation.path, err)
		}
		delete(allowed, operation.path)
	}
	if len(allowed) != 0 {
		return ValidatedReview{}, nil, fmt.Errorf("review repair: required paths were not repaired")
	}
	if err := guardProviderReview(original); err != nil {
		return ValidatedReview{}, nil, err
	}
	if repairedCount, err := findingCount(original); err != nil {
		return ValidatedReview{}, nil, err
	} else if repairedCount != originalCount {
		return ValidatedReview{}, nil, fmt.Errorf("review repair: finding count changed")
	}
	if err := rejectSeverityDowngrade(originalSeverity, original); err != nil {
		return ValidatedReview{}, nil, err
	}

	candidateRaw, err := json.Marshal(original)
	if err != nil {
		return ValidatedReview{}, nil, fmt.Errorf("review repair: marshal candidate: %w", err)
	}
	review, _, err := validator.validate(ctx, candidateRaw, scope, originalRaw, repairRaw, false)
	if err != nil {
		return ValidatedReview{}, nil, fmt.Errorf("review repair: patched candidate: %w", err)
	}
	return review, candidateRaw, nil
}

type repairPatch struct {
	repairs []repairOperation
}

type repairOperation struct {
	path  string
	value any
}

func (validator *ReviewValidator) decodeRepairPatch(ctx context.Context, raw []byte) (repairPatch, error) {
	patch, err := decodeJSONObject(raw, "repair patch")
	if err != nil {
		return repairPatch{}, err
	}
	if err := requireOnlyKeys(patch, "repair patch", "schema_version", "repairs"); err != nil {
		return repairPatch{}, err
	}
	assetID, err := ports.ParseAssetID(repairPatchSchemaID)
	if err != nil {
		return repairPatch{}, fmt.Errorf("review repair: repair patch schema ID: %w", err)
	}
	if err := validator.schemaValidator.Validate(ctx, assetID, raw); err != nil {
		return repairPatch{}, fmt.Errorf("review repair: repair patch schema: %w", err)
	}
	version, ok := patch["schema_version"].(string)
	if !ok || version != "kar-repair-patch.v1" {
		return repairPatch{}, fmt.Errorf("review repair: repair patch has invalid schema_version")
	}
	repairsValue, ok := patch["repairs"].([]any)
	if !ok || len(repairsValue) == 0 || len(repairsValue) > maxRepairOperations {
		return repairPatch{}, fmt.Errorf(
			"review repair: repair patch repairs must contain 1 through %d operations",
			maxRepairOperations,
		)
	}
	result := repairPatch{repairs: make([]repairOperation, 0, len(repairsValue))}
	seen := make(map[string]struct{}, len(repairsValue))
	for index, value := range repairsValue {
		operation, ok := value.(map[string]any)
		if !ok {
			return repairPatch{}, fmt.Errorf("review repair: repairs[%d] must be an object", index)
		}
		if err := requireOnlyKeys(operation, fmt.Sprintf("repair patch.repairs[%d]", index), "path", "value"); err != nil {
			return repairPatch{}, err
		}
		path, ok := operation["path"].(string)
		if !ok {
			return repairPatch{}, fmt.Errorf("review repair: repairs[%d].path must be a string", index)
		}
		if _, err := parseJSONPointer(path); err != nil {
			return repairPatch{}, fmt.Errorf("review repair: repairs[%d].path: %w", index, err)
		}
		if _, duplicate := seen[path]; duplicate {
			return repairPatch{}, fmt.Errorf("review repair: duplicate path %q", path)
		}
		seen[path] = struct{}{}
		value, exists := operation["value"]
		if !exists {
			return repairPatch{}, fmt.Errorf("review repair: repairs[%d].value is required", index)
		}
		result.repairs = append(result.repairs, repairOperation{path: path, value: value})
	}
	return result, nil
}

func setRepairValue(document map[string]any, pointer string, replacement any, allowMeaningfulEvidenceQuote bool) error {
	parts, err := parseJSONPointer(pointer)
	if err != nil {
		return err
	}
	if len(parts) == 0 {
		return fmt.Errorf("root replacement is forbidden")
	}
	var current any = document
	for _, part := range parts[:len(parts)-1] {
		switch container := current.(type) {
		case map[string]any:
			next, exists := container[part]
			if !exists {
				return fmt.Errorf("parent path does not exist")
			}
			current = next
		case []any:
			index, err := parseArrayIndex(part, len(container))
			if err != nil {
				return err
			}
			current = container[index]
		default:
			return fmt.Errorf("parent path is not an object or array")
		}
	}
	last := parts[len(parts)-1]
	cloned, err := cloneJSONValue(replacement)
	if err != nil {
		return err
	}
	switch container := current.(type) {
	case map[string]any:
		if currentValue, exists := container[last]; exists && meaningfulRepairTarget(pointer, currentValue) && !allowMeaningfulEvidenceQuote {
			return fmt.Errorf("would overwrite a meaningful value")
		}
		container[last] = cloned
		return nil
	case []any:
		index, err := parseArrayIndex(last, len(container))
		if err != nil {
			return err
		}
		if meaningfulRepairTarget(pointer, container[index]) {
			return fmt.Errorf("would overwrite a meaningful value")
		}
		container[index] = cloned
		return nil
	default:
		return fmt.Errorf("target parent is not an object or array")
	}
}

func parseJSONPointer(pointer string) ([]string, error) {
	if pointer == "" || !strings.HasPrefix(pointer, "/") {
		return nil, fmt.Errorf("must be a non-root JSON Pointer")
	}
	encoded := strings.Split(pointer[1:], "/")
	parts := make([]string, len(encoded))
	for index, value := range encoded {
		decoded, err := unescapeJSONPointerToken(value)
		if err != nil {
			return nil, err
		}
		if decoded == "" {
			return nil, fmt.Errorf("empty JSON Pointer token")
		}
		parts[index] = decoded
	}
	return parts, nil
}

func unescapeJSONPointerToken(value string) (string, error) {
	var result strings.Builder
	for index := 0; index < len(value); index++ {
		if value[index] != '~' {
			result.WriteByte(value[index])
			continue
		}
		if index+1 >= len(value) {
			return "", fmt.Errorf("invalid JSON Pointer escape")
		}
		index++
		switch value[index] {
		case '0':
			result.WriteByte('~')
		case '1':
			result.WriteByte('/')
		default:
			return "", fmt.Errorf("invalid JSON Pointer escape")
		}
	}
	return result.String(), nil
}

func parseArrayIndex(value string, length int) (int, error) {
	if length <= 0 {
		return 0, fmt.Errorf("array index %q is out of range", value)
	}
	if value == "0" {
		return 0, nil
	}
	if value == "" || value[0] < '1' || value[0] > '9' {
		return 0, fmt.Errorf("invalid array index %q", value)
	}

	index := 0
	for _, character := range value {
		if character < '0' || character > '9' {
			return 0, fmt.Errorf("invalid array index %q", value)
		}
		digit := int(character - '0')
		maximum := length - 1
		if index > maximum/10 || (index == maximum/10 && digit > maximum%10) {
			return 0, fmt.Errorf("array index %q is out of range", value)
		}
		index = index*10 + digit
	}
	return index, nil
}

func cloneJSONValue(value any) (any, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("clone repair value: %w", err)
	}
	var result any
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.UseNumber()
	if err := decoder.Decode(&result); err != nil {
		return nil, fmt.Errorf("clone repair value: %w", err)
	}
	return result, nil
}

func meaningfulJSONValue(value any) bool {
	switch value := value.(type) {
	case nil:
		return false
	case string:
		return meaningfulText(value)
	case []any:
		return len(value) > 0
	case map[string]any:
		return len(value) > 0
	default:
		return true
	}
}
func meaningfulRepairTarget(pointer string, value any) bool {
	parts, err := parseJSONPointer(pointer)
	if err != nil || len(parts) == 0 {
		return true
	}
	if len(parts) == 2 && parts[0] == "limitations" {
		text, ok := value.(string)
		return ok && meaningfulText(text)
	}
	switch parts[len(parts)-1] {
	case "summary", "title", "description", "recommendation", "quote", "path":
		text, ok := value.(string)
		return ok && meaningfulText(text)
	case "schema_version":
		text, ok := value.(string)
		return ok && text == "kar-provider-review-output.v3"
	case "completeness":
		text, ok := value.(string)
		return ok && (text == "complete" || text == "incomplete")
	case "severity":
		text, ok := value.(string)
		return ok && domain.Severity(text).Valid()
	case "confidence":
		text, ok := value.(string)
		return ok && domain.Confidence(text).Valid()
	case "side":
		text, ok := value.(string)
		return ok && (text == "base" || text == "head" || text == "worktree")
	case "line_start", "line_end":
		number, ok := value.(json.Number)
		if !ok || strings.ContainsAny(number.String(), ".eE") {
			return false
		}
		line, err := strconv.ParseInt(number.String(), 10, 0)
		return err == nil && line > 0
	case "limitations", "evidence":
		array, ok := value.([]any)
		return ok && len(array) > 0
	case "current":
		object, ok := value.(map[string]any)
		return ok && len(object) > 0
	default:
		return meaningfulJSONValue(value)
	}
}

func findingCount(document map[string]any) (int, error) {
	findings, ok := document["findings"].([]any)
	if !ok {
		return 0, fmt.Errorf("review repair: original findings must be an array")
	}
	return len(findings), nil
}

func findingSeverities(document map[string]any) ([]domain.Severity, error) {
	findings, ok := document["findings"].([]any)
	if !ok {
		return nil, fmt.Errorf("review repair: original findings must be an array")
	}
	result := make([]domain.Severity, len(findings))
	for index, value := range findings {
		finding, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("review repair: original finding %d must be an object", index)
		}
		severity, ok := finding["severity"].(string)
		if !ok {
			continue
		}
		parsed := domain.Severity(severity)
		if parsed.Valid() {
			result[index] = parsed
		}
	}
	return result, nil
}

func rejectSeverityDowngrade(original []domain.Severity, repaired map[string]any) error {
	findings, ok := repaired["findings"].([]any)
	if !ok || len(findings) != len(original) {
		return fmt.Errorf("review repair: finding count changed")
	}
	for index, before := range original {
		if !before.Valid() {
			continue
		}
		finding, ok := findings[index].(map[string]any)
		if !ok {
			return fmt.Errorf("review repair: finding %d is not an object", index)
		}
		afterText, ok := finding["severity"].(string)
		if !ok {
			continue
		}
		after := domain.Severity(afterText)
		if after.Valid() && after.Rank() < before.Rank() {
			return fmt.Errorf("review repair: finding %d severity was downgraded", index)
		}
	}
	return nil
}
