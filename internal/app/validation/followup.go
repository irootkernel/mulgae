package validation

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/irootkernel/kkachi-agent-review/internal/domain"
	"github.com/irootkernel/kkachi-agent-review/internal/ports"
)

// ProviderFollowupSchemaID is the sole schema accepted for provider followup output.
const ProviderFollowupSchemaID = "https://kar.local/schemas/kar-provider-followup-output.v2.schema.json"

// FollowupValidationScope is the complete trusted lineage and execution identity
// injected into a provider followup result. Providers have no authority over it.
type FollowupValidationScope struct {
	SessionID           domain.SessionID
	SourceRunID         domain.RunID
	ReviewID            domain.ReviewID
	FindingID           string
	SourceTargetSHA256  string
	SourceExcerptSHA256 string
	CurrentTargetSHA256 string
	Role                domain.Role
	ProviderInstance    string
}

// ValidatedFollowup is the defensive, publication-ready normalized provider
// result. Raw is the exact provider output; NormalizedRaw is the schema-valid
// document after trusted lineage and current-target values are injected.
type ValidatedFollowup struct {
	resolution       domain.FollowupResolution
	role             domain.Role
	providerInstance string
	providerRaw      []byte
	normalizedRaw    []byte
	providerSHA256   string
}

func (result ValidatedFollowup) Resolution() domain.FollowupResolution { return result.resolution }
func (result ValidatedFollowup) Role() domain.Role                     { return result.role }
func (result ValidatedFollowup) ProviderInstance() string              { return result.providerInstance }
func (result ValidatedFollowup) ProviderRaw() []byte {
	return append([]byte(nil), result.providerRaw...)
}
func (result ValidatedFollowup) NormalizedRaw() []byte {
	return append([]byte(nil), result.normalizedRaw...)
}
func (result ValidatedFollowup) ProviderSHA256() string { return result.providerSHA256 }

// FollowupValidator validates the provider-owned subset of the followup
// contract. Unlike ReviewValidator, it deliberately accepts no source-bearing
// provider document: all lineage and target identities are injected from scope.
type FollowupValidator struct {
	schemaValidator SchemaValidator
	schemaID        ports.AssetID
}

func NewFollowupValidator(schemaValidator SchemaValidator, schemaID ports.AssetID) (*FollowupValidator, error) {
	if nilFollowupSchemaValidator(schemaValidator) {
		return nil, fmt.Errorf("followup validation: nil schema validator")
	}
	if !schemaID.Valid() || schemaID.String() != ProviderFollowupSchemaID {
		return nil, fmt.Errorf("followup validation: schema ID must be %q", ProviderFollowupSchemaID)
	}
	return &FollowupValidator{schemaValidator: schemaValidator, schemaID: schemaID}, nil
}

func (validator *FollowupValidator) Validate(ctx context.Context, raw []byte, scope FollowupValidationScope) (ValidatedFollowup, error) {
	if validator == nil {
		return ValidatedFollowup{}, fmt.Errorf("followup validation: nil validator")
	}
	if ctx == nil {
		return ValidatedFollowup{}, fmt.Errorf("followup validation: nil context")
	}
	if err := ctx.Err(); err != nil {
		return ValidatedFollowup{}, fmt.Errorf("followup validation: context: %w", err)
	}
	if nilFollowupSchemaValidator(validator.schemaValidator) || !validator.schemaID.Valid() || validator.schemaID.String() != ProviderFollowupSchemaID {
		return ValidatedFollowup{}, fmt.Errorf("followup validation: invalid validator configuration")
	}
	trusted, err := validateFollowupScope(scope)
	if err != nil {
		return ValidatedFollowup{}, err
	}
	provider, err := decodeFollowupJSONObject(raw)
	if err != nil {
		return ValidatedFollowup{}, err
	}
	if err := guardFollowupProvider(provider); err != nil {
		return ValidatedFollowup{}, err
	}
	candidate, err := injectFollowupTrust(provider, trusted)
	if err != nil {
		return ValidatedFollowup{}, err
	}
	normalized, err := json.Marshal(candidate)
	if err != nil {
		return ValidatedFollowup{}, fmt.Errorf("followup validation: marshal normalized output: %w", err)
	}
	if err := validator.schemaValidator.Validate(ctx, validator.schemaID, normalized); err != nil {
		return ValidatedFollowup{}, fmt.Errorf("followup validation: schema: %w", err)
	}
	if err := validateFollowupSemantics(candidate); err != nil {
		return ValidatedFollowup{}, err
	}
	resolution, _ := candidate["resolution"].(string)
	sum := sha256.Sum256(raw)
	return ValidatedFollowup{
		resolution: domain.FollowupResolution(resolution), role: scope.Role,
		providerInstance: scope.ProviderInstance, providerRaw: append([]byte(nil), raw...),
		normalizedRaw: append([]byte(nil), normalized...), providerSHA256: hex.EncodeToString(sum[:]),
	}, nil
}

type trustedFollowupScope struct {
	sessionID, runID, reviewID, findingID      string
	sourceTarget, sourceExcerpt, currentTarget string
}

func validateFollowupScope(scope FollowupValidationScope) (trustedFollowupScope, error) {
	if _, err := domain.ParseSessionID(scope.SessionID.String()); err != nil {
		return trustedFollowupScope{}, fmt.Errorf("followup validation: invalid trusted session ID")
	}
	if _, err := domain.ParseRunID(scope.SourceRunID.String()); err != nil {
		return trustedFollowupScope{}, fmt.Errorf("followup validation: invalid trusted source run ID")
	}
	if _, err := domain.ParseReviewID(scope.ReviewID.String()); err != nil {
		return trustedFollowupScope{}, fmt.Errorf("followup validation: invalid trusted review ID")
	}
	if !followupFindingID(scope.FindingID) {
		return trustedFollowupScope{}, fmt.Errorf("followup validation: invalid trusted finding ID")
	}
	if !scope.Role.Valid() {
		return trustedFollowupScope{}, fmt.Errorf("followup validation: invalid trusted role %q", scope.Role)
	}
	if strings.TrimSpace(scope.ProviderInstance) == "" || !utf8.ValidString(scope.ProviderInstance) {
		return trustedFollowupScope{}, fmt.Errorf("followup validation: trusted provider instance is required")
	}
	sourceTarget, err := canonicalFollowupSHA256(scope.SourceTargetSHA256)
	if err != nil {
		return trustedFollowupScope{}, fmt.Errorf("followup validation: invalid trusted source target SHA-256")
	}
	sourceExcerpt, err := canonicalFollowupSHA256(scope.SourceExcerptSHA256)
	if err != nil {
		return trustedFollowupScope{}, fmt.Errorf("followup validation: invalid trusted source excerpt SHA-256")
	}
	currentTarget, err := canonicalFollowupSHA256(scope.CurrentTargetSHA256)
	if err != nil {
		return trustedFollowupScope{}, fmt.Errorf("followup validation: invalid trusted current target SHA-256")
	}
	return trustedFollowupScope{scope.SessionID.String(), scope.SourceRunID.String(), scope.ReviewID.String(), scope.FindingID, sourceTarget, sourceExcerpt, currentTarget}, nil
}

func canonicalFollowupSHA256(value string) (string, error) {
	value = strings.TrimPrefix(value, "sha256:")
	if len(value) != sha256.Size*2 || strings.ToLower(value) != value {
		return "", fmt.Errorf("invalid SHA-256")
	}
	if _, err := hex.DecodeString(value); err != nil {
		return "", err
	}
	return "sha256:" + value, nil
}

func decodeFollowupJSONObject(raw []byte) (map[string]any, error) {
	if len(bytes.TrimSpace(raw)) == 0 || !utf8.Valid(raw) {
		return nil, fmt.Errorf("followup validation: provider output must be non-empty UTF-8 JSON")
	}
	if err := rejectUnpairedJSONSurrogates(raw); err != nil {
		return nil, fmt.Errorf("followup validation: provider output: %w", err)
	}
	if err := rejectDuplicateJSONKeys(raw); err != nil {
		return nil, fmt.Errorf("followup validation: provider output: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, fmt.Errorf("followup validation: provider output must be one JSON object: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("followup validation: provider output contains trailing content")
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("followup validation: provider output must be a JSON object")
	}
	return object, nil
}

func guardFollowupProvider(provider map[string]any) error {
	return guardFollowupObject(provider, map[string]struct{}{"schema_version": {}, "summary": {}, "resolution": {}, "rationale": {}, "evidence": {}, "new_findings": {}, "limitations": {}}, "output", false)
}

func guardFollowupObject(object map[string]any, allowed map[string]struct{}, path string, evidence bool) error {
	for key := range object {
		if _, ok := allowed[key]; !ok {
			return fmt.Errorf("followup validation: provider supplied forbidden or unknown field %s.%s", path, key)
		}
	}
	if evidence {
		if _, present := object["source"]; present {
			return fmt.Errorf("followup validation: provider supplied source identity at %s", path)
		}
		current, ok := object["current"].(map[string]any)
		if !ok {
			return nil
		}
		for _, key := range []string{"target_sha256", "verification", "session_id", "run_id", "review_id", "finding_id", "source_target_sha256", "source_excerpt_sha256"} {
			if _, present := current[key]; present {
				return fmt.Errorf("followup validation: provider supplied system identity at %s.current.%s", path, key)
			}
		}
		return guardFollowupObject(current, map[string]struct{}{"path": {}, "line_start": {}, "line_end": {}, "side": {}, "quote": {}}, path+".current", false)
	}
	for key, value := range object {
		if key == "evidence" {
			values, ok := value.([]any)
			if !ok {
				continue
			}
			for index, item := range values {
				if child, ok := item.(map[string]any); ok {
					if err := guardFollowupObject(child, map[string]struct{}{"current": {}}, fmt.Sprintf("%s.evidence[%d]", path, index), true); err != nil {
						return err
					}
				}
			}
		}
		if key == "new_findings" {
			values, ok := value.([]any)
			if !ok {
				continue
			}
			for index, item := range values {
				if child, ok := item.(map[string]any); ok {
					if err := guardFollowupObject(child, map[string]struct{}{"severity": {}, "title": {}, "description": {}, "evidence": {}, "recommendation": {}, "confidence": {}}, fmt.Sprintf("%s.new_findings[%d]", path, index), false); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

func injectFollowupTrust(provider map[string]any, trusted trustedFollowupScope) (map[string]any, error) {
	raw, err := json.Marshal(provider)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var candidate map[string]any
	if err := decoder.Decode(&candidate); err != nil {
		return nil, err
	}
	inject := func(value any) error {
		evidence, ok := value.([]any)
		if !ok {
			return nil
		}
		for _, item := range evidence {
			entry, ok := item.(map[string]any)
			if !ok {
				continue
			}
			current, ok := entry["current"].(map[string]any)
			if !ok {
				continue
			}
			entry["source"] = map[string]any{"session_id": trusted.sessionID, "run_id": trusted.runID, "review_id": trusted.reviewID, "finding_id": trusted.findingID, "source_target_sha256": trusted.sourceTarget, "source_excerpt_sha256": trusted.sourceExcerpt}
			current["target_sha256"] = trusted.currentTarget
			current["verification"] = "claimed"
		}
		return nil
	}
	if err := inject(candidate["evidence"]); err != nil {
		return nil, err
	}
	if findings, ok := candidate["new_findings"].([]any); ok {
		for _, item := range findings {
			if finding, ok := item.(map[string]any); ok {
				if err := inject(finding["evidence"]); err != nil {
					return nil, err
				}
			}
		}
	}
	return candidate, nil
}

func validateFollowupSemantics(candidate map[string]any) error {
	resolution, ok := candidate["resolution"].(string)
	if !ok || !domain.FollowupResolution(resolution).Valid() {
		return fmt.Errorf("followup validation: invalid resolution")
	}
	for _, field := range []string{"summary", "rationale"} {
		if err := requireMeaningfulFollowupText(candidate[field], field); err != nil {
			return err
		}
	}
	if resolution == string(domain.FollowupResolved) && contradictsResolvedFollowup(candidate["rationale"].(string)) {
		return fmt.Errorf("followup validation: resolved rationale contradicts resolution")
	}
	check := func(value any) error {
		evidence, ok := value.([]any)
		if !ok {
			return nil
		}
		for _, item := range evidence {
			entry, ok := item.(map[string]any)
			if !ok {
				continue
			}
			current, ok := entry["current"].(map[string]any)
			if !ok {
				continue
			}
			if err := requireMeaningfulFollowupText(current["quote"], "current evidence quote"); err != nil {
				return err
			}
			start, startOK := current["line_start"].(json.Number)
			end, endOK := current["line_end"].(json.Number)
			if !startOK || !endOK {
				continue
			}
			s, se := start.Int64()
			e, ee := end.Int64()
			if se != nil || ee != nil || s < 1 || e < s {
				return fmt.Errorf("followup validation: current evidence has invalid line range")
			}
		}
		return nil
	}
	if err := check(candidate["evidence"]); err != nil {
		return err
	}
	if findings, ok := candidate["new_findings"].([]any); ok {
		for index, item := range findings {
			if finding, ok := item.(map[string]any); ok {
				for _, field := range []string{"title", "description", "recommendation"} {
					if err := requireMeaningfulFollowupText(finding[field], fmt.Sprintf("new_findings[%d].%s", index, field)); err != nil {
						return err
					}
				}
				if err := check(finding["evidence"]); err != nil {
					return err
				}
			}
		}
	}
	if limitations, ok := candidate["limitations"].([]any); ok {
		for index, limitation := range limitations {
			if err := requireMeaningfulFollowupText(limitation, fmt.Sprintf("limitations[%d]", index)); err != nil {
				return err
			}
		}
	}
	return nil
}

func requireMeaningfulFollowupText(value any, path string) error {
	text, ok := value.(string)
	if !ok || !meaningfulText(text) {
		return fmt.Errorf("followup validation: %s must be meaningful", path)
	}
	return nil
}

func contradictsResolvedFollowup(rationale string) bool {
	normalized := normalizeFollowupRationale(rationale)
	for _, phrase := range []string{
		"issue remains",
		"issue is still present",
		"issue still exists",
		"still open",
		"not resolved",
		"still unresolved",
		"remains unresolved",
	} {
		if strings.Contains(" "+normalized+" ", " "+phrase+" ") {
			return true
		}
	}
	return false
}

func normalizeFollowupRationale(value string) string {
	return strings.Join(strings.FieldsFunc(strings.ToLower(value), func(character rune) bool {
		return !unicode.IsLetter(character) && !unicode.IsDigit(character)
	}), " ")
}

func followupFindingID(value string) bool {
	if len(value) == 0 || len(value) > 64 || value[0] < 'A' || value[0] > 'Z' {
		return false
	}
	for _, character := range value[1:] {
		if (character < 'A' || character > 'Z') &&
			(character < '0' || character > '9') &&
			character != '_' && character != '-' {
			return false
		}
	}
	return true
}
func nilFollowupSchemaValidator(value SchemaValidator) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
