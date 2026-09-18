package providercli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
)

var (
	errZCodeLegacyProviderAmbiguous   = errors.New("ambiguous ZCode legacy provider config")
	errZCodeLegacySelectedInvalid     = errors.New("invalid selected ZCode legacy provider config")
	errZCodeLegacySelectedUnsupported = errors.New("unsupported selected ZCode legacy provider config")
)

type zcodeLegacyConfig struct {
	Provider orderedZCodeLegacyProviders `json:"provider"`
	Model    json.RawMessage             `json:"model"`
}

type orderedZCodeLegacyProviders []zcodeLegacyProviderEntry

type zcodeLegacyProviderEntry struct {
	ID  string
	Raw json.RawMessage
}

type zcodeLegacyProvider struct {
	Kind         string
	Name         string
	HasSource    bool
	SourceCustom bool
	Options      zcodeLegacyProviderOptions
	Headers      map[string]string
	Models       orderedZCodeLegacyModels
	HasNPM       bool
}

type zcodeLegacyProviderOptions struct {
	APIKey         string            `json:"apiKey"`
	BaseURL        string            `json:"baseURL"`
	APIKeyRequired *bool             `json:"apiKeyRequired"`
	Headers        map[string]string `json:"headers"`
}

type zcodeLegacyModel struct {
	ID               string
	Deleted          bool
	ContextWindow    int64
	HasContextWindow bool
	LimitContext     int64
	HasLimitContext  bool
}

type orderedZCodeLegacyModels []zcodeLegacyModelEntry

type zcodeLegacyModelEntry struct {
	ID    string
	Model zcodeLegacyModel
}

type zcodePersonalProviderConfig struct {
	SchemaVersion int                        `json:"schemaVersion"`
	Config        zcodePersonalProviderRules `json:"config"`
}

type zcodePersonalProviderRules struct {
	ProviderConfigRules   zcodeProviderConfigRules `json:"providerConfigRules"`
	ModelConfigRules      zcodeModelConfigRules    `json:"modelConfigRules"`
	DefaultModelSelection *zcodeModelSelection     `json:"defaultModelSelection,omitempty"`
}

type zcodeProviderConfigRules struct {
	ProviderRules []zcodeProviderRule `json:"providerRules"`
}

type zcodeProviderRule struct {
	ProviderID   string              `json:"providerId"`
	TemplateID   string              `json:"templateId,omitempty"`
	ProviderName string              `json:"providerName,omitempty"`
	Config       zcodeProviderConfig `json:"config"`
}

type zcodeProviderConfig struct {
	Group            string      `json:"group"`
	Access           zcodeAccess `json:"access"`
	API              *zcodeAPI   `json:"api,omitempty"`
	PersonalModelIDs []string    `json:"personalModelIds,omitempty"`
	ModelOrder       []string    `json:"modelOrder,omitempty"`
}

type zcodeAccess struct {
	Type   string `json:"type"`
	APIKey string `json:"apiKey,omitempty"`
}

type zcodeAPI struct {
	Type    string            `json:"type"`
	BaseURL string            `json:"baseUrl,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
}

type zcodeModelConfigRules struct {
	ProviderModelRules       []zcodeProviderModelRule `json:"providerModelRules"`
	ManualProviderModelRules []zcodeProviderModelRule `json:"manualProviderModelRules"`
}

type zcodeProviderModelRule struct {
	ModelID    string               `json:"modelId"`
	Config     zcodeModelRuleConfig `json:"config"`
	ProviderID string               `json:"providerId"`
}

type zcodeModelRuleConfig struct {
	Properties zcodeModelProperties `json:"properties"`
}

type zcodeModelProperties struct {
	ContextWindow int64 `json:"contextWindow"`
}

type zcodeModelSelection struct {
	ProviderID string `json:"providerId"`
	ModelID    string `json:"modelId"`
}

// materializeZCodePersonalProviderConfig mirrors ZCode's legacy CLI import for
// custom personal providers. app-server does not run that import itself, so
// Mulgae performs it while projecting the descriptor-anchored legacy config
// into the invocation's disposable HOME.
func materializeZCodePersonalProviderConfig(source []byte) ([]byte, error) {
	encoded, _, err := materializeZCodePersonalProviderConfigWithSelection(source)
	return encoded, err
}

func materializeZCodePersonalProviderConfigWithSelection(source []byte) ([]byte, *zcodeModelSelection, error) {
	legacy, err := decodeZCodeLegacyConfig(source)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid ZCode legacy config")
	}
	selection, err := zcodeLegacyDefaultModel(legacy.Model)
	if err != nil {
		return nil, nil, err
	}

	result := zcodePersonalProviderConfig{SchemaVersion: 1}
	result.Config.ProviderConfigRules.ProviderRules = make([]zcodeProviderRule, 0, len(legacy.Provider))
	result.Config.ModelConfigRules.ProviderModelRules = make([]zcodeProviderModelRule, 0)
	result.Config.ModelConfigRules.ManualProviderModelRules = make([]zcodeProviderModelRule, 0)
	emittedOrigins := make(map[string]string, len(legacy.Provider))
	emittedModels := make(map[string]map[string]struct{}, len(legacy.Provider))
	emittedRuleIndexes := make(map[string]int, len(legacy.Provider))
	emittedCollisions := make(map[string]bool)
	for _, entry := range legacy.Provider {
		providerID := strings.TrimSpace(entry.ID)
		if providerID == "" {
			continue
		}
		provider, decodeErr := decodeZCodeLegacyProvider(entry.Raw)
		if decodeErr != nil {
			if selection != nil && selection.ProviderID == providerID {
				return nil, nil, errZCodeLegacySelectedInvalid
			}
			continue
		}
		emittedID := providerID
		if mappedID, builtin := zcodeLegacyBuiltinProviderID(providerID); builtin {
			emittedID = mappedID
		}
		if emittedID != providerID {
			apiKey := strings.TrimSpace(provider.Options.APIKey)
			if apiKey == "" {
				if selection != nil && selection.ProviderID == providerID {
					return nil, nil, errZCodeLegacySelectedInvalid
				}
				continue
			}
			if _, duplicate := emittedOrigins[emittedID]; duplicate {
				emittedCollisions[emittedID] = true
			}
			emittedOrigins[emittedID] = providerID
			rule := zcodeProviderRule{
				ProviderID: emittedID, TemplateID: emittedID,
				Config: zcodeProviderConfig{
					Group:  "standard-personal",
					Access: zcodeAccess{Type: "api-key", APIKey: apiKey},
				},
			}
			upsertZCodeProviderRule(&result.Config.ProviderConfigRules.ProviderRules, emittedRuleIndexes, emittedID, rule)
			emittedModels[emittedID] = nil
			result.Config.ModelConfigRules.ProviderModelRules = removeZCodeProviderModelRules(result.Config.ModelConfigRules.ProviderModelRules, emittedID)
			continue
		}
		if strings.HasPrefix(providerID, "builtin:") || strings.HasPrefix(providerID, "account:") || provider.HasSource && !provider.SourceCustom {
			if selection != nil && selection.ProviderID == providerID {
				return nil, nil, errZCodeLegacySelectedUnsupported
			}
			continue
		}
		apiType, supportedKind := zcodeLegacyAPIType(provider.Kind)
		if provider.HasNPM || !supportedKind {
			if selection != nil && selection.ProviderID == providerID {
				return nil, nil, errZCodeLegacySelectedUnsupported
			}
			continue
		}
		if provider.Options.APIKeyRequired != nil && !*provider.Options.APIKeyRequired {
			if selection != nil && selection.ProviderID == providerID {
				return nil, nil, errZCodeLegacySelectedUnsupported
			}
			continue
		}
		apiKey := strings.TrimSpace(provider.Options.APIKey)
		if apiKey == "" {
			if selection != nil && selection.ProviderID == providerID {
				return nil, nil, errZCodeLegacySelectedInvalid
			}
			continue
		}
		if _, duplicate := emittedOrigins[emittedID]; duplicate {
			emittedCollisions[emittedID] = true
		}
		emittedOrigins[emittedID] = providerID
		modelIDs, modelRules := zcodeLegacyModels(providerID, provider.Models)
		if selection != nil && selection.ProviderID == providerID {
			present, deleted := zcodeLegacyModelState(selection.ModelID, provider.Models)
			if deleted {
				return nil, nil, errZCodeLegacySelectedInvalid
			}
			// ZCode permits an explicitly selected personal-provider model that
			// is not repeated in the optional provider model catalog. Preserve
			// that selection in the projected catalog so app-server can admit it.
			if !present {
				modelIDs = append(modelIDs, selection.ModelID)
			}
		}
		modelSet := make(map[string]struct{}, len(modelIDs))
		for _, modelID := range modelIDs {
			modelSet[modelID] = struct{}{}
		}
		emittedModels[emittedID] = modelSet
		name := strings.TrimSpace(provider.Name)
		if name == providerID {
			name = ""
		}
		rule := zcodeProviderRule{
			ProviderID: providerID, ProviderName: name,
			Config: zcodeProviderConfig{
				Group:            "standard-personal",
				Access:           zcodeAccess{Type: "api-key", APIKey: apiKey},
				API:              &zcodeAPI{Type: apiType, BaseURL: provider.Options.BaseURL, Headers: mergeZCodeHeaders(provider.Headers, provider.Options.Headers)},
				PersonalModelIDs: modelIDs, ModelOrder: modelIDs,
			},
		}
		upsertZCodeProviderRule(&result.Config.ProviderConfigRules.ProviderRules, emittedRuleIndexes, emittedID, rule)
		result.Config.ModelConfigRules.ProviderModelRules = removeZCodeProviderModelRules(result.Config.ModelConfigRules.ProviderModelRules, emittedID)
		result.Config.ModelConfigRules.ProviderModelRules = append(result.Config.ModelConfigRules.ProviderModelRules, modelRules...)
	}
	if selection != nil {
		selectedOrigin := selection.ProviderID
		if selectedOrigin == "builtin:zapi" || strings.HasPrefix(selectedOrigin, "account:") {
			return nil, nil, errZCodeLegacySelectedUnsupported
		}
		mappedID, builtin := zcodeLegacyBuiltinProviderID(selectedOrigin)
		if strings.HasPrefix(selectedOrigin, "builtin:") && !builtin {
			return nil, nil, errZCodeLegacySelectedUnsupported
		}
		if builtin {
			selection.ProviderID = mappedID
		}
		if emittedCollisions[selection.ProviderID] {
			return nil, nil, errZCodeLegacyProviderAmbiguous
		}
		if origin, ok := emittedOrigins[selection.ProviderID]; !ok || origin != selectedOrigin {
			return nil, nil, errZCodeLegacySelectedInvalid
		}
		if !builtin {
			if _, ok := emittedModels[selection.ProviderID][selection.ModelID]; !ok {
				return nil, nil, errZCodeLegacySelectedInvalid
			}
		}
	}
	result.Config.DefaultModelSelection = selection
	encoded, err := json.Marshal(result)
	if err != nil || int64(len(encoded)) > maxProjectedCredentialBytes {
		return nil, nil, fmt.Errorf("invalid ZCode personal provider config")
	}
	return encoded, cloneZCodeModelSelection(selection), nil
}

func upsertZCodeProviderRule(rules *[]zcodeProviderRule, indexes map[string]int, providerID string, rule zcodeProviderRule) {
	if index, ok := indexes[providerID]; ok {
		(*rules)[index] = rule
		return
	}
	indexes[providerID] = len(*rules)
	*rules = append(*rules, rule)
}

func removeZCodeProviderModelRules(rules []zcodeProviderModelRule, providerID string) []zcodeProviderModelRule {
	kept := rules[:0]
	for _, rule := range rules {
		if rule.ProviderID != providerID {
			kept = append(kept, rule)
		}
	}
	return kept
}

func zcodeLegacyModelState(selected string, models orderedZCodeLegacyModels) (present, deleted bool) {
	foundDeleted := false
	for _, entry := range models {
		modelID := strings.TrimSpace(entry.Model.ID)
		if modelID == "" {
			modelID = strings.TrimSpace(entry.ID)
		}
		if modelID != selected {
			continue
		}
		if entry.Model.Deleted {
			foundDeleted = true
			continue
		}
		return true, false
	}
	return false, foundDeleted
}

func cloneZCodeModelSelection(selection *zcodeModelSelection) *zcodeModelSelection {
	if selection == nil {
		return nil
	}
	clone := *selection
	return &clone
}

func zcodeLegacyAPIType(kind string) (string, bool) {
	switch kind {
	case "anthropic":
		return "anthropic-messages", true
	case "openai":
		return "openai-responses", true
	case "openai-compatible":
		return "openai-chat-completions", true
	}
	return "", false
}

func zcodeLegacyModels(providerID string, models orderedZCodeLegacyModels) ([]string, []zcodeProviderModelRule) {
	seen := make(map[string]struct{}, len(models))
	modelIDs := make([]string, 0, len(models))
	rules := make([]zcodeProviderModelRule, 0, len(models))
	for _, entry := range models {
		model := entry.Model
		if model.Deleted {
			continue
		}
		modelID := strings.TrimSpace(model.ID)
		if modelID == "" {
			modelID = strings.TrimSpace(entry.ID)
		}
		if modelID == "" {
			continue
		}
		if _, duplicate := seen[modelID]; duplicate {
			continue
		}
		seen[modelID] = struct{}{}
		modelIDs = append(modelIDs, modelID)
		contextWindow := int64(0)
		if model.HasContextWindow {
			contextWindow = model.ContextWindow
		} else if model.HasLimitContext {
			contextWindow = model.LimitContext
		}
		if contextWindow > 0 {
			rules = append(rules, zcodeProviderModelRule{
				ProviderID: providerID, ModelID: modelID,
				Config: zcodeModelRuleConfig{Properties: zcodeModelProperties{ContextWindow: contextWindow}},
			})
		}
	}
	return modelIDs, rules
}

func zcodeLegacyBuiltinProviderID(providerID string) (string, bool) {
	switch providerID {
	case "builtin:zai":
		return "zai-api", true
	case "builtin:bigmodel":
		return "bigmodel-api", true
	default:
		return "", false
	}
}

func (providers *orderedZCodeLegacyProviders) UnmarshalJSON(data []byte) error {
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return nil
	}
	entries, err := decodeOrderedJSONObject(data)
	if err != nil {
		return err
	}
	*providers = make([]zcodeLegacyProviderEntry, 0, len(entries))
	for _, entry := range entries {
		*providers = append(*providers, zcodeLegacyProviderEntry{ID: entry.key, Raw: entry.value})
	}
	return nil
}

func (models *orderedZCodeLegacyModels) UnmarshalJSON(data []byte) error {
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return nil
	}
	entries, err := decodeOrderedJSONObject(data)
	if err != nil {
		return err
	}
	*models = make([]zcodeLegacyModelEntry, 0, len(entries))
	for _, entry := range entries {
		model, err := decodeZCodeLegacyModel(entry.value)
		if err != nil {
			return err
		}
		*models = append(*models, zcodeLegacyModelEntry{ID: entry.key, Model: model})
	}
	return nil
}

func decodeZCodeLegacyConfig(data []byte) (zcodeLegacyConfig, error) {
	entries, err := decodeOrderedJSONObject(data)
	if err != nil {
		return zcodeLegacyConfig{}, err
	}
	var config zcodeLegacyConfig
	for _, entry := range entries {
		switch entry.key {
		case "provider":
			if err := json.Unmarshal(entry.value, &config.Provider); err != nil {
				return zcodeLegacyConfig{}, err
			}
		case "model":
			config.Model = append(config.Model[:0], entry.value...)
		}
	}
	return config, nil
}

func decodeZCodeLegacyProvider(data []byte) (zcodeLegacyProvider, error) {
	entries, err := decodeOrderedJSONObject(data)
	if err != nil {
		return zcodeLegacyProvider{}, err
	}
	var provider zcodeLegacyProvider
	for _, entry := range entries {
		switch entry.key {
		case "kind":
			err = json.Unmarshal(entry.value, &provider.Kind)
		case "name":
			err = json.Unmarshal(entry.value, &provider.Name)
		case "source":
			provider.HasSource = true
			var source string
			provider.SourceCustom = json.Unmarshal(entry.value, &source) == nil && source == "custom"
			err = nil
		case "options":
			provider.Options, err = decodeZCodeLegacyOptions(entry.value)
		case "headers":
			err = json.Unmarshal(entry.value, &provider.Headers)
		case "models":
			err = json.Unmarshal(entry.value, &provider.Models)
		case "npm":
			provider.HasNPM = true
		}
		if err != nil {
			return zcodeLegacyProvider{}, err
		}
	}
	return provider, nil
}

func decodeZCodeLegacyOptions(data []byte) (zcodeLegacyProviderOptions, error) {
	entries, err := decodeOrderedJSONObject(data)
	if err != nil {
		return zcodeLegacyProviderOptions{}, err
	}
	var options zcodeLegacyProviderOptions
	for _, entry := range entries {
		switch entry.key {
		case "apiKey":
			err = json.Unmarshal(entry.value, &options.APIKey)
		case "baseURL":
			err = json.Unmarshal(entry.value, &options.BaseURL)
		case "apiKeyRequired":
			err = json.Unmarshal(entry.value, &options.APIKeyRequired)
		case "headers":
			err = json.Unmarshal(entry.value, &options.Headers)
		}
		if err != nil {
			return zcodeLegacyProviderOptions{}, err
		}
	}
	return options, nil
}

func decodeZCodeLegacyModel(data []byte) (zcodeLegacyModel, error) {
	entries, err := decodeOrderedJSONObject(data)
	if err != nil {
		return zcodeLegacyModel{}, err
	}
	var model zcodeLegacyModel
	for _, entry := range entries {
		switch entry.key {
		case "id":
			err = json.Unmarshal(entry.value, &model.ID)
		case "deleted":
			model.Deleted = bytes.Equal(bytes.TrimSpace(entry.value), []byte("true"))
		case "contextWindow":
			model.ContextWindow, model.HasContextWindow, err = decodeZCodeLegacyContext(entry.value)
		case "limit":
			model.LimitContext, model.HasLimitContext, err = decodeZCodeLegacyLimit(entry.value)
		}
		if err != nil {
			return zcodeLegacyModel{}, err
		}
	}
	return model, nil
}

func decodeZCodeLegacyLimit(data []byte) (int64, bool, error) {
	entries, err := decodeOrderedJSONObject(data)
	if err != nil {
		return 0, false, err
	}
	for _, entry := range entries {
		if entry.key == "context" {
			return decodeZCodeLegacyContext(entry.value)
		}
	}
	return 0, false, nil
}

func decodeZCodeLegacyContext(data []byte) (int64, bool, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var number json.Number
	if err := decoder.Decode(&number); err != nil {
		return 0, false, err
	}
	if err := requireJSONEOF(decoder); err != nil {
		return 0, false, err
	}
	value, err := number.Float64()
	if err != nil || math.IsInf(value, 0) || math.IsNaN(value) || value <= 0 {
		return 0, false, fmt.Errorf("invalid positive context window")
	}
	if math.Trunc(value) != value {
		return 0, true, nil
	}
	if value > math.MaxInt64 {
		return 0, false, fmt.Errorf("context window exceeds integer range")
	}
	return int64(value), true, nil
}

type orderedJSONEntry struct {
	key   string
	value json.RawMessage
}

func decodeOrderedJSONObject(data []byte) ([]orderedJSONEntry, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	delimiter, ok := token.(json.Delim)
	if !ok || delimiter != '{' {
		return nil, fmt.Errorf("expected object")
	}
	entries := make([]orderedJSONEntry, 0)
	positions := make(map[string]int)
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		key, ok := keyToken.(string)
		if !ok {
			return nil, fmt.Errorf("invalid object key")
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, err
		}
		if position, duplicate := positions[key]; duplicate {
			entries[position].value = value
			continue
		}
		positions[key] = len(entries)
		entries = append(entries, orderedJSONEntry{key: key, value: value})
	}
	if _, err := decoder.Token(); err != nil {
		return nil, err
	}
	if err := requireJSONEOF(decoder); err != nil {
		return nil, err
	}
	sort.SliceStable(entries, func(left, right int) bool {
		leftIndex, leftIsIndex := ecmaScriptArrayIndex(entries[left].key)
		rightIndex, rightIsIndex := ecmaScriptArrayIndex(entries[right].key)
		switch {
		case leftIsIndex && rightIsIndex:
			return leftIndex < rightIndex
		case leftIsIndex:
			return true
		case rightIsIndex:
			return false
		default:
			return false
		}
	})
	return entries, nil
}

// ecmaScriptArrayIndex identifies the canonical decimal property names that
// JavaScript enumerates ahead of ordinary string keys. 2^32-1 is deliberately
// excluded by the ECMAScript array-index definition.
func ecmaScriptArrayIndex(key string) (uint64, bool) {
	if key == "" || len(key) > 1 && key[0] == '0' {
		return 0, false
	}
	value, err := strconv.ParseUint(key, 10, 32)
	if err != nil || value == math.MaxUint32 || strconv.FormatUint(value, 10) != key {
		return 0, false
	}
	return value, true
}

func requireJSONEOF(decoder *json.Decoder) error {
	if _, err := decoder.Token(); errors.Is(err, io.EOF) {
		return nil
	} else if err != nil {
		return err
	}
	return fmt.Errorf("invalid trailing JSON data")
}

func mergeZCodeHeaders(base, override map[string]string) map[string]string {
	if len(base) == 0 && len(override) == 0 {
		return nil
	}
	merged := make(map[string]string, len(base)+len(override))
	for key, value := range base {
		merged[key] = value
	}
	for key, value := range override {
		merged[key] = value
	}
	return merged
}

func zcodeLegacyDefaultModel(raw json.RawMessage) (*zcodeModelSelection, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var reference string
	if raw[0] == '"' {
		if err := json.Unmarshal(raw, &reference); err != nil {
			return nil, fmt.Errorf("invalid ZCode legacy default model")
		}
		if reference == "" {
			return nil, nil
		}
	} else {
		entries, err := decodeOrderedJSONObject(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid ZCode legacy default model")
		}
		for _, entry := range entries {
			if entry.key == "main" && json.Unmarshal(entry.value, &reference) != nil {
				return nil, fmt.Errorf("invalid ZCode legacy default model")
			}
		}
		if reference == "" {
			return nil, nil
		}
	}
	providerID, modelID, ok := strings.Cut(reference, "/")
	if !ok || strings.TrimSpace(providerID) == "" || strings.TrimSpace(modelID) == "" {
		return nil, fmt.Errorf("invalid ZCode legacy default model")
	}
	providerID, modelID = strings.TrimSpace(providerID), strings.TrimSpace(modelID)
	return &zcodeModelSelection{ProviderID: providerID, ModelID: modelID}, nil
}
