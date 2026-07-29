package clean

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
)

// CanonicalPlanBytes returns the RFC 8785-compatible JSON hash preimage. Clean
// plans contain only strings, integers, booleans, nulls, arrays, and objects;
// encoding/json's lexicographic object ordering is therefore RFC 8785 ordering
// for this schema after HTML escaping is disabled. No floats are admitted.
func CanonicalPlanBytes(plan CleanPlan) ([]byte, error) {
	if plan.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("clean: unsupported schema version %q", plan.SchemaVersion)
	}
	preimage := map[string]any{
		"schema_version":       plan.SchemaVersion,
		"now":                  plan.Now,
		"store_epoch":          plan.StoreEpoch,
		"input_policy_sha256":  plan.InputPolicySHA256,
		"policy":               plan.Policy.clone(),
		"retention_protection": plan.RetentionProtection,
		"run_decisions":        plan.RunDecisions,
		"delete_sets":          plan.DeleteSets,
		"ordered_actions":      plan.OrderedActions,
		"byte_accounting":      plan.ByteAccounting,
		"outcome_reasons":      plan.OutcomeReasons,
	}
	var encoded bytes.Buffer
	encoder := json.NewEncoder(&encoded)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(preimage); err != nil {
		return nil, err
	}
	raw := bytes.TrimSuffix(encoded.Bytes(), []byte{'\n'})
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	var output bytes.Buffer
	if err := appendCanonicalJSON(&output, value); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}
func appendCanonicalJSON(output *bytes.Buffer, value any) error {
	switch value := value.(type) {
	case nil:
		output.WriteString("null")
	case bool:
		output.WriteString(strconv.FormatBool(value))
	case string:
		output.WriteString(strconv.Quote(value))
	case json.Number:
		if _, err := strconv.ParseInt(string(value), 10, 64); err != nil {
			return fmt.Errorf("clean: non-integer JSON number %q", value)
		}
		output.WriteString(string(value))
	case []any:
		output.WriteByte('[')
		for index, item := range value {
			if index > 0 {
				output.WriteByte(',')
			}
			if err := appendCanonicalJSON(output, item); err != nil {
				return err
			}
		}
		output.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(value))
		for key := range value {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		output.WriteByte('{')
		for index, key := range keys {
			if index > 0 {
				output.WriteByte(',')
			}
			if err := appendCanonicalJSON(output, key); err != nil {
				return err
			}
			output.WriteByte(':')
			if err := appendCanonicalJSON(output, value[key]); err != nil {
				return err
			}
		}
		output.WriteByte('}')
	default:
		return fmt.Errorf("clean: unsupported canonical value %T", value)
	}
	return nil
}

// PlanHash returns the domain-separated digest over CanonicalPlanBytes.
func PlanHash(plan CleanPlan) (string, error) {
	bytes, err := CanonicalPlanBytes(plan)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	_, _ = h.Write([]byte("Mulgae-CLEAN-PLAN/1"))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write(bytes)
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}
