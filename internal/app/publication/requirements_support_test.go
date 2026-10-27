package publication_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/irootkernel/mulgae/internal/adapters/jsonschema"
	"github.com/irootkernel/mulgae/internal/app/publication"
	"github.com/irootkernel/mulgae/internal/app/validation"
	"github.com/irootkernel/mulgae/internal/builtin"
	"github.com/irootkernel/mulgae/internal/domain"
)

func TestRequirementsSupportBindsExactInputRowsAndContent(t *testing.T) {
	read := func(name string) []byte {
		t.Helper()
		raw, err := os.ReadFile("../../builtin/assets/examples/" + name + ".v1.valid.json")
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	inputRaw, supportRaw, contentRaw := read("requirements-input"), read("requirements-support"), read("requirement-content")
	input, err := validation.DecodeRequirementsInput(inputRaw, []domain.Role{domain.RoleLogic})
	if err != nil {
		t.Fatal(err)
	}
	validator, err := jsonschema.New(context.Background(), builtin.NewCatalog())
	if err != nil {
		t.Fatal(err)
	}
	evaluation, references, err := publication.DecodeRequirementsSupport(context.Background(), validator, supportRaw, inputRaw, input.Requirements(), true)
	if err != nil || evaluation.Availability() != domain.AssessmentNotRun || len(references) != 1 || !references[0].Matches(contentRaw) {
		t.Fatalf("paired support loses its input/content binding: %v", err)
	}
	mutatedContent := append([]byte(nil), contentRaw...)
	mutatedContent[len(mutatedContent)-2] ^= 1
	if references[0].Matches(mutatedContent) || references[0].Matches(append(contentRaw, ' ')) {
		t.Fatal("content tamper was accepted")
	}
	for name, mutate := range map[string]func(map[string]any){
		"selected count":  func(value map[string]any) { value["selected_count"] = 2 },
		"evaluated count": func(value map[string]any) { value["evaluated_count"] = 1 },
		"missing rows":    func(value map[string]any) { value["items"] = []any{} },
		"foreign ID":      func(value map[string]any) { value["items"].([]any)[0].(map[string]any)["requirement_id"] = "foreign" },
		"wrong owner":     func(value map[string]any) { value["items"].([]any)[0].(map[string]any)["owner_role"] = "security" },
		"wrong ordinal": func(value map[string]any) {
			value["items"].([]any)[0].(map[string]any)["content_path"] = "requirements/items/001.json"
		},
		"duplicate rows": func(value map[string]any) {
			value["items"] = append(value["items"].([]any), value["items"].([]any)[0])
			value["selected_count"] = 2
		},
		"input digest": func(value map[string]any) {
			value["input_sha256"] = value["items"].([]any)[0].(map[string]any)["content_sha256"]
		},
		"input length":     func(value map[string]any) { value["input_byte_length"] = 1 },
		"no-change reason": func(value map[string]any) { value["items"].([]any)[0].(map[string]any)["reason"] = "answer_omitted" },
	} {
		t.Run(name, func(t *testing.T) {
			var value map[string]any
			if err := json.Unmarshal(supportRaw, &value); err != nil {
				t.Fatal(err)
			}
			mutate(value)
			raw, _ := json.Marshal(value)
			if _, _, err := publication.DecodeRequirementsSupport(context.Background(), validator, raw, inputRaw, input.Requirements(), true); err == nil {
				t.Fatal("inconsistent support was accepted")
			}
		})
	}
	if _, _, err := publication.DecodeRequirementsSupport(context.Background(), validator, supportRaw, append(inputRaw, ' '), input.Requirements(), true); err == nil {
		t.Fatal("changed input bytes retained their old digest")
	}
	if _, _, err := publication.DecodeRequirementsSupport(context.Background(), validator, supportRaw, inputRaw, input.Requirements(), false); err == nil {
		t.Fatal("no-change placeholder was accepted for ordinary evaluation")
	}
	// The path is ordinal, so IDs that differ only by case cannot collide on disk.
	second, _ := domain.NewRequirement("rci-001", "other description", []string{"criterion"}, domain.RoleLogic)
	items := append(input.Requirements(), second)
	var duplicate map[string]any
	if err := json.Unmarshal(supportRaw, &duplicate); err != nil {
		t.Fatal(err)
	}
	row := duplicate["items"].([]any)[0].(map[string]any)
	copyRow := make(map[string]any, len(row))
	for key, value := range row {
		copyRow[key] = value
	}
	copyRow["requirement_id"] = second.ID()
	duplicate["items"], duplicate["selected_count"] = []any{row, copyRow}, 2
	var inputDocument map[string]any
	if err := json.Unmarshal(inputRaw, &inputDocument); err != nil {
		t.Fatal(err)
	}
	inputDocument["requirements"] = append(inputDocument["requirements"].([]any), map[string]any{"id": second.ID(), "text": second.Text(), "acceptance_criteria": second.AcceptanceCriteria(), "owner_role": second.OwnerRole()})
	twoInputRaw, _ := json.Marshal(inputDocument)
	inputDigest := sha256.Sum256(twoInputRaw)
	duplicate["input_sha256"], duplicate["input_byte_length"] = "sha256:"+hex.EncodeToString(inputDigest[:]), len(twoInputRaw)
	raw, _ := json.Marshal(duplicate)
	if _, _, err := publication.DecodeRequirementsSupport(context.Background(), validator, raw, twoInputRaw, items, true); err == nil {
		t.Fatal("distinct IDs shared a content path")
	}
	copyRow["content_path"] = "requirements/items/001.json"
	raw, _ = json.Marshal(duplicate)
	if _, _, err := publication.DecodeRequirementsSupport(context.Background(), validator, raw, twoInputRaw, items, true); err != nil {
		t.Fatalf("distinct ordinal paths were rejected: %v", err)
	}
}
