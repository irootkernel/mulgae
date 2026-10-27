package validation

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/domain"
)

func requirementInputExample(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile("../../builtin/assets/examples/requirements-input.v1.valid.json")
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestRequirementsInputOwnsExactUnboundedInvocationBytes(t *testing.T) {
	raw := requirementInputExample(t)
	input, err := DecodeRequirementsInput(raw, []domain.Role{domain.RoleLogic})
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	if input.SHA256() != "sha256:"+hex.EncodeToString(sum[:]) || !bytes.Equal(input.Bytes(), raw) {
		t.Fatal("exact input provenance was normalized")
	}
	raw[0] = ' '
	returned := input.Bytes()
	returned[0] = ' '
	items := input.Requirements()
	items[0] = domain.Requirement{}
	if input.Bytes()[0] != '{' || input.Requirements()[0].ID() != "RCI-001" {
		t.Fatal("caller mutated admitted input")
	}
	large := bytes.ReplaceAll(requirementInputExample(t), []byte("Preserve explicitly selected source sides."), bytes.Repeat([]byte("requirement prose "), 600000))
	if len(large) <= 8<<20 {
		t.Fatal("large fixture misses structured-envelope boundary")
	}
	if _, err := DecodeRequirementsInput(large, []domain.Role{domain.RoleLogic}); err != nil {
		t.Fatalf("requirement prose gained a byte ceiling: %v", err)
	}
}

func TestRequirementsInputRejectsUnsafeSyntaxAndOwnership(t *testing.T) {
	base := string(requirementInputExample(t))
	cases := map[string]string{
		"empty": "", "array": "[]", "trailing": base + "{}", "duplicate key": strings.Replace(base, `"schema_version":`, `"schema_version":"mulgae-requirements-input.v1","schema_version":`, 1),
		"unknown":       strings.Replace(base, `"requirements":`, `"unexpected":true,"requirements":`, 1),
		"unknown item":  strings.Replace(base, `"id":`, `"origin":"provider","id":`, 1),
		"bad version":   strings.Replace(base, RequirementsInputVersion, "v999", 1),
		"surrogate":     strings.Replace(base, "RCI-001", `\ud800`, 1),
		"invalid utf8":  strings.Replace(base, "RCI-001", string([]byte{0xff}), 1),
		"NUL":           strings.Replace(base, "Preserve explicitly", `Preserve\u0000 explicitly`, 1),
		"blank":         strings.Replace(base, "Preserve explicitly selected source sides.", "  ", 1),
		"null criteria": strings.Replace(base, `"acceptance_criteria": [`, `"acceptance_criteria": null, "bad": [`, 1),
		"bad id":        strings.Replace(base, "RCI-001", "1bad", 1),
		"wrong owner":   strings.Replace(base, `"logic"`, `"security"`, 1),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeRequirementsInput([]byte(raw), []domain.Role{domain.RoleLogic}); err == nil {
				t.Fatal("invalid input accepted")
			}
		})
	}
	var document map[string]any
	if err := json.Unmarshal([]byte(base), &document); err != nil {
		t.Fatal(err)
	}
	item := document["requirements"].([]any)[0]
	document["requirements"] = []any{item, item}
	raw, _ := json.Marshal(document)
	if _, err := DecodeRequirementsInput(raw, []domain.Role{domain.RoleLogic}); err == nil {
		t.Fatal("duplicate IDs accepted")
	}
}

func TestRequirementAssessmentAssignmentsRejectTheWholeForeignSection(t *testing.T) {
	logic, _ := domain.NewRequirement("logic", "description", []string{"criterion"}, domain.RoleLogic)
	security, _ := domain.NewRequirement("security", "description", []string{"criterion"}, domain.RoleSecurity)
	items := []domain.Requirement{logic, security}
	for _, answers := range [][]string{nil, {"logic"}} {
		if err := ValidateRequirementAssessmentAssignments(items, domain.RoleLogic, answers); err != nil {
			t.Fatalf("omitted or owned answers rejected: %v", err)
		}
	}
	for _, answers := range [][]string{{"foreign"}, {"security"}, {"logic", "logic"}, {"logic", "security"}} {
		if err := ValidateRequirementAssessmentAssignments(items, domain.RoleLogic, answers); err == nil {
			t.Fatal("foreign/duplicate/wrong-owner section accepted")
		}
	}
}
