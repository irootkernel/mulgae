package config

import "testing"

func TestValidZCodeModelRequiresQualifiedIndividualPlanSelection(t *testing.T) {
	for _, test := range []struct {
		value string
		want  bool
	}{
		{"account:zai-individual-coding-plan/GLM-5.3", true},
		{"account:zai-individual-coding-plan/GLM-5.3/variant", true},
		{"account:zai-individual-coding-plan/GLM-5.3/", false},
		{"GLM-5.3", false},
		{"zai/GLM-5.3", false},
		{"account:zai-individual-coding-plan/../GLM-5.3", false},
		{"account:zai-individual-coding-plan/GLM 5.3", false},
	} {
		if got := ValidZCodeModel(test.value); got != test.want {
			t.Fatalf("ValidZCodeModel(%q) = %t, want %t", test.value, got, test.want)
		}
	}
}

func TestValidZCodeReasoningEffortUsesOpaqueSafeToken(t *testing.T) {
	if !ValidZCodeReasoningEffort("high-precision") || ValidZCodeReasoningEffort("") || ValidZCodeReasoningEffort("high precision") {
		t.Fatal("unexpected ZCode reasoning effort grammar")
	}
}
