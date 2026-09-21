package config

import "testing"

func TestGrokPolicyGrammarPreservesExactSpelling(t *testing.T) {
	for _, value := range []string{"grok-4.5", "Vendor/Model_Name-1", "a"} {
		if !ValidGrokModel(value) {
			t.Errorf("model %q was rejected", value)
		}
	}
	for _, value := range []string{"high", "high-precision", "Effort_1.0"} {
		if !ValidGrokReasoningEffort(value) {
			t.Errorf("reasoning effort %q was rejected", value)
		}
	}
	for _, value := range []string{"", "/absolute", "a//b", "a/../b", " spaced", "a\tb", "a:b"} {
		if ValidGrokModel(value) {
			t.Errorf("invalid model %q was accepted", value)
		}
	}
	for _, value := range []string{"", "high/precision", " high", "high\n", "high:precision"} {
		if ValidGrokReasoningEffort(value) {
			t.Errorf("invalid reasoning effort %q was accepted", value)
		}
	}
}
