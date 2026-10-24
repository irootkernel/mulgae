package providercli

import (
	"testing"
)

// TestCapabilityEvidenceCandidatesFallbackCharacterization is a labeled
// characterization of the capability candidate fallback, not a DF-020 guard.
// Each case asserts only what is observable: the actual candidate count from
// capabilityEvidenceCandidates, each candidate's individual outcome, and the
// overall acceptance or rejection.
func TestCapabilityEvidenceCandidatesFallbackCharacterization(t *testing.T) {
	fixture := &currentProbeFixture{}
	validFence := "```json\n{\"root\":\"nonce\",\"link\":\"linked\",\"role\":\"logic\"}\n```"
	invalidFence := "```json\n{\"root\":\"wrong\",\"link\":\"linked\",\"role\":\"logic\"}\n```"

	// A fenced invalid object plus trailing narration never produces a second
	// candidate: controlledProbeJSON rejects the trailing text, so only the
	// raw-text candidate exists and its narrated binding admits.
	narrated := []byte(invalidFence + "\nReadiness confirmed with root=nonce link=linked role=logic after transport.")
	candidates, err := capabilityEvidenceCandidates(FamilyGrok, narrated)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 1 {
		t.Fatalf("candidates = %d, want 1 (controlledProbeJSON rejects trailing narration)", len(candidates))
	}
	if err := validateProbeEvidence(candidates[0], fixture); err != nil {
		t.Fatalf("raw-text candidate with valid narration rejected: %v", err)
	}
	if err := acceptCapabilityEvidence(FamilyGrok, narrated, fixture); err != nil {
		t.Fatalf("single raw-text candidate evidence rejected: %v", err)
	}

	// A valid fenced object produces two candidates; both are individually
	// valid and the evidence admits.
	fenced := []byte(validFence)
	candidates, err = capabilityEvidenceCandidates(FamilyGrok, fenced)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 2 {
		t.Fatalf("candidates = %d, want 2 (fenced JSON plus trimmed text)", len(candidates))
	}
	for index, candidate := range candidates {
		if err := validateProbeEvidence(candidate, fixture); err != nil {
			t.Fatalf("candidate %d individually invalid: %v", index, err)
		}
	}
	if err := acceptCapabilityEvidence(FamilyGrok, fenced, fixture); err != nil {
		t.Fatalf("valid fenced evidence rejected: %v", err)
	}

	// An invalid fenced object without narration leaves one invalid candidate.
	unbound := []byte(invalidFence + "\nunrelated narration without bindings")
	candidates, err = capabilityEvidenceCandidates(FamilyGrok, unbound)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 1 {
		t.Fatalf("candidates = %d, want 1", len(candidates))
	}
	if err := validateProbeEvidence(candidates[0], fixture); err == nil {
		t.Fatal("all-invalid candidate evidence accepted")
	}
	if err := acceptCapabilityEvidence(FamilyGrok, unbound, fixture); err == nil {
		t.Fatal("all-invalid candidate evidence accepted")
	}
}
