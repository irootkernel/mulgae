package providercli

import (
	"fmt"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/domain"
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

func TestCapabilityEvidenceV4FixtureNarratedEchoAndBindingCharacterization(t *testing.T) {
	t.Parallel()
	nonce, err := SecureProbeNonceGenerator{}.NewProbeNonce()
	if err != nil {
		t.Fatal(err)
	}
	link, err := SecureProbeNonceGenerator{}.NewProbeNonce()
	if err != nil {
		t.Fatal(err)
	}
	if nonce == link {
		t.Fatal("generated identical nonces")
	}
	wrongNonce := "0" + nonce[1:]
	if strings.HasPrefix(nonce, "0") {
		wrongNonce = "1" + nonce[1:]
	}

	role := domain.RoleSecurity
	fixture, request, err := newProbeFixture(role, nonce, link)
	if err != nil {
		t.Fatal(err)
	}
	if request.PolicyIdentity() != "current-qualification-fixture-v4" {
		t.Fatalf("fixture policy = %q, want current-qualification-fixture-v4", request.PolicyIdentity())
	}

	exactJSON := fmt.Sprintf(`{"root":%q,"link":%q,"role":%q}`, nonce, link, role)
	validFence := "```json\n" + exactJSON + "\n```"
	invalidFence := fmt.Sprintf("```json\n{\"root\":%q,\"link\":%q,\"role\":%q}\n```", wrongNonce, link, role)

	// Narrated echo of the real v4 packet without independent valid binding
	// must be rejected as invalid output, even when paired with an invalid fence.
	for _, echoed := range []struct {
		name  string
		bytes []byte
	}{
		{"narrated v4 packet echo", []byte("I received:\n" + string(fixture.Packet()) + "\nUnable to proceed.")},
		{"invalid fence plus v4 packet echo", []byte(invalidFence + "\n" + string(fixture.Packet()))},
	} {
		for _, family := range []string{FamilyZcode, FamilyGrok} {
			candidates, candErr := capabilityEvidenceCandidates(family, echoed.bytes)
			if candErr != nil {
				t.Fatalf("%s/%s candidates error: %v", family, echoed.name, candErr)
			}
			if len(candidates) != 1 {
				t.Fatalf("%s/%s candidates = %d, want 1", family, echoed.name, len(candidates))
			}
			if valErr := validateProbeEvidence(candidates[0], fixture); valErr == nil {
				t.Fatalf("%s/%s candidate unexpectedly accepted", family, echoed.name)
			}
			err := acceptCapabilityEvidence(family, echoed.bytes, fixture)
			if err == nil {
				t.Fatalf("%s/%s unexpectedly accepted", family, echoed.name)
			}
			requireOperationalCapabilityMismatch(t, err)
		}
	}

	// Genuine narrated binding with real v4 nonces remains admitted for active families.
	for _, narrated := range [][]byte{
		[]byte(fmt.Sprintf("Readiness confirmed with root=%s link=%s role=%s after transport.", nonce, link, role)),
		[]byte(invalidFence + "\n" + fmt.Sprintf("Readiness confirmed with root=%s link=%s role=%s after transport.", nonce, link, role)),
	} {
		for _, family := range []string{FamilyZcode, FamilyGrok} {
			candidates, candErr := capabilityEvidenceCandidates(family, narrated)
			if candErr != nil {
				t.Fatalf("%s narrated candidates error: %v", family, candErr)
			}
			if len(candidates) != 1 {
				t.Fatalf("%s narrated candidates = %d, want 1", family, len(candidates))
			}
			if valErr := validateProbeEvidence(candidates[0], fixture); valErr != nil {
				t.Fatalf("%s narrated candidate rejected: %v", family, valErr)
			}
			if acceptErr := acceptCapabilityEvidence(family, narrated, fixture); acceptErr != nil {
				t.Fatalf("%s narrated evidence rejected: %v", family, acceptErr)
			}
		}
	}

	// Genuine exact and fenced JSON bindings with real v4 nonces remain admitted
	// across active families.
	for _, structured := range [][]byte{[]byte(exactJSON), []byte(validFence)} {
		for _, family := range []string{FamilyZcode, FamilyGrok} {
			candidates, candErr := capabilityEvidenceCandidates(family, structured)
			if candErr != nil {
				t.Fatalf("%s JSON candidates error: %v", family, candErr)
			}
			if len(candidates) != 2 {
				t.Fatalf("%s JSON candidates = %d, want 2", family, len(candidates))
			}
			for index, candidate := range candidates {
				if valErr := validateProbeEvidence(candidate, fixture); valErr != nil {
					t.Fatalf("%s JSON candidate %d rejected: %v", family, index, valErr)
				}
			}
			if acceptErr := acceptCapabilityEvidence(family, structured, fixture); acceptErr != nil {
				t.Fatalf("%s JSON evidence rejected: %v", family, acceptErr)
			}
		}
	}
}
