package publication

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/app/evidence"
	"github.com/irootkernel/mulgae/internal/app/validation"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

func TestReducePublicationEvidenceUsesTotalAuthorityReducer(t *testing.T) {
	t.Parallel()

	target, err := domain.NewTargetIdentity(domain.TargetIdentityInput{
		Kind: domain.TargetPatch, SHA256: strings.Repeat("a", 64),
	})
	if err != nil {
		t.Fatal(err)
	}
	finding, err := domain.NewFinding(domain.FindingInput{
		Severity: domain.SeverityLow, Path: "internal/example.go", LineStart: 1,
		Role: domain.RoleLogic, ProviderInstance: "logic-provider", Title: "low",
		Description: "description", Recommendation: "recommendation", Confidence: domain.ConfidenceLow,
		Lifecycle: domain.FindingOpen, EvidenceState: domain.EvidenceUnverified,
		NormalizedRuleCategory: "low", NormalizedEvidenceRegion: "line one",
	})
	if err != nil {
		t.Fatal(err)
	}
	claim, err := evidence.NewCurrentClaim(evidence.CurrentClaimInput{
		TargetSHA256: "sha256:" + target.SHA256(), Side: evidence.SideWorktree,
		Path: "internal/example.go", LineStart: 1, LineEnd: 1, Quote: "line one\n",
	})
	if err != nil {
		t.Fatal(err)
	}
	unavailable, err := evidence.NewVerifier(publicationEvidenceReader{availability: evidence.ImmutableTargetUnavailable})
	if err != nil {
		t.Fatal(err)
	}
	unavailableReceipt, err := unavailable.VerifyCurrent(context.Background(), claim)
	if err != nil {
		t.Fatal(err)
	}
	items, authoritative, err := reducePublicationEvidence(
		[]evidence.CurrentReceipt{unavailableReceipt}, make([]validation.VerifiedVisualReference, 1), finding, target, "F001",
	)
	if err != nil || authoritative || len(items) != 0 {
		t.Fatalf("allowed low patch exception = (%#v, %t, %v), want no authority or excerpts", items, authoritative, err)
	}

	verified, err := evidence.NewVerifier(publicationEvidenceReader{
		availability: evidence.ImmutableTargetAvailable, bytes: []byte("line one\n"),
	})
	if err != nil {
		t.Fatal(err)
	}
	verifiedReceipt, err := verified.VerifyCurrent(context.Background(), claim)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := reducePublicationEvidence(
		[]evidence.CurrentReceipt{verifiedReceipt, unavailableReceipt}, make([]validation.VerifiedVisualReference, 2), finding, target, "F001",
	); err == nil {
		t.Fatal("mixed evidence authority was accepted")
	}
}

func TestReducePublicationEvidenceDropsOptionalNonAuthoritativeFinding(t *testing.T) {
	t.Parallel()
	target, err := domain.NewTargetIdentity(domain.TargetIdentityInput{Kind: domain.TargetWorkspace, SHA256: strings.Repeat("b", 64)})
	if err != nil {
		t.Fatal(err)
	}
	claim, err := evidence.NewCurrentClaim(evidence.CurrentClaimInput{
		TargetSHA256: "sha256:" + target.SHA256(), Side: evidence.SideWorktree,
		Path: "internal/example.go", LineStart: 1, LineEnd: 1, Quote: "line one\n",
	})
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := evidence.NewVerifier(publicationEvidenceReader{availability: evidence.ImmutableTargetUnavailable})
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := verifier.VerifyCurrent(context.Background(), claim)
	if err != nil {
		t.Fatal(err)
	}
	newFinding := func(severity domain.Severity) domain.Finding {
		finding, findingErr := domain.NewFinding(domain.FindingInput{
			Severity: severity, Path: "internal/example.go", LineStart: 1,
			Role: domain.RoleLogic, ProviderInstance: "logic-provider", Title: "finding",
			Description: "description", Recommendation: "recommendation", Confidence: domain.ConfidenceLow,
			Lifecycle: domain.FindingOpen, EvidenceState: domain.EvidenceUnverified,
			NormalizedRuleCategory: "finding", NormalizedEvidenceRegion: "line one",
		})
		if findingErr != nil {
			t.Fatal(findingErr)
		}
		return finding
	}
	items, authoritative, err := reducePublicationEvidence(
		[]evidence.CurrentReceipt{receipt}, make([]validation.VerifiedVisualReference, 1), newFinding(domain.SeverityMedium), target, "F001",
	)
	if err != nil || authoritative || len(items) != 0 {
		t.Fatalf("optional non-authoritative finding = (%#v, %t, %v), want omission", items, authoritative, err)
	}
	if _, _, err := reducePublicationEvidence(
		[]evidence.CurrentReceipt{receipt}, make([]validation.VerifiedVisualReference, 1), newFinding(domain.SeverityHigh), target, "F001",
	); err == nil {
		t.Fatal("required high-severity non-authoritative evidence was accepted")
	}
}

type publicationEvidenceReader struct {
	availability evidence.ImmutableTargetAvailability
	bytes        []byte
}

func (reader publicationEvidenceReader) ReadImmutableTarget(
	context.Context,
	string,
	evidence.Side,
	ports.SafeRelativePath,
) (evidence.ImmutableTargetAvailability, []byte, error) {
	return reader.availability, append([]byte(nil), reader.bytes...), nil
}

func TestProductionPublicationContextCopiesAndRejectsIncompleteProvenance(t *testing.T) {
	t.Parallel()
	provenance := ProductionReviewProvenance{
		BuildProduct: "mulgae", BuildVersion: "1.9.0", BuildCommit: "abc123",
		SnapshotManifestSHA256: sha256Identifier([]byte("snapshot")), WorkspaceTerminalReceipt: sha256Identifier([]byte("workspace-terminal")),
		Providers: []ProductionProviderProvenance{{
			Family: "kimi", Instance: "kimi-main", Version: "0.23.6", Executable: "/private/bin/kimi",
			ExecutableSHA256: sha256Identifier([]byte("kimi")), Launcher: "/private/bin/kimi",
			LauncherSHA256: sha256Identifier([]byte("kimi")), ProfileGeneration: "generation", AdapterProfile: "kimi-default",
			QualificationReceiptIDs: []string{sha256Identifier([]byte("qualification"))}, PacketTransportReceiptIDs: []string{sha256Identifier([]byte("transport"))},
			NamespaceTerminalReceipt: sha256Identifier([]byte("namespace-terminal")),
		}},
	}
	context, err := NewProductionPublicationContext(provenance)
	if err != nil {
		t.Fatal(err)
	}
	provenance.Providers[0].QualificationReceiptIDs[0] = sha256Identifier([]byte("mutated"))
	if got := context.immutableProductionProvenance().Providers[0].QualificationReceiptIDs[0]; got != sha256Identifier([]byte("qualification")) {
		t.Fatalf("context retained caller mutation: %q", got)
	}
	incomplete := provenance
	incomplete.Providers[0].NamespaceTerminalReceipt = ""
	if _, err := NewProductionPublicationContext(incomplete); err == nil {
		t.Fatal("incomplete production provenance was accepted")
	}
}

func appendPublicationRuntimeRepairInvocation(t *testing.T, candidate *PreparedCandidate) {
	t.Helper()
	invocation := candidate.roles[0].attempts[0].invocations[0]
	invocation.sequence = 2
	invocation.purpose = domain.InvocationRepair
	invocation.runtime = clonePreparedRuntimeArtifact(invocation.runtime)
	invocation.artifacts = []preparedAttemptArtifact{{
		kind: ports.AttemptArtifactRepairedCandidate, bytes: []byte("repaired capture"),
	}}
	candidate.roles[0].attempts[0].invocations = append(candidate.roles[0].attempts[0].invocations, invocation)
}

func clonePreparedRuntimeArtifact(runtime *preparedRuntimeArtifact) *preparedRuntimeArtifact {
	cloned := *runtime
	cloned.target = append([]byte(nil), runtime.target...)
	cloned.capturedArchive = append([]byte(nil), runtime.capturedArchive...)
	cloned.stdin = append([]byte(nil), runtime.stdin...)
	cloned.adapterParameters = make(map[string]string, len(runtime.adapterParameters))
	for key, value := range runtime.adapterParameters {
		cloned.adapterParameters[key] = value
	}
	return &cloned
}

func publicationTestReviewID(t *testing.T) domain.ReviewID {
	t.Helper()
	id, err := domain.ParseReviewID("019f596a-d174-7321-b920-c2d312c82cc2")
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func publicationTestTime() time.Time {
	return time.Date(2026, time.July, 13, 3, 0, 0, 500000000, time.UTC)
}
