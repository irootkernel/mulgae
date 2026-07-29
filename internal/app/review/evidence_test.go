package review

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"unsafe"

	"github.com/irootkernel/mulgae/internal/app/evidence"
	"github.com/irootkernel/mulgae/internal/app/validation"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

func TestVerifyValidatedEvidenceMapsSidesAndRetainsReceiptStatuses(t *testing.T) {
	groups := bridgeValidatedGroups(t, []string{
		bridgeFindingJSON("base", []bridgeClaimSpec{{
			side: evidence.SideBase, path: "src/a.go", lineStart: 1, lineEnd: 1, quote: "base\n",
		}}),
		bridgeFindingJSON("stale", []bridgeClaimSpec{{
			side: evidence.SideHead, path: "src/b.go", lineStart: 1, lineEnd: 1, quote: "stale\n",
		}}),
		bridgeFindingJSON("invalid", []bridgeClaimSpec{{
			side: evidence.SideWorktree, path: "src/c.go", lineStart: 1, lineEnd: 1, quote: "expected\n",
		}}),
		bridgeFindingJSON("unavailable", []bridgeClaimSpec{{
			side: evidence.SideHead, path: "src/d.go", lineStart: 1, lineEnd: 1, quote: "unavailable\n",
		}}),
	})
	reader := &bridgeImmutableReader{responses: map[string]bridgeReaderResponse{
		bridgeReaderKey(evidence.SideBase, "src/a.go"): {
			availability: evidence.ImmutableTargetAvailable,
			bytes:        []byte("base\n"),
		},
		bridgeReaderKey(evidence.SideHead, "src/b.go"): {
			availability: evidence.ImmutableTargetStale,
		},
		bridgeReaderKey(evidence.SideWorktree, "src/c.go"): {
			availability: evidence.ImmutableTargetAvailable,
			bytes:        []byte("actual\n"),
		},
		bridgeReaderKey(evidence.SideHead, "src/d.go"): {
			availability: evidence.ImmutableTargetUnavailable,
		},
	}}

	verified, err := VerifyValidatedEvidence(context.Background(), bridgeVerifier(t, reader), groups)
	if err != nil {
		t.Fatalf("VerifyValidatedEvidence() error = %v", err)
	}

	wants := []struct {
		id     string
		side   evidence.Side
		status evidence.ReceiptStatus
		path   string
	}{
		{id: "F001", side: evidence.SideBase, status: evidence.ReceiptVerified, path: "src/a.go"},
		{id: "F002", side: evidence.SideHead, status: evidence.ReceiptStale, path: "src/b.go"},
		{id: "F003", side: evidence.SideWorktree, status: evidence.ReceiptInvalid, path: "src/c.go"},
		{id: "F004", side: evidence.SideHead, status: evidence.ReceiptUnverifiable, path: "src/d.go"},
	}
	if len(verified) != len(wants) {
		t.Fatalf("verified group count = %d, want %d", len(verified), len(wants))
	}
	if len(reader.calls) != len(wants) {
		t.Fatalf("reader calls = %d, want %d", len(reader.calls), len(wants))
	}
	for index, want := range wants {
		if got := verified[index].FindingID(); got != want.id {
			t.Errorf("group %d FindingID() = %q, want %q", index, got, want.id)
		}
		if !verified[index].matchesFinding(groups[index].Finding()) {
			t.Errorf("group %d finding proof = %#v, want %#v", index, verified[index].findingProof(), groups[index].Finding())
		}
		receipts := verified[index].Receipts()
		if len(receipts) != 1 {
			t.Errorf("group %d receipts = %d, want 1", index, len(receipts))
			continue
		}
		if got := receipts[0].Status(); got != want.status {
			t.Errorf("group %d status = %q, want %q", index, got, want.status)
		}
		if got := receipts[0].Claim().Side(); got != want.side {
			t.Errorf("group %d receipt side = %q, want %q", index, got, want.side)
		}
		if got := reader.calls[index].side; got != want.side {
			t.Errorf("reader call %d side = %q, want %q", index, got, want.side)
		}
		if got := reader.calls[index].path; got != want.path {
			t.Errorf("reader call %d path = %q, want %q", index, got, want.path)
		}
	}
}

func TestVerifyValidatedEvidencePreservesValidationClaimOrder(t *testing.T) {
	groups := bridgeValidatedGroups(t, []string{bridgeFindingJSON("ordered", []bridgeClaimSpec{
		{side: evidence.SideBase, path: "src/zeta.go", lineStart: 2, lineEnd: 2, quote: "zeta\n"},
		{side: evidence.SideWorktree, path: "src/alpha.go", lineStart: 10, lineEnd: 10, quote: "ten\n"},
		{side: evidence.SideHead, path: "src/alpha.go", lineStart: 2, lineEnd: 10, quote: "two\nthree\nfour\nfive\nsix\nseven\neight\nnine\nten\n"},
		{side: evidence.SideBase, path: "src/alpha.go", lineStart: 2, lineEnd: 2, quote: "two\n"},
	})})
	wantOrder := []bridgeClaimSpec{
		{side: evidence.SideBase, path: "src/alpha.go", lineStart: 2, lineEnd: 2, quote: "two\n"},
		{side: evidence.SideHead, path: "src/alpha.go", lineStart: 2, lineEnd: 10, quote: "two\nthree\nfour\nfive\nsix\nseven\neight\nnine\nten\n"},
		{side: evidence.SideWorktree, path: "src/alpha.go", lineStart: 10, lineEnd: 10, quote: "ten\n"},
		{side: evidence.SideBase, path: "src/zeta.go", lineStart: 2, lineEnd: 2, quote: "zeta\n"},
	}
	claims := groups[0].Claims()
	if len(claims) != len(wantOrder) {
		t.Fatalf("validation claims = %#v, want %d claims", claims, len(wantOrder))
	}
	for index, want := range wantOrder {
		claim := claims[index]
		if claim.Side() != validation.CurrentEvidenceSide(want.side) || claim.Path().String() != want.path || claim.LineStart() != want.lineStart || claim.LineEnd() != want.lineEnd || string(claim.QuoteBytes()) != want.quote {
			t.Errorf("validation claim %d = %#v, want %#v", index, claim, want)
		}
	}

	alphaTarget := []byte("one\ntwo\nthree\nfour\nfive\nsix\nseven\neight\nnine\nten\n")
	reader := &bridgeImmutableReader{responses: map[string]bridgeReaderResponse{
		bridgeReaderKey(evidence.SideBase, "src/alpha.go"): {
			availability: evidence.ImmutableTargetAvailable,
			bytes:        alphaTarget,
		},
		bridgeReaderKey(evidence.SideHead, "src/alpha.go"): {
			availability: evidence.ImmutableTargetAvailable,
			bytes:        alphaTarget,
		},
		bridgeReaderKey(evidence.SideWorktree, "src/alpha.go"): {
			availability: evidence.ImmutableTargetAvailable,
			bytes:        alphaTarget,
		},
		bridgeReaderKey(evidence.SideBase, "src/zeta.go"): {
			availability: evidence.ImmutableTargetAvailable,
			bytes:        []byte("one\nzeta\n"),
		},
	}}

	verified, err := VerifyValidatedEvidence(context.Background(), bridgeVerifier(t, reader), groups)
	if err != nil {
		t.Fatalf("VerifyValidatedEvidence() error = %v", err)
	}
	if len(verified) != 1 || len(verified[0].Receipts()) != len(wantOrder) {
		t.Fatalf("verified = %#v, want one four-receipt group", verified)
	}
	if len(reader.calls) != len(wantOrder) {
		t.Fatalf("reader calls = %d, want %d", len(reader.calls), len(wantOrder))
	}
	receipts := verified[0].Receipts()
	for index, want := range wantOrder {
		if got := reader.calls[index]; got.side != want.side || got.path != want.path {
			t.Errorf("reader call %d = %#v, want side=%q path=%q", index, got, want.side, want.path)
		}
		claim := receipts[index].Claim()
		if claim.Side() != want.side || claim.Path().String() != want.path || claim.LineStart() != want.lineStart || claim.LineEnd() != want.lineEnd || string(claim.QuoteBytes()) != want.quote {
			t.Errorf("receipt %d claim = %#v, want %#v", index, claim, want)
		}
	}
}

func TestVerifyValidatedEvidenceFailsClosedOnReaderErrorAndCancellation(t *testing.T) {
	groups := bridgeValidatedGroups(t, []string{
		bridgeFindingJSON("first", []bridgeClaimSpec{{
			side: evidence.SideBase, path: "src/a.go", lineStart: 1, lineEnd: 1, quote: "first\n",
		}}),
		bridgeFindingJSON("second", []bridgeClaimSpec{{
			side: evidence.SideHead, path: "src/b.go", lineStart: 1, lineEnd: 1, quote: "second\n",
		}}),
	})

	t.Run("reader_error_discards_partial_results", func(t *testing.T) {
		reader := &bridgeImmutableReader{responses: map[string]bridgeReaderResponse{
			bridgeReaderKey(evidence.SideBase, "src/a.go"): {
				availability: evidence.ImmutableTargetAvailable,
				bytes:        []byte("first\n"),
			},
			bridgeReaderKey(evidence.SideHead, "src/b.go"): {
				err: errors.New("immutable target store unavailable"),
			},
		}}
		verified, err := VerifyValidatedEvidence(context.Background(), bridgeVerifier(t, reader), groups)
		if err == nil {
			t.Fatal("VerifyValidatedEvidence() error = nil, want reader error")
		}
		if verified != nil {
			t.Fatalf("VerifyValidatedEvidence() = %#v, want nil after reader error", verified)
		}
		if got := len(reader.calls); got != 2 {
			t.Fatalf("reader calls = %d, want 2", got)
		}
	})

	t.Run("pre_cancellation_reads_nothing", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		reader := &bridgeImmutableReader{}
		verified, err := VerifyValidatedEvidence(ctx, bridgeVerifier(t, reader), groups)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("VerifyValidatedEvidence() error = %v, want context.Canceled", err)
		}
		if verified != nil {
			t.Fatalf("VerifyValidatedEvidence() = %#v, want nil after cancellation", verified)
		}
		if got := len(reader.calls); got != 0 {
			t.Fatalf("reader calls = %d, want 0", got)
		}
	})

	t.Run("mid_verification_cancellation_discards_partial_results", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		reader := &bridgeImmutableReader{responses: map[string]bridgeReaderResponse{
			bridgeReaderKey(evidence.SideBase, "src/a.go"): {
				availability: evidence.ImmutableTargetAvailable,
				bytes:        []byte("first\n"),
				cancel:       cancel,
			},
		}}
		verified, err := VerifyValidatedEvidence(ctx, bridgeVerifier(t, reader), groups)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("VerifyValidatedEvidence() error = %v, want context.Canceled", err)
		}
		if verified != nil {
			t.Fatalf("VerifyValidatedEvidence() = %#v, want nil after cancellation", verified)
		}
		if got := len(reader.calls); got != 1 {
			t.Fatalf("reader calls = %d, want 1", got)
		}
	})
}

func TestVerifyValidatedEvidenceRejectsInvalidBridgeInputs(t *testing.T) {
	validGroups := bridgeValidatedGroups(t, []string{
		bridgeFindingJSON("first", []bridgeClaimSpec{{
			side: evidence.SideBase, path: "src/a.go", lineStart: 1, lineEnd: 1, quote: "first\n",
		}}),
		bridgeFindingJSON("second", []bridgeClaimSpec{{
			side: evidence.SideHead, path: "src/b.go", lineStart: 1, lineEnd: 1, quote: "second\n",
		}}),
	})

	t.Run("nil_verifier", func(t *testing.T) {
		verified, err := VerifyValidatedEvidence(context.Background(), nil, validGroups)
		if err == nil || verified != nil {
			t.Fatalf("VerifyValidatedEvidence() = (%#v, %v), want (nil, error)", verified, err)
		}
	})

	t.Run("nil_context", func(t *testing.T) {
		verified, err := VerifyValidatedEvidence(nil, bridgeVerifier(t, &bridgeImmutableReader{}), validGroups)
		if err == nil || verified != nil {
			t.Fatalf("VerifyValidatedEvidence() = (%#v, %v), want (nil, error)", verified, err)
		}
	})

	t.Run("empty_claims", func(t *testing.T) {
		reader := &bridgeImmutableReader{}
		verified, err := VerifyValidatedEvidence(
			context.Background(),
			bridgeVerifier(t, reader),
			[]validation.FindingEvidenceClaims{{}},
		)
		if err == nil || verified != nil {
			t.Fatalf("VerifyValidatedEvidence() = (%#v, %v), want (nil, error)", verified, err)
		}
		if got := len(reader.calls); got != 0 {
			t.Fatalf("reader calls = %d, want 0", got)
		}
	})

	for _, test := range []struct {
		name   string
		mutate func([]validation.FindingEvidenceClaims)
	}{
		{
			name: "duplicate_finding_ID",
			mutate: func(groups []validation.FindingEvidenceClaims) {
				bridgeSetFindingID(&groups[1], "F001")
			},
		},
		{
			name: "disordered_finding_ID",
			mutate: func(groups []validation.FindingEvidenceClaims) {
				bridgeSetFindingID(&groups[0], "F002")
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			groups := append([]validation.FindingEvidenceClaims(nil), validGroups...)
			test.mutate(groups)
			reader := &bridgeImmutableReader{}
			verified, err := VerifyValidatedEvidence(context.Background(), bridgeVerifier(t, reader), groups)
			if err == nil || verified != nil {
				t.Fatalf("VerifyValidatedEvidence() = (%#v, %v), want (nil, error)", verified, err)
			}
			if got := len(reader.calls); got != 0 {
				t.Fatalf("reader calls = %d, want 0", got)
			}
		})
	}

	t.Run("disordered_claims", func(t *testing.T) {
		groups := bridgeValidatedGroups(t, []string{bridgeFindingJSON("ordered", []bridgeClaimSpec{
			{side: evidence.SideBase, path: "src/ordered.go", lineStart: 1, lineEnd: 1, quote: "line\n"},
			{side: evidence.SideHead, path: "src/ordered.go", lineStart: 1, lineEnd: 1, quote: "line\n"},
		})})
		bridgeSwapClaims(&groups[0], 0, 1)
		reader := &bridgeImmutableReader{}
		verified, err := VerifyValidatedEvidence(context.Background(), bridgeVerifier(t, reader), groups)
		if err == nil || verified != nil {
			t.Fatalf("VerifyValidatedEvidence() = (%#v, %v), want (nil, error)", verified, err)
		}
		if got := len(reader.calls); got != 0 {
			t.Fatalf("reader calls = %d, want 0", got)
		}
	})
}

func TestVerifiedFindingEvidenceReturnsDefensiveReceiptCopies(t *testing.T) {
	groups := bridgeValidatedGroups(t, []string{bridgeFindingJSON("verified", []bridgeClaimSpec{{
		side: evidence.SideBase, path: "src/verified.go", lineStart: 1, lineEnd: 1, quote: "verified\n",
	}})})
	reader := &bridgeImmutableReader{responses: map[string]bridgeReaderResponse{
		bridgeReaderKey(evidence.SideBase, "src/verified.go"): {
			availability: evidence.ImmutableTargetAvailable,
			bytes:        []byte("verified\n"),
		},
	}}
	verified, err := VerifyValidatedEvidence(context.Background(), bridgeVerifier(t, reader), groups)
	if err != nil {
		t.Fatalf("VerifyValidatedEvidence() error = %v", err)
	}
	if len(verified) != 1 || len(verified[0].Receipts()) != 1 {
		t.Fatalf("verified = %#v, want one one-receipt group", verified)
	}

	receipts := verified[0].Receipts()
	receipts[0] = evidence.CurrentReceipt{}
	if got := verified[0].Receipts()[0].Status(); got != evidence.ReceiptVerified {
		t.Fatalf("receipt slice mutation changed stored status to %q", got)
	}
	if !verified[0].matchesFinding(groups[0].Finding()) {
		t.Fatalf("finding proof changed: %#v", verified[0].findingProof())
	}

	excerpt := verified[0].Receipts()[0].Excerpt()
	excerpt[0] = 'X'
	if got := string(verified[0].Receipts()[0].Excerpt()); got != "verified\n" {
		t.Fatalf("excerpt mutation leaked into receipt: %q", got)
	}
}
func TestEvidencePolicyCanonicalizesRequiredSeverities(t *testing.T) {
	t.Parallel()

	policy, err := NewEvidencePolicy([]domain.Severity{
		domain.SeverityBlocker,
		domain.SeverityLow,
		domain.SeverityCritical,
		domain.SeverityHigh,
		domain.SeverityLow,
	})
	if err != nil {
		t.Fatalf("NewEvidencePolicy() error = %v", err)
	}
	want := []domain.Severity{
		domain.SeverityLow,
		domain.SeverityHigh,
		domain.SeverityCritical,
		domain.SeverityBlocker,
	}
	if got := policy.RequiredSeverities(); !reflect.DeepEqual(got, want) {
		t.Fatalf("RequiredSeverities() = %v, want %v", got, want)
	}
	if policy.Requires(domain.SeverityInfo) || !policy.Requires(domain.SeverityLow) ||
		!policy.Requires(domain.SeverityHigh) || !policy.Requires(domain.SeverityCritical) ||
		!policy.Requires(domain.SeverityBlocker) {
		t.Fatalf("Requires() did not retain the required severity set: %v", policy.RequiredSeverities())
	}

	required := policy.RequiredSeverities()
	required[0] = domain.SeverityInfo
	if got := policy.RequiredSeverities(); !reflect.DeepEqual(got, want) {
		t.Fatalf("RequiredSeverities() leaked mutation: %v", got)
	}
	if _, err := NewEvidencePolicy([]domain.Severity{domain.Severity("unknown")}); err == nil {
		t.Fatal("NewEvidencePolicy() accepted an invalid severity")
	}
	if _, err := NewEvidencePolicy([]domain.Severity{
		domain.SeverityHigh,
		domain.SeverityCritical,
	}); err == nil {
		t.Fatal("NewEvidencePolicy() accepted a policy below the verification minimum")
	}

	defaultPolicy := DefaultEvidencePolicy()
	defaultWant := []domain.Severity{
		domain.SeverityHigh,
		domain.SeverityCritical,
		domain.SeverityBlocker,
	}
	if got := defaultPolicy.RequiredSeverities(); !reflect.DeepEqual(got, defaultWant) {
		t.Fatalf("DefaultEvidencePolicy() = %v, want %v", got, defaultWant)
	}
}

func TestReduceVerifiedFindingEvidenceProjectsVerifierReceiptStates(t *testing.T) {
	verifiedGroups := bridgeValidatedGroups(t, []string{
		bridgeFindingJSON("verified", []bridgeClaimSpec{{
			side: evidence.SideBase, path: "src/verified.go", lineStart: 1, lineEnd: 1, quote: "verified\n",
		}}),
		bridgeFindingJSON("stale", []bridgeClaimSpec{{
			side: evidence.SideHead, path: "src/stale.go", lineStart: 1, lineEnd: 1, quote: "stale\n",
		}}),
		bridgeFindingJSON("quote", []bridgeClaimSpec{{
			side: evidence.SideWorktree, path: "src/quote.go", lineStart: 1, lineEnd: 1, quote: "expected\n",
		}}),
		bridgeFindingJSON("line", []bridgeClaimSpec{{
			side: evidence.SideBase, path: "src/line.go", lineStart: 2, lineEnd: 2, quote: "second\n",
		}}),
		bridgeFindingJSON("unavailable", []bridgeClaimSpec{{
			side: evidence.SideHead, path: "src/unavailable.go", lineStart: 1, lineEnd: 1, quote: "unavailable\n",
		}}),
		bridgeFindingJSON("mixed", []bridgeClaimSpec{
			{side: evidence.SideBase, path: "src/mixed.go", lineStart: 1, lineEnd: 1, quote: "verified\n"},
			{side: evidence.SideHead, path: "src/mixed.go", lineStart: 1, lineEnd: 1, quote: "expected\n"},
		}),
	})
	reader := &bridgeImmutableReader{responses: map[string]bridgeReaderResponse{
		bridgeReaderKey(evidence.SideBase, "src/verified.go"): {
			availability: evidence.ImmutableTargetAvailable,
			bytes:        []byte("verified\n"),
		},
		bridgeReaderKey(evidence.SideHead, "src/stale.go"): {
			availability: evidence.ImmutableTargetStale,
		},
		bridgeReaderKey(evidence.SideWorktree, "src/quote.go"): {
			availability: evidence.ImmutableTargetAvailable,
			bytes:        []byte("actual\n"),
		},
		bridgeReaderKey(evidence.SideHead, "src/unavailable.go"): {
			availability: evidence.ImmutableTargetUnavailable,
		},
		bridgeReaderKey(evidence.SideBase, "src/line.go"): {
			availability: evidence.ImmutableTargetAvailable,
			bytes:        []byte("only\n"),
		},
		bridgeReaderKey(evidence.SideBase, "src/mixed.go"): {
			availability: evidence.ImmutableTargetAvailable,
			bytes:        []byte("verified\n"),
		},
		bridgeReaderKey(evidence.SideHead, "src/mixed.go"): {
			availability: evidence.ImmutableTargetAvailable,
			bytes:        []byte("actual\n"),
		},
	}}
	groups, err := VerifyValidatedEvidence(context.Background(), bridgeVerifier(t, reader), verifiedGroups)
	if err != nil {
		t.Fatalf("VerifyValidatedEvidence() error = %v", err)
	}
	findings := bridgeVerifiedFindings(groups)
	reduced, err := ReduceVerifiedFindingEvidence(findings, groups, structuralEvidencePolicy())
	if err != nil {
		t.Fatalf("ReduceVerifiedFindingEvidence() error = %v", err)
	}
	if len(reduced) != len(groups) {
		t.Fatalf("reduced finding count = %d, want %d", len(reduced), len(groups))
	}

	wantByPath := map[string]domain.EvidenceState{
		"src/verified.go":    domain.EvidenceVerified,
		"src/stale.go":       domain.EvidenceOutsideScope,
		"src/quote.go":       domain.EvidenceQuoteMismatch,
		"src/unavailable.go": domain.EvidenceUnverified,
		"src/line.go":        domain.EvidenceInvalidLine,
	}
	for index, group := range groups {
		receipts := group.Receipts()
		want, ok := wantByPath[receipts[0].Claim().Path().String()]
		if len(receipts) == 2 {
			want, ok = domain.EvidencePartiallyVerified, true
		}
		if !ok {
			t.Fatalf("unexpected receipt group %q: %#v", group.FindingID(), receipts)
		}
		if got := reduced[index].EvidenceState(); got != want {
			t.Errorf("finding %q evidence state = %q, want %q", reduced[index].ID(), got, want)
		}
		if got := reduced[index].ID(); got != group.FindingID() {
			t.Errorf("finding/receipt ID = %q/%q, want exact match", got, group.FindingID())
		}
	}
}

func TestReduceVerifiedFindingEvidenceFailsClosedOnRequiredOrMalformedEvidence(t *testing.T) {
	staleGroups := bridgeValidatedGroups(t, []string{
		bridgeFindingJSON("stale", []bridgeClaimSpec{{
			side: evidence.SideHead, path: "src/stale-required.go", lineStart: 1, lineEnd: 1, quote: "stale\n",
		}}),
	})
	staleReader := &bridgeImmutableReader{responses: map[string]bridgeReaderResponse{
		bridgeReaderKey(evidence.SideHead, "src/stale-required.go"): {
			availability: evidence.ImmutableTargetStale,
		},
	}}
	stale, err := VerifyValidatedEvidence(context.Background(), bridgeVerifier(t, staleReader), staleGroups)
	if err != nil {
		t.Fatalf("VerifyValidatedEvidence() error = %v", err)
	}
	findings := bridgeVerifiedFindings(stale)
	reduced, err := ReduceVerifiedFindingEvidence(findings, stale, DefaultEvidencePolicy())
	if reduced != nil {
		t.Fatalf("ReduceVerifiedFindingEvidence() = %#v, want nil policy-rejected output", reduced)
	}
	policyError, ok := AsEvidencePolicyError(err)
	if !ok {
		t.Fatalf("ReduceVerifiedFindingEvidence() error = %v, want EvidencePolicyError", err)
	}
	if policyError.FindingID() != "F001" || policyError.Severity() != domain.SeverityHigh ||
		policyError.EvidenceState() != domain.EvidenceOutsideScope {
		t.Fatalf("EvidencePolicyError = %#v", policyError)
	}

	verified := bridgeFullyVerifiedEvidence(t, 1)
	verifiedFindings := bridgeVerifiedFindings(verified)
	for _, test := range []struct {
		name   string
		mutate func([]VerifiedFindingEvidence)
	}{
		{
			name: "finding_ID_mismatch",
			mutate: func(groups []VerifiedFindingEvidence) {
				groups[0].findingID = "F002"
			},
		},
		{
			name: "empty_receipts",
			mutate: func(groups []VerifiedFindingEvidence) {
				groups[0].receipts = nil
			},
		},
		{
			name: "empty_validation_claims",
			mutate: func(groups []VerifiedFindingEvidence) {
				groups[0].claims = nil
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			groups := cloneVerifiedFindingEvidence(verified)
			test.mutate(groups)
			reduced, err := ReduceVerifiedFindingEvidence(verifiedFindings, groups, structuralEvidencePolicy())
			if err == nil || reduced != nil {
				t.Fatalf("ReduceVerifiedFindingEvidence() = (%#v, %v), want (nil, error)", reduced, err)
			}
		})
	}
}

func TestReduceVerifiedFindingEvidenceRejectsCrossReviewReceiptSubstitution(t *testing.T) {
	reviewA := bridgeValidatedReview(t, strings.Repeat("a", 64), []string{
		bridgeFindingJSON("review A", []bridgeClaimSpec{{
			side: evidence.SideBase, path: "src/review-a.go", lineStart: 1, lineEnd: 1, quote: "review A\n",
		}}),
	})
	reviewB := bridgeValidatedReview(t, strings.Repeat("b", 64), []string{
		bridgeFindingJSON("review B", []bridgeClaimSpec{{
			side: evidence.SideHead, path: "src/review-b.go", lineStart: 1, lineEnd: 1, quote: "review B\n",
		}}),
	})
	reader := &bridgeImmutableReader{responses: map[string]bridgeReaderResponse{
		bridgeReaderKey(evidence.SideBase, "src/review-a.go"): {
			availability: evidence.ImmutableTargetAvailable,
			bytes:        []byte("review A\n"),
		},
		bridgeReaderKey(evidence.SideHead, "src/review-b.go"): {
			availability: evidence.ImmutableTargetAvailable,
			bytes:        []byte("review B\n"),
		},
	}}
	verifiedA, err := VerifyValidatedEvidence(context.Background(), bridgeVerifier(t, reader), reviewA.EvidenceClaims())
	if err != nil {
		t.Fatalf("VerifyValidatedEvidence(review A) error = %v", err)
	}
	verifiedB, err := VerifyValidatedEvidence(context.Background(), bridgeVerifier(t, reader), reviewB.EvidenceClaims())
	if err != nil {
		t.Fatalf("VerifyValidatedEvidence(review B) error = %v", err)
	}
	if _, err := ReduceVerifiedFindingEvidence(reviewA.Findings(), verifiedA, structuralEvidencePolicy()); err != nil {
		t.Fatalf("ReduceVerifiedFindingEvidence(correct groups) error = %v", err)
	}

	swapped := append([]VerifiedFindingEvidence(nil), verifiedA...)
	swapped[0] = verifiedB[0]
	reduced, err := ReduceVerifiedFindingEvidence(reviewA.Findings(), swapped, structuralEvidencePolicy())
	if err == nil || reduced != nil {
		t.Fatalf("ReduceVerifiedFindingEvidence(swapped F001 group) = (%#v, %v), want (nil, error)", reduced, err)
	}
}

func TestReduceVerifiedFindingEvidenceRejectsReceiptClaimSetMismatches(t *testing.T) {
	validated := bridgeValidatedReview(t, strings.Repeat("a", 64), []string{
		bridgeFindingJSON("claim set", []bridgeClaimSpec{
			{side: evidence.SideBase, path: "src/claims.go", lineStart: 1, lineEnd: 1, quote: "one\n"},
			{side: evidence.SideHead, path: "src/claims.go", lineStart: 1, lineEnd: 1, quote: "one\n"},
		}),
	})
	reader := &bridgeImmutableReader{responses: map[string]bridgeReaderResponse{
		bridgeReaderKey(evidence.SideBase, "src/claims.go"): {
			availability: evidence.ImmutableTargetAvailable,
			bytes:        []byte("one\n"),
		},
		bridgeReaderKey(evidence.SideHead, "src/claims.go"): {
			availability: evidence.ImmutableTargetAvailable,
			bytes:        []byte("one\n"),
		},
	}}
	verified, err := VerifyValidatedEvidence(context.Background(), bridgeVerifier(t, reader), validated.EvidenceClaims())
	if err != nil {
		t.Fatalf("VerifyValidatedEvidence() error = %v", err)
	}
	findings := validated.Findings()

	for _, test := range []struct {
		name   string
		mutate func(*VerifiedFindingEvidence)
	}{
		{
			name: "reordered",
			mutate: func(group *VerifiedFindingEvidence) {
				group.receipts[0], group.receipts[1] = group.receipts[1], group.receipts[0]
			},
		},
		{
			name: "missing",
			mutate: func(group *VerifiedFindingEvidence) {
				group.receipts = group.receipts[:1]
			},
		},
		{
			name: "extra",
			mutate: func(group *VerifiedFindingEvidence) {
				group.receipts = append(group.receipts, group.receipts[0])
			},
		},
		{
			name: "different_target",
			mutate: func(group *VerifiedFindingEvidence) {
				bridgeSetReceiptClaimString(&group.receipts[0], "targetSHA256", "sha256:"+strings.Repeat("b", 64))
			},
		},
		{
			name: "different_range",
			mutate: func(group *VerifiedFindingEvidence) {
				bridgeSetReceiptClaimInt(&group.receipts[0], "lineEnd", 2)
			},
		},
		{
			name: "different_quote",
			mutate: func(group *VerifiedFindingEvidence) {
				bridgeSetReceiptClaimBytes(&group.receipts[0], "quote", []byte("two\n"))
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			groups := cloneVerifiedFindingEvidence(verified)
			test.mutate(&groups[0])
			reduced, err := ReduceVerifiedFindingEvidence(findings, groups, structuralEvidencePolicy())
			if err == nil || reduced != nil {
				t.Fatalf("ReduceVerifiedFindingEvidence() = (%#v, %v), want (nil, error)", reduced, err)
			}
		})
	}
}
func bridgeVerifiedFindings(groups []VerifiedFindingEvidence) []domain.Finding {
	findings := make([]domain.Finding, len(groups))
	for index, group := range groups {
		findings[index] = group.findingProof()
	}
	return findings
}

func bridgeFullyVerifiedEvidence(t *testing.T, count int) []VerifiedFindingEvidence {
	t.Helper()

	findings := make([]string, count)
	responses := make(map[string]bridgeReaderResponse, count)
	for index := range findings {
		path := fmt.Sprintf("src/receipt-%03d.go", index+1)
		quote := fmt.Sprintf("receipt %03d\n", index+1)
		findings[index] = bridgeFindingJSON(fmt.Sprintf("receipt %03d", index+1), []bridgeClaimSpec{{
			side: evidence.SideBase, path: path, lineStart: 1, lineEnd: 1, quote: quote,
		}})
		responses[bridgeReaderKey(evidence.SideBase, path)] = bridgeReaderResponse{
			availability: evidence.ImmutableTargetAvailable,
			bytes:        []byte(quote),
		}
	}
	groups, err := VerifyValidatedEvidence(
		context.Background(),
		bridgeVerifier(t, &bridgeImmutableReader{responses: responses}),
		bridgeValidatedGroups(t, findings),
	)
	if err != nil {
		t.Fatalf("VerifyValidatedEvidence() error = %v", err)
	}
	return groups
}

type bridgeClaimSpec struct {
	side      evidence.Side
	path      string
	lineStart int
	lineEnd   int
	quote     string
}

func bridgeFindingJSON(title string, claims []bridgeClaimSpec) string {
	evidenceJSON := make([]string, len(claims))
	for index, claim := range claims {
		evidenceJSON[index] = fmt.Sprintf(
			`{"current":{"path":%q,"side":%q,"line_start":%d,"line_end":%d,"quote":%q}}`,
			claim.path,
			string(claim.side),
			claim.lineStart,
			claim.lineEnd,
			claim.quote,
		)
	}
	return fmt.Sprintf(
		`{"severity":"high","title":%q,"description":"The bridge must retain every verifier result.","evidence":[%s],"recommendation":"Retain verifier results.","confidence":"high"}`,
		title,
		strings.Join(evidenceJSON, ","),
	)
}

func bridgeValidatedGroups(t *testing.T, findings []string) []validation.FindingEvidenceClaims {
	t.Helper()
	return bridgeValidatedReview(t, strings.Repeat("a", 64), findings).EvidenceClaims()
}

func bridgeValidatedReview(t *testing.T, targetSHA256 string, findings []string) validation.ValidatedReview {
	t.Helper()
	schemaID, err := ports.ParseAssetID(validation.ProviderReviewSchemaID)
	if err != nil {
		t.Fatal(err)
	}
	validator, err := validation.NewReviewValidator(bridgeSchemaValidator{}, schemaID)
	if err != nil {
		t.Fatal(err)
	}
	raw := fmt.Sprintf(
		`{"schema_version":"mulgae-provider-review-output.v1","summary":"Bridge evidence test.","completeness":"complete","limitations":[],"findings":[%s]}`,
		strings.Join(findings, ","),
	)
	review, repair, err := validator.Validate(context.Background(), []byte(raw), validation.ReviewValidationScope{
		TargetSHA256:     targetSHA256,
		Role:             domain.RoleSecurity,
		ProviderInstance: "fake.security",
	})
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if repair != nil {
		t.Fatalf("Validate() repair plan = %#v, want nil", repair)
	}
	return review
}

type bridgeSchemaValidator struct{}

func (bridgeSchemaValidator) Validate(context.Context, ports.AssetID, []byte) error { return nil }

type bridgeReaderResponse struct {
	availability evidence.ImmutableTargetAvailability
	bytes        []byte
	err          error
	cancel       context.CancelFunc
}

type bridgeReadCall struct {
	targetSHA256 string
	side         evidence.Side
	path         string
}

type bridgeImmutableReader struct {
	responses map[string]bridgeReaderResponse
	calls     []bridgeReadCall
}

func (reader *bridgeImmutableReader) ReadImmutableTarget(
	_ context.Context,
	targetSHA256 string,
	side evidence.Side,
	path ports.SafeRelativePath,
) (evidence.ImmutableTargetAvailability, []byte, error) {
	reader.calls = append(reader.calls, bridgeReadCall{
		targetSHA256: targetSHA256,
		side:         side,
		path:         path.String(),
	})
	response, ok := reader.responses[bridgeReaderKey(side, path.String())]
	if !ok {
		return "", nil, fmt.Errorf("unexpected immutable target read for %s %s", side, path.String())
	}
	if response.cancel != nil {
		response.cancel()
	}
	return response.availability, append([]byte(nil), response.bytes...), response.err
}

func bridgeReaderKey(side evidence.Side, path string) string {
	return string(side) + "\x00" + path
}

func bridgeVerifier(t *testing.T, reader evidence.ImmutableTargetReader) *evidence.Verifier {
	t.Helper()
	verifier, err := evidence.NewVerifier(reader)
	if err != nil {
		t.Fatal(err)
	}
	return verifier
}

func bridgeSetFindingID(group *validation.FindingEvidenceClaims, findingID string) {
	field := bridgeWritableField(group, "findingID")
	field.SetString(findingID)
}
func bridgeSetReceiptClaimString(receipt *evidence.CurrentReceipt, name, value string) {
	claim := bridgeWritableField(receipt, "claim")
	bridgeWritableStructField(claim, name).SetString(value)
}

func bridgeSetReceiptClaimInt(receipt *evidence.CurrentReceipt, name string, value int) {
	claim := bridgeWritableField(receipt, "claim")
	bridgeWritableStructField(claim, name).SetInt(int64(value))
}

func bridgeSetReceiptClaimBytes(receipt *evidence.CurrentReceipt, name string, value []byte) {
	claim := bridgeWritableField(receipt, "claim")
	bridgeWritableStructField(claim, name).SetBytes(value)
}

func bridgeSwapClaims(group *validation.FindingEvidenceClaims, left, right int) {
	claims := bridgeWritableField(group, "claims")
	copy := reflect.New(claims.Index(left).Type()).Elem()
	copy.Set(claims.Index(left))
	claims.Index(left).Set(claims.Index(right))
	claims.Index(right).Set(copy)
}

func bridgeWritableField(value any, name string) reflect.Value {
	return bridgeWritableStructField(reflect.ValueOf(value).Elem(), name)
}

func bridgeWritableStructField(value reflect.Value, name string) reflect.Value {
	field := value.FieldByName(name)
	return reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem()
}
