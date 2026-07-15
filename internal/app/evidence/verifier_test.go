package evidence

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/irootkernel/kkachi-agent-review/internal/ports"
	"golang.org/x/text/unicode/norm"
)

type fakeImmutableTargetReader struct {
	availability ImmutableTargetAvailability
	bytes        []byte
	err          error
	calls        int
	wantTarget   string
	wantSide     Side
	wantPath     string
}

func (reader *fakeImmutableTargetReader) ReadImmutableTarget(_ context.Context, targetSHA256 string, side Side, path ports.SafeRelativePath) (ImmutableTargetAvailability, []byte, error) {
	reader.calls++
	if reader.wantTarget != "" && targetSHA256 != reader.wantTarget {
		return "", nil, errors.New("unexpected target")
	}
	if reader.wantSide != "" && side != reader.wantSide {
		return "", nil, errors.New("unexpected side")
	}
	if reader.wantPath != "" && path.String() != reader.wantPath {
		return "", nil, errors.New("unexpected path")
	}
	return reader.availability, append([]byte(nil), reader.bytes...), reader.err
}

func TestVerifyCurrentPreservesLFAndFinalNonLFBytes(t *testing.T) {
	tests := []struct {
		name       string
		bytes      string
		lineStart  int
		lineEnd    int
		quote      string
		wantDigest string
	}{
		{
			name:       "selected_lines_include_terminating_LF",
			bytes:      "zero\none\ntwo\nthree\n",
			lineStart:  2,
			lineEnd:    3,
			quote:      "one\ntwo\n",
			wantDigest: expectedExcerptSHA256(strings.Repeat("a", sha256.Size*2), SideHead, "src/file.go", 2, 3, []byte("one\ntwo\n")),
		},
		{
			name:       "final_non_LF_line_is_a_line",
			bytes:      "zero\nlast",
			lineStart:  2,
			lineEnd:    2,
			quote:      "last",
			wantDigest: expectedExcerptSHA256(strings.Repeat("a", sha256.Size*2), SideHead, "src/file.go", 2, 2, []byte("last")),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			claim := mustCurrentClaim(t, CurrentClaimInput{
				TargetSHA256: strings.Repeat("a", sha256.Size*2),
				Side:         SideHead,
				Path:         "src/file.go",
				LineStart:    test.lineStart,
				LineEnd:      test.lineEnd,
				Quote:        test.quote,
			})
			reader := &fakeImmutableTargetReader{
				availability: ImmutableTargetAvailable,
				bytes:        []byte(test.bytes),
				wantTarget:   "sha256:" + strings.Repeat("a", sha256.Size*2),
				wantSide:     SideHead,
				wantPath:     "src/file.go",
			}
			verifier := mustVerifier(t, reader)

			receipt, err := verifier.VerifyCurrent(context.Background(), claim)
			if err != nil {
				t.Fatalf("VerifyCurrent() error = %v", err)
			}
			if got, want := receipt.Status(), ReceiptVerified; got != want {
				t.Fatalf("Status() = %q, want %q", got, want)
			}
			if got, want := receipt.ReasonCode(), ReasonVerified; got != want {
				t.Fatalf("ReasonCode() = %q, want %q", got, want)
			}
			if got, want := string(receipt.Excerpt()), test.quote; got != want {
				t.Fatalf("Excerpt() = %q, want %q", got, want)
			}
			if got, want := receipt.ExcerptSHA256(), test.wantDigest; got != want {
				t.Fatalf("ExcerptSHA256() = %q, want %q", got, want)
			}
		})
	}
}

func TestNewCurrentClaimRejectsUnsafePathsAndRanges(t *testing.T) {
	for _, path := range []string{
		"/absolute",
		"../escape",
		"nested/../escape",
		"nested\\escape",
		"nul\x00path",
		".",
		"..",
		"nested//path",
		"line\npath",
		norm.NFD.String("src/café.go"),
	} {
		t.Run("path_"+strings.ReplaceAll(path, "/", "_"), func(t *testing.T) {
			_, err := NewCurrentClaim(validClaimInput(path, 1, 1, "quote"))
			if err == nil {
				t.Fatalf("NewCurrentClaim(%q) accepted unsafe path", path)
			}
		})
	}

	for _, test := range []struct {
		name      string
		lineStart int
		lineEnd   int
	}{
		{name: "zero_start", lineStart: 0, lineEnd: 1},
		{name: "zero_end", lineStart: 1, lineEnd: 0},
		{name: "inverted", lineStart: 3, lineEnd: 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewCurrentClaim(validClaimInput("src/file.go", test.lineStart, test.lineEnd, "quote"))
			if err == nil {
				t.Fatal("NewCurrentClaim() accepted an invalid line range")
			}
		})
	}
}

func TestVerifyCurrentClassifiesNonVerifiedOutcomes(t *testing.T) {
	tests := []struct {
		name           string
		availability   ImmutableTargetAvailability
		bytes          string
		lineStart      int
		lineEnd        int
		quote          string
		wantStatus     ReceiptStatus
		wantReason     ReasonCode
		wantHash       bool
		wantExcerptNil bool
	}{
		{
			name:           "out_of_range",
			availability:   ImmutableTargetAvailable,
			bytes:          "first\n",
			lineStart:      2,
			lineEnd:        2,
			quote:          "second",
			wantStatus:     ReceiptInvalid,
			wantReason:     ReasonLineRangeOutOfBounds,
			wantExcerptNil: true,
		},
		{
			name:           "quote_mismatch",
			availability:   ImmutableTargetAvailable,
			bytes:          "first\n",
			lineStart:      1,
			lineEnd:        1,
			quote:          "first",
			wantStatus:     ReceiptInvalid,
			wantReason:     ReasonQuoteMismatch,
			wantHash:       true,
			wantExcerptNil: true,
		},
		{
			name:           "stale_target",
			availability:   ImmutableTargetStale,
			bytes:          "first\n",
			lineStart:      1,
			lineEnd:        1,
			quote:          "first\n",
			wantStatus:     ReceiptStale,
			wantReason:     ReasonStaleTarget,
			wantExcerptNil: true,
		},
		{
			name:           "unavailable_immutable_source",
			availability:   ImmutableTargetUnavailable,
			lineStart:      1,
			lineEnd:        1,
			quote:          "first\n",
			wantStatus:     ReceiptUnverifiable,
			wantReason:     ReasonTargetUnavailable,
			wantExcerptNil: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			claim := mustCurrentClaim(t, validClaimInput("src/file.go", test.lineStart, test.lineEnd, test.quote))
			verifier := mustVerifier(t, &fakeImmutableTargetReader{
				availability: test.availability,
				bytes:        []byte(test.bytes),
			})

			receipt, err := verifier.VerifyCurrent(context.Background(), claim)
			if err != nil {
				t.Fatalf("VerifyCurrent() error = %v", err)
			}
			if got, want := receipt.Status(), test.wantStatus; got != want {
				t.Fatalf("Status() = %q, want %q", got, want)
			}
			if got, want := receipt.ReasonCode(), test.wantReason; got != want {
				t.Fatalf("ReasonCode() = %q, want %q", got, want)
			}
			if got := receipt.ExcerptSHA256() != ""; got != test.wantHash {
				t.Fatalf("ExcerptSHA256() presence = %t, want %t", got, test.wantHash)
			}
			if got := receipt.Excerpt() == nil; got != test.wantExcerptNil {
				t.Fatalf("Excerpt() nil = %t, want %t", got, test.wantExcerptNil)
			}
		})
	}
}

func TestVerifyCurrentExcerptDigestBindsCanonicalIdentity(t *testing.T) {
	base := validClaimInput("src/café.go", 1, 1, "line\n")
	base.TargetSHA256 = strings.Repeat("a", sha256.Size*2)
	base.Side = SideBase

	inputs := []CurrentClaimInput{base}
	targetChanged := base
	targetChanged.TargetSHA256 = "sha256:" + strings.Repeat("b", sha256.Size*2)
	inputs = append(inputs, targetChanged)
	sideChanged := base
	sideChanged.Side = SideHead
	inputs = append(inputs, sideChanged)
	pathChanged := base
	pathChanged.Path = "src/other.go"
	inputs = append(inputs, pathChanged)
	rangeChanged := base
	rangeChanged.LineEnd = 2
	rangeChanged.Quote = "line\nnext\n"
	inputs = append(inputs, rangeChanged)

	digests := make(map[string]struct{}, len(inputs))
	for _, input := range inputs {
		bytes := []byte("line\n")
		if input.LineEnd == 2 {
			bytes = []byte("line\nnext\n")
		}
		claim := mustCurrentClaim(t, input)
		verifier := mustVerifier(t, &fakeImmutableTargetReader{
			availability: ImmutableTargetAvailable,
			bytes:        bytes,
		})
		receipt, err := verifier.VerifyCurrent(context.Background(), claim)
		if err != nil {
			t.Fatalf("VerifyCurrent() error = %v", err)
		}
		if receipt.Status() != ReceiptVerified {
			t.Fatalf("Status() = %q, want verified", receipt.Status())
		}
		expected := expectedExcerptSHA256(
			strings.TrimPrefix(input.TargetSHA256, "sha256:"),
			input.Side,
			input.Path,
			input.LineStart,
			input.LineEnd,
			bytes,
		)
		if got := receipt.ExcerptSHA256(); got != expected {
			t.Fatalf("ExcerptSHA256() = %q, want exact preimage digest %q", got, expected)
		}
		digests[receipt.ExcerptSHA256()] = struct{}{}
	}
	if got, want := len(digests), len(inputs); got != want {
		t.Fatalf("identity changes produced %d unique excerpt hashes, want %d", got, want)
	}
}

func TestNewCurrentClaimCanonicalizesSHAAndAcceptsNFCPath(t *testing.T) {
	path := "src/café.go"
	claim := mustCurrentClaim(t, CurrentClaimInput{
		TargetSHA256: "sha256:" + strings.Repeat("a", sha256.Size*2),
		Side:         SideWorktree,
		Path:         path,
		LineStart:    1,
		LineEnd:      1,
		Quote:        "café\n",
	})
	if got, want := claim.TargetSHA256(), "sha256:"+strings.Repeat("a", sha256.Size*2); got != want {
		t.Fatalf("TargetSHA256() = %q, want %q", got, want)
	}
	if got, want := claim.Path().String(), path; got != want {
		t.Fatalf("Path() = %q, want NFC path %q", got, want)
	}
}

func TestVerifyCurrentFailsClosedForCanceledContextAndReaderFailures(t *testing.T) {
	claim := mustCurrentClaim(t, validClaimInput("src/file.go", 1, 1, "line\n"))
	reader := &fakeImmutableTargetReader{availability: ImmutableTargetAvailable, bytes: []byte("line\n")}
	verifier := mustVerifier(t, reader)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	receipt, err := verifier.VerifyCurrent(ctx, claim)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("VerifyCurrent() error = %v, want context.Canceled", err)
	}
	if receipt.Status() != ReceiptUnverifiable || receipt.ReasonCode() != ReasonContextCanceled {
		t.Fatalf("canceled receipt = (%q, %q), want (unverifiable, context_canceled)", receipt.Status(), receipt.ReasonCode())
	}
	if reader.calls != 0 {
		t.Fatalf("canceled verification called reader %d times, want 0", reader.calls)
	}

	receipt, err = verifier.VerifyCurrent(nil, claim)
	if err == nil || receipt.Status() != ReceiptUnverifiable || receipt.ReasonCode() != ReasonNilContext {
		t.Fatalf("nil context result = (%q, %q, %v), want fail-closed nil-context result", receipt.Status(), receipt.ReasonCode(), err)
	}

	failedVerifier := mustVerifier(t, &fakeImmutableTargetReader{err: errors.New("store unavailable")})
	receipt, err = failedVerifier.VerifyCurrent(context.Background(), claim)
	if err == nil || receipt.Status() != ReceiptUnverifiable || receipt.ReasonCode() != ReasonReaderFailure {
		t.Fatalf("reader error result = (%q, %q, %v), want fail-closed reader failure", receipt.Status(), receipt.ReasonCode(), err)
	}
}

func TestVerifierAndReceiptDefensiveCopies(t *testing.T) {
	claim := mustCurrentClaim(t, validClaimInput("src/file.go", 1, 1, "line\n"))
	quote := claim.QuoteBytes()
	quote[0] = 'X'
	if got, want := claim.Quote(), "line\n"; got != want {
		t.Fatalf("Quote() after QuoteBytes mutation = %q, want %q", got, want)
	}

	reader := &fakeImmutableTargetReader{availability: ImmutableTargetAvailable, bytes: []byte("line\n")}
	verifier := mustVerifier(t, reader)
	receipt, err := verifier.VerifyCurrent(context.Background(), claim)
	if err != nil {
		t.Fatalf("VerifyCurrent() error = %v", err)
	}
	excerpt := receipt.Excerpt()
	excerpt[0] = 'X'
	if got, want := string(receipt.Excerpt()), "line\n"; got != want {
		t.Fatalf("Excerpt() after caller mutation = %q, want %q", got, want)
	}

	claimFromReceipt := receipt.Claim()
	receiptQuote := claimFromReceipt.QuoteBytes()
	receiptQuote[0] = 'X'
	if got, want := receipt.Claim().Quote(), "line\n"; got != want {
		t.Fatalf("receipt claim quote after caller mutation = %q, want %q", got, want)
	}
}

func TestNewVerifierRejectsNilAndTypedNilReader(t *testing.T) {
	if _, err := NewVerifier(nil); err == nil {
		t.Fatal("NewVerifier(nil) succeeded")
	}
	var typedNil *fakeImmutableTargetReader
	if _, err := NewVerifier(typedNil); err == nil {
		t.Fatal("NewVerifier(typed nil) succeeded")
	}
}

func validClaimInput(path string, lineStart, lineEnd int, quote string) CurrentClaimInput {
	return CurrentClaimInput{
		TargetSHA256: strings.Repeat("a", sha256.Size*2),
		Side:         SideHead,
		Path:         path,
		LineStart:    lineStart,
		LineEnd:      lineEnd,
		Quote:        quote,
	}
}

func mustCurrentClaim(t *testing.T, input CurrentClaimInput) CurrentClaim {
	t.Helper()
	claim, err := NewCurrentClaim(input)
	if err != nil {
		t.Fatalf("NewCurrentClaim() error = %v", err)
	}
	return claim
}

func mustVerifier(t *testing.T, reader ImmutableTargetReader) *Verifier {
	t.Helper()
	verifier, err := NewVerifier(reader)
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	return verifier
}

func expectedExcerptSHA256(targetHex string, side Side, path string, lineStart, lineEnd int, excerpt []byte) string {
	targetDigest, err := hex.DecodeString(targetHex)
	if err != nil {
		panic(err)
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte("KAR-EVIDENCE-EXCERPT/1"))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write(targetDigest)
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write([]byte(side))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write([]byte(path))
	_, _ = hash.Write([]byte{0})
	var rangeBytes [16]byte
	binary.BigEndian.PutUint64(rangeBytes[:8], uint64(lineStart))
	binary.BigEndian.PutUint64(rangeBytes[8:], uint64(lineEnd))
	_, _ = hash.Write(rangeBytes[:])
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write(excerpt)
	return "sha256:" + hex.EncodeToString(hash.Sum(nil))
}
