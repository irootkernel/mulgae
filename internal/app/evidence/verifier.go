// Package evidence verifies provider current-evidence claims against caller-owned
// immutable target bytes. It intentionally has no source-evidence, publication,
// storage, repair, provider, filesystem, or Git dependencies.
package evidence

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"reflect"
	"strings"
	"unicode/utf8"

	"github.com/irootkernel/mulgae/internal/ports"
	"golang.org/x/text/unicode/norm"
)

const excerptDigestDomain = "Mulgae-EVIDENCE-EXCERPT/1"

// Side identifies one captured side of a current review target.
type Side string

const (
	SideBase     Side = "base"
	SideHead     Side = "head"
	SideWorktree Side = "worktree"
	SideIndex    Side = "index"
)

// Valid reports whether side is one of the closed current-target sides.
func (side Side) Valid() bool {
	switch side {
	case SideBase, SideHead, SideWorktree, SideIndex:
		return true
	default:
		return false
	}
}

// ImmutableTargetAvailability is the typed result of looking up immutable
// target bytes. Readers must return Available only for the exact requested
// target identity. Stale and Unavailable never authorize byte verification.
type ImmutableTargetAvailability string

const (
	ImmutableTargetAvailable   ImmutableTargetAvailability = "available"
	ImmutableTargetStale       ImmutableTargetAvailability = "stale"
	ImmutableTargetUnavailable ImmutableTargetAvailability = "unavailable"
)

// Valid reports whether availability is a closed immutable-reader fact.
func (availability ImmutableTargetAvailability) Valid() bool {
	switch availability {
	case ImmutableTargetAvailable, ImmutableTargetStale, ImmutableTargetUnavailable:
		return true
	default:
		return false
	}
}

// ImmutableTargetReader is the consumer-owned port for exact immutable file
// bytes. The returned bytes must be newly allocated and owned by the caller.
// It receives the canonical target SHA-256, side, and SafeRelativePath that
// define the requested immutable file. A reader reports stale or unavailable
// lookup facts through ImmutableTargetAvailability rather than inferring them
// from provider output.
type ImmutableTargetReader interface {
	ReadImmutableTarget(context.Context, string, Side, ports.SafeRelativePath) (ImmutableTargetAvailability, []byte, error)
}

// CurrentClaimInput contains only a provider's untrusted location-and-quote
// claim plus a target SHA-256 supplied by trusted application code. There is
// deliberately no provider-supplied verification, excerpt digest, or source
// reference field.
type CurrentClaimInput struct {
	TargetSHA256 string
	Side         Side
	Path         string
	LineStart    int
	LineEnd      int
	Quote        string
}

// CurrentClaim is an immutable, canonical current-evidence claim. Its target
// identity comes from the application, never from a provider verification
// assertion.
type CurrentClaim struct {
	targetSHA256 string
	targetDigest [sha256.Size]byte
	side         Side
	path         ports.SafeRelativePath
	lineStart    int
	lineEnd      int
	quote        []byte
}

// NewCurrentClaim validates and canonicalizes one current-evidence claim.
// TargetSHA256 accepts either lower-case hexadecimal or sha256:<hex> and is
// stored as sha256:<hex>. Path is converted to ports.SafeRelativePath only
// after UTF-8 NFC and logical-target-path checks succeed.
func NewCurrentClaim(input CurrentClaimInput) (CurrentClaim, error) {
	targetSHA256, targetDigest, err := canonicalTargetSHA256(input.TargetSHA256)
	if err != nil {
		return CurrentClaim{}, fmt.Errorf("current evidence claim: %w", err)
	}
	if !input.Side.Valid() {
		return CurrentClaim{}, fmt.Errorf("current evidence claim: invalid side %q", input.Side)
	}
	path, err := canonicalCurrentPath(input.Path)
	if err != nil {
		return CurrentClaim{}, fmt.Errorf("current evidence claim: %w", err)
	}
	if input.LineStart <= 0 || input.LineEnd <= 0 {
		return CurrentClaim{}, fmt.Errorf("current evidence claim: line range must be positive")
	}
	if input.LineEnd < input.LineStart {
		return CurrentClaim{}, fmt.Errorf("current evidence claim: line end precedes line start")
	}
	if input.Quote == "" || !utf8.ValidString(input.Quote) {
		return CurrentClaim{}, fmt.Errorf("current evidence claim: quote must be non-empty valid UTF-8")
	}
	return CurrentClaim{
		targetSHA256: targetSHA256,
		targetDigest: targetDigest,
		side:         input.Side,
		path:         path,
		lineStart:    input.LineStart,
		lineEnd:      input.LineEnd,
		quote:        []byte(input.Quote),
	}, nil
}

// TargetSHA256 returns the canonical sha256:<lowercase-hex> target identity.
func (claim CurrentClaim) TargetSHA256() string { return claim.targetSHA256 }

// Side returns the claimed immutable target side.
func (claim CurrentClaim) Side() Side { return claim.side }

// Path returns the canonical relative logical target path.
func (claim CurrentClaim) Path() ports.SafeRelativePath { return claim.path }

// LineStart returns the one-based inclusive first line.
func (claim CurrentClaim) LineStart() int { return claim.lineStart }

// LineEnd returns the one-based inclusive final line.
func (claim CurrentClaim) LineEnd() int { return claim.lineEnd }

// Quote returns the exact UTF-8 quote text. It does not trim or normalize it.
func (claim CurrentClaim) Quote() string { return string(claim.quote) }

// QuoteBytes returns a defensive copy of the exact quote bytes.
func (claim CurrentClaim) QuoteBytes() []byte { return append([]byte(nil), claim.quote...) }

// ExcerptSHA256 computes the canonical source/current excerpt identity for
// exact bytes under this claim. It does not assert that the bytes were read from
// an immutable target; callers must retain a verifier-owned receipt for that
// authority.
func (claim CurrentClaim) ExcerptSHA256(excerpt []byte) (string, error) {
	if claim.validationReason() != ReasonVerified {
		return "", fmt.Errorf("current evidence claim is invalid")
	}
	if len(excerpt) == 0 {
		return "", fmt.Errorf("excerpt must be non-empty")
	}
	return excerptSHA256(claim, excerpt), nil
}

func (claim CurrentClaim) validationReason() ReasonCode {
	targetSHA256, targetDigest, err := canonicalTargetSHA256(claim.targetSHA256)
	if err != nil || targetSHA256 != claim.targetSHA256 || targetDigest != claim.targetDigest {
		return ReasonInvalidClaim
	}
	if !claim.side.Valid() {
		return ReasonInvalidClaim
	}
	path, err := canonicalCurrentPath(claim.path.String())
	if err != nil || path != claim.path {
		return ReasonInvalidPath
	}
	if claim.lineStart <= 0 || claim.lineEnd < claim.lineStart {
		return ReasonInvalidLineRange
	}
	if len(claim.quote) == 0 || !utf8.Valid(claim.quote) {
		return ReasonInvalidClaim
	}
	return ReasonVerified
}

// ReceiptStatus is the closed verification outcome computed only by this
// package. Providers cannot construct receipts or set this status.
type ReceiptStatus string

const (
	ReceiptVerified     ReceiptStatus = "verified"
	ReceiptStale        ReceiptStatus = "stale"
	ReceiptInvalid      ReceiptStatus = "invalid"
	ReceiptUnverifiable ReceiptStatus = "unverifiable"
)

// Valid reports whether status is a closed verification outcome.
func (status ReceiptStatus) Valid() bool {
	switch status {
	case ReceiptVerified, ReceiptStale, ReceiptInvalid, ReceiptUnverifiable:
		return true
	default:
		return false
	}
}

// ReasonCode is a safe, closed diagnostic classification. It never embeds
// provider bytes, filesystem paths, or reader error strings.
type ReasonCode string

const (
	ReasonVerified                  ReasonCode = "verified"
	ReasonStaleTarget               ReasonCode = "stale_target"
	ReasonInvalidClaim              ReasonCode = "invalid_claim"
	ReasonInvalidPath               ReasonCode = "invalid_path"
	ReasonInvalidLineRange          ReasonCode = "invalid_line_range"
	ReasonLineRangeOutOfBounds      ReasonCode = "line_range_out_of_bounds"
	ReasonQuoteMismatch             ReasonCode = "quote_mismatch"
	ReasonTargetUnavailable         ReasonCode = "target_unavailable"
	ReasonReaderFailure             ReasonCode = "reader_failure"
	ReasonInvalidReaderAvailability ReasonCode = "invalid_reader_availability"
	ReasonNilReader                 ReasonCode = "nil_reader"
	ReasonNilContext                ReasonCode = "nil_context"
	ReasonContextCanceled           ReasonCode = "context_canceled"
)

// Valid reports whether code is a closed safe diagnostic classification.
func (code ReasonCode) Valid() bool {
	switch code {
	case ReasonVerified,
		ReasonStaleTarget,
		ReasonInvalidClaim,
		ReasonInvalidPath,
		ReasonInvalidLineRange,
		ReasonLineRangeOutOfBounds,
		ReasonQuoteMismatch,
		ReasonTargetUnavailable,
		ReasonReaderFailure,
		ReasonInvalidReaderAvailability,
		ReasonNilReader,
		ReasonNilContext,
		ReasonContextCanceled:
		return true
	default:
		return false
	}
}

// CurrentReceipt is an immutable system-owned result. Claim preserves the
// canonical input identity. ExcerptSHA256 is populated only after immutable
// bytes selected a valid line range; Excerpt exposes bytes only when verified.
type CurrentReceipt struct {
	claim           CurrentClaim
	status          ReceiptStatus
	reason          ReasonCode
	excerptSHA256   string
	verifiedExcerpt []byte
}

// Claim returns the canonical current claim identity that was verified.
func (receipt CurrentReceipt) Claim() CurrentClaim { return receipt.claim }

// Status returns the system-computed closed verification status.
func (receipt CurrentReceipt) Status() ReceiptStatus { return receipt.status }

// ReasonCode returns the system-computed safe diagnostic code.
func (receipt CurrentReceipt) ReasonCode() ReasonCode { return receipt.reason }

// ExcerptSHA256 returns the canonical excerpt digest only when immutable bytes
// selected a valid range. A quote mismatch has a digest but never exposes its
// selected bytes.
func (receipt CurrentReceipt) ExcerptSHA256() string { return receipt.excerptSHA256 }

// Excerpt returns a defensive copy of the verified excerpt. It returns nil for
// stale, invalid, and unverifiable receipts even if a range was selected.
func (receipt CurrentReceipt) Excerpt() []byte {
	if receipt.status != ReceiptVerified {
		return nil
	}
	return append([]byte(nil), receipt.verifiedExcerpt...)
}

// Verifier owns the consumer-side immutable target reader used for current
// evidence verification.
type Verifier struct {
	reader ImmutableTargetReader
}

// NewVerifier creates a current-evidence verifier. A nil or typed-nil reader
// is rejected before it can weaken verification.
func NewVerifier(reader ImmutableTargetReader) (*Verifier, error) {
	if nilImmutableTargetReader(reader) {
		return nil, fmt.Errorf("current evidence verifier: nil immutable target reader")
	}
	return &Verifier{reader: reader}, nil
}

// VerifyCurrent validates claim identity, obtains immutable target bytes, and
// computes the receipt. Invalid evidence outcomes are returned as receipts;
// context and reader operation failures also return an error so callers retain
// cancellation and operational control flow while remaining fail-closed.
func (verifier *Verifier) VerifyCurrent(ctx context.Context, claim CurrentClaim) (CurrentReceipt, error) {
	if verifier == nil || nilImmutableTargetReader(verifier.reader) {
		return newReceipt(claim, ReceiptUnverifiable, ReasonNilReader, "", nil), fmt.Errorf("current evidence verification: nil immutable target reader")
	}
	if ctx == nil {
		return newReceipt(claim, ReceiptUnverifiable, ReasonNilContext, "", nil), fmt.Errorf("current evidence verification: nil context")
	}
	if err := ctx.Err(); err != nil {
		return newReceipt(claim, ReceiptUnverifiable, ReasonContextCanceled, "", nil), fmt.Errorf("current evidence verification: context: %w", err)
	}
	if reason := claim.validationReason(); reason != ReasonVerified {
		return newReceipt(claim, ReceiptInvalid, reason, "", nil), nil
	}

	availability, targetBytes, err := verifier.reader.ReadImmutableTarget(ctx, claim.targetSHA256, claim.side, claim.path)
	if err != nil {
		return newReceipt(claim, ReceiptUnverifiable, ReasonReaderFailure, "", nil), fmt.Errorf("current evidence verification: immutable target read: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return newReceipt(claim, ReceiptUnverifiable, ReasonContextCanceled, "", nil), fmt.Errorf("current evidence verification: context: %w", err)
	}

	switch availability {
	case ImmutableTargetStale:
		return newReceipt(claim, ReceiptStale, ReasonStaleTarget, "", nil), nil
	case ImmutableTargetUnavailable:
		return newReceipt(claim, ReceiptUnverifiable, ReasonTargetUnavailable, "", nil), nil
	case ImmutableTargetAvailable:
		// Continue below.
	default:
		return newReceipt(claim, ReceiptUnverifiable, ReasonInvalidReaderAvailability, "", nil), fmt.Errorf("current evidence verification: invalid immutable target availability")
	}

	excerpt, ok := selectExcerpt(targetBytes, claim.lineStart, claim.lineEnd)
	if !ok {
		return newReceipt(claim, ReceiptInvalid, ReasonLineRangeOutOfBounds, "", nil), nil
	}
	excerptSHA256 := excerptSHA256(claim, excerpt)
	if !bytes.Equal(claim.quote, excerpt) {
		return newReceipt(claim, ReceiptInvalid, ReasonQuoteMismatch, excerptSHA256, nil), nil
	}
	return newReceipt(claim, ReceiptVerified, ReasonVerified, excerptSHA256, excerpt), nil
}

func newReceipt(claim CurrentClaim, status ReceiptStatus, reason ReasonCode, excerptSHA256 string, verifiedExcerpt []byte) CurrentReceipt {
	receipt := CurrentReceipt{
		claim:         claim,
		status:        status,
		reason:        reason,
		excerptSHA256: excerptSHA256,
	}
	if status == ReceiptVerified {
		receipt.verifiedExcerpt = append([]byte(nil), verifiedExcerpt...)
	}
	return receipt
}

func canonicalTargetSHA256(value string) (string, [sha256.Size]byte, error) {
	var raw [sha256.Size]byte
	digest := strings.TrimPrefix(value, "sha256:")
	if len(digest) != sha256.Size*2 {
		return "", raw, fmt.Errorf("target SHA-256 must be 64 lowercase hexadecimal characters")
	}
	for _, character := range digest {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return "", raw, fmt.Errorf("target SHA-256 must be 64 lowercase hexadecimal characters")
		}
	}
	decoded, err := hex.DecodeString(digest)
	if err != nil {
		return "", raw, fmt.Errorf("target SHA-256 must be 64 lowercase hexadecimal characters")
	}
	copy(raw[:], decoded)
	return "sha256:" + digest, raw, nil
}

func canonicalCurrentPath(value string) (ports.SafeRelativePath, error) {
	if !utf8.ValidString(value) {
		return ports.SafeRelativePath{}, fmt.Errorf("path must be valid UTF-8")
	}
	if norm.NFC.String(value) != value {
		return ports.SafeRelativePath{}, fmt.Errorf("path must be UTF-8 NFC")
	}
	if strings.ContainsAny(value, "\x00\r\n") {
		return ports.SafeRelativePath{}, fmt.Errorf("path must not contain NUL or line breaks")
	}
	path, err := ports.NewSafeRelativePath(value)
	if err != nil {
		return ports.SafeRelativePath{}, fmt.Errorf("invalid path: %w", err)
	}
	return path, nil
}

func selectExcerpt(target []byte, lineStart, lineEnd int) ([]byte, bool) {
	if len(target) == 0 || lineStart <= 0 || lineEnd < lineStart {
		return nil, false
	}

	line := 1
	currentStart := 0
	for line < lineStart {
		newline := bytes.IndexByte(target[currentStart:], '\n')
		if newline < 0 {
			return nil, false
		}
		currentStart += newline + 1
		if currentStart == len(target) {
			return nil, false
		}
		line++
	}
	startOffset := currentStart

	for {
		newline := bytes.IndexByte(target[currentStart:], '\n')
		if line == lineEnd {
			if newline < 0 {
				return append([]byte(nil), target[startOffset:]...), true
			}
			endOffset := currentStart + newline + 1
			return append([]byte(nil), target[startOffset:endOffset]...), true
		}
		if newline < 0 {
			return nil, false
		}
		currentStart += newline + 1
		if currentStart == len(target) {
			return nil, false
		}
		line++
	}
}

func excerptSHA256(claim CurrentClaim, excerpt []byte) string {
	hash := sha256.New()
	_, _ = hash.Write([]byte(excerptDigestDomain))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write(claim.targetDigest[:])
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write([]byte(claim.side))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write([]byte(claim.path.String()))
	_, _ = hash.Write([]byte{0})

	var rangeBytes [16]byte
	binary.BigEndian.PutUint64(rangeBytes[:8], uint64(claim.lineStart))
	binary.BigEndian.PutUint64(rangeBytes[8:], uint64(claim.lineEnd))
	_, _ = hash.Write(rangeBytes[:])
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write(excerpt)
	return "sha256:" + hex.EncodeToString(hash.Sum(nil))
}

func nilImmutableTargetReader(reader ImmutableTargetReader) bool {
	if reader == nil {
		return true
	}
	value := reflect.ValueOf(reader)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}
