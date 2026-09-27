package query

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/irootkernel/mulgae/internal/domain"
)

const (
	InspectionReceiptVersion     = "mulgae-publication-receipt.v1"
	FindingCursorVersion         = "mulgae-finding-cursor.v1"
	DefaultFindingPageSize       = 100
	MaxFindingPageSize           = 1000
	MaxVerifiedContentChunkBytes = 16 * 1024
)

type ReadContractError string

func (err ReadContractError) Error() string { return string(err) }

const (
	ErrPublicationReceiptMismatch ReadContractError = "publication_receipt_mismatch"
	ErrCursorInvalid              ReadContractError = "cursor_invalid"
	ErrCursorMismatch             ReadContractError = "cursor_mismatch"
	ErrContentDigestMismatch      ReadContractError = "content_digest_mismatch"
	ErrReadContinuationIncomplete ReadContractError = "read_continuation_incomplete"
)

// InspectionReceipt binds one already verified publication and its support.
// Construction does not read storage or confer publication authority. The query
// service must verify and reobserve the complete P2 snapshot before returning it.
type InspectionReceipt struct {
	SchemaVersion       string `json:"schema_version"`
	ProjectBinding      string `json:"project_binding"`
	SessionID           string `json:"session_id"`
	RunID               string `json:"run_id"`
	ReviewID            string `json:"review_id"`
	RunType             string `json:"run_type"`
	TargetSHA256        string `json:"target_sha256"`
	FinalSHA256         string `json:"final_sha256"`
	ManifestSHA256      string `json:"manifest_sha256"`
	SupportSHA256       string `json:"support_sha256"`
	LineageSHA256       string `json:"lineage_sha256"`
	Epoch               uint64 `json:"epoch"`
	CaptureIdentity     string `json:"capture_identity"`
	CaptureAvailability string `json:"capture_availability"`
}

func DecodeInspectionReceipt(data []byte) (InspectionReceipt, error) {
	var receipt InspectionReceipt
	if err := decodeStrictDTO(data, &receipt); err != nil {
		return InspectionReceipt{}, fmt.Errorf("publication receipt: invalid JSON")
	}
	if _, err := receipt.Identity(); err != nil {
		return InspectionReceipt{}, err
	}
	canonical, err := json.Marshal(receipt)
	var compact bytes.Buffer
	if err != nil || json.Compact(&compact, data) != nil || !bytes.Equal(canonical, compact.Bytes()) {
		return InspectionReceipt{}, fmt.Errorf("publication receipt: noncanonical encoding")
	}
	return receipt, nil
}

func (receipt InspectionReceipt) Identity() (domain.PublicationReceipt, error) {
	invalid := func() (domain.PublicationReceipt, error) {
		return domain.PublicationReceipt{}, fmt.Errorf("publication receipt: invalid verified identity")
	}
	if receipt.SchemaVersion != InspectionReceiptVersion || receipt.Epoch == 0 {
		return invalid()
	}
	if _, err := domain.ParseSessionID(receipt.SessionID); err != nil {
		return invalid()
	}
	if _, err := domain.ParseRunID(receipt.RunID); err != nil {
		return invalid()
	}
	if _, err := domain.ParseReviewID(receipt.ReviewID); err != nil {
		return invalid()
	}
	if !domain.RunType(receipt.RunType).Valid() {
		return invalid()
	}
	for _, digest := range []string{receipt.ProjectBinding, receipt.TargetSHA256, receipt.FinalSHA256, receipt.ManifestSHA256, receipt.SupportSHA256} {
		if !readDigestValid(digest) {
			return invalid()
		}
	}
	if receipt.LineageSHA256 != "" && !readDigestValid(receipt.LineageSHA256) {
		return invalid()
	}
	switch receipt.CaptureAvailability {
	case "verified":
		if !readDigestValid(receipt.CaptureIdentity) {
			return invalid()
		}
	case "capture_identity_unavailable":
		if receipt.CaptureIdentity != "" {
			return invalid()
		}
	default:
		return invalid()
	}
	data, err := json.Marshal(receipt)
	if err != nil {
		return domain.PublicationReceipt{}, err
	}
	return domain.ParsePublicationReceipt(readContractDigest(InspectionReceiptVersion, data))
}

// FindingPageScope contains every selector whose change invalidates a cursor.
// Limit is bound too: changing a page size starts a new explicit query.
type FindingPageScope struct {
	ProjectBinding     string `json:"project_binding"`
	PublicationReceipt string `json:"publication_receipt"`
	RunID              string `json:"run_id"`
	QueryKind          string `json:"query_kind"`
	MinimumSeverity    string `json:"minimum_severity"`
	Limit              int    `json:"limit"`
}

func (scope FindingPageScope) Validate() error {
	if !readDigestValid(scope.ProjectBinding) || !readDigestValid(scope.PublicationReceipt) || scope.Limit < 1 || scope.Limit > MaxFindingPageSize {
		return ErrCursorInvalid
	}
	if _, err := domain.ParseRunID(scope.RunID); err != nil {
		return ErrCursorInvalid
	}
	if scope.QueryKind != "inspect" && scope.QueryKind != "findings" {
		return ErrCursorInvalid
	}
	// Preserve the existing severity floor rather than silently relabeling info.
	if scope.MinimumSeverity != "low" && scope.MinimumSeverity != "medium" && scope.MinimumSeverity != "high" && scope.MinimumSeverity != "critical" && scope.MinimumSeverity != "blocker" {
		return ErrCursorInvalid
	}
	return nil
}

type findingCursor struct {
	SchemaVersion string           `json:"schema_version"`
	Scope         FindingPageScope `json:"scope"`
	Offset        uint64           `json:"offset"`
}

// EncodeFindingCursor is an integrity envelope, not a secret or authorization
// token. Consumers still verify the named publication and query on every page.
func EncodeFindingCursor(scope FindingPageScope, offset uint64) (string, error) {
	if err := scope.Validate(); err != nil {
		return "", err
	}
	if offset == 0 || offset%uint64(scope.Limit) != 0 {
		return "", ErrCursorInvalid
	}
	data, err := json.Marshal(findingCursor{FindingCursorVersion, scope, offset})
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(data) + "." + strings.TrimPrefix(readContractDigest(FindingCursorVersion, data), "sha256:"), nil
}

func DecodeFindingCursor(value string, expected FindingPageScope) (uint64, error) {
	if err := expected.Validate(); err != nil {
		return 0, err
	}
	if len(value) > 4096 {
		return 0, ErrCursorInvalid
	}
	parts := strings.Split(value, ".")
	if len(parts) != 2 {
		return 0, ErrCursorInvalid
	}
	data, err := base64.RawURLEncoding.Strict().DecodeString(parts[0])
	if err != nil || base64.RawURLEncoding.EncodeToString(data) != parts[0] || readContractDigest(FindingCursorVersion, data) != "sha256:"+parts[1] {
		return 0, ErrCursorInvalid
	}
	var cursor findingCursor
	if err := decodeStrictDTO(data, &cursor); err != nil || cursor.SchemaVersion != FindingCursorVersion || cursor.Scope.Validate() != nil || cursor.Offset == 0 {
		return 0, ErrCursorInvalid
	}
	canonical, err := json.Marshal(cursor)
	if err != nil || !bytes.Equal(data, canonical) || cursor.Offset%uint64(cursor.Scope.Limit) != 0 {
		return 0, ErrCursorInvalid
	}
	if cursor.Scope != expected {
		return 0, ErrCursorMismatch
	}
	return cursor.Offset, nil
}

func FindingPageLimit(value int) (int, error) {
	if value == 0 {
		return DefaultFindingPageSize, nil
	}
	if value < 1 || value > MaxFindingPageSize {
		return 0, ErrCursorInvalid
	}
	return value, nil
}

// ContentContinuation validates an exact byte-offset continuation. The service
// additionally checks an issued boundary, total size, and the observed identities.
// No total-content ceiling is derived from the per-response chunk bound.
type ContentContinuation struct {
	Offset             int64
	PublicationReceipt string
	ContentSHA256      string
}

func (continuation ContentContinuation) Validate() error {
	if continuation.Offset < 0 {
		return ErrCursorInvalid
	}
	if continuation.Offset > 0 && (continuation.PublicationReceipt == "" || continuation.ContentSHA256 == "") {
		return ErrReadContinuationIncomplete
	}
	if continuation.PublicationReceipt != "" && !readDigestValid(continuation.PublicationReceipt) {
		return ErrCursorInvalid
	}
	if continuation.ContentSHA256 != "" && !readDigestValid(continuation.ContentSHA256) {
		return ErrCursorInvalid
	}
	return nil
}

func (continuation ContentContinuation) Check(receipt domain.PublicationReceipt, contentSHA256 string) error {
	if err := continuation.Validate(); err != nil {
		return err
	}
	if !receipt.Valid() || (continuation.PublicationReceipt != "" && continuation.PublicationReceipt != receipt.String()) {
		return ErrPublicationReceiptMismatch
	}
	if !readDigestValid(contentSHA256) || (continuation.ContentSHA256 != "" && continuation.ContentSHA256 != contentSHA256) {
		return ErrContentDigestMismatch
	}
	return nil
}

func readContractDigest(version string, data []byte) string {
	sum := sha256.Sum256(append([]byte(version+"\x00"), data...))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func readDigestValid(value string) bool {
	_, err := domain.ParsePublicationReceipt(value)
	return err == nil
}
