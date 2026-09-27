package query

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"unicode/utf8"

	"github.com/irootkernel/mulgae/internal/domain"
)

type ContentChunk struct {
	PublicationReceipt string `json:"publication_receipt"`
	ContentSHA256      string `json:"content_sha256"`
	MediaType          string `json:"media_type"`
	Encoding           string `json:"encoding"`
	Offset             int64  `json:"offset"`
	TotalBytes         int64  `json:"total_bytes"`
	ReturnedBytes      int64  `json:"returned_bytes"`
	NextOffset         *int64 `json:"next_offset"`
	Content            string `json:"content"`
	RunID              string `json:"run_id"`
	FindingID          string `json:"finding_id,omitempty"`
	Role               string `json:"role,omitempty"`
	EvidenceIndex      *int   `json:"evidence_index,omitempty"`
}

// NewContentChunk binds every continuation to complete content and publication.
func NewContentChunk(data []byte, mediaType string, text bool, receipt domain.PublicationReceipt, continuation ContentContinuation) (ContentChunk, error) {
	if text && !utf8.Valid(data) {
		return ContentChunk{}, ErrCursorInvalid
	}
	sum := sha256.Sum256(data)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	if err := continuation.Check(receipt, digest); err != nil {
		return ContentChunk{}, err
	}
	if continuation.Offset > int64(len(data)) || continuation.Offset != 0 && continuation.Offset == int64(len(data)) {
		return ContentChunk{}, ErrCursorInvalid
	}
	start := int64(0)
	for start < continuation.Offset {
		end := contentChunkEnd(data, text, start)
		if end > continuation.Offset {
			return ContentChunk{}, ErrCursorInvalid
		}
		start = end
	}
	end := contentChunkEnd(data, text, start)
	result := ContentChunk{PublicationReceipt: receipt.String(), ContentSHA256: digest, MediaType: mediaType, Encoding: "base64", Offset: start, TotalBytes: int64(len(data)), ReturnedBytes: end - start, Content: base64.StdEncoding.EncodeToString(data[start:end])}
	if text {
		result.Encoding = "utf8"
		result.Content = string(data[start:end])
	}
	if end < int64(len(data)) {
		result.NextOffset = &end
	}
	return result, nil
}
func contentChunkEnd(data []byte, text bool, start int64) int64 {
	end := min(start+MaxVerifiedContentChunkBytes, int64(len(data)))
	if text && end < int64(len(data)) {
		for end > start && !utf8.RuneStart(data[end]) {
			end--
		}
	}
	return end
}
