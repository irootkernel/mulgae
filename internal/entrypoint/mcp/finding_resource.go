package mcpentry

import (
	"fmt"
	"net/url"
	"strconv"
	"unicode/utf8"

	"github.com/irootkernel/mulgae/internal/app/query"
)

func parseFindingDetailURI(raw, run, finding string, values url.Values) (ResourceRequest, error) {
	invalid := func() (ResourceRequest, error) { return ResourceRequest{}, errInvalidResourceURI }
	if !validFindingID(finding) {
		return invalid()
	}
	for key, items := range values {
		if len(items) != 1 || items[0] == "" {
			return invalid()
		}
		switch key {
		case "project_binding", "publication_receipt", "content_sha256":
			if !validSHA256(items[0]) {
				return invalid()
			}
		case "offset":
		default:
			return invalid()
		}
	}
	continuation := query.ContentContinuation{PublicationReceipt: values.Get("publication_receipt"), ContentSHA256: values.Get("content_sha256")}
	if rawOffset, ok := values["offset"]; ok {
		n, err := strconv.ParseInt(rawOffset[0], 10, 64)
		if err != nil || n <= 0 || strconv.FormatInt(n, 10) != rawOffset[0] {
			return invalid()
		}
		continuation.Offset = n
	}
	if err := continuation.Validate(); err != nil {
		return ResourceRequest{}, err
	}
	binding := values.Get("project_binding")
	if raw != query.FindingDetailURI(run, finding, binding, continuation.PublicationReceipt, continuation.ContentSHA256, continuation.Offset) {
		return invalid()
	}
	return ResourceRequest{rawURI: raw, kind: ResourceFindingDetail, runID: run, findingID: finding, projectBinding: binding, continuation: continuation}, nil
}

func projectFindingChunk(request ResourceRequest, content ResourceContent) (ResourceResult, error) {
	chunk := content.Chunk
	if request.kind != ResourceFindingDetail || chunk == nil || chunk.RunID != request.runID || chunk.FindingID != request.findingID || chunk.MediaType != "application/json" || chunk.Encoding != "utf8" || !validSHA256(content.ProjectBinding) || !validSHA256(chunk.PublicationReceipt) || !validSHA256(chunk.ContentSHA256) || chunk.Offset != request.continuation.Offset || chunk.ReturnedBytes != int64(len(chunk.Content)) || chunk.ReturnedBytes > query.MaxVerifiedContentChunkBytes || !utf8.ValidString(chunk.Content) {
		return ResourceResult{}, fmt.Errorf("verified finding chunk is invalid")
	}
	if request.projectBinding != "" && request.projectBinding != content.ProjectBinding {
		return ResourceResult{}, fmt.Errorf("verified finding project changed")
	}
	if request.continuation.PublicationReceipt != "" && request.continuation.PublicationReceipt != chunk.PublicationReceipt {
		return ResourceResult{}, query.ErrPublicationReceiptMismatch
	}
	if request.continuation.ContentSHA256 != "" && request.continuation.ContentSHA256 != chunk.ContentSHA256 {
		return ResourceResult{}, query.ErrContentDigestMismatch
	}
	var next any
	if chunk.NextOffset != nil {
		if *chunk.NextOffset != chunk.Offset+chunk.ReturnedBytes || *chunk.NextOffset >= chunk.TotalBytes || *chunk.NextOffset <= chunk.Offset {
			return ResourceResult{}, fmt.Errorf("invalid finding continuation")
		}
		next = query.FindingDetailURI(request.runID, request.findingID, content.ProjectBinding, chunk.PublicationReceipt, chunk.ContentSHA256, *chunk.NextOffset)
	} else if chunk.Offset+chunk.ReturnedBytes != chunk.TotalBytes {
		return ResourceResult{}, fmt.Errorf("invalid finding EOF")
	}
	return ResourceResult{URI: request.rawURI, MIMEType: chunk.MediaType, Text: chunk.Content, Meta: map[string]any{
		"publication_receipt": chunk.PublicationReceipt, "content_sha256": chunk.ContentSHA256, "project_binding": content.ProjectBinding, "media_type": chunk.MediaType, "encoding": chunk.Encoding, "offset": chunk.Offset, "total_bytes": chunk.TotalBytes, "returned_bytes": chunk.ReturnedBytes, "next_offset": chunk.NextOffset, "run_id": chunk.RunID, "finding_id": chunk.FindingID, "io.mulgae/nextURI": next,
	}}, nil
}
