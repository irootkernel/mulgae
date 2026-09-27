package mcpentry

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"strconv"
	"unicode/utf8"

	"github.com/irootkernel/mulgae/internal/app/query"
	"github.com/irootkernel/mulgae/internal/domain"
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
	return ResourceRequest{verified: true, rawURI: raw, kind: ResourceFindingDetail, runID: run, findingID: finding, projectBinding: binding, continuation: continuation}, nil
}

func parseVerifiedContentURI(raw string, segments []string, values url.Values) (ResourceRequest, error) {
	invalid := func() (ResourceRequest, error) { return ResourceRequest{}, errInvalidResourceURI }
	request := ResourceRequest{rawURI: raw, runID: segments[0], verified: true}
	switch {
	case len(segments) == 2 && segments[1] == "report":
		request.kind = ResourceReport
	case len(segments) == 4 && segments[1] == "findings" && segments[3] == "evidence" && validFindingID(segments[2]):
		request.kind = ResourceEvidence
		request.findingID = segments[2]
	default:
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
		case "target_sha256":
			if request.kind != ResourceEvidence || !validSHA256(items[0]) {
				return invalid()
			}
			request.targetSHA256 = items[0]
		case "role":
			if request.kind != ResourceReport || !domain.Role(items[0]).Valid() {
				return invalid()
			}
			request.role = items[0]
		case "evidence_index":
			n, err := strconv.Atoi(items[0])
			if request.kind != ResourceEvidence || err != nil || n <= 0 || n >= 20 || strconv.Itoa(n) != items[0] {
				return invalid()
			}
			request.evidenceIndex = n
		case "offset":
			n, err := strconv.ParseInt(items[0], 10, 64)
			if err != nil || n <= 0 || strconv.FormatInt(n, 10) != items[0] {
				return invalid()
			}
			request.continuation.Offset = n
		default:
			return invalid()
		}
	}
	request.projectBinding = values.Get("project_binding")
	request.continuation.PublicationReceipt = values.Get("publication_receipt")
	request.continuation.ContentSHA256 = values.Get("content_sha256")
	if err := request.continuation.Validate(); err != nil {
		return ResourceRequest{}, err
	}
	canonical := ""
	if request.kind == ResourceReport {
		canonical = query.ReportContentURI(request.runID, request.role, request.projectBinding, request.continuation.PublicationReceipt, request.continuation.ContentSHA256, request.continuation.Offset)
	} else {
		if request.targetSHA256 == "" {
			return invalid()
		}
		canonical = query.EvidenceContentURI(request.runID, request.findingID, request.targetSHA256, request.evidenceIndex, request.projectBinding, request.continuation.PublicationReceipt, request.continuation.ContentSHA256, request.continuation.Offset)
	}
	if canonical != raw {
		return invalid()
	}
	return request, nil
}

func projectVerifiedChunk(request ResourceRequest, content ResourceContent) (ResourceResult, error) {
	chunk := content.Chunk
	if !request.verified || chunk == nil || chunk.RunID != request.runID || !validSHA256(content.ProjectBinding) || !validSHA256(chunk.PublicationReceipt) || !validSHA256(chunk.ContentSHA256) || chunk.Offset != request.continuation.Offset || chunk.ReturnedBytes < 0 || chunk.ReturnedBytes > query.MaxVerifiedContentChunkBytes || chunk.TotalBytes < chunk.Offset || chunk.ReturnedBytes > chunk.TotalBytes-chunk.Offset {
		return ResourceResult{}, fmt.Errorf("verified content chunk is invalid")
	}
	switch request.kind {
	case ResourceFindingDetail:
		if chunk.FindingID != request.findingID || chunk.MediaType != "application/json" || chunk.Encoding != "utf8" {
			return ResourceResult{}, fmt.Errorf("verified finding selector is invalid")
		}
	case ResourceReport:
		if chunk.Role != request.role || chunk.MediaType != "text/markdown" || chunk.Encoding != "utf8" {
			return ResourceResult{}, fmt.Errorf("verified report selector is invalid")
		}
	case ResourceEvidence:
		if chunk.FindingID != request.findingID || chunk.EvidenceIndex == nil || *chunk.EvidenceIndex != request.evidenceIndex || (chunk.MediaType != "text/plain" && chunk.MediaType != "application/octet-stream") {
			return ResourceResult{}, fmt.Errorf("verified evidence selector is invalid")
		}
	default:
		return ResourceResult{}, errInvalidResourceURI
	}
	if request.projectBinding != "" && request.projectBinding != content.ProjectBinding {
		return ResourceResult{}, fmt.Errorf("verified content project changed")
	}
	if request.continuation.PublicationReceipt != "" && request.continuation.PublicationReceipt != chunk.PublicationReceipt {
		return ResourceResult{}, query.ErrPublicationReceiptMismatch
	}
	if request.continuation.ContentSHA256 != "" && request.continuation.ContentSHA256 != chunk.ContentSHA256 {
		return ResourceResult{}, query.ErrContentDigestMismatch
	}
	result := ResourceResult{URI: request.rawURI, MIMEType: chunk.MediaType}
	switch chunk.Encoding {
	case "utf8":
		if !utf8.ValidString(chunk.Content) || int64(len(chunk.Content)) != chunk.ReturnedBytes {
			return ResourceResult{}, fmt.Errorf("invalid UTF-8 content chunk")
		}
		result.Text = chunk.Content
	case "base64":
		data, err := base64.StdEncoding.Strict().DecodeString(chunk.Content)
		if err != nil || int64(len(data)) != chunk.ReturnedBytes {
			return ResourceResult{}, fmt.Errorf("invalid binary content chunk")
		}
		result.Blob = data
	default:
		return ResourceResult{}, fmt.Errorf("invalid content encoding")
	}
	var next any
	if chunk.NextOffset != nil {
		if *chunk.NextOffset != chunk.Offset+chunk.ReturnedBytes || *chunk.NextOffset >= chunk.TotalBytes || *chunk.NextOffset <= chunk.Offset {
			return ResourceResult{}, fmt.Errorf("invalid content continuation")
		}
		switch request.kind {
		case ResourceFindingDetail:
			next = query.FindingDetailURI(request.runID, request.findingID, content.ProjectBinding, chunk.PublicationReceipt, chunk.ContentSHA256, *chunk.NextOffset)
		case ResourceReport:
			next = query.ReportContentURI(request.runID, request.role, content.ProjectBinding, chunk.PublicationReceipt, chunk.ContentSHA256, *chunk.NextOffset)
		case ResourceEvidence:
			next = query.EvidenceContentURI(request.runID, request.findingID, request.targetSHA256, request.evidenceIndex, content.ProjectBinding, chunk.PublicationReceipt, chunk.ContentSHA256, *chunk.NextOffset)
		}
	} else if chunk.Offset+chunk.ReturnedBytes != chunk.TotalBytes {
		return ResourceResult{}, fmt.Errorf("invalid content EOF")
	}
	result.Meta = map[string]any{"publication_receipt": chunk.PublicationReceipt, "content_sha256": chunk.ContentSHA256, "project_binding": content.ProjectBinding, "media_type": chunk.MediaType, "encoding": chunk.Encoding, "offset": chunk.Offset, "total_bytes": chunk.TotalBytes, "returned_bytes": chunk.ReturnedBytes, "next_offset": chunk.NextOffset, "run_id": chunk.RunID, "io.mulgae/nextURI": next}
	if chunk.FindingID != "" {
		result.Meta["finding_id"] = chunk.FindingID
	}
	if chunk.Role != "" {
		result.Meta["role"] = chunk.Role
	}
	if chunk.EvidenceIndex != nil {
		result.Meta["evidence_index"] = *chunk.EvidenceIndex
	}
	return result, nil
}
