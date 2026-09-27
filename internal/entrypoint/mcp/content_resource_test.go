package mcpentry

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/app/query"
	"github.com/irootkernel/mulgae/internal/domain"
)

func TestVerifiedContentResourceSelectorsAndLegacyOffsets(t *testing.T) {
	run := "r_019f596a-cfe4-7c9c-b82e-7149158243ba"
	digest := "sha256:" + strings.Repeat("a", 64)
	report := query.ReportContentURI(run, "logic", digest, digest, digest, 16384)
	evidence := query.EvidenceContentURI(run, "F001", digest, 1, digest, digest, digest, 16384)
	for _, uri := range []string{report, evidence} {
		request, err := ParseResourceURI(uri)
		if err != nil || !request.Verified() || request.Continuation().Offset != 16384 || request.ProjectBinding() != digest {
			t.Fatalf("lost selector: %+v %v", request, err)
		}
	}
	for _, uri := range []string{
		strings.Replace(report, "role=logic", "role=unknown", 1),
		report + "&role=logic",
		strings.Replace(report, "role=logic", "role=%6Cogic", 1),
		strings.Replace(report, "role=logic&project_binding=", "project_binding="+strings.Repeat("a", 2)+"&role=logic&project_binding=", 1),
		strings.Replace(evidence, "evidence_index=1", "evidence_index=0", 1),
		strings.Replace(evidence, "evidence_index=1", "evidence_index=20", 1),
		strings.Replace(evidence, "offset=16384", "offset=016384", 1),
		strings.Replace(evidence, "offset=16384", "offset=9223372036854775808", 1),
		query.ReportContentURI(run, "logic", "", "", "", 16384),
	} {
		if _, err := ParseResourceURI(uri); err == nil {
			t.Fatalf("accepted %s", uri)
		}
	}
	uri := query.ReportContentURI(run, "logic", "", "", "", 16384)
	if _, err := ParseResourceURI(uri); !errors.Is(err, query.ErrReadContinuationIncomplete) {
		t.Fatalf("continuation error: %v", err)
	}
	legacy, err := ParseResourceURI("mulgae://runs/" + run + "/report?offset=9223372036854775807")
	if err != nil || legacy.Verified() {
		t.Fatalf("legacy total offset ceiling: %v", err)
	}
}

func TestVerifiedContentResourcesReassembleTextAndBinary(t *testing.T) {
	run := "r_019f596a-cfe4-7c9c-b82e-7149158243ba"
	digest := "sha256:" + strings.Repeat("a", 64)
	receipt, _ := domain.ParsePublicationReceipt(digest)
	for _, text := range []bool{true, false} {
		data := bytes.Repeat([]byte{0, 0xff, 0x0a, 0x80}, 9000)
		uri := query.EvidenceContentURI(run, "F001", digest, 1, digest, digest, "", 0)
		media := "application/octet-stream"
		if text {
			data = []byte(strings.Repeat("🙂\tline\n", 6000))
			media = "text/markdown"
			uri = query.ReportContentURI(run, "logic", digest, digest, "", 0)
		}
		var combined []byte
		for {
			request, err := ParseResourceURI(uri)
			if err != nil {
				t.Fatal(err)
			}
			chunk, err := query.NewContentChunk(data, media, text, receipt, request.Continuation())
			if err != nil {
				t.Fatal(err)
			}
			chunk.RunID = run
			if text {
				chunk.Role = "logic"
			} else {
				index := 1
				chunk.FindingID = "F001"
				chunk.EvidenceIndex = &index
			}
			result, err := projectResource(request, ResourceContent{Chunk: &chunk, ProjectBinding: digest})
			if err != nil {
				t.Fatal(err)
			}
			if err := result.validate(uri); err != nil {
				t.Fatal(err)
			}
			if text {
				combined = append(combined, result.Text...)
			} else {
				combined = append(combined, result.Blob...)
			}
			if result.Meta["io.mulgae/nextURI"] == nil {
				break
			}
			uri = result.Meta["io.mulgae/nextURI"].(string)
			if !strings.Contains(uri, "publication_receipt=") || !strings.Contains(uri, "content_sha256=") {
				t.Fatal("unbound continuation")
			}
		}
		if !bytes.Equal(combined, data) {
			t.Fatal("resource changed bytes")
		}
	}
}
