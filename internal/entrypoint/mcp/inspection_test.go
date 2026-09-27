package mcpentry

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/app/query"
	"github.com/irootkernel/mulgae/internal/domain"
)

func (fake *toolBackendFake) InspectReview(ctx context.Context, input ListFindingsInput) (map[string]any, error) {
	return fake.ListFindings(ctx, input)
}
func (fake *invocationBackendFake) InspectReview(ctx context.Context, input ListFindingsInput) (map[string]any, error) {
	return fake.ListFindings(ctx, input)
}

func TestFindingDetailResourceContinuationsAndCanonicalSelectors(t *testing.T) {
	run := "r_01900000-0000-7000-8000-000000000002"
	digest := "sha256:" + strings.Repeat("1", 64)
	receipt, _ := domain.ParsePublicationReceipt(digest)
	content := []byte(strings.Repeat("가", 20000))
	uri := query.FindingDetailURI(run, "F001", digest, digest, "", 0)
	var reconstructed []byte
	for {
		request, err := ParseResourceURI(uri)
		if err != nil {
			t.Fatal(err)
		}
		chunk, err := query.NewContentChunk(content, "application/json", true, receipt, request.Continuation())
		if err != nil {
			t.Fatal(err)
		}
		chunk.RunID = run
		chunk.FindingID = "F001"
		result, err := projectResource(request, ResourceContent{Chunk: &chunk, ProjectBinding: digest})
		if err != nil {
			t.Fatal(err)
		}
		if err = result.validate(uri); err != nil {
			t.Fatal(err)
		}
		reconstructed = append(reconstructed, result.Text...)
		next := result.Meta["io.mulgae/nextURI"]
		if next == nil {
			break
		}
		uri = next.(string)
	}
	if !bytes.Equal(content, reconstructed) {
		t.Fatal("finding resource truncated UTF-8 content")
	}
	base := "mulgae://runs/" + run + "/findings/F001/detail"
	for _, suffix := range []string{"?offset=0", "?offset=01", "?unknown=1", "?project_binding=" + url.QueryEscape(digest) + "&project_binding=" + url.QueryEscape(digest), "?publication_receipt=" + url.QueryEscape(digest) + "&project_binding=" + url.QueryEscape(digest), "?offset=9223372036854775808"} {
		if _, err := ParseResourceURI(base + suffix); err == nil {
			t.Fatalf("accepted alias: %s", suffix)
		}
	}
	if _, err := ParseResourceURI(base + "?offset=16384"); !errors.Is(err, query.ErrReadContinuationIncomplete) {
		t.Fatal(err)
	}
}

func TestReadContractErrorsPreserveStrongerFailureClasses(t *testing.T) {
	for _, readErr := range []error{query.ErrCursorMismatch, query.ErrPublicationReceiptMismatch, query.ErrContentDigestMismatch, query.ErrReadContinuationIncomplete} {
		public := publicToolError(readErr, toolInspectReview)
		if public.Code != readErr.Error() || public.Class != "usage" {
			t.Fatalf("lost typed reason: %+v", public)
		}
		combined := errors.Join(readErr, context.Canceled)
		public = publicToolError(combined, toolInspectReview)
		if public.Code == readErr.Error() {
			t.Fatal("read mismatch hid cancellation")
		}
	}
}

func TestInspectionProjectionPreservesReceiptIntegerPrecision(t *testing.T) {
	page := query.Inspection{RunID: "r_01900000-0000-7000-8000-000000000002", FindingCount: 1, ReturnedCount: 1, Findings: []query.FindingSummary{{ID: "F10000", Severity: "high", Title: "Boundary", Evidence: []query.FindingEvidenceReference{}}}, Receipt: &query.InspectionReceipt{Epoch: 9007199254740993}}
	data, err := ProjectInspection(page, page.RunID, "high", "findings")
	if err != nil {
		t.Fatal(err)
	}
	if data["receipt"].(map[string]any)["epoch"].(json.Number).String() != "9007199254740993" {
		t.Fatal("publication epoch lost precision")
	}
	if data["findings"].([]any)[0].(map[string]any)["evidence_resource_uri"] != nil {
		t.Fatal("unavailable evidence exposed a URI")
	}
	page.Findings[0].Severity = "low"
	if _, err = ProjectInspection(page, page.RunID, "high", "findings"); err == nil {
		t.Fatal("finding below threshold was accepted")
	}
}

func TestInspectionMaximumPageFitsToolEnvelope(t *testing.T) {
	run := "r_01900000-0000-7000-8000-000000000002"
	digest := "sha256:" + strings.Repeat("1", 64)
	page := query.Inspection{RunID: run, FindingCount: 1000, ReturnedCount: 1000}
	for i := 0; i < 1000; i++ {
		id := fmt.Sprintf("F%03d", i+1)
		finding := query.FindingSummary{ID: id, Severity: "high", Title: strings.Repeat("T", 300), DetailURI: query.FindingDetailURI(run, id, digest, digest, "", 0)}
		for j := 0; j < 20; j++ {
			finding.Evidence = append(finding.Evidence, query.FindingEvidenceReference{Index: j, Availability: "evidence_unavailable"})
		}
		page.Findings = append(page.Findings, finding)
	}
	data, err := ProjectInspection(page, run, "low", "inspect")
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range []string{toolInspectReview, toolListFindings} {
		result, err := newToolSuccess(tool, "i_01900000-0000-7000-8000-000000000001", toolOutcomeSuccess, data)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(result)
		if err != nil || len(raw) <= maxToolResultBytes {
			t.Fatal("fixture does not exercise the previous transport ceiling")
		}
		if _, err = renderToolResult(result); err != nil {
			t.Fatalf("maximum finding page was rejected: %v", err)
		}
	}
}
