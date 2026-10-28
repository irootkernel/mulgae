package mcpentry

import (
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/app/query"
	"github.com/irootkernel/mulgae/internal/domain"
)

func TestRequirementsResourceBindsCanonicalChunksAndContinuation(t *testing.T) {
	run := "r_01900000-0000-7000-8000-000000000002"
	binding := "sha256:" + strings.Repeat("1", 64)
	receipt, _ := domain.ParsePublicationReceipt("sha256:" + strings.Repeat("2", 64))
	chunk, err := query.NewContentChunk([]byte(strings.Repeat("content🙂", 3000)), "application/json", true, receipt, query.ContentContinuation{})
	if err != nil {
		t.Fatal(err)
	}
	chunk.RunID, chunk.RequirementID = run, "A_a-1"
	uri := query.RequirementContentURI(run, chunk.RequirementID, binding, chunk.PublicationReceipt, chunk.ContentSHA256, 0)
	request, err := ParseResourceURI(uri)
	if err != nil || !request.Verified() || request.Kind() != ResourceRequirement || request.RequirementID() != chunk.RequirementID {
		t.Fatalf("requirement URI rejected: %v", err)
	}
	result, err := projectResource(request, ResourceContent{Chunk: &chunk, ProjectBinding: binding})
	if err != nil || result.Text != chunk.Content || result.Meta["requirement_id"] != chunk.RequirementID {
		t.Fatalf("requirement content lost identity: %v", err)
	}
	next, ok := result.Meta["io.mulgae/nextURI"].(string)
	if !ok || chunk.NextOffset == nil {
		t.Fatal("missing continuation URI")
	}
	continued, err := ParseResourceURI(next)
	if err != nil || continued.Continuation().Offset != *chunk.NextOffset || continued.Continuation().ContentSHA256 != chunk.ContentSHA256 || continued.Continuation().PublicationReceipt != chunk.PublicationReceipt {
		t.Fatalf("continuation lost binding: %v", err)
	}
	chunk.RequirementID = "other"
	if _, err := projectResource(request, ResourceContent{Chunk: &chunk, ProjectBinding: binding}); err == nil {
		t.Fatal("cross-item chunk accepted")
	}
	for _, bad := range []string{
		"mulgae://runs/" + run + "/requirements/../A",
		"mulgae://runs/" + run + "/requirements/%41",
		"mulgae://runs/" + run + "/requirements/A?offset=16384",
		uri + "&role=logic", uri + "&content_sha256=" + chunk.ContentSHA256,
	} {
		if _, err := ParseResourceURI(bad); err == nil {
			t.Fatal("noncanonical requirement URI accepted")
		}
	}
}
