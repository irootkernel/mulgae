package mcpentry

import (
	"bytes"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/app/query"
	"github.com/irootkernel/mulgae/internal/domain"
)

func TestLiveEvidenceResourceSelectorsAndBinaryContinuations(t *testing.T) {
	run := "r_019f596a-cf80-7c67-b265-f37053d51ccf"
	source, binding, receipt := "sha256:"+strings.Repeat("a", 64), "sha256:"+strings.Repeat("b", 64), "sha256:"+strings.Repeat("c", 64)
	textURI := query.SourceEvidenceContentURI(run, "F001", source, 0, binding, receipt, "", 0)
	request, err := ParseResourceURI(textURI)
	if err != nil || !request.Verified() || request.SourceIdentitySHA256() != source || request.TargetSHA256() != "" {
		t.Fatalf("source evidence selector: %+v %v", request, err)
	}
	imageURI := query.SourceImageContentURI(run, source, "worktree", "images/a b.png", binding, receipt, "", 0)
	request, err = ParseResourceURI(imageURI)
	if err != nil || request.Kind() != ResourceSourceImage || request.SourcePath() != "images/a b.png" {
		t.Fatalf("source image selector: %+v %v", request, err)
	}
	image := append([]byte{137, 80, 78, 71, 13, 10, 26, 10}, bytes.Repeat([]byte{0}, query.MaxVerifiedContentChunkBytes+1)...)
	publication, _ := domain.ParsePublicationReceipt(receipt)
	chunk, err := query.NewContentChunk(image, "image/png", false, publication, query.ContentContinuation{})
	if err != nil {
		t.Fatal(err)
	}
	chunk.RunID = run
	result, err := projectVerifiedChunk(request, ResourceContent{Chunk: &chunk, ProjectBinding: binding})
	if err != nil || !bytes.Equal(result.Blob, image[:chunk.ReturnedBytes]) || result.Meta["source_identity_sha256"] != source {
		t.Fatalf("binary source content: %v", err)
	}
	next, err := ParseResourceURI(result.Meta["io.mulgae/nextURI"].(string))
	if err != nil || next.SourceIdentitySHA256() != source || next.SourcePath() != request.SourcePath() || next.SourceSide() != request.SourceSide() || next.Continuation().ContentSHA256 != chunk.ContentSHA256 || next.Continuation().Offset != chunk.ReturnedBytes {
		t.Fatalf("image continuation changed authority: %+v %v", next, err)
	}
	chunk.MediaType = "text/plain"
	if _, err := projectVerifiedChunk(request, ResourceContent{Chunk: &chunk, ProjectBinding: binding}); err == nil {
		t.Fatal("image was projected as text")
	}
	for _, invalid := range []string{
		textURI + "&target_sha256=" + source,
		query.SourceImageContentURI(run, source, "worktree", "../auth.json", binding, receipt, "", 0),
		query.SourceImageContentURI(run, source, "unknown", "image.png", binding, receipt, "", 0),
		query.SourceImageContentURI(run, "", "worktree", "image.png", binding, receipt, "", 0),
		query.SourceEvidenceContentURI(run, "F001", source, 20, binding, receipt, "", 0),
	} {
		if _, err := ParseResourceURI(invalid); err == nil {
			t.Fatalf("malformed source resource admitted: %s", invalid)
		}
	}
}
