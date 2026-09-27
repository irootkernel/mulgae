package query

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/app/evidence"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

func bindContentFixture(t *testing.T, store *queryStore, run ports.PublicationRun, final finalDTO, manifest manifestDTO, additions map[string][]byte) {
	t.Helper()
	prefix := run.SessionID().String() + "/" + run.RunID().String() + "/"
	indexPath := prefix + "support/index.json"
	var index runtimeSupportIndexDTO
	if err := json.Unmarshal(store.auxiliaryArtifacts[indexPath].Bytes(), &index); err != nil {
		t.Fatal(err)
	}
	for path, data := range additions {
		path = prefix + path
		artifact := mustQueryArtifact(t, mustQueryPath(t, path), data)
		store.auxiliaryArtifacts[path] = artifact
		found := false
		for i := range index.Artifacts {
			if index.Artifacts[i].Path == path {
				index.Artifacts[i].SHA256 = artifact.SHA256()
				found = true
			}
		}
		if !found {
			index.Artifacts = append(index.Artifacts, artifactIdentityDTO{Path: path, SHA256: artifact.SHA256()})
		}
	}
	sort.Slice(index.Artifacts, func(i, j int) bool { return index.Artifacts[i].Path < index.Artifacts[j].Path })
	raw, err := json.Marshal(index)
	if err != nil {
		t.Fatal(err)
	}
	store.auxiliaryArtifacts[indexPath] = mustQueryArtifact(t, mustQueryPath(t, indexPath), raw)
	manifest.CompositeIdentity.SupportIndex.SHA256 = querySHA(raw)
	rebindInspection(t, store, run, final, manifest)
}

func TestReadContentRoleReportReassemblesAndRejectsTamper(t *testing.T) {
	service, store, run, binding := inspectionFixture(t, 0)
	data := []byte(strings.Repeat("report\t🙂\n", 5000) + "final\n")
	final, _ := decodeFinalDTO(store.snapshot.Final().Bytes())
	manifest, _ := decodeManifestDTO(store.snapshot.Manifest().Bytes())
	manifest.RoleReports[0].SHA256 = querySHA(data)
	manifest.RoleReports[0].ByteLength = len(data)
	bindContentFixture(t, store, run, final, manifest, map[string][]byte{"role-reports/logic.md": data})
	var combined []byte
	continuation := ContentContinuation{}
	for {
		chunk, err := service.ReadReport(context.Background(), run, binding, "logic", continuation, nil)
		if err != nil {
			t.Fatal(err)
		}
		if chunk.Role != "logic" || chunk.RunID != run.RunID().String() || chunk.ContentSHA256 != querySHA(data) || chunk.TotalBytes != int64(len(data)) {
			t.Fatalf("invalid metadata: %+v", chunk)
		}
		combined = append(combined, chunk.Content...)
		if chunk.NextOffset == nil {
			break
		}
		continuation = ContentContinuation{*chunk.NextOffset, chunk.PublicationReceipt, chunk.ContentSHA256}
	}
	if !bytes.Equal(combined, data) {
		t.Fatal("role report bytes changed")
	}
	for _, bad := range []ContentContinuation{{Offset: 1, PublicationReceipt: continuation.PublicationReceipt, ContentSHA256: continuation.ContentSHA256}, {Offset: int64(len(data)), PublicationReceipt: continuation.PublicationReceipt, ContentSHA256: continuation.ContentSHA256}} {
		if _, err := service.ReadReport(context.Background(), run, binding, "logic", bad, nil); !errors.Is(err, ErrCursorInvalid) {
			t.Fatalf("invalid boundary: %v", err)
		}
	}
	if _, err := service.ReadReport(context.Background(), run, binding, "testing", ContentContinuation{}, nil); err == nil {
		t.Fatal("missing role accepted")
	}
	path := run.SessionID().String() + "/" + run.RunID().String() + "/role-reports/logic.md"
	store.auxiliaryArtifacts[path] = mustQueryArtifact(t, mustQueryPath(t, path), []byte("tampered"))
	continuation.PublicationReceipt = "sha256:" + strings.Repeat("9", 64)
	chunk, err := service.ReadReport(context.Background(), run, binding, "logic", continuation, nil)
	if failureClass(t, err) != domain.FailureArtifact || chunk.Content != "" {
		t.Fatalf("tamper lost precedence: %v", err)
	}
}

func TestReadContentRenderedSnapshotReobservesAfterRenderer(t *testing.T) {
	service, store, run, binding := inspectionFixture(t, 0)
	render := func(ctx context.Context, reader ContentReader) ([]byte, error) {
		if _, err := reader.ReadCommitted(ctx, run); err != nil {
			t.Fatal(err)
		}
		store.observation = queryP2Observation(t, run, querySnapshotAtEpoch(t, store.snapshot, 2), domain.JournalCompleted, domain.ExitCommittedPass, 2)
		return []byte("rendered report"), nil
	}
	chunk, err := service.ReadReport(context.Background(), run, binding, "", ContentContinuation{}, render)
	if failureClass(t, err) != domain.FailureArtifact || chunk.Content != "" {
		t.Fatalf("mixed snapshot returned: %v", err)
	}
}

func TestReadContentEveryEvidenceIndexAndMissingSupport(t *testing.T) {
	service, store, run, binding := inspectionFixture(t, 1)
	final, _ := decodeFinalDTO(store.snapshot.Final().Bytes())
	manifest, _ := decodeManifestDTO(store.snapshot.Manifest().Bytes())
	prototype := final.Findings[0].Evidence[0]
	data := [][]byte{[]byte("line one\nline two"), []byte("tab\tline\nlast line\n")}
	final.Findings[0].Evidence = nil
	additions := map[string][]byte{}
	for _, content := range data {
		item := prototype
		item.Current.Quote = string(content)
		claim, err := evidence.NewCurrentClaim(evidence.CurrentClaimInput{TargetSHA256: item.Current.TargetSHA256, Side: evidence.Side(item.Current.Side), Path: item.Current.Path, LineStart: item.Current.LineStart, LineEnd: item.Current.LineEnd, Quote: string(content)})
		if err != nil {
			t.Fatal(err)
		}
		item.Current.CurrentExcerptSHA256, err = claim.ExcerptSHA256(content)
		if err != nil {
			t.Fatal(err)
		}
		item.Source.SourceExcerptSHA256 = item.Current.CurrentExcerptSHA256
		final.Findings[0].Evidence = append(final.Findings[0].Evidence, item)
	}
	sort.Slice(final.Findings[0].Evidence, func(i, j int) bool {
		return final.Findings[0].Evidence[i].Source.SourceExcerptSHA256 < final.Findings[0].Evidence[j].Source.SourceExcerptSHA256
	})
	for i, item := range final.Findings[0].Evidence {
		data[i] = []byte(item.Current.Quote)
		additions["excerpts/F001_"+strconv.Itoa(i+1)+".md"] = data[i]
	}
	bindContentFixture(t, store, run, final, manifest, additions)
	page, err := service.Inspect(context.Background(), run, binding, InspectionRequest{QueryKind: "inspect"})
	if err != nil {
		t.Fatalf("%v: %v", err, errors.Unwrap(err))
	}
	for i, expected := range data {
		chunk, err := service.ReadEvidence(context.Background(), run, binding, "F001", page.TargetSHA256, i, ContentContinuation{PublicationReceipt: page.PublicationReceipt})
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal([]byte(chunk.Content), expected) || chunk.EvidenceIndex == nil || *chunk.EvidenceIndex != i || page.Findings[0].Evidence[i].Availability != "verified" || page.Findings[0].Evidence[i].URI != EvidenceContentURI(run.RunID().String(), "F001", page.TargetSHA256, i, binding.String(), page.PublicationReceipt, querySHA(expected), 0) {
			t.Fatalf("index %d not preserved", i)
		}
	}
	if _, err := service.ReadEvidence(context.Background(), run, binding, "F001", page.TargetSHA256, 2, ContentContinuation{}); err == nil {
		t.Fatal("unbound index accepted")
	}
	path := run.SessionID().String() + "/" + run.RunID().String() + "/excerpts/F001_2.md"
	delete(store.auxiliaryArtifacts, path)
	if _, err := service.ReadEvidence(context.Background(), run, binding, "F001", page.TargetSHA256, 1, ContentContinuation{}); failureClass(t, err) != domain.FailureArtifact {
		t.Fatalf("lost bound support: %v", err)
	}
}

func TestReadContentHasNoReportCeilingAndBinaryChunksAreExact(t *testing.T) {
	service, _, run, binding := inspectionFixture(t, 0)
	data := []byte(strings.Repeat("x", (8<<20)+1))
	render := func(context.Context, ContentReader) ([]byte, error) { return data, nil }
	first, err := service.ReadReport(context.Background(), run, binding, "", ContentContinuation{}, render)
	if err != nil {
		t.Fatal(err)
	}
	last, err := service.ReadReport(context.Background(), run, binding, "", ContentContinuation{Offset: 8 << 20, PublicationReceipt: first.PublicationReceipt, ContentSHA256: first.ContentSHA256}, render)
	if err != nil || last.Content != "x" || last.NextOffset != nil || first.TotalBytes != int64(len(data)) {
		t.Fatalf("total report was capped: %+v %v", last, err)
	}
	identity, _ := domain.ParsePublicationReceipt(first.PublicationReceipt)
	binary := bytes.Repeat([]byte{0, 0xff, 0xfe, 0x80, 0x0a}, 7000)
	var combined []byte
	continuation := ContentContinuation{}
	for {
		chunk, err := NewContentChunk(binary, "application/octet-stream", false, identity, continuation)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := base64.StdEncoding.DecodeString(chunk.Content)
		if err != nil {
			t.Fatal(err)
		}
		combined = append(combined, decoded...)
		if chunk.NextOffset == nil {
			break
		}
		continuation = ContentContinuation{*chunk.NextOffset, chunk.PublicationReceipt, chunk.ContentSHA256}
	}
	if !bytes.Equal(combined, binary) {
		t.Fatal("binary content changed")
	}
}
