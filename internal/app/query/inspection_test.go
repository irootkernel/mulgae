package query

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/app/capture"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

func inspectionFixture(t *testing.T, count int) (*Service, *queryStore, ports.PublicationRun, domain.ProjectBinding) {
	t.Helper()
	run, snapshot, _, artifacts, _ := queryStatusRoleReportFixture(t)
	final, err := decodeFinalDTO(snapshot.Final().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	prototype := final.Findings[0]
	final.Findings = []finalFindingDTO{}
	final.RoleOutcomes[0].ValidFindingIDs = []string{}
	for i := 0; i < count; i++ {
		f := prototype
		f.ID = fmt.Sprintf("F%03d", i+1)
		f.Fingerprint = querySHA([]byte(f.ID))
		f.Evidence = append([]finalEvidenceDTO(nil), prototype.Evidence...)
		for j := range f.Evidence {
			f.Evidence[j].Source.FindingID = f.ID
		}
		final.Findings = append(final.Findings, f)
		final.RoleOutcomes[0].ValidFindingIDs = append(final.RoleOutcomes[0].ValidFindingIDs, f.ID)
	}
	exitCode := domain.ExitCommittedCIRejected
	if count == 0 {
		final.ContentVerdict = string(domain.ContentNoFindings)
		final.CIDecision = string(domain.CIPass)
		final.CIReasonCodes = []string{"policy_evaluated"}
		exitCode = domain.ExitCommittedPass
	}
	finalBytes, _ := json.Marshal(final)
	id, _ := ports.NewFinalReviewIdentity(snapshot.Final().Identity().ReviewID(), snapshot.Final().Identity().Path(), querySHA(finalBytes))
	artifact, _ := ports.NewFinalReviewArtifact(id, finalBytes)
	manifest, _ := decodeManifestDTO(snapshot.Manifest().Bytes())
	manifest.ExitCode = int(exitCode)
	manifest.ContentVerdict = final.ContentVerdict
	manifest.CIDecision = final.CIDecision
	manifest.CIReasonCodes = final.CIReasonCodes
	manifest.FinalReview.SHA256 = id.SHA256()
	manifest.RecoveryJournal.ExpectedFinal.SHA256 = id.SHA256()
	manifestBytes, _ := json.Marshal(manifest)
	snapshot, err = ports.NewCommittedPublicationSnapshot(artifact, mustQueryArtifact(t, snapshot.Manifest().Path(), manifestBytes), snapshot.LineageEdge(), snapshot.Epoch())
	if err != nil {
		t.Fatal(err)
	}
	store := &queryStore{snapshot: snapshot, observation: queryP2Observation(t, run, snapshot, domain.JournalCompleted, exitCode, 1), auxiliaryArtifacts: artifacts}
	binding, _ := domain.ParseProjectBinding("sha256:" + strings.Repeat("1", 64))
	return mustQueryService(t, store, &queryValidator{}, nil), store, run, binding
}

func TestInspectionPagesBindOnePublicationAndPreserveTotal(t *testing.T) {
	for _, count := range []int{0, 1, 2, 3, 4} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			service, _, run, binding := inspectionFixture(t, count)
			request := InspectionRequest{QueryKind: "inspect", MinimumSeverity: domain.SeverityLow, Limit: 2}
			var ids []string
			receipt := ""
			for {
				page, err := service.Inspect(context.Background(), run, binding, request)
				if err != nil {
					t.Fatalf("%v: %v", err, errors.Unwrap(err))
				}
				if page.FindingCount != count || page.ReturnedCount != len(page.Findings) || page.ReturnedCount > 2 {
					t.Fatalf("bad counts: %+v", page)
				}
				if page.CaptureAvailability != "capture_identity_unavailable" || page.CaptureIdentity != "" || page.Receipt == nil {
					t.Fatalf("historical capture: %+v", page)
				}
				if receipt != "" && receipt != page.PublicationReceipt {
					t.Fatal("receipt changed")
				}
				receipt = page.PublicationReceipt
				for _, f := range page.Findings {
					ids = append(ids, f.ID)
					if f.DetailURI == "" || f.Fingerprint == "" {
						t.Fatal("missing reference")
					}
				}
				if page.NextCursor == "" {
					break
				}
				request.Cursor = page.NextCursor
				request.ExpectedPublicationReceipt = receipt
			}
			if len(ids) != count {
				t.Fatalf("lost findings: %v", ids)
			}
			for i, id := range ids {
				if id != fmt.Sprintf("F%03d", i+1) {
					t.Fatal("changed ordering")
				}
			}
		})
	}
}

func TestInspectionRejectsForeignCursorsAndReceipt(t *testing.T) {
	service, _, run, binding := inspectionFixture(t, 3)
	base := InspectionRequest{QueryKind: "inspect", MinimumSeverity: domain.SeverityLow, Limit: 2}
	page, err := service.Inspect(context.Background(), run, binding, base)
	if err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*InspectionRequest){"filter": func(r *InspectionRequest) { r.MinimumSeverity = domain.SeverityHigh }, "limit": func(r *InspectionRequest) { r.Limit = 1 }, "kind": func(r *InspectionRequest) { r.QueryKind = "findings" }} {
		t.Run(name, func(t *testing.T) {
			r := base
			r.Cursor = page.NextCursor
			change(&r)
			if _, err := service.Inspect(context.Background(), run, binding, r); !errors.Is(err, ErrCursorMismatch) {
				t.Fatalf("got %v", err)
			}
		})
	}
	r := base
	r.Cursor = page.NextCursor
	foreign, _ := domain.ParseProjectBinding("sha256:" + strings.Repeat("2", 64))
	if _, err := service.Inspect(context.Background(), run, foreign, r); !errors.Is(err, ErrCursorMismatch) {
		t.Fatal(err)
	}
	r = base
	r.ExpectedPublicationReceipt = foreign.String()
	if _, err := service.Inspect(context.Background(), run, binding, r); !errors.Is(err, ErrPublicationReceiptMismatch) {
		t.Fatal(err)
	}
	scope := FindingPageScope{binding.String(), page.PublicationReceipt, run.RunID().String(), "inspect", "low", 2}
	r = base
	r.Cursor, _ = EncodeFindingCursor(scope, 4)
	if _, err := service.Inspect(context.Background(), run, binding, r); !errors.Is(err, ErrCursorInvalid) {
		t.Fatal(err)
	}
}

func TestInspectionRejectsCorruptionBeforeExpectedReceipt(t *testing.T) {
	service, store, run, binding := inspectionFixture(t, 1)
	for path := range store.auxiliaryArtifacts {
		if strings.HasSuffix(path, "/support/index.json") {
			delete(store.auxiliaryArtifacts, path)
		}
	}
	_, err := service.Inspect(context.Background(), run, binding, InspectionRequest{QueryKind: "inspect", ExpectedPublicationReceipt: "sha256:" + strings.Repeat("9", 64)})
	if failureClass(t, err) != domain.FailureArtifact {
		t.Fatal(err)
	}
}

func TestInspectionRejectsCleanupAndEpochChangeDuringSupportRead(t *testing.T) {
	for _, cleanup := range []bool{false, true} {
		t.Run(fmt.Sprint(cleanup), func(t *testing.T) {
			service, store, run, binding := inspectionFixture(t, 1)
			store.afterAuxiliary = func() {
				store.afterAuxiliary = nil
				if cleanup {
					store.observeErr = ports.ErrPublicationRunNotFound
				} else {
					changed := querySnapshotAtEpoch(t, store.snapshot, 2)
					store.observation = queryP2Observation(t, run, changed, domain.JournalCompleted, domain.ExitCommittedCIRejected, 2)
				}
			}
			page, err := service.Inspect(context.Background(), run, binding, InspectionRequest{QueryKind: "inspect"})
			if failureClass(t, err) != domain.FailureArtifact || page.PublicationReceipt != "" {
				t.Fatalf("mixed result: %+v/%v", page, err)
			}
		})
	}
}

func TestReadFindingReturnsBoundCompleteJSON(t *testing.T) {
	service, store, run, binding := inspectionFixture(t, 1)
	first, err := service.ReadFinding(context.Background(), run, binding, "F001", ContentContinuation{})
	if err != nil {
		t.Fatal(err)
	}
	var f finalFindingDTO
	if err = json.Unmarshal([]byte(first.Content), &f); err != nil || f.ID != "F001" || f.Description != "description" {
		t.Fatalf("lost detail: %v/%v", f, err)
	}
	if first.NextOffset != nil || first.ReturnedBytes != first.TotalBytes || first.PublicationReceipt == "" {
		t.Fatalf("bad chunk: %+v", first)
	}
	store.auxiliaryErr = errors.New("removed support")
	if _, err := service.ReadFinding(context.Background(), run, binding, "F001", ContentContinuation{PublicationReceipt: first.PublicationReceipt}); failureClass(t, err) != domain.FailureArtifact {
		t.Fatal(err)
	}
}

func TestReadFindingRejectsChangedBoundExcerpt(t *testing.T) {
	service, store, run, binding := inspectionFixture(t, 1)
	prefix := run.SessionID().String() + "/" + run.RunID().String()
	path := prefix + "/excerpts/F001_1.md"
	artifact := mustQueryArtifact(t, mustQueryPath(t, path), []byte("line one\nline two"))
	store.auxiliaryArtifacts[path] = artifact
	supportPath := prefix + "/support/index.json"
	var support runtimeSupportIndexDTO
	if err := json.Unmarshal(store.auxiliaryArtifacts[supportPath].Bytes(), &support); err != nil {
		t.Fatal(err)
	}
	support.Artifacts = append(support.Artifacts, artifactIdentityDTO{Path: path, SHA256: artifact.SHA256()})
	sort.Slice(support.Artifacts, func(i, j int) bool { return support.Artifacts[i].Path < support.Artifacts[j].Path })
	encoded, err := json.Marshal(support)
	if err != nil {
		t.Fatal(err)
	}
	store.auxiliaryArtifacts[supportPath] = mustQueryArtifact(t, mustQueryPath(t, supportPath), encoded)
	final, _ := decodeFinalDTO(store.snapshot.Final().Bytes())
	manifest, _ := decodeManifestDTO(store.snapshot.Manifest().Bytes())
	manifest.CompositeIdentity.SupportIndex.SHA256 = querySHA(encoded)
	rebindInspection(t, store, run, final, manifest)
	if _, err := service.ReadFinding(context.Background(), run, binding, "F001", ContentContinuation{}); err != nil {
		t.Fatal(err)
	}
	store.auxiliaryArtifacts[path] = mustQueryArtifact(t, mustQueryPath(t, path), []byte("changed excerpt"))
	chunk, err := service.ReadFinding(context.Background(), run, binding, "F001", ContentContinuation{})
	if err == nil {
		t.Fatal("returned finding detail after bound excerpt changed")
	}
	if failureClass(t, err) != domain.FailureArtifact || chunk.Content != "" {
		t.Fatalf("returned unverified content: %+v / %v", chunk, err)
	}
}

func TestContentChunksReassembleUTF8AndRejectUnissuedBoundaries(t *testing.T) {
	receipt, _ := domain.ParsePublicationReceipt("sha256:" + strings.Repeat("1", 64))
	data := []byte(strings.Repeat("a", MaxVerifiedContentChunkBytes-1) + strings.Repeat("가", 12000))
	continuation := ContentContinuation{}
	var got []byte
	for {
		chunk, err := NewContentChunk(data, "application/json", true, receipt, continuation)
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, []byte(chunk.Content)...)
		if chunk.ReturnedBytes > MaxVerifiedContentChunkBytes {
			t.Fatal("oversized chunk")
		}
		if chunk.NextOffset == nil {
			break
		}
		continuation = ContentContinuation{*chunk.NextOffset, chunk.PublicationReceipt, chunk.ContentSHA256}
	}
	if !bytes.Equal(data, got) {
		t.Fatal("content changed")
	}
	continuation.Offset = 1
	if _, err := NewContentChunk(data, "text/plain", true, receipt, continuation); !errors.Is(err, ErrCursorInvalid) {
		t.Fatal(err)
	}
	if _, err := NewContentChunk(data, "text/plain", true, receipt, ContentContinuation{Offset: 1}); !errors.Is(err, ErrReadContinuationIncomplete) {
		t.Fatal(err)
	}
	empty, err := NewContentChunk(nil, "text/plain", true, receipt, ContentContinuation{})
	if err != nil || empty.NextOffset != nil || empty.ReturnedBytes != 0 {
		t.Fatal("empty content rejected")
	}
}

func rebindInspection(t *testing.T, store *queryStore, run ports.PublicationRun, final finalDTO, manifest manifestDTO) {
	t.Helper()
	raw, err := json.Marshal(final)
	if err != nil {
		t.Fatal(err)
	}
	id, err := ports.NewFinalReviewIdentity(store.snapshot.Final().Identity().ReviewID(), store.snapshot.Final().Identity().Path(), querySHA(raw))
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := ports.NewFinalReviewArtifact(id, raw)
	if err != nil {
		t.Fatal(err)
	}
	manifest.FinalReview.SHA256 = id.SHA256()
	manifest.RecoveryJournal.ExpectedFinal.SHA256 = id.SHA256()
	raw, err = json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	store.snapshot, err = ports.NewCommittedPublicationSnapshot(artifact, mustQueryArtifact(t, store.snapshot.Manifest().Path(), raw), store.snapshot.LineageEdge(), store.snapshot.Epoch())
	if err != nil {
		t.Fatal(err)
	}
	store.observation = queryP2Observation(t, run, store.snapshot, domain.JournalCompleted, domain.OperationalExitCode(manifest.ExitCode), store.snapshot.Epoch().Value())
}

func TestInspectionPreservesReportsOnlyAndMixedAxes(t *testing.T) {
	for _, mixed := range []bool{false, true} {
		t.Run(fmt.Sprint(mixed), func(t *testing.T) {
			service, store, run, binding := inspectionFixture(t, 0)
			final, _ := decodeFinalDTO(store.snapshot.Final().Bytes())
			manifest, _ := decodeManifestDTO(store.snapshot.Manifest().Bytes())
			final.ContentVerdict = string(domain.ContentReportsOnly)
			final.StructuredExtractionStatus = string(domain.StructuredExtractionReportsOnly)
			for i := range manifest.Attempts {
				if !mixed || i == 0 {
					manifest.Attempts[i].ParseState = string(domain.ParseNotStarted)
					manifest.Attempts[i].ValidationState = string(domain.ValidationNotStarted)
				}
			}
			if mixed {
				final.StructuredExtractionStatus = string(domain.StructuredExtractionMixed)
			}
			manifest.ContentVerdict = final.ContentVerdict
			manifest.StructuredExtractionStatus = final.StructuredExtractionStatus
			rebindInspection(t, store, run, final, manifest)
			page, err := service.Inspect(context.Background(), run, binding, InspectionRequest{QueryKind: "inspect"})
			if err != nil {
				t.Fatalf("%v: %v", err, errors.Unwrap(err))
			}
			if page.ContentVerdict != "reports_only" || page.StructuredExtractionStatus != final.StructuredExtractionStatus || page.FindingCount != 0 || len(page.RoleReports) != 2 {
				t.Fatalf("collapsed report-only outcome: %+v", page)
			}
		})
	}
}

func TestReadFindingReassemblesLargeDetailAndRejectsStaleContent(t *testing.T) {
	service, store, run, binding := inspectionFixture(t, 1)
	final, _ := decodeFinalDTO(store.snapshot.Final().Bytes())
	manifest, _ := decodeManifestDTO(store.snapshot.Manifest().Bytes())
	final.Findings[0].Description = strings.Repeat("가", 11000)
	rebindInspection(t, store, run, final, manifest)
	continuation := ContentContinuation{}
	var all []byte
	for {
		chunk, err := service.ReadFinding(context.Background(), run, binding, "F001", continuation)
		if err != nil {
			t.Fatal(err)
		}
		all = append(all, chunk.Content...)
		if chunk.NextOffset == nil {
			break
		}
		continuation = ContentContinuation{*chunk.NextOffset, chunk.PublicationReceipt, chunk.ContentSHA256}
	}
	var got finalFindingDTO
	if err := json.Unmarshal(all, &got); err != nil || got.Description != final.Findings[0].Description {
		t.Fatalf("lost detail: %v", err)
	}
	continuation.ContentSHA256 = "sha256:" + strings.Repeat("8", 64)
	if _, err := service.ReadFinding(context.Background(), run, binding, "F001", continuation); !errors.Is(err, ErrContentDigestMismatch) {
		t.Fatal(err)
	}
}

func TestInspectionVerifiesCompleteCaptureAndRejectsLostBlob(t *testing.T) {
	service, store, run, binding := inspectionFixture(t, 0)
	target, err := ports.NewCapturedReviewPatchTarget([]byte("capture patch\n"))
	if err != nil {
		t.Fatal(err)
	}
	request, err := ports.NewWorkspaceSnapshotRequest(nil, "inspection-capture")
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := ports.NewCapturedTargetEvidence(map[ports.CapturedEvidenceSide][]ports.WorkspaceSnapshotFile{ports.CapturedEvidenceHead: nil})
	if err != nil {
		t.Fatal(err)
	}
	material, err := ports.NewCapturedReviewMaterialWithEvidence(target, request, nil, evidence)
	if err != nil {
		t.Fatal(err)
	}
	captureManifest, err := capture.NewCaptureManifest(material)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := captureManifest.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	identity, err := captureManifest.Identity()
	if err != nil {
		t.Fatal(err)
	}
	archive, err := ports.NewCapturedReviewArchive(material)
	if err != nil {
		t.Fatal(err)
	}
	prefix := run.SessionID().String() + "/" + run.RunID().String() + "/target/"
	additions := map[string][]byte{prefix + "capture-manifest.json": encoded, prefix + "captured-review.json": archive.Manifest()}
	blobPath := ""
	for _, blob := range archive.Blobs() {
		blobPath = prefix + blob.Path().String()
		additions[blobPath] = blob.Bytes()
	}
	supportPath := run.SessionID().String() + "/" + run.RunID().String() + "/support/index.json"
	var support runtimeSupportIndexDTO
	if err = json.Unmarshal(store.auxiliaryArtifacts[supportPath].Bytes(), &support); err != nil {
		t.Fatal(err)
	}
	support.SchemaVersion = "mulgae-run-support-index.v2"
	for path, data := range additions {
		artifact := mustQueryArtifact(t, mustQueryPath(t, path), data)
		store.auxiliaryArtifacts[path] = artifact
		support.Artifacts = append(support.Artifacts, artifactIdentityDTO{path, artifact.SHA256()})
	}
	sort.Slice(support.Artifacts, func(i, j int) bool { return support.Artifacts[i].Path < support.Artifacts[j].Path })
	encoded, err = json.Marshal(support)
	if err != nil {
		t.Fatal(err)
	}
	store.auxiliaryArtifacts[supportPath] = mustQueryArtifact(t, mustQueryPath(t, supportPath), encoded)
	final, _ := decodeFinalDTO(store.snapshot.Final().Bytes())
	manifest, _ := decodeManifestDTO(store.snapshot.Manifest().Bytes())
	final.Target.ContentSHA256 = "sha256:" + target.Identity().SHA256()
	manifest.Target.ContentSHA256 = final.Target.ContentSHA256
	manifest.CompositeIdentity.SupportIndex.SHA256 = querySHA(encoded)
	rebindInspection(t, store, run, final, manifest)
	page, err := service.Inspect(context.Background(), run, binding, InspectionRequest{QueryKind: "inspect"})
	if err != nil {
		t.Fatal(err)
	}
	if page.CaptureAvailability != "verified" || page.CaptureIdentity != identity.String() {
		t.Fatalf("capture unavailable: %+v", page)
	}
	if blobPath == "" {
		t.Fatal("fixture has no blob")
	}
	delete(store.auxiliaryArtifacts, blobPath)
	if _, err = service.Inspect(context.Background(), run, binding, InspectionRequest{QueryKind: "inspect"}); failureClass(t, err) != domain.FailureArtifact {
		t.Fatal(err)
	}
}

func TestInspectionNonP2CannotClaimCommittedContent(t *testing.T) {
	service, store, run, binding := inspectionFixture(t, 1)
	p0, err := ports.NewPublicationObservation(domain.JournalCollecting, domain.DurableObservationP0None, nil, nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	for name, observation := range map[string]ports.PublicationObservation{"P0": p0, "P1": queryP1StatusObservation(t, run, store.snapshot)} {
		t.Run(name, func(t *testing.T) {
			store.observation = observation
			page, err := service.Inspect(context.Background(), run, binding, InspectionRequest{QueryKind: "inspect"})
			if err != nil {
				t.Fatal(err)
			}
			if !page.DiagnosticOnly || page.PublicationReceipt != "" || page.Receipt != nil || page.ContentVerdict != "" || len(page.Findings) != 0 || len(page.RoleReports) != 0 || store.snapshotReads != 0 {
				t.Fatalf("non-P2 claimed publication: %+v", page)
			}
			if _, err = service.Inspect(context.Background(), run, binding, InspectionRequest{QueryKind: "findings"}); failureClass(t, err) != domain.FailureArtifact {
				t.Fatal(err)
			}
		})
	}
}

func TestInspectionMaximumPageRetainsFinalBoundary(t *testing.T) {
	service, _, run, binding := inspectionFixture(t, 1001)
	request := InspectionRequest{QueryKind: "findings", Limit: 1000}
	first, err := service.Inspect(context.Background(), run, binding, request)
	if err != nil {
		t.Fatal(err)
	}
	if first.FindingCount != 1001 || first.ReturnedCount != 1000 || first.NextCursor == "" || first.Findings[999].ID != "F1000" {
		t.Fatal("maximum page lost its boundary")
	}
	request.Cursor = first.NextCursor
	last, err := service.Inspect(context.Background(), run, binding, request)
	if err != nil {
		t.Fatal(err)
	}
	if last.FindingCount != 1001 || last.ReturnedCount != 1 || last.NextCursor != "" || last.Findings[0].ID != "F1001" || last.PublicationReceipt != first.PublicationReceipt {
		t.Fatal("final page changed selection")
	}
}

func TestInspectionObservedCorruptionNeverBecomesDiagnosticSuccess(t *testing.T) {
	service, store, run, binding := inspectionFixture(t, 1)
	observation, err := ports.NewPublicationObservation(domain.JournalCompleted, domain.DurableObservationAmbiguousOrMismatch, nil, []string{"observed_corruption"}, 1)
	if err != nil {
		t.Fatal(err)
	}
	store.observation = observation
	result, err := service.Inspect(context.Background(), run, binding, InspectionRequest{QueryKind: "inspect"})
	if failureClass(t, err) != domain.FailureArtifact || result.DiagnosticOnly || result.PublicationReceipt != "" {
		t.Fatalf("corruption was projected as success: %+v/%v", result, err)
	}
}
