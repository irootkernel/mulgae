package query

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/app/publication"
	"github.com/irootkernel/mulgae/internal/app/validation"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"

	"github.com/irootkernel/mulgae/internal/artifactwire"
)

func TestRequirementsV4NullPreservesLiveSourceBinding(t *testing.T) {
	_, store, _, _ := liveCommittedFixture(t, 1, 1)
	final, err := decodeFinalDTO(store.snapshot.Final().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := decodeManifestDTO(store.snapshot.Manifest().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	final.RequirementsSupport = []byte("null")
	manifest.RequirementsSupport = []byte("null")
	final.SchemaVersion = artifactwire.ReviewArtifactV4
	manifest.SchemaVersion = artifactwire.RunManifestV4
	if _, err := validateLivePublicationBinding(final, manifest); err != nil {
		t.Fatalf("new explicit-null v4 publication lost its live source binding: %v", err)
	}
}

func requirementsReadFixture(t *testing.T, large bool) (*Service, *queryStore, ports.PublicationRun, domain.ProjectBinding) {
	t.Helper()
	service, store, run, binding := liveCommittedFixture(t, 1, 1)
	final, _ := decodeFinalDTO(store.snapshot.Final().Bytes())
	manifest, _ := decodeManifestDTO(store.snapshot.Manifest().Bytes())
	final.SchemaVersion, manifest.SchemaVersion = artifactwire.ReviewArtifactV4, artifactwire.RunManifestV4
	prefix := run.SessionID().String() + "/" + run.RunID().String() + "/"
	indexPath := prefix + "support/index.json"
	var index runtimeSupportIndexDTO
	if err := json.Unmarshal(store.auxiliaryArtifacts[indexPath].Bytes(), &index); err != nil {
		t.Fatal(err)
	}
	index.SchemaVersion = artifactwire.SupportIndexV4
	rawIndex, _ := json.Marshal(index)
	store.auxiliaryArtifacts[indexPath] = mustQueryArtifact(t, mustQueryPath(t, indexPath), rawIndex)
	input := []byte(`{"schema_version":"mulgae-requirements-input.v1","requirements":[{"id":"A","text":"Requirement A","acceptance_criteria":["criterion"],"owner_role":"logic"},{"id":"a","text":"Requirement a","acceptance_criteria":["criterion"],"owner_role":"security"},{"id":"C","text":"Requirement C","acceptance_criteria":["criterion"],"owner_role":"logic"}]}`)
	current := final.Findings[0].Evidence[0].Current
	contents := []validation.RequirementContent{
		{SchemaVersion: validation.RequirementContentVersion, RequirementID: "A", Rationale: "The selected bytes support the criterion.", Evidence: []validation.RequirementContentEvidence{{Current: validation.RequirementCurrentEvidence{SourceIdentitySHA256: current.SourceIdentitySHA256, CurrentExcerptSHA256: current.CurrentExcerptSHA256, Side: validation.CurrentEvidenceSide(current.Side), Path: current.Path, LineStart: current.LineStart, LineEnd: current.LineEnd, Quote: current.Quote, Verification: "verified"}}}, ExaminedScope: "Selected implementation", Limitations: []string{"Fixture evidence only."}},
		{SchemaVersion: validation.RequirementContentVersion, RequirementID: "a", Rationale: "The provider cannot verify this criterion.", Evidence: []validation.RequirementContentEvidence{}, Limitations: []string{"No sufficient evidence."}},
		{SchemaVersion: validation.RequirementContentVersion, RequirementID: "C", Rationale: "No owner answer was admitted.", Evidence: []validation.RequirementContentEvidence{}, Limitations: []string{}},
	}
	if large {
		contents[0].Rationale = strings.Repeat("r", 9<<20)
	}
	items := []map[string]any{}
	additions := map[string][]byte{publication.RequirementsInputPath: input}
	for i, id := range []string{"A", "a", "C"} {
		path := []string{"requirements/items/000.json", "requirements/items/001.json", "requirements/items/002.json"}[i]
		raw, _ := json.Marshal(contents[i])
		additions[path] = raw
		owner, verdict, origin, reason := "logic", "met", "provider", ""
		if i == 1 {
			owner, verdict, reason = "security", "unverified", "insufficient_evidence"
		}
		if i == 2 {
			verdict, origin, reason = "unverified", "mulgae_derived", "answer_omitted"
		}
		items = append(items, map[string]any{"requirement_id": id, "owner_role": owner, "verdict": verdict, "origin": origin, "reason": reason, "content_path": path, "content_sha256": querySHA(raw), "content_byte_length": len(raw)})
	}
	metadata, _ := json.Marshal(map[string]any{"schema_version": publication.RequirementsSupportVersion, "input_path": publication.RequirementsInputPath, "input_sha256": querySHA(input), "input_byte_length": len(input), "availability": "evaluated", "selected_count": 3, "evaluated_count": 2, "items": items})
	additions[publication.RequirementsSupportPath] = metadata
	ref, _ := json.Marshal(artifactIdentityDTO{Path: publication.RequirementsSupportPath, SHA256: querySHA(metadata)})
	final.RequirementsSupport, manifest.RequirementsSupport = ref, ref
	bindContentFixture(t, store, run, final, manifest, additions)
	return service, store, run, binding
}

func TestRequirementsReadPagesKeepGlobalCountsOriginsAndFilters(t *testing.T) {
	service, store, run, binding := requirementsReadFixture(t, false)
	request := InspectionRequest{QueryKind: "inspect", MinimumSeverity: domain.SeverityBlocker, RequirementsLimit: 1}
	var receipt string
	for i, id := range []string{"A", "a", "C"} {
		page, err := service.Inspect(context.Background(), run, binding, request)
		if err != nil {
			t.Fatal(err)
		}
		requirements := page.Requirements
		if requirements == nil || requirements.SchemaVersion != RequirementsReadVersion || requirements.Availability != domain.AssessmentEvaluated || *requirements.SelectedCount != 3 || *requirements.EvaluatedCount != 2 || len(requirements.Items) != 1 || requirements.Items[0].RequirementID != id || page.FindingCount != 0 || len(page.Findings) != 0 {
			t.Fatal("requirements were filtered or page counts replaced whole-set counts")
		}
		if i == 0 {
			receipt = page.PublicationReceipt
		}
		if page.PublicationReceipt != receipt || page.RequirementContentURIs[id] != RequirementContentURI(run.RunID().String(), id, binding.String(), receipt, requirements.Items[0].ContentSHA256, 0) {
			t.Fatal("requirement content link lost its receipt")
		}
		if i == 1 && (requirements.Items[0].Origin != domain.AssessmentProvider || requirements.Items[0].Verdict != domain.RequirementUnverified) {
			t.Fatal("provider unverified became a placeholder")
		}
		if i == 2 && (requirements.Items[0].Origin != domain.AssessmentDerived || requirements.NextCursor != nil) {
			t.Fatal("derived origin or last page changed")
		}
		if requirements.NextCursor != nil {
			request.RequirementsCursor = *requirements.NextCursor
		}
		// A new service verifies the same persisted snapshot on continuation.
		service = mustQueryService(t, store, &queryValidator{}, nil)
	}
	request.RequirementsLimit = 2
	if _, err := service.Inspect(context.Background(), run, binding, request); !errors.Is(err, ErrCursorMismatch) && !errors.Is(err, ErrCursorInvalid) {
		t.Fatalf("changed page scope accepted: %v", err)
	}
}

func TestRequirementsReadRejectsGlobalAndContentTamperOutsidePage(t *testing.T) {
	for _, mode := range []string{"count", "order", "owner", "origin", "duplicate-path", "missing-content", "content-length", "input", "evidence-side", "evidence-digest", "missing-binding"} {
		t.Run(mode, func(t *testing.T) {
			service, store, run, binding := requirementsReadFixture(t, false)
			prefix := run.SessionID().String() + "/" + run.RunID().String() + "/"
			final, _ := decodeFinalDTO(store.snapshot.Final().Bytes())
			manifest, _ := decodeManifestDTO(store.snapshot.Manifest().Bytes())
			metadataPath := prefix + publication.RequirementsSupportPath
			var metadata map[string]any
			if err := json.Unmarshal(store.auxiliaryArtifacts[metadataPath].Bytes(), &metadata); err != nil {
				t.Fatal(err)
			}
			items := metadata["items"].([]any)
			last := items[2].(map[string]any)
			additions := map[string][]byte{}
			switch mode {
			case "count":
				metadata["evaluated_count"] = 1
			case "order":
				items[1], items[2] = items[2], items[1]
			case "owner":
				last["owner_role"] = "security"
			case "origin":
				last["origin"], last["reason"] = "provider", "insufficient_evidence"
			case "duplicate-path":
				last["content_path"] = items[0].(map[string]any)["content_path"]
			case "missing-content":
				delete(store.auxiliaryArtifacts, prefix+last["content_path"].(string))
			case "content-length":
				last["content_byte_length"] = 1
			case "input":
				additions[publication.RequirementsInputPath] = []byte(`{}`)
			case "missing-binding":
				final.RequirementsSupport = nil
			case "evidence-side", "evidence-digest":
				row := items[0].(map[string]any)
				path := row["content_path"].(string)
				var content validation.RequirementContent
				if err := json.Unmarshal(store.auxiliaryArtifacts[prefix+path].Bytes(), &content); err != nil {
					t.Fatal(err)
				}
				if mode == "evidence-side" {
					content.Evidence[0].Current.Side = validation.CurrentEvidenceSide("head")
				} else {
					content.Evidence[0].Current.CurrentExcerptSHA256 = "sha256:" + strings.Repeat("f", 64)
				}
				raw, _ := json.Marshal(content)
				additions[path] = raw
				row["content_sha256"], row["content_byte_length"] = querySHA(raw), len(raw)
			}
			raw, _ := json.Marshal(metadata)
			additions[publication.RequirementsSupportPath] = raw
			ref, _ := json.Marshal(artifactIdentityDTO{Path: publication.RequirementsSupportPath, SHA256: querySHA(raw)})
			if mode != "missing-binding" {
				final.RequirementsSupport = ref
			}
			manifest.RequirementsSupport = ref
			bindContentFixture(t, store, run, final, manifest, additions)
			if _, err := service.Inspect(context.Background(), run, binding, InspectionRequest{QueryKind: "inspect", RequirementsLimit: 1}); err == nil {
				t.Fatal("unserved selected support corruption was accepted")
			}
		})
	}
}

func TestRequirementsContentKeepsUnboundedBodyAndReceiptContinuation(t *testing.T) {
	service, store, run, binding := requirementsReadFixture(t, true)
	first, err := service.ReadRequirement(context.Background(), run, binding, "A", ContentContinuation{})
	if err != nil {
		t.Fatal(err)
	}
	if first.TotalBytes <= 9<<20 || first.ReturnedBytes > MaxVerifiedContentChunkBytes || first.NextOffset == nil || first.RequirementID != "A" {
		t.Fatal("large requirement was clipped or not chunked")
	}
	continuation := ContentContinuation{*first.NextOffset, first.PublicationReceipt, first.ContentSHA256}
	if _, err := service.ReadRequirement(context.Background(), run, binding, "A", continuation); err != nil {
		t.Fatal(err)
	}
	continuation.ContentSHA256 = "sha256:" + strings.Repeat("f", 64)
	if _, err := service.ReadRequirement(context.Background(), run, binding, "A", continuation); !errors.Is(err, ErrContentDigestMismatch) {
		t.Fatalf("wrong content digest accepted: %v", err)
	}
	continuation.ContentSHA256 = first.ContentSHA256
	continuation.PublicationReceipt = "sha256:" + strings.Repeat("f", 64)
	if _, err := service.ReadRequirement(context.Background(), run, binding, "A", continuation); !errors.Is(err, ErrPublicationReceiptMismatch) {
		t.Fatalf("wrong receipt accepted: %v", err)
	}
	path := run.SessionID().String() + "/" + run.RunID().String() + "/requirements/items/002.json"
	delete(store.auxiliaryArtifacts, path)
	if _, err := service.ReadRequirement(context.Background(), run, binding, "A", ContentContinuation{}); err == nil {
		t.Fatal("content read skipped another selected item's integrity")
	}
}

func TestRequirementsReadSeparatesLegacyUnknownFromNewNotRequested(t *testing.T) {
	for _, mode := range []string{"historical", "live-v3", "live-v4-null"} {
		t.Run(mode, func(t *testing.T) {
			service, store, run, binding := liveCommittedFixture(t, 1, 1)
			if mode == "historical" {
				service, store, run, binding = inspectionFixture(t, 0)
			}
			if mode == "live-v4-null" {
				final, _ := decodeFinalDTO(store.snapshot.Final().Bytes())
				manifest, _ := decodeManifestDTO(store.snapshot.Manifest().Bytes())
				final.SchemaVersion, manifest.SchemaVersion = artifactwire.ReviewArtifactV4, artifactwire.RunManifestV4
				final.RequirementsSupport, manifest.RequirementsSupport = []byte("null"), []byte("null")
				path := run.SessionID().String() + "/" + run.RunID().String() + "/support/index.json"
				var index runtimeSupportIndexDTO
				if err := json.Unmarshal(store.auxiliaryArtifacts[path].Bytes(), &index); err != nil {
					t.Fatal(err)
				}
				index.SchemaVersion = artifactwire.SupportIndexV4
				raw, _ := json.Marshal(index)
				store.auxiliaryArtifacts[path] = mustQueryArtifact(t, mustQueryPath(t, path), raw)
				manifest.CompositeIdentity.SupportIndex.SHA256 = querySHA(raw)
				rebindInspection(t, store, run, final, manifest)
			}
			page, err := service.Inspect(context.Background(), run, binding, InspectionRequest{QueryKind: "inspect"})
			if err != nil {
				t.Fatal(err)
			}
			r := page.Requirements
			if r == nil || r.InputSHA256 != nil || len(r.Items) != 0 || r.NextCursor != nil {
				t.Fatal("absent support invented input or rows")
			}
			if mode == "live-v4-null" {
				if r.Availability != domain.AssessmentNotRequested || r.SelectedCount == nil || *r.SelectedCount != 0 || r.EvaluatedCount == nil || *r.EvaluatedCount != 0 {
					t.Fatal("new explicit null did not establish not requested")
				}
			} else if r.Availability != domain.AssessmentUnavailable || r.SelectedCount != nil || r.EvaluatedCount != nil {
				t.Fatal("historical capability absence invented zero counts")
			}
			if mode == "historical" && r.Receipt.SchemaVersion != InspectionReceiptVersion {
				t.Fatal("historical receipt acquired live identity")
			}
		})
	}
}

func TestRequirementsReadsRejectConcurrentCleanupAndPublicationChange(t *testing.T) {
	for _, operation := range []string{"inspect", "content"} {
		for _, change := range []string{"cleanup", "epoch"} {
			t.Run(operation+"/"+change, func(t *testing.T) {
				service, store, run, binding := requirementsReadFixture(t, false)
				if change == "epoch" {
					armIdentityChangeAfterSnapshot(t, store, run)
				} else {
					path := run.SessionID().String() + "/" + run.RunID().String() + "/requirements/items/002.json"
					store.afterAuxiliaryFor = map[string]func(){path: func() { store.observeErr = ports.ErrPublicationRunNotFound }}
				}
				if operation == "inspect" {
					page, err := service.Inspect(context.Background(), run, binding, InspectionRequest{QueryKind: "inspect", RequirementsLimit: 1})
					if failureClass(t, err) != domain.FailureArtifact || page.Requirements != nil || len(page.Findings) != 0 {
						t.Fatal("inspection escaped final publication confirmation")
					}
				} else {
					chunk, err := service.ReadRequirement(context.Background(), run, binding, "A", ContentContinuation{})
					if failureClass(t, err) != domain.FailureArtifact || chunk.Content != "" {
						t.Fatal("content escaped final publication confirmation")
					}
				}
			})
		}
	}
}

func TestRequirementsReadMaximumPagesAndCursorScope(t *testing.T) {
	service, store, run, binding := requirementsReadFixture(t, false)
	final, _ := decodeFinalDTO(store.snapshot.Final().Bytes())
	manifest, _ := decodeManifestDTO(store.snapshot.Manifest().Bytes())
	selected := []any{}
	items := []any{}
	additions := map[string][]byte{}
	for i := 0; i < 100; i++ {
		id := fmt.Sprintf("R%03d", i)
		selected = append(selected, map[string]any{"id": id, "text": "Requirement", "acceptance_criteria": []string{"criterion"}, "owner_role": "logic"})
		path := fmt.Sprintf("requirements/items/%03d.json", i)
		content, _ := json.Marshal(validation.RequirementContent{SchemaVersion: validation.RequirementContentVersion, RequirementID: id, Rationale: "Owner answer omitted.", Evidence: []validation.RequirementContentEvidence{}, Limitations: []string{}})
		additions[path] = content
		items = append(items, map[string]any{"requirement_id": id, "owner_role": "logic", "verdict": "unverified", "origin": "mulgae_derived", "reason": "answer_omitted", "content_path": path, "content_sha256": querySHA(content), "content_byte_length": len(content)})
	}
	input, _ := json.Marshal(map[string]any{"schema_version": "mulgae-requirements-input.v1", "requirements": selected})
	additions[validation.RequirementsInputPath] = input
	metadata, _ := json.Marshal(map[string]any{"schema_version": validation.RequirementsSupportVersion, "input_path": validation.RequirementsInputPath, "input_sha256": querySHA(input), "input_byte_length": len(input), "availability": "evaluated", "selected_count": 100, "evaluated_count": 0, "items": items})
	additions[validation.RequirementsSupportPath] = metadata
	ref, _ := json.Marshal(artifactIdentityDTO{Path: validation.RequirementsSupportPath, SHA256: querySHA(metadata)})
	final.RequirementsSupport, manifest.RequirementsSupport = ref, ref
	bindContentFixture(t, store, run, final, manifest, additions)
	request := InspectionRequest{QueryKind: "inspect", RequirementsLimit: 40}
	offset := 0
	firstCursor := ""
	for _, count := range []int{40, 40, 20} {
		page, err := service.Inspect(context.Background(), run, binding, request)
		if err != nil {
			t.Fatal(err)
		}
		result := page.Requirements
		if *result.SelectedCount != 100 || *result.EvaluatedCount != 0 || len(result.Items) != count {
			t.Fatal("maximum selected set was clipped or recounted per page")
		}
		for i, row := range result.Items {
			if row.RequirementID != fmt.Sprintf("R%03d", offset+i) {
				t.Fatal("maximum page order changed")
			}
		}
		offset += count
		if result.NextCursor != nil {
			request.RequirementsCursor = *result.NextCursor
			if firstCursor == "" {
				firstCursor = *result.NextCursor
			}
		} else if offset != 100 {
			t.Fatal("early final page")
		}
	}
	for _, cursor := range []string{"invalid", firstCursor + "=", strings.Repeat("x", 4097)} {
		request.RequirementsCursor = cursor
		if _, err := service.Inspect(context.Background(), run, binding, request); !errors.Is(err, ErrCursorInvalid) {
			t.Fatalf("invalid requirements cursor accepted: %v", err)
		}
	}
	request.RequirementsCursor = firstCursor
	request.RequirementsLimit = 20
	if _, err := service.Inspect(context.Background(), run, binding, request); !errors.Is(err, ErrCursorMismatch) {
		t.Fatalf("cursor limit scope lost: %v", err)
	}
	otherBinding, _ := domain.ParseProjectBinding("sha256:" + strings.Repeat("f", 64))
	request.RequirementsLimit = 40
	if _, err := service.Inspect(context.Background(), run, otherBinding, request); !errors.Is(err, ErrCursorMismatch) {
		t.Fatalf("cursor binding scope lost: %v", err)
	}
}
