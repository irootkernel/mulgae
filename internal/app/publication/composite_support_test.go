//go:build darwin && arm64

package publication

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/adapters/filesystem"
	"github.com/irootkernel/mulgae/internal/adapters/jsonschema"
	"github.com/irootkernel/mulgae/internal/app/compositesupport"
	appevidence "github.com/irootkernel/mulgae/internal/app/evidence"
	appquery "github.com/irootkernel/mulgae/internal/app/query"
	appreport "github.com/irootkernel/mulgae/internal/app/report"
	"github.com/irootkernel/mulgae/internal/builtin"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

func copiedCompositeInput(t *testing.T) CompositeCandidateInput {
	t.Helper()
	targetBytes := []byte("diff --git a/a.go b/a.go\n")
	target, err := domain.NewTargetIdentity(domain.TargetIdentityInput{Kind: domain.TargetPatch, SHA256: bareSHA256(targetBytes)})
	if err != nil {
		t.Fatal(err)
	}
	root, _ := domain.ParseRunID("r_019f596a-cfe4-7c9c-b82e-7149158243ba")
	sourceRun, _ := domain.ParseRunID("r_019f596a-cfe5-7c9c-b82e-7149158243ba")
	rootReview, _ := domain.ParseReviewID("019f596a-d174-7321-b920-c2d312c82cc2")
	sourceReview, _ := domain.ParseReviewID("019f596a-d175-7321-b920-c2d312c82cc2")
	attempt, _ := domain.ParseAttemptID("a_019f596a-d048-79e7-b2b7-59822f012273")
	session, _ := domain.ParseSessionID("s_019f596a-cf80-7c67-b265-f37053d51ccf")
	coordinate, err := domain.NewCompositionSource(domain.RoleLogic, sourceRun, sourceReview, attempt)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := domain.NewCompositionFingerprint(root, []domain.CompositionSource{coordinate})
	if err != nil {
		t.Fatal(err)
	}
	run, err := fingerprint.RunID()
	if err != nil {
		t.Fatal(err)
	}
	report := []byte("# Logic\n\nNo findings.\n")
	input := CompositeCandidateInput{SessionID: session, RunID: run, Fingerprint: fingerprint, RootRunID: root, RootReviewID: rootReview, Target: target, TargetBytes: targetBytes, Threshold: domain.SeverityHigh, ContentVerdict: domain.ContentNoFindings, CoverageStatus: domain.CoverageComplete, ExtractionStatus: domain.StructuredExtractionStructured, CIDecision: domain.CIPass, CIReasonCodes: []string{"policy_evaluated"}, Sources: []CompositeSourceInput{{Kind: "recovery", Role: domain.RoleLogic, RunID: sourceRun, ReviewID: sourceReview, AttemptID: attempt, RoleReportSHA256: sha256Identifier(report)}}, Roles: []CompositeRoleInput{{Role: domain.RoleLogic, Required: true, Outcome: "completed", AttemptID: attempt, ProviderInstance: "codex-primary", SourceRunID: sourceRun, SourceReviewID: sourceReview, ValidFindingIDs: []string{}}}, RoleReports: []CompositeRoleReportInput{{Role: domain.RoleLogic, AttemptID: attempt, ProviderInstance: "codex-primary", SHA256: sha256Identifier(report), Bytes: report, SourceRunID: sourceRun}}}
	input.SourceSupport = []compositesupport.Material{{Source: compositesupport.Source{Role: domain.RoleLogic, SessionID: session.String(), RunID: sourceRun.String(), ReviewID: sourceReview.String(), AttemptID: attempt.String(), FinalSHA256: sha256Identifier([]byte("source-final")), ManifestSHA256: sha256Identifier([]byte("source-manifest")), SupportSHA256: sha256Identifier([]byte("source-support")), LineageSHA256: sha256Identifier([]byte("source-lineage")), Epoch: 1, TargetSHA256: sha256Identifier(targetBytes), ProviderIdentities: []string{"codex-primary"}, CaptureAvailability: "capture_identity_unavailable"}, Findings: []compositesupport.FindingMaterial{}}}
	return input
}

func copiedCompositeStore(t *testing.T) (*filesystem.PublicationStore, *jsonschema.Validator, publicationServiceClock, ports.AnchoredRoot, string) {
	t.Helper()
	ctx := context.Background()
	validator, err := jsonschema.New(ctx, builtin.NewCatalog())
	if err != nil {
		t.Fatal(err)
	}
	clock := publicationServiceClock{now: time.Date(2026, 7, 13, 3, 10, 0, 0, time.UTC)}
	review, _ := domain.ParseReviewID("019f596a-d176-7321-b920-c2d312c82cc2")
	store, err := filesystem.NewPublicationStore(validator, clock, compositeTestIDs{reviewID: review}, filesystem.NewSecureWriter())
	if err != nil {
		t.Fatal(err)
	}
	path := os.Getenv("MULGAE_TEST_COPIED_COMPOSITE_ROOT")
	if path == "" {
		path = filepath.Join(t.TempDir(), ".mulgae")
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatal(err)
	}
	root, err := ports.NewAnchoredRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	return store, validator, clock, root, path
}

func TestCompositeSupportCandidateBindsPortableSourceReceipt(t *testing.T) {
	input := copiedCompositeInput(t)
	candidate, err := PrepareCompositeCandidate(input)
	if err != nil {
		t.Fatal(err)
	}
	before := candidate.ValidatedCandidateSHA256()
	input.SourceSupport[0].Source.SupportSHA256 = sha256Identifier([]byte("different-source-support"))
	changed, err := PrepareCompositeCandidate(input)
	if err != nil {
		t.Fatal(err)
	}
	if before == changed.ValidatedCandidateSHA256() {
		t.Fatal("candidate digest omitted copied source receipt")
	}
	if candidate.ValidatedCandidateSHA256() != before {
		t.Fatal("prepared candidate aliases caller-owned support")
	}
	if candidate.legacyCandidateSHA256() != changed.legacyCandidateSHA256() {
		t.Fatal("fixture changed more than new support")
	}
}

func TestCompositeSupportPublicationResumesCopiesAtomically(t *testing.T) {
	for _, after := range []int{0, 1, 2, 3, 4, 5} {
		t.Run(fmt.Sprintf("after-%d", after), func(t *testing.T) {
			ctx := context.Background()
			input := copiedCompositeInput(t)
			candidate, err := PrepareCompositeCandidate(input)
			if err != nil {
				t.Fatal(err)
			}
			store, validator, clock, root, _ := copiedCompositeStore(t)
			fault := &compositeInterruptedStore{PublicationStore: store, after: after}
			interrupted, err := NewService(fault, validator, clock, 8<<20)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := interrupted.PublishCompositeNext(ctx, root, candidate); err == nil {
				t.Fatal("copy interruption unexpectedly published")
			}
			queries, err := appquery.NewService(store, validator, nil, 8<<20)
			if err != nil {
				t.Fatal(err)
			}
			run, err := ports.NewPublicationRun(root, input.SessionID, input.RunID)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := queries.ReadCommitted(ctx, run); err == nil {
				t.Fatal("interrupted support copies exposed a readable final")
			}
			changedInput := copiedCompositeInput(t)
			changedInput.SourceSupport[0].Source.ManifestSHA256 = sha256Identifier([]byte("different source manifest"))
			changed, err := PrepareCompositeCandidate(changedInput)
			if err != nil {
				t.Fatal(err)
			}
			resumed, err := NewService(store, validator, clock, 8<<20)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := resumed.PublishCompositeNext(ctx, root, changed); err == nil {
				t.Fatal("resume accepted a different support candidate at the same mapping")
			}
			result, err := resumed.PublishCompositeNext(ctx, root, candidate)
			if err != nil {
				t.Fatal(err)
			}
			if result.Decision().Authority() != domain.PublicationAuthorityP2 {
				t.Fatal("resume omitted P2")
			}
			if _, err := queries.ReadCommitted(ctx, run); err != nil {
				t.Fatalf("resumed self-contained read: %v", err)
			}
			repeated, err := resumed.PublishCompositeNext(ctx, root, candidate)
			if err != nil {
				t.Fatal(err)
			}
			first, _ := result.Final()
			again, _ := repeated.Final()
			if first != again {
				t.Fatal("replay changed immutable final identity")
			}
			if _, err := resumed.PublishCompositeNext(ctx, root, changed); err == nil {
				t.Fatal("P2 replay accepted changed portable source receipt")
			}
		})
	}
}

func TestCompositeSupportLegacyMappingReturnsExistingArtifactUnchanged(t *testing.T) {
	ctx := context.Background()
	input := copiedCompositeInput(t)
	modern, err := PrepareCompositeCandidate(input)
	if err != nil {
		t.Fatal(err)
	}
	input.SourceSupport = nil
	legacy, err := PrepareCompositeCandidate(input)
	if err != nil {
		t.Fatal(err)
	}
	store, validator, clock, root, path := copiedCompositeStore(t)
	service, err := NewService(store, validator, clock, 8<<20)
	if err != nil {
		t.Fatal(err)
	}
	original, err := service.PublishCompositeNext(ctx, root, legacy)
	if err != nil {
		t.Fatal(err)
	}
	before := copiedFiles(t, path)
	replay, err := service.PublishCompositeNext(ctx, root, modern)
	if err != nil {
		t.Fatalf("new writer exact legacy mapping: %v", err)
	}
	originalFinal, _ := original.Final()
	replayFinal, _ := replay.Final()
	if originalFinal != replayFinal {
		t.Fatal("legacy mapping changed final identity")
	}
	after := copiedFiles(t, path)
	if len(before) != len(after) {
		t.Fatal("legacy mapping retrofitted support files")
	}
	for name, raw := range before {
		if !bytes.Equal(raw, after[name]) {
			t.Fatalf("legacy mapping rewrote %s", name)
		}
	}
	changedInput := copiedCompositeInput(t)
	changedInput.CIDecision = domain.CIFail
	changed, err := PrepareCompositeCandidate(changedInput)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.PublishCompositeNext(ctx, root, changed); err == nil {
		t.Fatal("legacy fallback accepted changed non-support inputs")
	}
	reportPath := filepath.Join(path, input.SessionID.String(), input.RunID.String(), "role-reports", "logic.md")
	if err := os.WriteFile(reportPath, []byte("corrupted legacy report"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := service.PublishCompositeNext(ctx, root, modern); err == nil {
		t.Fatal("legacy fallback accepted corrupt immutable support")
	}
}

func copiedFiles(t *testing.T, root string) map[string][]byte {
	t.Helper()
	files := map[string][]byte{}
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		files[relative] = raw
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

func TestCompositeSupportBundleRejectsReboundCopies(t *testing.T) {
	input := copiedCompositeInput(t)
	candidate, err := PrepareCompositeCandidate(input)
	if err != nil {
		t.Fatal(err)
	}
	review, _ := domain.ParseReviewID("019f596a-d176-7321-b920-c2d312c82cc2")
	bundle, err := candidate.Build(context.Background(), &publicationTestValidator{}, review, time.Date(2026, 7, 13, 3, 10, 0, 0, time.UTC), 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateCompositeBundleSemantics(bundle); err != nil {
		t.Fatal(err)
	}
	for i, artifact := range bundle.excerpts {
		if filepath.Base(artifact.Path().String()) != "composite.json" {
			continue
		}
		var doc compositesupport.Document
		if err := json.Unmarshal(artifact.Bytes(), &doc); err != nil {
			t.Fatal(err)
		}
		doc.Sources[0].ProviderIdentities = []string{"different-provider"}
		raw, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		replacement, err := ports.NewImmutablePublicationArtifact(artifact.Path(), sha256Identifier(raw), raw)
		if err != nil {
			t.Fatal(err)
		}
		bundle.excerpts[i] = replacement
		if err := validateCompositeBundleSemantics(bundle); err == nil {
			t.Fatal("bundle accepted changed support without immutable index binding")
		}
		return
	}
	t.Fatal("new support metadata absent")
}

func TestCompositeSupportJournalRecoveryRetainsCopiedReceipt(t *testing.T) {
	for _, after := range []int{-1, -2} {
		for _, recoverFirst := range []bool{false, true} {
			t.Run(fmt.Sprintf("after-%d/recover-%t", after, recoverFirst), func(t *testing.T) {
				ctx := context.Background()
				input := copiedCompositeInput(t)
				candidate, err := PrepareCompositeCandidate(input)
				if err != nil {
					t.Fatal(err)
				}
				store, validator, clock, root, path := copiedCompositeStore(t)
				if os.Getenv("MULGAE_TEST_COPIED_COMPOSITE_ROOT") != "" {
					fault := &compositeInterruptedStore{PublicationStore: store, after: after}
					interrupted, err := NewService(fault, validator, clock, 8<<20)
					if err != nil {
						t.Fatal(err)
					}
					_, err = interrupted.PublishCompositeNext(ctx, root, candidate)
					t.Fatalf("interruption hook did not exit: %v", err)
				}
				command := exec.Command(os.Args[0], "-test.run=^"+t.Name()+"$")
				command.Env = append(os.Environ(), "MULGAE_TEST_COPIED_COMPOSITE_ROOT="+path)
				output, err := command.CombinedOutput()
				var exit *exec.ExitError
				if !errors.As(err, &exit) || exit.ExitCode() != 73 {
					t.Fatalf("child interruption = %v, output: %s", err, output)
				}
				service, err := NewService(store, validator, clock, 8<<20)
				if err != nil {
					t.Fatal(err)
				}
				run, err := ports.NewPublicationRun(root, input.SessionID, input.RunID)
				if err != nil {
					t.Fatal(err)
				}
				changedInput := copiedCompositeInput(t)
				changedInput.SourceSupport[0].Source.SupportSHA256 = sha256Identifier([]byte("different support receipt"))
				changed, err := PrepareCompositeCandidate(changedInput)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := service.PublishCompositeNext(ctx, root, changed); err == nil {
					t.Fatal("journal replay accepted changed support receipt")
				}
				if recoverFirst {
					recovered, err := service.Recover(ctx, run)
					if err != nil {
						t.Fatal(err)
					}
					if recovered.Decision().Authority() != domain.PublicationAuthorityP2 {
						t.Fatal("recovery omitted P2")
					}
				}
				result, err := service.PublishCompositeNext(ctx, root, candidate)
				if err != nil {
					t.Fatal(err)
				}
				if result.Decision().Authority() != domain.PublicationAuthorityP2 {
					t.Fatal("replay omitted P2")
				}
				queries, err := appquery.NewService(store, validator, nil, 8<<20)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := queries.ReadCommitted(ctx, run); err != nil {
					t.Fatalf("copied receipt not readable after recovery: %v", err)
				}
			})
		}
	}
}

func TestCompositeSupportRetainsRetirementPolicyWithoutSourceRuns(t *testing.T) {
	ctx := context.Background()
	input := copiedCompositeInput(t)
	input.SourceSupport[0].Source.ProviderIdentities = []string{"codex-primary", "kimi-retired"}
	candidate, err := PrepareCompositeCandidate(input)
	if err != nil {
		t.Fatal(err)
	}
	store, validator, clock, root, path := copiedCompositeStore(t)
	service, err := NewService(store, validator, clock, 8<<20)
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.PublishCompositeNext(ctx, root, candidate)
	if err != nil {
		t.Fatal(err)
	}
	if result.Decision().Authority() != domain.PublicationAuthorityP2 {
		t.Fatal("fixture did not publish")
	}
	for _, source := range input.Sources {
		if _, err := os.Stat(filepath.Join(path, input.SessionID.String(), source.RunID.String())); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("fixture unexpectedly has source run: %v", err)
		}
	}
	queries, err := appquery.NewService(store, validator, nil, 8<<20)
	if err != nil {
		t.Fatal(err)
	}
	run, err := ports.NewPublicationRun(root, input.SessionID, input.RunID)
	if err != nil {
		t.Fatal(err)
	}
	_, err = queries.ReadCommitted(ctx, run)
	var failure *domain.Failure
	if !errors.As(err, &failure) || failure.Class() != domain.FailureArtifact || failure.Reason() != "retired_provider_artifact" {
		t.Fatalf("copied retired provenance = %v, want retired_provider_artifact", err)
	}
}

func copiedCompositeMixedEvidenceInput(t *testing.T) CompositeCandidateInput {
	t.Helper()
	input := copiedCompositeInput(t)
	source := input.SourceSupport[0].Source
	finding := CompositeFindingInput{ID: "F001", Fingerprint: sha256Identifier([]byte("mixed evidence")), Role: domain.RoleLogic, Severity: domain.SeverityLow, Title: "Mixed evidence", Description: "Preserve available and historical evidence independently.", Recommendation: "Retain copied evidence.", Confidence: domain.ConfidenceHigh, Lifecycle: domain.FindingOpen, SourceRunID: input.Sources[0].RunID, SourceReviewID: input.Sources[0].ReviewID, SourceAttemptID: input.Sources[0].AttemptID, SourceFindingID: "F007"}
	input.Findings = []CompositeFindingInput{finding}
	input.Roles[0].ValidFindingIDs = []string{"F001"}
	input.ContentVerdict = domain.ContentFindingsPresent
	copied := compositesupport.FindingMaterial{Finding: compositesupport.Finding{ID: "F001", Role: domain.RoleLogic, SourceFindingID: "F007", Evidence: []compositesupport.Evidence{}}, Excerpts: [][]byte{}}
	claims := []any{}
	for index, quote := range []string{"available copied quote\n", "historical absent quote\n"} {
		claim, err := appevidence.NewCurrentClaim(appevidence.CurrentClaimInput{TargetSHA256: source.TargetSHA256, Side: appevidence.SideHead, Path: "a.go", LineStart: index + 1, LineEnd: index + 1, Quote: quote})
		if err != nil {
			t.Fatal(err)
		}
		digest, err := claim.ExcerptSHA256([]byte(quote))
		if err != nil {
			t.Fatal(err)
		}
		ref := compositesupport.Evidence{Index: index, Availability: "verified", TargetSHA256: source.TargetSHA256, Side: appevidence.SideHead, Path: "a.go", LineStart: index + 1, LineEnd: index + 1, ExcerptSHA256: digest, ContentSHA256: sha256Identifier([]byte(quote))}
		var excerpt []byte = []byte(quote)
		if index == 1 {
			ref.Availability = "evidence_unavailable"
			ref.ContentSHA256 = ""
			excerpt = nil
		}
		copied.Finding.Evidence = append(copied.Finding.Evidence, ref)
		copied.Excerpts = append(copied.Excerpts, excerpt)
		claims = append(claims, map[string]any{"current": map[string]any{"target_sha256": source.TargetSHA256, "side": "head", "path": "a.go", "line_start": index + 1, "line_end": index + 1, "quote": quote, "current_excerpt_sha256": digest}})
	}
	original, err := json.Marshal(map[string]any{"id": "F007", "role": "logic", "severity": "low", "title": finding.Title, "description": finding.Description, "recommendation": finding.Recommendation, "confidence": "high", "lifecycle": "open", "fingerprint": finding.Fingerprint, "evidence": claims})
	if err != nil {
		t.Fatal(err)
	}
	copied.Original = original
	copied.Finding.OriginalSHA256 = sha256Identifier(original)
	input.SourceSupport[0].Findings = []compositesupport.FindingMaterial{copied}
	return input
}

func TestCompositeSupportReportRendersMixedAvailabilityWithoutSources(t *testing.T) {
	ctx := context.Background()
	input := copiedCompositeMixedEvidenceInput(t)
	candidate, err := PrepareCompositeCandidate(input)
	if err != nil {
		t.Fatal(err)
	}
	store, validator, clock, root, path := copiedCompositeStore(t)
	publisher, err := NewService(store, validator, clock, 8<<20)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.PublishCompositeNext(ctx, root, candidate); err != nil {
		t.Fatal(err)
	}
	for _, source := range input.Sources {
		if _, err := os.Stat(filepath.Join(path, input.SessionID.String(), source.RunID.String())); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("source run unexpectedly exists: %v", err)
		}
	}
	queries, err := appquery.NewService(store, validator, nil, 8<<20)
	if err != nil {
		t.Fatal(err)
	}
	run, err := ports.NewPublicationRun(root, input.SessionID, input.RunID)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := domain.ParseProjectBinding(sha256Identifier([]byte("report fixture binding")))
	if err != nil {
		t.Fatal(err)
	}
	committed, err := queries.ReadCommitted(ctx, run)
	if err != nil {
		t.Fatal(err)
	}
	claims := committed.Findings()[0].Evidence()
	if len(claims) != 2 || claims[0].CopiedAvailability() != "verified" || claims[0].Verification() != appevidence.ReceiptVerified || claims[1].CopiedAvailability() != "evidence_unavailable" || claims[1].Verification() != appevidence.ReceiptUnverifiable {
		t.Fatal("copied evidence availability was misrepresented")
	}
	reports, err := appreport.NewService(queries)
	if err != nil {
		t.Fatal(err)
	}
	rendered, err := reports.Render(ctx, run)
	if err != nil {
		t.Fatalf("legacy report projection with historical absence: %v", err)
	}
	chunk, err := appreport.ReadContent(ctx, queries, run, binding, "", appquery.ContentContinuation{})
	if err != nil {
		t.Fatalf("verified read-report with historical absence: %v", err)
	}
	if chunk.Encoding != "utf8" {
		t.Fatalf("report encoding = %s", chunk.Encoding)
	}
	decoded := []byte(chunk.Content)
	if chunk.NextOffset != nil {
		t.Fatal("fixture unexpectedly exceeds one report chunk")
	}
	for label, raw := range map[string][]byte{"legacy report": rendered.Bytes(), "read-report": decoded} {
		if !bytes.Contains(raw, []byte("available copied quote")) || !bytes.Contains(raw, []byte("evidence_unavailable")) || bytes.Contains(raw, []byte("historical absent quote")) {
			t.Fatalf("%s did not preserve mixed evidence availability: %s", label, raw)
		}
	}
	_, err = queries.ReadEvidence(ctx, run, binding, "F001", input.SourceSupport[0].Source.TargetSHA256, 1, appquery.ContentContinuation{})
	var failure *domain.Failure
	if !errors.As(err, &failure) || failure.Class() != domain.FailureArtifact || failure.Reason() != "evidence_unavailable" {
		t.Fatalf("absent evidence direct read = %v", err)
	}
	copiedPath := filepath.Join(path, input.SessionID.String(), input.RunID.String(), compositesupport.ExcerptPath("F001", 0))
	for _, mutation := range []string{"missing", "corrupt"} {
		t.Run(mutation, func(t *testing.T) {
			if mutation == "missing" {
				if err := os.Remove(copiedPath); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(copiedPath, []byte("corrupt copied quote\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := reports.Render(ctx, run); err == nil {
				t.Fatal("legacy report downgraded broken bound evidence to historical absence")
			}
			if _, err := appreport.ReadContent(ctx, queries, run, binding, "", appquery.ContentContinuation{}); err == nil {
				t.Fatal("verified report downgraded broken bound evidence to historical absence")
			}
		})
	}
}
