package query

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/app/evidence"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

func TestLiveReceiptPreservesLegacyMeaningAndBindsSourceSelection(t *testing.T) {
	legacy := receiptContractFixture()
	oldIdentity, err := legacy.Identity()
	if err != nil {
		t.Fatal(err)
	}
	live := legacy
	live.SchemaVersion, live.TargetSHA256, live.SourceIdentitySHA256 = LiveInspectionReceiptVersion, "", legacy.TargetSHA256
	live.CaptureIdentity, live.CaptureAvailability = "", "not_captured"
	identity, err := live.Identity()
	if err != nil || identity == oldIdentity {
		t.Fatal("live receipt reused captured identity semantics")
	}
	data, _ := json.Marshal(live)
	if _, err := DecodeInspectionReceipt(data); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*InspectionReceipt){
		"captured hash": func(r *InspectionReceipt) { r.TargetSHA256 = legacy.TargetSHA256 },
		"capture claim": func(r *InspectionReceipt) {
			r.CaptureAvailability = "verified"
			r.CaptureIdentity = legacy.TargetSHA256
		},
		"absent source":   func(r *InspectionReceipt) { r.SourceIdentitySHA256 = "" },
		"unknown version": func(r *InspectionReceipt) { r.SchemaVersion = "mulgae-publication-receipt.v3" },
		"child lineage":   func(r *InspectionReceipt) { r.RunType = "rerun" },
	} {
		t.Run(name, func(t *testing.T) {
			bad := live
			mutate(&bad)
			if _, err := bad.Identity(); err == nil {
				t.Fatal("accepted mixed or unsupported source receipt")
			}
		})
	}
	legacy.SourceIdentitySHA256 = live.SourceIdentitySHA256
	if _, err := legacy.Identity(); err == nil {
		t.Fatal("historical receipt reinterpreted selection metadata as content")
	}
	live.SourceIdentitySHA256 = "sha256:" + strings.Repeat("2", 64)
	changed, _ := live.Identity()
	if changed == identity {
		t.Fatal("receipt omitted selection identity")
	}
}

func TestLiveReceiptExampleHasCanonicalSelectionIdentity(t *testing.T) {
	data, err := os.ReadFile("../../builtin/assets/examples/publication-receipt.v2.valid.json")
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := DecodeInspectionReceipt(data)
	if err != nil || receipt.SchemaVersion != LiveInspectionReceiptVersion || receipt.TargetSHA256 != "" || receipt.CaptureAvailability != "not_captured" {
		t.Fatalf("live receipt example: %+v, %v", receipt, err)
	}
}

func TestHistoricalReadRejectsLiveEvidenceAndImageSelectors(t *testing.T) {
	service, store, run, binding := inspectionFixture(t, 1)
	final, err := decodeFinalDTO(store.snapshot.Final().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := decodeManifestDTO(store.snapshot.Manifest().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	final.Findings[0].Evidence[0].Source.SourceExcerptSHA256 = final.Findings[0].Evidence[0].Current.CurrentExcerptSHA256
	bindContentFixture(t, store, run, final, manifest, map[string][]byte{"excerpts/F001_1.md": []byte(final.Findings[0].Evidence[0].Current.Quote)})
	review, err := service.ReadCommitted(context.Background(), run)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.ReadEvidence(context.Background(), run, binding, "F001", review.TargetSHA256(), 0, ContentContinuation{}); err != nil {
		t.Fatalf("captured fixture must remain readable: %v", err)
	}
	if _, err := service.ReadSourceEvidence(context.Background(), run, binding, "F001", review.TargetSHA256(), 0, ContentContinuation{}); !errors.Is(err, ErrCursorMismatch) {
		t.Fatalf("live reader accepted captured evidence: %v", err)
	}
	if _, err := service.ReadSourceImageArtifact(context.Background(), run, review.FinalSHA256(), review.TargetSHA256(), "worktree", "diagram.png"); !errors.Is(err, ErrPublicationReceiptMismatch) {
		t.Fatalf("live image reader accepted captured authority: %v", err)
	}
}

func TestHistoricalCommittedReviewRejectsLiveAuthority(t *testing.T) {
	for name, mutate := range map[string]func(*finalDTO, *manifestDTO){
		"source metadata":   func(f *finalDTO, _ *manifestDTO) { f.Target.LiveSource = &evidence.LiveSourceMetadata{} },
		"source provenance": func(f *finalDTO, _ *manifestDTO) { f.Provenance.LiveProduction = &liveProductionProvenanceDTO{} },
		"source identity":   func(_ *finalDTO, m *manifestDTO) { m.Target.SourceIdentitySHA256 = "sha256:" + strings.Repeat("a", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			run, snapshot, observation := queryCommittedFixture(t, domain.ExitCommittedCIRejected)
			final, err := decodeFinalDTO(snapshot.Final().Bytes())
			if err != nil {
				t.Fatal(err)
			}
			manifest, err := decodeManifestDTO(snapshot.Manifest().Bytes())
			if err != nil {
				t.Fatal(err)
			}
			decision, err := domain.ClassifyPublication(observation.ClassifierInput())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := buildCommittedReview(run, decision, snapshot, final, manifest); err != nil {
				t.Fatalf("historical fixture: %v", err)
			}
			mutate(&final, &manifest)
			if _, err := buildCommittedReview(run, decision, snapshot, final, manifest); err == nil {
				t.Fatal("historical result admitted live authority")
			}
		})
	}
}

func TestHistoricalRuntimeReadRejectsRehashedLiveSupport(t *testing.T) {
	for _, suffix := range []string{"source/source.json", "evidence/images/sha256-" + strings.Repeat("a", 64) + ".png"} {
		t.Run(suffix, func(t *testing.T) {
			run, snapshot, _, artifacts, paths, _ := queryRuntimeFixture(t)
			var index runtimeSupportIndexDTO
			if err := json.Unmarshal(artifacts[paths["support"]].Bytes(), &index); err != nil {
				t.Fatal(err)
			}
			path := mustQueryPath(t, run.SessionID().String()+"/"+run.RunID().String()+"/"+suffix)
			live := mustQueryArtifact(t, path, []byte("adversarial live support"))
			index.Artifacts = append(index.Artifacts, artifactIdentityDTO{Path: path.String(), SHA256: live.SHA256()})
			indexBytes, _ := json.Marshal(index)
			support := mustQueryArtifact(t, artifacts[paths["support"]].Path(), indexBytes)
			artifacts[paths["support"]], artifacts[path.String()] = support, live
			manifest, err := decodeManifestDTO(snapshot.Manifest().Bytes())
			if err != nil {
				t.Fatal(err)
			}
			manifest.CompositeIdentity.SupportIndex.SHA256 = support.SHA256()
			manifestBytes, _ := json.Marshal(manifest)
			boundManifest := mustQueryArtifact(t, snapshot.Manifest().Path(), manifestBytes)
			boundSnapshot, err := ports.NewCommittedPublicationSnapshot(snapshot.Final(), boundManifest, snapshot.LineageEdge(), snapshot.Epoch())
			if err != nil {
				t.Fatal(err)
			}
			observation := queryP2Observation(t, run, boundSnapshot, domain.JournalCompleted, domain.ExitCommittedCIRejected, 1)
			service := mustQueryService(t, &queryStore{snapshot: boundSnapshot, observation: observation, auxiliaryArtifacts: artifacts}, &queryValidator{}, nil)
			final, err := decodeFinalDTO(boundSnapshot.Final().Bytes())
			if err != nil {
				t.Fatal(err)
			}
			decision, err := domain.ClassifyPublication(observation.ClassifierInput())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := buildCommittedReview(run, decision, boundSnapshot, final, manifest); err != nil {
				t.Fatalf("coherent historical envelope: %v", err)
			}
			_, err = service.ReadRuntimeTarget(context.Background(), run)
			var failure *domain.Failure
			if !errors.As(err, &failure) || failure.Class() != domain.FailureArtifact {
				t.Fatalf("historical runtime admitted live support: %v", err)
			}
		})
	}
}

func TestLiveQueryRejectsReboundOperandsAndProvenance(t *testing.T) {
	data, err := os.ReadFile("../../builtin/assets/examples/review-artifact.v3.valid.json")
	if err != nil {
		t.Fatal(err)
	}
	provider := queryProductionFinalDTO().Provenance.Production.Providers[0]
	if !validProductionProvider(provider) {
		t.Fatal("provider fixture is not independently valid")
	}
	for name, mutate := range map[string]func(*finalDTO){
		"base operand":   func(f *finalDTO) { oid := strings.Repeat("a", 40); f.Target.BaseOID = &oid },
		"head operand":   func(f *finalDTO) { oid := strings.Repeat("a", 40); f.Target.HeadOID = &oid },
		"build mismatch": func(f *finalDTO) { f.Provenance.LiveProduction.BuildVersion = "other" },
		"source mismatch": func(f *finalDTO) {
			f.Provenance.LiveProduction.SourceIdentitySHA256 = "sha256:" + strings.Repeat("a", 64)
		},
		"providers on empty selection": func(f *finalDTO) { f.Provenance.LiveProduction.Providers = []productionProviderDTO{provider} },
		"objective without digest":     func(f *finalDTO) { f.Provenance.LiveProduction.ObjectivePresent = true },
		"digest without objective": func(f *finalDTO) {
			digest := "sha256:" + strings.Repeat("a", 64)
			f.Provenance.LiveProduction.ObjectiveSHA256 = &digest
		},
	} {
		t.Run(name, func(t *testing.T) {
			final, err := decodeFinalDTO(data)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := validateLiveQueryTarget(final); err != nil {
				t.Fatalf("valid live example: %v", err)
			}
			mutate(&final)
			if _, err := validateLiveQueryTarget(final); err == nil {
				t.Fatal("live reader accepted rebound operands or provenance")
			}
		})
	}
}

func TestLiveQueryRejectsVisualWithoutRetainedRaster(t *testing.T) {
	run, snapshot, _ := queryCommittedFixture(t, domain.ExitCommittedCIRejected)
	final, err := decodeFinalDTO(snapshot.Final().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	item := &final.Findings[0].Evidence[0]
	path, _ := ports.NewSafeRelativePath(item.Current.Path)
	selector, _ := ports.NewLiveSourceSelector(domain.LiveSourceWorkspace, "")
	target, err := ports.NewLiveSourceTarget(selector, ports.GitObjectID{}, ports.GitObjectID{}, false, []ports.LiveSourceChange{{Kind: "included", After: path}})
	if err != nil {
		t.Fatal(err)
	}
	identity, _ := evidence.NewLiveSourceIdentity(target)
	claim, err := evidence.NewLiveClaim(identity, evidence.SideWorktree, path.String(), item.Current.LineStart, item.Current.LineEnd, item.Current.Quote)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := claim.ExcerptSHA256([]byte(item.Current.Quote))
	if err != nil {
		t.Fatal(err)
	}
	item.Current.TargetSHA256, item.Source.SourceTargetSHA256 = "", ""
	item.Current.SourceIdentitySHA256, item.Source.SourceIdentitySHA256 = identity.SHA256(), identity.SHA256()
	item.Current.Side = "worktree"
	item.Current.CurrentExcerptSHA256, item.Source.SourceExcerptSHA256 = digest, digest
	final.SchemaVersion = "mulgae-review-artifact.v3"
	final.Target.ContentSHA256, final.Target.ManifestPath = "", "source/source.json"
	final.Target.BaseOID, final.Target.HeadOID = nil, nil
	final.Target.LiveSource = &evidence.LiveSourceMetadata{Identity: identity.Bytes(), SourceIdentitySHA256: identity.SHA256(), Changes: []evidence.LiveSourceChange{{Kind: "included", After: path.String()}}, Consistency: "caller_maintained", ReplayAvailability: "unsupported", BinaryEvidence: []evidence.LiveBinaryObservation{}}
	productionFinal := queryProductionFinalDTO()
	final.Mulgae = productionFinal.Mulgae
	production := productionFinal.Provenance.Production
	final.Provenance.LiveProduction = &liveProductionProvenanceDTO{BuildProduct: production.BuildProduct, BuildVersion: production.BuildVersion, BuildCommit: production.BuildCommit, ObjectiveSHA256: production.ObjectiveSHA256, ObjectivePresent: production.ObjectivePresent, SourceIdentitySHA256: identity.SHA256(), SourceTerminalReceipt: "source-terminal:v1:sha256:" + strings.Repeat("b", 64), Providers: production.Providers}
	final.Provenance.Production = nil
	if _, err := validateLiveQueryTarget(final); err != nil {
		t.Fatalf("valid changed live source: %v", err)
	}
	live, err := evidence.ValidateLiveSourceMetadata(final.Target.LiveSource)
	if err != nil {
		t.Fatal(err)
	}
	prefix := run.SessionID().String() + "/" + run.RunID().String() + "/"
	sourcePath := mustQueryPath(t, prefix+"source/source.json")
	excerptPath := mustQueryPath(t, prefix+"excerpts/F001_1.md")
	findingPath := mustQueryPath(t, prefix+"excerpts/F001.json")
	artifacts := map[string]ports.ImmutablePublicationArtifact{sourcePath.String(): mustQueryArtifact(t, sourcePath, identity.Bytes()), excerptPath.String(): mustQueryArtifact(t, excerptPath, []byte(item.Current.Quote))}
	verify := func() error {
		findingBytes, err := json.Marshal(final.Findings[0])
		if err != nil {
			t.Fatal(err)
		}
		artifacts[findingPath.String()] = mustQueryArtifact(t, findingPath, findingBytes)
		finalBytes, err := json.Marshal(final)
		if err != nil {
			t.Fatal(err)
		}
		return verifyLiveReadSupport(run, CommittedReview{finalBytes: finalBytes, liveSource: &live}, artifacts)
	}
	if err := verify(); err != nil {
		t.Fatalf("valid retained text without visual evidence: %v", err)
	}
	item.Visual = &visualEvidenceDTO{Path: "diagram.png", SHA256: "sha256:" + strings.Repeat("a", 64), BBox: visualBBoxDTO{Width: 1, Height: 1}, Verification: "verified"}
	if err := verify(); err == nil {
		t.Fatal("live reader accepted visual evidence without a retained raster")
	}
}

func TestLiveStoredFindingsRejectScopeInconsistentSides(t *testing.T) {
	base, _ := ports.ParseGitObjectID(strings.Repeat("a", 40))
	head, _ := ports.ParseGitObjectID(strings.Repeat("b", 40))
	for _, test := range []struct {
		name       string
		scope      domain.LiveSourceScope
		operand    string
		base       ports.GitObjectID
		head       ports.GitObjectID
		emptyBase  bool
		validSides []evidence.Side
		badSides   []evidence.Side
	}{
		{name: "workspace", scope: domain.LiveSourceWorkspace, validSides: []evidence.Side{evidence.SideWorktree}, badSides: []evidence.Side{evidence.SideIndex, evidence.SideBase, evidence.SideHead}},
		{name: "stage", scope: domain.LiveSourceStage, base: base, validSides: []evidence.Side{evidence.SideIndex, evidence.SideBase}, badSides: []evidence.Side{evidence.SideWorktree, evidence.SideHead}},
		{name: "head", scope: domain.LiveSourceHead, head: head, validSides: []evidence.Side{evidence.SideHead}, badSides: []evidence.Side{evidence.SideWorktree, evidence.SideIndex, evidence.SideBase}},
		{name: "commit", scope: domain.LiveSourceCommit, operand: head.String(), base: base, head: head, validSides: []evidence.Side{evidence.SideHead, evidence.SideBase}, badSides: []evidence.Side{evidence.SideWorktree, evidence.SideIndex}},
		{name: "diff", scope: domain.LiveSourceDiff, operand: base.String() + ".." + head.String(), base: base, head: head, validSides: []evidence.Side{evidence.SideHead, evidence.SideBase}, badSides: []evidence.Side{evidence.SideWorktree, evidence.SideIndex}},
		{name: "initial commit", scope: domain.LiveSourceCommit, operand: head.String(), head: head, emptyBase: true, validSides: []evidence.Side{evidence.SideHead}, badSides: []evidence.Side{evidence.SideBase, evidence.SideWorktree, evidence.SideIndex}},
		{name: "unborn stage", scope: domain.LiveSourceStage, emptyBase: true, validSides: []evidence.Side{evidence.SideIndex}, badSides: []evidence.Side{evidence.SideBase, evidence.SideHead, evidence.SideWorktree}},
	} {
		t.Run(test.name, func(t *testing.T) {
			run, snapshot, _ := queryCommittedFixture(t, domain.ExitCommittedCIRejected)
			final, err := decodeFinalDTO(snapshot.Final().Bytes())
			if err != nil {
				t.Fatal(err)
			}
			selector, err := ports.NewLiveSourceSelector(test.scope, test.operand)
			if err != nil {
				t.Fatal(err)
			}
			target, err := ports.NewLiveSourceTarget(selector, test.base, test.head, test.emptyBase, nil)
			if err != nil {
				t.Fatal(err)
			}
			identity, err := evidence.NewLiveSourceIdentity(target)
			if err != nil {
				t.Fatal(err)
			}
			reviewID, err := domain.ParseReviewID(final.ReviewID)
			if err != nil {
				t.Fatal(err)
			}
			roles, expected, err := buildRoles(final.RoleOutcomes)
			if err != nil {
				t.Fatal(err)
			}
			read := func(side evidence.Side) error {
				for index := range final.Findings {
					for evidenceIndex := range final.Findings[index].Evidence {
						item := &final.Findings[index].Evidence[evidenceIndex]
						claim, err := evidence.NewLiveClaim(identity, side, item.Current.Path, item.Current.LineStart, item.Current.LineEnd, item.Current.Quote)
						if err != nil {
							t.Fatal(err)
						}
						digest, err := claim.ExcerptSHA256([]byte(item.Current.Quote))
						if err != nil {
							t.Fatal(err)
						}
						item.Current.Side = string(side)
						item.Current.TargetSHA256, item.Source.SourceTargetSHA256 = "", ""
						item.Current.SourceIdentitySHA256, item.Source.SourceIdentitySHA256 = identity.SHA256(), identity.SHA256()
						item.Current.CurrentExcerptSHA256, item.Source.SourceExcerptSHA256 = digest, digest
					}
				}
				_, err := buildFindingsForSource(final.Findings, run.SessionID(), run.RunID(), reviewID, "", domain.RunTypeReview, final.ImmutableLineage, expected, roles, identity)
				return err
			}
			for _, side := range test.validSides {
				if err := read(side); err != nil {
					t.Fatalf("valid stored live evidence on %s: %v", side, err)
				}
			}
			for _, side := range test.badSides {
				t.Run(string(side), func(t *testing.T) {
					if err := read(side); err == nil {
						t.Fatal("stored live reader accepted a coherently rehashed side outside its source scope")
					}
				})
			}
		})
	}
}
