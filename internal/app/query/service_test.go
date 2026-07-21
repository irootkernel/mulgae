package query

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"testing"

	"github.com/irootkernel/kkachi-agent-review/internal/app/evidence"
	"github.com/irootkernel/kkachi-agent-review/internal/app/prompt"
	"github.com/irootkernel/kkachi-agent-review/internal/domain"
	"github.com/irootkernel/kkachi-agent-review/internal/ports"
)

func TestNewServiceRequiresStoreValidatorAndPositiveLimit(t *testing.T) {
	t.Parallel()
	store := &queryStore{}
	validator := &queryValidator{}
	reader := &queryTargetReader{}
	for name, call := range map[string]func() error{
		"nil store": func() error {
			_, err := NewService(nil, validator, reader, 1)
			return err
		},
		"nil validator": func() error {
			_, err := NewService(store, nil, reader, 1)
			return err
		},
		"zero limit": func() error {
			_, err := NewService(store, validator, reader, 0)
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if err := call(); err == nil {
				t.Fatal("NewService accepted an invalid dependency set")
			}
		})
	}
}

func TestNewServiceAllowsAbsentImmutableTargetReader(t *testing.T) {
	t.Parallel()
	store := &queryStore{}
	validator := &queryValidator{}
	var typedNilReader *queryTargetReader
	for name, reader := range map[string]evidence.ImmutableTargetReader{
		"nil":       nil,
		"typed nil": typedNilReader,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := NewService(store, validator, reader, 1); err != nil {
				t.Fatalf("NewService() error = %v", err)
			}
		})
	}
}
func TestValidateProductionProvenanceRejectsMutations(t *testing.T) {
	t.Parallel()
	valid := queryProductionFinalDTO()
	if err := validateProductionProvenance(valid); err != nil {
		t.Fatalf("valid production provenance rejected: %v", err)
	}
	for name, mutate := range map[string]func(*finalDTO){
		"build product":    func(final *finalDTO) { final.Provenance.Production.BuildProduct = "other" },
		"build version":    func(final *finalDTO) { final.Provenance.Production.BuildVersion = "0.2.0" },
		"build commit":     func(final *finalDTO) { final.Provenance.Production.BuildCommit = "other" },
		"objective pair":   func(final *finalDTO) { final.Provenance.Production.ObjectivePresent = false },
		"objective digest": func(final *finalDTO) { value := "sha256:invalid"; final.Provenance.Production.ObjectiveSHA256 = &value },
		"snapshot digest":  func(final *finalDTO) { final.Provenance.Production.SnapshotManifestSHA256 = "sha256:invalid" },
		"workspace receipt grammar": func(final *finalDTO) {
			final.Provenance.Production.WorkspaceTerminalReceipt = "Workspace:" + strings.Repeat("a", 64)
		},
		"provider family":     func(final *finalDTO) { final.Provenance.Production.Providers[0].Family = "" },
		"provider instance":   func(final *finalDTO) { final.Provenance.Production.Providers[0].Instance = "1invalid" },
		"provider version":    func(final *finalDTO) { final.Provenance.Production.Providers[0].Version = "" },
		"executable":          func(final *finalDTO) { final.Provenance.Production.Providers[0].Executable = "" },
		"executable digest":   func(final *finalDTO) { final.Provenance.Production.Providers[0].ExecutableSHA256 = "sha256:invalid" },
		"launcher pair":       func(final *finalDTO) { final.Provenance.Production.Providers[0].LauncherSHA256 = "" },
		"profile generation":  func(final *finalDTO) { final.Provenance.Production.Providers[0].ProfileGeneration = "" },
		"adapter profile":     func(final *finalDTO) { final.Provenance.Production.Providers[0].AdapterProfile = "" },
		"qualification empty": func(final *finalDTO) { final.Provenance.Production.Providers[0].QualificationReceiptIDs = nil },
		"qualification order": func(final *finalDTO) {
			receipts := final.Provenance.Production.Providers[0].QualificationReceiptIDs
			receipts[0], receipts[1] = receipts[1], receipts[0]
		},
		"qualification receipt grammar": func(final *finalDTO) {
			final.Provenance.Production.Providers[0].QualificationReceiptIDs[0] = "bad:" + strings.Repeat("A", 64)
		},
		"transport empty": func(final *finalDTO) { final.Provenance.Production.Providers[0].PacketTransportReceiptIDs = nil },
		"transport order": func(final *finalDTO) {
			receipts := final.Provenance.Production.Providers[0].PacketTransportReceiptIDs
			receipts[0], receipts[1] = receipts[1], receipts[0]
		},
		"transport receipt grammar": func(final *finalDTO) {
			final.Provenance.Production.Providers[0].PacketTransportReceiptIDs[0] = "bad:" + strings.Repeat("A", 64)
		},
		"namespace receipt grammar": func(final *finalDTO) {
			final.Provenance.Production.Providers[0].NamespaceTerminalReceipt = "bad:" + strings.Repeat("A", 64)
		},
		"provider order": func(final *finalDTO) {
			providers := final.Provenance.Production.Providers
			providers[0], providers[1] = providers[1], providers[0]
		},
		"child": func(final *finalDTO) { final.RunType = string(domain.RunTypeDelta) },
		"no change": func(final *finalDTO) {
			final.Target.ContentSHA256 = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
		},
	} {
		t.Run(name, func(t *testing.T) {
			final := queryProductionFinalDTO()
			mutate(&final)
			if err := validateProductionProvenance(final); err == nil {
				t.Fatal("mutated production provenance was accepted")
			}
		})
	}
}
func TestValidateProductionProvenanceAllowsOptionalPairs(t *testing.T) {
	t.Parallel()
	final := queryProductionFinalDTO()
	final.Provenance.Production.ObjectivePresent = false
	final.Provenance.Production.ObjectiveSHA256 = nil
	final.Provenance.Production.Providers[0].Launcher = ""
	final.Provenance.Production.Providers[0].LauncherSHA256 = ""
	if err := validateProductionProvenance(final); err != nil {
		t.Fatalf("valid optional production provenance pairs rejected: %v", err)
	}
}
func TestReadCommittedAllowsValidProductionProvenance(t *testing.T) {
	t.Parallel()
	run, snapshot, _ := queryCommittedFixture(t, domain.ExitCommittedCIRejected)
	final, err := decodeFinalDTO(snapshot.Final().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	productionFinal := queryProductionFinalDTO()
	final.KAR = productionFinal.KAR
	final.Provenance.Production = productionFinal.Provenance.Production
	finalBytes, err := json.Marshal(final)
	if err != nil {
		t.Fatal(err)
	}
	finalIdentity, err := ports.NewFinalReviewIdentity(snapshot.Final().Identity().ReviewID(), snapshot.Final().Identity().Path(), querySHA(finalBytes))
	if err != nil {
		t.Fatal(err)
	}
	finalArtifact, err := ports.NewFinalReviewArtifact(finalIdentity, finalBytes)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := decodeManifestDTO(snapshot.Manifest().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	manifest.FinalReview.SHA256 = finalIdentity.SHA256()
	manifest.RecoveryJournal.ExpectedFinal.SHA256 = finalIdentity.SHA256()
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifestArtifact := mustQueryArtifact(t, snapshot.Manifest().Path(), manifestBytes)
	productionSnapshot, err := ports.NewCommittedPublicationSnapshot(finalArtifact, manifestArtifact, snapshot.LineageEdge(), snapshot.Epoch())
	if err != nil {
		t.Fatal(err)
	}
	observation := queryP2Observation(t, run, productionSnapshot, domain.JournalCompleted, domain.ExitCommittedCIRejected, 1)
	service := mustQueryService(t, &queryStore{observation: observation, snapshot: productionSnapshot}, &queryValidator{}, nil)
	if _, err := service.ReadCommitted(context.Background(), run); err != nil {
		t.Fatalf("valid production review was unreadable: %v", err)
	}
}

func TestValidateProductionProvenanceAllowsLegacyNonproductionRoot(t *testing.T) {
	t.Parallel()
	final := queryProductionFinalDTO()
	final.Provenance.Production = nil
	if err := validateProductionProvenance(final); err != nil {
		t.Fatalf("legacy nonproduction root rejected: %v", err)
	}
}

func queryProductionFinalDTO() finalDTO {
	receipt := func(kind, suffix string) string { return kind + ":" + strings.Repeat(suffix, 64) }
	commit := "0123456789abcdef"
	objective := "sha256:" + strings.Repeat("a", 64)
	provider := func(family, instance string) productionProviderDTO {
		return productionProviderDTO{
			Family: family, Instance: instance, Version: "1.0.0", Executable: "/private/bin/" + instance,
			ExecutableSHA256: "sha256:" + strings.Repeat("b", 64), Launcher: "/private/bin/launcher",
			LauncherSHA256: "sha256:" + strings.Repeat("c", 64), ProfileGeneration: "generation",
			AdapterProfile: "default", QualificationReceiptIDs: []string{receipt("qualification-a", "1"), receipt("qualification-b", "2")},
			PacketTransportReceiptIDs: []string{receipt("transport-a", "3"), receipt("transport-b", "4")},
			NamespaceTerminalReceipt:  receipt("namespace", "5"),
		}
	}
	return finalDTO{
		RunType: string(domain.RunTypeReview), KAR: finalKARDTO{Version: "0.1.0", Commit: &commit},
		Target: finalTargetDTO{ContentSHA256: "sha256:" + strings.Repeat("d", 64)},
		Provenance: provenanceDTO{Production: &productionProvenanceDTO{
			BuildProduct: "kar", BuildVersion: "0.1.0", BuildCommit: commit, ObjectiveSHA256: &objective, ObjectivePresent: true,
			SnapshotManifestSHA256: "sha256:" + strings.Repeat("e", 64), WorkspaceTerminalReceipt: receipt("workspace", "6"),
			Providers: []productionProviderDTO{provider("alpha", "alpha-main"), provider("beta", "beta-main")},
		}},
	}
}
func TestCanonicalEvidenceItemsSupportsBoundedDeterministicEvidence(t *testing.T) {
	makeEvidence := func(index int) Evidence {
		return Evidence{
			sourceExcerptSHA256: fmt.Sprintf("sha256:%064x", index+1),
			targetSHA256:        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			lineStart:           index + 1,
			lineEnd:             index + 1,
			verification:        evidence.ReceiptVerified,
		}
	}
	for _, count := range []int{1, 2, 20} {
		items := make([]Evidence, count)
		for index := range items {
			items[index] = makeEvidence(index + 1)
		}
		ordered, err := canonicalEvidenceItems(items)
		if err != nil || len(ordered) != count {
			t.Fatalf("canonicalEvidenceItems(%d) = %d items, %v", count, len(ordered), err)
		}
		for index := 1; index < len(ordered); index++ {
			if canonicalEvidenceKey(ordered[index-1]) >= canonicalEvidenceKey(ordered[index]) {
				t.Fatalf("canonical evidence order is not strict at %d", index)
			}
		}
	}
	collision := makeEvidence(1)
	if _, err := canonicalEvidenceItems([]Evidence{collision, collision}); err == nil {
		t.Fatal("canonicalEvidenceItems accepted a full-tuple collision")
	}
}
func TestResolveRunUsesPublicationStoreBoundary(t *testing.T) {
	t.Parallel()
	run, _, _ := queryCommittedFixture(t, domain.ExitCommittedCIRejected)
	store := &queryStore{resolved: run}
	service := mustQueryService(t, store, &queryValidator{}, &queryTargetReader{})

	resolved, err := service.ResolveRun(context.Background(), run.Root(), run.RunID())
	if err != nil {
		t.Fatalf("ResolveRun() error = %v", err)
	}
	if resolved != run || store.resolveCalls != 1 {
		t.Fatalf("ResolveRun() = %#v, calls=%d", resolved, store.resolveCalls)
	}
}

func TestReadCommittedListFindingsAndRenderExcerpt(t *testing.T) {
	t.Parallel()
	run, snapshot, observation := queryCommittedFixture(t, domain.ExitCommittedCIRejected)
	path := mustQueryPath(t, run.SessionID().String()+"/"+run.RunID().String()+"/excerpts/F001_1.md")
	store := &queryStore{
		observation:       observation,
		snapshot:          snapshot,
		auxiliaryArtifact: mustQueryArtifact(t, path, []byte("line one\nline two")),
	}
	validator := &queryValidator{}
	service := mustQueryService(t, store, validator, &queryTargetReader{})

	review, err := service.ReadCommitted(context.Background(), run)
	if err != nil {
		t.Fatalf("ReadCommitted() error = %v", err)
	}
	if review.PublicationStatus() != domain.PublicationCommitted || review.CIDecision() != domain.CIFail {
		t.Fatalf("committed axes = (%q, %q)", review.PublicationStatus(), review.CIDecision())
	}
	if got := len(review.Findings()); got != 1 {
		t.Fatalf("finding count = %d, want 1", got)
	}
	evidenceItems := review.Findings()[0].Evidence()
	if evidenceItems[0].SourceExcerptSHA256() == evidenceItems[0].CurrentExcerptSHA256() {
		t.Fatal("fixture did not preserve distinct historical and current excerpt digests")
	}
	final := review.FinalBytes()
	final[0] = '!'
	if review.FinalBytes()[0] == '!' {
		t.Fatal("ReadCommitted exposed mutable final bytes")
	}

	findings, err := service.ListFindings(context.Background(), run, domain.SeverityHigh)
	if err != nil || len(findings) != 1 || findings[0].ID() != "F001" {
		t.Fatalf("ListFindings(high) = %#v, %v", findings, err)
	}
	findings, err = service.ListFindings(context.Background(), run, domain.SeverityCritical)
	if err != nil || len(findings) != 0 {
		t.Fatalf("ListFindings(critical) = %#v, %v", findings, err)
	}

	excerpt, err := service.RenderExcerpt(context.Background(), run, "F001", review.TargetSHA256())
	if err != nil || string(excerpt) != "line one\nline two" {
		t.Fatalf("RenderExcerpt() = %q, %v", excerpt, err)
	}
	indexed, err := service.RenderExcerptAt(context.Background(), run, "F001", review.TargetSHA256(), 1)
	if err != nil || string(indexed) != "line one\nline two" {
		t.Fatalf("RenderExcerptAt(1) = %q, %v", indexed, err)
	}
	if _, err := service.RenderExcerptAt(context.Background(), run, "F001", review.TargetSHA256(), 2); err == nil {
		t.Fatal("RenderExcerptAt accepted an unbound evidence index")
	}
	if store.auxiliaryReads != 2 {
		t.Fatalf("RenderExcerpt auxiliary reads = %d, want 2", store.auxiliaryReads)
	}
}
func TestReadCommittedPreservesFollowupOutcome(t *testing.T) {
	run, snapshot, observation := queryFollowupCommittedFixture(t, domain.FollowupResolved)
	service := mustQueryService(t, &queryStore{observation: observation, snapshot: snapshot}, &queryValidator{}, &queryTargetReader{})

	review, err := service.ReadCommitted(context.Background(), run)
	if err != nil {
		t.Fatalf("ReadCommitted() error = %v", err)
	}
	outcome, present := review.FollowupOutcome()
	if !present || outcome.Resolution() != domain.FollowupResolved || outcome.Rationale() != "verified resolution" || len(outcome.Evidence()) != 1 {
		t.Fatalf("FollowupOutcome() = %#v, present = %t", outcome, present)
	}
	followupEvidence := outcome.Evidence()[0]
	if followupEvidence.SourceRunID().String() != "r_019f596a-cfe4-7c9c-b82e-7149158243bc" ||
		followupEvidence.SourceExcerptSHA256() == followupEvidence.CurrentExcerptSHA256() {
		t.Fatalf("followup evidence did not preserve original source lineage: %#v", followupEvidence)
	}
}
func TestCommittedReviewLineageProjection(t *testing.T) {
	t.Parallel()
	pointer := func(value string) *string { return &value }
	parent := "r_019f596a-cfe4-7c9c-b82e-7149158243bb"
	source := "r_019f596a-cfe4-7c9c-b82e-7149158243bc"
	sourceReview := "019f596a-d174-7321-b920-c2d312c82cc3"
	current, err := domain.ParseRunID("r_019f596a-cfe4-7c9c-b82e-7149158243bd")
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name    string
		runType domain.RunType
		value   lineageDTO
		finding string
		replay  ReplayMode
	}{
		{name: "root", runType: domain.RunTypeReview},
		{name: "followup", runType: domain.RunTypeFollowup, value: lineageDTO{
			ParentRunID: pointer(parent), SourceRunID: pointer(source), SourceReviewID: pointer(sourceReview),
			SourceFindingRef: pointer("F001"),
		}, finding: "F001"},
		{name: "delta", runType: domain.RunTypeDelta, value: lineageDTO{
			ParentRunID: pointer(parent), SourceRunID: pointer(source), SourceReviewID: pointer(sourceReview),
		}},
		{name: "rerun", runType: domain.RunTypeRerun, value: lineageDTO{
			ParentRunID: pointer(parent), SourceRunID: pointer(source), SourceReviewID: pointer(sourceReview),
			ReplayMode: pointer(string(ReplayModeExact)),
		}, replay: ReplayModeExact},
	} {
		t.Run(test.name, func(t *testing.T) {
			lineage, err := buildCommittedLineage(test.runType, current, test.value)
			if err != nil {
				t.Fatal(err)
			}
			view := (CommittedReview{lineage: lineage}).Lineage()
			parentRunID, hasParent := view.ParentRunID()
			sourceRunID, hasSource := view.SourceRunID()
			sourceReviewID, hasReview := view.SourceReviewID()
			if test.runType == domain.RunTypeReview {
				if hasParent || hasSource || hasReview {
					t.Fatalf("root lineage exposes source identities: %#v", view)
				}
			} else if !hasParent || !hasSource || !hasReview ||
				parentRunID.String() != parent || sourceRunID.String() != source || sourceReviewID.String() != sourceReview {
				t.Fatalf("child lineage source identities = %#v", view)
			}
			finding, hasFinding := view.SourceFindingRef()
			if hasFinding != (test.finding != "") || finding != test.finding {
				t.Fatalf("source finding = (%q, %t), want (%q, %t)", finding, hasFinding, test.finding, test.finding != "")
			}
			replay, hasReplay := view.ReplayMode()
			if hasReplay != (test.replay != "") || replay != test.replay {
				t.Fatalf("replay mode = (%q, %t), want (%q, %t)", replay, hasReplay, test.replay, test.replay != "")
			}
		})
	}
}

func TestCommittedLineageRejectsMalformedAndContradictoryOptionalFields(t *testing.T) {
	t.Parallel()
	pointer := func(value string) *string { return &value }
	parent := "r_019f596a-cfe4-7c9c-b82e-7149158243bb"
	source := "r_019f596a-cfe4-7c9c-b82e-7149158243bc"
	sourceReview := "019f596a-d174-7321-b920-c2d312c82cc3"
	current, err := domain.ParseRunID("r_019f596a-cfe4-7c9c-b82e-7149158243bd")
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name    string
		runType domain.RunType
		value   lineageDTO
	}{
		{name: "root child field", runType: domain.RunTypeReview, value: lineageDTO{ParentRunID: pointer(parent)}},
		{name: "child malformed parent", runType: domain.RunTypeDelta, value: lineageDTO{
			ParentRunID: pointer("not-a-run"), SourceRunID: pointer(source), SourceReviewID: pointer(sourceReview),
		}},
		{name: "followup missing finding", runType: domain.RunTypeFollowup, value: lineageDTO{
			ParentRunID: pointer(parent), SourceRunID: pointer(source), SourceReviewID: pointer(sourceReview),
		}},
		{name: "delta replay contradiction", runType: domain.RunTypeDelta, value: lineageDTO{
			ParentRunID: pointer(parent), SourceRunID: pointer(source), SourceReviewID: pointer(sourceReview),
			ReplayMode: pointer(string(ReplayModeExact)),
		}},
		{name: "rerun finding contradiction", runType: domain.RunTypeRerun, value: lineageDTO{
			ParentRunID: pointer(parent), SourceRunID: pointer(source), SourceReviewID: pointer(sourceReview),
			SourceFindingRef: pointer("F001"), ReplayMode: pointer(string(ReplayModeExact)),
		}},
		{name: "rerun replay invalid", runType: domain.RunTypeRerun, value: lineageDTO{
			ParentRunID: pointer(parent), SourceRunID: pointer(source), SourceReviewID: pointer(sourceReview),
			ReplayMode: pointer("later"),
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := buildCommittedLineage(test.runType, current, test.value); err == nil {
				t.Fatal("malformed lineage was accepted")
			}
		})
	}
}
func TestReadCommittedRejectsMalformedOrContradictoryLineageArtifacts(t *testing.T) {
	t.Parallel()
	const rootLineage = `"parent_run_id":null,"source_run_id":null,"source_review_id":null,"source_finding_ref":null,"replay_mode":null`
	const childLineage = `"parent_run_id":"r_019f596a-cfe4-7c9c-b82e-7149158243bb","source_run_id":"r_019f596a-cfe4-7c9c-b82e-7149158243bc","source_review_id":"019f596a-d174-7321-b920-c2d312c82cc3","source_finding_ref":null,"replay_mode":null`
	for _, test := range []struct {
		name           string
		mutateManifest bool
	}{
		{name: "root child lineage", mutateManifest: true},
		{name: "final manifest lineage disagreement"},
	} {
		t.Run(test.name, func(t *testing.T) {
			run, snapshot, _ := queryCommittedFixture(t, domain.ExitCommittedCIRejected)
			finalBytes := strings.Replace(string(snapshot.Final().Bytes()), rootLineage, childLineage, 1)
			finalIdentity, err := ports.NewFinalReviewIdentity(
				snapshot.Final().Identity().ReviewID(),
				snapshot.Final().Identity().Path(),
				querySHA([]byte(finalBytes)),
			)
			if err != nil {
				t.Fatal(err)
			}
			final, err := ports.NewFinalReviewArtifact(finalIdentity, []byte(finalBytes))
			if err != nil {
				t.Fatal(err)
			}
			manifestBytes := string(snapshot.Manifest().Bytes())
			if test.mutateManifest {
				manifestBytes = strings.Replace(manifestBytes, rootLineage, childLineage, 1)
			}
			manifestBytes = strings.ReplaceAll(manifestBytes, snapshot.Final().Identity().SHA256(), finalIdentity.SHA256())
			manifest := mustQueryArtifact(t, snapshot.Manifest().Path(), []byte(manifestBytes))
			mutatedSnapshot, err := ports.NewCommittedPublicationSnapshot(final, manifest, snapshot.LineageEdge(), snapshot.Epoch())
			if err != nil {
				t.Fatal(err)
			}
			observation := queryP2Observation(t, run, mutatedSnapshot, domain.JournalCompleted, domain.ExitCommittedCIRejected, 1)
			service := mustQueryService(t, &queryStore{observation: observation, snapshot: mutatedSnapshot}, &queryValidator{}, nil)
			if _, err := service.ReadCommitted(context.Background(), run); err == nil {
				t.Fatal("malformed or contradictory lineage artifact was accepted")
			}
		})
	}
}

func TestRenderExcerptUsesPersistedArtifactAfterRestart(t *testing.T) {
	t.Parallel()
	run, snapshot, observation := queryCommittedFixture(t, domain.ExitCommittedCIRejected)
	path := mustQueryPath(t, run.SessionID().String()+"/"+run.RunID().String()+"/excerpts/F001_1.md")
	store := &queryStore{
		observation:       observation,
		snapshot:          snapshot,
		auxiliaryArtifact: mustQueryArtifact(t, path, []byte("line one\nline two")),
	}
	service := mustQueryService(t, store, &queryValidator{}, nil)

	excerpt, err := service.RenderExcerpt(
		context.Background(),
		run,
		"F001",
		"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	)
	if err != nil || string(excerpt) != "line one\nline two" {
		t.Fatalf("RenderExcerpt() = %q, %v", excerpt, err)
	}
	if store.auxiliaryReads != 1 {
		t.Fatalf("auxiliary reads = %d, want 1", store.auxiliaryReads)
	}
	if store.auxiliaryRequest.Path() != path {
		t.Fatalf("auxiliary path = %q, want %q", store.auxiliaryRequest.Path().String(), path.String())
	}
	if hash, ok := store.auxiliaryRequest.ExpectedSHA256(); ok || hash != "" {
		t.Fatalf("auxiliary expected hash = (%q, %t), want (empty, false)", hash, ok)
	}

	excerpt[0] = '!'
	reloaded, err := service.RenderExcerpt(
		context.Background(),
		run,
		"F001",
		"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	)
	if err != nil || string(reloaded) != "line one\nline two" {
		t.Fatalf("defensive RenderExcerpt() = %q, %v", reloaded, err)
	}
}

func TestRenderExcerptFailsClosedWhenPersistedArtifactIsMissing(t *testing.T) {
	t.Parallel()
	run, snapshot, observation := queryCommittedFixture(t, domain.ExitCommittedCIRejected)
	reader := &queryTargetReader{
		availability: evidence.ImmutableTargetAvailable,
		bytes:        []byte("line one\nline two"),
	}
	store := &queryStore{observation: observation, snapshot: snapshot}
	service := mustQueryService(t, store, &queryValidator{}, reader)

	_, err := service.RenderExcerpt(
		context.Background(),
		run,
		"F001",
		"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	)
	if failureClass(t, err) != domain.FailureArtifact {
		t.Fatalf("failure class = %q, want artifact", failureClass(t, err))
	}
	if store.auxiliaryReads != 1 || reader.calls != 0 {
		t.Fatalf("reads = auxiliary %d, target %d; want one durable read and no fallback", store.auxiliaryReads, reader.calls)
	}
}

func TestRenderExcerptRejectsPersistedArtifactCorruption(t *testing.T) {
	t.Parallel()
	expectedDigest := queryCurrentExcerptSHA256(t)
	cases := []struct {
		name         string
		sourceDigest string
		pathSuffix   string
		bytes        []byte
		zeroArtifact bool
	}{
		{
			name:         "tampered bytes",
			sourceDigest: expectedDigest,
			pathSuffix:   "F001_1.md",
			bytes:        []byte("tampered excerpt"),
		},
		{
			name:         "trailing bytes",
			sourceDigest: expectedDigest,
			pathSuffix:   "F001_1.md",
			bytes:        []byte("line one\nline two\ntrailing"),
		},
		{
			name:         "unexpected canonical path",
			sourceDigest: expectedDigest,
			pathSuffix:   "F001_2.md",
			bytes:        []byte("line one\nline two"),
		},
		{
			name:         "invalid artifact identity",
			sourceDigest: expectedDigest,
			zeroArtifact: true,
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			run, snapshot, observation := queryCommittedFixtureWithSourceExcerptSHA256(
				t,
				domain.ExitCommittedCIRejected,
				test.sourceDigest,
			)
			store := &queryStore{observation: observation, snapshot: snapshot}
			if test.zeroArtifact {
				store.returnZeroAuxiliaryArtifact = true
			} else {
				path := mustQueryPath(
					t,
					run.SessionID().String()+"/"+run.RunID().String()+"/excerpts/"+test.pathSuffix,
				)
				store.auxiliaryArtifact = mustQueryArtifact(t, path, test.bytes)
			}
			service := mustQueryService(t, store, &queryValidator{}, nil)
			_, err := service.RenderExcerpt(
				context.Background(),
				run,
				"F001",
				"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			)
			if failureClass(t, err) != domain.FailureArtifact {
				t.Fatalf("failure class = %q, want artifact", failureClass(t, err))
			}
		})
	}
}

func TestReadRunStatusNeverExposesFinalBeforeP2(t *testing.T) {
	t.Parallel()
	run, snapshot, _ := queryCommittedFixture(t, domain.ExitCommittedCIRejected)
	p1 := queryP1StatusObservation(t, run, snapshot)
	p0, err := ports.NewPublicationObservation(domain.JournalCollecting, domain.DurableObservationP0None, nil, nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	for name, observation := range map[string]ports.PublicationObservation{"P0": p0, "P1": p1} {
		t.Run(name, func(t *testing.T) {
			store := &queryStore{observation: observation, snapshot: snapshot}
			service := mustQueryService(t, store, &queryValidator{}, &queryTargetReader{})
			status, err := service.ReadRunStatus(context.Background(), run)
			if err != nil {
				t.Fatalf("ReadRunStatus() error = %v", err)
			}
			if _, ok := status.FinalPath(); ok || store.snapshotReads != 0 {
				t.Fatalf("%s exposed or read final before P2", name)
			}
		})
	}
}
func TestP0AndP1CommittedQueriesRejectWithoutDisclosureOrFallback(t *testing.T) {
	t.Parallel()

	run, snapshot, _ := queryCommittedFixture(t, domain.ExitCommittedCIRejected)
	p1 := queryP1StatusObservation(t, run, snapshot)
	p0, err := ports.NewPublicationObservation(domain.JournalCollecting, domain.DurableObservationP0None, nil, nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	calls := map[string]func(*Service) error{
		"ReadCommitted": func(service *Service) error {
			_, err := service.ReadCommitted(context.Background(), run)
			return err
		},
		"ListFindings": func(service *Service) error {
			_, err := service.ListFindings(context.Background(), run, "")
			return err
		},
		"RenderExcerpt": func(service *Service) error {
			_, err := service.RenderExcerpt(
				context.Background(),
				run,
				"F001",
				"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			)
			return err
		},
	}
	for observationName, observation := range map[string]ports.PublicationObservation{"P0": p0, "P1": p1} {
		for callName, call := range calls {
			t.Run(observationName+"/"+callName, func(t *testing.T) {
				reader := &queryTargetReader{}
				store := &queryStore{observation: observation, snapshot: snapshot}
				err := call(mustQueryService(t, store, &queryValidator{}, reader))
				if failureClass(t, err) != domain.FailureArtifact {
					t.Fatalf("failure class = %q, want artifact", failureClass(t, err))
				}
				if store.snapshotReads != 0 || store.auxiliaryReads != 0 || reader.calls != 0 {
					t.Fatalf(
						"%s disclosed or fell back before P2 (snapshot=%d auxiliary=%d target=%d)",
						callName,
						store.snapshotReads,
						store.auxiliaryReads,
						reader.calls,
					)
				}
			})
		}
	}
}

func queryP1StatusObservation(
	t *testing.T,
	run ports.PublicationRun,
	snapshot ports.CommittedPublicationSnapshot,
) ports.PublicationObservation {
	t.Helper()
	final := snapshot.Final()
	journalBytes := []byte(`{"state":"final_file_installed"}`)
	journal, err := ports.NewObservedMutablePublicationDocument(
		ports.MutablePublicationJournal,
		mustQueryPath(t, run.SessionID().String()+"/"+run.RunID().String()+"/publication/journal.json"),
		querySHA(journalBytes),
		journalBytes,
	)
	if err != nil {
		t.Fatal(err)
	}
	composite, err := ports.NewCommitCompositeRequest(
		run,
		final.Identity(),
		snapshot.Manifest(),
		snapshot.LineageEdge(),
		snapshot.Epoch(),
	)
	if err != nil {
		t.Fatal(err)
	}
	request, err := ports.NewPrepareCompositeRequest(composite)
	if err != nil {
		t.Fatal(err)
	}
	canonical := []ports.ImmutablePublicationArtifact{
		composite.Manifest(),
		composite.LineageEdge(),
		composite.Epoch().Record(),
	}
	paths := []ports.SafeRelativePath{
		request.StagedManifestPath(),
		request.StagedLineageEdgePath(),
		request.StagedEpochPath(),
	}
	staged := make([]ports.ImmutablePublicationArtifact, len(canonical))
	receipts := make([]ports.SecureWriteReceipt, len(canonical))
	for index := range canonical {
		staged[index], err = ports.NewImmutablePublicationArtifact(paths[index], canonical[index].SHA256(), canonical[index].Bytes())
		if err != nil {
			t.Fatal(err)
		}
		receipts[index], err = ports.NewSecureWriteReceipt(
			run.Root(),
			paths[index],
			staged[index].SHA256(),
			int64(len(staged[index].Bytes())),
			"publication_prepare",
			[]string{"prepared"},
		)
		if err != nil {
			t.Fatal(err)
		}
	}
	prepared, err := ports.NewPreparedComposite(
		request,
		staged[0],
		staged[1],
		staged[2],
		receipts,
		ports.CompositePreparationDurable,
	)
	if err != nil {
		t.Fatal(err)
	}
	material, err := ports.NewPublicationRecoveryMaterialWithPrepared(
		final,
		nil,
		journal,
		nil,
		final,
		prepared,
	)
	if err != nil {
		t.Fatal(err)
	}
	observation, err := ports.NewPublicationObservationWithRecovery(
		domain.JournalFinalFileInstalled,
		domain.DurableObservationP1Installed,
		nil,
		nil,
		1,
		material,
	)
	if err != nil {
		t.Fatal(err)
	}
	return observation
}

func TestReadCommittedRejectsArtifactAndSchemaCorruption(t *testing.T) {
	t.Parallel()
	run, snapshot, observation := queryCommittedFixture(t, domain.ExitCommittedCIRejected)
	for name, configure := range map[string]func(*queryStore, *queryValidator){
		"snapshot read failure": func(store *queryStore, _ *queryValidator) {
			store.readErr = errors.New("unavailable")
		},
		"schema failure": func(_ *queryStore, validator *queryValidator) {
			validator.err = errors.New("schema rejected")
		},
		"semantic final mismatch": func(store *queryStore, _ *queryValidator) {
			badFinalBytes := []byte(`{"schema_version":"kar-review-artifact.v2"}`)
			identity := snapshot.Final().Identity()
			badIdentity, err := ports.NewFinalReviewIdentity(identity.ReviewID(), identity.Path(), querySHA(badFinalBytes))
			if err != nil {
				t.Fatal(err)
			}
			badFinal, err := ports.NewFinalReviewArtifact(badIdentity, badFinalBytes)
			if err != nil {
				t.Fatal(err)
			}
			badSnapshot, err := ports.NewCommittedPublicationSnapshot(badFinal, snapshot.Manifest(), snapshot.LineageEdge(), snapshot.Epoch())
			if err != nil {
				t.Fatal(err)
			}
			store.snapshot = badSnapshot
		},
	} {
		t.Run(name, func(t *testing.T) {
			store := &queryStore{observation: observation, snapshot: snapshot}
			validator := &queryValidator{}
			configure(store, validator)
			service := mustQueryService(t, store, validator, &queryTargetReader{})
			if _, err := service.ReadCommitted(context.Background(), run); failureClass(t, err) != domain.FailureArtifact {
				t.Fatalf("failure class = %q, want artifact", failureClass(t, err))
			}
		})
	}
}

func TestBuildRolesAcceptsAndValidatesSkippedOutcomes(t *testing.T) {
	t.Parallel()
	attempt := "a_019f596a-d048-79e7-b2b7-59822f012273"
	provider := "logic-provider"
	selectedVia := "primary"
	empty := ""
	cases := []struct {
		name      string
		value     finalRoleDTO
		wantError bool
	}{
		{
			name: "valid skipped",
			value: finalRoleDTO{
				Role: string(domain.RoleLogic), Required: true, Outcome: "skipped",
			},
		},
		{
			name: "attempt binding",
			value: finalRoleDTO{
				Role: string(domain.RoleLogic), Required: true, Outcome: "skipped",
				AttemptID: &attempt,
			},
			wantError: true,
		},
		{
			name: "provider binding",
			value: finalRoleDTO{
				Role: string(domain.RoleLogic), Required: true, Outcome: "skipped",
				ProviderInstance: &provider,
			},
			wantError: true,
		},
		{
			name: "selection binding",
			value: finalRoleDTO{
				Role: string(domain.RoleLogic), Required: true, Outcome: "skipped",
				SelectedVia: &selectedVia,
			},
			wantError: true,
		},
		{
			name: "finding reference",
			value: finalRoleDTO{
				Role: string(domain.RoleLogic), Required: true, Outcome: "skipped",
				ValidFindingIDs: []string{"F001"},
			},
			wantError: true,
		},
		{
			name: "empty failure reason",
			value: finalRoleDTO{
				Role: string(domain.RoleLogic), Required: true, Outcome: "skipped",
				FailureReason: &empty,
			},
			wantError: true,
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			values := []finalRoleDTO{test.value}
			if !test.wantError {
				values = append(values, finalRoleDTO{
					Role: string(domain.RoleSecurity), Required: true, Outcome: "skipped",
				})
			}
			roles, _, err := buildRoles(values)
			if (err != nil) != test.wantError {
				t.Fatalf("buildRoles() error = %v, want error %t", err, test.wantError)
			}
			if !test.wantError {
				if _, present := roles[0].AttemptID(); present {
					t.Fatal("skipped role exposed an attempt")
				}
				if _, present := roles[0].ProviderInstance(); present {
					t.Fatal("skipped role exposed a provider")
				}
				if len(roles[0].ValidFindingIDs()) != 0 {
					t.Fatal("skipped role exposed findings")
				}
			}
		})
	}
}

func TestBuildFindingsRejectsOrphanRolesAndProviderMismatches(t *testing.T) {
	t.Parallel()
	run, snapshot, _ := queryCommittedFixture(t, domain.ExitCommittedCIRejected)
	final, err := decodeFinalDTO(snapshot.Final().Bytes())
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
	if _, err := buildFindings(final.Findings, run.SessionID(), run.RunID(), reviewID, final.Target.ContentSHA256, domain.RunTypeReview, final.ImmutableLineage, expected, roles); err != nil {
		t.Fatalf("buildFindings() rejected valid fixture: %v", err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*finalFindingDTO)
	}{
		{
			name: "orphan role",
			mutate: func(value *finalFindingDTO) {
				value.Role = string(domain.RoleTesting)
			},
		},
		{
			name: "provider mismatch",
			mutate: func(value *finalFindingDTO) {
				value.ProviderInstance = "other-provider"
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			values := append([]finalFindingDTO(nil), final.Findings...)
			test.mutate(&values[0])
			if _, err := buildFindings(values, run.SessionID(), run.RunID(), reviewID, final.Target.ContentSHA256, domain.RunTypeReview, final.ImmutableLineage, expected, roles); err == nil {
				t.Fatal("buildFindings() accepted invalid finding ownership")
			}
		})
	}
}

func TestSkippedRolesDetermineCoverageAndRunState(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		roles    []Role
		coverage domain.CoverageStatus
		state    domain.RunState
	}{
		{
			name: "required skipped",
			roles: []Role{
				{role: domain.RoleLogic, required: true, outcome: "skipped"},
				{role: domain.RoleSecurity, required: true, outcome: "completed"},
			},
			coverage: domain.CoverageIncomplete,
			state:    domain.RunFailed,
		},
		{
			name: "optional skipped",
			roles: []Role{
				{role: domain.RoleLogic, required: true, outcome: "completed"},
				{role: domain.RoleSecurity, required: true, outcome: "completed"},
				{role: domain.RoleTesting, outcome: "skipped"},
			},
			coverage: domain.CoverageDegraded,
			state:    domain.RunDegraded,
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if !consistentCommittedRunState(test.state, test.roles, test.coverage) {
				t.Fatalf("consistentCommittedRunState(%q) rejected skipped-role state", test.state)
			}
		})
	}
}

func TestSyntheticExcerptLayoutCapsAggregateAllocation(t *testing.T) {
	t.Parallel()
	layout, err := syntheticExcerptLayout(5, []byte("1234"), 8)
	if err != nil || len(layout) != 8 {
		t.Fatalf("syntheticExcerptLayout() = %q, %v", layout, err)
	}
	if _, err := syntheticExcerptLayout(5, []byte("12345"), 8); err == nil {
		t.Fatal("syntheticExcerptLayout accepted aggregate bytes over the cap")
	}
}
func TestValidateOutcomeProjectionCoversPassFailAndIncomplete(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		roles    []Role
		findings []Finding
		content  domain.ContentVerdict
		coverage domain.CoverageStatus
		ci       domain.CIDecision
		reasons  []string
		exit     domain.OperationalExitCode
	}{
		{
			name: "pass",
			roles: []Role{
				{role: domain.RoleLogic, required: true, outcome: "completed"},
				{role: domain.RoleSecurity, required: true, outcome: "completed"},
			},
			content: domain.ContentNoFindings, coverage: domain.CoverageComplete, ci: domain.CIPass,
			reasons: []string{"policy_evaluated"}, exit: domain.ExitCommittedPass,
		},
		{
			name: "CI fail",
			roles: []Role{
				{role: domain.RoleLogic, required: true, outcome: "completed"},
				{role: domain.RoleSecurity, required: true, outcome: "completed"},
			},
			findings: []Finding{{severity: domain.SeverityHigh}},
			content:  domain.ContentRequestChanges, coverage: domain.CoverageComplete, ci: domain.CIFail,
			reasons: []string{"request_changes_threshold"}, exit: domain.ExitCommittedCIRejected,
		},
		{
			name: "incomplete",
			roles: []Role{
				{role: domain.RoleLogic, required: true, outcome: "completed"},
				{role: domain.RoleSecurity, required: true, outcome: "failed"},
			},
			content: domain.ContentNoFindings, coverage: domain.CoverageIncomplete, ci: domain.CIFail,
			reasons: []string{"required_role_incomplete"}, exit: domain.ExitIncompleteCoverage,
		},
		{
			name: "skipped required",
			roles: []Role{
				{role: domain.RoleLogic, required: true, outcome: "skipped"},
				{role: domain.RoleSecurity, required: true, outcome: "completed"},
			},
			content: domain.ContentNoFindings, coverage: domain.CoverageIncomplete, ci: domain.CIFail,
			reasons: []string{"required_role_incomplete"}, exit: domain.ExitIncompleteCoverage,
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			exit := test.exit
			decision, err := domain.NewPublicationDecision(
				domain.PublicationCommitted,
				domain.PublicationAuthorityP2,
				domain.RecoveryActionReconstructCompletedStatus,
				&exit,
				nil,
			)
			if err != nil {
				t.Fatal(err)
			}
			final := finalDTO{
				SeverityThreshold: severityThresholdDTO{
					RequestChangesAtOrAbove: "high",
					PolicySource:            "project_local",
				},
				CIReasonCodes: append([]string(nil), test.reasons...),
			}
			manifest := manifestDTO{
				CIReasonCodes: append([]string(nil), test.reasons...),
				ExitCode:      int(test.exit),
			}
			if err := validateOutcomeProjection(
				final,
				manifest,
				test.roles,
				test.findings,
				test.content,
				test.coverage,
				test.ci,
				decision,
			); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestBuildCommittedReviewRejectsMandatoryRoleAndAttemptProvenanceGaps(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		mutate func(*finalDTO, *manifestDTO)
	}{
		{
			name: "missing logic role",
			mutate: func(final *finalDTO, _ *manifestDTO) {
				final.RoleOutcomes = final.RoleOutcomes[1:]
			},
		},
		{
			name: "missing security role",
			mutate: func(final *finalDTO, _ *manifestDTO) {
				final.RoleOutcomes = final.RoleOutcomes[:1]
			},
		},
		{
			name: "mandatory role is not required",
			mutate: func(final *finalDTO, _ *manifestDTO) {
				final.RoleOutcomes[0].Required = false
			},
		},
		{
			name: "missing selected attempt",
			mutate: func(_ *finalDTO, manifest *manifestDTO) {
				manifest.Attempts = manifest.Attempts[1:]
			},
		},
		{
			name: "attempt ID mismatch",
			mutate: func(_ *finalDTO, manifest *manifestDTO) {
				manifest.Attempts[0].AttemptID = "a_019f596a-d049-79e7-b2b7-59822f012273"
				manifest.Attempts[0].Path = "attempts/a_019f596a-d049-79e7-b2b7-59822f012273/status.json"
			},
		},
		{
			name: "attempt role mismatch",
			mutate: func(_ *finalDTO, manifest *manifestDTO) {
				manifest.Attempts[0].Role = string(domain.RoleTesting)
			},
		},
		{
			name: "attempt provider mismatch",
			mutate: func(_ *finalDTO, manifest *manifestDTO) {
				manifest.Attempts[0].ProviderInstance = "other-provider"
			},
		},
		{
			name: "attempt selection mismatch",
			mutate: func(_ *finalDTO, manifest *manifestDTO) {
				manifest.Attempts[0].SelectedAs = "fallback"
			},
		},
		{
			name: "successful role terminal state mismatch",
			mutate: func(_ *finalDTO, manifest *manifestDTO) {
				manifest.Attempts[0].State = string(domain.AttemptFailed)
			},
		},
		{
			name: "cancelled attempt before later success",
			mutate: func(_ *finalDTO, manifest *manifestDTO) {
				manifest.Attempts = append([]manifestAttemptDTO{{
					AttemptID:        "a_019f596a-d047-79e7-b2b7-59822f012273",
					Role:             string(domain.RoleLogic),
					ProviderInstance: "logic-provider",
					SelectedAs:       "primary",
					State:            string(domain.AttemptCancelled),
					ParseState:       string(domain.ParseNotStarted),
					ValidationState:  string(domain.ValidationNotStarted),
					Path:             "attempts/a_019f596a-d047-79e7-b2b7-59822f012273/status.json",
					InvocationCount:  1,
				}}, manifest.Attempts...)
			},
		},
		{
			name: "unrecorded failed attempt before later success",
			mutate: func(_ *finalDTO, manifest *manifestDTO) {
				manifest.Attempts = append([]manifestAttemptDTO{{
					AttemptID:        "a_019f596a-d046-79e7-b2b7-59822f012273",
					Role:             string(domain.RoleLogic),
					ProviderInstance: "logic-provider",
					SelectedAs:       "primary",
					State:            string(domain.AttemptFailed),
					ParseState:       string(domain.ParseValid),
					ValidationState:  string(domain.ValidationValid),
					Path:             "attempts/a_019f596a-d046-79e7-b2b7-59822f012273/status.json",
					InvocationCount:  1,
				}}, manifest.Attempts...)
			},
		},
		{
			name: "selected attempt for skipped role",
			mutate: func(final *finalDTO, _ *manifestDTO) {
				final.RoleOutcomes[0].Outcome = "skipped"
				final.RoleOutcomes[0].AttemptID = nil
				final.RoleOutcomes[0].ProviderInstance = nil
				final.RoleOutcomes[0].SelectedVia = nil
				final.RoleOutcomes[0].ValidFindingIDs = nil
				final.Findings = nil
			},
		},
		{
			name: "multiple evidence identities",
			mutate: func(final *finalDTO, _ *manifestDTO) {
				final.Findings[0].Evidence = append(final.Findings[0].Evidence, final.Findings[0].Evidence[0])
			},
		},
		{
			name: "final lineage identity mutation",
			mutate: func(final *finalDTO, _ *manifestDTO) {
				final.ImmutableLineage.LineageEdgeSHA = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
			},
		},
		{
			name: "manifest final identity mutation",
			mutate: func(_ *finalDTO, manifest *manifestDTO) {
				manifest.FinalReview.SHA256 = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
			},
		},
		{
			name: "current evidence digest missing",
			mutate: func(final *finalDTO, _ *manifestDTO) {
				final.Findings[0].Evidence[0].Current.CurrentExcerptSHA256 = ""
			},
		},
		{
			name: "current evidence digest malformed",
			mutate: func(final *finalDTO, _ *manifestDTO) {
				final.Findings[0].Evidence[0].Current.CurrentExcerptSHA256 = "sha256:invalid"
			},
		},
		{
			name: "current evidence digest does not match quote",
			mutate: func(final *finalDTO, _ *manifestDTO) {
				final.Findings[0].Evidence[0].Current.Quote = "different quote"
			},
		},
		{
			name: "manifest failure for successful role",
			mutate: func(_ *finalDTO, manifest *manifestDTO) {
				attemptID := manifest.Attempts[0].AttemptID
				manifest.Failures = append(manifest.Failures, manifestFailureDTO{
					Class:      string(domain.FailureProviderUnavailable),
					Stage:      "review",
					ReasonCode: "provider_unavailable",
					AttemptID:  &attemptID,
				})
			},
		},
		{
			name: "validated candidate digest missing",
			mutate: func(_ *finalDTO, manifest *manifestDTO) {
				manifest.RecoveryJournal.ValidatedCandidateSHA256 = nil
			},
		},
		{
			name: "validated candidate digest invalid",
			mutate: func(_ *finalDTO, manifest *manifestDTO) {
				digest := "sha256:invalid"
				manifest.RecoveryJournal.ValidatedCandidateSHA256 = &digest
			},
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
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
			test.mutate(&final, &manifest)
			if _, err := buildCommittedReview(run, decision, snapshot, final, manifest); err == nil {
				t.Fatal("buildCommittedReview accepted incomplete role or attempt provenance")
			}
		})
	}
}

func TestBuildRolesRejectsFindingsOwnedByFailedRole(t *testing.T) {
	t.Parallel()

	_, snapshot, _ := queryCommittedFixture(t, domain.ExitCommittedCIRejected)
	final, err := decodeFinalDTO(snapshot.Final().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	reason := "provider_unavailable"
	final.RoleOutcomes[0].Outcome = "failed"
	final.RoleOutcomes[0].FailureReason = &reason
	if _, _, err := buildRoles(final.RoleOutcomes); err == nil {
		t.Fatal("buildRoles accepted finding IDs on a failed role")
	}
}

func TestValidateManifestFailuresBindsPublishableFailedRoles(t *testing.T) {
	t.Parallel()

	attemptID := "a_019f596a-d048-79e7-b2b7-59822f012273"
	attempts := []manifestAttemptDTO{{
		AttemptID:        attemptID,
		Role:             string(domain.RoleLogic),
		ProviderInstance: "logic-provider",
		SelectedAs:       "primary",
		State:            string(domain.AttemptFailed),
		ParseState:       string(domain.ParseValid),
		ValidationState:  string(domain.ValidationValid),
		Path:             "attempts/" + attemptID + "/status.json",
		InvocationCount:  1,
	}}
	roles := []Role{{
		role:          domain.RoleLogic,
		outcome:       "failed",
		attemptID:     attemptID,
		failureReason: "provider_unavailable",
	}}
	valid := manifestFailureDTO{
		Class:      string(domain.FailureProviderUnavailable),
		Stage:      "review",
		ReasonCode: "provider_unavailable",
		AttemptID:  &attemptID,
	}
	if err := validateManifestFailures([]manifestFailureDTO{valid}, attempts, roles); err != nil {
		t.Fatalf("valid manifest failure rejected: %v", err)
	}
	otherAttempt := "a_019f596a-d049-79e7-b2b7-59822f012273"
	tests := []struct {
		name     string
		failures []manifestFailureDTO
	}{
		{name: "missing", failures: nil},
		{name: "extra", failures: []manifestFailureDTO{valid, valid}},
		{
			name: "wrong attempt",
			failures: []manifestFailureDTO{{
				Class: string(domain.FailureProviderUnavailable), Stage: "review",
				ReasonCode: "provider_unavailable", AttemptID: &otherAttempt,
			}},
		},
		{
			name: "wrong reason",
			failures: []manifestFailureDTO{{
				Class: string(domain.FailureProviderUnavailable), Stage: "review",
				ReasonCode: "different_reason", AttemptID: &attemptID,
			}},
		},
		{
			name: "timeout fact for failed attempt",
			failures: []manifestFailureDTO{{
				Class: string(domain.FailureTimeout), Stage: "review",
				ReasonCode: "provider_unavailable", AttemptID: &attemptID,
			}},
		},
		{
			name: "non-publishable class",
			failures: []manifestFailureDTO{{
				Class: string(domain.FailureInternal), Stage: "review",
				ReasonCode: "provider_unavailable", AttemptID: &attemptID,
			}},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := validateManifestFailures(test.failures, attempts, roles); err == nil {
				t.Fatal("validateManifestFailures accepted an invalid failure projection")
			}
		})
	}
}
func TestValidateManifestFailuresRetainsFailedPrimaryBeforeSuccessfulFallback(t *testing.T) {
	t.Parallel()

	failedAttemptID := "a_019f596a-d046-79e7-b2b7-59822f012273"
	successfulAttemptID := "a_019f596a-d048-79e7-b2b7-59822f012273"
	attempts := []manifestAttemptDTO{
		{
			AttemptID:        failedAttemptID,
			Role:             string(domain.RoleLogic),
			ProviderInstance: "logic-primary",
			SelectedAs:       "primary",
			State:            string(domain.AttemptFailed),
			ParseState:       string(domain.ParseValid),
			ValidationState:  string(domain.ValidationValid),
			Path:             "attempts/" + failedAttemptID + "/status.json",
			InvocationCount:  1,
		},
		{
			AttemptID:        successfulAttemptID,
			Role:             string(domain.RoleLogic),
			ProviderInstance: "logic-fallback",
			SelectedAs:       "fallback",
			State:            string(domain.AttemptSucceeded),
			ParseState:       string(domain.ParseValid),
			ValidationState:  string(domain.ValidationValid),
			Path:             "attempts/" + successfulAttemptID + "/status.json",
			InvocationCount:  1,
		},
	}
	roles := []Role{{
		role:             domain.RoleLogic,
		outcome:          "completed",
		attemptID:        successfulAttemptID,
		providerInstance: "logic-fallback",
		selectedVia:      "fallback",
	}}
	failures := []manifestFailureDTO{{
		Class:      string(domain.FailureProviderUnavailable),
		Stage:      "review",
		ReasonCode: "provider_unavailable",
		AttemptID:  &failedAttemptID,
	}}
	if err := validateManifestFailures(failures, attempts, roles); err != nil {
		t.Fatalf("validateManifestFailures() rejected retained failure provenance: %v", err)
	}
}
func TestValidateManifestFailuresRequiresCanonicalFailedAttemptOrder(t *testing.T) {
	t.Parallel()

	failedAttempt := func(
		attemptID string,
		role domain.Role,
		provider string,
		selectedAs string,
	) manifestAttemptDTO {
		return manifestAttemptDTO{
			AttemptID:        attemptID,
			Role:             string(role),
			ProviderInstance: provider,
			SelectedAs:       selectedAs,
			State:            string(domain.AttemptFailed),
			ParseState:       string(domain.ParseValid),
			ValidationState:  string(domain.ValidationValid),
			Path:             "attempts/" + attemptID + "/status.json",
			InvocationCount:  1,
		}
	}
	failure := func(attemptID, reason string) manifestFailureDTO {
		return manifestFailureDTO{
			Class:      string(domain.FailureProviderUnavailable),
			Stage:      "review",
			ReasonCode: reason,
			AttemptID:  &attemptID,
		}
	}

	logicPrimaryID := "a_019f596a-d046-79e7-b2b7-59822f012273"
	logicFallbackID := "a_019f596a-d047-79e7-b2b7-59822f012273"
	securityPrimaryID := "a_019f596a-d0ac-7c12-8b68-0bd73e911b2e"
	cases := []struct {
		name      string
		attempts  []manifestAttemptDTO
		roles     []Role
		failures  []manifestFailureDTO
		wantError bool
	}{
		{
			name: "cross-role canonical order",
			attempts: []manifestAttemptDTO{
				failedAttempt(logicPrimaryID, domain.RoleLogic, "logic-provider", "primary"),
				failedAttempt(securityPrimaryID, domain.RoleSecurity, "security-provider", "primary"),
			},
			roles: []Role{
				{role: domain.RoleLogic, outcome: "failed", attemptID: logicPrimaryID, failureReason: "logic_unavailable"},
				{role: domain.RoleSecurity, outcome: "failed", attemptID: securityPrimaryID, failureReason: "security_unavailable"},
			},
			failures: []manifestFailureDTO{
				failure(logicPrimaryID, "logic_unavailable"),
				failure(securityPrimaryID, "security_unavailable"),
			},
		},
		{
			name: "cross-role reordered",
			attempts: []manifestAttemptDTO{
				failedAttempt(logicPrimaryID, domain.RoleLogic, "logic-provider", "primary"),
				failedAttempt(securityPrimaryID, domain.RoleSecurity, "security-provider", "primary"),
			},
			roles: []Role{
				{role: domain.RoleLogic, outcome: "failed", attemptID: logicPrimaryID, failureReason: "logic_unavailable"},
				{role: domain.RoleSecurity, outcome: "failed", attemptID: securityPrimaryID, failureReason: "security_unavailable"},
			},
			failures: []manifestFailureDTO{
				failure(securityPrimaryID, "security_unavailable"),
				failure(logicPrimaryID, "logic_unavailable"),
			},
			wantError: true,
		},
		{
			name: "primary fallback canonical order",
			attempts: []manifestAttemptDTO{
				failedAttempt(logicPrimaryID, domain.RoleLogic, "logic-primary", "primary"),
				failedAttempt(logicFallbackID, domain.RoleLogic, "logic-fallback", "fallback"),
			},
			roles: []Role{
				{role: domain.RoleLogic, outcome: "failed", attemptID: logicFallbackID, failureReason: "fallback_unavailable"},
			},
			failures: []manifestFailureDTO{
				failure(logicPrimaryID, "primary_unavailable"),
				failure(logicFallbackID, "fallback_unavailable"),
			},
		},
		{
			name: "primary fallback reordered",
			attempts: []manifestAttemptDTO{
				failedAttempt(logicPrimaryID, domain.RoleLogic, "logic-primary", "primary"),
				failedAttempt(logicFallbackID, domain.RoleLogic, "logic-fallback", "fallback"),
			},
			roles: []Role{
				{role: domain.RoleLogic, outcome: "failed", attemptID: logicFallbackID, failureReason: "fallback_unavailable"},
			},
			failures: []manifestFailureDTO{
				failure(logicFallbackID, "fallback_unavailable"),
				failure(logicPrimaryID, "primary_unavailable"),
			},
			wantError: true,
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			err := validateManifestFailures(test.failures, test.attempts, test.roles)
			if (err != nil) != test.wantError {
				t.Fatalf("validateManifestFailures() error = %v, want error %t", err, test.wantError)
			}
		})
	}
}

func TestValidateManifestRoleAttemptBindingsRequiresCanonicalCoordinatorSequence(t *testing.T) {
	t.Parallel()

	_, snapshot, _ := queryCommittedFixture(t, domain.ExitCommittedCIRejected)
	final, err := decodeFinalDTO(snapshot.Final().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := decodeManifestDTO(snapshot.Manifest().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	roles, _, err := buildRoles(final.RoleOutcomes)
	if err != nil {
		t.Fatal(err)
	}
	fallback := func(state domain.AttemptState) manifestAttemptDTO {
		attempt := manifest.Attempts[0]
		attempt.AttemptID = "a_019f596a-d047-79e7-b2b7-59822f012273"
		attempt.ProviderInstance = "logic-fallback"
		attempt.SelectedAs = "fallback"
		attempt.State = string(state)
		attempt.Path = "attempts/" + attempt.AttemptID + "/status.json"
		return attempt
	}
	insertFallback := func(value *manifestDTO, attempt manifestAttemptDTO) {
		value.Attempts = append(
			append([]manifestAttemptDTO(nil), value.Attempts[:1]...),
			append([]manifestAttemptDTO{attempt}, value.Attempts[1:]...)...,
		)
	}
	cases := []struct {
		name      string
		mutate    func(*manifestDTO, []Role)
		wantError bool
	}{
		{
			name:   "canonical primary-only sequence",
			mutate: func(*manifestDTO, []Role) {},
		},
		{
			name: "fixed role order",
			mutate: func(value *manifestDTO, _ []Role) {
				value.Attempts[0], value.Attempts[1] = value.Attempts[1], value.Attempts[0]
			},
			wantError: true,
		},
		{
			name: "fallback cannot precede primary",
			mutate: func(value *manifestDTO, _ []Role) {
				value.Attempts[0].SelectedAs = "fallback"
			},
			wantError: true,
		},
		{
			name: "extra attempt after successful primary",
			mutate: func(value *manifestDTO, _ []Role) {
				insertFallback(value, fallback(domain.AttemptFailed))
			},
			wantError: true,
		},
		{
			name: "fallback provider duplicates primary",
			mutate: func(value *manifestDTO, _ []Role) {
				value.Attempts[0].State = string(domain.AttemptFailed)
				attempt := fallback(domain.AttemptSucceeded)
				attempt.ProviderInstance = value.Attempts[0].ProviderInstance
				insertFallback(value, attempt)
			},
			wantError: true,
		},
		{
			name: "later success cannot follow selected failure",
			mutate: func(value *manifestDTO, views []Role) {
				value.Attempts[0].State = string(domain.AttemptFailed)
				insertFallback(value, fallback(domain.AttemptSucceeded))
				views[0].outcome = "failed"
				views[0].failureReason = "provider_unavailable"
			},
			wantError: true,
		},
		{
			name: "configured fallback deterministically selects fallback",
			mutate: func(value *manifestDTO, views []Role) {
				value.Attempts[0].State = string(domain.AttemptFailed)
				insertFallback(value, fallback(domain.AttemptSucceeded))
				views[0].attemptID = "a_019f596a-d047-79e7-b2b7-59822f012273"
				views[0].providerInstance = "logic-fallback"
				views[0].selectedVia = "fallback"
			},
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			candidate := manifest
			candidate.Attempts = append([]manifestAttemptDTO(nil), manifest.Attempts...)
			views := cloneRoles(roles)
			test.mutate(&candidate, views)
			err := validateManifestRoleAttemptBindings(candidate.Attempts, views)
			if (err != nil) != test.wantError {
				t.Fatalf("validateManifestRoleAttemptBindings() error = %v, want error %t", err, test.wantError)
			}
		})
	}
}

func TestReadCommittedBindsSnapshotToStableP2Epoch(t *testing.T) {
	t.Parallel()
	run, snapshot, initial := queryCommittedFixture(t, domain.ExitCommittedCIRejected)
	exit := domain.ExitCommittedCIRejected
	epochTwo := querySnapshotAtEpoch(t, snapshot, 2)
	nextEpoch := queryP2Observation(t, run, epochTwo, domain.JournalCompleted, exit, 2)
	mutableHintOnly := queryP2Observation(t, run, snapshot, domain.JournalManifestCommitted, exit, 1)
	swappedSnapshot := querySnapshotWithManifestMutation(t, snapshot)
	swappedObservation := queryP2Observation(t, run, swappedSnapshot, domain.JournalCompleted, exit, 1)
	cases := []struct {
		name              string
		observations      []ports.PublicationObservation
		wantArtifactError bool
		wantObserveCalls  int
	}{
		{
			name:              "same epoch immutable identity swap",
			observations:      []ports.PublicationObservation{swappedObservation},
			wantArtifactError: true,
			wantObserveCalls:  1,
		},
		{
			name:              "same epoch immutable identity swap on confirmation",
			observations:      []ports.PublicationObservation{initial, swappedObservation},
			wantArtifactError: true,
			wantObserveCalls:  2,
		},
		{
			name:              "snapshot epoch differs from initial observation",
			observations:      []ports.PublicationObservation{nextEpoch},
			wantArtifactError: true,
			wantObserveCalls:  1,
		},
		{
			name:              "P2 epoch changes after snapshot read",
			observations:      []ports.PublicationObservation{initial, nextEpoch},
			wantArtifactError: true,
			wantObserveCalls:  2,
		},
		{
			name:             "mutable journal hint changes at same P2 epoch",
			observations:     []ports.PublicationObservation{initial, mutableHintOnly},
			wantObserveCalls: 2,
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			store := &queryStore{observations: test.observations, snapshot: snapshot}
			service := mustQueryService(t, store, &queryValidator{}, nil)
			_, err := service.ReadCommitted(context.Background(), run)
			if test.wantArtifactError {
				if failureClass(t, err) != domain.FailureArtifact {
					t.Fatalf("failure class = %q, want artifact", failureClass(t, err))
				}
			} else if err != nil {
				t.Fatalf("ReadCommitted() error = %v", err)
			}
			if store.observeCalls != test.wantObserveCalls {
				t.Fatalf("ObserveRun calls = %d, want %d", store.observeCalls, test.wantObserveCalls)
			}
		})
	}
}

func TestReadCommittedRejectsConfirmationDecisionExitMismatch(t *testing.T) {
	t.Parallel()

	run, snapshot, initial := queryCommittedFixture(t, domain.ExitCommittedCIRejected)
	confirmation := queryP2Observation(
		t,
		run,
		snapshot,
		domain.JournalCompleted,
		domain.ExitCommittedPass,
		1,
	)
	store := &queryStore{
		observations: []ports.PublicationObservation{initial, confirmation},
		snapshot:     snapshot,
	}

	_, err := mustQueryService(t, store, &queryValidator{}, nil).ReadCommitted(context.Background(), run)
	if failureClass(t, err) != domain.FailureArtifact {
		t.Fatalf("failure class = %q, want artifact", failureClass(t, err))
	}
	if store.observeCalls != 2 {
		t.Fatalf("ObserveRun calls = %d, want 2", store.observeCalls)
	}
}

func TestReadCommittedRejectsRehashedAlternateManifestPath(t *testing.T) {
	t.Parallel()

	run, snapshot, _ := queryCommittedFixture(t, domain.ExitCommittedCIRejected)
	alternatePath := mustQueryPath(t, run.SessionID().String()+"/"+run.RunID().String()+"/alternate/manifest.json")
	alternateSnapshot := querySnapshotWithManifestPath(t, snapshot, alternatePath)
	observation := queryP2Observation(
		t,
		run,
		alternateSnapshot,
		domain.JournalCompleted,
		domain.ExitCommittedCIRejected,
		1,
	)
	store := &queryStore{observation: observation, snapshot: alternateSnapshot}

	_, err := mustQueryService(t, store, &queryValidator{}, nil).ReadCommitted(context.Background(), run)
	if failureClass(t, err) != domain.FailureArtifact {
		t.Fatalf("failure class = %q, want artifact", failureClass(t, err))
	}
	if store.observeCalls != 1 {
		t.Fatalf("ObserveRun calls = %d, want 1", store.observeCalls)
	}
}

func TestReadRunStatusFailsClosedWhenP2EpochChangesDuringSnapshotRead(t *testing.T) {
	t.Parallel()
	run, snapshot, initial := queryCommittedFixture(t, domain.ExitCommittedCIRejected)
	exit := domain.ExitCommittedCIRejected
	changed := queryP2Observation(t, run, querySnapshotAtEpoch(t, snapshot, 2), domain.JournalCompleted, exit, 2)
	store := &queryStore{
		observations: []ports.PublicationObservation{initial, changed},
		snapshot:     snapshot,
	}
	service := mustQueryService(t, store, &queryValidator{}, nil)
	status, err := service.ReadRunStatus(context.Background(), run)
	if failureClass(t, err) != domain.FailureArtifact {
		t.Fatalf("failure class = %q, want artifact", failureClass(t, err))
	}
	if status.PublicationStatus() != domain.PublicationCorrupt {
		t.Fatalf("status = %q, want corrupt", status.PublicationStatus())
	}
	if _, present := status.FinalPath(); present {
		t.Fatal("ReadRunStatus exposed a final path from a changed P2 epoch")
	}
}
func TestQueryArgumentValidationDefersToDependencyAndCancellationPreflight(t *testing.T) {
	t.Parallel()
	run, _, observation := queryCommittedFixture(t, domain.ExitCommittedCIRejected)
	store := &queryStore{observation: observation}
	service := mustQueryService(t, store, &queryValidator{}, nil)
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := service.ListFindings(cancelled, run, domain.Severity("invalid")); failureClass(t, err) != domain.FailureCancelled {
		t.Fatalf("ListFindings cancellation precedence class = %q, want cancelled", failureClass(t, err))
	}
	if _, err := service.RenderExcerpt(cancelled, run, "bad", "bad"); failureClass(t, err) != domain.FailureCancelled {
		t.Fatalf("RenderExcerpt cancellation precedence class = %q, want cancelled", failureClass(t, err))
	}
	if store.observeCalls != 0 {
		t.Fatalf("argument validation preflight called ObserveRun %d times", store.observeCalls)
	}

	unavailable := &Service{}
	if _, err := unavailable.ListFindings(cancelled, run, domain.Severity("invalid")); failureClass(t, err) != domain.FailureArtifact {
		t.Fatalf("ListFindings dependency precedence class = %q, want artifact", failureClass(t, err))
	}
	if _, err := unavailable.RenderExcerpt(cancelled, run, "bad", "bad"); failureClass(t, err) != domain.FailureArtifact {
		t.Fatalf("RenderExcerpt dependency precedence class = %q, want artifact", failureClass(t, err))
	}
}

func TestQueryPreservesDependencyFailureOverConcurrentCancellation(t *testing.T) {
	run, snapshot, observation := queryCommittedFixture(t, domain.ExitCommittedCIRejected)

	t.Run("snapshot artifact", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		store := &queryStore{
			observation:   observation,
			snapshot:      snapshot,
			readErr:       errors.New("snapshot read failed"),
			afterSnapshot: cancel,
		}
		_, err := mustQueryService(t, store, &queryValidator{}, nil).ReadCommitted(ctx, run)
		if failureClass(t, err) != domain.FailureArtifact {
			t.Fatalf("snapshot failure class = %q, want artifact", failureClass(t, err))
		}
	})
	t.Run("snapshot invalid output", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		invalidOutput, err := domain.NewFailure(
			"query.test",
			domain.FailureInvalidOutput,
			"provider output is invalid",
			nil,
		)
		if err != nil {
			t.Fatal(err)
		}
		store := &queryStore{
			observation:   observation,
			snapshot:      snapshot,
			readErr:       invalidOutput,
			afterSnapshot: cancel,
		}
		_, err = mustQueryService(t, store, &queryValidator{}, nil).ReadCommitted(ctx, run)
		if failureClass(t, err) != domain.FailureCancelled {
			t.Fatalf("snapshot failure class = %q, want cancelled", failureClass(t, err))
		}
	})

	t.Run("excerpt artifact", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		store := &queryStore{
			observation:    observation,
			snapshot:       snapshot,
			auxiliaryErr:   errors.New("excerpt read failed"),
			afterAuxiliary: cancel,
		}
		_, err := mustQueryService(t, store, &queryValidator{}, nil).RenderExcerpt(
			ctx,
			run,
			"F001",
			"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		)
		if failureClass(t, err) != domain.FailureArtifact {
			t.Fatalf("excerpt failure class = %q, want artifact", failureClass(t, err))
		}
	})
}

func TestQueryDependencyCancellationNeverReturnsNilOrHidesHigherPrecedence(t *testing.T) {
	t.Parallel()

	run, snapshot, observation := queryCommittedFixture(t, domain.ExitCommittedCIRejected)
	store := &queryStore{
		observation: observation,
		snapshot:    snapshot,
		readErr:     context.Canceled,
	}
	if _, err := mustQueryService(t, store, &queryValidator{}, nil).ReadCommitted(context.Background(), run); err == nil {
		t.Fatal("live-context dependency cancellation returned nil")
	} else if failureClass(t, err) != domain.FailureCancelled {
		t.Fatalf("live-context dependency cancellation class = %q, want cancelled", failureClass(t, err))
	}

	newFailure := func(class domain.FailureClass) error {
		failure, err := domain.NewFailure("query.test", class, "dependency failure", nil)
		if err != nil {
			t.Fatal(err)
		}
		return failure
	}
	internal := newFailure(domain.FailureInternal)
	artifact := newFailure(domain.FailureArtifact)
	security := newFailure(domain.FailureSecurityPolicy)
	tests := []struct {
		name string
		err  error
		want domain.FailureClass
	}{
		{
			name: "internal over artifact security cancellation",
			err:  errors.Join(context.Canceled, security, artifact, internal),
			want: domain.FailureInternal,
		},
		{
			name: "security over artifact cancellation",
			err:  errors.Join(context.Canceled, security, artifact),
			want: domain.FailureSecurityPolicy,
		},
		{
			name: "security over cancellation",
			err:  errors.Join(context.Canceled, security),
			want: domain.FailureSecurityPolicy,
		},
		{
			name: "cancellation over invalid output",
			err:  errors.Join(context.Canceled, newFailure(domain.FailureInvalidOutput)),
			want: domain.FailureCancelled,
		},
		{
			name: "untyped leaf over cancellation",
			err:  errors.Join(context.Canceled, errors.New("raw dependency failure")),
			want: domain.FailureArtifact,
		},
		{
			name: "untyped leaf over cancellation and lower typed failure",
			err:  errors.Join(context.Canceled, newFailure(domain.FailureInvalidOutput), errors.New("raw dependency failure")),
			want: domain.FailureArtifact,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := reduceDependencyFailureClass(context.Background(), test.err, domain.FailureArtifact); got != test.want {
				t.Fatalf("class = %q, want %q", got, test.want)
			}
		})
	}
}

func TestCommittedFindingAndRuntimeSourcesBindEveryAuxiliaryDigest(t *testing.T) {
	t.Parallel()

	run, snapshot, observation, artifacts, _, attempt := queryRuntimeFixture(t)
	store := &queryStore{snapshot: snapshot, observation: observation, auxiliaryArtifacts: artifacts}
	service := mustQueryService(t, store, &queryValidator{}, nil)

	source, err := service.ReadCommittedFindingSource(context.Background(), run, "F001")
	if err != nil {
		t.Fatalf("ReadCommittedFindingSource() error = %v", err)
	}
	if string(source.Normalized()) != `{"id":"F001"}` || string(source.Excerpt()) != "line one\nline two" {
		t.Fatalf("ReadCommittedFindingSource() = normalized %q excerpt %q", source.Normalized(), source.Excerpt())
	}
	if _, err := service.ReadRuntimeTarget(context.Background(), run); err != nil {
		t.Fatalf("ReadRuntimeTarget() error = %v", err)
	}
	if _, err := service.ReadCommittedAttempt(context.Background(), run, attempt); err != nil {
		t.Fatalf("ReadCommittedAttempt() error = %v", err)
	}
	if len(store.auxiliaryRequests) == 0 {
		t.Fatal("query made no auxiliary artifact requests")
	}
	for _, request := range store.auxiliaryRequests {
		expected, ok := artifacts[request.Path().String()]
		if !ok {
			t.Fatalf("auxiliary request path %q is not a fixture artifact", request.Path().String())
		}
		got, present := request.ExpectedSHA256()
		if !present || got != expected.SHA256() {
			t.Fatalf("auxiliary request %q digest = (%q, %t), want (%q, true)", request.Path().String(), got, present, expected.SHA256())
		}
	}
}

func TestCommittedFindingAndRuntimeSourcesRejectMissingTamperedOrReboundArtifacts(t *testing.T) {
	t.Parallel()

	type reader func(*Service, ports.PublicationRun, domain.AttemptID) error
	readers := map[string]reader{
		"support": func(service *Service, run ports.PublicationRun, _ domain.AttemptID) error {
			_, err := service.ReadCommittedFindingSource(context.Background(), run, "F001")
			return err
		},
		"normalized": func(service *Service, run ports.PublicationRun, _ domain.AttemptID) error {
			_, err := service.ReadCommittedFindingSource(context.Background(), run, "F001")
			return err
		},
		"excerpt": func(service *Service, run ports.PublicationRun, _ domain.AttemptID) error {
			_, err := service.ReadCommittedFindingSource(context.Background(), run, "F001")
			return err
		},
		"target": func(service *Service, run ports.PublicationRun, _ domain.AttemptID) error {
			_, err := service.ReadRuntimeTarget(context.Background(), run)
			return err
		},
		"target-manifest": func(service *Service, run ports.PublicationRun, _ domain.AttemptID) error {
			_, err := service.ReadRuntimeTarget(context.Background(), run)
			return err
		},
		"prompt-manifest": func(service *Service, run ports.PublicationRun, attempt domain.AttemptID) error {
			_, err := service.ReadCommittedAttempt(context.Background(), run, attempt)
			return err
		},
		"stdin": func(service *Service, run ports.PublicationRun, attempt domain.AttemptID) error {
			_, err := service.ReadCommittedAttempt(context.Background(), run, attempt)
			return err
		},
	}
	for artifactName, read := range readers {
		for _, mutation := range []string{"missing", "tampered", "rebound"} {
			t.Run(artifactName+"/"+mutation, func(t *testing.T) {
				run, snapshot, observation, artifacts, paths, attempt := queryRuntimeFixture(t)
				path := paths[artifactName]
				switch mutation {
				case "missing":
					delete(artifacts, path)
				case "tampered":
					artifacts[path] = mustQueryArtifact(t, mustQueryPath(t, path), []byte("tampered support material"))
				case "rebound":
					reboundPath := mustQueryPath(t, run.SessionID().String()+"/"+run.RunID().String()+"/alternate/"+artifactName)
					artifacts[path] = mustQueryArtifact(t, reboundPath, artifacts[path].Bytes())
				}
				store := &queryStore{snapshot: snapshot, observation: observation, auxiliaryArtifacts: artifacts}
				if err := read(mustQueryService(t, store, &queryValidator{}, nil), run, attempt); err == nil {
					t.Fatalf("%s %s artifact was accepted", artifactName, mutation)
				}
			})
		}
	}
}
func TestRuntimeReadsFailClosedOnSupportInventoryTampering(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		artifact string
		missing  bool
		read     func(*Service, ports.PublicationRun, domain.AttemptID) error
	}{
		{"support index tampered", "support", false, func(service *Service, run ports.PublicationRun, _ domain.AttemptID) error {
			_, err := service.ReadRuntimeTarget(context.Background(), run)
			return err
		}},
		{"support index missing", "support", true, func(service *Service, run ports.PublicationRun, _ domain.AttemptID) error {
			_, err := service.ReadRuntimeTarget(context.Background(), run)
			return err
		}},
		{"target manifest tampered", "target-manifest", false, func(service *Service, run ports.PublicationRun, _ domain.AttemptID) error {
			_, err := service.ReadRuntimeTarget(context.Background(), run)
			return err
		}},
		{"target manifest missing", "target-manifest", true, func(service *Service, run ports.PublicationRun, _ domain.AttemptID) error {
			_, err := service.ReadRuntimeTarget(context.Background(), run)
			return err
		}},
		{"prompt manifest tampered", "prompt-manifest", false, func(service *Service, run ports.PublicationRun, attempt domain.AttemptID) error {
			_, err := service.ReadCommittedAttempt(context.Background(), run, attempt)
			return err
		}},
		{"prompt manifest missing", "prompt-manifest", true, func(service *Service, run ports.PublicationRun, attempt domain.AttemptID) error {
			_, err := service.ReadCommittedAttempt(context.Background(), run, attempt)
			return err
		}},
		{"stdin tampered", "stdin", false, func(service *Service, run ports.PublicationRun, attempt domain.AttemptID) error {
			_, err := service.ReadCommittedAttempt(context.Background(), run, attempt)
			return err
		}},
		{"stdin missing", "stdin", true, func(service *Service, run ports.PublicationRun, attempt domain.AttemptID) error {
			_, err := service.ReadCommittedAttempt(context.Background(), run, attempt)
			return err
		}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			run, snapshot, observation, artifacts, paths, attempt := queryRuntimeFixture(t)
			store := &queryStore{snapshot: snapshot, observation: observation, auxiliaryArtifacts: artifacts}
			service := mustQueryService(t, store, &queryValidator{}, nil)
			if _, err := service.ReadRuntimeTarget(context.Background(), run); err != nil {
				t.Fatalf("runtime fixture target read failed: %v", err)
			}
			if strings.Contains(test.artifact, "prompt") || test.artifact == "stdin" {
				if _, err := service.ReadCommittedAttempt(context.Background(), run, attempt); err != nil {
					t.Fatalf("runtime fixture attempt read failed: %v", err)
				}
			}
			if test.missing {
				delete(store.auxiliaryArtifacts, paths[test.artifact])
			} else {
				store.auxiliaryArtifacts[paths[test.artifact]] = mustQueryArtifact(t, mustQueryPath(t, paths[test.artifact]), []byte("tampered runtime material"))
			}
			if err := test.read(service, run, attempt); err == nil {
				t.Fatalf("%s did not fail closed", test.name)
			}
		})
	}
}

func TestReadRuntimeTargetRejectsMetadataThatDoesNotMatchFinalIdentity(t *testing.T) {
	t.Parallel()

	run, snapshot, _, artifacts, paths, _ := queryRuntimeFixture(t)
	targetManifest := artifacts[paths["target-manifest"]]
	mutatedTargetManifest := mustQueryArtifact(t, targetManifest.Path(), []byte(strings.Replace(
		string(targetManifest.Bytes()), `"base_object_id":""`,
		`"base_object_id":"0123456789012345678901234567890123456789"`, 1,
	)))
	support := artifacts[paths["support"]]
	mutatedSupport := mustQueryArtifact(t, support.Path(), []byte(strings.Replace(
		string(support.Bytes()), targetManifest.SHA256(), mutatedTargetManifest.SHA256(), 1,
	)))
	mutatedManifest := mustQueryArtifact(t, snapshot.Manifest().Path(), []byte(strings.Replace(
		string(snapshot.Manifest().Bytes()), support.SHA256(), mutatedSupport.SHA256(), 1,
	)))
	mutatedSnapshot, err := ports.NewCommittedPublicationSnapshot(
		snapshot.Final(), mutatedManifest, snapshot.LineageEdge(), snapshot.Epoch(),
	)
	if err != nil {
		t.Fatal(err)
	}
	artifacts[paths["target-manifest"]] = mutatedTargetManifest
	artifacts[paths["support"]] = mutatedSupport
	store := &queryStore{
		snapshot:           mutatedSnapshot,
		observation:        queryP2Observation(t, run, mutatedSnapshot, domain.JournalCompleted, domain.ExitCommittedCIRejected, 1),
		auxiliaryArtifacts: artifacts,
	}
	if _, err := mustQueryService(t, store, &queryValidator{}, nil).ReadRuntimeTarget(context.Background(), run); err == nil {
		t.Fatal("runtime target with mismatched final identity was accepted")
	}
}
func TestReadCommittedAttemptRejectsRepairPromptSelection(t *testing.T) {
	t.Parallel()

	run, snapshot, _, artifacts, paths, attempt := queryRuntimeFixture(t)
	targetManifest := artifacts[paths["target-manifest"]]
	mutatedTargetManifest := mustQueryArtifact(t, targetManifest.Path(), []byte(strings.Replace(
		string(targetManifest.Bytes()),
		`"sequence":1,"purpose":"initial"`,
		`"sequence":2,"purpose":"repair"`,
		1,
	)))
	support := artifacts[paths["support"]]
	mutatedSupport := mustQueryArtifact(t, support.Path(), []byte(strings.Replace(
		string(support.Bytes()), targetManifest.SHA256(), mutatedTargetManifest.SHA256(), 1,
	)))
	mutatedManifest := mustQueryArtifact(t, snapshot.Manifest().Path(), []byte(strings.Replace(
		string(snapshot.Manifest().Bytes()), support.SHA256(), mutatedSupport.SHA256(), 1,
	)))
	mutatedSnapshot, err := ports.NewCommittedPublicationSnapshot(
		snapshot.Final(), mutatedManifest, snapshot.LineageEdge(), snapshot.Epoch(),
	)
	if err != nil {
		t.Fatal(err)
	}
	artifacts[paths["target-manifest"]] = mutatedTargetManifest
	artifacts[paths["support"]] = mutatedSupport
	store := &queryStore{
		snapshot:           mutatedSnapshot,
		observation:        queryP2Observation(t, run, mutatedSnapshot, domain.JournalCompleted, domain.ExitCommittedCIRejected, 1),
		auxiliaryArtifacts: artifacts,
	}

	if _, err := mustQueryService(t, store, &queryValidator{}, nil).ReadCommittedAttempt(context.Background(), run, attempt); err == nil {
		t.Fatal("repair prompt selection was accepted as replay authority")
	}
}

func queryRuntimeFixture(t *testing.T) (ports.PublicationRun, ports.CommittedPublicationSnapshot, ports.PublicationObservation, map[string]ports.ImmutablePublicationArtifact, map[string]string, domain.AttemptID) {
	t.Helper()
	run, baseSnapshot, _ := queryCommittedFixture(t, domain.ExitCommittedCIRejected)
	prefix := run.SessionID().String() + "/" + run.RunID().String()
	attempt, err := domain.ParseAttemptID("a_019f596a-d048-79e7-b2b7-59822f012273")
	if err != nil {
		t.Fatal(err)
	}
	targetPath := prefix + "/target/target.bytes"
	target := mustQueryArtifact(t, mustQueryPath(t, targetPath), []byte("runtime target bytes"))
	stdinPath := prefix + "/prompts/" + attempt.String() + "/001-initial.stdin"
	stdin := mustQueryArtifact(t, mustQueryPath(t, stdinPath), []byte("runtime stdin bytes"))
	promptPath := prefix + "/prompts/" + attempt.String() + "/001-initial.manifest.json"
	completeStdinSHA256 := prompt.CompleteStdinSHA256(stdin.Bytes())
	prompt := mustQueryArtifact(t, mustQueryPath(t, promptPath), []byte(fmt.Sprintf(`{"schema_version":"kar-runtime-prompt-manifest.v1","target":{"path":%q,"sha256":%q},"stdin":{"path":%q,"sha256":%q},"complete_stdin_sha256":%q,"template_id":"review","template_version":"v1","template_sha256":"sha256:%s","source_invocation_id":"source","execution_invocation_id":"execution","scope":"repository","role":"logic","adapter_profile":"default","adapter_parameters":{"model":"trusted"}}`, targetPath, target.SHA256(), stdinPath, stdin.SHA256(), completeStdinSHA256, strings.Repeat("c", 64))))
	targetManifestPath := prefix + "/target/target-manifest.json"
	targetManifest := mustQueryArtifact(t, mustQueryPath(t, targetManifestPath), []byte(fmt.Sprintf(`{"schema_version":"kar-runtime-target-manifest.v1","target":{"path":%q,"sha256":%q},"target_kind":"patch","repository_id":"","base_object_id":"","head_object_id":"","head_tree_object_id":"","index_tree_object_id":"","prompts":[{"path":%q,"sha256":%q}],"selected_replay_prompts":[{"attempt_id":%q,"sequence":1,"purpose":"initial","artifact":{"path":%q,"sha256":%q}}]}`, targetPath, target.SHA256(), promptPath, prompt.SHA256(), attempt.String(), promptPath, prompt.SHA256())))
	normalizedPath := prefix + "/excerpts/F001.json"
	normalized := mustQueryArtifact(t, mustQueryPath(t, normalizedPath), []byte(`{"id":"F001"}`))
	excerptPath := prefix + "/excerpts/F001_1.md"
	excerpt := mustQueryArtifact(t, mustQueryPath(t, excerptPath), []byte("line one\nline two"))
	supportPath := prefix + "/support/index.json"
	support := mustQueryArtifact(t, mustQueryPath(t, supportPath), []byte(fmt.Sprintf(`{"schema_version":"kar-run-support-index.v1","artifacts":[{"path":%q,"sha256":%q},{"path":%q,"sha256":%q},{"path":%q,"sha256":%q},{"path":%q,"sha256":%q},{"path":%q,"sha256":%q},{"path":%q,"sha256":%q}]}`, normalizedPath, normalized.SHA256(), excerptPath, excerpt.SHA256(), targetPath, target.SHA256(), stdinPath, stdin.SHA256(), promptPath, prompt.SHA256(), targetManifestPath, targetManifest.SHA256())))

	finalRecord, err := decodeFinalDTO(baseSnapshot.Final().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	finalRecord.Target.ContentSHA256 = target.SHA256()
	for findingIndex := range finalRecord.Findings {
		for evidenceIndex := range finalRecord.Findings[findingIndex].Evidence {
			item := &finalRecord.Findings[findingIndex].Evidence[evidenceIndex]
			item.Source.SourceTargetSHA256 = target.SHA256()
			item.Current.TargetSHA256 = target.SHA256()
			claim, claimErr := evidence.NewCurrentClaim(evidence.CurrentClaimInput{
				TargetSHA256: item.Current.TargetSHA256,
				Side:         evidence.Side(item.Current.Side),
				Path:         item.Current.Path,
				LineStart:    item.Current.LineStart,
				LineEnd:      item.Current.LineEnd,
				Quote:        item.Current.Quote,
			})
			if claimErr != nil {
				t.Fatal(claimErr)
			}
			item.Current.CurrentExcerptSHA256, claimErr = claim.ExcerptSHA256([]byte(item.Current.Quote))
			if claimErr != nil {
				t.Fatal(claimErr)
			}
		}
	}
	finalBytes, err := json.Marshal(finalRecord)
	if err != nil {
		t.Fatal(err)
	}
	finalIdentity, err := ports.NewFinalReviewIdentity(baseSnapshot.Final().Identity().ReviewID(), baseSnapshot.Final().Identity().Path(), querySHA(finalBytes))
	if err != nil {
		t.Fatal(err)
	}
	final, err := ports.NewFinalReviewArtifact(finalIdentity, finalBytes)
	if err != nil {
		t.Fatal(err)
	}
	manifestRecord, err := decodeManifestDTO(baseSnapshot.Manifest().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	manifestRecord.Target.ContentSHA256 = target.SHA256()
	manifestRecord.CompositeIdentity.SupportIndex = &artifactIdentityDTO{Path: supportPath, SHA256: support.SHA256()}
	manifestRecord.FinalReview.SHA256 = finalIdentity.SHA256()
	manifestRecord.RecoveryJournal.ExpectedFinal.SHA256 = finalIdentity.SHA256()
	manifestBytes, err := json.Marshal(manifestRecord)
	if err != nil {
		t.Fatal(err)
	}
	manifest := mustQueryArtifact(t, baseSnapshot.Manifest().Path(), manifestBytes)
	snapshot, err := ports.NewCommittedPublicationSnapshot(final, manifest, baseSnapshot.LineageEdge(), baseSnapshot.Epoch())
	if err != nil {
		t.Fatal(err)
	}
	finalRecord, finalErr := decodeFinalDTO(final.Bytes())
	manifestRecord, manifestErr := decodeManifestDTO(manifest.Bytes())
	if finalErr != nil || manifestErr != nil {
		t.Fatalf("runtime fixture decode: final=%v manifest=%v", finalErr, manifestErr)
	}
	exit := domain.ExitCommittedCIRejected
	decision, decisionErr := domain.NewPublicationDecision(domain.PublicationCommitted, domain.PublicationAuthorityP2, domain.RecoveryActionReconstructCompletedStatus, &exit, nil)
	if decisionErr != nil {
		t.Fatal(decisionErr)
	}
	if _, semanticErr := buildCommittedReview(run, decision, snapshot, finalRecord, manifestRecord); semanticErr != nil {
		t.Fatalf("runtime fixture semantics: %v", semanticErr)
	}
	observation := queryP2Observation(t, run, snapshot, domain.JournalCompleted, domain.ExitCommittedCIRejected, 1)
	return run, snapshot, observation, map[string]ports.ImmutablePublicationArtifact{supportPath: support, normalizedPath: normalized, excerptPath: excerpt, targetPath: target, stdinPath: stdin, promptPath: prompt, targetManifestPath: targetManifest}, map[string]string{"support": supportPath, "normalized": normalizedPath, "excerpt": excerptPath, "target": targetPath, "target-manifest": targetManifestPath, "prompt-manifest": promptPath, "stdin": stdinPath}, attempt
}

type queryStore struct {
	observation                 ports.PublicationObservation
	observations                []ports.PublicationObservation
	snapshot                    ports.CommittedPublicationSnapshot
	resolved                    ports.PublicationRun
	auxiliaryArtifact           ports.ImmutablePublicationArtifact
	auxiliaryArtifacts          map[string]ports.ImmutablePublicationArtifact
	observeErr                  error
	readErr                     error
	resolveErr                  error
	auxiliaryErr                error
	returnZeroAuxiliaryArtifact bool
	snapshotReads               int
	resolveCalls                int
	observeCalls                int
	auxiliaryReads              int
	auxiliaryRequest            ports.ReadAuxiliaryArtifactRequest
	auxiliaryRequests           []ports.ReadAuxiliaryArtifactRequest
	afterSnapshot               func()
	afterAuxiliary              func()
}

func (store *queryStore) IssueReviewID(context.Context, ports.IssueReviewIDRequest) (ports.IssuedReviewID, error) {
	return ports.IssuedReviewID{}, errors.New("not implemented")
}
func (store *queryStore) ResolveRun(context.Context, ports.ResolvePublicationRunRequest) (ports.PublicationRun, error) {
	store.resolveCalls++
	return store.resolved, store.resolveErr
}

func (store *queryStore) ObserveRun(context.Context, ports.ObserveRunRequest) (ports.PublicationObservation, error) {
	index := store.observeCalls
	store.observeCalls++
	if len(store.observations) != 0 {
		if index >= len(store.observations) {
			index = len(store.observations) - 1
		}
		return store.observations[index], store.observeErr
	}
	return store.observation, store.observeErr
}

func (store *queryStore) PersistValidatedCandidate(context.Context, ports.PersistValidatedCandidateRequest) (ports.PersistValidatedCandidateResult, error) {
	return ports.PersistValidatedCandidateResult{}, errors.New("not implemented")
}

func (store *queryStore) PersistAuxiliaryArtifact(context.Context, ports.PersistAuxiliaryArtifactRequest) (ports.PersistAuxiliaryArtifactResult, error) {
	return ports.PersistAuxiliaryArtifactResult{}, errors.New("not implemented")
}

func (store *queryStore) ReadAuxiliaryArtifact(_ context.Context, request ports.ReadAuxiliaryArtifactRequest) (ports.ImmutablePublicationArtifact, error) {
	store.auxiliaryReads++
	store.auxiliaryRequest = request
	store.auxiliaryRequests = append(store.auxiliaryRequests, request)
	if store.afterAuxiliary != nil {
		store.afterAuxiliary()
	}
	if store.auxiliaryErr != nil {
		return ports.ImmutablePublicationArtifact{}, store.auxiliaryErr
	}
	if store.returnZeroAuxiliaryArtifact {
		return ports.ImmutablePublicationArtifact{}, nil
	}
	if artifact, ok := store.auxiliaryArtifacts[request.Path().String()]; ok {
		return artifact, nil
	}
	if !store.auxiliaryArtifact.Valid() {
		return ports.ImmutablePublicationArtifact{}, fs.ErrNotExist
	}
	return store.auxiliaryArtifact, nil
}

func (store *queryStore) PrepareComposite(context.Context, ports.PrepareCompositeRequest) (ports.PreparedComposite, error) {
	return ports.PreparedComposite{}, errors.New("not implemented")
}

func (store *queryStore) StageFinal(context.Context, ports.StageFinalRequest) (ports.StageFinalResult, error) {
	return ports.StageFinalResult{}, errors.New("not implemented")
}

func (store *queryStore) AdoptStagedFinal(context.Context, ports.AdoptStagedFinalRequest) (ports.StageFinalResult, error) {
	return ports.StageFinalResult{}, errors.New("not implemented")
}

func (store *queryStore) InstallFinal(context.Context, ports.InstallFinalRequest) (ports.InstallFinalResult, error) {
	return ports.InstallFinalResult{}, errors.New("not implemented")
}

func (store *queryStore) ReplaceMutable(context.Context, ports.MutableReplaceRequest) (ports.MutableReplaceResult, error) {
	return ports.MutableReplaceResult{}, errors.New("not implemented")
}

func (store *queryStore) CommitPreparedComposite(context.Context, ports.PreparedComposite) (ports.CompositeCommitResult, error) {
	return ports.CompositeCommitResult{}, errors.New("not implemented")
}

func (store *queryStore) ReadCommittedSnapshot(context.Context, ports.ReadCommittedSnapshotRequest) (ports.CommittedPublicationSnapshot, error) {
	store.snapshotReads++
	if store.afterSnapshot != nil {
		store.afterSnapshot()
	}
	return store.snapshot, store.readErr
}

func (store *queryStore) WriteCorruptionDiagnostic(context.Context, ports.CorruptionDiagnosticRequest) (ports.CorruptionDiagnosticResult, error) {
	return ports.CorruptionDiagnosticResult{}, errors.New("not implemented")
}

type queryValidator struct {
	err   error
	calls int
}

func (validator *queryValidator) Validate(context.Context, ports.AssetID, []byte) error {
	validator.calls++
	return validator.err
}

type queryTargetReader struct {
	availability evidence.ImmutableTargetAvailability
	bytes        []byte
	err          error
	calls        int
}

func (reader *queryTargetReader) ReadImmutableTarget(context.Context, string, evidence.Side, ports.SafeRelativePath) (evidence.ImmutableTargetAvailability, []byte, error) {
	reader.calls++
	return reader.availability, append([]byte(nil), reader.bytes...), reader.err
}

func mustQueryService(t *testing.T, store ports.PublicationStore, validator SchemaValidator, reader evidence.ImmutableTargetReader) *Service {
	t.Helper()
	service, err := NewService(store, validator, reader, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func queryCommittedFixture(t *testing.T, exit domain.OperationalExitCode) (ports.PublicationRun, ports.CommittedPublicationSnapshot, ports.PublicationObservation) {
	t.Helper()
	return queryCommittedFixtureWithSourceExcerptSHA256(t, exit, querySourceExcerptSHA256(t))
}

func queryCommittedFixtureWithSourceExcerptSHA256(
	t *testing.T,
	exit domain.OperationalExitCode,
	sourceExcerptSHA256 string,
) (ports.PublicationRun, ports.CommittedPublicationSnapshot, ports.PublicationObservation) {
	t.Helper()
	root, err := ports.NewAnchoredRoot("/private/query-test")
	if err != nil {
		t.Fatal(err)
	}
	sessionID, err := domain.ParseSessionID("s_019f596a-cf80-7c67-b265-f37053d51ccf")
	if err != nil {
		t.Fatal(err)
	}
	runID, err := domain.ParseRunID("r_019f596a-cfe4-7c9c-b82e-7149158243ba")
	if err != nil {
		t.Fatal(err)
	}
	reviewID, err := domain.ParseReviewID("019f596a-d174-7321-b920-c2d312c82cc2")
	if err != nil {
		t.Fatal(err)
	}
	run, err := ports.NewPublicationRun(root, sessionID, runID)
	if err != nil {
		t.Fatal(err)
	}
	prefix := sessionID.String() + "/" + runID.String()
	finalPath := mustQueryPath(t, prefix+"/review_"+reviewID.String()+".json")
	manifestPath := mustQueryPath(t, prefix+"/manifest.json")
	edgePath := mustQueryPath(t, "store/lineage-edges/e_"+reviewID.String()+".json")
	epochPath := mustQueryPath(t, "store/epochs/epoch_00000000000000000001.json")
	edgeBytes := []byte(`{"schema_version":"kar-lineage-edge.v1"}`)
	epochBytes := []byte(`{"schema_version":"kar-publication-epoch.v1"}`)
	edge := mustQueryArtifact(t, edgePath, edgeBytes)
	epochRecord := mustQueryArtifact(t, epochPath, epochBytes)
	epoch, err := ports.NewPublicationEpoch(1, epochRecord)
	if err != nil {
		t.Fatal(err)
	}
	finalBytes := []byte(fmt.Sprintf(`{
		"schema_version":"kar-review-artifact.v2","session_id":%q,"run_id":%q,"review_id":%q,"run_type":"review","created_at":"2026-07-13T03:00:00Z",
		"kar":{"version":"0.1.0","commit":null},
		"immutable_lineage":{"parent_run_id":null,"source_run_id":null,"source_review_id":null,"source_finding_ref":null,"replay_mode":null,"lineage_edge_path":%q,"lineage_edge_sha256":%q},
		"target":{"content_sha256":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","manifest_path":"target/target-manifest.json","base_oid":null,"head_oid":null},
		"validation":{"status":"valid","schema_validation":"passed","semantic_validation":"passed","evidence_validation":"passed"},
		"content_verdict":"request_changes","coverage_status":"complete","publication_status":"committed","ci_decision":"fail","ci_reason_codes":["request_changes_threshold"],
		"severity_threshold":{"request_changes_at_or_above":"high","policy_source":"project_local"},
		"role_outcomes":[
			{"role":"logic","required":true,"outcome":"completed","attempt_id":"a_019f596a-d048-79e7-b2b7-59822f012273","provider_instance":"logic-provider","selected_via":"primary","valid_finding_ids":["F001"],"failure_reason":null,"limitations":[]},
			{"role":"security","required":true,"outcome":"completed","attempt_id":"a_019f596a-d0ac-7c12-8b68-0bd73e911b2e","provider_instance":"security-provider","selected_via":"primary","valid_finding_ids":[],"failure_reason":null,"limitations":[]}
		],
		"findings":[{"id":"F001","fingerprint":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","role":"logic","provider_instance":"logic-provider","severity":"high","title":"title","description":"description","evidence":[{"source":{"session_id":%q,"run_id":%q,"review_id":%q,"finding_id":"F001","source_target_sha256":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","source_excerpt_sha256":%q},"current":{"target_sha256":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","side":"worktree","path":"internal/example.go","line_start":1,"line_end":2,"quote":"line one\nline two","current_excerpt_sha256":%q,"verification":"verified"}}],"recommendation":"recommendation","confidence":"high","lifecycle":"open"}],
		"limitations":[],"provenance":{"aggregation_path":"aggregation.json","final_validation_path":"validation/final.json","manifest_path":"manifest.json"}
	}`, sessionID.String(), runID.String(), reviewID.String(), edgePath.String(), edge.SHA256(), sessionID.String(), runID.String(), reviewID.String(), sourceExcerptSHA256, queryCurrentExcerptSHA256(t)))
	finalIdentity, err := ports.NewFinalReviewIdentity(reviewID, finalPath, querySHA(finalBytes))
	if err != nil {
		t.Fatal(err)
	}
	final, err := ports.NewFinalReviewArtifact(finalIdentity, finalBytes)
	if err != nil {
		t.Fatal(err)
	}
	manifestBytes := []byte(fmt.Sprintf(`{
		"schema_version":"kar-run-manifest.v2","session_id":%q,"run_id":%q,"run_type":"review","state":"completed","sealed":true,"created_at":"2026-07-13T03:00:00Z","started_at":null,"completed_at":"2026-07-13T03:01:00Z","kar_version":"0.1.0",
		"immutable_lineage":{"parent_run_id":null,"source_run_id":null,"source_review_id":null,"source_finding_ref":null,"replay_mode":null,"lineage_edge_path":%q,"lineage_edge_sha256":%q},
		"target":{"manifest_path":"target/target-manifest.json","content_sha256":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"selected_roles":["logic","security"],"required_roles":["logic","security"],"attempts":[
			{"attempt_id":"a_019f596a-d048-79e7-b2b7-59822f012273","role":"logic","provider_instance":"logic-provider","selected_as":"primary","state":"succeeded","parse_state":"valid","validation_state":"valid","path":"attempts/a_019f596a-d048-79e7-b2b7-59822f012273/status.json","invocation_count":1},
			{"attempt_id":"a_019f596a-d0ac-7c12-8b68-0bd73e911b2e","role":"security","provider_instance":"security-provider","selected_as":"primary","state":"succeeded","parse_state":"valid","validation_state":"valid","path":"attempts/a_019f596a-d0ac-7c12-8b68-0bd73e911b2e/status.json","invocation_count":1}
		],
		"content_verdict":"request_changes","coverage_status":"complete","publication_status":"committed","ci_decision":"fail","ci_reason_codes":["request_changes_threshold"],"persisted_journal_state":"completed","durable_observation_class":"P2_COMMITTED","derived_publication_status":"committed","publication_authority":"P2",
		"recovery_journal":{"expected_staged":null,"expected_final":{"path":%q,"sha256":%q},"validated_candidate_sha256":%q},
		"composite_identity":{"manifest":{"path":%q},"lineage_edge":{"path":%q,"sha256":%q},"epoch":{"path":%q}},"recovery_action":"reconstruct_completed_status",
		"final_review":{"review_id":%q,"path":%q,"sha256":%q},"failures":[],"warnings":[],"exit_code":1
	}`, sessionID.String(), runID.String(), edgePath.String(), edge.SHA256(), finalPath.String(), finalIdentity.SHA256(), finalIdentity.SHA256(), manifestPath.String(), edgePath.String(), edge.SHA256(), epochPath.String(), reviewID.String(), finalPath.String(), finalIdentity.SHA256()))
	manifest := mustQueryArtifact(t, manifestPath, manifestBytes)
	snapshot, err := ports.NewCommittedPublicationSnapshot(final, manifest, edge, epoch)
	if err != nil {
		t.Fatal(err)
	}
	observation := queryP2Observation(t, run, snapshot, domain.JournalCompleted, exit, 1)
	return run, snapshot, observation
}
func queryFollowupCommittedFixture(t *testing.T, resolution domain.FollowupResolution) (ports.PublicationRun, ports.CommittedPublicationSnapshot, ports.PublicationObservation) {
	t.Helper()
	run, snapshot, _ := queryCommittedFixture(t, domain.ExitCommittedCIRejected)
	lineage := `"parent_run_id":"r_019f596a-cfe4-7c9c-b82e-7149158243bb","source_run_id":"r_019f596a-cfe4-7c9c-b82e-7149158243bc","source_review_id":"019f596a-d174-7321-b920-c2d312c82cc3","source_finding_ref":"F001","replay_mode":null`
	outcome := `"followup_outcome":{"resolution":"` + string(resolution) + `","rationale":"verified resolution","evidence":[{"source":{"session_id":"s_019f596a-cf80-7c67-b265-f37053d51ccf","run_id":"r_019f596a-cfe4-7c9c-b82e-7149158243bc","review_id":"019f596a-d174-7321-b920-c2d312c82cc3","finding_id":"F001","source_target_sha256":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","source_excerpt_sha256":"` + querySourceExcerptSHA256(t) + `"},"current":{"target_sha256":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","side":"worktree","path":"internal/example.go","line_start":1,"line_end":2,"quote":"line one\nline two","current_excerpt_sha256":"` + queryCurrentExcerptSHA256(t) + `","verification":"verified"}}]},`
	finalBytes := strings.ReplaceAll(string(snapshot.Final().Bytes()), `"run_type":"review"`, `"run_type":"followup"`)
	finalBytes = strings.Replace(finalBytes, `"parent_run_id":null,"source_run_id":null,"source_review_id":null,"source_finding_ref":null,"replay_mode":null`, lineage, 1)
	finalBytes = strings.Replace(finalBytes, `"run_id":"r_019f596a-cfe4-7c9c-b82e-7149158243ba","review_id":"019f596a-d174-7321-b920-c2d312c82cc2","finding_id":"F001"`, `"run_id":"r_019f596a-cfe4-7c9c-b82e-7149158243bc","review_id":"019f596a-d174-7321-b920-c2d312c82cc3","finding_id":"F001"`, 1)
	finalBytes = strings.Replace(finalBytes, `"target":{"content_sha256"`, outcome+`"target":{"content_sha256"`, 1)
	finalIdentity, err := ports.NewFinalReviewIdentity(snapshot.Final().Identity().ReviewID(), snapshot.Final().Identity().Path(), querySHA([]byte(finalBytes)))
	if err != nil {
		t.Fatal(err)
	}
	final, err := ports.NewFinalReviewArtifact(finalIdentity, []byte(finalBytes))
	if err != nil {
		t.Fatal(err)
	}
	manifestBytes := strings.ReplaceAll(string(snapshot.Manifest().Bytes()), `"run_type":"review"`, `"run_type":"followup"`)
	manifestBytes = strings.Replace(manifestBytes, `"parent_run_id":null,"source_run_id":null,"source_review_id":null,"source_finding_ref":null,"replay_mode":null`, lineage, 1)
	manifestBytes = strings.Replace(manifestBytes, `"target":{"manifest_path"`, outcome+`"target":{"manifest_path"`, 1)
	manifestBytes = strings.ReplaceAll(manifestBytes, snapshot.Final().Identity().SHA256(), finalIdentity.SHA256())
	manifest := mustQueryArtifact(t, snapshot.Manifest().Path(), []byte(manifestBytes))
	followupSnapshot, err := ports.NewCommittedPublicationSnapshot(final, manifest, snapshot.LineageEdge(), snapshot.Epoch())
	if err != nil {
		t.Fatal(err)
	}
	return run, followupSnapshot, queryP2Observation(t, run, followupSnapshot, domain.JournalCompleted, domain.ExitCommittedCIRejected, 1)
}

func queryP2Observation(
	t *testing.T,
	run ports.PublicationRun,
	snapshot ports.CommittedPublicationSnapshot,
	journalState domain.PersistedJournalState,
	exit domain.OperationalExitCode,
	epoch uint64,
) ports.PublicationObservation {
	t.Helper()
	prefix := run.SessionID().String() + "/" + run.RunID().String()
	journalPath := mustQueryPath(t, prefix+"/publication/journal.json")
	journal, err := ports.NewMissingMutablePublicationDocument(ports.MutablePublicationJournal, journalPath)
	if err != nil {
		t.Fatal(err)
	}
	statusPath := mustQueryPath(t, prefix+"/status.json")
	status, err := ports.NewMissingMutablePublicationDocument(ports.MutablePublicationStatus, statusPath)
	if err != nil {
		t.Fatal(err)
	}
	material, err := ports.NewPublicationRecoveryMaterialWithCommittedSnapshot(
		snapshot.Final(),
		journal,
		status,
		snapshot,
	)
	if err != nil {
		t.Fatal(err)
	}
	observation, err := ports.NewPublicationObservationWithRecovery(
		journalState,
		domain.DurableObservationP2Committed,
		&exit,
		nil,
		epoch,
		material,
	)
	if err != nil {
		t.Fatal(err)
	}
	return observation
}

func querySnapshotAtEpoch(
	t *testing.T,
	snapshot ports.CommittedPublicationSnapshot,
	epochValue uint64,
) ports.CommittedPublicationSnapshot {
	t.Helper()
	path := mustQueryPath(t, fmt.Sprintf("store/epochs/epoch_%020d.json", epochValue))
	epochBytes := []byte(fmt.Sprintf(`{"schema_version":"kar-publication-epoch.v1","store_epoch":%d}`, epochValue))
	record := mustQueryArtifact(t, path, epochBytes)
	epoch, err := ports.NewPublicationEpoch(epochValue, record)
	if err != nil {
		t.Fatal(err)
	}
	updated, err := ports.NewCommittedPublicationSnapshot(
		snapshot.Final(),
		snapshot.Manifest(),
		snapshot.LineageEdge(),
		epoch,
	)
	if err != nil {
		t.Fatal(err)
	}
	return updated
}

func querySnapshotWithManifestMutation(
	t *testing.T,
	snapshot ports.CommittedPublicationSnapshot,
) ports.CommittedPublicationSnapshot {
	t.Helper()
	mutatedBytes := append(snapshot.Manifest().Bytes(), '\n')
	mutated, err := ports.NewImmutablePublicationArtifact(
		snapshot.Manifest().Path(),
		querySHA(mutatedBytes),
		mutatedBytes,
	)
	if err != nil {
		t.Fatal(err)
	}
	updated, err := ports.NewCommittedPublicationSnapshot(
		snapshot.Final(),
		mutated,
		snapshot.LineageEdge(),
		snapshot.Epoch(),
	)
	if err != nil {
		t.Fatal(err)
	}
	return updated
}
func querySnapshotWithManifestPath(
	t *testing.T,
	snapshot ports.CommittedPublicationSnapshot,
	path ports.SafeRelativePath,
) ports.CommittedPublicationSnapshot {
	t.Helper()
	manifest := snapshot.Manifest()
	manifestPath := manifest.Path().String()
	if strings.Count(string(manifest.Bytes()), manifestPath) != 1 {
		t.Fatalf("manifest fixture references %q an unexpected number of times", manifestPath)
	}
	manifestBytes := []byte(strings.ReplaceAll(string(manifest.Bytes()), manifestPath, path.String()))
	updatedManifest := mustQueryArtifact(t, path, manifestBytes)
	updated, err := ports.NewCommittedPublicationSnapshot(
		snapshot.Final(),
		updatedManifest,
		snapshot.LineageEdge(),
		snapshot.Epoch(),
	)
	if err != nil {
		t.Fatal(err)
	}
	return updated
}

func querySourceExcerptSHA256(t *testing.T) string {
	t.Helper()
	return querySHA([]byte("historical source excerpt"))
}

func queryCurrentExcerptSHA256(t *testing.T) string {
	t.Helper()
	claim, err := evidence.NewCurrentClaim(evidence.CurrentClaimInput{
		TargetSHA256: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Side:         evidence.SideWorktree,
		Path:         "internal/example.go",
		LineStart:    1,
		LineEnd:      2,
		Quote:        "line one\nline two",
	})
	if err != nil {
		t.Fatal(err)
	}
	digest, err := claim.ExcerptSHA256([]byte("line one\nline two"))
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

func mustQueryPath(t *testing.T, value string) ports.SafeRelativePath {
	t.Helper()
	path, err := ports.NewSafeRelativePath(value)
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func mustQueryArtifact(t *testing.T, path ports.SafeRelativePath, bytes []byte) ports.ImmutablePublicationArtifact {
	t.Helper()
	artifact, err := ports.NewImmutablePublicationArtifact(path, querySHA(bytes), bytes)
	if err != nil {
		t.Fatal(err)
	}
	return artifact
}

func querySHA(bytes []byte) string {
	sum := sha256.Sum256(bytes)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func failureClass(t *testing.T, err error) domain.FailureClass {
	t.Helper()
	var failure *domain.Failure
	if !errors.As(err, &failure) {
		t.Fatalf("error %v is not a domain failure", err)
	}
	return failure.Class()
}
