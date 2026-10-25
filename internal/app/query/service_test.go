package query

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"

	coreapp "github.com/irootkernel/mulgae/internal/app"
	"github.com/irootkernel/mulgae/internal/app/evidence"
	"github.com/irootkernel/mulgae/internal/app/prompt"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
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
	final.Mulgae = productionFinal.Mulgae
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
		RunType: string(domain.RunTypeReview), Mulgae: finalMulgaeDTO{Version: "0.1.0", Commit: &commit},
		Target: finalTargetDTO{ContentSHA256: "sha256:" + strings.Repeat("d", 64)},
		Provenance: provenanceDTO{Production: &productionProvenanceDTO{
			BuildProduct: "mulgae", BuildVersion: "0.1.0", BuildCommit: commit, ObjectiveSHA256: &objective, ObjectivePresent: true,
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
			badFinalBytes := []byte(`{"schema_version":"mulgae-review-artifact.v1"}`)
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
				StructuredExtractionStatus: string(domain.StructuredExtractionStructured),
				CIReasonCodes:              append([]string(nil), test.reasons...),
			}
			manifest := manifestDTO{
				StructuredExtractionStatus: string(domain.StructuredExtractionStructured),
				CIReasonCodes:              append([]string(nil), test.reasons...),
				ExitCode:                   int(test.exit),
			}
			if err := validateOutcomeProjection(
				final,
				manifest,
				test.roles,
				test.findings,
				test.content,
				test.coverage,
				domain.StructuredExtractionStructured,
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
				final.ImmutableLineage.LineageEdgeSHA256 = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
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
	assertCorruptRunStatus(t, status, run)
}

// TestReadRunStatusInterleavingsPreserveCorruptIdentity pins the safe corrupt
// status projection and its unavailable-recovery metadata, not just the
// failure class, when the publication identity changes mid-read.
func TestReadRunStatusInterleavingsPreserveCorruptIdentity(t *testing.T) {
	armAfterSnapshot := func(store *queryStore, mutate func()) {
		store.afterSnapshot = func() {
			store.afterSnapshot = nil
			mutate()
		}
	}
	for name, arm := range map[string]func(t *testing.T, store *queryStore, run ports.PublicationRun){
		"epoch change after snapshot": func(t *testing.T, store *queryStore, run ports.PublicationRun) {
			armAfterSnapshot(store, func() {
				store.observation = queryP2Observation(t, run, querySnapshotAtEpoch(t, store.snapshot, 2), domain.JournalCompleted, domain.ExitCommittedCIRejected, 2)
			})
		},
		"cleanup after snapshot": func(t *testing.T, store *queryStore, _ ports.PublicationRun) {
			armAfterSnapshot(store, func() { store.observeErr = ports.ErrPublicationRunNotFound })
		},
	} {
		t.Run(name, func(t *testing.T) {
			service, store, run, _ := inspectionFixture(t, 1)
			arm(t, store, run)
			status, err := service.ReadRunStatus(context.Background(), run)
			if failureClass(t, err) != domain.FailureArtifact {
				t.Fatalf("failure class = %q, want artifact", failureClass(t, err))
			}
			assertCorruptRunStatus(t, status, run)
		})
	}
	t.Run("stable status keeps published-review recovery metadata", func(t *testing.T) {
		service, _, run, _ := inspectionFixture(t, 1)
		status, err := service.ReadRunStatus(context.Background(), run)
		if err != nil {
			t.Fatal(err)
		}
		recoveryStatus := status.FailedRunRecovery()
		if recoveryStatus.Available || recoveryStatus.UnavailableReason == nil || *recoveryStatus.UnavailableReason != "published_review" {
			t.Fatalf("stable status recovery metadata = %+v, want unavailable published_review", recoveryStatus)
		}
	})
}

func TestValidRoleReportMarkdownMatchesProducerBoundary(t *testing.T) {
	t.Parallel()
	if !validRoleReportMarkdown([]byte("# ok\n")) {
		t.Fatal("valid markdown rejected")
	}
	if !validRoleReportMarkdown([]byte("a\x00b")) {
		t.Fatal("embedded NUL rejected unlike producer normalizeRoleReportMarkdown")
	}
	if validRoleReportMarkdown(nil) || validRoleReportMarkdown([]byte{}) {
		t.Fatal("empty markdown accepted")
	}
	if validRoleReportMarkdown([]byte("   \n\t  ")) {
		t.Fatal("whitespace-only markdown accepted")
	}
	if validRoleReportMarkdown([]byte{0xff, 0xfe, 0xfd}) {
		t.Fatal("non-UTF-8 markdown accepted")
	}
	if !validRoleReportMarkdown([]byte(strings.Repeat("a", (8<<20)+1))) {
		t.Fatal("large markdown rejected")
	}
}

func TestReadRunStatusAcceptsCanonicalEmptySupportIndexForNoChange(t *testing.T) {
	t.Parallel()
	// Exact publication marshalCanonical bytes for a provider-free no-change
	// support index. Keep lockstep with
	// publication.TestPrepareNoChangeCandidateSerializesZeroAttempts.
	canonicalEmptySupportIndex := []byte("{\"schema_version\":\"mulgae-run-support-index.v1\",\"artifacts\":[]}\n")
	run, snapshot, observation, artifacts := queryNoChangeCommittedFixture(t, canonicalEmptySupportIndex)
	status, err := mustQueryService(t, &queryStore{
		observation: observation, snapshot: snapshot, auxiliaryArtifacts: artifacts,
	}, &queryValidator{}, nil).ReadRunStatus(context.Background(), run)
	if err != nil {
		t.Fatalf("ReadRunStatus() error = %v", err)
	}
	content, hasContent := status.ContentVerdict()
	coverage, hasCoverage := status.CoverageStatus()
	ci, hasCI := status.CIDecision()
	if status.PublicationStatus() != domain.PublicationCommitted ||
		!hasContent || content != domain.ContentNoFindings ||
		!hasCoverage || coverage != domain.CoverageComplete ||
		!hasCI || ci != domain.CIPass ||
		len(status.RoleReportURIs()) != 0 {
		t.Fatalf("no-change status = %#v", status)
	}
}

func TestReadRunStatusRejectsMissingOrCorruptSupportIndexWithZeroRoleReports(t *testing.T) {
	t.Parallel()
	run, snapshot, observation := queryZeroRoleReportCommittedFixture(t, false, nil)
	store := &queryStore{observation: observation, snapshot: snapshot}
	status, err := mustQueryService(t, store, &queryValidator{}, nil).ReadRunStatus(context.Background(), run)
	if failureClass(t, err) != domain.FailureArtifact {
		t.Fatalf("missing support index failure class = %q, want artifact", failureClass(t, err))
	}
	assertCorruptRunStatus(t, status, run)

	run, snapshot, observation, artifacts := queryZeroRoleReportCommittedFixtureWithSupport(t, func(support []byte) []byte {
		return append([]byte(nil), support[:len(support)/2]...)
	})
	store = &queryStore{observation: observation, snapshot: snapshot, auxiliaryArtifacts: artifacts}
	status, err = mustQueryService(t, store, &queryValidator{}, nil).ReadRunStatus(context.Background(), run)
	if failureClass(t, err) != domain.FailureArtifact {
		t.Fatalf("corrupt support index failure class = %q, want artifact", failureClass(t, err))
	}
	assertCorruptRunStatus(t, status, run)
}

func TestReadRunStatusExposesVerifiedRoleReportURIsAndRejectsTamper(t *testing.T) {
	t.Parallel()
	run, snapshot, observation, artifacts, wantURIs := queryStatusRoleReportFixture(t)
	store := &queryStore{observation: observation, snapshot: snapshot, auxiliaryArtifacts: artifacts}
	status, err := mustQueryService(t, store, &queryValidator{}, nil).ReadRunStatus(context.Background(), run)
	if err != nil {
		t.Fatalf("ReadRunStatus() error = %v", err)
	}
	got := status.RoleReportURIs()
	if len(got) != len(wantURIs) {
		t.Fatalf("role report URIs = %#v, want %#v", got, wantURIs)
	}
	for index := range wantURIs {
		if got[index] != wantURIs[index] {
			t.Fatalf("role report URIs[%d] = %#v, want %#v", index, got[index], wantURIs[index])
		}
	}

	p0, err := ports.NewPublicationObservation(domain.JournalCollecting, domain.DurableObservationP0None, nil, nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	nonP2 := &queryStore{observation: p0, snapshot: snapshot, auxiliaryArtifacts: artifacts}
	nonP2Status, err := mustQueryService(t, nonP2, &queryValidator{}, nil).ReadRunStatus(context.Background(), run)
	if err != nil {
		t.Fatalf("non-P2 ReadRunStatus() error = %v", err)
	}
	if len(nonP2Status.RoleReportURIs()) != 0 || nonP2.snapshotReads != 0 {
		t.Fatalf("non-P2 exposed role report URIs or read snapshot: %#v reads=%d", nonP2Status, nonP2.snapshotReads)
	}

	logicPath := run.SessionID().String() + "/" + run.RunID().String() + "/role-reports/logic.md"
	tampered := mustQueryArtifact(t, mustQueryPath(t, logicPath), []byte("# tampered\n"))
	artifacts[logicPath] = tampered
	tamperStore := &queryStore{observation: observation, snapshot: snapshot, auxiliaryArtifacts: artifacts}
	tamperStatus, err := mustQueryService(t, tamperStore, &queryValidator{}, nil).ReadRunStatus(context.Background(), run)
	if failureClass(t, err) != domain.FailureArtifact {
		t.Fatalf("tampered report failure class = %q, want artifact", failureClass(t, err))
	}
	if len(tamperStatus.RoleReportURIs()) != 0 {
		t.Fatal("tampered report exposed role report URIs")
	}

	extraPath := run.SessionID().String() + "/" + run.RunID().String() + "/role-reports/testing.md"
	extra := mustQueryArtifact(t, mustQueryPath(t, extraPath), []byte("# unbound\n"))
	run2, snapshot2, observation2, artifacts2, _ := queryStatusRoleReportFixture(t)
	supportPath := run2.SessionID().String() + "/" + run2.RunID().String() + "/support/index.json"
	var index runtimeSupportIndexDTO
	if err := json.Unmarshal(artifacts2[supportPath].Bytes(), &index); err != nil {
		t.Fatal(err)
	}
	index.Artifacts = append(index.Artifacts, artifactIdentityDTO{Path: extraPath, SHA256: extra.SHA256()})
	rebuilt, err := json.Marshal(index)
	if err != nil {
		t.Fatal(err)
	}
	support := mustQueryArtifact(t, mustQueryPath(t, supportPath), rebuilt)
	artifacts2[supportPath] = support
	artifacts2[extraPath] = extra
	manifestRecord, err := decodeManifestDTO(snapshot2.Manifest().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	manifestRecord.CompositeIdentity.SupportIndex = &artifactIdentityDTO{Path: supportPath, SHA256: support.SHA256()}
	manifestBytes, err := json.Marshal(manifestRecord)
	if err != nil {
		t.Fatal(err)
	}
	manifest := mustQueryArtifact(t, snapshot2.Manifest().Path(), manifestBytes)
	snapshot2, err = ports.NewCommittedPublicationSnapshot(snapshot2.Final(), manifest, snapshot2.LineageEdge(), snapshot2.Epoch())
	if err != nil {
		t.Fatal(err)
	}
	observation2 = queryP2Observation(t, run2, snapshot2, domain.JournalCompleted, domain.ExitCommittedCIRejected, 1)
	unboundStore := &queryStore{observation: observation2, snapshot: snapshot2, auxiliaryArtifacts: artifacts2}
	unboundStatus, err := mustQueryService(t, unboundStore, &queryValidator{}, nil).ReadRunStatus(context.Background(), run2)
	if failureClass(t, err) != domain.FailureArtifact {
		t.Fatalf("unbound support role report failure class = %q, want artifact", failureClass(t, err))
	}
	if len(unboundStatus.RoleReportURIs()) != 0 {
		t.Fatal("unbound support role report exposed URIs")
	}

	// One request observes the publication twice: the initial binding and the
	// final confirmation after every artifact read. A change visible at the
	// confirmation fails the read without exposing role-report URIs.
	run3, snapshot3, observation3, artifacts3, _ := queryStatusRoleReportFixture(t)
	reobserveStore := &queryStore{
		observations: []ports.PublicationObservation{
			observation3,
			queryP2Observation(t, run3, querySnapshotAtEpoch(t, snapshot3, 2), domain.JournalCompleted, domain.ExitCommittedCIRejected, 2),
		},
		snapshot:           snapshot3,
		auxiliaryArtifacts: artifacts3,
	}
	reobserveStatus, err := mustQueryService(t, reobserveStore, &queryValidator{}, nil).ReadRunStatus(context.Background(), run3)
	if failureClass(t, err) != domain.FailureArtifact {
		t.Fatalf("post-artifact re-observation failure class = %q, want artifact", failureClass(t, err))
	}
	if len(reobserveStatus.RoleReportURIs()) != 0 {
		t.Fatal("unstable post-artifact observation exposed role report URIs")
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

func TestQueryFailureReductionUsesOperationalPrecedenceInBothJoinOrders(t *testing.T) {
	classes := []domain.FailureClass{
		domain.FailureInternal,
		domain.FailureSecurityPolicy,
		domain.FailureArtifact,
		domain.FailureCancelled,
		domain.FailureConfiguration,
		domain.FailureProviderUnavailable,
		domain.FailureTimeout,
		domain.FailureAuthentication,
		domain.FailureQuota,
		domain.FailureRateLimit,
		domain.FailureInvalidOutput,
	}
	newFailure := func(class domain.FailureClass) error {
		failure, err := domain.NewFailure("query.test", class, "dependency failure", nil)
		if err != nil {
			t.Fatal(err)
		}
		return failure
	}
	for firstIndex, first := range classes {
		for _, second := range classes[firstIndex+1:] {
			firstRank := coreapp.FailurePrecedence(first)
			secondRank := coreapp.FailurePrecedence(second)
			if firstRank == secondRank {
				continue
			}
			want := first
			if secondRank > firstRank {
				want = second
			}
			for _, failures := range [][]error{
				{newFailure(first), newFailure(second)},
				{newFailure(second), newFailure(first)},
			} {
				got := reduceDependencyFailureClass(context.Background(), errors.Join(failures...), domain.FailureArtifact)
				if got != want {
					t.Errorf("reduced class for %q/%q = %q, want %q", first, second, got, want)
				}
			}
		}
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

func compositionReadyRuntimeFixture(t *testing.T) (ports.PublicationRun, *queryStore, *Service) {
	t.Helper()
	run, snapshot, observation, artifacts, _, _ := queryRuntimeFixtureWithOptions(t, queryRuntimeFixtureOptions{bindAllRoleReports: true})
	store := &queryStore{snapshot: snapshot, observation: observation, auxiliaryArtifacts: artifacts}
	return run, store, mustQueryService(t, store, &queryValidator{}, nil)
}

// TestReadCommittedForCompositionSingleVerification is the failing-first
// regression for double verification inside one composition read: the root is
// verified once (exactly one snapshot read and one support-index read) even
// though the runtime-target and status projections consume the same node.
func TestReadCommittedForCompositionSingleVerification(t *testing.T) {
	run, store, service := compositionReadyRuntimeFixture(t)
	if _, err := service.ReadCommittedForComposition(context.Background(), run); err != nil {
		t.Fatalf("ReadCommittedForComposition() error = %v", err)
	}
	if store.snapshotReads != 1 {
		t.Fatalf("composition snapshot reads = %d, want 1", store.snapshotReads)
	}
	if reads := supportIndexReads(store); reads != 1 {
		t.Fatalf("composition support-index reads = %d, want 1", reads)
	}
}

// TestReadCommittedForCompositionRejectsIdentityChangeAfterSupportVerification
// keeps the composition read fail-closed: the stable call succeeds, and a
// publication-identity change armed after the snapshot read fails the read
// with no review returned. The final dependency-postorder confirmation owns
// that window.
func TestReadCommittedForCompositionRejectsIdentityChangeAfterSupportVerification(t *testing.T) {
	t.Run("stable", func(t *testing.T) {
		run, _, service := compositionReadyRuntimeFixture(t)
		review, err := service.ReadCommittedForComposition(context.Background(), run)
		if err != nil {
			t.Fatalf("stable composition read = %v", err)
		}
		if review.ReviewID().String() == "" {
			t.Fatal("stable composition read returned no review")
		}
	})
	t.Run("identity changed after snapshot", func(t *testing.T) {
		run, store, service := compositionReadyRuntimeFixture(t)
		store.afterSnapshot = func() {
			store.afterSnapshot = nil
			store.observation = queryP2Observation(t, run, querySnapshotAtEpoch(t, store.snapshot, 2), domain.JournalCompleted, domain.ExitCommittedCIRejected, 2)
		}
		review, err := service.ReadCommittedForComposition(context.Background(), run)
		if failureClass(t, err) != domain.FailureArtifact {
			t.Fatalf("changed composition source = %v, want artifact failure", err)
		}
		if review.ReviewID().String() != "" || review.FinalSHA256() != "" {
			t.Fatalf("failed composition read returned review data: %+v", review)
		}
	})
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
		"captured-archive": func(service *Service, run ports.PublicationRun, _ domain.AttemptID) error {
			_, err := service.ReadRuntimeTarget(context.Background(), run)
			return err
		},
		"captured-blob": func(service *Service, run ports.PublicationRun, _ domain.AttemptID) error {
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

type queryRuntimeFixtureOptions struct {
	legacyArchive bool
	artistBrief   bool
	artistVisuals bool
	// bindAllRoleReports also retains the security role report, so status
	// projection and composition reads see every manifest report bound.
	bindAllRoleReports bool
	// Negative-case deviations applied while the fixture is constructed, so
	// every digest binding (index member, index artifact, run manifest) stays
	// self-consistent and each named failure is reached deterministically.
	legacyArchiveWrongBinding  bool   // legacy archive material binds a different target
	omitArchiveFromIndex       bool   // support index omits the captured archive entry
	artistBriefDigestOverride  string // replaces the brief identity digest in the target manifest
	artistBriefPathOverride    string // replaces the brief identity path in the target manifest
	artistBriefOmitIndex       bool   // support index omits the brief entry
	manifestUnknownArtistField bool   // target manifest carries an artist_extra identity
}

// queryArtistBriefContent and queryArtistVisualsContent are the frozen artist
// input bytes. The visuals bytes follow the published artist visual manifest
// wire shape and stay opaque to the reader, which correlates by identity.
const (
	queryArtistBriefContent   = "# Artist brief\n\nDraw the reviewed home screen exactly as captured.\n"
	queryArtistVisualsContent = `{"schema_version":"mulgae-artist-visual-assets.v1","brief_path":"docs/roadmap.md","visual_assets":[{"path":"current/design-specs/home.png","sha256":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","media_type":"image/png"}]}`
)

// queryRuntimeFixture is the frozen synthetic runtime fixture: a support index
// v1, a modern split captured archive, prompts, and final/manifest rebinding
// served through the queryStore. Its bytes are unchanged; the variants below
// reuse the same construction with declared deviations only.
func queryRuntimeFixture(t *testing.T, canonicalPrompt ...bool) (ports.PublicationRun, ports.CommittedPublicationSnapshot, ports.PublicationObservation, map[string]ports.ImmutablePublicationArtifact, map[string]string, domain.AttemptID) {
	t.Helper()
	return queryRuntimeFixtureWithOptions(t, queryRuntimeFixtureOptions{}, canonicalPrompt...)
}

// queryArtistRuntimeFixture returns the runtime fixture with the target
// manifest binding optional artist input identities and the corresponding
// input artifacts retained in the store and support index. The two booleans
// enable independent presence, including combinations the writer never emits.
func queryArtistRuntimeFixture(t *testing.T, brief, visuals bool) (ports.PublicationRun, ports.CommittedPublicationSnapshot, ports.PublicationObservation, map[string]ports.ImmutablePublicationArtifact, map[string]string, domain.AttemptID) {
	t.Helper()
	return queryRuntimeFixtureWithOptions(t, queryRuntimeFixtureOptions{artistBrief: brief, artistVisuals: visuals})
}

// queryLegacyArchiveRuntimeFixture returns the runtime fixture with the
// captured archive in the legacy v1 single-byte form and no split blobs.
func queryLegacyArchiveRuntimeFixture(t *testing.T) (ports.PublicationRun, ports.CommittedPublicationSnapshot, ports.PublicationObservation, map[string]ports.ImmutablePublicationArtifact, map[string]string, domain.AttemptID) {
	t.Helper()
	return queryRuntimeFixtureWithOptions(t, queryRuntimeFixtureOptions{legacyArchive: true})
}

func queryRuntimeFixtureWithOptions(t *testing.T, options queryRuntimeFixtureOptions, canonicalPrompt ...bool) (ports.PublicationRun, ports.CommittedPublicationSnapshot, ports.PublicationObservation, map[string]ports.ImmutablePublicationArtifact, map[string]string, domain.AttemptID) {
	t.Helper()
	run, baseSnapshot, _ := queryCommittedFixture(t, domain.ExitCommittedCIRejected)
	prefix := run.SessionID().String() + "/" + run.RunID().String()
	attempt, err := domain.ParseAttemptID("a_019f596a-d048-79e7-b2b7-59822f012273")
	if err != nil {
		t.Fatal(err)
	}
	targetPath := prefix + "/target/target.bytes"
	target := mustQueryArtifact(t, mustQueryPath(t, targetPath), []byte("runtime target bytes"))
	capturedTarget, err := ports.NewCapturedReviewPatchTarget(target.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	capturedSnapshot, err := ports.NewWorkspaceSnapshotRequest(nil, "query-runtime-fixture")
	if err != nil {
		t.Fatal(err)
	}
	capturedEvidence, err := ports.NewCapturedTargetEvidence(map[ports.CapturedEvidenceSide][]ports.WorkspaceSnapshotFile{ports.CapturedEvidenceHead: nil})
	if err != nil {
		t.Fatal(err)
	}
	capturedMaterial, err := ports.NewCapturedReviewMaterialWithEvidence(capturedTarget, capturedSnapshot, nil, capturedEvidence)
	if err != nil {
		t.Fatal(err)
	}
	capturedPath := prefix + "/target/captured-review.json"
	var capturedManifest ports.ImmutablePublicationArtifact
	capturedArtifacts := make(map[string]ports.ImmutablePublicationArtifact)
	var capturedBlobPath string
	if options.legacyArchive {
		archiveMaterial := capturedMaterial
		if options.legacyArchiveWrongBinding {
			archiveMaterial = queryAlternateCapturedMaterial(t, "query-runtime-fixture-wrong-binding", "different runtime target bytes")
		}
		legacyBytes, legacyErr := queryLegacyArchiveFixture(t, archiveMaterial)
		if legacyErr != nil {
			t.Fatal(legacyErr)
		}
		capturedManifest = mustQueryArtifact(t, mustQueryPath(t, capturedPath), legacyBytes)
	} else {
		captured, capturedErr := ports.NewCapturedReviewArchive(capturedMaterial)
		if capturedErr != nil {
			t.Fatal(capturedErr)
		}
		capturedManifest = mustQueryArtifact(t, mustQueryPath(t, capturedPath), captured.Manifest())
		for _, blob := range captured.Blobs() {
			path := prefix + "/target/" + blob.Path().String()
			artifact := mustQueryArtifact(t, mustQueryPath(t, path), blob.Bytes())
			capturedArtifacts[path] = artifact
			capturedBlobPath = path
		}
	}
	stdinPath := prefix + "/prompts/" + attempt.String() + "/001-initial.stdin"
	stdin := mustQueryArtifact(t, mustQueryPath(t, stdinPath), []byte("runtime stdin bytes"))
	promptPath := prefix + "/prompts/" + attempt.String() + "/001-initial.manifest.json"
	completeStdinSHA256 := prompt.CompleteStdinSHA256(stdin.Bytes())
	prompt := mustQueryArtifact(t, mustQueryPath(t, promptPath), []byte(fmt.Sprintf(`{"schema_version":"mulgae-runtime-prompt-manifest.v1","target":{"path":%q,"sha256":%q},"stdin":{"path":%q,"sha256":%q},"complete_stdin_sha256":%q,"template_id":"review","template_version":"v1","template_sha256":"sha256:%s","source_invocation_id":"source","execution_invocation_id":"execution","scope":"repository","role":"logic","adapter_profile":"default","adapter_parameters":{"model":"trusted"}}`, targetPath, target.SHA256(), stdinPath, stdin.SHA256(), completeStdinSHA256, strings.Repeat("c", 64))))
	if len(canonicalPrompt) == 1 && canonicalPrompt[0] {
		compiled := queryCanonicalReplayPrompt(t, run, attempt, target.Bytes())
		stdin = mustQueryArtifact(t, mustQueryPath(t, stdinPath), compiled.Stdin())
		var wire runtimePromptManifestDTO
		if err := json.Unmarshal(prompt.Bytes(), &wire); err != nil {
			t.Fatal(err)
		}
		wire.Stdin.SHA256 = stdin.SHA256()
		wire.CompleteStdinSHA256 = compiled.CompleteStdinSHA256()
		wire.TemplateID, wire.TemplateVersion = compiled.TrustedTemplate().ID(), compiled.TrustedTemplate().Version()
		wire.TemplateSHA256 = "sha256:" + compiled.TrustedTemplate().SHA256()
		wire.SourceInvocationID = compiled.Scope().SourceInvocationID().String()
		wire.ExecutionInvocationID = compiled.Scope().ExecutionInvocationID().String()
		wire.Scope = compiled.Scope().FrameScope().String()
		raw, err := json.Marshal(wire)
		if err != nil {
			t.Fatal(err)
		}
		prompt = mustQueryArtifact(t, mustQueryPath(t, promptPath), raw)
	}
	roleReportPath := prefix + "/role-reports/logic.md"
	roleReport := mustQueryArtifact(t, mustQueryPath(t, roleReportPath), []byte("verified role report\n"))
	securityReportPath := prefix + "/role-reports/security.md"
	securityReport := mustQueryArtifact(t, mustQueryPath(t, securityReportPath), []byte("verified security report\n"))
	artistBriefPath := prefix + "/inputs/artist-brief.md"
	artistVisualsPath := prefix + "/inputs/artist-visual-assets.json"
	artistArtifacts := make(map[string]ports.ImmutablePublicationArtifact)
	var artistIdentities []artifactIdentityDTO
	var artistFields []string
	if options.artistBrief {
		brief := mustQueryArtifact(t, mustQueryPath(t, artistBriefPath), []byte(queryArtistBriefContent))
		artistArtifacts[artistBriefPath] = brief
		briefDigest := brief.SHA256()
		if options.artistBriefDigestOverride != "" {
			briefDigest = options.artistBriefDigestOverride
		}
		briefManifestPath := artistBriefPath
		if options.artistBriefPathOverride != "" {
			briefManifestPath = options.artistBriefPathOverride
		}
		if !options.artistBriefOmitIndex && options.artistBriefPathOverride == "" {
			artistIdentities = append(artistIdentities, artifactIdentityDTO{Path: artistBriefPath, SHA256: brief.SHA256()})
		}
		artistFields = append(artistFields, fmt.Sprintf(`"artist_brief":{"path":%q,"sha256":%q}`, briefManifestPath, briefDigest))
	}
	if options.artistVisuals {
		visuals := mustQueryArtifact(t, mustQueryPath(t, artistVisualsPath), []byte(queryArtistVisualsContent))
		artistArtifacts[artistVisualsPath] = visuals
		artistIdentities = append(artistIdentities, artifactIdentityDTO{Path: artistVisualsPath, SHA256: visuals.SHA256()})
		artistFields = append(artistFields, fmt.Sprintf(`"artist_visual_assets":{"path":%q,"sha256":%q}`, artistVisualsPath, visuals.SHA256()))
	}
	targetManifestPath := prefix + "/target/target-manifest.json"
	manifestJSON := fmt.Sprintf(`{"schema_version":"mulgae-runtime-target-manifest.v1","target":{"path":%q,"sha256":%q},"captured_archive":{"path":%q,"sha256":%q},"target_kind":"patch","repository_id":"","base_object_id":"","head_object_id":"","head_tree_object_id":"","index_tree_object_id":"","prompts":[{"path":%q,"sha256":%q}],"selected_replay_prompts":[{"attempt_id":%q,"sequence":1,"purpose":"initial","artifact":{"path":%q,"sha256":%q}}]`, targetPath, target.SHA256(), capturedPath, capturedManifest.SHA256(), promptPath, prompt.SHA256(), attempt.String(), promptPath, prompt.SHA256())
	if len(artistFields) > 0 {
		manifestJSON += "," + strings.Join(artistFields, ",")
	}
	if options.manifestUnknownArtistField {
		manifestJSON += `,"artist_extra":{"path":"` + artistBriefPath + `","sha256":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`
	}
	manifestJSON += "}"
	targetManifest := mustQueryArtifact(t, mustQueryPath(t, targetManifestPath), []byte(manifestJSON))
	normalizedPath := prefix + "/excerpts/F001.json"
	normalized := mustQueryArtifact(t, mustQueryPath(t, normalizedPath), []byte(`{"id":"F001"}`))
	excerptPath := prefix + "/excerpts/F001_1.md"
	excerpt := mustQueryArtifact(t, mustQueryPath(t, excerptPath), []byte("line one\nline two"))
	supportPath := prefix + "/support/index.json"
	supportIdentities := []artifactIdentityDTO{
		{Path: normalizedPath, SHA256: normalized.SHA256()}, {Path: excerptPath, SHA256: excerpt.SHA256()},
		{Path: targetPath, SHA256: target.SHA256()}, {Path: stdinPath, SHA256: stdin.SHA256()},
		{Path: promptPath, SHA256: prompt.SHA256()}, {Path: targetManifestPath, SHA256: targetManifest.SHA256()},
		{Path: roleReportPath, SHA256: roleReport.SHA256()},
	}
	if !options.omitArchiveFromIndex {
		supportIdentities = append(supportIdentities, artifactIdentityDTO{Path: capturedPath, SHA256: capturedManifest.SHA256()})
	}
	if options.bindAllRoleReports {
		supportIdentities = append(supportIdentities, artifactIdentityDTO{Path: securityReportPath, SHA256: securityReport.SHA256()})
	}
	supportIdentities = append(supportIdentities, artistIdentities...)
	for path, artifact := range capturedArtifacts {
		supportIdentities = append(supportIdentities, artifactIdentityDTO{Path: path, SHA256: artifact.SHA256()})
	}
	sort.Slice(supportIdentities, func(i, j int) bool { return supportIdentities[i].Path < supportIdentities[j].Path })
	supportBytes, err := json.Marshal(runtimeSupportIndexDTO{SchemaVersion: "mulgae-run-support-index.v1", Artifacts: supportIdentities})
	if err != nil {
		t.Fatal(err)
	}
	support := mustQueryArtifact(t, mustQueryPath(t, supportPath), supportBytes)

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
	manifestRecord.RoleReports[0].SHA256 = roleReport.SHA256()
	manifestRecord.RoleReports[0].ByteLength = len(roleReport.Bytes())
	if options.bindAllRoleReports {
		manifestRecord.RoleReports[1].SHA256 = securityReport.SHA256()
		manifestRecord.RoleReports[1].ByteLength = len(securityReport.Bytes())
	}
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
	artifacts := map[string]ports.ImmutablePublicationArtifact{supportPath: support, normalizedPath: normalized, excerptPath: excerpt, targetPath: target, stdinPath: stdin, promptPath: prompt, targetManifestPath: targetManifest, capturedPath: capturedManifest, roleReportPath: roleReport}
	if options.bindAllRoleReports {
		artifacts[securityReportPath] = securityReport
	}
	for path, artifact := range capturedArtifacts {
		artifacts[path] = artifact
	}
	for path, artifact := range artistArtifacts {
		artifacts[path] = artifact
	}
	paths := map[string]string{"support": supportPath, "normalized": normalizedPath, "excerpt": excerptPath, "target": targetPath, "target-manifest": targetManifestPath, "captured-archive": capturedPath, "captured-blob": capturedBlobPath, "prompt-manifest": promptPath, "stdin": stdinPath, "artist-brief": artistBriefPath, "artist-visuals": artistVisualsPath}
	return run, snapshot, observation, artifacts, paths, attempt
}

// queryAlternateCapturedMaterial builds a minimal captured material whose
// target differs from the fixture target, for wrong-binding controls.
func queryAlternateCapturedMaterial(t *testing.T, policy, targetBytes string) ports.CapturedReviewMaterial {
	t.Helper()
	otherTarget, err := ports.NewCapturedReviewPatchTarget([]byte(targetBytes))
	if err != nil {
		t.Fatal(err)
	}
	otherSnapshot, err := ports.NewWorkspaceSnapshotRequest(nil, policy)
	if err != nil {
		t.Fatal(err)
	}
	otherEvidence, err := ports.NewCapturedTargetEvidence(map[ports.CapturedEvidenceSide][]ports.WorkspaceSnapshotFile{ports.CapturedEvidenceHead: nil})
	if err != nil {
		t.Fatal(err)
	}
	material, err := ports.NewCapturedReviewMaterialWithEvidence(otherTarget, otherSnapshot, nil, otherEvidence)
	if err != nil {
		t.Fatal(err)
	}
	return material
}

// TestReadRuntimeTargetAdmitsRetainedArtistManifestFields proves the strict
// historical reader admits a runtime target manifest that binds retained
// artist inputs. Phase 1 uses existing APIs only: the read must succeed and
// the target bytes must be exact.
func TestReadRuntimeTargetAdmitsRetainedArtistManifestFields(t *testing.T) {
	t.Parallel()
	run, snapshot, observation, artifacts, _, _ := queryArtistRuntimeFixture(t, true, true)
	service := mustQueryService(t, &queryStore{snapshot: snapshot, observation: observation, auxiliaryArtifacts: artifacts}, &queryValidator{}, nil)
	target, err := service.ReadRuntimeTarget(context.Background(), run)
	if err != nil {
		t.Fatalf("ReadRuntimeTarget() error = %v, want a retained artist manifest to read", err)
	}
	if string(target.Bytes()) != "runtime target bytes" {
		t.Fatalf("target bytes = %q", target.Bytes())
	}
	brief, briefPresent := target.ArtistBrief()
	if !briefPresent || string(brief) != queryArtistBriefContent {
		t.Fatalf("artist brief = (%q, %t), want the exact retained brief bytes", brief, briefPresent)
	}
	visuals, visualsPresent := target.ArtistVisualAssets()
	if !visualsPresent || string(visuals) != queryArtistVisualsContent {
		t.Fatalf("artist visual assets = (%q, %t), want the exact retained manifest bytes", visuals, visualsPresent)
	}

	// Strict unknown-field rejection is preserved: an artist_extra identity is
	// still rejected by strict decoding.
	run, snapshot, observation, artifacts, _, _ = queryRuntimeFixtureWithOptions(t, queryRuntimeFixtureOptions{manifestUnknownArtistField: true})
	service = mustQueryService(t, &queryStore{snapshot: snapshot, observation: observation, auxiliaryArtifacts: artifacts}, &queryValidator{}, nil)
	if _, err := service.ReadRuntimeTarget(context.Background(), run); err == nil || !strings.Contains(err.Error(), "runtime target manifest decode failed") {
		t.Fatalf("unknown artist field = %v, want the strict decode rejection", err)
	}
}

// queryFixturePrefix is the frozen session/run prefix of the committed
// fixture the runtime fixture family builds on.
const queryFixturePrefix = "s_019f596a-cf80-7c67-b265-f37053d51ccf/r_019f596a-cfe4-7c9c-b82e-7149158243ba"

// TestReadRuntimeTargetArtistFieldPresenceCombinations pins old-manifest
// absence and independent optional-field presence, including the synthetic
// brief-only combination the writer never produces.
func TestReadRuntimeTargetArtistFieldPresenceCombinations(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name        string
		brief       bool
		visuals     bool
		wantBrief   bool
		wantVisuals bool
	}{
		{name: "old manifest without artist fields", brief: false, visuals: false, wantBrief: false, wantVisuals: false},
		{name: "brief only", brief: true, visuals: false, wantBrief: true, wantVisuals: false},
		{name: "visuals only", brief: false, visuals: true, wantBrief: false, wantVisuals: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			run, snapshot, observation, artifacts, _, _ := queryArtistRuntimeFixture(t, test.brief, test.visuals)
			service := mustQueryService(t, &queryStore{snapshot: snapshot, observation: observation, auxiliaryArtifacts: artifacts}, &queryValidator{}, nil)
			target, err := service.ReadRuntimeTarget(context.Background(), run)
			if err != nil {
				t.Fatalf("ReadRuntimeTarget() error = %v", err)
			}
			brief, briefPresent := target.ArtistBrief()
			if briefPresent != test.wantBrief || (briefPresent && string(brief) != queryArtistBriefContent) {
				t.Fatalf("artist brief = (%q, %t), want present %t", brief, briefPresent, test.wantBrief)
			}
			visuals, visualsPresent := target.ArtistVisualAssets()
			if visualsPresent != test.wantVisuals || (visualsPresent && string(visuals) != queryArtistVisualsContent) {
				t.Fatalf("artist visual assets = (%q, %t), want present %t", visuals, visualsPresent, test.wantVisuals)
			}
		})
	}
}

// TestReadRuntimeTargetRejectsMissingTamperedReboundOrCrossRunArtistArtifacts
// pins one named failure for each correlation requirement of a bound artist
// input.
func TestReadRuntimeTargetRejectsMissingTamperedReboundOrCrossRunArtistArtifacts(t *testing.T) {
	t.Parallel()
	readErr := func(t *testing.T, options queryRuntimeFixtureOptions, mutate func(artifacts map[string]ports.ImmutablePublicationArtifact, paths map[string]string)) error {
		t.Helper()
		run, snapshot, observation, artifacts, paths, _ := queryRuntimeFixtureWithOptions(t, options)
		if mutate != nil {
			mutate(artifacts, paths)
		}
		service := mustQueryService(t, &queryStore{snapshot: snapshot, observation: observation, auxiliaryArtifacts: artifacts}, &queryValidator{}, nil)
		_, err := service.ReadRuntimeTarget(context.Background(), run)
		return err
	}
	artist := queryRuntimeFixtureOptions{artistBrief: true, artistVisuals: true}
	for _, test := range []struct {
		name      string
		options   queryRuntimeFixtureOptions
		mutate    func(artifacts map[string]ports.ImmutablePublicationArtifact, paths map[string]string)
		wantError string
	}{
		{
			name:      "not in support index",
			options:   queryRuntimeFixtureOptions{artistBrief: true, artistVisuals: true, artistBriefOmitIndex: true},
			wantError: "artist brief is not support-indexed",
		},
		{
			name:    "missing from store",
			options: artist,
			mutate: func(artifacts map[string]ports.ImmutablePublicationArtifact, paths map[string]string) {
				delete(artifacts, paths["artist-brief"])
			},
			wantError: "runtime artifact read failed",
		},
		{
			name:    "tampered store bytes",
			options: artist,
			mutate: func(artifacts map[string]ports.ImmutablePublicationArtifact, paths map[string]string) {
				artifacts[paths["artist-brief"]] = mustQueryArtifact(t, mustQueryPath(t, paths["artist-brief"]), []byte("tampered brief bytes"))
			},
			wantError: "runtime artifact identity drifted",
		},
		{
			name:      "invalid digest identity",
			options:   queryRuntimeFixtureOptions{artistBrief: true, artistVisuals: true, artistBriefDigestOverride: "not-a-sha256"},
			wantError: "artist brief identity is invalid",
		},
		{
			name:      "rebound familiar path",
			options:   queryRuntimeFixtureOptions{artistBrief: true, artistVisuals: true, artistBriefPathOverride: queryFixturePrefix + "/target/target.bytes"},
			wantError: "artist brief path is not canonical",
		},
		{
			name:      "rebound sibling swap",
			options:   queryRuntimeFixtureOptions{artistBrief: true, artistVisuals: true, artistBriefPathOverride: queryFixturePrefix + "/inputs/artist-visual-assets.json"},
			wantError: "artist brief path is not canonical",
		},
		{
			name:      "cross-run path",
			options:   queryRuntimeFixtureOptions{artistBrief: true, artistVisuals: true, artistBriefPathOverride: "s_019f596a-cf80-7c67-b265-f37053d51cdf/r_019f596a-cfe4-7c9c-b82e-7149158243bb/inputs/artist-brief.md"},
			wantError: "artist brief path is not canonical",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			err := readErr(t, test.options, test.mutate)
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("artist correlation failure = %v, want %q", err, test.wantError)
			}
		})
	}
}

// TestReadRuntimeTargetLiveSourceReplayRefusalPreserved pins that a live-source
// committed review is refused before any runtime target manifest field would
// be decoded.
func TestReadRuntimeTargetLiveSourceReplayRefusalPreserved(t *testing.T) {
	t.Parallel()
	service, _, run, _ := liveAgyCommittedFixture(t)
	if _, err := service.ReadRuntimeTarget(context.Background(), run); !errors.Is(err, ErrSourceReplayUnavailable) {
		t.Fatalf("live-source ReadRuntimeTarget() = %v, want the source replay refusal", err)
	}
}

// TestReadRuntimeTargetLegacyArchiveControls pins the DF-022 re-entry
// contract for the historical v1 single-byte archive branch: exact byte
// preservation plus wrong-binding, missing, and tampered negatives, with the
// modern v2 reconstruction path as the control.
func TestReadRuntimeTargetLegacyArchiveControls(t *testing.T) {
	t.Parallel()

	t.Run("exact v1 bytes are preserved", func(t *testing.T) {
		t.Parallel()
		run, snapshot, observation, artifacts, paths, _ := queryLegacyArchiveRuntimeFixture(t)
		service := mustQueryService(t, &queryStore{snapshot: snapshot, observation: observation, auxiliaryArtifacts: artifacts}, &queryValidator{}, nil)
		target, err := service.ReadRuntimeTarget(context.Background(), run)
		if err != nil {
			t.Fatalf("ReadRuntimeTarget() error = %v", err)
		}
		legacy, legacyPresent := artifacts[paths["captured-archive"]]
		if !legacyPresent || !bytes.Equal(target.CapturedArchive(), legacy.Bytes()) {
			t.Fatalf("legacy archive bytes = %q, want the exact retained v1 bytes", target.CapturedArchive())
		}
		if string(target.Bytes()) != "runtime target bytes" {
			t.Fatalf("legacy target bytes = %q", target.Bytes())
		}
	})

	t.Run("wrong binding", func(t *testing.T) {
		t.Parallel()
		run, snapshot, observation, artifacts, _, _ := queryRuntimeFixtureWithOptions(t, queryRuntimeFixtureOptions{legacyArchive: true, legacyArchiveWrongBinding: true})
		service := mustQueryService(t, &queryStore{snapshot: snapshot, observation: observation, auxiliaryArtifacts: artifacts}, &queryValidator{}, nil)
		_, err := service.ReadRuntimeTarget(context.Background(), run)
		if err == nil || !strings.Contains(err.Error(), "captured archive target binding is invalid") {
			t.Fatalf("wrong binding = %v, want the captured archive target binding rejection", err)
		}
	})

	t.Run("missing from index", func(t *testing.T) {
		t.Parallel()
		run, snapshot, observation, artifacts, _, _ := queryRuntimeFixtureWithOptions(t, queryRuntimeFixtureOptions{legacyArchive: true, omitArchiveFromIndex: true})
		service := mustQueryService(t, &queryStore{snapshot: snapshot, observation: observation, auxiliaryArtifacts: artifacts}, &queryValidator{}, nil)
		_, err := service.ReadRuntimeTarget(context.Background(), run)
		if err == nil || !strings.Contains(err.Error(), "captured archive is not support-indexed") {
			t.Fatalf("missing archive index entry = %v, want the support-index rejection", err)
		}
	})

	t.Run("tampered store bytes", func(t *testing.T) {
		t.Parallel()
		run, snapshot, observation, artifacts, paths, _ := queryLegacyArchiveRuntimeFixture(t)
		artifacts[paths["captured-archive"]] = mustQueryArtifact(t, mustQueryPath(t, paths["captured-archive"]), []byte("tampered archive bytes"))
		service := mustQueryService(t, &queryStore{snapshot: snapshot, observation: observation, auxiliaryArtifacts: artifacts}, &queryValidator{}, nil)
		_, err := service.ReadRuntimeTarget(context.Background(), run)
		if err == nil || !strings.Contains(err.Error(), "runtime artifact identity drifted") {
			t.Fatalf("tampered archive bytes = %v, want the identity drift rejection", err)
		}
	})

	t.Run("v2 reconstruction control", func(t *testing.T) {
		t.Parallel()
		run, snapshot, observation, artifacts, _, _ := queryRuntimeFixture(t)
		service := mustQueryService(t, &queryStore{snapshot: snapshot, observation: observation, auxiliaryArtifacts: artifacts}, &queryValidator{}, nil)
		target, err := service.ReadRuntimeTarget(context.Background(), run)
		if err != nil {
			t.Fatalf("ReadRuntimeTarget() error = %v", err)
		}
		if len(target.CapturedArchive()) == 0 {
			t.Fatal("v2 control lost the reconstructed captured archive")
		}
		if _, err := ports.UnmarshalCapturedReviewMaterial(target.CapturedArchive()); err != nil {
			t.Fatalf("v2 reconstruction is not a valid captured bundle: %v", err)
		}
	})
}

type queryStore struct {
	observation                 ports.PublicationObservation
	observations                []ports.PublicationObservation
	observationsByRun           map[string]ports.PublicationObservation
	snapshot                    ports.CommittedPublicationSnapshot
	snapshotsByRun              map[string]ports.CommittedPublicationSnapshot
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
	snapshotReadsByRun          map[string]int
	auxiliaryReadsByRun         map[string]int
	snapshotRunIDs              []string
	afterSnapshot               func()
	afterAuxiliary              func()
	afterAuxiliaryFor           map[string]func()
	resolutionsByRun            map[string]ports.PublicationRun
	observeOrder                []string
}

func (store *queryStore) IssueReviewID(context.Context, ports.IssueReviewIDRequest) (ports.IssuedReviewID, error) {
	return ports.IssuedReviewID{}, errors.New("not implemented")
}
func (store *queryStore) ResolveRun(_ context.Context, request ports.ResolvePublicationRunRequest) (ports.PublicationRun, error) {
	store.resolveCalls++
	if resolved, ok := store.resolutionsByRun[request.RunID().String()]; ok {
		return resolved, store.resolveErr
	}
	return store.resolved, store.resolveErr
}

func (store *queryStore) ObserveRun(_ context.Context, request ports.ObserveRunRequest) (ports.PublicationObservation, error) {
	store.observeOrder = append(store.observeOrder, request.Run().RunID().String())
	if observation, ok := store.observationsByRun[request.Run().RunID().String()]; ok {
		store.observeCalls++
		return observation, store.observeErr
	}
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
	if store.auxiliaryReadsByRun == nil {
		store.auxiliaryReadsByRun = map[string]int{}
	}
	store.auxiliaryReadsByRun[request.Run().RunID().String()]++
	store.auxiliaryRequest = request
	store.auxiliaryRequests = append(store.auxiliaryRequests, request)
	if store.afterAuxiliary != nil {
		store.afterAuxiliary()
	}
	if hook := store.afterAuxiliaryFor[request.Path().String()]; hook != nil {
		hook()
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

func (store *queryStore) ReadCommittedSnapshot(_ context.Context, request ports.ReadCommittedSnapshotRequest) (ports.CommittedPublicationSnapshot, error) {
	store.snapshotReads++
	if store.snapshotReadsByRun == nil {
		store.snapshotReadsByRun = map[string]int{}
	}
	store.snapshotReadsByRun[request.Run().RunID().String()]++
	store.snapshotRunIDs = append(store.snapshotRunIDs, request.Run().RunID().String())
	if store.afterSnapshot != nil {
		store.afterSnapshot()
	}
	if snapshot, ok := store.snapshotsByRun[request.Run().RunID().String()]; ok {
		return snapshot, store.readErr
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
	edgeBytes := []byte(`{"schema_version":"mulgae-lineage-edge.v1"}`)
	epochBytes := []byte(`{"schema_version":"mulgae-publication-epoch.v1"}`)
	edge := mustQueryArtifact(t, edgePath, edgeBytes)
	epochRecord := mustQueryArtifact(t, epochPath, epochBytes)
	epoch, err := ports.NewPublicationEpoch(1, epochRecord)
	if err != nil {
		t.Fatal(err)
	}
	finalBytes := []byte(fmt.Sprintf(`{
		"schema_version":"mulgae-review-artifact.v1","session_id":%q,"run_id":%q,"review_id":%q,"run_type":"review","created_at":"2026-07-13T03:00:00Z",
		"mulgae":{"version":"0.1.0","commit":null},
		"immutable_lineage":{"parent_run_id":null,"source_run_id":null,"source_review_id":null,"source_finding_ref":null,"replay_mode":null,"lineage_edge_path":%q,"lineage_edge_sha256":%q},
		"target":{"content_sha256":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","manifest_path":"target/target-manifest.json","base_oid":null,"head_oid":null},
		"validation":{"status":"valid","schema_validation":"passed","semantic_validation":"passed","evidence_validation":"passed"},
		"content_verdict":"request_changes","coverage_status":"complete","structured_extraction_status":"structured","publication_status":"committed","ci_decision":"fail","ci_reason_codes":["request_changes_threshold"],
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
		"schema_version":"mulgae-run-manifest.v1","session_id":%q,"run_id":%q,"run_type":"review","state":"completed","sealed":true,"created_at":"2026-07-13T03:00:00Z","started_at":null,"completed_at":"2026-07-13T03:01:00Z","mulgae_version":"0.1.0",
		"immutable_lineage":{"parent_run_id":null,"source_run_id":null,"source_review_id":null,"source_finding_ref":null,"replay_mode":null,"lineage_edge_path":%q,"lineage_edge_sha256":%q},
		"target":{"manifest_path":"target/target-manifest.json","content_sha256":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"selected_roles":["logic","security"],"required_roles":["logic","security"],"attempts":[
			{"attempt_id":"a_019f596a-d048-79e7-b2b7-59822f012273","role":"logic","provider_instance":"logic-provider","selected_as":"primary","state":"succeeded","parse_state":"valid","validation_state":"valid","path":"attempts/a_019f596a-d048-79e7-b2b7-59822f012273/status.json","invocation_count":1},
			{"attempt_id":"a_019f596a-d0ac-7c12-8b68-0bd73e911b2e","role":"security","provider_instance":"security-provider","selected_as":"primary","state":"succeeded","parse_state":"valid","validation_state":"valid","path":"attempts/a_019f596a-d0ac-7c12-8b68-0bd73e911b2e/status.json","invocation_count":1}
		],
		"content_verdict":"request_changes","coverage_status":"complete","structured_extraction_status":"structured","publication_status":"committed","ci_decision":"fail","ci_reason_codes":["request_changes_threshold"],"persisted_journal_state":"completed","durable_observation_class":"P2_COMMITTED","derived_publication_status":"committed","publication_authority":"P2",
		"recovery_journal":{"expected_staged":null,"expected_final":{"path":%q,"sha256":%q},"validated_candidate_sha256":%q},
		"composite_identity":{"manifest":{"path":%q},"lineage_edge":{"path":%q,"sha256":%q},"epoch":{"path":%q}},"recovery_action":"reconstruct_completed_status",
		"final_review":{"review_id":%q,"path":%q,"sha256":%q},
		"role_reports":[
			{"role":"logic","path":"role-reports/logic.md","sha256":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","byte_length":12,"provider_instance":"logic-provider","attempt_id":"a_019f596a-d048-79e7-b2b7-59822f012273","content_type":"text/markdown"},
			{"role":"security","path":"role-reports/security.md","sha256":"sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","byte_length":16,"provider_instance":"security-provider","attempt_id":"a_019f596a-d0ac-7c12-8b68-0bd73e911b2e","content_type":"text/markdown"}
		],
		"failures":[],"warnings":[],"exit_code":1
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
	epochBytes := []byte(fmt.Sprintf(`{"schema_version":"mulgae-publication-epoch.v1","store_epoch":%d}`, epochValue))
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

func queryNoChangeCommittedFixture(
	t *testing.T,
	supportIndexBytes []byte,
) (ports.PublicationRun, ports.CommittedPublicationSnapshot, ports.PublicationObservation, map[string]ports.ImmutablePublicationArtifact) {
	t.Helper()
	run, baseSnapshot, _ := queryCommittedFixture(t, domain.ExitCommittedPass)
	emptyTargetSHA := "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	finalRecord, err := decodeFinalDTO(baseSnapshot.Final().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	for index := range finalRecord.RoleOutcomes {
		finalRecord.RoleOutcomes[index].Outcome = "not_applicable"
		finalRecord.RoleOutcomes[index].AttemptID = nil
		finalRecord.RoleOutcomes[index].ProviderInstance = nil
		finalRecord.RoleOutcomes[index].SelectedVia = nil
		finalRecord.RoleOutcomes[index].ValidFindingIDs = nil
		finalRecord.RoleOutcomes[index].FailureReason = nil
		finalRecord.RoleOutcomes[index].Limitations = []string{"No Git changes were captured."}
	}
	finalRecord.Findings = nil
	finalRecord.Target.ContentSHA256 = emptyTargetSHA
	finalRecord.ContentVerdict = string(domain.ContentNoFindings)
	finalRecord.CoverageStatus = string(domain.CoverageComplete)
	finalRecord.StructuredExtractionStatus = string(domain.StructuredExtractionStructured)
	finalRecord.CIDecision = string(domain.CIPass)
	finalRecord.CIReasonCodes = []string{"policy_evaluated"}
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
	manifestRecord.Attempts = nil
	manifestRecord.RoleReports = []manifestRoleReportDTO{}
	manifestRecord.Failures = nil
	manifestRecord.State = string(domain.RunCompleted)
	manifestRecord.Target.ContentSHA256 = emptyTargetSHA
	manifestRecord.ContentVerdict = string(domain.ContentNoFindings)
	manifestRecord.CoverageStatus = string(domain.CoverageComplete)
	manifestRecord.StructuredExtractionStatus = string(domain.StructuredExtractionStructured)
	manifestRecord.CIDecision = string(domain.CIPass)
	manifestRecord.CIReasonCodes = []string{"policy_evaluated"}
	manifestRecord.ExitCode = int(domain.ExitCommittedPass)
	manifestRecord.FinalReview.SHA256 = finalIdentity.SHA256()
	manifestRecord.RecoveryJournal.ExpectedFinal.SHA256 = finalIdentity.SHA256()
	prefix := run.SessionID().String() + "/" + run.RunID().String()
	supportPath := prefix + "/support/index.json"
	support := mustQueryArtifact(t, mustQueryPath(t, supportPath), supportIndexBytes)
	manifestRecord.CompositeIdentity.SupportIndex = &artifactIdentityDTO{Path: supportPath, SHA256: support.SHA256()}
	manifestBytes, err := json.Marshal(manifestRecord)
	if err != nil {
		t.Fatal(err)
	}
	manifest := mustQueryArtifact(t, baseSnapshot.Manifest().Path(), manifestBytes)
	snapshot, err := ports.NewCommittedPublicationSnapshot(final, manifest, baseSnapshot.LineageEdge(), baseSnapshot.Epoch())
	if err != nil {
		t.Fatal(err)
	}
	observation := queryP2Observation(t, run, snapshot, domain.JournalCompleted, domain.ExitCommittedPass, 1)
	return run, snapshot, observation, map[string]ports.ImmutablePublicationArtifact{supportPath: support}
}

func queryZeroRoleReportCommittedFixture(
	t *testing.T,
	withSupportIndex bool,
	mutateSupport func([]byte) []byte,
) (ports.PublicationRun, ports.CommittedPublicationSnapshot, ports.PublicationObservation) {
	t.Helper()
	run, snapshot, _ := queryZeroRoleReportCommittedMaterial(t, withSupportIndex, mutateSupport)
	observation := queryP2Observation(t, run, snapshot, domain.JournalCompleted, domain.ExitIncompleteCoverage, 1)
	return run, snapshot, observation
}

func queryZeroRoleReportCommittedFixtureWithSupport(
	t *testing.T,
	mutateSupport func([]byte) []byte,
) (ports.PublicationRun, ports.CommittedPublicationSnapshot, ports.PublicationObservation, map[string]ports.ImmutablePublicationArtifact) {
	t.Helper()
	run, snapshot, artifacts := queryZeroRoleReportCommittedMaterial(t, true, mutateSupport)
	observation := queryP2Observation(t, run, snapshot, domain.JournalCompleted, domain.ExitIncompleteCoverage, 1)
	return run, snapshot, observation, artifacts
}

func queryZeroRoleReportCommittedMaterial(
	t *testing.T,
	withSupportIndex bool,
	mutateSupport func([]byte) []byte,
) (ports.PublicationRun, ports.CommittedPublicationSnapshot, map[string]ports.ImmutablePublicationArtifact) {
	t.Helper()
	run, baseSnapshot, _ := queryCommittedFixture(t, domain.ExitCommittedCIRejected)
	finalRecord, err := decodeFinalDTO(baseSnapshot.Final().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	reason := "provider_unavailable"
	for index := range finalRecord.RoleOutcomes {
		finalRecord.RoleOutcomes[index].Outcome = "failed"
		finalRecord.RoleOutcomes[index].FailureReason = &reason
		finalRecord.RoleOutcomes[index].ValidFindingIDs = nil
	}
	finalRecord.Findings = nil
	finalRecord.ContentVerdict = string(domain.ContentNoFindings)
	finalRecord.CoverageStatus = string(domain.CoverageIncomplete)
	finalRecord.CIDecision = string(domain.CIFail)
	finalRecord.CIReasonCodes = []string{"required_role_incomplete"}
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
	manifestRecord.RoleReports = nil
	manifestRecord.State = string(domain.RunFailed)
	manifestRecord.ContentVerdict = string(domain.ContentNoFindings)
	manifestRecord.CoverageStatus = string(domain.CoverageIncomplete)
	manifestRecord.CIDecision = string(domain.CIFail)
	manifestRecord.CIReasonCodes = []string{"required_role_incomplete"}
	manifestRecord.ExitCode = int(domain.ExitIncompleteCoverage)
	manifestRecord.FinalReview.SHA256 = finalIdentity.SHA256()
	manifestRecord.RecoveryJournal.ExpectedFinal.SHA256 = finalIdentity.SHA256()
	failures := make([]manifestFailureDTO, 0, len(manifestRecord.Attempts))
	for index := range manifestRecord.Attempts {
		manifestRecord.Attempts[index].State = string(domain.AttemptFailed)
		attemptID := manifestRecord.Attempts[index].AttemptID
		failures = append(failures, manifestFailureDTO{
			Class: string(domain.FailureProviderUnavailable), Stage: "review",
			ReasonCode: "provider_unavailable", AttemptID: &attemptID,
		})
	}
	manifestRecord.Failures = failures
	artifacts := map[string]ports.ImmutablePublicationArtifact{}
	if withSupportIndex {
		prefix := run.SessionID().String() + "/" + run.RunID().String()
		targetPath := prefix + "/target/target.bytes"
		target := mustQueryArtifact(t, mustQueryPath(t, targetPath), []byte("zero-report target"))
		supportPath := prefix + "/support/index.json"
		supportBytes := []byte(fmt.Sprintf(
			`{"schema_version":"mulgae-run-support-index.v1","artifacts":[{"path":%q,"sha256":%q}]}`,
			targetPath, target.SHA256(),
		))
		if mutateSupport != nil {
			supportBytes = mutateSupport(supportBytes)
		}
		support := mustQueryArtifact(t, mustQueryPath(t, supportPath), supportBytes)
		manifestRecord.CompositeIdentity.SupportIndex = &artifactIdentityDTO{Path: supportPath, SHA256: support.SHA256()}
		artifacts[targetPath] = target
		artifacts[supportPath] = support
	} else {
		manifestRecord.CompositeIdentity.SupportIndex = nil
	}
	manifestBytes, err := json.Marshal(manifestRecord)
	if err != nil {
		t.Fatal(err)
	}
	manifest := mustQueryArtifact(t, baseSnapshot.Manifest().Path(), manifestBytes)
	snapshot, err := ports.NewCommittedPublicationSnapshot(final, manifest, baseSnapshot.LineageEdge(), baseSnapshot.Epoch())
	if err != nil {
		t.Fatal(err)
	}
	return run, snapshot, artifacts
}

func queryStatusRoleReportFixture(t *testing.T) (
	ports.PublicationRun,
	ports.CommittedPublicationSnapshot,
	ports.PublicationObservation,
	map[string]ports.ImmutablePublicationArtifact,
	[]RoleReportURI,
) {
	t.Helper()
	run, baseSnapshot, _ := queryCommittedFixture(t, domain.ExitCommittedCIRejected)
	prefix := run.SessionID().String() + "/" + run.RunID().String()
	logicPath := prefix + "/role-reports/logic.md"
	securityPath := prefix + "/role-reports/security.md"
	logic := mustQueryArtifact(t, mustQueryPath(t, logicPath), []byte("# logic\n\nreport\n"))
	security := mustQueryArtifact(t, mustQueryPath(t, securityPath), []byte("# security\n\nreport\n"))
	targetPath := prefix + "/target/target.bytes"
	target := mustQueryArtifact(t, mustQueryPath(t, targetPath), []byte("status target"))
	supportPath := prefix + "/support/index.json"
	support := mustQueryArtifact(t, mustQueryPath(t, supportPath), []byte(fmt.Sprintf(
		`{"schema_version":"mulgae-run-support-index.v1","artifacts":[{"path":%q,"sha256":%q},{"path":%q,"sha256":%q},{"path":%q,"sha256":%q}]}`,
		logicPath, logic.SHA256(), securityPath, security.SHA256(), targetPath, target.SHA256(),
	)))
	manifestRecord, err := decodeManifestDTO(baseSnapshot.Manifest().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	manifestRecord.RoleReports = []manifestRoleReportDTO{
		{
			Role: "logic", Path: "role-reports/logic.md", SHA256: logic.SHA256(), ByteLength: len(logic.Bytes()),
			ProviderInstance: "logic-provider", AttemptID: "a_019f596a-d048-79e7-b2b7-59822f012273", ContentType: "text/markdown",
		},
		{
			Role: "security", Path: "role-reports/security.md", SHA256: security.SHA256(), ByteLength: len(security.Bytes()),
			ProviderInstance: "security-provider", AttemptID: "a_019f596a-d0ac-7c12-8b68-0bd73e911b2e", ContentType: "text/markdown",
		},
	}
	manifestRecord.CompositeIdentity.SupportIndex = &artifactIdentityDTO{Path: supportPath, SHA256: support.SHA256()}
	manifestBytes, err := json.Marshal(manifestRecord)
	if err != nil {
		t.Fatal(err)
	}
	manifest := mustQueryArtifact(t, baseSnapshot.Manifest().Path(), manifestBytes)
	snapshot, err := ports.NewCommittedPublicationSnapshot(baseSnapshot.Final(), manifest, baseSnapshot.LineageEdge(), baseSnapshot.Epoch())
	if err != nil {
		t.Fatal(err)
	}
	observation := queryP2Observation(t, run, snapshot, domain.JournalCompleted, domain.ExitCommittedCIRejected, 1)
	artifacts := map[string]ports.ImmutablePublicationArtifact{
		logicPath: logic, securityPath: security, targetPath: target, supportPath: support,
	}
	uris := []RoleReportURI{
		{Role: "logic", URI: ".mulgae/" + logicPath},
		{Role: "security", URI: ".mulgae/" + securityPath},
	}
	return run, snapshot, observation, artifacts, uris
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

// supportIndexReads counts whole-support traversals by their support-index
// read for one run, so reuse tests can assert traversal counts without timing.
func supportIndexReads(store *queryStore) int {
	count := 0
	for _, request := range store.auxiliaryRequests {
		if strings.HasSuffix(request.Path().String(), "/support/index.json") {
			count++
		}
	}
	return count
}

func TestCompositeFindingRequiresSelectedRoleProvider(t *testing.T) {
	run, snapshot, observation, _, _, _ := queryRuntimeFixture(t)
	decision, err := domain.ClassifyPublication(observation.ClassifierInput())
	if err != nil {
		t.Fatal(err)
	}
	var final compositeFinalDTO
	if err := json.Unmarshal(snapshot.Final().Bytes(), &final); err != nil {
		t.Fatal(err)
	}
	var manifest compositeManifestDTO
	if err := json.Unmarshal(snapshot.Manifest().Bytes(), &manifest); err != nil {
		t.Fatal(err)
	}
	final.SchemaVersion, final.RunType = "mulgae-composite-review-artifact.v1", string(domain.RunTypeComposite)
	manifest.SchemaVersion, manifest.RunType = "mulgae-composite-run-manifest.v1", final.RunType
	if _, err := buildCompositeCommittedReview(run, decision, snapshot, final, manifest); err != nil {
		t.Fatalf("valid selected-role finding: %v", err)
	}
	if len(final.Findings) == 0 {
		t.Fatal("fixture must contain a finding")
	}
	final.Findings[0].Role = string(domain.RoleDocumentation)
	if _, err := buildCompositeCommittedReview(run, decision, snapshot, final, manifest); err == nil {
		t.Fatal("composite accepted a finding without a selected role provider")
	}
}

// indexReadsForRun counts support-index reads for one run.
func indexReadsForRun(store *queryStore, runID string) int {
	count := 0
	for _, request := range store.auxiliaryRequests {
		if request.Run().RunID().String() == runID && strings.HasSuffix(request.Path().String(), "/support/index.json") {
			count++
		}
	}
	return count
}

// lineageRunFixture clones the base committed fixture onto a new run and
// review identity. With a source it becomes a delta review of that source;
// every clone carries its own manifest-bound v1 support index without
// composite.json.
func lineageRunFixture(
	t *testing.T,
	base ports.PublicationRun,
	baseSnapshot ports.CommittedPublicationSnapshot,
	runIDText, reviewIDText, sourceRunIDText, sourceReviewIDText string,
) (ports.PublicationRun, ports.CommittedPublicationSnapshot, ports.PublicationObservation, ports.ImmutablePublicationArtifact) {
	t.Helper()
	runID, err := domain.ParseRunID(runIDText)
	if err != nil {
		t.Fatal(err)
	}
	reviewID, err := domain.ParseReviewID(reviewIDText)
	if err != nil {
		t.Fatal(err)
	}
	run, err := ports.NewPublicationRun(base.Root(), base.SessionID(), runID)
	if err != nil {
		t.Fatal(err)
	}
	prefix := run.SessionID().String() + "/" + run.RunID().String()
	finalPath := mustQueryPath(t, prefix+"/review_"+reviewID.String()+".json")
	manifestPath := mustQueryPath(t, prefix+"/manifest.json")
	edgePath := mustQueryPath(t, "store/lineage-edges/e_"+reviewID.String()+".json")
	edge := mustQueryArtifact(t, edgePath, []byte(`{"schema_version":"mulgae-lineage-edge.v1"}`))
	epochPath := mustQueryPath(t, "store/epochs/epoch_00000000000000000001.json")
	epochRecord := mustQueryArtifact(t, epochPath, []byte(`{"schema_version":"mulgae-publication-epoch.v1"}`))
	epoch, err := ports.NewPublicationEpoch(1, epochRecord)
	if err != nil {
		t.Fatal(err)
	}
	indexPath := prefix + "/support/index.json"
	index := mustQueryArtifact(t, mustQueryPath(t, indexPath), []byte(`{"schema_version":"mulgae-run-support-index.v1","artifacts":[]}`))
	rebase := func(value string) string {
		value = strings.ReplaceAll(value, base.RunID().String(), runIDText)
		value = strings.ReplaceAll(value, baseSnapshot.Final().Identity().ReviewID().String(), reviewIDText)
		value = strings.Replace(value, `"composite_identity":{"manifest":`, `"composite_identity":{"support_index":{"path":`+strconv.Quote(indexPath)+`,"sha256":`+strconv.Quote(index.SHA256())+`},"manifest":`, 1)
		if sourceRunIDText == "" {
			return value
		}
		lineage := `"parent_run_id":` + strconv.Quote(sourceRunIDText) + `,"source_run_id":` + strconv.Quote(sourceRunIDText) + `,"source_review_id":` + strconv.Quote(sourceReviewIDText) + `,"source_finding_ref":null,"replay_mode":null`
		value = strings.ReplaceAll(value, `"run_type":"review"`, `"run_type":"delta"`)
		return strings.Replace(value, `"parent_run_id":null,"source_run_id":null,"source_review_id":null,"source_finding_ref":null,"replay_mode":null`, lineage, 1)
	}
	finalBytes := []byte(rebase(string(baseSnapshot.Final().Bytes())))
	finalIdentity, err := ports.NewFinalReviewIdentity(reviewID, finalPath, querySHA(finalBytes))
	if err != nil {
		t.Fatal(err)
	}
	final, err := ports.NewFinalReviewArtifact(finalIdentity, finalBytes)
	if err != nil {
		t.Fatal(err)
	}
	manifestBody := strings.ReplaceAll(rebase(string(baseSnapshot.Manifest().Bytes())), baseSnapshot.Final().Identity().SHA256(), finalIdentity.SHA256())
	// The shared base manifest predates the required role-report transport
	// field; the derived clones carry it so they stay schema-valid.
	manifestRecord, err := decodeManifestDTO([]byte(manifestBody))
	if err != nil {
		t.Fatal(err)
	}
	for i := range manifestRecord.RoleReports {
		manifestRecord.RoleReports[i].Transport = "stdout"
	}
	manifestBytes, err := json.Marshal(manifestRecord)
	if err != nil {
		t.Fatal(err)
	}
	manifest := mustQueryArtifact(t, manifestPath, manifestBytes)
	snapshot, err := ports.NewCommittedPublicationSnapshot(final, manifest, edge, epoch)
	if err != nil {
		t.Fatal(err)
	}
	return run, snapshot, queryP2Observation(t, run, snapshot, domain.JournalCompleted, domain.ExitCommittedCIRejected, 1), index
}

// compositeRootFixture derives a schema-valid composite v1 publication from
// the embedded valid examples, rebinding its identities to the given run and
// lineage topology: two role sources and a root source that share one
// ancestor. Its retirement walk resolves both sources and then the root
// source.
func compositeRootFixture(
	t *testing.T,
	base ports.PublicationRun,
	runIDText, reviewIDText string,
	sourceARunID, sourceAReviewID, sourceBRunID, sourceBReviewID, rootSourceRunID, rootSourceReviewID string,
) (ports.PublicationRun, ports.CommittedPublicationSnapshot, ports.PublicationObservation, ports.ImmutablePublicationArtifact) {
	t.Helper()
	finalBytes, err := os.ReadFile("../../builtin/assets/examples/composite-review-artifact.v1.valid.json")
	if err != nil {
		t.Fatal(err)
	}
	manifestBytes, err := os.ReadFile("../../builtin/assets/examples/composite-run-manifest.v1.valid.json")
	if err != nil {
		t.Fatal(err)
	}
	var final compositeFinalDTO
	if err := json.Unmarshal(finalBytes, &final); err != nil {
		t.Fatal(err)
	}
	var manifest compositeManifestDTO
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatal(err)
	}
	runID, err := domain.ParseRunID(runIDText)
	if err != nil {
		t.Fatal(err)
	}
	reviewID, err := domain.ParseReviewID(reviewIDText)
	if err != nil {
		t.Fatal(err)
	}
	run, err := ports.NewPublicationRun(base.Root(), base.SessionID(), runID)
	if err != nil {
		t.Fatal(err)
	}
	prefix := run.SessionID().String() + "/" + run.RunID().String()
	finalPath := mustQueryPath(t, prefix+"/review_"+reviewID.String()+".json")
	manifestPath := mustQueryPath(t, prefix+"/manifest.json")
	edgePath := mustQueryPath(t, "store/lineage-edges/e_"+reviewID.String()+".json")
	edge := mustQueryArtifact(t, edgePath, []byte(`{"schema_version":"mulgae-lineage-edge.v1"}`))
	epochPath := mustQueryPath(t, "store/epochs/epoch_00000000000000000001.json")
	epochRecord := mustQueryArtifact(t, epochPath, []byte(`{"schema_version":"mulgae-publication-epoch.v1"}`))
	epoch, err := ports.NewPublicationEpoch(1, epochRecord)
	if err != nil {
		t.Fatal(err)
	}
	indexPath := prefix + "/support/index.json"
	index := mustQueryArtifact(t, mustQueryPath(t, indexPath), []byte(`{"schema_version":"mulgae-run-support-index.v1","artifacts":[]}`))
	final.SessionID, final.RunID, final.ReviewID = run.SessionID().String(), runIDText, reviewIDText
	final.ReviewComposition.RootRunID = rootSourceRunID
	final.ReviewComposition.RootReviewID = rootSourceReviewID
	final.ReviewComposition.Sources = []compositeSourceDTO{
		{Kind: "recovery", Role: "logic", RunID: sourceARunID, ReviewID: sourceAReviewID, AttemptID: "a_019f596a-d048-79e7-b2b7-59822f012273", RoleReportSHA256: "sha256:" + strings.Repeat("c", 64)},
		{Kind: "recovery", Role: "security", RunID: sourceBRunID, ReviewID: sourceBReviewID, AttemptID: "a_019f596a-d049-79e7-b2b7-59822f012273", RoleReportSHA256: "sha256:" + strings.Repeat("d", 64)},
	}
	// The example's AGY role provider is retired for committed non-live
	// reads; use live provider instances so the retirement walk passes.
	final.RoleOutcomes[0].ProviderInstance = "zcode-logic"
	final.RoleOutcomes[1].ProviderInstance = "zcode-security"
	final.RoleOutcomes[0].SourceRunID, final.RoleOutcomes[0].SourceReviewID = sourceARunID, sourceAReviewID
	final.RoleOutcomes[1].SourceRunID, final.RoleOutcomes[1].SourceReviewID = sourceBRunID, sourceBReviewID
	final.Findings[0].Source.RunID, final.Findings[0].Source.ReviewID = sourceARunID, sourceAReviewID
	finalBytes, err = json.Marshal(final)
	if err != nil {
		t.Fatal(err)
	}
	// The composite target schema admits only content_sha256 and
	// manifest_path, while the shared target DTO re-emits null base/head
	// members; strip them the way the embedded example omits them.
	var document map[string]any
	if err := json.Unmarshal(finalBytes, &document); err != nil {
		t.Fatal(err)
	}
	if target, ok := document["target"].(map[string]any); ok {
		delete(target, "base_oid")
		delete(target, "head_oid")
	}
	if finalBytes, err = json.Marshal(document); err != nil {
		t.Fatal(err)
	}
	finalIdentity, err := ports.NewFinalReviewIdentity(reviewID, finalPath, querySHA(finalBytes))
	if err != nil {
		t.Fatal(err)
	}
	finalArtifact, err := ports.NewFinalReviewArtifact(finalIdentity, finalBytes)
	if err != nil {
		t.Fatal(err)
	}
	manifest.SessionID, manifest.RunID = run.SessionID().String(), runIDText
	manifest.ImmutableLineage.LineageEdgePath, manifest.ImmutableLineage.LineageEdgeSHA256 = edgePath.String(), edge.SHA256()
	manifest.ReviewComposition = final.ReviewComposition
	manifest.RoleReports[0].SourceRunID = sourceARunID
	manifest.RoleReports[1].SourceRunID = sourceBRunID
	manifest.RecoveryJournal.ExpectedStaged.Path = prefix + "/publication/staged/review_" + reviewID.String() + ".json.tmp"
	manifest.RecoveryJournal.ExpectedFinal.Path = finalPath.String()
	manifest.RecoveryJournal.ExpectedFinal.SHA256 = finalIdentity.SHA256()
	validated := finalIdentity.SHA256()
	manifest.RecoveryJournal.ValidatedCandidateSHA256 = &validated
	manifest.CompositeIdentity.Manifest.Path = manifestPath.String()
	manifest.CompositeIdentity.LineageEdge.Path, manifest.CompositeIdentity.LineageEdge.SHA256 = edgePath.String(), edge.SHA256()
	manifest.CompositeIdentity.Epoch.Path = epochPath.String()
	manifest.CompositeIdentity.SupportIndex = &artifactIdentityDTO{Path: indexPath, SHA256: index.SHA256()}
	manifest.FinalReview.ReviewID, manifest.FinalReview.Path, manifest.FinalReview.SHA256 = reviewIDText, finalPath.String(), finalIdentity.SHA256()
	manifestBytes, err = json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifestArtifact := mustQueryArtifact(t, manifestPath, manifestBytes)
	snapshot, err := ports.NewCommittedPublicationSnapshot(finalArtifact, manifestArtifact, edge, epoch)
	if err != nil {
		t.Fatal(err)
	}
	return run, snapshot, queryP2Observation(t, run, snapshot, domain.JournalCompleted, domain.ExitCommittedPass, 1), index
}

// TestCommittedLineageConfirmsDependenciesInPostorder is the failing-first
// lineage regression: a composite root with two sources sharing one ancestor
// consumes each publication once (one initial observation, one snapshot read,
// one index read) and confirms every consumed publication exactly once in
// dependency postorder — the shared ancestor once, before both dependents,
// and the requested publication last.
func TestCommittedLineageConfirmsDependenciesInPostorder(t *testing.T) {
	const (
		ancestorRun    = "r_019f596a-cfe4-7c9c-b82e-7149158243be"
		sourceARun     = "r_019f596a-cfe4-7c9c-b82e-7149158243bb"
		sourceBRun     = "r_019f596a-cfe4-7c9c-b82e-7149158243bc"
		rootRun        = "r_019f596a-cfe4-7c9c-b82e-7149158243bd"
		ancestorReview = "019f596a-d174-7321-b920-c2d312c82cc5"
		sourceAReview  = "019f596a-d174-7321-b920-c2d312c82cc3"
		sourceBReview  = "019f596a-d174-7321-b920-c2d312c82cc4"
		rootReview     = "019f596a-d174-7321-b920-c2d312c82cc6"
	)
	baseRun, baseSnapshot, _ := queryCommittedFixture(t, domain.ExitCommittedCIRejected)
	ancestorPublication, ancestorSnapshot, ancestorObservation, ancestorIndex := lineageRunFixture(t, baseRun, baseSnapshot, ancestorRun, ancestorReview, "", "")
	sourceAPublication, sourceASnapshot, sourceAObservation, sourceAIndex := lineageRunFixture(t, baseRun, baseSnapshot, sourceARun, sourceAReview, ancestorRun, ancestorReview)
	sourceBPublication, sourceBSnapshot, sourceBObservation, sourceBIndex := lineageRunFixture(t, baseRun, baseSnapshot, sourceBRun, sourceBReview, ancestorRun, ancestorReview)
	rootPublication, rootSnapshot, rootObservation, rootIndex := compositeRootFixture(t, baseRun, rootRun, rootReview,
		sourceARun, sourceAReview, sourceBRun, sourceBReview, ancestorRun, ancestorReview)
	store := &queryStore{
		resolved: rootPublication,
		resolutionsByRun: map[string]ports.PublicationRun{
			ancestorRun: ancestorPublication, sourceARun: sourceAPublication, sourceBRun: sourceBPublication,
		},
		observationsByRun: map[string]ports.PublicationObservation{
			rootRun: rootObservation, sourceARun: sourceAObservation, sourceBRun: sourceBObservation, ancestorRun: ancestorObservation,
		},
		snapshotsByRun: map[string]ports.CommittedPublicationSnapshot{
			rootRun: rootSnapshot, sourceARun: sourceASnapshot, sourceBRun: sourceBSnapshot, ancestorRun: ancestorSnapshot,
		},
		auxiliaryArtifacts: map[string]ports.ImmutablePublicationArtifact{
			rootIndex.Path().String(): rootIndex, sourceAIndex.Path().String(): sourceAIndex, sourceBIndex.Path().String(): sourceBIndex, ancestorIndex.Path().String(): ancestorIndex,
		},
	}
	service := mustQueryService(t, store, &queryValidator{}, nil)
	review, err := service.ReadCommitted(context.Background(), rootPublication)
	if err != nil {
		t.Fatalf("lineage committed read: %v (%v)", err, errors.Unwrap(err))
	}
	if review.RunType() != domain.RunTypeComposite {
		t.Fatalf("lineage fixture run type = %q, want composite", review.RunType())
	}
	if store.resolveCalls != 3 {
		t.Fatalf("retirement walk resolved %d ancestors, want 3 (both sources and the shared root)", store.resolveCalls)
	}
	for runID, name := range map[string]string{ancestorRun: "ancestor", sourceARun: "source A", sourceBRun: "source B", rootRun: "root"} {
		if reads := store.snapshotReadsByRun[runID]; reads != 1 {
			t.Fatalf("%s snapshot reads = %d, want 1", name, reads)
		}
		if reads := indexReadsForRun(store, runID); reads != 1 {
			t.Fatalf("%s support-index reads = %d, want 1", name, reads)
		}
	}
	want := []string{rootRun, sourceARun, ancestorRun, sourceBRun, ancestorRun, sourceARun, sourceBRun, rootRun}
	if !slices.Equal(store.observeOrder, want) {
		t.Fatalf("observation order = %v, want dependency postorder %v", store.observeOrder, want)
	}
}

// TestSeparateRequestsDetectLaterCorruption pins fresh per-request
// verification: a second request through the same entry point detects both a
// body-only change of a served artifact (with P2 identities unchanged) and a
// later publication-identity change.
func TestSeparateRequestsDetectLaterCorruption(t *testing.T) {
	t.Run("served body changed between requests", func(t *testing.T) {
		service, store, run, _ := liveAgyCommittedFixture(t)
		// liveSourceIdentity performs the first, successful request. This leg
		// proves a later served-body change is detected; per-request support
		// freshness is pinned by
		// TestReportChunksKeepReceiptAndFullContentIdentityPerFreshRequest.
		sourceIdentity := liveSourceIdentity(t, service, run)
		path := run.SessionID().String() + "/" + run.RunID().String() + "/excerpts/F001_1.md"
		store.auxiliaryArtifacts[path] = mustQueryArtifact(t, mustQueryPath(t, path), []byte("changed between requests"))
		if _, err := service.ReadSourceEvidence(context.Background(), run, mustLiveBinding(t), "F001", sourceIdentity, 0, ContentContinuation{}); failureClass(t, err) != domain.FailureArtifact {
			t.Fatalf("later body change escaped fresh verification: %v", err)
		}
	})
	t.Run("publication identity changed between requests", func(t *testing.T) {
		service, store, run, _ := liveAgyCommittedFixture(t)
		if _, err := service.ReadCommitted(context.Background(), run); err != nil {
			t.Fatal(err)
		}
		store.observations = []ports.PublicationObservation{
			store.observation,
			queryP2Observation(t, run, querySnapshotAtEpoch(t, store.snapshot, 2), domain.JournalCompleted, domain.ExitCommittedCIRejected, 2),
		}
		store.observation = ports.PublicationObservation{}
		if _, err := service.ReadCommitted(context.Background(), run); failureClass(t, err) != domain.FailureArtifact {
			t.Fatalf("later identity change escaped fresh verification: %v", err)
		}
	})
}

func mustLiveBinding(t *testing.T) domain.ProjectBinding {
	t.Helper()
	binding, err := domain.ParseProjectBinding("sha256:" + strings.Repeat("1", 64))
	if err != nil {
		t.Fatal(err)
	}
	return binding
}

func liveSourceIdentity(t *testing.T, service *Service, run ports.PublicationRun) string {
	t.Helper()
	review, err := service.ReadCommitted(context.Background(), run)
	if err != nil {
		t.Fatal(err)
	}
	return review.SourceIdentitySHA256()
}

// TestReadCommittedStableWithoutSupportIndexKeepsTwoObservations guards the
// minimal path: a no-index publication keeps exactly the initial observation
// and one final confirmation.
func TestReadCommittedStableWithoutSupportIndexKeepsTwoObservations(t *testing.T) {
	run, snapshot, initial := queryCommittedFixture(t, domain.ExitCommittedCIRejected)
	store := &queryStore{observations: []ports.PublicationObservation{initial, initial}, snapshot: snapshot}
	if _, err := mustQueryService(t, store, &queryValidator{}, nil).ReadCommitted(context.Background(), run); err != nil {
		t.Fatal(err)
	}
	if store.observeCalls != 2 {
		t.Fatalf("ObserveRun calls = %d, want 2", store.observeCalls)
	}
}

// deltaRuntimeCompositionFixture builds a runtime-capable delta review whose
// lineage resolves to a committed ancestor, so a composition-support read
// consumes two publications in one call.
func deltaRuntimeCompositionFixture(t *testing.T) (ports.PublicationRun, ports.PublicationRun, *queryStore, *Service) {
	t.Helper()
	ancestorRunID := "r_019f596a-cfe4-7c9c-b82e-7149158243bf"
	ancestorReviewID := "019f596a-d174-7321-b920-c2d312c82cc7"
	baseRun, baseSnapshot, _ := queryCommittedFixture(t, domain.ExitCommittedCIRejected)
	deltaRun, runtimeSnapshot, _, artifacts, _, _ := queryRuntimeFixture(t)
	ancestorPublication, ancestorSnapshot, ancestorObservation, ancestorIndex := lineageRunFixture(t, baseRun, baseSnapshot, ancestorRunID, ancestorReviewID, "", "")
	final, err := decodeFinalDTO(runtimeSnapshot.Final().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	manifestRecord, err := decodeManifestDTO(runtimeSnapshot.Manifest().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	final.RunType = string(domain.RunTypeDelta)
	manifestRecord.RunType = final.RunType
	final.ImmutableLineage.ParentRunID = &ancestorRunID
	final.ImmutableLineage.SourceRunID = &ancestorRunID
	final.ImmutableLineage.SourceReviewID = &ancestorReviewID
	manifestRecord.ImmutableLineage = final.ImmutableLineage
	finalBytes, err := json.Marshal(final)
	if err != nil {
		t.Fatal(err)
	}
	finalIdentity, err := ports.NewFinalReviewIdentity(runtimeSnapshot.Final().Identity().ReviewID(), runtimeSnapshot.Final().Identity().Path(), querySHA(finalBytes))
	if err != nil {
		t.Fatal(err)
	}
	finalArtifact, err := ports.NewFinalReviewArtifact(finalIdentity, finalBytes)
	if err != nil {
		t.Fatal(err)
	}
	manifestRecord.FinalReview.SHA256 = finalIdentity.SHA256()
	manifestRecord.RecoveryJournal.ExpectedFinal.SHA256 = finalIdentity.SHA256()
	manifestBytes, err := json.Marshal(manifestRecord)
	if err != nil {
		t.Fatal(err)
	}
	manifestArtifact := mustQueryArtifact(t, runtimeSnapshot.Manifest().Path(), manifestBytes)
	deltaSnapshot, err := ports.NewCommittedPublicationSnapshot(finalArtifact, manifestArtifact, runtimeSnapshot.LineageEdge(), runtimeSnapshot.Epoch())
	if err != nil {
		t.Fatal(err)
	}
	deltaObservation := queryP2Observation(t, deltaRun, deltaSnapshot, domain.JournalCompleted, domain.ExitCommittedCIRejected, 1)
	store := &queryStore{
		resolved:           deltaRun,
		resolutionsByRun:   map[string]ports.PublicationRun{ancestorRunID: ancestorPublication},
		observationsByRun:  map[string]ports.PublicationObservation{deltaRun.RunID().String(): deltaObservation, ancestorRunID: ancestorObservation},
		snapshotsByRun:     map[string]ports.CommittedPublicationSnapshot{deltaRun.RunID().String(): deltaSnapshot, ancestorRunID: ancestorSnapshot},
		auxiliaryArtifacts: artifacts,
	}
	store.auxiliaryArtifacts[ancestorIndex.Path().String()] = ancestorIndex
	return deltaRun, ancestorPublication, store, mustQueryService(t, store, &queryValidator{}, nil)
}

// TestReadCompositionSupportConsumesEachPublicationOnce guards the delta
// composition path where the retirement walk and the composition walk both
// reach the ancestor: each consumed publication performs exactly one snapshot
// read and one support-index read per call.
func TestReadCompositionSupportConsumesEachPublicationOnce(t *testing.T) {
	deltaRun, ancestor, store, service := deltaRuntimeCompositionFixture(t)
	if _, err := service.ReadCompositionSupport(context.Background(), deltaRun); err != nil {
		t.Fatalf("ReadCompositionSupport() error = %v", err)
	}
	for runID, name := range map[string]string{deltaRun.RunID().String(): "delta root", ancestor.RunID().String(): "ancestor"} {
		if reads := store.snapshotReadsByRun[runID]; reads != 1 {
			t.Fatalf("%s snapshot reads = %d, want 1", name, reads)
		}
		if reads := indexReadsForRun(store, runID); reads != 1 {
			t.Fatalf("%s support-index reads = %d, want 1", name, reads)
		}
	}
}
