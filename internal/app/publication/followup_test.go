package publication

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/app/evidence"
	"github.com/irootkernel/mulgae/internal/app/validation"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

type followupProjectionSchemaValidator struct{}

func (followupProjectionSchemaValidator) Validate(context.Context, ports.AssetID, []byte) error {
	return nil
}

func TestFollowupCurrentTargetReaderUsesCapturedEvidenceBySideAndPath(t *testing.T) {
	target, err := ports.NewCapturedReviewPatchTarget([]byte("patch bytes\n"))
	if err != nil {
		t.Fatal(err)
	}
	path, _ := ports.NewSafeRelativePath("report.go")
	fileBytes := []byte("package report\n")
	file, err := ports.NewWorkspaceSnapshotFile(path, fileBytes, sha256Identifier(fileBytes))
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := ports.NewWorkspaceSnapshotRequest([]ports.WorkspaceSnapshotFile{file}, "followup-reader-test")
	if err != nil {
		t.Fatal(err)
	}
	capturedEvidence, err := ports.NewCapturedTargetEvidence(map[ports.CapturedEvidenceSide][]ports.WorkspaceSnapshotFile{
		ports.CapturedEvidenceWorktree: {file},
	})
	if err != nil {
		t.Fatal(err)
	}
	material, err := ports.NewCapturedReviewMaterialWithEvidence(target, snapshot, nil, capturedEvidence)
	if err != nil {
		t.Fatal(err)
	}
	archive, err := ports.MarshalCapturedReviewMaterial(material)
	if err != nil {
		t.Fatal(err)
	}
	targetSHA256 := "sha256:" + target.Identity().SHA256()
	reader, err := newFollowupCurrentTargetReader(targetSHA256, target.Bytes(), archive)
	if err != nil {
		t.Fatal(err)
	}
	availability, got, err := reader.ReadImmutableTarget(context.Background(), targetSHA256, evidence.SideWorktree, path)
	if err != nil || availability != evidence.ImmutableTargetAvailable || string(got) != string(fileBytes) {
		t.Fatalf("captured worktree evidence = %s %q, %v", availability, got, err)
	}
	availability, _, err = reader.ReadImmutableTarget(context.Background(), targetSHA256, evidence.SideHead, path)
	if err != nil || availability != evidence.ImmutableTargetUnavailable {
		t.Fatalf("absent head evidence = %s, %v", availability, err)
	}
}

func TestPrepareFollowupFindingsRetainsValidatedFindingAndVerifiedEvidence(t *testing.T) {
	input := followupProjectionInput(t, "line one\\n")
	findings, _, err := prepareFollowupFindings(input, "sha256:"+strings.Repeat("b", 64))
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].id != "F001" || findings[0].severity != domain.SeverityHigh ||
		len(findings[0].evidence) != 1 || findings[0].evidence[0].quote != "line one\n" ||
		findings[0].evidence[0].sourceRunID != input.SourceRunID.String() ||
		findings[0].evidence[0].sourceExcerptSHA256 != input.SourceExcerptSHA256 {
		t.Fatalf("followup projection did not retain trusted finding and evidence: %#v", findings)
	}
}

func TestPrepareFollowupFindingsRejectsUnboundCurrentEvidence(t *testing.T) {
	input := followupProjectionInput(t, "not present\\n")
	if _, _, err := prepareFollowupFindings(input, "sha256:"+strings.Repeat("b", 64)); err == nil {
		t.Fatal("accepted followup evidence whose quote is not bound to the immutable current target")
	}
}
func TestPrepareFollowupFindingsRejectsMismatchedSourceAuthority(t *testing.T) {
	input := followupProjectionInput(t, "line one\\n")
	input.SourceFindingID = "F999"
	if _, _, err := prepareFollowupFindings(input, "sha256:"+strings.Repeat("b", 64)); err == nil {
		t.Fatal("accepted followup evidence detached from its immutable source finding")
	}
}

func TestPrepareFollowupFindingsPreservesEveryResolution(t *testing.T) {
	for _, resolution := range []domain.FollowupResolution{
		domain.FollowupResolved,
		domain.FollowupPartiallyResolved,
		domain.FollowupStillOpen,
		domain.FollowupUnclear,
	} {
		t.Run(string(resolution), func(t *testing.T) {
			input := followupProjectionInput(t, "line one\\n")
			input.Output = followupProjectionOutput(t, resolution, "line one\\n", false)
			findings, outcome, err := prepareFollowupFindings(input, "sha256:"+strings.Repeat("b", 64))
			if err != nil || outcome.resolution != resolution || outcome.rationale != "verified finding" || len(outcome.evidence) != 1 {
				t.Fatalf("followup outcome = %#v, %v", outcome, err)
			}
			if len(findings) == 0 && (resolution == domain.FollowupPartiallyResolved || resolution == domain.FollowupStillOpen) {
				axes, _, exitCode, _, err := reduceFollowupAxes(findings, resolution, input.Output.Role(), domain.SeverityHigh)
				if err != nil {
					t.Fatal(err)
				}
				if resolution == domain.FollowupPartiallyResolved &&
					(axes.content != domain.ContentNoFindings || axes.coverage != domain.CoverageComplete || axes.ci != domain.CIPass || exitCode != int(domain.ExitCommittedPass)) {
					t.Fatalf("partially-resolved zero-findings axes = %#v, exit = %d", axes, exitCode)
				}
				if resolution == domain.FollowupStillOpen &&
					(axes.content != domain.ContentRequestChanges || axes.coverage != domain.CoverageComplete || axes.ci != domain.CIFail || exitCode != int(domain.ExitCommittedCIRejected)) {
					t.Fatalf("still-open zero-findings axes = %#v, exit = %d", axes, exitCode)
				}
			}
		})
	}
}
func TestPrepareFollowupFindingsCanonicalizesEvidenceBeforeFingerprinting(t *testing.T) {
	input := followupProjectionInput(t, "line one\\n")
	reverse := []followupEvidenceInput{
		{path: "src/z.go", lineStart: 1, lineEnd: 1, side: "head", quote: "line one\n"},
		{path: "src/a.go", lineStart: 1, lineEnd: 1, side: "head", quote: "line one\n"},
	}
	input.Output = followupProjectionOutputWithEvidence(t, domain.FollowupStillOpen, reverse, [][]followupEvidenceInput{reverse})
	findings, outcome, err := prepareFollowupFindings(input, "sha256:"+strings.Repeat("b", 64))
	if err != nil {
		t.Fatal(err)
	}
	if len(outcome.evidence) != 2 || outcome.evidence[0].path != "src/a.go" || outcome.evidence[1].path != "src/z.go" {
		t.Fatalf("outcome evidence is not canonical: %#v", outcome.evidence)
	}
	if len(findings) != 1 || len(findings[0].evidence) != 2 ||
		findings[0].evidence[0].path != "src/a.go" || findings[0].evidence[1].path != "src/z.go" {
		t.Fatalf("finding evidence is not canonical before fingerprinting: %#v", findings)
	}
	for _, item := range append(outcome.evidence, findings[0].evidence...) {
		if item.sourceSessionID != input.SourceSessionID.String() || item.sourceRunID != input.SourceRunID.String() ||
			item.sourceReviewID != input.SourceReviewID.String() || item.sourceFindingID != input.SourceFindingID ||
			item.sourceTargetSHA256 != input.SourceTargetSHA256 || item.sourceExcerptSHA256 != input.SourceExcerptSHA256 ||
			item.targetSHA256 != "sha256:"+strings.Repeat("b", 64) {
			t.Fatalf("canonicalization changed source/current tuple authority: %#v", item)
		}
	}
}

func TestPrepareFollowupFindingsEnforcesEvidenceCountBounds(t *testing.T) {
	for _, count := range []int{1, 2, 20} {
		t.Run("count_"+strconv.Itoa(count), func(t *testing.T) {
			input := followupProjectionInput(t, "line one\\n")
			items := make([]followupEvidenceInput, count)
			for index := range items {
				items[index] = followupEvidenceInput{path: fmt.Sprintf("src/%02d.go", index), lineStart: 1, lineEnd: 1, side: "head", quote: "line one\n"}
			}
			input.Output = followupProjectionOutputWithEvidence(t, domain.FollowupStillOpen, items, [][]followupEvidenceInput{items})
			findings, outcome, err := prepareFollowupFindings(input, "sha256:"+strings.Repeat("b", 64))
			if err != nil || len(outcome.evidence) != count || len(findings) != 1 || len(findings[0].evidence) != count {
				t.Fatalf("count %d = findings %#v, outcome %#v, %v", count, findings, outcome, err)
			}
		})
	}
}

func TestPrepareFollowupFindingsRejectsDuplicateTupleBeforeCandidate(t *testing.T) {
	input := followupProjectionInput(t, "line one\\n")
	duplicate := []followupEvidenceInput{
		{path: "src/a.go", lineStart: 1, lineEnd: 1, side: "head", quote: "line one\n"},
		{path: "src/a.go", lineStart: 1, lineEnd: 1, side: "head", quote: "line one\n"},
	}
	input.Output = followupProjectionOutputWithEvidence(t, domain.FollowupStillOpen, duplicate, [][]followupEvidenceInput{{duplicate[0]}})
	if _, _, err := prepareFollowupFindings(input, "sha256:"+strings.Repeat("b", 64)); err == nil || !strings.Contains(err.Error(), "evidence tuple is duplicated") {
		t.Fatalf("duplicate outcome tuple reached prepared candidate: %v", err)
	}

	input.Output = followupProjectionOutputWithEvidence(t, domain.FollowupStillOpen, []followupEvidenceInput{duplicate[0]}, [][]followupEvidenceInput{duplicate})
	if _, _, err := prepareFollowupFindings(input, "sha256:"+strings.Repeat("b", 64)); err == nil || !strings.Contains(err.Error(), "evidence tuple is duplicated") {
		t.Fatalf("duplicate finding tuple reached prepared candidate: %v", err)
	}
}

type followupEvidenceInput struct {
	path      string
	lineStart int
	lineEnd   int
	side      string
	quote     string
}

func followupProjectionInput(t *testing.T, quote string) FollowupCandidateInput {
	t.Helper()
	sessionID, err := domain.ParseSessionID("s_019f596a-cf80-7c67-b265-f37053d51ccf")
	if err != nil {
		t.Fatal(err)
	}
	runID, err := domain.ParseRunID("r_019f596a-cf81-7c67-b265-f37053d51ccf")
	if err != nil {
		t.Fatal(err)
	}
	reviewID, err := domain.ParseReviewID("019f596a-cf82-7c67-b265-f37053d51ccf")
	if err != nil {
		t.Fatal(err)
	}
	output := followupProjectionOutput(t, domain.FollowupStillOpen, quote, true)
	return FollowupCandidateInput{SourceSessionID: sessionID, SourceRunID: runID, SourceReviewID: reviewID, SourceFindingID: "F001", SourceTargetSHA256: "sha256:" + strings.Repeat("a", 64), SourceExcerptSHA256: sha256Identifier([]byte("source excerpt")), Provider: "provider", Output: output, Runtime: FollowupRuntimeArtifactInput{RuntimeTarget: []byte("line one\nline two\n")}}
}
func followupProjectionOutput(t *testing.T, resolution domain.FollowupResolution, quote string, withFinding bool) validation.ValidatedFollowup {
	t.Helper()
	sessionID, _ := domain.ParseSessionID("s_019f596a-cf80-7c67-b265-f37053d51ccf")
	runID, _ := domain.ParseRunID("r_019f596a-cf81-7c67-b265-f37053d51ccf")
	reviewID, _ := domain.ParseReviewID("019f596a-cf82-7c67-b265-f37053d51ccf")
	schemaID, _ := ports.ParseAssetID(validation.ProviderFollowupSchemaID)
	validator, err := validation.NewFollowupValidator(followupProjectionSchemaValidator{}, schemaID)
	if err != nil {
		t.Fatal(err)
	}
	findings := "[]"
	if withFinding {
		findings = `[{"severity":"high","title":"Retained finding","description":"The issue remains.","evidence":[{"current":{"path":"src/a.go","line_start":1,"line_end":1,"side":"head","quote":"` + quote + `"}}],"recommendation":"Fix it.","confidence":"high"}]`
	}
	raw := []byte(`{"schema_version":"mulgae-provider-followup-output.v1","summary":"followup","resolution":"` + string(resolution) + `","rationale":"verified finding","evidence":[{"current":{"path":"src/a.go","line_start":1,"line_end":1,"side":"head","quote":"` + quote + `"}}],"new_findings":` + findings + `,"limitations":[]}`)
	output, err := validator.Validate(context.Background(), raw, validation.FollowupValidationScope{SessionID: sessionID, SourceRunID: runID, ReviewID: reviewID, FindingID: "F001", SourceTargetSHA256: "sha256:" + strings.Repeat("a", 64), SourceExcerptSHA256: sha256Identifier([]byte("source excerpt")), CurrentTargetSHA256: "sha256:" + strings.Repeat("b", 64), Role: domain.RoleLogic, ProviderInstance: "provider"})
	if err != nil {
		t.Fatal(err)
	}
	return output
}
func followupProjectionOutputWithEvidence(t *testing.T, resolution domain.FollowupResolution, outcome []followupEvidenceInput, findingsEvidence [][]followupEvidenceInput) validation.ValidatedFollowup {
	t.Helper()
	sessionID, _ := domain.ParseSessionID("s_019f596a-cf80-7c67-b265-f37053d51ccf")
	runID, _ := domain.ParseRunID("r_019f596a-cf81-7c67-b265-f37053d51ccf")
	reviewID, _ := domain.ParseReviewID("019f596a-cf82-7c67-b265-f37053d51ccf")
	schemaID, _ := ports.ParseAssetID(validation.ProviderFollowupSchemaID)
	validator, err := validation.NewFollowupValidator(followupProjectionSchemaValidator{}, schemaID)
	if err != nil {
		t.Fatal(err)
	}
	toWire := func(items []followupEvidenceInput) []map[string]any {
		result := make([]map[string]any, len(items))
		for index, item := range items {
			result[index] = map[string]any{"current": map[string]any{
				"path": item.path, "line_start": item.lineStart, "line_end": item.lineEnd, "side": item.side, "quote": item.quote,
			}}
		}
		return result
	}
	newFindings := make([]map[string]any, len(findingsEvidence))
	for index, items := range findingsEvidence {
		newFindings[index] = map[string]any{
			"severity": "high", "title": "Retained finding", "description": "The issue remains.",
			"evidence": toWire(items), "recommendation": "Fix it.", "confidence": "high",
		}
	}
	raw, err := json.Marshal(map[string]any{
		"schema_version": "mulgae-provider-followup-output.v1", "summary": "followup", "resolution": resolution,
		"rationale": "verified finding", "evidence": toWire(outcome), "new_findings": newFindings, "limitations": []string{},
	})
	if err != nil {
		t.Fatal(err)
	}
	output, err := validator.Validate(context.Background(), raw, validation.FollowupValidationScope{
		SessionID: sessionID, SourceRunID: runID, ReviewID: reviewID, FindingID: "F001",
		SourceTargetSHA256: "sha256:" + strings.Repeat("a", 64), SourceExcerptSHA256: sha256Identifier([]byte("source excerpt")),
		CurrentTargetSHA256: "sha256:" + strings.Repeat("b", 64), Role: domain.RoleLogic, ProviderInstance: "provider",
	})
	if err != nil {
		t.Fatal(err)
	}
	return output
}
