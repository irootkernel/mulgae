package publication

import (
	"context"
	"strings"
	"testing"

	"github.com/irootkernel/kkachi-agent-review/internal/app/validation"
	"github.com/irootkernel/kkachi-agent-review/internal/domain"
	"github.com/irootkernel/kkachi-agent-review/internal/ports"
)

type followupProjectionSchemaValidator struct{}

func (followupProjectionSchemaValidator) Validate(context.Context, ports.AssetID, []byte) error {
	return nil
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
	raw := []byte(`{"schema_version":"kar-provider-followup-output.v2","summary":"followup","resolution":"` + string(resolution) + `","rationale":"verified finding","evidence":[{"current":{"path":"src/a.go","line_start":1,"line_end":1,"side":"head","quote":"` + quote + `"}}],"new_findings":` + findings + `,"limitations":[]}`)
	output, err := validator.Validate(context.Background(), raw, validation.FollowupValidationScope{SessionID: sessionID, SourceRunID: runID, ReviewID: reviewID, FindingID: "F001", SourceTargetSHA256: "sha256:" + strings.Repeat("a", 64), SourceExcerptSHA256: sha256Identifier([]byte("source excerpt")), CurrentTargetSHA256: "sha256:" + strings.Repeat("b", 64), Role: domain.RoleLogic, ProviderInstance: "provider"})
	if err != nil {
		t.Fatal(err)
	}
	return output
}
