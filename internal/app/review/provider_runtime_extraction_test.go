package review

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/app/evidence"
	"github.com/irootkernel/mulgae/internal/app/validation"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

const extractionAcceptedReport = "# logic review\n\nOne concrete defect, described in prose.\n"

func extractionValidatedReview(t *testing.T, targetSHA256, completeness, limitations string, findings []string) validation.ValidatedReview {
	t.Helper()
	schemaID, err := ports.ParseAssetID(validation.ProviderReviewSchemaID)
	if err != nil {
		t.Fatal(err)
	}
	validator, err := validation.NewReviewValidator(bridgeSchemaValidator{}, schemaID)
	if err != nil {
		t.Fatal(err)
	}
	raw := fmt.Sprintf(
		`{"schema_version":"mulgae-provider-review-output.v1","summary":"Transcribed from the accepted report.","completeness":%q,"limitations":[%s],"findings":[%s]}`,
		completeness, limitations, strings.Join(findings, ","),
	)
	review, repair, err := validator.Validate(context.Background(), []byte(raw), validation.ReviewValidationScope{
		TargetSHA256:     targetSHA256,
		Role:             domain.RoleLogic,
		ProviderInstance: "fake.logic",
	})
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if repair != nil {
		t.Fatalf("Validate() repair plan = %#v, want nil", repair)
	}
	return review
}

func extractionRuntime(t *testing.T, quote string) *ProviderInvocationRuntime {
	t.Helper()
	verifier, err := evidence.NewVerifier(&bridgeImmutableReader{responses: map[string]bridgeReaderResponse{
		bridgeReaderKey(evidence.SideHead, "src/file.go"): {availability: evidence.ImmutableTargetAvailable, bytes: []byte(quote)},
	}})
	if err != nil {
		t.Fatal(err)
	}
	return &ProviderInvocationRuntime{
		verifier: verifier, policy: DefaultEvidencePolicy(),
		pending:           make(map[domain.AttemptID]InvocationRepairInput),
		pendingExtraction: make(map[domain.AttemptID]InvocationExtractionInput),
	}
}

func extractionJob(t *testing.T) InvocationJob {
	t.Helper()
	job := coordinatorTypesJob(t, domain.RoleLogic, "fake.logic", 1)
	job.purpose = domain.InvocationExtract
	return job
}

// A successful trailer upgrades the role to structured while the published role
// report stays the accepted Markdown byte for byte, on its original transport.
func TestExtractionAcceptPreservesAcceptedReportAndTransport(t *testing.T) {
	job := extractionJob(t)
	runtime := extractionRuntime(t, "line\n")
	finding := bridgeFindingJSON("Transcribed defect", []bridgeClaimSpec{{
		path: "src/file.go", side: evidence.SideHead, lineStart: 1, lineEnd: 1, quote: "line\n",
	}})
	validated := extractionValidatedReview(t, job.Target().SHA256(), "complete", "", []string{finding})

	outcome := runtime.acceptExtraction(
		context.Background(), job, validated,
		[]byte(extractionAcceptedReport), ports.ProviderOutputTransportStagedFile,
	)
	if !outcome.Succeeded() {
		t.Fatalf("extraction outcome = %#v", outcome)
	}
	output, ok := outcome.Output()
	if !ok {
		t.Fatal("successful extraction has no output")
	}
	if output.ReportsOnly() {
		t.Fatal("extraction must clear reports-only")
	}
	if !bytes.Equal(output.ReportMarkdown(), []byte(extractionAcceptedReport)) {
		t.Fatalf("role report = %q, want the accepted report unchanged", output.ReportMarkdown())
	}
	if output.OutputTransport() != ports.ProviderOutputTransportStagedFile {
		t.Fatalf("transport = %q, want the transport that carried the accepted report", output.OutputTransport())
	}
	if output.ParseState() != domain.ParseValid || output.ValidationState() != domain.ValidationValid {
		t.Fatalf("extraction states = %q/%q", output.ParseState(), output.ValidationState())
	}
	if len(output.Findings()) != 1 {
		t.Fatalf("finding count = %d, want 1", len(output.Findings()))
	}
}

// Review coverage was decided when Mulgae accepted the report. A transcription
// pass must not be able to mark the role degraded through its own self-assessment.
func TestExtractionAcceptOverridesProviderCoverageClaims(t *testing.T) {
	job := extractionJob(t)
	runtime := extractionRuntime(t, "line\n")
	finding := bridgeFindingJSON("Transcribed defect", []bridgeClaimSpec{{
		path: "src/file.go", side: evidence.SideHead, lineStart: 1, lineEnd: 1, quote: "line\n",
	}})
	validated := extractionValidatedReview(
		t, job.Target().SHA256(), "incomplete", `"Could not transcribe every claim."`, []string{finding},
	)

	outcome := runtime.acceptExtraction(
		context.Background(), job, validated,
		[]byte(extractionAcceptedReport), ports.ProviderOutputTransportStdout,
	)
	if !outcome.Succeeded() {
		t.Fatalf("extraction outcome = %#v", outcome)
	}
	output, ok := outcome.Output()
	if !ok {
		t.Fatal("successful extraction has no output")
	}
	if output.Completeness() != "complete" || len(output.Limitations()) != 0 {
		t.Fatalf("coverage = %q limitations=%#v, want Mulgae-owned complete with no limitations",
			output.Completeness(), output.Limitations())
	}
	if coordinatorOutputDegraded(&output) {
		t.Fatal("extraction self-assessment must not degrade the role")
	}
}

// The trailer owns no further invocation slot, so a quote mismatch must never
// mint an exact-evidence repair plan.
func TestExtractionQuoteMismatchNeverMintsRepairPlan(t *testing.T) {
	job := extractionJob(t)
	runtime := extractionRuntime(t, "different\n")
	finding := bridgeFindingJSON("Mismatched quote", []bridgeClaimSpec{{
		path: "src/file.go", side: evidence.SideHead, lineStart: 1, lineEnd: 1, quote: "line\n",
	}})
	validated := extractionValidatedReview(t, job.Target().SHA256(), "complete", "", []string{finding})

	outcome := runtime.acceptExtraction(
		context.Background(), job, validated,
		[]byte(extractionAcceptedReport), ports.ProviderOutputTransportStdout,
	)
	if outcome.Succeeded() || coordinatorOutcomeCondition(outcome) != AttemptConditionUnrepairableEvidence {
		t.Fatalf("quote mismatch outcome = %#v", outcome)
	}
	if len(runtime.pending) != 0 {
		t.Fatalf("extraction retained a repair plan: %#v", runtime.pending)
	}
}

// Mulgae cannot prove a transcribed finding restates a claim the accepted report
// made, so a finding it could not confirm against the target is backed by
// nothing checkable. Unverified evidence is rejected at every severity, not only
// the severities the configured evidence policy names.
func TestExtractionRejectsUnverifiedEvidenceAtEverySeverity(t *testing.T) {
	for _, severity := range []string{"high", "medium", "low", "info"} {
		t.Run(severity, func(t *testing.T) {
			job := extractionJob(t)
			runtime := extractionRuntime(t, "different\n")
			finding := bridgeFindingJSON("Mismatched quote", []bridgeClaimSpec{{
				path: "src/file.go", side: evidence.SideHead, lineStart: 1, lineEnd: 1, quote: "line\n",
			}})
			finding = strings.Replace(finding, `"severity":"high"`, fmt.Sprintf(`"severity":%q`, severity), 1)
			validated := extractionValidatedReview(t, job.Target().SHA256(), "complete", "", []string{finding})

			outcome := runtime.acceptExtraction(
				context.Background(), job, validated,
				[]byte(extractionAcceptedReport), ports.ProviderOutputTransportStdout,
			)
			if outcome.Succeeded() || coordinatorOutcomeCondition(outcome) != AttemptConditionUnrepairableEvidence {
				t.Fatalf("unverified %s finding outcome = %#v, want a rejected transcription", severity, outcome)
			}
			if len(runtime.pending) != 0 {
				t.Fatalf("extraction retained a repair plan: %#v", runtime.pending)
			}
		})
	}
}

// An accepted free-form report is retained so the coordinator can schedule the
// trailer, and only an initial invocation leaves the second slot free.
func TestAcceptedFreeFormReportRetainsExtractionInputForInitialOnly(t *testing.T) {
	for _, purpose := range []domain.InvocationPurpose{domain.InvocationInitial, domain.InvocationRetry} {
		t.Run(string(purpose), func(t *testing.T) {
			job := coordinatorTypesJob(t, domain.RoleLogic, "fake.logic", 1)
			job.purpose = purpose
			runtime := extractionRuntime(t, "line\n")
			runtime.captures = make(map[captureKey]AttemptCapture)
			runtime.inventory = make(map[captureKey]RuntimeArtifactInventory)

			outcome, ok := runtime.acceptFreeFormReport(
				context.Background(), job, []byte(extractionAcceptedReport), nil, []byte("raw"), nil,
				domain.ParseNotStarted, domain.ValidationNotStarted, ports.ProviderOutputTransportStdout,
			)
			if !ok || !outcome.Succeeded() {
				t.Fatalf("free-form outcome = %#v, ok=%t", outcome, ok)
			}
			retained, present := runtime.pendingExtraction[job.AttemptID()]
			wantRetained := purpose == domain.InvocationInitial
			if present != wantRetained {
				t.Fatalf("retained extraction input = %t, want %t", present, wantRetained)
			}
			if wantRetained && !bytes.Equal(retained.AcceptedReport(), []byte(extractionAcceptedReport)) {
				t.Fatalf("retained report = %q", retained.AcceptedReport())
			}
		})
	}
}
