package validation

import (
	"bytes"
	"testing"

	"github.com/irootkernel/mulgae/internal/domain"
)

func TestNewReportsOnlyValidatedFollowupAcceptsFreeFormReport(t *testing.T) {
	t.Parallel()
	report := []byte("# followup\n\nThe finding still needs a human check.\n")
	output, err := NewReportsOnlyValidatedFollowup(
		domain.RoleLogic, "test.provider", report, domain.ParseNotStarted, domain.ValidationNotStarted,
	)
	if err != nil {
		t.Fatalf("NewReportsOnlyValidatedFollowup() error = %v", err)
	}
	if !output.ReportsOnly() || output.Resolution().Valid() || len(output.NormalizedRaw()) != 0 {
		t.Fatalf("reports-only output invented structured authority: %#v", output)
	}
	if output.StructuredExtractionStatus() != domain.StructuredExtractionReportsOnly {
		t.Fatalf("structured_extraction_status = %q", output.StructuredExtractionStatus())
	}
	if string(output.ProviderRaw()) != string(report) {
		t.Fatalf("provider raw = %q, want exact free-form report", output.ProviderRaw())
	}
}

func TestNewReportsOnlyValidatedFollowupAcceptsTenMiBReport(t *testing.T) {
	report := bytes.Repeat([]byte("a"), 10<<20)
	output, err := NewReportsOnlyValidatedFollowup(
		domain.RoleLogic,
		"logic-provider",
		report,
		domain.ParseNotStarted,
		domain.ValidationNotStarted,
	)
	if err != nil {
		t.Fatalf("NewReportsOnlyValidatedFollowup() rejected a 10 MiB report: %v", err)
	}
	if len(output.ProviderRaw()) != len(report) {
		t.Fatalf("report bytes = %d, want %d", len(output.ProviderRaw()), len(report))
	}
}

func TestNewReportsOnlyValidatedFollowupRejectsInventedStructuredPair(t *testing.T) {
	t.Parallel()
	if _, err := NewReportsOnlyValidatedFollowup(
		domain.RoleLogic, "test.provider", []byte("report"), domain.ParseValid, domain.ValidationValid,
	); err == nil {
		t.Fatal("accepted structured extraction pair for reports-only construction")
	}
	if _, err := NewReportsOnlyValidatedFollowup(
		domain.RoleLogic, "test.provider", []byte("   \n"), domain.ParseNotStarted, domain.ValidationNotStarted,
	); err == nil {
		t.Fatal("accepted whitespace-only role report")
	}
}
