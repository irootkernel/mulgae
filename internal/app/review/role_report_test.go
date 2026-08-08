package review

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/irootkernel/mulgae/internal/domain"
)

func TestNewReportsOnlyValidatedRoleOutputAcceptsMarkdown(t *testing.T) {
	t.Parallel()

	target := coordinatorTypesTarget(t, 1)
	output, err := NewReportsOnlyValidatedRoleOutput(
		domain.RoleLogic, "kimi-logic", target, []byte("# logic\n\nLooks fine.\n"),
	)
	if err != nil {
		t.Fatalf("NewReportsOnlyValidatedRoleOutput() error = %v", err)
	}
	if !output.ReportsOnly() || string(output.ReportMarkdown()) != "# logic\n\nLooks fine.\n" {
		t.Fatalf("reports-only output = reportsOnly=%t markdown=%q", output.ReportsOnly(), output.ReportMarkdown())
	}
	if len(output.Findings()) != 0 || output.Completeness() != "complete" {
		t.Fatalf("reports-only output retained structured fields: findings=%d completeness=%q", len(output.Findings()), output.Completeness())
	}
}

func TestNormalizeRoleReportMarkdownRejectsInvalidContentAndAcceptsLargeReport(t *testing.T) {
	t.Parallel()

	if _, err := normalizeRoleReportMarkdown(nil); err == nil {
		t.Fatal("empty report accepted")
	}
	if _, err := normalizeRoleReportMarkdown([]byte("   \n\t  ")); err == nil {
		t.Fatal("whitespace-only report accepted")
	}
	if _, err := normalizeRoleReportMarkdown([]byte{0xff, 0xfe, 0xfd}); err == nil || utf8.Valid([]byte{0xff, 0xfe, 0xfd}) {
		t.Fatalf("non-UTF-8 report accepted or unexpectedly valid: %v", err)
	}
	large := []byte(strings.Repeat("a", (8<<20)+1))
	if normalized, err := normalizeRoleReportMarkdown(large); err != nil || len(normalized) != len(large) {
		t.Fatalf("large report rejected: bytes=%d err=%v", len(normalized), err)
	}
}

func TestComputeStructuredExtractionStatus(t *testing.T) {
	t.Parallel()

	if got := ComputeStructuredExtractionStatus(nil); got != domain.StructuredExtractionStructured {
		t.Fatalf("empty = %q", got)
	}
	reportsOnly := []domain.RoleResultSummary{
		{Role: domain.RoleLogic, Selected: true, Valid: true, ReportsOnly: true},
		{Role: domain.RoleSecurity, Selected: true, Valid: true, ReportsOnly: true},
	}
	if got := ComputeStructuredExtractionStatus(reportsOnly); got != domain.StructuredExtractionReportsOnly {
		t.Fatalf("reports-only = %q", got)
	}
	mixed := []domain.RoleResultSummary{
		{Role: domain.RoleLogic, Selected: true, Valid: true, ReportsOnly: false},
		{Role: domain.RoleSecurity, Selected: true, Valid: true, ReportsOnly: true},
	}
	if got := ComputeStructuredExtractionStatus(mixed); got != domain.StructuredExtractionMixed {
		t.Fatalf("mixed = %q", got)
	}
}
