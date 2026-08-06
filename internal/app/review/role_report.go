package review

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/irootkernel/mulgae/internal/app/validation"
	"github.com/irootkernel/mulgae/internal/domain"
)

// maxRoleReportBytes bounds Mulgae-owned free-form role report bodies. It matches
// the existing report-command markdown cap so publication stays fail-closed.
const maxRoleReportBytes = 8 << 20

// NewReportsOnlyValidatedRoleOutput accepts one bounded free-form role report
// without a validated structured finding document. Provider prose remains
// untrusted content; Mulgae owns identity and publication.
func NewReportsOnlyValidatedRoleOutput(
	role domain.Role,
	providerInstance string,
	target domain.TargetIdentity,
	reportMarkdown []byte,
) (ValidatedRoleOutput, error) {
	canonicalTarget, err := canonicalCoordinatorTarget(target)
	if err != nil {
		return ValidatedRoleOutput{}, err
	}
	report, err := normalizeRoleReportMarkdown(reportMarkdown)
	if err != nil {
		return ValidatedRoleOutput{}, fmt.Errorf("review coordinator role output: %w", err)
	}
	output := ValidatedRoleOutput{
		role:             role,
		providerInstance: providerInstance,
		target:           canonicalTarget,
		completeness:     "complete",
		limitations:      nil,
		reportMarkdown:   report,
		reportsOnly:      true,
		parseState:       domain.ParseNotStarted,
		validationState:  domain.ValidationNotStarted,
	}
	if err := output.validate(); err != nil {
		return ValidatedRoleOutput{}, err
	}
	return output, nil
}

// ReportMarkdown returns a caller-owned copy of the Mulgae-owned role report body.
func (output ValidatedRoleOutput) ReportMarkdown() []byte {
	return append([]byte(nil), output.reportMarkdown...)
}

// ReportsOnly reports whether the role delivered a free-form report without a
// validated structured finding document.
func (output ValidatedRoleOutput) ReportsOnly() bool { return output.reportsOnly }

// ParseState returns Mulgae-owned parse coverage for the accepted attempt.
func (output ValidatedRoleOutput) ParseState() domain.ParseState { return output.parseState }

// ValidationState returns Mulgae-owned validation coverage for the accepted attempt.
func (output ValidatedRoleOutput) ValidationState() domain.ValidationState {
	return output.validationState
}

func (output *ValidatedRoleOutput) bindReportMarkdown(report []byte, reportsOnly bool) error {
	normalized, err := normalizeRoleReportMarkdown(report)
	if err != nil {
		return err
	}
	output.reportMarkdown = normalized
	output.reportsOnly = reportsOnly
	return nil
}

func (output *ValidatedRoleOutput) bindExtractionStates(parse domain.ParseState, validation domain.ValidationState) error {
	if !parse.Valid() || !validation.Valid() {
		return fmt.Errorf("invalid extraction states")
	}
	output.parseState = parse
	output.validationState = validation
	return nil
}

func normalizeRoleReportMarkdown(report []byte) ([]byte, error) {
	if len(report) == 0 {
		return nil, fmt.Errorf("role report is empty")
	}
	if len(report) > maxRoleReportBytes {
		return nil, fmt.Errorf("role report exceeds %d bytes", maxRoleReportBytes)
	}
	if !utf8.Valid(report) {
		return nil, fmt.Errorf("role report is not valid UTF-8")
	}
	if len(strings.TrimSpace(string(report))) == 0 {
		return nil, fmt.Errorf("role report is whitespace-only")
	}
	return append([]byte(nil), report...), nil
}

// deriveStructuredRoleReport synthesizes Markdown only when no provider
// assistant content exists. Production structured accepts must preserve the
// full adapter-extracted assistant content instead.
func deriveStructuredRoleReport(role domain.Role, review validation.ValidatedReview) ([]byte, error) {
	var builder strings.Builder
	builder.WriteString("# ")
	builder.WriteString(string(role))
	builder.WriteString(" review\n\n")
	summary := strings.TrimSpace(review.Summary())
	if summary == "" {
		summary = "Structured provider review accepted."
	}
	builder.WriteString(summary)
	builder.WriteByte('\n')
	findings := review.Findings()
	if len(findings) > 0 {
		builder.WriteString("\n## Findings\n")
		for index, finding := range findings {
			builder.WriteString(fmt.Sprintf("\n### %d. %s (%s)\n\n", index+1, finding.Title(), finding.Severity()))
			builder.WriteString(strings.TrimSpace(finding.Description()))
			builder.WriteByte('\n')
			if recommendation := strings.TrimSpace(finding.Recommendation()); recommendation != "" {
				builder.WriteString("\n**Recommendation:** ")
				builder.WriteString(recommendation)
				builder.WriteByte('\n')
			}
		}
	}
	if limitations := review.Limitations(); len(limitations) > 0 {
		builder.WriteString("\n## Limitations\n")
		for _, limitation := range limitations {
			builder.WriteString("- ")
			builder.WriteString(limitation)
			builder.WriteByte('\n')
		}
	}
	return normalizeRoleReportMarkdown([]byte(builder.String()))
}

// ComputeStructuredExtractionStatus derives Mulgae-owned structured-extraction
// coverage across selected role summaries.
func ComputeStructuredExtractionStatus(results []domain.RoleResultSummary) domain.StructuredExtractionStatus {
	return domain.ComputeStructuredExtractionStatus(results)
}
