package report

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/irootkernel/mulgae/internal/app/query"
	"github.com/irootkernel/mulgae/internal/app/validation"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

func renderRequirements(ctx context.Context, output *strings.Builder, reader CommittedReader, run ports.PublicationRun, review query.CommittedReview) error {
	evaluation := review.RequirementsEvaluation()
	writeHeading(output, "Requirements assessment")
	writeField(output, "Availability", string(evaluation.Availability()))
	selected, evaluated, known := evaluation.Counts()
	if known {
		writeField(output, "Selected requirements", fmt.Sprint(selected))
		writeField(output, "Admitted provider assessments", fmt.Sprint(evaluated))
	} else {
		writeField(output, "Selected requirements", "unavailable")
		writeField(output, "Admitted provider assessments", "unavailable")
	}
	rows := evaluation.Assessments()
	unmet, unverified := 0, 0
	for _, row := range rows {
		if row.Verdict() == domain.RequirementUnmet {
			unmet++
		}
		if row.Verdict() == domain.RequirementUnverified {
			unverified++
		}
	}
	if len(rows) > 0 {
		writeField(output, "Unmet requirements", fmt.Sprint(unmet))
		writeField(output, "Unverified requirements", fmt.Sprint(unverified))
		writeText(output, "Assessment responses do not change finding severity, operational exits or acceptance authority.")
	}
	writeBlankLine(output)
	for _, row := range rows {
		if err := reportContextFailure(ctx); err != nil {
			return err
		}
		contentReader, ok := reader.(query.RequirementContentReader)
		if !ok {
			return reportFailure(domain.FailureArtifact, "verified requirement content reader is unavailable", nil)
		}
		raw, err := contentReader.ReadRequirementContent(ctx, run, row.RequirementID())
		if err != nil {
			return err
		}
		var content validation.RequirementContent
		if err := json.Unmarshal(raw, &content); err != nil {
			return reportFailure(domain.FailureArtifact, "verified requirement content is invalid", err)
		}
		writeSubheading(output, row.RequirementID()+" — "+string(row.Verdict()))
		writeField(output, "Owner role", string(row.OwnerRole()))
		writeField(output, "Origin", string(row.Origin()))
		writeField(output, "Reason", string(row.Reason()))
		writeTextBlock(output, "Rationale", content.Rationale)
		writeTextBlock(output, "Examined scope", content.ExaminedScope)
		for _, limitation := range content.Limitations {
			writeTextBlock(output, "Limitation", limitation)
		}
		for _, item := range content.Evidence {
			current := item.Current
			writeField(output, "Evidence source selection SHA-256", current.SourceIdentitySHA256)
			writeField(output, "Evidence side", string(current.Side))
			writeField(output, "Evidence path", current.Path)
			writeField(output, "Evidence lines", fmt.Sprintf("%d-%d", current.LineStart, current.LineEnd))
			writeField(output, "Evidence excerpt SHA-256", current.CurrentExcerptSHA256)
			writeField(output, "Evidence verification", current.Verification)
			writeVerifiedExcerpt(output, []byte(current.Quote))
			if item.Visual != nil {
				writeField(output, "Visual path", item.Visual.Path)
				writeField(output, "Visual SHA-256", item.Visual.SHA256)
				writeField(output, "Visual region", fmt.Sprintf("%d,%d %dx%d", item.Visual.BBox.X, item.Visual.BBox.Y, item.Visual.BBox.Width, item.Visual.BBox.Height))
			}
		}
		writeBlankLine(output)
	}
	return nil
}
