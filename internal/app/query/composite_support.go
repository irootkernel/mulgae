package query

import (
	"context"
	"fmt"
	"math"
	"strings"

	"github.com/irootkernel/mulgae/internal/app/compositesupport"
	"github.com/irootkernel/mulgae/internal/app/evidence"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

func (service *Service) bindCompositeSupport(ctx context.Context, run ports.PublicationRun, review CommittedReview) (CommittedReview, error) {
	index, err := service.readRuntimeSupportIndex(ctx, run, review)
	if err != nil {
		return review, err
	}
	prefix := run.SessionID().String() + "/" + run.RunID().String() + "/"
	if _, ok := index[prefix+compositesupport.DocumentPath]; !ok {
		return review, nil
	}
	artifacts := map[string]ports.ImmutablePublicationArtifact{}
	for name, digest := range index {
		relative := strings.TrimPrefix(name, prefix)
		if relative != compositesupport.DocumentPath && !strings.HasPrefix(relative, "support/sources/") && !strings.HasPrefix(relative, "support/findings/") && !strings.HasPrefix(relative, "excerpts/") {
			continue
		}
		path, err := ports.NewSafeRelativePath(name)
		if err != nil {
			return review, err
		}
		kind, err := ports.ClassifyRunSupportArtifactPath(run.SessionID(), run.RunID(), path)
		if err != nil {
			return review, err
		}
		maximum := service.maxReadBytes
		if kind.IsVariableSized() {
			maximum = math.MaxInt64 - 1
		}
		artifact, err := service.readBoundRuntimeArtifactWithMaximum(ctx, run, review, path, digest, maximum)
		if err != nil {
			return review, err
		}
		artifacts[name] = artifact
	}
	doc, err := compositesupport.Verify(run.SessionID(), run.RunID(), review.TargetSHA256(), artifacts)
	if err != nil {
		return review, typedFailure(readCommittedStage, domain.FailureArtifact, "composite support invalid", err)
	}
	if err := compositesupport.VerifyFinal(doc, run.SessionID(), run.RunID(), review.FinalBytes(), artifacts); err != nil {
		return review, typedFailure(readCommittedStage, domain.FailureArtifact, "composite source binding invalid", err)
	}
	sources := map[domain.Role]compositesupport.Source{}
	for _, s := range doc.Sources {
		sources[s.Role] = s
	}
	byID := map[string]compositesupport.Finding{}
	for _, f := range doc.Findings {
		byID[f.ID] = f
	}
	for i := range review.findings {
		f := &review.findings[i]
		copied, ok := byID[f.id]
		if !ok {
			return review, fmt.Errorf("composite finding support absent")
		}
		source := sources[f.role]
		session, _ := domain.ParseSessionID(source.SessionID)
		sourceRun, _ := domain.ParseRunID(source.RunID)
		sourceReview, _ := domain.ParseReviewID(source.ReviewID)
		for _, e := range copied.Evidence {
			path, err := ports.NewSafeRelativePath(e.Path)
			if err != nil {
				return review, err
			}
			current := Evidence{sourceSessionID: session, sourceRunID: sourceRun, sourceReviewID: sourceReview, sourceFindingID: copied.SourceFindingID, sourceTargetSHA256: e.TargetSHA256, sourceExcerptSHA256: e.ExcerptSHA256, targetSHA256: e.TargetSHA256, currentExcerptSHA256: e.ExcerptSHA256, side: e.Side, path: path, lineStart: e.LineStart, lineEnd: e.LineEnd, verification: evidence.ReceiptUnverifiable, copiedAvailability: e.Availability}
			if e.Availability == "verified" {
				current.verification = evidence.ReceiptVerified
				current.quote = string(artifacts[prefix+compositesupport.ExcerptPath(f.id, e.Index)].Bytes())
			}
			f.evidence = append(f.evidence, current)
		}
	}
	review.compositeSupport = &doc
	review.compositeArtifacts = artifacts
	return review, nil
}
