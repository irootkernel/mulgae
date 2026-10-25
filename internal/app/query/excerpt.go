package query

import (
	"bytes"
	"context"
	"fmt"

	"github.com/irootkernel/mulgae/internal/app/evidence"
	"github.com/irootkernel/mulgae/internal/artifactwire"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

// ReadCommittedFindingSource rereads the final and manifest, then exposes only
// normalized finding and excerpt artifacts whose exact identities are bound by
// the manifest support index for one stable P2 finding.
func (service *Service) ReadCommittedFindingSource(ctx context.Context, run ports.PublicationRun, findingID string) (CommittedFindingSource, error) {
	if err := service.preflight(ctx, renderExcerptStage); err != nil {
		return CommittedFindingSource{}, err
	}
	if !validFindingID(findingID) {
		return CommittedFindingSource{}, typedFailure(renderExcerptStage, domain.FailureConfiguration, "finding ID is invalid", nil)
	}
	context := service.newReadContext()
	node, err := context.readCommitted(ctx, run, renderExcerptStage)
	if err != nil {
		return CommittedFindingSource{}, err
	}
	review := node.review
	var finding Finding
	for _, candidate := range review.Findings() {
		if candidate.ID() == findingID {
			finding = candidate
			break
		}
	}
	if finding.ID() == "" {
		return CommittedFindingSource{}, typedFailure(renderExcerptStage, domain.FailureArtifact, "finding is not bound to the requested run", nil)
	}
	normalizedPath, err := ports.NewSafeRelativePath(artifactwire.RunPath(run.SessionID().String(), run.RunID().String(), "excerpts/"+artifactwire.FindingName(findingID)))
	if err != nil {
		return CommittedFindingSource{}, typedFailure(renderExcerptStage, domain.FailureArtifact, "normalized finding artifact path is invalid", err)
	}
	if _, err := context.supportIndex(ctx, node, node.review); err != nil {
		return CommittedFindingSource{}, err
	}
	normalized, err := context.indexedArtifact(ctx, node, normalizedPath)
	if err != nil {
		return CommittedFindingSource{}, err
	}
	if len(normalized.Bytes()) == 0 {
		return CommittedFindingSource{}, typedFailure(renderExcerptStage, domain.FailureArtifact, "normalized finding artifact is invalid", nil)
	}
	claims := finding.Evidence()
	if len(claims) == 0 {
		return CommittedFindingSource{}, typedFailure(renderExcerptStage, domain.FailureArtifact, "finding has no committed current evidence", nil)
	}
	var excerpt []byte
	for evidenceIndex, current := range claims {
		persisted, readErr := context.readCommittedFindingExcerpt(ctx, node, findingID, evidenceIndex+1, current)
		if readErr != nil {
			return CommittedFindingSource{}, readErr
		}
		if evidenceIndex == 0 {
			excerpt = persisted
		}
	}
	if err := context.finish(ctx); err != nil {
		return CommittedFindingSource{}, err
	}
	return CommittedFindingSource{review: review, finding: finding, normalized: normalized.Bytes(), excerpt: excerpt}, nil
}

func (context *readContext) readCommittedFindingExcerpt(
	ctx context.Context,
	node *contextRun,
	findingID string,
	evidenceIndex int,
	current Evidence,
) ([]byte, error) {
	run, review := node.run, node.review
	if current.TargetSHA256() != review.TargetSHA256() || current.Verification() != evidence.ReceiptVerified {
		return nil, typedFailure(renderExcerptStage, domain.FailureArtifact, "finding current evidence is not bound to the committed target", nil)
	}
	var claim evidence.CurrentClaim
	var err error
	if review.liveSource != nil {
		if current.SourceIdentitySHA256() != review.SourceIdentitySHA256() || current.TargetSHA256() != "" {
			return nil, typedFailure(renderExcerptStage, domain.FailureArtifact, "finding source evidence identity mismatch", nil)
		}
		claim, err = evidence.NewLiveClaim(review.liveSource.Identity, current.Side(), current.Path().String(), current.LineStart(), current.LineEnd(), current.quote)
	} else {
		claim, err = evidence.NewCurrentClaim(evidence.CurrentClaimInput{
			TargetSHA256: current.TargetSHA256(), Side: current.Side(), Path: current.Path().String(),
			LineStart: current.LineStart(), LineEnd: current.LineEnd(), Quote: current.quote,
		})
	}
	if err != nil {
		return nil, typedFailure(renderExcerptStage, domain.FailureArtifact, "committed current evidence is invalid", err)
	}
	path, err := excerptArtifactPath(run, findingID, evidenceIndex)
	if err != nil {
		return nil, typedFailure(renderExcerptStage, domain.FailureArtifact, "committed excerpt artifact path is invalid", err)
	}
	artifact, err := context.indexedArtifact(ctx, node, path)
	if err != nil {
		return nil, err
	}
	return context.service.verifyPersistedExcerpt(ctx, claim, current.CurrentExcerptSHA256(), path, artifact)
}

// RenderExcerpt returns the first canonical committed evidence excerpt. Callers
// rendering multiple items must use RenderExcerptAt with its one-based index.
func (service *Service) RenderExcerpt(
	ctx context.Context,
	run ports.PublicationRun,
	findingID string,
	targetSHA256 string,
) ([]byte, error) {
	return service.RenderExcerptAt(ctx, run, findingID, targetSHA256, 1)
}

// RenderExcerptAt returns one canonical committed evidence excerpt by its
// one-based canonical index.
func (service *Service) RenderExcerptAt(
	ctx context.Context,
	run ports.PublicationRun,
	findingID string,
	targetSHA256 string,
	evidenceIndex int,
) ([]byte, error) {
	if err := service.preflight(ctx, renderExcerptStage); err != nil {
		return nil, err
	}
	if !validFindingID(findingID) {
		return nil, typedFailure(
			renderExcerptStage,
			domain.FailureConfiguration,
			"finding ID is invalid",
			nil,
		)
	}
	if evidenceIndex < 1 || evidenceIndex > 20 {
		return nil, typedFailure(
			renderExcerptStage,
			domain.FailureConfiguration,
			"evidence index is invalid",
			nil,
		)
	}
	canonicalTarget, ok := canonicalSHA256(targetSHA256)
	if !ok && targetSHA256 != "" {
		return nil, typedFailure(
			renderExcerptStage,
			domain.FailureConfiguration,
			"target SHA-256 is invalid",
			nil,
		)
	}
	context := service.newReadContext()
	node, err := context.readCommitted(ctx, run, renderExcerptStage)
	if err != nil {
		return nil, err
	}
	persisted, err := context.renderExcerptAt(ctx, node, findingID, canonicalTarget, evidenceIndex)
	if err != nil {
		return nil, err
	}
	if err := context.finish(ctx); err != nil {
		return nil, err
	}
	return persisted, nil
}

// renderExcerptAt is the public excerpt core over one verified context: live
// evidence serves through the verified support index while historical
// evidence keeps its claim-verified direct read.
func (context *readContext) renderExcerptAt(ctx context.Context, node *contextRun, findingID, canonicalTarget string, evidenceIndex int) ([]byte, error) {
	run, review := node.run, node.review
	var finding Finding
	found := false
	for _, candidate := range review.Findings() {
		if candidate.ID() == findingID {
			finding = candidate
			found = true
			break
		}
	}
	if !found {
		return nil, typedFailure(
			renderExcerptStage,
			domain.FailureArtifact,
			"finding is not bound to the requested run",
			nil,
		)
	}
	if canonicalTarget != review.TargetSHA256() {
		return nil, typedFailure(
			renderExcerptStage,
			domain.FailureConfiguration,
			"target SHA-256 does not match the committed finding",
			nil,
		)
	}
	claims := finding.Evidence()
	if evidenceIndex > len(claims) {
		return nil, typedFailure(
			renderExcerptStage,
			domain.FailureConfiguration,
			"evidence index is not bound to the committed finding",
			nil,
		)
	}
	current := claims[evidenceIndex-1]
	if review.liveSource != nil {
		if _, err := context.supportIndex(ctx, node, node.review); err != nil {
			return nil, err
		}
		return context.readCommittedFindingExcerpt(ctx, node, findingID, evidenceIndex, current)
	}
	if current.TargetSHA256() != canonicalTarget || current.Verification() != evidence.ReceiptVerified {
		return nil, typedFailure(
			renderExcerptStage,
			domain.FailureArtifact,
			"finding current evidence is not bound to the committed target",
			nil,
		)
	}
	claim, err := evidence.NewCurrentClaim(evidence.CurrentClaimInput{
		TargetSHA256: current.TargetSHA256(),
		Side:         current.Side(),
		Path:         current.Path().String(),
		LineStart:    current.LineStart(),
		LineEnd:      current.LineEnd(),
		Quote:        current.quote,
	})
	if err != nil {
		return nil, typedFailure(
			renderExcerptStage,
			domain.FailureArtifact,
			"committed current evidence is invalid",
			err,
		)
	}
	if err := contextFailure(ctx, renderExcerptStage); err != nil {
		return nil, err
	}
	artifactPath, err := excerptArtifactPath(run, findingID, evidenceIndex)
	if err != nil {
		return nil, typedFailure(
			renderExcerptStage,
			domain.FailureArtifact,
			"committed excerpt artifact path is invalid",
			err,
		)
	}
	request, err := ports.NewReadAuxiliaryArtifactRequest(run, artifactPath, "", context.service.maxReadBytes)
	if err != nil {
		return nil, typedFailure(
			renderExcerptStage,
			domain.FailureArtifact,
			"committed excerpt artifact request is invalid",
			err,
		)
	}
	artifact, err := context.service.store.ReadAuxiliaryArtifact(ctx, request)
	if err != nil {
		return nil, dependencyFailure(
			ctx,
			renderExcerptStage,
			domain.FailureArtifact,
			"committed excerpt artifact read failed",
			err,
		)
	}
	return context.service.verifyPersistedExcerpt(ctx, claim, current.CurrentExcerptSHA256(), artifactPath, artifact)
}

func (service *Service) verifyPersistedExcerpt(
	ctx context.Context,
	claim evidence.CurrentClaim,
	currentExcerptSHA256 string,
	expectedPath ports.SafeRelativePath,
	artifact ports.ImmutablePublicationArtifact,
) ([]byte, error) {
	if !artifact.Valid() {
		return nil, typedFailure(
			renderExcerptStage,
			domain.FailureArtifact,
			"committed excerpt artifact is invalid",
			nil,
		)
	}
	if artifact.Path() != expectedPath {
		return nil, typedFailure(
			renderExcerptStage,
			domain.FailureArtifact,
			"committed excerpt artifact path does not match the finding",
			nil,
		)
	}
	artifactBytes := artifact.Bytes()
	if claim.IsLiveSource() {
		digest, err := claim.ExcerptSHA256(artifactBytes)
		lines := bytes.Count(artifactBytes, []byte{'\n'})
		if len(artifactBytes) != 0 && artifactBytes[len(artifactBytes)-1] != '\n' {
			lines++
		}
		if err != nil || digest != currentExcerptSHA256 || !bytes.Equal(artifactBytes, []byte(claim.Quote())) || lines != claim.LineEnd()-claim.LineStart()+1 {
			return nil, typedFailure(renderExcerptStage, domain.FailureArtifact, "stored source excerpt is inconsistent", err)
		}
		return artifactBytes, nil
	}
	targetBytes, err := syntheticExcerptLayout(claim.LineStart(), artifactBytes, service.maxReadBytes)
	if err != nil {
		return nil, typedFailure(
			renderExcerptStage,
			domain.FailureArtifact,
			"committed excerpt artifact cannot satisfy the committed range",
			err,
		)
	}
	verifier, err := evidence.NewVerifier(persistedExcerptReader{
		targetSHA256: claim.TargetSHA256(),
		side:         claim.Side(),
		path:         claim.Path(),
		bytes:        targetBytes,
	})
	if err != nil {
		return nil, typedFailure(
			renderExcerptStage,
			domain.FailureArtifact,
			"committed excerpt verifier is unavailable",
			err,
		)
	}
	receipt, err := verifier.VerifyCurrent(ctx, claim)
	if err != nil {
		return nil, dependencyFailure(
			ctx,
			renderExcerptStage,
			domain.FailureArtifact,
			"committed excerpt artifact verification failed",
			err,
		)
	}
	if receipt.Status() != evidence.ReceiptVerified {
		return nil, typedFailure(
			renderExcerptStage,
			domain.FailureArtifact,
			"committed excerpt artifact does not match the finding",
			nil,
		)
	}
	verifiedExcerpt := receipt.Excerpt()
	if !bytes.Equal(verifiedExcerpt, artifactBytes) {
		return nil, typedFailure(
			renderExcerptStage,
			domain.FailureArtifact,
			"committed excerpt artifact bytes do not match the finding",
			nil,
		)
	}
	if receipt.ExcerptSHA256() != currentExcerptSHA256 {
		return nil, typedFailure(
			renderExcerptStage,
			domain.FailureArtifact,
			"committed excerpt artifact does not match the current excerpt identity",
			nil,
		)
	}
	return verifiedExcerpt, nil
}

func excerptArtifactPath(
	run ports.PublicationRun,
	findingID string,
	evidenceIndex int,
) (ports.SafeRelativePath, error) {
	return ports.NewSafeRelativePath(
		artifactwire.RunPath(run.SessionID().String(), run.RunID().String(), "excerpts/"+artifactwire.EvidenceExcerptName(findingID, evidenceIndex)),
	)
}

func syntheticExcerptLayout(lineStart int, excerpt []byte, maxReadBytes int64) ([]byte, error) {
	if lineStart <= 0 {
		return nil, fmt.Errorf("line start is invalid")
	}
	prefixLength := lineStart - 1
	excerptLength := int64(len(excerpt))
	if excerptLength > maxReadBytes || int64(prefixLength) > maxReadBytes-excerptLength {
		return nil, fmt.Errorf("synthetic excerpt layout exceeds read cap")
	}
	maxInt := int(^uint(0) >> 1)
	if prefixLength > maxInt-len(excerpt) {
		return nil, fmt.Errorf("synthetic excerpt layout overflows")
	}
	target := make([]byte, prefixLength+len(excerpt))
	for index := 0; index < prefixLength; index++ {
		target[index] = '\n'
	}
	copy(target[prefixLength:], excerpt)
	return target, nil
}

type persistedExcerptReader struct {
	targetSHA256 string
	side         evidence.Side
	path         ports.SafeRelativePath
	bytes        []byte
}

func (reader persistedExcerptReader) ReadImmutableTarget(
	_ context.Context,
	targetSHA256 string,
	side evidence.Side,
	path ports.SafeRelativePath,
) (evidence.ImmutableTargetAvailability, []byte, error) {
	if targetSHA256 != reader.targetSHA256 || side != reader.side || path != reader.path {
		return evidence.ImmutableTargetUnavailable, nil, nil
	}
	return evidence.ImmutableTargetAvailable, cloneBytes(reader.bytes), nil
}
