package query

import (
	"context"
	"strings"

	"github.com/irootkernel/mulgae/internal/app/recovery"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

const retiredProviderArtifactReason = "retired_provider_artifact"

func retiredProviderInstance(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	for _, family := range []string{"kimi", "agy"} {
		if value == family {
			return true
		}
		for _, separator := range []string{"-", ".", "_", "#", "/"} {
			if strings.HasPrefix(value, family+separator) {
				return true
			}
		}
	}
	return false
}

func finalRecordRetired(final finalDTO, manifest manifestDTO) bool {
	if final.Provenance.Production != nil {
		for _, provider := range final.Provenance.Production.Providers {
			if retiredProviderInstance(provider.Family) || retiredProviderInstance(provider.Instance) {
				return true
			}
		}
	}
	for _, attempt := range manifest.Attempts {
		if retiredProviderInstance(attempt.ProviderInstance) {
			return true
		}
	}
	for _, report := range manifest.RoleReports {
		if retiredProviderInstance(report.ProviderInstance) {
			return true
		}
	}
	return false
}

func (service *Service) committedArtifactRetired(ctx context.Context, run ports.PublicationRun, review CommittedReview, seen map[string]struct{}) (bool, error) {
	key := run.RunID().String()
	if _, duplicate := seen[key]; duplicate {
		return false, nil
	}
	seen[key] = struct{}{}
	for _, role := range review.Roles() {
		if provider, present := role.ProviderInstance(); present && retiredProviderInstance(provider) {
			return true, nil
		}
	}
	for _, attempt := range review.Attempts() {
		if retiredProviderInstance(attempt.ProviderInstance()) {
			return true, nil
		}
	}
	for _, report := range review.RoleReports() {
		if retiredProviderInstance(report.ProviderInstance()) {
			return true, nil
		}
	}

	if review.compositeSupport != nil {
		for _, source := range review.compositeSupport.Sources {
			for _, provider := range source.ProviderIdentities {
				if retiredProviderInstance(provider) {
					return true, nil
				}
			}
		}
		return false, nil
	}
	if review.RunType() == domain.RunTypeComposite {
		var final compositeFinalDTO
		if err := decodeStrictDTO(review.FinalBytes(), &final); err != nil {
			return false, typedFailure(readCommittedStage, domain.FailureArtifact, "committed composite final decode failed", err)
		}
		for _, source := range final.ReviewComposition.Sources {
			retired, err := service.sourceArtifactRetired(ctx, run.Root(), source.RunID, source.Kind, seen)
			if err != nil || retired {
				return retired, err
			}
		}
		return service.sourceArtifactRetired(ctx, run.Root(), final.ReviewComposition.RootRunID, final.ReviewComposition.RootSourceKind, seen)
	}

	var final finalDTO
	if err := decodeStrictDTO(review.FinalBytes(), &final); err != nil {
		return false, typedFailure(readCommittedStage, domain.FailureArtifact, "committed final decode failed", err)
	}
	if final.Provenance.Production != nil {
		for _, provider := range final.Provenance.Production.Providers {
			if retiredProviderInstance(provider.Family) || retiredProviderInstance(provider.Instance) {
				return true, nil
			}
		}
	}
	if final.ImmutableLineage.SourceRunID != nil {
		return service.sourceArtifactRetired(ctx, run.Root(), *final.ImmutableLineage.SourceRunID, final.ImmutableLineage.SourceKind, seen)
	}
	return false, nil
}

func (service *Service) sourceArtifactRetired(ctx context.Context, root ports.AnchoredRoot, rawRunID, kind string, seen map[string]struct{}) (bool, error) {
	runID, err := domain.ParseRunID(rawRunID)
	if err != nil {
		return false, typedFailure(readCommittedStage, domain.FailureArtifact, "retirement lineage run identity is invalid", err)
	}
	run, err := service.ResolveRun(ctx, root, runID)
	if err != nil {
		// Retirement adds no new corruption classification. Existing lineage
		// verification remains authoritative when a source cannot be resolved;
		// this predicate only inspects sources that resolve in the current store.
		return false, nil
	}
	if kind == "failed_run_recovery" {
		snapshot, err := recovery.Read(ctx, service.store, service.validator, run, service.maxReadBytes)
		if err != nil {
			return false, err
		}
		return service.recoveryArtifactRetired(ctx, run, snapshot, seen)
	}
	review, err := service.readCommittedUnfiltered(ctx, run)
	if err != nil {
		return false, err
	}
	return service.committedArtifactRetired(ctx, run, review, seen)
}

func (service *Service) recoveryArtifactRetired(ctx context.Context, run ports.PublicationRun, snapshot recovery.Snapshot, seen map[string]struct{}) (bool, error) {
	key := run.RunID().String()
	if _, duplicate := seen[key]; duplicate {
		return false, nil
	}
	seen[key] = struct{}{}
	document := snapshot.Document()
	for _, attempt := range document.Attempts {
		if retiredProviderInstance(attempt.ProviderInstance) {
			return true, nil
		}
	}
	for _, role := range document.Roles {
		if retiredProviderInstance(role.ProviderInstance) {
			return true, nil
		}
	}
	for _, finding := range document.Findings {
		if retiredProviderInstance(finding.ProviderInstance) {
			return true, nil
		}
	}
	if document.Source != nil {
		return service.sourceArtifactRetired(ctx, run.Root(), document.Source.RunID, document.Source.Kind, seen)
	}
	return false, nil
}
