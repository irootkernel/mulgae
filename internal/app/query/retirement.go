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
	return providerInstanceRetired(value, false)
}

func providerInstanceRetired(value string, _ bool) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	for _, family := range []string{"kimi", "cursor", "codex", "agy"} {
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
	_, bindingErr := validateLivePublicationBinding(final, manifest)
	retired := func(value string) bool { return providerInstanceRetired(value, bindingErr == nil) }
	if final.Provenance.LiveProduction != nil {
		for _, provider := range final.Provenance.LiveProduction.Providers {
			if retired(provider.Family) || retired(provider.Instance) {
				return true
			}
		}
	}
	if final.Provenance.Production != nil {
		for _, provider := range final.Provenance.Production.Providers {
			if retired(provider.Family) || retired(provider.Instance) {
				return true
			}
		}
	}
	for _, attempt := range manifest.Attempts {
		if retired(attempt.ProviderInstance) {
			return true
		}
	}
	for _, report := range manifest.RoleReports {
		if retired(report.ProviderInstance) {
			return true
		}
	}
	return false
}

func (context *readContext) committedRetired(ctx context.Context, node *contextRun) (bool, error) {
	if node.retireChecked {
		return node.retired, nil
	}
	node.retireChecked = true
	run, review := node.run, node.review
	retired := func(value string) bool { return providerInstanceRetired(value, review.liveSource != nil) }
	for _, role := range review.Roles() {
		if provider, present := role.ProviderInstance(); present && retired(provider) {
			node.retired = true
			return true, nil
		}
	}
	for _, attempt := range review.Attempts() {
		if retired(attempt.ProviderInstance()) {
			node.retired = true
			return true, nil
		}
	}
	for _, report := range review.RoleReports() {
		if retired(report.ProviderInstance()) {
			node.retired = true
			return true, nil
		}
	}

	if review.compositeSupport != nil {
		for _, source := range review.compositeSupport.Sources {
			for _, provider := range source.ProviderIdentities {
				if retiredProviderInstance(provider) {
					node.retired = true
					return true, nil
				}
			}
		}
		return false, nil
	}
	previousWalking := context.walking
	context.walking = node
	defer func() { context.walking = previousWalking }()
	if review.RunType() == domain.RunTypeComposite {
		var final compositeFinalDTO
		if err := decodeStrictDTO(review.FinalBytes(), &final); err != nil {
			return false, typedFailure(readCommittedStage, domain.FailureArtifact, "committed composite final decode failed", err)
		}
		for _, source := range final.ReviewComposition.Sources {
			retired, err := context.sourceRetired(ctx, run.Root(), source.RunID, source.Kind)
			if err != nil || retired {
				node.retired = retired
				return retired, err
			}
		}
		retired, err := context.sourceRetired(ctx, run.Root(), final.ReviewComposition.RootRunID, final.ReviewComposition.RootSourceKind)
		node.retired = retired
		return retired, err
	}

	var final finalDTO
	if err := decodeStrictDTO(review.FinalBytes(), &final); err != nil {
		return false, typedFailure(readCommittedStage, domain.FailureArtifact, "committed final decode failed", err)
	}
	if final.Provenance.LiveProduction != nil {
		for _, provider := range final.Provenance.LiveProduction.Providers {
			if retired(provider.Family) || retired(provider.Instance) {
				node.retired = true
				return true, nil
			}
		}
	}
	if final.Provenance.Production != nil {
		for _, provider := range final.Provenance.Production.Providers {
			if retired(provider.Family) || retired(provider.Instance) {
				node.retired = true
				return true, nil
			}
		}
	}
	if final.ImmutableLineage.SourceRunID != nil {
		retired, err := context.sourceRetired(ctx, run.Root(), *final.ImmutableLineage.SourceRunID, final.ImmutableLineage.SourceKind)
		node.retired = retired
		return retired, err
	}
	return false, nil
}

func (context *readContext) sourceRetired(ctx context.Context, root ports.AnchoredRoot, rawRunID, kind string) (bool, error) {
	runID, err := domain.ParseRunID(rawRunID)
	if err != nil {
		return false, typedFailure(readCommittedStage, domain.FailureArtifact, "retirement lineage run identity is invalid", err)
	}
	if node, consumed := context.byRun[runID.String()]; consumed && kind != "failed_run_recovery" {
		if context.walking != nil && !containsRun(context.walking.deps, node) {
			context.walking.deps = append(context.walking.deps, node)
		}
		return context.committedRetired(ctx, node)
	}
	run, err := context.service.ResolveRun(ctx, root, runID)
	if err != nil {
		// Retirement adds no new corruption classification. Existing lineage
		// verification remains authoritative when a source cannot be resolved;
		// this predicate only inspects sources that resolve in the current store.
		return false, nil
	}
	if kind == "failed_run_recovery" {
		snapshot, err := recovery.Read(ctx, context.service.store, context.service.validator, run, context.service.maxReadBytes)
		if err != nil {
			return false, err
		}
		return context.recoveryRetired(ctx, run, snapshot)
	}
	node, err := context.snapshotReview(ctx, run, readCommittedStage)
	if err != nil {
		return false, err
	}
	return context.committedRetired(ctx, node)
}

func (context *readContext) recoveryRetired(ctx context.Context, run ports.PublicationRun, snapshot recovery.Snapshot) (bool, error) {
	key := run.RunID().String()
	if context.recoverySeen == nil {
		context.recoverySeen = map[string]struct{}{}
	}
	if _, duplicate := context.recoverySeen[key]; duplicate {
		return false, nil
	}
	context.recoverySeen[key] = struct{}{}
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
		return context.sourceRetired(ctx, run.Root(), document.Source.RunID, document.Source.Kind)
	}
	return false, nil
}

func containsRun(nodes []*contextRun, node *contextRun) bool {
	for _, candidate := range nodes {
		if candidate == node {
			return true
		}
	}
	return false
}
