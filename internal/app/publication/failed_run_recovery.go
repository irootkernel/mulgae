package publication

import (
	"context"
	"fmt"
	"strings"

	"github.com/irootkernel/mulgae/internal/app/recovery"
	"github.com/irootkernel/mulgae/internal/app/review"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

// FailedRunRecoveryCommitter seals a separately validated failed-run snapshot
// only after real workspace cleanup. It does not accept a final-review candidate.
type FailedRunRecoveryCommitter interface {
	PersistFailedRunRecovery(context.Context, ports.AnchoredRoot, recovery.Prepared, ports.WorkspaceTerminalReceipt) (domain.SourceReference, error)
}

// PrepareFailedRunRecovery retains complete original inputs and only accepted,
// evidence-verified role output. Final publication's forbidden classes remain
// unchanged; security, configuration, and artifact failures also forbid recovery.
func PrepareFailedRunRecovery(ctx context.Context, result review.CoordinatorResult, target domain.TargetIdentity, threshold domain.Severity, snapshotSHA256 string, lineage RunPublicationContext, initial []review.RuntimeArtifactInventory) (recovery.Prepared, error) {
	if err := ctx.Err(); err != nil {
		return recovery.Prepared{}, err
	}
	if err := lineage.validate(); err != nil {
		return recovery.Prepared{}, err
	}
	document := recovery.Document{SessionID: result.SessionID().String(), RunID: result.RunID().String(), RunType: domain.RunTypeReview, RunState: result.RunState(), Threshold: threshold, SnapshotManifestSHA256: snapshotSHA256, Roles: []recovery.Role{}, Attempts: []recovery.Attempt{}, Findings: []recovery.Finding{}}
	if lineage.runType() == domain.RunTypeRerun {
		value := lineage.immutableLineage()
		document.RunType = domain.RunTypeRerun
		document.Source = &recovery.Source{Kind: "published_review", RunID: value.sourceRunID.String(), ReviewID: lineageReviewID(value.sourceReviewID), AttemptID: value.sourceAttemptID.String(), ReplayMode: string(*value.replayMode)}
		if value.sourceRecoveryManifestSHA256 != nil {
			document.Source.Kind = "failed_run_recovery"
			document.Source.RecoveryManifestSHA256 = cloneOptionalString(value.sourceRecoveryManifestSHA256)
		}
	} else if lineage.runType() != domain.RunTypeReview && lineage.runType() != "" {
		return recovery.Prepared{}, fmt.Errorf("recovery: unsupported run type")
	}
	if err := ctx.Err(); err != nil {
		return recovery.Prepared{}, err
	}
	summaries := result.RoleSummaries()
	successful := make([]review.CoordinatorRoleSummary, 0, len(summaries))
	for _, summary := range summaries {
		if err := ctx.Err(); err != nil {
			return recovery.Prepared{}, err
		}
		if summary.Valid() {
			successful = append(successful, summary)
		}
		switch summary.FailureClass() {
		case domain.FailureSecurityPolicy, domain.FailureConfiguration, domain.FailureArtifact:
			return recovery.Prepared{}, fmt.Errorf("recovery: unsafe terminal failure %s", summary.FailureClass())
		}
	}
	if err := ctx.Err(); err != nil {
		return recovery.Prepared{}, err
	}
	var roles []preparedRole
	var err error
	if len(successful) > 0 {
		roles, _, err = prepareRoles(successful)
		if err != nil {
			return recovery.Prepared{}, err
		}
	}
	if err := ctx.Err(); err != nil {
		return recovery.Prepared{}, err
	}
	findings, err := prepareFindings(result.Findings(), result.Evidence(), target, roles)
	if err != nil {
		return recovery.Prepared{}, err
	}
	bindFindingIDs(roles, findings)
	accepted := make(map[domain.Role]preparedRole, len(roles))
	for _, role := range roles {
		if err := ctx.Err(); err != nil {
			return recovery.Prepared{}, err
		}
		if err := validatePreparedRole(role); err != nil {
			return recovery.Prepared{}, err
		}
		accepted[role.role] = role
	}
	if err := ctx.Err(); err != nil {
		return recovery.Prepared{}, err
	}
	byAttempt := make(map[domain.AttemptID]review.RuntimeArtifactInventory, len(initial))
	for _, input := range initial {
		if err := ctx.Err(); err != nil {
			return recovery.Prepared{}, err
		}
		if input.RunID() != result.RunID() || input.TargetIdentity() != target || input.Purpose() != domain.InvocationInitial || input.Sequence() != 1 {
			return recovery.Prepared{}, fmt.Errorf("recovery: invalid initial input")
		}
		if _, exists := byAttempt[input.AttemptID()]; exists {
			return recovery.Prepared{}, fmt.Errorf("recovery: duplicate initial input")
		}
		byAttempt[input.AttemptID()] = input
	}
	if len(byAttempt) != len(summaries) {
		return recovery.Prepared{}, fmt.Errorf("recovery: incomplete initial inputs")
	}
	if err := ctx.Err(); err != nil {
		return recovery.Prepared{}, err
	}
	blobs := make(map[string][]byte)
	for _, summary := range summaries {
		if err := ctx.Err(); err != nil {
			return recovery.Prepared{}, err
		}
		attempts := summary.Attempts()
		if len(attempts) != 1 {
			return recovery.Prepared{}, fmt.Errorf("recovery: incomplete canonical attempt inputs")
		}
		attempt := attempts[0]
		input, ok := byAttempt[attempt.ID()]
		if !ok || input.Role() != summary.Role() {
			return recovery.Prepared{}, fmt.Errorf("recovery: initial attempt binding mismatch")
		}
		if document.Target.SHA256 == "" {
			document.Target = recovery.Target{Kind: target.Kind(), SHA256: "sha256:" + target.SHA256(), RepositoryID: target.RepositoryID(), BaseObjectID: target.BaseObjectID(), HeadObjectID: target.HeadObjectID(), HeadTreeObjectID: target.HeadTreeObjectID(), IndexTreeObjectID: target.IndexTreeObjectID(), GitMode: target.GitMode(), Bytes: recovery.AddBlob(blobs, input.Target()), CapturedArchive: recovery.AddBlob(blobs, input.CapturedArchive())}
		} else if recovery.Digest(input.Target()) != document.Target.Bytes.SHA256 || recovery.Digest(input.CapturedArchive()) != document.Target.CapturedArchive.SHA256 {
			return recovery.Prepared{}, fmt.Errorf("recovery: divergent target material")
		}
		document.Attempts = append(document.Attempts, recovery.Attempt{AttemptID: attempt.ID().String(), Role: summary.Role(), ProviderInstance: attempt.Route().ProviderInstance(), State: attempt.State(), FailureClass: attempt.FailureClass(), ReasonCode: attempt.ReasonCode(), InitialPrompt: recovery.Prompt{Stdin: recovery.AddBlob(blobs, input.Stdin()), SourceInvocationID: input.SourceInvocationID(), ExecutionInvocationID: input.ExecutionInvocationID(), TemplateID: input.TemplateID(), TemplateVersion: input.TemplateVersion(), TemplateSHA256: "sha256:" + strings.TrimPrefix(input.TemplateSHA256(), "sha256:"), AdapterProfile: input.AdapterProfile(), AdapterParameters: input.AdapterParameters(), Scope: input.Scope()}})
		role := recovery.Role{Role: summary.Role(), Required: summary.Required() || summary.Role() == domain.RoleLogic, Outcome: "failed", AttemptID: attempt.ID().String(), ProviderInstance: attempt.Route().ProviderInstance(), FindingIDs: []string{}}
		if value, ok := accepted[summary.Role()]; ok {
			report := recovery.AddBlob(blobs, value.reportMarkdown)
			role.Outcome = value.outcome
			role.ReportsOnly = value.reportsOnly
			role.Report = &report
			role.FindingIDs = append(role.FindingIDs, value.validFindingIDs...)
		}
		document.Roles = append(document.Roles, role)
	}
	if err := ctx.Err(); err != nil {
		return recovery.Prepared{}, err
	}
	for _, finding := range findings {
		if err := ctx.Err(); err != nil {
			return recovery.Prepared{}, err
		}
		item := recovery.Finding{ID: finding.id, Fingerprint: finding.fingerprint, Role: finding.role, ProviderInstance: finding.provider, Severity: finding.severity, Title: finding.title, Description: finding.description, Recommendation: finding.recommendation, Confidence: finding.confidence, Lifecycle: finding.lifecycle, Evidence: []recovery.Evidence{}}
		for _, claim := range finding.evidence {
			current := recovery.Evidence{TargetSHA256: claim.targetSHA256, Side: claim.side, Path: claim.path, LineStart: claim.lineStart, LineEnd: claim.lineEnd, Quote: claim.quote, ExcerptSHA256: claim.currentExcerptSHA256}
			if claim.visual != nil {
				visual := claim.visual
				current.Visual = &recovery.Visual{Path: visual.path, SHA256: visual.sha256, X: visual.x, Y: visual.y, Width: visual.width, Height: visual.height}
			}
			item.Evidence = append(item.Evidence, current)
		}
		document.Findings = append(document.Findings, item)
	}
	return recovery.NewPrepared(ctx, document, blobs)
}

func (service *Service) PersistFailedRunRecovery(ctx context.Context, root ports.AnchoredRoot, prepared recovery.Prepared, receipt ports.WorkspaceTerminalReceipt) (domain.SourceReference, error) {
	if service == nil || ctx == nil || !root.Valid() {
		return domain.SourceReference{}, fmt.Errorf("recovery: invalid persistence dependencies")
	}
	if err := ctx.Err(); err != nil {
		return domain.SourceReference{}, err
	}
	snapshot, err := prepared.Seal(ctx, receipt)
	if err != nil {
		return domain.SourceReference{}, err
	}
	if int64(len(snapshot.Manifest())) > service.maxBytes {
		return domain.SourceReference{}, fmt.Errorf("recovery: structured manifest exceeds publication bound")
	}
	document := snapshot.Document()
	session, err := domain.ParseSessionID(document.SessionID)
	if err != nil {
		return domain.SourceReference{}, err
	}
	runID, err := domain.ParseRunID(document.RunID)
	if err != nil {
		return domain.SourceReference{}, err
	}
	run, err := ports.NewPublicationRun(root, session, runID)
	if err != nil {
		return domain.SourceReference{}, err
	}
	schema, err := ports.ParseAssetID(recovery.SchemaURI)
	if err != nil {
		return domain.SourceReference{}, err
	}
	if err := service.validator.Validate(ctx, schema, snapshot.Manifest()); err != nil {
		return domain.SourceReference{}, err
	}
	if err := ctx.Err(); err != nil {
		return domain.SourceReference{}, err
	}
	persist := func(path ports.SafeRelativePath, raw []byte) error {
		artifact, err := ports.NewImmutablePublicationArtifact(path, recovery.Digest(raw), raw)
		if err != nil {
			return err
		}
		request, err := ports.NewPersistRunSupportArtifactRequest(run, artifact)
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		result, err := service.store.PersistAuxiliaryArtifact(ctx, request)
		if err != nil {
			return err
		}
		if !result.Valid() || result.Durability() != ports.AuxiliaryArtifactDurable || result.Artifact().SHA256() != artifact.SHA256() || result.Artifact().Path() != path {
			return fmt.Errorf("recovery: durable write receipt mismatch")
		}
		return nil
	}
	for _, blob := range document.Blobs() {
		if err := ctx.Err(); err != nil {
			return domain.SourceReference{}, err
		}
		path, err := recovery.BlobPath(run, blob)
		if err != nil {
			return domain.SourceReference{}, err
		}
		if err := persist(path, snapshot.Blob(blob)); err != nil {
			return domain.SourceReference{}, err
		}
	}
	if err := ctx.Err(); err != nil {
		return domain.SourceReference{}, err
	}
	// The manifest is the sole authority marker and is installed last, atomically.
	path, err := recovery.ManifestPath(run)
	if err != nil {
		return domain.SourceReference{}, err
	}
	if err := persist(path, snapshot.Manifest()); err != nil {
		return domain.SourceReference{}, err
	}
	return snapshot.Reference()
}
