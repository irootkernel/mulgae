package reviewcompose

import (
	"fmt"
	"strings"

	"github.com/irootkernel/mulgae/internal/app/recovery"
	"github.com/irootkernel/mulgae/internal/domain"
)

func sourceReference(run domain.RunID, review domain.ReviewID, hash string) (domain.SourceReference, error) {
	if hash != "" {
		if review.String() != "" {
			return domain.SourceReference{}, fmt.Errorf("ambiguous source reference")
		}
		return domain.NewRecoverySourceReference(run, hash)
	}
	return domain.NewPublishedSourceReference(run, review)
}
func compositionFingerprint(root Source, coordinates []domain.CompositionSource) (domain.CompositionFingerprint, error) {
	if root.RecoveryManifestSHA256 == "" {
		return domain.NewCompositionFingerprint(root.RunID, coordinates)
	}
	reference, err := sourceReference(root.RunID, root.ReviewID, root.RecoveryManifestSHA256)
	if err != nil {
		return domain.CompositionFingerprint{}, err
	}
	return domain.NewRecoveryCompositionFingerprint(reference, coordinates)
}
func sourceFromRecovery(snapshot recovery.Snapshot) (Source, error) {
	document := snapshot.Document()
	reference, err := snapshot.Reference()
	if err != nil {
		return Source{}, err
	}
	session, err := domain.ParseSessionID(document.SessionID)
	if err != nil {
		return Source{}, err
	}
	target, err := document.Target.Identity()
	if err != nil {
		return Source{}, err
	}
	source := Source{SessionID: session, RunID: reference.RunID(), RecoveryManifestSHA256: reference.RecoveryManifestSHA256(), RunType: document.RunType, TargetSHA256: document.Target.SHA256, TargetIdentity: target, TargetBytes: snapshot.Blob(document.Target.Bytes), CapturedArchive: snapshot.Blob(document.Target.CapturedArchive), Coverage: domain.CoverageIncomplete, Threshold: document.Threshold}
	if document.Source != nil {
		parent, err := document.Source.Reference()
		if err != nil {
			return Source{}, err
		}
		attempt, err := domain.ParseAttemptID(document.Source.AttemptID)
		if err != nil {
			return Source{}, err
		}
		source.SourceRunID = parent.RunID()
		source.SourceReviewID = parent.ReviewID()
		source.SourceRecoveryManifestSHA256 = parent.RecoveryManifestSHA256()
		source.SourceAttemptID = attempt
		source.HasSource = true
		source.HasSourceAttempt = true
	}
	for _, role := range document.Roles {
		attempt, err := domain.ParseAttemptID(role.AttemptID)
		if err != nil {
			return Source{}, err
		}
		source.Roles = append(source.Roles, Role{Name: role.Role, Required: role.Required, Outcome: role.Outcome, AttemptID: attempt, HasAttempt: true, ProviderInstance: role.ProviderInstance, FindingIDs: append([]string(nil), role.FindingIDs...), ReportsOnly: role.ReportsOnly})
		if role.Report != nil {
			source.RoleReports = append(source.RoleReports, RoleReport{Role: role.Role, AttemptID: attempt, ProviderInstance: role.ProviderInstance, Path: "recovery/blobs/sha256-" + strings.TrimPrefix(role.Report.SHA256, "sha256:"), SHA256: role.Report.SHA256, ByteLength: int(role.Report.ByteLength), ContentType: "text/markdown", Bytes: snapshot.Blob(*role.Report)})
		}
	}
	for _, item := range document.Attempts {
		attempt, err := domain.ParseAttemptID(item.AttemptID)
		if err != nil {
			return Source{}, err
		}
		source.Attempts = append(source.Attempts, Attempt{AttemptID: attempt, Role: item.Role, ProviderInstance: item.ProviderInstance, State: item.State})
	}
	for _, item := range document.Findings {
		source.Findings = append(source.Findings, SourceFinding{ID: item.ID, Fingerprint: item.Fingerprint, Role: item.Role, ProviderInstance: item.ProviderInstance, Severity: item.Severity, Title: item.Title, Description: item.Description, Recommendation: item.Recommendation, Confidence: item.Confidence, Lifecycle: item.Lifecycle})
	}
	return source, nil
}
