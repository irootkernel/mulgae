package kar

import (
	"context"
	"fmt"
	"path"
	"strings"

	appexport "github.com/irootkernel/kkachi-agent-review/internal/app/export"
	appquery "github.com/irootkernel/kkachi-agent-review/internal/app/query"
	"github.com/irootkernel/kkachi-agent-review/internal/domain"
	"github.com/irootkernel/kkachi-agent-review/internal/ports"
)

const maintenanceExportMaxBytes int64 = 8 << 20

// NewRedactedExportService composes offline export from verified P2 query reads
// and a paired secure export installer. It deliberately accepts no provider or
// runtime authority.
func NewRedactedExportService(
	queries *appquery.Service,
	installer appexport.ExportInstaller,
	clock ports.Clock,
	requestIDs RequestIDGenerator,
) (RedactedExportService, error) {
	if nilApplicationDependency(queries) || nilApplicationDependency(installer) || nilApplicationDependency(clock) || nilApplicationDependency(requestIDs) {
		return nil, fmt.Errorf("redacted export service: nil dependency")
	}
	return &redactedExportAdapter{queries: queries, installer: installer, clock: clock, requestIDs: requestIDs}, nil
}

type redactedExportAdapter struct {
	queries    *appquery.Service
	installer  appexport.ExportInstaller
	clock      ports.Clock
	requestIDs RequestIDGenerator
}

func (adapter *redactedExportAdapter) ExportRedactedRun(ctx context.Context, request RedactedExportRequest) (RedactedExportResult, error) {
	if adapter == nil || adapter.queries == nil || adapter.installer == nil || adapter.clock == nil || adapter.requestIDs == nil {
		return RedactedExportResult{}, fmt.Errorf("redacted export service: uninitialized")
	}
	if ctx == nil {
		return RedactedExportResult{}, context.Canceled
	}
	runID, err := domain.ParseRunID(request.RunID)
	if err != nil {
		return RedactedExportResult{}, err
	}
	bundlePath, err := ports.NewSafeRelativePath(request.OutputPath)
	if err != nil {
		return RedactedExportResult{}, err
	}
	manifestPath, err := exportManifestSidecar(bundlePath)
	if err != nil {
		return RedactedExportResult{}, err
	}
	run, err := adapter.queries.ResolveRun(ctx, request.ProjectRoot, runID)
	if err != nil {
		return RedactedExportResult{}, err
	}
	committed, err := adapter.queries.ReadCommitted(ctx, run)
	if err != nil {
		return RedactedExportResult{}, err
	}
	now := adapter.clock.Now()
	requestID, err := adapter.requestIDs.NewRequestID(now)
	if err != nil {
		return RedactedExportResult{}, fmt.Errorf("redacted export service: export identity: %w", err)
	}
	if !strings.HasPrefix(requestID, "i_") {
		return RedactedExportResult{}, fmt.Errorf("redacted export service: invalid export identity")
	}
	service, err := appexport.NewService(p2ExportProjectionReader{committed: committed}, adapter.installer, maintenanceExportMaxBytes)
	if err != nil {
		return RedactedExportResult{}, err
	}
	result, err := service.ExportRedactedRun(ctx, appexport.ExportRequest{
		Source: appexport.ExportSource{SessionID: committed.SessionID().String(), RunID: committed.RunID().String(), ReviewID: committed.ReviewID().String()},
		Root:   request.ProjectRoot, BundlePath: bundlePath, ManifestPath: manifestPath,
		ExportID: "x_" + strings.TrimPrefix(requestID, "i_"), CreatedAt: now,
	})
	if err != nil {
		return RedactedExportResult{}, err
	}
	return RedactedExportResult{
		ExportManifestURI: result.ManifestReceipt.Destination().String(),
		BundleURI:         result.BundleReceipt.Destination().String(),
		Redacted:          true,
	}, nil
}

// exportManifestSidecar derives the sidecar solely from the validated bundle path.
func exportManifestSidecar(bundle ports.SafeRelativePath) (ports.SafeRelativePath, error) {
	value := bundle.String()
	extension := path.Ext(value)
	if extension != "" {
		value = strings.TrimSuffix(value, extension)
	}
	return ports.NewSafeRelativePath(value + ".manifest.json")
}

type p2ExportProjectionReader struct {
	committed appquery.CommittedReview
}

func (reader p2ExportProjectionReader) ReadCommittedProjection(_ context.Context, source appexport.ExportSource) (appexport.VerifiedSourceProjection, error) {
	committed := reader.committed
	if source.SessionID != committed.SessionID().String() || source.RunID != committed.RunID().String() || source.ReviewID != committed.ReviewID().String() {
		return appexport.VerifiedSourceProjection{}, fmt.Errorf("P2 export source identity mismatch")
	}
	findings := committed.Findings()
	projection := appexport.VerifiedSourceProjection{
		SessionID: committed.SessionID().String(), RunID: committed.RunID().String(), ReviewID: committed.ReviewID().String(),
		RunManifest:     appexport.ImmutableArtifactRef{ArtifactPath: committed.ManifestPath().String(), SHA256: committed.ManifestSHA256()},
		ReviewArtifact:  appexport.ImmutableArtifactRef{ArtifactPath: committed.FinalPath().String(), SHA256: committed.FinalSHA256()},
		SchemaVersions:  []string{"kar-run-manifest.v2", "kar-review-artifact.v2"},
		Review:          appexport.Review{SchemaVersion: "kar-review-artifact.v2", ContentVerdict: string(committed.ContentVerdict()), CoverageStatus: string(committed.CoverageStatus())},
		Run:             appexport.Run{SchemaVersion: "kar-run-manifest.v2", State: string(committed.RunState())},
		Redaction:       appexport.RedactionManifest{Policy: "allowlisted-p2-projection", Dropped: []string{"raw_provider_output", "target_bytes", "environment", "host_paths"}},
		SourceIdentity:  appexport.SourceIdentity{SessionID: committed.SessionID().String(), RunID: committed.RunID().String(), ReviewID: committed.ReviewID().String(), SourceTargetSHA256: committed.TargetSHA256()},
		CurrentIdentity: appexport.CurrentIdentity{TargetSHA256: committed.TargetSHA256()},
	}
	for _, finding := range findings {
		projection.Findings = append(projection.Findings, appexport.Finding{ID: finding.ID(), Fingerprint: finding.Fingerprint(), Role: string(finding.Role()), Severity: string(finding.Severity()), Title: finding.Title(), Description: finding.Description(), Recommendation: finding.Recommendation(), Confidence: string(finding.Confidence()), Lifecycle: string(finding.Lifecycle())})
		for _, evidence := range finding.Evidence() {
			item := appexport.Evidence{FindingID: finding.ID(), SourceSessionID: evidence.SourceSessionID().String(), SourceRunID: evidence.SourceRunID().String(), SourceReviewID: evidence.SourceReviewID().String(), SourceFindingID: evidence.SourceFindingID(), SourceTargetSHA256: evidence.SourceTargetSHA256(), SourceExcerptSHA256: evidence.SourceExcerptSHA256(), TargetSHA256: evidence.TargetSHA256(), Path: evidence.Path().String(), Side: string(evidence.Side()), LineStart: evidence.LineStart(), LineEnd: evidence.LineEnd(), Verification: string(evidence.Verification())}
			projection.Evidence = append(projection.Evidence, item)
			if projection.SourceIdentity.FindingID == "" {
				projection.SourceIdentity = appexport.SourceIdentity{SessionID: item.SourceSessionID, RunID: item.SourceRunID, ReviewID: item.SourceReviewID, FindingID: item.SourceFindingID, SourceTargetSHA256: item.SourceTargetSHA256, SourceExcerptSHA256: item.SourceExcerptSHA256}
				projection.CurrentIdentity = appexport.CurrentIdentity{TargetSHA256: item.TargetSHA256, Path: item.Path, Side: item.Side, LineStart: item.LineStart, LineEnd: item.LineEnd, Verification: item.Verification}
			}
		}
	}
	return projection, nil
}
