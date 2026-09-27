//go:build darwin && arm64

package composition

import (
	"context"
	"errors"
	"github.com/irootkernel/mulgae/internal/adapters/filesystem"
	"github.com/irootkernel/mulgae/internal/app/query"
	"github.com/irootkernel/mulgae/internal/app/recovery"
	"github.com/irootkernel/mulgae/internal/domain"
	mcpentry "github.com/irootkernel/mulgae/internal/entrypoint/mcp"
	mulgaeentry "github.com/irootkernel/mulgae/internal/entrypoint/mulgae"
	"github.com/irootkernel/mulgae/internal/ports"
)

func (fake *mcpQueryFake) Inspect(ctx context.Context, run ports.PublicationRun, binding domain.ProjectBinding, request query.InspectionRequest) (query.Inspection, error) {
	view, err := fake.ListFindings(ctx, run, request.MinimumSeverity)
	return fixtureInspection(view, request, err)
}
func (fake *mcpMultiQueryFake) Inspect(ctx context.Context, run ports.PublicationRun, binding domain.ProjectBinding, request query.InspectionRequest) (query.Inspection, error) {
	view, err := fake.ListFindings(ctx, run, request.MinimumSeverity)
	return fixtureInspection(view, request, err)
}
func fixtureInspection(view mcpFixtureFindings, request query.InspectionRequest, err error) (query.Inspection, error) {
	if err != nil {
		return query.Inspection{}, err
	}
	page := query.Inspection{FailedRunRecovery: recovery.UnavailableStatus("published_review"), RunID: view.RunID, TargetSHA256: view.TargetSHA256, ReviewArtifactURI: view.ReviewArtifactURI, FindingCount: len(view.Findings), ReturnedCount: len(view.Findings), MinimumSeverity: string(request.MinimumSeverity), Findings: []query.FindingSummary{}, RoleReports: []query.InspectionRoleReport{}}
	for _, f := range view.Findings {
		var legacyURI *string
		if f.HasEvidence {
			uri, e := mcpentry.NewEvidenceResourceURI(view.RunID, f.ID, view.TargetSHA256)
			if e != nil {
				return query.Inspection{}, e
			}
			legacyURI = &uri
		}
		page.Findings = append(page.Findings, query.FindingSummary{EvidenceResourceURI: legacyURI, ID: f.ID, Title: f.Title, Severity: string(f.Severity), Evidence: []query.FindingEvidenceReference{}})
	}
	return page, nil
}
func (*mcpQueryFake) ReadFinding(context.Context, ports.PublicationRun, domain.ProjectBinding, string, query.ContentContinuation) (query.ContentChunk, error) {
	return query.ContentChunk{}, errors.New("unexpected read finding")
}
func (*mcpMultiQueryFake) ReadFinding(context.Context, ports.PublicationRun, domain.ProjectBinding, string, query.ContentContinuation) (query.ContentChunk, error) {
	return query.ContentChunk{}, errors.New("unexpected read finding")
}

type inspectionContextObserver struct{}
type inspectionContextLease struct{ root ports.AnchoredRoot }

func (inspectionContextObserver) ObserveProjectBinding(_ context.Context, root ports.AnchoredRoot) (ports.ProjectBindingLease, error) {
	return inspectionContextLease{root}, nil
}
func (lease inspectionContextLease) Observation() ports.ProjectBindingObservation {
	identity := ports.ProjectDirectoryIdentity{Device: 1, Inode: 2, BirthSeconds: 3}
	return ports.ProjectBindingObservation{Root: lease.root, GitDirectory: lease.root, CommonDirectory: lease.root, RootIdentity: identity, GitIdentity: identity, CommonIdentity: identity}
}
func (inspectionContextLease) Revalidate(ctx context.Context) error { return ctx.Err() }
func (inspectionContextLease) Close() error                         { return nil }
func inspectionContexts() *query.ProjectContextService {
	service, _ := query.NewProjectContextService(inspectionContextObserver{})
	return service
}
func newMCPBoundTestBackend(projectRoot, artifactRoot ports.AnchoredRoot, application *mulgaeentry.Application, queries mulgaeentry.PublicationQueryService, diagnostics ports.RuntimeDiagnosticQuery, reports mulgaeentry.PublicationReportService, enumerator *filesystem.RunSelector) (*mcpBackend, error) {
	backend, err := newMCPBackend(projectRoot, artifactRoot, application, queries, diagnostics, reports, enumerator)
	if err != nil {
		return nil, err
	}
	backend.projectContexts = inspectionContexts()
	backend.contextLease = inspectionContextLease{projectRoot}
	return backend, nil
}

// mcpFixtureFinding is one finding in the query service's preserved final order.
type mcpFixtureFinding struct {
	ID          string
	Severity    domain.Severity
	Title       string
	HasEvidence bool
}

// mcpFixtureFindings is a committed finding selection and its committed review URI.
type mcpFixtureFindings struct {
	RunID             string
	Findings          []mcpFixtureFinding
	ReviewArtifactURI string
	TargetSHA256      string
}
