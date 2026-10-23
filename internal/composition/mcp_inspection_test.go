//go:build darwin && arm64

package composition

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

func (*mcpQueryFake) ReadReport(context.Context, ports.PublicationRun, domain.ProjectBinding, string, query.ContentContinuation) (query.ContentChunk, error) {
	return query.ContentChunk{}, errors.New("unexpected report content read")
}
func (*mcpQueryFake) ReadEvidence(context.Context, ports.PublicationRun, domain.ProjectBinding, string, string, int, query.ContentContinuation) (query.ContentChunk, error) {
	return query.ContentChunk{}, errors.New("unexpected indexed evidence read")
}

func (*mcpQueryFake) ReadSourceEvidence(context.Context, ports.PublicationRun, domain.ProjectBinding, string, string, int, query.ContentContinuation) (query.ContentChunk, error) {
	return query.ContentChunk{}, errors.New("unexpected source evidence read")
}

func (*mcpQueryFake) ReadSourceImage(context.Context, ports.PublicationRun, domain.ProjectBinding, string, string, string, query.ContentContinuation) (query.ContentChunk, error) {
	return query.ContentChunk{}, errors.New("unexpected source image read")
}

func (*mcpMultiQueryFake) ReadReport(context.Context, ports.PublicationRun, domain.ProjectBinding, string, query.ContentContinuation) (query.ContentChunk, error) {
	return query.ContentChunk{}, errors.New("unexpected report content read")
}
func (*mcpMultiQueryFake) ReadEvidence(context.Context, ports.PublicationRun, domain.ProjectBinding, string, string, int, query.ContentContinuation) (query.ContentChunk, error) {
	return query.ContentChunk{}, errors.New("unexpected indexed evidence read")
}

func (*mcpMultiQueryFake) ReadSourceEvidence(context.Context, ports.PublicationRun, domain.ProjectBinding, string, string, int, query.ContentContinuation) (query.ContentChunk, error) {
	return query.ContentChunk{}, errors.New("unexpected source evidence read")
}

func (*mcpMultiQueryFake) ReadSourceImage(context.Context, ports.PublicationRun, domain.ProjectBinding, string, string, string, query.ContentContinuation) (query.ContentChunk, error) {
	return query.ContentChunk{}, errors.New("unexpected source image read")
}

// TestMCPInspectFallbackSuppressesPagedRequests pins that a missing
// publication carrying a cursor or an expected publication receipt can never
// fall back to the diagnostic projection: pagination selectors require the
// committed publication they were issued against.
func TestMCPInspectFallbackSuppressesPagedRequests(t *testing.T) {
	projectRoot := mustMCPRoot(t, canonicalTestTempDir(t))
	artifactRoot := mustMCPRoot(t, filepath.Join(projectRoot.String(), ".mulgae"))
	sessionID := mustMCPSessionID(t, "s_019f596a-cf80-7c67-b265-f37053d51ccf")
	runID := mustMCPRunID(t, "r_019f596a-cfe4-7c9c-b82e-7149158243ba")
	if err := os.MkdirAll(filepath.Join(artifactRoot.String(), sessionID.String(), runID.String()), 0o700); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.August, 14, 5, 0, 0, 0, time.UTC)
	status, err := ports.NewRuntimeDiagnosticRunStatus(ports.RuntimeDiagnosticRunStatusInput{
		SessionID: sessionID, RunID: runID, State: domain.RunFailed, StartedAt: now, UpdatedAt: now.Add(time.Second),
		CompletedAt: now.Add(time.Second), HasCompletedAt: true, SelectedRoles: []domain.Role{domain.RoleTesting},
		RolePathTotal: 1, RolePathFailed: 1, LastSequence: 3, TerminalCause: domain.DiagnosticCauseProviderSpawnFailed,
	})
	if err != nil {
		t.Fatal(err)
	}
	queries := &mcpQueryFake{resolveErr: ports.ErrPublicationRunNotFound}
	diagnostics := &mcpDiagnosticQueryFake{status: status}
	backend, err := newMCPBoundTestBackend(projectRoot, artifactRoot, &mulgaeentry.Application{}, queries, diagnostics, &mcpReportFake{}, filesystem.NewRunSelector())
	if err != nil {
		t.Fatal(err)
	}
	for name, input := range map[string]mcpentry.ListFindingsInput{
		"cursor set":           {RunID: runID.String(), Cursor: "opaque"},
		"expected receipt set": {RunID: runID.String(), ExpectedPublicationReceipt: "sha256:" + strings.Repeat("1", 64)},
	} {
		t.Run(name, func(t *testing.T) {
			if _, inspectErr := backend.InspectReview(context.Background(), input); inspectErr == nil {
				t.Fatalf("paged missing-publication request fell back to diagnostics")
			}
		})
	}
	if diagnostics.calls != 0 {
		t.Fatalf("suppressed fallback still consulted diagnostics %d times", diagnostics.calls)
	}
	diagnostics.calls = 0
	if data, inspectErr := backend.InspectReview(context.Background(), mcpentry.ListFindingsInput{RunID: runID.String()}); inspectErr != nil || data == nil {
		t.Fatalf("unpaged missing-publication inspect did not use the diagnostic projection: %v", inspectErr)
	}
	if diagnostics.calls == 0 {
		t.Fatal("unpaged missing-publication inspect never consulted diagnostics")
	}
}
