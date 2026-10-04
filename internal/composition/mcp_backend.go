//go:build darwin && arm64

package composition

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"unicode/utf8"

	"github.com/irootkernel/mulgae/internal/adapters/filesystem"
	"github.com/irootkernel/mulgae/internal/app/query"
	"github.com/irootkernel/mulgae/internal/app/reviewrun"
	"github.com/irootkernel/mulgae/internal/domain"
	mcpentry "github.com/irootkernel/mulgae/internal/entrypoint/mcp"
	mulgaeentry "github.com/irootkernel/mulgae/internal/entrypoint/mulgae"
	"github.com/irootkernel/mulgae/internal/ports"
)

type mcpBackend struct {
	projectContexts *query.ProjectContextService
	workspaceLease  ports.WorkspaceRootLease
	contextLease    ports.ProjectBindingLease
	contextError    error
	projectRoot     ports.AnchoredRoot
	artifactRoot    ports.AnchoredRoot
	application     *mulgaeentry.Application
	queries         mulgaeentry.PublicationQueryService
	diagnostics     ports.RuntimeDiagnosticQuery
	reports         mulgaeentry.PublicationReportService
	enumerator      *filesystem.RunSelector
}

func newMCPBackend(
	projectRoot, artifactRoot ports.AnchoredRoot,
	application *mulgaeentry.Application,
	queries mulgaeentry.PublicationQueryService,
	diagnostics ports.RuntimeDiagnosticQuery,
	reports mulgaeentry.PublicationReportService,
	enumerator *filesystem.RunSelector,
) (*mcpBackend, error) {
	if !projectRoot.Valid() || !artifactRoot.Valid() || application == nil || queries == nil || diagnostics == nil || reports == nil || enumerator == nil {
		return nil, fmt.Errorf("MCP backend: incomplete dependencies")
	}
	return &mcpBackend{
		projectRoot: projectRoot, artifactRoot: artifactRoot, application: application,
		queries: queries, diagnostics: diagnostics, reports: reports, enumerator: enumerator,
	}, nil
}

func (backend *mcpBackend) PreflightReview(
	ctx context.Context,
	requestID string,
	input mcpentry.RunReviewInput,
) (mcpentry.BackendResult, error) {
	if err := backend.preflight(ctx); err != nil {
		return mcpentry.BackendResult{}, err
	}
	arguments, err := mcpReviewArguments(input)
	if err != nil {
		return mcpentry.BackendResult{}, newMCPFailure("mcp.admission", domain.FailureConfiguration, "MCP preflight target is invalid", err)
	}
	arguments = append(arguments, "--preflight")
	invocation, err := mulgaeentry.Parse(arguments, backend.projectRoot.String(), requestID)
	if err != nil {
		class := domain.FailureInternal
		if errors.Is(err, mulgaeentry.ErrUsage) {
			class = domain.FailureConfiguration
		}
		return mcpentry.BackendResult{}, newMCPFailure("mcp.admission", class, "MCP preflight request is invalid", err)
	}
	request, available := invocation.Review()
	if !available || !request.Preflight() {
		return mcpentry.BackendResult{}, newMCPFailure("mcp.preflight", domain.FailureInternal, "MCP preflight request is unavailable", nil)
	}
	if err := backend.checkReviewProject(ctx, input.ExpectedProjectBinding); err != nil {
		return mcpentry.BackendResult{}, err
	}
	result, err := backend.application.PreflightReview(ctx, request, backend.projectRoot)
	if err != nil {
		return mcpentry.BackendResult{}, err
	}
	data, err := summarizeMCPPreflight(result)
	if err != nil {
		return mcpentry.BackendResult{}, err
	}
	return mcpentry.BackendResult{Outcome: "success", Data: data}, nil
}

func summarizeMCPPreflight(result mulgaeentry.ReviewPreflightResult) (map[string]any, error) {
	return map[string]any{
		"schema_version": result.SchemaVersion, "status": result.Status, "qualification": result.Qualification,
		"target": result.Target, "candidate_count": result.CandidateCount, "read_count": len(result.ReadPlan),
		"warnings": result.Warnings, "transmissions": result.Transmissions, "budget": result.Budget,
		"project_binding": result.ProjectBinding, "configuration_sha256": result.ConfigurationSHA256,
		"source_identity_sha256": result.SourceIdentitySHA256, "capabilities": result.Capabilities,
	}, nil
}

func (backend *mcpBackend) RunReview(
	ctx context.Context,
	requestID string,
	input mcpentry.RunReviewInput,
) (mcpentry.BackendResult, error) {
	if err := backend.preflight(ctx); err != nil {
		return mcpentry.BackendResult{}, err
	}
	arguments, err := mcpReviewArguments(input)
	if err != nil {
		return mcpentry.BackendResult{}, newMCPFailure("mcp.admission", domain.FailureConfiguration, "MCP review target is invalid", err)
	}
	invocation, err := mulgaeentry.Parse(arguments, backend.projectRoot.String(), requestID)
	if err != nil {
		class := domain.FailureInternal
		if errors.Is(err, mulgaeentry.ErrUsage) {
			class = domain.FailureConfiguration
		}
		return mcpentry.BackendResult{}, newMCPFailure("mcp.admission", class, "MCP review request is invalid", err)
	}
	request, available := invocation.Review()
	if !available || request.Preflight() {
		return mcpentry.BackendResult{}, fmt.Errorf("MCP review request is unavailable")
	}
	if err := backend.checkReviewProject(ctx, input.ExpectedProjectBinding); err != nil {
		return mcpentry.BackendResult{}, err
	}
	result, err := backend.application.StartReviewRun(ctx, request, backend.projectRoot)
	if err != nil {
		return mcpentry.BackendResult{}, err
	}
	decision := result.TerminalExit()
	outcome := "success"
	if decision.Code() == domain.ExitCommittedCIRejected {
		outcome = "request_changes"
	}
	reasons := make([]any, 0, len(decision.Reasons()))
	for _, reason := range decision.Reasons() {
		reasons = append(reasons, map[string]any{
			"code": reason.ReasonCode(), "exit_code": int(reason.Code()),
		})
	}
	reports := make([]any, 0, len(result.RoleReportURIs()))
	for _, report := range result.RoleReportURIs() {
		reports = append(reports, map[string]any{"role": report.Role, "uri": report.URI})
	}
	reportURI, err := mcpentry.NewReportResourceURI(result.RunID())
	if err != nil {
		return mcpentry.BackendResult{}, fmt.Errorf("MCP review report URI is invalid")
	}
	return mcpentry.BackendResult{Outcome: outcome, Data: map[string]any{
		"session_id": result.SessionID(), "run_id": result.RunID(),
		"run_manifest_uri": result.RunManifestURI(), "review_artifact_uri": result.ReviewArtifactURI(),
		"role_report_uris": reports, "report_resource_uri": reportURI,
		"terminal_exit_code": int(decision.Code()), "reasons": reasons,
		"guarded": result.Guarded(), "project_binding": result.ProjectBinding(), "source_identity_sha256": result.SourceIdentitySHA256(),
	}}, nil
}

func mcpReviewArguments(input mcpentry.RunReviewInput) ([]string, error) {
	if _, err := ports.NewLiveSourceSelector(domain.LiveSourceScope(input.Target.Kind), input.Target.Value); err != nil {
		return nil, fmt.Errorf("MCP review target is invalid")
	}
	arguments := []string{"review"}
	switch input.Target.Kind {
	case "workspace", "stage", "head":
		arguments = append(arguments, "--"+input.Target.Kind)
	case "diff", "commit":
		arguments = append(arguments, "--"+input.Target.Kind, input.Target.Value)
	default:
		return nil, fmt.Errorf("MCP review target is invalid")
	}
	if input.ExpectedProjectBinding != nil {
		arguments = append(arguments, "--expected-project-binding", *input.ExpectedProjectBinding)
	}
	if input.Objective != "" {
		arguments = append(arguments, "--objective", input.Objective)
	}
	if len(input.Roles) != 0 {
		arguments = append(arguments, "--roles", strings.Join(input.Roles, ","))
	}
	return arguments, nil
}

func (backend *mcpBackend) ListRuns(ctx context.Context, input mcpentry.ListRunsInput) (map[string]any, error) {
	if err := backend.preflight(ctx); err != nil {
		return nil, err
	}
	if _, err := os.Lstat(backend.artifactRoot.String()); errors.Is(err, os.ErrNotExist) {
		return map[string]any{"runs": []any{}, "next_cursor": nil, "omitted_count": 0}, nil
	} else if err != nil {
		return nil, newMCPFailure("mcp.list-runs", domain.FailureArtifact, "publication root observation failed", err)
	}
	candidates, diagnostics, err := backend.enumerator.Enumerate(ctx, backend.artifactRoot)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, newMCPFailure("mcp.list-runs", domain.FailureArtifact, "run enumeration failed", err)
	}
	runs := make([]any, 0, input.Limit)
	omitted := len(diagnostics)
	var nextCursor any
	for index := len(candidates) - 1; index >= 0; index-- {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		candidate := candidates[index]
		cursor := candidate.SessionID.String() + "/" + candidate.RunID.String()
		if input.Cursor != "" && cursor >= input.Cursor {
			continue
		}
		run, err := backend.queries.ResolveRun(ctx, backend.artifactRoot, candidate.RunID)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return nil, ctxErr
			}
			omitted++
			continue
		}
		if !run.Valid() || run.SessionID() != candidate.SessionID || run.RunID() != candidate.RunID {
			omitted++
			continue
		}
		status, err := backend.queries.ReadRunStatus(ctx, run)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return nil, ctxErr
			}
			omitted++
			continue
		}
		data, err := projectMCPRunStatus(status, candidate.SessionID, candidate.RunID)
		if err != nil {
			omitted++
			continue
		}
		runs = append(runs, data)
		if len(runs) == input.Limit {
			if index > 0 {
				nextCursor = cursor
			}
			break
		}
	}
	return map[string]any{"runs": runs, "next_cursor": nextCursor, "omitted_count": omitted}, nil
}

func (backend *mcpBackend) GetRun(ctx context.Context, input mcpentry.GetRunInput) (map[string]any, error) {
	if err := backend.preflight(ctx); err != nil {
		return nil, err
	}
	run, err := backend.resolveRun(ctx, input.RunID)
	if err != nil {
		if !solelyWraps(err, ports.ErrPublicationRunNotFound) {
			return nil, err
		}
		runID, parseErr := domain.ParseRunID(input.RunID)
		if parseErr != nil {
			return nil, parseErr
		}
		diagnosticStatus, diagnosticErr := backend.diagnostics.ReadRunStatus(ctx, backend.artifactRoot, runID)
		if diagnosticErr != nil {
			if solelyWraps(diagnosticErr, context.Canceled) || solelyWraps(diagnosticErr, context.DeadlineExceeded) {
				return nil, diagnosticErr
			}
			if solelyWraps(diagnosticErr, ports.ErrRuntimeDiagnosticRunNotFound) {
				return nil, newMCPFailure("mcp.get-run", domain.FailureArtifact, "run status is unavailable", mcpentry.ErrRunStatusUnavailable)
			}
			return nil, newMCPFailure("mcp.get-run", domain.FailureArtifact, "diagnostic run status is unavailable", diagnosticErr)
		}
		projected, projectionErr := mcpentry.ProjectDiagnosticRunStatus(diagnosticStatus, diagnosticStatus.SessionID(), runID)
		if projectionErr != nil {
			if errors.Is(projectionErr, mcpentry.ErrRunStatusUnavailable) {
				return nil, newMCPFailure("mcp.get-run", domain.FailureArtifact, "run status is unavailable", mcpentry.ErrRunStatusUnavailable)
			}
			return nil, newMCPFailure("mcp.get-run", domain.FailureArtifact, "diagnostic run status is invalid", projectionErr)
		}
		return projected, nil
	}
	status, err := backend.queries.ReadRunStatus(ctx, run)
	if err != nil {
		return nil, err
	}
	if status.PublicationState != domain.PublicationCommitted {
		diagnosticStatus, diagnosticErr := backend.diagnostics.ReadSessionRunStatus(ctx, backend.artifactRoot, run.SessionID(), run.RunID())
		switch {
		case diagnosticErr == nil:
			if summary, ok := diagnosticStatus.DiagnosticSummary(); ok {
				status.DiagnosticSummary, status.HasDiagnosticSummary = summary, true
			}
		case !solelyWraps(diagnosticErr, ports.ErrRuntimeDiagnosticRunNotFound):
			if solelyWraps(diagnosticErr, context.Canceled) || solelyWraps(diagnosticErr, context.DeadlineExceeded) {
				return nil, diagnosticErr
			}
			return nil, newMCPFailure("mcp.get-run", domain.FailureArtifact, "diagnostic run status is unavailable", diagnosticErr)
		}
	}
	return projectMCPRunStatus(status, run.SessionID(), run.RunID())
}

func solelyWraps(err, target error) bool {
	for err != nil {
		if err == target {
			return true
		}
		if joined, ok := err.(interface{ Unwrap() []error }); ok {
			children := joined.Unwrap()
			matched := false
			for _, child := range children {
				if child == nil {
					continue
				}
				if !solelyWraps(child, target) {
					return false
				}
				matched = true
			}
			return matched
		}
		wrapped, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = wrapped.Unwrap()
	}
	return false
}

func (backend *mcpBackend) InspectReview(ctx context.Context, input mcpentry.ListFindingsInput) (map[string]any, error) {
	return backend.inspect(ctx, input, "inspect")
}
func (backend *mcpBackend) ListFindings(ctx context.Context, input mcpentry.ListFindingsInput) (map[string]any, error) {
	return backend.inspect(ctx, input, "findings")
}
func (backend *mcpBackend) inspect(ctx context.Context, input mcpentry.ListFindingsInput, kind string) (map[string]any, error) {
	if err := backend.preflight(ctx); err != nil {
		return nil, err
	}
	binding, err := backend.readBinding(ctx, input.ExpectedProjectBinding)
	if err != nil {
		return nil, err
	}
	run, err := backend.resolveRun(ctx, input.RunID)
	if err != nil {
		if kind == "inspect" && input.Cursor == "" && input.ExpectedPublicationReceipt == "" && solelyWraps(err, ports.ErrPublicationRunNotFound) {
			runID, _ := domain.ParseRunID(input.RunID)
			status, e := backend.diagnostics.ReadRunStatus(ctx, backend.artifactRoot, runID)
			if e != nil {
				return nil, e
			}
			data, e := mcpentry.ProjectDiagnosticRunStatus(status, status.SessionID(), runID)
			if e != nil {
				return nil, e
			}
			if _, e = backend.resolveRun(ctx, input.RunID); !solelyWraps(e, ports.ErrPublicationRunNotFound) {
				return nil, newMCPFailure("query.inspect", domain.FailureArtifact, "publication changed during diagnostic inspection", e)
			}
			if _, e = backend.readBinding(ctx, input.ExpectedProjectBinding); e != nil {
				return nil, e
			}
			return data, nil
		}
		return nil, err
	}
	page, err := backend.queries.Inspect(ctx, run, binding, query.InspectionRequest{QueryKind: kind, MinimumSeverity: domain.Severity(input.MinimumSeverity), Limit: input.Limit, Cursor: input.Cursor, ExpectedPublicationReceipt: input.ExpectedPublicationReceipt})
	if err != nil {
		return nil, err
	}
	if _, err := backend.readBinding(ctx, input.ExpectedProjectBinding); err != nil {
		return nil, err
	}
	return mcpentry.ProjectInspection(page, input.RunID, input.MinimumSeverity, kind)
}

func (backend *mcpBackend) readBinding(ctx context.Context, expected *string) (domain.ProjectBinding, error) {
	observed, err := backend.GetContext(ctx)
	if err != nil {
		return domain.ProjectBinding{}, err
	}
	raw, ok := observed["project_binding"].(string)
	if !ok {
		return domain.ProjectBinding{}, newMCPFailure("query.context", domain.FailureSecurityPolicy, "project binding unavailable", nil)
	}
	if expected != nil && raw != *expected {
		return domain.ProjectBinding{}, newMCPFailure("query.context", domain.FailureConfiguration, "project_binding_mismatch", reviewrun.ErrProjectBindingMismatch)
	}
	return domain.ParseProjectBinding(raw)
}

func (backend *mcpBackend) ReadResource(ctx context.Context, request mcpentry.ResourceRequest) (mcpentry.ResourceContent, error) {
	if err := backend.preflight(ctx); err != nil {
		return mcpentry.ResourceContent{}, err
	}
	if request.Verified() {
		var expected *string
		if request.ProjectBinding() != "" {
			value := request.ProjectBinding()
			expected = &value
		}
		binding, err := backend.readBinding(ctx, expected)
		if err != nil {
			return mcpentry.ResourceContent{}, err
		}
		run, err := backend.resolveRun(ctx, request.RunID())
		if err != nil {
			return mcpentry.ResourceContent{}, err
		}
		var chunk query.ContentChunk
		switch request.Kind() {
		case mcpentry.ResourceFindingDetail:
			chunk, err = backend.queries.ReadFinding(ctx, run, binding, request.FindingID(), request.Continuation())
		case mcpentry.ResourceReport:
			chunk, err = backend.queries.ReadReport(ctx, run, binding, request.Role(), request.Continuation())
		case mcpentry.ResourceEvidence:
			if request.SourceIdentitySHA256() != "" {
				chunk, err = backend.queries.ReadSourceEvidence(ctx, run, binding, request.FindingID(), request.SourceIdentitySHA256(), request.EvidenceIndex(), request.Continuation())
			} else {
				chunk, err = backend.queries.ReadEvidence(ctx, run, binding, request.FindingID(), request.TargetSHA256(), request.EvidenceIndex(), request.Continuation())
			}
		case mcpentry.ResourceSourceImage:
			chunk, err = backend.queries.ReadSourceImage(ctx, run, binding, request.SourceIdentitySHA256(), request.SourceSide(), request.SourcePath(), request.Continuation())
		default:
			return mcpentry.ResourceContent{}, newMCPFailure("mcp.resource", domain.FailureConfiguration, "MCP resource kind is invalid", nil)
		}
		if err != nil {
			return mcpentry.ResourceContent{}, err
		}
		if _, err := backend.readBinding(ctx, expected); err != nil {
			return mcpentry.ResourceContent{}, err
		}
		return mcpentry.ResourceContent{Chunk: &chunk, ProjectBinding: binding.String()}, nil
	}
	run, err := backend.resolveRun(ctx, request.RunID())
	if err != nil {
		return mcpentry.ResourceContent{}, err
	}
	var contents []byte
	mimeType := "application/octet-stream"
	text := false
	switch request.Kind() {
	case mcpentry.ResourceReport:
		rendered, renderErr := backend.reports.Render(ctx, run)
		if renderErr != nil {
			return mcpentry.ResourceContent{}, renderErr
		}
		if rendered.RunID != request.RunID() || len(rendered.Markdown) == 0 || !utf8.Valid(rendered.Markdown) {
			return mcpentry.ResourceContent{}, newMCPFailure("mcp.resource", domain.FailureArtifact, "verified report projection is invalid", nil)
		}
		contents, mimeType, text = rendered.Markdown, "text/markdown", true
	case mcpentry.ResourceEvidence:
		contents, err = backend.queries.RenderExcerpt(ctx, run, request.FindingID(), request.TargetSHA256())
		if err != nil {
			return mcpentry.ResourceContent{}, err
		}
		if len(contents) == 0 {
			return mcpentry.ResourceContent{}, newMCPFailure("mcp.resource", domain.FailureArtifact, "verified evidence projection is invalid", nil)
		}
	default:
		return mcpentry.ResourceContent{}, newMCPFailure("mcp.resource", domain.FailureConfiguration, "MCP resource kind is invalid", nil)
	}
	return mcpentry.ResourceContent{MIMEType: mimeType, Bytes: append([]byte(nil), contents...), Text: text}, nil
}

func (backend *mcpBackend) resolveRun(ctx context.Context, raw string) (ports.PublicationRun, error) {
	runID, err := domain.ParseRunID(raw)
	if err != nil {
		return ports.PublicationRun{}, err
	}
	run, err := backend.queries.ResolveRun(ctx, backend.artifactRoot, runID)
	if err != nil {
		return ports.PublicationRun{}, err
	}
	if !run.Valid() || run.Root() != backend.artifactRoot || run.RunID() != runID {
		return ports.PublicationRun{}, fmt.Errorf("MCP run scope is invalid")
	}
	return run, nil
}

func (backend *mcpBackend) preflight(ctx context.Context) error {
	if backend == nil || ctx == nil || !backend.projectRoot.Valid() || !backend.artifactRoot.Valid() ||
		backend.application == nil || backend.queries == nil || backend.diagnostics == nil || backend.reports == nil || backend.enumerator == nil {
		return fmt.Errorf("MCP backend is unavailable")
	}
	return ctx.Err()
}

func projectMCPRunStatus(status mulgaeentry.RunStatusView, expectedSessionID domain.SessionID, expectedRunID domain.RunID) (map[string]any, error) {
	projection := mcpentry.RunStatusProjection{
		FailedRunRecovery: status.FailedRunRecovery,
		SessionID:         status.SessionID, RunID: status.RunID,
		RunState: status.RunState, HasRunState: status.HasRunState,
		PublicationState: status.PublicationState, RecoveryAction: status.RecoveryAction,
		FinalArtifactURI: status.FinalArtifactURI, HasFinalArtifact: status.HasFinalArtifact,
		ContentVerdict: status.ContentVerdict, CoverageStatus: status.CoverageStatus,
		CIDecision: status.CIDecision, HasAxes: status.HasAxes,
		DiagnosticSummary: status.DiagnosticSummary, HasDiagnosticSummary: status.HasDiagnosticSummary,
		RoleReports: make([]mcpentry.RoleReportProjection, 0, len(status.RoleReportURIs)),
	}
	for _, report := range status.RoleReportURIs {
		projection.RoleReports = append(projection.RoleReports, mcpentry.RoleReportProjection{Role: report.Role, URI: report.URI})
	}
	return mcpentry.ProjectRunStatus(projection, expectedSessionID, expectedRunID)
}

func newMCPFailure(stage string, class domain.FailureClass, reason string, cause error) error {
	failure, err := domain.NewFailure(stage, class, reason, cause)
	if err != nil {
		return errors.New("MCP failure invariant")
	}
	return failure
}

func (backend *mcpBackend) GetContext(ctx context.Context) (map[string]any, error) {
	if err := backend.preflight(ctx); err != nil {
		return nil, err
	}
	if backend.contextError != nil {
		return nil, backend.contextError
	}
	if backend.projectContexts == nil {
		return nil, newMCPFailure("query.context", domain.FailureInternal, "project context unavailable", nil)
	}
	result, err := backend.projectContexts.ReadLease(ctx, backend.contextLease)
	if err != nil {
		return nil, err
	}
	return map[string]any{"project_binding": result.ProjectBinding, "capabilities": result.Capabilities}, nil
}

// checkReviewProject keeps review admission bound to the server startup lease.
func (backend *mcpBackend) checkReviewProject(ctx context.Context, expected *string) error {
	if backend.contextLease == nil && expected == nil && backend.workspaceLease != nil {
		if err := backend.workspaceLease.Revalidate(ctx); err != nil {
			class := domain.FailureSecurityPolicy
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				class = domain.FailureCancelled
			}
			return newMCPFailure("mcp.admission", class, "startup workspace is unavailable or changed", err)
		}
		return nil
	}
	observed, err := backend.GetContext(ctx)
	if err != nil {
		return err
	}
	if expected != nil && observed["project_binding"] != *expected {
		return newMCPFailure("mcp.admission", domain.FailureConfiguration, "project_binding_mismatch", reviewrun.ErrProjectBindingMismatch)
	}
	return nil
}
