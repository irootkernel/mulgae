//go:build darwin && arm64

package composition

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"net/url"
	"os"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/irootkernel/mulgae/internal/adapters/filesystem"
	"github.com/irootkernel/mulgae/internal/domain"
	mcpentry "github.com/irootkernel/mulgae/internal/entrypoint/mcp"
	mulgaeentry "github.com/irootkernel/mulgae/internal/entrypoint/mulgae"
	"github.com/irootkernel/mulgae/internal/ports"
)

type mcpBackend struct {
	projectRoot  ports.AnchoredRoot
	artifactRoot ports.AnchoredRoot
	application  *mulgaeentry.Application
	queries      mulgaeentry.PublicationQueryService
	reports      mulgaeentry.PublicationReportService
	enumerator   *filesystem.RunSelector
}

func newMCPBackend(
	projectRoot, artifactRoot ports.AnchoredRoot,
	application *mulgaeentry.Application,
	queries mulgaeentry.PublicationQueryService,
	reports mulgaeentry.PublicationReportService,
	enumerator *filesystem.RunSelector,
) (*mcpBackend, error) {
	if !projectRoot.Valid() || !artifactRoot.Valid() || application == nil || queries == nil || reports == nil || enumerator == nil {
		return nil, fmt.Errorf("MCP backend: incomplete dependencies")
	}
	return &mcpBackend{
		projectRoot: projectRoot, artifactRoot: artifactRoot, application: application,
		queries: queries, reports: reports, enumerator: enumerator,
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
	fileSets := make([]any, 0, len(result.FileSets))
	for _, set := range result.FileSets {
		var totalBytes int64
		for _, file := range set.Files {
			if file.Size > 0 && totalBytes > math.MaxInt64-file.Size {
				return nil, newMCPFailure("mcp.preflight", domain.FailureInternal, "MCP preflight file summary overflowed", nil)
			}
			totalBytes += file.Size
		}
		fileSets = append(fileSets, map[string]any{
			"id": set.ID, "policy_identity": set.PolicyIdentity,
			"file_count": len(set.Files), "total_bytes": totalBytes,
		})
	}
	return map[string]any{
		"status": result.Status, "qualification": result.Qualification, "target": result.Target,
		"agy_permission_mode": result.AGYPermissionMode, "warnings": result.Warnings,
		"file_sets": fileSets, "generated_files": result.GeneratedFiles,
		"transmissions": result.Transmissions, "budget": result.Budget,
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
	return mcpentry.BackendResult{Outcome: outcome, Data: map[string]any{
		"session_id": result.SessionID(), "run_id": result.RunID(),
		"run_manifest_uri": result.RunManifestURI(), "review_artifact_uri": result.ReviewArtifactURI(),
		"role_report_uris": reports, "report_resource_uri": reportResourceURI(result.RunID(), 0),
		"terminal_exit_code": int(decision.Code()), "reasons": reasons,
	}}, nil
}

func mcpReviewArguments(input mcpentry.RunReviewInput) ([]string, error) {
	arguments := []string{"review"}
	switch input.Target.Kind {
	case "workspace", "stage", "dirty":
		arguments = append(arguments, "--"+input.Target.Kind)
	case "diff", "patch":
		arguments = append(arguments, "--"+input.Target.Kind, input.Target.Value)
	default:
		return nil, fmt.Errorf("MCP review target is invalid")
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
		data, err := runStatusData(status, candidate.SessionID, candidate.RunID)
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
		return nil, err
	}
	status, err := backend.queries.ReadRunStatus(ctx, run)
	if err != nil {
		return nil, err
	}
	return runStatusData(status, run.SessionID(), run.RunID())
}

func (backend *mcpBackend) ListFindings(ctx context.Context, input mcpentry.ListFindingsInput) (map[string]any, error) {
	if err := backend.preflight(ctx); err != nil {
		return nil, err
	}
	run, err := backend.resolveRun(ctx, input.RunID)
	if err != nil {
		return nil, err
	}
	view, err := backend.queries.ListFindings(ctx, run, domain.Severity(input.MinimumSeverity))
	if err != nil {
		return nil, err
	}
	artifactPath, pathErr := ports.NewSafeRelativePath(view.ReviewArtifactURI)
	if view.RunID != input.RunID || !validMCPSHA256(view.TargetSHA256) || pathErr != nil || artifactPath.String() != view.ReviewArtifactURI ||
		!strings.HasPrefix(view.ReviewArtifactURI, ".mulgae/") || len(view.Findings) > 1000 {
		return nil, fmt.Errorf("MCP findings projection is invalid")
	}
	minimum := domain.Severity(input.MinimumSeverity)
	findings := make([]any, 0, len(view.Findings))
	for _, finding := range view.Findings {
		if !validMCPFindingID(finding.ID) || !finding.Severity.Valid() || finding.Severity.Rank() < minimum.Rank() ||
			finding.Title == "" || strings.ContainsAny(finding.Title, "\x00\r\n") {
			return nil, fmt.Errorf("MCP finding projection is invalid")
		}
		findings = append(findings, map[string]any{
			"id": finding.ID, "severity": string(finding.Severity), "title": finding.Title,
			"evidence_resource_uri": evidenceResourceURI(view.RunID, finding.ID, view.TargetSHA256, 0),
		})
	}
	return map[string]any{
		"run_id": view.RunID, "minimum_severity": input.MinimumSeverity,
		"target_sha256": view.TargetSHA256, "finding_count": len(findings),
		"findings": findings, "review_artifact_uri": view.ReviewArtifactURI,
	}, nil
}

func (backend *mcpBackend) ReadResource(ctx context.Context, rawURI string) (mcpentry.ResourceResult, error) {
	if err := backend.preflight(ctx); err != nil {
		return mcpentry.ResourceResult{}, err
	}
	request, err := parseMCPResourceURI(rawURI)
	if err != nil {
		return mcpentry.ResourceResult{}, newMCPFailure("mcp.resource", domain.FailureConfiguration, "MCP resource URI is invalid", err)
	}
	run, err := backend.resolveRun(ctx, request.runID)
	if err != nil {
		return mcpentry.ResourceResult{}, err
	}
	var contents []byte
	mimeType := "application/octet-stream"
	text := false
	switch request.kind {
	case "report":
		rendered, renderErr := backend.reports.Render(ctx, run)
		if renderErr != nil {
			return mcpentry.ResourceResult{}, renderErr
		}
		if rendered.RunID != request.runID || len(rendered.Markdown) == 0 || int64(len(rendered.Markdown)) > mulgaeentry.MaxReportMarkdownBytes || !utf8.Valid(rendered.Markdown) {
			return mcpentry.ResourceResult{}, newMCPFailure("mcp.resource", domain.FailureArtifact, "verified report projection is invalid", nil)
		}
		contents, mimeType, text = rendered.Markdown, "text/markdown", true
	case "evidence":
		contents, err = backend.queries.RenderExcerpt(ctx, run, request.findingID, request.targetSHA256)
		if err != nil {
			return mcpentry.ResourceResult{}, err
		}
		if len(contents) == 0 || int64(len(contents)) > ports.PublicationStoreMaxReadBytes {
			return mcpentry.ResourceResult{}, newMCPFailure("mcp.resource", domain.FailureArtifact, "verified evidence projection is invalid", nil)
		}
	default:
		return mcpentry.ResourceResult{}, newMCPFailure("mcp.resource", domain.FailureConfiguration, "MCP resource kind is invalid", nil)
	}
	return chunkMCPResource(request, rawURI, mimeType, contents, text)
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
		backend.application == nil || backend.queries == nil || backend.reports == nil || backend.enumerator == nil {
		return fmt.Errorf("MCP backend is unavailable")
	}
	return ctx.Err()
}

func runStatusData(status mulgaeentry.RunStatusView, expectedSessionID domain.SessionID, expectedRunID domain.RunID) (map[string]any, error) {
	sessionID, sessionErr := domain.ParseSessionID(status.SessionID)
	runID, runErr := domain.ParseRunID(status.RunID)
	if sessionErr != nil || runErr != nil || sessionID != expectedSessionID || runID != expectedRunID ||
		!status.PublicationState.Valid() || !status.RecoveryAction.Valid() {
		return nil, fmt.Errorf("MCP run status projection is invalid")
	}
	if err := validateMCPPublicationPair(status); err != nil {
		return nil, err
	}
	if status.HasRunState != (status.RunState != "") || status.HasRunState && !status.RunState.Valid() ||
		status.HasFinalArtifact != (status.FinalArtifactURI != "") ||
		status.HasAxes != (status.ContentVerdict != "" && status.CoverageStatus != "" && status.CIDecision != "") {
		return nil, fmt.Errorf("MCP run status projection is inconsistent")
	}
	if status.HasFinalArtifact {
		path, err := ports.NewSafeRelativePath(status.FinalArtifactURI)
		if err != nil || path.String() != status.FinalArtifactURI || !strings.HasPrefix(status.FinalArtifactURI, ".mulgae/") {
			return nil, fmt.Errorf("MCP run status artifact URI is invalid")
		}
	}
	if status.HasAxes && (!status.ContentVerdict.Valid() || !status.CoverageStatus.Valid() || !status.CIDecision.Valid()) {
		return nil, fmt.Errorf("MCP run status outcome is invalid")
	}
	if status.PublicationState == domain.PublicationCommitted {
		if !status.HasRunState || !status.HasFinalArtifact || !status.HasAxes {
			return nil, fmt.Errorf("MCP committed run status is incomplete")
		}
	} else if status.HasFinalArtifact || status.HasAxes || len(status.RoleReportURIs) != 0 {
		return nil, fmt.Errorf("MCP non-committed run status exposed committed fields")
	}
	data := map[string]any{
		"session_id": status.SessionID, "run_id": status.RunID,
		"publication_status": string(status.PublicationState), "recovery_action": string(status.RecoveryAction),
	}
	if status.PublicationState == domain.PublicationCommitted {
		data["report_resource_uri"] = reportResourceURI(status.RunID, 0)
	} else {
		data["report_resource_uri"] = nil
	}
	if status.HasRunState {
		data["run_state"] = string(status.RunState)
	} else {
		data["run_state"] = nil
	}
	if status.HasFinalArtifact {
		data["final_artifact_uri"] = status.FinalArtifactURI
	} else {
		data["final_artifact_uri"] = nil
	}
	if status.HasAxes {
		data["content_verdict"] = string(status.ContentVerdict)
		data["coverage_status"] = string(status.CoverageStatus)
		data["ci_decision"] = string(status.CIDecision)
	} else {
		data["content_verdict"], data["coverage_status"], data["ci_decision"] = nil, nil, nil
	}
	roleReports := make([]any, 0, len(status.RoleReportURIs))
	rolePrefix := ".mulgae/" + sessionID.String() + "/" + runID.String() + "/role-reports/"
	seenRoles := make(map[string]struct{}, len(status.RoleReportURIs))
	for _, report := range status.RoleReportURIs {
		role := domain.Role(report.Role)
		if !role.Valid() || report.URI != rolePrefix+report.Role+".md" {
			return nil, fmt.Errorf("MCP run status role report URI is invalid")
		}
		if _, duplicate := seenRoles[report.Role]; duplicate {
			return nil, fmt.Errorf("MCP run status role report URI is duplicated")
		}
		seenRoles[report.Role] = struct{}{}
		roleReports = append(roleReports, map[string]any{"role": report.Role, "uri": report.URI})
	}
	data["role_report_uris"] = roleReports
	return data, nil
}

func validateMCPPublicationPair(status mulgaeentry.RunStatusView) error {
	switch status.PublicationState {
	case domain.PublicationNotPublished:
		if status.RecoveryAction != domain.RecoveryActionResumeCollection &&
			status.RecoveryAction != domain.RecoveryActionRestageValidatedCandidate {
			return fmt.Errorf("MCP not-published run status recovery action is invalid")
		}
	case domain.PublicationStaged:
		if status.RecoveryAction != domain.RecoveryActionInstallStagedFinal {
			return fmt.Errorf("MCP staged run status recovery action is invalid")
		}
	case domain.PublicationInstalled:
		if status.RecoveryAction != domain.RecoveryActionCommitCompositeEpoch {
			return fmt.Errorf("MCP installed run status recovery action is invalid")
		}
	case domain.PublicationCommitted:
		if status.RecoveryAction != domain.RecoveryActionReconstructCompletedStatus ||
			status.RunState != domain.RunCompleted && status.RunState != domain.RunDegraded && status.RunState != domain.RunFailed {
			return fmt.Errorf("MCP committed run status state is invalid")
		}
	default:
		return fmt.Errorf("MCP run status publication state is unreadable")
	}
	return nil
}

func validMCPFindingID(value string) bool {
	if len(value) < 4 || len(value) > 5 || value[0] != 'F' {
		return false
	}
	for _, character := range value[1:] {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func validMCPSHA256(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, character := range value[len("sha256:"):] {
		if character < '0' || character > '9' {
			if character < 'a' || character > 'f' {
				return false
			}
		}
	}
	return true
}

type mcpResourceRequest struct {
	kind         string
	runID        string
	findingID    string
	targetSHA256 string
	offset       int
}

func parseMCPResourceURI(raw string) (mcpResourceRequest, error) {
	if len(raw) == 0 || len(raw) > 8192 {
		return mcpResourceRequest{}, fmt.Errorf("resource URI length is invalid")
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "mulgae" || parsed.Host != "runs" || parsed.User != nil || parsed.Fragment != "" {
		return mcpResourceRequest{}, fmt.Errorf("resource URI authority is invalid")
	}
	segments := strings.Split(strings.TrimPrefix(parsed.EscapedPath(), "/"), "/")
	if len(segments) != 2 && len(segments) != 4 {
		return mcpResourceRequest{}, fmt.Errorf("resource URI path is invalid")
	}
	for index, segment := range segments {
		decoded, decodeErr := url.PathUnescape(segment)
		if decodeErr != nil || decoded != segment {
			return mcpResourceRequest{}, fmt.Errorf("resource URI path encoding is invalid")
		}
		segments[index] = decoded
	}
	if _, err := domain.ParseRunID(segments[0]); err != nil {
		return mcpResourceRequest{}, fmt.Errorf("resource run ID is invalid")
	}
	query, err := url.ParseQuery(parsed.RawQuery)
	if err != nil {
		return mcpResourceRequest{}, fmt.Errorf("resource URI query is invalid")
	}
	offset, err := parseMCPResourceOffset(query)
	if err != nil {
		return mcpResourceRequest{}, err
	}
	request := mcpResourceRequest{runID: segments[0], offset: offset}
	switch {
	case len(segments) == 2 && segments[1] == "report":
		if len(query) > 1 || query.Has("target_sha256") {
			return mcpResourceRequest{}, fmt.Errorf("report resource query is invalid")
		}
		request.kind = "report"
		if raw != reportResourceURI(request.runID, request.offset) {
			return mcpResourceRequest{}, fmt.Errorf("report resource URI is not canonical")
		}
	case len(segments) == 4 && segments[1] == "findings" && segments[3] == "evidence":
		if !validMCPFindingID(segments[2]) || len(query) > 2 || len(query["target_sha256"]) != 1 ||
			!validMCPSHA256(query.Get("target_sha256")) {
			return mcpResourceRequest{}, fmt.Errorf("evidence resource query is invalid")
		}
		request.kind, request.findingID, request.targetSHA256 = "evidence", segments[2], query.Get("target_sha256")
		if raw != evidenceResourceURI(request.runID, request.findingID, request.targetSHA256, request.offset) {
			return mcpResourceRequest{}, fmt.Errorf("evidence resource URI is not canonical")
		}
	default:
		return mcpResourceRequest{}, fmt.Errorf("resource URI path is invalid")
	}
	return request, nil
}

func parseMCPResourceOffset(query url.Values) (int, error) {
	values, present := query["offset"]
	if !present {
		return 0, nil
	}
	if len(values) != 1 || values[0] == "" || len(values[0]) > 8 {
		return 0, fmt.Errorf("resource offset is invalid")
	}
	offset, err := strconv.Atoi(values[0])
	if err != nil || offset < 0 || int64(offset) > ports.PublicationStoreMaxReadBytes {
		return 0, fmt.Errorf("resource offset is invalid")
	}
	return offset, nil
}

func reportResourceURI(runID string, offset int) string {
	uri := "mulgae://runs/" + runID + "/report"
	if offset != 0 {
		uri += "?offset=" + strconv.Itoa(offset)
	}
	return uri
}

func evidenceResourceURI(runID, findingID, targetSHA256 string, offset int) string {
	uri := "mulgae://runs/" + runID + "/findings/" + findingID + "/evidence?target_sha256=" + url.QueryEscape(targetSHA256)
	if offset != 0 {
		uri += "&offset=" + strconv.Itoa(offset)
	}
	return uri
}

func chunkMCPResource(
	request mcpResourceRequest,
	rawURI, mimeType string,
	contents []byte,
	text bool,
) (mcpentry.ResourceResult, error) {
	if !canonicalMCPResourceOffset(contents, text, request.offset) {
		return mcpentry.ResourceResult{}, newMCPFailure("mcp.resource", domain.FailureConfiguration, "resource offset is invalid", nil)
	}
	end := mcpResourceChunkEnd(contents, text, request.offset)
	chunk := append([]byte(nil), contents[request.offset:end]...)
	digest := sha256.Sum256(contents)
	var nextURI any
	if end < len(contents) {
		if request.kind == "report" {
			nextURI = reportResourceURI(request.runID, end)
		} else {
			nextURI = evidenceResourceURI(request.runID, request.findingID, request.targetSHA256, end)
		}
	}
	result := mcpentry.ResourceResult{
		URI: rawURI, MIMEType: mimeType,
		Meta: map[string]any{
			"io.mulgae/sha256": "sha256:" + hex.EncodeToString(digest[:]),
			"io.mulgae/offset": request.offset, "io.mulgae/chunkBytes": len(chunk),
			"io.mulgae/totalBytes": len(contents), "io.mulgae/complete": end == len(contents),
			"io.mulgae/nextURI": nextURI,
		},
	}
	if text {
		result.Text = string(chunk)
	} else {
		result.Blob = chunk
	}
	return result, nil
}

func canonicalMCPResourceOffset(contents []byte, text bool, offset int) bool {
	if offset < 0 || offset >= len(contents) {
		return false
	}
	for current := 0; current < len(contents); current = mcpResourceChunkEnd(contents, text, current) {
		if current == offset {
			return true
		}
		if current > offset {
			return false
		}
	}
	return false
}

func mcpResourceChunkEnd(contents []byte, text bool, offset int) int {
	end := offset + mcpentry.MaxResourceChunkBytes
	if end > len(contents) {
		end = len(contents)
	}
	if text {
		for end < len(contents) && end > offset && !utf8.RuneStart(contents[end]) {
			end--
		}
	}
	return end
}

func newMCPFailure(stage string, class domain.FailureClass, reason string, cause error) error {
	failure, err := domain.NewFailure(stage, class, reason, cause)
	if err != nil {
		return errors.New("MCP failure invariant")
	}
	return failure
}
