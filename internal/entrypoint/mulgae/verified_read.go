package mulgae

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/irootkernel/mulgae/internal/app"
	"github.com/irootkernel/mulgae/internal/app/query"
	"github.com/irootkernel/mulgae/internal/app/report"
	"github.com/irootkernel/mulgae/internal/app/reviewrun"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

type VerifiedReadRequest struct {
	RunID                  string
	FindingID              string
	Role                   string
	TargetSHA256           string
	SourceIdentitySHA256   string
	EvidenceIndex          int
	ExpectedProjectBinding string
	Page                   query.InspectionRequest
	Continuation           query.ContentContinuation
}

func parseVerifiedRead(command app.CommandName, arguments []string, requestID string) (Invocation, error) {
	allowed := map[string]bool{"--run": true, "--output": true, "--expected-project-binding": true, "--expected-publication-receipt": true}
	if command == app.CommandReadFinding || command == app.CommandReadReport || command == app.CommandExcerpt {
		for _, key := range []string{"--offset", "--expected-content-sha256"} {
			allowed[key] = true
		}
	} else {
		for _, key := range []string{"--severity", "--limit", "--cursor"} {
			allowed[key] = true
		}
	}
	if command == app.CommandReadFinding || command == app.CommandExcerpt {
		allowed["--finding"] = true
	}
	if command == app.CommandReadReport {
		allowed["--role"] = true
	}
	if command == app.CommandExcerpt {
		allowed["--current-target-sha256"] = true
		allowed["--source-identity-sha256"] = true
		allowed["--evidence-index"] = true
	}
	positional, options, err := parseOptions(arguments, allowed)
	if err != nil {
		return Invocation{}, err
	}
	if len(positional) != 0 {
		return Invocation{}, usageError("verified reads accept no positional arguments")
	}
	run, err := optionRunID(options)
	if err != nil {
		return Invocation{}, err
	}
	output, err := optionOutputFormat(options)
	if err != nil {
		return Invocation{}, err
	}
	request := VerifiedReadRequest{RunID: run, ExpectedProjectBinding: options["--expected-project-binding"]}
	for flag := range map[string]string{"--expected-project-binding": "expected_project_binding", "--expected-publication-receipt": "expected_publication_receipt", "--expected-content-sha256": "expected_content_sha256"} {
		if value, ok := options[flag]; ok {
			if _, err := domain.ParsePublicationReceipt(value); err != nil {
				return Invocation{}, usageError("invalid expected digest")
			}
		}
	}
	invocation := Invocation{command: command, availability: AvailabilityFoundation, requestID: requestID, outputFormat: output, hasRequestJSON: true}
	if command == app.CommandReadFinding || command == app.CommandReadReport || command == app.CommandExcerpt {
		request.FindingID = options["--finding"]
		if command != app.CommandReadReport && !queryFindingID(request.FindingID) {
			return Invocation{}, usageError("read-finding requires a canonical --finding")
		}
		if role, present := options["--role"]; present {
			if !domain.Role(role).Valid() {
				return Invocation{}, usageError("invalid role")
			}
			request.Role = role
		}
		if command == app.CommandExcerpt {
			request.TargetSHA256 = options["--current-target-sha256"]
			request.SourceIdentitySHA256 = options["--source-identity-sha256"]
			if (request.TargetSHA256 == "") == (request.SourceIdentitySHA256 == "") || request.TargetSHA256 != "" && !validSHA256Identifier(request.TargetSHA256) || request.SourceIdentitySHA256 != "" && !validSHA256Identifier(request.SourceIdentitySHA256) {
				return Invocation{}, usageError("excerpt requires exactly one canonical target or source identity")
			}
			if raw, present := options["--evidence-index"]; present {
				n, err := strconv.Atoi(raw)
				if err != nil || n < 0 || n >= 20 || strconv.Itoa(n) != raw {
					return Invocation{}, usageError("invalid evidence index")
				}
				request.EvidenceIndex = n
			}
			invocation.excerpt = &ExcerptRequest{runID: run, findingID: request.FindingID, currentTargetSHA256: request.TargetSHA256}
		}
		request.Continuation = query.ContentContinuation{PublicationReceipt: options["--expected-publication-receipt"], ContentSHA256: options["--expected-content-sha256"]}
		if raw, ok := options["--offset"]; ok {
			n, e := strconv.ParseInt(raw, 10, 64)
			if e != nil || n < 0 || strconv.FormatInt(n, 10) != raw {
				return Invocation{}, usageError("invalid offset")
			}
			request.Continuation.Offset = n
		}
		if err := request.Continuation.Validate(); err != nil {
			return Invocation{}, err
		}
	} else {
		severity := options["--severity"]
		if severity == "" {
			if command == app.CommandFindings {
				return Invocation{}, usageError("findings requires --severity")
			}
			severity = "low"
		}
		if !validMinimumSeverity(domain.Severity(severity)) {
			return Invocation{}, usageError("unsupported minimum severity")
		}
		request.Page = query.InspectionRequest{QueryKind: string(command), MinimumSeverity: domain.Severity(severity), Cursor: options["--cursor"], ExpectedPublicationReceipt: options["--expected-publication-receipt"]}
		if raw, ok := options["--limit"]; ok {
			n, e := strconv.Atoi(raw)
			if e != nil || n < 1 || n > query.MaxFindingPageSize {
				return Invocation{}, usageError("invalid page limit")
			}
			request.Page.Limit = n
		}
		if len(request.Page.Cursor) > 4096 {
			return Invocation{}, query.ErrCursorInvalid
		}
		if command == app.CommandFindings {
			invocation.findings = &FindingsRequest{runID: run, minimumSeverity: domain.Severity(severity)}
		}
	}
	invocation.verifiedRead = &request
	var evidenceIndex *int
	if command == app.CommandExcerpt {
		evidenceIndex = &request.EvidenceIndex
	}
	invocation.requestJSON, err = json.Marshal(struct {
		RequestID                  string       `json:"request_id"`
		Command                    string       `json:"command"`
		RunID                      string       `json:"run_id"`
		MinimumSeverity            string       `json:"minimum_severity,omitempty"`
		FindingID                  string       `json:"finding_id,omitempty"`
		OutputFormat               OutputFormat `json:"output_format"`
		ExpectedProjectBinding     string       `json:"expected_project_binding,omitempty"`
		ExpectedPublicationReceipt string       `json:"expected_publication_receipt,omitempty"`
		ExpectedContentSHA256      string       `json:"expected_content_sha256,omitempty"`
		Limit                      int          `json:"limit,omitempty"`
		Cursor                     string       `json:"cursor,omitempty"`
		Offset                     int64        `json:"offset,omitempty"`
		Role                       string       `json:"role,omitempty"`
		CurrentTargetSHA256        string       `json:"current_target_sha256,omitempty"`
		SourceIdentitySHA256       string       `json:"source_identity_sha256,omitempty"`
		EvidenceIndex              *int         `json:"evidence_index,omitempty"`
	}{requestID, string(command), run, string(request.Page.MinimumSeverity), request.FindingID, output, request.ExpectedProjectBinding, options["--expected-publication-receipt"], options["--expected-content-sha256"], request.Page.Limit, request.Page.Cursor, request.Continuation.Offset, request.Role, request.TargetSHA256, request.SourceIdentitySHA256, evidenceIndex})
	return invocation, err
}

func queryFindingID(value string) bool {
	if len(value) < 4 || len(value) > 64 || value[0] != 'F' {
		return false
	}
	for _, r := range value[1:] {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func (adapter publicationQueryAdapter) Inspect(ctx context.Context, run ports.PublicationRun, binding domain.ProjectBinding, request query.InspectionRequest) (query.Inspection, error) {
	return adapter.service.Inspect(ctx, run, binding, request)
}
func (adapter publicationQueryAdapter) ReadFinding(ctx context.Context, run ports.PublicationRun, binding domain.ProjectBinding, id string, continuation query.ContentContinuation) (query.ContentChunk, error) {
	return adapter.service.ReadFinding(ctx, run, binding, id, continuation)
}

func (adapter publicationQueryAdapter) ReadReport(ctx context.Context, run ports.PublicationRun, binding domain.ProjectBinding, role string, continuation query.ContentContinuation) (query.ContentChunk, error) {
	return report.ReadContent(ctx, adapter.service, run, binding, role, continuation)
}
func (adapter publicationQueryAdapter) ReadEvidence(ctx context.Context, run ports.PublicationRun, binding domain.ProjectBinding, finding, target string, index int, continuation query.ContentContinuation) (query.ContentChunk, error) {
	return adapter.service.ReadEvidence(ctx, run, binding, finding, target, index, continuation)
}

func (adapter publicationQueryAdapter) ReadSourceEvidence(ctx context.Context, run ports.PublicationRun, binding domain.ProjectBinding, finding, source string, index int, continuation query.ContentContinuation) (query.ContentChunk, error) {
	return adapter.service.ReadSourceEvidence(ctx, run, binding, finding, source, index, continuation)
}

func (adapter publicationQueryAdapter) ReadSourceImage(ctx context.Context, run ports.PublicationRun, binding domain.ProjectBinding, source, side, path string, continuation query.ContentContinuation) (query.ContentChunk, error) {
	return adapter.service.ReadSourceImage(ctx, run, binding, source, side, path, continuation)
}

func (application *Application) handleVerifiedRead(ctx context.Context, invocation Invocation, root string) (result execution) {
	fail := func(err error) execution {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureArtifact)}
	}
	if invocation.verifiedRead == nil || application.projectContexts == nil {
		return fail(errors.New("verified read dependencies unavailable"))
	}
	request := *invocation.verifiedRead
	anchor, err := ports.NewAnchoredRoot(root)
	if err != nil {
		return fail(err)
	}
	lease, err := application.projectContexts.Open(ctx, anchor)
	if err != nil {
		return fail(err)
	}
	defer func() {
		if err := lease.Close(); err != nil {
			result = fail(typedHandlerFailure("query.context", domain.FailureSecurityPolicy, "project binding close failed", err))
		}
	}()
	project, err := application.projectContexts.ReadLease(ctx, lease)
	if err != nil {
		return fail(err)
	}
	if request.ExpectedProjectBinding != "" && request.ExpectedProjectBinding != project.ProjectBinding {
		return fail(reviewrun.ErrProjectBindingMismatch)
	}
	binding, err := domain.ParseProjectBinding(project.ProjectBinding)
	if err != nil {
		return fail(err)
	}
	_, run, err := application.resolvePublicationRun(ctx, root, request.RunID)
	if err != nil {
		if invocation.Command() == app.CommandInspect && request.Page.Cursor == "" && request.Page.ExpectedPublicationReceipt == "" && solelyMissingPublication(err) {
			diagnostic, e := application.inspectDiagnostic(ctx, request, root)
			if e != nil {
				return fail(e)
			}
			if _, e = application.projectContexts.ReadLease(ctx, lease); e != nil {
				return fail(e)
			}
			return diagnostic
		}
		return fail(err)
	}
	var value any
	human := ""
	if invocation.Command() == app.CommandReadFinding || invocation.Command() == app.CommandReadReport || invocation.Command() == app.CommandExcerpt {
		var chunk query.ContentChunk
		var e error
		switch invocation.Command() {
		case app.CommandReadFinding:
			chunk, e = application.publicationQueries.ReadFinding(ctx, run, binding, request.FindingID, request.Continuation)
		case app.CommandReadReport:
			chunk, e = application.publicationQueries.ReadReport(ctx, run, binding, request.Role, request.Continuation)
		case app.CommandExcerpt:
			if request.SourceIdentitySHA256 != "" {
				chunk, e = application.publicationQueries.ReadSourceEvidence(ctx, run, binding, request.FindingID, request.SourceIdentitySHA256, request.EvidenceIndex, request.Continuation)
			} else {
				chunk, e = application.publicationQueries.ReadEvidence(ctx, run, binding, request.FindingID, request.TargetSHA256, request.EvidenceIndex, request.Continuation)
			}
		}
		if e != nil {
			return fail(e)
		}
		value = chunk
		human = chunk.Content
	} else {
		page, e := application.publicationQueries.Inspect(ctx, run, binding, request.Page)
		if e != nil {
			return fail(e)
		}
		if page.RunID != request.RunID || page.ReturnedCount != len(page.Findings) || page.FindingCount < page.ReturnedCount || len(page.Findings) > query.MaxFindingPageSize {
			return fail(errors.New("inspection projection is invalid"))
		}
		for _, f := range page.Findings {
			if !validFindingID(f.ID) || !domain.Severity(f.Severity).Valid() || f.Title == "" || strings.ContainsAny(f.Title, "\x00\r\n") {
				return fail(errors.New("inspection finding projection is invalid"))
			}
		}
		kind := "review_inspected"
		if invocation.Command() == app.CommandFindings {
			kind = "findings_listed"
		}
		value = struct {
			Kind string `json:"kind"`
			query.Inspection
		}{kind, page}
		human = fmt.Sprintf("review_artifact_uri: %s\nfinding_count: %d", page.ReviewArtifactURI, page.FindingCount)
		if page.NextCursor != "" {
			human += fmt.Sprintf("\nreturned_count: %d\nnext_cursor: %s", page.ReturnedCount, page.NextCursor)
		}
		for _, f := range page.Findings {
			human += fmt.Sprintf("\n%s [%s] %s", f.ID, f.Severity, f.Title)
		}
	}
	if _, err := application.projectContexts.ReadLease(ctx, lease); err != nil {
		return fail(err)
	}
	data, err := json.Marshal(value)
	if err != nil {
		return fail(err)
	}
	return execution{data: data, human: []byte(human)}
}
