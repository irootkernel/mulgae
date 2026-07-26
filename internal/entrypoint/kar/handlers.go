package kar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/irootkernel/kkachi-agent-review/internal/adapters/cli"
	adapterconfig "github.com/irootkernel/kkachi-agent-review/internal/adapters/config"
	"github.com/irootkernel/kkachi-agent-review/internal/app"
	appconfig "github.com/irootkernel/kkachi-agent-review/internal/app/config"
	appdelta "github.com/irootkernel/kkachi-agent-review/internal/app/delta"
	"github.com/irootkernel/kkachi-agent-review/internal/app/doctor"
	appfollowup "github.com/irootkernel/kkachi-agent-review/internal/app/followup"
	apphelp "github.com/irootkernel/kkachi-agent-review/internal/app/help"
	appinit "github.com/irootkernel/kkachi-agent-review/internal/app/init"
	"github.com/irootkernel/kkachi-agent-review/internal/app/providers"
	appreplay "github.com/irootkernel/kkachi-agent-review/internal/app/rerun"
	"github.com/irootkernel/kkachi-agent-review/internal/app/reviewrun"
	approles "github.com/irootkernel/kkachi-agent-review/internal/app/roles"
	appschema "github.com/irootkernel/kkachi-agent-review/internal/app/schema"
	"github.com/irootkernel/kkachi-agent-review/internal/domain"
	"github.com/irootkernel/kkachi-agent-review/internal/ports"
)

const (
	doctorResultSchema = "https://kar.local/schemas/kar-doctor-result.v2.schema.json"
)

type applicationCommandHandler func(*Application, context.Context, Invocation, string) execution

func (application *Application) execute(ctx context.Context, invocation Invocation, canonicalProjectRoot string) execution {
	handler, present := application.handlers[invocation.Command()]
	if !present || handler == nil {
		return execution{failure: executionFailureFor(invocation.Command(), errors.New("unsupported foundation dispatch"), domain.FailureInternal)}
	}
	return handler(application, ctx, invocation, canonicalProjectRoot)
}

func applicationCommandHandlers() map[app.CommandName]applicationCommandHandler {
	return map[app.CommandName]applicationCommandHandler{
		app.CommandHelp: func(application *Application, ctx context.Context, invocation Invocation, _ string) execution {
			return application.handleHelp(ctx, invocation)
		},
		app.CommandSchema: func(application *Application, ctx context.Context, invocation Invocation, _ string) execution {
			return application.handleSchema(ctx, invocation)
		},
		app.CommandInit: func(application *Application, ctx context.Context, invocation Invocation, _ string) execution {
			return application.handleInit(ctx, invocation)
		},
		app.CommandConfig: func(application *Application, ctx context.Context, invocation Invocation, _ string) execution {
			return application.handleConfig(ctx, invocation)
		},
		app.CommandDoctor: func(application *Application, ctx context.Context, invocation Invocation, _ string) execution {
			return application.handleDoctor(ctx, invocation)
		},
		app.CommandProviders: func(application *Application, ctx context.Context, invocation Invocation, _ string) execution {
			return application.handleProviders(ctx, invocation)
		},
		app.CommandRoles: func(application *Application, _ context.Context, invocation Invocation, _ string) execution {
			return application.handleRoles(invocation)
		},
		app.CommandStatus: func(application *Application, ctx context.Context, invocation Invocation, root string) execution {
			return application.handleStatus(ctx, invocation, root)
		},
		app.CommandReport: func(application *Application, ctx context.Context, invocation Invocation, root string) execution {
			return application.handleReport(ctx, invocation, root)
		},
		app.CommandFindings: func(application *Application, ctx context.Context, invocation Invocation, root string) execution {
			return application.handleFindings(ctx, invocation, root)
		},
		app.CommandExcerpt: func(application *Application, ctx context.Context, invocation Invocation, root string) execution {
			return application.handleExcerpt(ctx, invocation, root)
		},
		app.CommandReview: func(application *Application, ctx context.Context, invocation Invocation, root string) execution {
			return application.handleReview(ctx, invocation, root)
		},
		app.CommandPrompt: func(application *Application, _ context.Context, invocation Invocation, _ string) execution {
			return application.handlePrompt(invocation)
		},
		app.CommandFollowup: func(application *Application, ctx context.Context, invocation Invocation, _ string) execution {
			return application.handleFollowup(ctx, invocation)
		},
		app.CommandDelta: func(application *Application, ctx context.Context, invocation Invocation, _ string) execution {
			return application.handleDelta(ctx, invocation)
		},
		app.CommandRerun: func(application *Application, ctx context.Context, invocation Invocation, _ string) execution {
			return application.handleRerun(ctx, invocation)
		},
		app.CommandClean: func(application *Application, ctx context.Context, invocation Invocation, _ string) execution {
			return application.handleClean(ctx, invocation)
		},
		app.CommandExport: func(application *Application, ctx context.Context, invocation Invocation, root string) execution {
			return application.handleExport(ctx, invocation, root)
		},
	}
}

func validateApplicationCommandHandlers(specs []cli.CommandSpec, handlers map[app.CommandName]applicationCommandHandler) error {
	if err := cli.ValidateCommandSpecs(specs); err != nil {
		return err
	}
	if len(handlers) != len(specs) {
		return fmt.Errorf("got %d command handlers, want %d", len(handlers), len(specs))
	}
	for _, spec := range specs {
		handler, present := handlers[spec.Command()]
		if !present || handler == nil {
			return fmt.Errorf("command %q requires a handler", spec.Command())
		}
	}
	for command := range handlers {
		if !command.Valid() {
			return fmt.Errorf("handler registered for unknown command %q", command)
		}
	}
	return nil
}

func cloneApplicationHandlers(handlers map[app.CommandName]applicationCommandHandler) map[app.CommandName]applicationCommandHandler {
	clone := make(map[app.CommandName]applicationCommandHandler, len(handlers))
	for command, handler := range handlers {
		clone[command] = handler
	}
	return clone
}

func (application *Application) handleReview(ctx context.Context, invocation Invocation, canonicalProjectRoot string) execution {
	request, available := invocation.Review()
	if !available {
		return execution{failure: executionFailureFor(invocation.Command(), errors.New("missing request"), domain.FailureInternal)}
	}
	if nilApplicationDependency(application.reviewRuns) {
		return execution{failure: executionFailureFor(invocation.Command(), errors.New("review provider authority unavailable"), domain.FailureProviderUnavailable)}
	}
	projectRoot, _, err := publicationRoots(canonicalProjectRoot)
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureConfiguration)}
	}
	reviewRuns := application.reviewRuns
	if preparer, ok := reviewRuns.(ReviewRunServicePreparer); ok {
		reviewRuns, err = preparer.PrepareReviewRun(ctx, projectRoot)
		if err != nil {
			return execution{failure: executionFailureFor(invocation.Command(), classifyHandlerFailure("cli.review", domain.FailureProviderUnavailable, "review service failed", err), domain.FailureProviderUnavailable)}
		}
	}
	artifactDirectory, err := ports.NewSafeRelativePath(".kar")
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureInternal)}
	}
	if err := application.writer.EnsurePrivateDir(projectRoot, artifactDirectory); err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), classifyHandlerFailure("cli.review", domain.FailureArtifact, "private publication root unavailable", err), domain.FailureArtifact)}
	}
	result, err := reviewRuns.StartReviewRun(ctx, request, projectRoot)
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), classifyHandlerFailure("cli.review", domain.FailureProviderUnavailable, "review service failed", err), domain.FailureProviderUnavailable)}
	}
	if err := result.Validate(); err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureInternal)}
	}
	sessionID, runID := result.SessionID(), result.RunID()
	runManifestURI, reviewArtifactURI := result.RunManifestURI(), result.ReviewArtifactURI()
	exit, reasons, err := committedTerminalOutcome(result.TerminalExit())
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureInternal)}
	}
	data, err := json.Marshal(struct {
		Kind              string `json:"kind"`
		SessionID         string `json:"session_id"`
		RunID             string `json:"run_id"`
		RunManifestURI    string `json:"run_manifest_uri"`
		ReviewArtifactURI string `json:"review_artifact_uri"`
	}{"review_started", sessionID, runID, runManifestURI, reviewArtifactURI})
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureInternal)}
	}
	return execution{
		human:            []byte("review started: " + runID),
		data:             data,
		exit:             exit,
		committedReasons: reasons,
	}
}

func (application *Application) handlePrompt(invocation Invocation) execution {
	if _, available := invocation.Prompt(); !available {
		return execution{failure: executionFailureFor(invocation.Command(), errors.New("missing request"), domain.FailureInternal)}
	}
	return execution{failure: executionFailureFor(invocation.Command(), errors.New("prompt artifact authority unavailable"), domain.FailureArtifact)}
}
func (application *Application) handleFollowup(ctx context.Context, invocation Invocation) execution {
	request, available := invocation.Followup()
	if !available {
		return execution{failure: executionFailureFor(invocation.Command(), errors.New("missing request"), domain.FailureInternal)}
	}
	if application.followupRuns == nil {
		return execution{failure: executionFailureFor(invocation.Command(), errors.New("followup service unavailable"), domain.FailureProviderUnavailable)}
	}
	sourceRunID, err := domain.ParseRunID(request.SourceRunID())
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureConfiguration)}
	}
	target, err := followupTarget(request.Target())
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureConfiguration)}
	}
	var objective *string
	if value, present := request.Objective(); present {
		objective = &value
	}
	var role *domain.Role
	if value, present := request.Role(); present {
		parsed := domain.Role(value)
		if !parsed.Valid() {
			return execution{failure: executionFailureFor(invocation.Command(), errors.New("invalid role"), domain.FailureConfiguration)}
		}
		role = &parsed
	}
	result, err := application.followupRuns.StartFollowupRun(ctx, appfollowup.Request{
		SourceRunID: sourceRunID, FindingID: request.FindingID(), Target: target, Objective: objective, Role: role,
	})
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureArtifact)}
	}
	sessionID, runID, artifact, resolution := result.SessionID, result.RunID, result.ArtifactURI, result.FollowupResolution
	if _, err := domain.ParseSessionID(sessionID); err != nil || !validCommandRunID(runID) || !validCommandURI(artifact) ||
		!resolution.Valid() {
		return execution{failure: executionFailureFor(invocation.Command(), errors.New("invalid followup result"), domain.FailureInternal)}
	}
	exit, reasons, err := committedTerminalOutcome(result.TerminalExit)
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureInternal)}
	}
	data, err := json.Marshal(struct {
		Kind                string `json:"kind"`
		SessionID           string `json:"session_id"`
		RunID               string `json:"run_id"`
		FollowupArtifactURI string `json:"followup_artifact_uri"`
		Resolution          string `json:"resolution"`
	}{"followup_started", sessionID, runID, artifact, string(resolution)})
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureInternal)}
	}
	return execution{human: []byte("followup started: " + runID + "\nresolution: " + string(resolution)), data: data, exit: exit, committedReasons: reasons}
}

func (application *Application) handleDelta(ctx context.Context, invocation Invocation) execution {
	request, available := invocation.Delta()
	if !available {
		return execution{failure: executionFailureFor(invocation.Command(), errors.New("missing request"), domain.FailureInternal)}
	}
	if application.deltaRuns == nil {
		return execution{failure: executionFailureFor(invocation.Command(), errors.New("delta service unavailable"), domain.FailureProviderUnavailable)}
	}
	sourceRunID, err := domain.ParseRunID(request.SourceRunID())
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureConfiguration)}
	}
	target, err := deltaTarget(request.Target())
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureConfiguration)}
	}
	roles := make([]domain.Role, len(request.Roles()))
	for index, value := range request.Roles() {
		roles[index] = domain.Role(value)
		if !roles[index].Valid() {
			return execution{failure: executionFailureFor(invocation.Command(), errors.New("invalid role"), domain.FailureConfiguration)}
		}
	}
	result, err := application.deltaRuns.StartDeltaRun(ctx, appdelta.StartRequest{SourceRunID: sourceRunID, Target: target, Roles: roles})
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureArtifact)}
	}
	sessionID, runID, artifact := result.SessionID, result.RunID, result.ArtifactURI
	if _, err := domain.ParseSessionID(sessionID); err != nil || !validCommandRunID(runID) || !validCommandURI(artifact) {
		return execution{failure: executionFailureFor(invocation.Command(), errors.New("invalid delta result"), domain.FailureInternal)}
	}
	exit, reasons, err := committedTerminalOutcome(result.TerminalExit)
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureInternal)}
	}
	data, err := json.Marshal(struct {
		Kind              string `json:"kind"`
		SessionID         string `json:"session_id"`
		RunID             string `json:"run_id"`
		ReviewArtifactURI string `json:"review_artifact_uri"`
	}{"delta_started", sessionID, runID, artifact})
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureInternal)}
	}
	return execution{human: []byte("delta started: " + runID), data: data, exit: exit, committedReasons: reasons}
}

func (application *Application) handleRerun(ctx context.Context, invocation Invocation) execution {
	request, available := invocation.Rerun()
	if !available {
		return execution{failure: executionFailureFor(invocation.Command(), errors.New("missing request"), domain.FailureInternal)}
	}
	if application.reruns == nil {
		return execution{failure: executionFailureFor(invocation.Command(), errors.New("rerun service unavailable"), domain.FailureProviderUnavailable)}
	}
	sourceRunID, err := domain.ParseRunID(request.SourceRunID())
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureConfiguration)}
	}
	sourceAttemptID, err := domain.ParseAttemptID(request.SourceAttemptID())
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureConfiguration)}
	}
	mode := appreplay.ReplayMode(request.ReplayMode())
	result, err := application.reruns.StartRerun(ctx, appreplay.Request{SourceRunID: sourceRunID, SourceAttemptID: sourceAttemptID, ReplayMode: mode})
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureArtifact)}
	}
	sessionID, runID, manifest := result.SessionID, result.RunID, result.ArtifactURI
	if _, err := domain.ParseSessionID(sessionID); err != nil || !validCommandRunID(runID) || !validCommandURI(manifest) {
		return execution{failure: executionFailureFor(invocation.Command(), errors.New("invalid rerun result"), domain.FailureInternal)}
	}
	exit, reasons, err := committedTerminalOutcome(result.TerminalExit)
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureInternal)}
	}
	data, err := json.Marshal(struct {
		Kind              string `json:"kind"`
		SessionID         string `json:"session_id"`
		RunID             string `json:"run_id"`
		PromptManifestURI string `json:"prompt_manifest_uri"`
	}{"rerun_started", sessionID, runID, manifest})
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureInternal)}
	}
	return execution{human: []byte("rerun started: " + runID), data: data, exit: exit, committedReasons: reasons}
}

func (application *Application) handleClean(ctx context.Context, invocation Invocation) execution {
	request, available := invocation.Clean()
	if !available {
		return execution{failure: executionFailureFor(invocation.Command(), errors.New("missing request"), domain.FailureInternal)}
	}
	if application.retention == nil {
		return execution{failure: executionFailureFor(invocation.Command(), errors.New("retention service unavailable"), domain.FailureArtifact)}
	}
	var expectedPlanSHA256 *string
	if value, present := request.ExpectedPlanSHA256(); present {
		expectedPlanSHA256 = &value
	}
	result, err := application.retention.PlanAndApplyRetention(ctx, RetentionRequest{
		Mode: request.Mode(), ExpectedPlanSHA256: expectedPlanSHA256,
	})
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), classifyHandlerFailure("cli.clean", domain.FailureArtifact, "clean operation failed", err), domain.FailureArtifact)}
	}
	if (result.Mode != "" && result.Mode != request.Mode()) || !validCommandURI(result.CleanPlanURI) || strings.TrimSpace(result.PlanSHA256) == "" || result.Applied != (request.Mode() == CleanModeApply) {
		return execution{failure: executionFailureFor(invocation.Command(), errors.New("invalid clean result"), domain.FailureInternal)}
	}
	if request.Mode() == CleanModeExplain {
		if !validCleanExplainRows(result.ExplainRows) {
			return execution{failure: executionFailureFor(invocation.Command(), errors.New("invalid clean explain rows"), domain.FailureInternal)}
		}
	} else if len(result.ExplainRows) != 0 {
		return execution{failure: executionFailureFor(invocation.Command(), errors.New("unexpected clean explain rows"), domain.FailureInternal)}
	}
	data, err := json.Marshal(struct {
		Kind         string `json:"kind"`
		CleanPlanURI string `json:"clean_plan_uri"`
		PlanSHA256   string `json:"plan_sha256"`
		Applied      bool   `json:"applied"`
	}{"clean_completed", result.CleanPlanURI, result.PlanSHA256, result.Applied})
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureInternal)}
	}
	switch request.Mode() {
	case CleanModePlan:
		return execution{human: []byte("clean plan: " + result.CleanPlanURI), data: data}
	case CleanModeApply:
		return execution{human: []byte("clean completed: " + result.CleanPlanURI), data: data}
	case CleanModeExplain:
		return execution{human: []byte("clean explain: " + result.CleanPlanURI + "\n" + strings.Join(result.ExplainRows, "\n")), data: data}
	default:
		return execution{failure: executionFailureFor(invocation.Command(), errors.New("unsupported clean mode"), domain.FailureInternal)}
	}
}

func (application *Application) handleExport(ctx context.Context, invocation Invocation, canonicalProjectRoot string) execution {
	request, available := invocation.Export()
	if !available {
		return execution{failure: executionFailureFor(invocation.Command(), errors.New("missing request"), domain.FailureInternal)}
	}
	if application.exports == nil {
		return execution{failure: executionFailureFor(invocation.Command(), errors.New("export service unavailable"), domain.FailureArtifact)}
	}
	root, err := ports.NewAnchoredRoot(canonicalProjectRoot)
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureConfiguration)}
	}
	result, err := application.exports.ExportRedactedRun(ctx, RedactedExportRequest{
		RunID: request.RunID(), OutputPath: request.OutputPath(), Redacted: request.Redacted(), ProjectRoot: root,
	})
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureArtifact)}
	}
	if !result.Redacted || !validCommandURI(result.ExportManifestURI) || !validCommandURI(result.BundleURI) {
		return execution{failure: executionFailureFor(invocation.Command(), errors.New("invalid export result"), domain.FailureInternal)}
	}
	data, err := json.Marshal(struct {
		Kind              string `json:"kind"`
		ExportManifestURI string `json:"export_manifest_uri"`
		BundleURI         string `json:"bundle_uri"`
		Redacted          bool   `json:"redacted"`
	}{"export_created", result.ExportManifestURI, result.BundleURI, true})
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureInternal)}
	}
	return execution{human: []byte("export created: " + result.BundleURI), data: data}
}

func followupTarget(request TargetRequest) (appfollowup.Target, error) {
	kind := appfollowup.TargetKind(request.Kind())
	switch kind {
	case appfollowup.TargetWorkspace, appfollowup.TargetStage, appfollowup.TargetDirty, appfollowup.TargetDiff, appfollowup.TargetPatch, appfollowup.TargetStdin:
		if strings.TrimSpace(request.Value()) == "" {
			return appfollowup.Target{}, errors.New("empty target")
		}
		return appfollowup.Target{Kind: kind, Value: request.Value()}, nil
	default:
		return appfollowup.Target{}, errors.New("unsupported target")
	}
}

func deltaTarget(request TargetRequest) (appdelta.TargetRequest, error) {
	kind := appdelta.TargetKind(request.Kind())
	switch kind {
	case appdelta.TargetWorkspace, appdelta.TargetStage, appdelta.TargetDirty, appdelta.TargetDiff, appdelta.TargetPatch, appdelta.TargetStdin:
		if len(request.Value()) == 0 || len(request.Value()) > 4096 || strings.TrimSpace(request.Value()) == "" || strings.ContainsAny(request.Value(), "\x00\r\n") {
			return appdelta.TargetRequest{}, errors.New("invalid target")
		}
		return appdelta.TargetRequest{Kind: kind, Value: request.Value()}, nil
	default:
		return appdelta.TargetRequest{}, errors.New("unsupported target")
	}
}

func validCommandURI(value string) bool {
	return strings.TrimSpace(value) != "" && !strings.ContainsAny(value, "\x00\r\n")
}
func validCleanExplainRows(rows []string) bool {
	if len(rows) == 0 || len(rows) > 4096 {
		return false
	}
	for _, row := range rows {
		if len(row) > 4096 || strings.TrimSpace(row) == "" || strings.ContainsAny(row, "\x00\r\n") {
			return false
		}
	}
	return true
}

func validCommandRunID(value string) bool {
	_, err := domain.ParseRunID(value)
	return err == nil
}
func committedTerminalOutcome(terminalExit domain.OperationalExitDecision) (app.ExitCode, []string, error) {
	reasons := terminalExit.Reasons()
	if len(reasons) == 0 {
		return app.ExitCodeInternal, nil, errors.New("committed terminal exit authority is missing")
	}
	input, err := domain.NewOperationalExitInput(reasons)
	if err != nil {
		return app.ExitCodeInternal, nil, fmt.Errorf("committed terminal exit authority is invalid: %w", err)
	}
	reduced, err := domain.ReduceOperationalExit(input)
	if err != nil || reduced.Code() != terminalExit.Code() {
		return app.ExitCodeInternal, nil, errors.New("committed terminal exit authority is not reduced")
	}
	reasonCodes := make([]string, len(reasons))
	for index, reason := range reasons {
		reasonCodes[index] = reason.ReasonCode()
	}
	switch terminalExit.Code() {
	case domain.ExitCommittedPass:
		return app.ExitCodeSuccess, reasonCodes, nil
	case domain.ExitCommittedCIRejected:
		return app.ExitCodePolicy, reasonCodes, nil
	case domain.ExitIncompleteCoverage:
		return app.ExitCodeReadiness, reasonCodes, nil
	default:
		return app.ExitCodeInternal, nil, fmt.Errorf("terminal exit %d is not a committed P2 outcome", terminalExit.Code())
	}
}

func (application *Application) handleHelp(ctx context.Context, invocation Invocation) execution {
	request, available := invocation.Help()
	if !available {
		return execution{failure: executionFailureFor(invocation.Command(), errors.New("missing request"), domain.FailureInternal)}
	}
	service, err := apphelp.NewService(application.catalog)
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureArtifact)}
	}
	rendered, err := service.Render(ctx, request.Topic())
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureArtifact)}
	}
	data, err := json.Marshal(struct {
		Kind     string `json:"kind"`
		Topic    string `json:"topic"`
		Rendered bool   `json:"rendered"`
	}{"help_rendered", request.Topic(), true})
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureInternal)}
	}
	return execution{human: rendered, data: data}
}

func (application *Application) handleSchema(ctx context.Context, invocation Invocation) execution {
	request, available := invocation.Schema()
	if !available {
		return execution{failure: executionFailureFor(invocation.Command(), errors.New("missing request"), domain.FailureInternal)}
	}
	service := appschema.NewService(application.catalog, application.writer)
	switch request.Operation() {
	case SchemaOperationList:
		metadata, err := service.List(ctx)
		if err != nil {
			return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureArtifact)}
		}
		var output strings.Builder
		for _, schema := range metadata {
			output.WriteString(schema.Source().String())
			output.WriteByte('\n')
		}
		return execution{human: []byte(output.String()), data: nil}
	case SchemaOperationShow:
		schemaID, available := request.SchemaID()
		if !available {
			return execution{failure: executionFailureFor(invocation.Command(), errors.New("missing schema ID"), domain.FailureInternal)}
		}
		id, err := ports.ParseAssetID(schemaID)
		if err != nil {
			return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureConfiguration)}
		}
		_, raw, err := service.Show(ctx, id)
		if err != nil {
			return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureArtifact)}
		}
		data, err := schemaResultData(schemaID, nil)
		if err != nil {
			return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureInternal)}
		}
		return execution{human: raw, data: data}
	case SchemaOperationExport:
		schemaID, available := request.SchemaID()
		if !available {
			return execution{failure: executionFailureFor(invocation.Command(), errors.New("missing schema ID"), domain.FailureInternal)}
		}
		exportPath, available := request.ExportPath()
		if !available {
			return execution{failure: executionFailureFor(invocation.Command(), errors.New("missing export path"), domain.FailureInternal)}
		}
		id, err := ports.ParseAssetID(schemaID)
		if err != nil {
			return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureConfiguration)}
		}
		root, err := ports.NewAnchoredRoot(request.ProjectRoot())
		if err != nil {
			return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureConfiguration)}
		}
		destination, err := ports.NewSafeRelativePath(exportPath)
		if err != nil {
			return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureConfiguration)}
		}
		receipt, err := service.Export(ctx, id, root, destination)
		if err != nil {
			return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureArtifact)}
		}
		if receipt.Destination() != destination {
			return execution{failure: executionFailureFor(invocation.Command(), errors.New("export receipt mismatch"), domain.FailureArtifact)}
		}
		uri := receipt.Destination().String()
		data, err := schemaResultData(schemaID, &uri)
		if err != nil {
			return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureInternal)}
		}
		return execution{human: []byte("exported " + uri), data: data}
	default:
		return execution{failure: executionFailureFor(invocation.Command(), errors.New("unsupported operation"), domain.FailureConfiguration)}
	}
}

func (application *Application) handleInit(ctx context.Context, invocation Invocation) execution {
	request, available := invocation.Init()
	if !available {
		return execution{failure: executionFailureFor(invocation.Command(), errors.New("missing request"), domain.FailureInternal)}
	}
	root, err := ports.NewAnchoredRoot(request.ProjectRoot())
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureConfiguration)}
	}
	contextPath, _ := request.ContextPath()
	projectKind, _ := request.ProjectKind()
	artistBriefPath, artistDesignGlobs := request.ArtistInputs()
	installer, ok := application.writer.(ports.ConfigInstaller)
	if !ok {
		return execution{failure: &executionFailure{class: domain.FailureInternal, code: "init_installer_unavailable", stage: "cli.init", exit: app.ExitCodeInternal}}
	}
	attestor, ok := application.projectReader.(ports.ConfigLocalityAttestor)
	if !ok {
		return execution{failure: &executionFailure{class: domain.FailureInternal, code: "init_attestor_unavailable", stage: "cli.init", exit: app.ExitCodeInternal}}
	}
	if _, statErr := os.Lstat(filepath.Join(root.String(), ".git")); os.IsNotExist(statErr) {
		attestor = adapterconfig.NewFilesystemLocalityAttestor()
	} else if statErr != nil {
		return initObservedFailure(invocation, appinit.Selection{}, ports.ConfigDestinationNotObserved, domain.FailureSecurityPolicy, "config_locality_unsafe", "The project-local KAR configuration failed locality admission.", false)
	}
	mode, providerIDs := request.Selection()
	selection := appinit.Selection{Mode: appinit.SelectionMode(mode), ProviderIDs: providerIDs}
	kimiExecutable, kimiModel, kimiDataHome := request.KimiOverrides()
	zcodeNode, zcodeLauncher := request.ZCodeOverrides()
	agyExecutable, agyPermission := request.AGYOverrides()

	// Destination proof precedes native-account inspection so an existing
	// project-local authority wins deterministically and native failures can
	// truthfully report an observed-absent destination.
	initialSource, err := adapterconfig.NewLocalConfigSource(root, true)
	if err != nil {
		return initObservedFailure(invocation, selection, ports.ConfigDestinationNotObserved, domain.FailureSecurityPolicy, configLocalityFailureCode(err, "config_locality_unsafe"), "The project-local KAR configuration failed locality admission.", false)
	}
	initialProof, err := initialSource.Observation().Proof()
	if err != nil {
		return initObservedFailure(invocation, selection, ports.ConfigDestinationNotObserved, domain.FailureSecurityPolicy, configLocalityFailureCode(err, "config_locality_unsafe"), "The project-local KAR configuration failed locality admission.", false)
	}
	initialRequest, err := ports.NewConfigLocalityRequest(root, initialProof, nil, nil)
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureInternal)}
	}
	initialLocality, err := attestor.Attest(ctx, initialRequest)
	if err != nil {
		return initObservedFailure(invocation, selection, ports.ConfigDestinationNotObserved, domain.FailureSecurityPolicy, configLocalityFailureCode(err, "config_locality_unsafe"), "The project-local KAR configuration failed locality admission.", false)
	}
	if err := revalidateConfigLocality(ctx, initialSource, attestor, initialRequest, initialLocality); err != nil {
		return initObservedFailure(invocation, selection, ports.ConfigDestinationNotObserved, domain.FailureSecurityPolicy, configLocalityFailureCode(err, "config_locality_drifted"), "The project-local KAR configuration failed locality admission.", false)
	}
	if initialSource.Present() {
		return initObservedFailure(invocation, selection, ports.ConfigDestinationPresent, domain.FailureConfiguration, "init_destination_exists", "The project-local KAR configuration already exists.", false)
	}
	nativeUser, err := user.Current()
	if err != nil || nativeUser == nil {
		return initObservedFailure(invocation, selection, ports.ConfigDestinationAbsent, domain.FailureProviderUnavailable, "init_native_account_unavailable", "The native user account is unavailable.", false)
	}
	uid, err := strconv.ParseUint(nativeUser.Uid, 10, 32)
	if err != nil || int(uid) != os.Geteuid() {
		return initObservedFailure(invocation, selection, ports.ConfigDestinationAbsent, domain.FailureSecurityPolicy, "init_native_account_mismatch", "The native user account does not match the effective user.", false)
	}
	nativeHome := nativeUser.HomeDir
	assertedNativeHome, nativeHomeAsserted := request.NativeHome()
	if nativeHomeAsserted && assertedNativeHome != nativeHome {
		return initObservedFailure(invocation, selection, ports.ConfigDestinationAbsent, domain.FailureSecurityPolicy, "init_native_home_mismatch", "The asserted native home does not match the installed user.", false)
	}
	nativeHomeAuthority, err := application.inspector.ObserveNativeHomeIdentity(ctx, nativeHome)
	if contextCancellation(err) {
		return initObservedFailure(invocation, selection, ports.ConfigDestinationAbsent, domain.FailureCancelled, "request_cancelled", "The command was cancelled.", false)
	}
	if err != nil || !nativeHomeAuthority.Valid() || nativeHomeAuthority.Path() != nativeHome || nativeHomeAuthority.EffectiveUID() != uint32(os.Geteuid()) {
		return initObservedFailure(invocation, selection, ports.ConfigDestinationAbsent, domain.FailureSecurityPolicy, "init_native_home_mismatch", "The installed native home failed descriptor identity admission.", false)
	}
	var prevalidatedCommitted []byte
	var prevalidatedCommittedData []byte
	prevalidator := appinit.ResultPrevalidatorFunc(func(prevalidationContext context.Context, outcome appinit.PrevalidatedOutcome) error {
		result := outcome.Result
		if err := outcome.Validate(); err != nil {
			return err
		}
		data, err := json.Marshal(result)
		if err != nil {
			return err
		}
		requestJSON, available, err := envelopeRequestJSON(invocation)
		if err != nil || !available {
			return errors.New("init result prevalidation request unavailable")
		}
		if outcome.Failure == nil {
			if !result.Committed {
				return errors.New("init result prevalidation failure metadata unavailable")
			}
			prevalidatedCommittedData = append([]byte(nil), data...)
			commandResult, resultErr := app.NewCommandSuccess(app.CommandInit, data)
			if resultErr != nil {
				return resultErr
			}
			output, renderErr := application.renderer.Render(prevalidationContext, commandResult, requestJSON, nil)
			if renderErr == nil {
				prevalidatedCommitted = output
			}
			err = renderErr
			return err
		}
		failure := outcome.Failure
		diagnostic, err := app.NewDiagnosticWithRetryable("cli.init", failure.Class(), failure.Code(), failure.Message(), failure.Retryable())
		if err != nil {
			return err
		}
		commandResult, err := app.NewCommandFailure(app.CommandInit, requestedExit(failure.Class()), diagnostic)
		if err != nil {
			return err
		}
		_, err = application.renderer.Render(prevalidationContext, commandResult, requestJSON, data)
		return err
	})
	service, err := appinit.NewService(installer, application.inspector, attestor, prevalidator, application.clock, adapterconfig.SourceFactory{}, adapterconfig.YAMLCodec{})
	if err != nil {
		return execution{failure: &executionFailure{class: domain.FailureInternal, code: "init_service_unavailable", stage: "cli.init", exit: app.ExitCodeInternal}}
	}
	nativeHomeCurrent, err := application.inspector.ObserveNativeHomeIdentity(ctx, nativeHome)
	if contextCancellation(err) {
		return initObservedFailure(invocation, selection, ports.ConfigDestinationAbsent, domain.FailureCancelled, "request_cancelled", "The command was cancelled.", false)
	}
	if err != nil || !sameNativeHomeAuthority(nativeHomeAuthority, nativeHomeCurrent) {
		return initObservedFailure(invocation, selection, ports.ConfigDestinationAbsent, domain.FailureSecurityPolicy, "init_native_home_mismatch", "The installed native home changed during admission.", false)
	}
	initialized, err := service.InitializeProject(ctx, appinit.InitializeProjectRequest{
		ProjectRoot: root, ProjectName: request.ProjectName(), ContextPath: contextPath, ProjectKind: projectKind, ArtistBriefPath: artistBriefPath, ArtistDesignSpecGlobs: artistDesignGlobs, NativeHome: nativeHome,
		NativeHomeAsserted: nativeHomeAsserted,
		Selection:          selection,
		RoleIDs:            request.Roles(),
		Overrides:          appinit.Overrides{KimiExecutable: kimiExecutable, KimiModel: kimiModel, KimiDataHome: kimiDataHome, ZCodeNodeExecutable: zcodeNode, ZCodeLauncher: zcodeLauncher, AGYExecutable: agyExecutable, AGYPermissionMode: agyPermission},
	})
	if err != nil {
		data, marshalErr := json.Marshal(initialized)
		if marshalErr != nil {
			return execution{failure: &executionFailure{class: domain.FailureInternal, code: "init_result_prevalidation_failed", stage: "cli.init", exit: app.ExitCodeInternal}}
		}
		failure := executionFailureFor(invocation.Command(), err, domain.FailureArtifact)
		var initFailure *appinit.Failure
		if errors.As(err, &initFailure) {
			failure.class = initFailure.Class()
			failure.code = initFailure.Code()
			failure.message = initFailure.Message()
			failure.retryable = initFailure.Retryable()
			failure.hasRetryable = true
			failure.exit = requestedExit(failure.class)
		}
		if failure.code == "init_result_prevalidation_failed" {
			return execution{direct: &Result{stderr: []byte("kar: internal command-result prevalidation failed\n"), exit: app.ExitCodeInternal}}
		}
		return execution{human: []byte(initFailureHuman(initialized, failure.code)), failureData: data, failure: failure}
	}
	data := prevalidatedCommittedData
	if len(data) == 0 {
		return execution{direct: &Result{stderr: []byte("kar: init committed .kar/config.yaml; result delivery failed\n"), exit: app.ExitCodeArtifact}}
	}
	if invocation.OutputFormat() == OutputFormatJSON {
		if len(prevalidatedCommitted) == 0 {
			return execution{direct: &Result{stderr: []byte("kar: init committed .kar/config.yaml; result delivery failed\n"), exit: app.ExitCodeArtifact}}
		}
		return execution{direct: &Result{stdout: prevalidatedCommitted, exit: app.ExitCodeSuccess}}
	}
	var output strings.Builder
	output.WriteString("initialized: ")
	output.WriteString(initialized.ConfigURI)
	output.WriteString("\nproviders: ")
	output.WriteString(strings.Join(initialized.ConfiguredProviderIDs, ","))
	output.WriteString("\nroles: ")
	output.WriteString(strings.Join(initialized.ConfiguredRoleIDs, ","))
	return execution{human: []byte(output.String()), data: data}
}

func initObservedFailure(invocation Invocation, selection appinit.Selection, destination ports.ConfigDestinationState, class domain.FailureClass, code, message string, retryable bool) execution {
	result, err := appinit.NewObservedFailureResult(selection, destination)
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureInternal)}
	}
	data, err := json.Marshal(result)
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureInternal)}
	}
	failure := &executionFailure{class: class, code: code, message: message, retryable: retryable, hasRetryable: true, stage: "cli.init", exit: requestedExit(class)}
	resultExecution := execution{failureData: data, failure: failure}
	if class != domain.FailureCancelled {
		resultExecution.human = []byte(initFailureHuman(result, code))
	}
	return resultExecution
}

func (application *Application) handleConfig(ctx context.Context, invocation Invocation) execution {
	request, available := invocation.Config()
	if !available {
		return execution{failure: executionFailureFor(invocation.Command(), errors.New("missing request"), domain.FailureInternal)}
	}
	root, err := ports.NewAnchoredRoot(request.ProjectRoot())
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureConfiguration)}
	}
	attestor, ok := application.projectReader.(ports.ConfigLocalityAttestor)
	if !ok {
		return execution{failure: executionFailureFor(invocation.Command(), errors.New("config locality attestor unavailable"), domain.FailureInternal)}
	}
	source, err := adapterconfig.NewLocalConfigSource(root, false)
	if err != nil {
		class := domain.FailureConfiguration
		if os.IsNotExist(err) {
			class = domain.FailureProviderUnavailable
		}
		return execution{failure: executionFailureFor(invocation.Command(), err, class)}
	}
	proof, err := source.Observation().Proof()
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureSecurityPolicy)}
	}
	localityRequest, err := ports.NewConfigLocalityRequest(root, proof, nil, nil)
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureInternal)}
	}
	locality, err := attestor.Attest(ctx, localityRequest)
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureSecurityPolicy)}
	}
	if err := revalidateConfigLocality(ctx, source, attestor, localityRequest, locality); err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureSecurityPolicy)}
	}
	resolved, err := appconfig.NewService(adapterconfig.YAMLCodec{}).Resolve(ctx, appconfig.ResolveRequest{Source: source})
	if err != nil {
		class := domain.FailureConfiguration
		if admission, ok := adapterconfig.AsAdmissionError(err); ok && (admission.Reason() == adapterconfig.ReasonCredentialKeyDetected || admission.Reason() == adapterconfig.ReasonCredentialValueDetected) {
			class = domain.FailureSecurityPolicy
		}
		return execution{failure: executionFailureFor(invocation.Command(), err, class)}
	}
	installed, installedErr := user.Current()
	nativeHome, effectiveUID, err := admitConfiguredNativeAccount(resolved.Config().Raw().NativeUser.Home, installed, installedErr, os.Geteuid())
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureProviderUnavailable)}
	}
	nativeHomeAuthority, err := application.inspector.ObserveNativeHomeIdentity(ctx, nativeHome)
	if contextCancellation(err) {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureCancelled)}
	}
	if err != nil || !nativeHomeAuthority.Valid() || nativeHomeAuthority.Path() != nativeHome || nativeHomeAuthority.EffectiveUID() != effectiveUID {
		return execution{failure: executionFailureFor(invocation.Command(), errors.New("configured native home failed descriptor identity admission"), domain.FailureSecurityPolicy)}
	}
	if err := revalidateConfigLocality(ctx, source, attestor, localityRequest, locality); err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureSecurityPolicy)}
	}
	nativeHomeCurrent, err := application.inspector.ObserveNativeHomeIdentity(ctx, nativeHome)
	if contextCancellation(err) {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureCancelled)}
	}
	if err != nil || !sameNativeHomeAuthority(nativeHomeAuthority, nativeHomeCurrent) {
		return execution{failure: executionFailureFor(invocation.Command(), errors.New("configured native home changed during admission"), domain.FailureSecurityPolicy)}
	}
	output, err := resolvedConfigOutput(request, resolved)
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureInternal)}
	}

	return execution{human: output, data: output}
}

func admitConfiguredNativeAccount(configuredHome string, installed *user.User, installedErr error, effectiveUID int) (string, uint32, error) {
	if installedErr != nil || installed == nil || installed.HomeDir == "" || effectiveUID < 0 {
		return "", 0, errors.New("native user account is unavailable")
	}
	installedUID, err := strconv.ParseUint(installed.Uid, 10, 32)
	if err != nil || uint64(effectiveUID) != installedUID || configuredHome != installed.HomeDir {
		return "", 0, errors.New("configured native account does not match the effective user")
	}
	return installed.HomeDir, uint32(effectiveUID), nil
}

func (application *Application) handleDoctor(ctx context.Context, invocation Invocation) execution {
	request, available := invocation.Doctor()
	if !available {
		return execution{failure: executionFailureFor(invocation.Command(), errors.New("missing request"), domain.FailureInternal)}
	}
	root, err := ports.NewAnchoredRoot(request.ProjectRoot())
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureConfiguration)}
	}
	diagnosis, err := application.diagnoseLocalDoctor(ctx, root)
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureInternal)}
	}
	raw, err := json.Marshal(diagnosis)
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureInternal)}
	}
	schemaID, err := ports.ParseAssetID(doctorResultSchema)
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureInternal)}
	}
	if err := application.validator.Validate(ctx, schemaID, cloneApplicationBytes(raw)); err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureArtifact)}
	}

	human := localDoctorHumanOutput(diagnosis)
	if invocation.OutputFormat() == OutputFormatHuman {
		if diagnosis.Readiness.ExitCode == 0 {
			return execution{human: human, data: nil}
		}
		class := domain.FailureProviderUnavailable
		code := "readiness_unverified"
		if diagnosis.Readiness.State == "unsafe" {
			class, code = domain.FailureSecurityPolicy, "security_rejected"
		}
		return execution{
			human: human,
			failure: &executionFailure{
				class: class,
				code:  code,
				stage: "cli.doctor",
				exit:  app.ExitCode(diagnosis.Readiness.ExitCode),
			},
		}
	}

	data, err := json.Marshal(struct {
		Kind            string                    `json:"kind"`
		DoctorResultURI *string                   `json:"doctor_result_uri"`
		Readiness       string                    `json:"readiness"`
		Doctor          *doctor.LocalDoctorResult `json:"doctor"`
	}{"diagnosed", nil, diagnosis.Readiness.State, &diagnosis})
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureInternal)}
	}
	if diagnosis.Readiness.ExitCode == 0 {
		return execution{human: human, data: data}
	}
	class := domain.FailureProviderUnavailable
	code := "readiness_unverified"
	if diagnosis.Readiness.State == "unsafe" {
		class, code = domain.FailureSecurityPolicy, "security_rejected"
	}
	return execution{
		human:       human,
		data:        data,
		failureData: data,
		failure: &executionFailure{
			class: class,
			code:  code,
			stage: "cli.doctor",
			exit:  app.ExitCode(diagnosis.Readiness.ExitCode),
		},
	}
}

func (application *Application) diagnoseLocalDoctor(ctx context.Context, root ports.AnchoredRoot) (doctor.LocalDoctorResult, error) {
	now := application.clock.Now().UTC()
	base := doctor.LocalDoctorResult{
		SchemaVersion: doctor.LocalSchemaVersion, CheckedAt: now, ProjectRootURI: ".",
		Config:                doctor.LocalConfigProjection{Status: "missing", URI: adapterconfig.ConfigRelativePath, Authority: "project_local", Locality: "not_observed", TargetCommitOIDs: []string{}, ReasonCodes: []string{"config_missing"}},
		ConfiguredProviderIDs: []string{},
		ProviderInventory:     []doctor.LocalProviderInventoryRow{{Family: "kimi", State: "not_observed", Reason: "config_not_ready"}, {Family: "zcode", State: "not_observed", Reason: "config_not_ready"}, {Family: "agy", State: "not_observed", Reason: "config_not_ready"}},
		Assignment:            doctor.LocalAssignmentProjection{State: "not_observed", Resilience: "not_observed"},
		PlatformEvidence:      []doctor.LocalPlatformEvidence{{Cell: runtime.GOOS + "-" + runtime.GOARCH, Native: runtime.GOOS == "darwin" && runtime.GOARCH == "arm64"}},
		ToolsLock:             doctor.LocalToolsLock{State: "not_observed"},
		Readiness:             doctor.LocalReadiness{State: "unverified", ExitCode: 4, ReasonCodes: []string{"config_missing"}},
		Diagnostics:           []doctor.LocalDiagnostic{{Code: "config_missing", Category: "readiness", Message: "Project-local KAR configuration is missing.", Redacted: true}},
	}
	source, err := adapterconfig.NewLocalConfigSource(root, false)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return base, base.Validate()
		}
		reason := configLocalityFailureCode(err, "config_locality_unsafe")
		base.Config.Status, base.Config.Locality = "unsafe", "rejected"
		base.Config.ReasonCodes = []string{reason}
		base.Readiness = doctor.LocalReadiness{State: "unsafe", ExitCode: 8, ReasonCodes: []string{reason}}
		base.Diagnostics = []doctor.LocalDiagnostic{{Code: reason, Category: "security", Message: "Project-local KAR configuration failed security admission.", Redacted: true}}
		return base, base.Validate()
	}
	attestor, ok := application.projectReader.(ports.ConfigLocalityAttestor)
	if !ok {
		return doctor.LocalDoctorResult{}, fmt.Errorf("doctor locality attestor unavailable")
	}
	data, identity, err := source.Read()
	if err != nil {
		return doctor.LocalDoctorResult{}, err
	}
	proof, err := source.Proof()
	if err != nil {
		return doctor.LocalDoctorResult{}, err
	}
	request, err := ports.NewConfigLocalityRequest(root, proof, nil, nil)
	if err != nil {
		return doctor.LocalDoctorResult{}, err
	}
	locality, err := attestor.Attest(ctx, request)
	if err != nil {
		reason := configLocalityFailureCode(err, "config_locality_unsafe")
		base.Config.Status, base.Config.Locality = "unsafe", "rejected"
		base.Config.ReasonCodes = []string{reason}
		base.Readiness = doctor.LocalReadiness{State: "unsafe", ExitCode: 8, ReasonCodes: []string{reason}}
		base.Diagnostics = []doctor.LocalDiagnostic{{Code: reason, Category: "security", Message: "Project-local KAR configuration failed locality admission.", Redacted: true}}
		return base, base.Validate()
	}
	if err := revalidateConfigLocality(ctx, source, attestor, request, locality); err != nil {
		reason := configLocalityFailureCode(err, "config_locality_drifted")
		base.Config.Status, base.Config.Locality = "drifted", "drifted"
		base.Config.ReasonCodes = []string{reason}
		base.Readiness = doctor.LocalReadiness{State: "unsafe", ExitCode: 8, ReasonCodes: []string{reason}}
		base.Diagnostics = []doctor.LocalDiagnostic{{Code: reason, Category: "security", Message: "Project-local KAR configuration changed during admission.", Redacted: true}}
		return base, base.Validate()
	}
	config, err := adapterconfig.Decode(data)
	if err != nil {
		if admission, ok := adapterconfig.AsAdmissionError(err); ok && (admission.Reason() == adapterconfig.ReasonCredentialKeyDetected || admission.Reason() == adapterconfig.ReasonCredentialValueDetected) {
			reason := string(admission.Reason())
			base.Config.Status, base.Config.Locality = "unsafe", "verified"
			base.Config.ReasonCodes = []string{reason}
			base.Readiness = doctor.LocalReadiness{State: "unsafe", ExitCode: 8, ReasonCodes: []string{reason}}
			base.Diagnostics = []doctor.LocalDiagnostic{{Code: reason, Category: "security", Message: "Project-local KAR configuration contains prohibited credential material.", Redacted: true}}
			return base, base.Validate()
		}
		base.Config.Status, base.Config.Locality = "invalid", "verified"
		base.Config.ReasonCodes = []string{"config_yaml_invalid"}
		base.Readiness = doctor.LocalReadiness{State: "unverified", ExitCode: 4, ReasonCodes: []string{"config_yaml_invalid"}}
		base.Diagnostics = []doctor.LocalDiagnostic{{Code: "config_yaml_invalid", Category: "configuration", Message: "Project-local KAR configuration is invalid.", Redacted: true}}
		return base, base.Validate()
	}
	if err := revalidateConfigLocality(ctx, source, attestor, request, locality); err != nil {
		reason := configLocalityFailureCode(err, "config_locality_drifted")
		base.Config.Status, base.Config.Locality = "drifted", "drifted"
		base.Config.ReasonCodes = []string{reason}
		base.Readiness = doctor.LocalReadiness{State: "unsafe", ExitCode: 8, ReasonCodes: []string{reason}}
		base.Diagnostics = []doctor.LocalDiagnostic{{Code: reason, Category: "security", Message: "Project-local KAR configuration changed during admission.", Redacted: true}}
		return base, base.Validate()
	}
	head, _ := locality.Checkout()
	indexDigest, _, _ := locality.Index()
	base.Config = doctor.LocalConfigProjection{Status: "ready", URI: adapterconfig.ConfigRelativePath, SHA256: identity.SHA256(), Authority: "project_local", Locality: "verified", CheckoutHeadOID: head, IndexEntriesSHA256: indexDigest, TargetCommitOIDs: locality.ApplicableCommitOIDs(), ProvenanceState: "accepted", ReasonCodes: []string{}}
	installed, userErr := user.Current()
	installedUID := uint64(0)
	var installedUIDErr error
	if installed != nil {
		installedUID, installedUIDErr = strconv.ParseUint(installed.Uid, 10, 32)
	}
	if userErr != nil || installed == nil || installedUIDErr != nil || installed.HomeDir != config.NativeUser.Home || int(installedUID) != os.Geteuid() {
		base.Config.Status = "unsafe"
		base.Config.NativeHomeIdentity = "mismatch"
		base.Config.ReasonCodes = []string{"native_home_mismatch"}
		base.Readiness = doctor.LocalReadiness{State: "unsafe", ExitCode: 8, ReasonCodes: []string{"native_home_mismatch"}}
		base.Diagnostics = []doctor.LocalDiagnostic{{Code: "native_home_mismatch", Category: "security", Message: "Configured native home does not match the installed user.", Redacted: true}}
		return base, base.Validate()
	}
	nativeHomeAuthority, nativeHomeErr := application.inspector.ObserveNativeHomeIdentity(ctx, installed.HomeDir)
	if contextCancellation(nativeHomeErr) {
		return doctor.LocalDoctorResult{}, nativeHomeErr
	}
	if nativeHomeErr != nil || !nativeHomeAuthority.Valid() || nativeHomeAuthority.Path() != installed.HomeDir || nativeHomeAuthority.EffectiveUID() != uint32(os.Geteuid()) {
		base.Config.Status = "unsafe"
		base.Config.NativeHomeIdentity = "mismatch"
		base.Config.ReasonCodes = []string{"native_home_mismatch"}
		base.Readiness = doctor.LocalReadiness{State: "unsafe", ExitCode: 8, ReasonCodes: []string{"native_home_mismatch"}}
		base.Diagnostics = []doctor.LocalDiagnostic{{Code: "native_home_mismatch", Category: "security", Message: "Configured native home failed descriptor identity admission.", Redacted: true}}
		return base, base.Validate()
	}
	base.Config.NativeHomeIdentity = "verified"
	base.ConfiguredProviderIDs = config.Providers.Families()
	configured := make(map[reviewrun.Family][]string, len(base.ConfiguredProviderIDs))
	if provider := config.Providers.Kimi; provider != nil {
		configured[reviewrun.FamilyKimi] = []string{provider.Executable}
	}
	if provider := config.Providers.ZCode; provider != nil {
		configured[reviewrun.FamilyZCode] = []string{provider.NodeExecutable, provider.Launcher}
	}
	if provider := config.Providers.AGY; provider != nil {
		configured[reviewrun.FamilyAGY] = []string{provider.Executable}
	}
	profiles, discoveryErr := reviewrun.DiscoverConfiguredProviderProfiles(ctx, application.inspector, configured)
	securityDiscoveryFamilies := make(map[reviewrun.Family]struct{})
	for _, family := range reviewrun.ConfiguredProviderSecurityFamilies(discoveryErr) {
		securityDiscoveryFamilies[family] = struct{}{}
	}
	if discoveryErr != nil && len(securityDiscoveryFamilies) == 0 {
		return doctor.LocalDoctorResult{}, discoveryErr
	}
	profileByFamily := make(map[string]reviewrun.DiscoveredProviderProfile, len(profiles))
	for _, profile := range profiles {
		profileByFamily[string(profile.Family())] = profile
	}
	base.ProviderInventory = make([]doctor.LocalProviderInventoryRow, 0, 3)
	eligible := 0
	unsafeAdmission := len(securityDiscoveryFamilies) > 0
	for _, family := range []string{"kimi", "zcode", "agy"} {
		if _, configuredFamily := configured[reviewrun.Family(family)]; !configuredFamily {
			base.ProviderInventory = append(base.ProviderInventory, doctor.LocalProviderInventoryRow{Family: family, State: "not_configured", Reason: "not_configured"})
			continue
		}
		if _, unsafeIdentity := securityDiscoveryFamilies[reviewrun.Family(family)]; unsafeIdentity {
			base.ProviderInventory = append(base.ProviderInventory, doctor.LocalProviderInventoryRow{Family: family, State: "unavailable", Reason: "provider_security_admission_failed"})
			continue
		}
		profile := profileByFamily[family]
		if profile.Executable() == "" || profile.Launcher() == "" {
			base.ProviderInventory = append(base.ProviderInventory, doctor.LocalProviderInventoryRow{Family: family, State: "unavailable", Reason: "configured_identity_unavailable"})
			continue
		}
		if nilApplicationDependency(application.evidenceReader) {
			base.ProviderInventory = append(base.ProviderInventory, doctor.LocalProviderInventoryRow{Family: family, State: "unavailable", Reason: "provider_admission_unverified"})
			continue
		}
		evidence, evidenceErr := application.evidenceReader.ProviderEvidence(ctx, family)
		admitted, unsafe := localProviderAdmission(evidence, family)
		if evidenceErr != nil || !admitted {
			unsafeAdmission = unsafeAdmission || unsafe
			reason := "provider_admission_unverified"
			if unsafe {
				reason = "provider_security_admission_failed"
			}
			base.ProviderInventory = append(base.ProviderInventory, doctor.LocalProviderInventoryRow{Family: family, State: "unavailable", Reason: reason})
			continue
		}
		eligible++
		base.ProviderInventory = append(base.ProviderInventory, doctor.LocalProviderInventoryRow{Family: family, State: "eligible", Reason: "identity_admitted"})
	}
	nativeHomeCurrent, nativeHomeErr := application.inspector.ObserveNativeHomeIdentity(ctx, installed.HomeDir)
	if contextCancellation(nativeHomeErr) {
		return doctor.LocalDoctorResult{}, nativeHomeErr
	}
	if nativeHomeErr != nil || !sameNativeHomeAuthority(nativeHomeAuthority, nativeHomeCurrent) {
		base.Config.Status = "unsafe"
		base.Config.NativeHomeIdentity = "mismatch"
		base.Config.ReasonCodes = []string{"native_home_mismatch"}
		base.Assignment = doctor.LocalAssignmentProjection{State: "unavailable", Resilience: "unavailable"}
		base.Readiness = doctor.LocalReadiness{State: "unsafe", ExitCode: 8, ReasonCodes: []string{"native_home_mismatch"}}
		base.Diagnostics = []doctor.LocalDiagnostic{{Code: "native_home_mismatch", Category: "security", Message: "Configured native home changed during admission.", Redacted: true}}
		return base, base.Validate()
	}
	switch {
	case unsafeAdmission:
		base.Assignment = doctor.LocalAssignmentProjection{State: "unavailable", Resilience: "unavailable"}
		base.Readiness = doctor.LocalReadiness{State: "unsafe", ExitCode: 8, ReasonCodes: []string{"provider_security_admission_failed"}}
		base.Diagnostics = []doctor.LocalDiagnostic{{Code: "provider_security_admission_failed", Category: "security", Message: "A configured provider failed security admission.", Redacted: true}}
	case eligible == 0:
		base.Assignment = doctor.LocalAssignmentProjection{State: "unavailable", Resilience: "unavailable"}
		base.Readiness = doctor.LocalReadiness{State: "unverified", ExitCode: 4, ReasonCodes: []string{"provider_unavailable"}}
		base.Diagnostics = []doctor.LocalDiagnostic{{Code: "provider_unavailable", Category: "readiness", Message: "A configured provider is unavailable.", Redacted: true}}
	case eligible == 1:
		base.Assignment = doctor.LocalAssignmentProjection{State: "degraded_resilience", Resilience: "degraded"}
		base.Readiness = doctor.LocalReadiness{State: "degraded", ExitCode: 0, ReasonCodes: []string{"provider_resilience_degraded"}}
		base.Diagnostics = []doctor.LocalDiagnostic{{Code: "provider_resilience_degraded", Category: "readiness", Message: "All roles have a primary provider but no fallback provider.", Redacted: true}}
	default:
		base.Assignment = doctor.LocalAssignmentProjection{State: "ready", Resilience: "ready"}
		base.Readiness = doctor.LocalReadiness{State: "ready", ExitCode: 0, ReasonCodes: []string{}}
		base.Diagnostics = []doctor.LocalDiagnostic{}
	}
	return base, base.Validate()
}

func sameNativeHomeAuthority(left, right ports.NativeHomeLaunchAuthority) bool {
	return left.Valid() && right.Valid() &&
		left.Path() == right.Path() &&
		left.Device() == right.Device() &&
		left.Inode() == right.Inode() &&
		left.EffectiveUID() == right.EffectiveUID()
}

func contextCancellation(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

func revalidateConfigLocality(ctx context.Context, source *adapterconfig.LocalConfigSource, attestor ports.ConfigLocalityAttestor, request ports.ConfigLocalityRequest, expected ports.ConfigLocalityContext) error {
	if source == nil || attestor == nil {
		return fmt.Errorf("config locality unavailable")
	}
	if err := source.Revalidate(); err != nil {
		return err
	}
	if err := attestor.Revalidate(ctx, request, expected); err != nil {
		return err
	}
	return source.Revalidate()
}

func configLocalityFailureCode(err error, fallback string) string {
	if reason, ok := ports.ConfigLocalityReasonFromError(err); ok {
		return string(reason)
	}
	return fallback
}

func localProviderAdmission(evidence doctor.ProviderV2Evidence, family string) (admitted, unsafe bool) {
	if evidence.SchemaID != "https://kar.local/schemas/kar-provider-contract-evidence.v2.schema.json" || evidence.ProviderID != family || evidence.URI == "" || len(evidence.SHA256) != 64 {
		return false, false
	}
	if _, err := hex.DecodeString(evidence.SHA256); err != nil || evidence.SecureWriterIndexStatus != doctor.EvidenceStatusPass || evidence.AssignmentStatus != doctor.EvidenceStatusPass {
		return false, evidence.SecureWriterIndexStatus == doctor.EvidenceStatusFail
	}
	required := map[string]bool{
		"PV-VERSION": false, "PV-NONINTERACTIVE": false, "PV-PROMPT-TRANSPORT": false, "PV-JSON-ONLY": false,
		"PV-STDOUT-STDERR": false, "PV-CANCELLATION": false, "PV-OUTPUT-CAP": false, "PV-AUTH-CACHE-CONCURRENCY": false,
		"PV-EXIT-CLASSIFICATION": false, "PV-CWD-ISOLATION": false, "PV-ROLE-FIT-logic": false, "PV-ROLE-FIT-security": false,
		"PV-ROLE-FIT-maintainability": false, "PV-ROLE-FIT-product": false, "PV-ROLE-FIT-documentation": false, "PV-ROLE-FIT-testing": false,
	}
	if len(evidence.Probes) != len(required) {
		return false, false
	}
	for _, probe := range evidence.Probes {
		seen, known := required[probe.ID]
		if !known || seen {
			return false, false
		}
		required[probe.ID] = true
		if probe.Status != doctor.EvidenceStatusPass {
			securityProbe := probe.ID == "PV-CWD-ISOLATION" || probe.ID == "PV-PROMPT-TRANSPORT" || probe.ID == "PV-STDOUT-STDERR"
			return false, securityProbe && probe.Status == doctor.EvidenceStatusFail
		}
	}
	return true, false
}

func localDoctorHumanOutput(diagnosis doctor.LocalDoctorResult) []byte {
	var output strings.Builder
	fmt.Fprintf(&output, "Readiness: %s\nConfiguration: %s\nProviders:\n", diagnosis.Readiness.State, diagnosis.Config.Status)
	for _, row := range diagnosis.ProviderInventory {
		fmt.Fprintf(&output, "- %s: %s\n", row.Family, row.State)
	}
	return []byte(output.String())
}
func (application *Application) handleProviders(ctx context.Context, invocation Invocation) execution {
	data, err := providersResultData(0, nil)
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureInternal)}
	}
	request, available := invocation.Providers()
	if !available {
		return execution{
			failureData: data,
			failure:     executionFailureFor(invocation.Command(), errors.New("missing request"), domain.FailureInternal),
		}
	}
	root, err := ports.NewAnchoredRoot(request.ProjectRoot())
	if err != nil {
		return execution{
			failureData: data,
			failure:     executionFailureFor(invocation.Command(), err, domain.FailureConfiguration),
		}
	}
	diagnoser, err := doctor.NewService(application.clock, application.catalog, application.inspector, application.evidenceReader, root)
	if err != nil {
		return execution{
			failureData: data,
			failure:     executionFailureFor(invocation.Command(), err, domain.FailureInternal),
		}
	}
	service, err := providers.NewService(diagnoser)
	if err != nil {
		return execution{
			failureData: data,
			failure:     executionFailureFor(invocation.Command(), err, domain.FailureInternal),
		}
	}
	result, err := service.ListProviderProfiles(ctx, request.IncludeUnverified())
	if err != nil {
		return execution{
			failureData: data,
			failure:     executionFailureFor(invocation.Command(), err, domain.FailureArtifact),
		}
	}
	providerEvidenceURI, readyProviderCount, err := providersEvidenceURI(result.Profiles())
	if err != nil {
		return execution{
			failureData: data,
			failure:     executionFailureFor(invocation.Command(), err, domain.FailureArtifact),
		}
	}
	data, err = providersResultData(readyProviderCount, providerEvidenceURI)
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureInternal)}
	}
	human := []byte(result.RenderHuman())
	if len(human) == 0 {
		human = []byte("no evidence-qualified provider profiles")
	}
	if readyProviderCount != 0 {
		return execution{human: human, data: data}
	}
	return execution{
		human:       human,
		data:        data,
		failureData: data,
		failure: &executionFailure{
			class: domain.FailureProviderUnavailable,
			code:  "readiness_unverified",
			stage: "cli.providers",
			exit:  app.ExitCodeReadiness,
		},
	}
}

func (application *Application) handleRoles(invocation Invocation) execution {
	if _, available := invocation.Roles(); !available {
		return execution{failure: executionFailureFor(invocation.Command(), errors.New("missing request"), domain.FailureInternal)}
	}
	roles := approles.ListRoles()
	data, err := json.Marshal(struct {
		Kind  string          `json:"kind"`
		Roles []approles.Role `json:"roles"`
	}{"roles_listed", roles})
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureInternal)}
	}
	var human strings.Builder
	human.WriteString("Roles:\n")
	for _, role := range roles {
		human.WriteString("- ")
		human.WriteString(role.ID)
		switch {
		case role.Mandatory:
			human.WriteString(" (mandatory)")
		case role.Availability == approles.AvailabilityUIProjects:
			human.WriteString(" (UI only)")
		}
		human.WriteByte('\n')
	}
	return execution{human: []byte(human.String()), data: data}
}

const maxReportMarkdownBytes int64 = 8 << 20

func (application *Application) handleStatus(ctx context.Context, invocation Invocation, canonicalProjectRoot string) execution {
	request, available := invocation.Status()
	if !available {
		return execution{failure: executionFailureFor(invocation.Command(), errors.New("missing request"), domain.FailureInternal)}
	}
	_, run, err := application.resolvePublicationRun(ctx, canonicalProjectRoot, request.RunID())
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureConfiguration)}
	}
	status, err := application.publicationQueries.ReadRunStatus(ctx, run)
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureArtifact)}
	}
	data, err := statusResultData(request, status)
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureArtifact)}
	}
	return execution{human: statusHumanOutput(status), data: data}
}

func (application *Application) handleReport(ctx context.Context, invocation Invocation, canonicalProjectRoot string) execution {
	request, available := invocation.Report()
	if !available {
		return execution{failure: executionFailureFor(invocation.Command(), errors.New("missing request"), domain.FailureInternal)}
	}
	destination, err := ports.NewSafeRelativePath(request.OutputPath())
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureConfiguration)}
	}
	if reportOutputUsesControlNamespace(destination.String()) {
		return execution{failure: executionFailureFor(invocation.Command(), errors.New("report output path is reserved"), domain.FailureConfiguration)}
	}
	projectRoot, run, err := application.resolvePublicationRun(ctx, canonicalProjectRoot, request.RunID())
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureConfiguration)}
	}
	if nilApplicationDependency(application.publicationReports) {
		return execution{failure: executionFailureFor(invocation.Command(), errors.New("G006 report service is unavailable"), domain.FailureArtifact)}
	}
	rendered, err := application.publicationReports.Render(ctx, run)
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureArtifact)}
	}
	if rendered.RunID != request.RunID() || len(rendered.Markdown) == 0 || int64(len(rendered.Markdown)) > maxReportMarkdownBytes {
		return execution{failure: executionFailureFor(invocation.Command(), errors.New("rendered report is not bound to the selected run"), domain.FailureArtifact)}
	}
	receipt, err := application.persistReportMarkdown(ctx, projectRoot, destination, rendered.SourceIDs, rendered.Markdown)
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureArtifact)}
	}
	uri := receipt.Destination().String()
	data, err := json.Marshal(struct {
		Kind      string `json:"kind"`
		ReportURI string `json:"report_uri"`
	}{"report_rendered", uri})
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureInternal)}
	}
	return execution{human: []byte("report rendered: " + uri), data: data}
}

func (application *Application) handleFindings(ctx context.Context, invocation Invocation, canonicalProjectRoot string) execution {
	request, available := invocation.Findings()
	if !available {
		return execution{failure: executionFailureFor(invocation.Command(), errors.New("missing request"), domain.FailureInternal)}
	}
	_, run, err := application.resolvePublicationRun(ctx, canonicalProjectRoot, request.RunID())
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureConfiguration)}
	}
	findings, err := application.publicationQueries.ListFindings(ctx, run, request.MinimumSeverity())
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureArtifact)}
	}
	if err := validateFindingsView(request, findings); err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureArtifact)}
	}
	data, err := json.Marshal(struct {
		Kind              string `json:"kind"`
		RunID             string `json:"run_id"`
		FindingCount      int    `json:"finding_count"`
		ReviewArtifactURI string `json:"review_artifact_uri"`
	}{"findings_listed", findings.RunID, len(findings.Findings), findings.ReviewArtifactURI})
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureInternal)}
	}
	return execution{human: findingsHumanOutput(findings), data: data}
}

func (application *Application) handleExcerpt(ctx context.Context, invocation Invocation, canonicalProjectRoot string) execution {
	request, available := invocation.Excerpt()
	if !available {
		return execution{failure: executionFailureFor(invocation.Command(), errors.New("missing request"), domain.FailureInternal)}
	}
	_, run, err := application.resolvePublicationRun(ctx, canonicalProjectRoot, request.RunID())
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureConfiguration)}
	}
	excerpt, err := application.publicationQueries.RenderExcerpt(ctx, run, request.FindingID(), request.CurrentTargetSHA256())
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureArtifact)}
	}
	if len(excerpt) == 0 {
		return execution{failure: executionFailureFor(invocation.Command(), errors.New("verified excerpt is empty"), domain.FailureArtifact)}
	}
	encoded := base64.StdEncoding.EncodeToString(excerpt)
	digest := sha256.Sum256(excerpt)
	checksum := "sha256:" + hex.EncodeToString(digest[:])
	data, err := json.Marshal(struct {
		Kind          string  `json:"kind"`
		EvidenceState string  `json:"evidence_state"`
		ExcerptURI    *string `json:"excerpt_uri"`
		ExcerptBase64 *string `json:"excerpt_base64"`
		ExcerptSHA256 *string `json:"excerpt_sha256"`
	}{"excerpt_rendered", "verified", nil, &encoded, &checksum})
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureInternal)}
	}
	return execution{human: excerpt, data: data, verbatim: true}
}

func (application *Application) resolvePublicationRun(
	ctx context.Context,
	canonicalProjectRoot string,
	rawRunID string,
) (ports.AnchoredRoot, ports.PublicationRun, error) {
	projectRoot, artifactRoot, err := publicationRoots(canonicalProjectRoot)
	if err != nil {
		return ports.AnchoredRoot{}, ports.PublicationRun{}, err
	}
	if nilApplicationDependency(application.publicationQueries) {
		return ports.AnchoredRoot{}, ports.PublicationRun{}, typedHandlerFailure("cli.query", domain.FailureArtifact, "G006 query service is unavailable", nil)
	}
	runID, err := domain.ParseRunID(rawRunID)
	if err != nil {
		return ports.AnchoredRoot{}, ports.PublicationRun{}, err
	}
	run, err := application.publicationQueries.ResolveRun(ctx, artifactRoot, runID)
	if err != nil {
		return ports.AnchoredRoot{}, ports.PublicationRun{}, classifyHandlerFailure(
			"cli.query",
			domain.FailureArtifact,
			"publication run resolution failed",
			err,
		)
	}
	if !run.Valid() || run.Root() != artifactRoot || run.RunID() != runID {
		return ports.AnchoredRoot{}, ports.PublicationRun{}, typedHandlerFailure("cli.query", domain.FailureArtifact, "publication run resolution returned an invalid scope", nil)
	}
	return projectRoot, run, nil
}

func publicationRoots(canonicalProjectRoot string) (ports.AnchoredRoot, ports.AnchoredRoot, error) {
	projectRoot, err := ports.NewAnchoredRoot(canonicalProjectRoot)
	if err != nil {
		return ports.AnchoredRoot{}, ports.AnchoredRoot{}, err
	}
	artifactPath := projectRoot.String() + "/.kar"
	if projectRoot.String() == "/" {
		artifactPath = "/.kar"
	}
	artifactRoot, err := ports.NewAnchoredRoot(artifactPath)
	if err != nil {
		return ports.AnchoredRoot{}, ports.AnchoredRoot{}, err
	}
	return projectRoot, artifactRoot, nil
}

func validateStatusPublicationPair(status RunStatusView) error {
	switch status.PublicationState {
	case domain.PublicationNotPublished:
		if status.RecoveryAction != domain.RecoveryActionResumeCollection &&
			status.RecoveryAction != domain.RecoveryActionRestageValidatedCandidate {
			return errors.New("not-published status has an invalid recovery action")
		}
	case domain.PublicationStaged:
		if status.RecoveryAction != domain.RecoveryActionInstallStagedFinal {
			return errors.New("staged status has an invalid recovery action")
		}
	case domain.PublicationInstalled:
		if status.RecoveryAction != domain.RecoveryActionCommitCompositeEpoch {
			return errors.New("installed status has an invalid recovery action")
		}
	case domain.PublicationCommitted:
		if status.RecoveryAction != domain.RecoveryActionReconstructCompletedStatus {
			return errors.New("committed status has an invalid recovery action")
		}
		switch status.RunState {
		case domain.RunCompleted, domain.RunDegraded, domain.RunFailed:
		default:
			return errors.New("committed status has a non-publishable run state")
		}
		return nil
	default:
		return errors.New("status does not represent a readable publication state")
	}
	if status.HasRunState || status.RunState != "" || status.HasFinalArtifact ||
		status.FinalArtifactURI != "" || status.HasAxes ||
		status.ContentVerdict != "" || status.CoverageStatus != "" || status.CIDecision != "" {
		return errors.New("non-P2 status exposed committed authority fields")
	}
	return nil
}

func statusResultData(request StatusRequest, status RunStatusView) ([]byte, error) {
	if status.RunID != request.RunID() || !status.PublicationState.Valid() || !status.RecoveryAction.Valid() {
		return nil, errors.New("status projection is invalid")
	}
	if err := validateStatusPublicationPair(status); err != nil {
		return nil, err
	}
	if status.HasRunState {
		if !status.RunState.Valid() {
			return nil, errors.New("status run state is invalid")
		}
	} else if status.RunState != "" {
		return nil, errors.New("status run state presence is inconsistent")
	}
	if status.HasFinalArtifact {
		if status.PublicationState != domain.PublicationCommitted {
			return nil, errors.New("non-P2 status exposed a final artifact path")
		}
		path, err := ports.NewSafeRelativePath(status.FinalArtifactURI)
		if err != nil || path.String() != status.FinalArtifactURI || !strings.HasPrefix(status.FinalArtifactURI, ".kar/") {
			return nil, errors.New("status final artifact path is invalid")
		}
	} else if status.FinalArtifactURI != "" {
		return nil, errors.New("status final artifact presence is inconsistent")
	}
	if status.HasAxes {
		if status.PublicationState != domain.PublicationCommitted || !status.HasFinalArtifact ||
			!status.ContentVerdict.Valid() || !status.CoverageStatus.Valid() || !status.CIDecision.Valid() {
			return nil, errors.New("status outcome axes are not an all-or-none P2 projection")
		}
	} else if status.ContentVerdict != "" || status.CoverageStatus != "" || status.CIDecision != "" {
		return nil, errors.New("status outcome axes are present without P2 authority")
	}
	if status.PublicationState == domain.PublicationCommitted &&
		(!status.HasRunState || !status.HasFinalArtifact || !status.HasAxes) {
		return nil, errors.New("P2 status omitted committed authority fields")
	}
	var contentVerdict *string
	var coverageStatus *string
	var ciDecision *string
	if status.HasAxes {
		content := string(status.ContentVerdict)
		coverage := string(status.CoverageStatus)
		ci := string(status.CIDecision)
		contentVerdict = &content
		coverageStatus = &coverage
		ciDecision = &ci
	}
	var runState *string
	if status.HasRunState {
		value := string(status.RunState)
		runState = &value
	}
	recoveryAction := string(status.RecoveryAction)
	var finalArtifactURI *string
	if status.HasFinalArtifact {
		finalArtifactURI = &status.FinalArtifactURI
	}
	return json.Marshal(struct {
		Kind              string  `json:"kind"`
		RunID             string  `json:"run_id"`
		RunState          *string `json:"run_state"`
		PublicationStatus string  `json:"publication_status"`
		RecoveryAction    string  `json:"recovery_action"`
		FinalArtifactURI  *string `json:"final_artifact_uri"`
		ContentVerdict    *string `json:"content_verdict,omitempty"`
		CoverageStatus    *string `json:"coverage_status,omitempty"`
		CIDecision        *string `json:"ci_decision,omitempty"`
	}{
		Kind:              "status_read",
		RunID:             status.RunID,
		RunState:          runState,
		PublicationStatus: string(status.PublicationState),
		RecoveryAction:    recoveryAction,
		FinalArtifactURI:  finalArtifactURI,
		ContentVerdict:    contentVerdict,
		CoverageStatus:    coverageStatus,
		CIDecision:        ciDecision,
	})
}

func statusHumanOutput(status RunStatusView) []byte {
	var output strings.Builder
	output.WriteString("run_id: ")
	output.WriteString(status.RunID)
	if status.HasRunState {
		output.WriteString("\nrun_state: ")
		output.WriteString(string(status.RunState))
	} else {
		output.WriteString("\nrun_state: unavailable")
	}
	output.WriteString("\npublication_status: ")
	output.WriteString(string(status.PublicationState))
	output.WriteString("\nrecovery_action: ")
	output.WriteString(string(status.RecoveryAction))
	if status.HasFinalArtifact {
		output.WriteString("\nfinal_artifact_uri: ")
		output.WriteString(status.FinalArtifactURI)
	}
	if status.HasAxes {
		output.WriteString("\ncontent_verdict: ")
		output.WriteString(string(status.ContentVerdict))
		output.WriteString("\ncoverage_status: ")
		output.WriteString(string(status.CoverageStatus))
		output.WriteString("\nci_decision: ")
		output.WriteString(string(status.CIDecision))
	}
	return []byte(output.String())
}

func validateFindingsView(request FindingsRequest, findings FindingsView) error {
	if findings.RunID != request.RunID() || len(findings.Findings) > 1_000_000 {
		return errors.New("findings projection is not bound to the selected run")
	}
	path, err := ports.NewSafeRelativePath(findings.ReviewArtifactURI)
	if err != nil || path.String() != findings.ReviewArtifactURI || !strings.HasPrefix(findings.ReviewArtifactURI, ".kar/") {
		return errors.New("findings projection omitted the committed review artifact URI")
	}
	for _, finding := range findings.Findings {
		if !validFindingID(finding.ID) || !finding.Severity.Valid() ||
			finding.Title == "" || strings.ContainsAny(finding.Title, "\x00\r\n") {
			return errors.New("findings projection contains an invalid finding")
		}
	}
	return nil
}

func findingsHumanOutput(findings FindingsView) []byte {
	var output strings.Builder
	output.WriteString("review_artifact_uri: ")
	output.WriteString(findings.ReviewArtifactURI)
	output.WriteString("\nfinding_count: ")
	output.WriteString(strconv.Itoa(len(findings.Findings)))
	for _, finding := range findings.Findings {
		output.WriteByte('\n')
		output.WriteString(finding.ID)
		output.WriteString(" [")
		output.WriteString(string(finding.Severity))
		output.WriteString("] ")
		output.WriteString(finding.Title)
	}
	return []byte(output.String())
}

type configurationOutput struct {
	Kind         string                    `json:"kind"`
	Mode         ConfigMode                `json:"mode"`
	ConfigURI    string                    `json:"config_uri"`
	ConfigSHA256 string                    `json:"config_sha256"`
	Policy       json.RawMessage           `json:"policy,omitempty"`
	Provenance   []appconfig.ProvenanceRow `json:"provenance,omitempty"`
}

func resolvedConfigOutput(request ConfigRequest, resolved appconfig.Resolution) ([]byte, error) {
	policy := resolved.RedactedJSON()
	if !json.Valid(policy) {
		return nil, errors.New("redacted policy JSON is invalid")
	}
	output := configurationOutput{Kind: "configuration_resolved", Mode: request.Mode(), ConfigURI: resolved.URI(), ConfigSHA256: resolved.SHA256()}
	if request.Mode() == ConfigModeProvenance {
		output.Provenance = resolved.Provenance()
	} else {
		output.Policy = json.RawMessage(policy)
	}
	return json.Marshal(output)
}

func initFailureHuman(result appinit.InitializeProjectResult, code string) string {
	switch code {
	case "init_destination_exists":
		return "kar: .kar/config.yaml already exists"
	case "init_private_dir_commit_unconfirmed", "init_existing_private_dir_commit_unconfirmed":
		return "kar: private KAR directory durability is unconfirmed"
	case "init_commit_unconfirmed":
		return "kar: .kar/config.yaml was installed but durability is unconfirmed"
	default:
		return "kar: initialization failed (" + code + ")"
	}
}

func schemaResultData(schemaID string, exportURI *string) ([]byte, error) {
	return json.Marshal(struct {
		Kind      string  `json:"kind"`
		SchemaID  string  `json:"schema_id"`
		ExportURI *string `json:"export_uri"`
	}{"schema_inspected", schemaID, exportURI})
}
func providersEvidenceURI(profiles []providers.Profile) (*string, int, error) {
	var authorityURI *string
	readyProviderCount := 0
	for _, profile := range profiles {
		if profile.Support() != providers.SupportSupported {
			continue
		}
		readyProviderCount++
		uri, available := profile.EvidenceURI()
		if !available {
			return nil, 0, errors.New("supported provider profile omitted authority evidence URI")
		}
		if authorityURI == nil {
			authorityURI = &uri
			continue
		}
		if *authorityURI != uri {
			return nil, 0, errors.New("supported provider profiles have conflicting authority evidence URIs")
		}
	}
	return authorityURI, readyProviderCount, nil
}

func providersResultData(readyProviderCount int, providerEvidenceURI *string) ([]byte, error) {
	return json.Marshal(struct {
		Kind                string  `json:"kind"`
		ProviderEvidenceURI *string `json:"provider_evidence_uri"`
		ReadyProviderCount  int     `json:"ready_provider_count"`
	}{"providers_listed", providerEvidenceURI, readyProviderCount})
}

func (application *Application) persistJSON(
	ctx context.Context,
	root ports.AnchoredRoot,
	directory ports.SafeRelativePath,
	destination ports.SafeRelativePath,
	channel string,
	sourceIDs []string,
	contents []byte,
) (ports.SecureWriteReceipt, error) {
	if err := application.writer.EnsurePrivateDir(root, directory); err != nil {
		return ports.SecureWriteReceipt{}, typedHandlerFailure("cli.persist", domain.FailureArtifact, "private output directory unavailable", err)
	}
	aborted := false
	var abortCause error
	request, err := ports.NewSecureWriteRequest(
		root,
		destination,
		channel,
		bytes.NewReader(contents),
		int64(len(contents)),
		sourceIDs,
		func(cause error) {
			aborted = true
			abortCause = cause
		},
	)
	if err != nil {
		return ports.SecureWriteReceipt{}, typedHandlerFailure("cli.persist", domain.FailureInternal, "output request construction failed", err)
	}
	receipt, drop, writeErr := application.writer.Write(ctx, request)
	if drop != nil {
		return ports.SecureWriteReceipt{}, typedHandlerFailure(
			"cli.persist",
			domain.FailureSecurityPolicy,
			"secure writer rejected output",
			errors.Join(writeErr, abortCause),
		)
	}
	if writeErr != nil {
		return ports.SecureWriteReceipt{}, typedHandlerFailure(
			"cli.persist",
			domain.FailureArtifact,
			"output write failed",
			errors.Join(writeErr, abortCause),
		)
	}
	if aborted {
		return ports.SecureWriteReceipt{}, typedHandlerFailure("cli.persist", domain.FailureInternal, "secure writer abort callback was not accompanied by a rejection", abortCause)
	}
	expected := sha256.Sum256(contents)
	if receipt.Root() != root ||
		receipt.Destination() != destination ||
		receipt.ByteLength() != int64(len(contents)) ||
		receipt.SHA256() != "sha256:"+hex.EncodeToString(expected[:]) ||
		receipt.Channel() != channel ||
		!sameStrings(receipt.SourceIDs(), sourceIDs) {
		return ports.SecureWriteReceipt{}, typedHandlerFailure("cli.persist", domain.FailureArtifact, "output receipt did not bind accepted bytes and lineage", nil)
	}
	return receipt, nil
}
func (application *Application) persistReportMarkdown(
	ctx context.Context,
	root ports.AnchoredRoot,
	destination ports.SafeRelativePath,
	sourceIDs []string,
	contents []byte,
) (ports.SecureWriteReceipt, error) {
	if len(contents) == 0 || int64(len(contents)) > maxReportMarkdownBytes {
		return ports.SecureWriteReceipt{}, typedHandlerFailure("cli.report", domain.FailureArtifact, "report bytes exceed the write limit", nil)
	}
	if reportOutputUsesControlNamespace(destination.String()) {
		return ports.SecureWriteReceipt{}, typedHandlerFailure("cli.report", domain.FailureConfiguration, "report output path is reserved", nil)
	}
	if parent, present, err := reportParentDirectory(destination); err != nil {
		return ports.SecureWriteReceipt{}, typedHandlerFailure("cli.report", domain.FailureArtifact, "report output parent is invalid", err)
	} else if present {
		if err := application.writer.EnsurePrivateDir(root, parent); err != nil {
			return ports.SecureWriteReceipt{}, typedHandlerFailure("cli.report", domain.FailureArtifact, "private report output directory unavailable", err)
		}
	}
	aborted := false
	var abortCause error
	request, err := ports.NewSecureWriteRequest(
		root,
		destination,
		"report_markdown",
		bytes.NewReader(contents),
		maxReportMarkdownBytes,
		cloneApplicationStrings(sourceIDs),
		func(cause error) {
			aborted = true
			abortCause = cause
		},
	)
	if err != nil {
		return ports.SecureWriteReceipt{}, typedHandlerFailure("cli.report", domain.FailureArtifact, "report write request is invalid", err)
	}
	receipt, drop, writeErr := application.writer.Write(ctx, request)
	if drop != nil {
		return ports.SecureWriteReceipt{}, typedHandlerFailure(
			"cli.report",
			domain.FailureSecurityPolicy,
			"secure writer rejected report output",
			errors.Join(writeErr, abortCause),
		)
	}
	if writeErr != nil {
		return ports.SecureWriteReceipt{}, classifyHandlerFailure(
			"cli.report",
			domain.FailureArtifact,
			"report output write failed",
			errors.Join(writeErr, abortCause),
		)
	}
	if aborted {
		return ports.SecureWriteReceipt{}, typedHandlerFailure("cli.report", domain.FailureInternal, "secure writer abort callback was not accompanied by a rejection", abortCause)
	}
	expected := sha256.Sum256(contents)
	if receipt.Root() != root ||
		receipt.Destination() != destination ||
		receipt.ByteLength() != int64(len(contents)) ||
		receipt.SHA256() != "sha256:"+hex.EncodeToString(expected[:]) ||
		receipt.Channel() != "report_markdown" ||
		!sameStrings(receipt.SourceIDs(), sourceIDs) {
		return ports.SecureWriteReceipt{}, typedHandlerFailure("cli.report", domain.FailureArtifact, "report output receipt did not bind accepted bytes and lineage", nil)
	}
	return receipt, nil
}

func reportParentDirectory(destination ports.SafeRelativePath) (ports.SafeRelativePath, bool, error) {
	index := strings.LastIndexByte(destination.String(), '/')
	if index < 0 {
		return ports.SafeRelativePath{}, false, nil
	}
	parent, err := ports.NewSafeRelativePath(destination.String()[:index])
	if err != nil {
		return ports.SafeRelativePath{}, false, err
	}
	return parent, true, nil
}

func reportOutputUsesControlNamespace(outputPath string) bool {
	namespace, _, _ := strings.Cut(outputPath, "/")
	switch {
	case strings.EqualFold(namespace, ".kar"),
		strings.EqualFold(namespace, ".git"),
		strings.EqualFold(namespace, ".gjc"):
		return true
	default:
		return false
	}
}
func sameStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func classifyHandlerFailure(stage string, fallback domain.FailureClass, reason string, cause error) error {
	if cause != nil {
		var failure *domain.Failure
		if errors.As(cause, &failure) ||
			errors.Is(cause, context.Canceled) ||
			errors.Is(cause, context.DeadlineExceeded) {
			return cause
		}
	}
	return typedHandlerFailure(stage, fallback, reason, cause)
}
func typedHandlerFailure(stage string, class domain.FailureClass, reason string, cause error) error {
	failure, err := domain.NewFailure(stage, class, reason, cause)
	if err != nil {
		return errors.New("handler failure invariant")
	}
	return failure
}
