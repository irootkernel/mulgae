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
	"strconv"
	"strings"

	"github.com/irootkernel/kkachi-agent-review/internal/app"
	appconfig "github.com/irootkernel/kkachi-agent-review/internal/app/config"
	appdelta "github.com/irootkernel/kkachi-agent-review/internal/app/delta"
	"github.com/irootkernel/kkachi-agent-review/internal/app/doctor"
	appfollowup "github.com/irootkernel/kkachi-agent-review/internal/app/followup"
	apphelp "github.com/irootkernel/kkachi-agent-review/internal/app/help"
	appinit "github.com/irootkernel/kkachi-agent-review/internal/app/init"
	"github.com/irootkernel/kkachi-agent-review/internal/app/providers"
	appreplay "github.com/irootkernel/kkachi-agent-review/internal/app/rerun"
	appschema "github.com/irootkernel/kkachi-agent-review/internal/app/schema"
	"github.com/irootkernel/kkachi-agent-review/internal/domain"
	"github.com/irootkernel/kkachi-agent-review/internal/ports"
)

const (
	globalConfigAssetID = "defaults:global-config"
	doctorResultSchema  = "https://kar.local/schemas/kar-doctor-result.v1.schema.json"
)

func (application *Application) execute(ctx context.Context, invocation Invocation, canonicalProjectRoot string) execution {
	switch invocation.Command() {
	case app.CommandHelp:
		return application.handleHelp(ctx, invocation)
	case app.CommandSchema:
		return application.handleSchema(ctx, invocation)
	case app.CommandInit:
		return application.handleInit(ctx, invocation)
	case app.CommandConfig:
		return application.handleConfig(ctx, invocation)
	case app.CommandDoctor:
		return application.handleDoctor(ctx, invocation)
	case app.CommandProviders:
		return application.handleProviders(ctx, invocation)
	case app.CommandStatus:
		return application.handleStatus(ctx, invocation, canonicalProjectRoot)
	case app.CommandReport:
		return application.handleReport(ctx, invocation, canonicalProjectRoot)
	case app.CommandFindings:
		return application.handleFindings(ctx, invocation, canonicalProjectRoot)
	case app.CommandExcerpt:
		return application.handleExcerpt(ctx, invocation, canonicalProjectRoot)
	case app.CommandFollowup:
		return application.handleFollowup(ctx, invocation)
	case app.CommandDelta:
		return application.handleDelta(ctx, invocation)
	case app.CommandRerun:
		return application.handleRerun(ctx, invocation)
	case app.CommandClean:
		return application.handleClean(ctx, invocation)
	case app.CommandExport:
		return application.handleExport(ctx, invocation, canonicalProjectRoot)
	default:
		return execution{failure: executionFailureFor(invocation.Command(), errors.New("unsupported foundation dispatch"), domain.FailureInternal)}
	}
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
	case appfollowup.TargetDiff, appfollowup.TargetPatch, appfollowup.TargetStdin:
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
	case appdelta.TargetDiff, appdelta.TargetPatch, appdelta.TargetStdin:
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
	var contextPath *ports.SafeRelativePath
	if raw, present := request.ContextPath(); present {
		parsed, err := ports.NewSafeRelativePath(raw)
		if err != nil {
			return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureConfiguration)}
		}
		contextPath = &parsed
	}
	service, err := appinit.NewService(application.writer, application.clock)
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureInternal)}
	}
	initialized, err := service.InitializeProject(ctx, appinit.InitializeProjectRequest{
		ProjectRoot:         root,
		ProjectName:         request.ProjectName(),
		ContextPath:         contextPath,
		IntendedProviderIDs: request.IntendedProviderIDs(),
	})
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureArtifact)}
	}
	if initialized.ConfigReceipt.Destination().String() != ".kar.yaml" {
		return execution{failure: executionFailureFor(invocation.Command(), errors.New("initialization receipt mismatch"), domain.FailureArtifact)}
	}
	for _, provider := range initialized.ProviderStatuses {
		if provider.Status != "unverified" {
			return execution{failure: executionFailureFor(invocation.Command(), errors.New("provider status promoted"), domain.FailureInternal)}
		}
	}
	projectConfigURI := initialized.ConfigReceipt.Destination().String()
	data, err := json.Marshal(struct {
		Kind                string   `json:"kind"`
		ProjectConfigURI    string   `json:"project_config_uri"`
		IntendedProviderIDs []string `json:"intended_provider_ids"`
	}{"initialized", projectConfigURI, request.IntendedProviderIDs()})
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureInternal)}
	}
	var output strings.Builder
	output.WriteString("initialized: ")
	output.WriteString(projectConfigURI)
	for _, provider := range initialized.ProviderStatuses {
		output.WriteByte('\n')
		output.WriteString(provider.ID)
		output.WriteString(": ")
		output.WriteString(provider.Status)
	}
	return execution{human: []byte(output.String()), data: data}
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
	globalID, err := ports.ParseAssetID(globalConfigAssetID)
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureInternal)}
	}
	metadata, globalYAML, err := application.catalog.Read(ctx, globalID)
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureArtifact)}
	}
	globalDigest := sha256.Sum256(globalYAML)
	if metadata.ID() != globalID ||
		metadata.Kind() != ports.AssetKindDefaults ||
		metadata.ByteLength() != int64(len(globalYAML)) ||
		metadata.SHA256() != "sha256:"+hex.EncodeToString(globalDigest[:]) {
		return execution{failure: executionFailureFor(invocation.Command(), errors.New("global default metadata mismatch"), domain.FailureArtifact)}
	}

	resolveRequest := appconfig.ResolveRequest{GlobalYAML: globalYAML}
	if rawPath, enabled := request.ProjectConfigPath(); enabled {
		path, err := ports.NewSafeRelativePath(rawPath)
		if err != nil {
			return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureConfiguration)}
		}
		expectedCommit, err := ports.ParseGitObjectID(request.Reference())
		if err != nil {
			return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureConfiguration)}
		}
		resolveRequest.Project = &appconfig.ProjectConfigRequest{
			Root:           root,
			ExpectedCommit: expectedCommit,
			Reference:      expectedCommit.String(),
			Path:           &path,
		}
	}
	service, err := appconfig.NewService(application.projectReader)
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureInternal)}
	}
	resolved, err := service.Resolve(ctx, resolveRequest)
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureConfiguration)}
	}
	output, err := resolvedConfigOutput(request, resolved)
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureInternal)}
	}

	if invocation.OutputFormat() == OutputFormatHuman {
		return execution{human: output, data: nil}
	}
	destination, err := ports.NewSafeRelativePath(".kar/config/" + invocation.RequestID() + ".json")
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureInternal)}
	}
	directory, err := ports.NewSafeRelativePath(".kar/config")
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureInternal)}
	}
	sourceIDs := configResolutionSourceIDs(resolved)
	receipt, err := application.persistJSON(ctx, root, directory, destination, "config_resolution", sourceIDs, output)
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureArtifact)}
	}
	uri := receipt.Destination().String()
	data, err := json.Marshal(struct {
		Kind              string `json:"kind"`
		ResolvedPolicyURI string `json:"resolved_policy_uri"`
		PolicySHA256      string `json:"policy_sha256"`
	}{"configuration_resolved", uri, receipt.SHA256()})
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureInternal)}
	}
	return execution{human: output, data: data}
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
	service, err := doctor.NewService(application.clock, application.catalog, application.inspector, application.evidenceReader, root)
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureInternal)}
	}
	diagnosis, err := service.DiagnoseEnvironment(ctx)
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureArtifact)}
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

	if invocation.OutputFormat() == OutputFormatHuman {
		if diagnosis.Readiness.State == doctor.ReadinessReady {
			return execution{human: raw, data: nil}
		}
		return execution{
			human: raw,
			failure: &executionFailure{
				class: domain.FailureProviderUnavailable,
				code:  "readiness_unverified",
				stage: "cli.doctor",
				exit:  app.ExitCodeReadiness,
			},
		}
	}

	destination, err := ports.NewSafeRelativePath(".kar/diagnostics/" + invocation.RequestID() + ".json")
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureInternal)}
	}
	directory, err := ports.NewSafeRelativePath(".kar/diagnostics")
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureInternal)}
	}
	receipt, err := application.persistJSON(ctx, root, directory, destination, "doctor_result", []string{doctorResultSchema}, raw)
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureArtifact)}
	}
	uri := receipt.Destination().String()
	data, err := json.Marshal(struct {
		Kind            string `json:"kind"`
		DoctorResultURI string `json:"doctor_result_uri"`
		Readiness       string `json:"readiness"`
	}{"diagnosed", uri, string(diagnosis.Readiness.State)})
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureInternal)}
	}
	if diagnosis.Readiness.State == doctor.ReadinessReady {
		return execution{human: raw, data: data}
	}
	return execution{
		human:       raw,
		data:        data,
		failureData: data,
		failure: &executionFailure{
			class: domain.FailureProviderUnavailable,
			code:  "readiness_unverified",
			stage: "cli.doctor",
			exit:  app.ExitCodeReadiness,
		},
	}
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
	Mode              ConfigMode                      `json:"mode"`
	Policy            json.RawMessage                 `json:"policy"`
	ProjectProvenance *configurationProjectProvenance `json:"project_provenance"`
}

type configurationProjectProvenance struct {
	Commit string `json:"commit"`
	Path   string `json:"path"`
}

func resolvedConfigOutput(request ConfigRequest, resolved appconfig.Resolution) ([]byte, error) {
	policy := resolved.RedactedJSON()
	if !json.Valid(policy) {
		return nil, errors.New("redacted policy JSON is invalid")
	}
	var provenance *configurationProjectProvenance
	if project, available := resolved.Project(); available {
		provenance = &configurationProjectProvenance{
			Commit: project.Commit().String(),
			Path:   project.Path().String(),
		}
	}
	return json.Marshal(configurationOutput{
		Mode:              request.Mode(),
		Policy:            json.RawMessage(policy),
		ProjectProvenance: provenance,
	})
}
func configResolutionSourceIDs(resolved appconfig.Resolution) []string {
	sourceIDs := []string{globalConfigAssetID, "config:resolved-policy:v1"}
	if project, available := resolved.Project(); available {
		sourceIDs = append(sourceIDs, "config:project:"+project.Commit().String()+":"+project.Path().String())
	}
	return sourceIDs
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
		strings.EqualFold(namespace, ".gjc"),
		strings.EqualFold(namespace, ".kar.yaml"),
		strings.EqualFold(namespace, ".kar.yml"):
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
