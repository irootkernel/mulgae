// Package kar parses the fixed KAR command line into immutable invocations.
package kar

import (
	"context"

	"github.com/irootkernel/kkachi-agent-review/internal/app"
	"github.com/irootkernel/kkachi-agent-review/internal/domain"
)

// OutputFormat controls the CLI rendering selected by an invocation.
type OutputFormat string

const (
	// OutputFormatJSON requests the machine-readable command envelope.
	OutputFormatJSON OutputFormat = "json"
	// OutputFormatHuman requests the human-readable command envelope.
	OutputFormatHuman OutputFormat = "human"
)

// Availability describes whether a command is executable in the current milestone.
type Availability string

const (
	// AvailabilityFoundation identifies an executable foundation command.
	AvailabilityFoundation Availability = "foundation"
	// AvailabilityFutureMilestone identifies a recognized but unavailable command.
	AvailabilityFutureMilestone Availability = "future_milestone"
)

// ConfigMode selects the configuration view returned by the config service.
type ConfigMode string

const (
	// ConfigModeEffective selects the effective configuration view.
	ConfigModeEffective ConfigMode = "effective"
	// ConfigModeProvenance selects the provenance configuration view.
	ConfigModeProvenance ConfigMode = "provenance"
)

// SchemaOperation selects a schema catalog operation.
type SchemaOperation string

const (
	// SchemaOperationList lists the embedded schema catalog.
	SchemaOperationList SchemaOperation = "list"
	// SchemaOperationShow renders one embedded schema.
	SchemaOperationShow SchemaOperation = "show"
	// SchemaOperationExport securely writes one embedded schema.
	SchemaOperationExport SchemaOperation = "export"
)

// RequestResolver resolves CLI-only selectors before a schema request is frozen.
// Implementations must return canonical IDs and a nonempty captured stdin target.
type RequestResolver interface {
	ResolveRun(context.Context, string) (string, error)
	ResolveAttempt(context.Context, string, string, string) (string, error)
	CaptureTarget(context.Context) (string, error)
}

// Invocation is the immutable result of parsing one KAR command line.
type Invocation struct {
	command        app.CommandName
	availability   Availability
	requestID      string
	outputFormat   OutputFormat
	requestJSON    []byte
	hasRequestJSON bool
	help           *HelpRequest
	init           *InitRequest
	doctor         *DoctorRequest
	config         *ConfigRequest
	providers      *ProvidersRequest
	schema         *SchemaRequest
	status         *StatusRequest
	report         *ReportRequest
	findings       *FindingsRequest
	excerpt        *ExcerptRequest
	followup       *FollowupRequest
	review         *ReviewRequest
	delta          *DeltaRequest
	rerun          *RerunRequest
	clean          *CleanRequest
	prompt         *PromptRequest
	export         *ExportRequest
}

// Command returns the exact recognized command name.
func (invocation Invocation) Command() app.CommandName { return invocation.command }

// Availability reports whether the command can execute in this milestone.
func (invocation Invocation) Availability() Availability { return invocation.availability }

// FutureMilestone reports whether dispatch must reject the command as unavailable.
func (invocation Invocation) FutureMilestone() bool {
	return invocation.availability == AvailabilityFutureMilestone
}

// RequestID returns the caller-provided request identifier.
func (invocation Invocation) RequestID() string { return invocation.requestID }

// OutputFormat returns the selected response representation.
func (invocation Invocation) OutputFormat() OutputFormat { return invocation.outputFormat }

// RequestJSON returns a caller-owned copy of the exact command-request object.
// The boolean is false when no contract-consistent request object is available.
func (invocation Invocation) RequestJSON() ([]byte, bool) {
	if !invocation.hasRequestJSON {
		return nil, false
	}
	return cloneBytes(invocation.requestJSON), true
}

// Help returns the parsed help fields when this is a help invocation.
func (invocation Invocation) Help() (HelpRequest, bool) {
	if invocation.help == nil {
		return HelpRequest{}, false
	}
	return *invocation.help, true
}

// Init returns the parsed init fields when this is an init invocation.
func (invocation Invocation) Init() (InitRequest, bool) {
	if invocation.init == nil {
		return InitRequest{}, false
	}
	return cloneInitRequest(*invocation.init), true
}

// Doctor returns the parsed doctor fields when this is a doctor invocation.
func (invocation Invocation) Doctor() (DoctorRequest, bool) {
	if invocation.doctor == nil {
		return DoctorRequest{}, false
	}
	return *invocation.doctor, true
}

// Status returns the parsed status fields when this is a status invocation.
func (invocation Invocation) Status() (StatusRequest, bool) {
	if invocation.status == nil {
		return StatusRequest{}, false
	}
	return *invocation.status, true
}

// Report returns the parsed report fields when this is a report invocation.
func (invocation Invocation) Report() (ReportRequest, bool) {
	if invocation.report == nil {
		return ReportRequest{}, false
	}
	return *invocation.report, true
}

// Findings returns the parsed findings fields when this is a findings invocation.
func (invocation Invocation) Findings() (FindingsRequest, bool) {
	if invocation.findings == nil {
		return FindingsRequest{}, false
	}
	return *invocation.findings, true
}

// Excerpt returns the parsed excerpt fields when this is an excerpt invocation.
func (invocation Invocation) Excerpt() (ExcerptRequest, bool) {
	if invocation.excerpt == nil {
		return ExcerptRequest{}, false
	}
	return *invocation.excerpt, true
}

// Config returns the parsed config fields when this is a config invocation.
func (invocation Invocation) Config() (ConfigRequest, bool) {
	if invocation.config == nil {
		return ConfigRequest{}, false
	}
	return *invocation.config, true
}

// Providers returns the parsed providers fields when this is a providers invocation.
func (invocation Invocation) Providers() (ProvidersRequest, bool) {
	if invocation.providers == nil {
		return ProvidersRequest{}, false
	}
	return *invocation.providers, true
}

// Schema returns the parsed schema fields when this is a schema invocation.
func (invocation Invocation) Schema() (SchemaRequest, bool) {
	if invocation.schema == nil {
		return SchemaRequest{}, false
	}
	return *invocation.schema, true
}

// Review returns the parsed review fields when this is a review invocation.
func (invocation Invocation) Review() (ReviewRequest, bool) {
	if invocation.review == nil {
		return ReviewRequest{}, false
	}
	return cloneReviewRequest(*invocation.review), true
}

// Followup returns the parsed followup fields when this is a followup invocation.
func (invocation Invocation) Followup() (FollowupRequest, bool) {
	if invocation.followup == nil {
		return FollowupRequest{}, false
	}
	return *invocation.followup, true
}

// Delta returns the parsed delta fields when this is a delta invocation.
func (invocation Invocation) Delta() (DeltaRequest, bool) {
	if invocation.delta == nil {
		return DeltaRequest{}, false
	}
	return cloneDeltaRequest(*invocation.delta), true
}

// Rerun returns the parsed rerun fields when this is a rerun invocation.
func (invocation Invocation) Rerun() (RerunRequest, bool) {
	if invocation.rerun == nil {
		return RerunRequest{}, false
	}
	return *invocation.rerun, true
}

// Clean returns the parsed clean fields when this is a clean invocation.
func (invocation Invocation) Clean() (CleanRequest, bool) {
	if invocation.clean == nil {
		return CleanRequest{}, false
	}
	return *invocation.clean, true
}

// Prompt returns the parsed prompt fields when this is a prompt invocation.
func (invocation Invocation) Prompt() (PromptRequest, bool) {
	if invocation.prompt == nil {
		return PromptRequest{}, false
	}
	return *invocation.prompt, true
}

// Export returns the parsed export fields when this is an export invocation.
func (invocation Invocation) Export() (ExportRequest, bool) {
	if invocation.export == nil {
		return ExportRequest{}, false
	}
	return *invocation.export, true
}

// HelpRequest contains a validated fixed help topic.
type HelpRequest struct {
	topic string
}

// Topic returns the requested help topic.
func (request HelpRequest) Topic() string { return request.topic }

// InitRequest contains the executable init fields. ContextPath is absent unless
// the user explicitly supplied --context.
type InitRequest struct {
	projectRoot         string
	projectName         string
	contextPath         string
	hasContextPath      bool
	selectionMode       string
	providerIDs         []string
	roleIDs             []string
	nativeHome          string
	hasNativeHome       bool
	kimiExecutable      string
	kimiModel           string
	kimiDataHome        string
	zcodeNodeExecutable string
	zcodeLauncher       string
	agyExecutable       string
	agyPermissionMode   string
}

// ProjectRoot returns the canonical project root selected for initialization.
func (request InitRequest) ProjectRoot() string { return request.projectRoot }

// ProjectName returns the validated project name.
func (request InitRequest) ProjectName() string { return request.projectName }

// ContextPath returns the optional safe relative context path.
func (request InitRequest) ContextPath() (string, bool) {
	return request.contextPath, request.hasContextPath
}

func (request InitRequest) Selection() (string, []string) {
	return request.selectionMode, cloneStrings(request.providerIDs)
}

// Roles returns the canonical project role set selected for initialization.
func (request InitRequest) Roles() []string { return cloneStrings(request.roleIDs) }
func (request InitRequest) NativeHome() (string, bool) {
	return request.nativeHome, request.hasNativeHome
}
func (request InitRequest) KimiOverrides() (string, string, string) {
	return request.kimiExecutable, request.kimiModel, request.kimiDataHome
}
func (request InitRequest) ZCodeOverrides() (string, string) {
	return request.zcodeNodeExecutable, request.zcodeLauncher
}
func (request InitRequest) AGYOverrides() (string, string) {
	return request.agyExecutable, request.agyPermissionMode
}
func (request InitRequest) Overwrite() bool { return false }

// DoctorRequest contains the executable doctor fields.
type DoctorRequest struct {
	projectRoot    string
	checkProviders bool
	checkPlatform  bool
}

// ProjectRoot returns the canonical project root selected for diagnosis.
func (request DoctorRequest) ProjectRoot() string { return request.projectRoot }

// CheckProviders reports the fixed provider-check selection.
func (request DoctorRequest) CheckProviders() bool { return request.checkProviders }

// CheckPlatform reports the fixed platform-check selection.
func (request DoctorRequest) CheckPlatform() bool { return request.checkPlatform }

// StatusRequest contains the immutable run selected for status lookup.
type StatusRequest struct {
	runID string
}

// RunID returns the selected canonical review-run ID.
func (request StatusRequest) RunID() string { return request.runID }

// ReportRequest contains the immutable report-rendering fields.
type ReportRequest struct {
	runID      string
	outputPath string
}

// RunID returns the selected canonical review-run ID.
func (request ReportRequest) RunID() string { return request.runID }

// OutputPath returns the selected safe relative report path.
func (request ReportRequest) OutputPath() string { return request.outputPath }

// FindingsRequest contains the immutable finding-query fields.
type FindingsRequest struct {
	runID           string
	minimumSeverity domain.Severity
}

// RunID returns the selected canonical review-run ID.
func (request FindingsRequest) RunID() string { return request.runID }

// MinimumSeverity returns the inclusive severity threshold for the query.
func (request FindingsRequest) MinimumSeverity() domain.Severity {
	return request.minimumSeverity
}

// ExcerptRequest contains the immutable evidence-excerpt fields.
type ExcerptRequest struct {
	runID               string
	findingID           string
	currentTargetSHA256 string
}

// RunID returns the selected canonical review-run ID.
func (request ExcerptRequest) RunID() string { return request.runID }

// FindingID returns the selected canonical run-scoped finding ID.
func (request ExcerptRequest) FindingID() string { return request.findingID }

// CurrentTargetSHA256 returns the immutable current-target integrity identifier.
func (request ExcerptRequest) CurrentTargetSHA256() string {
	return request.currentTargetSHA256
}

// ProvidersRequest contains the immutable provider-profile listing fields.
type ProvidersRequest struct {
	projectRoot       string
	includeUnverified bool
}

// ProjectRoot returns the canonical project root selected for provider listing.
func (request ProvidersRequest) ProjectRoot() string { return request.projectRoot }

// IncludeUnverified reports whether unverified provider profiles are included.
func (request ProvidersRequest) IncludeUnverified() bool { return request.includeUnverified }

// ConfigRequest contains the executable configuration-selection fields.
type ConfigRequest struct {
	projectRoot string
	mode        ConfigMode
}

// ProjectRoot returns the canonical project root selected for configuration.
func (request ConfigRequest) ProjectRoot() string { return request.projectRoot }

// Mode returns the requested configuration view.
func (request ConfigRequest) Mode() ConfigMode { return request.mode }

// SchemaRequest contains the executable schema catalog fields.
type SchemaRequest struct {
	operation     SchemaOperation
	projectRoot   string
	schemaID      string
	hasSchemaID   bool
	exportPath    string
	hasExportPath bool
}

// Operation returns the explicit schema catalog operation.
func (request SchemaRequest) Operation() SchemaOperation { return request.operation }

// ProjectRoot returns the canonical project root selected for schema export.
func (request SchemaRequest) ProjectRoot() string { return request.projectRoot }

// SchemaID returns the selected schema identifier for show and export operations.
func (request SchemaRequest) SchemaID() (string, bool) {
	return request.schemaID, request.hasSchemaID
}

// ExportPath returns the selected safe relative export path for export operations.
func (request SchemaRequest) ExportPath() (string, bool) {
	return request.exportPath, request.hasExportPath
}

// TargetRequest contains one literal command-request target.
type TargetRequest struct {
	kind  string
	value string
}

// Kind returns the selected project or external-input target kind.
func (request TargetRequest) Kind() string { return request.kind }

// Value returns the target value.
func (request TargetRequest) Value() string { return request.value }

// ReviewRequest contains the immutable independent-review fields.
type ReviewRequest struct {
	target        TargetRequest
	objective     string
	hasObjective  bool
	roles         []string
	rolesExplicit bool
	sessionID     string
	hasSessionID  bool
}

// Target returns the literal target request.
func (request ReviewRequest) Target() TargetRequest { return request.target }

// Objective returns the optional review objective.
func (request ReviewRequest) Objective() (string, bool) {
	return request.objective, request.hasObjective
}

// Roles returns a caller-owned copy of the requested roles.
func (request ReviewRequest) Roles() []string { return cloneStrings(request.roles) }

// RolesExplicit reports whether --roles was supplied by the caller.
func (request ReviewRequest) RolesExplicit() bool { return request.rolesExplicit }

// SessionID returns the optional imported workflow session ID.
func (request ReviewRequest) SessionID() (string, bool) {
	return request.sessionID, request.hasSessionID
}

// PromptRequest contains the immutable prompt-rendering fields.
type PromptRequest struct {
	runID               string
	attemptID           string
	includeGuardedBytes bool
}

// RunID returns the selected canonical review-run ID.
func (request PromptRequest) RunID() string { return request.runID }

// AttemptID returns the selected canonical attempt ID.
func (request PromptRequest) AttemptID() string { return request.attemptID }

// IncludeGuardedBytes reports whether guarded bytes are included.
func (request PromptRequest) IncludeGuardedBytes() bool { return request.includeGuardedBytes }

// FollowupRequest contains the immutable source finding and target fields.
type FollowupRequest struct {
	sourceRunID  string
	findingID    string
	target       TargetRequest
	objective    string
	hasObjective bool
	role         string
	hasRole      bool
}

// SourceRunID returns the source run selected for the child workflow.
func (request FollowupRequest) SourceRunID() string { return request.sourceRunID }

// FindingID returns the source finding selected for followup.
func (request FollowupRequest) FindingID() string { return request.findingID }

// Target returns the literal target request.
func (request FollowupRequest) Target() TargetRequest { return request.target }

// Objective returns the optional followup objective.
func (request FollowupRequest) Objective() (string, bool) {
	return request.objective, request.hasObjective
}

// Role returns the optional followup role.
func (request FollowupRequest) Role() (string, bool) { return request.role, request.hasRole }

// DeltaRequest contains the immutable source run, target, and roles.
type DeltaRequest struct {
	sourceRunID string
	target      TargetRequest
	roles       []string
}

// SourceRunID returns the source run selected for the delta workflow.
func (request DeltaRequest) SourceRunID() string { return request.sourceRunID }

// Target returns the literal target request.
func (request DeltaRequest) Target() TargetRequest { return request.target }

// Roles returns a caller-owned copy of the requested roles.
func (request DeltaRequest) Roles() []string { return cloneStrings(request.roles) }

// ReplayMode identifies the rerun prompt construction mode.
type ReplayMode string

const (
	// ReplayModeExact reuses the captured source invocation exactly.
	ReplayModeExact ReplayMode = "exact"
	// ReplayModeRecompose recompiles from current trusted templates.
	ReplayModeRecompose ReplayMode = "recompose"
)

// RerunRequest contains the immutable source attempt and replay selection.
type RerunRequest struct {
	sourceRunID     string
	sourceAttemptID string
	replayMode      ReplayMode
}

// SourceRunID returns the source run selected for replay.
func (request RerunRequest) SourceRunID() string { return request.sourceRunID }

// SourceAttemptID returns the source attempt selected for replay.
func (request RerunRequest) SourceAttemptID() string { return request.sourceAttemptID }

// ReplayMode returns the selected replay construction mode.
func (request RerunRequest) ReplayMode() ReplayMode { return request.replayMode }

// CleanMode identifies the literal maintenance request mode.
type CleanMode string

const (
	// CleanModePlan produces a dry-run clean plan.
	CleanModePlan CleanMode = "plan"
	// CleanModeApply executes a hash-bound clean plan.
	CleanModeApply CleanMode = "apply"
	// CleanModeExplain renders a dry-run plan with deterministic human rows.
	CleanModeExplain CleanMode = "explain"
)

// CleanRequest contains the immutable clean-plan selection.
type CleanRequest struct {
	mode                CleanMode
	expectedPlanSHA256  string
	hasExpectedPlanHash bool
}

// Mode returns the literal clean request mode.
func (request CleanRequest) Mode() CleanMode { return request.mode }

// ExpectedPlanSHA256 returns the required apply-plan hash when present.
func (request CleanRequest) ExpectedPlanSHA256() (string, bool) {
	return request.expectedPlanSHA256, request.hasExpectedPlanHash
}

// ExportRequest contains the immutable redacted export selection.
type ExportRequest struct {
	runID      string
	outputPath string
	redacted   bool
}

// RunID returns the source run selected for export.
func (request ExportRequest) RunID() string { return request.runID }

// OutputPath returns the safe relative export output path.
func (request ExportRequest) OutputPath() string { return request.outputPath }

// Redacted reports the schema-required redacted export mode.
func (request ExportRequest) Redacted() bool { return request.redacted }

func cloneInitRequest(request InitRequest) InitRequest {
	request.providerIDs = cloneStrings(request.providerIDs)
	request.roleIDs = cloneStrings(request.roleIDs)
	return request
}

func cloneReviewRequest(request ReviewRequest) ReviewRequest {
	request.roles = cloneStrings(request.roles)
	return request
}

func cloneDeltaRequest(request DeltaRequest) DeltaRequest {
	request.roles = cloneStrings(request.roles)
	return request
}

func cloneStrings(values []string) []string {
	if values == nil {
		return nil
	}
	copyValues := make([]string, len(values))
	copy(copyValues, values)
	return copyValues
}

func cloneBytes(values []byte) []byte {
	if values == nil {
		return nil
	}
	copyValues := make([]byte, len(values))
	copy(copyValues, values)
	return copyValues
}
