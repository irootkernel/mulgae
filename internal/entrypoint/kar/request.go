// Package kar parses the fixed KAR command line into immutable invocations.
package kar

import (
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
	intendedProviderIDs []string
	overwrite           bool
}

// ProjectRoot returns the canonical project root selected for initialization.
func (request InitRequest) ProjectRoot() string { return request.projectRoot }

// ProjectName returns the validated project name.
func (request InitRequest) ProjectName() string { return request.projectName }

// ContextPath returns the optional safe relative context path.
func (request InitRequest) ContextPath() (string, bool) {
	return request.contextPath, request.hasContextPath
}

// IntendedProviderIDs returns a caller-owned copy of intended provider IDs.
func (request InitRequest) IntendedProviderIDs() []string {
	return cloneStrings(request.intendedProviderIDs)
}

// Overwrite reports the fixed non-overwrite initialization policy.
func (request InitRequest) Overwrite() bool { return request.overwrite }

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
	projectRoot          string
	reference            string
	projectConfigPath    string
	projectConfigEnabled bool
	mode                 ConfigMode
}

// ProjectRoot returns the canonical project root selected for configuration.
func (request ConfigRequest) ProjectRoot() string { return request.projectRoot }

// Reference returns the exact immutable Git object ID selected as the trusted
// project-configuration base.
func (request ConfigRequest) Reference() string { return request.reference }

// ProjectConfigPath returns the explicitly selected safe relative
// project-configuration path. It is false when no project layer was selected.
func (request ConfigRequest) ProjectConfigPath() (string, bool) {
	return request.projectConfigPath, request.projectConfigEnabled
}

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

func cloneInitRequest(request InitRequest) InitRequest {
	request.intendedProviderIDs = cloneStrings(request.intendedProviderIDs)
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
