package kar

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"time"

	"github.com/irootkernel/kkachi-agent-review/internal/adapters/cli"
	"github.com/irootkernel/kkachi-agent-review/internal/app"
	"github.com/irootkernel/kkachi-agent-review/internal/domain"
	"github.com/irootkernel/kkachi-agent-review/internal/ports"
)

// RequestIDGenerator creates the request identifier bound into a parsed command
// request and its command-result envelope.
type RequestIDGenerator interface {
	NewRequestID(time.Time) (string, error)
}

// Dependencies are the explicit inward dependencies required by Application.
// All are required so every foundation command retains the same trusted
// boundaries regardless of which command happens to be invoked.
type Dependencies struct {
	Clock                ports.Clock
	RequestIDGenerator   RequestIDGenerator
	Catalog              ports.ContractCatalog
	JSONSchemaValidator  cli.SchemaValidator
	SecureWriter         ports.SecureFileWriter
	TrustedProjectReader ports.TrustedProjectReader
	EnvironmentInspector ports.EnvironmentInspector
}

// Application is the executable foundation command surface. It owns no mutable
// process state and only reaches the filesystem, Git, and environment through
// the injected ports.
type Application struct {
	clock         ports.Clock
	requestIDs    RequestIDGenerator
	catalog       ports.ContractCatalog
	validator     cli.SchemaValidator
	writer        ports.SecureFileWriter
	projectReader ports.TrustedProjectReader
	inspector     ports.EnvironmentInspector
	renderer      *cli.EnvelopeRenderer
}

// Result is the complete process projection of one invocation. Stdout and
// Stderr return caller-owned copies so a caller cannot mutate application-owned
// response bytes.
type Result struct {
	stdout []byte
	stderr []byte
	exit   app.ExitCode
}

// Stdout returns a defensive copy of command standard output.
func (result Result) Stdout() []byte { return cloneApplicationBytes(result.stdout) }

// Stderr returns a defensive copy of command standard error.
func (result Result) Stderr() []byte { return cloneApplicationBytes(result.stderr) }

// ExitCode returns the assigned KAR process exit code.
func (result Result) ExitCode() app.ExitCode { return result.exit }

// NewApplication constructs the foundation CLI application. Missing or typed
// nil dependencies are rejected before any command can execute.
func NewApplication(dependencies Dependencies) (*Application, error) {
	if nilApplicationDependency(dependencies.Clock) {
		return nil, fmt.Errorf("kar application: nil clock")
	}
	if nilApplicationDependency(dependencies.RequestIDGenerator) {
		return nil, fmt.Errorf("kar application: nil request ID generator")
	}
	if nilApplicationDependency(dependencies.Catalog) {
		return nil, fmt.Errorf("kar application: nil contract catalog")
	}
	if nilApplicationDependency(dependencies.JSONSchemaValidator) {
		return nil, fmt.Errorf("kar application: nil JSON schema validator")
	}
	if nilApplicationDependency(dependencies.SecureWriter) {
		return nil, fmt.Errorf("kar application: nil secure writer")
	}
	if nilApplicationDependency(dependencies.TrustedProjectReader) {
		return nil, fmt.Errorf("kar application: nil trusted project reader")
	}
	if nilApplicationDependency(dependencies.EnvironmentInspector) {
		return nil, fmt.Errorf("kar application: nil environment inspector")
	}

	renderer, err := cli.NewEnvelopeRenderer(dependencies.Clock, dependencies.JSONSchemaValidator)
	if err != nil {
		return nil, fmt.Errorf("kar application: command envelope renderer: %w", err)
	}
	return &Application{
		clock:         dependencies.Clock,
		requestIDs:    dependencies.RequestIDGenerator,
		catalog:       dependencies.Catalog,
		validator:     dependencies.JSONSchemaValidator,
		writer:        dependencies.SecureWriter,
		projectReader: dependencies.TrustedProjectReader,
		inspector:     dependencies.EnvironmentInspector,
		renderer:      renderer,
	}, nil
}

// Run parses and executes argv against canonicalDefaultRoot. It never returns
// raw adapter errors: machine output contains a validated envelope when the
// parser supplied a contract-valid request, while human failures use stderr.
func (application *Application) Run(ctx context.Context, argv []string, canonicalDefaultRoot string) Result {
	if application == nil || application.renderer == nil {
		return errorResult(app.ExitCodeInternal, "kar: application is unavailable")
	}
	contextUnavailable := ctx == nil

	requestID, err := application.newRequestID()
	if err != nil {
		return errorResult(app.ExitCodeInternal, "kar: invocation could not be created")
	}
	invocation, err := Parse(cloneApplicationStrings(argv), canonicalDefaultRoot, requestID)
	if err != nil {
		return errorResult(app.ExitCodeUsage, "kar: invalid command usage")
	}
	if invocation.FutureMilestone() {
		return errorResult(app.ExitCodeUsage, "kar: command is unavailable in this foundation milestone")
	}
	if invocation.OutputFormat() == OutputFormatJSON {
		if _, available := invocation.RequestJSON(); !available {
			// schema list deliberately has no schema_id request variant in the
			// frozen common envelope, so it cannot truthfully emit JSON.
			return errorResult(app.ExitCodeUsage, "kar: invalid command usage")
		}
	}
	if contextUnavailable {
		return application.renderFailure(context.Background(), invocation, execution{
			failure: executionFailureFor(invocation.Command(), context.Canceled, domain.FailureCancelled),
		})
	}
	if err := ctx.Err(); err != nil {
		return application.renderFailure(envelopeContext(ctx), invocation, execution{
			failure: executionFailureFor(invocation.Command(), err, domain.FailureCancelled),
		})
	}

	execution := application.execute(ctx, invocation)
	if execution.failure != nil {
		return application.renderFailure(ctx, invocation, execution)
	}
	return application.renderSuccess(ctx, invocation, execution)
}

func (application *Application) newRequestID() (requestID string, err error) {
	defer func() {
		if recover() != nil {
			requestID = ""
			err = errors.New("request ID generator failed")
		}
	}()
	now := application.clock.Now()
	if now.IsZero() {
		return "", errors.New("clock returned zero time")
	}
	requestID, err = application.requestIDs.NewRequestID(now)
	if err != nil {
		return "", err
	}
	if !validRequestID(requestID) {
		return "", errors.New("request ID generator returned an invalid ID")
	}
	return requestID, nil
}

type execution struct {
	human       []byte
	data        []byte
	failureData []byte
	failure     *executionFailure
}

type executionFailure struct {
	class domain.FailureClass
	code  string
	stage string
	exit  app.ExitCode
}

func (application *Application) renderSuccess(ctx context.Context, invocation Invocation, run execution) Result {
	if invocation.OutputFormat() == OutputFormatHuman {
		return newResult(terminalOutput(run.human), nil, app.ExitCodeSuccess)
	}

	request, available := invocation.RequestJSON()
	if !available {
		return errorResult(app.ExitCodeUsage, "kar: invalid command usage")
	}
	commandResult, err := app.NewCommandSuccess(invocation.Command(), run.data)
	if err != nil {
		return application.renderFailure(context.WithoutCancel(ctx), invocation, execution{
			failure: executionFailureFor(invocation.Command(), err, domain.FailureInternal),
		})
	}
	output, err := application.renderer.Render(context.WithoutCancel(ctx), commandResult, request, nil)
	if err != nil {
		return application.renderFailure(context.WithoutCancel(ctx), invocation, execution{
			failure: executionFailureFor(invocation.Command(), err, domain.FailureInternal),
		})
	}
	return newResult(output, nil, app.ExitCodeSuccess)
}

func (application *Application) renderFailure(ctx context.Context, invocation Invocation, run execution) Result {
	failure := *run.failure
	exit := projectedFailureExit(invocation.Command(), failure.exit)
	if invocation.OutputFormat() == OutputFormatHuman {
		if len(run.human) != 0 {
			return newResult(terminalOutput(run.human), nil, exit)
		}
		return errorResult(exit, humanFailureMessage(failure.class))
	}
	request, available := invocation.RequestJSON()
	if !available {
		return errorResult(app.ExitCodeUsage, "kar: invalid command usage")
	}
	resultData := run.failureData
	var err error
	if len(resultData) == 0 {
		resultData, err = failureResultJSON(invocation)
		if err != nil {
			return errorResult(app.ExitCodeInternal, "kar: command result could not be rendered")
		}
	}
	diagnostic, err := app.NewDiagnostic(
		failure.stage,
		failure.class,
		failure.code,
		stableFailureMessage(failure.class),
		"", "", domain.AttemptID{}, false, false, "", "",
	)
	if err != nil {
		return errorResult(app.ExitCodeInternal, "kar: command result could not be rendered")
	}
	commandResult, err := app.NewCommandFailure(invocation.Command(), exit, diagnostic)
	if err != nil {
		return errorResult(app.ExitCodeInternal, "kar: command result could not be rendered")
	}
	output, err := application.renderer.Render(envelopeContext(ctx), commandResult, request, resultData)
	if err != nil {
		return errorResult(app.ExitCodeInternal, "kar: command result could not be rendered")
	}
	return newResult(output, nil, exit)
}

func failureResultJSON(invocation Invocation) ([]byte, error) {
	switch invocation.Command() {
	case app.CommandHelp:
		request, available := invocation.Help()
		if !available {
			return nil, errors.New("missing help request")
		}
		return json.Marshal(struct {
			Kind     string `json:"kind"`
			Topic    string `json:"topic"`
			Rendered bool   `json:"rendered"`
		}{"help_rendered", request.Topic(), false})
	case app.CommandInit:
		request, available := invocation.Init()
		if !available {
			return nil, errors.New("missing init request")
		}
		return json.Marshal(struct {
			Kind                string   `json:"kind"`
			ProjectConfigURI    *string  `json:"project_config_uri"`
			IntendedProviderIDs []string `json:"intended_provider_ids"`
		}{"initialized", nil, request.IntendedProviderIDs()})
	case app.CommandDoctor:
		return json.Marshal(struct {
			Kind            string  `json:"kind"`
			DoctorResultURI *string `json:"doctor_result_uri"`
			Readiness       string  `json:"readiness"`
		}{"diagnosed", nil, "unverified"})
	case app.CommandConfig:
		return json.Marshal(struct {
			Kind              string  `json:"kind"`
			ResolvedPolicyURI *string `json:"resolved_policy_uri"`
			PolicySHA256      *string `json:"policy_sha256"`
		}{"configuration_resolved", nil, nil})
	case app.CommandSchema:
		request, available := invocation.Schema()
		if !available {
			return nil, errors.New("missing schema request")
		}
		schemaID, available := request.SchemaID()
		if !available {
			return nil, errors.New("missing schema ID")
		}
		return json.Marshal(struct {
			Kind      string  `json:"kind"`
			SchemaID  string  `json:"schema_id"`
			ExportURI *string `json:"export_uri"`
		}{"schema_inspected", schemaID, nil})
	default:
		return nil, errors.New("missing command failure projection")
	}
}

func executionFailureFor(command app.CommandName, err error, fallback domain.FailureClass) *executionFailure {
	class := fallback
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		class = domain.FailureCancelled
	} else {
		var typed *domain.Failure
		if errors.As(err, &typed) && typed != nil && typed.Class().Valid() {
			class = typed.Class()
		}
	}

	failure := &executionFailure{
		class: class,
		stage: "cli." + string(command),
		exit:  requestedExit(class),
	}
	switch class {
	case domain.FailureConfiguration:
		failure.code = "configuration_rejected"
	case domain.FailureArtifact:
		failure.code = "artifact_unavailable"
	case domain.FailureSecurityPolicy:
		failure.code = "security_rejected"
	case domain.FailureCancelled:
		failure.code = "request_cancelled"
	case domain.FailureProviderUnavailable, domain.FailureTimeout, domain.FailureAuthentication, domain.FailureQuota, domain.FailureRateLimit:
		failure.code = "readiness_unverified"
	default:
		failure.class = domain.FailureInternal
		failure.code = "internal_failure"
		failure.exit = app.ExitCodeInternal
	}
	return failure
}

func requestedExit(class domain.FailureClass) app.ExitCode {
	switch class {
	case domain.FailureConfiguration:
		return app.ExitCodeUsage
	case domain.FailureArtifact:
		return app.ExitCodeArtifact
	case domain.FailureSecurityPolicy:
		return app.ExitCodeSecurity
	case domain.FailureCancelled:
		return app.ExitCodeCancellation
	case domain.FailureProviderUnavailable, domain.FailureTimeout, domain.FailureAuthentication, domain.FailureQuota, domain.FailureRateLimit:
		return app.ExitCodeReadiness
	default:
		return app.ExitCodeInternal
	}
}

func permittedFailureExit(command app.CommandName, requested app.ExitCode) (app.ExitCode, bool) {
	allowed := map[app.CommandName]map[app.ExitCode]bool{
		app.CommandInit:   {app.ExitCodeUsage: true, app.ExitCodeArtifact: true},
		app.CommandDoctor: {app.ExitCodeUsage: true, app.ExitCodeReadiness: true, app.ExitCodeArtifact: true, app.ExitCodeSecurity: true},
		app.CommandConfig: {app.ExitCodeUsage: true, app.ExitCodeSecurity: true},
		app.CommandSchema: {app.ExitCodeUsage: true, app.ExitCodeArtifact: true},
		app.CommandHelp:   {app.ExitCodeUsage: true},
	}
	return requested, allowed[command][requested]
}

// projectedFailureExit keeps every foundation-mode result inside the command's
// frozen exhaustive exit contract. The projection is output-format independent.
func projectedFailureExit(command app.CommandName, requested app.ExitCode) app.ExitCode {
	if exit, permitted := permittedFailureExit(command, requested); permitted {
		return exit
	}
	switch command {
	case app.CommandConfig:
		return app.ExitCodeSecurity
	case app.CommandInit, app.CommandDoctor, app.CommandSchema:
		return app.ExitCodeArtifact
	case app.CommandHelp:
		return app.ExitCodeUsage
	default:
		return app.ExitCodeInternal
	}
}

func stableFailureMessage(class domain.FailureClass) string {
	switch class {
	case domain.FailureConfiguration:
		return "The command configuration is invalid."
	case domain.FailureArtifact:
		return "A required artifact could not be read or written."
	case domain.FailureSecurityPolicy:
		return "The secure output policy rejected the command output."
	case domain.FailureCancelled:
		return "The command was cancelled."
	case domain.FailureProviderUnavailable, domain.FailureTimeout, domain.FailureAuthentication, domain.FailureQuota, domain.FailureRateLimit:
		return "Required readiness evidence is unverified."
	default:
		return "The command could not be completed."
	}
}

func humanFailureMessage(class domain.FailureClass) string {
	switch class {
	case domain.FailureConfiguration:
		return "kar: configuration could not be resolved"
	case domain.FailureArtifact:
		return "kar: a required artifact could not be read or written"
	case domain.FailureSecurityPolicy:
		return "kar: secure output policy rejected the command output"
	case domain.FailureCancelled:
		return "kar: request was cancelled"
	default:
		return "kar: command could not be completed"
	}
}

func newResult(stdout, stderr []byte, exit app.ExitCode) Result {
	return Result{
		stdout: cloneApplicationBytes(stdout),
		stderr: cloneApplicationBytes(stderr),
		exit:   exit,
	}
}

func errorResult(exit app.ExitCode, message string) Result {
	return newResult(nil, terminalOutput([]byte(message)), exit)
}

func terminalOutput(value []byte) []byte {
	trimmed := bytes.TrimRight(cloneApplicationBytes(value), "\n")
	return append(trimmed, '\n')
}
func envelopeContext(ctx context.Context) context.Context {
	if ctx != nil && ctx.Err() != nil {
		return context.WithoutCancel(ctx)
	}
	return ctx
}

func cloneApplicationBytes(value []byte) []byte {
	if value == nil {
		return nil
	}
	return append([]byte(nil), value...)
}

func cloneApplicationStrings(value []string) []string {
	if value == nil {
		return nil
	}
	return append([]string(nil), value...)
}

func nilApplicationDependency(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
