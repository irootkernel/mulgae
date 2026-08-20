package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"time"

	"github.com/irootkernel/mulgae/internal/app"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

const commandResultSchemaVersion = "mulgae-command-result.v5"

// SchemaValidator validates raw JSON against a catalog schema. It is satisfied
// by adapters/jsonschema.Validator without coupling this CLI adapter to it.
type SchemaValidator interface {
	Validate(context.Context, ports.AssetID, []byte) error
}

// EnvelopeRenderer renders application command results as the common command
// result contract. It is immutable after construction.
type EnvelopeRenderer struct {
	clock     ports.Clock
	validator SchemaValidator
	schemaID  ports.AssetID
}

// NewEnvelopeRenderer constructs a renderer with the required wall clock and
// final-envelope schema validator.
func NewEnvelopeRenderer(clock ports.Clock, validator SchemaValidator) (*EnvelopeRenderer, error) {
	if nilClock(clock) {
		return nil, fmt.Errorf("cli envelope: nil clock")
	}
	if nilSchemaValidator(validator) {
		return nil, fmt.Errorf("cli envelope: nil schema validator")
	}

	schemaID, err := ports.ParseAssetID(commandResultContractURI)
	if err != nil {
		return nil, fmt.Errorf("cli envelope: command result schema ID: %w", err)
	}
	return &EnvelopeRenderer{
		clock:     clock,
		validator: validator,
		schemaID:  schemaID,
	}, nil
}

// Render returns a schema-validated canonical command-result envelope followed
// by exactly one newline. requestRaw and selected result data must each contain
// exactly one non-null JSON object with no duplicate keys. Failed command
// results use failureResultRaw because the command contract requires a result
// object even when command execution failed.
func (renderer *EnvelopeRenderer) Render(ctx context.Context, commandResult app.CommandResult, requestRaw, failureResultRaw []byte) ([]byte, error) {
	if renderer == nil {
		return nil, fmt.Errorf("cli envelope: nil renderer")
	}
	if ctx == nil {
		return nil, fmt.Errorf("cli envelope: nil context")
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("cli envelope: context: %w", err)
	}
	if nilClock(renderer.clock) {
		return nil, fmt.Errorf("cli envelope: nil clock")
	}
	if nilSchemaValidator(renderer.validator) {
		return nil, fmt.Errorf("cli envelope: nil schema validator")
	}
	if !renderer.schemaID.Valid() {
		return nil, fmt.Errorf("cli envelope: invalid command result schema ID")
	}

	if !commandResult.Command().Valid() {
		return nil, fmt.Errorf("cli envelope: invalid command result command")
	}
	if !commandResult.ExitCode().Valid() {
		return nil, fmt.Errorf("cli envelope: invalid command result exit code")
	}
	if !commandResult.CommittedOutcome() && commandResult.OK() != (commandResult.ExitCode() == app.ExitCodeSuccess) {
		return nil, fmt.Errorf("cli envelope: inconsistent command result status")
	}

	request, err := decodeJSONObject(requestRaw, "request")
	if err != nil {
		return nil, err
	}
	var requestValue any = request
	if _, rejected := request["request_state"]; rejected {
		requestValue = json.RawMessage(cloneEnvelopeBytes(requestRaw))
	}

	resultRaw := failureResultRaw
	if commandResult.OK() || commandResult.CommittedOutcome() {
		resultRaw = commandResult.Data()
	}
	result, err := decodeJSONObject(resultRaw, "result")
	if err != nil {
		return nil, err
	}

	completedAt, err := renderer.completedAt()
	if err != nil {
		return nil, err
	}
	exitKind, err := exitKind(commandResult.ExitCode())
	if err != nil {
		return nil, err
	}

	diagnostics := commandResult.Diagnostics()
	reasons := make([]commandReason, 0, len(diagnostics))
	if commandResult.CommittedOutcome() {
		if len(diagnostics) != 0 {
			return nil, fmt.Errorf("cli envelope: committed outcome has diagnostics")
		}
		for index, committed := range commandResult.CommittedReasons() {
			reason, err := reasonForCommittedOutcome(commandResult.ExitCode(), committed)
			if err != nil {
				return nil, fmt.Errorf("cli envelope: committed reason %d: %w", index, err)
			}
			reasons = append(reasons, reason)
		}
		if len(reasons) == 0 {
			return nil, fmt.Errorf("cli envelope: committed outcome has no reasons")
		}
	} else {
		for index, diagnostic := range diagnostics {
			reason, err := reasonForDiagnostic(diagnostic)
			if err != nil {
				return nil, fmt.Errorf("cli envelope: diagnostic %d: %w", index, err)
			}
			reasons = append(reasons, reason)
		}
		if commandResult.OK() && len(reasons) != 0 {
			return nil, fmt.Errorf("cli envelope: successful command result has diagnostics")
		}
		if !commandResult.OK() && len(reasons) == 0 {
			return nil, fmt.Errorf("cli envelope: failed command result has no diagnostics")
		}
	}

	candidate, err := json.Marshal(commandEnvelope{
		SchemaVersion: commandResultSchemaVersion,
		Command:       commandResult.Command(),
		Request:       requestValue,
		CompletedAt:   completedAt,
		Exit: commandExit{
			Code: int(commandResult.ExitCode()),
			Kind: exitKind,
		},
		Reasons: reasons,
		Result:  result,
	})
	if err != nil {
		return nil, fmt.Errorf("cli envelope: marshal: %w", err)
	}

	validatorInput := cloneEnvelopeBytes(candidate)
	if err := renderer.validator.Validate(ctx, renderer.schemaID, validatorInput); err != nil {
		return nil, fmt.Errorf("cli envelope: schema validation: %w", err)
	}

	output := make([]byte, len(candidate)+1)
	copy(output, candidate)
	output[len(candidate)] = '\n'
	return output, nil
}

type commandEnvelope struct {
	SchemaVersion string          `json:"schema_version"`
	Command       app.CommandName `json:"command"`
	Request       any             `json:"request"`
	CompletedAt   string          `json:"completed_at"`
	Exit          commandExit     `json:"exit"`
	Reasons       []commandReason `json:"reasons"`
	Result        map[string]any  `json:"result"`
}

type commandExit struct {
	Code int    `json:"code"`
	Kind string `json:"kind"`
}

type commandReason struct {
	Category    string  `json:"category"`
	Code        string  `json:"code"`
	Message     string  `json:"message"`
	Retryable   bool    `json:"retryable"`
	ArtifactURI *string `json:"artifact_uri"`
}

func (renderer *EnvelopeRenderer) completedAt() (completedAt string, err error) {
	defer func() {
		if recover() != nil {
			completedAt = ""
			err = fmt.Errorf("cli envelope: clock failed")
		}
	}()

	now := renderer.clock.Now()
	if now.IsZero() {
		return "", fmt.Errorf("cli envelope: clock returned zero time")
	}
	return now.UTC().Truncate(time.Millisecond).Format("2006-01-02T15:04:05.000Z07:00"), nil
}

func decodeJSONObject(raw []byte, name string) (map[string]any, error) {
	object, err := app.DecodeStrictJSONObject(cloneEnvelopeBytes(raw))
	if err != nil {
		return nil, fmt.Errorf("cli envelope: %s must contain exactly one non-null JSON object without duplicate keys: %w", name, err)
	}
	return object, nil
}

func exitKind(code app.ExitCode) (string, error) {
	switch code {
	case app.ExitCodeSuccess:
		return "success", nil
	case app.ExitCodePolicy:
		return "policy", nil
	case app.ExitCodeUsage:
		return "usage", nil
	case app.ExitCodeReadiness:
		return "readiness", nil
	case app.ExitCodeArtifact:
		return "artifact", nil
	case app.ExitCodeSecurity:
		return "security", nil
	case app.ExitCodeCancellation:
		return "cancellation", nil
	case app.ExitCodeInternal:
		return "internal", nil
	default:
		return "", fmt.Errorf("cli envelope: unassigned exit code %d", code)
	}
}

func reasonForDiagnostic(diagnostic app.Diagnostic) (commandReason, error) {
	category, err := diagnosticCategory(diagnostic.FailureClass())
	if err != nil {
		return commandReason{}, err
	}
	if diagnostic.FailureClass() == domain.FailureConfiguration &&
		((diagnostic.Stage() == "cli.init" && diagnostic.MachineCode() == "init_selection_invalid") || diagnostic.MachineCode() == "invalid_command_usage") {
		category = "usage"
	}

	artifactURI := diagnostic.ArtifactPath()
	var artifact *string
	if artifactURI != "" {
		artifact = &artifactURI
	}
	return commandReason{
		Category:    category,
		Code:        diagnostic.MachineCode(),
		Message:     diagnostic.Message(),
		Retryable:   diagnostic.Retryable(),
		ArtifactURI: artifact,
	}, nil
}

func reasonForCommittedOutcome(exit app.ExitCode, committed app.CommittedReason) (commandReason, error) {
	var category, message string
	switch exit {
	case app.ExitCodeSuccess:
		category, message = "evidence", "Committed child workflow passed"
	case app.ExitCodePolicy:
		category, message = "policy", "Committed child workflow policy outcome"
	case app.ExitCodeReadiness:
		category, message = "readiness", "Committed child workflow readiness outcome"
	default:
		return commandReason{}, fmt.Errorf("committed outcome uses exit %d", exit)
	}
	if committed.Message() != "" {
		message = committed.Message()
	}
	return commandReason{
		Category: category,
		Code:     committed.Code(),
		Message:  message,
	}, nil
}

func diagnosticCategory(class domain.FailureClass) (string, error) {
	switch class {
	case domain.FailureProviderUnavailable, domain.FailureTimeout, domain.FailureAuthentication,
		domain.FailureQuota, domain.FailureRateLimit:
		return "readiness", nil
	case domain.FailureInvalidOutput:
		return "evidence", nil
	case domain.FailureSecurityPolicy:
		return "security", nil
	case domain.FailureConfiguration:
		return "configuration", nil
	case domain.FailureArtifact:
		return "artifact", nil
	case domain.FailureInternal:
		return "internal", nil
	case domain.FailureCancelled:
		return "cancellation", nil
	default:
		return "", fmt.Errorf("unmapped failure class %q", class)
	}
}

func cloneEnvelopeBytes(value []byte) []byte {
	if value == nil {
		return nil
	}
	return append([]byte(nil), value...)
}

func nilClock(clock ports.Clock) bool {
	return nilInterface(clock)
}

func nilSchemaValidator(validator SchemaValidator) bool {
	return nilInterface(validator)
}

func nilInterface(value any) bool {
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
