// Package cli exposes the fixed Mulgae command registry and its dispatcher.
package cli

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/irootkernel/mulgae/internal/app"
)

const commandResultContractURI = "https://mulgae.local/schemas/mulgae-command-result.v1.schema.json"

const commandRequestPointerPrefix = commandResultContractURI + "#/$defs/requests/"
const fixedCommandSpecCount = 17

const (
	doctorResultContractURI             = "https://mulgae.local/schemas/mulgae-doctor-result.v2.schema.json"
	runManifestContractURI              = "https://mulgae.local/schemas/mulgae-run-manifest.v2.schema.json"
	reviewArtifactContractURI           = "https://mulgae.local/schemas/mulgae-review-artifact.v3.schema.json"
	providerFollowupOutputContractURI   = "https://mulgae.local/schemas/mulgae-provider-followup-output.v2.schema.json"
	providerContractEvidenceContractURI = "https://mulgae.local/schemas/mulgae-provider-contract-evidence.v1.schema.json"
	cleanPlanContractURI                = "https://mulgae.local/schemas/mulgae-clean-plan.v1.schema.json"
	exportManifestContractURI           = "https://mulgae.local/schemas/mulgae-export-manifest.v1.schema.json"
)

// CommandSpec is immutable metadata for one command in the fixed Mulgae surface.
type CommandSpec struct {
	command            app.CommandName
	owner              string
	service            string
	requestContractURI string
	outputContractURIs []string
	typedExits         []app.ExitCode
}

// Command returns the command named by this specification.
func (spec CommandSpec) Command() app.CommandName { return spec.command }

// Owner returns the application package that owns the command.
func (spec CommandSpec) Owner() string { return spec.owner }

// Service returns the application service that implements the command.
func (spec CommandSpec) Service() string { return spec.service }

// RequestContractURI returns the command's literal request-variant URI.
func (spec CommandSpec) RequestContractURI() string { return spec.requestContractURI }

// OutputContractURIs returns a caller-owned copy of the command's output contracts.
func (spec CommandSpec) OutputContractURIs() []string {
	return cloneStrings(spec.outputContractURIs)
}

// TypedExits returns a caller-owned copy of the command's assigned failure exits.
func (spec CommandSpec) TypedExits() []app.ExitCode {
	return cloneExitCodes(spec.typedExits)
}

// CommandSpecs returns a fresh copy of the canonical, ordered 17-command registry.
func CommandSpecs() []CommandSpec {
	return canonicalCommandSpecs()
}

// ValidateCommandSpecs rejects a registry that is incomplete or whose command
// metadata differs from the canonical Mulgae contract.
func ValidateCommandSpecs(specs []CommandSpec) error {
	return validateCommandSpecs(specs)
}

// NewDispatcher validates a complete canonical registry and handler set before
// constructing an immutable dispatcher.
func NewDispatcher(specs []CommandSpec, handlers map[app.CommandName]Handler) (*Dispatcher, error) {
	if err := validateCommandSpecs(specs); err != nil {
		return nil, err
	}
	if err := validateHandlers(specs, handlers); err != nil {
		return nil, err
	}

	dispatcher := &Dispatcher{
		specs:    make(map[app.CommandName]CommandSpec, len(specs)),
		handlers: make(map[app.CommandName]Handler, len(handlers)),
	}
	for _, spec := range cloneCommandSpecs(specs) {
		dispatcher.specs[spec.command] = spec
	}
	for command, handler := range handlers {
		dispatcher.handlers[command] = handler
	}
	return dispatcher, nil
}

func canonicalCommandSpecs() []CommandSpec {
	return []CommandSpec{
		newCommandSpec(app.CommandInit, "internal/app/init", "InitializeProject", []string{commandResultContractURI}, []app.ExitCode{app.ExitCodeUsage, app.ExitCodeReadiness, app.ExitCodeArtifact, app.ExitCodeSecurity, app.ExitCodeCancellation, app.ExitCodeInternal}),
		newCommandSpec(app.CommandDoctor, "internal/app/doctor", "DiagnoseEnvironment", []string{doctorResultContractURI, commandResultContractURI}, []app.ExitCode{app.ExitCodeUsage, app.ExitCodeReadiness, app.ExitCodeArtifact, app.ExitCodeSecurity, app.ExitCodeCancellation}),
		newCommandSpec(app.CommandReview, "internal/app/review", "StartReviewRun", []string{runManifestContractURI, reviewArtifactContractURI, commandResultContractURI}, []app.ExitCode{app.ExitCodePolicy, app.ExitCodeUsage, app.ExitCodeReadiness, app.ExitCodeArtifact, app.ExitCodeSecurity, app.ExitCodeCancellation, app.ExitCodeInternal}),
		newCommandSpec(app.CommandFollowup, "internal/app/followup", "StartFollowupRun", []string{providerFollowupOutputContractURI, runManifestContractURI, reviewArtifactContractURI, commandResultContractURI}, []app.ExitCode{app.ExitCodePolicy, app.ExitCodeUsage, app.ExitCodeReadiness, app.ExitCodeArtifact, app.ExitCodeSecurity, app.ExitCodeCancellation, app.ExitCodeInternal}),
		newCommandSpec(app.CommandDelta, "internal/app/delta", "StartDeltaRun", []string{runManifestContractURI, reviewArtifactContractURI, commandResultContractURI}, []app.ExitCode{app.ExitCodePolicy, app.ExitCodeUsage, app.ExitCodeReadiness, app.ExitCodeArtifact, app.ExitCodeSecurity, app.ExitCodeCancellation, app.ExitCodeInternal}),
		newCommandSpec(app.CommandRerun, "internal/app/rerun", "StartRerun", []string{runManifestContractURI, reviewArtifactContractURI, commandResultContractURI}, []app.ExitCode{app.ExitCodePolicy, app.ExitCodeUsage, app.ExitCodeReadiness, app.ExitCodeArtifact, app.ExitCodeSecurity, app.ExitCodeCancellation, app.ExitCodeInternal}),
		newCommandSpec(app.CommandStatus, "internal/app/query", "ReadRunStatus", []string{runManifestContractURI, commandResultContractURI}, []app.ExitCode{app.ExitCodeUsage, app.ExitCodeArtifact, app.ExitCodeSecurity, app.ExitCodeCancellation, app.ExitCodeInternal}),
		newCommandSpec(app.CommandReport, "internal/app/report", "RenderReport", []string{commandResultContractURI}, []app.ExitCode{app.ExitCodeUsage, app.ExitCodeArtifact, app.ExitCodeSecurity, app.ExitCodeCancellation, app.ExitCodeInternal}),
		newCommandSpec(app.CommandFindings, "internal/app/query", "ListFindings", []string{reviewArtifactContractURI, commandResultContractURI}, []app.ExitCode{app.ExitCodeUsage, app.ExitCodeArtifact, app.ExitCodeSecurity, app.ExitCodeCancellation, app.ExitCodeInternal}),
		newCommandSpec(app.CommandExcerpt, "internal/app/query", "RenderExcerpt", []string{commandResultContractURI}, []app.ExitCode{app.ExitCodeUsage, app.ExitCodeReadiness, app.ExitCodeArtifact, app.ExitCodeSecurity, app.ExitCodeCancellation, app.ExitCodeInternal}),
		newCommandSpec(app.CommandProviders, "internal/app/providers", "ListProviderProfiles", []string{providerContractEvidenceContractURI, commandResultContractURI}, []app.ExitCode{app.ExitCodeUsage, app.ExitCodeReadiness, app.ExitCodeArtifact, app.ExitCodeSecurity}),
		newCommandSpec(app.CommandRoles, "internal/app/roles", "ListRoles", []string{commandResultContractURI}, []app.ExitCode{app.ExitCodeUsage}),
		newCommandSpec(app.CommandConfig, "internal/app/config", "ResolveConfiguration", []string{runManifestContractURI, commandResultContractURI}, []app.ExitCode{app.ExitCodeUsage, app.ExitCodeReadiness, app.ExitCodeArtifact, app.ExitCodeSecurity, app.ExitCodeCancellation, app.ExitCodeInternal}),
		newCommandSpec(app.CommandSchema, "internal/app/schema", "InspectSchema", []string{commandResultContractURI}, []app.ExitCode{app.ExitCodeUsage, app.ExitCodeArtifact}),
		newCommandSpec(app.CommandClean, "internal/app/clean", "PlanAndApplyRetention", []string{cleanPlanContractURI, commandResultContractURI}, []app.ExitCode{app.ExitCodeUsage, app.ExitCodeArtifact, app.ExitCodeSecurity}),
		newCommandSpec(app.CommandExport, "internal/app/export", "ExportRedactedRun", []string{exportManifestContractURI, commandResultContractURI}, []app.ExitCode{app.ExitCodeUsage, app.ExitCodeArtifact, app.ExitCodeSecurity}),
		newCommandSpec(app.CommandHelp, "internal/app/help", "RenderHelp", []string{commandResultContractURI}, []app.ExitCode{app.ExitCodeUsage}),
	}
}

func newCommandSpec(command app.CommandName, owner string, service string, outputs []string, exits []app.ExitCode) CommandSpec {
	return CommandSpec{
		command:            command,
		owner:              owner,
		service:            service,
		requestContractURI: commandRequestPointerPrefix + string(command),
		outputContractURIs: cloneStrings(outputs),
		typedExits:         cloneExitCodes(exits),
	}
}

func validateCommandSpecs(specs []CommandSpec) error {
	return validateCommandSpecsAgainstCanonical(specs, canonicalCommandSpecs())
}

func validatedDispatcherCommandSpecs(dispatcherSpecs map[app.CommandName]CommandSpec, handlers map[app.CommandName]Handler) ([]CommandSpec, error) {
	canonical := canonicalCommandSpecs()
	if len(canonical) != fixedCommandSpecCount {
		return nil, fmt.Errorf("cli registry: canonical registry has %d command specs, want fixed %d", len(canonical), fixedCommandSpecCount)
	}
	if len(dispatcherSpecs) != fixedCommandSpecCount {
		return nil, fmt.Errorf("cli registry: dispatcher has %d command specs, want fixed %d", len(dispatcherSpecs), fixedCommandSpecCount)
	}

	specs := make([]CommandSpec, 0, fixedCommandSpecCount)
	for _, canonicalSpec := range canonical {
		spec, present := dispatcherSpecs[canonicalSpec.command]
		if !present {
			return nil, fmt.Errorf("cli registry: dispatcher is missing canonical command spec %q", canonicalSpec.command)
		}
		specs = append(specs, spec)
	}
	if err := validateCommandSpecsAgainstCanonical(specs, canonical); err != nil {
		return nil, err
	}
	if err := validateHandlers(specs, handlers); err != nil {
		return nil, err
	}
	return specs, nil
}

func validateCommandSpecsAgainstCanonical(specs []CommandSpec, canonical []CommandSpec) error {
	if len(canonical) != fixedCommandSpecCount {
		return fmt.Errorf("cli registry: canonical registry has %d command specs, want fixed %d", len(canonical), fixedCommandSpecCount)
	}
	if len(specs) != fixedCommandSpecCount {
		return fmt.Errorf("cli registry: got %d command specs, want fixed %d", len(specs), fixedCommandSpecCount)
	}

	seenCommands := make(map[app.CommandName]struct{}, len(specs))
	for index, spec := range specs {
		if !spec.command.Valid() {
			return fmt.Errorf("cli registry: command spec %d has unknown command %q", index, spec.command)
		}
		if _, duplicate := seenCommands[spec.command]; duplicate {
			return fmt.Errorf("cli registry: duplicate command %q", spec.command)
		}
		seenCommands[spec.command] = struct{}{}
		if spec.command != canonical[index].command {
			return fmt.Errorf("cli registry: command spec %d is %q, want %q", index, spec.command, canonical[index].command)
		}
		if strings.TrimSpace(spec.owner) == "" || strings.TrimSpace(spec.service) == "" {
			return fmt.Errorf("cli registry: command %q requires a non-empty owner and service", spec.command)
		}
		if !uniqueStrings(spec.outputContractURIs) {
			return fmt.Errorf("cli registry: command %q has duplicate or empty output contract URIs", spec.command)
		}
		if !uniqueExitCodes(spec.typedExits) {
			return fmt.Errorf("cli registry: command %q has duplicate or invalid typed exits", spec.command)
		}
		if !commandSpecEqual(spec, canonical[index]) {
			return fmt.Errorf("cli registry: command %q metadata does not match the canonical contract", spec.command)
		}
	}
	return nil
}

func validateHandlers(specs []CommandSpec, handlers map[app.CommandName]Handler) error {
	byCommand := make(map[app.CommandName]CommandSpec, len(specs))
	for _, spec := range specs {
		byCommand[spec.command] = spec
	}
	for command, handler := range handlers {
		_, known := byCommand[command]
		if !known {
			return fmt.Errorf("cli registry: handler registered for unknown command %q", command)
		}
		if handlerIsNil(handler) {
			return fmt.Errorf("cli registry: command %q has a nil handler", command)
		}
	}
	for _, spec := range specs {
		handler, present := handlers[spec.command]
		if !present || handlerIsNil(handler) {
			return fmt.Errorf("cli registry: command %q requires a handler", spec.command)
		}
	}
	return nil
}

func commandSpecEqual(left CommandSpec, right CommandSpec) bool {
	if left.command != right.command ||
		left.owner != right.owner ||
		left.service != right.service ||
		left.requestContractURI != right.requestContractURI ||
		len(left.outputContractURIs) != len(right.outputContractURIs) ||
		len(left.typedExits) != len(right.typedExits) {
		return false
	}
	for index := range left.outputContractURIs {
		if left.outputContractURIs[index] != right.outputContractURIs[index] {
			return false
		}
	}
	for index := range left.typedExits {
		if left.typedExits[index] != right.typedExits[index] {
			return false
		}
	}
	return true
}

func uniqueStrings(values []string) bool {
	if len(values) == 0 {
		return false
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value == "" {
			return false
		}
		if _, duplicate := seen[value]; duplicate {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func uniqueExitCodes(values []app.ExitCode) bool {
	if len(values) == 0 {
		return false
	}
	seen := make(map[app.ExitCode]struct{}, len(values))
	for _, value := range values {
		if !value.Valid() || value == app.ExitCodeSuccess {
			return false
		}
		if _, duplicate := seen[value]; duplicate {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func cloneCommandSpecs(specs []CommandSpec) []CommandSpec {
	cloned := make([]CommandSpec, len(specs))
	for index, spec := range specs {
		cloned[index] = CommandSpec{
			command:            spec.command,
			owner:              spec.owner,
			service:            spec.service,
			requestContractURI: spec.requestContractURI,
			outputContractURIs: cloneStrings(spec.outputContractURIs),
			typedExits:         cloneExitCodes(spec.typedExits),
		}
	}
	return cloned
}

func cloneStrings(values []string) []string {
	if values == nil {
		return nil
	}
	return append([]string(nil), values...)
}

func cloneExitCodes(values []app.ExitCode) []app.ExitCode {
	if values == nil {
		return nil
	}
	return append([]app.ExitCode(nil), values...)
}

func handlerIsNil(handler Handler) bool {
	if handler == nil {
		return true
	}
	value := reflect.ValueOf(handler)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}
