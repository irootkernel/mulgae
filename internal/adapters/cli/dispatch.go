package cli

import (
	"context"
	"fmt"

	"github.com/irootkernel/kkachi-agent-review/internal/app"
	"github.com/irootkernel/kkachi-agent-review/internal/domain"
)

// Handler executes one foundation command.
type Handler interface {
	Execute(context.Context, []string) (app.CommandResult, error)
}

// Dispatcher routes only executable foundation commands from a validated registry.
type Dispatcher struct {
	specs    map[app.CommandName]CommandSpec
	handlers map[app.CommandName]Handler
}

// Dispatch executes a foundation command. Callers must parse raw command tokens
// with app.ParseCommandName before dispatching them. Registry and handler
// invariants are returned as Go errors; a recognized future command returns its
// typed unavailable result.
func (dispatcher *Dispatcher) Dispatch(ctx context.Context, command app.CommandName, args []string) (app.CommandResult, error) {
	if dispatcher == nil {
		return app.CommandResult{}, dispatchInvariantError("nil dispatcher")
	}
	if !command.Valid() {
		return app.CommandResult{}, fmt.Errorf("cli dispatch: invalid command %q", command)
	}

	specs, err := validatedDispatcherCommandSpecs(dispatcher.specs, dispatcher.handlers)
	if err != nil {
		return app.CommandResult{}, dispatchInvariantError("dispatcher registry: %v", err)
	}
	spec, present := commandSpec(specs, command)
	if !present {
		return app.CommandResult{}, dispatchInvariantError("canonical command spec missing for %q", command)
	}
	if spec.availability == AvailabilityFutureMilestone {
		return unavailableCommandResult(command)
	}

	handler, present := dispatcher.handlers[command]
	if !present || handlerIsNil(handler) {
		return app.CommandResult{}, dispatchInvariantError("foundation command %q has no handler", command)
	}
	result, err := handler.Execute(ctx, cloneStrings(args))
	if err != nil {
		return app.CommandResult{}, fmt.Errorf("cli dispatch: execute %q: %w", command, err)
	}
	if result.Command() != command {
		return app.CommandResult{}, dispatchInvariantError("handler result command %q does not match dispatched command %q", result.Command(), command)
	}
	if !result.OK() && !spec.hasTypedExit(result.ExitCode()) {
		return app.CommandResult{}, dispatchInvariantError("handler result exit %d is not declared for command %q", result.ExitCode(), command)
	}
	return result, nil
}

func dispatchInvariantError(format string, arguments ...any) error {
	return fmt.Errorf("cli dispatch: %w: %s", domain.ErrInvariant, fmt.Sprintf(format, arguments...))
}

func commandSpec(specs []CommandSpec, command app.CommandName) (CommandSpec, bool) {
	for _, spec := range specs {
		if spec.command == command {
			return spec, true
		}
	}
	return CommandSpec{}, false
}

func (spec CommandSpec) hasTypedExit(exit app.ExitCode) bool {
	for _, typedExit := range spec.typedExits {
		if typedExit == exit {
			return true
		}
	}
	return false
}

func unavailableCommandResult(command app.CommandName) (app.CommandResult, error) {
	diagnostic, err := app.NewDiagnostic(
		"cli.dispatch",
		domain.FailureConfiguration,
		"command_unavailable_in_g003",
		"Command is unavailable in G003.",
		"",
		"",
		domain.AttemptID{},
		false,
		false,
		"",
		"kar help",
	)
	if err != nil {
		return app.CommandResult{}, err
	}
	return app.NewCommandFailure(command, app.ExitCodeUsage, diagnostic)
}
