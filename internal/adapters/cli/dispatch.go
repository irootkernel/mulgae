package cli

import (
	"context"
	"fmt"

	"github.com/irootkernel/mulgae/internal/app"
	"github.com/irootkernel/mulgae/internal/domain"
)

// Handler executes one command.
type Handler interface {
	Execute(context.Context, []string) (app.CommandResult, error)
}

// Dispatcher routes commands from a validated registry.
type Dispatcher struct {
	specs    map[app.CommandName]CommandSpec
	handlers map[app.CommandName]Handler
}

// Dispatch executes a command. Callers must parse raw command tokens with
// app.ParseCommandName before dispatching them. Registry and handler invariants
// are returned as Go errors.
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

	handler, present := dispatcher.handlers[command]
	if !present || handlerIsNil(handler) {
		return app.CommandResult{}, dispatchInvariantError("command %q has no handler", command)
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
