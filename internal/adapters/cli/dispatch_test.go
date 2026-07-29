package cli

import (
	"context"
	"errors"
	"testing"

	"github.com/irootkernel/mulgae/internal/app"
	"github.com/irootkernel/mulgae/internal/domain"
)

type testHandler struct {
	result     app.CommandResult
	err        error
	calls      int
	gotArgs    []string
	mutateArgs bool
}

func (handler *testHandler) Execute(_ context.Context, args []string) (app.CommandResult, error) {
	handler.calls++
	handler.gotArgs = append([]string(nil), args...)
	if handler.mutateArgs && len(args) > 0 {
		args[0] = "mutated"
	}
	return handler.result, handler.err
}

func TestDispatchExecutesEveryRegisteredCommand(t *testing.T) {
	handlers := testCommandHandlers(t)
	dispatcher, err := NewDispatcher(CommandSpecs(), handlers)
	if err != nil {
		t.Fatal(err)
	}

	for _, specification := range CommandSpecs() {
		command := specification.Command()
		t.Run(string(command), func(t *testing.T) {
			result, err := dispatcher.Dispatch(context.Background(), command, []string{"request"})
			if err != nil {
				t.Fatal(err)
			}
			if !result.OK() || result.Command() != command || result.ExitCode() != app.ExitCodeSuccess {
				t.Fatalf("result = ok:%v command:%q exit:%d", result.OK(), result.Command(), result.ExitCode())
			}
			if handlers[command].(*testHandler).calls != 1 {
				t.Fatalf("handler calls = %d, want 1", handlers[command].(*testHandler).calls)
			}
		})
	}
}

func TestDispatchRejectsMissingHandlerAsInvariant(t *testing.T) {
	handlers := testCommandHandlers(t)
	dispatcher, err := NewDispatcher(CommandSpecs(), handlers)
	if err != nil {
		t.Fatal(err)
	}
	delete(dispatcher.handlers, app.CommandReview)

	result, err := dispatcher.Dispatch(context.Background(), app.CommandReview, nil)
	assertDispatcherInvariantError(t, result, err)
	if handlers[app.CommandReview].(*testHandler).calls != 0 {
		t.Fatal("review handler was called")
	}
}
func TestDispatchRejectsMissingCanonicalSpecAsInvariant(t *testing.T) {
	handlers := testCommandHandlers(t)
	dispatcher, err := NewDispatcher(CommandSpecs(), handlers)
	if err != nil {
		t.Fatal(err)
	}
	delete(dispatcher.specs, app.CommandReview)

	result, err := dispatcher.Dispatch(context.Background(), app.CommandReview, nil)
	assertDispatcherInvariantError(t, result, err)
	for command, handler := range handlers {
		if handler.(*testHandler).calls != 0 {
			t.Fatalf("handler %q was called", command)
		}
	}
}

func TestDispatchRejectsInvalidCommandNameWithoutCallingHandler(t *testing.T) {
	handlers := testCommandHandlers(t)
	dispatcher, err := NewDispatcher(CommandSpecs(), handlers)
	if err != nil {
		t.Fatal(err)
	}

	result, err := dispatcher.Dispatch(context.Background(), app.CommandName("unknown"), nil)
	if err == nil {
		t.Fatal("Dispatch succeeded for an invalid command")
	}
	if errors.Is(err, domain.ErrInvariant) {
		t.Fatalf("Dispatch error = %v, must be an invalid-command error", err)
	}
	if result.Command() != "" || result.OK() || result.ExitCode() != app.ExitCodeSuccess {
		t.Fatalf("invalid result = command:%q ok:%v exit:%d", result.Command(), result.OK(), result.ExitCode())
	}
	for command, handler := range handlers {
		if handler.(*testHandler).calls != 0 {
			t.Fatalf("handler %q was called", command)
		}
	}
}

func TestDispatchRejectsHandlerCommandMismatchAsInvariant(t *testing.T) {
	handlers := testCommandHandlers(t)
	mismatch, err := app.NewCommandSuccess(app.CommandDoctor, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	mismatchHandler := &testHandler{result: mismatch}
	handlers[app.CommandInit] = mismatchHandler
	dispatcher, err := NewDispatcher(CommandSpecs(), handlers)
	if err != nil {
		t.Fatal(err)
	}

	result, err := dispatcher.Dispatch(context.Background(), app.CommandInit, nil)
	assertDispatcherInvariantError(t, result, err)
	if mismatchHandler.calls != 1 {
		t.Fatalf("mismatch handler calls = %d, want 1", mismatchHandler.calls)
	}
}

func TestDispatchPreservesWrappedHandlerError(t *testing.T) {
	handlers := testCommandHandlers(t)
	result, err := app.NewCommandSuccess(app.CommandInit, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	handlerErr := errors.New("untrusted-secret")
	failingHandler := &testHandler{result: result, err: handlerErr}
	handlers[app.CommandInit] = failingHandler
	dispatcher, err := NewDispatcher(CommandSpecs(), handlers)
	if err != nil {
		t.Fatal(err)
	}

	result, err = dispatcher.Dispatch(context.Background(), app.CommandInit, nil)
	if !errors.Is(err, handlerErr) {
		t.Fatalf("Dispatch error = %v, want wrapped handler error", err)
	}
	if errors.Is(err, domain.ErrInvariant) {
		t.Fatalf("Dispatch error = %v, must not be an invariant", err)
	}
	assertEmptyCommandResult(t, result)
	if failingHandler.calls != 1 {
		t.Fatalf("failing handler calls = %d, want 1", failingHandler.calls)
	}
}

func TestDispatchRejectsUndeclaredHandlerFailureExitAsInvariant(t *testing.T) {
	handlers := testCommandHandlers(t)
	diagnostic, err := app.NewDiagnostic(
		"test",
		domain.FailureConfiguration,
		"undeclared_exit",
		"Test failure.",
		"",
		"",
		domain.AttemptID{},
		false,
		false,
		"",
		"",
	)
	if err != nil {
		t.Fatal(err)
	}
	failure, err := app.NewCommandFailure(app.CommandInit, app.ExitCodePolicy, diagnostic)
	if err != nil {
		t.Fatal(err)
	}
	failingHandler := &testHandler{result: failure}
	handlers[app.CommandInit] = failingHandler
	dispatcher, err := NewDispatcher(CommandSpecs(), handlers)
	if err != nil {
		t.Fatal(err)
	}

	result, err := dispatcher.Dispatch(context.Background(), app.CommandInit, nil)
	assertDispatcherInvariantError(t, result, err)
	if failingHandler.calls != 1 {
		t.Fatalf("failing handler calls = %d, want 1", failingHandler.calls)
	}
}
func TestDispatchReturnsDeclaredReadinessFailure(t *testing.T) {
	handlers := testCommandHandlers(t)
	diagnostic, err := app.NewDiagnostic(
		"test",
		domain.FailureConfiguration,
		"service_not_ready",
		"Service is not ready.",
		"",
		"",
		domain.AttemptID{},
		false,
		false,
		"",
		"",
	)
	if err != nil {
		t.Fatal(err)
	}
	failure, err := app.NewCommandFailure(app.CommandReview, app.ExitCodeReadiness, diagnostic)
	if err != nil {
		t.Fatal(err)
	}
	handler := &testHandler{result: failure}
	handlers[app.CommandReview] = handler
	dispatcher, err := NewDispatcher(CommandSpecs(), handlers)
	if err != nil {
		t.Fatal(err)
	}

	result, err := dispatcher.Dispatch(context.Background(), app.CommandReview, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.OK() || result.Command() != app.CommandReview || result.ExitCode() != app.ExitCodeReadiness {
		t.Fatalf("readiness result = ok:%v command:%q exit:%d", result.OK(), result.Command(), result.ExitCode())
	}
	if handler.calls != 1 {
		t.Fatalf("readiness handler calls = %d, want 1", handler.calls)
	}
}

func TestDispatchPassesCommandResultAndDefensivelyCopiesArgs(t *testing.T) {
	handlers := testCommandHandlers(t)
	result, err := app.NewCommandSuccess(app.CommandInit, []byte(`{"command":"result"}`))
	if err != nil {
		t.Fatal(err)
	}
	handler := &testHandler{result: result, mutateArgs: true}
	handlers[app.CommandInit] = handler
	dispatcher, err := NewDispatcher(CommandSpecs(), handlers)
	if err != nil {
		t.Fatal(err)
	}

	args := []string{"original"}
	got, err := dispatcher.Dispatch(context.Background(), app.CommandInit, args)
	if err != nil {
		t.Fatal(err)
	}
	if !got.OK() || got.Command() != app.CommandInit || got.ExitCode() != app.ExitCodeSuccess || string(got.Data()) != `{"command":"result"}` {
		t.Fatalf("command result = ok:%v command:%q exit:%d data:%q", got.OK(), got.Command(), got.ExitCode(), got.Data())
	}
	if handler.calls != 1 || len(handler.gotArgs) != 1 || handler.gotArgs[0] != "original" {
		t.Fatalf("handler calls/args = %d/%q", handler.calls, handler.gotArgs)
	}
	if args[0] != "original" {
		t.Fatalf("caller args mutated to %q", args[0])
	}
}

func assertDispatcherInvariantError(t *testing.T, result app.CommandResult, err error) {
	t.Helper()
	if !errors.Is(err, domain.ErrInvariant) {
		t.Fatalf("Dispatch error = %v, want ErrInvariant", err)
	}
	assertEmptyCommandResult(t, result)
}

func assertEmptyCommandResult(t *testing.T, result app.CommandResult) {
	t.Helper()
	if result.Command() != "" || result.OK() || result.ExitCode() != app.ExitCodeSuccess {
		t.Fatalf("empty result = command:%q ok:%v exit:%d", result.Command(), result.OK(), result.ExitCode())
	}
}
