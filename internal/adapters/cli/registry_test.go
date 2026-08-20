package cli

import (
	"context"
	"slices"
	"testing"

	"github.com/irootkernel/mulgae/internal/app"
)

const testCommandResultContractURI = "https://mulgae.local/schemas/mulgae-command-result.v5.schema.json"

func TestCommandSpecsMatchCompleteSOTContract(t *testing.T) {
	want := []struct {
		command app.CommandName
		owner   string
		service string
		request string
		outputs []string
		exits   []app.ExitCode
	}{
		{app.CommandInit, "internal/app/init", "InitializeProject", testCommandResultContractURI + "#/$defs/requests/init", []string{testCommandResultContractURI}, []app.ExitCode{app.ExitCodeUsage, app.ExitCodeReadiness, app.ExitCodeArtifact, app.ExitCodeSecurity, app.ExitCodeCancellation, app.ExitCodeInternal}},
		{app.CommandDoctor, "internal/app/doctor", "DiagnoseEnvironment", testCommandResultContractURI + "#/$defs/requests/doctor", []string{"https://mulgae.local/schemas/mulgae-doctor-result.v2.schema.json", testCommandResultContractURI}, []app.ExitCode{app.ExitCodeUsage, app.ExitCodeReadiness, app.ExitCodeArtifact, app.ExitCodeSecurity, app.ExitCodeCancellation}},
		{app.CommandReview, "internal/app/review", "StartReviewRun", testCommandResultContractURI + "#/$defs/requests/review", []string{"https://mulgae.local/schemas/mulgae-run-manifest.v1.schema.json", "https://mulgae.local/schemas/mulgae-review-artifact.v1.schema.json", "https://mulgae.local/schemas/mulgae-review-preflight.v3.schema.json", testCommandResultContractURI}, []app.ExitCode{app.ExitCodePolicy, app.ExitCodeUsage, app.ExitCodeReadiness, app.ExitCodeArtifact, app.ExitCodeSecurity, app.ExitCodeCancellation, app.ExitCodeInternal}},
		{app.CommandFollowup, "internal/app/followup", "StartFollowupRun", testCommandResultContractURI + "#/$defs/requests/followup", []string{"https://mulgae.local/schemas/mulgae-provider-followup-output.v1.schema.json", "https://mulgae.local/schemas/mulgae-run-manifest.v1.schema.json", "https://mulgae.local/schemas/mulgae-review-artifact.v1.schema.json", testCommandResultContractURI}, []app.ExitCode{app.ExitCodePolicy, app.ExitCodeUsage, app.ExitCodeReadiness, app.ExitCodeArtifact, app.ExitCodeSecurity, app.ExitCodeCancellation, app.ExitCodeInternal}},
		{app.CommandDelta, "internal/app/delta", "StartDeltaRun", testCommandResultContractURI + "#/$defs/requests/delta", []string{"https://mulgae.local/schemas/mulgae-run-manifest.v1.schema.json", "https://mulgae.local/schemas/mulgae-review-artifact.v1.schema.json", testCommandResultContractURI}, []app.ExitCode{app.ExitCodePolicy, app.ExitCodeUsage, app.ExitCodeReadiness, app.ExitCodeArtifact, app.ExitCodeSecurity, app.ExitCodeCancellation, app.ExitCodeInternal}},
		{app.CommandRerun, "internal/app/rerun", "StartRerun", testCommandResultContractURI + "#/$defs/requests/rerun", []string{"https://mulgae.local/schemas/mulgae-run-manifest.v1.schema.json", "https://mulgae.local/schemas/mulgae-review-artifact.v1.schema.json", testCommandResultContractURI}, []app.ExitCode{app.ExitCodePolicy, app.ExitCodeUsage, app.ExitCodeReadiness, app.ExitCodeArtifact, app.ExitCodeSecurity, app.ExitCodeCancellation, app.ExitCodeInternal}},
		{app.CommandStatus, "internal/app/query", "ReadRunStatus", testCommandResultContractURI + "#/$defs/requests/status", []string{"https://mulgae.local/schemas/mulgae-run-manifest.v1.schema.json", testCommandResultContractURI}, []app.ExitCode{app.ExitCodeUsage, app.ExitCodeArtifact, app.ExitCodeSecurity, app.ExitCodeCancellation, app.ExitCodeInternal}},
		{app.CommandReport, "internal/app/report", "RenderReport", testCommandResultContractURI + "#/$defs/requests/report", []string{testCommandResultContractURI}, []app.ExitCode{app.ExitCodeUsage, app.ExitCodeArtifact, app.ExitCodeSecurity, app.ExitCodeCancellation, app.ExitCodeInternal}},
		{app.CommandFindings, "internal/app/query", "ListFindings", testCommandResultContractURI + "#/$defs/requests/findings", []string{"https://mulgae.local/schemas/mulgae-review-artifact.v1.schema.json", testCommandResultContractURI}, []app.ExitCode{app.ExitCodeUsage, app.ExitCodeArtifact, app.ExitCodeSecurity, app.ExitCodeCancellation, app.ExitCodeInternal}},
		{app.CommandExcerpt, "internal/app/query", "RenderExcerpt", testCommandResultContractURI + "#/$defs/requests/excerpt", []string{testCommandResultContractURI}, []app.ExitCode{app.ExitCodeUsage, app.ExitCodeReadiness, app.ExitCodeArtifact, app.ExitCodeSecurity, app.ExitCodeCancellation, app.ExitCodeInternal}},
		{app.CommandProviders, "internal/app/providers", "ListProviderProfiles", testCommandResultContractURI + "#/$defs/requests/providers", []string{"https://mulgae.local/schemas/mulgae-provider-contract-evidence.v2.schema.json", testCommandResultContractURI}, []app.ExitCode{app.ExitCodeUsage, app.ExitCodeReadiness, app.ExitCodeArtifact, app.ExitCodeSecurity}},
		{app.CommandHeartbeat, "internal/app/heartbeat", "ProbeProvider", testCommandResultContractURI + "#/$defs/requests/heartbeat", []string{"https://mulgae.local/schemas/mulgae-provider-heartbeat-result.v1.schema.json", testCommandResultContractURI}, []app.ExitCode{app.ExitCodeUsage, app.ExitCodeReadiness, app.ExitCodeArtifact, app.ExitCodeSecurity, app.ExitCodeCancellation, app.ExitCodeInternal}},
		{app.CommandRoles, "internal/app/roles", "ListRoles", testCommandResultContractURI + "#/$defs/requests/roles", []string{testCommandResultContractURI}, []app.ExitCode{app.ExitCodeUsage}},
		{app.CommandConfig, "internal/app/config", "ResolveConfiguration", testCommandResultContractURI + "#/$defs/requests/config", []string{"https://mulgae.local/schemas/mulgae-run-manifest.v1.schema.json", testCommandResultContractURI}, []app.ExitCode{app.ExitCodeUsage, app.ExitCodeReadiness, app.ExitCodeArtifact, app.ExitCodeSecurity, app.ExitCodeCancellation, app.ExitCodeInternal}},
		{app.CommandSchema, "internal/app/schema", "InspectSchema", testCommandResultContractURI + "#/$defs/requests/schema", []string{testCommandResultContractURI}, []app.ExitCode{app.ExitCodeUsage, app.ExitCodeArtifact}},
		{app.CommandClean, "internal/app/clean", "CleanRuns", testCommandResultContractURI + "#/$defs/requests/clean", []string{"https://mulgae.local/schemas/mulgae-clean-plan.v1.schema.json", testCommandResultContractURI}, []app.ExitCode{app.ExitCodeUsage, app.ExitCodeArtifact, app.ExitCodeSecurity}},
		{app.CommandExport, "internal/app/export", "ExportRedactedRun", testCommandResultContractURI + "#/$defs/requests/export", []string{"https://mulgae.local/schemas/mulgae-export-manifest.v1.schema.json", testCommandResultContractURI}, []app.ExitCode{app.ExitCodeUsage, app.ExitCodeArtifact, app.ExitCodeSecurity}},
		{app.CommandHelp, "internal/app/help", "RenderHelp", testCommandResultContractURI + "#/$defs/requests/help", []string{testCommandResultContractURI}, []app.ExitCode{app.ExitCodeUsage}},
	}

	got := CommandSpecs()
	if len(got) != 18 {
		t.Fatalf("CommandSpecs length = %d, want 18", len(got))
	}
	if len(got) != len(want) {
		t.Fatalf("CommandSpecs length = %d, want %d", len(got), len(want))
	}
	for index, expected := range want {
		spec := got[index]
		if spec.Command() != expected.command || spec.Owner() != expected.owner || spec.Service() != expected.service || spec.RequestContractURI() != expected.request {
			t.Fatalf("spec %d metadata = command:%q owner:%q service:%q request:%q", index, spec.Command(), spec.Owner(), spec.Service(), spec.RequestContractURI())
		}
		if !slices.Equal(spec.OutputContractURIs(), expected.outputs) {
			t.Fatalf("spec %q outputs = %q, want %q", spec.Command(), spec.OutputContractURIs(), expected.outputs)
		}
		if !slices.Equal(spec.TypedExits(), expected.exits) {
			t.Fatalf("spec %q exits = %v, want %v", spec.Command(), spec.TypedExits(), expected.exits)
		}
	}
}

func TestCommandSpecsMutationIsIsolated(t *testing.T) {
	first := CommandSpecs()
	second := CommandSpecs()
	if &first[0] == &second[0] {
		t.Fatal("CommandSpecs reused its result slice")
	}

	first[0].owner = "mutated"
	first[0].outputContractURIs[0] = "mutated"
	first[0].typedExits[0] = app.ExitCodeInternal
	if second[0].Owner() != "internal/app/init" {
		t.Fatalf("owner after first result mutation = %q", second[0].Owner())
	}
	if got := second[0].OutputContractURIs()[0]; got != testCommandResultContractURI {
		t.Fatalf("output after first result mutation = %q", got)
	}
	if got := second[0].TypedExits()[0]; got != app.ExitCodeUsage {
		t.Fatalf("exit after first result mutation = %d", got)
	}

	outputs := second[0].OutputContractURIs()
	exits := second[0].TypedExits()
	outputs[0] = "mutated"
	exits[0] = app.ExitCodeInternal
	if got := second[0].OutputContractURIs()[0]; got != testCommandResultContractURI {
		t.Fatalf("output after accessor mutation = %q", got)
	}
	if got := second[0].TypedExits()[0]; got != app.ExitCodeUsage {
		t.Fatalf("exit after accessor mutation = %d", got)
	}
}

func TestNewDispatcherRejectsInvalidRegistryAndHandlerSets(t *testing.T) {
	tests := []struct {
		name   string
		mutate func([]CommandSpec, map[app.CommandName]Handler)
	}{
		{name: "wrong order", mutate: func(specs []CommandSpec, _ map[app.CommandName]Handler) { specs[0], specs[1] = specs[1], specs[0] }},
		{name: "duplicate command", mutate: func(specs []CommandSpec, _ map[app.CommandName]Handler) { specs[1].command = specs[0].command }},
		{name: "empty owner", mutate: func(specs []CommandSpec, _ map[app.CommandName]Handler) { specs[0].owner = "" }},
		{name: "empty service", mutate: func(specs []CommandSpec, _ map[app.CommandName]Handler) { specs[0].service = "" }},
		{name: "duplicate output contract", mutate: func(specs []CommandSpec, _ map[app.CommandName]Handler) {
			specs[2].outputContractURIs[1] = specs[2].outputContractURIs[0]
		}},
		{name: "duplicate typed exit", mutate: func(specs []CommandSpec, _ map[app.CommandName]Handler) {
			specs[2].typedExits[1] = specs[2].typedExits[0]
		}},
		{name: "empty output contracts", mutate: func(specs []CommandSpec, _ map[app.CommandName]Handler) { specs[2].outputContractURIs = nil }},
		{name: "unassigned typed exit", mutate: func(specs []CommandSpec, _ map[app.CommandName]Handler) { specs[2].typedExits[0] = app.ExitCode(3) }},
		{name: "empty typed exits", mutate: func(specs []CommandSpec, _ map[app.CommandName]Handler) { specs[2].typedExits = nil }},
		{name: "wrong request URI", mutate: func(specs []CommandSpec, _ map[app.CommandName]Handler) {
			specs[0].requestContractURI = "https://invalid.example/request"
		}},
		{name: "missing handler", mutate: func(_ []CommandSpec, handlers map[app.CommandName]Handler) { delete(handlers, app.CommandHelp) }},
		{name: "nil handler", mutate: func(_ []CommandSpec, handlers map[app.CommandName]Handler) { handlers[app.CommandInit] = nil }},
		{name: "typed nil handler", mutate: func(_ []CommandSpec, handlers map[app.CommandName]Handler) {
			handlers[app.CommandInit] = (*testHandler)(nil)
		}},
		{name: "unknown handler", mutate: func(_ []CommandSpec, handlers map[app.CommandName]Handler) { handlers["unknown"] = &testHandler{} }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			specs := testCommandSpecs()
			handlers := testCommandHandlers(t)
			test.mutate(specs, handlers)
			if _, err := NewDispatcher(specs, handlers); err == nil {
				t.Fatal("NewDispatcher succeeded")
			}
		})
	}
}
func TestNewDispatcherRejectsWrongCardinality(t *testing.T) {
	tests := []struct {
		name  string
		specs []CommandSpec
	}{
		{name: "too few", specs: testCommandSpecs()[:16]},
		{name: "too many", specs: append(testCommandSpecs(), CommandSpec{})},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewDispatcher(test.specs, testCommandHandlers(t)); err == nil {
				t.Fatal("NewDispatcher succeeded")
			}
		})
	}
}

func TestNewDispatcherDefensivelyCopiesSpecsAndHandlers(t *testing.T) {
	specs := testCommandSpecs()
	handlers := testCommandHandlers(t)
	initHandler := handlers[app.CommandInit].(*testHandler)
	dispatcher, err := NewDispatcher(specs, handlers)
	if err != nil {
		t.Fatal(err)
	}

	specs[0].outputContractURIs[0] = "mutated"
	handlers[app.CommandInit] = &testHandler{}

	result, err := dispatcher.Dispatch(context.Background(), app.CommandInit, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !result.OK() || initHandler.calls != 1 {
		t.Fatalf("dispatch after caller mutation = ok:%v calls:%d", result.OK(), initHandler.calls)
	}
}

func testCommandSpecs() []CommandSpec {
	return cloneCommandSpecs(CommandSpecs())
}

func testCommandHandlers(t *testing.T) map[app.CommandName]Handler {
	t.Helper()
	handlers := make(map[app.CommandName]Handler, fixedCommandSpecCount)
	for _, specification := range CommandSpecs() {
		command := specification.Command()
		result, err := app.NewCommandSuccess(command, []byte(`{}`))
		if err != nil {
			t.Fatal(err)
		}
		handlers[command] = &testHandler{result: result}
	}
	return handlers
}
