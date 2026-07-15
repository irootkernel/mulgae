package cli

import (
	"context"
	"slices"
	"testing"

	"github.com/irootkernel/kkachi-agent-review/internal/app"
)

const testCommandResultContractURI = "https://kar.local/schemas/kar-command-result.v1.schema.json"

func TestCommandSpecsMatchCompleteSOTContract(t *testing.T) {
	want := []struct {
		command      app.CommandName
		availability Availability
		owner        string
		service      string
		request      string
		outputs      []string
		exits        []app.ExitCode
	}{
		{app.CommandInit, AvailabilityFoundation, "internal/app/init", "InitializeProject", "https://kar.local/schemas/kar-command-result.v1.schema.json#/$defs/requests/init", []string{testCommandResultContractURI}, []app.ExitCode{app.ExitCodeUsage, app.ExitCodeArtifact}},
		{app.CommandDoctor, AvailabilityFoundation, "internal/app/doctor", "DiagnoseEnvironment", "https://kar.local/schemas/kar-command-result.v1.schema.json#/$defs/requests/doctor", []string{"https://kar.local/schemas/kar-doctor-result.v1.schema.json", testCommandResultContractURI}, []app.ExitCode{app.ExitCodeUsage, app.ExitCodeReadiness, app.ExitCodeArtifact, app.ExitCodeSecurity}},
		{app.CommandReview, AvailabilityFutureMilestone, "internal/app/review", "StartReviewRun", "https://kar.local/schemas/kar-command-result.v1.schema.json#/$defs/requests/review", []string{"https://kar.local/schemas/kar-run-manifest.v2.schema.json", "https://kar.local/schemas/kar-review-artifact.v2.schema.json", testCommandResultContractURI}, []app.ExitCode{app.ExitCodePolicy, app.ExitCodeUsage, app.ExitCodeReadiness, app.ExitCodeArtifact, app.ExitCodeSecurity, app.ExitCodeCancellation, app.ExitCodeInternal}},
		{app.CommandFollowup, AvailabilityFutureMilestone, "internal/app/followup", "StartFollowupRun", "https://kar.local/schemas/kar-command-result.v1.schema.json#/$defs/requests/followup", []string{"https://kar.local/schemas/kar-provider-followup-output.v2.schema.json", "https://kar.local/schemas/kar-run-manifest.v2.schema.json", "https://kar.local/schemas/kar-review-artifact.v2.schema.json", testCommandResultContractURI}, []app.ExitCode{app.ExitCodePolicy, app.ExitCodeUsage, app.ExitCodeReadiness, app.ExitCodeArtifact, app.ExitCodeSecurity, app.ExitCodeCancellation, app.ExitCodeInternal}},
		{app.CommandDelta, AvailabilityFutureMilestone, "internal/app/delta", "StartDeltaRun", "https://kar.local/schemas/kar-command-result.v1.schema.json#/$defs/requests/delta", []string{"https://kar.local/schemas/kar-run-manifest.v2.schema.json", "https://kar.local/schemas/kar-review-artifact.v2.schema.json", testCommandResultContractURI}, []app.ExitCode{app.ExitCodePolicy, app.ExitCodeUsage, app.ExitCodeReadiness, app.ExitCodeArtifact, app.ExitCodeSecurity, app.ExitCodeCancellation, app.ExitCodeInternal}},
		{app.CommandRerun, AvailabilityFutureMilestone, "internal/app/rerun", "StartRerun", "https://kar.local/schemas/kar-command-result.v1.schema.json#/$defs/requests/rerun", []string{"https://kar.local/schemas/kar-run-manifest.v2.schema.json", "https://kar.local/schemas/kar-review-artifact.v2.schema.json", "https://kar.local/schemas/kar-prompt-manifest.v1.schema.json", testCommandResultContractURI}, []app.ExitCode{app.ExitCodePolicy, app.ExitCodeUsage, app.ExitCodeReadiness, app.ExitCodeArtifact, app.ExitCodeSecurity, app.ExitCodeCancellation, app.ExitCodeInternal}},
		{app.CommandStatus, AvailabilityFutureMilestone, "internal/app/query", "ReadRunStatus", "https://kar.local/schemas/kar-command-result.v1.schema.json#/$defs/requests/status", []string{"https://kar.local/schemas/kar-run-manifest.v2.schema.json", testCommandResultContractURI}, []app.ExitCode{app.ExitCodeUsage, app.ExitCodeArtifact}},
		{app.CommandReport, AvailabilityFutureMilestone, "internal/app/report", "RenderReport", "https://kar.local/schemas/kar-command-result.v1.schema.json#/$defs/requests/report", []string{testCommandResultContractURI}, []app.ExitCode{app.ExitCodeUsage, app.ExitCodeArtifact}},
		{app.CommandFindings, AvailabilityFutureMilestone, "internal/app/query", "ListFindings", "https://kar.local/schemas/kar-command-result.v1.schema.json#/$defs/requests/findings", []string{"https://kar.local/schemas/kar-review-artifact.v2.schema.json", testCommandResultContractURI}, []app.ExitCode{app.ExitCodeUsage, app.ExitCodeArtifact}},
		{app.CommandExcerpt, AvailabilityFutureMilestone, "internal/app/query", "RenderExcerpt", "https://kar.local/schemas/kar-command-result.v1.schema.json#/$defs/requests/excerpt", []string{testCommandResultContractURI}, []app.ExitCode{app.ExitCodeUsage, app.ExitCodeReadiness, app.ExitCodeArtifact}},
		{app.CommandProviders, AvailabilityFutureMilestone, "internal/app/providers", "ListProviderProfiles", "https://kar.local/schemas/kar-command-result.v1.schema.json#/$defs/requests/providers", []string{"https://kar.local/schemas/kar-provider-contract-evidence.v1.schema.json", testCommandResultContractURI}, []app.ExitCode{app.ExitCodeUsage, app.ExitCodeReadiness, app.ExitCodeArtifact, app.ExitCodeSecurity}},
		{app.CommandConfig, AvailabilityFoundation, "internal/app/config", "ResolveConfiguration", "https://kar.local/schemas/kar-command-result.v1.schema.json#/$defs/requests/config", []string{"https://kar.local/schemas/kar-run-manifest.v2.schema.json", testCommandResultContractURI}, []app.ExitCode{app.ExitCodeUsage, app.ExitCodeSecurity}},
		{app.CommandPrompt, AvailabilityFutureMilestone, "internal/app/prompt", "InspectPrompt", "https://kar.local/schemas/kar-command-result.v1.schema.json#/$defs/requests/prompt", []string{"https://kar.local/schemas/kar-prompt-manifest.v1.schema.json", testCommandResultContractURI}, []app.ExitCode{app.ExitCodeUsage, app.ExitCodeArtifact, app.ExitCodeSecurity, app.ExitCodeInternal}},
		{app.CommandSchema, AvailabilityFoundation, "internal/app/schema", "InspectSchema", "https://kar.local/schemas/kar-command-result.v1.schema.json#/$defs/requests/schema", []string{testCommandResultContractURI}, []app.ExitCode{app.ExitCodeUsage, app.ExitCodeArtifact}},
		{app.CommandClean, AvailabilityFutureMilestone, "internal/app/clean", "PlanAndApplyRetention", "https://kar.local/schemas/kar-command-result.v1.schema.json#/$defs/requests/clean", []string{"https://kar.local/schemas/kar-clean-plan.v1.schema.json", testCommandResultContractURI}, []app.ExitCode{app.ExitCodeUsage, app.ExitCodeArtifact, app.ExitCodeSecurity}},
		{app.CommandExport, AvailabilityFutureMilestone, "internal/app/export", "ExportRedactedRun", "https://kar.local/schemas/kar-command-result.v1.schema.json#/$defs/requests/export", []string{"https://kar.local/schemas/kar-export-manifest.v1.schema.json", testCommandResultContractURI}, []app.ExitCode{app.ExitCodeUsage, app.ExitCodeArtifact, app.ExitCodeSecurity}},
		{app.CommandHelp, AvailabilityFoundation, "internal/app/help", "RenderHelp", "https://kar.local/schemas/kar-command-result.v1.schema.json#/$defs/requests/help", []string{testCommandResultContractURI}, []app.ExitCode{app.ExitCodeUsage}},
	}

	got := CommandSpecs()
	if len(got) != 17 {
		t.Fatalf("CommandSpecs length = %d, want 17", len(got))
	}
	if len(got) != len(want) {
		t.Fatalf("CommandSpecs length = %d, want %d", len(got), len(want))
	}
	for index, expected := range want {
		spec := got[index]
		if spec.Command() != expected.command || spec.Availability() != expected.availability || spec.Owner() != expected.owner || spec.Service() != expected.service || spec.RequestContractURI() != expected.request {
			t.Fatalf("spec %d metadata = command:%q availability:%q owner:%q service:%q request:%q", index, spec.Command(), spec.Availability(), spec.Owner(), spec.Service(), spec.RequestContractURI())
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
		{name: "invalid availability", mutate: func(specs []CommandSpec, _ map[app.CommandName]Handler) {
			specs[0].availability = Availability("invalid")
		}},
		{name: "wrong request URI", mutate: func(specs []CommandSpec, _ map[app.CommandName]Handler) {
			specs[0].requestContractURI = "https://invalid.example/request"
		}},
		{name: "missing foundation handler", mutate: func(_ []CommandSpec, handlers map[app.CommandName]Handler) { delete(handlers, app.CommandHelp) }},
		{name: "nil foundation handler", mutate: func(_ []CommandSpec, handlers map[app.CommandName]Handler) { handlers[app.CommandInit] = nil }},
		{name: "typed nil foundation handler", mutate: func(_ []CommandSpec, handlers map[app.CommandName]Handler) {
			handlers[app.CommandInit] = (*testHandler)(nil)
		}},
		{name: "future handler", mutate: func(_ []CommandSpec, handlers map[app.CommandName]Handler) {
			handlers[app.CommandReview] = &testHandler{}
		}},
		{name: "unknown handler", mutate: func(_ []CommandSpec, handlers map[app.CommandName]Handler) { handlers["unknown"] = &testHandler{} }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			specs := testCommandSpecs()
			handlers := testFoundationHandlers(t)
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
			if _, err := NewDispatcher(test.specs, testFoundationHandlers(t)); err == nil {
				t.Fatal("NewDispatcher succeeded")
			}
		})
	}
}

func TestNewDispatcherDefensivelyCopiesSpecsAndHandlers(t *testing.T) {
	specs := testCommandSpecs()
	handlers := testFoundationHandlers(t)
	initHandler := handlers[app.CommandInit].(*testHandler)
	dispatcher, err := NewDispatcher(specs, handlers)
	if err != nil {
		t.Fatal(err)
	}

	specs[0].availability = AvailabilityFutureMilestone
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

func testFoundationHandlers(t *testing.T) map[app.CommandName]Handler {
	t.Helper()
	handlers := make(map[app.CommandName]Handler)
	for _, command := range []app.CommandName{
		app.CommandInit,
		app.CommandDoctor,
		app.CommandConfig,
		app.CommandSchema,
		app.CommandHelp,
	} {
		result, err := app.NewCommandSuccess(command, []byte(`{}`))
		if err != nil {
			t.Fatal(err)
		}
		handlers[command] = &testHandler{result: result}
	}
	return handlers
}
