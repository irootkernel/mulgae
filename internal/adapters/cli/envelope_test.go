package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/app"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

func TestEnvelopeRendererRendersCanonicalEnvelopeInContractOrder(t *testing.T) {
	t.Parallel()

	validator := &envelopeValidator{}
	renderer := mustEnvelopeRenderer(t, validator)
	request := []byte(`{"target":{"value":"origin/main...HEAD","kind":"diff"},"source_run_id":"r_019f596a-cfe4-7c9c-b82e-7149158243ba","request_id":"i_019f596a-e201-7a4b-8d76-1cf503a1849e","role":"logic","output_format":"json","objective":"Verify whether the source finding is resolved.","finding_id":"F003","command":"followup"}`)
	result := mustCommandSuccess(t, app.CommandFollowup, []byte(`{"run_id":"r_019f596a-e254-7b6f-93cd-4c67cf3d4b2e","followup_artifact_uri":".mulgae/followup.json","session_id":"s_019f596a-cf80-7c67-b265-f37053d51ccf","resolution":"still_open","kind":"followup_started"}`))

	got, err := renderer.Render(context.Background(), result, request, nil)
	if err != nil {
		t.Fatalf("Render() error = %v", err)
	}
	want := []byte("{\"schema_version\":\"mulgae-command-result.v2\",\"command\":\"followup\",\"request\":{\"command\":\"followup\",\"finding_id\":\"F003\",\"objective\":\"Verify whether the source finding is resolved.\",\"output_format\":\"json\",\"request_id\":\"i_019f596a-e201-7a4b-8d76-1cf503a1849e\",\"role\":\"logic\",\"source_run_id\":\"r_019f596a-cfe4-7c9c-b82e-7149158243ba\",\"target\":{\"kind\":\"diff\",\"value\":\"origin/main...HEAD\"}},\"completed_at\":\"2026-07-13T03:10:00.123Z\",\"exit\":{\"code\":0,\"kind\":\"success\"},\"reasons\":[],\"result\":{\"followup_artifact_uri\":\".mulgae/followup.json\",\"kind\":\"followup_started\",\"resolution\":\"still_open\",\"run_id\":\"r_019f596a-e254-7b6f-93cd-4c67cf3d4b2e\",\"session_id\":\"s_019f596a-cf80-7c67-b265-f37053d51ccf\"}}\n")
	if !bytes.Equal(got, want) {
		t.Fatalf("Render() = %s\nwant     = %s", got, want)
	}
	if validator.calls != 1 {
		t.Fatalf("validator calls = %d, want 1", validator.calls)
	}
	if !bytes.Equal(validator.raw, want[:len(want)-1]) {
		t.Fatalf("validator input = %s\nwant            = %s", validator.raw, want[:len(want)-1])
	}
}

func TestEnvelopeRendererMapsEveryExitCode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		code app.ExitCode
		kind string
	}{
		{name: "success", code: app.ExitCodeSuccess, kind: "success"},
		{name: "policy", code: app.ExitCodePolicy, kind: "policy"},
		{name: "usage", code: app.ExitCodeUsage, kind: "usage"},
		{name: "readiness", code: app.ExitCodeReadiness, kind: "readiness"},
		{name: "artifact", code: app.ExitCodeArtifact, kind: "artifact"},
		{name: "security", code: app.ExitCodeSecurity, kind: "security"},
		{name: "cancellation", code: app.ExitCodeCancellation, kind: "cancellation"},
		{name: "internal", code: app.ExitCodeInternal, kind: "internal"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			validator := &envelopeValidator{}
			renderer := mustEnvelopeRenderer(t, validator)
			result := commandResultForExit(t, test.code)
			raw, err := renderer.Render(context.Background(), result, []byte(`{}`), []byte(`{}`))
			if err != nil {
				t.Fatalf("Render() error = %v", err)
			}

			var envelope struct {
				Exit commandExit `json:"exit"`
			}
			if err := json.Unmarshal(raw, &envelope); err != nil {
				t.Fatalf("decode envelope: %v", err)
			}
			if envelope.Exit.Code != int(test.code) || envelope.Exit.Kind != test.kind {
				t.Fatalf("exit = %#v, want code %d kind %q", envelope.Exit, test.code, test.kind)
			}
			if validator.calls != 1 {
				t.Fatalf("validator calls = %d, want 1", validator.calls)
			}
		})
	}
}

func TestEnvelopeRendererHonorsCommandOwnedRetryability(t *testing.T) {
	t.Parallel()
	diagnostic, err := app.NewDiagnosticWithRetryable(
		"cli.init",
		domain.FailureArtifact,
		"init_write_failed",
		"The project-local Mulgae configuration could not be written.",
		true,
	)
	if err != nil {
		t.Fatal(err)
	}
	result, err := app.NewCommandFailure(app.CommandInit, app.ExitCodeArtifact, diagnostic)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := mustEnvelopeRenderer(t, &envelopeValidator{}).Render(context.Background(), result, []byte(`{}`), []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		Reasons []commandReason `json:"reasons"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatal(err)
	}
	if len(envelope.Reasons) != 1 || !envelope.Reasons[0].Retryable {
		t.Fatalf("reasons = %#v, want retryable init artifact", envelope.Reasons)
	}
}

func TestEnvelopeRendererRedactsDiagnosticInternals(t *testing.T) {
	t.Parallel()

	attemptID, err := domain.ParseAttemptID("a_019f596a-e254-7b6f-93cd-4c67cf3d4b2e")
	if err != nil {
		t.Fatalf("ParseAttemptID() error = %v", err)
	}
	diagnostic, err := app.NewDiagnostic(
		"provider_internal_stage",
		domain.FailureSecurityPolicy,
		"secret_guard_triggered",
		"The guarded input cannot be transmitted.",
		"security_reviewer",
		"remote-provider.internal",
		attemptID,
		".mulgae/diagnostics/guard.json",
		"mulgae doctor --internal-debug",
	)
	if err != nil {
		t.Fatalf("NewDiagnostic() error = %v", err)
	}
	result, err := app.NewCommandFailure(app.CommandDoctor, app.ExitCodeSecurity, diagnostic)
	if err != nil {
		t.Fatalf("NewCommandFailure() error = %v", err)
	}

	raw, err := mustEnvelopeRenderer(t, &envelopeValidator{}).Render(context.Background(), result, []byte(`{}`), []byte(`{}`))
	if err != nil {
		t.Fatalf("Render() error = %v", err)
	}
	for _, forbidden := range []string{
		"provider_internal_stage",
		"security_reviewer",
		"remote-provider.internal",
		attemptID.String(),
		"mulgae doctor --internal-debug",
		"provider_fault",
	} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("envelope leaks diagnostic internals %q: %s", forbidden, raw)
		}
	}

	var envelope struct {
		Reasons []commandReason `json:"reasons"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	want := commandReason{
		Category:    "security",
		Code:        "secret_guard_triggered",
		Message:     "The guarded input cannot be transmitted.",
		Retryable:   false,
		ArtifactURI: stringPointer(".mulgae/diagnostics/guard.json"),
	}
	if len(envelope.Reasons) != 1 || !equalReason(envelope.Reasons[0], want) {
		t.Fatalf("reasons = %#v, want %#v", envelope.Reasons, want)
	}
}

func TestEnvelopeRendererMapsDiagnosticClassesInInputOrder(t *testing.T) {
	t.Parallel()

	tests := []struct {
		class     domain.FailureClass
		category  string
		retryable bool
	}{
		{class: domain.FailureProviderUnavailable, category: "readiness", retryable: true},
		{class: domain.FailureInvalidOutput, category: "evidence", retryable: true},
		{class: domain.FailureTimeout, category: "readiness", retryable: true},
		{class: domain.FailureAuthentication, category: "readiness", retryable: true},
		{class: domain.FailureQuota, category: "readiness", retryable: true},
		{class: domain.FailureRateLimit, category: "readiness", retryable: true},
		{class: domain.FailureSecurityPolicy, category: "security", retryable: false},
		{class: domain.FailureConfiguration, category: "configuration", retryable: false},
		{class: domain.FailureArtifact, category: "artifact", retryable: false},
		{class: domain.FailureInternal, category: "internal", retryable: false},
		{class: domain.FailureCancelled, category: "cancellation", retryable: false},
	}
	for _, test := range tests {
		category, err := diagnosticCategory(test.class)
		if err != nil {
			t.Fatalf("diagnosticCategory(%q) error = %v", test.class, err)
		}
		if category != test.category {
			t.Fatalf("diagnosticCategory(%q) = %q, want %q", test.class, category, test.category)
		}
	}

	diagnostics := make([]app.Diagnostic, 0, len(tests))
	for _, test := range tests {
		diagnostic, err := app.NewDiagnostic(
			"cli_test",
			test.class,
			string(test.class),
			"The command failed.",
			"",
			"",
			domain.AttemptID{},
			"",
			"",
		)
		if err != nil {
			t.Fatalf("NewDiagnostic(%q) error = %v", test.class, err)
		}
		diagnostics = append(diagnostics, diagnostic)
	}
	result, err := app.NewCommandFailure(app.CommandReview, app.ExitCodeInternal, diagnostics...)
	if err != nil {
		t.Fatalf("NewCommandFailure() error = %v", err)
	}

	raw, err := mustEnvelopeRenderer(t, &envelopeValidator{}).Render(context.Background(), result, []byte(`{}`), []byte(`{}`))
	if err != nil {
		t.Fatalf("Render() error = %v", err)
	}
	var envelope struct {
		Reasons []commandReason `json:"reasons"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	if len(envelope.Reasons) != len(tests) {
		t.Fatalf("reason count = %d, want %d", len(envelope.Reasons), len(tests))
	}
	for index, test := range tests {
		reason := envelope.Reasons[index]
		if reason.Category != test.category || reason.Code != string(test.class) || reason.Message != "The command failed." || reason.Retryable != test.retryable || reason.ArtifactURI != nil {
			t.Fatalf("reason %d = %#v, want category %q code %q retryable %t without artifact", index, reason, test.category, test.class, test.retryable)
		}
	}
}

func TestDiagnosticCategoryFailsClosedForUnmappedClass(t *testing.T) {
	t.Parallel()

	category, err := diagnosticCategory(domain.FailureClass("future_failure_class"))
	if err == nil {
		t.Fatal("diagnosticCategory() error = nil, want unmapped-class rejection")
	}
	if category != "" {
		t.Fatalf("diagnosticCategory() = %q, want empty category", category)
	}
}

func TestEnvelopeRendererRejectsInvalidRawObjects(t *testing.T) {
	t.Parallel()

	success := mustCommandSuccess(t, app.CommandReview, []byte(`{}`))
	failure := mustCommandFailure(t, app.CommandReview, app.ExitCodeUsage)
	tests := []struct {
		name       string
		result     app.CommandResult
		request    []byte
		projection []byte
	}{
		{name: "nil request", result: success},
		{name: "malformed request", result: success, request: []byte(`{`)},
		{name: "null request", result: success, request: []byte(`null`)},
		{name: "request is array", result: success, request: []byte(`[]`)},
		{name: "duplicate request keys", result: success, request: []byte(`{"kind":"first","kind":"second"}`)},
		{name: "nested duplicate request keys", result: success, request: []byte(`{"request":{"kind":"first","kind":"second"}}`)},
		{name: "trailing request", result: success, request: []byte(`{}{}`)},
		{name: "nil failure projection", result: failure, request: []byte(`{}`)},
		{name: "malformed failure projection", result: failure, request: []byte(`{}`), projection: []byte(`{`)},
		{name: "null failure projection", result: failure, request: []byte(`{}`), projection: []byte(`null`)},
		{name: "failure projection is array", result: failure, request: []byte(`{}`), projection: []byte(`[]`)},
		{name: "duplicate failure projection keys", result: failure, request: []byte(`{}`), projection: []byte(`{"kind":"first","kind":"second"}`)},
		{name: "nested duplicate failure projection keys", result: failure, request: []byte(`{}`), projection: []byte(`{"result":{"kind":"first","kind":"second"}}`)},
		{name: "trailing failure projection", result: failure, request: []byte(`{}`), projection: []byte(`{}{}`)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			validator := &envelopeValidator{}
			got, err := mustEnvelopeRenderer(t, validator).Render(context.Background(), test.result, test.request, test.projection)
			if err == nil {
				t.Fatal("Render() error = nil, want JSON rejection")
			}
			if got != nil {
				t.Fatalf("Render() output = %q, want nil", got)
			}
			if validator.calls != 0 {
				t.Fatalf("validator calls = %d, want 0", validator.calls)
			}
		})
	}
}

func TestEnvelopeRendererFailsClosedWhenValidationFailsAndCopiesOutput(t *testing.T) {
	t.Parallel()

	validator := &envelopeValidator{err: errors.New("schema rejected"), mutate: true}
	renderer := mustEnvelopeRenderer(t, validator)
	result := mustCommandSuccess(t, app.CommandReview, []byte(`{"kind":"review_started"}`))
	got, err := renderer.Render(context.Background(), result, []byte(`{"command":"review"}`), nil)
	if err == nil {
		t.Fatal("Render() error = nil, want validation error")
	}
	if got != nil {
		t.Fatalf("Render() output = %q, want nil", got)
	}
	if validator.calls != 1 {
		t.Fatalf("validator calls = %d, want 1", validator.calls)
	}
	if validator.schemaID.String() != commandResultContractURI {
		t.Fatalf("validator schema ID = %q, want %q", validator.schemaID.String(), commandResultContractURI)
	}
	if len(validator.raw) == 0 || validator.raw[0] != '[' {
		t.Fatalf("validator did not receive its own mutable copy: %q", validator.raw)
	}

	validator.err = nil
	validator.mutate = false
	output, err := renderer.Render(context.Background(), result, []byte(`{"command":"review"}`), nil)
	if err != nil {
		t.Fatalf("Render() error = %v", err)
	}
	if len(output) == 0 || output[0] != '{' || output[len(output)-1] != '\n' {
		t.Fatalf("output was mutated through validator input: %q", output)
	}
	validator.raw[0] = '['
	if output[0] != '{' {
		t.Fatalf("output aliases validator input: %q", output)
	}
}

func TestEnvelopeRendererKeepsAttributedCommittedReasonInsideClosedShape(t *testing.T) {
	reason, err := app.NewCommittedReason(
		"provider_output_missing",
		"Stage provider.execute; role logic; provider zcode-logic; reason provider_output_missing; hint: run mulgae doctor.",
	)
	if err != nil {
		t.Fatal(err)
	}
	result, err := app.NewCommittedCommandOutcomeWithReasons(
		app.CommandReview, app.ExitCodeReadiness, []byte(`{"kind":"review_started"}`), []app.CommittedReason{reason},
	)
	if err != nil {
		t.Fatal(err)
	}
	output, err := mustEnvelopeRenderer(t, &envelopeValidator{}).Render(
		context.Background(), result, []byte(`{"command":"review"}`), nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		SchemaVersion string          `json:"schema_version"`
		Reasons       []commandReason `json:"reasons"`
	}
	if err := json.Unmarshal(output, &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.SchemaVersion != "mulgae-command-result.v2" || len(envelope.Reasons) != 1 ||
		envelope.Reasons[0].Code != reason.Code() || envelope.Reasons[0].Message != reason.Message() {
		t.Fatalf("committed envelope = %#v", envelope)
	}
}

type envelopeClock struct {
	now time.Time
}

func (clock envelopeClock) Now() time.Time {
	return clock.now
}

type envelopeValidator struct {
	calls    int
	schemaID ports.AssetID
	raw      []byte
	err      error
	mutate   bool
}

func (validator *envelopeValidator) Validate(_ context.Context, schemaID ports.AssetID, raw []byte) error {
	validator.calls++
	validator.schemaID = schemaID
	validator.raw = raw
	if validator.mutate && len(raw) != 0 {
		raw[0] = '['
	}
	return validator.err
}

func mustEnvelopeRenderer(t *testing.T, validator SchemaValidator) *EnvelopeRenderer {
	t.Helper()
	renderer, err := NewEnvelopeRenderer(envelopeClock{now: time.Date(2026, 7, 13, 3, 10, 0, 123456789, time.UTC)}, validator)
	if err != nil {
		t.Fatalf("NewEnvelopeRenderer() error = %v", err)
	}
	return renderer
}

func mustCommandSuccess(t *testing.T, command app.CommandName, data []byte) app.CommandResult {
	t.Helper()
	result, err := app.NewCommandSuccess(command, data)
	if err != nil {
		t.Fatalf("NewCommandSuccess() error = %v", err)
	}
	return result
}

func mustCommandFailure(t *testing.T, command app.CommandName, code app.ExitCode) app.CommandResult {
	t.Helper()
	diagnostic, err := app.NewDiagnostic(
		"cli_test",
		domain.FailureConfiguration,
		"command_failed",
		"The command failed.",
		"",
		"",
		domain.AttemptID{},
		"",
		"",
	)
	if err != nil {
		t.Fatalf("NewDiagnostic() error = %v", err)
	}
	result, err := app.NewCommandFailure(command, code, diagnostic)
	if err != nil {
		t.Fatalf("NewCommandFailure() error = %v", err)
	}
	return result
}

func commandResultForExit(t *testing.T, code app.ExitCode) app.CommandResult {
	t.Helper()
	if code == app.ExitCodeSuccess {
		return mustCommandSuccess(t, app.CommandReview, []byte(`{}`))
	}
	return mustCommandFailure(t, app.CommandReview, code)
}

func stringPointer(value string) *string {
	return &value
}

func equalReason(left, right commandReason) bool {
	if left.Category != right.Category || left.Code != right.Code || left.Message != right.Message || left.Retryable != right.Retryable {
		return false
	}
	if left.ArtifactURI == nil || right.ArtifactURI == nil {
		return left.ArtifactURI == nil && right.ArtifactURI == nil
	}
	return *left.ArtifactURI == *right.ArtifactURI
}
