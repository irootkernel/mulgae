package app

import (
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/domain"
)

func TestExitCodeValuesAreExactAndClosed(t *testing.T) {
	t.Parallel()

	tests := []struct {
		code ExitCode
		want int
	}{
		{ExitCodeSuccess, 0},
		{ExitCodePolicy, 1},
		{ExitCodeUsage, 2},
		{ExitCodeReadiness, 4},
		{ExitCodeArtifact, 7},
		{ExitCodeSecurity, 8},
		{ExitCodeCancellation, 9},
		{ExitCodeInternal, 10},
	}
	for _, test := range tests {
		if int(test.code) != test.want {
			t.Errorf("exit code = %d, want %d", test.code, test.want)
		}
		if !test.code.Valid() {
			t.Errorf("exit code %d is not valid", test.code)
		}
	}
	for _, code := range []ExitCode{-1, 3, 5, 6, 11} {
		if code.Valid() {
			t.Errorf("unassigned exit code %d is valid", code)
		}
	}
}

func TestCommandResultRejectsInvalidCombinations(t *testing.T) {
	t.Parallel()

	diagnostic := testDiagnostic(t)
	tests := []struct {
		name        string
		command     CommandName
		ok          bool
		exitCode    ExitCode
		data        []byte
		diagnostics []Diagnostic
	}{
		{
			name:     "unknown command",
			command:  "unknown",
			ok:       true,
			exitCode: ExitCodeSuccess,
		},
		{
			name:     "success nonzero exit",
			command:  CommandReview,
			ok:       true,
			exitCode: ExitCodePolicy,
		},
		{
			name:        "success diagnostics",
			command:     CommandReview,
			ok:          true,
			exitCode:    ExitCodeSuccess,
			diagnostics: []Diagnostic{diagnostic},
		},
		{
			name:        "failure zero exit",
			command:     CommandReview,
			ok:          false,
			exitCode:    ExitCodeSuccess,
			diagnostics: []Diagnostic{diagnostic},
		},
		{
			name:        "failure unassigned exit",
			command:     CommandReview,
			ok:          false,
			exitCode:    ExitCode(3),
			diagnostics: []Diagnostic{diagnostic},
		},
		{
			name:        "failure data",
			command:     CommandReview,
			ok:          false,
			exitCode:    ExitCodeArtifact,
			data:        []byte("not allowed"),
			diagnostics: []Diagnostic{diagnostic},
		},
		{
			name:     "failure no diagnostic",
			command:  CommandReview,
			ok:       false,
			exitCode: ExitCodeArtifact,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewCommandResult(test.command, test.ok, test.exitCode, test.data, test.diagnostics); err == nil {
				t.Fatal("NewCommandResult succeeded")
			}
		})
	}
}
func TestCommandResultRejectsUnrenderableSuccessData(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		data []byte
	}{
		{name: "nil"},
		{name: "empty"},
		{name: "malformed", data: []byte(`{`)},
		{name: "null", data: []byte(`null`)},
		{name: "array", data: []byte(`[]`)},
		{name: "duplicate keys", data: []byte(`{"kind":"first","kind":"second"}`)},
		{name: "nested duplicate keys", data: []byte(`{"result":{"kind":"first","kind":"second"}}`)},
		{name: "trailing value", data: []byte(`{}{}`)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewCommandSuccess(CommandReview, test.data); err == nil {
				t.Fatal("NewCommandSuccess succeeded")
			}
		})
	}
}

func TestCommandResultAcceptsEmptyJSONObjectSuccess(t *testing.T) {
	t.Parallel()

	result, err := NewCommandSuccess(CommandReview, []byte(`{}`))
	if err != nil {
		t.Fatalf("NewCommandSuccess() error = %v", err)
	}
	if got := string(result.Data()); got != `{}` {
		t.Fatalf("Data() = %q, want {}", got)
	}
}

func TestCommandResultDefensivelyOwnsDataAndDiagnostics(t *testing.T) {
	t.Parallel()

	data := []byte(`{"kind":"result data"}`)
	success, err := NewCommandSuccess(CommandStatus, data)
	if err != nil {
		t.Fatal(err)
	}
	data[2] = 'X'
	if got := string(success.Data()); got != `{"kind":"result data"}` {
		t.Fatalf("data after input mutation = %q", got)
	}
	returnedData := success.Data()
	returnedData[2] = 'Y'
	if got := string(success.Data()); got != `{"kind":"result data"}` {
		t.Fatalf("data after return mutation = %q", got)
	}
	if !success.OK() || success.ExitCode() != ExitCodeSuccess || success.Command() != CommandStatus {
		t.Fatalf("success = OK:%v exit:%d command:%q", success.OK(), success.ExitCode(), success.Command())
	}

	diagnostic := testDiagnostic(t)
	diagnostics := []Diagnostic{diagnostic}
	failure, err := NewCommandResult(CommandReview, false, ExitCodeSecurity, nil, diagnostics)
	if err != nil {
		t.Fatal(err)
	}
	diagnostics[0] = Diagnostic{}
	if got := failure.Diagnostics()[0].MachineCode(); got != "secret_detected" {
		t.Fatalf("diagnostic after input mutation = %q", got)
	}
	returnedDiagnostics := failure.Diagnostics()
	returnedDiagnostics[0] = Diagnostic{}
	if got := failure.Diagnostics()[0].MachineCode(); got != "secret_detected" {
		t.Fatalf("diagnostic after return mutation = %q", got)
	}
	if failure.OK() || failure.ExitCode() != ExitCodeSecurity || failure.Data() != nil {
		t.Fatalf("failure = OK:%v exit:%d data:%v", failure.OK(), failure.ExitCode(), failure.Data())
	}
}

func TestDiagnosticPreservesTypedFailureContext(t *testing.T) {
	t.Parallel()

	attempt, err := domain.ParseAttemptID("a_019f596a-cf80-7c67-b265-f37053d51ccf")
	if err != nil {
		t.Fatal(err)
	}
	diagnostic, err := NewDiagnostic(
		"secure.write",
		domain.FailureSecurityPolicy,
		"secret_detected",
		"untrusted bytes were dropped",
		"security",
		"kimi-main",
		attempt,
		".mulgae/diagnostics/secure-write.json",
		"mulgae doctor security",
	)
	if err != nil {
		t.Fatal(err)
	}
	if diagnostic.Stage() != "secure.write" || diagnostic.FailureClass() != domain.FailureSecurityPolicy {
		t.Fatalf("classification = %q/%q", diagnostic.Stage(), diagnostic.FailureClass())
	}
	if diagnostic.MachineCode() != "secret_detected" || diagnostic.Message() != "untrusted bytes were dropped" {
		t.Fatalf("reason = %q/%q", diagnostic.MachineCode(), diagnostic.Message())
	}
	if diagnostic.Role() != "security" || diagnostic.Provider() != "kimi-main" || diagnostic.AttemptID() != attempt {
		t.Fatalf("context = %q/%q/%q", diagnostic.Role(), diagnostic.Provider(), diagnostic.AttemptID().String())
	}
	// A security-policy failure is Mulgae's own refusal, not the provider's
	// fault, so it must not be advertised as worth retrying elsewhere.
	if diagnostic.ProviderFault() || diagnostic.Retryable() {
		t.Fatal("security failure was classified as a provider fault")
	}
	if diagnostic.ArtifactPath() != ".mulgae/diagnostics/secure-write.json" || diagnostic.RecommendedNextCommand() != "mulgae doctor security" {
		t.Fatalf("guidance = %q/%q", diagnostic.ArtifactPath(), diagnostic.RecommendedNextCommand())
	}
}

func TestNewDiagnosticRejectsIncompleteReason(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		stage        string
		failureClass domain.FailureClass
		machineCode  string
		message      string
	}{
		{name: "empty stage", failureClass: domain.FailureInternal, machineCode: "internal_error", message: "failed"},
		{name: "unknown class", stage: "app.result", failureClass: "unknown", machineCode: "internal_error", message: "failed"},
		{name: "empty machine code", stage: "app.result", failureClass: domain.FailureInternal, message: "failed"},
		{name: "invalid machine code", stage: "app.result", failureClass: domain.FailureInternal, machineCode: "InternalError", message: "failed"},
		{name: "empty message", stage: "app.result", failureClass: domain.FailureInternal, machineCode: "internal_error"},
		{name: "line break", stage: "app.result\nnext", failureClass: domain.FailureInternal, machineCode: "internal_error", message: "failed"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewDiagnostic(
				test.stage,
				test.failureClass,
				test.machineCode,
				test.message,
				"",
				"",
				domain.AttemptID{},
				"",
				"",
			)
			if err == nil {
				t.Fatal("NewDiagnostic succeeded")
			}
		})
	}
}

func testDiagnostic(t *testing.T) Diagnostic {
	t.Helper()
	diagnostic, err := NewDiagnostic(
		"provider.execute",
		domain.FailureSecurityPolicy,
		"secret_detected",
		strings.TrimSpace(" untrusted bytes were dropped "),
		"security",
		"kimi-main",
		domain.AttemptID{},
		".mulgae/diagnostics/provider.json",
		"mulgae doctor security",
	)
	if err != nil {
		t.Fatal(err)
	}
	return diagnostic
}
