package ports

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/domain"
)

func TestProcessExecutionErrorPreservesTypedPrimaryCauseAndSeparatedEvidence(t *testing.T) {
	underlying := errors.New("private adapter detail")
	failure, err := NewProcessExecutionError(
		domain.DiagnosticCauseProviderProcessWaitFailed,
		domain.DiagnosticCauseProcessGroupCleanupFailed,
		[]byte("stdout evidence"),
		[]byte("stderr evidence"),
		underlying,
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := failure.Error(); got != "process execution failed: provider_process_wait_failed" {
		t.Fatalf("safe error = %q", got)
	}
	if failure.PrimaryCause() != domain.DiagnosticCauseProviderProcessWaitFailed {
		t.Fatalf("primary cause = %q", failure.PrimaryCause())
	}
	if cleanup, ok := failure.CleanupCause(); !ok || cleanup != domain.DiagnosticCauseProcessGroupCleanupFailed {
		t.Fatalf("cleanup cause = %q, %t", cleanup, ok)
	}
	if !errors.Is(failure, underlying) {
		t.Fatal("underlying cause was not retained")
	}
	stdout := failure.Stdout()
	stderr := failure.Stderr()
	stdout[0], stderr[0] = 'X', 'X'
	if string(failure.Stdout()) != "stdout evidence" || string(failure.Stderr()) != "stderr evidence" {
		t.Fatal("process evidence was not defensively copied")
	}
	if _, err := NewProcessExecutionError(domain.DiagnosticCauseProviderProcessWaitFailed, domain.DiagnosticCauseOutputDecodeFailed, nil, nil, nil); err == nil {
		t.Fatal("non-cleanup supplemental cause accepted")
	}
}

func TestValidateProcessOutputFrameAllowsOnlyOneTerminalLF(t *testing.T) {
	for _, valid := range [][]byte{[]byte(`{"status":"ok"}`), []byte("{\"status\":\"ok\"}\n")} {
		if err := ValidateProcessOutputFrame(ProcessOutputFramingStrictJSON, valid); err != nil {
			t.Fatalf("valid provider JSON frame rejected: %q: %v", valid, err)
		}
	}
	for _, invalid := range [][]byte{[]byte(" {\"status\":\"ok\"}"), []byte("{\"status\":\"ok\"} "), []byte("{\"status\":\"ok\"}\n\n"), []byte("{\"status\":\"ok\"}\r\n")} {
		if err := ValidateProcessOutputFrame(ProcessOutputFramingStrictJSON, invalid); err == nil {
			t.Fatalf("noncanonical provider JSON frame accepted: %q", invalid)
		}
	}
}

func TestExtractProcessOutputJSONFrameSelectsTerminalObject(t *testing.T) {
	want := "{\n  \"root\": \"nonce\",\n  \"role\": \"logic\"\n}"
	for _, stdout := range [][]byte{
		[]byte("I inspected the immutable file.\n" + want + "\n"),
		[]byte("I inspected the immutable file.\n```json\n" + want + "\n```\n"),
	} {
		frame, err := ExtractProcessOutputJSONFrame(ProcessOutputFramingTerminalJSONObject, stdout)
		if err != nil || string(frame) != want {
			t.Fatalf("terminal JSON frame = %q, %v", frame, err)
		}
	}
	for _, invalid := range [][]byte{
		[]byte("narration without JSON\n"),
		[]byte("same-line {\"status\":\"ok\"}\n"),
		[]byte("{\"status\":\"ok\"}\ntrailing text\n"),
		[]byte("narration\n[1,2,3]\n"),
	} {
		if _, err := ExtractProcessOutputJSONFrame(ProcessOutputFramingTerminalJSONObject, invalid); err == nil {
			t.Fatalf("invalid terminal JSON frame accepted: %q", invalid)
		}
	}
}

func TestParseConcurrencyKeyNormalizesNFCAndASCIIcase(t *testing.T) {
	upper, err := ParseConcurrencyKey("KIMI-MAIN")
	if err != nil {
		t.Fatal(err)
	}
	lower, err := ParseConcurrencyKey("kimi-main")
	if err != nil {
		t.Fatal(err)
	}
	if upper != lower {
		t.Fatalf("normalized keys differ: %q and %q", upper, lower)
	}
	if got, want := upper.String(), "kimi-main"; got != want {
		t.Fatalf("String() = %q, want %q", got, want)
	}

	kelvin, err := ParseConcurrencyKey("\u212Aey")
	if err != nil {
		t.Fatalf("ParseConcurrencyKey() NFC canonical equivalent error = %v", err)
	}
	if got, want := kelvin.String(), "key"; got != want {
		t.Fatalf("NFC-normalized key = %q, want %q", got, want)
	}

	for _, value := range []string{"k\u00e9y", "ke\u0301y", string([]byte{'k', 0xff, 'y'})} {
		if _, err := ParseConcurrencyKey(value); err == nil {
			t.Errorf("ParseConcurrencyKey(%q) succeeded for non-ASCII input", value)
		}
	}
}

func TestParseConcurrencyKeyAcceptsOnlyCanonicalGrammarAfterNormalization(t *testing.T) {
	maximum := "a" + strings.Repeat("b", 62) + "z"
	for _, value := range []string{"a", "1", "a.b", "a_b", "a-b", maximum} {
		key, err := ParseConcurrencyKey(value)
		if err != nil {
			t.Errorf("ParseConcurrencyKey(%q) error = %v", value, err)
			continue
		}
		if !key.Valid() {
			t.Errorf("ParseConcurrencyKey(%q) produced invalid key", value)
		}
	}

	for _, value := range []string{
		"",
		".key",
		"-key",
		"_key",
		"key.",
		"key-",
		"key_",
		"key/part",
		"key part",
		" key",
		"key ",
		"key\npart",
		strings.Repeat("a", 65),
	} {
		if _, err := ParseConcurrencyKey(value); err == nil {
			t.Errorf("ParseConcurrencyKey(%q) succeeded", value)
		}
	}

	if (ConcurrencyKey{value: "KIMI"}).Valid() {
		t.Error("noncanonical manually constructed key is valid")
	}
}

func TestProviderRouteRetainsOnlySafeProviderIdentity(t *testing.T) {
	route, err := NewProviderRoute("kimi-main")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := route.ProviderInstance(), "kimi-main"; got != want {
		t.Fatalf("ProviderInstance() = %q, want %q", got, want)
	}
	if !route.Valid() {
		t.Fatal("valid route reports invalid")
	}

	for _, test := range []struct {
		name     string
		provider string
	}{
		{name: "empty provider", provider: ""},
		{name: "unsafe provider", provider: "Kimi Main"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewProviderRoute(test.provider); err == nil {
				t.Fatal("NewProviderRoute() succeeded")
			}
		})
	}
}

func TestEnvironmentVariableValidatesPortableNameAndNULFreeValue(t *testing.T) {
	variable, err := NewEnvironmentVariable("_MULGAE_1", "value=allowed")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := variable.Name(), "_MULGAE_1"; got != want {
		t.Fatalf("Name() = %q, want %q", got, want)
	}
	if got, want := variable.Value(), "value=allowed"; got != want {
		t.Fatalf("Value() = %q, want %q", got, want)
	}
	if !variable.Valid() {
		t.Fatal("valid environment variable reports invalid")
	}

	for _, test := range []struct {
		name  string
		value string
	}{
		{name: "", value: "value"},
		{name: "1Mulgae", value: "value"},
		{name: "Mulgae-NAME", value: "value"},
		{name: "Mulgae=NAME", value: "value"},
		{name: "K\u00c9Y", value: "value"},
		{name: "Mulgae", value: "value\x00suffix"},
	} {
		if _, err := NewEnvironmentVariable(test.name, test.value); err == nil {
			t.Errorf("NewEnvironmentVariable(%q, %q) succeeded", test.name, test.value)
		}
	}
}

func TestNewProcessRequestCopiesInputsAndCompletesEnvironment(t *testing.T) {
	key := schedulingTestConcurrencyKey(t)
	environment := []EnvironmentVariable{
		schedulingTestEnvironmentVariable(t, "ZED", "last"),
		schedulingTestEnvironmentVariable(t, "ALPHA", "first"),
	}
	argv := []string{"/usr/bin/provider", "--request", ""}
	stdin := []byte("request bytes")
	request, err := NewProcessRequest(
		"/usr/bin/provider",
		argv,
		environment,
		"/work",
		stdin,
		3*time.Second,
		1024,
		2048,
		key,
	)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := request.Executable(), "/usr/bin/provider"; got != want {
		t.Fatalf("Executable() = %q, want %q", got, want)
	}
	if got, want := request.WorkingDirectory(), "/work"; got != want {
		t.Fatalf("WorkingDirectory() = %q, want %q", got, want)
	}
	if got, want := request.Timeout(), 3*time.Second; got != want {
		t.Fatalf("Timeout() = %s, want %s", got, want)
	}
	if got, want := request.MaxStdoutBytes(), int64(1024); got != want {
		t.Fatalf("MaxStdoutBytes() = %d, want %d", got, want)
	}
	if got, want := request.MaxStderrBytes(), int64(2048); got != want {
		t.Fatalf("MaxStderrBytes() = %d, want %d", got, want)
	}
	if got := request.ConcurrencyKey(); got != key {
		t.Fatalf("ConcurrencyKey() = %q, want %q", got, key)
	}
	if !request.Valid() {
		t.Fatal("valid request reports invalid")
	}

	argv[1] = "--changed"
	environment[0] = schedulingTestEnvironmentVariable(t, "CHANGED", "changed")
	stdin[0] = 'x'
	if got, want := request.Argv(), []string{"/usr/bin/provider", "--request", ""}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Argv() after source mutation = %#v, want %#v", got, want)
	}
	if got, want := request.Environment(), []EnvironmentVariable{
		schedulingTestEnvironmentVariable(t, "ALPHA", "first"),
		schedulingTestEnvironmentVariable(t, "PWD", "/work"),
		schedulingTestEnvironmentVariable(t, "ZED", "last"),
	}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Environment() after source mutation = %#v, want %#v", got, want)
	}
	if got := request.Stdin(); !bytes.Equal(got, []byte("request bytes")) {
		t.Fatalf("Stdin() after source mutation = %q", got)
	}

	returnedArgv := request.Argv()
	returnedArgv[1] = "--mutated"
	returnedEnvironment := request.Environment()
	returnedEnvironment[0] = EnvironmentVariable{}
	returnedStdin := request.Stdin()
	returnedStdin[0] = 'y'
	if got := request.Argv()[1]; got != "--request" {
		t.Fatalf("Argv() after getter mutation = %q", got)
	}
	if got := request.Environment()[0].Name(); got != "ALPHA" {
		t.Fatalf("Environment() after getter mutation = %q", got)
	}
	if got := request.Stdin(); !bytes.Equal(got, []byte("request bytes")) {
		t.Fatalf("Stdin() after getter mutation = %q", got)
	}
}

func TestNewProcessRequestAcceptsMatchingPWDWithoutDuplication(t *testing.T) {
	input := schedulingValidProcessRequestInput(t)
	input.environment = []EnvironmentVariable{
		schedulingTestEnvironmentVariable(t, "ZED", "last"),
		schedulingTestEnvironmentVariable(t, "PWD", input.workingDirectory),
		schedulingTestEnvironmentVariable(t, "ALPHA", "first"),
	}

	request, err := input.new()
	if err != nil {
		t.Fatal(err)
	}
	if got, want := request.Environment(), []EnvironmentVariable{
		schedulingTestEnvironmentVariable(t, "ALPHA", "first"),
		schedulingTestEnvironmentVariable(t, "PWD", "/work"),
		schedulingTestEnvironmentVariable(t, "ZED", "last"),
	}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Environment() = %#v, want %#v", got, want)
	}
}
func TestProcessRequestValidRejectsMissingOrMismatchedPWD(t *testing.T) {
	input := schedulingValidProcessRequestInput(t)
	request, err := input.new()
	if err != nil {
		t.Fatal(err)
	}

	missing := request
	missing.environment = []EnvironmentVariable{
		schedulingTestEnvironmentVariable(t, "MULGAE_TOKEN", "redacted"),
	}
	if missing.Valid() {
		t.Fatal("request without effective PWD reports valid")
	}

	mismatched := request
	mismatched.environment = cloneEnvironmentVariables(request.environment)
	for index := range mismatched.environment {
		if mismatched.environment[index].name == "PWD" {
			mismatched.environment[index].value = "/other"
		}
	}
	if mismatched.Valid() {
		t.Fatal("request with mismatched effective PWD reports valid")
	}
}

func TestNewProcessRequestRejectsInvalidDirectExecutionInputs(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*schedulingProcessRequestInput)
	}{
		{name: "empty executable", change: func(input *schedulingProcessRequestInput) { input.executable = "" }},
		{name: "relative executable", change: func(input *schedulingProcessRequestInput) { input.executable = "provider" }},
		{name: "noncanonical executable", change: func(input *schedulingProcessRequestInput) { input.executable = "/usr/bin/../provider" }},
		{name: "NUL executable", change: func(input *schedulingProcessRequestInput) { input.executable = "/usr/bin/pro\x00vider" }},
		{name: "empty argv", change: func(input *schedulingProcessRequestInput) { input.argv = nil }},
		{name: "argv zero differs", change: func(input *schedulingProcessRequestInput) { input.argv[0] = "/usr/bin/other" }},
		{name: "NUL argv", change: func(input *schedulingProcessRequestInput) { input.argv[1] = "--bad\x00argument" }},
		{name: "relative working directory", change: func(input *schedulingProcessRequestInput) { input.workingDirectory = "work" }},
		{name: "NUL working directory", change: func(input *schedulingProcessRequestInput) { input.workingDirectory = "/work/\x00tmp" }},
		{name: "zero timeout", change: func(input *schedulingProcessRequestInput) { input.timeout = 0 }},
		{name: "negative timeout", change: func(input *schedulingProcessRequestInput) { input.timeout = -time.Second }},
		{name: "zero stdout cap", change: func(input *schedulingProcessRequestInput) { input.maxStdoutBytes = 0 }},
		{name: "negative stdout cap", change: func(input *schedulingProcessRequestInput) { input.maxStdoutBytes = -1 }},
		{name: "zero stderr cap", change: func(input *schedulingProcessRequestInput) { input.maxStderrBytes = 0 }},
		{name: "negative stderr cap", change: func(input *schedulingProcessRequestInput) { input.maxStderrBytes = -1 }},
		{name: "duplicate environment name", change: func(input *schedulingProcessRequestInput) {
			input.environment = []EnvironmentVariable{
				schedulingTestEnvironmentVariable(t, "ALPHA", "one"),
				schedulingTestEnvironmentVariable(t, "ALPHA", "two"),
			}
		}},
		{name: "invalid environment entry", change: func(input *schedulingProcessRequestInput) {
			input.environment = []EnvironmentVariable{{}}
		}},
		{name: "PWD differs from working directory", change: func(input *schedulingProcessRequestInput) {
			input.environment = append(input.environment, schedulingTestEnvironmentVariable(t, "PWD", "/other"))
		}},
		{name: "invalid concurrency key", change: func(input *schedulingProcessRequestInput) { input.concurrencyKey = ConcurrencyKey{} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := schedulingValidProcessRequestInput(t)
			test.change(&input)
			if _, err := input.new(); err == nil {
				t.Fatal("NewProcessRequest() succeeded")
			}
		})
	}
}

func TestStdinWriteReceiptBindsExactWriteFacts(t *testing.T) {
	successfullyWritten := []byte("written")
	receipt, err := NewStdinWriteReceipt(
		int64(len(successfullyWritten)+3),
		int64(len(successfullyWritten)),
		schedulingStdinWriteSHA256(successfullyWritten),
		false,
	)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.IntendedByteLength() != int64(len(successfullyWritten)+3) ||
		receipt.WrittenByteCount() != int64(len(successfullyWritten)) ||
		receipt.Complete() {
		t.Fatalf("receipt = %#v, want incomplete exact-write facts", receipt)
	}
	wantDigest := schedulingStdinWriteSHA256(successfullyWritten)
	if receipt.SHA256() != wantDigest {
		t.Fatalf("SHA256() = %q, want %q", receipt.SHA256(), wantDigest)
	}
	successfullyWritten[0] = 'X'
	if receipt.SHA256() != wantDigest || !receipt.Valid() {
		t.Fatal("receipt changed after source mutation")
	}

	zero := schedulingStdinReceipt(t, 0, 0)
	if !zero.Complete() || zero.WrittenByteCount() != 0 {
		t.Fatalf("zero-length receipt = %#v, want complete", zero)
	}

	for _, input := range []struct {
		intended int64
		written  int64
		digest   string
		complete bool
	}{
		{intended: -1, digest: wantDigest},
		{intended: 1, written: 2, digest: wantDigest},
		{intended: 1, written: 1, digest: "not-a-digest", complete: true},
		{intended: 1, written: 1, digest: wantDigest},
	} {
		if _, err := NewStdinWriteReceipt(input.intended, input.written, input.digest, input.complete); err == nil {
			t.Fatal("NewStdinWriteReceipt() accepted incoherent facts")
		}
	}
}

func TestProcessTerminationIsClosed(t *testing.T) {
	for _, termination := range []ProcessTermination{
		ProcessTerminationExited,
		ProcessTerminationSignaled,
		ProcessTerminationStartFailed,
		ProcessTerminationStartUnavailable,
		ProcessTerminationStartConfiguration,
		ProcessTerminationStartSecurity,
		ProcessTerminationTimedOut,
		ProcessTerminationCancelled,
		ProcessTerminationStdoutLimit,
		ProcessTerminationStderrLimit,
		ProcessTerminationStdinIncomplete,
		ProcessTerminationResidualProcessGroup,
		ProcessTerminationLockFailed,
		ProcessTerminationLockUnavailable,
		ProcessTerminationLockConfiguration,
		ProcessTerminationLockSecurity,
	} {
		if !termination.Valid() {
			t.Errorf("%q is invalid", termination)
		}
	}
	for _, termination := range []ProcessTermination{"", "killed", "Exited"} {
		if termination.Valid() {
			t.Errorf("%q is valid", termination)
		}
	}
}
func TestNewProcessSignalValidatesExactFacts(t *testing.T) {
	signal, err := NewProcessSignal(15, "SIGTERM")
	if err != nil {
		t.Fatal(err)
	}
	if !signal.Valid() || signal.Number() != 15 || signal.Name() != "SIGTERM" {
		t.Fatalf("signal = %#v", signal)
	}
	for _, test := range []struct {
		number int
		name   string
	}{
		{number: 0, name: "SIGTERM"},
		{number: 15, name: ""},
		{number: 15, name: "TERM"},
		{number: 15, name: "SIGterm"},
	} {
		if _, err := NewProcessSignal(test.number, test.name); err == nil {
			t.Fatalf("NewProcessSignal(%d, %q) succeeded", test.number, test.name)
		}
	}
}

func TestNewProcessObservationCopiesNeutralFacts(t *testing.T) {
	startedAt := time.Date(2026, time.July, 15, 12, 0, 0, 0, time.UTC)
	endedAt := startedAt.Add(time.Second)
	stdout := []byte("stdout")
	stderr := []byte("stderr")
	exitCode := 0
	observation, err := NewProcessObservation(
		stdout,
		stderr,
		&exitCode,
		ProcessTerminationExited,
		schedulingStdinReceipt(t, 0, 0),
		startedAt,
		endedAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	exitCode = 1
	stdout[0] = 'x'
	stderr[0] = 'y'
	if got := observation.Stdout(); !bytes.Equal(got, []byte("stdout")) {
		t.Fatalf("Stdout() after source mutation = %q", got)
	}
	if got := observation.Stderr(); !bytes.Equal(got, []byte("stderr")) {
		t.Fatalf("Stderr() after source mutation = %q", got)
	}
	returnedStdout := observation.Stdout()
	returnedStdout[0] = 'z'
	returnedStderr := observation.Stderr()
	returnedStderr[0] = 'z'
	if got := observation.Stdout(); !bytes.Equal(got, []byte("stdout")) {
		t.Fatalf("Stdout() after getter mutation = %q", got)
	}
	if got := observation.Stderr(); !bytes.Equal(got, []byte("stderr")) {
		t.Fatalf("Stderr() after getter mutation = %q", got)
	}
	if got, ok := observation.ExitCode(); !ok || got != 0 {
		t.Fatalf("ExitCode() = (%d, %t), want (0, true)", got, ok)
	}
	if _, _, ok := observation.Signal(); ok {
		t.Fatal("exited observation has a signal")
	}
	if got := observation.Termination(); got != ProcessTerminationExited {
		t.Fatalf("Termination() = %q, want %q", got, ProcessTerminationExited)
	}
	if got := observation.StartedAt(); !got.Equal(startedAt) || got.Location() != time.UTC {
		t.Fatalf("StartedAt() = %s (%s), want %s (UTC)", got, got.Location(), startedAt)
	}
	if got := observation.EndedAt(); !got.Equal(endedAt) || got.Location() != time.UTC {
		t.Fatalf("EndedAt() = %s (%s), want %s (UTC)", got, got.Location(), endedAt)
	}
	if !observation.Succeeded() {
		t.Fatal("zero exited process does not report success")
	}
	if !observation.Valid() {
		t.Fatal("valid observation reports invalid")
	}
}

func TestNewProcessObservationDistinguishesExitedAndNonExitedFacts(t *testing.T) {
	startedAt := time.Date(2026, time.July, 15, 12, 0, 0, 0, time.UTC)
	endedAt := startedAt.Add(time.Second)
	nonzeroExit := 7
	nonzero, err := NewProcessObservation(
		nil,
		nil,
		&nonzeroExit,
		ProcessTerminationExited,
		schedulingStdinReceipt(t, 0, 0),
		startedAt,
		endedAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	if nonzero.Succeeded() {
		t.Fatal("nonzero normal exit reports success")
	}
	signaledSignal, err := NewProcessSignal(15, "SIGTERM")
	if err != nil {
		t.Fatal(err)
	}
	signaled, err := NewProcessObservation(
		nil,
		nil,
		nil,
		ProcessTerminationSignaled,
		schedulingStdinReceipt(t, 0, 0),
		startedAt,
		endedAt,
		signaledSignal,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := signaled.ExitCode(); ok {
		t.Fatal("signaled observation has an exit code")
	}
	if number, name, ok := signaled.Signal(); !ok || number != 15 || name != "SIGTERM" {
		t.Fatalf("Signal() = (%d, %q, %t), want (15, %q, true)", number, name, ok, "SIGTERM")
	}
	if signaled.Succeeded() || !signaled.Valid() {
		t.Fatal("signaled observation does not preserve its neutral facts")
	}

	for _, termination := range []ProcessTermination{
		ProcessTerminationStartFailed,
		ProcessTerminationTimedOut,
		ProcessTerminationCancelled,
		ProcessTerminationStdoutLimit,
		ProcessTerminationStderrLimit,
		ProcessTerminationStdinIncomplete,
		ProcessTerminationLockFailed,
	} {
		observation, err := NewProcessObservation(
			nil,
			nil,
			nil,
			termination,
			schedulingStdinReceipt(t, 0, 0),
			startedAt,
			endedAt,
		)
		if err != nil {
			t.Errorf("NewProcessObservation(%q) error = %v", termination, err)
			continue
		}
		if _, ok := observation.ExitCode(); ok {
			t.Errorf("%q observation has an exit code", termination)
		}
		if _, _, ok := observation.Signal(); ok {
			t.Errorf("%q observation has a signal", termination)
		}
		if observation.Succeeded() {
			t.Errorf("%q observation reports success", termination)
		}
	}
}

func TestProcessObservationPostOutputEscalationAcceptsLeaderTerminatedByEarlierSignal(t *testing.T) {
	stdout := []byte(`{"status":"ok"}`)
	frame, err := NewProcessOutputFrameReceipt(ProcessOutputFramingTerminalJSONObject, stdout, time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	packet, err := NewProviderPacketFromBytes([]byte("packet"))
	if err != nil {
		t.Fatal(err)
	}
	term, err := NewProcessSignal(15, "SIGTERM")
	if err != nil {
		t.Fatal(err)
	}
	kill, err := NewProcessSignal(9, "SIGKILL")
	if err != nil {
		t.Fatal(err)
	}
	termRequest, err := NewAcceptedPostOutputProcessGroupSignalRequestReceipt(term, packet.Identity(), frame)
	if err != nil {
		t.Fatal(err)
	}
	killRequest, err := NewAcceptedPostOutputEscalationProcessGroupSignalRequestReceipt(kill, packet.Identity(), frame)
	if err != nil {
		t.Fatal(err)
	}
	final, err := NewSignaledProcessFinalTermination(term)
	if err != nil {
		t.Fatal(err)
	}
	lifecycle, err := NewProcessLifecycleReceipt(final, true, []ProcessGroupSignalRequestReceipt{termRequest, killRequest}, frame)
	if err != nil {
		t.Fatal(err)
	}
	startedAt := time.Date(2026, time.July, 27, 1, 0, 0, 0, time.UTC)
	observation, err := NewStartedProcessObservation(
		stdout,
		nil,
		ProcessTerminationSignaled,
		schedulingStdinReceipt(t, 0, 0),
		lifecycle,
		startedAt,
		startedAt.Add(time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}
	if !observation.Succeeded() {
		t.Fatal("leader terminated by accepted SIGTERM was rejected after descendant SIGKILL escalation")
	}
}

func TestNewProcessObservationRejectsIncoherentFacts(t *testing.T) {
	startedAt := time.Date(2026, time.July, 15, 12, 0, 0, 0, time.UTC)
	endedAt := startedAt.Add(time.Second)
	zero := 0
	negative := -1
	nonUTC := time.Date(2026, time.July, 15, 12, 0, 0, 0, time.FixedZone("UTC", 0))

	for _, test := range []struct {
		name        string
		exitCode    *int
		termination ProcessTermination
		startedAt   time.Time
		endedAt     time.Time
	}{
		{name: "unknown termination", exitCode: &zero, termination: ProcessTermination("unknown"), startedAt: startedAt, endedAt: endedAt},
		{name: "exited without code", termination: ProcessTerminationExited, startedAt: startedAt, endedAt: endedAt},
		{name: "negative exited code", exitCode: &negative, termination: ProcessTerminationExited, startedAt: startedAt, endedAt: endedAt},
		{name: "nonexited with code", exitCode: &zero, termination: ProcessTerminationTimedOut, startedAt: startedAt, endedAt: endedAt},
		{name: "zero start", exitCode: &zero, termination: ProcessTerminationExited, endedAt: endedAt},
		{name: "zero end", exitCode: &zero, termination: ProcessTerminationExited, startedAt: startedAt},
		{name: "non UTC start", exitCode: &zero, termination: ProcessTerminationExited, startedAt: nonUTC, endedAt: endedAt},
		{name: "end before start", exitCode: &zero, termination: ProcessTerminationExited, startedAt: endedAt, endedAt: startedAt},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewProcessObservation(
				nil,
				nil,
				test.exitCode,
				test.termination,
				schedulingStdinReceipt(t, 0, 0),
				test.startedAt,
				test.endedAt,
			); err == nil {
				t.Fatal("NewProcessObservation() succeeded")
			}
		})
	}
	if _, err := NewProcessObservation(
		nil,
		nil,
		&zero,
		ProcessTerminationExited,
		schedulingStdinReceipt(t, 1, 0),
		startedAt,
		endedAt,
	); err == nil {
		t.Fatal("NewProcessObservation() accepted incomplete stdin for normal completion")
	}
	signal, err := NewProcessSignal(9, "SIGKILL")
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name        string
		exitCode    *int
		termination ProcessTermination
		signals     []ProcessSignal
	}{
		{name: "exited with signal", exitCode: &zero, termination: ProcessTerminationExited, signals: []ProcessSignal{signal}},
		{name: "signaled without signal", termination: ProcessTerminationSignaled},
		{name: "signaled with invalid signal", termination: ProcessTerminationSignaled, signals: []ProcessSignal{{number: 0, name: "SIGTERM"}}},
		{name: "signaled with exit code", exitCode: &zero, termination: ProcessTerminationSignaled, signals: []ProcessSignal{signal}},
		{name: "other termination with signal", termination: ProcessTerminationTimedOut, signals: []ProcessSignal{signal}},
		{name: "multiple signals", termination: ProcessTerminationSignaled, signals: []ProcessSignal{signal, signal}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewProcessObservation(
				nil,
				nil,
				test.exitCode,
				test.termination,
				schedulingStdinReceipt(t, 0, 0),
				startedAt,
				endedAt,
				test.signals...,
			); err == nil {
				t.Fatal("NewProcessObservation() succeeded")
			}
		})
	}
}

func schedulingStdinReceipt(t *testing.T, intended, written int64) StdinWriteReceipt {
	t.Helper()
	if written < 0 || written > intended {
		t.Fatal("invalid scheduling stdin receipt test input")
	}
	receipt, err := NewStdinWriteReceipt(
		intended,
		written,
		schedulingStdinWriteSHA256(make([]byte, written)),
		written == intended,
	)
	if err != nil {
		t.Fatal(err)
	}
	return receipt
}

func schedulingStdinWriteSHA256(value []byte) string {
	hash := sha256.New()
	_, _ = hash.Write([]byte("Mulgae-PROVIDER-STDIN/1"))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write(value)
	return hex.EncodeToString(hash.Sum(nil))
}
func schedulingTestConcurrencyKey(t *testing.T) ConcurrencyKey {
	t.Helper()
	key, err := ParseConcurrencyKey("kimi-main")
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func schedulingTestEnvironmentVariable(t *testing.T, name, value string) EnvironmentVariable {
	t.Helper()
	variable, err := NewEnvironmentVariable(name, value)
	if err != nil {
		t.Fatal(err)
	}
	return variable
}

type schedulingProcessRequestInput struct {
	executable       string
	argv             []string
	environment      []EnvironmentVariable
	workingDirectory string
	stdin            []byte
	timeout          time.Duration
	maxStdoutBytes   int64
	maxStderrBytes   int64
	concurrencyKey   ConcurrencyKey
}

func schedulingValidProcessRequestInput(t *testing.T) schedulingProcessRequestInput {
	t.Helper()
	return schedulingProcessRequestInput{
		executable:       "/usr/bin/provider",
		argv:             []string{"/usr/bin/provider", "--request"},
		environment:      []EnvironmentVariable{schedulingTestEnvironmentVariable(t, "MULGAE_TOKEN", "redacted")},
		workingDirectory: "/work",
		stdin:            []byte("stdin"),
		timeout:          time.Second,
		maxStdoutBytes:   1,
		maxStderrBytes:   1,
		concurrencyKey:   schedulingTestConcurrencyKey(t),
	}
}

func (input schedulingProcessRequestInput) new() (ProcessRequest, error) {
	return NewProcessRequest(
		input.executable,
		input.argv,
		input.environment,
		input.workingDirectory,
		input.stdin,
		input.timeout,
		input.maxStdoutBytes,
		input.maxStderrBytes,
		input.concurrencyKey,
	)
}

var (
	_ ProcessRunner = schedulingProcessRunnerStub{}
)

type schedulingProcessRunnerStub struct{}

func (schedulingProcessRunnerStub) Run(context.Context, ProcessRequest) (ProcessObservation, error) {
	return ProcessObservation{}, nil
}

func TestNewProviderProcessRequestEnforcesOnePacketChannel(t *testing.T) {
	packet := schedulingTestPacket(t, []byte("packet"))
	key := schedulingTestConcurrencyKey(t)
	newRequest := func(binding ProviderPacketBinding, argv []string, workingDirectory string) (ProcessRequest, error) {
		return NewProviderProcessRequest(
			"/usr/bin/provider", argv, nil, workingDirectory, binding,
			time.Second, 1024, 1024, key,
		)
	}
	argvBinding, err := NewArgvLiteralProviderPacketBinding(packet, 1)
	if err != nil {
		t.Fatal(err)
	}
	stdinBinding, err := NewStdinProviderPacketBinding(packet)
	if err != nil {
		t.Fatal(err)
	}
	fileBinding, err := NewPromptFileProviderPacketBinding(packet, 1, "@prompt/request.json", "/work")
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name       string
		binding    ProviderPacketBinding
		argv       []string
		workingDir string
		wantStdin  []byte
		wantError  bool
	}{
		{name: "argv exactly once", binding: argvBinding, argv: []string{"/usr/bin/provider", "packet"}, workingDir: "/work"},
		{name: "stdin exactly once", binding: stdinBinding, argv: []string{"/usr/bin/provider", "--request"}, workingDir: "/work", wantStdin: []byte("packet")},
		{name: "prompt file exactly once", binding: fileBinding, argv: []string{"/usr/bin/provider", "@prompt/request.json"}, workingDir: "/work"},
		{name: "argv missing packet", binding: argvBinding, argv: []string{"/usr/bin/provider", "--request"}, workingDir: "/work", wantError: true},
		{name: "argv wrong index", binding: argvBinding, argv: []string{"packet", "/usr/bin/provider"}, workingDir: "/work", wantError: true},
		{name: "argv duplicate packet", binding: argvBinding, argv: []string{"/usr/bin/provider", "packet", "packet"}, workingDir: "/work", wantError: true},
		{name: "stdin packet duplicated in argv", binding: stdinBinding, argv: []string{"/usr/bin/provider", "packet"}, workingDir: "/work", wantError: true},
		{name: "prompt file duplicate reference", binding: fileBinding, argv: []string{"/usr/bin/provider", "@prompt/request.json", "@prompt/request.json"}, workingDir: "/work", wantError: true},
		{name: "prompt file literal packet", binding: fileBinding, argv: []string{"/usr/bin/provider", "@prompt/request.json", "packet"}, workingDir: "/work", wantError: true},
		{name: "prompt file cwd mismatch", binding: fileBinding, argv: []string{"/usr/bin/provider", "@prompt/request.json"}, workingDir: "/other", wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			request, err := newRequest(test.binding, test.argv, test.workingDir)
			if test.wantError {
				if err == nil {
					t.Fatal("NewProviderProcessRequest() succeeded")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := request.Stdin(); !bytes.Equal(got, test.wantStdin) {
				t.Fatalf("Stdin() = %q, want %q", got, test.wantStdin)
			}
		})
	}

	nulPacket, err := NewProviderPacket([]byte("packet\x00suffix"), schedulingStdinWriteSHA256([]byte("packet\x00suffix")))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewArgvLiteralProviderPacketBinding(nulPacket, 1); err == nil {
		t.Fatal("NewArgvLiteralProviderPacketBinding() accepted NUL packet")
	}
	for _, reference := range []string{"@prompt/request.json", "@/absolute", "@../traversal", "@prompt/../request", "@prompt\x00file"} {
		_, err := NewPromptFileProviderPacketBinding(packet, 1, reference, "/work")
		if (reference == "@prompt/request.json") != (err == nil) {
			t.Errorf("NewPromptFileProviderPacketBinding(%q) error = %v", reference, err)
		}
	}
}

func TestProviderRunTerminalReceiptCanonicalizesAndCopies(t *testing.T) {
	alpha := schedulingTerminalReceipt(t, "alpha-main", "generation-a")
	zeta := schedulingTerminalReceipt(t, "zeta-main", "generation-z")
	input := []ProviderNamespaceTerminalReceipt{zeta, alpha}
	receipt, err := NewProviderRunTerminalReceipt(input)
	if err != nil {
		t.Fatal(err)
	}
	if !receipt.Valid() {
		t.Fatal("aggregate receipt reports invalid")
	}
	input[0] = ProviderNamespaceTerminalReceipt{}
	got := receipt.NamespaceReceipts()
	if len(got) != 2 || got[0] != alpha || got[1] != zeta {
		t.Fatalf("canonical receipts = %#v", got)
	}
	got[0] = ProviderNamespaceTerminalReceipt{}
	if receipt.NamespaceReceipts()[0] != alpha {
		t.Fatal("aggregate receipt exposed internal storage")
	}
}

func TestProviderRunTerminalReceiptRejectsEmptyDuplicateAndInvalid(t *testing.T) {
	valid := schedulingTerminalReceipt(t, "alpha-main", "generation-a")
	if _, err := NewProviderRunTerminalReceipt(nil); err == nil {
		t.Fatal("empty aggregate accepted")
	}
	if _, err := NewProviderRunTerminalReceipt([]ProviderNamespaceTerminalReceipt{valid, valid}); err == nil {
		t.Fatal("duplicate provider instance accepted")
	}
	if _, err := NewProviderRunTerminalReceipt([]ProviderNamespaceTerminalReceipt{{}}); err == nil {
		t.Fatal("invalid namespace receipt accepted")
	}
}
func schedulingTestPacket(t *testing.T, bytes []byte) ProviderPacket {
	t.Helper()
	packet, err := NewProviderPacket(bytes, schedulingStdinWriteSHA256(bytes))
	if err != nil {
		t.Fatal(err)
	}
	return packet
}

type testCredentialSourceAuthority struct{}

func (testCredentialSourceAuthority) ValidateCredentialSource(int64, os.FileMode, string) error {
	return nil
}

func TestCredentialProjectionRequestAuthority(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "credential")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	digest := fmt.Sprintf("%064x", 1)
	request, err := NewCredentialProjectionRequestWithAuthority(
		"provider", "generation", file.Name(), file, digest, 0, 0600,
		CredentialProjectionZCodeConfig, testCredentialSourceAuthority{},
	)
	if err != nil {
		t.Fatal(err)
	}
	if request.SourceAuthority() == nil {
		t.Fatal("authority was not retained")
	}
}
func TestNewAcceptedProcessGroupSignalRequestReceiptRestrictsReasons(t *testing.T) {
	signal, err := NewProcessSignal(15, "SIGTERM")
	if err != nil {
		t.Fatal(err)
	}

	for _, reason := range []ProcessGroupSignalRequestReason{
		ProcessGroupSignalRequestCancellation,
		ProcessGroupSignalRequestTimeout,
		ProcessGroupSignalRequestStdoutLimit,
		ProcessGroupSignalRequestStderrLimit,
		ProcessGroupSignalRequestStdinIncomplete,
		ProcessGroupSignalRequestResidualGroup,
		ProcessGroupSignalRequestInternalTeardown,
	} {
		receipt, err := NewAcceptedProcessGroupSignalRequestReceipt(reason, signal)
		if err != nil {
			t.Fatalf("NewAcceptedProcessGroupSignalRequestReceipt(%q): %v", reason, err)
		}
		if !receipt.Valid() || receipt.Reason() != reason {
			t.Fatalf("receipt for %q = %#v", reason, receipt)
		}
	}

	for _, reason := range []ProcessGroupSignalRequestReason{
		"",
		"arbitrary",
		ProcessGroupSignalRequestPostOutput,
		ProcessGroupSignalRequestPostOutputEscalation,
	} {
		if _, err := NewAcceptedProcessGroupSignalRequestReceipt(reason, signal); err == nil {
			t.Fatalf("NewAcceptedProcessGroupSignalRequestReceipt(%q) succeeded", reason)
		}
	}
}
func schedulingTerminalReceipt(t *testing.T, instance, generation string) ProviderNamespaceTerminalReceipt {
	t.Helper()
	var lease *schedulingTerminalLease
	acquired, err := AcquireProviderNamespaceLease(context.Background(), instance, func(_ context.Context, _ string, binding ProviderNamespaceTerminalBinding) (ProviderNamespaceLease, error) {
		lease = &schedulingTerminalLease{instance: instance, generation: generation}
		drain, err := binding.Bind(generation, func(context.Context) error { return nil })
		if err != nil {
			return nil, err
		}
		lease.drain = drain
		return lease, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := acquired.DrainTerminal(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return receipt
}

type schedulingTerminalLease struct {
	instance   string
	generation string
	drain      ProviderNamespaceTerminalDrain
}

func (lease *schedulingTerminalLease) ProviderInstance() string { return lease.instance }
func (lease *schedulingTerminalLease) Generation() string       { return lease.generation }
func (*schedulingTerminalLease) Environment() []EnvironmentVariable {
	return nil
}
func (*schedulingTerminalLease) ProjectCredential(context.Context, CredentialProjectionRequest) (CredentialProjectionReceipt, error) {
	return CredentialProjectionReceipt{}, errors.New("unexpected credential projection")
}
func (*schedulingTerminalLease) ValidateForSpawn() error { return nil }
func (lease *schedulingTerminalLease) DrainTerminal(ctx context.Context) (ProviderNamespaceTerminalReceipt, error) {
	return lease.drain(ctx)
}
