//go:build darwin && arm64 && vm_qualification

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/artifactwire"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

const (
	vmLossResourceSpecJSON        = `{"schema":"haepari.resource/v1","id":"mulgae-review","kind":"lock","capacity":1,"liveness_seconds":12,"max_hold_seconds":21600}`
	vmMaxHoldLossResourceSpecJSON = `{"schema":"haepari.resource/v1","id":"mulgae-review","kind":"lock","capacity":1,"liveness_seconds":6,"max_hold_seconds":10}`
)

type vmLossCaseFixture struct {
	name           string
	caseDir        string
	controllerHome string
	project        string
	providers      string
	barrier        string
	environment    []string
	controller     *vmController
}

// vmNativeLossScenarios exercises caller cancellation, borrowed parent
// liveness expiry, mid-run controller loss, and owned max-hold expiry against
// real per-case foreground Haepari controllers backed by native SQLite state.
func vmNativeLossScenarios(t *testing.T, ctx context.Context, root, haepari, binary, work string, environment []string) {
	t.Helper()

	results := map[string]any{
		"schema": "mulgae.vm-native-loss-qualification/v1",
	}

	t.Run("caller_cancellation", func(t *testing.T) {
		results["caller_cancellation"] = vmRunCallerCancellationLossCase(t, ctx, root, haepari, binary, work, environment)
	})
	t.Run("borrowed_parent_liveness_expiry", func(t *testing.T) {
		results["borrowed_parent_liveness_expiry"] = vmRunBorrowedLivenessExpiryLossCase(t, ctx, root, haepari, binary, work, environment)
	})
	t.Run("controller_loss_owned_review", func(t *testing.T) {
		results["controller_loss_owned_review"] = vmRunControllerLossOwnedReviewCase(t, ctx, root, haepari, binary, work, environment)
	})
	t.Run("owned_max_hold_expiry", func(t *testing.T) {
		results["owned_max_hold_expiry"] = vmRunOwnedMaxHoldExpiryLossCase(t, ctx, root, haepari, binary, work, environment)
	})
	t.Run("abrupt_caller_loss_unverified_drain", func(t *testing.T) {
		results["abrupt_caller_loss_unverified_drain"] = vmRunAbruptCallerLossUnverifiedDrainCase(t, ctx, root, haepari, binary, work, environment)
	})

	vmWriteJSON(t, filepath.Join(work, "loss-scenarios-result.json"), results)
}

func vmSetupLossCase(t *testing.T, parentCtx context.Context, root, haepari, binary, work, name string, environment []string) (*vmLossCaseFixture, context.Context) {
	t.Helper()
	return vmSetupLossCaseWithResource(t, parentCtx, root, haepari, binary, work, name, vmLossResourceSpecJSON, environment)
}

func vmSetupLossCaseWithResource(t *testing.T, parentCtx context.Context, root, haepari, binary, work, name, resourceSpecJSON string, environment []string) (*vmLossCaseFixture, context.Context) {
	t.Helper()

	caseDir := filepath.Join(work, "loss-"+name)
	controllerHome := filepath.Join(caseDir, "controller")
	project := filepath.Join(caseDir, "project")
	providers := filepath.Join(caseDir, "providers")
	barrier := filepath.Join(caseDir, "barrier")
	for _, dir := range []string{caseDir, controllerHome, project, providers, barrier} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	controllerIdentity, err := os.Stat(controllerHome)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		current, statErr := os.Stat(controllerHome)
		if statErr != nil || !os.SameFile(current, controllerIdentity) {
			t.Errorf("case %s controller root identity changed; cleanup refused", name)
			return
		}
		if removeErr := os.RemoveAll(controllerHome); removeErr != nil {
			t.Error(removeErr)
		}
	})

	bundle, node, launcher := fakeZCodeAppPaths(providers)
	logPath := filepath.Join(caseDir, "provider.jsonl")
	buildFakeZCodeWithReport(t, root, node, launcher, logPath, "wait_review", barrier, fakeZCodeReportTemplate)
	initializeReviewGitRepository(t, project)
	runTestCommand(t, project, "git", "add", "review.go")
	runTestCommand(t, project, "git", "-c", "user.name=Mulgae VM", "-c", "user.email=mulgae-vm@example.invalid", "commit", "-m", "review target")

	caseCtx, cancel := context.WithTimeout(parentCtx, 60*time.Second)
	t.Cleanup(cancel)

	caseEnv := vmZCodeToolsEnvironment(withHaepariHome(environment, controllerHome), node, launcher)
	controller := vmStartController(t, caseCtx, haepari, controllerHome, caseEnv)

	resourceFile := filepath.Join(caseDir, "review-resource.json")
	mustWriteTestFile(t, resourceFile, []byte(resourceSpecJSON))
	vmHaepari(t, haepari, caseDir, caseEnv, "resource", "register", "--file", resourceFile, "--json")
	if _, err := os.Stat(filepath.Join(controllerHome, "state.sqlite")); err != nil {
		t.Fatalf("case %s controller did not create SQLite state: %v", name, err)
	}

	initializeOfflineProvidersForRoles(t, binary, project, caseEnv, "zcode", "logic", bundle)

	return &vmLossCaseFixture{
		name:           name,
		caseDir:        caseDir,
		controllerHome: controllerHome,
		project:        project,
		providers:      providers,
		barrier:        barrier,
		environment:    caseEnv,
		controller:     controller,
	}, caseCtx
}

func vmStartControlledWaitReview(t *testing.T, ctx context.Context, binary, project, barrier string, environment []string, label string) (*runningBinary, int, func() binaryResult) {
	t.Helper()

	running := startMulgaeBinaryWithEnv(t, ctx, binary, project, environment, "review", "--head", "--roles", "logic", "--output", "json")
	waited := false
	var cached binaryResult
	waitOnce := func() binaryResult {
		t.Helper()
		if !waited {
			waited = true
			cached = waitMulgaeBinary(t, running)
		}
		return cached
	}
	t.Cleanup(func() {
		if !waited && running != nil && running.command != nil && running.command.Process != nil {
			_ = running.command.Process.Kill()
			_ = waitOnce()
		}
	})

	var readyFile string
	vmWaitFor(t, ctx, func() bool {
		matches, _ := filepath.Glob(filepath.Join(barrier, "*.ready"))
		if len(matches) == 1 {
			readyFile = matches[0]
			return true
		}
		return false
	}, label+" provider readiness marker")

	pidText := strings.TrimSuffix(filepath.Base(readyFile), ".ready")
	pid, err := strconv.Atoi(pidText)
	if err != nil || pid <= 1 {
		t.Fatalf("%s invalid provider PID marker %q: %v", label, readyFile, err)
	}
	if err := syscall.Kill(pid, 0); err != nil {
		t.Fatalf("%s provider PID %d is not live at barrier: %v", label, pid, err)
	}
	if err := os.WriteFile(filepath.Join(barrier, "release.ready"), []byte("release"), 0o600); err != nil {
		t.Fatal(err)
	}
	return running, pid, waitOnce
}

func vmAssertProviderPIDGone(t *testing.T, ctx context.Context, pid int, label string) {
	t.Helper()
	vmWaitFor(t, ctx, func() bool {
		err := syscall.Kill(pid, 0)
		return errors.Is(err, syscall.ESRCH)
	}, label+" provider PID exit")
}

func vmReadLockIntentBytes(t *testing.T, project, sessionID, runID string) []byte {
	t.Helper()
	path := filepath.Join(project, ".mulgae", artifactwire.DiagnosticHaepariLockIntentPath(sessionID, runID))
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return data
}

func vmRunCallerCancellationLossCase(t *testing.T, parentCtx context.Context, root, haepari, binary, work string, environment []string) map[string]any {
	t.Helper()

	fixture, ctx := vmSetupLossCase(t, parentCtx, root, haepari, binary, work, "caller-cancel", environment)
	defer fixture.controller.stop(t)

	running, providerPID, waitReview := vmStartControlledWaitReview(t, ctx, binary, fixture.project, fixture.barrier, fixture.environment, "caller-cancel")
	if err := running.command.Process.Signal(os.Interrupt); err != nil {
		t.Fatalf("signal caller cancellation: %v", err)
	}
	result := waitReview()
	if result.exitCode == 0 {
		t.Fatalf("caller-cancelled review unexpectedly succeeded: %s", result.stdout)
	}
	vmAssertProviderPIDGone(t, ctx, providerPID, "caller-cancel")

	var envelope commandEnvelope
	if err := json.Unmarshal(result.stdout, &envelope); err != nil || envelope.Result.SessionID == nil || envelope.Result.RunID == nil {
		t.Fatalf("caller-cancel envelope: exit=%d stdout=%s err=%v", result.exitCode, result.stdout, err)
	}
	sessionID, runID := *envelope.Result.SessionID, *envelope.Result.RunID
	if commandEnvelopeHasReason(envelope, string(domain.DiagnosticCauseCoordinationDrainUnverified)) {
		t.Fatalf("caller-cancel reported unverified drain despite physical provider exit: %#v", envelope.Reasons)
	}
	diagLog := readRuntimeDiagnosticLog(t, fixture.project, sessionID, runID)
	if bytes.Contains(diagLog, []byte(domain.DiagnosticCauseCoordinationDrainUnverified)) {
		t.Fatalf("caller-cancel runtime log recorded unverified drain:\n%s", diagLog)
	}
	if envelope.Exit.Kind != "cancelled" &&
		!commandEnvelopeHasReason(envelope, string(domain.DiagnosticCauseCoordinationCancelled)) &&
		!bytes.Contains(diagLog, []byte(domain.DiagnosticProcessCancelled)) &&
		!bytes.Contains(diagLog, []byte(domain.DiagnosticCauseCoordinationCancelled)) {
		t.Fatalf("caller-cancel missing typed cancellation cause: envelope=%#v\nlog=%s", envelope, diagLog)
	}

	rawIntent := vmReadLockIntentBytes(t, fixture.project, sessionID, runID)
	var intent artifactwire.HaepariLockIntentWireV2
	if err := json.Unmarshal(rawIntent, &intent); err != nil {
		t.Fatalf("decode caller-cancel v2 lock intent: %v", err)
	}
	if intent.SchemaVersion != artifactwire.HaepariLockIntentSchemaV2 || intent.LocalDrainState != string(ports.ReviewLocalDrainVerified) {
		t.Fatalf("caller-cancel lock intent = %+v, want schema=%s local_drain_state=verified", intent, artifactwire.HaepariLockIntentSchemaV2)
	}

	return map[string]any{
		"session_id":        sessionID,
		"run_id":            runID,
		"provider_pid":      providerPID,
		"exit_code":         result.exitCode,
		"exit_kind":         envelope.Exit.Kind,
		"schema_version":    intent.SchemaVersion,
		"local_drain_state": intent.LocalDrainState,
	}
}

func vmRunBorrowedLivenessExpiryLossCase(t *testing.T, parentCtx context.Context, root, haepari, binary, work string, environment []string) map[string]any {
	t.Helper()

	fixture, ctx := vmSetupLossCase(t, parentCtx, root, haepari, binary, work, "borrowed-expiry", environment)
	defer fixture.controller.stop(t)

	acquired := vmHaepari(t, haepari, fixture.caseDir, fixture.environment, "lock", "acquire", "mulgae-review",
		"--request-key", "loss-borrowed-parent", "--holder", "guest-loss-parent", "--json")
	parent, ok := acquired["current"].(map[string]any)
	if !ok || parent["state"] != "granted" {
		t.Fatalf("borrowed-expiry parent was not granted: %v", acquired)
	}
	grantID := parent["grant_id"].(string)
	parentRequestID := parent["request_id"].(string)
	parentGeneration := int64(parent["generation"].(float64))

	borrowedWire := artifactwire.HaepariBorrowedGrantWire{
		InstallationID: parent["installation_id"].(string),
		LockID:         "mulgae-review",
		GrantID:        grantID,
		Generation:     parentGeneration,
	}
	rawGrant, err := json.Marshal(borrowedWire)
	if err != nil {
		t.Fatal(err)
	}
	borrowedEnv := append(append([]string{}, fixture.environment...), "HAEPARI_LOCK_GRANT="+string(rawGrant))

	_, providerPID, waitReview := vmStartControlledWaitReview(t, ctx, binary, fixture.project, fixture.barrier, borrowedEnv, "borrowed-expiry")
	result := waitReview()
	if result.exitCode == 0 {
		t.Fatalf("borrowed-expiry child review unexpectedly succeeded after lease expiry: %s", result.stdout)
	}
	vmAssertProviderPIDGone(t, ctx, providerPID, "borrowed-expiry")

	var envelope commandEnvelope
	if err := json.Unmarshal(result.stdout, &envelope); err != nil || envelope.Result.SessionID == nil || envelope.Result.RunID == nil {
		t.Fatalf("borrowed-expiry envelope: exit=%d stdout=%s err=%v", result.exitCode, result.stdout, err)
	}
	sessionID, runID := *envelope.Result.SessionID, *envelope.Result.RunID
	diagLog := readRuntimeDiagnosticLog(t, fixture.project, sessionID, runID)
	if !commandEnvelopeHasReason(envelope, string(domain.DiagnosticCauseCoordinationProtectionLost)) &&
		!bytes.Contains(diagLog, []byte(domain.DiagnosticCauseCoordinationProtectionLost)) {
		t.Fatalf("borrowed-expiry did not report haepari_protection_lost: envelope=%#v\nlog=%s", envelope, diagLog)
	}
	if commandEnvelopeHasReason(envelope, string(domain.DiagnosticCauseCoordinationDrainUnverified)) ||
		bytes.Contains(diagLog, []byte(domain.DiagnosticCauseCoordinationDrainUnverified)) {
		t.Fatalf("borrowed-expiry reported unverified drain despite physical provider exit: envelope=%#v", envelope.Reasons)
	}

	rawIntent := vmReadLockIntentBytes(t, fixture.project, sessionID, runID)
	var intent artifactwire.HaepariLockIntentWireV3
	if err := json.Unmarshal(rawIntent, &intent); err != nil {
		t.Fatalf("decode borrowed-expiry v3 lock intent: %v", err)
	}
	if intent.SchemaVersion != artifactwire.HaepariLockIntentSchemaV3 ||
		intent.LocalDrainState != string(ports.ReviewLocalDrainVerified) ||
		intent.BorrowedGrant != borrowedWire {
		t.Fatalf("borrowed-expiry v3 intent mismatch: %+v", intent)
	}

	page := vmHaepari(t, haepari, fixture.caseDir, fixture.environment, "locks", "list", "--lock", "mulgae-review", "--json")
	var parentAfter map[string]any
	for _, item := range page["requests"].([]any) {
		row := item.(map[string]any)
		if row["request_id"] == parentRequestID {
			parentAfter = row
		}
	}
	if parentAfter == nil {
		t.Fatal("borrowed-expiry parent request missing from native controller inventory")
	}
	if int64(parentAfter["generation"].(float64)) != parentGeneration ||
		parentAfter["grant_id"] != parent["grant_id"] ||
		parentAfter["liveness_deadline"] != parent["liveness_deadline"] ||
		parentAfter["max_hold_deadline"] != parent["max_hold_deadline"] ||
		parentAfter["state"] == "released" || parentAfter["state"] == "cancelled" {
		t.Fatalf("borrower mutated parent renew/release/cancel state: before=%v after=%v", parent, parentAfter)
	}

	// Reuse the already-expired parent grant to verify borrower admission
	// rejection on an expired grant without adding a second liveness wait.
	readyBefore, _ := filepath.Glob(filepath.Join(fixture.barrier, "*.ready"))
	expiredRejected := runMulgaeBinaryWithEnv(t, binary, fixture.project, borrowedEnv, "review", "--head", "--roles", "logic", "--output", "json")
	var expiredEnv commandEnvelope
	if err := json.Unmarshal(expiredRejected.stdout, &expiredEnv); err != nil || expiredRejected.exitCode == 0 ||
		!commandEnvelopeHasReason(expiredEnv, string(domain.DiagnosticCauseCoordinationReadinessFailed)) {
		t.Fatalf("expired borrower admission was not refused with haepari_readiness_failed: exit=%d stdout=%s err=%v",
			expiredRejected.exitCode, expiredRejected.stdout, err)
	}
	readyAfter, _ := filepath.Glob(filepath.Join(fixture.barrier, "*.ready"))
	if len(readyAfter) != len(readyBefore) {
		t.Fatalf("expired borrower admission invoked provider (%d -> %d)", len(readyBefore), len(readyAfter))
	}

	// Synthetic parent owner cleanup is performed only after child termination and verification.
	if parentAfter["state"] == "granted" {
		_ = runMulgaeBinaryWithEnv(t, haepari, fixture.caseDir, fixture.environment, "lock", "release", grantID, "--json")
	}

	return map[string]any{
		"session_id":                    sessionID,
		"run_id":                        runID,
		"provider_pid":                  providerPID,
		"exit_code":                     result.exitCode,
		"schema_version":                intent.SchemaVersion,
		"local_drain_state":             intent.LocalDrainState,
		"parent_state":                  parentAfter["state"],
		"parent_generation":             parentGeneration,
		"expired_admission_refused":     true,
		"expired_admission_reason_code": string(domain.DiagnosticCauseCoordinationReadinessFailed),
	}
}

func vmRunControllerLossOwnedReviewCase(t *testing.T, parentCtx context.Context, root, haepari, binary, work string, environment []string) map[string]any {
	t.Helper()

	fixture, ctx := vmSetupLossCase(t, parentCtx, root, haepari, binary, work, "controller-loss", environment)
	defer fixture.controller.stop(t)

	_, providerPID, waitReview := vmStartControlledWaitReview(t, ctx, binary, fixture.project, fixture.barrier, fixture.environment, "controller-loss")
	fixture.controller.stop(t)

	result := waitReview()
	if result.exitCode == 0 {
		t.Fatalf("controller-loss review unexpectedly succeeded after daemon stop: %s", result.stdout)
	}
	vmAssertProviderPIDGone(t, ctx, providerPID, "controller-loss")

	var envelope commandEnvelope
	if err := json.Unmarshal(result.stdout, &envelope); err != nil || envelope.Result.SessionID == nil || envelope.Result.RunID == nil {
		t.Fatalf("controller-loss envelope: exit=%d stdout=%s err=%v", result.exitCode, result.stdout, err)
	}
	sessionID, runID := *envelope.Result.SessionID, *envelope.Result.RunID
	diagLog := readRuntimeDiagnosticLog(t, fixture.project, sessionID, runID)
	hasProtectionOrDispositionCause := commandEnvelopeHasReason(envelope, string(domain.DiagnosticCauseCoordinationProtectionLost)) ||
		commandEnvelopeHasReason(envelope, string(domain.DiagnosticCauseCoordinationDispositionFailed)) ||
		bytes.Contains(diagLog, []byte(domain.DiagnosticCauseCoordinationProtectionLost)) ||
		bytes.Contains(diagLog, []byte(domain.DiagnosticCauseCoordinationDispositionFailed))
	if !hasProtectionOrDispositionCause {
		t.Fatalf("controller-loss did not record protection/disposition failure cause: envelope=%#v\nlog=%s", envelope, diagLog)
	}
	if commandEnvelopeHasReason(envelope, string(domain.DiagnosticCauseCoordinationDrainUnverified)) ||
		bytes.Contains(diagLog, []byte(domain.DiagnosticCauseCoordinationDrainUnverified)) {
		t.Fatalf("controller-loss reported unverified drain despite physical provider exit: envelope=%#v", envelope.Reasons)
	}

	rawIntent := vmReadLockIntentBytes(t, fixture.project, sessionID, runID)
	var intent artifactwire.HaepariLockIntentWireV2
	if err := json.Unmarshal(rawIntent, &intent); err != nil {
		t.Fatalf("decode controller-loss v2 lock intent: %v", err)
	}
	if intent.SchemaVersion != artifactwire.HaepariLockIntentSchemaV2 ||
		intent.LocalDrainState != string(ports.ReviewLocalDrainVerified) ||
		intent.ObservedRequest == nil ||
		intent.ObservedRequest.State != string(ports.ReviewLockStateGranted) {
		t.Fatalf("controller-loss v2 intent did not preserve verified local drain and unconfirmed native disposition: %+v", intent)
	}

	restarted := vmStartController(t, ctx, haepari, fixture.controllerHome, fixture.environment)
	defer restarted.stop(t)
	reconciled := vmHaepari(t, haepari, fixture.caseDir, fixture.environment, "locks", "list", "--lock", "mulgae-review", "--json")
	var nativeState any
	for _, item := range reconciled["requests"].([]any) {
		row := item.(map[string]any)
		if row["request_id"] == intent.ObservedRequest.RequestID {
			nativeState = row["state"]
		}
	}
	if nativeState == nil {
		t.Fatal("restarted controller lost the persisted lock request record")
	}

	return map[string]any{
		"session_id":                    sessionID,
		"run_id":                        runID,
		"provider_pid":                  providerPID,
		"exit_code":                     result.exitCode,
		"schema_version":                intent.SchemaVersion,
		"local_drain_state":             intent.LocalDrainState,
		"recorded_observed_state":       intent.ObservedRequest.State,
		"restarted_native_ledger_state": nativeState,
	}
}

func vmRunOwnedMaxHoldExpiryLossCase(t *testing.T, parentCtx context.Context, root, haepari, binary, work string, environment []string) map[string]any {
	t.Helper()

	fixture, ctx := vmSetupLossCaseWithResource(t, parentCtx, root, haepari, binary, work, "max-hold-expiry", vmMaxHoldLossResourceSpecJSON, environment)
	defer fixture.controller.stop(t)

	// 1. Owned review admission against a resource whose max_hold_seconds (10s)
	// is smaller than the execution+drain budget must fail closed with
	// haepari_hold_budget_exceeded, settle the unused grant on the controller,
	// and never dispatch a provider.
	budgetResult := runMulgaeBinaryWithEnv(t, binary, fixture.project, fixture.environment, "review", "--head", "--roles", "logic", "--output", "json")
	if budgetResult.exitCode == 0 {
		t.Fatalf("owned review unexpectedly succeeded with insufficient max_hold_seconds: %s", budgetResult.stdout)
	}
	var budgetEnvelope commandEnvelope
	if err := json.Unmarshal(budgetResult.stdout, &budgetEnvelope); err != nil ||
		budgetEnvelope.Result.SessionID == nil || budgetEnvelope.Result.RunID == nil ||
		!commandEnvelopeHasReason(budgetEnvelope, string(domain.DiagnosticCauseCoordinationHoldBudgetExceeded)) {
		t.Fatalf("owned max-hold admission did not fail closed with haepari_hold_budget_exceeded: exit=%d stdout=%s err=%v",
			budgetResult.exitCode, budgetResult.stdout, err)
	}
	readyFiles, _ := filepath.Glob(filepath.Join(fixture.barrier, "*.ready"))
	if len(readyFiles) != 0 {
		t.Fatalf("owned max-hold admission invoked provider despite budget rejection: %v", readyFiles)
	}
	sessionID, runID := *budgetEnvelope.Result.SessionID, *budgetEnvelope.Result.RunID
	rawIntent := vmReadLockIntentBytes(t, fixture.project, sessionID, runID)
	var intent artifactwire.HaepariLockIntentWireV2
	if err := json.Unmarshal(rawIntent, &intent); err != nil ||
		intent.SchemaVersion != artifactwire.HaepariLockIntentSchemaV2 ||
		intent.LocalDrainState != string(ports.ReviewLocalDrainNotStarted) ||
		intent.ObservedRequest == nil ||
		intent.ObservedRequest.State != string(ports.ReviewLockStateReleased) {
		t.Fatalf("owned max-hold unused grant settlement intent mismatch: %+v / %v", intent, err)
	}

	// 2. Native max_hold_deadline enforcement despite active renewal: acquire a
	// grant (liveness=6s, max_hold=10s), renew before liveness expiry so the
	// grant stays alive past 6s, then verify max_hold_deadline expires it at 10s
	// and any subsequent renewal or borrowed admission fails closed.
	acquired := vmHaepari(t, haepari, fixture.caseDir, fixture.environment, "lock", "acquire", "mulgae-review",
		"--request-key", "loss-max-hold-grant", "--holder", "guest-max-hold-holder", "--json")
	current, ok := acquired["current"].(map[string]any)
	if !ok || current["state"] != "granted" {
		t.Fatalf("max-hold native acquire was not granted: %v", acquired)
	}
	grantID := current["grant_id"].(string)
	requestID := current["request_id"].(string)
	generation := int64(current["generation"].(float64))

	select {
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	case <-time.After(3500 * time.Millisecond):
	}
	renewed := vmHaepari(t, haepari, fixture.caseDir, fixture.environment, "lock", "renew", grantID, "--json")["current"].(map[string]any)
	if renewed["state"] != "granted" || renewed["max_hold_deadline"] != current["max_hold_deadline"] {
		t.Fatalf("max-hold mid-lease renewal did not preserve max_hold_deadline: before=%v after=%v", current, renewed)
	}

	vmWaitFor(t, ctx, func() bool {
		probe := runMulgaeBinaryWithEnv(t, haepari, fixture.caseDir, fixture.environment, "lock", "renew", grantID, "--json")
		return probe.exitCode != 0 && bytes.Contains(probe.stdout, []byte("LOCK_EXPIRED"))
	}, "native max_hold_deadline expiry despite renewal")

	borrowedWire := artifactwire.HaepariBorrowedGrantWire{
		InstallationID: current["installation_id"].(string),
		LockID:         "mulgae-review",
		GrantID:        grantID,
		Generation:     generation,
	}
	rawGrant, err := json.Marshal(borrowedWire)
	if err != nil {
		t.Fatal(err)
	}
	borrowedEnv := append(append([]string{}, fixture.environment...), "HAEPARI_LOCK_GRANT="+string(rawGrant))
	maxHoldBorrowed := runMulgaeBinaryWithEnv(t, binary, fixture.project, borrowedEnv, "review", "--head", "--roles", "logic", "--output", "json")
	var maxHoldBorrowedEnv commandEnvelope
	if err := json.Unmarshal(maxHoldBorrowed.stdout, &maxHoldBorrowedEnv); err != nil || maxHoldBorrowed.exitCode == 0 ||
		!commandEnvelopeHasReason(maxHoldBorrowedEnv, string(domain.DiagnosticCauseCoordinationReadinessFailed)) {
		t.Fatalf("borrowed review against max-hold-expired grant was not refused: exit=%d stdout=%s err=%v",
			maxHoldBorrowed.exitCode, maxHoldBorrowed.stdout, err)
	}
	readyAfter, _ := filepath.Glob(filepath.Join(fixture.barrier, "*.ready"))
	if len(readyAfter) != 0 {
		t.Fatalf("max-hold-expired borrowed review invoked provider: %v", readyAfter)
	}

	page := vmHaepari(t, haepari, fixture.caseDir, fixture.environment, "locks", "list", "--lock", "mulgae-review", "--json")
	var expiredRow map[string]any
	for _, item := range page["requests"].([]any) {
		row := item.(map[string]any)
		if row["request_id"] == requestID {
			expiredRow = row
		}
	}
	if expiredRow == nil || expiredRow["state"] != "hold_expired" || expiredRow["reason"] != "max_hold_deadline" {
		t.Fatalf("max-hold-expired request state = %v, want hold_expired", expiredRow)
	}

	return map[string]any{
		"session_id":                     sessionID,
		"run_id":                         runID,
		"budget_exit_code":               budgetResult.exitCode,
		"budget_reason_code":             string(domain.DiagnosticCauseCoordinationHoldBudgetExceeded),
		"unused_grant_settled_state":     intent.ObservedRequest.State,
		"unused_grant_local_drain_state": intent.LocalDrainState,
		"max_hold_request_id":            requestID,
		"max_hold_terminal_state":        expiredRow["state"],
		"max_hold_borrowed_refused":      true,
		"max_hold_provider_invocations":  0,
	}
}

func vmRunAbruptCallerLossUnverifiedDrainCase(t *testing.T, parentCtx context.Context, root, haepari, binary, work string, environment []string) map[string]any {
	t.Helper()

	fixture, ctx := vmSetupLossCase(t, parentCtx, root, haepari, binary, work, "abrupt-caller-loss", environment)
	defer fixture.controller.stop(t)

	running, providerPID, waitReview := vmStartControlledWaitReview(t, ctx, binary, fixture.project, fixture.barrier, fixture.environment, "abrupt-caller-loss")
	providerPGID, pgidErr := syscall.Getpgid(providerPID)
	ownPGID := syscall.Getpgrp()
	providerDrained := false
	killOwnedProviderGroup := func() {
		if providerDrained || providerPID <= 1 {
			return
		}
		if pgidErr == nil && providerPGID > 1 && providerPGID != ownPGID {
			_ = syscall.Kill(-providerPGID, syscall.SIGKILL)
		}
		_ = syscall.Kill(providerPID, syscall.SIGKILL)
	}
	t.Cleanup(func() {
		killOwnedProviderGroup()
	})
	if pgidErr != nil || providerPGID <= 1 || providerPGID == ownPGID {
		t.Fatalf("owned provider has no isolated process group: %d / %v", providerPGID, pgidErr)
	}

	intentMatches, err := filepath.Glob(filepath.Join(fixture.project, ".mulgae", filepath.FromSlash(artifactwire.DiagnosticHaepariLockIntentPath("s_*", "r_*"))))
	if err != nil || len(intentMatches) != 1 {
		t.Fatalf("abrupt-caller-loss expected exactly 1 persisted v2 lock intent before SIGKILL, got %v / %v", intentMatches, err)
	}
	intentBefore, err := os.ReadFile(intentMatches[0])
	if err != nil {
		t.Fatalf("read initial lock intent: %v", err)
	}
	var intent artifactwire.HaepariLockIntentWireV2
	if err := json.Unmarshal(intentBefore, &intent); err != nil {
		t.Fatalf("decode initial v2 lock intent: %v", err)
	}
	if intent.SchemaVersion != artifactwire.HaepariLockIntentSchemaV2 ||
		intent.LocalDrainState != string(ports.ReviewLocalDrainUnverified) ||
		intent.ObservedRequest == nil ||
		intent.ObservedRequest.State != string(ports.ReviewLockStateGranted) {
		t.Fatalf("abrupt-caller-loss initial v2 intent = %+v, want unverified/granted", intent)
	}
	sessionID, runID := intent.SessionID, intent.RunID
	requestID := intent.ObservedRequest.RequestID
	grantID := intent.ObservedRequest.GrantID

	// Abruptly SIGKILL only the fixture-owned Mulgae caller process (not graceful SIGINT).
	if err := running.command.Process.Signal(syscall.SIGKILL); err != nil {
		t.Fatalf("SIGKILL fixture-owned Mulgae caller: %v", err)
	}
	callerResult := waitReview()
	if callerResult.exitCode == 0 {
		t.Fatalf("abruptly SIGKILLed Mulgae caller unexpectedly exited 0: %s", callerResult.stdout)
	}

	intentAfterKill := vmReadLockIntentBytes(t, fixture.project, sessionID, runID)
	if !bytes.Equal(intentBefore, intentAfterKill) {
		t.Fatalf("abrupt caller SIGKILL mutated persisted unverified v2 intent bytes")
	}
	beforeCleanMaterial := vmRunOwnedTreeMaterial(t, fixture.project, sessionID, runID)
	providerAliveAfterCallerKill := syscall.Kill(providerPID, 0) == nil

	// Observe the 12-second native lease after caller death. Renewing here
	// would keep it alive and destroy the observation; use one read-only query.
	select {
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	case <-time.After(13 * time.Second):
	}

	page := vmHaepari(t, haepari, fixture.caseDir, fixture.environment, "locks", "list", "--lock", "mulgae-review", "--json")
	var expiredRow map[string]any
	for _, item := range page["requests"].([]any) {
		row := item.(map[string]any)
		if row["request_id"] == requestID {
			expiredRow = row
		}
	}
	if expiredRow == nil || expiredRow["state"] != "hold_expired" || expiredRow["reason"] != "liveness_deadline" {
		t.Fatalf("abrupt-caller-loss native request state after liveness expiry = %v, want hold_expired/liveness_deadline", expiredRow)
	}
	providerAliveAfterLeaseExpiry := syscall.Kill(providerPID, 0) == nil
	if !providerAliveAfterCallerKill || !providerAliveAfterLeaseExpiry {
		t.Fatalf("expected wait_review provider PID %d to remain alive across abrupt caller SIGKILL and native lease expiry (after_kill=%t after_expiry=%t)",
			providerPID, providerAliveAfterCallerKill, providerAliveAfterLeaseExpiry)
	}

	// Candidate clean must protect the diagnostic-only run whose v2 lock intent
	// remains unverified, leaving the original intent bytes and artifacts intact.
	cleanRun := runMulgaeBinaryWithEnv(t, binary, fixture.project, fixture.environment, "clean", "--all", "--output", "json")
	var cleanEnvelope map[string]any
	if err := json.Unmarshal(cleanRun.stdout, &cleanEnvelope); err != nil {
		t.Fatalf("decode abrupt-caller-loss clean output: %v (%s)", err, cleanRun.stdout)
	}
	cleanResult, ok := cleanEnvelope["result"].(map[string]any)
	if cleanRun.exitCode != 0 || !ok || cleanResult["affected_run_count"] != float64(0) || cleanResult["affected_bytes"] != float64(0) {
		t.Fatalf("clean --all did not preserve the valid protected diagnostic run: exit=%d result=%#v", cleanRun.exitCode, cleanEnvelope)
	}
	intentAfterClean := vmReadLockIntentBytes(t, fixture.project, sessionID, runID)
	if !bytes.Equal(intentBefore, intentAfterClean) {
		t.Fatalf("clean --all altered persisted unverified v2 lock intent bytes")
	}
	afterCleanMaterial := vmRunOwnedTreeMaterial(t, fixture.project, sessionID, runID)
	if !reflect.DeepEqual(beforeCleanMaterial, afterCleanMaterial) {
		t.Fatalf("clean --all altered diagnostic artifacts of unverified-drain run: before=%v after=%v", beforeCleanMaterial, afterCleanMaterial)
	}

	// Explicitly terminate only the case-owned provider process/group after
	// recording product cleanup protection, and verify PID + process group exit.
	killOwnedProviderGroup()
	vmAssertProviderPIDGone(t, ctx, providerPID, "abrupt-caller-loss")
	if pgidErr == nil && providerPGID > 1 && providerPGID != ownPGID {
		vmWaitFor(t, ctx, func() bool {
			err := syscall.Kill(-providerPGID, 0)
			return errors.Is(err, syscall.ESRCH)
		}, "abrupt-caller-loss provider process group exit")
	}

	providerDrained = true
	return map[string]any{
		"session_id":                         sessionID,
		"run_id":                             runID,
		"request_id":                         requestID,
		"grant_id":                           grantID,
		"provider_pid":                       providerPID,
		"provider_pgid":                      providerPGID,
		"caller_exit_code":                   callerResult.exitCode,
		"schema_version":                     intent.SchemaVersion,
		"persisted_local_drain_state":        intent.LocalDrainState,
		"provider_alive_after_caller_kill":   providerAliveAfterCallerKill,
		"native_state_after_liveness_expiry": expiredRow["state"],
		"provider_alive_after_lease_expiry":  providerAliveAfterLeaseExpiry,
		"clean_exit_code":                    cleanRun.exitCode,
		"clean_protected_artifacts_intact":   true,
		"owned_provider_group_drained":       true,
	}
}
