//go:build darwin && arm64

package e2e

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	adaptercli "github.com/irootkernel/mulgae/internal/adapters/cli"
	adapterconfig "github.com/irootkernel/mulgae/internal/adapters/config"
	"github.com/irootkernel/mulgae/internal/app"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

const productName = "mulgae"

func currentCommandResultContractURI(t *testing.T) string {
	t.Helper()
	var contractURI string
	for _, specification := range adaptercli.CommandSpecs() {
		requestURI, fragment, found := strings.Cut(specification.RequestContractURI(), "#")
		wantFragment := "/$defs/requests/" + string(specification.Command())
		if !found || requestURI == "" || fragment != wantFragment {
			t.Fatalf("command %q request contract = %q, want current command-result request fragment %q", specification.Command(), specification.RequestContractURI(), wantFragment)
		}
		if contractURI == "" {
			contractURI = requestURI
		} else if requestURI != contractURI {
			t.Fatalf("command %q request contract base = %q, want %q", specification.Command(), requestURI, contractURI)
		}
		declaredOutput := false
		for _, outputURI := range specification.OutputContractURIs() {
			if outputURI == contractURI {
				declaredOutput = true
				break
			}
		}
		if !declaredOutput {
			t.Fatalf("command %q does not declare current command-result output contract %q", specification.Command(), contractURI)
		}
	}
	if contractURI == "" {
		t.Fatal("CLI registry has no command-result contract authority")
	}
	return contractURI
}

func TestCurrentCommandResultContractAuthority(t *testing.T) {
	if _, err := ports.ParseAssetID(currentCommandResultContractURI(t)); err != nil {
		t.Fatalf("current command-result contract URI is invalid: %v", err)
	}
}

type versionOutput struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Unbound capability evidence is an operational qualification rejection:
// exit 4 readiness, retryable, one family probe, and no publication artifacts.
func TestIntegrationIndependentProcessesDoNotShareProviderLocks(t *testing.T) {
	root := repositoryRoot(t)
	binary := buildMulgaeBinary(t, root)
	nativeHome := integrationNativeHome(t, binary)
	providerDirectory := canonicalTestTempDir(t)
	barrier := canonicalTestTempDir(t)
	zcodeAppBundle, zcodeNode, zcodeLauncher := fakeZCodeAppPaths(providerDirectory)
	buildFakeZCodeWithBarrier(t, root, zcodeNode, zcodeLauncher, filepath.Join(canonicalTestTempDir(t), "zcode.jsonl"), barrier)

	for _, runtimeRoot := range []struct {
		name   string
		useXDG bool
	}{
		{name: "XDG runtime directory", useXDG: true},
		{name: "TMPDIR fallback", useXDG: false},
	} {
		t.Run(runtimeRoot.name, func(t *testing.T) {
			for _, projects := range []struct {
				name   string
				shared bool
			}{
				{name: "different projects", shared: false},
				{name: "same project", shared: true},
			} {
				t.Run(projects.name, func(t *testing.T) {
					clearProviderBarrier(t, barrier)
					sharedRuntimeRoot := canonicalTestTempDir(t)
					environment := sharedMulgaeProcessEnv(t, nativeHome, providerDirectory, sharedRuntimeRoot, runtimeRoot.useXDG)

					firstProject := canonicalTestTempDir(t)
					initializeReviewGitRepository(t, firstProject)
					secondProject := firstProject
					if !projects.shared {
						secondProject = canonicalTestTempDir(t)
						initializeReviewGitRepository(t, secondProject)
					}
					for _, project := range uniqueStrings(firstProject, secondProject) {
						runTestCommand(t, project, "git", "add", "review.go")
						runTestCommand(t, project, "git", "-c", "user.name=Mulgae E2E", "-c", "user.email=mulgae-e2e@example.invalid", "commit", "-m", "review target")
						initialized := runMulgaeBinaryWithEnv(t, binary, project, environment,
							"init", "--providers", "zcode", "--roles", "logic",
							"--zcode-app-bundle", zcodeAppBundle)
						if initialized.exitCode != 0 {
							t.Fatalf("initialize concurrent review config: exit=%d stdout=%q stderr=%q", initialized.exitCode, initialized.stdout, initialized.stderr)
						}
					}

					ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
					defer cancel()
					arguments := []string{"review", "--diff", "HEAD~1..HEAD", "--roles", "logic", "--objective", "Review the captured change.", "--output", "json"}
					first := startMulgaeBinaryWithEnv(t, ctx, binary, firstProject, environment, arguments...)
					second := startMulgaeBinaryWithEnv(t, ctx, binary, secondProject, environment, arguments...)
					firstResult := waitMulgaeBinary(t, first)
					secondResult := waitMulgaeBinary(t, second)
					firstEnvelope := assertSuccessfulConcurrentReview(t, firstProject, firstResult)
					secondEnvelope := assertSuccessfulConcurrentReview(t, secondProject, secondResult)
					if *firstEnvelope.Result.SessionID == *secondEnvelope.Result.SessionID || *firstEnvelope.Result.RunID == *secondEnvelope.Result.RunID {
						t.Fatalf("concurrent reviews reused identity: first=%#v second=%#v", firstEnvelope.Result, secondEnvelope.Result)
					}

					markers, err := filepath.Glob(filepath.Join(barrier, "*.ready"))
					if err != nil || len(markers) != 2 {
						t.Fatalf("provider overlap markers = %v, %v; want exactly two review processes", markers, err)
					}
					assertNoGlobalProviderLockNamespace(t, sharedRuntimeRoot, runtimeRoot.useXDG)
				})
			}
		})
	}
}

func TestIntegrationPublicationLockCancellationPreservesTypedFailureAndArtifacts(t *testing.T) {
	root := repositoryRoot(t)
	binary := buildMulgaeBinary(t, root)
	project := canonicalTestTempDir(t)
	initializeReviewGitRepository(t, project)
	runTestCommand(t, project, "git", "add", "review.go")
	runTestCommand(t, project, "git", "-c", "user.name=Mulgae E2E", "-c", "user.email=mulgae-e2e@example.invalid", "commit", "-m", "review target")

	nativeHome := integrationNativeHome(t, binary)
	providerDirectory := canonicalTestTempDir(t)
	zcodeLog := filepath.Join(canonicalTestTempDir(t), "zcode.jsonl")
	zcodeAppBundle, zcodeNode, zcodeLauncher := fakeZCodeAppPaths(providerDirectory)
	buildFakeZCode(t, root, zcodeNode, zcodeLauncher, zcodeLog, "success")
	environment := isolatedMulgaeEnvWith(t, nativeHome, providerDirectory)
	initialized := runMulgaeBinaryWithEnv(t, binary, project, environment,
		"init", "--providers", "zcode", "--roles", "logic",
		"--zcode-app-bundle", zcodeAppBundle)
	if initialized.exitCode != 0 {
		t.Fatalf("initialize publication-lock config: exit=%d stdout=%q stderr=%q", initialized.exitCode, initialized.stdout, initialized.stderr)
	}

	arguments := []string{"review", "--diff", "HEAD~1..HEAD", "--roles", "logic", "--objective", "Review the captured change.", "--output", "json"}
	baseline := assertSuccessfulConcurrentReview(t, project, runMulgaeBinaryWithEnv(t, binary, project, environment, arguments...))
	baselineRoot := filepath.Join(project, ".mulgae", *baseline.Result.SessionID, *baseline.Result.RunID)
	beforeBaseline := snapshotTestTreeMaterial(t, baselineRoot)
	storeRoot := filepath.Join(project, ".mulgae", "store")

	lockFile, err := os.OpenFile(filepath.Join(storeRoot, "locks", "store.lock"), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer lockFile.Close()
	if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatalf("hold publication lock: %v", err)
	}
	defer syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN) //nolint:errcheck -- best-effort test cleanup
	beforeStore := snapshotTestTreeMaterial(t, storeRoot)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	running := startMulgaeBinaryWithEnv(t, ctx, binary, project, environment, arguments...)

	var diagnosticLogPath string
	deadline := time.Now().Add(20 * time.Second)
	for diagnosticLogPath == "" && time.Now().Before(deadline) {
		logs, globErr := filepath.Glob(filepath.Join(project, ".mulgae", "diagnostics", "s_*", "r_*", "mulgae-runtime.jsonl"))
		if globErr != nil {
			t.Fatal(globErr)
		}
		for _, path := range logs {
			if strings.Contains(path, *baseline.Result.RunID) {
				continue
			}
			data, readErr := os.ReadFile(path)
			if readErr == nil && bytes.Contains(data, []byte(`"event":"workspace_cleanup_completed"`)) {
				diagnosticLogPath = path
				break
			}
		}
		if diagnosticLogPath == "" {
			time.Sleep(10 * time.Millisecond)
		}
	}
	if diagnosticLogPath == "" {
		cancel()
		result := waitMulgaeBinary(t, running)
		t.Fatalf("review did not reach publication lock: exit=%d stdout=%q stderr=%q", result.exitCode, result.stdout, result.stderr)
	}
	// Workspace cleanup is the final durable event before candidate preparation
	// and publication. Give the process time to enter the held lock's bounded
	// polling loop so this exercises lock-wait cancellation, not an earlier
	// context checkpoint.
	time.Sleep(100 * time.Millisecond)
	if err := running.command.Process.Signal(syscall.Signal(0)); err != nil {
		result := waitMulgaeBinary(t, running)
		t.Fatalf("review exited before publication-lock cancellation: exit=%d stdout=%q stderr=%q", result.exitCode, result.stdout, result.stderr)
	}
	if err := running.command.Process.Signal(os.Interrupt); err != nil {
		t.Fatalf("cancel publication-lock waiter: %v", err)
	}
	result := waitMulgaeBinary(t, running)
	if result.exitCode != int(app.ExitCodeArtifact) || len(result.stderr) != 0 {
		t.Fatalf("publication-lock waiter: exit=%d stdout=%q stderr=%q", result.exitCode, result.stdout, result.stderr)
	}
	var envelope commandEnvelope
	if err := json.Unmarshal(result.stdout, &envelope); err != nil {
		t.Fatalf("decode publication-lock envelope: %v: %q", err, result.stdout)
	}
	if envelope.Exit.Code != int(app.ExitCodeArtifact) || envelope.Exit.Kind != "artifact" ||
		len(envelope.Reasons) != 1 || envelope.Reasons[0].Category != "artifact" || envelope.Reasons[0].Code != string(domain.DiagnosticCausePublicationStoreLockFailed) ||
		envelope.Reasons[0].Retryable || envelope.Reasons[0].ArtifactURI == nil ||
		envelope.Result.RunManifestURI != nil || envelope.Result.ReviewArtifactURI != nil {
		t.Fatalf("publication-lock envelope = %#v", envelope)
	}
	diagnosticRoot := filepath.Dir(diagnosticLogPath)
	wantDiagnosticURI, err := filepath.Rel(project, diagnosticRoot)
	if err != nil {
		t.Fatal(err)
	}
	if *envelope.Reasons[0].ArtifactURI != filepath.ToSlash(wantDiagnosticURI) {
		t.Fatalf("publication diagnostic URI = %q, want %q", *envelope.Reasons[0].ArtifactURI, filepath.ToSlash(wantDiagnosticURI))
	}
	diagnosticLog, err := os.ReadFile(diagnosticLogPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(diagnosticLog, []byte(`"event":"runtime_diagnostics_closed"`)) ||
		!bytes.Contains(diagnosticLog, []byte(`"event":"run_stopped"`)) ||
		!bytes.Contains(diagnosticLog, []byte(`"state":"failed"`)) ||
		!bytes.Contains(diagnosticLog, []byte(`"cause":"publication_store_lock_failed"`)) {
		t.Fatalf("publication-lock cancellation did not preserve the typed failure:\n%s", diagnosticLog)
	}
	for _, event := range []domain.RuntimeDiagnosticEventCode{
		domain.DiagnosticPublicationPreparationStarted,
		domain.DiagnosticPublicationStaged,
		domain.DiagnosticPublicationInstalled,
		domain.DiagnosticPublicationCommitted,
	} {
		if bytes.Contains(diagnosticLog, []byte(`"event":"`+string(event)+`"`)) {
			t.Fatalf("publication diagnostics recorded %s before acquiring the lock:\n%s", event, diagnosticLog)
		}
	}
	if got := snapshotTestTreeMaterial(t, baselineRoot); !reflect.DeepEqual(got, beforeBaseline) {
		t.Fatalf("publication contention changed the committed baseline: before=%v after=%v", beforeBaseline, got)
	}
	if got := snapshotTestTreeMaterial(t, storeRoot); !reflect.DeepEqual(got, beforeStore) {
		t.Fatalf("publication contention changed the epoch store: before=%v after=%v", beforeStore, got)
	}
}

// ZCode roles deliver their report through the staged file Mulgae granted them.
// The manifest records which transport carried each published report.
// A staged file the provider never wrote is operationally missing output: the
// role completes on its configured fallback and the run still publishes.
func commandEnvelopeHasReason(envelope commandEnvelope, code string) bool {
	for _, reason := range envelope.Reasons {
		if reason.Code == code {
			return true
		}
	}
	return false
}

// TestIntegrationStagedFileMissingIsAnOperationalRoleFailure proves a missing
// staged output file is classified as an operational invalid-output failure
// rather than a staging violation, and that the role simply fails: Mulgae does
// not move it to the other configured provider.
func TestIntegrationIsolatedReleaseFixtureComposesExactRecoveredReview(t *testing.T) {
	for _, role := range []string{"logic", "maintainability"} {
		t.Run(role, func(t *testing.T) { testReleaseBinaryComposesRecoveredRole(t, role) })
	}
}

func testReleaseBinaryComposesRecoveredRole(t *testing.T, failedRole string) {
	t.Helper()
	reviewRoles := "logic"
	if failedRole != "logic" {
		reviewRoles += "," + failedRole
	}
	root := repositoryRoot(t)
	binary := buildMulgaeBinary(t, root)
	project := canonicalTestTempDir(t)
	initializeReviewGitRepository(t, project)

	nativeHome := integrationNativeHome(t, binary)
	providerDirectory := canonicalTestTempDir(t)
	logDirectory := canonicalTestTempDir(t)
	zcodeLog := filepath.Join(logDirectory, "zcode.jsonl")
	zcodeAppBundle, zcodeNode, zcodeLauncher := fakeZCodeAppPaths(providerDirectory)
	buildFakeZCode(t, root, zcodeNode, zcodeLauncher, zcodeLog, "fail_first_"+failedRole)
	environment := isolatedMulgaeEnvWith(t, nativeHome, providerDirectory)
	initializeOfflineProvidersForRoles(t, binary, project, environment, "zcode", reviewRoles, zcodeAppBundle)

	incomplete := runMulgaeBinaryWithEnv(t, binary, project, environment,
		"review", "--dirty", "--roles", reviewRoles, "--output", "json")
	var rootEnvelope commandEnvelope
	if err := json.Unmarshal(incomplete.stdout, &rootEnvelope); err != nil {
		t.Fatalf("decode incomplete root: %v: %q", err, incomplete.stdout)
	}
	if incomplete.exitCode != int(domain.ExitIncompleteCoverage) || rootEnvelope.Result.RunID == nil ||
		!commandEnvelopeHasReason(rootEnvelope, "required_role_incomplete") {
		t.Fatalf("incomplete root = exit %d envelope %#v stderr %q", incomplete.exitCode, rootEnvelope, incomplete.stderr)
	}

	recovered := runMulgaeBinaryWithEnv(t, binary, project, environment,
		"rerun", "--run", *rootEnvelope.Result.RunID, "--role", failedRole, "--provider", "zcode-"+failedRole, "--output", "json")
	var recoveryEnvelope commandEnvelope
	if err := json.Unmarshal(recovered.stdout, &recoveryEnvelope); err != nil {
		t.Fatalf("decode exact recovery: %v: %q", err, recovered.stdout)
	}
	if recovered.exitCode != 0 || recoveryEnvelope.Result.RunID == nil {
		dumpRuntimeDiagnostics(t, project, recoveryEnvelope)
		t.Fatalf("exact recovery = exit %d envelope %#v stderr %q", recovered.exitCode, recoveryEnvelope, recovered.stderr)
	}

	composed := runMulgaeBinaryWithEnv(t, binary, project, environment,
		"compose", "--root-run", *rootEnvelope.Result.RunID, "--recovery-run", *recoveryEnvelope.Result.RunID, "--output", "json")
	var compositeEnvelope commandEnvelope
	if err := json.Unmarshal(composed.stdout, &compositeEnvelope); err != nil {
		t.Fatalf("decode composite: %v: %q", err, composed.stdout)
	}
	if composed.exitCode != 0 || compositeEnvelope.Result.Kind != "composite_published" || compositeEnvelope.Result.RunID == nil ||
		compositeEnvelope.Result.RootRunID == nil || *compositeEnvelope.Result.RootRunID != *rootEnvelope.Result.RunID ||
		!reflect.DeepEqual(compositeEnvelope.Result.RecoveryRunIDs, []string{*recoveryEnvelope.Result.RunID}) ||
		compositeEnvelope.Result.ReconciliationState != "created" ||
		compositeEnvelope.Result.PublicationStatus != string(domain.PublicationCommitted) ||
		compositeEnvelope.Result.CoverageStatus != string(domain.CoverageComplete) ||
		compositeEnvelope.Result.CIDecision != string(domain.CIPass) || !compositeEnvelope.Result.RetrySafe {
		t.Fatalf("composite = exit %d envelope %#v stderr %q", composed.exitCode, compositeEnvelope, composed.stderr)
	}
	reconciled := runMulgaeBinaryWithEnv(t, binary, project, environment,
		"compose", "--root-run", *rootEnvelope.Result.RunID, "--recovery-run", *recoveryEnvelope.Result.RunID, "--output", "json")
	var reconciledEnvelope commandEnvelope
	if err := json.Unmarshal(reconciled.stdout, &reconciledEnvelope); err != nil {
		t.Fatalf("decode reconciled composite: %v: %q", err, reconciled.stdout)
	}
	if reconciled.exitCode != 0 || reconciledEnvelope.Result.RunID == nil || reconciledEnvelope.Result.ReviewID == nil ||
		*reconciledEnvelope.Result.RunID != *compositeEnvelope.Result.RunID ||
		*reconciledEnvelope.Result.ReviewID != *compositeEnvelope.Result.ReviewID ||
		reconciledEnvelope.Result.ReconciliationState != "reconciled" || !reconciledEnvelope.Result.RetrySafe {
		t.Fatalf("reconciled composite = exit %d envelope %#v stderr %q", reconciled.exitCode, reconciledEnvelope, reconciled.stderr)
	}

	status := runMulgaeBinaryWithEnv(t, binary, project, environment,
		"status", "--run", *compositeEnvelope.Result.RunID, "--output", "json")
	var statusEnvelope commandEnvelope
	if err := json.Unmarshal(status.stdout, &statusEnvelope); err != nil {
		t.Fatalf("decode composite status: %v: %q", err, status.stdout)
	}
	if status.exitCode != 0 || statusEnvelope.Result.RunID == nil || *statusEnvelope.Result.RunID != *compositeEnvelope.Result.RunID ||
		statusEnvelope.Result.PublicationStatus != compositeEnvelope.Result.PublicationStatus ||
		statusEnvelope.Result.CoverageStatus != compositeEnvelope.Result.CoverageStatus ||
		statusEnvelope.Result.CIDecision != compositeEnvelope.Result.CIDecision {
		t.Fatalf("composite status = exit %d envelope %#v stderr %q", status.exitCode, statusEnvelope, status.stderr)
	}
	findings := runMulgaeBinaryWithEnv(t, binary, project, environment,
		"findings", "--run", *compositeEnvelope.Result.RunID, "--severity", "low", "--output", "json")
	if findings.exitCode != 0 || len(findings.stderr) != 0 {
		t.Fatalf("composite findings = exit %d stdout %q stderr %q", findings.exitCode, findings.stdout, findings.stderr)
	}
}

// Staging Mulgae did not authorize is a boundary breach: the role publishes
// nothing and the run fails closed as a security condition.
func TestIntegrationStagedSymlinkFailsClosedAsSecurityViolation(t *testing.T) {
	root := repositoryRoot(t)
	binary := buildMulgaeBinary(t, root)
	nativeHome := integrationNativeHome(t, binary)

	for _, test := range []struct {
		name     string
		staged   string
		smuggled bool
	}{
		{name: "symbolic link", staged: "symlink", smuggled: true},
		{name: "extra staged entry", staged: "extra"},
	} {
		t.Run(test.name, func(t *testing.T) {
			project := canonicalTestTempDir(t)
			initializeReviewGitRepository(t, project)
			providerDirectory := canonicalTestTempDir(t)
			logDirectory := canonicalTestTempDir(t)
			zcodeLog := filepath.Join(logDirectory, "zcode.jsonl")
			zcodeAppBundle, zcodeNode, zcodeLauncher := fakeZCodeAppPaths(providerDirectory)
			buildFakeZCodeWithStagedOutput(t, root, zcodeNode, zcodeLauncher, zcodeLog, "success", test.staged)
			environment := isolatedMulgaeEnvWith(t, nativeHome, providerDirectory)
			initializeOfflineProviders(t, binary, project, environment, "zcode", zcodeAppBundle)

			review := runMulgaeBinaryWithEnv(t, binary, project, environment,
				"review", "--dirty", "--roles", "security", "--output", "json")
			var envelope commandEnvelope
			if err := json.Unmarshal(review.stdout, &envelope); err != nil {
				t.Fatalf("decode staging violation envelope: %v: %q", err, review.stdout)
			}
			if review.exitCode != int(app.ExitCodeSecurity) || envelope.Exit.Code != int(app.ExitCodeSecurity) ||
				envelope.Exit.Kind != "security" || len(envelope.Reasons) != 1 ||
				envelope.Reasons[0].Category != "security" || envelope.Reasons[0].Retryable ||
				envelope.Reasons[0].ArtifactURI == nil {
				dumpRuntimeDiagnostics(t, project, envelope)
				t.Fatalf("staging violation review = exit %d envelope %#v stderr %q", review.exitCode, envelope, review.stderr)
			}
			if envelope.Result.RunManifestURI != nil || envelope.Result.ReviewArtifactURI != nil ||
				len(envelope.Result.RoleReportURIs) != 0 {
				t.Fatalf("staging violation published artifacts: %#v", envelope.Result)
			}
			entries, err := os.ReadDir(filepath.Join(project, ".mulgae"))
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 3 || entries[0].Name() != "config.yaml" || entries[1].Name() != "diagnostics" || entries[2].Name() != "local.yaml" {
				t.Fatalf("staging violation created publication artifacts: %v", entries)
			}
			diagnosticRoot := filepath.Join(project, filepath.FromSlash(*envelope.Reasons[0].ArtifactURI))
			log, err := os.ReadFile(filepath.Join(diagnosticRoot, "mulgae-runtime.jsonl"))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Contains(log, []byte(`"cause":"`+string(domain.DiagnosticCauseProviderOutputStagingViolation)+`"`)) {
				t.Fatalf("staging violation diagnostics omitted the staging violation cause:\n%s", log)
			}
			if !bytes.Contains(log, []byte(`"event":"`+string(domain.DiagnosticRuntimeClosed)+`"`)) {
				t.Fatalf("staging violation diagnostics were not finalized:\n%s", log)
			}
			statusBytes, err := os.ReadFile(filepath.Join(diagnosticRoot, "status.json"))
			if err != nil {
				t.Fatal(err)
			}
			var status struct {
				State             domain.RunState `json:"state"`
				RolePathCompleted int             `json:"role_path_completed"`
				RolePathFailed    int             `json:"role_path_failed"`
				P2URI             string          `json:"p2_uri"`
			}
			if err := json.Unmarshal(statusBytes, &status); err != nil {
				t.Fatal(err)
			}
			if status.State == domain.RunCompleted || status.RolePathCompleted != 0 || status.RolePathFailed != 1 || status.P2URI != "" {
				t.Fatalf("staging violation diagnostic status = %#v", status)
			}
			launches := fakeZCodeReviewObservations(t, zcodeLog)
			if len(launches) != 1 || launches[0].Destination == "" {
				t.Fatalf("staging violation launches = %#v, want one destination-bound launch", launches)
			}
			if _, err := os.Lstat(launches[0].Destination); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("violating staging %q survived the run: %v", launches[0].Destination, err)
			}
			if !test.smuggled {
				return
			}
			smuggled := filepath.Join(logDirectory, "smuggled-role-report.md")
			body, err := os.ReadFile(smuggled)
			if err != nil || string(body) != fakeZCodeStagedReport("security") {
				t.Fatalf("linked report outside staging = %q, %v", body, err)
			}
		})
	}
}

func restoreTestCapturedReviewArchive(t *testing.T, project, sessionID, runID string) ports.CapturedReviewMaterial {
	t.Helper()
	targetRoot := filepath.Join(project, ".mulgae", sessionID, runID, "target")
	manifest, err := os.ReadFile(filepath.Join(targetRoot, "captured-review.json"))
	if err != nil {
		t.Fatal(err)
	}
	references, err := ports.CapturedReviewArchiveBlobReferences(manifest)
	if err != nil {
		t.Fatal(err)
	}
	blobs := make([]ports.CapturedReviewArchiveBlob, 0, len(references))
	for _, reference := range references {
		contents, readErr := os.ReadFile(filepath.Join(targetRoot, filepath.FromSlash(reference.Path().String())))
		if readErr != nil {
			t.Fatal(readErr)
		}
		blob, blobErr := ports.NewCapturedReviewArchiveBlob(reference.Path(), contents)
		if blobErr != nil || blob.SHA256() != reference.SHA256() {
			t.Fatalf("captured review blob %q is invalid: %v", reference.Path().String(), blobErr)
		}
		blobs = append(blobs, blob)
	}
	material, err := ports.RestoreCapturedReviewArchive(manifest, blobs)
	if err != nil {
		t.Fatal(err)
	}
	return material
}

func snapshotTestTree(t *testing.T, root string) []string {
	t.Helper()
	var paths []string
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == root {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		paths = append(paths, filepath.ToSlash(relative))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return paths
}

func snapshotTestTreeMaterial(t *testing.T, root string) map[string]string {
	t.Helper()
	material := make(map[string]string)
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == root {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		name := filepath.ToSlash(relative)
		if entry.IsDir() {
			material[name] = "directory"
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		digest := sha256.Sum256(data)
		material[name] = hex.EncodeToString(digest[:])
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return material
}

func environmentValue(t *testing.T, environment []string, name string) string {
	t.Helper()
	prefix := name + "="
	for _, value := range environment {
		if strings.HasPrefix(value, prefix) {
			return strings.TrimPrefix(value, prefix)
		}
	}
	t.Fatalf("environment omits %s", name)
	return ""
}

func initializeOfflineProviders(t *testing.T, binary, project string, environment []string, providers, zcodeAppBundle string) {
	initializeOfflineProvidersForRoles(t, binary, project, environment, providers, "security", zcodeAppBundle)
}

func initializeOfflineProvidersForRoles(t *testing.T, binary, project string, environment []string, providers, roles, zcodeAppBundle string) {
	t.Helper()
	arguments := []string{"init", "--providers", providers, "--roles", roles, "--zcode-app-bundle", zcodeAppBundle}
	initialized := runMulgaeBinaryWithEnv(t, binary, project, environment, arguments...)
	if initialized.exitCode != 0 {
		t.Fatalf("initialize offline providers: exit=%d stdout=%q stderr=%q", initialized.exitCode, initialized.stdout, initialized.stderr)
	}
}

// dumpRuntimeDiagnostics logs the runtime diagnostic stream a review left
// behind so an integration failure stays inspectable from the test output.
func dumpRuntimeDiagnostics(t *testing.T, project string, envelope commandEnvelope) {
	t.Helper()
	if envelope.Result.SessionID == nil || envelope.Result.RunID == nil {
		return
	}
	log, err := os.ReadFile(filepath.Join(
		project, ".mulgae", "diagnostics", *envelope.Result.SessionID, *envelope.Result.RunID, "mulgae-runtime.jsonl",
	))
	if err != nil {
		return
	}
	t.Logf("runtime diagnostics:\n%s", log)
}

func readRuntimeDiagnosticLog(t *testing.T, project, session, run string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(project, ".mulgae", "diagnostics", session, run, "mulgae-runtime.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func assertRuntimeDiagnosticStatus(t *testing.T, project, session, run string, wantState domain.RunState, wantP2 string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(project, ".mulgae", "diagnostics", session, run, "status.json"))
	if err != nil {
		t.Fatal(err)
	}
	var status struct {
		State domain.RunState `json:"state"`
		P2URI string          `json:"p2_uri"`
	}
	if err := json.Unmarshal(data, &status); err != nil || status.State != wantState || status.P2URI != wantP2 {
		t.Fatalf("runtime diagnostic status = %#v, %v; want %s/%q", status, err, wantState, wantP2)
	}
}

type commandRoleReportURI struct {
	Role string `json:"role"`
	URI  string `json:"uri"`
}

type commandEnvelope struct {
	SchemaVersion string `json:"schema_version"`
	Command       string `json:"command"`
	Request       struct {
		RequestState string `json:"request_state"`
		OutputFormat string `json:"output_format"`
	} `json:"request"`
	Exit struct {
		Code int    `json:"code"`
		Kind string `json:"kind"`
	} `json:"exit"`
	Result struct {
		Kind                string                 `json:"kind"`
		SessionID           *string                `json:"session_id"`
		RunID               *string                `json:"run_id"`
		ReviewID            *string                `json:"review_id"`
		RootRunID           *string                `json:"root_run_id"`
		RecoveryRunIDs      []string               `json:"recovery_run_ids"`
		ReconciliationState string                 `json:"reconciliation_state"`
		RetrySafe           bool                   `json:"retry_safe"`
		PublicationStatus   string                 `json:"publication_status"`
		CoverageStatus      string                 `json:"coverage_status"`
		CIDecision          string                 `json:"ci_decision"`
		RunManifestURI      *string                `json:"run_manifest_uri"`
		ReviewArtifactURI   *string                `json:"review_artifact_uri"`
		PromptManifestURI   *string                `json:"prompt_manifest_uri"`
		RoleReportURIs      []commandRoleReportURI `json:"role_report_uris"`
	} `json:"result"`
	Reasons []struct {
		Category    string  `json:"category"`
		Code        string  `json:"code"`
		Message     string  `json:"message"`
		Retryable   bool    `json:"retryable"`
		ArtifactURI *string `json:"artifact_uri"`
	} `json:"reasons"`
}

type manifestRoleReport struct {
	Role             string `json:"role"`
	Path             string `json:"path"`
	SHA256           string `json:"sha256"`
	ByteLength       int    `json:"byte_length"`
	ProviderInstance string `json:"provider_instance"`
	AttemptID        string `json:"attempt_id"`
	ContentType      string `json:"content_type"`
	Transport        string `json:"transport"`
}

// publishedRoleReport is the exact transport, provider instance, and bytes one
// committed role report must carry.
type publishedRoleReport struct {
	transport        string
	providerInstance string
	content          string
}

func readManifestRoleReports(t *testing.T, project string, envelope commandEnvelope) []manifestRoleReport {
	t.Helper()
	if envelope.Result.RunManifestURI == nil {
		t.Fatalf("command envelope lacks a committed run manifest: %#v", envelope.Result)
	}
	manifestBytes, err := os.ReadFile(filepath.Join(project, *envelope.Result.RunManifestURI))
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		RoleReports []manifestRoleReport `json:"role_reports"`
	}
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatalf("decode manifest role reports: %v", err)
	}
	return manifest.RoleReports
}

// assertPublishedRoleReports pins the provider output transport recorded for
// each committed role report and the exact bytes that transport carried. Under
// the staged_file transport the published body is the provider-staged file, so
// a role that stages one body while printing another must publish the staged
// one.
func assertPublishedRoleReports(t *testing.T, project string, envelope commandEnvelope, want map[string]publishedRoleReport) {
	t.Helper()
	reports := readManifestRoleReports(t, project, envelope)
	if len(reports) != len(want) {
		t.Fatalf("published role reports = %d, want %d: %#v", len(reports), len(want), reports)
	}
	uris := make(map[string]string, len(envelope.Result.RoleReportURIs))
	for _, uri := range envelope.Result.RoleReportURIs {
		uris[uri.Role] = uri.URI
	}
	for _, report := range reports {
		expected, ok := want[report.Role]
		if !ok {
			t.Fatalf("unexpected published role report %#v", report)
		}
		if report.Transport != expected.transport || report.ProviderInstance != expected.providerInstance {
			t.Fatalf("role %q published transport/provider = %q/%q, want %q/%q",
				report.Role, report.Transport, report.ProviderInstance, expected.transport, expected.providerInstance)
		}
		uri, ok := uris[report.Role]
		if !ok {
			t.Fatalf("role %q has no published report URI: %#v", report.Role, envelope.Result.RoleReportURIs)
		}
		content, err := os.ReadFile(filepath.Join(project, uri))
		if err != nil {
			t.Fatalf("read published role report %q: %v", uri, err)
		}
		if string(content) != expected.content {
			t.Fatalf("role %q published report = %q, want %q", report.Role, content, expected.content)
		}
		if bytes.Contains(content, []byte("Standard output is ignored under the staged file transport.")) {
			t.Fatalf("role %q published the ignored ZCode stdout envelope: %s", report.Role, content)
		}
	}
}

func assertCommandRoleReportInventory(t *testing.T, project string, envelope commandEnvelope) {
	t.Helper()
	if envelope.Result.SessionID == nil || envelope.Result.RunID == nil || envelope.Result.RunManifestURI == nil || envelope.Result.ReviewArtifactURI == nil {
		t.Fatalf("command envelope lacks committed identity for role-report checks: %#v", envelope.Result)
	}
	manifestBytes, err := os.ReadFile(filepath.Join(project, *envelope.Result.RunManifestURI))
	if err != nil {
		t.Fatal(err)
	}
	reviewBytes, err := os.ReadFile(filepath.Join(project, *envelope.Result.ReviewArtifactURI))
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		RoleReports []manifestRoleReport `json:"role_reports"`
	}
	var review struct {
		RoleOutcomes []struct {
			Role             string  `json:"role"`
			Outcome          string  `json:"outcome"`
			AttemptID        *string `json:"attempt_id"`
			ProviderInstance *string `json:"provider_instance"`
		} `json:"role_outcomes"`
	}
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatalf("decode manifest for role reports: %v", err)
	}
	if err := json.Unmarshal(reviewBytes, &review); err != nil {
		t.Fatalf("decode review for role reports: %v", err)
	}
	expectedRoles := make([]string, 0, len(review.RoleOutcomes))
	outcomesByRole := make(map[string]struct {
		AttemptID        *string
		ProviderInstance *string
	}, len(review.RoleOutcomes))
	for _, outcome := range review.RoleOutcomes {
		outcomesByRole[outcome.Role] = struct {
			AttemptID        *string
			ProviderInstance *string
		}{AttemptID: outcome.AttemptID, ProviderInstance: outcome.ProviderInstance}
		if outcome.Outcome == "completed" || outcome.Outcome == "degraded" {
			expectedRoles = append(expectedRoles, outcome.Role)
		}
	}
	if len(manifest.RoleReports) != len(expectedRoles) || len(envelope.Result.RoleReportURIs) != len(expectedRoles) {
		t.Fatalf("role report cardinality mismatch: outcomes=%v manifest=%d uris=%d", expectedRoles, len(manifest.RoleReports), len(envelope.Result.RoleReportURIs))
	}
	prefix := ".mulgae/" + *envelope.Result.SessionID + "/" + *envelope.Result.RunID + "/role-reports/"
	for index, role := range expectedRoles {
		report := manifest.RoleReports[index]
		uri := envelope.Result.RoleReportURIs[index]
		outcome := outcomesByRole[role]
		if report.Role != role || uri.Role != role || report.Path != "role-reports/"+role+".md" ||
			report.ContentType != "text/markdown" || report.ByteLength <= 0 ||
			(report.Transport != "staged_file" && report.Transport != "stdout") ||
			outcome.AttemptID == nil || outcome.ProviderInstance == nil ||
			report.AttemptID != *outcome.AttemptID || report.ProviderInstance != *outcome.ProviderInstance ||
			uri.URI != prefix+role+".md" {
			t.Fatalf("role report identity mismatch at %d: role=%q report=%#v uri=%#v outcome=%#v", index, role, report, uri, outcome)
		}
		content, err := os.ReadFile(filepath.Join(project, uri.URI))
		if err != nil {
			t.Fatalf("read role report %q: %v", uri.URI, err)
		}
		if len(content) != report.ByteLength {
			t.Fatalf("role report %q byte length = %d, want %d", role, len(content), report.ByteLength)
		}
		sum := sha256.Sum256(content)
		digest := "sha256:" + hex.EncodeToString(sum[:])
		if digest != report.SHA256 {
			t.Fatalf("role report %q digest = %q, want %q", role, digest, report.SHA256)
		}
	}
}

type fakeZCodeObservation struct {
	Argv        []string `json:"argv"`
	CWD         string   `json:"cwd"`
	Prompt      string   `json:"prompt"`
	Destination string   `json:"destination"`
}

func initializeReviewGitRepository(t *testing.T, directory string) {
	t.Helper()
	mustWriteTestFile(t, filepath.Join(directory, "roadmap.md"), []byte("# Roadmap\nReview the linked design.\n"))
	mustWriteTestFile(t, filepath.Join(directory, "docs", "linked.md"), []byte("# Linked design\nThe review must preserve immutable inputs.\n"))
	mustWriteTestFile(t, filepath.Join(directory, "review.go"), []byte("package review\n\nconst state = \"before\"\n"))
	runTestCommand(t, directory, "git", "init")
	runTestCommand(t, directory, "git", "add", ".")
	runTestCommand(t, directory, "git", "-c", "user.name=Mulgae E2E", "-c", "user.email=mulgae-e2e@example.invalid", "commit", "-m", "baseline")
	mustWriteTestFile(t, filepath.Join(directory, "review.go"), []byte("package review\n\nconst state = \"after\"\n"))
}

// stagedOutputDestinationMarker is the exact Mulgae-owned trusted layer line
// that precedes the single absolute path a staged review launch may write. It
// is duplicated here on purpose: the fake provider must recognize the shipped
// contract text, not a constant it shares with the implementation.
const stagedOutputDestinationMarker = "Write your complete final Markdown role report to this exact absolute file path, creating that one file only:"

// fakeZCodeStagedReportTemplate is the exact Markdown body the fake ZCode
// stages for one role. The generated fake substitutes __ROLE__ with the role
// its launch prompt names, so a published role report can be compared byte for
// byte against fakeZCodeStagedReport.
const fakeZCodeStagedReportTemplate = "# __ROLE__ role report\n\n" +
	"Staged file transport carried this __ROLE__ body.\n\n" +
	"```json\n" +
	"{\"schema_version\":\"mulgae-provider-review-output.v1\",\"summary\":\"No __ROLE__ findings.\"," +
	"\"completeness\":\"complete\",\"limitations\":[],\"findings\":[]}\n" +
	"```\n"

// fakeZCodeIgnoredStdout is the session envelope the fake ZCode prints on
// standard output for every review launch. The staged_file transport ignores
// standard output for acceptance, so this text must never reach a published
// role report.
const fakeZCodeIgnoredStdout = "{\"schema_version\":\"mulgae-provider-review-output.v1\"," +
	"\"summary\":\"Standard output is ignored under the staged file transport.\"," +
	"\"completeness\":\"complete\",\"limitations\":[],\"findings\":[]}"

func fakeZCodeStagedReport(role string) string {
	return strings.ReplaceAll(fakeZCodeStagedReportTemplate, "__ROLE__", role)
}

func buildFakeZCode(t *testing.T, root, binary, launcher, logPath, mode string) {
	t.Helper()
	buildFakeZCodeWithStagedOutputAndBarrier(t, root, binary, launcher, logPath, mode, "write", "")
}

func fakeZCodeAppPaths(root string) (string, string, string) {
	bundle := filepath.Join(root, "ZCode.app")
	return bundle,
		filepath.Join(bundle, "Contents", "MacOS", "ZCode"),
		filepath.Join(bundle, "Contents", "Resources", "glm", "zcode.cjs")
}

func buildFakeZCodeWithBarrier(t *testing.T, root, binary, launcher, logPath, barrier string) {
	t.Helper()
	buildFakeZCodeWithStagedOutputAndBarrier(t, root, binary, launcher, logPath, "success", "write", barrier)
}

// buildFakeZCodeWithStagedOutput builds the offline ZCode fake. staged selects
// how the fake honours the Mulgae-owned staged output destination its review
// prompt states: "write" stages exactly the one role report Mulgae granted,
// "none" stages nothing, "symlink" stages a symbolic link to a report the fake
// also writes outside staging, and "extra" stages a second file beside the
// report. Every variant still prints the ignored stdout session envelope.
func buildFakeZCodeWithStagedOutput(t *testing.T, root, binary, launcher, logPath, mode, staged string) {
	t.Helper()
	buildFakeZCodeWithStagedOutputAndBarrier(t, root, binary, launcher, logPath, mode, staged, "")
}

func buildFakeZCodeWithStagedOutputAndBarrier(t *testing.T, root, binary, launcher, logPath, mode, staged, barrier string) {
	t.Helper()
	mustWriteTestFile(t, launcher, []byte("// offline fake ZCode launcher\n"))
	mustWriteTestFile(t, filepath.Join(filepath.Dir(launcher), "..", "config", "provider", "zcode-builtin.json"), []byte(`{"schemaVersion":1,"revision":30,"config":{"providerConfigRules":{"providerRules":[{"providerId":"account:zai-individual-coding-plan","config":{"builtinModelIds":["GLM-5.3","GLM-5.3-Flash"],"access":{"type":"zhipu-account","mode":"individual-coding-plan","accountType":"zai"}}}]}}}
`))
	mustWriteTestFile(t, filepath.Join(filepath.Dir(filepath.Dir(binary)), "Info.plist"), []byte(`<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>CFBundleShortVersionString</key><string>3.12.3</string></dict></plist>
`))
	source := filepath.Join(t.TempDir(), "main.go")
	program := `package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type observation struct {
	Argv        []string ` + "`json:\"argv\"`" + `
	CWD         string   ` + "`json:\"cwd\"`" + `
	Prompt      string   ` + "`json:\"prompt\"`" + `
	Destination string   ` + "`json:\"destination,omitempty\"`" + `
}

const destinationMarker = "__FAKE_ZCODE_DESTINATION_MARKER__"
const barrierDirectory = __FAKE_ZCODE_BARRIER__

var roleGuide = regexp.MustCompile("Mulgae ROOT REVIEW ROLE GUIDE/[0-9]+: ([A-Z]+)")

func main() {
	argv := append([]string(nil), os.Args[1:]...)
	if len(argv) == 2 && argv[1] == "--version" {
		fmt.Println("22.14.0")
		return
	}
	if len(argv) != 3 || argv[1] != "app-server" || argv[2] != "--stdio" {
		panic("non-canonical ZCode invocation")
	}
	serve(argv)
}

// serve speaks the ZCode app-server protocol on stdio: one session per
// process, the packet as the single turn's content, and the staged report or
// controlled qualification proof produced before turn completion.
func serve(argv []string) {
	sessionID := "sess_fake"
	var prompt, mode, denylist, proof string
	capability, accountConfigured, authAccepted, modelSelected := false, false, false, false
	stdout := bufio.NewWriter(os.Stdout)
	defer stdout.Flush()
	reply := func(id json.RawMessage, result any) {
		payload, err := json.Marshal(map[string]any{"id": id, "result": result})
		if err != nil {
			panic(err)
		}
		fmt.Fprintln(stdout, string(payload))
		stdout.Flush()
	}
	notifyTurn := func(kind string) {
		payload, err := json.Marshal(map[string]any{
			"method": "computer-use/operation-event",
			"params": map[string]any{"kind": kind, "turnId": "turn_fake", "sessionId": sessionID},
		})
		if err != nil {
			panic(err)
		}
		fmt.Fprintln(stdout, string(payload))
		stdout.Flush()
	}
	serverRequest := func(id, method string, params any) {
		payload, err := json.Marshal(map[string]any{"id": id, "method": method, "params": params})
		if err != nil {
			panic(err)
		}
		fmt.Fprintln(stdout, string(payload))
		stdout.Flush()
	}
	reader := bufio.NewReader(os.Stdin)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		var message struct {
			ID     json.RawMessage ` + "`json:\"id\"`" + `
			Method string          ` + "`json:\"method\"`" + `
			Params json.RawMessage ` + "`json:\"params\"`" + `
		}
		if json.Unmarshal([]byte(line), &message) != nil {
			panic("unparseable protocol message")
		}
		if message.Method == "" {
			var response struct {
				ID string ` + "`json:\"id\"`" + `
				Result struct {
					HeadersApplied bool ` + "`json:\"headersApplied\"`" + `
					RequestAuth struct { APIKey string ` + "`json:\"apiKey\"`" + ` } ` + "`json:\"requestAuth\"`" + `
				} ` + "`json:\"result\"`" + `
			}
			if json.Unmarshal([]byte(line), &response) != nil {
				panic("unparseable protocol response")
			}
			if response.ID == "server-auth" {
				if !response.Result.HeadersApplied || response.Result.RequestAuth.APIKey != "fake-zcode-api-key" {
					panic("invalid ZCode runtime auth response")
				}
				authAccepted = true
			}
			continue
		}
		switch message.Method {
		case "provider/updateAccountConfig":
			var params struct {
				Revision string ` + "`json:\"revision\"`" + `
				States map[string]struct { Current bool ` + "`json:\"current\"`" + ` } ` + "`json:\"states\"`" + `
			}
			if json.Unmarshal(message.Params, &params) != nil || params.Revision == "" || !params.States["account:zai-individual-coding-plan"].Current {
				panic("non-canonical ZCode account configuration")
			}
			accountConfigured = true
			reply(message.ID, map[string]any{"receivedRevision": params.Revision, "providerCount": 1})
		case "session/create":
			var params struct {
				Mode         string   ` + "`json:\"mode\"`" + `
				ToolDenylist []string ` + "`json:\"toolDenylist\"`" + `
			}
			if json.Unmarshal(message.Params, &params) != nil || params.Mode == "" || len(params.ToolDenylist) == 0 || !accountConfigured {
				panic("non-canonical ZCode session create")
			}
			mode = params.Mode
			denylist = strings.Join(params.ToolDenylist, ",")
			modelSelected = true
			serverRequest("server-1", "session/requestRuntimePreferences", map[string]any{
				"sessionId": sessionID,
				"scope":     "runtime-materialization",
			})
			serverRequest("server-auth", "interaction/requestProviderRuntimeHeaders", map[string]any{
				"providerId": "account:zai-individual-coding-plan",
				"accountAccess": map[string]any{"type": "zhipu-account", "mode": "individual-coding-plan", "accountType": "zai"},
			})
			reply(message.ID, map[string]any{
				"session": map[string]any{"sessionId": sessionID},
				"settings": map[string]any{"model": map[string]any{"available": []any{
					map[string]any{"ref": map[string]any{"providerId": "account:zai-individual-coding-plan", "modelId": "GLM-5.3"}, "reasoning": map[string]any{"defaultLevel": "max"}},
					map[string]any{"ref": map[string]any{"providerId": "account:zai-individual-coding-plan", "modelId": "GLM-5.3-Flash"}, "reasoning": map[string]any{"defaultLevel": "max"}},
				}}},
			})
		case "session/setModel":
			var params struct {
				SessionID string ` + "`json:\"sessionId\"`" + `
				Model struct {
					ProviderID string ` + "`json:\"providerId\"`" + `
					ModelID string ` + "`json:\"modelId\"`" + `
					Options struct { ReasoningLevel string ` + "`json:\"reasoningLevel\"`" + ` } ` + "`json:\"options\"`" + `
				} ` + "`json:\"model\"`" + `
			}
			if json.Unmarshal(message.Params, &params) != nil || params.SessionID != sessionID || params.Model.ProviderID != "account:zai-individual-coding-plan" || params.Model.ModelID == "" || params.Model.Options.ReasoningLevel != "max" {
				panic("non-canonical ZCode model selection")
			}
			modelSelected = true
			selection := map[string]any{"providerId": params.Model.ProviderID, "modelId": params.Model.ModelID, "options": map[string]any{"reasoningLevel": params.Model.Options.ReasoningLevel}}
			reply(message.ID, map[string]any{
				"protocol": map[string]any{"name": "ZCode Protocol", "version": 1},
				"session": map[string]any{"sessionId": sessionID, "model": selection},
				"settings": map[string]any{"model": map[string]any{"current": selection}},
			})
		case "session/send":
			var params struct {
				SessionID string ` + "`json:\"sessionId\"`" + `
				Content   string ` + "`json:\"content\"`" + `
			}
			if json.Unmarshal(message.Params, &params) != nil || params.Content == "" || !authAccepted || !modelSelected {
				panic("non-canonical ZCode session send")
			}
			prompt = params.Content
			capability = strings.Contains(prompt, "Prove readiness by returning exactly one JSON object and nothing else.")
			if capability {
				if mode != "plan" || denylist != "*" {
					panic("non-canonical ZCode capability conversation")
				}
			} else if mode != "yolo" || !strings.Contains(denylist, "Bash") || strings.Contains(denylist, "Write") {
				panic("non-canonical ZCode review conversation")
			}
			destination := stagedDestination(prompt)
			cwd, cwdErr := os.Getwd()
			if cwdErr != nil {
				panic(cwdErr)
			}
			log, logErr := os.OpenFile("__FAKE_ZCODE_LOG__", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
			if logErr != nil {
				panic(logErr)
			}
			if encodeErr := json.NewEncoder(log).Encode(observation{Argv: argv, CWD: cwd, Prompt: prompt, Destination: destination}); encodeErr != nil {
				panic(encodeErr)
			}
			if closeErr := log.Close(); closeErr != nil {
				panic(closeErr)
			}
			reply(message.ID, map[string]any{"accepted": true, "sessionId": sessionID, "stateRevision": 1})
			if capability {
				proof = capabilityProof(prompt)
				notifyTurn("turn-completed")
				continue
			}
			if destination == "" {
				// The structured extraction trailer runs without a staged
				// destination and returns exact JSON as the assistant text.
				proof = __FAKE_ZCODE_STDOUT__
				notifyTurn("turn-completed")
				continue
			}
			if !reviewFailureVariant(prompt) {
				if "__FAKE_ZCODE_MODE__" == "reject_child_qualification" {
					if writeErr := os.WriteFile("__FAKE_ZCODE_LOG__.reviewed", []byte("reviewed"), 0600); writeErr != nil {
						panic(writeErr)
					}
				}
				waitForPeer()
				stage(destination, report(prompt))
			}
			notifyTurn("turn-completed")
		case "session/messages":
			reply(message.ID, map[string]any{
				"messages": []any{map[string]any{
					"info":  map[string]any{"role": "assistant"},
					"parts": []any{map[string]any{"type": "text", "text": proof}},
				}},
			})
		case "session/close":
			reply(message.ID, map[string]any{"closed": true})
		default:
			panic("unexpected ZCode protocol method " + message.Method)
		}
	}
}

// capabilityProof extracts the controlled qualification binding from the
// packet and returns the JSON object a real provider would answer with.
func capabilityProof(prompt string) string {
	if "__FAKE_ZCODE_MODE__" == "reject_child_qualification" {
		if _, err := os.Stat("__FAKE_ZCODE_LOG__.reviewed"); err == nil {
			return "Qualification response omitted fixture bindings."
		}
	}
	root := regexp.MustCompile("(?:root must be |root=)([0-9a-f]{64})").FindStringSubmatch(prompt)
	link := regexp.MustCompile("(?:link must be |link=)([^\\s;]+)").FindStringSubmatch(prompt)
	role := regexp.MustCompile("(?:role must be |role=)([a-z]+)").FindStringSubmatch(prompt)
	if len(root) != 2 || len(link) != 2 || len(role) != 2 {
		panic("native qualification reference did not resolve")
	}
	return fmt.Sprintf("{\"root\":%q,\"link\":%q,\"role\":%q}", root[1], link[1], role[1])
}

// reviewFailureVariant applies the configured simulated review failure and
// reports whether the conversation failed instead of staging a report.
func reviewFailureVariant(prompt string) bool {
 role := roleGuide.FindStringSubmatch(prompt)
 if len(role) == 2 && "__FAKE_ZCODE_MODE__" == "wait_twice_documentation" && strings.ToLower(role[1]) == "documentation" {
  for index := 1; index <= 2; index++ {
   marker, err := os.OpenFile(fmt.Sprintf("__FAKE_ZCODE_LOG__.waiting.%d", index), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
   if err == nil {
    if err := marker.Close(); err != nil { panic(err) }
    for { time.Sleep(time.Second) }
   }
   if !os.IsExist(err) { panic(err) }
  }
 }
 if len(role) == 2 && "__FAKE_ZCODE_MODE__" == "fail_first_"+strings.ToLower(role[1]) {
		for attempt := 1; attempt <= 2; attempt++ {
			marker, err := os.OpenFile(fmt.Sprintf("__FAKE_ZCODE_LOG__.failed.%d", attempt), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if err == nil {
				if err := marker.Close(); err != nil {
					panic(err)
				}
				fmt.Fprintln(os.Stderr, "provider execution failed")
				os.Exit(1)
			}
			if !os.IsExist(err) {
				panic(err)
			}
		}
	}
	switch "__FAKE_ZCODE_MODE__" {
	case "rate_limit_review":
		fmt.Fprintln(os.Stderr, "rate_limit")
		os.Exit(1)
	case "login_review":
		fmt.Fprintln(os.Stderr, "zcode login required")
		os.Exit(1)
	case "fail_review":
		fmt.Fprintln(os.Stderr, "provider execution failed")
		os.Exit(1)
	}
	return false
}

func waitForPeer() {
	if barrierDirectory == "" {
		return
	}
	marker := filepath.Join(barrierDirectory, fmt.Sprintf("%d.ready", os.Getpid()))
	if err := os.WriteFile(marker, []byte("ready\n"), 0600); err != nil {
		panic(err)
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		entries, err := os.ReadDir(barrierDirectory)
		if err != nil {
			panic(err)
		}
		ready := 0
		for _, entry := range entries {
			if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".ready") {
				ready++
			}
		}
		if ready >= 2 {
			return
		}
		if time.Now().After(deadline) {
			panic("peer review provider did not start concurrently")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// stagedDestination returns the one absolute path the last trusted layer of a
// staged launch states. A prompt without that layer returns the empty string.
func stagedDestination(prompt string) string {
	index := strings.Index(prompt, destinationMarker)
	if index < 0 {
		return ""
	}
	line := strings.TrimPrefix(prompt[index+len(destinationMarker):], "\n")
	if end := strings.IndexByte(line, '\n'); end >= 0 {
		line = line[:end]
	}
	destination := strings.TrimSpace(line)
	if !filepath.IsAbs(destination) || filepath.Clean(destination) != destination ||
		filepath.Base(destination) != "role-report.md" {
		panic("staged output destination is not a canonical absolute role report path")
	}
	return destination
}

// report is the Markdown body this fake stages for the role its launch prompt
// names. Standard output never carries it.
func report(prompt string) string {
	role := roleGuide.FindStringSubmatch(prompt)
	if len(role) != 2 {
		panic("ZCode review prompt omits the role guide")
	}
	return strings.ReplaceAll(__FAKE_ZCODE_STAGED_BODY__, "__ROLE__", strings.ToLower(role[1]))
}

// stage writes the report exactly as the configured staging behaviour requires.
// Mulgae created the staging directory before this process started.
func stage(destination, body string) {
	switch "__FAKE_ZCODE_STAGED__" {
	case "none":
		return
	case "symlink":
		outside := filepath.Join(filepath.Dir("__FAKE_ZCODE_LOG__"), "smuggled-role-report.md")
		if err := os.WriteFile(outside, []byte(body), 0600); err != nil {
			panic(err)
		}
		if err := os.Symlink(outside, destination); err != nil {
			panic(err)
		}
		return
	case "extra":
		if err := os.WriteFile(destination, []byte(body), 0600); err != nil {
			panic(err)
		}
		if err := os.WriteFile(filepath.Join(filepath.Dir(destination), "extra-notes.md"), []byte(body), 0600); err != nil {
			panic(err)
		}
		return
	}
	if err := os.WriteFile(destination, []byte(body), 0600); err != nil {
		panic(err)
	}
}
`
	program = strings.ReplaceAll(program, "__FAKE_ZCODE_DESTINATION_MARKER__", stagedOutputDestinationMarker)
	program = strings.ReplaceAll(program, "__FAKE_ZCODE_BARRIER__", strconv.Quote(barrier))
	program = strings.ReplaceAll(program, "__FAKE_ZCODE_STAGED_BODY__", strconv.Quote(fakeZCodeStagedReportTemplate))
	program = strings.ReplaceAll(program, "__FAKE_ZCODE_STDOUT__", strconv.Quote(fakeZCodeIgnoredStdout))
	program = strings.ReplaceAll(program, "__FAKE_ZCODE_LOG__", logPath)
	program = strings.ReplaceAll(program, "__FAKE_ZCODE_MODE__", mode)
	program = strings.ReplaceAll(program, "__FAKE_ZCODE_STAGED__", staged)
	mustWriteTestFile(t, source, []byte(program))
	build := exec.Command("go", "build", "-o", binary, source)
	build.Dir = root
	build.Env = append(os.Environ(), "GOPROXY=off", "GOSUMDB=off", "GOCACHE="+t.TempDir())
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build fake ZCode: %v\n%s", err, output)
	}
}

func readFakeZCodeObservations(t *testing.T, path string) []fakeZCodeObservation {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fake ZCode observations: %v", err)
	}
	var observations []fakeZCodeObservation
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var observation fakeZCodeObservation
		if err := json.Unmarshal([]byte(line), &observation); err != nil {
			t.Fatalf("decode fake ZCode observation %q: %v", line, err)
		}
		observations = append(observations, observation)
	}
	return observations
}

// fakeZCodeReviewObservations returns only the review launches of the fake
// ZCode: capability probes carry no staged destination and are excluded.
func fakeZCodeReviewObservations(t *testing.T, path string) []fakeZCodeObservation {
	t.Helper()
	reviews := make([]fakeZCodeObservation, 0, 2)
	for _, observation := range readFakeZCodeObservations(t, path) {
		if len(observation.Argv) == 2 && observation.Argv[1] == "--version" {
			continue
		}
		if strings.Contains(observation.Prompt, "Prove readiness by returning exactly one JSON object and nothing else.") {
			continue
		}
		reviews = append(reviews, observation)
	}
	return reviews
}

func mustWriteTestFile(t *testing.T, path string, contents []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatalf("create test file directory %q: %v", path, err)
	}
	if err := os.WriteFile(path, contents, 0600); err != nil {
		t.Fatalf("write test file %q: %v", path, err)
	}
}

func runTestCommand(t *testing.T, directory, name string, arguments ...string) {
	t.Helper()
	command := exec.Command(name, arguments...)
	command.Dir = directory
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("run %s %q: %v\n%s", name, arguments, err, output)
	}
}

func assertNullResultFields(t *testing.T, result map[string]json.RawMessage, fields []string) {
	t.Helper()
	for _, field := range fields {
		if got, present := result[field]; !present || !bytes.Equal(got, []byte("null")) {
			t.Fatalf("result.%s = %s, want exact null", field, got)
		}
	}
}
func buildMulgaeBinary(t *testing.T, root string) string {
	t.Helper()
	if binary := os.Getenv("MULGAE_E2E_BINARY"); binary != "" {
		if info, err := os.Stat(binary); err != nil || info.IsDir() || info.Mode()&0o111 == 0 {
			t.Fatalf("MULGAE_E2E_BINARY is not an executable file: %q: %v", binary, err)
		}
		return binary
	}
	buildDirectory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(buildDirectory, "mulgae")
	nativeHome := binary + ".native-home"
	if err := os.Mkdir(nativeHome, 0700); err != nil {
		t.Fatal(err)
	}
	ldflags := "-X main.buildVersion=v1.4.2 -X main.buildRevision=0123456789abcdef0123456789abcdef01234567 -X github.com/irootkernel/mulgae/internal/adapters/environment.buildNativeHomeOverride=" + nativeHome
	build := exec.Command("go", "build", "-ldflags", ldflags, "-o", binary, ".")
	build.Dir = root
	build.Env = append(os.Environ(), "GOPROXY=off", "GOSUMDB=off", "GOCACHE="+t.TempDir())
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build Mulgae binary: %v\n%s", err, output)
	}
	return binary
}

func integrationNativeHome(t *testing.T, binary string) string {
	t.Helper()
	isolated := binary + ".native-home"
	if info, err := os.Stat(isolated); err == nil && info.IsDir() {
		writeFakeZCodeAccountState(t, isolated)
		return isolated
	}
	t.Fatalf("isolated native home unavailable beside E2E binary: %q", isolated)
	return ""
}

func writeFakeZCodeAccountState(t *testing.T, home string) {
	t.Helper()
	v2 := filepath.Join(home, ".zcode", "v2")
	if err := os.MkdirAll(v2, 0700); err != nil {
		t.Fatalf("create fake ZCode account state: %v", err)
	}
	mustWriteTestFile(t, filepath.Join(v2, "setting.json"), []byte(`{"providerFamilyDomain":"zai","providerFamilyConnectionSelections":{"zai":{"kind":"individual-coding-plan"}}}
`))
	credentials := map[string]string{
		"oauth:zai:user_info": `{"user_id":"fake-account"}`,
		"account-provider:coding-plan:account:zai-individual-coding-plan:account:fake-account:api-key": "fake-zcode-api-key",
	}
	encoded, err := json.Marshal(credentials)
	if err != nil {
		t.Fatal(err)
	}
	mustWriteTestFile(t, filepath.Join(v2, "credentials.json"), encoded)
}

func mustAssetID(t *testing.T, value string) ports.AssetID {
	t.Helper()
	id, err := ports.ParseAssetID(value)
	if err != nil {
		t.Fatalf("parse asset ID %q: %v", value, err)
	}
	return id
}

func terminalLF(value []byte) []byte {
	return append(bytes.TrimRight(append([]byte(nil), value...), "\n"), '\n')
}

func readE2EConfig(t *testing.T, project string) adapterconfig.Config {
	t.Helper()
	projectData, err := os.ReadFile(filepath.Join(project, ".mulgae", "config.yaml"))
	if err != nil {
		t.Fatalf("read project config: %v", err)
	}
	localData, err := os.ReadFile(filepath.Join(project, ".mulgae", "local.yaml"))
	if err != nil {
		t.Fatalf("read local config: %v", err)
	}
	config, err := adapterconfig.DecodeSplit(projectData, localData)
	if err != nil {
		t.Fatalf("decode Config v2 pair: %v", err)
	}
	return config
}

type binaryResult struct {
	stdout   []byte
	stderr   []byte
	exitCode int
}

type runningBinary struct {
	command *exec.Cmd
	stdout  bytes.Buffer
	stderr  bytes.Buffer
}

func runMulgaeBinary(t *testing.T, binary, workingDirectory string, arguments ...string) binaryResult {
	t.Helper()
	return runMulgaeBinaryWithEnv(t, binary, workingDirectory, isolatedMulgaeEnv(t), arguments...)
}

func runMulgaeBinaryWithEnv(t *testing.T, binary, workingDirectory string, environment []string, arguments ...string) binaryResult {
	t.Helper()
	command := exec.Command(binary, arguments...)
	command.Dir = workingDirectory
	command.Env = environment
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	result := binaryResult{stdout: stdout.Bytes(), stderr: stderr.Bytes()}
	if err == nil {
		return result
	}
	var exitError *exec.ExitError
	if !errors.As(err, &exitError) {
		t.Fatalf("run Mulgae %q: %v", arguments, err)
	}
	result.exitCode = exitError.ExitCode()
	return result
}

func startMulgaeBinaryWithEnv(t *testing.T, ctx context.Context, binary, workingDirectory string, environment []string, arguments ...string) *runningBinary {
	t.Helper()
	running := &runningBinary{command: exec.CommandContext(ctx, binary, arguments...)}
	running.command.Dir = workingDirectory
	running.command.Env = environment
	running.command.Stdout = &running.stdout
	running.command.Stderr = &running.stderr
	if err := running.command.Start(); err != nil {
		t.Fatalf("start Mulgae %q: %v", arguments, err)
	}
	return running
}

func waitMulgaeBinary(t *testing.T, running *runningBinary) binaryResult {
	t.Helper()
	if running == nil || running.command == nil {
		t.Fatal("wait for nil Mulgae process")
	}
	err := running.command.Wait()
	result := binaryResult{stdout: running.stdout.Bytes(), stderr: running.stderr.Bytes()}
	if err == nil {
		return result
	}
	var exitError *exec.ExitError
	if !errors.As(err, &exitError) {
		t.Fatalf("wait for Mulgae: %v", err)
	}
	result.exitCode = exitError.ExitCode()
	return result
}

func assertSuccessfulConcurrentReview(t *testing.T, project string, result binaryResult) commandEnvelope {
	t.Helper()
	if result.exitCode != 0 || len(result.stderr) != 0 {
		t.Fatalf("concurrent review = exit %d stdout %q stderr %q", result.exitCode, result.stdout, result.stderr)
	}
	var envelope commandEnvelope
	if err := json.Unmarshal(result.stdout, &envelope); err != nil {
		t.Fatalf("decode concurrent review: %v: %q", err, result.stdout)
	}
	if envelope.Exit.Code != 0 || envelope.Exit.Kind != "success" ||
		envelope.Result.SessionID == nil || envelope.Result.RunID == nil ||
		envelope.Result.RunManifestURI == nil || envelope.Result.ReviewArtifactURI == nil {
		t.Fatalf("concurrent review did not publish a successful result: %#v", envelope)
	}
	assertCommandRoleReportInventory(t, project, envelope)
	return envelope
}

func isolatedMulgaeEnv(t *testing.T) []string {
	t.Helper()
	root := t.TempDir()
	return []string{
		"HOME=" + root,
		"TMPDIR=" + root,
		"XDG_CACHE_HOME=" + root,
		"XDG_CONFIG_HOME=" + root,
		"PATH=/usr/bin:/bin:/usr/sbin:/sbin",
		"NO_PROXY=*",
		"GOPROXY=off",
		"GOSUMDB=off",
	}
}
func isolatedMulgaeEnvWith(t *testing.T, home, providerDirectory string) []string {
	t.Helper()
	return []string{
		"HOME=" + home,
		"TMPDIR=" + canonicalTestTempDir(t),
		"XDG_CACHE_HOME=" + canonicalTestTempDir(t),
		"XDG_CONFIG_HOME=" + canonicalTestTempDir(t),
		"PATH=" + providerDirectory + ":/usr/bin",
		"NO_PROXY=*",
		"GOPROXY=off",
		"GOSUMDB=off",
	}
}

func sharedMulgaeProcessEnv(t *testing.T, home, providerDirectory, runtimeRoot string, useXDG bool) []string {
	t.Helper()
	environment := []string{
		"HOME=" + home,
		"TMPDIR=" + runtimeRoot,
		"XDG_CACHE_HOME=" + canonicalTestTempDir(t),
		"XDG_CONFIG_HOME=" + canonicalTestTempDir(t),
		"PATH=" + providerDirectory + ":/usr/bin",
		"NO_PROXY=*",
		"GOPROXY=off",
		"GOSUMDB=off",
	}
	if useXDG {
		return append(environment, "XDG_RUNTIME_DIR="+runtimeRoot)
	}
	return append(environment, "XDG_RUNTIME_DIR=")
}

func uniqueStrings(values ...string) []string {
	seen := make(map[string]bool, len(values))
	unique := make([]string, 0, len(values))
	for _, value := range values {
		if !seen[value] {
			seen[value] = true
			unique = append(unique, value)
		}
	}
	return unique
}

func clearProviderBarrier(t *testing.T, barrier string) {
	t.Helper()
	entries, err := os.ReadDir(barrier)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".ready") {
			t.Fatalf("unexpected provider barrier entry %q", entry.Name())
		}
		if err := os.Remove(filepath.Join(barrier, entry.Name())); err != nil {
			t.Fatal(err)
		}
	}
}

func canonicalTestTempDir(t *testing.T) string {
	t.Helper()
	path, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Clean(path)
}

func assertNoProjectProviderLocks(t *testing.T, project string) {
	t.Helper()
	if _, err := os.Lstat(filepath.Join(project, "locks")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Mulgae created a provider-lock namespace in the review target: %v", err)
	}
}

func assertNoGlobalProviderLockNamespace(t *testing.T, runtimeRoot string, useXDG bool) {
	t.Helper()
	for _, path := range []string{
		filepath.Join(runtimeRoot, "mulgae"),
		filepath.Join(runtimeRoot, "mulgae-"+strconv.Itoa(os.Geteuid())),
	} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("Mulgae created global provider lock namespace %q (XDG=%t): %v", path, useXDG, err)
		}
	}
	entries, err := os.ReadDir(runtimeRoot)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".mulgae-lane-") && strings.HasSuffix(entry.Name(), ".guard") {
			t.Fatalf("Mulgae created global provider lock guard %q (XDG=%t)", entry.Name(), useXDG)
		}
	}
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	workingDirectory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	root, err := filepath.Abs(filepath.Join(workingDirectory, "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("repository root %q: %v", root, err)
	}
	return root
}

type compositionProjectReader struct {
	commit  ports.GitObjectID
	readErr error
	reads   int
}

func (reader *compositionProjectReader) ResolveCommit(context.Context, ports.AnchoredRoot, string) (ports.GitObjectID, error) {
	return reader.commit, nil
}

func (reader *compositionProjectReader) ReadFileAtCommit(context.Context, ports.AnchoredRoot, ports.GitObjectID, ports.SafeRelativePath) ([]byte, error) {
	reader.reads++
	return nil, reader.readErr
}

func TestIntegrationChildQualificationFailureRetainsPrivateDiagnostics(t *testing.T) {
	repository := repositoryRoot(t)
	binary := buildMulgaeBinary(t, repository)
	project := canonicalTestTempDir(t)
	initializeReviewGitRepository(t, project)
	nativeHome := integrationNativeHome(t, binary)
	providerDirectory := canonicalTestTempDir(t)
	appBundle, node, launcher := fakeZCodeAppPaths(providerDirectory)
	buildFakeZCode(t, repository, node, launcher, filepath.Join(canonicalTestTempDir(t), "zcode.jsonl"), "reject_child_qualification")
	environment := isolatedMulgaeEnvWith(t, nativeHome, providerDirectory)
	initialized := runMulgaeBinaryWithEnv(t, binary, project, environment, "init", "--providers", "zcode", "--roles", "logic", "--zcode-app-bundle", appBundle)
	if initialized.exitCode != 0 {
		t.Fatalf("init failed: exit=%d stdout=%s stderr=%s", initialized.exitCode, initialized.stdout, initialized.stderr)
	}
	root := runMulgaeBinaryWithEnv(t, binary, project, environment, "review", "--dirty", "--roles", "logic", "--output", "json")
	var parent commandEnvelope
	if err := json.Unmarshal(root.stdout, &parent); err != nil {
		t.Fatal(err)
	}
	if root.exitCode != 0 || parent.Result.RunID == nil {
		t.Fatalf("root failed: %s", root.stdout)
	}
	rootLog := readRuntimeDiagnosticLog(t, project, *parent.Result.SessionID, *parent.Result.RunID)
	candidates := 0
	for _, line := range bytes.Split(bytes.TrimSpace(rootLog), []byte("\n")) {
		var event struct{ Event, Provider, Outcome string }
		if err := json.Unmarshal(line, &event); err != nil {
			t.Fatal(err)
		}
		if event.Event == "qualification_candidate_checked" {
			candidates++
			if event.Provider != "zcode-logic" || event.Outcome != "qualified" {
				t.Fatalf("probe I/O misrepresented as admission: %+v", event)
			}
		}
	}
	if candidates != 1 {
		t.Fatalf("qualification decisions = %d, want 1", candidates)
	}
	child := runMulgaeBinaryWithEnv(t, binary, project, environment, "delta", "--since-run", *parent.Result.RunID, "--dirty", "--roles", "logic", "--output", "json")
	var rejected commandEnvelope
	if err := json.Unmarshal(child.stdout, &rejected); err != nil {
		t.Fatal(err)
	}
	if child.exitCode != 4 || !commandEnvelopeHasReason(rejected, "provider_qualification_failed") || rejected.Result.RunID != nil || rejected.Result.SessionID != nil || rejected.Result.RunManifestURI != nil || rejected.Result.ReviewArtifactURI != nil {
		t.Fatalf("child qualification failure = %s stderr=%s", child.stdout, child.stderr)
	}
	var diagnosticURI string
	for _, reason := range rejected.Reasons {
		if reason.ArtifactURI != nil {
			diagnosticURI = *reason.ArtifactURI
		}
	}
	parts := strings.Split(diagnosticURI, "/")
	if len(parts) != 3 || parts[0] != "diagnostics" {
		t.Fatalf("missing diagnostic reference: %q", diagnosticURI)
	}
	sessionID, runID := parts[1], parts[2]
	if runID == *parent.Result.RunID || sessionID != *parent.Result.SessionID {
		t.Fatal("child diagnostic identity does not preserve lineage")
	}
	assertRuntimeDiagnosticStatus(t, project, sessionID, runID, domain.RunFailed, "")
	log := readRuntimeDiagnosticLog(t, project, sessionID, runID)
	if !bytes.Contains(log, []byte(`"operation":"capability"`)) || !bytes.Contains(log, []byte(`"exit_code":0`)) || !bytes.Contains(log, []byte(`"outcome":"rejected"`)) {
		t.Fatalf("missing qualification process diagnostics: %s", log)
	}
	base := filepath.Join(project, ".mulgae", "diagnostics", sessionID, runID, "qualification")
	files, err := filepath.Glob(filepath.Join(base, "*", "capability", "stdout.raw"))
	if err != nil || len(files) != 1 {
		t.Fatalf("retained capability streams = %v, err=%v", files, err)
	}
	body, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	// The capability stream is the protocol transcript; the qualification
	// evidence is the assistant text it carries, which the fake deliberately
	// omits fixture bindings from in this scenario.
	if !bytes.Contains(body, []byte(`"text":"Qualification response omitted fixture bindings."`)) {
		t.Fatalf("capability response was changed: %q", body)
	}
	info, err := os.Stat(files[0])
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("private stream permissions: %v %v", info, err)
	}
	for _, phase := range []string{"request", "version"} {
		files, err := filepath.Glob(filepath.Join(base, "*", phase, "stdout.raw"))
		if err != nil || len(files) != 1 {
			t.Fatalf("missing %s evidence: %v %v", phase, files, err)
		}
	}
	if bytes.Contains(child.stdout, []byte("Qualification response omitted")) {
		t.Fatal("raw response leaked to public result")
	}
}
