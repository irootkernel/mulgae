//go:build darwin && arm64

package e2e

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
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
					arguments := []string{"review", "--diff", "HEAD~1..HEAD", "--roles", "logic", "--objective", "Review the selected change.", "--output", "json"}
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

	arguments := []string{"review", "--diff", "HEAD~1..HEAD", "--roles", "logic", "--objective", "Review the selected change.", "--output", "json"}
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
			if readErr == nil && bytes.Contains(data, []byte(`"event":"coordinator_reduction_completed"`)) {
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
	// Reduction precedes provider drain, source closure and publication. Give
	// the process time to finish cleanup and enter the held lock's bounded
	// polling loop; the typed failure below verifies lock-wait cancellation.
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

func commandEnvelopeHasReason(envelope commandEnvelope, code string) bool {
	for _, reason := range envelope.Reasons {
		if reason.Code == code {
			return true
		}
	}
	return false
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
			report.Transport != "stdout" ||
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

// The offline provider returns this complete body through native assistant text.
const fakeZCodeReportTemplate = "# __ROLE__ role report\n\n" +
	"Native assistant transport carried this __ROLE__ body.\n\n" +
	"```json\n" +
	"{\"schema_version\":\"mulgae-provider-review-output.v1\",\"summary\":\"No __ROLE__ findings.\"," +
	"\"completeness\":\"complete\",\"limitations\":[],\"findings\":[]}\n" +
	"```\n"

func buildFakeZCode(t *testing.T, root, binary, launcher, logPath, mode string) {
	t.Helper()
	buildFakeZCodeWithReport(t, root, binary, launcher, logPath, mode, "", fakeZCodeReportTemplate)
}

func fakeZCodeAppPaths(root string) (string, string, string) {
	bundle := filepath.Join(root, "ZCode.app")
	return bundle,
		filepath.Join(bundle, "Contents", "MacOS", "ZCode"),
		filepath.Join(bundle, "Contents", "Resources", "glm", "zcode.cjs")
}

func buildFakeZCodeWithBarrier(t *testing.T, root, binary, launcher, logPath, barrier string) {
	t.Helper()
	buildFakeZCodeWithReport(t, root, binary, launcher, logPath, "success", barrier, fakeZCodeReportTemplate)
}

func buildFakeZCodeWithReport(t *testing.T, root, binary, launcher, logPath, mode, barrier, reportBody string) {
	t.Helper()
	startFakeZCodeObserver(t, logPath, barrier)
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
	"net"
	"os"
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
// process, the packet as the single turn's content, and assistant text or
// controlled qualification proof produced before turn completion.
func serve(argv []string) {
	sessionID := "sess_fake"
	var prompt, mode, denylist, proof string
	var allowlist []string
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
				ToolAllowlist []string ` + "`json:\"toolAllowlist\"`" + `
			}
			if json.Unmarshal(message.Params, &params) != nil || params.Mode == "" || len(params.ToolDenylist) == 0 || !accountConfigured {
				panic("non-canonical ZCode session create")
			}
			mode = params.Mode
			denylist = strings.Join(params.ToolDenylist, ",")
			allowlist = params.ToolAllowlist
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
			} else if mode != "plan" || !strings.Contains(denylist, "Write") || len(allowlist) != 4 {
				panic("non-canonical ZCode review conversation")
			}
			destination := ""
			if strings.Contains(prompt, "Write your complete final Markdown role report to this exact absolute file path") { panic("live review granted report-file output") }
			cwd, cwdErr := os.Getwd()
			if cwdErr != nil {
				panic(cwdErr)
			}
			observe(observation{Argv: argv, CWD: cwd, Prompt: prompt, Destination: destination}, false)
			reply(message.ID, map[string]any{"accepted": true, "sessionId": sessionID, "stateRevision": 1})
			if capability {
				proof = capabilityProof(prompt)
				notifyTurn("turn-completed")
				continue
			}
			if destination != "" { panic("live review granted report-file output") }
			if !reviewFailureVariant() {
				waitForPeer()
				proof = report(prompt)
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
	root := regexp.MustCompile("(?:root must be |root=)([0-9a-f]{64})").FindStringSubmatch(prompt)
	link := regexp.MustCompile("(?:link must be |link=)([^\\s;]+)").FindStringSubmatch(prompt)
	role := regexp.MustCompile("(?:role must be |role=)([a-z]+)").FindStringSubmatch(prompt)
	if len(root) != 2 || len(link) != 2 || len(role) != 2 {
		panic("native qualification reference did not resolve")
	}
	return fmt.Sprintf("{\"root\":%q,\"link\":%q,\"role\":%q}", root[1], link[1], role[1])
}

// reviewFailureVariant simulates a terminal provider failure or cancellation wait.
func reviewFailureVariant() bool {
	switch "__FAKE_ZCODE_MODE__" {
	case "wait_review":
		for { time.Sleep(time.Second) }
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

func observe(value observation, barrier bool) {
	connection, err := net.Dial("unix", "__FAKE_ZCODE_SOCKET__")
	if err != nil { panic(err) }
	defer connection.Close()
	if err := json.NewEncoder(connection).Encode(map[string]any{"observation": value, "barrier": barrier, "pid": os.Getpid()}); err != nil { panic(err) }
	var acknowledged bool
	if err := json.NewDecoder(connection).Decode(&acknowledged); err != nil || !acknowledged { panic("observer acknowledgement failed") }
}
func waitForPeer() {
	if barrierDirectory != "" { observe(observation{}, true) }
}

// report returns the complete assistant message for the requested role.
func report(prompt string) string {
	role := roleGuide.FindStringSubmatch(prompt)
	if len(role) != 2 {
		panic("ZCode review prompt omits the role guide")
	}
	return strings.ReplaceAll(__FAKE_ZCODE_REPORT_BODY__, "__ROLE__", strings.ToLower(role[1]))
}


`
	program = strings.ReplaceAll(program, "__FAKE_ZCODE_BARRIER__", strconv.Quote(barrier))
	program = strings.ReplaceAll(program, "__FAKE_ZCODE_REPORT_BODY__", strconv.Quote(reportBody))
	program = strings.ReplaceAll(program, "__FAKE_ZCODE_LOG__", logPath)
	program = strings.ReplaceAll(program, "__FAKE_ZCODE_SOCKET__", fakeZCodeObserverSocket(logPath))
	program = strings.ReplaceAll(program, "__FAKE_ZCODE_MODE__", mode)
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
	if len(data) == 0 {
		return observations
	}
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

func fakeZCodeObserverSocket(log string) string {
	sum := sha256.Sum256([]byte(log))
	return filepath.Join(os.TempDir(), "zcode-observer-"+hex.EncodeToString(sum[:8])+".sock")
}

func startFakeZCodeObserver(t *testing.T, logPath, barrierPath string) {
	t.Helper()
	listener, err := net.Listen("unix", fakeZCodeObserverSocket(logPath))
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	done := make(chan struct{})
	t.Cleanup(func() { _ = listener.Close(); <-done })
	go func() {
		defer close(done)
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer connection.Close()
				var err error
				var request struct {
					Observation fakeZCodeObservation
					Barrier     bool
					PID         int
				}
				if json.NewDecoder(connection).Decode(&request) != nil {
					return
				}
				mu.Lock()
				if request.Barrier {
					err = os.WriteFile(filepath.Join(barrierPath, strconv.Itoa(request.PID)+".ready"), []byte("ready"), 0600)
				} else {
					var file *os.File
					file, err = os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
					if err == nil {
						err = errors.Join(json.NewEncoder(file).Encode(request.Observation), file.Close())
					}
				}
				mu.Unlock()
				if err != nil {
					return
				}
				if request.Barrier {
					deadline := time.Now().Add(15 * time.Second)
					for time.Now().Before(deadline) {
						markers, readErr := filepath.Glob(filepath.Join(barrierPath, "*.ready"))
						if readErr == nil && len(markers) >= 2 {
							break
						}
						time.Sleep(10 * time.Millisecond)
					}
				}
				_ = json.NewEncoder(connection).Encode(true)
			}()
		}
	}()
}

func logFakeProviderPanic(t *testing.T, project string) {
	t.Helper()
	_ = filepath.WalkDir(filepath.Join(project, ".mulgae", "diagnostics"), func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() || !strings.Contains(entry.Name(), "stderr") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err == nil {
			for _, line := range bytes.Split(data, []byte{'\n'}) {
				if bytes.HasPrefix(line, []byte("panic:")) {
					t.Logf("fake provider panic: %s", line)
				}
			}
		}
		return nil
	})
}
