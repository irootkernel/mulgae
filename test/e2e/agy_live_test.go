//go:build darwin && arm64 && live_e2e && live_agy

package e2e

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"

	adapterconfig "github.com/irootkernel/mulgae/internal/adapters/config"
)

func TestE2EAgySingleAccountReleaseBinaryReview(t *testing.T) {
	scenario := beginLiveE2ELogScope(t, "scenario", "name=agy-single-account-release-binary-review")
	defer scenario.end()
	// This manually owned fixture is retained even on success. In particular,
	// no test cleanup may erase a namespace whose process drain is unverified.
	if os.Getenv("MULGAE_E2E_PROJECT_ROOT") == "" {
		t.Fatal("test-agy must supply a preserved project")
	}
	environment := liveE2EEnvironment{binary: requireLiveExecutable(t, "MULGAE_E2E_BINARY", "")}
	agy := requireLiveExecutable(t, "MULGAE_E2E_AGY_EXECUTABLE", "")
	agyBefore := agyFileDigest(t, agy)
	installed, err := user.LookupId(strconv.Itoa(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	token := filepath.Join(installed.HomeDir, ".gemini", "antigravity-cli", "antigravity-oauth-token")
	tokenBefore := agyTokenDigest(t, token)
	defer func() {
		if agyTokenDigest(t, token) != tokenBefore || agyFileDigest(t, agy) != agyBefore {
			t.Error("original AGY token or executable changed")
		}
	}()
	validator := newLiveE2EValidator(t)
	project := initializeLiveE2ERepository(t)
	if !strings.Contains(project, "(") {
		t.Fatal("test-agy requires a parenthesized project path")
	}
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	marker := "agy-source-read-" + hex.EncodeToString(nonce[:])
	if err := os.Mkdir(filepath.Join(project, "docs"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "docs", "Review (single account).md"),
		[]byte("# Source reading proof\n\n"+marker+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sourceBefore := agySourceDigests(t, project)
	defer func() {
		if !reflect.DeepEqual(sourceBefore, agySourceDigests(t, project)) {
			t.Error("original source or Git state changed")
		}
	}()
	runLiveMulgae(t, validator, environment, project, 0, "init", "--providers", "agy",
		"--roles", "documentation", "--agy-executable", agy, "--output", "json")
	config := readE2EConfig(t, project)
	if config.Providers.Agy == nil || config.Providers.Agy.Model != "" || config.Providers.Agy.ReasoningEffort != "" {
		t.Fatal("AGY init did not preserve native model and effort omission")
	}
	config.Providers.Agy.Timeout = "6m"
	config.Validation.Repair = adapterconfig.RepairConfig{}
	config.Validation.Extraction.Enabled = false
	config.Validation.Extraction.EnabledExplicit = true
	config.Resources.PrimaryRepairAttempts = 0
	config.Resources.RoleMaxInvocations = 2
	config.Resources.RunMaxInvocations = 2
	projectConfig, localConfig, err := adapterconfig.EncodeSplit(config)
	if err != nil {
		t.Fatal(err)
	}
	writeLiveExistingConfig(t, filepath.Join(project, ".mulgae", "config.yaml"), projectConfig)
	writeLiveExistingConfig(t, filepath.Join(project, ".mulgae", "local.yaml"), localConfig)
	runLiveMulgae(t, validator, environment, project, 0, "config", "--output", "json")
	runLiveMulgae(t, validator, environment, project, 0, "doctor", "--output", "json")
	expected := map[string]string{"documentation": "agy-documentation"}
	run, status, reason := runLiveRecoverableAttempt(t, validator, environment, project,
		"agy-single-account-release-binary-review", expected, validateLiveSingleInvocationGate, 1, 1,
		"review", "--workspace", "--roles", "documentation", "--output", "json",
		"--objective", "Read docs/Review (single account).md from the original source and reproduce its agy-source-read marker verbatim in your concise Markdown documentation report. The marker value is available only in that source file. Report only concrete documentation defects; no findings is valid.")
	if status != "passed" {
		t.Fatalf("single AGY review failed without an automatic retry: %s: %s", status, reason)
	}
	assertLiveRoleReportMarker(t, project, run, "documentation", marker)
	assertLiveRoleReportTransports(t, run, "AGY single-account review")
	assertAgyNaturalProcessTerminal(t, project, run)
	runID := run.manifest.RunID
	runLiveMulgae(t, validator, environment, project, 0, "status", "--run", runID, "--output", "json")
	inspection := runLiveMulgae(t, validator, environment, project, 0, "inspect", "--run", runID, "--output", "json")
	projectBinding := inspection.Result.Receipt.ProjectBinding
	if projectBinding == "" {
		t.Fatal("verified inspection has no project binding")
	}
	var rendered []byte
	for _, role := range []string{"", "documentation"} {
		arguments := []string{"read-report", "--run", runID}
		if role != "" {
			arguments = append(arguments, "--role", role)
		}
		var complete []byte
		binding := projectBinding
		var receipt, digest string
		for {
			chunk := runLiveMulgae(t, validator, environment, project, 0, append(arguments, "--output", "json")...).Result
			part := []byte(chunk.Content)
			if chunk.Encoding == "base64" {
				part, err = base64.StdEncoding.DecodeString(chunk.Content)
				if err != nil {
					t.Fatal(err)
				}
			}
			if receipt == "" {
				receipt, digest = chunk.PublicationReceipt, chunk.ContentSHA256
			}
			if binding == "" || receipt == "" || chunk.PublicationReceipt != receipt || chunk.ContentSHA256 != digest {
				t.Fatal("public report continuation identity changed")
			}
			complete = append(complete, part...)
			if chunk.NextOffset == nil {
				sum := sha256.Sum256(complete)
				if digest != "sha256:"+hex.EncodeToString(sum[:]) {
					t.Fatal("public report content digest mismatch")
				}
				if role == "" {
					if !bytes.Contains(complete, []byte("Source selection SHA-256")) {
						t.Fatal("rendered report lacks live-source provenance")
					}
					rendered = complete
				} else if !bytes.Contains(complete, []byte(marker)) {
					t.Fatal("public role report lacks the source-only marker")
				}
				break
			}
			if *chunk.NextOffset != int64(len(complete)) || len(part) == 0 {
				t.Fatal("public report continuation made no progress")
			}
			arguments = []string{"read-report", "--run", runID, "--offset", strconv.FormatInt(*chunk.NextOffset, 10),
				"--expected-project-binding", binding, "--expected-publication-receipt", receipt, "--expected-content-sha256", digest}
			if role != "" {
				arguments = append(arguments, "--role", role)
			}
		}
	}
	if !reflect.DeepEqual(sourceBefore, agySourceDigests(t, project)) {
		t.Fatal("original source or Git state changed before report export")
	}
	runLiveMulgae(t, validator, environment, project, 0, "report", "--run", runID,
		"--output-path", "agy-report.md", "--output", "json")
	report, err := os.ReadFile(filepath.Join(project, "agy-report.md"))
	if err != nil || !bytes.Equal(report, rendered) {
		t.Fatalf("exported report differs from verified public content: %v", err)
	}
	info, err := os.Stat(filepath.Join(project, "agy-report.md"))
	if err != nil {
		t.Fatal(err)
	}
	reportSum := sha256.Sum256(rendered)
	sourceBefore["agy-report.md"] = info.Mode().String() + ":" + hex.EncodeToString(reportSum[:])
	runLiveMulgae(t, validator, environment, project, 0, "export", "--run", runID,
		"--output-path", ".mulgae/agy-export.zip", "--output", "json")
	archive, err := zip.OpenReader(filepath.Join(project, ".mulgae", "agy-export.zip"))
	if err != nil {
		t.Fatal(err)
	}
	if len(archive.File) == 0 {
		t.Error("export contains no artifacts")
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	assertNoProjectProviderLocks(t, project)
	for _, prefix := range []string{"mulgae-review-namespaces-*", "mulgae-review-workspaces-*"} {
		remaining, err := filepath.Glob(filepath.Join(os.TempDir(), prefix))
		if err != nil || len(remaining) != 0 {
			t.Fatalf("AGY review did not close its private runtime roots: %v: %v", remaining, err)
		}
	}
	scenario.status = "passed"
}

func assertAgyNaturalProcessTerminal(t *testing.T, project string, run livePublishedRun) {
	t.Helper()
	attempts := liveAttemptsForRole(run.manifest.Attempts, "documentation")
	if len(attempts) != 1 {
		t.Fatal("AGY review has no unique attempt")
	}
	path := filepath.Join(project, ".mulgae", "diagnostics", run.manifest.SessionID, run.manifest.RunID,
		"attempts", attempts[0].AttemptID, "invocations", "001-initial", "status.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var status struct {
		ProcessState string `json:"process_state"`
		Termination  string `json:"termination"`
		ExitCode     *int   `json:"exit_code"`
	}
	if err := json.Unmarshal(data, &status); err != nil {
		t.Fatal(err)
	}
	// Successful diagnostics retain process facts, not session receipts. The
	// exact production binary publishes only after the AGY driver observes
	// half-close/EOF and agyNaturalExitObservation proves zero exit, complete
	// input, no requested signals and process-group absence. Owner regressions
	// exercise those rejection paths; the gate also checks runtime-root removal.
	if status.ProcessState != "succeeded" || status.Termination != "exited" || status.ExitCode == nil || *status.ExitCode != 0 {
		t.Fatalf("AGY invocation lacks a natural successful process terminal: %+v", status)
	}
}

func agyFileDigest(t *testing.T, path string) [32]byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return sha256.Sum256(data)
}

func agyTokenDigest(t *testing.T, path string) [32]byte {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatal("default AGY token must be a regular mode-0600 file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() || stat.Nlink != 1 {
		t.Fatal("default AGY token ownership or link count is unsafe")
	}
	return agyFileDigest(t, path)
}

func agySourceDigests(t *testing.T, project string) map[string]string {
	t.Helper()
	digests := make(map[string]string)
	err := filepath.WalkDir(project, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if path == filepath.Join(project, ".mulgae") {
				return filepath.SkipDir
			}
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(project, path)
		if err != nil {
			return err
		}
		sum := agyFileDigest(t, path)
		digests[relative] = info.Mode().String() + ":" + hex.EncodeToString(sum[:])
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return digests
}
