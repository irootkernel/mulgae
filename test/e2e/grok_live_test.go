//go:build darwin && arm64 && live_e2e && live_grok

package e2e

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
	"time"

	adapterconfig "github.com/irootkernel/mulgae/internal/adapters/config"
)

func TestE2EGrokReleaseBinaryReview(t *testing.T) {
	scenario := beginLiveE2ELogScope(t, "scenario", "name=grok-release-binary-review")
	defer scenario.end()

	binary := requireLiveExecutable(t, "MULGAE_E2E_BINARY", "")
	grok := requireLiveExecutable(t, "MULGAE_E2E_GROK_EXECUTABLE", lookupLiveExecutable(t, "grok"))
	validator := newLiveE2EValidator(t)
	project := initializeLiveE2ERepository(t)
	environment := liveE2EEnvironment{binary: binary}
	marker := appendLiveReadMarker(t, project, "counter.go", "grok-read")
	sourceBefore := grokSourceDigests(t, project)
	installed, err := user.LookupId(strconv.Itoa(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	auth := filepath.Join(installed.HomeDir, ".grok", "auth.json")
	authBefore, executableBefore := grokFileDigest(t, auth), grokFileDigest(t, grok)
	defer func() {
		if !reflect.DeepEqual(sourceBefore, grokSourceDigests(t, project)) ||
			grokFileDigest(t, auth) != authBefore || grokFileDigest(t, grok) != executableBefore {
			t.Error("original Grok source, Git, authentication or executable changed")
		}
	}()

	initialized := runLiveMulgae(t, validator, environment, project, 0,
		"init", "--providers", "grok", "--roles", "logic",
		"--grok-executable", grok, "--output", "json",
	)
	if initialized.Result.Kind != "initialized" {
		t.Fatalf("Grok init result kind = %q", initialized.Result.Kind)
	}
	config := readE2EConfig(t, project)
	config.Validation.Repair = adapterconfig.RepairConfig{}
	config.Validation.Extraction.Enabled = true
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

	expected := map[string]string{"logic": "grok-logic"}
	run := runLiveRecoverableWorkflowWithGate(
		t, validator, environment, project, "grok-release-binary-review", expected,
		func(project string, run livePublishedRun, expected map[string]string) error {
			if err := validateLiveRecoverableAssignments(run, expected); err != nil {
				return err
			}
			if err := validateLivePrimaryProcessTerminals(project, run, expected); err != nil {
				return err
			}
			if err := validateGrokExtractionInvocation(project, run); err != nil {
				return err
			}
			return validateLiveRoleReportTransports(run)
		},
		"review", "--workspace", "--roles", "logic", "--output", "json",
		"--objective", "Review the original workspace. Read counter.go and reproduce its grok-read marker verbatim. Return only a concise Markdown report, with no JSON and no findings unless the selected original source contains a concrete defect.",
	)
	assertLiveRecoverableAssignments(t, run, expected)
	assertLiveRoleReportTransports(t, run, "Grok release-binary review")
	assertLiveRoleReportMarker(t, project, run, "logic", marker)
	assertNoProjectProviderLocks(t, project)
	for _, prefix := range []string{"mulgae-review-namespaces-*", "mulgae-review-workspaces-*"} {
		remaining, err := filepath.Glob(filepath.Join(os.TempDir(), prefix))
		if err != nil || len(remaining) != 0 {
			t.Fatalf("Grok review did not close its private runtime roots: %v: %v", remaining, err)
		}
	}
	scenario.status = "passed"
}

func validateGrokExtractionInvocation(project string, run livePublishedRun) error {
	attempts := liveAttemptsForRole(run.manifest.Attempts, "logic")
	if len(attempts) != 1 || attempts[0].ProviderInstance != "grok-logic" || attempts[0].InvocationCount != 2 ||
		run.manifest.StructuredExtractionState != "structured" || run.review.StructuredExtractionStatus != "structured" {
		return fmt.Errorf("Grok gate requires one initial review and successful same-provider structured extraction")
	}
	path := filepath.Join(project, ".mulgae", "diagnostics", run.manifest.SessionID, run.manifest.RunID,
		"attempts", attempts[0].AttemptID, "invocations", "002-extract", "status.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read Grok extraction invocation status: %w", err)
	}
	var status liveInvocationStatus
	if err := json.Unmarshal(data, &status); err != nil {
		return fmt.Errorf("decode Grok extraction invocation status: %w", err)
	}
	started, startErr := time.Parse(time.RFC3339Nano, status.StartedAt)
	completed, completeErr := time.Parse(time.RFC3339Nano, status.CompletedAt)
	if startErr != nil || completeErr != nil || status.ProcessState != "succeeded" || !started.Before(completed) {
		return fmt.Errorf("Grok extraction did not complete successfully")
	}
	return nil
}

func grokFileDigest(t *testing.T, path string) string {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func grokSourceDigests(t *testing.T, project string) map[string]string {
	t.Helper()
	result := make(map[string]string)
	err := filepath.WalkDir(project, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == filepath.Join(project, ".mulgae") {
			return filepath.SkipDir
		}
		relative, err := filepath.Rel(project, path)
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if entry.IsDir() {
			result[relative] = info.Mode().String()
		} else {
			result[relative] = info.Mode().String() + ":" + grokFileDigest(t, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}
