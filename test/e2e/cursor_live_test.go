//go:build darwin && arm64 && live_e2e && live_cursor

package e2e

import (
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
)

var cursorVersionPattern = regexp.MustCompile(`^[0-9]{4}\.[0-9]{2}\.[0-9]{2}-[0-9a-f]+$`)

func TestE2ECursorReleaseBinaryReview(t *testing.T) {
	scenario := beginLiveE2ELogScope(t, "scenario", "name=cursor-release-binary-review")
	defer scenario.end()

	if os.Getenv("CURSOR_AUTH_TOKEN") == "" {
		t.Fatal("CURSOR_AUTH_TOKEN is required")
	}
	binary := requireLiveExecutable(t, "MULGAE_E2E_BINARY", "")
	cursor := requireLiveExecutable(t, "MULGAE_E2E_CURSOR_EXECUTABLE", "")
	if version := observedCursorVersion(t, cursor); !cursorVersionPattern.MatchString(version) {
		t.Fatalf("Cursor version and family preflight rejected %q", version)
	}
	validator := newLiveE2EValidator(t)
	project := initializeLiveE2ERepository(t)
	environment := liveE2EEnvironment{binary: binary}

	initialized := runLiveMulgae(t, validator, environment, project, 0,
		"init", "--providers", "cursor", "--roles", "logic",
		"--cursor-executable", cursor, "--output", "json",
	)
	if initialized.Result.Kind != "initialized" {
		t.Fatalf("Cursor init result kind = %q", initialized.Result.Kind)
	}

	expected := map[string]string{"logic": "cursor-logic"}
	run := runLiveRecoverableWorkflowWithGate(
		t, validator, environment, project, "cursor-release-binary-review", expected,
		func(project string, run livePublishedRun, expected map[string]string) error {
			if err := validateLiveRecoverableAssignments(run, expected); err != nil {
				return err
			}
			if err := validateLivePrimaryProcessTerminals(project, run, expected); err != nil {
				return err
			}
			return validateLiveRoleReportTransports(run)
		},
		"review", "--workspace", "--roles", "logic", "--output", "json",
		"--objective", "Review the original workspace. Return a concise Markdown report with no findings unless the selected original source contains a concrete defect.",
	)
	assertLiveRecoverableAssignments(t, run, expected)
	assertLiveRoleReportTransports(t, run, "Cursor release-binary review")
	assertNoProjectProviderLocks(t, project)
	scenario.status = "passed"
}

func observedCursorVersion(t *testing.T, executable string) string {
	t.Helper()
	output, err := exec.Command(executable, "--version").CombinedOutput()
	if err != nil {
		t.Fatalf("Cursor version probe failed: %v", err)
	}
	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			return line
		}
	}
	t.Fatal("Cursor version probe returned no version")
	return ""
}
