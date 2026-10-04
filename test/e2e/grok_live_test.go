//go:build darwin && arm64 && live_e2e && live_grok

package e2e

import "testing"

func TestE2EGrokReleaseBinaryReview(t *testing.T) {
	scenario := beginLiveE2ELogScope(t, "scenario", "name=grok-release-binary-review")
	defer scenario.end()

	binary := requireLiveExecutable(t, "MULGAE_E2E_BINARY", "")
	grok := requireLiveExecutable(t, "MULGAE_E2E_GROK_EXECUTABLE", lookupLiveExecutable(t, "grok"))
	validator := newLiveE2EValidator(t)
	project := initializeLiveE2ERepository(t)
	environment := liveE2EEnvironment{binary: binary}

	initialized := runLiveMulgae(t, validator, environment, project, 0,
		"init", "--providers", "grok", "--roles", "logic",
		"--grok-executable", grok, "--output", "json",
	)
	if initialized.Result.Kind != "initialized" {
		t.Fatalf("Grok init result kind = %q", initialized.Result.Kind)
	}

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
			return validateLiveRoleReportTransports(run)
		},
		"review", "--workspace", "--roles", "logic", "--output", "json",
		"--objective", "Review the original workspace. Return a concise Markdown report with no findings unless the selected original source contains a concrete defect.",
	)
	assertLiveRecoverableAssignments(t, run, expected)
	assertLiveRoleReportTransports(t, run, "Grok release-binary review")
	assertNoProjectProviderLocks(t, project)
	scenario.status = "passed"
}
