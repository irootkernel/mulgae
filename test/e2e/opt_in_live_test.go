//go:build darwin && arm64 && live_e2e && live_e2e_opt_in

package e2e

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	adapterconfig "github.com/irootkernel/mulgae/internal/adapters/config"
)

const (
	optInCodexPrimaryProfile   = "primary"
	optInCodexSecondaryProfile = "secondary"
)

type optInLiveEnvironment struct {
	binary             string
	codexExecutable    string
	codexPrimaryHome   string
	codexSecondaryHome string
	kimiExecutable     string
	kimiDataHome       string
}

type optInProtectedFile struct {
	label  string
	path   string
	info   os.FileInfo
	digest [sha256.Size]byte
}

func TestE2EOptInMixedCredentialProfiles(t *testing.T) {
	scenario := beginLiveE2ELogScope(t, "scenario", "name=opt-in-mixed-credential-profiles")
	defer scenario.end()
	environment := requireOptInLiveEnvironment(t)
	protected := captureOptInProtectedFiles(t, environment)
	t.Cleanup(func() { assertOptInProtectedFilesUnchanged(t, protected) })

	validator := newLiveE2EValidator(t)
	project := initializeLiveE2ERepository(t)
	runtimeEnvironment := liveE2EEnvironment{binary: environment.binary}
	initialized := runLiveMulgae(t, validator, runtimeEnvironment, project, 0,
		"init", "--providers", "kimi,codex", "--roles", "logic,security,documentation",
		"--kimi-executable", environment.kimiExecutable, "--kimi-data-home", environment.kimiDataHome,
		"--codex-executable", environment.codexExecutable, "--output", "json",
	)
	if initialized.Result.Kind != "initialized" {
		t.Fatalf("opt-in init result kind = %q", initialized.Result.Kind)
	}
	configureOptInCredentialProfiles(t, project, environment)

	effective := runLiveMulgae(t, validator, runtimeEnvironment, project, 0, "config", "--mode", "effective", "--output", "json")
	assertOptInConfigMatrix(t, effective.Result.Policy, environment)
	provenance := runLiveMulgae(t, validator, runtimeEnvironment, project, 0, "config", "--mode", "provenance", "--output", "json")
	assertOptInPrivatePathsRedacted(t, provenance.Result.Policy, environment)

	expected := map[string]string{
		"logic":         "kimi-logic",
		"security":      "codex-primary-security",
		"documentation": "codex-secondary-documentation",
	}
	run := runLiveRecoverableWorkflowWithGate(t, validator, runtimeEnvironment, project, "opt-in-mixed-credential-profiles", expected, validateOptInLiveGate,
		"review", "--dirty",
		"--objective", "This is a provider-route compatibility check. Do not report findings or evidence claims. Return exactly this single Markdown sentence and nothing else: Route compatibility completed with no findings.",
		"--roles", "logic,security,documentation", "--output", "json",
	)
	assertLiveRecoverableAssignments(t, run, expected)
	assertLiveRoleReportTransports(t, run, "opt-in mixed-profile review", false)
	assertNoProjectProviderLocks(t, project)
	scenario.status = "passed"
}

func validateOptInLiveGate(project string, run livePublishedRun, expected map[string]string) error {
	if err := validateLiveRecoverableAssignments(run, expected); err != nil {
		return err
	}
	if err := validateLivePrimaryProcessTerminals(project, run, expected); err != nil {
		return err
	}
	return validateLiveRoleReportTransports(run, false)
}

func requireOptInLiveEnvironment(t *testing.T) optInLiveEnvironment {
	t.Helper()
	environment := optInLiveEnvironment{
		binary:             requireLiveExecutable(t, "MULGAE_E2E_BINARY", ""),
		codexExecutable:    requireLiveExecutable(t, "MULGAE_E2E_CODEX_EXECUTABLE", ""),
		codexPrimaryHome:   requireCanonicalOptInDirectory(t, "MULGAE_E2E_CODEX_PRIMARY_HOME"),
		codexSecondaryHome: requireCanonicalOptInDirectory(t, "MULGAE_E2E_CODEX_SECONDARY_HOME"),
		kimiExecutable:     requireLiveExecutable(t, "MULGAE_E2E_KIMI_EXECUTABLE", ""),
		kimiDataHome:       requireCanonicalOptInDirectory(t, "MULGAE_E2E_KIMI_DATA_HOME"),
	}
	primaryInfo, err := os.Stat(environment.codexPrimaryHome)
	if err != nil {
		t.Fatalf("inspect primary Codex home: %v", err)
	}
	secondaryInfo, err := os.Stat(environment.codexSecondaryHome)
	if err != nil {
		t.Fatalf("inspect secondary Codex home: %v", err)
	}
	if os.SameFile(primaryInfo, secondaryInfo) {
		t.Fatal("opt-in E2E requires distinct primary and secondary Codex homes")
	}
	return environment
}

func requireCanonicalOptInDirectory(t *testing.T, name string) string {
	t.Helper()
	path := os.Getenv(name)
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		t.Fatalf("%s must be a canonical absolute directory", name)
	}
	info, err := os.Stat(path)
	if err != nil || !info.IsDir() {
		t.Fatalf("%s must name an existing directory", name)
	}
	return path
}

func configureOptInCredentialProfiles(t *testing.T, project string, environment optInLiveEnvironment) {
	t.Helper()
	config := readE2EConfig(t, project)
	if config.Providers.Kimi == nil || config.Providers.Codex == nil {
		t.Fatalf("opt-in init omitted required providers: %#v", config.Providers)
	}
	config.Providers.Codex.DefaultCredentialProfile = optInCodexPrimaryProfile
	config.Providers.Codex.CredentialHomes = []adapterconfig.CodexCredentialHomeConfig{
		{Profile: optInCodexPrimaryProfile, Home: environment.codexPrimaryHome},
		{Profile: optInCodexSecondaryProfile, Home: environment.codexSecondaryHome},
	}
	config.Roles.Logic.PrimaryProvider = "kimi"
	config.Roles.Logic.CredentialProfile = ""
	config.Roles.Security.PrimaryProvider = "codex"
	config.Roles.Security.CredentialProfile = optInCodexPrimaryProfile
	config.Roles.Documentation.PrimaryProvider = "codex"
	config.Roles.Documentation.CredentialProfile = optInCodexSecondaryProfile
	projectConfig, localConfig, err := adapterconfig.EncodeSplit(config)
	if err != nil {
		t.Fatalf("encode opt-in Config v3 pair: %v", err)
	}
	writeExistingOptInConfig(t, filepath.Join(project, ".mulgae", "config.yaml"), projectConfig)
	writeExistingOptInConfig(t, filepath.Join(project, ".mulgae", "local.yaml"), localConfig)
	admitted := readE2EConfig(t, project)
	if admitted.Resources.MaxActiveLanes != 3 {
		t.Fatalf("opt-in max_active_lanes = %d, want 3", admitted.Resources.MaxActiveLanes)
	}
}

func writeExistingOptInConfig(t *testing.T, path string, content []byte) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		t.Fatalf("opt-in config destination is unavailable: %v", err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		t.Fatalf("open opt-in config destination: %v", err)
	}
	if _, err := file.Write(content); err != nil {
		_ = file.Close()
		t.Fatalf("write opt-in config destination: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close opt-in config destination: %v", err)
	}
}

func assertOptInConfigMatrix(t *testing.T, raw []byte, environment optInLiveEnvironment) {
	t.Helper()
	assertOptInPrivatePathsRedacted(t, raw, environment)
	var redacted struct {
		ConfiguredProviderIDs []string `json:"configured_provider_ids"`
		Policy                struct {
			RoleAssignments []struct {
				Role              string `json:"role"`
				PrimaryProvider   string `json:"primary_provider"`
				CredentialProfile string `json:"credential_profile"`
			} `json:"role_assignments"`
		} `json:"policy"`
	}
	if err := json.Unmarshal(raw, &redacted); err != nil {
		t.Fatalf("decode opt-in redacted config: %v", err)
	}
	if !reflect.DeepEqual(redacted.ConfiguredProviderIDs, []string{"kimi", "codex"}) {
		t.Fatalf("opt-in configured providers = %v", redacted.ConfiguredProviderIDs)
	}
	want := map[string][2]string{
		"logic":         {"kimi", ""},
		"security":      {"codex", optInCodexPrimaryProfile},
		"documentation": {"codex", optInCodexSecondaryProfile},
	}
	for _, assignment := range redacted.Policy.RoleAssignments {
		expected, ok := want[assignment.Role]
		if !ok {
			continue
		}
		if assignment.PrimaryProvider != expected[0] || assignment.CredentialProfile != expected[1] {
			t.Fatalf("unexpected opt-in role assignment: %#v", assignment)
		}
		delete(want, assignment.Role)
	}
	if len(want) != 0 {
		t.Fatalf("opt-in config omitted role assignments: %v", want)
	}
}

func assertOptInPrivatePathsRedacted(t *testing.T, raw []byte, environment optInLiveEnvironment) {
	t.Helper()
	for _, path := range []string{environment.codexPrimaryHome, environment.codexSecondaryHome, environment.kimiDataHome} {
		if bytes.Contains(raw, []byte(path)) {
			t.Fatal("opt-in config output exposed a private provider home")
		}
	}
}

func captureOptInProtectedFiles(t *testing.T, environment optInLiveEnvironment) []optInProtectedFile {
	t.Helper()
	specs := []struct {
		label string
		path  string
	}{
		{label: "Codex primary auth", path: filepath.Join(environment.codexPrimaryHome, "auth.json")},
		{label: "Codex secondary auth", path: filepath.Join(environment.codexSecondaryHome, "auth.json")},
		{label: "Kimi config", path: filepath.Join(environment.kimiDataHome, "config.toml")},
		{label: "Kimi credentials", path: filepath.Join(environment.kimiDataHome, "credentials", "kimi-code.json")},
	}
	protected := make([]optInProtectedFile, 0, len(specs))
	for _, spec := range specs {
		info, err := os.Lstat(spec.path)
		if err != nil || !info.Mode().IsRegular() {
			t.Fatalf("%s is unavailable or unsafe", spec.label)
		}
		content, err := os.ReadFile(spec.path)
		if err != nil {
			t.Fatalf("read %s: %v", spec.label, err)
		}
		protected = append(protected, optInProtectedFile{label: spec.label, path: spec.path, info: info, digest: sha256.Sum256(content)})
	}
	return protected
}

func assertOptInProtectedFilesUnchanged(t *testing.T, protected []optInProtectedFile) {
	t.Helper()
	for _, before := range protected {
		after, err := os.Lstat(before.path)
		if err != nil || !after.Mode().IsRegular() || !os.SameFile(before.info, after) || after.Mode() != before.info.Mode() || after.Size() != before.info.Size() || !after.ModTime().Equal(before.info.ModTime()) {
			t.Errorf("%s identity or metadata changed", before.label)
			continue
		}
		content, err := os.ReadFile(before.path)
		if err != nil {
			t.Errorf("read %s after E2E: %v", before.label, err)
			continue
		}
		if digest := sha256.Sum256(content); digest != before.digest {
			t.Errorf("%s content changed", before.label)
		}
	}
}
