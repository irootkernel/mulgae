//go:build darwin && arm64 && live_e2e

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	adapterconfig "github.com/irootkernel/kkachi-agent-review/internal/adapters/config"
	"github.com/irootkernel/kkachi-agent-review/internal/adapters/jsonschema"
	"github.com/irootkernel/kkachi-agent-review/internal/builtin"
	"github.com/irootkernel/kkachi-agent-review/internal/ports"
)

const (
	liveCommandSchema  = "https://kar.local/schemas/kar-command-result.v1.schema.json"
	liveManifestSchema = "https://kar.local/schemas/kar-run-manifest.v2.schema.json"
	liveReviewSchema   = "https://kar.local/schemas/kar-review-artifact.v2.schema.json"
)

type liveE2EEnvironment struct {
	binary        string
	nativeHome    string
	kimi          string
	kimiDataHome  string
	zcodeNode     string
	zcodeLauncher string
	agy           string
}

type liveCommandEnvelope struct {
	Command string `json:"command"`
	Exit    struct {
		Code int    `json:"code"`
		Kind string `json:"kind"`
	} `json:"exit"`
	Result struct {
		Kind              string          `json:"kind"`
		SessionID         *string         `json:"session_id"`
		RunID             *string         `json:"run_id"`
		RunManifestURI    *string         `json:"run_manifest_uri"`
		ReviewArtifactURI *string         `json:"review_artifact_uri"`
		Policy            json.RawMessage `json:"policy"`
		Doctor            json.RawMessage `json:"doctor"`
	} `json:"result"`
	Reasons []struct {
		Category  string `json:"category"`
		Code      string `json:"code"`
		Message   string `json:"message"`
		Retryable bool   `json:"retryable"`
	} `json:"reasons"`
}

type liveLineage struct {
	ParentRunID      *string `json:"parent_run_id"`
	SourceRunID      *string `json:"source_run_id"`
	SourceReviewID   *string `json:"source_review_id"`
	SourceFindingRef *string `json:"source_finding_ref"`
	ReplayMode       *string `json:"replay_mode"`
}

type liveAttempt struct {
	AttemptID        string `json:"attempt_id"`
	Role             string `json:"role"`
	ProviderInstance string `json:"provider_instance"`
	SelectedAs       string `json:"selected_as"`
	State            string `json:"state"`
	InvocationCount  int    `json:"invocation_count"`
}

type liveFailure struct {
	Class      string  `json:"class"`
	Stage      string  `json:"stage"`
	ReasonCode string  `json:"reason_code"`
	AttemptID  *string `json:"attempt_id"`
}

type liveManifest struct {
	RunID                string        `json:"run_id"`
	RunType              string        `json:"run_type"`
	State                string        `json:"state"`
	Sealed               bool          `json:"sealed"`
	ImmutableLineage     liveLineage   `json:"immutable_lineage"`
	SelectedRoles        []string      `json:"selected_roles"`
	Attempts             []liveAttempt `json:"attempts"`
	Failures             []liveFailure `json:"failures"`
	PublicationStatus    string        `json:"publication_status"`
	PublicationAuthority string        `json:"publication_authority"`
	ExitCode             int           `json:"exit_code"`
}

type liveRoleOutcome struct {
	Role             string  `json:"role"`
	Outcome          string  `json:"outcome"`
	AttemptID        *string `json:"attempt_id"`
	ProviderInstance *string `json:"provider_instance"`
	SelectedVia      *string `json:"selected_via"`
}

type liveFinding struct {
	ID               string `json:"id"`
	Role             string `json:"role"`
	ProviderInstance string `json:"provider_instance"`
}

type liveReview struct {
	RunID             string            `json:"run_id"`
	ReviewID          string            `json:"review_id"`
	RunType           string            `json:"run_type"`
	ImmutableLineage  liveLineage       `json:"immutable_lineage"`
	PublicationStatus string            `json:"publication_status"`
	RoleOutcomes      []liveRoleOutcome `json:"role_outcomes"`
	Findings          []liveFinding     `json:"findings"`
}

type livePublishedRun struct {
	envelope liveCommandEnvelope
	manifest liveManifest
	review   liveReview
}

func TestE2EActualProvidersThreeIndependentPrimaryLanes(t *testing.T) {
	environment := requireLiveE2EEnvironment(t)
	validator := newLiveE2EValidator(t)
	project := initializeLiveE2ERepository(t)

	initResult := runLiveKAR(t, validator, environment, project, 0, liveInitArguments(environment, "kimi,zcode,agy")...)
	if initResult.Result.Kind != "initialized" {
		t.Fatalf("init result kind = %q", initResult.Result.Kind)
	}
	configResult := runLiveKAR(t, validator, environment, project, 0, "config", "--output", "json")
	assertLiveConfigMatrix(t, configResult.Result.Policy)
	assertLiveThreeLaneConfig(t, project)
	doctorResult := runLiveKAR(t, validator, environment, project, 4, "doctor", "--output", "json")
	assertLiveDoctorPrequalification(t, doctorResult.Result.Doctor)

	expected := map[string]string{
		"logic": "kimi-default", "security": "zcode-default", "documentation": "agy-default",
	}
	run := runLiveFocusedPrimaryWorkflow(t, validator, environment, project, expected,
		"review", "--diff", "HEAD^...HEAD",
		"--objective", "Review only the deterministic fixture assigned to the current role and do not report any other path. Logic: counter.go is intentionally correct; return findings: []. Documentation: README.md accurately documents ClampNonNegative; return findings: []. Security: report exactly one high-severity finding for the planted traversal in report.go. Its only evidence must use path report.go, side head, line_start 8, line_end 9, and the exact JSON-string quote func ReadReport(base, name string) ([]byte, error) {\\n\\treturn os.ReadFile(filepath.Join(base, name)) // deliberate directory traversal for KAR live E2E\\n. Return only the single schema-valid result required for the current role.",
		"--roles", "logic,security,documentation", "--output", "json",
	)
	assertLivePrimaryAssignments(t, run, expected)
	assertLiveSecurityFinding(t, run, "zcode-default")
}

// runLiveFullProductionWorkflows retains the full G010 workflow scenario while
// T05 stabilizes the focused three-provider lane gate. It is deliberately not
// a Test function and therefore cannot enter test-e2e until explicitly restored.
func runLiveFullProductionWorkflows(t *testing.T) {
	t.Helper()
	environment := requireLiveE2EEnvironment(t)
	validator := newLiveE2EValidator(t)
	project := initializeLiveE2ERepository(t)

	initResult := runLiveKAR(t, validator, environment, project, 0, liveInitArguments(environment, "kimi,zcode,agy")...)
	if initResult.Result.Kind != "initialized" {
		t.Fatalf("init result kind = %q", initResult.Result.Kind)
	}

	configResult := runLiveKAR(t, validator, environment, project, 0, "config", "--output", "json")
	assertLiveConfigMatrix(t, configResult.Result.Policy)
	doctorResult := runLiveKAR(t, validator, environment, project, 4, "doctor", "--output", "json")
	assertLiveDoctorPrequalification(t, doctorResult.Result.Doctor)

	root := runLivePublishedWorkflow(t, validator, environment, project, []int{0, 1, 4},
		"review", "--diff", "HEAD^...HEAD",
		"--objective", "Review the deliberate directory traversal in report.go. The security role must report the unvalidated user-controlled path as a verified finding; every role must return a schema-valid result.",
		"--roles", "logic,security,maintainability,product,documentation,testing",
		"--output", "json",
	)
	assertLiveAssignments(t, root, map[string][2]string{
		"logic": {"kimi-default", "zcode-default"}, "security": {"zcode-default", "agy-default"}, "maintainability": {"zcode-default", "agy-default"},
		"product": {"zcode-default", "agy-default"}, "documentation": {"agy-default", "zcode-default"}, "testing": {"zcode-default", "agy-default"},
	})
	if len(root.review.Findings) == 0 {
		t.Fatal("six-role review produced no source finding for the deliberate directory traversal")
	}
	sourceFinding := root.review.Findings[0]
	sourceAttempt := requireLiveSelectedAttempt(t, root, "logic")

	writeLiveFixedReportPath(t, project)
	followup := runLivePublishedWorkflow(t, validator, environment, project, []int{0, 1, 4},
		"followup", "--run", root.manifest.RunID, "--finding", sourceFinding.ID,
		"--diff", "git", "--objective", "Verify only whether the original directory traversal is resolved.",
		"--output", "json",
	)
	assertLiveSourceLineage(t, followup, root, sourceFinding.ID, "")
	assertLiveSourceBoundAssignment(t, followup, sourceFinding.Role, sourceFinding.ProviderInstance)

	delta := runLivePublishedWorkflow(t, validator, environment, project, []int{0, 1, 4},
		"delta", "--since-run", root.manifest.RunID, "--diff", "git",
		"--roles", "logic,security,documentation", "--output", "json",
	)
	assertLiveSourceLineage(t, delta, root, "", "")
	assertLiveAssignments(t, delta, map[string][2]string{
		"logic": {"kimi-default", "zcode-default"}, "security": {"zcode-default", "agy-default"}, "documentation": {"agy-default", "zcode-default"},
	})

	exact := runLivePublishedWorkflow(t, validator, environment, project, []int{0, 1, 4},
		"rerun", "--run", root.manifest.RunID, "--attempt", sourceAttempt.AttemptID,
		"--replay", "exact", "--output", "json",
	)
	assertLiveSourceLineage(t, exact, root, "", "exact")
	assertLiveSourceBoundAssignment(t, exact, sourceAttempt.Role, sourceAttempt.ProviderInstance)

	recompose := runLivePublishedWorkflow(t, validator, environment, project, []int{0, 1, 4},
		"rerun", "--run", root.manifest.RunID, "--attempt", sourceAttempt.AttemptID,
		"--replay", "recompose", "--output", "json",
	)
	assertLiveSourceLineage(t, recompose, root, "", "recompose")
	assertLiveAssignments(t, recompose, map[string][2]string{"logic": {"kimi-default", "zcode-default"}})
}

func liveInitArguments(environment liveE2EEnvironment, providers string) []string {
	arguments := []string{"init", "--providers", providers}
	if strings.Contains(providers, "kimi") {
		arguments = append(arguments, "--kimi-executable", environment.kimi, "--kimi-data-home", environment.kimiDataHome)
	}
	if strings.Contains(providers, "zcode") {
		arguments = append(arguments, "--zcode-node-executable", environment.zcodeNode, "--zcode-launcher", environment.zcodeLauncher)
	}
	if strings.Contains(providers, "agy") {
		arguments = append(arguments, "--agy-executable", environment.agy)
	}
	return append(arguments, "--output", "json")
}

func requireLiveE2EEnvironment(t *testing.T) liveE2EEnvironment {
	t.Helper()
	installed, err := user.Current()
	if err != nil || installed == nil || !filepath.IsAbs(installed.HomeDir) || filepath.Clean(installed.HomeDir) != installed.HomeDir {
		t.Fatalf("native installed-user HOME is unavailable: %v", err)
	}
	binary := requireLiveExecutable(t, "KAR_E2E_BINARY", "")
	kimi := requireLiveExecutable(t, "KAR_E2E_KIMI_EXECUTABLE", filepath.Join(installed.HomeDir, ".kimi-code", "bin", "kimi"))
	zcodeNode := requireLiveExecutable(t, "KAR_E2E_ZCODE_NODE_EXECUTABLE", lookupLiveExecutable(t, "node"))
	zcodeLauncher := requireLiveExecutable(t, "KAR_E2E_ZCODE_LAUNCHER", "/Applications/ZCode.app/Contents/Resources/glm/zcode.cjs")
	agyDefault := filepath.Join(installed.HomeDir, ".local", "bin", "agy")
	if found, lookupErr := exec.LookPath("agy"); lookupErr == nil {
		agyDefault = found
	}
	agy := requireLiveExecutable(t, "KAR_E2E_AGY_EXECUTABLE", agyDefault)
	kimiDataHome := envOrDefault("KAR_E2E_KIMI_DATA_HOME", filepath.Join(installed.HomeDir, ".kimi-code"))
	if info, statErr := os.Stat(kimiDataHome); statErr != nil || !info.IsDir() {
		t.Fatalf("Kimi native data home is unavailable: %q: %v", kimiDataHome, statErr)
	}
	return liveE2EEnvironment{binary: binary, nativeHome: installed.HomeDir, kimi: kimi, kimiDataHome: kimiDataHome, zcodeNode: zcodeNode, zcodeLauncher: zcodeLauncher, agy: agy}
}

func requireLiveExecutable(t *testing.T, environmentName, fallback string) string {
	t.Helper()
	path := envOrDefault(environmentName, fallback)
	if !filepath.IsAbs(path) {
		resolved, err := filepath.Abs(path)
		if err != nil {
			t.Fatalf("%s is not resolvable: %q: %v", environmentName, path, err)
		}
		path = resolved
	}
	path = filepath.Clean(path)
	info, err := os.Stat(path)
	if err != nil || info.IsDir() || info.Mode()&0o111 == 0 {
		t.Fatalf("%s is not an executable file: %q: %v", environmentName, path, err)
	}
	return path
}

func lookupLiveExecutable(t *testing.T, name string) string {
	t.Helper()
	path, err := exec.LookPath(name)
	if err != nil {
		t.Fatalf("required live provider launcher %q is unavailable: %v", name, err)
	}
	return path
}

func envOrDefault(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func initializeLiveE2ERepository(t *testing.T) string {
	t.Helper()
	project := t.TempDir()
	if preserved := os.Getenv("KAR_E2E_PROJECT_ROOT"); preserved != "" {
		if !filepath.IsAbs(preserved) || filepath.Clean(preserved) != preserved {
			t.Fatalf("KAR_E2E_PROJECT_ROOT is not canonical absolute: %q", preserved)
		}
		entries, err := os.ReadDir(preserved)
		if err != nil || len(entries) != 0 {
			t.Fatalf("KAR_E2E_PROJECT_ROOT must be an existing empty directory: %q: %v", preserved, err)
		}
		project = preserved
		t.Logf("preserving live E2E project at %s", project)
	}
	mustLiveGit(t, project, "init", "--quiet")
	mustLiveGit(t, project, "config", "user.name", "KAR Live E2E")
	mustLiveGit(t, project, "config", "user.email", "kar-live-e2e@example.invalid")
	baseline := "package report\n\nimport (\n\t\"errors\"\n\t\"os\"\n\t\"path/filepath\"\n)\n\nfunc ReadReport(base, name string) ([]byte, error) {\n\tif filepath.Base(name) != name {\n\t\treturn nil, errors.New(\"invalid report name\")\n\t}\n\treturn os.ReadFile(filepath.Join(base, name))\n}\n"
	if err := os.WriteFile(filepath.Join(project, "report.go"), []byte(baseline), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "counter.go"), []byte("package report\n\nfunc ClampNonNegative(value int) int {\n\treturn value\n}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "README.md"), []byte("# Live E2E fixture\n\n## API\n\nAPI documentation pending.\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	mustLiveGit(t, project, "add", "report.go", "counter.go", "README.md")
	mustLiveGit(t, project, "commit", "--quiet", "-m", "baseline")
	vulnerable := "package report\n\nimport (\n\t\"os\"\n\t\"path/filepath\"\n)\n\nfunc ReadReport(base, name string) ([]byte, error) {\n\treturn os.ReadFile(filepath.Join(base, name)) // deliberate directory traversal for KAR live E2E\n}\n"
	if err := os.WriteFile(filepath.Join(project, "report.go"), []byte(vulnerable), 0o600); err != nil {
		t.Fatal(err)
	}
	correctLogic := "package report\n\nfunc ClampNonNegative(value int) int {\n\tif value < 0 {\n\t\treturn 0\n\t}\n\treturn value\n}\n"
	if err := os.WriteFile(filepath.Join(project, "counter.go"), []byte(correctLogic), 0o600); err != nil {
		t.Fatal(err)
	}
	documentation := "# Live E2E fixture\n\n## API\n\n`ClampNonNegative(value)` returns zero for negative values and otherwise returns `value`.\n"
	if err := os.WriteFile(filepath.Join(project, "README.md"), []byte(documentation), 0o600); err != nil {
		t.Fatal(err)
	}
	mustLiveGit(t, project, "add", "report.go", "counter.go", "README.md")
	mustLiveGit(t, project, "commit", "--quiet", "-m", "focused review fixtures")
	return project
}

func writeLiveFixedReportPath(t *testing.T, project string) {
	t.Helper()
	fixed := "package report\n\nimport (\n\t\"errors\"\n\t\"os\"\n\t\"path/filepath\"\n\t\"strings\"\n)\n\nfunc ReadReport(base, name string) ([]byte, error) {\n\tclean := filepath.Clean(name)\n\tif clean == \".\" || filepath.IsAbs(clean) || clean == \"..\" || strings.HasPrefix(clean, \"..\"+string(os.PathSeparator)) {\n\t\treturn nil, errors.New(\"invalid report path\")\n\t}\n\treturn os.ReadFile(filepath.Join(base, clean))\n}\n"
	if err := os.WriteFile(filepath.Join(project, "report.go"), []byte(fixed), 0o600); err != nil {
		t.Fatal(err)
	}
}

func mustLiveGit(t *testing.T, directory string, arguments ...string) {
	t.Helper()
	command := exec.Command("git", arguments...)
	command.Dir = directory
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v: %s", arguments, err, output)
	}
}

func newLiveE2EValidator(t *testing.T) *jsonschema.Validator {
	t.Helper()
	validator, err := jsonschema.New(context.Background(), builtin.NewCatalog())
	if err != nil {
		t.Fatal(err)
	}
	return validator
}

func runLiveKAR(t *testing.T, validator *jsonschema.Validator, environment liveE2EEnvironment, project string, allowedExit int, arguments ...string) liveCommandEnvelope {
	t.Helper()
	return runLiveKARAllowed(t, validator, environment, project, []int{allowedExit}, arguments...)
}

func runLiveKARAllowed(t *testing.T, validator *jsonschema.Validator, environment liveE2EEnvironment, project string, allowedExits []int, arguments ...string) liveCommandEnvelope {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 32*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, environment.binary, arguments...)
	command.Dir = project
	command.Env = os.Environ()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	if ctx.Err() != nil {
		t.Fatalf("kar %s timed out", arguments[0])
	}
	exitCode := 0
	if err != nil {
		exitError, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatalf("kar %s failed to execute: %v", arguments[0], err)
		}
		exitCode = exitError.ExitCode()
	}
	if stderr.Len() != 0 {
		t.Fatalf("kar %s wrote stderr: %s", arguments[0], stderr.String())
	}
	if !containsLiveExit(allowedExits, exitCode) {
		t.Fatalf("kar %s exit = %d, allowed %v; stdout=%s", arguments[0], exitCode, allowedExits, stdout.String())
	}
	validateLiveJSON(t, validator, liveCommandSchema, stdout.Bytes(), arguments[0]+" command envelope")
	var envelope liveCommandEnvelope
	if err := json.Unmarshal(stdout.Bytes(), &envelope); err != nil {
		t.Fatalf("decode kar %s envelope: %v", arguments[0], err)
	}
	if envelope.Command != arguments[0] || envelope.Exit.Code != exitCode {
		t.Fatalf("kar %s envelope does not match process exit: %#v", arguments[0], envelope.Exit)
	}
	return envelope
}

func containsLiveExit(values []int, value int) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

func runLivePublishedWorkflow(t *testing.T, validator *jsonschema.Validator, environment liveE2EEnvironment, project string, allowedExits []int, arguments ...string) livePublishedRun {
	t.Helper()
	envelope := runLiveKARAllowed(t, validator, environment, project, allowedExits, arguments...)
	return loadLivePublishedWorkflow(t, validator, project, envelope, arguments[0])
}

func runLiveFocusedPrimaryWorkflow(t *testing.T, validator *jsonschema.Validator, environment liveE2EEnvironment, project string, expected map[string]string, arguments ...string) livePublishedRun {
	t.Helper()
	const maxAttempts = 3
	var last string
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		envelope := runLiveKARAllowed(t, validator, environment, project, []int{0, 1, 4, 7, 8, 9, 10}, arguments...)
		if liveReasonPresent(envelope, "provider_login_required") {
			t.Fatalf("focused live attempt %d requires provider login: %#v", attempt, envelope.Reasons)
		}
		if envelope.Result.RunID == nil || envelope.Result.RunManifestURI == nil || envelope.Result.ReviewArtifactURI == nil {
			if !liveReasonPresent(envelope, "provider_execution_failed") || envelope.Exit.Kind != "internal" && envelope.Exit.Kind != "readiness" {
				t.Fatalf("focused live attempt %d stopped without retry authority: exit=%#v reasons=%#v result=%#v", attempt, envelope.Exit, envelope.Reasons, envelope.Result)
			}
			last = fmt.Sprintf("non-P2 %s: %#v", envelope.Exit.Kind, envelope.Reasons)
			t.Logf("focused live attempt %d/%d did not reach P2; retrying bounded provider execution: %s", attempt, maxAttempts, last)
			continue
		}
		run := loadLivePublishedWorkflow(t, validator, project, envelope, arguments[0])
		if err := validateLivePrimaryAssignments(run, expected); err == nil && liveSecurityFindingPresent(run, "zcode-default") {
			return run
		} else if err != nil {
			last = err.Error()
		} else {
			last = "successful primaries did not publish the required ZCode security finding"
		}
		t.Logf("focused live attempt %d/%d used a non-primary outcome; retrying the whole review: %s", attempt, maxAttempts, last)
	}
	t.Fatalf("focused live provider gate did not produce one primary-only run after %d attempts: %s", maxAttempts, last)
	return livePublishedRun{}
}

func liveReasonPresent(envelope liveCommandEnvelope, code string) bool {
	for _, reason := range envelope.Reasons {
		if reason.Code == code {
			return true
		}
	}
	return false
}

func loadLivePublishedWorkflow(t *testing.T, validator *jsonschema.Validator, project string, envelope liveCommandEnvelope, command string) livePublishedRun {
	t.Helper()
	if envelope.Result.RunID == nil || envelope.Result.RunManifestURI == nil || envelope.Result.ReviewArtifactURI == nil {
		t.Fatalf("kar %s did not return committed P2 URIs: exit=%#v reasons=%#v result=%#v", command, envelope.Exit, envelope.Reasons, envelope.Result)
	}
	manifestBytes := readLiveArtifact(t, project, *envelope.Result.RunManifestURI)
	reviewBytes := readLiveArtifact(t, project, *envelope.Result.ReviewArtifactURI)
	validateLiveJSON(t, validator, liveManifestSchema, manifestBytes, command+" run manifest")
	validateLiveJSON(t, validator, liveReviewSchema, reviewBytes, command+" review artifact")
	var manifest liveManifest
	var review liveReview
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatalf("decode %s manifest: %v", command, err)
	}
	if err := json.Unmarshal(reviewBytes, &review); err != nil {
		t.Fatalf("decode %s review: %v", command, err)
	}
	if manifest.RunID != *envelope.Result.RunID || review.RunID != manifest.RunID || manifest.RunType != command && !(command == "rerun" && manifest.RunType == "rerun") || review.RunType != manifest.RunType {
		t.Fatalf("%s P2 identity mismatch: manifest=%#v review=%#v", command, manifest, review)
	}
	if manifest.ExitCode != envelope.Exit.Code || !manifest.Sealed || manifest.PublicationStatus != "committed" || manifest.PublicationAuthority != "P2" || review.PublicationStatus != "committed" {
		t.Fatalf("%s P2/exit mismatch: exit=%d manifest=%#v review publication=%q", command, envelope.Exit.Code, manifest, review.PublicationStatus)
	}
	return livePublishedRun{envelope: envelope, manifest: manifest, review: review}
}

func readLiveArtifact(t *testing.T, project, uri string) []byte {
	t.Helper()
	if filepath.IsAbs(uri) || filepath.Clean(uri) != uri || !strings.HasPrefix(uri, ".kar/") {
		t.Fatalf("unsafe live artifact URI %q", uri)
	}
	value, err := os.ReadFile(filepath.Join(project, uri))
	if err != nil {
		t.Fatalf("read live artifact %q: %v", uri, err)
	}
	return value
}

func validateLiveJSON(t *testing.T, validator *jsonschema.Validator, schema string, value []byte, label string) {
	t.Helper()
	id, err := ports.ParseAssetID(schema)
	if err != nil {
		t.Fatal(err)
	}
	if err := validator.Validate(context.Background(), id, value); err != nil {
		t.Fatalf("%s is not schema-valid: %v", label, err)
	}
}

func assertLiveConfigMatrix(t *testing.T, raw json.RawMessage) {
	t.Helper()
	var redacted struct {
		ConfiguredProviderIDs []string `json:"configured_provider_ids"`
		Policy                struct {
			RoleAssignments []struct {
				Role             string  `json:"role"`
				PrimaryProvider  string  `json:"primary_provider"`
				FallbackProvider *string `json:"fallback_provider"`
			} `json:"role_assignments"`
		} `json:"policy"`
	}
	if err := json.Unmarshal(raw, &redacted); err != nil {
		t.Fatalf("decode redacted config: %v", err)
	}
	if !reflect.DeepEqual(redacted.ConfiguredProviderIDs, []string{"kimi", "zcode", "agy"}) {
		t.Fatalf("configured providers = %v", redacted.ConfiguredProviderIDs)
	}
	want := map[string][2]string{
		"logic": {"kimi", "zcode"}, "security": {"zcode", "agy"}, "maintainability": {"zcode", "agy"},
		"product": {"zcode", "agy"}, "documentation": {"agy", "zcode"}, "testing": {"zcode", "agy"},
	}
	if len(redacted.Policy.RoleAssignments) != len(want) {
		t.Fatalf("role assignment count = %d", len(redacted.Policy.RoleAssignments))
	}
	for _, assignment := range redacted.Policy.RoleAssignments {
		expected, ok := want[assignment.Role]
		if !ok || assignment.FallbackProvider == nil || assignment.PrimaryProvider != expected[0] || *assignment.FallbackProvider != expected[1] {
			t.Fatalf("unexpected config assignment: %#v", assignment)
		}
	}
}

func assertLiveThreeLaneConfig(t *testing.T, project string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(project, ".kar", "config.yaml"))
	if err != nil {
		t.Fatalf("read live config: %v", err)
	}
	config, err := adapterconfig.Decode(data)
	if err != nil {
		t.Fatalf("decode live config: %v", err)
	}
	if config.Resources.MaxActiveLanes != 3 {
		t.Fatalf("max_active_lanes = %d, want 3", config.Resources.MaxActiveLanes)
	}
}

func assertLiveDoctorPrequalification(t *testing.T, raw json.RawMessage) {
	t.Helper()
	families := []string{"kimi", "zcode", "agy"}
	var doctor struct {
		ConfiguredProviderIDs []string `json:"configured_provider_ids"`
		Readiness             struct {
			State string `json:"state"`
		} `json:"readiness"`
		ProviderInventory []struct {
			Family string `json:"family"`
			State  string `json:"state"`
			Reason string `json:"reason"`
		} `json:"provider_inventory"`
	}
	if err := json.Unmarshal(raw, &doctor); err != nil {
		t.Fatalf("decode doctor result: %v", err)
	}
	if doctor.Readiness.State != "unverified" || !reflect.DeepEqual(doctor.ConfiguredProviderIDs, families) {
		t.Fatalf("doctor readiness = %#v", doctor)
	}
	unverified := map[string]bool{}
	for _, row := range doctor.ProviderInventory {
		if row.State == "unavailable" && row.Reason == "provider_admission_unverified" {
			unverified[row.Family] = true
		}
	}
	for _, family := range families {
		if !unverified[family] {
			t.Fatalf("doctor did not retain truthful prequalification state for %s: %#v", family, doctor.ProviderInventory)
		}
	}
}

func assertLiveAssignments(t *testing.T, run livePublishedRun, expected map[string][2]string) {
	t.Helper()
	if len(run.manifest.SelectedRoles) != len(expected) || len(run.review.RoleOutcomes) != len(expected) {
		t.Fatalf("selected role cardinality mismatch: selected=%v outcomes=%#v", run.manifest.SelectedRoles, run.review.RoleOutcomes)
	}
	for role, providers := range expected {
		attempts := liveAttemptsForRole(run.manifest.Attempts, role)
		var outcome *liveRoleOutcome
		for index := range run.review.RoleOutcomes {
			if run.review.RoleOutcomes[index].Role == role {
				outcome = &run.review.RoleOutcomes[index]
				break
			}
		}
		if outcome == nil || outcome.Outcome != "completed" || outcome.AttemptID == nil || outcome.ProviderInstance == nil || outcome.SelectedVia == nil {
			t.Fatalf("%s role outcome is not completed: %#v", role, outcome)
		}
		if len(attempts) == 0 || attempts[0].ProviderInstance != providers[0] || attempts[0].SelectedAs != "primary" {
			t.Fatalf("%s primary attempt does not bind %s: %#v", role, providers[0], attempts)
		}
		switch *outcome.SelectedVia {
		case "primary":
			if len(attempts) != 1 || attempts[0].State != "succeeded" || *outcome.AttemptID != attempts[0].AttemptID || *outcome.ProviderInstance != providers[0] {
				t.Fatalf("%s primary outcome mismatch: attempts=%#v outcome=%#v", role, attempts, outcome)
			}
		case "fallback":
			if providers[1] == "" || len(attempts) != 2 || attempts[0].State == "succeeded" || attempts[1].ProviderInstance != providers[1] ||
				attempts[1].SelectedAs != "fallback" || attempts[1].State != "succeeded" || *outcome.AttemptID != attempts[1].AttemptID || *outcome.ProviderInstance != providers[1] {
				t.Fatalf("%s fallback outcome mismatch: attempts=%#v outcome=%#v", role, attempts, outcome)
			}
		default:
			t.Fatalf("%s selected_via = %q", role, *outcome.SelectedVia)
		}
	}
}

func assertLivePrimaryAssignments(t *testing.T, run livePublishedRun, expected map[string]string) {
	t.Helper()
	if err := validateLivePrimaryAssignments(run, expected); err != nil {
		t.Fatal(err)
	}
}

func validateLivePrimaryAssignments(run livePublishedRun, expected map[string]string) error {
	if len(run.manifest.SelectedRoles) != len(expected) || len(run.review.RoleOutcomes) != len(expected) {
		return fmt.Errorf("selected role cardinality mismatch: selected=%v outcomes=%#v", run.manifest.SelectedRoles, run.review.RoleOutcomes)
	}
	providers := make(map[string]struct{}, len(expected))
	for role, provider := range expected {
		attempts := liveAttemptsForRole(run.manifest.Attempts, role)
		if len(attempts) != 1 {
			return fmt.Errorf("%s role has %d attempts, want one primary attempt: %#v; failures=%#v outcomes=%#v", role, len(attempts), attempts, run.manifest.Failures, run.review.RoleOutcomes)
		}
		attempt := attempts[0]
		if attempt.ProviderInstance != provider || attempt.SelectedAs != "primary" || attempt.State != "succeeded" || attempt.InvocationCount != 1 {
			return fmt.Errorf("%s primary lane mismatch: %#v, want provider=%s state=succeeded invocation_count=1; failures=%#v", role, attempt, provider, run.manifest.Failures)
		}
		if _, duplicate := providers[provider]; duplicate {
			return fmt.Errorf("provider %s was assigned more than one focused primary role", provider)
		}
		providers[provider] = struct{}{}

		var outcome *liveRoleOutcome
		for index := range run.review.RoleOutcomes {
			if run.review.RoleOutcomes[index].Role == role {
				outcome = &run.review.RoleOutcomes[index]
				break
			}
		}
		if outcome == nil || outcome.Outcome != "completed" && outcome.Outcome != "degraded" || outcome.AttemptID == nil || *outcome.AttemptID != attempt.AttemptID ||
			outcome.ProviderInstance == nil || *outcome.ProviderInstance != provider || outcome.SelectedVia == nil || *outcome.SelectedVia != "primary" {
			return fmt.Errorf("%s primary outcome mismatch: attempt=%#v outcome=%#v", role, attempt, outcome)
		}
	}
	if len(providers) != len(expected) {
		return fmt.Errorf("focused run used %d independent providers, want %d: %v", len(providers), len(expected), providers)
	}
	return nil
}

func assertLiveSecurityFinding(t *testing.T, run livePublishedRun, provider string) {
	t.Helper()
	if liveSecurityFindingPresent(run, provider) {
		return
	}
	t.Fatalf("focused run has no security finding from %s: %#v", provider, run.review.Findings)
}

func liveSecurityFindingPresent(run livePublishedRun, provider string) bool {
	for _, finding := range run.review.Findings {
		if finding.Role == "security" && finding.ProviderInstance == provider {
			return true
		}
	}
	return false
}

func assertLiveSourceBoundAssignment(t *testing.T, run livePublishedRun, role, provider string) {
	t.Helper()
	attempt := requireLiveAttempt(t, run.manifest.Attempts, role)
	if attempt.ProviderInstance != provider || attempt.SelectedAs != "primary" || attempt.State != "succeeded" {
		t.Fatalf("source-bound %s attempt = %#v, want successful %s", role, attempt, provider)
	}
	if len(run.review.RoleOutcomes) != 1 || run.review.RoleOutcomes[0].Role != role || run.review.RoleOutcomes[0].Outcome != "completed" ||
		run.review.RoleOutcomes[0].AttemptID == nil || *run.review.RoleOutcomes[0].AttemptID != attempt.AttemptID ||
		run.review.RoleOutcomes[0].ProviderInstance == nil || *run.review.RoleOutcomes[0].ProviderInstance != provider ||
		run.review.RoleOutcomes[0].SelectedVia == nil || *run.review.RoleOutcomes[0].SelectedVia != "primary" {
		t.Fatalf("source-bound %s outcome mismatch: %#v", role, run.review.RoleOutcomes)
	}
}

func liveAttemptsForRole(attempts []liveAttempt, role string) []liveAttempt {
	result := make([]liveAttempt, 0, 2)
	for _, attempt := range attempts {
		if attempt.Role == role {
			result = append(result, attempt)
		}
	}
	return result
}

func requireLiveAttempt(t *testing.T, attempts []liveAttempt, role string) liveAttempt {
	t.Helper()
	var matches []liveAttempt
	for _, attempt := range attempts {
		if attempt.Role == role {
			matches = append(matches, attempt)
		}
	}
	if len(matches) != 1 {
		t.Fatalf("role %s has %d attempts: %#v", role, len(matches), matches)
	}
	return matches[0]
}

func requireLiveSelectedAttempt(t *testing.T, run livePublishedRun, role string) liveAttempt {
	t.Helper()
	var outcome *liveRoleOutcome
	for index := range run.review.RoleOutcomes {
		if run.review.RoleOutcomes[index].Role == role {
			outcome = &run.review.RoleOutcomes[index]
			break
		}
	}
	if outcome == nil || outcome.AttemptID == nil {
		t.Fatalf("role %s has no selected attempt outcome: %#v", role, run.review.RoleOutcomes)
	}
	for _, attempt := range run.manifest.Attempts {
		if attempt.AttemptID == *outcome.AttemptID {
			return attempt
		}
	}
	t.Fatalf("role %s selected attempt %s is absent", role, *outcome.AttemptID)
	return liveAttempt{}
}

func assertLiveSourceLineage(t *testing.T, child, source livePublishedRun, finding, replay string) {
	t.Helper()
	lineage := child.manifest.ImmutableLineage
	if lineage.SourceRunID == nil || *lineage.SourceRunID != source.manifest.RunID || lineage.SourceReviewID == nil || *lineage.SourceReviewID != source.review.ReviewID {
		t.Fatalf("child source lineage does not bind root P2: %#v", lineage)
	}
	if finding == "" {
		if lineage.SourceFindingRef != nil {
			t.Fatalf("unexpected source finding lineage: %#v", lineage)
		}
	} else if lineage.SourceFindingRef == nil || *lineage.SourceFindingRef != finding {
		t.Fatalf("followup source finding lineage = %#v, want %s", lineage, finding)
	}
	if replay == "" {
		if lineage.ReplayMode != nil {
			t.Fatalf("unexpected replay lineage: %#v", lineage)
		}
	} else if lineage.ReplayMode == nil || *lineage.ReplayMode != replay {
		t.Fatalf("replay lineage = %#v, want %s", lineage, replay)
	}
	if !reflect.DeepEqual(lineage, child.review.ImmutableLineage) {
		t.Fatalf("manifest/review lineage mismatch: %#v != %#v", lineage, child.review.ImmutableLineage)
	}
}

func (environment liveE2EEnvironment) String() string {
	return fmt.Sprintf("KAR=%s HOME=%s Kimi=%s ZCode=%s/%s AGY=%s", environment.binary, environment.nativeHome, environment.kimi, environment.zcodeNode, environment.zcodeLauncher, environment.agy)
}
