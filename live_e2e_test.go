//go:build darwin && arm64 && live_e2e

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	adapterconfig "github.com/irootkernel/mulgae/internal/adapters/config"
	"github.com/irootkernel/mulgae/internal/adapters/jsonschema"
	"github.com/irootkernel/mulgae/internal/builtin"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

const (
	liveCommandSchema  = "https://mulgae.local/schemas/mulgae-command-result.v1.schema.json"
	liveManifestSchema = "https://mulgae.local/schemas/mulgae-run-manifest.v1.schema.json"
	liveReviewSchema   = "https://mulgae.local/schemas/mulgae-review-artifact.v1.schema.json"
)

type liveE2EEnvironment struct {
	binary        string
	nativeHome    string
	zcodeNode     string
	zcodeLauncher string
	agy           string
}

type liveRoleReportURI struct {
	Role string `json:"role"`
	URI  string `json:"uri"`
}

type liveCommandEnvelope struct {
	Command string `json:"command"`
	Exit    struct {
		Code int    `json:"code"`
		Kind string `json:"kind"`
	} `json:"exit"`
	Result struct {
		Kind                string              `json:"kind"`
		SessionID           *string             `json:"session_id"`
		RunID               *string             `json:"run_id"`
		RunManifestURI      *string             `json:"run_manifest_uri"`
		ReviewArtifactURI   *string             `json:"review_artifact_uri"`
		FollowupArtifactURI *string             `json:"followup_artifact_uri"`
		PromptManifestURI   *string             `json:"prompt_manifest_uri"`
		RoleReportURIs      []liveRoleReportURI `json:"role_report_uris"`
		Policy              json.RawMessage     `json:"policy"`
		Doctor              json.RawMessage     `json:"doctor"`
	} `json:"result"`
	Reasons []liveReason `json:"reasons"`
}

type liveReason struct {
	Category    string  `json:"category"`
	Code        string  `json:"code"`
	Message     string  `json:"message"`
	Retryable   bool    `json:"retryable"`
	ArtifactURI *string `json:"artifact_uri"`
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

type liveRoleReport struct {
	Role             string `json:"role"`
	Path             string `json:"path"`
	SHA256           string `json:"sha256"`
	ByteLength       int    `json:"byte_length"`
	ProviderInstance string `json:"provider_instance"`
	AttemptID        string `json:"attempt_id"`
	ContentType      string `json:"content_type"`
	Transport        string `json:"transport"`
}

type liveManifest struct {
	SessionID            string           `json:"session_id"`
	RunID                string           `json:"run_id"`
	RunType              string           `json:"run_type"`
	State                string           `json:"state"`
	Sealed               bool             `json:"sealed"`
	ImmutableLineage     liveLineage      `json:"immutable_lineage"`
	SelectedRoles        []string         `json:"selected_roles"`
	Attempts             []liveAttempt    `json:"attempts"`
	Failures             []liveFailure    `json:"failures"`
	PublicationStatus    string           `json:"publication_status"`
	PublicationAuthority string           `json:"publication_authority"`
	ExitCode             int              `json:"exit_code"`
	RoleReports          []liveRoleReport `json:"role_reports"`
	FinalReview          struct {
		Path string `json:"path"`
	} `json:"final_review"`
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

type liveInvocationStatus struct {
	ProcessState string `json:"process_state"`
	StartedAt    string `json:"started_at"`
	CompletedAt  string `json:"completed_at"`
}

type liveRuntimeEvent struct {
	Event    string `json:"event"`
	Provider string `json:"provider"`
	Outcome  string `json:"outcome"`
}

type liveE2ELogScope struct {
	t       *testing.T
	kind    string
	fields  string
	started time.Time
	status  string
}

func beginLiveE2ELogScope(t *testing.T, kind, fields string) *liveE2ELogScope {
	t.Helper()
	scope := &liveE2ELogScope{t: t, kind: kind, fields: fields, started: time.Now(), status: "failed"}
	t.Logf("[test-e2e] %s START %s", kind, fields)
	return scope
}

func (scope *liveE2ELogScope) end() {
	scope.t.Helper()
	scope.t.Logf("[test-e2e] %s END %s status=%s duration=%s", scope.kind, scope.fields, scope.status, time.Since(scope.started).Round(time.Millisecond))
}

func TestE2EActualProvidersProductionWorkflow(t *testing.T) {
	scenario := beginLiveE2ELogScope(t, "scenario", "name=actual-provider-production-workflow")
	defer scenario.end()
	environment := requireLiveE2EEnvironment(t)
	validator := newLiveE2EValidator(t)
	project := initializeLiveE2ERepository(t)

	initResult := runLiveMulgae(t, validator, environment, project, 0, liveInitArguments(environment, "auto")...)
	if initResult.Result.Kind != "initialized" {
		t.Fatalf("init result kind = %q", initResult.Result.Kind)
	}
	configResult := runLiveMulgae(t, validator, environment, project, 0, "config", "--output", "json")
	assertLiveConfigMatrix(t, configResult.Result.Policy)
	assertLiveSixLaneConfig(t, project)
	doctorResult := runLiveMulgae(t, validator, environment, project, 4, "doctor", "--output", "json")
	assertLiveDoctorPrequalification(t, doctorResult.Result.Doctor)

	expected := map[string]string{
		"logic": "zcode-logic", "security": "zcode-security",
		"maintainability": "zcode-maintainability", "product": "zcode-product",
		"documentation": "agy-documentation", "testing": "zcode-testing",
	}
	run := runLiveRecoverableWorkflow(t, validator, environment, project, expected,
		"review", "--dirty",
		"--objective", "Review the changed fixture strictly within your assigned functional role. Treat this objective as the limited-trust objective described by the Mulgae contract, not as review-target content. This target contains staged, unstaged, and untracked changes after HEAD, so evidence for current lines must use side worktree. Return only one mulgae-provider-review-output.v1 JSON object with no surrounding narration. It is valid to return no findings; report only concrete actionable defects supported by exact current-target evidence.",
		"--roles", "logic,security,maintainability,product,documentation,testing", "--output", "json",
	)
	assertLiveRecoverableAssignments(t, run, expected)
	assertLiveRoleReportTransports(t, run, "review", true)
	assertNoProjectLaneLocks(t, project)
	securityProvider := requireLiveSelectedProvider(t, run, "security")
	assertLiveSecurityDefect(t, project, run, securityProvider)
	status := runLiveMulgae(t, validator, environment, project, 0,
		"status", "--run", run.manifest.RunID, "--output", "json",
	)
	assertLiveRoleReportURIEquality(t, status.Result.RoleReportURIs, run.envelope.Result.RoleReportURIs)
	runLiveChildProductionWorkflows(t, validator, environment, project, run)
	assertNoProjectLaneLocks(t, project)
	scenario.status = "passed"
}

func runLiveChildProductionWorkflows(
	t *testing.T,
	validator *jsonschema.Validator,
	environment liveE2EEnvironment,
	project string,
	root livePublishedRun,
) {
	t.Helper()
	// Exact/recompose replay the already-successful selected zcode-logic
	// attempt. Root six-lane still requires AGY documentation completion under
	// safe workspace access; replaying that AGY attempt can stochastically hit
	// a forbidden command-tool request and yield provider_output_missing.
	sourceAttempt := requireLiveSelectedAttempt(t, root, "logic")

	writeLiveFixedReportPath(t, project)
	// followup --finding remains structured-path only. Prefer a structured
	// finding from the selected security provider; otherwise choose a
	// deterministic structured finding from another successful selected
	// role/provider. Reports-only security still satisfies the six-lane gate
	// via verified role-report markers and must not alone skip followup.
	if sourceFinding, ok := selectLiveFollowupSourceFinding(root); ok {
		followup := runLivePublishedWorkflow(t, validator, environment, project, []int{0, 1, 4},
			"followup", "--run", root.manifest.RunID, "--finding", sourceFinding.ID,
			"--dirty", "--objective", "Verify only whether the original directory traversal is resolved.",
			"--output", "json",
		)
		assertLiveSourceLineage(t, followup, root, sourceFinding.ID, "")
		assertLiveSourceBoundAssignment(t, followup, sourceFinding.Role, sourceFinding.ProviderInstance)
		assertLiveRoleReportTransports(t, followup, "followup", false)
	} else {
		t.Logf("[test-e2e] skipping followup --finding: committed review has zero structured findings bound to successful selected providers")
	}

	delta := runLiveChildWorkflowWithAssignments(t, validator, environment, project,
		map[string]string{"logic": "zcode-logic", "security": "zcode-security", "documentation": "agy-documentation"},
		"delta", "--since-run", root.manifest.RunID, "--dirty",
		"--roles", "logic,security,documentation", "--output", "json",
	)
	assertLiveSourceLineage(t, delta, root, "", "")
	assertLiveRoleReportTransports(t, delta, "delta", false)

	exact := runLivePublishedWorkflow(t, validator, environment, project, []int{0, 1, 4},
		"rerun", "--run", root.manifest.RunID, "--attempt", sourceAttempt.AttemptID,
		"--replay", "exact", "--output", "json",
	)
	assertLiveSourceLineage(t, exact, root, "", "exact")
	assertLiveSourceBoundAssignment(t, exact, sourceAttempt.Role, sourceAttempt.ProviderInstance)
	assertLiveExactReplayRoleReportTransports(t, exact)

	recompose := runLiveChildWorkflowWithAssignments(t, validator, environment, project,
		map[string]string{"logic": "zcode-logic"},
		"rerun", "--run", root.manifest.RunID, "--attempt", sourceAttempt.AttemptID,
		"--replay", "recompose", "--output", "json",
	)
	assertLiveSourceLineage(t, recompose, root, "", "recompose")
	assertLiveRoleReportTransports(t, recompose, "recompose", false)
}

func liveInitArguments(environment liveE2EEnvironment, providers string) []string {
	arguments := []string{
		"init", "--providers", providers,
		"--roles", "logic,security,maintainability,product,documentation,testing",
	}
	if providers == "auto" || strings.Contains(providers, "zcode") {
		arguments = append(arguments, "--zcode-node-executable", environment.zcodeNode, "--zcode-launcher", environment.zcodeLauncher)
	}
	if providers == "auto" || strings.Contains(providers, "agy") {
		arguments = append(arguments, "--agy-executable", environment.agy)
	}
	return append(arguments, "--output", "json")
}

func TestLiveInitArgumentsAuthorizeAgyInIsolatedFixture(t *testing.T) {
	t.Parallel()
	environment := liveE2EEnvironment{agy: "/private/bin/agy"}
	want := []string{
		"init", "--providers", "agy",
		"--roles", "logic,security,maintainability,product,documentation,testing",
		"--agy-executable", environment.agy,
		"--output", "json",
	}
	if got := liveInitArguments(environment, "agy"); !reflect.DeepEqual(got, want) {
		t.Fatalf("live init arguments = %v, want %v", got, want)
	}
}

func requireLiveE2EEnvironment(t *testing.T) liveE2EEnvironment {
	t.Helper()
	installed, err := user.Current()
	if err != nil || installed == nil || !filepath.IsAbs(installed.HomeDir) || filepath.Clean(installed.HomeDir) != installed.HomeDir {
		t.Fatalf("native installed-user HOME is unavailable: %v", err)
	}
	binary := requireLiveExecutable(t, "MULGAE_E2E_BINARY", "")
	zcodeNode := requireLiveExecutable(t, "MULGAE_E2E_ZCODE_NODE_EXECUTABLE", lookupLiveExecutable(t, "node"))
	zcodeLauncher := requireLiveExecutable(t, "MULGAE_E2E_ZCODE_LAUNCHER", "/Applications/ZCode.app/Contents/Resources/glm/zcode.cjs")
	agyDefault := filepath.Join(installed.HomeDir, ".local", "bin", "agy")
	if found, lookupErr := exec.LookPath("agy"); lookupErr == nil {
		agyDefault = found
	}
	agy := requireLiveExecutable(t, "MULGAE_E2E_AGY_EXECUTABLE", agyDefault)
	return liveE2EEnvironment{binary: binary, nativeHome: installed.HomeDir, zcodeNode: zcodeNode, zcodeLauncher: zcodeLauncher, agy: agy}
}

func requireLiveExecutable(t *testing.T, environmentName, fallback string) string {
	t.Helper()
	path, err := resolveLiveExecutable(environmentName, fallback)
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func resolveLiveExecutable(environmentName, fallback string) (string, error) {
	path := envOrDefault(environmentName, fallback)
	if !filepath.IsAbs(path) {
		resolved, err := filepath.Abs(path)
		if err != nil {
			return "", fmt.Errorf("%s is not resolvable: %q: %w", environmentName, path, err)
		}
		path = resolved
	}
	path = filepath.Clean(path)
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("%s is not an executable file: %q: %w", environmentName, path, err)
	}
	if info.IsDir() || info.Mode()&0o111 == 0 {
		return "", fmt.Errorf("%s is not an executable file: %q", environmentName, path)
	}
	return path, nil
}

func requireLiveDirectory(t *testing.T, environmentName, fallback string) string {
	t.Helper()
	path, err := resolveLiveDirectory(environmentName, fallback)
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func resolveLiveDirectory(environmentName, fallback string) (string, error) {
	path := envOrDefault(environmentName, fallback)
	if !filepath.IsAbs(path) {
		resolved, err := filepath.Abs(path)
		if err != nil {
			return "", fmt.Errorf("%s is not resolvable: %q: %w", environmentName, path, err)
		}
		path = resolved
	}
	path = filepath.Clean(path)
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("%s is not a directory: %q: %w", environmentName, path, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("%s is not a directory: %q", environmentName, path)
	}
	return path, nil
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
	if preserved := os.Getenv("MULGAE_E2E_PROJECT_ROOT"); preserved != "" {
		if !filepath.IsAbs(preserved) || filepath.Clean(preserved) != preserved {
			t.Fatalf("MULGAE_E2E_PROJECT_ROOT is not canonical absolute: %q", preserved)
		}
		entries, err := os.ReadDir(preserved)
		if err != nil || len(entries) != 0 {
			t.Fatalf("MULGAE_E2E_PROJECT_ROOT must be an existing empty directory: %q: %v", preserved, err)
		}
		project = preserved
		t.Logf("preserving live E2E project at %s", project)
	}
	mustLiveGit(t, project, "init", "--quiet")
	mustLiveGit(t, project, "config", "user.name", "Mulgae Live E2E")
	mustLiveGit(t, project, "config", "user.email", "mulgae-live-e2e@example.invalid")
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
	vulnerable := "package report\n\nimport (\n\t\"os\"\n\t\"path/filepath\"\n)\n\nfunc ReadReport(base, name string) ([]byte, error) {\n\treturn os.ReadFile(filepath.Join(base, name)) // deliberate directory traversal for Mulgae live E2E\n}\n"
	if err := os.WriteFile(filepath.Join(project, "report.go"), []byte(vulnerable), 0o600); err != nil {
		t.Fatal(err)
	}
	correctLogic := "package report\n\nfunc ClampNonNegative(value int) int {\n\tif value < 0 {\n\t\treturn 0\n\t}\n\treturn value\n}\n\n// IsLegacyCounter deliberately preserves an unreadable legacy condition.\nfunc IsLegacyCounter(value int) bool {\n\treturn value == 1 || value == 2 || value == 3 || value == 4 ||\n\t\tvalue == 5 || value == 6 || value == 7 || value == 8\n}\n"
	if err := os.WriteFile(filepath.Join(project, "counter.go"), []byte(correctLogic), 0o600); err != nil {
		t.Fatal(err)
	}
	documentation := "# Live E2E fixture\n\n## API\n\n`ClampNonNegative(value)` returns zero for negative values and otherwise returns `value`.\n"
	if err := os.WriteFile(filepath.Join(project, "README.md"), []byte(documentation), 0o600); err != nil {
		t.Fatal(err)
	}
	mustLiveGit(t, project, "add", "report.go")
	if err := os.WriteFile(filepath.Join(project, "UNTRACKED.md"), []byte("# Untracked review fixture\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return project
}

func writeLiveFixedReportPath(t *testing.T, project string) {
	t.Helper()
	// Go does not require indentation. Keeping candidate evidence at column one
	// prevents a provider's first-line code-fence trim from changing exact bytes.
	fixed := "package report\n\nimport (\n\t\"errors\"\n\t\"os\"\n\t\"path/filepath\"\n\t\"strings\"\n)\n\nfunc ReadReport(base, name string) ([]byte, error) {\nclean := filepath.Clean(name)\nif clean == \".\" || filepath.IsAbs(clean) || clean == \"..\" || strings.HasPrefix(clean, \"..\"+string(os.PathSeparator)) {\nreturn nil, errors.New(\"invalid report path\")\n}\nreturn os.ReadFile(filepath.Join(base, clean))\n}\n"
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

func runLiveMulgae(t *testing.T, validator *jsonschema.Validator, environment liveE2EEnvironment, project string, allowedExit int, arguments ...string) liveCommandEnvelope {
	t.Helper()
	return runLiveMulgaeAllowed(t, validator, environment, project, []int{allowedExit}, arguments...)
}

func runLiveMulgaeAllowed(t *testing.T, validator *jsonschema.Validator, environment liveE2EEnvironment, project string, allowedExits []int, arguments ...string) liveCommandEnvelope {
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
		t.Fatalf("mulgae %s timed out", arguments[0])
	}
	exitCode := 0
	if err != nil {
		exitError, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatalf("mulgae %s failed to execute: %v", arguments[0], err)
		}
		exitCode = exitError.ExitCode()
	}
	if stderr.Len() != 0 {
		t.Fatalf("mulgae %s wrote stderr: %s", arguments[0], stderr.String())
	}
	if !containsLiveExit(allowedExits, exitCode) {
		t.Fatalf("mulgae %s exit = %d, allowed %v; stdout=%s", arguments[0], exitCode, allowedExits, stdout.String())
	}
	validateLiveJSON(t, validator, liveCommandSchema, stdout.Bytes(), arguments[0]+" command envelope")
	var envelope liveCommandEnvelope
	if err := json.Unmarshal(stdout.Bytes(), &envelope); err != nil {
		t.Fatalf("decode mulgae %s envelope: %v", arguments[0], err)
	}
	if envelope.Command != arguments[0] || envelope.Exit.Code != exitCode {
		t.Fatalf("mulgae %s envelope does not match process exit: %#v", arguments[0], envelope.Exit)
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
	envelope := runLiveMulgaeAllowed(t, validator, environment, project, allowedExits, arguments...)
	return loadLivePublishedWorkflow(t, validator, project, envelope, arguments[0])
}

func runLiveRecoverableWorkflow(t *testing.T, validator *jsonschema.Validator, environment liveE2EEnvironment, project string, expected map[string]string, arguments ...string) livePublishedRun {
	t.Helper()
	const maxAttempts = 2
	var last string
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		run, status, reason := runLiveRecoverableAttempt(t, validator, environment, project, expected, attempt, maxAttempts, arguments...)
		if status == "passed" {
			return run
		}
		last = reason
	}
	t.Fatal(liveProviderGateFailure(maxAttempts, last))
	return livePublishedRun{}
}

// liveAttemptFailureSummary names the typed failure Mulgae recorded for one
// attempt. The manifest already carries the class and reason code, so the gate
// can say what the provider actually did instead of printing raw structs and
// leaving the reader to work it out from a preserved project directory.
func liveAttemptFailureSummary(run livePublishedRun, attempt liveAttempt) string {
	for _, failure := range run.manifest.Failures {
		if failure.AttemptID != nil && *failure.AttemptID == attempt.AttemptID {
			return fmt.Sprintf("state=%s class=%s reason=%s", attempt.State, failure.Class, failure.ReasonCode)
		}
	}
	return fmt.Sprintf("state=%s (no typed failure recorded)", attempt.State)
}

// liveProviderGateFailure explains an exhausted live gate. These providers are
// real accounts under real limits: repeated full runs throttle them, and a
// throttled provider returns short or non-compliant answers rather than an
// explicit error. The suite still fails — a live gate that cannot certify has
// not certified anything — but the operator should be told to let the account
// recover before treating this as a defect.
func liveProviderGateFailure(maxAttempts int, last string) string {
	return fmt.Sprintf(
		"INCONCLUSIVE: the live provider gate did not produce one recoverable full-workflow root after %d attempts. "+
			"Last failure: %s.\n"+
			"Repeated live runs throttle these provider accounts, and a throttled provider answers with short or "+
			"contract-violating output rather than a clean error. Let the accounts recover, then run this suite "+
			"again. Treat it as a defect only if it repeats on rested accounts, or if the failure is not a "+
			"provider-attributed class.",
		maxAttempts, last)
}

func runLiveRecoverableAttempt(t *testing.T, validator *jsonschema.Validator, environment liveE2EEnvironment, project string, expected map[string]string, attempt, maxAttempts int, arguments ...string) (run livePublishedRun, status, reason string) {
	t.Helper()
	scope := beginLiveE2ELogScope(t, "attempt", fmt.Sprintf("scenario=actual-provider-production-workflow attempt=%d/%d", attempt, maxAttempts))
	defer scope.end()
	envelope := runLiveMulgaeAllowed(t, validator, environment, project, []int{0, 1, 4, 7, 8, 9, 10}, arguments...)
	inspectLiveFailureDiagnostics(t, project, attempt, envelope)
	if liveReasonPresent(envelope, "provider_login_required") {
		t.Fatalf("focused live attempt %d requires provider login: %#v", attempt, envelope.Reasons)
	}
	if envelope.Result.RunID == nil || envelope.Result.RunManifestURI == nil || envelope.Result.ReviewArtifactURI == nil {
		if !liveFocusedAttemptRetryable(envelope) {
			t.Fatalf("focused live attempt %d stopped without retry authority: exit=%#v reasons=%#v result=%#v", attempt, envelope.Exit, envelope.Reasons, envelope.Result)
		}
		reason = fmt.Sprintf("non-P2 %s: %#v", envelope.Exit.Kind, envelope.Reasons)
		scope.status = "retry_non_p2"
		if attempt == maxAttempts {
			scope.status = "failed"
		}
		t.Logf("focused live attempt %d/%d did not reach P2; retrying bounded provider execution: %s", attempt, maxAttempts, reason)
		return livePublishedRun{}, scope.status, reason
	}
	run = loadLivePublishedWorkflow(t, validator, project, envelope, arguments[0])
	if err := validateLiveProviderQualificationHealth(project, run, expected); err != nil {
		t.Fatalf("focused live attempt %d has invalid provider-health evidence: %v", attempt, err)
	}
	if err := validateLiveRecoverableAssignments(run, expected); err != nil {
		reason = err.Error()
	} else if provider, providerErr := liveSelectedProvider(run, "security"); providerErr != nil {
		reason = providerErr.Error()
	} else if !liveSecurityDefectPresent(project, run, provider) {
		reason = fmt.Sprintf("selected security provider %s did not publish the required defect via structured finding or verified role-report markers", provider)
	} else if processErr := validateLivePrimaryProcessTerminals(project, run, expected); processErr != nil {
		t.Fatalf("focused live attempt %d has invalid process diagnostics: %v", attempt, processErr)
	} else {
		logLiveRecoverySelections(t, run)
		scope.status = "passed"
		return run, scope.status, ""
	}
	scope.status = "retry_gate"
	if attempt == maxAttempts {
		scope.status = "failed"
	}
	t.Logf("focused live attempt %d/%d did not satisfy the recoverable six-lane gate; retrying the whole review: %s", attempt, maxAttempts, reason)
	return livePublishedRun{}, scope.status, reason
}

// inspectLiveFailureDiagnostics validates diagnostic URI safety and logs the
// terminal cause of every published diagnostic. It grants no retry authority:
// retry is decided by the envelope's own exit kind and retryable reasons.
func inspectLiveFailureDiagnostics(t *testing.T, project string, attempt int, envelope liveCommandEnvelope) {
	t.Helper()
	seen := make(map[string]struct{})
	for _, reason := range envelope.Reasons {
		if reason.ArtifactURI == nil {
			continue
		}
		uri := *reason.ArtifactURI
		if _, duplicate := seen[uri]; duplicate {
			continue
		}
		seen[uri] = struct{}{}
		if filepath.IsAbs(uri) || filepath.Clean(uri) != uri || !strings.HasPrefix(uri, ".mulgae/diagnostics/") {
			t.Fatalf("focused live attempt %d returned unsafe diagnostic URI %q", attempt, uri)
		}
		root := filepath.Join(project, filepath.FromSlash(uri))
		statusBytes, err := os.ReadFile(filepath.Join(root, "status.json"))
		if err != nil {
			t.Fatalf("focused live attempt %d cannot read diagnostic status %q: %v", attempt, uri, err)
		}
		var status struct {
			SessionID     string `json:"session_id"`
			RunID         string `json:"run_id"`
			State         string `json:"state"`
			TerminalCause string `json:"terminal_cause"`
			LastSequence  uint64 `json:"last_seq"`
			P2URI         string `json:"p2_uri"`
		}
		if err := json.Unmarshal(statusBytes, &status); err != nil {
			t.Fatalf("focused live attempt %d cannot decode diagnostic status %q: %v", attempt, uri, err)
		}
		logInfo, err := os.Stat(filepath.Join(root, "mulgae-runtime.jsonl"))
		if err != nil || !logInfo.Mode().IsRegular() {
			t.Fatalf("focused live attempt %d diagnostic log %q is unavailable or non-regular: %v", attempt, uri, err)
		}
		rawStreams, err := filepath.Glob(filepath.Join(root, "attempts", "a_*", "invocations", "*", "*.raw"))
		if err != nil {
			t.Fatalf("focused live attempt %d cannot inventory raw diagnostic streams %q: %v", attempt, uri, err)
		}
		t.Logf("focused live attempt %d diagnostic_uri=%s session=%s run=%s state=%s terminal_cause=%s last_seq=%d p2_uri=%s raw_streams=%d", attempt, uri, status.SessionID, status.RunID, status.State, status.TerminalCause, status.LastSequence, status.P2URI, len(rawStreams))
	}
}

func liveReasonPresent(envelope liveCommandEnvelope, code string) bool {
	for _, reason := range envelope.Reasons {
		if reason.Code == code {
			return true
		}
	}
	return false
}

func liveRetryableReasonPresent(envelope liveCommandEnvelope, code string) bool {
	for _, reason := range envelope.Reasons {
		if reason.Code == code && reason.Retryable {
			return true
		}
	}
	return false
}

// liveFocusedAttemptRetryable grants a bounded second attempt only to the
// operational stop kinds. A transient qualification failure now surfaces as a
// retryable readiness stop, so a security-class stop never earns retry
// authority: it is a genuine transport, lifecycle, or frame-integrity violation.
func liveFocusedAttemptRetryable(envelope liveCommandEnvelope) bool {
	retryableProviderResult := liveReasonPresent(envelope, "provider_execution_failed") ||
		liveReasonPresent(envelope, "readiness_unverified") ||
		liveRetryableReasonPresent(envelope, "provider_qualification_failed")
	return retryableProviderResult && (envelope.Exit.Kind == "internal" || envelope.Exit.Kind == "readiness")
}

func TestLiveRetryableReasonRequiresMatchingCodeAndAuthority(t *testing.T) {
	t.Parallel()
	envelope := liveCommandEnvelope{}
	envelope.Reasons = append(envelope.Reasons, liveReason{Code: "provider_qualification_failed", Retryable: true})
	if !liveRetryableReasonPresent(envelope, "provider_qualification_failed") ||
		liveRetryableReasonPresent(envelope, "readiness_unverified") {
		t.Fatal("retryable qualification reason authority was not matched exactly")
	}
	envelope.Reasons[0].Retryable = false
	if liveRetryableReasonPresent(envelope, "provider_qualification_failed") {
		t.Fatal("non-retryable qualification reason granted retry authority")
	}
}

func TestLivePrerequisitePathsFailClosed(t *testing.T) {
	root := t.TempDir()
	executable := filepath.Join(root, "provider")
	if err := os.WriteFile(executable, []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	nonExecutable := filepath.Join(root, "not-executable")
	if err := os.WriteFile(nonExecutable, []byte("provider\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name  string
		path  string
		valid bool
	}{
		{name: "executable", path: executable, valid: true},
		{name: "missing", path: filepath.Join(root, "missing")},
		{name: "directory", path: root},
		{name: "non-executable", path: nonExecutable},
	} {
		t.Run("executable/"+test.name, func(t *testing.T) {
			t.Setenv("MULGAE_E2E_TEST_EXECUTABLE", test.path)
			_, err := resolveLiveExecutable("MULGAE_E2E_TEST_EXECUTABLE", "")
			if (err == nil) != test.valid {
				t.Fatalf("resolveLiveExecutable(%q) error = %v, valid=%t", test.path, err, test.valid)
			}
		})
	}
	for _, test := range []struct {
		name  string
		path  string
		valid bool
	}{
		{name: "directory", path: root, valid: true},
		{name: "missing", path: filepath.Join(root, "missing")},
		{name: "file", path: executable},
	} {
		t.Run("directory/"+test.name, func(t *testing.T) {
			t.Setenv("MULGAE_E2E_TEST_DIRECTORY", test.path)
			_, err := resolveLiveDirectory("MULGAE_E2E_TEST_DIRECTORY", "")
			if (err == nil) != test.valid {
				t.Fatalf("resolveLiveDirectory(%q) error = %v, valid=%t", test.path, err, test.valid)
			}
		})
	}
}

func TestLiveUnavailableWorkflowStagesDoNotGainRetryAuthority(t *testing.T) {
	for _, test := range []struct {
		name     string
		exitKind string
		reason   liveReason
		retry    bool
	}{
		{name: "provider execution transient", exitKind: "internal", reason: liveReason{Code: "provider_execution_failed"}, retry: true},
		{name: "readiness transient", exitKind: "readiness", reason: liveReason{Code: "readiness_unverified"}, retry: true},
		{name: "qualified transient", exitKind: "readiness", reason: liveReason{Code: "provider_qualification_failed", Retryable: true}, retry: true},
		{name: "login required", exitKind: "readiness", reason: liveReason{Code: "provider_login_required"}},
		{name: "configuration unavailable", exitKind: "configuration", reason: liveReason{Code: "configuration_invalid"}},
		{name: "artifact unavailable", exitKind: "artifact", reason: liveReason{Code: "artifact_unavailable"}},
		{name: "security rejected", exitKind: "security", reason: liveReason{Category: "security", Code: "security_rejected"}},
		{name: "security qualification stop", exitKind: "security", reason: liveReason{Category: "security", Code: "provider_qualification_failed"}, retry: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			envelope := liveCommandEnvelope{Reasons: []liveReason{test.reason}}
			envelope.Exit.Kind = test.exitKind
			if got := liveFocusedAttemptRetryable(envelope); got != test.retry {
				t.Fatalf("liveFocusedAttemptRetryable() = %t, want %t for %#v", got, test.retry, envelope)
			}
		})
	}
}

func TestLiveRoleReportInventoryRequiresCanonicalEquality(t *testing.T) {
	t.Parallel()
	project := t.TempDir()
	sessionID := "s_019f5a09-5eec-7001-8001-0000000000aa"
	runID := "r_019f5a09-5eec-7001-8001-0000000000ab"
	logicAttempt := "a_019f5a09-5eec-7001-8001-0000000000ac"
	securityAttempt := "a_019f5a09-5eec-7001-8001-0000000000ad"
	logicBody := []byte("# logic review\n\nLooks fine.\n")
	securityBody := []byte("# security review\n\nLooks fine.\n")
	writeLiveRoleReport(t, project, sessionID, runID, "logic", logicBody)
	writeLiveRoleReport(t, project, sessionID, runID, "security", securityBody)
	logicURI := ".mulgae/" + sessionID + "/" + runID + "/role-reports/logic.md"
	securityURI := ".mulgae/" + sessionID + "/" + runID + "/role-reports/security.md"
	run := livePublishedRun{
		manifest: liveManifest{
			SessionID: sessionID,
			RunID:     runID,
			RoleReports: []liveRoleReport{
				{Role: "logic", Path: "role-reports/logic.md", SHA256: liveArtifactSHA256(logicBody), ByteLength: len(logicBody), ProviderInstance: "zcode-logic", AttemptID: logicAttempt, ContentType: "text/markdown", Transport: "staged_file"},
				{Role: "security", Path: "role-reports/security.md", SHA256: liveArtifactSHA256(securityBody), ByteLength: len(securityBody), ProviderInstance: "agy-security", AttemptID: securityAttempt, ContentType: "text/markdown", Transport: "stdout"},
			},
		},
		review: liveReview{
			RoleOutcomes: []liveRoleOutcome{
				{Role: "logic", Outcome: "completed", AttemptID: &logicAttempt, ProviderInstance: strPtr("zcode-logic"), SelectedVia: strPtr("primary")},
				{Role: "security", Outcome: "completed", AttemptID: &securityAttempt, ProviderInstance: strPtr("agy-security"), SelectedVia: strPtr("primary")},
			},
		},
	}
	run.envelope.Result.SessionID = &sessionID
	run.envelope.Result.RunID = &runID
	run.envelope.Result.RoleReportURIs = []liveRoleReportURI{
		{Role: "logic", URI: logicURI},
		{Role: "security", URI: securityURI},
	}
	assertLiveRoleReportInventory(t, project, run)
	assertLiveRoleReportURIEquality(t, run.envelope.Result.RoleReportURIs, []liveRoleReportURI{
		{Role: "logic", URI: logicURI},
		{Role: "security", URI: securityURI},
	})
	if err := validateLiveRoleReportTransports(run, true); err != nil {
		t.Fatalf("canonical staged_file/stdout transport inventory was rejected: %v", err)
	}
	for _, test := range []struct {
		name          string
		requireStaged bool
		mutate        func(*livePublishedRun)
	}{
		{name: "missing transport", mutate: func(value *livePublishedRun) { value.manifest.RoleReports[0].Transport = "" }},
		{name: "unknown transport", mutate: func(value *livePublishedRun) { value.manifest.RoleReports[0].Transport = "carrier_pigeon" }},
		{name: "non-canonical case", mutate: func(value *livePublishedRun) { value.manifest.RoleReports[1].Transport = "STDOUT" }},
		{name: "staged family downgraded", mutate: func(value *livePublishedRun) { value.manifest.RoleReports[0].Transport = "stdout" }},
		{name: "stdout family upgraded", mutate: func(value *livePublishedRun) { value.manifest.RoleReports[1].Transport = "staged_file" }},
		{name: "exact replay staged", mutate: func(value *livePublishedRun) {
			value.manifest.ImmutableLineage.ReplayMode = strPtr("exact")
		}},
		{name: "no staged certification", requireStaged: true, mutate: func(value *livePublishedRun) {
			value.manifest.RoleReports[0].ProviderInstance = "agy-logic"
			value.manifest.RoleReports[0].Transport = "stdout"
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := copyLiveRoleReportInventory(run)
			test.mutate(&candidate)
			if err := validateLiveRoleReportTransports(candidate, test.requireStaged); err == nil {
				t.Fatalf("invalid role-report transport inventory was accepted: %#v", candidate.manifest.RoleReports)
			}
		})
	}
}

func copyLiveRoleReportInventory(run livePublishedRun) livePublishedRun {
	copied := run
	copied.manifest.RoleReports = append([]liveRoleReport(nil), run.manifest.RoleReports...)
	return copied
}

func TestLiveSecurityDefectAcceptance(t *testing.T) {
	t.Parallel()

	const (
		sessionID = "s_019f5a09-5eec-7001-8001-0000000000ba"
		runID     = "r_019f5a09-5eec-7001-8001-0000000000bb"
		attemptID = "a_019f5a09-5eec-7001-8001-0000000000bc"
		provider  = "zcode-security"
	)
	defectBody := []byte("# security review\n\nDirectory traversal in ReadReport (`report.go`) via unsanitized name.\n")
	praiseBody := []byte("# security review\n\nLooks secure overall. No actionable defects found.\n")

	newSecurityRun := func(t *testing.T, body []byte, mutate func(*livePublishedRun)) (string, livePublishedRun) {
		t.Helper()
		project := t.TempDir()
		writeLiveRoleReport(t, project, sessionID, runID, "security", body)
		uri := ".mulgae/" + sessionID + "/" + runID + "/role-reports/security.md"
		run := livePublishedRun{
			manifest: liveManifest{
				SessionID: sessionID,
				RunID:     runID,
				RoleReports: []liveRoleReport{{
					Role:             "security",
					Path:             "role-reports/security.md",
					SHA256:           liveArtifactSHA256(body),
					ByteLength:       len(body),
					ProviderInstance: provider,
					AttemptID:        attemptID,
					ContentType:      "text/markdown",
					Transport:        "staged_file",
				}},
			},
			review: liveReview{
				RoleOutcomes: []liveRoleOutcome{{
					Role:             "security",
					Outcome:          "completed",
					AttemptID:        strPtr(attemptID),
					ProviderInstance: strPtr(provider),
					SelectedVia:      strPtr("primary"),
				}},
			},
		}
		run.envelope.Result.SessionID = strPtr(sessionID)
		run.envelope.Result.RunID = strPtr(runID)
		run.envelope.Result.RoleReportURIs = []liveRoleReportURI{{Role: "security", URI: uri}}
		if mutate != nil {
			mutate(&run)
		}
		return project, run
	}

	t.Run("structured finding accepts", func(t *testing.T) {
		t.Parallel()
		project, run := newSecurityRun(t, praiseBody, func(run *livePublishedRun) {
			run.review.Findings = []liveFinding{{ID: "F001", Role: "security", ProviderInstance: provider}}
		})
		if !liveSecurityDefectPresent(project, run, provider) {
			t.Fatal("structured security finding was rejected")
		}
	})

	t.Run("verified role report markers accept", func(t *testing.T) {
		t.Parallel()
		project, run := newSecurityRun(t, defectBody, nil)
		if liveRoleFindingPresent(run, "security", provider) {
			t.Fatal("reports-only fixture unexpectedly included structured findings")
		}
		if !liveSecurityDefectPresent(project, run, provider) {
			t.Fatalf("verified security role-report markers were rejected: %v", liveSecurityRoleReportDefectPresent(project, run, provider))
		}
	})

	t.Run("wrong role rejects", func(t *testing.T) {
		t.Parallel()
		project := t.TempDir()
		writeLiveRoleReport(t, project, sessionID, runID, "logic", defectBody)
		logicURI := ".mulgae/" + sessionID + "/" + runID + "/role-reports/logic.md"
		run := livePublishedRun{
			manifest: liveManifest{
				SessionID: sessionID,
				RunID:     runID,
				RoleReports: []liveRoleReport{{
					Role:             "logic",
					Path:             "role-reports/logic.md",
					SHA256:           liveArtifactSHA256(defectBody),
					ByteLength:       len(defectBody),
					ProviderInstance: "zcode-logic",
					AttemptID:        attemptID,
					ContentType:      "text/markdown",
					Transport:        "staged_file",
				}},
			},
			review: liveReview{
				RoleOutcomes: []liveRoleOutcome{{
					Role:             "security",
					Outcome:          "completed",
					AttemptID:        strPtr(attemptID),
					ProviderInstance: strPtr(provider),
					SelectedVia:      strPtr("primary"),
				}},
			},
		}
		run.envelope.Result.SessionID = strPtr(sessionID)
		run.envelope.Result.RunID = strPtr(runID)
		run.envelope.Result.RoleReportURIs = []liveRoleReportURI{{Role: "logic", URI: logicURI}}
		if liveSecurityDefectPresent(project, run, provider) {
			t.Fatal("defect markers under a non-security role report were accepted")
		}
	})

	t.Run("wrong provider rejects", func(t *testing.T) {
		t.Parallel()
		project, run := newSecurityRun(t, defectBody, func(run *livePublishedRun) {
			run.manifest.RoleReports[0].ProviderInstance = "agy-security"
			run.manifest.RoleReports[0].Transport = "stdout"
		})
		if liveSecurityDefectPresent(project, run, provider) {
			t.Fatal("security role report bound to a different provider was accepted")
		}
	})

	t.Run("wrong path rejects", func(t *testing.T) {
		t.Parallel()
		project, run := newSecurityRun(t, defectBody, func(run *livePublishedRun) {
			run.manifest.RoleReports[0].Path = "role-reports/other.md"
			run.envelope.Result.RoleReportURIs[0].URI = ".mulgae/" + sessionID + "/" + runID + "/role-reports/other.md"
		})
		writeLiveRoleReport(t, project, sessionID, runID, "other", defectBody)
		if liveSecurityDefectPresent(project, run, provider) {
			t.Fatal("non-canonical security role-report path was accepted")
		}
	})

	t.Run("wrong digest rejects", func(t *testing.T) {
		t.Parallel()
		project, run := newSecurityRun(t, defectBody, func(run *livePublishedRun) {
			run.manifest.RoleReports[0].SHA256 = "sha256:" + strings.Repeat("ab", 32)
		})
		if liveSecurityDefectPresent(project, run, provider) {
			t.Fatal("security role report with inventory digest mismatch was accepted")
		}
	})

	t.Run("missing marker rejects", func(t *testing.T) {
		t.Parallel()
		project, run := newSecurityRun(t, praiseBody, nil)
		if liveSecurityDefectPresent(project, run, provider) {
			t.Fatal("security role report without fixture defect markers was accepted")
		}
	})
}

func TestLiveFollowupSourceFindingSelection(t *testing.T) {
	t.Parallel()

	outcome := func(role, provider, attemptID string) liveRoleOutcome {
		return liveRoleOutcome{
			Role:             role,
			Outcome:          "completed",
			AttemptID:        strPtr(attemptID),
			ProviderInstance: strPtr(provider),
			SelectedVia:      strPtr("primary"),
		}
	}
	runWith := func(outcomes []liveRoleOutcome, findings []liveFinding) livePublishedRun {
		return livePublishedRun{review: liveReview{RoleOutcomes: outcomes, Findings: findings}}
	}

	t.Run("security preferred", func(t *testing.T) {
		t.Parallel()
		run := runWith(
			[]liveRoleOutcome{
				outcome("logic", "zcode-logic", "a_logic"),
				outcome("security", "zcode-security", "a_security"),
			},
			[]liveFinding{
				{ID: "F010", Role: "logic", ProviderInstance: "zcode-logic"},
				{ID: "F001", Role: "security", ProviderInstance: "zcode-security"},
			},
		)
		got, ok := selectLiveFollowupSourceFinding(run)
		if !ok || got.ID != "F001" || got.Role != "security" || got.ProviderInstance != "zcode-security" {
			t.Fatalf("selectLiveFollowupSourceFinding() = %#v present=%t, want security F001", got, ok)
		}
	})

	t.Run("deterministic alternate", func(t *testing.T) {
		t.Parallel()
		run := runWith(
			[]liveRoleOutcome{
				outcome("security", "zcode-security", "a_security"),
				outcome("documentation", "agy-documentation", "a_docs"),
				outcome("logic", "zcode-logic", "a_logic"),
			},
			[]liveFinding{
				{ID: "F020", Role: "documentation", ProviderInstance: "agy-documentation"},
				{ID: "F002", Role: "logic", ProviderInstance: "zcode-logic"},
				{ID: "F001", Role: "logic", ProviderInstance: "zcode-logic"},
			},
		)
		got, ok := selectLiveFollowupSourceFinding(run)
		if !ok || got.ID != "F002" || got.Role != "logic" || got.ProviderInstance != "zcode-logic" {
			t.Fatalf("selectLiveFollowupSourceFinding() = %#v present=%t, want first committed logic finding F002", got, ok)
		}
	})

	t.Run("wrong unselected provider excluded", func(t *testing.T) {
		t.Parallel()
		run := runWith(
			[]liveRoleOutcome{
				outcome("security", "zcode-security", "a_security"),
				outcome("logic", "zcode-logic", "a_logic"),
			},
			[]liveFinding{
				{ID: "F001", Role: "security", ProviderInstance: "agy-security"},
				{ID: "F002", Role: "logic", ProviderInstance: "agy-logic"},
				{ID: "F003", Role: "logic", ProviderInstance: "zcode-logic"},
			},
		)
		got, ok := selectLiveFollowupSourceFinding(run)
		if !ok || got.ID != "F003" || got.Role != "logic" || got.ProviderInstance != "zcode-logic" {
			t.Fatalf("selectLiveFollowupSourceFinding() = %#v present=%t, want selected-provider logic F003", got, ok)
		}
	})

	t.Run("none", func(t *testing.T) {
		t.Parallel()
		run := runWith(
			[]liveRoleOutcome{
				outcome("security", "zcode-security", "a_security"),
				outcome("logic", "zcode-logic", "a_logic"),
			},
			[]liveFinding{
				{ID: "F001", Role: "security", ProviderInstance: "agy-security"},
				{ID: "F002", Role: "logic", ProviderInstance: "agy-logic"},
			},
		)
		if got, ok := selectLiveFollowupSourceFinding(run); ok {
			t.Fatalf("selectLiveFollowupSourceFinding() = %#v, want none", got)
		}
		if got, ok := selectLiveFollowupSourceFinding(runWith(nil, nil)); ok {
			t.Fatalf("empty review selected %#v", got)
		}
	})
}

func writeLiveRoleReport(t *testing.T, project, sessionID, runID, role string, body []byte) {
	t.Helper()
	path := filepath.Join(project, ".mulgae", sessionID, runID, "role-reports", role+".md")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
}

func strPtr(value string) *string { return &value }

func TestLiveChildWorkflowRequiresCommittedIdentity(t *testing.T) {
	sessionID := "s_019f5a09-5eec-7001-8001-000000000001"
	runID := "r_019f5a09-5eec-7001-8001-000000000001"
	complete := liveCommandEnvelope{}
	complete.Result.SessionID = &sessionID
	complete.Result.RunID = &runID
	if err := validateLivePublishedEnvelope(complete); err != nil {
		t.Fatalf("complete child identity rejected: %v", err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*liveCommandEnvelope)
	}{
		{name: "missing session", mutate: func(value *liveCommandEnvelope) { value.Result.SessionID = nil }},
		{name: "missing run", mutate: func(value *liveCommandEnvelope) { value.Result.RunID = nil }},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := complete
			test.mutate(&candidate)
			if err := validateLivePublishedEnvelope(candidate); err == nil {
				t.Fatal("incomplete child workflow envelope was accepted")
			}
		})
	}
}

func TestLiveArtifactURINormalizationIsProjectBound(t *testing.T) {
	t.Parallel()

	project := t.TempDir()
	artifact := filepath.Join(project, ".mulgae", "session", "manifest.json")
	if err := os.MkdirAll(filepath.Dir(artifact), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(artifact, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{
		".mulgae/session/manifest.json",
		(&url.URL{Scheme: "file", Path: artifact}).String(),
	} {
		got, err := normalizeLiveArtifactURI(project, value)
		if err != nil || got != ".mulgae/session/manifest.json" {
			t.Fatalf("normalizeLiveArtifactURI(%q) = %q, %v", value, got, err)
		}
	}
	for _, value := range []string{
		"../manifest.json",
		"file://remote.example/private/manifest.json",
		(&url.URL{Scheme: "file", Path: filepath.Join(filepath.Dir(project), "outside.json")}).String(),
	} {
		if _, err := normalizeLiveArtifactURI(project, value); err == nil {
			t.Fatalf("unsafe artifact URI %q was accepted", value)
		}
	}
}

func loadLivePublishedWorkflow(t *testing.T, validator *jsonschema.Validator, project string, envelope liveCommandEnvelope, command string) livePublishedRun {
	t.Helper()
	if err := validateLivePublishedEnvelope(envelope); err != nil {
		t.Fatalf("mulgae %s did not return a committed child identity: %v; exit=%#v reasons=%#v result=%#v", command, err, envelope.Exit, envelope.Reasons, envelope.Result)
	}
	manifestURI := fmt.Sprintf(".mulgae/%s/%s/manifest.json", *envelope.Result.SessionID, *envelope.Result.RunID)
	if envelope.Result.RunManifestURI != nil && *envelope.Result.RunManifestURI != manifestURI {
		t.Fatalf("mulgae %s returned non-canonical manifest URI %q, want %q", command, *envelope.Result.RunManifestURI, manifestURI)
	}
	manifestBytes := readLiveArtifact(t, project, manifestURI)
	validateLiveJSON(t, validator, liveManifestSchema, manifestBytes, command+" run manifest")
	var manifest liveManifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatalf("decode %s manifest: %v", command, err)
	}
	if manifest.SessionID != *envelope.Result.SessionID || manifest.RunID != *envelope.Result.RunID || manifest.FinalReview.Path == "" {
		t.Fatalf("%s manifest identity/final review is incomplete: %#v", command, manifest)
	}
	reviewURI := ".mulgae/" + manifest.FinalReview.Path
	suppliedReviewURI := envelope.Result.ReviewArtifactURI
	if command == "followup" {
		suppliedReviewURI = envelope.Result.FollowupArtifactURI
	}
	if suppliedReviewURI != nil {
		normalized, err := normalizeLiveArtifactURI(project, *suppliedReviewURI)
		if err != nil || normalized != reviewURI {
			t.Fatalf("mulgae %s returned final review URI %q, want %q: %v", command, *suppliedReviewURI, reviewURI, err)
		}
	}
	if (command == "review" || command == "delta" || command == "followup") && suppliedReviewURI == nil {
		t.Fatalf("mulgae %s omitted its contract-defined final review URI", command)
	}
	if command == "rerun" {
		if envelope.Result.PromptManifestURI == nil {
			t.Fatal("mulgae rerun omitted its contract-defined prompt manifest URI")
		}
		_ = readLiveArtifact(t, project, *envelope.Result.PromptManifestURI)
	}
	reviewBytes := readLiveArtifact(t, project, reviewURI)
	validateLiveJSON(t, validator, liveReviewSchema, reviewBytes, command+" review artifact")
	var review liveReview
	if err := json.Unmarshal(reviewBytes, &review); err != nil {
		t.Fatalf("decode %s review: %v", command, err)
	}
	if manifest.RunID != *envelope.Result.RunID || review.RunID != manifest.RunID || manifest.RunType != command && !(command == "rerun" && manifest.RunType == "rerun") || review.RunType != manifest.RunType {
		t.Fatalf("%s P2 identity mismatch: manifest=%#v review=%#v", command, manifest, review)
	}
	if manifest.ExitCode != envelope.Exit.Code || !manifest.Sealed || manifest.PublicationStatus != "committed" || manifest.PublicationAuthority != "P2" || review.PublicationStatus != "committed" {
		t.Fatalf("%s P2/exit mismatch: exit=%d manifest=%#v review publication=%q", command, envelope.Exit.Code, manifest, review.PublicationStatus)
	}
	run := livePublishedRun{envelope: envelope, manifest: manifest, review: review}
	assertLiveRoleReportInventory(t, project, run)
	return run
}

func assertLiveRoleReportInventory(t *testing.T, project string, run livePublishedRun) {
	t.Helper()
	expectedRoles := make([]string, 0, len(run.review.RoleOutcomes))
	outcomesByRole := make(map[string]liveRoleOutcome, len(run.review.RoleOutcomes))
	for _, outcome := range run.review.RoleOutcomes {
		outcomesByRole[outcome.Role] = outcome
		if liveSuccessfulRoleOutcome(outcome.Outcome) {
			expectedRoles = append(expectedRoles, outcome.Role)
		}
	}
	if len(run.manifest.RoleReports) != len(expectedRoles) {
		t.Fatalf("manifest role_reports cardinality = %d, want %d successful outcomes %v", len(run.manifest.RoleReports), len(expectedRoles), expectedRoles)
	}
	if len(run.envelope.Result.RoleReportURIs) != len(expectedRoles) {
		t.Fatalf("command role_report_uris cardinality = %d, want %d successful outcomes %v", len(run.envelope.Result.RoleReportURIs), len(expectedRoles), expectedRoles)
	}
	prefix := fmt.Sprintf(".mulgae/%s/%s/role-reports/", run.manifest.SessionID, run.manifest.RunID)
	for index, role := range expectedRoles {
		report := run.manifest.RoleReports[index]
		uri := run.envelope.Result.RoleReportURIs[index]
		outcome := outcomesByRole[role]
		if report.Role != role || uri.Role != role {
			t.Fatalf("role report order mismatch at %d: outcome=%q manifest=%q uri=%q", index, role, report.Role, uri.Role)
		}
		if report.Path != "role-reports/"+role+".md" || report.ContentType != "text/markdown" ||
			report.ByteLength <= 0 || report.SHA256 == "" || report.AttemptID == "" || report.ProviderInstance == "" {
			t.Fatalf("manifest role report metadata invalid for %q: %#v", role, report)
		}
		if outcome.AttemptID == nil || outcome.ProviderInstance == nil ||
			report.AttemptID != *outcome.AttemptID || report.ProviderInstance != *outcome.ProviderInstance {
			t.Fatalf("manifest role report %q does not match successful outcome authority: report=%#v outcome=%#v", role, report, outcome)
		}
		wantURI := prefix + role + ".md"
		if uri.URI != wantURI {
			t.Fatalf("command role_report_uris[%d] = %#v, want uri %q", index, uri, wantURI)
		}
		content := readLiveArtifact(t, project, wantURI)
		if len(content) != report.ByteLength {
			t.Fatalf("role report %q byte length = %d, want %d", role, len(content), report.ByteLength)
		}
		if digest := liveArtifactSHA256(content); digest != report.SHA256 {
			t.Fatalf("role report %q digest = %q, want %q", role, digest, report.SHA256)
		}
	}
	if err := validateLiveRoleReportTransports(run, false); err != nil {
		t.Fatal(err)
	}
}

func assertLiveRoleReportURIEquality(t *testing.T, left, right []liveRoleReportURI) {
	t.Helper()
	if !reflect.DeepEqual(left, right) {
		t.Fatalf("role_report_uris mismatch: left=%#v right=%#v", left, right)
	}
}

// liveProviderFamily returns the adapter family of a provider instance, which
// production planning always names "<family>-<role>".
func liveProviderFamily(providerInstance string) string {
	if index := strings.Index(providerInstance, "-"); index > 0 {
		return providerInstance[:index]
	}
	return ""
}

// liveExpectedRoleReportTransport is the adapter-owned transport a committed
// role report must record. The transport is per provider family and never
// configurable: ZCode review, followup, delta, and recomposed rerun invocations
// hold the staged_file write grant, every other family keeps stdout, and an
// exact replay always reproduces stdout because it acquires no fresh grant.
func liveExpectedRoleReportTransport(providerInstance, replayMode string) string {
	if replayMode == "exact" {
		return "stdout"
	}
	if liveProviderFamily(providerInstance) == "zcode" {
		return "staged_file"
	}
	return "stdout"
}

func liveReplayMode(manifest liveManifest) string {
	if manifest.ImmutableLineage.ReplayMode == nil {
		return ""
	}
	return *manifest.ImmutableLineage.ReplayMode
}

// validateLiveRoleReportTransports binds every committed role-report inventory
// entry to the transport its producing provider family is granted. It is part
// of the canonical-equality surface: an absent, unknown, downgraded, or
// upgraded transport is a contract violation, never a transient condition.
// requireStagedFile additionally certifies that the run actually exercised the
// staged_file route at least once.
func validateLiveRoleReportTransports(run livePublishedRun, requireStagedFile bool) error {
	replayMode := liveReplayMode(run.manifest)
	staged := 0
	for _, report := range run.manifest.RoleReports {
		if report.Transport != "staged_file" && report.Transport != "stdout" {
			return fmt.Errorf("role report %q recorded transport %q, want the staged_file|stdout enum", report.Role, report.Transport)
		}
		want := liveExpectedRoleReportTransport(report.ProviderInstance, replayMode)
		if report.Transport != want {
			return fmt.Errorf("role report %q from %q recorded transport %q, want adapter-owned %q (replay_mode=%q)",
				report.Role, report.ProviderInstance, report.Transport, want, replayMode)
		}
		if report.Transport == "staged_file" {
			staged++
		}
	}
	if requireStagedFile && staged == 0 {
		return fmt.Errorf("committed role_reports carry no staged_file entry, so this run certified nothing about the provider-written staging transport: %#v", run.manifest.RoleReports)
	}
	return nil
}

func assertLiveRoleReportTransports(t *testing.T, run livePublishedRun, label string, requireStagedFile bool) {
	t.Helper()
	if err := validateLiveRoleReportTransports(run, requireStagedFile); err != nil {
		t.Fatalf("%s role-report transport inventory is invalid: %v", label, err)
	}
}

// assertLiveExactReplayRoleReportTransports keeps byte-exact replay on the
// stdout transport independently of the family grant: an exact replay must
// reproduce the recorded transport rather than acquire a staging destination.
func assertLiveExactReplayRoleReportTransports(t *testing.T, run livePublishedRun) {
	t.Helper()
	if liveReplayMode(run.manifest) != "exact" {
		t.Fatalf("exact replay manifest lost its replay lineage: %#v", run.manifest.ImmutableLineage)
	}
	if len(run.manifest.RoleReports) == 0 {
		t.Fatalf("exact replay committed no role_reports inventory: %#v", run.manifest)
	}
	for _, report := range run.manifest.RoleReports {
		if report.Transport != "stdout" {
			t.Fatalf("exact replay role report %q from %q recorded transport %q, want byte-exact stdout", report.Role, report.ProviderInstance, report.Transport)
		}
	}
	assertLiveRoleReportTransports(t, run, "exact", false)
}

func liveArtifactSHA256(content []byte) string {
	sum := sha256.Sum256(content)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func validateLivePublishedEnvelope(envelope liveCommandEnvelope) error {
	if envelope.Result.SessionID == nil || envelope.Result.RunID == nil {
		return fmt.Errorf("committed P2 session or run identity is absent")
	}
	return nil
}

func readLiveArtifact(t *testing.T, project, uri string) []byte {
	t.Helper()
	normalized, err := normalizeLiveArtifactURI(project, uri)
	if err != nil {
		t.Fatalf("unsafe live artifact URI %q: %v", uri, err)
	}
	value, err := os.ReadFile(filepath.Join(project, normalized))
	if err != nil {
		t.Fatalf("read live artifact %q: %v", uri, err)
	}
	return value
}

func normalizeLiveArtifactURI(project, uri string) (string, error) {
	if !filepath.IsAbs(uri) && filepath.Clean(uri) == uri && strings.HasPrefix(uri, ".mulgae/") {
		return filepath.ToSlash(uri), nil
	}
	parsed, err := url.Parse(uri)
	if err != nil || parsed.Scheme != "file" || parsed.Host != "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || !filepath.IsAbs(parsed.Path) {
		return "", fmt.Errorf("URI is not a local artifact path")
	}
	projectPath, err := filepath.EvalSymlinks(project)
	if err != nil {
		return "", fmt.Errorf("resolve project: %w", err)
	}
	artifactPath, err := filepath.EvalSymlinks(parsed.Path)
	if err != nil {
		return "", fmt.Errorf("resolve artifact: %w", err)
	}
	relative, err := filepath.Rel(projectPath, artifactPath)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("artifact is outside the live project")
	}
	relative = filepath.ToSlash(relative)
	if !strings.HasPrefix(relative, ".mulgae/") {
		return "", fmt.Errorf("artifact is outside the private publication root")
	}
	return relative, nil
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
				Role            string `json:"role"`
				PrimaryProvider string `json:"primary_provider"`
			} `json:"role_assignments"`
		} `json:"policy"`
	}
	if err := json.Unmarshal(raw, &redacted); err != nil {
		t.Fatalf("decode redacted config: %v", err)
	}
	if !reflect.DeepEqual(redacted.ConfiguredProviderIDs, []string{"zcode", "agy"}) {
		t.Fatalf("configured providers = %v", redacted.ConfiguredProviderIDs)
	}
	// Each role names exactly one provider: the first configured family from its
	// own preference order. The projection carries no second route.
	want := map[string]string{
		"logic": "zcode", "security": "zcode", "maintainability": "zcode",
		"product": "zcode", "documentation": "agy", "testing": "zcode",
		"artist": "",
	}
	if len(redacted.Policy.RoleAssignments) != len(want) {
		t.Fatalf("role assignment count = %d", len(redacted.Policy.RoleAssignments))
	}
	for _, assignment := range redacted.Policy.RoleAssignments {
		expected, ok := want[assignment.Role]
		if !ok || assignment.PrimaryProvider != expected {
			t.Fatalf("unexpected config assignment: %#v", assignment)
		}
	}
}

func assertLiveSixLaneConfig(t *testing.T, project string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(project, ".mulgae", "config.yaml"))
	if err != nil {
		t.Fatalf("read live config: %v", err)
	}
	config, err := adapterconfig.Decode(data)
	if err != nil {
		t.Fatalf("decode live config: %v", err)
	}
	if config.Resources.MaxActiveLanes != 6 {
		t.Fatalf("max_active_lanes = %d, want 6", config.Resources.MaxActiveLanes)
	}
}

func validateLiveProviderQualificationHealth(project string, run livePublishedRun, expected map[string]string) error {
	if run.envelope.Result.SessionID == nil || run.envelope.Result.RunID == nil {
		return fmt.Errorf("run has no diagnostic identity")
	}
	path := filepath.Join(project, ".mulgae", "diagnostics", *run.envelope.Result.SessionID, *run.envelope.Result.RunID, "mulgae-runtime.jsonl")
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read runtime diagnostic log: %w", err)
	}
	lines := bytes.Split(bytes.TrimSpace(data), []byte("\n"))
	events := make([]liveRuntimeEvent, 0, len(lines))
	for index, line := range lines {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var event liveRuntimeEvent
		if err := json.Unmarshal(line, &event); err != nil {
			return fmt.Errorf("decode runtime diagnostic event %d: %w", index+1, err)
		}
		events = append(events, event)
	}
	return validateLiveQualificationEvents(events, expected)
}

func validateLiveQualificationEvents(events []liveRuntimeEvent, expected map[string]string) error {
	// A role owns exactly one candidate, so qualification probes one provider
	// instance per role and never a family the role does not use.
	candidates := make(map[string]struct{}, len(expected))
	for role, provider := range expected {
		if provider == "" {
			return fmt.Errorf("%s has an empty qualification candidate", role)
		}
		if _, duplicate := candidates[provider]; duplicate {
			return fmt.Errorf("qualification candidate %s is assigned more than once", provider)
		}
		candidates[provider] = struct{}{}
	}
	lastOutcome := make(map[string]string, len(candidates))
	qualified := make(map[string]bool, len(candidates))
	qualificationSucceeded := 0
	for _, event := range events {
		switch event.Event {
		case "qualification_candidate_checked":
			if _, ok := candidates[event.Provider]; !ok {
				return fmt.Errorf("unexpected qualification candidate %q", event.Provider)
			}
			if event.Outcome != "qualified" && event.Outcome != "rejected" {
				return fmt.Errorf("qualification candidate %s has invalid outcome %q", event.Provider, event.Outcome)
			}
			lastOutcome[event.Provider] = event.Outcome
			if event.Outcome == "qualified" {
				qualified[event.Provider] = true
			}
		case "qualification_succeeded":
			qualificationSucceeded++
		}
	}
	if qualificationSucceeded != 1 {
		return fmt.Errorf("qualification_succeeded cardinality = %d, want 1", qualificationSucceeded)
	}
	for provider := range candidates {
		if !qualified[provider] || lastOutcome[provider] != "qualified" {
			return fmt.Errorf("qualification candidate %s did not finish qualified: last=%q", provider, lastOutcome[provider])
		}
	}
	return nil
}

func validateLivePrimaryProcessTerminals(project string, run livePublishedRun, expected map[string]string) error {
	if run.envelope.Result.SessionID == nil || run.envelope.Result.RunID == nil {
		return fmt.Errorf("run has no diagnostic identity")
	}
	for role, provider := range expected {
		attempts := liveAttemptsForRole(run.manifest.Attempts, role)
		primary, ok := livePrimaryAttempt(attempts, provider)
		if !ok {
			return fmt.Errorf("%s process interval has no exact primary attempt", role)
		}
		path := filepath.Join(project, ".mulgae", "diagnostics", *run.envelope.Result.SessionID, *run.envelope.Result.RunID,
			"attempts", primary.AttemptID, "invocations", "001-initial", "status.json")
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s invocation status: %w", role, err)
		}
		var status liveInvocationStatus
		if err := json.Unmarshal(data, &status); err != nil {
			return fmt.Errorf("decode %s invocation status: %w", role, err)
		}
		started, startErr := time.Parse(time.RFC3339Nano, status.StartedAt)
		completed, completeErr := time.Parse(time.RFC3339Nano, status.CompletedAt)
		if startErr != nil || completeErr != nil || !liveTerminalProcessState(status.ProcessState) || !started.Before(completed) {
			return fmt.Errorf("invalid %s process interval state=%q started=%q completed=%q", role, status.ProcessState, status.StartedAt, status.CompletedAt)
		}
	}
	return nil
}

func liveTerminalProcessState(state string) bool {
	return state == "succeeded" || state == "failed" || state == "timed_out"
}

func TestLiveTerminalProcessStateAcceptsCompletedProcesses(t *testing.T) {
	t.Parallel()
	for _, state := range []string{"succeeded", "failed", "timed_out"} {
		if !liveTerminalProcessState(state) {
			t.Fatalf("terminal process state %q was rejected", state)
		}
	}
	for _, state := range []string{"", "pending", "running"} {
		if liveTerminalProcessState(state) {
			t.Fatalf("non-terminal process state %q was accepted", state)
		}
	}
}

func assertLiveDoctorPrequalification(t *testing.T, raw json.RawMessage) {
	t.Helper()
	families := []string{"zcode", "agy"}
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
		if row.State == "unavailable" && row.Reason == "provider_static_admission_unverified" {
			unverified[row.Family] = true
		}
	}
	for _, family := range families {
		if !unverified[family] {
			t.Fatalf("doctor did not retain truthful prequalification state for %s: %#v", family, doctor.ProviderInventory)
		}
	}
}

func assertLiveAssignments(t *testing.T, run livePublishedRun, expected map[string]string) {
	t.Helper()
	if err := validateLiveAssignments(run, expected); err != nil {
		t.Fatal(err)
	}
}

func validateLiveAssignments(run livePublishedRun, expected map[string]string) error {
	if len(run.manifest.SelectedRoles) != len(expected) || len(run.review.RoleOutcomes) != len(expected) {
		return fmt.Errorf("selected role cardinality mismatch: selected=%v outcomes=%#v", run.manifest.SelectedRoles, run.review.RoleOutcomes)
	}
	for role, provider := range expected {
		attempts := liveAttemptsForRole(run.manifest.Attempts, role)
		var outcome *liveRoleOutcome
		for index := range run.review.RoleOutcomes {
			if run.review.RoleOutcomes[index].Role == role {
				outcome = &run.review.RoleOutcomes[index]
				break
			}
		}
		if outcome == nil || !liveSuccessfulRoleOutcome(outcome.Outcome) || outcome.AttemptID == nil || outcome.ProviderInstance == nil || outcome.SelectedVia == nil {
			return fmt.Errorf("%s role outcome is not a successful product outcome: %#v", role, outcome)
		}
		// One provider per role means exactly one attempt, always primary.
		if len(attempts) != 1 || attempts[0].ProviderInstance != provider || attempts[0].SelectedAs != "primary" {
			return fmt.Errorf("%s does not bind exactly one primary attempt from %s: %#v", role, provider, attempts)
		}
		if *outcome.SelectedVia != "primary" {
			return fmt.Errorf("%s selected_via = %q, want primary", role, *outcome.SelectedVia)
		}
		if attempts[0].State != "succeeded" || *outcome.AttemptID != attempts[0].AttemptID || *outcome.ProviderInstance != provider {
			return fmt.Errorf("%s primary outcome mismatch: attempts=%#v outcome=%#v", role, attempts, outcome)
		}
	}
	return nil
}

// runLiveChildWorkflowWithAssignments runs one child workflow and retries it
// while any selected role misses its own provider. Live providers are
// stochastic: the same role on the same provider can succeed in one run and
// return provider_output_missing in the next. Mulgae no longer masks that by
// moving the role elsewhere, so this scenario absorbs it the way the root
// workflow already does, rather than asserting a live provider never flakes.
func runLiveChildWorkflowWithAssignments(
	t *testing.T,
	validator *jsonschema.Validator,
	environment liveE2EEnvironment,
	project string,
	expected map[string]string,
	arguments ...string,
) livePublishedRun {
	t.Helper()
	const maxAttempts = 2
	var last error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		run := runLivePublishedWorkflow(t, validator, environment, project, []int{0, 1, 4}, arguments...)
		last = validateLiveAssignments(run, expected)
		if last == nil {
			return run
		}
		t.Logf("[test-e2e] %s attempt %d/%d did not bind every role to its provider; retrying: %v",
			arguments[0], attempt, maxAttempts, last)
	}
	t.Fatalf("live %s did not bind every role to its configured provider after %d attempts: %v", arguments[0], maxAttempts, last)
	return livePublishedRun{}
}

func assertLiveRecoverableAssignments(t *testing.T, run livePublishedRun, expected map[string]string) {
	t.Helper()
	if err := validateLiveRecoverableAssignments(run, expected); err != nil {
		t.Fatal(err)
	}
}

// validateLiveRecoverableAssignments keeps direct primary launch mandatory and
// accepts one bounded same-provider repair as the selected P2 outcome. A role is
// bound to one provider, so no other route can produce the outcome.
func validateLiveRecoverableAssignments(run livePublishedRun, expected map[string]string) error {
	if len(run.manifest.SelectedRoles) != len(expected) || len(run.review.RoleOutcomes) != len(expected) {
		return fmt.Errorf("selected role cardinality mismatch: selected=%v outcomes=%#v", run.manifest.SelectedRoles, run.review.RoleOutcomes)
	}
	selectedRoles := make(map[string]bool, len(run.manifest.SelectedRoles))
	for _, role := range run.manifest.SelectedRoles {
		if selectedRoles[role] {
			return fmt.Errorf("selected role %s is duplicated", role)
		}
		selectedRoles[role] = true
	}
	for role, provider := range expected {
		if !selectedRoles[role] {
			return fmt.Errorf("selected role %s is absent", role)
		}
		attempts := liveAttemptsForRole(run.manifest.Attempts, role)
		if len(attempts) != 1 {
			return fmt.Errorf("%s attempt cardinality = %d, want exactly one primary attempt: %#v", role, len(attempts), attempts)
		}
		primary := attempts[0]
		if primary.ProviderInstance != provider || primary.SelectedAs != "primary" || primary.InvocationCount < 1 || primary.InvocationCount > 2 {
			return fmt.Errorf("%s primary launch mismatch: %#v, want one bounded attempt from %s", role, primary, provider)
		}

		var outcome *liveRoleOutcome
		for index := range run.review.RoleOutcomes {
			if run.review.RoleOutcomes[index].Role == role {
				if outcome != nil {
					return fmt.Errorf("%s role outcome is duplicated", role)
				}
				outcome = &run.review.RoleOutcomes[index]
			}
		}
		if outcome == nil || outcome.Outcome != "completed" && outcome.Outcome != "degraded" || outcome.AttemptID == nil || outcome.ProviderInstance == nil || outcome.SelectedVia == nil {
			return fmt.Errorf("%s role has no successful terminal outcome on %s: %s",
				role, primary.ProviderInstance, liveAttemptFailureSummary(run, primary))
		}
		if *outcome.SelectedVia != "primary" {
			return fmt.Errorf("%s selected_via = %q, want primary", role, *outcome.SelectedVia)
		}
		if primary.State != "succeeded" || *outcome.AttemptID != primary.AttemptID || *outcome.ProviderInstance != provider {
			return fmt.Errorf("%s selected primary outcome mismatch: attempts=%#v outcome=%#v", role, attempts, outcome)
		}
	}
	return nil
}

func liveSelectedProvider(run livePublishedRun, role string) (string, error) {
	for _, outcome := range run.review.RoleOutcomes {
		if outcome.Role == role && outcome.ProviderInstance != nil && outcome.AttemptID != nil && outcome.SelectedVia != nil &&
			(outcome.Outcome == "completed" || outcome.Outcome == "degraded") {
			return *outcome.ProviderInstance, nil
		}
	}
	return "", fmt.Errorf("role %s has no selected successful provider", role)
}

func requireLiveSelectedProvider(t *testing.T, run livePublishedRun, role string) string {
	t.Helper()
	provider, err := liveSelectedProvider(run, role)
	if err != nil {
		t.Fatal(err)
	}
	return provider
}

func logLiveRecoverySelections(t *testing.T, run livePublishedRun) {
	t.Helper()
	for _, outcome := range run.review.RoleOutcomes {
		if outcome.ProviderInstance == nil || outcome.SelectedVia == nil {
			continue
		}
		t.Logf("[test-e2e] role=%s provider=%s selected_via=%s outcome=%s", outcome.Role, *outcome.ProviderInstance, *outcome.SelectedVia, outcome.Outcome)
	}
}

func TestLiveRecoverableAssignmentGate(t *testing.T) {
	t.Parallel()
	expected := map[string]string{"logic": "kimi-logic"}
	primaryRun := func(invocations int) livePublishedRun {
		attemptID, provider, selectedVia := "a_primary", "kimi-logic", "primary"
		return livePublishedRun{
			manifest: liveManifest{SelectedRoles: []string{"logic"}, Attempts: []liveAttempt{{
				AttemptID: attemptID, Role: "logic", ProviderInstance: provider, SelectedAs: "primary", State: "succeeded", InvocationCount: invocations,
			}}},
			review: liveReview{RoleOutcomes: []liveRoleOutcome{{
				Role: "logic", Outcome: "completed", AttemptID: &attemptID, ProviderInstance: &provider, SelectedVia: &selectedVia,
			}}},
		}
	}
	// A second attempt on any provider is now impossible: nothing writes it, and
	// a published run that claims one is not a run this build could have produced.
	secondAttemptRun := func(primaryState, secondProvider string, secondInvocations int) livePublishedRun {
		attemptID, provider, selectedVia := "a_second", secondProvider, "fallback"
		return livePublishedRun{
			manifest: liveManifest{SelectedRoles: []string{"logic"}, Attempts: []liveAttempt{
				{AttemptID: "a_primary", Role: "logic", ProviderInstance: "kimi-logic", SelectedAs: "primary", State: primaryState, InvocationCount: 2},
				{AttemptID: attemptID, Role: "logic", ProviderInstance: provider, SelectedAs: "fallback", State: "succeeded", InvocationCount: secondInvocations},
			}},
			review: liveReview{RoleOutcomes: []liveRoleOutcome{{
				Role: "logic", Outcome: "degraded", AttemptID: &attemptID, ProviderInstance: &provider, SelectedVia: &selectedVia,
			}}},
		}
	}
	for _, test := range []struct {
		name string
		run  livePublishedRun
		want bool
	}{
		{name: "initial primary", run: primaryRun(1), want: true},
		{name: "primary repair", run: primaryRun(2), want: true},
		{name: "second attempt on another provider", run: secondAttemptRun("failed", "zcode-logic", 1)},
		{name: "second attempt after successful primary", run: secondAttemptRun("succeeded", "zcode-logic", 1)},
		{name: "primary invocation overflow", run: primaryRun(3)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := validateLiveRecoverableAssignments(test.run, expected); (err == nil) != test.want {
				t.Fatalf("validateLiveRecoverableAssignments() error = %v, want success=%t", err, test.want)
			}
		})
	}
}

func TestLiveQualificationHealthGate(t *testing.T) {
	t.Parallel()
	expected := map[string]string{"logic": "kimi-logic"}
	qualified := func(provider string) liveRuntimeEvent {
		return liveRuntimeEvent{Event: "qualification_candidate_checked", Provider: provider, Outcome: "qualified"}
	}
	rejected := func(provider string) liveRuntimeEvent {
		return liveRuntimeEvent{Event: "qualification_candidate_checked", Provider: provider, Outcome: "rejected"}
	}
	succeeded := liveRuntimeEvent{Event: "qualification_succeeded"}
	for _, test := range []struct {
		name   string
		events []liveRuntimeEvent
		want   bool
	}{
		{name: "all qualified", events: []liveRuntimeEvent{qualified("kimi-logic"), succeeded}, want: true},
		{name: "retry then qualified", events: []liveRuntimeEvent{rejected("kimi-logic"), qualified("kimi-logic"), succeeded}, want: true},
		{name: "candidate missing", events: []liveRuntimeEvent{succeeded}},
		{name: "terminal rejection", events: []liveRuntimeEvent{qualified("kimi-logic"), rejected("kimi-logic"), succeeded}},
		{name: "unexpected candidate", events: []liveRuntimeEvent{qualified("kimi-logic"), qualified("zcode-logic"), succeeded}},
		{name: "overall success missing", events: []liveRuntimeEvent{qualified("kimi-logic")}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := validateLiveQualificationEvents(test.events, expected); (err == nil) != test.want {
				t.Fatalf("validateLiveQualificationEvents() error = %v, want success=%t", err, test.want)
			}
		})
	}
}

func requireLiveFinding(t *testing.T, run livePublishedRun, role, provider string) liveFinding {
	t.Helper()
	for _, finding := range run.review.Findings {
		if finding.Role == role && finding.ProviderInstance == provider {
			return finding
		}
	}
	t.Fatalf("focused run has no %s finding from %s: %#v", role, provider, run.review.Findings)
	return liveFinding{}
}

// selectLiveFollowupSourceFinding chooses one validated structured finding for
// live followup admission. Preference order:
//  1. first committed finding from the selected successful security provider
//  2. first committed finding from another successful selected role/provider,
//     walking FixedRoleOrder and committed finding order
//
// Findings bound to an unselected or unsuccessful provider are excluded.
// Returns false only when the committed review has no eligible structured findings.
func selectLiveFollowupSourceFinding(run livePublishedRun) (liveFinding, bool) {
	selected := liveSuccessfulSelectedProviders(run)
	if finding, ok := firstLiveFindingForSelectedProvider(run, string(domain.RoleSecurity), selected); ok {
		return finding, true
	}
	for _, role := range domain.FixedRoleOrder() {
		if role == domain.RoleSecurity {
			continue
		}
		if finding, ok := firstLiveFindingForSelectedProvider(run, string(role), selected); ok {
			return finding, true
		}
	}
	return liveFinding{}, false
}

func liveSuccessfulSelectedProviders(run livePublishedRun) map[string]string {
	selected := make(map[string]string, len(run.review.RoleOutcomes))
	for _, outcome := range run.review.RoleOutcomes {
		if !liveSuccessfulRoleOutcome(outcome.Outcome) ||
			outcome.ProviderInstance == nil || strings.TrimSpace(*outcome.ProviderInstance) == "" ||
			outcome.AttemptID == nil || outcome.SelectedVia == nil {
			continue
		}
		selected[outcome.Role] = *outcome.ProviderInstance
	}
	return selected
}

func firstLiveFindingForSelectedProvider(run livePublishedRun, role string, selected map[string]string) (liveFinding, bool) {
	provider, ok := selected[role]
	if !ok {
		return liveFinding{}, false
	}
	for _, finding := range run.review.Findings {
		if finding.Role == role && finding.ProviderInstance == provider && strings.TrimSpace(finding.ID) != "" {
			return finding, true
		}
	}
	return liveFinding{}, false
}

func livePrimaryAttempt(attempts []liveAttempt, provider string) (liveAttempt, bool) {
	var result liveAttempt
	found := false
	for _, attempt := range attempts {
		if attempt.SelectedAs != "primary" {
			continue
		}
		if found || attempt.ProviderInstance != provider {
			return liveAttempt{}, false
		}
		result, found = attempt, true
	}
	return result, found
}

func assertLiveSecurityDefect(t *testing.T, project string, run livePublishedRun, provider string) {
	t.Helper()
	if liveSecurityDefectPresent(project, run, provider) {
		return
	}
	t.Fatalf("selected security provider %s did not publish the required defect via structured finding or verified role-report markers: findings=%#v role_reports=%#v", provider, run.review.Findings, run.manifest.RoleReports)
}

func liveRoleFindingPresent(run livePublishedRun, role, provider string) bool {
	for _, finding := range run.review.Findings {
		if finding.Role == role && finding.ProviderInstance == provider {
			return true
		}
	}
	return false
}

// Fixture-specific markers for the deliberate ReadReport path-traversal defect
// in the live E2E report.go target. Arbitrary praise prose must not satisfy
// the six-lane gate.
const (
	liveSecurityDefectPathMarker   = "report.go"
	liveSecurityDefectSymbolMarker = "ReadReport"
)

func liveSecurityDefectPresent(project string, run livePublishedRun, provider string) bool {
	if liveRoleFindingPresent(run, "security", provider) {
		return true
	}
	return liveSecurityRoleReportDefectPresent(project, run, provider) == nil
}

func liveSecurityDefectTraversalMarkerPresent(body string) bool {
	lower := strings.ToLower(body)
	for _, marker := range []string{
		"directory traversal",
		"path traversal",
		"path-traversal",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func liveSecurityRoleReportDefectPresent(project string, run livePublishedRun, provider string) error {
	if provider == "" || run.manifest.SessionID == "" || run.manifest.RunID == "" {
		return fmt.Errorf("security role-report defect check requires selected provider and committed run identity")
	}
	var outcome *liveRoleOutcome
	for index := range run.review.RoleOutcomes {
		candidate := &run.review.RoleOutcomes[index]
		if candidate.Role != "security" {
			continue
		}
		if outcome != nil {
			return fmt.Errorf("duplicate security role outcomes")
		}
		outcome = candidate
	}
	if outcome == nil || outcome.ProviderInstance == nil || outcome.AttemptID == nil || outcome.SelectedVia == nil {
		return fmt.Errorf("security role has no selected successful outcome")
	}
	if !liveSuccessfulRoleOutcome(outcome.Outcome) {
		return fmt.Errorf("security role outcome %q is not successful", outcome.Outcome)
	}
	if *outcome.ProviderInstance != provider {
		return fmt.Errorf("selected security provider %q does not match required %q", *outcome.ProviderInstance, provider)
	}

	var report *liveRoleReport
	for index := range run.manifest.RoleReports {
		candidate := &run.manifest.RoleReports[index]
		if candidate.Role != "security" {
			continue
		}
		if report != nil {
			return fmt.Errorf("duplicate security role_reports inventory entries")
		}
		report = candidate
	}
	if report == nil {
		return fmt.Errorf("manifest role_reports lacks selected security inventory entry")
	}
	if report.ProviderInstance != provider {
		return fmt.Errorf("security role report provider %q does not match selected %q", report.ProviderInstance, provider)
	}
	if report.AttemptID != *outcome.AttemptID {
		return fmt.Errorf("security role report attempt_id %q does not match selected outcome %q", report.AttemptID, *outcome.AttemptID)
	}
	if report.Path != "role-reports/security.md" || report.ContentType != "text/markdown" || report.ByteLength <= 0 || report.SHA256 == "" {
		return fmt.Errorf("security role report metadata is invalid: %#v", *report)
	}

	wantURI := fmt.Sprintf(".mulgae/%s/%s/role-reports/security.md", run.manifest.SessionID, run.manifest.RunID)
	var matchedURI bool
	for _, uri := range run.envelope.Result.RoleReportURIs {
		if uri.Role != "security" {
			continue
		}
		if matchedURI {
			return fmt.Errorf("duplicate security role_report_uris entries")
		}
		if uri.URI != wantURI {
			return fmt.Errorf("security role_report_uri %q is not manifest-bound path %q", uri.URI, wantURI)
		}
		matchedURI = true
	}
	if !matchedURI {
		return fmt.Errorf("command role_report_uris lacks selected security inventory entry")
	}

	content, err := loadLiveArtifactBytes(project, wantURI)
	if err != nil {
		return fmt.Errorf("read verified security role report: %w", err)
	}
	if len(content) != report.ByteLength {
		return fmt.Errorf("security role report byte length = %d, want digest-bound %d", len(content), report.ByteLength)
	}
	if digest := liveArtifactSHA256(content); digest != report.SHA256 {
		return fmt.Errorf("security role report digest = %q, want inventory %q", digest, report.SHA256)
	}

	body := string(content)
	if !strings.Contains(body, liveSecurityDefectPathMarker) {
		return fmt.Errorf("verified security role report lacks fixture path marker %q", liveSecurityDefectPathMarker)
	}
	if !strings.Contains(body, liveSecurityDefectSymbolMarker) {
		return fmt.Errorf("verified security role report lacks fixture symbol marker %q", liveSecurityDefectSymbolMarker)
	}
	if !liveSecurityDefectTraversalMarkerPresent(body) {
		return fmt.Errorf("verified security role report lacks fixture traversal defect marker")
	}
	return nil
}

func loadLiveArtifactBytes(project, uri string) ([]byte, error) {
	normalized, err := normalizeLiveArtifactURI(project, uri)
	if err != nil {
		return nil, err
	}
	return os.ReadFile(filepath.Join(project, normalized))
}

func assertLiveSourceBoundAssignment(t *testing.T, run livePublishedRun, role, provider string) {
	t.Helper()
	attempt := requireLiveAttempt(t, run.manifest.Attempts, role)
	if attempt.ProviderInstance != provider || attempt.SelectedAs != "primary" || attempt.State != "succeeded" {
		t.Fatalf("source-bound %s attempt = %#v, want successful %s", role, attempt, provider)
	}
	if len(run.review.RoleOutcomes) != 1 || run.review.RoleOutcomes[0].Role != role || !liveSuccessfulRoleOutcome(run.review.RoleOutcomes[0].Outcome) ||
		run.review.RoleOutcomes[0].AttemptID == nil || *run.review.RoleOutcomes[0].AttemptID != attempt.AttemptID ||
		run.review.RoleOutcomes[0].ProviderInstance == nil || *run.review.RoleOutcomes[0].ProviderInstance != provider ||
		run.review.RoleOutcomes[0].SelectedVia == nil || *run.review.RoleOutcomes[0].SelectedVia != "primary" {
		t.Fatalf("source-bound %s outcome mismatch: %#v", role, run.review.RoleOutcomes)
	}
}

func liveSuccessfulRoleOutcome(outcome string) bool {
	return outcome == "completed" || outcome == "degraded"
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
	return fmt.Sprintf("Mulgae=%s HOME=%s ZCode=%s/%s AGY=%s", environment.binary, environment.nativeHome, environment.zcodeNode, environment.zcodeLauncher, environment.agy)
}
