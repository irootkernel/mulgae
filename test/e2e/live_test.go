//go:build darwin && arm64 && live_e2e

package e2e

import (
	"bytes"
	"context"
	"crypto/rand"
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
	environmentadapter "github.com/irootkernel/mulgae/internal/adapters/environment"
	"github.com/irootkernel/mulgae/internal/adapters/jsonschema"
	"github.com/irootkernel/mulgae/internal/app/reviewrun"
	"github.com/irootkernel/mulgae/internal/builtin"
	"github.com/irootkernel/mulgae/internal/ports"
)

const (
	liveCommandSchema  = "https://mulgae.local/schemas/mulgae-command-result.v12.schema.json"
	liveManifestSchema = "https://mulgae.local/schemas/mulgae-run-manifest.v1.schema.json"
	liveReviewSchema   = "https://mulgae.local/schemas/mulgae-review-artifact.v1.schema.json"
)

type liveE2EEnvironment struct {
	binary         string
	nativeHome     string
	zcodeAppBundle string
	grokExecutable string
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
	ParseState       string `json:"parse_state"`
	ValidationState  string `json:"validation_state"`
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
	SessionID                 string           `json:"session_id"`
	RunID                     string           `json:"run_id"`
	RunType                   string           `json:"run_type"`
	ContentVerdict            string           `json:"content_verdict"`
	CoverageStatus            string           `json:"coverage_status"`
	StructuredExtractionState string           `json:"structured_extraction_status"`
	CIDecision                string           `json:"ci_decision"`
	State                     string           `json:"state"`
	Sealed                    bool             `json:"sealed"`
	ImmutableLineage          liveLineage      `json:"immutable_lineage"`
	SelectedRoles             []string         `json:"selected_roles"`
	Attempts                  []liveAttempt    `json:"attempts"`
	Failures                  []liveFailure    `json:"failures"`
	PublicationStatus         string           `json:"publication_status"`
	PublicationAuthority      string           `json:"publication_authority"`
	ExitCode                  int              `json:"exit_code"`
	RoleReports               []liveRoleReport `json:"role_reports"`
	FinalReview               struct {
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
	RunID                      string            `json:"run_id"`
	ReviewID                   string            `json:"review_id"`
	RunType                    string            `json:"run_type"`
	ImmutableLineage           liveLineage       `json:"immutable_lineage"`
	ContentVerdict             string            `json:"content_verdict"`
	CoverageStatus             string            `json:"coverage_status"`
	StructuredExtractionStatus string            `json:"structured_extraction_status"`
	PublicationStatus          string            `json:"publication_status"`
	CIDecision                 string            `json:"ci_decision"`
	RoleOutcomes               []liveRoleOutcome `json:"role_outcomes"`
	Findings                   []liveFinding     `json:"findings"`
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

func TestE2EZCodeGrokReviewAggregation(t *testing.T) {
	scenario := beginLiveE2ELogScope(t, "scenario", "name=zcode-grok-review-aggregation")
	defer scenario.end()
	environment := requireLiveE2EEnvironment(t)
	validator := newLiveE2EValidator(t)
	project := initializeLiveE2ERepository(t)
	logicMarker := appendLiveReadMarker(t, project, "counter.go", "logic-read")
	securityMarker := appendLiveReadMarker(t, project, "report.go", "security-read")

	initResult := runLiveMulgae(t, validator, environment, project, 0, liveAutoInitArguments(environment)...)
	if initResult.Result.Kind != "initialized" {
		t.Fatalf("init result kind = %q", initResult.Result.Kind)
	}
	configureLiveMixedReview(t, project)
	configResult := runLiveMulgae(t, validator, environment, project, 0, "config", "--output", "json")
	assertLiveConfigMatrix(t, configResult.Result.Policy)
	assertLiveMixedReviewConfig(t, project)
	doctorResult := runLiveMulgae(t, validator, environment, project, 0, "doctor", "--output", "json")
	assertLiveDoctorPrequalification(t, doctorResult.Result.Doctor)

	expected := map[string]string{"logic": "zcode-logic", "security": "grok-security"}
	run := runLiveRecoverableWorkflowWithGate(t, validator, environment, project, "zcode-grok-review-aggregation", expected, validateLiveSingleInvocationGate,
		"review", "--dirty",
		"--objective", "Review the changed fixture strictly within your assigned functional role. Return a concise Markdown role report. The logic role must read counter.go and reproduce its logic-read marker verbatim. The security role must read report.go and reproduce its security-read marker verbatim. It is valid to report no defects; report only concrete actionable defects supported by the captured target.",
		"--roles", "logic,security", "--output", "json",
	)
	assertLiveRecoverableAssignments(t, run, expected)
	assertLiveRoleReportMarker(t, project, run, "logic", logicMarker)
	assertLiveRoleReportMarker(t, project, run, "security", securityMarker)
	assertLiveReportsOnlyAggregation(t, run)
	assertLiveRoleReportTransports(t, run, "review", true)
	assertNoProjectProviderLocks(t, project)
	doctorAfterReview := runLiveMulgae(t, validator, environment, project, 0, "doctor", "--output", "json")
	assertLiveDoctorPrequalification(t, doctorAfterReview.Result.Doctor)
	status := runLiveMulgae(t, validator, environment, project, 0,
		"status", "--run", run.manifest.RunID, "--output", "json",
	)
	assertLiveRoleReportURIEquality(t, status.Result.RoleReportURIs, run.envelope.Result.RoleReportURIs)
	assertNoProjectProviderLocks(t, project)
	scenario.status = "passed"
}

func appendLiveReadMarker(t *testing.T, project, relativePath, prefix string) string {
	t.Helper()
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	marker := prefix + "-" + hex.EncodeToString(nonce[:])
	path := filepath.Join(project, relativePath)
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	body = append(body, []byte("\n// "+prefix+" marker: "+marker+"\n")...)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	return marker
}

func liveAutoInitArguments(environment liveE2EEnvironment) []string {
	arguments := []string{
		"init", "--providers", "auto",
		"--roles", "logic,security",
		"--zcode-app-bundle", environment.zcodeAppBundle,
		"--grok-executable", environment.grokExecutable,
	}
	return append(arguments, "--output", "json")
}

func configureLiveMixedReview(t *testing.T, project string) {
	t.Helper()
	config := readE2EConfig(t, project)
	if config.Providers.ZCode == nil || config.Providers.Grok == nil {
		t.Fatalf("automatic init omitted required providers: %#v", config.Providers)
	}
	config.Roles.Logic.PrimaryProvider = "zcode"
	config.Roles.Security.PrimaryProvider = "grok"
	config.Review.RequiredRoles = []string{"logic", "security"}
	config.Validation.Repair = adapterconfig.RepairConfig{}
	config.Validation.Extraction.Enabled = false
	config.Validation.Extraction.EnabledExplicit = true
	config.Resources.MaxActiveLanes = 2
	config.Resources.PrimaryRepairAttempts = 0
	// The execution preflight models two structural slots per role even when
	// repair and extraction are disabled. The live gate below still requires
	// exactly one observed initial invocation from each provider.
	config.Resources.RoleMaxInvocations = 2
	config.Resources.RunMaxInvocations = 4
	projectConfig, localConfig, err := adapterconfig.EncodeSplit(config)
	if err != nil {
		t.Fatalf("encode mixed-review Config v4 pair: %v", err)
	}
	writeLiveExistingConfig(t, filepath.Join(project, ".mulgae", "config.yaml"), projectConfig)
	writeLiveExistingConfig(t, filepath.Join(project, ".mulgae", "local.yaml"), localConfig)
}

func writeLiveExistingConfig(t *testing.T, path string, content []byte) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		t.Fatalf("live config destination is unavailable: %v", err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		t.Fatalf("open live config destination: %v", err)
	}
	if _, err := file.Write(content); err != nil {
		_ = file.Close()
		t.Fatalf("write live config destination: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close live config destination: %v", err)
	}
}

func requireLiveE2EEnvironment(t *testing.T) liveE2EEnvironment {
	t.Helper()
	installed, err := user.Current()
	if err != nil || installed == nil || !filepath.IsAbs(installed.HomeDir) || filepath.Clean(installed.HomeDir) != installed.HomeDir {
		t.Fatalf("native installed-user HOME is unavailable: %v", err)
	}
	binary := requireLiveExecutable(t, "MULGAE_E2E_BINARY", "")
	zcodeAppBundle := requireLiveDirectory(t, "MULGAE_E2E_ZCODE_APP_BUNDLE", "/Applications/ZCode.app")
	profile, discoverErr := reviewrun.DiscoverProviderProfileWithOverride(context.Background(), environmentadapter.NewInspector(), reviewrun.FamilyZCode, zcodeAppBundle)
	if discoverErr != nil || profile.Executable() == "" || profile.Launcher() == "" || profile.ZCodeProviderConfig() == "" {
		t.Fatalf("ZCode production discovery failed: reason=%q error=%v", profile.Reason(), discoverErr)
	}
	grokExecutable := requireLiveExecutable(t, "MULGAE_E2E_GROK_EXECUTABLE", lookupLiveExecutable(t, "grok"))
	return liveE2EEnvironment{binary: binary, nativeHome: installed.HomeDir, zcodeAppBundle: zcodeAppBundle, grokExecutable: grokExecutable}
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

func runLiveRecoverableWorkflowWithGate(t *testing.T, validator *jsonschema.Validator, environment liveE2EEnvironment, project, scenario string, expected map[string]string, gate func(string, livePublishedRun, map[string]string) error, arguments ...string) livePublishedRun {
	t.Helper()
	const maxAttempts = 2
	var last string
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		run, status, reason := runLiveRecoverableAttempt(t, validator, environment, project, scenario, expected, gate, attempt, maxAttempts, arguments...)
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

func runLiveRecoverableAttempt(t *testing.T, validator *jsonschema.Validator, environment liveE2EEnvironment, project, scenario string, expected map[string]string, gate func(string, livePublishedRun, map[string]string) error, attempt, maxAttempts int, arguments ...string) (run livePublishedRun, status, reason string) {
	t.Helper()
	scope := beginLiveE2ELogScope(t, "attempt", fmt.Sprintf("scenario=%s attempt=%d/%d", scenario, attempt, maxAttempts))
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
	if gate == nil {
		t.Fatal("focused live attempt has no verification gate")
	} else if err := gate(project, run, expected); err != nil {
		reason = err.Error()
	} else {
		logLiveRecoverySelections(t, run)
		scope.status = "passed"
		return run, scope.status, ""
	}
	scope.status = "retry_gate"
	if attempt == maxAttempts {
		scope.status = "failed"
	}
	t.Logf("focused live attempt %d/%d did not satisfy the %s gate; retrying the whole review: %s", attempt, maxAttempts, scenario, reason)
	return livePublishedRun{}, scope.status, reason
}

func validateLiveSingleInvocationGate(project string, run livePublishedRun, expected map[string]string) error {
	if err := validateLiveRecoverableAssignments(run, expected); err != nil {
		return err
	}
	for role, provider := range expected {
		attempts := liveAttemptsForRole(run.manifest.Attempts, role)
		if len(attempts) != 1 || attempts[0].ProviderInstance != provider || attempts[0].InvocationCount != 1 {
			return fmt.Errorf("%s invocation budget mismatch: %#v", role, attempts)
		}
	}
	if err := validateLivePrimaryProcessTerminals(project, run, expected); err != nil {
		return fmt.Errorf("invalid process diagnostics: %w", err)
	}
	return nil
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

func copyLiveRoleReportInventory(run livePublishedRun) livePublishedRun {
	copied := run
	copied.manifest.RoleReports = append([]liveRoleReport(nil), run.manifest.RoleReports...)
	return copied
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
// configurable: every ZCode or Grok review-family launch, including exact
// replay, receives a fresh staged_file write grant; every other family keeps
// stdout.
func liveExpectedRoleReportTransport(providerInstance, _ string) string {
	if family := liveProviderFamily(providerInstance); family == "zcode" || family == "grok" {
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
			RequiredRoles      []string `json:"required_roles"`
			RoleMaxInvocations int      `json:"role_max_invocations"`
			RunMaxInvocations  int      `json:"run_max_invocations"`
			ExtractionEnabled  bool     `json:"extraction_enabled"`
			RoleAssignments    []struct {
				Role            string `json:"role"`
				PrimaryProvider string `json:"primary_provider"`
			} `json:"role_assignments"`
		} `json:"policy"`
	}
	if err := json.Unmarshal(raw, &redacted); err != nil {
		t.Fatalf("decode redacted config: %v", err)
	}
	if !reflect.DeepEqual(redacted.ConfiguredProviderIDs, []string{"zcode", "grok"}) {
		t.Fatalf("configured providers = %v", redacted.ConfiguredProviderIDs)
	}
	want := map[string]string{
		"logic": "zcode", "security": "grok", "maintainability": "zcode",
		"product": "zcode", "documentation": "zcode", "testing": "zcode",
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
	if !reflect.DeepEqual(redacted.Policy.RequiredRoles, []string{"logic", "security"}) ||
		redacted.Policy.RoleMaxInvocations != 2 || redacted.Policy.RunMaxInvocations != 4 || redacted.Policy.ExtractionEnabled {
		t.Fatalf("mixed-review policy = %#v", redacted.Policy)
	}
}

func assertLiveMixedReviewConfig(t *testing.T, project string) {
	t.Helper()
	config := readE2EConfig(t, project)
	if config.Resources.MaxActiveLanes != 2 || config.Resources.PrimaryRepairAttempts != 0 ||
		config.Resources.RoleMaxInvocations != 2 || config.Resources.RunMaxInvocations != 4 ||
		config.Validation.Repair.Enabled || config.Validation.Extraction.Enabled {
		t.Fatalf("mixed-review execution policy = validation=%#v resources=%#v", config.Validation, config.Resources)
	}
	if !config.Roles.Logic.Enabled || !config.Roles.Security.Enabled || config.Roles.Maintainability.Enabled ||
		config.Roles.Product.Enabled || config.Roles.Documentation.Enabled || config.Roles.Testing.Enabled || config.Roles.Artist.Enabled {
		t.Fatalf("mixed-review enabled roles = %#v", config.Roles)
	}
}

func assertLiveRoleReportMarker(t *testing.T, project string, run livePublishedRun, role, marker string) {
	t.Helper()
	for _, report := range run.envelope.Result.RoleReportURIs {
		if report.Role == role {
			if body := readLiveArtifact(t, project, report.URI); !bytes.Contains(body, []byte(marker)) {
				t.Fatalf("published %s report does not prove captured workspace access", role)
			}
			return
		}
	}
	t.Fatalf("published review has no %s role report", role)
}

func assertLiveReportsOnlyAggregation(t *testing.T, run livePublishedRun) {
	t.Helper()
	if run.manifest.ContentVerdict != "reports_only" || run.review.ContentVerdict != "reports_only" ||
		run.manifest.CoverageStatus != "complete" || run.review.CoverageStatus != "complete" ||
		run.manifest.StructuredExtractionState != "reports_only" || run.review.StructuredExtractionStatus != "reports_only" ||
		run.manifest.CIDecision != "pass" || run.review.CIDecision != "pass" || len(run.review.Findings) != 0 {
		t.Fatalf("mixed-provider reports-only aggregation mismatch: manifest=%#v review=%#v", run.manifest, run.review)
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
	families := []string{"zcode", "grok"}
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
	if doctor.Readiness.State != "ready" || !reflect.DeepEqual(doctor.ConfiguredProviderIDs, families) {
		t.Fatalf("doctor readiness = %#v", doctor)
	}
	eligible := map[string]bool{}
	for _, row := range doctor.ProviderInventory {
		if row.State != "eligible" {
			continue
		}
		reasonAccepted := row.Reason == "provider_cli_version_supported" || row.Reason == "provider_cli_version_newer_than_verified"
		if row.Family == "zcode" {
			reasonAccepted = row.Reason == "zcode_application_version_supported" || row.Reason == "zcode_application_version_newer_than_verified"
		}
		if reasonAccepted {
			eligible[row.Family] = true
		}
	}
	for _, family := range families {
		if !eligible[family] {
			t.Fatalf("doctor did not retain truthful prequalification state for %s: %#v", family, doctor.ProviderInventory)
		}
	}
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

func logLiveRecoverySelections(t *testing.T, run livePublishedRun) {
	t.Helper()
	for _, outcome := range run.review.RoleOutcomes {
		if outcome.ProviderInstance == nil || outcome.SelectedVia == nil {
			continue
		}
		t.Logf("[test-e2e] role=%s provider=%s selected_via=%s outcome=%s", outcome.Role, *outcome.ProviderInstance, *outcome.SelectedVia, outcome.Outcome)
	}
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

func (environment liveE2EEnvironment) String() string {
	return fmt.Sprintf("Mulgae=%s HOME=%s ZCode.app=%s", environment.binary, environment.nativeHome, environment.zcodeAppBundle)
}
