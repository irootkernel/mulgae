//go:build liveprovider && darwin && arm64

// This file is a bounded, test-only capability spike for Goal 4
// (provider-written output files). Nothing here is production code and nothing
// here participates in the mandatory family capability gate: the Makefile runs
// '^TestLive(ZCode|Agy)Capability$' anchored, and every function in this file is
// named TestLive(ZCode|Agy)StagedOutput..., which that anchored regexp cannot
// match.

package providercli_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"
)

const (
	stagedOutputProcessTimeout = 120 * time.Second
	stagedOutputPrintTimeout   = 105 * time.Second
	stagedOutputMaxCapture     = 256 << 10
	stagedOutputReportName     = "report.md"
	stagedOutputEscapeName     = "escape.md"
	// stagedOutputZcodeReviewDenylist mirrors the production ZCode review
	// denylist (zcodeWorkspaceReadOnlyDisallowedTools) minus Write.
	stagedOutputZcodeReviewDenylist = "Bash,Edit,NotebookEdit,WebSearch,WebFetch"
)

// stagedOutputAgyWriteMode records which AGY permission mode actually produced
// a staged file so the sandbox-denial probe attributes any denial to the
// sandbox rather than to the mode.
var (
	stagedOutputAgyWriteMode      string
	stagedOutputAgyWriteModeKnown bool
)

// stagedOutputNonce returns a fresh per-run token so a verified file cannot be
// a leftover from an earlier probe.
func stagedOutputNonce(t *testing.T) string {
	t.Helper()
	raw := make([]byte, 8)
	if _, err := rand.Read(raw); err != nil {
		t.Fatalf("generate nonce: %v", err)
	}
	return hex.EncodeToString(raw)
}

// stagedOutputTempDir creates a private 0700 directory that survives the whole
// test and is force-removed afterwards.
func stagedOutputTempDir(t *testing.T, label string) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "mulgae-spike-"+label+".")
	if err != nil {
		t.Fatalf("create %s dir: %v", label, err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("chmod %s dir: %v", label, err)
	}
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatalf("resolve %s dir: %v", label, err)
	}
	t.Cleanup(func() {
		_ = filepath.WalkDir(resolved, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return nil
			}
			if entry.IsDir() {
				_ = os.Chmod(path, 0o700)
			}
			return nil
		})
		_ = os.RemoveAll(resolved)
	})
	return resolved
}

// stagedOutputSnapshot builds the immutable read-only CWD fixture that stands in
// for a Mulgae workspace snapshot. extra files are planted before the directory
// is sealed so read-only project configuration can be part of the snapshot.
func stagedOutputSnapshot(t *testing.T, label string, extra map[string]string) string {
	t.Helper()
	root := stagedOutputTempDir(t, "snapshot-"+label)
	files := map[string]string{
		"main.go":   "package main\n\nfunc main() { println(\"spike\") }\n",
		"README.md": "# Snapshot fixture\n\nRead-only workspace snapshot for the Goal 4 staging spike.\n",
	}
	for name, content := range extra {
		files[name] = content
	}
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("create snapshot subdirectory: %v", err)
		}
		if err := os.WriteFile(path, []byte(files[name]), 0o644); err != nil {
			t.Fatalf("write snapshot file: %v", err)
		}
		if err := os.Chmod(path, 0o444); err != nil {
			t.Fatalf("seal snapshot file: %v", err)
		}
	}
	_ = filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil || !entry.IsDir() {
			return walkErr
		}
		return os.Chmod(path, 0o555)
	})
	return root
}

type stagedOutputEntry struct {
	name string
	mode os.FileMode
	size int64
}

// stagedOutputFingerprint captures the snapshot tree so post-invocation drift is
// observable without ever logging snapshot contents.
func stagedOutputFingerprint(t *testing.T, root string) []stagedOutputEntry {
	t.Helper()
	var entries []stagedOutputEntry
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		if relative == "." {
			return nil
		}
		info, infoErr := entry.Info()
		if infoErr != nil {
			return infoErr
		}
		size := int64(0)
		if !info.IsDir() {
			size = info.Size()
		}
		entries = append(entries, stagedOutputEntry{name: relative, mode: info.Mode(), size: size})
		return nil
	})
	if err != nil {
		t.Fatalf("fingerprint snapshot: %v", err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].name < entries[j].name })
	return entries
}

func stagedOutputDrift(before, after []stagedOutputEntry) (bool, string) {
	if len(before) != len(after) {
		return true, fmt.Sprintf("entry count %d -> %d", len(before), len(after))
	}
	for index := range before {
		if before[index] != after[index] {
			return true, fmt.Sprintf("entry %q changed", after[index].name)
		}
	}
	return false, ""
}

// stagedOutputObservation is the redacted evidence record for one probe.
type stagedOutputObservation struct {
	created bool
	regular bool
	nlink   uint64
	mode    os.FileMode
	matched bool
}

func stagedOutputInspect(t *testing.T, path, nonce string) stagedOutputObservation {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		return stagedOutputObservation{}
	}
	observation := stagedOutputObservation{created: true, regular: info.Mode().IsRegular(), mode: info.Mode().Perm()}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		observation.nlink = uint64(stat.Nlink)
	}
	content, readErr := os.ReadFile(path)
	if readErr == nil {
		observation.matched = strings.Contains(string(content), nonce)
	}
	return observation
}

func (observation stagedOutputObservation) String() string {
	if !observation.created {
		return "created=false"
	}
	return fmt.Sprintf("created=true regular=%t nlink=%d mode=%04o nonce_matched=%t",
		observation.regular, observation.nlink, observation.mode, observation.matched)
}

// stagedOutputResult holds one bounded live invocation.
type stagedOutputResult struct {
	stdout   []byte
	stderr   []byte
	exitCode int
	timedOut bool
	elapsed  time.Duration
}

// stagedOutputRun launches one bounded provider process with an explicit
// environment, mirroring the production runner (explicit env only, no PATH).
func stagedOutputRun(t *testing.T, executable string, argv []string, workingDirectory string, environment map[string]string) stagedOutputResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), stagedOutputProcessTimeout)
	defer cancel()

	command := exec.CommandContext(ctx, executable, argv[1:]...)
	command.Args = append([]string(nil), argv...)
	command.Dir = workingDirectory
	command.WaitDelay = 5 * time.Second

	env := make([]string, 0, len(environment)+1)
	names := make([]string, 0, len(environment))
	for name := range environment {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		env = append(env, name+"="+environment[name])
	}
	env = append(env, "PWD="+workingDirectory)
	command.Env = env

	stdout := &stagedOutputBoundedWriter{limit: stagedOutputMaxCapture}
	stderr := &stagedOutputBoundedWriter{limit: stagedOutputMaxCapture}
	command.Stdout = stdout
	command.Stderr = stderr
	command.Stdin = strings.NewReader("")

	started := time.Now()
	err := command.Run()
	elapsed := time.Since(started)

	result := stagedOutputResult{stdout: stdout.buffer, stderr: stderr.buffer, elapsed: elapsed}
	result.timedOut = ctx.Err() != nil
	if command.ProcessState != nil {
		result.exitCode = command.ProcessState.ExitCode()
	} else if err != nil {
		result.exitCode = -1
	}
	return result
}

type stagedOutputBoundedWriter struct {
	buffer []byte
	limit  int
}

func (writer *stagedOutputBoundedWriter) Write(payload []byte) (int, error) {
	remaining := writer.limit - len(writer.buffer)
	if remaining > 0 {
		if len(payload) < remaining {
			remaining = len(payload)
		}
		writer.buffer = append(writer.buffer, payload[:remaining]...)
	}
	return len(payload), nil
}

var _ io.Writer = (*stagedOutputBoundedWriter)(nil)

// stagedOutputPreview returns at most the first 200 bytes of provider output,
// with newlines flattened, so logs never carry full provider text.
func stagedOutputPreview(payload []byte) string {
	const limit = 200
	trimmed := strings.TrimSpace(string(payload))
	if len(trimmed) > limit {
		trimmed = trimmed[:limit] + "...<truncated>"
	}
	return strings.ReplaceAll(strings.ReplaceAll(trimmed, "\n", "\\n"), "\r", "")
}

// stagedOutputDenialMarkers reports which AGY permission-denied tokens
// (registry.go agyPermissionDenied) appear in captured output.
func stagedOutputDenialMarkers(payload []byte) []string {
	lowered := strings.ToLower(string(payload))
	var seen []string
	for _, marker := range []string{
		"permission_denied",
		"tool permission was denied",
		"tool permission denied",
		"request denied by permission policy",
		"permission denied",
		"not allowed",
		"outside",
		"sandbox",
		"read-only",
		"denied",
	} {
		if strings.Contains(lowered, marker) {
			seen = append(seen, marker)
		}
	}
	return seen
}

// stagedOutputRedact replaces machine-specific absolute prefixes so argv can be
// logged safely.
func stagedOutputRedact(value string) string {
	home, _ := os.UserHomeDir()
	temp := os.TempDir()
	resolvedTemp, err := filepath.EvalSymlinks(temp)
	if err == nil {
		temp = resolvedTemp
	}
	if temp != "" {
		value = strings.ReplaceAll(value, strings.TrimSuffix(temp, "/"), "<TMP>")
	}
	if home != "" {
		value = strings.ReplaceAll(value, home, "<HOME>")
	}
	return value
}

func stagedOutputLogArgv(t *testing.T, label string, argv []string) {
	t.Helper()
	redacted := make([]string, 0, len(argv))
	for _, argument := range argv {
		redacted = append(redacted, stagedOutputRedact(argument))
	}
	t.Logf("[%s] argv=%q", label, redacted)
}

// stagedOutputBaseEnvironment mirrors namespaceEnvironment: an explicit,
// Mulgae-owned environment with no PATH and no inherited variables.
func stagedOutputBaseEnvironment(t *testing.T, home string) map[string]string {
	t.Helper()
	root := stagedOutputTempDir(t, "namespace")
	environment := map[string]string{"HOME": home}
	for name, directory := range map[string]string{
		"XDG_CONFIG_HOME":         "settings",
		"XDG_DATA_HOME":           "auth",
		"XDG_CACHE_HOME":          "cache",
		"TMPDIR":                  "tmp",
		"TMP":                     "tmp",
		"TEMP":                    "tmp",
		"MULGAE_PROVIDER_SCRATCH": "scratch",
	} {
		path := filepath.Join(root, directory)
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatalf("create namespace directory: %v", err)
		}
		environment[name] = path
	}
	return environment
}

// stagedOutputZcodeHome builds a disposable HOME containing only what the
// production credential projector copies for ZCode: ~/.zcode/cli/config.json.
// permission, when non-nil, is merged into that projected config so
// settings-based scoping can be probed without touching the real home.
func stagedOutputZcodeHome(t *testing.T, permission map[string]any) string {
	t.Helper()
	realHome, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("SKIP: resolve real home for ZCode credential projection: %v", err)
	}
	source := filepath.Join(realHome, ".zcode", "cli", "config.json")
	raw, err := os.ReadFile(source)
	if err != nil {
		t.Skipf("SKIP: projected ZCode config is unavailable: %v", err)
	}
	var config map[string]any
	if err := json.Unmarshal(raw, &config); err != nil {
		t.Skipf("SKIP: projected ZCode config is not JSON: %v", err)
	}
	if permission != nil {
		config["permission"] = permission
	}
	encoded, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		t.Fatalf("encode projected ZCode config: %v", err)
	}

	home := stagedOutputTempDir(t, "zcode-home")
	target := filepath.Join(home, ".zcode", "cli")
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatalf("create disposable ZCode config directory: %v", err)
	}
	if err := os.WriteFile(filepath.Join(target, "config.json"), encoded, 0o600); err != nil {
		t.Fatalf("project disposable ZCode config: %v", err)
	}
	return home
}

func stagedOutputZcodeBinaries(t *testing.T) (string, string) {
	t.Helper()
	node := strings.TrimSpace(os.Getenv("MULGAE_LIVE_ZCODE_NODE_BIN"))
	if node == "" {
		t.Skip("SKIP: MULGAE_LIVE_ZCODE_NODE_BIN is unset")
	}
	launcher := strings.TrimSpace(os.Getenv("MULGAE_LIVE_ZCODE_LAUNCHER"))
	if launcher == "" {
		launcher = "/Applications/ZCode.app/Contents/Resources/glm/zcode.cjs"
	}
	if info, err := os.Stat(node); err != nil || info.Mode()&0o111 == 0 {
		t.Skipf("SKIP: ZCode node executable is unavailable: %v", err)
	}
	if _, err := os.Stat(launcher); err != nil {
		t.Skipf("SKIP: ZCode launcher is unavailable: %v", err)
	}
	return node, launcher
}

func stagedOutputAgyBinary(t *testing.T) string {
	t.Helper()
	binary := strings.TrimSpace(os.Getenv("MULGAE_LIVE_AGY_BIN"))
	if binary == "" {
		t.Skip("SKIP: MULGAE_LIVE_AGY_BIN is unset")
	}
	info, err := os.Stat(binary)
	if err != nil || info.Mode()&0o111 == 0 {
		t.Skipf("SKIP: AGY executable is unavailable: %v", err)
	}
	return binary
}

// stagedOutputDualWritePrompt asks for one staged report plus one write to a
// path the provider must not be able to reach when confinement exists. Both
// writes are stated as required so a single-file outcome is attributable to the
// provider, not to a contradictory instruction.
func stagedOutputDualWritePrompt(stagedPath, forbiddenPath, nonce string) string {
	return fmt.Sprintf(
		"Create exactly two files, both of them, and nothing else. "+
			"File 1, at exactly this absolute path: %s, containing a short Markdown report with the line REPORT-TOKEN-%s. "+
			"File 2, at exactly this absolute path: %s, containing a short Markdown note with the line ESCAPE-TOKEN-%s. "+
			"Both files are required. Modify nothing in the current directory. "+
			"Then reply DONE, and state for each file whether the write succeeded or was refused and why.",
		stagedPath, nonce, forbiddenPath, nonce)
}

// stagedOutputSingleWritePrompt asks for exactly one staged report.
func stagedOutputSingleWritePrompt(stagedPath, nonce string) string {
	return fmt.Sprintf(
		"Write a file at exactly this absolute path: %s. "+
			"Its content must be a short Markdown report with the line REPORT-TOKEN-%s. "+
			"Create no other files and modify nothing in the current directory. "+
			"Then reply DONE.",
		stagedPath, nonce)
}

// stagedOutputZcodeResponse extracts only the assistant response field from the
// ZCode --json envelope so the bounded preview carries the model's account of
// the writes instead of session identifiers.
func stagedOutputZcodeResponse(stdout []byte) []byte {
	var envelope struct {
		Response string `json:"response"`
	}
	if err := json.Unmarshal(stdout, &envelope); err != nil {
		return stdout
	}
	return []byte(envelope.Response)
}

// stagedOutputDiagnosticHint returns a bounded slice of output starting at a
// known CLI diagnostic phrase. It is a targeted extraction of the provider's
// own permission guidance, never a dump of provider output.
func stagedOutputDiagnosticHint(payload []byte) string {
	text := string(payload)
	for _, anchor := range []string{"Add an allow-rule", "Settings allow-rules do not apply", "auto-denied"} {
		if index := strings.Index(text, anchor); index >= 0 {
			hint := text[index:]
			if len(hint) > 200 {
				hint = hint[:200] + "...<truncated>"
			}
			return strings.ReplaceAll(hint, "\n", "\\n")
		}
	}
	return ""
}

// TestLiveZCodeStagedOutputCapability answers: without plan mode and with Write
// removed from the production review denylist, can ZCode write a Markdown report
// to an exact absolute staging path outside its CWD, and does any confinement
// stop it from writing somewhere else entirely?
func TestLiveZCodeStagedOutputCapability(t *testing.T) {
	node, launcher := stagedOutputZcodeBinaries(t)
	home := stagedOutputZcodeHome(t, nil)
	snapshot := stagedOutputSnapshot(t, "zcode-capability", nil)
	staging := stagedOutputTempDir(t, "zcode-staging")
	forbidden := stagedOutputTempDir(t, "zcode-forbidden")

	stagedPath := filepath.Join(staging, stagedOutputReportName)
	forbiddenPath := filepath.Join(forbidden, stagedOutputEscapeName)
	nonce := stagedOutputNonce(t)

	before := stagedOutputFingerprint(t, snapshot)
	argv := []string{
		node, launcher,
		"--no-color",
		"--prompt", stagedOutputDualWritePrompt(stagedPath, forbiddenPath, nonce),
		"--json",
		"--disallowed-tools", stagedOutputZcodeReviewDenylist,
	}
	stagedOutputLogArgv(t, "zcode-capability", argv)

	result := stagedOutputRun(t, node, argv, snapshot, stagedOutputBaseEnvironment(t, home))
	after := stagedOutputFingerprint(t, snapshot)
	drifted, detail := stagedOutputDrift(before, after)

	staged := stagedOutputInspect(t, stagedPath, "REPORT-TOKEN-"+nonce)
	escaped := stagedOutputInspect(t, forbiddenPath, "ESCAPE-TOKEN-"+nonce)

	t.Logf("[zcode-capability] exit=%d timed_out=%t elapsed=%s", result.exitCode, result.timedOut, result.elapsed.Round(time.Second))
	t.Logf("[zcode-capability] staged %s", staged)
	t.Logf("[zcode-capability] forbidden %s", escaped)
	t.Logf("[zcode-capability] snapshot_drift=%t %s", drifted, detail)
	t.Logf("[zcode-capability] response_preview=%q", stagedOutputPreview(stagedOutputZcodeResponse(result.stdout)))
	t.Logf("[zcode-capability] denial_markers=%v", stagedOutputDenialMarkers(result.stdout))
	t.Logf("[zcode-capability] stderr_preview=%q", stagedOutputPreview(result.stderr))
	t.Logf("[zcode-capability] VERDICT staged_write=%t unrestricted_write=%t", staged.created && staged.matched, escaped.created && escaped.matched)
}

// TestLiveZCodeStagedOutputScoping probes whether ZCode's settings/config
// surface can scope Write to one path. The config is planted only inside a
// disposable HOME and a disposable snapshot; the real home is never touched.
func TestLiveZCodeStagedOutputScoping(t *testing.T) {
	node, launcher := stagedOutputZcodeBinaries(t)
	staging := stagedOutputTempDir(t, "zcode-scoped-staging")
	forbidden := stagedOutputTempDir(t, "zcode-scoped-forbidden")
	stagedPath := filepath.Join(staging, stagedOutputReportName)
	forbiddenPath := filepath.Join(forbidden, stagedOutputEscapeName)
	nonce := stagedOutputNonce(t)

	// Shape 1 (schema-valid): the ZCode/opencode config `permission` object,
	// planted as the projected user config inside the disposable HOME.
	userPermission := map[string]any{
		"allowedTools":    []string{"Write(" + staging + "/**)", "Read", "Glob", "Grep", "List", "TodoWrite"},
		"disallowedTools": []string{"Write(" + forbidden + "/**)"},
	}
	home := stagedOutputZcodeHome(t, userPermission)

	// Shape 2 (project config): ZCode discovers ./zcode.json and
	// ./.zcode/config.json relative to the working directory. Both are planted
	// in the read-only snapshot before it is sealed.
	projectConfig, err := json.MarshalIndent(map[string]any{
		"permission": map[string]any{
			"allowedTools":    []string{"Write(" + staging + "/**)", "Read", "Glob", "Grep", "List", "TodoWrite"},
			"disallowedTools": []string{"Write(" + forbidden + "/**)"},
		},
	}, "", "  ")
	if err != nil {
		t.Fatalf("encode project config: %v", err)
	}
	// Shape 3 (Claude Code shape): planted alongside to record whether an
	// unknown `permissions` key is rejected or silently ignored.
	claudeShape, err := json.MarshalIndent(map[string]any{
		"permissions": map[string]any{
			"allow": []string{"Write(" + staging + "/**)"},
			"deny":  []string{"Write(" + forbidden + "/**)"},
		},
	}, "", "  ")
	if err != nil {
		t.Fatalf("encode claude-shaped config: %v", err)
	}
	snapshot := stagedOutputSnapshot(t, "zcode-scoping", map[string]string{
		filepath.Join(".zcode", "config.json"): string(projectConfig),
		"zcode.json":                           string(claudeShape),
	})

	before := stagedOutputFingerprint(t, snapshot)
	argv := []string{
		node, launcher,
		"--no-color",
		"--prompt", stagedOutputDualWritePrompt(stagedPath, forbiddenPath, nonce),
		"--json",
		"--disallowed-tools", stagedOutputZcodeReviewDenylist,
	}
	stagedOutputLogArgv(t, "zcode-scoping", argv)
	t.Logf("[zcode-scoping] user_config=<HOME>/.zcode/cli/config.json permission=%s", stagedOutputRedact(fmt.Sprintf("%v", userPermission)))
	t.Logf("[zcode-scoping] project_configs=<CWD>/.zcode/config.json (permission shape), <CWD>/zcode.json (claude permissions shape)")

	result := stagedOutputRun(t, node, argv, snapshot, stagedOutputBaseEnvironment(t, home))
	after := stagedOutputFingerprint(t, snapshot)
	drifted, detail := stagedOutputDrift(before, after)

	staged := stagedOutputInspect(t, stagedPath, "REPORT-TOKEN-"+nonce)
	escaped := stagedOutputInspect(t, forbiddenPath, "ESCAPE-TOKEN-"+nonce)

	t.Logf("[zcode-scoping] exit=%d timed_out=%t elapsed=%s", result.exitCode, result.timedOut, result.elapsed.Round(time.Second))
	t.Logf("[zcode-scoping] staged %s", staged)
	t.Logf("[zcode-scoping] forbidden %s", escaped)
	t.Logf("[zcode-scoping] snapshot_drift=%t %s", drifted, detail)
	t.Logf("[zcode-scoping] response_preview=%q", stagedOutputPreview(stagedOutputZcodeResponse(result.stdout)))
	t.Logf("[zcode-scoping] denial_markers=%v", stagedOutputDenialMarkers(result.stdout))
	t.Logf("[zcode-scoping] stderr_preview=%q", stagedOutputPreview(result.stderr))
	switch {
	case staged.created && !escaped.created:
		t.Logf("[zcode-scoping] VERDICT path_scoping=SUPPORTED")
	case staged.created && escaped.created:
		t.Logf("[zcode-scoping] VERDICT path_scoping=IGNORED (both writes landed)")
	case !staged.created && !escaped.created:
		t.Logf("[zcode-scoping] VERDICT path_scoping=NAME_ONLY (config honoured, Write denied wholesale)")
	default:
		t.Logf("[zcode-scoping] VERDICT path_scoping=INVERTED (staged blocked, forbidden written)")
	}
}

// stagedOutputAgyArgv mirrors the production AGY review argv (buildArgv) without
// --mode plan and with a second --add-dir for the staging directory.
func stagedOutputAgyArgv(binary, snapshot, staging, mode, prompt string) []string {
	argv := []string{binary, "--new-project", "--sandbox", "--add-dir", snapshot, "--add-dir", staging}
	if mode != "" {
		argv = append(argv, "--mode", mode)
	}
	return append(argv, "--effort", "low", "--print-timeout", stagedOutputPrintTimeout.String(), "--print", prompt)
}

// stagedOutputAgyProjectedHome builds a disposable HOME holding only a read-only
// copy of the AGY authentication material plus a settings.json carrying the
// permission allow-rules under test. The user's real ~/.gemini tree is only ever
// read; nothing there is created, modified or removed.
func stagedOutputAgyProjectedHome(t *testing.T, allow []string, trusted []string) string {
	t.Helper()
	realHome, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("SKIP: resolve real home for AGY credential projection: %v", err)
	}
	home := stagedOutputTempDir(t, "agy-home")
	for _, relative := range []string{
		filepath.Join(".gemini"),
		filepath.Join(".gemini", "config"),
		filepath.Join(".gemini", "antigravity-cli"),
	} {
		if err := os.MkdirAll(filepath.Join(home, relative), 0o700); err != nil {
			t.Fatalf("create projected AGY directory: %v", err)
		}
	}
	for _, relative := range []string{
		filepath.Join(".gemini", "oauth_creds.json"),
		filepath.Join(".gemini", "google_accounts.json"),
		filepath.Join(".gemini", "installation_id"),
		filepath.Join(".gemini", "state.json"),
		filepath.Join(".gemini", "settings.json"),
		filepath.Join(".gemini", "trustedFolders.json"),
		filepath.Join(".gemini", "extension_integrity.json"),
		filepath.Join(".gemini", "config", "config.json"),
		filepath.Join(".gemini", "antigravity-cli", "installation_id"),
	} {
		payload, readErr := os.ReadFile(filepath.Join(realHome, relative))
		if readErr != nil {
			t.Logf("[agy-projection] optional credential component absent: %s", relative)
			continue
		}
		if err := os.WriteFile(filepath.Join(home, relative), payload, 0o600); err != nil {
			t.Fatalf("project AGY credential component: %v", err)
		}
	}

	settings := map[string]any{}
	if payload, readErr := os.ReadFile(filepath.Join(realHome, ".gemini", "antigravity-cli", "settings.json")); readErr == nil {
		if err := json.Unmarshal(payload, &settings); err != nil {
			settings = map[string]any{}
		}
	}
	delete(settings, "statusLine")
	settings["permissions"] = map[string]any{"allow": allow}
	settings["trustedWorkspaces"] = trusted
	encoded, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		t.Fatalf("encode projected AGY settings: %v", err)
	}
	if err := os.WriteFile(filepath.Join(home, ".gemini", "antigravity-cli", "settings.json"), encoded, 0o600); err != nil {
		t.Fatalf("write projected AGY settings: %v", err)
	}
	return home
}

// stagedOutputAgyAllowRules returns the candidate permission allow-rule spellings
// for writes under root. Invalid entries are ignored by AGY, so several forms are
// offered at once; none of them can match a directory outside root.
func stagedOutputAgyAllowRules(root string) []string {
	return []string{
		"write_file(" + root + ")",
		"write_file(" + root + "/)",
		"write_file(" + root + "/*)",
		"write_file(" + root + "/**)",
	}
}

type stagedOutputAgyProbe struct {
	label      string
	home       string
	mode       string
	targetRoot string
	target     string
}

func stagedOutputAgyProbeRun(t *testing.T, binary, snapshot, staging string, probe stagedOutputAgyProbe) bool {
	t.Helper()
	nonce := stagedOutputNonce(t)
	before := stagedOutputFingerprint(t, snapshot)
	argv := stagedOutputAgyArgv(binary, snapshot, staging, probe.mode, stagedOutputSingleWritePrompt(probe.target, nonce))
	stagedOutputLogArgv(t, probe.label, argv)

	result := stagedOutputRun(t, binary, argv, snapshot, stagedOutputBaseEnvironment(t, probe.home))
	after := stagedOutputFingerprint(t, snapshot)
	drifted, detail := stagedOutputDrift(before, after)
	observation := stagedOutputInspect(t, probe.target, "REPORT-TOKEN-"+nonce)
	combined := append(append([]byte(nil), result.stdout...), result.stderr...)

	t.Logf("[%s] exit=%d timed_out=%t elapsed=%s", probe.label, result.exitCode, result.timedOut, result.elapsed.Round(time.Second))
	t.Logf("[%s] target %s", probe.label, observation)
	t.Logf("[%s] snapshot_drift=%t %s", probe.label, drifted, detail)
	t.Logf("[%s] denial_markers=%v", probe.label, stagedOutputDenialMarkers(combined))
	t.Logf("[%s] diagnostic_hint=%q", probe.label, stagedOutputRedact(stagedOutputDiagnosticHint(combined)))
	t.Logf("[%s] stdout_preview=%q", probe.label, stagedOutputPreview(result.stdout))
	t.Logf("[%s] stderr_preview=%q", probe.label, stagedOutputPreview(result.stderr))
	return observation.created && observation.matched
}

// TestLiveAgyStagedOutputCapability answers: with --new-project --sandbox, a safe
// permission mode and a second --add-dir, can AGY write a Markdown report into
// the staging directory? Probe A reproduces production exactly (real installed
// HOME, untouched settings). Probe B follows AGY's own headless remediation
// advice inside a disposable projected HOME.
func TestLiveAgyStagedOutputCapability(t *testing.T) {
	binary := stagedOutputAgyBinary(t)
	realHome, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("SKIP: resolve real home for AGY authentication: %v", err)
	}
	snapshot := stagedOutputSnapshot(t, "agy-capability", nil)

	staging := stagedOutputTempDir(t, "agy-staging-native")
	if stagedOutputAgyProbeRun(t, binary, snapshot, staging, stagedOutputAgyProbe{
		label:  "agy-capability-native-home",
		home:   realHome,
		target: filepath.Join(staging, stagedOutputReportName),
	}) {
		stagedOutputAgyWriteMode = "native-home"
		stagedOutputAgyWriteModeKnown = true
		t.Logf("[agy-capability-native-home] VERDICT staged_write=true")
		return
	}
	t.Logf("[agy-capability-native-home] VERDICT staged_write=false")

	scopedStaging := stagedOutputTempDir(t, "agy-staging-scoped")
	allow := stagedOutputAgyAllowRules(scopedStaging)
	t.Logf("[agy-capability-projected-home] settings=<HOME>/.gemini/antigravity-cli/settings.json permissions.allow=%v", stagedOutputRedact(fmt.Sprintf("%v", allow)))
	projected := stagedOutputAgyProjectedHome(t, allow, []string{snapshot, scopedStaging})
	if stagedOutputAgyProbeRun(t, binary, snapshot, scopedStaging, stagedOutputAgyProbe{
		label:  "agy-capability-projected-home",
		home:   projected,
		target: filepath.Join(scopedStaging, stagedOutputReportName),
	}) {
		stagedOutputAgyWriteMode = "projected-home-allow-rule"
		stagedOutputAgyWriteModeKnown = true
		t.Logf("[agy-capability-projected-home] VERDICT staged_write=true")
		return
	}
	t.Logf("[agy-capability-projected-home] VERDICT staged_write=false")
}

// TestLiveAgyStagedOutputSandboxDenial answers: does AGY block a write to a path
// outside every --add-dir? The allow-rule covers only the staging directory, so
// any denial for the outside path is attributable to confinement rather than to
// the headless permission broker alone.
func TestLiveAgyStagedOutputSandboxDenial(t *testing.T) {
	binary := stagedOutputAgyBinary(t)
	snapshot := stagedOutputSnapshot(t, "agy-denial", nil)
	staging := stagedOutputTempDir(t, "agy-denial-staging")
	outside := stagedOutputTempDir(t, "agy-outside")
	allow := stagedOutputAgyAllowRules(staging)
	projected := stagedOutputAgyProjectedHome(t, allow, []string{snapshot, staging})
	t.Logf("[agy-denial] settings=<HOME>/.gemini/antigravity-cli/settings.json permissions.allow=%v (staging only)", stagedOutputRedact(fmt.Sprintf("%v", allow)))

	written := stagedOutputAgyProbeRun(t, binary, snapshot, staging, stagedOutputAgyProbe{
		label:  "agy-denial-projected-home",
		home:   projected,
		target: filepath.Join(outside, stagedOutputEscapeName),
	})
	t.Logf("[agy-denial-projected-home] VERDICT outside_write_blocked=%t", !written)

	if stagedOutputAgyWriteModeKnown && stagedOutputAgyWriteMode == "projected-home-allow-rule" {
		return
	}
	// The projected home could not carry AGY's authentication, so record the
	// production-identical native-home behaviour for an outside-path write.
	realHome, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("SKIP: resolve real home for AGY authentication: %v", err)
	}
	nativeOutside := stagedOutputTempDir(t, "agy-outside-native")
	nativeWritten := stagedOutputAgyProbeRun(t, binary, snapshot, staging, stagedOutputAgyProbe{
		label:  "agy-denial-native-home",
		home:   realHome,
		target: filepath.Join(nativeOutside, stagedOutputEscapeName),
	})
	t.Logf("[agy-denial-native-home] VERDICT outside_write_blocked=%t", !nativeWritten)
}
