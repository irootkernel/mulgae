//go:build darwin && arm64

package e2e

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/adapters/cli"
	adapterconfig "github.com/irootkernel/mulgae/internal/adapters/config"
	"github.com/irootkernel/mulgae/internal/app"
	"github.com/irootkernel/mulgae/internal/builtin"
	"github.com/irootkernel/mulgae/internal/domain"
	mulgaeentry "github.com/irootkernel/mulgae/internal/entrypoint/mulgae"
	"github.com/irootkernel/mulgae/internal/ports"
)

const productName = "mulgae"

type versionOutput struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

func TestIntegrationMulgaeBinaryBoundary(t *testing.T) {
	root := repositoryRoot(t)
	binary := buildMulgaeBinary(t, root)

	t.Run("version outside project", func(t *testing.T) {
		directory := t.TempDir()
		human := runMulgaeBinary(t, binary, directory, "--version")
		if human.exitCode != 0 || string(human.stdout) != "mulgae v1.4.2\n" || len(human.stderr) != 0 {
			t.Fatalf("human version = exit %d stdout %q stderr %q", human.exitCode, human.stdout, human.stderr)
		}
		machine := runMulgaeBinary(t, binary, directory, "version", "--json")
		if machine.exitCode != 0 || len(machine.stderr) != 0 {
			t.Fatalf("JSON version = exit %d stdout %q stderr %q", machine.exitCode, machine.stdout, machine.stderr)
		}
		var version versionOutput
		if err := json.Unmarshal(machine.stdout, &version); err != nil {
			t.Fatal(err)
		}
		if version.Name != productName || version.Version != "v1.4.2" {
			t.Fatalf("JSON version = %#v", version)
		}
	})

	t.Run("authoritative help", func(t *testing.T) {
		catalog := builtin.NewCatalog()
		for _, topic := range []string{
			"quickstart", "config", "providers", "role-paths", "prompts",
			"workflows", "artifacts", "validation", "ci", "exit-codes", "security",
		} {
			t.Run(topic, func(t *testing.T) {
				id := mustAssetID(t, "help:"+topic)
				_, authoritative, err := catalog.Read(context.Background(), id)
				if err != nil {
					t.Fatalf("read authoritative help: %v", err)
				}

				got := runMulgaeBinary(t, binary, t.TempDir(), "help", topic)
				if got.exitCode != 0 || len(got.stderr) != 0 {
					t.Fatalf("help %q = exit %d stdout %q stderr %q", topic, got.exitCode, got.stdout, got.stderr)
				}
				want := terminalLF(authoritative)
				if !bytes.Equal(got.stdout, want) {
					t.Fatalf("help %q bytes differ from authoritative asset\n got: %q\nwant: %q", topic, got.stdout, want)
				}
			})
		}
	})

	t.Run("help never opens project config", func(t *testing.T) {
		workingDirectory := t.TempDir()
		privateDirectory := filepath.Join(workingDirectory, ".mulgae")
		if err := os.Mkdir(privateDirectory, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := syscall.Mkfifo(filepath.Join(privateDirectory, "config.yaml"), 0o600); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, binary, "help", "quickstart")
		command.Dir = workingDirectory
		command.Env = isolatedMulgaeEnv(t)
		output, err := command.CombinedOutput()
		if ctx.Err() != nil {
			t.Fatal("help blocked while opening project config")
		}
		if err != nil {
			t.Fatalf("help failed: %v: %s", err, output)
		}
		if len(output) == 0 {
			t.Fatal("help returned no embedded documentation")
		}
	})

	t.Run("all provider subsets use canonical order", func(t *testing.T) {
		installed, err := user.Current()
		if err != nil || installed == nil {
			t.Fatalf("current native account unavailable: %#v %v", installed, err)
		}
		providerDirectory := canonicalTestTempDir(t)
		paths := map[string]string{
			"kimi":  filepath.Join(providerDirectory, "kimi"),
			"zcode": filepath.Join(providerDirectory, "zcode-node"),
			"agy":   filepath.Join(providerDirectory, "agy"),
		}
		for _, path := range paths {
			mustWriteTestFile(t, path, []byte("#!/bin/sh\nexit 0\n"))
			if err := os.Chmod(path, 0o700); err != nil {
				t.Fatal(err)
			}
		}
		launcher := filepath.Join(providerDirectory, "zcode-launcher.cjs")
		mustWriteTestFile(t, launcher, []byte("module.exports = {};\n"))
		environment := isolatedMulgaeEnvWith(t, installed.HomeDir, providerDirectory)
		for _, test := range []struct {
			name     string
			input    string
			expected []string
		}{
			{name: "kimi", input: "kimi", expected: []string{"kimi"}},
			{name: "zcode", input: "zcode", expected: []string{"zcode"}},
			{name: "agy", input: "agy", expected: []string{"agy"}},
			{name: "kimi zcode", input: "zcode,kimi", expected: []string{"kimi", "zcode"}},
			{name: "kimi agy", input: "agy,kimi", expected: []string{"kimi", "agy"}},
			{name: "zcode agy", input: "agy,zcode", expected: []string{"zcode", "agy"}},
			{name: "all", input: "agy,zcode,kimi", expected: []string{"kimi", "zcode", "agy"}},
		} {
			t.Run(test.name, func(t *testing.T) {
				project := canonicalTestTempDir(t)
				initializeReviewGitRepository(t, project)
				arguments := []string{"init", "--providers", test.input, "--output", "json"}
				for _, family := range test.expected {
					switch family {
					case "kimi":
						arguments = append(arguments, "--kimi-executable", paths[family])
					case "zcode":
						arguments = append(arguments, "--zcode-node-executable", paths[family], "--zcode-launcher", launcher)
					case "agy":
						arguments = append(arguments, "--agy-executable", paths[family], "--agy-permission-mode", "safe")
					}
				}
				result := runMulgaeBinaryWithEnv(t, binary, project, environment, arguments...)
				if result.exitCode != 0 || len(result.stderr) != 0 {
					t.Fatalf("init subset %q = exit %d stdout %q stderr %q", test.input, result.exitCode, result.stdout, result.stderr)
				}
				var envelope struct {
					Request struct {
						Selection struct {
							ProviderIDs []string `json:"provider_ids"`
						} `json:"selection"`
					} `json:"request"`
					Result struct {
						Selected   []string `json:"selected_provider_ids"`
						Candidates []string `json:"candidate_provider_ids"`
						Configured []string `json:"configured_provider_ids"`
					} `json:"result"`
				}
				if err := json.Unmarshal(result.stdout, &envelope); err != nil {
					t.Fatal(err)
				}
				if !slices.Equal(envelope.Request.Selection.ProviderIDs, test.expected) || !slices.Equal(envelope.Result.Selected, test.expected) || !slices.Equal(envelope.Result.Candidates, test.expected) || !slices.Equal(envelope.Result.Configured, test.expected) {
					t.Fatalf("canonical provider order = request %v selected %v candidates %v configured %v, want %v", envelope.Request.Selection.ProviderIDs, envelope.Result.Selected, envelope.Result.Candidates, envelope.Result.Configured, test.expected)
				}
				config := readE2EConfig(t, project)
				if got := config.Providers.Families(); !slices.Equal(got, test.expected) {
					t.Fatalf("config provider order = %v, want %v", got, test.expected)
				}
			})
		}
	})

	t.Run("auto discovery requires zcode and agy while ignoring ambient kimi", func(t *testing.T) {
		installed, err := user.Current()
		if err != nil || installed == nil {
			t.Fatalf("current native account unavailable: %#v %v", installed, err)
		}
		overrideDirectory := canonicalTestTempDir(t)
		emptyPATH := canonicalTestTempDir(t)
		paths := map[string]string{
			"kimi":     filepath.Join(emptyPATH, "kimi"),
			"node":     filepath.Join(overrideDirectory, "node-override"),
			"launcher": filepath.Join(overrideDirectory, "zcode-launcher.cjs"),
			"agy":      filepath.Join(overrideDirectory, "agy-override"),
		}
		for _, path := range []string{paths["kimi"], paths["node"], paths["agy"]} {
			mustWriteTestFile(t, path, []byte("#!/bin/sh\nexit 0\n"))
			if err := os.Chmod(path, 0o700); err != nil {
				t.Fatal(err)
			}
		}
		mustWriteTestFile(t, paths["launcher"], []byte("module.exports = {};\n"))
		environment := isolatedMulgaeEnvWith(t, installed.HomeDir, emptyPATH)
		for _, test := range []struct {
			name       string
			arguments  []string
			shouldPass bool
			candidates []string
		}{
			{name: "neither", candidates: []string{}},
			{name: "zcode only", arguments: []string{"--zcode-node-executable", paths["node"], "--zcode-launcher", paths["launcher"]}, candidates: []string{"zcode"}},
			{name: "agy only", arguments: []string{"--agy-executable", paths["agy"]}, candidates: []string{"agy"}},
			{name: "zcode and agy", arguments: []string{"--zcode-node-executable", paths["node"], "--zcode-launcher", paths["launcher"], "--agy-executable", paths["agy"], "--agy-permission-mode", "safe", "--native-home", installed.HomeDir}, shouldPass: true, candidates: []string{"zcode", "agy"}},
		} {
			for _, format := range []string{"human", "json"} {
				t.Run(fmt.Sprintf("%s_%s", test.name, format), func(t *testing.T) {
					project := canonicalTestTempDir(t)
					initializeReviewGitRepository(t, project)
					arguments := []string{"init", "--providers", "auto", "--name", "auto-project"}
					arguments = append(arguments, test.arguments...)
					if format == "json" {
						arguments = append(arguments, "--output", "json")
					}
					result := runMulgaeBinaryWithEnv(t, binary, project, environment, arguments...)
					if !test.shouldPass {
						if result.exitCode != 4 || len(result.stderr) != 0 || len(result.stdout) == 0 {
							t.Fatalf("auto %s = exit %d stdout %q stderr %q", test.name, result.exitCode, result.stdout, result.stderr)
						}
						if _, err := os.Lstat(filepath.Join(project, ".mulgae")); !errors.Is(err, os.ErrNotExist) {
							t.Fatalf("auto %s mutated project: %v", test.name, err)
						}
						return
					}
					if result.exitCode != 0 || len(result.stderr) != 0 || len(result.stdout) == 0 {
						t.Fatalf("auto %s = exit %d stdout %q stderr %q", test.name, result.exitCode, result.stdout, result.stderr)
					}
					config := readE2EConfig(t, project)
					if !slices.Equal(config.Providers.Families(), test.candidates) {
						t.Fatalf("auto config families = %v, want %v", config.Providers.Families(), test.candidates)
					}
					if config.Roles.Logic.PrimaryProvider != "zcode" {
						t.Fatalf("auto logic assignment = %#v", config.Roles.Logic)
					}
					if format == "json" {
						var envelope struct {
							Request struct {
								Selection struct {
									Mode string `json:"mode"`
								} `json:"selection"`
							} `json:"request"`
							Result struct {
								Candidates []string `json:"candidate_provider_ids"`
								Configured []string `json:"configured_provider_ids"`
							} `json:"result"`
						}
						if err := json.Unmarshal(result.stdout, &envelope); err != nil || envelope.Request.Selection.Mode != "auto" || !slices.Equal(envelope.Result.Candidates, test.candidates) || !slices.Equal(envelope.Result.Configured, test.candidates) {
							t.Fatalf("auto JSON projection = %#v err=%v", envelope, err)
						}
					}
				})
			}
		}
	})

	t.Run("agy omission selects headless default while safe remains explicit", func(t *testing.T) {
		installed, err := user.Current()
		if err != nil || installed == nil {
			t.Fatalf("current native account unavailable: %#v %v", installed, err)
		}
		providerDirectory := canonicalTestTempDir(t)
		agy := filepath.Join(providerDirectory, "agy")
		mustWriteTestFile(t, agy, []byte("#!/bin/sh\nexit 0\n"))
		if err := os.Chmod(agy, 0o700); err != nil {
			t.Fatal(err)
		}
		environment := isolatedMulgaeEnvWith(t, installed.HomeDir, providerDirectory)
		projects := []string{canonicalTestTempDir(t), canonicalTestTempDir(t), canonicalTestTempDir(t)}
		for _, project := range projects {
			initializeReviewGitRepository(t, project)
		}
		base := []string{"init", "--name", "headless-project", "--providers", "agy", "--agy-executable", agy, "--output", "json"}
		omitted := runMulgaeBinaryWithEnv(t, binary, projects[0], environment, base...)
		explicitHeadlessArguments := append(append([]string(nil), base...), "--agy-permission-mode", "dangerously-skip-permissions")
		explicitHeadless := runMulgaeBinaryWithEnv(t, binary, projects[1], environment, explicitHeadlessArguments...)
		safeArguments := append(append([]string(nil), base...), "--agy-permission-mode", "safe")
		safe := runMulgaeBinaryWithEnv(t, binary, projects[2], environment, safeArguments...)
		if omitted.exitCode != 0 || explicitHeadless.exitCode != 0 || safe.exitCode != 0 {
			t.Fatalf("AGY init exits = omitted %d explicit-headless %d safe %d", omitted.exitCode, explicitHeadless.exitCode, safe.exitCode)
		}
		omittedConfig, err := os.ReadFile(filepath.Join(projects[0], ".mulgae", "config.yaml"))
		if err != nil {
			t.Fatal(err)
		}
		explicitHeadlessConfig, err := os.ReadFile(filepath.Join(projects[1], ".mulgae", "config.yaml"))
		if err != nil {
			t.Fatal(err)
		}
		safeConfig, err := os.ReadFile(filepath.Join(projects[2], ".mulgae", "config.yaml"))
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(omittedConfig, []byte("permission_mode:")) ||
			!bytes.Contains(explicitHeadlessConfig, []byte(`permission_mode: "dangerously-skip-permissions"`)) ||
			!bytes.Contains(safeConfig, []byte(`permission_mode: "safe"`)) {
			t.Fatalf("AGY canonical modes = omitted:\n%s\nexplicit headless:\n%s\nsafe:\n%s", omittedConfig, explicitHeadlessConfig, safeConfig)
		}
		repeated := runMulgaeBinaryWithEnv(t, binary, projects[2], environment, safeArguments...)
		if repeated.exitCode != 2 || len(repeated.stderr) != 0 {
			t.Fatalf("repeat init = exit %d stdout %q stderr %q", repeated.exitCode, repeated.stdout, repeated.stderr)
		}
		after, err := os.ReadFile(filepath.Join(projects[2], ".mulgae", "config.yaml"))
		if err != nil || !bytes.Equal(after, safeConfig) {
			t.Fatalf("repeat init changed config: %v", err)
		}
	})

	t.Run("closed stdout preserves committed init", func(t *testing.T) {
		installed, err := user.Current()
		if err != nil || installed == nil {
			t.Fatalf("current native account unavailable: %#v %v", installed, err)
		}
		project := canonicalTestTempDir(t)
		initializeReviewGitRepository(t, project)
		providerDirectory := canonicalTestTempDir(t)
		agy := filepath.Join(providerDirectory, "agy")
		mustWriteTestFile(t, agy, []byte("#!/bin/sh\nexit 0\n"))
		if err := os.Chmod(agy, 0o700); err != nil {
			t.Fatal(err)
		}
		readPipe, writePipe, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		if err := readPipe.Close(); err != nil {
			t.Fatal(err)
		}
		command := exec.Command(binary, "init", "--providers", "agy", "--agy-executable", agy, "--output", "json")
		command.Dir = project
		command.Env = isolatedMulgaeEnvWith(t, installed.HomeDir, providerDirectory)
		command.Stdout = writePipe
		var stderr bytes.Buffer
		command.Stderr = &stderr
		runErr := command.Run()
		_ = writePipe.Close()
		var exitError *exec.ExitError
		if !errors.As(runErr, &exitError) || exitError.ExitCode() != 7 {
			t.Fatalf("closed stdout init = %v stderr %q", runErr, stderr.String())
		}
		if stderr.String() != "mulgae: init committed .mulgae/config.yaml; result delivery failed\n" {
			t.Fatalf("closed stdout stderr = %q", stderr.String())
		}
		if _, err := os.Stat(filepath.Join(project, ".mulgae", "config.yaml")); err != nil {
			t.Fatalf("committed config missing after delivery failure: %v", err)
		}
		localInfo, err := os.Stat(filepath.Join(project, ".mulgae", "local.yaml"))
		if err != nil || localInfo.Mode().Perm() != 0o600 {
			t.Fatalf("committed local config = %v, %v", localInfo, err)
		}
	})

	t.Run("command census", func(t *testing.T) {
		const runID = "r_019f596a-cf80-7c67-b265-f37053d51ccf"
		const attemptID = "a_019f596a-cf80-7c67-b265-f37053d51ccf"
		cases := []struct {
			command string
			argv    []string
			exit    int
		}{
			{"init", []string{"init"}, 4},
			{"doctor", []string{"doctor"}, 4},
			{"review", []string{"review", "--dirty", "--output", "json"}, 2},
			{"followup", []string{"followup", "--run", runID, "--finding", "F001", "--dirty"}, 2},
			{"delta", []string{"delta", "--since-run", runID, "--dirty", "--roles", "logic"}, 2},
			{"rerun", []string{"rerun", "--run", runID, "--attempt", attemptID}, 2},
			{"status", []string{"status", "--run", runID}, 7},
			{"report", []string{"report", "--run", runID, "--output-path", "report.md"}, 7},
			{"findings", []string{"findings", "--run", runID, "--severity", "low"}, 7},
			{"excerpt", []string{"excerpt", "--run", runID, "--finding", "F001", "--current-target-sha256", "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}, 7},
			{"providers", []string{"providers", "--include-unverified"}, 4},
			{"heartbeat", []string{"heartbeat", "--provider", "agy"}, 2},
			{"roles", []string{"roles"}, 0},
			{"config", []string{"config"}, 2},
			{"schema", []string{"schema", "list"}, 0},
			{"clean", []string{"clean", "--all", "--dry-run"}, 7},
			{"export", []string{"export", "--run", runID, "--output-path", "review.zip"}, 7},
			{"help", []string{"help"}, 0},
		}
		if got, want := len(cases), 18; got != want {
			t.Fatalf("documented command census = %d, want %d", got, want)
		}
		specs := cli.CommandSpecs()
		if got, want := len(specs), len(cases); got != want {
			t.Fatalf("canonical command registry count = %d, want %d", got, want)
		}
		for index, spec := range specs {
			if got, want := string(spec.Command()), cases[index].command; got != want {
				t.Fatalf("canonical command registry[%d] = %q, want %q", index, got, want)
			}
		}
		seen := make(map[string]bool, len(cases))
		for _, test := range cases {
			t.Run(test.command, func(t *testing.T) {
				if seen[test.command] {
					t.Fatalf("duplicate command %q", test.command)
				}
				seen[test.command] = true
				got := runMulgaeBinary(t, binary, t.TempDir(), test.argv...)
				if got.exitCode != test.exit {
					t.Fatalf("%s exit = %d, want %d; stdout %q stderr %q", test.command, got.exitCode, test.exit, got.stdout, got.stderr)
				}
			})
		}
	})

	t.Run("usage streams", func(t *testing.T) {
		for _, argv := range [][]string{
			{"not-a-command"},
			{"prompt", "--run", "r_019f596a-cf80-7c67-b265-f37053d51ccf", "--attempt", "a_019f596a-cf80-7c67-b265-f37053d51ccf"},
			{"review", "--diff"},
			{"review", "--dirty", "--ci"},
		} {
			got := runMulgaeBinary(t, binary, t.TempDir(), argv...)
			if got.exitCode != 2 || len(got.stdout) != 0 || !bytes.Equal(got.stderr, []byte("mulgae: invalid command usage\nhint: run mulgae help workflows\n")) {
				t.Fatalf("usage %q = exit %d stdout %q stderr %q", argv, got.exitCode, got.stdout, got.stderr)
			}
		}
	})

	t.Run("schema list formats", func(t *testing.T) {
		human := runMulgaeBinary(t, binary, t.TempDir(), "schema", "list")
		if human.exitCode != 0 || len(human.stdout) == 0 || len(human.stderr) != 0 {
			t.Fatalf("schema list human = exit %d stdout %q stderr %q", human.exitCode, human.stdout, human.stderr)
		}
		json := runMulgaeBinary(t, binary, t.TempDir(), "schema", "list", "--output", "json")
		if json.exitCode != 2 || len(json.stdout) != 0 || !bytes.Equal(json.stderr, []byte("mulgae: invalid command usage\nhint: run mulgae help workflows\n")) {
			t.Fatalf("schema list JSON = exit %d stdout %q stderr %q", json.exitCode, json.stdout, json.stderr)
		}
	})

	t.Run("authority absent envelopes", func(t *testing.T) {
		cases := []struct {
			name       string
			argv       []string
			exit       int
			check      func(*testing.T, commandEnvelope)
			nullFields []string
		}{
			{
				name:       "review",
				argv:       []string{"review", "--dirty", "--output", "json"},
				exit:       2,
				nullFields: []string{"session_id", "run_id", "run_manifest_uri", "review_artifact_uri"},
				check: func(t *testing.T, envelope commandEnvelope) {
					if envelope.Command != "review" || envelope.Result.Kind != "review_started" ||
						envelope.Result.SessionID != nil || envelope.Result.RunID != nil ||
						envelope.Result.RunManifestURI != nil || envelope.Result.ReviewArtifactURI != nil ||
						envelope.Exit.Code != 2 || envelope.Exit.Kind != "usage" {
						t.Fatalf("review authority-absent envelope = %#v", envelope)
					}
				},
			},
		}
		for _, test := range cases {
			t.Run(test.name, func(t *testing.T) {
				got := runMulgaeBinary(t, binary, t.TempDir(), test.argv...)
				if got.exitCode != test.exit || len(got.stderr) != 0 {
					t.Fatalf("%s = exit %d stdout %q stderr %q", test.name, got.exitCode, got.stdout, got.stderr)
				}
				var envelope commandEnvelope
				if err := json.Unmarshal(got.stdout, &envelope); err != nil {
					t.Fatalf("decode %s envelope: %v", test.name, err)
				}
				var raw struct {
					Result map[string]json.RawMessage `json:"result"`
				}
				if err := json.Unmarshal(got.stdout, &raw); err != nil {
					t.Fatalf("decode %s result: %v", test.name, err)
				}
				assertNullResultFields(t, raw.Result, test.nullFields)
				test.check(t, envelope)
			})
		}
	})
}

// Unbound capability evidence is an operational qualification rejection:
// exit 4 readiness, retryable, one family probe, and no publication artifacts.
func TestIntegrationMulgaeProductionReviewSubprocessKimiQualificationNonAdmission(t *testing.T) {
	root := repositoryRoot(t)
	binary := buildMulgaeBinary(t, root)
	project := canonicalTestTempDir(t)
	initializeReviewGitRepository(t, project)

	home := canonicalTestTempDir(t)
	seedKimiCredentials(t, home)
	providerDirectory := canonicalTestTempDir(t)
	logPath := filepath.Join(canonicalTestTempDir(t), "kimi-observations.jsonl")
	buildFakeKimi(t, root, filepath.Join(providerDirectory, "kimi"), logPath)
	environment := isolatedMulgaeEnvWith(t, home, providerDirectory)
	initialized := runMulgaeBinaryWithEnv(t, binary, project, environment,
		"init", "--providers", "kimi", "--roles", "security", "--kimi-executable", filepath.Join(providerDirectory, "kimi"), "--kimi-data-home", filepath.Join(home, ".kimi-code"))
	if initialized.exitCode != 0 {
		t.Fatalf("initialize Kimi local config: exit=%d stdout=%q stderr=%q", initialized.exitCode, initialized.stdout, initialized.stderr)
	}

	review := runMulgaeBinaryWithEnv(t, binary, project, environment,
		"review", "--dirty", "--objective", "@roadmap.md review the changed behavior without rewriting this objective", "--roles", "logic,security", "--output", "json")
	if review.exitCode != 4 || len(review.stderr) != 0 {
		t.Fatalf("Kimi qualification non-admission = exit %d stdout %q stderr %q", review.exitCode, review.stdout, review.stderr)
	}
	var envelope commandEnvelope
	if err := json.Unmarshal(review.stdout, &envelope); err != nil {
		t.Fatalf("decode Kimi qualification envelope: %v", err)
	}
	if envelope.Command != "review" || envelope.Exit.Code != 4 || envelope.Exit.Kind != "readiness" ||
		envelope.Result.Kind != "review_started" || envelope.Result.SessionID == nil ||
		envelope.Result.RunID == nil || envelope.Result.RunManifestURI != nil || envelope.Result.ReviewArtifactURI != nil ||
		len(envelope.Reasons) != 1 || envelope.Reasons[0].Category != "readiness" || envelope.Reasons[0].ArtifactURI == nil ||
		envelope.Reasons[0].Code != "provider_qualification_failed" || !envelope.Reasons[0].Retryable {
		t.Fatalf("Kimi qualification envelope = %#v", envelope)
	}
	if _, err := domain.ParseSessionID(*envelope.Result.SessionID); err != nil {
		t.Fatalf("Kimi qualification session ID = %q: %v", *envelope.Result.SessionID, err)
	}
	if _, err := domain.ParseRunID(*envelope.Result.RunID); err != nil {
		t.Fatalf("Kimi qualification run ID = %q: %v", *envelope.Result.RunID, err)
	}
	entries, err := os.ReadDir(filepath.Join(project, ".mulgae"))
	if err != nil {
		t.Fatalf("read Kimi qualification artifact directory: %v", err)
	}
	if len(entries) != 3 || entries[0].Name() != "config.yaml" || entries[1].Name() != "diagnostics" || !entries[1].IsDir() || entries[2].Name() != "local.yaml" {
		t.Fatalf("Kimi qualification rejection created unexpected artifacts: %v", entries)
	}
	diagnosticRuns, err := filepath.Glob(filepath.Join(project, ".mulgae", "diagnostics", "s_*", "r_*"))
	if err != nil || len(diagnosticRuns) != 1 {
		t.Fatalf("Kimi qualification diagnostics = %v, %v", diagnosticRuns, err)
	}
	wantDiagnosticURI, err := filepath.Rel(project, diagnosticRuns[0])
	if err != nil || filepath.ToSlash(wantDiagnosticURI) != *envelope.Reasons[0].ArtifactURI {
		t.Fatalf("Kimi diagnostic URI = %v, want %q (rel err %v)", envelope.Reasons[0].ArtifactURI, filepath.ToSlash(wantDiagnosticURI), err)
	}
	if !strings.Contains(*envelope.Reasons[0].ArtifactURI, "/"+*envelope.Result.SessionID+"/"+*envelope.Result.RunID) {
		t.Fatalf("Kimi diagnostic URI %q does not bind returned identity", *envelope.Reasons[0].ArtifactURI)
	}
	logBytes, err := os.ReadFile(filepath.Join(diagnosticRuns[0], "mulgae-runtime.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(string(logBytes), "\n"), "\n")
	var terminal struct {
		Event domain.RuntimeDiagnosticEventCode `json:"event"`
	}
	if len(lines) == 0 || json.Unmarshal([]byte(lines[len(lines)-1]), &terminal) != nil || terminal.Event != domain.DiagnosticRuntimeClosed {
		t.Fatalf("Kimi qualification diagnostics were not finalized: %q", logBytes)
	}
	observations := readFakeKimiObservations(t, logPath)
	if len(observations) != 1 {
		t.Fatalf("Kimi qualification launch count = %d, want 1 family probe: %#v", len(observations), observations)
	}
	observation := observations[0]
	if !strings.Contains(observation.Prompt, "Prove readiness by returning exactly one JSON object and nothing else.") {
		t.Fatalf("Kimi qualification prompt missing readiness binding: %#v", observation)
	}
	if !strings.Contains(observation.Prompt, "role=logic") && !strings.Contains(observation.Prompt, "role must be logic") {
		t.Fatalf("Kimi family qualification did not probe base role: %#v", observation)
	}
}

func TestIntegrationMulgaeProductionReviewSubprocessAGY(t *testing.T) {
	root := repositoryRoot(t)
	binary := buildMulgaeBinary(t, root)
	project := canonicalTestTempDir(t)
	initializeReviewGitRepository(t, project)
	mustWriteTestFile(t, filepath.Join(project, "security-fixtures.txt"), []byte(strings.Join([]string{
		"changePassword: vi.fn()",
		"Authorization: Bearer abcdefghijklmnop",
		"api_key=placeholder-api-key",
		"-----BEGIN RSA PRIVATE KEY-----",
		"placeholder",
		"-----END RSA PRIVATE KEY-----",
	}, "\n")+"\n"))
	runTestCommand(t, project, "git", "add", "security-fixtures.txt")

	installedUser, err := user.Current()
	if err != nil || installedUser == nil || !filepath.IsAbs(installedUser.HomeDir) || filepath.Clean(installedUser.HomeDir) != installedUser.HomeDir {
		t.Fatalf("current native home unavailable: user=%#v err=%v", installedUser, err)
	}
	uid, err := strconv.ParseUint(installedUser.Uid, 10, 32)
	if err != nil || int(uid) != os.Geteuid() {
		t.Fatalf("current native user identity is not effective UID: uid=%q euid=%d err=%v", installedUser.Uid, os.Geteuid(), err)
	}

	providerDirectory := canonicalTestTempDir(t)
	logPath := filepath.Join(canonicalTestTempDir(t), "agy-observations.jsonl")
	const credentialLikeSummary = "Reviewed changePassword: vi.fn() with Authorization: Bearer abcdefghijklmnop and password=development-only fixtures."
	credentialLikeOutput := fmt.Sprintf(
		`{"schema_version":"mulgae-provider-review-output.v1","summary":"One informational fixture finding.","completeness":"complete","limitations":[],"findings":[{"severity":"info","title":"Credential-like fixture remains reviewable","description":%q,"evidence":[{"current":{"path":"security-fixtures.txt","side":"index","line_start":2,"line_end":2,"quote":"Authorization: Bearer abcdefghijklmnop\n"}}],"recommendation":%q,"confidence":"high"}]}`,
		credentialLikeSummary, credentialLikeSummary,
	)
	buildFakeAGYWithReviewOutput(t, root, filepath.Join(providerDirectory, "agy"), logPath, credentialLikeOutput)
	environment := isolatedMulgaeEnvWith(t, installedUser.HomeDir, providerDirectory)
	environment = append(environment, "MULGAE_FAKE_AGY_LOG="+logPath)
	initialized := runMulgaeBinaryWithEnv(t, binary, project, environment,
		"init", "--providers", "agy", "--roles", "security", "--agy-executable", filepath.Join(providerDirectory, "agy"))
	if initialized.exitCode != 0 {
		t.Fatalf("initialize AGY local config: exit=%d stdout=%q stderr=%q", initialized.exitCode, initialized.stdout, initialized.stderr)
	}
	configBytes, err := os.ReadFile(filepath.Join(project, ".mulgae", "config.yaml"))
	if err != nil || bytes.Contains(configBytes, []byte("permission_mode:")) {
		t.Fatalf("default AGY config should omit permission mode: err=%v\n%s", err, configBytes)
	}

	const objective = "@roadmap.md review the changed behavior without rewriting this objective"
	review := runMulgaeBinaryWithEnv(t, binary, project, environment,
		"review", "--stage", "--objective", objective, "--roles", "logic,security", "--output", "json")
	if review.exitCode != 0 || len(review.stderr) != 0 {
		var failed commandEnvelope
		if err := json.Unmarshal(review.stdout, &failed); err == nil {
			t.Logf("AGY production review reasons: %#v", failed.Reasons)
		}
		observations := readFakeAGYObservations(t, logPath)
		argv := make([][]string, 0, len(observations))
		for _, observation := range observations {
			argv = append(argv, observation.Argv)
		}
		if diagnosticRuns, _ := filepath.Glob(filepath.Join(project, ".mulgae", "diagnostics", "s_*", "r_*")); len(diagnosticRuns) == 1 {
			if diagnosticLog, readErr := os.ReadFile(filepath.Join(diagnosticRuns[0], "mulgae-runtime.jsonl")); readErr == nil {
				t.Logf("AGY runtime diagnostics:\n%s", diagnosticLog)
			}
		}
		t.Fatalf("AGY production review failed: exit=%d launches=%d argv=%v stdout=%q stderr=%q", review.exitCode, len(observations), argv, review.stdout, review.stderr)
	}
	var reviewEnvelope commandEnvelope
	if err := json.Unmarshal(review.stdout, &reviewEnvelope); err != nil {
		t.Fatalf("decode AGY review envelope: %v", err)
	}
	if reviewEnvelope.Result.Kind != "review_started" ||
		reviewEnvelope.Exit.Code != 0 || reviewEnvelope.Exit.Kind != "success" ||
		reviewEnvelope.Result.SessionID == nil || reviewEnvelope.Result.RunID == nil ||
		reviewEnvelope.Result.RunManifestURI == nil || reviewEnvelope.Result.ReviewArtifactURI == nil {
		t.Fatalf("AGY review did not publish a successful P2 result: %#v", reviewEnvelope)
	}
	for _, uri := range []string{*reviewEnvelope.Result.RunManifestURI, *reviewEnvelope.Result.ReviewArtifactURI} {
		if !strings.HasPrefix(uri, ".mulgae/") {
			t.Fatalf("published URI %q is not a P2 project URI", uri)
		}
		if _, err := os.Stat(filepath.Join(project, uri)); err != nil {
			t.Fatalf("published URI %q is not reopenable: %v", uri, err)
		}
	}
	finalBytes, err := os.ReadFile(filepath.Join(project, *reviewEnvelope.Result.ReviewArtifactURI))
	if err != nil || !bytes.Contains(finalBytes, []byte(credentialLikeSummary)) {
		t.Fatalf("published final omitted credential-like reviewed evidence: err=%v\n%s", err, finalBytes)
	}
	diagnosticLog, err := os.ReadFile(filepath.Join(project, ".mulgae", "diagnostics", *reviewEnvelope.Result.SessionID, *reviewEnvelope.Result.RunID, "mulgae-runtime.jsonl"))
	if err != nil {
		t.Fatalf("read AGY runtime diagnostics: %v", err)
	}
	wantDiagnosticOrder := []domain.RuntimeDiagnosticEventCode{
		domain.DiagnosticQualificationStarted,
		domain.DiagnosticQualificationCandidateChecked,
		domain.DiagnosticQualificationSucceeded,
		domain.DiagnosticReviewPlanCreated,
		domain.DiagnosticAssignmentResolved,
		domain.DiagnosticAssignmentResolved,
		domain.DiagnosticRunBudgetAccepted,
		domain.DiagnosticRunStarted,
		domain.DiagnosticInvocationPrepared,
		domain.DiagnosticProcessStarted,
		domain.DiagnosticOutputParsed,
		domain.DiagnosticValidationSucceeded,
		domain.DiagnosticReductionCompleted,
		domain.DiagnosticNamespaceDrainStarted,
		domain.DiagnosticNamespaceDrained,
		domain.DiagnosticWorkspaceCleanupStarted,
		domain.DiagnosticWorkspaceCleanupCompleted,
		domain.DiagnosticPublicationPreparationStarted,
		domain.DiagnosticPublicationStaged,
		domain.DiagnosticPublicationInstalled,
		domain.DiagnosticPublicationCommitted,
		domain.DiagnosticRuntimeClosed,
	}
	diagnosticPosition := 0
	var previousSequence uint64
	for _, line := range strings.Split(strings.TrimSuffix(string(diagnosticLog), "\n"), "\n") {
		var event struct {
			Sequence uint64                            `json:"seq"`
			Code     domain.RuntimeDiagnosticEventCode `json:"event"`
		}
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatalf("decode AGY runtime diagnostic: %v", err)
		}
		if diagnosticPosition < len(wantDiagnosticOrder) && event.Code == wantDiagnosticOrder[diagnosticPosition] {
			diagnosticPosition++
		}
		if event.Sequence <= previousSequence {
			t.Fatalf("AGY diagnostic sequence %d followed %d", event.Sequence, previousSequence)
		}
		previousSequence = event.Sequence
	}
	if diagnosticPosition != len(wantDiagnosticOrder) {
		t.Fatalf("AGY runtime diagnostic order missing %v:\n%s", wantDiagnosticOrder[diagnosticPosition:], diagnosticLog)
	}
	statusBytes, err := os.ReadFile(filepath.Join(project, ".mulgae", "diagnostics", *reviewEnvelope.Result.SessionID, *reviewEnvelope.Result.RunID, "status.json"))
	if err != nil {
		t.Fatalf("read AGY runtime diagnostic status: %v", err)
	}
	var diagnosticStatus struct {
		State             domain.RunState `json:"state"`
		RolePathTotal     int             `json:"role_path_total"`
		RolePathCompleted int             `json:"role_path_completed"`
		RolePathFailed    int             `json:"role_path_failed"`
		P2URI             string          `json:"p2_uri"`
	}
	if err := json.Unmarshal(statusBytes, &diagnosticStatus); err != nil {
		t.Fatalf("decode AGY runtime diagnostic status: %v", err)
	}
	if diagnosticStatus.State != domain.RunCompleted || diagnosticStatus.RolePathTotal != 2 || diagnosticStatus.RolePathCompleted != 2 || diagnosticStatus.RolePathFailed != 0 || diagnosticStatus.P2URI != *reviewEnvelope.Result.RunManifestURI {
		t.Fatalf("AGY runtime diagnostic status = %#v, want completed 2/2 role paths linked to %q", diagnosticStatus, *reviewEnvelope.Result.RunManifestURI)
	}
	rawStreams, err := filepath.Glob(filepath.Join(project, ".mulgae", "diagnostics", *reviewEnvelope.Result.SessionID, *reviewEnvelope.Result.RunID, "attempts", "a_*", "invocations", "*", "*.raw"))
	if err != nil || len(rawStreams) != 0 {
		t.Fatalf("credential-like AGY raw diagnostics should be dropped without blocking publication: %v, %v", rawStreams, err)
	}

	status := runMulgaeBinaryWithEnv(t, binary, project, environment,
		"status", "--run", *reviewEnvelope.Result.RunID, "--output", "json")
	if status.exitCode != 0 || len(status.stderr) != 0 {
		t.Fatalf("published status = exit %d stdout %q stderr %q", status.exitCode, status.stdout, status.stderr)
	}
	var statusEnvelope struct {
		Exit struct {
			Code int    `json:"code"`
			Kind string `json:"kind"`
		} `json:"exit"`
		Result struct {
			RunID             string  `json:"run_id"`
			PublicationStatus string  `json:"publication_status"`
			FinalArtifactURI  *string `json:"final_artifact_uri"`
		} `json:"result"`
	}
	if err := json.Unmarshal(status.stdout, &statusEnvelope); err != nil {
		t.Fatalf("decode status envelope: %v", err)
	}
	if statusEnvelope.Exit.Code != 0 || statusEnvelope.Exit.Kind != "success" ||
		statusEnvelope.Result.RunID != *reviewEnvelope.Result.RunID ||
		statusEnvelope.Result.PublicationStatus != "committed" ||
		statusEnvelope.Result.FinalArtifactURI == nil ||
		!strings.HasPrefix(*statusEnvelope.Result.FinalArtifactURI, ".mulgae/") {
		t.Fatalf("published status is not a successful committed P2 reopening: %#v", statusEnvelope)
	}
	if _, err := os.Stat(filepath.Join(project, *statusEnvelope.Result.FinalArtifactURI)); err != nil {
		t.Fatalf("reopened P2 final artifact %q is unavailable: %v", *statusEnvelope.Result.FinalArtifactURI, err)
	}

	observations := readFakeAGYObservations(t, logPath)
	versionChecks := make([]fakeAGYObservation, 0, 2)
	qualificationRuns := make([]fakeAGYObservation, 0, 2)
	reviewRuns := make([]fakeAGYObservation, 0, 2)
	for _, observation := range observations {
		switch {
		case len(observation.Argv) == 1 && observation.Argv[0] == "--version":
			versionChecks = append(versionChecks, observation)
		case observation.Prompt == "@roadmap.md":
			qualificationRuns = append(qualificationRuns, observation)
		default:
			reviewRuns = append(reviewRuns, observation)
		}
	}
	// Version observation is diagnostic-only and may time out before the fake
	// process starts on a heavily instrumented race run. Qualification and role
	// execution are the authoritative launches and remain exact.
	// AGY control evidence is instance-bound, so each configured AGY role route
	// performs its own qualification probe within the command.
	if len(versionChecks) > 2 || len(qualificationRuns) != 2 || len(reviewRuns) != 2 {
		argv := make([][]string, 0, len(observations))
		for _, observation := range observations {
			argv = append(argv, observation.Argv)
		}
		t.Fatalf("AGY launches = versions:%d qualifications:%d reviews:%d argv=%v, want at most two diagnostic version checks, two instance qualifications, and two review launches", len(versionChecks), len(qualificationRuns), len(reviewRuns), argv)
	}
	for _, observation := range observations {
		if observation.Home != installedUser.HomeDir || observation.CWD == "" {
			t.Fatalf("AGY native-home/CWD contract = %#v", observation)
		}
		if len(observation.Argv) == 1 && observation.Argv[0] == "--version" {
			continue
		}
		for _, value := range []string{observation.XDGConfigHome, observation.XDGCacheHome, observation.TempDir, observation.Scratch} {
			if value == "" || value == installedUser.HomeDir || strings.HasPrefix(value, installedUser.HomeDir+string(filepath.Separator)) {
				t.Fatalf("AGY disposable environment escaped native home: %#v", observation)
			}
		}
	}
	for _, observation := range qualificationRuns {
		if observation.CWD != observation.Snapshot || observation.Prompt != "@roadmap.md" {
			t.Fatalf("AGY qualification snapshot/control contract = %#v", observation)
		}
	}
	for _, observation := range reviewRuns {
		if observation.CWD != observation.Snapshot || !strings.Contains(observation.Prompt, objective) {
			t.Fatalf("AGY review snapshot/control contract = %#v", observation)
		}
	}
}

func TestIntegrationMulgaeProductionSixRoleReviewPublishesAndReopens(t *testing.T) {
	root := repositoryRoot(t)
	binary := buildMulgaeBinary(t, root)
	project := canonicalTestTempDir(t)
	initializeReviewGitRepository(t, project)

	installedUser, err := user.Current()
	if err != nil || installedUser == nil || !filepath.IsAbs(installedUser.HomeDir) {
		t.Fatalf("current native home unavailable: user=%#v err=%v", installedUser, err)
	}
	providerDirectory := canonicalTestTempDir(t)
	logDirectory := canonicalTestTempDir(t)
	zcodeNode := filepath.Join(providerDirectory, "node")
	zcodeLauncher := filepath.Join(providerDirectory, "zcode.cjs")
	agyExecutable := filepath.Join(providerDirectory, "agy")
	buildFakeZCode(t, root, zcodeNode, zcodeLauncher, filepath.Join(logDirectory, "zcode.jsonl"), "success")
	buildFakeAGY(t, root, agyExecutable, filepath.Join(logDirectory, "agy.jsonl"))
	environment := isolatedMulgaeEnvWith(t, installedUser.HomeDir, providerDirectory)

	initialized := runMulgaeBinaryWithEnv(t, binary, project, environment,
		"init", "--providers", "zcode,agy",
		"--roles", "logic,security,maintainability,product,documentation,testing",
		"--zcode-node-executable", zcodeNode, "--zcode-launcher", zcodeLauncher,
		"--agy-executable", agyExecutable)
	if initialized.exitCode != 0 {
		t.Fatalf("initialize six-role config: exit=%d stdout=%q stderr=%q", initialized.exitCode, initialized.stdout, initialized.stderr)
	}

	review := runMulgaeBinaryWithEnv(t, binary, project, environment,
		"review", "--dirty",
		"--roles", "logic,security,maintainability,product,documentation,testing",
		"--objective", "Review the changed behavior and report only captured-target findings.",
		"--output", "json")
	if review.exitCode != 0 || len(review.stderr) != 0 {
		t.Fatalf("six-role production review: exit=%d stdout=%q stderr=%q", review.exitCode, review.stdout, review.stderr)
	}
	var envelope commandEnvelope
	if err := json.Unmarshal(review.stdout, &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Result.SessionID == nil || envelope.Result.RunID == nil ||
		envelope.Result.RunManifestURI == nil || envelope.Result.ReviewArtifactURI == nil {
		t.Fatalf("six-role publication omitted identity or artifacts: %#v", envelope)
	}
	for _, uri := range []*string{envelope.Result.RunManifestURI, envelope.Result.ReviewArtifactURI} {
		if _, err := os.Stat(filepath.Join(project, *uri)); err != nil {
			t.Fatalf("six-role publication artifact %q is unreadable: %v", *uri, err)
		}
	}
	assertCommandRoleReportInventory(t, project, envelope)
	// Documentation prefers AGY and keeps the stdout transport; every other role
	// runs on ZCode and publishes exactly the body that launch staged. The
	// deliberately different stdout envelope each ZCode launch printed is never
	// accepted.
	wantReports := map[string]publishedRoleReport{
		"documentation": {
			transport:        "stdout",
			providerInstance: "agy-documentation",
			content:          fakeAGYDefaultReviewOutput,
		},
	}
	for _, role := range []string{"logic", "security", "maintainability", "product", "testing"} {
		wantReports[role] = publishedRoleReport{
			transport:        "staged_file",
			providerInstance: "zcode-" + role,
			content:          fakeZCodeStagedReport(role),
		}
	}
	assertPublishedRoleReports(t, project, envelope, wantReports)
	stagedLaunches := fakeZCodeReviewObservations(t, filepath.Join(logDirectory, "zcode.jsonl"))
	if len(stagedLaunches) != 5 {
		t.Fatalf("six-role ZCode review launches = %d, want one per ZCode-primary role", len(stagedLaunches))
	}
	destinations := make(map[string]bool, len(stagedLaunches))
	for _, launch := range stagedLaunches {
		if launch.Destination == "" || destinations[launch.Destination] {
			t.Fatalf("six-role staged destinations are not one per launch: %q", launch.Destination)
		}
		destinations[launch.Destination] = true
		if _, err := os.Lstat(launch.Destination); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("staging %q survived the run: %v", launch.Destination, err)
		}
	}
	diagnosticBytes, err := os.ReadFile(filepath.Join(
		project, ".mulgae", "diagnostics", *envelope.Result.SessionID, *envelope.Result.RunID, "status.json",
	))
	if err != nil {
		t.Fatal(err)
	}
	var diagnostic struct {
		State             domain.RunState `json:"state"`
		RolePathTotal     int             `json:"role_path_total"`
		RolePathCompleted int             `json:"role_path_completed"`
		RolePathFailed    int             `json:"role_path_failed"`
		P2URI             string          `json:"p2_uri"`
	}
	if err := json.Unmarshal(diagnosticBytes, &diagnostic); err != nil {
		t.Fatal(err)
	}
	if diagnostic.State != domain.RunCompleted || diagnostic.RolePathTotal != 6 || diagnostic.RolePathCompleted != 6 ||
		diagnostic.RolePathFailed != 0 || diagnostic.P2URI != *envelope.Result.RunManifestURI {
		t.Fatalf("six-role diagnostic status = %#v", diagnostic)
	}

	status := runMulgaeBinaryWithEnv(t, binary, project, environment,
		"status", "--run", *envelope.Result.RunID, "--output", "json")
	if status.exitCode != 0 || len(status.stderr) != 0 {
		t.Fatalf("six-role status: exit=%d stdout=%q stderr=%q", status.exitCode, status.stdout, status.stderr)
	}
	var statusEnvelope commandEnvelope
	if err := json.Unmarshal(status.stdout, &statusEnvelope); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(statusEnvelope.Result.RoleReportURIs, envelope.Result.RoleReportURIs) {
		t.Fatalf("six-role status role_report_uris = %#v, want %#v", statusEnvelope.Result.RoleReportURIs, envelope.Result.RoleReportURIs)
	}
	findings := runMulgaeBinaryWithEnv(t, binary, project, environment,
		"findings", "--run", *envelope.Result.RunID, "--severity", "low", "--output", "json")
	if findings.exitCode != 0 || len(findings.stderr) != 0 {
		t.Fatalf("six-role findings: exit=%d stdout=%q stderr=%q", findings.exitCode, findings.stdout, findings.stderr)
	}
}

func TestIntegrationIndependentProcessesDoNotShareProviderLocks(t *testing.T) {
	root := repositoryRoot(t)
	binary := buildMulgaeBinary(t, root)
	installedUser, err := user.Current()
	if err != nil || installedUser == nil || !filepath.IsAbs(installedUser.HomeDir) {
		t.Fatalf("current native home unavailable: user=%#v err=%v", installedUser, err)
	}
	providerDirectory := canonicalTestTempDir(t)
	barrier := canonicalTestTempDir(t)
	zcodeNode := filepath.Join(providerDirectory, "node")
	zcodeLauncher := filepath.Join(providerDirectory, "zcode.cjs")
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
					environment := sharedMulgaeProcessEnv(t, installedUser.HomeDir, providerDirectory, sharedRuntimeRoot, runtimeRoot.useXDG)

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
							"--zcode-node-executable", zcodeNode, "--zcode-launcher", zcodeLauncher)
						if initialized.exitCode != 0 {
							t.Fatalf("initialize concurrent review config: exit=%d stdout=%q stderr=%q", initialized.exitCode, initialized.stdout, initialized.stderr)
						}
					}

					ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
					defer cancel()
					arguments := []string{"review", "--diff", "HEAD~1..HEAD", "--roles", "logic", "--objective", "Review the captured change.", "--output", "json"}
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

	installedUser, err := user.Current()
	if err != nil || installedUser == nil || !filepath.IsAbs(installedUser.HomeDir) {
		t.Fatalf("current native home unavailable: user=%#v err=%v", installedUser, err)
	}
	providerDirectory := canonicalTestTempDir(t)
	zcodeLog := filepath.Join(canonicalTestTempDir(t), "zcode.jsonl")
	zcodeNode := filepath.Join(providerDirectory, "node")
	zcodeLauncher := filepath.Join(providerDirectory, "zcode.cjs")
	buildFakeZCode(t, root, zcodeNode, zcodeLauncher, zcodeLog, "success")
	environment := isolatedMulgaeEnvWith(t, installedUser.HomeDir, providerDirectory)
	initialized := runMulgaeBinaryWithEnv(t, binary, project, environment,
		"init", "--providers", "zcode", "--roles", "logic",
		"--zcode-node-executable", zcodeNode, "--zcode-launcher", zcodeLauncher)
	if initialized.exitCode != 0 {
		t.Fatalf("initialize publication-lock config: exit=%d stdout=%q stderr=%q", initialized.exitCode, initialized.stdout, initialized.stderr)
	}

	arguments := []string{"review", "--diff", "HEAD~1..HEAD", "--roles", "logic", "--objective", "Review the captured change.", "--output", "json"}
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
			if readErr == nil && bytes.Contains(data, []byte(`"event":"workspace_cleanup_completed"`)) {
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
	// Workspace cleanup is the final durable event before candidate preparation
	// and publication. Give the process time to enter the held lock's bounded
	// polling loop so this exercises lock-wait cancellation, not an earlier
	// context checkpoint.
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

// ZCode roles deliver their report through the staged file Mulgae granted them
// while the AGY-primary role keeps the stdout transport. The manifest records
// which transport carried each published report.
func TestIntegrationStagedFileTransportPublishesRoleReports(t *testing.T) {
	root := repositoryRoot(t)
	binary := buildMulgaeBinary(t, root)
	project := canonicalTestTempDir(t)
	initializeReviewGitRepository(t, project)

	installedUser, err := user.Current()
	if err != nil || installedUser == nil || !filepath.IsAbs(installedUser.HomeDir) {
		t.Fatalf("current native home unavailable: user=%#v err=%v", installedUser, err)
	}
	pngBytes, err := base64.StdEncoding.DecodeString("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=")
	if err != nil {
		t.Fatal(err)
	}
	mustWriteTestFile(t, filepath.Join(project, "screenshots", "staged.png"), pngBytes)
	runTestCommand(t, project, "git", "add", "review.go", "screenshots/staged.png")

	providerDirectory := canonicalTestTempDir(t)
	logDirectory := canonicalTestTempDir(t)
	zcodeLog := filepath.Join(logDirectory, "zcode.jsonl")
	zcodeNode := filepath.Join(providerDirectory, "node")
	zcodeLauncher := filepath.Join(providerDirectory, "zcode.cjs")
	agyExecutable := filepath.Join(providerDirectory, "agy")
	buildFakeZCode(t, root, zcodeNode, zcodeLauncher, zcodeLog, "success")
	buildFakeAGYWithReviewOutput(t, root, agyExecutable, filepath.Join(logDirectory, "agy.jsonl"), fakeAGYDefaultReviewOutput)
	environment := isolatedMulgaeEnvWith(t, installedUser.HomeDir, providerDirectory)

	initialized := runMulgaeBinaryWithEnv(t, binary, project, environment,
		"init", "--providers", "zcode,agy", "--roles", "logic,security,artist", "--project-kind", "ui",
		"--artist-brief", "roadmap.md", "--artist-design-specs", "screenshots/**/*.png",
		"--zcode-node-executable", zcodeNode, "--zcode-launcher", zcodeLauncher,
		"--agy-executable", agyExecutable)
	if initialized.exitCode != 0 {
		t.Fatalf("initialize staged transport config: exit=%d stdout=%q stderr=%q", initialized.exitCode, initialized.stdout, initialized.stderr)
	}

	review := runMulgaeBinaryWithEnv(t, binary, project, environment,
		"review", "--stage", "--roles", "logic,security,artist", "--output", "json")
	var envelope commandEnvelope
	if err := json.Unmarshal(review.stdout, &envelope); err != nil {
		t.Fatalf("decode staged transport envelope: %v: %q", err, review.stdout)
	}
	if review.exitCode != 0 || len(review.stderr) != 0 || envelope.Exit.Kind != "success" ||
		envelope.Result.RunManifestURI == nil || envelope.Result.ReviewArtifactURI == nil {
		for _, launch := range fakeZCodeReviewObservations(t, zcodeLog) {
			t.Logf("ZCode review launch staged destination = %q", launch.Destination)
		}
		dumpRuntimeDiagnostics(t, project, envelope)
		t.Fatalf("staged transport review = exit %d envelope %#v stderr %q", review.exitCode, envelope, review.stderr)
	}
	assertCommandRoleReportInventory(t, project, envelope)
	assertPublishedRoleReports(t, project, envelope, map[string]publishedRoleReport{
		"logic":    {transport: "staged_file", providerInstance: "zcode-logic", content: fakeZCodeStagedReport("logic")},
		"security": {transport: "staged_file", providerInstance: "zcode-security", content: fakeZCodeStagedReport("security")},
		"artist":   {transport: "stdout", providerInstance: "agy-artist", content: fakeAGYDefaultReviewOutput},
	})

	launches := fakeZCodeReviewObservations(t, zcodeLog)
	if len(launches) != 2 {
		t.Fatalf("staged ZCode review launches = %d, want logic and security: %#v", len(launches), launches)
	}
	destinations := make(map[string]bool, len(launches))
	for _, launch := range launches {
		if launch.Destination == "" || destinations[launch.Destination] {
			t.Fatalf("staged destinations are not one per launch: %#v", launches)
		}
		destinations[launch.Destination] = true
		if !strings.Contains(launch.Prompt, stagedOutputDestinationMarker+"\n"+launch.Destination+"\n") {
			t.Fatalf("staged destination is not stated by the trusted layer: %q", launch.Destination)
		}
		if _, err := os.Lstat(launch.Destination); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("staging %q survived the run: %v", launch.Destination, err)
		}
	}
}

// A staged file the provider never wrote is operationally missing output: the
// role completes on its configured fallback and the run still publishes.
func commandEnvelopeHasReason(envelope commandEnvelope, code string) bool {
	for _, reason := range envelope.Reasons {
		if reason.Code == code {
			return true
		}
	}
	return false
}

// TestIntegrationStagedFileMissingIsAnOperationalRoleFailure proves a missing
// staged output file is classified as an operational invalid-output failure
// rather than a staging violation, and that the role simply fails: Mulgae does
// not move it to the other configured provider.
func TestIntegrationStagedFileMissingIsAnOperationalRoleFailure(t *testing.T) {
	root := repositoryRoot(t)
	binary := buildMulgaeBinary(t, root)
	project := canonicalTestTempDir(t)
	initializeReviewGitRepository(t, project)

	installedUser, err := user.Current()
	if err != nil || installedUser == nil {
		t.Fatalf("current native home unavailable: user=%#v err=%v", installedUser, err)
	}
	providerDirectory := canonicalTestTempDir(t)
	logDirectory := canonicalTestTempDir(t)
	zcodeLog := filepath.Join(logDirectory, "zcode.jsonl")
	agyLog := filepath.Join(logDirectory, "agy.jsonl")
	zcodeNode := filepath.Join(providerDirectory, "node")
	zcodeLauncher := filepath.Join(providerDirectory, "zcode.cjs")
	agyExecutable := filepath.Join(providerDirectory, "agy")
	buildFakeZCodeWithStagedOutput(t, root, zcodeNode, zcodeLauncher, zcodeLog, "success", "none")
	buildFakeAGYWithReviewOutput(t, root, agyExecutable, agyLog, fakeAGYDefaultReviewOutput)
	environment := isolatedMulgaeEnvWith(t, installedUser.HomeDir, providerDirectory)
	environment = append(environment, "MULGAE_FAKE_AGY_LOG="+agyLog)
	initializeOfflineProviders(t, binary, project, environment, "zcode,agy", zcodeNode, zcodeLauncher, agyExecutable)

	review := runMulgaeBinaryWithEnv(t, binary, project, environment,
		"review", "--dirty", "--roles", "security", "--output", "json")
	var envelope commandEnvelope
	if err := json.Unmarshal(review.stdout, &envelope); err != nil {
		t.Fatalf("decode staged failure envelope: %v: %q", err, review.stdout)
	}
	// The role produced no review, so coverage is incomplete. The run still
	// publishes: the operator needs the report to see what failed and why.
	if review.exitCode != int(domain.ExitIncompleteCoverage) || envelope.Result.RunManifestURI == nil ||
		envelope.Result.SessionID == nil || envelope.Result.RunID == nil {
		dumpRuntimeDiagnostics(t, project, envelope)
		t.Fatalf("staged failure review = exit %d envelope %#v stderr %q", review.exitCode, envelope, review.stderr)
	}
	if !commandEnvelopeHasReason(envelope, "provider_output_missing") ||
		!commandEnvelopeHasReason(envelope, "required_role_incomplete") {
		t.Fatalf("staged failure reasons = %#v", envelope.Reasons)
	}

	launches := fakeZCodeReviewObservations(t, zcodeLog)
	if len(launches) != 1 || launches[0].Destination == "" {
		t.Fatalf("staged launches = %#v, want exactly one destination-bound launch", launches)
	}
	// AGY is configured, but security is bound to ZCode. Mulgae must not run the
	// role somewhere else just because its own provider failed.
	if contents, err := os.ReadFile(agyLog); err == nil && bytes.Contains(contents, []byte("security")) {
		t.Fatalf("a failed ZCode role was rerouted to AGY:\n%s", contents)
	}

	log := readRuntimeDiagnosticLog(t, project, *envelope.Result.SessionID, *envelope.Result.RunID)
	if !bytes.Contains(log, []byte(`"cause":"`+string(domain.DiagnosticCauseProviderOutputFileMissing)+`"`)) {
		t.Fatalf("staged failure diagnostics omitted the missing staged file cause:\n%s", log)
	}
	for _, event := range []domain.RuntimeDiagnosticEventCode{
		domain.DiagnosticAttemptFailed, domain.DiagnosticRoleExhausted, domain.DiagnosticRuntimeClosed,
	} {
		if !bytes.Contains(log, []byte(`"event":"`+string(event)+`"`)) {
			t.Fatalf("staged failure diagnostic omitted %s:\n%s", event, log)
		}
	}
	if bytes.Contains(log, []byte(`"cause":"`+string(domain.DiagnosticCauseProviderOutputStagingViolation)+`"`)) {
		t.Fatalf("a missing staged file was classified as a staging violation:\n%s", log)
	}
}

// Staging Mulgae did not authorize is a boundary breach: the role publishes
// nothing and the run fails closed as a security condition.
func TestIntegrationStagedSymlinkFailsClosedAsSecurityViolation(t *testing.T) {
	root := repositoryRoot(t)
	binary := buildMulgaeBinary(t, root)
	installedUser, err := user.Current()
	if err != nil || installedUser == nil {
		t.Fatalf("current native home unavailable: user=%#v err=%v", installedUser, err)
	}

	for _, test := range []struct {
		name     string
		staged   string
		smuggled bool
	}{
		{name: "symbolic link", staged: "symlink", smuggled: true},
		{name: "extra staged entry", staged: "extra"},
	} {
		t.Run(test.name, func(t *testing.T) {
			project := canonicalTestTempDir(t)
			initializeReviewGitRepository(t, project)
			providerDirectory := canonicalTestTempDir(t)
			logDirectory := canonicalTestTempDir(t)
			zcodeLog := filepath.Join(logDirectory, "zcode.jsonl")
			zcodeNode := filepath.Join(providerDirectory, "node")
			zcodeLauncher := filepath.Join(providerDirectory, "zcode.cjs")
			buildFakeZCodeWithStagedOutput(t, root, zcodeNode, zcodeLauncher, zcodeLog, "success", test.staged)
			environment := isolatedMulgaeEnvWith(t, installedUser.HomeDir, providerDirectory)
			initializeOfflineProviders(t, binary, project, environment, "zcode", zcodeNode, zcodeLauncher, "")

			review := runMulgaeBinaryWithEnv(t, binary, project, environment,
				"review", "--dirty", "--roles", "security", "--output", "json")
			var envelope commandEnvelope
			if err := json.Unmarshal(review.stdout, &envelope); err != nil {
				t.Fatalf("decode staging violation envelope: %v: %q", err, review.stdout)
			}
			if review.exitCode != int(app.ExitCodeSecurity) || envelope.Exit.Code != int(app.ExitCodeSecurity) ||
				envelope.Exit.Kind != "security" || len(envelope.Reasons) != 1 ||
				envelope.Reasons[0].Category != "security" || envelope.Reasons[0].Retryable ||
				envelope.Reasons[0].ArtifactURI == nil {
				dumpRuntimeDiagnostics(t, project, envelope)
				t.Fatalf("staging violation review = exit %d envelope %#v stderr %q", review.exitCode, envelope, review.stderr)
			}
			if envelope.Result.RunManifestURI != nil || envelope.Result.ReviewArtifactURI != nil ||
				len(envelope.Result.RoleReportURIs) != 0 {
				t.Fatalf("staging violation published artifacts: %#v", envelope.Result)
			}
			entries, err := os.ReadDir(filepath.Join(project, ".mulgae"))
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 3 || entries[0].Name() != "config.yaml" || entries[1].Name() != "diagnostics" || entries[2].Name() != "local.yaml" {
				t.Fatalf("staging violation created publication artifacts: %v", entries)
			}
			diagnosticRoot := filepath.Join(project, filepath.FromSlash(*envelope.Reasons[0].ArtifactURI))
			log, err := os.ReadFile(filepath.Join(diagnosticRoot, "mulgae-runtime.jsonl"))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Contains(log, []byte(`"cause":"`+string(domain.DiagnosticCauseProviderOutputStagingViolation)+`"`)) {
				t.Fatalf("staging violation diagnostics omitted the staging violation cause:\n%s", log)
			}
			if !bytes.Contains(log, []byte(`"event":"`+string(domain.DiagnosticRuntimeClosed)+`"`)) {
				t.Fatalf("staging violation diagnostics were not finalized:\n%s", log)
			}
			statusBytes, err := os.ReadFile(filepath.Join(diagnosticRoot, "status.json"))
			if err != nil {
				t.Fatal(err)
			}
			var status struct {
				State             domain.RunState `json:"state"`
				RolePathCompleted int             `json:"role_path_completed"`
				RolePathFailed    int             `json:"role_path_failed"`
				P2URI             string          `json:"p2_uri"`
			}
			if err := json.Unmarshal(statusBytes, &status); err != nil {
				t.Fatal(err)
			}
			if status.State == domain.RunCompleted || status.RolePathCompleted != 0 || status.RolePathFailed != 1 || status.P2URI != "" {
				t.Fatalf("staging violation diagnostic status = %#v", status)
			}
			launches := fakeZCodeReviewObservations(t, zcodeLog)
			if len(launches) != 1 || launches[0].Destination == "" {
				t.Fatalf("staging violation launches = %#v, want one destination-bound launch", launches)
			}
			if _, err := os.Lstat(launches[0].Destination); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("violating staging %q survived the run: %v", launches[0].Destination, err)
			}
			if !test.smuggled {
				return
			}
			smuggled := filepath.Join(logDirectory, "smuggled-role-report.md")
			body, err := os.ReadFile(smuggled)
			if err != nil || string(body) != fakeZCodeStagedReport("security") {
				t.Fatalf("linked report outside staging = %q, %v", body, err)
			}
		})
	}
}

func TestIntegrationMulgaeProductionReviewPreflightIsExecutionFreeAndPreservesPNG(t *testing.T) {
	root := repositoryRoot(t)
	binary := buildMulgaeBinary(t, root)
	project := canonicalTestTempDir(t)
	initializeReviewGitRepository(t, project)
	pngBytes, err := base64.StdEncoding.DecodeString("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=")
	if err != nil {
		t.Fatal(err)
	}
	largePNG := make([]byte, 4<<20)
	copy(largePNG, pngBytes)
	for index := 0; index < 8; index++ {
		mustWriteTestFile(t, filepath.Join(project, "screenshots", fmt.Sprintf("provider-view-%02d.png", index)), largePNG)
	}
	runTestCommand(t, project, "git", "add", "screenshots")
	runTestCommand(t, project, "git", "commit", "-m", "Add provider view raster fixtures")
	mustWriteTestFile(t, filepath.Join(project, ".gitignore"), []byte("git-ignored.txt\n"))
	mustWriteTestFile(t, filepath.Join(project, ".mulgaeignore"), []byte("ignored.txt\nignored-untracked.txt\n"))
	mustWriteTestFile(t, filepath.Join(project, "ignored.txt"), []byte("ignored baseline\n"))
	runTestCommand(t, project, "git", "add", ".gitignore", ".mulgaeignore")
	runTestCommand(t, project, "git", "add", "-f", "ignored.txt")
	runTestCommand(t, project, "git", "commit", "-m", "Track capture controls")

	providerDirectory := canonicalTestTempDir(t)
	logDirectory := canonicalTestTempDir(t)
	zcodeLog, agyLog := filepath.Join(logDirectory, "zcode.jsonl"), filepath.Join(logDirectory, "agy.jsonl")
	zcodeNode, zcodeLauncher := filepath.Join(providerDirectory, "node"), filepath.Join(providerDirectory, "zcode.cjs")
	agyExecutable := filepath.Join(providerDirectory, "agy")
	buildFakeZCode(t, root, zcodeNode, zcodeLauncher, zcodeLog, "success")
	buildFakeAGY(t, root, agyExecutable, agyLog)
	home := canonicalTestTempDir(t)
	environment := isolatedMulgaeEnvWith(t, home, providerDirectory)
	initialized := runMulgaeBinaryWithEnv(t, binary, project, environment,
		"init", "--providers", "zcode,agy", "--roles", "logic,security,artist", "--project-kind", "ui",
		"--artist-brief", "roadmap.md", "--artist-design-specs", "screenshots/**/*.png",
		"--zcode-node-executable", zcodeNode, "--zcode-launcher", zcodeLauncher, "--agy-executable", agyExecutable)
	if initialized.exitCode != 0 {
		t.Fatalf("initialize first-project integration config: exit=%d stdout=%q stderr=%q", initialized.exitCode, initialized.stdout, initialized.stderr)
	}

	configPath := filepath.Join(project, ".mulgae", "config.yaml")
	configBytes, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	const defaultZCode = "  zcode: {}\n"
	if !bytes.Contains(configBytes, []byte(defaultZCode)) {
		t.Fatalf("config omits default ZCode policy:\n%s", configBytes)
	}
	configBytes = bytes.Replace(configBytes, []byte(defaultZCode), []byte("  zcode:\n    timeout: \"30m\"\n"), 1)
	mustWriteTestFile(t, configPath, configBytes)

	mustWriteTestFile(t, filepath.Join(project, ".gitignore"), []byte("git-ignored.txt\n# dirty control\n"))
	mustWriteTestFile(t, filepath.Join(project, ".mulgaeignore"), []byte("ignored.txt\nignored-untracked.txt\n# dirty control\n"))
	mustWriteTestFile(t, filepath.Join(project, "ignored.txt"), []byte("ignored dirty\n"))
	mustWriteTestFile(t, filepath.Join(project, "ignored-untracked.txt"), []byte("ignored untracked\n"))
	mustWriteTestFile(t, filepath.Join(project, "included-untracked.txt"), []byte("included untracked\n"))
	beforeDirtyMulgae := snapshotTestTree(t, filepath.Join(project, ".mulgae"))
	dirty := runMulgaeBinaryWithEnv(t, binary, project, environment, "review", "--dirty", "--roles", "logic,security", "--preflight", "--output", "json")
	if dirty.exitCode != 0 || len(dirty.stderr) != 0 {
		t.Fatalf("tracked-control dirty preflight = exit %d stdout=%q stderr=%q", dirty.exitCode, dirty.stdout, dirty.stderr)
	}
	var dirtyEnvelope struct {
		Result struct {
			Kind      string                            `json:"kind"`
			Preflight mulgaeentry.ReviewPreflightResult `json:"preflight"`
		} `json:"result"`
	}
	if err := json.Unmarshal(dirty.stdout, &dirtyEnvelope); err != nil {
		t.Fatal(err)
	}
	if dirtyEnvelope.Result.Kind != "review_preflight" || dirtyEnvelope.Result.Preflight.Status != "eligible" || len(dirtyEnvelope.Result.Preflight.FileSets) != 1 {
		t.Fatalf("tracked-control dirty result = %#v", dirtyEnvelope.Result)
	}
	dirtyPaths := make([]string, 0, len(dirtyEnvelope.Result.Preflight.FileSets[0].Files))
	for _, file := range dirtyEnvelope.Result.Preflight.FileSets[0].Files {
		dirtyPaths = append(dirtyPaths, file.Path)
		if strings.Contains(file.Path, ".gitignore") || strings.Contains(file.Path, ".mulgaeignore") || strings.Contains(file.Path, "ignored") {
			t.Fatalf("dirty preflight transmitted control or ignored path %q", file.Path)
		}
	}
	if !slices.Contains(dirtyPaths, "after/included-untracked.txt") || !slices.Contains(dirtyPaths, "after/review.go") {
		t.Fatalf("dirty preflight paths = %v", dirtyPaths)
	}
	if got := snapshotTestTree(t, filepath.Join(project, ".mulgae")); !reflect.DeepEqual(got, beforeDirtyMulgae) {
		t.Fatalf("dirty preflight mutated .mulgae: before=%v after=%v", beforeDirtyMulgae, got)
	}

	worktreePNG := append(append([]byte(nil), pngBytes...), []byte("worktree-only-drift")...)
	mustWriteTestFile(t, filepath.Join(project, "screenshots", "staged.png"), pngBytes)
	credentialFixtures := []byte(strings.Join([]string{
		"changePassword: vi.fn()",
		"Authorization: Bearer abcdefghijklmnop",
		"api_key=placeholder-api-key",
		"-----BEGIN RSA PRIVATE KEY-----",
		"placeholder-private-key",
		"-----END RSA PRIVATE KEY-----",
		"database_password=development-only",
	}, "\n") + "\n")
	mustWriteTestFile(t, filepath.Join(project, "security-fixtures.txt"), credentialFixtures)
	mustWriteTestFile(t, filepath.Join(project, "ignored.txt"), []byte("must not be transmitted\n"))
	mustWriteTestFile(t, filepath.Join(project, ".mulgaeignore"), []byte("ignored.txt\n"))
	runTestCommand(t, project, "git", "add", "review.go", "screenshots/staged.png", "security-fixtures.txt", ".mulgaeignore")
	mustWriteTestFile(t, filepath.Join(project, "screenshots", "staged.png"), worktreePNG)

	beforeMulgae := snapshotTestTree(t, filepath.Join(project, ".mulgae"))
	tempRoot := environmentValue(t, environment, "TMPDIR")
	beforeTemp := snapshotTestTree(t, tempRoot)
	first := runMulgaeBinaryWithEnv(t, binary, project, environment, "review", "--stage", "--roles", "logic,security,artist", "--preflight", "--output", "json")
	second := runMulgaeBinaryWithEnv(t, binary, project, environment, "review", "--stage", "--roles", "logic,security,artist", "--preflight", "--output", "json")
	if first.exitCode != 0 || second.exitCode != 0 || len(first.stderr) != 0 || len(second.stderr) != 0 {
		t.Fatalf("preflight exits = %d/%d stderr=%q/%q stdout=%q", first.exitCode, second.exitCode, first.stderr, second.stderr, first.stdout)
	}
	if got := snapshotTestTree(t, filepath.Join(project, ".mulgae")); !reflect.DeepEqual(got, beforeMulgae) {
		t.Fatalf("preflight mutated .mulgae: before=%v after=%v", beforeMulgae, got)
	}
	if got := snapshotTestTree(t, tempRoot); !reflect.DeepEqual(got, beforeTemp) {
		t.Fatalf("preflight leaked temporary workspace: before=%v after=%v", beforeTemp, got)
	}
	for _, logPath := range []string{zcodeLog, agyLog} {
		if observed, readErr := os.ReadFile(logPath); readErr == nil && len(bytes.TrimSpace(observed)) != 0 {
			t.Fatalf("preflight invoked provider %s: %s", logPath, observed)
		} else if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
			t.Fatal(readErr)
		}
	}

	type preflightEnvelope struct {
		Result struct {
			Kind      string                            `json:"kind"`
			Preflight mulgaeentry.ReviewPreflightResult `json:"preflight"`
		} `json:"result"`
	}
	decode := func(raw []byte) mulgaeentry.ReviewPreflightResult {
		t.Helper()
		var envelope preflightEnvelope
		if err := json.Unmarshal(raw, &envelope); err != nil {
			t.Fatal(err)
		}
		if envelope.Result.Kind != "review_preflight" {
			t.Fatalf("result kind = %q", envelope.Result.Kind)
		}
		return envelope.Result.Preflight
	}
	firstResult, secondResult := decode(first.stdout), decode(second.stdout)
	if !reflect.DeepEqual(firstResult, secondResult) {
		t.Fatalf("preflight projection is nondeterministic:\n%#v\n%#v", firstResult, secondResult)
	}
	// One transmission per role: each role is bound to exactly one provider.
	wantRoutes := []string{
		"logic/primary/zcode/zcode-logic/30m/not_applicable/prompt",
		"security/primary/zcode/zcode-security/30m/not_applicable/prompt",
		"artist/primary/agy/agy-artist/15m/safe/prompt",
	}
	gotRoutes := make([]string, 0, len(firstResult.Transmissions))
	if len(firstResult.FileSets) != 1 || firstResult.FileSets[0].ID == "" {
		t.Fatalf("preflight file sets = %#v, want one identified exact transmission set", firstResult.FileSets)
	}
	fileSetID := firstResult.FileSets[0].ID
	for _, route := range firstResult.Transmissions {
		gotRoutes = append(gotRoutes, strings.Join([]string{route.Role, route.RouteKind, route.ProviderFamily, route.ProviderInstance, route.ConfiguredTimeout, route.PermissionMode, route.TargetChannel}, "/"))
		if route.FileSetID != fileSetID {
			t.Fatalf("preflight routes do not share the exact file set: %#v", firstResult.Transmissions)
		}
	}
	if firstResult.AGYPermissionMode != "safe" || !slices.Equal(gotRoutes, wantRoutes) {
		t.Fatalf("preflight routes = mode %q %v, want %v", firstResult.AGYPermissionMode, gotRoutes, wantRoutes)
	}
	// One path per role, each carrying its provider call plus its one repair.
	wantRolePaths := []mulgaeentry.ReviewPreflightRolePath{
		{Role: "logic", ProviderInstance: "zcode-logic", InvocationCount: 2, TransitionCount: 1, InvocationTimeouts: "1h0m0s", Deadline: "1h0m2s"},
		{Role: "security", ProviderInstance: "zcode-security", InvocationCount: 2, TransitionCount: 1, InvocationTimeouts: "1h0m0s", Deadline: "1h0m2s"},
		{Role: "artist", ProviderInstance: "agy-artist", InvocationCount: 2, TransitionCount: 1, InvocationTimeouts: "30m0s", Deadline: "30m2s"},
	}
	// Three roles at two invocations each: six invocations and three role paths. The
	// critical path is one role's provider call plus its repair and transition.
	if budget := firstResult.Budget; budget.ReasonCode != "eligible" || budget.MaxActiveLanes != 3 || budget.TotalInvocations != 6 ||
		budget.CriticalPathDeadline != "1h0m2s" || budget.RunDeadline != "1h0m7s" ||
		budget.Ceilings.ProviderTimeout != "60m" || budget.Ceilings.RolePathDeadline != "14h0m14s" || budget.Ceilings.RunDeadline != "14h0m19s" ||
		budget.Ceilings.MaxInvocationsPerRole != 2 || budget.Ceilings.MaxInvocationsPerRun != 6 ||
		!reflect.DeepEqual(budget.RolePaths, wantRolePaths) {
		t.Fatalf("preflight budget = %#v, want exact first-project capacity envelope", budget)
	}
	wantPNGHash := sha256.Sum256(pngBytes)
	wantPNG := "sha256:" + hex.EncodeToString(wantPNGHash[:])
	seenPNG, seenIgnored := false, false
	sideBytes := map[string]int64{"after": 0, "before": 0}
	paths := make([]string, 0, len(firstResult.FileSets[0].Files))
	for _, file := range firstResult.FileSets[0].Files {
		paths = append(paths, file.Path)
		for side := range sideBytes {
			if strings.HasPrefix(file.Path, side+"/") {
				sideBytes[side] += file.Size
			}
		}
		if file.Path == "ignored.txt" {
			seenIgnored = true
		}
		if file.Path == "after/screenshots/staged.png" {
			seenPNG = file.MediaType == "image/png" && file.Disposition == "binary_preserved" && file.Size == int64(len(pngBytes)) && file.SHA256 == wantPNG
		}
	}
	if !seenPNG || seenIgnored {
		t.Fatalf("preflight file catalog PNG/ignored = %t/%t: %#v", seenPNG, seenIgnored, firstResult.FileSets)
	}
	combinedBytes := sideBytes["after"] + sideBytes["before"]
	if sideBytes["after"] > 64<<20 || sideBytes["before"] > 64<<20 || combinedBytes <= 64<<20 {
		t.Fatalf("preflight workspace bytes = before:%d after:%d combined:%d", sideBytes["before"], sideBytes["after"], combinedBytes)
	}
	wantPaths := []string{ports.WorkspaceReviewTargetName, "after/docs/linked.md", "after/review.go", "after/roadmap.md"}
	for index := 0; index < 8; index++ {
		wantPaths = append(wantPaths, fmt.Sprintf("after/screenshots/provider-view-%02d.png", index))
	}
	wantPaths = append(wantPaths, "after/screenshots/staged.png", "after/security-fixtures.txt", "before/docs/linked.md", "before/review.go", "before/roadmap.md")
	for index := 0; index < 8; index++ {
		wantPaths = append(wantPaths, fmt.Sprintf("before/screenshots/provider-view-%02d.png", index))
	}
	if !slices.Equal(paths, wantPaths) {
		t.Fatalf("exact transmitted source paths = %v, want %v", paths, wantPaths)
	}

	actual := runMulgaeBinaryWithEnv(t, binary, project, environment,
		"review", "--stage", "--roles", "logic,security,artist", "--output", "json")
	var actualEnvelope commandEnvelope
	if err := json.Unmarshal(actual.stdout, &actualEnvelope); err != nil || actual.exitCode != 0 || len(actual.stderr) != 0 ||
		actualEnvelope.Result.Kind != "review_started" || actualEnvelope.Result.SessionID == nil || actualEnvelope.Result.RunID == nil ||
		actualEnvelope.Result.RunManifestURI == nil || actualEnvelope.Result.ReviewArtifactURI == nil {
		t.Fatalf("actual first-project review = exit %d envelope %#v decode=%v stdout=%q stderr=%q", actual.exitCode, actualEnvelope, err, actual.stdout, actual.stderr)
	}
	status := runMulgaeBinaryWithEnv(t, binary, project, environment,
		"status", "--run", *actualEnvelope.Result.RunID, "--output", "json")
	if status.exitCode != 0 || !bytes.Contains(status.stdout, []byte(`"publication_status":"committed"`)) {
		t.Fatalf("published review query = exit %d stdout=%q stderr=%q", status.exitCode, status.stdout, status.stderr)
	}
	type zcodeObservation struct {
		CWD    string `json:"cwd"`
		Prompt string `json:"prompt"`
	}
	zcodeBytes, err := os.ReadFile(zcodeLog)
	if err != nil {
		t.Fatal(err)
	}
	var zcodeQualification, zcodeReviews int
	for _, line := range strings.Split(strings.TrimSpace(string(zcodeBytes)), "\n") {
		var observation zcodeObservation
		if err := json.Unmarshal([]byte(line), &observation); err != nil {
			t.Fatal(err)
		}
		if observation.CWD == project || !strings.HasPrefix(observation.CWD, tempRoot+string(filepath.Separator)) {
			t.Fatalf("ZCode escaped the bounded snapshot: %#v", observation)
		}
		if strings.Contains(observation.Prompt, "Prove readiness by returning exactly one JSON object and nothing else.") {
			zcodeQualification++
		} else {
			zcodeReviews++
		}
	}
	if zcodeQualification != 1 || zcodeReviews != 2 {
		t.Fatalf("ZCode launches = qualification:%d reviews:%d, want 1/2", zcodeQualification, zcodeReviews)
	}
	agyObservations := readFakeAGYObservations(t, agyLog)
	var agyQualification, agyReviews int
	for _, observation := range agyObservations {
		if len(observation.Argv) == 1 && observation.Argv[0] == "--version" {
			continue
		}
		if observation.CWD != observation.Snapshot || observation.CWD == project || !strings.HasPrefix(observation.CWD, tempRoot+string(filepath.Separator)) {
			t.Fatalf("AGY bounded snapshot contract = %#v", observation)
		}
		if observation.Prompt == "@roadmap.md" {
			agyQualification++
			continue
		}
		agyReviews++
		if observation.Fixture != string(credentialFixtures) || observation.PNG != wantPNG ||
			!slices.Contains(observation.Argv, "--sandbox") || slices.Contains(observation.Argv, "--dangerously-skip-permissions") ||
			!slices.Contains(observation.Argv, "--add-dir") {
			t.Fatalf("AGY did not read the exact captured fixture and raster evidence: %#v", observation)
		}
	}
	// AGY owns only the artist role, so it is probed and executed exactly once.
	// Qualification no longer probes a family for roles it does not own.
	if agyQualification != 1 || agyReviews != 1 {
		t.Fatalf("AGY launches = qualification:%d reviews:%d, want 1/1: %#v", agyQualification, agyReviews, agyObservations)
	}
	archive := restoreTestCapturedReviewArchive(t, project, *actualEnvelope.Result.SessionID, *actualEnvelope.Result.RunID)
	restoredWorkspace, err := archive.ProviderWorkspace()
	if err != nil {
		t.Fatal(err)
	}
	var restoredBytes int64
	for _, file := range restoredWorkspace.Files() {
		restoredBytes += int64(len(file.Bytes()))
	}
	wantRestoredBytes := combinedBytes + int64(len(archive.Target().Bytes()))
	if restoredBytes != wantRestoredBytes {
		t.Fatalf("restored provider workspace bytes = %d, want %d", restoredBytes, wantRestoredBytes)
	}
	assertExactPNG := func(label string, files []ports.WorkspaceSnapshotFile) {
		t.Helper()
		for _, file := range files {
			if file.Path().String() == "screenshots/staged.png" {
				if file.MediaType() != "image/png" || file.SHA256() != wantPNG || !bytes.Equal(file.Bytes(), pngBytes) {
					t.Fatalf("%s PNG = media=%q hash=%q bytes=%x", label, file.MediaType(), file.SHA256(), file.Bytes())
				}
				return
			}
		}
		t.Fatalf("%s omitted staged PNG", label)
	}
	assertExactPNG("archive snapshot", archive.Snapshot().Files())
	indexEvidence, ok := archive.Evidence().Files(ports.CapturedEvidenceIndex)
	if !ok {
		t.Fatal("archive omitted index evidence")
	}
	assertExactPNG("archive index evidence", indexEvidence)
	if observed, err := os.ReadFile(filepath.Join(project, "screenshots", "staged.png")); err != nil || !bytes.Equal(observed, worktreePNG) {
		t.Fatalf("actual review mutated the divergent worktree PNG: err=%v bytes=%x", err, observed)
	}
	agyBytes, err := os.ReadFile(agyLog)
	if err != nil {
		t.Fatal(err)
	}
	providerLogBaseline := map[string][]byte{zcodeLog: append([]byte(nil), zcodeBytes...), agyLog: append([]byte(nil), agyBytes...)}
	assertProviderLogsUnchanged := func(stage string) {
		t.Helper()
		for path, baseline := range providerLogBaseline {
			observed, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(observed, baseline) {
				t.Fatalf("%s preflight invoked a provider: path=%s err=%v\nbefore=%s\nafter=%s", stage, path, err, baseline, observed)
			}
		}
	}

	beforeMulgae = snapshotTestTree(t, filepath.Join(project, ".mulgae"))
	beforeTemp = snapshotTestTree(t, tempRoot)

	mustWriteTestFile(t, filepath.Join(project, "screenshots", "staged.png"), []byte("not-a-png"))
	runTestCommand(t, project, "git", "add", "screenshots/staged.png")
	failed := runMulgaeBinaryWithEnv(t, binary, project, environment, "review", "--stage", "--roles", "security", "--preflight", "--output", "json")
	if failed.exitCode != int(app.ExitCodeArtifact) || !bytes.Contains(failed.stdout, []byte(`"kind":"review_preflight_failed"`)) ||
		!bytes.Contains(failed.stdout, []byte(`"code":"unsupported_content"`)) {
		t.Fatalf("capture failure = exit %d stdout=%q stderr=%q", failed.exitCode, failed.stdout, failed.stderr)
	}
	if got := snapshotTestTree(t, tempRoot); !reflect.DeepEqual(got, beforeTemp) {
		t.Fatalf("capture failure leaked temporary workspace: before=%v after=%v", beforeTemp, got)
	}
	if got := snapshotTestTree(t, filepath.Join(project, ".mulgae")); !reflect.DeepEqual(got, beforeMulgae) {
		t.Fatalf("capture failure mutated .mulgae: before=%v after=%v", beforeMulgae, got)
	}
	assertProviderLogsUnchanged("capture-failure")
	runTestCommand(t, project, "git", "reset")
	mustWriteTestFile(t, filepath.Join(project, "screenshots", "staged.png"), pngBytes)
	noChange := runMulgaeBinaryWithEnv(t, binary, project, environment, "review", "--stage", "--roles", "security", "--preflight", "--output", "json")
	if noChange.exitCode != 0 {
		t.Fatalf("no-change preflight = exit %d stdout=%q stderr=%q", noChange.exitCode, noChange.stdout, noChange.stderr)
	}
	noChangeResult := decode(noChange.stdout)
	if noChangeResult.Status != "no_change" || len(noChangeResult.Transmissions) != 0 || noChangeResult.Budget.TotalInvocations != 0 || len(noChangeResult.Budget.RolePaths) != 0 {
		t.Fatalf("no-change projection = %#v", noChangeResult)
	}
	if got := snapshotTestTree(t, tempRoot); !reflect.DeepEqual(got, beforeTemp) {
		t.Fatalf("no-change preflight leaked temporary workspace: before=%v after=%v", beforeTemp, got)
	}
	if got := snapshotTestTree(t, filepath.Join(project, ".mulgae")); !reflect.DeepEqual(got, beforeMulgae) {
		t.Fatalf("no-change preflight mutated .mulgae: before=%v after=%v", beforeMulgae, got)
	}
	assertProviderLogsUnchanged("no-change")
}

func restoreTestCapturedReviewArchive(t *testing.T, project, sessionID, runID string) ports.CapturedReviewMaterial {
	t.Helper()
	targetRoot := filepath.Join(project, ".mulgae", sessionID, runID, "target")
	manifest, err := os.ReadFile(filepath.Join(targetRoot, "captured-review.json"))
	if err != nil {
		t.Fatal(err)
	}
	references, err := ports.CapturedReviewArchiveBlobReferences(manifest)
	if err != nil {
		t.Fatal(err)
	}
	blobs := make([]ports.CapturedReviewArchiveBlob, 0, len(references))
	for _, reference := range references {
		contents, readErr := os.ReadFile(filepath.Join(targetRoot, filepath.FromSlash(reference.Path().String())))
		if readErr != nil {
			t.Fatal(readErr)
		}
		blob, blobErr := ports.NewCapturedReviewArchiveBlob(reference.Path(), contents)
		if blobErr != nil || blob.SHA256() != reference.SHA256() {
			t.Fatalf("captured review blob %q is invalid: %v", reference.Path().String(), blobErr)
		}
		blobs = append(blobs, blob)
	}
	material, err := ports.RestoreCapturedReviewArchive(manifest, blobs)
	if err != nil {
		t.Fatal(err)
	}
	return material
}

func snapshotTestTree(t *testing.T, root string) []string {
	t.Helper()
	var paths []string
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
		paths = append(paths, filepath.ToSlash(relative))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return paths
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

func TestIntegrationMulgaeOfflineDiagnosticFailureWorkflows(t *testing.T) {
	repository := repositoryRoot(t)
	binary := buildMulgaeBinary(t, repository)
	installedUser, err := user.Current()
	if err != nil || installedUser == nil {
		t.Fatalf("current user unavailable: %#v, %v", installedUser, err)
	}

	// A rate limit is the provider's fault and may well pass on a later run, but
	// Mulgae still does not substitute the other configured provider for it.
	t.Run("rate limit fails its role without substituting another provider", func(t *testing.T) {
		project := canonicalTestTempDir(t)
		initializeReviewGitRepository(t, project)
		providerDirectory := canonicalTestTempDir(t)
		zcodeLog := filepath.Join(canonicalTestTempDir(t), "zcode.jsonl")
		agyLog := filepath.Join(canonicalTestTempDir(t), "agy.jsonl")
		zcodeNode := filepath.Join(providerDirectory, "node")
		zcodeLauncher := filepath.Join(providerDirectory, "zcode.cjs")
		buildFakeZCode(t, repository, zcodeNode, zcodeLauncher, zcodeLog, "rate_limit_review")
		buildFakeAGY(t, repository, filepath.Join(providerDirectory, "agy"), agyLog)
		environment := isolatedMulgaeEnvWith(t, installedUser.HomeDir, providerDirectory)
		environment = append(environment, "MULGAE_FAKE_AGY_LOG="+agyLog)
		initializeOfflineProviders(t, binary, project, environment, "zcode,agy", zcodeNode, zcodeLauncher, filepath.Join(providerDirectory, "agy"))

		result := runMulgaeBinaryWithEnv(t, binary, project, environment, "review", "--dirty", "--roles", "security", "--output", "json")
		var envelope commandEnvelope
		if err := json.Unmarshal(result.stdout, &envelope); err != nil {
			t.Fatal(err)
		}
		if result.exitCode != int(domain.ExitIncompleteCoverage) || envelope.Result.RunManifestURI == nil ||
			envelope.Result.SessionID == nil || envelope.Result.RunID == nil {
			observations, _ := os.ReadFile(zcodeLog)
			agyObservations, _ := os.ReadFile(agyLog)
			t.Fatalf("rate-limited review = exit %d envelope %#v stderr %q zcode observations %s agy observations %s", result.exitCode, envelope, result.stderr, observations, agyObservations)
		}
		if !commandEnvelopeHasReason(envelope, "rate_limit") || !commandEnvelopeHasReason(envelope, "required_role_incomplete") {
			t.Fatalf("rate-limited reasons = %#v", envelope.Reasons)
		}
		if contents, err := os.ReadFile(agyLog); err == nil && bytes.Contains(contents, []byte("security")) {
			t.Fatalf("a rate-limited ZCode role was rerouted to AGY:\n%s", contents)
		}
		log := readRuntimeDiagnosticLog(t, project, *envelope.Result.SessionID, *envelope.Result.RunID)
		for _, event := range []domain.RuntimeDiagnosticEventCode{domain.DiagnosticAttemptFailed, domain.DiagnosticRoleExhausted, domain.DiagnosticRuntimeClosed} {
			if !bytes.Contains(log, []byte(`"event":"`+string(event)+`"`)) {
				t.Fatalf("rate-limited diagnostic omitted %s:\n%s", event, log)
			}
		}
		// A transient failure must not be reported as an unusable provider.
		if bytes.Contains(log, []byte(`"event":"`+string(domain.DiagnosticProviderQuarantined)+`"`)) {
			t.Fatalf("a rate limit was reported as an unusable provider:\n%s", log)
		}
	})

	for _, testCase := range []struct {
		name       string
		mode       string
		wantExit   int
		wantReason string
	}{
		{name: "login required is terminal for its role", mode: "login_review", wantExit: 4, wantReason: "provider_login_required"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			project := canonicalTestTempDir(t)
			initializeReviewGitRepository(t, project)
			providerDirectory := canonicalTestTempDir(t)
			zcodeNode := filepath.Join(providerDirectory, "node")
			zcodeLauncher := filepath.Join(providerDirectory, "zcode.cjs")
			buildFakeZCode(t, repository, zcodeNode, zcodeLauncher, filepath.Join(canonicalTestTempDir(t), "zcode.jsonl"), testCase.mode)
			environment := isolatedMulgaeEnvWith(t, installedUser.HomeDir, providerDirectory)
			initializeOfflineProviders(t, binary, project, environment, "zcode", zcodeNode, zcodeLauncher, "")

			result := runMulgaeBinaryWithEnv(t, binary, project, environment, "review", "--dirty", "--roles", "security", "--output", "json")
			var envelope commandEnvelope
			if err := json.Unmarshal(result.stdout, &envelope); err != nil {
				t.Fatal(err)
			}
			if result.exitCode != testCase.wantExit || len(envelope.Reasons) != 1 || envelope.Reasons[0].Code != testCase.wantReason || envelope.Reasons[0].ArtifactURI == nil || envelope.Result.RunManifestURI != nil {
				t.Fatalf("terminal review = exit %d envelope %#v stderr %q", result.exitCode, envelope, result.stderr)
			}
			diagnosticRoot := filepath.Join(project, filepath.FromSlash(*envelope.Reasons[0].ArtifactURI))
			statusBytes, err := os.ReadFile(filepath.Join(diagnosticRoot, "status.json"))
			if err != nil {
				t.Fatal(err)
			}
			var status struct {
				State domain.RunState `json:"state"`
				P2URI string          `json:"p2_uri"`
			}
			if err := json.Unmarshal(statusBytes, &status); err != nil || status.State != domain.RunFailed || status.P2URI != "" {
				t.Fatalf("terminal diagnostic status = %#v, %v", status, err)
			}
			if log, err := os.ReadFile(filepath.Join(diagnosticRoot, "mulgae-runtime.jsonl")); err != nil || !bytes.Contains(log, []byte(`"event":"`+string(domain.DiagnosticRuntimeClosed)+`"`)) {
				t.Fatalf("terminal diagnostic log = %q, %v", log, err)
			}
			raw, err := filepath.Glob(filepath.Join(diagnosticRoot, "attempts", "a_*", "invocations", "*", "*.raw"))
			if err != nil || len(raw) == 0 {
				t.Fatalf("terminal raw diagnostics = %v, %v", raw, err)
			}
		})
	}

	t.Run("execution failure retries once and remains inspectable", func(t *testing.T) {
		project := canonicalTestTempDir(t)
		initializeReviewGitRepository(t, project)
		providerDirectory := canonicalTestTempDir(t)
		zcodeNode := filepath.Join(providerDirectory, "node")
		zcodeLauncher := filepath.Join(providerDirectory, "zcode.cjs")
		zcodeLog := filepath.Join(canonicalTestTempDir(t), "zcode.jsonl")
		buildFakeZCode(t, repository, zcodeNode, zcodeLauncher, zcodeLog, "fail_review")
		environment := isolatedMulgaeEnvWith(t, installedUser.HomeDir, providerDirectory)
		initializeOfflineProviders(t, binary, project, environment, "zcode", zcodeNode, zcodeLauncher, "")

		result := runMulgaeBinaryWithEnv(t, binary, project, environment, "review", "--dirty", "--roles", "security", "--output", "json")
		var envelope commandEnvelope
		if err := json.Unmarshal(result.stdout, &envelope); err != nil {
			t.Fatal(err)
		}
		if result.exitCode != int(domain.ExitIncompleteCoverage) || envelope.Result.RunManifestURI == nil ||
			envelope.Result.SessionID == nil || envelope.Result.RunID == nil ||
			!commandEnvelopeHasReason(envelope, "provider_execution_failed") ||
			!commandEnvelopeHasReason(envelope, "required_role_incomplete") {
			t.Fatalf("retried execution failure = exit %d envelope %#v stderr %q", result.exitCode, envelope, result.stderr)
		}
		log := readRuntimeDiagnosticLog(t, project, *envelope.Result.SessionID, *envelope.Result.RunID)
		if count := bytes.Count(log, []byte(`"event":"`+string(domain.DiagnosticInvocationPrepared)+`"`)); count != 2 {
			t.Fatalf("retried execution failure prepared invocations = %d, want 2:\n%s", count, log)
		}
		if count := bytes.Count(log, []byte(`"event":"`+string(domain.DiagnosticProcessStarted)+`"`)); count != 2 {
			t.Fatalf("retried execution failure process starts = %d, want 2:\n%s", count, log)
		}
	})

	t.Run("diagnostic open failure stops before provider spawn", func(t *testing.T) {
		project := canonicalTestTempDir(t)
		initializeReviewGitRepository(t, project)
		providerDirectory := canonicalTestTempDir(t)
		zcodeLog := filepath.Join(canonicalTestTempDir(t), "zcode.jsonl")
		zcodeNode := filepath.Join(providerDirectory, "node")
		zcodeLauncher := filepath.Join(providerDirectory, "zcode.cjs")
		buildFakeZCode(t, repository, zcodeNode, zcodeLauncher, zcodeLog, "success")
		environment := isolatedMulgaeEnvWith(t, installedUser.HomeDir, providerDirectory)
		initializeOfflineProviders(t, binary, project, environment, "zcode", zcodeNode, zcodeLauncher, "")
		diagnosticsRoot := filepath.Join(project, ".mulgae", "diagnostics")
		if err := os.Mkdir(diagnosticsRoot, 0o500); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(diagnosticsRoot, 0o700) })

		result := runMulgaeBinaryWithEnv(t, binary, project, environment, "review", "--dirty", "--roles", "security", "--output", "json")
		var envelope commandEnvelope
		if err := json.Unmarshal(result.stdout, &envelope); err != nil {
			t.Fatal(err)
		}
		if result.exitCode != 7 || len(envelope.Reasons) != 1 || envelope.Reasons[0].Code != "artifact_unavailable" || envelope.Reasons[0].ArtifactURI != nil {
			t.Fatalf("diagnostic persistence failure = exit %d envelope %#v stderr %q", result.exitCode, envelope, result.stderr)
		}
		if observations, err := os.ReadFile(zcodeLog); err == nil && len(bytes.TrimSpace(observations)) != 0 {
			t.Fatalf("provider spawned after diagnostic open failure: %s", observations)
		}
	})
}

func initializeOfflineProviders(t *testing.T, binary, project string, environment []string, providers, zcodeNode, zcodeLauncher, agy string) {
	t.Helper()
	arguments := []string{"init", "--providers", providers, "--roles", "security", "--zcode-node-executable", zcodeNode, "--zcode-launcher", zcodeLauncher}
	if agy != "" {
		arguments = append(arguments, "--agy-executable", agy)
	}
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
	Command string `json:"command"`
	Exit    struct {
		Code int    `json:"code"`
		Kind string `json:"kind"`
	} `json:"exit"`
	Result struct {
		Kind              string                 `json:"kind"`
		SessionID         *string                `json:"session_id"`
		RunID             *string                `json:"run_id"`
		RunManifestURI    *string                `json:"run_manifest_uri"`
		ReviewArtifactURI *string                `json:"review_artifact_uri"`
		PromptManifestURI *string                `json:"prompt_manifest_uri"`
		RoleReportURIs    []commandRoleReportURI `json:"role_report_uris"`
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
			(report.Transport != "staged_file" && report.Transport != "stdout") ||
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

type fakeKimiObservation struct {
	CWD    string `json:"cwd"`
	Prompt string `json:"prompt"`
}
type fakeZCodeObservation struct {
	Argv        []string `json:"argv"`
	CWD         string   `json:"cwd"`
	Prompt      string   `json:"prompt"`
	Destination string   `json:"destination"`
}
type fakeAGYObservation struct {
	Argv          []string `json:"argv"`
	CWD           string   `json:"cwd"`
	Home          string   `json:"home"`
	XDGConfigHome string   `json:"xdg_config_home"`
	XDGCacheHome  string   `json:"xdg_cache_home"`
	TempDir       string   `json:"tmpdir"`
	Scratch       string   `json:"scratch"`
	Snapshot      string   `json:"snapshot"`
	Prompt        string   `json:"prompt"`
	Fixture       string   `json:"fixture,omitempty"`
	PNG           string   `json:"png_sha256,omitempty"`
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

func seedKimiCredentials(t *testing.T, home string) {
	t.Helper()
	for path, contents := range map[string][]byte{
		".kimi-code/config.toml":                []byte("endpoint = \"offline\"\n"),
		".kimi-code/credentials/kimi-code.json": []byte("{\"token\":\"offline\"}\n"),
		".kimi/config.toml":                     []byte("endpoint = \"offline\"\n"),
		".kimi/credentials/kimi-code.json":      []byte("{\"token\":\"offline\"}\n"),
	} {
		mustWriteTestFile(t, filepath.Join(home, path), contents)
	}
}

func buildFakeKimi(t *testing.T, root, binary, logPath string) {
	t.Helper()
	source := filepath.Join(t.TempDir(), "main.go")
	program := `package main

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
)

type observation struct {
	CWD string
	Prompt string
}

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--version" {
		fmt.Println("0.28.0")
		return
	}
	if len(os.Args) != 7 || os.Args[1] != "--model" ||
		os.Args[2] != "kimi-code/kimi-for-coding" || os.Args[3] != "--prompt" ||
		os.Args[5] != "--output-format" || os.Args[6] != "stream-json" {
		panic("non-canonical Kimi invocation")
	}
	prompt := os.Args[4]
	cwd, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	log, err := os.OpenFile("__FAKE_KIMI_LOG__", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		panic(err)
	}
	if err := json.NewEncoder(log).Encode(observation{CWD: cwd, Prompt: prompt}); err != nil {
		panic(err)
	}
	if err := log.Close(); err != nil {
		panic(err)
	}
	content := "{\"schema_version\":\"mulgae-provider-review-output.v1\",\"summary\":\"No findings.\",\"completeness\":\"complete\",\"limitations\":[],\"findings\":[]}"
	if prompt == "@roadmap.md" {
		roadmap, err := os.ReadFile("roadmap.md")
		if err != nil {
			panic(err)
		}
		root := regexp.MustCompile("(?:root must be |root=)([0-9a-f]{64})").FindStringSubmatch(string(roadmap))
		role := regexp.MustCompile("(?:role must be |role=)([a-z]+)").FindStringSubmatch(string(roadmap))
		link, err := os.ReadFile("docs/linked.md")
		if err != nil || len(root) != 2 || len(role) != 2 {
			panic("native qualification reference did not resolve")
		}
		content = fmt.Sprintf("{\"root\":%q,\"link\":%q,\"role\":%q}", root[1], strings.TrimSpace(string(link)), role[1])
	}
	if err := json.NewEncoder(os.Stdout).Encode(map[string]string{"role": "assistant", "content": content}); err != nil {
		panic(err)
	}
}
`
	mustWriteTestFile(t, source, []byte(strings.ReplaceAll(program, "__FAKE_KIMI_LOG__", logPath)))
	build := exec.Command("go", "build", "-o", binary, source)
	build.Dir = root
	build.Env = append(os.Environ(), "GOPROXY=off", "GOSUMDB=off", "GOCACHE="+t.TempDir())
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build fake Kimi: %v\n%s", err, output)
	}
}

// stagedOutputDestinationMarker is the exact Mulgae-owned trusted layer line
// that precedes the single absolute path a staged review launch may write. It
// is duplicated here on purpose: the fake provider must recognize the shipped
// contract text, not a constant it shares with the implementation.
const stagedOutputDestinationMarker = "Write your complete final Markdown role report to this exact absolute file path, creating that one file only:"

// fakeZCodeStagedReportTemplate is the exact Markdown body the fake ZCode
// stages for one role. The generated fake substitutes __ROLE__ with the role
// its launch prompt names, so a published role report can be compared byte for
// byte against fakeZCodeStagedReport.
const fakeZCodeStagedReportTemplate = "# __ROLE__ role report\n\n" +
	"Staged file transport carried this __ROLE__ body.\n\n" +
	"```json\n" +
	"{\"schema_version\":\"mulgae-provider-review-output.v1\",\"summary\":\"No __ROLE__ findings.\"," +
	"\"completeness\":\"complete\",\"limitations\":[],\"findings\":[]}\n" +
	"```\n"

// fakeZCodeIgnoredStdout is the session envelope the fake ZCode prints on
// standard output for every review launch. The staged_file transport ignores
// standard output for acceptance, so this text must never reach a published
// role report.
const fakeZCodeIgnoredStdout = "{\"schema_version\":\"mulgae-provider-review-output.v1\"," +
	"\"summary\":\"Standard output is ignored under the staged file transport.\"," +
	"\"completeness\":\"complete\",\"limitations\":[],\"findings\":[]}"

// fakeAGYDefaultReviewOutput is the stdout review envelope buildFakeAGY emits.
// AGY keeps the stdout transport, so its published role report is exactly these
// bytes.
const fakeAGYDefaultReviewOutput = "{\"schema_version\":\"mulgae-provider-review-output.v1\",\"summary\":\"No findings.\",\"completeness\":\"complete\",\"limitations\":[],\"findings\":[]}"

func fakeZCodeStagedReport(role string) string {
	return strings.ReplaceAll(fakeZCodeStagedReportTemplate, "__ROLE__", role)
}

func buildFakeZCode(t *testing.T, root, binary, launcher, logPath, mode string) {
	t.Helper()
	buildFakeZCodeWithStagedOutputAndBarrier(t, root, binary, launcher, logPath, mode, "write", "")
}

func buildFakeZCodeWithBarrier(t *testing.T, root, binary, launcher, logPath, barrier string) {
	t.Helper()
	buildFakeZCodeWithStagedOutputAndBarrier(t, root, binary, launcher, logPath, "success", "write", barrier)
}

// buildFakeZCodeWithStagedOutput builds the offline ZCode fake. staged selects
// how the fake honours the Mulgae-owned staged output destination its review
// prompt states: "write" stages exactly the one role report Mulgae granted,
// "none" stages nothing, "symlink" stages a symbolic link to a report the fake
// also writes outside staging, and "extra" stages a second file beside the
// report. Every variant still prints the ignored stdout session envelope.
func buildFakeZCodeWithStagedOutput(t *testing.T, root, binary, launcher, logPath, mode, staged string) {
	t.Helper()
	buildFakeZCodeWithStagedOutputAndBarrier(t, root, binary, launcher, logPath, mode, staged, "")
}

func buildFakeZCodeWithStagedOutputAndBarrier(t *testing.T, root, binary, launcher, logPath, mode, staged, barrier string) {
	t.Helper()
	mustWriteTestFile(t, launcher, []byte("// offline fake ZCode launcher\n"))
	source := filepath.Join(t.TempDir(), "main.go")
	program := `package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type observation struct {
	Argv []string ` + "`json:\"argv\"`" + `
	CWD string ` + "`json:\"cwd\"`" + `
	Prompt string ` + "`json:\"prompt\"`" + `
	Destination string ` + "`json:\"destination,omitempty\"`" + `
}

const destinationMarker = "__FAKE_ZCODE_DESTINATION_MARKER__"
const barrierDirectory = __FAKE_ZCODE_BARRIER__

var roleGuide = regexp.MustCompile("Mulgae ROOT REVIEW ROLE GUIDE/[0-9]+: ([A-Z]+)")

func main() {
	argv := append([]string(nil), os.Args[1:]...)
	if len(argv) == 2 && argv[1] == "--version" {
		fmt.Println("22.14.0")
		return
	}
	prompt := ""
	mode := ""
	disallowed := ""
	for index := range argv {
		switch argv[index] {
		case "--prompt":
			if index+1 < len(argv) {
				prompt = argv[index+1]
			}
		case "--mode":
			if index+1 < len(argv) {
				mode = argv[index+1]
			}
		case "--disallowed-tools":
			if index+1 < len(argv) {
				disallowed = argv[index+1]
			}
		}
	}
	if prompt == "" || mode == "" || disallowed == "" {
		panic("non-canonical ZCode invocation")
	}
	capability := strings.Contains(prompt, "Prove readiness by returning exactly one JSON object and nothing else.")
	if capability {
		if mode != "plan" || disallowed != "*" {
			panic("non-canonical ZCode capability invocation")
		}
	} else if mode != "yolo" || !strings.Contains(disallowed, "Bash") || strings.Contains(disallowed, "Write") {
		panic("non-canonical ZCode review invocation")
	}
	destination := stagedDestination(prompt)
	cwd, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	log, err := os.OpenFile("__FAKE_ZCODE_LOG__", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		panic(err)
	}
	if err := json.NewEncoder(log).Encode(observation{Argv: argv, CWD: cwd, Prompt: prompt, Destination: destination}); err != nil {
		panic(err)
	}
	if err := log.Close(); err != nil {
		panic(err)
	}
	if capability {
		if destination != "" {
			panic("ZCode capability invocation carries a staged output destination")
		}
		root := regexp.MustCompile("(?:root must be |root=)([0-9a-f]{64})").FindStringSubmatch(prompt)
		link := regexp.MustCompile("(?:link must be |link=)([^\\s;]+)").FindStringSubmatch(prompt)
		role := regexp.MustCompile("(?:role must be |role=)([a-z]+)").FindStringSubmatch(prompt)
		if len(root) != 2 || len(link) != 2 || len(role) != 2 {
			panic("native qualification reference did not resolve")
		}
		fmt.Printf("{\"root\":%q,\"link\":%q,\"role\":%q}", root[1], link[1], role[1])
		return
	}
	// A provider that fails before it produces output never honours staging, so
	// the simulated failures below exit ahead of the destination requirement.
	switch "__FAKE_ZCODE_MODE__" {
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
	if destination == "" {
		panic("ZCode review invocation omits the staged output destination")
	}
	waitForPeer()
	stage(destination, report(prompt))
	fmt.Print(__FAKE_ZCODE_STDOUT__)
}

func waitForPeer() {
	if barrierDirectory == "" {
		return
	}
	marker := filepath.Join(barrierDirectory, fmt.Sprintf("%d.ready", os.Getpid()))
	if err := os.WriteFile(marker, []byte("ready\n"), 0600); err != nil {
		panic(err)
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		entries, err := os.ReadDir(barrierDirectory)
		if err != nil {
			panic(err)
		}
		ready := 0
		for _, entry := range entries {
			if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".ready") {
				ready++
			}
		}
		if ready >= 2 {
			return
		}
		if time.Now().After(deadline) {
			panic("peer review provider did not start concurrently")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// stagedDestination returns the one absolute path the last trusted layer of a
// staged launch states. A prompt without that layer returns the empty string.
func stagedDestination(prompt string) string {
	index := strings.Index(prompt, destinationMarker)
	if index < 0 {
		return ""
	}
	line := strings.TrimPrefix(prompt[index+len(destinationMarker):], "\n")
	if end := strings.IndexByte(line, '\n'); end >= 0 {
		line = line[:end]
	}
	destination := strings.TrimSpace(line)
	if !filepath.IsAbs(destination) || filepath.Clean(destination) != destination ||
		filepath.Base(destination) != "role-report.md" {
		panic("staged output destination is not a canonical absolute role report path")
	}
	return destination
}

// report is the Markdown body this fake stages for the role its launch prompt
// names. Standard output never carries it.
func report(prompt string) string {
	role := roleGuide.FindStringSubmatch(prompt)
	if len(role) != 2 {
		panic("ZCode review prompt omits the role guide")
	}
	return strings.ReplaceAll(__FAKE_ZCODE_STAGED_BODY__, "__ROLE__", strings.ToLower(role[1]))
}

// stage writes the report exactly as the configured staging behaviour requires.
// Mulgae created the staging directory before this process started.
func stage(destination, body string) {
	switch "__FAKE_ZCODE_STAGED__" {
	case "none":
		return
	case "symlink":
		outside := filepath.Join(filepath.Dir("__FAKE_ZCODE_LOG__"), "smuggled-role-report.md")
		if err := os.WriteFile(outside, []byte(body), 0600); err != nil {
			panic(err)
		}
		if err := os.Symlink(outside, destination); err != nil {
			panic(err)
		}
		return
	case "extra":
		if err := os.WriteFile(destination, []byte(body), 0600); err != nil {
			panic(err)
		}
		if err := os.WriteFile(filepath.Join(filepath.Dir(destination), "extra-notes.md"), []byte(body), 0600); err != nil {
			panic(err)
		}
		return
	}
	if err := os.WriteFile(destination, []byte(body), 0600); err != nil {
		panic(err)
	}
}
`
	program = strings.ReplaceAll(program, "__FAKE_ZCODE_DESTINATION_MARKER__", stagedOutputDestinationMarker)
	program = strings.ReplaceAll(program, "__FAKE_ZCODE_BARRIER__", strconv.Quote(barrier))
	program = strings.ReplaceAll(program, "__FAKE_ZCODE_STAGED_BODY__", strconv.Quote(fakeZCodeStagedReportTemplate))
	program = strings.ReplaceAll(program, "__FAKE_ZCODE_STDOUT__", strconv.Quote(fakeZCodeIgnoredStdout))
	program = strings.ReplaceAll(program, "__FAKE_ZCODE_LOG__", logPath)
	program = strings.ReplaceAll(program, "__FAKE_ZCODE_MODE__", mode)
	program = strings.ReplaceAll(program, "__FAKE_ZCODE_STAGED__", staged)
	mustWriteTestFile(t, source, []byte(program))
	build := exec.Command("go", "build", "-o", binary, source)
	build.Dir = root
	build.Env = append(os.Environ(), "GOPROXY=off", "GOSUMDB=off", "GOCACHE="+t.TempDir())
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build fake ZCode: %v\n%s", err, output)
	}
}

func buildFakeAGY(t *testing.T, root, binary, logPath string) {
	buildFakeAGYWithReviewOutput(t, root, binary, logPath, "")
}

func buildFakeAGYWithReviewOutput(t *testing.T, root, binary, logPath, reviewOutput string) {
	t.Helper()
	source := filepath.Join(t.TempDir(), "main.go")
	program := `package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"
)

type observation struct {
	Argv []string ` + "`json:\"argv\"`" + `
	CWD string ` + "`json:\"cwd\"`" + `
	Home string ` + "`json:\"home\"`" + `
	XDGConfigHome string ` + "`json:\"xdg_config_home\"`" + `
	XDGCacheHome string ` + "`json:\"xdg_cache_home\"`" + `
	TempDir string ` + "`json:\"tmpdir\"`" + `
	Scratch string ` + "`json:\"scratch\"`" + `
	Snapshot string ` + "`json:\"snapshot\"`" + `
	Prompt string ` + "`json:\"prompt\"`" + `
	Fixture string ` + "`json:\"fixture,omitempty\"`" + `
	PNG string ` + "`json:\"png_sha256,omitempty\"`" + `
}

func main() {
	cwd, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	argv := append([]string(nil), os.Args[1:]...)
	observation := observation{
		Argv: argv, CWD: cwd, Home: os.Getenv("HOME"),
		XDGConfigHome: os.Getenv("XDG_CONFIG_HOME"), XDGCacheHome: os.Getenv("XDG_CACHE_HOME"),
		TempDir: os.Getenv("TMPDIR"), Scratch: os.Getenv("MULGAE_PROVIDER_SCRATCH"),
	}
	if len(argv) == 1 && argv[0] == "--version" {
		write(observation)
		fmt.Println("1.1.4")
		return
	}
	printTimeout := ""
	switch {
	case len(argv) == 12 && argv[0] == "--new-project" && argv[1] == "--sandbox" &&
		argv[2] == "--add-dir" && argv[3] == cwd && argv[4] == "--mode" && argv[5] == "plan" &&
		argv[6] == "--effort" && argv[7] == "low" && argv[8] == "--print-timeout" &&
		argv[10] == "--print":
		printTimeout = argv[9]
		observation.Snapshot, observation.Prompt = argv[3], argv[11]
	case len(argv) == 16 && argv[0] == "--new-project" && argv[1] == "--sandbox" &&
		argv[2] == "--add-dir" && argv[3] == cwd && argv[4] == "--mode" && argv[5] == "plan" &&
		argv[6] == "--effort" && argv[7] == "low" && argv[8] == "--print-timeout" &&
		argv[10] == "--print" && argv[12] == "--output-format" && argv[13] == "json" &&
		argv[14] == "--json-schema" && json.Valid([]byte(argv[15])):
		printTimeout = argv[9]
		observation.Snapshot, observation.Prompt = argv[3], argv[11]
	case len(argv) == 13 && argv[0] == "--new-project" && argv[1] == "--sandbox" &&
		argv[2] == "--dangerously-skip-permissions" && argv[3] == "--add-dir" && argv[4] == cwd &&
		argv[5] == "--mode" && argv[6] == "plan" && argv[7] == "--effort" && argv[8] == "low" &&
		argv[9] == "--print-timeout" && argv[11] == "--print":
		printTimeout = argv[10]
		observation.Snapshot, observation.Prompt = argv[4], argv[12]
	case len(argv) == 17 && argv[0] == "--new-project" && argv[1] == "--sandbox" &&
		argv[2] == "--dangerously-skip-permissions" && argv[3] == "--add-dir" && argv[4] == cwd &&
		argv[5] == "--mode" && argv[6] == "plan" && argv[7] == "--effort" && argv[8] == "low" &&
		argv[9] == "--print-timeout" && argv[11] == "--print" && argv[13] == "--output-format" &&
		argv[14] == "json" && argv[15] == "--json-schema" && json.Valid([]byte(argv[16])):
		printTimeout = argv[10]
		observation.Snapshot, observation.Prompt = argv[4], argv[12]
	default:
		panic("non-canonical AGY invocation")
	}
	// Qualification probes stay inside the bounded three-minute probe deadline; reviews
	// keep the full configured runtime deadline.
	if observation.Prompt == "@roadmap.md" {
		if printTimeout != "2m55s" || len(argv) != 16 && len(argv) != 17 {
			panic("non-canonical AGY qualification print timeout")
		}
	} else if printTimeout != "14m55s" || len(argv) != 12 && len(argv) != 13 {
		panic("non-canonical AGY review print timeout")
	}
	if observation.Prompt != "@roadmap.md" {
		fixture, fixtureErr := os.ReadFile("after/security-fixtures.txt")
		png, pngErr := os.ReadFile("after/screenshots/staged.png")
		if fixtureErr == nil && pngErr == nil {
			observation.Fixture = string(fixture)
			digest := sha256.Sum256(png)
			observation.PNG = fmt.Sprintf("sha256:%x", digest[:])
		} else if fixtureErr != nil && !os.IsNotExist(fixtureErr) || pngErr != nil && !os.IsNotExist(pngErr) {
			panic("partial review inspection fixture")
		}
	}
	write(observation)
	if observation.Prompt == "@roadmap.md" {
		roadmap, err := os.ReadFile("roadmap.md")
		if err != nil {
			panic(err)
		}
		link, err := os.ReadFile("docs/linked.md")
		root := regexp.MustCompile("(?:root must be |root=)([0-9a-f]{64})").FindStringSubmatch(string(roadmap))
		role := regexp.MustCompile("(?:role must be |role=)([a-z]+)").FindStringSubmatch(string(roadmap))
		if err != nil || len(root) != 2 || len(role) != 2 {
			panic("native qualification reference did not resolve")
		}
		fmt.Printf("{\"status\":\"success\",\"structured_output\":{\"root\":%q,\"link\":%q,\"role\":%q}}", root[1], strings.TrimSpace(string(link)), role[1])
		_ = os.Stdout.Close()
		for { time.Sleep(time.Hour) }
	}
	content := __FAKE_AGY_REVIEW_OUTPUT__
	if content == "" {
		content = "{\"schema_version\":\"mulgae-provider-review-output.v1\",\"summary\":\"No findings.\",\"completeness\":\"complete\",\"limitations\":[],\"findings\":[]}"
	}
	fmt.Print(content)
	_ = os.Stdout.Close()
	for { time.Sleep(time.Hour) }
}

func write(observation observation) {
	log, err := os.OpenFile("__FAKE_AGY_LOG__", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		panic(err)
	}
	defer log.Close()
	if err := json.NewEncoder(log).Encode(observation); err != nil {
		panic(err)
	}
}`
	program = strings.ReplaceAll(program, "__FAKE_AGY_LOG__", logPath)
	program = strings.ReplaceAll(program, "__FAKE_AGY_REVIEW_OUTPUT__", strconv.Quote(reviewOutput))
	mustWriteTestFile(t, source, []byte(program))
	build := exec.Command("go", "build", "-o", binary, source)
	build.Dir = root
	build.Env = append(os.Environ(), "GOPROXY=off", "GOSUMDB=off", "GOCACHE="+t.TempDir())
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build fake AGY: %v\n%s", err, output)
	}
}

func readFakeAGYObservations(t *testing.T, path string) []fakeAGYObservation {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fake AGY observations: %v", err)
	}
	var observations []fakeAGYObservation
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var observation fakeAGYObservation
		if err := json.Unmarshal([]byte(line), &observation); err != nil {
			t.Fatalf("decode fake AGY observation %q: %v", line, err)
		}
		observations = append(observations, observation)
	}
	return observations
}

func readFakeZCodeObservations(t *testing.T, path string) []fakeZCodeObservation {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fake ZCode observations: %v", err)
	}
	var observations []fakeZCodeObservation
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

func readFakeKimiObservations(t *testing.T, path string) []fakeKimiObservation {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fake Kimi observations: %v", err)
	}
	var observations []fakeKimiObservation
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var observation fakeKimiObservation
		if err := json.Unmarshal([]byte(line), &observation); err != nil {
			t.Fatalf("decode fake Kimi observation %q: %v", line, err)
		}
		observations = append(observations, observation)
	}
	return observations
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
	binary := filepath.Join(t.TempDir(), "mulgae")
	build := exec.Command("go", "build", "-ldflags", "-X main.buildVersion=v1.4.2 -X main.buildRevision=0123456789abcdef0123456789abcdef01234567", "-o", binary, ".")
	build.Dir = root
	build.Env = append(os.Environ(), "GOPROXY=off", "GOSUMDB=off", "GOCACHE="+t.TempDir())
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build Mulgae binary: %v\n%s", err, output)
	}
	return binary
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
