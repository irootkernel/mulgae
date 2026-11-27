//go:build darwin && arm64 && live_e2e

package e2e

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	adapterconfig "github.com/irootkernel/mulgae/internal/adapters/config"
	"github.com/irootkernel/mulgae/internal/adapters/jsonschema"
)

const liveDefaultZCodeModel = "account:zai-individual-coding-plan/GLM-5.4"

func TestE2EZCodeIndexRequirementsInheritSessionSettings(t *testing.T) {
	t.Setenv("MULGAE_E2E_PROJECT_ROOT", "")
	environment := requireLiveE2EEnvironment(t)
	validator := newLiveE2EValidator(t)
	project := initializeLiveE2ERepository(t)
	runLiveMulgae(t, validator, environment, project, 0, "init", "--providers", "zcode",
		"--zcode-app-bundle", environment.zcodeAppBundle, "--output", "json")
	config := readE2EConfig(t, project)
	config.Providers.ZCode.Model, config.Providers.ZCode.ReasoningEffort = "", ""
	writeLiveZCodeSharedPolicy(t, project, config)

	marker := appendLiveReadMarker(t, project, "counter.go", "index-only")
	mustLiveGit(t, project, "add", "counter.go")
	writeLiveZCodeFixture(t, project, "counter.go", []byte("package report\n\n// Worktree decoy.\n"))
	input := []byte(`{"schema_version":"mulgae-requirements-input.v1","requirements":[{"id":"INDEX-MARKER","text":"The selected counter.go has an index-only marker.","acceptance_criteria":["Locate the line starting with // index-only marker: in the staged counter.go. Cite the exact line from the index as evidence and include that line in your role report."],"owner_role":"logic"}]}`)
	writeLiveZCodeFixture(t, project, "requirements.json", input)
	preflight := runLiveMulgae(t, validator, environment, project, 0, "review", "--stage", "--roles", "logic",
		"--requirements", "requirements.json", "--preflight", "--output", "json")
	var binding struct {
		ProjectBinding string `json:"project_binding"`
	}
	if err := json.Unmarshal(preflight.Result.Preflight, &binding); err != nil || binding.ProjectBinding == "" {
		t.Fatalf("index requirements preflight omitted project binding: %v", err)
	}
	observed := observeLiveZCodeLaunches(t, environment, project)
	run := runLiveZCodeReview(t, validator, environment, project, "zcode-index-requirements-inherited",
		map[string]string{"logic": "zcode-logic"}, "review", "--stage", "--roles", "logic",
		"--requirements", "requirements.json", "--expected-project-binding", binding.ProjectBinding, "--output", "json")
	result := runLiveMulgae(t, validator, environment, project, 0, "inspect", "--run", run.manifest.RunID,
		"--requirements-limit", "1", "--output", "json")
	var requirements struct {
		Availability string `json:"availability"`
		InputSHA256  string `json:"input_sha256"`
		Evaluated    int    `json:"evaluated_count"`
		Items        []struct {
			ID      string `json:"requirement_id"`
			Verdict string `json:"verdict"`
			Origin  string `json:"origin"`
		} `json:"items"`
	}
	if err := json.Unmarshal(result.Result.Requirements, &requirements); err != nil {
		t.Fatal(err)
	}
	if requirements.Availability != "evaluated" || requirements.InputSHA256 != liveArtifactSHA256(input) || requirements.Evaluated != 1 ||
		len(requirements.Items) != 1 || requirements.Items[0].ID != "INDEX-MARKER" || requirements.Items[0].Verdict != "met" || requirements.Items[0].Origin != "provider" {
		t.Fatalf("expected a verified provider assessment for the selected index requirement: %#v", requirements)
	}
	attempts := liveAttemptsForRole(run.manifest.Attempts, "logic")
	if len(attempts) != 1 || attempts[0].InvocationCount != 2 {
		t.Fatal("expected one primary invocation and one follow-up extraction")
	}
	assertLiveRoleReportMarker(t, project, run, "logic", marker)
	assertNoProjectProviderLocks(t, project)
	assertLiveZCodeLaunches(t, observed(), "", "", map[string]int{"Read,Bash,Write": 1, "Read,Write": 2})
	t.Log("certified index-only source, inherited model and effort argv, B-1 review tools, and verified requirement")
}

func TestE2EZCodeArtistAndSyntheticHeartbeat(t *testing.T) {
	t.Setenv("MULGAE_E2E_PROJECT_ROOT", "")
	environment := requireLiveE2EEnvironment(t)
	validator := newLiveE2EValidator(t)
	project := initializeLiveE2ERepository(t)
	writeLiveZCodeFixture(t, project, "ARTIST.md", []byte("Review the two squares in figure.png.\n"))
	img := image.NewRGBA(image.Rect(0, 0, 256, 160))
	draw.Draw(img, img.Bounds(), image.White, image.Point{}, draw.Src)
	draw.Draw(img, image.Rect(16, 32, 112, 128), image.NewUniform(color.RGBA{R: 245, A: 255}), image.Point{}, draw.Src)
	draw.Draw(img, image.Rect(144, 32, 240, 128), image.NewUniform(color.RGBA{B: 245, A: 255}), image.Point{}, draw.Src)
	var visual bytes.Buffer
	if err := png.Encode(&visual, img); err != nil {
		t.Fatal(err)
	}
	writeLiveZCodeFixture(t, project, "figure.png", visual.Bytes())
	// Grok supplies the logic assignment only. An accidental invocation must fail.
	runLiveMulgae(t, validator, environment, project, 0, "init", "--providers", "zcode,grok", "--roles", "logic,artist", "--project-kind", "ui",
		"--artist-brief", "ARTIST.md", "--artist-design-specs", "figure.png", "--zcode-app-bundle", environment.zcodeAppBundle, "--grok-executable", "/usr/bin/false", "--output", "json")
	config := readE2EConfig(t, project)
	config.Roles.Logic.PrimaryProvider = "grok"
	config.Validation.Extraction.Enabled, config.Validation.Extraction.EnabledExplicit = false, true
	writeLiveZCodeSharedPolicy(t, project, config)

	t.Run("artist_png", func(t *testing.T) {
		observed := observeLiveZCodeLaunches(t, environment, project)
		run := runLiveZCodeReview(t, validator, environment, project, "zcode-artist-png", map[string]string{"artist": "zcode-artist"},
			"review", "--workspace", "--roles", "artist", "--output", "json",
			"--objective", "Read figure.png. Include a plain-text line starting with IMAGE MARKER: followed by the lowercase English color names of the left and right squares, in that order. Report colors directly visible in the image.")
		assertLiveRoleReportMarker(t, project, run, "artist", "IMAGE MARKER: red blue")
		assertNoProjectProviderLocks(t, project)
		assertLiveZCodeLaunches(t, observed(), liveDefaultZCodeModel, "max", map[string]int{"Read,Write": 1, "Read,Grep,Glob,Write": 1})
		t.Log("certified shell-free workspace artist PNG read")
	})
	t.Run("synthetic_heartbeat", func(t *testing.T) {
		observed := observeLiveZCodeLaunches(t, environment, project)
		result := runLiveMulgae(t, validator, environment, project, 0, "heartbeat", "--provider", "zcode", "--authorize-live-request", "--output", "json")
		var heartbeat struct {
			Status    string `json:"status"`
			Provider  string `json:"provider_id"`
			Attempted bool   `json:"attempted"`
		}
		if err := json.Unmarshal(result.Result.Heartbeat, &heartbeat); err != nil || heartbeat.Status != "succeeded" || heartbeat.Provider != "zcode" || !heartbeat.Attempted {
			t.Fatalf("synthetic ZCode heartbeat result=%#v error=%v", heartbeat, err)
		}
		assertNoProjectProviderLocks(t, project)
		// ProviderCurrentQualifier.QualifyCurrent admits one bounded operational
		// qualification retry on a fresh fixture inside the same namespace graph
		// (internal/app/reviewrun/current_qualifier.go).
		assertLiveZCodeLaunchesWithRetries(t, observed(), liveDefaultZCodeModel, "max", map[string]int{"Read,Write": 1}, 1)
		t.Log("certified live ZCode heartbeat where logic is assigned only to Grok")
	})
}

func writeLiveZCodeFixture(t *testing.T, project, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(project, path), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeLiveZCodeSharedPolicy(t *testing.T, project string, config adapterconfig.Config) {
	t.Helper()
	shared, _, err := adapterconfig.EncodeSplit(config)
	if err != nil {
		t.Fatal(err)
	}
	writeLiveExistingConfig(t, filepath.Join(project, ".mulgae", "config.yaml"), shared)
}

func runLiveZCodeReview(t *testing.T, validator *jsonschema.Validator, environment liveE2EEnvironment, project, scenario string, expected map[string]string, args ...string) livePublishedRun {
	t.Helper()
	validate := validateLiveSingleInvocationGate
	if slices.Contains(args, "--requirements") {
		validate = func(project string, run livePublishedRun, expected map[string]string) error {
			if err := validateLiveRecoverableAssignments(run, expected); err != nil {
				return err
			}
			return validateLivePrimaryProcessTerminals(project, run, expected)
		}
	}
	run, status, reason := runLiveRecoverableAttempt(t, validator, environment, project, scenario, expected, validate, 1, 1, args...)
	if status != "passed" {
		t.Fatal(reason)
	}
	assertSingleLiveZCodeQualification(t, project, run)
	return run
}

// The qualification diagnostic records one physical capability probe with the
// same invocation ID on its process terminal and qualified result. Candidate
// rows may cover more than one role derived from that single observation.
func assertSingleLiveZCodeQualification(t *testing.T, project string, run livePublishedRun) {
	t.Helper()
	events, err := readLiveRuntimeEvents(project, run)
	if err != nil {
		t.Fatal(err)
	}
	qualified, processTerminal := map[string]bool{}, map[string]bool{}
	for _, event := range events {
		if event.Event != "provider_io_observed" || event.Component != "qualification" || event.InvocationID == "" {
			continue
		}
		if event.Operation == "result" && event.Outcome == "qualified" {
			qualified[event.InvocationID] = true
		}
		if event.Operation == "capability" && event.Termination == "exited" && event.ExitCode != nil {
			processTerminal[event.InvocationID] = true
		}
	}
	if len(qualified) != 1 || !maps.Equal(qualified, processTerminal) {
		t.Fatalf("expected one qualified ZCode invocation with a matching physical process terminal, result=%d terminal=%d", len(qualified), len(processTerminal))
	}
}

type liveZCodeProcessKey struct {
	pid     int32
	started unix.Timeval
}

type liveZCodeLaunch struct {
	model, effort, tools, graph                 string
	modelSupplied, effortSupplied, projectBound bool
}

func observeLiveZCodeLaunches(t *testing.T, environment liveE2EEnvironment, project string) func() map[liveZCodeProcessKey]liveZCodeLaunch {
	t.Helper()
	js := filepath.Join(filepath.Dir(environment.zcodeCompanion), "herdr-zcode-app.mjs")
	project, err := filepath.EvalSymlinks(project)
	if err != nil {
		t.Fatal(err)
	}
	neutral := filepath.Join(environment.nativeHome, ".mulgae", "home")
	root := fmt.Sprintf("/private/tmp/mulgae-provider-namespaces-%d", os.Geteuid())
	existing, err := os.ReadDir(root)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	priorGraphs := make(map[string]bool, len(existing))
	for _, entry := range existing {
		priorGraphs[entry.Name()] = true
	}
	ctx, stop := context.WithCancel(context.Background())
	done := make(chan map[liveZCodeProcessKey]liveZCodeLaunch, 1)
	t.Cleanup(stop)
	go func() {
		ticker := time.NewTicker(40 * time.Millisecond)
		defer ticker.Stop()
		seen := map[liveZCodeProcessKey]liveZCodeLaunch{}
		for {
			procs, _ := unix.SysctlKinfoProcSlice("kern.proc.uid", unix.Geteuid())
			for _, proc := range procs {
				key := liveZCodeProcessKey{proc.Proc.P_pid, proc.Proc.P_starttime}
				if _, ok := seen[key]; ok {
					continue
				}
				raw, err := unix.SysctlRaw("kern.procargs2", int(key.pid))
				if err != nil {
					continue
				}
				if launch, ok := nativeLiveZCodeLaunch(liveProcessArguments(raw), js, neutral, project, root, priorGraphs); ok {
					seen[key] = launch
				}
			}
			select {
			case <-ctx.Done():
				done <- seen
				return
			case <-ticker.C:
			}
		}
	}()
	return func() map[liveZCodeProcessKey]liveZCodeLaunch {
		stop()
		return <-done
	}
}

func nativeLiveZCodeLaunch(argv []string, js, neutral, project, managedRoot string, priorGraphs map[string]bool) (liveZCodeLaunch, bool) {
	if len(argv) < 2 || argv[1] != js || liveArgumentValue(argv, "--cwd") != neutral ||
		!slices.Contains(argv, "--consume-auth-file") {
		return liveZCodeLaunch{}, false
	}
	authPath := liveArgumentValue(argv, "--auth-file")
	relative, ok := strings.CutPrefix(authPath, managedRoot+"/")
	parts := strings.Split(relative, "/")
	if !ok || len(parts) != 5 || !strings.HasPrefix(parts[0], "mulgae-review-namespaces-") ||
		priorGraphs[parts[0]] || !strings.HasPrefix(parts[1], "provider-zcode-") || parts[2] != "auth" ||
		!strings.HasPrefix(parts[3], "iso-") || parts[4] != "auth.json" {
		return liveZCodeLaunch{}, false
	}
	return liveZCodeLaunch{
		model: liveArgumentValue(argv, "--model"), effort: liveArgumentValue(argv, "--reasoning-effort"),
		tools: liveArgumentValue(argv, "--tool-allowlist"), graph: parts[0],
		modelSupplied: slices.Contains(argv, "--model"), effortSupplied: slices.Contains(argv, "--reasoning-effort"),
		projectBound: slices.Contains(argv, project),
	}, true
}

func liveProcessArguments(raw []byte) []string {
	if len(raw) < 5 {
		return nil
	}
	count := int(binary.LittleEndian.Uint32(raw[:4]))
	_, rest, found := bytes.Cut(raw[4:], []byte{0})
	if !found || count == 0 || count > len(rest) {
		return nil
	}
	rest = bytes.TrimLeft(rest, "\x00")
	args := make([]string, 0, count)
	for range count {
		arg, next, found := bytes.Cut(rest, []byte{0})
		if !found {
			return nil
		}
		args = append(args, string(arg))
		rest = next
	}
	return args
}

func liveArgumentValue(argv []string, option string) string {
	i := slices.Index(argv, option)
	if i >= 0 && i+1 < len(argv) {
		return argv[i+1]
	}
	return ""
}

func assertLiveZCodeLaunches(t *testing.T, launches map[liveZCodeProcessKey]liveZCodeLaunch, model, effort string, expected map[string]int) {
	t.Helper()
	assertLiveZCodeLaunchesWithRetries(t, launches, model, effort, expected, 0)
}

func assertLiveZCodeLaunchesWithRetries(t *testing.T, launches map[liveZCodeProcessKey]liveZCodeLaunch, model, effort string, expected map[string]int, maxQualificationRetries int) {
	t.Helper()
	counts := make(map[string]int)
	graphs := make(map[string]bool)
	projectBound := false
	for _, launch := range launches {
		if launch.model != model || launch.effort != effort || launch.modelSupplied != (model != "") || launch.effortSupplied != (effort != "") {
			t.Fatal("observed provider model or effort differs from the fixture policy")
		}
		counts[launch.tools]++
		graphs[launch.graph] = true
		projectBound = projectBound || launch.projectBound
	}
	if len(graphs) != 1 || len(expected) > 1 && !projectBound {
		t.Fatal("companion launches did not bind one managed namespace graph to the scenario")
	}
	if !liveZCodeLaunchCountsMatch(counts, expected, maxQualificationRetries) {
		t.Fatalf("observed companion process counts %v differ from expected tool allowlists %v (max_qualification_retries=%d)", counts, expected, maxQualificationRetries)
	}
	t.Logf("observed companion launches by tool allowlist=%v explicit_model=%t explicit_effort=%t", counts, model != "", effort != "")
}

func liveZCodeLaunchCountsMatch(counts, expected map[string]int, maxQualificationRetries int) bool {
	if len(counts) != len(expected) {
		return false
	}
	for tools, want := range expected {
		got, ok := counts[tools]
		if !ok {
			return false
		}
		if tools == "Read,Write" && maxQualificationRetries > 0 {
			if got < want || got > want+maxQualificationRetries {
				return false
			}
			continue
		}
		if got != want {
			return false
		}
	}
	return true
}

func TestLiveZCodeLaunchCountMatching(t *testing.T) {
	cases := []struct {
		name                    string
		counts                  map[string]int
		expected                map[string]int
		maxQualificationRetries int
		want                    bool
	}{
		{
			name:                    "exact_match_zero_retries",
			counts:                  map[string]int{"Read,Write": 1, "Read,Bash,Write": 1},
			expected:                map[string]int{"Read,Write": 1, "Read,Bash,Write": 1},
			maxQualificationRetries: 0,
			want:                    true,
		},
		{
			name:                    "rejects_plus_one_with_zero_retries",
			counts:                  map[string]int{"Read,Write": 2},
			expected:                map[string]int{"Read,Write": 1},
			maxQualificationRetries: 0,
			want:                    false,
		},
		{
			name:                    "accepts_single_attempt_with_one_retry_budget",
			counts:                  map[string]int{"Read,Write": 1},
			expected:                map[string]int{"Read,Write": 1},
			maxQualificationRetries: 1,
			want:                    true,
		},
		{
			name:                    "accepts_bounded_retry_with_one_retry_budget",
			counts:                  map[string]int{"Read,Write": 2},
			expected:                map[string]int{"Read,Write": 1},
			maxQualificationRetries: 1,
			want:                    true,
		},
		{
			name:                    "rejects_zero_count_with_one_retry_budget",
			counts:                  map[string]int{"Read,Write": 0},
			expected:                map[string]int{"Read,Write": 1},
			maxQualificationRetries: 1,
			want:                    false,
		},
		{
			name:                    "rejects_exceeding_retry_budget",
			counts:                  map[string]int{"Read,Write": 3},
			expected:                map[string]int{"Read,Write": 1},
			maxQualificationRetries: 1,
			want:                    false,
		},
		{
			name:                    "rejects_extra_allowlist_key",
			counts:                  map[string]int{"Read,Write": 1, "Read,Bash,Write": 1},
			expected:                map[string]int{"Read,Write": 1},
			maxQualificationRetries: 1,
			want:                    false,
		},
		{
			name:                    "rejects_wrong_allowlist_key",
			counts:                  map[string]int{"Read,Grep,Glob,Write": 1},
			expected:                map[string]int{"Read,Write": 1},
			maxQualificationRetries: 1,
			want:                    false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := liveZCodeLaunchCountsMatch(tc.counts, tc.expected, tc.maxQualificationRetries); got != tc.want {
				t.Fatalf("liveZCodeLaunchCountsMatch(%v, %v, %d) = %t, want %t", tc.counts, tc.expected, tc.maxQualificationRetries, got, tc.want)
			}
		})
	}
}

// The live observer matches the production reviewer home and admission path.
// This check keeps private process environment outside the parsed arguments.
func TestLiveZCodeLaunchMetadataKeepsScenarioGraph(t *testing.T) {
	const js = "/operator/bin/herdr-zcode-app.mjs"
	const neutral = "/operator/.mulgae/home"
	const source = "/fixture/project"
	const managed = "/private/tmp/mulgae-provider-namespaces-501"
	const graph = "mulgae-review-namespaces-123"
	auth := managed + "/" + graph + "/provider-zcode-logic-abcd/auth/iso-term-abcd/auth.json"
	arguments := []string{"/usr/bin/node", js, "--cwd", neutral, "--auth-file", auth,
		"--consume-auth-file", "--additional-dir", source, "--tool-allowlist", "Read,Bash,Write"}
	var raw [4]byte
	binary.LittleEndian.PutUint32(raw[:], uint32(len(arguments)))
	data := append(raw[:], []byte("/usr/bin/node\x00\x00"+strings.Join(arguments, "\x00")+"\x00--model\x00private-env\x00")...)
	parsed := liveProcessArguments(data)
	launch, ok := nativeLiveZCodeLaunch(parsed, js, neutral, source, managed, nil)
	if !ok || launch.graph != graph || !launch.projectBound || launch.modelSupplied || launch.effortSupplied || launch.tools != "Read,Bash,Write" {
		t.Fatal("managed native process did not preserve the expected omitted-flag and project binding")
	}
	if _, ok := nativeLiveZCodeLaunch(parsed, js, neutral, source, managed, map[string]bool{graph: true}); ok {
		t.Fatal("admitted a pre-existing namespace graph")
	}
}
