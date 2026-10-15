//go:build darwin && arm64

package providercli

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/app/reviewrun"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

func TestCursorCredentialProjectionOmitsRulesSkillsAndMCP(t *testing.T) {
	home := credentialSourceTempDir(t)
	for _, relative := range []string{".cursor/rules/rule.md", ".cursor/skills/skill.md", ".cursor/mcp.json"} {
		writeCredentialSource(t, home, relative, "user-material")
	}
	base, err := NewNamespaceFactory(credentialSourceTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	factory, err := NewCredentialProjectingNamespaceFactory(base, home, map[string]CredentialSourceFamily{
		"cursor_logic": CredentialSourceCursor,
	})
	if err != nil {
		t.Fatal(err)
	}
	lease, err := factory.AcquireProviderNamespace(context.Background(), "cursor_logic", FamilyCursor)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = lease.DrainTerminal(context.Background()) })
	concrete := lease.(*namespaceLease)
	if len(concrete.seeds) != 0 || len(credentialSources[CredentialSourceCursor]) != 0 {
		t.Fatalf("cursor projected %d files", len(concrete.seeds))
	}
	err = filepath.WalkDir(concrete.root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		name := entry.Name()
		if name == ".cursor" || name == "rules" || name == "skills" || name == "mcp.json" || name == "rule.md" || name == "skill.md" {
			t.Errorf("user material copied into namespace: %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	token, err := ports.NewEnvironmentVariable("CURSOR_AUTH_TOKEN", "selected-token")
	if err != nil {
		t.Fatal(err)
	}
	rejected := []ports.EnvironmentVariable{}
	for _, item := range []struct{ name, value string }{
		{"AGENT_CLI_CREDENTIAL_STORE", "file"},
		{"CURSOR_RULES", filepath.Join(home, ".cursor", "rules")},
		{"CURSOR_SKILLS", filepath.Join(home, ".cursor", "skills")},
		{"CURSOR_MCP", filepath.Join(home, ".cursor", "mcp.json")},
	} {
		variable, varErr := ports.NewEnvironmentVariable(item.name, item.value)
		if varErr != nil {
			t.Fatal(varErr)
		}
		rejected = append(rejected, variable)
	}
	dataDir, err := concrete.cursorDataDirectory()
	if err != nil {
		t.Fatal(err)
	}
	environment, err := isolatedProcessEnvironmentWithCursorData(FamilyCursor, append([]ports.EnvironmentVariable{token}, rejected...), lease.Environment(), dataDir)
	if err != nil {
		t.Fatal(err)
	}
	values := credentialSourceEnvironment(environment)
	if values["CURSOR_AUTH_TOKEN"] != "selected-token" || values["AGENT_CLI_CREDENTIAL_STORE"] != "memory" || values["CURSOR_DATA_DIR"] != dataDir {
		t.Fatalf("auth projection = %#v", values)
	}
	parent, err := canonicalCursorDataParent()
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(values["CURSOR_DATA_DIR"]) != parent || values["CURSOR_DATA_DIR"] == parent || values["CURSOR_DATA_DIR"] == zcodeRuntimeTempDirectory || values["XDG_CONFIG_HOME"] != filepath.Join(concrete.root, "settings") {
		t.Fatalf("cursor directories = %#v", values)
	}
	for _, name := range []string{"CURSOR_RULES", "CURSOR_SKILLS", "CURSOR_MCP"} {
		if _, ok := values[name]; ok {
			t.Fatalf("%s was projected", name)
		}
	}
	if strings.Count(strings.Join(environmentText(environment), "\n"), "AGENT_CLI_CREDENTIAL_STORE=") != 1 {
		t.Fatalf("credential store = %#v", values)
	}
}

func TestCursorDataChildIsPrivateToItsLease(t *testing.T) {
	base, err := NewNamespaceFactory(credentialSourceTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	first, err := base.AcquireProviderNamespace(context.Background(), "cursor_first", FamilyCursor)
	if err != nil {
		t.Fatal(err)
	}
	second, err := base.AcquireProviderNamespace(context.Background(), "cursor_second", FamilyCursor)
	if err != nil {
		t.Fatal(err)
	}
	firstDir, err := first.(*namespaceLease).cursorDataDirectory()
	if err != nil {
		t.Fatal(err)
	}
	secondDir, err := second.(*namespaceLease).cursorDataDirectory()
	if err != nil {
		t.Fatal(err)
	}
	parent, err := canonicalCursorDataParent()
	if err != nil {
		t.Fatal(err)
	}
	if firstDir == secondDir || filepath.Dir(firstDir) != parent || filepath.Dir(secondDir) != parent || firstDir == parent || secondDir == parent {
		t.Fatalf("data children = %s %s", firstDir, secondDir)
	}
	if _, err := first.DrainTerminal(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(firstDir); !os.IsNotExist(err) {
		t.Fatalf("drained child still present: %v", err)
	}
	if info, err := os.Lstat(parent); err != nil || !info.IsDir() {
		t.Fatalf("parent removed with child: %v", err)
	}
	if _, err := os.Lstat(secondDir); err != nil {
		t.Fatal(err)
	}
	if _, err := second.DrainTerminal(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(secondDir); !os.IsNotExist(err) {
		t.Fatalf("second child still present: %v", err)
	}
	if _, err := os.Lstat(parent); err != nil {
		t.Fatal(err)
	}
}

func TestCursorAdmissionKeepsPublicFamiliesClosed(t *testing.T) {
	identity, err := (RuntimeBuilder{}).RuntimeSafetyPolicyIdentity(FamilyCursor)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := RuntimeSafetyPolicyForFamily(CredentialSourceCursor)
	if err != nil || policy.Identity() != identity || !strings.Contains(string(policy.bytes), `"rules":false`) || !strings.Contains(string(policy.bytes), `"skills":false`) || !strings.Contains(string(policy.bytes), `"mcp":false`) {
		t.Fatalf("cursor safety policy = %q %v", policy.bytes, err)
	}
	for _, family := range []CredentialSourceFamily{CredentialSourceZCode, CredentialSourceGrok, CredentialSourceCodex} {
		if _, err := RuntimeSafetyPolicyForFamily(family); err != nil {
			t.Fatal(err)
		}
	}
	public := reviewrun.Families()
	if len(public) != 3 || public[0] != reviewrun.FamilyZCode || public[1] != reviewrun.FamilyGrok || public[2] != reviewrun.FamilyCodex {
		t.Fatalf("public families = %v", public)
	}
	if reviewrun.Family(FamilyCursor).Valid() {
		t.Fatal("cursor became a public family")
	}
	if _, err := reviewrun.NewRoleProviderAssignment(domain.RoleLogic, reviewrun.Family(FamilyCursor)); err == nil {
		t.Fatal("public role assignment admitted cursor")
	}
	executable, err := filepath.EvalSymlinks("/bin/echo")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewRuntimeDefinition(FamilyCursor, "cursor_logic", "", executable, "", "cursor_logic", []string{executable}, nil, "/private/tmp", time.Second); err != nil {
		t.Fatal(err)
	}
}

func TestCursorLiveLaunchUsesSeatbeltNeutralCwdAndGitEnvironment(t *testing.T) {
	execution, credentialFile := cursorMatrixExecution(t, domain.LiveSourceWorkspace)
	credentialRoot := filepath.Dir(credentialFile)
	for _, purpose := range []ports.ProviderInvocationPurpose{ports.ProviderInvocationInitial, ports.ProviderInvocationExtract} {
		t.Run(string(purpose), func(t *testing.T) {
			request := cursorLiveLaunchRequest(t, execution, purpose)
			if request.WorkingDirectory() != execution.ReviewerHome().Root().String() {
				t.Fatalf("cwd = %s", request.WorkingDirectory())
			}
			boundary, guarded := request.LiveReadOnlyBoundary()
			if !guarded || boundary.WritableRoot().String() == execution.Binding().Root.String() {
				t.Fatal("live cursor launch missed the seatbelt boundary")
			}
			if !anchoredContains(boundary.ReadOnlyRoots(), execution.Binding().Root.String()) || !anchoredContains(boundary.ReadOnlyRoots(), execution.ReviewerHome().Root().String()) {
				t.Fatalf("read-only roots = %v", boundary.ReadOnlyRoots())
			}
			if !anchoredContains(boundary.CredentialRoots(), credentialRoot) {
				t.Fatalf("credential roots = %v", boundary.CredentialRoots())
			}
			values := credentialSourceEnvironment(request.Environment())
			runtimeTemp, present := boundary.RuntimeTempRoot()
			parent, err := canonicalCursorDataParent()
			if err != nil {
				t.Fatal(err)
			}
			if !present || values["CURSOR_DATA_DIR"] != runtimeTemp.String() || filepath.Dir(runtimeTemp.String()) != parent || runtimeTemp.String() == parent || runtimeTemp.String() == zcodeRuntimeTempDirectory {
				t.Fatalf("cursor data root present=%t path=%s", present, runtimeTemp.String())
			}
			if values["CURSOR_AUTH_TOKEN"] != "selected-token" || values["AGENT_CLI_CREDENTIAL_STORE"] != "memory" || values["GIT_CONFIG_NOSYSTEM"] != "1" || values["GIT_CONFIG_GLOBAL"] != "/dev/null" {
				t.Fatalf("launch environment = %#v", values)
			}
			if values["GIT_DIR"] != execution.Binding().GitDirectory.String() || values["GIT_WORK_TREE"] != execution.ReviewerHome().Root().String() || values["GIT_WORK_TREE"] == execution.Binding().Root.String() {
				t.Fatalf("cursor git binding dir=%s work=%s", values["GIT_DIR"], values["GIT_WORK_TREE"])
			}
			if values["TMPDIR"] != values["CURSOR_DATA_DIR"] || values["TMP"] != values["CURSOR_DATA_DIR"] || values["TEMP"] != values["CURSOR_DATA_DIR"] || values["TMPDIR"] == "/tmp" || values["TMPDIR"] == "/private/tmp" || strings.HasPrefix(values["TMPDIR"], "/var/folders/") {
				t.Fatalf("cursor diagnostic temp = %s", values["TMPDIR"])
			}
			if values["TMPPREFIX"] != values["CURSOR_DATA_DIR"]+"/zsh" || values["TMPPREFIX"] == "/tmp/zsh" || strings.HasPrefix(values["TMPPREFIX"], "/var/folders/") {
				t.Fatalf("cursor TMPPREFIX = %s", values["TMPPREFIX"])
			}
			shell := exec.Command("/bin/zsh", "-f", "-c", "print -r -- $TMPPREFIX")
			shell.Env = []string{"PATH=/usr/bin:/bin", "TMPPREFIX=" + values["TMPPREFIX"]}
			printed, shellErr := shell.Output()
			if shellErr != nil || strings.TrimSpace(string(printed)) != values["TMPPREFIX"] {
				t.Fatalf("zsh TMPPREFIX = %q %v", printed, shellErr)
			}
			if _, ok := values["CURSOR_RULES"]; ok {
				t.Fatal("rules were projected into the live environment")
			}
			if argv := request.Argv(); len(argv) != 2 || argv[1] != "acp" || strings.Contains(strings.Join(argv, " "), "--sandbox") {
				t.Fatalf("argv = %q", argv)
			}
		})
	}
}

func TestCursorQualificationLaunchUsesSeatbeltNeutralCwdAndGitEnvironment(t *testing.T) {
	root, identity := testWorkspaceRoot(t)
	namespaceRoot := credentialSourceTempDir(t)
	base, err := NewNamespaceFactory(namespaceRoot)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := base.AcquireProviderNamespace(context.Background(), "cursor_qualify", FamilyCursor)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = lease.DrainTerminal(context.Background()) })
	concrete := lease.(*namespaceLease)
	token, err := ports.NewEnvironmentVariable("CURSOR_AUTH_TOKEN", "selected-token")
	if err != nil {
		t.Fatal(err)
	}
	rules, err := ports.NewEnvironmentVariable("CURSOR_RULES", filepath.Join(namespaceRoot, ".cursor", "rules"))
	if err != nil {
		t.Fatal(err)
	}
	dataDir, err := concrete.cursorDataDirectory()
	if err != nil {
		t.Fatal(err)
	}
	environment, err := isolatedProcessEnvironmentWithCursorData(FamilyCursor, []ports.EnvironmentVariable{token, rules}, lease.Environment(), dataDir)
	if err != nil {
		t.Fatal(err)
	}
	executable, err := filepath.EvalSymlinks("/bin/echo")
	if err != nil {
		t.Fatal(err)
	}
	definition, err := NewRuntimeDefinition(FamilyCursor, "cursor_qualify", "", executable, "", "cursor_qualify", []string{executable}, nil, root.Path(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	fixture := &currentProbeFixture{root: root, identity: identity, role: domain.RoleLogic}
	runner := &cursorLaunchRecorder{}
	probe, err := NewCurrentProbe(runner, &currentProbeVerifier{})
	if err != nil {
		t.Fatal(err)
	}
	namespace := retainedQualificationNamespace{lease: lease}
	if _, _, err := probe.runBound(context.Background(), definition, namespace, fixture, []string{executable, "--version"}, environment, time.Minute, nil); len(runner.requests) != 1 {
		t.Fatalf("version launch was not recorded: %v", err)
	}
	packet, err := ports.NewProviderPacketFromBytes(fixture.Packet())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := probe.runBound(context.Background(), definition, namespace, fixture, []string{executable, "acp"}, environment, time.Minute, &packet); len(runner.requests) != 2 {
		t.Fatalf("capability launch was not recorded: %v", err)
	}
	neutral := filepath.Join(concrete.root, "home")
	for _, request := range runner.requests {
		if request.WorkingDirectory() != neutral || request.WorkingDirectory() == root.Path() {
			t.Fatalf("qualification cwd = %s", request.WorkingDirectory())
		}
		boundary, guarded := request.LiveReadOnlyBoundary()
		if !guarded || boundary.WritableRoot().String() != concrete.root || !anchoredContains(boundary.CredentialRoots(), filepath.Join(concrete.root, "auth")) || !anchoredContains(boundary.ReadOnlyRoots(), neutral) || !anchoredContains(boundary.ReadOnlyRoots(), root.Path()) {
			t.Fatalf("qualification boundary writable=%s credentials=%v read-only=%v", boundary.WritableRoot().String(), boundary.CredentialRoots(), boundary.ReadOnlyRoots())
		}
		values := credentialSourceEnvironment(request.Environment())
		runtimeTemp, present := boundary.RuntimeTempRoot()
		parent, parentErr := canonicalCursorDataParent()
		if parentErr != nil {
			t.Fatal(parentErr)
		}
		if !present || values["CURSOR_DATA_DIR"] != runtimeTemp.String() || values["CURSOR_DATA_DIR"] != dataDir || filepath.Dir(dataDir) != parent || dataDir == parent {
			t.Fatalf("qualification data root present=%t env=%s lease=%s", present, values["CURSOR_DATA_DIR"], dataDir)
		}
		if values["CURSOR_AUTH_TOKEN"] != "selected-token" || values["AGENT_CLI_CREDENTIAL_STORE"] != "memory" || values["GIT_CONFIG_NOSYSTEM"] != "1" {
			t.Fatalf("qualification environment = %#v", values)
		}
		if _, ok := values["CURSOR_RULES"]; ok {
			t.Fatal("qualification projected user rules")
		}
	}
}

func cursorLiveLaunchRequest(t *testing.T, execution ports.LiveReviewExecution, purpose ports.ProviderInvocationPurpose) ports.ProcessRequest {
	t.Helper()
	executable, err := filepath.EvalSymlinks("/bin/echo")
	if err != nil {
		t.Fatal(err)
	}
	token, err := ports.NewEnvironmentVariable("CURSOR_AUTH_TOKEN", "selected-token")
	if err != nil {
		t.Fatal(err)
	}
	rules, err := ports.NewEnvironmentVariable("CURSOR_RULES", "/private/tmp/.cursor/rules")
	if err != nil {
		t.Fatal(err)
	}
	definition, err := NewRuntimeDefinition(FamilyCursor, "cursor_review", "", executable, "", "cursor_review", []string{executable}, []ports.EnvironmentVariable{token, rules}, execution.Binding().Root.String(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	base, err := NewNamespaceFactory(credentialSourceTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	factory, err := NewCredentialProjectingNamespaceFactory(base, credentialSourceTempDir(t), map[string]CredentialSourceFamily{
		"cursor_review": CredentialSourceCursor,
	})
	if err != nil {
		t.Fatal(err)
	}
	runner := &cursorLaunchRecorder{}
	registry, err := NewRegistryWithNamespaceFactory(runner, factory, definition)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = registry.Close(context.Background()) })
	attempt, err := domain.ParseAttemptID("a_019f596a-cf80-7c67-b265-f37053d51ccf")
	if err != nil {
		t.Fatal(err)
	}
	stdin := []byte("review bytes")
	invocation, err := ports.NewProviderInvocation(domain.RoleSecurity, "cursor_review", attempt, purpose, stdin, "i_019f596a-cf80-7c67-b265-f37053d51ccd", "019f596a-cf80-7c67-b265-f37053d51cce", testStdinDigest(stdin))
	if err != nil {
		t.Fatal(err)
	}
	invocation, err = ports.NewProviderInvocationInLiveSource(invocation, execution)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Observe(context.Background(), invocation); err == nil || len(runner.requests) != 1 {
		t.Fatalf("live launch was not recorded: %v requests=%d", err, len(runner.requests))
	}
	return runner.requests[0]
}

type cursorLaunchRecorder struct {
	requests []ports.ProcessRequest
}

func (runner *cursorLaunchRecorder) Run(_ context.Context, request ports.ProcessRequest) (ports.ProcessObservation, error) {
	runner.requests = append(runner.requests, request)
	if directory, _, bound := request.LaunchDirectory(); bound && directory != nil {
		_ = directory.Close()
	}
	return ports.ProcessObservation{}, os.ErrClosed
}

func (runner *cursorLaunchRecorder) Converse(ctx context.Context, request ports.ProcessRequest, _ ports.ProviderSessionDriver) (ports.ProcessObservation, error) {
	return runner.Run(ctx, request)
}

func anchoredContains(roots []ports.AnchoredRoot, path string) bool {
	for _, root := range roots {
		if root.String() == path {
			return true
		}
	}
	return false
}

func environmentText(environment []ports.EnvironmentVariable) []string {
	values := make([]string, 0, len(environment))
	for _, variable := range environment {
		values = append(values, variable.Name()+"="+variable.Value())
	}
	return values
}
