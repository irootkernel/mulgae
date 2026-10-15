//go:build darwin && arm64

package providercli

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	gittargetadapter "github.com/irootkernel/mulgae/internal/adapters/gittarget"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

func TestCursorQualificationDeniesFactoryHomesAndProject(t *testing.T) {
	base := credentialSourceTempDir(t)
	runtime := filepath.Join(base, "runtime")
	project := filepath.Join(base, "project")
	fixture := filepath.Join(base, "fixture")
	primary := filepath.Join(base, "codex-primary")
	secondary := filepath.Join(base, "codex-secondary")
	for _, path := range []string{
		filepath.Join(runtime, ".codex"),
		filepath.Join(runtime, ".grok"),
		filepath.Join(runtime, ".cursor"),
		filepath.Join(runtime, ".config", "cursor"),
		project, fixture, primary, secondary,
	} {
		if err := os.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	cursorPolicy, err := RuntimeSafetyPolicyForFamily(CredentialSourceCursor)
	if err != nil {
		t.Fatal(err)
	}
	codexPolicy, err := RuntimeSafetyPolicyForFamily(CredentialSourceCodex)
	if err != nil {
		t.Fatal(err)
	}
	namespaces, err := NewNamespaceFactory(filepath.Join(base, "namespaces"))
	if err != nil {
		t.Fatal(err)
	}
	factory, err := NewCredentialProjectingNamespaceFactoryWithProjectRoot(
		namespaces, runtime, project,
		map[string]CredentialSourceFamily{
			"cursor_qualify":  CredentialSourceCursor,
			"codex_primary":   CredentialSourceCodex,
			"codex_secondary": CredentialSourceCodex,
		},
		map[string]RuntimeSafetyPolicy{
			"cursor_qualify":  cursorPolicy,
			"codex_primary":   codexPolicy,
			"codex_secondary": codexPolicy,
		},
		nil,
		map[string]string{"codex_primary": primary, "codex_secondary": secondary},
	)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := factory.AcquireProviderNamespace(context.Background(), "cursor_qualify", FamilyCursor)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = lease.DrainTerminal(context.Background()) })
	concrete := lease.(*namespaceLease)
	if len(concrete.cursorConfiguredRoots) != 2 {
		t.Fatalf("configured roots = %v", concrete.cursorConfiguredRoots)
	}
	source, err := ports.NewAnchoredRoot(fixture)
	if err != nil {
		t.Fatal(err)
	}
	boundary, neutral, err := retainedQualificationNamespace{lease: lease}.cursorLaunchBoundary(source)
	if err != nil {
		t.Fatal(err)
	}
	if neutral.String() != filepath.Join(concrete.root, "home") {
		t.Fatalf("neutral = %s", neutral.String())
	}
	readOnly := map[string]struct{}{}
	for _, root := range boundary.ReadOnlyRoots() {
		readOnly[root.String()] = struct{}{}
	}
	if len(readOnly) != 2 {
		t.Fatalf("read-only roots = %v", boundary.ReadOnlyRoots())
	}
	if _, ok := readOnly[fixture]; !ok {
		t.Fatal("fixture is not the permitted source")
	}
	if _, ok := readOnly[neutral.String()]; !ok {
		t.Fatal("neutral cwd is not readable")
	}
	if _, projectAllowed := readOnly[project]; projectAllowed {
		t.Fatal("project is a permitted source")
	}
	if _, homeAllowed := readOnly[runtime]; homeAllowed {
		t.Fatal("runtime home is a permitted source")
	}
	credentials := map[string]struct{}{}
	for _, root := range boundary.CredentialRoots() {
		credentials[root.String()] = struct{}{}
	}
	for _, path := range []string{
		filepath.Join(concrete.root, "auth"),
		filepath.Join(runtime, ".codex"),
		filepath.Join(runtime, ".grok"),
		filepath.Join(runtime, ".cursor"),
		filepath.Join(runtime, ".config", "cursor"),
		primary, secondary, project,
	} {
		if _, ok := credentials[path]; !ok {
			t.Fatalf("missing deny %s in %v", path, boundary.CredentialRoots())
		}
	}
	if _, ok := credentials[runtime]; ok {
		t.Fatal("runtime home was denied as a whole")
	}
	if _, ok := credentials[filepath.Join(runtime, ".zcode")]; ok {
		t.Fatal("absent .zcode was denied")
	}
	if boundary.WritableRoot().String() != concrete.root {
		t.Fatalf("writable = %s", boundary.WritableRoot().String())
	}
	parent, err := ports.NewAnchoredRoot(filepath.Dir(concrete.root))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := (retainedQualificationNamespace{lease: lease}).cursorLaunchBoundary(parent); err == nil {
		t.Fatal("namespace inside the source was admitted")
	}
}

func TestCursorQualificationRejectsCredentialRootOverRuntimeHome(t *testing.T) {
	base := credentialSourceTempDir(t)
	runtime := filepath.Join(base, "runtime")
	fixture := filepath.Join(base, "fixture")
	disjoint := filepath.Join(base, "codex-disjoint")
	for _, path := range []string{runtime, fixture, disjoint} {
		if err := os.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	source, err := ports.NewAnchoredRoot(fixture)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		project string
		codex   string
	}{
		{name: "project-equals-home", project: runtime, codex: disjoint},
		{name: "configured-root-equals-home", project: disjoint, codex: runtime},
		{name: "configured-root-contains-home", project: disjoint, codex: base},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lease := cursorQualificationLease(t, runtime, tc.project, tc.codex)
			_, _, err := (retainedQualificationNamespace{lease: lease}).cursorLaunchBoundary(source)
			var boundaryErr *cursorBoundaryError
			if !errors.As(err, &boundaryErr) {
				t.Fatalf("boundary error = %v", err)
			}
		})
	}
}

func TestCursorLiveLaunchRejectsSourceAroundReviewerHome(t *testing.T) {
	base := credentialSourceTempDir(t)
	operator := filepath.Join(base, "operator")
	if err := os.Mkdir(operator, 0700); err != nil {
		t.Fatal(err)
	}
	git := func(dir string, args ...string) {
		t.Helper()
		command := exec.Command("/usr/bin/git", append([]string{"-C", dir}, args...)...)
		command.Env = []string{"PATH=/usr/bin:/bin", "HOME=/var/empty", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1"}
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v (%s)", args, err, output)
		}
	}
	git(operator, "init", "--quiet")
	operatorRoot, err := ports.NewAnchoredRoot(operator)
	if err != nil {
		t.Fatal(err)
	}
	home, err := OpenReviewerHome(operatorRoot, []byte("guide\n"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = home.Close() })
	if err := cursorRejectContainedLaunch(base, home.Root().String()); err == nil {
		t.Fatal("ancestor of the reviewer home was admitted")
	}
	credentials := filepath.Join(base, "credentials")
	if err := os.Mkdir(credentials, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(credentials, "secret.txt"), []byte("secret\n"), 0600); err != nil {
		t.Fatal(err)
	}
	credentialRoot, err := ports.NewAnchoredRoot(credentials)
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := gittargetadapter.NewLiveSourceAdapter(gittargetadapter.NewExecRunner(), []ports.AnchoredRoot{credentialRoot})
	if err != nil {
		t.Fatal(err)
	}
	source, err := adapter.OpenLiveSource(context.Background(), operatorRoot, mustLiveSelector(t, domain.LiveSourceWorkspace))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = source.Close() })
	execution, err := ports.NewLiveReviewExecution(context.Background(), source, home, []ports.AnchoredRoot{credentialRoot})
	if err != nil {
		t.Fatal(err)
	}
	runner := &cursorLaunchRecorder{}
	err = launchCursor(t, runner, execution)
	var boundaryErr *cursorBoundaryError
	if !errors.As(err, &boundaryErr) || len(runner.requests) != 0 {
		t.Fatalf("operator home source launched: %v requests=%d", err, len(runner.requests))
	}
}

func cursorQualificationLease(t *testing.T, runtime, project, codex string) *namespaceLease {
	t.Helper()
	cursorPolicy, err := RuntimeSafetyPolicyForFamily(CredentialSourceCursor)
	if err != nil {
		t.Fatal(err)
	}
	codexPolicy, err := RuntimeSafetyPolicyForFamily(CredentialSourceCodex)
	if err != nil {
		t.Fatal(err)
	}
	namespaces, err := NewNamespaceFactory(filepath.Join(runtime, "namespaces"))
	if err != nil {
		t.Fatal(err)
	}
	factory, err := NewCredentialProjectingNamespaceFactoryWithProjectRoot(
		namespaces, runtime, project,
		map[string]CredentialSourceFamily{"cursor_qualify": CredentialSourceCursor, "codex_primary": CredentialSourceCodex},
		map[string]RuntimeSafetyPolicy{"cursor_qualify": cursorPolicy, "codex_primary": codexPolicy},
		nil,
		map[string]string{"codex_primary": codex},
	)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := factory.AcquireProviderNamespace(context.Background(), "cursor_qualify", FamilyCursor)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = lease.DrainTerminal(context.Background()) })
	concrete, ok := lease.(*namespaceLease)
	if !ok {
		t.Fatal("cursor lease is not concrete")
	}
	return concrete
}

func mustLiveSelector(t *testing.T, scope domain.LiveSourceScope) ports.LiveSourceSelector {
	t.Helper()
	selector, err := ports.NewLiveSourceSelector(scope, "")
	if err != nil {
		t.Fatal(err)
	}
	return selector
}

func launchCursor(t *testing.T, runner *cursorLaunchRecorder, execution ports.LiveReviewExecution) error {
	t.Helper()
	executable, err := filepath.EvalSymlinks("/bin/echo")
	if err != nil {
		t.Fatal(err)
	}
	definition, err := NewRuntimeDefinition(FamilyCursor, "cursor_review", "", executable, "", "cursor_review", []string{executable}, nil, execution.ReviewerHome().Root().String(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	base, err := NewNamespaceFactory(credentialSourceTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	factory, err := NewCredentialProjectingNamespaceFactory(base, credentialSourceTempDir(t), map[string]CredentialSourceFamily{"cursor_review": CredentialSourceCursor})
	if err != nil {
		t.Fatal(err)
	}
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
	invocation, err := ports.NewProviderInvocation(domain.RoleSecurity, "cursor_review", attempt, ports.ProviderInvocationInitial, stdin, "i_019f596a-cf80-7c67-b265-f37053d51ccd", "019f596a-cf80-7c67-b265-f37053d51cce", testStdinDigest(stdin))
	if err != nil {
		t.Fatal(err)
	}
	invocation, err = ports.NewProviderInvocationInLiveSource(invocation, execution)
	if err != nil {
		t.Fatal(err)
	}
	_, err = registry.Observe(context.Background(), invocation)
	return err
}
