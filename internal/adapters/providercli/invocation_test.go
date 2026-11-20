package providercli

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

type nativeInvocationFixture struct {
	identity  ports.WorkspaceSnapshotIdentity
	reference string
}

func (fixture nativeInvocationFixture) Reference() string {
	if fixture.reference == "" {
		return "roadmap.md"
	}
	return fixture.reference
}
func (nativeInvocationFixture) Nonce() string  { return "nonce" }
func (nativeInvocationFixture) Link() string   { return "link" }
func (nativeInvocationFixture) Packet() []byte { return []byte("fixture-packet") }
func (fixture nativeInvocationFixture) WorkspaceSnapshotIdentity() ports.WorkspaceSnapshotIdentity {
	return fixture.identity
}
func (fixture nativeInvocationFixture) Validate() error { return nil }

func TestNativeProbeInvocationCodexUsesAppServer(t *testing.T) {
	identity := nativeInvocationIdentity(t, t.TempDir())
	fixture := nativeInvocationFixture{identity: identity}
	transport, err := NewRuntimeTransport(ports.ProviderPacketChannelProtocol, -1, "")
	if err != nil {
		t.Fatal(err)
	}
	definition, err := newTestProfileWithTransport(t, FamilyCodex, "codex_current", []string{"/private/bin/codex"}, transport)
	if err != nil {
		t.Fatal(err)
	}

	argv, err := (NativeProbeInvocation{}).CapabilityArgv(definition, fixture)
	want := appendCodexProtocolServerArgv(definition.BaseArgv(), "", "")
	if err != nil || !reflect.DeepEqual(argv, want) {
		t.Fatalf("Codex argv = %#v, err = %v, want %#v", argv, err, want)
	}
	if err := (NativeProbeInvocation{}).Validate(definition, fixture, argv); err != nil {
		t.Fatalf("validate exact Codex argv: %v", err)
	}
	tampered := append([]string(nil), argv...)
	tampered[len(tampered)-1] = "other.schema.json"
	if err := (NativeProbeInvocation{}).Validate(definition, fixture, tampered); err == nil {
		t.Fatal("validate accepted a different Codex launch")
	}
}

// TestZCodeQualificationDenylistStillFullyToolDenied pins the qualification
// boundary. The review argv gained yolo mode and a Write grant for the
// staged_file transport; qualification must keep its plan-mode, fully
// tool-denied profile so the capability probe stays prompt-bound.
func TestZCodeQualificationDenylistStillFullyToolDenied(t *testing.T) {
	fixture := nativeInvocationFixture{reference: "fixtures/probe.json"}
	definition := testProfile(t, FamilyZcode, "zcode_current", "", "")

	argv, err := (NativeProbeInvocation{}).CapabilityArgv(definition, fixture)
	want := []string{"/private/bin/zcode", "app-server", "--stdio"}
	if err != nil || !reflect.DeepEqual(argv, want) {
		t.Fatalf("ZCode qualification argv = %#v, err = %v, want %#v", argv, err, want)
	}
	if err := (NativeProbeInvocation{}).Validate(definition, fixture, argv); err != nil {
		t.Fatalf("validate exact ZCode qualification argv: %v", err)
	}
	if reflect.DeepEqual(zcodeCapabilityProtocolDenylist, zcodeReviewProtocolDenylist) {
		t.Fatal("qualification shares the review denylist")
	}
}

func TestNativeProbeInvocationAllowsDeclaredZcodeLauncher(t *testing.T) {
	fixture := nativeInvocationFixture{reference: "fixtures/probe.json"}
	definition := testProfile(t, FamilyZcode, "zcode_current", "", "")
	definition.launcher = "/private/bin/zcode-launcher"
	definition.baseArgv = []string{definition.executable, definition.launcher}

	argv, err := (NativeProbeInvocation{}).CapabilityArgv(definition, fixture)
	want := []string{definition.executable, definition.launcher, "app-server", "--stdio"}
	if err != nil || !reflect.DeepEqual(argv, want) {
		t.Fatalf("ZCode launcher argv = %#v, err = %v, want %#v", argv, err, want)
	}
}

func nativeInvocationIdentity(t *testing.T, path string) ports.WorkspaceSnapshotIdentity {
	t.Helper()
	identity, err := ports.NewWorkspaceSnapshotIdentity(path, "snapshot-0123456789abcdef0123456789abcdef", "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "policy", 1, 2, 3, 4)
	if err != nil {
		t.Fatal(err)
	}
	return identity
}

type codexArgvLiveSourceStub struct {
	binding ports.ProjectBindingObservation
	target  ports.LiveSourceTarget
}

func (s codexArgvLiveSourceStub) Root() ports.AnchoredRoot       { return s.binding.Root }
func (s codexArgvLiveSourceStub) Target() ports.LiveSourceTarget { return s.target }
func (s codexArgvLiveSourceStub) RevalidateExecution(context.Context) (ports.ProjectBindingObservation, error) {
	return s.binding, nil
}
func (s codexArgvLiveSourceStub) List(context.Context, domain.LiveSourceSide) ([]ports.SafeRelativePath, error) {
	return nil, nil
}
func (s codexArgvLiveSourceStub) Read(context.Context, domain.LiveSourceSide, ports.SafeRelativePath) (ports.LiveSourceFile, error) {
	return ports.LiveSourceFile{}, nil
}
func (s codexArgvLiveSourceStub) AdmitPath(context.Context, domain.LiveSourceSide, ports.SafeRelativePath) error {
	return nil
}
func (s codexArgvLiveSourceStub) Close() error { return nil }

type codexArgvReviewerHomeStub struct {
	root ports.AnchoredRoot
}

func (h codexArgvReviewerHomeStub) Root() ports.AnchoredRoot                    { return h.root }
func (h codexArgvReviewerHomeStub) Guide() []byte                               { return []byte("guide\n") }
func (h codexArgvReviewerHomeStub) DuplicateLaunchDirectory() (*os.File, error) { return nil, nil }
func (h codexArgvReviewerHomeStub) Revalidate() error                           { return nil }
func (h codexArgvReviewerHomeStub) Close() error                                { return nil }

func TestCodexLiveReviewArgvDeniesEveryCredentialRootIncludingCursor(t *testing.T) {
	base := t.TempDir()
	home := filepath.Join(base, "operator")
	project, err := ports.NewAnchoredRoot(filepath.Join(base, "project"))
	if err != nil {
		t.Fatal(err)
	}
	neutral, err := ports.NewAnchoredRoot(filepath.Join(home, ".mulgae", "home"))
	if err != nil {
		t.Fatal(err)
	}
	credPaths := []string{
		filepath.Join(home, ".codex"),
		filepath.Join(home, ".grok"),
		filepath.Join(home, ".zcode"),
		filepath.Join(home, ".gemini"),
		filepath.Join(home, ".cursor"),
		filepath.Join(home, ".config", "cursor"),
	}
	credentials := make([]ports.AnchoredRoot, 0, len(credPaths))
	for _, p := range credPaths {
		root, rootErr := ports.NewAnchoredRoot(p)
		if rootErr != nil {
			t.Fatal(rootErr)
		}
		credentials = append(credentials, root)
	}
	selector, err := ports.NewLiveSourceSelector(domain.LiveSourceWorkspace, "")
	if err != nil {
		t.Fatal(err)
	}
	target, err := ports.NewLiveSourceTarget(selector, ports.GitObjectID{}, ports.GitObjectID{}, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	source := codexArgvLiveSourceStub{
		binding: ports.ProjectBindingObservation{
			Root:         project,
			RootIdentity: ports.ProjectDirectoryIdentity{Device: 1, Inode: 2},
		},
		target: target,
	}
	execution, err := ports.NewLiveReviewExecution(context.Background(), source, codexArgvReviewerHomeStub{root: neutral}, credentials)
	if err != nil {
		t.Fatal(err)
	}
	transport, err := NewRuntimeTransport(ports.ProviderPacketChannelProtocol, -1, "")
	if err != nil {
		t.Fatal(err)
	}
	profile, err := newTestProfileWithTransport(t, FamilyCodex, "codex_live", []string{"/private/bin/codex"}, transport)
	if err != nil {
		t.Fatal(err)
	}
	gitEnv, err := liveGitEnvironment(execution.Binding())
	if err != nil {
		t.Fatal(err)
	}
	argv, err := liveReviewArgv(definition(profile), execution, gitEnv, false)
	if err != nil {
		t.Fatalf("liveReviewArgv(FamilyCodex): %v", err)
	}
	permissionsArg := ""
	for i := 0; i < len(argv)-1; i++ {
		if argv[i] == "-c" && strings.HasPrefix(argv[i+1], "permissions.mulgae=") {
			permissionsArg = argv[i+1]
		}
	}
	if permissionsArg == "" {
		t.Fatalf("Codex live argv missing permissions.mulgae config: %q", argv)
	}
	for _, credPath := range credPaths {
		want := strconv.Quote(credPath) + `="deny"`
		if !strings.Contains(permissionsArg, want) {
			t.Fatalf("Codex permissions.mulgae missing credential denial %s in %s", want, permissionsArg)
		}
	}
}
