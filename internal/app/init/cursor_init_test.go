package init

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	adapterconfig "github.com/irootkernel/mulgae/internal/adapters/config"
	appconfig "github.com/irootkernel/mulgae/internal/app/config"
	"github.com/irootkernel/mulgae/internal/builtin"
	"github.com/irootkernel/mulgae/internal/ports"
)

func TestInitializeProjectCursorExecutableWritesThePhysicalSplit(t *testing.T) {
	executable := "/opt/cursor/bin/cursor-agent"
	rootPath := t.TempDir()
	if err := os.Chmod(rootPath, 0o700); err != nil {
		t.Fatal(err)
	}
	root, err := ports.NewAnchoredRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService(&testInstaller{}, testInspector{}, testAttestor{}, testResultPrevalidator{}, testClock{}, adapterconfig.SourceFactory{}, adapterconfig.YAMLCodec{}, builtin.NewCatalog())
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.InitializeProject(context.Background(), InitializeProjectRequest{
		ProjectRoot: root, ProjectName: "project", NativeHome: "/Users/test",
		Selection: Selection{Mode: SelectionSelected, ProviderIDs: []string{"cursor"}},
		Overrides: Overrides{CursorExecutable: executable},
	})
	if err != nil || !result.Committed || result.Discovery[3].ExecutableSource != "override" || result.Discovery[3].Status != "candidate" {
		t.Fatalf("cursor init = %#v err=%v", result, err)
	}
	project, err := os.ReadFile(filepath.Join(rootPath, ".mulgae", "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	local, err := os.ReadFile(filepath.Join(rootPath, ".mulgae", "local.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(project, []byte(executable)) || bytes.Contains(project, []byte("model:")) || bytes.Contains(project, []byte("reasoning_effort:")) || bytes.Contains(project, []byte("credential")) || !bytes.Contains(project, []byte("  cursor: {}")) {
		t.Fatalf("cursor project policy is invalid:\n%s", project)
	}
	if !bytes.Contains(local, []byte(`executable: "/opt/cursor/bin/cursor-agent"`)) || bytes.Contains(local, []byte("model:")) || bytes.Contains(local, []byte("timeout:")) || bytes.Contains(local, []byte("credential")) {
		t.Fatalf("cursor machine authority is invalid:\n%s", local)
	}
	decoded, err := adapterconfig.DecodeSplit(project, local)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Providers.Cursor == nil || decoded.Providers.Cursor.Executable != executable || decoded.Providers.Cursor.Timeout != appconfig.ProviderTimeoutText(appconfig.DefaultProviderTimeout) || decoded.Roles.Logic.PrimaryProvider != "cursor" {
		t.Fatalf("decoded cursor config = %#v roles=%#v", decoded.Providers.Cursor, decoded.Roles.Logic)
	}
	againProject, againLocal, err := adapterconfig.EncodeSplit(decoded)
	if err != nil {
		t.Fatal(err)
	}
	roundTrip, err := adapterconfig.DecodeSplit(againProject, againLocal)
	if err != nil {
		t.Fatal(err)
	}
	if roundTrip.Providers.Cursor == nil || roundTrip.Providers.Cursor.Executable != executable || roundTrip.Providers.Cursor.Timeout != decoded.Providers.Cursor.Timeout {
		t.Fatalf("physical round trip = %#v", roundTrip.Providers.Cursor)
	}
	timedProject := bytes.Replace(project, []byte("  cursor: {}"), []byte("  cursor:\n    timeout: \"25m\""), 1)
	timed, err := adapterconfig.DecodeSplit(timedProject, local)
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := appconfig.ResolveConfiguration(timed)
	if err != nil {
		t.Fatal(err)
	}
	timeout, ok := resolved.ProviderTimeout("cursor")
	if !ok || timeout != 25*time.Minute || resolved.Raw().Providers.Cursor == nil || resolved.Raw().Providers.Cursor.Timeout != "25m" {
		t.Fatalf("configured cursor timeout = %s ok=%v raw=%#v", timeout, ok, resolved.Raw().Providers.Cursor)
	}
	for _, injected := range [][]byte{
		[]byte("  cursor:\n    executable: \"/opt/cursor/bin/cursor-agent\""),
		[]byte("  cursor:\n    model: \"cursor-model\""),
		[]byte("  cursor:\n    default_credential_profile: \"work\""),
	} {
		if _, err := adapterconfig.DecodeSplit(bytes.Replace(project, []byte("  cursor: {}"), injected, 1), local); err == nil {
			t.Fatalf("project cursor field was accepted:\n%s", injected)
		}
	}
	machineModel := bytes.Replace(local, []byte("  cursor:\n    executable:"), []byte("  cursor:\n    model: \"cursor-model\"\n    executable:"), 1)
	if _, err := adapterconfig.DecodeSplit(project, machineModel); err == nil {
		t.Fatal("machine-local cursor model was accepted")
	}
}

func TestInitializeProjectDiscoversCursorExecutable(t *testing.T) {
	executable := "/opt/cursor/bin/cursor-agent"
	rootPath := t.TempDir()
	if err := os.Chmod(rootPath, 0o700); err != nil {
		t.Fatal(err)
	}
	root, err := ports.NewAnchoredRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	inspector := &scopedDiscoveryInspector{observations: map[string]ports.ExecutableObservation{
		"cursor": availableDiscoveryObservation(t, "cursor", executable),
	}}
	service, err := NewService(&testInstaller{}, inspector, testAttestor{}, testResultPrevalidator{}, testClock{}, adapterconfig.SourceFactory{}, adapterconfig.YAMLCodec{}, builtin.NewCatalog())
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.InitializeProject(context.Background(), InitializeProjectRequest{
		ProjectRoot: root, ProjectName: "project", NativeHome: "/Users/test",
		Selection: Selection{Mode: SelectionSelected, ProviderIDs: []string{"cursor"}},
	})
	if err != nil || result.Discovery[3].ExecutableSource != "startup_path" || !result.Discovery[3].Configured {
		t.Fatalf("discovered cursor init = %#v err=%v", result.Discovery, err)
	}
	decoded, err := readInstalledConfig(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Providers.Cursor == nil || decoded.Providers.Cursor.Executable != executable {
		t.Fatalf("discovered executable = %#v", decoded.Providers.Cursor)
	}
}

func TestInitializeProjectMixedProvidersKeepPreferenceRoute(t *testing.T) {
	rootPath := t.TempDir()
	if err := os.Chmod(rootPath, 0o700); err != nil {
		t.Fatal(err)
	}
	root, err := ports.NewAnchoredRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService(&testInstaller{}, testInspector{}, testAttestor{}, testResultPrevalidator{}, testClock{}, adapterconfig.SourceFactory{}, adapterconfig.YAMLCodec{}, builtin.NewCatalog())
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.InitializeProject(context.Background(), InitializeProjectRequest{
		ProjectRoot: root, ProjectName: "project", NativeHome: "/Users/test",
		Selection: Selection{Mode: SelectionSelected, ProviderIDs: []string{"grok", "codex"}},
		Overrides: Overrides{GrokExecutable: "/opt/grok/bin/grok", CodexExecutable: "/opt/codex/bin/codex"},
	})
	if err != nil || !result.Committed {
		t.Fatalf("grok/codex init = %#v err=%v", result, err)
	}
	decoded, err := readInstalledConfig(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	want, err := appconfig.CanonicalRolesConfig(testRoleDefaults(), []string{"grok", "codex"})
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Providers.Cursor != nil || decoded.Roles.Logic.PrimaryProvider != want.Logic.PrimaryProvider || decoded.Roles.Logic.PrimaryProvider == "cursor" {
		t.Fatalf("mixed route = %#v want %s", decoded.Roles.Logic, want.Logic.PrimaryProvider)
	}
}
