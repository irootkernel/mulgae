package init

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	adapterconfig "github.com/irootkernel/mulgae/internal/adapters/config"
	"github.com/irootkernel/mulgae/internal/builtin"
	"github.com/irootkernel/mulgae/internal/ports"
)

func TestInitializeProjectAgyPolicyAndOptionalAutoDiscovery(t *testing.T) {
	for _, test := range []struct {
		name, model, effort string
		auto, available     bool
		wantFailure         bool
	}{
		{name: "explicit native defaults", available: true},
		{name: "explicit settings", model: "gemini-3", effort: "max", available: true},
		{name: "auto with AGY", auto: true, available: true},
		{name: "auto without AGY", auto: true},
		{name: "auto AGY policy", auto: true, available: true, model: "gemini-3", effort: "high"},
		{name: "missing selected AGY", wantFailure: true},
		{name: "missing auto AGY with override", auto: true, model: "gemini-3", wantFailure: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := t.TempDir()
			if err := os.Chmod(path, 0700); err != nil {
				t.Fatal(err)
			}
			root, err := ports.NewAnchoredRoot(path)
			if err != nil {
				t.Fatal(err)
			}
			inspector := &scopedDiscoveryInspector{observations: map[string]ports.ExecutableObservation{}}
			if test.available {
				inspector.observations["agy"] = availableDiscoveryObservation(t, "agy", "/opt/agy/bin/agy")
			}
			service, err := NewService(&testInstaller{}, inspector, testAttestor{}, testResultPrevalidator{}, testClock{}, adapterconfig.SourceFactory{}, adapterconfig.YAMLCodec{}, builtin.NewCatalog())
			if err != nil {
				t.Fatal(err)
			}
			selection := Selection{Mode: SelectionSelected, ProviderIDs: []string{"agy"}}
			overrides := Overrides{AgyModel: test.model, AgyReasoningEffort: test.effort}
			if test.auto {
				selection = Selection{Mode: SelectionAuto}
				overrides.ZCodeAppBundle = "/Applications/ZCode.app"
				overrides.GrokExecutable = "/opt/grok/bin/grok"
				// This inspector supports only identity observation. Init cannot run a provider.
				for _, name := range []string{"/Applications/ZCode.app/Contents/MacOS/ZCode", "/Applications/ZCode.app/Contents/Resources/glm/zcode.cjs", "/opt/grok/bin/grok"} {
					inspector.observations[name] = availableDiscoveryObservation(t, name, name)
				}
				inspector.fileObservations = map[string]ports.FileIdentityObservation{
					"/Applications/ZCode.app/Contents/MacOS/ZCode":                                  availableFileObservation(t, "/Applications/ZCode.app/Contents/MacOS/ZCode", "/Applications/ZCode.app/Contents/MacOS/ZCode"),
					"/Applications/ZCode.app/Contents/Resources/glm/zcode.cjs":                      availableFileObservation(t, "/Applications/ZCode.app/Contents/Resources/glm/zcode.cjs", "/Applications/ZCode.app/Contents/Resources/glm/zcode.cjs"),
					"/Applications/ZCode.app/Contents/Resources/config/provider/zcode-builtin.json": availableFileObservation(t, "/Applications/ZCode.app/Contents/Resources/config/provider/zcode-builtin.json", "/Applications/ZCode.app/Contents/Resources/config/provider/zcode-builtin.json"),
				}
			}
			result, err := service.InitializeProject(context.Background(), InitializeProjectRequest{ProjectRoot: root, ProjectName: "project", NativeHome: "/Users/test", Selection: selection, RoleIDs: []string{"logic", "documentation"}, Overrides: overrides})
			if test.wantFailure {
				if err == nil || result.Committed {
					t.Fatalf("missing selected provider did not fail: %#v %v", result, err)
				}
				if _, err := os.Stat(filepath.Join(path, ".mulgae", "config.yaml")); !os.IsNotExist(err) {
					t.Fatalf("failed discovery installed project policy: %v", err)
				}
				return
			}
			if err != nil || !result.Committed {
				t.Fatalf("init: %#v, %v", result, err)
			}
			if len(result.Discovery) != 5 || len(inspector.legacyCalls) != 0 {
				t.Fatalf("discovery: %#v legacy=%v", result.Discovery, inspector.legacyCalls)
			}
			config, err := readInstalledConfig(path)
			if err != nil {
				t.Fatal(err)
			}
			wantIDs := []string{"agy"}
			if test.auto {
				wantIDs = []string{"zcode", "grok"}
				if test.available {
					wantIDs = append(wantIDs, "agy")
				}
			}
			if !reflect.DeepEqual(result.ConfiguredProviderIDs, wantIDs) {
				t.Fatalf("configured=%v want=%v", result.ConfiguredProviderIDs, wantIDs)
			}
			wantDocumentation := "zcode"
			if test.available {
				wantDocumentation = "agy"
				if config.Providers.Agy == nil || config.Providers.Agy.Model != test.model || config.Providers.Agy.ReasoningEffort != test.effort || config.Providers.Agy.Executable != "/opt/agy/bin/agy" {
					t.Fatalf("AGY policy: %#v", config.Providers.Agy)
				}
			} else if config.Providers.Agy != nil {
				t.Fatal("absent AGY was configured")
			}
			if config.Roles.Documentation.PrimaryProvider != wantDocumentation || test.auto && config.Roles.Logic.PrimaryProvider != "zcode" {
				t.Fatalf("roles: %#v", config.Roles)
			}
			project, err := os.ReadFile(filepath.Join(path, ".mulgae", "config.yaml"))
			if err != nil {
				t.Fatal(err)
			}
			local, err := os.ReadFile(filepath.Join(path, ".mulgae", "local.yaml"))
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(project, []byte("/opt/agy")) || bytes.Contains(local, []byte("reasoning_effort:")) || bytes.Contains(local, []byte("model:")) {
				t.Fatal("project/local authority leaked across the split")
			}
			if test.model == "" && bytes.Contains(project, []byte("gemini")) {
				t.Fatal("init invented a native model default")
			}
		})
	}
}
