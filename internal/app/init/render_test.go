package init

import (
	"bytes"
	adapterconfig "github.com/irootkernel/mulgae/internal/adapters/config"
	"testing"
)

func TestRenderConfigYAMLIsCanonicalAndRoundTrips(t *testing.T) {
	config, err := candidateConfig(InitializeProjectRequest{ProjectName: "project", NativeHome: "/Users/test"}, testRoleDefaults(), candidates{agy: &adapterconfig.AGYProviderConfig{Executable: "/bin/agy", PermissionMode: "safe"}})
	if err != nil {
		t.Fatal(err)
	}
	data, err := RenderConfigYAML(adapterconfig.YAMLCodec{}, config)
	if err != nil {
		t.Fatal(err)
	}
	again, err := adapterconfig.Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	rendered, _ := adapterconfig.EncodeCanonical(again)
	if !bytes.Equal(data, rendered) {
		t.Fatal("canonical rendering is not idempotent")
	}
}

func TestCandidateConfigDefaultsAutoProviderTimeouts(t *testing.T) {
	config, err := candidateConfig(
		InitializeProjectRequest{ProjectName: "project", NativeHome: "/Users/test"},
		testRoleDefaults(),
		candidates{
			zcode: &adapterconfig.ZCodeProviderConfig{NodeExecutable: "/bin/node", Launcher: "/Applications/ZCode.app/zcode.cjs"},
			agy:   &adapterconfig.AGYProviderConfig{Executable: "/bin/agy", PermissionMode: adapterconfig.DefaultAGYPermissionMode},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	rendered, err := adapterconfig.EncodeCanonical(config)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(rendered, []byte("timeout:")) {
		t.Fatalf("init emitted default timeouts:\n%s", rendered)
	}
	decoded, err := adapterconfig.Decode(rendered)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Providers.ZCode.Timeout != "15m" || decoded.Providers.AGY.Timeout != "15m" {
		t.Fatalf("init defaults = zcode:%q agy:%q", decoded.Providers.ZCode.Timeout, decoded.Providers.AGY.Timeout)
	}
}
