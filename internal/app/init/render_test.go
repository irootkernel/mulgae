package init

import (
	"bytes"
	adapterconfig "github.com/irootkernel/kkachi-agent-review/internal/adapters/config"
	"testing"
)

func TestRenderConfigYAMLIsCanonicalAndRoundTrips(t *testing.T) {
	config := candidateConfig(InitializeProjectRequest{ProjectName: "project", NativeHome: "/Users/test"}, candidates{agy: &adapterconfig.AGYProviderConfig{Executable: "/bin/agy", PermissionMode: "safe"}})
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
