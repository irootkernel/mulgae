package providercli

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/ports"
)

func TestGrokReviewArgvPinsExactACPRoute(t *testing.T) {
	const executable = "/private/bin/grok"
	argv, err := grokACPArgv(executable, protocolPurposeReview)
	if err != nil {
		t.Fatal(err)
	}
	want := append([]string{executable}, grokReviewArgvTail...)
	if !reflect.DeepEqual(argv, want) {
		t.Fatalf("review argv = %q, want %q", argv, want)
	}
	if err := validateGrokACPArgv(executable, protocolPurposeReview, argv); err != nil {
		t.Fatal(err)
	}
}

func TestGrokNonReviewArgvRemovesFilesystemTools(t *testing.T) {
	for _, purpose := range []protocolInvocationPurpose{protocolPurposeExtraction, protocolPurposeQualification} {
		argv, err := grokACPArgv("/private/bin/grok", purpose)
		if err != nil {
			t.Fatal(err)
		}
		joined := strings.Join(argv, " ")
		if strings.Contains(joined, "read_file") || strings.Contains(joined, "grep") || strings.Contains(joined, "list_dir") || strings.Contains(joined, "Write") {
			t.Fatalf("purpose %q retained filesystem tools: %q", purpose, argv)
		}
		if !strings.Contains(joined, "--disable-web-search") || !strings.Contains(joined, "--no-subagents") || !strings.Contains(joined, "--deny MCPTool") || !strings.Contains(joined, "agent --no-leader stdio") {
			t.Fatalf("purpose %q lost defense-in-depth controls: %q", purpose, argv)
		}
	}
}

func TestGrokBoundaryBundleIsPrivateBoundAndDriftDetecting(t *testing.T) {
	root := t.TempDir()
	grokHome := filepath.Join(root, "home", ".grok")
	if err := os.MkdirAll(grokHome, 0700); err != nil {
		t.Fatal(err)
	}
	nativeHome := filepath.Join(root, "native-home")
	liveProject := filepath.Join(root, "live-project")
	if err := os.Mkdir(nativeHome, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(liveProject, 0700); err != nil {
		t.Fatal(err)
	}
	bundle, err := installGrokBoundaryBundle(grokHome, nativeHome, liveProject)
	if err != nil {
		t.Fatal(err)
	}
	if err := bundle.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, file := range bundle.files {
		if file.info.Mode().Perm() != 0600 {
			t.Fatalf("%s mode = %o", filepath.Base(file.path), file.info.Mode().Perm())
		}
	}
	sandbox, err := os.ReadFile(filepath.Join(grokHome, "sandbox.toml"))
	if err != nil || !strings.Contains(string(sandbox), nativeHome) || !strings.Contains(string(sandbox), liveProject) || !strings.Contains(string(sandbox), `extends = "workspace"`) {
		t.Fatalf("sandbox policy = %q, %v", sandbox, err)
	}
	managed, err := os.ReadFile(filepath.Join(grokHome, "managed_config.toml"))
	if err != nil || !strings.Contains(string(managed), "allow_managed_mcp_servers_only = true") || !strings.Contains(string(managed), "allowed_mcp_servers = []") {
		t.Fatalf("managed policy = %q, %v", managed, err)
	}
	if err := os.WriteFile(filepath.Join(grokHome, "config.toml"), []byte("[features]\nmanaged_config = true\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := bundle.Validate(); err == nil {
		t.Fatal("boundary bundle accepted content drift")
	}
}

func TestGrokEnvironmentPinsDisposableHomeAndRejectsAmbientFallback(t *testing.T) {
	root := "/private/mulgae-owned-namespace"
	namespace := directExecutionNamespaceEnvironment(t, root, filepath.Join(root, "home"))
	configured := []ports.EnvironmentVariable{mustEnvironment(t, "GROK_HOME", "/Users/operator/.grok")}
	environment, err := isolatedProcessEnvironment(grokCandidateFamily, configured, namespace)
	if err != nil {
		t.Fatal(err)
	}
	values := make(map[string]string, len(environment))
	count := 0
	for _, variable := range environment {
		values[variable.Name()] = variable.Value()
		if variable.Name() == "GROK_HOME" {
			count++
		}
	}
	want := filepath.Join(root, "home", ".grok")
	if count != 1 || values["GROK_HOME"] != want {
		t.Fatalf("GROK_HOME entries = %d, value = %q, want %q", count, values["GROK_HOME"], want)
	}
}
