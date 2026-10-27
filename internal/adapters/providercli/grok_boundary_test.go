package providercli

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
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
	policy, err := os.ReadFile(filepath.Join(grokHome, "requirements.toml"))
	if err != nil || !strings.HasPrefix(string(policy), "fail_closed = true\n") || !strings.Contains(string(policy), "allow_managed_mcp_servers_only = true") || !strings.Contains(string(policy), "allowed_mcp_servers = []") {
		t.Fatalf("requirements policy = %q, %v", policy, err)
	}
	if err := os.WriteFile(filepath.Join(grokHome, "requirements.toml"), []byte("fail_closed = false\n"), 0600); err != nil {
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
	environment, err := isolatedProcessEnvironment(FamilyGrok, configured, namespace)
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

func TestGrokBoundaryAllowsNativeBookkeepingWithoutPolicyRestoration(t *testing.T) {
	bundle, home := grokBoundaryTestBundle(t)
	for invocation := 0; invocation < 2; invocation++ {
		if err := os.WriteFile(filepath.Join(home, "config.next"), []byte("[ui]\nwelcome_seen = true\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(filepath.Join(home, "config.next"), filepath.Join(home, "config.toml")); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(filepath.Join(home, "managed_config.toml")); err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		if err := bundle.Validate(); err != nil {
			t.Fatalf("native bookkeeping changed policy authority after invocation %d: %v", invocation+1, err)
		}
	}
}

func TestGrokBoundaryRejectsProtectedFileDrift(t *testing.T) {
	for _, name := range []string{"requirements.toml", "sandbox.toml"} {
		for _, change := range []string{"removed", "replacement", "content", "mode", "symlink", "hardlink"} {
			t.Run(name+"/"+change, func(t *testing.T) {
				bundle, home := grokBoundaryTestBundle(t)
				path := filepath.Join(home, name)
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				switch change {
				case "removed":
					err = os.Remove(path)
				case "replacement", "symlink":
					retained := path + ".retained"
					if err = os.Rename(path, retained); err == nil {
						if change == "symlink" {
							err = os.Symlink(retained, path)
						} else {
							err = os.WriteFile(path, data, 0600)
						}
					}
				case "content":
					err = os.WriteFile(path, append(data, []byte("\n# changed\n")...), 0600)
				case "mode":
					err = os.Chmod(path, 0644)
				case "hardlink":
					err = os.Link(path, path+".link")
				}
				if err != nil {
					t.Fatal(err)
				}
				if err := bundle.Validate(); err == nil {
					t.Fatal("accepted protected policy drift")
				}
			})
		}
	}
}

func grokBoundaryTestBundle(t *testing.T) (grokBoundaryBundle, string) {
	t.Helper()
	root := t.TempDir()
	home := filepath.Join(root, "home", ".grok")
	if err := os.MkdirAll(home, 0700); err != nil {
		t.Fatal(err)
	}
	bundle, err := installGrokBoundaryBundle(home, filepath.Join(root, "native-home"), filepath.Join(root, "project"))
	if err != nil {
		t.Fatal(err)
	}
	return bundle, home
}

func TestGrokBoundaryRejectsForeignOwner(t *testing.T) {
	bundle, _ := grokBoundaryTestBundle(t)
	info, err := os.Lstat(bundle.files[0].path)
	if err != nil {
		t.Fatal(err)
	}
	if !safeGrokBoundaryFile(info) {
		t.Fatal("owned private policy was rejected")
	}
	stat := *info.Sys().(*syscall.Stat_t)
	stat.Uid++
	if safeGrokBoundaryFile(grokForeignOwnerInfo{FileInfo: info, stat: &stat}) {
		t.Fatal("foreign policy owner was accepted")
	}
}

type grokForeignOwnerInfo struct {
	os.FileInfo
	stat *syscall.Stat_t
}

func (info grokForeignOwnerInfo) Sys() any { return info.stat }
