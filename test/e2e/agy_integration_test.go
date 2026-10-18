//go:build darwin && arm64

package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestIntegrationAgyHeartbeatAcquiresNamespaceWithDocumentationDefaults(t *testing.T) {
	source := repositoryRoot(t)
	binary := buildMulgaeBinary(t, source)
	project := canonicalTestTempDir(t)
	initializeReviewGitRepository(t, project)
	providers := canonicalTestTempDir(t)
	bundle, node, launcher := fakeZCodeAppPaths(providers)
	buildFakeZCode(t, source, node, launcher, filepath.Join(canonicalTestTempDir(t), "zcode.jsonl"), "success")
	native := integrationNativeHome(t, binary)
	token := filepath.Join(native, ".gemini", "antigravity-cli", "antigravity-oauth-token")
	mustWriteTestFile(t, token, []byte("synthetic-AGY-account"))
	agy := filepath.Join(providers, "agy")
	observations := filepath.Join(providers, "agy-observations")
	startFakeZCodeObserver(t, observations, "")
	// Reject before any model request. Reaching this version observation proves
	// that production acquired the diagnostic namespace and projected its token.
	program := filepath.Join(canonicalTestTempDir(t), "agy.go")
	mustWriteTestFile(t, program, []byte(fmt.Sprintf(`package main
import ("encoding/json"; "fmt"; "net"; "os")
func main() {
 connection, err := net.Dial("unix", %q)
 if err != nil { os.Exit(98) }
 if err := json.NewEncoder(connection).Encode(map[string]any{"Observation": map[string]any{"argv": os.Args}}); err != nil { os.Exit(98) }
 var acknowledged bool
 if err := json.NewDecoder(connection).Decode(&acknowledged); err != nil || !acknowledged { os.Exit(98) }
 connection.Close()
 if len(os.Args) == 2 && os.Args[1] == "--version" {
  fmt.Println("0.0.0")
  return
 }
 os.Exit(99)
}
`, fakeZCodeObserverSocket(observations))))
	runTestCommand(t, source, "go", "build", "-o", agy, program)
	environment := isolatedMulgaeEnvWith(t, native, providers)
	initialized := runMulgaeBinaryWithEnv(t, binary, project, environment, "init", "--providers", "zcode,agy", "--roles", "logic,documentation", "--zcode-app-bundle", bundle, "--agy-executable", agy, "--output", "json")
	if initialized.exitCode != 0 {
		t.Fatalf("init: %s %s", initialized.stdout, initialized.stderr)
	}
	config := readE2EConfig(t, project)
	if config.Roles.Logic.PrimaryProvider != "zcode" || config.Roles.Documentation.PrimaryProvider != "agy" {
		t.Fatalf("generated defaults: %#v", config.Roles)
	}
	result := runMulgaeBinaryWithEnv(t, binary, project, environment, "heartbeat", "--provider", "agy", "--authorize-live-request", "--output", "json")
	var envelope struct {
		Result struct {
			Heartbeat struct {
				Status     string `json:"status"`
				ReasonCode string `json:"reason_code"`
				Attempted  bool   `json:"attempted"`
			} `json:"heartbeat"`
		} `json:"result"`
	}
	if err := json.Unmarshal(result.stdout, &envelope); err != nil {
		t.Fatal(err)
	}
	h := envelope.Result.Heartbeat
	if result.exitCode != 4 || h.Status != "provider_failure" || h.ReasonCode != "provider_failure" {
		t.Fatalf("heartbeat failed before incompatible-version qualification: exit=%d stdout=%s stderr=%s", result.exitCode, result.stdout, result.stderr)
	}
	calls, err := os.ReadFile(observations)
	if err != nil {
		t.Fatalf("diagnostic namespace never reached its version-only process: %v", err)
	}
	var observed fakeZCodeObservation
	if err := json.Unmarshal(calls, &observed); err != nil || len(observed.Argv) != 2 || observed.Argv[1] != "--version" {
		t.Fatalf("expected only a version observation: %q %v", calls, err)
	}
	if body, err := os.ReadFile(token); err != nil || !bytes.Equal(body, []byte("synthetic-AGY-account")) {
		t.Fatal("heartbeat modified the original synthetic token", err)
	}
}
