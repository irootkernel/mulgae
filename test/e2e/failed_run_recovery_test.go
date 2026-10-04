//go:build darwin && arm64

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestIntegrationIsolatedReleaseFixtureCancelsLiveReviewWithoutReplay(t *testing.T) {
	source := repositoryRoot(t)
	binary := buildMulgaeBinary(t, source)
	project := canonicalTestTempDir(t)
	initializeReviewGitRepository(t, project)
	providers := canonicalTestTempDir(t)
	log := filepath.Join(canonicalTestTempDir(t), "provider.jsonl")
	bundle, node, launcher := fakeZCodeAppPaths(providers)
	buildFakeZCode(t, source, node, launcher, log, "wait_review")
	environment := isolatedMulgaeEnvWith(t, integrationNativeHome(t, binary), providers)
	initializeOfflineProvidersForRoles(t, binary, project, environment, "zcode", "logic", bundle)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	running := startMulgaeBinaryWithEnv(t, ctx, binary, project, environment, "review", "--workspace", "--roles", "logic", "--output", "json")
	started := false
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if data, err := os.ReadFile(log); err == nil && bytes.Contains(data, []byte("Mulgae ROOT REVIEW ROLE GUIDE")) {
			started = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !started {
		cancel()
		result := waitMulgaeBinary(t, running)
		t.Fatalf("provider did not start: %+v", result)
	}
	if err := running.command.Process.Signal(os.Interrupt); err != nil {
		t.Fatal(err)
	}
	result := waitMulgaeBinary(t, running)
	var envelope commandEnvelope
	if err := json.Unmarshal(result.stdout, &envelope); err != nil {
		t.Fatal(err)
	}
	if result.exitCode != 9 || envelope.Result.RunID == nil || envelope.Result.ReviewArtifactURI != nil {
		t.Fatalf("cancelled review gained publication: %+v %s", result, result.stdout)
	}
	status := runMulgaeBinaryWithEnv(t, binary, project, environment, "status", "--run", *envelope.Result.RunID, "--output", "json")
	var observed struct {
		Result struct {
			RunState          string  `json:"run_state"`
			PublicationStatus *string `json:"publication_status"`
			DiagnosticOnly    bool    `json:"diagnostic_only"`
			Recovery          struct {
				Available bool `json:"available"`
			} `json:"failed_run_recovery"`
		}
	}
	if err := json.Unmarshal(status.stdout, &observed); err != nil {
		t.Fatal(err)
	}
	if status.exitCode != 0 || observed.Result.RunState != "cancelled" || observed.Result.PublicationStatus != nil || !observed.Result.DiagnosticOnly || observed.Result.Recovery.Available {
		t.Fatalf("cancelled live status gained replay authority: %s", status.stdout)
	}
	replay := runMulgaeBinaryWithEnv(t, binary, project, environment, "rerun", "--run", *envelope.Result.RunID, "--output", "json")
	if replay.exitCode != 2 || len(replay.stdout) != 0 {
		t.Fatal("retired replay admitted cancelled live run")
	}
}
