package mulgae

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestReviewPreflightExampleIsSemanticallyValidAndTamperingFailsClosed(t *testing.T) {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate test source")
	}
	bytes, err := os.ReadFile(filepath.Join(filepath.Dir(filename), "..", "..", "builtin", "assets", "examples", "review-preflight.v8.valid.json"))
	if err != nil {
		t.Fatal(err)
	}
	var valid ReviewPreflightResult
	if err := json.Unmarshal(bytes, &valid); err != nil {
		t.Fatal(err)
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid example: %v", err)
	}

	for name, mutate := range map[string]func(*ReviewPreflightResult){
		"absolute path":                func(result *ReviewPreflightResult) { result.ReadPlan[0].Path = "/etc/passwd" },
		"wrong source side":            func(result *ReviewPreflightResult) { result.ReadPlan[0].Side = "worktree" },
		"source identity":              func(result *ReviewPreflightResult) { result.SourceIdentitySHA256 = "sha256:" + strings.Repeat("d", 64) },
		"retired execution capability": func(result *ReviewPreflightResult) { result.Capabilities.ExecutionGuard = "v1" },
		"budget total":                 func(result *ReviewPreflightResult) { result.Budget.TotalInvocations++ },
		"role path deadline":           func(result *ReviewPreflightResult) { result.Budget.RolePaths[0].Deadline = "31m" },
		"duplicate role path": func(result *ReviewPreflightResult) {
			duplicate := result.Budget.RolePaths[0]
			duplicate.ProviderInstance = "agy-logic"
			result.Budget.RolePaths = append(result.Budget.RolePaths, duplicate)
		},
		"route order": func(result *ReviewPreflightResult) { result.Transmissions[0].RouteKind = "fallback" },
	} {
		t.Run(name, func(t *testing.T) {
			var candidate ReviewPreflightResult
			if err := json.Unmarshal(bytes, &candidate); err != nil {
				t.Fatal(err)
			}
			mutate(&candidate)
			if err := candidate.Validate(); err == nil {
				t.Fatal("tampered preflight result was accepted")
			}
		})
	}
}

func TestReviewPreflightValidateWarningsAndNoChange(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	bytes, err := os.ReadFile(filepath.Join(filepath.Dir(filename), "..", "..", "builtin", "assets", "examples", "review-preflight.v8.valid.json"))
	if err != nil {
		t.Fatal(err)
	}
	var result ReviewPreflightResult
	if err := json.Unmarshal(bytes, &result); err != nil {
		t.Fatal(err)
	}
	result.Warnings = []string{"unexpected warning"}
	if err := result.Validate(); err == nil {
		t.Fatal("unexpected warning was accepted")
	}
	result.Warnings = nil

	result.Status = "no_change"
	result.CandidateCount = 0
	result.Transmissions = nil
	result.Budget.ReasonCode = "no_change"
	result.Budget.MaxActiveLanes = 0
	result.Budget.TotalInvocations = 0
	result.Budget.CriticalPathDeadline = "0s"
	result.Budget.RunDeadline = "0s"
	result.Budget.RolePaths = nil
	if err := result.Validate(); err != nil {
		t.Fatalf("no-change result: %v", err)
	}
}

func TestReviewPreflightValidateAcceptsCodexCredentialProfileInstance(t *testing.T) {
	result := loadReviewPreflightExample(t)
	result.Transmissions[0].ProviderFamily = "codex"
	result.Transmissions[0].ProviderInstance = "codex-work-logic"
	result.Budget.RolePaths[0].ProviderInstance = "codex-work-logic"
	if err := result.Validate(); err != nil {
		t.Fatalf("named Codex credential profile rejected: %v", err)
	}
}

func TestReviewPreflightValidateAcceptsLargeNativeReadPlan(t *testing.T) {
	result := loadReviewPreflightExample(t)
	result.ReadPlan = make([]ReviewPreflightRead, 10_002)
	for index := range result.ReadPlan {
		result.ReadPlan[index] = ReviewPreflightRead{Side: "index", Path: fmt.Sprintf("files/%05d.txt", index)}
	}
	if err := result.Validate(); err != nil {
		t.Fatalf("large native inventory rejected: %v", err)
	}
	result.ReadPlan[10_001] = result.ReadPlan[10_000]
	if err := result.Validate(); err == nil {
		t.Fatal("duplicated native path admitted")
	}
}

func loadReviewPreflightExample(t *testing.T) ReviewPreflightResult {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate test source")
	}
	bytes, err := os.ReadFile(filepath.Join(filepath.Dir(filename), "..", "..", "builtin", "assets", "examples", "review-preflight.v8.valid.json"))
	if err != nil {
		t.Fatal(err)
	}
	var result ReviewPreflightResult
	if err := json.Unmarshal(bytes, &result); err != nil {
		t.Fatal(err)
	}
	return result
}
