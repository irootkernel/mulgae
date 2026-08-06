package mulgae

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestReviewPreflightExampleIsSemanticallyValidAndTamperingFailsClosed(t *testing.T) {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate test source")
	}
	bytes, err := os.ReadFile(filepath.Join(filepath.Dir(filename), "..", "..", "builtin", "assets", "examples", "review-preflight.v1.valid.json"))
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
		"absolute path": func(result *ReviewPreflightResult) { result.FileSets[0].Files[0].Path = "/etc/passwd" },
		"manifest collision": func(result *ReviewPreflightResult) {
			result.FileSets[0].Files[0].Path = "._mulgae_workspace_manifest.json"
		},
		"file set identity": func(result *ReviewPreflightResult) {
			result.FileSets[0].ID = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
		},
		"budget total":  func(result *ReviewPreflightResult) { result.Budget.TotalInvocations++ },
		"lane deadline": func(result *ReviewPreflightResult) { result.Budget.Lanes[0].Deadline = "31m" },
		"route order":   func(result *ReviewPreflightResult) { result.Transmissions[0].RouteKind = "fallback" },
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

func TestReviewPreflightValidateSafeModeWarningAndNoChange(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	bytes, err := os.ReadFile(filepath.Join(filepath.Dir(filename), "..", "..", "builtin", "assets", "examples", "review-preflight.v1.valid.json"))
	if err != nil {
		t.Fatal(err)
	}
	var result ReviewPreflightResult
	if err := json.Unmarshal(bytes, &result); err != nil {
		t.Fatal(err)
	}
	result.AGYPermissionMode = "safe"
	result.Warnings = nil
	for index := range result.Transmissions {
		if result.Transmissions[index].ProviderFamily == "agy" {
			result.Transmissions[index].PermissionMode = "safe"
		}
	}
	if err := result.Validate(); err != nil {
		t.Fatalf("safe mode result: %v", err)
	}

	result.AGYPermissionMode = "dangerously-skip-permissions"
	result.Warnings = []string{"AGY dangerously-skip-permissions is opt-in and may approve write or shell tool requests outside Mulgae's read-oriented boundary."}
	for index := range result.Transmissions {
		if result.Transmissions[index].ProviderFamily == "agy" {
			result.Transmissions[index].PermissionMode = "dangerously-skip-permissions"
		}
	}
	if err := result.Validate(); err != nil {
		t.Fatalf("headless mode result: %v", err)
	}
	result.AGYPermissionMode = "safe"
	result.Warnings = nil
	for index := range result.Transmissions {
		if result.Transmissions[index].ProviderFamily == "agy" {
			result.Transmissions[index].PermissionMode = "safe"
		}
	}

	result.Status = "no_change"
	result.Transmissions = nil
	result.Budget.ReasonCode = "no_change"
	result.Budget.MaxActiveLanes = 0
	result.Budget.TotalInvocations = 0
	result.Budget.TotalOutputCapBytes = 0
	result.Budget.CriticalPathDeadline = "0s"
	result.Budget.RunDeadline = "0s"
	result.Budget.Lanes = nil
	if err := result.Validate(); err != nil {
		t.Fatalf("no-change result: %v", err)
	}
}

func TestReviewPreflightValidateAcceptsEmptyTextFile(t *testing.T) {
	result := loadReviewPreflightExample(t)
	file := &result.FileSets[0].Files[1]
	file.Size = 0
	file.SHA256 = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	id, err := reviewPreflightFileSetID(result.FileSets[0].PolicyIdentity, result.FileSets[0].Files)
	if err != nil {
		t.Fatal(err)
	}
	result.FileSets[0].ID = id
	for index := range result.Transmissions {
		result.Transmissions[index].FileSetID = id
	}
	if err := result.Validate(); err != nil {
		t.Fatalf("empty text file: %v", err)
	}
}

func loadReviewPreflightExample(t *testing.T) ReviewPreflightResult {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate test source")
	}
	bytes, err := os.ReadFile(filepath.Join(filepath.Dir(filename), "..", "..", "builtin", "assets", "examples", "review-preflight.v1.valid.json"))
	if err != nil {
		t.Fatal(err)
	}
	var result ReviewPreflightResult
	if err := json.Unmarshal(bytes, &result); err != nil {
		t.Fatal(err)
	}
	return result
}
