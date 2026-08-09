package mulgae

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/irootkernel/mulgae/internal/ports"
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

func TestReviewPreflightValidateAcceptsBoundedGitProviderView(t *testing.T) {
	result := loadReviewPreflightExample(t)
	files := make([]ReviewPreflightFile, 0, 10_002)
	for _, directory := range []string{"after", "before"} {
		for index := 0; index < 5_001; index++ {
			file := ReviewPreflightFile{
				Path:        fmt.Sprintf("%s/files/%05d.txt", directory, index),
				MediaType:   "text/plain",
				SHA256:      "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
				Disposition: "text",
			}
			if index < 9 {
				file.Path = fmt.Sprintf("%s/assets/%05d.png", directory, index)
				file.MediaType = "image/png"
				file.Size = ports.WorkspaceSnapshotMaxFileBytes
				file.SHA256 = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
				file.Disposition = "binary_preserved"
			}
			files = append(files, file)
		}
	}
	result.FileSets[0].PolicyIdentity = "index;layout=ordinary-directories-v1"
	result.FileSets[0].Files = files
	id, err := reviewPreflightFileSetID(result.FileSets[0].PolicyIdentity, files)
	if err != nil {
		t.Fatal(err)
	}
	result.FileSets[0].ID = id
	for index := range result.Transmissions {
		result.Transmissions[index].FileSetID = id
	}
	if err := result.Validate(); err != nil {
		t.Fatalf("bounded Git provider view: %v", err)
	}
}

func TestReviewPreflightValidateReportsAuthoritativeLimitInvariant(t *testing.T) {
	tests := []struct {
		name, policy, code, invariant string
		fileCount                     int
	}{
		{name: "snapshot", policy: "current", code: "preflight_result_validation_failed", invariant: "snapshot_resource_limit", fileCount: 17},
		{name: "provider view", policy: "index;layout=ordinary-directories-v1", code: "provider_view_limit_validation_failed", invariant: "provider_view_resource_limit", fileCount: 33},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := loadReviewPreflightExample(t)
			files := make([]ReviewPreflightFile, test.fileCount)
			for index := range files {
				files[index] = ReviewPreflightFile{
					Path: fmt.Sprintf("files/%05d.png", index), MediaType: "image/png",
					Size:        ports.WorkspaceSnapshotMaxFileBytes,
					SHA256:      "sha256:0000000000000000000000000000000000000000000000000000000000000000",
					Disposition: "binary_preserved",
				}
			}
			setReviewPreflightFiles(t, &result, test.policy, files)
			err := result.Validate()
			failure, ok := err.(*reviewPreflightValidationFailure)
			if !ok || failure.code != test.code || failure.invariant != test.invariant || !failure.hasLimitFacts ||
				failure.fileCount != test.fileCount || failure.byteCount != int64(test.fileCount)*ports.WorkspaceSnapshotMaxFileBytes {
				t.Fatalf("limit validation failure = %#v, present=%t, err=%v", failure, ok, err)
			}
		})
	}
}

func setReviewPreflightFiles(t *testing.T, result *ReviewPreflightResult, policy string, files []ReviewPreflightFile) {
	t.Helper()
	result.FileSets[0].PolicyIdentity = policy
	result.FileSets[0].Files = files
	id, err := reviewPreflightFileSetID(policy, files)
	if err != nil {
		t.Fatal(err)
	}
	result.FileSets[0].ID = id
	for index := range result.Transmissions {
		result.Transmissions[index].FileSetID = id
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
