package mulgae

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRequirementsVerifiedReadSelectorsKeepFindingFiltersIndependent(t *testing.T) {
	run := "r_01900000-0000-7000-8000-000000000002"
	invocation, err := Parse([]string{"inspect", "--run", run, "--severity", "blocker", "--limit", "10", "--requirements-limit", "1", "--requirements-cursor", "opaque"}, testProjectRoot, testRequestID)
	if err != nil {
		t.Fatal(err)
	}
	request := invocation.verifiedRead
	if request == nil || request.Page.RequirementsLimit != 1 || request.Page.RequirementsCursor != "opaque" || request.Page.Limit != 10 || string(request.Page.MinimumSeverity) != "blocker" {
		t.Fatal("requirements page replaced finding selectors")
	}
	raw, _ := invocation.RequestJSON()
	var decoded map[string]any
	if json.Unmarshal(raw, &decoded) != nil || decoded["requirements_limit"] != float64(1) || decoded["requirements_cursor"] != "opaque" {
		t.Fatal("requirements selectors missing from command request")
	}
	invocation, err = Parse([]string{"read-report", "--run", run, "--requirement", "A_a-1", "--offset", "16384", "--expected-publication-receipt", "sha256:" + strings.Repeat("1", 64), "--expected-content-sha256", "sha256:" + strings.Repeat("2", 64)}, testProjectRoot, testRequestID)
	if err != nil || invocation.verifiedRead.RequirementID != "A_a-1" || invocation.verifiedRead.Continuation.Offset != 16384 {
		t.Fatalf("requirement chunk selector failed: %v", err)
	}
	for _, args := range [][]string{
		{"read-report", "--run", run, "--requirement", "A", "--role", "logic"},
		{"read-report", "--run", run, "--requirement", "../A"},
		{"read-report", "--run", run, "--requirement", "é"},
		{"read-report", "--run", run, "--requirement", "A", "--offset", "16384"},
		{"inspect", "--run", run, "--requirements-limit", "0"},
		{"inspect", "--run", run, "--requirements-limit", "101"},
		{"inspect", "--run", run, "--requirements-cursor", strings.Repeat("x", 4097)},
		{"inspect", "--run", run, "--requirement", "A"},
	} {
		if _, err := Parse(args, testProjectRoot, testRequestID); err == nil {
			t.Fatalf("invalid requirement selector accepted: %v", args[:3])
		}
	}
}
