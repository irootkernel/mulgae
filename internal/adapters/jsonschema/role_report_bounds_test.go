package jsonschema

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestRoleReportSchemaBoundsAcceptAndReject(t *testing.T) {
	t.Parallel()

	commandDoc := readAssetJSON(t, "schemas/mulgae-command-result.v2.schema.json")
	manifestDoc := readAssetJSON(t, "schemas/mulgae-run-manifest.v1.schema.json")
	commandID := "https://mulgae.local/schemas/mulgae-command-result.v2.schema.json"
	manifestID := "https://mulgae.local/schemas/mulgae-run-manifest.v1.schema.json"

	seven := []any{
		map[string]any{"role": "logic", "uri": "role-reports/logic.md"},
		map[string]any{"role": "security", "uri": "role-reports/security.md"},
		map[string]any{"role": "maintainability", "uri": "role-reports/maintainability.md"},
		map[string]any{"role": "product", "uri": "role-reports/product.md"},
		map[string]any{"role": "documentation", "uri": "role-reports/documentation.md"},
		map[string]any{"role": "testing", "uri": "role-reports/testing.md"},
		map[string]any{"role": "artist", "uri": "role-reports/artist.md"},
	}
	if err := validateAgainstRef(t, commandID, commandDoc, commandID+"#/$defs/role_report_uris", seven); err != nil {
		t.Fatalf("seven canonical role_report_uris rejected: %v", err)
	}
	eight := append(append([]any{}, seven...), map[string]any{"role": "logic", "uri": "role-reports/logic-extra.md"})
	if err := validateAgainstRef(t, commandID, commandDoc, commandID+"#/$defs/role_report_uris", eight); err == nil {
		t.Fatal("role_report_uris accepted more than seven entries")
	}
	if err := validateAgainstRef(t, commandID, commandDoc, commandID+"#/$defs/role_report_uris", []any{
		map[string]any{"role": "unknown", "uri": "role-reports/unknown.md"},
	}); err == nil {
		t.Fatal("role_report_uris accepted a non-canonical role")
	}

	followupSuccess := map[string]any{
		"kind":                         "followup_started",
		"session_id":                   "s_019f596a-cf80-7c67-b265-f37053d51ccf",
		"run_id":                       "r_019f596a-e254-7b6f-93cd-4c67cf3d4b2e",
		"followup_artifact_uri":        ".mulgae/s_019f596a-cf80-7c67-b265-f37053d51ccf/r_019f596a-e254-7b6f-93cd-4c67cf3d4b2e/followup.json",
		"resolution":                   "resolved",
		"structured_extraction_status": "structured",
		"role_report_uris":             []any{map[string]any{"role": "logic", "uri": "role-reports/logic.md"}},
	}
	if err := validateAgainstRef(t, commandID, commandDoc, commandID+"#/$defs/results/followup/oneOf/0", followupSuccess); err != nil {
		t.Fatalf("followup success with exactly one role_report_uris rejected: %v", err)
	}
	followupReportsOnly := map[string]any{
		"kind":                         "followup_started",
		"session_id":                   "s_019f596a-cf80-7c67-b265-f37053d51ccf",
		"run_id":                       "r_019f596a-e254-7b6f-93cd-4c67cf3d4b2e",
		"followup_artifact_uri":        ".mulgae/s_019f596a-cf80-7c67-b265-f37053d51ccf/r_019f596a-e254-7b6f-93cd-4c67cf3d4b2e/followup.json",
		"resolution":                   nil,
		"structured_extraction_status": "reports_only",
		"role_report_uris":             []any{map[string]any{"role": "logic", "uri": "role-reports/logic.md"}},
	}
	if err := validateAgainstRef(t, commandID, commandDoc, commandID+"#/$defs/results/followup/oneOf/1", followupReportsOnly); err != nil {
		t.Fatalf("reports-only followup success rejected: %v", err)
	}
	followupZero := cloneMap(followupSuccess)
	followupZero["role_report_uris"] = []any{}
	if err := validateAgainstRef(t, commandID, commandDoc, commandID+"#/$defs/results/followup/oneOf/0", followupZero); err == nil {
		t.Fatal("followup success accepted zero role_report_uris")
	}
	followupTwo := cloneMap(followupSuccess)
	followupTwo["role_report_uris"] = []any{
		map[string]any{"role": "logic", "uri": "role-reports/logic.md"},
		map[string]any{"role": "security", "uri": "role-reports/security.md"},
	}
	if err := validateAgainstRef(t, commandID, commandDoc, commandID+"#/$defs/results/followup/oneOf/0", followupTwo); err == nil {
		t.Fatal("followup success accepted more than one role_report_uris")
	}

	manifestReports := []any{
		map[string]any{
			"role": "logic", "path": "role-reports/logic.md",
			"sha256":      "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
			"byte_length": 12, "provider_instance": "logic-provider",
			"attempt_id": "a_019f596a-d048-79e7-b2b7-59822f012273", "content_type": "text/markdown",
			"transport": "stdout",
		},
	}
	if err := validateAgainstRef(t, manifestID, manifestDoc, manifestID+"#/properties/role_reports", manifestReports); err != nil {
		t.Fatalf("manifest role_reports rejected: %v", err)
	}
	largeReport := cloneMap(manifestReports[0].(map[string]any))
	largeReport["byte_length"] = 10 << 20
	if err := validateAgainstRef(t, manifestID, manifestDoc, manifestID+"#/properties/role_reports", []any{largeReport}); err != nil {
		t.Fatalf("manifest role_reports rejected a large report identity: %v", err)
	}
	if err := validateAgainstRef(t, manifestID, manifestDoc, manifestID+"#/properties/role_reports", eightManifestRoleReports()); err == nil {
		t.Fatal("manifest role_reports accepted more than seven entries")
	}
}

func TestReviewPreflightV2RolePathSchemaBounds(t *testing.T) {
	t.Parallel()

	document := readAssetJSON(t, "schemas/mulgae-review-preflight.v2.schema.json")
	resourceID := "https://mulgae.local/schemas/mulgae-review-preflight.v2.schema.json"
	ref := resourceID + "#/properties/budget/properties/role_paths"
	roles := []string{"logic", "security", "maintainability", "product", "documentation", "testing", "artist"}
	paths := make([]any, 0, len(roles))
	for _, role := range roles {
		paths = append(paths, map[string]any{
			"role": role, "provider_instance": "zcode-" + role,
			"invocation_count": 2, "transition_count": 1,
			"invocation_timeouts": "1h0m0s", "deadline": "1h0m2s",
		})
	}
	if err := validateAgainstRef(t, resourceID, document, ref, paths); err != nil {
		t.Fatalf("seven unique role paths rejected: %v", err)
	}

	duplicateRole := append([]any(nil), paths...)
	duplicateRole[1] = map[string]any{
		"role": "logic", "provider_instance": "agy-logic",
		"invocation_count": 2, "transition_count": 1,
		"invocation_timeouts": "30m0s", "deadline": "30m2s",
	}
	if err := validateAgainstRef(t, resourceID, document, ref, duplicateRole); err == nil {
		t.Fatal("role_paths accepted the same role with a different provider")
	}

	for name, field := range map[string]string{"invocation count": "invocation_count", "transition count": "transition_count"} {
		t.Run(name, func(t *testing.T) {
			invalid := []any{map[string]any{
				"role": "logic", "provider_instance": "zcode-logic",
				"invocation_count": 2, "transition_count": 1,
				"invocation_timeouts": "1h0m0s", "deadline": "1h0m2s",
			}}
			invalid[0].(map[string]any)[field] = 3
			if err := validateAgainstRef(t, resourceID, document, ref, invalid); err == nil {
				t.Fatalf("role_paths accepted %s above its v2 bound", field)
			}
		})
	}
}

func eightManifestRoleReports() []any {
	roles := []string{"logic", "security", "maintainability", "product", "documentation", "testing", "artist", "logic"}
	reports := make([]any, 0, len(roles))
	for index, role := range roles {
		reports = append(reports, map[string]any{
			"role": role, "path": "role-reports/" + role + ".md",
			"sha256":      "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
			"byte_length": index + 1, "provider_instance": role + "-provider",
			"attempt_id": "a_019f596a-d048-79e7-b2b7-59822f012273", "content_type": "text/markdown",
			"transport": "staged_file",
		})
	}
	return reports
}

func readAssetJSON(t *testing.T, relative string) any {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	path := filepath.Join(filepath.Dir(thisFile), "..", "..", "builtin", "assets", filepath.FromSlash(relative))
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var document any
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	return document
}

func validateAgainstRef(t *testing.T, resourceID string, resource any, ref string, value any) error {
	t.Helper()
	wrapperID := "https://mulgae.local/schemas/role-report-bounds-wrapper.json"
	compiler := newSchemaCompiler()
	if err := compiler.AddResource(resourceID, resource); err != nil {
		t.Fatal(err)
	}
	if err := compiler.AddResource(wrapperID, map[string]any{
		"$schema": draft2020URI,
		"$id":     wrapperID,
		"$ref":    ref,
	}); err != nil {
		t.Fatal(err)
	}
	schema, err := compiler.Compile(wrapperID)
	if err != nil {
		t.Fatal(err)
	}
	return schema.Validate(value)
}

func cloneMap(value map[string]any) map[string]any {
	cloned := make(map[string]any, len(value))
	for key, item := range value {
		cloned[key] = item
	}
	return cloned
}
