package jsonschema

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/builtin"
)

func TestCommandResultV19BindsLiveReviewAndRejectsRetiredAdmission(t *testing.T) {
	validator := newBuiltinValidator(t)
	catalog := builtin.NewCatalog()
	_, raw, err := catalog.Read(context.Background(), mustAssetID(t, "example:review-preflight.v8.valid.json"))
	if err != nil {
		t.Fatal(err)
	}
	var preflight map[string]any
	if err := json.Unmarshal(raw, &preflight); err != nil {
		t.Fatal(err)
	}
	request := map[string]any{
		"command": "review", "request_id": "i_019f596a-e201-7a4b-8d76-1cf503a1849e",
		"target":    map[string]any{"kind": "stage", "value": ""},
		"objective": nil, "roles": []string{"logic"}, "role_selection": "explicit",
		"artist_brief": nil, "artist_design_specs": []string{}, "session_id": nil,
		"output_format": "json", "preflight": true,
		"expected_project_binding": preflight["project_binding"],
	}
	envelope := map[string]any{
		"schema_version": "mulgae-command-result.v19", "command": "review",
		"request": request, "completed_at": "2026-10-04T00:00:00Z",
		"exit": map[string]any{"code": 0, "kind": "success"}, "reasons": []any{},
		"result": map[string]any{"kind": "review_preflight", "preflight": preflight},
	}
	schema := mustAssetID(t, "https://mulgae.local/schemas/mulgae-command-result.v19.schema.json")
	validate := func() error {
		data, err := json.Marshal(envelope)
		if err != nil {
			t.Fatal(err)
		}
		return validator.Validate(context.Background(), schema, data)
	}
	if err := validate(); err != nil {
		t.Fatalf("independent binding and live preflight rejected: %v", err)
	}
	request["expected_request_digest"] = "sha256:" + strings.Repeat("a", 64)
	if err := validate(); err == nil {
		t.Fatal("capture-bound request accepted")
	}
	delete(request, "expected_request_digest")
	for _, kind := range []string{"dirty", "patch", "stdin"} {
		request["target"] = map[string]any{"kind": kind, "value": "retired"}
		if err := validate(); err == nil {
			t.Fatalf("retired source selector accepted: %s", kind)
		}
	}
	request["target"] = map[string]any{"kind": "stage", "value": ""}
	delete(request, "preflight")
	envelope["result"] = map[string]any{
		"kind": "review_started", "session_id": "s_019f596a-cf80-7c67-b265-f37053d51ccf",
		"run_id":           "r_019f596a-cf80-7c67-b265-f37053d51ccf",
		"run_manifest_uri": ".mulgae/store/run-manifest.json", "review_artifact_uri": ".mulgae/store/final.json",
		"role_report_uris": []any{}, "guarded": false, "project_binding": preflight["project_binding"],
		"source_identity_sha256": preflight["source_identity_sha256"],
	}
	if err := validate(); err != nil {
		t.Fatalf("live terminal result rejected: %v", err)
	}
	result := envelope["result"].(map[string]any)
	request["target"] = map[string]any{"kind": "workspace", "value": ""}
	delete(request, "expected_project_binding")
	result["project_binding"] = ""
	if err := validate(); err != nil {
		t.Fatalf("unguarded non-Git workspace rejected: %v", err)
	}
	result["guarded"] = true
	if err := validate(); err == nil {
		t.Fatal("non-Git workspace falsely claimed guarded execution")
	}
	result["guarded"] = false
	request["expected_project_binding"] = preflight["project_binding"]
	if err := validate(); err == nil {
		t.Fatal("non-Git result silently ignored an expected binding")
	}
	delete(request, "expected_project_binding")
	request["target"] = map[string]any{"kind": "stage", "value": ""}
	if err := validate(); err == nil {
		t.Fatal("Git-only source lost binding authority")
	}
	result["project_binding"] = preflight["project_binding"]
	delete(result, "source_identity_sha256")
	if err := validate(); err == nil {
		t.Fatal("terminal live result lost source identity")
	}
	result["source_identity_sha256"] = preflight["source_identity_sha256"]
	result["capture_identity"] = "sha256:" + strings.Repeat("b", 64)
	if err := validate(); err == nil {
		t.Fatal("live result accepted immutable capture claim")
	}
	for _, command := range []string{"followup", "delta", "rerun", "compose"} {
		envelope["command"] = command
		if err := validate(); err == nil {
			t.Fatalf("retired command envelope accepted: %s", command)
		}
	}
}

func TestLivePreflightSchemasKeepNonGitBindingExplicit(t *testing.T) {
	validator := newBuiltinValidator(t)
	_, raw, err := builtin.NewCatalog().Read(context.Background(), mustAssetID(t, "example:review-preflight.v8.valid.json"))
	if err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatal(err)
	}
	value["project_binding"] = ""
	value["capabilities"].(map[string]any)["project_binding"] = ""
	target := value["target"].(map[string]any)
	target["scope"], target["base_oid"] = "workspace", ""
	for _, schemaName := range []string{"mulgae-review-preflight.v8", "mulgae-command-result.v19"} {
		t.Run(schemaName, func(t *testing.T) {
			schema := mustAssetID(t, "https://mulgae.local/schemas/"+schemaName+".schema.json")
			validate := func() error {
				var document any = value
				if schemaName == "mulgae-command-result.v19" {
					document = map[string]any{"schema_version": schemaName, "command": "review", "request": map[string]any{"command": "review", "request_id": "i_019f596a-e201-7a4b-8d76-1cf503a1849e", "target": map[string]any{"kind": "workspace", "value": ""}, "objective": nil, "roles": []string{"logic"}, "role_selection": "explicit", "artist_brief": nil, "artist_design_specs": []string{}, "session_id": nil, "output_format": "json", "preflight": true}, "completed_at": "2026-10-04T00:00:00Z", "exit": map[string]any{"code": 0, "kind": "success"}, "reasons": []any{}, "result": map[string]any{"kind": "review_preflight", "preflight": value}}
				}
				data, err := json.Marshal(document)
				if err != nil {
					t.Fatal(err)
				}
				return validator.Validate(context.Background(), schema, data)
			}
			if err := validate(); err != nil {
				t.Fatalf("non-Git preflight rejected: %v", err)
			}
			value["capabilities"].(map[string]any)["project_binding"] = "v1"
			if err := validate(); err == nil {
				t.Fatal("unavailable binding falsely advertised its capability")
			}
			value["capabilities"].(map[string]any)["project_binding"] = ""
			target["scope"], target["head_oid"] = "head", strings.Repeat("a", 40)
			if err := validate(); err == nil {
				t.Fatal("Git preflight accepted absent binding")
			}
			target["scope"], target["head_oid"] = "workspace", ""
		})
	}
}
