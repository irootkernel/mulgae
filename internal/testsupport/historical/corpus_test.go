package historical

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHistoricalCorpusRecords(t *testing.T) {
	corpus, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"ordinary-v1-nonminified", "ordinary-v2", "no-change", "artist", "rerun-exact", "rerun-recompose", "delta", "recovery-child-v2", "failed-recovery", "retired-kimi", "composite-legacy-v1", "composite-copied-v1", "composite-mixed-v1", "composite-copied-v2", "followup-resolved", "followup-partially_resolved", "followup-still_open", "followup-unclear"}
	if corpus.SourceCommit != "ce88495ad339e7b3b7fcf47cc8c9313939cf496d" {
		t.Fatal("corpus provenance changed")
	}
	seen := map[string]bool{}
	controls := map[string]bool{}
	for _, c := range corpus.Cases {
		seen[c.ID] = true
		actualFormats := map[string]bool{}
		for _, raw := range c.Artifacts() {
			if len(raw) == 0 || raw[0] != '{' {
				continue
			}
			var envelope struct {
				SchemaVersion string `json:"schema_version"`
			}
			if json.Unmarshal(raw, &envelope) == nil && envelope.SchemaVersion != "" {
				actualFormats[envelope.SchemaVersion] = true
			}
		}
		if len(actualFormats) != len(c.Formats) {
			t.Fatalf("format inventory changed for %s", c.ID)
		}
		for _, version := range c.Formats {
			if !actualFormats[version] {
				t.Fatalf("%s declares absent format %s", c.ID, version)
			}
		}
		if c.ID == "composite-legacy-v1" {
			var index struct {
				SchemaVersion string `json:"schema_version"`
			}
			path := c.SessionID + "/" + c.RunID + "/support/index.json"
			if err := json.Unmarshal(c.Artifacts()[path], &index); err != nil {
				t.Fatal(err)
			}
			if index.SchemaVersion != "mulgae-run-support-index.v1" {
				t.Fatal("legacy composite support index was upgraded")
			}
		}
		for _, control := range c.Controls {
			controls[control] = true
		}
		for _, file := range c.Files {
			if strings.Contains(file.Path, "/attempts/") || strings.HasSuffix(file.Path, ".raw") || strings.HasSuffix(file.Path, ".jsonl") {
				t.Fatalf("transcript/runtime input: %s", file.Path)
			}
		}
	}
	for _, id := range want {
		if !seen[id] {
			t.Errorf("missing family %s", id)
		}
	}
	for _, control := range []string{"missing", "tampered", "rebound", "cross-run", "wrong-lineage"} {
		if !controls[control] {
			t.Errorf("missing control %s", control)
		}
	}
	c := corpus.Cases[0]
	files := c.Artifacts()
	for path, raw := range files {
		if len(raw) > 0 {
			raw[0] ^= 1
			if string(raw) == string(c.Artifacts()[path]) {
				t.Fatal("loader aliases owned bytes")
			}
			break
		}
	}
}
func TestHistoricalCorpusRejectsChecksumMutation(t *testing.T) {
	corpus, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	// A complete copy retains every record; only one input byte is corrupted.
	if err := os.CopyFS(root, os.DirFS("testdata")); err != nil {
		t.Fatal(err)
	}
	file := corpus.Cases[0].Files[0]
	path := filepath.Join(root, file.Data)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw[0] ^= 1
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFrom(root); err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("mutation accepted: %v", err)
	}
}
