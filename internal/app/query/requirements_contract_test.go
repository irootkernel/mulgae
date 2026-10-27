package query

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/adapters/jsonschema"
	"github.com/irootkernel/mulgae/internal/builtin"
	"github.com/irootkernel/mulgae/internal/ports"
)

func TestRequirementsReadRejectsNoChangeReasonForEvaluatedResults(t *testing.T) {
	fixture, err := os.ReadFile("../../builtin/assets/examples/requirements-read.v1.valid.json")
	if err != nil {
		t.Fatal(err)
	}
	validator, err := jsonschema.New(context.Background(), builtin.NewCatalog())
	if err != nil {
		t.Fatal(err)
	}
	id, _ := ports.ParseAssetID("https://mulgae.local/schemas/mulgae-requirements-read.v1.schema.json")
	for _, test := range []struct {
		name         string
		availability string
		origin       string
		reason       string
		evaluated    int
		emptyPage    bool
		valid        bool
	}{
		{"no change", "not_run", "mulgae_derived", "no_change_target", 0, false, true},
		{"evaluated no-change contradiction", "evaluated", "mulgae_derived", "no_change_target", 0, false, false},
		{"ordinary placeholder", "evaluated", "mulgae_derived", "answer_omitted", 0, false, true},
		{"provider unverified", "evaluated", "provider", "insufficient_evidence", 1, false, true},
		{"ordinary empty page", "evaluated", "", "", 0, true, true},
		{"no-change empty page", "not_run", "", "", 0, true, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var value map[string]any
			if err := json.Unmarshal(fixture, &value); err != nil {
				t.Fatal(err)
			}
			value["availability"], value["evaluated_count"] = test.availability, test.evaluated
			if test.emptyPage {
				value["items"], value["next_cursor"] = []any{}, "page-2"
			} else {
				row := value["items"].([]any)[0].(map[string]any)
				row["origin"], row["reason"] = test.origin, test.reason
			}
			raw, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			if err := validator.Validate(context.Background(), id, raw); (err == nil) != test.valid {
				t.Fatalf("read state accepted=%v, want %v: %v", err == nil, test.valid, err)
			}
		})
	}
}

func TestRequirementsReadContractSeparatesHistoricalCountsAndContent(t *testing.T) {
	raw, err := os.ReadFile("../../builtin/assets/examples/requirements-read.v1.valid.json")
	if err != nil {
		t.Fatal(err)
	}
	validator, err := jsonschema.New(context.Background(), builtin.NewCatalog())
	if err != nil {
		t.Fatal(err)
	}
	id, _ := ports.ParseAssetID("https://mulgae.local/schemas/mulgae-requirements-read.v1.schema.json")
	var value map[string]any
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatal(err)
	}
	if err := validator.Validate(context.Background(), id, raw); err != nil {
		t.Fatal(err)
	}
	for _, availability := range []string{"not_requested", "unavailable"} {
		value["availability"], value["items"], value["input_sha256"], value["next_cursor"] = availability, []any{}, nil, nil
		value["selected_count"], value["evaluated_count"] = 0, 0
		if availability == "unavailable" {
			value["selected_count"], value["evaluated_count"] = nil, nil
		}
		raw, _ := json.Marshal(value)
		if err := validator.Validate(context.Background(), id, raw); err != nil {
			t.Fatalf("honest absence rejected: %v", err)
		}
		value["selected_count"] = 1
		raw, _ = json.Marshal(value)
		if err := validator.Validate(context.Background(), id, raw); err == nil {
			t.Fatal("absent assessment invented selected coverage")
		}
	}
	legacyRaw, err := os.ReadFile("../../builtin/assets/examples/publication-receipt.v1.valid.json")
	if err != nil {
		t.Fatal(err)
	}
	legacyReceipt, err := DecodeInspectionReceipt(legacyRaw)
	if err != nil || legacyReceipt.SchemaVersion != InspectionReceiptVersion || legacyReceipt.SourceIdentitySHA256 != "" {
		t.Fatalf("legacy receipt did not retain its captured identity: %v", err)
	}
	var legacy map[string]any
	if err := json.Unmarshal(legacyRaw, &legacy); err != nil {
		t.Fatal(err)
	}
	value["receipt"], value["availability"] = legacy, "unavailable"
	value["selected_count"], value["evaluated_count"] = nil, nil
	legacyRead, _ := json.Marshal(value)
	if err := validator.Validate(context.Background(), id, legacyRead); err != nil {
		t.Fatalf("historical unavailable result rejected its original v1 receipt: %v", err)
	}
	value["availability"], value["selected_count"], value["evaluated_count"] = "not_requested", 0, 0
	legacyRead, _ = json.Marshal(value)
	if err := validator.Validate(context.Background(), id, legacyRead); err == nil {
		t.Fatal("historical v1 receipt invented a new not-requested capability")
	}
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatal(err)
	}
	value["next_cursor"] = strings.Repeat("a", 4097)
	raw, _ = json.Marshal(value)
	if err := validator.Validate(context.Background(), id, raw); err == nil {
		t.Fatal("unbounded continuation cursor accepted")
	}
	// Prose larger than the structured envelope is consumed through the existing
	// publication/digest-bound chunk API, without embedding it in metadata pages.
	receiptRaw, err := os.ReadFile("../../builtin/assets/examples/publication-receipt.v2.valid.json")
	if err != nil {
		t.Fatal(err)
	}
	var receipt InspectionReceipt
	if err := json.Unmarshal(receiptRaw, &receipt); err != nil {
		t.Fatal(err)
	}
	identity, err := receipt.Identity()
	if err != nil {
		t.Fatal(err)
	}
	prose := bytes.Repeat([]byte("requirement content\n"), 500000)
	chunk, err := NewContentChunk(prose, "application/json", true, identity, ContentContinuation{})
	if err != nil || chunk.ReturnedBytes > MaxVerifiedContentChunkBytes || chunk.TotalBytes != int64(len(prose)) || chunk.NextOffset == nil {
		t.Fatalf("unbounded content did not use bounded continuation: %v", err)
	}
	continuation := ContentContinuation{Offset: *chunk.NextOffset, PublicationReceipt: chunk.PublicationReceipt, ContentSHA256: chunk.ContentSHA256}
	if _, err := NewContentChunk(prose, "application/json", true, identity, continuation); err != nil {
		t.Fatal(err)
	}
	continuation.ContentSHA256 = "sha256:" + strings.Repeat("f", 64)
	if _, err := NewContentChunk(prose, "application/json", true, identity, continuation); err == nil {
		t.Fatal("content continuation escaped the complete-content digest")
	}
}
