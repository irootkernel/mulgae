//go:build darwin && arm64

package e2e

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// These consumer DTOs deliberately import no Mulgae producer package, schema,
// generator, or version constant. Unknown fields are additive; versions and
// identity availability are explicit compatibility decisions.
type verifiedConsumerResult struct {
	ProjectBinding      string            `json:"project_binding"`
	Capabilities        map[string]string `json:"capabilities"`
	SourceIdentity      string            `json:"source_identity_sha256"`
	CaptureIdentity     string            `json:"capture_identity"`
	CaptureAvailability string            `json:"capture_availability"`
	PublicationReceipt  string            `json:"publication_receipt"`
	RunID               string            `json:"run_id"`
	InvocationID        string            `json:"invocation_id"`
	Guarded             bool              `json:"guarded"`
	RequestDigest       string            `json:"request_digest"`
	TerminalExitCode    int               `json:"terminal_exit_code"`
	Target              struct {
		SHA256 string `json:"sha256"`
	} `json:"target"`
	RequestReceipt struct {
		SchemaVersion   string `json:"schema_version"`
		ProjectBinding  string `json:"project_binding"`
		CaptureIdentity string `json:"capture_identity"`
		RequestDigest   string `json:"request_digest"`
	} `json:"request_receipt"`
	Findings []struct {
		ID        string `json:"id"`
		DetailURI string `json:"detail_uri"`
		Evidence  []struct {
			Index int    `json:"index"`
			URI   string `json:"uri"`
		} `json:"evidence"`
	} `json:"findings"`
	RoleReports []struct {
		Role string `json:"role"`
		URI  string `json:"uri"`
	} `json:"role_reports"`
	FindingCount  int    `json:"finding_count"`
	ReturnedCount int    `json:"returned_count"`
	Content       string `json:"content"`
	ContentSHA256 string `json:"content_sha256"`
	Encoding      string `json:"encoding"`
	Offset        int64  `json:"offset"`
	TotalBytes    int64  `json:"total_bytes"`
	ReturnedBytes int64  `json:"returned_bytes"`
	NextOffset    *int64 `json:"next_offset"`
}

func decodeVerifiedConsumerEnvelope(raw []byte, transport, operation string, legacy bool) (json.RawMessage, error) {
	var envelope struct {
		SchemaVersion string          `json:"schema_version"`
		Command       string          `json:"command"`
		Tool          string          `json:"tool"`
		Outcome       string          `json:"outcome"`
		Result        json.RawMessage `json:"result"`
		Data          json.RawMessage `json:"data"`
		Exit          *struct {
			Code *int   `json:"code"`
			Kind string `json:"kind"`
		} `json:"exit"`
		Reasons *[]struct {
			Category string `json:"category"`
			Code     string `json:"code"`
		} `json:"reasons"`
		Error *struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, err
	}
	if transport == "cli" {
		if envelope.Command != operation || envelope.SchemaVersion != "mulgae-command-result.v13" && (legacy || envelope.SchemaVersion != "mulgae-command-result.v18" && envelope.SchemaVersion != "mulgae-command-result.v19") {
			return nil, fmt.Errorf("unsupported CLI contract")
		}
		if envelope.Exit == nil || envelope.Exit.Code == nil || *envelope.Exit.Code != 0 || envelope.Exit.Kind != "success" || envelope.Reasons == nil {
			return nil, fmt.Errorf("CLI failure or missing outcome")
		}
		for _, reason := range *envelope.Reasons {
			if operation != "review" && operation != "rerun" || reason.Category != "evidence" || reason.Code == "" {
				return nil, fmt.Errorf("unexpected CLI diagnostic")
			}
		}
		if len(envelope.Result) == 0 || string(envelope.Result) == "null" {
			return nil, fmt.Errorf("missing CLI result")
		}
		return envelope.Result, nil
	}
	if transport != "mcp" || envelope.SchemaVersion != "mulgae-mcp-tool-result.v1" || envelope.Tool != operation {
		return nil, fmt.Errorf("unsupported MCP contract")
	}
	if envelope.Outcome == "error" && envelope.Error != nil {
		return nil, fmt.Errorf("MCP failure: %s", envelope.Error.Code)
	}
	if envelope.Error != nil || envelope.Outcome != "success" && envelope.Outcome != "request_changes" || len(envelope.Data) == 0 || string(envelope.Data) == "null" {
		return nil, fmt.Errorf("invalid MCP outcome")
	}
	return envelope.Data, nil
}

func decodeVerifiedConsumerResult(raw []byte) (verifiedConsumerResult, error) {
	var value verifiedConsumerResult
	if err := json.Unmarshal(raw, &value); err != nil {
		return value, err
	}
	for name, version := range value.Capabilities {
		switch name {
		case "project_binding", "execution_guard", "capture_identity", "inspection", "finding_pages", "finding_details", "report_content", "indexed_evidence", "composite_evidence", "live_source", "source_evidence":
		default:
			return value, fmt.Errorf("unknown capability %s", name)
		}
		if version != "" && version != "v1" {
			return value, fmt.Errorf("unsupported capability %s", name)
		}
	}
	switch value.CaptureAvailability {
	case "":
		// Legacy absence does not confer verified capture support.
		if value.CaptureIdentity != "" && value.RequestReceipt.RequestDigest == "" && value.RequestDigest == "" {
			return value, fmt.Errorf("capture identity without availability")
		}
	case "verified":
		if !consumerDigest(value.CaptureIdentity) {
			return value, fmt.Errorf("verified capture has no digest")
		}
	case "capture_identity_unavailable", "not_captured":
		if value.CaptureIdentity != "" {
			return value, fmt.Errorf("unavailable capture has a digest")
		}
	default:
		return value, fmt.Errorf("unsupported capture availability")
	}
	return value, nil
}

func consumerDigest(value string) bool {
	if len(value) != 71 || !strings.HasPrefix(value, "sha256:") || strings.ToLower(value) != value || value == "sha256:"+strings.Repeat("0", 64) {
		return false
	}
	_, err := hex.DecodeString(value[7:])
	return err == nil
}

func TestVerifiedWorkflowFrozenConsumers(t *testing.T) {
	for _, tc := range []struct {
		name, transport, operation string
		legacy, reject             bool
	}{
		{"legacy-cli", "cli", "findings", true, false},
		{"legacy-cli", "cli", "findings", false, false},
		{"current-cli", "cli", "inspect", false, false},
		{"current-cli", "cli", "inspect", true, true},
		{"historical-mcp", "mcp", "inspect_review", false, false},
		{"unsupported-mcp", "mcp", "inspect_review", false, true},
		{"corrupt-mcp", "mcp", "inspect_review", false, true},
		{"inconsistent-cli", "cli", "inspect", false, true},
		{"error-cli", "cli", "inspect", false, true},
		{"missing-outcome-cli", "cli", "inspect", false, true},
	} {
		t.Run(fmt.Sprintf("%s/legacy=%t", tc.name, tc.legacy), func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join("testdata", "verified-consumer", tc.name+".json"))
			if err != nil {
				t.Fatal(err)
			}
			data, err := decodeVerifiedConsumerEnvelope(raw, tc.transport, tc.operation, tc.legacy)
			var decoded verifiedConsumerResult
			if err == nil {
				decoded, err = decodeVerifiedConsumerResult(data)
			}
			if (err != nil) != tc.reject {
				t.Fatalf("frozen consumer rejection=%t want=%t: %v", err != nil, tc.reject, err)
			}
			if tc.name == "historical-mcp" && (decoded.CaptureIdentity != "" || decoded.CaptureAvailability != "capture_identity_unavailable" || !consumerDigest(decoded.PublicationReceipt)) {
				t.Fatal("historical absence lost its coherent publication")
			}
			if tc.name == "legacy-cli" && (decoded.Capabilities != nil || decoded.CaptureIdentity != "" || decoded.PublicationReceipt != "") {
				t.Fatal("legacy response gained native verification authority")
			}
			if tc.name == "corrupt-mcp" && (err == nil || !strings.Contains(err.Error(), "artifact_integrity")) {
				t.Fatal("integrity failure became historical unavailability")
			}
		})
	}
}
