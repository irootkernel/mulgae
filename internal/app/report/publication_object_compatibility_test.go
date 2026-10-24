package report

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func m2Destinations() map[string]func() any {
	return map[string]func() any{"reportMulgaeDTO": func() any { return &reportMulgaeDTO{} }, "reportLineageDTO": func() any { return &reportLineageDTO{} }, "reportValidationDTO": func() any { return &reportValidationDTO{} }, "reportSeverityDTO": func() any { return &reportSeverityDTO{} }, "reportRoleDTO": func() any { return &reportRoleDTO{} }, "reportVisualEvidenceDTO": func() any { return &reportVisualEvidenceDTO{} }, "reportVisualBBoxDTO": func() any { return &reportVisualBBoxDTO{} }, "reportProductionProvenanceDTO": func() any { return &reportProductionProvenanceDTO{} }, "reportProductionProviderDTO": func() any { return &reportProductionProviderDTO{} }, "reportFinalDTO": func() any { return &reportFinalDTO{} }}
}

type m2CompatibilityOutcome struct {
	JSON      string `json:"json,omitempty"`
	ErrorType string `json:"error_type,omitempty"`
	Message   string `json:"message,omitempty"`
	Offset    int64  `json:"offset,omitempty"`
	Value     string `json:"value,omitempty"`
	Type      string `json:"type,omitempty"`
	Struct    string `json:"struct,omitempty"`
	Field     string `json:"field,omitempty"`
}
type m2CompatibilityCase struct {
	Destination string                 `json:"destination"`
	Input       string                 `json:"input"`
	Guard       string                 `json:"guard"`
	Outcome     m2CompatibilityOutcome `json:"outcome"`
}

func m2Observe(raw []byte, destination any) m2CompatibilityOutcome {
	err := decodeReportStrictObject(raw, destination)
	result := m2CompatibilityOutcome{}
	if err == nil {
		encoded, marshalErr := json.Marshal(destination)
		if marshalErr != nil {
			panic(marshalErr)
		}
		result.JSON = string(encoded)
	} else {
		result.ErrorType, result.Message = fmt.Sprintf("%T", err), err.Error()
		var typed *json.UnmarshalTypeError
		if errors.As(err, &typed) {
			result.Offset, result.Value, result.Type, result.Struct, result.Field = typed.Offset, typed.Value, typed.Type.String(), typed.Struct, typed.Field
		}
		var syntax *json.SyntaxError
		if errors.As(err, &syntax) {
			result.Offset = syntax.Offset
		}
	}
	return result
}

// A1 allows only exact, mechanically relocated Go names. All remaining fields
// and every caller prefix are still compared against the pre-move record.
func m2ApplyDiagnosticMove(t *testing.T, name string, before, after m2CompatibilityOutcome) {
	t.Helper()
	if before.Type == after.Type && before.Struct == after.Struct {
		t.Fatalf("empty diagnostic move %s", name)
	}
	if after.Struct != m2MovedStructName(before.Struct) || after.Type != m2MovedTypeName(before.Type) {
		t.Fatalf("undeclared diagnostic-name relocation %s: %+v => %+v", name, before, after)
	}
	message := before.Message
	if before.Struct != after.Struct {
		message = strings.Replace(message, before.Struct+"."+before.Field, after.Struct+"."+before.Field, 1)
	}
	if before.Type != after.Type {
		suffix := " of type " + before.Type
		if !strings.HasSuffix(message, suffix) {
			t.Fatalf("unexpected diagnostic suffix %s", name)
		}
		message = strings.TrimSuffix(message, suffix) + " of type " + after.Type
	}
	stable := after
	stable.Struct, stable.Type, stable.Message = before.Struct, before.Type, before.Message
	if message != after.Message || stable != before {
		t.Fatalf("non-name diagnostic change %s: %+v => %+v", name, before, after)
	}
}
func testM2ObjectCompatibility(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "m2-object-before.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cases map[string]m2CompatibilityCase
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}
	changes := map[string]m2CompatibilityOutcome{}
	if delta, err := os.ReadFile(filepath.Join("testdata", "m2-object-diagnostic-moves.json")); err == nil {
		if err := json.Unmarshal(delta, &changes); err != nil {
			t.Fatal(err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	for name, after := range changes {
		before, ok := cases[name]
		if !ok {
			t.Fatalf("unaccounted move %s", name)
		}
		m2ApplyDiagnosticMove(t, name, before.Outcome, after)
		before.Outcome = after
		cases[name] = before
	}
	destinations := m2Destinations()
	seen := map[string]bool{}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			makeValue, ok := destinations[c.Destination]
			if !ok {
				t.Fatalf("missing destination %s", c.Destination)
			}
			seen[c.Destination] = true
			got := m2Observe([]byte(c.Input), makeValue())
			if !reflect.DeepEqual(got, c.Outcome) {
				t.Fatalf("got %+v; want %+v", got, c.Outcome)
			}
			if c.Guard == "type" && (got.Type == "" || got.ErrorType == "") {
				t.Fatal("malformed input missed intended typed guard")
			}
		})
	}
	if len(seen) != len(destinations) {
		t.Fatalf("destinations exercised %d want %d", len(seen), len(destinations))
	}
}

func m2MovedStructName(value string) string {
	switch value {
	case "reportLineageDTO":
		return "ImmutableLineage"
	case "reportMulgaeDTO":
		return "BuildMetadata"
	case "reportProductionProvenanceDTO":
		return "ProductionProvenance"
	case "reportProductionProviderDTO":
		return "ProductionProvider"
	case "reportRoleDTO":
		return "RoleOutcome"
	case "reportSeverityDTO":
		return "SeverityThreshold"
	case "reportValidationDTO":
		return "Validation"
	case "reportVisualBBoxDTO":
		return "VisualBoundingBox"
	case "reportVisualEvidenceDTO":
		return "VisualEvidence"
	}
	return value
}

func m2MovedTypeName(value string) string {
	return strings.NewReplacer(
		"report.reportProductionProvenanceDTO", "artifactwire.ProductionProvenance",
		"report.reportProductionProviderDTO", "artifactwire.ProductionProvider",
		"report.reportVisualEvidenceDTO", "artifactwire.VisualEvidence",
		"report.reportValidationDTO", "artifactwire.Validation",
		"report.reportVisualBBoxDTO", "artifactwire.VisualBoundingBox",
		"report.reportSeverityDTO", "artifactwire.SeverityThreshold",
		"report.reportLineageDTO", "artifactwire.ImmutableLineage",
		"report.reportMulgaeDTO", "artifactwire.BuildMetadata",
		"report.reportRoleDTO", "artifactwire.RoleOutcome",
	).Replace(value)
}

func TestM2DiagnosticMoveRejectsNonNameChanges(t *testing.T) {
	for _, value := range []string{"int", "string", "[]string", "bool", "uint64"} {
		if m2MovedTypeName(value) != value || m2MovedStructName(value) != value {
			t.Fatalf("non-name change allowed for %s", value)
		}
	}
}
