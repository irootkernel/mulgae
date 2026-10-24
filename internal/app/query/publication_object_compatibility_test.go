package query

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
	return map[string]func() any{"finalMulgaeDTO": func() any { return &finalMulgaeDTO{} }, "lineageDTO": func() any { return &lineageDTO{} }, "finalValidationDTO": func() any { return &finalValidationDTO{} }, "severityThresholdDTO": func() any { return &severityThresholdDTO{} }, "finalRoleDTO": func() any { return &finalRoleDTO{} }, "visualEvidenceDTO": func() any { return &visualEvidenceDTO{} }, "visualBBoxDTO": func() any { return &visualBBoxDTO{} }, "liveProductionProvenanceDTO": func() any { return &liveProductionProvenanceDTO{} }, "productionProvenanceDTO": func() any { return &productionProvenanceDTO{} }, "productionProviderDTO": func() any { return &productionProviderDTO{} }, "manifestRoleReportDTO": func() any { return &manifestRoleReportDTO{} }, "manifestAttemptDTO": func() any { return &manifestAttemptDTO{} }, "manifestFailureDTO": func() any { return &manifestFailureDTO{} }, "pathPointerDTO": func() any { return &pathPointerDTO{} }, "finalReviewDTO": func() any { return &finalReviewDTO{} }, "compositeRoleDTO": func() any { return &compositeRoleDTO{} }, "compositeFindingDTO": func() any { return &compositeFindingDTO{} }, "compositeFindingSourceDTO": func() any { return &compositeFindingSourceDTO{} }, "compositeCompositionDTO": func() any { return &compositeCompositionDTO{} }, "compositeSourceDTO": func() any { return &compositeSourceDTO{} }, "compositeManifestRoleDTO": func() any { return &compositeManifestRoleDTO{} }, "finalDTO": func() any { return &finalDTO{} }, "manifestDTO": func() any { return &manifestDTO{} }, "compositeFinalDTO": func() any { return &compositeFinalDTO{} }, "compositeManifestDTO": func() any { return &compositeManifestDTO{} }, "InspectionReceipt": func() any { return &InspectionReceipt{} }, "findingCursor": func() any { return &findingCursor{} }}
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
	err := decodeStrictDTO(raw, destination)
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
	case "compositeCompositionDTO":
		return "CompositeComposition"
	case "compositeFindingDTO":
		return "CompositeFinding"
	case "compositeFindingSourceDTO":
		return "CompositeFindingSource"
	case "compositeManifestRoleDTO":
		return "CompositeManifestRole"
	case "compositeRoleDTO":
		return "CompositeRole"
	case "compositeSourceDTO":
		return "CompositeSource"
	case "finalMulgaeDTO":
		return "BuildMetadata"
	case "finalReviewDTO":
		return "FinalReviewIdentity"
	case "finalRoleDTO":
		return "RoleOutcome"
	case "finalValidationDTO":
		return "Validation"
	case "lineageDTO":
		return "ImmutableLineage"
	case "liveProductionProvenanceDTO":
		return "LiveProductionProvenance"
	case "manifestAttemptDTO":
		return "ManifestAttempt"
	case "manifestFailureDTO":
		return "ManifestFailure"
	case "manifestRoleReportDTO":
		return "ManifestRoleReport"
	case "pathPointerDTO":
		return "PathPointer"
	case "productionProvenanceDTO":
		return "ProductionProvenance"
	case "productionProviderDTO":
		return "ProductionProvider"
	case "severityThresholdDTO":
		return "SeverityThreshold"
	case "visualBBoxDTO":
		return "VisualBoundingBox"
	case "visualEvidenceDTO":
		return "VisualEvidence"
	}
	return value
}

func m2MovedTypeName(value string) string {
	return strings.NewReplacer(
		"query.liveProductionProvenanceDTO", "artifactwire.LiveProductionProvenance",
		"query.compositeFindingSourceDTO", "artifactwire.CompositeFindingSource",
		"query.compositeManifestRoleDTO", "artifactwire.CompositeManifestRole",
		"query.productionProvenanceDTO", "artifactwire.ProductionProvenance",
		"query.compositeCompositionDTO", "artifactwire.CompositeComposition",
		"query.productionProviderDTO", "artifactwire.ProductionProvider",
		"query.manifestRoleReportDTO", "artifactwire.ManifestRoleReport",
		"query.severityThresholdDTO", "artifactwire.SeverityThreshold",
		"query.compositeFindingDTO", "artifactwire.CompositeFinding",
		"query.finalValidationDTO", "artifactwire.Validation",
		"query.manifestAttemptDTO", "artifactwire.ManifestAttempt",
		"query.manifestFailureDTO", "artifactwire.ManifestFailure",
		"query.compositeSourceDTO", "artifactwire.CompositeSource",
		"query.visualEvidenceDTO", "artifactwire.VisualEvidence",
		"query.compositeRoleDTO", "artifactwire.CompositeRole",
		"query.finalMulgaeDTO", "artifactwire.BuildMetadata",
		"query.pathPointerDTO", "artifactwire.PathPointer",
		"query.finalReviewDTO", "artifactwire.FinalReviewIdentity",
		"query.visualBBoxDTO", "artifactwire.VisualBoundingBox",
		"query.finalRoleDTO", "artifactwire.RoleOutcome",
		"query.lineageDTO", "artifactwire.ImmutableLineage",
	).Replace(value)
}

func TestM2DiagnosticMoveRejectsNonNameChanges(t *testing.T) {
	for _, value := range []string{"int", "string", "[]string", "bool", "uint64"} {
		if m2MovedTypeName(value) != value || m2MovedStructName(value) != value {
			t.Fatalf("non-name change allowed for %s", value)
		}
	}
}
