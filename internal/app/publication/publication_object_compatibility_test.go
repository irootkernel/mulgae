package publication

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
	return map[string]func() any{"mulgaeWire": func() any { return &mulgaeWire{} }, "immutableLineageWire": func() any { return &immutableLineageWire{} }, "validationWire": func() any { return &validationWire{} }, "severityThresholdWire": func() any { return &severityThresholdWire{} }, "roleOutcomeWire": func() any { return &roleOutcomeWire{} }, "visualEvidenceWire": func() any { return &visualEvidenceWire{} }, "visualBoundingBoxWire": func() any { return &visualBoundingBoxWire{} }, "liveProductionProvenanceWire": func() any { return &liveProductionProvenanceWire{} }, "productionProvenanceWire": func() any { return &productionProvenanceWire{} }, "productionProviderWire": func() any { return &productionProviderWire{} }, "manifestRoleReportWire": func() any { return &manifestRoleReportWire{} }, "manifestAttemptWire": func() any { return &manifestAttemptWire{} }, "manifestFailureWire": func() any { return &manifestFailureWire{} }, "pathPointerWire": func() any { return &pathPointerWire{} }, "finalReviewIdentityWire": func() any { return &finalReviewIdentityWire{} }, "restartStateWire": func() any { return &restartStateWire{} }, "publicationJournalWire": func() any { return &publicationJournalWire{} }, "publicationStatusWire": func() any { return &publicationStatusWire{} }, "publicationEpochWire": func() any { return &publicationEpochWire{} }, "lineageChildWire": func() any { return &lineageChildWire{} }, "lineageEdgeWire": func() any { return &lineageEdgeWire{} }, "publicationCorruptionDiagnosticWire": func() any { return &publicationCorruptionDiagnosticWire{} }, "finalReviewWire": func() any { return &finalReviewWire{} }, "runManifestWire": func() any { return &runManifestWire{} }, "compositeManifestReadWire": func() any { return &compositeManifestReadWire{} }}
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
	err := unmarshalCanonicalPublicationRecord(raw, destination, "M2 characterization")
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

func TestM2PublicationObjectCompatibility(t *testing.T) { testM2ObjectCompatibility(t) }

func m2MovedStructName(value string) string {
	switch value {
	case "compositeCompositionWire":
		return "CompositeComposition"
	case "compositeManifestRoleReadWire":
		return "CompositeManifestRole"
	case "compositeManifestRoleWire":
		return "CompositeManifestRole"
	case "compositeSourceWire":
		return "CompositeSource"
	case "finalReviewIdentityWire":
		return "FinalReviewIdentity"
	case "immutableLineageWire":
		return "ImmutableLineage"
	case "lineageChildWire":
		return "LineageChild"
	case "lineageEdgeWire":
		return "LineageEdge"
	case "liveProductionProvenanceWire":
		return "LiveProductionProvenance"
	case "manifestAttemptWire":
		return "ManifestAttempt"
	case "manifestFailureWire":
		return "ManifestFailure"
	case "manifestRoleReportWire":
		return "ManifestRoleReport"
	case "mulgaeWire":
		return "BuildMetadata"
	case "pathPointerWire":
		return "PathPointer"
	case "productionProvenanceWire":
		return "ProductionProvenance"
	case "productionProviderWire":
		return "ProductionProvider"
	case "publicationCorruptionDiagnosticWire":
		return "CorruptionDiagnostic"
	case "publicationEpochWire":
		return "PublicationEpoch"
	case "publicationJournalWire":
		return "PublicationJournal"
	case "publicationStatusWire":
		return "PublicationStatus"
	case "restartStateWire":
		return "RestartState"
	case "roleOutcomeWire":
		return "RoleOutcome"
	case "severityThresholdWire":
		return "SeverityThreshold"
	case "validationWire":
		return "Validation"
	case "visualBoundingBoxWire":
		return "VisualBoundingBox"
	case "visualEvidenceWire":
		return "VisualEvidence"
	}
	return value
}

func m2MovedTypeName(value string) string {
	return strings.NewReplacer(
		"publication.publicationCorruptionDiagnosticWire", "artifactwire.CorruptionDiagnostic",
		"publication.compositeManifestRoleReadWire", "artifactwire.CompositeManifestRole",
		"publication.liveProductionProvenanceWire", "artifactwire.LiveProductionProvenance",
		"publication.compositeManifestRoleWire", "artifactwire.CompositeManifestRole",
		"publication.productionProvenanceWire", "artifactwire.ProductionProvenance",
		"publication.compositeCompositionWire", "artifactwire.CompositeComposition",
		"publication.finalReviewIdentityWire", "artifactwire.FinalReviewIdentity",
		"publication.publicationJournalWire", "artifactwire.PublicationJournal",
		"publication.productionProviderWire", "artifactwire.ProductionProvider",
		"publication.manifestRoleReportWire", "artifactwire.ManifestRoleReport",
		"publication.publicationStatusWire", "artifactwire.PublicationStatus",
		"publication.severityThresholdWire", "artifactwire.SeverityThreshold",
		"publication.visualBoundingBoxWire", "artifactwire.VisualBoundingBox",
		"publication.publicationEpochWire", "artifactwire.PublicationEpoch",
		"publication.immutableLineageWire", "artifactwire.ImmutableLineage",
		"publication.manifestAttemptWire", "artifactwire.ManifestAttempt",
		"publication.manifestFailureWire", "artifactwire.ManifestFailure",
		"publication.compositeSourceWire", "artifactwire.CompositeSource",
		"publication.visualEvidenceWire", "artifactwire.VisualEvidence",
		"publication.restartStateWire", "artifactwire.RestartState",
		"publication.lineageChildWire", "artifactwire.LineageChild",
		"publication.lineageEdgeWire", "artifactwire.LineageEdge",
		"publication.roleOutcomeWire", "artifactwire.RoleOutcome",
		"publication.pathPointerWire", "artifactwire.PathPointer",
		"publication.validationWire", "artifactwire.Validation",
		"publication.mulgaeWire", "artifactwire.BuildMetadata",
	).Replace(value)
}

func TestM2DiagnosticMoveRejectsNonNameChanges(t *testing.T) {
	for _, value := range []string{"int", "string", "[]string", "bool", "uint64"} {
		if m2MovedTypeName(value) != value || m2MovedStructName(value) != value {
			t.Fatalf("non-name change allowed for %s", value)
		}
	}
}
