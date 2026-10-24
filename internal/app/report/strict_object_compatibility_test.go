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

type strictCompatibilityDTO struct {
	Text     string                   `json:"text"`
	Integer  int64                    `json:"integer"`
	Unsigned uint64                   `json:"unsigned"`
	Float    float64                  `json:"float"`
	Number   json.Number              `json:"number"`
	Value    any                      `json:"value"`
	Raw      json.RawMessage          `json:"raw"`
	Children []strictCompatibilityDTO `json:"children"`
}

type strictCompatibilityOutcome struct {
	JSON      string `json:"json,omitempty"`
	ErrorType string `json:"error_type,omitempty"`
	Message   string `json:"message,omitempty"`
	Offset    int64  `json:"offset,omitempty"`
	Value     string `json:"value,omitempty"`
	Type      string `json:"type,omitempty"`
	Struct    string `json:"struct,omitempty"`
	Field     string `json:"field,omitempty"`
}

func strictCompatibilityOutcomes(t *testing.T) map[string]strictCompatibilityOutcome {
	t.Helper()
	result := map[string]strictCompatibilityOutcome{}
	observe := func(name string, raw []byte, destination any) {
		err := decodeReportStrictObject(raw, destination)
		got := strictCompatibilityOutcome{}
		if err == nil {
			encoded, marshalErr := json.Marshal(destination)
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			got.JSON = string(encoded)
		} else {
			got.ErrorType, got.Message = fmt.Sprintf("%T", err), err.Error()
			var syntax *json.SyntaxError
			if errors.As(err, &syntax) {
				got.Offset = syntax.Offset
			}
			var typed *json.UnmarshalTypeError
			if errors.As(err, &typed) {
				got.Offset, got.Value, got.Type, got.Struct, got.Field = typed.Offset, typed.Value, typed.Type.String(), typed.Struct, typed.Field
			}
		}
		result[name] = got
	}
	for _, c := range []struct{ name, raw string }{
		{"empty", ""}, {"whitespace", " \r\n"}, {"null", `null`}, {"array", `[]`}, {"scalar", `1`},
		{"empty object", `{}`}, {"unknown", `{"unknown":1}`}, {"duplicate", `{"text":"a","text":"b"}`},
		{"escaped duplicate", `{"text":"a","\u0074ext":"b"}`}, {"nested duplicate", `{"value":{"x":1,"x":2}}`},
		{"array duplicate", `{"value":[{"x":1,"x":2}]}`}, {"case alias", `{"text":"a","TEXT":"b"}`},
		{"trailing value", `{} {}`}, {"trailing garbage", `{} x`}, {"root before trailing", `[] {}`},
		{"duplicate before unknown", `{"unknown":1,"unknown":2}`}, {"trailing before unknown", `{"unknown":1} {}`},
		{"duplicate before type", `{"integer":"bad","integer":1}`}, {"nested type", `{"children":[{"integer":"bad"}]}`},
		{"invalid UTF8", "{\"text\":\"\xff\"}"}, {"UTF8 before syntax", "\xff{"},
		{"lone high", `{"text":"\ud800"}`}, {"lone low", `{"text":"\udc00"}`}, {"paired", `{"text":"\ud83d\ude00"}`},
		{"literal escape", `{"text":"\\uD800"}`}, {"malformed escape", `{"text":"\uZZZZ"}`}, {"bad escape", `{"text":"\q"}`},
		{"unterminated", `{"text":"`}, {"integer max", `{"integer":9223372036854775807}`}, {"integer overflow", `{"integer":9223372036854775808}`},
		{"fraction to integer", `{"integer":1.5}`}, {"exponent to integer", `{"integer":1e0}`}, {"unsigned negative", `{"unsigned":-1}`},
		{"unsigned max", `{"unsigned":18446744073709551615}`}, {"float overflow", `{"float":1e400}`}, {"number overflow", `{"number":1e400}`},
		{"any overflow", `{"value":1e400}`}, {"raw overflow", `{"raw":1e400}`}, {"leading zero", `{"integer":01}`},
		{"NaN", `{"float":NaN}`}, {"unicode HTML", `{"text":"café é 한글 <&>\r\n"}`},
		{"overflow before duplicate", `{"value":1e400,"text":"a","text":"b"}`},
	} {
		observe("synthetic/"+c.name, []byte(c.raw), &strictCompatibilityDTO{})
	}

	for _, c := range []struct{ name, raw string }{
		{"empty", `{}`}, {"unknown", `{"unknown":1}`}, {"nested type", `{"mulgae":{"version":42}}`},
		{"nested identity", `{"immutable_lineage":{"source_attempt_id":42}}`}, {"trailing", `{} {}`},
	} {
		observe("reportFinalDTO/"+c.name, []byte(c.raw), &reportFinalDTO{})
	}

	return result
}

func TestStrictObjectCompatibility(t *testing.T) {
	t.Run("M2 actual destinations", testM2ObjectCompatibility)
	raw, err := os.ReadFile(filepath.Join("testdata", "m1-strict-before.json"))
	if err != nil {
		t.Fatal(err)
	}
	var expected map[string]strictCompatibilityOutcome
	if err := json.Unmarshal(raw, &expected); err != nil {
		t.Fatal(err)
	}
	// A1 permits only mechanically moved Go type/struct names. Keep the original
	// snapshot and assert every exact replacement separately, without normalization.
	changes := map[string]strictCompatibilityOutcome{}
	delta, err := os.ReadFile(filepath.Join("testdata", "m1-strict-diagnostic-moves.json"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	if err == nil {
		if err := json.Unmarshal(delta, &changes); err != nil {
			t.Fatal(err)
		}
	}
	for name, replacement := range changes {
		before, found := expected[name]
		if !found || before.ErrorType != "*json.UnmarshalTypeError" || before.Struct == replacement.Struct && before.Type == replacement.Type {
			t.Fatalf("invalid diagnostic move %s", name)
		}
		wantMessage := before.Message
		if before.Struct != replacement.Struct {
			wantMessage = strings.Replace(wantMessage, before.Struct+"."+before.Field, replacement.Struct+"."+before.Field, 1)
		}
		if before.Type != replacement.Type {
			if !strings.HasSuffix(wantMessage, " of type "+before.Type) {
				t.Fatalf("unexpected type diagnostic %s", name)
			}
			wantMessage = strings.TrimSuffix(wantMessage, " of type "+before.Type) + " of type " + replacement.Type
		}
		if replacement.Message != wantMessage {
			t.Fatalf("nonmechanical diagnostic message %s", name)
		}
		fixed := replacement
		fixed.Struct, fixed.Type, fixed.Message = before.Struct, before.Type, before.Message
		if fixed != before {
			t.Fatalf("non-name diagnostic change %s: before=%+v after=%+v", name, before, replacement)
		}
		expected[name] = replacement
	}
	actual := strictCompatibilityOutcomes(t)
	if len(actual) != len(expected) {
		t.Fatalf("case count=%d want %d", len(actual), len(expected))
	}
	for name, want := range expected {
		t.Run(name, func(t *testing.T) {
			if got, found := actual[name]; !found || !reflect.DeepEqual(got, want) {
				t.Fatalf("got %+v; want %+v", got, want)
			}
		})
	}
}
