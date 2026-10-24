package strictjson

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
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
		err := DecodeObject(raw, destination)
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

	return result
}

func TestDecodeObjectCompatibility(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "object-before.json"))
	if err != nil {
		t.Fatal(err)
	}
	var expected map[string]strictCompatibilityOutcome
	if err := json.Unmarshal(raw, &expected); err != nil {
		t.Fatal(err)
	}
	actual := strictCompatibilityOutcomes(t)
	if len(actual) != len(expected) {
		t.Fatalf("case count %d want %d", len(actual), len(expected))
	}
	for name, want := range expected {
		t.Run(name, func(t *testing.T) {
			if got, ok := actual[name]; !ok || !reflect.DeepEqual(got, want) {
				t.Fatalf("got %+v;want %+v", got, want)
			}
		})
	}
}
