//go:build darwin && arm64

package filesystem

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/artifactwire"
)

type supportWireDiagnostic struct {
	ErrorType string `json:"error_type"`
	Message   string `json:"message"`
	Offset    int64  `json:"offset"`
	Value     string `json:"value"`
	Type      string `json:"type"`
	Struct    string `json:"struct"`
	Field     string `json:"field"`
}

func supportWireDiagnostics(t *testing.T) map[string]supportWireDiagnostic {
	t.Helper()
	result := map[string]supportWireDiagnostic{}
	for name, raw := range map[string]string{"root": `1`, "schema": `{"schema_version":1}`, "artifacts": `{"artifacts":1}`, "member": `{"artifacts":[1]}`, "path": `{"artifacts":[{"path":1}]}`} {
		var destination artifactwire.SupportIndex
		err := strictDecodePublicationJSON([]byte(raw), &destination)
		var typed *json.UnmarshalTypeError
		if !errors.As(err, &typed) {
			t.Fatalf("%s error=%v", name, err)
		}
		result[name] = supportWireDiagnostic{fmt.Sprintf("%T", err), err.Error(), typed.Offset, typed.Value, typed.Type.String(), typed.Struct, typed.Field}
	}
	return result
}
func TestSupportIndexDecoderDiagnostics(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "m1-support-diagnostics.json"))
	if err != nil {
		t.Fatal(err)
	}
	var expected map[string]struct{ Before, After supportWireDiagnostic }
	if err := json.Unmarshal(raw, &expected); err != nil {
		t.Fatal(err)
	}
	actual := supportWireDiagnostics(t)
	if len(actual) != len(expected) {
		t.Fatal("diagnostic inventory changed")
	}
	for name, pair := range expected {
		t.Run(name, func(t *testing.T) {
			before, after := pair.Before, pair.After
			stableBefore, stableAfter := before, after
			stableBefore.Message, stableBefore.Type, stableBefore.Struct = "", "", ""
			stableAfter.Message, stableAfter.Type, stableAfter.Struct = "", "", ""
			if stableBefore != stableAfter || before.Type == after.Type && before.Struct == after.Struct {
				t.Fatal("invalid A1 diagnostic move")
			}
			message := before.Message
			if before.Struct != after.Struct {
				message = strings.Replace(message, before.Struct+"."+before.Field, after.Struct+"."+after.Field, 1)
			}
			if before.Type != after.Type {
				if !strings.HasSuffix(message, " of type "+before.Type) {
					t.Fatal("unexpected type message")
				}
				message = strings.TrimSuffix(message, " of type "+before.Type) + " of type " + after.Type
			}
			if message != after.Message {
				t.Fatal("nonmechanical message change")
			}
			if !reflect.DeepEqual(actual[name], after) {
				t.Fatalf("got %+v; want %+v", actual[name], after)
			}
		})
	}
}
