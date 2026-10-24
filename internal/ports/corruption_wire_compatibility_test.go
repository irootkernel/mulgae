package ports

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"
)

func TestCorruptionDiagnosticWireTypeIdentity(t *testing.T) {
	run := publicationTestRun(t)
	// This boundary returns the raw decoder message; retain its named Go type.
	err := validateCorruptionDiagnosticPayload([]byte(`{"observation_epoch":"bad"}`), run, 1, nil)
	var typed *json.UnmarshalTypeError
	if !errors.As(err, &typed) || fmt.Sprintf("%T", err) != "*fmt.wrapError" || typed.Struct != "corruptionDiagnosticWire" || typed.Type.String() != "uint64" || typed.Field != "observation_epoch" || typed.Value != "string" || typed.Offset != 26 || err.Error() != `diagnostic payload: json: cannot unmarshal string into Go struct field corruptionDiagnosticWire.observation_epoch of type uint64` {
		t.Fatalf("typed guard=%+v; error=%v", typed, err)
	}
}
