package providercli

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/ports"
)

// Exercise the original family methods before extracting their common mechanics.
func TestProtocolStringResponseMatches(t *testing.T) {
	for _, test := range []struct {
		name, raw, method string
		expected          []string
		want              bool
	}{
		{name: "absent", expected: []string{""}},
		{name: "malformed", raw: `"unfinished`, expected: []string{"unfinished"}},
		{name: "number", raw: `1`, expected: []string{"1"}},
		{name: "boolean", raw: `true`, expected: []string{"true"}},
		{name: "object", raw: `{}`, expected: []string{""}},
		{name: "array", raw: `[]`, expected: []string{""}},
		{name: "null is not a request", raw: `null`, expected: []string{"mulgae-create"}},
		{name: "null preserves empty string decode", raw: `null`, expected: []string{""}, want: true},
		{name: "empty string", raw: `""`, expected: []string{""}, want: true},
		{name: "matching", raw: `"mulgae-create"`, expected: []string{"mulgae-create"}, want: true},
		{name: "other request", raw: `"mulgae-send"`, expected: []string{"mulgae-create"}},
		{name: "other prefix", raw: `"other-new"`, expected: []string{"mulgae-create"}},
		{name: "escaped equivalent", raw: `"mulgae-\u0063reate"`, expected: []string{"mulgae-create"}, want: true},
		{name: "surrounding JSON whitespace", raw: " \t\"mulgae-create\"\n", expected: []string{"mulgae-create"}, want: true},
		{name: "trailing value", raw: `"mulgae-create" {}`, expected: []string{"mulgae-create"}},
		{name: "server request", raw: `"mulgae-create"`, method: "session/request_permission", expected: []string{"mulgae-create"}},
		{name: "whitespace method remains a method", raw: `"mulgae-create"`, method: " ", expected: []string{"mulgae-create"}},
		{name: "no expected IDs", raw: `"mulgae-create"`},
		{name: "multiple", raw: `"mulgae-send"`, expected: []string{"mulgae-create", "mulgae-send"}, want: true},
		{name: "duplicate expected IDs", raw: `"mulgae-create"`, expected: []string{"mulgae-create", "mulgae-create"}, want: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			zcode := zcodeProtocolMessage{ID: json.RawMessage(test.raw), Method: test.method}
			if got := zcode.correlatesTo(test.expected...); got != test.want {
				t.Errorf("zcode correlation = %t, want %t", got, test.want)
			}
			if len(test.expected) == 1 && zcode.isResponseID(test.expected[0]) != test.want {
				t.Error("single-ID wrapper differs from expected correlation")
			}
		})
	}

	t.Run("protocol line tolerance stays local", func(t *testing.T) {
		for _, test := range []struct {
			name, suffix string
		}{
			{"additive field", `,"extra":true}`},
			{"duplicate ID", `,"id":"own"}`},
			{"trailing JSON", `} {"unrelated":true}`},
		} {
			t.Run(test.name, func(t *testing.T) {
				zcode, err := parseZcodeProtocolMessage([]byte(`{"id":"own"` + test.suffix))
				if err != nil || !zcode.isResponseID("own") {
					t.Fatalf("ZCode existing line tolerance changed: %v", err)
				}
			})
		}
	})
}

func TestProtocolDiagnosticIdentifierGrammar(t *testing.T) {
	for _, test := range []struct {
		name, value string
		admitted    bool
	}{
		{"empty", "", true}, {"ASCII", "session-1", true}, {"Unicode", "session-물개", true},
		{"511 bytes", strings.Repeat("s", 511), true}, {"512 bytes", strings.Repeat("s", 512), true},
		{"513 bytes", strings.Repeat("s", 513), false},
		{"multibyte 511 bytes", strings.Repeat("é", 255) + "s", true},
		{"multibyte 512 bytes", strings.Repeat("é", 256), true},
		{"multibyte 513 bytes", strings.Repeat("é", 256) + "s", false},
		{"invalid UTF8", "a\xffb", false}, {"replacement rune", "a\ufffdb", true},
		{"leading space", " session", false}, {"trailing space", "session ", false},
		{"leading Unicode space", "\u2003session", false}, {"trailing Unicode space", "session\u00a0", false},
		{"interior space", "session one", true}, {"interior Unicode space", "session\u2003one", true},
		{"NUL", "session\x00one", false}, {"tab", "session\tone", false},
		{"newline", "session\none", false}, {"DEL", "session\x7fone", false}, {"C1", "session\u0085one", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			want := ""
			if test.admitted {
				want = test.value
			}
			got := sanitizeProtocolDiagnosticIdentifier(test.value)
			if got != want {
				t.Errorf("zcode diagnostic = %q, want %q", got, want)
			}
			input := ports.ProviderSessionObservationInput{Phase: ports.ProviderSessionPhaseCreate, Terminal: ports.ProviderSessionCompleted, ProviderSessionID: got, ProviderTurnID: got}
			if _, err := ports.NewProviderSessionObservation(input); err != nil {
				t.Errorf("zcode sanitizer result violates port grammar: %v", err)
			}
			_, err := ports.NewProviderSessionObservation(ports.ProviderSessionObservationInput{Phase: ports.ProviderSessionPhaseCreate, Terminal: ports.ProviderSessionCompleted, ProviderSessionID: test.value})
			if (err == nil) != test.admitted {
				t.Fatalf("raw port admission = %v, want admitted=%t", err, test.admitted)
			}
		})
	}
}
