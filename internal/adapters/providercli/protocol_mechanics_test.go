package providercli

import (
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/ports"
)

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
