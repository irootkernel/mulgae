package providercli

import (
	"encoding/json"
	"strings"
	"unicode"
	"unicode/utf8"
)

// sanitizeProtocolDiagnosticIdentifier omits unsafe diagnostic identifiers.
// Callers retain raw wire identifiers for native correlation and decide whether
// an omitted identifier also invalidates an authoritative protocol receipt.
func sanitizeProtocolDiagnosticIdentifier(value string) string {
	if len(value) > 512 || !utf8.ValidString(value) || value != strings.TrimSpace(value) {
		return ""
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return ""
		}
	}
	return value
}

// protocolStringResponseMatches shares JSON-RPC string-ID matching for protocol adapters.
// Request identities, outstanding state and other native ID codecs stay local.
func protocolStringResponseMatches(rawID json.RawMessage, method string, expected ...string) bool {
	if len(rawID) == 0 || method != "" {
		return false
	}
	var decoded string
	if json.Unmarshal(rawID, &decoded) != nil {
		return false
	}
	for _, id := range expected {
		if decoded == id {
			return true
		}
	}
	return false
}
