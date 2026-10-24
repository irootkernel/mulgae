package validation

import (
	"context"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

// DF-013: these are provider-parser controls, independent of schema parsing.
func TestProviderJSONSurrogateCompatibility(t *testing.T) {
	for _, test := range []struct {
		name, escaped, want, reason string
	}{
		{"lone low", `\udc00`, "", "unpaired low UTF-16 surrogate escape"},
		{"lone high", `\ud800`, "", "unpaired high UTF-16 surrogate escape"},
		{"paired", `\ud83d\ude00`, "😀", ""},
		{"literal escape", `\\uD800`, `\uD800`, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, parser := range []struct {
				name   string
				decode func([]byte) (map[string]any, error)
			}{
				{"review", func(raw []byte) (map[string]any, error) { return decodeJSONObject(raw, "provider output") }},
				{"followup", decodeFollowupJSONObject},
			} {
				t.Run(parser.name, func(t *testing.T) {
					got, err := parser.decode([]byte(`{"summary":"` + test.escaped + `"}`))
					if test.reason != "" {
						if err == nil || !strings.Contains(err.Error(), test.reason) {
							t.Fatalf("error=%v, want %s", err, test.reason)
						}
					} else if err != nil || got["summary"] != test.want {
						t.Fatalf("summary=%v error=%v, want %q", got["summary"], err, test.want)
					}
				})
			}
			reviewRaw := providerReviewWith(t, func(document map[string]any) { document["summary"] = "SURROGATE" })
			reviewRaw = []byte(strings.Replace(string(reviewRaw), "SURROGATE", test.escaped, 1))
			review := testReviewValidator(t, &recordingSchemaValidator{})
			_, plan, err := review.Validate(context.Background(), reviewRaw, testScope())
			if test.reason != "" {
				cause, classified := RuntimeCause(err)
				if !classified || cause != domain.DiagnosticCauseCandidateValidationFailed || err.Error() != "review validation failed: candidate_validation_failed" || plan == nil || plan.Mode() != RepairModeReformatOnly {
					t.Fatalf("review error=%v plan=%v", err, plan)
				}
			} else if err != nil || plan != nil {
				t.Fatalf("review error=%v plan=%v", err, plan)
			}
			followup := followupTestValidator(t, followupSchemaFunc(func(context.Context, ports.AssetID, []byte) error { return nil }))
			document := followupTestDocument("resolved", "The issue was removed by the current change.")
			document["summary"] = "SURROGATE"
			followupRaw := []byte(strings.Replace(string(followupTestJSON(t, document)), "SURROGATE", test.escaped, 1))
			_, repairable, err := followup.ValidateWithRepairAuthority(context.Background(), followupRaw, followupTestScope(t))
			if test.reason != "" {
				if err == nil || !strings.Contains(err.Error(), test.reason) || !repairable {
					t.Fatalf("followup error=%v repairable=%t", err, repairable)
				}
			} else if err != nil || repairable {
				t.Fatalf("followup error=%v repairable=%t", err, repairable)
			}
		})
	}
}
