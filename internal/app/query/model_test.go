package query

import (
	"strings"
	"testing"

	"github.com/irootkernel/kkachi-agent-review/internal/domain"
)

func TestDecodeFinalDTORejectsDuplicateUnknownAndTrailingJSON(t *testing.T) {
	t.Parallel()
	for name, raw := range map[string]string{
		"duplicate": `{"schema_version":"kar-review-artifact.v3","schema_version":"kar-review-artifact.v3"}`,
		"unknown":   `{"unexpected":true}`,
		"trailing":  `{} {}`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := decodeFinalDTO([]byte(raw)); err == nil {
				t.Fatalf("decodeFinalDTO(%q) succeeded", raw)
			}
		})
	}
}

func TestCommittedReviewAndFindingViewsDefendCallerMutations(t *testing.T) {
	t.Parallel()
	review := CommittedReview{
		roles: []Role{{
			role: domain.RoleLogic, findingIDs: []string{"F001"}, limitations: []string{"limited"},
		}},
		findings: []Finding{{
			id: "F001", evidence: []Evidence{{quote: "verified quote"}},
		}},
		finalBytes: []byte("final"), manifestBytes: []byte("manifest"),
	}

	roles := review.Roles()
	roles[0].findingIDs[0] = "F999"
	roles[0].limitations[0] = "changed"
	if got := review.Roles()[0].ValidFindingIDs()[0]; got != "F001" {
		t.Fatalf("role finding IDs leaked mutation: %q", got)
	}
	if got := review.Roles()[0].Limitations()[0]; got != "limited" {
		t.Fatalf("role limitations leaked mutation: %q", got)
	}

	findings := review.Findings()
	findings[0].evidence[0].quote = "changed"
	if got := review.Findings()[0].Evidence()[0].quote; got != "verified quote" {
		t.Fatalf("finding evidence leaked mutation: %q", got)
	}
	final := review.FinalBytes()
	final[0] = 'X'
	if got := string(review.FinalBytes()); got != "final" {
		t.Fatalf("final bytes leaked mutation: %q", got)
	}
	manifest := review.ManifestBytes()
	manifest[0] = 'X'
	if got := string(review.ManifestBytes()); got != "manifest" {
		t.Fatalf("manifest bytes leaked mutation: %q", got)
	}

	if strings.Contains(review.Findings()[0].Evidence()[0].quote, "changed") {
		t.Fatal("defensive evidence copy retained caller mutation")
	}
}
