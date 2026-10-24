package mcpentry

import (
	"errors"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/app/reviewrun"
)

func TestReviewMappingDirectCompatibility(t *testing.T) {
	const id = "i_019f596a-cf80-7c67-b265-f37053d51ccf"
	for _, test := range []struct {
		name, objective, binding string
		roles                    []string
		reject, guard            bool
	}{
		{"empty", "", "", nil, false, false},
		{"direct former parser bound", strings.Repeat("x", 12000), "", nil, false, false},
		{"direct over former parser bound", strings.Repeat("x", 12001), "", nil, true, false},
		{"newline before bad binding", "\n", "bad", nil, true, false},
		{"flag before bad binding", "--focus", "bad", nil, true, false},
		{"roles before bad binding", "focus", "bad", []string{"logic", "logic"}, true, false},
		{"empty binding", "focus", "", nil, true, true},
		{"invalid binding", "focus", "bad", nil, true, true},
		{"direct CSV normalization", "focus", "", []string{"testing,logic"}, false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := RunReviewInput{Target: ReviewTarget{Kind: "workspace"}, Objective: test.objective, Roles: test.roles}
			if test.binding != "" || test.name == "empty binding" {
				input.ExpectedProjectBinding = &test.binding
			}
			request, err := NewReviewRequest(input, "/fixture", id, false)
			if (err != nil) != test.reject || errors.Is(err, reviewrun.ErrGuardInvalid) != test.guard {
				t.Fatalf("mapping err=%v reject=%t guard=%t", err, test.reject, test.guard)
			}
			if !test.reject {
				objective, present := request.Objective()
				if objective != test.objective || present != (test.objective != "") {
					t.Fatal("objective normalization changed")
				}
			}
		})
	}
	for _, root := range []string{"relative", "/fixture/../other", "/fixture\\other", "/fixture\n"} {
		if _, err := NewReviewRequest(RunReviewInput{Target: ReviewTarget{Kind: "workspace"}}, root, id, false); err == nil {
			t.Fatalf("unsafe root admitted: %q", root)
		}
	}
}
