package mulgae

import (
	"errors"
	"github.com/irootkernel/mulgae/internal/app/reviewrun"
	"strings"
	"testing"
)

func TestReviewGuardGrammarPreservesAdmissionReasons(t *testing.T) {
	d := "sha256:" + strings.Repeat("a", 64)
	for _, test := range []struct {
		name  string
		flags []string
		want  error
	}{
		{"unguarded", nil, nil},
		{"paired", []string{"--expected-project-binding", d, "--expected-request-digest", d}, nil},
		{"preflight binding", []string{"--preflight", "--expected-project-binding", d}, nil},
		{"half binding", []string{"--expected-project-binding", d}, reviewrun.ErrGuardIncomplete},
		{"half request", []string{"--expected-request-digest", d}, reviewrun.ErrGuardIncomplete},
		{"invalid", []string{"--expected-project-binding", "invalid", "--expected-request-digest", d}, reviewrun.ErrGuardInvalid},
		{"empty", []string{"--expected-project-binding", "", "--expected-request-digest", d}, reviewrun.ErrGuardInvalid},
		{"preflight request", []string{"--preflight", "--expected-project-binding", d, "--expected-request-digest", d}, reviewrun.ErrGuardIncomplete},
	} {
		t.Run(test.name, func(t *testing.T) {
			invocation, err := Parse(append([]string{"review", "--stage"}, test.flags...), testProjectRoot, testRequestID)
			if test.want != nil {
				if !errors.Is(err, test.want) || !errors.Is(err, ErrUsage) {
					t.Fatalf("error=%v want=%v", err, test.want)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			request, ok := invocation.Review()
			if !ok {
				t.Fatal("review absent")
			}
			if len(test.flags) > 0 && request.ExpectedProjectBinding() != d {
				t.Fatal("binding dropped")
			}
		})
	}
}
