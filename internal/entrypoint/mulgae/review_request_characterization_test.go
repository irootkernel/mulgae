//go:build darwin && arm64

package mulgae

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/app"
	"github.com/irootkernel/mulgae/internal/app/reviewrun"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

func mustCharacterizationArtistInputs(t *testing.T) ports.ArtistReviewInputs {
	t.Helper()
	inputs, err := ports.NewArtistReviewInputs("docs/brief.md", []string{"design/**/*.png"})
	if err != nil {
		t.Fatal(err)
	}
	return inputs
}

func TestReviewRequestTransportCharacterization(t *testing.T) {
	for _, text := range []string{strings.Repeat("x", 12000), strings.Repeat("界", 4000)} {
		invocation := mustParse(t, []string{"review", "--workspace", "--objective", text})
		request, _ := invocation.Review()
		if value, present := request.Objective(); !present || value != text {
			t.Fatal("objective bytes changed")
		}
		for _, oversized := range []string{text + "x", text + "界"} {
			if _, err := Parse([]string{"review", "--workspace", "--objective", oversized}, testProjectRoot, testRequestID); !errors.Is(err, ErrUsage) {
				t.Fatalf("oversized objective: %v", err)
			}
		}
	}
	for _, test := range []struct{ objective, binding, want string }{
		{"\n", "bad", "review objective is malformed"},
		{"--focus", "bad", "flag value is missing"},
		{"focus", "bad", "guard_invalid"},
	} {
		argv := []string{"review", "--workspace", "--objective", test.objective, "--expected-project-binding", test.binding, "--output", "invalid"}
		if _, err := Parse(argv, testProjectRoot, testRequestID); err == nil || !strings.Contains(err.Error(), test.want) {
			t.Fatalf("combined invalid input: %v, want %s", err, test.want)
		}
		fixture := newFoundationFixture(t)
		fake := &reviewRunFake{}
		fixture.application.reviewRuns = fake
		result := fixture.application.Run(context.Background(), argv, testAnchoredRoot(t))
		if result.ExitCode() != app.ExitCodeUsage || len(result.Stdout()) != 0 || len(result.Stderr()) == 0 || fake.calls+fake.preflightCalls != 0 {
			t.Fatalf("usage projection: exit=%d stdout=%q stderr=%q calls=%d", result.ExitCode(), result.Stdout(), result.Stderr(), fake.calls+fake.preflightCalls)
		}
	}
	for _, selector := range [][]string{{"--workspace"}, {"--stage"}, {"--head"}, {"--commit", "HEAD"}, {"--diff", "main...HEAD"}} {
		invocation := mustParse(t, append([]string{"review"}, selector...))
		request, _ := invocation.Review()
		if request.RequestedRolesExplicit() || !reflect.DeepEqual(request.Roles(), []string{"logic", "security", "maintainability", "product", "documentation", "testing"}) {
			t.Fatalf("omitted role intent: %v", request.Roles())
		}
	}
}

func TestReviewPolicyRepeatedResolutionCharacterization(t *testing.T) {
	request, _ := mustParse(t, []string{"review", "--workspace"}).Review()
	inputs := mustCharacterizationArtistInputs(t)
	enabled := map[domain.Role]bool{domain.RoleLogic: true, domain.RoleArtist: true}
	for range 2 {
		admitted, err := reviewrun.ResolveRequest(request, enabled, inputs, true)
		resolved := admitted.Request()
		if err != nil || !resolved.ArtistAutomatic() || resolved.RequestedRolesExplicit() || !reflect.DeepEqual(resolved.Roles(), []string{"logic", "artist"}) {
			t.Fatalf("repeated automatic selection: %v %+v", err, resolved)
		}
		request = resolved
	}
}

func TestRejectedInitOutputModes(t *testing.T) {
	for _, test := range []struct {
		name   string
		output []string
		json   bool
	}{
		{"json", []string{"--output", "json"}, true},
		{"duplicate json", []string{"--output", "json", "--output", "json"}, true},
		{"mixed", []string{"--output", "json", "--output", "human"}, false},
		{"reverse mixed", []string{"--output", "human", "--output", "json"}, false},
		{"human", []string{"--output", "human"}, false},
		{"dangling", []string{"--output"}, false},
		{"absent", nil, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newFoundationFixture(t)
			result := fixture.application.Run(context.Background(), append([]string{"init", "--unknown"}, test.output...), testAnchoredRoot(t))
			if result.ExitCode() != app.ExitCodeUsage {
				t.Fatalf("exit=%d", result.ExitCode())
			}
			if !test.json {
				if len(result.Stdout()) != 0 || string(result.Stderr()) != "mulgae: invalid command usage\nhint: run mulgae help workflows\n" {
					t.Fatalf("human rejection: %q %q", result.Stdout(), result.Stderr())
				}
				return
			}
			assertFoundationEnvelope(t, fixture, result, app.ExitCodeUsage)
			var envelope struct {
				Request struct {
					RequestState string `json:"request_state"`
				}
				Result struct {
					WriteState string `json:"write_state"`
					Committed  bool   `json:"committed"`
				}
				Reasons []struct {
					Code string `json:"code"`
				}
			}
			if err := json.Unmarshal(result.Stdout(), &envelope); err != nil {
				t.Fatal(err)
			}
			if envelope.Request.RequestState != "invalid" || envelope.Result.WriteState != "not_attempted" || envelope.Result.Committed || len(envelope.Reasons) != 1 || envelope.Reasons[0].Code != "init_selection_invalid" || len(result.Stderr()) != 0 {
				t.Fatalf("JSON rejection: %s", result.Stdout())
			}
		})
	}
}
