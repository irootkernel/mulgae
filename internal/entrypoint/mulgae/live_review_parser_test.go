package mulgae

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestParseLiveReviewSelectorsAndIndependentBinding(t *testing.T) {
	for _, selector := range [][]string{{"--workspace"}, {"--stage"}, {"--head"}, {"--commit", "HEAD"}, {"--diff", "main...HEAD"}} {
		arguments := append([]string{"review"}, selector...)
		arguments = append(arguments, "--expected-project-binding", "sha256:"+strings.Repeat("a", 64))
		invocation, err := Parse(arguments, "/fixture", "i_019f596a-e201-7a4b-8d76-1cf503a1849e")
		if err != nil {
			t.Fatalf("%v: %v", selector, err)
		}
		request, _ := invocation.Review()
		if !validReviewRunRequest(request) || request.ExpectedProjectBinding() == "" {
			t.Fatalf("live request not admitted: %+v", request)
		}
		var wire map[string]any
		if err := json.Unmarshal(invocation.requestJSON, &wire); err != nil {
			t.Fatal(err)
		}
		if _, present := wire["expected_request_digest"]; present {
			t.Fatal("retired capture guard was emitted")
		}
	}
	for _, arguments := range [][]string{{"review", "--dirty"}, {"review", "--patch", "patch.diff"}, {"review", "--stdin", "token"}, {"review", "--workspace", "--expected-request-digest", "sha256:" + strings.Repeat("b", 64)}, {"review", "--workspace", "--head"}, {"review", "--commit", "--unsafe"}, {"review", "--diff", "HEAD"}} {
		if _, err := Parse(arguments, "/fixture", "i_019f596a-e201-7a4b-8d76-1cf503a1849e"); err == nil {
			t.Fatalf("retired or malformed request admitted: %v", arguments)
		}
	}
}

func TestParseRejectsRetiredExecutionCommands(t *testing.T) {
	for _, command := range []string{"followup", "delta", "rerun", "compose"} {
		if _, err := Parse([]string{command}, "/fixture", "i_019f596a-e201-7a4b-8d76-1cf503a1849e"); err == nil {
			t.Fatalf("retired execution command admitted: %s", command)
		}
	}
}
