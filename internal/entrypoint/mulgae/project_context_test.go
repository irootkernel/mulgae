package mulgae

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/adapters/gittarget"
	"github.com/irootkernel/mulgae/internal/app/query"
)

func TestApplicationProjectContext(t *testing.T) {
	fixture := newFoundationFixture(t)
	service, err := query.NewProjectContextService(gittarget.ProjectBindingObserver{})
	if err != nil {
		t.Fatal(err)
	}
	fixture.application.projectContexts = service
	// These dependencies must remain unused by context, including failure paths.
	fixture.application.writer = nil
	fixture.application.projectReader = nil
	fixture.application.inspector = nil
	fixture.application.versionObserver = nil
	fixture.application.reviewRuns = nil
	fixture.application.heartbeats = nil
	root := testAnchoredRoot(t)
	result := fixture.application.Run(context.Background(), []string{"context", "--output", "json"}, root)
	if result.ExitCode() != 0 {
		t.Fatalf("context: exit %d, %s, %s", result.ExitCode(), result.Stdout(), result.Stderr())
	}
	var envelope struct {
		Result query.ProjectContext `json:"result"`
	}
	if err := json.Unmarshal(result.Stdout(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Result.Capabilities != (query.VerifiedReadCapabilities{ProjectBinding: "v1", ExecutionGuard: "v1", CaptureIdentity: "v1"}) || strings.Contains(string(result.Stdout()), root) {
		t.Fatalf("unsafe context: %s", result.Stdout())
	}
	failure := fixture.application.Run(context.Background(), []string{"context", "--output", "json"}, testAnchoredRoot(t)+"/missing")
	if failure.ExitCode() != 8 || !strings.Contains(string(failure.Stdout()), `"project_binding":null`) {
		t.Fatalf("context failure: %d %s", failure.ExitCode(), failure.Stdout())
	}
	for _, args := range [][]string{{"context", "foreign"}, {"context", "--project-root", root}, {"context", "--run", "latest"}} {
		if _, err := Parse(args, root, "i_019f596a-e201-7a4b-8d76-1cf503a1849e"); err == nil {
			t.Fatalf("context accepted selectors: %v", args)
		}
	}
}
