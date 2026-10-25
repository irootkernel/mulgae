package review_test

import (
	"bytes"
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/adapters/fakeprovider"
	"github.com/irootkernel/mulgae/internal/app/evidence"
	"github.com/irootkernel/mulgae/internal/app/prompt"
	"github.com/irootkernel/mulgae/internal/app/review"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

type e2eClock struct{ now time.Time }

func (clock e2eClock) Now() time.Time { return clock.now }

type e2eImmutableTargetReader struct {
	calls int
}

func (reader *e2eImmutableTargetReader) ReadImmutableTarget(
	_ context.Context,
	_ string,
	side evidence.Side,
	path ports.SafeRelativePath,
) (evidence.ImmutableTargetAvailability, []byte, error) {
	reader.calls++
	if side != evidence.SideHead || path.String() != "internal/app/coordinator.go" {
		return "", nil, fmt.Errorf("unexpected immutable target read for %s %s", side, path.String())
	}
	return evidence.ImmutableTargetAvailable, append(bytes.Repeat([]byte("\n"), 119), []byte("queueFallback(task)")...), nil
}

type e2eIDs struct {
	next          int
	reviewIDCalls int
}

func e2eUUID(number int) string {
	return fmt.Sprintf("019f5a09-5eec-7%03x-8%03x-%012x", number&0x0fff, number&0x0fff, number)
}

func (ids *e2eIDs) issue() string {
	ids.next++
	return e2eUUID(ids.next)
}

func (ids *e2eIDs) NewSessionID(time.Time) (domain.SessionID, error) {
	return domain.ParseSessionID("s_" + ids.issue())
}
func (ids *e2eIDs) NewRunID(time.Time) (domain.RunID, error) {
	return domain.ParseRunID("r_" + ids.issue())
}
func (ids *e2eIDs) NewAttemptID(time.Time) (domain.AttemptID, error) {
	return domain.ParseAttemptID("a_" + ids.issue())
}
func (ids *e2eIDs) NewReviewID(time.Time) (domain.ReviewID, error) {
	ids.reviewIDCalls++
	return domain.ParseReviewID(ids.issue())
}
func (ids *e2eIDs) NewRoleTaskID(time.Time) (string, error) {
	return "rt_" + ids.issue(), nil
}
func (ids *e2eIDs) NewSourceInvocationID(time.Time) (string, error) {
	return "i_" + ids.issue(), nil
}
func (ids *e2eIDs) NewExecutionInvocationID(time.Time) (string, error) {
	return ids.issue(), nil
}

type e2eInvocationIssuer struct {
	sources    []prompt.SourceInvocationID
	executions []prompt.ExecutionInvocationID
}

func (issuer *e2eInvocationIssuer) NewSourceInvocationID() (prompt.SourceInvocationID, error) {
	if len(issuer.sources) == 0 {
		return prompt.SourceInvocationID{}, fmt.Errorf("source identity queue exhausted")
	}
	id := issuer.sources[0]
	issuer.sources = issuer.sources[1:]
	return id, nil
}

func (issuer *e2eInvocationIssuer) NewExecutionInvocationID() (prompt.ExecutionInvocationID, error) {
	if len(issuer.executions) == 0 {
		return prompt.ExecutionInvocationID{}, fmt.Errorf("execution identity queue exhausted")
	}
	id := issuer.executions[0]
	issuer.executions = issuer.executions[1:]
	return id, nil
}

func e2eLayer(t *testing.T, id, content string) prompt.TrustedLayer {
	t.Helper()
	layer, err := prompt.NewTrustedLayer(id, "v1", []byte(content))
	if err != nil {
		t.Fatal(err)
	}
	return layer
}

func e2eTarget(t *testing.T) ports.CapturedGitTarget {
	t.Helper()
	base, err := ports.ParseGitObjectID("1111111111111111111111111111111111111111")
	if err != nil {
		t.Fatal(err)
	}
	head, err := ports.ParseGitObjectID("2222222222222222222222222222222222222222")
	if err != nil {
		t.Fatal(err)
	}
	tree, err := ports.ParseGitObjectID("3333333333333333333333333333333333333333")
	if err != nil {
		t.Fatal(err)
	}
	target, err := ports.NewCapturedGitTarget("e2e-repository", base, head, tree, nil, []byte("diff --git a/a.go b/a.go\n"))
	if err != nil {
		t.Fatal(err)
	}
	return target
}

func parseE2ESession(t *testing.T, number int) domain.SessionID {
	t.Helper()
	id, err := domain.ParseSessionID("s_" + e2eUUID(number))
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func parseE2ERun(t *testing.T, number int) domain.RunID {
	t.Helper()
	id, err := domain.ParseRunID("r_" + e2eUUID(number))
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func parseE2EAttempt(t *testing.T, number int) domain.AttemptID {
	t.Helper()
	id, err := domain.ParseAttemptID("a_" + e2eUUID(number))
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func parseE2ERoleTask(t *testing.T, number int) prompt.RoleTaskID {
	t.Helper()
	id, err := prompt.ParseRoleTaskID("rt_" + e2eUUID(number))
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func parseE2ESource(t *testing.T, number int) prompt.SourceInvocationID {
	t.Helper()
	id, err := prompt.ParseSourceInvocationID("i_" + e2eUUID(number))
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func parseE2EExecution(t *testing.T, number int) prompt.ExecutionInvocationID {
	t.Helper()
	id, err := prompt.ParseExecutionInvocationID(e2eUUID(number))
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func compileE2EPrompt(t *testing.T, template prompt.TrustedTemplate, sessionID domain.SessionID, runID domain.RunID, roleTaskID prompt.RoleTaskID, attemptID domain.AttemptID, sourceID prompt.SourceInvocationID, executionID prompt.ExecutionInvocationID, target []byte, prior *prompt.Payload) prompt.CompiledPrompt {
	t.Helper()
	coordinates, err := prompt.NewScopeCoordinates(sessionID, runID, roleTaskID, attemptID)
	if err != nil {
		t.Fatal(err)
	}
	compiler, err := prompt.NewCompiler(template, &e2eInvocationIssuer{
		sources:    []prompt.SourceInvocationID{sourceID},
		executions: []prompt.ExecutionInvocationID{executionID},
	})
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := compiler.Compile(prompt.CompileInput{
		Scope:               coordinates,
		ReviewTarget:        prompt.NewPayload(target),
		PriorProviderOutput: prior,
	})
	if err != nil {
		t.Fatal(err)
	}
	return compiled
}

func expectedE2ECall(provider string, role domain.Role, attemptID domain.AttemptID, purpose ports.ProviderInvocationPurpose, compiled prompt.CompiledPrompt, stdout []byte) fakeprovider.ExpectedCall {
	return fakeprovider.ExpectedCall{
		ProviderInstance:      provider,
		Role:                  role,
		Purpose:               purpose,
		AttemptID:             attemptID,
		SourceInvocationID:    compiled.Scope().SourceInvocationID().String(),
		ExecutionInvocationID: compiled.Scope().ExecutionInvocationID().String(),
		Stdin:                 compiled.Stdin(),
		Result:                fakeprovider.Result{Stdout: stdout},
	}
}

func e2eAssignment(t *testing.T, role domain.Role, provider string) review.Assignment {
	t.Helper()
	route, err := ports.NewProviderRoute(provider)
	if err != nil {
		t.Fatal(err)
	}
	assignment, err := review.NewScheduledAssignment(role, false, route)
	if err != nil {
		t.Fatal(err)
	}
	return assignment
}
