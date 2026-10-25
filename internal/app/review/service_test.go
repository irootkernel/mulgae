package review

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/app/evidence"
	"github.com/irootkernel/mulgae/internal/app/prompt"
	"github.com/irootkernel/mulgae/internal/app/validation"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

type reviewTestClock struct{ now time.Time }

func (clock reviewTestClock) Now() time.Time { return clock.now }

type reviewTestIDs struct{ next int }

func (ids *reviewTestIDs) nextUUID() string {
	ids.next++
	return fmt.Sprintf("019f5a09-5eec-7%03x-8%03x-%012x", ids.next&0x0fff, ids.next&0x0fff, ids.next)
}

func (ids *reviewTestIDs) NewSessionID(time.Time) (domain.SessionID, error) {
	return domain.ParseSessionID("s_" + ids.nextUUID())
}
func (ids *reviewTestIDs) NewRunID(time.Time) (domain.RunID, error) {
	return domain.ParseRunID("r_" + ids.nextUUID())
}
func (ids *reviewTestIDs) NewAttemptID(time.Time) (domain.AttemptID, error) {
	return domain.ParseAttemptID("a_" + ids.nextUUID())
}
func (ids *reviewTestIDs) NewReviewID(time.Time) (domain.ReviewID, error) {
	return domain.ParseReviewID(ids.nextUUID())
}
func (ids *reviewTestIDs) NewRoleTaskID(time.Time) (string, error) {
	return "rt_" + ids.nextUUID(), nil
}
func (ids *reviewTestIDs) NewSourceInvocationID(time.Time) (string, error) {
	return "i_" + ids.nextUUID(), nil
}
func (ids *reviewTestIDs) NewExecutionInvocationID(time.Time) (string, error) {
	return ids.nextUUID(), nil
}

type controlledReviewIDs struct {
	*reviewTestIDs
	sourceCalls      int
	sourceFailureAt  int
	reuseSourceAt    int
	sourceFailure    error
	cancelSourceAt   int
	cancel           context.CancelFunc
	executionCalls   int
	reuseExecutionAt int
}

func (ids *controlledReviewIDs) NewSourceInvocationID(now time.Time) (string, error) {
	ids.sourceCalls++
	if ids.cancel != nil && ids.sourceCalls == ids.cancelSourceAt {
		ids.cancel()
	}
	if ids.sourceFailure != nil && ids.sourceCalls == ids.sourceFailureAt {
		return "", ids.sourceFailure
	}
	if ids.reuseSourceAt == ids.sourceCalls {
		return fmt.Sprintf("i_019f5a09-5eec-7%03x-8%03x-%012x", ids.next&0x0fff, ids.next&0x0fff, ids.next), nil
	}
	return ids.reviewTestIDs.NewSourceInvocationID(now)
}

func (ids *controlledReviewIDs) NewExecutionInvocationID(now time.Time) (string, error) {
	ids.executionCalls++
	if ids.reuseExecutionAt == ids.executionCalls {
		return fmt.Sprintf("019f5a09-5eec-7%03x-8%03x-%012x", ids.next&0x0fff, ids.next&0x0fff, ids.next), nil
	}
	return ids.reviewTestIDs.NewExecutionInvocationID(now)
}

type permissiveReviewSchema struct{}

func (permissiveReviewSchema) Validate(context.Context, ports.AssetID, []byte) error { return nil }

type reviewProviderResponse struct {
	stdout      []byte
	wireFail    bool
	lengthDelta int
	err         error
}

type recordingReviewProvider struct {
	responses   []reviewProviderResponse
	invocations []ports.ProviderInvocation
}

func (provider *recordingReviewProvider) Invoke(ctx context.Context, invocation ports.ProviderInvocation) (ports.ProviderResult, error) {
	if err := ctx.Err(); err != nil {
		return ports.ProviderResult{}, err
	}
	provider.invocations = append(provider.invocations, invocation)
	if len(provider.responses) == 0 {
		return ports.ProviderResult{}, errors.New("unexpected provider invocation")
	}
	response := provider.responses[0]
	provider.responses = provider.responses[1:]
	if response.err != nil {
		return ports.ProviderResult{}, response.err
	}
	digest := invocation.CompleteStdinSHA256()
	length := len(invocation.Stdin()) + response.lengthDelta
	if response.wireFail {
		digest = "0000000000000000000000000000000000000000000000000000000000000000"
	}
	return ports.NewProviderResult(response.stdout, length, digest)
}

func newReviewValidator(t *testing.T) *validation.ReviewValidator {
	t.Helper()
	schemaID, err := ports.ParseAssetID(validation.ProviderReviewSchemaID)
	if err != nil {
		t.Fatal(err)
	}
	validator, err := validation.NewReviewValidator(permissiveReviewSchema{}, schemaID)
	if err != nil {
		t.Fatal(err)
	}
	return validator
}

type reviewTestEvidenceResponse struct {
	availability evidence.ImmutableTargetAvailability
	bytes        []byte
	err          error
	cancel       context.CancelFunc
}

type reviewTestEvidenceReader struct {
	responses map[string]reviewTestEvidenceResponse
	calls     int
}

func (reader *reviewTestEvidenceReader) ReadImmutableTarget(
	_ context.Context,
	_ string,
	side evidence.Side,
	path ports.SafeRelativePath,
) (evidence.ImmutableTargetAvailability, []byte, error) {
	reader.calls++
	response, ok := reader.responses[reviewTestEvidenceKey(side, path.String())]
	if !ok {
		return "", nil, fmt.Errorf("unexpected immutable target read for %s %s", side, path.String())
	}
	if response.cancel != nil {
		response.cancel()
	}
	return response.availability, append([]byte(nil), response.bytes...), response.err
}

func reviewTestEvidenceKey(side evidence.Side, path string) string {
	return string(side) + "\x00" + path
}

func highFindingEvidenceBytes(quote string) []byte {
	return append(bytes.Repeat([]byte("\n"), 119), []byte(quote)...)
}

func verifiedHighFindingReader() *reviewTestEvidenceReader {
	return &reviewTestEvidenceReader{responses: map[string]reviewTestEvidenceResponse{
		reviewTestEvidenceKey(evidence.SideHead, "internal/app/coordinator.go"): {
			availability: evidence.ImmutableTargetAvailable,
			bytes:        highFindingEvidenceBytes("queueFallback(task)"),
		},
	}}
}

func newReviewTestVerifier(t *testing.T, reader evidence.ImmutableTargetReader) *evidence.Verifier {
	t.Helper()
	verifier, err := evidence.NewVerifier(reader)
	if err != nil {
		t.Fatal(err)
	}
	return verifier
}

func testTrustedLayer(t *testing.T, id, content string) prompt.TrustedLayer {
	t.Helper()
	layer, err := prompt.NewTrustedLayer(id, "v1", []byte(content))
	if err != nil {
		t.Fatal(err)
	}
	return layer
}

func requiredAssignments(t *testing.T) []Assignment {
	t.Helper()
	logic, err := NewScheduledAssignment(domain.RoleLogic, false, coordinatorTestRoute(t, "fake.logic"))
	if err != nil {
		t.Fatal(err)
	}
	security, err := NewScheduledAssignment(domain.RoleSecurity, false, coordinatorTestRoute(t, "fake.security"))
	if err != nil {
		t.Fatal(err)
	}
	return []Assignment{logic, security}
}

func allAssignments(t *testing.T) []Assignment {
	t.Helper()
	assignments := make([]Assignment, 0, len(domain.CoreRoleOrder()))
	for _, role := range domain.CoreRoleOrder() {
		assignment, err := NewScheduledAssignment(role, false, coordinatorTestRoute(t, "fake."+string(role)))
		if err != nil {
			t.Fatal(err)
		}
		assignments = append(assignments, assignment)
	}
	return assignments
}

func validNoFindingReview() []byte {
	return []byte(`{"schema_version":"mulgae-provider-review-output.v1","summary":"No findings were identified.","completeness":"complete","limitations":[],"findings":[]}`)
}

func validHighFindingReview() []byte {
	return []byte(`{"schema_version":"mulgae-provider-review-output.v1","summary":"One high finding was identified.","completeness":"complete","limitations":[],"findings":[{"severity":"high","title":"Fallback after valid negative review","description":"The coordinator must preserve valid negative review results.","evidence":[{"current":{"path":"internal/app/coordinator.go","side":"head","line_start":120,"line_end":120,"quote":"queueFallback(task)"}}],"recommendation":"Treat valid findings as successful role output.","confidence":"high"}]}`)
}
func validIncompleteHighFindingReview() []byte {
	return []byte(`{"schema_version":"mulgae-provider-review-output.v1","summary":"One incomplete high finding was identified.","completeness":"incomplete","limitations":["The provider could not inspect generated fixtures."],"findings":[{"severity":"high","title":"Fallback after valid negative review","description":"The coordinator must preserve valid negative review results.","evidence":[{"current":{"path":"internal/app/coordinator.go","side":"head","line_start":120,"line_end":120,"quote":"queueFallback(task)"}}],"recommendation":"Treat valid findings as successful role output.","confidence":"high"}]}`)
}

func repairableHighFindingReview() []byte {
	return []byte(`{"schema_version":"mulgae-provider-review-output.v1","completeness":"complete","limitations":[],"findings":[{"severity":"high","title":"Fallback after valid negative review","description":"The coordinator must preserve valid negative review results.","evidence":[{"current":{"path":"internal/app/coordinator.go","side":"head","line_start":120,"line_end":120,"quote":"queueFallback(task)"}}],"recommendation":"Treat valid findings as successful role output.","confidence":"high"}]}`)
}

func repairSummaryPatch() []byte {
	return []byte(`{"schema_version":"mulgae-repair-patch.v1","repairs":[{"path":"/summary","value":"One high finding was identified."}]}`)
}

func failureClass(t *testing.T, err error) domain.FailureClass {
	t.Helper()
	var failure *domain.Failure
	if !errors.As(err, &failure) {
		t.Fatalf("error %T = %v, want *domain.Failure", err, err)
	}
	return failure.Class()
}
