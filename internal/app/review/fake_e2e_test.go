package review_test

import (
	"bytes"
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/irootkernel/kkachi-agent-review/internal/adapters/fakeprovider"
	adapterjsonschema "github.com/irootkernel/kkachi-agent-review/internal/adapters/jsonschema"
	"github.com/irootkernel/kkachi-agent-review/internal/app/evidence"
	"github.com/irootkernel/kkachi-agent-review/internal/app/prompt"
	"github.com/irootkernel/kkachi-agent-review/internal/app/review"
	"github.com/irootkernel/kkachi-agent-review/internal/app/validation"
	"github.com/irootkernel/kkachi-agent-review/internal/builtin"
	"github.com/irootkernel/kkachi-agent-review/internal/domain"
	"github.com/irootkernel/kkachi-agent-review/internal/ports"
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

func TestFakeProviderE2ERepairNormalizationAndAxes(t *testing.T) {
	ctx := context.Background()
	common := e2eLayer(t, "common", "Common review constraints.")
	runLayer := e2eLayer(t, "review-run", "This is a review run.")
	jsonLayer := e2eLayer(t, "json-output", "Return JSON only.")
	logicLayer := e2eLayer(t, "logic", "Review logic defects.")
	securityLayer := e2eLayer(t, "security", "Review security defects.")
	target := e2eTarget(t)

	logicTemplate, err := prompt.ComposeTrustedTemplate("review-logic", "v1", common, runLayer, logicLayer, jsonLayer)
	if err != nil {
		t.Fatal(err)
	}
	securityTemplate, err := prompt.ComposeTrustedTemplate("review-security", "v1", common, runLayer, securityLayer, jsonLayer)
	if err != nil {
		t.Fatal(err)
	}
	initialRaw := []byte(`{"schema_version":"kar-provider-review-output.v2","completeness":"complete","limitations":[],"findings":[{"severity":"high","title":"Fallback after valid negative review","description":"The coordinator must preserve valid negative review results.","evidence":[{"current":{"path":"internal/app/coordinator.go","side":"head","line_start":120,"line_end":120,"quote":"queueFallback(task)"}}],"recommendation":"Treat valid findings as successful role output.","confidence":"high"}]}`)
	repairRaw := []byte(`{"schema_version":"kar-repair-patch.v1","repairs":[{"path":"/summary","value":"One high finding was identified."}]}`)
	validNoFindings := []byte(`{"schema_version":"kar-provider-review-output.v2","summary":"No findings were identified.","completeness":"complete","limitations":[],"findings":[]}`)

	sessionID := parseE2ESession(t, 1)
	runID := parseE2ERun(t, 2)
	logicAttemptID := parseE2EAttempt(t, 4)
	logicInitial := compileE2EPrompt(t, logicTemplate, sessionID, runID, parseE2ERoleTask(t, 3), logicAttemptID, parseE2ESource(t, 5), parseE2EExecution(t, 6), target.Bytes(), nil)
	repairBase, err := prompt.NewTrustedLayer("review-repair-base", "v1", logicTemplate.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	repairConstraints, err := prompt.NewTrustedLayer("review-repair-constraints", "v1", []byte("KAR REPAIR CONSTRAINTS/1\nmode:fill_missing_fields\nallowed_paths:\n- /summary\nReturn only the repair form required by mode.\nDo not change role, provider identity, finding count, severity, target identity, or unrelated fields."))
	if err != nil {
		t.Fatal(err)
	}
	repairTemplate, err := prompt.ComposeTrustedTemplate("review-repair-"+logicTemplate.ID(), "v1", repairBase, repairConstraints)
	if err != nil {
		t.Fatal(err)
	}
	prior := prompt.NewPayload(initialRaw)
	logicRepair := compileE2EPrompt(t, repairTemplate, sessionID, runID, parseE2ERoleTask(t, 3), logicAttemptID, parseE2ESource(t, 7), parseE2EExecution(t, 8), target.Bytes(), &prior)
	securityAttemptID := parseE2EAttempt(t, 10)
	securityInitial := compileE2EPrompt(t, securityTemplate, sessionID, runID, parseE2ERoleTask(t, 9), securityAttemptID, parseE2ESource(t, 11), parseE2EExecution(t, 12), target.Bytes(), nil)

	provider, err := fakeprovider.New([]fakeprovider.ExpectedCall{
		expectedE2ECall("fake.logic", domain.RoleLogic, logicAttemptID, ports.ProviderInvocationInitial, logicInitial, initialRaw),
		expectedE2ECall("fake.logic", domain.RoleLogic, logicAttemptID, ports.ProviderInvocationRepair, logicRepair, repairRaw),
		expectedE2ECall("fake.security", domain.RoleSecurity, securityAttemptID, ports.ProviderInvocationInitial, securityInitial, validNoFindings),
	})
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := adapterjsonschema.New(ctx, builtin.NewCatalog())
	if err != nil {
		t.Fatal(err)
	}
	schemaID, err := ports.ParseAssetID(validation.ProviderReviewSchemaID)
	if err != nil {
		t.Fatal(err)
	}
	reviewValidator, err := validation.NewReviewValidator(adapter, schemaID)
	if err != nil {
		t.Fatal(err)
	}
	reader := &e2eImmutableTargetReader{}
	verifier, err := evidence.NewVerifier(reader)
	if err != nil {
		t.Fatal(err)
	}
	ids := &e2eIDs{}
	service, err := review.NewService(e2eClock{now: time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)}, ids, provider, reviewValidator, verifier)
	if err != nil {
		t.Fatal(err)
	}
	logic, err := review.NewAssignment(domain.RoleLogic, false, "fake.logic")
	if err != nil {
		t.Fatal(err)
	}
	security, err := review.NewAssignment(domain.RoleSecurity, false, "fake.security")
	if err != nil {
		t.Fatal(err)
	}
	templates, err := review.NewTemplateSet(common, runLayer, jsonLayer, map[domain.Role]prompt.TrustedLayer{
		domain.RoleLogic:    logicLayer,
		domain.RoleSecurity: securityLayer,
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.Execute(ctx, review.NewRequest(target, []review.Assignment{logic, security}, templates, nil, ""))
	if err != nil {
		t.Fatal(err)
	}
	if len(provider.Transcript()) != 3 || ids.reviewIDCalls != 0 {
		t.Fatal("E2E review invoked an unexpected provider count or created final artifact identity")
	}
	if result.FallbackScheduled() || result.Outcomes().PublicationStatus() != domain.PublicationNotPublished {
		t.Fatal("E2E review scheduled fallback or acquired publication authority")
	}
	findings := result.Findings()
	if len(findings) != 1 || findings[0].ID() != "F001" || result.Outcomes().ContentVerdict() != domain.ContentRequestChanges || result.Outcomes().CoverageStatus() != domain.CoverageComplete {
		t.Fatalf("E2E result did not prove repair, normalization, and axes: findings=%#v axes=%#v", findings, result.Outcomes())
	}
	evidenceGroups := result.Evidence()
	if reader.calls != 1 || len(evidenceGroups) != 1 || !evidenceGroups[0].MatchesFinding(findings[0]) ||
		len(evidenceGroups[0].Receipts()) != 1 || evidenceGroups[0].Receipts()[0].Status() != evidence.ReceiptVerified {
		t.Fatalf("E2E verifier evidence = groups:%#v reads:%d", evidenceGroups, reader.calls)
	}
	findings[0] = domain.Finding{}
	if copied := result.Findings(); len(copied) != 1 || copied[0].ID() != "F001" {
		t.Fatal("E2E result findings were not defensively copied")
	}

	logicExecution := result.RoleExecutions()[0]
	wires := logicExecution.PromptWireIdentities()
	if !logicExecution.Repaired() || len(wires) != 2 || wires[0].SourceInvocationID() == wires[1].SourceInvocationID() || wires[0].ExecutionInvocationID() == wires[1].ExecutionInvocationID() {
		t.Fatal("E2E repair did not retain fresh source and execution wire identities")
	}
	wires[0] = review.PromptWireIdentity{}
	if restored := result.RoleExecutions()[0].PromptWireIdentities(); len(restored) != 2 || restored[0].Purpose() != ports.ProviderInvocationInitial {
		t.Fatal("E2E result prompt wires were not defensively copied")
	}
}
