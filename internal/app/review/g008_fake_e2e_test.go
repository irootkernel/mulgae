package review_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/adapters/fakeprovider"
	adapterjsonschema "github.com/irootkernel/mulgae/internal/adapters/jsonschema"
	"github.com/irootkernel/mulgae/internal/app/evidence"
	"github.com/irootkernel/mulgae/internal/app/prompt"
	"github.com/irootkernel/mulgae/internal/app/review"
	"github.com/irootkernel/mulgae/internal/app/validation"
	"github.com/irootkernel/mulgae/internal/builtin"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

// g008PromptSource binds the coordinator to real compiled provider packets. It
// deliberately has no provider-output authority: repair material is supplied by
// ProviderInvocationRuntime only after validation returns a repair plan.
type g008PromptSource struct {
	packets map[string]review.RuntimePrompt
}

func (s g008PromptSource) Prompt(_ context.Context, job review.InvocationJob, repair *review.InvocationRepairInput) (review.RuntimePrompt, error) {
	if job.Purpose() == domain.InvocationRepair && repair == nil {
		return review.RuntimePrompt{}, fmt.Errorf("missing repair input")
	}
	packet, ok := s.packets[fmt.Sprintf("%s/%s", job.Role(), job.Purpose())]
	if !ok {
		return review.RuntimePrompt{}, fmt.Errorf("unexpected job %s/%s", job.Role(), job.Purpose())
	}
	return packet, nil
}

func TestIntegrationG008ProviderRuntimeCapturesRepairArtifactsDeterministically(t *testing.T) {
	ctx := context.Background()
	target := e2eTarget(t)
	identity, err := domain.NewTargetIdentity(domain.TargetIdentityInput{Kind: domain.TargetGit, SHA256: strings.TrimPrefix(target.SHA256(), "sha256:"), RepositoryID: target.RepositoryID(), BaseObjectID: target.BaseObjectID().String(), HeadObjectID: target.HeadObjectID().String(), HeadTreeObjectID: target.HeadTreeID().String()})
	if err != nil {
		t.Fatal(err)
	}
	common := e2eLayer(t, "common", "Common review constraints.")
	runLayer := e2eLayer(t, "review-run", "This is a review run.")
	jsonLayer := e2eLayer(t, "json-output", "Return JSON only.")
	logicLayer := e2eLayer(t, "logic", "Review logic defects.")
	securityLayer := e2eLayer(t, "security", "Review security defects.")
	logicTemplate, err := prompt.ComposeTrustedTemplate("review-logic", "v1", common, runLayer, logicLayer, jsonLayer)
	if err != nil {
		t.Fatal(err)
	}
	securityTemplate, err := prompt.ComposeTrustedTemplate("review-security", "v1", common, runLayer, securityLayer, jsonLayer)
	if err != nil {
		t.Fatal(err)
	}
	ids := &e2eIDs{}
	sessionID, runID, attemptID := parseE2ESession(t, 1), parseE2ERun(t, 2), parseE2EAttempt(t, 3)
	initial := compileE2EPrompt(t, logicTemplate, sessionID, runID, parseE2ERoleTask(t, 5), attemptID, parseE2ESource(t, 7), parseE2EExecution(t, 8), target.Bytes(), nil)
	repairBase, err := prompt.NewTrustedLayer("repair-base", "v1", logicTemplate.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	repairRules, err := prompt.NewTrustedLayer("repair-rules", "v1", []byte("Mulgae REPAIR CONSTRAINTS/1\nmode:fill_missing_fields\nallowed_paths:\n- /summary\nReturn only the repair form required by mode."))
	if err != nil {
		t.Fatal(err)
	}
	repairTemplate, err := prompt.ComposeTrustedTemplate("repair", "v1", repairBase, repairRules)
	if err != nil {
		t.Fatal(err)
	}
	initialRaw := []byte(`{"schema_version":"mulgae-provider-review-output.v1","completeness":"complete","limitations":[],"findings":[{"severity":"high","title":"Fallback after valid negative review","description":"The coordinator must preserve valid negative review results.","evidence":[{"current":{"path":"internal/app/coordinator.go","side":"head","line_start":120,"line_end":120,"quote":"queueFallback(task)"}}],"recommendation":"Treat valid findings as successful role output.","confidence":"high"}]}`)
	prior := prompt.NewPayload(initialRaw)
	repair := compileE2EPrompt(t, repairTemplate, sessionID, runID, parseE2ERoleTask(t, 5), attemptID, parseE2ESource(t, 9), parseE2EExecution(t, 10), target.Bytes(), &prior)
	securityAttempt := parseE2EAttempt(t, 4)
	security := compileE2EPrompt(t, securityTemplate, sessionID, runID, parseE2ERoleTask(t, 6), securityAttempt, parseE2ESource(t, 11), parseE2EExecution(t, 12), target.Bytes(), nil)
	extraRoles := []domain.Role{domain.RoleMaintainability, domain.RoleProduct, domain.RoleDocumentation, domain.RoleTesting}
	extraAttempts := []domain.AttemptID{parseE2EAttempt(t, 5), parseE2EAttempt(t, 6), parseE2EAttempt(t, 7), parseE2EAttempt(t, 8)}
	extraPackets := make([]prompt.CompiledPrompt, 0, len(extraRoles))
	for index := range extraRoles {
		extraPackets = append(extraPackets, compileE2EPrompt(t, securityTemplate, sessionID, runID, parseE2ERoleTask(t, 13+index), extraAttempts[index], parseE2ESource(t, 21+index*2), parseE2EExecution(t, 22+index*2), target.Bytes(), nil))
	}
	// The initial packet is schema-invalid (missing summary), forcing the real validator repair path.
	invalid := initialRaw
	fixed := []byte(`{"schema_version":"mulgae-repair-patch.v1","repairs":[{"path":"/summary","value":"One high finding was identified."}]}`)
	valid := []byte(`{"schema_version":"mulgae-provider-review-output.v1","summary":"No findings.","completeness":"complete","limitations":[],"findings":[]}`)
	provider, err := fakeprovider.New([]fakeprovider.ExpectedCall{
		expectedE2ECall("fake.logic", domain.RoleLogic, attemptID, ports.ProviderInvocationInitial, initial, invalid),
		expectedE2ECall("fake.security", domain.RoleSecurity, securityAttempt, ports.ProviderInvocationInitial, security, valid),
		expectedE2ECall("fake.maintainability", domain.RoleMaintainability, extraAttempts[0], ports.ProviderInvocationInitial, extraPackets[0], valid),
		expectedE2ECall("fake.product", domain.RoleProduct, extraAttempts[1], ports.ProviderInvocationInitial, extraPackets[1], valid),
		expectedE2ECall("fake.documentation", domain.RoleDocumentation, extraAttempts[2], ports.ProviderInvocationInitial, extraPackets[2], valid),
		expectedE2ECall("fake.testing", domain.RoleTesting, extraAttempts[3], ports.ProviderInvocationInitial, extraPackets[3], valid),
		expectedE2ECall("fake.logic", domain.RoleLogic, attemptID, ports.ProviderInvocationRepair, repair, fixed),
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
	validator, err := validation.NewReviewValidator(adapter, schemaID)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := evidence.NewVerifier(&e2eImmutableTargetReader{})
	if err != nil {
		t.Fatal(err)
	}
	packets := map[string]review.RuntimePrompt{
		fmt.Sprintf("%s/%s", domain.RoleLogic, domain.InvocationInitial):    {Prompt: initial, Target: target.Bytes()},
		fmt.Sprintf("%s/%s", domain.RoleLogic, domain.InvocationRepair):     {Prompt: repair, Target: target.Bytes()},
		fmt.Sprintf("%s/%s", domain.RoleSecurity, domain.InvocationInitial): {Prompt: security, Target: target.Bytes()},
	}
	for index, role := range extraRoles {
		packets[fmt.Sprintf("%s/%s", role, domain.InvocationInitial)] = review.RuntimePrompt{Prompt: extraPackets[index], Target: target.Bytes()}
	}
	runtime, err := review.NewProviderInvocationRuntime(provider, g008PromptSource{packets: packets}, validator, verifier)
	if err != nil {
		t.Fatal(err)
	}
	limit, err := review.NewInvocationLimits(time.Second, 256<<10, 256<<10)
	if err != nil {
		t.Fatal(err)
	}
	logicRoute, err := ports.NewProviderRoute("fake.logic", mustG008Key(t, "g008"))
	if err != nil {
		t.Fatal(err)
	}
	securityRoute, err := ports.NewProviderRoute("fake.security", mustG008Key(t, "g008"))
	if err != nil {
		t.Fatal(err)
	}
	routes := map[domain.Role]ports.ProviderRoute{
		domain.RoleLogic:    logicRoute,
		domain.RoleSecurity: securityRoute,
	}
	for _, role := range extraRoles {
		route, routeErr := ports.NewProviderRoute("fake."+string(role), mustG008Key(t, "g008"))
		if routeErr != nil {
			t.Fatal(routeErr)
		}
		routes[role] = route
	}
	budgets := make([]review.RoleBudget, 0, len(domain.CoreRoleOrder()))
	assignments := make([]review.Assignment, 0, len(domain.CoreRoleOrder()))
	for _, role := range domain.CoreRoleOrder() {
		budget, budgetErr := review.NewRouteBudget(routes[role], limit)
		if budgetErr != nil {
			t.Fatal(budgetErr)
		}
		roleBudget, roleBudgetErr := review.NewRoleBudget(role, budget)
		if roleBudgetErr != nil {
			t.Fatal(roleBudgetErr)
		}
		assignment, assignmentErr := review.NewScheduledAssignment(role, false, routes[role])
		if assignmentErr != nil {
			t.Fatal(assignmentErr)
		}
		budgets = append(budgets, roleBudget)
		assignments = append(assignments, assignment)
	}
	receipt, err := review.PreflightRunBudgetWithCapacity(budgets, review.DefaultHarnessCeilings(), 1)
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := review.NewCoordinator(e2eClock{now: time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)}, ids, runtime, 1, receipt)
	if err != nil {
		t.Fatal(err)
	}
	result, err := coordinator.Execute(ctx, identity, assignments, domain.SeverityHigh, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.RunID() != runID || len(provider.Transcript()) != 7 {
		t.Fatalf("unexpected deterministic execution: run=%s state=%s roles=%#v trace=%#v calls=%d", result.RunID(), result.RunState(), result.RoleSummaries(), result.Trace(), len(provider.Transcript()))
	}
	captures := runtime.Captures()
	if len(captures) != 7 {
		t.Fatalf("captures=%d, want repair-inclusive 7", len(captures))
	}
	var repaired bool
	for _, capture := range captures {
		if capture.AttemptID() != attemptID {
			continue
		}
		for _, artifact := range capture.Artifacts() {
			if artifact.Kind() == ports.AttemptArtifactRepairedCandidate {
				repaired = true
			}
		}
	}
	if !repaired {
		t.Fatal("repaired attempt artifact was not retained")
	}
}

func mustG008Key(t *testing.T, value string) ports.ConcurrencyKey {
	t.Helper()
	key, err := ports.ParseConcurrencyKey(value)
	if err != nil {
		t.Fatal(err)
	}
	return key
}
