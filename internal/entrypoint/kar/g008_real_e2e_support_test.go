package kar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/irootkernel/kkachi-agent-review/internal/adapters/filesystem"
	adapterjsonschema "github.com/irootkernel/kkachi-agent-review/internal/adapters/jsonschema"
	"github.com/irootkernel/kkachi-agent-review/internal/app/childrun"
	"github.com/irootkernel/kkachi-agent-review/internal/app/evidence"
	appfollowup "github.com/irootkernel/kkachi-agent-review/internal/app/followup"
	"github.com/irootkernel/kkachi-agent-review/internal/app/prompt"
	"github.com/irootkernel/kkachi-agent-review/internal/app/publication"
	appquery "github.com/irootkernel/kkachi-agent-review/internal/app/query"
	"github.com/irootkernel/kkachi-agent-review/internal/app/review"
	"github.com/irootkernel/kkachi-agent-review/internal/app/validation"
	"github.com/irootkernel/kkachi-agent-review/internal/builtin"
	"github.com/irootkernel/kkachi-agent-review/internal/domain"
	"github.com/irootkernel/kkachi-agent-review/internal/ports"
)

// g008RealE2EFixture is deliberately test-local. It supplies real storage,
// validation, provider observation, and publication authority to sibling G008 E2E tests.
type g008RealE2EFixture struct {
	root             ports.AnchoredRoot
	clock            g008RealE2EClock
	ids              *g008RealE2EIDs
	validator        *adapterjsonschema.Validator
	writer           *filesystem.SecureWriter
	store            *filesystem.PublicationStore
	queries          *appquery.Service
	publisher        *publication.Service
	coordinator      *review.Coordinator
	runtime          *review.ProviderInvocationRuntime
	followupPrompts  g008RealE2EFollowupPromptSource
	provider         *g008RealE2EProvider
	assignments      []review.Assignment
	target           domain.TargetIdentity
	childExecutor    *childrun.Executor
	followupExecutor *childrun.FollowupExecutor
}

type g008RealE2ERootResult struct {
	SessionID         domain.SessionID
	RunID             domain.RunID
	ReviewID          domain.ReviewID
	AttemptID         domain.AttemptID
	SecurityAttemptID domain.AttemptID
	Queries           *appquery.Service
	Sources           *G008Sources
	Transcript        []g008RealE2EProviderCall
}

type g008RealE2EClock struct{ now time.Time }

func (clock g008RealE2EClock) Now() time.Time { return clock.now }

type g008RealE2EIDs struct{ next int }

func (ids *g008RealE2EIDs) issue() string {
	ids.next++
	return fmt.Sprintf("019f5a09-5eec-7%03x-8%03x-%012x", ids.next, ids.next, ids.next)
}
func (ids *g008RealE2EIDs) NewSessionID(time.Time) (domain.SessionID, error) {
	return domain.ParseSessionID("s_" + ids.issue())
}
func (ids *g008RealE2EIDs) NewRunID(time.Time) (domain.RunID, error) {
	return domain.ParseRunID("r_" + ids.issue())
}
func (ids *g008RealE2EIDs) NewAttemptID(time.Time) (domain.AttemptID, error) {
	return domain.ParseAttemptID("a_" + ids.issue())
}
func (ids *g008RealE2EIDs) NewReviewID(time.Time) (domain.ReviewID, error) {
	return domain.ParseReviewID(ids.issue())
}
func (ids *g008RealE2EIDs) NewRequestID(time.Time) (string, error) { return "i_" + ids.issue(), nil }

type g008RealE2EInvocationIDs struct{ next int }

func (ids *g008RealE2EInvocationIDs) issue() string {
	ids.next++
	return fmt.Sprintf("019f5a09-5eed-7%03x-8%03x-%012x", ids.next, ids.next, ids.next)
}
func (ids *g008RealE2EInvocationIDs) NewSourceInvocationID() (prompt.SourceInvocationID, error) {
	return prompt.ParseSourceInvocationID("i_" + ids.issue())
}
func (ids *g008RealE2EInvocationIDs) NewExecutionInvocationID() (prompt.ExecutionInvocationID, error) {
	return prompt.ParseExecutionInvocationID(ids.issue())
}

type g008RealE2EPromptSource struct {
	mu       sync.Mutex
	compiler *prompt.Compiler
	next     int
	cache    map[string]review.RuntimePrompt
	targets  map[string][]byte
}

func (source *g008RealE2EPromptSource) Prompt(_ context.Context, job review.InvocationJob, repair *review.InvocationRepairInput) (review.RuntimePrompt, error) {
	source.mu.Lock()
	defer source.mu.Unlock()
	if (job.Purpose() == domain.InvocationRepair) != (repair != nil) {
		return review.RuntimePrompt{}, fmt.Errorf("unexpected repair material for %s", job.Purpose())
	}
	key := fmt.Sprintf("%s/%s/%s", job.RunID(), job.AttemptID(), job.Purpose())
	if packet, ok := source.cache[key]; ok {
		return packet, nil
	}
	source.next++
	roleTask, err := prompt.ParseRoleTaskID(fmt.Sprintf("rt_019f5a09-5eee-7%03x-8%03x-%012x", source.next, source.next, source.next))
	if err != nil {
		return review.RuntimePrompt{}, err
	}
	scope, err := prompt.NewScopeCoordinates(job.SessionID(), job.RunID(), roleTask, job.AttemptID())
	if err != nil {
		return review.RuntimePrompt{}, err
	}
	target, ok := source.targets[job.Target().SHA256()]
	if !ok {
		return review.RuntimePrompt{}, fmt.Errorf("missing fixture target bytes for %s", job.Target().SHA256())
	}
	input := prompt.CompileInput{Scope: scope, ReviewTarget: prompt.NewPayload(target)}
	if repair != nil {
		prior := prompt.NewPayload(repair.InitialCandidate())
		input.PriorProviderOutput = &prior
	}
	compiled, err := source.compiler.Compile(input)
	if err != nil {
		return review.RuntimePrompt{}, err
	}
	packet := review.RuntimePrompt{Prompt: compiled, Target: target, AdapterProfile: "g008-real"}
	source.cache[key] = packet
	return packet, nil
}
func (source *g008RealE2EPromptSource) DeltaPrompt(_ context.Context, job review.InvocationJob, material review.DeltaInvocationMaterial, repair *review.InvocationRepairInput) (review.RuntimePrompt, error) {
	source.mu.Lock()
	defer source.mu.Unlock()
	source.next++
	roleTask, err := prompt.ParseRoleTaskID(fmt.Sprintf("rt_019f5a09-5eee-7%03x-8%03x-%012x", source.next, source.next, source.next))
	if err != nil {
		return review.RuntimePrompt{}, err
	}
	scope, err := prompt.NewScopeCoordinates(job.SessionID(), job.RunID(), roleTask, job.AttemptID())
	if err != nil {
		return review.RuntimePrompt{}, err
	}
	sourcePayload := prompt.NewPayload(material.SourceTarget)
	deltaPayload := prompt.NewPayload(material.Delta)
	input := prompt.CompileInput{
		Scope:          scope,
		ProjectContext: &sourcePayload,
		ReviewTarget:   prompt.NewPayload(material.CurrentTarget),
		PriorReport:    &deltaPayload,
	}
	if repair != nil {
		prior := prompt.NewPayload(repair.InitialCandidate())
		input.PriorProviderOutput = &prior
	}
	compiled, err := source.compiler.Compile(input)
	if err != nil {
		return review.RuntimePrompt{}, err
	}
	return review.RuntimePrompt{
		Prompt: compiled, Target: append([]byte(nil), material.CurrentTarget...),
		AdapterProfile: "g008-real",
	}, nil
}

func (source *g008RealE2EPromptSource) ExactReplayPrompt(_ context.Context, job review.InvocationJob, input review.ExactReplayInput) (review.RuntimePrompt, error) {
	source.mu.Lock()
	defer source.mu.Unlock()
	if job.Route().ProviderInstance() != "g008."+string(input.Role) {
		return review.RuntimePrompt{}, fmt.Errorf("unexpected exact replay provider route %q", job.Route().ProviderInstance())
	}
	for _, material := range source.cache {
		if material.Prompt.Scope().AttemptID() != input.SourceAttemptID ||
			material.Prompt.CompleteStdinSHA256() != input.CompleteStdinSHA256 ||
			string(material.Prompt.Stdin()) != string(input.Stdin) ||
			material.Prompt.Scope().SourceInvocationID().String() != input.SourceInvocationID {
			continue
		}
		replayed, err := source.compiler.Replay(material.Prompt)
		if err != nil {
			return review.RuntimePrompt{}, err
		}
		target, ok := source.targets[job.Target().SHA256()]
		if !ok {
			return review.RuntimePrompt{}, fmt.Errorf("missing fixture replay target bytes for %s", job.Target().SHA256())
		}
		return review.RuntimePrompt{
			Prompt: replayed, Target: append([]byte(nil), target...),
			AdapterProfile: input.AdapterProfile, AdapterParameters: input.AdapterParameters,
		}, nil
	}
	return review.RuntimePrompt{}, fmt.Errorf("missing exact replay source prompt")
}

type g008RealE2EImmutableTarget struct{}

func (g008RealE2EImmutableTarget) ReadImmutableTarget(_ context.Context, _ string, side evidence.Side, path ports.SafeRelativePath) (evidence.ImmutableTargetAvailability, []byte, error) {
	if side != evidence.SideHead || path.String() != "internal/app/coordinator.go" {
		return "", nil, fmt.Errorf("unexpected immutable target %s %s", side, path)
	}
	return evidence.ImmutableTargetAvailable, append(bytes.Repeat([]byte("\n"), 119), []byte("queueFallback(task)")...), nil
}

type g008RealE2EFollowupPromptSource struct{ provider *g008RealE2EProvider }

func (source g008RealE2EFollowupPromptSource) BuildFollowupInvocation(_ context.Context, execution appfollowup.Execution, _ domain.Run, attemptID domain.AttemptID) (ports.ProviderInvocation, error) {
	stdin := []byte("followup:" + execution.Source.RunID.String() + ":" + execution.Source.Finding.ID)
	hash := sha256.New()
	_, _ = hash.Write([]byte("KAR-PROVIDER-STDIN/1"))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write(stdin)
	source.provider.mu.Lock()
	source.provider.followup = []byte(`{"schema_version":"kar-provider-followup-output.v2","summary":"F001 remains open.","resolution":"still_open","rationale":"The current target preserves the source finding.","evidence":[{"current":{"path":"internal/app/coordinator.go","line_start":1,"line_end":1,"side":"head","quote":"queueFallback(task)"}}],"new_findings":[],"limitations":[]}`)
	source.provider.mu.Unlock()
	return ports.NewProviderInvocation(execution.Source.Finding.Role, "g008.logic", attemptID, ports.ProviderInvocationInitial, stdin, "i_019f5a09-5eed-7001-8001-000000000001", "019f5a09-5eed-7002-8002-000000000002", hex.EncodeToString(hash.Sum(nil)))
}

func (source g008RealE2EFollowupPromptSource) BuildFollowupRuntimeArtifact(_ context.Context, execution appfollowup.Execution, run domain.Run, invocation ports.ProviderInvocation) (publication.FollowupRuntimeArtifactInput, error) {
	return publication.FollowupRuntimeArtifactInput{
		RuntimeRunID:                 run.ID(),
		RuntimeAttemptID:             invocation.AttemptID(),
		RuntimeSequence:              1,
		RuntimePurpose:               domain.InvocationInitial,
		RuntimeRole:                  invocation.Role(),
		RuntimeTarget:                append([]byte(nil), execution.Current.Bytes...),
		RuntimeTargetIdentity:        execution.Current.Identity,
		RuntimeStdin:                 invocation.Stdin(),
		RuntimeStdinSHA256:           invocation.CompleteStdinSHA256(),
		RuntimeTemplateID:            "g008-followup",
		RuntimeTemplateVersion:       "v1",
		RuntimeTemplateSHA256:        g008RealTargetHash([]byte("g008-followup-template-v1")),
		RuntimeSourceInvocationID:    invocation.SourceInvocationID(),
		RuntimeExecutionInvocationID: invocation.ExecutionInvocationID(),
		RuntimeScope:                 run.SessionID().String() + "/" + run.ID().String() + "/" + invocation.AttemptID().String(),
		RuntimeAdapterProfile:        "g008-real",
		RuntimeAdapterParameters:     map[string]string{},
	}, nil
}

type g008RealE2EProviderCall struct {
	AttemptID   domain.AttemptID
	Purpose     ports.ProviderInvocationPurpose
	StdinSHA256 string
}
type g008RealE2EProvider struct {
	mu              sync.Mutex
	calls           []g008RealE2EProviderCall
	followup        []byte
	logicNoFindings bool
}

func (provider *g008RealE2EProvider) Observe(_ context.Context, invocation ports.ProviderInvocation) (ports.ProviderExecutionObservation, error) {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	provider.calls = append(provider.calls, g008RealE2EProviderCall{AttemptID: invocation.AttemptID(), Purpose: invocation.Purpose(), StdinSHA256: invocation.CompleteStdinSHA256()})
	var stdout []byte
	switch {
	case provider.followup != nil && bytes.HasPrefix(invocation.Stdin(), []byte("followup:")):
		stdout = append([]byte(nil), provider.followup...)
		provider.followup = nil
	case provider.logicNoFindings && invocation.Role() == domain.RoleLogic && invocation.Purpose() == ports.ProviderInvocationInitial:
		stdout = []byte(`{"schema_version":"kar-provider-review-output.v2","summary":"No logic findings.","completeness":"complete","limitations":[],"findings":[]}`)
	case invocation.Role() == domain.RoleLogic && invocation.Purpose() == ports.ProviderInvocationInitial:
		stdout = []byte(`{"schema_version":"kar-provider-review-output.v2","summary":"F001: one high finding.","completeness":"complete","limitations":[],"findings":[{"severity":"high","title":"F001","description":"Fallback must preserve valid negative review results.","evidence":[{"current":{"path":"internal/app/coordinator.go","side":"head","line_start":120,"line_end":120,"quote":"queueFallback(task)"}}],"recommendation":"Preserve the valid result.","confidence":"high"}]}`)
	case invocation.Role() == domain.RoleLogic && invocation.Purpose() == ports.ProviderInvocationRepair:
		stdout = []byte(`{"schema_version":"kar-repair-patch.v1","repairs":[{"path":"/summary","value":"F001: one high finding."}]}`)
	case invocation.Role() == domain.RoleSecurity && invocation.Purpose() == ports.ProviderInvocationInitial:
		stdout = []byte(`{"schema_version":"kar-provider-review-output.v2","summary":"No security findings.","completeness":"complete","limitations":[],"findings":[]}`)
	case invocation.Purpose() == ports.ProviderInvocationInitial:
		stdout = []byte(`{"schema_version":"kar-provider-review-output.v2","summary":"No findings.","completeness":"complete","limitations":[],"findings":[]}`)
	default:
		return ports.ProviderExecutionObservation{}, fmt.Errorf("unexpected scripted provider call %s/%s", invocation.Role(), invocation.Purpose())
	}
	result, err := ports.NewProviderResult(stdout, len(invocation.Stdin()), invocation.CompleteStdinSHA256())
	if err != nil {
		return ports.ProviderExecutionObservation{}, err
	}
	receipt, err := ports.NewStdinWriteReceipt(int64(len(invocation.Stdin())), int64(len(invocation.Stdin())), invocation.CompleteStdinSHA256(), true)
	if err != nil {
		return ports.ProviderExecutionObservation{}, err
	}
	exit := 0
	process, err := ports.NewProcessObservation(stdout, nil, &exit, ports.ProcessTerminationExited, receipt, time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC), time.Date(2026, 7, 14, 12, 0, 1, 0, time.UTC))
	if err != nil {
		return ports.ProviderExecutionObservation{}, err
	}
	return ports.NewSuccessfulProviderExecutionObservation(invocation, result, process, 256<<10, 256<<10)
}
func (provider *g008RealE2EProvider) Invoke(ctx context.Context, invocation ports.ProviderInvocation) (ports.ProviderResult, error) {
	observation, err := provider.Observe(ctx, invocation)
	if err != nil {
		return ports.ProviderResult{}, err
	}
	result, ok := observation.Result()
	if !ok {
		return ports.ProviderResult{}, fmt.Errorf("fixture provider returned no result")
	}
	return result, nil
}
func (provider *g008RealE2EProvider) Transcript() []g008RealE2EProviderCall {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	return append([]g008RealE2EProviderCall(nil), provider.calls...)
}

func newG008RealE2EFixture(t *testing.T) *g008RealE2EFixture {
	t.Helper()
	ctx := context.Background()
	root, err := ports.NewAnchoredRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root.String(), 0o700); err != nil {
		t.Fatal(err)
	}
	catalog := builtin.NewCatalog()
	validator, err := adapterjsonschema.New(ctx, catalog)
	if err != nil {
		t.Fatal(err)
	}
	clock := g008RealE2EClock{now: time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)}
	ids := &g008RealE2EIDs{}
	writer := filesystem.NewSecureWriter()
	store, err := filesystem.NewPublicationStore(validator, clock, ids, writer)
	if err != nil {
		t.Fatal(err)
	}
	queries, err := appquery.NewService(store, validator, nil, 8<<20)
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := publication.NewService(store, validator, clock, 8<<20)
	if err != nil {
		t.Fatal(err)
	}
	base, _ := ports.ParseGitObjectID("1111111111111111111111111111111111111111")
	head, _ := ports.ParseGitObjectID("2222222222222222222222222222222222222222")
	tree, _ := ports.ParseGitObjectID("3333333333333333333333333333333333333333")
	captured, err := ports.NewCapturedGitTarget("g008-fixture", base, head, tree, nil, []byte("diff --git a/a.go b/a.go\n"))
	if err != nil {
		t.Fatal(err)
	}
	target, err := domain.NewTargetIdentity(domain.TargetIdentityInput{Kind: domain.TargetGit, SHA256: strings.TrimPrefix(captured.SHA256(), "sha256:"), RepositoryID: captured.RepositoryID(), BaseObjectID: captured.BaseObjectID().String(), HeadObjectID: captured.HeadObjectID().String(), HeadTreeObjectID: captured.HeadTreeID().String()})
	if err != nil {
		t.Fatal(err)
	}
	schema, _ := ports.ParseAssetID(validation.ProviderReviewSchemaID)
	reviewValidator, err := validation.NewReviewValidator(validator, schema)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := evidence.NewVerifier(g008RealE2EImmutableTarget{})
	if err != nil {
		t.Fatal(err)
	}
	layer, err := prompt.NewTrustedLayer("g008-real", "v1", []byte("Return the required JSON review output."))
	if err != nil {
		t.Fatal(err)
	}
	template, err := prompt.ComposeTrustedTemplate("g008-real", "v1", layer)
	if err != nil {
		t.Fatal(err)
	}
	compiler, err := prompt.NewCompiler(template, &g008RealE2EInvocationIDs{})
	if err != nil {
		t.Fatal(err)
	}
	patchBytes := []byte("queueFallback(task)")
	patchTarget, err := domain.NewTargetIdentity(domain.TargetIdentityInput{Kind: domain.TargetPatch, SHA256: g008RealTargetHash(patchBytes)})
	if err != nil {
		t.Fatal(err)
	}
	prompts := &g008RealE2EPromptSource{compiler: compiler, cache: make(map[string]review.RuntimePrompt), targets: map[string][]byte{target.SHA256(): captured.Bytes(), patchTarget.SHA256(): patchBytes}}
	provider := &g008RealE2EProvider{}
	runtime, err := review.NewObservedProviderInvocationRuntime(provider, prompts, reviewValidator, verifier)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := ports.ParseConcurrencyKey("g008")
	limits, _ := review.NewInvocationLimits(time.Second, 256<<10, 256<<10)
	roleBudgets := make([]review.RoleBudget, 0, len(domain.FixedRoleOrder()))
	assignments := make([]review.Assignment, 0, len(domain.FixedRoleOrder()))
	for _, role := range domain.FixedRoleOrder() {
		route, routeErr := ports.NewProviderRoute("g008."+string(role), key)
		if routeErr != nil {
			t.Fatal(routeErr)
		}
		routeBudget, budgetErr := review.NewRouteBudget(route, limits)
		if budgetErr != nil {
			t.Fatal(budgetErr)
		}
		roleBudget, budgetErr := review.NewRoleBudget(role, routeBudget, nil)
		if budgetErr != nil {
			t.Fatal(budgetErr)
		}
		assignment, assignmentErr := review.NewScheduledAssignment(role, false, route, nil)
		if assignmentErr != nil {
			t.Fatal(assignmentErr)
		}
		roleBudgets = append(roleBudgets, roleBudget)
		assignments = append(assignments, assignment)
	}
	receipt, err := review.PreflightRunBudget(roleBudgets, review.DefaultHarnessCeilings())
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := review.NewCoordinator(clock, ids, runtime, nil, 1, receipt)
	if err != nil {
		t.Fatal(err)
	}
	fixture := &g008RealE2EFixture{root: root, clock: clock, ids: ids, validator: validator, writer: writer, store: store, queries: queries, publisher: publisher, coordinator: coordinator, runtime: runtime, provider: provider, assignments: assignments, target: target}
	fixture.followupPrompts = g008RealE2EFollowupPromptSource{provider: provider}
	fixture.childExecutor, err = childrun.NewExecutor(coordinator, runtime, publisher, root, childrun.ExecutorConfig{Assignments: fixture.assignments, SeverityThreshold: domain.SeverityHigh, KARVersion: "g008-test", KARCommit: "g008-test"})
	if err != nil {
		t.Fatal(err)
	}
	followupSchema, _ := ports.ParseAssetID(validation.ProviderFollowupSchemaID)
	followupValidator, err := validation.NewFollowupValidator(validator, followupSchema)
	if err != nil {
		t.Fatal(err)
	}
	fixture.followupExecutor, err = childrun.NewFollowupExecutor(clock, ids, provider, fixture.followupPrompts, followupValidator, publisher, root, childrun.FollowupExecutorConfig{ProviderInstance: "g008.logic", SeverityThreshold: domain.SeverityHigh, KARVersion: "g008-test", KARCommit: "g008-test"})
	if err != nil {
		t.Fatal(err)
	}
	return fixture
}

func (fixture *g008RealE2EFixture) executeAndPublishRoot(t *testing.T) g008RealE2ERootResult {
	t.Helper()
	result, err := fixture.coordinator.Execute(context.Background(), fixture.target, fixture.assignments, domain.SeverityHigh, nil)
	if err != nil {
		t.Fatal(err)
	}
	inventory := fixture.runtime.DrainRuntimeArtifactsForRun(result.RunID())
	candidate, err := publication.PrepareCandidateWithRuntimeArtifacts(result, fixture.target, domain.SeverityHigh, "g008-test", "g008-test", publication.RunPublicationContext{}, inventory)
	if err != nil {
		t.Fatal(err)
	}
	published, err := fixture.publisher.Publish(context.Background(), fixture.root, candidate, 1)
	if err != nil {
		t.Fatal(err)
	}
	issued, ok := published.IssuedReviewID()
	if !ok {
		t.Fatal("root publication did not issue a review ID")
	}
	resolver, err := NewG008RequestResolver(fixture.root, fixture.queries, filesystem.NewRunSelector(fixture.root), strings.NewReader(""))
	if err != nil {
		t.Fatal(err)
	}
	sources, err := NewG008Sources(fixture.root, resolver, fixture.queries)
	if err != nil {
		t.Fatal(err)
	}
	return g008RealE2ERootResult{SessionID: result.SessionID(), RunID: result.RunID(), ReviewID: issued.ReviewID(), AttemptID: fixture.provider.Transcript()[0].AttemptID, SecurityAttemptID: fixture.provider.Transcript()[1].AttemptID, Queries: fixture.queries, Sources: sources, Transcript: fixture.provider.Transcript()}
}

type g008RealE2EInventoryEntry struct {
	Path, SHA256 string
	Bytes        int64
}

func (fixture *g008RealE2EFixture) inventorySnapshot(t *testing.T) []g008RealE2EInventoryEntry {
	t.Helper()
	var entries []g008RealE2EInventoryEntry
	err := filepath.WalkDir(fixture.root.String(), func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		bytes, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(bytes)
		relative, err := filepath.Rel(fixture.root.String(), path)
		if err != nil {
			return err
		}
		entries = append(entries, g008RealE2EInventoryEntry{Path: filepath.ToSlash(relative), SHA256: hex.EncodeToString(sum[:]), Bytes: int64(len(bytes))})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	return entries
}
