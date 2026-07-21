package review

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/irootkernel/kkachi-agent-review/internal/app/evidence"
	"github.com/irootkernel/kkachi-agent-review/internal/app/prompt"
	"github.com/irootkernel/kkachi-agent-review/internal/app/validation"
	"github.com/irootkernel/kkachi-agent-review/internal/domain"
	"github.com/irootkernel/kkachi-agent-review/internal/ports"
)

// RuntimePrompt is the trusted prompt and target material supplied for one job.
// Source implementations own template, objective, target-byte, and identity
// selection; provider output never participates in their construction.
// RuntimeArtifactInventory is the immutable source material retained for one
// provider invocation. It has no provider-output or publication authority.
type RuntimeArtifactInventory struct {
	runID                 domain.RunID
	attemptID             domain.AttemptID
	sequence              uint64
	purpose               domain.InvocationPurpose
	role                  domain.Role
	target                []byte
	targetIdentity        domain.TargetIdentity
	stdin                 []byte
	stdinSHA256           string
	templateID            string
	templateVersion       string
	templateSHA256        string
	sourceInvocationID    string
	executionInvocationID string
	scope                 string
	adapterProfile        string
	adapterParameters     map[string]string
	captures              []ports.CapturedAttemptArtifact
}

func (inventory RuntimeArtifactInventory) RunID() domain.RunID         { return inventory.runID }
func (inventory RuntimeArtifactInventory) AttemptID() domain.AttemptID { return inventory.attemptID }
func (inventory RuntimeArtifactInventory) Sequence() uint64            { return inventory.sequence }
func (inventory RuntimeArtifactInventory) Purpose() domain.InvocationPurpose {
	return inventory.purpose
}
func (inventory RuntimeArtifactInventory) Role() domain.Role { return inventory.role }
func (inventory RuntimeArtifactInventory) Target() []byte {
	return append([]byte(nil), inventory.target...)
}
func (inventory RuntimeArtifactInventory) TargetIdentity() domain.TargetIdentity {
	return inventory.targetIdentity
}
func (inventory RuntimeArtifactInventory) Stdin() []byte {
	return append([]byte(nil), inventory.stdin...)
}
func (inventory RuntimeArtifactInventory) StdinSHA256() string     { return inventory.stdinSHA256 }
func (inventory RuntimeArtifactInventory) TemplateID() string      { return inventory.templateID }
func (inventory RuntimeArtifactInventory) TemplateVersion() string { return inventory.templateVersion }
func (inventory RuntimeArtifactInventory) TemplateSHA256() string  { return inventory.templateSHA256 }
func (inventory RuntimeArtifactInventory) SourceInvocationID() string {
	return inventory.sourceInvocationID
}
func (inventory RuntimeArtifactInventory) ExecutionInvocationID() string {
	return inventory.executionInvocationID
}
func (inventory RuntimeArtifactInventory) Scope() string          { return inventory.scope }
func (inventory RuntimeArtifactInventory) AdapterProfile() string { return inventory.adapterProfile }
func (inventory RuntimeArtifactInventory) AdapterParameters() map[string]string {
	result := make(map[string]string, len(inventory.adapterParameters))
	for key, value := range inventory.adapterParameters {
		result[key] = value
	}
	return result
}
func (inventory RuntimeArtifactInventory) Captures() []ports.CapturedAttemptArtifact {
	return append([]ports.CapturedAttemptArtifact(nil), inventory.captures...)
}

// AdapterProfile and AdapterParameters identify the trusted execution adapter.
// They are source material, never provider output.
type RuntimePrompt struct {
	Prompt            prompt.CompiledPrompt
	Target            []byte
	AdapterProfile    string
	AdapterParameters map[string]string
}

// InvocationRepairInput is trusted state retained from a repair-eligible initial
// invocation. Its accessors return defensive copies.
type InvocationRepairInput struct {
	initial []byte
	plan    validation.RepairPlan
}

func (input InvocationRepairInput) InitialCandidate() []byte {
	return append([]byte(nil), input.initial...)
}
func (input InvocationRepairInput) Plan() validation.RepairPlan { return input.plan }

// InvocationPromptSource supplies trusted prompt material keyed by the immutable
// coordinator job. repair is nil for initial jobs and is present only for the
// one coordinator-authorized repair invocation of the same attempt.
type InvocationPromptSource interface {
	Prompt(context.Context, InvocationJob, *InvocationRepairInput) (RuntimePrompt, error)
}

// DeltaInvocationMaterial is the immutable A-to-B input for one delta
// invocation. Source and current bytes are independently bound to their
// identities; Delta is comparator-owned material and is never recomputed here.
type DeltaInvocationMaterial struct {
	SourceRunID           domain.RunID
	SourceTarget          []byte
	SourceTargetIdentity  domain.TargetIdentity
	CurrentTarget         []byte
	CurrentTargetIdentity domain.TargetIdentity
	Delta                 []byte
}

// DeltaInvocationPromptSource composes a canonical delta-aware prompt. It is
// intentionally separate from Prompt so delta execution cannot fall back to a
// current-target-only prompt.
type DeltaInvocationPromptSource interface {
	DeltaPrompt(context.Context, InvocationJob, DeltaInvocationMaterial, *InvocationRepairInput) (RuntimePrompt, error)
}

// ExactReplayInput is the stored provider-wire authority for one selected
// attempt. Only ExecutionInvocationID is minted afresh by the prompt source.
type ExactReplayInput struct {
	SourceRunID            domain.RunID
	SourceAttemptID        domain.AttemptID
	SourceProviderInstance string
	Stdin                  []byte
	CompleteStdinSHA256    string
	SourceInvocationID     string
	Role                   domain.Role
	AdapterProfile         string
	AdapterParameters      map[string]string
}

// ExactReplayPromptSource replays stored wire authority into a fresh execution
// identity. Implementations must preserve every ExactReplayInput field.
type ExactReplayPromptSource interface {
	ExactReplayPrompt(context.Context, InvocationJob, ExactReplayInput) (RuntimePrompt, error)
}

// AttemptCapture binds defensive captured provider streams to one coordinator
// attempt and invocation sequence. Artifacts with SecurityRejected set never
// expose their rejected bytes.
type AttemptCapture struct {
	attemptID domain.AttemptID
	sequence  uint64
	artifacts []ports.CapturedAttemptArtifact
}

func (capture AttemptCapture) AttemptID() domain.AttemptID { return capture.attemptID }
func (capture AttemptCapture) Sequence() uint64            { return capture.sequence }
func (capture AttemptCapture) Artifacts() []ports.CapturedAttemptArtifact {
	return append([]ports.CapturedAttemptArtifact(nil), capture.artifacts...)
}

// ProviderInvocationRuntime is the real bridge from coordinator jobs to prompt,
// provider, validation, repair, and evidence verification. It has no scheduler,
// transition, fallback, or publication authority.
type ProviderInvocationRuntime struct {
	provider          ports.ReviewProvider
	observed          ports.ObservedReviewProvider
	source            InvocationPromptSource
	validator         *validation.ReviewValidator
	verifier          *evidence.Verifier
	workspace         ports.WorkspaceExecutionAuthority
	workspaceIdentity ports.WorkspaceSnapshotIdentity
	hasWorkspace      bool
	policy            EvidencePolicy
	allowSourceScope  bool

	mu        sync.Mutex
	pending   map[domain.AttemptID]InvocationRepairInput
	captures  map[captureKey]AttemptCapture
	inventory map[captureKey]RuntimeArtifactInventory
}

type captureKey struct {
	attemptID domain.AttemptID
	sequence  uint64
}

// NewProviderInvocationRuntime constructs a coordinator InvocationRuntime using
// the existing authoritative review validator and evidence reducer.
func NewProviderInvocationRuntime(provider ports.ReviewProvider, source InvocationPromptSource, validator *validation.ReviewValidator, verifier *evidence.Verifier) (*ProviderInvocationRuntime, error) {
	if nilInterface(provider) {
		return nil, fmt.Errorf("provider invocation runtime: nil provider")
	}
	if nilInterface(source) {
		return nil, fmt.Errorf("provider invocation runtime: nil prompt source")
	}
	if validator == nil {
		return nil, fmt.Errorf("provider invocation runtime: nil review validator")
	}
	if verifier == nil {
		return nil, fmt.Errorf("provider invocation runtime: nil evidence verifier")
	}
	return &ProviderInvocationRuntime{provider: provider, source: source, validator: validator, verifier: verifier, policy: DefaultEvidencePolicy(), pending: make(map[domain.AttemptID]InvocationRepairInput), captures: make(map[captureKey]AttemptCapture), inventory: make(map[captureKey]RuntimeArtifactInventory)}, nil
}

// NewObservedProviderInvocationRuntime constructs a runtime directly from the
// observation boundary. It preserves process streams as artifacts while using
// only the provider result's isolated stdout as the validation candidate.
func NewObservedProviderInvocationRuntime(provider ports.ObservedReviewProvider, source InvocationPromptSource, validator *validation.ReviewValidator, verifier *evidence.Verifier) (*ProviderInvocationRuntime, error) {
	if nilInterface(provider) {
		return nil, fmt.Errorf("provider invocation runtime: nil observed provider")
	}
	if nilInterface(source) {
		return nil, fmt.Errorf("provider invocation runtime: nil prompt source")
	}
	if validator == nil {
		return nil, fmt.Errorf("provider invocation runtime: nil review validator")
	}
	if verifier == nil {
		return nil, fmt.Errorf("provider invocation runtime: nil evidence verifier")
	}
	return &ProviderInvocationRuntime{observed: provider, source: source, validator: validator, verifier: verifier, policy: DefaultEvidencePolicy(), pending: make(map[domain.AttemptID]InvocationRepairInput), captures: make(map[captureKey]AttemptCapture), inventory: make(map[captureKey]RuntimeArtifactInventory)}, nil
}

// NewObservedProviderInvocationRuntimeWithWorkspace constructs an observed
// runtime bound to one capture-owned workspace authority for every invocation.
func NewObservedProviderInvocationRuntimeWithWorkspace(provider ports.ObservedReviewProvider, source InvocationPromptSource, workspace ports.WorkspaceExecutionAuthority, validator *validation.ReviewValidator, verifier *evidence.Verifier) (*ProviderInvocationRuntime, error) {
	if nilInterface(workspace) {
		return nil, fmt.Errorf("provider invocation runtime: nil workspace authority")
	}
	identity := workspace.WorkspaceSnapshotIdentity()
	if !identity.Valid() {
		return nil, fmt.Errorf("provider invocation runtime: invalid workspace identity")
	}
	runtime, err := NewObservedProviderInvocationRuntime(provider, source, validator, verifier)
	if err != nil {
		return nil, err
	}
	runtime.workspace = workspace
	runtime.workspaceIdentity = identity
	runtime.hasWorkspace = true
	return runtime, nil
}

// Captures returns defensive captured artifacts in attempt then invocation order.
func (runtime *ProviderInvocationRuntime) Captures() []AttemptCapture {
	if runtime == nil {
		return nil
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	result := make([]AttemptCapture, 0, len(runtime.captures))
	for _, capture := range runtime.captures {
		result = append(result, cloneAttemptCapture(capture))
	}
	sort.Slice(result, func(left, right int) bool {
		if result[left].attemptID != result[right].attemptID {
			return result[left].attemptID.String() < result[right].attemptID.String()
		}
		return result[left].sequence < result[right].sequence
	})
	return result
}

// DrainCaptures returns all captured artifacts and removes them from this
// runtime. Callers that share a runtime across runs must drain receipts after
// durable publication.
func (runtime *ProviderInvocationRuntime) DrainCaptures() []AttemptCapture {
	if runtime == nil {
		return nil
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	result := make([]AttemptCapture, 0, len(runtime.captures))
	for key, capture := range runtime.captures {
		result = append(result, cloneAttemptCapture(capture))
		delete(runtime.captures, key)
	}
	sort.Slice(result, func(left, right int) bool {
		if result[left].attemptID != result[right].attemptID {
			return result[left].attemptID.String() < result[right].attemptID.String()
		}
		return result[left].sequence < result[right].sequence
	})
	return result
}

// Capture returns one defensive receipt by coordinator attempt and invocation sequence.
func (runtime *ProviderInvocationRuntime) Capture(attemptID domain.AttemptID, sequence uint64) (AttemptCapture, bool) {
	if runtime == nil || sequence == 0 {
		return AttemptCapture{}, false
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	capture, ok := runtime.captures[captureKey{attemptID: attemptID, sequence: sequence}]
	return cloneAttemptCapture(capture), ok
}

func cloneAttemptCapture(capture AttemptCapture) AttemptCapture {
	return AttemptCapture{attemptID: capture.attemptID, sequence: capture.sequence, artifacts: append([]ports.CapturedAttemptArtifact(nil), capture.artifacts...)}
}

// RuntimeArtifacts returns defensive source snapshots in attempt then invocation
// order. Provider output remains limited to the captured attempt streams.
func (runtime *ProviderInvocationRuntime) RuntimeArtifacts() []RuntimeArtifactInventory {
	if runtime == nil {
		return nil
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	return runtime.runtimeArtifacts(false)
}

// DrainRuntimeArtifacts returns source snapshots and removes them from this
// runtime. The snapshot is keyed by run, attempt, and invocation sequence.
func (runtime *ProviderInvocationRuntime) DrainRuntimeArtifacts() []RuntimeArtifactInventory {
	if runtime == nil {
		return nil
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	return runtime.runtimeArtifacts(true)
}

// DrainRuntimeArtifactsForRun returns and removes only source snapshots owned by
// runID. It is safe to use when one runtime serves concurrent child runs.
func (runtime *ProviderInvocationRuntime) DrainRuntimeArtifactsForRun(runID domain.RunID) []RuntimeArtifactInventory {
	if runtime == nil {
		return nil
	}
	if _, err := domain.ParseRunID(runID.String()); err != nil {
		return nil
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	result := make([]RuntimeArtifactInventory, 0)
	for key, inventory := range runtime.inventory {
		if inventory.runID != runID {
			continue
		}
		result = append(result, cloneRuntimeArtifactInventory(inventory))
		delete(runtime.inventory, key)
	}
	sort.Slice(result, func(left, right int) bool {
		if result[left].attemptID != result[right].attemptID {
			return result[left].attemptID.String() < result[right].attemptID.String()
		}
		return result[left].sequence < result[right].sequence
	})
	return result
}

func (runtime *ProviderInvocationRuntime) runtimeArtifacts(drain bool) []RuntimeArtifactInventory {
	result := make([]RuntimeArtifactInventory, 0, len(runtime.inventory))
	for key, inventory := range runtime.inventory {
		result = append(result, cloneRuntimeArtifactInventory(inventory))
		if drain {
			delete(runtime.inventory, key)
		}
	}
	sort.Slice(result, func(left, right int) bool {
		if result[left].runID != result[right].runID {
			return result[left].runID.String() < result[right].runID.String()
		}
		if result[left].attemptID != result[right].attemptID {
			return result[left].attemptID.String() < result[right].attemptID.String()
		}
		return result[left].sequence < result[right].sequence
	})
	return result
}

func cloneRuntimeArtifactInventory(inventory RuntimeArtifactInventory) RuntimeArtifactInventory {
	clone := inventory
	clone.target = append([]byte(nil), inventory.target...)
	clone.stdin = append([]byte(nil), inventory.stdin...)
	clone.adapterParameters = inventory.AdapterParameters()
	clone.captures = append([]ports.CapturedAttemptArtifact(nil), inventory.captures...)
	return clone
}

// Invoke executes exactly one coordinator-authorized invocation. A repair job is
// accepted only after this runtime retained a repair plan for its initial job.
func (runtime *ProviderInvocationRuntime) Invoke(ctx context.Context, job InvocationJob) AttemptOutcome {
	if runtime == nil || !job.Limits().Valid() {
		return runtimeCondition(job, AttemptConditionInternalInvariant)
	}
	if ctx == nil {
		return runtimeCondition(job, AttemptConditionConfigurationViolation)
	}
	invocationCtx, cancel := context.WithTimeout(ctx, job.Limits().Timeout())
	defer cancel()
	if err := invocationCtx.Err(); err != nil {
		return runtimeCondition(job, runtimeContextCondition(err))
	}

	var repair *InvocationRepairInput
	if job.Purpose() == domain.InvocationRepair {
		runtime.mu.Lock()
		input, ok := runtime.pending[job.AttemptID()]
		runtime.mu.Unlock()
		if !ok {
			return runtimeCondition(job, AttemptConditionInternalInvariant)
		}
		copy := InvocationRepairInput{initial: append([]byte(nil), input.initial...), plan: input.plan}
		repair = &copy
	}
	material, err := runtime.source.Prompt(invocationCtx, job, repair)
	if err != nil {
		return runtimeCondition(job, runtimeErrorCondition(invocationCtx, err))
	}
	if err := material.Prompt.Validate(); err != nil ||
		!runtime.promptMatchesJob(material.Prompt, job) ||
		sha256Identifier(material.Target) != "sha256:"+job.Target().SHA256() {
		return runtimeCondition(job, AttemptConditionConfigurationViolation)
	}
	if err := runtime.recordRuntimeArtifact(job, material); err != nil {
		return runtimeCondition(job, AttemptConditionConfigurationViolation)
	}
	providerInvocation, err := runtime.providerInvocation(job, material)
	if err != nil {
		return runtimeCondition(job, runtimeProviderErrorCondition(invocationCtx, err))
	}
	var stdout, rawStdout, stderr []byte
	if runtime.observed != nil {
		observation, observeErr := runtime.observed.Observe(invocationCtx, providerInvocation)
		if observeErr != nil {
			return runtimeCondition(job, runtimeProviderErrorCondition(invocationCtx, observeErr))
		}
		if err := observation.Validate(); err != nil || !sameProviderInvocation(observation.Invocation(), providerInvocation) {
			return runtimeCondition(job, AttemptConditionSecurityViolation)
		}
		rawStdout, stderr = observation.Stdout(), observation.Stderr()
		if !observation.Succeeded() {
			if err := runtime.capture(job, nil, rawStdout, stderr, false); err != nil {
				return runtimeCondition(job, AttemptConditionArtifactFailure)
			}
			return runtimeCondition(job, observedStatusCondition(observation.Status()))
		}
		result, ok := observation.Result()
		if !ok || result.StdinByteLength() != len(material.Prompt.Stdin()) || result.CompleteStdinSHA256() != material.Prompt.CompleteStdinSHA256() {
			return runtimeCondition(job, AttemptConditionSecurityViolation)
		}
		stdout = result.Stdout()
		if int64(len(stdout)) > job.Limits().MaxStdoutBytes() {
			if err := runtime.capture(job, nil, rawStdout, stderr, true); err != nil {
				return runtimeCondition(job, AttemptConditionArtifactFailure)
			}
			return runtimeCondition(job, AttemptConditionArtifactFailure)
		}
	} else {
		result, invokeErr := runtime.provider.Invoke(invocationCtx, providerInvocation)
		if invokeErr != nil {
			return runtimeCondition(job, runtimeProviderErrorCondition(invocationCtx, invokeErr))
		}
		stdout = result.Stdout()
		rawStdout = stdout
		if int64(len(stdout)) > job.Limits().MaxStdoutBytes() {
			if err := runtime.capture(job, nil, stdout, nil, true); err != nil {
				return runtimeCondition(job, AttemptConditionArtifactFailure)
			}
			return runtimeCondition(job, AttemptConditionArtifactFailure)
		}
		if result.StdinByteLength() != len(material.Prompt.Stdin()) || result.CompleteStdinSHA256() != material.Prompt.CompleteStdinSHA256() {
			return runtimeCondition(job, AttemptConditionSecurityViolation)
		}
	}

	scope := validation.ReviewValidationScope{TargetSHA256: job.Target().SHA256(), Role: job.Role(), ProviderInstance: job.Route().ProviderInstance()}
	if job.Purpose() == domain.InvocationInitial {
		validated, plan, validationErr := runtime.validator.Validate(invocationCtx, stdout, scope)
		if validationErr != nil {
			securityRejected := isSecurityOutputError(validationErr)
			if err := runtime.capture(job, stdout, rawStdout, stderr, securityRejected); err != nil {
				return runtimeCondition(job, AttemptConditionArtifactFailure)
			}
			if securityRejected {
				return runtimeCondition(job, AttemptConditionSecurityViolation)
			}
			if plan != nil {
				runtime.mu.Lock()
				runtime.pending[job.AttemptID()] = InvocationRepairInput{initial: append([]byte(nil), stdout...), plan: *plan}
				runtime.mu.Unlock()
			}
			return runtimeCondition(job, AttemptConditionInvalidProviderOutput)
		}
		if plan != nil {
			return runtimeCondition(job, AttemptConditionInternalInvariant)
		}
		if err := runtime.capture(job, stdout, rawStdout, stderr, false); err != nil {
			return runtimeCondition(job, AttemptConditionArtifactFailure)
		}
		return runtime.accept(invocationCtx, job, validated)
	}
	validated, repairedCandidate, validationErr := runtime.validator.ApplyRepairCandidate(invocationCtx, repair.initial, stdout, scope, repair.plan)
	securityRejected := validationErr != nil && isSecurityOutputError(validationErr)
	if validationErr != nil {
		if err := runtime.capture(job, nil, rawStdout, stderr, securityRejected); err != nil {
			return runtimeCondition(job, AttemptConditionArtifactFailure)
		}
	} else if err := runtime.capture(job, repairedCandidate, rawStdout, stderr, false); err != nil {
		return runtimeCondition(job, AttemptConditionArtifactFailure)
	}
	runtime.mu.Lock()
	delete(runtime.pending, job.AttemptID())
	runtime.mu.Unlock()
	if validationErr != nil {
		if securityRejected {
			return runtimeCondition(job, AttemptConditionSecurityViolation)
		}
		return runtimeCondition(job, runtimeErrorCondition(invocationCtx, validationErr))
	}
	return runtime.accept(invocationCtx, job, validated)
}

// InvokeDelta executes a delta-aware invocation through the explicit delta
// prompt source. Initial and its one coordinator-authorized repair both retain
// the same immutable A-to-B material; no ordinary prompt fallback is available.
func (runtime *ProviderInvocationRuntime) InvokeDelta(ctx context.Context, job InvocationJob, input DeltaInvocationMaterial) AttemptOutcome {
	if runtime == nil ||
		(job.Purpose() != domain.InvocationInitial && job.Purpose() != domain.InvocationRepair) ||
		input.SourceRunID.String() == "" ||
		sha256Identifier(input.SourceTarget) != "sha256:"+input.SourceTargetIdentity.SHA256() ||
		sha256Identifier(input.CurrentTarget) != "sha256:"+input.CurrentTargetIdentity.SHA256() ||
		input.CurrentTargetIdentity != job.Target() {
		return runtimeCondition(job, AttemptConditionConfigurationViolation)
	}
	source, ok := runtime.source.(DeltaInvocationPromptSource)
	if !ok {
		return runtimeCondition(job, AttemptConditionConfigurationViolation)
	}
	var repair *InvocationRepairInput
	if job.Purpose() == domain.InvocationRepair {
		runtime.mu.Lock()
		input, exists := runtime.pending[job.AttemptID()]
		runtime.mu.Unlock()
		if !exists {
			return runtimeCondition(job, AttemptConditionInternalInvariant)
		}
		copy := InvocationRepairInput{initial: append([]byte(nil), input.initial...), plan: input.plan}
		repair = &copy
	}
	material, err := source.DeltaPrompt(ctx, job, cloneDeltaInvocationMaterial(input), repair)
	if err != nil {
		return runtimeCondition(job, runtimeErrorCondition(ctx, err))
	}
	return runtime.invokeExplicitMaterial(ctx, job, material, false)
}

// InvokeExactReplay executes exactly one stored provider wire invocation using
// a fresh execution identity supplied by the explicit replay prompt source.
func (runtime *ProviderInvocationRuntime) InvokeExactReplay(ctx context.Context, job InvocationJob, input ExactReplayInput) AttemptOutcome {
	if runtime == nil || job.Purpose() != domain.InvocationInitial || input.Role != job.Role() ||
		input.SourceRunID.String() == "" || input.SourceAttemptID.String() == "" ||
		!validCoordinatorProviderInstance(input.SourceProviderInstance) ||
		input.SourceProviderInstance != job.Route().ProviderInstance() ||
		input.CompleteStdinSHA256 == "" || prompt.CompleteStdinSHA256(input.Stdin) != input.CompleteStdinSHA256 ||
		input.SourceInvocationID == "" {
		return runtimeCondition(job, AttemptConditionConfigurationViolation)
	}
	source, ok := runtime.source.(ExactReplayPromptSource)
	if !ok {
		return runtimeCondition(job, AttemptConditionConfigurationViolation)
	}
	material, err := source.ExactReplayPrompt(ctx, job, cloneExactReplayInput(input))
	if err != nil {
		return runtimeCondition(job, runtimeErrorCondition(ctx, err))
	}
	scope := material.Prompt.Scope()
	if material.Prompt.CompleteStdinSHA256() != input.CompleteStdinSHA256 ||
		string(material.Prompt.Stdin()) != string(input.Stdin) ||
		scope.SessionID() != job.SessionID() ||
		scope.RunID() != input.SourceRunID ||
		scope.AttemptID() != input.SourceAttemptID ||
		scope.SourceInvocationID().String() != input.SourceInvocationID ||
		material.AdapterProfile != input.AdapterProfile ||
		!sameAdapterParameters(material.AdapterParameters, input.AdapterParameters) {
		return runtimeCondition(job, AttemptConditionConfigurationViolation)
	}
	return runtime.invokeExplicitMaterial(ctx, job, material, true)
}

func (runtime *ProviderInvocationRuntime) invokeExplicitMaterial(ctx context.Context, job InvocationJob, material RuntimePrompt, allowSourceScope bool) AttemptOutcome {
	if ctx == nil {
		return runtimeCondition(job, AttemptConditionConfigurationViolation)
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	_, inventoryExists := runtime.inventory[captureKey{job.AttemptID(), invocationSequence(job.Purpose())}]
	if inventoryExists {
		return runtimeCondition(job, AttemptConditionConfigurationViolation)
	}
	clonePending := make(map[domain.AttemptID]InvocationRepairInput)
	if pending, ok := runtime.pending[job.AttemptID()]; ok {
		clonePending[job.AttemptID()] = InvocationRepairInput{
			initial: append([]byte(nil), pending.initial...),
			plan:    pending.plan,
		}
	}
	clone := &ProviderInvocationRuntime{
		provider: runtime.provider, observed: runtime.observed, source: explicitRuntimePromptSource{material: material},
		validator: runtime.validator, verifier: runtime.verifier, workspace: runtime.workspace,
		workspaceIdentity: runtime.workspaceIdentity, hasWorkspace: runtime.hasWorkspace, policy: runtime.policy,
		allowSourceScope: allowSourceScope,
		pending:          clonePending, captures: make(map[captureKey]AttemptCapture),
		inventory: make(map[captureKey]RuntimeArtifactInventory),
	}
	outcome := clone.Invoke(ctx, job)
	clone.mu.Lock()
	captures := clone.captures
	inventory := clone.inventory
	pending, pendingExists := clone.pending[job.AttemptID()]
	clone.mu.Unlock()
	for key := range inventory {
		if _, exists := runtime.inventory[key]; exists {
			return runtimeCondition(job, AttemptConditionInternalInvariant)
		}
	}
	for key, value := range captures {
		runtime.captures[key] = cloneAttemptCapture(value)
	}
	for key, value := range inventory {
		runtime.inventory[key] = cloneRuntimeArtifactInventory(value)
	}
	if pendingExists {
		runtime.pending[job.AttemptID()] = InvocationRepairInput{
			initial: append([]byte(nil), pending.initial...),
			plan:    pending.plan,
		}
	} else {
		delete(runtime.pending, job.AttemptID())
	}
	return outcome
}

type explicitRuntimePromptSource struct {
	material RuntimePrompt
}

func (source explicitRuntimePromptSource) Prompt(_ context.Context, _ InvocationJob, _ *InvocationRepairInput) (RuntimePrompt, error) {
	return RuntimePrompt{
		Prompt: source.material.Prompt, Target: append([]byte(nil), source.material.Target...),
		AdapterProfile: source.material.AdapterProfile, AdapterParameters: cloneAdapterParameters(source.material.AdapterParameters),
	}, nil
}

func cloneDeltaInvocationMaterial(input DeltaInvocationMaterial) DeltaInvocationMaterial {
	input.SourceTarget = append([]byte(nil), input.SourceTarget...)
	input.CurrentTarget = append([]byte(nil), input.CurrentTarget...)
	input.Delta = append([]byte(nil), input.Delta...)
	return input
}

func cloneExactReplayInput(input ExactReplayInput) ExactReplayInput {
	input.Stdin = append([]byte(nil), input.Stdin...)
	input.AdapterParameters = cloneAdapterParameters(input.AdapterParameters)
	return input
}

func cloneAdapterParameters(parameters map[string]string) map[string]string {
	result := make(map[string]string, len(parameters))
	for key, value := range parameters {
		result[key] = value
	}
	return result
}

func sameAdapterParameters(left, right map[string]string) bool {
	if len(left) != len(right) {
		return false
	}
	for key, value := range left {
		if right[key] != value {
			return false
		}
	}
	return true
}
func (runtime *ProviderInvocationRuntime) accept(ctx context.Context, job InvocationJob, validated validation.ValidatedReview) AttemptOutcome {
	verified, err := VerifyValidatedEvidence(ctx, runtime.verifier, validated.EvidenceClaims())
	if err != nil {
		return runtimeCondition(job, runtimeErrorCondition(ctx, err))
	}
	if _, err = ReduceVerifiedFindingEvidence(validated.Findings(), verified, runtime.policy); err != nil {
		return runtimeCondition(job, AttemptConditionInvalidEvidenceClaim)
	}
	output, err := NewEvidenceValidatedRoleOutput(job.Role(), job.Route().ProviderInstance(), job.Target(), validated.Findings(), validated.Completeness(), validated.Limitations(), verified)
	if err != nil {
		return runtimeCondition(job, AttemptConditionInvalidEvidenceClaim)
	}
	outcome, err := NewAttemptOutcome(job, &output, nil)
	if err != nil {
		return runtimeCondition(job, AttemptConditionInternalInvariant)
	}
	return outcome
}

func (runtime *ProviderInvocationRuntime) capture(job InvocationJob, candidate, stdout, stderr []byte, reject bool) error {
	artifacts := make([]ports.CapturedAttemptArtifact, 0, 3)
	add := func(kind ports.AttemptArtifactKind, content []byte, securityRejected bool) error {
		if len(content) == 0 && !securityRejected {
			return nil
		}
		if securityRejected {
			content = nil
		}
		artifact, err := ports.NewCapturedAttemptArtifact(kind, content, securityRejected)
		if err != nil {
			return fmt.Errorf("provider invocation runtime: capture %s: %w", kind, err)
		}
		artifacts = append(artifacts, artifact)
		return nil
	}
	if job.Purpose() == domain.InvocationRepair {
		if len(candidate) > 0 {
			if err := add(ports.AttemptArtifactRepairedCandidate, candidate, reject); err != nil {
				return err
			}
		}
	} else if err := add(ports.AttemptArtifactInitialCandidate, candidate, reject); err != nil {
		return err
	}
	if err := add(ports.AttemptArtifactStdout, stdout, reject); err != nil {
		return err
	}
	if err := add(ports.AttemptArtifactStderr, stderr, reject); err != nil {
		return err
	}
	runtime.mu.Lock()
	key := captureKey{job.AttemptID(), invocationSequence(job.Purpose())}
	runtime.captures[key] = AttemptCapture{attemptID: job.AttemptID(), sequence: invocationSequence(job.Purpose()), artifacts: artifacts}
	if inventory, ok := runtime.inventory[key]; ok {
		inventory.captures = append([]ports.CapturedAttemptArtifact(nil), artifacts...)
		runtime.inventory[key] = inventory
	}
	runtime.mu.Unlock()
	return nil
}
func (runtime *ProviderInvocationRuntime) promptMatchesJob(compiled prompt.CompiledPrompt, job InvocationJob) bool {
	scope := compiled.Scope()
	if scope.SessionID() != job.SessionID() {
		return false
	}
	return runtime.allowSourceScope ||
		(scope.RunID() == job.RunID() && scope.AttemptID() == job.AttemptID())
}
func (runtime *ProviderInvocationRuntime) recordRuntimeArtifact(job InvocationJob, material RuntimePrompt) error {
	scope := material.Prompt.Scope()
	if scope.RunID().String() == "" ||
		(!runtime.allowSourceScope && scope.AttemptID() != job.AttemptID()) ||
		material.Prompt.CompleteStdinSHA256() == "" {
		return fmt.Errorf("invalid runtime artifact scope")
	}
	template := material.Prompt.TrustedTemplate()
	inventory := RuntimeArtifactInventory{
		runID: job.RunID(), attemptID: job.AttemptID(), sequence: invocationSequence(job.Purpose()),
		purpose: job.Purpose(), role: job.Role(), target: append([]byte(nil), material.Target...),
		targetIdentity: job.Target(), stdin: material.Prompt.Stdin(),
		stdinSHA256: material.Prompt.CompleteStdinSHA256(), templateID: template.ID(),
		templateVersion: template.Version(), templateSHA256: template.SHA256(),
		sourceInvocationID:    scope.SourceInvocationID().String(),
		executionInvocationID: scope.ExecutionInvocationID().String(), scope: scope.FrameScope().String(),
		adapterProfile: material.AdapterProfile, adapterParameters: make(map[string]string, len(material.AdapterParameters)),
	}
	for key, value := range material.AdapterParameters {
		inventory.adapterParameters[key] = value
	}
	runtime.mu.Lock()
	runtime.inventory[captureKey{job.AttemptID(), invocationSequence(job.Purpose())}] = inventory
	runtime.mu.Unlock()
	return nil
}

func (runtime *ProviderInvocationRuntime) providerInvocation(job InvocationJob, material RuntimePrompt) (ports.ProviderInvocation, error) {
	packet, err := ports.NewProviderPacket(material.Prompt.Stdin(), material.Prompt.CompleteStdinSHA256())
	if err != nil {
		return ports.ProviderInvocation{}, err
	}
	if runtime.hasWorkspace {
		if !sameWorkspaceSnapshotIdentity(runtime.workspace.WorkspaceSnapshotIdentity(), runtime.workspaceIdentity) {
			return ports.ProviderInvocation{}, fmt.Errorf("%w: workspace identity changed", ports.ErrWorkspaceSnapshotDrift)
		}
		return ports.NewProviderInvocationWithPacketInWorkspace(
			job.Role(), job.Route().ProviderInstance(), job.AttemptID(), runtimePurpose(job.Purpose()), packet,
			material.Prompt.Scope().SourceInvocationID().String(), material.Prompt.Scope().ExecutionInvocationID().String(),
			runtime.workspace,
		)
	}
	return ports.NewProviderInvocationWithPacket(
		job.Role(), job.Route().ProviderInstance(), job.AttemptID(), runtimePurpose(job.Purpose()), packet,
		material.Prompt.Scope().SourceInvocationID().String(), material.Prompt.Scope().ExecutionInvocationID().String(),
	)
}

func runtimePurpose(purpose domain.InvocationPurpose) ports.ProviderInvocationPurpose {
	if purpose == domain.InvocationRepair {
		return ports.ProviderInvocationRepair
	}
	return ports.ProviderInvocationInitial
}
func runtimeCondition(job InvocationJob, condition AttemptCondition) AttemptOutcome {
	outcome, err := NewAttemptOutcome(job, nil, &condition)
	if err != nil {
		return AttemptOutcome{}
	}
	return outcome
}
func runtimeContextCondition(err error) AttemptCondition {
	if errors.Is(err, context.DeadlineExceeded) {
		return AttemptConditionTimeout
	}
	return AttemptConditionCancelled
}
func runtimeErrorCondition(ctx context.Context, err error) AttemptCondition {
	if ctx != nil && ctx.Err() != nil {
		return runtimeContextCondition(ctx.Err())
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return AttemptConditionTimeout
	}
	if errors.Is(err, context.Canceled) {
		return AttemptConditionCancelled
	}
	return AttemptConditionInvalidProviderOutput
}
func isSecurityOutputError(err error) bool {
	message := err.Error()
	return strings.Contains(message, "system-owned") ||
		strings.Contains(message, "provider supplied") ||
		strings.Contains(message, "forbidden")
}
func sha256Identifier(bytes []byte) string {
	sum := sha256.Sum256(bytes)
	return fmt.Sprintf("sha256:%x", sum)
}
func runtimeProviderErrorCondition(ctx context.Context, err error) AttemptCondition {
	if ctx != nil && ctx.Err() != nil {
		return runtimeContextCondition(ctx.Err())
	}
	if errors.Is(err, ports.ErrWorkspaceSnapshotDrift) {
		return AttemptConditionSecurityViolation
	}
	message := err.Error()
	switch {
	case strings.Contains(message, "unavailable"):
		return AttemptConditionProviderUnavailable
	case strings.Contains(message, "auth"):
		return AttemptConditionAuthentication
	case strings.Contains(message, "quota"):
		return AttemptConditionQuota
	case strings.Contains(message, "rate"):
		return AttemptConditionRateLimit
	default:
		return AttemptConditionInternalInvariant
	}
}
func sameProviderInvocation(left, right ports.ProviderInvocation) bool {
	if left.Role() != right.Role() ||
		left.ProviderInstance() != right.ProviderInstance() ||
		left.AttemptID() != right.AttemptID() ||
		left.Purpose() != right.Purpose() ||
		left.SourceInvocationID() != right.SourceInvocationID() ||
		left.ExecutionInvocationID() != right.ExecutionInvocationID() ||
		left.CompleteStdinSHA256() != right.CompleteStdinSHA256() ||
		string(left.Stdin()) != string(right.Stdin()) {
		return false
	}
	leftIdentity, leftHasWorkspace := left.WorkspaceSnapshotIdentity()
	rightIdentity, rightHasWorkspace := right.WorkspaceSnapshotIdentity()
	return leftHasWorkspace == rightHasWorkspace &&
		(!leftHasWorkspace || sameWorkspaceSnapshotIdentity(leftIdentity, rightIdentity))
}

func sameWorkspaceSnapshotIdentity(left, right ports.WorkspaceSnapshotIdentity) bool {
	leftRootDevice, leftRootInode := left.RootIdentity()
	rightRootDevice, rightRootInode := right.RootIdentity()
	leftSnapshotDevice, leftSnapshotInode := left.SnapshotFSIdentity()
	rightSnapshotDevice, rightSnapshotInode := right.SnapshotFSIdentity()
	return left.SnapshotName() == right.SnapshotName() &&
		left.ManifestSHA256() == right.ManifestSHA256() &&
		left.PolicyIdentity() == right.PolicyIdentity() &&
		leftRootDevice == rightRootDevice &&
		leftRootInode == rightRootInode &&
		leftSnapshotDevice == rightSnapshotDevice &&
		leftSnapshotInode == rightSnapshotInode
}

func observedStatusCondition(status ports.ProviderExecutionStatus) AttemptCondition {
	switch status {
	case ports.ProviderExecutionStatusUnavailable:
		return AttemptConditionProviderUnavailable
	case ports.ProviderExecutionStatusTimedOut:
		return AttemptConditionTimeout
	case ports.ProviderExecutionStatusAuthentication:
		return AttemptConditionAuthentication
	case ports.ProviderExecutionStatusQuota:
		return AttemptConditionQuota
	case ports.ProviderExecutionStatusRateLimit:
		return AttemptConditionRateLimit
	case ports.ProviderExecutionStatusSecurityViolation:
		return AttemptConditionSecurityViolation
	case ports.ProviderExecutionStatusMutationViolation:
		return AttemptConditionMutationViolation
	case ports.ProviderExecutionStatusConfigurationViolation:
		return AttemptConditionConfigurationViolation
	case ports.ProviderExecutionStatusArtifactFailure:
		return AttemptConditionArtifactFailure
	case ports.ProviderExecutionStatusCancelled:
		return AttemptConditionCancelled
	default:
		return AttemptConditionInternalInvariant
	}
}
