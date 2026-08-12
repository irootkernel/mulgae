package review

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/irootkernel/mulgae/internal/app/evidence"
	"github.com/irootkernel/mulgae/internal/app/prompt"
	"github.com/irootkernel/mulgae/internal/app/validation"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

// RuntimePrompt is the trusted prompt and target material supplied for one job.
// Source implementations own template, objective, target-byte, and identity
// selection; provider output never participates in their construction.
// RuntimeArtifactInventory is the immutable source material retained for one
// provider invocation. It has no provider-output or publication authority.
type RuntimeArtifactInventory struct {
	runID                  domain.RunID
	attemptID              domain.AttemptID
	sequence               uint64
	purpose                domain.InvocationPurpose
	role                   domain.Role
	target                 []byte
	capturedArchive        []byte
	targetIdentity         domain.TargetIdentity
	stdin                  []byte
	stdinSHA256            string
	templateID             string
	templateVersion        string
	templateSHA256         string
	sourceInvocationID     string
	executionInvocationID  string
	scope                  string
	adapterProfile         string
	adapterParameters      map[string]string
	captures               []ports.CapturedAttemptArtifact
	stdoutDiagnostic       ports.RuntimeDiagnosticRawResult
	stderrDiagnostic       ports.RuntimeDiagnosticRawResult
	hasStdoutDiagnostic    bool
	hasStderrDiagnostic    bool
	diagnosticLastSequence uint64
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
func (inventory RuntimeArtifactInventory) CapturedArchive() []byte {
	return append([]byte(nil), inventory.capturedArchive...)
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
func (inventory RuntimeArtifactInventory) DiagnosticStdout() (ports.RuntimeDiagnosticRawResult, bool) {
	return inventory.stdoutDiagnostic, inventory.hasStdoutDiagnostic
}
func (inventory RuntimeArtifactInventory) DiagnosticStderr() (ports.RuntimeDiagnosticRawResult, bool) {
	return inventory.stderrDiagnostic, inventory.hasStderrDiagnostic
}

// AdapterProfile and AdapterParameters identify the trusted execution adapter.
// They are source material, never provider output.
type RuntimePrompt struct {
	Prompt            prompt.CompiledPrompt
	Target            []byte
	CapturedArchive   []byte
	AdapterProfile    string
	AdapterParameters map[string]string
}

// InvocationRepairInput is trusted state retained from a repair-eligible initial
// invocation. Its accessors return defensive copies.
type InvocationRepairInput struct {
	initial         []byte
	primaryReport   []byte
	plan            validation.RepairPlan
	parseState      domain.ParseState
	validationState domain.ValidationState
}

func (input InvocationRepairInput) InitialCandidate() []byte {
	return append([]byte(nil), input.initial...)
}

// PrimaryReport returns the original full assistant content retained as the
// Mulgae-owned role report body across structured repair.
func (input InvocationRepairInput) PrimaryReport() []byte {
	return append([]byte(nil), input.primaryReport...)
}

func (input InvocationRepairInput) Plan() validation.RepairPlan { return input.plan }

func cloneInvocationRepairInput(input InvocationRepairInput) InvocationRepairInput {
	return InvocationRepairInput{
		initial:         append([]byte(nil), input.initial...),
		primaryReport:   append([]byte(nil), input.primaryReport...),
		plan:            input.plan,
		parseState:      input.parseState,
		validationState: input.validationState,
	}
}

// InvocationPromptSource supplies trusted prompt material keyed by the immutable
// coordinator job. repair is nil for initial jobs and is present only for the
// one coordinator-authorized repair invocation of the same attempt.
type InvocationPromptSource interface {
	Prompt(context.Context, InvocationJob, *InvocationRepairInput) (RuntimePrompt, error)
}

// RuntimeDiagnosticSinkResolver supplies an already-opened run sink. The
// provider runtime may persist per-invocation raw streams but never opens or
// finalizes the sink; reviewrun owns that lifecycle in D-E03.
type RuntimeDiagnosticSinkResolver interface {
	RuntimeDiagnosticSink(domain.RunID) (ports.RuntimeDiagnosticSink, bool)
}

// BindRuntimeDiagnostics installs the child-run sink resolver before the
// runtime executes its first invocation. It is intentionally one-shot.
func (runtime *ProviderInvocationRuntime) BindRuntimeDiagnostics(resolver RuntimeDiagnosticSinkResolver) error {
	if runtime == nil || nilInterface(resolver) {
		return fmt.Errorf("provider invocation runtime: invalid diagnostic resolver")
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if !nilInterface(runtime.diagnostics) || len(runtime.inventory) != 0 || len(runtime.captures) != 0 {
		return fmt.Errorf("provider invocation runtime: diagnostics must be bound before execution")
	}
	runtime.diagnostics = resolver
	return nil
}

// BindProviderOutputStaging installs the adapter-owned staging locator before
// the runtime executes its first invocation. It is intentionally one-shot: the
// destination of every launch must be resolved by exactly one authority.
func (runtime *ProviderInvocationRuntime) BindProviderOutputStaging(locator ports.ProviderOutputStagingLocator) error {
	if runtime == nil || nilInterface(locator) {
		return fmt.Errorf("provider invocation runtime: invalid provider output staging locator")
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if !nilInterface(runtime.staging) || len(runtime.inventory) != 0 || len(runtime.captures) != 0 {
		return fmt.Errorf("provider invocation runtime: staging locator must be bound before execution")
	}
	runtime.staging = locator
	return nil
}

// ResolveStagedOutputDestination returns the Mulgae-owned staged destination for
// exactly one provider launch. It is the single resolution used by both the
// prompt authority that states the path to the provider and the runtime that
// binds the same path to the invocation, so the two can never disagree. A nil
// locator, an unknown instance, or a declared stdout transport all keep the
// launch on stdout.
func ResolveStagedOutputDestination(
	locator ports.ProviderOutputStagingLocator,
	job InvocationJob,
) (ports.StagedOutputDestination, bool) {
	if nilInterface(locator) {
		return ports.StagedOutputDestination{}, false
	}
	destination, transport, ok := locator.ProviderOutputStagingDestination(
		job.Route().ProviderInstance(), job.AttemptID(), runtimePurpose(job.Purpose()),
	)
	if !ok || transport != ports.ProviderOutputTransportStagedFile || !destination.Valid() {
		return ports.StagedOutputDestination{}, false
	}
	return destination, true
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
	SourceRunID                 domain.RunID
	SourceAttemptID             domain.AttemptID
	SourceProviderInstance      string
	Stdin                       []byte
	CompleteStdinSHA256         string
	SourceInvocationID          string
	SourceExecutionInvocationID string
	TemplateID                  string
	TemplateVersion             string
	TemplateSHA256              string
	Role                        domain.Role
	AdapterProfile              string
	AdapterParameters           map[string]string
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
// transition or publication authority.
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
	diagnostics       RuntimeDiagnosticSinkResolver
	staging           ports.ProviderOutputStagingLocator

	mu             sync.Mutex
	pending        map[domain.AttemptID]InvocationRepairInput
	captures       map[captureKey]AttemptCapture
	inventory      map[captureKey]RuntimeArtifactInventory
	activeExplicit map[captureKey]struct{}
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
	return &ProviderInvocationRuntime{provider: provider, source: source, validator: validator, verifier: verifier, policy: DefaultEvidencePolicy(), pending: make(map[domain.AttemptID]InvocationRepairInput), captures: make(map[captureKey]AttemptCapture), inventory: make(map[captureKey]RuntimeArtifactInventory), activeExplicit: make(map[captureKey]struct{})}, nil
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
	return &ProviderInvocationRuntime{observed: provider, source: source, validator: validator, verifier: verifier, policy: DefaultEvidencePolicy(), pending: make(map[domain.AttemptID]InvocationRepairInput), captures: make(map[captureKey]AttemptCapture), inventory: make(map[captureKey]RuntimeArtifactInventory), activeExplicit: make(map[captureKey]struct{})}, nil
}

// NewObservedProviderInvocationRuntimeWithDiagnostics constructs an observed
// runtime that may persist separated raw streams through an already-open sink.
func NewObservedProviderInvocationRuntimeWithDiagnostics(
	provider ports.ObservedReviewProvider,
	source InvocationPromptSource,
	validator *validation.ReviewValidator,
	verifier *evidence.Verifier,
	diagnostics RuntimeDiagnosticSinkResolver,
) (*ProviderInvocationRuntime, error) {
	if nilInterface(diagnostics) {
		return nil, fmt.Errorf("provider invocation runtime: nil diagnostic sink resolver")
	}
	runtime, err := NewObservedProviderInvocationRuntime(provider, source, validator, verifier)
	if err != nil {
		return nil, err
	}
	runtime.diagnostics = diagnostics
	return runtime, nil
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

// NewObservedProviderInvocationRuntimeWithWorkspaceAndDiagnostics combines a
// capture-owned workspace with an already-opened per-run diagnostic sink.
func NewObservedProviderInvocationRuntimeWithWorkspaceAndDiagnostics(
	provider ports.ObservedReviewProvider,
	source InvocationPromptSource,
	workspace ports.WorkspaceExecutionAuthority,
	validator *validation.ReviewValidator,
	verifier *evidence.Verifier,
	diagnostics RuntimeDiagnosticSinkResolver,
) (*ProviderInvocationRuntime, error) {
	if nilInterface(diagnostics) {
		return nil, fmt.Errorf("provider invocation runtime: nil diagnostic sink resolver")
	}
	runtime, err := NewObservedProviderInvocationRuntimeWithWorkspace(provider, source, workspace, validator, verifier)
	if err != nil {
		return nil, err
	}
	runtime.diagnostics = diagnostics
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
	clone.capturedArchive = append([]byte(nil), inventory.capturedArchive...)
	clone.stdin = append([]byte(nil), inventory.stdin...)
	clone.adapterParameters = inventory.AdapterParameters()
	clone.captures = append([]ports.CapturedAttemptArtifact(nil), inventory.captures...)
	return clone
}

// Invoke executes exactly one coordinator-authorized invocation. A repair job is
// accepted only after this runtime retained a repair plan for its initial job.
func (runtime *ProviderInvocationRuntime) Invoke(ctx context.Context, job InvocationJob) (outcome AttemptOutcome) {
	var diagnosticObservation *ports.ProviderExecutionObservation
	parseState, validationState := domain.ParseNotStarted, domain.ValidationNotStarted
	runtimeArtifactsExpected := false
	defer func() {
		outcome.runtimeArtifactsExpected = runtimeArtifactsExpected
	}()
	defer func() {
		if diagnosticObservation == nil {
			return
		}
		if err := runtime.replaceInvocationDiagnosticStatus(ctx, job, *diagnosticObservation, parseState, validationState); err != nil {
			outcome = runtimeCondition(job, diagnosticConditionForPersistence(err))
		}
	}()
	if runtime == nil || !job.Limits().Valid() {
		return runtimeCondition(job, AttemptConditionInternalInvariant)
	}
	if ctx == nil {
		return runtimeCondition(job, AttemptConditionConfigurationViolation)
	}
	// Prompt construction and local validation are bounded by the enclosing run
	// budget, but do not consume the configured provider process window. The
	// exact provider timeout starts immediately before Observe/Invoke below.
	invocationCtx := ctx
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
		copy := cloneInvocationRepairInput(input)
		repair = &copy
	}
	material, err := runtime.source.Prompt(invocationCtx, job, repair)
	if err != nil {
		return runtimeCondition(job, runtimePromptErrorCondition(invocationCtx, err))
	}
	if err := material.Prompt.Validate(); err != nil ||
		!runtime.promptMatchesJob(material.Prompt, job) ||
		sha256Identifier(material.Target) != "sha256:"+job.Target().SHA256() {
		return runtimeCondition(job, AttemptConditionConfigurationViolation)
	}
	// A staged launch must state its own resolved absolute path to the provider.
	// The prompt authority appends that layer last; a prompt that does not carry
	// it would leave the provider writing nowhere Mulgae accepts.
	if destination, staged := runtime.stagedOutputDestination(job); staged &&
		!promptDeclaresStagedOutputDestination(material.Prompt, destination) {
		return runtimeCondition(job, AttemptConditionConfigurationViolation)
	}
	if err := runtime.recordRuntimeArtifact(job, material); err != nil {
		return runtimeCondition(job, AttemptConditionConfigurationViolation)
	}
	runtimeArtifactsExpected = true
	providerInvocation, err := runtime.providerInvocation(job, material)
	if err != nil {
		return runtimeCondition(job, runtimeProviderErrorCondition(invocationCtx, err))
	}
	if err := runtime.emitInvocationDiagnostic(invocationCtx, job, domain.RuntimeDiagnosticInfo, domain.DiagnosticInvocationPrepared, "", string(domain.InvocationQueued), "", "", 0, false, "", 0); err != nil {
		return runtimeCondition(job, diagnosticConditionForPersistence(err))
	}
	// Never start a provider with an enclosing deadline that would truncate its
	// configured process window. Capacity waiting and prompt preparation may use
	// the run budget, but their delay is reported as an execution timeout.
	providerCtx, cancelProvider, fullWindow := newProviderExecutionContext(invocationCtx, job.Limits().Timeout())
	if !fullWindow {
		return runtimeCondition(job, AttemptConditionTimeout)
	}
	defer cancelProvider()
	var stdout, rawStdout, stderr []byte
	// Legacy provider results are always carried by process stdout. A staged_file
	// observation substitutes the staged bytes into its isolated result, so the
	// assistant content below is the same value in both transports.
	transport := ports.ProviderOutputTransportStdout
	if runtime.observed != nil {
		providerStarted := time.Now()
		observation, observeErr := runtime.observed.Observe(providerCtx, providerInvocation)
		providerElapsed := time.Since(providerStarted)
		if observeErr != nil {
			if observation.Validate() == nil && sameProviderInvocation(observation.Invocation(), providerInvocation) {
				diagnosticObservation = diagnosticObservationPointer(observation)
				if err := runtime.emitObservationDiagnostics(invocationCtx, job, observation); err != nil {
					return runtimeCondition(job, diagnosticConditionForPersistence(err))
				}
				if err := runtime.capture(invocationCtx, job, nil, observation.Stdout(), observation.Stderr(), false); err != nil {
					return runtimeCondition(job, diagnosticConditionForPersistence(err))
				}
				condition := runtimeProviderErrorCondition(providerCtx, observeErr)
				if !observation.Succeeded() && observedStatusCondition(observation.Status(), observation.PrimaryCause()) == AttemptConditionProviderTimeout {
					condition = AttemptConditionProviderTimeout
				}
				return runtimeObservedCondition(job, condition, observation, providerElapsed)
			}
			return runtimeProviderCondition(job, runtimeProviderErrorCondition(providerCtx, observeErr), providerElapsed)
		}
		if err := observation.Validate(); err != nil || !sameProviderInvocation(observation.Invocation(), providerInvocation) {
			return runtimeCondition(job, AttemptConditionSecurityViolation)
		}
		diagnosticObservation = diagnosticObservationPointer(observation)
		if err := runtime.emitObservationDiagnostics(invocationCtx, job, observation); err != nil {
			return runtimeCondition(job, diagnosticConditionForPersistence(err))
		}
		rawStdout, stderr = observation.Stdout(), observation.Stderr()
		if !observation.Succeeded() {
			if err := runtime.capture(invocationCtx, job, nil, rawStdout, stderr, false); err != nil {
				return runtimeCondition(job, diagnosticConditionForPersistence(err))
			}
			return runtimeObservedCondition(job, observedStatusCondition(observation.Status(), observation.PrimaryCause()), observation, providerElapsed)
		}
		result, ok := observation.Result()
		if !ok || result.StdinByteLength() != len(material.Prompt.Stdin()) || result.CompleteStdinSHA256() != material.Prompt.CompleteStdinSHA256() {
			return runtimeCondition(job, AttemptConditionSecurityViolation)
		}
		transport = observation.OutputTransport()
		stdout = result.Stdout()
	} else {
		providerStarted := time.Now()
		result, invokeErr := runtime.provider.Invoke(providerCtx, providerInvocation)
		providerElapsed := time.Since(providerStarted)
		if invokeErr != nil {
			return runtimeProviderCondition(job, runtimeProviderErrorCondition(providerCtx, invokeErr), providerElapsed)
		}
		stdout = result.Stdout()
		rawStdout = stdout
		if result.StdinByteLength() != len(material.Prompt.Stdin()) || result.CompleteStdinSHA256() != material.Prompt.CompleteStdinSHA256() {
			return runtimeCondition(job, AttemptConditionSecurityViolation)
		}
	}

	scope := validation.ReviewValidationScope{TargetSHA256: job.Target().SHA256(), Role: job.Role(), ProviderInstance: job.Route().ProviderInstance()}
	if job.Role() == domain.RoleArtist && len(material.CapturedArchive) > 0 {
		if captured, archiveErr := ports.UnmarshalCapturedReviewMaterial(material.CapturedArchive); archiveErr == nil {
			scope.ArtistInputsConfigured = true
			scope.ArtistInputsReady = captured.ArtistVisualsReady()
			scope.VisualAssets = make(map[string]string)
			if workspace, workspaceErr := captured.ProviderWorkspace(); workspaceErr == nil {
				for _, file := range workspace.Files() {
					if file.MediaType() == "image/png" || file.MediaType() == "image/jpeg" || file.MediaType() == "image/webp" {
						scope.VisualAssets[file.Path().String()] = file.SHA256()
					}
				}
			}
		}
	}
	assistantContent := append([]byte(nil), stdout...)
	contentClass, validateBytes := classifyAssistantContent(assistantContent)
	if job.Purpose() == domain.InvocationInitial {
		if contentClass == assistantContentFreeForm {
			// Pure prose must not enter Validate: decode failures always mint
			// RepairModeReformatOnly and would incorrectly schedule repair.
			// Capture streams only — never persist prose as an initial candidate.
			if outcome, ok := runtime.acceptFreeFormReport(
				invocationCtx, job, assistantContent, nil, rawStdout, stderr,
				domain.ParseNotStarted, domain.ValidationNotStarted, transport,
			); ok {
				return outcome
			}
			if err := runtime.capture(invocationCtx, job, nil, rawStdout, stderr, false); err != nil {
				return runtimeCondition(job, diagnosticConditionForPersistence(err))
			}
			return runtimeCondition(job, AttemptConditionArtifactFailure)
		}
		if err := runtime.emitInvocationDiagnostic(invocationCtx, job, domain.RuntimeDiagnosticInfo, domain.DiagnosticOutputParseStarted, "", "", "", "", 0, false, "", 0); err != nil {
			return runtimeCondition(job, diagnosticConditionForPersistence(err))
		}
		if err := runtime.emitInvocationDiagnostic(invocationCtx, job, domain.RuntimeDiagnosticInfo, domain.DiagnosticValidationStarted, "", "", "", "", 0, false, "", 0); err != nil {
			return runtimeCondition(job, diagnosticConditionForPersistence(err))
		}
		validated, plan, validationErr := runtime.validator.Validate(invocationCtx, validateBytes, scope)
		parseState = diagnosticParseState(validationErr, validateBytes)
		if validationErr == nil {
			validationState = domain.ValidationValid
		} else {
			validationState = domain.ValidationInvalid
		}
		if err := runtime.emitValidationDiagnostics(invocationCtx, job, validationErr, false); err != nil {
			return runtimeCondition(job, diagnosticConditionForPersistence(err))
		}
		if validationErr != nil {
			securityRejected := isSecurityValidationError(validationErr)
			if securityRejected {
				if err := runtime.capture(invocationCtx, job, validateBytes, rawStdout, stderr, true); err != nil {
					return runtimeCondition(job, diagnosticConditionForPersistence(err))
				}
				return runtimeCondition(job, AttemptConditionSecurityViolation)
			}
			if plan != nil {
				if err := runtime.capture(invocationCtx, job, validateBytes, rawStdout, stderr, false); err != nil {
					return runtimeCondition(job, diagnosticConditionForPersistence(err))
				}
				runtime.mu.Lock()
				runtime.pending[job.AttemptID()] = InvocationRepairInput{
					initial:         append([]byte(nil), validateBytes...),
					primaryReport:   assistantContent,
					plan:            *plan,
					parseState:      parseState,
					validationState: domain.ValidationInvalid,
				}
				runtime.mu.Unlock()
				return runtimeCondition(job, initialValidationFailureCondition(plan, validationErr))
			}
			// Structured/structured-like validation failure accepted as
			// reports-only retains validateBytes as the initial candidate.
			if outcome, ok := runtime.acceptFreeFormReport(
				invocationCtx, job, assistantContent, validateBytes, rawStdout, stderr,
				parseState, domain.ValidationInvalid, transport,
			); ok {
				return outcome
			}
			if err := runtime.capture(invocationCtx, job, validateBytes, rawStdout, stderr, false); err != nil {
				return runtimeCondition(job, diagnosticConditionForPersistence(err))
			}
			return runtimeCondition(job, initialValidationFailureCondition(plan, validationErr))
		}
		if plan != nil {
			return runtimeCondition(job, AttemptConditionInternalInvariant)
		}
		if err := runtime.capture(invocationCtx, job, validateBytes, rawStdout, stderr, false); err != nil {
			return runtimeCondition(job, diagnosticConditionForPersistence(err))
		}
		return runtime.accept(invocationCtx, job, validated, assistantContent, transport)
	}
	if contentClass == assistantContentFreeForm {
		// Repair responses without a structured/structured-like candidate cannot
		// satisfy ApplyRepairCandidate; keep the original primary report and
		// never store it as a repaired candidate.
		if outcome, ok := runtime.acceptFreeFormReport(
			invocationCtx, job, repair.primaryReport, nil, rawStdout, stderr,
			repair.parseState, domain.ValidationRepairExhausted, transport,
		); ok {
			runtime.mu.Lock()
			delete(runtime.pending, job.AttemptID())
			runtime.mu.Unlock()
			return outcome
		}
		if err := runtime.capture(invocationCtx, job, nil, rawStdout, stderr, false); err != nil {
			return runtimeCondition(job, diagnosticConditionForPersistence(err))
		}
		runtime.mu.Lock()
		delete(runtime.pending, job.AttemptID())
		runtime.mu.Unlock()
		return runtimeCondition(job, AttemptConditionArtifactFailure)
	}
	validated, repairedCandidate, validationErr := runtime.validator.ApplyRepairCandidate(invocationCtx, repair.initial, validateBytes, scope, repair.plan)
	parseState = diagnosticParseState(validationErr, validateBytes)
	if validationErr == nil {
		validationState = domain.ValidationRepairedValid
	} else {
		validationState = domain.ValidationRepairExhausted
	}
	if err := runtime.emitValidationDiagnostics(invocationCtx, job, validationErr, true); err != nil {
		return runtimeCondition(job, diagnosticConditionForPersistence(err))
	}
	securityRejected := validationErr != nil && isSecurityValidationError(validationErr)
	if validationErr != nil {
		if securityRejected {
			if err := runtime.capture(invocationCtx, job, nil, rawStdout, stderr, true); err != nil {
				return runtimeCondition(job, diagnosticConditionForPersistence(err))
			}
			runtime.mu.Lock()
			delete(runtime.pending, job.AttemptID())
			runtime.mu.Unlock()
			return runtimeCondition(job, AttemptConditionSecurityViolation)
		}
		// Repair responses must not replace the original primary report and
		// must not persist that report as a repaired candidate.
		if outcome, ok := runtime.acceptFreeFormReport(
			invocationCtx, job, repair.primaryReport, nil, rawStdout, stderr,
			parseState, domain.ValidationRepairExhausted, transport,
		); ok {
			runtime.mu.Lock()
			delete(runtime.pending, job.AttemptID())
			runtime.mu.Unlock()
			return outcome
		}
		if err := runtime.capture(invocationCtx, job, nil, rawStdout, stderr, false); err != nil {
			return runtimeCondition(job, diagnosticConditionForPersistence(err))
		}
		runtime.mu.Lock()
		delete(runtime.pending, job.AttemptID())
		runtime.mu.Unlock()
		return runtimeCondition(job, runtimeErrorCondition(invocationCtx, validationErr))
	}
	if err := runtime.capture(invocationCtx, job, repairedCandidate, rawStdout, stderr, false); err != nil {
		return runtimeCondition(job, diagnosticConditionForPersistence(err))
	}
	primaryReport := append([]byte(nil), repair.primaryReport...)
	runtime.mu.Lock()
	delete(runtime.pending, job.AttemptID())
	runtime.mu.Unlock()
	return runtime.accept(invocationCtx, job, validated, primaryReport, transport)
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
		copy := cloneInvocationRepairInput(input)
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
		input.SourceInvocationID == "" || input.SourceExecutionInvocationID == "" || input.TemplateID == "" || input.TemplateVersion == "" || input.TemplateSHA256 == "" {
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
	key := captureKey{job.AttemptID(), invocationSequence(job.Purpose())}
	runtime.mu.Lock()
	_, inventoryExists := runtime.inventory[key]
	_, invocationActive := runtime.activeExplicit[key]
	if inventoryExists || invocationActive {
		runtime.mu.Unlock()
		return runtimeCondition(job, AttemptConditionConfigurationViolation)
	}
	if runtime.activeExplicit == nil {
		runtime.activeExplicit = make(map[captureKey]struct{})
	}
	runtime.activeExplicit[key] = struct{}{}
	clonePending := make(map[domain.AttemptID]InvocationRepairInput)
	if pending, ok := runtime.pending[job.AttemptID()]; ok {
		clonePending[job.AttemptID()] = cloneInvocationRepairInput(pending)
	}
	runtime.mu.Unlock()
	clone := &ProviderInvocationRuntime{
		provider: runtime.provider, observed: runtime.observed, source: explicitRuntimePromptSource{material: material},
		validator: runtime.validator, verifier: runtime.verifier, workspace: runtime.workspace,
		workspaceIdentity: runtime.workspaceIdentity, hasWorkspace: runtime.hasWorkspace, policy: runtime.policy,
		allowSourceScope: allowSourceScope, diagnostics: runtime.diagnostics, staging: runtime.staging,
		pending: clonePending, captures: make(map[captureKey]AttemptCapture),
		inventory: make(map[captureKey]RuntimeArtifactInventory),
	}
	outcome := clone.Invoke(ctx, job)
	clone.mu.Lock()
	captures := clone.captures
	inventory := clone.inventory
	pending, pendingExists := clone.pending[job.AttemptID()]
	clone.mu.Unlock()
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	delete(runtime.activeExplicit, key)
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
		runtime.pending[job.AttemptID()] = cloneInvocationRepairInput(pending)
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
		CapturedArchive: append([]byte(nil), source.material.CapturedArchive...),
		AdapterProfile:  source.material.AdapterProfile, AdapterParameters: cloneAdapterParameters(source.material.AdapterParameters),
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
func (runtime *ProviderInvocationRuntime) accept(ctx context.Context, job InvocationJob, validated validation.ValidatedReview, primaryReport []byte, transport ports.ProviderOutputTransport) AttemptOutcome {
	verified, err := VerifyValidatedEvidence(ctx, runtime.verifier, validated.EvidenceClaims())
	if err != nil {
		return runtimeCondition(job, runtimeErrorCondition(ctx, err))
	}
	if paths, ok := exactEvidenceRepairPaths(verified); ok {
		if job.Purpose() != domain.InvocationInitial {
			return runtimeCondition(job, AttemptConditionUnrepairableEvidence)
		}
		plan, planErr := validation.NewExactEvidenceRepairPlan(validated.OriginalRaw(), paths)
		if planErr != nil {
			return runtimeCondition(job, AttemptConditionInternalInvariant)
		}
		runtime.mu.Lock()
		runtime.pending[job.AttemptID()] = InvocationRepairInput{
			initial:         validated.OriginalRaw(),
			primaryReport:   append([]byte(nil), primaryReport...),
			plan:            *plan,
			parseState:      domain.ParseValid,
			validationState: domain.ValidationInvalid,
		}
		runtime.mu.Unlock()
		return runtimeCondition(job, AttemptConditionInvalidEvidenceClaim)
	}
	if _, err = ReduceVerifiedFindingEvidence(validated.Findings(), verified, runtime.policy); err != nil {
		return runtimeCondition(job, AttemptConditionUnrepairableEvidence)
	}
	output, err := NewEvidenceValidatedRoleOutput(job.Role(), job.Route().ProviderInstance(), job.Target(), validated.Findings(), validated.Completeness(), validated.Limitations(), verified)
	if err != nil {
		return runtimeCondition(job, AttemptConditionInvalidEvidenceClaim)
	}
	report, reportErr := bindStructuredPrimaryReport(job.Role(), validated, primaryReport)
	if reportErr != nil {
		return runtimeCondition(job, AttemptConditionInternalInvariant)
	}
	if err := output.bindReportMarkdown(report, false); err != nil {
		return runtimeCondition(job, AttemptConditionInternalInvariant)
	}
	if err := output.bindOutputTransport(transport); err != nil {
		return runtimeCondition(job, AttemptConditionInternalInvariant)
	}
	validation := domain.ValidationValid
	if job.Purpose() == domain.InvocationRepair {
		validation = domain.ValidationRepairedValid
	}
	if err := output.bindExtractionStates(domain.ParseValid, validation); err != nil {
		return runtimeCondition(job, AttemptConditionInternalInvariant)
	}
	outcome, err := NewAttemptOutcome(job, &output, nil)
	if err != nil {
		return runtimeCondition(job, AttemptConditionInternalInvariant)
	}
	return outcome
}

func bindStructuredPrimaryReport(role domain.Role, validated validation.ValidatedReview, primaryReport []byte) ([]byte, error) {
	// Production primary report is always the full adapter-extracted assistant
	// content, including pure structured JSON and mixed Markdown+JSON.
	if len(bytes.TrimSpace(primaryReport)) > 0 {
		return normalizeRoleReportMarkdown(primaryReport)
	}
	// Prefer exact provider raw when callers omit primaryReport (tests / repair
	// bridges). Synthetic derive is only the last backward fallback.
	if original := validated.OriginalRaw(); len(bytes.TrimSpace(original)) > 0 {
		return normalizeRoleReportMarkdown(original)
	}
	return deriveStructuredRoleReport(role, validated)
}

// acceptFreeFormReport accepts a Mulgae-owned free-form role report. reportBody
// is the published report markdown; candidate is an optional initial structured
// candidate retained only when an initial structured/structured-like validation
// failure is accepted reports-only. Pure prose and free-form repair responses
// pass a nil candidate so only raw stdout/stderr are captured.
func (runtime *ProviderInvocationRuntime) acceptFreeFormReport(
	ctx context.Context,
	job InvocationJob,
	reportBody, candidate, rawStdout, stderr []byte,
	parse domain.ParseState,
	validation domain.ValidationState,
	transport ports.ProviderOutputTransport,
) (AttemptOutcome, bool) {
	output, err := NewReportsOnlyValidatedRoleOutput(job.Role(), job.Route().ProviderInstance(), job.Target(), reportBody)
	if err != nil {
		return AttemptOutcome{}, false
	}
	if err := output.bindExtractionStates(parse, validation); err != nil {
		return AttemptOutcome{}, false
	}
	if err := output.bindOutputTransport(transport); err != nil {
		return AttemptOutcome{}, false
	}
	if err := runtime.capture(ctx, job, candidate, rawStdout, stderr, false); err != nil {
		return runtimeCondition(job, diagnosticConditionForPersistence(err)), true
	}
	outcome, err := NewAttemptOutcome(job, &output, nil)
	if err != nil {
		return runtimeCondition(job, AttemptConditionInternalInvariant), true
	}
	return outcome, true
}

func exactEvidenceRepairPaths(groups []VerifiedFindingEvidence) ([]string, bool) {
	paths := make([]string, 0)
	for findingIndex, group := range groups {
		for evidenceIndex, receipt := range group.Receipts() {
			if receipt.Status() == evidence.ReceiptVerified {
				continue
			}
			if receipt.Status() != evidence.ReceiptInvalid || receipt.ReasonCode() != evidence.ReasonQuoteMismatch || receipt.ExcerptSHA256() == "" {
				return nil, false
			}
			paths = append(paths, fmt.Sprintf("/findings/%d/evidence/%d/current/quote", findingIndex, evidenceIndex))
		}
	}
	return paths, len(paths) > 0
}

func (runtime *ProviderInvocationRuntime) capture(ctx context.Context, job InvocationJob, candidate, stdout, stderr []byte, reject bool) error {
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
	if !reject {
		if err := runtime.persistDiagnosticRaw(ctx, job, key, stdout, stderr); err != nil {
			return err
		}
	}
	return nil
}

func (runtime *ProviderInvocationRuntime) persistDiagnosticRaw(
	ctx context.Context,
	job InvocationJob,
	key captureKey,
	stdout, stderr []byte,
) error {
	if runtime.diagnostics == nil || len(stdout) == 0 && len(stderr) == 0 {
		return nil
	}
	sink, ok := runtime.diagnostics.RuntimeDiagnosticSink(job.RunID())
	if !ok || nilInterface(sink) {
		return nil
	}
	runtime.mu.Lock()
	inventory, exists := runtime.inventory[key]
	runtime.mu.Unlock()
	if !exists || inventory.sourceInvocationID == "" {
		return fmt.Errorf("provider invocation runtime: diagnostic raw inventory unavailable")
	}
	persistCtx := context.WithoutCancel(ctx)
	persist := func(stream domain.RuntimeDiagnosticStream, content []byte, maximum int64) error {
		if len(content) == 0 {
			return nil
		}
		request, err := ports.NewRuntimeDiagnosticRawRequest(
			job.AttemptID(), inventory.sourceInvocationID, key.sequence, runtimePurpose(job.Purpose()),
			stream, bytes.NewReader(content), maximum, []string{"provider:" + string(stream)}, func(error) {},
		)
		if err != nil {
			return fmt.Errorf("provider invocation runtime: diagnostic raw request: %w", err)
		}
		result, err := sink.PersistRaw(persistCtx, request)
		securityDropped := false
		if err != nil {
			var rejection *ports.RuntimeDiagnosticSecurityRejectionError
			drop, dropped := result.Drop()
			if !errors.As(err, &rejection) || !result.ValidFor(stream) || !dropped || !sameRuntimeDiagnosticDrop(*drop, rejection.Drop()) {
				return err
			}
			securityDropped = true
		} else {
			if !result.ValidFor(stream) {
				return fmt.Errorf("provider invocation runtime: invalid diagnostic raw result")
			}
			if _, dropped := result.Drop(); dropped {
				return fmt.Errorf("provider invocation runtime: unclassified diagnostic raw drop")
			}
		}
		runtime.mu.Lock()
		current, currentExists := runtime.inventory[key]
		if currentExists {
			if stream == domain.DiagnosticStdout {
				current.stdoutDiagnostic, current.hasStdoutDiagnostic = result, true
			} else {
				current.stderrDiagnostic, current.hasStderrDiagnostic = result, true
			}
			runtime.inventory[key] = current
		}
		runtime.mu.Unlock()
		if !currentExists {
			return fmt.Errorf("provider invocation runtime: diagnostic raw inventory disappeared")
		}
		if securityDropped {
			if err := runtime.markCapturedStreamSecurityRejected(key, stream); err != nil {
				return err
			}
		}
		return nil
	}
	if err := persist(domain.DiagnosticStdout, stdout, job.Limits().MaxStdoutBytes()); err != nil {
		return err
	}
	return persist(domain.DiagnosticStderr, stderr, job.Limits().MaxStderrBytes())
}

func (runtime *ProviderInvocationRuntime) markCapturedStreamSecurityRejected(key captureKey, stream domain.RuntimeDiagnosticStream) error {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	capture, captured := runtime.captures[key]
	inventory, inventoried := runtime.inventory[key]
	if !captured || !inventoried {
		return fmt.Errorf("provider invocation runtime: dropped diagnostic capture is unavailable")
	}
	redact := func(artifacts []ports.CapturedAttemptArtifact) ([]ports.CapturedAttemptArtifact, error) {
		result := append([]ports.CapturedAttemptArtifact(nil), artifacts...)
		for index, artifact := range result {
			redactArtifact := stream == domain.DiagnosticStderr && artifact.Kind() == ports.AttemptArtifactStderr ||
				stream == domain.DiagnosticStdout && (artifact.Kind() == ports.AttemptArtifactStdout || artifact.Kind() == ports.AttemptArtifactInitialCandidate || artifact.Kind() == ports.AttemptArtifactRepairedCandidate)
			if !redactArtifact {
				continue
			}
			rejected, err := ports.NewCapturedAttemptArtifact(artifact.Kind(), nil, true)
			if err != nil {
				return nil, err
			}
			result[index] = rejected
		}
		return result, nil
	}
	redacted, err := redact(capture.artifacts)
	if err != nil {
		return err
	}
	capture.artifacts = redacted
	inventory.captures = append([]ports.CapturedAttemptArtifact(nil), redacted...)
	runtime.captures[key] = capture
	runtime.inventory[key] = inventory
	return nil
}

func sameRuntimeDiagnosticDrop(left, right ports.DropMetadata) bool {
	if left.Channel() != right.Channel() || left.Detector() != right.Detector() || left.Count() != right.Count() {
		return false
	}
	leftSources, rightSources := left.SourceIDs(), right.SourceIDs()
	if len(leftSources) != len(rightSources) {
		return false
	}
	for index := range leftSources {
		if leftSources[index] != rightSources[index] {
			return false
		}
	}
	return true
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
		capturedArchive: append([]byte(nil), material.CapturedArchive...),
		targetIdentity:  job.Target(), stdin: material.Prompt.Stdin(),
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
	var invocation ports.ProviderInvocation
	if runtime.hasWorkspace {
		if !sameWorkspaceSnapshotIdentity(runtime.workspace.WorkspaceSnapshotIdentity(), runtime.workspaceIdentity) {
			return ports.ProviderInvocation{}, fmt.Errorf("%w: workspace identity changed", ports.ErrWorkspaceSnapshotDrift)
		}
		invocation, err = ports.NewProviderInvocationWithPacketInWorkspace(
			job.Role(), job.Route().ProviderInstance(), job.AttemptID(), runtimePurpose(job.Purpose()), packet,
			material.Prompt.Scope().SourceInvocationID().String(), material.Prompt.Scope().ExecutionInvocationID().String(),
			runtime.workspace,
		)
	} else {
		invocation, err = ports.NewProviderInvocationWithPacket(
			job.Role(), job.Route().ProviderInstance(), job.AttemptID(), runtimePurpose(job.Purpose()), packet,
			material.Prompt.Scope().SourceInvocationID().String(), material.Prompt.Scope().ExecutionInvocationID().String(),
		)
	}
	if err != nil {
		return ports.ProviderInvocation{}, err
	}
	destination, staged := runtime.stagedOutputDestination(job)
	if !staged {
		return invocation, nil
	}
	return ports.NewProviderInvocationWithStagedOutput(invocation, destination)
}

// stagedOutputDestination resolves the staged destination for one launch of this
// runtime. Initial and repair are distinct launches, so the locator returns a
// distinct per-purpose directory for each and both invocations carry their own.
// Exact replay reproduces stored provider wire authority and therefore never
// introduces a destination the replayed launch did not already have.
func (runtime *ProviderInvocationRuntime) stagedOutputDestination(job InvocationJob) (ports.StagedOutputDestination, bool) {
	if runtime == nil || runtime.allowSourceScope {
		return ports.StagedOutputDestination{}, false
	}
	return ResolveStagedOutputDestination(runtime.staging, job)
}

// promptDeclaresStagedOutputDestination reports whether the compiled launch
// prompt ends with exactly the trusted layer that names destination. A staged
// launch whose prompt states a different path, or no path at all, would send the
// provider to a directory the adapter rejects, so the runtime fails it closed
// instead of executing it.
func promptDeclaresStagedOutputDestination(compiled prompt.CompiledPrompt, destination ports.StagedOutputDestination) bool {
	expected, err := OutputDestinationTrustedLayer(destination)
	if err != nil {
		return false
	}
	manifest := compiled.TrustedTemplate().TrustedLayerManifest()
	if len(manifest) == 0 {
		return false
	}
	last := manifest[len(manifest)-1]
	return last.ID() == OutputDestinationTrustedLayerID && last.SHA256() == expected.SHA256()
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

func runtimeObservedCondition(job InvocationJob, condition AttemptCondition, observation ports.ProviderExecutionObservation, measuredElapsed time.Duration) AttemptOutcome {
	if condition != AttemptConditionProviderTimeout || observation.Validate() != nil {
		return runtimeCondition(job, condition)
	}
	process, ok := observation.AvailableProcessObservation()
	elapsed := measuredElapsed
	if ok {
		elapsed = process.EndedAt().Sub(process.StartedAt())
	}
	if elapsed < 0 {
		elapsed = 0
	}
	return runtimeProviderCondition(job, condition, elapsed)
}

func runtimeProviderCondition(job InvocationJob, condition AttemptCondition, elapsed time.Duration) AttemptOutcome {
	if condition != AttemptConditionProviderTimeout {
		return runtimeCondition(job, condition)
	}
	if elapsed < 0 {
		elapsed = 0
	}
	outcome, err := NewProviderTimeoutAttemptOutcome(job, elapsed)
	if err != nil {
		return runtimeCondition(job, condition)
	}
	return outcome
}

func contextCanRunFor(ctx context.Context, duration time.Duration) bool {
	if ctx == nil || duration <= 0 || ctx.Err() != nil {
		return false
	}
	deadline, ok := ctx.Deadline()
	return !ok || time.Until(deadline) >= duration
}

func newProviderExecutionContext(parent context.Context, duration time.Duration) (context.Context, context.CancelFunc, bool) {
	if parent == nil || duration <= 0 || parent.Err() != nil {
		return nil, nil, false
	}
	parentDeadline, hasParentDeadline := parent.Deadline()
	providerCtx, cancel := context.WithTimeout(parent, duration)
	if hasParentDeadline {
		providerDeadline, hasProviderDeadline := providerCtx.Deadline()
		// Equality means context.WithTimeout inherited the parent's earlier
		// deadline. Only a strictly earlier child deadline proves that the full
		// configured provider window owns this context.
		if !hasProviderDeadline || !providerDeadline.Before(parentDeadline) {
			cancel()
			return nil, nil, false
		}
	}
	return providerCtx, cancel, true
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

// Prompt construction is trusted pre-provider work. Treating its failures as
// invalid provider output incorrectly authorizes a repair without a retained
// validation repair plan.
func runtimePromptErrorCondition(ctx context.Context, err error) AttemptCondition {
	if ctx != nil && ctx.Err() != nil {
		return runtimeContextCondition(ctx.Err())
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return AttemptConditionTimeout
	}
	if errors.Is(err, context.Canceled) {
		return AttemptConditionCancelled
	}
	return AttemptConditionInternalInvariant
}
func isSecurityValidationError(err error) bool {
	cause, ok := validation.RuntimeCause(err)
	return ok && cause == domain.DiagnosticCauseObservationMismatch
}
func sha256Identifier(bytes []byte) string {
	sum := sha256.Sum256(bytes)
	return fmt.Sprintf("sha256:%x", sum)
}
func runtimeProviderErrorCondition(ctx context.Context, err error) AttemptCondition {
	// A typed provider timeout is an observation about the provider process, not
	// merely an inference from the enclosing invocation context. The process and
	// its context commonly reach their deadline together, so retain that more
	// specific observation before consulting ctx.Err(). Untyped deadline errors
	// still describe the enclosing execution budget below.
	if runtimeProviderObservedTimeout(err) {
		return AttemptConditionProviderTimeout
	}
	if errors.Is(err, ports.ErrProviderInstanceAlreadyActive) {
		return AttemptConditionInternalInvariant
	}
	if ctx != nil && ctx.Err() != nil {
		return runtimeContextCondition(ctx.Err())
	}
	if errors.Is(err, ports.ErrWorkspaceSnapshotDrift) || errors.Is(err, ports.ErrProviderPacketSecurity) {
		return AttemptConditionSecurityViolation
	}
	if errors.Is(err, ports.ErrProviderLoginRequired) {
		return AttemptConditionLoginRequired
	}
	var providerFailure *ports.ProviderRuntimeError
	if errors.As(err, &providerFailure) {
		return runtimeCauseCondition(providerFailure.Cause())
	}
	var processFailure *ports.ProcessExecutionError
	if errors.As(err, &processFailure) {
		return runtimeCauseCondition(processFailure.PrimaryCause())
	}
	return AttemptConditionInternalInvariant
}

func runtimeProviderObservedTimeout(err error) bool {
	var providerFailure *ports.ProviderRuntimeError
	if errors.As(err, &providerFailure) && providerFailure.Cause() == domain.DiagnosticCauseTimedOut {
		return true
	}
	var processFailure *ports.ProcessExecutionError
	return errors.As(err, &processFailure) && processFailure.PrimaryCause() == domain.DiagnosticCauseTimedOut
}

func runtimeCauseCondition(cause domain.RuntimeDiagnosticCause) AttemptCondition {
	switch cause {
	case domain.DiagnosticCauseLoginRequired:
		return AttemptConditionLoginRequired
	case domain.DiagnosticCauseAuthenticationFailed:
		return AttemptConditionAuthentication
	case domain.DiagnosticCauseQuotaExceeded:
		return AttemptConditionQuota
	case domain.DiagnosticCauseRateLimited:
		return AttemptConditionRateLimit
	case domain.DiagnosticCauseTimedOut:
		return AttemptConditionProviderTimeout
	case domain.DiagnosticCausePermissionDenied:
		return AttemptConditionProviderPermissionDenied
	case domain.DiagnosticCauseWorkspaceRevalidationFailed,
		domain.DiagnosticCauseTransportVerificationFailed,
		domain.DiagnosticCausePromptFilePreStartFailed,
		domain.DiagnosticCausePromptFilePostEndFailed,
		domain.DiagnosticCauseTransportReceiptMismatch,
		domain.DiagnosticCauseLifecycleReceiptInvalid,
		domain.DiagnosticCauseOutputFrameMismatch,
		domain.DiagnosticCauseSignalReceiptMismatch,
		domain.DiagnosticCauseObservationMismatch,
		// A provider that wrote outside the single staged file it was granted
		// breached a boundary, so staging violations fail the run closed.
		domain.DiagnosticCauseProviderOutputStagingViolation:
		return AttemptConditionSecurityViolation
	case domain.DiagnosticCauseOutputMissing,
		// A staged file the provider never wrote is missing output, exactly like
		// an empty stdout transport: operational, and repair stays available.
		domain.DiagnosticCauseProviderOutputFileMissing:
		return AttemptConditionProviderOutputMissing
	case domain.DiagnosticCauseOutputFrameMissing,
		domain.DiagnosticCauseOutputEnvelopeInvalid,
		domain.DiagnosticCauseOutputDecodeFailed,
		domain.DiagnosticCauseResultBindingFailed,
		// Staged bytes Mulgae could not read back as usable output are an
		// ordinary decode failure rather than a boundary breach.
		domain.DiagnosticCauseProviderOutputFileInvalid:
		return AttemptConditionProviderOutputDecodeFailed
	case domain.DiagnosticCauseProviderOutputStagingCleanupFailed:
		// Staging Mulgae cannot prove it removed is an artifact fact: fail closed
		// rather than reuse the attempt through repair.
		return AttemptConditionArtifactFailure
	case domain.DiagnosticCauseCandidateValidationFailed,
		domain.DiagnosticCauseCandidateRepairPlanInvalid:
		return AttemptConditionSemanticContradiction
	case domain.DiagnosticCauseProviderSpawnFailed:
		return AttemptConditionProviderSpawnFailed
	case domain.DiagnosticCauseProviderExecutionFailed,
		domain.DiagnosticCauseProviderProcessWaitFailed,
		domain.DiagnosticCauseObservationInvalid:
		return AttemptConditionProviderUnavailable
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
	leftDestination, leftHasStaged := left.StagedOutputDestination()
	rightDestination, rightHasStaged := right.StagedOutputDestination()
	if leftHasStaged != rightHasStaged || (leftHasStaged && leftDestination != rightDestination) {
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

// observedStatusCondition selects the coordinator condition for a failed
// observation. The typed cause is authoritative and is consulted before the
// execution status: the adapter projects a missing or unusable staged file onto
// an artifact-failure status, and only the cause proves those two remain
// operational invalid-output outcomes that keep repair available.
func observedStatusCondition(status ports.ProviderExecutionStatus, cause domain.RuntimeDiagnosticCause) AttemptCondition {
	switch cause {
	case domain.DiagnosticCauseOutputMissing,
		domain.DiagnosticCauseProviderOutputFileMissing:
		return AttemptConditionProviderOutputMissing
	case domain.DiagnosticCauseOutputFrameMissing,
		domain.DiagnosticCauseOutputEnvelopeInvalid,
		domain.DiagnosticCauseOutputDecodeFailed,
		domain.DiagnosticCauseResultBindingFailed,
		domain.DiagnosticCauseProviderOutputFileInvalid:
		return AttemptConditionProviderOutputDecodeFailed
	case domain.DiagnosticCausePermissionDenied:
		return AttemptConditionProviderPermissionDenied
	case domain.DiagnosticCauseProviderOutputStagingViolation:
		return AttemptConditionSecurityViolation
	case domain.DiagnosticCauseProviderOutputStagingCleanupFailed:
		return AttemptConditionArtifactFailure
	}
	switch status {
	case ports.ProviderExecutionStatusUnavailable:
		return AttemptConditionProviderUnavailable
	case ports.ProviderExecutionStatusTimedOut:
		return AttemptConditionProviderTimeout
	case ports.ProviderExecutionStatusAuthentication:
		if cause == domain.DiagnosticCauseLoginRequired {
			return AttemptConditionLoginRequired
		}
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

func initialValidationFailureCondition(plan *validation.RepairPlan, err error) AttemptCondition {
	if plan == nil {
		if cause, ok := validation.RuntimeCause(err); ok && cause == domain.DiagnosticCauseCandidateValidationFailed {
			return AttemptConditionSemanticContradiction
		}
		return AttemptConditionUnrepairableProviderOutput
	}
	return AttemptConditionInvalidProviderOutput
}
