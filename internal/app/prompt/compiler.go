// Package prompt compiles the byte-exact provider stdin packet. It owns the
// only concatenation boundary between trusted template bytes and untrusted
// framed payloads.
package prompt

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"sync"

	"github.com/irootkernel/kkachi-agent-review/internal/domain"
)

const (
	// MaxReviewTargetBytes is the fixed captured-target cap. Oversized targets
	// fail; they are never silently truncated.
	MaxReviewTargetBytes = 180000

	framePreamble       = "KAR-UNTRUSTED/1\n"
	framesPreamble      = "\nKAR-FRAMES/1\n"
	framesEnd           = "KAR-FRAMES-END/1\n"
	stdinHashDomain     = "KAR-PROVIDER-STDIN/1\x00"
	sectionHashDomain   = "KAR-PROMPT-SECTION/1\x00"
	sectionIDHexLength  = 32
	sha256HexLength     = sha256.Size * 2
	maximumDecimalBytes = 20
)

// SectionKind identifies one untrusted frame type in the standalone grammar.
type SectionKind string

const (
	SectionProjectContext      SectionKind = "project_context"
	SectionReviewTarget        SectionKind = "review_target"
	SectionPriorProviderOutput SectionKind = "prior_provider_output"
	SectionPriorFinding        SectionKind = "prior_finding"
	SectionPriorReport         SectionKind = "prior_report"
	SectionExternalLog         SectionKind = "external_log"
)

func (kind SectionKind) Valid() bool {
	switch kind {
	case SectionProjectContext, SectionReviewTarget, SectionPriorProviderOutput,
		SectionPriorFinding, SectionPriorReport, SectionExternalLog:
		return true
	default:
		return false
	}
}

// RoleTaskID is the canonical, opaque role-task identifier used in a frame
// scope. Domain role tasks deliberately do not expose an identifier because
// their aggregate is not an artifact identity.
type RoleTaskID struct{ value string }

// SourceInvocationID is the source identity shared by every frame in one
// newly composed packet.
type SourceInvocationID struct{ value string }

// ExecutionInvocationID identifies one provider process. Unlike source
// identities, it deliberately has no prefix.
type ExecutionInvocationID struct{ value string }

func ParseRoleTaskID(value string) (RoleTaskID, error) {
	if err := validatePrefixedUUIDv7(value, "rt_"); err != nil {
		return RoleTaskID{}, fmt.Errorf("role task id: %w", err)
	}
	return RoleTaskID{value: value}, nil
}

func ParseSourceInvocationID(value string) (SourceInvocationID, error) {
	if err := validatePrefixedUUIDv7(value, "i_"); err != nil {
		return SourceInvocationID{}, fmt.Errorf("source invocation id: %w", err)
	}
	return SourceInvocationID{value: value}, nil
}

func ParseExecutionInvocationID(value string) (ExecutionInvocationID, error) {
	if err := validateUUIDv7(value); err != nil {
		return ExecutionInvocationID{}, fmt.Errorf("execution invocation id: %w", err)
	}
	return ExecutionInvocationID{value: value}, nil
}

func (id RoleTaskID) String() string            { return id.value }
func (id SourceInvocationID) String() string    { return id.value }
func (id ExecutionInvocationID) String() string { return id.value }

// ScopeCoordinates are the stable identities shared by a source invocation
// and all of its exact replays.
type ScopeCoordinates struct {
	sessionID  domain.SessionID
	runID      domain.RunID
	roleTaskID RoleTaskID
	attemptID  domain.AttemptID
}

func NewScopeCoordinates(sessionID domain.SessionID, runID domain.RunID, roleTaskID RoleTaskID, attemptID domain.AttemptID) (ScopeCoordinates, error) {
	coordinates := ScopeCoordinates{
		sessionID:  sessionID,
		runID:      runID,
		roleTaskID: roleTaskID,
		attemptID:  attemptID,
	}
	if err := coordinates.validate(); err != nil {
		return ScopeCoordinates{}, err
	}
	return coordinates, nil
}

func (coordinates ScopeCoordinates) SessionID() domain.SessionID { return coordinates.sessionID }
func (coordinates ScopeCoordinates) RunID() domain.RunID         { return coordinates.runID }
func (coordinates ScopeCoordinates) RoleTaskID() RoleTaskID      { return coordinates.roleTaskID }
func (coordinates ScopeCoordinates) AttemptID() domain.AttemptID { return coordinates.attemptID }

func (coordinates ScopeCoordinates) validate() error {
	if _, err := domain.ParseSessionID(coordinates.sessionID.String()); err != nil {
		return fmt.Errorf("prompt scope: invalid session id: %w", err)
	}
	if _, err := domain.ParseRunID(coordinates.runID.String()); err != nil {
		return fmt.Errorf("prompt scope: invalid run id: %w", err)
	}
	if _, err := ParseRoleTaskID(coordinates.roleTaskID.String()); err != nil {
		return fmt.Errorf("prompt scope: invalid role task id: %w", err)
	}
	if _, err := domain.ParseAttemptID(coordinates.attemptID.String()); err != nil {
		return fmt.Errorf("prompt scope: invalid attempt id: %w", err)
	}
	return nil
}

// FrameScope is the identity serialized in every untrusted frame. Execution
// identity is intentionally excluded from the frame grammar.
type FrameScope struct {
	coordinates        ScopeCoordinates
	sourceInvocationID SourceInvocationID
}

func NewFrameScope(coordinates ScopeCoordinates, sourceInvocationID SourceInvocationID) (FrameScope, error) {
	frameScope := FrameScope{coordinates: coordinates, sourceInvocationID: sourceInvocationID}
	if err := frameScope.validate(); err != nil {
		return FrameScope{}, err
	}
	return frameScope, nil
}

func (scope FrameScope) Coordinates() ScopeCoordinates          { return scope.coordinates }
func (scope FrameScope) SessionID() domain.SessionID            { return scope.coordinates.sessionID }
func (scope FrameScope) RunID() domain.RunID                    { return scope.coordinates.runID }
func (scope FrameScope) RoleTaskID() RoleTaskID                 { return scope.coordinates.roleTaskID }
func (scope FrameScope) AttemptID() domain.AttemptID            { return scope.coordinates.attemptID }
func (scope FrameScope) SourceInvocationID() SourceInvocationID { return scope.sourceInvocationID }
func (scope FrameScope) String() string {
	return scope.SessionID().String() + "/" + scope.RunID().String() + "/" + scope.RoleTaskID().String() + "/" + scope.AttemptID().String() + "/" + scope.SourceInvocationID().String()
}

func (scope FrameScope) validate() error {
	if err := scope.coordinates.validate(); err != nil {
		return err
	}
	if _, err := ParseSourceInvocationID(scope.sourceInvocationID.String()); err != nil {
		return fmt.Errorf("prompt scope: invalid source invocation id: %w", err)
	}
	return nil
}

func (scope FrameScope) equal(other FrameScope) bool {
	return scope.SessionID() == other.SessionID() &&
		scope.RunID() == other.RunID() &&
		scope.RoleTaskID() == other.RoleTaskID() &&
		scope.AttemptID() == other.AttemptID() &&
		scope.SourceInvocationID() == other.SourceInvocationID()
}

// Scope binds the full canonical identity for one process invocation.
type Scope struct {
	frameScope            FrameScope
	executionInvocationID ExecutionInvocationID
}

func NewScope(coordinates ScopeCoordinates, sourceInvocationID SourceInvocationID, executionInvocationID ExecutionInvocationID) (Scope, error) {
	frameScope, err := NewFrameScope(coordinates, sourceInvocationID)
	if err != nil {
		return Scope{}, err
	}
	scope := Scope{frameScope: frameScope, executionInvocationID: executionInvocationID}
	if err := scope.validate(); err != nil {
		return Scope{}, err
	}
	return scope, nil
}

func (scope Scope) FrameScope() FrameScope        { return scope.frameScope }
func (scope Scope) Coordinates() ScopeCoordinates { return scope.frameScope.coordinates }
func (scope Scope) SessionID() domain.SessionID   { return scope.frameScope.SessionID() }
func (scope Scope) RunID() domain.RunID           { return scope.frameScope.RunID() }
func (scope Scope) RoleTaskID() RoleTaskID        { return scope.frameScope.RoleTaskID() }
func (scope Scope) AttemptID() domain.AttemptID   { return scope.frameScope.AttemptID() }
func (scope Scope) SourceInvocationID() SourceInvocationID {
	return scope.frameScope.SourceInvocationID()
}
func (scope Scope) ExecutionInvocationID() ExecutionInvocationID { return scope.executionInvocationID }

func (scope Scope) validate() error {
	if err := scope.frameScope.validate(); err != nil {
		return err
	}
	if _, err := ParseExecutionInvocationID(scope.executionInvocationID.String()); err != nil {
		return fmt.Errorf("prompt scope: invalid execution invocation id: %w", err)
	}
	if rawUUID(scope.SourceInvocationID().String()) == scope.ExecutionInvocationID().String() {
		return fmt.Errorf("prompt scope: source and execution invocation ids must be distinct")
	}
	return nil
}

// TrustedLayer is an immutable compiler input. Callers provide individual
// trusted assets; only ComposeTrustedTemplate joins them into template bytes.
type TrustedLayer struct {
	id      string
	version string
	bytes   []byte
}

func NewTrustedLayer(id, version string, content []byte) (TrustedLayer, error) {
	if err := validateTemplateLabel("layer id", id); err != nil {
		return TrustedLayer{}, err
	}
	if err := validateTemplateLabel("layer version", version); err != nil {
		return TrustedLayer{}, err
	}
	if len(content) > 0 && content[len(content)-1] == '\n' {
		return TrustedLayer{}, fmt.Errorf("trusted layer: must not end with LF")
	}
	return TrustedLayer{id: id, version: version, bytes: cloneBytes(content)}, nil
}

func (layer TrustedLayer) ID() string      { return layer.id }
func (layer TrustedLayer) Version() string { return layer.version }
func (layer TrustedLayer) Bytes() []byte   { return cloneBytes(layer.bytes) }

func (layer TrustedLayer) validate() error {
	if err := validateTemplateLabel("layer id", layer.id); err != nil {
		return err
	}
	if err := validateTemplateLabel("layer version", layer.version); err != nil {
		return err
	}
	if len(layer.bytes) > 0 && layer.bytes[len(layer.bytes)-1] == '\n' {
		return fmt.Errorf("trusted layer: must not end with LF")
	}
	return nil
}

// ComposeTrustedTemplate is the compiler-owned trusted-layer composer. It
// inserts exactly one blank line between consecutive trusted layers and never
// exposes a raw trusted-byte concatenation helper.
func ComposeTrustedTemplate(id, version string, layers ...TrustedLayer) (TrustedTemplate, error) {
	if len(layers) == 0 {
		return TrustedTemplate{}, fmt.Errorf("trusted template: at least one trusted layer is required")
	}
	contentLength := len(layers) - 1
	for index, layer := range layers {
		if err := layer.validate(); err != nil {
			return TrustedTemplate{}, fmt.Errorf("trusted template: layer %d: %w", index+1, err)
		}
		contentLength += len(layer.bytes)
	}
	content := make([]byte, 0, contentLength)
	for index, layer := range layers {
		if index > 0 {
			content = append(content, '\n', '\n')
		}
		content = append(content, layer.bytes...)
	}
	return NewTrustedTemplate(id, version, content)
}

// TrustedTemplate holds exact immutable trusted bytes. Its byte getter always
// returns a copy, and the compiler copies it again when constructed.
type TrustedTemplate struct {
	id      string
	version string
	bytes   []byte
	sha256  string
}

func NewTrustedTemplate(id, version string, content []byte) (TrustedTemplate, error) {
	if err := validateTemplateLabel("id", id); err != nil {
		return TrustedTemplate{}, err
	}
	if err := validateTemplateLabel("version", version); err != nil {
		return TrustedTemplate{}, err
	}
	if len(content) > 0 && content[len(content)-1] == '\n' {
		return TrustedTemplate{}, fmt.Errorf("trusted template: must not end with LF")
	}
	copied := cloneBytes(content)
	return TrustedTemplate{
		id:      id,
		version: version,
		bytes:   copied,
		sha256:  payloadSHA256(copied),
	}, nil
}

func (template TrustedTemplate) ID() string      { return template.id }
func (template TrustedTemplate) Version() string { return template.version }
func (template TrustedTemplate) Bytes() []byte   { return cloneBytes(template.bytes) }
func (template TrustedTemplate) SHA256() string  { return template.sha256 }
func (template TrustedTemplate) ByteLength() int { return len(template.bytes) }

func (template TrustedTemplate) validate() error {
	if err := validateTemplateLabel("id", template.id); err != nil {
		return err
	}
	if err := validateTemplateLabel("version", template.version); err != nil {
		return err
	}
	if len(template.bytes) > 0 && template.bytes[len(template.bytes)-1] == '\n' {
		return fmt.Errorf("trusted template: must not end with LF")
	}
	if template.sha256 != payloadSHA256(template.bytes) {
		return fmt.Errorf("trusted template: SHA-256 does not match bytes")
	}
	return nil
}

// Payload is an immutable untrusted byte value. It may be empty; a nil
// optional Payload pointer means that optional section is absent.
type Payload struct{ bytes []byte }

func NewPayload(content []byte) Payload { return Payload{bytes: cloneBytes(content)} }

func (payload Payload) Bytes() []byte   { return cloneBytes(payload.bytes) }
func (payload Payload) ByteLength() int { return len(payload.bytes) }
func (payload Payload) SHA256() string  { return payloadSHA256(payload.bytes) }

// CompileInput describes the only permitted frame cardinalities. The compiler
// determines every frame kind and order; callers cannot supply raw frames.
type CompileInput struct {
	Scope               ScopeCoordinates
	ProjectContext      *Payload
	ReviewTarget        Payload
	PriorProviderOutput *Payload
	PriorFinding        *Payload
	PriorReport         *Payload
	ExternalLogs        []Payload
}

// InvocationIDIssuer issues fresh canonical identities. The compiler tracks
// all returned raw UUIDv7 values and rejects a repeated identity, including a
// source/execution namespace collision.
type InvocationIDIssuer interface {
	NewSourceInvocationID() (SourceInvocationID, error)
	NewExecutionInvocationID() (ExecutionInvocationID, error)
}

// IdentityError reports a failure while issuing, reserving, or constructing an
// invocation identity. It lets callers distinguish identity failures from
// input, template, and frame validation failures.
type IdentityError struct {
	operation string
	cause     error
}

func (err *IdentityError) Error() string {
	if err == nil {
		return "<nil>"
	}
	if err.cause == nil {
		return "prompt identity: " + err.operation
	}
	return fmt.Sprintf("prompt identity: %s: %v", err.operation, err.cause)
}

func (err *IdentityError) Unwrap() error {
	if err == nil {
		return nil
	}
	return err.cause
}

// Operation identifies the identity operation that failed.
func (err *IdentityError) Operation() string {
	if err == nil {
		return ""
	}
	return err.operation
}

func newIdentityError(operation string, cause error) *IdentityError {
	return &IdentityError{operation: operation, cause: cause}
}

// Compiler owns trusted-template composition and the exact stdin wire format.
type Compiler struct {
	template TrustedTemplate
	issuer   InvocationIDIssuer

	mu                    sync.Mutex
	usedInvocationUUID    map[string]struct{}
	sourceWireIdentity    map[string]string
	executionWireIdentity map[string]string
}

func NewCompiler(template TrustedTemplate, issuer InvocationIDIssuer) (*Compiler, error) {
	if err := template.validate(); err != nil {
		return nil, fmt.Errorf("prompt compiler: invalid trusted template: %w", err)
	}
	if nilInterface(issuer) {
		return nil, fmt.Errorf("prompt compiler: invocation id issuer is required")
	}
	return &Compiler{
		template:              cloneTrustedTemplate(template),
		issuer:                issuer,
		usedInvocationUUID:    make(map[string]struct{}),
		sourceWireIdentity:    make(map[string]string),
		executionWireIdentity: make(map[string]string),
	}, nil
}

// Compile mints a fresh source and execution identity, frames the supplied
// untrusted data, and returns the exact provider stdin bytes.
func (compiler *Compiler) Compile(input CompileInput) (CompiledPrompt, error) {
	if compiler == nil {
		return CompiledPrompt{}, fmt.Errorf("prompt compiler: nil receiver")
	}
	if err := input.Scope.validate(); err != nil {
		return CompiledPrompt{}, err
	}
	pending, err := orderedPayloads(input)
	if err != nil {
		return CompiledPrompt{}, err
	}
	scope, err := compiler.issueScope(input.Scope)
	if err != nil {
		return CompiledPrompt{}, err
	}
	sections, err := framePayloads(scope.FrameScope(), pending)
	if err != nil {
		return CompiledPrompt{}, err
	}
	stdin := composeStdin(compiler.template.bytes, sections)
	prompt := CompiledPrompt{
		template: cloneTrustedTemplate(compiler.template),
		scope:    scope,
		stdin:    stdin,
		sections: cloneSections(sections),
		digest:   CompleteStdinSHA256(stdin),
	}
	if err := prompt.Validate(); err != nil {
		return CompiledPrompt{}, fmt.Errorf("prompt compiler: generated invalid packet: %w", err)
	}
	if err := compiler.bindCompiledWireIdentity(scope, prompt.digest); err != nil {
		return CompiledPrompt{}, err
	}
	return prompt, nil
}

// Replay performs an exact replay: it preserves stored stdin and source
// identity, mints only a fresh execution identity, and marks the result as a
// replay. A caller wanting current templates must call Compile instead.
func (compiler *Compiler) Replay(source CompiledPrompt) (CompiledPrompt, error) {
	if compiler == nil {
		return CompiledPrompt{}, fmt.Errorf("prompt compiler: nil receiver")
	}
	if err := source.Validate(); err != nil {
		return CompiledPrompt{}, fmt.Errorf("prompt replay: invalid source packet: %w", err)
	}
	executionID, err := compiler.issueReplayExecutionID(
		source.scope.SourceInvocationID(),
		source.scope.ExecutionInvocationID(),
		source.digest,
	)
	if err != nil {
		return CompiledPrompt{}, err
	}
	scope, err := NewScope(source.scope.Coordinates(), source.scope.SourceInvocationID(), executionID)
	if err != nil {
		return CompiledPrompt{}, newIdentityError("replay scope construction", err)
	}
	replay := CompiledPrompt{
		template:              cloneTrustedTemplate(source.template),
		scope:                 scope,
		stdin:                 cloneBytes(source.stdin),
		sections:              cloneSections(source.sections),
		digest:                source.digest,
		replayedSourceInvoked: source.scope.SourceInvocationID(),
		exactReplay:           true,
	}
	if err := replay.Validate(); err != nil {
		return CompiledPrompt{}, fmt.Errorf("prompt replay: generated invalid packet: %w", err)
	}
	return replay, nil
}

func (compiler *Compiler) issueScope(coordinates ScopeCoordinates) (Scope, error) {
	compiler.mu.Lock()
	defer compiler.mu.Unlock()

	sourceID, err := compiler.issuer.NewSourceInvocationID()
	if err != nil {
		return Scope{}, newIdentityError("compile source invocation issuance", err)
	}
	if _, err := ParseSourceInvocationID(sourceID.String()); err != nil {
		return Scope{}, newIdentityError("compile source invocation validation", err)
	}
	if err := compiler.reserveIssuedUUID(rawUUID(sourceID.String())); err != nil {
		return Scope{}, newIdentityError("compile source invocation reservation", err)
	}
	executionID, err := compiler.issuer.NewExecutionInvocationID()
	if err != nil {
		return Scope{}, newIdentityError("compile execution invocation issuance", err)
	}
	if _, err := ParseExecutionInvocationID(executionID.String()); err != nil {
		return Scope{}, newIdentityError("compile execution invocation validation", err)
	}
	if err := compiler.reserveIssuedUUID(executionID.String()); err != nil {
		return Scope{}, newIdentityError("compile execution invocation reservation", err)
	}
	scope, err := NewScope(coordinates, sourceID, executionID)
	if err != nil {
		return Scope{}, newIdentityError("compile scope construction", err)
	}
	return scope, nil
}

func (compiler *Compiler) issueReplayExecutionID(sourceID SourceInvocationID, priorExecutionID ExecutionInvocationID, wireIdentity string) (ExecutionInvocationID, error) {
	compiler.mu.Lock()
	defer compiler.mu.Unlock()

	if _, err := ParseSourceInvocationID(sourceID.String()); err != nil {
		return ExecutionInvocationID{}, newIdentityError("replay source invocation validation", err)
	}
	if err := compiler.reserveReplaySourceWireIdentity(sourceID, wireIdentity); err != nil {
		return ExecutionInvocationID{}, newIdentityError("replay source wire identity reservation", err)
	}
	if err := compiler.reserveReplayExecutionWireIdentity(sourceID, priorExecutionID, wireIdentity); err != nil {
		return ExecutionInvocationID{}, newIdentityError("replay prior execution wire identity reservation", err)
	}

	executionID, err := compiler.issuer.NewExecutionInvocationID()
	if err != nil {
		return ExecutionInvocationID{}, newIdentityError("replay execution invocation issuance", err)
	}
	if _, err := ParseExecutionInvocationID(executionID.String()); err != nil {
		return ExecutionInvocationID{}, newIdentityError("replay execution invocation validation", err)
	}
	if executionID == priorExecutionID {
		return ExecutionInvocationID{}, newIdentityError(
			"replay execution invocation freshness",
			fmt.Errorf("issuer reused source packet execution invocation UUIDv7 %q", executionID.String()),
		)
	}
	if err := compiler.reserveIssuedUUID(executionID.String()); err != nil {
		return ExecutionInvocationID{}, newIdentityError("replay execution invocation reservation", err)
	}
	compiler.executionWireIdentity[executionID.String()] = replayWireBinding(sourceID, wireIdentity)
	return executionID, nil
}

func (compiler *Compiler) reserveReplaySourceWireIdentity(sourceID SourceInvocationID, wireIdentity string) error {
	raw := rawUUID(sourceID.String())
	if boundWireIdentity, exists := compiler.sourceWireIdentity[raw]; exists {
		if boundWireIdentity != wireIdentity {
			return fmt.Errorf("source invocation UUIDv7 %q is already bound to a different wire identity", raw)
		}
		return nil
	}
	if _, exists := compiler.usedInvocationUUID[raw]; exists {
		return fmt.Errorf("source invocation UUIDv7 %q collides with an existing invocation identity", raw)
	}
	compiler.usedInvocationUUID[raw] = struct{}{}
	compiler.sourceWireIdentity[raw] = wireIdentity
	return nil
}

func (compiler *Compiler) reserveReplayExecutionWireIdentity(sourceID SourceInvocationID, executionID ExecutionInvocationID, wireIdentity string) error {
	raw := executionID.String()
	binding := replayWireBinding(sourceID, wireIdentity)
	if bound, exists := compiler.executionWireIdentity[raw]; exists {
		if bound != binding {
			return fmt.Errorf("execution invocation UUIDv7 %q is already bound to a different replay source", raw)
		}
		return nil
	}
	if _, exists := compiler.usedInvocationUUID[raw]; exists {
		return fmt.Errorf("execution invocation UUIDv7 %q collides with an existing invocation identity", raw)
	}
	compiler.usedInvocationUUID[raw] = struct{}{}
	compiler.executionWireIdentity[raw] = binding
	return nil
}

func replayWireBinding(sourceID SourceInvocationID, wireIdentity string) string {
	return sourceID.String() + "\x00" + wireIdentity
}

func (compiler *Compiler) bindCompiledWireIdentity(scope Scope, wireIdentity string) error {
	compiler.mu.Lock()
	defer compiler.mu.Unlock()

	sourceRaw := rawUUID(scope.SourceInvocationID().String())
	executionRaw := scope.ExecutionInvocationID().String()
	if _, exists := compiler.usedInvocationUUID[sourceRaw]; !exists {
		return newIdentityError("compile source wire identity binding", fmt.Errorf("source invocation UUIDv7 %q was not reserved", sourceRaw))
	}
	if _, exists := compiler.usedInvocationUUID[executionRaw]; !exists {
		return newIdentityError("compile execution wire identity binding", fmt.Errorf("execution invocation UUIDv7 %q was not reserved", executionRaw))
	}
	if _, exists := compiler.sourceWireIdentity[sourceRaw]; exists {
		return newIdentityError("compile source wire identity binding", fmt.Errorf("source invocation UUIDv7 %q is already bound to a wire identity", sourceRaw))
	}
	if _, exists := compiler.executionWireIdentity[executionRaw]; exists {
		return newIdentityError("compile execution wire identity binding", fmt.Errorf("execution invocation UUIDv7 %q is already bound to a wire identity", executionRaw))
	}
	compiler.sourceWireIdentity[sourceRaw] = wireIdentity
	compiler.executionWireIdentity[executionRaw] = replayWireBinding(scope.SourceInvocationID(), wireIdentity)
	return nil
}

func (compiler *Compiler) reserveIssuedUUID(raw string) error {
	if _, exists := compiler.usedInvocationUUID[raw]; exists {
		return fmt.Errorf("issuer reused invocation UUIDv7 %q", raw)
	}
	compiler.usedInvocationUUID[raw] = struct{}{}
	return nil
}

type pendingPayload struct {
	kind    SectionKind
	payload []byte
}

func orderedPayloads(input CompileInput) ([]pendingPayload, error) {
	if len(input.ReviewTarget.bytes) > MaxReviewTargetBytes {
		return nil, fmt.Errorf("prompt compiler: review target exceeds %d bytes", MaxReviewTargetBytes)
	}
	pending := make([]pendingPayload, 0, 5+len(input.ExternalLogs))
	if input.ProjectContext != nil {
		pending = append(pending, pendingPayload{kind: SectionProjectContext, payload: cloneBytes(input.ProjectContext.bytes)})
	}
	pending = append(pending, pendingPayload{kind: SectionReviewTarget, payload: cloneBytes(input.ReviewTarget.bytes)})
	if input.PriorProviderOutput != nil {
		pending = append(pending, pendingPayload{kind: SectionPriorProviderOutput, payload: cloneBytes(input.PriorProviderOutput.bytes)})
	}
	if input.PriorFinding != nil {
		pending = append(pending, pendingPayload{kind: SectionPriorFinding, payload: cloneBytes(input.PriorFinding.bytes)})
	}
	if input.PriorReport != nil {
		pending = append(pending, pendingPayload{kind: SectionPriorReport, payload: cloneBytes(input.PriorReport.bytes)})
	}
	for _, externalLog := range input.ExternalLogs {
		pending = append(pending, pendingPayload{kind: SectionExternalLog, payload: cloneBytes(externalLog.bytes)})
	}
	return pending, nil
}

func framePayloads(scope FrameScope, pending []pendingPayload) ([]FramedSection, error) {
	sections := make([]FramedSection, 0, len(pending))
	for index, item := range pending {
		if !item.kind.Valid() {
			return nil, fmt.Errorf("prompt compiler: invalid section kind %q", item.kind)
		}
		ordinal := uint64(index + 1)
		sectionID := deriveSectionID(scope.SourceInvocationID(), ordinal, item.kind, item.payload)
		frame := makeFrame(scope, sectionID, item.kind, item.payload)
		sections = append(sections, frame)
	}
	if err := validateSections(sections); err != nil {
		return nil, err
	}
	return sections, nil
}

func makeFrame(scope FrameScope, sectionID string, kind SectionKind, payload []byte) FramedSection {
	payload = cloneBytes(payload)
	payloadDigest := payloadSHA256(payload)
	var frame bytes.Buffer
	frame.Grow(len(framePreamble) + len(scope.String()) + len(sectionID)*2 + len(kind) + len(payload) + 96)
	frame.WriteString(framePreamble)
	frame.WriteString("scope:")
	frame.WriteString(scope.String())
	frame.WriteByte('\n')
	frame.WriteString("section-id:")
	frame.WriteString(sectionID)
	frame.WriteByte('\n')
	frame.WriteString("kind:")
	frame.WriteString(string(kind))
	frame.WriteByte('\n')
	frame.WriteString("length:")
	frame.WriteString(strconv.FormatUint(uint64(len(payload)), 10))
	frame.WriteByte('\n')
	frame.WriteString("sha256:")
	frame.WriteString(payloadDigest)
	frame.WriteString("\n\n")
	frame.Write(payload)
	frame.WriteByte('\n')
	frame.WriteString("KAR-END/")
	frame.WriteString(sectionID)
	frame.WriteByte('\n')
	frameBytes := frame.Bytes()
	return FramedSection{
		scope:         scope,
		id:            sectionID,
		kind:          kind,
		payload:       payload,
		payloadSHA256: payloadDigest,
		frame:         cloneBytes(frameBytes),
	}
}

func composeStdin(template []byte, sections []FramedSection) []byte {
	total := len(template) + len(framesPreamble) + len(framesEnd)
	for _, section := range sections {
		total += len(section.frame)
	}
	stdin := make([]byte, 0, total)
	stdin = append(stdin, template...)
	stdin = append(stdin, framesPreamble...)
	for _, section := range sections {
		stdin = append(stdin, section.frame...)
	}
	stdin = append(stdin, framesEnd...)
	return stdin
}

// FramedSection records one validated frame and exposes defensive copies of
// its untrusted payload and exact frame bytes.
type FramedSection struct {
	scope         FrameScope
	id            string
	kind          SectionKind
	payload       []byte
	payloadSHA256 string
	frame         []byte
}

func (section FramedSection) Scope() FrameScope      { return section.scope }
func (section FramedSection) ID() string             { return section.id }
func (section FramedSection) Kind() SectionKind      { return section.kind }
func (section FramedSection) Payload() []byte        { return cloneBytes(section.payload) }
func (section FramedSection) PayloadSHA256() string  { return section.payloadSHA256 }
func (section FramedSection) FrameBytes() []byte     { return cloneBytes(section.frame) }
func (section FramedSection) PayloadByteLength() int { return len(section.payload) }

// CompiledPrompt is an immutable provider-stdin packet. It does not contain a
// provider, result, outcome, or any publication authority.
type CompiledPrompt struct {
	template TrustedTemplate
	scope    Scope
	stdin    []byte
	sections []FramedSection
	digest   string

	replayedSourceInvoked SourceInvocationID
	exactReplay           bool
}

func (prompt CompiledPrompt) TrustedTemplate() TrustedTemplate {
	return cloneTrustedTemplate(prompt.template)
}
func (prompt CompiledPrompt) Scope() Scope                 { return prompt.scope }
func (prompt CompiledPrompt) Stdin() []byte                { return cloneBytes(prompt.stdin) }
func (prompt CompiledPrompt) CompleteStdinSHA256() string  { return prompt.digest }
func (prompt CompiledPrompt) WireIdentity() string         { return prompt.digest }
func (prompt CompiledPrompt) CompleteStdinByteLength() int { return len(prompt.stdin) }
func (prompt CompiledPrompt) ExactReplay() bool            { return prompt.exactReplay }

func (prompt CompiledPrompt) ReplayedSourceInvocationID() (SourceInvocationID, bool) {
	if !prompt.exactReplay {
		return SourceInvocationID{}, false
	}
	return prompt.replayedSourceInvoked, true
}

func (prompt CompiledPrompt) Sections() []FramedSection { return cloneSections(prompt.sections) }

// Validate verifies the exact stdin bytes, all frame constraints, stored
// section metadata, hash, scope, and replay marker.
func (prompt CompiledPrompt) Validate() error {
	if err := prompt.template.validate(); err != nil {
		return fmt.Errorf("prompt: invalid trusted template: %w", err)
	}
	if err := prompt.scope.validate(); err != nil {
		return fmt.Errorf("prompt: invalid scope: %w", err)
	}
	if prompt.digest != CompleteStdinSHA256(prompt.stdin) {
		return fmt.Errorf("prompt: complete stdin SHA-256 does not match bytes")
	}
	parsed, err := ParseStdin(prompt.template, prompt.stdin)
	if err != nil {
		return fmt.Errorf("prompt: invalid stdin: %w", err)
	}
	if !parsed.scope.equal(prompt.scope.FrameScope()) {
		return fmt.Errorf("prompt: stdin frame scope does not match prompt scope")
	}
	if !sectionsEqual(parsed.sections, prompt.sections) {
		return fmt.Errorf("prompt: stdin sections do not match prompt metadata")
	}
	if prompt.exactReplay {
		if prompt.replayedSourceInvoked != prompt.scope.SourceInvocationID() {
			return fmt.Errorf("prompt: replay source invocation id does not match scope")
		}
	} else if prompt.replayedSourceInvoked.String() != "" {
		return fmt.Errorf("prompt: non-replay packet has replay metadata")
	}
	return nil
}

// ParsedPrompt is the result of parsing a complete stdin byte stream before a
// provider process is started. It has no execution identity because execution
// identity is outside of the SOT frame grammar.
type ParsedPrompt struct {
	scope    FrameScope
	stdin    []byte
	sections []FramedSection
	digest   string
}

func (parsed ParsedPrompt) Scope() FrameScope            { return parsed.scope }
func (parsed ParsedPrompt) Stdin() []byte                { return cloneBytes(parsed.stdin) }
func (parsed ParsedPrompt) Sections() []FramedSection    { return cloneSections(parsed.sections) }
func (parsed ParsedPrompt) CompleteStdinSHA256() string  { return parsed.digest }
func (parsed ParsedPrompt) WireIdentity() string         { return parsed.digest }
func (parsed ParsedPrompt) CompleteStdinByteLength() int { return len(parsed.stdin) }

// ParseStdin accepts only a complete, canonical SOT section-12/13 packet. It
// rejects malformed headers, bad lengths or hashes, scope divergence, missing
// review targets, wrong order, truncation, and any trailing byte.
func ParseStdin(template TrustedTemplate, stdin []byte) (ParsedPrompt, error) {
	if err := template.validate(); err != nil {
		return ParsedPrompt{}, fmt.Errorf("prompt parser: invalid trusted template: %w", err)
	}
	if len(stdin) < len(template.bytes)+len(framesPreamble)+len(framesEnd) {
		return ParsedPrompt{}, fmt.Errorf("prompt parser: stdin is truncated")
	}
	if !bytes.HasPrefix(stdin, template.bytes) {
		return ParsedPrompt{}, fmt.Errorf("prompt parser: stdin does not start with trusted template bytes")
	}
	offset := len(template.bytes)
	if !bytes.HasPrefix(stdin[offset:], []byte(framesPreamble)) {
		return ParsedPrompt{}, fmt.Errorf("prompt parser: KAR-FRAMES sentinel is missing")
	}
	offset += len(framesPreamble)

	sections := make([]FramedSection, 0, 1)
	var scope FrameScope
	hasScope := false
	for {
		if bytes.HasPrefix(stdin[offset:], []byte(framesEnd)) {
			offset += len(framesEnd)
			break
		}
		if offset == len(stdin) {
			return ParsedPrompt{}, fmt.Errorf("prompt parser: KAR-FRAMES-END sentinel is missing")
		}
		section, next, err := parseFrame(stdin, offset)
		if err != nil {
			return ParsedPrompt{}, err
		}
		if !hasScope {
			scope = section.scope
			hasScope = true
		} else if !scope.equal(section.scope) {
			return ParsedPrompt{}, fmt.Errorf("prompt parser: frame scope does not match preceding frames")
		}
		sections = append(sections, section)
		offset = next
	}
	if offset != len(stdin) {
		return ParsedPrompt{}, fmt.Errorf("prompt parser: trailing bytes after KAR-FRAMES-END sentinel")
	}
	if err := validateSections(sections); err != nil {
		return ParsedPrompt{}, fmt.Errorf("prompt parser: %w", err)
	}
	return ParsedPrompt{
		scope:    scope,
		stdin:    cloneBytes(stdin),
		sections: cloneSections(sections),
		digest:   CompleteStdinSHA256(stdin),
	}, nil
}

func parseFrame(stdin []byte, offset int) (FramedSection, int, error) {
	start := offset
	line, next, err := readASCIIHeader(stdin, offset)
	if err != nil {
		return FramedSection{}, 0, fmt.Errorf("prompt parser: frame preamble: %w", err)
	}
	if line != strings.TrimSuffix(framePreamble, "\n") {
		return FramedSection{}, 0, fmt.Errorf("prompt parser: frame preamble is malformed")
	}
	offset = next

	scopeLine, next, err := readASCIIHeader(stdin, offset)
	if err != nil {
		return FramedSection{}, 0, fmt.Errorf("prompt parser: frame scope: %w", err)
	}
	scopeValue, ok := strings.CutPrefix(scopeLine, "scope:")
	if !ok {
		return FramedSection{}, 0, fmt.Errorf("prompt parser: scope header is malformed")
	}
	scope, err := parseFrameScope(scopeValue)
	if err != nil {
		return FramedSection{}, 0, fmt.Errorf("prompt parser: scope header: %w", err)
	}
	offset = next

	idLine, next, err := readASCIIHeader(stdin, offset)
	if err != nil {
		return FramedSection{}, 0, fmt.Errorf("prompt parser: section id: %w", err)
	}
	sectionID, ok := strings.CutPrefix(idLine, "section-id:")
	if !ok || !isLowerHexString(sectionID, sectionIDHexLength) {
		return FramedSection{}, 0, fmt.Errorf("prompt parser: section-id header is malformed")
	}
	offset = next

	kindLine, next, err := readASCIIHeader(stdin, offset)
	if err != nil {
		return FramedSection{}, 0, fmt.Errorf("prompt parser: section kind: %w", err)
	}
	kindValue, ok := strings.CutPrefix(kindLine, "kind:")
	kind := SectionKind(kindValue)
	if !ok || !kind.Valid() {
		return FramedSection{}, 0, fmt.Errorf("prompt parser: kind header is malformed")
	}
	offset = next

	lengthLine, next, err := readASCIIHeader(stdin, offset)
	if err != nil {
		return FramedSection{}, 0, fmt.Errorf("prompt parser: section length: %w", err)
	}
	lengthValue, ok := strings.CutPrefix(lengthLine, "length:")
	if !ok {
		return FramedSection{}, 0, fmt.Errorf("prompt parser: length header is malformed")
	}
	length, err := parseCanonicalDecimal(lengthValue)
	if err != nil {
		return FramedSection{}, 0, fmt.Errorf("prompt parser: length header: %w", err)
	}
	offset = next

	digestLine, next, err := readASCIIHeader(stdin, offset)
	if err != nil {
		return FramedSection{}, 0, fmt.Errorf("prompt parser: section SHA-256: %w", err)
	}
	payloadDigest, ok := strings.CutPrefix(digestLine, "sha256:")
	if !ok || !isLowerHexString(payloadDigest, sha256HexLength) {
		return FramedSection{}, 0, fmt.Errorf("prompt parser: sha256 header is malformed")
	}
	offset = next

	separator, next, err := readASCIIHeader(stdin, offset)
	if err != nil {
		return FramedSection{}, 0, fmt.Errorf("prompt parser: payload separator: %w", err)
	}
	if separator != "" {
		return FramedSection{}, 0, fmt.Errorf("prompt parser: payload separator is malformed")
	}
	offset = next
	remaining := len(stdin) - offset
	if length > uint64(remaining) {
		return FramedSection{}, 0, fmt.Errorf("prompt parser: payload is truncated")
	}
	payloadEnd := offset + int(length)
	payload := cloneBytes(stdin[offset:payloadEnd])
	offset = payloadEnd
	if offset == len(stdin) || stdin[offset] != '\n' {
		return FramedSection{}, 0, fmt.Errorf("prompt parser: payload terminator is missing")
	}
	offset++

	endLine, next, err := readASCIIHeader(stdin, offset)
	if err != nil {
		return FramedSection{}, 0, fmt.Errorf("prompt parser: frame end: %w", err)
	}
	if endLine != "KAR-END/"+sectionID {
		return FramedSection{}, 0, fmt.Errorf("prompt parser: frame end id does not match section-id")
	}
	offset = next
	if payloadSHA256(payload) != payloadDigest {
		return FramedSection{}, 0, fmt.Errorf("prompt parser: payload SHA-256 does not match bytes")
	}
	return FramedSection{
		scope:         scope,
		id:            sectionID,
		kind:          kind,
		payload:       payload,
		payloadSHA256: payloadDigest,
		frame:         cloneBytes(stdin[start:offset]),
	}, offset, nil
}

func validateSections(sections []FramedSection) error {
	if len(sections) == 0 {
		return fmt.Errorf("must contain exactly one review_target frame")
	}
	seen := make(map[SectionKind]bool, 5)
	previousRank := -1
	var expectedScope FrameScope
	for index, section := range sections {
		if err := section.scope.validate(); err != nil {
			return fmt.Errorf("section %d: invalid scope: %w", index+1, err)
		}
		if index == 0 {
			expectedScope = section.scope
		} else if !expectedScope.equal(section.scope) {
			return fmt.Errorf("section %d: scope does not match preceding frames", index+1)
		}
		if !section.kind.Valid() {
			return fmt.Errorf("section %d: invalid kind %q", index+1, section.kind)
		}
		if !isLowerHexString(section.id, sectionIDHexLength) {
			return fmt.Errorf("section %d: invalid section id", index+1)
		}
		if section.payloadSHA256 != payloadSHA256(section.payload) {
			return fmt.Errorf("section %d: payload SHA-256 does not match bytes", index+1)
		}
		expectedSectionID := deriveSectionID(section.scope.SourceInvocationID(), uint64(index+1), section.kind, section.payload)
		if section.id != expectedSectionID {
			return fmt.Errorf("section %d: section id is not derived from its source invocation, ordinal, kind, and payload", index+1)
		}
		if section.kind == SectionReviewTarget && len(section.payload) > MaxReviewTargetBytes {
			return fmt.Errorf("section %d: review target exceeds %d bytes", index+1, MaxReviewTargetBytes)
		}
		if !bytes.Equal(section.frame, makeFrame(section.scope, section.id, section.kind, section.payload).frame) {
			return fmt.Errorf("section %d: frame bytes are not canonical", index+1)
		}
		rank, singleton := sectionOrder(section.kind)
		if rank < previousRank {
			return fmt.Errorf("section %d: kind %q is out of order", index+1, section.kind)
		}
		if singleton && seen[section.kind] {
			return fmt.Errorf("section %d: kind %q may occur only once", index+1, section.kind)
		}
		seen[section.kind] = true
		previousRank = rank
	}
	if !seen[SectionReviewTarget] {
		return fmt.Errorf("must contain exactly one review_target frame")
	}
	return nil
}

func sectionOrder(kind SectionKind) (rank int, singleton bool) {
	switch kind {
	case SectionProjectContext:
		return 0, true
	case SectionReviewTarget:
		return 1, true
	case SectionPriorProviderOutput:
		return 2, true
	case SectionPriorFinding:
		return 3, true
	case SectionPriorReport:
		return 4, true
	case SectionExternalLog:
		return 5, false
	default:
		return -1, true
	}
}

func parseFrameScope(value string) (FrameScope, error) {
	parts := strings.Split(value, "/")
	if len(parts) != 5 {
		return FrameScope{}, fmt.Errorf("must contain session/run/role-task/attempt/source-invocation")
	}
	sessionID, err := domain.ParseSessionID(parts[0])
	if err != nil {
		return FrameScope{}, err
	}
	runID, err := domain.ParseRunID(parts[1])
	if err != nil {
		return FrameScope{}, err
	}
	roleTaskID, err := ParseRoleTaskID(parts[2])
	if err != nil {
		return FrameScope{}, err
	}
	attemptID, err := domain.ParseAttemptID(parts[3])
	if err != nil {
		return FrameScope{}, err
	}
	sourceID, err := ParseSourceInvocationID(parts[4])
	if err != nil {
		return FrameScope{}, err
	}
	coordinates, err := NewScopeCoordinates(sessionID, runID, roleTaskID, attemptID)
	if err != nil {
		return FrameScope{}, err
	}
	return NewFrameScope(coordinates, sourceID)
}

func readASCIIHeader(input []byte, offset int) (string, int, error) {
	if offset >= len(input) {
		return "", 0, fmt.Errorf("truncated header")
	}
	relativeEnd := bytes.IndexByte(input[offset:], '\n')
	if relativeEnd < 0 {
		return "", 0, fmt.Errorf("header is missing LF")
	}
	end := offset + relativeEnd
	line := input[offset:end]
	for _, value := range line {
		if value == '\r' || value > 0x7f {
			return "", 0, fmt.Errorf("header contains non-ASCII or CR byte")
		}
	}
	return string(line), end + 1, nil
}

func parseCanonicalDecimal(value string) (uint64, error) {
	if len(value) == 0 || len(value) > maximumDecimalBytes {
		return 0, fmt.Errorf("must contain 1 through %d decimal digits", maximumDecimalBytes)
	}
	if value == "0" {
		return 0, nil
	}
	if value[0] == '0' {
		return 0, fmt.Errorf("must not contain a leading zero")
	}
	var parsed uint64
	for _, digit := range []byte(value) {
		if digit < '0' || digit > '9' {
			return 0, fmt.Errorf("must contain decimal digits only")
		}
		component := uint64(digit - '0')
		if parsed > (^uint64(0)-component)/10 {
			return 0, fmt.Errorf("overflows uint64")
		}
		parsed = parsed*10 + component
	}
	return parsed, nil
}

func deriveSectionID(sourceID SourceInvocationID, ordinal uint64, kind SectionKind, payload []byte) string {
	hash := sha256.New()
	_, _ = hash.Write([]byte(sectionHashDomain))
	_, _ = hash.Write([]byte(sourceID.String()))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write([]byte(strconv.FormatUint(ordinal, 10)))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write([]byte(kind))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write(payload)
	sum := hash.Sum(nil)
	return hex.EncodeToString(sum[:sectionIDHexLength/2])
}

// CompleteStdinSHA256 returns the raw lowercase hexadecimal SOT wire identity.
func CompleteStdinSHA256(stdin []byte) string {
	hash := sha256.New()
	_, _ = hash.Write([]byte(stdinHashDomain))
	_, _ = hash.Write(stdin)
	return hex.EncodeToString(hash.Sum(nil))
}

func payloadSHA256(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func validateTemplateLabel(name, value string) error {
	if value == "" {
		return fmt.Errorf("trusted template: %s is required", name)
	}
	for _, byteValue := range []byte(value) {
		if byteValue == 0 || byteValue == '\r' || byteValue == '\n' {
			return fmt.Errorf("trusted template: %s contains a forbidden byte", name)
		}
	}
	return nil
}

func validatePrefixedUUIDv7(value, prefix string) error {
	if !strings.HasPrefix(value, prefix) {
		return fmt.Errorf("must start with %q", prefix)
	}
	return validateUUIDv7(strings.TrimPrefix(value, prefix))
}

func validateUUIDv7(value string) error {
	if len(value) != 36 {
		return fmt.Errorf("must contain 36 canonical UUID characters")
	}
	for index, byteValue := range []byte(value) {
		switch index {
		case 8, 13, 18, 23:
			if byteValue != '-' {
				return fmt.Errorf("hyphen at byte %d is missing", index)
			}
		default:
			if !isLowerHexByte(byteValue) {
				return fmt.Errorf("byte %d is not lowercase hexadecimal", index)
			}
		}
	}
	if value[14] != '7' {
		return fmt.Errorf("version nibble is not 7")
	}
	if !strings.ContainsRune("89ab", rune(value[19])) {
		return fmt.Errorf("variant nibble is not RFC 9562")
	}
	if value == "00000000-0000-7000-8000-000000000000" {
		return fmt.Errorf("zero-form UUIDv7 is not an issued identifier")
	}
	return nil
}

func isLowerHexString(value string, length int) bool {
	if len(value) != length {
		return false
	}
	for _, byteValue := range []byte(value) {
		if !isLowerHexByte(byteValue) {
			return false
		}
	}
	return true
}

func isLowerHexByte(value byte) bool {
	return value >= '0' && value <= '9' || value >= 'a' && value <= 'f'
}

func rawUUID(sourceInvocationID string) string {
	return strings.TrimPrefix(sourceInvocationID, "i_")
}

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflectValue := reflect.ValueOf(value)
	switch reflectValue.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return reflectValue.IsNil()
	default:
		return false
	}
}
func cloneTrustedTemplate(template TrustedTemplate) TrustedTemplate {
	return TrustedTemplate{
		id:      template.id,
		version: template.version,
		bytes:   cloneBytes(template.bytes),
		sha256:  template.sha256,
	}
}

func cloneSections(sections []FramedSection) []FramedSection {
	copied := make([]FramedSection, len(sections))
	for index, section := range sections {
		copied[index] = FramedSection{
			scope:         section.scope,
			id:            section.id,
			kind:          section.kind,
			payload:       cloneBytes(section.payload),
			payloadSHA256: section.payloadSHA256,
			frame:         cloneBytes(section.frame),
		}
	}
	return copied
}

func sectionsEqual(left, right []FramedSection) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if !left[index].scope.equal(right[index].scope) ||
			left[index].id != right[index].id ||
			left[index].kind != right[index].kind ||
			left[index].payloadSHA256 != right[index].payloadSHA256 ||
			!bytes.Equal(left[index].payload, right[index].payload) ||
			!bytes.Equal(left[index].frame, right[index].frame) {
			return false
		}
	}
	return true
}

func cloneBytes(value []byte) []byte {
	return append([]byte(nil), value...)
}
