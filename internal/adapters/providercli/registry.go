// Package providercli implements exact, opt-in direct CLI review providers.
package providercli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/irootkernel/kkachi-agent-review/internal/ports"
)

const (
	FamilyKimi  = "kimi"
	FamilyZcode = "zcode"
	FamilyAgy   = "agy"

	EvidencePass = "PASS"
)

// DefinitionAuthorizer decides whether one exact runtime definition candidate
// may be made runnable. Implementations must treat the candidate as the whole
// authorization subject.
type DefinitionAuthorizer interface {
	Authorize(context.Context, RuntimeDefinitionCandidate) error
}

// RuntimeDefinitionCandidate is an immutable process profile presented to the
// production authorization authority before any runnable definition exists.
type RuntimeDefinitionCandidate struct {
	family, instance, version, executable, executableSHA256 string
	concurrencyKey                                          ports.ConcurrencyKey
	profileID                                               string
	baseArgv                                                []string
	environment                                             []ports.EnvironmentVariable
	workingDirectory                                        string
	timeout                                                 time.Duration
	maxStdoutBytes, maxStderrBytes                          int64
}

// NewRuntimeDefinitionCandidate constructs an immutable authorization subject.
func NewRuntimeDefinitionCandidate(
	family, instance, version, executable, executableSHA256 string,
	concurrencyKey ports.ConcurrencyKey,
	profileID string,
	baseArgv []string,
	environment []ports.EnvironmentVariable,
	workingDirectory string,
	timeout time.Duration,
	maxStdoutBytes, maxStderrBytes int64,
) (RuntimeDefinitionCandidate, error) {
	candidate := RuntimeDefinitionCandidate{
		family: family, instance: instance, version: version, executable: executable,
		executableSHA256: executableSHA256, concurrencyKey: concurrencyKey, profileID: profileID,
		baseArgv:         append([]string(nil), baseArgv...),
		environment:      append([]ports.EnvironmentVariable(nil), environment...),
		workingDirectory: workingDirectory, timeout: timeout,
		maxStdoutBytes: maxStdoutBytes, maxStderrBytes: maxStderrBytes,
	}
	if err := candidate.validate(); err != nil {
		return RuntimeDefinitionCandidate{}, fmt.Errorf("provider runtime definition candidate: %w", err)
	}
	return candidate, nil
}

func (c RuntimeDefinitionCandidate) Family() string                       { return c.family }
func (c RuntimeDefinitionCandidate) Instance() string                     { return c.instance }
func (c RuntimeDefinitionCandidate) Version() string                      { return c.version }
func (c RuntimeDefinitionCandidate) Executable() string                   { return c.executable }
func (c RuntimeDefinitionCandidate) ExecutableSHA256() string             { return c.executableSHA256 }
func (c RuntimeDefinitionCandidate) ConcurrencyKey() ports.ConcurrencyKey { return c.concurrencyKey }
func (c RuntimeDefinitionCandidate) ProfileID() string                    { return c.profileID }
func (c RuntimeDefinitionCandidate) BaseArgv() []string                   { return append([]string(nil), c.baseArgv...) }
func (c RuntimeDefinitionCandidate) Environment() []ports.EnvironmentVariable {
	return append([]ports.EnvironmentVariable(nil), c.environment...)
}
func (c RuntimeDefinitionCandidate) WorkingDirectory() string { return c.workingDirectory }
func (c RuntimeDefinitionCandidate) Timeout() time.Duration   { return c.timeout }
func (c RuntimeDefinitionCandidate) MaxStdoutBytes() int64    { return c.maxStdoutBytes }
func (c RuntimeDefinitionCandidate) MaxStderrBytes() int64    { return c.maxStderrBytes }

func (c RuntimeDefinitionCandidate) validate() error {
	return definition{
		family: c.family, instance: c.instance, version: c.version, executable: c.executable,
		executableSHA256: c.executableSHA256, concurrencyKey: c.concurrencyKey, profileID: c.profileID,
		baseArgv: c.baseArgv, environment: c.environment, workingDirectory: c.workingDirectory,
		timeout: c.timeout, maxStdoutBytes: c.maxStdoutBytes, maxStderrBytes: c.maxStderrBytes,
		evidence: tupleEvidence{
			family: c.family, instance: c.instance, version: c.version, executableSHA256: c.executableSHA256,
			concurrencyKey: c.concurrencyKey, profileID: c.profileID, profileSHA256: profileDigest(c.baseArgv), state: EvidencePass,
		},
	}.validate()
}

func (c RuntimeDefinitionCandidate) definition() definition {
	evidence := tupleEvidence{
		family: c.family, instance: c.instance, version: c.version, executableSHA256: c.executableSHA256,
		concurrencyKey: c.concurrencyKey, profileID: c.profileID, profileSHA256: profileDigest(c.baseArgv), state: EvidencePass,
	}
	return definition{
		family: c.family, instance: c.instance, version: c.version, executable: c.executable,
		executableSHA256: c.executableSHA256, concurrencyKey: c.concurrencyKey, profileID: c.profileID,
		evidence: evidence, baseArgv: append([]string(nil), c.baseArgv...),
		environment:      append([]ports.EnvironmentVariable(nil), c.environment...),
		workingDirectory: c.workingDirectory, timeout: c.timeout,
		maxStdoutBytes: c.maxStdoutBytes, maxStderrBytes: c.maxStderrBytes,
	}
}

type tupleEvidence struct {
	family, instance, version, executableSHA256 string
	concurrencyKey                              ports.ConcurrencyKey
	profileID, profileSHA256, state             string
}

// newTupleEvidence validates PASS evidence. profileArgv is the exact base argv
// recorded by the evidence collection process and is bound by its digest.
func newTupleEvidence(
	family, instance, version, executableSHA256 string,
	concurrencyKey ports.ConcurrencyKey,
	profileID, state string,
	profileArgv []string,
) (tupleEvidence, error) {
	evidence := tupleEvidence{
		family:           family,
		instance:         instance,
		version:          version,
		executableSHA256: executableSHA256,
		concurrencyKey:   concurrencyKey,
		profileID:        profileID,
		profileSHA256:    profileDigest(profileArgv),
		state:            state,
	}
	if err := evidence.validate(); err != nil {
		return tupleEvidence{}, fmt.Errorf("provider tuple evidence: %w", err)
	}
	return evidence, nil
}

func (e tupleEvidence) validate() error {
	if !validFamily(e.family) {
		return fmt.Errorf("unsupported family")
	}
	if !validProviderInstanceID(e.instance) || e.version == "" {
		return fmt.Errorf("invalid instance or version")
	}
	if !validSHA256(e.executableSHA256) || !e.concurrencyKey.Valid() {
		return fmt.Errorf("invalid executable tuple")
	}
	if !validSafeID(e.profileID) || !validSHA256(e.profileSHA256) {
		return fmt.Errorf("invalid profile binding")
	}
	if e.state != EvidencePass {
		return fmt.Errorf("evidence state is not PASS")
	}
	return nil
}

type definition struct {
	family, instance, version, executable, executableSHA256 string
	concurrencyKey                                          ports.ConcurrencyKey
	profileID                                               string
	evidence                                                tupleEvidence
	baseArgv                                                []string
	environment                                             []ports.EnvironmentVariable
	workingDirectory                                        string
	timeout                                                 time.Duration
	maxStdoutBytes, maxStderrBytes                          int64
}

func newDefinition(
	family, instance, version, executable, executableSHA256 string,
	concurrencyKey ports.ConcurrencyKey,
	profileID string,
	evidence tupleEvidence,
	baseArgv []string,
	environment []ports.EnvironmentVariable,
	workingDirectory string,
	timeout time.Duration,
	maxStdoutBytes, maxStderrBytes int64,
) (definition, error) {
	candidateDefinition := definition{
		family:           family,
		instance:         instance,
		version:          version,
		executable:       executable,
		executableSHA256: executableSHA256,
		concurrencyKey:   concurrencyKey,
		profileID:        profileID,
		evidence:         evidence,
		baseArgv:         append([]string(nil), baseArgv...),
		environment:      append([]ports.EnvironmentVariable(nil), environment...),
		workingDirectory: workingDirectory,
		timeout:          timeout,
		maxStdoutBytes:   maxStdoutBytes,
		maxStderrBytes:   maxStderrBytes,
	}
	if err := candidateDefinition.validate(); err != nil {
		return definition{}, fmt.Errorf("provider definition: %w", err)
	}
	return candidateDefinition, nil
}

func (d definition) validate() error {
	if !validFamily(d.family) {
		return fmt.Errorf("unsupported family")
	}
	if !validProviderInstanceID(d.instance) || d.version == "" || !validSafeID(d.profileID) {
		return fmt.Errorf("invalid identity")
	}
	if !validCanonicalAbsolute(d.executable) || !validSHA256(d.executableSHA256) {
		return fmt.Errorf("invalid executable")
	}
	if !d.concurrencyKey.Valid() || !validCanonicalAbsolute(d.workingDirectory) {
		return fmt.Errorf("invalid process location")
	}
	if d.timeout <= 0 || d.maxStdoutBytes <= 0 || d.maxStderrBytes <= 0 {
		return fmt.Errorf("invalid process limits")
	}
	if len(d.baseArgv) == 0 || d.baseArgv[0] != d.executable {
		return fmt.Errorf("base argv must begin with executable")
	}
	for _, argument := range d.baseArgv {
		if argument == "" || strings.IndexByte(argument, 0) >= 0 {
			return fmt.Errorf("invalid base argv")
		}
	}
	for _, variable := range d.environment {
		if !variable.Valid() {
			return fmt.Errorf("invalid environment")
		}
	}
	if _, err := ports.NewProcessRequest(d.executable, d.baseArgv, d.environment, d.workingDirectory, nil, d.timeout, d.maxStdoutBytes, d.maxStderrBytes, d.concurrencyKey); err != nil {
		return fmt.Errorf("invalid process profile: %w", err)
	}
	if err := d.evidence.validate(); err != nil {
		return err
	}
	if d.evidence.family != d.family ||
		d.evidence.instance != d.instance ||
		d.evidence.version != d.version ||
		d.evidence.executableSHA256 != d.executableSHA256 ||
		d.evidence.concurrencyKey != d.concurrencyKey ||
		d.evidence.profileID != d.profileID ||
		d.evidence.profileSHA256 != profileDigest(d.baseArgv) {
		return fmt.Errorf("evidence tuple does not match definition")
	}
	return nil
}

// Registry is an immutable, concurrent-safe opt-in set of exact provider profiles.
type Registry struct {
	runner      ports.ProcessRunner
	definitions map[string]definition
	lanes       map[ports.ConcurrencyKey]chan struct{}
}

var _ ports.ObservedReviewProvider = (*Registry)(nil)

func newRegistry(runner ports.ProcessRunner, definitions ...definition) (*Registry, error) {
	if nilRunner(runner) {
		return nil, fmt.Errorf("provider registry: nil process runner")
	}
	if len(definitions) == 0 || len(definitions) > 32 {
		return nil, fmt.Errorf("provider registry: one through 32 definitions are required")
	}
	registry := &Registry{
		runner:      runner,
		definitions: make(map[string]definition, len(definitions)),
		lanes:       make(map[ports.ConcurrencyKey]chan struct{}, len(definitions)),
	}
	for _, definition := range definitions {
		if err := definition.validate(); err != nil {
			return nil, fmt.Errorf("provider registry: %w", err)
		}
		if _, ok := registry.definitions[definition.instance]; ok {
			return nil, fmt.Errorf("provider registry: duplicate instance %q", definition.instance)
		}
		registry.definitions[definition.instance] = cloneDefinition(definition)
		if _, ok := registry.lanes[definition.concurrencyKey]; !ok {
			registry.lanes[definition.concurrencyKey] = make(chan struct{}, 1)
		}
	}
	return registry, nil
}

// NewAuthorizedRegistry is the sole production composition boundary for a
// runnable provider registry. It never executes a provider while constructing
// the registry.
func NewAuthorizedRegistry(ctx context.Context, runner ports.ProcessRunner, authorizer DefinitionAuthorizer, candidates ...RuntimeDefinitionCandidate) (*Registry, error) {
	if ctx == nil {
		return nil, fmt.Errorf("provider registry: nil context")
	}
	if nilRunner(runner) {
		return nil, fmt.Errorf("provider registry: nil process runner")
	}
	if nilDefinitionAuthorizer(authorizer) {
		return nil, fmt.Errorf("provider registry: nil definition authorizer")
	}
	if len(candidates) == 0 || len(candidates) > 32 {
		return nil, fmt.Errorf("provider registry: one through 32 candidates are required")
	}

	lastFamily := -1
	lastInstance := ""
	instances := make(map[string]struct{}, len(candidates))
	for _, candidate := range candidates {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("provider registry: authorization context: %w", err)
		}
		if err := candidate.validate(); err != nil {
			return nil, fmt.Errorf("provider registry: invalid candidate: %w", err)
		}
		if _, ok := instances[candidate.instance]; ok {
			return nil, fmt.Errorf("provider registry: duplicate instance %q", candidate.instance)
		}
		instances[candidate.instance] = struct{}{}
		familyOrder := supportedFamilyOrder(candidate.family)
		if familyOrder < lastFamily || (familyOrder == lastFamily && candidate.instance <= lastInstance) {
			return nil, fmt.Errorf("provider registry: candidates must be in canonical family and instance order")
		}
		lastFamily = familyOrder
		lastInstance = candidate.instance
	}
	definitions := make([]definition, 0, len(candidates))
	for _, candidate := range candidates {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("provider registry: authorization context: %w", err)
		}
		if err := authorizer.Authorize(ctx, cloneCandidate(candidate)); err != nil {
			return nil, fmt.Errorf("provider registry: authorize %q: %w", candidate.instance, err)
		}
		definitions = append(definitions, candidate.definition())
	}
	return newRegistry(runner, definitions...)
}

func cloneCandidate(candidate RuntimeDefinitionCandidate) RuntimeDefinitionCandidate {
	candidate.baseArgv = append([]string(nil), candidate.baseArgv...)
	candidate.environment = append([]ports.EnvironmentVariable(nil), candidate.environment...)
	return candidate
}

func (r *Registry) Observe(ctx context.Context, invocation ports.ProviderInvocation) (ports.ProviderExecutionObservation, error) {
	if r == nil || nilRunner(r.runner) {
		return ports.ProviderExecutionObservation{}, fmt.Errorf("provider registry: nil process runner")
	}
	if ctx == nil {
		return ports.ProviderExecutionObservation{}, fmt.Errorf("provider registry: nil context")
	}
	definition, ok := r.definitions[invocation.ProviderInstance()]
	if !ok {
		return ports.ProviderExecutionObservation{}, fmt.Errorf("provider registry: unregistered provider instance %q", invocation.ProviderInstance())
	}
	if err := definition.validate(); err != nil {
		return ports.ProviderExecutionObservation{}, fmt.Errorf("provider registry: invalid registered definition: %w", err)
	}
	argv := buildArgv(definition, invocation.Stdin())
	request, err := ports.NewProcessRequest(
		definition.executable,
		argv,
		definition.environment,
		definition.workingDirectory,
		invocation.Stdin(),
		definition.timeout,
		definition.maxStdoutBytes,
		definition.maxStderrBytes,
		definition.concurrencyKey,
	)
	if err != nil {
		return ports.ProviderExecutionObservation{}, fmt.Errorf("provider registry: construct process request: %w", err)
	}
	lane := r.lanes[definition.concurrencyKey]
	if lane == nil {
		return ports.ProviderExecutionObservation{}, fmt.Errorf("provider registry: missing concurrency lane")
	}
	if err := acquireLane(ctx, lane); err != nil {
		return ports.ProviderExecutionObservation{}, fmt.Errorf("provider registry: acquire concurrency lane: %w", err)
	}
	defer func() {
		<-lane
	}()
	processObservation, runErr := r.runner.Run(ctx, request)
	if runErr != nil {
		return ports.ProviderExecutionObservation{}, fmt.Errorf("provider registry: process runner: %w", runErr)
	}
	if !processObservation.Valid() {
		return ports.ProviderExecutionObservation{}, fmt.Errorf("provider registry: process runner returned invalid observation")
	}
	if processObservation.Succeeded() {
		resultBytes, isolated, parseErr := providerResult(definition.family, processObservation.Stdout())
		if parseErr != nil {
			return ports.NewFailedProviderExecutionObservation(ports.ProviderExecutionStatusArtifactFailure, invocation, processObservation, "invalid_provider_output", definition.maxStdoutBytes, definition.maxStderrBytes)
		}
		result, resultErr := ports.NewProviderResult(resultBytes, len(invocation.Stdin()), invocation.CompleteStdinSHA256())
		if resultErr != nil {
			return ports.ProviderExecutionObservation{}, fmt.Errorf("provider registry: construct provider result: %w", resultErr)
		}
		if isolated {
			return ports.NewIsolatedSuccessfulProviderExecutionObservation(invocation, result, processObservation, definition.maxStdoutBytes, definition.maxStderrBytes)
		}
		return ports.NewSuccessfulProviderExecutionObservation(invocation, result, processObservation, definition.maxStdoutBytes, definition.maxStderrBytes)
	}
	return ports.NewFailedProviderExecutionObservation(classify(processObservation), invocation, processObservation, diagnosticCode(processObservation), definition.maxStdoutBytes, definition.maxStderrBytes)
}

func buildArgv(definition definition, prompt []byte) []string {
	argv := append([]string(nil), definition.baseArgv...)
	switch definition.family {
	case FamilyKimi:
		return append(argv, "--prompt", string(prompt), "--output-format", "stream-json")
	case FamilyZcode:
		return append(argv, "--mode", "plan", "--no-color", "--prompt", string(prompt))
	case FamilyAgy:
		return append(argv, "--print", string(prompt), "--sandbox", "--mode", "plan", "--print-timeout", "2m")
	default:
		panic("validated provider family")
	}
}

func providerResult(family string, stdout []byte) ([]byte, bool, error) {
	switch family {
	case FamilyKimi:
		result, err := kimiContent(stdout)
		return result, true, err
	case FamilyZcode, FamilyAgy:
		if err := strictJSON(stdout); err != nil {
			return nil, false, err
		}
		return append([]byte(nil), stdout...), false, nil
	default:
		return nil, false, fmt.Errorf("unknown provider family")
	}
}

func strictJSON(value []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(value))
	var document json.RawMessage
	if err := decoder.Decode(&document); err != nil {
		return err
	}
	var extra json.RawMessage
	if err := decoder.Decode(&extra); err == nil {
		return fmt.Errorf("multiple JSON documents")
	} else if err != io.EOF {
		return err
	}
	return nil
}

func kimiContent(stdout []byte) ([]byte, error) {
	var content []byte
	found := false
	for _, line := range bytes.Split(stdout, []byte{'\n'}) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		var event map[string]json.RawMessage
		if err := json.Unmarshal(line, &event); err != nil {
			return nil, err
		}
		roleValue, ok := event["role"]
		if !ok {
			continue
		}
		var role string
		if err := json.Unmarshal(roleValue, &role); err != nil {
			return nil, err
		}
		if role != "assistant" {
			continue
		}
		rawContent, ok := event["content"]
		if !ok || found {
			return nil, fmt.Errorf("expected exactly one assistant content")
		}
		var value string
		if err := json.Unmarshal(rawContent, &value); err != nil {
			return nil, err
		}
		content = []byte(value)
		found = true
	}
	if !found {
		return nil, fmt.Errorf("expected exactly one assistant content")
	}
	return content, nil
}

func classify(observation ports.ProcessObservation) ports.ProviderExecutionStatus {
	switch observation.Termination() {
	case ports.ProcessTerminationTimedOut:
		return ports.ProviderExecutionStatusTimedOut
	case ports.ProcessTerminationCancelled:
		return ports.ProviderExecutionStatusCancelled
	case ports.ProcessTerminationStdoutLimit, ports.ProcessTerminationStderrLimit, ports.ProcessTerminationStdinIncomplete:
		return ports.ProviderExecutionStatusArtifactFailure
	case ports.ProcessTerminationStartUnavailable, ports.ProcessTerminationLockUnavailable:
		return ports.ProviderExecutionStatusUnavailable
	case ports.ProcessTerminationStartConfiguration, ports.ProcessTerminationLockConfiguration:
		return ports.ProviderExecutionStatusConfigurationViolation
	case ports.ProcessTerminationStartSecurity, ports.ProcessTerminationLockSecurity, ports.ProcessTerminationResidualProcessGroup:
		return ports.ProviderExecutionStatusSecurityViolation
	default:
		return ports.ProviderExecutionStatusInternalFailure
	}
}

func diagnosticCode(observation ports.ProcessObservation) string {
	switch observation.Termination() {
	case ports.ProcessTerminationTimedOut:
		return "process_timeout"
	case ports.ProcessTerminationCancelled:
		return "process_cancelled"
	case ports.ProcessTerminationStdoutLimit:
		return "stdout_limit"
	case ports.ProcessTerminationStderrLimit:
		return "stderr_limit"
	case ports.ProcessTerminationStdinIncomplete:
		return "stdin_incomplete"
	case ports.ProcessTerminationStartUnavailable, ports.ProcessTerminationLockUnavailable:
		return "process_unavailable"
	case ports.ProcessTerminationStartConfiguration, ports.ProcessTerminationLockConfiguration:
		return "process_configuration"
	case ports.ProcessTerminationStartSecurity, ports.ProcessTerminationLockSecurity, ports.ProcessTerminationResidualProcessGroup:
		return "process_security"
	default:
		return "process_internal"
	}
}

func cloneDefinition(definition definition) definition {
	definition.baseArgv = append([]string(nil), definition.baseArgv...)
	definition.environment = append([]ports.EnvironmentVariable(nil), definition.environment...)
	return definition
}

func profileDigest(argv []string) string {
	hash := sha256.New()
	for _, argument := range argv {
		_, _ = hash.Write([]byte(argument))
		_, _ = hash.Write([]byte{0})
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func validFamily(value string) bool {
	return value == FamilyKimi || value == FamilyZcode || value == FamilyAgy
}

func validCanonicalAbsolute(value string) bool {
	return value != "" && filepath.IsAbs(value) && filepath.Clean(value) == value && strings.IndexByte(value, 0) < 0
}

func validSHA256(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func validSafeID(value string) bool {
	if value == "" || len(value) > 64 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, character := range value[1:] {
		if (character >= 'a' && character <= 'z') ||
			(character >= '0' && character <= '9') ||
			character == '_' || character == '-' {
			continue
		}
		return false
	}
	return true
}

func validProviderInstanceID(value string) bool {
	if value == "" || len(value) > 64 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, character := range value[1:] {
		if (character >= 'a' && character <= 'z') ||
			(character >= '0' && character <= '9') ||
			character == '.' || character == '_' || character == '-' {
			continue
		}
		return false
	}
	return true
}

func acquireLane(ctx context.Context, lane chan struct{}) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case lane <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func nilRunner(runner ports.ProcessRunner) bool {
	if runner == nil {
		return true
	}
	value := reflect.ValueOf(runner)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}
func supportedFamilyOrder(family string) int {
	switch family {
	case FamilyKimi:
		return 0
	case FamilyZcode:
		return 1
	case FamilyAgy:
		return 2
	default:
		return -1
	}
}

func nilDefinitionAuthorizer(authorizer DefinitionAuthorizer) bool {
	if authorizer == nil {
		return true
	}
	value := reflect.ValueOf(authorizer)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}
