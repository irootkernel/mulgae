// Package providercli implements opt-in direct CLI review providers.
package providercli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

const (
	FamilyKimi  = "kimi"
	FamilyZcode = "zcode"
	FamilyAgy   = "agy"
)

var errInvalidZcodeEnvelope = errors.New("invalid ZCode headless envelope")
var errProviderOutputFrameMissing = errors.New("provider output frame missing")

type providerOutputFailure struct {
	cause domain.RuntimeDiagnosticCause
	err   error
}

func (failure *providerOutputFailure) Error() string {
	return "provider output failed: " + string(failure.cause)
}
func (failure *providerOutputFailure) Unwrap() error { return failure.err }
func (failure *providerOutputFailure) Cause() domain.RuntimeDiagnosticCause {
	return failure.cause
}

func newProviderOutputFailure(cause domain.RuntimeDiagnosticCause, err error) error {
	return &providerOutputFailure{cause: cause, err: err}
}

// RuntimeTransport is an immutable provider packet transport profile.
type RuntimeTransport struct {
	channel   ports.ProviderPacketChannel
	argvIndex int
	reference string
}

// NewRuntimeTransport constructs one explicit packet transport profile.
func NewRuntimeTransport(channel ports.ProviderPacketChannel, argvIndex int, reference string) (RuntimeTransport, error) {
	transport := RuntimeTransport{channel: channel, argvIndex: argvIndex, reference: reference}
	if err := transport.validate(); err != nil {
		return RuntimeTransport{}, fmt.Errorf("provider runtime transport: %w", err)
	}
	return transport, nil
}

func (t RuntimeTransport) Channel() ports.ProviderPacketChannel { return t.channel }
func (t RuntimeTransport) ArgvIndex() int                       { return t.argvIndex }
func (t RuntimeTransport) Reference() string                    { return t.reference }

func (t RuntimeTransport) validate() error {
	switch t.channel {
	case ports.ProviderPacketChannelArgvLiteral:
		if t.argvIndex < 0 || t.reference != "" {
			return fmt.Errorf("argv-literal transport requires an argv index and no reference")
		}
	case ports.ProviderPacketChannelStdin:
		if t.argvIndex != -1 || t.reference != "" {
			return fmt.Errorf("stdin transport must not have an argv index or reference")
		}
	case ports.ProviderPacketChannelPromptFile:
		if t.argvIndex < 0 || !validPromptFileReference(t.reference) {
			return fmt.Errorf("prompt-file transport requires an argv index and valid reference")
		}
	default:
		return fmt.Errorf("unsupported packet channel")
	}
	return nil
}

// RuntimeDefinition is an immutable provider process profile.
type RuntimeDefinition struct {
	family, instance, version, executable, executableSHA256 string
	launcher, launcherSHA256, profileGeneration             string
	runtimeSafetyPolicyIdentity                             string
	kimiModel                                               string
	concurrencyKey                                          ports.ConcurrencyKey
	profileID                                               string
	baseArgv                                                []string
	transport                                               RuntimeTransport
	environment                                             []ports.EnvironmentVariable
	workingDirectory                                        string
	timeout                                                 time.Duration
	maxStdoutBytes, maxStderrBytes                          int64
	postOutputLifecycle                                     ports.BoundedPostOutputLifecycle
	hasPostOutputLifecycle                                  bool
	requiresWorkspaceAuthority                              bool
	requiresSpawnVerification                               bool
	productionExplicitTransport                             bool
}

// NewRuntimeDefinition constructs a supported family runtime profile using the
// argv-literal print transport of the current provider families.
func NewRuntimeDefinition(
	family, instance, version, executable, executableSHA256 string,
	concurrencyKey ports.ConcurrencyKey,
	profileID string,
	baseArgv []string,
	environment []ports.EnvironmentVariable,
	workingDirectory string,
	timeout time.Duration,
	maxStdoutBytes, maxStderrBytes int64,
) (RuntimeDefinition, error) {
	transport, err := defaultRuntimeTransport(family, len(baseArgv))
	if err != nil {
		return RuntimeDefinition{}, err
	}
	return NewRuntimeDefinitionWithTransport(
		family, instance, version, executable, executableSHA256, concurrencyKey, profileID,
		baseArgv, transport, environment, workingDirectory, timeout, maxStdoutBytes, maxStderrBytes,
	)
}

// NewRuntimeDefinitionWithTransport constructs a supported family runtime
// profile with one explicit, immutable provider packet transport.
func NewRuntimeDefinitionWithTransport(
	family, instance, version, executable, executableSHA256 string,
	concurrencyKey ports.ConcurrencyKey,
	profileID string,
	baseArgv []string,
	transport RuntimeTransport,
	environment []ports.EnvironmentVariable,
	workingDirectory string,
	timeout time.Duration,
	maxStdoutBytes, maxStderrBytes int64,
) (RuntimeDefinition, error) {
	definition := RuntimeDefinition{
		family: family, instance: instance, version: version, executable: executable,
		executableSHA256: executableSHA256, concurrencyKey: concurrencyKey, profileID: profileID,
		baseArgv:         append([]string(nil), baseArgv...),
		transport:        transport,
		environment:      append([]ports.EnvironmentVariable(nil), environment...),
		workingDirectory: workingDirectory, timeout: timeout,
		maxStdoutBytes: maxStdoutBytes, maxStderrBytes: maxStderrBytes,
	}
	if err := definition.validate(); err != nil {
		return RuntimeDefinition{}, fmt.Errorf("provider runtime definition: %w", err)
	}
	return definition, nil
}

// NewProductionRuntimeDefinition constructs a profile that requires an
// invocation-bound workspace authority at execution time.
func NewProductionRuntimeDefinition(
	family, instance, version, executable, executableSHA256 string,
	concurrencyKey ports.ConcurrencyKey,
	profileID string,
	baseArgv []string,
	environment []ports.EnvironmentVariable,
	workingDirectory string,
	timeout time.Duration,
	maxStdoutBytes, maxStderrBytes int64,
) (RuntimeDefinition, error) {
	definition, err := NewRuntimeDefinition(
		family, instance, version, executable, executableSHA256, concurrencyKey, profileID,
		baseArgv, environment, workingDirectory, timeout, maxStdoutBytes, maxStderrBytes,
	)
	if err != nil {
		return RuntimeDefinition{}, err
	}
	definition.requiresWorkspaceAuthority = true
	return definition, nil
}

// NewProductionRuntimeDefinitionWithTransport constructs a production-only
// profile. It requires explicit packet transport, descriptor identities for both
// executable and launcher, and a profile generation.
func NewProductionRuntimeDefinitionWithTransport(
	family, instance, version, executable, executableSHA256, launcher, launcherSHA256 string,
	concurrencyKey ports.ConcurrencyKey, profileID, profileGeneration string, baseArgv []string,
	transport RuntimeTransport, environment []ports.EnvironmentVariable, workingDirectory string,
	timeout time.Duration, maxStdoutBytes, maxStderrBytes int64,
) (RuntimeDefinition, error) {
	definition, err := NewRuntimeDefinitionWithTransport(
		family, instance, version, executable, executableSHA256, concurrencyKey, profileID,
		baseArgv, transport, environment, workingDirectory, timeout, maxStdoutBytes, maxStderrBytes,
	)
	if err != nil {
		return RuntimeDefinition{}, err
	}
	definition.launcher = launcher
	definition.launcherSHA256 = launcherSHA256
	definition.profileGeneration = profileGeneration
	definition.requiresWorkspaceAuthority = true
	definition.requiresSpawnVerification = true
	definition.productionExplicitTransport = true
	if err := definition.validate(); err != nil {
		return RuntimeDefinition{}, fmt.Errorf("provider runtime definition: %w", err)
	}
	return definition, nil
}

// NewProductionRuntimeDefinitionWithTransportAndSafetyPolicy constructs a
// production profile bound to one immutable runtime safety policy identity.
func NewProductionRuntimeDefinitionWithTransportAndSafetyPolicy(
	family, instance, version, executable, executableSHA256, launcher, launcherSHA256 string,
	concurrencyKey ports.ConcurrencyKey, profileID, profileGeneration, runtimeSafetyPolicyIdentity string,
	baseArgv []string, transport RuntimeTransport, environment []ports.EnvironmentVariable,
	workingDirectory string, timeout time.Duration, maxStdoutBytes, maxStderrBytes int64,
) (RuntimeDefinition, error) {
	if runtimeSafetyPolicyIdentity == "" {
		return RuntimeDefinition{}, fmt.Errorf("provider runtime definition: runtime safety policy identity is required")
	}
	definition, err := NewProductionRuntimeDefinitionWithTransport(
		family, instance, version, executable, executableSHA256, launcher, launcherSHA256,
		concurrencyKey, profileID, profileGeneration, baseArgv, transport, environment,
		workingDirectory, timeout, maxStdoutBytes, maxStderrBytes,
	)
	if err != nil {
		return RuntimeDefinition{}, err
	}
	definition.runtimeSafetyPolicyIdentity = runtimeSafetyPolicyIdentity
	return definition, nil
}

// NewProductionKimiRuntimeDefinitionWithTransportAndSafetyPolicy binds the
// operator-admitted Kimi model without placing Mulgae-only metadata in provider
// argv.
func NewProductionKimiRuntimeDefinitionWithTransportAndSafetyPolicy(
	family, instance, version, executable, executableSHA256, launcher, launcherSHA256 string,
	concurrencyKey ports.ConcurrencyKey, profileID, profileGeneration, runtimeSafetyPolicyIdentity, kimiModel string,
	baseArgv []string, transport RuntimeTransport, environment []ports.EnvironmentVariable,
	workingDirectory string, timeout time.Duration, maxStdoutBytes, maxStderrBytes int64,
) (RuntimeDefinition, error) {
	definition, err := NewProductionRuntimeDefinitionWithTransportAndSafetyPolicy(
		family, instance, version, executable, executableSHA256, launcher, launcherSHA256,
		concurrencyKey, profileID, profileGeneration, runtimeSafetyPolicyIdentity, baseArgv,
		transport, environment, workingDirectory, timeout, maxStdoutBytes, maxStderrBytes,
	)
	if err != nil {
		return RuntimeDefinition{}, err
	}
	if family != FamilyKimi || kimiModel == "" || strings.IndexByte(kimiModel, 0) >= 0 {
		return RuntimeDefinition{}, fmt.Errorf("provider runtime definition: invalid Kimi model")
	}
	definition.kimiModel = kimiModel
	if err := definition.validate(); err != nil {
		return RuntimeDefinition{}, fmt.Errorf("provider runtime definition: %w", err)
	}
	return definition, nil
}

// NewProductionRuntimeDefinitionWithTransportAndSafetyPolicyAndPostOutputLifecycle
// constructs the AGY production profile with an explicit transport, immutable
// runtime safety policy identity, and bounded post-output lifecycle.
func NewProductionRuntimeDefinitionWithTransportAndSafetyPolicyAndPostOutputLifecycle(
	family, instance, version, executable, executableSHA256, launcher, launcherSHA256 string,
	concurrencyKey ports.ConcurrencyKey, profileID, profileGeneration, runtimeSafetyPolicyIdentity string,
	baseArgv []string, transport RuntimeTransport, lifecycle ports.BoundedPostOutputLifecycle,
	environment []ports.EnvironmentVariable, workingDirectory string, timeout time.Duration,
	maxStdoutBytes, maxStderrBytes int64,
) (RuntimeDefinition, error) {
	definition, err := NewProductionRuntimeDefinitionWithTransportAndSafetyPolicy(
		family, instance, version, executable, executableSHA256, launcher, launcherSHA256,
		concurrencyKey, profileID, profileGeneration, runtimeSafetyPolicyIdentity, baseArgv, transport,
		environment, workingDirectory, timeout, maxStdoutBytes, maxStderrBytes,
	)
	if err != nil {
		return RuntimeDefinition{}, err
	}
	definition.postOutputLifecycle = lifecycle
	definition.hasPostOutputLifecycle = true
	if err := definition.validate(); err != nil {
		return RuntimeDefinition{}, fmt.Errorf("provider runtime definition: %w", err)
	}
	return definition, nil
}

// NewRuntimeDefinitionWithTransportAndPostOutputLifecycle enables the bounded
// strict-JSON lifecycle for AGY only.
func NewRuntimeDefinitionWithTransportAndPostOutputLifecycle(
	family, instance, version, executable, executableSHA256 string,
	concurrencyKey ports.ConcurrencyKey, profileID string, baseArgv []string,
	transport RuntimeTransport, lifecycle ports.BoundedPostOutputLifecycle,
	environment []ports.EnvironmentVariable, workingDirectory string, timeout time.Duration,
	maxStdoutBytes, maxStderrBytes int64,
) (RuntimeDefinition, error) {
	definition, err := NewRuntimeDefinitionWithTransport(
		family, instance, version, executable, executableSHA256, concurrencyKey, profileID,
		baseArgv, transport, environment, workingDirectory, timeout, maxStdoutBytes, maxStderrBytes,
	)
	if err != nil {
		return RuntimeDefinition{}, err
	}
	definition.postOutputLifecycle = lifecycle
	definition.hasPostOutputLifecycle = true
	if err := definition.validate(); err != nil {
		return RuntimeDefinition{}, fmt.Errorf("provider runtime definition: %w", err)
	}
	return definition, nil
}

func (d RuntimeDefinition) Family() string                       { return d.family }
func (d RuntimeDefinition) Instance() string                     { return d.instance }
func (d RuntimeDefinition) Version() string                      { return d.version }
func (d RuntimeDefinition) Executable() string                   { return d.executable }
func (d RuntimeDefinition) ExecutableSHA256() string             { return d.executableSHA256 }
func (d RuntimeDefinition) ConcurrencyKey() ports.ConcurrencyKey { return d.concurrencyKey }
func (d RuntimeDefinition) ProfileID() string                    { return d.profileID }
func (d RuntimeDefinition) Launcher() string                     { return d.launcher }
func (d RuntimeDefinition) LauncherSHA256() string               { return d.launcherSHA256 }
func (d RuntimeDefinition) ProfileGeneration() string            { return d.profileGeneration }
func (d RuntimeDefinition) RuntimeSafetyPolicyIdentity() string {
	return d.runtimeSafetyPolicyIdentity
}
func (d RuntimeDefinition) KimiModel() string           { return d.kimiModel }
func (d RuntimeDefinition) Transport() RuntimeTransport { return d.transport }
func (d RuntimeDefinition) BaseArgv() []string          { return append([]string(nil), d.baseArgv...) }
func (d RuntimeDefinition) Environment() []ports.EnvironmentVariable {
	return append([]ports.EnvironmentVariable(nil), d.environment...)
}
func (d RuntimeDefinition) WorkingDirectory() string { return d.workingDirectory }
func (d RuntimeDefinition) Timeout() time.Duration   { return d.timeout }
func (d RuntimeDefinition) MaxStdoutBytes() int64    { return d.maxStdoutBytes }
func (d RuntimeDefinition) MaxStderrBytes() int64    { return d.maxStderrBytes }
func (d RuntimeDefinition) PostOutputLifecycle() (ports.BoundedPostOutputLifecycle, bool) {
	if !d.hasPostOutputLifecycle {
		return ports.BoundedPostOutputLifecycle{}, false
	}
	return d.postOutputLifecycle, true
}
func (d RuntimeDefinition) TransportChannel() ports.ProviderPacketChannel {
	return d.transport.Channel()
}
func (d RuntimeDefinition) TransportArgvIndex() int    { return d.transport.ArgvIndex() }
func (d RuntimeDefinition) TransportReference() string { return d.transport.Reference() }

func (d RuntimeDefinition) validate() error {
	if !validFamily(d.family) {
		return fmt.Errorf("unsupported family")
	}
	if !validProviderInstanceID(d.instance) {
		return fmt.Errorf("invalid identity")
	}
	if !validCanonicalAbsolute(d.executable) {
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
	if err := d.transport.validate(); err != nil {
		return fmt.Errorf("invalid runtime transport: %w", err)
	}
	if err := validateRuntimeTransportShape(d.family, d.baseArgv, d.transport); err != nil {
		return err
	}
	for _, variable := range d.environment {
		if !variable.Valid() {
			return fmt.Errorf("invalid environment")
		}
	}
	if _, err := ports.NewProcessRequest(d.executable, d.baseArgv, d.environment, d.workingDirectory, nil, d.timeout, d.maxStdoutBytes, d.maxStderrBytes, d.concurrencyKey); err != nil {
		return fmt.Errorf("invalid process profile: %w", err)
	}
	if d.requiresSpawnVerification {
		if d.executableSHA256 == "" || !validCanonicalAbsolute(d.launcher) || d.launcherSHA256 == "" || d.profileGeneration == "" {
			return fmt.Errorf("production identity is incomplete")
		}
		if d.family == FamilyZcode {
			if len(d.baseArgv) < 2 || d.baseArgv[1] != d.launcher {
				return fmt.Errorf("zcode base argv must contain launcher")
			}
		} else if d.launcher != d.executable || d.launcherSHA256 != d.executableSHA256 {
			return fmt.Errorf("direct launcher identity must equal executable identity")
		}
	}
	if d.hasPostOutputLifecycle {
		if d.family != FamilyAgy || !d.postOutputLifecycle.Valid() {
			return fmt.Errorf("post-output lifecycle is supported only by AGY")
		}
	} else if d.postOutputLifecycle.Valid() {
		return fmt.Errorf("post-output lifecycle present without marker")
	}
	if d.family != FamilyKimi && d.kimiModel != "" {
		return fmt.Errorf("Kimi model is bound to another family")
	}
	return nil
}

type definition RuntimeDefinition

func (d definition) validate() error {
	return RuntimeDefinition(d).validate()
}

func (d definition) postOutputPolicy() (ports.BoundedPostOutputLifecycle, bool) {
	return RuntimeDefinition(d).PostOutputLifecycle()
}

// SpawnVerifier revalidates current executable and launcher descriptor identities
// immediately before a provider process is spawned.
type SpawnVerifier interface {
	VerifyProviderSpawn(context.Context, RuntimeDefinition) error
}

// QualificationNamespace is the non-draining, non-credential authority for the
// exact namespace lease retained by a Registry.
type retainedQualificationNamespace struct {
	lease ports.ProviderNamespaceLease
}

type namespaceRuntimeSafetyPolicyIdentity interface {
	RuntimeSafetyPolicyIdentity() string
}

type nativeHomeLaunchAuthorityLease interface {
	NativeHomeLaunchAuthority() (ports.NativeHomeLaunchAuthority, bool)
}

func (namespace retainedQualificationNamespace) ProviderInstance() string {
	return namespace.lease.ProviderInstance()
}

func (namespace retainedQualificationNamespace) Generation() string {
	return namespace.lease.Generation()
}

func (namespace retainedQualificationNamespace) Environment() []ports.EnvironmentVariable {
	return namespace.lease.Environment()
}

func (namespace retainedQualificationNamespace) RuntimeSafetyPolicyIdentity() string {
	lease, ok := namespace.lease.(namespaceRuntimeSafetyPolicyIdentity)
	if !ok {
		return ""
	}
	return lease.RuntimeSafetyPolicyIdentity()
}

func (namespace retainedQualificationNamespace) NativeHomeLaunchAuthority() (ports.NativeHomeLaunchAuthority, bool) {
	lease, ok := namespace.lease.(nativeHomeLaunchAuthorityLease)
	if !ok {
		return ports.NativeHomeLaunchAuthority{}, false
	}
	return lease.NativeHomeLaunchAuthority()
}

func (namespace retainedQualificationNamespace) ValidateForSpawn() error {
	return namespace.lease.ValidateForSpawn()
}

// Registry is an immutable, concurrent-safe opt-in set of provider capability profiles.
type Registry struct {
	runner               ports.ProcessRunner
	definitions          map[string]definition
	namespaces           map[string]ports.ProviderNamespaceLease
	namespaceGenerations map[string]string
	namespaceReceipts    map[string]ports.ProviderNamespaceTerminalReceipt
	activeInstances      map[string]struct{}
	spawnVerifier        SpawnVerifier

	stateMu    sync.Mutex
	closed     bool
	active     int
	activeZero chan struct{}
	closeMu    chan struct{}
	receipt    ports.ProviderRunTerminalReceipt
}

var _ ports.ObservedReviewProvider = (*Registry)(nil)
var _ ports.ProviderOutputStagingLocator = (*Registry)(nil)

// RegistryConstructionError retains a registry whose namespace cleanup failed
// during construction. The retained registry must be closed with a fresh,
// bounded context before its terminal receipts can be used.
type RegistryConstructionError struct {
	cause    error
	registry *Registry
}

func (err *RegistryConstructionError) Error() string { return err.cause.Error() }
func (err *RegistryConstructionError) Unwrap() error { return err.cause }

func registryConstructionError(cause, cleanupErr error, registry *Registry) error {
	if cleanupErr == nil {
		return cause
	}
	return &RegistryConstructionError{cause: errors.Join(cause, cleanupErr), registry: registry}
}

// RegistryFromConstructionError returns the retryable cleanup owner retained by
// a failed registry construction.
func RegistryFromConstructionError(err error) (*Registry, bool) {
	var construction *RegistryConstructionError
	if !errors.As(err, &construction) || construction.registry == nil {
		return nil, false
	}
	return construction.registry, true
}

func newRegistry(ctx context.Context, runner ports.ProcessRunner, definitions ...definition) (*Registry, error) {
	factory, err := newEphemeralNamespaceFactory()
	if err != nil {
		return nil, err
	}
	return newRegistryWithNamespaces(ctx, runner, factory, definitions...)
}

func newRegistryWithNamespaces(
	ctx context.Context, runner ports.ProcessRunner, factory ports.ProviderNamespaceFactory, definitions ...definition,
) (*Registry, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, fmt.Errorf("provider registry: invalid construction context")
	}
	if nilRunner(runner) {
		return nil, fmt.Errorf("provider registry: nil process runner")
	}
	if nilProviderNamespaceFactory(factory) {
		return nil, fmt.Errorf("provider registry: nil namespace factory")
	}
	if len(definitions) == 0 || len(definitions) > 32 {
		return nil, fmt.Errorf("provider registry: one through 32 definitions are required")
	}
	activeZero := make(chan struct{})
	close(activeZero)
	registry := &Registry{
		runner:               runner,
		definitions:          make(map[string]definition, len(definitions)),
		namespaces:           make(map[string]ports.ProviderNamespaceLease, len(definitions)),
		namespaceGenerations: make(map[string]string, len(definitions)),
		namespaceReceipts:    make(map[string]ports.ProviderNamespaceTerminalReceipt, len(definitions)),
		activeInstances:      make(map[string]struct{}, len(definitions)),
		activeZero:           activeZero,
		closeMu:              make(chan struct{}, 1),
	}
	for _, definition := range definitions {
		if err := definition.validate(); err != nil {
			cause := fmt.Errorf("provider registry: %w", err)
			return nil, registryConstructionError(cause, registry.drainNamespacesError(ctx), registry)
		}
		if _, ok := registry.definitions[definition.instance]; ok {
			cause := fmt.Errorf("provider registry: duplicate instance %q", definition.instance)
			return nil, registryConstructionError(cause, registry.drainNamespacesError(ctx), registry)
		}
		namespace, err := factory.AcquireProviderNamespace(ctx, definition.instance)
		if err != nil || nilProviderNamespaceLease(namespace) ||
			namespace.ProviderInstance() != definition.instance || namespace.Generation() == "" ||
			namespace.ValidateForSpawn() != nil {
			acquireErr := fmt.Errorf("provider registry: acquire namespace for %q", definition.instance)
			if err != nil {
				acquireErr = errors.Join(acquireErr, err)
			}
			if !nilProviderNamespaceLease(namespace) {
				registry.namespaces[definition.instance] = namespace
			}
			return nil, registryConstructionError(acquireErr, registry.drainNamespacesError(ctx), registry)
		}
		registry.definitions[definition.instance] = cloneDefinition(definition)
		registry.namespaces[definition.instance] = namespace
		registry.namespaceGenerations[definition.instance] = namespace.Generation()
	}
	return registry, nil
}

// NewRegistry constructs a runnable registry from supported family runtime
// profiles. It never executes a provider while constructing the registry.
func NewRegistry(runner ports.ProcessRunner, profiles ...RuntimeDefinition) (*Registry, error) {
	return NewRegistryWithContext(context.TODO(), runner, profiles...)
}

// NewRegistryWithContext constructs a runnable registry using the caller's
// bounded construction context.
func NewRegistryWithContext(ctx context.Context, runner ports.ProcessRunner, profiles ...RuntimeDefinition) (*Registry, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, fmt.Errorf("provider registry: invalid construction context")
	}
	if nilRunner(runner) {
		return nil, fmt.Errorf("provider registry: nil process runner")
	}
	if len(profiles) == 0 || len(profiles) > 32 {
		return nil, fmt.Errorf("provider registry: one through 32 profiles are required")
	}

	lastFamily := -1
	lastInstance := ""
	instances := make(map[string]struct{}, len(profiles))
	definitions := make([]definition, 0, len(profiles))
	for _, profile := range profiles {
		if err := profile.validate(); err != nil {
			return nil, fmt.Errorf("provider registry: invalid profile: %w", err)
		}
		if profile.requiresWorkspaceAuthority {
			return nil, fmt.Errorf("provider registry: production definitions require an explicit namespace factory")
		}
		if _, ok := instances[profile.instance]; ok {
			return nil, fmt.Errorf("provider registry: duplicate instance %q", profile.instance)
		}
		instances[profile.instance] = struct{}{}
		familyOrder := supportedFamilyOrder(profile.family)
		if familyOrder < lastFamily || (familyOrder == lastFamily && profile.instance <= lastInstance) {
			return nil, fmt.Errorf("provider registry: profiles must be in canonical family and instance order")
		}
		lastFamily = familyOrder
		lastInstance = profile.instance
		definitions = append(definitions, definition(profile))
	}
	return newRegistry(ctx, runner, definitions...)
}

// NewRegistryWithNamespaceFactory constructs a registry whose production
// namespace authority is supplied by the composition root.
func NewRegistryWithNamespaceFactory(
	runner ports.ProcessRunner, factory ports.ProviderNamespaceFactory, profiles ...RuntimeDefinition,
) (*Registry, error) {
	return NewRegistryWithNamespaceFactoryContext(context.TODO(), runner, factory, profiles...)
}

// NewRegistryWithNamespaceFactoryContext constructs a registry using the
// caller's bounded context for namespace acquisition and cleanup.
func NewRegistryWithNamespaceFactoryContext(
	ctx context.Context, runner ports.ProcessRunner, factory ports.ProviderNamespaceFactory, profiles ...RuntimeDefinition,
) (*Registry, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, fmt.Errorf("provider registry: invalid construction context")
	}
	if nilRunner(runner) {
		return nil, fmt.Errorf("provider registry: nil process runner")
	}
	if nilProviderNamespaceFactory(factory) {
		return nil, fmt.Errorf("provider registry: nil namespace factory")
	}
	if len(profiles) == 0 || len(profiles) > 32 {
		return nil, fmt.Errorf("provider registry: one through 32 profiles are required")
	}
	lastFamily := -1
	lastInstance := ""
	instances := make(map[string]struct{}, len(profiles))
	definitions := make([]definition, 0, len(profiles))
	for _, profile := range profiles {
		if err := profile.validate(); err != nil {
			return nil, fmt.Errorf("provider registry: invalid profile: %w", err)
		}
		if _, ok := instances[profile.instance]; ok {
			return nil, fmt.Errorf("provider registry: duplicate instance %q", profile.instance)
		}
		instances[profile.instance] = struct{}{}
		familyOrder := supportedFamilyOrder(profile.family)
		if familyOrder < lastFamily || (familyOrder == lastFamily && profile.instance <= lastInstance) {
			return nil, fmt.Errorf("provider registry: profiles must be in canonical family and instance order")
		}
		lastFamily = familyOrder
		lastInstance = profile.instance
		definitions = append(definitions, definition(profile))
	}
	return newRegistryWithNamespaces(ctx, runner, factory, definitions...)
}

// NewProductionRegistry constructs a registry that cannot run without
// workspace authority and descriptor-bound spawn verification.
func NewProductionRegistry(
	runner ports.ProcessRunner, factory ports.ProviderNamespaceFactory, verifier SpawnVerifier,
	profiles ...RuntimeDefinition,
) (*Registry, error) {
	return NewProductionRegistryWithContext(context.TODO(), runner, factory, verifier, profiles...)
}

// NewProductionRegistryWithContext constructs a production registry using the
// caller's bounded context for namespace acquisition and cleanup.
func NewProductionRegistryWithContext(
	ctx context.Context, runner ports.ProcessRunner, factory ports.ProviderNamespaceFactory, verifier SpawnVerifier,
	profiles ...RuntimeDefinition,
) (*Registry, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, fmt.Errorf("provider registry: invalid construction context")
	}
	if nilSpawnVerifier(verifier) {
		return nil, fmt.Errorf("provider registry: nil spawn verifier")
	}
	for _, profile := range profiles {
		if !profile.requiresWorkspaceAuthority || !profile.requiresSpawnVerification || !profile.productionExplicitTransport {
			return nil, fmt.Errorf("provider registry: profile is not production-qualified")
		}
	}
	registry, err := NewRegistryWithNamespaceFactoryContext(ctx, runner, factory, profiles...)
	if err != nil {
		return nil, err
	}
	for _, profile := range profiles {
		namespace, ok := registry.namespaces[profile.instance]
		lease, hasRuntimeSafetyPolicyIdentity := namespace.(namespaceRuntimeSafetyPolicyIdentity)
		if !ok || !hasRuntimeSafetyPolicyIdentity || profile.runtimeSafetyPolicyIdentity == "" ||
			lease.RuntimeSafetyPolicyIdentity() == "" ||
			lease.RuntimeSafetyPolicyIdentity() != profile.runtimeSafetyPolicyIdentity {
			cause := fmt.Errorf("provider registry: namespace runtime safety policy identity for %q", profile.instance)
			return nil, registryConstructionError(cause, registry.drainNamespacesError(ctx), registry)
		}
	}
	registry.spawnVerifier = verifier
	return registry, nil
}

// QualificationNamespace returns a narrowed view of the exact namespace lease
// retained for instance. It never exposes credential projection or drain
// authority.
func (r *Registry) QualificationNamespace(instance string) (QualificationNamespace, bool) {
	if r == nil {
		return nil, false
	}
	r.stateMu.Lock()
	defer r.stateMu.Unlock()
	if r.closed {
		return nil, false
	}
	lease, ok := r.namespaces[instance]
	if !ok || nilProviderNamespaceLease(lease) {
		return nil, false
	}
	_, ok = r.definitions[instance]
	if !ok {
		return nil, false
	}
	return retainedQualificationNamespace{lease: lease}, true
}

// stagedOutputParentDirectoryName is the fixed scratch subdirectory that holds
// every per-invocation staging directory of one provider instance.
const stagedOutputParentDirectoryName = "output"

// familyReviewOutputTransport declares how a review invocation of family is
// expected to deliver its role report. Each grant comes from live capability
// evidence, never from preference: ZCode reliably writes one regular file at an
// absolute staging path once it runs outside plan mode with Write removed from
// the review denylist, headless AGY auto-denies write_file in safe mode
// whatever its mode, and Kimi is out of scope for provider-written output. Any
// family without positive evidence keeps the stdout transport.
func familyReviewOutputTransport(family string) ports.ProviderOutputTransport {
	if family == FamilyZcode {
		return ports.ProviderOutputTransportStagedFile
	}
	return ports.ProviderOutputTransportStdout
}

// ProviderOutputStagingDestination resolves the staged-output destination and
// declared transport of one review invocation. It is pure computation: nothing
// is created, and no filesystem state is inspected.
//
// ok reports whether the returned pair is an authoritative decision for this
// invocation. It is false for an unregistered instance, a terminally drained
// registry, a namespace that drifted or cannot name a scratch area, and any
// purpose this adapter will not stage; every refusal returns the stdout
// transport, so a caller that ignores ok still stages nothing.
//
// The destination lives inside the instance's own disposable namespace scratch
// area (MULGAE_PROVIDER_SCRATCH). The registry acquires that namespace lease at
// construction and retains it until Close, so the path is computable before any
// spawn and is removed with the namespace it belongs to.
func (r *Registry) ProviderOutputStagingDestination(
	providerInstance string, attemptID domain.AttemptID, purpose ports.ProviderInvocationPurpose,
) (ports.StagedOutputDestination, ports.ProviderOutputTransport, bool) {
	if r == nil {
		return ports.StagedOutputDestination{}, ports.ProviderOutputTransportStdout, false
	}
	r.stateMu.Lock()
	closed := r.closed
	definition, registered := r.definitions[providerInstance]
	namespace := r.namespaces[providerInstance]
	generation := r.namespaceGenerations[providerInstance]
	r.stateMu.Unlock()
	if closed || !registered || nilProviderNamespaceLease(namespace) || namespace.Generation() != generation {
		return ports.StagedOutputDestination{}, ports.ProviderOutputTransportStdout, false
	}
	ordinal, staged := stagedOutputPurposeOrdinal(purpose)
	if !staged {
		return ports.StagedOutputDestination{}, ports.ProviderOutputTransportStdout, false
	}
	transport := familyReviewOutputTransport(definition.family)
	if transport != ports.ProviderOutputTransportStagedFile {
		return ports.StagedOutputDestination{}, transport, true
	}
	directory, located := stagedOutputDirectory(namespace.Environment(), attemptID, ordinal)
	if !located {
		return ports.StagedOutputDestination{}, ports.ProviderOutputTransportStdout, false
	}
	destination, err := ports.NewStagedOutputDestination(directory, stagedOutputFilename)
	if err != nil {
		return ports.StagedOutputDestination{}, ports.ProviderOutputTransportStdout, false
	}
	return destination, transport, true
}

// stagedOutputPurposeOrdinal maps the closed review purposes this adapter may
// stage to their stable per-attempt ordinal, which keeps the initial and repair
// invocations of one attempt in distinct staging directories. Every other
// purpose is refused, an exact replay of an earlier invocation in particular:
// a replay must reproduce the transport its original recorded rather than
// acquire a fresh write grant here.
func stagedOutputPurposeOrdinal(purpose ports.ProviderInvocationPurpose) (int, bool) {
	switch purpose {
	case ports.ProviderInvocationInitial:
		return 0, true
	case ports.ProviderInvocationRepair:
		return 1, true
	default:
		return 0, false
	}
}

// stagedOutputDirectory computes the per-invocation staging directory beneath
// the namespace scratch area. The split it produces is exactly the one
// createStagedOutputDirectory consumes: parent <scratch>/output, per-invocation
// directory <attempt>-<ordinal>.
func stagedOutputDirectory(
	environment []ports.EnvironmentVariable, attemptID domain.AttemptID, ordinal int,
) (string, bool) {
	scratch := ""
	for _, variable := range environment {
		if variable.Name() == "MULGAE_PROVIDER_SCRATCH" {
			scratch = variable.Value()
			break
		}
	}
	if !validCanonicalAbsolute(scratch) || scratch == string(filepath.Separator) {
		return "", false
	}
	name := fmt.Sprintf("%s-%d", attemptID.String(), ordinal)
	if !validStagedOutputDirectoryName(name) {
		return "", false
	}
	return filepath.Join(scratch, stagedOutputParentDirectoryName, name), true
}

func (r *Registry) Observe(ctx context.Context, invocation ports.ProviderInvocation) (observation ports.ProviderExecutionObservation, err error) {
	if r == nil || nilRunner(r.runner) {
		return ports.ProviderExecutionObservation{}, providerRuntimeFailure(domain.DiagnosticCauseProviderSpawnFailed, fmt.Errorf("provider registry: nil process runner"))
	}
	if ctx == nil {
		return ports.ProviderExecutionObservation{}, fmt.Errorf("provider registry: nil context")
	}
	definition, ok := r.definitions[invocation.ProviderInstance()]
	if !ok {
		return ports.ProviderExecutionObservation{}, providerRuntimeFailure(domain.DiagnosticCauseProviderSpawnFailed, fmt.Errorf("provider registry: unregistered provider instance %q", invocation.ProviderInstance()))
	}
	r.stateMu.Lock()
	if r.closed {
		r.stateMu.Unlock()
		return ports.ProviderExecutionObservation{}, providerRuntimeFailure(domain.DiagnosticCauseProviderSpawnFailed, fmt.Errorf("provider registry: terminally drained"))
	}
	if _, active := r.activeInstances[definition.instance]; active {
		r.stateMu.Unlock()
		return ports.ProviderExecutionObservation{}, providerRuntimeFailure(domain.DiagnosticCauseObservationMismatch, fmt.Errorf("provider registry: provider instance %q is already active in this run", definition.instance))
	}
	if r.active == 0 {
		r.activeZero = make(chan struct{})
	}
	r.active++
	r.activeInstances[definition.instance] = struct{}{}
	r.stateMu.Unlock()
	defer r.observeDone(definition.instance)
	if err := definition.validate(); err != nil {
		return ports.ProviderExecutionObservation{}, providerRuntimeFailure(domain.DiagnosticCauseProviderSpawnFailed, fmt.Errorf("provider registry: invalid registered definition: %w", err))
	}
	packet := invocation.Packet()
	namespace := r.namespaces[definition.instance]
	if nilProviderNamespaceLease(namespace) || namespace.Generation() != r.namespaceGenerations[definition.instance] {
		return ports.ProviderExecutionObservation{}, providerRuntimeFailure(domain.DiagnosticCauseWorkspaceRevalidationFailed, fmt.Errorf("provider registry: namespace generation drift"))
	}
	if namespace.Generation() != r.namespaceGenerations[definition.instance] {
		return ports.ProviderExecutionObservation{}, providerRuntimeFailure(domain.DiagnosticCauseWorkspaceRevalidationFailed, fmt.Errorf("provider registry: namespace generation drift"))
	}
	if err := namespace.ValidateForSpawn(); err != nil {
		return ports.ProviderExecutionObservation{}, providerRuntimeFailure(domain.DiagnosticCauseWorkspaceRevalidationFailed, fmt.Errorf("provider registry: namespace lease validation: %w", err))
	}
	// The staging lease is acquired before the process starts and released on
	// every exit path below - success, provider failure, guard failure, timeout
	// and cancellation alike - exactly as the workspace guard is.
	staging, stagingErr := r.acquireStagedOutputLease(invocation)
	if stagingErr != nil {
		return ports.ProviderExecutionObservation{}, stagingErr
	}
	if staging != nil {
		defer func() {
			observation, err = releaseStagedOutputLease(staging, definition, invocation, observation, err)
		}()
	}

	var processObservation ports.ProcessObservation
	var runErr error
	if workspace, ok := invocation.ExecutionWorkspace(); ok {
		processObservation, runErr = r.runInWorkspace(ctx, definition, invocation, workspace, packet, namespace, namespace.Environment())
	} else {
		if definition.requiresWorkspaceAuthority {
			return ports.ProviderExecutionObservation{}, providerRuntimeFailure(domain.DiagnosticCauseProviderSpawnFailed, fmt.Errorf("provider registry: production definition requires workspace authority"))
		}
		processObservation, runErr = r.runLegacy(ctx, definition, packet, namespace.Environment())
	}
	if runErr != nil {
		cause, cleanupCause := providerRunCauses(runErr)
		status, diagnostic := providerFailureProjection(cause)
		var processFailure *ports.ProcessExecutionError
		if !errors.As(runErr, &processFailure) {
			typedErr, typedConstructErr := ports.NewProviderRuntimeError(cause, runErr)
			if typedConstructErr != nil {
				return ports.ProviderExecutionObservation{}, typedConstructErr
			}
			if !processObservation.Valid() {
				return ports.ProviderExecutionObservation{}, typedErr
			}
			observation, observationErr := ports.NewFailedProviderExecutionObservationWithCause(
				status, invocation, processObservation, diagnostic, cause, cleanupCause,
				definition.maxStdoutBytes, definition.maxStderrBytes,
			)
			if observationErr != nil {
				return ports.ProviderExecutionObservation{}, observationErr
			}
			return observation, typedErr
		}
		if processObservation.Valid() {
			return ports.NewFailedProviderExecutionObservationWithCause(
				status, invocation, processObservation, diagnostic, cause, cleanupCause,
				definition.maxStdoutBytes, definition.maxStderrBytes,
			)
		}
		return ports.NewPartialFailedProviderExecutionObservation(
			status, invocation, processFailure.Stdout(), processFailure.Stderr(), diagnostic,
			cause, cleanupCause,
			definition.maxStdoutBytes, definition.maxStderrBytes,
		)
	}
	if !processObservation.Valid() {
		return ports.ProviderExecutionObservation{}, providerRuntimeFailure(domain.DiagnosticCauseObservationInvalid, fmt.Errorf("provider registry: process runner returned invalid observation"))
	}
	if definition.family == FamilyAgy && agyPermissionDenied(processObservation.Stderr()) {
		return ports.NewFailedProviderExecutionObservationWithCause(
			ports.ProviderExecutionStatusAuthentication, invocation, processObservation,
			"provider_permission_denied", domain.DiagnosticCausePermissionDenied, "",
			definition.maxStdoutBytes, definition.maxStderrBytes,
		)
	}
	if processObservation.Succeeded() {
		if staging != nil {
			// The workspace guard has already revalidated at this point, so the
			// staged bytes are read back from a snapshot that never drifted.
			return stagedFileObservation(definition, invocation, processObservation, staging)
		}
		providerOutput, outputErr := completeProcessStdout(ctx, processObservation)
		if outputErr != nil {
			return ports.NewFailedProviderExecutionObservationWithCause(
				ports.ProviderExecutionStatusArtifactFailure, invocation, processObservation,
				"provider_output_read_failed", domain.DiagnosticCauseOutputDecodeFailed, "",
				definition.maxStdoutBytes, definition.maxStderrBytes,
			)
		}
		resultBytes, isolated, parseErr := providerResult(definition.family, providerOutput)
		if parseErr != nil {
			cause := domain.DiagnosticCauseOutputDecodeFailed
			var outputFailure *providerOutputFailure
			if errors.As(parseErr, &outputFailure) {
				cause = outputFailure.Cause()
			}
			return ports.NewFailedProviderExecutionObservationWithCause(
				ports.ProviderExecutionStatusArtifactFailure, invocation, processObservation,
				providerOutputDiagnostic(cause), cause, "",
				definition.maxStdoutBytes, definition.maxStderrBytes,
			)
		}
		result, resultErr := ports.NewProviderResultForInput(resultBytes, invocation.InputIdentity())
		if resultErr != nil {
			return ports.NewFailedProviderExecutionObservationWithCause(
				ports.ProviderExecutionStatusArtifactFailure, invocation, processObservation,
				"invalid_provider_output", domain.DiagnosticCauseResultBindingFailed, "",
				definition.maxStdoutBytes, definition.maxStderrBytes,
			)
		}
		if isolated {
			return ports.NewIsolatedSuccessfulProviderExecutionObservation(invocation, result, processObservation, definition.maxStdoutBytes, definition.maxStderrBytes)
		}
		return ports.NewSuccessfulProviderExecutionObservation(invocation, result, processObservation, definition.maxStdoutBytes, definition.maxStderrBytes)
	}
	status, diagnostic, cause := classifyProviderFailure(definition.family, processObservation)
	return ports.NewFailedProviderExecutionObservationWithCause(
		status, invocation, processObservation, diagnostic, cause, "",
		definition.maxStdoutBytes, definition.maxStderrBytes,
	)
}

func completeProcessStdout(ctx context.Context, observation ports.ProcessObservation) ([]byte, error) {
	artifact, ok := observation.StdoutArtifact()
	if !ok {
		return observation.Stdout(), nil
	}
	reader, err := artifact.Open(ctx)
	if err != nil {
		closeProviderContentArtifact(artifact)
		return nil, err
	}
	content, readErr := io.ReadAll(reader)
	closeErr := reader.Close()
	closeProviderContentArtifact(artifact)
	if readErr != nil || closeErr != nil {
		return nil, errors.Join(readErr, closeErr)
	}
	return content, nil
}

func closeProviderContentArtifact(artifact ports.ContentArtifact) {
	if lease, ok := artifact.(ports.ContentLease); ok && lease != nil {
		_ = lease.Close()
	}
}

// acquireStagedOutputLease creates the single per-invocation staging directory
// an invocation that declares the staged_file transport is allowed to use. The
// requested destination must be exactly the destination this registry computes
// for that invocation: a directory Mulgae did not choose is a staging
// violation, never a location this adapter creates on request. An invocation
// without a staged destination keeps the stdout transport and no lease.
func (r *Registry) acquireStagedOutputLease(invocation ports.ProviderInvocation) (*stagedOutputLease, error) {
	destination, declared := invocation.StagedOutputDestination()
	if !declared {
		return nil, nil
	}
	expected, transport, resolved := r.ProviderOutputStagingDestination(
		invocation.ProviderInstance(), invocation.AttemptID(), invocation.Purpose(),
	)
	if !resolved || transport != ports.ProviderOutputTransportStagedFile || expected != destination {
		return nil, providerRuntimeFailure(
			domain.DiagnosticCauseProviderOutputStagingViolation,
			fmt.Errorf("provider registry: staged output destination was not chosen by this registry"),
		)
	}
	lease, err := createStagedOutputDirectory(
		filepath.Dir(destination.Directory()), filepath.Base(destination.Directory()),
	)
	if err != nil {
		return nil, providerRuntimeFailure(
			stagedOutputCause(err), fmt.Errorf("provider registry: create staged output: %w", err),
		)
	}
	leased, leasedErr := lease.Destination()
	if leasedErr == nil && leased == destination {
		return lease, nil
	}
	failure := fmt.Errorf("provider registry: staged output lease does not name the registry destination")
	if leasedErr != nil {
		failure = errors.Join(failure, leasedErr)
	}
	if cleanupErr := lease.Cleanup(); cleanupErr != nil {
		failure = errors.Join(failure, cleanupErr)
	}
	return nil, providerRuntimeFailure(domain.DiagnosticCauseProviderOutputStagingViolation, failure)
}

// releaseStagedOutputLease removes the staging directory on every exit path. A
// cleanup that cannot prove the directory is gone overrides a provider success
// with a typed artifact failure, exactly as post-execution workspace drift
// overrides one: staging Mulgae cannot prove it removed is not a reviewable
// result. An outcome that already failed keeps its own classification, so a
// provider process failure still wins over the staging it left behind.
func releaseStagedOutputLease(
	lease *stagedOutputLease, definition definition, invocation ports.ProviderInvocation,
	observation ports.ProviderExecutionObservation, err error,
) (ports.ProviderExecutionObservation, error) {
	cleanupErr := lease.Cleanup()
	if cleanupErr == nil || err != nil || !observation.Succeeded() {
		return observation, err
	}
	cause := stagedOutputCause(cleanupErr)
	status, diagnostic := providerFailureProjection(cause)
	processObservation, ok := observation.AvailableProcessObservation()
	if !ok {
		return ports.ProviderExecutionObservation{}, providerRuntimeFailure(cause, cleanupErr)
	}
	failed, failedErr := ports.NewFailedProviderExecutionObservationWithCause(
		status, invocation, processObservation, diagnostic, cause, "",
		definition.maxStdoutBytes, definition.maxStderrBytes,
	)
	if failedErr != nil {
		return ports.ProviderExecutionObservation{}, failedErr
	}
	return failed, nil
}

// stagedFileObservation reads back the single file the provider was allowed to
// stage and binds those exact bytes as the provider result. Process stdout and
// stderr stay bounded diagnostic evidence only: a staged invocation never parses
// stdout, so empty or non-envelope stdout cannot fail it.
func stagedFileObservation(
	definition definition, invocation ports.ProviderInvocation,
	processObservation ports.ProcessObservation, lease *stagedOutputLease,
) (ports.ProviderExecutionObservation, error) {
	staged, receipt, validateErr := lease.Validate()
	if validateErr != nil {
		cause := stagedOutputCause(validateErr)
		status, diagnostic := providerFailureProjection(cause)
		return ports.NewFailedProviderExecutionObservationWithCause(
			status, invocation, processObservation, diagnostic, cause, "",
			definition.maxStdoutBytes, definition.maxStderrBytes,
		)
	}
	result, resultErr := ports.NewProviderResultForInput(staged, invocation.InputIdentity())
	if resultErr != nil {
		return ports.NewFailedProviderExecutionObservationWithCause(
			ports.ProviderExecutionStatusArtifactFailure, invocation, processObservation,
			"invalid_provider_output", domain.DiagnosticCauseResultBindingFailed, "",
			definition.maxStdoutBytes, definition.maxStderrBytes,
		)
	}
	return ports.NewStagedFileSuccessfulProviderExecutionObservation(
		invocation, result, processObservation,
		definition.maxStdoutBytes, definition.maxStderrBytes, receipt,
	)
}

// stagedOutputCause returns the typed staging cause carried by a staged output
// failure. Anything untyped fails closed as a staging violation.
func stagedOutputCause(err error) domain.RuntimeDiagnosticCause {
	var failure *providerOutputFailure
	if errors.As(err, &failure) && failure.Cause().Valid() {
		return failure.Cause()
	}
	return domain.DiagnosticCauseProviderOutputStagingViolation
}

func providerRuntimeFailure(cause domain.RuntimeDiagnosticCause, err error) error {
	failure, constructionErr := ports.NewProviderRuntimeError(cause, err)
	if constructionErr != nil {
		return constructionErr
	}
	return failure
}

func (r *Registry) runLegacy(
	ctx context.Context, definition definition, packet ports.ProviderPacket, environment []ports.EnvironmentVariable,
) (ports.ProcessObservation, error) {
	request, err := processRequest(definition, packet, definition.workingDirectory, environment)
	if err != nil {
		return ports.ProcessObservation{}, fmt.Errorf("provider registry: %w", err)
	}
	if definition.requiresSpawnVerification {
		if r.spawnVerifier == nil {
			return ports.ProcessObservation{}, fmt.Errorf("provider registry: missing spawn verifier")
		}
		if err := r.spawnVerifier.VerifyProviderSpawn(ctx, RuntimeDefinition(definition)); err != nil {
			return ports.ProcessObservation{}, fmt.Errorf("provider registry: spawn revalidation: %w", err)
		}
	}
	observation, err := r.runner.Run(ctx, request)
	if err != nil {
		return observation, fmt.Errorf("provider registry: process runner: %w", err)
	}
	return observation, nil
}

func (r *Registry) runInWorkspace(
	ctx context.Context, definition definition, invocation ports.ProviderInvocation,
	workspace ports.WorkspaceExecutionAuthority, packet ports.ProviderPacket,
	namespace ports.ProviderNamespaceLease, environment []ports.EnvironmentVariable,
) (observation ports.ProcessObservation, err error) {
	expected, ok := invocation.WorkspaceSnapshotIdentity()
	if !ok || !expected.Valid() || workspace.WorkspaceSnapshotIdentity() != expected {
		return ports.ProcessObservation{}, workspaceGuardError("workspace identity mismatch", nil)
	}
	guard, guardErr := workspace.RevalidateForExecution()
	if guardErr != nil {
		return ports.ProcessObservation{}, workspaceGuardError("pre-execution revalidation", guardErr)
	}
	if nilWorkspaceExecutionGuard(guard) {
		return ports.ProcessObservation{}, workspaceGuardError("pre-execution revalidation returned nil guard", nil)
	}
	defer func() {
		if closeErr := guard.Close(); closeErr != nil {
			err = workspaceGuardError("close", closeErr)
		}
	}()

	root := guard.WorkspaceRoot()
	if guard.WorkspaceSnapshotIdentity() != expected || !root.Valid() || root.SnapshotIdentity() != expected {
		return ports.ProcessObservation{}, workspaceGuardError("guard workspace identity mismatch", nil)
	}
	request, requestErr := processRequest(definition, packet, root.Path(), environment)
	if requestErr != nil {
		return ports.ProcessObservation{}, fmt.Errorf("provider registry: %w", requestErr)
	}
	if _, staged := invocation.StagedOutputDestination(); !staged {
		request, requestErr = ports.NewSpooledStdoutProcessRequest(request)
		if requestErr != nil {
			return ports.ProcessObservation{}, fmt.Errorf("provider registry: mark report stdout: %w", requestErr)
		}
	}
	launchDirectory, duplicateErr := guard.DuplicateLaunchDirectory()
	if duplicateErr != nil {
		return ports.ProcessObservation{}, workspaceGuardError("duplicate launch directory", duplicateErr)
	}
	if definition.family == FamilyAgy && definition.requiresSpawnVerification {
		authorityLease, ok := namespace.(nativeHomeLaunchAuthorityLease)
		if !ok {
			_ = launchDirectory.Close()
			return ports.ProcessObservation{}, fmt.Errorf("provider registry: missing AGY native home authority")
		}
		authority, ok := authorityLease.NativeHomeLaunchAuthority()
		if !ok {
			_ = launchDirectory.Close()
			return ports.ProcessObservation{}, fmt.Errorf("provider registry: missing AGY native home authority")
		}
		request, requestErr = ports.NewBoundProcessRequestWithNativeHomeAuthority(request, root, launchDirectory, authority)
	} else {
		request, requestErr = ports.NewBoundProcessRequest(request, root, launchDirectory)
	}
	if requestErr != nil {
		_ = launchDirectory.Close()
		return ports.ProcessObservation{}, workspaceGuardError("construct bound process request", requestErr)
	}
	if definition.requiresSpawnVerification {
		if r.spawnVerifier == nil {
			return ports.ProcessObservation{}, fmt.Errorf("provider registry: missing spawn verifier")
		}
		if err := r.spawnVerifier.VerifyProviderSpawn(ctx, RuntimeDefinition(definition)); err != nil {
			return ports.ProcessObservation{}, fmt.Errorf("provider registry: spawn revalidation: %w", err)
		}
	}

	observation, err = r.runner.Run(ctx, request)
	if postErr := guard.RevalidateAfterExecution(); postErr != nil {
		return observation, workspaceGuardError("post-execution revalidation", postErr)
	}
	if err != nil {
		return observation, fmt.Errorf("provider registry: process runner: %w", err)
	}
	return observation, nil
}

func processRequest(
	definition definition, packet ports.ProviderPacket, workingDirectory string, namespaceEnvironment []ports.EnvironmentVariable,
) (ports.ProcessRequest, error) {
	argv, binding, err := providerProcessRequest(definition, packet, workingDirectory)
	if err != nil {
		return ports.ProcessRequest{}, fmt.Errorf("construct packet transport: %w", err)
	}
	environment, err := isolatedProcessEnvironment(definition.environment, namespaceEnvironment)
	if err != nil {
		return ports.ProcessRequest{}, err
	}
	if lifecycle, ok := definition.postOutputPolicy(); ok {
		return ports.NewProviderProcessRequestWithPostOutputLifecycle(
			definition.executable, argv, environment, workingDirectory, binding,
			lifecycle, definition.timeout, definition.maxStdoutBytes, definition.maxStderrBytes,
			definition.concurrencyKey,
		)
	}
	return ports.NewProviderProcessRequest(
		definition.executable, argv, environment, workingDirectory, binding,
		definition.timeout, definition.maxStdoutBytes, definition.maxStderrBytes, definition.concurrencyKey,
	)
}

// Close terminally drains every namespace after all in-flight provider calls
// finish. A cancelled or partial drain remains retryable; successfully drained
// namespaces retain their actual receipts and are never drained again.
func (r *Registry) Close(ctx context.Context) (ports.ProviderRunTerminalReceipt, error) {
	if r == nil || ctx == nil {
		return ports.ProviderRunTerminalReceipt{}, fmt.Errorf("provider registry: invalid terminal drain")
	}
	r.stateMu.Lock()
	r.closed = true
	activeZero := r.activeZero
	r.stateMu.Unlock()
	if err := ctx.Err(); err != nil {
		return ports.ProviderRunTerminalReceipt{}, err
	}

	select {
	case <-activeZero:
	case <-ctx.Done():
		return ports.ProviderRunTerminalReceipt{}, ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return ports.ProviderRunTerminalReceipt{}, err
	}
	select {
	case r.closeMu <- struct{}{}:
		defer func() { <-r.closeMu }()
	case <-ctx.Done():
		return ports.ProviderRunTerminalReceipt{}, ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return ports.ProviderRunTerminalReceipt{}, err
	}
	if r.receipt.Valid() {
		return r.receipt, nil
	}
	receipt, err := r.drainNamespacesWithContext(ctx)
	if err != nil {
		return ports.ProviderRunTerminalReceipt{}, err
	}
	r.receipt = receipt
	return receipt, nil
}

func (r *Registry) observeDone(instance string) {
	r.stateMu.Lock()
	defer r.stateMu.Unlock()
	delete(r.activeInstances, instance)
	r.active--
	if r.active == 0 {
		close(r.activeZero)
	}
}

func (r *Registry) drainNamespacesError(ctx context.Context) error {
	_, err := r.drainNamespacesWithContext(ctx)
	return err
}
func (r *Registry) drainNamespacesWithContext(ctx context.Context) (ports.ProviderRunTerminalReceipt, error) {
	if ctx == nil {
		return ports.ProviderRunTerminalReceipt{}, fmt.Errorf("provider registry: invalid terminal drain context")
	}
	var result error
	for instance, namespace := range r.namespaces {
		if _, drained := r.namespaceReceipts[instance]; drained {
			continue
		}
		if nilProviderNamespaceLease(namespace) {
			result = errors.Join(result, fmt.Errorf("provider registry: missing namespace lease for %q", instance))
			continue
		}
		receipt, err := namespace.DrainTerminal(ctx)
		if err != nil {
			result = errors.Join(result, fmt.Errorf("provider registry: terminal drain namespace %q: %w", instance, err))
			continue
		}
		if !receipt.Valid() || receipt.ProviderInstance() != instance || receipt.Generation() != namespace.Generation() {
			result = errors.Join(result, fmt.Errorf("provider registry: invalid terminal receipt for namespace %q", instance))
			continue
		}
		r.namespaceReceipts[instance] = receipt
	}
	if result != nil {
		return ports.ProviderRunTerminalReceipt{}, result
	}
	receipts := make([]ports.ProviderNamespaceTerminalReceipt, 0, len(r.namespaceReceipts))
	for _, receipt := range r.namespaceReceipts {
		receipts = append(receipts, receipt)
	}
	aggregate, err := ports.NewProviderRunTerminalReceipt(receipts)
	if err != nil {
		return ports.ProviderRunTerminalReceipt{}, fmt.Errorf("provider registry: aggregate terminal receipt: %w", err)
	}
	return aggregate, nil
}

func newEphemeralNamespaceFactory() (*NamespaceFactory, error) {
	root, err := os.MkdirTemp("", "mulgae-provider-namespaces-")
	if err != nil {
		return nil, fmt.Errorf("provider registry: create namespace root: %w", err)
	}
	factory, err := NewNamespaceFactory(root)
	if err != nil {
		if cleanupErr := os.RemoveAll(root); cleanupErr != nil {
			return nil, errors.Join(err, fmt.Errorf("provider registry: remove namespace root: %w", cleanupErr))
		}
		return nil, err
	}
	return factory, nil
}

func nilProviderNamespaceFactory(factory ports.ProviderNamespaceFactory) bool {
	if factory == nil {
		return true
	}
	value := reflect.ValueOf(factory)
	return value.Kind() == reflect.Ptr && value.IsNil()
}

func nilProviderNamespaceLease(lease ports.ProviderNamespaceLease) bool {
	if lease == nil {
		return true
	}
	value := reflect.ValueOf(lease)
	return value.Kind() == reflect.Ptr && value.IsNil()
}

func isolatedProcessEnvironment(
	configured, namespace []ports.EnvironmentVariable,
) ([]ports.EnvironmentVariable, error) {
	if len(namespace) == 0 {
		return nil, fmt.Errorf("provider registry: empty namespace environment")
	}
	environment := make([]ports.EnvironmentVariable, 0, len(configured)+len(namespace))
	owned := make(map[string]struct{}, len(namespace))
	for _, variable := range namespace {
		if !variable.Valid() || !namespaceEnvironmentName(variable.Name()) {
			return nil, fmt.Errorf("provider registry: invalid namespace environment")
		}
		if _, exists := owned[variable.Name()]; exists {
			return nil, fmt.Errorf("provider registry: duplicate namespace environment")
		}
		owned[variable.Name()] = struct{}{}
		environment = append(environment, variable)
	}
	required := [...]string{"HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME", "TMPDIR", "TMP", "TEMP", "MULGAE_PROVIDER_SCRATCH"}
	for _, name := range required {
		if _, exists := owned[name]; !exists {
			return nil, fmt.Errorf("provider registry: incomplete namespace environment")
		}
	}
	for _, variable := range configured {
		if !variable.Valid() {
			return nil, fmt.Errorf("provider registry: invalid configured environment")
		}
		if _, reserved := owned[variable.Name()]; reserved || unsafeNamespaceEnvironmentName(variable.Name()) {
			continue
		}
		environment = append(environment, variable)
	}
	return environment, nil
}

func namespaceEnvironmentName(name string) bool {
	switch name {
	case "HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME",
		"TMPDIR", "TMP", "TEMP", "MULGAE_PROVIDER_SCRATCH":
		return true
	default:
		return false
	}
}

func unsafeNamespaceEnvironmentName(name string) bool {
	return name == "HOME" || name == "TMPDIR" || name == "TMP" || name == "TEMP" ||
		strings.HasPrefix(name, "XDG_") || name == "MULGAE_PROVIDER_SCRATCH"
}

func workspaceGuardError(operation string, cause error) error {
	if cause == nil {
		return fmt.Errorf("provider registry: workspace guard %s: %w", operation, ports.ErrWorkspaceSnapshotDrift)
	}
	return fmt.Errorf("provider registry: workspace guard %s: %w: %w", operation, ports.ErrWorkspaceSnapshotDrift, cause)
}

func providerRunCauses(err error) (domain.RuntimeDiagnosticCause, domain.RuntimeDiagnosticCause) {
	var failure *ports.ProcessExecutionError
	if errors.As(err, &failure) {
		cleanup, _ := failure.CleanupCause()
		return failure.PrimaryCause(), cleanup
	}
	if errors.Is(err, ports.ErrWorkspaceSnapshotDrift) {
		return domain.DiagnosticCauseWorkspaceRevalidationFailed, ""
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return domain.DiagnosticCauseTimedOut, ""
	}
	// Every error reaching this point occurred before a valid process
	// observation existed. Preserve that boundary as a spawn failure instead of
	// allowing an ordinary preparation failure to collapse into an invariant.
	return domain.DiagnosticCauseProviderSpawnFailed, ""
}

func providerFailureProjection(cause domain.RuntimeDiagnosticCause) (ports.ProviderExecutionStatus, string) {
	switch cause {
	case domain.DiagnosticCauseTimedOut:
		return ports.ProviderExecutionStatusTimedOut, "provider_timeout"
	case domain.DiagnosticCauseLoginRequired:
		return ports.ProviderExecutionStatusAuthentication, "login_required"
	case domain.DiagnosticCauseAuthenticationFailed:
		return ports.ProviderExecutionStatusAuthentication, "provider_auth"
	case domain.DiagnosticCausePermissionDenied:
		return ports.ProviderExecutionStatusAuthentication, "provider_permission_denied"
	case domain.DiagnosticCauseQuotaExceeded:
		return ports.ProviderExecutionStatusQuota, "provider_quota"
	case domain.DiagnosticCauseRateLimited:
		return ports.ProviderExecutionStatusRateLimit, "provider_rate_limit"
	case domain.DiagnosticCauseTransportVerificationFailed,
		domain.DiagnosticCausePromptFilePreStartFailed,
		domain.DiagnosticCausePromptFilePostEndFailed,
		domain.DiagnosticCauseTransportReceiptMismatch,
		domain.DiagnosticCauseLifecycleReceiptInvalid,
		domain.DiagnosticCauseOutputFrameMismatch,
		domain.DiagnosticCauseSignalReceiptMismatch,
		domain.DiagnosticCauseWorkspaceRevalidationFailed,
		// A provider that wrote outside the single file it was granted, or
		// staging whose identity moved underneath the retained descriptor,
		// breached a boundary rather than produced poor output.
		domain.DiagnosticCauseProviderOutputStagingViolation:
		return ports.ProviderExecutionStatusSecurityViolation, "process_security"
	case domain.DiagnosticCauseOutputFrameMissing, domain.DiagnosticCauseOutputEnvelopeInvalid,
		domain.DiagnosticCauseOutputDecodeFailed, domain.DiagnosticCauseResultBindingFailed,
		domain.DiagnosticCauseOutputMissing,
		// A missing or unusable staged file is an ordinary operational output
		// outcome, so repair stays available to the application.
		domain.DiagnosticCauseProviderOutputFileMissing,
		domain.DiagnosticCauseProviderOutputFileInvalid:
		return ports.ProviderExecutionStatusArtifactFailure, providerOutputDiagnostic(cause)
	case domain.DiagnosticCauseProviderOutputStagingCleanupFailed:
		return ports.ProviderExecutionStatusArtifactFailure, "provider_output_staging_cleanup_failed"
	default:
		return ports.ProviderExecutionStatusInternalFailure, "process_internal"
	}
}

// providerOutputDiagnostic deliberately projects every closed output cause to
// one safe external code. Consumers that need the distinction use PrimaryCause.
func providerOutputDiagnostic(cause domain.RuntimeDiagnosticCause) string {
	if cause == domain.DiagnosticCauseOutputMissing {
		return "provider_output_missing"
	}
	return "invalid_provider_output"
}

func nilWorkspaceExecutionGuard(guard ports.WorkspaceExecutionGuard) bool {
	if guard == nil {
		return true
	}
	value := reflect.ValueOf(guard)
	return value.Kind() == reflect.Ptr && value.IsNil()
}

func providerProcessRequest(definition definition, packet ports.ProviderPacket, workingDirectory string) ([]string, ports.ProviderPacketBinding, error) {
	if !validCanonicalAbsolute(workingDirectory) {
		return nil, ports.ProviderPacketBinding{}, fmt.Errorf("invalid working directory")
	}
	argv, err := buildArgv(definition, workingDirectory, packet.Bytes())
	if err != nil {
		return nil, ports.ProviderPacketBinding{}, err
	}
	switch definition.transport.channel {
	case ports.ProviderPacketChannelArgvLiteral:
		binding, err := ports.NewArgvLiteralProviderPacketBinding(packet, definition.transport.argvIndex)
		return argv, binding, err
	case ports.ProviderPacketChannelStdin:
		binding, err := ports.NewStdinProviderPacketBinding(packet)
		return argv, binding, err
	case ports.ProviderPacketChannelPromptFile:
		binding, err := ports.NewPromptFileProviderPacketBinding(
			packet, definition.transport.argvIndex, definition.transport.reference, workingDirectory,
		)
		return argv, binding, err
	default:
		return nil, ports.ProviderPacketBinding{}, fmt.Errorf("unsupported packet channel")
	}
}

func buildArgv(definition definition, workingDirectory string, packet []byte) ([]string, error) {
	value := ""
	switch definition.transport.channel {
	case ports.ProviderPacketChannelArgvLiteral:
		value = string(packet)
	case ports.ProviderPacketChannelStdin:
		value = "-"
	case ports.ProviderPacketChannelPromptFile:
		value = definition.transport.reference
	default:
		return nil, fmt.Errorf("unsupported packet channel")
	}

	argv := append([]string(nil), definition.baseArgv...)
	switch definition.family {
	case FamilyKimi:
		return appendKimiInvocation(argv, definition.kimiModel, value), nil
	case FamilyZcode:
		return appendZcodeInvocation(argv, value), nil
	case FamilyAgy:
		controls := []string{"--new-project", "--sandbox"}
		if agyPermissionBypassEnabled(definition.baseArgv, definition.transport) {
			controls = append(controls, "--dangerously-skip-permissions")
		}
		controls = append(controls, "--add-dir", workingDirectory, "--mode", "plan", "--effort", "low", "--print-timeout", agyPrintTimeout(definition.timeout).String(), "--print", value)
		return append(argv, controls...), nil
	default:
		return nil, fmt.Errorf("unknown provider family")
	}
}

func providerResult(family string, stdout []byte) ([]byte, bool, error) {
	if len(bytes.TrimSpace(stdout)) == 0 {
		return nil, true, newProviderOutputFailure(domain.DiagnosticCauseOutputMissing, fmt.Errorf("provider output is empty"))
	}
	switch family {
	case FamilyKimi:
		result, err := kimiContent(stdout)
		if err != nil {
			cause := domain.DiagnosticCauseOutputDecodeFailed
			if errors.Is(err, errProviderOutputFrameMissing) {
				cause = domain.DiagnosticCauseOutputFrameMissing
			}
			return nil, true, newProviderOutputFailure(cause, err)
		}
		return result, true, nil
	case FamilyZcode:
		result, err := zcodeContent(stdout)
		if err != nil {
			if errors.Is(err, errInvalidZcodeEnvelope) {
				return nil, false, newProviderOutputFailure(domain.DiagnosticCauseOutputEnvelopeInvalid, err)
			}
			return append([]byte(nil), stdout...), false, nil
		}
		return result, true, nil
	case FamilyAgy:
		result, err := agyContent(stdout)
		if err != nil {
			return nil, true, newProviderOutputFailure(domain.DiagnosticCauseOutputDecodeFailed, err)
		}
		return result, true, nil
	default:
		return nil, false, newProviderOutputFailure(domain.DiagnosticCauseResultBindingFailed, fmt.Errorf("unknown provider family"))
	}
}

func agyContent(stdout []byte) ([]byte, error) {
	frame, err := ports.ExtractProcessOutputJSONFrame(ports.ProcessOutputFramingTerminalJSONObject, stdout)
	if err != nil {
		trimmed := bytes.TrimSpace(stdout)
		if len(trimmed) == 0 || !utf8.Valid(stdout) {
			return nil, err
		}
		// Malformed native JSON envelopes stay fail-closed. Pure Markdown/prose
		// may reach application free-form acceptance.
		if trimmed[0] == '{' || trimmed[0] == '[' {
			return nil, err
		}
		// Trim only for nonempty/shape checks; return exact stdout bytes.
		return append([]byte(nil), stdout...), nil
	}
	if text := agyReviewResultText(frame); len(bytes.TrimSpace(text)) > 0 {
		return append([]byte(nil), text...), nil
	}
	return frame, nil
}

func zcodeContent(stdout []byte) ([]byte, error) {
	frame, err := ports.ExtractProcessOutputJSONFrame(ports.ProcessOutputFramingTerminalJSONObject, stdout)
	if err != nil {
		return nil, err
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(frame, &envelope); err != nil {
		return nil, err
	}
	rawResponse, present := envelope["response"]
	if !present {
		// Legacy headless payloads may be the review document itself only when
		// trimmed stdout is exactly that JSON object. Embedded or fenced JSON
		// inside free-form stdout must keep exact assistant bytes for primary
		// reports; providerResult maps frame-missing to isolated=false identity.
		if !bytes.Equal(bytes.TrimSpace(stdout), frame) {
			return nil, errProviderOutputFrameMissing
		}
		return frame, nil
	}
	var response string
	if err := json.Unmarshal(rawResponse, &response); err != nil || strings.TrimSpace(response) == "" {
		return nil, errInvalidZcodeEnvelope
	}
	// Preserve the exact extracted assistant response bytes. TrimSpace is only
	// used above to reject empty responses; structured candidates are derived
	// later by the application layer. Never return the raw CLI envelope.
	return append([]byte(nil), response...), nil
}

// extractUniqueFencedPayload unwraps one complete JSON fence without deciding
// whether the provider-owned payload is valid JSON. Payload parsing and repair
// authority belong to the application validation layer, while this adapter
// remains responsible for rejecting ambiguous transport framing.
func extractUniqueFencedPayload(output []byte) ([]byte, error) {
	const (
		fenceStart = "```json\n"
		fenceEnd   = "\n```"
	)
	start := bytes.Index(output, []byte(fenceStart))
	if start < 0 || start > 0 && output[start-1] != '\n' {
		return nil, errProviderOutputFrameMissing
	}
	contentStart := start + len(fenceStart)
	if bytes.Contains(output[contentStart:], []byte(fenceStart)) {
		return nil, errProviderOutputFrameMissing
	}
	endOffset := bytes.Index(output[contentStart:], []byte(fenceEnd))
	if endOffset < 0 {
		return nil, errProviderOutputFrameMissing
	}
	candidate := bytes.TrimSpace(output[contentStart : contentStart+endOffset])
	if len(candidate) == 0 {
		return nil, errProviderOutputFrameMissing
	}
	return append([]byte(nil), candidate...), nil
}

func kimiContent(stdout []byte) ([]byte, error) {
	var content []byte
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
		if !ok {
			continue
		}
		var value string
		if err := json.Unmarshal(rawContent, &value); err != nil {
			return nil, err
		}
		content = []byte(value)
	}
	if content == nil {
		return nil, errProviderOutputFrameMissing
	}
	return content, nil
}

func classifyProviderFailure(
	family string,
	observation ports.ProcessObservation,
) (ports.ProviderExecutionStatus, string, domain.RuntimeDiagnosticCause) {
	if hasPostOutputTrailingBytes(observation) {
		return ports.ProviderExecutionStatusArtifactFailure, "post_output_trailing_bytes", domain.DiagnosticCauseOutputEnvelopeInvalid
	}
	if observation.Termination() == ports.ProcessTerminationExited {
		if status, diagnostic, cause, ok := nativeProviderOutcome(family, observation.Stdout(), observation.Stderr()); ok {
			return status, diagnostic, cause
		}
	}
	status := classify(observation)
	diagnostic := diagnosticCode(observation)
	switch observation.Termination() {
	case ports.ProcessTerminationTimedOut:
		return status, diagnostic, domain.DiagnosticCauseTimedOut
	case ports.ProcessTerminationStartFailed, ports.ProcessTerminationStartUnavailable,
		ports.ProcessTerminationStartConfiguration, ports.ProcessTerminationStartSecurity,
		ports.ProcessTerminationLockFailed, ports.ProcessTerminationLockUnavailable,
		ports.ProcessTerminationLockConfiguration, ports.ProcessTerminationLockSecurity:
		return status, diagnostic, domain.DiagnosticCauseProviderSpawnFailed
	case ports.ProcessTerminationResidualProcessGroup:
		return status, diagnostic, domain.DiagnosticCauseProcessGroupCleanupFailed
	case ports.ProcessTerminationStdoutLimit, ports.ProcessTerminationStderrLimit,
		ports.ProcessTerminationStdinIncomplete:
		return status, diagnostic, domain.DiagnosticCauseObservationInvalid
	default:
		return status, diagnostic, domain.DiagnosticCauseProviderExecutionFailed
	}
}

// nativeProviderOutcome maps a native provider diagnostic to a typed execution
// outcome. Two constraints bound the token tables and must be preserved:
//
//   - No branch may ever match a bare "timeout" token. AGY argv carries
//     --print-timeout, and an argv echo in stderr must not read as a native
//     provider timeout. Timeout evidence is either the exact native phrase or a
//     transport-level phrase such as "timed out".
//   - Short/numeric tokens (429, 503) and prose tokens (overloaded, try again
//     later) are matched on stderr only. This function is also reached from
//     classifyProviderFailure for REVIEW invocations whose stdout is
//     model-authored review text, so a review discussing capacity planning or
//     HTTP 503 handling must never classify as a transient provider condition.
func nativeProviderOutcome(
	family string,
	stdout, stderr []byte,
) (ports.ProviderExecutionStatus, string, domain.RuntimeDiagnosticCause, bool) {
	output := bytes.ToLower(bytes.Join([][]byte{stdout, stderr}, []byte{'\n'}))
	errorOutput := bytes.ToLower(stderr)
	containsAny := func(values ...string) bool {
		for _, value := range values {
			if bytes.Contains(output, []byte(value)) {
				return true
			}
		}
		return false
	}
	errorContainsAny := func(values ...string) bool {
		for _, value := range values {
			if bytes.Contains(errorOutput, []byte(value)) {
				return true
			}
		}
		return false
	}
	loginRequired := providerLoginRequired(output)
	switch family {
	case FamilyKimi:
		loginRequired = loginRequired || containsAny("kimi.login_required", "kimi login required")
	case FamilyZcode:
		loginRequired = loginRequired || containsAny("zcode.login_required", "zcode login required")
	case FamilyAgy:
		loginRequired = loginRequired || containsAny("agy.login_required", "agy login required")
	default:
		return "", "", "", false
	}
	switch {
	case loginRequired:
		return ports.ProviderExecutionStatusAuthentication, "login_required", domain.DiagnosticCauseLoginRequired, true
	case family == FamilyAgy && agyPermissionDenied(stderr):
		return ports.ProviderExecutionStatusAuthentication, "provider_permission_denied", domain.DiagnosticCausePermissionDenied, true
	case providerNativeTimeout(output) ||
		errorContainsAny("timed out", "deadline exceeded", "etimedout", "request timeout", "read timeout", "connection timed out"):
		return ports.ProviderExecutionStatusTimedOut, "provider_timeout", domain.DiagnosticCauseTimedOut, true
	case containsAny("quota_exceeded", "insufficient_quota", "quota exceeded",
		"insufficient_credits", "insufficient credits", "usage limit", "usage_limit_reached"):
		return ports.ProviderExecutionStatusQuota, "provider_quota", domain.DiagnosticCauseQuotaExceeded, true
	case containsAny("rate_limit", "rate limit", "too many requests", "rate-limited", "ratelimit") ||
		errorContainsAny("429", "http 429", "slow down", "try again later", "please try again", "retry after", "retry-after"):
		return ports.ProviderExecutionStatusRateLimit, "provider_rate_limit", domain.DiagnosticCauseRateLimited, true
	case containsAny("service unavailable", "bad gateway", "gateway timeout", "internal server error") ||
		errorContainsAny("503", "502", "504", "overloaded", "over capacity", "at capacity", "server is busy", "temporarily unavailable"):
		return ports.ProviderExecutionStatusUnavailable, "provider_overloaded", domain.DiagnosticCauseProviderExecutionFailed, true
	case containsAny("authentication_failed", "invalid api key", "invalid_api_key"):
		return ports.ProviderExecutionStatusAuthentication, "provider_auth", domain.DiagnosticCauseAuthenticationFailed, true
	default:
		return "", "", "", false
	}
}

func agyPermissionDenied(stderr []byte) bool {
	output := bytes.ToLower(stderr)
	for _, signal := range [][]byte{
		[]byte("permission_denied"),
		[]byte("tool permission was denied"),
		[]byte("tool permission denied"),
		[]byte("request denied by permission policy"),
		// Headless AGY refuses a write tool with its own auto-deny message
		// ("... was auto-denied ..."), which matches none of the phrases above.
		[]byte("auto-denied"),
	} {
		if bytes.Contains(output, signal) {
			return true
		}
	}
	return false
}

func classify(observation ports.ProcessObservation) ports.ProviderExecutionStatus {
	if hasPostOutputTrailingBytes(observation) {
		return ports.ProviderExecutionStatusArtifactFailure
	}
	if observation.Termination() == ports.ProcessTerminationExited &&
		(providerLoginRequired(observation.Stderr()) || providerLoginRequired(observation.Stdout())) {
		return ports.ProviderExecutionStatusAuthentication
	}
	if observation.Termination() == ports.ProcessTerminationExited &&
		(providerNativeTimeout(observation.Stderr()) || providerNativeTimeout(observation.Stdout())) {
		return ports.ProviderExecutionStatusTimedOut
	}
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
func hasPostOutputTrailingBytes(observation ports.ProcessObservation) bool {
	lifecycle, ok := observation.LifecycleReceipt()
	if !ok {
		return false
	}
	frame, ok := lifecycle.OutputFrame()
	return ok && (int64(len(observation.Stdout())) != frame.ByteLength() ||
		ports.ValidateProcessOutputFrame(frame.Framing(), observation.Stdout()) != nil)
}

func diagnosticCode(observation ports.ProcessObservation) string {
	if hasPostOutputTrailingBytes(observation) {
		return "post_output_trailing_bytes"
	}
	if observation.Termination() == ports.ProcessTerminationExited &&
		(providerLoginRequired(observation.Stderr()) || providerLoginRequired(observation.Stdout())) {
		return "login_required"
	}
	if observation.Termination() == ports.ProcessTerminationExited &&
		(providerNativeTimeout(observation.Stderr()) || providerNativeTimeout(observation.Stdout())) {
		return "provider_timeout"
	}
	for _, request := range observation.SignalRequests() {
		if request.Reason() == ports.ProcessGroupSignalRequestPostOutputEscalation {
			return "post_output_termination_grace"
		}
	}
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

func providerLoginRequired(stderr []byte) bool {
	return bytes.Contains(bytes.ToLower(stderr), []byte("auth.login_required"))
}

func providerNativeTimeout(output []byte) bool {
	return bytes.Contains(bytes.ToLower(output), []byte("timeout waiting for response"))
}

func cloneDefinition(definition definition) definition {
	definition.baseArgv = append([]string(nil), definition.baseArgv...)
	definition.environment = append([]ports.EnvironmentVariable(nil), definition.environment...)
	return definition
}
func defaultRuntimeTransport(family string, baseArgvLength int) (RuntimeTransport, error) {
	index, err := runtimeTransportArgvIndex(family, baseArgvLength)
	if err != nil {
		return RuntimeTransport{}, err
	}
	return NewRuntimeTransport(ports.ProviderPacketChannelArgvLiteral, index, "")
}

func validateRuntimeTransportShape(family string, baseArgv []string, transport RuntimeTransport) error {
	if transport.channel == ports.ProviderPacketChannelStdin {
		return nil
	}
	if family == FamilyAgy && (transport.argvIndex == len(baseArgv)+11 || transport.argvIndex == len(baseArgv)+12) {
		return nil
	}
	index, err := runtimeTransportArgvIndex(family, len(baseArgv))
	if err != nil {
		return err
	}
	if transport.argvIndex != index {
		return fmt.Errorf("packet transport argv index does not match %s print profile", family)
	}
	return nil
}

func runtimeTransportArgvIndex(family string, baseArgvLength int) (int, error) {
	switch family {
	case FamilyKimi:
		return baseArgvLength + 3, nil
	case FamilyZcode:
		return baseArgvLength + 4, nil
	case FamilyAgy:
		// Safe AGY argv omits --dangerously-skip-permissions; print lands at +11.
		// Explicit headless bypass uses +12 and remains opt-in only.
		return baseArgvLength + 11, nil
	default:
		return 0, fmt.Errorf("unsupported family")
	}
}

func validPromptFileReference(value string) bool {
	if len(value) < 2 || value[0] != '@' || strings.IndexByte(value, 0) >= 0 {
		return false
	}
	reference := value[1:]
	return !filepath.IsAbs(reference) && filepath.Clean(reference) == reference && reference != "." && reference != ".." &&
		!strings.HasPrefix(reference, "../") && !strings.Contains(reference, "/../")
}

func validFamily(value string) bool {
	return value == FamilyKimi || value == FamilyZcode || value == FamilyAgy
}

func nilSpawnVerifier(verifier SpawnVerifier) bool {
	if verifier == nil {
		return true
	}
	value := reflect.ValueOf(verifier)
	return value.Kind() == reflect.Ptr && value.IsNil()
}
func validCanonicalAbsolute(value string) bool {
	return value != "" && filepath.IsAbs(value) && filepath.Clean(value) == value && strings.IndexByte(value, 0) < 0
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
