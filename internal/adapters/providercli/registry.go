// Package providercli implements opt-in direct CLI review providers.
package providercli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/irootkernel/kkachi-agent-review/internal/ports"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"time"
)

const (
	FamilyKimi  = "kimi"
	FamilyZcode = "zcode"
	FamilyAgy   = "agy"
)

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
// operator-admitted Kimi model without placing KAR-only metadata in provider
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
	lanes                map[ports.ConcurrencyKey]chan struct{}
	namespaces           map[string]ports.ProviderNamespaceLease
	namespaceGenerations map[string]string
	namespaceReceipts    map[string]ports.ProviderNamespaceTerminalReceipt
	spawnVerifier        SpawnVerifier

	stateMu    sync.Mutex
	closed     bool
	active     int
	activeZero chan struct{}
	closeMu    chan struct{}
	receipt    ports.ProviderRunTerminalReceipt
}

var _ ports.ObservedReviewProvider = (*Registry)(nil)

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
		lanes:                make(map[ports.ConcurrencyKey]chan struct{}, len(definitions)),
		namespaces:           make(map[string]ports.ProviderNamespaceLease, len(definitions)),
		namespaceGenerations: make(map[string]string, len(definitions)),
		namespaceReceipts:    make(map[string]ports.ProviderNamespaceTerminalReceipt, len(definitions)),
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
		if _, ok := registry.lanes[definition.concurrencyKey]; !ok {
			registry.lanes[definition.concurrencyKey] = make(chan struct{}, 1)
		}
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

func (r *Registry) Observe(ctx context.Context, invocation ports.ProviderInvocation) (ports.ProviderExecutionObservation, error) {
	if r == nil || nilRunner(r.runner) {
		return ports.ProviderExecutionObservation{}, fmt.Errorf("provider registry: nil process runner")
	}
	if ctx == nil {
		return ports.ProviderExecutionObservation{}, fmt.Errorf("provider registry: nil context")
	}
	r.stateMu.Lock()
	if r.closed {
		r.stateMu.Unlock()
		return ports.ProviderExecutionObservation{}, fmt.Errorf("provider registry: terminally drained")
	}
	if r.active == 0 {
		r.activeZero = make(chan struct{})
	}
	r.active++
	r.stateMu.Unlock()
	defer r.observeDone()
	definition, ok := r.definitions[invocation.ProviderInstance()]
	if !ok {
		return ports.ProviderExecutionObservation{}, fmt.Errorf("provider registry: unregistered provider instance %q", invocation.ProviderInstance())
	}
	if err := definition.validate(); err != nil {
		return ports.ProviderExecutionObservation{}, fmt.Errorf("provider registry: invalid registered definition: %w", err)
	}
	packet := invocation.Packet()
	namespace := r.namespaces[definition.instance]
	if nilProviderNamespaceLease(namespace) || namespace.Generation() != r.namespaceGenerations[definition.instance] {
		return ports.ProviderExecutionObservation{}, fmt.Errorf("provider registry: namespace generation drift")
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
	if namespace.Generation() != r.namespaceGenerations[definition.instance] {
		return ports.ProviderExecutionObservation{}, fmt.Errorf("provider registry: namespace generation drift")
	}
	if err := namespace.ValidateForSpawn(); err != nil {
		return ports.ProviderExecutionObservation{}, fmt.Errorf("provider registry: namespace lease validation: %w", err)
	}

	var processObservation ports.ProcessObservation
	var runErr error
	if workspace, ok := invocation.ExecutionWorkspace(); ok {
		processObservation, runErr = r.runInWorkspace(ctx, definition, invocation, workspace, packet, namespace, namespace.Environment())
	} else {
		if definition.requiresWorkspaceAuthority {
			return ports.ProviderExecutionObservation{}, fmt.Errorf("provider registry: production definition requires workspace authority")
		}
		processObservation, runErr = r.runLegacy(ctx, definition, packet, namespace.Environment())
	}
	if runErr != nil {
		return ports.ProviderExecutionObservation{}, runErr
	}
	if !processObservation.Valid() {
		return ports.ProviderExecutionObservation{}, fmt.Errorf("provider registry: process runner returned invalid observation")
	}
	if processObservation.Succeeded() {
		resultBytes, isolated, parseErr := providerResult(definition.family, processObservation.Stdout())
		if parseErr != nil {
			return ports.NewFailedProviderExecutionObservation(ports.ProviderExecutionStatusArtifactFailure, invocation, processObservation, "invalid_provider_output", definition.maxStdoutBytes, definition.maxStderrBytes)
		}
		result, resultErr := ports.NewProviderResultForInput(resultBytes, invocation.InputIdentity())
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
		return ports.ProcessObservation{}, fmt.Errorf("provider registry: process runner: %w", err)
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
			observation = ports.ProcessObservation{}
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
		return ports.ProcessObservation{}, workspaceGuardError("post-execution revalidation", postErr)
	}
	if err != nil {
		return ports.ProcessObservation{}, fmt.Errorf("provider registry: process runner: %w", err)
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

func (r *Registry) observeDone() {
	r.stateMu.Lock()
	defer r.stateMu.Unlock()
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
	root, err := os.MkdirTemp("", "kar-provider-namespaces-")
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
	required := [...]string{"HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME", "TMPDIR", "TMP", "TEMP", "KAR_PROVIDER_SCRATCH"}
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
		"TMPDIR", "TMP", "TEMP", "KAR_PROVIDER_SCRATCH":
		return true
	default:
		return false
	}
}

func unsafeNamespaceEnvironmentName(name string) bool {
	return name == "HOME" || name == "TMPDIR" || name == "TMP" || name == "TEMP" ||
		strings.HasPrefix(name, "XDG_") || name == "KAR_PROVIDER_SCRATCH"
}

func workspaceGuardError(operation string, cause error) error {
	if cause == nil {
		return fmt.Errorf("provider registry: workspace guard %s: %w", operation, ports.ErrWorkspaceSnapshotDrift)
	}
	return fmt.Errorf("provider registry: workspace guard %s: %w: %w", operation, ports.ErrWorkspaceSnapshotDrift, cause)
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
		return append(argv, "--mode", "plan", "--no-color", "--prompt", value), nil
	case FamilyAgy:
		controls := []string{"--new-project", "--sandbox"}
		if definition.transport.ArgvIndex() == 11 {
			controls = append(controls, "--dangerously-skip-permissions")
		}
		controls = append(controls, "--add-dir", workingDirectory, "--mode", "plan", "--print-timeout", "2m", "--print", value)
		return append(argv, controls...), nil
	default:
		return nil, fmt.Errorf("unknown provider family")
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
	return ports.ValidateProcessOutputFrame(ports.ProcessOutputFramingStrictJSON, value)
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
	if hasPostOutputTrailingBytes(observation) {
		return ports.ProviderExecutionStatusArtifactFailure
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
	if family == FamilyAgy && (transport.argvIndex == len(baseArgv)+9 || transport.argvIndex == len(baseArgv)+10) {
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
		return baseArgvLength + 10, nil
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
