package ports

import (
	"context"
	"time"

	"github.com/irootkernel/mulgae/internal/domain"
)

// ProviderRuntimeDefinition is the provider-independent identity and execution
// surface consumed by application-layer qualification. Adapter-owned runtime
// definitions implement this contract without exposing their concrete type.
type ProviderRuntimeDefinition interface {
	Family() string
	Instance() string
	Version() string
	Executable() string
	ExecutableSHA256() string
	Launcher() string
	LauncherSHA256() string
	ProfileGeneration() string
	RuntimeSafetyPolicyIdentity() string
	ProfileID() string
	KimiModel() string
	BaseArgv() []string
	Environment() []EnvironmentVariable
	WorkingDirectory() string
	Timeout() time.Duration
	PostOutputLifecycle() (BoundedPostOutputLifecycle, bool)
	TransportChannel() ProviderPacketChannel
	TransportArgvIndex() int
	TransportReference() string
}

// ProviderRuntimeSpec is the neutral construction request passed from the
// application layer to a provider adapter. The adapter validates all
// family-specific argv, transport, lifecycle, and safety-policy constraints.
type ProviderRuntimeSpec struct {
	Family                      string
	Instance                    string
	Version                     string
	Executable                  string
	ExecutableSHA256            string
	Launcher                    string
	LauncherSHA256              string
	ProfileID                   string
	ProfileGeneration           string
	RuntimeSafetyPolicyIdentity string
	KimiModel                   string
	CodexModel                  string
	CodexReasoningEffort        string
	BaseArgv                    []string
	TransportChannel            ProviderPacketChannel
	TransportArgvIndex          int
	TransportReference          string
	Environment                 []EnvironmentVariable
	WorkingDirectory            string
	Timeout                     time.Duration
	PostOutputLifecycle         BoundedPostOutputLifecycle
	HasPostOutputLifecycle      bool
}

// ProviderRuntimeBuilder owns adapter-specific runtime-policy lookup and
// construction. Application packages supply neutral specs only.
type ProviderRuntimeBuilder interface {
	RuntimeSafetyPolicyIdentity(string) (string, error)
	BuildProductionRuntime(ProviderRuntimeSpec) (ProviderRuntimeDefinition, error)
}

// ProviderQualificationNamespace is retained namespace authority for one
// provider instance. Probe workspaces remain independently leased.
type ProviderQualificationNamespace interface {
	ProviderInstance() string
	Generation() string
	Environment() []EnvironmentVariable
	RuntimeSafetyPolicyIdentity() string
	ValidateForSpawn() error
	NativeHomeLaunchAuthority() (NativeHomeLaunchAuthority, bool)
}

// ProviderQualificationFixtureLease is the application-visible portion of an
// adapter probe fixture. The adapter retains packet and workspace operations.
type ProviderQualificationFixtureLease interface {
	Role() domain.Role
	WorkspaceSnapshotIdentity() WorkspaceSnapshotIdentity
	Validate() error
	DrainTerminal(context.Context) (QualificationWorkspaceTerminalReceipt, error)
}

// ProviderQualificationFixtureFactory acquires independently materialized
// qualification fixtures for requested roles.
type ProviderQualificationFixtureFactory interface {
	Acquire(context.Context, domain.Role) (ProviderQualificationFixtureLease, error)
}

// ProviderDirectExecutionAuthority is current, descriptor-bound authority for
// the complete qualified role set.
type ProviderDirectExecutionAuthority interface {
	AuthorityID() string
	ExpiresAt() time.Time
	Valid() bool
	Matches(ProviderRuntimeDefinition, string, string, []domain.Role) bool
	AGYControlAuthorityID() (string, bool)
}

// ProviderEquivalentRouteAuthorityDeriver mints a new exact-runtime direct
// execution authority for one sibling route after validating shareable family
// profile equivalence against a live family capability proof. Application code
// must not manufacture destination authority by rewriting identity fields.
type ProviderEquivalentRouteAuthorityDeriver interface {
	DeriveEquivalentRouteDirectExecutionAuthority(
		source ProviderDirectExecutionAuthority,
		sourceDefinition ProviderRuntimeDefinition,
		destinationDefinition ProviderRuntimeDefinition,
		observedVersion string,
		sourceNamespaceGeneration string,
		destinationNamespaceGeneration string,
		sourceProvedRoles []domain.Role,
		destinationRoles []domain.Role,
	) (ProviderDirectExecutionAuthority, error)
}

// ProviderCurrentProbeReceipt is one adapter observation translated into a
// provider-independent receipt boundary.
type ProviderCurrentProbeReceipt struct {
	Kind                     string
	EvidenceID               string
	ExpiresAt                time.Time
	DirectExecutionAuthority ProviderDirectExecutionAuthority
}

// ProviderCurrentProbeRequest binds one runtime, namespace, and independent
// fixture set to a single current observation.
type ProviderCurrentProbeRequest struct {
	Definition   ProviderRuntimeDefinition
	Namespace    ProviderQualificationNamespace
	Fixture      ProviderQualificationFixtureLease
	RoleFixtures []ProviderQualificationFixtureLease
	Now          time.Time
	TTL          time.Duration
}

// ProviderCurrentProbeResult is current version and capability evidence after
// adapter-specific validation.
type ProviderCurrentProbeResult struct {
	VersionArgv []string
	Version     string
	Receipts    []ProviderCurrentProbeReceipt
}

// ProviderCurrentProbe executes the adapter-owned current qualification probe.
type ProviderCurrentProbe interface {
	QualifyProviderCurrent(context.Context, ProviderCurrentProbeRequest) (ProviderCurrentProbeResult, error)
}

// ProviderLoginAuthenticator performs an explicit operator-facing login flow
// for one exact discovered runtime. Implementations must not inherit ambient
// process environment or retain native provider output.
type ProviderLoginAuthenticator interface {
	LoginProvider(context.Context, ProviderRuntimeDefinition) error
}

// ProviderQualificationRegistry is the retained admitted execution authority.
type ProviderQualificationRegistry interface {
	ObservedReviewProvider
	QualificationNamespace(string) (ProviderQualificationNamespace, bool)
	Close(context.Context) (ProviderRunTerminalReceipt, error)
}

// ProviderQualificationRegistryFactory constructs retained registries and
// exposes cleanup authority when construction fails after acquisition.
type ProviderQualificationRegistryFactory interface {
	NewProviderQualificationRegistry(context.Context, []ProviderRuntimeDefinition) (ProviderQualificationRegistry, error)
	RegistryFromConstructionError(error) (ProviderQualificationRegistry, bool)
}
