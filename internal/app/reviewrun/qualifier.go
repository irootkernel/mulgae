package reviewrun

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/irootkernel/kkachi-agent-review/internal/app/review"
	"github.com/irootkernel/kkachi-agent-review/internal/domain"
	"github.com/irootkernel/kkachi-agent-review/internal/ports"
)

// CurrentQualifier performs the isolated current checks for one discovered
// provider. It must never use the host HOME or working directory: the supplied
// identity names the namespace retained by the run-owned registry. VersionArgv
// must be the exact discovered invocation plus "--version".
type CurrentQualifier interface {
	QualifyCurrent(context.Context, CurrentQualificationRequest) (CurrentQualificationResult, error)
}

// CurrentQualifierFunc adapts a function for injection in tests and composition.
type CurrentQualifierFunc func(context.Context, CurrentQualificationRequest) (CurrentQualificationResult, error)

func (function CurrentQualifierFunc) QualifyCurrent(ctx context.Context, request CurrentQualificationRequest) (CurrentQualificationResult, error) {
	return function(ctx, request)
}

// CurrentQualificationRequest is the complete immutable probe boundary. The
// definition is production-only and the identity is shared by every receipt.
type CurrentQualificationRequest struct {
	Profile        DiscoveredProviderProfile
	Definition     ports.ProviderRuntimeDefinition
	Identity       Identity
	Namespace      ports.ProviderQualificationNamespace
	RequestedRoles []domain.Role
	BaseRole       domain.Role
	Now            time.Time
}

// CurrentQualificationResult is immutable current evidence bound to exactly the
// supplied request identity. SupportedRoles must exactly match the canonical
// receipt-backed role authority.
type CurrentQualificationResult struct {
	VersionArgv       []string
	Version           string
	KnownIncompatible bool
	Receipts          []Receipt
	SupportedRoles    []domain.Role
	RoleReceipts      []CurrentRoleReceipt
	BaseRole          domain.Role
	Observations      []ProviderQualificationObservation
}

// CurrentRoleReceipt is explicit current evidence for one role.
type CurrentRoleReceipt struct {
	Role     domain.Role
	State    ReceiptState
	Identity Identity
}

// QualifiedRunCandidate binds one identity-only discovered profile to its
// declared production process profile and role authority.
type QualifiedRunCandidate struct {
	Profile          DiscoveredProviderProfile
	Definition       ports.ProviderRuntimeDefinition
	SnapshotManifest string
	SupportedRoles   []domain.Role
	BaseRole         domain.Role
	Limits           review.InvocationLimits
}

// QualifiedRunRegistry is the retained production execution authority.
type QualifiedRunRegistry = ports.ProviderQualificationRegistry

// QualifiedRunRegistryFactory creates production-only retained registries.
type QualifiedRunRegistryFactory = ports.ProviderQualificationRegistryFactory

// QualifiedRunFactory turns identity-only discovery into immutable routes and a
// run-owned registry. It has no fallback to live process state.
type QualifiedRunFactory struct {
	qualifier     CurrentQualifier
	registries    QualifiedRunRegistryFactory
	clock         ports.Clock
	authenticator ports.ProviderLoginAuthenticator
}

// NewQualifiedRunFactory validates the injected current probe and production
// registry authorities. Clock is required so all receipts share one expiry basis.
func NewQualifiedRunFactory(qualifier CurrentQualifier, registries QualifiedRunRegistryFactory, clock ports.Clock) (*QualifiedRunFactory, error) {
	return newQualifiedRunFactory(qualifier, registries, clock, nil)
}

// NewQualifiedRunFactoryWithLoginAuthenticator enables one bounded Kimi login
// recovery after a typed qualification-stage login-required response.
func NewQualifiedRunFactoryWithLoginAuthenticator(qualifier CurrentQualifier, registries QualifiedRunRegistryFactory, clock ports.Clock, authenticator ports.ProviderLoginAuthenticator) (*QualifiedRunFactory, error) {
	if nilInterface(authenticator) {
		return nil, fmt.Errorf("review run: provider login authenticator unavailable")
	}
	return newQualifiedRunFactory(qualifier, registries, clock, authenticator)
}

func newQualifiedRunFactory(qualifier CurrentQualifier, registries QualifiedRunRegistryFactory, clock ports.Clock, authenticator ports.ProviderLoginAuthenticator) (*QualifiedRunFactory, error) {
	if nilInterface(qualifier) || nilInterface(registries) || nilInterface(clock) {
		return nil, fmt.Errorf("review run: current qualifier dependencies unavailable")
	}
	return &QualifiedRunFactory{qualifier: qualifier, registries: registries, clock: clock, authenticator: authenticator}, nil
}

// QualifiedRun owns immutable routes and an admitted-only composite registry.
type QualifiedRun struct {
	routes                    []QualifiedRoute
	registry                  QualifiedRunRegistry
	admitted                  []qualifiedProviderEvidence
	qualificationFailures     []ProviderQualificationFailure
	qualificationObservations []ProviderQualificationObservation

	terminalMu sync.Mutex
	receipt    QualifiedRunTerminalReceipt
}

type qualifiedProviderEvidence struct {
	identity                  Identity
	qualificationReceiptIDs   []string
	packetTransportReceiptIDs []string
}

// QualifiedProviderTerminalEvidence binds exact accepted current evidence to
// the actual terminal namespace receipt for one admitted provider.
type QualifiedProviderTerminalEvidence struct {
	identity                   Identity
	qualificationReceiptIDs    []string
	packetTransportReceiptIDs  []string
	namespaceTerminalReceiptID string
}

func (evidence QualifiedProviderTerminalEvidence) Identity() Identity { return evidence.identity }

func (evidence QualifiedProviderTerminalEvidence) QualificationReceiptIDs() []string {
	return append([]string(nil), evidence.qualificationReceiptIDs...)
}

func (evidence QualifiedProviderTerminalEvidence) PacketTransportReceiptIDs() []string {
	return append([]string(nil), evidence.packetTransportReceiptIDs...)
}

func (evidence QualifiedProviderTerminalEvidence) NamespaceTerminalReceiptID() string {
	return evidence.namespaceTerminalReceiptID
}

func (evidence QualifiedProviderTerminalEvidence) Valid() bool {
	return evidence.identity.complete() &&
		canonicalReceiptIDs(evidence.qualificationReceiptIDs) &&
		canonicalReceiptIDs(evidence.packetTransportReceiptIDs) &&
		evidence.namespaceTerminalReceiptID != ""
}

type qualifiedRunRegistryComposite struct {
	registries  map[string]QualifiedRunRegistry
	generations map[string]string
	instances   []string

	closeMu sync.Mutex
	closed  map[string]ports.ProviderRunTerminalReceipt
	receipt ports.ProviderRunTerminalReceipt
}

// NewQualifiedRun qualifies each candidate in its own retained namespace.
// Operational unavailability skips only that candidate; all other failures
// drain every acquired namespace and fail closed.
func (factory *QualifiedRunFactory) NewQualifiedRun(ctx context.Context, candidates []QualifiedRunCandidate) (*QualifiedRun, error) {
	run, err := factory.newQualifiedRunAttempt(ctx, candidates)
	if err == nil || nilInterface(factory.authenticator) {
		return run, err
	}
	candidate, ok := kimiLoginRecoveryCandidate(err, candidates)
	if !ok {
		return nil, err
	}
	receipt, drained := ProviderRunTerminalReceiptFromError(err)
	if !drained {
		return nil, err
	}
	firstObservations := loginMitigatedQualificationObservations(qualificationObservationsFromError(err))
	if loginErr := factory.authenticator.LoginProvider(ctx, candidate.Definition); loginErr != nil {
		cause, causeErr := domain.NewFailure("reviewrun.login", domain.FailureAuthentication, "provider login failed", loginErr)
		if causeErr != nil {
			return nil, newQualifiedRunConstructionError(causeErr, receipt)
		}
		return nil, newQualifiedRunConstructionError(withQualificationObservations(NewProviderLoginRequiredError([]string{candidate.Definition.Instance()}, cause), firstObservations), receipt)
	}
	run, retryErr := factory.newQualifiedRunAttempt(ctx, candidates)
	if retryErr != nil {
		observations := append(firstObservations, qualificationObservationsFromError(retryErr)...)
		return nil, withQualificationObservations(retryErr, observations)
	}
	run.qualificationObservations = append(firstObservations, run.qualificationObservations...)
	return run, nil
}

func kimiLoginRecoveryCandidate(err error, candidates []QualifiedRunCandidate) (QualifiedRunCandidate, bool) {
	providers, loginRequired := ProviderLoginRequiredProvidersFromError(err)
	if !loginRequired || len(providers) != 1 {
		return QualifiedRunCandidate{}, false
	}
	for _, candidate := range candidates {
		if candidate.Definition != nil && candidate.Definition.Instance() == providers[0] && Family(candidate.Definition.Family()) == FamilyKimi {
			return candidate, true
		}
	}
	return QualifiedRunCandidate{}, false
}

func (factory *QualifiedRunFactory) newQualifiedRunAttempt(ctx context.Context, candidates []QualifiedRunCandidate) (*QualifiedRun, error) {
	if factory == nil || ctx == nil || len(candidates) == 0 || len(candidates) > 32 {
		return nil, fmt.Errorf("review run: invalid qualified run request")
	}
	seen := make(map[string]struct{}, len(candidates))
	for _, candidate := range candidates {
		if err := validateQualifiedRunCandidate(candidate, seen); err != nil {
			return nil, err
		}
	}
	now := factory.clock.Now()
	if now.IsZero() {
		return nil, fmt.Errorf("review run: current qualifier clock returned zero time")
	}
	admitted := make(map[string]QualifiedRunRegistry, len(candidates))
	admittedGenerations := make(map[string]string, len(candidates))
	admittedInstances := make([]string, 0, len(candidates))
	admittedEvidence := make([]qualifiedProviderEvidence, 0, len(candidates))
	qualificationFailures := make([]ProviderQualificationFailure, 0, len(candidates))
	qualificationObservations := make([]ProviderQualificationObservation, 0, len(candidates))
	closedReceipts := make(map[string]ports.ProviderRunTerminalReceipt, len(candidates))
	cleanupFailures := 0
	release := func(ctx context.Context, instance string) error {
		registry, ok := admitted[instance]
		if !ok {
			return nil
		}
		receipt, err := closeQualifiedRunRegistry(ctx, registry, instance, admittedGenerations[instance])
		if err != nil {
			cleanupFailures++
			return err
		}
		closedReceipts[instance] = receipt
		delete(admitted, instance)
		delete(admittedGenerations, instance)
		return nil
	}
	cleanupRegistry := func() *qualifiedRunRegistryComposite {
		registries := make(map[string]QualifiedRunRegistry, len(admitted))
		for instance, registry := range admitted {
			registries[instance] = registry
		}
		generations := make(map[string]string, len(admittedGenerations))
		for instance, generation := range admittedGenerations {
			generations[instance] = generation
		}
		closed := make(map[string]ports.ProviderRunTerminalReceipt, len(closedReceipts))
		for instance, receipt := range closedReceipts {
			closed[instance] = receipt
		}
		return &qualifiedRunRegistryComposite{
			registries: registries, generations: generations, instances: append([]string(nil), admittedInstances...), closed: closed,
		}
	}
	closeAdmitted := func(parent context.Context) (ports.ProviderRunTerminalReceipt, QualifiedRunRegistry, error) {
		if len(admittedInstances) == 0 {
			return ports.NewEmptyProviderRunTerminalReceipt(), nil, nil
		}
		registry := cleanupRegistry()
		var lastErr error
		for attempt := cleanupFailures; attempt < 2; attempt++ {
			cleanupCtx, cancel := context.WithTimeout(parent, time.Minute)
			receipt, err := registry.Close(cleanupCtx)
			cancel()
			if err == nil && receipt.Valid() {
				return receipt, nil, nil
			}
			if err == nil {
				lastErr = fmt.Errorf("review run: terminal drain returned incomplete receipt")
			} else {
				lastErr = err
			}
		}
		return ports.ProviderRunTerminalReceipt{}, registry, fmt.Errorf("review run: terminal drain: %w", lastErr)
	}
	fail := func(cause error) (*QualifiedRun, error) {
		receipt, registry, err := closeAdmitted(ctx)
		if err != nil {
			return nil, newQualifiedRunConstructionError(cause, ports.ProviderRunTerminalReceipt{}, registry)
		}
		return nil, newQualifiedRunConstructionError(cause, receipt)
	}

	routes := make([]QualifiedRoute, 0, len(candidates))
	for _, candidate := range candidates {
		definition := candidate.Definition
		registry, err := factory.registries.NewProviderQualificationRegistry(ctx, []ports.ProviderRuntimeDefinition{definition})
		if err != nil {
			if currentQualificationUnavailable(err) {
				failure, failureErr := newOperationalQualificationFailure(definition, err)
				if failureErr != nil {
					return fail(failureErr)
				}
				qualificationFailures = append(qualificationFailures, failure)
				continue
			}
			if retained, ok := factory.registries.RegistryFromConstructionError(err); ok {
				admitted[definition.Instance()] = retained
				admittedInstances = append(admittedInstances, definition.Instance())
				if namespace, retained := retained.QualificationNamespace(definition.Instance()); retained {
					admittedGenerations[definition.Instance()] = namespace.Generation()
				}
			}
			return fail(providerQualificationBoundaryError(definition, err, qualificationReasonCode(err, "qualification_failed")))
		}
		admitted[definition.Instance()] = registry
		admittedInstances = append(admittedInstances, definition.Instance())
		namespace, ok := registry.QualificationNamespace(definition.Instance())
		if !ok || namespace == nil || namespace.ProviderInstance() != definition.Instance() || namespace.Generation() == "" ||
			namespace.RuntimeSafetyPolicyIdentity() != definition.RuntimeSafetyPolicyIdentity() {
			if closeErr := release(ctx, definition.Instance()); closeErr != nil {
				return fail(fmt.Errorf("review run: production registry namespace for %q: terminal drain: %w", definition.Instance(), closeErr))
			}
			return fail(fmt.Errorf("review run: production registry did not retain namespace for %q", definition.Instance()))
		}
		admittedGenerations[definition.Instance()] = namespace.Generation()
		requestIdentity := qualificationIdentity(candidate, definition, namespace.Generation())
		result, qualificationErr := factory.qualifier.QualifyCurrent(ctx, CurrentQualificationRequest{
			Profile: candidate.Profile, Definition: definition, Identity: requestIdentity, Namespace: namespace,
			RequestedRoles: append([]domain.Role(nil), candidate.SupportedRoles...), BaseRole: candidate.BaseRole, Now: now,
		})
		if qualificationErr != nil {
			qualificationObservations = append(qualificationObservations, qualificationObservationsFromError(qualificationErr)...)
			if closeErr := release(ctx, definition.Instance()); closeErr != nil {
				return fail(fmt.Errorf("review run: current qualification for %q: %w; terminal drain: %v", definition.Instance(), qualificationErr, closeErr))
			}
			if _, loginRequired := ProviderLoginRequiredProvidersFromError(qualificationErr); loginRequired {
				return fail(fmt.Errorf("review run: current qualification for %q: %w", definition.Instance(), qualificationErr))
			}
			if currentQualificationUnavailable(qualificationErr) {
				failure, failureErr := newOperationalQualificationFailure(definition, qualificationErr)
				if failureErr != nil {
					return fail(failureErr)
				}
				qualificationFailures = append(qualificationFailures, failure)
				continue
			}
			return fail(providerQualificationBoundaryError(definition, qualificationErr, qualificationReasonCode(qualificationErr, "qualification_failed")))
		}
		qualificationObservations = append(qualificationObservations, result.Observations...)
		identity := requestIdentity
		identity.Version = result.Version
		profile := candidate.Profile.WithQualifiedVersion(result.VersionArgv, result.Version)
		qualification := ValidateQualification(QualificationInput{Identity: identity, Version: result.Version, KnownIncompatible: result.KnownIncompatible, Receipts: result.Receipts, Now: now})
		supportedRoles, roleErr := qualifiedSupportedRoles(candidate, result, identity)
		if profile.Classification() == VersionRed {
			if closeErr := release(ctx, definition.Instance()); closeErr != nil {
				return fail(fmt.Errorf("review run: below-minimum provider %q: terminal drain: %w", definition.Instance(), closeErr))
			}
			cause, causeErr := domain.NewFailure("reviewrun.qualification", domain.FailureConfiguration, "provider version is incompatible", nil)
			if causeErr != nil {
				return fail(causeErr)
			}
			failure, failureErr := NewProviderQualificationFailure(definition.Instance(), Family(definition.Family()), "version_incompatible", cause)
			if failureErr != nil {
				return fail(failureErr)
			}
			qualificationFailures = append(qualificationFailures, failure)
			continue
		}
		if !profile.Available() || (definition.Version() != "" && profile.Version() != definition.Version()) || !qualification.Available() || roleErr != nil {
			if closeErr := release(ctx, definition.Instance()); closeErr != nil {
				return fail(fmt.Errorf("review run: invalid current qualification for %q: terminal drain: %w", definition.Instance(), closeErr))
			}
			cause, causeErr := domain.NewFailure("reviewrun.qualification", domain.FailureProviderUnavailable, "current qualification is invalid", nil)
			if causeErr != nil {
				return fail(causeErr)
			}
			return fail(providerQualificationBoundaryError(definition, cause, "qualification_invalid"))
		}
		route, err := ports.NewProviderRoute(definition.Instance(), definition.ConcurrencyKey())
		if err != nil {
			if closeErr := release(ctx, definition.Instance()); closeErr != nil {
				return fail(fmt.Errorf("review run: provider route for %q: %w; terminal drain: %v", definition.Instance(), err, closeErr))
			}
			return fail(fmt.Errorf("review run: provider route for %q: %w", definition.Instance(), err))
		}
		ordinal, _ := familyOrdinal(identity.Family)
		qualified, err := NewQualifiedRoute(qualification, route, candidate.Limits, supportedRoles, result.BaseRole, ordinal)
		if err != nil {
			if closeErr := release(ctx, definition.Instance()); closeErr != nil {
				return fail(fmt.Errorf("review run: qualified route for %q: %w; terminal drain: %v", definition.Instance(), err, closeErr))
			}
			return fail(fmt.Errorf("review run: qualified route for %q: %w", definition.Instance(), err))
		}
		evidence, err := admittedEvidenceFromQualification(identity, result)
		if err != nil {
			if closeErr := release(ctx, definition.Instance()); closeErr != nil {
				return fail(fmt.Errorf("review run: retain admitted evidence for %q: %w; terminal drain: %v", definition.Instance(), err, closeErr))
			}
			return fail(fmt.Errorf("review run: retain admitted evidence for %q: %w", definition.Instance(), err))
		}
		routes = append(routes, qualified)
		admittedEvidence = append(admittedEvidence, evidence)
	}
	if len(routes) == 0 {
		receipt, registry, err := closeAdmitted(ctx)
		if err != nil {
			failure := providerQualificationReadinessError(qualificationFailures)
			return nil, newQualifiedRunConstructionError(failure, ports.ProviderRunTerminalReceipt{}, registry)
		}
		failure := providerQualificationReadinessError(qualificationFailures)
		return nil, newQualifiedRunConstructionError(failure, receipt)
	}
	retainedInstances := make([]string, 0, len(routes))
	for _, instance := range admittedInstances {
		if _, ok := admitted[instance]; ok {
			retainedInstances = append(retainedInstances, instance)
		}
	}
	return &QualifiedRun{
		routes: routes, registry: &qualifiedRunRegistryComposite{
			registries: admitted, generations: admittedGenerations, instances: retainedInstances,
		},
		admitted: admittedEvidence, qualificationFailures: append([]ProviderQualificationFailure(nil), qualificationFailures...),
		qualificationObservations: append([]ProviderQualificationObservation(nil), qualificationObservations...),
	}, nil
}

func validateQualifiedRunCandidate(candidate QualifiedRunCandidate, seen map[string]struct{}) error {
	if !candidate.Profile.Family().Valid() || !candidate.Limits.Valid() || candidate.SnapshotManifest == "" {
		return fmt.Errorf("review run: invalid qualified run candidate")
	}
	if _, err := canonicalQualificationRoles(candidate.BaseRole, candidate.SupportedRoles); err != nil {
		return fmt.Errorf("review run: invalid qualified run candidate: %w", err)
	}
	definition := candidate.Definition
	if Family(definition.Family()) != candidate.Profile.Family() || definition.Instance() == "" || definition.Executable() != candidate.Profile.Executable() || definition.ExecutableSHA256() != candidate.Profile.SHA256() || definition.Launcher() != candidate.Profile.Launcher() || definition.LauncherSHA256() != candidate.Profile.LauncherSHA256() {
		return fmt.Errorf("review run: discovered profile does not match production definition")
	}
	if _, duplicate := seen[definition.Instance()]; duplicate {
		return fmt.Errorf("review run: duplicate provider instance %q", definition.Instance())
	}
	seen[definition.Instance()] = struct{}{}
	return nil
}

func qualificationIdentity(candidate QualifiedRunCandidate, definition ports.ProviderRuntimeDefinition, generation string) Identity {
	return Identity{
		Family: Family(definition.Family()), Instance: definition.Instance(), ProfileGeneration: definition.ProfileGeneration(),
		AdapterProfile: definition.ProfileID(), Version: definition.Version(), Executable: definition.Executable(),
		ExecutableSHA256: definition.ExecutableSHA256(), Launcher: definition.Launcher(), LauncherSHA256: definition.LauncherSHA256(),
		SnapshotManifest: candidate.SnapshotManifest, NamespaceLease: definition.Instance() + ":" + generation, NamespaceGeneration: generation,
	}
}

func admittedEvidenceFromQualification(identity Identity, result CurrentQualificationResult) (qualifiedProviderEvidence, error) {
	qualificationIDs := make([]string, 0, len(result.Receipts)+len(result.RoleReceipts))
	transportIDs := make([]string, 0, 1)
	for _, receipt := range result.Receipts {
		if receipt.Identity != identity || receipt.State != ReceiptPass {
			return qualifiedProviderEvidence{}, fmt.Errorf("invalid admitted qualification receipt")
		}
		id := qualificationReceiptID(receipt)
		if receipt.Kind == ReceiptTransport {
			transportIDs = append(transportIDs, id)
		} else {
			qualificationIDs = append(qualificationIDs, id)
		}
	}
	for _, receipt := range result.RoleReceipts {
		if receipt.Identity != identity || receipt.State != ReceiptPass {
			return qualifiedProviderEvidence{}, fmt.Errorf("invalid admitted role receipt")
		}
		qualificationIDs = append(qualificationIDs, currentRoleReceiptID(receipt))
	}
	if !canonicalizeReceiptIDs(qualificationIDs) || !canonicalizeReceiptIDs(transportIDs) {
		return qualifiedProviderEvidence{}, fmt.Errorf("invalid admitted receipt identities")
	}
	return qualifiedProviderEvidence{
		identity: identity, qualificationReceiptIDs: qualificationIDs, packetTransportReceiptIDs: transportIDs,
	}, nil
}

func qualificationReceiptID(receipt Receipt) string {
	return fmt.Sprintf("qualification:%x", sha256.Sum256([]byte(fmt.Sprintf("%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s",
		receipt.Kind, receipt.State, receipt.ExpiresAt.UTC().Format(time.RFC3339Nano), receipt.Identity.Family, receipt.Identity.Instance,
		receipt.Identity.ProfileGeneration, receipt.Identity.AdapterProfile, receipt.Identity.Version, receipt.Identity.Executable,
		receipt.Identity.ExecutableSHA256, receipt.Identity.Launcher, receipt.Identity.LauncherSHA256, receipt.Identity.SnapshotManifest,
		receipt.Identity.NamespaceLease, receipt.Identity.NamespaceGeneration, receipt.AuthorityID, receipt.AuthorityScope,
		receipt.Provenance.Version, receipt.Provenance.Path, receipt.Provenance.SHA256, receipt.Provenance.Profile))))
}

func currentRoleReceiptID(receipt CurrentRoleReceipt) string {
	return fmt.Sprintf("role:%x", sha256.Sum256([]byte(fmt.Sprintf("%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s",
		receipt.Role, receipt.State, receipt.Identity.Family, receipt.Identity.Instance, receipt.Identity.ProfileGeneration,
		receipt.Identity.AdapterProfile, receipt.Identity.Version, receipt.Identity.Executable, receipt.Identity.ExecutableSHA256,
		receipt.Identity.Launcher, receipt.Identity.LauncherSHA256, receipt.Identity.SnapshotManifest, receipt.Identity.NamespaceLease,
		receipt.Identity.NamespaceGeneration))))
}

func canonicalizeReceiptIDs(ids []string) bool {
	sort.Strings(ids)
	return canonicalReceiptIDs(ids)
}

func canonicalReceiptIDs(ids []string) bool {
	if len(ids) == 0 {
		return false
	}
	for index, id := range ids {
		if id == "" || (index > 0 && ids[index-1] >= id) {
			return false
		}
	}
	return true
}
func qualifiedSupportedRoles(candidate QualifiedRunCandidate, result CurrentQualificationResult, identity Identity) ([]domain.Role, error) {
	requested, err := canonicalQualificationRoles(candidate.BaseRole, candidate.SupportedRoles)
	if err != nil {
		return nil, fmt.Errorf("invalid declared role authority: %w", err)
	}
	reported, err := canonicalQualificationRoles(candidate.BaseRole, result.SupportedRoles)
	if err != nil {
		return nil, fmt.Errorf("invalid current supported roles: %w", err)
	}
	if len(reported) != len(requested) {
		return nil, fmt.Errorf("current supported roles do not match requested authority")
	}
	for index, role := range requested {
		if reported[index] != role {
			return nil, fmt.Errorf("current supported roles do not match requested authority")
		}
	}
	if !result.BaseRole.Valid() || result.BaseRole != candidate.BaseRole {
		return nil, fmt.Errorf("invalid current base role")
	}
	seen := make(map[domain.Role]struct{}, len(result.RoleReceipts))
	for _, receipt := range result.RoleReceipts {
		if !receipt.Role.Valid() || receipt.State != ReceiptPass || receipt.Identity != identity {
			return nil, fmt.Errorf("invalid current role receipt")
		}
		if _, duplicate := seen[receipt.Role]; duplicate {
			return nil, fmt.Errorf("duplicate current role receipt")
		}
		seen[receipt.Role] = struct{}{}
	}
	if len(seen) != len(requested) {
		return nil, fmt.Errorf("current role receipts do not match requested authority")
	}
	for _, role := range requested {
		if _, ok := seen[role]; !ok {
			return nil, fmt.Errorf("requested role did not qualify")
		}
	}
	return requested, nil
}

type qualifiedRunConstructionError struct {
	cause     error
	receipt   ports.ProviderRunTerminalReceipt
	registry  QualifiedRunRegistry
	authority RunAuthority
}

func newQualifiedRunConstructionError(cause error, receipt ports.ProviderRunTerminalReceipt, registries ...QualifiedRunRegistry) error {
	var registry QualifiedRunRegistry
	if len(registries) > 0 {
		registry = registries[0]
	}
	if registry == nil && !receipt.Valid() {
		return cause
	}
	construction := &qualifiedRunConstructionError{cause: cause, receipt: receipt, registry: registry}
	if registry != nil {
		construction.authority = &registryCleanupAuthority{registry: registry}
	}
	return construction
}

func newQualifiedRunConstructionErrorWithAuthority(cause error, authority RunAuthority) error {
	if nilInterface(authority) {
		return cause
	}
	return &qualifiedRunConstructionError{cause: cause, authority: authority}
}

func (err *qualifiedRunConstructionError) Error() string { return err.cause.Error() }
func (err *qualifiedRunConstructionError) Unwrap() error { return err.cause }

// ProviderRunTerminalReceiptFromError exposes complete cleanup proof from a
// failed construction. It returns false while cleanup remains retryable.
func ProviderRunTerminalReceiptFromError(err error) (ports.ProviderRunTerminalReceipt, bool) {
	var terminal interface {
		ProviderRunTerminalReceipt() ports.ProviderRunTerminalReceipt
	}
	if !errors.As(err, &terminal) {
		return ports.ProviderRunTerminalReceipt{}, false
	}
	receipt := terminal.ProviderRunTerminalReceipt()
	return receipt, receipt.Valid()
}

func (err *qualifiedRunConstructionError) ProviderRunTerminalReceipt() ports.ProviderRunTerminalReceipt {
	if err.registry != nil || err.authority != nil {
		return ports.ProviderRunTerminalReceipt{}
	}
	return err.receipt
}

// QualifiedRunRegistryFromError exposes the acquisition-owned cleanup authority
// when construction cleanup exhausted its bounded retries.
func QualifiedRunRegistryFromError(err error) (QualifiedRunRegistry, bool) {
	var retained interface {
		QualifiedRunRegistry() QualifiedRunRegistry
	}
	if !errors.As(err, &retained) {
		return nil, false
	}
	registry := retained.QualifiedRunRegistry()
	return registry, !nilInterface(registry)
}

func (err *qualifiedRunConstructionError) QualifiedRunRegistry() QualifiedRunRegistry {
	return err.registry
}

// RunAuthorityFromError exposes the qualified-run cleanup owner retained after
// planner construction exhausts its bounded cleanup retries.
func RunAuthorityFromError(err error) (RunAuthority, bool) {
	var retained interface {
		RunAuthority() RunAuthority
	}
	if !errors.As(err, &retained) {
		return nil, false
	}
	authority := retained.RunAuthority()
	return authority, !nilInterface(authority)
}

func (err *qualifiedRunConstructionError) RunAuthority() RunAuthority {
	return err.authority
}

func currentQualificationUnavailable(err error) bool {
	var failure *domain.Failure
	if !errors.As(err, &failure) {
		return false
	}
	switch failure.Class() {
	case domain.FailureProviderUnavailable, domain.FailureAuthentication, domain.FailureTimeout, domain.FailureQuota, domain.FailureRateLimit:
		return true
	case domain.FailureInvalidOutput:
		return failure.Stage() == "reviewrun.current.capability"
	default:
		return false
	}
}

func qualificationReasonCode(err error, fallback string) string {
	var failure *domain.Failure
	if errors.As(err, &failure) && failure != nil && failure.Class().Valid() {
		return string(failure.Class())
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return string(domain.FailureTimeout)
	}
	if errors.Is(err, context.Canceled) {
		return string(domain.FailureCancelled)
	}
	return fallback
}

func closeQualifiedRunRegistry(ctx context.Context, registry QualifiedRunRegistry, instance, generation string) (ports.ProviderRunTerminalReceipt, error) {
	if ctx == nil {
		return ports.ProviderRunTerminalReceipt{}, fmt.Errorf("review run: invalid terminal close context")
	}
	receipt, err := registry.Close(ctx)
	if err != nil {
		return ports.ProviderRunTerminalReceipt{}, err
	}
	receipts := receipt.NamespaceReceipts()
	if !receipt.Valid() || receipt.NoNamespaces() || len(receipts) != 1 || receipts[0].ProviderInstance() != instance ||
		(generation != "" && receipts[0].Generation() != generation) {
		return ports.ProviderRunTerminalReceipt{}, fmt.Errorf("review run: invalid terminal receipt for %q", instance)
	}
	return receipt, nil
}

func (registry *qualifiedRunRegistryComposite) QualificationNamespace(instance string) (ports.ProviderQualificationNamespace, bool) {
	if registry == nil {
		return nil, false
	}
	child, ok := registry.registries[instance]
	if !ok {
		return nil, false
	}
	return child.QualificationNamespace(instance)
}

func (registry *qualifiedRunRegistryComposite) Observe(ctx context.Context, invocation ports.ProviderInvocation) (ports.ProviderExecutionObservation, error) {
	if registry == nil {
		return ports.ProviderExecutionObservation{}, fmt.Errorf("review run: admitted registry unavailable")
	}
	child, ok := registry.registries[invocation.ProviderInstance()]
	if !ok {
		return ports.ProviderExecutionObservation{}, fmt.Errorf("review run: provider instance %q was not admitted", invocation.ProviderInstance())
	}
	return child.Observe(ctx, invocation)
}

func (registry *qualifiedRunRegistryComposite) Close(ctx context.Context) (ports.ProviderRunTerminalReceipt, error) {
	if registry == nil || ctx == nil {
		return ports.ProviderRunTerminalReceipt{}, fmt.Errorf("review run: invalid admitted registry close")
	}
	registry.closeMu.Lock()
	defer registry.closeMu.Unlock()
	if registry.receipt.Valid() {
		return registry.receipt, nil
	}
	instances := append([]string(nil), registry.instances...)
	sort.Strings(instances)
	if registry.closed == nil {
		registry.closed = make(map[string]ports.ProviderRunTerminalReceipt, len(instances))
	}
	receipts := make([]ports.ProviderNamespaceTerminalReceipt, 0, len(instances))
	for _, instance := range instances {
		receipt, closed := registry.closed[instance]
		if !closed {
			child, ok := registry.registries[instance]
			if !ok || child == nil {
				return ports.ProviderRunTerminalReceipt{}, fmt.Errorf("review run: admitted registry unavailable for %q", instance)
			}
			var err error
			receipt, err = closeQualifiedRunRegistry(ctx, child, instance, registry.generations[instance])
			if err != nil {
				return ports.ProviderRunTerminalReceipt{}, err
			}
			registry.closed[instance] = receipt
		}
		receipts = append(receipts, receipt.NamespaceReceipts()...)
	}
	aggregate, err := ports.NewProviderRunTerminalReceipt(receipts)
	if err != nil {
		return ports.ProviderRunTerminalReceipt{}, err
	}
	registry.receipt = aggregate
	return aggregate, nil
}

// Routes returns caller-owned immutable planning authorities.
func (run *QualifiedRun) Routes() []QualifiedRoute {
	if run == nil {
		return nil
	}
	return append([]QualifiedRoute(nil), run.routes...)
}

// QualificationFailures returns safe rejected configured-candidate facts.
func (run *QualifiedRun) QualificationFailures() []ProviderQualificationFailure {
	if run == nil {
		return nil
	}
	return append([]ProviderQualificationFailure(nil), run.qualificationFailures...)
}

// QualificationObservations returns ordered, safe probe-attempt facts.
func (run *QualifiedRun) QualificationObservations() []ProviderQualificationObservation {
	if run == nil {
		return nil
	}
	return append([]ProviderQualificationObservation(nil), run.qualificationObservations...)
}

// Registry returns the run-owned production execution authority.
func (run *QualifiedRun) Registry() QualifiedRunRegistry {
	if run == nil {
		return nil
	}
	return run.registry
}

// QualifiedRunTerminalReceipt records a successful terminal drain of every
// namespace retained by the run.
type QualifiedRunTerminalReceipt struct {
	receipt     ports.ProviderRunTerminalReceipt
	providers   []QualifiedProviderTerminalEvidence
	cleanupOnly bool
}

func (receipt QualifiedRunTerminalReceipt) Instances() []string {
	instances := make([]string, len(receipt.providers))
	for index, provider := range receipt.providers {
		instances[index] = provider.Identity().Instance
	}
	return instances
}

func (receipt QualifiedRunTerminalReceipt) Drained() bool {
	return receipt.receipt.Valid() && (receipt.cleanupOnly || len(receipt.providers) > 0)
}

func (receipt QualifiedRunTerminalReceipt) ProviderRunTerminalReceipt() ports.ProviderRunTerminalReceipt {
	return receipt.receipt
}

func (receipt QualifiedRunTerminalReceipt) Providers() []QualifiedProviderTerminalEvidence {
	providers := append([]QualifiedProviderTerminalEvidence(nil), receipt.providers...)
	for index := range providers {
		providers[index].qualificationReceiptIDs = append([]string(nil), providers[index].qualificationReceiptIDs...)
		providers[index].packetTransportReceiptIDs = append([]string(nil), providers[index].packetTransportReceiptIDs...)
	}
	return providers
}

func (receipt QualifiedRunTerminalReceipt) NamespaceReceipts() []ports.ProviderNamespaceTerminalReceipt {
	return receipt.receipt.NamespaceReceipts()
}

// DrainTerminal closes the registry once all calls have finished. It joins the
// actual namespace terminal receipts to exactly the providers admitted earlier.
func (run *QualifiedRun) DrainTerminal(ctx context.Context) (QualifiedRunTerminalReceipt, error) {
	if run == nil || ctx == nil || nilInterface(run.registry) {
		return QualifiedRunTerminalReceipt{}, fmt.Errorf("review run: invalid qualified run terminal drain")
	}
	run.terminalMu.Lock()
	defer run.terminalMu.Unlock()
	if run.receipt.Drained() {
		return run.receipt, nil
	}
	receipt, err := run.registry.Close(ctx)
	if err != nil {
		return QualifiedRunTerminalReceipt{}, err
	}
	terminal, err := newQualifiedRunTerminalReceipt(run.admitted, receipt)
	if err != nil {
		return QualifiedRunTerminalReceipt{}, err
	}
	run.receipt = terminal
	return terminal, nil
}

func newQualifiedRunTerminalReceipt(admitted []qualifiedProviderEvidence, receipt ports.ProviderRunTerminalReceipt) (QualifiedRunTerminalReceipt, error) {
	if !receipt.Valid() || receipt.NoNamespaces() || len(admitted) == 0 {
		return QualifiedRunTerminalReceipt{}, fmt.Errorf("review run: qualified run terminal drain incomplete")
	}
	namespaces := receipt.NamespaceReceipts()
	if len(namespaces) != len(admitted) {
		return QualifiedRunTerminalReceipt{}, fmt.Errorf("review run: terminal receipt set does not match admitted providers")
	}
	byInstance := make(map[string]ports.ProviderNamespaceTerminalReceipt, len(namespaces))
	for _, namespace := range namespaces {
		if !namespace.Valid() {
			return QualifiedRunTerminalReceipt{}, fmt.Errorf("review run: invalid namespace terminal receipt")
		}
		if _, exists := byInstance[namespace.ProviderInstance()]; exists {
			return QualifiedRunTerminalReceipt{}, fmt.Errorf("review run: duplicate namespace terminal receipt")
		}
		byInstance[namespace.ProviderInstance()] = namespace
	}
	providers := make([]QualifiedProviderTerminalEvidence, 0, len(admitted))
	seen := make(map[string]struct{}, len(admitted))
	for _, admittedProvider := range admitted {
		if !admittedProvider.identity.complete() {
			return QualifiedRunTerminalReceipt{}, fmt.Errorf("review run: invalid admitted provider evidence")
		}
		instance := admittedProvider.identity.Instance
		namespace, ok := byInstance[instance]
		if !ok {
			return QualifiedRunTerminalReceipt{}, fmt.Errorf("review run: missing namespace terminal receipt for %q", instance)
		}
		if namespace.Generation() != admittedProvider.identity.NamespaceGeneration {
			return QualifiedRunTerminalReceipt{}, fmt.Errorf("review run: stale namespace terminal receipt for %q", instance)
		}
		if _, exists := seen[instance]; exists {
			return QualifiedRunTerminalReceipt{}, fmt.Errorf("review run: duplicate admitted provider %q", instance)
		}
		seen[instance] = struct{}{}
		provider := QualifiedProviderTerminalEvidence{
			identity:                   admittedProvider.identity,
			qualificationReceiptIDs:    append([]string(nil), admittedProvider.qualificationReceiptIDs...),
			packetTransportReceiptIDs:  append([]string(nil), admittedProvider.packetTransportReceiptIDs...),
			namespaceTerminalReceiptID: namespace.ReceiptID(),
		}
		if !provider.Valid() {
			return QualifiedRunTerminalReceipt{}, fmt.Errorf("review run: invalid terminal provider evidence")
		}
		providers = append(providers, provider)
	}
	sort.Slice(providers, func(left, right int) bool {
		if providers[left].identity.Family != providers[right].identity.Family {
			return providers[left].identity.Family < providers[right].identity.Family
		}
		return providers[left].identity.Instance < providers[right].identity.Instance
	})
	return QualifiedRunTerminalReceipt{receipt: receipt, providers: providers}, nil
}
