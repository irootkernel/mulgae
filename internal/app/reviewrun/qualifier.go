package reviewrun

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/irootkernel/mulgae/internal/app/review"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

// CurrentQualifier performs the isolated current checks for one discovered
// provider. It must never use the host HOME or working directory: the supplied
// identity names the namespace retained by the run-owned registry. VersionArgv
// must be the exact discovered invocation plus "--version".
type CurrentQualifier interface {
	QualifyCurrent(context.Context, CurrentQualificationRequest) (CurrentQualificationResult, error)
}

// FamilyRouteDeriver derives exact sibling-route admission from one live family
// qualification without copying the representative authority identity.
type FamilyRouteDeriver interface {
	DeriveEquivalentFamilyRoute(context.Context, FamilyRouteDerivationRequest) (CurrentQualificationResult, error)
}

// FamilyRouteDerivationRequest binds one live family result to a sibling route.
type FamilyRouteDerivationRequest struct {
	Source               CurrentQualificationResult
	SourceDefinition     ports.ProviderRuntimeDefinition
	SourceNamespaceGen   string
	Destination          QualifiedRunCandidate
	DestinationIdentity  Identity
	DestinationNamespace ports.ProviderQualificationNamespace
	Now                  time.Time
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
// receipt-backed role authority. familyAuthority is the adapter-minted exact
// direct-execution authority for the probed definition and is never remapped by
// rewriting app-layer identity fields.
type CurrentQualificationResult struct {
	VersionArgv       []string
	Version           string
	KnownIncompatible bool
	Receipts          []Receipt
	SupportedRoles    []domain.Role
	RoleReceipts      []CurrentRoleReceipt
	BaseRole          domain.Role
	Observations      []ProviderQualificationObservation

	familyAuthority           ports.ProviderDirectExecutionAuthority
	familyDefinition          ports.ProviderRuntimeDefinition
	familyNamespaceGeneration string
	familyProvedRoles         []domain.Role
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
	groups, err := groupCandidatesByFamilyRuntimeProfile(candidates)
	if err != nil {
		return nil, err
	}
	batches := scheduleFamilyQualificationGroups(groups)
	admission, admitErr := runFamilyQualificationBatches(ctx, batches, func(ctx context.Context, group familyQualificationGroup) (familyGroupAdmission, error) {
		return factory.admitFamilyQualificationGroup(ctx, group, now)
	})
	cleanupFailures := 0
	closeAdmitted := func(parent context.Context) (ports.ProviderRunTerminalReceipt, QualifiedRunRegistry, error) {
		if len(admission.admitted) == 0 {
			return ports.NewEmptyProviderRunTerminalReceipt(), nil, nil
		}
		registry := &qualifiedRunRegistryComposite{
			registries: admission.admitted, generations: admission.generations,
			instances: append([]string(nil), admission.instances...), closed: admission.closedReceipt,
		}
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
	if admitErr != nil {
		receipt, registry, err := closeAdmitted(ctx)
		if err != nil {
			return nil, newQualifiedRunConstructionError(admitErr, ports.ProviderRunTerminalReceipt{}, registry)
		}
		return nil, newQualifiedRunConstructionError(admitErr, receipt)
	}
	if len(admission.routes) == 0 {
		receipt, registry, err := closeAdmitted(ctx)
		failure := providerQualificationReadinessError(admission.failures)
		if err != nil {
			return nil, newQualifiedRunConstructionError(failure, ports.ProviderRunTerminalReceipt{}, registry)
		}
		return nil, newQualifiedRunConstructionError(failure, receipt)
	}
	retainedInstances := make([]string, 0, len(admission.routes))
	for _, instance := range admission.instances {
		if _, ok := admission.admitted[instance]; ok {
			retainedInstances = append(retainedInstances, instance)
		}
	}
	return &QualifiedRun{
		routes: admission.routes, registry: &qualifiedRunRegistryComposite{
			registries: admission.admitted, generations: admission.generations, instances: retainedInstances,
		},
		admitted: admission.evidence, qualificationFailures: append([]ProviderQualificationFailure(nil), admission.failures...),
		qualificationObservations: append([]ProviderQualificationObservation(nil), admission.observations...),
	}, nil
}

func (factory *QualifiedRunFactory) admitFamilyQualificationGroup(ctx context.Context, group familyQualificationGroup, now time.Time) (familyGroupAdmission, error) {
	admission := familyGroupAdmission{
		admitted:      make(map[string]QualifiedRunRegistry, len(group.candidates)),
		generations:   make(map[string]string, len(group.candidates)),
		closedReceipt: make(map[string]ports.ProviderRunTerminalReceipt, len(group.candidates)),
	}
	release := func(instance string) error {
		registry, ok := admission.admitted[instance]
		if !ok {
			return nil
		}
		receipt, err := closeQualifiedRunRegistry(ctx, registry, instance, admission.generations[instance])
		if err != nil {
			return err
		}
		admission.closedReceipt[instance] = receipt
		delete(admission.admitted, instance)
		delete(admission.generations, instance)
		return nil
	}
	releaseAll := func() {
		for _, instance := range append([]string(nil), admission.instances...) {
			_ = release(instance)
		}
	}
	for _, candidate := range group.candidates {
		definition := candidate.Definition
		registry, err := factory.registries.NewProviderQualificationRegistry(ctx, []ports.ProviderRuntimeDefinition{definition})
		if err != nil {
			if currentQualificationUnavailable(err) {
				failure, failureErr := newOperationalQualificationFailure(definition, err)
				if failureErr != nil {
					releaseAll()
					return admission, failureErr
				}
				admission.failures = append(admission.failures, failure)
				continue
			}
			if retained, ok := factory.registries.RegistryFromConstructionError(err); ok {
				admission.admitted[definition.Instance()] = retained
				admission.instances = append(admission.instances, definition.Instance())
				if namespace, retainedNS := retained.QualificationNamespace(definition.Instance()); retainedNS {
					admission.generations[definition.Instance()] = namespace.Generation()
				}
			}
			releaseAll()
			return admission, providerQualificationBoundaryError(definition, err, qualificationReasonCode(err, "qualification_failed"))
		}
		admission.admitted[definition.Instance()] = registry
		admission.instances = append(admission.instances, definition.Instance())
		namespace, ok := registry.QualificationNamespace(definition.Instance())
		if !ok || namespace == nil || namespace.ProviderInstance() != definition.Instance() || namespace.Generation() == "" ||
			namespace.RuntimeSafetyPolicyIdentity() != definition.RuntimeSafetyPolicyIdentity() {
			_ = release(definition.Instance())
			releaseAll()
			return admission, fmt.Errorf("review run: production registry did not retain namespace for %q", definition.Instance())
		}
		admission.generations[definition.Instance()] = namespace.Generation()
	}
	if len(admission.admitted) == 0 {
		return admission, nil
	}
	representative := group.candidates[group.representative]
	repDefinition := representative.Definition
	if _, retained := admission.admitted[repDefinition.Instance()]; !retained {
		for index, candidate := range group.candidates {
			if _, ok := admission.admitted[candidate.Definition.Instance()]; ok {
				representative = candidate
				group.representative = index
				repDefinition = candidate.Definition
				break
			}
		}
	}
	repRegistry, ok := admission.admitted[repDefinition.Instance()]
	if !ok {
		releaseAll()
		return admission, fmt.Errorf("review run: representative namespace unavailable for %q", repDefinition.Instance())
	}
	repNamespace, ok := repRegistry.QualificationNamespace(repDefinition.Instance())
	if !ok {
		releaseAll()
		return admission, fmt.Errorf("review run: representative namespace unavailable for %q", repDefinition.Instance())
	}
	requestIdentity := qualificationIdentity(representative, repDefinition, repNamespace.Generation())
	familyResult, qualificationErr := factory.qualifier.QualifyCurrent(ctx, CurrentQualificationRequest{
		Profile: representative.Profile, Definition: repDefinition, Identity: requestIdentity, Namespace: repNamespace,
		RequestedRoles: append([]domain.Role(nil), group.roles...), BaseRole: group.baseRole, Now: now,
	})
	if qualificationErr != nil {
		admission.observations = append(admission.observations, qualificationObservationsFromError(qualificationErr)...)
		if _, loginRequired := ProviderLoginRequiredProvidersFromError(qualificationErr); loginRequired {
			// Leave namespaces admitted so the factory-level drain owns cleanup proof.
			return admission, fmt.Errorf("review run: current qualification for %q: %w", repDefinition.Instance(), qualificationErr)
		}
		if currentQualificationUnavailable(qualificationErr) {
			failedCandidates := make([]QualifiedRunCandidate, 0, len(group.candidates))
			for _, candidate := range group.candidates {
				if _, retained := admission.admitted[candidate.Definition.Instance()]; retained {
					failedCandidates = append(failedCandidates, candidate)
				}
			}
			releaseAll()
			for _, candidate := range failedCandidates {
				failure, failureErr := newOperationalQualificationFailure(candidate.Definition, qualificationErr)
				if failureErr != nil {
					return admission, failureErr
				}
				admission.failures = append(admission.failures, failure)
			}
			return admission, nil
		}
		// Leave namespaces admitted so construction cleanup can retain or prove drain.
		return admission, providerQualificationBoundaryError(repDefinition, qualificationErr, qualificationReasonCode(qualificationErr, "qualification_failed"))
	}
	// Attempt-1 rejections survive a successful bounded retry so runtime
	// diagnostics still record the transient probe failure.
	for _, observation := range familyResult.Observations {
		if observation.Outcome() == qualificationOutcomeRejected {
			admission.observations = append(admission.observations, observation)
		}
	}
	deriver, hasDeriver := factory.qualifier.(FamilyRouteDeriver)
	for _, candidate := range group.candidates {
		definition := candidate.Definition
		if _, retained := admission.admitted[definition.Instance()]; !retained {
			continue
		}
		namespaceGeneration := admission.generations[definition.Instance()]
		identity := qualificationIdentity(candidate, definition, namespaceGeneration)
		var result CurrentQualificationResult
		var routeErr error
		if definition.Instance() == repDefinition.Instance() &&
			namespaceGeneration == admission.generations[repDefinition.Instance()] {
			result, routeErr = remapCurrentQualificationResult(familyResult, identity, candidate.SupportedRoles, candidate.BaseRole)
		} else if hasDeriver {
			namespace, ok := admission.admitted[definition.Instance()].QualificationNamespace(definition.Instance())
			if !ok {
				releaseAll()
				return admission, fmt.Errorf("review run: destination namespace unavailable for %q", definition.Instance())
			}
			result, routeErr = deriver.DeriveEquivalentFamilyRoute(ctx, FamilyRouteDerivationRequest{
				Source: familyResult, SourceDefinition: repDefinition,
				SourceNamespaceGen: admission.generations[repDefinition.Instance()],
				Destination:        candidate, DestinationIdentity: identity, DestinationNamespace: namespace, Now: now,
			})
		} else {
			routeErr = fmt.Errorf("family route derivation unavailable for sibling instance %q", definition.Instance())
		}
		if routeErr != nil {
			releaseAll()
			return admission, fmt.Errorf("review run: derive family qualification for %q: %w", definition.Instance(), routeErr)
		}
		identity.Version = result.Version
		profile := candidate.Profile.WithQualifiedVersion(result.VersionArgv, result.Version)
		qualification := ValidateQualification(QualificationInput{Identity: identity, Version: result.Version, KnownIncompatible: result.KnownIncompatible, Receipts: result.Receipts, Now: now})
		supportedRoles, roleErr := qualifiedSupportedRoles(candidate, result, identity)
		if profile.Classification() == VersionRed {
			_ = release(definition.Instance())
			cause, causeErr := domain.NewFailure("reviewrun.qualification", domain.FailureConfiguration, "provider version is incompatible", nil)
			if causeErr != nil {
				releaseAll()
				return admission, causeErr
			}
			failure, failureErr := NewProviderQualificationFailure(definition.Instance(), Family(definition.Family()), "version_incompatible", cause)
			if failureErr != nil {
				releaseAll()
				return admission, failureErr
			}
			admission.failures = append(admission.failures, failure)
			continue
		}
		if !profile.Available() || (definition.Version() != "" && profile.Version() != definition.Version()) || !qualification.Available() || roleErr != nil {
			releaseAll()
			cause, causeErr := domain.NewFailure("reviewrun.qualification", domain.FailureProviderUnavailable, "current qualification is invalid", nil)
			if causeErr != nil {
				return admission, causeErr
			}
			return admission, providerQualificationBoundaryError(definition, cause, "qualification_invalid")
		}
		route, err := ports.NewProviderRoute(definition.Instance(), definition.ConcurrencyKey())
		if err != nil {
			releaseAll()
			return admission, fmt.Errorf("review run: provider route for %q: %w", definition.Instance(), err)
		}
		ordinal, _ := familyOrdinal(identity.Family)
		qualified, err := NewQualifiedRoute(qualification, route, candidate.Limits, supportedRoles, result.BaseRole, ordinal)
		if err != nil {
			releaseAll()
			return admission, fmt.Errorf("review run: qualified route for %q: %w", definition.Instance(), err)
		}
		evidence, err := admittedEvidenceFromQualification(identity, result)
		if err != nil {
			releaseAll()
			return admission, fmt.Errorf("review run: retain admitted evidence for %q: %w", definition.Instance(), err)
		}
		admission.routes = append(admission.routes, qualified)
		admission.evidence = append(admission.evidence, evidence)
		// Emit one candidate-checked observation per admitted route, including
		// siblings that inherit readiness from a shared family probe.
		admission.observations = append(admission.observations, qualifiedQualificationObservation(definition.Instance()))
	}
	return admission, nil
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
		failure, _ := ports.NewProviderRuntimeError(domain.DiagnosticCauseProviderExecutionFailed, fmt.Errorf("review run: admitted registry unavailable"))
		return ports.ProviderExecutionObservation{}, failure
	}
	child, ok := registry.registries[invocation.ProviderInstance()]
	if !ok {
		failure, _ := ports.NewProviderRuntimeError(domain.DiagnosticCauseProviderExecutionFailed, fmt.Errorf("review run: provider instance %q was not admitted", invocation.ProviderInstance()))
		return ports.ProviderExecutionObservation{}, failure
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
