package reviewrun

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

const (
	currentQualificationTTL       = time.Minute
	currentQualificationDrainWait = 5 * time.Second
)

// ProviderCurrentQualifier adapts descriptor-bound provider probes into
// provider-independent current admission evidence.
type ProviderCurrentQualifier struct {
	probe    ports.ProviderCurrentProbe
	fixtures ports.ProviderQualificationFixtureFactory
	deriver  ports.ProviderEquivalentRouteAuthorityDeriver
}

var _ CurrentQualifier = (*ProviderCurrentQualifier)(nil)
var _ FamilyRouteDeriver = (*ProviderCurrentQualifier)(nil)

// NewProviderCurrentQualifier constructs the production current qualifier.
func NewProviderCurrentQualifier(probe ports.ProviderCurrentProbe, fixtures ports.ProviderQualificationFixtureFactory) (*ProviderCurrentQualifier, error) {
	if nilInterface(probe) || nilInterface(fixtures) {
		return nil, fmt.Errorf("review run: current qualifier dependencies unavailable")
	}
	qualifier := &ProviderCurrentQualifier{probe: probe, fixtures: fixtures}
	if deriver, ok := probe.(ports.ProviderEquivalentRouteAuthorityDeriver); ok {
		qualifier.deriver = deriver
	}
	return qualifier, nil
}

// QualifyCurrent acquires one base-role fixture, performs one descriptor-bound
// family/runtime probe, and derives role admission from that evidence. Invalid
// capability formatting, capability evidence mismatches, security failures, and
// login-required responses are never retried; one transient operational probe
// failure admits at most one additional probe on a freshly materialized fixture
// under the same expiry basis. Every acquired fixture is drained exactly once
// before it returns, and the attempt-1 rejection stays in the observations.
func (qualifier *ProviderCurrentQualifier) QualifyCurrent(ctx context.Context, request CurrentQualificationRequest) (result CurrentQualificationResult, err error) {
	if qualifier == nil || nilInterface(qualifier.probe) || nilInterface(qualifier.fixtures) || ctx == nil || request.Now.IsZero() {
		return CurrentQualificationResult{}, fmt.Errorf("review run: invalid current qualification authority")
	}
	roles, err := qualifier.rolesFor(request)
	if err != nil {
		return CurrentQualificationResult{}, err
	}

	fixtures := make([]ports.ProviderQualificationFixtureLease, 0, 2)
	defer func() {
		if cleanupErr := drainProbeFixtures(fixtures); cleanupErr != nil {
			failure, failureErr := domain.NewFailure("reviewrun.current.cleanup", domain.FailureInternal, "qualification fixture cleanup failed", cleanupErr)
			if failureErr != nil {
				cleanupErr = failureErr
			} else {
				cleanupErr = failure
			}
			if err != nil {
				err = errors.Join(cleanupErr, err)
			} else {
				result = CurrentQualificationResult{}
				err = cleanupErr
			}
		}
	}()

	base, acquireErr := qualifier.acquire(ctx, request.BaseRole, &fixtures)
	if acquireErr != nil {
		return CurrentQualificationResult{}, acquireErr
	}

	provider := request.Definition.Instance()
	probeRequest := ports.ProviderCurrentProbeRequest{
		Definition: request.Definition, Namespace: request.Namespace, Fixture: base, RoleFixtures: nil,
		Now: request.Now, TTL: currentQualificationTTL,
	}
	probeResult, probeErr := qualifier.probe.QualifyProviderCurrent(ctx, probeRequest)
	observations := make([]ProviderQualificationObservation, 0, 2)
	if probeErr != nil && ctx.Err() == nil && retryableOperationalProbeFailure(probeErr) {
		// One bounded retry on a fresh fixture: a transient provider execution
		// failure must never reuse the consumed workspace, and a fixture
		// acquisition failure must never mask the original provider failure.
		retryFixture, retryAcquireErr := qualifier.acquire(ctx, request.BaseRole, &fixtures)
		if retryAcquireErr == nil {
			observations = append(observations, rejectedQualificationObservation(provider, probeErr, true))
			probeRequest.Fixture = retryFixture
			probeResult, probeErr = qualifier.probe.QualifyProviderCurrent(ctx, probeRequest)
		}
	}
	if probeErr != nil {
		observations = append(observations, rejectedQualificationObservation(provider, probeErr, false))
		if errors.Is(probeErr, ports.ErrProviderLoginRequired) {
			return CurrentQualificationResult{}, withQualificationObservations(newProviderLoginRequiredError([]string{provider}, probeErr), observations)
		}
		return CurrentQualificationResult{}, withQualificationObservations(admissionProbeError(probeErr), observations)
	}
	observations = append(observations, qualifiedQualificationObservation(provider))
	observed := request.Identity
	observed.Version = probeResult.Version
	// Direct-execution Matches binds the exact probed role set; family role
	// admission is derived at the application layer from that exact proof.
	provedRoles := []domain.Role{request.BaseRole}
	familyAuthority, authorityErr := directExecutionAuthorityFromProbeReceipts(probeResult.Receipts)
	if authorityErr != nil {
		return CurrentQualificationResult{}, authorityErr
	}
	receipts, receiptErr := currentProbeAppReceipts(
		probeResult.Receipts,
		observed,
		request.Definition,
		request.Namespace.Generation(),
		provedRoles,
	)
	if receiptErr != nil {
		return CurrentQualificationResult{}, receiptErr
	}
	roleReceipts := make([]CurrentRoleReceipt, 0, len(roles))
	for _, role := range roles {
		roleReceipts = append(roleReceipts, CurrentRoleReceipt{Role: role, State: ReceiptPass, Identity: observed})
	}
	result = CurrentQualificationResult{
		VersionArgv: append([]string(nil), probeResult.VersionArgv...), Version: probeResult.Version,
		Receipts: receipts, SupportedRoles: append([]domain.Role(nil), roles...),
		RoleReceipts: roleReceipts, BaseRole: request.BaseRole, Observations: observations,
		familyAuthority: familyAuthority, familyDefinition: request.Definition,
		familyNamespaceGeneration: request.Namespace.Generation(),
		familyProvedRoles:         append([]domain.Role(nil), provedRoles...),
	}
	return result, nil
}

// DeriveEquivalentFamilyRoute mints destination-bound receipts from a live
// family authority through the adapter derivation boundary.
func (qualifier *ProviderCurrentQualifier) DeriveEquivalentFamilyRoute(
	ctx context.Context,
	request FamilyRouteDerivationRequest,
) (CurrentQualificationResult, error) {
	if qualifier == nil || nilInterface(qualifier.deriver) || ctx == nil || request.Now.IsZero() {
		return CurrentQualificationResult{}, fmt.Errorf("review run: family route derivation unavailable")
	}
	if request.Source.familyAuthority == nil || request.SourceDefinition == nil || request.Destination.Definition == nil ||
		request.DestinationNamespace == nil || request.Source.Version == "" || len(request.Source.familyProvedRoles) == 0 {
		return CurrentQualificationResult{}, fmt.Errorf("review run: incomplete family route derivation request")
	}
	if familyRuntimeProfileKeyFor(request.SourceDefinition) != familyRuntimeProfileKeyFor(request.Destination.Definition) {
		return CurrentQualificationResult{}, fmt.Errorf("review run: destination runtime is outside the shareable family profile")
	}
	destinationGeneration := request.DestinationNamespace.Generation()
	if destinationGeneration == "" || request.DestinationNamespace.ProviderInstance() != request.Destination.Definition.Instance() {
		return CurrentQualificationResult{}, fmt.Errorf("review run: destination namespace binding drift")
	}
	destinationRoles, roleErr := canonicalQualificationRoles(request.Destination.BaseRole, request.Destination.SupportedRoles)
	if roleErr != nil {
		return CurrentQualificationResult{}, fmt.Errorf("review run: invalid destination family roles: %w", roleErr)
	}
	if Family(request.SourceDefinition.Family()) == FamilyAGY &&
		request.SourceDefinition.Instance() != request.Destination.Definition.Instance() {
		return CurrentQualificationResult{}, fmt.Errorf("review run: AGY cross-instance family derivation is not permitted")
	}
	derivedAuthority, err := qualifier.deriver.DeriveEquivalentRouteDirectExecutionAuthority(
		request.Source.familyAuthority,
		request.SourceDefinition,
		request.Destination.Definition,
		request.Source.Version,
		request.SourceNamespaceGen,
		destinationGeneration,
		append([]domain.Role(nil), request.Source.familyProvedRoles...),
		append([]domain.Role(nil), destinationRoles...),
	)
	if err != nil {
		return CurrentQualificationResult{}, fmt.Errorf("review run: derive equivalent route authority: %w", err)
	}
	observed := request.DestinationIdentity
	observed.Version = request.Source.Version
	templated, remapErr := remapCurrentQualificationResultWithoutAuthority(
		request.Source, observed, destinationRoles, request.Destination.BaseRole,
	)
	if remapErr != nil {
		return CurrentQualificationResult{}, remapErr
	}
	authorityReceipts, receiptErr := appReceiptsFromDirectExecutionAuthority(
		derivedAuthority,
		observed,
		request.Destination.Definition,
		destinationGeneration,
		destinationRoles,
	)
	if receiptErr != nil {
		return CurrentQualificationResult{}, receiptErr
	}
	merged := make([]Receipt, 0, len(templated.Receipts))
	for _, receipt := range templated.Receipts {
		if receipt.Kind == ReceiptCapability || receipt.Kind == ReceiptSecurityPolicy {
			continue
		}
		merged = append(merged, receipt)
	}
	merged = append(merged, authorityReceipts...)
	sort.Slice(merged, func(i, j int) bool {
		return receiptKindOrdinal(merged[i].Kind) < receiptKindOrdinal(merged[j].Kind)
	})
	return CurrentQualificationResult{
		VersionArgv: append([]string(nil), request.Source.VersionArgv...), Version: request.Source.Version,
		KnownIncompatible: request.Source.KnownIncompatible, Receipts: merged,
		SupportedRoles: templated.SupportedRoles, RoleReceipts: templated.RoleReceipts,
		BaseRole: request.Destination.BaseRole, Observations: append([]ProviderQualificationObservation(nil), request.Source.Observations...),
		familyAuthority: derivedAuthority, familyDefinition: request.Destination.Definition,
		familyNamespaceGeneration: destinationGeneration,
		familyProvedRoles:         append([]domain.Role(nil), destinationRoles...),
	}, nil
}

func directExecutionAuthorityFromProbeReceipts(receipts []ports.ProviderCurrentProbeReceipt) (ports.ProviderDirectExecutionAuthority, error) {
	for _, receipt := range receipts {
		if receipt.Kind == "direct-execution-authority" {
			if receipt.DirectExecutionAuthority == nil || !receipt.DirectExecutionAuthority.Valid() {
				return nil, fmt.Errorf("review run: invalid current probe direct-execution authority")
			}
			return receipt.DirectExecutionAuthority, nil
		}
	}
	return nil, fmt.Errorf("review run: missing current probe direct-execution authority")
}

func (qualifier *ProviderCurrentQualifier) rolesFor(request CurrentQualificationRequest) ([]domain.Role, error) {
	definition := request.Definition
	identity := request.Identity
	if request.Namespace == nil || definition.Instance() == "" || request.Profile.Family() != Family(definition.Family()) ||
		request.Profile.Executable() != definition.Executable() || request.Profile.SHA256() != definition.ExecutableSHA256() ||
		request.Profile.Launcher() != definition.Launcher() || request.Profile.LauncherSHA256() != definition.LauncherSHA256() ||
		request.Namespace.ProviderInstance() != definition.Instance() || request.Namespace.Generation() == "" ||
		request.Namespace.RuntimeSafetyPolicyIdentity() != definition.RuntimeSafetyPolicyIdentity() ||
		identity.Family != Family(definition.Family()) || identity.Instance != definition.Instance() ||
		identity.ProfileGeneration != definition.ProfileGeneration() || identity.AdapterProfile != definition.ProfileID() ||
		identity.Version != definition.Version() || identity.Executable != definition.Executable() ||
		identity.ExecutableSHA256 != definition.ExecutableSHA256() || identity.Launcher != definition.Launcher() ||
		identity.LauncherSHA256 != definition.LauncherSHA256() ||
		identity.NamespaceLease != definition.Instance()+":"+request.Namespace.Generation() ||
		identity.NamespaceGeneration != request.Namespace.Generation() {
		return nil, fmt.Errorf("review run: current qualification request binding drift")
	}
	roles, err := canonicalQualificationRoles(request.BaseRole, request.RequestedRoles)
	if err != nil {
		return nil, fmt.Errorf("review run: invalid current qualification roles: %w", err)
	}
	return roles, nil
}

func (qualifier *ProviderCurrentQualifier) acquire(ctx context.Context, role domain.Role, acquired *[]ports.ProviderQualificationFixtureLease) (ports.ProviderQualificationFixtureLease, error) {
	fixture, err := qualifier.fixtures.Acquire(ctx, role)
	if err != nil {
		return nil, err
	}
	*acquired = append(*acquired, fixture)
	if fixture == nil || fixture.Validate() != nil || fixture.Role() != role || !fixture.WorkspaceSnapshotIdentity().Valid() {
		return nil, fmt.Errorf("review run: invalid acquired fixture for %q", role)
	}
	for _, prior := range (*acquired)[:len(*acquired)-1] {
		if prior == nil || fixture.WorkspaceSnapshotIdentity() == prior.WorkspaceSnapshotIdentity() {
			return nil, fmt.Errorf("review run: qualification fixture workspace reused for %q", role)
		}
	}
	return fixture, nil
}

func canonicalQualificationRoles(baseRole domain.Role, requestedRoles []domain.Role) ([]domain.Role, error) {
	if !baseRole.Valid() || len(requestedRoles) == 0 {
		return nil, fmt.Errorf("invalid base role or requested roles")
	}
	requested := make(map[domain.Role]struct{}, len(requestedRoles))
	for _, role := range requestedRoles {
		if !role.Valid() {
			return nil, fmt.Errorf("invalid requested role %q", role)
		}
		if _, duplicate := requested[role]; duplicate {
			return nil, fmt.Errorf("duplicate requested role %q", role)
		}
		requested[role] = struct{}{}
	}
	if _, ok := requested[baseRole]; !ok {
		return nil, fmt.Errorf("base role is not requested")
	}
	roles := make([]domain.Role, 0, len(requested))
	for _, role := range domain.FixedRoleOrder() {
		if _, ok := requested[role]; ok {
			roles = append(roles, role)
		}
	}
	return roles, nil
}

func drainProbeFixtures(fixtures []ports.ProviderQualificationFixtureLease) error {
	var result error
	for _, fixture := range fixtures {
		if fixture == nil {
			result = errors.Join(result, fmt.Errorf("review run: nil acquired qualification fixture"))
			continue
		}
		var receiptErr error
		for attempt := 0; attempt < 2; attempt++ {
			ctx, cancel := context.WithTimeout(context.Background(), currentQualificationDrainWait)
			receipt, err := fixture.DrainTerminal(ctx)
			cancel()
			if err == nil && receipt.Valid() && receipt.WorkspaceSnapshotIdentity() == fixture.WorkspaceSnapshotIdentity() {
				receiptErr = nil
				break
			}
			if err == nil {
				err = fmt.Errorf("invalid terminal receipt")
			}
			receiptErr = err
		}
		if receiptErr != nil {
			result = errors.Join(result, fmt.Errorf("review run: drain qualification fixture for %q: %w", fixture.Role(), receiptErr))
		}
	}
	return result
}

// retryableOperationalProbeFailure admits exactly one bounded retry for a
// transient provider execution failure. Format, evidence, transport, lifecycle,
// security, login, configuration, and cancellation failures are never retried.
func retryableOperationalProbeFailure(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, ports.ErrProviderLoginRequired) {
		return false
	}
	var failure *domain.Failure
	if !errors.As(err, &failure) {
		return false
	}
	switch failure.Class() {
	case domain.FailureTimeout, domain.FailureQuota, domain.FailureRateLimit, domain.FailureProviderUnavailable:
		return true
	case domain.FailureInvalidOutput:
		cause, ok := typedQualificationDiagnosticCause(err)
		if !ok {
			return false
		}
		switch cause {
		case domain.DiagnosticCauseProviderExecutionFailed, domain.DiagnosticCauseProviderSpawnFailed,
			domain.DiagnosticCauseProviderProcessWaitFailed, domain.DiagnosticCauseProcessGroupCleanupFailed,
			domain.DiagnosticCauseTimedOut, domain.DiagnosticCauseRateLimited, domain.DiagnosticCauseQuotaExceeded:
			return true
		}
	}
	return false
}

func admissionProbeError(err error) error {
	var failure *domain.Failure
	if !errors.As(err, &failure) || failure.Class() != domain.FailureInvalidOutput {
		return err
	}
	adapted, adaptationErr := domain.NewFailure("reviewrun.current.capability", domain.FailureInvalidOutput, failure.Reason(), err)
	if adaptationErr != nil {
		return err
	}
	return adapted
}

func currentProbeAppReceipts(
	receipts []ports.ProviderCurrentProbeReceipt,
	identity Identity,
	definition ports.ProviderRuntimeDefinition,
	namespaceGeneration string,
	roles []domain.Role,
) ([]Receipt, error) {
	kinds := map[string]ReceiptKind{
		"workspace": ReceiptWorkspace, "environment": ReceiptEnvironment, "transport": ReceiptTransport,
		"native-reference": ReceiptNativeReference, "base-role": ReceiptBaseRole, "assignment": ReceiptAssignment,
	}
	expected := map[string]struct{}{
		"workspace": {}, "manifest": {}, "namespace": {}, "environment": {}, "transport": {},
		"native-reference": {}, "version": {}, "capability": {}, "base-role": {}, "assignment": {},
		"direct-execution-authority": {},
	}
	seen := make(map[string]struct{}, len(receipts))
	mapped := make([]Receipt, 0, len(ReceiptKinds()))
	var expiresAt time.Time
	for _, receipt := range receipts {
		if _, ok := expected[receipt.Kind]; !ok {
			return nil, fmt.Errorf("review run: unrecognized current probe receipt %q", receipt.Kind)
		}
		if _, duplicate := seen[receipt.Kind]; duplicate || receipt.ExpiresAt.IsZero() {
			return nil, fmt.Errorf("review run: invalid current probe receipt %q", receipt.Kind)
		}
		if expiresAt.IsZero() {
			expiresAt = receipt.ExpiresAt
		} else if !expiresAt.Equal(receipt.ExpiresAt) {
			return nil, fmt.Errorf("review run: current probe receipt expiry mismatch")
		}
		seen[receipt.Kind] = struct{}{}
		if receipt.Kind == "direct-execution-authority" {
			if receipt.DirectExecutionAuthority == nil {
				return nil, fmt.Errorf("review run: invalid current probe direct-execution authority")
			}
			authorityReceipts, authorityErr := appReceiptsFromDirectExecutionAuthority(
				receipt.DirectExecutionAuthority, identity, definition, namespaceGeneration, roles,
			)
			if authorityErr != nil {
				return nil, authorityErr
			}
			if !receipt.ExpiresAt.Equal(receipt.DirectExecutionAuthority.ExpiresAt()) {
				return nil, fmt.Errorf("review run: invalid current probe direct-execution authority")
			}
			mapped = append(mapped, authorityReceipts...)
			continue
		}
		if receipt.DirectExecutionAuthority != nil {
			return nil, fmt.Errorf("review run: unexpected current probe direct-execution authority")
		}
		if kind, ok := kinds[receipt.Kind]; ok {
			mapped = append(mapped, Receipt{Kind: kind, State: ReceiptPass, ExpiresAt: receipt.ExpiresAt, Identity: identity})
		}
	}
	if len(seen) != len(expected) {
		return nil, fmt.Errorf("review run: incomplete current probe receipts")
	}
	sort.Slice(mapped, func(i, j int) bool {
		return receiptKindOrdinal(mapped[i].Kind) < receiptKindOrdinal(mapped[j].Kind)
	})
	return mapped, nil
}

func appReceiptsFromDirectExecutionAuthority(
	authority ports.ProviderDirectExecutionAuthority,
	identity Identity,
	definition ports.ProviderRuntimeDefinition,
	namespaceGeneration string,
	roles []domain.Role,
) ([]Receipt, error) {
	if authority == nil || !authority.Valid() || authority.AuthorityID() == "" ||
		!authority.Matches(definition, identity.Version, namespaceGeneration, roles) {
		return nil, fmt.Errorf("review run: invalid current probe direct-execution authority")
	}
	proof := &validatedAuthorityProof{
		directAuthorityID: authority.AuthorityID(),
		identity:          identity,
		expiresAt:         authority.ExpiresAt(),
	}
	mapped := []Receipt{{
		Kind: ReceiptCapability, State: ReceiptPass, ExpiresAt: authority.ExpiresAt(), Identity: identity,
		AuthorityID: authority.AuthorityID(), AuthorityScope: AuthorityScopeDirectExecution, authority: proof,
	}}
	if authorityID, ok := authority.AGYControlAuthorityID(); ok {
		if identity.Family != FamilyAGY || authorityID == "" {
			return nil, fmt.Errorf("review run: invalid AGY current probe control authority")
		}
		proof.agyControlID = authorityID
		mapped = append(mapped, Receipt{
			Kind: ReceiptSecurityPolicy, State: ReceiptPass, ExpiresAt: authority.ExpiresAt(), Identity: identity,
			AuthorityID: authorityID, AuthorityScope: AuthorityScopeAGYCanonicalPlanControls, authority: proof,
		})
		return mapped, nil
	}
	if identity.Family == FamilyAGY {
		return nil, fmt.Errorf("review run: missing AGY current probe control authority")
	}
	if identity.Family != FamilyKimi && identity.Family != FamilyZCode && identity.Family != FamilyCodex {
		return nil, fmt.Errorf("review run: unsupported current probe authority family")
	}
	mapped = append(mapped, Receipt{
		Kind: ReceiptSecurityPolicy, State: ReceiptPass, ExpiresAt: authority.ExpiresAt(), Identity: identity,
		AuthorityID: authority.AuthorityID(), AuthorityScope: AuthorityScopeDirectExecution, authority: proof,
	})
	return mapped, nil
}

func receiptKindOrdinal(kind ReceiptKind) int {
	for index, candidate := range ReceiptKinds() {
		if kind == candidate {
			return index
		}
	}
	return len(ReceiptKinds())
}
