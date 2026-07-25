package reviewrun

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/irootkernel/kkachi-agent-review/internal/domain"
	"github.com/irootkernel/kkachi-agent-review/internal/ports"
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
}

var _ CurrentQualifier = (*ProviderCurrentQualifier)(nil)

// NewProviderCurrentQualifier constructs the production current qualifier.
func NewProviderCurrentQualifier(probe ports.ProviderCurrentProbe, fixtures ports.ProviderQualificationFixtureFactory) (*ProviderCurrentQualifier, error) {
	if nilInterface(probe) || nilInterface(fixtures) {
		return nil, fmt.Errorf("review run: current qualifier dependencies unavailable")
	}
	return &ProviderCurrentQualifier{probe: probe, fixtures: fixtures}, nil
}

// QualifyCurrent acquires independently materialized fixtures, performs one
// descriptor-bound probe, and returns evidence bound only to its observed
// version. Every acquired fixture is drained before it returns.
func (qualifier *ProviderCurrentQualifier) QualifyCurrent(ctx context.Context, request CurrentQualificationRequest) (result CurrentQualificationResult, err error) {
	if qualifier == nil || nilInterface(qualifier.probe) || nilInterface(qualifier.fixtures) || ctx == nil || request.Now.IsZero() {
		return CurrentQualificationResult{}, fmt.Errorf("review run: invalid current qualification authority")
	}
	roles, err := qualifier.rolesFor(request)
	if err != nil {
		return CurrentQualificationResult{}, err
	}

	fixtures := make([]ports.ProviderQualificationFixtureLease, 0, len(roles))
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
	roleFixtures := make([]ports.ProviderQualificationFixtureLease, 0, len(roles)-1)
	for _, role := range roles {
		if role == request.BaseRole {
			continue
		}
		fixture, acquireErr := qualifier.acquire(ctx, role, &fixtures)
		if acquireErr != nil {
			return CurrentQualificationResult{}, acquireErr
		}
		roleFixtures = append(roleFixtures, fixture)
	}

	provider := request.Definition.Instance()
	probeResult, observations, probeErr := qualifyProviderCurrentWithRetry(ctx, provider, func() (ports.ProviderCurrentProbeResult, error) {
		return qualifier.probe.QualifyProviderCurrent(ctx, ports.ProviderCurrentProbeRequest{
			Definition: request.Definition, Namespace: request.Namespace, Fixture: base, RoleFixtures: roleFixtures,
			Now: request.Now, TTL: currentQualificationTTL,
		})
	})
	if probeErr != nil {
		if errors.Is(probeErr, ports.ErrProviderLoginRequired) {
			return CurrentQualificationResult{}, withQualificationObservations(newProviderLoginRequiredError([]string{provider}, probeErr), observations)
		}
		return CurrentQualificationResult{}, withQualificationObservations(admissionProbeError(probeErr), observations)
	}
	observed := request.Identity
	observed.Version = probeResult.Version
	receipts, receiptErr := currentProbeAppReceipts(
		probeResult.Receipts,
		observed,
		request.Definition,
		request.Namespace.Generation(),
		roles,
	)
	if receiptErr != nil {
		return CurrentQualificationResult{}, receiptErr
	}
	roleReceipts := make([]CurrentRoleReceipt, 0, len(roles))
	for _, role := range roles {
		roleReceipts = append(roleReceipts, CurrentRoleReceipt{Role: role, State: ReceiptPass, Identity: observed})
	}
	return CurrentQualificationResult{
		VersionArgv: append([]string(nil), probeResult.VersionArgv...), Version: probeResult.Version,
		Receipts: receipts, SupportedRoles: append([]domain.Role(nil), roles...),
		RoleReceipts: roleReceipts, BaseRole: request.BaseRole, Observations: observations,
	}, nil
}

func qualifyProviderCurrentWithRetry(
	ctx context.Context,
	provider string,
	probe func() (ports.ProviderCurrentProbeResult, error),
) (ports.ProviderCurrentProbeResult, []ProviderQualificationObservation, error) {
	probeResult, probeErr := probe()
	observations := make([]ProviderQualificationObservation, 0, 2)
	if retryableCapabilityOutputFailure(probeErr) && ctx.Err() == nil {
		observations = append(observations, rejectedQualificationObservation(provider, probeErr, true))
		retryResult, retryErr := probe()
		if retryErr == nil {
			probeResult, probeErr = retryResult, nil
			observations = append(observations, qualifiedQualificationObservation(provider))
		} else {
			observations = append(observations, rejectedQualificationObservation(provider, retryErr, false))
			probeErr = errors.Join(probeErr, retryErr)
		}
	} else if probeErr != nil {
		observations = append(observations, rejectedQualificationObservation(provider, probeErr, false))
	} else {
		observations = append(observations, qualifiedQualificationObservation(provider))
	}
	return probeResult, observations, probeErr
}

func retryableCapabilityOutputFailure(err error) bool {
	if err == nil {
		return false
	}
	var failures []*domain.Failure
	collectDomainFailures(err, &failures)
	if len(failures) == 0 {
		return false
	}
	for _, failure := range failures {
		if failure == nil || failure.Class() != domain.FailureInvalidOutput {
			return false
		}
	}
	return true
}

func collectDomainFailures(err error, failures *[]*domain.Failure) {
	if err == nil {
		return
	}
	if failure, ok := err.(*domain.Failure); ok {
		*failures = append(*failures, failure)
		return
	}
	switch wrapped := err.(type) {
	case interface{ Unwrap() error }:
		collectDomainFailures(wrapped.Unwrap(), failures)
	case interface{ Unwrap() []error }:
		for _, child := range wrapped.Unwrap() {
			collectDomainFailures(child, failures)
		}
	}
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
			authority := receipt.DirectExecutionAuthority
			if authority == nil || !authority.Valid() || authority.AuthorityID() == "" ||
				!authority.ExpiresAt().Equal(receipt.ExpiresAt) ||
				!authority.Matches(definition, identity.Version, namespaceGeneration, roles) {
				return nil, fmt.Errorf("review run: invalid current probe direct-execution authority")
			}
			proof := &validatedAuthorityProof{
				directAuthorityID: authority.AuthorityID(),
				identity:          identity,
				expiresAt:         receipt.ExpiresAt,
			}
			mapped = append(mapped, Receipt{
				Kind: ReceiptCapability, State: ReceiptPass, ExpiresAt: receipt.ExpiresAt, Identity: identity,
				AuthorityID: authority.AuthorityID(), AuthorityScope: AuthorityScopeDirectExecution, authority: proof,
			})
			if authorityID, ok := authority.AGYControlAuthorityID(); ok {
				if identity.Family != FamilyAGY || authorityID == "" {
					return nil, fmt.Errorf("review run: invalid AGY current probe control authority")
				}
				proof.agyControlID = authorityID
				mapped = append(mapped, Receipt{
					Kind: ReceiptSecurityPolicy, State: ReceiptPass, ExpiresAt: receipt.ExpiresAt, Identity: identity,
					AuthorityID: authorityID, AuthorityScope: AuthorityScopeAGYCanonicalPlanControls, authority: proof,
				})
			} else {
				if identity.Family == FamilyAGY {
					return nil, fmt.Errorf("review run: missing AGY current probe control authority")
				}
				if identity.Family != FamilyKimi && identity.Family != FamilyZCode {
					return nil, fmt.Errorf("review run: unsupported current probe authority family")
				}
				mapped = append(mapped, Receipt{
					Kind: ReceiptSecurityPolicy, State: ReceiptPass, ExpiresAt: receipt.ExpiresAt, Identity: identity,
					AuthorityID: authority.AuthorityID(), AuthorityScope: AuthorityScopeDirectExecution, authority: proof,
				})
			}
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

func receiptKindOrdinal(kind ReceiptKind) int {
	for index, candidate := range ReceiptKinds() {
		if kind == candidate {
			return index
		}
	}
	return len(ReceiptKinds())
}
