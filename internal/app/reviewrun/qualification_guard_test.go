package reviewrun

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

// qualificationGuardProbe returns one fully valid current-probe receipt set and
// applies an optional mutation to the assembled slice. It is local to the
// DF-020 controls so the shared currentQualifierProbe fake stays unchanged.
type qualificationGuardProbe struct {
	mutate func(receipts []ports.ProviderCurrentProbeReceipt) []ports.ProviderCurrentProbeReceipt
}

func (probe *qualificationGuardProbe) QualifyProviderCurrent(_ context.Context, request ports.ProviderCurrentProbeRequest) (ports.ProviderCurrentProbeResult, error) {
	expires := request.Now.Add(time.Minute)
	receipts := make([]ports.ProviderCurrentProbeReceipt, 0, len(currentProbeReceiptKinds)+1)
	for _, kind := range currentProbeReceiptKinds {
		receipt := ports.ProviderCurrentProbeReceipt{Kind: kind, ExpiresAt: expires}
		if kind == "direct-execution-authority" {
			receipt.DirectExecutionAuthority = fakeFamilyAuthority{id: "sha256:guard-authority", expires: expires}
		}
		receipts = append(receipts, receipt)
	}
	if probe.mutate != nil {
		receipts = probe.mutate(receipts)
	}
	return ports.ProviderCurrentProbeResult{VersionArgv: []string{"provider", "--version"}, Version: "0.16.5", Receipts: receipts}, nil
}

func guardCurrentQualifier(t *testing.T, probe *qualificationGuardProbe) *ProviderCurrentQualifier {
	t.Helper()
	qualifier, err := NewProviderCurrentQualifier(probe, &currentQualifierFixtures{})
	if err != nil {
		t.Fatal(err)
	}
	return qualifier
}

// TestCurrentProbeAppReceiptsRejectsInvalidFirstAndLaterReceipts is a DF-020
// control: the receipt loop every successful current probe passes through
// (currentProbeAppReceipts) rejects an invalid entry in the first and in a
// later position of an otherwise valid set. Position independence is the
// property under guard, and the positive control proves the unmutated set
// admits through the whole QualifyCurrent path.
func TestCurrentProbeAppReceiptsRejectsInvalidFirstAndLaterReceipts(t *testing.T) {
	request := testCurrentQualificationRequest(t, []domain.Role{domain.RoleLogic}, domain.RoleLogic)
	if _, err := guardCurrentQualifier(t, &qualificationGuardProbe{}).QualifyCurrent(context.Background(), request); err != nil {
		t.Fatalf("positive control rejected a valid receipt set: %v", err)
	}

	laterIndex := len(currentProbeReceiptKinds) / 2
	rejectionChecks := map[string][]string{
		"unrecognized-kind": {"unrecognized current probe receipt"},
		"zero-expiry":       {"invalid current probe receipt"},
		"expiry-mismatch":   {"expiry mismatch"},
		"duplicate-kind":    {"invalid current probe receipt"},
	}
	for name, mutate := range map[string]func(position int, receipts []ports.ProviderCurrentProbeReceipt) []ports.ProviderCurrentProbeReceipt{
		"unrecognized-kind": func(position int, receipts []ports.ProviderCurrentProbeReceipt) []ports.ProviderCurrentProbeReceipt {
			receipts[position].Kind = "not-a-receipt-kind"
			return receipts
		},
		"zero-expiry": func(position int, receipts []ports.ProviderCurrentProbeReceipt) []ports.ProviderCurrentProbeReceipt {
			receipts[position].ExpiresAt = time.Time{}
			return receipts
		},
		"expiry-mismatch": func(position int, receipts []ports.ProviderCurrentProbeReceipt) []ports.ProviderCurrentProbeReceipt {
			receipts[position].ExpiresAt = receipts[position].ExpiresAt.Add(2 * time.Minute)
			return receipts
		},
		"duplicate-kind": func(position int, receipts []ports.ProviderCurrentProbeReceipt) []ports.ProviderCurrentProbeReceipt {
			return append(receipts, receipts[position])
		},
	} {
		for _, position := range []struct {
			label          string
			duplicateLabel string
			index          int
		}{{label: "first", index: 0, duplicateLabel: "duplicate-of-first-receipt"}, {label: "later", index: laterIndex, duplicateLabel: "duplicate-of-later-receipt"}} {
			positionLabel := position.label
			if name == "duplicate-kind" {
				positionLabel = position.duplicateLabel
			}
			t.Run(name+"/"+positionLabel, func(t *testing.T) {
				probe := &qualificationGuardProbe{mutate: func(receipts []ports.ProviderCurrentProbeReceipt) []ports.ProviderCurrentProbeReceipt {
					return mutate(position.index, receipts)
				}}
				_, err := guardCurrentQualifier(t, probe).QualifyCurrent(context.Background(), request)
				if err == nil {
					t.Fatalf("invalid %s receipt in %s position was accepted", name, position.label)
				}
				// Each case is rejected by its intended check, so deleting any
				// single check fails its own case.
				for _, want := range rejectionChecks[name] {
					if strings.Contains(err.Error(), want) {
						return
					}
				}
				t.Fatalf("invalid %s receipt rejected by the wrong check: %v", name, err)
			})
		}
	}
}

// TestValidateQualificationRejectsInvalidFirstAndLaterReceipts is a DF-020
// control on the second receipt loop (ValidateQualification): invalid entries
// fail closed in the first and in a later position, and the all-valid set
// admits.
func TestValidateQualificationRejectsInvalidFirstAndLaterReceipts(t *testing.T) {
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	build := func(mutate func(position int, receipts []Receipt) []Receipt) QualificationInput {
		candidate := authorityCandidateForFamilyRole(t, FamilyGrok, domain.RoleLogic)
		identity := qualificationIdentity(candidate, candidate.Definition, "generation-1")
		identity.Version = "1.0.89"
		expires := now.Add(time.Minute)
		proof := &validatedAuthorityProof{directAuthorityID: "sha256:guard-authority", identity: identity, expiresAt: expires}
		receipts := []Receipt{
			{Kind: ReceiptWorkspace, State: ReceiptPass, ExpiresAt: expires, Identity: identity},
			{Kind: ReceiptEnvironment, State: ReceiptPass, ExpiresAt: expires, Identity: identity},
			{Kind: ReceiptTransport, State: ReceiptPass, ExpiresAt: expires, Identity: identity},
			{Kind: ReceiptNativeReference, State: ReceiptPass, ExpiresAt: expires, Identity: identity},
			{Kind: ReceiptCapability, State: ReceiptPass, ExpiresAt: expires, Identity: identity, AuthorityID: "sha256:guard-authority", AuthorityScope: AuthorityScopeDirectExecution, authority: proof},
			{Kind: ReceiptBaseRole, State: ReceiptPass, ExpiresAt: expires, Identity: identity},
			{Kind: ReceiptAssignment, State: ReceiptPass, ExpiresAt: expires, Identity: identity},
			{Kind: ReceiptSecurityPolicy, State: ReceiptPass, ExpiresAt: expires, Identity: identity, AuthorityID: "sha256:guard-authority", AuthorityScope: AuthorityScopeDirectExecution, authority: proof},
		}
		if mutate != nil {
			receipts = mutate(0, receipts)
		}
		return QualificationInput{Identity: identity, Version: "1.0.89", Receipts: receipts, Now: now}
	}
	if decision := ValidateQualification(build(nil)); !decision.Available() {
		t.Fatalf("positive control rejected a valid qualification: %s", decision.Reason())
	}
	// Each case asserts its own decision reason, and the expired case expires
	// every receipt at the same instant so expiry_mismatch cannot mask
	// expired_receipt.
	reasons := map[string]string{
		"duplicate-kind":    "invalid_receipts",
		"non-pass-state":    "non_passing_receipt",
		"expired-receipt":   "expired_receipt",
		"identity-mismatch": "identity_mismatch",
	}

	for name, mutate := range map[string]func(position int, receipts []Receipt) []Receipt{
		"duplicate-kind": func(position int, receipts []Receipt) []Receipt {
			return append(receipts, receipts[position])
		},
		"non-pass-state": func(position int, receipts []Receipt) []Receipt {
			receipts[position].State = ReceiptFailed
			return receipts
		},
		"expired-receipt": func(position int, receipts []Receipt) []Receipt {
			for index := range receipts {
				receipts[index].ExpiresAt = now.Add(-time.Minute)
			}
			return receipts
		},
		"identity-mismatch": func(position int, receipts []Receipt) []Receipt {
			receipts[position].Identity.Instance = "other-instance"
			return receipts
		},
	} {
		for _, position := range []struct {
			label          string
			duplicateLabel string
			index          int
		}{{label: "first", index: 0}, {label: "later", index: 2}} {
			t.Run(name+"/"+position.label, func(t *testing.T) {
				input := build(func(_ int, receipts []Receipt) []Receipt {
					return mutate(position.index, receipts)
				})
				decision := ValidateQualification(input)
				if decision.Available() {
					t.Fatalf("invalid %s receipt in %s position was admitted", name, position.label)
				}
				if decision.Reason() != reasons[name] {
					t.Fatalf("invalid %s receipt in %s position rejected as %q, want %q", name, position.label, decision.Reason(), reasons[name])
				}
			})
		}
	}
}

// guardRegistryFactory is a per-instance registry factory so concurrent
// qualification groups never share mutable fake state.
type guardRegistryFactory struct {
	registries map[string]*qualifierRegistry
}

func (factory *guardRegistryFactory) NewProviderQualificationRegistry(_ context.Context, definitions []ports.ProviderRuntimeDefinition) (ports.ProviderQualificationRegistry, error) {
	if len(definitions) != 1 {
		return nil, fmt.Errorf("guard registry factory expects one definition")
	}
	registry, ok := factory.registries[definitions[0].Instance()]
	if !ok {
		return nil, fmt.Errorf("guard registry factory has no registry for %q", definitions[0].Instance())
	}
	return registry, nil
}

func (*guardRegistryFactory) RegistryFromConstructionError(error) (ports.ProviderQualificationRegistry, bool) {
	return nil, false
}

func guardRegistry(t *testing.T, instance, policy string) *qualifierRegistry {
	t.Helper()
	receipt := mustProviderRunTerminalReceipt(t, acquiredProviderNamespaceTerminalReceipt(t, instance, "generation-1"))
	return &qualifierRegistry{
		namespaces: map[string]ports.ProviderQualificationNamespace{
			instance: qualifierNamespace{instance: instance, generation: "generation-1", policy: policy},
		},
		receipt: receipt,
	}
}

func guardRegistryFactoryFor(t *testing.T, candidates ...QualifiedRunCandidate) *guardRegistryFactory {
	t.Helper()
	factory := &guardRegistryFactory{registries: make(map[string]*qualifierRegistry, len(candidates))}
	for _, candidate := range candidates {
		instance := candidate.Definition.Instance()
		factory.registries[instance] = guardRegistry(t, instance, candidate.Definition.RuntimeSafetyPolicyIdentity())
	}
	return factory
}

// TestQualifiedRunOperationalInvalidOutputObservationKeepsRemainingRoutes is a
// DF-020 aggregation control. An invalid-output failure staged as
// reviewrun.current.capability is operational: the rejected candidate gets no
// route, its failure and observations stay in original group order, and the
// run proceeds with the remaining routes. The all-rejected variant fails with
// the readiness error.
func TestQualifiedRunOperationalInvalidOutputObservationKeepsRemainingRoutes(t *testing.T) {
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	operationalFailure := func(instance string) error {
		failure, err := domain.NewFailure("reviewrun.current.capability", domain.FailureInvalidOutput, "controlled evidence mismatch", nil)
		if err != nil {
			t.Fatal(err)
		}
		return withQualificationObservations(failure, []ProviderQualificationObservation{
			rejectedQualificationObservation(instance, failure, false),
		})
	}

	for _, test := range []struct {
		name             string
		failCodex        bool
		failGrok         bool
		wantRoutes       int
		wantFailureAt    string
		wantObservations []string
	}{
		{name: "first group", failCodex: true, wantRoutes: 1, wantFailureAt: "codex-logic",
			wantObservations: []string{"codex-logic:rejected", "grok-logic:qualified"}},
		{name: "later group", failGrok: true, wantRoutes: 1, wantFailureAt: "grok-logic",
			wantObservations: []string{"codex-logic:qualified", "grok-logic:rejected"}},
		{name: "all rejected", failCodex: true, failGrok: true, wantRoutes: 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			codex := authorityCandidateForFamilyRole(t, FamilyCodex, domain.RoleLogic)
			grok := authorityCandidateForFamilyRole(t, FamilyGrok, domain.RoleLogic)
			failing := map[string]bool{"codex-logic": test.failCodex, "grok-logic": test.failGrok}
			qualifier := &familyDerivingQualifier{
				qualify: func(_ context.Context, request CurrentQualificationRequest) (CurrentQualificationResult, error) {
					if failing[request.Definition.Instance()] {
						return CurrentQualificationResult{}, operationalFailure(request.Definition.Instance())
					}
					return syntheticFamilyQualificationResult(t, request, now), nil
				},
				derive: func(_ context.Context, request FamilyRouteDerivationRequest) (CurrentQualificationResult, error) {
					return syntheticDerivedFamilyRoute(t, request, now), nil
				},
			}
			factory, err := NewQualifiedRunFactory(qualifier, guardRegistryFactoryFor(t, codex, grok), qualifierClock{now: now})
			if err != nil {
				t.Fatal(err)
			}
			run, err := factory.NewQualifiedRun(context.Background(), []QualifiedRunCandidate{codex, grok})
			if test.failCodex && test.failGrok {
				if err == nil || run != nil {
					t.Fatalf("all-operational rejection returned run=%v err=%v", run, err)
				}
				var failure *domain.Failure
				if !errors.As(err, &failure) || failure.Class() != domain.FailureProviderUnavailable {
					t.Fatalf("readiness error class = %v, want provider_unavailable: %v", failure, err)
				}
				rejected, ok := ProviderQualificationFailuresFromError(err)
				if !ok || len(rejected) != 2 {
					t.Fatalf("readiness failures = %#v, ok=%t", rejected, ok)
				}
				// The readiness aggregate re-sorts failures canonically by the
				// fixed family ordinal (grok precedes codex), which is the
				// existing nonfatal-failure projection.
				if rejected[0].ProviderInstance() != "grok-logic" || rejected[1].ProviderInstance() != "codex-logic" {
					t.Fatalf("readiness failure order = %v, want the canonical family-ordinal order", []string{rejected[0].ProviderInstance(), rejected[1].ProviderInstance()})
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			routes := run.Routes()
			if len(routes) != test.wantRoutes {
				t.Fatalf("routes = %d, want %d", len(routes), test.wantRoutes)
			}
			for _, route := range routes {
				if instance := route.Qualification().Identity().Instance; instance == test.wantFailureAt {
					t.Fatalf("rejected candidate %s retained a route", instance)
				}
			}
			failures := run.QualificationFailures()
			if len(failures) != 1 || failures[0].ProviderInstance() != test.wantFailureAt ||
				failures[0].ReasonCode() != string(domain.FailureInvalidOutput) {
				t.Fatalf("operational failures = %#v, want one invalid_output record for %s", failures, test.wantFailureAt)
			}
			if got := observationIdentities(run.QualificationObservations()); !reflect.DeepEqual(got, test.wantObservations) {
				t.Fatalf("observation sequence = %v, want %v", got, test.wantObservations)
			}
		})
	}
}

// TestQualifiedRunFatalSelectionReportsOnlySelectedObservations is
// failing-first at the base: with two fatal groups in one batch, each carrying
// different observations, only the selected error's observations are reported.
// On the base the earlier group's error is returned, so its observations would
// surface instead.
func TestQualifiedRunFatalSelectionReportsOnlySelectedObservations(t *testing.T) {
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	codex := authorityCandidateForFamilyRole(t, FamilyCodex, domain.RoleLogic)
	grok := authorityCandidateForFamilyRole(t, FamilyGrok, domain.RoleLogic)
	ordinaryCause, err := domain.NewFailure("capability", domain.FailureInvalidOutput, "invalid output", nil)
	if err != nil {
		t.Fatal(err)
	}
	protectedCause, err := domain.NewFailure("capability", domain.FailureSecurityPolicy, "security violation", nil)
	if err != nil {
		t.Fatal(err)
	}
	qualifier := &familyDerivingQualifier{
		qualify: func(_ context.Context, request CurrentQualificationRequest) (CurrentQualificationResult, error) {
			switch request.Definition.Instance() {
			case "codex-logic":
				return CurrentQualificationResult{}, withQualificationObservations(ordinaryCause, []ProviderQualificationObservation{
					rejectedQualificationObservation("codex-logic", ordinaryCause, false),
				})
			case "grok-logic":
				return CurrentQualificationResult{}, withQualificationObservations(protectedCause, []ProviderQualificationObservation{
					rejectedQualificationObservation("grok-logic", protectedCause, false),
				})
			}
			return CurrentQualificationResult{}, fmt.Errorf("unexpected instance %q", request.Definition.Instance())
		},
	}
	factory, err := NewQualifiedRunFactory(qualifier, guardRegistryFactoryFor(t, codex, grok), qualifierClock{now: now})
	if err != nil {
		t.Fatal(err)
	}
	run, runErr := factory.NewQualifiedRun(context.Background(), []QualifiedRunCandidate{codex, grok})
	if runErr == nil || run != nil {
		t.Fatalf("fatal batch returned run=%v err=%v", run, runErr)
	}
	if !errors.Is(runErr, protectedCause) {
		t.Fatalf("selected fatal error = %v, want the later protected cause", runErr)
	}
	if got := observationIdentities(qualificationObservationsFromError(runErr)); !reflect.DeepEqual(got, []string{"grok-logic:rejected"}) {
		t.Fatalf("reported observations = %v, want exactly the selected error's grok-logic:rejected", got)
	}
}

// TestQualifiedRunFatalCapabilityStageFailsClosed is a DF-020 aggregation
// control: the same invalid-output class under a non-operational stage is a
// fatal boundary error, so the run fails closed with no routes.
func TestQualifiedRunFatalCapabilityStageFailsClosed(t *testing.T) {
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	codex := authorityCandidateForFamilyRole(t, FamilyCodex, domain.RoleLogic)
	grok := authorityCandidateForFamilyRole(t, FamilyGrok, domain.RoleLogic)
	cause, err := domain.NewFailure("capability", domain.FailureInvalidOutput, "invalid output", nil)
	if err != nil {
		t.Fatal(err)
	}
	qualifier := &familyDerivingQualifier{
		qualify: func(_ context.Context, request CurrentQualificationRequest) (CurrentQualificationResult, error) {
			if request.Definition.Instance() == "codex-logic" {
				return CurrentQualificationResult{}, cause
			}
			return syntheticFamilyQualificationResult(t, request, now), nil
		},
		derive: func(_ context.Context, request FamilyRouteDerivationRequest) (CurrentQualificationResult, error) {
			return syntheticDerivedFamilyRoute(t, request, now), nil
		},
	}
	factory, err := NewQualifiedRunFactory(qualifier, guardRegistryFactoryFor(t, codex, grok), qualifierClock{now: now})
	if err != nil {
		t.Fatal(err)
	}
	run, err := factory.NewQualifiedRun(context.Background(), []QualifiedRunCandidate{codex, grok})
	if err == nil || run != nil {
		t.Fatalf("fatal capability stage returned run=%v err=%v", run, err)
	}
	var failure *domain.Failure
	if !errors.As(err, &failure) || failure.Class() != domain.FailureProviderUnavailable {
		t.Fatalf("fatal class = %v, want provider_unavailable: %v", failure, err)
	}
}
