package reviewrun

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

// guardEscape bounds every rendezvous wait. The escape only fails the test and
// releases blocked workers; it is never evidence of overlap, and no assertion
// depends on timing.
const guardEscape = 10 * time.Second

var matrixNow = time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)

func matrixCause(class domain.FailureClass) error {
	failure, err := domain.NewFailure("reviewrun.qualification", class, "matrix failure", nil)
	if err != nil {
		panic(err)
	}
	return failure
}

// TestScheduleFamilyQualificationGroupsBatchesByFamily is failing-first: the
// base scheduler returns one group per batch, while the batch scheduler must
// cut original-order batches that stop at the first repeated family.
func TestScheduleFamilyQualificationGroupsBatchesByFamily(t *testing.T) {
	grokPrimary := authorityCandidateForFamilyRole(t, FamilyGrok, domain.RoleLogic)
	grokMutated := mutateFamilyCandidateDefinition(t, authorityCandidateForFamilyRole(t, FamilyGrok, domain.RoleSecurity), func(d *testRuntimeMutation) {
		d.transportArgvIndex++
	})
	zcodeLogic := authorityCandidateForFamilyRole(t, FamilyZCode, domain.RoleLogic)
	zcodeSecurity := mutateFamilyCandidateDefinition(t, authorityCandidateForFamilyRole(t, FamilyZCode, domain.RoleSecurity), func(d *testRuntimeMutation) {
		d.zcodeModel = "account:zai-individual-coding-plan/GLM-5.3-Flash"
	})
	groups, err := groupCandidatesByFamilyRuntimeProfile([]QualifiedRunCandidate{zcodeLogic, zcodeSecurity, grokPrimary, grokMutated})
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 4 {
		t.Fatalf("groups = %d, want 4 (two per family)", len(groups))
	}
	batches := scheduleFamilyQualificationGroups(groups)
	families := batchFamilies(batches)
	if len(families) != 3 {
		t.Fatalf("batches = %v, want 3 batches (A,A,B,B shape)", families)
	}
	for batchIndex, want := range [][]Family{{FamilyGrok}, {FamilyGrok, FamilyZCode}, {FamilyZCode}} {
		got := families[batchIndex]
		if len(got) != len(want) {
			t.Fatalf("batch %d families = %v, want %v", batchIndex, got, want)
		}
		for index := range want {
			if got[index] != want[index] {
				t.Fatalf("batch %d families = %v, want %v", batchIndex, got, want)
			}
		}
	}
	scheduled := 0
	for batchIndex, batch := range batches {
		seen := make(map[Family]struct{}, len(batch))
		for _, group := range batch {
			if _, repeated := seen[group.family]; repeated {
				t.Fatalf("batch %d repeats family %s", batchIndex, group.family)
			}
			seen[group.family] = struct{}{}
		}
		scheduled += len(batch)
	}
	if scheduled != len(groups) {
		t.Fatalf("scheduled groups = %d, want %d", scheduled, len(groups))
	}
}

func batchFamilies(batches [][]familyQualificationGroup) [][]Family {
	families := make([][]Family, len(batches))
	for index, batch := range batches {
		families[index] = make([]Family, len(batch))
		for groupIndex, group := range batch {
			families[index][groupIndex] = group.family
		}
	}
	return families
}

// TestScheduledFamilyQualificationOverlapsDistinctFamilies is failing-first:
// through the real scheduler, two distinct-family groups must be inside admit
// at the same time. On the base the scheduler yields single-group batches, the
// rendezvous never completes, and the bounded escape fails the test.
func TestScheduledFamilyQualificationOverlapsDistinctFamilies(t *testing.T) {
	grok := authorityCandidateForFamilyRole(t, FamilyGrok, domain.RoleLogic)
	zcode := authorityCandidateForFamilyRole(t, FamilyZCode, domain.RoleLogic)
	groups, err := groupCandidatesByFamilyRuntimeProfile([]QualifiedRunCandidate{grok, zcode})
	if err != nil {
		t.Fatal(err)
	}
	batches := scheduleFamilyQualificationGroups(groups)

	entered := make(chan Family, len(groups))
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseWorkers := func() { releaseOnce.Do(func() { close(release) }) }
	defer releaseWorkers()
	admit := func(_ context.Context, group familyQualificationGroup) (familyGroupAdmission, error) {
		select {
		case entered <- group.family:
		case <-time.After(guardEscape):
			return familyGroupAdmission{}, nil
		}
		<-release
		return familyGroupAdmission{}, nil
	}

	var batchErr error
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, batchErr = runFamilyQualificationBatches(context.Background(), batches, admit)
	}()
	joined := 0
	for joined < len(groups) {
		select {
		case <-entered:
			joined++
		case <-time.After(guardEscape):
			t.Fatalf("distinct-family qualification groups did not overlap: %d of %d group(s) entered admit concurrently", joined, len(groups))
		}
	}
	releaseWorkers()
	<-done
	if batchErr != nil {
		t.Fatal(batchErr)
	}
}

// TestScheduledFamilyQualificationExcludesSameFamily proves same-family
// exclusion through the real scheduler and runner with blocking admissions.
// Deterministically it detects an entry whose family does not belong to the
// current batch's family set while that batch is held, and a same-family
// entry while another same-family admission is still held. Under -race it
// detects any further overlap: two same-family admissions not ordered by the
// runner's batch barrier (its WaitGroup) race on that family's
// deliberately unsynchronized cell, and the race detector reports it. This
// covers a runner that starts a later same-family group before the earlier
// batch has finished, whatever the arrival timing.
func TestScheduledFamilyQualificationExcludesSameFamily(t *testing.T) {
	zcodeLogic := authorityCandidateForFamilyRole(t, FamilyZCode, domain.RoleLogic)
	zcodeSecurity := mutateFamilyCandidateDefinition(t, authorityCandidateForFamilyRole(t, FamilyZCode, domain.RoleSecurity), func(d *testRuntimeMutation) {
		d.zcodeModel = "account:zai-individual-coding-plan/GLM-5.3-Flash"
	})
	grok := authorityCandidateForFamilyRole(t, FamilyGrok, domain.RoleLogic)
	groups, err := groupCandidatesByFamilyRuntimeProfile([]QualifiedRunCandidate{zcodeLogic, zcodeSecurity, grok})
	if err != nil {
		t.Fatal(err)
	}
	batches := scheduleFamilyQualificationGroups(groups)

	var mu sync.Mutex
	inFlight := make(map[Family]bool, len(groups))
	// familyCells holds one deliberately unsynchronized cell per family,
	// allocated before the runner starts so this map is only read during the
	// run. Each cell is read as the very first statement of an admission and
	// written as the very last statement after all test synchronization, so
	// no mutex, channel or other test ordering touches it: only the runner's
	// batch barrier (its WaitGroup) can order one same-family admission's
	// write against the next same-family admission's read.
	familyCells := make(map[Family]*int, len(groups))
	for _, group := range groups {
		cell := 0
		familyCells[group.family] = &cell
	}
	type blockedEntry struct {
		family Family
		done   chan struct{}
	}
	entries := make(chan blockedEntry, len(groups))
	emergency := make(chan struct{})
	var emergencyOnce sync.Once
	releaseAll := func() { emergencyOnce.Do(func() { close(emergency) }) }
	defer releaseAll()
	violations := make(chan string, len(groups))
	admit := func(_ context.Context, group familyQualificationGroup) (familyGroupAdmission, error) {
		entrySequence := *familyCells[group.family]
		done := make(chan struct{})
		mu.Lock()
		alreadyInFlight := inFlight[group.family]
		inFlight[group.family] = true
		mu.Unlock()
		if alreadyInFlight {
			violations <- fmt.Sprintf("family %s entered admit while another group of the same family was in flight", group.family)
		}
		entries <- blockedEntry{family: group.family, done: done}
		select {
		case <-done:
		case <-emergency:
		}
		mu.Lock()
		inFlight[group.family] = false
		mu.Unlock()
		*familyCells[group.family] = entrySequence + 1
		return familyGroupAdmission{}, nil
	}

	var batchErr error
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		_, batchErr = runFamilyQualificationBatches(context.Background(), batches, admit)
	}()

	// Release batch by batch, only after exactly the current batch's family
	// set has entered. An entry from any other family means the runner moved a
	// later-batch group into the current batch or started batches together.
	for batchIndex, batch := range batches {
		expected := make(map[Family]int, len(batch))
		for _, group := range batch {
			expected[group.family]++
		}
		var current []blockedEntry
		for len(current) < len(batch) {
			select {
			case received := <-entries:
				if expected[received.family] == 0 {
					t.Fatalf("batch %d received an entry of family %s outside its scheduled family set %v", batchIndex, received.family, expected)
				}
				expected[received.family]--
				current = append(current, received)
			case <-time.After(guardEscape):
				t.Fatalf("batch %d did not collect its %d scheduled entries; a same-family group may be blocking a batch boundary", batchIndex, len(batch))
			}
		}
		select {
		case extra := <-entries:
			t.Fatalf("batch %d collected an extra entry of family %s beyond its schedule", batchIndex, extra.family)
		default:
		}
		for _, received := range current {
			close(received.done)
		}
	}
	<-finished
	close(violations)
	for violation := range violations {
		t.Fatalf("same-family qualification violation: %s", violation)
	}
	if batchErr != nil {
		t.Fatal(batchErr)
	}
}

// TestQualifiedRunMatchesSequentialOracle holds on the base and after the
// change: the production run retains exactly the sequentially-computed
// routes, evidence, observations and failure records in original group order
// (the run's own fields; the readiness and planner projections re-sort
// failures canonically).
func TestQualifiedRunMatchesSequentialOracle(t *testing.T) {
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	candidates := []QualifiedRunCandidate{
		authorityCandidateForFamilyRole(t, FamilyZCode, domain.RoleLogic),
		authorityCandidateForFamilyRole(t, FamilyZCode, domain.RoleSecurity),
		authorityCandidateForFamilyRole(t, FamilyGrok, domain.RoleLogic),
		authorityCandidateForFamilyRole(t, FamilyGrok, domain.RoleSecurity),
	}
	qualifier := &familyDerivingQualifier{
		qualify: func(_ context.Context, request CurrentQualificationRequest) (CurrentQualificationResult, error) {
			return syntheticFamilyQualificationResult(t, request, now), nil
		},
		derive: func(_ context.Context, request FamilyRouteDerivationRequest) (CurrentQualificationResult, error) {
			return syntheticDerivedFamilyRoute(t, request, now), nil
		},
	}
	factory, err := NewQualifiedRunFactory(qualifier, guardRegistryFactoryFor(t, candidates...), qualifierClock{now: now})
	if err != nil {
		t.Fatal(err)
	}
	groups, err := groupCandidatesByFamilyRuntimeProfile(candidates)
	if err != nil {
		t.Fatal(err)
	}
	expected := familyGroupAdmission{}
	for _, group := range groups {
		part, admitErr := factory.admitFamilyQualificationGroup(context.Background(), group, now)
		if admitErr != nil {
			t.Fatal(admitErr)
		}
		expected = mergeFamilyGroupAdmissions([]familyGroupAdmission{expected, part})
	}
	run, err := factory.NewQualifiedRun(context.Background(), candidates)
	if err != nil {
		t.Fatal(err)
	}
	if len(expected.routes) == 0 || len(run.routes) != len(expected.routes) {
		t.Fatalf("routes = %d, oracle = %d", len(run.routes), len(expected.routes))
	}
	assertOrderedAdmission(t, run, expected)
}

func assertOrderedAdmission(t *testing.T, run *QualifiedRun, expected familyGroupAdmission) {
	t.Helper()
	if !reflect.DeepEqual(run.routes, expected.routes) {
		t.Fatalf("routes differ from sequential oracle:\nrun    = %#v\noracle = %#v", routeIdentities(run.routes), routeIdentities(expected.routes))
	}
	if !reflect.DeepEqual(run.admitted, expected.evidence) {
		t.Fatalf("admitted evidence differs from sequential oracle:\nrun    = %#v\noracle = %#v", evidenceIdentities(run.admitted), evidenceIdentities(expected.evidence))
	}
	if !reflect.DeepEqual(run.qualificationFailures, expected.failures) {
		t.Fatalf("failures differ from sequential oracle: run=%#v oracle=%#v", run.qualificationFailures, expected.failures)
	}
	if !reflect.DeepEqual(run.qualificationObservations, expected.observations) {
		t.Fatalf("observations differ from sequential oracle: run=%v oracle=%v", observationIdentities(run.qualificationObservations), observationIdentities(expected.observations))
	}
}

func routeIdentities(routes []QualifiedRoute) []string {
	identities := make([]string, len(routes))
	for index, route := range routes {
		identities[index] = route.Qualification().Identity().Instance
	}
	return identities
}

func evidenceIdentities(evidence []qualifiedProviderEvidence) []string {
	identities := make([]string, len(evidence))
	for index, item := range evidence {
		identities[index] = item.identity.Instance
	}
	return identities
}

func observationIdentities(observations []ProviderQualificationObservation) []string {
	identities := make([]string, len(observations))
	for index, observation := range observations {
		identities[index] = observation.ProviderInstance() + ":" + observation.Outcome()
	}
	return identities
}

// k1RegistryFactory returns per-instance registries and operationally fails
// construction for designated instances, so a real group admission produces
// non-empty routes, evidence, failures and observations at once.
type k1RegistryFactory struct {
	registries          map[string]*qualifierRegistry
	operationalFailures map[string]error
}

func (factory *k1RegistryFactory) NewProviderQualificationRegistry(_ context.Context, definitions []ports.ProviderRuntimeDefinition) (ports.ProviderQualificationRegistry, error) {
	if len(definitions) != 1 {
		return nil, fmt.Errorf("k1 registry factory expects one definition")
	}
	instance := definitions[0].Instance()
	if cause, failing := factory.operationalFailures[instance]; failing {
		return nil, cause
	}
	registry, ok := factory.registries[instance]
	if !ok {
		return nil, fmt.Errorf("k1 registry factory has no registry for %q", instance)
	}
	return registry, nil
}

func (*k1RegistryFactory) RegistryFromConstructionError(error) (ports.ProviderQualificationRegistry, bool) {
	return nil, false
}

// k1AdmissionParts builds real, distinguishable, fully populated parts for one
// grok group (earlier) and one zcode group (later) through the production
// group admission, plus the real schedule for those groups. The security
// sibling of each family is operationally skipped at registry construction, so
// every part carries a route, admitted evidence, a nonfatal failure and a
// qualified observation. The later part additionally carries a released
// namespace receipt in closedReceipt, as the real release path records.
type k1AdmissionParts struct {
	laterCandidate QualifiedRunCandidate
	parts          map[Family]familyGroupAdmission
	errs           map[Family]error
	batches        [][]familyQualificationGroup
	registries     map[string]*qualifierRegistry
}

func buildK1AdmissionParts(t *testing.T) *k1AdmissionParts {
	t.Helper()
	grokLogic := authorityCandidateForFamilyRole(t, FamilyGrok, domain.RoleLogic)
	grokSecurity := authorityCandidateForFamilyRole(t, FamilyGrok, domain.RoleSecurity)
	zcodeLogic := authorityCandidateForFamilyRole(t, FamilyZCode, domain.RoleLogic)
	zcodeSecurity := authorityCandidateForFamilyRole(t, FamilyZCode, domain.RoleSecurity)
	candidates := []QualifiedRunCandidate{grokLogic, grokSecurity, zcodeLogic, zcodeSecurity}
	qualifier := &familyDerivingQualifier{
		qualify: func(_ context.Context, request CurrentQualificationRequest) (CurrentQualificationResult, error) {
			return syntheticFamilyQualificationResult(t, request, matrixNow), nil
		},
		derive: func(_ context.Context, request FamilyRouteDerivationRequest) (CurrentQualificationResult, error) {
			return syntheticDerivedFamilyRoute(t, request, matrixNow), nil
		},
	}
	registries := make(map[string]*qualifierRegistry, len(candidates))
	for _, candidate := range candidates {
		instance := candidate.Definition.Instance()
		registries[instance] = guardRegistry(t, instance, candidate.Definition.RuntimeSafetyPolicyIdentity())
	}
	factory, err := NewQualifiedRunFactory(qualifier, &k1RegistryFactory{
		registries: registries,
		operationalFailures: map[string]error{
			"grok-security":  matrixCause(domain.FailureProviderUnavailable),
			"zcode-security": matrixCause(domain.FailureProviderUnavailable),
		},
	}, qualifierClock{now: matrixNow})
	if err != nil {
		t.Fatal(err)
	}
	groups, err := groupCandidatesByFamilyRuntimeProfile(candidates)
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 2 || groups[0].family != FamilyGrok || groups[1].family != FamilyZCode {
		t.Fatalf("groups = %v, want one grok group before one zcode group", batchFamilies([][]familyQualificationGroup{groups}))
	}
	built := &k1AdmissionParts{
		laterCandidate: zcodeLogic,
		parts:          make(map[Family]familyGroupAdmission, 2),
		errs:           make(map[Family]error, 2),
		registries:     registries,
	}
	for _, group := range groups {
		part, admitErr := factory.admitFamilyQualificationGroup(context.Background(), group, matrixNow)
		if admitErr != nil {
			t.Fatalf("real %s part admission failed: %v", group.family, admitErr)
		}
		if len(part.routes) != 1 || len(part.evidence) != 1 || len(part.failures) != 1 || len(part.observations) != 1 {
			t.Fatalf("real %s part is not fully populated: routes=%d evidence=%d failures=%d observations=%d",
				group.family, len(part.routes), len(part.evidence), len(part.failures), len(part.observations))
		}
		built.parts[group.family] = part
	}
	// A real release moves an acquired instance out of admitted into
	// closedReceipt while keeping it in instances (qualifier.go:287-299);
	// represent the later group's released sibling in exactly that state.
	// zcode-logic itself stays admitted with no closedReceipt.
	later := built.parts[FamilyZCode]
	const releasedSibling = "zcode-documentation"
	// The registry exists so the close-count assertion can detect an illegal
	// re-close of the released sibling; the composite must never touch it.
	built.registries[releasedSibling] = guardRegistry(t, releasedSibling, built.laterCandidate.Definition.RuntimeSafetyPolicyIdentity())
	later.instances = append(later.instances, releasedSibling)
	later.closedReceipt[releasedSibling] = mustProviderRunTerminalReceipt(t, acquiredProviderNamespaceTerminalReceipt(t, releasedSibling, "generation-1"))
	// familyGroupAdmission is a value, so the modified copy must be written
	// back or the instances append is lost.
	built.parts[FamilyZCode] = later
	built.batches = scheduleFamilyQualificationGroups(groups)
	return built
}

func (built *k1AdmissionParts) admit(_ context.Context, group familyQualificationGroup) (familyGroupAdmission, error) {
	return built.parts[group.family], built.errs[group.family]
}

// assertK1Reduction checks the fatal-path reduction contract: the inclusive
// public prefix of the first failed group for all four public fields, complete
// cleanup ownership from every started group (including the later group's
// closedReceipt), and exactly-once closing through the composite.
func assertK1Reduction(t *testing.T, built *k1AdmissionParts, merged familyGroupAdmission) {
	t.Helper()
	grokPart, zcodePart := built.parts[FamilyGrok], built.parts[FamilyZCode]
	if !reflect.DeepEqual(merged.routes, grokPart.routes) {
		t.Fatalf("reduced routes = %v, want exactly the first group's %v", routeIdentities(merged.routes), routeIdentities(grokPart.routes))
	}
	if !reflect.DeepEqual(merged.evidence, grokPart.evidence) {
		t.Fatalf("reduced evidence = %v, want exactly the first group's %v", evidenceIdentities(merged.evidence), evidenceIdentities(grokPart.evidence))
	}
	if !reflect.DeepEqual(merged.failures, grokPart.failures) {
		t.Fatalf("reduced failures = %#v, want exactly the first group's %#v", merged.failures, grokPart.failures)
	}
	if !reflect.DeepEqual(merged.observations, grokPart.observations) {
		t.Fatalf("reduced observations = %v, want exactly the first group's %v", observationIdentities(merged.observations), observationIdentities(grokPart.observations))
	}
	// Every instance of every started part is owned exactly once: pending
	// close in merged.admitted, or released with its receipt in
	// merged.closedReceipt (a real release deletes the instance from admitted
	// while keeping it in instances) — not both, and not neither.
	for _, part := range []familyGroupAdmission{grokPart, zcodePart} {
		for _, instance := range part.instances {
			_, pendingClose := merged.admitted[instance]
			_, released := merged.closedReceipt[instance]
			if pendingClose == released {
				t.Fatalf("instance %s ownership = (admitted=%t, released=%t), want exactly one of the two", instance, pendingClose, released)
			}
		}
	}
	if _, retained := merged.closedReceipt["zcode-documentation"]; !retained {
		t.Fatal("later group's released sibling was dropped from cleanup ownership")
	}
	composite := &qualifiedRunRegistryComposite{
		registries: merged.admitted, generations: merged.generations,
		instances: append([]string(nil), merged.instances...), closed: merged.closedReceipt,
	}
	receipt, closeErr := composite.Close(context.Background())
	if closeErr != nil || !receipt.Valid() {
		t.Fatalf("composite close = %v, receipt valid = %t", closeErr, receipt.Valid())
	}
	// Every admitted instance of every started group closes exactly once,
	// including the later group's zcode-logic; the released sibling is not
	// closed again; skipped siblings are never admitted.
	for instance, wantCloses := range map[string]int{
		"grok-logic": 1, "zcode-logic": 1,
		"zcode-documentation": 0, "grok-security": 0, "zcode-security": 0,
	} {
		if closes := built.registries[instance].closed; closes != wantCloses {
			t.Fatalf("%s closes = %d, want %d", instance, closes, wantCloses)
		}
	}
	// The aggregate terminal receipt covers every instance in instances.
	receiptInstances := make(map[string]struct{}, len(merged.instances))
	for _, namespace := range receipt.NamespaceReceipts() {
		receiptInstances[namespace.ProviderInstance()] = struct{}{}
	}
	for _, instance := range merged.instances {
		if _, covered := receiptInstances[instance]; !covered {
			t.Fatalf("aggregate receipt is missing a namespace receipt for %s: %v", instance, receiptInstances)
		}
	}
	if len(receiptInstances) != len(merged.instances) {
		t.Fatalf("aggregate receipt covers %d instances, want exactly %d", len(receiptInstances), len(merged.instances))
	}
}

// TestRunFamilyQualificationBatchesFatalSelectionMatrix is failing-first at
// the runner level with real fully populated parts: the base merge returns the
// first-index error and drops the later part entirely, while the batch runner
// must select by canonical failure precedence over the full cause tree (ties
// to the earlier group) and return the selected original error value itself.
func TestRunFamilyQualificationBatchesFatalSelectionMatrix(t *testing.T) {
	ordinary := func() error { return matrixCause(domain.FailureProviderUnavailable) }
	protected := func() error { return matrixCause(domain.FailureSecurityPolicy) }
	configuration := func() error { return matrixCause(domain.FailureConfiguration) }
	cleanupFailure, cleanupErr := domain.NewFailure("reviewrun.current.cleanup", domain.FailureInternal, "qualification fixture cleanup failed", nil)
	if cleanupErr != nil {
		t.Fatal(cleanupErr)
	}
	for _, cell := range []struct {
		name      string
		errA      error
		errB      error
		wantFirst bool
		wantClass domain.FailureClass
	}{
		{name: "earlier ordinary later protected", errA: ordinary(), errB: protected()},
		{name: "earlier protected later ordinary", errA: protected(), errB: ordinary(), wantFirst: true},
		{name: "equal class ties keep earlier error", errA: ordinary(), errB: ordinary(), wantFirst: true},
		{name: "earlier ordinary later configuration", errA: ordinary(), errB: configuration()},
		{name: "untyped earlier loses to typed ordinary", errA: fmt.Errorf("matrix untyped invariant"), errB: ordinary()},
		{name: "joined nested protected cause wins", errA: ordinary(), errB: errors.Join(ordinary(), protected())},
		{name: "later protected wrapped once still wins", errA: ordinary(), errB: fmt.Errorf("matrix wrap: %w", protected())},
		{name: "earlier ordinary later cleanup failure", errA: ordinary(), errB: cleanupFailure, wantClass: domain.FailureInternal},
		{name: "earlier ordinary later bare canceled", errA: ordinary(), errB: context.Canceled},
		{name: "earlier ordinary later bare deadline", errA: ordinary(), errB: context.DeadlineExceeded},
		{name: "earlier canceled later protected", errA: context.Canceled, errB: protected()},
	} {
		t.Run(cell.name, func(t *testing.T) {
			built := buildK1AdmissionParts(t)
			built.errs[FamilyGrok] = cell.errA
			built.errs[FamilyZCode] = cell.errB
			merged, err := runFamilyQualificationBatches(context.Background(), built.batches, built.admit)
			if err == nil {
				t.Fatal("matrix batch returned no fatal error")
			}
			wantSelected, wantRejected := cell.errB, cell.errA
			if cell.wantFirst {
				wantSelected, wantRejected = cell.errA, cell.errB
			}
			if !errors.Is(err, wantSelected) || err != wantSelected {
				t.Fatalf("selected error = %v, want the %s group's original error value", err, selectedLabel(cell.wantFirst))
			}
			if errors.Is(err, wantRejected) && wantRejected != wantSelected {
				t.Fatal("non-selected same-batch error was joined into the returned error")
			}
			if cell.wantClass != "" && runtimeDiagnosticFailureClass(err) != cell.wantClass {
				t.Fatalf("selected error class = %q, want %q", runtimeDiagnosticFailureClass(err), cell.wantClass)
			}
			assertK1Reduction(t, built, merged)
		})
	}
}

// TestRunFamilyQualificationBatchesRanksBoundaryWrappedProtectedCause is a
// separate failing-first cell: a later protected cause wrapped by the real
// providerQualificationBoundaryError must rank exactly as
// runtimeDiagnosticFailureClass ranks it.
func TestRunFamilyQualificationBatchesRanksBoundaryWrappedProtectedCause(t *testing.T) {
	built := buildK1AdmissionParts(t)
	boundaryWrapped := providerQualificationBoundaryError(built.laterCandidate.Definition, matrixCause(domain.FailureSecurityPolicy), string(domain.FailureSecurityPolicy))
	built.errs[FamilyGrok] = matrixCause(domain.FailureProviderUnavailable)
	built.errs[FamilyZCode] = boundaryWrapped
	merged, batchErr := runFamilyQualificationBatches(context.Background(), built.batches, built.admit)
	if batchErr != boundaryWrapped {
		t.Fatalf("selected error = %v, want the boundary-wrapped protected error value itself", batchErr)
	}
	assertK1Reduction(t, built, merged)
}

// TestBatchRetainsLaterAcquisitionsForCleanup is failing-first at the runner
// level with real parts: when the first group fails fatally, a later
// successful group's public contribution is dropped while its complete
// cleanup ownership, including its closedReceipt, still reaches the merge.
func TestBatchRetainsLaterAcquisitionsForCleanup(t *testing.T) {
	built := buildK1AdmissionParts(t)
	built.errs[FamilyGrok] = matrixCause(domain.FailureProviderUnavailable)
	merged, err := runFamilyQualificationBatches(context.Background(), built.batches, built.admit)
	if err == nil {
		t.Fatal("expected the failed group's fatal error")
	}
	assertK1Reduction(t, built, merged)
}

// TestBatchFatalStopsLaterBatches is a sequencing characterization that holds
// on the base: a fatal group failure prevents later batches from starting. It
// fails if later batches keep starting after a fatal batch.
func TestBatchFatalStopsLaterBatches(t *testing.T) {
	grok := authorityCandidateForFamilyRole(t, FamilyGrok, domain.RoleLogic)
	zcodePrimary := authorityCandidateForFamilyRole(t, FamilyZCode, domain.RoleLogic)
	zcodeLater := mutateFamilyCandidateDefinition(t, authorityCandidateForFamilyRole(t, FamilyZCode, domain.RoleSecurity), func(d *testRuntimeMutation) {
		d.zcodeModel = "account:zai-individual-coding-plan/GLM-5.3-Flash"
	})
	groups, err := groupCandidatesByFamilyRuntimeProfile([]QualifiedRunCandidate{grok, zcodePrimary, zcodeLater})
	if err != nil {
		t.Fatal(err)
	}
	batches := scheduleFamilyQualificationGroups(groups)
	if len(batches) < 2 || !containsFamily(batches[1], FamilyZCode) {
		t.Fatalf("batches = %v, want a repeated family forcing a later zcode batch", batchFamilies(batches))
	}
	var mu sync.Mutex
	called := make(map[Family]int, len(groups))
	fatal := matrixCause(domain.FailureProviderUnavailable)
	admit := func(_ context.Context, group familyQualificationGroup) (familyGroupAdmission, error) {
		mu.Lock()
		called[group.family]++
		mu.Unlock()
		if group.family == FamilyGrok {
			return familyGroupAdmission{}, fatal
		}
		return familyGroupAdmission{}, nil
	}
	merged, batchErr := runFamilyQualificationBatches(context.Background(), batches, admit)
	if batchErr != fatal {
		t.Fatalf("returned error = %v, want the fatal group's error value", batchErr)
	}
	if len(merged.admitted) != 0 {
		t.Fatalf("merged admission = %#v, want empty for empty parts", merged.admitted)
	}
	// The family-keyed counter cannot distinguish the two zcode groups, so the
	// sentinel asserts on the count: batch 1 already ran one zcode group, and a
	// started later batch would make it two.
	mu.Lock()
	defer mu.Unlock()
	if zcodeBatches := called[FamilyZCode]; zcodeBatches > 1 {
		t.Fatalf("zcode admissions = %d, want at most one: a later batch started after the fatal batch", zcodeBatches)
	}
}

func containsFamily(batch []familyQualificationGroup, family Family) bool {
	for _, group := range batch {
		if group.family == family {
			return true
		}
	}
	return false
}

// TestBatchMergeFollowsOriginalOrderUnderReverseCompletion makes the earlier
// group's admit wait until the later group's admit has signalled, immediately
// before it returns, then asserts that both the success-path merge and the
// failure-path prefix keep the original group order. It uses a hand-built
// single batch. The success-path variant holds on the base runner; the
// failure-path variant is failing-first there (the base merge drops the later
// group's cleanup ownership).
func TestBatchMergeFollowsOriginalOrderUnderReverseCompletion(t *testing.T) {
	for _, variant := range []struct {
		name         string
		errA         error
		wantFatal    bool
		wantRouteIDs []string
	}{
		{name: "success merge", wantRouteIDs: []string{"grok-logic", "zcode-logic"}},
		{name: "failure prefix", errA: matrixCause(domain.FailureProviderUnavailable), wantFatal: true, wantRouteIDs: []string{"grok-logic"}},
	} {
		t.Run(variant.name, func(t *testing.T) {
			built := buildK1AdmissionParts(t)
			laterReturned := make(chan struct{})
			var closeLater sync.Once
			releaseLater := func() { closeLater.Do(func() { close(laterReturned) }) }
			defer releaseLater()
			grokPart, zcodePart := built.parts[FamilyGrok], built.parts[FamilyZCode]
			escaped := make(chan error, 1)
			admit := func(_ context.Context, group familyQualificationGroup) (familyGroupAdmission, error) {
				if group.family != FamilyGrok {
					releaseLater()
					return zcodePart, nil
				}
				select {
				case <-laterReturned:
				case <-time.After(guardEscape):
					escaped <- fmt.Errorf("later group admit never returned; batches appear serialized")
					return familyGroupAdmission{}, matrixCause(domain.FailureInternal)
				}
				return grokPart, variant.errA
			}
			merged, batchErr := runFamilyQualificationBatches(
				context.Background(),
				[][]familyQualificationGroup{{familyQualificationGroup{family: FamilyGrok}, familyQualificationGroup{family: FamilyZCode}}},
				admit,
			)
			select {
			case escape := <-escaped:
				t.Fatal(escape)
			default:
			}
			if variant.wantFatal {
				if batchErr != variant.errA {
					t.Fatalf("returned error = %v, want the earlier group's error value", batchErr)
				}
			} else if batchErr != nil {
				t.Fatal(batchErr)
			}
			if got := routeIdentities(merged.routes); !reflect.DeepEqual(got, variant.wantRouteIDs) {
				t.Fatalf("merged routes = %v, want %v", got, variant.wantRouteIDs)
			}
			wantObservations := []string{"grok-logic:qualified"}
			if !variant.wantFatal {
				wantObservations = append(wantObservations, "zcode-logic:qualified")
			}
			if got := observationIdentities(merged.observations); !reflect.DeepEqual(got, wantObservations) {
				t.Fatalf("merged observations = %v, want %v", got, wantObservations)
			}
			// Every instance of every started part is owned exactly once:
			// pending close in merged.admitted, or released in
			// merged.closedReceipt — not both, and not neither.
			for _, part := range []familyGroupAdmission{grokPart, zcodePart} {
				for _, instance := range part.instances {
					_, pendingClose := merged.admitted[instance]
					_, released := merged.closedReceipt[instance]
					if pendingClose == released {
						t.Fatalf("instance %s ownership = (admitted=%t, released=%t), want exactly one of the two", instance, pendingClose, released)
					}
				}
			}
		})
	}
}

func selectedLabel(first bool) string {
	if first {
		return "earlier"
	}
	return "later"
}

// TestBatchFailedDrainRetainsOwnership is failing-first at the full
// NewQualifiedRun level: with an earlier ordinary fatal group and a later
// protected one in one batch, the selected protected error survives a failed
// factory drain, the retained registry holds both groups' instances, the
// receipt is not exposed, and exactly two drain attempts were made.
func TestBatchFailedDrainRetainsOwnership(t *testing.T) {
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	zcode := authorityCandidateForFamilyRole(t, FamilyZCode, domain.RoleLogic)
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
			case "zcode-logic":
				return CurrentQualificationResult{}, ordinaryCause
			case "grok-logic":
				return CurrentQualificationResult{}, protectedCause
			}
			return CurrentQualificationResult{}, fmt.Errorf("unexpected instance %q", request.Definition.Instance())
		},
		derive: func(_ context.Context, request FamilyRouteDerivationRequest) (CurrentQualificationResult, error) {
			return syntheticDerivedFamilyRoute(t, request, now), nil
		},
	}
	factory := newFailingDrainFactory(t, qualifier, now, zcode, grok)
	run, runErr := factory.NewQualifiedRun(context.Background(), []QualifiedRunCandidate{zcode, grok})
	if runErr == nil || run != nil {
		t.Fatalf("failed drain returned run=%v err=%v", run, runErr)
	}
	if !errors.Is(runErr, protectedCause) {
		t.Fatalf("selected fatal error = %v, want the later protected cause", runErr)
	}
	if errors.Is(runErr, ordinaryCause) {
		t.Fatal("earlier ordinary cause was joined into the selected error")
	}
	retained, ok := QualifiedRunRegistryFromError(runErr)
	if !ok || retained == nil {
		t.Fatalf("construction cleanup did not retain a registry: %v", runErr)
	}
	composite, ok := retained.(*qualifiedRunRegistryComposite)
	if !ok {
		t.Fatalf("retained registry type = %T, want the run composite", retained)
	}
	for _, instance := range []string{"zcode-logic", "grok-logic"} {
		if _, present := composite.registries[instance]; !present {
			t.Fatalf("retained registry is missing %s: %#v", instance, composite.registries)
		}
	}
	if receipt, ok := ProviderRunTerminalReceiptFromError(runErr); ok || receipt.Valid() {
		t.Fatalf("terminal receipt exposed after failed drain: %#v ok=%t", receipt, ok)
	}
	// The composite drains children in sorted instance order and stops at the
	// first failure, so the earlier-sorted child (grok-logic) observes both
	// factory drain attempts; the later child stays retained and unclosed for
	// the retryable cleanup owner.
	registry := factory.registries.(*guardRegistryFactory)
	if closes := len(registry.registries["grok-logic"].closeContexts); closes != 2 {
		t.Fatalf("drain attempts = %d, want exactly 2", closes)
	}
	if closes := registry.registries["zcode-logic"].closed; closes != 0 {
		t.Fatalf("later-instance closes = %d, want 0 while the earlier child keeps failing", closes)
	}
}

func newFailingDrainFactory(t *testing.T, qualifier CurrentQualifier, now time.Time, candidates ...QualifiedRunCandidate) *QualifiedRunFactory {
	t.Helper()
	base := guardRegistryFactoryFor(t, candidates...)
	for _, registry := range base.registries {
		registry.closeErr = fmt.Errorf("drain failed")
	}
	factory, err := NewQualifiedRunFactory(qualifier, base, qualifierClock{now: now})
	if err != nil {
		t.Fatal(err)
	}
	return factory
}

// TestQualifiedRunRecoversQualifyCurrentPanicAndDrains is failing-first: on
// the base a panic inside group admission crashes the process. With the R1
// recovery it becomes a payload-free typed internal failure whose partial
// acquisitions are drained exactly once.
func TestQualifiedRunRecoversQualifyCurrentPanicAndDrains(t *testing.T) {
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	grok := authorityCandidateForFamilyRole(t, FamilyGrok, domain.RoleLogic)
	qualifier := &familyDerivingQualifier{
		qualify: func(context.Context, CurrentQualificationRequest) (CurrentQualificationResult, error) {
			panic("guard panic: qualification probe")
		},
	}
	factory, err := NewQualifiedRunFactory(qualifier, guardRegistryFactoryFor(t, grok), qualifierClock{now: now})
	if err != nil {
		t.Fatal(err)
	}
	run, runErr := factory.NewQualifiedRun(context.Background(), []QualifiedRunCandidate{grok})
	if runErr == nil || run != nil {
		t.Fatalf("panicking group returned run=%v err=%v", run, runErr)
	}
	var failure *domain.Failure
	if !errors.As(runErr, &failure) || failure.Class() != domain.FailureInternal || failure.Stage() != "reviewrun.qualification" {
		t.Fatalf("panic classification = %#v, want typed internal reviewrun.qualification failure", failure)
	}
	if strings.Contains(runErr.Error(), "panic") || strings.Contains(runErr.Error(), "guard") {
		t.Fatalf("panic payload leaked into the failure: %v", runErr)
	}
	registries := factoryGuardRegistries(factory, grok)
	if closes := registries["grok-logic"].closed; closes != 1 {
		t.Fatalf("panicked group namespace closes = %d, want exactly one drain", closes)
	}
}

// TestQualifiedRunRecoversSiblingDerivationPanicAndDrains is failing-first on
// the base: the panic happens after both sibling namespaces were acquired, so
// the recovery must drain both.
func TestQualifiedRunRecoversSiblingDerivationPanicAndDrains(t *testing.T) {
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	logic := authorityCandidateForFamilyRole(t, FamilyGrok, domain.RoleLogic)
	security := authorityCandidateForFamilyRole(t, FamilyGrok, domain.RoleSecurity)
	qualifier := &familyDerivingQualifier{
		qualify: func(_ context.Context, request CurrentQualificationRequest) (CurrentQualificationResult, error) {
			return syntheticFamilyQualificationResult(t, request, now), nil
		},
		derive: func(context.Context, FamilyRouteDerivationRequest) (CurrentQualificationResult, error) {
			panic("guard panic: sibling derivation")
		},
	}
	factory, err := NewQualifiedRunFactory(qualifier, guardRegistryFactoryFor(t, logic, security), qualifierClock{now: now})
	if err != nil {
		t.Fatal(err)
	}
	run, runErr := factory.NewQualifiedRun(context.Background(), []QualifiedRunCandidate{logic, security})
	if runErr == nil || run != nil {
		t.Fatalf("panicking derivation returned run=%v err=%v", run, runErr)
	}
	var failure *domain.Failure
	if !errors.As(runErr, &failure) || failure.Class() != domain.FailureInternal {
		t.Fatalf("panic classification = %#v, want internal failure", failure)
	}
	if strings.Contains(runErr.Error(), "panic") {
		t.Fatalf("panic payload leaked into the failure: %v", runErr)
	}
	registries := factoryGuardRegistries(factory, logic, security)
	for _, instance := range []string{"grok-logic", "grok-security"} {
		if closes := registries[instance].closed; closes != 1 {
			t.Fatalf("%s closes = %d, want exactly one drain", instance, closes)
		}
	}
}

// TestQualifiedRunPanicRetainsRegistryWhenDrainFails is failing-first on the
// base: after the recovered panic, a failing factory drain retains the
// panicked group's registry without exposing a receipt.
func TestQualifiedRunPanicRetainsRegistryWhenDrainFails(t *testing.T) {
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	grok := authorityCandidateForFamilyRole(t, FamilyGrok, domain.RoleLogic)
	qualifier := &familyDerivingQualifier{
		qualify: func(context.Context, CurrentQualificationRequest) (CurrentQualificationResult, error) {
			panic("guard panic: qualification probe")
		},
	}
	factory := newFailingDrainFactory(t, qualifier, now, grok)
	run, runErr := factory.NewQualifiedRun(context.Background(), []QualifiedRunCandidate{grok})
	if runErr == nil || run != nil {
		t.Fatalf("panicking group with failed drain returned run=%v err=%v", run, runErr)
	}
	var failure *domain.Failure
	if !errors.As(runErr, &failure) || failure.Class() != domain.FailureInternal {
		t.Fatalf("panic classification = %#v, want internal failure", failure)
	}
	retained, ok := QualifiedRunRegistryFromError(runErr)
	if !ok || retained == nil {
		t.Fatalf("failed drain did not retain the panicked group's registry: %v", runErr)
	}
	composite, ok := retained.(*qualifiedRunRegistryComposite)
	if !ok {
		t.Fatalf("retained registry type = %T", retained)
	}
	if _, present := composite.registries["grok-logic"]; !present {
		t.Fatalf("retained registry is missing the panicked group's instance: %#v", composite.registries)
	}
	if receipt, ok := ProviderRunTerminalReceiptFromError(runErr); ok || receipt.Valid() {
		t.Fatalf("terminal receipt exposed after failed drain: %#v ok=%t", receipt, ok)
	}
}

func factoryGuardRegistries(factory *QualifiedRunFactory, candidates ...QualifiedRunCandidate) map[string]*qualifierRegistry {
	source := factory.registries.(*guardRegistryFactory)
	registries := make(map[string]*qualifierRegistry, len(candidates))
	for _, candidate := range candidates {
		instance := candidate.Definition.Instance()
		registries[instance] = source.registries[instance]
	}
	return registries
}

// TestConcurrentBatchesPreserveInstanceAndProfileAuthority verifies that
// equivalent ZCode and Grok profiles share one probe with sibling derivation
// while distinct-model ZCode and distinct-settings Grok candidates remain
// independently probed, and derivation never crosses a family profile.
func TestConcurrentBatchesPreserveInstanceAndProfileAuthority(t *testing.T) {
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	zcodeDistinctModel := mutateFamilyCandidateDefinition(t, authorityCandidateForFamilyRole(t, FamilyZCode, domain.RoleDocumentation), func(d *testRuntimeMutation) {
		d.zcodeModel = "account:zai-individual-coding-plan/GLM-5.3-Flash"
	})
	grokDistinctSettings := mutateFamilyCandidateDefinition(t, authorityCandidateForFamilyRole(t, FamilyGrok, domain.RoleDocumentation), func(d *testRuntimeMutation) {
		d.grokSettingsIdentity = "sha256:" + strings.Repeat("d", 64)
	})
	candidates := []QualifiedRunCandidate{
		authorityCandidateForFamilyRole(t, FamilyZCode, domain.RoleLogic),
		authorityCandidateForFamilyRole(t, FamilyZCode, domain.RoleSecurity),
		zcodeDistinctModel,
		authorityCandidateForFamilyRole(t, FamilyGrok, domain.RoleLogic),
		authorityCandidateForFamilyRole(t, FamilyGrok, domain.RoleSecurity),
		grokDistinctSettings,
	}
	var mu sync.Mutex
	qualifyCalls := make(map[string]int)
	deriveCalls := make(map[string]int)
	qualifier := &familyDerivingQualifier{
		qualify: func(_ context.Context, request CurrentQualificationRequest) (CurrentQualificationResult, error) {
			mu.Lock()
			qualifyCalls[request.Definition.Instance()]++
			mu.Unlock()
			return syntheticFamilyQualificationResult(t, request, now), nil
		},
		derive: func(_ context.Context, request FamilyRouteDerivationRequest) (CurrentQualificationResult, error) {
			if familyRuntimeProfileKeyFor(request.SourceDefinition) != familyRuntimeProfileKeyFor(request.Destination.Definition) {
				t.Error("derivation invoked across unequal family profiles")
			}
			mu.Lock()
			deriveCalls[request.Destination.Definition.Instance()]++
			mu.Unlock()
			return syntheticDerivedFamilyRoute(t, request, now), nil
		},
	}
	factory, err := NewQualifiedRunFactory(qualifier, guardRegistryFactoryFor(t, candidates...), qualifierClock{now: now})
	if err != nil {
		t.Fatal(err)
	}
	run, err := factory.NewQualifiedRun(context.Background(), candidates)
	if err != nil {
		t.Fatal(err)
	}
	if routes := run.Routes(); len(routes) != len(candidates) {
		t.Fatalf("routes = %d, want one per candidate (%d)", len(routes), len(candidates))
	}
	for _, instance := range []string{"zcode-logic", "zcode-documentation", "grok-logic", "grok-documentation"} {
		if calls := qualifyCalls[instance]; calls != 1 {
			t.Fatalf("QualifyCurrent calls for %s = %d, want 1", instance, calls)
		}
	}
	for _, instance := range []string{"zcode-documentation", "grok-documentation"} {
		if calls := deriveCalls[instance]; calls != 0 {
			t.Fatalf("distinct-profile candidate %s derived from another profile: %d calls", instance, calls)
		}
	}
	for _, instance := range []string{"zcode-security", "grok-security"} {
		if calls := deriveCalls[instance]; calls != 1 {
			t.Fatalf("DeriveEquivalentFamilyRoute calls for %s = %d, want 1", instance, calls)
		}
		if calls := qualifyCalls[instance]; calls != 0 {
			t.Fatalf("same-profile sibling %s was probed directly: %d calls", instance, calls)
		}
	}
}

// TestQualifiedRunCancellationDuringMultiFamilyBatch cancels the run while
// both distinct-family admissions are in flight and their probes block; the
// fakes then return their own context errors.
func TestQualifiedRunCancellationDuringMultiFamilyBatch(t *testing.T) {
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	zcode := authorityCandidateForFamilyRole(t, FamilyZCode, domain.RoleLogic)
	grok := authorityCandidateForFamilyRole(t, FamilyGrok, domain.RoleLogic)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered := make(chan string, 2)
	// The markers are created once so the selected boundary error can be
	// identified by cause-chain identity rather than by message text, which
	// the boundary wrapper replaces.
	zcodeMarker := fmt.Errorf("zcode-logic cancelled: %w", context.Canceled)
	grokMarker := fmt.Errorf("grok-logic cancelled: %w", context.Canceled)
	qualifier := &familyDerivingQualifier{
		qualify: func(requestCtx context.Context, request CurrentQualificationRequest) (CurrentQualificationResult, error) {
			entered <- request.Definition.Instance()
			<-requestCtx.Done()
			if request.Definition.Instance() == "zcode-logic" {
				return CurrentQualificationResult{}, zcodeMarker
			}
			return CurrentQualificationResult{}, grokMarker
		},
	}
	factory, err := NewQualifiedRunFactory(qualifier, guardRegistryFactoryFor(t, zcode, grok), qualifierClock{now: now})
	if err != nil {
		t.Fatal(err)
	}
	var run *QualifiedRun
	var runErr error
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		run, runErr = factory.NewQualifiedRun(ctx, []QualifiedRunCandidate{zcode, grok})
	}()
	joined := 0
	for joined < 2 {
		select {
		case <-entered:
			joined++
		case <-time.After(guardEscape):
			cancel()
			t.Fatalf("cancellation batch never had both groups in flight: %d of 2 entered", joined)
		}
	}
	cancel()
	<-finished
	if runErr == nil || run != nil {
		t.Fatalf("cancelled run returned run=%v err=%v", run, runErr)
	}
	if class := runtimeDiagnosticFailureClass(runErr); class != domain.FailureCancelled {
		t.Fatalf("cancelled run class = %q, want cancelled: %v", class, runErr)
	}
	if !errors.Is(runErr, context.Canceled) {
		t.Fatalf("cancelled run error does not wrap context.Canceled: %v", runErr)
	}
	// Equal cancellation classes tie to the earlier group (grok precedes zcode
	// in canonical group-key order): the selected error wraps the grok marker
	// and does not wrap the zcode marker.
	if !errors.Is(runErr, grokMarker) {
		t.Fatalf("selected error = %v, want the earlier group's cancellation", runErr)
	}
	if errors.Is(runErr, zcodeMarker) {
		t.Fatalf("later group's cancellation was joined into the selected error: %v", runErr)
	}
	source := factory.registries.(*guardRegistryFactory)
	for _, instance := range []string{"zcode-logic", "grok-logic"} {
		if closes := source.registries[instance].closed; closes != 1 {
			t.Fatalf("%s closes = %d, want exactly one drain under closeAdmitted", instance, closes)
		}
	}
}
