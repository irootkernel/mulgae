package reviewrun

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/adapters/providercli"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

func TestCurrentQualifierCanonicalRolesRejectDuplicateAndMissingBase(t *testing.T) {
	if _, err := canonicalQualificationRoles(domain.RoleLogic, []domain.Role{domain.RoleLogic, domain.RoleLogic}); err == nil {
		t.Fatal("duplicate role accepted")
	}
	if _, err := canonicalQualificationRoles(domain.RoleLogic, []domain.Role{domain.RoleSecurity}); err == nil {
		t.Fatal("missing base role accepted")
	}
	roles, err := canonicalQualificationRoles(domain.RoleLogic, []domain.Role{domain.RoleTesting, domain.RoleLogic, domain.RoleSecurity})
	if err != nil {
		t.Fatal(err)
	}
	want := []domain.Role{domain.RoleLogic, domain.RoleSecurity, domain.RoleTesting}
	for i := range want {
		if roles[i] != want[i] {
			t.Fatalf("canonical roles = %v, want %v", roles, want)
		}
	}
}

func TestCurrentProbeAppReceiptsRejectsUnboundGenericAuthority(t *testing.T) {
	for _, family := range []Family{FamilyKimi, FamilyZCode, FamilyCodex} {
		t.Run(string(family), func(t *testing.T) {
			identity := Identity{Family: family, Version: "2.0.0"}
			expires := time.Now().Add(time.Minute)
			kinds := []string{"workspace", "manifest", "namespace", "environment", "transport", "native-reference", "version", "capability", "base-role", "assignment", "direct-execution-authority"}
			providerReceipts := make([]ports.ProviderCurrentProbeReceipt, 0, len(kinds))
			for _, kind := range kinds {
				providerReceipts = append(providerReceipts, ports.ProviderCurrentProbeReceipt{Kind: kind, ExpiresAt: expires})
			}
			if _, err := currentProbeAppReceipts(providerReceipts, identity, providercli.RuntimeDefinition{}, "", nil); err == nil {
				t.Fatal("nil direct-execution authority accepted")
			}
			providerReceipts[len(providerReceipts)-1].Kind = "security-policy"
			if _, err := currentProbeAppReceipts(providerReceipts, identity, providercli.RuntimeDefinition{}, "", nil); err == nil {
				t.Fatal("obsolete security-policy payload accepted")
			}
		})
	}
}

func TestDrainProbeFixturesRetriesAndRejectsMismatchedReceipt(t *testing.T) {
	fixture := newCurrentQualifierFixture(t, domain.RoleLogic, testCurrentQualifierWorkspaceIdentity(t), 1, false)
	if err := drainProbeFixtures([]ports.ProviderQualificationFixtureLease{fixture}); err != nil || fixture.drains != 2 {
		t.Fatalf("retry drain = %v, calls=%d", err, fixture.drains)
	}
	fixture = newCurrentQualifierFixture(t, domain.RoleLogic, testCurrentQualifierWorkspaceIdentity(t), 0, true)
	if err := drainProbeFixtures([]ports.ProviderQualificationFixtureLease{fixture}); err == nil || fixture.drains != 2 {
		t.Fatalf("wrong receipt drain = %v, calls=%d", err, fixture.drains)
	}
}

func TestAdmissionProbeErrorPreservesTypedFailures(t *testing.T) {
	auth, err := domain.NewFailure("capability", domain.FailureAuthentication, "authentication unavailable", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := admissionProbeError(auth); got != auth {
		t.Fatal("authentication failure was replaced")
	}
	invalid, err := domain.NewFailure("capability", domain.FailureInvalidOutput, "bad evidence", errors.New("bad"))
	if err != nil {
		t.Fatal(err)
	}
	var got *domain.Failure
	if !errors.As(admissionProbeError(invalid), &got) || got.Stage() != "reviewrun.current.capability" || got.Class() != domain.FailureInvalidOutput {
		t.Fatalf("invalid output was not adapted for admission: %v", got)
	}
}

func TestCapabilityOutputIsNotRetried(t *testing.T) {
	invalid, err := domain.NewFailure("capability", domain.FailureInvalidOutput, "invalid output", nil)
	if err != nil {
		t.Fatal(err)
	}
	probe := &currentQualifierProbe{failures: []error{invalid, nil}}
	qualifier, err := NewProviderCurrentQualifier(probe, &currentQualifierFixtures{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := qualifier.QualifyCurrent(context.Background(), testCurrentQualificationRequest(t, []domain.Role{domain.RoleLogic}, domain.RoleLogic)); err == nil {
		t.Fatal("invalid capability output succeeded")
	}
	if len(probe.requests) != 1 {
		t.Fatalf("probe calls = %d, want 1 (no format retry)", len(probe.requests))
	}
}

type currentQualifierFixture struct {
	role     domain.Role
	identity ports.WorkspaceSnapshotIdentity
	terminal ports.QualificationWorkspaceLease
	drains   int
}

func newCurrentQualifierFixture(t *testing.T, role domain.Role, identity ports.WorkspaceSnapshotIdentity, failures int, wrongReceipt bool) *currentQualifierFixture {
	t.Helper()
	fixture := &currentQualifierFixture{role: role, identity: identity}
	terminalIdentity := identity
	if wrongReceipt {
		terminalIdentity = testCurrentQualifierOtherWorkspaceIdentity()
	}
	terminal := &currentQualifierTerminalLease{identity: terminalIdentity}
	acquired, err := ports.AcquireQualificationWorkspaceLease(context.Background(), func(_ context.Context, binding ports.QualificationWorkspaceTerminalBinding) (ports.QualificationWorkspaceLease, error) {
		drain, err := binding.Bind(terminalIdentity, func(context.Context) error {
			if fixture.drains <= failures {
				return errors.New("drain failed")
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
		terminal.drain = drain
		return terminal, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture.terminal = acquired
	return fixture
}
func newCurrentQualifierFixtureForRole(role domain.Role, identity ports.WorkspaceSnapshotIdentity) (*currentQualifierFixture, error) {
	fixture := &currentQualifierFixture{role: role, identity: identity}
	terminal := &currentQualifierTerminalLease{identity: identity}
	acquired, err := ports.AcquireQualificationWorkspaceLease(context.Background(), func(_ context.Context, binding ports.QualificationWorkspaceTerminalBinding) (ports.QualificationWorkspaceLease, error) {
		drain, err := binding.Bind(identity, func(context.Context) error {
			return nil
		})
		if err != nil {
			return nil, err
		}
		terminal.drain = drain
		return terminal, nil
	})
	if err != nil {
		return nil, err
	}
	fixture.terminal = acquired
	return fixture, nil
}

type currentQualifierTerminalLease struct {
	identity ports.WorkspaceSnapshotIdentity
	drain    ports.QualificationWorkspaceTerminalDrain
}

func (lease *currentQualifierTerminalLease) WorkspaceSnapshotIdentity() ports.WorkspaceSnapshotIdentity {
	return lease.identity
}
func (*currentQualifierTerminalLease) RevalidateForExecution() (ports.WorkspaceExecutionGuard, error) {
	return nil, nil
}
func (lease *currentQualifierTerminalLease) DrainTerminal(ctx context.Context) (ports.QualificationWorkspaceTerminalReceipt, error) {
	return lease.drain(ctx)
}

func (fixture *currentQualifierFixture) Reference() string             { return "roadmap.md" }
func (fixture *currentQualifierFixture) Nonce() string                 { return "nonce" }
func (fixture *currentQualifierFixture) Link() string                  { return "linked:nonce" }
func (fixture *currentQualifierFixture) Missing() string               { return "missing:nonce" }
func (fixture *currentQualifierFixture) Denied() string                { return "denied:nonce" }
func (fixture *currentQualifierFixture) Outside() string               { return "outside:nonce" }
func (*currentQualifierFixture) Validate() error                       { return nil }
func (*currentQualifierFixture) Workspace() providercli.ProbeWorkspace { return nil }
func (*currentQualifierFixture) Packet() []byte                        { return nil }
func (*currentQualifierFixture) PacketSHA256() string                  { return "" }
func (fixture *currentQualifierFixture) Role() domain.Role             { return fixture.role }
func (fixture *currentQualifierFixture) WorkspaceSnapshotIdentity() ports.WorkspaceSnapshotIdentity {
	return fixture.identity
}
func (*currentQualifierFixture) RevalidateForExecution() (ports.WorkspaceExecutionGuard, error) {
	return nil, nil
}
func (fixture *currentQualifierFixture) DrainTerminal(ctx context.Context) (ports.QualificationWorkspaceTerminalReceipt, error) {
	fixture.drains++
	return fixture.terminal.DrainTerminal(ctx)
}

func testCurrentQualifierWorkspaceIdentity(t *testing.T) ports.WorkspaceSnapshotIdentity {
	t.Helper()
	identity, err := ports.NewWorkspaceSnapshotIdentity("/private/fixture", "snapshot-0123456789abcdef0123456789abcdef", "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "qualification", 1, 2, 3, 4)
	if err != nil {
		t.Fatal(err)
	}
	return identity
}

func testCurrentQualifierOtherWorkspaceIdentity() ports.WorkspaceSnapshotIdentity {
	identity, _ := ports.NewWorkspaceSnapshotIdentity("/private/other", "snapshot-fedcba9876543210fedcba9876543210", "sha256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210", "qualification", 5, 6, 7, 8)
	return identity
}

type currentQualifierProbe struct {
	requests       []ports.ProviderCurrentProbeRequest
	failures       []error
	dropKind       string
	duplicateKind  string
	mismatchExpiry bool
	authority      bool
}

func (probe *currentQualifierProbe) QualifyProviderCurrent(_ context.Context, request ports.ProviderCurrentProbeRequest) (ports.ProviderCurrentProbeResult, error) {
	probe.requests = append(probe.requests, request)
	if len(probe.failures) >= len(probe.requests) && probe.failures[len(probe.requests)-1] != nil {
		return ports.ProviderCurrentProbeResult{}, probe.failures[len(probe.requests)-1]
	}
	receipts := make([]ports.ProviderCurrentProbeReceipt, 0, len(currentProbeReceiptKinds)+1)
	for _, kind := range currentProbeReceiptKinds {
		if kind != probe.dropKind {
			receipt := ports.ProviderCurrentProbeReceipt{Kind: kind, ExpiresAt: request.Now.Add(time.Minute)}
			if kind == "direct-execution-authority" && probe.authority {
				receipt.DirectExecutionAuthority = fakeFamilyAuthority{id: "sha256:current-probe-authority", expires: receipt.ExpiresAt}
			}
			receipts = append(receipts, receipt)
		}
	}
	if probe.duplicateKind != "" {
		receipts = append(receipts, ports.ProviderCurrentProbeReceipt{Kind: probe.duplicateKind, ExpiresAt: request.Now.Add(time.Minute)})
	}
	if probe.mismatchExpiry && len(receipts) > 0 {
		receipts[len(receipts)-1].ExpiresAt = request.Now.Add(2 * time.Minute)
	}
	return ports.ProviderCurrentProbeResult{VersionArgv: []string{"provider", "--version"}, Version: "0.23.6", Receipts: receipts}, nil
}

func TestProviderCurrentQualifierDoesNotRetryInvalidCapabilityOutput(t *testing.T) {
	invalid, err := domain.NewFailure("capability", domain.FailureInvalidOutput, "invalid output", nil)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := domain.NewFailure("capability", domain.FailureAuthentication, "authentication unavailable", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name     string
		failures []error
	}{
		{name: "invalid output", failures: []error{invalid}},
		{name: "authentication", failures: []error{auth}},
	} {
		t.Run(test.name, func(t *testing.T) {
			probe := &currentQualifierProbe{failures: test.failures}
			qualifier, err := NewProviderCurrentQualifier(probe, &currentQualifierFixtures{})
			if err != nil {
				t.Fatal(err)
			}
			request := testCurrentQualificationRequest(t, []domain.Role{domain.RoleLogic}, domain.RoleLogic)
			if _, err := qualifier.QualifyCurrent(context.Background(), request); err == nil {
				t.Fatal("failing capability probe succeeded")
			}
			if len(probe.requests) != 1 {
				t.Fatalf("probe calls = %d, want 1", len(probe.requests))
			}
		})
	}
}

type currentQualifierDiagnosticError struct {
	cause domain.RuntimeDiagnosticCause
	err   error
}

func (err currentQualifierDiagnosticError) Error() string                        { return err.err.Error() }
func (err currentQualifierDiagnosticError) Unwrap() error                        { return err.err }
func (err currentQualifierDiagnosticError) Cause() domain.RuntimeDiagnosticCause { return err.cause }

func TestQualifyProviderCurrentRecordsSingleRejectionWithoutRetryMitigation(t *testing.T) {
	invalid, err := domain.NewFailure(
		"capability", domain.FailureInvalidOutput, "invalid output",
		currentQualifierDiagnosticError{cause: domain.DiagnosticCauseOutputFrameMissing, err: errors.New("missing")},
	)
	if err != nil {
		t.Fatal(err)
	}
	probe := &currentQualifierProbe{failures: []error{invalid}}
	qualifier, err := NewProviderCurrentQualifier(probe, &currentQualifierFixtures{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = qualifier.QualifyCurrent(context.Background(), testCurrentQualificationRequest(t, []domain.Role{domain.RoleLogic}, domain.RoleLogic))
	if err == nil {
		t.Fatal("expected capability rejection")
	}
	observations := qualificationObservationsFromError(err)
	if len(observations) != 1 || observations[0].Outcome() != qualificationOutcomeRejected ||
		observations[0].Cause() != domain.DiagnosticCauseOutputFrameMissing || observations[0].Mitigation() != "" {
		t.Fatalf("rejection chronology = %#v", observations)
	}
	if len(probe.requests) != 1 {
		t.Fatalf("probe calls = %d, want 1", len(probe.requests))
	}
}

// A capability fixture-evidence mismatch (owner decision D1, part 2) is an
// operational rejection, not a security failure: qualification treats it like
// any other invalid-output capability failure so remaining qualification
// batches continue and readiness reports an operational cause.
func TestCapabilityEvidenceMismatchIsOperationallyUnavailable(t *testing.T) {
	mismatch, err := domain.NewFailure(
		"capability", domain.FailureInvalidOutput, "controlled evidence mismatch",
		currentQualifierDiagnosticError{cause: domain.DiagnosticCauseObservationMismatch, err: errors.New("controlled evidence mismatch")},
	)
	if err != nil {
		t.Fatal(err)
	}
	probe := &currentQualifierProbe{failures: []error{mismatch}}
	qualifier, err := NewProviderCurrentQualifier(probe, &currentQualifierFixtures{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = qualifier.QualifyCurrent(context.Background(), testCurrentQualificationRequest(t, []domain.Role{domain.RoleLogic}, domain.RoleLogic))
	if err == nil {
		t.Fatal("capability evidence mismatch was accepted")
	}
	if !currentQualificationUnavailable(err) {
		t.Fatalf("capability evidence mismatch was not treated as operationally unavailable: %v", err)
	}
	if len(probe.requests) != 1 {
		t.Fatalf("probe calls = %d, want 1 (no retry)", len(probe.requests))
	}
	observations := qualificationObservationsFromError(err)
	if len(observations) != 1 || observations[0].Outcome() != qualificationOutcomeRejected ||
		observations[0].Cause() != domain.DiagnosticCauseObservationMismatch {
		t.Fatalf("rejection chronology = %#v", observations)
	}
}

func TestProviderCurrentQualifierAttributesLoginRequiredWithoutRetry(t *testing.T) {
	auth, err := domain.NewFailure(
		"capability",
		domain.FailureAuthentication,
		"provider login required",
		ports.ErrProviderLoginRequired,
	)
	if err != nil {
		t.Fatal(err)
	}
	probe := &currentQualifierProbe{failures: []error{auth}}
	qualifier, err := NewProviderCurrentQualifier(probe, &currentQualifierFixtures{})
	if err != nil {
		t.Fatal(err)
	}
	request := testCurrentQualificationRequest(t, []domain.Role{domain.RoleLogic}, domain.RoleLogic)
	_, err = qualifier.QualifyCurrent(context.Background(), request)
	providers, ok := ProviderLoginRequiredProvidersFromError(err)
	if !ok || !errors.Is(err, ports.ErrProviderLoginRequired) ||
		!reflect.DeepEqual(providers, []string{request.Definition.Instance()}) {
		t.Fatalf("login-required result = providers %#v error %v", providers, err)
	}
	if len(probe.requests) != 1 {
		t.Fatalf("probe calls = %d, want 1", len(probe.requests))
	}
}

// currentQualifierProbeFailure builds one typed probe failure. An empty cause
// leaves the chain without a typed diagnostic cause.
func currentQualifierProbeFailure(t *testing.T, class domain.FailureClass, cause domain.RuntimeDiagnosticCause) error {
	t.Helper()
	var wrapped error
	if cause != "" {
		wrapped = currentQualifierDiagnosticError{cause: cause, err: errors.New("probe attempt failed")}
	}
	failure, err := domain.NewFailure("capability", class, "provider capability attempt failed", wrapped)
	if err != nil {
		t.Fatal(err)
	}
	return failure
}

func TestProviderCurrentQualifierRetriesTransientExecutionFailureOnce(t *testing.T) {
	transient := currentQualifierProbeFailure(t, domain.FailureInvalidOutput, domain.DiagnosticCauseProviderExecutionFailed)
	probe := &currentQualifierProbe{failures: []error{transient, nil}, authority: true}
	fixtures := &currentQualifierFixtures{}
	qualifier, err := NewProviderCurrentQualifier(probe, fixtures)
	if err != nil {
		t.Fatal(err)
	}
	result, err := qualifier.QualifyCurrent(context.Background(), testCurrentQualificationRequest(t, []domain.Role{domain.RoleLogic}, domain.RoleLogic))
	if err != nil {
		t.Fatalf("bounded operational retry did not qualify: %v", err)
	}
	if len(probe.requests) != 2 {
		t.Fatalf("probe calls = %d, want 2 (exactly one bounded retry)", len(probe.requests))
	}
	if probe.requests[0].Fixture.WorkspaceSnapshotIdentity() == probe.requests[1].Fixture.WorkspaceSnapshotIdentity() {
		t.Fatal("bounded retry reused the consumed qualification fixture")
	}
	if !probe.requests[0].Now.Equal(probe.requests[1].Now) || probe.requests[0].TTL != probe.requests[1].TTL {
		t.Fatalf("retry changed the expiry basis: now %v/%v ttl %v/%v",
			probe.requests[0].Now, probe.requests[1].Now, probe.requests[0].TTL, probe.requests[1].TTL)
	}
	if !sameRoles(fixtures.acquired, []domain.Role{domain.RoleLogic, domain.RoleLogic}) {
		t.Fatalf("acquired fixtures = %v, want one fresh base fixture per attempt", fixtures.acquired)
	}
	observations := result.Observations
	if len(observations) != 2 ||
		observations[0].Outcome() != qualificationOutcomeRejected ||
		observations[0].Mitigation() != qualificationMitigationRetry ||
		observations[0].Cause() != domain.DiagnosticCauseProviderExecutionFailed ||
		observations[1].Outcome() != qualificationOutcomeQualified || observations[1].Mitigation() != "" {
		t.Fatalf("observation chronology = %#v", observations)
	}
	if len(fixtures.leased) != 2 {
		t.Fatalf("leased fixtures = %d, want 2", len(fixtures.leased))
	}
	for index, lease := range fixtures.leased {
		if lease.drains != 1 {
			t.Fatalf("fixture %d drains = %d, want exactly one terminal drain", index, lease.drains)
		}
	}
}

func TestProviderCurrentQualifierBoundsOperationalRetryToOneAttempt(t *testing.T) {
	transient := currentQualifierProbeFailure(t, domain.FailureInvalidOutput, domain.DiagnosticCauseProviderExecutionFailed)
	probe := &currentQualifierProbe{failures: []error{transient, transient}, authority: true}
	fixtures := &currentQualifierFixtures{}
	qualifier, err := NewProviderCurrentQualifier(probe, fixtures)
	if err != nil {
		t.Fatal(err)
	}
	_, err = qualifier.QualifyCurrent(context.Background(), testCurrentQualificationRequest(t, []domain.Role{domain.RoleLogic}, domain.RoleLogic))
	if err == nil {
		t.Fatal("exhausted bounded operational retry qualified")
	}
	if len(probe.requests) != 2 {
		t.Fatalf("probe calls = %d, want 2 (retry is bounded to one attempt)", len(probe.requests))
	}
	observations := qualificationObservationsFromError(err)
	if len(observations) != 2 ||
		observations[0].Outcome() != qualificationOutcomeRejected ||
		observations[0].Mitigation() != qualificationMitigationRetry ||
		observations[1].Outcome() != qualificationOutcomeRejected || observations[1].Mitigation() != "" {
		t.Fatalf("rejection chronology = %#v", observations)
	}
	if len(fixtures.leased) != 2 {
		t.Fatalf("leased fixtures = %d, want 2", len(fixtures.leased))
	}
	for index, lease := range fixtures.leased {
		if lease.drains != 1 {
			t.Fatalf("fixture %d drains = %d, want exactly one terminal drain", index, lease.drains)
		}
	}
}

func TestProviderCurrentQualifierDoesNotRetryEvidenceOrSecurityFailures(t *testing.T) {
	loginRequired, err := domain.NewFailure("capability", domain.FailureAuthentication, "provider login required", ports.ErrProviderLoginRequired)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name    string
		failure error
	}{
		{name: "evidence mismatch", failure: currentQualifierProbeFailure(t, domain.FailureInvalidOutput, domain.DiagnosticCauseObservationMismatch)},
		{name: "output frame missing", failure: currentQualifierProbeFailure(t, domain.FailureInvalidOutput, domain.DiagnosticCauseOutputFrameMissing)},
		{name: "transport receipt mismatch", failure: currentQualifierProbeFailure(t, domain.FailureSecurityPolicy, domain.DiagnosticCauseTransportReceiptMismatch)},
		{name: "security policy", failure: currentQualifierProbeFailure(t, domain.FailureSecurityPolicy, "")},
		{name: "login required", failure: loginRequired},
	} {
		t.Run(test.name, func(t *testing.T) {
			probe := &currentQualifierProbe{failures: []error{test.failure, test.failure}, authority: true}
			fixtures := &currentQualifierFixtures{}
			qualifier, err := NewProviderCurrentQualifier(probe, fixtures)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := qualifier.QualifyCurrent(context.Background(), testCurrentQualificationRequest(t, []domain.Role{domain.RoleLogic}, domain.RoleLogic)); err == nil {
				t.Fatal("evidence or security probe failure qualified")
			}
			if len(probe.requests) != 1 {
				t.Fatalf("probe calls = %d, want 1 (never retried)", len(probe.requests))
			}
			if !sameRoles(fixtures.acquired, []domain.Role{domain.RoleLogic}) {
				t.Fatalf("acquired fixtures = %v, want one base fixture", fixtures.acquired)
			}
		})
	}
}

func TestRetryableOperationalProbeFailurePredicate(t *testing.T) {
	loginRequired, err := domain.NewFailure("capability", domain.FailureAuthentication, "provider login required", ports.ErrProviderLoginRequired)
	if err != nil {
		t.Fatal(err)
	}
	cancelledTimeout, err := domain.NewFailure("capability", domain.FailureTimeout, "provider timed out", context.Canceled)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name  string
		err   error
		retry bool
	}{
		{name: "nil"},
		{name: "context cancelled", err: context.Canceled},
		{name: "context deadline exceeded", err: context.DeadlineExceeded},
		{name: "untyped error", err: errors.New("provider failed")},
		{name: "typed cause without failure", err: currentQualifierDiagnosticError{cause: domain.DiagnosticCauseProviderExecutionFailed, err: errors.New("spawn")}},
		{name: "timeout", err: currentQualifierProbeFailure(t, domain.FailureTimeout, ""), retry: true},
		{name: "quota", err: currentQualifierProbeFailure(t, domain.FailureQuota, ""), retry: true},
		{name: "rate limit", err: currentQualifierProbeFailure(t, domain.FailureRateLimit, ""), retry: true},
		{name: "provider unavailable", err: currentQualifierProbeFailure(t, domain.FailureProviderUnavailable, ""), retry: true},
		{name: "timeout wrapping cancellation", err: cancelledTimeout},
		{name: "invalid output execution failed", err: currentQualifierProbeFailure(t, domain.FailureInvalidOutput, domain.DiagnosticCauseProviderExecutionFailed), retry: true},
		{name: "invalid output spawn failed", err: currentQualifierProbeFailure(t, domain.FailureInvalidOutput, domain.DiagnosticCauseProviderSpawnFailed), retry: true},
		{name: "invalid output process wait failed", err: currentQualifierProbeFailure(t, domain.FailureInvalidOutput, domain.DiagnosticCauseProviderProcessWaitFailed), retry: true},
		{name: "invalid output process group cleanup failed", err: currentQualifierProbeFailure(t, domain.FailureInvalidOutput, domain.DiagnosticCauseProcessGroupCleanupFailed), retry: true},
		{name: "invalid output timed out", err: currentQualifierProbeFailure(t, domain.FailureInvalidOutput, domain.DiagnosticCauseTimedOut), retry: true},
		{name: "invalid output rate limited", err: currentQualifierProbeFailure(t, domain.FailureInvalidOutput, domain.DiagnosticCauseRateLimited), retry: true},
		{name: "invalid output quota exceeded", err: currentQualifierProbeFailure(t, domain.FailureInvalidOutput, domain.DiagnosticCauseQuotaExceeded), retry: true},
		{name: "invalid output without typed cause", err: currentQualifierProbeFailure(t, domain.FailureInvalidOutput, "")},
		{name: "invalid output observation mismatch", err: currentQualifierProbeFailure(t, domain.FailureInvalidOutput, domain.DiagnosticCauseObservationMismatch)},
		{name: "invalid output frame missing", err: currentQualifierProbeFailure(t, domain.FailureInvalidOutput, domain.DiagnosticCauseOutputFrameMissing)},
		{name: "invalid output frame mismatch", err: currentQualifierProbeFailure(t, domain.FailureInvalidOutput, domain.DiagnosticCauseOutputFrameMismatch)},
		{name: "invalid output decode failed", err: currentQualifierProbeFailure(t, domain.FailureInvalidOutput, domain.DiagnosticCauseOutputDecodeFailed)},
		{name: "invalid output envelope invalid", err: currentQualifierProbeFailure(t, domain.FailureInvalidOutput, domain.DiagnosticCauseOutputEnvelopeInvalid)},
		{name: "invalid output transport receipt mismatch", err: currentQualifierProbeFailure(t, domain.FailureInvalidOutput, domain.DiagnosticCauseTransportReceiptMismatch)},
		{name: "invalid output result binding failed", err: currentQualifierProbeFailure(t, domain.FailureInvalidOutput, domain.DiagnosticCauseResultBindingFailed)},
		{name: "authentication", err: currentQualifierProbeFailure(t, domain.FailureAuthentication, domain.DiagnosticCauseAuthenticationFailed)},
		{name: "login required", err: loginRequired},
		{name: "security policy violation", err: currentQualifierProbeFailure(t, domain.FailureSecurityPolicy, domain.DiagnosticCauseTransportReceiptMismatch)},
		{name: "configuration violation", err: currentQualifierProbeFailure(t, domain.FailureConfiguration, "")},
		{name: "cancelled", err: currentQualifierProbeFailure(t, domain.FailureCancelled, "")},
		{name: "internal", err: currentQualifierProbeFailure(t, domain.FailureInternal, domain.DiagnosticCauseProviderExecutionFailed)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := retryableOperationalProbeFailure(test.err); got != test.retry {
				t.Fatalf("retryableOperationalProbeFailure(%v) = %v, want %v", test.err, got, test.retry)
			}
		})
	}
}

type currentQualifierFixtures struct {
	acquired []domain.Role
	leased   []*currentQualifierFixture
	next     int
}

func (fixtures *currentQualifierFixtures) Acquire(_ context.Context, role domain.Role) (ports.ProviderQualificationFixtureLease, error) {
	fixtures.next++
	fixtures.acquired = append(fixtures.acquired, role)
	identity, err := ports.NewWorkspaceSnapshotIdentity(
		fmt.Sprintf("/private/fixture-%d", fixtures.next),
		fmt.Sprintf("snapshot-%032d", fixtures.next),
		"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"qualification", uint64(fixtures.next), 2, 3, 4,
	)
	if err != nil {
		return nil, err
	}
	fixture, err := newCurrentQualifierFixtureForRole(role, identity)
	if err != nil {
		return nil, err
	}
	fixtures.leased = append(fixtures.leased, fixture)
	return fixture, nil
}

var currentProbeReceiptKinds = []string{
	"workspace", "manifest", "namespace", "environment", "transport", "native-reference",
	"version", "capability", "base-role", "assignment", "direct-execution-authority",
}

func portCurrentProbeReceipts(receipts []providercli.CurrentProbeReceipt) []ports.ProviderCurrentProbeReceipt {
	translated := make([]ports.ProviderCurrentProbeReceipt, len(receipts))
	for index, receipt := range receipts {
		translated[index] = ports.ProviderCurrentProbeReceipt{Kind: receipt.Kind, EvidenceID: receipt.EvidenceID, ExpiresAt: receipt.ExpiresAt}
		if receipt.DirectExecutionAuthority != nil {
			translated[index].DirectExecutionAuthority = receipt.DirectExecutionAuthority
		}
	}
	return translated
}

func TestProviderCurrentQualifierUsesRequestRolesWithoutAuthorityBleed(t *testing.T) {
	probe := &currentQualifierProbe{}
	fixtures := &currentQualifierFixtures{}
	qualifier, err := NewProviderCurrentQualifier(probe, fixtures)
	if err != nil {
		t.Fatal(err)
	}
	first := testCurrentQualificationRequest(t, []domain.Role{domain.RoleTesting, domain.RoleLogic}, domain.RoleLogic)
	if _, err := qualifier.QualifyCurrent(context.Background(), first); err == nil {
		t.Fatal("untyped fake direct-execution authority accepted")
	}
	second := testCurrentQualificationRequest(t, []domain.Role{domain.RoleSecurity}, domain.RoleSecurity)
	if _, err := qualifier.QualifyCurrent(context.Background(), second); err == nil {
		t.Fatal("untyped fake direct-execution authority accepted")
	}
	if len(probe.requests) != 2 {
		t.Fatalf("probe calls = %d", len(probe.requests))
	}
	if got := fixtureRoles(probe.requests[0]); !sameRoles(got, []domain.Role{domain.RoleLogic}) {
		t.Fatalf("first fixture roles = %v, want base role only", got)
	}
	if got := fixtureRoles(probe.requests[1]); !sameRoles(got, []domain.Role{domain.RoleSecurity}) {
		t.Fatalf("second fixture roles = %v", got)
	}
	if !sameRoles(fixtures.acquired, []domain.Role{domain.RoleLogic, domain.RoleSecurity}) {
		t.Fatalf("acquired fixtures = %v, want one base fixture per request", fixtures.acquired)
	}
}
func TestProviderCurrentQualifierRejectsIncompleteDuplicateAndMismatchedDirectEvidence(t *testing.T) {
	for _, test := range []struct {
		name  string
		probe *currentQualifierProbe
	}{
		{name: "missing", probe: &currentQualifierProbe{dropKind: "base-role"}},
		{name: "duplicate", probe: &currentQualifierProbe{duplicateKind: "assignment"}},
		{name: "mismatched authority", probe: &currentQualifierProbe{mismatchExpiry: true}},
	} {
		t.Run(test.name, func(t *testing.T) {
			qualifier, err := NewProviderCurrentQualifier(test.probe, &currentQualifierFixtures{})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := qualifier.QualifyCurrent(context.Background(), testCurrentQualificationRequest(t, []domain.Role{domain.RoleLogic}, domain.RoleLogic)); err == nil {
				t.Fatal("invalid direct qualification evidence accepted")
			}
		})
	}
}

func testCurrentQualificationRequest(t *testing.T, roles []domain.Role, base domain.Role) CurrentQualificationRequest {
	t.Helper()
	transport, err := providercli.NewRuntimeTransport(ports.ProviderPacketChannelStdin, -1, "")
	if err != nil {
		t.Fatal(err)
	}
	definition, err := providercli.NewProductionRuntimeDefinitionWithTransportAndSafetyPolicy(
		"kimi", "current-qualifier", "", "/private/bin/kimi",
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"/private/bin/kimi", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"kimi-default", "profile-generation", "policy-identity", []string{"/private/bin/kimi"},
		transport, nil, "/private/work", time.Second,
	)
	if err != nil {
		t.Fatal(err)
	}
	namespace := qualifierNamespace{instance: definition.Instance(), generation: "generation-1", policy: definition.RuntimeSafetyPolicyIdentity()}
	profile := DiscoveredProviderProfile{
		family: FamilyKimi, executable: definition.Executable(), launcher: definition.Launcher(),
		sha256: definition.ExecutableSHA256(), launcherSHA256: definition.LauncherSHA256(),
	}
	return CurrentQualificationRequest{
		Profile: profile, Definition: definition, Namespace: namespace, RequestedRoles: append([]domain.Role(nil), roles...), BaseRole: base,
		Identity: Identity{
			Family: Family(definition.Family()), Instance: definition.Instance(), ProfileGeneration: definition.ProfileGeneration(),
			AdapterProfile: definition.ProfileID(), Version: definition.Version(), Executable: definition.Executable(),
			ExecutableSHA256: definition.ExecutableSHA256(), Launcher: definition.Launcher(), LauncherSHA256: definition.LauncherSHA256(),
			NamespaceLease: definition.Instance() + ":" + namespace.Generation(), NamespaceGeneration: namespace.Generation(),
		},
		Now: time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC),
	}
}

func fixtureRoles(request ports.ProviderCurrentProbeRequest) []domain.Role {
	roles := []domain.Role{request.Fixture.Role()}
	for _, fixture := range request.RoleFixtures {
		roles = append(roles, fixture.Role())
	}
	return roles
}

func sameRoles(got, want []domain.Role) bool {
	if len(got) != len(want) {
		return false
	}
	for index := range want {
		if got[index] != want[index] {
			return false
		}
	}
	return true
}

type authorityProbeNamespace struct {
	instance, generation, policy string
	nativeHome                   ports.NativeHomeLaunchAuthority
	environment                  []ports.EnvironmentVariable
}

func (n authorityProbeNamespace) ProviderInstance() string { return n.instance }
func (n authorityProbeNamespace) Generation() string       { return n.generation }
func (n authorityProbeNamespace) Environment() []ports.EnvironmentVariable {
	return append([]ports.EnvironmentVariable(nil), n.environment...)
}
func (n authorityProbeNamespace) RuntimeSafetyPolicyIdentity() string { return n.policy }
func (authorityProbeNamespace) ValidateForSpawn() error               { return nil }
func (n authorityProbeNamespace) NativeHomeLaunchAuthority() (ports.NativeHomeLaunchAuthority, bool) {
	return n.nativeHome, n.nativeHome.Valid()
}

type authorityProbeFixture struct {
	root     ports.ValidatedWorkspaceRoot
	identity ports.WorkspaceSnapshotIdentity
}

func (authorityProbeFixture) Reference() string { return "roadmap.md" }
func (authorityProbeFixture) Nonce() string     { return "nonce" }
func (authorityProbeFixture) Link() string      { return "linked" }
func (authorityProbeFixture) Validate() error   { return nil }
func (f authorityProbeFixture) Workspace() providercli.ProbeWorkspace {
	return authorityProbeWorkspace{fixture: f}
}
func (authorityProbeFixture) Packet() []byte { return []byte("fixture") }
func (f authorityProbeFixture) PacketSHA256() string {
	sum := sha256.Sum256(f.Packet())
	return "sha256:" + hex.EncodeToString(sum[:])
}
func (authorityProbeFixture) Role() domain.Role { return domain.RoleLogic }
func (f authorityProbeFixture) WorkspaceSnapshotIdentity() ports.WorkspaceSnapshotIdentity {
	return f.identity
}
func (f authorityProbeFixture) RevalidateForExecution() (ports.WorkspaceExecutionGuard, error) {
	return authorityProbeGuard{fixture: f}, nil
}
func (authorityProbeFixture) DrainTerminal(context.Context) (ports.QualificationWorkspaceTerminalReceipt, error) {
	return ports.QualificationWorkspaceTerminalReceipt{}, nil
}

type authorityProbeWorkspace struct{ fixture authorityProbeFixture }

func (w authorityProbeWorkspace) WorkspaceSnapshotIdentity() ports.WorkspaceSnapshotIdentity {
	return w.fixture.identity
}
func (w authorityProbeWorkspace) RevalidateForExecution() (ports.WorkspaceExecutionGuard, error) {
	return w.fixture.RevalidateForExecution()
}
func (authorityProbeWorkspace) DrainTerminal(context.Context) (ports.QualificationWorkspaceTerminalReceipt, error) {
	return ports.QualificationWorkspaceTerminalReceipt{}, nil
}

type authorityProbeGuard struct{ fixture authorityProbeFixture }

func (g authorityProbeGuard) WorkspaceRoot() ports.ValidatedWorkspaceRoot { return g.fixture.root }
func (g authorityProbeGuard) WorkspaceSnapshotIdentity() ports.WorkspaceSnapshotIdentity {
	return g.fixture.identity
}
func (g authorityProbeGuard) DuplicateLaunchDirectory() (*os.File, error) {
	return os.Open(g.fixture.root.Path())
}
func (authorityProbeGuard) RevalidateAfterExecution() error { return nil }
func (authorityProbeGuard) Close() error                    { return nil }

type authorityProbeVerifier struct{}

func (authorityProbeVerifier) VerifyProviderSpawn(context.Context, providercli.RuntimeDefinition) error {
	return nil
}

type authorityProbeRunner struct {
	t       *testing.T
	family  Family
	version string
	calls   int
}

func (r *authorityProbeRunner) Run(_ context.Context, request ports.ProcessRequest) (ports.ProcessObservation, error) {
	r.t.Helper()
	r.calls++
	file, _, ok := request.BoundLaunchDirectory()
	if !ok {
		r.t.Fatal("current probe request was not bound to the fixture")
	}
	_ = file.Close()
	if r.calls == 1 {
		return authorityProbeObservation(r.t, []byte(r.version+"\n"), ports.ProviderPacketChannelArgvLiteral, ports.ProviderPacketIdentity{}, "", "", nil, nil), nil
	}
	binding, ok := request.ProviderPacketBinding()
	if !ok || !binding.Valid() {
		r.t.Fatal("capability request omitted provider packet binding")
	}
	output := []byte(`{"root":"nonce","link":"linked","role":"logic"}`)
	if r.family == FamilyKimi {
		output = []byte("{\"role\":\"assistant\",\"content\":\"{\\\"root\\\":\\\"nonce\\\",\\\"link\\\":\\\"linked\\\",\\\"role\\\":\\\"logic\\\"}\"}\n")
	}
	var lifecycle ports.ProcessLifecycleReceipt
	if r.family == FamilyAGY {
		policy, ok := request.PostOutputLifecycle()
		if !ok || !policy.Valid() {
			r.t.Fatal("AGY capability request omitted lifecycle policy")
		}
		frame, err := ports.NewProcessOutputFrameReceipt(policy.Framing(), output, policy.StabilityGrace())
		if err != nil {
			r.t.Fatal(err)
		}
		signal, err := ports.NewProcessSignal(15, "SIGTERM")
		if err != nil {
			r.t.Fatal(err)
		}
		signalReceipt, err := ports.NewAcceptedPostOutputProcessGroupSignalRequestReceipt(signal, binding.PacketIdentity(), frame)
		if err != nil {
			r.t.Fatal(err)
		}
		final, err := ports.NewExitedProcessFinalTermination(0)
		if err != nil {
			r.t.Fatal(err)
		}
		lifecycle, err = ports.NewProcessLifecycleReceipt(final, true, []ports.ProcessGroupSignalRequestReceipt{signalReceipt}, frame)
		if err != nil {
			r.t.Fatal(err)
		}
	} else {
		final, err := ports.NewExitedProcessFinalTermination(0)
		if err != nil {
			r.t.Fatal(err)
		}
		lifecycle, err = ports.NewProcessLifecycleReceipt(final, true, nil)
		if err != nil {
			r.t.Fatal(err)
		}
	}
	return authorityProbeObservation(r.t, output, binding.Channel(), binding.PacketIdentity(), binding.PromptFileReference(), binding.SnapshotCWD(), binding.Packet().Bytes(), &lifecycle), nil
}

func authorityProbeObservation(t *testing.T, output []byte, channel ports.ProviderPacketChannel, packet ports.ProviderPacketIdentity, reference, cwd string, stdinBytes []byte, lifecycle *ports.ProcessLifecycleReceipt) ports.ProcessObservation {
	t.Helper()
	var written int64
	if channel == ports.ProviderPacketChannelStdin {
		written = int64(len(stdinBytes))
	} else {
		stdinBytes = nil
	}
	stdin, err := ports.NewStdinWriteReceipt(written, written, authorityProbeStdinDigest(stdinBytes), true)
	if err != nil {
		t.Fatal(err)
	}
	if !packet.Valid() {
		exitCode := 0
		observation, err := ports.NewProcessObservation(
			output, nil, &exitCode, ports.ProcessTerminationExited, stdin,
			time.Unix(0, 0).UTC(), time.Unix(1, 0).UTC(),
		)
		if err != nil {
			t.Fatal(err)
		}
		return observation
	}
	preStart, postEnd := ports.ProviderPacketIdentity{}, ports.ProviderPacketIdentity{}
	if channel == ports.ProviderPacketChannelPromptFile {
		preStart, postEnd = packet, packet
	}
	transport, err := ports.NewProviderPacketTransportReceipt(channel, packet, reference, cwd, preStart, postEnd)
	if err != nil {
		t.Fatal(err)
	}
	if lifecycle != nil {
		observation, err := ports.NewStartedProviderProcessObservation(output, nil, ports.ProcessTerminationExited, stdin, transport, *lifecycle, time.Unix(0, 0).UTC(), time.Unix(1, 0).UTC())
		if err != nil {
			t.Fatal(err)
		}
		return observation
	}
	exitCode := 0
	observation, err := ports.NewProviderProcessObservation(output, nil, &exitCode, ports.ProcessTerminationExited, stdin, transport, time.Unix(0, 0).UTC(), time.Unix(1, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	return observation
}

func authorityProbeDigest(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}
func authorityProbeStdinDigest(value []byte) string {
	hash := sha256.New()
	_, _ = hash.Write([]byte("Mulgae-PROVIDER-STDIN/1"))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write(value)
	return hex.EncodeToString(hash.Sum(nil))
}

func currentProbeAuthorityInput(t *testing.T, family Family, version string) QualificationInput {
	return currentProbeAuthorityInputForInstance(t, family, string(family)+"-current", version)
}

func currentProbeAuthorityInputForInstance(t *testing.T, family Family, instance, version string) QualificationInput {
	t.Helper()
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	probeVersion := version
	if version == "current" {
		probeVersion = "0.23.6"
	}
	directory := filepath.Join(t.TempDir(), "snapshot-0123456789abcdef0123456789abcdef")
	definition, namespace := authorityProbeDefinition(t, family, instance, probeVersion, directory)
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	workspace, err := ports.NewWorkspaceSnapshotIdentity(directory, "snapshot-0123456789abcdef0123456789abcdef", "sha256:"+authorityProbeDigest([]byte("workspace")), "qualification", 1, 2, 3, 4)
	if err != nil {
		t.Fatal(err)
	}
	root, err := ports.NewValidatedWorkspaceRoot(directory, workspace)
	if err != nil {
		t.Fatal(err)
	}
	fixture := authorityProbeFixture{root: root, identity: workspace}
	runner := &authorityProbeRunner{t: t, family: family, version: probeVersion}
	probe, err := providercli.NewCurrentProbe(runner, authorityProbeVerifier{})
	if err != nil {
		t.Fatal(err)
	}
	result, err := probe.QualifyCurrent(context.Background(), providercli.CurrentProbeRequest{
		Definition: definition, Namespace: namespace, Fixture: fixture, Invocation: providercli.NativeProbeInvocation{}, Now: now, TTL: time.Hour,
	})
	if err != nil {
		causes := []string{}
		for cause := err; cause != nil; cause = errors.Unwrap(cause) {
			causes = append(causes, cause.Error())
		}
		t.Fatalf("current probe failed: %q", causes)
	}
	identity := Identity{
		Family: family, Instance: definition.Instance(), ProfileGeneration: definition.ProfileGeneration(), AdapterProfile: definition.ProfileID(),
		Version: probeVersion, Executable: definition.Executable(), ExecutableSHA256: definition.ExecutableSHA256(),
		Launcher: definition.Launcher(), LauncherSHA256: definition.LauncherSHA256(),
		NamespaceLease: definition.Instance() + ":" + namespace.Generation(), NamespaceGeneration: namespace.Generation(), SnapshotManifest: "manifest-1",
	}
	receipts, err := currentProbeAppReceipts(portCurrentProbeReceipts(result.Receipts), identity, definition, namespace.Generation(), []domain.Role{domain.RoleLogic})
	if err != nil {
		t.Fatal(err)
	}
	input := QualificationInput{Identity: identity, Version: probeVersion, Receipts: receipts, Now: now}
	if version == probeVersion {
		return input
	}
	input.Identity.Version = version
	input.Version = version
	for index := range input.Receipts {
		input.Receipts[index].Identity.Version = version
	}
	return input
}

func authorityProbeDefinition(t *testing.T, family Family, instance, version, workingDirectory string) (providercli.RuntimeDefinition, authorityProbeNamespace) {
	t.Helper()
	argvIndex := 4
	if family == FamilyZCode {
		argvIndex = 6
	} else if family == FamilyAGY {
		argvIndex = 13
	}
	channel, reference := ports.ProviderPacketChannelPromptFile, "@roadmap.md"
	if family == FamilyCodex {
		channel, argvIndex, reference = ports.ProviderPacketChannelStdin, -1, ""
	}
	transport, err := providercli.NewRuntimeTransport(channel, argvIndex, reference)
	if err != nil {
		t.Fatal(err)
	}
	policy := string(family) + "-policy"
	namespace := authorityProbeNamespace{instance: instance, generation: "generation-1", policy: policy, environment: authorityProbeEnvironment(t, family)}
	if family == FamilyAGY {
		namespace.nativeHome, err = ports.NewNativeHomeLaunchAuthority("/private/HOME", 1, 1, 1)
		if err != nil {
			t.Fatal(err)
		}
		lifecycle, err := ports.NewBoundedPostOutputLifecycle(ports.ProcessOutputFramingTerminalJSONObject, time.Second, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		definition, err := providercli.NewProductionRuntimeDefinitionWithTransportAndSafetyPolicyAndPostOutputLifecycle(
			string(family), instance, version, "/private/bin/"+string(family), qualifierTestSHA, "/private/bin/"+string(family), qualifierTestSHA,
			string(family)+"-profile", "profile-1", policy, []string{"/private/bin/" + string(family)}, transport, lifecycle, nil, workingDirectory, 3*time.Second,
		)
		if err != nil {
			t.Fatal(err)
		}
		return definition, namespace
	}
	executable := "/private/bin/" + string(family)
	launcher := executable
	baseArgv := []string{executable}
	if family == FamilyZCode {
		executable = "/usr/bin/node"
		launcher = "/private/bin/zcode.cjs"
		baseArgv = []string{executable, launcher}
	}
	definition, err := providercli.NewProductionRuntimeDefinitionWithTransportAndSafetyPolicy(
		string(family), instance, version, executable, qualifierTestSHA, launcher, qualifierTestSHA,
		string(family)+"-profile", "profile-1", policy, baseArgv, transport, nil, workingDirectory, time.Second,
	)
	if err != nil {
		t.Fatal(err)
	}
	return definition, namespace
}
func authorityProbeEnvironment(t *testing.T, family Family) []ports.EnvironmentVariable {
	t.Helper()
	root := "/private/mulgae-provider-namespace"
	values := map[string]string{
		"HOME":                    filepath.Join(root, "home"),
		"XDG_CONFIG_HOME":         filepath.Join(root, "settings"),
		"XDG_DATA_HOME":           filepath.Join(root, "auth"),
		"XDG_CACHE_HOME":          filepath.Join(root, "cache"),
		"TMPDIR":                  filepath.Join(root, "tmp"),
		"TMP":                     filepath.Join(root, "tmp"),
		"TEMP":                    filepath.Join(root, "tmp"),
		"MULGAE_PROVIDER_SCRATCH": filepath.Join(root, "scratch"),
	}
	if family == FamilyAGY {
		values["HOME"] = "/private/HOME"
	}
	names := []string{"HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME", "TMPDIR", "TMP", "TEMP", "MULGAE_PROVIDER_SCRATCH"}
	environment := make([]ports.EnvironmentVariable, 0, len(names))
	for _, name := range names {
		variable, err := ports.NewEnvironmentVariable(name, values[name])
		if err != nil {
			t.Fatal(err)
		}
		environment = append(environment, variable)
	}
	return environment
}
