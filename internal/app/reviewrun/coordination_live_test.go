package reviewrun

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/app/review"
	"github.com/irootkernel/mulgae/internal/app/validation"
	"github.com/irootkernel/mulgae/internal/builtin"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

type coordinationChangingAdmission struct {
	plan  ExecutionPlan
	calls int
	drift bool
}

func (admission *coordinationChangingAdmission) AdmitLive(context.Context, LiveRequest, ports.LiveSourceReader, domain.ProjectBinding) (ExecutionPlan, error) {
	admission.calls++
	plan := admission.plan.clone()
	if admission.drift && admission.calls > 1 {
		plan.MaxWorkers++
	}
	return plan, nil
}

func TestLiveServiceCoordinationRevalidatesAfterGrant(t *testing.T) {
	for _, drift := range []string{"source", "plan"} {
		t.Run(drift, func(t *testing.T) {
			root, _ := ports.NewAnchoredRoot("/project")
			git, _ := ports.NewAnchoredRoot("/project/.git")
			neutral, _ := ports.NewAnchoredRoot("/neutral")
			credential, _ := ports.NewAnchoredRoot("/credential")
			selector, _ := ports.NewLiveSourceSelector(domain.LiveSourceWorkspace, "")
			path, _ := ports.NewSafeRelativePath("source.go")
			target, _ := ports.NewLiveSourceTarget(selector, ports.GitObjectID{}, ports.GitObjectID{}, false, []ports.LiveSourceChange{{Kind: "included", After: path}})
			binding := ports.ProjectBindingObservation{Root: root, GitDirectory: git, CommonDirectory: git, RootIdentity: ports.ProjectDirectoryIdentity{Device: 1, Inode: 2}, GitIdentity: ports.ProjectDirectoryIdentity{Device: 1, Inode: 3}, CommonIdentity: ports.ProjectDirectoryIdentity{Device: 1, Inode: 3}}
			source := &serviceLiveSource{promptLiveReader: promptLiveReader{target: target, binding: binding}}
			plan := reviewRunPlan(t, []domain.Role{domain.RoleLogic})
			plan.Ceilings = review.DefaultHarnessCeilings()
			admission := &coordinationChangingAdmission{plan: plan, drift: drift == "plan"}
			coordination, store, transport := newOwnerTestCoordinator(t)
			transport.queued = true
			transport.wait = func(context.Context, string) (ports.ReviewLockReply, error) {
				transport.mu.Lock()
				defer transport.mu.Unlock()
				if drift == "source" {
					source.binding.RootIdentity.Inode++
				}
				transport.grant()
				return transport.reply(ports.ReviewLockReceiptOperationClaim), nil
			}
			factory := &serviceLiveAuthority{}
			calls := []string{}
			publisher := &serviceLivePublisher{t: t, source: source, stop: errors.New("unexpected publication")}
			common, err := LoadLiveReviewCommon(context.Background(), builtin.NewCatalog())
			if err != nil {
				t.Fatal(err)
			}
			service, err := NewLiveService(LiveDependencies{Coordination: coordination, Sources: serviceLiveOpener{source}, ReviewerHome: promptLiveHome{root: neutral}, CredentialRoots: []ports.AnchoredRoot{credential}, Admission: admission, Clock: serviceClock{}, IDs: &serviceIDs{}, Build: BuildIdentity{Product: "mulgae", Version: "test", Module: "github.com/irootkernel/mulgae", VCSRevision: "abc123"}, Authority: factory, Validator: &validation.ReviewValidator{}, Publication: publisher, Templates: mustServiceTemplates(t), Common: common, Diagnostics: &serviceDiagnosticFactory{calls: &calls}, Detector: &packetDetectorFake{}})
			if err != nil {
				t.Fatal(err)
			}
			selection, _ := NewRunSelection([]domain.Role{domain.RoleLogic}, nil)
			_, err = service.Execute(context.Background(), LiveRequest{ProjectRoot: root, ArtifactRoot: root, Target: selector, Selection: selection})
			if err == nil || factory.calls != 0 || publisher.calls != 0 || !source.closed || transport.acquires != 1 || transport.releases != 1 || store.record.LocalDrainState != ports.ReviewLocalDrainVerified {
				t.Fatalf("post-wait drift admitted provider work or lost cleanup: %v", err)
			}
		})
	}

	t.Run("uncertain-acquire-reconciles-via-exact-replay-and-settles-without-provider-dispatch", func(t *testing.T) {
		root, _ := ports.NewAnchoredRoot("/project")
		git, _ := ports.NewAnchoredRoot("/project/.git")
		neutral, _ := ports.NewAnchoredRoot("/neutral")
		credential, _ := ports.NewAnchoredRoot("/credential")
		selector, _ := ports.NewLiveSourceSelector(domain.LiveSourceWorkspace, "")
		path, _ := ports.NewSafeRelativePath("source.go")
		target, _ := ports.NewLiveSourceTarget(selector, ports.GitObjectID{}, ports.GitObjectID{}, false, []ports.LiveSourceChange{{Kind: "included", After: path}})
		binding := ports.ProjectBindingObservation{Root: root, GitDirectory: git, CommonDirectory: git, RootIdentity: ports.ProjectDirectoryIdentity{Device: 1, Inode: 2}, GitIdentity: ports.ProjectDirectoryIdentity{Device: 1, Inode: 3}, CommonIdentity: ports.ProjectDirectoryIdentity{Device: 1, Inode: 3}}
		source := &serviceLiveSource{promptLiveReader: promptLiveReader{target: target, binding: binding}}
		plan := reviewRunPlan(t, []domain.Role{domain.RoleLogic})
		plan.Ceilings = review.DefaultHarnessCeilings()
		admission := &coordinationChangingAdmission{plan: plan}
		coordination, store, transport := newOwnerTestCoordinator(t)
		var firstPayload []byte
		transport.acquire = func(_ context.Context, raw []byte) (ports.ReviewLockReply, error) {
			transport.mu.Lock()
			defer transport.mu.Unlock()
			if transport.acquires == 1 {
				firstPayload = append([]byte(nil), raw...)
				var parsed struct {
					LockID     string `json:"lock_id"`
					RequestKey string `json:"request_key"`
					Holder     string `json:"holder"`
				}
				if err := json.Unmarshal(raw, &parsed); err != nil {
					return ports.ReviewLockReply{}, err
				}
				now := time.Now().UTC()
				transport.current = ports.ReviewLockRequest{
					InstallationID: transport.instID(),
					LockID:         parsed.LockID,
					RequestID:      "request-1",
					RequestKey:     parsed.RequestKey,
					Holder:         parsed.Holder,
					State:          ports.ReviewLockStateQueued,
					Sequence:       1,
					Slot:           -1,
					QueuedAt:       now,
				}
				transport.grant()
				return ports.ReviewLockReply{}, &ports.ReviewCoordinationError{
					Reason:    ports.ReviewCoordinationReasonAcquireUncertain,
					Operation: ports.ReviewLockOperationAcquire,
					Retry:     ports.ReviewCoordinationRetrySameKey,
					Uncertain: true,
					Message:   "post-write transport interruption",
				}
			}
			if string(raw) != string(firstPayload) {
				t.Fatalf("expected exact same canonical acquire payload on replay: got %s, want %s", raw, firstPayload)
			}
			return transport.reply(ports.ReviewLockReceiptOperationAcquire), nil
		}
		factory := &serviceLiveAuthority{}
		calls := []string{}
		publisher := &serviceLivePublisher{t: t, source: source, stop: errors.New("unexpected publication")}
		common, err := LoadLiveReviewCommon(context.Background(), builtin.NewCatalog())
		if err != nil {
			t.Fatal(err)
		}
		service, err := NewLiveService(LiveDependencies{Coordination: coordination, Sources: serviceLiveOpener{source}, ReviewerHome: promptLiveHome{root: neutral}, CredentialRoots: []ports.AnchoredRoot{credential}, Admission: admission, Clock: serviceClock{}, IDs: &serviceIDs{}, Build: BuildIdentity{Product: "mulgae", Version: "test", Module: "github.com/irootkernel/mulgae", VCSRevision: "abc123"}, Authority: factory, Validator: &validation.ReviewValidator{}, Publication: publisher, Templates: mustServiceTemplates(t), Common: common, Diagnostics: &serviceDiagnosticFactory{calls: &calls}, Detector: &packetDetectorFake{}})
		if err != nil {
			t.Fatal(err)
		}
		selection, _ := NewRunSelection([]domain.Role{domain.RoleLogic}, nil)
		res, err := service.Execute(context.Background(), LiveRequest{ProjectRoot: root, ArtifactRoot: root, Target: selector, Selection: selection})
		sessionID, runID, allocated := RuntimeDiagnosticIdentityFromError(err)
		if err == nil || !allocated || res.Final().Valid() || factory.calls != 0 || publisher.calls != 0 || !source.closed || transport.acquires != 2 || transport.releases != 1 || store.record.LocalDrainState != ports.ReviewLocalDrainNotStarted || store.record.ObservedRequest.State != ports.ReviewLockStateReleased || store.record.SessionID != sessionID || store.record.RunID != runID {
			t.Fatalf("uncertain acquire in LiveService failed to replay, settle, or retain original run without provider dispatch: err=%v acquires=%d releases=%d factory=%d record=%+v", err, transport.acquires, transport.releases, factory.calls, store.record)
		}
		if cause, ok := CoordinationFailureReason(err); !ok || cause != domain.DiagnosticCauseCoordinationProtectionLost {
			t.Fatalf("expected haepari_protection_lost, got (%q, %v)", cause, ok)
		}
	})
}

func TestReviewCoordinatorOwnedPersistenceFailureSettlesOnlyUnusedGrant(t *testing.T) {
	for _, boundary := range []string{"observation", "local-state"} {
		t.Run(boundary, func(t *testing.T) {
			coordinator, store, transport := newOwnerTestCoordinator(t)
			if boundary == "observation" {
				store.observationErr = errors.New("observation refused")
			} else {
				store.localErr = errors.New("local state refused")
			}
			_, err := coordinator.startOwnedReview(context.Background(), ownerTestRequest(t), time.Minute)
			if err == nil || runtimeDiagnosticFailureClass(err) != domain.FailureArtifact || transport.acquires != 1 || transport.releases != 1 || store.record.LocalDrainState != ports.ReviewLocalDrainNotStarted {
				t.Fatalf("persistence failure crossed protected boundary: %v", err)
			}
		})
	}
}
