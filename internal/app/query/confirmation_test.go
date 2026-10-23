package query

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/app/evidence"
	"github.com/irootkernel/mulgae/internal/app/recovery"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

// armIdentityChangeAfterSnapshot swaps the only observed publication's
// identity for an epoch-2 observation at its first snapshot read. No read
// between the snapshot read and the final confirmation observes the store
// again, so only that confirmation can detect the change.
func armIdentityChangeAfterSnapshot(t *testing.T, store *queryStore, run ports.PublicationRun) {
	t.Helper()
	store.afterSnapshot = func() {
		store.afterSnapshot = nil
		store.observation = queryP2Observation(t, run, querySnapshotAtEpoch(t, store.snapshot, 2), domain.JournalCompleted, domain.ExitCommittedCIRejected, 2)
	}
}

// armRunIdentityChangeAfterSnapshot arms the identity change for one consumed
// publication in a per-run store, at that publication's snapshot read.
func armRunIdentityChangeAfterSnapshot(t *testing.T, store *queryStore, run ports.PublicationRun) {
	t.Helper()
	runID := run.RunID().String()
	store.afterSnapshot = func() {
		if store.snapshotRunIDs[len(store.snapshotRunIDs)-1] != runID {
			return
		}
		store.afterSnapshot = nil
		store.observationsByRun[runID] = queryP2Observation(t, run, querySnapshotAtEpoch(t, store.snapshotsByRun[runID], 2), domain.JournalCompleted, domain.ExitCommittedCIRejected, 2)
	}
}

// runtimeLeg is one queryRuntimeFixture publication ready for a stable or
// mutated entry-point call.
type runtimeLeg struct {
	service   *Service
	store     *queryStore
	run       ports.PublicationRun
	attempt   domain.AttemptID
	targetSHA string
}

func newRuntimeLeg(t *testing.T) *runtimeLeg {
	t.Helper()
	run, snapshot, observation, artifacts, paths, attempt := queryRuntimeFixture(t)
	store := &queryStore{snapshot: snapshot, observation: observation, auxiliaryArtifacts: artifacts}
	return &runtimeLeg{
		service:   mustQueryService(t, store, &queryValidator{}, nil),
		store:     store,
		run:       run,
		attempt:   attempt,
		targetSHA: artifacts[paths["target"]].SHA256(),
	}
}

// liveImageFixture retains one verified PNG observation on the live fixture.
// The normalized finding metadata is rebound together with the raster, since
// live support verification requires it to mirror the final's finding.
func liveImageFixture(t *testing.T) (*Service, *queryStore, ports.PublicationRun) {
	t.Helper()
	png := []byte{137, 80, 78, 71, 13, 10, 26, 10, 0}
	service, store, run, _ := liveCommittedFixture(t, 1, 1)
	final, err := decodeFinalDTO(store.snapshot.Final().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := decodeManifestDTO(store.snapshot.Manifest().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	digest := querySHA(png)
	imageArtifactPath := "evidence/images/sha256-" + strings.TrimPrefix(digest, "sha256:") + ".png"
	final.Findings[0].Evidence[0].Visual = &visualEvidenceDTO{Path: "diagram.png", SHA256: digest, BBox: visualBBoxDTO{Width: 1, Height: 1}, Verification: "verified"}
	final.Target.LiveSource.BinaryEvidence = []evidence.LiveBinaryObservation{{
		Side: "worktree", Path: "diagram.png", SHA256: digest, MediaType: "image/png",
		ByteLength: len(png), ArtifactPath: run.SessionID().String() + "/" + run.RunID().String() + "/" + imageArtifactPath,
	}}
	normalized, err := json.Marshal(final.Findings[0])
	if err != nil {
		t.Fatal(err)
	}
	bindContentFixture(t, store, run, final, manifest, map[string][]byte{imageArtifactPath: png, "excerpts/F001.json": normalized})
	return service, store, run
}

// recoveryConsumedCommittedFixture builds a recovery run whose retained
// source is a published review, so the recovery readers consume one committed
// ancestor. The recompose replay mode keeps exact-replay verification from
// re-reading that ancestor, leaving the final confirmation as the only guard.
func recoveryConsumedCommittedFixture(t *testing.T) (*Service, *recoveryParentStore, ports.PublicationRun, ports.PublicationRun) {
	t.Helper()
	parent, snapshot, observation, artifacts, _, attemptID := queryRuntimeFixture(t, true)
	base := &queryStore{snapshot: snapshot, observation: observation, auxiliaryArtifacts: artifacts}
	p0, err := ports.NewPublicationObservation(domain.JournalCollecting, domain.DurableObservationP0None, nil, nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	store := &recoveryParentStore{queryStore: base, parent: parent.RunID(), p0: p0}
	service, err := NewService(store, &queryValidator{}, nil, 8<<20)
	if err != nil {
		t.Fatal(err)
	}
	original, err := service.ReadCommittedAttempt(context.Background(), parent, attemptID)
	if err != nil {
		t.Fatal(err)
	}
	childID := "a_019f5a09-5eec-7001-8001-000000000025"
	childRunID, err := domain.ParseRunID("r_019f5a09-5eec-7001-8001-000000000025")
	if err != nil {
		t.Fatal(err)
	}
	childAttemptID, err := domain.ParseAttemptID(childID)
	if err != nil {
		t.Fatal(err)
	}
	childRun, err := ports.NewPublicationRun(parent.Root(), parent.SessionID(), childRunID)
	if err != nil {
		t.Fatal(err)
	}
	// The recompose replay mode keeps exact-replay verification from
	// re-reading the ancestor, but requires the child prompt to carry its own
	// scope, so compile one instead of reusing the parent's.
	compiled := queryCanonicalReplayPrompt(t, childRun, childAttemptID, original.target.bytes)
	blobs := map[string][]byte{}
	input := original.prompt
	prompt := recovery.Prompt{Stdin: recovery.AddBlob(blobs, compiled.Stdin()), SourceInvocationID: compiled.Scope().SourceInvocationID().String(), ExecutionInvocationID: compiled.Scope().ExecutionInvocationID().String(), TemplateID: compiled.TrustedTemplate().ID(), TemplateVersion: compiled.TrustedTemplate().Version(), TemplateSHA256: "sha256:" + compiled.TrustedTemplate().SHA256(), AdapterProfile: input.adapterProfile, AdapterParameters: input.adapterParameters, Scope: compiled.Scope().FrameScope().String()}
	reviewID := original.ReviewID().String()
	document := recovery.Document{SchemaVersion: recovery.SchemaVersion, SessionID: parent.SessionID().String(), RunID: "r_019f5a09-5eec-7001-8001-000000000025", RunType: domain.RunTypeRerun, RunState: domain.RunCancelled, Threshold: domain.SeverityHigh,
		Source:                 &recovery.Source{Kind: "published_review", RunID: parent.RunID().String(), ReviewID: &reviewID, AttemptID: attemptID.String(), ReplayMode: "recompose"},
		Target:                 recovery.Target{Kind: domain.TargetPatch, SHA256: "sha256:" + original.target.identity.SHA256(), Bytes: recovery.AddBlob(blobs, original.target.bytes), CapturedArchive: recovery.AddBlob(blobs, original.target.capturedArchive)},
		SnapshotManifestSHA256: "sha256:" + strings.Repeat("a", 64), WorkspaceTerminalReceipt: "workspace-terminal:v1:sha256:" + strings.Repeat("b", 64), Findings: []recovery.Finding{},
		Attempts: []recovery.Attempt{{AttemptID: childID, Role: original.role, ProviderInstance: original.provider, State: domain.AttemptCancelled, FailureClass: domain.FailureCancelled, ReasonCode: "cancelled", InitialPrompt: prompt}},
		Roles:    []recovery.Role{{Role: original.role, Required: true, Outcome: "failed", AttemptID: childID, ProviderInstance: original.provider, FindingIDs: []string{}}},
	}
	child := installQueryRecovery(t, base, parent.Root(), document, blobs)
	base.resolutionsByRun = map[string]ports.PublicationRun{child.RunID().String(): child, parent.RunID().String(): parent}
	return service, store, child, parent
}

// TestEntryPointsConfirmConsumedPublicationsBeforeReturning pins the DF-010
// final-confirmation rule for ListFindings, ReadCommittedRoleReport,
// ReadRuntimeTarget, ReadCommittedAttempt, ReadCommittedFindingSource,
// RenderExcerptAt, ReadCommittedForComposition, ReadCompositionSupport,
// ReadSourceImageArtifact, ReadFailedRunRecovery and
// ReadRecoveryCompositionProviders: the unmutated call succeeds, and a
// publication-identity change of a consumed committed publication, armed
// after its snapshot read and visible only to the final confirmation, fails
// the call without returning data. Recovery legs arm the change on the
// consumed committed ancestor. The other context owners are covered
// elsewhere: ReadCommitted by TestReadCommittedBindsSnapshotToStableP2Epoch
// and TestReadCommittedStableWithoutSupportIndexKeepsTwoObservations, Inspect
// by TestInspectionInterleavingsFailClosedAtEveryObservationPoint, ReadFinding
// by TestReadFindingInterleavingsAfterSnapshotFailClosed, ReadRunStatus by
// TestReadRunStatusInterleavingsPreserveCorruptIdentity, the content reads by
// TestReadContentInterleavingsFailClosed and
// TestReadSourceEvidenceRejectsReboundAndUnservedCorruptSupport, and
// WithVerifiedSnapshot by the report package's
// TestWithVerifiedSnapshotConfirmsBeforeReturning.
func TestEntryPointsConfirmConsumedPublicationsBeforeReturning(t *testing.T) {
	entries := []struct {
		name            string
		stable, mutated func(*testing.T)
	}{
		{
			name: "ListFindings",
			stable: func(t *testing.T) {
				service, _, run, _ := inspectionFixture(t, 1)
				findings, err := service.ListFindings(context.Background(), run, domain.SeverityLow)
				if err != nil || len(findings) != 1 {
					t.Fatalf("stable ListFindings = %v (%v)", findings, err)
				}
			},
			mutated: func(t *testing.T) {
				service, store, run, _ := inspectionFixture(t, 1)
				armIdentityChangeAfterSnapshot(t, store, run)
				findings, err := service.ListFindings(context.Background(), run, domain.SeverityLow)
				if failureClass(t, err) != domain.FailureArtifact || len(findings) != 0 {
					t.Fatalf("changed publication listed findings: %v (%v)", findings, err)
				}
			},
		},
		{
			name: "ReadCommittedRoleReport",
			stable: func(t *testing.T) {
				service, _, run, _ := inspectionFixture(t, 1)
				review, err := service.ReadCommitted(context.Background(), run)
				if err != nil {
					t.Fatal(err)
				}
				content, err := service.ReadCommittedRoleReport(context.Background(), run, review.RoleReports()[0])
				if err != nil || len(content) == 0 {
					t.Fatalf("stable role report = %q (%v)", content, err)
				}
			},
			mutated: func(t *testing.T) {
				service, store, run, _ := inspectionFixture(t, 1)
				review, err := service.ReadCommitted(context.Background(), run)
				if err != nil {
					t.Fatal(err)
				}
				armIdentityChangeAfterSnapshot(t, store, run)
				content, err := service.ReadCommittedRoleReport(context.Background(), run, review.RoleReports()[0])
				if failureClass(t, err) != domain.FailureArtifact || len(content) != 0 {
					t.Fatalf("changed publication served a role report: %q (%v)", content, err)
				}
			},
		},

		{
			name: "ReadCommittedForComposition",
			stable: func(t *testing.T) {
				run, _, service := compositionReadyRuntimeFixture(t)
				if _, err := service.ReadCommittedForComposition(context.Background(), run); err != nil {
					t.Fatalf("stable composition read = %v", err)
				}
			},
			mutated: func(t *testing.T) {
				run, store, service := compositionReadyRuntimeFixture(t)
				armIdentityChangeAfterSnapshot(t, store, run)
				if review, err := service.ReadCommittedForComposition(context.Background(), run); failureClass(t, err) != domain.FailureArtifact || review.ReviewID().String() != "" {
					t.Fatalf("changed composition source = %+v (%v)", review, err)
				}
			},
		},
		{
			name: "ReadCompositionSupport",
			stable: func(t *testing.T) {
				deltaRun, _, _, service := deltaRuntimeCompositionFixture(t)
				if _, err := service.ReadCompositionSupport(context.Background(), deltaRun); err != nil {
					t.Fatalf("stable composition support = %v", err)
				}
			},
			mutated: func(t *testing.T) {
				deltaRun, _, store, service := deltaRuntimeCompositionFixture(t)
				armRunIdentityChangeAfterSnapshot(t, store, deltaRun)
				// ReadCompositionSupport reports partial material alongside
				// errors; the artifact failure governs the call.
				if _, err := service.ReadCompositionSupport(context.Background(), deltaRun); failureClass(t, err) != domain.FailureArtifact {
					t.Fatalf("changed composition support = %v", err)
				}
			},
		},
		{
			name: "ReadSourceImageArtifact",
			stable: func(t *testing.T) {
				service, _, run := liveImageFixture(t)
				review, err := service.ReadCommitted(context.Background(), run)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := service.ReadSourceImageArtifact(context.Background(), run, review.FinalSHA256(), review.SourceIdentitySHA256(), "worktree", "diagram.png"); err != nil {
					t.Fatalf("stable source image = %v", err)
				}
			},
			mutated: func(t *testing.T) {
				service, store, run := liveImageFixture(t)
				review, err := service.ReadCommitted(context.Background(), run)
				if err != nil {
					t.Fatal(err)
				}
				armIdentityChangeAfterSnapshot(t, store, run)
				artifact, err := service.ReadSourceImageArtifact(context.Background(), run, review.FinalSHA256(), review.SourceIdentitySHA256(), "worktree", "diagram.png")
				if failureClass(t, err) != domain.FailureArtifact || artifact.Valid() {
					t.Fatalf("changed publication served a source image: %+v (%v)", artifact, err)
				}
			},
		},
		{
			name: "ReadFailedRunRecovery",
			stable: func(t *testing.T) {
				service, _, child, _ := recoveryConsumedCommittedFixture(t)
				if snapshot, err := service.ReadFailedRunRecovery(context.Background(), child); err != nil || !snapshot.Status().Available {
					t.Fatalf("stable recovery read = %+v (%v)", snapshot.Status(), err)
				}
			},
			mutated: func(t *testing.T) {
				service, store, child, parent := recoveryConsumedCommittedFixture(t)
				armIdentityChangeAfterSnapshot(t, store.queryStore, parent)
				if snapshot, err := service.ReadFailedRunRecovery(context.Background(), child); failureClass(t, err) != domain.FailureArtifact || len(snapshot.Manifest()) != 0 {
					t.Fatalf("changed recovery ancestor = %+v (%v)", snapshot.Status(), err)
				}
			},
		},
		{
			name: "ReadRecoveryCompositionProviders",
			stable: func(t *testing.T) {
				service, _, child, _ := recoveryConsumedCommittedFixture(t)
				providers, err := service.ReadRecoveryCompositionProviders(context.Background(), child)
				if err != nil || len(providers) == 0 {
					t.Fatalf("stable recovery providers = %v (%v)", providers, err)
				}
			},
			mutated: func(t *testing.T) {
				service, store, child, parent := recoveryConsumedCommittedFixture(t)
				armIdentityChangeAfterSnapshot(t, store.queryStore, parent)
				if providers, err := service.ReadRecoveryCompositionProviders(context.Background(), child); failureClass(t, err) != domain.FailureArtifact || len(providers) != 0 {
					t.Fatalf("changed recovery ancestor providers = %v (%v)", providers, err)
				}
			},
		},
	}
	// Each runtime call reports whether it returned data, so the mutated leg
	// can assert the failure carried none.
	for _, spec := range []struct {
		name string
		call func(*runtimeLeg) (bool, error)
	}{
		{name: "ReadRuntimeTarget", call: func(leg *runtimeLeg) (bool, error) {
			target, err := leg.service.ReadRuntimeTarget(context.Background(), leg.run)
			return target.Identity().SHA256() != "" || len(target.Bytes()) != 0, err
		}},
		{name: "ReadCommittedAttempt", call: func(leg *runtimeLeg) (bool, error) {
			attempt, err := leg.service.ReadCommittedAttempt(context.Background(), leg.run, leg.attempt)
			return attempt.ReviewID().String() != "" || len(attempt.prompt.stdin) != 0, err
		}},
		{name: "ReadCommittedFindingSource", call: func(leg *runtimeLeg) (bool, error) {
			source, err := leg.service.ReadCommittedFindingSource(context.Background(), leg.run, "F001")
			return len(source.Normalized()) != 0 || len(source.Excerpt()) != 0, err
		}},
		{name: "RenderExcerptAt", call: func(leg *runtimeLeg) (bool, error) {
			excerpt, err := leg.service.RenderExcerpt(context.Background(), leg.run, "F001", leg.targetSHA)
			return len(excerpt) != 0, err
		}},
	} {
		spec := spec
		entries = append(entries, struct {
			name            string
			stable, mutated func(*testing.T)
		}{
			name: spec.name,
			stable: func(t *testing.T) {
				leg := newRuntimeLeg(t)
				if returned, err := spec.call(leg); err != nil || !returned {
					t.Fatalf("stable %s = returned %t, %v", spec.name, returned, err)
				}
			},
			mutated: func(t *testing.T) {
				leg := newRuntimeLeg(t)
				armIdentityChangeAfterSnapshot(t, leg.store, leg.run)
				returned, err := spec.call(leg)
				if failureClass(t, err) != domain.FailureArtifact || returned {
					t.Fatalf("%s accepted a changed consumed publication: returned %t, %v", spec.name, returned, err)
				}
			},
		})
	}
	for _, entry := range entries {
		t.Run(entry.name, func(t *testing.T) {
			entry.stable(t)
		})
		t.Run(entry.name+"/changed_consumed_publication", entry.mutated)
	}
}
