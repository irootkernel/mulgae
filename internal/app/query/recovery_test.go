package query

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/app/prompt"
	"github.com/irootkernel/mulgae/internal/app/recovery"
	"github.com/irootkernel/mulgae/internal/app/review"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

func TestReadFailedRunRecoveryVerifiesReboundStagedInput(t *testing.T) {
	for _, change := range []string{"destination only", "base template", "output contract", "adapter parameter"} {
		t.Run(change, func(t *testing.T) {
			document, blobs := queryRecoveryFixture(t)
			input := &document.Attempts[1].InitialPrompt
			stdin := blobs[input.Stdin.SHA256]
			boundary := strings.Index(string(stdin), "\nMulgae-FRAMES/1\n")
			base, err := prompt.NewTrustedTemplate(input.TemplateID, input.TemplateVersion, stdin[:boundary])
			if err != nil {
				t.Fatal(err)
			}
			oldDestination, _ := ports.NewStagedOutputDestination("/private/tmp/recovery-old", "role-report.md")
			original, err := review.ComposeRootReviewOutputDestination(base, oldDestination)
			if err != nil {
				t.Fatal(err)
			}
			bind := func(template, previous prompt.TrustedTemplate, suffix string) {
				t.Helper()
				compiler, err := prompt.NewCompiler(template, recoveryIssuer{suffix})
				if err != nil {
					t.Fatal(err)
				}
				execution, _ := prompt.ParseExecutionInvocationID(input.ExecutionInvocationID)
				compiled, err := compiler.ReplayStoredWithReboundTemplate(previous, blobs[input.Stdin.SHA256], execution)
				if err != nil {
					t.Fatal(err)
				}
				manifest, err := template.TrustedLayerManifestJSON()
				if err != nil {
					t.Fatal(err)
				}
				input.Stdin = recovery.AddBlob(blobs, compiled.Stdin())
				input.TemplateID, input.TemplateVersion = template.ID(), template.Version()
				input.TemplateSHA256 = "sha256:" + template.SHA256()
				input.ExecutionInvocationID = compiled.Scope().ExecutionInvocationID().String()
				input.AdapterParameters[prompt.TrustedLayerManifestAdapterParameter] = manifest
			}
			bind(original, base, "000000000041")
			root, _ := ports.NewAnchoredRoot(t.TempDir())
			observation, _ := ports.NewPublicationObservation(domain.JournalCollecting, domain.DurableObservationP0None, nil, nil, 1)
			store := &queryStore{observation: observation}
			parent := installQueryRecovery(t, store, root, document, blobs)
			hash := recovery.Digest(queryRecoveryJSON(t, document))
			document.Source = &recovery.Source{Kind: "failed_run_recovery", RunID: parent.RunID().String(), RecoveryManifestSHA256: &hash, AttemptID: document.Attempts[1].AttemptID, ReplayMode: "exact"}
			document.RunID = "r_019f5a09-5eec-7001-8001-000000000012"
			document.RunType = domain.RunTypeRerun
			document.Attempts, document.Roles = document.Attempts[1:], document.Roles[1:]
			document.Attempts[0].AttemptID = "a_019f5a09-5eec-7001-8001-000000000023"
			document.Roles[0].AttemptID = document.Attempts[0].AttemptID
			input = &document.Attempts[0].InitialPrompt
			newDestination, _ := ports.NewStagedOutputDestination("/private/tmp/recovery-new", "role-report.md")
			rebound, err := review.RebindRootReviewOutputDestination(original, newDestination)
			if err != nil {
				t.Fatal(err)
			}
			if change == "base template" {
				changed, _ := prompt.NewTrustedTemplate(base.ID(), base.Version(), []byte("Changed review instructions."))
				rebound, err = review.ComposeRootReviewOutputDestination(changed, newDestination)
			} else if change == "output contract" {
				first, _ := prompt.NewTrustedLayer("review:original-template", "1", base.Bytes())
				output, _ := review.OutputDestinationTrustedLayer(newDestination)
				invalid, _ := prompt.NewTrustedLayer(output.ID(), output.Version(), append(output.Bytes(), []byte("\nExtra instructions.")...))
				rebound, err = prompt.ComposeTrustedTemplate(original.ID(), original.Version(), first, invalid)
			}
			if err != nil {
				t.Fatal(err)
			}
			bind(rebound, original, "000000000042")
			if change == "adapter parameter" {
				input.AdapterParameters["model"] = "changed"
			}
			child := installQueryRecovery(t, store, root, document, blobs)
			service := mustQueryService(t, store, &queryValidator{}, nil)
			_, err = service.ReadFailedRunRecovery(context.Background(), child)
			if change == "destination only" && err != nil || change != "destination only" && err == nil {
				t.Fatalf("staged exact replay %s: %v", change, err)
			}
		})
	}
}

func TestReadRunStatusClassifiesRecoveryReadFailuresWithoutUnverifiedStatus(t *testing.T) {
	run, _, _ := queryCommittedFixture(t, domain.ExitCommittedCIRejected)
	observation, err := ports.NewPublicationObservation(domain.JournalCollecting, domain.DurableObservationP0None, nil, nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	security, _ := domain.NewFailure("recovery.read", domain.FailureSecurityPolicy, "unsafe source", nil)
	providerUnavailable, _ := domain.NewFailure("recovery.read", domain.FailureProviderUnavailable, "source unavailable", nil)
	for _, test := range []struct {
		name        string
		cause       error
		class       domain.FailureClass
		wantCorrupt bool
	}{
		{"corruption", errors.New("invalid recovery blob"), domain.FailureArtifact, true},
		{"joined artifact and cancellation", errors.Join(errors.New("invalid recovery blob"), context.Canceled), domain.FailureArtifact, true},
		{"security", security, domain.FailureSecurityPolicy, false},
		{"cancellation", context.Canceled, domain.FailureCancelled, false},
		{"provider unavailable", providerUnavailable, domain.FailureProviderUnavailable, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := &queryStore{observation: observation, auxiliaryErr: test.cause}
			service := mustQueryService(t, store, &queryValidator{}, &queryTargetReader{})
			status, err := service.ReadRunStatus(context.Background(), run)
			if failureClass(t, err) != test.class {
				t.Fatalf("failure = %v, want %s", err, test.class)
			}
			if test.wantCorrupt {
				assertCorruptRunStatus(t, status, run)
			} else {
				assertZeroRunStatus(t, status)
			}
		})
	}
}

func TestReadRunStatusP2ReadFailuresDoNotProjectUnverifiedStatus(t *testing.T) {
	run, snapshot, observation, artifacts, _, _ := queryRuntimeFixture(t, true)
	security, _ := domain.NewFailure("status.read", domain.FailureSecurityPolicy, "unsafe source", nil)
	providerUnavailable, _ := domain.NewFailure("status.read", domain.FailureProviderUnavailable, "source unavailable", nil)
	for _, test := range []struct {
		name               string
		configure          func(*queryStore, ports.CommittedPublicationSnapshot)
		causeClass         domain.FailureClass
		wantAuxiliaryReads bool
	}{
		{
			name: "snapshot cancellation",
			configure: func(store *queryStore, _ ports.CommittedPublicationSnapshot) {
				store.readErr = context.Canceled
			},
			causeClass: domain.FailureCancelled,
		},
		{
			name: "snapshot security",
			configure: func(store *queryStore, _ ports.CommittedPublicationSnapshot) {
				store.readErr = security
			},
			causeClass: domain.FailureSecurityPolicy,
		},
		{
			name: "support provider unavailable",
			configure: func(store *queryStore, _ ports.CommittedPublicationSnapshot) {
				store.auxiliaryErr = providerUnavailable
			},
			causeClass:         domain.FailureProviderUnavailable,
			wantAuxiliaryReads: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := &queryStore{observation: observation, snapshot: snapshot, auxiliaryArtifacts: artifacts}
			test.configure(store, snapshot)
			status, err := mustQueryService(t, store, &queryValidator{}, nil).ReadRunStatus(context.Background(), run)
			if failureClass(t, err) != test.causeClass {
				t.Fatalf("failure class = %q, want %q", failureClass(t, err), test.causeClass)
			}
			assertZeroRunStatus(t, status)
			if test.wantAuxiliaryReads && store.auxiliaryReads == 0 {
				t.Fatal("support provider failure was returned before an auxiliary artifact read")
			}
		})
	}
}

func TestReadRunStatusObservedCorruptionHasValidUnavailableRecovery(t *testing.T) {
	run, _, _ := queryCommittedFixture(t, domain.ExitCommittedCIRejected)
	observation, err := ports.NewPublicationObservation(
		domain.JournalCompleted,
		domain.DurableObservationAmbiguousOrMismatch,
		nil,
		[]string{"observed_corruption"},
		1,
	)
	if err != nil {
		t.Fatal(err)
	}
	status, err := mustQueryService(t, &queryStore{observation: observation}, &queryValidator{}, nil).ReadRunStatus(context.Background(), run)
	if failureClass(t, err) != domain.FailureArtifact {
		t.Fatalf("failure class = %q, want artifact", failureClass(t, err))
	}
	assertCorruptRunStatus(t, status, run)
}

func assertCorruptRunStatus(t *testing.T, status RunStatus, run ports.PublicationRun) {
	t.Helper()
	if status.SessionID() != run.SessionID() || status.RunID() != run.RunID() || status.PublicationStatus() != domain.PublicationCorrupt || status.Authority() != domain.PublicationAuthorityNone || status.RecoveryAction() != domain.RecoveryActionEmitImmutableCorruptionDiagnostic {
		t.Fatalf("safe corrupt identity lost: %+v", status)
	}
	if _, ok := status.FinalPath(); ok || len(status.RoleReportURIs()) != 0 {
		t.Fatal("corrupt status exposed final authority or role reports")
	}
	recovery := status.FailedRunRecovery()
	if recovery.Available || recovery.UnavailableReason == nil || *recovery.UnavailableReason != "source_invalid" || recovery.ValidateFor(run.RunID()) != nil {
		t.Fatalf("invalid recovery status: %+v", recovery)
	}
}

func assertZeroRunStatus(t *testing.T, status RunStatus) {
	t.Helper()
	if status.SessionID().String() != "" || status.RunID().String() != "" || status.PublicationStatus() != "" || status.Authority() != "" || status.RecoveryAction() != "" {
		t.Fatalf("non-artifact failure returned an unverified status identity: %+v", status)
	}
	if _, ok := status.RunState(); ok {
		t.Fatal("non-artifact failure returned run state")
	}
	if _, ok := status.ContentVerdict(); ok {
		t.Fatal("non-artifact failure returned content verdict")
	}
	if _, ok := status.CoverageStatus(); ok {
		t.Fatal("non-artifact failure returned coverage status")
	}
	if _, ok := status.CIDecision(); ok {
		t.Fatal("non-artifact failure returned CI decision")
	}
	if _, ok := status.FinalPath(); ok || len(status.RoleReportURIs()) != 0 {
		t.Fatal("non-artifact failure returned final or role-report authority")
	}
	recovery := status.FailedRunRecovery()
	if recovery.Available || recovery.SourceKind != nil || recovery.RunID != nil || recovery.ManifestSHA256 != nil || len(recovery.AcceptedRoles) != 0 || len(recovery.RetryAttempts) != 0 || recovery.UnavailableReason != nil {
		t.Fatalf("non-artifact failure returned recovery projection: %+v", recovery)
	}
}

func TestReadFailedRunRecoveryBindsExactAncestorInput(t *testing.T) {
	for _, test := range []struct {
		name         string
		mutate       func(*recovery.Document)
		removeParent bool
	}{
		{name: "valid"},
		{name: "missing parent", removeParent: true},
		{name: "provider changed", mutate: func(d *recovery.Document) {
			d.Attempts[0].ProviderInstance = "other.provider"
			d.Roles[0].ProviderInstance = "other.provider"
		}},
		{name: "adapter changed", mutate: func(d *recovery.Document) { d.Attempts[0].InitialPrompt.AdapterProfile = "other" }},
		{name: "parameters changed", mutate: func(d *recovery.Document) { d.Attempts[0].InitialPrompt.AdapterParameters["model"] = "other" }},
		{name: "foreign attempt", mutate: func(d *recovery.Document) { d.Source.AttemptID = "a_019f5a09-5eec-7001-8001-000000000021" }},
		{name: "wrong parent hash", mutate: func(d *recovery.Document) {
			hash := "sha256:" + strings.Repeat("f", 64)
			d.Source.RecoveryManifestSHA256 = &hash
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			document, blobs := queryRecoveryFixture(t)
			root, _ := ports.NewAnchoredRoot(t.TempDir())
			observation, _ := ports.NewPublicationObservation(domain.JournalCollecting, domain.DurableObservationP0None, nil, nil, 1)
			store := &queryStore{observation: observation}
			parent := installQueryRecovery(t, store, root, document, blobs)
			hash := recovery.Digest(queryRecoveryJSON(t, document))
			sourceAttempt := document.Attempts[1].AttemptID
			document.RunType = domain.RunTypeRerun
			document.RunID = "r_019f5a09-5eec-7001-8001-000000000012"
			document.Source = &recovery.Source{Kind: "failed_run_recovery", RunID: parent.RunID().String(), RecoveryManifestSHA256: &hash, AttemptID: sourceAttempt, ReplayMode: "exact"}
			document.Roles = document.Roles[1:]
			document.Attempts = document.Attempts[1:]
			document.Attempts[0].AttemptID = "a_019f5a09-5eec-7001-8001-000000000023"
			document.Attempts[0].InitialPrompt.ExecutionInvocationID = "019f5a09-5eec-7002-8001-000000000023"
			document.Roles[0].AttemptID = document.Attempts[0].AttemptID
			if test.mutate != nil {
				test.mutate(&document)
			}
			run := installQueryRecovery(t, store, root, document, blobs)
			if test.removeParent {
				path, _ := recovery.ManifestPath(parent)
				delete(store.auxiliaryArtifacts, path.String())
			}
			service := mustQueryService(t, store, &queryValidator{}, &queryTargetReader{})
			snapshot, err := service.ReadFailedRunRecovery(context.Background(), run)
			if test.name == "valid" {
				if err != nil || !snapshot.Status().Available {
					t.Fatalf("valid exact child rejected: %v", err)
				}
			} else if err == nil || errors.Is(err, recovery.ErrUnavailable) {
				t.Fatalf("invalid exact child admitted or hidden as absent: %v", err)
			}
		})
	}
}

func TestReadFailedRunRecoveryBoundsRepeatedExactAncestors(t *testing.T) {
	for _, links := range []int{2, 128, 129} {
		t.Run(fmt.Sprint(links), func(t *testing.T) {
			document, blobs := queryRecoveryFixture(t)
			root, _ := ports.NewAnchoredRoot(t.TempDir())
			observation, _ := ports.NewPublicationObservation(domain.JournalCollecting, domain.DurableObservationP0None, nil, nil, 1)
			store := &queryStore{observation: observation}
			run := installQueryRecovery(t, store, root, document, blobs)
			sourceAttempt := document.Attempts[1].AttemptID
			for link := 0; link < links; link++ {
				hash := recovery.Digest(queryRecoveryJSON(t, document))
				parent := document.RunID
				document.Roles = document.Roles[len(document.Roles)-1:]
				document.Attempts = document.Attempts[len(document.Attempts)-1:]
				document.RunID = fmt.Sprintf("r_019f5a09-5eec-7001-8001-%012d", 100+link)
				document.RunType = domain.RunTypeRerun
				document.Source = &recovery.Source{Kind: "failed_run_recovery", RunID: parent, RecoveryManifestSHA256: &hash, AttemptID: sourceAttempt, ReplayMode: "exact"}
				document.Attempts[0].AttemptID = fmt.Sprintf("a_019f5a09-5eec-7001-8001-%012d", 100+link)
				document.Attempts[0].InitialPrompt.ExecutionInvocationID = fmt.Sprintf("019f5a09-5eec-7002-8001-%012d", 100+link)
				document.Roles[0].AttemptID = document.Attempts[0].AttemptID
				sourceAttempt = document.Attempts[0].AttemptID
				run = installQueryRecovery(t, store, root, document, blobs)
			}
			service := mustQueryService(t, store, &queryValidator{}, nil)
			_, err := service.ReadFailedRunRecovery(context.Background(), run)
			if links <= 128 && err != nil || links > 128 && err == nil {
				t.Fatalf("%d-link ancestry: %v", links, err)
			}
		})
	}
}

func TestReadFailedRunRecoveryRejectsCommittedExactLineageCycleBeforeDepth(t *testing.T) {
	baseRun, baseSnapshot, _, baseArtifacts, basePaths, attemptID := queryRuntimeFixture(t, true)
	bRun, bSnapshot, bObservation, bArtifacts, bPaths, _ := queryRekeyRuntimeFixture(
		t,
		baseRun,
		baseSnapshot,
		baseArtifacts,
		basePaths,
		"r_019f596a-cfe4-7c9c-b82e-7149158243be",
		attemptID,
	)
	reviewID := baseSnapshot.Final().Identity().ReviewID()
	bSnapshot = querySetExactRerunLineage(t, bSnapshot, baseRun.RunID(), baseRun.RunID(), reviewID, attemptID)
	bSnapshot, bObservation, bArtifacts = queryRebindRuntimePrompt(
		t,
		bRun,
		bSnapshot,
		bArtifacts,
		bPaths,
		baseArtifacts[basePaths["prompt-manifest"]],
		baseArtifacts[basePaths["stdin"]],
		attemptID,
	)
	aSnapshot := querySetExactRerunLineage(t, baseSnapshot, bRun.RunID(), bRun.RunID(), reviewID, attemptID)
	aObservation := queryP2Observation(t, baseRun, aSnapshot, domain.JournalCompleted, domain.ExitCommittedCIRejected, 1)

	store := &queryStore{
		observationsByRun: map[string]ports.PublicationObservation{
			baseRun.RunID().String(): aObservation,
			bRun.RunID().String():    bObservation,
		},
		snapshotsByRun: map[string]ports.CommittedPublicationSnapshot{
			baseRun.RunID().String(): aSnapshot,
			bRun.RunID().String():    bSnapshot,
		},
		auxiliaryArtifacts: map[string]ports.ImmutablePublicationArtifact{},
	}
	for path, artifact := range baseArtifacts {
		store.auxiliaryArtifacts[path] = artifact
	}
	for path, artifact := range bArtifacts {
		store.auxiliaryArtifacts[path] = artifact
	}
	service := mustQueryService(t, store, &queryValidator{}, nil)
	committedA, err := service.ReadCommittedAttempt(context.Background(), baseRun, attemptID)
	if err != nil {
		t.Fatalf("committed A fixture is unreadable: %v", err)
	}
	if _, err := service.ReadCommittedAttempt(context.Background(), bRun, attemptID); err != nil {
		t.Fatalf("committed B fixture is unreadable: %v", err)
	}

	target := committedA.Target()
	targetIdentity := target.Identity()
	blobs := map[string][]byte{}
	childPrompt := committedA.Prompt()
	childAttemptID := "a_019f596a-d048-79e7-b2b7-59822f012274"
	childSourceReviewID := committedA.ReviewID().String()
	childPromptBlob := recovery.AddBlob(blobs, childPrompt.Stdin())
	document := recovery.Document{
		SchemaVersion: recovery.SchemaVersion,
		SessionID:     baseRun.SessionID().String(),
		RunID:         "r_019f596a-cfe4-7c9c-b82e-7149158243bd",
		RunType:       domain.RunTypeRerun,
		RunState:      domain.RunFailed,
		Threshold:     domain.SeverityHigh,
		Source: &recovery.Source{
			Kind:       "published_review",
			RunID:      baseRun.RunID().String(),
			ReviewID:   &childSourceReviewID,
			AttemptID:  attemptID.String(),
			ReplayMode: "exact",
		},
		Target: recovery.Target{
			Kind:              targetIdentity.Kind(),
			SHA256:            "sha256:" + targetIdentity.SHA256(),
			RepositoryID:      targetIdentity.RepositoryID(),
			BaseObjectID:      targetIdentity.BaseObjectID(),
			HeadObjectID:      targetIdentity.HeadObjectID(),
			HeadTreeObjectID:  targetIdentity.HeadTreeObjectID(),
			IndexTreeObjectID: targetIdentity.IndexTreeObjectID(),
			GitMode:           targetIdentity.GitMode(),
			Bytes:             recovery.AddBlob(blobs, target.Bytes()),
			CapturedArchive:   recovery.AddBlob(blobs, target.CapturedArchive()),
		},
		SnapshotManifestSHA256:   "sha256:" + strings.Repeat("a", 64),
		WorkspaceTerminalReceipt: "workspace-terminal:v1:sha256:" + strings.Repeat("b", 64),
		Attempts: []recovery.Attempt{{
			AttemptID:        childAttemptID,
			Role:             committedA.Role(),
			ProviderInstance: committedA.Provider(),
			State:            domain.AttemptCancelled,
			FailureClass:     domain.FailureCancelled,
			ReasonCode:       "cancelled",
			InitialPrompt: recovery.Prompt{
				Stdin:                 childPromptBlob,
				SourceInvocationID:    childPrompt.SourceInvocationID(),
				ExecutionInvocationID: childPrompt.ExecutionInvocationID(),
				TemplateID:            childPrompt.TemplateID(),
				TemplateVersion:       childPrompt.TemplateVersion(),
				TemplateSHA256:        childPrompt.TemplateSHA256(),
				AdapterProfile:        childPrompt.AdapterProfile(),
				AdapterParameters:     childPrompt.AdapterParameters(),
				Scope:                 childPrompt.Scope(),
			},
		}},
		Roles: []recovery.Role{{
			Role:             committedA.Role(),
			Required:         true,
			Outcome:          "failed",
			AttemptID:        childAttemptID,
			ProviderInstance: committedA.Provider(),
			FindingIDs:       []string{},
		}},
		Findings: []recovery.Finding{},
	}
	p0, err := ports.NewPublicationObservation(domain.JournalCollecting, domain.DurableObservationP0None, nil, nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	store.observation = p0
	child := installQueryRecovery(t, store, baseRun.Root(), document, blobs)
	store.snapshotReads, store.auxiliaryReads, store.observeCalls = 0, 0, 0
	store.snapshotReadsByRun = map[string]int{}
	store.auxiliaryReadsByRun = map[string]int{}
	store.snapshotRunIDs = nil
	store.auxiliaryRequests = nil

	_, err = service.ReadFailedRunRecovery(context.Background(), child)
	if err == nil || failureClass(t, err) != domain.FailureArtifact || !queryErrorChainContains(err, "cycles") {
		t.Fatalf("committed exact lineage cycle was not rejected as an artifact failure: %v", err)
	}
	if store.snapshotReadsByRun[baseRun.RunID().String()] == 0 || store.snapshotReadsByRun[bRun.RunID().String()] == 0 || store.auxiliaryReadsByRun[baseRun.RunID().String()] == 0 || store.auxiliaryReadsByRun[bRun.RunID().String()] == 0 {
		t.Fatalf("cycle check did not read both committed ancestors: snapshots=%v auxiliary=%v", store.snapshotReadsByRun, store.auxiliaryReadsByRun)
	}
	seenB := false
	for _, runID := range store.snapshotRunIDs {
		if runID == bRun.RunID().String() {
			seenB = true
			continue
		}
		if seenB && runID == baseRun.RunID().String() {
			t.Fatal("cycle check re-read A after reading B instead of stopping at the repeated source")
		}
	}
}

func queryErrorChainContains(err error, needle string) bool {
	if err == nil {
		return false
	}
	if strings.Contains(err.Error(), needle) {
		return true
	}
	switch unwrapped := err.(type) {
	case interface{ Unwrap() []error }:
		for _, nested := range unwrapped.Unwrap() {
			if queryErrorChainContains(nested, needle) {
				return true
			}
		}
	case interface{ Unwrap() error }:
		return queryErrorChainContains(unwrapped.Unwrap(), needle)
	}
	return false
}

func TestReadFailedRunRecoveryRejectsForeignSameSessionPrompt(t *testing.T) {
	document, blobs := queryRecoveryFixture(t)
	foreign := document.Attempts[0].InitialPrompt
	root, _ := ports.NewAnchoredRoot(t.TempDir())
	observation, _ := ports.NewPublicationObservation(domain.JournalCollecting, domain.DurableObservationP0None, nil, nil, 1)
	store := &queryStore{observation: observation}
	parent := installQueryRecovery(t, store, root, document, blobs)
	hash := recovery.Digest(queryRecoveryJSON(t, document))
	attempt := document.Attempts[1]
	role := document.Roles[1]
	document.RunType = domain.RunTypeRerun
	document.RunID = "r_019f5a09-5eec-7001-8001-000000000012"
	document.Source = &recovery.Source{Kind: "failed_run_recovery", RunID: parent.RunID().String(), RecoveryManifestSHA256: &hash, AttemptID: attempt.AttemptID, ReplayMode: "exact"}
	attempt.AttemptID = "a_019f5a09-5eec-7001-8001-000000000023"
	attempt.InitialPrompt = foreign
	role.AttemptID = attempt.AttemptID
	document.Attempts = []recovery.Attempt{attempt}
	document.Roles = []recovery.Role{role}
	run := installQueryRecovery(t, store, root, document, blobs)
	service := mustQueryService(t, store, &queryValidator{}, nil)
	if _, err := service.ReadFailedRunRecovery(context.Background(), run); err == nil {
		t.Fatal("self-consistent foreign input was admitted as exact replay")
	}
}

func TestReadFailedRunRecoveryVerifiesPublishedOriginal(t *testing.T) {
	for _, tamper := range []bool{false, true} {
		t.Run(fmt.Sprint(tamper), func(t *testing.T) {
			parent, snapshot, observation, artifacts, _, attemptID := queryRuntimeFixture(t, true)
			base := &queryStore{snapshot: snapshot, observation: observation, auxiliaryArtifacts: artifacts}
			p0, _ := ports.NewPublicationObservation(domain.JournalCollecting, domain.DurableObservationP0None, nil, nil, 1)
			store := &recoveryParentStore{queryStore: base, parent: parent.RunID(), p0: p0}
			service, err := NewService(store, &queryValidator{}, nil, 8<<20)
			if err != nil {
				t.Fatal(err)
			}
			original, err := service.ReadCommittedAttempt(context.Background(), parent, attemptID)
			if err != nil {
				t.Fatal(err)
			}
			blobs := map[string][]byte{}
			input := original.prompt
			prompt := recovery.Prompt{Stdin: recovery.AddBlob(blobs, input.stdin), SourceInvocationID: input.sourceInvocationID, ExecutionInvocationID: "019f5a09-5eec-7002-8001-000000000025", TemplateID: input.templateID, TemplateVersion: input.templateVersion, TemplateSHA256: input.templateSHA256, AdapterProfile: input.adapterProfile, AdapterParameters: input.adapterParameters, Scope: input.scope}
			if tamper {
				prompt.AdapterParameters["model"] = "changed"
			}
			reviewID := original.ReviewID().String()
			childID := "a_019f5a09-5eec-7001-8001-000000000025"
			document := recovery.Document{SchemaVersion: recovery.SchemaVersion, SessionID: parent.SessionID().String(), RunID: "r_019f5a09-5eec-7001-8001-000000000025", RunType: domain.RunTypeRerun, RunState: domain.RunCancelled, Threshold: domain.SeverityHigh,
				Source:                 &recovery.Source{Kind: "published_review", RunID: parent.RunID().String(), ReviewID: &reviewID, AttemptID: attemptID.String(), ReplayMode: "exact"},
				Target:                 recovery.Target{Kind: domain.TargetPatch, SHA256: "sha256:" + original.target.identity.SHA256(), Bytes: recovery.AddBlob(blobs, original.target.bytes), CapturedArchive: recovery.AddBlob(blobs, original.target.capturedArchive)},
				SnapshotManifestSHA256: "sha256:" + strings.Repeat("a", 64), WorkspaceTerminalReceipt: "workspace-terminal:v1:sha256:" + strings.Repeat("b", 64), Findings: []recovery.Finding{},
				Attempts: []recovery.Attempt{{AttemptID: childID, Role: original.role, ProviderInstance: original.provider, State: domain.AttemptCancelled, FailureClass: domain.FailureCancelled, ReasonCode: "cancelled", InitialPrompt: prompt}},
				Roles:    []recovery.Role{{Role: original.role, Required: true, Outcome: "failed", AttemptID: childID, ProviderInstance: original.provider, FindingIDs: []string{}}},
			}
			child := installQueryRecovery(t, base, parent.Root(), document, blobs)
			_, err = service.ReadFailedRunRecovery(context.Background(), child)
			if tamper && err == nil || !tamper && err != nil {
				t.Fatalf("published original binding: %v", err)
			}
		})
	}
}
