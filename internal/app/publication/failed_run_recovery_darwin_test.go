//go:build darwin && arm64

package publication

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/adapters/filesystem"
	"github.com/irootkernel/mulgae/internal/adapters/jsonschema"
	"github.com/irootkernel/mulgae/internal/app/clean"
	"github.com/irootkernel/mulgae/internal/app/query"
	"github.com/irootkernel/mulgae/internal/app/recovery"
	"github.com/irootkernel/mulgae/internal/app/review"
	"github.com/irootkernel/mulgae/internal/builtin"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

func TestIntegrationFailedRecoveryReadAfterProcessRestart(t *testing.T) {
	ctx := context.Background()
	validator, err := jsonschema.New(ctx, builtin.NewCatalog())
	if err != nil {
		t.Fatal(err)
	}
	clock := publicationServiceClock{now: publicationTestTime()}
	store, err := filesystem.NewPublicationStore(validator, clock, publicationIntegrationIDs{reviewID: publicationTestReviewID(t)}, filesystem.NewSecureWriter())
	if err != nil {
		t.Fatal(err)
	}
	if rootPath := os.Getenv("MULGAE_TEST_RECOVERY_RESTART_ROOT"); rootPath != "" {
		root, err := ports.NewAnchoredRoot(rootPath)
		if err != nil {
			t.Fatal(err)
		}
		queries, err := query.NewService(store, validator, nil, 8<<20)
		if err != nil {
			t.Fatal(err)
		}
		runID, err := domain.ParseRunID(os.Getenv("MULGAE_TEST_RECOVERY_RESTART_RUN"))
		if err != nil {
			t.Fatal(err)
		}
		run, err := queries.ResolveRun(ctx, root, runID)
		if err != nil {
			t.Fatal(err)
		}
		snapshot, err := queries.ReadFailedRunRecovery(ctx, run)
		if err != nil {
			t.Fatal(err)
		}
		status, err := queries.ReadRunStatus(ctx, run)
		if err != nil {
			t.Fatal(err)
		}
		state, present := status.RunState()
		if !present || state != snapshot.Document().RunState || !status.FailedRunRecovery().Available || status.PublicationStatus() != domain.PublicationNotPublished || len(status.FailedRunRecovery().AcceptedRoles) != 1 || len(status.FailedRunRecovery().RetryAttempts) != 2 {
			t.Fatalf("restart status lost failed recovery: %+v", status.FailedRunRecovery())
		}
		if _, err := queries.ReadCommitted(ctx, run); err == nil {
			t.Fatal("failed recovery acquired final-review authority")
		}
		reference, err := snapshot.Reference()
		if err != nil || reference.RunID() != runID || reference.ReviewID().String() != "" || reference.RecoveryManifestSHA256() != recovery.Digest(snapshot.Manifest()) {
			t.Fatalf("historical recovery lost verified source identity: %v", err)
		}
		for _, blob := range snapshot.Document().Blobs() {
			content := snapshot.Blob(blob)
			if recovery.Digest(content) != blob.SHA256 || int64(len(content)) != blob.ByteLength {
				t.Fatal("historical recovery blob lost bound content")
			}
		}
		if len(snapshot.Blob(snapshot.Document().Target.CapturedArchive)) == 0 {
			t.Fatal("historical archive disappeared after restart")
		}
		return
	}
	result, target, inputs, _ := failedRecoveryCoordinator(t, review.AttemptConditionInternalInvariant)
	root, err := ports.NewAnchoredRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// Construct a validated historical fixture without reviving source execution.
	manifest := recovery.Digest([]byte("historical snapshot manifest"))
	prepared, err := PrepareFailedRunRecovery(ctx, result, target, domain.SeverityHigh, manifest, RunPublicationContext{}, inputs)
	if err != nil {
		t.Fatal(err)
	}
	terminal := failedRecoveryTerminalReceipt(t, result.RunID(), manifest)
	publisher, err := NewService(store, validator, clock, 8<<20)
	if err != nil {
		t.Fatal(err)
	}
	reference, err := publisher.PersistFailedRunRecovery(ctx, root, prepared, terminal)
	if err != nil {
		t.Fatal(err)
	}
	if reference.Kind() != "failed_run_recovery" || reference.ReviewID().String() != "" {
		t.Fatal("failed source used final review identity")
	}
	command := exec.Command(os.Args[0], "-test.run=^TestIntegrationFailedRecoveryReadAfterProcessRestart$", "-test.count=1")
	command.Env = append(os.Environ(), "MULGAE_TEST_RECOVERY_RESTART_ROOT="+root.String(), "MULGAE_TEST_RECOVERY_RESTART_RUN="+result.RunID().String())
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("new process failed to restore recovery: %v\n%s", err, output)
	}

	cleanup, err := filesystem.NewCleanupStore(root, store, clock)
	if err != nil {
		t.Fatal(err)
	}
	retention, err := cleanup.Observe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(retention.Runs) != 1 || retention.Runs[0].RunID != result.RunID().String() || retention.Runs[0].Corrupt || retention.Runs[0].Committed || !retention.Runs[0].Completed {
		t.Fatalf("recovery retention misclassified: %+v", retention.Runs)
	}
	t.Run("failed workspace release", func(t *testing.T) {
		failedRoot, err := ports.NewAnchoredRoot(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		failure := errors.New("injected workspace removal failure")
		failedLease, err := ports.AcquireWorkspaceSnapshotLease(ctx, func(_ context.Context, binding ports.WorkspaceTerminalBinding) (ports.WorkspaceSnapshotLease, error) {
			release, err := binding.Bind(terminal.WorkspaceSnapshotIdentity(), func(ports.WorkspaceCompletionEvidence) error { return failure })
			if err != nil {
				return nil, err
			}
			return recoveryReceiptLease{identity: terminal.WorkspaceSnapshotIdentity(), release: release}, nil
		})
		if err != nil {
			t.Fatal(err)
		}
		completion, err := ports.NewWorkspaceCompletionEvidence(terminal.WorkspaceSnapshotIdentity(), result.RunID().String(), ports.NewEmptyProviderRunTerminalReceipt())
		if err != nil {
			t.Fatal(err)
		}
		receipt, err := failedLease.Release(completion)
		if !errors.Is(err, failure) || receipt.Valid() {
			t.Fatalf("failed release granted terminal proof: %v", err)
		}
		if _, err := publisher.PersistFailedRunRecovery(ctx, failedRoot, prepared, receipt); err == nil {
			t.Fatal("failed cleanup granted recovery authority")
		}
		marker := filepath.Join(failedRoot.String(), result.SessionID().String(), result.RunID().String(), "recovery", "manifest.json")
		if _, err := os.Stat(marker); !os.IsNotExist(err) {
			t.Fatalf("failed cleanup left recovery marker: %v", err)
		}
	})
	for _, failManifest := range []bool{false, true} {
		t.Run(fmt.Sprintf("storage failure manifest=%t", failManifest), func(t *testing.T) {
			failedRoot, err := ports.NewAnchoredRoot(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			broken := failedRecoveryWriteStore{PublicationStore: store, manifest: failManifest}
			service, err := NewService(broken, validator, clock, 8<<20)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := service.PersistFailedRunRecovery(ctx, failedRoot, prepared, terminal); err == nil {
				t.Fatal("failed persistence granted replay authority")
			}
			marker := filepath.Join(failedRoot.String(), result.SessionID().String(), result.RunID().String(), "recovery", "manifest.json")
			if _, err := os.Stat(marker); !os.IsNotExist(err) {
				t.Fatalf("failed persistence left authority marker: %v", err)
			}
		})
	}
	run, err := ports.NewPublicationRun(root, result.SessionID(), result.RunID())
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := recovery.Read(ctx, store, validator, run, 8<<20)
	if err != nil {
		t.Fatal(err)
	}
	// A failed replay retains an explicit edge to its source, even without P2.
	childID, err := domain.ParseRunID("r_019f5a09-5eec-7001-8001-000000000099")
	if err != nil {
		t.Fatal(err)
	}
	document := snapshot.Document()
	document.RunID, document.RunType = childID.String(), domain.RunTypeRerun
	document.WorkspaceTerminalReceipt = ""
	digest := recovery.Digest(snapshot.Manifest())
	document.Source = &recovery.Source{Kind: "failed_run_recovery", RunID: result.RunID().String(), RecoveryManifestSHA256: &digest, AttemptID: document.Attempts[1].AttemptID, ReplayMode: "exact"}
	document.Roles, document.Attempts, document.Findings = document.Roles[1:2], document.Attempts[1:2], []recovery.Finding{}
	childBlobs := map[string][]byte{}
	for _, blob := range document.Blobs() {
		childBlobs[blob.SHA256] = snapshot.Blob(blob)
	}
	document.SnapshotManifestSHA256 = manifest
	childPrepared, err := recovery.NewPrepared(ctx, document, childBlobs)
	if err != nil {
		t.Fatal(err)
	}
	childTerminal := failedRecoveryTerminalReceipt(t, childID, manifest)
	if _, err := publisher.PersistFailedRunRecovery(ctx, root, childPrepared, childTerminal); err != nil {
		t.Fatal(err)
	}
	retention, err = cleanup.Observe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(retention.Edges) != 1 || !retention.Edges[0].Valid || retention.Edges[0].ParentRunID != result.RunID().String() || retention.Edges[0].ChildRunID != childID.String() {
		t.Fatalf("failed replay lost cleanup lineage: %+v", retention.Edges)
	}
	for _, retained := range retention.Runs {
		if retained.Corrupt || retained.Committed || !retained.Completed {
			t.Fatalf("failed lineage misclassified: %+v", retained)
		}
	}

	cleaner, err := clean.NewService(clock, validator, cleanup)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := cleaner.Run(ctx, clean.Request{All: true, DryRun: true})
	if err != nil || len(plan.Plan.OrderedActions) != 0 || len(plan.Plan.RetentionProtection.TransitiveAncestorProtection) != 1 {
		t.Fatalf("uncommitted recovery or ancestor lost retention: %+v, %v", plan.Plan, err)
	}

	blobPath, err := recovery.BlobPath(run, snapshot.Document().Attempts[1].InitialPrompt.Stdin)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root.String(), blobPath.String()), []byte("tampered"), 0600); err != nil {
		t.Fatal(err)
	}
	queries, err := query.NewService(store, validator, nil, 8<<20)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := queries.ReadFailedRunRecovery(ctx, run); err == nil {
		t.Fatal("tampered input was replayable")
	}
	if _, err := queries.ReadRunStatus(ctx, run); err == nil {
		t.Fatal("status advertised corrupt recovery")
	}
	retention, err = cleanup.Observe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, retained := range retention.Runs {
		if retained.Corrupt || retained.Committed || !retained.Completed {
			t.Fatalf("cleanup materialized a tampered blob: %+v", retained)
		}
	}
	plan, err = cleaner.Run(ctx, clean.Request{All: true, DryRun: true})
	if err != nil || len(plan.Plan.OrderedActions) != 0 || len(plan.Plan.RetentionProtection.TransitiveAncestorProtection) != 1 {
		t.Fatalf("blob tampering changed recovery retention: %+v, %v", plan.Plan, err)
	}
	manifestPath, err := recovery.ManifestPath(run)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root.String(), manifestPath.String()), append(snapshot.Manifest(), '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	retention, err = cleanup.Observe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	corruptRoot := false
	for _, retained := range retention.Runs {
		if retained.RunID == run.RunID().String() {
			corruptRoot = retained.Corrupt && !retained.Committed
		}
	}
	plan, err = cleaner.Run(ctx, clean.Request{All: true, DryRun: true})
	if err != nil || !corruptRoot || len(plan.Plan.OrderedActions) != 0 {
		t.Fatalf("corrupt recovery metadata lost retention: %+v, %v", plan.Plan, err)
	}
}

type failedRecoveryWriteStore struct {
	ports.PublicationStore
	manifest bool
}

func (store failedRecoveryWriteStore) PersistAuxiliaryArtifact(ctx context.Context, request ports.PersistAuxiliaryArtifactRequest) (ports.PersistAuxiliaryArtifactResult, error) {
	if strings.HasSuffix(request.Artifact().Path().String(), "/recovery/manifest.json") == store.manifest {
		return ports.PersistAuxiliaryArtifactResult{}, errors.New("injected recovery write failure")
	}
	return store.PublicationStore.PersistAuxiliaryArtifact(ctx, request)
}
