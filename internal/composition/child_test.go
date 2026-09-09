//go:build darwin && arm64

package composition

import (
	"context"
	"errors"
	"strings"
	"testing"

	appreplay "github.com/irootkernel/mulgae/internal/app/rerun"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

type rerunCleanupTestLease struct {
	identity ports.WorkspaceSnapshotIdentity
	release  ports.WorkspaceTerminalRelease
}

func (lease *rerunCleanupTestLease) WorkspaceSnapshotIdentity() ports.WorkspaceSnapshotIdentity {
	return lease.identity
}
func (*rerunCleanupTestLease) RevalidateForExecution() (ports.WorkspaceExecutionGuard, error) {
	return nil, errors.New("unexpected workspace revalidation")
}
func (*rerunCleanupTestLease) Receipt() ports.WorkspaceSnapshotReceipt {
	return ports.WorkspaceSnapshotReceipt{}
}
func (lease *rerunCleanupTestLease) Release(evidence ports.WorkspaceCompletionEvidence) (ports.WorkspaceTerminalReceipt, error) {
	return lease.release(evidence)
}
func (*rerunCleanupTestLease) Abort(ports.WorkspaceAbortEvidence) error { return nil }

func TestRerunRecoveryCleanupReleasesOnceAndSkipsFallback(t *testing.T) {
	workspace := rerunCleanupWorkspace(t)
	releaseCalls := 0
	lease := rerunCleanupLease(t, workspace, func(ports.WorkspaceCompletionEvidence) error {
		releaseCalls++
		return nil
	})
	runID := rerunCleanupRunID(t, "r_019f596a-cf80-7c67-b265-f37053d51ccf")
	cleanup := rerunRecoveryCleanup{
		expectedSourceSHA256: "source-v1",
		readSource: func(context.Context) (appreplay.SourceAttempt, error) {
			return appreplay.SourceAttempt{ImmutableSHA256: "source-v1"}, nil
		},
		drainTerminal: func(context.Context) (ports.ProviderRunTerminalReceipt, error) {
			return ports.NewEmptyProviderRunTerminalReceipt(), nil
		},
		workspace: workspace,
		release:   lease.Release,
	}
	receipt, err := cleanup.run(context.Background(), runID)
	if err != nil || !receipt.Valid() || receipt.RunID() != runID.String() || releaseCalls != 1 {
		t.Fatalf("recovery cleanup = receipt %#v, error %v, releases %d", receipt, err, releaseCalls)
	}
	fallbackCalls := 0
	if err := cleanup.finish(func() error {
		fallbackCalls++
		return nil
	}); err != nil || fallbackCalls != 0 || releaseCalls != 1 {
		t.Fatalf("successful recovery cleanup used fallback: error %v, fallback %d, releases %d", err, fallbackCalls, releaseCalls)
	}
}

func TestRerunRecoveryCleanupRejectsChangedSourceAndBadReceipts(t *testing.T) {
	workspace := rerunCleanupWorkspace(t)
	runID := rerunCleanupRunID(t, "r_019f596a-cf80-7c67-b265-f37053d51ccf")
	otherRunID := rerunCleanupRunID(t, "r_019f596a-cf81-7c67-b265-f37053d51ccf")
	terminal := ports.NewEmptyProviderRunTerminalReceipt()
	otherLease := rerunCleanupLease(t, workspace, func(ports.WorkspaceCompletionEvidence) error { return nil })
	otherEvidence, err := ports.NewWorkspaceCompletionEvidence(workspace, otherRunID.String(), terminal)
	if err != nil {
		t.Fatal(err)
	}
	mismatchedReceipt, err := otherLease.Release(otherEvidence)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name       string
		source     string
		release    ports.WorkspaceTerminalRelease
		wantError  string
		wantDrains int
	}{
		{
			name: "changed source", source: "source-v2", wantError: "recovery source changed during child execution",
			release: func(ports.WorkspaceCompletionEvidence) (ports.WorkspaceTerminalReceipt, error) {
				t.Fatal("changed source reached workspace release")
				return ports.WorkspaceTerminalReceipt{}, nil
			},
		},
		{
			name: "invalid receipt", source: "source-v1", wantError: "recovery cleanup receipt is invalid", wantDrains: 1,
			release: func(ports.WorkspaceCompletionEvidence) (ports.WorkspaceTerminalReceipt, error) {
				return ports.WorkspaceTerminalReceipt{}, nil
			},
		},
		{
			name: "mismatched receipt", source: "source-v1", wantError: "recovery cleanup receipt is invalid", wantDrains: 1,
			release: func(ports.WorkspaceCompletionEvidence) (ports.WorkspaceTerminalReceipt, error) {
				return mismatchedReceipt, nil
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			drains := 0
			cleanup := rerunRecoveryCleanup{
				expectedSourceSHA256: "source-v1",
				readSource: func(context.Context) (appreplay.SourceAttempt, error) {
					return appreplay.SourceAttempt{ImmutableSHA256: test.source}, nil
				},
				drainTerminal: func(context.Context) (ports.ProviderRunTerminalReceipt, error) {
					drains++
					return terminal, nil
				},
				workspace: workspace,
				release:   test.release,
			}
			if _, err := cleanup.run(context.Background(), runID); err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("recovery cleanup error = %v, want %q", err, test.wantError)
			}
			if cleanup.cleaned || drains != test.wantDrains {
				t.Fatalf("rejected cleanup state = cleaned %t, drains %d", cleanup.cleaned, drains)
			}
			fallbackCalls := 0
			if err := cleanup.finish(func() error { fallbackCalls++; return nil }); err != nil || fallbackCalls != 1 {
				t.Fatalf("rejected cleanup fallback = error %v, calls %d", err, fallbackCalls)
			}
		})
	}
}

func rerunCleanupWorkspace(t *testing.T) ports.WorkspaceSnapshotIdentity {
	t.Helper()
	identity, err := ports.NewWorkspaceSnapshotIdentity(
		"/private/snapshot", "snapshot-0123456789abcdef0123456789abcdef",
		"sha256:"+strings.Repeat("a", 64), "policy", 1, 2, 3, 4,
	)
	if err != nil {
		t.Fatal(err)
	}
	return identity
}

func rerunCleanupRunID(t *testing.T, value string) domain.RunID {
	t.Helper()
	runID, err := domain.ParseRunID(value)
	if err != nil {
		t.Fatal(err)
	}
	return runID
}

func rerunCleanupLease(t *testing.T, identity ports.WorkspaceSnapshotIdentity, verify func(ports.WorkspaceCompletionEvidence) error) ports.WorkspaceSnapshotLease {
	t.Helper()
	lease, err := ports.AcquireWorkspaceSnapshotLease(context.Background(), func(_ context.Context, binding ports.WorkspaceTerminalBinding) (ports.WorkspaceSnapshotLease, error) {
		release, err := binding.Bind(identity, verify)
		if err != nil {
			return nil, err
		}
		return &rerunCleanupTestLease{identity: identity, release: release}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return lease
}
