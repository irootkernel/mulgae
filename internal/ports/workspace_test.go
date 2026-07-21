package ports

import (
	"context"
	"errors"
	"testing"
)

type workspaceTerminalTestLease struct {
	identity WorkspaceSnapshotIdentity
	release  WorkspaceTerminalRelease
}

func (lease *workspaceTerminalTestLease) WorkspaceSnapshotIdentity() WorkspaceSnapshotIdentity {
	return lease.identity
}

func (lease *workspaceTerminalTestLease) RevalidateForExecution() (WorkspaceExecutionGuard, error) {
	return nil, nil
}

func (lease *workspaceTerminalTestLease) Receipt() WorkspaceSnapshotReceipt {
	return WorkspaceSnapshotReceipt{}
}

func (lease *workspaceTerminalTestLease) Release(evidence WorkspaceCompletionEvidence) (WorkspaceTerminalReceipt, error) {
	return lease.release(evidence)
}

func (lease *workspaceTerminalTestLease) Abort(WorkspaceAbortEvidence) error { return nil }

type qualificationTerminalTestLease struct {
	identity WorkspaceSnapshotIdentity
	drain    QualificationWorkspaceTerminalDrain
}

func (lease *qualificationTerminalTestLease) WorkspaceSnapshotIdentity() WorkspaceSnapshotIdentity {
	return lease.identity
}

func (lease *qualificationTerminalTestLease) RevalidateForExecution() (WorkspaceExecutionGuard, error) {
	return nil, nil
}

func (lease *qualificationTerminalTestLease) DrainTerminal(ctx context.Context) (QualificationWorkspaceTerminalReceipt, error) {
	return lease.drain(ctx)
}

type providerTerminalTestLease struct {
	instance   string
	generation string
	drain      ProviderNamespaceTerminalDrain
}

func (lease *providerTerminalTestLease) ProviderInstance() string { return lease.instance }
func (lease *providerTerminalTestLease) Generation() string       { return lease.generation }
func (lease *providerTerminalTestLease) Environment() []EnvironmentVariable {
	return nil
}
func (lease *providerTerminalTestLease) ProjectCredential(context.Context, CredentialProjectionRequest) (CredentialProjectionReceipt, error) {
	return CredentialProjectionReceipt{}, nil
}
func (lease *providerTerminalTestLease) ValidateForSpawn() error { return nil }
func (lease *providerTerminalTestLease) DrainTerminal(ctx context.Context) (ProviderNamespaceTerminalReceipt, error) {
	return lease.drain(ctx)
}

func providerTerminalReceiptForTest(t *testing.T, instance, generation string) ProviderNamespaceTerminalReceipt {
	t.Helper()
	var acquired *providerTerminalTestLease
	lease, err := AcquireProviderNamespaceLease(context.Background(), instance, func(_ context.Context, gotInstance string, binding ProviderNamespaceTerminalBinding) (ProviderNamespaceLease, error) {
		acquired = &providerTerminalTestLease{instance: gotInstance, generation: generation}
		drain, err := binding.Bind(generation, func(context.Context) error { return nil })
		if err != nil {
			return nil, err
		}
		acquired.drain = drain
		return acquired, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := lease.DrainTerminal(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return receipt
}

func TestWorkspaceAbortEvidenceRequiresAggregateTerminalReceipt(t *testing.T) {
	workspace, err := NewWorkspaceSnapshotIdentity(
		"/private/snapshot", "snapshot-0123456789abcdef0123456789abcdef",
		"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"policy", 1, 2, 3, 4,
	)
	if err != nil {
		t.Fatal(err)
	}
	first := providerTerminalReceiptForTest(t, "alpha-main", "generation-a")
	second := providerTerminalReceiptForTest(t, "zeta-main", "generation-z")
	terminal, err := NewProviderRunTerminalReceipt([]ProviderNamespaceTerminalReceipt{second, first})
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := NewWorkspaceAbortEvidence(workspace, WorkspaceAbortExecutionFailure, terminal)
	if err != nil {
		t.Fatal(err)
	}
	if !evidence.Valid() || len(evidence.TerminalReceipt().NamespaceReceipts()) != 2 {
		t.Fatalf("abort evidence = %#v", evidence)
	}
	if _, err := NewWorkspaceAbortEvidence(workspace, WorkspaceAbortExecutionFailure, ProviderRunTerminalReceipt{}); err == nil {
		t.Fatal("abort evidence accepted missing aggregate terminal receipt")
	}
}
func TestQualificationWorkspaceTerminalReceiptRequiresWorkspaceIdentity(t *testing.T) {
	if _, err := (QualificationWorkspaceTerminalBinding{}).Bind(WorkspaceSnapshotIdentity{}, func(context.Context) error { return nil }); err == nil {
		t.Fatal("qualification terminal binding accepted an empty workspace identity")
	}
	workspace, err := NewWorkspaceSnapshotIdentity(
		"/private/snapshot", "snapshot-0123456789abcdef0123456789abcdef",
		"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"policy", 1, 2, 3, 4,
	)
	if err != nil {
		t.Fatal(err)
	}
	var acquired *qualificationTerminalTestLease
	lease, err := AcquireQualificationWorkspaceLease(context.Background(), func(_ context.Context, binding QualificationWorkspaceTerminalBinding) (QualificationWorkspaceLease, error) {
		acquired = &qualificationTerminalTestLease{identity: workspace}
		drain, err := binding.Bind(workspace, func(context.Context) error { return nil })
		if err != nil {
			return nil, err
		}
		acquired.drain = drain
		return acquired, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := lease.DrainTerminal(context.Background())
	if err != nil || !receipt.Valid() || receipt.WorkspaceSnapshotIdentity() != workspace {
		t.Fatalf("qualification terminal receipt = %#v, %v", receipt, err)
	}
}
func TestWorkspaceCompletionEvidenceAndTerminalReceipt(t *testing.T) {
	workspace, err := NewWorkspaceSnapshotIdentity(
		"/private/snapshot", "snapshot-0123456789abcdef0123456789abcdef",
		"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"policy", 1, 2, 3, 4,
	)
	if err != nil {
		t.Fatal(err)
	}
	namespace := providerTerminalReceiptForTest(t, "alpha-main", "generation-a")
	terminal, err := NewProviderRunTerminalReceipt([]ProviderNamespaceTerminalReceipt{namespace})
	if err != nil {
		t.Fatal(err)
	}
	completion, err := NewWorkspaceCompletionEvidence(workspace, "r_019f596a-cf81-7c67-b265-f37053d51ccf", terminal)
	if err != nil {
		t.Fatal(err)
	}
	var acquired *workspaceTerminalTestLease
	lease, err := AcquireWorkspaceSnapshotLease(context.Background(), func(_ context.Context, binding WorkspaceTerminalBinding) (WorkspaceSnapshotLease, error) {
		acquired = &workspaceTerminalTestLease{identity: workspace}
		release, err := binding.Bind(workspace, func(WorkspaceCompletionEvidence) error { return nil })
		if err != nil {
			return nil, err
		}
		acquired.release = release
		return acquired, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	first, err := lease.Release(completion)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lease.Release(completion); err == nil {
		t.Fatal("workspace terminal release allowed stale issuance")
	}
	if !first.Valid() {
		t.Fatalf("terminal receipt is invalid: %#v", first)
	}
	if first.WorkspaceSnapshotIdentity() != workspace || first.RunID() != "r_019f596a-cf81-7c67-b265-f37053d51ccf" || !first.ProviderRunTerminalReceipt().Equal(terminal) {
		t.Fatalf("terminal receipt lost completion identity: %#v", first)
	}
	received := first.ProviderRunTerminalReceipt().NamespaceReceipts()
	received[0] = ProviderNamespaceTerminalReceipt{}
	if !first.ProviderRunTerminalReceipt().Equal(terminal) {
		t.Fatal("terminal receipt exposed provider aggregate storage")
	}
	if _, err := NewWorkspaceCompletionEvidence(workspace, "", terminal); err == nil {
		t.Fatal("completion evidence accepted empty run ID")
	}
	if _, err := NewWorkspaceCompletionEvidence(workspace, "run-1", terminal); err == nil {
		t.Fatal("completion evidence accepted non-canonical run ID")
	}
	if _, err := NewWorkspaceCompletionEvidence(workspace, "r_019f596a-cf81-7c67-b265-f37053d51ccf", ProviderRunTerminalReceipt{}); err == nil {
		t.Fatal("completion evidence accepted incomplete provider aggregate")
	}
}
func TestQualificationWorkspaceTerminalDrainRequiresCompletedAcquisition(t *testing.T) {
	workspace, err := NewWorkspaceSnapshotIdentity(
		"/private/qualification", "snapshot-0123456789abcdef0123456789abcdef",
		"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"policy", 1, 2, 3, 4,
	)
	if err != nil {
		t.Fatal(err)
	}
	mismatch, err := NewWorkspaceSnapshotIdentity(
		"/private/other-qualification", "snapshot-0123456789abcdef0123456789abcdef",
		"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"policy", 1, 2, 3, 4,
	)
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name string
		kind string
	}{
		{name: "success", kind: "success"},
		{name: "callback error", kind: "error"},
		{name: "nil lease", kind: "nil"},
		{name: "identity mismatch", kind: "mismatch"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var drain QualificationWorkspaceTerminalDrain
			effects := 0
			lease, err := AcquireQualificationWorkspaceLease(context.Background(), func(_ context.Context, binding QualificationWorkspaceTerminalBinding) (QualificationWorkspaceLease, error) {
				acquired := &qualificationTerminalTestLease{identity: workspace}
				var bindErr error
				drain, bindErr = binding.Bind(workspace, func(context.Context) error {
					effects++
					return nil
				})
				if bindErr != nil {
					return nil, bindErr
				}
				receipt, drainErr := drain(context.Background())
				if drainErr == nil || receipt.Valid() {
					t.Fatal("qualification terminal drain issued proof before acquisition completed")
				}
				switch test.kind {
				case "error":
					return nil, errors.New("acquisition failed")
				case "nil":
					return nil, nil
				case "mismatch":
					return &qualificationTerminalTestLease{identity: mismatch}, nil
				default:
					acquired.drain = drain
					return acquired, nil
				}
			})
			if effects != 0 {
				t.Fatalf("qualification terminal effects ran during acquisition: %d", effects)
			}
			if test.kind != "success" {
				if err == nil || lease != nil {
					t.Fatalf("qualification acquisition (%s) = %v, %v", test.kind, lease, err)
				}
				receipt, drainErr := drain(context.Background())
				if drainErr == nil || receipt.Valid() {
					t.Fatal("qualification terminal drain issued proof after failed acquisition")
				}
				if effects != 0 {
					t.Fatalf("qualification terminal effects ran after failed acquisition: %d", effects)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			receipt, err := lease.DrainTerminal(context.Background())
			if err != nil || !receipt.Valid() {
				t.Fatalf("qualification terminal drain = %#v, %v", receipt, err)
			}
			retry, err := lease.DrainTerminal(context.Background())
			if err != nil || retry != receipt || effects != 1 {
				t.Fatalf("qualification terminal retry = %#v, %v; effects = %d", retry, err, effects)
			}
		})
	}
}

func TestWorkspaceTerminalReleaseRequiresCompletedAcquisition(t *testing.T) {
	workspace, err := NewWorkspaceSnapshotIdentity(
		"/private/workspace", "snapshot-0123456789abcdef0123456789abcdef",
		"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"policy", 1, 2, 3, 4,
	)
	if err != nil {
		t.Fatal(err)
	}
	mismatch, err := NewWorkspaceSnapshotIdentity(
		"/private/other-workspace", "snapshot-0123456789abcdef0123456789abcdef",
		"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"policy", 1, 2, 3, 4,
	)
	if err != nil {
		t.Fatal(err)
	}
	namespace := providerTerminalReceiptForTest(t, "alpha-main", "generation-a")
	terminal, err := NewProviderRunTerminalReceipt([]ProviderNamespaceTerminalReceipt{namespace})
	if err != nil {
		t.Fatal(err)
	}
	completion, err := NewWorkspaceCompletionEvidence(workspace, "r_019f596a-cf81-7c67-b265-f37053d51ccf", terminal)
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name string
		kind string
	}{
		{name: "success", kind: "success"},
		{name: "callback error", kind: "error"},
		{name: "nil lease", kind: "nil"},
		{name: "identity mismatch", kind: "mismatch"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var release WorkspaceTerminalRelease
			effects := 0
			lease, err := AcquireWorkspaceSnapshotLease(context.Background(), func(_ context.Context, binding WorkspaceTerminalBinding) (WorkspaceSnapshotLease, error) {
				acquired := &workspaceTerminalTestLease{identity: workspace}
				var bindErr error
				release, bindErr = binding.Bind(workspace, func(WorkspaceCompletionEvidence) error {
					effects++
					return nil
				})
				if bindErr != nil {
					return nil, bindErr
				}
				receipt, releaseErr := release(completion)
				if releaseErr == nil || receipt.Valid() {
					t.Fatal("workspace terminal release issued proof before acquisition completed")
				}
				switch test.kind {
				case "error":
					return nil, errors.New("acquisition failed")
				case "nil":
					return nil, nil
				case "mismatch":
					return &workspaceTerminalTestLease{identity: mismatch}, nil
				default:
					acquired.release = release
					return acquired, nil
				}
			})
			if effects != 0 {
				t.Fatalf("workspace terminal effects ran during acquisition: %d", effects)
			}
			if test.kind != "success" {
				if err == nil || lease != nil {
					t.Fatalf("workspace acquisition (%s) = %v, %v", test.kind, lease, err)
				}
				receipt, releaseErr := release(completion)
				if releaseErr == nil || receipt.Valid() {
					t.Fatal("workspace terminal release issued proof after failed acquisition")
				}
				if effects != 0 {
					t.Fatalf("workspace terminal effects ran after failed acquisition: %d", effects)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			receipt, err := lease.Release(completion)
			if err != nil || !receipt.Valid() {
				t.Fatalf("workspace terminal release = %#v, %v", receipt, err)
			}
			if _, err := lease.Release(completion); err == nil || effects != 1 {
				t.Fatalf("workspace terminal release retry did not remain consumed; effects = %d", effects)
			}
		})
	}
}
