//go:build darwin && arm64

package workspace

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/adapters/providercli"
	"github.com/irootkernel/mulgae/internal/ports"
	"golang.org/x/sys/unix"
)

const testRunID = "r_019f596a-cf81-7c67-b265-f37053d51ccf"

type detectorFunc func(context.Context, ports.SafeRelativePath, []byte) (ports.WorkspaceContentVerdict, error)

func (fn detectorFunc) DetectWorkspaceContent(ctx context.Context, path ports.SafeRelativePath, data []byte) (ports.WorkspaceContentVerdict, error) {
	return fn(ctx, path, data)
}

func snapshotFile(t *testing.T, name, contents string) ports.WorkspaceSnapshotFile {
	t.Helper()
	path, err := ports.NewSafeRelativePath(name)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(contents))
	file, err := ports.NewWorkspaceSnapshotFile(path, []byte(contents), "sha256:"+hex.EncodeToString(sum[:]))
	if err != nil {
		t.Fatal(err)
	}
	return file
}
func snapshotRequest(t *testing.T, files ...ports.WorkspaceSnapshotFile) ports.WorkspaceSnapshotRequest {
	t.Helper()
	request, err := ports.NewWorkspaceSnapshotRequest(files, "snapshot-policy-v1")
	if err != nil {
		t.Fatal(err)
	}
	return request
}
func cleanDetector(context.Context, ports.SafeRelativePath, []byte) (ports.WorkspaceContentVerdict, error) {
	return ports.WorkspaceContentClean, nil
}
func materializer(t *testing.T, detector detectorFunc) *Materializer {
	t.Helper()
	root, err := ports.NewAnchoredRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	result, err := NewMaterializer(root, detector)
	if err != nil {
		t.Fatal(err)
	}
	return result
}
func terminalReceipt(t *testing.T) ports.ProviderNamespaceTerminalReceipt {
	t.Helper()
	factory, err := providercli.NewNamespaceFactory(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	lease, err := factory.AcquireProviderNamespace(context.Background(), "workspace-test")
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := lease.DrainTerminal(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return receipt
}

func completionEvidence(t *testing.T, workspace ports.WorkspaceSnapshotIdentity, runID string) ports.WorkspaceCompletionEvidence {
	t.Helper()
	terminal, err := ports.NewProviderRunTerminalReceipt([]ports.ProviderNamespaceTerminalReceipt{terminalReceipt(t)})
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := ports.NewWorkspaceCompletionEvidence(workspace, runID, terminal)
	if err != nil {
		t.Fatal(err)
	}
	return evidence
}

func TestMaterializeLinkedFilesAndReceipt(t *testing.T) {
	m := materializer(t, cleanDetector)
	request := snapshotRequest(t, snapshotFile(t, "docs/linked.md", "linked"), snapshotFile(t, "roadmap.md", "roadmap"))
	receipt, err := m.Materialize(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(filepath.Join(receipt.SnapshotPath(), "roadmap.md")); err != nil || string(got) != "roadmap" {
		t.Fatalf("roadmap: %q, %v", got, err)
	}
	if got, err := os.ReadFile(filepath.Join(receipt.SnapshotPath(), "docs", "linked.md")); err != nil || string(got) != "linked" {
		t.Fatalf("linked: %q, %v", got, err)
	}
	if err := m.Revalidate(receipt); err != nil {
		t.Fatal(err)
	}
	if _, err := os.OpenFile(filepath.Join(receipt.SnapshotPath(), "roadmap.md"), os.O_WRONLY|os.O_APPEND, 0); err == nil {
		t.Fatal("materialized file remained writable")
	}
	if err := m.Cleanup(receipt); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(receipt.SnapshotPath()); !os.IsNotExist(err) {
		t.Fatalf("snapshot survives cleanup: %v", err)
	}
}

func TestRequestRejectsUnsafeBytesAndBounds(t *testing.T) {
	for _, name := range []string{"/absolute", "../escape", ".git/config", ".mulgae/state"} {
		path, err := ports.NewSafeRelativePath(name)
		if err != nil {
			continue
		}
		sum := sha256.Sum256([]byte("x"))
		if _, err := ports.NewWorkspaceSnapshotFile(path, []byte("x"), "sha256:"+hex.EncodeToString(sum[:])); err == nil {
			t.Fatalf("accepted unsafe path %q", name)
		}
	}
	path, _ := ports.NewSafeRelativePath("bad.md")
	if _, err := ports.NewWorkspaceSnapshotFile(path, []byte{0xff}, "sha256:"+strings.Repeat("0", 64)); err == nil {
		t.Fatal("accepted invalid UTF-8")
	}
	if _, err := ports.NewWorkspaceSnapshotFile(path, []byte{'a', 0}, "sha256:"+strings.Repeat("0", 64)); err == nil {
		t.Fatal("accepted NUL")
	}
	large := strings.Repeat("x", int(ports.WorkspaceSnapshotMaxFileBytes)+1)
	if _, err := ports.NewWorkspaceSnapshotFile(path, []byte(large), "sha256:"+strings.Repeat("0", 64)); err == nil {
		t.Fatal("accepted mismatched oversized file")
	}
	if _, err := ports.NewWorkspaceSnapshotRequest(make([]ports.WorkspaceSnapshotFile, ports.WorkspaceSnapshotMaxFiles+1), "policy"); err == nil {
		t.Fatal("accepted excessive file count")
	}
}

func TestMaterializeRejectsReservedCaseAndBlockedWithoutDestination(t *testing.T) {
	m := materializer(t, func(_ context.Context, _ ports.SafeRelativePath, data []byte) (ports.WorkspaceContentVerdict, error) {
		switch string(data) {
		case "secret":
			return ports.WorkspaceContentSecret, nil
		case "instruction":
			return ports.WorkspaceContentDangerousProviderInstruction, nil
		default:
			return ports.WorkspaceContentClean, nil
		}
	})
	for _, blocked := range []string{"secret", "instruction"} {
		request := snapshotRequest(t, snapshotFile(t, "a.md", blocked), snapshotFile(t, "b.md", "ok"))
		if _, err := m.Materialize(context.Background(), request); err == nil {
			t.Fatalf("accepted blocked content %q", blocked)
		}
		entries, err := os.ReadDir(m.root.String())
		if err != nil || len(entries) != 0 {
			t.Fatalf("blocked bytes created destination: %v %v", entries, err)
		}
	}
	m = materializer(t, cleanDetector)
	reserved, err := ports.NewSafeRelativePath(".git/x")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("x"))
	if _, err := ports.NewWorkspaceSnapshotFile(reserved, []byte("x"), "sha256:"+hex.EncodeToString(sum[:])); err == nil {
		t.Fatal("accepted reserved path")
	}
	files := []ports.WorkspaceSnapshotFile{snapshotFile(t, "Readme.md", "x"), snapshotFile(t, "readme.md", "x")}
	if _, err := ports.NewWorkspaceSnapshotRequest(files, "snapshot-policy-v1"); err == nil {
		t.Fatal("accepted case-fold collision")
	}
}

func TestSnapshotDefensiveCopiesDriftAndOwnership(t *testing.T) {
	m := materializer(t, cleanDetector)
	file := snapshotFile(t, "roadmap.md", "before")
	copy := file.Bytes()
	copy[0] = 'X'
	if string(file.Bytes()) != "before" {
		t.Fatal("source file bytes were not defensive")
	}
	receipt, err := m.Materialize(context.Background(), snapshotRequest(t, file))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = os.Chmod(receipt.SnapshotPath(), 0700)
		_ = os.Chmod(filepath.Join(receipt.SnapshotPath(), "roadmap.md"), 0600)
		_ = os.Chmod(filepath.Join(receipt.SnapshotPath(), "._mulgae_workspace_manifest.json"), 0600)
	}()
	if err := os.Chmod(filepath.Join(receipt.SnapshotPath(), "roadmap.md"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(receipt.SnapshotPath(), "roadmap.md"), []byte("after"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := m.Revalidate(receipt); err == nil {
		t.Fatal("revalidation missed identity drift")
	}
	if err := m.Cleanup(receipt); err == nil {
		t.Fatal("cleanup removed drifted snapshot")
	}
}
func TestMaterializeLeaseRevalidationRejectsFilesystemDrift(t *testing.T) {
	request := snapshotRequest(t, snapshotFile(t, "docs/a.md", "a"), snapshotFile(t, "top.md", "top"))
	cases := []struct {
		name   string
		mutate func(*testing.T, string)
	}{
		{"added empty directory", func(t *testing.T, root string) {
			t.Helper()
			makeWorkspaceWritable(t, root)
			if err := os.Mkdir(filepath.Join(root, "empty"), 0755); err != nil {
				t.Fatal(err)
			}
		}},
		{"added nonempty directory", func(t *testing.T, root string) {
			t.Helper()
			makeWorkspaceWritable(t, root)
			if err := os.Mkdir(filepath.Join(root, "extra"), 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, "extra", "file"), []byte("x"), 0644); err != nil {
				t.Fatal(err)
			}
		}},
		{"removed directory", func(t *testing.T, root string) {
			t.Helper()
			makeWorkspaceWritable(t, root)
			if err := os.RemoveAll(filepath.Join(root, "docs")); err != nil {
				t.Fatal(err)
			}
		}},
		{"removed file", func(t *testing.T, root string) {
			t.Helper()
			makeWorkspaceWritable(t, root)
			if err := os.Remove(filepath.Join(root, "top.md")); err != nil {
				t.Fatal(err)
			}
		}},
		{"changed file content", func(t *testing.T, root string) {
			t.Helper()
			makeWorkspaceWritable(t, root)
			if err := os.WriteFile(filepath.Join(root, "top.md"), []byte("changed"), 0644); err != nil {
				t.Fatal(err)
			}
		}},
		{"changed manifest content", func(t *testing.T, root string) {
			t.Helper()
			makeWorkspaceWritable(t, root)
			if err := os.WriteFile(filepath.Join(root, manifestName), []byte("changed"), 0644); err != nil {
				t.Fatal(err)
			}
		}},
		{"writable file mode", func(t *testing.T, root string) {
			t.Helper()
			if err := os.Chmod(filepath.Join(root, "top.md"), 0644); err != nil {
				t.Fatal(err)
			}
		}},
		{"writable directory mode", func(t *testing.T, root string) {
			t.Helper()
			if err := os.Chmod(filepath.Join(root, "docs"), 0755); err != nil {
				t.Fatal(err)
			}
		}},
		{"file hard link", func(t *testing.T, root string) {
			t.Helper()
			makeWorkspaceWritable(t, root)
			if err := os.Link(filepath.Join(root, "top.md"), filepath.Join(root, "linked.md")); err != nil {
				t.Fatal(err)
			}
		}},
		{"symlink", func(t *testing.T, root string) {
			t.Helper()
			makeWorkspaceWritable(t, root)
			if err := os.Symlink("top.md", filepath.Join(root, "link")); err != nil {
				t.Fatal(err)
			}
		}},
		{"special file", func(t *testing.T, root string) {
			t.Helper()
			makeWorkspaceWritable(t, root)
			if err := unix.Mkfifo(filepath.Join(root, "pipe"), 0600); err != nil {
				t.Fatal(err)
			}
		}},
		{"case changed directory path", func(t *testing.T, root string) {
			t.Helper()
			makeWorkspaceWritable(t, root)
			if err := os.Rename(filepath.Join(root, "docs"), filepath.Join(root, "temporary")); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(filepath.Join(root, "temporary"), filepath.Join(root, "DOCS")); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			m := materializer(t, cleanDetector)
			lease, err := m.MaterializeLease(context.Background(), request)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { makeWorkspaceWritable(t, m.root.String()) })
			test.mutate(t, lease.Receipt().SnapshotPath())
			if _, err := lease.RevalidateForExecution(); err == nil {
				t.Fatal("execution revalidation accepted filesystem drift")
			}
			if err := m.Cleanup(lease.Receipt()); err == nil {
				t.Fatal("cleanup removed drifted snapshot")
			}
			if _, err := os.Lstat(lease.Receipt().SnapshotPath()); err != nil {
				t.Fatalf("cleanup did not preserve drift evidence: %v", err)
			}
		})
	}
}

func TestMaterializeLeaseRejectsSnapshotAndRootReplacement(t *testing.T) {
	t.Run("snapshot", func(t *testing.T) {
		m := materializer(t, cleanDetector)
		lease, err := m.MaterializeLease(context.Background(), snapshotRequest(t, snapshotFile(t, "a.md", "a")))
		if err != nil {
			t.Fatal(err)
		}
		snapshot := lease.Receipt().SnapshotPath()
		parked := snapshot + "-original"
		if err := os.Rename(snapshot, parked); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(snapshot, 0755); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { makeWorkspaceWritable(t, m.root.String()) })
		if _, err := lease.RevalidateForExecution(); err == nil {
			t.Fatal("execution revalidation accepted replacement snapshot")
		}
		if err := m.Cleanup(lease.Receipt()); err == nil {
			t.Fatal("cleanup removed replacement snapshot")
		}
		if _, err := os.Lstat(snapshot); err != nil {
			t.Fatalf("replacement snapshot evidence missing: %v", err)
		}
		if _, err := os.Lstat(parked); err != nil {
			t.Fatalf("original snapshot evidence missing: %v", err)
		}
	})
	t.Run("root", func(t *testing.T) {
		parent := t.TempDir()
		rootPath := filepath.Join(parent, "root")
		if err := os.Mkdir(rootPath, 0700); err != nil {
			t.Fatal(err)
		}
		root, err := ports.NewAnchoredRoot(rootPath)
		if err != nil {
			t.Fatal(err)
		}
		m, err := NewMaterializer(root, detectorFunc(cleanDetector))
		if err != nil {
			t.Fatal(err)
		}
		lease, err := m.MaterializeLease(context.Background(), snapshotRequest(t, snapshotFile(t, "a.md", "a")))
		if err != nil {
			t.Fatal(err)
		}
		parked := rootPath + "-original"
		if err := os.Rename(rootPath, parked); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(rootPath, 0700); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { makeWorkspaceWritable(t, parent) })
		if _, err := lease.RevalidateForExecution(); err == nil {
			t.Fatal("execution revalidation accepted replacement root")
		}
		if err := m.Cleanup(lease.Receipt()); err == nil {
			t.Fatal("cleanup removed replacement root")
		}
		if _, err := os.Lstat(filepath.Join(parked, lease.WorkspaceSnapshotIdentity().SnapshotName())); err != nil {
			t.Fatalf("original snapshot evidence missing after root replacement: %v", err)
		}
	})
}

func TestMaterializeLeaseGuardsAndCompletionReceipt(t *testing.T) {
	m := materializer(t, cleanDetector)
	lease, err := m.MaterializeLease(context.Background(), snapshotRequest(t, snapshotFile(t, "docs/a.md", "a")))
	if err != nil {
		t.Fatal(err)
	}
	evidence := completionEvidence(t, lease.WorkspaceSnapshotIdentity(), testRunID)
	first, err := lease.RevalidateForExecution()
	if err != nil {
		t.Fatal(err)
	}
	second, err := lease.RevalidateForExecution()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lease.Release(evidence); err == nil {
		t.Fatal("released with active guards")
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := lease.Release(evidence); err == nil {
		t.Fatal("released while an independent guard remained active")
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	terminal, err := lease.Release(evidence)
	if err != nil {
		t.Fatal(err)
	}
	if !terminal.Valid() || terminal.WorkspaceSnapshotIdentity() != lease.WorkspaceSnapshotIdentity() || terminal.RunID() != evidence.RunID() || !terminal.ProviderRunTerminalReceipt().Equal(evidence.ProviderRunTerminalReceipt()) {
		t.Fatalf("release terminal receipt = %#v", terminal)
	}
	if _, err := os.Lstat(lease.WorkspaceSnapshotIdentity().SnapshotPath()); !os.IsNotExist(err) {
		t.Fatalf("release issued receipt before cleanup: %v", err)
	}
	if _, err := lease.Release(evidence); err == nil {
		t.Fatal("release accepted an idempotent terminal retry")
	}
}

func TestMaterializeLeaseCompletionRequiresMatchingWorkspace(t *testing.T) {
	m := materializer(t, cleanDetector)
	lease, err := m.MaterializeLease(context.Background(), snapshotRequest(t, snapshotFile(t, "a.md", "a")))
	if err != nil {
		t.Fatal(err)
	}
	other, err := m.MaterializeLease(context.Background(), snapshotRequest(t, snapshotFile(t, "b.md", "b")))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lease.Release(completionEvidence(t, other.WorkspaceSnapshotIdentity(), testRunID)); err == nil {
		t.Fatal("released with another valid workspace identity")
	}
	if _, err := lease.Release(completionEvidence(t, lease.WorkspaceSnapshotIdentity(), testRunID)); err != nil {
		t.Fatal(err)
	}
	if _, err := other.Release(completionEvidence(t, other.WorkspaceSnapshotIdentity(), testRunID)); err != nil {
		t.Fatal(err)
	}
}
func TestMaterializeLeaseFailedCleanupReturnsNoReceipt(t *testing.T) {
	m := materializer(t, cleanDetector)
	lease, err := m.MaterializeLease(context.Background(), snapshotRequest(t, snapshotFile(t, "a.md", "a")))
	if err != nil {
		t.Fatal(err)
	}
	snapshot := lease.WorkspaceSnapshotIdentity().SnapshotPath()
	t.Cleanup(func() { makeWorkspaceWritable(t, m.root.String()) })
	if err := os.Rename(snapshot, snapshot+"-renamed"); err != nil {
		t.Fatal(err)
	}
	receipt, err := lease.Release(completionEvidence(t, lease.WorkspaceSnapshotIdentity(), testRunID))
	if err == nil || receipt.Valid() {
		t.Fatalf("failed cleanup issued terminal receipt: %#v, %v", receipt, err)
	}
}

func TestMaterializeLeaseAbortRequiresExactEvidenceAndNoGuards(t *testing.T) {
	m := materializer(t, cleanDetector)
	lease, err := m.MaterializeLease(context.Background(), snapshotRequest(t, snapshotFile(t, "a.md", "a")))
	if err != nil {
		t.Fatal(err)
	}
	guard, err := lease.RevalidateForExecution()
	if err != nil {
		t.Fatal(err)
	}
	terminalReceipt := terminalReceipt(t)
	runTerminalReceipt, err := ports.NewProviderRunTerminalReceipt([]ports.ProviderNamespaceTerminalReceipt{terminalReceipt})
	if err != nil {
		t.Fatal(err)
	}
	abort, err := ports.NewWorkspaceAbortEvidence(lease.WorkspaceSnapshotIdentity(), ports.WorkspaceAbortExecutionFailure, runTerminalReceipt)
	if err != nil {
		t.Fatal(err)
	}
	if err := lease.Abort(abort); err == nil {
		t.Fatal("aborted with active execution guard")
	}
	if err := guard.Close(); err != nil {
		t.Fatal(err)
	}
	if err := lease.Abort(abort); err != nil {
		t.Fatal(err)
	}
	if err := lease.Abort(abort); err != nil {
		t.Fatalf("exact abort retry failed: %v", err)
	}
	differentAbort, err := ports.NewWorkspaceAbortEvidence(lease.WorkspaceSnapshotIdentity(), ports.WorkspaceAbortSecurityViolation, runTerminalReceipt)
	if err != nil {
		t.Fatal(err)
	}
	if err := lease.Abort(differentAbort); err == nil {
		t.Fatal("accepted non-identical abort retry")
	}
	if _, err := lease.Release(completionEvidence(t, lease.WorkspaceSnapshotIdentity(), testRunID)); err == nil {
		t.Fatal("released an already aborted lease")
	}
	if _, err := lease.RevalidateForExecution(); err == nil {
		t.Fatal("aborted lease minted an execution guard")
	}
}
func TestCleanupQuarantineRestoresReplacementAfterValidatedSwap(t *testing.T) {
	m := materializer(t, cleanDetector)
	lease, err := m.MaterializeLease(context.Background(), snapshotRequest(t, snapshotFile(t, "a.md", "owned")))
	if err != nil {
		t.Fatal(err)
	}
	snapshot := lease.WorkspaceSnapshotIdentity().SnapshotPath()
	displaced := snapshot + "-owned"
	t.Cleanup(func() {
		makeWorkspaceWritable(t, displaced)
		makeWorkspaceWritable(t, snapshot)
	})
	replaced := false
	m.operations.beforeQuarantine = func(_ int, _ string) {
		if replaced {
			return
		}
		replaced = true
		if err := os.Rename(snapshot, displaced); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(snapshot, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(snapshot, "replacement"), []byte("replacement"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	owner := cleanupOwnerForReceipt(m, lease.Receipt())
	if err := owner.Retry(); err != nil {
		t.Fatalf("cleanup after initial pathname displacement: %v", err)
	}
	if got, err := os.ReadFile(filepath.Join(snapshot, "replacement")); err != nil || string(got) != "replacement" {
		t.Fatalf("replacement was modified: %q, %v", got, err)
	}
	if _, err := os.Stat(displaced); !os.IsNotExist(err) {
		t.Fatalf("owned snapshot remained: %v", err)
	}
}
func TestCleanupQuarantineRejectsTombSubstitutionAfterVerification(t *testing.T) {
	m := materializer(t, cleanDetector)
	lease, err := m.MaterializeLease(context.Background(), snapshotRequest(t, snapshotFile(t, "a.md", "owned")))
	if err != nil {
		t.Fatal(err)
	}
	snapshot := lease.WorkspaceSnapshotIdentity().SnapshotPath()
	displaced := snapshot + "-owned"
	t.Cleanup(func() {
		makeWorkspaceWritable(t, displaced)
		makeWorkspaceWritable(t, snapshot)
	})
	replaced := false
	replacement := ""
	m.operations.afterQuarantineVerification = func(_ int, tomb string) {
		if replaced {
			return
		}
		replaced = true
		tombPath := filepath.Join(m.root.String(), tomb)
		replacement = tombPath
		if err := os.Rename(tombPath, displaced); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(tombPath, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(tombPath, "replacement"), []byte("replacement"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	owner := cleanupOwnerForReceipt(m, lease.Receipt())
	if err := owner.Retry(); err != nil {
		t.Fatalf("cleanup after tomb substitution: %v", err)
	}
	if got, err := os.ReadFile(filepath.Join(replacement, "replacement")); err != nil || string(got) != "replacement" {
		t.Fatalf("replacement was modified: %q, %v", got, err)
	}
	if _, err := os.Stat(displaced); !os.IsNotExist(err) {
		t.Fatalf("owned snapshot remained: %v", err)
	}
}

func TestMaterializeRollbackCleanupErrorRetainsRetryOwner(t *testing.T) {
	m := materializer(t, cleanDetector)
	primary := errors.New("injected materialization failure")
	cleanup := errors.New("injected cleanup failure")
	m.operations.beforeSeal = func() error { return primary }
	removeTree := m.operations.removeTreeFD
	failed := false
	m.operations.removeTreeFD = func(tree *workspaceTreeCleanupOwner) error {
		if !failed {
			failed = true
			return cleanup
		}
		return removeTree(tree)
	}
	_, err := m.Materialize(context.Background(), snapshotRequest(t, snapshotFile(t, "a.md", "a")))
	if !errors.Is(err, primary) || !errors.Is(err, cleanup) {
		t.Fatalf("rollback diagnostics = %v", err)
	}
	owner, ok := MaterializationCleanupRetryOwner(err)
	if !ok || owner == nil {
		t.Fatalf("rollback error did not retain retry owner: %T %[1]v", err)
	}
	if err := owner.Retry(); err != nil {
		t.Fatalf("retry cleanup: %v", err)
	}
	entries, err := os.ReadDir(m.root.String())
	if err != nil || len(entries) != 0 {
		t.Fatalf("retry left snapshot entries: %v, %v", entries, err)
	}
}
func TestCleanupOwnerRetainsDescriptorAcrossPostUnlinkFailures(t *testing.T) {
	m := materializer(t, cleanDetector)
	receipt, err := m.Materialize(context.Background(), snapshotRequest(t, snapshotFile(t, "a.md", "owned")))
	if err != nil {
		t.Fatal(err)
	}
	owner := cleanupOwnerForReceipt(m, receipt)
	proofFailure := errors.New("injected detachment proof failure")
	unlinkFailure := errors.New("injected unlink failure")
	closeFailure := errors.New("injected descriptor close failure")
	failProof, failUnlink, failClose := true, true, true
	detached := m.operations.descriptorDetached
	unlink := m.operations.unlinkat
	closeFD := m.operations.close
	substituted := false
	replacement := ""
	m.operations.unlinkat = func(parentFD int, name string, flags int) error {
		if failUnlink {
			failUnlink = false
			return unlinkFailure
		}
		if !substituted {
			substituted = true
			root := m.root.String()
			if err := os.Rename(filepath.Join(root, name), filepath.Join(root, "owned-snapshot")); err != nil {
				t.Fatal(err)
			}
			replacement = filepath.Join(root, name)
			if err := os.Mkdir(replacement, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(replacement, "replacement"), []byte("replacement"), 0600); err != nil {
				t.Fatal(err)
			}
			return nil
		}
		return unlink(parentFD, name, flags)
	}
	m.operations.descriptorDetached = func(fd int, device, inode uint64) error {
		if failProof {
			failProof = false
			return proofFailure
		}
		return detached(fd, device, inode)
	}
	m.operations.close = func(fd int) error {
		if fd == owner.fd && failClose {
			failClose = false
			return closeFailure
		}
		return closeFD(fd)
	}
	if err := owner.Retry(); !errors.Is(err, unlinkFailure) {
		t.Fatalf("post-tree unlink failure = %v", err)
	}
	if owner.stage != workspaceCleanupTreeCleared {
		t.Fatalf("stage before unlink retry = %d", owner.stage)
	}
	if err := owner.Retry(); !errors.Is(err, proofFailure) {
		t.Fatalf("post-unlink proof failure = %v", err)
	}
	if owner.stage != workspaceCleanupTreeCleared {
		t.Fatalf("stage after unlink proof failure = %d", owner.stage)
	}
	if err := owner.Retry(); !errors.Is(err, closeFailure) {
		t.Fatalf("descriptor close failure = %v", err)
	}
	if owner.stage != workspaceCleanupDetachmentVerified {
		t.Fatalf("stage after close failure = %d", owner.stage)
	}
	if err := owner.Retry(); err != nil {
		t.Fatalf("descriptor cleanup retry: %v", err)
	}
	if owner.stage != workspaceCleanupOwnerReleased {
		t.Fatalf("terminal cleanup stage = %d", owner.stage)
	}
	if _, err := os.Stat(filepath.Join(m.root.String(), "owned-snapshot")); !os.IsNotExist(err) {
		t.Fatalf("owned snapshot remained: %v", err)
	}
	if got, err := os.ReadFile(filepath.Join(replacement, "replacement")); err != nil || string(got) != "replacement" {
		t.Fatalf("pathname replacement changed: %q, %v", got, err)
	}
}

func TestExecutionGuardCloseFailureRetainsLeaseOwnership(t *testing.T) {
	m := materializer(t, cleanDetector)
	lease, err := m.MaterializeLease(context.Background(), snapshotRequest(t, snapshotFile(t, "a.md", "owned")))
	if err != nil {
		t.Fatal(err)
	}
	guard, err := lease.RevalidateForExecution()
	if err != nil {
		t.Fatal(err)
	}
	closeFailure := errors.New("injected guard close failure")
	closeFD := m.operations.close
	failed := true
	m.operations.close = func(fd int) error {
		if failed {
			failed = false
			return closeFailure
		}
		return closeFD(fd)
	}
	if err := guard.Close(); !errors.Is(err, closeFailure) {
		t.Fatalf("guard close failure = %v", err)
	}
	if _, err := lease.Release(completionEvidence(t, lease.WorkspaceSnapshotIdentity(), testRunID)); err == nil {
		t.Fatal("lease released after failed guard close")
	}
	if err := guard.Close(); err != nil {
		t.Fatalf("guard close retry: %v", err)
	}
	if _, err := lease.Release(completionEvidence(t, lease.WorkspaceSnapshotIdentity(), testRunID)); err != nil {
		t.Fatalf("release after proven guard close: %v", err)
	}
}

func TestMaterializeReceiptDoesNotExposeExecutionAuthority(t *testing.T) {
	m := materializer(t, cleanDetector)
	receipt, err := m.Materialize(context.Background(), snapshotRequest(t, snapshotFile(t, "a.md", "a")))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := any(receipt).(ports.WorkspaceExecutionAuthority); ok {
		t.Fatal("legacy receipt exposed execution authority")
	}
	if err := m.Cleanup(receipt); err != nil {
		t.Fatal(err)
	}
	lease, err := m.MaterializeLease(context.Background(), snapshotRequest(t, snapshotFile(t, "a.md", "a")))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := any(lease).(ports.WorkspaceExecutionAuthority); !ok {
		t.Fatal("v2 lease did not expose execution authority")
	}
	if _, err := lease.Release(completionEvidence(t, lease.WorkspaceSnapshotIdentity(), testRunID)); err != nil {
		t.Fatal(err)
	}
}
func TestQualificationLeaseGuardsModesAndRetryableDrain(t *testing.T) {
	m := materializer(t, cleanDetector)
	lease, err := m.MaterializeQualificationLease(context.Background(), snapshotRequest(t,
		snapshotFile(t, "docs/linked.md", "linked"),
		snapshotFile(t, "roadmap.md", "roadmap"),
	))
	if err != nil {
		t.Fatal(err)
	}
	identity := lease.WorkspaceSnapshotIdentity()
	if info, err := os.Stat(identity.SnapshotPath()); err != nil || info.Mode().Perm() != 0555 {
		t.Fatalf("snapshot directory mode = %v, %v", info.Mode(), err)
	}
	if info, err := os.Stat(filepath.Join(identity.SnapshotPath(), "roadmap.md")); err != nil || info.Mode().Perm() != 0444 {
		t.Fatalf("snapshot file mode = %v, %v", info.Mode(), err)
	}
	guard, err := lease.RevalidateForExecution()
	if err != nil {
		t.Fatal(err)
	}
	launch, err := guard.DuplicateLaunchDirectory()
	if err != nil {
		t.Fatal(err)
	}
	if err := launch.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := lease.DrainTerminal(context.Background()); err == nil {
		t.Fatal("drained with an active guard")
	}
	if err := guard.RevalidateAfterExecution(); err != nil {
		t.Fatal(err)
	}
	if err := guard.Close(); err != nil {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := lease.DrainTerminal(cancelled); err == nil {
		t.Fatal("drained with a canceled context")
	}
	receipt, err := lease.DrainTerminal(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !receipt.Valid() || receipt.WorkspaceSnapshotIdentity() != identity {
		t.Fatalf("terminal receipt = %#v", receipt)
	}
	if _, err := os.Lstat(identity.SnapshotPath()); !os.IsNotExist(err) {
		t.Fatalf("qualification snapshot remains after drain: %v", err)
	}
	retry, err := lease.DrainTerminal(context.Background())
	if err != nil || retry != receipt {
		t.Fatalf("idempotent drain = %#v, %v", retry, err)
	}
	if _, err := lease.RevalidateForExecution(); err == nil {
		t.Fatal("drained qualification lease minted a guard")
	}
}

func TestQualificationLeaseRejectsDriftWithoutTerminalReceipt(t *testing.T) {
	for _, mutate := range []struct {
		name string
		fn   func(*testing.T, string)
	}{
		{"symlink", func(t *testing.T, root string) {
			makeWorkspaceWritable(t, root)
			if err := os.Symlink("roadmap.md", filepath.Join(root, "link")); err != nil {
				t.Fatal(err)
			}
		}},
		{"renamed snapshot", func(t *testing.T, root string) {
			if err := os.Rename(root, root+"-renamed"); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(mutate.name, func(t *testing.T) {
			m := materializer(t, cleanDetector)
			lease, err := m.MaterializeQualificationLease(context.Background(), snapshotRequest(t, snapshotFile(t, "roadmap.md", "roadmap")))
			if err != nil {
				t.Fatal(err)
			}
			snapshot := lease.WorkspaceSnapshotIdentity().SnapshotPath()
			t.Cleanup(func() { makeWorkspaceWritable(t, m.root.String()) })
			mutate.fn(t, snapshot)
			if _, err := lease.RevalidateForExecution(); err == nil {
				t.Fatal("qualification execution accepted drift")
			}
			if receipt, err := lease.DrainTerminal(context.Background()); err == nil || receipt.Valid() {
				t.Fatalf("drifted qualification lease issued terminal receipt: %#v, %v", receipt, err)
			}
		})
	}
}

func TestQualificationLeaseIsIndependentFromUserWorkspaceLease(t *testing.T) {
	m := materializer(t, cleanDetector)
	request := snapshotRequest(t, snapshotFile(t, "roadmap.md", "roadmap"))
	userLease, err := m.MaterializeLease(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	qualificationLease, err := m.MaterializeQualificationLease(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if userLease.WorkspaceSnapshotIdentity() == qualificationLease.WorkspaceSnapshotIdentity() {
		t.Fatal("qualification and user leases share an identity")
	}
	if _, err := qualificationLease.DrainTerminal(context.Background()); err != nil {
		t.Fatal(err)
	}
	userGuard, err := userLease.RevalidateForExecution()
	if err != nil {
		t.Fatalf("qualification cleanup affected user lease: %v", err)
	}
	if err := userGuard.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := userLease.Release(completionEvidence(t, userLease.WorkspaceSnapshotIdentity(), testRunID)); err != nil {
		t.Fatal(err)
	}
}

func makeWorkspaceWritable(t *testing.T, root string) {
	t.Helper()
	if err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return nil
		}
		if entry.IsDir() {
			return os.Chmod(path, 0700)
		}
		return os.Chmod(path, 0600)
	}); err != nil && !os.IsNotExist(err) {
		t.Errorf("restore workspace permissions: %v", err)
	}
}
func TestCleanupOwnerRetriesPreUnlinkTreeFailure(t *testing.T) {
	m := materializer(t, cleanDetector)
	receipt, err := m.Materialize(context.Background(), snapshotRequest(t, snapshotFile(t, "a.md", "owned")))
	if err != nil {
		t.Fatal(err)
	}
	owner := cleanupOwnerForReceipt(m, receipt)
	treeFailure := errors.New("injected tree failure")
	removeTree := m.operations.removeTreeFD
	failed := true
	m.operations.removeTreeFD = func(tree *workspaceTreeCleanupOwner) error {
		if failed {
			failed = false
			return treeFailure
		}
		return removeTree(tree)
	}
	if err := owner.Retry(); !errors.Is(err, treeFailure) {
		t.Fatalf("pre-unlink tree failure = %v", err)
	}
	if owner.stage != workspaceCleanupQuarantined {
		t.Fatalf("stage before unlink = %d", owner.stage)
	}
	if err := owner.Retry(); err != nil {
		t.Fatalf("pre-unlink cleanup retry: %v", err)
	}
	if owner.stage != workspaceCleanupOwnerReleased {
		t.Fatalf("terminal cleanup stage = %d", owner.stage)
	}
}
func TestCleanupTreeRetriesAfterSiblingPrefixAndChildCloseFailure(t *testing.T) {
	m := materializer(t, cleanDetector)
	receipt, err := m.Materialize(context.Background(), snapshotRequest(t,
		snapshotFile(t, "a.md", "first"),
		snapshotFile(t, "z/child.md", "second"),
		snapshotFile(t, "zz.md", "third"),
	))
	if err != nil {
		t.Fatal(err)
	}
	closeFD := m.operations.close
	closeCalls := 0
	closeFailure := errors.New("injected child close failure")
	m.operations.close = func(fd int) error {
		closeCalls++
		if closeCalls == 2 {
			return closeFailure
		}
		return closeFD(fd)
	}
	owner := cleanupOwnerForReceipt(m, receipt)
	if err := owner.Retry(); !errors.Is(err, closeFailure) {
		t.Fatalf("tree close failure = %v", err)
	}
	if owner.tree == nil || len(owner.tree.stack) != 2 ||
		owner.tree.stack[0].next <= 0 ||
		owner.tree.stack[0].next >= len(owner.tree.stack[0].names) ||
		owner.tree.stack[0].names[owner.tree.stack[0].next] != "z" {
		if owner.tree == nil {
			t.Fatal("tree traversal did not retain the child after sibling prefix: nil tree")
		}
		t.Fatalf(
			"tree traversal did not retain the child after sibling prefix: stack=%d root-next=%d root-names=%q child=%q",
			len(owner.tree.stack),
			owner.tree.stack[0].next,
			owner.tree.stack[0].names,
			owner.tree.stack[len(owner.tree.stack)-1].name,
		)
	}
	if err := owner.Retry(); err != nil {
		t.Fatalf("tree cleanup retry: %v", err)
	}
	if owner.stage != workspaceCleanupOwnerReleased {
		t.Fatalf("terminal cleanup stage = %d", owner.stage)
	}
}

func TestCleanupTreeReenumeratesInParentChildReplacementToTerminal(t *testing.T) {
	m := materializer(t, cleanDetector)
	receipt, err := m.Materialize(context.Background(), snapshotRequest(t, snapshotFile(t, "z/child.md", "owned")))
	if err != nil {
		t.Fatal(err)
	}
	owner := cleanupOwnerForReceipt(m, receipt)
	replaced := false
	injected := false
	replacementName := ""
	m.operations.beforeTreeUnlink = func(_ int, _ string) {
		if injected {
			return
		}
		injected = true
		replaced = true
	}
	unlink := m.operations.unlinkat
	m.operations.unlinkat = func(parentFD int, name string, flags int) error {
		if !replaced {
			return unlink(parentFD, name, flags)
		}
		replaced = false
		snapshot := filepath.Join(m.root.String(), owner.tomb)
		if err := os.Rename(filepath.Join(snapshot, name), filepath.Join(snapshot, "owned-z")); err != nil {
			t.Fatal(err)
		}
		replacementName = filepath.Join(snapshot, name)
		if err := os.Mkdir(replacementName, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(replacementName, "replacement"), []byte("replacement"), 0600); err != nil {
			t.Fatal(err)
		}
		return nil
	}
	if err := owner.Retry(); err == nil {
		t.Fatal("child unlink substitution unexpectedly succeeded")
	}
	if err := owner.Retry(); err != nil {
		t.Fatalf("in-parent replacement cleanup retry: %v", err)
	}
	if _, err := os.Stat(replacementName); !os.IsNotExist(err) {
		t.Fatalf("in-parent replacement remained in owned snapshot: %v", err)
	}
	if _, err := os.Stat(filepath.Join(m.root.String(), "owned-z")); !os.IsNotExist(err) {
		t.Fatalf("owned child remained after retry: %v", err)
	}
	if owner.stage != workspaceCleanupOwnerReleased || owner.fd != -1 || owner.rootFD != -1 {
		t.Fatalf("cleanup did not close all descriptors: %#v", owner)
	}
}
func TestCleanupOwnerRetriesPreUnlinkSnapshotReplacement(t *testing.T) {
	m := materializer(t, cleanDetector)
	receipt, err := m.Materialize(context.Background(), snapshotRequest(t, snapshotFile(t, "a.md", "owned")))
	if err != nil {
		t.Fatal(err)
	}
	owner := cleanupOwnerForReceipt(m, receipt)
	replaced := false
	replacementName := ""
	m.operations.beforeSnapshotUnlink = func(_ int, name string) {
		if replaced {
			return
		}
		replaced = true
		replacementName = name
		root := m.root.String()
		if err := os.Rename(filepath.Join(root, name), filepath.Join(root, "owned-snapshot")); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(filepath.Join(root, name), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, name, "replacement"), []byte("replacement"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := owner.Retry(); !errors.Is(err, errIdentityDrift) {
		t.Fatalf("pre-unlink replacement cleanup = %v", err)
	}
	replacement := filepath.Join(m.root.String(), replacementName, "replacement")
	if got, err := os.ReadFile(replacement); err != nil || string(got) != "replacement" {
		t.Fatalf("snapshot replacement was modified: %q, %v", got, err)
	}
	if err := owner.Retry(); err != nil {
		t.Fatalf("pre-unlink replacement retry: %v", err)
	}
	if _, err := os.Stat(filepath.Join(m.root.String(), "owned-snapshot")); !os.IsNotExist(err) {
		t.Fatalf("owned snapshot remained after retry: %v", err)
	}
	if got, err := os.ReadFile(replacement); err != nil || string(got) != "replacement" {
		t.Fatalf("snapshot replacement was modified after retry: %q, %v", got, err)
	}
	if owner.stage != workspaceCleanupOwnerReleased || owner.fd != -1 || owner.rootFD != -1 {
		t.Fatalf("cleanup did not close all descriptors: %#v", owner)
	}
}
func TestPublicCleanupFailureRetainsPostUnlinkRetryOwner(t *testing.T) {
	m := materializer(t, cleanDetector)
	receipt, err := m.Materialize(context.Background(), snapshotRequest(t, snapshotFile(t, "a.md", "owned")))
	if err != nil {
		t.Fatal(err)
	}
	proofFailure := errors.New("injected public cleanup detachment failure")
	detached := m.operations.descriptorDetached
	failed := true
	m.operations.descriptorDetached = func(fd int, device, inode uint64) error {
		if failed {
			failed = false
			return proofFailure
		}
		return detached(fd, device, inode)
	}

	err = m.Cleanup(receipt)
	if !errors.Is(err, proofFailure) {
		t.Fatalf("public cleanup failure = %v", err)
	}
	owner, ok := WorkspaceCleanupRetryOwner(err)
	if !ok || owner == nil || owner.stage != workspaceCleanupTreeCleared {
		t.Fatalf("public cleanup did not retain post-unlink retry owner: %T %[1]v", err)
	}
	if err := os.Mkdir(receipt.SnapshotPath(), 0700); err != nil {
		t.Fatal(err)
	}
	if err := owner.Retry(); err != nil {
		t.Fatalf("public cleanup retry: %v", err)
	}
	if _, err := os.Stat(receipt.SnapshotPath()); err != nil {
		t.Fatalf("pathname replacement was removed: %v", err)
	}
}
func TestCleanupAcquisitionRootCloseFailureRetainsDescriptor(t *testing.T) {
	m := materializer(t, cleanDetector)
	receipt, err := m.Materialize(context.Background(), snapshotRequest(t, snapshotFile(t, "a.md", "owned")))
	if err != nil {
		t.Fatal(err)
	}
	owner := cleanupOwnerForReceipt(m, receipt)
	closeFailure := errors.New("injected cleanup root close failure")
	closeFD := m.operations.close
	failed := true
	m.operations.close = func(fd int) error {
		if failed {
			failed = false
			return closeFailure
		}
		return closeFD(fd)
	}

	if err := owner.Retry(); !errors.Is(err, closeFailure) {
		t.Fatalf("cleanup root close failure = %v", err)
	}
	if owner.stage != workspaceCleanupQuarantinedRootClosePending || owner.rootFD < 0 {
		t.Fatalf("cleanup root close did not retain quarantine stage: %d", owner.stage)
	}
	if err := owner.Retry(); err != nil {
		t.Fatalf("cleanup retry after root close failure: %v", err)
	}
}

func TestCleanupUnlinkRootCloseFailureRetainsDescriptor(t *testing.T) {
	m := materializer(t, cleanDetector)
	receipt, err := m.Materialize(context.Background(), snapshotRequest(t, snapshotFile(t, "a.md", "owned")))
	if err != nil {
		t.Fatal(err)
	}
	owner := cleanupOwnerForReceipt(m, receipt)
	closeFailure := errors.New("injected unlink root close failure")
	closeFD := m.operations.close
	rootCloses := 0
	m.operations.close = func(fd int) error {
		if fd != owner.fd {
			rootCloses++
			if rootCloses == 2 {
				return closeFailure
			}
		}
		return closeFD(fd)
	}

	if err := owner.Retry(); !errors.Is(err, closeFailure) {
		t.Fatalf("unlink root close failure = %v", err)
	}
	if owner.stage != workspaceCleanupUnlinkCommittedRootClosePending || owner.rootFD < 0 {
		t.Fatalf("unlink root close lost authority: stage=%d rootFD=%d", owner.stage, owner.rootFD)
	}
	if err := owner.Retry(); err != nil {
		t.Fatalf("unlink root close retry: %v", err)
	}
	if owner.stage != workspaceCleanupOwnerReleased {
		t.Fatalf("unlink root close retry stage = %d", owner.stage)
	}
}
func TestCleanupSourceVerificationCloseAndRootCloseFailuresRetainDescriptors(t *testing.T) {
	m := materializer(t, cleanDetector)
	receipt, err := m.Materialize(context.Background(), snapshotRequest(t, snapshotFile(t, "a.md", "owned")))
	if err != nil {
		t.Fatal(err)
	}
	owner := cleanupOwnerForReceipt(m, receipt)
	snapshot := receipt.SnapshotPath()
	displaced := snapshot + "-owned"
	t.Cleanup(func() {
		makeWorkspaceWritable(t, displaced)
		makeWorkspaceWritable(t, snapshot)
	})
	displacedOnce := false
	m.operations.beforeQuarantine = func(_ int, _ string) {
		if displacedOnce {
			return
		}
		displacedOnce = true
		if err := os.Rename(snapshot, displaced); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(snapshot, 0700); err != nil {
			t.Fatal(err)
		}
	}
	rootCloseFailure := errors.New("injected root close failure")
	closeFD := m.operations.close
	failRoot := true
	m.operations.close = func(fd int) error {
		if fd != owner.fd && failRoot {
			failRoot = false
			return rootCloseFailure
		}
		return closeFD(fd)
	}
	if err := owner.Retry(); !errors.Is(err, rootCloseFailure) {
		t.Fatalf("quarantine root close failure = %v", err)
	}
	if owner.stage != workspaceCleanupQuarantinedRootClosePending || owner.fd < 0 || owner.rootFD < 0 {
		t.Fatalf("quarantine descriptors were not retained: stage=%d fd=%d rootFD=%d", owner.stage, owner.fd, owner.rootFD)
	}
	if err := owner.Retry(); err != nil {
		t.Fatalf("quarantine retry = %v", err)
	}
	if owner.stage != workspaceCleanupOwnerReleased || owner.fd >= 0 || owner.rootFD >= 0 {
		t.Fatalf("quarantine retry retained stale authority: stage=%d fd=%d rootFD=%d", owner.stage, owner.fd, owner.rootFD)
	}
	if _, err := os.Stat(snapshot); err != nil {
		t.Fatalf("replacement pathname was removed: %v", err)
	}
	if _, err := os.Stat(displaced); !os.IsNotExist(err) {
		t.Fatalf("owned pathname remained: %v", err)
	}
}

func TestCleanupRenameCloseFailureRetainsSourceDescriptor(t *testing.T) {
	m := materializer(t, cleanDetector)
	receipt, err := m.Materialize(context.Background(), snapshotRequest(t, snapshotFile(t, "a.md", "owned")))
	if err != nil {
		t.Fatal(err)
	}
	owner := cleanupOwnerForReceipt(m, receipt)
	renameFailure := errors.New("injected rename failure")
	rename := m.operations.renameatxNp
	failRename := true
	m.operations.renameatxNp = func(oldDirFD int, oldName string, newDirFD int, newName string, flags uint32) error {
		if failRename {
			failRename = false
			return renameFailure
		}
		return rename(oldDirFD, oldName, newDirFD, newName, flags)
	}
	closeFailure := errors.New("injected source close failure")
	closeFD := m.operations.close
	failClose := true
	m.operations.close = func(fd int) error {
		if fd == owner.fd && failClose {
			failClose = false
			return closeFailure
		}
		return closeFD(fd)
	}

	if err := owner.Retry(); !errors.Is(err, renameFailure) {
		t.Fatalf("rename failure = %v", err)
	}
	if owner.stage != workspaceCleanupAcquired || owner.fd < 0 {
		t.Fatalf("rename failure lost source descriptor: stage=%d fd=%d", owner.stage, owner.fd)
	}
	if err := owner.Retry(); !errors.Is(err, closeFailure) {
		t.Fatalf("rename retry close failure: %v", err)
	}
	if owner.stage != workspaceCleanupDetachmentVerified || owner.fd < 0 {
		t.Fatalf("rename retry lost descriptor: stage=%d fd=%d", owner.stage, owner.fd)
	}
	if err := owner.Retry(); err != nil {
		t.Fatalf("rename close retry: %v", err)
	}
	if owner.stage != workspaceCleanupOwnerReleased {
		t.Fatalf("rename close retry stage = %d", owner.stage)
	}
}

func TestCleanupRollbackCloseFailureRetainsCurrentPathAuthority(t *testing.T) {
	m := materializer(t, cleanDetector)
	receipt, err := m.Materialize(context.Background(), snapshotRequest(t, snapshotFile(t, "a.md", "owned")))
	if err != nil {
		t.Fatal(err)
	}
	owner := cleanupOwnerForReceipt(m, receipt)
	snapshot := receipt.SnapshotPath()
	displaced := snapshot + "-owned"
	t.Cleanup(func() {
		makeWorkspaceWritable(t, displaced)
		makeWorkspaceWritable(t, snapshot)
	})
	replacement := ""
	m.operations.afterQuarantineVerification = func(_ int, tomb string) {
		tombPath := filepath.Join(m.root.String(), tomb)
		replacement = tombPath
		if err := os.Rename(tombPath, displaced); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(tombPath, 0700); err != nil {
			t.Fatal(err)
		}
	}
	closeFailure := errors.New("injected rollback close failure")
	closeFD := m.operations.close
	failed := true
	m.operations.close = func(fd int) error {
		if fd == owner.fd && failed {
			failed = false
			return closeFailure
		}
		return closeFD(fd)
	}
	if err := owner.Retry(); !errors.Is(err, closeFailure) {
		t.Fatalf("cleanup close failure = %v", err)
	}
	if owner.stage != workspaceCleanupDetachmentVerified || owner.fd < 0 {
		t.Fatalf("cleanup close lost descriptor authority: stage=%d fd=%d", owner.stage, owner.fd)
	}
	if err := owner.Retry(); err != nil {
		t.Fatalf("cleanup close retry: %v", err)
	}
	if owner.stage != workspaceCleanupOwnerReleased || owner.fd >= 0 {
		t.Fatalf("cleanup close retry stage = %d", owner.stage)
	}
	if _, err := os.Stat(replacement); err != nil {
		t.Fatalf("replacement pathname was removed: %v", err)
	}
	if _, err := os.Stat(displaced); !os.IsNotExist(err) {
		t.Fatalf("owned pathname remained: %v", err)
	}
}
func TestWorkspaceDescriptorCloseRetryOwnerRetainsExactDescriptor(t *testing.T) {
	closeFailure := errors.New("injected descriptor close failure")
	primary := errors.New("primary validation failure")
	calls := 0
	err := closeDescriptor(primary, func(fd int) error {
		calls++
		if calls == 1 {
			return closeFailure
		}
		return nil
	}, 91)
	if !errors.Is(err, primary) || !errors.Is(err, closeFailure) {
		t.Fatalf("joined close error = %v", err)
	}
	owner, ok := WorkspaceDescriptorCloseRetryOwner(err)
	if !ok || owner == nil {
		t.Fatal("close failure did not retain retry owner")
	}
	if err := owner.Retry(); err != nil {
		t.Fatalf("retry close = %v", err)
	}
	if calls != 2 {
		t.Fatalf("close calls = %d, want 2", calls)
	}
}

func TestRevalidateCloseFailureRetainsRetryOwner(t *testing.T) {
	m := materializer(t, cleanDetector)
	receipt, err := m.Materialize(context.Background(), snapshotRequest(t, snapshotFile(t, "a.md", "owned")))
	if err != nil {
		t.Fatal(err)
	}
	closeFailure := errors.New("injected revalidation close failure")
	closeFD := m.operations.close
	failed := true
	m.operations.close = func(fd int) error {
		if failed {
			failed = false
			return closeFailure
		}
		return closeFD(fd)
	}
	err = m.Revalidate(receipt)
	if !errors.Is(err, closeFailure) {
		t.Fatalf("revalidate close error = %v", err)
	}
	owner, ok := WorkspaceDescriptorCloseRetryOwner(err)
	if !ok || owner == nil {
		t.Fatal("revalidate close failure did not retain retry owner")
	}
	if err := owner.Retry(); err != nil {
		t.Fatalf("revalidate descriptor close retry = %v", err)
	}
	m.operations.close = closeFD
	if err := m.Cleanup(receipt); err != nil {
		t.Fatalf("cleanup = %v", err)
	}
}
