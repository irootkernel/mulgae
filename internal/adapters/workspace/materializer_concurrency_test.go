//go:build darwin && arm64

package workspace

import (
	"context"
	"path/filepath"
	"sync"
	"testing"

	"github.com/irootkernel/mulgae/internal/ports"
)

// concurrencyMaterializer anchors this test's own root resolved once with
// EvalSymlinks, because the default macOS TMPDIR crosses /var through a
// symlink. The shared materializer helper stays unchanged.
func concurrencyMaterializer(t *testing.T) *Materializer {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	anchored, err := ports.NewAnchoredRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	result, err := NewMaterializer(anchored, detectorFunc(cleanDetector))
	if err != nil {
		t.Fatal(err)
	}
	return result
}

// TestMaterializerConcurrentQualificationLeases overlaps two qualification
// lease materializations on one real materializer and proves each lease is a
// distinct snapshot that drains cleanly.
func TestMaterializerConcurrentQualificationLeases(t *testing.T) {
	m := concurrencyMaterializer(t)
	first := snapshotRequest(t, snapshotFile(t, "first.md", "first"))
	second := snapshotRequest(t, snapshotFile(t, "second.md", "second"))

	start := make(chan struct{})
	leases := make(chan ports.QualificationWorkspaceLease, 2)
	failures := make(chan error, 2)
	var wait sync.WaitGroup
	for _, request := range []ports.WorkspaceSnapshotRequest{first, second} {
		wait.Add(1)
		go func(request ports.WorkspaceSnapshotRequest) {
			defer wait.Done()
			<-start
			lease, err := m.MaterializeQualificationLease(context.Background(), request)
			if err != nil {
				failures <- err
				return
			}
			leases <- lease
		}(request)
	}
	close(start)
	wait.Wait()
	close(leases)
	close(failures)
	for err := range failures {
		t.Fatal(err)
	}
	snapshots := make(map[string]struct{}, 2)
	for lease := range leases {
		identity := lease.WorkspaceSnapshotIdentity()
		if !identity.Valid() {
			t.Fatalf("concurrently materialized identity invalid: %#v", identity)
		}
		snapshots[identity.SnapshotPath()] = struct{}{}
		if _, err := lease.DrainTerminal(context.Background()); err != nil {
			t.Fatalf("concurrently materialized lease drain: %v", err)
		}
	}
	if len(snapshots) != 2 {
		t.Fatalf("snapshot paths = %v, want two distinct snapshots", snapshots)
	}
}
