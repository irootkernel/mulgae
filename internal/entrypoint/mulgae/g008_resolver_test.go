package mulgae

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/irootkernel/mulgae/internal/adapters/filesystem"
	"github.com/irootkernel/mulgae/internal/ports"
)

func TestG008RequestResolverMissingProjectArtifactsDoesNotCreateWorkspace(t *testing.T) {
	fixture := newG008RealE2EFixture(t)
	projectRoot := t.TempDir()
	artifactPath := filepath.Join(projectRoot, ".mulgae")
	artifactRoot, err := ports.NewAnchoredRoot(artifactPath)
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := NewG008RequestResolver(artifactRoot, fixture.queries, filesystem.NewRunSelector(artifactRoot))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.ResolveRun(context.Background(), "latest"); !errors.Is(err, ErrProjectRootMismatch) {
		t.Fatalf("ResolveRun error = %v, want project root mismatch", err)
	}
	if _, err := resolver.ResolveRun(context.Background(), testRunID); !errors.Is(err, ErrProjectRootMismatch) {
		t.Fatalf("ResolveRun explicit error = %v, want project root mismatch", err)
	}

	if _, err := os.Lstat(artifactPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing artifact root stat = %v, want not exist", err)
	}
	if err := os.Mkdir(artifactPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.ResolveRun(context.Background(), testRunID); err == nil || errors.Is(err, ErrProjectRootMismatch) {
		t.Fatalf("missing explicit run error = %v, want non-root artifact failure", err)
	}
}

func TestCommittedCreatedAtRejectsNoncanonicalManifestTimestamp(t *testing.T) {
	for _, timestamp := range []string{
		"2026-07-14T12:00:00+00:00",
		"2026-07-14T12:00:00.1000Z",
		"2026-07-14T12:00:00Z ",
		"not-a-timestamp",
	} {
		if _, err := committedCreatedAt([]byte(`{"created_at":"` + timestamp + `"}`)); err == nil {
			t.Fatalf("committedCreatedAt(%q) succeeded", timestamp)
		}
	}
	if _, err := committedCreatedAt([]byte(`{"created_at":"2026-07-14T12:00:00.1Z"}`)); err != nil {
		t.Fatalf("canonical manifest timestamp rejected: %v", err)
	}
}
