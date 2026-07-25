//go:build darwin && arm64

package config

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"

	"github.com/irootkernel/kkachi-agent-review/internal/ports"
)

// FilesystemLocalityAttestor admits private local configuration for a project
// that has no Git administrative entry. It binds the root/config inode proof
// and revalidates both before every provider spawn.
type FilesystemLocalityAttestor struct{}

func NewFilesystemLocalityAttestor() *FilesystemLocalityAttestor {
	return &FilesystemLocalityAttestor{}
}

func (attestor *FilesystemLocalityAttestor) Attest(_ context.Context, request ports.ConfigLocalityRequest) (ports.ConfigLocalityContext, error) {
	if attestor == nil || !request.Root().Valid() {
		return ports.ConfigLocalityContext{}, fmt.Errorf("filesystem config locality: invalid request")
	}
	if _, err := os.Lstat(filepath.Join(request.Root().String(), ".git")); err == nil || !os.IsNotExist(err) {
		return ports.ConfigLocalityContext{}, fmt.Errorf("filesystem config locality: Git administrative entry is present")
	}
	source, err := NewLocalConfigSource(request.Root(), true)
	if err != nil {
		return ports.ConfigLocalityContext{}, err
	}
	proof, err := source.Observation().Proof()
	if err != nil || !proof.Equal(request.Config()) {
		return ports.ConfigLocalityContext{}, fmt.Errorf("filesystem config locality: config proof drifted")
	}
	digest := sha256.Sum256(request.TargetBytes())
	return ports.NewFilesystemConfigLocalityContext(proof, ports.ParsedTargetProof{
		SHA256: fmt.Sprintf("sha256:%x", digest), Parsed: false, PrivatePathFree: true,
	})
}

func (attestor *FilesystemLocalityAttestor) Revalidate(ctx context.Context, request ports.ConfigLocalityRequest, expected ports.ConfigLocalityContext) error {
	actual, err := attestor.Attest(ctx, request)
	if err != nil {
		return err
	}
	if !actual.Equal(expected) {
		return fmt.Errorf("filesystem config locality: drifted")
	}
	return nil
}
