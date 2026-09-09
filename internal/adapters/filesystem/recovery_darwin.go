//go:build darwin && arm64

package filesystem

import (
	"context"
	"errors"
	"io/fs"

	"github.com/irootkernel/mulgae/internal/ports"
)

// lockedRecoveryReader reuses confined reads without acquiring the store lock.
// Publication operations hold that lock; cleanup also uses it for verified
// read-only metadata inspection with unchanged-manifest confirmation.
type lockedRecoveryReader struct{}

func (lockedRecoveryReader) PersistAuxiliaryArtifact(context.Context, ports.PersistAuxiliaryArtifactRequest) (ports.PersistAuxiliaryArtifactResult, error) {
	return ports.PersistAuxiliaryArtifactResult{}, errors.New("recovery observation is read-only")
}
func (lockedRecoveryReader) ReadAuxiliaryArtifact(ctx context.Context, request ports.ReadAuxiliaryArtifactRequest) (ports.ImmutablePublicationArtifact, error) {
	if err := ctx.Err(); err != nil {
		return ports.ImmutablePublicationArtifact{}, err
	}
	file, err := readPublicationFile(request.Run().Root(), request.Path(), request.MaxReadBytes())
	if errors.Is(err, errPublicationAbsent) {
		return ports.ImmutablePublicationArtifact{}, fs.ErrNotExist
	}
	if err != nil {
		return ports.ImmutablePublicationArtifact{}, err
	}
	if hash, ok := request.ExpectedSHA256(); ok && hash != file.sha256 {
		return ports.ImmutablePublicationArtifact{}, errors.New("recovery artifact hash mismatch")
	}
	return ports.NewImmutablePublicationArtifact(request.Path(), file.sha256, file.bytes)
}
