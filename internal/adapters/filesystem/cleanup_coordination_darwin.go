//go:build darwin && arm64

package filesystem

import (
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/irootkernel/mulgae/internal/artifactwire"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
	"golang.org/x/sys/unix"
)

type cleanupCoordinationProof struct {
	material  string
	protected bool
}

func coordinationIntentIdentity(stat unix.Stat_t) string {
	return fmt.Sprintf("%d:%d:%d:%d:%d:%d:%d:%v:%v", stat.Dev, stat.Ino, stat.Mode, stat.Uid, stat.Gid, stat.Nlink, stat.Size, stat.Mtim, stat.Ctim)
}

// The same proof is used for epoch admission and immediately before deletion.
// Native terminal state never supplies local termination proof.
func cleanupCoordinationProofAt(fd int, session domain.SessionID, run domain.RunID) (cleanupCoordinationProof, error) {
	var directory, before, after unix.Stat_t
	if err := unix.Fstat(fd, &directory); err != nil {
		return cleanupCoordinationProof{protected: true}, err
	}
	prefix := fmt.Sprintf("%d:%d/", directory.Dev, directory.Ino)
	err := unix.Fstatat(fd, artifactwire.HaepariLockIntentFilename, &before, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return cleanupCoordinationProof{material: prefix + "absent"}, nil
	}
	if err != nil {
		return cleanupCoordinationProof{material: prefix + "unsafe", protected: true}, err
	}
	proof := cleanupCoordinationProof{material: prefix + coordinationIntentIdentity(before), protected: true}
	data, err := readPrivateCoordinationIntentFile(fd, artifactwire.HaepariLockIntentFilename, ports.RuntimeDiagnosticStatusMaxBytes)
	if err != nil {
		return proof, err
	}
	digest := sha256.Sum256(data)
	proof.material += fmt.Sprintf("/%x", digest)
	if err := unix.Fstatat(fd, artifactwire.HaepariLockIntentFilename, &after, unix.AT_SYMLINK_NOFOLLOW); err != nil || coordinationIntentIdentity(before) != coordinationIntentIdentity(after) {
		return proof, errors.New("cleanup store: coordination intent changed during read")
	}
	record, err := decodeCoordinationIntentWire(data, session, run)
	if err != nil {
		return proof, err
	}
	switch record.SchemaVersion {
	case artifactwire.HaepariLockIntentSchemaV2:
		proof.protected = record.ObservedRequest == nil || !record.ObservedRequest.State.IsTerminal() || record.LocalDrainState != ports.ReviewLocalDrainNotStarted && record.LocalDrainState != ports.ReviewLocalDrainVerified
	case artifactwire.HaepariLockIntentSchemaV3:
		proof.protected = record.LocalDrainState != ports.ReviewLocalDrainNotStarted && record.LocalDrainState != ports.ReviewLocalDrainVerified
	default:
		proof.protected = true
	}
	return proof, nil
}

func (store *CleanupStore) readCoordinationProof(session domain.SessionID, run domain.RunID) (cleanupCoordinationProof, bool, error) {
	fd, err := unix.Open(store.root.String(), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return cleanupCoordinationProof{protected: true}, false, err
	}
	for _, name := range []string{"diagnostics", session.String(), run.String()} {
		next, openErr := unix.Openat(fd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		closeFD(fd)
		if errors.Is(openErr, unix.ENOENT) {
			return cleanupCoordinationProof{}, false, nil
		}
		if openErr != nil {
			return cleanupCoordinationProof{protected: true}, false, openErr
		}
		fd = next
	}
	defer closeFD(fd)
	proof, err := cleanupCoordinationProofAt(fd, session, run)
	return proof, true, err
}

func (store *CleanupStore) admitCoordinationDeletion(session domain.SessionID, run domain.RunID, proof cleanupCoordinationProof) error {
	if proof.protected {
		return errors.New("cleanup store: coordination intent retains local protection")
	}
	if store.coordinationProofs != nil {
		expected, found := store.coordinationProofs[session.String()+"/"+run.String()]
		if !found || expected != proof {
			return errors.New("cleanup store: coordination intent changed after snapshot")
		}
	}
	return nil
}
