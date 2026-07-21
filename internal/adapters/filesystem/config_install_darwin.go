//go:build darwin && arm64

package filesystem

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"

	"github.com/irootkernel/kkachi-agent-review/internal/ports"
	"golang.org/x/sys/unix"
)

var _ ports.ConfigInstaller = (*SecureWriter)(nil)

func (writer *SecureWriter) PrepareConfigDirectory(ctx context.Context, root ports.AnchoredRoot) (ports.ConfigDirectoryReceipt, error) {
	if ctx == nil || !root.Valid() {
		return ports.ConfigDirectoryReceipt{}, ports.NewConfigInstallError(ports.ConfigInstallStagePreinstall, ports.ConfigDestinationNotObserved, fmt.Errorf("invalid request"))
	}
	if err := ctx.Err(); err != nil {
		return ports.ConfigDirectoryReceipt{}, err
	}
	operations := writer.operationSet()
	rootFD, err := openAnchoredRoot(root)
	if err != nil {
		return ports.ConfigDirectoryReceipt{}, ports.NewConfigInstallError(ports.ConfigInstallStagePreinstall, ports.ConfigDestinationNotObserved, err)
	}
	defer closeFD(rootFD)
	rootIdentity, err := privateDirectoryIdentityForFD(rootFD)
	if err != nil {
		return ports.ConfigDirectoryReceipt{}, ports.NewConfigInstallError(ports.ConfigInstallStagePreinstall, ports.ConfigDestinationNotObserved, err)
	}
	created := false
	karFD, openErr := unix.Openat(rootFD, ".kar", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(openErr, unix.ENOENT) {
		if err := unix.Mkdirat(rootFD, ".kar", privateDirectoryMode); err != nil {
			stage := ports.ConfigInstallStagePreinstall
			if errors.Is(err, unix.EEXIST) {
				stage = ports.ConfigInstallStagePrivateDirRace
			}
			return ports.ConfigDirectoryReceipt{}, ports.NewConfigInstallError(stage, ports.ConfigDestinationNotObserved, err)
		}
		created = true
		karFD, openErr = unix.Openat(rootFD, ".kar", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	}
	if openErr != nil {
		return ports.ConfigDirectoryReceipt{}, ports.NewConfigInstallError(ports.ConfigInstallStagePreinstall, ports.ConfigDestinationNotObserved, openErr)
	}
	defer closeFD(karFD)
	if err := verifyPrivateDirectory(karFD); err != nil {
		return ports.ConfigDirectoryReceipt{}, ports.NewConfigInstallError(ports.ConfigInstallStagePreinstall, observeConfig(karFD), err)
	}
	karIdentity, err := privateDirectoryIdentityForFD(karFD)
	if err != nil {
		return ports.ConfigDirectoryReceipt{}, ports.NewConfigInstallError(ports.ConfigInstallStagePreinstall, observeConfig(karFD), err)
	}
	proof, err := configDirectoryIdentity(rootIdentity, karIdentity)
	if err != nil {
		return ports.ConfigDirectoryReceipt{}, ports.NewConfigInstallError(ports.ConfigInstallStagePreinstall, observeConfig(karFD), err)
	}
	receipt, err := ports.NewVerifiedConfigDirectoryReceipt(created, proof)
	if err != nil {
		return ports.ConfigDirectoryReceipt{}, ports.NewConfigInstallError(ports.ConfigInstallStagePreinstall, observeConfig(karFD), err)
	}
	if err := operations.fsync(rootFD); err != nil {
		return receipt, ports.NewConfigInstallError(ports.ConfigInstallStageRootSync, observeConfig(karFD), err)
	}
	if err := revalidateRootAndPrivate(root, rootIdentity, karIdentity); err != nil {
		return receipt, ports.NewConfigInstallError(ports.ConfigInstallStageRootReattestation, observeConfigAtRoot(root), err)
	}
	return receipt, nil
}

func (writer *SecureWriter) InstallConfig(ctx context.Context, root ports.AnchoredRoot, prepared ports.ConfigDirectoryReceipt, data []byte) (ports.ConfigInstallReceipt, error) {
	if ctx == nil || !root.Valid() || len(data) < 1 {
		return ports.ConfigInstallReceipt{}, ports.NewConfigInstallError(ports.ConfigInstallStagePreinstall, ports.ConfigDestinationNotObserved, fmt.Errorf("invalid request"))
	}
	expectedProof, ok := prepared.Identity()
	if !ok {
		return ports.ConfigInstallReceipt{}, ports.NewConfigInstallError(ports.ConfigInstallStagePreinstall, ports.ConfigDestinationNotObserved, fmt.Errorf("missing prepared directory identity"))
	}
	operations := writer.operationSet()
	rootFD, err := openAnchoredRoot(root)
	if err != nil {
		return ports.ConfigInstallReceipt{}, ports.NewConfigInstallError(ports.ConfigInstallStagePreinstall, ports.ConfigDestinationNotObserved, err)
	}
	defer closeFD(rootFD)
	rootIdentity, err := privateDirectoryIdentityForFD(rootFD)
	if err != nil {
		return ports.ConfigInstallReceipt{}, ports.NewConfigInstallError(ports.ConfigInstallStagePreinstall, ports.ConfigDestinationNotObserved, err)
	}
	directoryFD, err := unix.Openat(rootFD, ".kar", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return ports.ConfigInstallReceipt{}, ports.NewConfigInstallError(ports.ConfigInstallStagePreinstall, ports.ConfigDestinationNotObserved, err)
	}
	defer closeFD(directoryFD)
	if err := verifyPrivateDirectory(directoryFD); err != nil {
		return ports.ConfigInstallReceipt{}, ports.NewConfigInstallError(ports.ConfigInstallStagePreinstall, observeConfig(directoryFD), err)
	}
	directoryIdentity, err := privateDirectoryIdentityForFD(directoryFD)
	if err != nil {
		return ports.ConfigInstallReceipt{}, ports.NewConfigInstallError(ports.ConfigInstallStagePreinstall, ports.ConfigDestinationNotObserved, err)
	}
	actualProof, err := configDirectoryIdentity(rootIdentity, directoryIdentity)
	if err != nil || !actualProof.Equal(expectedProof) {
		return ports.ConfigInstallReceipt{}, ports.NewConfigInstallError(ports.ConfigInstallStagePreparedIdentity, observeConfig(directoryFD), errors.Join(err, fmt.Errorf("prepared directory identity changed")))
	}
	if state := observeConfig(directoryFD); state == ports.ConfigDestinationPresent {
		return ports.ConfigInstallReceipt{}, ports.NewConfigInstallError(ports.ConfigInstallStageCollision, state, unix.EEXIST)
	}
	temporaryFD, temporaryName, err := createPrivateTempFile(operations, directoryFD)
	if err != nil {
		return ports.ConfigInstallReceipt{}, ports.NewConfigInstallError(ports.ConfigInstallStagePreinstall, ports.ConfigDestinationAbsent, err)
	}
	cleanup := func(cause error) error {
		return errors.Join(cause, purgeTemporaryFile(operations, directoryFD, &temporaryFD, &temporaryName))
	}
	if err := writeAllWith(temporaryFD, data, operations.write); err != nil {
		return ports.ConfigInstallReceipt{}, ports.NewConfigInstallError(ports.ConfigInstallStagePreinstall, ports.ConfigDestinationAbsent, cleanup(err))
	}
	if err := operations.fsync(temporaryFD); err != nil {
		return ports.ConfigInstallReceipt{}, ports.NewConfigInstallError(ports.ConfigInstallStagePreinstall, ports.ConfigDestinationAbsent, cleanup(err))
	}
	sum := sha256.Sum256(data)
	identity, err := secureFileIdentityForFD(temporaryFD)
	if err != nil {
		return ports.ConfigInstallReceipt{}, ports.NewConfigInstallError(ports.ConfigInstallStagePreinstall, ports.ConfigDestinationAbsent, cleanup(err))
	}
	if err := revalidateRootAndPrivate(root, rootIdentity, directoryIdentity); err != nil {
		return ports.ConfigInstallReceipt{}, ports.NewConfigInstallError(ports.ConfigInstallStagePreparedIdentity, observeConfigAtRoot(root), cleanup(err))
	}
	if err := ctx.Err(); err != nil {
		cleanupErr := cleanup(err)
		state := observeConfig(directoryFD)
		stage := ports.ConfigInstallStagePreinstall
		if state == ports.ConfigDestinationPresent {
			stage = ports.ConfigInstallStageCollision
		}
		return ports.ConfigInstallReceipt{}, ports.NewConfigInstallError(stage, state, cleanupErr)
	}
	if operations.beforeInstall != nil {
		operations.beforeInstall(directoryFD, temporaryName)
	}
	// Re-read the fsynced pathname immediately before the no-replace install.
	// Equality with data carries the already-completed canonical YAML and
	// semantic admission across the filesystem transaction boundary.
	if err := verifyInstalledFileAt(directoryFD, temporaryName, identity, sum[:], int64(len(data))); err != nil {
		return ports.ConfigInstallReceipt{}, ports.NewConfigInstallError(ports.ConfigInstallStagePreinstall, ports.ConfigDestinationAbsent, cleanup(err))
	}
	if err := operations.renameatxNp(directoryFD, temporaryName, directoryFD, "config.yaml", unix.RENAME_EXCL); err != nil {
		state := ports.ConfigDestinationAbsent
		stage := ports.ConfigInstallStagePreinstall
		if errors.Is(err, unix.EEXIST) {
			state = ports.ConfigDestinationPresent
			stage = ports.ConfigInstallStageCollision
		}
		return ports.ConfigInstallReceipt{}, ports.NewConfigInstallError(stage, state, cleanup(err))
	}
	temporaryName = ""
	configProof, proofErr := ports.NewConfigFileIdentity(identity.device, identity.inode, uint32(os.Geteuid()), 0o600, 1, int64(len(data)), fmt.Sprintf("sha256:%x", sum))
	if proofErr != nil {
		return ports.ConfigInstallReceipt{}, ports.NewConfigInstallError(ports.ConfigInstallStageFinalReattestation, ports.ConfigDestinationPresent, proofErr)
	}
	receipt, receiptErr := ports.NewVerifiedConfigInstallReceipt(actualProof, configProof)
	if receiptErr != nil {
		return ports.ConfigInstallReceipt{}, ports.NewConfigInstallError(ports.ConfigInstallStageFinalReattestation, ports.ConfigDestinationPresent, receiptErr)
	}
	if err := operations.close(temporaryFD); err != nil {
		return receipt, ports.NewConfigInstallError(ports.ConfigInstallStageFinalReattestation, ports.ConfigDestinationPresent, err)
	}
	temporaryFD = -1
	if err := verifyConfigAt(directoryFD, "config.yaml", identity, sum[:], int64(len(data))); err != nil {
		return receipt, ports.NewConfigInstallError(ports.ConfigInstallStageFinalReattestation, observeConfig(directoryFD), err)
	}
	if err := operations.fsync(directoryFD); err != nil {
		return receipt, ports.NewConfigInstallError(ports.ConfigInstallStageDirectorySync, ports.ConfigDestinationPresent, err)
	}
	if err := revalidateRootAndPrivate(root, rootIdentity, directoryIdentity); err != nil {
		return receipt, ports.NewConfigInstallError(ports.ConfigInstallStageFinalReattestation, observeInstalledConfigAtRoot(root), err)
	}
	if err := verifyConfigAt(directoryFD, "config.yaml", identity, sum[:], int64(len(data))); err != nil {
		return receipt, ports.NewConfigInstallError(ports.ConfigInstallStageFinalReattestation, observeInstalledConfigAtRoot(root), err)
	}
	return receipt, nil
}

func configDirectoryIdentity(root, private privateDirectoryIdentity) (ports.ConfigDirectoryIdentity, error) {
	return ports.NewConfigDirectoryIdentity(root.device, root.inode, root.uid, root.mode, private.device, private.inode, private.uid, private.mode)
}

func observeConfig(directoryFD int) ports.ConfigDestinationState {
	var stat unix.Stat_t
	err := unix.Fstatat(directoryFD, "config.yaml", &stat, unix.AT_SYMLINK_NOFOLLOW)
	if err == nil {
		return ports.ConfigDestinationPresent
	}
	if errors.Is(err, unix.ENOENT) {
		return ports.ConfigDestinationAbsent
	}
	return ports.ConfigDestinationNotObserved
}

func observeConfigAtRoot(root ports.AnchoredRoot) ports.ConfigDestinationState {
	rootFD, err := openAnchoredRoot(root)
	if err != nil {
		return ports.ConfigDestinationNotObserved
	}
	defer closeFD(rootFD)
	directoryFD, err := unix.Openat(rootFD, ".kar", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return ports.ConfigDestinationAbsent
	}
	if err != nil {
		return ports.ConfigDestinationNotObserved
	}
	defer closeFD(directoryFD)
	if err := verifyPrivateDirectory(directoryFD); err != nil {
		return ports.ConfigDestinationNotObserved
	}
	return observeConfig(directoryFD)
}

func observeInstalledConfigAtRoot(root ports.AnchoredRoot) ports.ConfigDestinationState {
	if observeConfigAtRoot(root) == ports.ConfigDestinationPresent {
		return ports.ConfigDestinationPresent
	}
	return ports.ConfigDestinationNotObserved
}
func revalidateRootAndPrivate(root ports.AnchoredRoot, rootIdentity, karIdentity privateDirectoryIdentity) error {
	rootFD, err := openAnchoredRoot(root)
	if err != nil {
		return err
	}
	defer closeFD(rootFD)
	actual, err := privateDirectoryIdentityForFD(rootFD)
	if err != nil || actual != rootIdentity {
		return fmt.Errorf("root identity changed")
	}
	karFD, err := unix.Openat(rootFD, ".kar", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer closeFD(karFD)
	if err := verifyPrivateDirectory(karFD); err != nil {
		return err
	}
	actualKar, err := privateDirectoryIdentityForFD(karFD)
	if err != nil || actualKar != karIdentity {
		return fmt.Errorf("private directory identity changed")
	}
	return nil
}
func verifyConfigAt(directoryFD int, name string, identity secureFileIdentity, sum []byte, size int64) error {
	var stat unix.Stat_t
	if err := unix.Fstatat(directoryFD, name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if stat.Nlink != 1 {
		return fmt.Errorf("config link count changed")
	}
	return verifyInstalledFileAt(directoryFD, name, identity, sum, size)
}
