//go:build darwin && arm64

package filesystem

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"

	"github.com/irootkernel/mulgae/internal/ports"
	"golang.org/x/sys/unix"
)

var _ ports.ConfigInstaller = (*SecureWriter)(nil)
var _ ports.SplitConfigInstaller = (*SecureWriter)(nil)

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
	mulgaeFD, openErr := unix.Openat(rootFD, ".mulgae", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(openErr, unix.ENOENT) {
		if err := unix.Mkdirat(rootFD, ".mulgae", privateDirectoryMode); err != nil {
			stage := ports.ConfigInstallStagePreinstall
			if errors.Is(err, unix.EEXIST) {
				stage = ports.ConfigInstallStagePrivateDirRace
			}
			return ports.ConfigDirectoryReceipt{}, ports.NewConfigInstallError(stage, ports.ConfigDestinationNotObserved, err)
		}
		created = true
		mulgaeFD, openErr = unix.Openat(rootFD, ".mulgae", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	}
	if openErr != nil {
		return ports.ConfigDirectoryReceipt{}, ports.NewConfigInstallError(ports.ConfigInstallStagePreinstall, ports.ConfigDestinationNotObserved, openErr)
	}
	defer closeFD(mulgaeFD)
	var mulgaeStat unix.Stat_t
	if err := unix.Fstat(mulgaeFD, &mulgaeStat); err == nil && mulgaeStat.Uid == uint32(os.Geteuid()) && mulgaeStat.Mode&unix.S_IFMT == unix.S_IFDIR && mulgaeStat.Mode&0o7777 == 0o755 {
		if err := unix.Fchmod(mulgaeFD, privateDirectoryMode); err != nil {
			return ports.ConfigDirectoryReceipt{}, ports.NewConfigInstallError(ports.ConfigInstallStagePreinstall, observeConfig(mulgaeFD), err)
		}
	}
	if err := verifyPrivateDirectory(mulgaeFD); err != nil {
		return ports.ConfigDirectoryReceipt{}, ports.NewConfigInstallError(ports.ConfigInstallStagePreinstall, observeConfig(mulgaeFD), err)
	}
	mulgaeIdentity, err := privateDirectoryIdentityForFD(mulgaeFD)
	if err != nil {
		return ports.ConfigDirectoryReceipt{}, ports.NewConfigInstallError(ports.ConfigInstallStagePreinstall, observeConfig(mulgaeFD), err)
	}
	proof, err := configDirectoryIdentity(rootIdentity, mulgaeIdentity)
	if err != nil {
		return ports.ConfigDirectoryReceipt{}, ports.NewConfigInstallError(ports.ConfigInstallStagePreinstall, observeConfig(mulgaeFD), err)
	}
	receipt, err := ports.NewVerifiedConfigDirectoryReceipt(created, proof)
	if err != nil {
		return ports.ConfigDirectoryReceipt{}, ports.NewConfigInstallError(ports.ConfigInstallStagePreinstall, observeConfig(mulgaeFD), err)
	}
	if err := operations.fsync(rootFD); err != nil {
		return receipt, ports.NewConfigInstallError(ports.ConfigInstallStageRootSync, observeConfig(mulgaeFD), err)
	}
	if err := revalidateRootAndPrivate(root, rootIdentity, mulgaeIdentity); err != nil {
		return receipt, ports.NewConfigInstallError(ports.ConfigInstallStageRootReattestation, observeConfigAtRoot(root), err)
	}
	return receipt, nil
}

func (writer *SecureWriter) InstallConfig(ctx context.Context, root ports.AnchoredRoot, prepared ports.ConfigDirectoryReceipt, data []byte) (ports.ConfigInstallReceipt, error) {
	return writer.installNamedConfig(ctx, root, prepared, "config.yaml", data)
}

func (writer *SecureWriter) InstallConfigBundle(ctx context.Context, root ports.AnchoredRoot, prepared ports.ConfigDirectoryReceipt, projectData, localData []byte) (ports.ConfigInstallReceipt, error) {
	projectReceipt, err := writer.installNamedConfig(ctx, root, prepared, "config.yaml", projectData)
	if err != nil {
		return projectReceipt, err
	}
	localReceipt, err := writer.installNamedConfig(ctx, root, prepared, "local.yaml", localData)
	if err == nil || localReceipt.Installed() {
		return localReceipt, err
	}
	return projectReceipt, ports.NewConfigInstallError(ports.ConfigInstallStageBundlePartial, ports.ConfigDestinationPresent, err)
}

func (writer *SecureWriter) InstallLocalConfig(ctx context.Context, root ports.AnchoredRoot, prepared ports.ConfigDirectoryReceipt, data []byte) (ports.ConfigInstallReceipt, error) {
	return writer.installNamedConfig(ctx, root, prepared, "local.yaml", data)
}

func (writer *SecureWriter) RefreshLocalConfig(ctx context.Context, root ports.AnchoredRoot, prepared ports.ConfigDirectoryReceipt, data []byte) (ports.ConfigInstallReceipt, error) {
	return writer.replaceNamedConfig(ctx, root, prepared, "local.yaml", data)
}

func (writer *SecureWriter) installNamedConfig(ctx context.Context, root ports.AnchoredRoot, prepared ports.ConfigDirectoryReceipt, name string, data []byte) (ports.ConfigInstallReceipt, error) {
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
	directoryFD, err := unix.Openat(rootFD, ".mulgae", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return ports.ConfigInstallReceipt{}, ports.NewConfigInstallError(ports.ConfigInstallStagePreinstall, ports.ConfigDestinationNotObserved, err)
	}
	defer closeFD(directoryFD)
	if err := verifyPrivateDirectory(directoryFD); err != nil {
		return ports.ConfigInstallReceipt{}, ports.NewConfigInstallError(ports.ConfigInstallStagePreinstall, observeNamedConfig(directoryFD, name), err)
	}
	directoryIdentity, err := privateDirectoryIdentityForFD(directoryFD)
	if err != nil {
		return ports.ConfigInstallReceipt{}, ports.NewConfigInstallError(ports.ConfigInstallStagePreinstall, ports.ConfigDestinationNotObserved, err)
	}
	actualProof, err := configDirectoryIdentity(rootIdentity, directoryIdentity)
	if err != nil || !actualProof.Equal(expectedProof) {
		return ports.ConfigInstallReceipt{}, ports.NewConfigInstallError(ports.ConfigInstallStagePreparedIdentity, observeNamedConfig(directoryFD, name), errors.Join(err, fmt.Errorf("prepared directory identity changed")))
	}
	if state := observeNamedConfig(directoryFD, name); state == ports.ConfigDestinationPresent {
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
		state := observeNamedConfig(directoryFD, name)
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
	if err := operations.renameatxNp(directoryFD, temporaryName, directoryFD, name, unix.RENAME_EXCL); err != nil {
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
	if err := verifyConfigAt(directoryFD, name, identity, sum[:], int64(len(data))); err != nil {
		return receipt, ports.NewConfigInstallError(ports.ConfigInstallStageFinalReattestation, observeNamedConfig(directoryFD, name), err)
	}
	if err := operations.fsync(directoryFD); err != nil {
		return receipt, ports.NewConfigInstallError(ports.ConfigInstallStageDirectorySync, ports.ConfigDestinationPresent, err)
	}
	if err := revalidateRootAndPrivate(root, rootIdentity, directoryIdentity); err != nil {
		return receipt, ports.NewConfigInstallError(ports.ConfigInstallStageFinalReattestation, observeInstalledNamedConfigAtRoot(root, name), err)
	}
	if err := verifyConfigAt(directoryFD, name, identity, sum[:], int64(len(data))); err != nil {
		return receipt, ports.NewConfigInstallError(ports.ConfigInstallStageFinalReattestation, observeInstalledNamedConfigAtRoot(root, name), err)
	}
	return receipt, nil
}

func (writer *SecureWriter) replaceNamedConfig(ctx context.Context, root ports.AnchoredRoot, prepared ports.ConfigDirectoryReceipt, name string, data []byte) (ports.ConfigInstallReceipt, error) {
	if ctx == nil || !root.Valid() || len(data) == 0 {
		return ports.ConfigInstallReceipt{}, ports.NewConfigInstallError(ports.ConfigInstallStagePreinstall, ports.ConfigDestinationNotObserved, fmt.Errorf("invalid request"))
	}
	expected, ok := prepared.Identity()
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
	directoryFD, err := unix.Openat(rootFD, ".mulgae", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return ports.ConfigInstallReceipt{}, ports.NewConfigInstallError(ports.ConfigInstallStagePreinstall, ports.ConfigDestinationNotObserved, err)
	}
	defer closeFD(directoryFD)
	if err := verifyPrivateDirectory(directoryFD); err != nil {
		return ports.ConfigInstallReceipt{}, ports.NewConfigInstallError(ports.ConfigInstallStagePreinstall, ports.ConfigDestinationNotObserved, err)
	}
	directoryIdentity, err := privateDirectoryIdentityForFD(directoryFD)
	actual, proofErr := configDirectoryIdentity(rootIdentity, directoryIdentity)
	if err != nil || proofErr != nil || !actual.Equal(expected) {
		return ports.ConfigInstallReceipt{}, ports.NewConfigInstallError(ports.ConfigInstallStagePreparedIdentity, ports.ConfigDestinationNotObserved, errors.Join(err, proofErr))
	}
	if observeNamedConfig(directoryFD, name) != ports.ConfigDestinationPresent {
		return ports.ConfigInstallReceipt{}, ports.NewConfigInstallError(ports.ConfigInstallStageCollision, ports.ConfigDestinationAbsent, unix.ENOENT)
	}
	if err := verifyExistingPrivateConfig(directoryFD, name); err != nil {
		return ports.ConfigInstallReceipt{}, ports.NewConfigInstallError(ports.ConfigInstallStagePreinstall, ports.ConfigDestinationPresent, err)
	}
	temporaryFD, temporaryName, err := createPrivateTempFile(operations, directoryFD)
	if err != nil {
		return ports.ConfigInstallReceipt{}, ports.NewConfigInstallError(ports.ConfigInstallStagePreinstall, ports.ConfigDestinationPresent, err)
	}
	cleanup := func(cause error) error {
		return errors.Join(cause, purgeTemporaryFile(operations, directoryFD, &temporaryFD, &temporaryName))
	}
	if err := writeAllWith(temporaryFD, data, operations.write); err != nil {
		return ports.ConfigInstallReceipt{}, ports.NewConfigInstallError(ports.ConfigInstallStagePreinstall, ports.ConfigDestinationPresent, cleanup(err))
	}
	if err := operations.fsync(temporaryFD); err != nil {
		return ports.ConfigInstallReceipt{}, ports.NewConfigInstallError(ports.ConfigInstallStagePreinstall, ports.ConfigDestinationPresent, cleanup(err))
	}
	sum := sha256.Sum256(data)
	identity, err := secureFileIdentityForFD(temporaryFD)
	if err != nil {
		return ports.ConfigInstallReceipt{}, ports.NewConfigInstallError(ports.ConfigInstallStagePreinstall, ports.ConfigDestinationPresent, cleanup(err))
	}
	if err := verifyInstalledFileAt(directoryFD, temporaryName, identity, sum[:], int64(len(data))); err != nil {
		return ports.ConfigInstallReceipt{}, ports.NewConfigInstallError(ports.ConfigInstallStagePreinstall, ports.ConfigDestinationPresent, cleanup(err))
	}
	if err := ctx.Err(); err != nil {
		return ports.ConfigInstallReceipt{}, ports.NewConfigInstallError(ports.ConfigInstallStagePreinstall, ports.ConfigDestinationPresent, cleanup(err))
	}
	if operations.beforeInstall != nil {
		operations.beforeInstall(directoryFD, temporaryName)
	}
	if err := verifyInstalledFileAt(directoryFD, temporaryName, identity, sum[:], int64(len(data))); err != nil {
		return ports.ConfigInstallReceipt{}, ports.NewConfigInstallError(ports.ConfigInstallStagePreinstall, ports.ConfigDestinationPresent, cleanup(err))
	}
	if err := verifyExistingPrivateConfig(directoryFD, name); err != nil {
		return ports.ConfigInstallReceipt{}, ports.NewConfigInstallError(ports.ConfigInstallStagePreinstall, observeNamedConfig(directoryFD, name), cleanup(err))
	}
	if err := revalidateRootAndPrivate(root, rootIdentity, directoryIdentity); err != nil {
		return ports.ConfigInstallReceipt{}, ports.NewConfigInstallError(ports.ConfigInstallStagePreparedIdentity, observeInstalledNamedConfigAtRoot(root, name), cleanup(err))
	}
	if err := operations.renameatxNp(directoryFD, temporaryName, directoryFD, name, unix.RENAME_SWAP); err != nil {
		return ports.ConfigInstallReceipt{}, ports.NewConfigInstallError(ports.ConfigInstallStagePreinstall, ports.ConfigDestinationPresent, cleanup(err))
	}
	configProof, err := ports.NewConfigFileIdentity(identity.device, identity.inode, uint32(os.Geteuid()), 0o600, 1, int64(len(data)), fmt.Sprintf("sha256:%x", sum))
	if err != nil {
		return ports.ConfigInstallReceipt{}, ports.NewConfigInstallError(ports.ConfigInstallStageFinalReattestation, ports.ConfigDestinationPresent, err)
	}
	receipt, err := ports.NewVerifiedConfigInstallReceipt(actual, configProof)
	if err != nil {
		return ports.ConfigInstallReceipt{}, ports.NewConfigInstallError(ports.ConfigInstallStageFinalReattestation, ports.ConfigDestinationPresent, err)
	}
	if err := operations.close(temporaryFD); err != nil {
		return receipt, ports.NewConfigInstallError(ports.ConfigInstallStageFinalReattestation, ports.ConfigDestinationPresent, err)
	}
	temporaryFD = -1
	if err := unix.Unlinkat(directoryFD, temporaryName, 0); err != nil {
		return receipt, ports.NewConfigInstallError(ports.ConfigInstallStageFinalReattestation, ports.ConfigDestinationPresent, err)
	}
	temporaryName = ""
	if err := operations.fsync(directoryFD); err != nil {
		return receipt, ports.NewConfigInstallError(ports.ConfigInstallStageDirectorySync, ports.ConfigDestinationPresent, err)
	}
	if err := revalidateRootAndPrivate(root, rootIdentity, directoryIdentity); err != nil {
		return receipt, ports.NewConfigInstallError(ports.ConfigInstallStageFinalReattestation, observeInstalledNamedConfigAtRoot(root, name), err)
	}
	if err := verifyConfigAt(directoryFD, name, identity, sum[:], int64(len(data))); err != nil {
		return receipt, ports.NewConfigInstallError(ports.ConfigInstallStageFinalReattestation, ports.ConfigDestinationPresent, err)
	}
	return receipt, nil
}

func verifyExistingPrivateConfig(directoryFD int, name string) error {
	fd, err := unix.Openat(directoryFD, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer closeFD(fd)
	if err := verifyPrivateRegularFile(fd); err != nil {
		return err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return err
	}
	if stat.Nlink != 1 {
		return fmt.Errorf("config link count is not one")
	}
	return nil
}

func configDirectoryIdentity(root, private privateDirectoryIdentity) (ports.ConfigDirectoryIdentity, error) {
	return ports.NewConfigDirectoryIdentity(root.device, root.inode, root.uid, root.mode, private.device, private.inode, private.uid, private.mode)
}

func observeConfig(directoryFD int) ports.ConfigDestinationState {
	return observeNamedConfig(directoryFD, "config.yaml")
}

func observeNamedConfig(directoryFD int, name string) ports.ConfigDestinationState {
	var stat unix.Stat_t
	err := unix.Fstatat(directoryFD, name, &stat, unix.AT_SYMLINK_NOFOLLOW)
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
	directoryFD, err := unix.Openat(rootFD, ".mulgae", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
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
	return observeInstalledNamedConfigAtRoot(root, "config.yaml")
}

func observeInstalledNamedConfigAtRoot(root ports.AnchoredRoot, name string) ports.ConfigDestinationState {
	rootFD, err := openAnchoredRoot(root)
	if err != nil {
		return ports.ConfigDestinationNotObserved
	}
	defer closeFD(rootFD)
	directoryFD, err := unix.Openat(rootFD, ".mulgae", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return ports.ConfigDestinationNotObserved
	}
	defer closeFD(directoryFD)
	if observeNamedConfig(directoryFD, name) == ports.ConfigDestinationPresent {
		return ports.ConfigDestinationPresent
	}
	return ports.ConfigDestinationNotObserved
}
func revalidateRootAndPrivate(root ports.AnchoredRoot, rootIdentity, mulgaeIdentity privateDirectoryIdentity) error {
	rootFD, err := openAnchoredRoot(root)
	if err != nil {
		return err
	}
	defer closeFD(rootFD)
	actual, err := privateDirectoryIdentityForFD(rootFD)
	if err != nil || actual != rootIdentity {
		return fmt.Errorf("root identity changed")
	}
	mulgaeFD, err := unix.Openat(rootFD, ".mulgae", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer closeFD(mulgaeFD)
	if err := verifyPrivateDirectory(mulgaeFD); err != nil {
		return err
	}
	actualMulgae, err := privateDirectoryIdentityForFD(mulgaeFD)
	if err != nil || actualMulgae != mulgaeIdentity {
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
