//go:build darwin && arm64

// Package workspace materializes captured, provider-neutral workspace snapshots.
package workspace

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"strings"
	"sync"

	"github.com/irootkernel/mulgae/internal/ports"
	"golang.org/x/sys/unix"
)

const manifestName = "._mulgae_workspace_manifest.json"

var errIdentityDrift = ports.ErrWorkspaceSnapshotDrift

type WorkspaceDescriptorCloseOwner struct {
	mu     sync.Mutex
	close  func() error
	closed bool
}

func newWorkspaceCloseOwner(close func() error) *WorkspaceDescriptorCloseOwner {
	return &WorkspaceDescriptorCloseOwner{close: close}
}

func newWorkspaceDescriptorCloseOwner(close func(int) error, fd int) *WorkspaceDescriptorCloseOwner {
	return newWorkspaceCloseOwner(func() error { return close(fd) })
}

func (owner *WorkspaceDescriptorCloseOwner) Retry() error {
	if owner == nil {
		return fmt.Errorf("workspace descriptor close: invalid owner")
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if owner.closed {
		return nil
	}
	if err := owner.close(); err != nil {
		return err
	}
	owner.closed = true
	return nil
}

type WorkspaceDescriptorCloseError struct {
	cause error
	owner *WorkspaceDescriptorCloseOwner
}

func (err *WorkspaceDescriptorCloseError) Error() string { return err.cause.Error() }
func (err *WorkspaceDescriptorCloseError) Unwrap() error { return err.cause }

func (err *WorkspaceDescriptorCloseError) RetryOwner() *WorkspaceDescriptorCloseOwner {
	if err == nil {
		return nil
	}
	return err.owner
}

func WorkspaceDescriptorCloseRetryOwner(err error) (*WorkspaceDescriptorCloseOwner, bool) {
	var closeErr *WorkspaceDescriptorCloseError
	if !errors.As(err, &closeErr) || closeErr.owner == nil {
		return nil, false
	}
	return closeErr.owner, true
}

func closeDescriptor(cause error, close func(int) error, fd int) error {
	owner := newWorkspaceDescriptorCloseOwner(close, fd)
	if closeErr := owner.Retry(); closeErr != nil {
		return &WorkspaceDescriptorCloseError{cause: errors.Join(cause, closeErr), owner: owner}
	}
	return cause
}

func closeFile(cause error, file *os.File) error {
	owner := newWorkspaceCloseOwner(file.Close)
	if closeErr := owner.Retry(); closeErr != nil {
		return &WorkspaceDescriptorCloseError{cause: errors.Join(cause, closeErr), owner: owner}
	}
	return cause
}

// Materializer writes only captured request bytes beneath one caller-approved root.
type Materializer struct {
	root       ports.AnchoredRoot
	detector   ports.WorkspaceContentDetector
	operations materializerOperations
}

type materializerOperations struct {
	renameatxNp                 func(int, string, int, string, uint32) error
	removeTreeFD                func(*workspaceTreeCleanupOwner) error
	unlinkat                    func(int, string, int) error
	descriptorDetached          func(int, uint64, uint64) error
	close                       func(int) error
	beforeQuarantine            func(int, string)
	afterQuarantineVerification func(int, string)
	beforeSeal                  func() error
	beforeSnapshotUnlink        func(int, string)
	beforeTreeUnlink            func(int, string)
}

func defaultMaterializerOperations() materializerOperations {
	return materializerOperations{
		renameatxNp: unix.RenameatxNp,
		removeTreeFD: func(tree *workspaceTreeCleanupOwner) error {
			return tree.Retry()
		},
		unlinkat:           unix.Unlinkat,
		descriptorDetached: descriptorDetached,
		close:              unix.Close,
	}
}

// NewMaterializer opens no project path. root must be an existing non-symlink directory.
func NewMaterializer(root ports.AnchoredRoot, detector ports.WorkspaceContentDetector) (*Materializer, error) {
	if !root.Valid() || detector == nil {
		return nil, fmt.Errorf("workspace materializer: invalid root or detector")
	}
	fd, err := openRoot(root)
	if err != nil {
		return nil, fmt.Errorf("workspace materializer root: %w", err)
	}
	operations := defaultMaterializerOperations()
	if err := closeDescriptor(nil, operations.close, fd); err != nil {
		return nil, err
	}
	return &Materializer{root: root, detector: detector, operations: operations}, nil
}

// Materialize validates every captured byte and detector verdict before creating a destination.
func (m *Materializer) Materialize(ctx context.Context, request ports.WorkspaceSnapshotRequest) (receipt ports.WorkspaceSnapshotReceipt, err error) {
	if m == nil || ctx == nil || !m.root.Valid() || m.detector == nil || !request.Valid() {
		return ports.WorkspaceSnapshotReceipt{}, fmt.Errorf("workspace materialize: invalid materializer, context, or request")
	}
	files := request.Files()
	if err := validateFiles(files); err != nil {
		return ports.WorkspaceSnapshotReceipt{}, err
	}
	for _, file := range files {
		if err := ctx.Err(); err != nil {
			return ports.WorkspaceSnapshotReceipt{}, err
		}
		if !file.IsText() {
			continue
		}
		verdict, err := m.detector.DetectWorkspaceContent(ctx, file.Path(), file.Bytes())
		if err != nil {
			return ports.WorkspaceSnapshotReceipt{}, fmt.Errorf("workspace content detector: %w", err)
		}
		if verdict != ports.WorkspaceContentClean {
			return ports.WorkspaceSnapshotReceipt{}, fmt.Errorf("workspace content detector rejected %q: %s", file.Path().String(), verdict)
		}
	}
	var rollbackOwner *WorkspaceSnapshotCleanupOwner
	completed := false
	rootFD, err := openRoot(m.root)
	if err != nil {
		return ports.WorkspaceSnapshotReceipt{}, fmt.Errorf("workspace materialize root: %w", err)
	}
	defer func() {
		wasCompleted := completed
		if closeErr := closeDescriptor(err, m.operations.close, rootFD); closeErr != nil {
			completed = false
			receipt = ports.WorkspaceSnapshotReceipt{}
			err = closeErr
			if wasCompleted && rollbackOwner != nil {
				if cleanupErr := rollbackOwner.Retry(); cleanupErr != nil {
					err = newMaterializationCleanupError(err, cleanupErr, rollbackOwner)
				}
			}
		}
	}()
	rootDev, rootIno, err := fdIdentity(rootFD)
	if err != nil {
		return ports.WorkspaceSnapshotReceipt{}, err
	}
	name, err := randomSnapshotName(rootFD)
	if err != nil {
		return ports.WorkspaceSnapshotReceipt{}, err
	}
	if err := unix.Mkdirat(rootFD, name, 0700); err != nil {
		return ports.WorkspaceSnapshotReceipt{}, fmt.Errorf("workspace create destination: %w", err)
	}
	rollbackOwner = &WorkspaceSnapshotCleanupOwner{
		materializer: m,
		descriptor: workspaceSnapshotDescriptor{
			name: name, rootDevice: rootDev, rootInode: rootIno,
		},
		fd:     -1,
		rootFD: -1,
	}
	defer func() {
		if completed || rollbackOwner == nil {
			return
		}
		if cleanupErr := rollbackOwner.Retry(); cleanupErr != nil {
			receipt = ports.WorkspaceSnapshotReceipt{}
			err = newMaterializationCleanupError(err, cleanupErr, rollbackOwner)
		}
	}()
	var snapshotStat unix.Stat_t
	if err := unix.Fstatat(rootFD, name, &snapshotStat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return ports.WorkspaceSnapshotReceipt{}, fmt.Errorf("workspace inspect destination: %w", err)
	}
	if snapshotStat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return ports.WorkspaceSnapshotReceipt{}, errIdentityDrift
	}
	rollbackOwner.descriptor.snapshotDev = uint64(snapshotStat.Dev)
	rollbackOwner.descriptor.snapshotIno = snapshotStat.Ino
	snapshotFD, err := unix.Openat(rootFD, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return ports.WorkspaceSnapshotReceipt{}, fmt.Errorf("workspace open destination: %w", err)
	}
	defer func() {
		if closeErr := closeDescriptor(err, m.operations.close, snapshotFD); closeErr != nil {
			completed = false
			receipt = ports.WorkspaceSnapshotReceipt{}
			err = closeErr
		}
	}()
	snapshotDev, snapshotIno, err := fdIdentity(snapshotFD)
	if err != nil {
		return ports.WorkspaceSnapshotReceipt{}, err
	}
	if snapshotDev != rollbackOwner.descriptor.snapshotDev || snapshotIno != rollbackOwner.descriptor.snapshotIno {
		return ports.WorkspaceSnapshotReceipt{}, errIdentityDrift
	}
	directories := map[string]struct{}{"": {}}
	for _, file := range files {
		directory, base := path.Split(file.Path().String())
		directory = strings.TrimSuffix(directory, "/")
		if err := writeFile(snapshotFD, directory, base, file.Bytes(), directories, m.operations.close); err != nil {
			return ports.WorkspaceSnapshotReceipt{}, err
		}
	}
	manifest, err := canonicalManifest(request.PolicyIdentity(), files, rootDev, rootIno, snapshotDev, snapshotIno)
	if err != nil {
		return ports.WorkspaceSnapshotReceipt{}, err
	}
	if err := writeFile(snapshotFD, "", manifestName, manifest, directories, m.operations.close); err != nil {
		return ports.WorkspaceSnapshotReceipt{}, err
	}
	if m.operations.beforeSeal != nil {
		if err := m.operations.beforeSeal(); err != nil {
			return ports.WorkspaceSnapshotReceipt{}, err
		}
	}
	if err := sealDirectories(snapshotFD, directories, m.operations.close); err != nil {
		return ports.WorkspaceSnapshotReceipt{}, err
	}
	manifestSum := sha256.Sum256(manifest)
	receipt, err = ports.NewWorkspaceSnapshotReceipt(m.root.String()+"/"+name, name, "sha256:"+hex.EncodeToString(manifestSum[:]), request.PolicyIdentity(), rootDev, rootIno, snapshotDev, snapshotIno, files)
	if err != nil {
		return ports.WorkspaceSnapshotReceipt{}, err
	}
	completed = true
	return receipt, nil
}

// MaterializeLease creates a v2, capture-owned execution lease. Legacy v1
// receipts returned by Materialize are intentionally not convertible to this
// capability.
func (m *Materializer) MaterializeLease(ctx context.Context, request ports.WorkspaceSnapshotRequest) (ports.WorkspaceSnapshotLease, error) {
	return ports.AcquireWorkspaceSnapshotLease(ctx, func(ctx context.Context, binding ports.WorkspaceTerminalBinding) (ports.WorkspaceSnapshotLease, error) {
		return m.materializeLease(ctx, request, binding)
	})
}

func (m *Materializer) materializeLease(ctx context.Context, request ports.WorkspaceSnapshotRequest, binding ports.WorkspaceTerminalBinding) (ports.WorkspaceSnapshotLease, error) {
	receipt, err := m.Materialize(ctx, request)
	if err != nil {
		return nil, err
	}
	name, rootDev, rootIno, snapshotDev, snapshotIno := receipt.SnapshotIdentity()
	identity, err := ports.NewWorkspaceSnapshotIdentity(receipt.SnapshotPath(), name, receipt.ManifestSHA256(), receipt.PolicyIdentity(), rootDev, rootIno, snapshotDev, snapshotIno)
	if err != nil {
		return nil, m.cleanupAfterMaterialization(err, receipt)
	}
	lease := &WorkspaceSnapshotLease{materializer: m, receipt: receipt, identity: identity, cleanupOwner: cleanupOwnerForReceipt(m, receipt)}
	if err := lease.revalidateLocked(); err != nil {
		return nil, m.cleanupAfterMaterialization(err, receipt)
	}
	release, err := binding.Bind(identity, lease.releaseEffects)
	if err != nil {
		return nil, m.cleanupAfterMaterialization(err, receipt)
	}
	lease.terminalRelease = release
	return lease, nil
}

// MaterializeQualificationLease creates an ephemeral execution lease for fixed
// qualification inputs. It uses the same materialization and revalidation
// boundary as a user snapshot, without accepting publication or abort evidence.
func (m *Materializer) MaterializeQualificationLease(ctx context.Context, request ports.WorkspaceSnapshotRequest) (ports.QualificationWorkspaceLease, error) {
	return ports.AcquireQualificationWorkspaceLease(ctx, func(ctx context.Context, binding ports.QualificationWorkspaceTerminalBinding) (ports.QualificationWorkspaceLease, error) {
		return m.materializeQualificationLease(ctx, request, binding)
	})
}

func (m *Materializer) materializeQualificationLease(ctx context.Context, request ports.WorkspaceSnapshotRequest, binding ports.QualificationWorkspaceTerminalBinding) (ports.QualificationWorkspaceLease, error) {
	receipt, err := m.Materialize(ctx, request)
	if err != nil {
		return nil, err
	}
	name, rootDev, rootIno, snapshotDev, snapshotIno := receipt.SnapshotIdentity()
	identity, err := ports.NewWorkspaceSnapshotIdentity(receipt.SnapshotPath(), name, receipt.ManifestSHA256(), receipt.PolicyIdentity(), rootDev, rootIno, snapshotDev, snapshotIno)
	if err != nil {
		return nil, m.cleanupAfterMaterialization(err, receipt)
	}
	lease := &qualificationWorkspaceLease{materializer: m, receipt: receipt, identity: identity, cleanupOwner: cleanupOwnerForReceipt(m, receipt)}
	if err := lease.revalidateLocked(); err != nil {
		return nil, m.cleanupAfterMaterialization(err, receipt)
	}
	drain, err := binding.Bind(identity, lease.drainTerminalEffects)
	if err != nil {
		return nil, m.cleanupAfterMaterialization(err, receipt)
	}
	lease.terminalDrain = drain
	return lease, nil
}

// qualificationWorkspaceLease owns only an ephemeral qualification snapshot.
// Unlike WorkspaceSnapshotLease, failures never terminally consume this lease:
// cleanup can be retried until it succeeds.
type qualificationWorkspaceLease struct {
	mu            sync.Mutex
	materializer  *Materializer
	receipt       ports.WorkspaceSnapshotReceipt
	identity      ports.WorkspaceSnapshotIdentity
	terminalDrain ports.QualificationWorkspaceTerminalDrain
	activeGuards  uint
	drained       bool
	cleanupOwner  *WorkspaceSnapshotCleanupOwner
}

func (lease *qualificationWorkspaceLease) WorkspaceSnapshotIdentity() ports.WorkspaceSnapshotIdentity {
	if lease == nil {
		return ports.WorkspaceSnapshotIdentity{}
	}
	return lease.identity
}

func (lease *qualificationWorkspaceLease) RevalidateForExecution() (ports.WorkspaceExecutionGuard, error) {
	if lease == nil {
		return nil, fmt.Errorf("qualification workspace execution guard: invalid lease")
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.drained {
		return nil, fmt.Errorf("qualification workspace execution guard: lease drained")
	}
	if err := lease.revalidateLocked(); err != nil {
		return nil, err
	}
	rootFD, err := openRoot(lease.materializer.root)
	if err != nil {
		return nil, fmt.Errorf("qualification workspace execution guard root: %w", err)
	}
	fd, openErr := unix.Openat(rootFD, lease.identity.SnapshotName(), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if closeErr := closeDescriptor(openErr, lease.materializer.operations.close, rootFD); closeErr != nil {
		if openErr == nil {
			closeErr = closeDescriptor(closeErr, lease.materializer.operations.close, fd)
		}
		return nil, closeErr
	}
	if openErr != nil {
		return nil, ports.ErrWorkspaceSnapshotDrift
	}
	guard := &qualificationWorkspaceExecutionGuard{lease: lease, fd: fd}
	root, err := ports.NewValidatedWorkspaceRoot(lease.identity.SnapshotPath(), lease.identity)
	if err != nil {
		return nil, closeDescriptor(err, lease.materializer.operations.close, guard.fd)
	}
	guard.root = root
	lease.activeGuards++
	return guard, nil
}

func (lease *qualificationWorkspaceLease) DrainTerminal(ctx context.Context) (ports.QualificationWorkspaceTerminalReceipt, error) {
	if lease == nil || lease.terminalDrain == nil {
		return ports.QualificationWorkspaceTerminalReceipt{}, fmt.Errorf("qualification workspace drain: invalid lease")
	}
	return lease.terminalDrain(ctx)
}

func (lease *qualificationWorkspaceLease) drainTerminalEffects(ctx context.Context) error {
	if lease == nil || ctx == nil {
		return fmt.Errorf("qualification workspace drain: invalid lease or context")
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.drained {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if lease.activeGuards != 0 {
		return fmt.Errorf("qualification workspace drain: execution guards remain active")
	}
	if lease.cleanupOwner == nil {
		return fmt.Errorf("qualification workspace drain: missing cleanup owner")
	}
	if lease.cleanupOwner.stage == workspaceCleanupAcquired {
		if err := lease.revalidateLocked(); err != nil {
			return err
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := lease.cleanupOwner.Retry(); err != nil {
		return err
	}
	lease.drained = true
	return nil
}

func (lease *qualificationWorkspaceLease) revalidateLocked() error {
	if lease.materializer == nil || !lease.identity.Valid() || !lease.receipt.Valid() {
		return fmt.Errorf("qualification workspace lease: invalid lease")
	}
	if err := lease.materializer.Revalidate(lease.receipt); err != nil {
		return err
	}
	return nil
}

type qualificationWorkspaceExecutionGuard struct {
	mu     sync.Mutex
	lease  *qualificationWorkspaceLease
	root   ports.ValidatedWorkspaceRoot
	fd     int
	closed bool
}

func (guard *qualificationWorkspaceExecutionGuard) WorkspaceRoot() ports.ValidatedWorkspaceRoot {
	return guard.root
}

func (guard *qualificationWorkspaceExecutionGuard) WorkspaceSnapshotIdentity() ports.WorkspaceSnapshotIdentity {
	return guard.root.SnapshotIdentity()
}

func (guard *qualificationWorkspaceExecutionGuard) DuplicateLaunchDirectory() (*os.File, error) {
	if guard == nil {
		return nil, fmt.Errorf("qualification workspace execution guard: invalid guard")
	}
	guard.mu.Lock()
	defer guard.mu.Unlock()
	if guard.closed {
		return nil, fmt.Errorf("qualification workspace execution guard: closed")
	}
	device, inode, err := fdIdentity(guard.fd)
	expectedDevice, expectedInode := guard.root.SnapshotIdentity().SnapshotFSIdentity()
	if err != nil || device != expectedDevice || inode != expectedInode {
		return nil, ports.ErrWorkspaceSnapshotDrift
	}
	duplicate, err := unix.Dup(guard.fd)
	if err != nil {
		return nil, fmt.Errorf("qualification workspace execution guard: duplicate launch directory: %w", err)
	}
	return os.NewFile(uintptr(duplicate), guard.root.Path()), nil
}

func (guard *qualificationWorkspaceExecutionGuard) RevalidateAfterExecution() error {
	if guard == nil {
		return fmt.Errorf("qualification workspace execution guard: invalid guard")
	}
	guard.mu.Lock()
	defer guard.mu.Unlock()
	if guard.closed {
		return fmt.Errorf("qualification workspace execution guard: closed")
	}
	guard.lease.mu.Lock()
	defer guard.lease.mu.Unlock()
	if guard.lease.drained {
		return ports.ErrWorkspaceSnapshotDrift
	}
	return guard.lease.revalidateLocked()
}

func (guard *qualificationWorkspaceExecutionGuard) Close() error {
	if guard == nil {
		return fmt.Errorf("qualification workspace execution guard: invalid guard")
	}
	guard.mu.Lock()
	defer guard.mu.Unlock()
	if guard.closed {
		return nil
	}
	if err := guard.lease.materializer.operations.close(guard.fd); err != nil {
		return fmt.Errorf("qualification workspace execution guard close: %w", err)
	}
	guard.closed = true
	guard.lease.mu.Lock()
	defer guard.lease.mu.Unlock()
	if guard.lease.activeGuards == 0 {
		return fmt.Errorf("qualification workspace execution guard: guard accounting underflow")
	}
	guard.lease.activeGuards--
	return nil
}

type WorkspaceSnapshotLease struct {
	mu              sync.Mutex
	materializer    *Materializer
	receipt         ports.WorkspaceSnapshotReceipt
	identity        ports.WorkspaceSnapshotIdentity
	terminalRelease ports.WorkspaceTerminalRelease
	activeGuards    uint
	released        bool
	aborted         bool
	abortEvidence   ports.WorkspaceAbortEvidence
	cleanupOwner    *WorkspaceSnapshotCleanupOwner
}

func (lease *WorkspaceSnapshotLease) WorkspaceSnapshotIdentity() ports.WorkspaceSnapshotIdentity {
	if lease == nil {
		return ports.WorkspaceSnapshotIdentity{}
	}
	return lease.identity
}

func (lease *WorkspaceSnapshotLease) Receipt() ports.WorkspaceSnapshotReceipt {
	if lease == nil {
		return ports.WorkspaceSnapshotReceipt{}
	}
	return lease.receipt
}

func (lease *WorkspaceSnapshotLease) RevalidateForExecution() (ports.WorkspaceExecutionGuard, error) {
	if lease == nil {
		return nil, fmt.Errorf("workspace execution guard: invalid lease")
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.released {
		return nil, fmt.Errorf("workspace execution guard: lease released")
	}
	if err := lease.revalidateLocked(); err != nil {
		return nil, err
	}
	rootFD, err := openRoot(lease.materializer.root)
	if err != nil {
		return nil, fmt.Errorf("workspace execution guard root: %w", err)
	}
	fd, openErr := unix.Openat(rootFD, lease.identity.SnapshotName(), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if closeErr := closeDescriptor(openErr, lease.materializer.operations.close, rootFD); closeErr != nil {
		if openErr == nil {
			closeErr = closeDescriptor(closeErr, lease.materializer.operations.close, fd)
		}
		return nil, closeErr
	}
	if openErr != nil {
		return nil, ports.ErrWorkspaceSnapshotDrift
	}
	guard := &workspaceExecutionGuard{lease: lease, fd: fd}
	root, err := ports.NewValidatedWorkspaceRoot(lease.identity.SnapshotPath(), lease.identity)
	if err != nil {
		return nil, closeDescriptor(err, lease.materializer.operations.close, guard.fd)
	}
	guard.root = root
	lease.activeGuards++
	return guard, nil
}

func (lease *WorkspaceSnapshotLease) Release(evidence ports.WorkspaceCompletionEvidence) (ports.WorkspaceTerminalReceipt, error) {
	if lease == nil || lease.terminalRelease == nil {
		return ports.WorkspaceTerminalReceipt{}, fmt.Errorf("workspace lease release: invalid lease")
	}
	return lease.terminalRelease(evidence)
}

func (lease *WorkspaceSnapshotLease) releaseEffects(evidence ports.WorkspaceCompletionEvidence) error {
	if lease == nil || !evidence.Valid() {
		return fmt.Errorf("workspace lease release: invalid completion evidence")
	}
	if evidence.WorkspaceSnapshotIdentity() != lease.identity {
		return fmt.Errorf("workspace lease release: workspace identity mismatch")
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.released {
		return fmt.Errorf("workspace lease release: lease already terminated")
	}
	if lease.activeGuards != 0 {
		return fmt.Errorf("workspace lease release: execution guards remain active")
	}
	if err := lease.cleanupLocked("workspace lease release"); err != nil {
		return err
	}
	lease.released = true
	return nil
}

func (lease *WorkspaceSnapshotLease) Abort(evidence ports.WorkspaceAbortEvidence) error {
	if lease == nil || !evidence.Valid() {
		return fmt.Errorf("workspace lease abort: invalid abort evidence")
	}
	if evidence.WorkspaceSnapshotIdentity() != lease.identity {
		return fmt.Errorf("workspace lease abort: workspace identity mismatch")
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.released {
		if lease.aborted && lease.abortEvidence.Equal(evidence) {
			return nil
		}
		return fmt.Errorf("workspace lease abort: lease already terminated by different evidence")
	}
	if lease.activeGuards != 0 {
		return fmt.Errorf("workspace lease abort: execution guards remain active")
	}
	if err := lease.cleanupLocked("workspace lease abort"); err != nil {
		return err
	}
	lease.released = true
	lease.aborted = true
	lease.abortEvidence = evidence
	return nil
}

func (lease *WorkspaceSnapshotLease) cleanupLocked(prefix string) error {
	if lease.cleanupOwner == nil {
		return fmt.Errorf("%s: missing cleanup owner", prefix)
	}
	if lease.cleanupOwner.stage == workspaceCleanupAcquired {
		if err := lease.revalidateLocked(); err != nil {
			return err
		}
	}
	return lease.cleanupOwner.Retry()
}

func (lease *WorkspaceSnapshotLease) revalidateLocked() (err error) {
	if lease.materializer == nil || !lease.identity.Valid() || !lease.receipt.Valid() {
		return fmt.Errorf("workspace lease: invalid lease")
	}
	if err := lease.materializer.Revalidate(lease.receipt); err != nil {
		return err
	}
	rootFD, err := openRoot(lease.materializer.root)
	if err != nil {
		return fmt.Errorf("workspace lease revalidate root: %w", err)
	}
	defer func() {
		err = closeDescriptor(err, lease.materializer.operations.close, rootFD)
	}()
	fd, err := unix.Openat(rootFD, lease.identity.SnapshotName(), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return ports.ErrWorkspaceSnapshotDrift
	}
	defer func() {
		err = closeDescriptor(err, lease.materializer.operations.close, fd)
	}()
	return validateLeaseTree(fd, lease.receipt.Files(), lease.identity.ManifestSHA256(), lease.materializer.operations.close)
}

type workspaceExecutionGuard struct {
	mu     sync.Mutex
	lease  *WorkspaceSnapshotLease
	root   ports.ValidatedWorkspaceRoot
	fd     int
	closed bool
}

func (guard *workspaceExecutionGuard) WorkspaceRoot() ports.ValidatedWorkspaceRoot { return guard.root }
func (guard *workspaceExecutionGuard) WorkspaceSnapshotIdentity() ports.WorkspaceSnapshotIdentity {
	return guard.root.SnapshotIdentity()
}
func (guard *workspaceExecutionGuard) DuplicateLaunchDirectory() (*os.File, error) {
	if guard == nil {
		return nil, fmt.Errorf("workspace execution guard: invalid guard")
	}
	guard.mu.Lock()
	defer guard.mu.Unlock()
	if guard.closed {
		return nil, fmt.Errorf("workspace execution guard: closed")
	}
	device, inode, err := fdIdentity(guard.fd)
	expectedDevice, expectedInode := guard.root.SnapshotIdentity().SnapshotFSIdentity()
	if err != nil || device != expectedDevice || inode != expectedInode {
		return nil, ports.ErrWorkspaceSnapshotDrift
	}
	duplicate, err := unix.Dup(guard.fd)
	if err != nil {
		return nil, fmt.Errorf("workspace execution guard: duplicate launch directory: %w", err)
	}
	return os.NewFile(uintptr(duplicate), guard.root.Path()), nil
}
func (guard *workspaceExecutionGuard) RevalidateAfterExecution() error {
	if guard == nil {
		return fmt.Errorf("workspace execution guard: invalid guard")
	}
	guard.mu.Lock()
	defer guard.mu.Unlock()
	if guard.closed {
		return fmt.Errorf("workspace execution guard: closed")
	}
	guard.lease.mu.Lock()
	defer guard.lease.mu.Unlock()
	if guard.lease.released {
		return ports.ErrWorkspaceSnapshotDrift
	}
	return guard.lease.revalidateLocked()
}
func (guard *workspaceExecutionGuard) Close() error {
	if guard == nil {
		return fmt.Errorf("workspace execution guard: invalid guard")
	}
	guard.mu.Lock()
	defer guard.mu.Unlock()
	if guard.closed {
		return nil
	}
	if err := guard.lease.materializer.operations.close(guard.fd); err != nil {
		return fmt.Errorf("workspace execution guard close: %w", err)
	}
	guard.closed = true
	guard.lease.mu.Lock()
	defer guard.lease.mu.Unlock()
	if guard.lease.activeGuards == 0 {
		return fmt.Errorf("workspace execution guard: guard accounting underflow")
	}
	guard.lease.activeGuards--
	return nil
}
func validateLeaseTree(rootFD int, files []ports.WorkspaceSnapshotFile, manifestSHA256 string, close func(int) error) error {
	expectedFiles := map[string]ports.WorkspaceSnapshotFile{manifestName: {}}
	expectedDirectories := map[string]struct{}{"": {}}
	for _, file := range files {
		expectedFiles[file.Path().String()] = file
		directory := path.Dir(file.Path().String())
		for directory != "." {
			expectedDirectories[directory] = struct{}{}
			directory = path.Dir(directory)
		}
	}
	rootDev, _, err := fdIdentity(rootFD)
	if err != nil {
		return ports.ErrWorkspaceSnapshotDrift
	}
	return validateLeaseDirectory(rootFD, "", rootDev, expectedFiles, expectedDirectories, manifestSHA256, close)
}

func validateLeaseDirectory(fd int, relative string, rootDev uint64, files map[string]ports.WorkspaceSnapshotFile, directories map[string]struct{}, manifestSHA256 string, close func(int) error) error {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || uint64(stat.Dev) != rootDev || stat.Mode&0777 != 0555 {
		return ports.ErrWorkspaceSnapshotDrift
	}
	names, err := directoryNames(fd)
	if err != nil {
		return errors.Join(ports.ErrWorkspaceSnapshotDrift, err)
	}
	for _, name := range names {
		child := name
		if relative != "" {
			child = relative + "/" + name
		}
		var childStat unix.Stat_t
		if err := unix.Fstatat(fd, name, &childStat, unix.AT_SYMLINK_NOFOLLOW); err != nil || uint64(childStat.Dev) != rootDev {
			return ports.ErrWorkspaceSnapshotDrift
		}
		switch childStat.Mode & unix.S_IFMT {
		case unix.S_IFDIR:
			if _, ok := directories[child]; !ok {
				return ports.ErrWorkspaceSnapshotDrift
			}
			childFD, err := unix.Openat(fd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			if err != nil {
				return ports.ErrWorkspaceSnapshotDrift
			}
			err = validateLeaseDirectory(childFD, child, rootDev, files, directories, manifestSHA256, close)
			err = closeDescriptor(err, close, childFD)
			if err != nil {
				return err
			}
		case unix.S_IFREG:
			expected, ok := files[child]
			if !ok || childStat.Mode&0777 != 0444 || childStat.Nlink != 1 {
				return ports.ErrWorkspaceSnapshotDrift
			}
			bytes, err := readRegular(fd, name, close)
			if err != nil {
				return errors.Join(ports.ErrWorkspaceSnapshotDrift, err)
			}
			if child == manifestName {
				if digest(bytes) != manifestSHA256 {
					return ports.ErrWorkspaceSnapshotDrift
				}
			} else if int64(len(bytes)) != int64(len(expected.Bytes())) || digest(bytes) != expected.SHA256() {
				return ports.ErrWorkspaceSnapshotDrift
			}
			delete(files, child)
		default:
			return ports.ErrWorkspaceSnapshotDrift
		}
	}
	if stat.Mode&0777 != 0555 {
		return ports.ErrWorkspaceSnapshotDrift
	}
	delete(directories, relative)
	if relative == "" && (len(files) != 0 || len(directories) != 0) {
		return ports.ErrWorkspaceSnapshotDrift
	}
	return nil
}

// Revalidate proves the receipt's root, directory, manifest, and captured file identities.
func (m *Materializer) Revalidate(receipt ports.WorkspaceSnapshotReceipt) (err error) {
	if m == nil || !receipt.Valid() {
		return fmt.Errorf("workspace revalidate: invalid receipt")
	}
	name, rootDev, rootIno, snapshotDev, snapshotIno := receipt.SnapshotIdentity()
	if receipt.SnapshotPath() != m.root.String()+"/"+name {
		return errIdentityDrift
	}
	rootFD, err := openRoot(m.root)
	if err != nil {
		return fmt.Errorf("workspace revalidate root: %w", err)
	}
	defer func() {
		err = closeDescriptor(err, m.operations.close, rootFD)
	}()
	dev, ino, err := fdIdentity(rootFD)
	if err != nil || dev != rootDev || ino != rootIno {
		return errIdentityDrift
	}
	fd, err := unix.Openat(rootFD, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return errIdentityDrift
	}
	defer func() {
		err = closeDescriptor(err, m.operations.close, fd)
	}()
	dev, ino, err = fdIdentity(fd)
	if err != nil || dev != snapshotDev || ino != snapshotIno {
		return errIdentityDrift
	}
	if err := validateLeaseTree(fd, receipt.Files(), receipt.ManifestSHA256(), m.operations.close); err != nil {
		return errors.Join(errIdentityDrift, err)
	}
	return nil
}

// WorkspaceSnapshotCleanupOwner retains descriptor-backed, monotonic cleanup
// authority. Once quarantine succeeds, retries never reopen the snapshot path.
type WorkspaceSnapshotCleanupOwner struct {
	mu           sync.Mutex
	materializer *Materializer
	descriptor   workspaceSnapshotDescriptor
	stage        workspaceCleanupStage
	tomb         string
	fd           int
	rootFD       int
	tree         *workspaceTreeCleanupOwner
}

type workspaceCleanupStage uint8

const (
	workspaceCleanupAcquired workspaceCleanupStage = iota
	workspaceCleanupAcquiredRootClosePending
	workspaceCleanupAcquiredSourceClosePending
	workspaceCleanupAcquiredSourceAndRootClosePending
	workspaceCleanupQuarantined
	workspaceCleanupQuarantinedRootClosePending
	workspaceCleanupTreeCleared
	workspaceCleanupTreeClearedRootClosePending
	workspaceCleanupUnlinkCommitted
	workspaceCleanupUnlinkCommittedRootClosePending
	workspaceCleanupDetachmentVerified
	workspaceCleanupDescriptorClosed
	workspaceCleanupRestoredPath
	workspaceCleanupRestoredPathRootClosePending
	workspaceCleanupRestoredPathClosePending
	workspaceCleanupRestoredPathCloseAndRootClosePending
	workspaceCleanupOwnerReleased
)

type workspaceSnapshotDescriptor struct {
	name        string
	rootDevice  uint64
	rootInode   uint64
	snapshotDev uint64
	snapshotIno uint64
}

func cleanupOwnerForReceipt(m *Materializer, receipt ports.WorkspaceSnapshotReceipt) *WorkspaceSnapshotCleanupOwner {
	name, rootDevice, rootInode, snapshotDev, snapshotIno := receipt.SnapshotIdentity()
	return &WorkspaceSnapshotCleanupOwner{
		materializer: m,
		descriptor:   workspaceSnapshotDescriptor{name, rootDevice, rootInode, snapshotDev, snapshotIno},
		fd:           -1,
		rootFD:       -1,
	}
}

// Retry resumes cleanup from the last proven stage. It never reacquires an
// unlinked snapshot by pathname.
func (owner *WorkspaceSnapshotCleanupOwner) Retry() error {
	if owner == nil || owner.materializer == nil || owner.descriptor.name == "" {
		return fmt.Errorf("workspace cleanup retry: invalid owner")
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if owner.stage == workspaceCleanupOwnerReleased {
		return nil
	}
	return owner.retryLocked()
}

func (owner *WorkspaceSnapshotCleanupOwner) retryLocked() error {
	switch owner.stage {
	case workspaceCleanupAcquiredRootClosePending:
		if err := owner.closeRootPendingLocked(workspaceCleanupAcquired); err != nil {
			return err
		}
	case workspaceCleanupAcquiredSourceClosePending:
		if err := owner.closeAcquiredDescriptorLocked(); err != nil {
			return err
		}
	case workspaceCleanupAcquiredSourceAndRootClosePending:
		if err := owner.closeRootPendingLocked(workspaceCleanupAcquiredSourceClosePending); err != nil {
			return err
		}
		return owner.retryLocked()
	case workspaceCleanupQuarantinedRootClosePending:
		if err := owner.closeRootPendingLocked(workspaceCleanupQuarantined); err != nil {
			return err
		}
	case workspaceCleanupTreeClearedRootClosePending:
		if err := owner.closeRootPendingLocked(workspaceCleanupTreeCleared); err != nil {
			return err
		}
	case workspaceCleanupUnlinkCommittedRootClosePending:
		if err := owner.closeRootPendingLocked(workspaceCleanupUnlinkCommitted); err != nil {
			return err
		}
	case workspaceCleanupRestoredPathRootClosePending:
		if err := owner.closeRootPendingLocked(workspaceCleanupRestoredPath); err != nil {
			return err
		}
		return owner.retryLocked()
	case workspaceCleanupRestoredPathCloseAndRootClosePending:
		if err := owner.closeRootPendingLocked(workspaceCleanupRestoredPathClosePending); err != nil {
			return err
		}
		return owner.retryLocked()
	case workspaceCleanupRestoredPath, workspaceCleanupRestoredPathClosePending:
		if err := owner.closeRestoredDescriptorLocked(); err != nil {
			return err
		}
	}
	operations := owner.materializer.operations
	if owner.stage == workspaceCleanupAcquired {
		rootFD, err := openRoot(owner.materializer.root)
		if err != nil {
			return fmt.Errorf("workspace cleanup root: %w", err)
		}
		quarantineErr := owner.quarantineLocked(rootFD)
		if err := owner.closeRootAfterStageLocked(rootFD); err != nil {
			return fmt.Errorf("workspace cleanup quarantine: %w", errors.Join(quarantineErr, err))
		}
		if quarantineErr != nil {
			return fmt.Errorf("workspace cleanup quarantine: %w", quarantineErr)
		}
	}
	if owner.fd < 0 {
		return fmt.Errorf("workspace cleanup: missing retained descriptor")
	}
	if owner.stage == workspaceCleanupQuarantined {
		if owner.tree == nil {
			owner.tree = newWorkspaceTreeCleanupOwner(owner.fd, operations.close, operations.renameatxNp, operations.unlinkat, operations.descriptorDetached, operations.beforeTreeUnlink)
		}
		if err := operations.removeTreeFD(owner.tree); err != nil {
			return fmt.Errorf("workspace cleanup tree: %w", err)
		}
		if !owner.tree.Terminal() {
			return fmt.Errorf("workspace cleanup tree: traversal did not reach terminal state")
		}
		owner.stage = workspaceCleanupTreeCleared
	}
	if owner.stage == workspaceCleanupTreeCleared {
		rootFD, err := openRoot(owner.materializer.root)
		if err != nil {
			return fmt.Errorf("workspace cleanup root: %w", err)
		}
		unlinkErr := owner.unlinkLocked(rootFD)
		if err := owner.closeRootAfterStageLocked(rootFD); err != nil {
			return fmt.Errorf("workspace cleanup unlink: %w", errors.Join(unlinkErr, err))
		}
		if unlinkErr != nil {
			return fmt.Errorf("workspace cleanup unlink: %w", unlinkErr)
		}
	}
	if owner.stage == workspaceCleanupUnlinkCommitted {
		if err := operations.descriptorDetached(owner.fd, owner.descriptor.snapshotDev, owner.descriptor.snapshotIno); err != nil {
			return fmt.Errorf("workspace cleanup detachment: %w", err)
		}
		owner.stage = workspaceCleanupDetachmentVerified
	}
	if owner.stage == workspaceCleanupDetachmentVerified {
		if err := operations.close(owner.fd); err != nil {
			return fmt.Errorf("workspace cleanup descriptor close: %w", err)
		}
		owner.fd = -1
		owner.stage = workspaceCleanupDescriptorClosed
	}
	owner.stage = workspaceCleanupOwnerReleased
	return nil
}

func (owner *WorkspaceSnapshotCleanupOwner) closeRootAfterStageLocked(rootFD int) error {
	if err := owner.materializer.operations.close(rootFD); err != nil {
		owner.rootFD = rootFD
		switch owner.stage {
		case workspaceCleanupAcquired:
			owner.stage = workspaceCleanupAcquiredRootClosePending
		case workspaceCleanupAcquiredSourceClosePending:
			owner.stage = workspaceCleanupAcquiredSourceAndRootClosePending
		case workspaceCleanupQuarantined:
			owner.stage = workspaceCleanupQuarantinedRootClosePending
		case workspaceCleanupTreeCleared:
			owner.stage = workspaceCleanupTreeClearedRootClosePending
		case workspaceCleanupUnlinkCommitted:
			owner.stage = workspaceCleanupUnlinkCommittedRootClosePending
		case workspaceCleanupRestoredPath:
			owner.stage = workspaceCleanupRestoredPathRootClosePending
		case workspaceCleanupRestoredPathClosePending:
			owner.stage = workspaceCleanupRestoredPathCloseAndRootClosePending
		default:
			return fmt.Errorf("workspace cleanup root close: invalid stage %d: %w", owner.stage, err)
		}
		return err
	}
	return nil
}

func (owner *WorkspaceSnapshotCleanupOwner) closeRootPendingLocked(next workspaceCleanupStage) error {
	if owner.rootFD < 0 {
		return fmt.Errorf("workspace cleanup: missing retained root descriptor")
	}
	if err := owner.materializer.operations.close(owner.rootFD); err != nil {
		return fmt.Errorf("workspace cleanup root close: %w", err)
	}
	owner.rootFD = -1
	owner.stage = next
	return nil
}
func (owner *WorkspaceSnapshotCleanupOwner) closeAcquiredDescriptorLocked() error {
	if owner.fd < 0 {
		return fmt.Errorf("workspace cleanup: missing retained source descriptor")
	}
	if err := owner.materializer.operations.close(owner.fd); err != nil {
		owner.stage = workspaceCleanupAcquiredSourceClosePending
		return fmt.Errorf("workspace cleanup source descriptor close: %w", err)
	}
	owner.fd = -1
	owner.stage = workspaceCleanupAcquired
	return nil
}

func (owner *WorkspaceSnapshotCleanupOwner) closeRestoredDescriptorLocked() error {
	if owner.fd < 0 {
		return fmt.Errorf("workspace cleanup: missing restored snapshot descriptor")
	}
	if err := owner.materializer.operations.close(owner.fd); err != nil {
		owner.stage = workspaceCleanupRestoredPathClosePending
		return fmt.Errorf("workspace cleanup restored descriptor close: %w", err)
	}
	owner.fd = -1
	owner.stage = workspaceCleanupAcquired
	return nil
}

func (owner *WorkspaceSnapshotCleanupOwner) quarantineLocked(rootFD int) error {
	rootDevice, rootInode, err := fdIdentity(rootFD)
	if err != nil || rootDevice != owner.descriptor.rootDevice || rootInode != owner.descriptor.rootInode {
		return errIdentityDrift
	}
	if owner.fd < 0 {
		if owner.materializer.operations.beforeQuarantine != nil {
			owner.materializer.operations.beforeQuarantine(rootFD, owner.descriptor.name)
		}
		name, err := findRetainedDirectory(rootFD, owner.descriptor.name, owner.descriptor.snapshotDev, owner.descriptor.snapshotIno)
		if err != nil {
			return err
		}
		fd, err := unix.Openat(rootFD, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return err
		}
		owner.fd = fd
		owner.tomb = name
	}
	tomb, err := relocateRetainedDirectory(owner.materializer.operations.renameatxNp, rootFD, owner.tomb, owner.fd, owner.descriptor.snapshotDev, owner.descriptor.snapshotIno)
	if err != nil {
		return err
	}
	owner.tomb, owner.stage = tomb, workspaceCleanupQuarantined
	if err := verifyTombIdentity(rootFD, tomb, owner.fd, owner.descriptor); err != nil {
		return err
	}
	if owner.materializer.operations.afterQuarantineVerification != nil {
		owner.materializer.operations.afterQuarantineVerification(rootFD, tomb)
	}
	tomb, err = relocateRetainedDirectory(owner.materializer.operations.renameatxNp, rootFD, owner.tomb, owner.fd, owner.descriptor.snapshotDev, owner.descriptor.snapshotIno)
	if err != nil {
		return err
	}
	owner.tomb = tomb
	return verifyTombIdentity(rootFD, tomb, owner.fd, owner.descriptor)
}

func (owner *WorkspaceSnapshotCleanupOwner) unlinkLocked(rootFD int) error {
	tomb, err := relocateRetainedDirectory(owner.materializer.operations.renameatxNp, rootFD, owner.tomb, owner.fd, owner.descriptor.snapshotDev, owner.descriptor.snapshotIno)
	if err != nil {
		if !errors.Is(err, errIdentityDrift) {
			return err
		}
		detachErr := owner.materializer.operations.descriptorDetached(owner.fd, owner.descriptor.snapshotDev, owner.descriptor.snapshotIno)
		if detachErr == nil {
			owner.stage = workspaceCleanupUnlinkCommitted
			return nil
		}
		return errors.Join(err, detachErr)
	}
	owner.tomb = tomb
	if owner.materializer.operations.beforeSnapshotUnlink != nil {
		owner.materializer.operations.beforeSnapshotUnlink(rootFD, owner.tomb)
	}
	if err := verifyTombIdentity(rootFD, owner.tomb, owner.fd, owner.descriptor); err != nil {
		return err
	}
	if err := owner.materializer.operations.unlinkat(rootFD, owner.tomb, unix.AT_REMOVEDIR); err != nil {
		return err
	}
	if err := owner.materializer.operations.descriptorDetached(owner.fd, owner.descriptor.snapshotDev, owner.descriptor.snapshotIno); err != nil {
		return err
	}
	owner.stage = workspaceCleanupUnlinkCommitted
	return nil
}

// MaterializationCleanupError reports a primary materialization failure together
// with a failed cleanup and retains the retry owner.
type MaterializationCleanupError struct {
	cause error
	owner *WorkspaceSnapshotCleanupOwner
}

func (err *MaterializationCleanupError) Error() string { return err.cause.Error() }
func (err *MaterializationCleanupError) Unwrap() error { return err.cause }

// CleanupOwner returns the exact snapshot cleanup authority retained by err.
func (err *MaterializationCleanupError) CleanupOwner() *WorkspaceSnapshotCleanupOwner {
	if err == nil {
		return nil
	}
	return err.owner
}

// MaterializationCleanupRetryOwner extracts retry authority without relying on
// receipt strings or tokens.
func MaterializationCleanupRetryOwner(err error) (*WorkspaceSnapshotCleanupOwner, bool) {
	var cleanupErr *MaterializationCleanupError
	if !errors.As(err, &cleanupErr) || cleanupErr.owner == nil {
		return nil, false
	}
	return cleanupErr.owner, true
}

// WorkspaceCleanupError reports failed public cleanup and retains exact retry
// authority through any irreversible cleanup stage.
type WorkspaceCleanupError struct {
	cause error
	owner *WorkspaceSnapshotCleanupOwner
}

func (err *WorkspaceCleanupError) Error() string { return err.cause.Error() }
func (err *WorkspaceCleanupError) Unwrap() error { return err.cause }

// CleanupOwner returns the exact snapshot cleanup authority retained by err.
func (err *WorkspaceCleanupError) CleanupOwner() *WorkspaceSnapshotCleanupOwner {
	if err == nil {
		return nil
	}
	return err.owner
}

// WorkspaceCleanupRetryOwner extracts retry authority from public cleanup.
func WorkspaceCleanupRetryOwner(err error) (*WorkspaceSnapshotCleanupOwner, bool) {
	var cleanupErr *WorkspaceCleanupError
	if !errors.As(err, &cleanupErr) || cleanupErr.owner == nil {
		return nil, false
	}
	return cleanupErr.owner, true
}

func newMaterializationCleanupError(primary, cleanup error, owner *WorkspaceSnapshotCleanupOwner) error {
	return &MaterializationCleanupError{cause: errors.Join(primary, cleanup), owner: owner}
}

func (m *Materializer) cleanupAfterMaterialization(primary error, receipt ports.WorkspaceSnapshotReceipt) error {
	owner := cleanupOwnerForReceipt(m, receipt)
	if cleanupErr := owner.Retry(); cleanupErr != nil {
		return newMaterializationCleanupError(primary, cleanupErr, owner)
	}
	return primary
}

// Cleanup removes only a fully revalidated receipt-owned snapshot.
func (m *Materializer) Cleanup(receipt ports.WorkspaceSnapshotReceipt) error {
	if err := m.Revalidate(receipt); err != nil {
		return fmt.Errorf("workspace cleanup: %w", err)
	}
	owner := cleanupOwnerForReceipt(m, receipt)
	if err := owner.Retry(); err != nil {
		return &WorkspaceCleanupError{cause: err, owner: owner}
	}
	return nil
}
func verifyTombIdentity(rootFD int, tomb string, tombFD int, descriptor workspaceSnapshotDescriptor) error {
	device, inode, err := fdIdentity(tombFD)
	if err != nil || device != descriptor.snapshotDev || inode != descriptor.snapshotIno {
		return errIdentityDrift
	}
	var stat unix.Stat_t
	if err := unix.Fstatat(rootFD, tomb, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR || uint64(stat.Dev) != descriptor.snapshotDev || stat.Ino != descriptor.snapshotIno {
		return errIdentityDrift
	}
	return nil
}
func relocateRetainedDirectory(renameatxNp func(int, string, int, string, uint32) error, parentFD int, preferred string, retainedFD int, device, inode uint64) (string, error) {
	retainedDevice, retainedInode, err := fdIdentity(retainedFD)
	if err != nil || retainedDevice != device || retainedInode != inode {
		return "", errIdentityDrift
	}
	for range 32 {
		name, err := findRetainedDirectory(parentFD, preferred, device, inode)
		if err != nil {
			return "", err
		}
		private, err := randomTombName(parentFD)
		if err != nil {
			return "", err
		}
		if err := renameatxNp(parentFD, name, parentFD, private, unix.RENAME_EXCL); err != nil {
			return "", err
		}
		descriptor := workspaceSnapshotDescriptor{snapshotDev: device, snapshotIno: inode}
		if err := verifyTombIdentity(parentFD, private, retainedFD, descriptor); err == nil {
			return private, nil
		}
		preferred = ""
	}
	return "", errIdentityDrift
}

func findRetainedDirectory(parentFD int, preferred string, device, inode uint64) (string, error) {
	if preferred != "" {
		var stat unix.Stat_t
		err := unix.Fstatat(parentFD, preferred, &stat, unix.AT_SYMLINK_NOFOLLOW)
		if err == nil && stat.Mode&unix.S_IFMT == unix.S_IFDIR && uint64(stat.Dev) == device && uint64(stat.Ino) == inode {
			return preferred, nil
		}
		if err != nil && !errors.Is(err, unix.ENOENT) {
			return "", err
		}
	}
	names, err := directoryNames(parentFD)
	if err != nil {
		return "", err
	}
	for _, name := range names {
		var stat unix.Stat_t
		err := unix.Fstatat(parentFD, name, &stat, unix.AT_SYMLINK_NOFOLLOW)
		if err != nil {
			if errors.Is(err, unix.ENOENT) {
				continue
			}
			return "", err
		}
		if stat.Mode&unix.S_IFMT == unix.S_IFDIR && uint64(stat.Dev) == device && uint64(stat.Ino) == inode {
			return name, nil
		}
	}
	return "", errIdentityDrift
}

func validateFiles(files []ports.WorkspaceSnapshotFile) error {
	folded := make(map[string]string, len(files))
	previous := ""
	for _, file := range files {
		value := file.Path().String()
		if value == manifestName || value == ".git" || value == ".mulgae" || strings.HasPrefix(value, ".git/") || strings.HasPrefix(value, ".mulgae/") {
			return fmt.Errorf("workspace snapshot: reserved path %q", value)
		}
		for _, part := range strings.Split(value, "/") {
			if part == ".git" || part == ".mulgae" {
				return fmt.Errorf("workspace snapshot: reserved path %q", value)
			}
		}
		if previous != "" && strings.HasPrefix(value, previous+"/") {
			return fmt.Errorf("workspace snapshot: file-directory collision %q and %q", previous, value)
		}
		previous = value
		key := strings.ToLower(value)
		if prior, ok := folded[key]; ok {
			return fmt.Errorf("workspace snapshot: case-fold collision %q and %q", prior, value)
		}
		folded[key] = value
	}
	return nil
}

func openRoot(root ports.AnchoredRoot) (int, error) {
	return unix.Open(root.String(), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
}
func fdIdentity(fd int) (uint64, uint64, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return 0, 0, err
	}
	return uint64(stat.Dev), uint64(stat.Ino), nil
}
func digest(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}
func randomSnapshotName(rootFD int) (string, error) {
	for range 32 {
		bytes := make([]byte, 16)
		if _, err := rand.Read(bytes); err != nil {
			return "", err
		}
		name := "snapshot-" + hex.EncodeToString(bytes)
		var stat unix.Stat_t
		err := unix.Fstatat(rootFD, name, &stat, unix.AT_SYMLINK_NOFOLLOW)
		if errors.Is(err, unix.ENOENT) {
			return name, nil
		}
		if err != nil {
			return "", err
		}
	}
	return "", fmt.Errorf("workspace snapshot: cannot allocate destination")
}
func randomTombName(rootFD int) (string, error) {
	for range 32 {
		bytes := make([]byte, 16)
		if _, err := rand.Read(bytes); err != nil {
			return "", err
		}
		name := ".snapshot-tomb-" + hex.EncodeToString(bytes)
		var stat unix.Stat_t
		err := unix.Fstatat(rootFD, name, &stat, unix.AT_SYMLINK_NOFOLLOW)
		if errors.Is(err, unix.ENOENT) {
			return name, nil
		}
		if err != nil {
			return "", err
		}
	}
	return "", fmt.Errorf("workspace snapshot: cannot allocate tomb")
}

func writeFile(snapshotFD int, directory, base string, data []byte, directories map[string]struct{}, close func(int) error) (err error) {
	dirFD, err := openDirectory(snapshotFD, directory, true, directories, close)
	if err != nil {
		return err
	}
	defer func() {
		err = closeDescriptor(err, close, dirFD)
	}()
	fd, err := unix.Openat(dirFD, base, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return fmt.Errorf("workspace create file %q: %w", base, err)
	}
	for data := data; len(data) > 0; {
		n, writeErr := unix.Write(fd, data)
		if writeErr != nil {
			return closeDescriptor(writeErr, close, fd)
		}
		data = data[n:]
	}
	if err := unix.Fsync(fd); err != nil {
		return closeDescriptor(err, close, fd)
	}
	if err := unix.Fchmod(fd, 0444); err != nil {
		return closeDescriptor(err, close, fd)
	}
	return closeDescriptor(nil, close, fd)
}

func openDirectory(rootFD int, relative string, create bool, directories map[string]struct{}, close func(int) error) (fd int, err error) {
	fd, err = unix.Dup(rootFD)
	if err != nil {
		return 0, err
	}
	if relative == "" {
		return fd, nil
	}
	current := ""
	for _, part := range strings.Split(relative, "/") {
		if current == "" {
			current = part
		} else {
			current += "/" + part
		}
		next, openErr := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if errors.Is(openErr, unix.ENOENT) && create {
			openErr = unix.Mkdirat(fd, part, 0700)
			if openErr == nil {
				next, openErr = unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			}
		}
		closeErr := closeDescriptor(openErr, close, fd)
		if closeErr != nil {
			if next >= 0 {
				closeErr = closeDescriptor(closeErr, close, next)
			}
			return 0, closeErr
		}
		if openErr != nil {
			return 0, openErr
		}
		fd = next
		directories[current] = struct{}{}
	}
	return fd, nil
}

func sealDirectories(rootFD int, directories map[string]struct{}, close func(int) error) error {
	for directory := range directories {
		fd, err := openDirectory(rootFD, directory, false, directories, close)
		if err != nil {
			return err
		}
		err = unix.Fchmod(fd, 0555)
		if err = closeDescriptor(err, close, fd); err != nil {
			return err
		}
	}
	return nil
}

type manifestFile struct {
	Path               string `json:"path"`
	Size               int64  `json:"size"`
	SHA256             string `json:"sha256"`
	MediaType          string `json:"media_type"`
	CaptureDisposition string `json:"capture_disposition"`
	Mode               uint32 `json:"mode"`
	Links              uint64 `json:"links"`
}
type manifestDirectory struct {
	Path  string `json:"path"`
	Mode  uint32 `json:"mode"`
	Links uint64 `json:"links"`
}
type manifestDocument struct {
	Version        string              `json:"version"`
	PolicyIdentity string              `json:"policy_identity"`
	Directories    []manifestDirectory `json:"directories"`
	Files          []manifestFile      `json:"files"`
	RootDevice     uint64              `json:"root_device"`
	RootInode      uint64              `json:"root_inode"`
	SnapshotDevice uint64              `json:"snapshot_device"`
	SnapshotInode  uint64              `json:"snapshot_inode"`
}

func canonicalManifest(policy string, files []ports.WorkspaceSnapshotFile, rootDevice, rootInode, snapshotDevice, snapshotInode uint64) ([]byte, error) {
	entries := make([]manifestFile, len(files))
	directories := map[string]struct{}{"": {}}
	for i, file := range files {
		disposition := "text"
		if !file.IsText() {
			disposition = "binary_preserved"
		}
		entries[i] = manifestFile{
			Path: file.Path().String(), Size: int64(len(file.Bytes())), SHA256: file.SHA256(),
			MediaType: file.MediaType(), CaptureDisposition: disposition, Mode: 0444, Links: 1,
		}
		directory := path.Dir(file.Path().String())
		for directory != "." {
			directories[directory] = struct{}{}
			directory = path.Dir(directory)
		}
	}
	names := make([]string, 0, len(directories))
	links := make(map[string]uint64, len(directories))
	for directory := range directories {
		names = append(names, directory)
		if directory != "" {
			parent := path.Dir(directory)
			if parent == "." {
				parent = ""
			}
			links[parent]++
		}
	}
	sort.Strings(names)
	directoryEntries := make([]manifestDirectory, len(names))
	for i, directory := range names {
		directoryEntries[i] = manifestDirectory{directory, 0555, links[directory] + 2}
	}
	return json.Marshal(manifestDocument{"v3", policy, directoryEntries, entries, rootDevice, rootInode, snapshotDevice, snapshotInode})
}

func readRegular(rootFD int, relative string, close func(int) error) (bytes []byte, err error) {
	directory, base := path.Split(relative)
	fd, err := openDirectory(rootFD, strings.TrimSuffix(directory, "/"), false, map[string]struct{}{}, close)
	if err != nil {
		return nil, err
	}
	defer func() {
		err = closeDescriptor(err, close, fd)
	}()
	file, err := unix.Openat(fd, base, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer func() {
		err = closeDescriptor(err, close, file)
	}()
	var stat unix.Stat_t
	if err := unix.Fstat(file, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, errIdentityDrift
	}
	return io.ReadAll(&fdReader{fd: file})
}

type fdReader struct{ fd int }

func (r *fdReader) Read(p []byte) (int, error) {
	n, err := unix.Read(r.fd, p)
	if n == 0 && err == nil {
		return 0, io.EOF
	}
	return n, err
}

func directoryNames(fd int) ([]string, error) {
	duplicate, err := unix.Dup(fd)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(duplicate), "")
	if _, err := unix.Seek(duplicate, 0, 0); err != nil {
		return nil, closeFile(err, file)
	}
	entries, err := file.ReadDir(-1)
	if err = closeFile(err, file); err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.Name() == "." || entry.Name() == ".." {
			continue
		}
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	return names, nil
}

type workspaceTreeFrame struct {
	fd               int
	parent           *workspaceTreeFrame
	name             string
	device           uint64
	inode            uint64
	names            []string
	next             int
	enumerated       bool
	enumerationClose *WorkspaceDescriptorCloseOwner
	unlinked         bool
}

type workspaceTreeCleanupOwner struct {
	root         *workspaceTreeFrame
	stack        []*workspaceTreeFrame
	close        func(int) error
	renameatxNp  func(int, string, int, string, uint32) error
	unlinkat     func(int, string, int) error
	detached     func(int, uint64, uint64) error
	beforeUnlink func(int, string)
}

func newWorkspaceTreeCleanupOwner(fd int, close func(int) error, renameatxNp func(int, string, int, string, uint32) error, unlinkat func(int, string, int) error, detached func(int, uint64, uint64) error, beforeUnlink func(int, string)) *workspaceTreeCleanupOwner {
	root := &workspaceTreeFrame{fd: fd}
	return &workspaceTreeCleanupOwner{root: root, stack: []*workspaceTreeFrame{root}, close: close, renameatxNp: renameatxNp, unlinkat: unlinkat, detached: detached, beforeUnlink: beforeUnlink}
}

func (owner *workspaceTreeCleanupOwner) Terminal() bool {
	return owner != nil && len(owner.stack) == 0
}

func (owner *workspaceTreeCleanupOwner) Retry() error {
	if owner == nil || owner.close == nil || owner.renameatxNp == nil || owner.unlinkat == nil || owner.detached == nil || len(owner.stack) == 0 && owner.root == nil {
		return fmt.Errorf("workspace cleanup tree: invalid traversal owner")
	}
	for len(owner.stack) > 0 {
		frame := owner.stack[len(owner.stack)-1]
		if frame.enumerationClose != nil {
			if err := frame.enumerationClose.Retry(); err != nil {
				return err
			}
			frame.enumerationClose = nil
		}
		if !frame.enumerated {
			if err := unix.Fchmod(frame.fd, 0700); err != nil {
				return err
			}
			names, err := directoryNames(frame.fd)
			if err != nil {
				if closeOwner, ok := WorkspaceDescriptorCloseRetryOwner(err); ok {
					frame.enumerationClose = closeOwner
				}
				return err
			}
			frame.names = names
			frame.enumerated = true
		}
		if frame.next < len(frame.names) {
			name := frame.names[frame.next]
			var stat unix.Stat_t
			if err := unix.Fstatat(frame.fd, name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
				if errors.Is(err, unix.ENOENT) {
					frame.next++
					continue
				}
				return err
			}
			if stat.Mode&unix.S_IFMT != unix.S_IFDIR {
				if err := unix.Unlinkat(frame.fd, name, 0); err != nil {
					return err
				}
				frame.next++
				continue
			}
			childFD, err := unix.Openat(frame.fd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			if err != nil {
				return err
			}
			device, inode, err := fdIdentity(childFD)
			if err != nil {
				return closeDescriptor(err, owner.close, childFD)
			}
			child := &workspaceTreeFrame{fd: childFD, parent: frame, name: name, device: device, inode: inode}
			owner.stack = append(owner.stack, child)
			continue
		}
		if frame == owner.root {
			owner.stack = owner.stack[:len(owner.stack)-1]
			continue
		}
		if !frame.unlinked {
			name, err := relocateRetainedDirectory(owner.renameatxNp, frame.parent.fd, frame.name, frame.fd, frame.device, frame.inode)
			if err != nil {
				if !errors.Is(err, errIdentityDrift) {
					return err
				}
				if detachErr := owner.detached(frame.fd, frame.device, frame.inode); detachErr != nil {
					return errors.Join(err, detachErr)
				}
				frame.unlinked = true
			} else {
				frame.name = name
				if owner.beforeUnlink != nil {
					owner.beforeUnlink(frame.parent.fd, frame.name)
				}
				descriptor := workspaceSnapshotDescriptor{snapshotDev: frame.device, snapshotIno: frame.inode}
				if err := verifyTombIdentity(frame.parent.fd, frame.name, frame.fd, descriptor); err != nil {
					return err
				}
				if err := owner.unlinkat(frame.parent.fd, frame.name, unix.AT_REMOVEDIR); err != nil {
					return err
				}
				if err := owner.detached(frame.fd, frame.device, frame.inode); err != nil {
					return err
				}
				frame.unlinked = true
			}
		}
		if !frame.unlinked {
			return fmt.Errorf("workspace cleanup tree: child unlink did not detach descriptor")
		}
		if err := closeDescriptor(nil, owner.close, frame.fd); err != nil {
			return err
		}
		frame.parent.names = nil
		frame.parent.next = 0
		frame.parent.enumerated = false
		owner.stack = owner.stack[:len(owner.stack)-1]
	}
	return nil
}
