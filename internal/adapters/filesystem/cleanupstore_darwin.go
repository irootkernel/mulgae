//go:build darwin && arm64

package filesystem

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/irootkernel/kkachi-agent-review/internal/app/clean"
	"github.com/irootkernel/kkachi-agent-review/internal/domain"
	"github.com/irootkernel/kkachi-agent-review/internal/ports"
	"golang.org/x/sys/unix"
)

const (
	cleanupPlanDirectory = "store/clean/plans"
	cleanupTombDirectory = "store/clean/tombstones"
	cleanupMaximumBytes  = int64(32 << 20)
)

// CleanupStore is the durable, root-confined implementation of clean.ApplyStore.
// The caller owns policy resolution; this adapter owns only observation and effects.
type CleanupStore struct {
	root        ports.AnchoredRoot
	publication *PublicationStore
	policy      clean.Policy
	policyHash  string
	clock       ports.Clock
	operations  secureWriterOperations
}

var _ clean.ApplyStore = (*CleanupStore)(nil)

func NewCleanupStore(root ports.AnchoredRoot, publication *PublicationStore, policy clean.Policy, policySHA256 string, clock ports.Clock) (*CleanupStore, error) {
	if !root.Valid() || publication == nil || clock == nil {
		return nil, errors.New("cleanup store: root, publication authority, and clock are required")
	}
	if err := publication.valid(); err != nil {
		return nil, fmt.Errorf("cleanup store: publication authority: %w", err)
	}
	if !cleanupSHA256(policySHA256) || policy.RetentionAgeSeconds < 0 || policy.MinAgeForSizeSeconds < 0 || policy.TargetBytes < 0 {
		return nil, errors.New("cleanup store: invalid resolved retention policy")
	}
	seen := map[string]bool{}
	for _, id := range policy.ExplicitKeepRunIDs {
		if _, err := domain.ParseRunID(id); err != nil || seen[id] {
			return nil, errors.New("cleanup store: invalid explicit keep run ID")
		}
		seen[id] = true
	}
	policy.ExplicitKeepRunIDs = append([]string(nil), policy.ExplicitKeepRunIDs...)
	return &CleanupStore{root: root, publication: publication, policy: policy, policyHash: policySHA256, clock: clock, operations: defaultSecureWriterOperations()}, nil
}

// RetentionPolicy returns this store's explicitly configured policy authority.
func (store *CleanupStore) RetentionPolicy(ctx context.Context) (clean.Policy, string, error) {
	if store == nil {
		return clean.Policy{}, "", errors.New("cleanup store: nil store")
	}
	if err := ctx.Err(); err != nil {
		return clean.Policy{}, "", err
	}
	return cloneCleanupPolicy(store.policy), store.policyHash, nil
}

// WithCleanupTransaction uses PublicationStore's authoritative lock namespace.
func (store *CleanupStore) WithCleanupTransaction(ctx context.Context, callback func(clean.CleanupTransaction) error) error {
	if store == nil || store.publication == nil || callback == nil {
		return errors.New("cleanup store: publication authority and transaction callback are required")
	}
	return store.publication.withLock(ctx, store.root, func() error {
		return callback(cleanupTransaction{store})
	})
}

type cleanupTransaction struct{ *CleanupStore }

func (transaction cleanupTransaction) Snapshot(ctx context.Context) (clean.RetentionSnapshot, error) {
	return transaction.CleanupStore.snapshotLocked(ctx)
}
func (transaction cleanupTransaction) PersistDryRunPlan(ctx context.Context, plan clean.CleanPlan) error {
	return transaction.CleanupStore.persistDryRunPlan(ctx, plan)
}

// PersistDryRunPlan commits an immutable canonical dry-run receipt by hash.
func (store *CleanupStore) PersistDryRunPlan(ctx context.Context, plan clean.CleanPlan) error {
	if store == nil {
		return errors.New("cleanup store: nil store")
	}
	return store.WithCleanupTransaction(ctx, func(transaction clean.CleanupTransaction) error {
		return transaction.PersistDryRunPlan(ctx, plan)
	})
}

// PersistDryRunPlan implements clean.CleanupTransaction and must be called
// while the transaction lock is held.
func (store *CleanupStore) persistDryRunPlan(ctx context.Context, plan clean.CleanPlan) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if plan.SchemaVersion != clean.SchemaVersion || plan.Mode != "dry_run" || plan.ApplyIdentity != nil || !cleanupSHA256(plan.PlanHash) {
		return errors.New("cleanup store: invalid dry-run plan")
	}
	hash, err := clean.PlanHash(plan)
	if err != nil || hash != plan.PlanHash {
		return errors.New("cleanup store: dry-run plan hash mismatch")
	}
	data, err := json.Marshal(plan)
	if err != nil {
		return err
	}
	return store.writeImmutable(filepath.Join(cleanupPlanDirectory, strings.TrimPrefix(hash, "sha256:")+".json"), data)
}

func (store *CleanupStore) Snapshot(ctx context.Context) (clean.RetentionSnapshot, error) {
	if store == nil || store.publication == nil {
		return clean.RetentionSnapshot{}, errors.New("cleanup store: publication authority is required")
	}
	var snapshot clean.RetentionSnapshot
	err := store.publication.withLock(ctx, store.root, func() error {
		var err error
		snapshot, err = store.snapshotLocked(ctx)
		return err
	})
	return snapshot, err
}

func (store *CleanupStore) snapshotLocked(ctx context.Context) (clean.RetentionSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return clean.RetentionSnapshot{}, err
	}
	runs, edges, material, err := store.observeLocked(ctx)
	if err != nil {
		return clean.RetentionSnapshot{}, err
	}
	digest := sha256.Sum256(material)
	value := int64(uint64(digest[0])<<56|uint64(digest[1])<<48|uint64(digest[2])<<40|uint64(digest[3])<<32|uint64(digest[4])<<24|uint64(digest[5])<<16|uint64(digest[6])<<8|uint64(digest[7])) & 0x7fffffffffffffff
	if value == 0 {
		value = 1
	}
	return clean.RetentionSnapshot{Now: store.clock.Now().UTC(), StoreEpoch: clean.StoreEpoch{Value: value, SHA256: "sha256:" + hex.EncodeToString(digest[:])}, InputPolicySHA256: store.policyHash, Policy: cloneCleanupPolicy(store.policy), Runs: runs, Edges: edges}, nil
}

func (store *CleanupStore) DryRunPlan(ctx context.Context, hash string) (clean.CleanPlan, error) {
	if err := ctx.Err(); err != nil {
		return clean.CleanPlan{}, err
	}
	if !cleanupSHA256(hash) {
		return clean.CleanPlan{}, errors.New("cleanup store: invalid plan hash")
	}
	data, err := store.readRegular(filepath.Join(cleanupPlanDirectory, strings.TrimPrefix(hash, "sha256:")+".json"))
	if err != nil {
		return clean.CleanPlan{}, err
	}
	var plan clean.CleanPlan
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&plan); err != nil {
		return clean.CleanPlan{}, fmt.Errorf("cleanup store: decode persisted plan: %w", err)
	}
	if plan.SchemaVersion != clean.SchemaVersion || plan.Mode != "dry_run" || plan.ApplyIdentity != nil || plan.PlanHash != hash {
		return clean.CleanPlan{}, errors.New("cleanup store: invalid persisted plan")
	}
	computed, err := clean.PlanHash(plan)
	if err != nil || computed != hash {
		return clean.CleanPlan{}, errors.New("cleanup store: persisted plan hash mismatch")
	}
	return plan.Clone(), nil
}

func (store *CleanupStore) Tombstones(ctx context.Context) ([]clean.Tombstone, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	dir, err := walkPrivateDirectory(store.root, []string{"store", "clean", "tombstones"}, false)
	if errors.Is(err, unix.ENOENT) {
		return []clean.Tombstone{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer closeFD(dir)
	entries, err := cleanupDirNames(dir)
	if err != nil {
		return nil, err
	}
	out := make([]clean.Tombstone, 0, len(entries))
	for _, name := range entries {
		data, err := cleanupReadRegularAt(dir, name)
		if err != nil {
			return nil, err
		}
		tombstone, err := decodeCleanupTombstone(data)
		if err != nil {
			return nil, err
		}
		if name != cleanupTombstoneName(tombstone) {
			return nil, errors.New("cleanup store: tombstone filename does not match body")
		}
		out = append(out, tombstone)
	}
	return out, nil
}

func (store *CleanupStore) Tombstone(ctx context.Context, tombstone clean.Tombstone) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !cleanupTombstone(tombstone) {
		return errors.New("cleanup store: invalid tombstone")
	}
	data, err := json.Marshal(tombstone)
	if err != nil {
		return err
	}
	return store.writeImmutable(filepath.Join(cleanupTombDirectory, cleanupTombstoneName(tombstone)), data)
}

func (store *CleanupStore) DeleteTombstoned(ctx context.Context, tombstone clean.Tombstone) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !cleanupTombstone(tombstone) {
		return errors.New("cleanup store: invalid tombstone")
	}
	name := cleanupTombstoneName(tombstone)
	directory, err := walkPrivateDirectory(store.root, []string{"store", "clean", "tombstones"}, false)
	if err != nil {
		return fmt.Errorf("cleanup store: open tombstone directory: %w", err)
	}
	defer closeFD(directory)
	data, err := cleanupReadRegularAt(directory, name)
	if err != nil {
		return fmt.Errorf("cleanup store: tombstone absent: %w", err)
	}
	persisted, err := decodeCleanupTombstone(data)
	if err != nil {
		return err
	}
	if persisted != tombstone {
		return errors.New("cleanup store: tombstone body does not match deletion request")
	}
	directoryID, err := privateDirectoryIdentityForFD(directory)
	if err != nil {
		return fmt.Errorf("cleanup store: tombstone directory identity: %w", err)
	}
	if err := store.deleteRun(tombstone.RunID); err != nil {
		return err
	}
	if err := revalidatePrivateDirectory(store.root, []string{"store", "clean", "tombstones"}, directoryID, defaultSecureWriterOperations()); err != nil {
		return fmt.Errorf("cleanup store: tombstone directory changed before removal: %w", err)
	}
	if err := unix.Unlinkat(directory, name, 0); err != nil && !errors.Is(err, unix.ENOENT) {
		return err
	}
	return unix.Fsync(directory)
}

func (store *CleanupStore) observeLocked(ctx context.Context) ([]clean.RunObservation, []clean.LineageEdgeObservation, []byte, error) {
	entries, err := os.ReadDir(store.root.String())
	if err != nil {
		return nil, nil, nil, err
	}
	var runs []clean.RunObservation
	var edges []clean.LineageEdgeObservation
	hashInput := make([]byte, 0)
	for _, session := range entries {
		if !strings.HasPrefix(session.Name(), "s_") {
			continue
		}
		sessionID, err := domain.ParseSessionID(session.Name())
		if err != nil {
			continue
		}
		sessionPath := filepath.Join(store.root.String(), session.Name())
		si, err := os.Lstat(sessionPath)
		if err != nil || !si.IsDir() || si.Mode()&os.ModeSymlink != 0 {
			continue
		}
		children, err := os.ReadDir(sessionPath)
		if err != nil {
			return nil, nil, nil, err
		}
		for _, child := range children {
			if !strings.HasPrefix(child.Name(), "r_") {
				continue
			}
			runID, err := domain.ParseRunID(child.Name())
			if err != nil {
				continue
			}
			runPath := filepath.Join(sessionPath, child.Name())
			info, err := os.Lstat(runPath)
			observation := clean.RunObservation{RunID: child.Name(), SessionID: session.Name(), Corrupt: err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0}
			material := []byte(session.Name() + "/" + child.Name() + "\x00")
			if !observation.Corrupt {
				observation.RegularFileBytes, err = lstatTreeBytes(runPath)
				if err != nil {
					observation.Corrupt = true
				} else {
					run, runErr := ports.NewPublicationRun(store.root, sessionID, runID)
					request, requestErr := ports.NewObserveRunRequest(run, cleanupMaximumBytes)
					if runErr != nil || requestErr != nil {
						observation.Corrupt = true
					} else {
						publication, snapshot, observeErr := store.publication.observeLocked(ctx, request)
						if observeErr != nil || publication.ClassifierInput().Observation() != domain.DurableObservationP2Committed || snapshot == nil || !snapshot.Valid() {
							observation.Corrupt = true
						} else {
							final := snapshot.Final()
							manifest := snapshot.Manifest()
							lineage := snapshot.LineageEdge()
							epoch := snapshot.Epoch().Record()
							completedAt, completed := authoritativeCompletion(manifest.Bytes())
							if !completed {
								observation.Corrupt = true
							} else {
								material = append(material, final.Bytes()...)
								material = append(material, manifest.Bytes()...)
								material = append(material, lineage.Bytes()...)
								material = append(material, epoch.Bytes()...)
								observation.Completed = true
								observation.CompletedAt = completedAt
								observation.Committed = true
								if parent, ok := authoritativeLineageParent(lineage.Bytes(), child.Name()); ok {
									edges = append(edges, clean.LineageEdgeObservation{
										LineageEdgeRef: clean.LineageEdgeRef{ParentRunID: parent, ChildRunID: child.Name(), EdgePath: lineage.Path().String(), SHA256: lineage.SHA256()},
										Valid:          true,
									})
								}
							}
						}
					}
				}
			}
			observation.Active = !observation.Completed
			material = append(material, []byte(fmt.Sprintf("\x00%t:%t:%t:%t:%d\n", observation.Completed, observation.Active, observation.Committed, observation.Corrupt, observation.RegularFileBytes))...)
			hashInput = append(hashInput, material...)
			runs = append(runs, observation)
		}
	}
	sort.Slice(runs, func(i, j int) bool { return runs[i].RunID < runs[j].RunID })
	sort.Slice(edges, func(i, j int) bool { return edges[i].ChildRunID < edges[j].ChildRunID })
	return runs, edges, hashInput, nil
}

func authoritativeCompletion(data []byte) (*time.Time, bool) {
	var manifest struct {
		State       string  `json:"state"`
		CompletedAt *string `json:"completed_at"`
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	if err := decoder.Decode(&manifest); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return nil, false
	}
	switch manifest.State {
	case "completed", "degraded", "failed":
	default:
		return nil, false
	}
	if manifest.CompletedAt == nil {
		return nil, false
	}
	completedAt, err := time.Parse(time.RFC3339Nano, *manifest.CompletedAt)
	if err != nil || completedAt.UTC().Format(time.RFC3339Nano) != *manifest.CompletedAt {
		return nil, false
	}
	return &completedAt, true
}
func authoritativeLineageParent(data []byte, child string) (string, bool) {
	var edge struct {
		Child struct {
			RunID string `json:"run_id"`
		} `json:"child"`
		ParentRunID string `json:"parent_run_id"`
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	if err := decoder.Decode(&edge); err != nil || decoder.Decode(&struct{}{}) != io.EOF || edge.Child.RunID != child {
		return "", false
	}
	if _, err := domain.ParseRunID(edge.ParentRunID); err != nil {
		return "", false
	}
	return edge.ParentRunID, true
}
func lstatTreeBytes(root string) (int64, error) {
	var total int64
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("symlink in run")
		}
		if info.Mode().IsRegular() {
			if info.Size() > cleanupMaximumBytes-total {
				return errors.New("run byte overflow")
			}
			total += info.Size()
		}
		return nil
	})
	return total, err
}
func (store *CleanupStore) deleteRun(id string) error {
	rootFD, err := unix.Open(store.root.String(), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("cleanup store: open artifact root: %w", err)
	}
	defer unix.Close(rootFD)
	names, err := cleanupDirNames(rootFD)
	if err != nil {
		return err
	}
	sessionName := ""
	for _, name := range names {
		if _, err := domain.ParseSessionID(name); err != nil {
			continue
		}
		var stat unix.Stat_t
		if err := unix.Fstatat(rootFD, name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR {
			continue
		}
		sessionFD, err := unix.Openat(rootFD, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			continue
		}
		err = unix.Fstatat(sessionFD, id, &stat, unix.AT_SYMLINK_NOFOLLOW)
		unix.Close(sessionFD)
		if err == nil && stat.Mode&unix.S_IFMT == unix.S_IFDIR {
			if sessionName != "" {
				return errors.New("cleanup store: duplicate canonical run ID")
			}
			sessionName = name
		}
	}
	if sessionName == "" {
		return nil
	}
	sessionFD, err := unix.Openat(rootFD, sessionName, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("cleanup store: reopen session: %w", err)
	}
	defer unix.Close(sessionFD)
	if err := cleanupRemoveTreeAt(sessionFD, id); err != nil {
		return fmt.Errorf("cleanup store: remove run: %w", err)
	}
	if err := unix.Fsync(sessionFD); err != nil {
		return fmt.Errorf("cleanup store: sync run parent: %w", err)
	}
	return nil
}

func cleanupDirNames(fd int) ([]string, error) {
	dup, err := unix.Dup(fd)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(dup), "cleanup directory")
	defer file.Close()
	return file.Readdirnames(-1)
}

func cleanupRemoveTreeAt(parentFD int, name string) error {
	var stat unix.Stat_t
	if err := unix.Fstatat(parentFD, name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return errors.New("unsafe deletion target")
	}
	fd, err := unix.Openat(parentFD, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	names, err := cleanupDirNames(fd)
	if err == nil {
		for _, child := range names {
			if child == "." || child == ".." {
				continue
			}
			var childStat unix.Stat_t
			if err = unix.Fstatat(fd, child, &childStat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
				break
			}
			if childStat.Mode&unix.S_IFMT == unix.S_IFDIR {
				err = cleanupRemoveTreeAt(fd, child)
			} else {
				err = unix.Unlinkat(fd, child, 0)
			}
			if err != nil {
				break
			}
		}
	}
	if closeErr := unix.Close(fd); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return unix.Unlinkat(parentFD, name, unix.AT_REMOVEDIR)
}
func (store *CleanupStore) readRegular(relative string) ([]byte, error) {
	parts, name, err := cleanupImmutablePath(relative)
	if err != nil {
		return nil, err
	}
	directory, err := walkPrivateDirectory(store.root, parts, false)
	if err != nil {
		return nil, err
	}
	defer closeFD(directory)
	return cleanupReadRegularAt(directory, name)
}

func cleanupReadRegularAt(directory int, name string) ([]byte, error) {
	if name == "" || name == "." || name == ".." || strings.ContainsRune(name, 0) || strings.Contains(name, "/") {
		return nil, errors.New("cleanup store: invalid immutable file name")
	}
	var expected unix.Stat_t
	if err := unix.Fstatat(directory, name, &expected, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return nil, err
	}
	if expected.Mode&unix.S_IFMT != unix.S_IFREG || expected.Size < 0 || expected.Size > cleanupMaximumBytes {
		return nil, errors.New("unsafe regular file")
	}
	fd, err := unix.Openat(directory, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "cleanup immutable file")
	defer file.Close()
	var actual unix.Stat_t
	if err := unix.Fstat(fd, &actual); err != nil {
		return nil, err
	}
	if actual.Mode&unix.S_IFMT != unix.S_IFREG || actual.Dev != expected.Dev || actual.Ino != expected.Ino || actual.Size != expected.Size {
		return nil, errors.New("unsafe regular file")
	}
	data, err := io.ReadAll(io.LimitReader(file, cleanupMaximumBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) != expected.Size {
		return nil, errors.New("unsafe regular file")
	}
	if err := unix.Fstat(fd, &actual); err != nil {
		return nil, err
	}
	if actual.Mode&unix.S_IFMT != unix.S_IFREG || actual.Dev != expected.Dev || actual.Ino != expected.Ino || actual.Size != expected.Size {
		return nil, errors.New("unsafe regular file")
	}
	return data, nil
}
func (store *CleanupStore) writeImmutable(relative string, data []byte) (result error) {
	if int64(len(data)) > cleanupMaximumBytes {
		return errors.New("cleanup store: immutable content exceeds maximum size")
	}
	parts, name, err := cleanupImmutablePath(relative)
	if err != nil {
		return err
	}
	rootFD, err := openAnchoredRoot(store.root)
	if err != nil {
		return err
	}
	rootID, err := privateDirectoryIdentityForFD(rootFD)
	closeErr := unix.Close(rootFD)
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	directory, err := walkPrivateDirectory(store.root, parts, true)
	if err != nil {
		return err
	}
	defer closeFD(directory)
	directoryID, err := privateDirectoryIdentityForFD(directory)
	if err != nil {
		return err
	}
	if _, err := cleanupReadRegularAt(directory, name); err == nil {
		return cleanupVerifyImmutable(directory, name, data, store.root, parts, rootID, directoryID, store.operations)
	} else if !errors.Is(err, unix.ENOENT) {
		return err
	}

	operations := store.operations.withDefaults()
	temporaryFD, temporaryName, err := createPrivateTempFile(operations, directory)
	if err != nil {
		return err
	}
	defer func() {
		if temporaryName == "" {
			closeFD(temporaryFD)
			return
		}
		cleanupErr := purgeTemporaryFile(operations, directory, &temporaryFD, &temporaryName)
		if result == nil {
			result = cleanupErr
		} else if cleanupErr != nil {
			result = errors.Join(result, cleanupErr)
		}
	}()
	if err := writeAll(temporaryFD, data); err != nil {
		return fmt.Errorf("cleanup store: write immutable temporary: %w", err)
	}
	if err := unix.Fsync(temporaryFD); err != nil {
		return fmt.Errorf("cleanup store: sync immutable temporary: %w", err)
	}
	temporaryID, err := secureFileIdentityForFD(temporaryFD)
	if err != nil {
		return fmt.Errorf("cleanup store: immutable temporary identity: %w", err)
	}
	if err := errors.Join(
		revalidatePrivateDirectory(store.root, nil, rootID, operations),
		revalidatePrivateDirectory(store.root, parts, directoryID, operations),
		validateSecureFileAt(directory, temporaryName, temporaryID),
	); err != nil {
		return fmt.Errorf("cleanup store: immutable namespace changed before install: %w", err)
	}
	if err := operations.renameatxNp(directory, temporaryName, directory, name, unix.RENAME_EXCL); err != nil {
		if !errors.Is(err, unix.EEXIST) {
			return fmt.Errorf("cleanup store: install immutable file: %w", err)
		}
		return cleanupVerifyImmutable(directory, name, data, store.root, parts, rootID, directoryID, operations)
	}
	temporaryName = ""
	if err := operations.close(temporaryFD); err != nil {
		return err
	}
	temporaryFD = -1
	return cleanupVerifyImmutable(directory, name, data, store.root, parts, rootID, directoryID, operations)
}

func cleanupVerifyImmutable(
	directory int,
	name string,
	data []byte,
	root ports.AnchoredRoot,
	parts []string,
	rootID privateDirectoryIdentity,
	directoryID privateDirectoryIdentity,
	operations secureWriterOperations,
) error {
	operations = operations.withDefaults()
	if err := errors.Join(
		revalidatePrivateDirectory(root, nil, rootID, operations),
		revalidatePrivateDirectory(root, parts, directoryID, operations),
	); err != nil {
		return fmt.Errorf("cleanup store: immutable namespace changed before directory sync: %w", err)
	}
	if err := operations.fsync(directory); err != nil {
		return fmt.Errorf("cleanup store: sync immutable directory: %w", err)
	}
	if err := errors.Join(
		revalidatePrivateDirectory(root, nil, rootID, operations),
		revalidatePrivateDirectory(root, parts, directoryID, operations),
	); err != nil {
		return fmt.Errorf("cleanup store: immutable namespace changed after directory sync: %w", err)
	}
	installed, err := cleanupReadRegularAt(directory, name)
	if err != nil {
		return err
	}
	if string(installed) != string(data) {
		return errors.New("cleanup store: immutable installed content changed")
	}
	return nil
}

func cleanupImmutablePath(relative string) ([]string, string, error) {
	components := strings.Split(relative, "/")
	if len(components) < 2 {
		return nil, "", errors.New("cleanup store: invalid immutable path")
	}
	for _, component := range components {
		if component == "" || component == "." || component == ".." || strings.ContainsRune(component, 0) {
			return nil, "", errors.New("cleanup store: invalid immutable path")
		}
	}
	return components[:len(components)-1], components[len(components)-1], nil
}

func cleanupSHA256(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(value) != 71 {
		return false
	}
	_, err := hex.DecodeString(value[7:])
	return err == nil && value == strings.ToLower(value)
}
func cleanupTombstone(t clean.Tombstone) bool {
	_, err := domain.ParseRunID(t.RunID)
	return err == nil && cleanupSHA256(t.PlanHash)
}

func cleanupTombstoneName(t clean.Tombstone) string {
	return t.RunID + "." + strings.TrimPrefix(t.PlanHash, "sha256:") + ".json"
}

func decodeCleanupTombstone(data []byte) (clean.Tombstone, error) {
	var tombstone clean.Tombstone
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&tombstone); err != nil || decoder.Decode(&struct{}{}) != io.EOF || !cleanupTombstone(tombstone) {
		return clean.Tombstone{}, errors.New("cleanup store: corrupt tombstone")
	}
	return tombstone, nil
}
func cloneCleanupPolicy(p clean.Policy) clean.Policy {
	p.ExplicitKeepRunIDs = append([]string{}, p.ExplicitKeepRunIDs...)
	return p
}
