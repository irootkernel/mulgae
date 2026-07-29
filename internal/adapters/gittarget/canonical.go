//go:build darwin && arm64

package gittarget

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/irootkernel/mulgae/internal/ports"
)

const (
	captureFormatVersion                   uint16 = 1
	maxCanonicalGitMetadataBytes                  = 16 << 20
	maxCanonicalGitMetadataEntries                = 4096
	maxCanonicalGitMetadataDepth                  = 64
	maxCanonicalGitMetadataPathBytes              = 4096
	canonicalGitMetadataDirectoryBatchSize        = 128
)

type canonicalRepository struct {
	gitDir       string
	repositoryID string
}

func newCanonicalRepository(root ports.AnchoredRoot, references ...string) (canonicalRepository, func() error, error) {
	directories, err := openCanonicalGitDirectorySet(root.String())
	if err != nil {
		return canonicalRepository{}, nil, err
	}

	gitDir, err := os.MkdirTemp("", "mulgae-git-")
	if err != nil {
		err = fmt.Errorf("Git canonical admin directory: %w", err)
		err = joinCanonicalConstructionCleanup(err, "close Git metadata descriptors", directories.source.close)
		return canonicalRepository{}, nil, err
	}
	cleanup := func() error {
		return os.RemoveAll(gitDir)
	}
	if err := initializeCanonicalGitDirectory(gitDir, directories, references); err != nil {
		err = joinCanonicalConstructionCleanup(err, "cleanup canonical repository", cleanup)
		err = joinCanonicalConstructionCleanup(err, "close Git metadata descriptors", directories.source.close)
		return canonicalRepository{}, nil, err
	}
	if err := directories.source.close(); err != nil {
		err = fmt.Errorf("close Git metadata descriptors: %w", err)
		err = joinCanonicalConstructionCleanup(err, "cleanup canonical repository", cleanup)
		return canonicalRepository{}, nil, err
	}
	return canonicalRepository{
		gitDir:       gitDir,
		repositoryID: canonicalRepositoryID(directories.common.path),
	}, cleanup, nil
}

// newCanonicalObjectRepository builds the minimal immutable-object context used
// for exact OID reads. It deliberately does not snapshot mutable references.
func newCanonicalObjectRepository(root ports.AnchoredRoot, objectID ports.GitObjectID) (canonicalRepository, func() error, error) {
	directories, err := openCanonicalGitDirectorySet(root.String())
	if err != nil {
		return canonicalRepository{}, nil, err
	}
	if err := directories.source.verify(); err != nil {
		err = joinCanonicalConstructionCleanup(err, "close Git metadata descriptors", directories.source.close)
		return canonicalRepository{}, nil, err
	}

	objectFormat, err := canonicalObjectFormatForObjectID(objectID)
	if err != nil {
		err = joinCanonicalConstructionCleanup(err, "close Git metadata descriptors", directories.source.close)
		return canonicalRepository{}, nil, err
	}
	gitDir, err := os.MkdirTemp("", "mulgae-git-")
	if err != nil {
		err = fmt.Errorf("Git canonical admin directory: %w", err)
		err = joinCanonicalConstructionCleanup(err, "close Git metadata descriptors", directories.source.close)
		return canonicalRepository{}, nil, err
	}
	cleanup := func() error {
		return os.RemoveAll(gitDir)
	}
	if err := initializeCanonicalObjectDirectory(gitDir, directories.objects.path, objectFormat); err != nil {
		err = joinCanonicalConstructionCleanup(err, "cleanup canonical repository", cleanup)
		err = joinCanonicalConstructionCleanup(err, "close Git metadata descriptors", directories.source.close)
		return canonicalRepository{}, nil, err
	}
	if err := os.MkdirAll(filepath.Join(gitDir, "refs", "heads"), 0o700); err != nil {
		err = fmt.Errorf("Git canonical refs directory: %w", err)
		err = joinCanonicalConstructionCleanup(err, "cleanup canonical repository", cleanup)
		err = joinCanonicalConstructionCleanup(err, "close Git metadata descriptors", directories.source.close)
		return canonicalRepository{}, nil, err
	}
	if err := writeCanonicalGitFile(filepath.Join(gitDir, "HEAD"), []byte("ref: refs/heads/mulgae-oid-only\n")); err != nil {
		err = joinCanonicalConstructionCleanup(err, "cleanup canonical repository", cleanup)
		err = joinCanonicalConstructionCleanup(err, "close Git metadata descriptors", directories.source.close)
		return canonicalRepository{}, nil, err
	}
	if err := directories.source.close(); err != nil {
		err = fmt.Errorf("close Git metadata descriptors: %w", err)
		err = joinCanonicalConstructionCleanup(err, "cleanup canonical repository", cleanup)
		return canonicalRepository{}, nil, err
	}
	return canonicalRepository{
		gitDir:       gitDir,
		repositoryID: canonicalRepositoryID(directories.common.path),
	}, cleanup, nil
}

func joinCanonicalConstructionCleanup(primary error, label string, cleanup func() error) error {
	if cleanup == nil {
		return primary
	}
	cleanupErr := cleanup()
	if cleanupErr == nil {
		return primary
	}
	wrapped := fmt.Errorf("%s: %w", label, cleanupErr)
	if primary == nil {
		return wrapped
	}
	return errors.Join(primary, wrapped)
}

func (repository canonicalRepository) command(args ...string) Command {
	commandArgs := []string{
		"--git-dir=" + repository.gitDir,
		"--no-replace-objects",
		"-c", "core.attributesFile=/dev/null",
		"-c", "core.quotePath=true",
		"-c", "color.ui=false",
		"-c", "pager.diff=false",
	}
	commandArgs = append(commandArgs, args...)
	return Command{Dir: repository.gitDir, Args: commandArgs}
}

// canonicalRepositoryID binds capture identity to the resolved common Git
// directory without consulting mutable repository configuration.
func canonicalRepositoryID(commonGitDir string) string {
	digest := sha256.Sum256([]byte("mulgae.git-admin-path/v1\x00" + commonGitDir))
	return fmt.Sprintf("git-dir-sha256:%x", digest)
}

type canonicalMetadataIdentity struct {
	device     uint64
	inode      uint64
	mode       uint16
	size       int64
	mtimeSec   int64
	mtimeNsec  int64
	ctimeSec   int64
	ctimeNsec  int64
	generation uint32
}

func (identity canonicalMetadataIdentity) sameFile(other canonicalMetadataIdentity) bool {
	return identity.device == other.device &&
		identity.inode == other.inode &&
		identity.mode == other.mode &&
		identity.size == other.size &&
		identity.mtimeSec == other.mtimeSec &&
		identity.mtimeNsec == other.mtimeNsec &&
		identity.ctimeSec == other.ctimeSec &&
		identity.ctimeNsec == other.ctimeNsec &&
		identity.generation == other.generation
}

func (identity canonicalMetadataIdentity) sameDirectory(other canonicalMetadataIdentity) bool {
	return identity.sameFile(other)
}

func (identity canonicalMetadataIdentity) sameLocation(other canonicalMetadataIdentity) bool {
	return identity.device == other.device && identity.inode == other.inode
}

type canonicalMetadataDirectory struct {
	path     string
	file     *os.File
	identity canonicalMetadataIdentity
	parent   *canonicalMetadataDirectory
	name     string
}

func (directory *canonicalMetadataDirectory) verify() error {
	if directory == nil || directory.file == nil {
		return fmt.Errorf("missing directory descriptor")
	}
	actual, err := canonicalMetadataIdentityForFile(directory.file)
	if err != nil {
		return err
	}
	if !directory.identity.sameDirectory(actual) {
		return fmt.Errorf("changed while reading")
	}
	if directory.parent != nil {
		namespaceIdentity, err := canonicalMetadataEntryAt(directory.parent, directory.name)
		if err != nil {
			return fmt.Errorf("namespace entry changed: %w", err)
		}
		if err := validateCanonicalMetadataIdentity(namespaceIdentity, true); err != nil {
			return fmt.Errorf("namespace entry changed: %w", err)
		}
		if !directory.identity.sameDirectory(namespaceIdentity) {
			return fmt.Errorf("namespace entry changed while reading")
		}
		return nil
	}
	fd, err := unix.Open(directory.path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("root namespace changed: %w", err)
	}
	reopened := os.NewFile(uintptr(fd), directory.path)
	reopenedIdentity, identityErr := canonicalMetadataIdentityForFile(reopened)
	var verificationErr error
	if identityErr != nil {
		verificationErr = fmt.Errorf("root namespace changed: %w", identityErr)
	}
	verificationErr = joinCanonicalConstructionCleanup(
		verificationErr,
		"close root namespace verification",
		reopened.Close,
	)
	if verificationErr != nil {
		return verificationErr
	}
	if !directory.identity.sameDirectory(reopenedIdentity) {
		return fmt.Errorf("root namespace changed while reading")
	}
	return nil
}

type canonicalRepositorySource struct {
	directories []*canonicalMetadataDirectory
}

func (source *canonicalRepositorySource) addDirectory(directory *canonicalMetadataDirectory) {
	if source != nil && directory != nil {
		source.directories = append(source.directories, directory)
	}
}

func (source *canonicalRepositorySource) verify() error {
	if source == nil {
		return fmt.Errorf("missing metadata source")
	}
	seen := make(map[*os.File]struct{}, len(source.directories))
	for _, directory := range source.directories {
		if directory == nil || directory.file == nil {
			return fmt.Errorf("missing directory descriptor")
		}
		if _, ok := seen[directory.file]; ok {
			continue
		}
		seen[directory.file] = struct{}{}
		if err := directory.verify(); err != nil {
			return fmt.Errorf("Git canonical metadata %q: %w", directory.path, err)
		}
	}
	return nil
}

func (source *canonicalRepositorySource) close() error {
	if source == nil {
		return nil
	}
	var closeErr error
	seen := make(map[*os.File]struct{}, len(source.directories))
	for _, directory := range source.directories {
		if directory == nil || directory.file == nil {
			continue
		}
		if _, ok := seen[directory.file]; ok {
			continue
		}
		seen[directory.file] = struct{}{}
		file := directory.file
		directory.file = nil
		if err := file.Close(); err != nil {
			closeErr = errors.Join(closeErr, fmt.Errorf("close %q: %w", directory.path, err))
		}
	}
	return closeErr
}

type canonicalGitDirectorySet struct {
	source   *canonicalRepositorySource
	worktree *canonicalMetadataDirectory
	common   *canonicalMetadataDirectory
	objects  *canonicalMetadataDirectory
}

func openCanonicalGitDirectorySet(root string) (canonicalGitDirectorySet, error) {
	source, rootDirectory, err := openCanonicalRepositoryRoot(root)
	if err != nil {
		return canonicalGitDirectorySet{}, err
	}
	fail := func(err error) (canonicalGitDirectorySet, error) {
		err = joinCanonicalConstructionCleanup(err, "close Git metadata descriptors", source.close)
		return canonicalGitDirectorySet{}, err
	}

	gitEntry, err := canonicalMetadataEntryAt(rootDirectory, ".git")
	if err != nil {
		return fail(fmt.Errorf("Git canonical admin directory: %w", err))
	}

	var worktree *canonicalMetadataDirectory
	switch gitEntry.mode & unix.S_IFMT {
	case unix.S_IFDIR:
		worktree, err = source.openDirectoryAt(rootDirectory, ".git")
	case unix.S_IFREG:
		data, readErr := readCanonicalMetadataFileAt(rootDirectory, ".git", nil)
		if readErr != nil {
			return fail(fmt.Errorf("Git canonical admin path: %w", readErr))
		}
		worktree, err = source.directoryFromFile(rootDirectory, data, "gitdir: ")
	default:
		return fail(fmt.Errorf("Git canonical admin directory is not a directory or gitdir file"))
	}
	if err != nil {
		return fail(fmt.Errorf("Git canonical admin directory: %w", err))
	}

	common := worktree
	commonEntry, err := canonicalMetadataEntryAt(worktree, "commondir")
	switch {
	case err == nil:
		if commonEntry.mode&unix.S_IFMT != unix.S_IFREG {
			return fail(fmt.Errorf("Git canonical common directory: commondir is not a regular file"))
		}
		data, readErr := readCanonicalMetadataFileAt(worktree, "commondir", nil)
		if readErr != nil {
			return fail(fmt.Errorf("Git canonical common directory: %w", readErr))
		}
		common, err = source.directoryFromFile(worktree, data, "")
		if err != nil {
			return fail(fmt.Errorf("Git canonical common directory: %w", err))
		}
	case os.IsNotExist(err):
	case err != nil:
		return fail(fmt.Errorf("Git canonical common directory: %w", err))
	}

	objects, err := source.openDirectoryAt(common, "objects")
	if err != nil {
		return fail(fmt.Errorf("Git canonical object database: %w", err))
	}
	if strings.ContainsAny(objects.path, "\x00\r\n") {
		return fail(fmt.Errorf("Git canonical object database path is unsafe"))
	}
	return canonicalGitDirectorySet{
		source:   source,
		worktree: worktree,
		common:   common,
		objects:  objects,
	}, nil
}

func canonicalGitDirectories(root string) (worktreePath string, commonPath string, resultErr error) {
	directories, err := openCanonicalGitDirectorySet(root)
	if err != nil {
		return "", "", err
	}
	defer func() {
		resultErr = joinCanonicalConstructionCleanup(
			resultErr,
			"close Git metadata descriptors",
			directories.source.close,
		)
		if resultErr != nil {
			worktreePath = ""
			commonPath = ""
		}
	}()
	if err := directories.source.verify(); err != nil {
		return "", "", err
	}
	return directories.worktree.path, directories.common.path, nil
}

func openCanonicalRepositoryRoot(root string) (*canonicalRepositorySource, *canonicalMetadataDirectory, error) {
	if err := validateCanonicalMetadataPath(root); err != nil {
		return nil, nil, err
	}
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return nil, nil, fmt.Errorf("project root is not canonical")
	}
	fd, err := unix.Open(root, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, nil, err
	}
	file := os.NewFile(uintptr(fd), root)
	identity, err := canonicalMetadataIdentityForFile(file)
	if err != nil {
		err = joinCanonicalConstructionCleanup(err, "close project root descriptor", file.Close)
		return nil, nil, err
	}
	if err := validateCanonicalMetadataIdentity(identity, true); err != nil {
		err = joinCanonicalConstructionCleanup(err, "close project root descriptor", file.Close)
		return nil, nil, err
	}
	directory := &canonicalMetadataDirectory{path: root, file: file, identity: identity}
	source := &canonicalRepositorySource{}
	source.addDirectory(directory)
	return source, directory, nil
}

func (source *canonicalRepositorySource) openDirectoryAt(parent *canonicalMetadataDirectory, name string) (*canonicalMetadataDirectory, error) {
	if err := validateCanonicalMetadataComponent(name, name == ".."); err != nil {
		return nil, err
	}
	before, err := canonicalMetadataEntryAt(parent, name)
	if err != nil {
		return nil, err
	}
	if err := validateCanonicalMetadataIdentity(before, true); err != nil {
		return nil, err
	}
	fd, err := unix.Openat(int(parent.file.Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	path := filepath.Clean(filepath.Join(parent.path, name))
	file := os.NewFile(uintptr(fd), path)
	opened, err := canonicalMetadataIdentityForFile(file)
	if err != nil {
		err = joinCanonicalConstructionCleanup(err, "close Git metadata directory", file.Close)
		return nil, err
	}
	if err := validateCanonicalMetadataIdentity(opened, true); err != nil {
		err = joinCanonicalConstructionCleanup(err, "close Git metadata directory", file.Close)
		return nil, err
	}
	if !before.sameDirectory(opened) {
		err := fmt.Errorf("changed before opening")
		err = joinCanonicalConstructionCleanup(err, "close Git metadata directory", file.Close)
		return nil, err
	}
	directory := &canonicalMetadataDirectory{
		path:     path,
		file:     file,
		identity: opened,
		parent:   parent,
		name:     name,
	}
	source.addDirectory(directory)
	return directory, nil
}

func (source *canonicalRepositorySource) directoryFromFile(base *canonicalMetadataDirectory, data []byte, prefix string) (*canonicalMetadataDirectory, error) {
	text := string(data)
	if !strings.HasSuffix(text, "\n") || strings.Count(text, "\n") != 1 || strings.ContainsAny(text, "\x00\r") {
		return nil, fmt.Errorf("Git canonical admin path is not one safe line")
	}
	value := strings.TrimSuffix(text, "\n")
	if prefix != "" {
		if !strings.HasPrefix(value, prefix) {
			return nil, fmt.Errorf("Git canonical admin path is missing %q", prefix)
		}
		value = strings.TrimPrefix(value, prefix)
	}
	if value == "" || strings.TrimSpace(value) != value || filepath.Clean(value) != value {
		return nil, fmt.Errorf("Git canonical admin path is unsafe")
	}
	if len(value) > maxCanonicalGitMetadataPathBytes {
		return nil, fmt.Errorf("Git canonical admin path exceeds %d-byte limit", maxCanonicalGitMetadataPathBytes)
	}
	relative := value
	if filepath.IsAbs(value) {
		var err error
		relative, err = filepath.Rel(base.path, value)
		if err != nil {
			return nil, fmt.Errorf("Git canonical admin path is unsafe")
		}
	}
	if relative == "." {
		return base, nil
	}
	current := base
	for _, component := range strings.Split(relative, string(filepath.Separator)) {
		if component == "" || component == "." {
			return nil, fmt.Errorf("Git canonical admin path is unsafe")
		}
		next, err := source.openDirectoryAt(current, component)
		if err != nil {
			return nil, err
		}
		current = next
	}
	if err := validateCanonicalMetadataPath(current.path); err != nil {
		return nil, err
	}
	return current, nil
}

func canonicalMetadataEntryAt(parent *canonicalMetadataDirectory, name string) (canonicalMetadataIdentity, error) {
	if parent == nil || parent.file == nil {
		return canonicalMetadataIdentity{}, fmt.Errorf("missing parent directory descriptor")
	}
	var stat unix.Stat_t
	if err := unix.Fstatat(int(parent.file.Fd()), name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return canonicalMetadataIdentity{}, err
	}
	return canonicalMetadataIdentityForStat(&stat), nil
}

func openCanonicalMetadataFileAt(parent *canonicalMetadataDirectory, name string) (*os.File, canonicalMetadataIdentity, error) {
	if err := validateCanonicalMetadataComponent(name, false); err != nil {
		return nil, canonicalMetadataIdentity{}, err
	}
	before, err := canonicalMetadataEntryAt(parent, name)
	if err != nil {
		return nil, canonicalMetadataIdentity{}, err
	}
	if err := validateCanonicalMetadataIdentity(before, false); err != nil {
		return nil, canonicalMetadataIdentity{}, err
	}
	fd, err := unix.Openat(int(parent.file.Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, canonicalMetadataIdentity{}, err
	}
	file := os.NewFile(uintptr(fd), filepath.Join(parent.path, name))
	opened, err := canonicalMetadataIdentityForFile(file)
	if err != nil {
		err = joinCanonicalConstructionCleanup(err, "close Git metadata file", file.Close)
		return nil, canonicalMetadataIdentity{}, err
	}
	if err := validateCanonicalMetadataIdentity(opened, false); err != nil {
		err = joinCanonicalConstructionCleanup(err, "close Git metadata file", file.Close)
		return nil, canonicalMetadataIdentity{}, err
	}
	if !before.sameFile(opened) {
		err := fmt.Errorf("changed before opening")
		err = joinCanonicalConstructionCleanup(err, "close Git metadata file", file.Close)
		return nil, canonicalMetadataIdentity{}, err
	}
	return file, opened, nil
}

// canonicalMetadataReadHook provides deterministic mutation synchronization for
// package tests. Production leaves it nil.
var canonicalMetadataReadHook func(string)

func readCanonicalMetadataOpenFile(file *os.File, identity canonicalMetadataIdentity, path string) ([]byte, error) {
	if canonicalMetadataReadHook != nil {
		canonicalMetadataReadHook(path)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxCanonicalGitMetadataBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxCanonicalGitMetadataBytes {
		return nil, fmt.Errorf("exceeds %d-byte limit", maxCanonicalGitMetadataBytes)
	}
	after, err := canonicalMetadataIdentityForFile(file)
	if err != nil {
		return nil, err
	}
	if !identity.sameFile(after) || int64(len(data)) != identity.size {
		return nil, fmt.Errorf("changed while reading")
	}
	return data, nil
}

func readCanonicalMetadataFileAt(parent *canonicalMetadataDirectory, name string, expected *canonicalMetadataIdentity) (data []byte, resultErr error) {
	file, identity, err := openCanonicalMetadataFileAt(parent, name)
	if err != nil {
		return nil, err
	}
	defer func() {
		resultErr = joinCanonicalConstructionCleanup(resultErr, "close Git metadata file", file.Close)
		if resultErr != nil {
			data = nil
		}
	}()
	if expected != nil && !identity.sameFile(*expected) {
		return nil, fmt.Errorf("changed before reading")
	}
	return readCanonicalMetadataOpenFile(file, identity, filepath.Join(parent.path, name))
}

type canonicalObjectIDFileKind uint8

const (
	canonicalObjectIDFileNone canonicalObjectIDFileKind = iota
	canonicalObjectIDFileReference
	canonicalObjectIDFileReflog
)

type canonicalMetadataSnapshotFile struct {
	path        string
	destination string
	data        []byte
	identity    canonicalMetadataIdentity
	file        *os.File
	objectIDs   canonicalObjectIDFileKind
}

type canonicalMetadataSnapshot struct {
	files        []canonicalMetadataSnapshotFile
	destinations map[string]struct{}
	config       []byte
	entries      int
	bytes        int64
}

func newCanonicalMetadataSnapshot() *canonicalMetadataSnapshot {
	return &canonicalMetadataSnapshot{destinations: make(map[string]struct{})}
}

func (snapshot *canonicalMetadataSnapshot) captureFile(parent *canonicalMetadataDirectory, name, destination string, objectIDs canonicalObjectIDFileKind, required bool) ([]byte, error) {
	file, identity, err := openCanonicalMetadataFileAt(parent, name)
	if err != nil {
		if os.IsNotExist(err) && !required {
			return nil, nil
		}
		return nil, err
	}
	data, err := readCanonicalMetadataOpenFile(file, identity, filepath.Join(parent.path, name))
	if err != nil {
		err = joinCanonicalConstructionCleanup(err, "close Git metadata file", file.Close)
		return nil, err
	}
	if err := snapshot.addFile(canonicalMetadataSnapshotFile{
		path:        filepath.Join(parent.path, name),
		destination: destination,
		data:        data,
		identity:    identity,
		file:        file,
		objectIDs:   objectIDs,
	}); err != nil {
		err = joinCanonicalConstructionCleanup(err, "close Git metadata file", file.Close)
		return nil, err
	}
	return data, nil
}

func (snapshot *canonicalMetadataSnapshot) addFile(file canonicalMetadataSnapshotFile) error {
	if file.destination != "" {
		if err := validateCanonicalMetadataDestination(file.destination); err != nil {
			return err
		}
		if _, exists := snapshot.destinations[file.destination]; exists {
			return fmt.Errorf("Git canonical metadata destination %q is ambiguous", file.destination)
		}
		snapshot.destinations[file.destination] = struct{}{}
	}
	if file.identity.size < 0 || snapshot.bytes > maxCanonicalGitMetadataBytes-file.identity.size {
		return fmt.Errorf("Git canonical metadata exceeds %d-byte limit", maxCanonicalGitMetadataBytes)
	}
	snapshot.bytes += file.identity.size
	snapshot.files = append(snapshot.files, file)
	return nil
}

func (snapshot *canonicalMetadataSnapshot) captureDirectory(source *canonicalRepositorySource, directory *canonicalMetadataDirectory, destination string, depth int, objectIDs canonicalObjectIDFileKind) error {
	if canonicalMetadataReadHook != nil {
		canonicalMetadataReadHook(directory.path)
	}
	for {
		names, err := directory.file.Readdirnames(canonicalGitMetadataDirectoryBatchSize)
		sort.Strings(names)
		for _, name := range names {
			if err := validateCanonicalMetadataComponent(name, false); err != nil {
				return fmt.Errorf("Git canonical metadata %q has unsafe directory entry", directory.path)
			}
			if snapshot.entries == maxCanonicalGitMetadataEntries {
				return fmt.Errorf("Git canonical metadata exceeds %d-entry limit", maxCanonicalGitMetadataEntries)
			}
			snapshot.entries++
			entry, statErr := canonicalMetadataEntryAt(directory, name)
			if statErr != nil {
				return fmt.Errorf("Git canonical metadata %q: %w", filepath.Join(directory.path, name), statErr)
			}
			childDestination := name
			if destination != "" {
				childDestination = filepath.Join(destination, name)
			}
			switch entry.mode & unix.S_IFMT {
			case unix.S_IFDIR:
				if depth >= maxCanonicalGitMetadataDepth {
					return fmt.Errorf("Git canonical metadata exceeds %d-directory-depth limit", maxCanonicalGitMetadataDepth)
				}
				child, openErr := source.openDirectoryAt(directory, name)
				if openErr != nil {
					return fmt.Errorf("Git canonical metadata %q: %w", filepath.Join(directory.path, name), openErr)
				}
				if err := snapshot.captureDirectory(source, child, childDestination, depth+1, objectIDs); err != nil {
					return err
				}
			case unix.S_IFREG:
				if _, readErr := snapshot.captureFile(directory, name, childDestination, objectIDs, true); readErr != nil {
					return fmt.Errorf("Git canonical metadata %q: %w", filepath.Join(directory.path, name), readErr)
				}
			default:
				return fmt.Errorf("Git canonical metadata %q is not a regular file", filepath.Join(directory.path, name))
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
	}
	if err := directory.verify(); err != nil {
		return err
	}
	return nil
}

func (snapshot *canonicalMetadataSnapshot) captureDirectoryAt(source *canonicalRepositorySource, parent *canonicalMetadataDirectory, name, destination string, depth int, objectIDs canonicalObjectIDFileKind, required bool) error {
	return snapshot.captureDirectoryPathAt(source, parent, []string{name}, destination, depth, objectIDs, required)
}

func (snapshot *canonicalMetadataSnapshot) captureDirectoryPathAt(source *canonicalRepositorySource, parent *canonicalMetadataDirectory, names []string, destination string, depth int, objectIDs canonicalObjectIDFileKind, required bool) error {
	directory := parent
	for _, name := range names {
		child, err := source.openDirectoryAt(directory, name)
		if err != nil {
			if os.IsNotExist(err) && !required {
				return nil
			}
			return err
		}
		directory = child
	}
	return snapshot.captureDirectory(source, directory, destination, depth, objectIDs)
}

func (snapshot *canonicalMetadataSnapshot) verify(source *canonicalRepositorySource) error {
	for _, file := range snapshot.files {
		actual, err := canonicalMetadataIdentityForFile(file.file)
		if err != nil {
			return err
		}
		if !file.identity.sameFile(actual) || int64(len(file.data)) != file.identity.size {
			return fmt.Errorf("Git canonical metadata %q changed while reading", file.path)
		}
	}
	return source.verify()
}

func (snapshot *canonicalMetadataSnapshot) close() error {
	var closeErr error
	for index := range snapshot.files {
		file := snapshot.files[index].file
		if file == nil {
			continue
		}
		snapshot.files[index].file = nil
		if err := file.Close(); err != nil {
			closeErr = errors.Join(closeErr, fmt.Errorf("close %q: %w", snapshot.files[index].path, err))
		}
	}
	return closeErr
}

func snapshotCanonicalGitMetadata(directories canonicalGitDirectorySet, references []string) (*canonicalMetadataSnapshot, error) {
	snapshot := newCanonicalMetadataSnapshot()
	fail := func(err error) (*canonicalMetadataSnapshot, error) {
		err = joinCanonicalConstructionCleanup(err, "close Git metadata snapshots", snapshot.close)
		return nil, err
	}

	if _, err := snapshot.captureFile(directories.worktree, "HEAD", "HEAD", canonicalObjectIDFileReference, true); err != nil {
		return fail(fmt.Errorf("Git canonical metadata %q: %w", filepath.Join(directories.worktree.path, "HEAD"), err))
	}
	if _, err := snapshot.captureFile(directories.worktree, "index", "index", canonicalObjectIDFileNone, false); err != nil {
		return fail(fmt.Errorf("Git canonical metadata %q: %w", filepath.Join(directories.worktree.path, "index"), err))
	}
	config, err := snapshot.captureFile(directories.common, "config", "", canonicalObjectIDFileNone, false)
	if err != nil {
		return fail(fmt.Errorf("Git canonical metadata %q: %w", filepath.Join(directories.common.path, "config"), err))
	}
	snapshot.config = config
	for _, name := range []string{"packed-refs", "shallow"} {
		if _, err := snapshot.captureFile(directories.common, name, name, canonicalObjectIDFileReference, false); err != nil {
			return fail(fmt.Errorf("Git canonical metadata %q: %w", filepath.Join(directories.common.path, name), err))
		}
	}
	if err := snapshot.captureDirectoryAt(directories.source, directories.common, "refs", "refs", 0, canonicalObjectIDFileReference, false); err != nil {
		return fail(fmt.Errorf("Git canonical metadata %q: %w", filepath.Join(directories.common.path, "refs"), err))
	}
	if !directories.worktree.identity.sameLocation(directories.common.identity) {
		if err := snapshot.captureDirectoryAt(directories.source, directories.worktree, "refs", "refs", 0, canonicalObjectIDFileReference, false); err != nil {
			return fail(fmt.Errorf("Git canonical metadata %q: %w", filepath.Join(directories.worktree.path, "refs"), err))
		}
	}
	if canonicalReferencesUseReflogs(references) {
		if directories.worktree.identity.sameLocation(directories.common.identity) {
			if err := snapshot.captureDirectoryAt(directories.source, directories.common, "logs", "logs", 0, canonicalObjectIDFileReflog, false); err != nil {
				return fail(fmt.Errorf("Git canonical metadata %q: %w", filepath.Join(directories.common.path, "logs"), err))
			}
		} else {
			if err := snapshot.captureDirectoryPathAt(directories.source, directories.common, []string{"logs", "refs"}, filepath.Join("logs", "refs"), 0, canonicalObjectIDFileReflog, false); err != nil {
				return fail(fmt.Errorf("Git canonical metadata %q: %w", filepath.Join(directories.common.path, "logs", "refs"), err))
			}
			if err := snapshot.captureDirectoryAt(directories.source, directories.worktree, "logs", "logs", 0, canonicalObjectIDFileReflog, false); err != nil {
				return fail(fmt.Errorf("Git canonical metadata %q: %w", filepath.Join(directories.worktree.path, "logs"), err))
			}
		}
	}
	for _, name := range []string{"ORIG_HEAD", "FETCH_HEAD", "MERGE_HEAD", "CHERRY_PICK_HEAD", "REVERT_HEAD", "BISECT_HEAD", "REBASE_HEAD"} {
		if _, err := snapshot.captureFile(directories.worktree, name, name, canonicalObjectIDFileReference, false); err != nil {
			return fail(fmt.Errorf("Git canonical metadata %q: %w", filepath.Join(directories.worktree.path, name), err))
		}
	}
	return snapshot, nil
}

func writeCanonicalMetadataSnapshot(gitDir string, snapshot *canonicalMetadataSnapshot) error {
	for _, file := range snapshot.files {
		if file.destination == "" {
			continue
		}
		destination := filepath.Join(gitDir, file.destination)
		if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
			return fmt.Errorf("Git canonical metadata %q: %w", destination, err)
		}
		if err := writeCanonicalGitFile(destination, file.data); err != nil {
			return fmt.Errorf("Git canonical metadata %q: %w", destination, err)
		}
	}
	return nil
}

func initializeCanonicalGitDirectory(gitDir string, directories canonicalGitDirectorySet, references []string) (initializeErr error) {
	snapshot, err := snapshotCanonicalGitMetadata(directories, references)
	if err != nil {
		return err
	}
	snapshotOpen := true
	defer func() {
		if snapshotOpen {
			initializeErr = joinCanonicalConstructionCleanup(
				initializeErr,
				"close Git canonical metadata snapshots",
				snapshot.close,
			)
		}
	}()

	objectFormat, err := canonicalObjectFormat(snapshot)
	if err != nil {
		return err
	}
	if err := snapshot.verify(directories.source); err != nil {
		return err
	}
	closeErr := snapshot.close()
	snapshotOpen = false
	if closeErr != nil {
		return fmt.Errorf("close Git canonical metadata snapshots: %w", closeErr)
	}
	if err := writeCanonicalMetadataSnapshot(gitDir, snapshot); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(gitDir, "refs", "heads"), 0o700); err != nil {
		return fmt.Errorf("Git canonical refs directory: %w", err)
	}
	return initializeCanonicalObjectDirectory(gitDir, directories.objects.path, objectFormat)
}

func initializeCanonicalObjectDirectory(gitDir, objectDirectory, objectFormat string) error {
	if err := os.MkdirAll(filepath.Join(gitDir, "objects", "info"), 0o700); err != nil {
		return fmt.Errorf("Git canonical object directory: %w", err)
	}
	if err := writeCanonicalGitFile(filepath.Join(gitDir, "config"), canonicalGitConfig(objectFormat)); err != nil {
		return err
	}
	if err := writeCanonicalGitFile(filepath.Join(gitDir, "objects", "info", "alternates"), []byte(objectDirectory+"\n")); err != nil {
		return err
	}
	return nil
}

func canonicalReferencesUseReflogs(references []string) bool {
	for _, reference := range references {
		if strings.Contains(reference, "@{") {
			return true
		}
	}
	return false
}

func canonicalGitConfig(objectFormat string) []byte {
	config := "[core]\n\tbare = true\n\tattributesFile = /dev/null\n\tquotePath = true\n[pager]\n\tdiff = false\n[color]\n\tui = false\n[diff]\n\texternal =\n\trenames = false\n\talgorithm = myers\n\tindentHeuristic = false\n\tcontext = 3\n\tinterHunkContext = 0\n"
	if objectFormat == "sha256" {
		config += "[core]\n\trepositoryformatversion = 1\n[extensions]\n\tobjectformat = sha256\n"
	}
	return []byte(config)
}

func canonicalObjectFormatForObjectID(objectID ports.GitObjectID) (string, error) {
	switch len(objectID.String()) {
	case 40:
		return "sha1", nil
	case 64:
		return "sha256", nil
	default:
		return "", fmt.Errorf("Git canonical object format has invalid object ID length")
	}
}

func canonicalObjectFormat(snapshot *canonicalMetadataSnapshot) (string, error) {
	if snapshot == nil {
		return "", fmt.Errorf("Git canonical object format is indeterminate")
	}
	structuralFormat, err := canonicalStructuralObjectFormat(snapshot.config)
	if err != nil {
		return "", err
	}

	length := 0
	for _, file := range snapshot.files {
		switch file.objectIDs {
		case canonicalObjectIDFileReference:
			if err := recordCanonicalObjectIDData(file.data, &length); err != nil {
				return "", err
			}
		case canonicalObjectIDFileReflog:
			if err := recordCanonicalReflogObjectIDData(file.data, &length); err != nil {
				return "", err
			}
		}
	}
	oidFormat := ""
	switch length {
	case 40:
		oidFormat = "sha1"
	case 64:
		oidFormat = "sha256"
	case 0:
	default:
		return "", fmt.Errorf("Git canonical object format is indeterminate")
	}
	if structuralFormat == "" && oidFormat == "" {
		return "", fmt.Errorf("Git canonical object format is indeterminate")
	}
	if structuralFormat != "" && oidFormat != "" && structuralFormat != oidFormat {
		return "", fmt.Errorf("Git canonical object format is inconsistent")
	}
	if structuralFormat != "" {
		return structuralFormat, nil
	}
	return oidFormat, nil
}

func canonicalStructuralObjectFormat(config []byte) (string, error) {
	if len(config) == 0 {
		return "", nil
	}
	section := ""
	versionSet := false
	version := 0
	objectFormatSet := false
	objectFormat := ""

	for _, raw := range strings.Split(string(config), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			if !strings.HasSuffix(line, "]") {
				return "", fmt.Errorf("Git canonical object format has malformed structural config")
			}
			section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			if strings.ContainsAny(section, " \t\"") {
				section = ""
			}
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.ToLower(strings.TrimSpace(stripCanonicalConfigComment(value)))
		switch {
		case section == "core" && key == "repositoryformatversion":
			if versionSet {
				return "", fmt.Errorf("Git canonical object format has ambiguous repository format version")
			}
			parsed, err := strconv.Atoi(value)
			if err != nil || (parsed != 0 && parsed != 1) {
				return "", fmt.Errorf("Git canonical object format has invalid repository format version")
			}
			versionSet = true
			version = parsed
		case section == "extensions" && key == "objectformat":
			if objectFormatSet {
				return "", fmt.Errorf("Git canonical object format has ambiguous object format")
			}
			if value != "sha1" && value != "sha256" {
				return "", fmt.Errorf("Git canonical object format is unsupported")
			}
			objectFormatSet = true
			objectFormat = value
		}
	}
	if objectFormatSet {
		if objectFormat == "sha256" && (!versionSet || version != 1) {
			return "", fmt.Errorf("Git canonical object format is inconsistent")
		}
		if objectFormat == "sha1" && versionSet && version != 0 {
			return "", fmt.Errorf("Git canonical object format is inconsistent")
		}
		return objectFormat, nil
	}
	if versionSet {
		return "sha1", nil
	}
	return "", nil
}

func stripCanonicalConfigComment(value string) string {
	for index, character := range value {
		if (character == '#' || character == ';') && (index == 0 || value[index-1] == ' ' || value[index-1] == '\t') {
			return strings.TrimSpace(value[:index])
		}
	}
	return value
}

func recordCanonicalObjectIDData(data []byte, length *int) error {
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" || line[0] == '#' {
			continue
		}
		fields := strings.Fields(strings.TrimPrefix(line, "^"))
		if len(fields) > 0 {
			if err := recordCanonicalObjectIDLength(fields[0], length); err != nil {
				return err
			}
		}
	}
	return nil
}

func recordCanonicalReflogObjectIDData(data []byte, length *int) error {
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		for index := 0; index < len(fields) && index < 2; index++ {
			if err := recordCanonicalObjectIDLength(fields[index], length); err != nil {
				return err
			}
		}
	}
	return nil
}

func recordCanonicalObjectIDLength(value string, length *int) error {
	if !isCanonicalObjectID(value) {
		return nil
	}
	if *length != 0 && *length != len(value) {
		return fmt.Errorf("Git canonical object format is inconsistent")
	}
	*length = len(value)
	return nil
}

func isCanonicalObjectID(value string) bool {
	if len(value) != 40 && len(value) != 64 {
		return false
	}
	for _, character := range value {
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return false
		}
	}
	return true
}

func canonicalMetadataIdentityForFile(file *os.File) (canonicalMetadataIdentity, error) {
	if file == nil {
		return canonicalMetadataIdentity{}, fmt.Errorf("missing filesystem identity")
	}
	var stat unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &stat); err != nil {
		return canonicalMetadataIdentity{}, err
	}
	return canonicalMetadataIdentityForStat(&stat), nil
}

func canonicalMetadataIdentityForStat(stat *unix.Stat_t) canonicalMetadataIdentity {
	return canonicalMetadataIdentity{
		device:     uint64(uint32(stat.Dev)),
		inode:      stat.Ino,
		mode:       stat.Mode,
		size:       stat.Size,
		mtimeSec:   stat.Mtim.Sec,
		mtimeNsec:  stat.Mtim.Nsec,
		ctimeSec:   stat.Ctim.Sec,
		ctimeNsec:  stat.Ctim.Nsec,
		generation: stat.Gen,
	}
}

func validateCanonicalMetadataIdentity(identity canonicalMetadataIdentity, directory bool) error {
	switch identity.mode & unix.S_IFMT {
	case unix.S_IFLNK:
		return fmt.Errorf("must not be a symlink")
	case unix.S_IFDIR:
		if directory {
			return nil
		}
		return fmt.Errorf("not a regular file")
	case unix.S_IFREG:
		if directory {
			return fmt.Errorf("not a directory")
		}
		if identity.size < 0 || identity.size > maxCanonicalGitMetadataBytes {
			return fmt.Errorf("exceeds %d-byte limit", maxCanonicalGitMetadataBytes)
		}
		return nil
	default:
		if directory {
			return fmt.Errorf("not a directory")
		}
		return fmt.Errorf("not a regular file")
	}
}

func validateCanonicalMetadataComponent(name string, allowParent bool) error {
	if name == "" || len(name) > maxCanonicalGitMetadataPathBytes || strings.ContainsRune(name, 0) || strings.ContainsRune(name, filepath.Separator) {
		return fmt.Errorf("unsafe path component")
	}
	if name == "." || (name == ".." && !allowParent) {
		return fmt.Errorf("unsafe path component")
	}
	return nil
}

func validateCanonicalMetadataDestination(path string) error {
	if err := validateCanonicalMetadataPath(path); err != nil {
		return err
	}
	if filepath.IsAbs(path) || filepath.Clean(path) != path || path == "." || path == ".." || strings.HasPrefix(path, ".."+string(filepath.Separator)) {
		return fmt.Errorf("unsafe destination path")
	}
	return nil
}

func validateCanonicalMetadataPath(path string) error {
	if path == "" || len(path) > maxCanonicalGitMetadataPathBytes || strings.ContainsRune(path, 0) {
		return fmt.Errorf("Git canonical metadata path exceeds %d-byte limit", maxCanonicalGitMetadataPathBytes)
	}
	return nil
}

func openCanonicalMetadataParent(path string) (*canonicalRepositorySource, *canonicalMetadataDirectory, string, error) {
	if err := validateCanonicalMetadataPath(path); err != nil {
		return nil, nil, "", err
	}
	clean := filepath.Clean(path)
	if !filepath.IsAbs(clean) || clean != path {
		return nil, nil, "", fmt.Errorf("metadata path is not canonical")
	}
	name := filepath.Base(clean)
	if err := validateCanonicalMetadataComponent(name, false); err != nil {
		return nil, nil, "", err
	}
	source, parent, err := openCanonicalRepositoryRoot(filepath.Dir(clean))
	if err != nil {
		return nil, nil, "", err
	}
	return source, parent, name, nil
}

func readCanonicalGitMetadata(path string) ([]byte, error) {
	return readCanonicalGitMetadataExpected(path, nil)
}

func readCanonicalGitMetadataExpected(path string, expected *canonicalMetadataIdentity) (data []byte, resultErr error) {
	source, parent, name, err := openCanonicalMetadataParent(path)
	if err != nil {
		return nil, err
	}
	defer func() {
		resultErr = joinCanonicalConstructionCleanup(
			resultErr,
			"close Git metadata descriptors",
			source.close,
		)
		if resultErr != nil {
			data = nil
		}
	}()
	data, err = readCanonicalMetadataFileAt(parent, name, expected)
	if err != nil {
		return nil, err
	}
	if err := source.verify(); err != nil {
		return nil, err
	}
	return data, nil
}

func inspectCanonicalMetadataPath(path string, directory bool) (identity canonicalMetadataIdentity, resultErr error) {
	source, parent, name, err := openCanonicalMetadataParent(path)
	if err != nil {
		return canonicalMetadataIdentity{}, err
	}
	defer func() {
		resultErr = joinCanonicalConstructionCleanup(
			resultErr,
			"close Git metadata descriptors",
			source.close,
		)
		if resultErr != nil {
			identity = canonicalMetadataIdentity{}
		}
	}()
	if directory {
		child, err := source.openDirectoryAt(parent, name)
		if err != nil {
			return canonicalMetadataIdentity{}, err
		}
		if err := source.verify(); err != nil {
			return canonicalMetadataIdentity{}, err
		}
		return child.identity, nil
	}
	file, identity, err := openCanonicalMetadataFileAt(parent, name)
	if err != nil {
		return canonicalMetadataIdentity{}, err
	}
	closeErr := file.Close()
	verifyErr := source.verify()
	if closeErr != nil {
		verifyErr = errors.Join(verifyErr, fmt.Errorf("close Git metadata file: %w", closeErr))
	}
	if verifyErr != nil {
		return canonicalMetadataIdentity{}, verifyErr
	}
	return identity, nil
}

type canonicalDirectoryPlan struct {
	entries int
	bytes   int64
}

type canonicalMetadataTraversal struct {
	entries int
}

func (traversal *canonicalMetadataTraversal) reserve(plan canonicalDirectoryPlan, copiedBytes int64) error {
	if traversal == nil || copiedBytes < 0 || copiedBytes > maxCanonicalGitMetadataBytes-plan.bytes {
		return fmt.Errorf("Git canonical metadata exceeds %d-byte limit", maxCanonicalGitMetadataBytes)
	}
	if traversal.entries > maxCanonicalGitMetadataEntries-plan.entries {
		return fmt.Errorf("Git canonical metadata exceeds %d-entry limit", maxCanonicalGitMetadataEntries)
	}
	traversal.entries += plan.entries
	return nil
}

func copyCanonicalGitFile(source, destination string, required bool, copiedBytes *int64, expected *canonicalMetadataIdentity) error {
	data, err := readCanonicalGitMetadataExpected(source, expected)
	if os.IsNotExist(err) && !required {
		return nil
	}
	if err != nil {
		return fmt.Errorf("Git canonical metadata %q: %w", source, err)
	}
	if err := addCanonicalMetadataBytes(copiedBytes, len(data)); err != nil {
		return err
	}
	if err := writeCanonicalGitFile(destination, data); err != nil {
		return fmt.Errorf("Git canonical metadata %q: %w", destination, err)
	}
	return nil
}

func copyCanonicalGitDirectory(sourcePath, destination string, copiedBytes *int64, traversal *canonicalMetadataTraversal) (resultErr error) {
	if copiedBytes == nil {
		return fmt.Errorf("Git canonical metadata byte counter is nil")
	}
	source, parent, name, err := openCanonicalMetadataParent(sourcePath)
	if err != nil {
		return err
	}
	defer func() {
		resultErr = joinCanonicalConstructionCleanup(
			resultErr,
			"close Git metadata descriptors",
			source.close,
		)
	}()

	directory, err := source.openDirectoryAt(parent, name)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("Git canonical metadata %q: %w", sourcePath, err)
	}
	snapshot := newCanonicalMetadataSnapshot()
	snapshotOpen := true
	defer func() {
		if snapshotOpen {
			resultErr = joinCanonicalConstructionCleanup(
				resultErr,
				"close Git metadata snapshots",
				snapshot.close,
			)
		}
	}()
	if err := snapshot.captureDirectory(source, directory, "", 0, canonicalObjectIDFileNone); err != nil {
		return err
	}
	if err := snapshot.verify(source); err != nil {
		return err
	}
	if err := traversal.reserve(canonicalDirectoryPlan{entries: snapshot.entries, bytes: snapshot.bytes}, *copiedBytes); err != nil {
		return err
	}
	closeErr := snapshot.close()
	snapshotOpen = false
	if closeErr != nil {
		return closeErr
	}
	if err := writeCanonicalMetadataSnapshot(destination, snapshot); err != nil {
		return err
	}
	if err := addCanonicalMetadataBytes(copiedBytes, int(snapshot.bytes)); err != nil {
		return err
	}
	return nil
}

func addCanonicalMetadataBytes(total *int64, count int) error {
	if total == nil || count < 0 || *total < 0 || *total > maxCanonicalGitMetadataBytes-int64(count) {
		return fmt.Errorf("Git canonical metadata exceeds %d-byte limit", maxCanonicalGitMetadataBytes)
	}
	*total += int64(count)
	return nil
}

func writeCanonicalGitFile(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	written, writeErr := file.Write(data)
	var resultErr error
	switch {
	case writeErr != nil:
		resultErr = writeErr
	case written != len(data):
		resultErr = fmt.Errorf("short write")
	}
	return joinCanonicalConstructionCleanup(resultErr, "close Git canonical file", file.Close)
}

var captureFormatMagic = []byte("mulgae.git-target\x00")

// canonicalCapturedBytes frames every captured field in a fixed order. Field
// names and values are independently length-prefixed so no two field bindings
// can share a byte representation.
func canonicalCapturedBytes(
	repositoryID string,
	baseObjectID ports.GitObjectID,
	headObjectID ports.GitObjectID,
	headTreeID ports.GitObjectID,
	indexTreeID *ports.GitObjectID,
	includeUntracked bool,
	diff []byte,
	inventory []byte,
) []byte {
	data := make([]byte, 0, len(captureFormatMagic)+2+256+len(repositoryID)+len(diff)+len(inventory))
	data = append(data, captureFormatMagic...)
	data = appendUint16(data, captureFormatVersion)
	data = appendFrameField(data, "repository-id", []byte(repositoryID))
	data = appendFrameField(data, "base-object-id", []byte(baseObjectID.String()))
	data = appendFrameField(data, "head-object-id", []byte(headObjectID.String()))
	data = appendFrameField(data, "head-tree-id", []byte(headTreeID.String()))
	if indexTreeID == nil {
		data = appendFrameField(data, "index-tree-id", nil)
	} else {
		data = appendFrameField(data, "index-tree-id", []byte(indexTreeID.String()))
	}
	if includeUntracked {
		data = appendFrameField(data, "include-untracked", []byte{1})
	} else {
		data = appendFrameField(data, "include-untracked", []byte{0})
	}
	data = appendFrameField(data, "diff", diff)
	data = appendFrameField(data, "untracked-inventory", inventory)
	return data
}

func appendFrameField(data []byte, name string, value []byte) []byte {
	data = appendUint32(data, uint32(len(name)))
	data = append(data, name...)
	data = appendUint64(data, uint64(len(value)))
	return append(data, value...)
}

func appendUint16(data []byte, value uint16) []byte {
	var encoded [2]byte
	binary.BigEndian.PutUint16(encoded[:], value)
	return append(data, encoded[:]...)
}

func appendUint32(data []byte, value uint32) []byte {
	var encoded [4]byte
	binary.BigEndian.PutUint32(encoded[:], value)
	return append(data, encoded[:]...)
}

func appendUint64(data []byte, value uint64) []byte {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	return append(data, encoded[:]...)
}
