//go:build darwin && arm64

package herdr

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

const (
	// EnvHerdrCoreBin optionally pins an explicit canonical path to the
	// herdr-core / hc binary. When set, discovery never falls back to PATH or
	// ~/.local/bin even if the configured value is empty or invalid.
	EnvHerdrCoreBin = "MULGAE_HERDR_CORE_BIN"

	maxResolveSymlinkHops    = 40
	maxResolvePathComponents = 4096
)

var (
	// ErrExecutableNotFound reports that no trusted herdr-core / hc binary was
	// discovered across the admitted search locations.
	ErrExecutableNotFound = errors.New("herdr-core executable not found")
	// ErrUnsafeExecutable reports that an explicit or candidate herdr-core
	// binary violated path, ownership, mode, or exclusion safety rules.
	ErrUnsafeExecutable = errors.New("herdr-core executable is unsafe")
)

var candidateBinaryNames = []string{"hc", "herdr-core"}

// ResolvedExecutable holds the verified canonical path and sha256:-prefixed
// content digest of the discovered herdr-core / hc executable.
type ResolvedExecutable struct {
	Path   string
	SHA256 string
}

// ResolveOptions configures safe herdr-core / hc binary discovery without
// mutating process environment state.
type ResolveOptions struct {
	OverridePath  string
	HasOverride   bool
	PathEnv       string
	NativeHome    string
	ExcludedRoots []string
}

// DefaultResolveOptions builds production discovery options from the current
// process environment and native user home.
func DefaultResolveOptions(nativeHome string, excludedRoots ...string) ResolveOptions {
	override, hasOverride := os.LookupEnv(EnvHerdrCoreBin)
	return ResolveOptions{
		OverridePath:  override,
		HasOverride:   hasOverride,
		PathEnv:       os.Getenv("PATH"),
		NativeHome:    nativeHome,
		ExcludedRoots: append([]string(nil), excludedRoots...),
	}
}

// ResolveExecutable discovers and verifies the herdr-core / hc executable using
// strict precedence:
//  1. MULGAE_HERDR_CORE_BIN (when set, never falls back on invalid/unsafe path);
//  2. safe PATH entries (skipping relative, excluded, and unsafe directories);
//  3. <nativeHome>/.local/bin/{hc,herdr-core}.
func ResolveExecutable(opts ResolveOptions) (ResolvedExecutable, error) {
	euid := uint32(unix.Geteuid())
	excluded, err := normalizeExcludedRoots(opts.ExcludedRoots)
	if err != nil {
		return ResolvedExecutable{}, fmt.Errorf("%w: %v", ErrUnsafeExecutable, err)
	}

	if opts.HasOverride {
		resolved, err := verifyExecutableCandidate(opts.OverridePath, euid, excluded)
		if err != nil {
			return ResolvedExecutable{}, fmt.Errorf("%w: %s: %v", ErrUnsafeExecutable, EnvHerdrCoreBin, err)
		}
		return resolved, nil
	}

	var unsafeErr error
	for _, entry := range filepath.SplitList(opts.PathEnv) {
		if entry == "" || !validCanonicalAbsolutePath(entry) {
			continue
		}
		if pathWithinAnyRoot(entry, excluded) {
			continue
		}
		dirCanonical, dirErr := resolveSafeDirectoryChain(entry, euid, excluded)
		if dirErr != nil {
			continue
		}
		if pathWithinAnyRoot(dirCanonical, excluded) {
			continue
		}
		for _, name := range candidateBinaryNames {
			candidate := filepath.Join(entry, name)
			if _, statErr := os.Lstat(candidate); errors.Is(statErr, os.ErrNotExist) {
				continue
			}
			resolved, verifyErr := verifyExecutableCandidate(candidate, euid, excluded)
			if verifyErr == nil {
				return resolved, nil
			}
			if unsafeErr == nil {
				unsafeErr = verifyErr
			}
		}
	}

	if opts.NativeHome != "" && validCanonicalAbsolutePath(opts.NativeHome) {
		localBin := filepath.Join(opts.NativeHome, ".local", "bin")
		if !pathWithinAnyRoot(localBin, excluded) {
			if dirCanonical, dirErr := resolveSafeDirectoryChain(localBin, euid, excluded); dirErr == nil && !pathWithinAnyRoot(dirCanonical, excluded) {
				for _, name := range candidateBinaryNames {
					candidate := filepath.Join(localBin, name)
					if _, statErr := os.Lstat(candidate); errors.Is(statErr, os.ErrNotExist) {
						continue
					}
					resolved, verifyErr := verifyExecutableCandidate(candidate, euid, excluded)
					if verifyErr == nil {
						return resolved, nil
					}
					if unsafeErr == nil {
						unsafeErr = verifyErr
					}
				}
			}
		}
	}

	if unsafeErr != nil {
		return ResolvedExecutable{}, fmt.Errorf("%w: %v", ErrUnsafeExecutable, unsafeErr)
	}
	return ResolvedExecutable{}, ErrExecutableNotFound
}

func verifyExecutableCandidate(candidate string, euid uint32, excluded []string) (ResolvedExecutable, error) {
	if !validCanonicalAbsolutePath(candidate) {
		return ResolvedExecutable{}, fmt.Errorf("path must be absolute and canonical")
	}
	if pathWithinAnyRoot(candidate, excluded) {
		return ResolvedExecutable{}, fmt.Errorf("path lies inside an excluded root")
	}
	canonical, err := resolveSafeSymlinkFileChain(candidate, euid, excluded)
	if err != nil {
		return ResolvedExecutable{}, err
	}
	if !validCanonicalAbsolutePath(canonical) {
		return ResolvedExecutable{}, fmt.Errorf("resolved path is not canonical")
	}
	if pathWithinAnyRoot(canonical, excluded) {
		return ResolvedExecutable{}, fmt.Errorf("resolved path lies inside an excluded root")
	}
	return openAndHashVerifiedExecutable(canonical, euid)
}

func openAndHashVerifiedExecutable(canonical string, euid uint32) (ResolvedExecutable, error) {
	components := splitAbsoluteComponents(canonical)
	if len(components) == 0 || len(components) > maxResolvePathComponents {
		return ResolvedExecutable{}, fmt.Errorf("invalid executable path")
	}
	dirFD, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return ResolvedExecutable{}, err
	}
	if err := validateExecutableAncestorFD(dirFD, euid); err != nil {
		_ = unix.Close(dirFD)
		return ResolvedExecutable{}, err
	}
	for _, component := range components[:len(components)-1] {
		nextFD, openErr := unix.Openat(dirFD, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		_ = unix.Close(dirFD)
		if openErr != nil {
			return ResolvedExecutable{}, openErr
		}
		dirFD = nextFD
		if err := validateExecutableAncestorFD(dirFD, euid); err != nil {
			_ = unix.Close(dirFD)
			return ResolvedExecutable{}, err
		}
	}
	fileFD, openErr := unix.Openat(dirFD, components[len(components)-1], unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	_ = unix.Close(dirFD)
	if openErr != nil {
		return ResolvedExecutable{}, openErr
	}
	file := os.NewFile(uintptr(fileFD), canonical)
	defer file.Close()

	if err := descriptorPathMatches(fileFD, canonical); err != nil {
		return ResolvedExecutable{}, err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fileFD, &stat); err != nil {
		return ResolvedExecutable{}, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return ResolvedExecutable{}, fmt.Errorf("executable is not a regular file")
	}
	if stat.Uid != 0 && stat.Uid != euid {
		return ResolvedExecutable{}, fmt.Errorf("executable has untrusted owner uid %d", stat.Uid)
	}
	if stat.Mode&0o022 != 0 {
		return ResolvedExecutable{}, fmt.Errorf("executable is group- or world-writable")
	}
	if stat.Mode&(unix.S_ISUID|unix.S_ISGID) != 0 {
		return ResolvedExecutable{}, fmt.Errorf("executable must not have setuid or setgid bit")
	}
	if stat.Mode&0o111 == 0 {
		return ResolvedExecutable{}, fmt.Errorf("file is not executable")
	}
	if stat.Uid == euid && stat.Mode&0o100 == 0 {
		return ResolvedExecutable{}, fmt.Errorf("owner execute bit is missing")
	}
	if stat.Uid != euid && unix.Access(canonical, unix.X_OK) != nil {
		return ResolvedExecutable{}, fmt.Errorf("file is not executable by effective user")
	}

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return ResolvedExecutable{}, fmt.Errorf("hash executable: %w", err)
	}
	return ResolvedExecutable{
		Path:   canonical,
		SHA256: "sha256:" + hex.EncodeToString(hasher.Sum(nil)),
	}, nil
}

// resolveSafeDirectoryChain walks an existing directory path component by
// component, following symlinks while requiring every traversed directory and
// symlink to be owned by root or euid, outside excluded roots, and not
// group/world-writable.
func resolveSafeDirectoryChain(path string, euid uint32, excluded []string) (string, error) {
	resolved, isDir, err := resolveSafePathChain(path, euid, excluded)
	if err != nil {
		return "", err
	}
	if !isDir {
		return "", fmt.Errorf("path is not a directory")
	}
	return resolved, nil
}

func resolveSafeSymlinkFileChain(path string, euid uint32, excluded []string) (string, error) {
	resolved, isDir, err := resolveSafePathChain(path, euid, excluded)
	if err != nil {
		return "", err
	}
	if isDir {
		return "", fmt.Errorf("executable path resolves to a directory")
	}
	return resolved, nil
}

func resolveSafePathChain(path string, euid uint32, excluded []string) (string, bool, error) {
	if !validCanonicalAbsolutePath(path) {
		return "", false, fmt.Errorf("path must be canonical and absolute")
	}
	if err := validateSafeDirectoryPath("/", euid); err != nil {
		return "", false, err
	}
	current := "/"
	queue := splitAbsoluteComponents(path)
	if len(queue) > maxResolvePathComponents {
		return "", false, fmt.Errorf("path exceeds component limit")
	}
	hops := 0
	isDir := true

	for len(queue) > 0 {
		seg := queue[0]
		queue = queue[1:]
		if seg == "" || seg == "." {
			continue
		}
		if seg == ".." {
			if current != "/" {
				current = filepath.Dir(current)
			}
			if pathWithinAnyRoot(current, excluded) {
				return "", false, fmt.Errorf("path traverses excluded root")
			}
			isDir = true
			continue
		}
		next := filepath.Join(current, seg)
		if pathWithinAnyRoot(next, excluded) {
			return "", false, fmt.Errorf("path traverses excluded root")
		}
		var st unix.Stat_t
		if err := unix.Lstat(next, &st); err != nil {
			return "", false, err
		}
		switch st.Mode & unix.S_IFMT {
		case unix.S_IFLNK:
			if st.Uid != 0 && st.Uid != euid {
				return "", false, fmt.Errorf("symlink %q has untrusted owner", next)
			}
			hops++
			if hops > maxResolveSymlinkHops {
				return "", false, fmt.Errorf("too many symlink hops")
			}
			target, err := os.Readlink(next)
			if err != nil {
				return "", false, err
			}
			if target == "" || strings.ContainsRune(target, 0) {
				return "", false, fmt.Errorf("invalid symlink target")
			}
			if strings.HasPrefix(target, "/") {
				current = "/"
			}
			targetParts := splitAbsoluteComponents(target)
			if len(targetParts)+len(queue) > maxResolvePathComponents {
				return "", false, fmt.Errorf("symlink expansion exceeds component limit")
			}
			nextQueue := make([]string, 0, len(targetParts)+len(queue))
			nextQueue = append(nextQueue, targetParts...)
			nextQueue = append(nextQueue, queue...)
			queue = nextQueue
			isDir = true
		case unix.S_IFDIR:
			if st.Uid != 0 && st.Uid != euid {
				return "", false, fmt.Errorf("directory %q has untrusted owner", next)
			}
			if st.Mode&0o022 != 0 {
				return "", false, fmt.Errorf("directory %q is group- or world-writable", next)
			}
			current = next
			isDir = true
		case unix.S_IFREG:
			if len(queue) != 0 {
				return "", false, fmt.Errorf("regular file encountered before leaf")
			}
			current = next
			isDir = false
		default:
			return "", false, fmt.Errorf("unsupported file type along executable path")
		}
	}
	return current, isDir, nil
}

func validateSafeDirectoryPath(path string, euid uint32) error {
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return fmt.Errorf("not a directory")
	}
	if st.Uid != 0 && st.Uid != euid {
		return fmt.Errorf("directory has untrusted owner")
	}
	if st.Mode&0o022 != 0 {
		return fmt.Errorf("directory is group- or world-writable")
	}
	return nil
}

func validateExecutableAncestorFD(fd int, euid uint32) error {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return fmt.Errorf("ancestor is not a directory")
	}
	if st.Uid != 0 && st.Uid != euid {
		return fmt.Errorf("ancestor directory has untrusted owner")
	}
	if st.Mode&0o022 != 0 {
		return fmt.Errorf("ancestor directory is group- or world-writable")
	}
	return nil
}

func normalizeExcludedRoots(roots []string) ([]string, error) {
	seen := make(map[string]struct{}, len(roots)*2)
	out := make([]string, 0, len(roots)*2)
	add := func(path string) {
		clean := filepath.Clean(path)
		if clean == "" || clean == "/" {
			return
		}
		if _, ok := seen[clean]; ok {
			return
		}
		seen[clean] = struct{}{}
		out = append(out, clean)
	}
	for _, root := range roots {
		if root == "" {
			continue
		}
		if !filepath.IsAbs(root) || strings.ContainsRune(root, 0) {
			return nil, fmt.Errorf("excluded root %q must be absolute", root)
		}
		clean := filepath.Clean(root)
		if clean == "/" {
			return nil, fmt.Errorf("excluded root must not be /")
		}
		add(clean)
		if resolved, err := resolveExcludedRootWithMissingTail(clean); err == nil && filepath.IsAbs(resolved) && resolved != "/" {
			add(resolved)
		}
	}
	return out, nil
}

func resolveExcludedRootWithMissingTail(clean string) (string, error) {
	if resolved, err := filepath.EvalSymlinks(clean); err == nil {
		return filepath.Clean(resolved), nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	prefix := clean
	var tail []string
	for prefix != "/" && prefix != "." {
		if _, err := os.Lstat(prefix); err == nil {
			resolvedPrefix, evalErr := filepath.EvalSymlinks(prefix)
			if evalErr != nil {
				return "", evalErr
			}
			parts := make([]string, 0, len(tail)+1)
			parts = append(parts, resolvedPrefix)
			for i := len(tail) - 1; i >= 0; i-- {
				parts = append(parts, tail[i])
			}
			return filepath.Clean(filepath.Join(parts...)), nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		tail = append(tail, filepath.Base(prefix))
		prefix = filepath.Dir(prefix)
	}
	return clean, nil
}

func pathWithinAnyRoot(path string, roots []string) bool {
	clean := filepath.Clean(path)
	for _, root := range roots {
		if clean == root || strings.HasPrefix(clean, root+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

func validCanonicalAbsolutePath(path string) bool {
	if path == "" || path == "/" || !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsRune(path, 0) || !utf8.ValidString(path) {
		return false
	}
	for _, r := range path {
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

func splitAbsoluteComponents(path string) []string {
	parts := strings.Split(path, "/")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}
