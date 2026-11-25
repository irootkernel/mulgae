//go:build darwin && arm64

package process

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"unicode"
	"unicode/utf8"
	"unsafe"

	"github.com/irootkernel/mulgae/internal/ports"
	"golang.org/x/sys/unix"
)

const seatbeltExecutable = "/usr/bin/sandbox-exec"

// liveOwnedPTYSlavePattern matches the kernel's numbered terminal slave
// device paths. It is deliberately anchored and never widened to /dev or all
// terminals.
const liveOwnedPTYSlavePattern = `^/dev/ttys[0-9]+$`

// liveBoundaryArgv adds the fixed platform launcher without changing provider
// identity or introducing a shell. The kernel policy is independent of the
// provider's planning mode and protocol permission gate.
func liveBoundaryArgv(ctx context.Context, request ports.ProcessRequest) (string, []string, error) {
	boundary, guarded := request.LiveReadOnlyBoundary()
	if !guarded {
		return request.Executable(), request.Argv(), nil
	}
	if boundary.PaneTTY() {
		return "", nil, fmt.Errorf("process runner: pane TTY boundary requires the pane trampoline launcher")
	}
	admissionContext, cancel := context.WithTimeout(ctx, request.Timeout())
	defer cancel()
	profile, err := compileLiveBoundaryProfile(admissionContext, boundary)
	if err != nil {
		return "", nil, err
	}
	argv := append([]string{seatbeltExecutable, "-p", profile, request.Executable()}, request.Argv()[1:]...)
	return seatbeltExecutable, argv, nil
}

// compileLiveBoundaryProfile admits boundary roots and builds the Seatbelt SBPL
// profile shared by inline -p protocol launches and file-based -f pane
// trampoline launches. Existing OwnedPTY-only and default profiles stay
// byte-identical when no ControlPlaneRoots or PaneTTY options are enabled.
func compileLiveBoundaryProfile(ctx context.Context, boundary ports.LiveReadOnlyBoundary) (string, error) {
	if !boundary.Valid() {
		return "", fmt.Errorf("process runner: invalid live read-only boundary")
	}
	var profile strings.Builder
	profile.WriteString("(version 1)\n(allow default)\n")
	if err := validateLiveBoundaryDirectory(boundary.WritableRoot().String()); err != nil {
		return "", fmt.Errorf("process runner: live writable namespace admission: %w", err)
	}
	profile.WriteString("(deny file-write* file-link (require-all (require-not (subpath " + strconv.Quote(boundary.WritableRoot().String()) + "))")
	if root, present := boundary.RuntimeTempRoot(); present {
		if err := validateLiveBoundaryDirectory(root.String()); err != nil {
			return "", fmt.Errorf("process runner: live runtime directory admission: %w", err)
		}
		profile.WriteString(" (require-not (subpath " + strconv.Quote(root.String()) + "))")
	}
	profile.WriteString(" (require-not (literal \"/dev/null\"))")
	if boundary.OwnedPTY() {
		// The owned-terminal carve-out lives inside the global deny predicate
		// itself: a later allow rule can never override an explicit deny. Only
		// the master device and slaves the kernel binds to this process
		// through com.apple.sandbox.pty leave the write denial; foreign
		// terminals are denied explicitly below.
		profile.WriteString(` (require-not (literal "/dev/ptmx"))`)
		profile.WriteString(` (require-not (require-all (regex #"` + liveOwnedPTYSlavePattern + `") (extension "com.apple.sandbox.pty")))`)
	}
	if boundary.PaneTTY() {
		// Exempt only the trampoline-verified controlling slave parameter and
		// /dev/tty inside the global write-deny predicate; every other
		// /dev/ttys[0-9]+ remains explicitly denied below.
		profile.WriteString(` (require-not (literal (param "PANE_TTY")))`)
		profile.WriteString(` (require-not (literal "/dev/tty"))`)
	}
	profile.WriteString("))\n")
	if root, present := boundary.RuntimeTempRoot(); present {
		profile.WriteString("(deny file-write-unlink (literal " + strconv.Quote(root.String()) + "))\n")
	}
	if boundary.OwnedPTY() && !boundary.PaneTTY() {
		profile.WriteString("(allow pseudo-tty)\n")
		profile.WriteString("(deny file-read* file-write* (literal \"/dev/tty\"))\n")
		profile.WriteString(`(deny file-read* file-write* file-ioctl (require-all (regex #"` + liveOwnedPTYSlavePattern + `") (require-not (extension "com.apple.sandbox.pty"))))` + "\n")
	} else if boundary.PaneTTY() {
		if boundary.OwnedPTY() {
			profile.WriteString("(allow pseudo-tty)\n")
			profile.WriteString(`(deny file-read* file-write* file-ioctl (require-all (regex #"` + liveOwnedPTYSlavePattern + `") (require-not (literal (param "PANE_TTY"))) (require-not (extension "com.apple.sandbox.pty"))))` + "\n")
		} else {
			profile.WriteString(`(deny file-read* file-write* file-ioctl (require-all (regex #"` + liveOwnedPTYSlavePattern + `") (require-not (literal (param "PANE_TTY")))))` + "\n")
		}
		// Empirically verified on darwin/arm64: macOS Seatbelt enforces
		// ioctl-command filtering for TIOCSTI (#x80017472) with EPERM while
		// preserving TIOCGWINSZ/TIOCSWINSZ and termios raw-mode ioctls.
		profile.WriteString("(deny file-ioctl (ioctl-command #x80017472))\n")
	}
	if parent, present := boundary.ManagedNamespaceRoot(); present {
		if err := validateLiveBoundaryDirectory(parent.String()); err != nil {
			return "", fmt.Errorf("process runner: managed namespace admission: %w", err)
		}
		profile.WriteString("(deny file-read-data file-link (require-all (subpath " +
			strconv.Quote(parent.String()) + ") (require-not (subpath " +
			strconv.Quote(boundary.WritableRoot().String()) + "))))\n")
	}
	ancestors := map[string]bool{}
	missingCredentials := map[string]bool{}
	for _, group := range []struct {
		roots      []ports.AnchoredRoot
		operations string
	}{
		{boundary.ReadOnlyRoots(), "file-write* file-link"},
		{boundary.CredentialRoots(), "file-read* file-write* file-link"},
	} {
		for _, root := range group.roots {
			path := root.String()
			if err := validateLiveBoundaryDirectory(path); err != nil {
				if group.operations != "file-read* file-write* file-link" || !errors.Is(err, os.ErrNotExist) {
					return "", fmt.Errorf("process runner: live boundary admission: %w", err)
				}
				// Optional, unconfigured credential homes still receive deny rules.
				// The descriptor walk rejects symlinks in every existing ancestor.
				missingCredentials[path] = true
			}
			profile.WriteString("(deny " + group.operations + " (subpath " + strconv.Quote(path) + "))\n")
			profile.WriteString("(deny network-outbound (remote unix-socket (subpath " + strconv.Quote(path) + ")))\n")
			for parent := path; parent != "/"; parent = filepath.Dir(parent) {
				if !ancestors[parent] {
					profile.WriteString("(deny file-write-unlink (literal " + strconv.Quote(parent) + "))\n")
					ancestors[parent] = true
				}
			}
		}
	}
	// Missing-tolerant control-plane roots and literals are explicitly excluded
	// from validateLiveRootFileLinks so missing /private/tmp/mgh-<uid> or live
	// operator control-plane trees never break launches.
	emittedSubpathDenies := map[string]bool{}
	emittedLiteralDenies := map[string]bool{}
	for _, root := range boundary.ControlPlaneRoots() {
		expanded, err := expandMissingTolerantPolicyPaths(root.String())
		if err != nil {
			return "", fmt.Errorf("process runner: live control-plane admission: %w", err)
		}
		for _, path := range expanded {
			if emittedSubpathDenies[path] {
				continue
			}
			emittedSubpathDenies[path] = true
			profile.WriteString("(deny file-read* file-write* file-link (subpath " + strconv.Quote(path) + "))\n")
			profile.WriteString("(deny network-outbound (remote unix-socket (subpath " + strconv.Quote(path) + ")))\n")
			for parent := path; parent != "/"; parent = filepath.Dir(parent) {
				if !ancestors[parent] {
					profile.WriteString("(deny file-write-unlink (literal " + strconv.Quote(parent) + "))\n")
					ancestors[parent] = true
				}
			}
		}
	}
	for _, literal := range boundary.ControlPlaneLiterals() {
		expanded, err := expandMissingTolerantPolicyPaths(literal.String())
		if err != nil {
			return "", fmt.Errorf("process runner: live control-plane literal admission: %w", err)
		}
		for _, path := range expanded {
			if emittedLiteralDenies[path] {
				continue
			}
			emittedLiteralDenies[path] = true
			profile.WriteString("(deny file-read* file-write* file-link (literal " + strconv.Quote(path) + "))\n")
			profile.WriteString("(deny network-outbound (remote unix-socket (literal " + strconv.Quote(path) + ")))\n")
			for parent := filepath.Dir(path); parent != "/"; parent = filepath.Dir(parent) {
				if !ancestors[parent] {
					profile.WriteString("(deny file-write-unlink (literal " + strconv.Quote(parent) + "))\n")
					ancestors[parent] = true
				}
			}
		}
	}
	if boundary.PaneTTY() {
		for _, root := range boundary.TerminalSecretRoots() {
			expanded, err := expandMissingTolerantPolicyPaths(root.String())
			if err != nil {
				return "", fmt.Errorf("process runner: live terminal secret-root admission: %w", err)
			}
			for _, path := range expanded {
				if emittedSubpathDenies[path] {
					continue
				}
				emittedSubpathDenies[path] = true
				profile.WriteString("(deny file-read* file-write* file-link (subpath " + strconv.Quote(path) + "))\n")
				profile.WriteString("(deny network-outbound (remote unix-socket (subpath " + strconv.Quote(path) + ")))\n")
			}
		}
		for _, literal := range boundary.TerminalDeniedLiterals() {
			expanded, err := expandMissingTolerantPolicyPaths(literal.String())
			if err != nil {
				return "", fmt.Errorf("process runner: live terminal literal admission: %w", err)
			}
			for _, path := range expanded {
				if emittedLiteralDenies[path] {
					continue
				}
				emittedLiteralDenies[path] = true
				profile.WriteString("(deny file-read* file-write* file-link (literal " + strconv.Quote(path) + "))\n")
			}
		}
	}
	if boundary.BashGate() {
		if err := writeBashGateSeatbeltRules(&profile, boundary); err != nil {
			return "", fmt.Errorf("process runner: live bash-gate admission: %w", err)
		}
	}
	aliasRoots := append(boundary.CredentialRoots(), boundary.WritableRoot())
	if root, present := boundary.RuntimeTempRoot(); present {
		aliasRoots = append(aliasRoots, root)
	}
	for _, root := range aliasRoots {
		if missingCredentials[root.String()] {
			continue
		}
		if err := validateLiveRootFileLinks(ctx, root.String()); err != nil {
			return "", fmt.Errorf("process runner: live file alias admission: %w", err)
		}
	}
	return profile.String(), nil
}

func writeBashGateSeatbeltRules(profile *strings.Builder, boundary ports.LiveReadOnlyBoundary) error {
	allowedUnixSockets := boundary.BashGateAllowedUnixSockets()
	if len(allowedUnixSockets) == 0 {
		profile.WriteString("(deny network-outbound (remote unix-socket))\n")
	} else {
		profile.WriteString("(deny network-outbound (require-all (remote unix-socket)")
		for _, socketRoot := range allowedUnixSockets {
			profile.WriteString(" (require-not (remote unix-socket (literal " + strconv.Quote(socketRoot.String()) + ")))")
		}
		profile.WriteString("))\n")
	}
	profile.WriteString("(deny network-outbound (remote ip \"localhost:*\"))\n")
	profile.WriteString("(deny process-exec" +
		" (literal \"/usr/bin/security\")" +
		" (literal \"/usr/bin/osascript\")" +
		" (literal \"/usr/bin/open\")" +
		" (literal \"/bin/launchctl\")" +
		" (regex #\"^(.*/)?git-credential-[^/]+$\")" +
		" (regex #\"^(.*/)?tmux$\")" +
		" (regex #\"^(.*/)?(hc|herdr|herdr-core|herdr-app|herdrd)$\")" +
		" (regex #\"^(.*/)?ssh[^/]*$\")" +
		" (regex #\"^(.*/)?docker$\"))\n")
	// Prevent copy-and-exec or repo-hosted binary bypasses by denying
	// process-exec across writable, runtime-temp, and read-only source roots.
	execDenyRoots := make([]ports.AnchoredRoot, 0, len(boundary.ReadOnlyRoots())+2)
	execDenyRoots = append(execDenyRoots, boundary.WritableRoot())
	if root, present := boundary.RuntimeTempRoot(); present {
		execDenyRoots = append(execDenyRoots, root)
	}
	execDenyRoots = append(execDenyRoots, boundary.ReadOnlyRoots()...)
	seenExecDeny := map[string]bool{}
	for _, root := range execDenyRoots {
		expanded, err := expandMissingTolerantPolicyPaths(root.String())
		if err != nil {
			return err
		}
		for _, path := range expanded {
			if seenExecDeny[path] {
				continue
			}
			seenExecDeny[path] = true
			profile.WriteString("(deny process-exec (subpath " + strconv.Quote(path) + "))\n")
		}
	}
	return nil
}

// expandMissingTolerantPolicyPaths resolves path component-by-component from
// "/" (following existing and dangling symlinks safely without lexically
// collapsing ".." across unresolved symlinks) so Seatbelt denies both the
// requested path and its canonical target even when the leaf does not yet
// exist at profile compilation time. Fails closed on permission/loop errors or
// if any resolved target is "/" or unrepresentable in SBPL.
func expandMissingTolerantPolicyPaths(path string) ([]string, error) {
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("policy path must be absolute")
	}
	clean := filepath.Clean(path)
	if clean == "/" || !printableSeatbeltPath(clean) {
		return nil, fmt.Errorf("policy path is unrepresentable")
	}
	if root, err := ports.NewAnchoredRoot(clean); err != nil || !root.Valid() {
		return nil, fmt.Errorf("policy path is invalid")
	}
	paths := []string{clean}
	resolved, err := resolvePathComponentsMissingTolerant(path)
	if err != nil {
		return nil, err
	}
	if resolved == "/" || !printableSeatbeltPath(resolved) {
		return nil, fmt.Errorf("resolved policy path is unrepresentable")
	}
	root, err := ports.NewAnchoredRoot(resolved)
	if err != nil || !root.Valid() {
		return nil, fmt.Errorf("resolved policy path is invalid")
	}
	if root.String() != clean {
		paths = append(paths, root.String())
	}
	return paths, nil
}

const (
	maxMissingPolicySymlinkHops = 40
	maxResolvedPathComponents   = 4096
)

func resolvePathComponentsMissingTolerant(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("policy path must be absolute")
	}
	current := "/"
	missingDepth := 0
	hops := 0
	queue := splitPathComponents(path)
	if len(queue) > maxResolvedPathComponents {
		return "", fmt.Errorf("resolved path exceeds component bound")
	}

	for len(queue) > 0 {
		seg := queue[0]
		queue = queue[1:]
		if seg == "" || seg == "." {
			continue
		}
		if seg == ".." {
			if current != "/" {
				current = filepath.Dir(current)
				if missingDepth > 0 {
					missingDepth--
				}
			}
			continue
		}
		next := filepath.Join(current, seg)
		if missingDepth > 0 {
			current = next
			missingDepth++
			continue
		}
		info, err := os.Lstat(next)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ENOTDIR) {
				current = next
				missingDepth = 1
				continue
			}
			return "", err
		}
		if info.Mode()&os.ModeSymlink == 0 {
			current = next
			continue
		}
		hops++
		if hops > maxMissingPolicySymlinkHops {
			return "", fmt.Errorf("too many symlink hops")
		}
		target, err := os.Readlink(next)
		if err != nil {
			return "", err
		}
		if target == "" {
			return "", fmt.Errorf("empty symlink target")
		}
		if strings.HasPrefix(target, "/") {
			current = "/"
			missingDepth = 0
		}
		targetParts := splitPathComponents(target)
		if len(targetParts)+len(queue) > maxResolvedPathComponents {
			return "", fmt.Errorf("resolved path exceeds component bound")
		}
		newQueue := make([]string, 0, len(targetParts)+len(queue))
		newQueue = append(newQueue, targetParts...)
		newQueue = append(newQueue, queue...)
		queue = newQueue
	}
	return current, nil
}

func splitPathComponents(path string) []string {
	raw := strings.Split(path, "/")
	out := make([]string, 0, len(raw))
	for _, part := range raw {
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func printableSeatbeltPath(path string) bool {
	if !utf8.ValidString(path) {
		return false
	}
	for _, r := range path {
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

// Admit each path through descriptors: aliases and symlinked ancestors cannot
// silently leave the named protection behind.
func validateLiveBoundaryDirectory(path string) error {
	fd, err := openLiveBoundaryDirectory(path)
	if err != nil {
		return err
	}
	return unix.Close(fd)
}

func openLiveBoundaryDirectory(path string) (int, error) {
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	for _, component := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		next, err := unix.Openat(fd, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			_ = unix.Close(fd)
			return -1, err
		}
		_ = unix.Close(fd)
		fd = next
	}
	if err := descriptorPathMatches(fd, path); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

// Seatbelt path rules do not deny an already existing hardlink outside a
// protected tree. Reject multiply linked credential or writable-root files
// before any spawn; global link denial prevents importing an outside alias.
// Inspect metadata through directory descriptors; never follow links or read
// file contents. Cancellation and the request deadline bound traversal.
func validateLiveRootFileLinks(ctx context.Context, path string) error {
	fd, err := openLiveBoundaryDirectory(path)
	if err != nil {
		return err
	}
	directory := os.NewFile(uintptr(fd), path)
	defer directory.Close()
	return inspectLiveRootDirectory(ctx, directory, path)
}

func inspectLiveRootDirectory(ctx context.Context, directory *os.File, path string) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		entries, err := directory.ReadDir(128)
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		for _, entry := range entries {
			if err := ctx.Err(); err != nil {
				return err
			}
			var stat unix.Stat_t
			if err := unix.Fstatat(int(directory.Fd()), entry.Name(), &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
				if errors.Is(err, unix.ENOENT) {
					continue
				}
				return err
			}
			switch stat.Mode & unix.S_IFMT {
			case unix.S_IFREG, unix.S_IFSOCK:
				if stat.Nlink != 1 {
					return fmt.Errorf("credential or writable-root file has a hardlink alias")
				}
			case unix.S_IFDIR:
				fd, err := unix.Openat(int(directory.Fd()), entry.Name(), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
				if err != nil {
					if errors.Is(err, unix.ENOENT) {
						continue
					}
					return err
				}
				childPath := filepath.Join(path, entry.Name())
				child := os.NewFile(uintptr(fd), childPath)
				var retained unix.Stat_t
				err = unix.Fstat(fd, &retained)
				if err == nil && (retained.Dev != stat.Dev || retained.Ino != stat.Ino || retained.Btim != stat.Btim) {
					err = fmt.Errorf("live alias-admission directory changed")
				}
				if err == nil {
					err = inspectLiveRootDirectory(ctx, child, childPath)
				}
				closeErr := child.Close()
				if err := errors.Join(err, closeErr); err != nil {
					return err
				}
			}
		}
		if errors.Is(err, io.EOF) {
			return descriptorPathMatches(int(directory.Fd()), path)
		}
	}
}

func descriptorPath(fd int) (string, error) {
	buffer := make([]byte, 4096)
	_, _, errno := unix.Syscall(
		unix.SYS_FCNTL, //nolint:staticcheck // Darwin exposes F_GETPATH only through fcntl(2).
		uintptr(fd), uintptr(unix.F_GETPATH), uintptr(unsafe.Pointer(&buffer[0])),
	)
	if errno != 0 {
		return "", errno
	}
	end := 0
	for end < len(buffer) && buffer[end] != 0 {
		end++
	}
	if end == 0 || end == len(buffer) {
		return "", fmt.Errorf("descriptor path unavailable")
	}
	return string(buffer[:end]), nil
}

func descriptorPathMatches(fd int, path string) error {
	actual, err := descriptorPath(fd)
	if err != nil {
		return err
	}
	if actual != path {
		return fmt.Errorf("protected directory is not descriptor-canonical")
	}
	return nil
}

func validateNeutralLaunchDirectory(fd int, path string) error {
	if err := descriptorPathMatches(fd, path); err != nil {
		return err
	}
	var retained, named unix.Stat_t
	if err := unix.Fstat(fd, &retained); err != nil {
		return err
	}
	if err := unix.Lstat(path, &named); err != nil {
		return err
	}
	if retained.Mode&unix.S_IFMT != unix.S_IFDIR || named.Mode&unix.S_IFMT != unix.S_IFDIR || retained.Dev != named.Dev || retained.Ino != named.Ino || retained.Btim != named.Btim {
		return fmt.Errorf("neutral launch directory identity changed")
	}
	return nil
}
