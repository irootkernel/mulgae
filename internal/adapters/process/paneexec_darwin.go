//go:build darwin && arm64

package process

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/irootkernel/mulgae/internal/ports"
	"golang.org/x/sys/unix"
)

const (
	paneExecMinArgvLen          = 19
	paneExecEnvFileName         = "env.json"
	paneExecProfileFileName     = "seatbelt.sb"
	paneExecEnvFileVersion      = 1
	paneExecMaxEnvFileBytes     = 256 * 1024
	paneExecMaxProfileFileBytes = 256 * 1024
	paneExecReadChunkBytes      = 32 * 1024
)

var paneTTYSlaveRegexp = regexp.MustCompile(liveOwnedPTYSlavePattern)

var _ ports.PaneLaunchBuilder = (*PaneLaunchBuilder)(nil)

type paneEnvFilePayload struct {
	Version      int                `json:"version"`
	WritableRoot string             `json:"writable_root"`
	Entries      []paneEnvFileEntry `json:"entries"`
}

type paneEnvFileEntry struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type paneControlFileIdentity struct {
	path   string
	dev    uint64
	ino    uint64
	sha256 string
}

type paneExecSpec struct {
	envPath      string
	envDev       uint64
	envIno       uint64
	envSHA256    string
	profilePath  string
	profileDev   uint64
	profileIno   uint64
	profileSHA   string
	cwdPath      string
	cwdDev       uint64
	cwdIno       uint64
	cwdBtimSec   int64
	cwdBtimNsec  int64
	cwdEUID      uint32
	providerExec string
	providerDev  uint64
	providerIno  uint64
	providerArgs []string
}

// PaneLaunchBuilder constructs integrity-bound __mulgae_paneexec_v1 launch
// specifications backed by 0400 private per-pane env and Seatbelt profile files.
type PaneLaunchBuilder struct {
	executableOverride string
}

// NewPaneLaunchBuilder returns a production PaneLaunchBuilder that resolves
// Mulgae's canonical verified executable via os.Executable and EvalSymlinks.
func NewPaneLaunchBuilder() *PaneLaunchBuilder {
	return &PaneLaunchBuilder{}
}

// BuildPaneLaunch validates the terminal request and boundary, materializes
// 0400 env and Seatbelt profile files in the caller's private per-pane control
// directory (covered by ControlPlaneRoots), and returns the integrity-bound
// __mulgae_paneexec_v1 launch specification.
func (builder *PaneLaunchBuilder) BuildPaneLaunch(ctx context.Context, request ports.PaneLaunchRequest) (ports.PaneLaunchSpec, error) {
	if ctx == nil {
		return ports.PaneLaunchSpec{}, fmt.Errorf("pane launch builder: nil context")
	}
	if err := ctx.Err(); err != nil {
		return ports.PaneLaunchSpec{}, err
	}
	if !request.Valid() {
		return ports.PaneLaunchSpec{}, fmt.Errorf("pane launch builder: invalid pane launch request")
	}
	proc := request.Process()
	boundary, guarded := proc.LiveReadOnlyBoundary()
	if !guarded || !boundary.Valid() || !boundary.PaneTTY() {
		return ports.PaneLaunchSpec{}, fmt.Errorf("pane launch builder: pane TTY boundary is required")
	}
	writableRoot := boundary.WritableRoot().String()
	envEntries, err := validatePaneEnvironmentVariables(proc.Environment(), writableRoot)
	if err != nil {
		return ports.PaneLaunchSpec{}, fmt.Errorf("pane launch builder: %w", err)
	}
	envBytes, err := json.Marshal(paneEnvFilePayload{
		Version:      paneExecEnvFileVersion,
		WritableRoot: writableRoot,
		Entries:      envEntries,
	})
	if err != nil {
		return ports.PaneLaunchSpec{}, fmt.Errorf("pane launch builder: encode env file: %w", err)
	}
	if len(envBytes) > paneExecMaxEnvFileBytes {
		return ports.PaneLaunchSpec{}, fmt.Errorf("pane launch builder: env file exceeds size limit")
	}

	admissionCtx, cancel := context.WithTimeout(ctx, proc.Timeout())
	defer cancel()
	profileText, err := compileLiveBoundaryProfile(admissionCtx, boundary)
	if err != nil {
		return ports.PaneLaunchSpec{}, fmt.Errorf("pane launch builder: %w", err)
	}
	profileBytes := []byte(profileText)
	if len(profileBytes) > paneExecMaxProfileFileBytes {
		return ports.PaneLaunchSpec{}, fmt.Errorf("pane launch builder: profile file exceeds size limit")
	}

	cwdPath := proc.WorkingDirectory()
	cwdFD, err := openLiveBoundaryDirectory(cwdPath)
	if err != nil {
		return ports.PaneLaunchSpec{}, fmt.Errorf("pane launch builder: admit neutral cwd: %w", err)
	}
	var cwdStat unix.Stat_t
	cwdStatErr := unix.Fstat(cwdFD, &cwdStat)
	cwdCloseErr := unix.Close(cwdFD)
	euid := uint32(unix.Geteuid())
	if cwdStatErr != nil || cwdCloseErr != nil || cwdStat.Mode&unix.S_IFMT != unix.S_IFDIR || cwdStat.Uid != euid {
		return ports.PaneLaunchSpec{}, fmt.Errorf("pane launch builder: invalid neutral cwd identity")
	}
	if launchFile, launchRoot, bound := proc.LaunchDirectory(); bound {
		if launchRoot.String() != cwdPath {
			return ports.PaneLaunchSpec{}, fmt.Errorf("pane launch builder: launch directory root mismatch")
		}
		if err := validateNeutralLaunchDirectory(int(launchFile.Fd()), cwdPath); err != nil {
			return ports.PaneLaunchSpec{}, fmt.Errorf("pane launch builder: launch directory revalidation: %w", err)
		}
		var launchStat unix.Stat_t
		if err := unix.Fstat(int(launchFile.Fd()), &launchStat); err != nil ||
			launchStat.Dev != cwdStat.Dev || launchStat.Ino != cwdStat.Ino ||
			launchStat.Btim != cwdStat.Btim || launchStat.Uid != cwdStat.Uid {
			return ports.PaneLaunchSpec{}, fmt.Errorf("pane launch builder: launch directory identity mismatch")
		}
	}

	providerExec := proc.Executable()
	providerDev, providerIno, err := statVerifiedRegularExecutable(providerExec)
	if err != nil {
		return ports.PaneLaunchSpec{}, fmt.Errorf("pane launch builder: admit provider executable: %w", err)
	}

	mulgaeExec, err := builder.resolveMulgaeExecutable()
	if err != nil {
		return ports.PaneLaunchSpec{}, fmt.Errorf("pane launch builder: %w", err)
	}

	controlDir := request.ControlDirectory().String()
	controlDirFD, err := openPrivatePaneControlDirectory(controlDir, euid)
	if err != nil {
		return ports.PaneLaunchSpec{}, fmt.Errorf("pane launch builder: admit control directory: %w", err)
	}
	defer func() { _ = unix.Close(controlDirFD) }()

	envFile, err := writePrivatePaneControlFile(controlDirFD, controlDir, paneExecEnvFileName, envBytes, euid)
	if err != nil {
		return ports.PaneLaunchSpec{}, fmt.Errorf("pane launch builder: write env file: %w", err)
	}
	profileFile, err := writePrivatePaneControlFile(controlDirFD, controlDir, paneExecProfileFileName, profileBytes, euid)
	if err != nil {
		_ = unix.Unlinkat(controlDirFD, paneExecEnvFileName, 0)
		return ports.PaneLaunchSpec{}, fmt.Errorf("pane launch builder: write profile file: %w", err)
	}

	providerArgv := proc.Argv()
	argv := make([]string, 0, paneExecMinArgvLen+len(providerArgv)-1)
	argv = append(argv,
		mulgaeExec,
		paneExecHiddenArgument,
		envFile.path,
		strconv.FormatUint(envFile.dev, 10),
		strconv.FormatUint(envFile.ino, 10),
		envFile.sha256,
		profileFile.path,
		strconv.FormatUint(profileFile.dev, 10),
		strconv.FormatUint(profileFile.ino, 10),
		profileFile.sha256,
		cwdPath,
		strconv.FormatUint(uint64(cwdStat.Dev), 10),
		strconv.FormatUint(cwdStat.Ino, 10),
		strconv.FormatInt(cwdStat.Btim.Sec, 10),
		strconv.FormatInt(cwdStat.Btim.Nsec, 10),
		strconv.FormatUint(uint64(euid), 10),
		providerExec,
		strconv.FormatUint(providerDev, 10),
		strconv.FormatUint(providerIno, 10),
	)
	argv = append(argv, providerArgv[1:]...)

	spec, err := ports.NewPaneLaunchSpec(
		mulgaeExec,
		argv,
		envFile.path,
		"sha256:"+envFile.sha256,
		profileFile.path,
		"sha256:"+profileFile.sha256,
	)
	if err != nil {
		_ = unix.Unlinkat(controlDirFD, paneExecEnvFileName, 0)
		_ = unix.Unlinkat(controlDirFD, paneExecProfileFileName, 0)
		return ports.PaneLaunchSpec{}, fmt.Errorf("pane launch builder: assemble spec: %w", err)
	}
	return spec, nil
}

func (builder *PaneLaunchBuilder) resolveMulgaeExecutable() (string, error) {
	raw := ""
	if builder != nil && builder.executableOverride != "" {
		raw = builder.executableOverride
	} else {
		var err error
		raw, err = os.Executable()
		if err != nil {
			return "", fmt.Errorf("resolve trusted Mulgae executable: %w", err)
		}
	}
	resolved, err := filepath.EvalSymlinks(raw)
	if err != nil {
		return "", fmt.Errorf("canonicalize trusted Mulgae executable: %w", err)
	}
	absolute, err := filepath.Abs(resolved)
	if err != nil {
		return "", fmt.Errorf("canonicalize trusted Mulgae executable: %w", err)
	}
	canonical := filepath.Clean(absolute)
	if _, _, err := statVerifiedRegularExecutable(canonical); err != nil {
		return "", fmt.Errorf("verify trusted Mulgae executable: %w", err)
	}
	return canonical, nil
}

// execPaneTrampoline executes Mulgae's hidden __mulgae_paneexec_v1 trampoline.
// It validates every integrity-bound input, enters the verified neutral cwd,
// confirms all three standard descriptors refer to the single controlling PTY
// slave without cgo, sweeps inherited descriptors >= 3 to O_CLOEXEC, constructs
// an exact envp without ever consulting os.Environ(), and execve's compiled-in
// /usr/bin/sandbox-exec with -D PANE_TTY=<slave> -f <profile-file>.
func execPaneTrampoline(argv []string) error {
	spec, err := parsePaneExecArgv(argv)
	if err != nil {
		return err
	}
	euid := uint32(unix.Geteuid())
	if spec.cwdEUID != euid {
		return fmt.Errorf("pane exec: effective UID mismatch")
	}

	// Step 1: Open, validate, read, and close BOTH private control files before
	// the O_CLOEXEC sweep.
	envBytes, err := readVerifiedPaneControlFile(spec.envPath, spec.envDev, spec.envIno, spec.envSHA256, paneExecMaxEnvFileBytes, euid)
	if err != nil {
		return fmt.Errorf("pane exec: env file: %w", err)
	}
	if _, err := readVerifiedPaneControlFile(spec.profilePath, spec.profileDev, spec.profileIno, spec.profileSHA, paneExecMaxProfileFileBytes, euid); err != nil {
		return fmt.Errorf("pane exec: profile file: %w", err)
	}
	envPayload, err := decodeAndValidatePaneEnvFile(envBytes)
	if err != nil {
		return fmt.Errorf("pane exec: env payload: %w", err)
	}

	// Step 2: Open neutral cwd via O_NOFOLLOW + F_GETPATH, verify
	// (dev, ino, btime, euid), fchdir, re-verify ".", and close descriptors.
	if err := enterVerifiedPaneCWD(spec.cwdPath, spec.cwdDev, spec.cwdIno, spec.cwdBtimSec, spec.cwdBtimNsec, euid); err != nil {
		return fmt.Errorf("pane exec: cwd: %w", err)
	}

	// Step 3: Re-verify provider executable canonical path and (dev, ino) AFTER
	// fchdir.
	providerDev, providerIno, err := statVerifiedRegularExecutable(spec.providerExec)
	if err != nil || providerDev != spec.providerDev || providerIno != spec.providerIno {
		return fmt.Errorf("pane exec: provider executable identity mismatch")
	}

	// Step 4 & 5: Verify fds 0, 1, 2 are identical controlling TTY slave without
	// cgo and resolve exact ^/dev/ttys[0-9]+$ slave path.
	paneTTY, err := verifyControllingPaneTTY()
	if err != nil {
		return fmt.Errorf("pane exec: controlling tty: %w", err)
	}

	// Step 6: Mark every inherited descriptor fd >= 3 as O_CLOEXEC.
	if err := markInheritedDescriptorsCloseOnExec(); err != nil {
		return fmt.Errorf("pane exec: %w", err)
	}

	// Step 7: Build exact envp without ever calling os.Environ().
	envp, err := buildExactPaneEnvp(envPayload)
	if err != nil {
		return fmt.Errorf("pane exec: environment: %w", err)
	}

	// Step 8: Exec compiled-in /usr/bin/sandbox-exec with parameterized PANE_TTY
	// and -f <profile-file>.
	execArgv := make([]string, 0, 6+len(spec.providerArgs))
	execArgv = append(execArgv,
		seatbeltExecutable,
		"-D", "PANE_TTY="+paneTTY,
		"-f", spec.profilePath,
		spec.providerExec,
	)
	execArgv = append(execArgv, spec.providerArgs...)
	return syscall.Exec(seatbeltExecutable, execArgv, envp)
}

func parsePaneExecArgv(argv []string) (paneExecSpec, error) {
	if len(argv) < paneExecMinArgvLen || argv[1] != paneExecHiddenArgument {
		return paneExecSpec{}, fmt.Errorf("pane exec: invalid trampoline arguments")
	}
	for index, argument := range argv {
		if strings.ContainsRune(argument, 0) {
			return paneExecSpec{}, fmt.Errorf("pane exec: argv[%d] contains NUL", index)
		}
	}
	envPath := argv[2]
	profilePath := argv[6]
	cwdPath := argv[10]
	providerExec := argv[16]
	for _, path := range []string{envPath, profilePath, cwdPath, providerExec} {
		if !validPaneCanonicalPath(path) {
			return paneExecSpec{}, fmt.Errorf("pane exec: non-canonical absolute path")
		}
	}
	if envPath == profilePath {
		return paneExecSpec{}, fmt.Errorf("pane exec: env and profile paths must differ")
	}
	envDev, err := parseStrictPositiveUint64(argv[3])
	if err != nil {
		return paneExecSpec{}, fmt.Errorf("pane exec: invalid env dev")
	}
	envIno, err := parseStrictPositiveUint64(argv[4])
	if err != nil {
		return paneExecSpec{}, fmt.Errorf("pane exec: invalid env ino")
	}
	if !validLowerHexSHA256(argv[5]) {
		return paneExecSpec{}, fmt.Errorf("pane exec: invalid env sha256")
	}
	profileDev, err := parseStrictPositiveUint64(argv[7])
	if err != nil {
		return paneExecSpec{}, fmt.Errorf("pane exec: invalid profile dev")
	}
	profileIno, err := parseStrictPositiveUint64(argv[8])
	if err != nil {
		return paneExecSpec{}, fmt.Errorf("pane exec: invalid profile ino")
	}
	if !validLowerHexSHA256(argv[9]) {
		return paneExecSpec{}, fmt.Errorf("pane exec: invalid profile sha256")
	}
	cwdDev, err := parseStrictPositiveUint64(argv[11])
	if err != nil {
		return paneExecSpec{}, fmt.Errorf("pane exec: invalid cwd dev")
	}
	cwdIno, err := parseStrictPositiveUint64(argv[12])
	if err != nil {
		return paneExecSpec{}, fmt.Errorf("pane exec: invalid cwd ino")
	}
	cwdBtimSec, err := parseStrictInt64(argv[13])
	if err != nil {
		return paneExecSpec{}, fmt.Errorf("pane exec: invalid cwd btime sec")
	}
	cwdBtimNsec, err := parseStrictInt64(argv[14])
	if err != nil || cwdBtimNsec < 0 || cwdBtimNsec >= 1_000_000_000 {
		return paneExecSpec{}, fmt.Errorf("pane exec: invalid cwd btime nsec")
	}
	cwdEUID64, err := parseStrictUint32(argv[15])
	if err != nil {
		return paneExecSpec{}, fmt.Errorf("pane exec: invalid cwd euid")
	}
	providerDev, err := parseStrictPositiveUint64(argv[17])
	if err != nil {
		return paneExecSpec{}, fmt.Errorf("pane exec: invalid provider dev")
	}
	providerIno, err := parseStrictPositiveUint64(argv[18])
	if err != nil {
		return paneExecSpec{}, fmt.Errorf("pane exec: invalid provider ino")
	}
	return paneExecSpec{
		envPath:      envPath,
		envDev:       envDev,
		envIno:       envIno,
		envSHA256:    argv[5],
		profilePath:  profilePath,
		profileDev:   profileDev,
		profileIno:   profileIno,
		profileSHA:   argv[9],
		cwdPath:      cwdPath,
		cwdDev:       cwdDev,
		cwdIno:       cwdIno,
		cwdBtimSec:   cwdBtimSec,
		cwdBtimNsec:  cwdBtimNsec,
		cwdEUID:      cwdEUID64,
		providerExec: providerExec,
		providerDev:  providerDev,
		providerIno:  providerIno,
		providerArgs: append([]string(nil), argv[paneExecMinArgvLen:]...),
	}, nil
}

func openPrivatePaneControlDirectory(path string, euid uint32) (int, error) {
	if !validPaneCanonicalPath(path) {
		return -1, fmt.Errorf("invalid canonical control directory path")
	}
	components := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(components) == 0 {
		return -1, fmt.Errorf("empty control directory path")
	}
	for _, component := range components {
		if component == "" || component == "." || component == ".." {
			return -1, fmt.Errorf("unsafe control directory component")
		}
	}
	dirFD, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	if err := validateControlAncestorFD(dirFD, euid); err != nil {
		_ = unix.Close(dirFD)
		return -1, err
	}
	for index, component := range components {
		next, openErr := unix.Openat(dirFD, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if openErr != nil {
			_ = unix.Close(dirFD)
			return -1, openErr
		}
		_ = unix.Close(dirFD)
		dirFD = next
		isLeafControlDir := index == len(components)-1
		if isLeafControlDir {
			var stat unix.Stat_t
			if err := unix.Fstat(dirFD, &stat); err != nil {
				_ = unix.Close(dirFD)
				return -1, err
			}
			if stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != euid || stat.Mode&0o7777 != 0o700 {
				_ = unix.Close(dirFD)
				return -1, fmt.Errorf("control directory must be private (0700) and owned by effective user")
			}
		} else {
			if err := validateControlAncestorFD(dirFD, euid); err != nil {
				_ = unix.Close(dirFD)
				return -1, err
			}
		}
	}
	if err := descriptorPathMatches(dirFD, path); err != nil {
		_ = unix.Close(dirFD)
		return -1, err
	}
	return dirFD, nil
}

// validateControlAncestorFD enforces trusted ownership and non-writable
// permissions on every intermediate directory above a private pane control
// directory (closing -f <profilePath> path-swap TOCTOU risks). Group/world-
// writable directories are admitted only when owned by root with the sticky
// bit set (such as /private/tmp).
func validateControlAncestorFD(fd int, euid uint32) error {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return fmt.Errorf("control ancestor is not a directory")
	}
	if stat.Uid != 0 && stat.Uid != euid {
		return fmt.Errorf("control ancestor has untrusted owner")
	}
	if stat.Mode&0o022 != 0 && (stat.Uid != 0 || stat.Mode&unix.S_ISVTX == 0) {
		return fmt.Errorf("control ancestor is group- or world-writable without sticky root protection")
	}
	return nil
}

func writePrivatePaneControlFile(dirFD int, dirPath, name string, data []byte, euid uint32) (paneControlFileIdentity, error) {
	fullPath := filepath.Join(dirPath, name)
	fileFD, err := unix.Openat(dirFD, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o400)
	if err != nil {
		return paneControlFileIdentity{}, err
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = unix.Unlinkat(dirFD, name, 0)
		}
	}()
	written := 0
	for written < len(data) {
		n, writeErr := unix.Write(fileFD, data[written:])
		if n > 0 {
			written += n
		}
		if writeErr != nil {
			if errors.Is(writeErr, unix.EINTR) {
				continue
			}
			_ = unix.Close(fileFD)
			return paneControlFileIdentity{}, writeErr
		}
	}
	if err := unix.Fchmod(fileFD, 0o400); err != nil {
		_ = unix.Close(fileFD)
		return paneControlFileIdentity{}, err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fileFD, &stat); err != nil {
		_ = unix.Close(fileFD)
		return paneControlFileIdentity{}, err
	}
	if err := descriptorPathMatches(fileFD, fullPath); err != nil {
		_ = unix.Close(fileFD)
		return paneControlFileIdentity{}, err
	}
	if err := unix.Close(fileFD); err != nil {
		return paneControlFileIdentity{}, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != euid || stat.Mode&0o7777 != 0o400 || stat.Nlink != 1 || stat.Size != int64(len(data)) {
		return paneControlFileIdentity{}, fmt.Errorf("control file metadata verification failed")
	}
	sum := sha256.Sum256(data)
	cleanup = false
	return paneControlFileIdentity{
		path:   fullPath,
		dev:    uint64(stat.Dev),
		ino:    stat.Ino,
		sha256: hex.EncodeToString(sum[:]),
	}, nil
}

func openAnchoredFileNoFollow(path string) (int, error) {
	if !validPaneCanonicalPath(path) {
		return -1, fmt.Errorf("invalid canonical path")
	}
	components := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(components) == 0 {
		return -1, fmt.Errorf("empty path components")
	}
	for _, component := range components {
		if component == "" || component == "." || component == ".." {
			return -1, fmt.Errorf("unsafe path component")
		}
	}
	dirFD, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	for _, component := range components[:len(components)-1] {
		next, openErr := unix.Openat(dirFD, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if openErr != nil {
			_ = unix.Close(dirFD)
			return -1, openErr
		}
		_ = unix.Close(dirFD)
		dirFD = next
	}
	fileFD, err := unix.Openat(dirFD, components[len(components)-1], unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	closeDirErr := unix.Close(dirFD)
	if err != nil {
		return -1, err
	}
	if closeDirErr != nil {
		_ = unix.Close(fileFD)
		return -1, closeDirErr
	}
	if err := descriptorPathMatches(fileFD, path); err != nil {
		_ = unix.Close(fileFD)
		return -1, err
	}
	return fileFD, nil
}

func readVerifiedPaneControlFile(path string, wantDev, wantIno uint64, wantSHA256 string, maxBytes int64, euid uint32) ([]byte, error) {
	if !validPaneCanonicalPath(path) {
		return nil, fmt.Errorf("invalid canonical control file path")
	}
	dirPath := filepath.Dir(path)
	leaf := filepath.Base(path)
	if leaf == "" || leaf == "." || leaf == ".." || dirPath == "/" {
		return nil, fmt.Errorf("unsafe control file path")
	}
	dirFD, err := openPrivatePaneControlDirectory(dirPath, euid)
	if err != nil {
		return nil, err
	}
	fd, err := unix.Openat(dirFD, leaf, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	closeDirErr := unix.Close(dirFD)
	if err != nil {
		return nil, err
	}
	if closeDirErr != nil {
		_ = unix.Close(fd)
		return nil, closeDirErr
	}
	if err := descriptorPathMatches(fd, path); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG ||
		stat.Uid != euid ||
		stat.Mode&0o7777 != 0o400 ||
		stat.Nlink != 1 ||
		uint64(stat.Dev) != wantDev ||
		stat.Ino != wantIno ||
		stat.Size < 0 ||
		stat.Size > maxBytes {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("control file metadata mismatch")
	}
	data, readErr := readBoundedFD(fd, maxBytes)
	closeErr := unix.Close(fd)
	if readErr != nil || closeErr != nil {
		return nil, errors.Join(readErr, closeErr)
	}
	if int64(len(data)) != stat.Size {
		return nil, fmt.Errorf("control file size changed while reading")
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != wantSHA256 {
		return nil, fmt.Errorf("control file digest mismatch")
	}
	return data, nil
}

func readBoundedFD(fd int, maxBytes int64) ([]byte, error) {
	var out []byte
	chunk := make([]byte, paneExecReadChunkBytes)
	for {
		n, err := unix.Read(fd, chunk)
		if n > 0 {
			if int64(len(out))+int64(n) > maxBytes {
				return nil, fmt.Errorf("file exceeds maximum allowed size")
			}
			out = append(out, chunk[:n]...)
		}
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return nil, err
		}
		if n == 0 {
			return out, nil
		}
	}
}

func enterVerifiedPaneCWD(cwdPath string, wantDev, wantIno uint64, wantBtimSec, wantBtimNsec int64, euid uint32) error {
	cwdFD, err := openLiveBoundaryDirectory(cwdPath)
	if err != nil {
		return err
	}
	var cwdStat unix.Stat_t
	if err := unix.Fstat(cwdFD, &cwdStat); err != nil {
		_ = unix.Close(cwdFD)
		return err
	}
	if cwdStat.Mode&unix.S_IFMT != unix.S_IFDIR ||
		uint64(cwdStat.Dev) != wantDev ||
		cwdStat.Ino != wantIno ||
		cwdStat.Btim.Sec != wantBtimSec ||
		cwdStat.Btim.Nsec != wantBtimNsec ||
		cwdStat.Uid != euid {
		_ = unix.Close(cwdFD)
		return fmt.Errorf("neutral cwd identity mismatch")
	}
	if err := unix.Fchdir(cwdFD); err != nil {
		_ = unix.Close(cwdFD)
		return err
	}
	dotFD, err := unix.Open(".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		_ = unix.Close(cwdFD)
		return err
	}
	var dotStat unix.Stat_t
	dotStatErr := unix.Fstat(dotFD, &dotStat)
	dotPathErr := descriptorPathMatches(dotFD, cwdPath)
	closeErr := errors.Join(unix.Close(dotFD), unix.Close(cwdFD))
	if dotStatErr != nil || dotPathErr != nil || closeErr != nil {
		return errors.Join(dotStatErr, dotPathErr, closeErr)
	}
	if dotStat.Mode&unix.S_IFMT != unix.S_IFDIR ||
		dotStat.Dev != cwdStat.Dev ||
		dotStat.Ino != cwdStat.Ino ||
		dotStat.Btim != cwdStat.Btim ||
		dotStat.Uid != cwdStat.Uid {
		return fmt.Errorf("post-fchdir cwd identity mismatch")
	}
	return nil
}

func statVerifiedRegularExecutable(path string) (uint64, uint64, error) {
	fd, err := openAnchoredFileNoFollow(path)
	if err != nil {
		return 0, 0, err
	}
	var stat unix.Stat_t
	statErr := unix.Fstat(fd, &stat)
	closeErr := unix.Close(fd)
	if statErr != nil || closeErr != nil {
		return 0, 0, errors.Join(statErr, closeErr)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o111 == 0 {
		return 0, 0, fmt.Errorf("executable must be a regular executable file")
	}
	return uint64(stat.Dev), stat.Ino, nil
}

// verifyControllingPaneTTY proves without cgo that fds 0, 1, and 2 are all the
// same character device, that this process is the session leader whose
// controlling terminal (/dev/tty) is bound to that exact device, and resolves
// its canonical ^/dev/ttys[0-9]+$ slave path.
func verifyControllingPaneTTY() (string, error) {
	var stats [3]unix.Stat_t
	for fd := 0; fd < 3; fd++ {
		if err := unix.Fstat(fd, &stats[fd]); err != nil {
			return "", fmt.Errorf("fstat fd %d: %w", fd, err)
		}
		if stats[fd].Mode&unix.S_IFMT != unix.S_IFCHR || stats[fd].Rdev == 0 {
			return "", fmt.Errorf("fd %d is not a character device", fd)
		}
		if fd > 0 && stats[fd].Rdev != stats[0].Rdev {
			return "", fmt.Errorf("standard descriptors do not share one tty device")
		}
	}
	pid := unix.Getpid()
	pgrp := unix.Getpgrp()
	sid, err := unix.Getsid(0)
	if err != nil || sid != pid {
		return "", fmt.Errorf("process is not session leader")
	}
	fd0Pgrp, err := unix.IoctlGetInt(0, unix.TIOCGPGRP)
	if err != nil || fd0Pgrp != pgrp {
		return "", fmt.Errorf("fd 0 foreground process group mismatch")
	}
	// Open /dev/tty with O_NOCTTY|O_CLOEXEC to confirm a live controlling
	// terminal, verify its foreground pgrp, and close it immediately. On Darwin,
	// fstat("/dev/tty").Rdev reports the ctty pseudo-device (major 2, minor 0)
	// rather than the underlying /dev/ttys* slave; the kernel's kinfo_proc
	// e_tdev field reports the exact controlling-terminal st_rdev.
	ttyFD, err := unix.Open("/dev/tty", unix.O_RDONLY|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", fmt.Errorf("open /dev/tty: %w", err)
	}
	var ttyStat unix.Stat_t
	ttyStatErr := unix.Fstat(ttyFD, &ttyStat)
	ttyPgrp, ttyPgrpErr := unix.IoctlGetInt(ttyFD, unix.TIOCGPGRP)
	ttyCloseErr := unix.Close(ttyFD)
	if ttyStatErr != nil || ttyPgrpErr != nil || ttyCloseErr != nil {
		return "", fmt.Errorf("inspect /dev/tty: %w", errors.Join(ttyStatErr, ttyPgrpErr, ttyCloseErr))
	}
	if ttyStat.Mode&unix.S_IFMT != unix.S_IFCHR || ttyPgrp != pgrp {
		return "", fmt.Errorf("/dev/tty does not match process group")
	}
	kinfo, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil || kinfo == nil || kinfo.Eproc.Tdev != stats[0].Rdev {
		return "", fmt.Errorf("controlling terminal device does not match fd 0")
	}
	return resolveControllingTTYSlave(0, stats[0].Rdev)
}

func resolveControllingTTYSlave(fd int, expectedRdev int32) (string, error) {
	if path, err := descriptorPath(fd); err == nil {
		if err := verifyTTYSlavePath(path, expectedRdev); err == nil {
			return path, nil
		}
	}
	return scanTTYSlaveByRdev(expectedRdev)
}

func verifyTTYSlavePath(path string, expectedRdev int32) error {
	if !paneTTYSlaveRegexp.MatchString(path) {
		return fmt.Errorf("slave path does not match %s", liveOwnedPTYSlavePattern)
	}
	var stat unix.Stat_t
	if err := unix.Lstat(path, &stat); err != nil {
		return err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFCHR || stat.Rdev != expectedRdev {
		return fmt.Errorf("slave path rdev mismatch")
	}
	return nil
}

func scanTTYSlaveByRdev(expectedRdev int32) (string, error) {
	devFD, err := unix.Open("/dev", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", err
	}
	dir := os.NewFile(uintptr(devFD), "/dev")
	defer dir.Close()
	for {
		names, readErr := dir.Readdirnames(128)
		for _, name := range names {
			if !strings.HasPrefix(name, "ttys") {
				continue
			}
			candidate := "/dev/" + name
			if err := verifyTTYSlavePath(candidate, expectedRdev); err == nil {
				return candidate, nil
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				break
			}
			return "", readErr
		}
	}
	return "", fmt.Errorf("controlling tty slave device not found")
}

func decodeAndValidatePaneEnvFile(raw []byte) (paneEnvFilePayload, error) {
	var payload paneEnvFilePayload
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		return paneEnvFilePayload{}, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return paneEnvFilePayload{}, fmt.Errorf("trailing bytes in env file")
	}
	if payload.Version != paneExecEnvFileVersion {
		return paneEnvFilePayload{}, fmt.Errorf("unsupported env file version")
	}
	if !validPaneCanonicalPath(payload.WritableRoot) {
		return paneEnvFilePayload{}, fmt.Errorf("invalid writable root")
	}
	vars := make([]ports.EnvironmentVariable, 0, len(payload.Entries))
	for _, entry := range payload.Entries {
		variable, err := ports.NewEnvironmentVariable(entry.Name, entry.Value)
		if err != nil {
			return paneEnvFilePayload{}, err
		}
		vars = append(vars, variable)
	}
	validated, err := validatePaneEnvironmentVariables(vars, payload.WritableRoot)
	if err != nil {
		return paneEnvFilePayload{}, err
	}
	payload.Entries = validated
	return payload, nil
}

func validatePaneEnvironmentVariables(environment []ports.EnvironmentVariable, writableRoot string) ([]paneEnvFileEntry, error) {
	if !validPaneCanonicalPath(writableRoot) {
		return nil, fmt.Errorf("invalid writable root")
	}
	seen := make(map[string]struct{}, len(environment))
	entries := make([]paneEnvFileEntry, 0, len(environment))
	for _, variable := range environment {
		if !variable.Valid() {
			return nil, fmt.Errorf("invalid environment variable")
		}
		name := variable.Name()
		value := variable.Value()
		if _, exists := seen[name]; exists {
			return nil, fmt.Errorf("duplicate environment variable %q", name)
		}
		if err := validateAllowedPaneEnvEntry(name, value, writableRoot, false); err != nil {
			return nil, err
		}
		seen[name] = struct{}{}
		entries = append(entries, paneEnvFileEntry{Name: name, Value: value})
	}
	sort.Slice(entries, func(left, right int) bool {
		return entries[left].Name < entries[right].Name
	})
	return entries, nil
}

func validateAllowedPaneEnvEntry(name, value, writableRoot string, allowTerminalID bool) error {
	if strings.HasPrefix(name, "DYLD_") || strings.HasPrefix(name, "LD_") || name == "GODEBUG" {
		return fmt.Errorf("forbidden runtime loader/debug variable %q", name)
	}
	if strings.HasPrefix(name, "HC_") {
		if allowTerminalID && name == ports.TerminalPaneIDEnvName {
			if !ports.ValidTerminalPaneID(value) {
				return fmt.Errorf("invalid %s pass-through value", ports.TerminalPaneIDEnvName)
			}
			return nil
		}
		return fmt.Errorf("forbidden control-plane variable %q", name)
	}
	if strings.HasPrefix(name, "XDG_") {
		if !validPaneCanonicalPath(value) || !pathWithinRoot(value, writableRoot) {
			return fmt.Errorf("out-of-namespace XDG variable %q", name)
		}
	}
	return nil
}

// buildExactPaneEnvp assembles the exact execve envp solely from the verified
// 0400 env file plus the single validated inherited HC_TERMINAL_ID variable.
// It deliberately never calls os.Environ().
func buildExactPaneEnvp(payload paneEnvFilePayload) ([]string, error) {
	envp := make([]string, 0, len(payload.Entries)+1)
	seen := make(map[string]struct{}, len(payload.Entries)+1)
	for _, entry := range payload.Entries {
		if _, exists := seen[entry.Name]; exists {
			return nil, fmt.Errorf("duplicate environment variable %q", entry.Name)
		}
		if err := validateAllowedPaneEnvEntry(entry.Name, entry.Value, payload.WritableRoot, false); err != nil {
			return nil, err
		}
		seen[entry.Name] = struct{}{}
		envp = append(envp, entry.Name+"="+entry.Value)
	}
	if terminalID, present := os.LookupEnv(ports.TerminalPaneIDEnvName); present {
		if err := validateAllowedPaneEnvEntry(ports.TerminalPaneIDEnvName, terminalID, payload.WritableRoot, true); err != nil {
			return nil, err
		}
		envp = append(envp, ports.TerminalPaneIDEnvName+"="+terminalID)
	}
	sort.Strings(envp)
	if err := verifyFinalPaneEnvp(envp, payload.WritableRoot); err != nil {
		return nil, err
	}
	return envp, nil
}

func verifyFinalPaneEnvp(envp []string, writableRoot string) error {
	seen := make(map[string]struct{}, len(envp))
	for _, pair := range envp {
		name, value, ok := strings.Cut(pair, "=")
		if !ok {
			return fmt.Errorf("malformed envp entry")
		}
		if _, err := ports.NewEnvironmentVariable(name, value); err != nil {
			return err
		}
		if _, exists := seen[name]; exists {
			return fmt.Errorf("duplicate envp entry %q", name)
		}
		seen[name] = struct{}{}
		if err := validateAllowedPaneEnvEntry(name, value, writableRoot, true); err != nil {
			return err
		}
	}
	return nil
}

func pathWithinRoot(path, root string) bool {
	cleanPath := filepath.Clean(path)
	cleanRoot := filepath.Clean(root)
	return cleanPath == cleanRoot || strings.HasPrefix(cleanPath, cleanRoot+string(filepath.Separator))
}

func validPaneCanonicalPath(path string) bool {
	return path != "" &&
		path != "/" &&
		filepath.IsAbs(path) &&
		filepath.Clean(path) == path &&
		!strings.ContainsRune(path, 0) &&
		printableSeatbeltPath(path)
}

func validLowerHexSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	for index := 0; index < len(value); index++ {
		c := value[index]
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') {
			continue
		}
		return false
	}
	return true
}

func parseStrictPositiveUint64(raw string) (uint64, error) {
	value, err := strconv.ParseUint(raw, 10, 64)
	if err != nil || value == 0 || strconv.FormatUint(value, 10) != raw {
		return 0, fmt.Errorf("invalid positive uint64")
	}
	return value, nil
}

func parseStrictUint32(raw string) (uint32, error) {
	value, err := strconv.ParseUint(raw, 10, 32)
	if err != nil || strconv.FormatUint(value, 10) != raw {
		return 0, fmt.Errorf("invalid uint32")
	}
	return uint32(value), nil
}

func parseStrictInt64(raw string) (int64, error) {
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || strconv.FormatInt(value, 10) != raw {
		return 0, fmt.Errorf("invalid int64")
	}
	return value, nil
}
