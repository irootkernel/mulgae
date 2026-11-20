//go:build darwin && arm64

package herdr

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	watchdogArgSentinel   = "__mulgae_herdr_watchdog_v1"
	maxWatchdogSignalRead = 64
)

// RunWatchdogMode executes the hidden parent-death supervisor when argv carries
// the internal Mulgae herdr watchdog sentinel. It returns handled=false for all
// ordinary invocations.
func RunWatchdogMode(argv []string) (bool, error) {
	if len(argv) < 2 || argv[1] != watchdogArgSentinel {
		return false, nil
	}
	if len(argv) != 3 {
		return true, fmt.Errorf("herdr watchdog: invalid argument count")
	}
	sessionDir := argv[2]
	if !validCanonicalAbsolutePath(sessionDir) {
		return true, fmt.Errorf("herdr watchdog: invalid session directory")
	}
	return true, runWatchdog(os.Stdin, sessionDir, defaultTeardownTimeout, ensureTrackedProcessGroupStopped)
}

func startParentDeathWatchdog(watchdogExe, sessionDir string) (*exec.Cmd, *os.File, chan error, error) {
	exe, err := resolveWatchdogExecutable(watchdogExe)
	if err != nil {
		return nil, nil, nil, err
	}
	pipeR, pipeW, err := os.Pipe()
	if err != nil {
		return nil, nil, nil, err
	}
	cmd := exec.Command(exe, watchdogArgSentinel, sessionDir)
	cmd.Dir = sessionDir
	cmd.Env = []string{
		"PATH=/usr/bin:/bin",
		"HOME=" + sessionDir,
		"TMPDIR=" + sessionDir,
	}
	cmd.Stdin = pipeR
	cmd.Stdout = nil
	cmd.Stderr = nil
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		_ = pipeR.Close()
		_ = pipeW.Close()
		return nil, nil, nil, err
	}
	_ = pipeR.Close()
	waitCh := make(chan error, 1)
	go func(c *exec.Cmd, ch chan<- error) {
		ch <- c.Wait()
		close(ch)
	}(cmd, waitCh)
	return cmd, pipeW, waitCh, nil
}

func resolveWatchdogExecutable(override string) (string, error) {
	raw := override
	if raw == "" {
		var err error
		raw, err = os.Executable()
		if err != nil {
			return "", fmt.Errorf("resolve watchdog executable: %w", err)
		}
	}
	resolved, err := filepath.EvalSymlinks(raw)
	if err != nil {
		return "", fmt.Errorf("resolve watchdog executable symlinks: %w", err)
	}
	abs, err := filepath.Abs(resolved)
	if err != nil {
		return "", fmt.Errorf("resolve watchdog executable abs: %w", err)
	}
	clean := filepath.Clean(abs)
	if !validCanonicalAbsolutePath(clean) {
		return "", fmt.Errorf("invalid watchdog executable path")
	}
	return clean, nil
}

func readWatchdogSignal(r io.Reader) string {
	limited := io.LimitReader(r, maxWatchdogSignalRead)
	reader := bufio.NewReaderSize(limited, maxWatchdogSignalRead)
	line, _ := reader.ReadString('\n')
	return strings.TrimSpace(line)
}

func runWatchdog(
	stdin io.Reader,
	sessionDir string,
	teardownTimeout time.Duration,
	stopGroup func(trackedProcess, time.Time) error,
) error {
	if readWatchdogSignal(stdin) == "clean" {
		return nil
	}
	if teardownTimeout <= 0 {
		teardownTimeout = defaultTeardownTimeout
	}
	if stopGroup == nil {
		stopGroup = ensureTrackedProcessGroupStopped
	}
	euid := uint32(unix.Geteuid())
	dirFD, err := openPrivateOwnedDirectoryNoFollow(sessionDir, euid)
	if err != nil {
		if errors.Is(err, unix.ENOENT) || errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("herdr watchdog: verify session dir: %w", err)
	}
	rec, err := readOwnerLockFromDirFD(dirFD, sessionDir, euid)
	_ = unix.Close(dirFD)
	if err != nil {
		// Retain sessionDir and owner.lock.json for stale reaping on next start.
		return fmt.Errorf("herdr watchdog: read owner lock: %w", err)
	}

	// Only accept disk-loaded core/holder entries that carry valid PIDs and
	// non-zero P_starttime identity.
	tracked := make(map[int]trackedProcess)
	if validTargetPID(rec.CorePID) && hasStartTime(rec.CoreStartSec, rec.CoreStartUsec) {
		tracked[rec.CorePID] = trackedProcess{
			PID:       rec.CorePID,
			StartSec:  rec.CoreStartSec,
			StartUsec: rec.CoreStartUsec,
		}
	}
	for _, holder := range rec.Holders {
		if validTargetPID(holder.PID) && hasStartTime(holder.StartSec, holder.StartUsec) {
			tracked[holder.PID] = holder
		}
	}

	deadline := time.Now().Add(teardownTimeout)
	sigkillReserve := min(500*time.Millisecond, teardownTimeout/3)
	gracefulDeadline := deadline.Add(-sigkillReserve)

	// Contact the session socket ONLY if it lies strictly inside sessionDir and
	// is a user-owned Unix socket.
	sockPath := filepath.Join(sessionDir, "s.sock")
	if rec.SocketPath == "" || rec.SocketPath == sockPath {
		var sockStat unix.Stat_t
		if unix.Lstat(sockPath, &sockStat) == nil && sockStat.Mode&unix.S_IFMT == unix.S_IFSOCK && sockStat.Uid == euid {
			if client, rpcErr := NewRPCClient(sockPath, 2*time.Second); rpcErr == nil {
				if rem := time.Until(gracefulDeadline); rem > 50*time.Millisecond {
					statusCtx, cancelStatus := context.WithTimeout(context.Background(), min(time.Second, rem/2))
					if status, statusErr := client.ServerStatus(statusCtx); statusErr == nil {
						if corePID, ok := uint32ToValidPID(status.PID); ok {
							if _, exists := tracked[corePID]; !exists {
								if sec, usec, alive, pErr := processStartTime(corePID); pErr == nil && alive {
									tracked[corePID] = trackedProcess{PID: corePID, StartSec: sec, StartUsec: usec}
								}
							}
						}
						recordHoldersFromStatus(tracked, status)
					}
					cancelStatus()
				}
				if rem := time.Until(gracefulDeadline); rem > 50*time.Millisecond {
					stopCtx, cancelStop := context.WithTimeout(context.Background(), min(1500*time.Millisecond, rem))
					_, _ = client.ServerStop(stopCtx)
					cancelStop()
				}
			}
		}
	}

	pids := make([]int, 0, len(tracked))
	for pid := range tracked {
		pids = append(pids, pid)
	}
	sort.Ints(pids)

	var errs []error
	for _, pid := range pids {
		if err := stopGroup(tracked[pid], deadline); err != nil {
			errs = append(errs, fmt.Errorf("pid %d: %w", pid, err))
		}
	}
	if len(errs) > 0 {
		// Retain sessionDir and owner.lock.json so ReapStaleSessions cleans it
		// up on the next start once surviving processes exit.
		return fmt.Errorf("herdr watchdog: processes not proven absent: %w", errors.Join(errs...))
	}
	if err := os.RemoveAll(sessionDir); err != nil {
		return fmt.Errorf("herdr watchdog: remove session dir: %w", err)
	}
	return nil
}

func readOwnerLockFromDirFD(dirFD int, sessionDir string, euid uint32) (ownerLockRecord, error) {
	lockFD, err := unix.Openat(dirFD, ownerLockFileName, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return ownerLockRecord{}, err
	}
	lockFile := os.NewFile(uintptr(lockFD), filepath.Join(sessionDir, ownerLockFileName))
	var lockStat unix.Stat_t
	statErr := unix.Fstat(lockFD, &lockStat)
	var rawLock []byte
	var readErr error
	if statErr == nil && lockStat.Mode&unix.S_IFMT == unix.S_IFREG && lockStat.Uid == euid && lockStat.Size >= 0 && lockStat.Size <= maxOwnerLockBytes {
		rawLock, readErr = io.ReadAll(io.LimitReader(lockFile, maxOwnerLockBytes+1))
	}
	_ = lockFile.Close()
	if statErr != nil {
		return ownerLockRecord{}, statErr
	}
	if readErr != nil {
		return ownerLockRecord{}, readErr
	}
	if len(rawLock) == 0 || len(rawLock) > maxOwnerLockBytes {
		return ownerLockRecord{}, fmt.Errorf("invalid owner lock size")
	}
	var rec ownerLockRecord
	if err := json.Unmarshal(rawLock, &rec); err != nil {
		return ownerLockRecord{}, err
	}
	if rec.Version != ownerLockVersion {
		return ownerLockRecord{}, fmt.Errorf("unsupported owner lock version %d", rec.Version)
	}
	if rec.SessionID == "" || rec.SessionID != filepath.Base(sessionDir) {
		return ownerLockRecord{}, fmt.Errorf("owner lock session id mismatch")
	}
	if rec.OwnerPID <= 1 || rec.OwnerPID > math.MaxInt32 || !hasStartTime(rec.OwnerStartSec, rec.OwnerStartUsec) {
		return ownerLockRecord{}, fmt.Errorf("owner lock missing owner identity")
	}
	return rec, nil
}
