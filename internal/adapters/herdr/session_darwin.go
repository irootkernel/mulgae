//go:build darwin && arm64

package herdr

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/irootkernel/mulgae/internal/ports"
	"golang.org/x/sys/unix"
)

const (
	defaultDaemonStartupTimeout = 10 * time.Second
	defaultTeardownTimeout      = 5 * time.Second
	defaultCheckInInterval      = 30 * time.Second
	defaultWatchdogStopTimeout  = 2 * time.Second
	staleMissingLockGrace       = 60 * time.Second
	ownerLockFileName           = "owner.lock.json"
	ownerLockVersion            = 1
	maxOwnerLockBytes           = 64 * 1024
	darwinProcessStateZombie    = 5
	processProbeInterval        = 15 * time.Millisecond
)

// ErrSessionClosed reports that Session.Close has started or completed and the
// session refuses any new terminal executions.
var ErrSessionClosed = errors.New("herdr session closed")

var sessionDirNameRegexp = regexp.MustCompile(`^[0-9a-f]{16}$`)

type sessionState uint8

const (
	sessionIdle sessionState = iota
	sessionStarting
	sessionRunning
	sessionClosing
	sessionClosed
)

type trackedProcess struct {
	PID       int   `json:"pid"`
	StartSec  int64 `json:"start_sec"`
	StartUsec int64 `json:"start_usec"`
}

type trackedPane struct {
	PID       int
	SID       int
	StartSec  int64
	StartUsec int64
	CreatedMS uint64
}

type ownerLockRecord struct {
	Version        int              `json:"version"`
	SessionID      string           `json:"session_id"`
	OwnerPID       int              `json:"owner_pid"`
	OwnerStartSec  int64            `json:"owner_start_sec"`
	OwnerStartUsec int64            `json:"owner_start_usec"`
	CorePID        int              `json:"core_pid,omitempty"`
	CoreStartSec   int64            `json:"core_start_sec,omitempty"`
	CoreStartUsec  int64            `json:"core_start_usec,omitempty"`
	Holders        []trackedProcess `json:"holders,omitempty"`
	SocketPath     string           `json:"socket_path"`
}

// SessionOptions configures one isolated per-run herdr-core session.
type SessionOptions struct {
	Clock                    ports.Clock
	LaunchBuilder            ports.PaneLaunchBuilder
	NativeHome               ports.AnchoredRoot
	ResolveOptions           *ResolveOptions
	ExcludedResolveRoots     []string
	BaseDir                  string
	InheritedHCSocket        string
	HasInheritedSocket       bool
	AmbientTerminalSocket    string
	HasAmbientTerminalSocket bool
	WatchdogExecutable       string
	DaemonStartupTimeout     time.Duration
	TeardownTimeout          time.Duration
	CheckInInterval          time.Duration
	DisableWatchdog          bool
	DisableStaleReaper       bool

	// Unexported test seams for deterministic offline tests.
	fakeSocketPath  string
	fakeExecutable  *ResolvedExecutable
	inspector       processInspector
	stopTrackedProc func(trackedProcess, time.Time) error
}

// Session manages one lazily started, isolated herdr-core daemon and implements
// ports.TerminalSessionRunner.
type Session struct {
	clock                 ports.Clock
	launchBuilder         ports.PaneLaunchBuilder
	nativeHome            ports.AnchoredRoot
	resolveOptions        *ResolveOptions
	excludedResolveRoots  []string
	baseDir               string
	inheritedHCSocket     string
	ambientTerminalSocket string
	watchdogExecutable    string
	daemonStartupTimeout  time.Duration
	teardownTimeout       time.Duration
	checkInInterval       time.Duration
	disableWatchdog       bool
	disableStaleReaper    bool
	fakeSocketPath        string
	fakeExecutable        *ResolvedExecutable
	inspector             processInspector
	stopTrackedProc       func(trackedProcess, time.Time) error

	sessionCtx    context.Context
	sessionCancel context.CancelFunc
	paneSeq       atomic.Uint64

	persistMu sync.Mutex

	mu                  sync.Mutex
	state               sessionState
	closeRequested      bool
	closeInFlight       bool
	dirRemovalStarted   bool
	closeDone           chan struct{}
	activeRuns          int
	runsIdleCh          chan struct{}
	startDone           chan struct{}
	startErr            error
	sessionID           string
	sessionDir          string
	socketPath          string
	panesDir            string
	executable          ResolvedExecutable
	identity            ports.TerminalRuntimeIdentity
	rpc                 *RPCClient
	coreCmd             *exec.Cmd
	coreWaitCh          chan error
	coreProc            trackedProcess
	ownerProc           trackedProcess
	holders             map[int]trackedProcess
	holdersGen          uint64
	persistedHoldersGen uint64
	trackedPanes        map[string]trackedPane
	watchdogCmd         *exec.Cmd
	watchdogPipe        *os.File
	watchdogWaitCh      chan error
}

var _ ports.TerminalSessionRunner = (*Session)(nil)

// NewSession validates configuration for an isolated herdr-core session without
// touching the filesystem or starting a daemon.
func NewSession(opts SessionOptions) (*Session, error) {
	if opts.Clock == nil {
		return nil, fmt.Errorf("herdr session: nil clock")
	}
	if opts.LaunchBuilder == nil {
		return nil, fmt.Errorf("herdr session: nil pane launch builder")
	}
	if !opts.NativeHome.Valid() {
		return nil, fmt.Errorf("herdr session: invalid native home")
	}
	baseDir := opts.BaseDir
	if baseDir == "" {
		baseDir = fmt.Sprintf("/private/tmp/mgh-%d", unix.Geteuid())
	}
	if !validCanonicalAbsolutePath(baseDir) {
		return nil, fmt.Errorf("herdr session: invalid base directory")
	}
	inheritedSocket := opts.InheritedHCSocket
	if !opts.HasInheritedSocket {
		inheritedSocket = os.Getenv("HC_SOCKET")
	}
	ambientTerminalSocket := opts.AmbientTerminalSocket
	if !opts.HasAmbientTerminalSocket {
		ambientTerminalSocket = os.Getenv("HC_TERMINAL_SOCKET")
	}
	startupTimeout := opts.DaemonStartupTimeout
	if startupTimeout <= 0 {
		startupTimeout = defaultDaemonStartupTimeout
	}
	teardownTimeout := opts.TeardownTimeout
	if teardownTimeout <= 0 {
		teardownTimeout = defaultTeardownTimeout
	}
	checkInInterval := opts.CheckInInterval
	if checkInInterval <= 0 {
		checkInInterval = defaultCheckInInterval
	}
	inspector := opts.inspector
	if inspector == nil {
		inspector = darwinProcessInspector{}
	}
	var resolveCopy *ResolveOptions
	if opts.ResolveOptions != nil {
		copied := *opts.ResolveOptions
		copied.ExcludedRoots = append([]string(nil), copied.ExcludedRoots...)
		resolveCopy = &copied
	}
	sessionCtx, sessionCancel := context.WithCancel(context.Background())
	return &Session{
		clock:                 opts.Clock,
		launchBuilder:         opts.LaunchBuilder,
		nativeHome:            opts.NativeHome,
		resolveOptions:        resolveCopy,
		excludedResolveRoots:  append([]string(nil), opts.ExcludedResolveRoots...),
		baseDir:               baseDir,
		inheritedHCSocket:     inheritedSocket,
		ambientTerminalSocket: ambientTerminalSocket,
		watchdogExecutable:    opts.WatchdogExecutable,
		daemonStartupTimeout:  startupTimeout,
		teardownTimeout:       teardownTimeout,
		checkInInterval:       checkInInterval,
		disableWatchdog:       opts.DisableWatchdog,
		disableStaleReaper:    opts.DisableStaleReaper,
		fakeSocketPath:        opts.fakeSocketPath,
		fakeExecutable:        opts.fakeExecutable,
		inspector:             inspector,
		stopTrackedProc:       opts.stopTrackedProc,
		sessionCtx:            sessionCtx,
		sessionCancel:         sessionCancel,
		state:                 sessionIdle,
		holders:               make(map[int]trackedProcess),
		trackedPanes:          make(map[string]trackedPane),
	}, nil
}

func (s *Session) recordTrackedPane(paneID string, pane trackedPane) {
	if s == nil || paneID == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cur := s.trackedPanes[paneID]
	if validTargetPID(pane.PID) {
		cur.PID = pane.PID
	}
	if pane.SID > 1 && pane.SID <= math.MaxInt32 {
		cur.SID = pane.SID
	}
	if hasStartTime(pane.StartSec, pane.StartUsec) {
		cur.StartSec = pane.StartSec
		cur.StartUsec = pane.StartUsec
	}
	if pane.CreatedMS > 0 {
		cur.CreatedMS = pane.CreatedMS
	}
	s.trackedPanes[paneID] = cur
}

func (s *Session) lookupTrackedPane(paneID string) (trackedPane, bool) {
	if s == nil || paneID == "" {
		return trackedPane{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	pane, ok := s.trackedPanes[paneID]
	return pane, ok
}

func (s *Session) clearTrackedPane(paneID string) {
	if s == nil || paneID == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.trackedPanes, paneID)
}

// SessionDir returns the canonical private session directory once started, or
// empty string if not yet started.
func (s *Session) SessionDir() string {
	if s == nil {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sessionDir
}

// SocketPath returns the isolated HC_SOCKET path once started, or empty string
// if not yet started.
func (s *Session) SocketPath() string {
	if s == nil {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.socketPath
}

// CorePID returns the tracked foreground herdr-core daemon PID once started.
func (s *Session) CorePID() int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.coreProc.PID
}

// HolderPIDs returns a sorted snapshot of tracked holder PIDs observed for this
// session.
func (s *Session) HolderPIDs() []int {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	pids := make([]int, 0, len(s.holders))
	for pid := range s.holders {
		pids = append(pids, pid)
	}
	sort.Ints(pids)
	return pids
}

// RuntimeIdentity returns the verified herdr-core binary + protocol handshake
// identity, lazily starting the isolated daemon if it has not started yet.
func (s *Session) RuntimeIdentity(ctx context.Context) (ports.TerminalRuntimeIdentity, error) {
	if s == nil {
		return ports.TerminalRuntimeIdentity{}, fmt.Errorf("herdr session: nil session")
	}
	if ctx == nil {
		return ports.TerminalRuntimeIdentity{}, fmt.Errorf("herdr session: nil context")
	}
	if err := ctx.Err(); err != nil {
		return ports.TerminalRuntimeIdentity{}, err
	}
	if err := s.ensureStarted(ctx); err != nil {
		return ports.TerminalRuntimeIdentity{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.identity.Valid() {
		return ports.TerminalRuntimeIdentity{}, fmt.Errorf("herdr session: runtime identity unavailable")
	}
	return s.identity, nil
}

func (s *Session) ensureStarted(ctx context.Context) error {
	for {
		s.mu.Lock()
		switch s.state {
		case sessionRunning:
			if s.closeRequested {
				s.mu.Unlock()
				return ErrSessionClosed
			}
			s.mu.Unlock()
			return nil
		case sessionClosing, sessionClosed:
			s.mu.Unlock()
			return ErrSessionClosed
		case sessionStarting:
			done := s.startDone
			s.mu.Unlock()
			select {
			case <-done:
				continue
			case <-ctx.Done():
				return ctx.Err()
			}
		case sessionIdle:
			if s.closeRequested {
				s.state = sessionClosed
				s.mu.Unlock()
				return ErrSessionClosed
			}
			s.state = sessionStarting
			s.startDone = make(chan struct{})
			s.startErr = nil
			done := s.startDone
			s.mu.Unlock()

			startCtx, cancelStart := context.WithCancel(ctx)
			stopSessionCancel := context.AfterFunc(s.sessionCtx, cancelStart)
			retained, err := s.startLockedOwner(startCtx)
			stopSessionCancel()
			cancelStart()

			s.mu.Lock()
			s.startErr = err
			switch {
			case err != nil && retained:
				// Surviving core/watchdog/sessionDir retained for Session.Close()
				// retry even if s.closeRequested is already true.
				s.state = sessionClosing
			case err != nil:
				if s.closeRequested {
					s.state = sessionClosed
				} else {
					s.state = sessionIdle
				}
			case s.closeRequested:
				s.state = sessionClosing
			default:
				s.state = sessionRunning
			}
			close(done)
			closing := s.closeRequested
			s.mu.Unlock()

			if err != nil {
				if closing && !retained {
					return ErrSessionClosed
				}
				return err
			}
			if closing {
				return ErrSessionClosed
			}
			return nil
		}
	}
}

func (s *Session) startLockedOwner(ctx context.Context) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	euid := uint32(unix.Geteuid())

	var resolved ResolvedExecutable
	if s.fakeExecutable != nil {
		resolved = *s.fakeExecutable
	} else {
		opts := DefaultResolveOptions(s.nativeHome.String(), s.excludedResolveRoots...)
		if s.resolveOptions != nil {
			opts = *s.resolveOptions
		}
		var err error
		resolved, err = ResolveExecutable(opts)
		if err != nil {
			return false, fmt.Errorf("herdr session: resolve executable: %w", err)
		}
	}

	if err := ensurePrivateBaseDir(s.baseDir, euid); err != nil {
		return false, fmt.Errorf("herdr session: prepare base dir: %w", err)
	}
	if !s.disableStaleReaper {
		reapCtx, cancel := context.WithTimeout(ctx, s.teardownTimeout)
		_ = ReapStaleSessions(reapCtx, s.baseDir)
		cancel()
	}

	sessionID, err := randomHexBytes(8)
	if err != nil {
		return false, fmt.Errorf("herdr session: generate session id: %w", err)
	}
	sessionDir := filepath.Join(s.baseDir, sessionID)
	panesDir := filepath.Join(sessionDir, "panes")
	stateDir := filepath.Join(sessionDir, "state")
	cfgDir := filepath.Join(sessionDir, "cfg")
	herdrCfgDir := filepath.Join(cfgDir, "herdr-core")

	if err := createVerifiedPrivateDir(sessionDir, euid); err != nil {
		return false, fmt.Errorf("herdr session: create session dir: %w", err)
	}
	cleanupDir := true
	defer func() {
		if cleanupDir {
			_ = os.RemoveAll(sessionDir)
		}
	}()
	for _, sub := range []string{panesDir, stateDir, cfgDir, herdrCfgDir} {
		if err := createVerifiedPrivateDir(sub, euid); err != nil {
			return false, fmt.Errorf("herdr session: create private subdir: %w", err)
		}
	}

	configContent := "notes = false\ndraft_wait = 0\nnotes_quiet = 0\n"
	if err := writePrivateFileAtomic(filepath.Join(herdrCfgDir, "config.toml"), []byte(configContent), 0o600); err != nil {
		return false, fmt.Errorf("herdr session: write config.toml: %w", err)
	}

	socketPath := filepath.Join(sessionDir, "s.sock")
	if s.fakeSocketPath != "" {
		socketPath = s.fakeSocketPath
	}

	ownerPID := os.Getpid()
	ownerSec, ownerUsec, alive, err := processStartTime(ownerPID)
	if err != nil || !alive {
		return false, fmt.Errorf("herdr session: inspect owner process start time: %w", err)
	}
	ownerProc := trackedProcess{PID: ownerPID, StartSec: ownerSec, StartUsec: ownerUsec}

	if err := writeOwnerLockAtomic(sessionDir, ownerLockRecord{
		Version:        ownerLockVersion,
		SessionID:      sessionID,
		OwnerPID:       ownerProc.PID,
		OwnerStartSec:  ownerProc.StartSec,
		OwnerStartUsec: ownerProc.StartUsec,
		SocketPath:     socketPath,
	}); err != nil {
		return false, fmt.Errorf("herdr session: write owner lock: %w", err)
	}

	var (
		rpcClient      *RPCClient
		coreCmd        *exec.Cmd
		coreWaitCh     chan error
		coreProc       trackedProcess
		coreOutput     boundedBuffer
		watchdogCmd    *exec.Cmd
		watchdogPipe   *os.File
		watchdogWaitCh chan error
		retained       bool
	)

	stopStarted := func() error {
		var stopErr error
		waitDone := true
		if coreProc.PID != 0 {
			stopDeadline := time.Now().Add(s.teardownTimeout)
			stopProc := s.stopTrackedProc
			if stopProc == nil {
				stopProc = ensureTrackedProcessGroupStopped
			}
			stopErr = stopProc(coreProc, stopDeadline)
			if !waitCoreExit(coreWaitCh, stopDeadline) {
				waitDone = false
				if stopErr == nil {
					stopErr = fmt.Errorf("herdr session: daemon wait did not complete during startup abort")
				}
			}
		}
		if stopErr != nil || !waitDone {
			// Retain sessionDir, owner.lock.json, and live watchdog so both
			// parent-death cleanup and Session.Close() can retry teardown until
			// ESRCH is proven.
			cleanupDir = false
			retained = true
			s.mu.Lock()
			s.sessionID = sessionID
			s.sessionDir = sessionDir
			s.socketPath = socketPath
			s.panesDir = panesDir
			s.executable = resolved
			s.rpc = rpcClient
			s.coreCmd = coreCmd
			s.coreWaitCh = coreWaitCh
			s.coreProc = coreProc
			s.ownerProc = ownerProc
			s.watchdogCmd = watchdogCmd
			s.watchdogPipe = watchdogPipe
			s.watchdogWaitCh = watchdogWaitCh
			s.mu.Unlock()
			return stopErr
		}
		stopWatchdogCleanly(watchdogCmd, watchdogPipe, watchdogWaitCh)
		return nil
	}

	if s.fakeSocketPath == "" {
		coreCmd = exec.Command(resolved.Path, "serve")
		coreCmd.Dir = sessionDir
		coreCmd.Env = []string{
			"PATH=/usr/bin:/bin",
			"HOME=" + sessionDir,
			"TMPDIR=" + sessionDir,
			"HC_SOCKET=" + socketPath,
			"HC_SESSION=mulgae-" + sessionID,
			"XDG_STATE_HOME=" + stateDir,
			"XDG_CONFIG_HOME=" + cfgDir,
			"SSH_CONNECTION=1",
		}
		coreCmd.Stdin = nil
		coreCmd.Stdout = &coreOutput
		coreCmd.Stderr = &coreOutput
		coreCmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		if err := coreCmd.Start(); err != nil {
			return false, fmt.Errorf("herdr session: start daemon: %w", err)
		}
		if !validTargetPID(coreCmd.Process.Pid) {
			_ = coreCmd.Wait()
			return false, fmt.Errorf("herdr session: invalid daemon pid %d", coreCmd.Process.Pid)
		}
		// Inspect P_starttime BEFORE starting cmd.Wait() so even an immediate
		// crash remains an un-reaped zombie whose PID cannot be recycled yet.
		cInfo, cErr := inspectProcess(coreCmd.Process.Pid)
		if cErr != nil || !cInfo.Exists || !hasStartTime(cInfo.StartSec, cInfo.StartUsec) {
			_ = unix.Kill(-coreCmd.Process.Pid, unix.SIGKILL)
			_ = coreCmd.Wait()
			return false, fmt.Errorf("herdr session: inspect daemon start time (pid=%d exists=%t): %w", coreCmd.Process.Pid, cInfo.Exists, cErr)
		}
		coreProc = trackedProcess{
			PID:       coreCmd.Process.Pid,
			StartSec:  cInfo.StartSec,
			StartUsec: cInfo.StartUsec,
		}
		coreWaitCh = make(chan error, 1)
		go func(cmd *exec.Cmd, ch chan<- error) {
			ch <- cmd.Wait()
			close(ch)
		}(coreCmd, coreWaitCh)

		if err := writeOwnerLockAtomic(sessionDir, ownerLockRecord{
			Version:        ownerLockVersion,
			SessionID:      sessionID,
			OwnerPID:       ownerProc.PID,
			OwnerStartSec:  ownerProc.StartSec,
			OwnerStartUsec: ownerProc.StartUsec,
			CorePID:        coreProc.PID,
			CoreStartSec:   coreProc.StartSec,
			CoreStartUsec:  coreProc.StartUsec,
			SocketPath:     socketPath,
		}); err != nil {
			abortErr := stopStarted()
			return retained, errors.Join(fmt.Errorf("herdr session: update owner lock: %w", err), abortErr)
		}

		if !s.disableWatchdog {
			wdCmd, wdPipe, wdWaitCh, wdErr := startParentDeathWatchdog(s.watchdogExecutable, sessionDir)
			if wdErr != nil {
				abortErr := stopStarted()
				return retained, errors.Join(fmt.Errorf("herdr session: start watchdog: %w", wdErr), abortErr)
			}
			watchdogCmd = wdCmd
			watchdogPipe = wdPipe
			watchdogWaitCh = wdWaitCh
		}
	}

	rpcClient, err = NewRPCClient(socketPath, defaultRPCCallTimeout)
	if err != nil {
		abortErr := stopStarted()
		return retained, errors.Join(err, abortErr)
	}

	helloCtx, cancelHello := context.WithTimeout(ctx, s.daemonStartupTimeout)
	defer cancelHello()
	helloRes, err := waitForDaemonHello(helloCtx, rpcClient, coreWaitCh, &coreOutput)
	if err != nil {
		abortErr := stopStarted()
		return retained, errors.Join(fmt.Errorf("herdr session: daemon handshake: %w", err), abortErr)
	}

	identity, err := ports.NewTerminalRuntimeIdentity(resolved.Path, resolved.SHA256, helloRes.Version, int(helloRes.Generation))
	if err != nil {
		abortErr := stopStarted()
		return retained, errors.Join(fmt.Errorf("herdr session: runtime identity: %w", err), abortErr)
	}

	holders := make(map[int]trackedProcess)
	if status, statusErr := rpcClient.ServerStatus(helloCtx); statusErr == nil {
		if statusPID, ok := uint32ToValidPID(status.PID); ok && (coreProc.PID == 0 || !hasStartTime(coreProc.StartSec, coreProc.StartUsec)) {
			if cSec, cUsec, cAlive, cErr := processStartTime(statusPID); cErr == nil && cAlive {
				coreProc = trackedProcess{PID: statusPID, StartSec: cSec, StartUsec: cUsec}
			}
		}
		recordHoldersFromStatus(holders, status)
	}

	s.mu.Lock()
	s.sessionID = sessionID
	s.sessionDir = sessionDir
	s.socketPath = socketPath
	s.panesDir = panesDir
	s.executable = resolved
	s.identity = identity
	s.rpc = rpcClient
	s.coreCmd = coreCmd
	s.coreWaitCh = coreWaitCh
	s.coreProc = coreProc
	s.ownerProc = ownerProc
	s.holders = holders
	if len(holders) > 0 {
		s.holdersGen++
	}
	s.watchdogCmd = watchdogCmd
	s.watchdogPipe = watchdogPipe
	s.watchdogWaitCh = watchdogWaitCh
	s.mu.Unlock()

	if s.fakeSocketPath == "" {
		s.persistTrackingFiles()
	}

	cleanupDir = false
	return false, nil
}

func waitForDaemonHello(ctx context.Context, client *RPCClient, coreWaitCh <-chan error, output *boundedBuffer) (HelloResult, error) {
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()

	var lastErr error
	for {
		callCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		res, err := client.Hello(callCtx)
		cancel()
		if err == nil {
			return res, nil
		}
		var handshakeErr *ProtocolHandshakeError
		if errors.As(err, &handshakeErr) {
			return HelloResult{}, err
		}
		lastErr = err

		if coreWaitCh != nil {
			select {
			case waitErr := <-coreWaitCh:
				return HelloResult{}, fmt.Errorf("herdr-core exited during startup (err=%v): %s", waitErr, strings.TrimSpace(output.String()))
			default:
			}
		}

		select {
		case <-ctx.Done():
			if lastErr != nil {
				return HelloResult{}, fmt.Errorf("%w (last handshake error: %v)", ctx.Err(), lastErr)
			}
			return HelloResult{}, ctx.Err()
		case <-ticker.C:
		}
	}
}

func (s *Session) refreshHolders(ctx context.Context) {
	s.mu.Lock()
	client := s.rpc
	fake := s.fakeSocketPath != ""
	s.mu.Unlock()
	if client == nil {
		return
	}
	callCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	status, err := client.ServerStatus(callCtx)
	if err != nil {
		return
	}
	s.mu.Lock()
	changed := recordHoldersFromStatus(s.holders, status)
	if changed {
		s.holdersGen++
	}
	s.mu.Unlock()
	if changed && !fake {
		s.persistTrackingFiles()
	}
}

// recordHoldersFromStatus merges live holders validated with P_starttime into
// dst and prunes previously tracked holders that are no longer reported AND
// proven absent so s.holders never grows unboundedly.
func recordHoldersFromStatus(dst map[int]trackedProcess, status StatusResult) bool {
	changed := false
	reported := make(map[int]struct{}, len(status.Holders)+1)
	addHolder := func(rawPID uint32) {
		pid, ok := uint32ToValidPID(rawPID)
		if !ok {
			return
		}
		reported[pid] = struct{}{}
		if existing, exists := dst[pid]; exists && hasStartTime(existing.StartSec, existing.StartUsec) {
			if matched, err := processMatchesStartTime(pid, existing.StartSec, existing.StartUsec); err == nil && matched {
				return
			}
		}
		sec, usec, alive, err := processStartTime(pid)
		if err != nil || !alive || !hasStartTime(sec, usec) {
			return
		}
		next := trackedProcess{PID: pid, StartSec: sec, StartUsec: usec}
		if existing, exists := dst[pid]; !exists || existing != next {
			dst[pid] = next
			changed = true
		}
	}
	if status.Holder != nil {
		addHolder(status.Holder.PID)
	}
	for _, holder := range status.Holders {
		addHolder(holder.PID)
	}
	for pid, proc := range dst {
		if _, stillReported := reported[pid]; stillReported {
			continue
		}
		state, err := inspectTrackedProcessGroup(proc)
		if err == nil && !state.groupStillExists {
			delete(dst, pid)
			changed = true
		}
	}
	return changed
}

func (s *Session) persistTrackingFiles() {
	_ = s.persistTrackingFilesMode(false)
}

func (s *Session) persistTrackingFilesMode(allowCloseInFlight bool) bool {
	s.persistMu.Lock()
	defer s.persistMu.Unlock()

	s.mu.Lock()
	if s.sessionDir == "" || s.state == sessionClosed || s.dirRemovalStarted || (!allowCloseInFlight && s.closeInFlight) {
		s.mu.Unlock()
		return false
	}
	sessionDir := s.sessionDir
	sessionID := s.sessionID
	socketPath := s.socketPath
	ownerProc := s.ownerProc
	coreProc := s.coreProc
	snapGen := s.holdersGen
	holders := make([]trackedProcess, 0, len(s.holders))
	for _, h := range s.holders {
		if validTargetPID(h.PID) && hasStartTime(h.StartSec, h.StartUsec) {
			holders = append(holders, h)
		}
	}
	s.mu.Unlock()

	sort.Slice(holders, func(i, j int) bool { return holders[i].PID < holders[j].PID })

	rec := ownerLockRecord{
		Version:        ownerLockVersion,
		SessionID:      sessionID,
		OwnerPID:       ownerProc.PID,
		OwnerStartSec:  ownerProc.StartSec,
		OwnerStartUsec: ownerProc.StartUsec,
		Holders:        holders,
		SocketPath:     socketPath,
	}
	if validTargetPID(coreProc.PID) && hasStartTime(coreProc.StartSec, coreProc.StartUsec) {
		rec.CorePID = coreProc.PID
		rec.CoreStartSec = coreProc.StartSec
		rec.CoreStartUsec = coreProc.StartUsec
	}
	if writeOwnerLockAtomic(sessionDir, rec) != nil {
		return false
	}
	s.mu.Lock()
	if snapGen > s.persistedHoldersGen {
		s.persistedHoldersGen = snapGen
	}
	s.mu.Unlock()
	return true
}

func (s *Session) hasUnstoppedHoldersLocked(stoppedHolders map[int]trackedProcess, fake bool) bool {
	if fake && s.stopTrackedProc == nil {
		return false
	}
	for pid, proc := range s.holders {
		if prev, ok := stoppedHolders[pid]; !ok || prev != proc {
			return true
		}
	}
	return false
}

// Close idempotently stops the isolated herdr-core daemon, its holder(s), and
// remaining panes, verifies that both core and holder PIDs reach ESRCH, stops
// the watchdog, and removes the private session directory. Calling Close on a
// session that was never started is a safe no-op that prevents future runs.
func (s *Session) Close(ctx context.Context) error {
	if s == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}

	s.sessionCancel()

	for {
		s.mu.Lock()
		switch s.state {
		case sessionClosed:
			s.mu.Unlock()
			return nil
		case sessionIdle:
			s.state = sessionClosed
			s.closeRequested = true
			s.mu.Unlock()
			return nil
		case sessionStarting:
			s.closeRequested = true
			done := s.startDone
			s.mu.Unlock()
			select {
			case <-done:
				continue
			case <-ctx.Done():
				return ctx.Err()
			}
		case sessionRunning, sessionClosing:
			s.state = sessionClosing
			s.closeRequested = true
			if s.closeInFlight {
				closeDone := s.closeDone
				s.mu.Unlock()
				select {
				case <-closeDone:
					continue
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			s.closeInFlight = true
			closeDone := make(chan struct{})
			s.closeDone = closeDone

			var waitRunsCh chan struct{}
			if s.activeRuns > 0 {
				if s.runsIdleCh == nil {
					s.runsIdleCh = make(chan struct{})
				}
				waitRunsCh = s.runsIdleCh
			}
			s.mu.Unlock()

			closeBudget := s.teardownTimeout
			if dl, ok := ctx.Deadline(); ok {
				if rem := time.Until(dl); rem < closeBudget {
					closeBudget = max(0, rem)
				}
			}
			closeDeadline := time.Now().Add(closeBudget)

			if waitRunsCh != nil {
				// Reserve at least half of closeBudget for performClose so an
				// active run cannot starve daemon/holder teardown and ESRCH proof.
				waitBudget := closeBudget / 2
				if waitBudget > 0 {
					timer := time.NewTimer(waitBudget)
					select {
					case <-waitRunsCh:
						timer.Stop()
					case <-timer.C:
					}
				}
			}

			stoppedHolders := make(map[int]trackedProcess)
			rpcDone := false
			coreStopped := false
			var closeErr error
			var sessionDir string
			var fake bool
			var watchdogCmd *exec.Cmd
			var watchdogPipe *os.File
			var watchdogWaitCh chan error

			for {
				s.mu.Lock()
				rpc := s.rpc
				if rpcDone {
					rpc = nil
				}
				coreWaitCh := s.coreWaitCh
				coreProc := s.coreProc
				if coreStopped {
					coreWaitCh = nil
					coreProc = trackedProcess{}
				}
				sessionDir = s.sessionDir
				fake = s.fakeSocketPath != ""
				holders := make(map[int]trackedProcess, len(s.holders))
				for pid, proc := range s.holders {
					if prev, ok := stoppedHolders[pid]; ok && prev == proc {
						continue
					}
					holders[pid] = proc
				}
				trackedPanes := make(map[string]trackedPane, len(s.trackedPanes))
				for paneID, pane := range s.trackedPanes {
					trackedPanes[paneID] = pane
				}
				watchdogCmd = s.watchdogCmd
				watchdogPipe = s.watchdogPipe
				watchdogWaitCh = s.watchdogWaitCh
				s.mu.Unlock()

				res := s.performClose(closeDeadline, rpc, coreWaitCh, coreProc, holders, trackedPanes, fake)
				rpcDone = true
				if res.coreStopped {
					coreStopped = true
				}
				for pid, proc := range res.stoppedHolders {
					stoppedHolders[pid] = proc
				}

				s.mu.Lock()
				for pid, proc := range res.prunedHolders {
					if existing, exists := s.holders[pid]; exists && existing == proc {
						delete(s.holders, pid)
						s.holdersGen++
					}
				}
				for pid, proc := range res.discoveredHolders {
					if validTargetPID(pid) && hasStartTime(proc.StartSec, proc.StartUsec) {
						if existing, exists := s.holders[pid]; exists {
							if startStrictlyBefore(existing.StartSec, existing.StartUsec, proc.StartSec, proc.StartUsec) {
								s.holders[pid] = proc
								s.holdersGen++
							}
						} else if stopped, wasStopped := res.stoppedHolders[pid]; !wasStopped || stopped != proc {
							s.holders[pid] = proc
							s.holdersGen++
						}
					}
				}
				for _, paneID := range res.verifiedAbsentPanes {
					delete(s.trackedPanes, paneID)
				}
				for paneID, pane := range res.unverifiedPanes {
					cur := s.trackedPanes[paneID]
					s.trackedPanes[paneID] = mergeTrackedPane(cur, pane.PID, pane.SID, pane.StartSec, pane.StartUsec, pane.CreatedMS)
				}

				hasUnstoppedHolders := s.hasUnstoppedHoldersLocked(stoppedHolders, fake)
				remainingPanes := len(s.trackedPanes)

				if res.err != nil {
					closeErr = res.err
					s.mu.Unlock()
					break
				}
				if remainingPanes == 0 && !hasUnstoppedHolders {
					closeErr = nil
					s.mu.Unlock()
					break
				}
				if !time.Now().Before(closeDeadline) {
					var remErrs []error
					if remainingPanes > 0 {
						remErrs = append(remErrs, fmt.Errorf("herdr session close: %d tracked pane(s) remained unverified before deadline", remainingPanes))
					}
					if hasUnstoppedHolders {
						remErrs = append(remErrs, fmt.Errorf("herdr session close: newly discovered holder(s) remained unstopped before deadline"))
					}
					closeErr = errors.Join(remErrs...)
					s.mu.Unlock()
					break
				}
				s.mu.Unlock()
			}

			watchdogStopped := false
			if closeErr == nil {
				// Serialize against persistTrackingFiles (lock order: persistMu -> mu)
				// and verify neither late tracked panes nor unstopped holders arrived
				// before committing to directory removal and stopping the watchdog.
				s.persistMu.Lock()
				s.mu.Lock()
				latePanes := len(s.trackedPanes)
				lateHolders := s.hasUnstoppedHoldersLocked(stoppedHolders, fake)
				committed := latePanes == 0 && !lateHolders
				if committed && sessionDir != "" {
					s.dirRemovalStarted = true
				}
				s.mu.Unlock()
				s.persistMu.Unlock()
				if !committed {
					var lateErrs []error
					if latePanes > 0 {
						lateErrs = append(lateErrs, fmt.Errorf("herdr session close: %d tracked pane(s) arrived before directory removal", latePanes))
					}
					if lateHolders {
						lateErrs = append(lateErrs, fmt.Errorf("herdr session close: unstopped holder(s) arrived before directory removal"))
					}
					closeErr = errors.Join(lateErrs...)
				} else {
					stopWatchdogCleanly(watchdogCmd, watchdogPipe, watchdogWaitCh)
					watchdogStopped = true
					if sessionDir != "" {
						if rmErr := os.RemoveAll(sessionDir); rmErr != nil {
							closeErr = fmt.Errorf("herdr session close: remove session dir: %w", rmErr)
						}
					}
				}
			}

			s.mu.Lock()
			for closeErr != nil && !s.dirRemovalStarted && !fake && s.holdersGen != s.persistedHoldersGen {
				s.mu.Unlock()
				if !s.persistTrackingFilesMode(true) {
					s.mu.Lock()
					break
				}
				s.mu.Lock()
			}
			if watchdogStopped {
				s.watchdogCmd = nil
				s.watchdogPipe = nil
				s.watchdogWaitCh = nil
			}
			if closeErr == nil {
				latePanes := len(s.trackedPanes)
				lateHolders := s.hasUnstoppedHoldersLocked(stoppedHolders, fake)
				if latePanes > 0 || lateHolders {
					var lateErrs []error
					if latePanes > 0 {
						lateErrs = append(lateErrs, fmt.Errorf("herdr session close: %d tracked pane(s) arrived during finalization", latePanes))
					}
					if lateHolders {
						lateErrs = append(lateErrs, fmt.Errorf("herdr session close: unstopped holder(s) arrived during finalization"))
					}
					closeErr = errors.Join(lateErrs...)
				}
			}
			if closeErr == nil {
				s.state = sessionClosed
				s.coreCmd = nil
				s.coreWaitCh = nil
				s.rpc = nil
			}
			s.closeInFlight = false
			close(closeDone)
			s.closeDone = nil
			s.mu.Unlock()

			return closeErr
		}
	}
}

type closeAttemptResult struct {
	coreStopped         bool
	discoveredHolders   map[int]trackedProcess
	prunedHolders       map[int]trackedProcess
	stoppedHolders      map[int]trackedProcess
	unverifiedPanes     map[string]trackedPane
	verifiedAbsentPanes []string
	err                 error
}

func (s *Session) performClose(
	teardownDeadline time.Time,
	rpc *RPCClient,
	coreWaitCh chan error,
	coreProc trackedProcess,
	holders map[int]trackedProcess,
	trackedPanes map[string]trackedPane,
	fake bool,
) closeAttemptResult {
	remainingBudget := max(0, time.Until(teardownDeadline))
	teardownCtx, cancel := context.WithDeadline(context.Background(), teardownDeadline)
	defer cancel()

	// Always reserve a post-SIGKILL settle window so graceful RPC / wait calls
	// never exhaust teardownDeadline before escalation can complete.
	sigkillReserve := min(500*time.Millisecond, remainingBudget/3)
	gracefulDeadline := teardownDeadline.Add(-sigkillReserve)

	initialHolders := make(map[int]trackedProcess, len(holders))
	for pid, proc := range holders {
		initialHolders[pid] = proc
	}
	prunedHolders := make(map[int]trackedProcess)

	var errs []error
	if rpc != nil {
		if rem := time.Until(gracefulDeadline); rem > 50*time.Millisecond {
			statusCtx, cancelStatus := context.WithTimeout(teardownCtx, min(time.Second, rem/3))
			if status, err := rpc.ServerStatus(statusCtx); err == nil {
				recordHoldersFromStatus(holders, status)
				for pid, proc := range initialHolders {
					if _, stillPresent := holders[pid]; !stillPresent {
						prunedHolders[pid] = proc
					}
				}
			}
			cancelStatus()
		}

		if rem := time.Until(gracefulDeadline); rem > 50*time.Millisecond {
			listCtx, cancelList := context.WithTimeout(teardownCtx, min(time.Second, rem/3))
			if listRes, err := rpc.TerminalList(listCtx, ListParams{All: true}); err == nil {
				for idx, term := range listRes.Terminals {
					paneID := term.Address
					termPID := terminalPID(term)
					if !ports.ValidTerminalPaneID(paneID) {
						errs = append(errs, fmt.Errorf("herdr session close: invalid pane address %q", paneID))
						if validTargetPID(termPID) {
							alreadyTrackedPID := false
							for _, existing := range trackedPanes {
								if existing.PID == termPID {
									alreadyTrackedPID = true
									break
								}
							}
							if !alreadyTrackedPID {
								pane := trackedPane{
									PID:       termPID,
									SID:       s.capturePaneSID(termPID),
									CreatedMS: term.CreatedMS,
								}
								if term.State != "finished" {
									pane.StartSec, pane.StartUsec = s.capturePaneStartTime(termPID, term.CreatedMS)
								}
								trackedPanes[fmt.Sprintf("invalid-address-close-%d-%d", idx, termPID)] = pane
							}
						}
						continue
					}
					existing, alreadyTracked := trackedPanes[paneID]
					if alreadyTracked || term.State != "finished" || term.PID != nil {
						pane := mergeTrackedPane(existing, termPID, 0, 0, 0, term.CreatedMS)
						if validTargetPID(pane.PID) {
							if pane.SID == 0 {
								pane.SID = s.capturePaneSID(pane.PID)
							}
							if term.State != "finished" && !hasStartTime(pane.StartSec, pane.StartUsec) {
								pane.StartSec, pane.StartUsec = s.capturePaneStartTime(pane.PID, pane.CreatedMS)
							}
						}
						trackedPanes[paneID] = pane
					}
				}
			}
			cancelList()
		}

		if rem := time.Until(gracefulDeadline); rem > 50*time.Millisecond {
			stopCtx, cancelStop := context.WithTimeout(teardownCtx, min(1500*time.Millisecond, rem))
			_, _ = rpc.ServerStop(stopCtx)
			cancelStop()
		}
	}

	stopProc := s.stopTrackedProc
	if stopProc == nil {
		stopProc = ensureTrackedProcessGroupStopped
	}

	coreStopped := true
	stoppedHolders := make(map[int]trackedProcess, len(holders)+len(prunedHolders))
	for pid, proc := range prunedHolders {
		stoppedHolders[pid] = proc
	}
	if !fake || s.stopTrackedProc != nil {
		if coreWaitCh != nil {
			if grace := time.Until(gracefulDeadline); grace > 0 {
				_ = waitCoreExit(coreWaitCh, gracefulDeadline)
			}
		}

		if coreProc.PID != 0 {
			if err := stopProc(coreProc, teardownDeadline); err != nil {
				coreStopped = false
				errs = append(errs, fmt.Errorf("herdr session close: core pid %d: %w", coreProc.PID, err))
			}
		}
		if !waitCoreExit(coreWaitCh, teardownDeadline) {
			coreStopped = false
			errs = append(errs, fmt.Errorf("herdr session close: core wait did not complete"))
		}

		holderPIDs := make([]int, 0, len(holders))
		for pid := range holders {
			holderPIDs = append(holderPIDs, pid)
		}
		sort.Ints(holderPIDs)
		for _, pid := range holderPIDs {
			proc := holders[pid]
			if err := stopProc(proc, teardownDeadline); err != nil {
				errs = append(errs, fmt.Errorf("herdr session close: holder pid %d: %w", pid, err))
				continue
			}
			stoppedHolders[pid] = proc
		}
	} else {
		for pid, proc := range holders {
			stoppedHolders[pid] = proc
		}
	}

	paneIDs := make([]string, 0, len(trackedPanes))
	for paneID := range trackedPanes {
		paneIDs = append(paneIDs, paneID)
	}
	sort.Strings(paneIDs)
	var verifiedAbsentPanes []string
	unverifiedPanes := make(map[string]trackedPane)
	for _, paneID := range paneIDs {
		pane := trackedPanes[paneID]
		if _, err := s.verifyPaneProcessGroupAndSessionAbsent(pane, teardownDeadline, true, 0); err != nil {
			errs = append(errs, fmt.Errorf("herdr session close: pane %s: %w", paneID, err))
			unverifiedPanes[paneID] = pane
			continue
		}
		verifiedAbsentPanes = append(verifiedAbsentPanes, paneID)
	}

	return closeAttemptResult{
		coreStopped:         coreStopped,
		discoveredHolders:   holders,
		prunedHolders:       prunedHolders,
		stoppedHolders:      stoppedHolders,
		unverifiedPanes:     unverifiedPanes,
		verifiedAbsentPanes: verifiedAbsentPanes,
		err:                 errors.Join(errs...),
	}
}

func waitCoreExit(coreWaitCh <-chan error, deadline time.Time) bool {
	if coreWaitCh == nil {
		return true
	}
	select {
	case <-coreWaitCh:
		return true
	default:
	}
	waitRem := time.Until(deadline)
	if waitRem <= 0 {
		return false
	}
	timer := time.NewTimer(waitRem)
	defer timer.Stop()
	select {
	case <-coreWaitCh:
		return true
	case <-timer.C:
		return false
	}
}

func stopWatchdogCleanly(cmd *exec.Cmd, pipe *os.File, waitCh chan error) {
	if pipe != nil {
		_, _ = pipe.WriteString("clean\n")
		_ = pipe.Close()
	}
	if cmd == nil || waitCh == nil {
		return
	}
	select {
	case <-waitCh:
		return
	case <-time.After(defaultWatchdogStopTimeout):
	}
	if cmd.Process != nil && validTargetPID(cmd.Process.Pid) {
		_ = unix.Kill(-cmd.Process.Pid, unix.SIGKILL)
	}
	select {
	case <-waitCh:
	case <-time.After(time.Second):
	}
}

// ReapStaleSessions safely inspects entries under baseDir (default
// /private/tmp/mgh-<uid>) and reaps ONLY stale Mulgae sessions whose recorded
// owner PID is dead or whose Darwin P_starttime no longer matches (preventing
// PID-reuse hazards). Live Mulgae sessions and unreadable/errored lookups are
// never disturbed.
func ReapStaleSessions(ctx context.Context, baseDir string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if !validCanonicalAbsolutePath(baseDir) {
		return fmt.Errorf("herdr stale reaper: invalid base directory")
	}
	euid := uint32(unix.Geteuid())
	dirFD, err := openPrivateOwnedDirectoryNoFollow(baseDir, euid)
	if err != nil {
		if errors.Is(err, unix.ENOENT) || errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	baseFile := os.NewFile(uintptr(dirFD), baseDir)
	defer baseFile.Close()

	entries, err := baseFile.ReadDir(-1)
	if err != nil {
		return err
	}

	var errs []error
	for _, entry := range entries {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		name := entry.Name()
		if !sessionDirNameRegexp.MatchString(name) {
			continue
		}
		entryPath := filepath.Join(baseDir, name)
		if err := reapStaleSessionEntry(ctx, dirFD, name, entryPath, euid); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func reapStaleSessionEntry(ctx context.Context, baseFD int, name, entryPath string, euid uint32) error {
	subFD, err := unix.Openat(baseFD, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOTDIR) {
			return nil
		}
		return err
	}
	var dirStat unix.Stat_t
	statErr := unix.Fstat(subFD, &dirStat)
	if statErr != nil || dirStat.Mode&unix.S_IFMT != unix.S_IFDIR || dirStat.Uid != euid {
		_ = unix.Close(subFD)
		return nil
	}

	rec, lockErr := readOwnerLockFromDirFD(subFD, entryPath, euid)
	_ = unix.Close(subFD)
	if lockErr != nil {
		if errors.Is(lockErr, unix.ENOENT) {
			mtime := time.Unix(dirStat.Mtim.Sec, dirStat.Mtim.Nsec)
			if time.Since(mtime) > staleMissingLockGrace {
				_ = os.RemoveAll(entryPath)
			}
		}
		return nil
	}
	if rec.SessionID != name {
		return nil
	}

	matched, matchErr := processMatchesStartTime(rec.OwnerPID, rec.OwnerStartSec, rec.OwnerStartUsec)
	if matchErr != nil || matched {
		// Fail closed on sysctl error and preserve live sessions.
		return nil
	}

	deadline := time.Now().Add(defaultTeardownTimeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	sigkillReserve := min(500*time.Millisecond, max(time.Millisecond, time.Until(deadline)/3))
	gracefulDeadline := deadline.Add(-sigkillReserve)

	// Load only disk entries carrying valid PIDs AND non-zero P_starttime.
	tracked := make(map[int]trackedProcess)
	if validTargetPID(rec.CorePID) && hasStartTime(rec.CoreStartSec, rec.CoreStartUsec) {
		tracked[rec.CorePID] = trackedProcess{PID: rec.CorePID, StartSec: rec.CoreStartSec, StartUsec: rec.CoreStartUsec}
	}
	for _, holder := range rec.Holders {
		if validTargetPID(holder.PID) && hasStartTime(holder.StartSec, holder.StartUsec) {
			tracked[holder.PID] = holder
		}
	}

	sockPath := filepath.Join(entryPath, "s.sock")
	var sockStat unix.Stat_t
	if unix.Lstat(sockPath, &sockStat) == nil && sockStat.Mode&unix.S_IFMT == unix.S_IFSOCK && sockStat.Uid == euid {
		if client, err := NewRPCClient(sockPath, 2*time.Second); err == nil {
			if rem := time.Until(gracefulDeadline); rem > 50*time.Millisecond {
				statusCtx, cancelStatus := context.WithTimeout(ctx, min(time.Second, rem/2))
				if status, err := client.ServerStatus(statusCtx); err == nil {
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
				stopCtx, cancelStop := context.WithTimeout(ctx, min(1500*time.Millisecond, rem))
				_, _ = client.ServerStop(stopCtx)
				cancelStop()
			}
		}
	}

	pids := make([]int, 0, len(tracked))
	for pid := range tracked {
		pids = append(pids, pid)
	}
	sort.Ints(pids)

	allStopped := true
	for _, pid := range pids {
		if err := ensureTrackedProcessGroupStopped(tracked[pid], deadline); err != nil {
			allStopped = false
		}
	}
	if !allStopped {
		return fmt.Errorf("herdr stale reaper: stale session %s processes still running", name)
	}
	if err := os.RemoveAll(entryPath); err != nil {
		return fmt.Errorf("herdr stale reaper: remove %s: %w", name, err)
	}
	return nil
}

type processInfo struct {
	Exists    bool
	Zombie    bool
	StartSec  int64
	StartUsec int64
	PGID      int
}

type trackedGroupState struct {
	leaderMatches        bool
	leaderReused         bool
	survivingPGIDMembers []int
	groupStillExists     bool
}

func validTargetPID(pid int) bool {
	return pid > 1 && pid <= math.MaxInt32 && pid != os.Getpid() && pid != unix.Getpgrp()
}

func uint32ToValidPID(raw uint32) (int, bool) {
	if raw <= 1 || raw > math.MaxInt32 {
		return 0, false
	}
	pid := int(raw)
	if !validTargetPID(pid) {
		return 0, false
	}
	return pid, true
}

func hasStartTime(sec, usec int64) bool {
	return sec != 0 || usec != 0
}

func startAtOrAfter(sec, usec, refSec, refUsec int64) bool {
	return sec > refSec || (sec == refSec && usec >= refUsec)
}

func startStrictlyBefore(sec, usec, refSec, refUsec int64) bool {
	return sec < refSec || (sec == refSec && usec < refUsec)
}

func inspectProcess(pid int) (processInfo, error) {
	if pid <= 0 || pid > math.MaxInt32 {
		return processInfo{}, nil
	}
	procs, err := unix.SysctlKinfoProcSlice("kern.proc.pid", pid)
	if err != nil {
		if errors.Is(err, unix.ESRCH) {
			return processInfo{}, nil
		}
		return processInfo{}, err
	}
	for _, kp := range procs {
		if int(kp.Proc.P_pid) == pid {
			return processInfo{
				Exists:    true,
				Zombie:    kp.Proc.P_stat == darwinProcessStateZombie,
				StartSec:  int64(kp.Proc.P_starttime.Sec),
				StartUsec: int64(kp.Proc.P_starttime.Usec),
				PGID:      int(kp.Eproc.Pgid),
			}, nil
		}
	}
	return processInfo{}, nil
}

func inspectTrackedProcessGroup(proc trackedProcess) (trackedGroupState, error) {
	if !validTargetPID(proc.PID) {
		return trackedGroupState{groupStillExists: true}, fmt.Errorf("unsafe target pid %d", proc.PID)
	}
	if !hasStartTime(proc.StartSec, proc.StartUsec) {
		return trackedGroupState{groupStillExists: true}, fmt.Errorf("missing start time identity for pid %d", proc.PID)
	}

	var state trackedGroupState
	leaderInfo, err := inspectProcess(proc.PID)
	if err != nil {
		return trackedGroupState{groupStillExists: true}, err
	}
	if leaderInfo.Exists {
		// Match BOTH live processes AND zombies with matching P_starttime so
		// un-reaped zombies are never treated as ESRCH.
		if leaderInfo.StartSec == proc.StartSec && leaderInfo.StartUsec == proc.StartUsec {
			state.leaderMatches = true
		} else {
			state.leaderReused = true
		}
	}

	pgrpProcs, pgrpErr := unix.SysctlKinfoProcSlice("kern.proc.pgrp", proc.PID)
	if pgrpErr != nil && !errors.Is(pgrpErr, unix.ESRCH) {
		return trackedGroupState{groupStillExists: true}, pgrpErr
	}
	for _, kp := range pgrpProcs {
		if int(kp.Eproc.Pgid) != proc.PID {
			continue
		}
		mpid := int(kp.Proc.P_pid)
		if !validTargetPID(mpid) {
			continue
		}
		if state.leaderReused && mpid == proc.PID {
			continue
		}
		mSec := int64(kp.Proc.P_starttime.Sec)
		mUsec := int64(kp.Proc.P_starttime.Usec)
		if !startAtOrAfter(mSec, mUsec, proc.StartSec, proc.StartUsec) {
			continue
		}
		if state.leaderReused && !startStrictlyBefore(mSec, mUsec, leaderInfo.StartSec, leaderInfo.StartUsec) {
			continue
		}
		state.survivingPGIDMembers = append(state.survivingPGIDMembers, mpid)
	}

	killGroupErr := unix.Kill(-proc.PID, 0)
	killGroupESRCH := errors.Is(killGroupErr, unix.ESRCH)

	state.groupStillExists = state.leaderMatches || len(state.survivingPGIDMembers) > 0 || (!killGroupESRCH && !state.leaderReused)
	return state, nil
}

func signalTrackedGroup(proc trackedProcess, state trackedGroupState, sig unix.Signal) {
	if !validTargetPID(proc.PID) || !hasStartTime(proc.StartSec, proc.StartUsec) {
		return
	}
	if state.leaderMatches {
		_ = unix.Kill(-proc.PID, sig)
		_ = unix.Kill(proc.PID, sig)
	}
	for _, mpid := range state.survivingPGIDMembers {
		if validTargetPID(mpid) {
			_ = unix.Kill(mpid, sig)
		}
	}
}

func ensureTrackedProcessGroupStopped(proc trackedProcess, deadline time.Time) error {
	if !validTargetPID(proc.PID) {
		return fmt.Errorf("refusing to signal unsafe pid %d", proc.PID)
	}
	if !hasStartTime(proc.StartSec, proc.StartUsec) {
		return fmt.Errorf("refusing to signal pid %d without start time identity", proc.PID)
	}

	state, err := inspectTrackedProcessGroup(proc)
	if err == nil && !state.groupStillExists {
		return nil
	}

	// Reserve at least half of remaining time (up to 500ms) for SIGKILL + ESRCH
	// verification if SIGTERM does not settle promptly.
	if err == nil {
		signalTrackedGroup(proc, state, unix.SIGTERM)
	}
	termGrace := min(500*time.Millisecond, max(0, time.Until(deadline)/2))
	termDeadline := time.Now().Add(termGrace)
	for time.Now().Before(termDeadline) {
		state, err = inspectTrackedProcessGroup(proc)
		if err == nil && !state.groupStillExists {
			return nil
		}
		time.Sleep(min(processProbeInterval, max(time.Millisecond, time.Until(termDeadline))))
	}

	for {
		state, err = inspectTrackedProcessGroup(proc)
		if err == nil && !state.groupStillExists {
			return nil
		}
		if err == nil {
			signalTrackedGroup(proc, state, unix.SIGKILL)
		}
		if !time.Now().Before(deadline) {
			if err != nil {
				return fmt.Errorf("process group %d inspection failed before deadline: %w", proc.PID, err)
			}
			return fmt.Errorf("process group %d did not exit before deadline (leaderMatches=%t members=%v)",
				proc.PID, state.leaderMatches, state.survivingPGIDMembers)
		}
		time.Sleep(min(processProbeInterval, max(time.Millisecond, time.Until(deadline))))
	}
}

func processStartTime(pid int) (sec int64, usec int64, alive bool, err error) {
	info, err := inspectProcess(pid)
	if err != nil {
		return 0, 0, false, err
	}
	if !info.Exists || info.Zombie || !hasStartTime(info.StartSec, info.StartUsec) {
		return 0, 0, false, nil
	}
	return info.StartSec, info.StartUsec, true, nil
}

func processMatchesStartTime(pid int, wantSec, wantUsec int64) (bool, error) {
	if pid <= 0 || pid > math.MaxInt32 || !hasStartTime(wantSec, wantUsec) {
		return false, nil
	}
	info, err := inspectProcess(pid)
	if err != nil {
		return false, err
	}
	if !info.Exists || info.Zombie {
		return false, nil
	}
	return info.StartSec == wantSec && info.StartUsec == wantUsec, nil
}

func ensurePrivateBaseDir(baseDir string, euid uint32) error {
	if err := validateControlAncestors(filepath.Dir(baseDir), euid); err != nil {
		return err
	}
	if err := os.Mkdir(baseDir, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	fd, err := openPrivateOwnedDirectoryNoFollow(baseDir, euid)
	if err != nil {
		return err
	}
	return unix.Close(fd)
}

func createVerifiedPrivateDir(dirPath string, euid uint32) error {
	if err := os.Mkdir(dirPath, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(dirPath, 0o700); err != nil {
		return err
	}
	fd, err := openPrivateOwnedDirectoryNoFollow(dirPath, euid)
	if err != nil {
		return err
	}
	return unix.Close(fd)
}

func openPrivateOwnedDirectoryNoFollow(path string, euid uint32) (int, error) {
	if !validCanonicalAbsolutePath(path) {
		return -1, fmt.Errorf("invalid canonical directory path")
	}
	components := splitAbsoluteComponents(path)
	if len(components) == 0 {
		return -1, fmt.Errorf("empty directory path")
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
		nextFD, openErr := unix.Openat(dirFD, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		_ = unix.Close(dirFD)
		if openErr != nil {
			return -1, openErr
		}
		dirFD = nextFD
		if index == len(components)-1 {
			var st unix.Stat_t
			if err := unix.Fstat(dirFD, &st); err != nil {
				_ = unix.Close(dirFD)
				return -1, err
			}
			if st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != euid || st.Mode&0o7777 != 0o700 {
				_ = unix.Close(dirFD)
				return -1, fmt.Errorf("directory %q must be private (0700) owned by effective user", path)
			}
		} else if err := validateControlAncestorFD(dirFD, euid); err != nil {
			_ = unix.Close(dirFD)
			return -1, err
		}
	}
	if err := descriptorPathMatches(dirFD, path); err != nil {
		_ = unix.Close(dirFD)
		return -1, err
	}
	return dirFD, nil
}

func validateControlAncestors(path string, euid uint32) error {
	if path == "/" {
		fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		if err != nil {
			return err
		}
		err = validateControlAncestorFD(fd, euid)
		_ = unix.Close(fd)
		return err
	}
	if !validCanonicalAbsolutePath(path) {
		return fmt.Errorf("invalid ancestor path")
	}
	components := splitAbsoluteComponents(path)
	dirFD, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	if err := validateControlAncestorFD(dirFD, euid); err != nil {
		_ = unix.Close(dirFD)
		return err
	}
	for _, component := range components {
		nextFD, openErr := unix.Openat(dirFD, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		_ = unix.Close(dirFD)
		if openErr != nil {
			return openErr
		}
		dirFD = nextFD
		if err := validateControlAncestorFD(dirFD, euid); err != nil {
			_ = unix.Close(dirFD)
			return err
		}
	}
	err = descriptorPathMatches(dirFD, path)
	_ = unix.Close(dirFD)
	return err
}

func validateControlAncestorFD(fd int, euid uint32) error {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return fmt.Errorf("ancestor is not a directory")
	}
	if st.Uid != 0 && st.Uid != euid {
		return fmt.Errorf("ancestor has untrusted owner")
	}
	if st.Mode&0o022 != 0 && (st.Uid != 0 || st.Mode&unix.S_ISVTX == 0) {
		return fmt.Errorf("ancestor is group- or world-writable without sticky root protection")
	}
	return nil
}

func writeOwnerLockAtomic(sessionDir string, rec ownerLockRecord) error {
	data, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return writePrivateFileAtomic(filepath.Join(sessionDir, ownerLockFileName), data, 0o600)
}

func writePrivateFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	suffix, err := randomHexBytes(6)
	if err != nil {
		return err
	}
	tmpPath := filepath.Join(dir, "."+filepath.Base(path)+".tmp."+suffix)
	file, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, mode)
	if err != nil {
		return err
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()
	if err := writeAll(file, data); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Chmod(mode); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	cleanup = false
	return nil
}

func randomHexBytes(numBytes int) (string, error) {
	raw := make([]byte, numBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
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
	end := bytes.IndexByte(buffer, 0)
	if end <= 0 {
		return "", fmt.Errorf("descriptor path unavailable")
	}
	return string(buffer[:end]), nil
}

func descriptorPathMatches(fd int, expected string) error {
	actual, err := descriptorPath(fd)
	if err != nil {
		return err
	}
	if actual != expected {
		return fmt.Errorf("descriptor path mismatch")
	}
	return nil
}

type boundedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

const maxDaemonDiagBufferBytes = 64 * 1024

func (b *boundedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	remaining := maxDaemonDiagBufferBytes - b.buf.Len()
	if remaining > 0 {
		if len(p) > remaining {
			_, _ = b.buf.Write(p[:remaining])
		} else {
			_, _ = b.buf.Write(p)
		}
	}
	return len(p), nil
}

func (b *boundedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
