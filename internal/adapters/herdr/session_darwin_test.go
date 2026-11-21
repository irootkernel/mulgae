//go:build darwin && arm64

package herdr

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	runtimeadapter "github.com/irootkernel/mulgae/internal/adapters/runtime"
	"github.com/irootkernel/mulgae/internal/ports"
	"golang.org/x/sys/unix"
)

type fakeWatchdogHandle struct {
	cmd     *exec.Cmd
	pipeW   *os.File
	waitCh  chan error
	stopped atomic.Bool
	signal  atomic.Value
	pipeR   *os.File
}

func newFakeWatchdogHandle(t *testing.T) *fakeWatchdogHandle {
	t.Helper()
	pipeR, pipeW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	handle := &fakeWatchdogHandle{
		cmd:    &exec.Cmd{},
		pipeW:  pipeW,
		waitCh: make(chan error, 1),
		pipeR:  pipeR,
	}
	go func() {
		sig := readWatchdogSignal(pipeR)
		_ = pipeR.Close()
		handle.signal.Store(sig)
		handle.stopped.Store(true)
		handle.waitCh <- nil
		close(handle.waitCh)
	}()
	t.Cleanup(func() {
		_ = pipeW.Close()
		_ = pipeR.Close()
	})
	return handle
}

func TestOfflineCloseKeepsWatchdogAliveWhenLateArrivalAbortsDirRemoval(t *testing.T) {
	t.Parallel()

	t.Run("late tracked pane aborts dir removal without stopping watchdog until subsequent Close commits", func(t *testing.T) {
		fix := newOfflineFixture(t)
		srv := startFakeHerdrServer(t)
		inspector := newFakeProcessInspector()
		sess := fix.newFakeSession(t, srv, inspector)

		if _, err := sess.RuntimeIdentity(context.Background()); err != nil {
			t.Fatal(err)
		}
		sessionDir := sess.SessionDir()
		wd := newFakeWatchdogHandle(t)

		initialPID := 59201
		latePID := 59202
		inspector.mu.Lock()
		inspector.killZeroErr[initialPID] = unix.ESRCH
		inspector.killZeroErr[latePID] = nil // stubborn until cleared
		inspector.mu.Unlock()

		sess.mu.Lock()
		sess.watchdogCmd = wd.cmd
		sess.watchdogPipe = wd.pipeW
		sess.watchdogWaitCh = wd.waitCh
		sess.trackedPanes["t-initial"] = trackedPane{PID: initialPID, SID: initialPID}
		sess.mu.Unlock()

		// Hold persistMu before launching Close so Close can finish performClose
		// and clear "t-initial" (exiting its performClose loop), then block right
		// before the persistMu -> mu directory-removal commit check.
		sess.persistMu.Lock()
		close1ErrCh := make(chan error, 1)
		go func() {
			close1ErrCh <- sess.Close(context.Background())
		}()

		// Wait deterministically until Close has cleared "t-initial" and exited the
		// performClose loop, then inject the late tracked pane while still holding
		// persistMu so Close is guaranteed to hit the pre-commit check.
		waitDeadline := time.Now().Add(3 * time.Second)
		for {
			sess.mu.Lock()
			_, initialStillTracked := sess.trackedPanes["t-initial"]
			sess.mu.Unlock()
			if !initialStillTracked {
				break
			}
			if !time.Now().Before(waitDeadline) {
				sess.persistMu.Unlock()
				t.Fatal("timed out waiting for Close to finish performClose loop")
			}
			time.Sleep(time.Millisecond)
		}

		if wd.stopped.Load() {
			sess.persistMu.Unlock()
			t.Fatal("watchdog was stopped before persistMu -> mu directory-removal commit check")
		}

		sess.recordTrackedPane("t-late", trackedPane{PID: latePID, SID: latePID})
		sess.persistMu.Unlock()

		closeErr1 := <-close1ErrCh
		if closeErr1 == nil || !strings.Contains(closeErr1.Error(), "arrived before directory removal") {
			t.Fatalf("Close #1 err = %v, want late tracked pane error before directory removal", closeErr1)
		}
		if _, statErr := os.Lstat(sessionDir); statErr != nil {
			t.Fatalf("sessionDir was prematurely removed despite late tracked pane: %v", statErr)
		}
		if wd.stopped.Load() {
			t.Fatal("watchdog was stopped even though Close #1 aborted directory removal")
		}
		sess.mu.Lock()
		wdCmd := sess.watchdogCmd
		wdPipe := sess.watchdogPipe
		wdWaitCh := sess.watchdogWaitCh
		dirRemovalStarted := sess.dirRemovalStarted
		state := sess.state
		sess.mu.Unlock()
		if wdCmd == nil || wdPipe == nil || wdWaitCh == nil {
			t.Fatalf("watchdog fields cleared on aborted Close #1: cmd=%v pipe=%v waitCh=%v", wdCmd, wdPipe, wdWaitCh)
		}
		if dirRemovalStarted || state != sessionClosing {
			t.Fatalf("session state after aborted Close #1: dirRemovalStarted=%t state=%v, want false/sessionClosing", dirRemovalStarted, state)
		}

		// Clear the late pane survivor and verify Close #2 commits directory
		// removal, stops the watchdog cleanly, clears watchdog fields, and removes sessionDir.
		inspector.mu.Lock()
		inspector.killZeroErr[latePID] = unix.ESRCH
		inspector.mu.Unlock()

		if closeErr2 := sess.Close(context.Background()); closeErr2 != nil {
			t.Fatalf("Close #2 after late pane cleared: %v", closeErr2)
		}
		if _, statErr := os.Lstat(sessionDir); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("sessionDir survived Close #2: %v", statErr)
		}
		if !wd.stopped.Load() {
			t.Fatal("watchdog was not stopped when Close #2 committed directory removal")
		}
		if gotSig, _ := wd.signal.Load().(string); gotSig != "clean" {
			t.Fatalf("watchdog stop signal = %q, want %q", gotSig, "clean")
		}
		sess.mu.Lock()
		wdCmd = sess.watchdogCmd
		wdPipe = sess.watchdogPipe
		wdWaitCh = sess.watchdogWaitCh
		state = sess.state
		sess.mu.Unlock()
		if wdCmd != nil || wdPipe != nil || wdWaitCh != nil || state != sessionClosed {
			t.Fatalf("post-Close #2 state: cmd=%v pipe=%v waitCh=%v state=%v", wdCmd, wdPipe, wdWaitCh, state)
		}
	})

	t.Run("late unstopped holder aborts dir removal, retains watchdog, and persists holder until subsequent Close commits", func(t *testing.T) {
		fix := newOfflineFixture(t)
		srv := startFakeHerdrServer(t)
		inspector := newFakeProcessInspector()

		baseDir := filepath.Join(fix.base, "mgh-late-holder-wd")
		sessionID := "0123456789abcdef"
		sessionDir := filepath.Join(baseDir, sessionID)
		if err := os.MkdirAll(sessionDir, 0o700); err != nil {
			t.Fatal(err)
		}
		ownerPID := os.Getpid()
		ownerSec, ownerUsec, alive, err := processStartTime(ownerPID)
		if err != nil || !alive {
			t.Fatalf("processStartTime(self): alive=%t err=%v", alive, err)
		}
		if err := writeOwnerLockAtomic(sessionDir, ownerLockRecord{
			Version:        ownerLockVersion,
			SessionID:      sessionID,
			OwnerPID:       ownerPID,
			OwnerStartSec:  ownerSec,
			OwnerStartUsec: ownerUsec,
			SocketPath:     srv.sockPath,
		}); err != nil {
			t.Fatal(err)
		}
		client, err := NewRPCClient(srv.sockPath, 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		nativeHomeRoot, err := ports.NewAnchoredRoot(fix.nativeHome)
		if err != nil {
			t.Fatal(err)
		}

		srv.onStatus = func(_ *fakeHerdrServer) (StatusResult, *RPCError) {
			return StatusResult{Core: CoreInfo{ID: "c"}, Version: "0.1.20"}, nil
		}

		var allowHolderStop atomic.Bool
		sess, err := NewSession(SessionOptions{
			Clock:                    runtimeadapter.SystemClock{},
			LaunchBuilder:            fix.launchBuilder,
			NativeHome:               nativeHomeRoot,
			BaseDir:                  baseDir,
			HasInheritedSocket:       true,
			HasAmbientTerminalSocket: true,
			TeardownTimeout:          2 * time.Second,
			DisableWatchdog:          true,
			DisableStaleReaper:       true,
			inspector:                inspector,
			stopTrackedProc: func(proc trackedProcess, _ time.Time) error {
				if proc.PID == 59204 && !allowHolderStop.Load() {
					return errors.New("late holder still alive")
				}
				return nil
			},
		})
		if err != nil {
			t.Fatal(err)
		}

		initialPID := 59203
		lateHolder := trackedProcess{PID: 59204, StartSec: 1700000001, StartUsec: 42}
		inspector.mu.Lock()
		inspector.killZeroErr[initialPID] = unix.ESRCH
		inspector.mu.Unlock()

		wd := newFakeWatchdogHandle(t)
		sess.mu.Lock()
		sess.state = sessionRunning
		sess.sessionID = sessionID
		sess.sessionDir = sessionDir
		sess.socketPath = srv.sockPath
		sess.ownerProc = trackedProcess{PID: ownerPID, StartSec: ownerSec, StartUsec: ownerUsec}
		sess.rpc = client
		sess.watchdogCmd = wd.cmd
		sess.watchdogPipe = wd.pipeW
		sess.watchdogWaitCh = wd.waitCh
		sess.trackedPanes["t-initial"] = trackedPane{PID: initialPID, SID: initialPID}
		sess.mu.Unlock()

		sess.persistMu.Lock()
		close1ErrCh := make(chan error, 1)
		go func() {
			close1ErrCh <- sess.Close(context.Background())
		}()

		waitDeadline := time.Now().Add(3 * time.Second)
		for {
			sess.mu.Lock()
			_, initialStillTracked := sess.trackedPanes["t-initial"]
			sess.mu.Unlock()
			if !initialStillTracked {
				break
			}
			if !time.Now().Before(waitDeadline) {
				sess.persistMu.Unlock()
				t.Fatal("timed out waiting for Close to finish performClose loop")
			}
			time.Sleep(time.Millisecond)
		}

		sess.mu.Lock()
		sess.holders[lateHolder.PID] = lateHolder
		sess.holdersGen++
		sess.mu.Unlock()
		sess.persistMu.Unlock()

		closeErr1 := <-close1ErrCh
		if closeErr1 == nil || !strings.Contains(closeErr1.Error(), "unstopped holder(s) arrived before directory removal") {
			t.Fatalf("Close #1 err = %v, want late unstopped holder error", closeErr1)
		}
		if _, statErr := os.Lstat(sessionDir); statErr != nil {
			t.Fatalf("sessionDir prematurely removed despite late holder: %v", statErr)
		}
		if wd.stopped.Load() {
			t.Fatal("watchdog was stopped despite late holder aborting directory removal")
		}
		rawLock, readErr := os.ReadFile(filepath.Join(sessionDir, ownerLockFileName))
		if readErr != nil {
			t.Fatalf("read owner.lock.json after aborted Close #1: %v", readErr)
		}
		var rec ownerLockRecord
		if unmarshalErr := json.Unmarshal(rawLock, &rec); unmarshalErr != nil {
			t.Fatalf("unmarshal owner.lock.json: %v", unmarshalErr)
		}
		persistedLateHolder := false
		for _, h := range rec.Holders {
			if h == lateHolder {
				persistedLateHolder = true
				break
			}
		}
		if !persistedLateHolder {
			t.Fatalf("late holder %+v was not persisted to owner.lock.json: %+v", lateHolder, rec.Holders)
		}

		allowHolderStop.Store(true)
		if closeErr2 := sess.Close(context.Background()); closeErr2 != nil {
			t.Fatalf("Close #2 after late holder stoppable: %v", closeErr2)
		}
		if _, statErr := os.Lstat(sessionDir); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("sessionDir survived Close #2: %v", statErr)
		}
		if !wd.stopped.Load() {
			t.Fatal("watchdog was not stopped on committed Close #2")
		}
		if gotSig, _ := wd.signal.Load().(string); gotSig != "clean" {
			t.Fatalf("watchdog stop signal = %q, want %q", gotSig, "clean")
		}
	})
}
