//go:build darwin && arm64 && live_herdr

package herdr

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	processadapter "github.com/irootkernel/mulgae/internal/adapters/process"
	runtimeadapter "github.com/irootkernel/mulgae/internal/adapters/runtime"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
	"golang.org/x/sys/unix"
)

const (
	liveProbeArg          = "__herdr_live_probe_v1"
	liveWatchdogVictimArg = "__herdr_watchdog_victim_v1"
)

func init() {
	testMainHook = runLiveHerdrHelper
}

func runLiveHerdrHelper(argv []string) (bool, int) {
	if len(argv) < 2 {
		return false, 0
	}
	switch argv[1] {
	case liveProbeArg:
		return true, execLiveProbe(argv[2:])
	case liveWatchdogVictimArg:
		return true, execWatchdogVictim(argv[2:])
	default:
		return false, 0
	}
}

type liveSocketAttempt struct {
	Label       string `json:"label"`
	Path        string `json:"path"`
	ConnectErr  string `json:"connect_err"`
	ConnectPerm bool   `json:"connect_eperm"`
	StatErr     string `json:"stat_err"`
	StatPerm    bool   `json:"stat_eperm"`
	LinkErr     string `json:"link_err,omitempty"`
	LinkPerm    bool   `json:"link_eperm,omitempty"`
}

type liveSecurityProbeReport struct {
	FGetPath0          string              `json:"fgetpath_fd0"`
	OwnTTYOpenOK       bool                `json:"own_tty_open_ok"`
	OwnTTYRawModeOK    bool                `json:"own_tty_raw_mode_ok"`
	OwnTTYErr          string              `json:"own_tty_err,omitempty"`
	ForeignTTYPath     string              `json:"foreign_tty_path"`
	ForeignTTYErr      string              `json:"foreign_tty_err"`
	ForeignTTYPerm     bool                `json:"foreign_tty_eperm"`
	TIOCSTIErr         string              `json:"tiocsti_err"`
	TIOCSTIPerm        bool                `json:"tiocsti_eperm"`
	SocketAttempts     []liveSocketAttempt `json:"socket_attempts"`
	Env                []string            `json:"env"`
	ControlFileReadErr string              `json:"control_file_read_err"`
	ControlFilePerm    bool                `json:"control_file_eperm"`
}

func execLiveProbe(args []string) int {
	if len(args) < 1 {
		return 2
	}
	mode := args[0]
	switch mode {
	case "osc_done":
		// Emit OSC 7501 idle, read input line, emit working, write marker, emit done, stay alive.
		reportPath := args[1]
		emitOSC7501("state=idle")
		reader := bufio.NewReader(os.Stdin)
		line, _ := reader.ReadString('\n')
		emitOSC7501("state=working")
		time.Sleep(150 * time.Millisecond)
		_ = os.WriteFile(reportPath, []byte("RECEIVED:"+strings.TrimSpace(line)+"\n"), 0o600)
		emitOSC7501("state=done")
		time.Sleep(time.Hour)
		return 0
	case "osc_checkins_done":
		// Emit idle, wait for input, emit working, hold 650ms so check-ins fire, then done.
		reportPath := args[1]
		emitOSC7501("state=idle")
		reader := bufio.NewReader(os.Stdin)
		line, _ := reader.ReadString('\n')
		emitOSC7501("state=working")
		time.Sleep(650 * time.Millisecond)
		_ = os.WriteFile(reportPath, []byte("CHECKIN_OK:"+strings.TrimSpace(line)+"\n"), 0o600)
		emitOSC7501("state=done")
		time.Sleep(time.Hour)
		return 0
	case "osc_blocked_auth":
		emitOSC7501("state=blocked:kind=auth")
		time.Sleep(time.Hour)
		return 0
	case "osc_error":
		emitOSC7501("state=idle")
		reader := bufio.NewReader(os.Stdin)
		_, _ = reader.ReadString('\n')
		emitOSC7501("state=working")
		time.Sleep(100 * time.Millisecond)
		emitOSC7501("state=error")
		time.Sleep(time.Hour)
		return 0
	case "osc_hang_for_cancel":
		emitOSC7501("state=idle")
		reader := bufio.NewReader(os.Stdin)
		_, _ = reader.ReadString('\n')
		emitOSC7501("state=working")
		time.Sleep(time.Hour)
		return 0
	case "exit_before_report":
		code := 10
		if len(args) >= 2 {
			if parsed, err := strconv.Atoi(args[1]); err == nil {
				code = parsed
			}
		}
		_, _ = fmt.Fprintln(os.Stdout, "exiting before osc 7501")
		return code
	case "security_audit":
		// args: reportPath, foreignTTYPath, writableDir, controlFilePath, [label=path ...]
		if len(args) < 5 {
			return 3
		}
		reportPath := args[1]
		foreignTTY := args[2]
		writableDir := args[3]
		controlFile := args[4]
		socketSpecs := args[5:]

		report := liveSecurityProbeReport{
			ForeignTTYPath: foreignTTY,
			Env:            os.Environ(),
		}
		sort.Strings(report.Env)

		if p, err := descriptorPath(0); err == nil {
			report.FGetPath0 = p
			if fd, openErr := unix.Open(p, unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0); openErr == nil {
				report.OwnTTYOpenOK = true
				orig, getErr := unix.IoctlGetTermios(fd, unix.TIOCGETA)
				if getErr == nil {
					raw := *orig
					raw.Lflag &^= unix.ECHO | unix.ICANON
					if setErr := unix.IoctlSetTermios(fd, unix.TIOCSETA, &raw); setErr == nil {
						if restoreErr := unix.IoctlSetTermios(fd, unix.TIOCSETA, orig); restoreErr == nil {
							report.OwnTTYRawModeOK = true
						} else {
							report.OwnTTYErr = restoreErr.Error()
						}
					} else {
						report.OwnTTYErr = setErr.Error()
					}
				} else {
					report.OwnTTYErr = getErr.Error()
				}
				_ = unix.Close(fd)
			} else {
				report.OwnTTYErr = openErr.Error()
			}
		} else {
			report.OwnTTYErr = "fgetpath: " + err.Error()
		}

		if fd, err := unix.Open(foreignTTY, unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0); err == nil {
			_ = unix.Close(fd)
			report.ForeignTTYErr = "UNEXPECTED_OPEN_SUCCESS"
		} else {
			report.ForeignTTYErr = err.Error()
			report.ForeignTTYPerm = errors.Is(err, unix.EPERM)
		}

		// Verify TIOCSTI (#x80017472) is denied EPERM on fd 0.
		var ch byte = 'x'
		_, _, tiocstiErrno := unix.Syscall(unix.SYS_IOCTL, 0, uintptr(unix.TIOCSTI), uintptr(unsafe.Pointer(&ch)))
		if tiocstiErrno != 0 {
			report.TIOCSTIErr = tiocstiErrno.Error()
			report.TIOCSTIPerm = errors.Is(tiocstiErrno, unix.EPERM)
		} else {
			report.TIOCSTIErr = "UNEXPECTED_TIOCSTI_SUCCESS"
		}

		// Verify private per-pane control file is unreadable (EPERM).
		if _, err := os.ReadFile(controlFile); err != nil {
			report.ControlFileReadErr = err.Error()
			report.ControlFilePerm = errors.Is(err, unix.EPERM) || errors.Is(err, os.ErrPermission)
		} else {
			report.ControlFileReadErr = "UNEXPECTED_READ_SUCCESS"
		}

		for idx, spec := range socketSpecs {
			label, sockPath, ok := strings.Cut(spec, "=")
			if !ok {
				continue
			}
			attempt := liveSocketAttempt{Label: label, Path: sockPath}
			sfd, sockErr := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM, 0)
			if sockErr == nil {
				connErr := unix.Connect(sfd, &unix.SockaddrUnix{Name: sockPath})
				_ = unix.Close(sfd)
				if connErr != nil {
					attempt.ConnectErr = connErr.Error()
					attempt.ConnectPerm = errors.Is(connErr, unix.EPERM)
				} else {
					attempt.ConnectErr = "UNEXPECTED_CONNECT_SUCCESS"
				}
			} else {
				attempt.ConnectErr = sockErr.Error()
			}

			var st unix.Stat_t
			if statErr := unix.Stat(sockPath, &st); statErr == nil {
				attempt.StatErr = "UNEXPECTED_STAT_SUCCESS"
			} else {
				attempt.StatErr = statErr.Error()
				attempt.StatPerm = errors.Is(statErr, unix.EPERM)
			}

			// Attempt hardlink creation into writableDir from inside sandbox.
			if !strings.HasPrefix(label, "symlink:") {
				linkTarget := filepath.Join(writableDir, fmt.Sprintf("hl-%d.sock", idx))
				linkErr := unix.Link(sockPath, linkTarget)
				if linkErr != nil {
					attempt.LinkErr = linkErr.Error()
					attempt.LinkPerm = errors.Is(linkErr, unix.EPERM)
				} else {
					attempt.LinkErr = "UNEXPECTED_LINK_SUCCESS"
				}
			}
			report.SocketAttempts = append(report.SocketAttempts, attempt)
		}

		encoded, _ := json.MarshalIndent(report, "", "  ")
		_ = os.WriteFile(reportPath, encoded, 0o600)
		emitOSC7501("state=done")
		time.Sleep(time.Hour)
		return 0
	default:
		return 4
	}
}

func emitOSC7501(body string) {
	_, _ = fmt.Fprintf(os.Stdout, "\x1b]7501;%s\x07", body)
}

type watchdogVictimState struct {
	SessionDir  string `json:"session_dir"`
	CorePID     int    `json:"core_pid"`
	HolderPIDs  []int  `json:"holder_pids"`
	PanePID     int    `json:"pane_pid"`
	WatchdogPID int    `json:"watchdog_pid"`
}

func execWatchdogVictim(args []string) int {
	if len(args) < 3 {
		return 2
	}
	stateFile := args[0]
	nativeHome := args[1]
	workBase := args[2]

	nativeRoot, err := ports.NewAnchoredRoot(nativeHome)
	if err != nil {
		return 3
	}
	sess, err := NewSession(SessionOptions{
		Clock:         runtimeadapter.SystemClock{},
		LaunchBuilder: processadapter.NewPaneLaunchBuilder(),
		NativeHome:    nativeRoot,
	})
	if err != nil {
		return 4
	}
	if _, err := sess.RuntimeIdentity(context.Background()); err != nil {
		return 5
	}
	// Spawn one long-lived pane directly via RPC so holder is also spawned!
	sess.mu.Lock()
	rpc := sess.rpc
	sess.mu.Unlock()
	term, err := rpc.TerminalRun(context.Background(), RunParams{
		Argv:     []string{"/bin/sleep", "60"},
		CWD:      workBase,
		NoParent: true,
		NoNotify: true,
	})
	if err != nil {
		return 6
	}
	sess.refreshHolders(context.Background())

	sess.mu.Lock()
	watchdogPID := 0
	if sess.watchdogCmd != nil && sess.watchdogCmd.Process != nil {
		watchdogPID = sess.watchdogCmd.Process.Pid
	}
	sess.mu.Unlock()

	payload := watchdogVictimState{
		SessionDir:  sess.SessionDir(),
		CorePID:     sess.CorePID(),
		HolderPIDs:  sess.HolderPIDs(),
		PanePID:     terminalPID(term),
		WatchdogPID: watchdogPID,
	}
	raw, _ := json.Marshal(payload)
	_ = os.WriteFile(stateFile, raw, 0o600)

	// Block forever awaiting SIGKILL from parent test!
	time.Sleep(time.Hour)
	return 0
}

type defaultCoreSnapshot struct {
	Entries []string
}

func captureDefaultCoreSnapshot(t *testing.T) defaultCoreSnapshot {
	t.Helper()
	out, err := exec.Command("/bin/ps", "-axww", "-o", "pid=,ppid=,lstart=,command=").Output()
	if err != nil {
		t.Fatalf("ps snapshot: %v", err)
	}
	var entries []string
	for _, line := range strings.Split(string(out), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.Contains(trimmed, "--hc-launchd") || strings.Contains(trimmed, "/default/default.holder.") {
			entries = append(entries, trimmed)
		}
	}
	sort.Strings(entries)
	return defaultCoreSnapshot{Entries: entries}
}

func assertDefaultCoreUntouched(t *testing.T, before defaultCoreSnapshot) {
	t.Helper()
	after := captureDefaultCoreSnapshot(t)
	if strings.Join(before.Entries, "\n") != strings.Join(after.Entries, "\n") {
		t.Fatalf("operator default herdr-core changed!\nbefore:\n%s\nafter:\n%s",
			strings.Join(before.Entries, "\n"), strings.Join(after.Entries, "\n"))
	}
}

func assertNoMulgaeHerdrLeaks(t *testing.T, baseDir string) {
	t.Helper()
	if entries, err := os.ReadDir(baseDir); err == nil {
		var leftovers []string
		for _, e := range entries {
			if sessionDirNameRegexp.MatchString(e.Name()) {
				leftovers = append(leftovers, e.Name())
			}
		}
		if len(leftovers) > 0 {
			t.Fatalf("leftover session dirs in %s: %v", baseDir, leftovers)
		}
	}
	selfPID := strconv.Itoa(os.Getpid())
	for _, args := range [][]string{
		{"-axww", "-o", "pid=,ppid=,command="},
		{"-axww", "-E", "-o", "pid=,ppid=,command="},
	} {
		out, err := exec.Command("/bin/ps", args...).Output()
		if err != nil {
			t.Fatalf("ps %v leak check: %v", args, err)
		}
		for _, line := range strings.Split(string(out), "\n") {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" {
				continue
			}
			fields := strings.Fields(trimmed)
			if len(fields) > 0 && fields[0] == selfPID {
				continue
			}
			if strings.Contains(trimmed, baseDir) || strings.Contains(trimmed, watchdogArgSentinel) {
				t.Fatalf("leftover mulgae herdr process (%v): %s", args, trimmed)
			}
		}
	}
}

func openForeignSyntheticPTY(t *testing.T) (int, int, string) {
	t.Helper()
	master, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(master), uintptr(unix.TIOCPTYGRANT), 0); errno != 0 {
		_ = unix.Close(master)
		t.Fatal(errno)
	}
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(master), uintptr(unix.TIOCPTYUNLK), 0); errno != 0 {
		_ = unix.Close(master)
		t.Fatal(errno)
	}
	var name [128]byte
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(master), uintptr(unix.TIOCPTYGNAME), uintptr(unsafe.Pointer(&name[0]))); errno != 0 {
		_ = unix.Close(master)
		t.Fatal(errno)
	}
	end := bytes.IndexByte(name[:], 0)
	if end <= 0 {
		_ = unix.Close(master)
		t.Fatal("synthetic foreign PTY has no slave name")
	}
	path := string(name[:end])
	slave, err := unix.Open(path, unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		_ = unix.Close(master)
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = unix.Close(slave)
		_ = unix.Close(master)
	})
	return master, slave, path
}

func canonicalTestBinary(t *testing.T) string {
	t.Helper()
	raw, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := filepath.EvalSymlinks(raw)
	if err != nil {
		t.Fatal(err)
	}
	abs, err := filepath.Abs(resolved)
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Clean(abs)
}

func mustNativeHomeRoot(t *testing.T) ports.AnchoredRoot {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := filepath.EvalSymlinks(home)
	if err != nil {
		t.Fatal(err)
	}
	root, err := ports.NewAnchoredRoot(resolved)
	if err != nil {
		t.Fatal(err)
	}
	return root
}

type liveTestWorkspace struct {
	base       string
	sourceDir  string
	neutralDir string
	writable   string
	promptPath string
	nativeHome ports.AnchoredRoot
}

func newLiveTestWorkspace(t *testing.T) liveTestWorkspace {
	t.Helper()
	// Keep temp path short (< 104 bytes) so symlink Unix-socket probes stay within
	// Darwin sockaddr_un.sun_path limits and exercise Seatbelt EPERM rather than EINVAL.
	rawBase, err := os.MkdirTemp("/private/tmp", "mht-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(rawBase) })
	base, err := filepath.EvalSymlinks(rawBase)
	if err != nil {
		t.Fatal(err)
	}
	w := liveTestWorkspace{
		base:       base,
		sourceDir:  filepath.Join(base, "src"),
		neutralDir: filepath.Join(base, "neutral"),
		writable:   filepath.Join(base, "ns"),
		nativeHome: mustNativeHomeRoot(t),
	}
	for _, dir := range []string{
		w.sourceDir,
		w.neutralDir,
		w.writable,
		filepath.Join(w.writable, "home"),
		filepath.Join(w.writable, "tmp"),
		filepath.Join(w.writable, "scratch", "input"),
	} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	w.promptPath = filepath.Join(w.writable, "scratch", "input", "prompt.md")
	if err := os.WriteFile(w.promptPath, []byte("live herdr test prompt\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	return w
}

func (w liveTestWorkspace) buildRequest(
	t *testing.T,
	execPath string,
	args []string,
	initialInput string,
	requireOSC bool,
	startupTimeout time.Duration,
	totalTimeout time.Duration,
	checkIn time.Duration,
	labels map[string]string,
) (ports.TerminalExecutionRequest, *os.File) {
	t.Helper()
	packet, err := ports.NewProviderPacketFromBytes([]byte("live herdr test prompt\n"))
	if err != nil {
		t.Fatal(err)
	}
	binding, err := ports.NewTerminalProviderPacketBinding(packet)
	if err != nil {
		t.Fatal(err)
	}
	mustEnv := func(k, v string) ports.EnvironmentVariable {
		ev, err := ports.NewEnvironmentVariable(k, v)
		if err != nil {
			t.Fatal(err)
		}
		return ev
	}
	env := []ports.EnvironmentVariable{
		mustEnv("PATH", "/usr/bin:/bin"),
		mustEnv("HOME", filepath.Join(w.writable, "home")),
		mustEnv("TMPDIR", filepath.Join(w.writable, "tmp")),
		mustEnv("TERM", "xterm-256color"),
		mustEnv("COLORTERM", "truecolor"),
		mustEnv("TERM_PROGRAM", "ghostty"),
		mustEnv("LANG", "en_US.UTF-8"),
	}
	argv := append([]string{execPath}, args...)
	procReq, err := ports.NewProviderTerminalProcessRequest(execPath, argv, env, w.neutralDir, binding, totalTimeout)
	if err != nil {
		t.Fatal(err)
	}
	mustRoot := func(p string) ports.AnchoredRoot {
		r, err := ports.NewAnchoredRoot(p)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	boundary, err := ports.NewLiveReadOnlyBoundary(
		[]ports.AnchoredRoot{
			mustRoot(w.sourceDir),
			mustRoot(w.neutralDir),
			mustRoot(filepath.Dir(w.promptPath)),
		},
		[]ports.AnchoredRoot{
			mustRoot(filepath.Join(w.nativeHome.String(), ".grok")),
		},
		mustRoot(w.writable),
	)
	if err != nil {
		t.Fatal(err)
	}
	boundary, err = ports.NewLiveReadOnlyBoundaryWithPaneTTY(boundary, w.nativeHome)
	if err != nil {
		t.Fatal(err)
	}
	procReq, err = ports.NewLiveReadOnlyProcessRequest(procReq, boundary)
	if err != nil {
		t.Fatal(err)
	}
	launchDir, err := os.Open(w.neutralDir)
	if err != nil {
		t.Fatal(err)
	}
	procReq, err = ports.NewNeutralBoundProcessRequest(procReq, mustRoot(w.neutralDir), launchDir)
	if err != nil {
		_ = launchDir.Close()
		t.Fatal(err)
	}
	req, err := ports.NewTerminalExecutionRequest(ports.TerminalExecutionRequestInput{
		Process:             procReq,
		StartupTimeout:      startupTimeout,
		PromptFilePath:      mustRoot(w.promptPath),
		InitialInput:        initialInput,
		RequireOSCReporting: requireOSC,
		CheckInInterval:     checkIn,
		Columns:             160,
		Rows:                48,
		Labels:              labels,
	})
	if err != nil {
		_ = launchDir.Close()
		t.Fatal(err)
	}
	return req, launchDir
}

func TestLiveHerdrIsolatedCoreLifecycleAndSecurityBoundaries(t *testing.T) {
	beforeDefault := captureDefaultCoreSnapshot(t)
	defaultBaseDir := fmt.Sprintf("/private/tmp/mgh-%d", unix.Geteuid())
	t.Cleanup(func() {
		assertNoMulgaeHerdrLeaks(t, defaultBaseDir)
		assertDefaultCoreUntouched(t, beforeDefault)
	})

	nativeHome := mustNativeHomeRoot(t)
	resolvedHC, err := ResolveExecutable(DefaultResolveOptions(nativeHome.String()))
	if err != nil {
		t.Fatalf("ResolveExecutable(real hc): %v", err)
	}
	t.Logf("resolved real hc: %s (%s)", resolvedHC.Path, resolvedHC.SHA256)

	sess, err := NewSession(SessionOptions{
		Clock:         runtimeadapter.SystemClock{},
		LaunchBuilder: processadapter.NewPaneLaunchBuilder(),
		NativeHome:    nativeHome,
	})
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	closed := false
	defer func() {
		if !closed {
			_ = sess.Close(context.Background())
		}
	}()

	identity, err := sess.RuntimeIdentity(context.Background())
	if err != nil {
		t.Fatalf("RuntimeIdentity: %v", err)
	}
	if !identity.Valid() || identity.Generation() != 1 || identity.Executable() != resolvedHC.Path || identity.ExecutableSHA256() != resolvedHC.SHA256 {
		t.Fatalf("unexpected RuntimeIdentity: %+v", identity)
	}
	sessionDir := sess.SessionDir()
	corePID := sess.CorePID()
	if !strings.HasPrefix(sessionDir, defaultBaseDir+"/") || corePID <= 1 {
		t.Fatalf("unexpected sessionDir=%q corePID=%d", sessionDir, corePID)
	}
	// Verify foreground serve child (NO launchd!).
	psCoreOut, err := exec.Command("/bin/ps", "-p", strconv.Itoa(corePID), "-ww", "-o", "ppid=,command=").Output()
	if err != nil {
		t.Fatalf("ps corePID %d: %v", corePID, err)
	}
	if strings.Contains(string(psCoreOut), "--hc-launchd") {
		t.Fatalf("herdr-core launched via launchd instead of foreground serve: %s", psCoreOut)
	}

	testBin := canonicalTestBinary(t)

	// 1. Real OSC 7501: idle -> quiet-window terminal.send -> working -> done.
	t.Run("osc7501 idle send working done", func(t *testing.T) {
		w := newLiveTestWorkspace(t)
		reportPath := filepath.Join(w.writable, "done.txt")
		req, launchDir := w.buildRequest(
			t, testBin, []string{liveProbeArg, "osc_done", reportPath},
			"HELLO_REAL_HC_7501", true, 10*time.Second, 25*time.Second, 5*time.Second,
			map[string]string{"mulgae_registry": "live-done"},
		)
		obs, err := sess.RunTerminal(context.Background(), req)
		assertLaunchDirClosed(t, launchDir)
		if err != nil {
			t.Fatalf("RunTerminal(osc_done): %v", err)
		}
		if !obs.Reported() || obs.ExitedBeforeReport() || obs.TurnCount() < 1 {
			t.Fatalf("unexpected obs: reported=%t exitedBefore=%t turns=%d", obs.Reported(), obs.ExitedBeforeReport(), obs.TurnCount())
		}
		if st, _ := obs.ProgramStatus(); st != ports.TerminalProgramStatusDone {
			t.Fatalf("ProgramStatus = %q, want done", st)
		}
		if !obs.ProcessObservation().TerminalSessionCompleted() || !obs.ProcessObservation().ProcessGroupAbsent() {
			t.Fatalf("TerminalSessionCompleted=%t ProcessGroupAbsent=%t", obs.ProcessObservation().TerminalSessionCompleted(), obs.ProcessObservation().ProcessGroupAbsent())
		}
		got, err := os.ReadFile(reportPath)
		if err != nil || !strings.Contains(string(got), "RECEIVED:HELLO_REAL_HC_7501") {
			t.Fatalf("report = %q err=%v", string(got), err)
		}
	})

	// 2. Real OSC 7501: timeout check-ins followed by completion.
	t.Run("osc7501 timeout check-ins then done", func(t *testing.T) {
		w := newLiveTestWorkspace(t)
		reportPath := filepath.Join(w.writable, "checkins.txt")
		req, launchDir := w.buildRequest(
			t, testBin, []string{liveProbeArg, "osc_checkins_done", reportPath},
			"CHECKIN_MSG", true, 10*time.Second, 25*time.Second, 200*time.Millisecond,
			nil,
		)
		obs, err := sess.RunTerminal(context.Background(), req)
		assertLaunchDirClosed(t, launchDir)
		if err != nil {
			t.Fatalf("RunTerminal(checkins): %v", err)
		}
		if st, _ := obs.ProgramStatus(); st != ports.TerminalProgramStatusDone {
			t.Fatalf("ProgramStatus = %q, want done", st)
		}
		got, err := os.ReadFile(reportPath)
		if err != nil || !strings.Contains(string(got), "CHECKIN_OK:CHECKIN_MSG") {
			t.Fatalf("checkins report = %q err=%v", string(got), err)
		}
	})

	// 3. Real OSC 7501: blocked(auth).
	t.Run("osc7501 blocked auth", func(t *testing.T) {
		w := newLiveTestWorkspace(t)
		req, launchDir := w.buildRequest(
			t, testBin, []string{liveProbeArg, "osc_blocked_auth"},
			"SHOULD_NOT_SEND", true, 10*time.Second, 20*time.Second, 2*time.Second, nil,
		)
		obs, err := sess.RunTerminal(context.Background(), req)
		assertLaunchDirClosed(t, launchDir)
		if err != nil {
			t.Fatalf("RunTerminal(blocked_auth): %v", err)
		}
		if st, _ := obs.ProgramStatus(); st != ports.TerminalProgramStatusBlocked {
			t.Fatalf("ProgramStatus = %q, want blocked", st)
		}
		if kind, _ := obs.BlockedKind(); kind != ports.TerminalBlockedKindAuth {
			t.Fatalf("BlockedKind = %q, want auth", kind)
		}
	})

	// 4. Real OSC 7501: error.
	t.Run("osc7501 error", func(t *testing.T) {
		w := newLiveTestWorkspace(t)
		req, launchDir := w.buildRequest(
			t, testBin, []string{liveProbeArg, "osc_error"},
			"TRIGGER_ERROR", true, 10*time.Second, 25*time.Second, 2*time.Second, nil,
		)
		obs, err := sess.RunTerminal(context.Background(), req)
		assertLaunchDirClosed(t, launchDir)
		if err != nil {
			t.Fatalf("RunTerminal(osc_error): %v", err)
		}
		if st, _ := obs.ProgramStatus(); st != ports.TerminalProgramStatusError {
			t.Fatalf("ProgramStatus = %q, want error", st)
		}
	})

	// 5. Real pre-reported exit (independent of exit code 10 vs 125).
	for _, code := range []int{10, 125} {
		t.Run(fmt.Sprintf("pre-reported exit %d", code), func(t *testing.T) {
			w := newLiveTestWorkspace(t)
			req, launchDir := w.buildRequest(
				t, testBin, []string{liveProbeArg, "exit_before_report", strconv.Itoa(code)},
				"NEVER_SENT", true, 10*time.Second, 20*time.Second, 2*time.Second, nil,
			)
			obs, err := sess.RunTerminal(context.Background(), req)
			assertLaunchDirClosed(t, launchDir)
			if err != nil {
				t.Fatalf("RunTerminal(exit=%d): %v", code, err)
			}
			if obs.Reported() || !obs.ExitedBeforeReport() {
				t.Fatalf("exit=%d: Reported=%t ExitedBeforeReport=%t", code, obs.Reported(), obs.ExitedBeforeReport())
			}
			if gotCode, ok := obs.ProcessObservation().ExitCode(); !ok || gotCode != code {
				t.Fatalf("ExitCode = (%d, %t), want %d", gotCode, ok, code)
			}
		})
	}

	// 6. Real cancellation mid-turn.
	t.Run("cancellation mid-turn", func(t *testing.T) {
		w := newLiveTestWorkspace(t)
		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			time.Sleep(1500 * time.Millisecond)
			cancel()
		}()
		req, launchDir := w.buildRequest(
			t, testBin, []string{liveProbeArg, "osc_hang_for_cancel"},
			"START_WORK", true, 10*time.Second, 25*time.Second, 5*time.Second, nil,
		)
		obs, err := sess.RunTerminal(ctx, req)
		assertLaunchDirClosed(t, launchDir)
		if err != nil {
			t.Fatalf("RunTerminal(cancel): %v", err)
		}
		if obs.ProcessObservation().Termination() != ports.ProcessTerminationCancelled {
			t.Fatalf("Termination = %q, want cancelled", obs.ProcessObservation().Termination())
		}
		if !obs.ProcessObservation().ProcessGroupAbsent() {
			t.Fatal("cancelled pane did not prove ProcessGroupAbsent")
		}
	})

	// 7. Real holder PTY + Seatbelt kernel boundary verification:
	//    - Every core/holder Unix socket enumerated and EPERM-denied (incl. symlink & hardlink alias)
	//    - Own-slave F_GETPATH + raw mode OK + foreign /dev/ttys* EPERM + TIOCSTI EPERM
	//    - Exact envp (zero DYLD_*, LD_*, GODEBUG, HC_TERMINAL_SOCKET, HC_SOCKET, HC_SESSION, HC_SCOPE; only validated HC_TERMINAL_ID)
	t.Run("real holder PTY sockets tty envp security audit", func(t *testing.T) {
		w := newLiveTestWorkspace(t)
		_, _, foreignTTY := openForeignSyntheticPTY(t)

		// Enumerate EVERY Unix socket under sessionDir (core s.sock + holder s.holder.*.sock).
		var enumeratedSockets []string
		err := filepath.WalkDir(sessionDir, func(path string, d os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			info, statErr := d.Info()
			if statErr == nil && info.Mode()&os.ModeSocket != 0 {
				enumeratedSockets = append(enumeratedSockets, path)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("enumerate session sockets: %v", err)
		}
		if len(enumeratedSockets) < 2 {
			t.Fatalf("expected >= 2 Unix sockets (core + holder) in %s, got %v", sessionDir, enumeratedSockets)
		}
		t.Logf("enumerated session sockets: %v", enumeratedSockets)

		socketArgs := make([]string, 0, len(enumeratedSockets)*2+2)
		for idx, sockPath := range enumeratedSockets {
			socketArgs = append(socketArgs, fmt.Sprintf("direct-%d=%s", idx, sockPath))
			symPath := filepath.Join(w.writable, fmt.Sprintf("sym-%d.sock", idx))
			if err := os.Symlink(sockPath, symPath); err != nil {
				t.Fatal(err)
			}
			socketArgs = append(socketArgs, fmt.Sprintf("symlink:sym-%d=%s", idx, symPath))
		}
		// Also include ALL operator default herdr-core sockets if present (read-only path enumeration only!).
		defaultStateDir := filepath.Join(nativeHome.String(), ".local", "state", "herdr-core", "default")
		if entries, readErr := os.ReadDir(defaultStateDir); readErr == nil {
			for idx, e := range entries {
				if strings.HasSuffix(e.Name(), ".sock") {
					p := filepath.Join(defaultStateDir, e.Name())
					socketArgs = append(socketArgs, fmt.Sprintf("default-core-%d=%s", idx, p))
				}
			}
		}

		// Create a sentinel control file inside sessionDir/panes to verify EPERM denial.
		sentinelControlFile := filepath.Join(sessionDir, "panes", "sentinel.secret")
		if err := os.WriteFile(sentinelControlFile, []byte("top-secret-control-file"), 0o400); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = os.Remove(sentinelControlFile) }()

		reportPath := filepath.Join(w.writable, "audit.json")
		probeArgs := append([]string{liveProbeArg, "security_audit", reportPath, foreignTTY, w.writable, sentinelControlFile}, socketArgs...)
		req, launchDir := w.buildRequest(t, testBin, probeArgs, "", true, 10*time.Second, 20*time.Second, 2*time.Second, nil)
		obs, err := sess.RunTerminal(context.Background(), req)
		assertLaunchDirClosed(t, launchDir)
		if err != nil {
			t.Fatalf("RunTerminal(security_audit): %v", err)
		}
		if !obs.ProcessObservation().TerminalSessionCompleted() {
			t.Fatalf("security_audit observation did not complete cleanly: %+v", obs)
		}

		raw, err := os.ReadFile(reportPath)
		if err != nil {
			t.Fatalf("read audit report: %v", err)
		}
		var rep liveSecurityProbeReport
		if err := json.Unmarshal(raw, &rep); err != nil {
			t.Fatalf("decode audit report: %v\n%s", err, raw)
		}
		if !regexp.MustCompile(`^/dev/ttys[0-9]+$`).MatchString(rep.FGetPath0) {
			t.Fatalf("F_GETPATH on real holder slave = %q, want ^/dev/ttys[0-9]+$", rep.FGetPath0)
		}
		if !rep.OwnTTYOpenOK || !rep.OwnTTYRawModeOK {
			t.Fatalf("own holder slave open/raw mode failed: open=%t raw=%t err=%q", rep.OwnTTYOpenOK, rep.OwnTTYRawModeOK, rep.OwnTTYErr)
		}
		if !rep.ForeignTTYPerm {
			t.Fatalf("foreign TTY %s was not denied EPERM: %q", rep.ForeignTTYPath, rep.ForeignTTYErr)
		}
		if !rep.TIOCSTIPerm {
			t.Fatalf("TIOCSTI was not denied EPERM: %q", rep.TIOCSTIErr)
		}
		if !rep.ControlFilePerm {
			t.Fatalf("private per-pane control file was not denied EPERM: %q", rep.ControlFileReadErr)
		}
		if len(rep.SocketAttempts) != len(socketArgs) {
			t.Fatalf("socket attempts count = %d, want %d (args=%v)", len(rep.SocketAttempts), len(socketArgs), socketArgs)
		}
		for _, attempt := range rep.SocketAttempts {
			if !attempt.ConnectPerm || !attempt.StatPerm {
				t.Fatalf("socket %s (%s) not EPERM-denied: connect=%q stat=%q", attempt.Label, attempt.Path, attempt.ConnectErr, attempt.StatErr)
			}
			if !strings.HasPrefix(attempt.Label, "symlink:") && !attempt.LinkPerm {
				t.Fatalf("hardlink creation to socket %s (%s) not EPERM-denied: link=%q", attempt.Label, attempt.Path, attempt.LinkErr)
			}
		}

		// Verify exact envp equality (7 caller env keys + PWD set to neutralDir
		// by __mulgae_paneexec_v1 + validated HC_TERMINAL_ID; zero SSH_CONNECTION,
		// XDG_*, DYLD_*, LD_*, GODEBUG, HC_SOCKET, HC_TERMINAL_SOCKET, HC_SESSION, HC_SCOPE).
		wantFixedEnv := map[string]string{
			"PATH":         "/usr/bin:/bin",
			"HOME":         filepath.Join(w.writable, "home"),
			"TMPDIR":       filepath.Join(w.writable, "tmp"),
			"PWD":          w.neutralDir,
			"TERM":         "xterm-256color",
			"COLORTERM":    "truecolor",
			"TERM_PROGRAM": "ghostty",
			"LANG":         "en_US.UTF-8",
		}
		envMap := make(map[string]string, len(rep.Env))
		for _, entry := range rep.Env {
			k, v, ok := strings.Cut(entry, "=")
			if !ok {
				t.Fatalf("malformed env entry %q", entry)
			}
			envMap[k] = v
		}
		if len(envMap) != len(wantFixedEnv)+1 {
			t.Fatalf("unexpected envp key count %d (want %d): %v", len(envMap), len(wantFixedEnv)+1, rep.Env)
		}
		for k, wantVal := range wantFixedEnv {
			if gotVal, ok := envMap[k]; !ok || gotVal != wantVal {
				t.Fatalf("env[%q] = (%q, %t), want %q (env=%v)", k, gotVal, ok, wantVal, rep.Env)
			}
		}
		hcID, hasID := envMap[ports.TerminalPaneIDEnvName]
		if !hasID || !ports.ValidTerminalPaneID(hcID) {
			t.Fatalf("validated HC_TERMINAL_ID missing or invalid in pane envp: %q (env=%v)", hcID, rep.Env)
		}

		// Pre-existing hardlink aliases to BOTH core s.sock AND holder socket(s)
		// inside writableDir MUST be rejected BEFORE spawn by
		// validateLiveRootFileLinks (S_IFSOCK Nlink!=1), with canary non-execution.
		for idx, sockPath := range enumeratedSockets {
			hardlinkAlias := filepath.Join(w.writable, fmt.Sprintf("preexisting-sock-%d.sock", idx))
			canaryPath := filepath.Join(w.writable, fmt.Sprintf("hardlink-canary-%d.ran", idx))
			if err := os.Link(sockPath, hardlinkAlias); err != nil {
				t.Fatalf("create pre-existing hardlink alias to %s: %v", sockPath, err)
			}
			hlReq, hlLaunchDir := w.buildRequest(
				t, "/bin/sh",
				[]string{"-c", fmt.Sprintf("touch %s", strconv.Quote(canaryPath))},
				"", false, 5*time.Second, 10*time.Second, 0, nil,
			)
			_, hlErr := sess.RunTerminal(context.Background(), hlReq)
			_ = os.Remove(hardlinkAlias)
			assertLaunchDirClosed(t, hlLaunchDir)
			var procErr *ports.ProcessExecutionError
			if !errors.As(hlErr, &procErr) || procErr.PrimaryCause() != domain.DiagnosticCauseProviderSpawnFailed || procErr.Unwrap() == nil || !strings.Contains(procErr.Unwrap().Error(), "hardlink alias") {
				t.Fatalf("hardlink alias to %s err = %v (unwrapped=%v), want ProcessExecutionError(%s) mentioning hardlink alias",
					sockPath, hlErr, procErr.Unwrap(), domain.DiagnosticCauseProviderSpawnFailed)
			}
			if _, statErr := os.Lstat(canaryPath); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("canary %s executed despite pre-existing socket hardlink alias: %v", canaryPath, statErr)
			}
		}
	})

	// 8. Pure /bin/sh child proves /dev/fd == {0, 1, 2} (plus sh opendir fd 3) on real holder!
	t.Run("strict /dev/fd == {0,1,2} in real holder pane", func(t *testing.T) {
		w := newLiveTestWorkspace(t)
		fdReport := filepath.Join(w.writable, "devfd.txt")
		script := fmt.Sprintf(
			`fds=""; for p in /dev/fd/*; do fds="${fds}${p##*/},"; done; printf 'DEVFD=[%%s]\n' "$fds" > %s`,
			strconv.Quote(fdReport),
		)
		req, launchDir := w.buildRequest(t, "/bin/sh", []string{"-c", script}, "", false, 10*time.Second, 15*time.Second, 2*time.Second, nil)
		obs, err := sess.RunTerminal(context.Background(), req)
		assertLaunchDirClosed(t, launchDir)
		if err != nil {
			t.Fatalf("RunTerminal(/dev/fd check): %v", err)
		}
		if !obs.ProcessObservation().TerminalSessionCompleted() {
			t.Fatalf("/dev/fd pane did not complete cleanly: %+v", obs)
		}
		got, err := os.ReadFile(fdReport)
		if err != nil {
			t.Fatalf("read devfd report: %v", err)
		}
		if strings.TrimSpace(string(got)) != "DEVFD=[0,1,2,3,]" {
			t.Fatalf("unexpected /dev/fd inventory in real holder pane: %q (want DEVFD=[0,1,2,3,])", strings.TrimSpace(string(got)))
		}
	})

	// 9. Verify Close stops BOTH corePID and ALL tracked holderPIDs cleanly and removes sessionDir.
	holderPIDs := sess.HolderPIDs()
	if len(holderPIDs) == 0 {
		t.Fatal("expected at least one tracked holder PID after running real panes")
	}
	t.Logf("stopping isolated core=%d holders=%v dir=%s", corePID, holderPIDs, sessionDir)
	if err := sess.Close(context.Background()); err != nil {
		t.Fatalf("Session.Close(): %v", err)
	}
	closed = true
	if err := unix.Kill(corePID, 0); !errors.Is(err, unix.ESRCH) {
		t.Fatalf("core PID %d survived Close: %v", corePID, err)
	}
	for _, hpid := range holderPIDs {
		if err := unix.Kill(hpid, 0); !errors.Is(err, unix.ESRCH) {
			t.Fatalf("holder PID %d survived Close: %v", hpid, err)
		}
	}
	if _, err := os.Lstat(sessionDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("session dir %s survived Close: %v", sessionDir, err)
	}
}

func TestLiveHerdrParentDeathWatchdogOnSIGKILL(t *testing.T) {
	beforeDefault := captureDefaultCoreSnapshot(t)
	defaultBaseDir := fmt.Sprintf("/private/tmp/mgh-%d", unix.Geteuid())
	t.Cleanup(func() {
		assertNoMulgaeHerdrLeaks(t, defaultBaseDir)
		assertDefaultCoreUntouched(t, beforeDefault)
	})

	nativeHome := mustNativeHomeRoot(t)
	workBase := canonicalTempDir(t)
	stateFile := filepath.Join(workBase, "victim.json")
	testBin := canonicalTestBinary(t)

	victim := exec.Command(testBin, liveWatchdogVictimArg, stateFile, nativeHome.String(), workBase)
	victim.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := victim.Start(); err != nil {
		t.Fatalf("start victim: %v", err)
	}
	victimReaped := false
	defer func() {
		if !victimReaped {
			if victim.Process != nil {
				_ = unix.Kill(victim.Process.Pid, unix.SIGKILL)
			}
			_ = victim.Wait()
		}
	}()

	var st watchdogVictimState
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if raw, err := os.ReadFile(stateFile); err == nil && len(raw) > 0 {
			if json.Unmarshal(raw, &st) == nil && st.CorePID > 0 && len(st.HolderPIDs) > 0 && st.PanePID > 0 {
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	if st.CorePID == 0 || len(st.HolderPIDs) == 0 || st.PanePID == 0 {
		t.Fatalf("victim failed to publish state: %+v", st)
	}
	t.Logf("SIGKILLing victim=%d owning core=%d holders=%v pane=%d dir=%s",
		victim.Process.Pid, st.CorePID, st.HolderPIDs, st.PanePID, st.SessionDir)

	if err := unix.Kill(victim.Process.Pid, unix.SIGKILL); err != nil {
		t.Fatalf("SIGKILL victim: %v", err)
	}
	_ = victim.Wait()
	victimReaped = true

	// Watchdog must clean up core, holder, pane, sessionDir, and then exit promptly!
	cleanupDeadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(cleanupDeadline) {
		coreDead := errors.Is(unix.Kill(st.CorePID, 0), unix.ESRCH)
		paneDead := errors.Is(unix.Kill(st.PanePID, 0), unix.ESRCH)
		watchdogDead := st.WatchdogPID <= 1 || errors.Is(unix.Kill(st.WatchdogPID, 0), unix.ESRCH)
		holdersDead := true
		for _, hpid := range st.HolderPIDs {
			if !errors.Is(unix.Kill(hpid, 0), unix.ESRCH) {
				holdersDead = false
			}
		}
		_, dirErr := os.Lstat(st.SessionDir)
		dirGone := errors.Is(dirErr, os.ErrNotExist)
		if coreDead && paneDead && holdersDead && dirGone && watchdogDead {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("watchdog did not clean up after SIGKILL (core=%d holders=%v pane=%d watchdog=%d dir=%s)",
		st.CorePID, st.HolderPIDs, st.PanePID, st.WatchdogPID, st.SessionDir)
}
