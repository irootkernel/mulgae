//go:build darwin && arm64

package process

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/irootkernel/mulgae/internal/ports"
	"golang.org/x/sys/unix"
)

func openBlockingSyntheticPTY(t *testing.T) (masterFD int, slaveFD int, slavePath string) {
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
		t.Fatal("synthetic pty has no slave name")
	}
	path := string(name[:end])
	slave, err := unix.Open(path, unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		_ = unix.Close(master)
		t.Fatal(err)
	}
	return master, slave, path
}

func readPTYUntilEOF(masterFD int, timeout time.Duration) []byte {
	_ = unix.SetNonblock(masterFD, true)
	deadline := time.Now().Add(timeout)
	var out []byte
	buf := make([]byte, 4096)
	for time.Now().Before(deadline) {
		n, err := unix.Read(masterFD, buf)
		if n > 0 {
			out = append(out, buf[:n]...)
			continue
		}
		if err == unix.EAGAIN || err == unix.EINTR {
			time.Sleep(5 * time.Millisecond)
			continue
		}
		break
	}
	return out
}

func canonicalTestExecutable(t *testing.T) string {
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

func mustRoot(t *testing.T, path string) ports.AnchoredRoot {
	t.Helper()
	r, err := ports.NewAnchoredRoot(path)
	if err != nil {
		t.Fatalf("NewAnchoredRoot(%q): %v", path, err)
	}
	return r
}

func assertTrampolineRejectedExit125(t *testing.T, err error, label string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: trampoline unexpectedly succeeded", label)
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 125 {
		t.Fatalf("%s: err = %v (exit=%d), want trampoline rejection exit 125", label, err, exitCodeOrNeg(err))
	}
}

func exitCodeOrNeg(err error) int {
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	return -1
}

func writeMarkerExecutable(t *testing.T, path, markerPath string) {
	t.Helper()
	script := fmt.Sprintf("#!/bin/sh\nprintf RAN > %s\nexit 0\n", strconv.Quote(markerPath))
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
}

func assertMarkerAbsent(t *testing.T, markerPath, label string) {
	t.Helper()
	if _, err := os.Lstat(markerPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("%s: marker %q exists or stat failed (target executed!): err=%v", label, markerPath, err)
	}
}

func copyFileExecutable(t *testing.T, src, dst string) {
	t.Helper()
	in, err := os.Open(src)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o700)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		t.Fatal(err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
}

type paneTestFixture struct {
	base            string
	source          string
	neutral         string
	nativeHome      string
	writable        string
	controlPlaneDir string
	paneControlDir  string
	credentials     []string
}

func newPaneTestFixture(t *testing.T) paneTestFixture {
	t.Helper()
	// Keep temporary base short so Unix socket paths stay well under Darwin's 104-byte sun_path limit.
	tmp, err := os.MkdirTemp("", "mp")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(tmp) })
	base, err := filepath.EvalSymlinks(tmp)
	if err != nil {
		t.Fatal(err)
	}
	f := paneTestFixture{
		base:            base,
		source:          filepath.Join(base, "src"),
		neutral:         filepath.Join(base, "neu"),
		nativeHome:      filepath.Join(base, "home"),
		writable:        filepath.Join(base, "ns"),
		controlPlaneDir: filepath.Join(base, "cp"),
		paneControlDir:  filepath.Join(base, "cp", "p1"),
	}
	f.credentials = []string{
		filepath.Join(f.nativeHome, ".grok"),
		filepath.Join(f.nativeHome, ".cursor"),
		filepath.Join(f.nativeHome, ".config", "cursor"),
	}
	for _, dir := range []string{
		f.source, f.neutral, f.nativeHome, f.writable,
		filepath.Join(f.writable, "home"),
		filepath.Join(f.writable, "settings"),
		filepath.Join(f.writable, "tmp"),
		f.controlPlaneDir, f.paneControlDir,
	} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

func (f paneTestFixture) buildLaunch(
	t *testing.T,
	providerExec string,
	providerArgs []string,
	extraEnv []ports.EnvironmentVariable,
	configureBoundary func(ports.LiveReadOnlyBoundary) (ports.LiveReadOnlyBoundary, error),
) ports.PaneLaunchSpec {
	t.Helper()
	packet, err := ports.NewProviderPacketFromBytes([]byte("pane exec fixture packet"))
	if err != nil {
		t.Fatal(err)
	}
	binding, err := ports.NewTerminalProviderPacketBinding(packet)
	if err != nil {
		t.Fatal(err)
	}
	env := []ports.EnvironmentVariable{
		mustEnvironment(t, "PATH", "/usr/bin:/bin"),
		mustEnvironment(t, "HOME", filepath.Join(f.writable, "home")),
		mustEnvironment(t, "XDG_CONFIG_HOME", filepath.Join(f.writable, "settings")),
		mustEnvironment(t, "TMPDIR", filepath.Join(f.writable, "tmp")),
		mustEnvironment(t, "TERM", "xterm-256color"),
		mustEnvironment(t, "COLORTERM", "truecolor"),
		mustEnvironment(t, "TERM_PROGRAM", "ghostty"),
		mustEnvironment(t, "LANG", "en_US.UTF-8"),
	}
	env = append(env, extraEnv...)
	argv := append([]string{providerExec}, providerArgs...)
	req, err := ports.NewProviderTerminalProcessRequest(providerExec, argv, env, f.neutral, binding, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	credRoots := make([]ports.AnchoredRoot, 0, len(f.credentials))
	for _, c := range f.credentials {
		credRoots = append(credRoots, mustRoot(t, c))
	}
	boundary, err := ports.NewLiveReadOnlyBoundary(
		[]ports.AnchoredRoot{mustRoot(t, f.source), mustRoot(t, f.neutral)},
		credRoots,
		mustRoot(t, f.writable),
	)
	if err != nil {
		t.Fatal(err)
	}
	boundary, err = ports.NewLiveReadOnlyBoundaryWithControlPlane(
		boundary,
		[]ports.AnchoredRoot{mustRoot(t, f.controlPlaneDir), mustRoot(t, filepath.Join(f.base, "missing-cp-root"))},
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	boundary, err = ports.NewLiveReadOnlyBoundaryWithPaneTTY(boundary, mustRoot(t, f.nativeHome))
	if err != nil {
		t.Fatal(err)
	}
	if configureBoundary != nil {
		boundary, err = configureBoundary(boundary)
		if err != nil {
			t.Fatal(err)
		}
	}
	req, err = ports.NewLiveReadOnlyProcessRequest(req, boundary)
	if err != nil {
		t.Fatal(err)
	}
	launchReq, err := ports.NewPaneLaunchRequest(req, mustRoot(t, f.paneControlDir))
	if err != nil {
		t.Fatal(err)
	}
	spec, err := NewPaneLaunchBuilder().BuildPaneLaunch(context.Background(), launchReq)
	if err != nil {
		t.Fatalf("BuildPaneLaunch: %v", err)
	}
	return spec
}

func runSpecOnSyntheticPTY(t *testing.T, argv []string, env []string, extraFiles []*os.File) ([]byte, error, string) {
	t.Helper()
	masterFD, slaveFD, slavePath := openBlockingSyntheticPTY(t)
	defer func() { _ = unix.Close(masterFD) }()
	slaveFile := os.NewFile(uintptr(slaveFD), slavePath)

	cmd := &exec.Cmd{
		Path:        argv[0],
		Args:        argv,
		Env:         env,
		Stdin:       slaveFile,
		Stdout:      slaveFile,
		Stderr:      slaveFile,
		ExtraFiles:  extraFiles,
		SysProcAttr: &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0},
	}
	if err := cmd.Start(); err != nil {
		_ = slaveFile.Close()
		return nil, err, slavePath
	}
	_ = slaveFile.Close()

	waitCh := make(chan error, 1)
	go func() { waitCh <- cmd.Wait() }()

	out := readPTYUntilEOF(masterFD, 10*time.Second)
	var waitErr error
	select {
	case waitErr = <-waitCh:
	case <-time.After(10 * time.Second):
		_ = cmd.Process.Kill()
		select {
		case <-waitCh:
		case <-time.After(time.Second):
		}
		waitErr = errors.New("pane child timed out")
	}
	return out, waitErr, slavePath
}

// TestPaneExecChild runs inside the real macOS Seatbelt sandbox launched via
// __mulgae_paneexec_v1 on a synthetic controlling PTY.
func TestPaneExecChild(t *testing.T) {
	args := helperArguments()
	if len(args) < 2 || args[0] != "paneexec" {
		return
	}
	mode := args[1]
	switch mode {
	case "inspect":
		// Args: expectedCWD, foreignSlavePath, canaryDev, canaryIno, pipeDev, pipeIno, writableRoot, expectHCID
		if len(args) != 10 {
			fmt.Fprintf(os.Stderr, "bad inspect args: %v\n", args)
			os.Exit(2)
		}
		expectedCWD := args[2]
		foreignSlave := args[3]
		canaryDev, _ := strconv.ParseUint(args[4], 10, 64)
		canaryIno, _ := strconv.ParseUint(args[5], 10, 64)
		pipeDev, _ := strconv.ParseUint(args[6], 10, 64)
		pipeIno, _ := strconv.ParseUint(args[7], 10, 64)
		writableRoot := args[8]
		expectHCID := args[9]

		// 1. Verify cwd.
		cwd, err := os.Getwd()
		if err != nil || cwd != expectedCWD {
			fmt.Fprintf(os.Stderr, "cwd=%q want=%q err=%v\n", cwd, expectedCWD, err)
			os.Exit(21)
		}

		// 2. Verify inherited canary and leaked pipe FDs are absent from /dev/fd.
		if canaryDev == 0 || canaryIno == 0 || pipeIno == 0 {
			fmt.Fprintf(os.Stderr, "invalid canary/pipe identities: canary=(%d,%d) pipe=(%d,%d)\n", canaryDev, canaryIno, pipeDev, pipeIno)
			os.Exit(22)
		}
		fdDir, err := os.Open("/dev/fd")
		if err != nil {
			fmt.Fprintf(os.Stderr, "open /dev/fd: %v\n", err)
			os.Exit(22)
		}
		names, err := fdDir.Readdirnames(-1)
		if err != nil {
			fmt.Fprintf(os.Stderr, "readdir /dev/fd: %v\n", err)
			os.Exit(22)
		}
		dirFD := int(fdDir.Fd())
		for _, name := range names {
			fd, convErr := strconv.Atoi(name)
			if convErr != nil || fd < 3 || fd == dirFD {
				continue
			}
			var st unix.Stat_t
			if err := unix.Fstat(fd, &st); err != nil {
				continue
			}
			if uint64(st.Dev) == canaryDev && st.Ino == canaryIno {
				fmt.Fprintf(os.Stderr, "leaked canary fd=%d\n", fd)
				os.Exit(23)
			}
			// On Darwin anonymous pipes have st_dev == 0 and non-zero st_ino with S_IFIFO.
			if st.Mode&unix.S_IFMT == unix.S_IFIFO && uint64(st.Dev) == pipeDev && st.Ino == pipeIno {
				fmt.Fprintf(os.Stderr, "leaked pipe fd=%d\n", fd)
				os.Exit(24)
			}
		}
		_ = fdDir.Close()

		// 3. Verify EXACT envp equality against expected keys/values (zero extra, zero missing).
		wantEnv := map[string]string{
			"PATH":            "/usr/bin:/bin",
			"HOME":            filepath.Join(writableRoot, "home"),
			"XDG_CONFIG_HOME": filepath.Join(writableRoot, "settings"),
			"TMPDIR":          filepath.Join(writableRoot, "tmp"),
			"PWD":             expectedCWD,
			"TERM":            "xterm-256color",
			"COLORTERM":       "truecolor",
			"TERM_PROGRAM":    "ghostty",
			"LANG":            "en_US.UTF-8",
		}
		if expectHCID != "" {
			wantEnv["HC_TERMINAL_ID"] = expectHCID
		}
		gotEnv := map[string]string{}
		for _, pair := range os.Environ() {
			k, v, ok := strings.Cut(pair, "=")
			if !ok {
				os.Exit(25)
			}
			gotEnv[k] = v
		}
		if len(gotEnv) != len(wantEnv) {
			fmt.Fprintf(os.Stderr, "env count mismatch: got=%v want=%v\n", gotEnv, wantEnv)
			os.Exit(26)
		}
		for k, wv := range wantEnv {
			if gv, ok := gotEnv[k]; !ok || gv != wv {
				fmt.Fprintf(os.Stderr, "env key %q mismatch: got=(%q,%t) want=%q\n", k, gv, ok, wv)
				os.Exit(27)
			}
		}

		// 4. Verify own PANE_TTY raw-mode termios + TIOCGWINSZ + /dev/tty + direct own slave path open.
		termios, err := unix.IoctlGetTermios(0, unix.TIOCGETA)
		if err != nil {
			fmt.Fprintf(os.Stderr, "TIOCGETA failed: %v\n", err)
			os.Exit(28)
		}
		raw := *termios
		raw.Lflag &^= unix.ECHO | unix.ICANON
		if err := unix.IoctlSetTermios(0, unix.TIOCSETA, &raw); err != nil {
			fmt.Fprintf(os.Stderr, "TIOCSETA raw failed: %v\n", err)
			os.Exit(29)
		}
		if err := unix.IoctlSetTermios(0, unix.TIOCSETA, termios); err != nil {
			fmt.Fprintf(os.Stderr, "TIOCSETA restore failed: %v\n", err)
			os.Exit(30)
		}
		if _, err := unix.IoctlGetWinsize(0, unix.TIOCGWINSZ); err != nil {
			fmt.Fprintf(os.Stderr, "TIOCGWINSZ failed: %v\n", err)
			os.Exit(31)
		}
		ownPath, err := descriptorPath(0)
		if err != nil || !paneTTYSlaveRegexp.MatchString(ownPath) {
			fmt.Fprintf(os.Stderr, "own slave path=%q err=%v\n", ownPath, err)
			os.Exit(32)
		}
		ownFD, err := unix.Open(ownPath, unix.O_RDWR|unix.O_NOCTTY, 0)
		if err != nil {
			fmt.Fprintf(os.Stderr, "direct open own slave %q failed: %v\n", ownPath, err)
			os.Exit(33)
		}
		if _, err := unix.IoctlGetTermios(ownFD, unix.TIOCGETA); err != nil {
			_ = unix.Close(ownFD)
			fmt.Fprintf(os.Stderr, "own slave TIOCGETA failed: %v\n", err)
			os.Exit(34)
		}
		if _, err := unix.IoctlGetWinsize(ownFD, unix.TIOCGWINSZ); err != nil {
			_ = unix.Close(ownFD)
			fmt.Fprintf(os.Stderr, "own slave TIOCGWINSZ failed: %v\n", err)
			os.Exit(35)
		}
		if _, err := unix.Write(ownFD, []byte("OWN_SLAVE_OPEN_OK\n")); err != nil {
			_ = unix.Close(ownFD)
			fmt.Fprintf(os.Stderr, "own slave write failed: %v\n", err)
			os.Exit(36)
		}
		_ = unix.Close(ownFD)

		ttyFD, err := unix.Open("/dev/tty", unix.O_RDWR, 0)
		if err != nil {
			fmt.Fprintf(os.Stderr, "open /dev/tty failed: %v\n", err)
			os.Exit(37)
		}
		_, _ = unix.Write(ttyFD, []byte("DEV_TTY_WRITE_OK\n"))
		_ = unix.Close(ttyFD)

		// 5. TIOCSTI on own tty MUST fail EPERM.
		var ch byte = 'x'
		if _, _, errno := unix.Syscall(unix.SYS_IOCTL, 0, uintptr(unix.TIOCSTI), uintptr(unsafe.Pointer(&ch))); errno != unix.EPERM {
			fmt.Fprintf(os.Stderr, "TIOCSTI errno=%v want EPERM\n", errno)
			os.Exit(38)
		}

		// 6. Foreign /dev/ttys* MUST fail EPERM.
		if fd, err := unix.Open(foreignSlave, unix.O_RDONLY|unix.O_NOCTTY|unix.O_NONBLOCK, 0); err != unix.EPERM {
			if err == nil {
				_ = unix.Close(fd)
			}
			fmt.Fprintf(os.Stderr, "foreign read open err=%v want EPERM\n", err)
			os.Exit(39)
		}
		if fd, err := unix.Open(foreignSlave, unix.O_WRONLY|unix.O_NOCTTY|unix.O_NONBLOCK, 0); err != unix.EPERM {
			if err == nil {
				_ = unix.Close(fd)
			}
			fmt.Fprintf(os.Stderr, "foreign write open err=%v want EPERM\n", err)
			os.Exit(40)
		}

		// 7. /dev/ptmx MUST fail EPERM in PaneTTY-only mode.
		if fd, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY, 0); err != unix.EPERM {
			if err == nil {
				_ = unix.Close(fd)
			}
			fmt.Fprintf(os.Stderr, "/dev/ptmx open err=%v want EPERM\n", err)
			os.Exit(41)
		}

		fmt.Fprintln(os.Stdout, "PANE_INSPECT_OK")
		os.Exit(0)

	case "composed-pty":
		// Args: foreignSlavePath
		if len(args) != 3 {
			os.Exit(2)
		}
		foreignSlave := args[2]
		// Own PANE_TTY raw-mode termios round-trip, /dev/tty, and direct own slave path open must all work.
		termios, err := unix.IoctlGetTermios(0, unix.TIOCGETA)
		if err != nil {
			fmt.Fprintf(os.Stderr, "composed TIOCGETA err=%v\n", err)
			os.Exit(41)
		}
		raw := *termios
		raw.Lflag &^= unix.ECHO | unix.ICANON
		if err := unix.IoctlSetTermios(0, unix.TIOCSETA, &raw); err != nil {
			fmt.Fprintf(os.Stderr, "composed TIOCSETA raw err=%v\n", err)
			os.Exit(42)
		}
		if err := unix.IoctlSetTermios(0, unix.TIOCSETA, termios); err != nil {
			fmt.Fprintf(os.Stderr, "composed TIOCSETA restore err=%v\n", err)
			os.Exit(43)
		}
		ownPath, err := descriptorPath(0)
		if err != nil || !paneTTYSlaveRegexp.MatchString(ownPath) {
			fmt.Fprintf(os.Stderr, "composed own slave path=%q err=%v\n", ownPath, err)
			os.Exit(44)
		}
		ownFD, err := unix.Open(ownPath, unix.O_RDWR|unix.O_NOCTTY, 0)
		if err != nil {
			fmt.Fprintf(os.Stderr, "composed open own slave %q err=%v\n", ownPath, err)
			os.Exit(45)
		}
		if _, err := unix.IoctlGetTermios(ownFD, unix.TIOCGETA); err != nil {
			_ = unix.Close(ownFD)
			fmt.Fprintf(os.Stderr, "composed own slave TIOCGETA err=%v\n", err)
			os.Exit(46)
		}
		if _, err := unix.IoctlGetWinsize(ownFD, unix.TIOCGWINSZ); err != nil {
			_ = unix.Close(ownFD)
			fmt.Fprintf(os.Stderr, "composed own slave TIOCGWINSZ err=%v\n", err)
			os.Exit(47)
		}
		if _, err := unix.Write(ownFD, []byte("COMPOSED_OWN_SLAVE_OK\n")); err != nil {
			_ = unix.Close(ownFD)
			fmt.Fprintf(os.Stderr, "composed own slave write err=%v\n", err)
			os.Exit(48)
		}
		_ = unix.Close(ownFD)

		ttyFD, err := unix.Open("/dev/tty", unix.O_RDWR, 0)
		if err != nil {
			fmt.Fprintf(os.Stderr, "composed /dev/tty err=%v\n", err)
			os.Exit(49)
		}
		_ = unix.Close(ttyFD)
		// Nested /dev/ptmx allocation must work when OwnedPTY is composed.
		m, s, _, err := openSyntheticPTY()
		if err != nil {
			fmt.Fprintf(os.Stderr, "composed nested pty err=%v\n", err)
			os.Exit(50)
		}
		_ = unix.Close(s)
		_ = unix.Close(m)
		// Foreign slave and TIOCSTI must STILL fail EPERM.
		if fd, err := unix.Open(foreignSlave, unix.O_RDONLY|unix.O_NOCTTY|unix.O_NONBLOCK, 0); err != unix.EPERM {
			if err == nil {
				_ = unix.Close(fd)
			}
			fmt.Fprintf(os.Stderr, "composed foreign slave err=%v\n", err)
			os.Exit(51)
		}
		var ch byte = 'x'
		if _, _, errno := unix.Syscall(unix.SYS_IOCTL, 0, uintptr(unix.TIOCSTI), uintptr(unsafe.Pointer(&ch))); errno != unix.EPERM {
			fmt.Fprintf(os.Stderr, "composed TIOCSTI errno=%v\n", errno)
			os.Exit(52)
		}
		fmt.Fprintln(os.Stdout, "PANE_COMPOSED_OK")
		os.Exit(0)

	case "deny-files-and-sockets":
		// Args: comma-separated denied file paths, comma-separated denied socket paths
		if len(args) != 4 {
			os.Exit(2)
		}
		for _, p := range strings.Split(args[2], ",") {
			if p == "" {
				continue
			}
			fd, err := unix.Open(p, unix.O_RDONLY, 0)
			if err != unix.EPERM {
				if err == nil {
					_ = unix.Close(fd)
				}
				fmt.Fprintf(os.Stderr, "file %q not denied EPERM: err=%v\n", p, err)
				os.Exit(51)
			}
		}
		for _, sock := range strings.Split(args[3], ",") {
			if sock == "" {
				continue
			}
			conn, err := net.DialTimeout("unix", sock, time.Second)
			if err == nil {
				_ = conn.Close()
				fmt.Fprintf(os.Stderr, "socket %q unexpectedly connected\n", sock)
				os.Exit(52)
			}
			if !errors.Is(err, unix.EPERM) && !strings.Contains(strings.ToLower(err.Error()), "operation not permitted") {
				fmt.Fprintf(os.Stderr, "socket %q error=%v want EPERM\n", sock, err)
				os.Exit(53)
			}
		}
		fmt.Fprintln(os.Stdout, "PANE_DENIES_OK")
		os.Exit(0)

	case "bash-gate":
		// Args: writable socket, IPv4, IPv6, denied executables, companion fixture.
		if len(args) != 7 {
			os.Exit(2)
		}
		writableSock := args[2]
		ipv4Addr := args[3]
		ipv6Addr := args[4]
		deniedBins := strings.Split(args[5], ",")

		// 1. Arbitrary unix socket (even inside WritableRoot!) must be denied EPERM.
		if conn, err := net.DialTimeout("unix", writableSock, time.Second); err == nil {
			_ = conn.Close()
			fmt.Fprintln(os.Stderr, "writable unix socket connected under bash-gate")
			os.Exit(61)
		} else if !errors.Is(err, unix.EPERM) {
			fmt.Fprintf(os.Stderr, "writable unix socket err=%v want EPERM\n", err)
			os.Exit(62)
		}

		// 2. /private/var/run/mDNSResponder must remain allowed.
		if conn, err := net.DialTimeout("unix", "/private/var/run/mDNSResponder", time.Second); err != nil {
			fmt.Fprintf(os.Stderr, "mDNSResponder denied under bash-gate: %v\n", err)
			os.Exit(63)
		} else {
			_ = conn.Close()
		}

		// 3. localhost IPv4 and IPv6 TCP must fail EPERM.
		for _, addr := range []string{ipv4Addr, ipv6Addr} {
			if addr == "" {
				continue
			}
			if conn, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
				_ = conn.Close()
				fmt.Fprintf(os.Stderr, "localhost tcp %s connected under bash-gate\n", addr)
				os.Exit(64)
			} else if !errors.Is(err, unix.EPERM) {
				fmt.Fprintf(os.Stderr, "localhost tcp %s err=%v want EPERM\n", addr, err)
				os.Exit(65)
			}
		}

		// 4. Denied local executables (including copy-and-exec inside WritableRoot and ReadOnlyRoots) must fail EPERM.
		for _, bin := range deniedBins {
			if bin == "" {
				continue
			}
			err := exec.Command(bin).Run()
			if err == nil {
				fmt.Fprintf(os.Stderr, "denied binary %s succeeded under bash-gate\n", bin)
				os.Exit(66)
			}
			if !errors.Is(err, unix.EPERM) && !strings.Contains(strings.ToLower(err.Error()), "operation not permitted") {
				fmt.Fprintf(os.Stderr, "denied binary %s err=%v want EPERM\n", bin, err)
				os.Exit(67)
			}
		}

		for _, binary := range []string{"/usr/bin/true", args[6]} {
			if err := exec.Command(binary).Run(); err != nil {
				fmt.Fprintf(os.Stderr, "%s failed under bash-gate: %v\n", binary, err)
				os.Exit(68)
			}
		}

		fmt.Fprintln(os.Stdout, "PANE_BASH_GATE_OK")
		os.Exit(0)
	}
	os.Exit(2)
}

func TestProcessRunnerRunRejectsTerminalRequestBeforeSpawn(t *testing.T) {
	f := newPaneTestFixture(t)
	marker := filepath.Join(f.writable, "runner-spawned-marker")
	target := filepath.Join(f.base, "should-not-run")
	writeMarkerExecutable(t, target, marker)

	packet, err := ports.NewProviderPacketFromBytes([]byte("terminal packet"))
	if err != nil {
		t.Fatal(err)
	}
	binding, err := ports.NewTerminalProviderPacketBinding(packet)
	if err != nil {
		t.Fatal(err)
	}
	req, err := ports.NewProviderTerminalProcessRequest(target, []string{target}, nil, f.neutral, binding, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	boundary, err := ports.NewLiveReadOnlyBoundary(
		[]ports.AnchoredRoot{mustRoot(t, f.source), mustRoot(t, f.neutral)},
		[]ports.AnchoredRoot{mustRoot(t, f.credentials[0])},
		mustRoot(t, f.writable),
	)
	if err != nil {
		t.Fatal(err)
	}
	boundary, err = ports.NewLiveReadOnlyBoundaryWithPaneTTY(boundary, mustRoot(t, f.nativeHome))
	if err != nil {
		t.Fatal(err)
	}
	req, err = ports.NewLiveReadOnlyProcessRequest(req, boundary)
	if err != nil {
		t.Fatal(err)
	}
	launchDir, err := os.Open(f.neutral)
	if err != nil {
		t.Fatal(err)
	}
	defer launchDir.Close()
	req, err = ports.NewNeutralBoundProcessRequest(req, mustRoot(t, f.neutral), launchDir)
	if err != nil {
		t.Fatal(err)
	}

	runner, err := NewRunner(&runnerTestClock{times: []time.Time{time.Now().UTC()}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Run(context.Background(), req); err == nil || !strings.Contains(err.Error(), "terminal") {
		t.Fatalf("Runner.Run(terminal) error = %v, want terminal rejection", err)
	}
	if _, err := launchDir.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("Runner.Run(terminal) early rejection retained launch directory: %v", err)
	}
	assertMarkerAbsent(t, marker, "Runner.Run(terminal)")
}

// TestLiveBoundaryAGYOwnedPTYProfileByteIdentical pins the exact SBPL profile
// output for AGY's OwnedPTY boundary so TASK-084 additions never perturb
// existing AGY Seatbelt clauses by even one byte.
func TestLiveBoundaryAGYOwnedPTYProfileByteIdentical(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(base, "source")
	neutral := filepath.Join(base, "neutral")
	creds := filepath.Join(base, "credentials")
	writable := filepath.Join(base, "writable")
	for _, dir := range []string{source, neutral, creds, writable} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	packet, err := ports.NewProviderPacketFromBytes([]byte("agy fixture"))
	if err != nil {
		t.Fatal(err)
	}
	binding, err := ports.NewProtocolProviderPacketBinding(packet)
	if err != nil {
		t.Fatal(err)
	}
	req, err := ports.NewProviderProtocolProcessRequest("/bin/sh", []string{"/bin/sh", "-c", "exit 0"}, nil, neutral, binding, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	boundary, err := ports.NewLiveReadOnlyBoundary(
		[]ports.AnchoredRoot{mustRoot(t, source), mustRoot(t, neutral)},
		[]ports.AnchoredRoot{mustRoot(t, creds)},
		mustRoot(t, writable),
	)
	if err != nil {
		t.Fatal(err)
	}
	boundary, err = ports.NewLiveReadOnlyBoundaryWithOwnedPTY(boundary)
	if err != nil {
		t.Fatal(err)
	}
	req, err = ports.NewLiveReadOnlyProcessRequest(req, boundary)
	if err != nil {
		t.Fatal(err)
	}
	execPath, argv, err := liveBoundaryArgv(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if execPath != seatbeltExecutable || len(argv) < 3 || argv[1] != "-p" {
		t.Fatalf("unexpected argv = %q", argv)
	}
	gotProfile := argv[2]

	// Build exact pre-TASK-084 OwnedPTY SBPL profile byte-for-byte.
	var want strings.Builder
	want.WriteString("(version 1)\n(allow default)\n")
	want.WriteString("(deny file-write* file-link (require-all (require-not (subpath " + strconv.Quote(writable) + ")) (require-not (literal \"/dev/null\")) (require-not (literal \"/dev/ptmx\")) (require-not (require-all (regex #\"^/dev/ttys[0-9]+$\") (extension \"com.apple.sandbox.pty\")))))\n")
	want.WriteString("(allow pseudo-tty)\n")
	want.WriteString("(deny file-read* file-write* (literal \"/dev/tty\"))\n")
	want.WriteString("(deny file-read* file-write* file-ioctl (require-all (regex #\"^/dev/ttys[0-9]+$\") (require-not (extension \"com.apple.sandbox.pty\"))))\n")
	seen := map[string]bool{}
	for _, group := range []struct {
		paths []string
		ops   string
	}{
		{[]string{source, neutral}, "file-write* file-link"},
		{[]string{creds}, "file-read* file-write* file-link"},
	} {
		for _, p := range group.paths {
			want.WriteString("(deny " + group.ops + " (subpath " + strconv.Quote(p) + "))\n")
			want.WriteString("(deny network-outbound (remote unix-socket (subpath " + strconv.Quote(p) + ")))\n")
			for parent := p; parent != "/"; parent = filepath.Dir(parent) {
				if !seen[parent] {
					want.WriteString("(deny file-write-unlink (literal " + strconv.Quote(parent) + "))\n")
					seen[parent] = true
				}
			}
		}
	}
	if gotProfile != want.String() {
		t.Fatalf("AGY OwnedPTY SBPL profile drifted!\ngot:\n%s\nwant:\n%s", gotProfile, want.String())
	}
}

func TestPaneExecTrampolineFDSetEnvScrubbingAndControllingTTY(t *testing.T) {
	f := newPaneTestFixture(t)
	binary := canonicalTestExecutable(t)
	canary := openInheritedCanary(t, f.base)

	foreignMaster, foreignSlave, foreignPath := openBlockingSyntheticPTY(t)
	defer func() {
		_ = unix.Close(foreignMaster)
		_ = unix.Close(foreignSlave)
	}()

	leakedPipeR, leakedPipeW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer leakedPipeR.Close()
	defer leakedPipeW.Close()
	if _, err := leakedPipeW.Write([]byte("PIPE_CANARY")); err != nil {
		t.Fatal(err)
	}
	var pipeStat unix.Stat_t
	if err := unix.Fstat(int(leakedPipeR.Fd()), &pipeStat); err != nil {
		t.Fatal(err)
	}
	if pipeStat.Ino == 0 || pipeStat.Mode&unix.S_IFMT != unix.S_IFIFO {
		t.Fatalf("unexpected leaked pipe stat: dev=%d ino=%d mode=%#o", pipeStat.Dev, pipeStat.Ino, pipeStat.Mode)
	}

	pollutedEnvBase := []string{
		"HC_TERMINAL_SOCKET=/private/tmp/mgh-501/s.sock",
		"HC_SOCKET=/private/tmp/mgh-501/s.sock",
		"HC_SESSION=mulgae-1234",
		"HC_SCOPE=default",
		"DYLD_LIBRARY_PATH=/tmp/evil",
		"DYLD_FALLBACK_LIBRARY_PATH=/tmp/evil-fallback",
		"DYLD_FRAMEWORK_PATH=/tmp/evil-framework",
		"LD_PRELOAD=/tmp/evil.so",
		"GODEBUG=http2debug=2",
		"XDG_STATE_HOME=/private/tmp/mgh-501/state",
		"AMBIENT_HOST_SECRET=top-secret-value",
	}

	// 1. Valid HC_TERMINAL_ID pass-through + exact envp equality + own PANE_TTY raw mode/direct open + leaked canary/pipe absence.
	t.Run("with valid HC_TERMINAL_ID", func(t *testing.T) {
		spec := f.buildLaunch(
			t,
			binary,
			[]string{
				"-test.run=^TestPaneExecChild$", "--", "paneexec", "inspect",
				f.neutral, foreignPath,
				strconv.FormatUint(canary.device, 10), strconv.FormatUint(canary.inode, 10),
				strconv.FormatUint(uint64(pipeStat.Dev), 10), strconv.FormatUint(pipeStat.Ino, 10),
				f.writable, "pane-valid-42",
			},
			nil,
			nil,
		)
		pollutedEnv := append([]string{"HC_TERMINAL_ID=pane-valid-42"}, pollutedEnvBase...)
		out, runErr, _ := runSpecOnSyntheticPTY(t, spec.Argv(), pollutedEnv, []*os.File{leakedPipeR})
		if runErr != nil || !bytes.Contains(out, []byte("OWN_SLAVE_OPEN_OK")) ||
			!bytes.Contains(out, []byte("DEV_TTY_WRITE_OK")) || !bytes.Contains(out, []byte("PANE_INSPECT_OK")) {
			t.Fatalf("pane inspect failed: err=%v output=%q", runErr, string(out))
		}
		canary.assertParentPreserved(t)
	})

	// 2. Absent HC_TERMINAL_ID: exact envp contains ONLY the 0400 env file entries (zero HC_TERMINAL_ID).
	t.Run("with absent HC_TERMINAL_ID", func(t *testing.T) {
		fAbsent := newPaneTestFixture(t)
		spec := fAbsent.buildLaunch(
			t,
			binary,
			[]string{
				"-test.run=^TestPaneExecChild$", "--", "paneexec", "inspect",
				fAbsent.neutral, foreignPath,
				strconv.FormatUint(canary.device, 10), strconv.FormatUint(canary.inode, 10),
				strconv.FormatUint(uint64(pipeStat.Dev), 10), strconv.FormatUint(pipeStat.Ino, 10),
				fAbsent.writable, "",
			},
			nil,
			nil,
		)
		out, runErr, _ := runSpecOnSyntheticPTY(t, spec.Argv(), pollutedEnvBase, []*os.File{leakedPipeR})
		if runErr != nil || !bytes.Contains(out, []byte("OWN_SLAVE_OPEN_OK")) || !bytes.Contains(out, []byte("PANE_INSPECT_OK")) {
			t.Fatalf("pane inspect (absent HC_TERMINAL_ID) failed: err=%v output=%q", runErr, string(out))
		}
		canary.assertParentPreserved(t)
	})

	// 3. Pure /bin/sh child (zero Go runtime internal descriptors) with both canary (including highFD)
	// and leakedPipeR/W open proves /dev/fd inside child is strictly {0,1,2} (plus sh's opendir fd 3).
	t.Run("strict {0,1,2} FD set in shell child including high canary FD", func(t *testing.T) {
		fShell := newPaneTestFixture(t)
		checkFDs := []string{"3", "4", "5", "6", "7", "8", "9", strconv.Itoa(canary.fd)}
		if canary.highFD >= 0 {
			checkFDs = append(checkFDs, strconv.Itoa(canary.highFD))
		}
		script := fmt.Sprintf(
			`for fd in %s; do if (exec >&$fd) 2>/dev/null; then echo LEAKED_FD_$fd; exit 9; fi; done; fds=""; for p in /dev/fd/*; do fds="${fds}${p##*/},"; done; printf 'DEVFD=[%%s]\n' "$fds"; echo STRICT_FD_SET_OK`,
			strings.Join(checkFDs, " "),
		)
		fdCheckSpec := fShell.buildLaunch(t, "/bin/sh", []string{"-c", script}, nil, nil)
		pollutedEnv := append([]string{"HC_TERMINAL_ID=pane-valid-42"}, pollutedEnvBase...)
		fdOut, fdErr, _ := runSpecOnSyntheticPTY(t, fdCheckSpec.Argv(), pollutedEnv, []*os.File{leakedPipeR, leakedPipeW})
		if fdErr != nil || !bytes.Contains(fdOut, []byte("STRICT_FD_SET_OK")) || bytes.Contains(fdOut, []byte("LEAKED_FD")) {
			t.Fatalf("strict {0,1,2} fd check failed: err=%v output=%q", fdErr, string(fdOut))
		}
		if !bytes.Contains(fdOut, []byte("DEVFD=[0,1,2,3,]")) {
			t.Fatalf("unexpected /dev/fd inventory (want strictly 0,1,2 plus sh opendir fd 3): output=%q", string(fdOut))
		}
		canary.assertParentPreserved(t)
	})
}

func TestPaneExecTrampolineComposedPaneTTYWithOwnedPTY(t *testing.T) {
	f := newPaneTestFixture(t)
	binary := canonicalTestExecutable(t)
	foreignMaster, foreignSlave, foreignPath := openBlockingSyntheticPTY(t)
	defer func() {
		_ = unix.Close(foreignMaster)
		_ = unix.Close(foreignSlave)
	}()

	spec := f.buildLaunch(
		t,
		binary,
		[]string{"-test.run=^TestPaneExecChild$", "--", "paneexec", "composed-pty", foreignPath},
		nil,
		func(b ports.LiveReadOnlyBoundary) (ports.LiveReadOnlyBoundary, error) {
			return ports.NewLiveReadOnlyBoundaryWithOwnedPTY(b)
		},
	)
	out, err, _ := runSpecOnSyntheticPTY(t, spec.Argv(), []string{"HC_TERMINAL_ID=pane-composed-1"}, nil)
	if err != nil || !bytes.Contains(out, []byte("COMPOSED_OWN_SLAVE_OK")) || !bytes.Contains(out, []byte("PANE_COMPOSED_OK")) {
		t.Fatalf("composed PaneTTY+OwnedPTY failed: err=%v output=%q", err, string(out))
	}
}

func TestPaneExecTrampolineRejectsInvalidDescriptorsAndTerminalID(t *testing.T) {
	f := newPaneTestFixture(t)
	marker := filepath.Join(f.writable, "descriptor-test-ran")
	target := filepath.Join(f.base, "marker-target")
	writeMarkerExecutable(t, target, marker)
	spec := f.buildLaunch(t, target, nil, nil, nil)

	// Positive control: valid synthetic controlling PTY executes target and writes marker.
	if out, err, _ := runSpecOnSyntheticPTY(t, spec.Argv(), []string{"HC_TERMINAL_ID=pane-control"}, nil); err != nil {
		t.Fatalf("positive control failed: err=%v output=%q", err, string(out))
	}
	if data, err := os.ReadFile(marker); err != nil || string(data) != "RAN" {
		t.Fatalf("positive control did not execute target: data=%q err=%v", data, err)
	}
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}

	t.Run("rejects pipe on stderr (fd 2)", func(t *testing.T) {
		masterFD, slaveFD, slavePath := openBlockingSyntheticPTY(t)
		defer func() { _ = unix.Close(masterFD) }()
		slaveFile := os.NewFile(uintptr(slaveFD), slavePath)
		defer slaveFile.Close()
		var stderr bytes.Buffer
		cmd := &exec.Cmd{
			Path:        spec.Executable(),
			Args:        spec.Argv(),
			Env:         []string{"HC_TERMINAL_ID=pane-1"},
			Stdin:       slaveFile,
			Stdout:      slaveFile,
			Stderr:      &stderr, // pipe, NOT slave!
			SysProcAttr: &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0},
		}
		assertTrampolineRejectedExit125(t, cmd.Run(), "pipe on stderr")
		assertMarkerAbsent(t, marker, "pipe on stderr")
	})

	t.Run("rejects pipe on stdout (fd 1)", func(t *testing.T) {
		masterFD, slaveFD, slavePath := openBlockingSyntheticPTY(t)
		defer func() { _ = unix.Close(masterFD) }()
		slaveFile := os.NewFile(uintptr(slaveFD), slavePath)
		defer slaveFile.Close()
		var stdout bytes.Buffer
		cmd := &exec.Cmd{
			Path:        spec.Executable(),
			Args:        spec.Argv(),
			Env:         []string{"HC_TERMINAL_ID=pane-1"},
			Stdin:       slaveFile,
			Stdout:      &stdout, // pipe, NOT slave!
			Stderr:      slaveFile,
			SysProcAttr: &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0},
		}
		assertTrampolineRejectedExit125(t, cmd.Run(), "pipe on stdout")
		assertMarkerAbsent(t, marker, "pipe on stdout")
	})

	t.Run("rejects unix socket on stderr (fd 2)", func(t *testing.T) {
		masterFD, slaveFD, slavePath := openBlockingSyntheticPTY(t)
		defer func() { _ = unix.Close(masterFD) }()
		slaveFile := os.NewFile(uintptr(slaveFD), slavePath)
		defer slaveFile.Close()
		fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
		if err != nil {
			t.Fatal(err)
		}
		sockA := os.NewFile(uintptr(fds[0]), "sockA")
		sockB := os.NewFile(uintptr(fds[1]), "sockB")
		defer sockA.Close()
		defer sockB.Close()
		cmd := &exec.Cmd{
			Path:        spec.Executable(),
			Args:        spec.Argv(),
			Env:         []string{"HC_TERMINAL_ID=pane-1"},
			Stdin:       slaveFile,
			Stdout:      slaveFile,
			Stderr:      sockA, // socket, NOT slave!
			SysProcAttr: &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0},
		}
		assertTrampolineRejectedExit125(t, cmd.Run(), "unix socket on stderr")
		assertMarkerAbsent(t, marker, "unix socket on stderr")
	})

	t.Run("rejects regular file on stdin (fd 0)", func(t *testing.T) {
		masterFD, slaveFD, slavePath := openBlockingSyntheticPTY(t)
		defer func() { _ = unix.Close(masterFD) }()
		slaveFile := os.NewFile(uintptr(slaveFD), slavePath)
		defer slaveFile.Close()
		regPath := filepath.Join(f.base, "stdin.txt")
		if err := os.WriteFile(regPath, []byte("hi"), 0o600); err != nil {
			t.Fatal(err)
		}
		regFile, err := os.Open(regPath)
		if err != nil {
			t.Fatal(err)
		}
		defer regFile.Close()
		cmd := &exec.Cmd{
			Path:        spec.Executable(),
			Args:        spec.Argv(),
			Env:         []string{"HC_TERMINAL_ID=pane-1"},
			Stdin:       regFile,
			Stdout:      slaveFile,
			Stderr:      slaveFile,
			SysProcAttr: &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 1},
		}
		assertTrampolineRejectedExit125(t, cmd.Run(), "regular file on stdin")
		assertMarkerAbsent(t, marker, "regular file on stdin")
	})

	t.Run("rejects mismatched controlling tty vs standard descriptors", func(t *testing.T) {
		masterA, slaveA, pathA := openBlockingSyntheticPTY(t)
		defer func() { _ = unix.Close(masterA) }()
		fileA := os.NewFile(uintptr(slaveA), pathA)
		defer fileA.Close()

		masterB, slaveB, pathB := openBlockingSyntheticPTY(t)
		defer func() { _ = unix.Close(masterB) }()
		fileB := os.NewFile(uintptr(slaveB), pathB)
		defer fileB.Close()

		cmd := &exec.Cmd{
			Path:        spec.Executable(),
			Args:        spec.Argv(),
			Env:         []string{"HC_TERMINAL_ID=pane-1"},
			Stdin:       fileB,
			Stdout:      fileB,
			Stderr:      fileB,
			ExtraFiles:  []*os.File{fileA}, // fd 3 is slave A; Ctty=3 sets controlling tty to A while fds 0,1,2 are B!
			SysProcAttr: &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 3},
		}
		assertTrampolineRejectedExit125(t, cmd.Run(), "mismatched controlling tty")
		assertMarkerAbsent(t, marker, "mismatched controlling tty")
	})

	t.Run("rejects non-session-leader without controlling tty", func(t *testing.T) {
		masterFD, slaveFD, slavePath := openBlockingSyntheticPTY(t)
		defer func() { _ = unix.Close(masterFD) }()
		slaveFile := os.NewFile(uintptr(slaveFD), slavePath)
		defer slaveFile.Close()
		cmd := &exec.Cmd{
			Path:   spec.Executable(),
			Args:   spec.Argv(),
			Env:    []string{"HC_TERMINAL_ID=pane-1"},
			Stdin:  slaveFile,
			Stdout: slaveFile,
			Stderr: slaveFile,
			// No Setsid/Setctty: process actually enters __mulgae_paneexec_v1 and fails Getsid != Getpid.
		}
		assertTrampolineRejectedExit125(t, cmd.Run(), "non-session-leader")
		assertMarkerAbsent(t, marker, "non-session-leader")
	})

	for _, badID := range []string{"", "bad space", "bad/slash", "bad;semi", "-leading", strings.Repeat("a", 129)} {
		t.Run("rejects invalid HC_TERMINAL_ID="+badID, func(t *testing.T) {
			_, err, _ := runSpecOnSyntheticPTY(t, spec.Argv(), []string{"HC_TERMINAL_ID=" + badID}, nil)
			assertTrampolineRejectedExit125(t, err, "invalid HC_TERMINAL_ID="+badID)
			assertMarkerAbsent(t, marker, "invalid HC_TERMINAL_ID="+badID)
		})
	}

	t.Run("builder rejects forbidden env variables and unsafe control directory", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			env  ports.EnvironmentVariable
		}{
			{"DYLD", mustEnvironment(t, "DYLD_INSERT_LIBRARIES", "/tmp/evil")},
			{"LD", mustEnvironment(t, "LD_PRELOAD", "/tmp/evil")},
			{"GODEBUG", mustEnvironment(t, "GODEBUG", "gctrace=1")},
			{"HC_SOCKET", mustEnvironment(t, "HC_SOCKET", "/tmp/s.sock")},
			{"HC_TERMINAL_SOCKET", mustEnvironment(t, "HC_TERMINAL_SOCKET", "/tmp/s.sock")},
			{"out-of-namespace XDG", mustEnvironment(t, "XDG_STATE_HOME", f.base)},
		} {
			t.Run(tc.name, func(t *testing.T) {
				fx := newPaneTestFixture(t)
				packet, _ := ports.NewProviderPacketFromBytes([]byte("p"))
				binding, _ := ports.NewTerminalProviderPacketBinding(packet)
				req, err := ports.NewProviderTerminalProcessRequest("/usr/bin/true", []string{"/usr/bin/true"}, []ports.EnvironmentVariable{tc.env}, fx.neutral, binding, time.Minute)
				if err != nil {
					t.Fatal(err)
				}
				b, _ := ports.NewLiveReadOnlyBoundary([]ports.AnchoredRoot{mustRoot(t, fx.source), mustRoot(t, fx.neutral)}, []ports.AnchoredRoot{mustRoot(t, fx.credentials[0])}, mustRoot(t, fx.writable))
				b, _ = ports.NewLiveReadOnlyBoundaryWithControlPlane(b, []ports.AnchoredRoot{mustRoot(t, fx.controlPlaneDir)}, nil)
				b, _ = ports.NewLiveReadOnlyBoundaryWithPaneTTY(b, mustRoot(t, fx.nativeHome))
				req, _ = ports.NewLiveReadOnlyProcessRequest(req, b)
				launchReq, err := ports.NewPaneLaunchRequest(req, mustRoot(t, fx.paneControlDir))
				if err != nil {
					t.Fatal(err)
				}
				if _, err := NewPaneLaunchBuilder().BuildPaneLaunch(context.Background(), launchReq); err == nil {
					t.Fatalf("BuildPaneLaunch accepted forbidden env %s", tc.name)
				}
			})
		}

		// Non-0700 control directory must be rejected.
		fx := newPaneTestFixture(t)
		if err := os.Chmod(fx.paneControlDir, 0o755); err != nil {
			t.Fatal(err)
		}
		packet, _ := ports.NewProviderPacketFromBytes([]byte("p"))
		binding, _ := ports.NewTerminalProviderPacketBinding(packet)
		req, _ := ports.NewProviderTerminalProcessRequest("/usr/bin/true", []string{"/usr/bin/true"}, nil, fx.neutral, binding, time.Minute)
		b, _ := ports.NewLiveReadOnlyBoundary([]ports.AnchoredRoot{mustRoot(t, fx.source), mustRoot(t, fx.neutral)}, []ports.AnchoredRoot{mustRoot(t, fx.credentials[0])}, mustRoot(t, fx.writable))
		b, _ = ports.NewLiveReadOnlyBoundaryWithControlPlane(b, []ports.AnchoredRoot{mustRoot(t, fx.controlPlaneDir)}, nil)
		b, _ = ports.NewLiveReadOnlyBoundaryWithPaneTTY(b, mustRoot(t, fx.nativeHome))
		req, _ = ports.NewLiveReadOnlyProcessRequest(req, b)
		launchReq, _ := ports.NewPaneLaunchRequest(req, mustRoot(t, fx.paneControlDir))
		if _, err := NewPaneLaunchBuilder().BuildPaneLaunch(context.Background(), launchReq); err == nil {
			t.Fatal("BuildPaneLaunch accepted world-readable 0755 control directory")
		}
	})
}

func TestPaneExecTrampolineIntegrityBindingRejections(t *testing.T) {
	newMarkedTarget := func(t *testing.T, f paneTestFixture) (string, string) {
		t.Helper()
		marker := filepath.Join(f.writable, "target-ran-marker")
		bin := filepath.Join(f.base, "marked-provider")
		writeMarkerExecutable(t, bin, marker)
		return bin, marker
	}

	t.Run("positive control executes unmodified target", func(t *testing.T) {
		f := newPaneTestFixture(t)
		bin, marker := newMarkedTarget(t, f)
		spec := f.buildLaunch(t, bin, nil, nil, nil)
		out, err, _ := runSpecOnSyntheticPTY(t, spec.Argv(), []string{"HC_TERMINAL_ID=p1"}, nil)
		if err != nil {
			t.Fatalf("positive control failed: err=%v output=%q", err, string(out))
		}
		data, readErr := os.ReadFile(marker)
		if readErr != nil || string(data) != "RAN" {
			t.Fatalf("positive control did not execute marked target: data=%q err=%v", data, readErr)
		}
	})

	t.Run("tampered env sha256", func(t *testing.T) {
		f := newPaneTestFixture(t)
		bin, marker := newMarkedTarget(t, f)
		spec := f.buildLaunch(t, bin, nil, nil, nil)
		argv := spec.Argv()
		argv[5] = strings.Repeat("0", 64) // env sha256 mismatch
		_, err, _ := runSpecOnSyntheticPTY(t, argv, []string{"HC_TERMINAL_ID=p1"}, nil)
		assertTrampolineRejectedExit125(t, err, "tampered env sha256")
		assertMarkerAbsent(t, marker, "tampered env sha256")
	})

	t.Run("tampered profile sha256", func(t *testing.T) {
		f := newPaneTestFixture(t)
		bin, marker := newMarkedTarget(t, f)
		spec := f.buildLaunch(t, bin, nil, nil, nil)
		argv := spec.Argv()
		argv[9] = strings.Repeat("f", 64) // profile sha256 mismatch
		_, err, _ := runSpecOnSyntheticPTY(t, argv, []string{"HC_TERMINAL_ID=p1"}, nil)
		assertTrampolineRejectedExit125(t, err, "tampered profile sha256")
		assertMarkerAbsent(t, marker, "tampered profile sha256")
	})

	t.Run("env file wrong mode 0444", func(t *testing.T) {
		f := newPaneTestFixture(t)
		bin, marker := newMarkedTarget(t, f)
		spec := f.buildLaunch(t, bin, nil, nil, nil)
		if err := os.Chmod(spec.EnvFilePath(), 0o444); err != nil {
			t.Fatal(err)
		}
		_, err, _ := runSpecOnSyntheticPTY(t, spec.Argv(), []string{"HC_TERMINAL_ID=p1"}, nil)
		assertTrampolineRejectedExit125(t, err, "env file mode 0444")
		assertMarkerAbsent(t, marker, "env file mode 0444")
	})

	t.Run("env file hardlinked nlink 2", func(t *testing.T) {
		f := newPaneTestFixture(t)
		bin, marker := newMarkedTarget(t, f)
		spec := f.buildLaunch(t, bin, nil, nil, nil)
		if err := os.Link(spec.EnvFilePath(), filepath.Join(f.paneControlDir, "env-alias")); err != nil {
			t.Fatal(err)
		}
		_, err, _ := runSpecOnSyntheticPTY(t, spec.Argv(), []string{"HC_TERMINAL_ID=p1"}, nil)
		assertTrampolineRejectedExit125(t, err, "hardlinked env file")
		assertMarkerAbsent(t, marker, "hardlinked env file")
	})

	t.Run("replaced env file inode with identical bytes", func(t *testing.T) {
		f := newPaneTestFixture(t)
		bin, marker := newMarkedTarget(t, f)
		spec := f.buildLaunch(t, bin, nil, nil, nil)
		origBytes, err := os.ReadFile(spec.EnvFilePath())
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(spec.EnvFilePath()); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(spec.EnvFilePath(), origBytes, 0o400); err != nil {
			t.Fatal(err)
		}
		_, err, _ = runSpecOnSyntheticPTY(t, spec.Argv(), []string{"HC_TERMINAL_ID=p1"}, nil)
		assertTrampolineRejectedExit125(t, err, "replaced env inode")
		assertMarkerAbsent(t, marker, "replaced env inode")
	})

	t.Run("profile file wrong mode 0600", func(t *testing.T) {
		f := newPaneTestFixture(t)
		bin, marker := newMarkedTarget(t, f)
		spec := f.buildLaunch(t, bin, nil, nil, nil)
		if err := os.Chmod(spec.ProfileFilePath(), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err, _ := runSpecOnSyntheticPTY(t, spec.Argv(), []string{"HC_TERMINAL_ID=p1"}, nil)
		assertTrampolineRejectedExit125(t, err, "profile mode 0600")
		assertMarkerAbsent(t, marker, "profile mode 0600")
	})

	t.Run("control directory widened to 0755 before exec", func(t *testing.T) {
		f := newPaneTestFixture(t)
		bin, marker := newMarkedTarget(t, f)
		spec := f.buildLaunch(t, bin, nil, nil, nil)
		if err := os.Chmod(f.paneControlDir, 0o755); err != nil {
			t.Fatal(err)
		}
		_, err, _ := runSpecOnSyntheticPTY(t, spec.Argv(), []string{"HC_TERMINAL_ID=p1"}, nil)
		assertTrampolineRejectedExit125(t, err, "control dir 0755 at exec")
		assertMarkerAbsent(t, marker, "control dir 0755 at exec")
	})

	t.Run("control ancestor directory widened to 0777 before exec", func(t *testing.T) {
		f := newPaneTestFixture(t)
		bin, marker := newMarkedTarget(t, f)
		spec := f.buildLaunch(t, bin, nil, nil, nil)
		if err := os.Chmod(f.controlPlaneDir, 0o777); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(f.controlPlaneDir, 0o700) })
		_, err, _ := runSpecOnSyntheticPTY(t, spec.Argv(), []string{"HC_TERMINAL_ID=p1"}, nil)
		assertTrampolineRejectedExit125(t, err, "control ancestor 0777 at exec")
		assertMarkerAbsent(t, marker, "control ancestor 0777 at exec")
	})

	t.Run("replaced neutral cwd inode/btime", func(t *testing.T) {
		f := newPaneTestFixture(t)
		bin, marker := newMarkedTarget(t, f)
		spec := f.buildLaunch(t, bin, nil, nil, nil)
		if err := os.Rename(f.neutral, f.neutral+"-old"); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(f.neutral, 0o700); err != nil {
			t.Fatal(err)
		}
		_, err, _ := runSpecOnSyntheticPTY(t, spec.Argv(), []string{"HC_TERMINAL_ID=p1"}, nil)
		assertTrampolineRejectedExit125(t, err, "replaced neutral cwd")
		assertMarkerAbsent(t, marker, "replaced neutral cwd")
	})

	t.Run("symlinked env file rejected", func(t *testing.T) {
		f := newPaneTestFixture(t)
		bin, marker := newMarkedTarget(t, f)
		spec := f.buildLaunch(t, bin, nil, nil, nil)
		realCopy := filepath.Join(f.paneControlDir, "real-env.json")
		if err := os.Rename(spec.EnvFilePath(), realCopy); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(realCopy, spec.EnvFilePath()); err != nil {
			t.Fatal(err)
		}
		_, err, _ := runSpecOnSyntheticPTY(t, spec.Argv(), []string{"HC_TERMINAL_ID=p1"}, nil)
		assertTrampolineRejectedExit125(t, err, "symlinked env file")
		assertMarkerAbsent(t, marker, "symlinked env file")
	})

	t.Run("replaced provider executable inode", func(t *testing.T) {
		f := newPaneTestFixture(t)
		bin, marker := newMarkedTarget(t, f)
		spec := f.buildLaunch(t, bin, nil, nil, nil)
		if err := os.Remove(bin); err != nil {
			t.Fatal(err)
		}
		writeMarkerExecutable(t, bin, marker)
		_, err, _ := runSpecOnSyntheticPTY(t, spec.Argv(), []string{"HC_TERMINAL_ID=p1"}, nil)
		assertTrampolineRejectedExit125(t, err, "replaced provider executable inode")
		assertMarkerAbsent(t, marker, "replaced provider executable inode")
	})

	t.Run("trampoline independently rejects tampered env payload with forbidden vars", func(t *testing.T) {
		f := newPaneTestFixture(t)
		bin, marker := newMarkedTarget(t, f)
		spec := f.buildLaunch(t, bin, nil, nil, nil)
		badPayload := fmt.Sprintf(`{"version":1,"writable_root":%q,"entries":[{"name":"HC_SOCKET","value":"/tmp/s.sock"}]}`, f.writable)
		badPath := filepath.Join(f.paneControlDir, "bad-env.json")
		if err := os.WriteFile(badPath, []byte(badPayload), 0o400); err != nil {
			t.Fatal(err)
		}
		var st unix.Stat_t
		if err := unix.Lstat(badPath, &st); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256([]byte(badPayload))
		argv := spec.Argv()
		argv[2] = badPath
		argv[3] = strconv.FormatUint(uint64(st.Dev), 10)
		argv[4] = strconv.FormatUint(st.Ino, 10)
		argv[5] = hex.EncodeToString(sum[:])
		_, err, _ := runSpecOnSyntheticPTY(t, argv, []string{"HC_TERMINAL_ID=p1"}, nil)
		assertTrampolineRejectedExit125(t, err, "tampered env payload with HC_SOCKET")
		assertMarkerAbsent(t, marker, "tampered env payload with HC_SOCKET")
	})
}

func TestPaneExecSeatbeltControlPlaneSecretRootsAndCursorCredentials(t *testing.T) {
	f := newPaneTestFixture(t)
	binary := canonicalTestExecutable(t)

	// Populate Cursor credentials, secret roots (dirs + regular files + symlinked dotfiles/dirs),
	// ancestor literals, and a multiply-linked file inside ControlPlaneRoots (proving
	// ControlPlaneRoots is excluded from validateLiveRootFileLinks!).
	cpHardlinkOrig := filepath.Join(f.controlPlaneDir, "live-state")
	if err := os.WriteFile(cpHardlinkOrig, []byte("cp-state"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(cpHardlinkOrig, filepath.Join(f.controlPlaneDir, "live-state-alias")); err != nil {
		t.Fatal(err)
	}

	// Control-plane Unix socket inside ControlPlaneRoots + symlink alias inside WritableRoot.
	cpSockPath := filepath.Join(f.controlPlaneDir, "s.sock")
	cpListener, err := net.Listen("unix", cpSockPath)
	if err != nil {
		t.Fatal(err)
	}
	defer cpListener.Close()
	cpSockAlias := filepath.Join(f.writable, "cp-alias.sock")
	if err := os.Symlink(cpSockPath, cpSockAlias); err != nil {
		t.Fatal(err)
	}

	// Inherited ControlPlaneLiteral socket sitting in a shared directory (not subpath-denied!).
	litSockPath := filepath.Join(f.base, "inherited-hc.sock")
	litListener, err := net.Listen("unix", litSockPath)
	if err != nil {
		t.Fatal(err)
	}
	defer litListener.Close()

	// Symlinked dotfiles directory to test symlinked secret dotfile, ancestor literal,
	// symlinked secret directory, AND missing leaf under a symlinked ancestor created post-compile!
	dotfilesDir := filepath.Join(f.base, "dotfiles")
	dotfilesGH := filepath.Join(dotfilesDir, "gh")
	dotfilesSub := filepath.Join(dotfilesDir, "post-cp-real")
	for _, dir := range []string{dotfilesGH, dotfilesSub} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	dotfilesNPMRC := filepath.Join(dotfilesDir, "npmrc")
	dotfilesAgents := filepath.Join(dotfilesDir, "AGENTS.md")
	dotfilesGHHosts := filepath.Join(dotfilesGH, "hosts.yml")
	for _, p := range []string{dotfilesNPMRC, dotfilesAgents, dotfilesGHHosts} {
		if err := os.WriteFile(p, []byte("SYMLINKED_SECRET\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// Symlink ~/.npmrc -> dotfiles/npmrc, ~/AGENTS.md -> dotfiles/AGENTS.md, ~/.config/gh -> dotfiles/gh.
	if err := os.MkdirAll(filepath.Join(f.nativeHome, ".config"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(dotfilesNPMRC, filepath.Join(f.nativeHome, ".npmrc")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(dotfilesAgents, filepath.Join(f.nativeHome, "AGENTS.md")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(dotfilesGH, filepath.Join(f.nativeHome, ".config", "gh")); err != nil {
		t.Fatal(err)
	}

	// Symlinked ancestor whose child leaf does NOT exist yet at profile compile time:
	// postCPSymlink -> dotfiles/post-cp-real; we register postCPSymlink/future-cp in ControlPlaneRoots,
	// then create post-cp-real/future-cp/secret.txt AFTER BuildPaneLaunch!
	postCPSymlink := filepath.Join(f.base, "post-cp-link")
	if err := os.Symlink(dotfilesSub, postCPSymlink); err != nil {
		t.Fatal(err)
	}
	postCPMissingLeaf := filepath.Join(postCPSymlink, "future-cp")
	postCPCreatedViaLink := filepath.Join(postCPMissingLeaf, "secret.txt")
	postCPCreatedViaReal := filepath.Join(dotfilesSub, "future-cp", "secret.txt")

	// Create remaining secret files & dirs under fake nativeHome + Cursor dirs.
	secretDirFiles := []string{
		filepath.Join(f.nativeHome, ".ssh", "id_ed25519"),
		filepath.Join(f.nativeHome, ".gnupg", "secring.gpg"),
		filepath.Join(f.nativeHome, ".aws", "credentials"),
		filepath.Join(f.nativeHome, ".docker", "config.json"),
		filepath.Join(f.nativeHome, ".kube", "config"),
		filepath.Join(f.nativeHome, "Library", "Keychains", "login.keychain-db"),
		filepath.Join(f.nativeHome, ".claude", "settings.json"),
		filepath.Join(f.nativeHome, ".config", "herdr", "config.toml"),
		filepath.Join(f.nativeHome, ".local", "state", "herdr-core", "state.json"),
		filepath.Join(f.nativeHome, ".cursor", "cli-config.json"),
		filepath.Join(f.nativeHome, ".config", "cursor", "auth.json"),
	}
	secretRegularFiles := []string{
		filepath.Join(f.nativeHome, ".netrc"),
		filepath.Join(f.nativeHome, ".git-credentials"),
		filepath.Join(f.nativeHome, ".pypirc"),
		filepath.Join(f.nativeHome, "CLAUDE.md"),
		filepath.Join(f.nativeHome, ".mcp.json"),
	}
	for _, p := range append(append([]string(nil), secretDirFiles...), secretRegularFiles...) {
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("SECRET_DATA\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	deniedFiles := append(append([]string(nil), secretDirFiles...), secretRegularFiles...)
	deniedFiles = append(deniedFiles,
		filepath.Join(f.nativeHome, ".npmrc"),
		dotfilesNPMRC,
		filepath.Join(f.nativeHome, "AGENTS.md"),
		dotfilesAgents,
		filepath.Join(f.nativeHome, ".config", "gh", "hosts.yml"),
		dotfilesGHHosts,
		postCPCreatedViaLink,
		postCPCreatedViaReal,
		filepath.Join(f.paneControlDir, paneExecEnvFileName),
		filepath.Join(f.paneControlDir, paneExecProfileFileName),
	)
	deniedSockets := []string{cpSockPath, cpSockAlias, litSockPath}

	spec := f.buildLaunch(
		t,
		binary,
		[]string{"-test.run=^TestPaneExecChild$", "--", "paneexec", "deny-files-and-sockets", strings.Join(deniedFiles, ","), strings.Join(deniedSockets, ",")},
		nil,
		func(b ports.LiveReadOnlyBoundary) (ports.LiveReadOnlyBoundary, error) {
			return ports.NewLiveReadOnlyBoundaryWithControlPlane(
				b,
				[]ports.AnchoredRoot{mustRoot(t, postCPMissingLeaf)},
				[]ports.AnchoredRoot{mustRoot(t, litSockPath)},
			)
		},
	)

	// Create the missing leaf under the symlinked ancestor AFTER profile compilation.
	if err := os.MkdirAll(filepath.Dir(postCPCreatedViaReal), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(postCPCreatedViaReal, []byte("POST_COMPILE_SECRET\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	out, runErr, _ := runSpecOnSyntheticPTY(t, spec.Argv(), []string{"HC_TERMINAL_ID=pane-sec-1"}, nil)
	if runErr != nil || !bytes.Contains(out, []byte("PANE_DENIES_OK")) {
		t.Fatalf("control-plane/secret-root/cursor denial test failed: err=%v output=%q", runErr, string(out))
	}
}

func TestPaneExecSeatbeltComponentSymlinkResolutionPostCompile(t *testing.T) {
	f := newPaneTestFixture(t)
	// CredentialRoots enforces O_NOFOLLOW on every existing ancestor; omit
	// ~/.config/cursor here so ~/.config can be a symlink exercising
	// TerminalSecretRoots missing-tolerant component-by-component resolution.
	f.credentials = f.credentials[:len(f.credentials)-1]
	binary := canonicalTestExecutable(t)

	dotfilesDir := filepath.Join(f.base, "dotfiles")
	xdgConfig := filepath.Join(dotfilesDir, "xdg-config")
	deepNested := filepath.Join(dotfilesDir, "deep", "nested")
	for _, dir := range []string{xdgConfig, deepNested} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}

	// 1. Dangling relative symlink inside a symlinked parent directory:
	//    ~/.config -> dotfiles/xdg-config
	//    ~/.config/gh -> ../secrets/gh  (dotfiles/secrets/gh does NOT exist yet!)
	// Lexical filepath.Join(filepath.Dir("~/.config/gh"), "../secrets/gh") would
	// erroneously resolve to ~/secrets/gh instead of dotfiles/secrets/gh.
	if err := os.Symlink(xdgConfig, filepath.Join(f.nativeHome, ".config")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../secrets/gh", filepath.Join(xdgConfig, "gh")); err != nil {
		t.Fatal(err)
	}

	// 2. Target containing <existing_symlink>/../<missing>:
	//    existing-sub-link -> dotfiles/deep/nested
	//    cp-dotdot-link -> existing-sub-link/../future-from-link
	// Lexical filepath.Clean would erroneously collapse existing-sub-link/.. to f.base/future-from-link
	// instead of dotfiles/deep/future-from-link.
	existingSubLink := filepath.Join(f.base, "existing-sub-link")
	if err := os.Symlink(deepNested, existingSubLink); err != nil {
		t.Fatal(err)
	}
	cpDotDotLink := filepath.Join(f.base, "cp-dotdot-link")
	if err := os.Symlink("existing-sub-link/../future-from-link", cpDotDotLink); err != nil {
		t.Fatal(err)
	}

	ghTokenViaHome := filepath.Join(f.nativeHome, ".config", "gh", "token.txt")
	ghTokenViaReal := filepath.Join(dotfilesDir, "secrets", "gh", "token.txt")
	cpSecretViaLink := filepath.Join(cpDotDotLink, "secret.txt")
	cpSecretViaReal := filepath.Join(dotfilesDir, "deep", "future-from-link", "secret.txt")

	deniedFiles := []string{
		ghTokenViaHome,
		ghTokenViaReal,
		cpSecretViaLink,
		cpSecretViaReal,
	}

	spec := f.buildLaunch(
		t,
		binary,
		[]string{"-test.run=^TestPaneExecChild$", "--", "paneexec", "deny-files-and-sockets", strings.Join(deniedFiles, ","), ""},
		nil,
		func(b ports.LiveReadOnlyBoundary) (ports.LiveReadOnlyBoundary, error) {
			return ports.NewLiveReadOnlyBoundaryWithControlPlane(
				b,
				[]ports.AnchoredRoot{mustRoot(t, cpDotDotLink)},
				nil,
			)
		},
	)

	// Materialize BOTH canonical targets POST-compile.
	for _, targetFile := range []string{ghTokenViaReal, cpSecretViaReal} {
		if err := os.MkdirAll(filepath.Dir(targetFile), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(targetFile, []byte("POST_COMPILE_COMPONENT_SECRET\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	out, runErr, _ := runSpecOnSyntheticPTY(t, spec.Argv(), []string{"HC_TERMINAL_ID=pane-symlink-comp-1"}, nil)
	if runErr != nil || !bytes.Contains(out, []byte("PANE_DENIES_OK")) {
		t.Fatalf("component-by-component symlink denial test failed: err=%v output=%q", runErr, string(out))
	}
}

func TestPaneExecSeatbeltMissingTolerantSymlinkFailsClosedOnUnsafeTargets(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, nativeHome string)
	}{
		{
			name: "symlink to filesystem root",
			setup: func(t *testing.T, nativeHome string) {
				if err := os.Symlink("/", filepath.Join(nativeHome, ".netrc")); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "symlink to unprintable control char path",
			setup: func(t *testing.T, nativeHome string) {
				if err := os.Symlink("/private/tmp/bad\apath", filepath.Join(nativeHome, ".netrc")); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "symlink loop exceeds hop bound",
			setup: func(t *testing.T, nativeHome string) {
				if err := os.Symlink("loop-b", filepath.Join(nativeHome, ".netrc")); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(".netrc", filepath.Join(nativeHome, "loop-b")); err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newPaneTestFixture(t)
			tc.setup(t, f.nativeHome)
			packet, _ := ports.NewProviderPacketFromBytes([]byte("p"))
			binding, _ := ports.NewTerminalProviderPacketBinding(packet)
			req, _ := ports.NewProviderTerminalProcessRequest("/usr/bin/true", []string{"/usr/bin/true"}, nil, f.neutral, binding, time.Minute)
			b, _ := ports.NewLiveReadOnlyBoundary(
				[]ports.AnchoredRoot{mustRoot(t, f.source), mustRoot(t, f.neutral)},
				[]ports.AnchoredRoot{mustRoot(t, f.credentials[0])},
				mustRoot(t, f.writable),
			)
			b, _ = ports.NewLiveReadOnlyBoundaryWithControlPlane(b, []ports.AnchoredRoot{mustRoot(t, f.controlPlaneDir)}, nil)
			b, _ = ports.NewLiveReadOnlyBoundaryWithPaneTTY(b, mustRoot(t, f.nativeHome))
			req, _ = ports.NewLiveReadOnlyProcessRequest(req, b)
			launchReq, err := ports.NewPaneLaunchRequest(req, mustRoot(t, f.paneControlDir))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := NewPaneLaunchBuilder().BuildPaneLaunch(context.Background(), launchReq); err == nil {
				t.Fatalf("BuildPaneLaunch accepted unsafe symlink case %q instead of failing closed", tc.name)
			}
		})
	}

	t.Run("EACCES on unreadable parent directory fails closed", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root bypasses 0000 directory permissions")
		}
		f := newPaneTestFixture(t)
		lockedParent := filepath.Join(f.base, "locked-parent")
		if err := os.Mkdir(lockedParent, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(lockedParent, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(lockedParent, 0o700) })

		unreadableChild := filepath.Join(lockedParent, "child")
		if _, err := expandMissingTolerantPolicyPaths(unreadableChild); err == nil {
			t.Fatalf("expandMissingTolerantPolicyPaths(%q) succeeded on 0000 parent", unreadableChild)
		}
		packet, _ := ports.NewProviderPacketFromBytes([]byte("p"))
		binding, _ := ports.NewTerminalProviderPacketBinding(packet)
		req, _ := ports.NewProviderTerminalProcessRequest("/usr/bin/true", []string{"/usr/bin/true"}, nil, f.neutral, binding, time.Minute)
		b, _ := ports.NewLiveReadOnlyBoundary(
			[]ports.AnchoredRoot{mustRoot(t, f.source), mustRoot(t, f.neutral)},
			[]ports.AnchoredRoot{mustRoot(t, f.credentials[0])},
			mustRoot(t, f.writable),
		)
		b, _ = ports.NewLiveReadOnlyBoundaryWithControlPlane(b, []ports.AnchoredRoot{mustRoot(t, f.controlPlaneDir), mustRoot(t, unreadableChild)}, nil)
		b, _ = ports.NewLiveReadOnlyBoundaryWithPaneTTY(b, mustRoot(t, f.nativeHome))
		req, _ = ports.NewLiveReadOnlyProcessRequest(req, b)
		launchReq, err := ports.NewPaneLaunchRequest(req, mustRoot(t, f.paneControlDir))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := NewPaneLaunchBuilder().BuildPaneLaunch(context.Background(), launchReq); err == nil {
			t.Fatalf("BuildPaneLaunch accepted unreadable 0000 control-plane parent %q", unreadableChild)
		}
	})

	t.Run("ENOTDIR when regular file occupies ancestor of missing-tolerant path is tolerated", func(t *testing.T) {
		f := newPaneTestFixture(t)
		regAncestor := filepath.Join(f.base, "regular-ancestor")
		if err := os.WriteFile(regAncestor, []byte("not-a-dir"), 0o600); err != nil {
			t.Fatal(err)
		}
		underReg := filepath.Join(regAncestor, "child", "leaf")
		got, err := expandMissingTolerantPolicyPaths(underReg)
		if err != nil {
			t.Fatalf("expandMissingTolerantPolicyPaths(%q) failed on ENOTDIR ancestor: %v", underReg, err)
		}
		if len(got) != 1 || got[0] != underReg {
			t.Fatalf("expandMissingTolerantPolicyPaths(%q) = %v, want [%q]", underReg, got, underReg)
		}
		_ = f.buildLaunch(t, "/usr/bin/true", nil, nil, func(b ports.LiveReadOnlyBoundary) (ports.LiveReadOnlyBoundary, error) {
			return ports.NewLiveReadOnlyBoundaryWithControlPlane(b, []ports.AnchoredRoot{mustRoot(t, underReg)}, nil)
		})
	})

	t.Run("initial path exceeding component bound fails closed", func(t *testing.T) {
		overlong := "/" + strings.Repeat("a/", maxResolvedPathComponents+1) + "leaf"
		if _, err := resolvePathComponentsMissingTolerant(overlong); err == nil {
			t.Fatal("resolvePathComponentsMissingTolerant accepted path exceeding component bound")
		}
		if _, err := expandMissingTolerantPolicyPaths(overlong); err == nil {
			t.Fatal("expandMissingTolerantPolicyPaths accepted path exceeding component bound")
		}
	})
}

func TestPaneExecSeatbeltBashGateControls(t *testing.T) {
	f := newPaneTestFixture(t)
	binary := canonicalTestExecutable(t)

	// Unix socket inside WritableRoot (normally allowed, MUST be denied by B-1 Bash-gate!).
	writableSock := filepath.Join(f.writable, "w.sock")
	unixListener, err := net.Listen("unix", writableSock)
	if err != nil {
		t.Fatal(err)
	}
	defer unixListener.Close()

	// Localhost IPv4 and IPv6 TCP listeners (MUST be denied by B-1 Bash-gate!).
	tcp4, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcp4.Close()
	ipv6Addr := ""
	if tcp6, err6 := net.Listen("tcp6", "[::1]:0"); err6 == nil {
		defer tcp6.Close()
		ipv6Addr = tcp6.Addr().String()
	}

	// Copy-and-exec defense: copied executable in WritableRoot AND repo-hosted executable in ReadOnlyRoots (source) MUST fail EPERM.
	copiedInWritable := filepath.Join(f.writable, "copied-true")
	copyFileExecutable(t, "/usr/bin/true", copiedInWritable)
	repoExecutable := filepath.Join(f.source, "herdr-zcode")
	copyFileExecutable(t, "/usr/bin/true", repoExecutable)

	// Synthetic executables matching B-1 process-exec regex denials.
	fakeBinDir := filepath.Join(f.base, "fakebin")
	if err := os.Mkdir(fakeBinDir, 0o700); err != nil {
		t.Fatal(err)
	}
	companion := filepath.Join(fakeBinDir, "herdr-zcode")
	copyFileExecutable(t, "/usr/bin/true", companion)
	deniedBins := []string{
		"/usr/bin/security",
		"/usr/bin/osascript",
		"/usr/bin/open",
		"/bin/launchctl",
		copiedInWritable,
		repoExecutable,
	}
	for _, name := range []string{"git-credential-osxkeychain", "tmux", "hc", "herdr", "herdr-core", "herdr-app", "herdrd", "ssh", "docker"} {
		p := filepath.Join(fakeBinDir, name)
		if err := os.WriteFile(p, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
			t.Fatal(err)
		}
		deniedBins = append(deniedBins, p)
	}

	spec := f.buildLaunch(
		t,
		binary,
		[]string{"-test.run=^TestPaneExecChild$", "--", "paneexec", "bash-gate", writableSock, tcp4.Addr().String(), ipv6Addr, strings.Join(deniedBins, ","), companion},
		nil,
		func(b ports.LiveReadOnlyBoundary) (ports.LiveReadOnlyBoundary, error) {
			return ports.NewLiveReadOnlyBoundaryWithBashGate(b)
		},
	)
	out, runErr, _ := runSpecOnSyntheticPTY(t, spec.Argv(), []string{"HC_TERMINAL_ID=pane-b1-1"}, nil)
	if runErr != nil || !bytes.Contains(out, []byte("PANE_BASH_GATE_OK")) {
		t.Fatalf("B-1 Bash-gate controls failed: err=%v output=%q", runErr, string(out))
	}
}

func TestPaneExecScanTTYSlaveByRdevFallback(t *testing.T) {
	masterFD, slaveFD, slavePath := openBlockingSyntheticPTY(t)
	defer func() {
		_ = unix.Close(masterFD)
		_ = unix.Close(slaveFD)
	}()
	var st unix.Stat_t
	if err := unix.Fstat(slaveFD, &st); err != nil {
		t.Fatal(err)
	}
	got, err := scanTTYSlaveByRdev(st.Rdev)
	if err != nil {
		t.Fatalf("scanTTYSlaveByRdev() error = %v", err)
	}
	if got != slavePath {
		t.Fatalf("scanTTYSlaveByRdev() = %q, want %q", got, slavePath)
	}
}
