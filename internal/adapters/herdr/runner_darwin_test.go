//go:build darwin && arm64

package herdr

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	processadapter "github.com/irootkernel/mulgae/internal/adapters/process"
	runtimeadapter "github.com/irootkernel/mulgae/internal/adapters/runtime"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
	"golang.org/x/sys/unix"
)

type fakeProcessInspector struct {
	mu           sync.Mutex
	killZeroErr  map[int]error
	pgrpMembers  map[int][]int
	sessMembers  map[int][]int
	killCalls    []int
	pidKillCalls []int
	clearOnKill  bool
	sidByPID     map[int]int
	procInfo     map[int]processInfo
}

func newFakeProcessInspector() *fakeProcessInspector {
	return &fakeProcessInspector{
		killZeroErr: make(map[int]error),
		pgrpMembers: make(map[int][]int),
		sessMembers: make(map[int][]int),
		sidByPID:    make(map[int]int),
		procInfo:    make(map[int]processInfo),
	}
}

func (f *fakeProcessInspector) signalGroupZero(pid int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err, ok := f.killZeroErr[pid]; ok {
		return err
	}
	return unix.ESRCH
}

func (f *fakeProcessInspector) signalGroupKill(pid int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.killCalls = append(f.killCalls, pid)
	if f.clearOnKill {
		f.killZeroErr[pid] = unix.ESRCH
		delete(f.pgrpMembers, pid)
		delete(f.sessMembers, pid)
	}
	return nil
}

func (f *fakeProcessInspector) signalPIDKill(pid int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pidKillCalls = append(f.pidKillCalls, pid)
	return nil
}

func (f *fakeProcessInspector) sessionPIDs(sid int) ([]int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]int(nil), f.sessMembers[sid]...), nil
}

func (f *fakeProcessInspector) pgrpPIDs(pgid int) ([]int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]int(nil), f.pgrpMembers[pgid]...), nil
}

func (f *fakeProcessInspector) getSID(pid int) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if sid, ok := f.sidByPID[pid]; ok {
		return sid, nil
	}
	return pid, nil
}

func (f *fakeProcessInspector) processInfo(pid int) (processInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if info, ok := f.procInfo[pid]; ok {
		return info, nil
	}
	return processInfo{}, nil
}

type fakeHerdrServer struct {
	mu           sync.Mutex
	sockPath     string
	ln           net.Listener
	terminals    map[string]*Terminal
	nextPaneNum  int
	screenByPane map[string]string

	helloGen        uint32
	helloVersion    string
	serverStopCalls int
	sendCalls       []SendParams
	waitCalls       []WaitParams
	killCalls       []string
	rmCalls         []string
	readCalls       []ReadParams
	runCalls        []RunParams

	onStatus func(s *fakeHerdrServer) (StatusResult, *RPCError)
	onRun    func(s *fakeHerdrServer, params RunParams) (Terminal, *RPCError)
	onList   func(s *fakeHerdrServer, params ListParams) (ListResult, *RPCError, bool)
	onGet    func(s *fakeHerdrServer, addr string, conn net.Conn) (Terminal, *RPCError, bool)
	onSend   func(s *fakeHerdrServer, params SendParams) (SendResult, *RPCError)
	onWait   func(s *fakeHerdrServer, params WaitParams, conn net.Conn) (WaitResult, *RPCError, bool)
	onKill   func(s *fakeHerdrServer, addr string) (Terminal, *RPCError)
	onRM     func(s *fakeHerdrServer, addr string) (RemoveResult, *RPCError)
}

func startFakeHerdrServer(t *testing.T) *fakeHerdrServer {
	t.Helper()
	dir, err := os.MkdirTemp("", "mhfakesrv")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sockPath := filepath.Join(dir, "s.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}
	srv := &fakeHerdrServer{
		sockPath:     sockPath,
		ln:           ln,
		terminals:    make(map[string]*Terminal),
		screenByPane: make(map[string]string),
		helloGen:     1,
		helloVersion: "0.1.20",
	}
	t.Cleanup(func() { _ = ln.Close() })
	go srv.serve()
	return srv
}

func (s *fakeHerdrServer) serve() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handleConn(conn)
	}
}

func (s *fakeHerdrServer) handleConn(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	if !scanner.Scan() {
		return
	}
	var raw struct {
		ID     uint64          `json:"id"`
		Method string          `json:"method"`
		Params json.RawMessage `json:"params"`
	}
	if err := json.Unmarshal(scanner.Bytes(), &raw); err != nil {
		return
	}

	switch raw.Method {
	case "hello":
		s.mu.Lock()
		gen, ver := s.helloGen, s.helloVersion
		s.mu.Unlock()
		writeRPCResult(conn, raw.ID, HelloResult{
			Generation: gen,
			Version:    ver,
			Core:       CoreInfo{ID: "fake-core", Name: "test"},
			Methods:    requiredRPCMethods,
		})
	case "server.status":
		s.mu.Lock()
		onStatus := s.onStatus
		liveCount := uint(0)
		finCount := uint(0)
		for _, term := range s.terminals {
			if term.State == "live" {
				liveCount++
			} else {
				finCount++
			}
		}
		s.mu.Unlock()
		if onStatus != nil {
			res, rpcErr := onStatus(s)
			if rpcErr != nil {
				writeRPCError(conn, raw.ID, rpcErr.Code, rpcErr.Message, rpcErr.Kind, rpcErr.Hint)
				return
			}
			writeRPCResult(conn, raw.ID, res)
			return
		}
		writeRPCResult(conn, raw.ID, StatusResult{
			Core:     CoreInfo{ID: "fake-core", Name: "test"},
			Version:  "0.1.20",
			PID:      42424,
			UptimeMS: 100,
			Holder:   &HolderInfo{PID: 42425, Instance: "inst", Current: true, Terminals: liveCount},
			Holders:  []HolderInfo{{PID: 42425, Instance: "inst", Current: true, Terminals: liveCount}},
			Live:     liveCount,
			Finished: finCount,
		})
	case "server.stop":
		s.mu.Lock()
		s.serverStopCalls++
		s.mu.Unlock()
		writeRPCResult(conn, raw.ID, StopResult{Stopped: true})
	case "terminal.run":
		var params RunParams
		_ = json.Unmarshal(raw.Params, &params)
		s.mu.Lock()
		s.runCalls = append(s.runCalls, params)
		onRun := s.onRun
		s.mu.Unlock()
		if onRun != nil {
			res, rpcErr := onRun(s, params)
			if rpcErr != nil {
				writeRPCError(conn, raw.ID, rpcErr.Code, rpcErr.Message, rpcErr.Kind, rpcErr.Hint)
				return
			}
			writeRPCResult(conn, raw.ID, res)
			return
		}
		s.mu.Lock()
		s.nextPaneNum++
		addr := fmt.Sprintf("t%d", s.nextPaneNum)
		pid := uint32(50000 + s.nextPaneNum)
		term := &Terminal{
			Address:  addr,
			Argv:     params.Argv,
			CWD:      params.CWD,
			Labels:   params.Labels,
			State:    "live",
			PID:      &pid,
			Reported: true,
			Status:   &TerminalStatus{State: "idle"},
			Screen:   "exact",
			Cols:     200,
			Rows:     120,
		}
		s.terminals[addr] = term
		res := *term
		s.mu.Unlock()
		writeRPCResult(conn, raw.ID, res)
	case "terminal.get":
		var params TerminalRefParams
		_ = json.Unmarshal(raw.Params, &params)
		s.mu.Lock()
		onGet := s.onGet
		s.mu.Unlock()
		if onGet != nil {
			res, rpcErr, skipWrite := onGet(s, params.Terminal, conn)
			if skipWrite {
				return
			}
			if rpcErr != nil {
				writeRPCError(conn, raw.ID, rpcErr.Code, rpcErr.Message, rpcErr.Kind, rpcErr.Hint)
				return
			}
			writeRPCResult(conn, raw.ID, res)
			return
		}
		s.mu.Lock()
		term, ok := s.terminals[params.Terminal]
		var copied Terminal
		if ok {
			copied = *term
		}
		s.mu.Unlock()
		if !ok {
			writeRPCError(conn, raw.ID, -32000, "not_found", "not_found", "")
			return
		}
		writeRPCResult(conn, raw.ID, copied)
	case "terminal.list":
		var params ListParams
		_ = json.Unmarshal(raw.Params, &params)
		s.mu.Lock()
		onList := s.onList
		s.mu.Unlock()
		if onList != nil {
			res, rpcErr, skipWrite := onList(s, params)
			if skipWrite {
				return
			}
			if rpcErr != nil {
				writeRPCError(conn, raw.ID, rpcErr.Code, rpcErr.Message, rpcErr.Kind, rpcErr.Hint)
				return
			}
			writeRPCResult(conn, raw.ID, res)
			return
		}
		s.mu.Lock()
		out := make([]Terminal, 0, len(s.terminals))
		for _, term := range s.terminals {
			if !params.All && term.State != "live" {
				continue
			}
			matched := true
			for k, v := range params.Labels {
				if term.Labels[k] != v {
					matched = false
					break
				}
			}
			if matched {
				out = append(out, *term)
			}
		}
		s.mu.Unlock()
		writeRPCResult(conn, raw.ID, ListResult{Terminals: out})
	case "terminal.send":
		var params SendParams
		_ = json.Unmarshal(raw.Params, &params)
		s.mu.Lock()
		s.sendCalls = append(s.sendCalls, params)
		onSend := s.onSend
		s.mu.Unlock()
		if onSend != nil {
			res, rpcErr := onSend(s, params)
			if rpcErr != nil {
				writeRPCError(conn, raw.ID, rpcErr.Code, rpcErr.Message, rpcErr.Kind, rpcErr.Hint)
				return
			}
			writeRPCResult(conn, raw.ID, res)
			return
		}
		started := true
		status := "idle"
		s.mu.Lock()
		term := s.terminals[params.Terminal]
		var turn uint64
		if term != nil {
			turn = term.Turn
			term.Status = &TerminalStatus{State: "working"}
		}
		s.mu.Unlock()
		writeRPCResult(conn, raw.ID, SendResult{Turn: turn, Started: &started, Status: &status})
	case "terminal.wait":
		var params WaitParams
		_ = json.Unmarshal(raw.Params, &params)
		s.mu.Lock()
		s.waitCalls = append(s.waitCalls, params)
		onWait := s.onWait
		s.mu.Unlock()
		if onWait != nil {
			res, rpcErr, skipWrite := onWait(s, params, conn)
			if skipWrite {
				return
			}
			if rpcErr != nil {
				writeRPCError(conn, raw.ID, rpcErr.Code, rpcErr.Message, rpcErr.Kind, rpcErr.Hint)
				return
			}
			writeRPCResult(conn, raw.ID, res)
			return
		}
		s.mu.Lock()
		term := s.terminals[params.Terminal]
		res := WaitResult{Terminal: params.Terminal, Ended: true, Reason: "status"}
		if term != nil {
			if term.State == "finished" {
				res.Reason = "exit"
				res.ExitCode = term.ExitCode
				res.Signal = term.Signal
			} else if term.Status != nil {
				st := term.Status.State
				res.Status = &st
			}
			res.Turn = term.Turn
		}
		s.mu.Unlock()
		writeRPCResult(conn, raw.ID, res)
	case "terminal.kill":
		var params TerminalRefParams
		_ = json.Unmarshal(raw.Params, &params)
		s.mu.Lock()
		s.killCalls = append(s.killCalls, params.Terminal)
		onKill := s.onKill
		s.mu.Unlock()
		if onKill != nil {
			res, rpcErr := onKill(s, params.Terminal)
			if rpcErr != nil {
				writeRPCError(conn, raw.ID, rpcErr.Code, rpcErr.Message, rpcErr.Kind, rpcErr.Hint)
				return
			}
			writeRPCResult(conn, raw.ID, res)
			return
		}
		s.mu.Lock()
		term, ok := s.terminals[params.Terminal]
		if !ok {
			s.mu.Unlock()
			writeRPCError(conn, raw.ID, -32000, "not_found", "not_found", "")
			return
		}
		term.State = "finished"
		sig := int32(unix.SIGHUP)
		term.Signal = &sig
		copied := *term
		s.mu.Unlock()
		writeRPCResult(conn, raw.ID, copied)
	case "terminal.read":
		var params ReadParams
		_ = json.Unmarshal(raw.Params, &params)
		s.mu.Lock()
		s.readCalls = append(s.readCalls, params)
		text := s.screenByPane[params.Terminal]
		s.mu.Unlock()
		writeRPCResult(conn, raw.ID, ReadResult{Text: text, Complete: true, How: "screen"})
	case "terminal.rm":
		var params TerminalRefParams
		_ = json.Unmarshal(raw.Params, &params)
		s.mu.Lock()
		s.rmCalls = append(s.rmCalls, params.Terminal)
		onRM := s.onRM
		s.mu.Unlock()
		if onRM != nil {
			res, rpcErr := onRM(s, params.Terminal)
			if rpcErr != nil {
				writeRPCError(conn, raw.ID, rpcErr.Code, rpcErr.Message, rpcErr.Kind, rpcErr.Hint)
				return
			}
			writeRPCResult(conn, raw.ID, res)
			return
		}
		s.mu.Lock()
		delete(s.terminals, params.Terminal)
		s.mu.Unlock()
		writeRPCResult(conn, raw.ID, RemoveResult{Removed: params.Terminal})
	}
}

type offlineFixture struct {
	base          string
	sourceDir     string
	neutralDir    string
	nativeHome    string
	writableDir   string
	promptPath    string
	providerExec  string
	fakeExec      ResolvedExecutable
	launchBuilder ports.PaneLaunchBuilder
}

func newOfflineFixture(t *testing.T) offlineFixture {
	t.Helper()
	base := canonicalTempDir(t)
	f := offlineFixture{
		base:          base,
		sourceDir:     filepath.Join(base, "src"),
		neutralDir:    filepath.Join(base, "neutral"),
		nativeHome:    filepath.Join(base, "home"),
		writableDir:   filepath.Join(base, "ns"),
		providerExec:  filepath.Join(base, "bin", "fake-provider"),
		launchBuilder: processadapter.NewPaneLaunchBuilder(),
	}
	for _, dir := range []string{
		f.sourceDir,
		f.neutralDir,
		f.nativeHome,
		f.writableDir,
		filepath.Join(f.writableDir, "home"),
		filepath.Join(f.writableDir, "tmp"),
		filepath.Join(f.writableDir, "scratch", "input"),
		filepath.Dir(f.providerExec),
	} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	writeFakeBinary(t, f.providerExec, 0o755, []byte("#!/bin/sh\nexit 0\n"))
	fakeHC := filepath.Join(base, "bin", "hc")
	digest := writeFakeBinary(t, fakeHC, 0o755, []byte("#!/bin/sh\nexit 0\n"))
	f.fakeExec = ResolvedExecutable{Path: fakeHC, SHA256: digest}

	f.promptPath = filepath.Join(f.writableDir, "scratch", "input", "prompt.md")
	if err := os.WriteFile(f.promptPath, []byte("review prompt body\nNONCE=123456\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f offlineFixture) newTerminalRequest(
	t *testing.T,
	promptBytes []byte,
	initialInput string,
	requireOSC bool,
	startupTimeout time.Duration,
	totalTimeout time.Duration,
	checkIn time.Duration,
	labels map[string]string,
	bindLaunchDir bool,
) (ports.TerminalExecutionRequest, *os.File) {
	t.Helper()
	packet, err := ports.NewProviderPacketFromBytes(promptBytes)
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
		mustEnv("HOME", filepath.Join(f.writableDir, "home")),
		mustEnv("TMPDIR", filepath.Join(f.writableDir, "tmp")),
		mustEnv("TERM", "xterm-256color"),
		mustEnv("COLORTERM", "truecolor"),
		mustEnv("TERM_PROGRAM", "ghostty"),
		mustEnv("LANG", "en_US.UTF-8"),
	}
	procReq, err := ports.NewProviderTerminalProcessRequest(
		f.providerExec,
		[]string{f.providerExec, "--flag"},
		env,
		f.neutralDir,
		binding,
		totalTimeout,
	)
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
			mustRoot(f.sourceDir),
			mustRoot(f.neutralDir),
			mustRoot(filepath.Dir(f.promptPath)),
		},
		[]ports.AnchoredRoot{
			mustRoot(filepath.Join(f.nativeHome, ".grok")),
		},
		mustRoot(f.writableDir),
	)
	if err != nil {
		t.Fatal(err)
	}
	boundary, err = ports.NewLiveReadOnlyBoundaryWithPaneTTY(boundary, mustRoot(f.nativeHome))
	if err != nil {
		t.Fatal(err)
	}
	procReq, err = ports.NewLiveReadOnlyProcessRequest(procReq, boundary)
	if err != nil {
		t.Fatal(err)
	}
	var launchFile *os.File
	if bindLaunchDir {
		launchFile, err = os.Open(f.neutralDir)
		if err != nil {
			t.Fatal(err)
		}
		procReq, err = ports.NewNeutralBoundProcessRequest(procReq, mustRoot(f.neutralDir), launchFile)
		if err != nil {
			_ = launchFile.Close()
			t.Fatal(err)
		}
	}
	req, err := ports.NewTerminalExecutionRequest(ports.TerminalExecutionRequestInput{
		Process:             procReq,
		StartupTimeout:      startupTimeout,
		PromptFilePath:      mustRoot(f.promptPath),
		InitialInput:        initialInput,
		RequireOSCReporting: requireOSC,
		CheckInInterval:     checkIn,
		Columns:             160,
		Rows:                48,
		Labels:              labels,
	})
	if err != nil {
		if launchFile != nil {
			_ = launchFile.Close()
		}
		t.Fatal(err)
	}
	return req, launchFile
}

func (f offlineFixture) newFakeSession(t *testing.T, srv *fakeHerdrServer, inspector processInspector) *Session {
	t.Helper()
	nativeHomeRoot, err := ports.NewAnchoredRoot(f.nativeHome)
	if err != nil {
		t.Fatal(err)
	}
	baseDir := filepath.Join(f.base, "mgh-test")
	sess, err := NewSession(SessionOptions{
		Clock:                    runtimeadapter.SystemClock{},
		LaunchBuilder:            f.launchBuilder,
		NativeHome:               nativeHomeRoot,
		BaseDir:                  baseDir,
		InheritedHCSocket:        filepath.Join(f.base, "ambient-hc", "default.sock"),
		HasInheritedSocket:       true,
		AmbientTerminalSocket:    filepath.Join(f.base, "ambient-hc", "term.sock"),
		HasAmbientTerminalSocket: true,
		TeardownTimeout:          600 * time.Millisecond,
		DisableWatchdog:          true,
		DisableStaleReaper:       true,
		fakeSocketPath:           srv.sockPath,
		fakeExecutable:           &f.fakeExec,
		inspector:                inspector,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sess.Close(context.Background()) })
	return sess
}

func assertLaunchDirClosed(t *testing.T, f *os.File) {
	t.Helper()
	if f == nil {
		return
	}
	if _, err := f.Stat(); err == nil {
		t.Fatal("LaunchDirectory was NOT closed by RunTerminal")
	}
}

func TestOfflineRunnerIdleSendWorkingDoneAndCheckIns(t *testing.T) {
	t.Parallel()

	fix := newOfflineFixture(t)
	srv := startFakeHerdrServer(t)
	inspector := newFakeProcessInspector()
	sess := fix.newFakeSession(t, srv, inspector)

	waitAttempt := 0
	srv.onWait = func(s *fakeHerdrServer, params WaitParams, _ net.Conn) (WaitResult, *RPCError, bool) {
		s.mu.Lock()
		defer s.mu.Unlock()
		term := s.terminals[params.Terminal]
		waitAttempt++
		if waitAttempt <= 2 {
			st := "working"
			return WaitResult{Terminal: params.Terminal, Ended: false, Reason: "timeout", Status: &st, Turn: term.Turn}, nil, false
		}
		term.Turn = 1
		term.Status = &TerminalStatus{State: "done"}
		s.screenByPane[params.Terminal] = "review completed"
		st := "done"
		return WaitResult{Terminal: params.Terminal, Ended: true, Reason: "status", Status: &st, Turn: 1}, nil, false
	}

	req, launchDir := fix.newTerminalRequest(
		t,
		[]byte("review prompt body\n"),
		"Read prompt.md and write role-report.md",
		true,
		2*time.Second,
		5*time.Second,
		100*time.Millisecond,
		map[string]string{"mulgae_registry": "gen-1"},
		true,
	)

	obs, err := sess.RunTerminal(context.Background(), req)
	assertLaunchDirClosed(t, launchDir)
	if err != nil {
		t.Fatalf("RunTerminal(): %v", err)
	}
	if !obs.Valid() || !obs.Reported() || obs.ExitedBeforeReport() {
		t.Fatalf("obs = %+v", obs)
	}
	status, ok := obs.ProgramStatus()
	if !ok || status != ports.TerminalProgramStatusDone {
		t.Fatalf("ProgramStatus = (%q, %t), want done", status, ok)
	}
	if obs.TurnCount() != 1 {
		t.Fatalf("TurnCount = %d, want 1", obs.TurnCount())
	}
	if !obs.ProcessObservation().TerminalSessionCompleted() || !obs.ProcessObservation().ProcessGroupAbsent() {
		t.Fatalf("process observation did not complete terminal teardown truthfully: %+v", obs.ProcessObservation())
	}
	if string(obs.ScreenCapture()) != "review completed" {
		t.Fatalf("ScreenCapture = %q, want %q", obs.ScreenCapture(), "review completed")
	}
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if len(srv.sendCalls) != 1 || srv.sendCalls[0].If != "idle" {
		t.Fatalf("sendCalls = %+v", srv.sendCalls)
	}
	if len(srv.waitCalls) < 3 {
		t.Fatalf("expected >= 3 wait calls (2 timeout check-ins + done), got %d", len(srv.waitCalls))
	}
	if len(srv.killCalls) != 1 || len(srv.rmCalls) != 1 || len(srv.readCalls) != 1 || srv.readCalls[0].Lines != 0 {
		t.Fatalf("teardown RPC sequence mismatch: kill=%v read=%+v rm=%v", srv.killCalls, srv.readCalls, srv.rmCalls)
	}
}

func TestOfflineRunnerBlockedAuthAndError(t *testing.T) {
	t.Parallel()

	t.Run("blocked auth at startup skips terminal.send", func(t *testing.T) {
		fix := newOfflineFixture(t)
		srv := startFakeHerdrServer(t)
		sess := fix.newFakeSession(t, srv, newFakeProcessInspector())

		srv.onRun = func(s *fakeHerdrServer, params RunParams) (Terminal, *RPCError) {
			s.mu.Lock()
			defer s.mu.Unlock()
			pid := uint32(51001)
			term := &Terminal{
				Address:  "t1",
				Argv:     params.Argv,
				CWD:      params.CWD,
				Labels:   params.Labels,
				State:    "live",
				PID:      &pid,
				Reported: true,
				Status:   &TerminalStatus{State: "blocked", Kind: "auth", Msg: "login required"},
				Screen:   "exact",
			}
			s.terminals["t1"] = term
			return *term, nil
		}

		req, launchDir := fix.newTerminalRequest(t, []byte("review prompt body\n"), "do work", true, 2*time.Second, 5*time.Second, 0, nil, true)
		obs, err := sess.RunTerminal(context.Background(), req)
		assertLaunchDirClosed(t, launchDir)
		if err != nil {
			t.Fatalf("RunTerminal(blocked auth): %v", err)
		}
		if status, _ := obs.ProgramStatus(); status != ports.TerminalProgramStatusBlocked {
			t.Fatalf("ProgramStatus = %q, want blocked", status)
		}
		if kind, _ := obs.BlockedKind(); kind != ports.TerminalBlockedKindAuth {
			t.Fatalf("BlockedKind = %q, want auth", kind)
		}
		srv.mu.Lock()
		defer srv.mu.Unlock()
		if len(srv.sendCalls) != 0 {
			t.Fatalf("terminal.send was called on blocked pane: %+v", srv.sendCalls)
		}
	})

	t.Run("error after send", func(t *testing.T) {
		fix := newOfflineFixture(t)
		srv := startFakeHerdrServer(t)
		sess := fix.newFakeSession(t, srv, newFakeProcessInspector())

		srv.onWait = func(s *fakeHerdrServer, params WaitParams, _ net.Conn) (WaitResult, *RPCError, bool) {
			s.mu.Lock()
			defer s.mu.Unlock()
			term := s.terminals[params.Terminal]
			term.Turn = 1
			term.Status = &TerminalStatus{State: "error", Msg: "api error"}
			st := "error"
			return WaitResult{Terminal: params.Terminal, Ended: true, Reason: "status", Status: &st, Turn: 1}, nil, false
		}

		req, launchDir := fix.newTerminalRequest(t, []byte("review prompt body\n"), "do work", true, 2*time.Second, 5*time.Second, 0, nil, true)
		obs, err := sess.RunTerminal(context.Background(), req)
		assertLaunchDirClosed(t, launchDir)
		if err != nil {
			t.Fatalf("RunTerminal(error): %v", err)
		}
		if status, _ := obs.ProgramStatus(); status != ports.TerminalProgramStatusError {
			t.Fatalf("ProgramStatus = %q, want error", status)
		}
	})
}

func TestOfflineRunnerPreReportedExitIndependentOfExitCode(t *testing.T) {
	t.Parallel()

	for _, code := range []int32{10, 125, 1} {
		t.Run(fmt.Sprintf("exit_%d", code), func(t *testing.T) {
			fix := newOfflineFixture(t)
			srv := startFakeHerdrServer(t)
			sess := fix.newFakeSession(t, srv, newFakeProcessInspector())

			srv.onRun = func(s *fakeHerdrServer, params RunParams) (Terminal, *RPCError) {
				s.mu.Lock()
				defer s.mu.Unlock()
				pid := uint32(52000 + code)
				exitVal := code
				term := &Terminal{
					Address:  "t1",
					Argv:     params.Argv,
					CWD:      params.CWD,
					Labels:   params.Labels,
					State:    "finished",
					PID:      &pid,
					ExitCode: &exitVal,
					Reported: false,
					Screen:   "exact",
				}
				s.terminals["t1"] = term
				return *term, nil
			}

			req, launchDir := fix.newTerminalRequest(t, []byte("review prompt body\n"), "do work", true, 2*time.Second, 5*time.Second, 0, nil, true)
			obs, err := sess.RunTerminal(context.Background(), req)
			assertLaunchDirClosed(t, launchDir)
			if err != nil {
				t.Fatalf("RunTerminal(exit=%d): %v", code, err)
			}
			if obs.Reported() || !obs.ExitedBeforeReport() {
				t.Fatalf("exit=%d: Reported=%t ExitedBeforeReport=%t, want false/true", code, obs.Reported(), obs.ExitedBeforeReport())
			}
			gotCode, hasCode := obs.ProcessObservation().ExitCode()
			if !hasCode || gotCode != int(code) {
				t.Fatalf("ExitCode = (%d, %t), want %d", gotCode, hasCode, code)
			}
			if obs.ProcessObservation().TerminalSessionCompleted() {
				t.Fatalf("pre-reported exit %d should not satisfy TerminalSessionCompleted", code)
			}
		})
	}
}

func TestOfflineRunnerCancellationAndTeardownFailClosed(t *testing.T) {
	t.Parallel()

	t.Run("cancellation tears down cleanly", func(t *testing.T) {
		fix := newOfflineFixture(t)
		srv := startFakeHerdrServer(t)
		sess := fix.newFakeSession(t, srv, newFakeProcessInspector())

		waitEntered := make(chan struct{})
		var enteredOnce sync.Once
		release := make(chan struct{})
		t.Cleanup(func() { close(release) })
		srv.onWait = func(s *fakeHerdrServer, params WaitParams, _ net.Conn) (WaitResult, *RPCError, bool) {
			enteredOnce.Do(func() { close(waitEntered) })
			<-release
			return WaitResult{}, nil, true
		}

		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			<-waitEntered
			cancel()
		}()

		req, launchDir := fix.newTerminalRequest(t, []byte("review prompt body\n"), "work", true, 2*time.Second, 10*time.Second, 5*time.Second, nil, true)
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

	t.Run("stubborn PGID survivor fails closed with ProcessGroupCleanupFailed", func(t *testing.T) {
		fix := newOfflineFixture(t)
		srv := startFakeHerdrServer(t)
		inspector := newFakeProcessInspector()
		inspector.killZeroErr[50001] = nil // Still alive even after SIGKILL.
		sess := fix.newFakeSession(t, srv, inspector)

		srv.onWait = func(s *fakeHerdrServer, params WaitParams, _ net.Conn) (WaitResult, *RPCError, bool) {
			s.mu.Lock()
			defer s.mu.Unlock()
			term := s.terminals[params.Terminal]
			term.Turn = 1
			term.Status = &TerminalStatus{State: "done"}
			st := "done"
			return WaitResult{Terminal: params.Terminal, Ended: true, Reason: "status", Status: &st, Turn: 1}, nil, false
		}

		req, launchDir := fix.newTerminalRequest(t, []byte("review prompt body\n"), "work", true, 2*time.Second, 5*time.Second, 0, nil, true)
		_, err := sess.RunTerminal(context.Background(), req)
		assertLaunchDirClosed(t, launchDir)
		var procErr *ports.ProcessExecutionError
		if !errors.As(err, &procErr) || procErr.PrimaryCause() != domain.DiagnosticCauseProcessGroupCleanupFailed {
			t.Fatalf("teardown survivor err = %v, want ProcessExecutionError(%s)", err, domain.DiagnosticCauseProcessGroupCleanupFailed)
		}
		srv.mu.Lock()
		defer srv.mu.Unlock()
		if len(srv.rmCalls) != 0 {
			t.Fatalf("terminal.rm must not be called when survivor persists: %v", srv.rmCalls)
		}
	})

	t.Run("stubborn KERN_PROC_SESSION survivor fails closed even when PGID is ESRCH", func(t *testing.T) {
		fix := newOfflineFixture(t)
		srv := startFakeHerdrServer(t)
		inspector := newFakeProcessInspector()
		inspector.killZeroErr[50001] = unix.ESRCH
		inspector.sessMembers[50001] = []int{59999}
		sess := fix.newFakeSession(t, srv, inspector)

		srv.onWait = func(s *fakeHerdrServer, params WaitParams, _ net.Conn) (WaitResult, *RPCError, bool) {
			s.mu.Lock()
			defer s.mu.Unlock()
			term := s.terminals[params.Terminal]
			term.Turn = 1
			term.Status = &TerminalStatus{State: "done"}
			st := "done"
			return WaitResult{Terminal: params.Terminal, Ended: true, Reason: "status", Status: &st, Turn: 1}, nil, false
		}

		req, launchDir := fix.newTerminalRequest(t, []byte("review prompt body\n"), "work", true, 2*time.Second, 5*time.Second, 0, nil, true)
		_, err := sess.RunTerminal(context.Background(), req)
		assertLaunchDirClosed(t, launchDir)
		var procErr *ports.ProcessExecutionError
		if !errors.As(err, &procErr) || procErr.PrimaryCause() != domain.DiagnosticCauseProcessGroupCleanupFailed {
			t.Fatalf("session survivor err = %v, want ProcessExecutionError(%s)", err, domain.DiagnosticCauseProcessGroupCleanupFailed)
		}
	})
}

func TestOfflineLabelScopedDrainAndIdempotentClose(t *testing.T) {
	t.Parallel()

	fix := newOfflineFixture(t)
	srv := startFakeHerdrServer(t)
	inspector := newFakeProcessInspector()
	sess := fix.newFakeSession(t, srv, inspector)

	// Start lazily via RuntimeIdentity.
	id, err := sess.RuntimeIdentity(context.Background())
	if err != nil || !id.Valid() || id.Version() != "0.1.20" || id.Generation() != 1 {
		t.Fatalf("RuntimeIdentity() = (%+v, %v)", id, err)
	}

	pidA, pidB := uint32(55001), uint32(55002)
	srv.mu.Lock()
	srv.terminals["t-a"] = &Terminal{Address: "t-a", State: "live", PID: &pidA, Labels: map[string]string{"mulgae_registry": "gen-a"}}
	srv.terminals["t-b"] = &Terminal{Address: "t-b", State: "live", PID: &pidB, Labels: map[string]string{"mulgae_registry": "gen-b"}}
	srv.mu.Unlock()

	// Make t-a stubborn on first drain attempt so retryability is verified.
	inspector.killZeroErr[int(pidA)] = nil
	if err := sess.DrainLabeledPanes(context.Background(), "mulgae_registry", "gen-a"); err == nil {
		t.Fatal("DrainLabeledPanes succeeded while t-a survived")
	}
	srv.mu.Lock()
	if srv.serverStopCalls != 0 {
		t.Fatalf("DrainLabeledPanes called server.stop (%d)", srv.serverStopCalls)
	}
	if _, stillB := srv.terminals["t-b"]; !stillB {
		t.Fatal("DrainLabeledPanes touched unrelated label gen-b")
	}
	if len(srv.rmCalls) != 0 {
		t.Fatalf("DrainLabeledPanes called rm on surviving pane: %v", srv.rmCalls)
	}
	srv.mu.Unlock()

	// Retry once t-a reaches ESRCH.
	inspector.mu.Lock()
	inspector.killZeroErr[int(pidA)] = unix.ESRCH
	inspector.mu.Unlock()
	if err := sess.DrainLabeledPanes(context.Background(), "mulgae_registry", "gen-a"); err != nil {
		t.Fatalf("DrainLabeledPanes retry: %v", err)
	}
	srv.mu.Lock()
	if srv.serverStopCalls != 0 {
		t.Fatalf("DrainLabeledPanes retry called server.stop (%d)", srv.serverStopCalls)
	}
	if _, existsA := srv.terminals["t-a"]; existsA {
		t.Fatal("t-a was not removed after drain retry")
	}
	if _, existsB := srv.terminals["t-b"]; !existsB {
		t.Fatal("t-b was removed by gen-a drain")
	}
	srv.mu.Unlock()

	// Idempotent Session.Close refuses future runs and closes LaunchDirectory.
	if err := sess.Close(context.Background()); err != nil {
		t.Fatalf("Close #1: %v", err)
	}
	if err := sess.Close(context.Background()); err != nil {
		t.Fatalf("Close #2 (idempotent): %v", err)
	}
	srv.mu.Lock()
	stopCalls := srv.serverStopCalls
	srv.mu.Unlock()
	if stopCalls != 1 {
		t.Fatalf("server.stop called %d times, want 1", stopCalls)
	}
	req, launchDir := fix.newTerminalRequest(t, []byte("review prompt body\n"), "after close", true, time.Second, 3*time.Second, 0, nil, true)
	_, err = sess.RunTerminal(context.Background(), req)
	assertLaunchDirClosed(t, launchDir)
	if !errors.Is(err, ErrSessionClosed) {
		t.Fatalf("RunTerminal after Close err = %v, want ErrSessionClosed", err)
	}
}

func TestOfflineCloseNeverStartedIsNoOp(t *testing.T) {
	t.Parallel()

	fix := newOfflineFixture(t)
	nativeHomeRoot, err := ports.NewAnchoredRoot(fix.nativeHome)
	if err != nil {
		t.Fatal(err)
	}
	baseDir := filepath.Join(fix.base, "never-created-base")
	sess, err := NewSession(SessionOptions{
		Clock:         runtimeadapter.SystemClock{},
		LaunchBuilder: fix.launchBuilder,
		NativeHome:    nativeHomeRoot,
		BaseDir:       baseDir,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := sess.Close(context.Background()); err != nil {
		t.Fatalf("Close(idle) #1: %v", err)
	}
	if err := sess.Close(context.Background()); err != nil {
		t.Fatalf("Close(idle) #2: %v", err)
	}
	if _, err := os.Lstat(baseDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Close on never-started session created baseDir: %v", err)
	}
	req, launchDir := fix.newTerminalRequest(t, []byte("review prompt body\n"), "hi", true, time.Second, 3*time.Second, 0, nil, true)
	_, err = sess.RunTerminal(context.Background(), req)
	assertLaunchDirClosed(t, launchDir)
	if !errors.Is(err, ErrSessionClosed) {
		t.Fatalf("RunTerminal after idle Close err = %v, want ErrSessionClosed", err)
	}
}

func TestOfflineStaleSessionReaper(t *testing.T) {
	t.Parallel()

	base := filepath.Join(canonicalTempDir(t), "mgh-reaper")
	if err := os.Mkdir(base, 0o700); err != nil {
		t.Fatal(err)
	}

	// 1. Dead owner session -> must be reaped.
	deadCmd := exec.Command("/bin/sh", "-c", "exit 0")
	if err := deadCmd.Run(); err != nil {
		t.Fatal(err)
	}
	deadPID := deadCmd.Process.Pid
	deadDir := filepath.Join(base, "0000000000000001")
	if err := os.Mkdir(deadDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writeOwnerLockAtomic(deadDir, ownerLockRecord{
		Version:        ownerLockVersion,
		SessionID:      "0000000000000001",
		OwnerPID:       deadPID,
		OwnerStartSec:  1,
		OwnerStartUsec: 1,
		SocketPath:     filepath.Join(deadDir, "s.sock"),
	}); err != nil {
		t.Fatal(err)
	}

	// 2. Live owner session (current process + exact P_starttime) -> MUST be preserved!
	selfPID := os.Getpid()
	selfSec, selfUsec, alive, err := processStartTime(selfPID)
	if err != nil || !alive {
		t.Fatalf("processStartTime(self): alive=%t err=%v", alive, err)
	}
	liveDir := filepath.Join(base, "0000000000000002")
	if err := os.Mkdir(liveDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writeOwnerLockAtomic(liveDir, ownerLockRecord{
		Version:        ownerLockVersion,
		SessionID:      "0000000000000002",
		OwnerPID:       selfPID,
		OwnerStartSec:  selfSec,
		OwnerStartUsec: selfUsec,
		SocketPath:     filepath.Join(liveDir, "s.sock"),
	}); err != nil {
		t.Fatal(err)
	}

	// 3. PID-reuse hazard: live owner PID with DIFFERENT start time -> MUST be reaped
	// safely (and its stale child sleep process killed, without harming self!).
	staleChild := exec.Command("/bin/sleep", "30")
	staleChild.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := staleChild.Start(); err != nil {
		t.Fatal(err)
	}
	staleReaped := make(chan struct{})
	go func() {
		_ = staleChild.Wait()
		close(staleReaped)
	}()
	t.Cleanup(func() {
		select {
		case <-staleReaped:
			return
		default:
			_ = unix.Kill(-staleChild.Process.Pid, unix.SIGKILL)
			<-staleReaped
		}
	})
	childSec, childUsec, childAlive, err := processStartTime(staleChild.Process.Pid)
	if err != nil || !childAlive {
		t.Fatalf("processStartTime(staleChild): alive=%t err=%v", childAlive, err)
	}

	reusedDir := filepath.Join(base, "0000000000000003")
	if err := os.Mkdir(reusedDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writeOwnerLockAtomic(reusedDir, ownerLockRecord{
		Version:        ownerLockVersion,
		SessionID:      "0000000000000003",
		OwnerPID:       selfPID,
		OwnerStartSec:  selfSec - 100, // Mismatched start time -> PID reused!
		OwnerStartUsec: selfUsec,
		CorePID:        staleChild.Process.Pid,
		CoreStartSec:   childSec,
		CoreStartUsec:  childUsec,
		SocketPath:     filepath.Join(reusedDir, "s.sock"),
	}); err != nil {
		t.Fatal(err)
	}

	// 4. Unrelated non-16hex directory -> MUST be ignored.
	otherDir := filepath.Join(base, "keep-me")
	if err := os.Mkdir(otherDir, 0o700); err != nil {
		t.Fatal(err)
	}

	if err := ReapStaleSessions(context.Background(), base); err != nil {
		t.Fatalf("ReapStaleSessions(): %v", err)
	}
	<-staleReaped

	if _, err := os.Lstat(deadDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("dead owner session dir still exists: %v", err)
	}
	if _, err := os.Lstat(reusedDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("PID-reuse stale session dir still exists: %v", err)
	}
	if _, err := os.Lstat(liveDir); err != nil {
		t.Fatalf("live session dir was unexpectedly removed: %v", err)
	}
	if _, err := os.Lstat(otherDir); err != nil {
		t.Fatalf("unrelated dir was unexpectedly removed: %v", err)
	}
	if err := unix.Kill(-staleChild.Process.Pid, 0); !errors.Is(err, unix.ESRCH) {
		t.Fatalf("stale child process survived reaper: %v", err)
	}
}

func TestOfflineRunnerStartupTimeoutTotalTimeoutAndPromptMutation(t *testing.T) {
	t.Parallel()

	t.Run("startup timeout when pane never reports", func(t *testing.T) {
		fix := newOfflineFixture(t)
		srv := startFakeHerdrServer(t)
		sess := fix.newFakeSession(t, srv, newFakeProcessInspector())

		srv.onRun = func(s *fakeHerdrServer, params RunParams) (Terminal, *RPCError) {
			s.mu.Lock()
			defer s.mu.Unlock()
			pid := uint32(53001)
			term := &Terminal{Address: "t1", State: "live", PID: &pid, Reported: false, Screen: "exact"}
			s.terminals["t1"] = term
			return *term, nil
		}
		srv.onWait = func(s *fakeHerdrServer, params WaitParams, _ net.Conn) (WaitResult, *RPCError, bool) {
			time.Sleep(40 * time.Millisecond)
			return WaitResult{Terminal: params.Terminal, Ended: false, Reason: "timeout"}, nil, false
		}

		req, launchDir := fix.newTerminalRequest(t, []byte("review prompt body\n"), "work", true, 120*time.Millisecond, 2*time.Second, 50*time.Millisecond, nil, true)
		obs, err := sess.RunTerminal(context.Background(), req)
		assertLaunchDirClosed(t, launchDir)
		if err != nil {
			t.Fatalf("RunTerminal(startup timeout): %v", err)
		}
		if obs.ProcessObservation().Termination() != ports.ProcessTerminationTimedOut {
			t.Fatalf("Termination = %q, want timed_out", obs.ProcessObservation().Termination())
		}
		if !obs.ProcessObservation().ProcessGroupAbsent() {
			t.Fatal("startup timeout did not prove ProcessGroupAbsent")
		}
	})

	t.Run("post-teardown prompt file mutation fails closed", func(t *testing.T) {
		fix := newOfflineFixture(t)
		srv := startFakeHerdrServer(t)
		sess := fix.newFakeSession(t, srv, newFakeProcessInspector())

		srv.onWait = func(s *fakeHerdrServer, params WaitParams, _ net.Conn) (WaitResult, *RPCError, bool) {
			s.mu.Lock()
			defer s.mu.Unlock()
			term := s.terminals[params.Terminal]
			term.Turn = 1
			term.Status = &TerminalStatus{State: "done"}
			// Mutate prompt file before post-teardown digest verification!
			_ = os.Chmod(fix.promptPath, 0o600)
			_ = os.WriteFile(fix.promptPath, []byte("tampered prompt body!!\n"), 0o400)
			st := "done"
			return WaitResult{Terminal: params.Terminal, Ended: true, Reason: "status", Status: &st, Turn: 1}, nil, false
		}

		req, launchDir := fix.newTerminalRequest(t, []byte("review prompt body\n"), "work", true, 2*time.Second, 5*time.Second, 0, nil, true)
		_, err := sess.RunTerminal(context.Background(), req)
		assertLaunchDirClosed(t, launchDir)
		var procErr *ports.ProcessExecutionError
		if !errors.As(err, &procErr) || procErr.PrimaryCause() != domain.DiagnosticCausePromptFilePostEndFailed {
			t.Fatalf("post-teardown prompt mutation err = %v, want ProcessExecutionError(%s)", err, domain.DiagnosticCausePromptFilePostEndFailed)
		}
	})
}

type scriptedClock struct {
	mu    sync.Mutex
	times []time.Time
	idx   int
}

func (c *scriptedClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.idx >= len(c.times) {
		return c.times[len(c.times)-1]
	}
	t := c.times[c.idx]
	c.idx++
	return t
}

func TestOfflineConcurrentCloseAndRetryPreservesDiscoveredHolders(t *testing.T) {
	t.Parallel()

	fix := newOfflineFixture(t)
	srv := startFakeHerdrServer(t)

	// Start a real short-lived sleep process so recordHoldersFromStatus records
	// a valid live PID with non-zero P_starttime when ServerStatus runs in Close.
	holderChild := exec.Command("/bin/sleep", "30")
	holderChild.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := holderChild.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = unix.Kill(-holderChild.Process.Pid, unix.SIGKILL)
		_ = holderChild.Wait()
	})
	holderPID := holderChild.Process.Pid

	// Initial startup reports no holder; Close's ServerStatus discovers holderPID.
	var statusCalls atomic.Int32
	srv.onStatus = func(_ *fakeHerdrServer) (StatusResult, *RPCError) {
		call := statusCalls.Add(1)
		if call == 1 {
			return StatusResult{Core: CoreInfo{ID: "c"}, Version: "0.1.20"}, nil
		}
		h := HolderInfo{PID: uint32(holderPID), Instance: "h1", Current: true}
		return StatusResult{Core: CoreInfo{ID: "c"}, Version: "0.1.20", Holder: &h, Holders: []HolderInfo{h}}, nil
	}

	closeEntered := make(chan struct{})
	releaseFirstClose := make(chan struct{})
	var stopAttempt atomic.Int32
	var seenOnRetry atomic.Bool

	nativeHomeRoot, err := ports.NewAnchoredRoot(fix.nativeHome)
	if err != nil {
		t.Fatal(err)
	}
	sess, err := NewSession(SessionOptions{
		Clock:                    runtimeadapter.SystemClock{},
		LaunchBuilder:            fix.launchBuilder,
		NativeHome:               nativeHomeRoot,
		BaseDir:                  filepath.Join(fix.base, "mgh-close-retry"),
		InheritedHCSocket:        filepath.Join(fix.base, "ambient", "s.sock"),
		HasInheritedSocket:       true,
		HasAmbientTerminalSocket: true,
		TeardownTimeout:          time.Second,
		DisableWatchdog:          true,
		DisableStaleReaper:       true,
		fakeSocketPath:           srv.sockPath,
		fakeExecutable:           &fix.fakeExec,
		inspector:                newFakeProcessInspector(),
		stopTrackedProc: func(proc trackedProcess, _ time.Time) error {
			n := stopAttempt.Add(1)
			if n == 1 {
				close(closeEntered)
				<-releaseFirstClose
				return fmt.Errorf("simulated stubborn holder %d", proc.PID)
			}
			if proc.PID == holderPID && hasStartTime(proc.StartSec, proc.StartUsec) {
				seenOnRetry.Store(true)
			}
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := sess.RuntimeIdentity(context.Background()); err != nil {
		t.Fatalf("RuntimeIdentity: %v", err)
	}
	if len(sess.HolderPIDs()) != 0 {
		t.Fatalf("expected 0 holders before Close, got %v", sess.HolderPIDs())
	}

	errCh1 := make(chan error, 1)
	go func() {
		errCh1 <- sess.Close(context.Background())
	}()
	<-closeEntered

	// Launch a second concurrent Close() while attempt #1 is in-flight; it must
	// serialize on closeDone and retry once attempt #1 fails.
	errCh2 := make(chan error, 1)
	go func() {
		errCh2 <- sess.Close(context.Background())
	}()
	time.Sleep(30 * time.Millisecond)

	// Make status fail on retry so the ONLY way retry sees holderPID is because
	// attempt #1 merged it back into s.holders before returning error!
	srv.mu.Lock()
	srv.onStatus = func(_ *fakeHerdrServer) (StatusResult, *RPCError) {
		return StatusResult{}, &RPCError{Code: -32000, Message: "core down", Kind: "unavailable"}
	}
	srv.mu.Unlock()

	close(releaseFirstClose)

	err1 := <-errCh1
	err2 := <-errCh2
	if err1 == nil {
		t.Fatal("expected Close attempt #1 to fail on stubborn holder")
	}
	if err2 != nil {
		t.Fatalf("expected serialized concurrent Close retry to succeed, got %v", err2)
	}
	if !seenOnRetry.Load() {
		t.Fatalf("holder PID %d discovered in Close #1 was NOT preserved into retry", holderPID)
	}
}

func TestOfflineConcurrentRunTerminalCallsOnOneSession(t *testing.T) {
	t.Parallel()

	fix := newOfflineFixture(t)
	srv := startFakeHerdrServer(t)
	sess := fix.newFakeSession(t, srv, newFakeProcessInspector())

	srv.onWait = func(s *fakeHerdrServer, params WaitParams, _ net.Conn) (WaitResult, *RPCError, bool) {
		time.Sleep(25 * time.Millisecond)
		s.mu.Lock()
		defer s.mu.Unlock()
		term := s.terminals[params.Terminal]
		term.Turn = 1
		term.Status = &TerminalStatus{State: "done"}
		st := "done"
		return WaitResult{Terminal: params.Terminal, Ended: true, Reason: "status", Status: &st, Turn: 1}, nil, false
	}

	const workers = 3
	type outcome struct {
		obs ports.TerminalExecutionObservation
		err error
	}
	reqs := make([]ports.TerminalExecutionRequest, workers)
	dirs := make([]*os.File, workers)
	for i := range workers {
		reqs[i], dirs[i] = fix.newTerminalRequest(
			t,
			[]byte("review prompt body\n"),
			fmt.Sprintf("worker-%d", i),
			true,
			2*time.Second,
			5*time.Second,
			100*time.Millisecond,
			map[string]string{"worker": fmt.Sprintf("w%d", i)},
			true,
		)
	}

	outcomes := make([]outcome, workers)
	var wg sync.WaitGroup
	for i := range workers {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			obs, err := sess.RunTerminal(context.Background(), reqs[idx])
			outcomes[idx] = outcome{obs: obs, err: err}
		}(i)
	}
	wg.Wait()

	for i, out := range outcomes {
		assertLaunchDirClosed(t, dirs[i])
		if out.err != nil {
			t.Fatalf("concurrent worker %d failed: %v", i, out.err)
		}
		if !out.obs.Valid() || !out.obs.ProcessObservation().TerminalSessionCompleted() {
			t.Fatalf("concurrent worker %d invalid observation: %+v", i, out.obs)
		}
	}
}

func TestOfflinePreStartContextFailureValidatesProviderExecutionObservation(t *testing.T) {
	t.Parallel()

	fix := newOfflineFixture(t)
	srv := startFakeHerdrServer(t)
	sess := fix.newFakeSession(t, srv, newFakeProcessInspector())

	// Warm session so RunTerminal reaches pre-start context check with valid identity.
	if _, err := sess.RuntimeIdentity(context.Background()); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	req, launchDir := fix.newTerminalRequest(t, []byte("review prompt body\n"), "work", true, 2*time.Second, 5*time.Second, 0, nil, true)
	obs, err := sess.RunTerminal(ctx, req)
	assertLaunchDirClosed(t, launchDir)
	if err != nil {
		t.Fatalf("RunTerminal(cancelled pre-start): %v", err)
	}
	if obs.ProcessObservation().Termination() != ports.ProcessTerminationCancelled {
		t.Fatalf("Termination = %q, want cancelled", obs.ProcessObservation().Termination())
	}

	// Verify the returned ProcessObservation passes ProviderExecutionObservation.Validate().
	packet, err := ports.NewProviderPacketFromBytes([]byte("review prompt body\n"))
	if err != nil {
		t.Fatal(err)
	}
	attemptID, err := domain.ParseAttemptID("a_01950000-0000-7000-8000-000000000001")
	if err != nil {
		t.Fatal(err)
	}
	invocation, err := ports.NewProviderInvocationWithPacket(
		domain.RoleLogic,
		"grok-logic",
		attemptID,
		ports.ProviderInvocationInitial,
		packet,
		"i_01950000-0000-7000-8000-000000000001",
		"01950000-0000-7000-8000-000000000001",
	)
	if err != nil {
		t.Fatal(err)
	}
	failedObs, err := ports.NewFailedProviderExecutionObservationWithCause(
		ports.ProviderExecutionStatusCancelled,
		invocation,
		obs.ProcessObservation(),
		"cancelled",
		domain.DiagnosticCauseProviderProcessWaitFailed,
		"",
	)
	if err != nil {
		t.Fatalf("NewFailedProviderExecutionObservationWithCause failed: %v", err)
	}
	if err := failedObs.Validate(); err != nil {
		t.Fatalf("ProviderExecutionObservation.Validate() failed on preStartContextFailure: %v", err)
	}
}

func TestOfflineNaturalNonZeroExitWithResidualSurvivorRecordsResidualDisposition(t *testing.T) {
	t.Parallel()

	fix := newOfflineFixture(t)
	srv := startFakeHerdrServer(t)
	inspector := newFakeProcessInspector()
	inspector.clearOnKill = true
	// Pane exits naturally with exit code 1, yet leaves a residual process in PGID 54001.
	inspector.killZeroErr[54001] = nil
	inspector.pgrpMembers[54001] = []int{54002}
	sess := fix.newFakeSession(t, srv, inspector)

	srv.onRun = func(s *fakeHerdrServer, params RunParams) (Terminal, *RPCError) {
		s.mu.Lock()
		defer s.mu.Unlock()
		pid := uint32(54001)
		exitVal := int32(1)
		term := &Terminal{
			Address:  "t1",
			Argv:     params.Argv,
			CWD:      params.CWD,
			Labels:   params.Labels,
			State:    "finished",
			PID:      &pid,
			ExitCode: &exitVal,
			Reported: false,
			Screen:   "exact",
		}
		s.terminals["t1"] = term
		return *term, nil
	}

	req, launchDir := fix.newTerminalRequest(t, []byte("review prompt body\n"), "work", true, 2*time.Second, 5*time.Second, 0, nil, true)
	obs, err := sess.RunTerminal(context.Background(), req)
	assertLaunchDirClosed(t, launchDir)
	if err != nil {
		t.Fatalf("RunTerminal(residual survivor): %v", err)
	}
	procObs := obs.ProcessObservation()
	if procObs.Termination() != ports.ProcessTerminationResidualProcessGroup {
		t.Fatalf("Termination = %q, want %q", procObs.Termination(), ports.ProcessTerminationResidualProcessGroup)
	}
	if procObs.TerminalSessionCompleted() {
		t.Fatal("natural non-zero exit with residual survivor MUST NOT report TerminalSessionCompleted() == true")
	}
	lifecycle, ok := procObs.LifecycleReceipt()
	if !ok || !lifecycle.ProcessGroupAbsent() {
		t.Fatalf("missing lifecycle receipt or ProcessGroupAbsent: %+v", lifecycle)
	}
	foundResidual := false
	for _, sigReq := range lifecycle.SignalRequests() {
		if sigReq.Reason() == ports.ProcessGroupSignalRequestResidualGroup {
			foundResidual = true
		}
	}
	if !foundResidual {
		t.Fatalf("expected ProcessGroupSignalRequestResidualGroup in %+v", lifecycle.SignalRequests())
	}
}

func TestOfflinePerRPCTimeoutNotMisclassifiedAsTotalTimeout(t *testing.T) {
	t.Parallel()

	fix := newOfflineFixture(t)
	srv := startFakeHerdrServer(t)
	sess := fix.newFakeSession(t, srv, newFakeProcessInspector())

	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	var getCount atomic.Int32
	srv.onGet = func(s *fakeHerdrServer, addr string, _ net.Conn) (Terminal, *RPCError, bool) {
		// Hang the post-send refreshPaneState (2s sub-context) while totalDeadline is 20s away.
		if getCount.Add(1) == 1 {
			<-release
			return Terminal{}, nil, true
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		return *s.terminals[addr], nil, false
	}

	req, launchDir := fix.newTerminalRequest(t, []byte("review prompt body\n"), "work", true, 15*time.Second, 20*time.Second, 5*time.Second, nil, true)
	_, err := sess.RunTerminal(context.Background(), req)
	assertLaunchDirClosed(t, launchDir)
	var procErr *ports.ProcessExecutionError
	if !errors.As(err, &procErr) || procErr.PrimaryCause() != domain.DiagnosticCauseProviderProcessWaitFailed {
		t.Fatalf("per-RPC 2s timeout err = %v, want ProcessExecutionError(%s) (not ProcessTerminationTimedOut)", err, domain.DiagnosticCauseProviderProcessWaitFailed)
	}
}

func TestOfflinePostSendTotalTimeoutClassification(t *testing.T) {
	t.Parallel()

	fix := newOfflineFixture(t)
	srv := startFakeHerdrServer(t)
	sess := fix.newFakeSession(t, srv, newFakeProcessInspector())

	srv.onWait = func(s *fakeHerdrServer, params WaitParams, _ net.Conn) (WaitResult, *RPCError, bool) {
		time.Sleep(60 * time.Millisecond)
		st := "working"
		return WaitResult{Terminal: params.Terminal, Ended: false, Reason: "timeout", Status: &st, Turn: 0}, nil, false
	}

	req, launchDir := fix.newTerminalRequest(t, []byte("review prompt body\n"), "work", true, 120*time.Millisecond, 220*time.Millisecond, 50*time.Millisecond, nil, true)
	obs, err := sess.RunTerminal(context.Background(), req)
	assertLaunchDirClosed(t, launchDir)
	if err != nil {
		t.Fatalf("RunTerminal(post-send total timeout): %v", err)
	}
	if obs.ProcessObservation().Termination() != ports.ProcessTerminationTimedOut {
		t.Fatalf("Termination = %q, want %q", obs.ProcessObservation().Termination(), ports.ProcessTerminationTimedOut)
	}
	if !obs.ProcessObservation().ProcessGroupAbsent() {
		t.Fatal("post-send total timeout did not prove ProcessGroupAbsent")
	}
}

func TestOfflineSessionHelloGenerationMismatchFailsFastAndCleansUp(t *testing.T) {
	t.Parallel()

	fix := newOfflineFixture(t)
	srv := startFakeHerdrServer(t)
	srv.helloGen = 2

	baseDir := filepath.Join(fix.base, "mgh-bad-gen")
	nativeHomeRoot, err := ports.NewAnchoredRoot(fix.nativeHome)
	if err != nil {
		t.Fatal(err)
	}
	sess, err := NewSession(SessionOptions{
		Clock:                    runtimeadapter.SystemClock{},
		LaunchBuilder:            fix.launchBuilder,
		NativeHome:               nativeHomeRoot,
		BaseDir:                  baseDir,
		HasInheritedSocket:       true,
		HasAmbientTerminalSocket: true,
		DaemonStartupTimeout:     5 * time.Second,
		DisableWatchdog:          true,
		DisableStaleReaper:       true,
		fakeSocketPath:           srv.sockPath,
		fakeExecutable:           &fix.fakeExec,
	})
	if err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	_, err = sess.RuntimeIdentity(context.Background())
	elapsed := time.Since(start)
	var handshakeErr *ProtocolHandshakeError
	if !errors.As(err, &handshakeErr) {
		t.Fatalf("RuntimeIdentity(gen=2) err = %v, want *ProtocolHandshakeError", err)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("hello generation mismatch did not fail fast: elapsed=%v", elapsed)
	}
	entries, readErr := os.ReadDir(baseDir)
	if readErr == nil && len(entries) != 0 {
		t.Fatalf("failed handshake left session dir behind in %s: %v", baseDir, entries)
	}
}

func TestOfflineBackwardClockFailsClosedWithObservationInvalid(t *testing.T) {
	t.Parallel()

	fix := newOfflineFixture(t)
	srv := startFakeHerdrServer(t)
	srv.onWait = func(s *fakeHerdrServer, params WaitParams, _ net.Conn) (WaitResult, *RPCError, bool) {
		s.mu.Lock()
		defer s.mu.Unlock()
		term := s.terminals[params.Terminal]
		term.Turn = 1
		term.Status = &TerminalStatus{State: "done"}
		st := "done"
		return WaitResult{Terminal: params.Terminal, Ended: true, Reason: "status", Status: &st, Turn: 1}, nil, false
	}

	baseTime := time.Date(2026, 11, 20, 12, 0, 10, 0, time.UTC)
	clk := &scriptedClock{times: []time.Time{baseTime, baseTime.Add(-5 * time.Second)}}
	nativeHomeRoot, err := ports.NewAnchoredRoot(fix.nativeHome)
	if err != nil {
		t.Fatal(err)
	}
	sess, err := NewSession(SessionOptions{
		Clock:                    clk,
		LaunchBuilder:            fix.launchBuilder,
		NativeHome:               nativeHomeRoot,
		BaseDir:                  filepath.Join(fix.base, "mgh-backward-clock"),
		InheritedHCSocket:        filepath.Join(fix.base, "ambient", "s.sock"),
		HasInheritedSocket:       true,
		HasAmbientTerminalSocket: true,
		TeardownTimeout:          time.Second,
		DisableWatchdog:          true,
		DisableStaleReaper:       true,
		fakeSocketPath:           srv.sockPath,
		fakeExecutable:           &fix.fakeExec,
		inspector:                newFakeProcessInspector(),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sess.Close(context.Background()) })

	req, launchDir := fix.newTerminalRequest(t, []byte("review prompt body\n"), "work", true, 2*time.Second, 5*time.Second, 0, nil, true)
	_, err = sess.RunTerminal(context.Background(), req)
	assertLaunchDirClosed(t, launchDir)
	var procErr *ports.ProcessExecutionError
	if !errors.As(err, &procErr) || procErr.PrimaryCause() != domain.DiagnosticCauseObservationInvalid {
		t.Fatalf("backward clock err = %v, want ProcessExecutionError(%s)", err, domain.DiagnosticCauseObservationInvalid)
	}
}

func TestOfflineWatchdogModeVerifiesStartTimeESRCHAndRetainsDirOnSurvivor(t *testing.T) {
	t.Parallel()

	base := filepath.Join(canonicalTempDir(t), "mgh-wd")
	if err := os.Mkdir(base, 0o700); err != nil {
		t.Fatal(err)
	}

	makeSessionDir := func(t *testing.T, id string, rec ownerLockRecord) string {
		t.Helper()
		dir := filepath.Join(base, id)
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := writeOwnerLockAtomic(dir, rec); err != nil {
			t.Fatal(err)
		}
		return dir
	}

	// 1. Clean shutdown signal ("clean\n") exits cleanly without removing sessionDir.
	cleanDir := makeSessionDir(t, "1111111111111111", ownerLockRecord{
		Version: ownerLockVersion, SessionID: "1111111111111111",
		OwnerPID: 99999, OwnerStartSec: 1, OwnerStartUsec: 1,
	})
	if err := runWatchdog(strings.NewReader("clean\n"), cleanDir, time.Second, nil); err != nil {
		t.Fatalf("runWatchdog(clean): %v", err)
	}
	if _, err := os.Lstat(cleanDir); err != nil {
		t.Fatalf("clean signal removed sessionDir: %v", err)
	}

	// 2. Unexpected EOF with stubborn survivor MUST retain sessionDir & owner.lock.json.
	surviveDir := makeSessionDir(t, "2222222222222222", ownerLockRecord{
		Version: ownerLockVersion, SessionID: "2222222222222222",
		OwnerPID: 99998, OwnerStartSec: 1, OwnerStartUsec: 1,
		CorePID: 88888, CoreStartSec: 100, CoreStartUsec: 200,
	})
	err := runWatchdog(strings.NewReader(""), surviveDir, time.Second, func(proc trackedProcess, _ time.Time) error {
		if proc.PID != 88888 || proc.StartSec != 100 || proc.StartUsec != 200 {
			return fmt.Errorf("unexpected tracked proc %+v", proc)
		}
		return fmt.Errorf("still alive")
	})
	if err == nil {
		t.Fatal("runWatchdog succeeded despite unproven survivor")
	}
	if _, statErr := os.Lstat(filepath.Join(surviveDir, ownerLockFileName)); statErr != nil {
		t.Fatalf("owner.lock.json was removed despite unproven survivor: %v", statErr)
	}

	// 3. Unexpected EOF with real child process: verifies P_starttime, kills to ESRCH, and removes sessionDir.
	child := exec.Command("/bin/sleep", "30")
	child.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	childReaped := make(chan struct{})
	go func() {
		_ = child.Wait()
		close(childReaped)
	}()
	t.Cleanup(func() {
		select {
		case <-childReaped:
			return
		default:
			_ = unix.Kill(-child.Process.Pid, unix.SIGKILL)
			<-childReaped
		}
	})
	cSec, cUsec, alive, err := processStartTime(child.Process.Pid)
	if err != nil || !alive {
		t.Fatalf("processStartTime(child): alive=%t err=%v", alive, err)
	}

	killDir := makeSessionDir(t, "3333333333333333", ownerLockRecord{
		Version: ownerLockVersion, SessionID: "3333333333333333",
		OwnerPID: 99997, OwnerStartSec: 1, OwnerStartUsec: 1,
		CorePID: child.Process.Pid, CoreStartSec: cSec, CoreStartUsec: cUsec,
	})
	if err := runWatchdog(strings.NewReader(""), killDir, 3*time.Second, ensureTrackedProcessGroupStopped); err != nil {
		t.Fatalf("runWatchdog(EOF real child): %v", err)
	}
	<-childReaped
	if _, statErr := os.Lstat(killDir); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("sessionDir survived successful watchdog cleanup: %v", statErr)
	}
	if killErr := unix.Kill(-child.Process.Pid, 0); !errors.Is(killErr, unix.ESRCH) {
		t.Fatalf("child process survived watchdog cleanup: %v", killErr)
	}

	// 4. RunWatchdogMode ignores ordinary argv and rejects malformed sentinel args.
	if handled, err := RunWatchdogMode([]string{"mulgae", "version"}); handled || err != nil {
		t.Fatalf("RunWatchdogMode(ordinary) = (%t, %v), want (false, nil)", handled, err)
	}
	if handled, err := RunWatchdogMode([]string{"mulgae", watchdogArgSentinel, "relative/dir"}); !handled || err == nil {
		t.Fatalf("RunWatchdogMode(relative dir) = (%t, %v), want (true, error)", handled, err)
	}
}

func TestOfflinePromptPrefixIntegrityAndOSCStateMachineHardening(t *testing.T) {
	t.Parallel()

	t.Run("tampered prompt packet prefix rejected even when file has trailing nonce", func(t *testing.T) {
		fix := newOfflineFixture(t)
		srv := startFakeHerdrServer(t)
		sess := fix.newFakeSession(t, srv, newFakeProcessInspector())

		// Write prompt.md longer than packet (simulating trailing nonce), but with different prefix bytes.
		_ = os.Chmod(fix.promptPath, 0o600)
		if err := os.WriteFile(fix.promptPath, []byte("TAMPERED prompt body\nNONCE=123456\n"), 0o400); err != nil {
			t.Fatal(err)
		}
		req, launchDir := fix.newTerminalRequest(t, []byte("review prompt body\n"), "work", true, 2*time.Second, 5*time.Second, 0, nil, true)
		_, err := sess.RunTerminal(context.Background(), req)
		assertLaunchDirClosed(t, launchDir)
		var procErr *ports.ProcessExecutionError
		if !errors.As(err, &procErr) || procErr.PrimaryCause() != domain.DiagnosticCausePromptFilePreStartFailed {
			t.Fatalf("tampered prefix err = %v, want ProcessExecutionError(%s)", err, domain.DiagnosticCausePromptFilePreStartFailed)
		}
	})

	t.Run("non-0400 prompt file rejected", func(t *testing.T) {
		fix := newOfflineFixture(t)
		srv := startFakeHerdrServer(t)
		sess := fix.newFakeSession(t, srv, newFakeProcessInspector())

		if err := os.Chmod(fix.promptPath, 0o600); err != nil {
			t.Fatal(err)
		}
		req, launchDir := fix.newTerminalRequest(t, []byte("review prompt body\n"), "work", true, 2*time.Second, 5*time.Second, 0, nil, true)
		_, err := sess.RunTerminal(context.Background(), req)
		assertLaunchDirClosed(t, launchDir)
		var procErr *ports.ProcessExecutionError
		if !errors.As(err, &procErr) || procErr.PrimaryCause() != domain.DiagnosticCausePromptFilePreStartFailed {
			t.Fatalf("non-0400 prompt err = %v, want ProcessExecutionError(%s)", err, domain.DiagnosticCausePromptFilePreStartFailed)
		}
	})

	t.Run("startup done before initial input fails closed", func(t *testing.T) {
		fix := newOfflineFixture(t)
		srv := startFakeHerdrServer(t)
		sess := fix.newFakeSession(t, srv, newFakeProcessInspector())

		srv.onRun = func(s *fakeHerdrServer, params RunParams) (Terminal, *RPCError) {
			s.mu.Lock()
			defer s.mu.Unlock()
			pid := uint32(56001)
			term := &Terminal{
				Address:  "t1",
				Argv:     params.Argv,
				CWD:      params.CWD,
				Labels:   params.Labels,
				State:    "live",
				PID:      &pid,
				Reported: true,
				Status:   &TerminalStatus{State: "done"},
				Screen:   "exact",
			}
			s.terminals["t1"] = term
			return *term, nil
		}

		req, launchDir := fix.newTerminalRequest(t, []byte("review prompt body\n"), "must send me", true, 2*time.Second, 5*time.Second, 0, nil, true)
		_, err := sess.RunTerminal(context.Background(), req)
		assertLaunchDirClosed(t, launchDir)
		var procErr *ports.ProcessExecutionError
		if !errors.As(err, &procErr) || procErr.PrimaryCause() != domain.DiagnosticCauseProviderProcessWaitFailed {
			t.Fatalf("startup done before send err = %v, want ProcessExecutionError(%s)", err, domain.DiagnosticCauseProviderProcessWaitFailed)
		}
	})

	t.Run("status_mismatch retries send and Started=false does not finish early", func(t *testing.T) {
		fix := newOfflineFixture(t)
		srv := startFakeHerdrServer(t)
		sess := fix.newFakeSession(t, srv, newFakeProcessInspector())

		var sendAttempts atomic.Int32
		srv.onSend = func(s *fakeHerdrServer, params SendParams) (SendResult, *RPCError) {
			n := sendAttempts.Add(1)
			if n == 1 {
				return SendResult{}, &RPCError{Code: -32000, Message: "status changed", Kind: "status_mismatch"}
			}
			started := false
			st := "idle"
			return SendResult{Turn: 0, Started: &started, Status: &st}, nil
		}

		var getCount atomic.Int32
		srv.onGet = func(s *fakeHerdrServer, addr string, _ net.Conn) (Terminal, *RPCError, bool) {
			s.mu.Lock()
			defer s.mu.Unlock()
			term := s.terminals[addr]
			c := getCount.Add(1)
			// 1: refresh after status_mismatch -> idle (triggers retry)
			// 2: post-send refresh -> still idle turn=0 (Started=false -> must NOT finish!)
			// 3: next poll -> working
			// 4+: done turn=1
			switch {
			case c == 3:
				term.Status = &TerminalStatus{State: "working"}
			case c >= 4:
				term.Turn = 1
				term.Status = &TerminalStatus{State: "done"}
			}
			return *term, nil, false
		}

		req, launchDir := fix.newTerminalRequest(t, []byte("review prompt body\n"), "retry me", true, 2*time.Second, 5*time.Second, 100*time.Millisecond, nil, true)
		obs, err := sess.RunTerminal(context.Background(), req)
		assertLaunchDirClosed(t, launchDir)
		if err != nil {
			t.Fatalf("RunTerminal(status_mismatch + Started=false): %v", err)
		}
		if sendAttempts.Load() != 2 {
			t.Fatalf("sendAttempts = %d, want 2", sendAttempts.Load())
		}
		if obs.TurnCount() != 1 {
			t.Fatalf("TurnCount = %d, want 1", obs.TurnCount())
		}
		if status, _ := obs.ProgramStatus(); status != ports.TerminalProgramStatusDone {
			t.Fatalf("ProgramStatus = %q, want done", status)
		}
	})
}

func TestOfflineDrainFinishedPaneVerifiesSurvivorsAcrossRetriesAndFailedTeardown(t *testing.T) {
	t.Parallel()

	t.Run("two consecutive DrainLabeledPanes fail closed on finished pane while survivor persists", func(t *testing.T) {
		fix := newOfflineFixture(t)
		srv := startFakeHerdrServer(t)
		inspector := newFakeProcessInspector()
		sess := fix.newFakeSession(t, srv, inspector)

		if _, err := sess.RuntimeIdentity(context.Background()); err != nil {
			t.Fatal(err)
		}

		pidA := uint32(55101)
		srv.mu.Lock()
		srv.terminals["t-a"] = &Terminal{
			Address: "t-a",
			State:   "live",
			PID:     &pidA,
			Labels:  map[string]string{"mulgae_registry": "gen-retry"},
		}
		srv.mu.Unlock()

		// Survivor persists across BOTH attempt #1 (which marks t-a "finished" via
		// terminal.kill) and attempt #2 (which sees State == "finished").
		inspector.mu.Lock()
		inspector.killZeroErr[int(pidA)] = nil
		inspector.sessMembers[int(pidA)] = []int{55102}
		inspector.mu.Unlock()

		if err := sess.DrainLabeledPanes(context.Background(), "mulgae_registry", "gen-retry"); err == nil {
			t.Fatal("DrainLabeledPanes attempt #1 succeeded despite survivor")
		}
		srv.mu.Lock()
		stateAfter1 := srv.terminals["t-a"].State
		rmAfter1 := len(srv.rmCalls)
		srv.mu.Unlock()
		if stateAfter1 != "finished" {
			t.Fatalf("expected fake server to mark t-a finished after kill, got %q", stateAfter1)
		}
		if rmAfter1 != 0 {
			t.Fatalf("attempt #1 must not call terminal.rm while survivor persists: rmCalls=%d", rmAfter1)
		}

		// Attempt #2 sees State == "finished" but MUST STILL fail closed and NOT remove!
		if err := sess.DrainLabeledPanes(context.Background(), "mulgae_registry", "gen-retry"); err == nil {
			t.Fatal("DrainLabeledPanes attempt #2 succeeded on finished pane despite persisting survivor")
		}
		srv.mu.Lock()
		rmAfter2 := len(srv.rmCalls)
		_, stillPresent := srv.terminals["t-a"]
		srv.mu.Unlock()
		if rmAfter2 != 0 || !stillPresent {
			t.Fatalf("attempt #2 must not call terminal.rm while survivor persists: rmCalls=%d stillPresent=%t", rmAfter2, stillPresent)
		}

		// Once ESRCH + empty session is reached, attempt #3 removes t-a and returns nil.
		inspector.mu.Lock()
		inspector.killZeroErr[int(pidA)] = unix.ESRCH
		delete(inspector.sessMembers, int(pidA))
		inspector.mu.Unlock()

		if err := sess.DrainLabeledPanes(context.Background(), "mulgae_registry", "gen-retry"); err != nil {
			t.Fatalf("DrainLabeledPanes attempt #3 after ESRCH: %v", err)
		}
		srv.mu.Lock()
		_, existsAfter3 := srv.terminals["t-a"]
		rmAfter3 := len(srv.rmCalls)
		srv.mu.Unlock()
		if existsAfter3 || rmAfter3 != 1 {
			t.Fatalf("attempt #3 did not remove t-a cleanly: exists=%t rmCalls=%d", existsAfter3, rmAfter3)
		}
	})

	t.Run("DrainLabeledPanes after failed RunTerminal teardown survivor fails closed until ESRCH", func(t *testing.T) {
		fix := newOfflineFixture(t)
		srv := startFakeHerdrServer(t)
		inspector := newFakeProcessInspector()
		// RunTerminal spawns t1 with pid 50001; keep a stubborn session survivor alive.
		inspector.killZeroErr[50001] = unix.ESRCH
		inspector.sessMembers[50001] = []int{59001}
		sess := fix.newFakeSession(t, srv, inspector)

		srv.onWait = func(s *fakeHerdrServer, params WaitParams, _ net.Conn) (WaitResult, *RPCError, bool) {
			s.mu.Lock()
			defer s.mu.Unlock()
			term := s.terminals[params.Terminal]
			term.Turn = 1
			term.Status = &TerminalStatus{State: "done"}
			st := "done"
			return WaitResult{Terminal: params.Terminal, Ended: true, Reason: "status", Status: &st, Turn: 1}, nil, false
		}

		req, launchDir := fix.newTerminalRequest(t, []byte("review prompt body\n"), "work", true, 2*time.Second, 5*time.Second, 0, map[string]string{"mulgae_registry": "gen-teardown"}, true)
		_, err := sess.RunTerminal(context.Background(), req)
		assertLaunchDirClosed(t, launchDir)
		var procErr *ports.ProcessExecutionError
		if !errors.As(err, &procErr) || procErr.PrimaryCause() != domain.DiagnosticCauseProcessGroupCleanupFailed {
			t.Fatalf("RunTerminal survivor err = %v, want ProcessExecutionError(%s)", err, domain.DiagnosticCauseProcessGroupCleanupFailed)
		}

		// Server now has t1 in "finished" state (from teardown's terminal.kill),
		// yet survivor 59001 persists: DrainLabeledPanes MUST fail closed without rm.
		if drainErr := sess.DrainLabeledPanes(context.Background(), "mulgae_registry", "gen-teardown"); drainErr == nil {
			t.Fatal("DrainLabeledPanes succeeded while failed RunTerminal teardown survivor persisted")
		}
		srv.mu.Lock()
		rmBeforeClear := len(srv.rmCalls)
		srv.mu.Unlock()
		if rmBeforeClear != 0 {
			t.Fatalf("terminal.rm must not be called while RunTerminal teardown survivor persists: rmCalls=%d", rmBeforeClear)
		}

		// Clear survivor -> retry removes t1 and succeeds.
		inspector.mu.Lock()
		delete(inspector.sessMembers, 50001)
		inspector.mu.Unlock()

		if drainErr := sess.DrainLabeledPanes(context.Background(), "mulgae_registry", "gen-teardown"); drainErr != nil {
			t.Fatalf("DrainLabeledPanes retry after survivor cleared: %v", drainErr)
		}
		srv.mu.Lock()
		_, stillExists := srv.terminals["t1"]
		rmAfterClear := len(srv.rmCalls)
		srv.mu.Unlock()
		if stillExists || rmAfterClear != 1 {
			t.Fatalf("expected t1 removed after survivor cleared: exists=%t rmCalls=%d", stillExists, rmAfterClear)
		}
	})

	t.Run("reused leader PID on finished pane is not signaled while pane-era check succeeds", func(t *testing.T) {
		fix := newOfflineFixture(t)
		srv := startFakeHerdrServer(t)
		inspector := newFakeProcessInspector()
		sess := fix.newFakeSession(t, srv, inspector)

		if _, err := sess.RuntimeIdentity(context.Background()); err != nil {
			t.Fatal(err)
		}

		reusedPID := uint32(55200)
		paneCreated := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
		reusedStarted := paneCreated.Add(30 * time.Second)
		inspector.mu.Lock()
		// Reused PID is alive (kill(-pid, 0) == nil) with a much newer P_starttime.
		inspector.killZeroErr[int(reusedPID)] = nil
		inspector.procInfo[int(reusedPID)] = processInfo{
			Exists:    true,
			StartSec:  reusedStarted.Unix(),
			StartUsec: 0,
			PGID:      int(reusedPID),
		}
		inspector.pgrpMembers[int(reusedPID)] = []int{int(reusedPID)}
		inspector.sessMembers[int(reusedPID)] = []int{int(reusedPID)}
		inspector.mu.Unlock()

		srv.mu.Lock()
		srv.terminals["t-reused"] = &Terminal{
			Address:   "t-reused",
			State:     "finished",
			PID:       &reusedPID,
			CreatedMS: uint64(paneCreated.UnixMilli()),
			Labels:    map[string]string{"mulgae_registry": "gen-reused"},
		}
		srv.mu.Unlock()

		if err := sess.DrainLabeledPanes(context.Background(), "mulgae_registry", "gen-reused"); err != nil {
			t.Fatalf("DrainLabeledPanes(reused PID): %v", err)
		}
		inspector.mu.Lock()
		kills := append([]int(nil), inspector.killCalls...)
		pidKills := append([]int(nil), inspector.pidKillCalls...)
		inspector.mu.Unlock()
		if len(kills) != 0 || len(pidKills) != 0 {
			t.Fatalf("must never signal reused PID! killCalls=%v pidKillCalls=%v", kills, pidKills)
		}
	})
}

func TestOfflineKillNotFoundWithLocalSIGKILLEscalationFailsClosed(t *testing.T) {
	t.Parallel()

	fix := newOfflineFixture(t)
	srv := startFakeHerdrServer(t)
	inspector := newFakeProcessInspector()
	inspector.clearOnKill = true
	// Pane pid 50001 is still alive when teardown runs; local SIGKILL clears it.
	inspector.killZeroErr[50001] = nil
	sess := fix.newFakeSession(t, srv, inspector)

	srv.onWait = func(s *fakeHerdrServer, params WaitParams, _ net.Conn) (WaitResult, *RPCError, bool) {
		s.mu.Lock()
		defer s.mu.Unlock()
		term := s.terminals[params.Terminal]
		term.Turn = 1
		term.Status = &TerminalStatus{State: "done"}
		st := "done"
		return WaitResult{Terminal: params.Terminal, Ended: true, Reason: "status", Status: &st, Turn: 1}, nil, false
	}
	srv.onKill = func(s *fakeHerdrServer, addr string) (Terminal, *RPCError) {
		s.mu.Lock()
		delete(s.terminals, addr)
		s.mu.Unlock()
		return Terminal{}, &RPCError{Code: -32000, Message: "not found", Kind: "not_found"}
	}

	req, launchDir := fix.newTerminalRequest(t, []byte("review prompt body\n"), "work", true, 2*time.Second, 5*time.Second, 0, nil, true)
	obs, err := sess.RunTerminal(context.Background(), req)
	assertLaunchDirClosed(t, launchDir)
	var procErr *ports.ProcessExecutionError
	if !errors.As(err, &procErr) || procErr.PrimaryCause() != domain.DiagnosticCauseProcessGroupCleanupFailed {
		t.Fatalf("kill not_found + local SIGKILL err = %v, want ProcessExecutionError(%s)", err, domain.DiagnosticCauseProcessGroupCleanupFailed)
	}
	if obs.Valid() && obs.ProcessObservation().TerminalSessionCompleted() {
		t.Fatal("terminal.kill not_found MUST NEVER report TerminalSessionCompleted() == true")
	}
	inspector.mu.Lock()
	killCalls := append([]int(nil), inspector.killCalls...)
	inspector.mu.Unlock()
	if len(killCalls) == 0 || killCalls[0] != 50001 {
		t.Fatalf("expected local SIGKILL escalation on 50001 despite not_found, got killCalls=%v", killCalls)
	}
}

func TestOfflineTerminalRemoveRetriesTransientLiveRPCError(t *testing.T) {
	t.Parallel()

	t.Run("RunTerminal teardown retries transient live twice then succeeds", func(t *testing.T) {
		fix := newOfflineFixture(t)
		srv := startFakeHerdrServer(t)
		sess := fix.newFakeSession(t, srv, newFakeProcessInspector())

		srv.onWait = func(s *fakeHerdrServer, params WaitParams, _ net.Conn) (WaitResult, *RPCError, bool) {
			s.mu.Lock()
			defer s.mu.Unlock()
			term := s.terminals[params.Terminal]
			term.Turn = 1
			term.Status = &TerminalStatus{State: "done"}
			st := "done"
			return WaitResult{Terminal: params.Terminal, Ended: true, Reason: "status", Status: &st, Turn: 1}, nil, false
		}
		var rmAttempts atomic.Int32
		srv.onRM = func(s *fakeHerdrServer, addr string) (RemoveResult, *RPCError) {
			if rmAttempts.Add(1) <= 2 {
				return RemoveResult{}, &RPCError{Code: -32000, Message: "still live", Kind: "live"}
			}
			s.mu.Lock()
			delete(s.terminals, addr)
			s.mu.Unlock()
			return RemoveResult{Removed: addr}, nil
		}

		req, launchDir := fix.newTerminalRequest(t, []byte("review prompt body\n"), "work", true, 2*time.Second, 5*time.Second, 0, nil, true)
		obs, err := sess.RunTerminal(context.Background(), req)
		assertLaunchDirClosed(t, launchDir)
		if err != nil {
			t.Fatalf("RunTerminal with transient terminal.rm live error: %v", err)
		}
		if rmAttempts.Load() != 3 {
			t.Fatalf("terminal.rm attempts = %d, want 3", rmAttempts.Load())
		}
		if !obs.Valid() || !obs.ProcessObservation().TerminalSessionCompleted() {
			t.Fatalf("expected valid completed observation, got %+v", obs)
		}
	})

	t.Run("DrainLabeledPanes retries transient live twice then succeeds", func(t *testing.T) {
		fix := newOfflineFixture(t)
		srv := startFakeHerdrServer(t)
		sess := fix.newFakeSession(t, srv, newFakeProcessInspector())

		if _, err := sess.RuntimeIdentity(context.Background()); err != nil {
			t.Fatal(err)
		}
		pid := uint32(55301)
		srv.mu.Lock()
		srv.terminals["t-live-rm"] = &Terminal{
			Address: "t-live-rm",
			State:   "live",
			PID:     &pid,
			Labels:  map[string]string{"mulgae_registry": "gen-rm-retry"},
		}
		srv.mu.Unlock()

		var rmAttempts atomic.Int32
		srv.onRM = func(s *fakeHerdrServer, addr string) (RemoveResult, *RPCError) {
			if rmAttempts.Add(1) <= 2 {
				return RemoveResult{}, &RPCError{Code: -32000, Message: "still live", Kind: "live"}
			}
			s.mu.Lock()
			delete(s.terminals, addr)
			s.mu.Unlock()
			return RemoveResult{Removed: addr}, nil
		}

		if err := sess.DrainLabeledPanes(context.Background(), "mulgae_registry", "gen-rm-retry"); err != nil {
			t.Fatalf("DrainLabeledPanes with transient terminal.rm live error: %v", err)
		}
		if rmAttempts.Load() != 3 {
			t.Fatalf("terminal.rm attempts = %d, want 3", rmAttempts.Load())
		}
	})
}

func TestOfflineMalformedControlPlaneSocketFailsClosed(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name            string
		inheritedSocket string
		ambientSocket   string
	}{
		{name: "inherited root slash", inheritedSocket: "/"},
		{name: "inherited NUL byte", inheritedSocket: "/private/tmp/bad\x00sock"},
		{name: "inherited trailing space", inheritedSocket: "/private/tmp/op.sock "},
		{name: "inherited newline only", inheritedSocket: "\n"},
		{name: "inherited relative path", inheritedSocket: "relative.sock"},
		{name: "inherited unclean path", inheritedSocket: "/private/tmp/../tmp/op.sock"},
		{name: "ambient root slash", ambientSocket: "/"},
		{name: "ambient NUL byte", ambientSocket: "/private/tmp/bad\x00term.sock"},
		{name: "ambient trailing space", ambientSocket: "/private/tmp/term.sock "},
		{name: "ambient newline only", ambientSocket: "\n"},
		{name: "ambient relative path", ambientSocket: "relative.sock"},
		{name: "ambient unclean path", ambientSocket: "/private/tmp/../tmp/term.sock"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fix := newOfflineFixture(t)
			srv := startFakeHerdrServer(t)
			nativeHomeRoot, err := ports.NewAnchoredRoot(fix.nativeHome)
			if err != nil {
				t.Fatal(err)
			}
			sess, err := NewSession(SessionOptions{
				Clock:                    runtimeadapter.SystemClock{},
				LaunchBuilder:            fix.launchBuilder,
				NativeHome:               nativeHomeRoot,
				BaseDir:                  filepath.Join(fix.base, "mgh-bad-sock"),
				InheritedHCSocket:        tc.inheritedSocket,
				HasInheritedSocket:       true,
				AmbientTerminalSocket:    tc.ambientSocket,
				HasAmbientTerminalSocket: true,
				TeardownTimeout:          time.Second,
				DisableWatchdog:          true,
				DisableStaleReaper:       true,
				fakeSocketPath:           srv.sockPath,
				fakeExecutable:           &fix.fakeExec,
				inspector:                newFakeProcessInspector(),
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = sess.Close(context.Background()) })

			req, launchDir := fix.newTerminalRequest(t, []byte("review prompt body\n"), "work", true, 2*time.Second, 5*time.Second, 0, nil, true)
			_, err = sess.RunTerminal(context.Background(), req)
			assertLaunchDirClosed(t, launchDir)
			var procErr *ports.ProcessExecutionError
			if !errors.As(err, &procErr) || procErr.PrimaryCause() != domain.DiagnosticCauseProviderSpawnFailed {
				t.Fatalf("malformed socket err = %v, want ProcessExecutionError(%s)", err, domain.DiagnosticCauseProviderSpawnFailed)
			}
			srv.mu.Lock()
			runCount := len(srv.runCalls)
			srv.mu.Unlock()
			if runCount != 0 {
				t.Fatalf("terminal.run must not be called when overlayControlPlane fails: runCalls=%d", runCount)
			}
		})
	}
}

func TestOfflineTrackedProcessZeroStartTimeFailsClosedAndCloseCapsRunsIdleWait(t *testing.T) {
	t.Parallel()

	t.Run("zero P_starttime fails closed in inspect and ensureStopped", func(t *testing.T) {
		proc := trackedProcess{PID: 54321, StartSec: 0, StartUsec: 0}
		if state, err := inspectTrackedProcessGroup(proc); err == nil || !state.groupStillExists {
			t.Fatalf("inspectTrackedProcessGroup(zero start) = (%+v, %v), want error with groupStillExists=true", state, err)
		}
		if err := ensureTrackedProcessGroupStopped(proc, time.Now().Add(50*time.Millisecond)); err == nil {
			t.Fatal("ensureTrackedProcessGroupStopped(zero start) succeeded, want error")
		}
	})

	t.Run("Close caps runsIdleCh wait to half of closeBudget and finishes performClose within deadline", func(t *testing.T) {
		fix := newOfflineFixture(t)
		srv := startFakeHerdrServer(t)
		nativeHomeRoot, err := ports.NewAnchoredRoot(fix.nativeHome)
		if err != nil {
			t.Fatal(err)
		}
		sess, err := NewSession(SessionOptions{
			Clock:                    runtimeadapter.SystemClock{},
			LaunchBuilder:            fix.launchBuilder,
			NativeHome:               nativeHomeRoot,
			BaseDir:                  filepath.Join(fix.base, "mgh-close-budget"),
			HasInheritedSocket:       true,
			HasAmbientTerminalSocket: true,
			TeardownTimeout:          2 * time.Second,
			DisableWatchdog:          true,
			DisableStaleReaper:       true,
			fakeSocketPath:           srv.sockPath,
			fakeExecutable:           &fix.fakeExec,
			inspector:                newFakeProcessInspector(),
		})
		if err != nil {
			t.Fatal(err)
		}

		if _, err := sess.RuntimeIdentity(context.Background()); err != nil {
			t.Fatal(err)
		}

		// Simulate an active run that will not finish before Close's deadline.
		sess.mu.Lock()
		sess.activeRuns = 1
		sess.mu.Unlock()
		t.Cleanup(func() {
			sess.mu.Lock()
			sess.activeRuns = 0
			if sess.runsIdleCh != nil {
				close(sess.runsIdleCh)
				sess.runsIdleCh = nil
			}
			sess.mu.Unlock()
		})

		closeCtx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
		defer cancel()
		start := time.Now()
		closeErr := sess.Close(closeCtx)
		elapsed := time.Since(start)
		if closeErr != nil {
			t.Fatalf("Close with active run and tight deadline: %v", closeErr)
		}
		// Must wait roughly half of 400ms (~200ms) for runsIdleCh, then still have
		// budget left to execute server.stop and return well under 400ms+margin!
		if elapsed > 700*time.Millisecond {
			t.Fatalf("Close blew past ctx deadline budget: elapsed=%v", elapsed)
		}
		srv.mu.Lock()
		stops := srv.serverStopCalls
		srv.mu.Unlock()
		if stops != 1 {
			t.Fatalf("server.stop calls = %d, want 1 (performClose must not be starved by runsIdleCh)", stops)
		}
	})
}

func TestOfflineCapturePaneIdentityBoundsStartTimeAndSID(t *testing.T) {
	t.Parallel()

	fix := newOfflineFixture(t)
	srv := startFakeHerdrServer(t)
	inspector := newFakeProcessInspector()
	sess := fix.newFakeSession(t, srv, inspector)

	created := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	createdMS := uint64(created.UnixMilli())

	// 1. capturePaneSID must never adopt a foreign sid != panePID.
	inspector.mu.Lock()
	inspector.sidByPID[56100] = 77777
	inspector.mu.Unlock()
	if got := sess.capturePaneSID(56100); got != 56100 {
		t.Fatalf("capturePaneSID(56100) with foreign sid=77777 = %d, want 56100", got)
	}

	// 2. capturePaneStartTime accepts in-window start times and rejects out-of-window start times.
	inspector.mu.Lock()
	inspector.procInfo[56101] = processInfo{Exists: true, StartSec: created.Add(500 * time.Millisecond).Unix(), StartUsec: 123}
	inspector.procInfo[56102] = processInfo{Exists: true, StartSec: created.Add(30 * time.Second).Unix(), StartUsec: 456}
	inspector.procInfo[56103] = processInfo{Exists: true, StartSec: created.Add(-10 * time.Second).Unix(), StartUsec: 789}
	inspector.mu.Unlock()

	if sec, usec := sess.capturePaneStartTime(56101, createdMS); sec != created.Add(500*time.Millisecond).Unix() || usec != 123 {
		t.Fatalf("in-window capturePaneStartTime(56101) = (%d, %d), want (%d, 123)", sec, usec, created.Add(500*time.Millisecond).Unix())
	}
	if sec, usec := sess.capturePaneStartTime(56102, createdMS); sec != 0 || usec != 0 {
		t.Fatalf("post-window capturePaneStartTime(56102) = (%d, %d), want (0, 0)", sec, usec)
	}
	if sec, usec := sess.capturePaneStartTime(56103, createdMS); sec != 0 || usec != 0 {
		t.Fatalf("pre-window capturePaneStartTime(56103) = (%d, %d), want (0, 0)", sec, usec)
	}

	// 3. A pane already "finished" on TerminalRun must NOT capture start time from a
	// recycled PID, and teardown must treat that PID as leaderReused (never signaling it).
	reusedPID := uint32(56104)
	reusedStart := created.Add(30 * time.Second)
	inspector.mu.Lock()
	inspector.killZeroErr[int(reusedPID)] = nil
	inspector.procInfo[int(reusedPID)] = processInfo{Exists: true, StartSec: reusedStart.Unix(), StartUsec: 0, PGID: int(reusedPID)}
	inspector.pgrpMembers[int(reusedPID)] = []int{int(reusedPID)}
	inspector.sessMembers[int(reusedPID)] = []int{int(reusedPID)}
	inspector.mu.Unlock()

	srv.onRun = func(s *fakeHerdrServer, params RunParams) (Terminal, *RPCError) {
		s.mu.Lock()
		defer s.mu.Unlock()
		exitZero := int32(0)
		term := &Terminal{
			Address:   "t-fin",
			Argv:      params.Argv,
			CWD:       params.CWD,
			Labels:    params.Labels,
			State:     "finished",
			PID:       &reusedPID,
			ExitCode:  &exitZero,
			CreatedMS: createdMS,
			Reported:  false,
			Screen:    "exact",
		}
		s.terminals["t-fin"] = term
		return *term, nil
	}

	req, launchDir := fix.newTerminalRequest(t, []byte("review prompt body\n"), "work", true, 2*time.Second, 5*time.Second, 0, nil, true)
	obs, err := sess.RunTerminal(context.Background(), req)
	assertLaunchDirClosed(t, launchDir)
	if err != nil {
		t.Fatalf("RunTerminal(already finished with recycled PID): %v", err)
	}
	if !obs.Valid() || !obs.ExitedBeforeReport() {
		t.Fatalf("unexpected observation for pre-finished pane: %+v", obs)
	}
	inspector.mu.Lock()
	kills := append([]int(nil), inspector.killCalls...)
	pidKills := append([]int(nil), inspector.pidKillCalls...)
	inspector.mu.Unlock()
	if len(kills) != 0 || len(pidKills) != 0 {
		t.Fatalf("must not signal recycled PID of already-finished pane! kills=%v pidKills=%v", kills, pidKills)
	}
}

func TestOfflineStartupAbortRetainsSurvivingCoreIntoSessionClosing(t *testing.T) {
	t.Parallel()

	fix := newOfflineFixture(t)
	dummyCore := filepath.Join(fix.base, "bin", "dummy-core")
	digest := writeFakeBinary(t, dummyCore, 0o755, []byte("#!/bin/sh\nexec /bin/sleep 30\n"))
	dummyExec := ResolvedExecutable{Path: dummyCore, SHA256: digest}

	nativeHomeRoot, err := ports.NewAnchoredRoot(fix.nativeHome)
	if err != nil {
		t.Fatal(err)
	}
	var stopCalls atomic.Int32
	sess, err := NewSession(SessionOptions{
		Clock:                    runtimeadapter.SystemClock{},
		LaunchBuilder:            fix.launchBuilder,
		NativeHome:               nativeHomeRoot,
		BaseDir:                  filepath.Join(fix.base, "mgh-start-abort"),
		HasInheritedSocket:       true,
		HasAmbientTerminalSocket: true,
		DaemonStartupTimeout:     150 * time.Millisecond,
		TeardownTimeout:          600 * time.Millisecond,
		DisableWatchdog:          true,
		DisableStaleReaper:       true,
		fakeExecutable:           &dummyExec,
		stopTrackedProc: func(proc trackedProcess, dl time.Time) error {
			if stopCalls.Add(1) == 1 {
				return fmt.Errorf("simulated stubborn core pid %d", proc.PID)
			}
			return ensureTrackedProcessGroupStopped(proc, dl)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sess.Close(context.Background()) })

	_, startErr := sess.RuntimeIdentity(context.Background())
	if startErr == nil || !strings.Contains(startErr.Error(), "simulated stubborn core") {
		t.Fatalf("RuntimeIdentity abort err = %v, want wrapped stubborn core error", startErr)
	}
	sessionDir := sess.SessionDir()
	corePID := sess.CorePID()
	if sessionDir == "" || corePID <= 1 {
		t.Fatalf("expected retained sessionDir and corePID after failed abort, got dir=%q pid=%d", sessionDir, corePID)
	}
	if _, statErr := os.Lstat(filepath.Join(sessionDir, ownerLockFileName)); statErr != nil {
		t.Fatalf("expected owner.lock.json retained after failed startup abort: %v", statErr)
	}

	// Session must be in sessionClosing and refuse new runs instead of leaking a second daemon.
	if _, retryStartErr := sess.RuntimeIdentity(context.Background()); !errors.Is(retryStartErr, ErrSessionClosed) {
		t.Fatalf("RuntimeIdentity after retained startup abort = %v, want ErrSessionClosed", retryStartErr)
	}

	// Session.Close() retries teardown, kills core to ESRCH, and removes sessionDir.
	if closeErr := sess.Close(context.Background()); closeErr != nil {
		t.Fatalf("Close retry after retained startup abort: %v", closeErr)
	}
	if killErr := unix.Kill(-corePID, 0); !errors.Is(killErr, unix.ESRCH) {
		t.Fatalf("core pid %d survived Close retry: %v", corePID, killErr)
	}
	if _, statErr := os.Lstat(sessionDir); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("sessionDir %s survived Close retry: %v", sessionDir, statErr)
	}
}

func TestOfflineCloseVerifiesTrackedPaneSurvivorsAndRetainsSessionDir(t *testing.T) {
	t.Parallel()

	fix := newOfflineFixture(t)
	srv := startFakeHerdrServer(t)
	inspector := newFakeProcessInspector()
	// Stubborn session survivor keeps pane t1 (pid 50001) tracked after RunTerminal teardown fails.
	inspector.killZeroErr[50001] = unix.ESRCH
	inspector.sessMembers[50001] = []int{59101}
	sess := fix.newFakeSession(t, srv, inspector)

	srv.onWait = func(s *fakeHerdrServer, params WaitParams, _ net.Conn) (WaitResult, *RPCError, bool) {
		s.mu.Lock()
		defer s.mu.Unlock()
		term := s.terminals[params.Terminal]
		term.Turn = 1
		term.Status = &TerminalStatus{State: "done"}
		st := "done"
		return WaitResult{Terminal: params.Terminal, Ended: true, Reason: "status", Status: &st, Turn: 1}, nil, false
	}

	req, launchDir := fix.newTerminalRequest(t, []byte("review prompt body\n"), "work", true, 2*time.Second, 5*time.Second, 0, nil, true)
	_, err := sess.RunTerminal(context.Background(), req)
	assertLaunchDirClosed(t, launchDir)
	var procErr *ports.ProcessExecutionError
	if !errors.As(err, &procErr) || procErr.PrimaryCause() != domain.DiagnosticCauseProcessGroupCleanupFailed {
		t.Fatalf("RunTerminal survivor err = %v, want ProcessExecutionError(%s)", err, domain.DiagnosticCauseProcessGroupCleanupFailed)
	}
	sessionDir := sess.SessionDir()
	if sessionDir == "" {
		t.Fatal("expected non-empty sessionDir")
	}

	// Close #1 MUST fail closed on the surviving tracked pane and retain sessionDir.
	closeErr1 := sess.Close(context.Background())
	if closeErr1 == nil || !strings.Contains(closeErr1.Error(), "pane t1") {
		t.Fatalf("Close #1 err = %v, want error citing surviving pane t1", closeErr1)
	}
	if _, statErr := os.Lstat(sessionDir); statErr != nil {
		t.Fatalf("sessionDir was removed despite surviving tracked pane: %v", statErr)
	}

	// Once the tracked pane survivor exits, Close #2 proves absence and removes sessionDir.
	inspector.mu.Lock()
	delete(inspector.sessMembers, 50001)
	inspector.mu.Unlock()

	if closeErr2 := sess.Close(context.Background()); closeErr2 != nil {
		t.Fatalf("Close #2 after tracked pane survivor exited: %v", closeErr2)
	}
	if _, statErr := os.Lstat(sessionDir); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("sessionDir survived successful Close #2: %v", statErr)
	}
}

func TestOfflineDrainAndRemoveHonorTeardownDeadlineOnStalledRPC(t *testing.T) {
	t.Parallel()

	t.Run("DrainLabeledPanes bounds stalled terminal.list by teardownTimeout", func(t *testing.T) {
		fix := newOfflineFixture(t)
		srv := startFakeHerdrServer(t)
		nativeHomeRoot, err := ports.NewAnchoredRoot(fix.nativeHome)
		if err != nil {
			t.Fatal(err)
		}
		sess, err := NewSession(SessionOptions{
			Clock:                    runtimeadapter.SystemClock{},
			LaunchBuilder:            fix.launchBuilder,
			NativeHome:               nativeHomeRoot,
			BaseDir:                  filepath.Join(fix.base, "mgh-drain-stall"),
			HasInheritedSocket:       true,
			HasAmbientTerminalSocket: true,
			TeardownTimeout:          200 * time.Millisecond,
			DisableWatchdog:          true,
			DisableStaleReaper:       true,
			fakeSocketPath:           srv.sockPath,
			fakeExecutable:           &fix.fakeExec,
			inspector:                newFakeProcessInspector(),
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = sess.Close(context.Background()) })

		if _, err := sess.RuntimeIdentity(context.Background()); err != nil {
			t.Fatal(err)
		}

		release := make(chan struct{})
		t.Cleanup(func() { close(release) })
		srv.onList = func(_ *fakeHerdrServer, _ ListParams) (ListResult, *RPCError, bool) {
			<-release
			return ListResult{}, nil, true
		}

		start := time.Now()
		drainErr := sess.DrainLabeledPanes(context.Background(), "mulgae_registry", "gen-stall")
		elapsed := time.Since(start)
		if !errors.Is(drainErr, context.DeadlineExceeded) {
			t.Fatalf("DrainLabeledPanes(stalled list) err = %v, want context.DeadlineExceeded", drainErr)
		}
		if elapsed > 2*time.Second {
			t.Fatalf("DrainLabeledPanes waited %v instead of honoring 200ms teardownTimeout", elapsed)
		}
	})

	t.Run("removePaneWithRetry bounds stalled terminal.rm by deadline", func(t *testing.T) {
		srv := startFakeHerdrServer(t)
		release := make(chan struct{})
		t.Cleanup(func() { close(release) })
		srv.onRM = func(_ *fakeHerdrServer, _ string) (RemoveResult, *RPCError) {
			<-release
			return RemoveResult{}, nil
		}

		client, err := NewRPCClient(srv.sockPath, 30*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		rmErr := removePaneWithRetry(context.Background(), client, "t1", time.Now().Add(200*time.Millisecond), nil)
		elapsed := time.Since(start)
		if !errors.Is(rmErr, context.DeadlineExceeded) {
			t.Fatalf("removePaneWithRetry(stalled rm) err = %v, want context.DeadlineExceeded", rmErr)
		}
		if elapsed > 2*time.Second {
			t.Fatalf("removePaneWithRetry waited %v instead of honoring 200ms deadline", elapsed)
		}
	})
}

func TestOfflineSendInitialInputContradictedBlockedOrFinishedFailsClosed(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name         string
		sendErrKind  string
		refreshState string
	}{
		{name: "blocked send contradicted by live idle", sendErrKind: "blocked", refreshState: "idle"},
		{name: "finished send contradicted by live done", sendErrKind: "finished", refreshState: "done"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fix := newOfflineFixture(t)
			srv := startFakeHerdrServer(t)
			sess := fix.newFakeSession(t, srv, newFakeProcessInspector())

			srv.onSend = func(_ *fakeHerdrServer, _ SendParams) (SendResult, *RPCError) {
				return SendResult{}, &RPCError{Code: -32000, Message: tc.sendErrKind, Kind: tc.sendErrKind}
			}
			srv.onGet = func(s *fakeHerdrServer, addr string, _ net.Conn) (Terminal, *RPCError, bool) {
				s.mu.Lock()
				defer s.mu.Unlock()
				term := s.terminals[addr]
				term.State = "live"
				term.Status = &TerminalStatus{State: tc.refreshState}
				return *term, nil, false
			}

			req, launchDir := fix.newTerminalRequest(t, []byte("review prompt body\n"), "work", true, 2*time.Second, 5*time.Second, 0, nil, true)
			_, err := sess.RunTerminal(context.Background(), req)
			assertLaunchDirClosed(t, launchDir)
			var procErr *ports.ProcessExecutionError
			if !errors.As(err, &procErr) || procErr.PrimaryCause() != domain.DiagnosticCauseProviderProcessWaitFailed {
				t.Fatalf("%s err = %v, want ProcessExecutionError(%s)", tc.name, err, domain.DiagnosticCauseProviderProcessWaitFailed)
			}
		})
	}
}

func TestOfflineCloseTrackedPaneCompletenessAndDiscovery(t *testing.T) {
	t.Parallel()

	t.Run("untracked finished pane failing DrainLabeledPanes is retained for Session.Close", func(t *testing.T) {
		fix := newOfflineFixture(t)
		srv := startFakeHerdrServer(t)
		inspector := newFakeProcessInspector()
		sess := fix.newFakeSession(t, srv, inspector)

		if _, err := sess.RuntimeIdentity(context.Background()); err != nil {
			t.Fatal(err)
		}

		pid := uint32(57001)
		srv.mu.Lock()
		srv.terminals["t-untracked-fin"] = &Terminal{
			Address: "t-untracked-fin",
			State:   "finished",
			PID:     &pid,
			Labels:  map[string]string{"mulgae_registry": "gen-fin-retain"},
		}
		srv.mu.Unlock()
		inspector.mu.Lock()
		inspector.killZeroErr[int(pid)] = nil
		inspector.mu.Unlock()

		if err := sess.DrainLabeledPanes(context.Background(), "mulgae_registry", "gen-fin-retain"); err == nil {
			t.Fatal("DrainLabeledPanes succeeded despite surviving untracked finished pane")
		}

		// Even if the daemon later drops t-untracked-fin from terminal.list,
		// Session.Close() MUST still fail closed because DrainLabeledPanes retained it!
		srv.mu.Lock()
		delete(srv.terminals, "t-untracked-fin")
		srv.mu.Unlock()

		sessionDir := sess.SessionDir()
		closeErr1 := sess.Close(context.Background())
		if closeErr1 == nil || !strings.Contains(closeErr1.Error(), "pane t-untracked-fin") {
			t.Fatalf("Close #1 err = %v, want failure citing retained pane t-untracked-fin", closeErr1)
		}
		if _, statErr := os.Lstat(sessionDir); statErr != nil {
			t.Fatalf("sessionDir was removed despite retained pane survivor: %v", statErr)
		}

		inspector.mu.Lock()
		inspector.killZeroErr[int(pid)] = unix.ESRCH
		inspector.mu.Unlock()
		if closeErr2 := sess.Close(context.Background()); closeErr2 != nil {
			t.Fatalf("Close #2 after survivor cleared: %v", closeErr2)
		}
		if _, statErr := os.Lstat(sessionDir); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("sessionDir survived Close #2: %v", statErr)
		}
	})

	t.Run("performClose discovers untracked daemon-known pane via TerminalList and verifies absence", func(t *testing.T) {
		fix := newOfflineFixture(t)
		srv := startFakeHerdrServer(t)
		inspector := newFakeProcessInspector()
		sess := fix.newFakeSession(t, srv, inspector)

		if _, err := sess.RuntimeIdentity(context.Background()); err != nil {
			t.Fatal(err)
		}

		// Inject a daemon-known live pane never tracked on Session.
		pid := uint32(57002)
		srv.mu.Lock()
		srv.terminals["t-daemon-only"] = &Terminal{
			Address: "t-daemon-only",
			State:   "live",
			PID:     &pid,
		}
		srv.mu.Unlock()
		inspector.mu.Lock()
		inspector.killZeroErr[int(pid)] = nil
		inspector.mu.Unlock()

		sessionDir := sess.SessionDir()
		closeErr1 := sess.Close(context.Background())
		if closeErr1 == nil || !strings.Contains(closeErr1.Error(), "pane t-daemon-only") {
			t.Fatalf("Close #1 err = %v, want failure citing discovered pane t-daemon-only", closeErr1)
		}
		if _, statErr := os.Lstat(sessionDir); statErr != nil {
			t.Fatalf("sessionDir removed despite discovered surviving pane: %v", statErr)
		}

		// Delete t-daemon-only from srv.terminals while survivor STILL persists:
		// Close #2 MUST still fail closed because Close #1 merged it back into s.trackedPanes!
		srv.mu.Lock()
		delete(srv.terminals, "t-daemon-only")
		srv.mu.Unlock()

		closeErr2 := sess.Close(context.Background())
		if closeErr2 == nil || !strings.Contains(closeErr2.Error(), "pane t-daemon-only") {
			t.Fatalf("Close #2 err = %v, want failure citing merged-back pane t-daemon-only", closeErr2)
		}
		if _, statErr := os.Lstat(sessionDir); statErr != nil {
			t.Fatalf("sessionDir removed despite merged-back surviving pane: %v", statErr)
		}

		// Only once the survivor reaches ESRCH may Close #3 succeed and remove sessionDir.
		inspector.mu.Lock()
		inspector.killZeroErr[int(pid)] = unix.ESRCH
		inspector.mu.Unlock()

		if closeErr3 := sess.Close(context.Background()); closeErr3 != nil {
			t.Fatalf("Close #3 after discovered pane cleared: %v", closeErr3)
		}
		if _, statErr := os.Lstat(sessionDir); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("sessionDir survived Close #3: %v", statErr)
		}
	})

	t.Run("late-added tracked pane during Close prevents premature sessionClosed and dir removal", func(t *testing.T) {
		fix := newOfflineFixture(t)
		srv := startFakeHerdrServer(t)
		inspector := newFakeProcessInspector()
		sess := fix.newFakeSession(t, srv, inspector)

		if _, err := sess.RuntimeIdentity(context.Background()); err != nil {
			t.Fatal(err)
		}

		latePID := 57003
		inspector.mu.Lock()
		inspector.killZeroErr[latePID] = nil // stubborn until cleared
		inspector.mu.Unlock()

		// Inject a late tracked pane while performClose is executing (after Close
		// took its initial s.trackedPanes snapshot!).
		var injected atomic.Bool
		srv.onList = func(_ *fakeHerdrServer, _ ListParams) (ListResult, *RPCError, bool) {
			if injected.CompareAndSwap(false, true) {
				sess.recordTrackedPane("t-late", trackedPane{PID: latePID, SID: latePID})
			}
			return ListResult{}, nil, false
		}

		sessionDir := sess.SessionDir()
		closeErr1 := sess.Close(context.Background())
		if closeErr1 == nil || !strings.Contains(closeErr1.Error(), "pane t-late") {
			t.Fatalf("Close #1 err = %v, want failure citing late-added pane t-late", closeErr1)
		}
		if _, statErr := os.Lstat(sessionDir); statErr != nil {
			t.Fatalf("sessionDir was prematurely removed despite late-added tracked pane: %v", statErr)
		}

		inspector.mu.Lock()
		inspector.killZeroErr[latePID] = unix.ESRCH
		inspector.mu.Unlock()
		if closeErr2 := sess.Close(context.Background()); closeErr2 != nil {
			t.Fatalf("Close #2 after late pane cleared: %v", closeErr2)
		}
		if _, statErr := os.Lstat(sessionDir); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("sessionDir survived Close #2: %v", statErr)
		}
	})
}

func TestOfflinePreCreationStartTimeFailsClosedWithoutSignaling(t *testing.T) {
	t.Parallel()

	fix := newOfflineFixture(t)
	srv := startFakeHerdrServer(t)
	inspector := newFakeProcessInspector()
	sess := fix.newFakeSession(t, srv, inspector)

	created := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	preExistingStart := created.Add(-30 * time.Second)
	pid := 57101

	inspector.mu.Lock()
	inspector.killZeroErr[pid] = nil
	inspector.procInfo[pid] = processInfo{
		Exists:    true,
		StartSec:  preExistingStart.Unix(),
		StartUsec: 0,
		PGID:      pid,
	}
	inspector.pgrpMembers[pid] = []int{pid}
	inspector.sessMembers[pid] = []int{pid}
	inspector.mu.Unlock()

	pane := trackedPane{
		PID:       pid,
		SID:       pid,
		CreatedMS: uint64(created.UnixMilli()),
	}
	escalated, err := sess.verifyPaneProcessGroupAndSessionAbsent(pane, time.Now().Add(200*time.Millisecond), true, 0)
	if err == nil || !strings.Contains(err.Error(), "precedes pane created_ms") {
		t.Fatalf("verifyPaneProcessGroupAndSessionAbsent(pre-creation PID) = (escalated=%t, err=%v), want fail-closed pre-creation error", escalated, err)
	}
	if escalated {
		t.Fatal("pre-creation PID must fail closed WITHOUT escalating")
	}
	inspector.mu.Lock()
	kills := append([]int(nil), inspector.killCalls...)
	pidKills := append([]int(nil), inspector.pidKillCalls...)
	inspector.mu.Unlock()
	if len(kills) != 0 || len(pidKills) != 0 {
		t.Fatalf("pre-creation PID must never be signaled! killCalls=%v pidKillCalls=%v", kills, pidKills)
	}
}

func TestOfflineNoInitialInputOSCPaneWorkingPastStartupTimeoutCompletes(t *testing.T) {
	t.Parallel()

	fix := newOfflineFixture(t)
	srv := startFakeHerdrServer(t)
	sess := fix.newFakeSession(t, srv, newFakeProcessInspector())

	srv.onRun = func(s *fakeHerdrServer, params RunParams) (Terminal, *RPCError) {
		s.mu.Lock()
		defer s.mu.Unlock()
		pid := uint32(57201)
		term := &Terminal{
			Address:  "t-noinput",
			Argv:     params.Argv,
			CWD:      params.CWD,
			Labels:   params.Labels,
			State:    "live",
			PID:      &pid,
			Reported: true,
			Status:   &TerminalStatus{State: "working"},
			Screen:   "exact",
		}
		s.terminals["t-noinput"] = term
		return *term, nil
	}

	var waitCount atomic.Int32
	srv.onWait = func(s *fakeHerdrServer, params WaitParams, _ net.Conn) (WaitResult, *RPCError, bool) {
		// Sleep 260ms — well past StartupTimeout (120ms) — while remaining well within TotalTimeout (3s).
		if waitCount.Add(1) == 1 {
			time.Sleep(260 * time.Millisecond)
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		term := s.terminals[params.Terminal]
		term.Turn = 1
		term.Status = &TerminalStatus{State: "done"}
		st := "done"
		return WaitResult{Terminal: params.Terminal, Ended: true, Reason: "status", Status: &st, Turn: 1}, nil, false
	}

	// Empty InitialInput with RequireOSCReporting=true, tight StartupTimeout (120ms), generous TotalTimeout (3s).
	req, launchDir := fix.newTerminalRequest(t, []byte("review prompt body\n"), "", true, 120*time.Millisecond, 3*time.Second, 50*time.Millisecond, nil, true)
	obs, err := sess.RunTerminal(context.Background(), req)
	assertLaunchDirClosed(t, launchDir)
	if err != nil {
		t.Fatalf("RunTerminal(no initial input working past startupTimeout): %v", err)
	}
	if status, _ := obs.ProgramStatus(); status != ports.TerminalProgramStatusDone {
		t.Fatalf("ProgramStatus = %q, want done", status)
	}
	if term := obs.ProcessObservation().Termination(); term == ports.ProcessTerminationTimedOut {
		t.Fatalf("Termination = %q, must not time out at startupTimeout once working", term)
	}
	if !obs.ProcessObservation().TerminalSessionCompleted() {
		t.Fatal("expected TerminalSessionCompleted() == true")
	}
}

func TestOfflineFilterPaneEraMembersSkipsExitedMembersWithoutSpuriousEscalation(t *testing.T) {
	t.Parallel()

	fix := newOfflineFixture(t)
	srv := startFakeHerdrServer(t)
	inspector := newFakeProcessInspector()
	sess := fix.newFakeSession(t, srv, inspector)

	created := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	pid := uint32(57301)
	exitedChildPID := 57302

	// Simulate pgrp/session snapshot returning exitedChildPID whose subsequent
	// processInfo reports Exists == false (already exited cleanly).
	inspector.mu.Lock()
	inspector.killZeroErr[int(pid)] = unix.ESRCH
	inspector.pgrpMembers[int(pid)] = []int{exitedChildPID}
	inspector.sessMembers[int(pid)] = []int{exitedChildPID}
	inspector.procInfo[exitedChildPID] = processInfo{Exists: false}
	inspector.mu.Unlock()

	srv.onRun = func(s *fakeHerdrServer, params RunParams) (Terminal, *RPCError) {
		s.mu.Lock()
		defer s.mu.Unlock()
		exitZero := int32(0)
		term := &Terminal{
			Address:   "t-exited-member",
			Argv:      params.Argv,
			CWD:       params.CWD,
			Labels:    params.Labels,
			State:     "finished",
			PID:       &pid,
			ExitCode:  &exitZero,
			CreatedMS: uint64(created.UnixMilli()),
			Reported:  true,
			Status:    &TerminalStatus{State: "done"},
			Turn:      1,
			Screen:    "exact",
		}
		s.terminals["t-exited-member"] = term
		return *term, nil
	}

	req, launchDir := fix.newTerminalRequest(t, []byte("review prompt body\n"), "", true, 2*time.Second, 5*time.Second, 0, nil, true)
	obs, err := sess.RunTerminal(context.Background(), req)
	assertLaunchDirClosed(t, launchDir)
	if err != nil {
		t.Fatalf("RunTerminal(exited member): %v", err)
	}
	if term := obs.ProcessObservation().Termination(); term != ports.ProcessTerminationExited {
		t.Fatalf("Termination = %q, want %q (must not spuriously escalate to residual_process_group)", term, ports.ProcessTerminationExited)
	}
	inspector.mu.Lock()
	kills := append([]int(nil), inspector.killCalls...)
	pidKills := append([]int(nil), inspector.pidKillCalls...)
	inspector.mu.Unlock()
	if len(kills) != 0 || len(pidKills) != 0 {
		t.Fatalf("already-exited member must not trigger SIGKILL escalation: killCalls=%v pidKillCalls=%v", kills, pidKills)
	}
}

func TestOfflineNoInitialInputUnreportedToWorkingAtStartupTimeoutCompletes(t *testing.T) {
	t.Parallel()

	fix := newOfflineFixture(t)
	srv := startFakeHerdrServer(t)
	sess := fix.newFakeSession(t, srv, newFakeProcessInspector())

	srv.onRun = func(s *fakeHerdrServer, params RunParams) (Terminal, *RPCError) {
		s.mu.Lock()
		defer s.mu.Unlock()
		pid := uint32(57401)
		term := &Terminal{
			Address:  "t-unreported-boundary",
			Argv:     params.Argv,
			CWD:      params.CWD,
			Labels:   params.Labels,
			State:    "live",
			PID:      &pid,
			Reported: false,
			Screen:   "exact",
		}
		s.terminals["t-unreported-boundary"] = term
		return *term, nil
	}

	var waitCalls atomic.Int32
	srv.onWait = func(s *fakeHerdrServer, params WaitParams, _ net.Conn) (WaitResult, *RPCError, bool) {
		n := waitCalls.Add(1)
		if n == 1 {
			// Return timeout RIGHT past StartupTimeout (120ms) after transitioning
			// the pane from Reported:false to Reported:true, Status:"working".
			time.Sleep(150 * time.Millisecond)
			s.mu.Lock()
			term := s.terminals[params.Terminal]
			term.Reported = true
			term.Status = &TerminalStatus{State: "working"}
			s.mu.Unlock()
			st := "working"
			return WaitResult{Terminal: params.Terminal, Ended: false, Reason: "timeout", Status: &st, Turn: 0}, nil, false
		}
		time.Sleep(40 * time.Millisecond)
		s.mu.Lock()
		term := s.terminals[params.Terminal]
		term.Turn = 1
		term.Status = &TerminalStatus{State: "done"}
		s.mu.Unlock()
		st := "done"
		return WaitResult{Terminal: params.Terminal, Ended: true, Reason: "status", Status: &st, Turn: 1}, nil, false
	}

	// CheckInInterval (500ms) >= StartupTimeout (120ms), empty InitialInput, generous TotalTimeout (3s).
	req, launchDir := fix.newTerminalRequest(t, []byte("review prompt body\n"), "", true, 120*time.Millisecond, 3*time.Second, 500*time.Millisecond, nil, true)
	obs, err := sess.RunTerminal(context.Background(), req)
	assertLaunchDirClosed(t, launchDir)
	if err != nil {
		t.Fatalf("RunTerminal(unreported->working at StartupTimeout): %v", err)
	}
	if status, _ := obs.ProgramStatus(); status != ports.TerminalProgramStatusDone {
		t.Fatalf("ProgramStatus = %q, want done", status)
	}
	if term := obs.ProcessObservation().Termination(); term == ports.ProcessTerminationTimedOut {
		t.Fatalf("Termination = %q, must switch to totalDeadline when working reported at StartupTimeout", term)
	}
	if !obs.ProcessObservation().TerminalSessionCompleted() {
		t.Fatal("expected TerminalSessionCompleted() == true")
	}
}

func TestOfflineClosePersistsConcurrentRefreshHoldersUpdateOnFailedClose(t *testing.T) {
	t.Parallel()

	fix := newOfflineFixture(t)
	srv := startFakeHerdrServer(t)

	holderChild := exec.Command("/bin/sleep", "30")
	holderChild.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := holderChild.Start(); err != nil {
		t.Fatal(err)
	}
	holderReaped := make(chan struct{})
	go func() {
		_ = holderChild.Wait()
		close(holderReaped)
	}()
	t.Cleanup(func() {
		select {
		case <-holderReaped:
			return
		default:
			_ = unix.Kill(-holderChild.Process.Pid, unix.SIGKILL)
			<-holderReaped
		}
	})
	holderPID := holderChild.Process.Pid

	baseDir := filepath.Join(fix.base, "mgh-persist-concurrent")
	sessionID := "abcdef0123456789"
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

	// Configure Session with fakeSocketPath == "" so production persistence runs,
	// and fail stopTrackedProc on Close so Close() returns an error while
	// retaining sessionDir.
	sess, err := NewSession(SessionOptions{
		Clock:                    runtimeadapter.SystemClock{},
		LaunchBuilder:            fix.launchBuilder,
		NativeHome:               nativeHomeRoot,
		BaseDir:                  baseDir,
		HasInheritedSocket:       true,
		HasAmbientTerminalSocket: true,
		TeardownTimeout:          3 * time.Second,
		DisableWatchdog:          true,
		DisableStaleReaper:       true,
		inspector:                newFakeProcessInspector(),
		stopTrackedProc: func(proc trackedProcess, _ time.Time) error {
			return fmt.Errorf("simulated stubborn proc %d", proc.PID)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	sess.mu.Lock()
	sess.state = sessionRunning
	sess.sessionID = sessionID
	sess.sessionDir = sessionDir
	sess.socketPath = srv.sockPath
	sess.ownerProc = trackedProcess{PID: ownerPID, StartSec: ownerSec, StartUsec: ownerUsec}
	sess.coreProc = trackedProcess{PID: 58001, StartSec: 1, StartUsec: 1}
	sess.rpc = client
	sess.mu.Unlock()

	// Synchronously run refreshHolders from inside performClose's ServerStatus
	// handler (call #1, while closeInFlight == true). refreshHolders receives
	// holderPID on call #2, updates s.holders + s.holdersGen, and skips writing
	// owner.lock.json because closeInFlight == true; then call #1 returns an
	// empty status to performClose so ONLY the failed-Close persistence loop
	// can durably write holderPID to owner.lock.json.
	var statusCalls atomic.Int32
	var refreshRecordedHolder atomic.Bool
	var wroteWhileClosing atomic.Bool
	srv.onStatus = func(_ *fakeHerdrServer) (StatusResult, *RPCError) {
		n := statusCalls.Add(1)
		if n == 1 {
			sess.refreshHolders(context.Background())
			refreshRecordedHolder.Store(len(sess.HolderPIDs()) > 0)
			if rawMid, readErr := os.ReadFile(filepath.Join(sessionDir, ownerLockFileName)); readErr == nil {
				var mid ownerLockRecord
				if json.Unmarshal(rawMid, &mid) == nil && len(mid.Holders) > 0 {
					wroteWhileClosing.Store(true)
				}
			}
			return StatusResult{Core: CoreInfo{ID: "c"}, Version: "0.1.20"}, nil
		}
		h := HolderInfo{PID: uint32(holderPID), Instance: "h-concurrent", Current: true}
		return StatusResult{Core: CoreInfo{ID: "c"}, Version: "0.1.20", Holder: &h, Holders: []HolderInfo{h}}, nil
	}

	closeErr := sess.Close(context.Background())
	if closeErr == nil {
		t.Fatal("expected Close() to fail on stubborn coreProc")
	}
	if got := statusCalls.Load(); got != 2 {
		t.Fatalf("statusCalls = %d, want 2 (performClose + synchronous refreshHolders)", got)
	}
	if !refreshRecordedHolder.Load() {
		t.Fatal("refreshHolders did not record holderPID while closeInFlight == true")
	}
	if wroteWhileClosing.Load() {
		t.Fatal("refreshHolders unexpectedly wrote owner.lock.json while closeInFlight == true")
	}

	// Verify owner.lock.json now durably contains holderPID after failed Close!
	rawLock, err := os.ReadFile(filepath.Join(sessionDir, ownerLockFileName))
	if err != nil {
		t.Fatalf("read owner.lock.json after failed Close: %v", err)
	}
	var rec ownerLockRecord
	if err := json.Unmarshal(rawLock, &rec); err != nil {
		t.Fatalf("unmarshal owner.lock.json: %v", err)
	}
	found := false
	for _, h := range rec.Holders {
		if h.PID == holderPID && hasStartTime(h.StartSec, h.StartUsec) {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("holder PID %d updated by refreshHolders during closeInFlight was NOT persisted to owner.lock.json: %+v", holderPID, rec.Holders)
	}
}

func TestRunTerminalUnsafeExecutableReturnsSecurityProcessExecutionError(t *testing.T) {
	fix := newOfflineFixture(t)
	unsafeBin := filepath.Join(fix.base, "unsafe-herdr-core")
	if err := os.WriteFile(unsafeBin, []byte("#!/bin/sh\nexit 0\n"), 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(unsafeBin, 0o777); err != nil {
		t.Fatal(err)
	}
	t.Setenv(EnvHerdrCoreBin, unsafeBin)

	nativeHomeRoot, err := ports.NewAnchoredRoot(fix.nativeHome)
	if err != nil {
		t.Fatal(err)
	}
	sess, err := NewSession(SessionOptions{
		Clock:                    runtimeadapter.SystemClock{},
		LaunchBuilder:            fix.launchBuilder,
		NativeHome:               nativeHomeRoot,
		BaseDir:                  filepath.Join(fix.base, "mgh-unsafe-exec"),
		HasInheritedSocket:       true,
		HasAmbientTerminalSocket: true,
		TeardownTimeout:          time.Second,
		DisableWatchdog:          true,
		DisableStaleReaper:       true,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sess.Close(context.Background()) })

	req, launchDir := fix.newTerminalRequest(t, []byte("review prompt\n"), "work", true, 2*time.Second, 5*time.Second, 0, nil, true)
	_, err = sess.RunTerminal(context.Background(), req)
	assertLaunchDirClosed(t, launchDir)
	if !errors.Is(err, ErrUnsafeExecutable) {
		t.Fatalf("RunTerminal(unsafe binary) err = %v, want wrap of ErrUnsafeExecutable", err)
	}
	var procErr *ports.ProcessExecutionError
	if !errors.As(err, &procErr) || procErr.PrimaryCause() != domain.DiagnosticCauseTransportVerificationFailed {
		t.Fatalf("RunTerminal(unsafe binary) err = %T (%v), want *ports.ProcessExecutionError(%s)", err, err, domain.DiagnosticCauseTransportVerificationFailed)
	}
}
