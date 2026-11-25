// The offline integration fixture implements the herdr-core RPC operations
// needed by Mulgae and runs the actual argv trampoline in a child session.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/irootkernel/mulgae/internal/adapters/herdr"
)

type pane struct {
	terminal herdr.Terminal
	stdin    io.WriteCloser
	done     chan struct{}
}

type daemon struct {
	mu       sync.Mutex
	listener net.Listener
	panes    map[string]*pane
	next     int
}

type request struct {
	ID     json.RawMessage `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
}

var observerSocket string

func main() {
	if len(os.Args) != 2 || os.Args[1] != "serve" {
		os.Exit(2)
	}
	listener, err := net.Listen("unix", os.Getenv("HC_SOCKET"))
	if err != nil {
		panic(err)
	}
	d := daemon{listener: listener, panes: make(map[string]*pane)}
	for {
		connection, err := listener.Accept()
		if err != nil {
			d.stopPanes()
			return
		}
		go d.handle(connection)
	}
}

func (d *daemon) handle(connection net.Conn) {
	defer connection.Close()
	var req request
	if json.NewDecoder(connection).Decode(&req) != nil {
		return
	}
	result, err := d.call(req)
	wire := map[string]any{"jsonrpc": "2.0", "id": req.ID}
	if err != nil {
		wire["error"] = map[string]any{"code": -32000, "message": err.Error(), "data": map[string]string{"kind": err.Error()}}
	} else {
		wire["result"] = result
	}
	_ = json.NewEncoder(connection).Encode(wire)
	if req.Method == "server.stop" {
		_ = d.listener.Close()
	}
}

func (d *daemon) call(req request) (any, error) {
	switch req.Method {
	case "hello":
		return herdr.HelloResult{Generation: 1, Version: "0.1.0", Core: herdr.CoreInfo{ID: "hc", Name: "herdr-core"}, Methods: []string{
			"hello", "server.status", "server.stop", "terminal.run", "terminal.list", "terminal.get", "terminal.kill",
			"terminal.rm", "terminal.read", "terminal.send", "terminal.wait",
		}}, nil
	case "server.status":
		return herdr.StatusResult{Version: "0.1.0", PID: uint32(os.Getpid())}, nil
	case "server.stop":
		return herdr.StopResult{Stopped: true}, nil
	case "terminal.run":
		var params herdr.RunParams
		if err := json.Unmarshal(req.Params, &params); err != nil {
			return nil, err
		}
		return d.run(params)
	case "terminal.list":
		var params herdr.ListParams
		if err := json.Unmarshal(req.Params, &params); err != nil {
			return nil, err
		}
		d.mu.Lock()
		defer d.mu.Unlock()
		terminals := []herdr.Terminal{}
		for _, p := range d.panes {
			matches := true
			for key, value := range params.Labels {
				matches = matches && p.terminal.Labels[key] == value
			}
			if matches && (params.All || p.terminal.State != "finished") {
				terminals = append(terminals, p.terminal)
			}
		}
		return herdr.ListResult{Terminals: terminals}, nil
	}
	var params herdr.SendParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return nil, err
	}
	d.mu.Lock()
	p, ok := d.panes[params.Terminal]
	if !ok {
		d.mu.Unlock()
		return nil, fmt.Errorf("not_found")
	}
	terminal := p.terminal
	d.mu.Unlock()
	switch req.Method {
	case "terminal.get":
		return terminal, nil
	case "terminal.send":
		if terminal.State == "finished" {
			return nil, fmt.Errorf("finished")
		}
		if params.If == "idle" && (terminal.Status == nil || terminal.Status.State != "idle") {
			return nil, fmt.Errorf("status_mismatch")
		}
		if _, err := fmt.Fprintln(p.stdin, params.Text); err != nil {
			return nil, err
		}
		return herdr.SendResult{Turn: terminal.Turn + 1}, nil
	case "terminal.wait":
		select {
		case <-p.done:
		case <-time.After(15 * time.Millisecond):
		}
		d.mu.Lock()
		defer d.mu.Unlock()
		terminal = p.terminal
		reason := "timeout"
		var status *string
		ended := terminal.State == "finished"
		if ended {
			reason = "exit"
		} else if terminal.Status != nil && terminal.Status.State != "working" {
			reason, status = "status", &terminal.Status.State
		}
		return herdr.WaitResult{Terminal: terminal.Address, Ended: ended, Reason: reason, Status: status, Turn: terminal.Turn, ExitCode: terminal.ExitCode, Signal: terminal.Signal, Children: []herdr.WaitResult{}}, nil
	case "terminal.kill":
		if terminal.PID != nil {
			_ = syscall.Kill(-int(*terminal.PID), syscall.SIGHUP)
		}
		select {
		case <-p.done:
		case <-time.After(time.Second):
			return nil, fmt.Errorf("fixture kill deadline")
		}
		d.mu.Lock()
		defer d.mu.Unlock()
		return p.terminal, nil
	case "terminal.rm":
		if terminal.State != "finished" {
			return nil, fmt.Errorf("live")
		}
		d.mu.Lock()
		delete(d.panes, terminal.Address)
		d.mu.Unlock()
		return herdr.RemoveResult{Removed: terminal.Address}, nil
	case "terminal.read":
		return herdr.ReadResult{Text: terminal.Screen, Complete: true, How: "terminal"}, nil
	default:
		return nil, fmt.Errorf("unsupported method %s", req.Method)
	}
}

func (d *daemon) run(params herdr.RunParams) (herdr.Terminal, error) {
	if len(params.Argv) == 0 {
		return herdr.Terminal{}, fmt.Errorf("missing terminal argv")
	}
	d.mu.Lock()
	d.next++
	id := "fixture-" + strconv.Itoa(d.next)
	d.mu.Unlock()
	cmd := exec.Command(params.Argv[0], params.Argv[1:]...)
	cmd.Env = append(os.Environ(), "HC_TERMINAL_ID="+id)
	cmd.Dir = params.CWD
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	master, slave, err := openTerminal()
	if err != nil {
		return herdr.Terminal{}, err
	}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
	started := uint64(time.Now().UnixMilli())
	err = cmd.Start()
	_ = slave.Close()
	if err != nil {
		_ = master.Close()
		return herdr.Terminal{}, err
	}
	d.mu.Lock()
	pid := uint32(cmd.Process.Pid)
	terminal := herdr.Terminal{Address: id, Argv: params.Argv, CWD: params.CWD, State: "running", Labels: params.Labels, PID: &pid, CreatedMS: started}
	p := &pane{terminal: terminal, stdin: master, done: make(chan struct{})}
	d.panes[id] = p
	d.mu.Unlock()

	outputDone := make(chan struct{})
	go func() {
		defer close(outputDone)
		defer master.Close()
		scanner := bufio.NewScanner(master)
		scanner.Buffer(make([]byte, 4096), 4<<20)
		for scanner.Scan() {
			d.ingest(p, scanner.Text())
		}
	}()
	go func() {
		_ = cmd.Wait()
		<-outputDone
		d.mu.Lock()
		defer d.mu.Unlock()
		p.terminal.State, p.terminal.PID = "finished", nil
		if status, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); ok && status.Signaled() {
			sig := int32(status.Signal())
			p.terminal.Signal = &sig
		} else {
			exit := int32(cmd.ProcessState.ExitCode())
			p.terminal.ExitCode = &exit
		}
		when := uint64(time.Now().UnixMilli())
		p.terminal.FinishedMS = &when
		close(p.done)
	}()
	return terminal, nil
}

// openTerminal gives the real launcher one owned controlling PTY.
func openTerminal() (*os.File, *os.File, error) {
	fd, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	master := os.NewFile(uintptr(fd), "fixture PTY")
	fail := func(err error) (*os.File, *os.File, error) {
		_ = master.Close()
		return nil, nil, err
	}
	for _, request := range []uintptr{unix.TIOCPTYGRANT, unix.TIOCPTYUNLK} {
		if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), request, 0); errno != 0 {
			return fail(errno)
		}
	}
	var name [128]byte
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.TIOCPTYGNAME, uintptr(unsafe.Pointer(&name[0]))); errno != 0 {
		return fail(errno)
	}
	path, _, _ := strings.Cut(string(name[:]), "\x00")
	slaveFD, err := unix.Open(path, unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fail(err)
	}
	return master, os.NewFile(uintptr(slaveFD), path), nil
}

func (d *daemon) ingest(p *pane, line string) {
	if raw, ok := strings.CutPrefix(line, "MULGAE_FIXTURE_OBSERVE "); ok {
		reply := "rejected"
		if relayObservation([]byte(raw)) == nil {
			reply = "acknowledged"
		}
		_, _ = fmt.Fprintln(p.stdin, reply)
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	var status herdr.TerminalStatus
	switch line {
	case "MULGAE_FIXTURE_IDLE":
		status.State = "idle"
	case "MULGAE_FIXTURE_WORKING":
		status.State = "working"
	case "MULGAE_FIXTURE_DONE":
		status.State = "done"
		p.terminal.Turn++
	default:
		p.terminal.Screen += line + "\n"
		return
	}
	now := uint64(time.Now().UnixMilli())
	p.terminal.Reported, p.terminal.Status, p.terminal.StatusMS = true, &status, &now
}

// relayObservation connects two test-owned processes outside the pane guard.
func relayObservation(raw []byte) error {
	conn, err := net.DialTimeout("unix", observerSocket, time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return err
	}
	if _, err := conn.Write(append(raw, '\n')); err != nil {
		return err
	}
	var acknowledged bool
	if err := json.NewDecoder(conn).Decode(&acknowledged); err != nil {
		return err
	}
	if !acknowledged {
		return fmt.Errorf("fixture observation refused")
	}
	return nil
}

func (d *daemon) stopPanes() {
	d.mu.Lock()
	panes := make([]*pane, 0, len(d.panes))
	for _, p := range d.panes {
		if p.terminal.PID != nil {
			_ = syscall.Kill(-int(*p.terminal.PID), syscall.SIGKILL)
		}
		panes = append(panes, p)
	}
	d.mu.Unlock()
	for _, p := range panes {
		<-p.done
	}
}
