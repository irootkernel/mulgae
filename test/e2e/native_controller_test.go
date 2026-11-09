//go:build darwin && arm64 && (vm_qualification || live_e2e)

package e2e

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

type vmController struct {
	command *exec.Cmd
	log     *os.File
	stopped bool
}

func vmStartController(t *testing.T, ctx context.Context, binary, home string, environment []string) *vmController {
	t.Helper()
	log, err := os.OpenFile(filepath.Join(home, "qualification-daemon.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(ctx, binary, "daemon", "run", "--root", home)
	command.Env, command.Stdout, command.Stderr = environment, log, log
	if err := command.Start(); err != nil {
		log.Close()
		t.Fatal(err)
	}
	controller := &vmController{command: command, log: log}
	t.Cleanup(func() { controller.stop(t) })
	vmWaitFor(t, ctx, func() bool { _, err := os.Stat(filepath.Join(home, "control.sock")); return err == nil }, "native controller socket")
	return controller
}

func (controller *vmController) stop(t *testing.T) {
	t.Helper()
	if controller == nil || controller.stopped {
		return
	}
	controller.stopped = true
	_ = controller.command.Process.Signal(syscall.SIGTERM)
	done := make(chan error, 1)
	go func() { done <- controller.command.Wait() }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		_ = controller.command.Process.Kill()
		<-done
		t.Error("native controller required forced termination")
	}
	if err := controller.log.Close(); err != nil {
		t.Error(err)
	}
}

func vmWaitFor(t *testing.T, ctx context.Context, ready func() bool, label string) {
	t.Helper()
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	deadline := time.NewTimer(30 * time.Second)
	defer deadline.Stop()
	for {
		if ready() {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal("timed out: " + label)
		case <-deadline.C:
			t.Fatal("fixture condition did not complete within 30 seconds: " + label)
		case <-ticker.C:
		}
	}
}
