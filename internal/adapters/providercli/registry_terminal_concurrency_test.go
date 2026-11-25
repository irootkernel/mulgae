//go:build darwin && arm64

package providercli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	gittargetadapter "github.com/irootkernel/mulgae/internal/adapters/gittarget"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

type managedTerminalCall struct {
	root     string
	complete chan struct{}
}

type managedTerminalBarrier struct {
	fakeTerminalSessionRunner
	t       *testing.T
	started chan managedTerminalCall
}

func (runner *managedTerminalBarrier) RunTerminal(ctx context.Context, req ports.TerminalExecutionRequest) (ports.TerminalExecutionObservation, error) {
	if directory, _, ok := req.Process().LaunchDirectory(); ok {
		defer directory.Close()
	}
	boundary, _ := req.Process().LiveReadOnlyBoundary()
	call := managedTerminalCall{root: boundary.WritableRoot().String(), complete: make(chan struct{})}
	select {
	case runner.started <- call:
	case <-ctx.Done():
		return ports.TerminalExecutionObservation{}, ctx.Err()
	}
	select {
	case <-call.complete:
	case <-ctx.Done():
		return ports.TerminalExecutionObservation{}, ctx.Err()
	}
	t := runner.t
	path := findStagedOutputPath(t, call.root, stagedOutputFilename)
	nonce := extractPromptNonce(t, req.PromptFilePath().String())
	if err := os.WriteFile(path, []byte("fixture report\n"+terminalCompletionNoncePrefix+nonce+"\n"), 0o600); err != nil {
		return ports.TerminalExecutionObservation{}, err
	}
	return makeTerminalSessionObservation(t, &runner.fakeTerminalSessionRunner, req, ports.TerminalExecutionObservationInput{
		ProgramStatus: ports.TerminalProgramStatusDone, TurnCount: 1,
	}, ports.ProcessTerminationExited, 0, true, nil, nil), nil
}

func TestRegistryTerminalConcurrencyAndDrain(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	root := reviewerHomeTestRoot(t)
	project := filepath.Join(root.String(), "source")
	operator := filepath.Join(root.String(), "operator")
	credential := filepath.Join(operator, ".grok")
	for _, dir := range []string{project, operator, credential} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	native, _ := ports.NewAnchoredRoot(operator)
	home, err := OpenReviewerHome(native, []byte("fixture guide"))
	if err != nil {
		t.Fatal(err)
	}
	defer home.Close()
	sourceRoot, _ := ports.NewAnchoredRoot(project)
	credentialRoot, _ := ports.NewAnchoredRoot(credential)
	sourceAdapter, err := gittargetadapter.NewLiveSourceAdapter(gittargetadapter.NewExecRunner(), []ports.AnchoredRoot{credentialRoot})
	if err != nil {
		t.Fatal(err)
	}
	selector, _ := ports.NewLiveSourceSelector(domain.LiveSourceWorkspace, "")
	source, err := sourceAdapter.OpenLiveSource(ctx, sourceRoot, selector)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	execution, err := ports.NewLiveReviewExecution(ctx, source, home, []ports.AnchoredRoot{credentialRoot})
	if err != nil {
		t.Fatal(err)
	}

	terminal := &managedTerminalBarrier{
		fakeTerminalSessionRunner: fakeTerminalSessionRunner{identity: defaultFakeTerminalIdentity(t)},
		t:                         t, started: make(chan managedTerminalCall, 3),
	}
	makeRegistry := func(name string, instances ...string) *Registry {
		factory, err := NewNamespaceFactory(filepath.Join(root.String(), name))
		if err != nil {
			t.Fatal(err)
		}
		definitions := make([]definition, 0, len(instances))
		for _, instance := range instances {
			def := testDefinition(t, FamilyGrok, instance)
			def.timeout = 10 * time.Second
			definitions = append(definitions, def)
		}
		reg, err := newRegistryWithNamespaces(ctx, &countingRunner{}, factory, definitions...)
		if err != nil {
			t.Fatal(err)
		}
		reg.terminalRunner = terminal
		t.Cleanup(func() { _, _ = reg.Close(context.Background()) })
		return reg
	}
	left := makeRegistry("left", "grok-logic", "grok-security")
	right := makeRegistry("right", "grok-logic")
	invocation := func(instance string) ports.ProviderInvocation {
		bound, err := ports.NewProviderInvocationInLiveSource(testInvocation(t, instance), execution)
		if err != nil {
			t.Fatal(err)
		}
		return bound
	}
	run := func(reg *Registry, inv ports.ProviderInvocation) (managedTerminalCall, <-chan error) {
		result := make(chan error, 1)
		go func() {
			observation, err := reg.Observe(ctx, inv)
			if err == nil && observation.Status() != ports.ProviderExecutionStatusSucceeded {
				err = errors.New("terminal observation did not succeed")
			}
			result <- err
		}()
		select {
		case call := <-terminal.started:
			return call, result
		case err := <-result:
			t.Fatalf("terminal invocation stopped at admission: %v", err)
		case <-ctx.Done():
			t.Fatal("terminal invocation did not start within the fixture deadline")
		}
		return managedTerminalCall{}, nil
	}
	logic, gotLogic := run(left, invocation("grok-logic"))
	if _, err := left.Observe(ctx, invocation("grok-logic")); !errors.Is(err, ports.ErrProviderInstanceAlreadyActive) {
		t.Fatalf("same-instance refusal = %v", err)
	}
	security, gotSecurity := run(left, invocation("grok-security"))
	peer, gotPeer := run(right, invocation("grok-logic"))
	if logic.root == security.root || logic.root == peer.root || security.root == peer.root {
		t.Fatal("overlapping invocations share namespace roots")
	}
	for _, c := range []managedTerminalCall{logic, security, peer} {
		close(c.complete)
	}
	for _, result := range []<-chan error{gotLogic, gotSecurity, gotPeer} {
		if err := <-result; err != nil {
			t.Fatal(err)
		}
	}
	retry, gotRetry := run(left, invocation("grok-logic"))
	cancelled, stopClose := context.WithTimeout(ctx, 25*time.Millisecond)
	defer stopClose()
	if _, err := left.Close(cancelled); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("close with active invocation = %v", err)
	}
	close(retry.complete)
	if err := <-gotRetry; err != nil {
		t.Fatal(err)
	}
	for _, reg := range []*Registry{left, right} {
		receipt, err := reg.Close(ctx)
		if err != nil || !receipt.Valid() {
			t.Fatalf("terminal drain receipt invalid: %v", err)
		}
	}
}
