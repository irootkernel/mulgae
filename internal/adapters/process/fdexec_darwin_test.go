//go:build darwin && arm64

package process

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/irootkernel/mulgae/internal/ports"
)

const descriptorConversationFrame = `{"operation":"probe","argument":"literal argument with spaces"}`

type descriptorConversationDriver struct{}

func (descriptorConversationDriver) Drive(ctx context.Context, exchange ports.ProviderSessionExchange) error {
	if err := exchange.SendLine(ctx, []byte(descriptorConversationFrame)); err != nil {
		return err
	}
	line, err := exchange.ReceiveLine(ctx)
	if err != nil {
		return err
	}
	if string(line) != "CANARY_ABSENT" {
		return fmt.Errorf("unexpected descriptor probe response %q", line)
	}
	if err := exchange.CloseInput(ctx); err != nil {
		return err
	}
	if _, err := exchange.ReceiveLine(ctx); !errors.Is(err, io.EOF) {
		return fmt.Errorf("descriptor probe stream end: %w", err)
	}
	return nil
}

func guardedConversationFixture(t *testing.T, bound bool) (ports.ProcessRequest, inheritedCanaryDescriptors) {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	neutral, source := filepath.Join(base, "neutral"), filepath.Join(base, "source")
	credentials, namespace := filepath.Join(base, "credentials"), filepath.Join(base, "invocation")
	for _, path := range []string{neutral, source, credentials, namespace} {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	canary := openInheritedCanary(t, credentials)
	arguments := append(canary.arguments(), neutral, "literal argument with spaces")
	request := guardedCanaryLaunchRequest(t, helperBinary(t), neutral, source, credentials, namespace, arguments)
	if bound {
		directory, err := os.Open(neutral)
		if err != nil {
			t.Fatal(err)
		}
		root, err := ports.NewAnchoredRoot(neutral)
		if err != nil {
			_ = directory.Close()
			t.Fatal(err)
		}
		request, err = ports.NewNeutralBoundProcessRequest(request, root, directory)
		if err != nil {
			_ = directory.Close()
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = directory.Close() })
	}
	return request, canary
}

func TestGuardedConversationPreservesExecutionAndReceipts(t *testing.T) {
	for _, bound := range []bool{false, true} {
		t.Run(fmt.Sprintf("bound=%t", bound), func(t *testing.T) {
			request, canary := guardedConversationFixture(t, bound)
			observation, err := newTestRunner(t).Converse(context.Background(), request, descriptorConversationDriver{})
			if err != nil {
				t.Fatal(err)
			}
			if artifact, ok := observation.StdoutArtifact(); ok {
				if lease, ok := artifact.(ports.ContentLease); ok {
					defer lease.Close()
				}
			}
			assertTermination(t, observation, ports.ProcessTerminationExited)
			assertExitCode(t, observation, 0)
			if !observation.Succeeded() || !observation.ProcessGroupAbsent() || len(observation.SignalRequests()) != 0 {
				t.Fatal("guarded conversation did not exit naturally without residual processes")
			}
			frame := []byte(descriptorConversationFrame + "\n")
			receipt := observation.StdinWriteReceipt()
			if !receipt.Complete() || receipt.IntendedByteLength() != int64(len(frame)) || receipt.WrittenByteCount() != int64(len(frame)) || receipt.SHA256() != runnerTestStdinDigest(frame) {
				t.Fatalf("guarded stdin receipt = %#v", receipt)
			}
			if string(observation.Stdout()) != "CANARY_ABSENT\n" {
				t.Fatalf("guarded stdout = %q", observation.Stdout())
			}
			canary.assertParentPreserved(t)
		})
	}
}

func TestCleanExecRejectsMalformedArgumentsBeforeExec(t *testing.T) {
	for _, argv := range [][]string{
		{"mulgae", cleanExecHiddenArgument},
		{"mulgae", cleanExecHiddenArgument, "relative"},
		{"mulgae", cleanExecHiddenArgument, "/usr/bin/../bin/sh"},
	} {
		if handled, err := ExecInheritedDirectory(argv); !handled || err == nil {
			t.Fatalf("malformed clean-exec arguments %q: handled=%t, error=%v", argv, handled, err)
		}
	}
}

func TestGuardedConversationCancellationBeforeStart(t *testing.T) {
	for _, bound := range []bool{false, true} {
		t.Run(fmt.Sprintf("bound=%t", bound), func(t *testing.T) {
			request, canary := guardedConversationFixture(t, bound)
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			observation, err := newTestRunner(t).Converse(ctx, request, descriptorConversationDriver{})
			if err != nil {
				t.Fatal(err)
			}
			assertTermination(t, observation, ports.ProcessTerminationCancelled)
			if _, started := observation.LifecycleReceipt(); started || len(observation.Stdout()) != 0 || len(observation.SignalRequests()) != 0 {
				t.Fatal("cancelled guarded request started a target or reported process activity")
			}
			canary.assertParentPreserved(t)
		})
	}
}
