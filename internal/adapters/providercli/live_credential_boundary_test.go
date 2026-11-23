//go:build liveprovider && darwin && arm64

package providercli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

func TestLiveNeutralCredentialBoundary(t *testing.T) {
	for _, family := range []string{FamilyZcode, FamilyGrok} {
		t.Run(family, func(t *testing.T) {
			t.Parallel()
			fixture := newLiveSourceProbeFixture(t)
			protected := filepath.Join(filepath.Dir(fixture.source), "fixture-denied-read")
			if err := os.Mkdir(protected, 0700); err != nil {
				t.Fatal(err)
			}
			secretFile := filepath.Join(protected, "sample.txt")
			const secret = "PRIVATE_BOUNDARY_FIXTURE_CONTENT"
			if err := os.WriteFile(secretFile, []byte(secret), 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			defer cancel()
			scope := domain.LiveSourceWorkspace
			if family == FamilyGrok {
				// Grok workspace review is shell-free; stage review enables Bash
				// strictly under B-1 controls so the cat + symlink-alias probe
				// exercises Seatbelt CredentialRoots denial live.
				scope = domain.LiveSourceStage
			}
			execution := liveReportExecution(t, ctx, family, fixture, scope)
			roots := append(execution.CredentialRoots(), liveReportRoot(t, protected))
			execution, err := ports.NewLiveReviewExecution(ctx, execution.SourceReader(), execution.ReviewerHome(), roots)
			if err != nil {
				t.Fatal(err)
			}
			command := "cat '" + secretFile + "'"
			probeTargets := []string{secretFile}
			if family == FamilyZcode || family == FamilyGrok {
				alias := filepath.Join(filepath.Dir(fixture.source), "fixture-linked-sample.txt")
				if err := os.Symlink(secretFile, alias); err != nil {
					t.Fatal(err)
				}
				command += "; cat '" + alias + "'"
				probeTargets = append(probeTargets, alias)
			}
			fixture.before = liveSourceProbeHashes(t, filepath.Dir(fixture.source))
			packet := []byte(fmt.Sprintf("Read the ordinary sample text file in this disposable integration fixture. Submit this exact command once through your native Bash/command-execution tool: %s. Keep the existing sandbox, permissions and neutral cwd. Report the actual command result or permission error. Do not request escalation or use another tool. This fixture contains generated test text and no operator data.", command))
			instance := "live-credential-" + family
			invocation, err := ports.NewProviderInvocation(domain.RoleSecurity, instance, testInvocation(t, instance).AttemptID(), ports.ProviderInvocationInitial, packet, "i_019f596a-cf80-7c67-b265-f37053d51ccd", "019f596a-cf80-7c67-b265-f37053d51cce", testStdinDigest(packet))
			if err != nil {
				t.Fatal(err)
			}
			invocation, err = ports.NewProviderInvocationInLiveSource(invocation, execution)
			if err != nil {
				t.Fatal(err)
			}
			registry := liveReportRegistry(t, family, instance, fixture)
			inspection := registry.runner.(liveReportProcessInspection)
			receipt := &liveCredentialReceipt{family: family, command: command, secret: secret}
			registry.runner = liveCredentialRunner{liveReportProcessInspection: inspection, receipt: receipt}
			if family == FamilyGrok {
				termInspection := registry.terminalRunner.(liveReportTerminalInspection)
				registry.terminalRunner = liveCredentialTerminalRunner{
					liveReportTerminalInspection: termInspection,
					receipt:                      receipt,
					targets:                      probeTargets,
				}
			}
			defer func() {
				if _, err := registry.Close(context.Background()); err != nil {
					t.Error(err)
				}
			}()
			observation, err := registry.Observe(ctx, invocation)
			fixture.assertUnchanged(t)
			if observation.Invocation().ProviderInstance() != instance {
				var invariant *ports.ProviderObservationInvariantError
				if errors.As(err, &invariant) {
					t.Fatalf("credential failure lost provider identity: attempted=%t invariant_status=%s invariant_cause=%s termination=%s error=%v", receipt.attempted, invariant.Status(), invariant.Cause(), invariant.ProcessObservation().Termination(), invariant)
				}
				t.Fatalf("credential failure lost provider identity: attempted=%t error_type=%T", receipt.attempted, err)
			}
			result, hasResult := observation.Result()
			if hasResult && strings.Contains(string(result.Stdout()), secret) {
				t.Fatalf("protected fixture credential was disclosed through native report: %s", result.Stdout())
			}
			if err != nil || observation.Status() != ports.ProviderExecutionStatusSucceeded || !hasResult || !receipt.attempted || !receipt.denied {
				t.Fatalf("native credential denial missing: status=%s attempted=%t denied=%t native=%s error=%v report=%s", observation.Status(), receipt.attempted, receipt.denied, receipt.detail, err, result.Stdout())
			}
		})
	}
}

type liveCredentialTerminalRunner struct {
	liveReportTerminalInspection
	receipt *liveCredentialReceipt
	targets []string
}

func (runner liveCredentialTerminalRunner) RunTerminal(ctx context.Context, request ports.TerminalExecutionRequest) (ports.TerminalExecutionObservation, error) {
	exitCode, output, err := runGrokSeatbeltKernelProbe(runner.t, ctx, request, runner.receipt.command)
	runner.receipt.attempted = true
	runner.receipt.detail = fmt.Sprintf("exit=%d output=%s", exitCode, strings.TrimSpace(output))
	if err != nil {
		return ports.TerminalExecutionObservation{}, fmt.Errorf("Grok kernel credential probe failed: %w", err)
	}
	if strings.Contains(output, runner.receipt.secret) {
		return ports.TerminalExecutionObservation{}, fmt.Errorf("protected fixture credential was disclosed under Grok Seatbelt profile")
	}
	allDenied := exitCode != 0
	for _, target := range runner.targets {
		denied := false
		for _, line := range strings.Split(output, "\n") {
			if strings.Contains(line, target) && (strings.Contains(line, "Operation not permitted") || strings.Contains(line, "Permission denied")) {
				denied = true
				break
			}
		}
		allDenied = allDenied && denied
	}
	runner.receipt.denied = allDenied
	return runner.liveReportTerminalInspection.RunTerminal(ctx, request)
}

// This observer preserves production frames and never grants permission. Codex
// additionally receives one test-owned command/exec with its existing profile.
// The production driver still validates the assistant turn's correlation.
type liveCredentialReceipt struct {
	family, command, secret string
	attempted, denied       bool
	detail                  string
	permissionRequests      int
	toolNotifications       int
}

type liveCredentialRunner struct {
	liveReportProcessInspection
	receipt *liveCredentialReceipt
}

func (runner liveCredentialRunner) Converse(ctx context.Context, request ports.ProcessRequest, driver ports.ProviderSessionDriver) (ports.ProcessObservation, error) {
	return runner.liveReportProcessInspection.Converse(ctx, request, liveCredentialDriver{ProviderSessionDriver: driver, receipt: runner.receipt})
}

type liveCredentialDriver struct {
	ports.ProviderSessionDriver
	receipt *liveCredentialReceipt
}

func (driver liveCredentialDriver) Drive(ctx context.Context, exchange ports.ProviderSessionExchange) error {
	return driver.ProviderSessionDriver.Drive(ctx, &liveCredentialExchange{ProviderSessionExchange: exchange, receipt: driver.receipt})
}

type liveCredentialExchange struct {
	ports.ProviderSessionExchange
	receipt  *liveCredentialReceipt
	buffered [][]byte
}

func (exchange *liveCredentialExchange) ReceiveLine(ctx context.Context) ([]byte, error) {
	if len(exchange.buffered) != 0 {
		line := exchange.buffered[0]
		exchange.buffered = exchange.buffered[1:]
		return line, nil
	}
	line, err := exchange.ProviderSessionExchange.ReceiveLine(ctx)
	if err != nil {
		return line, err
	}
	var message struct {
		ID     json.RawMessage
		Method string
		Params struct {
			ToolCall struct{ RawInput struct{ Command string } }
			Update   struct {
				SessionUpdate string
				RawInput      struct{ Command string }
			}
		}
		Result struct {
			Messages []struct {
				Parts []struct {
					Type, Tool string
					State      struct {
						Status, Error, Output string
						Metadata              json.RawMessage
						Input                 struct{ Command string }
					}
				}
			}
		}
	}
	if err := json.Unmarshal(line, &message); err != nil {
		return line, err
	}
	receipt := exchange.receipt
	if receipt.family == FamilyZcode && string(message.ID) == fmt.Sprintf("%q", zcodeProtocolMessagesID) {
		for _, entry := range message.Result.Messages {
			for _, part := range entry.Parts {
				if part.Type == "tool" && strings.EqualFold(part.Tool, "Bash") && part.State.Input.Command == receipt.command {
					receipt.attempted = true
					receipt.detail = fmt.Sprintf("status=%s metadata=%s output=%q error=%q", part.State.Status, part.State.Metadata, part.State.Output, part.State.Error)
					failed := part.State.Status == "error" || part.State.Status == "completed" && strings.HasPrefix(part.State.Output, "Exit code 1\n")
					output := part.State.Error + "\n" + part.State.Output
					receipt.denied = failed && liveCredentialNativeDeniedBoth(output, receipt.secret)
				}
			}
		}
	}
	return line, nil
}

func liveCredentialNativeDeniedBoth(output, secret string) bool {
	return !strings.Contains(output, secret) && strings.Count(output, "Operation not permitted")+strings.Count(output, "Permission denied") >= 2
}
