//go:build darwin && arm64

package providercli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

func TestGrokLiveInvocationAuditsBoundaryBeforeAcceptingReport(t *testing.T) {
	for _, purpose := range []ports.ProviderInvocationPurpose{ports.ProviderInvocationInitial, ports.ProviderInvocationExtract} {
		for _, outcome := range []string{"unchanged", "policy drift", "error and drift", "drain unknown",
			"ACP error", "ACP error and drift", "ACP login stderr", "ACP login stderr and drift",
			"ACP rate-limit stderr", "ACP rate-limit stderr and drift"} {
			t.Run(string(purpose)+"/"+outcome, func(t *testing.T) {
				_, execution, project := countingLiveFixture(t, domain.LiveSourceWorkspace)
				root, identity := testWorkspaceRoot(t)
				fixture := &currentProbeFixture{root: root, identity: identity}
				runner := &grokBoundaryMutationRunner{observation: currentProbeCapabilityProtocolObservation(t, fixture, []byte("protocol transcript"))}
				registry, err := newRegistry(context.Background(), runner, testDefinition(t, FamilyGrok, "grok-boundary"))
				if err != nil {
					t.Fatal(err)
				}
				defer func() {
					if _, err := registry.Close(context.Background()); err != nil {
						t.Error(err)
					}
				}()
				lease := registry.namespaces["grok-boundary"].(*namespaceLease)
				home := filepath.Join(lease.root, "home", ".grok")
				if err := os.MkdirAll(home, 0700); err != nil {
					t.Fatal(err)
				}
				bundle, err := installGrokBoundaryBundle(home, filepath.Dir(execution.ReviewerHome().Root().String()), project)
				if err != nil {
					t.Fatal(err)
				}
				lease.grokBoundary = &bundle
				runner.after = func() {
					if outcome == "policy drift" || outcome == "error and drift" || outcome == "drain unknown" ||
						outcome == "ACP error and drift" || outcome == "ACP login stderr and drift" || outcome == "ACP rate-limit stderr and drift" {
						if err := os.WriteFile(bundle.files[0].path, []byte("policy changed"), 0600); err != nil {
							t.Fatal(err)
						}
					}
				}
				if outcome == "error and drift" {
					runner.runErr = context.Canceled
				} else if outcome == "drain unknown" {
					runner.observation = ports.ProcessObservation{}
					runner.runErr = errors.New("fixture process-group drain unverified")
				}
				if outcome == "ACP error" || outcome == "ACP error and drift" ||
					outcome == "ACP login stderr" || outcome == "ACP login stderr and drift" ||
					outcome == "ACP rate-limit stderr" || outcome == "ACP rate-limit stderr and drift" {
					runner.protocolLines = []string{grokInitializeResult, grokAuthResult, grokNewResult,
						`{"jsonrpc":"2.0","id":"mulgae-session-prompt","error":{"code":-32603,"message":"fixture prompt failed"}}`}
					var stderr []byte
					switch outcome {
					case "ACP login stderr", "ACP login stderr and drift":
						stderr = []byte("auth.login_required")
					case "ACP rate-limit stderr", "ACP rate-limit stderr and drift":
						stderr = []byte("HTTP 429 too many requests")
					}
					base := runner.observation
					transport, _ := base.ProviderPacketTransportReceipt()
					lifecycle, _ := base.LifecycleReceipt()
					runner.observation, err = ports.NewStartedProviderProcessObservation(base.Stdout(), stderr,
						base.Termination(), base.StdinWriteReceipt(), transport, lifecycle, base.StartedAt(), base.EndedAt())
					if err != nil {
						t.Fatal(err)
					}
				}
				initial := testInvocation(t, "grok-boundary")
				invocation, err := ports.NewProviderInvocation(initial.Role(), initial.ProviderInstance(), initial.AttemptID(), purpose,
					fixture.Packet(), "i_019f596a-cf80-7c67-b265-f37053d51ccd", "019f596a-cf80-7c67-b265-f37053d51cce", testStdinDigest(fixture.Packet()))
				if err != nil {
					t.Fatal(err)
				}
				invocation, err = ports.NewProviderInvocationInLiveSource(invocation, execution)
				if err != nil {
					t.Fatal(err)
				}
				observation, err := registry.Observe(context.Background(), invocation)
				if !runner.completed {
					t.Fatalf("did not reach completed protocol invocation: %v", err)
				}
				if runner.protocolLines != nil {
					var acpFailure *grokACPError
					if !errors.As(runner.driveErr, &acpFailure) || acpFailure.ProtocolFailureCause() != domain.DiagnosticCauseProviderExecutionFailed {
						t.Fatalf("fixture did not produce a typed ACP failure: %v", runner.driveErr)
					}
				}
				_, present := observation.Result()
				switch outcome {
				case "unchanged":
					if err != nil || observation.Status() != ports.ProviderExecutionStatusSucceeded || !present {
						t.Fatalf("unchanged policy lost result: status=%s err=%v", observation.Status(), err)
					}
				case "ACP error", "ACP login stderr", "ACP rate-limit stderr":
					wantStatus := ports.ProviderExecutionStatusUnavailable
					wantCause := domain.DiagnosticCauseProviderExecutionFailed
					if outcome == "ACP login stderr" {
						wantStatus, wantCause = ports.ProviderExecutionStatusAuthentication, domain.DiagnosticCauseLoginRequired
					} else if outcome == "ACP rate-limit stderr" {
						wantStatus, wantCause = ports.ProviderExecutionStatusRateLimit, domain.DiagnosticCauseRateLimited
					}
					if err != nil || present || observation.Status() != wantStatus || observation.PrimaryCause() != wantCause {
						t.Fatalf("ordinary ACP projection changed: status=%s cause=%s result=%t err=%v", observation.Status(), observation.PrimaryCause(), present, err)
					}
					session, ok := observation.SessionObservation()
					if !ok || session.Terminal() != ports.ProviderSessionFailed || session.ProviderSessionID() != "session-script" {
						t.Fatalf("ordinary ACP failure lost session authority: session=%+v present=%t", session.Input(), ok)
					}
				case "drain unknown":
					if err == nil || present || observation.PrimaryCause() == domain.DiagnosticCauseWorkspaceRevalidationFailed {
						t.Fatalf("uncertain drain manufactured stable boundary audit: status=%s cause=%s err=%v", observation.Status(), observation.PrimaryCause(), err)
					}
				default:
					if err == nil || present || observation.Status() != ports.ProviderExecutionStatusSecurityViolation ||
						observation.PrimaryCause() != domain.DiagnosticCauseWorkspaceRevalidationFailed {
						t.Fatalf("same invocation accepted policy drift: status=%s cause=%s result=%t err=%v", observation.Status(), observation.PrimaryCause(), present, err)
					}
				}
				if _, err := os.Lstat(bundle.files[0].path); err != nil {
					t.Fatalf("invocation removed its protection files: %v", err)
				}
			})
		}
	}
}

func TestGrokQualificationAuditsBoundaryAtFailingInvocation(t *testing.T) {
	for _, outcome := range []string{"unchanged", "policy drift", "error and drift", "drain unknown"} {
		t.Run(outcome, func(t *testing.T) {
			bundle, _ := grokBoundaryTestBundle(t)
			namespace := &grokBoundaryProbeNamespace{currentProbeNamespace: currentProbeNamespace{instance: "grok-boundary"}, bundle: bundle}
			root, identity := testWorkspaceRoot(t)
			fixture := &currentProbeFixture{root: root, identity: identity}
			runner := &grokBoundaryMutationRunner{observation: currentProbeCapabilityProtocolObservation(t, fixture, []byte("protocol transcript"))}
			runner.after = func() {
				if outcome != "unchanged" {
					if err := os.WriteFile(bundle.files[0].path, []byte("policy changed"), 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
			if outcome == "error and drift" {
				runner.runErr = context.Canceled
			} else if outcome == "drain unknown" {
				runner.observation = ports.ProcessObservation{}
				runner.runErr = errors.New("fixture process-group drain unverified")
			}
			probe, err := NewCurrentProbe(runner, &currentProbeVerifier{})
			if err != nil {
				t.Fatal(err)
			}
			definition := testProfile(t, FamilyGrok, "grok-boundary", "", "")
			argv, err := grokACPArgv(definition.Executable(), protocolPurposeQualification)
			if err != nil {
				t.Fatal(err)
			}
			packet, err := ports.NewProviderPacketFromBytes(fixture.Packet())
			if err != nil {
				t.Fatal(err)
			}
			_, evidence, _, err := probe.runBound(context.Background(), definition, namespace, fixture, argv, nil, time.Second, &packet, "")
			if !runner.completed {
				t.Fatalf("did not execute qualification conversation: %v", err)
			}
			if outcome == "unchanged" {
				if err != nil || len(evidence) == 0 || namespace.validations != 2 {
					t.Fatalf("unchanged qualification: validations=%d evidence=%q err=%v", namespace.validations, evidence, err)
				}
			} else if outcome == "drain unknown" {
				if err == nil || len(evidence) != 0 || namespace.validations != 1 {
					t.Fatalf("uncertain drain triggered stable audit: validations=%d err=%v", namespace.validations, err)
				}
			} else {
				var failure *domain.Failure
				if err == nil || len(evidence) != 0 || !errors.As(err, &failure) || failure.Class() != domain.FailureSecurityPolicy ||
					failure.Stage() != "namespace" || namespace.validations != 2 {
					t.Fatalf("policy drift lost failing-stage security classification: validations=%d evidence=%q err=%v", namespace.validations, evidence, err)
				}
			}
		})
	}
}

type grokBoundaryProbeNamespace struct {
	currentProbeNamespace
	bundle      grokBoundaryBundle
	validations int
}

func TestGrokVersionProbeAuditsBoundaryAfterExit(t *testing.T) {
	for _, drift := range []bool{false, true} {
		t.Run(fmt.Sprint(drift), func(t *testing.T) {
			bundle, _ := grokBoundaryTestBundle(t)
			namespace := &grokBoundaryProbeNamespace{currentProbeNamespace: currentProbeNamespace{instance: "grok-boundary"}, bundle: bundle}
			root, identity := testWorkspaceRoot(t)
			fixture := &currentProbeFixture{root: root, identity: identity}
			runner := &grokBoundaryMutationRunner{observation: currentProbeCapabilityProtocolObservation(t, fixture, []byte("grok 1.0.70 (123abc)\n"))}
			runner.after = func() {
				if drift {
					if err := os.WriteFile(bundle.files[0].path, []byte("policy changed"), 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
			probe, err := NewCurrentProbe(runner, &currentProbeVerifier{})
			if err != nil {
				t.Fatal(err)
			}
			definition := testProfile(t, FamilyGrok, "grok-boundary", "", "")
			_, _, _, err = probe.runBound(context.Background(), definition, namespace, fixture,
				[]string{definition.Executable(), "--version"}, nil, time.Second, nil, "")
			if !runner.completed || namespace.validations != 2 {
				t.Fatalf("version probe missed its terminal audit: completed=%t validations=%d err=%v", runner.completed, namespace.validations, err)
			}
			if drift {
				var failure *domain.Failure
				if !errors.As(err, &failure) || failure.Class() != domain.FailureSecurityPolicy || failure.Stage() != "namespace" {
					t.Fatalf("version probe accepted policy drift: %v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func (namespace *grokBoundaryProbeNamespace) ValidateForSpawn() error {
	namespace.validations++
	return namespace.bundle.Validate()
}

type grokBoundaryMutationRunner struct {
	observation   ports.ProcessObservation
	after         func()
	runErr        error
	completed     bool
	protocolLines []string
	driveErr      error
}

func (runner *grokBoundaryMutationRunner) Run(_ context.Context, request ports.ProcessRequest) (ports.ProcessObservation, error) {
	if directory, _, ok := request.BoundLaunchDirectory(); ok {
		defer directory.Close()
	}
	runner.completed = true
	runner.after()
	return runner.observation, runner.runErr
}

func (runner *grokBoundaryMutationRunner) Converse(ctx context.Context, request ports.ProcessRequest, driver ports.ProviderSessionDriver) (ports.ProcessObservation, error) {
	if directory, _, ok := request.LaunchDirectory(); ok {
		defer directory.Close()
	} else if directory, _, ok := request.BoundLaunchDirectory(); ok {
		defer directory.Close()
	}
	lines := runner.protocolLines
	if lines == nil {
		lines = []string{grokInitializeResult, grokAuthResult, grokNewResult,
			`{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"session-script","update":{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"review result"}}}}`,
			grokPromptResult, grokCloseResult}
	}
	runner.driveErr = driver.Drive(ctx, newScriptedProtocolExchange(lines...))
	runner.completed = true
	runner.after()
	return runner.observation, errors.Join(runner.driveErr, runner.runErr)
}
