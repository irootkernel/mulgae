//go:build darwin && arm64

package providercli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	filesystemadapter "github.com/irootkernel/mulgae/internal/adapters/filesystem"
	gittargetadapter "github.com/irootkernel/mulgae/internal/adapters/gittarget"
	workspaceadapter "github.com/irootkernel/mulgae/internal/adapters/workspace"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

func TestZCodeRegistryRetainsTerminalFailures(t *testing.T) {
	stagedRejections := map[string]ports.StagedOutputRejection{
		"missing output": ports.StagedOutputMissing, "empty output": ports.StagedOutputEmpty,
		"missing marker": ports.StagedOutputCompletionMarkerMissing, "wrong marker": ports.StagedOutputCompletionMarkerMismatch,
	}
	for _, scenario := range []string{"account", "model", "residual", "runtime drift", "binding drift", "qualification package drift", "missing output", "empty output", "missing marker", "wrong marker"} {
		t.Run(scenario, func(t *testing.T) {
			ctx := t.Context()
			f := newTerminalTestFixture(t)
			root := func(path string) ports.AnchoredRoot {
				t.Helper()
				value, err := ports.NewAnchoredRoot(path)
				if err != nil {
					t.Fatal(err)
				}
				return value
			}
			const instance = "zcode-logic"
			app := filepath.Join(f.root, "ZCode.app")
			if err := os.Mkdir(app, 0o700); err != nil {
				t.Fatal(err)
			}
			script := strings.ReplaceAll(fixtureZCodePreparationScript(), "/Applications/Fixture ZCode.app", app)
			if scenario == "account" {
				script = "#!/bin/sh\nprintf '%s\\n' '{\"reason\":\"desktop_account_unavailable\",\"message\":\"fixture\"}'\nexit 1\n"
			}
			pkg := fixtureZCodePackage(t, script)
			companion := ports.ZCodeCompanionObservation{
				Executable: pkg.Launcher.Path, ExecutableSHA256: pkg.Launcher.SHA256, PackageSHA256: pkg.PackageSHA256,
				Version: "0.2.0", AppVersion: "4.0.0", AppBundle: app, BundleOverride: app, MinimumAppVersion: "3.18.2",
			}
			policy, err := RuntimeSafetyPolicyForFamily(CredentialSourceZCode)
			if err != nil {
				t.Fatal(err)
			}
			rawDefinition, err := (RuntimeBuilder{}).BuildProductionRuntime(ports.ProviderRuntimeSpec{
				Family: FamilyZcode, Instance: instance, Version: companion.Version,
				Executable: companion.Executable, ExecutableSHA256: companion.ExecutableSHA256,
				Launcher: companion.Executable, LauncherSHA256: companion.ExecutableSHA256,
				ZCodeCompanion: companion, ApplicationVersion: companion.AppVersion,
				ProfileID: instance, ProfileGeneration: "fixture", RuntimeSafetyPolicyIdentity: policy.Identity(),
				BaseArgv: []string{companion.Executable}, TransportChannel: ports.ProviderPacketChannelTerminal, TransportArgvIndex: -1,
				WorkingDirectory: f.neutralCWD.String(), Timeout: time.Minute,
			})
			if err != nil {
				t.Fatal(err)
			}
			definition := rawDefinition.(RuntimeDefinition)
			managed := filepath.Join(f.root, "managed")
			namespaces, err := NewManagedNamespaceFactory(filepath.Join(managed, "registry-namespaces"), root(managed))
			if err != nil {
				t.Fatal(err)
			}
			protected := []ports.AnchoredRoot{
				root(filepath.Join(f.nativeHome.String(), ".zcode")),
				root(filepath.Join(f.nativeHome.String(), "Library", "Keychains")),
			}
			for _, path := range protected {
				if err := os.MkdirAll(path.String(), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			factory, err := NewCredentialProjectingNamespaceFactoryWithPolicies(namespaces, f.nativeHome.String(),
				map[string]CredentialSourceFamily{instance: CredentialSourceZCode}, map[string]RuntimeSafetyPolicy{instance: policy})
			if err != nil {
				t.Fatal(err)
			}
			terminalIdentity := defaultFakeTerminalIdentity(t)
			terminal := &fakeTerminalSessionRunner{identity: terminalIdentity}
			terminal.runFunc = func(_ context.Context, req ports.TerminalExecutionRequest) (ports.TerminalExecutionObservation, error) {
				if reason := stagedRejections[scenario]; reason != "" {
					if reason != ports.StagedOutputMissing {
						boundary, _ := req.Process().LiveReadOnlyBoundary()
						path := findStagedOutputPath(t, boundary.WritableRoot().String(), stagedOutputFilename)
						contents := map[string]string{"missing marker": "# Fixture report\n", "wrong marker": "# Fixture report\nMULGAE_COMPLETE:wrong\n"}
						if err := os.WriteFile(path, []byte(contents[scenario]), 0o600); err != nil {
							t.Fatal(err)
						}
					}
					return makeTerminalSessionObservation(t, terminal, req, ports.TerminalExecutionObservationInput{
						ProgramStatus: ports.TerminalProgramStatusDone, TurnCount: 1,
					}, ports.ProcessTerminationExited, 0, true, nil, nil), nil
				}
				if scenario != "model" && scenario != "residual" {
					t.Fatal("terminal pane started despite preflight refusal")
				}
				return makeTerminalSessionObservation(t, terminal, req, ports.TerminalExecutionObservationInput{
					ExitedBeforeReport: true,
				}, ports.ProcessTerminationExited, 1, scenario == "model", nil, []byte("Selected model unavailable")), nil
			}
			process := &countingRunner{}
			registry, err := NewProductionRegistryWithTerminalRunner(ctx, process, terminal, factory, testSpawnVerifier{}, definition)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				receipt, err := registry.Close(cleanup)
				if err != nil || !receipt.Valid() {
					t.Errorf("registry drain: %v", err)
				}
			})
			ns, ok := registry.QualificationNamespace(instance)
			if !ok {
				t.Fatal("missing retained namespace")
			}
			home, err := OpenReviewerHome(f.nativeHome, []byte("fixture guide"))
			if err != nil {
				t.Fatal(err)
			}
			defer home.Close()

			if scenario == "qualification package drift" {
				member := filepath.Join(filepath.Dir(filepath.Dir(pkg.Launcher.Path)), "lib", "toolchain.mjs")
				if err := os.WriteFile(member, []byte("changed fixture package member"), 0o600); err != nil {
					t.Fatal(err)
				}
				materializer, err := workspaceadapter.NewMaterializer(root(f.root), filesystemadapter.NewContentDetector())
				if err != nil {
					t.Fatal(err)
				}
				fixtures, err := NewProbeFixtureLeaseFactory(materializer, SecureProbeNonceGenerator{})
				if err != nil {
					t.Fatal(err)
				}
				fixture, err := fixtures.Acquire(ctx, domain.RoleLogic)
				if err != nil {
					t.Fatal(err)
				}
				defer func() {
					if receipt, err := fixture.DrainTerminal(ctx); err != nil || !receipt.Valid() {
						t.Errorf("fixture drain: %v", err)
					}
				}()
				probe, err := NewCurrentProbeWithTerminalRunner(process, testSpawnVerifier{}, terminal)
				if err != nil {
					t.Fatal(err)
				}
				_, err = probe.QualifyCurrent(ctx, CurrentProbeRequest{
					Definition: definition, Namespace: ns, Fixture: fixture, Invocation: NativeProbeInvocation{}, Now: time.Now().UTC(), TTL: time.Minute,
				})
				assertZCodeRegistrySecurityFailure(t, err, domain.DiagnosticCauseProviderOwnershipViolation)
				return
			}

			preparation := zcodeFixtureReceipt(f.root).ZCodeTerminalObservation
			terminalPolicy, err := RuntimeSafetyPolicyForZCodeTerminal(terminalIdentity, pkg, app, preparation, "", "")
			if err != nil {
				t.Fatal(err)
			}
			proof := currentProbeDirectExecutionTestProof()
			proof.ProviderInstance, proof.ProfileID, proof.ProfileGeneration = instance, definition.ProfileID(), definition.ProfileGeneration()
			proof.ProviderVersion, proof.ObservedVersion = definition.Version(), definition.Version()
			proof.Executable, proof.ExecutableSHA256 = definition.Executable(), definition.ExecutableSHA256()
			proof.Launcher, proof.LauncherSHA256 = definition.Launcher(), definition.LauncherSHA256()
			proof.NamespaceGeneration = ns.Generation()
			proof.ZCodePreparation = &preparation
			proof.TerminalRuntimeExecutable, proof.TerminalRuntimeExecutableSHA256 = terminalIdentity.Executable(), terminalIdentity.ExecutableSHA256()
			proof.TerminalRuntimeVersion, proof.TerminalRuntimeGeneration = terminalIdentity.Version(), terminalIdentity.Generation()
			proof.TerminalRuntimePolicyIdentity = terminalPolicy.Identity()
			authority, err := newCurrentProbeDirectExecutionAuthorityReceiptForDefinition([]currentProbeDirectExecutionRoleProof{proof}, time.Now().UTC().Add(time.Minute), definition)
			if err != nil {
				t.Fatal(err)
			}
			if scenario == "binding drift" {
				mutated := definition
				mutated.zcodeCompanion.PackageSHA256 = strings.Repeat("f", 64)
				err = registry.BindProviderQualification(mutated, authority, companion.Version, []domain.Role{domain.RoleLogic})
				assertZCodeRegistrySecurityFailure(t, err, domain.DiagnosticCauseWorkspaceRevalidationFailed)
				return
			}
			if err := registry.BindProviderQualification(definition, authority, companion.Version, []domain.Role{domain.RoleLogic}); err != nil {
				t.Fatal(err)
			}
			if scenario == "runtime drift" {
				terminal.identity, err = ports.NewTerminalRuntimeIdentity(terminalIdentity.Executable(), terminalIdentity.ExecutableSHA256(), terminalIdentity.Version(), terminalIdentity.Generation()+1)
				if err != nil {
					t.Fatal(err)
				}
			}

			sourceAdapter, err := gittargetadapter.NewLiveSourceAdapter(gittargetadapter.NewExecRunner(), protected)
			if err != nil {
				t.Fatal(err)
			}
			selector, _ := ports.NewLiveSourceSelector(domain.LiveSourceWorkspace, "")
			source, err := sourceAdapter.OpenLiveSource(ctx, f.sourceRoot, selector)
			if err != nil {
				t.Fatal(err)
			}
			defer source.Close()
			execution, err := ports.NewLiveReviewExecution(ctx, source, home, protected)
			if err != nil {
				t.Fatal(err)
			}
			invocation, err := ports.NewProviderInvocationInLiveSource(testInvocation(t, instance), execution)
			if err != nil {
				t.Fatal(err)
			}
			observation, err := registry.Observe(ctx, invocation)
			if scenario == "runtime drift" {
				var cause *ports.ProviderRuntimeError
				if !errors.As(err, &cause) || cause.Cause() != domain.DiagnosticCauseWorkspaceRevalidationFailed || len(terminal.requests) != 0 {
					t.Fatalf("runtime drift did not stop before pane: %v", err)
				}
				return
			}
			if err != nil || observation.Validate() != nil {
				t.Fatalf("invalid failure observation: %v / %v", err, observation.Validate())
			}
			_, hasProcess := observation.AvailableProcessObservation()
			if got, want := observation.StagedOutputRejection(), stagedRejections[scenario]; got != want {
				t.Fatalf("staged output rejection = %q, want %q", got, want)
			}
			if reason := stagedRejections[scenario]; reason != "" {
				wantCause := domain.DiagnosticCauseProviderOutputFileInvalid
				if reason == ports.StagedOutputMissing {
					wantCause = domain.DiagnosticCauseProviderOutputFileMissing
				}
				if observation.Status() != ports.ProviderExecutionStatusArtifactFailure ||
					observation.PrimaryCause() != wantCause || observation.DiagnosticCode() != "invalid_provider_output" || !hasProcess {
					t.Fatalf("unexpected staged failure projection: %s/%s/%s", observation.Status(), observation.PrimaryCause(), observation.DiagnosticCode())
				}
			}
			switch scenario {
			case "account":
				if observation.Status() != ports.ProviderExecutionStatusConfigurationViolation ||
					observation.DiagnosticCode() != "zcode_account_configuration" || hasProcess || len(terminal.requests) != 0 {
					t.Fatalf("host refusal lost configuration identity or fabricated process: %s/%s", observation.Status(), observation.DiagnosticCode())
				}
			case "model":
				if observation.Status() != ports.ProviderExecutionStatusConfigurationViolation ||
					observation.DiagnosticCode() != "zcode_model_selection" || !hasProcess {
					t.Fatalf("model refusal lost configuration identity or process: %s/%s", observation.Status(), observation.DiagnosticCode())
				}
			case "residual":
				if observation.Status() != ports.ProviderExecutionStatusSecurityViolation ||
					observation.PrimaryCause() != domain.DiagnosticCauseProcessGroupCleanupFailed || !hasProcess {
					t.Fatalf("residual group lost security precedence: %s/%s", observation.Status(), observation.PrimaryCause())
				}
			}
		})
	}
}

func assertZCodeRegistrySecurityFailure(t *testing.T, err error, cause domain.RuntimeDiagnosticCause) {
	t.Helper()
	var failure *domain.Failure
	var runtime *ports.ProviderRuntimeError
	if !errors.As(err, &failure) || failure.Class() != domain.FailureSecurityPolicy || !errors.As(err, &runtime) || runtime.Cause() != cause {
		t.Fatalf("failure lost security class or %s: %v", cause, err)
	}
}
