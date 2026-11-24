//go:build darwin && arm64

package providercli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/adapters/herdr"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

const (
	zcodeFixtureCatalog = `{"schemaVersion":1,"revision":48}`
	zcodeFixtureAuth    = `{"providerId":"account:zai-individual-coding-plan","identity":"synthetic","apiKey":"fixture-only","accountAccess":{"type":"zhipu-account","mode":"individual-coding-plan","accountType":"zai"}}`
)

func zcodeFixtureReceipt(dir string) zcodePreparationReceipt {
	return zcodePreparationReceipt{
		AuthFile: filepath.Join(dir, "auth.json"), CatalogFile: filepath.Join(dir, "catalog.json"),
		CatalogSource: "desktop-cache", MinimumVersion: "3.18.2", ProviderID: zcodeCodingPlanProvider,
		ZCodeTerminalObservation: ZCodeTerminalObservation{
			AppVersion: "4.0.0", CatalogRevision: 48,
			CatalogSHA256:         fmt.Sprintf("%x", sha256.Sum256([]byte(zcodeFixtureCatalog))),
			AccountIdentitySHA256: fmt.Sprintf("%x", sha256.Sum256([]byte("synthetic"))),
		},
	}
}

func TestZCodeTerminalReceiptRejectsInvalidOrSecretFields(t *testing.T) {
	receipt := zcodeFixtureReceipt("/private/tmp/fixture")
	profile := zcodeTerminalProfile{desktop: herdr.ZCodeCompanionObservation{AppVersion: receipt.AppVersion, MinimumVersion: receipt.MinimumVersion}}
	valid, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := profile.validatePreparationReceipt(valid, filepath.Dir(receipt.AuthFile)); err != nil || got != receipt {
		t.Fatalf("valid preparation receipt rejected: %v", err)
	}
	for _, suffix := range []string{`,"apiKey":"fixture-only"}`, `,"appVersion":"4.0.0"}`, `}{}`, `,"APPVERSION":"4.0.0"}`} {
		invalid := append(slices.Clone(valid[:len(valid)-1]), suffix...)
		if _, err := profile.validatePreparationReceipt(invalid, filepath.Dir(receipt.AuthFile)); err == nil || strings.Contains(err.Error(), "fixture-only") {
			t.Fatalf("malformed receipt accepted or disclosed: %v", err)
		}
	}
	drift := receipt.ZCodeTerminalObservation
	drift.CatalogRevision++
	profile.expected = &drift
	if _, err := profile.validatePreparationReceipt(valid, filepath.Dir(receipt.AuthFile)); err == nil {
		t.Fatal("previously qualified catalog drift was accepted")
	}
}

func TestZCodeTerminalPreparedFilesRejectUnsafeInputs(t *testing.T) {
	for _, scenario := range []string{
		"valid", "auth symlink", "auth mode", "auth hardlink", "invalid access", "wrong owner identity",
		"empty auth", "oversized auth", "duplicate auth key", "catalog symlink", "catalog mode", "catalog hardlink",
		"oversized catalog", "wrong digest", "wrong revision", "duplicate catalog key",
	} {
		t.Run(scenario, func(t *testing.T) {
			receipt := zcodeFixtureReceipt(t.TempDir())
			authContents := zcodeFixtureAuth
			authMode := os.FileMode(0o600)
			if scenario == "auth mode" {
				authMode = 0o644
			}
			if scenario == "invalid access" {
				authContents = strings.Replace(authContents, `"mode":"individual-coding-plan"`, `"mode":"invalid-mode"`, 1)
			}
			if scenario == "wrong owner identity" {
				authContents = strings.Replace(authContents, "synthetic", "wrong-identity", 1)
			}
			if scenario == "empty auth" {
				authContents = ""
			}
			if scenario == "oversized auth" {
				authContents = strings.Repeat("x", (64<<10)+1)
			}
			if scenario == "duplicate auth key" {
				authContents = strings.Replace(authContents, `"identity":"synthetic"`, `"identity":"synthetic","identity":"synthetic"`, 1)
			}
			if err := os.WriteFile(receipt.AuthFile, []byte(authContents), authMode); err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "auth symlink":
				outside := filepath.Join(t.TempDir(), "auth")
				if err := os.Rename(receipt.AuthFile, outside); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, receipt.AuthFile); err != nil {
					t.Fatal(err)
				}
			case "auth hardlink":
				if err := os.Link(receipt.AuthFile, filepath.Join(t.TempDir(), "alias")); err != nil {
					t.Fatal(err)
				}
			}
			catalog := []byte(zcodeFixtureCatalog)
			if scenario == "oversized catalog" {
				catalog = make([]byte, (4<<20)+1)
			}
			if scenario == "duplicate catalog key" {
				catalog = []byte(`{"schemaVersion":1,"revision":48,"revision":48}`)
				receipt.CatalogSHA256 = fmt.Sprintf("%x", sha256.Sum256(catalog))
			}
			if scenario == "wrong digest" {
				receipt.CatalogSHA256 = strings.Repeat("a", 64)
			}
			if scenario == "wrong revision" {
				receipt.CatalogRevision++
			}
			catalogMode := os.FileMode(0o400)
			if scenario == "catalog mode" {
				catalogMode = 0o600
			}
			if err := os.WriteFile(receipt.CatalogFile, catalog, catalogMode); err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "catalog symlink":
				outside := filepath.Join(t.TempDir(), "catalog")
				if err := os.Rename(receipt.CatalogFile, outside); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, receipt.CatalogFile); err != nil {
					t.Fatal(err)
				}
			case "catalog hardlink":
				if err := os.Link(receipt.CatalogFile, filepath.Join(t.TempDir(), "alias")); err != nil {
					t.Fatal(err)
				}
			}
			dir, err := os.Open(filepath.Dir(receipt.AuthFile))
			if err != nil {
				t.Fatal(err)
			}
			defer dir.Close()
			_, _, err = validateZCodePreparedFiles(dir, receipt)
			if (err == nil) != (scenario == "valid") {
				t.Fatalf("unexpected validation outcome: %v", err)
			}
			if err != nil {
				var failure *ports.ProviderRuntimeError
				if !errors.As(err, &failure) || failure.Cause() != domain.DiagnosticCauseProviderOwnershipViolation {
					t.Fatalf("prepared input refusal lost its protected cause: %v", err)
				}
			}
		})
	}
}

func TestZCodeTerminalDrainZeroesUnconsumedProjection(t *testing.T) {
	ctx := context.Background()
	factory, err := NewNamespaceFactory(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	value, err := factory.AcquireProviderNamespace(ctx, "fixture", FamilyGrok)
	if err != nil {
		t.Fatal(err)
	}
	lease := value.(*namespaceLease)
	t.Cleanup(func() { _, _ = lease.DrainTerminal(ctx) })
	lease.terminalMu.Lock()
	dir, err := retainZCodeProjectionDirectory(lease)
	lease.terminalMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	path := dir.Name()
	// A killed producer may have written partial credentials before emitting
	// any receipt. The registered cleanup must still sanitize the inode.
	authPath := filepath.Join(path, "auth.json")
	const partial = "fixture-only partial credential"
	command := exec.Command("/bin/sh", "-c", `umask 077; printf '%s' "$1" > "$2"; kill -KILL "$$"`, "fixture", partial, authPath)
	var killed *exec.ExitError
	if err := command.Run(); !errors.As(err, &killed) || killed.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL {
		t.Fatalf("fixture producer did not terminate by SIGKILL: %v", err)
	}
	file, err := os.Open(authPath)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	receipt, err := lease.DrainTerminal(ctx)
	if err != nil || !receipt.Valid() || !receipt.CredentialsZeroed() || !receipt.TornDown() {
		t.Fatalf("namespace drain did not certify teardown: %v", err)
	}
	retained, err := io.ReadAll(file)
	if err != nil || !bytes.Equal(retained, make([]byte, len(partial))) {
		t.Fatal("unconsumed credential was not zeroed")
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("projection directory remains: %v", err)
	}
}

func TestZCodeTerminalArgvKeepsIndependentOmissions(t *testing.T) {
	f := newTerminalTestFixture(t)
	profile := zcodeTerminalProfile{}
	inv := terminalProfileInvocation{
		Definition: f.def, NamespaceRoot: f.namespaceRoot, NeutralCWD: f.neutralCWD, NativeHome: f.nativeHome,
		SourceRoot: f.sourceRoot, PromptPath: "/input/prompt.md", OutputPath: "/output/role-report.md",
		HostArgs: []string{"--auth-file", "/fixture/auth.json", "--consume-auth-file", "--catalog-file", "/fixture/catalog.json", "--no-copy-catalog"},
	}
	for _, purpose := range []terminalInvocationPurpose{terminalPurposeReview, terminalPurposeExtraction, terminalPurposeQualification} {
		inv.Purpose = purpose
		for _, model := range []string{"", "account:zai-individual-coding-plan/GLM-5.4"} {
			inv.Definition.zcodeModel = model
			for _, effort := range []string{"", "max"} {
				inv.Definition.zcodeReasoningEffort = effort
				args, err := profile.BuildArgv(inv)
				if err != nil {
					t.Fatal(err)
				}
				if slices.Contains(args, "--model") != (model != "") || slices.Contains(args, "--reasoning-effort") != (effort != "") ||
					slices.Contains(args, f.sourceRoot.String()) != (purpose == terminalPurposeReview) ||
					!slices.Contains(args, "--consume-auth-file") || slices.Contains(args, "--app-bundle") {
					t.Fatalf("wrong args for %q / %q / %q: %v", purpose, model, effort, args)
				}
			}
		}
	}
}

func TestZCodeTerminalPreparationFailureClassification(t *testing.T) {
	for _, reason := range []string{"desktop_account_unavailable", "desktop_keychain_unavailable"} {
		err := zcodePreparationFailure(reason)
		var failure *domain.Failure
		if !errors.As(err, &failure) || failure.Stage() != "zcode_account_configuration" || failure.Class() != domain.FailureConfiguration {
			t.Fatalf("incorrect classification for %s: %v", reason, err)
		}
	}
	reasons := map[domain.RuntimeDiagnosticCause][]string{
		domain.DiagnosticCauseProviderOwnershipViolation: {"catalog_invalid", "output_exists", "output_dir_invalid", "projection_failed", "fixture-only arbitrary error"},
		domain.DiagnosticCauseTimedOut:                   {"preparation_timeout"},
		domain.DiagnosticCauseProviderExecutionFailed:    {"preparation_interrupted"},
		domain.DiagnosticCauseProviderSpawnFailed:        {"app_bundle_missing", "app_bundle_invalid", "app_version_below_minimum", "embedded_runtime_invalid", "invalid_arguments"},
	}
	for want, group := range reasons {
		for _, reason := range group {
			err := zcodePreparationFailure(reason)
			var failure *ports.ProviderRuntimeError
			if !errors.As(err, &failure) || failure.Cause() != want || strings.Contains(err.Error(), "fixture-only") ||
				errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("closed reason %q was misclassified or disclosed: %v", reason, err)
			}
		}
	}
	timeout := zcodePreparationFailure("preparation_timeout")
	if status, _ := providerFailureProjection(domain.DiagnosticCauseTimedOut); status != ports.ProviderExecutionStatusTimedOut {
		t.Fatalf("wrong transport timeout status: %s", status)
	}
	var timeoutFailure *domain.Failure
	if !errors.As(classifyProbeFailure(context.Background(), FamilyZcode, timeout, nil), &timeoutFailure) ||
		timeoutFailure.Class() != domain.FailureTimeout {
		t.Fatalf("wrong qualifier timeout class: %v", timeoutFailure)
	}
}

func TestZCodeTerminalModelFailureClassification(t *testing.T) {
	for _, screen := range []string{
		"Requested model is absent from the projected account catalog (revision 48). The session stopped with no fallback model.",
		"Selected reasoning level was not applied",
	} {
		var failure *domain.Failure
		err := zcodeTerminalConfigurationFailure(ports.TerminalProgramStatusError, "", []byte(screen))
		if !errors.As(err, &failure) || failure.Stage() != "zcode_model_selection" || failure.Class() != domain.FailureConfiguration {
			t.Fatalf("incorrect model configuration classification: %v", err)
		}
	}
}

func fixtureZCodePackage(t *testing.T, launcher string) herdr.ZCodePackage {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range strings.Fields(`
		bin/herdr-zcode bin/herdr-zcode-app.mjs
		lib/app-server-client.mjs lib/app-server-controller.mjs lib/desktop-account.mjs
		lib/desktop-catalog.mjs lib/desktop-keychain.mjs lib/desktop-runtime.mjs
		lib/error-classification.mjs lib/herdr-reporter.mjs lib/osc7501-reporter.mjs
		lib/prepare-isolated.mjs lib/runtime-profile.mjs lib/toolchain.mjs
		package.json scripts/desktop-bootstrap.pl scripts/tool-bin/npm scripts/tool-bin/npx
		scripts/toolchain.sh toolchains.env`) {
		path = filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		content, mode := "offline fixture", os.FileMode(0o600)
		if filepath.Base(path) == "herdr-zcode" {
			content, mode = launcher, 0o700
		}
		if err := os.WriteFile(path, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
	}
	pkg, err := herdr.ResolveZCodePackage(herdr.ResolveOptions{
		HasOverride: true, OverridePath: filepath.Join(root, "bin", "herdr-zcode"),
	})
	if err != nil {
		t.Fatal(err)
	}
	return pkg
}

func fixtureZCodePreparationScript() string {
	receipt := zcodeFixtureReceipt("/unused")
	return fmt.Sprintf(`#!/bin/sh
[ "$#" -eq 6 ] && [ "$1" = prepare-isolated ] && [ "$2" = --out-dir ] &&
[ "$4" = --json ] && [ "$5" = --app-bundle ] && [ "$6" = '/Applications/Fixture ZCode.app' ] &&
[ "$PWD" = /private/var/empty ] && [ "$PATH" = /usr/bin:/bin ] && [ "$TMPDIR" = /tmp ] &&
[ -d "$HOME/.mulgae/home" ] &&
[ -z "${NVM_DIR+x}${HC_SOCKET+x}${HERDR_SOCKET+x}${DYLD_LIBRARY_PATH+x}${NODE_OPTIONS+x}" ] || exit 2
case "$0" in /*/bin/herdr-zcode) ;; *) exit 2 ;; esac
umask 077
printf '%%s' '%s' > "$3/auth.json" || exit 2
printf '%%s' '%s' > "$3/catalog.json" || exit 2
chmod 0400 "$3/catalog.json" || exit 2
printf '{"authFile":"%%s/auth.json","catalogFile":"%%s/catalog.json","catalogSource":"desktop-cache","catalogRevision":48,"catalogSHA256":"%s","appVersion":"4.0.0","minZcodeAppVersion":"3.18.2","providerId":"%s","accountIdentitySHA256":"%s"}\n' "$3" "$3"
`, zcodeFixtureAuth, zcodeFixtureCatalog, receipt.CatalogSHA256, receipt.ProviderID, receipt.AccountIdentitySHA256)
}

func fixtureZCodeTerminalProfile(t *testing.T) zcodeTerminalProfile {
	t.Helper()
	const app = "/Applications/Fixture ZCode.app"
	return zcodeTerminalProfile{
		pkg: fixtureZCodePackage(t, fixtureZCodePreparationScript()),
		desktop: herdr.ZCodeCompanionObservation{
			AppVersion: "4.0.0", AppBundle: app, MinimumVersion: "3.18.2",
		},
		appBundle: app,
	}
}

type beforeZCodeSpawnProfile struct {
	zcodeTerminalProfile
	beforeVerify func(*terminalProfileInvocation) error
}

func (profile beforeZCodeSpawnProfile) PrepareHost(ctx context.Context, inv *terminalProfileInvocation) (terminalHostPreparation, error) {
	preparation, err := profile.zcodeTerminalProfile.PrepareHost(ctx, inv)
	if err != nil {
		return terminalHostPreparation{}, err
	}
	verify := preparation.verifySpawn
	preparation.verifySpawn = func() error {
		if err := profile.beforeVerify(inv); err != nil {
			return err
		}
		return verify()
	}
	return preparation, nil
}

func TestZCodeTerminalDriverOffline(t *testing.T) {
	t.Setenv("NVM_DIR", "/ambient")
	t.Setenv("HC_SOCKET", "/ambient")
	t.Setenv("HERDR_SOCKET", "/ambient")
	t.Setenv("DYLD_LIBRARY_PATH", "/ambient")
	t.Setenv("NODE_OPTIONS", "--ambient")
	profile := fixtureZCodeTerminalProfile(t)
	for _, tc := range []struct {
		name, wantTools, wantStage string
		wantStatus                 ports.ProviderExecutionStatus
		wantClass                  domain.FailureClass
		purpose                    terminalInvocationPurpose
		scope                      domain.LiveSourceScope
		beforeSpawn                string
		absent, reported           bool
		status                     ports.TerminalProgramStatus
		blocked                    ports.TerminalBlockedKind
		termination                ports.ProcessTermination
		exit                       int
		stderr                     string
	}{
		{name: "workspace", wantTools: "Read,Grep,Glob,Write", purpose: terminalPurposeReview, scope: domain.LiveSourceWorkspace, absent: true, reported: true, status: ports.TerminalProgramStatusDone, termination: ports.ProcessTerminationExited},
		{name: "git", wantTools: "Read,Bash,Write", purpose: terminalPurposeReview, scope: domain.LiveSourceStage, absent: true, reported: true, status: ports.TerminalProgramStatusDone, termination: ports.ProcessTerminationExited},
		{name: "extraction", wantTools: "Read,Write", purpose: terminalPurposeExtraction, absent: true, reported: true, status: ports.TerminalProgramStatusDone, termination: ports.ProcessTerminationExited},
		{name: "model refusal before OSC", wantTools: "Read,Write", wantStage: "zcode_model_selection", wantStatus: ports.ProviderExecutionStatusConfigurationViolation, wantClass: domain.FailureConfiguration, purpose: terminalPurposeQualification, absent: true, termination: ports.ProcessTerminationExited, exit: 1, stderr: "Selected model unavailable"},
		{name: "blocked auth", wantTools: "Read,Write", wantStage: "zcode_account_configuration", wantStatus: ports.ProviderExecutionStatusConfigurationViolation, wantClass: domain.FailureConfiguration, purpose: terminalPurposeQualification, absent: true, reported: true, status: ports.TerminalProgramStatusBlocked, blocked: ports.TerminalBlockedKindAuth, termination: ports.ProcessTerminationExited, exit: 1},
		{name: "blocked quota", wantTools: "Read,Write", wantStage: "provider_quota", wantStatus: ports.ProviderExecutionStatusQuota, wantClass: domain.FailureQuota, purpose: terminalPurposeQualification, absent: true, reported: true, status: ports.TerminalProgramStatusBlocked, blocked: ports.TerminalBlockedKindQuota, termination: ports.ProcessTerminationExited, exit: 1},
		{name: "unsolicited signal", wantTools: "Read,Write", wantStage: "process_internal", wantStatus: ports.ProviderExecutionStatusInternalFailure, wantClass: domain.FailureInternal, purpose: terminalPurposeQualification, absent: true, reported: true, status: ports.TerminalProgramStatusError, termination: ports.ProcessTerminationSignaled, stderr: "Selected model unavailable"},
		{name: "residual group", wantTools: "Read,Write", wantStage: "process_security", wantStatus: ports.ProviderExecutionStatusSecurityViolation, wantClass: domain.FailureSecurityPolicy, purpose: terminalPurposeQualification, reported: true, status: ports.TerminalProgramStatusError, termination: ports.ProcessTerminationExited, exit: 1, stderr: "Selected model unavailable"},
		{name: "drain before descriptor verification", purpose: terminalPurposeQualification, beforeSpawn: "drain"},
		{name: "prepared auth changed", purpose: terminalPurposeQualification, beforeSpawn: "auth"},
		{name: "prepared catalog changed", purpose: terminalPurposeQualification, beforeSpawn: "catalog"},
		{name: "prepared package changed", purpose: terminalPurposeQualification, beforeSpawn: "package"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			activeProfile := profile
			if tc.beforeSpawn == "package" {
				activeProfile = fixtureZCodeTerminalProfile(t)
			}
			ctx := context.Background()
			f := newTerminalTestFixture(t)
			factory, err := NewNamespaceFactory(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			ns, err := factory.AcquireProviderNamespace(ctx, "zcode_fixture", FamilyZcode)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if _, err := ns.DrainTerminal(ctx); err != nil {
					t.Errorf("fixture namespace cleanup: %v", err)
				}
			})
			lease := ns.(*namespaceLease)
			req := f.baseRequest(t, tc.purpose, []byte("fixture request"))
			req.NamespaceRoot, req.NamespaceEnvironment, req.Namespace = lease.root, ns.Environment(), lease
			req.Definition.executable, req.Definition.executableSHA256 = activeProfile.pkg.Launcher.Path, activeProfile.pkg.Launcher.SHA256
			req.LiveScope = tc.scope
			runner := &fakeTerminalSessionRunner{identity: defaultFakeTerminalIdentity(t)}
			var launched bool
			var credential *os.File
			runner.runFunc = func(_ context.Context, terminal ports.TerminalExecutionRequest) (ports.TerminalExecutionObservation, error) {
				launched = true
				proc := terminal.Process()
				args := proc.Argv()
				if len(args) == 0 || args[0] != activeProfile.pkg.Launcher.Path ||
					fixtureFlagValue(args, "--tool-allowlist") != tc.wantTools ||
					fixtureFlagValue(args, "--app-bundle") != activeProfile.appBundle ||
					fixtureFlagValue(args, "--runtime-dir") != filepath.Join(lease.root, "tmp") ||
					!slices.Contains(args, "--consume-auth-file") || !slices.Contains(args, "--no-copy-catalog") ||
					!strings.Contains(fixtureFlagValue(args, "--tool-denylist"), "Agent,TodoWrite,NotebookEdit,WebSearch,WebFetch") {
					t.Fatal("wrong executable, tool policy, or runtime arguments")
				}
				env := namespaceEnvironmentMap(t, proc.Environment())
				for key, want := range map[string]string{"PATH": "/usr/bin:/bin", "TERM": "xterm-256color", "LANG": "en_US.UTF-8", "TMPDIR": zcodeRuntimeTempDirectory, "TMP": zcodeRuntimeTempDirectory, "TEMP": zcodeRuntimeTempDirectory} {
					if env[key] != want {
						t.Fatalf("wrong pane environment for %s", key)
					}
				}
				boundary, ok := proc.LiveReadOnlyBoundary()
				runtimeTemp, hasTemp := boundary.RuntimeTempRoot()
				if !ok || !hasTemp || !boundary.PaneTTY() || boundary.BashGate() != (tc.scope == domain.LiveSourceStage) ||
					runtimeTemp.String() != lease.zcodeRuntimeTemp {
					t.Fatal("incorrect pane Seatbelt authority")
				}
				authPath := fixtureFlagValue(args, "--auth-file")
				credential, err = os.Open(authPath)
				if err != nil {
					t.Fatalf("fixture auth did not reach fake terminal runner: %v", err)
				}
				t.Cleanup(func() { _ = credential.Close() })
				if tc.wantStage == "" {
					nonce := extractPromptNonce(t, terminal.PromptFilePath().String())
					out := findStagedOutputPath(t, lease.root, activeProfile.OutputFilename(tc.purpose))
					if err := os.WriteFile(out, []byte("fixture-result\n"+terminalCompletionNoncePrefix+nonce+"\n"), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				input := ports.TerminalExecutionObservationInput{
					Reported: tc.reported, ExitedBeforeReport: !tc.reported, ProgramStatus: tc.status, BlockedKind: tc.blocked,
				}
				if tc.status == ports.TerminalProgramStatusDone {
					input.TurnCount = 1
				}
				return makeTerminalSessionObservation(t, runner, terminal, input, tc.termination, tc.exit, tc.absent, nil, []byte(tc.stderr)), nil
			}
			var selected terminalProviderProfile = activeProfile
			if tc.beforeSpawn != "" {
				selected = beforeZCodeSpawnProfile{activeProfile, func(inv *terminalProfileInvocation) error {
					switch tc.beforeSpawn {
					case "drain":
						_, err := inv.Namespace.DrainTerminal(ctx)
						return err
					case "auth":
						p := fixtureFlagValue(inv.HostArgs, "--auth-file")
						return os.WriteFile(p, []byte(strings.Replace(zcodeFixtureAuth, "fixture-only", "fixture-edit", 1)), 0o600)
					case "package":
						root := filepath.Dir(filepath.Dir(activeProfile.pkg.Launcher.Path))
						return os.WriteFile(filepath.Join(root, "scripts", "toolchain.sh"), []byte("late package edit"), 0o600)
					default:
						p := fixtureFlagValue(inv.HostArgs, "--catalog-file")
						if err := os.Remove(p); err != nil {
							return err
						}
						return os.WriteFile(p, []byte(`{"schemaVersion":1,"revision":49}`), 0o400)
					}
				}}
			}
			result, err := executeTerminalInvocation(ctx, runner, selected, req)
			if tc.beforeSpawn != "" {
				if launched || !isProtectedQualificationSecurityFailure(err) {
					t.Fatalf("unsafe projection reached launch or lost its security category: %v", err)
				}
				if tc.beforeSpawn == "package" {
					var failure *ports.ProviderRuntimeError
					if !errors.As(err, &failure) || failure.Cause() != domain.DiagnosticCauseProviderOwnershipViolation ||
						failure.Unwrap() == nil || !strings.Contains(failure.Unwrap().Error(), "companion package drift") {
						t.Fatalf("late package change did not reach the package verifier: %v", err)
					}
				}
				return
			}
			if !launched {
				t.Fatalf("prepare-isolated and verified request did not reach fake runner: %v", err)
			}
			if tc.wantStage == "" {
				if err != nil || strings.TrimSpace(string(result.OutputBytes)) != "fixture-result" {
					t.Fatalf("staged output was not admitted: %v", err)
				}
			} else {
				var failure *terminalDriverFailure
				if !errors.As(err, &failure) || failure.Diagnostic() != tc.wantStage || failure.Status() != tc.wantStatus {
					t.Fatalf("wanted terminal failure %s: %v", tc.wantStage, err)
				}
				var classified *domain.Failure
				if !errors.As(classifyProbeFailure(ctx, FamilyZcode, err, nil), &classified) || classified.Class() != tc.wantClass {
					t.Fatalf("wanted qualifier class %s: %v", tc.wantClass, classified)
				}
			}
			if _, err := ns.DrainTerminal(ctx); err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(credential)
			if err != nil || !bytes.Equal(got, make([]byte, len(zcodeFixtureAuth))) {
				t.Fatal("projected credential inode was not zeroed")
			}
		})
	}
}

func fixtureFlagValue(args []string, flag string) string {
	index := slices.Index(args, flag)
	if index < 0 || index+1 == len(args) {
		return ""
	}
	return args[index+1]
}

func TestZCodeTerminalHostFailureProjection(t *testing.T) {
	for _, tc := range []struct {
		name, script, stage string
		cause               domain.RuntimeDiagnosticCause
	}{
		{"account", `printf '%s\n' '{"reason":"desktop_account_unavailable","message":"fixture"}'; exit 1`, "zcode_account_configuration", ""},
		{"secret failure payload", `printf '%s\n' '{"reason":"desktop_account_unavailable","message":"fixture","apiKey":"sensitive-fixture"}'; exit 1`, "", domain.DiagnosticCauseProviderOwnershipViolation},
		{"malformed failure", `printf '%s\n' '{"reason":'; exit 1`, "", domain.DiagnosticCauseProviderOwnershipViolation},
		{"empty message", `printf '%s\n' '{"reason":"desktop_account_unavailable","message":""}'; exit 1`, "", domain.DiagnosticCauseProviderOwnershipViolation},
		{"different exit", `printf '%s\n' '{"reason":"desktop_account_unavailable","message":"fixture"}'; exit 2`, "", domain.DiagnosticCauseProviderSpawnFailed},
		{"oversize", `head -c 16385 /dev/zero; exit 1`, "", domain.DiagnosticCauseProviderOwnershipViolation},
		{"unverified teardown", `kill -KILL "$$"`, "", domain.DiagnosticCauseProcessGroupCleanupFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			profile := zcodeTerminalProfile{pkg: fixtureZCodePackage(t, "#!/bin/sh\n"+tc.script+"\n")}
			_, err := profile.runPreparation(context.Background(), "/private/var/empty", t.TempDir())
			if err == nil || strings.Contains(err.Error(), "sensitive-fixture") {
				t.Fatalf("failure was lost or leaked: %v", err)
			}
			if tc.stage != "" {
				var failure *domain.Failure
				if !errors.As(err, &failure) || failure.Stage() != tc.stage {
					t.Fatalf("wrong prepare-isolated account stage: %v", err)
				}
				return
			}
			cancelled, cancel := context.WithCancel(context.Background())
			cancel()
			cause, _ := providerRunCauses(err)
			status, _ := providerFailureProjection(cause)
			var failure *domain.Failure
			if cause != tc.cause {
				t.Fatalf("wrong prepare-isolated cause: %v", err)
			}
			if tc.cause == domain.DiagnosticCauseProviderSpawnFailed {
				return
			}
			if status != ports.ProviderExecutionStatusSecurityViolation || !isProtectedQualificationSecurityFailure(err) ||
				!errors.As(classifyProbeFailure(cancelled, FamilyZcode, err, nil), &failure) || failure.Class() != domain.FailureSecurityPolicy {
				t.Fatalf("protected refusal was downgraded or hidden by cancellation: %v", err)
			}
		})
	}
}

func TestZCodeTerminalRunPreparationInterruptionProjection(t *testing.T) {
	const fixture = `#!/usr/bin/perl
use strict;
$SIG{TERM} = sub { exit 1; };
open(my $marker, '>', "$ARGV[2]/started") or die "open fixture marker";
close $marker or die "close fixture marker";
sleep 30;
exit 3;
`
	profile := zcodeTerminalProfile{pkg: fixtureZCodePackage(t, fixture)}
	for _, tc := range []struct {
		name       string
		parentWant error
	}{
		{"local budget", nil},
		{"parent deadline", context.DeadlineExceeded},
		{"parent cancellation", context.Canceled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tc.parentWant == context.DeadlineExceeded {
				var stopDeadline context.CancelFunc
				ctx, stopDeadline = context.WithTimeout(ctx, 2*time.Second)
				defer stopDeadline()
			}
			dir := t.TempDir()
			marker := filepath.Join(dir, "started")
			done := make(chan error, 1)
			go func() {
				_, err := profile.runPreparation(ctx, "/private/var/empty", dir)
				done <- err
			}()
			if tc.parentWant == context.Canceled {
				deadline := time.Now().Add(3 * time.Second)
				for time.Now().Before(deadline) {
					if _, err := os.Stat(marker); err == nil {
						break
					}
					time.Sleep(10 * time.Millisecond)
				}
				cancel()
			}
			err := <-done
			if _, err := os.Stat(marker); err != nil {
				t.Fatalf("synthetic companion never started: %v", err)
			}
			if tc.parentWant != nil {
				if err != tc.parentWant || ctx.Err() != tc.parentWant {
					t.Fatalf("parent interruption changed classification: got %v, want %v", err, tc.parentWant)
				}
				return
			}
			if ctx.Err() != nil || !errors.Is(err, herdr.ErrZCodeCompanionTimeout) ||
				errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("local budget was not distinguished from parent interruption: %v", err)
			}
			cause, _ := providerRunCauses(err)
			status, _ := providerFailureProjection(cause)
			if cause != domain.DiagnosticCauseTimedOut || status != ports.ProviderExecutionStatusTimedOut {
				t.Fatalf("local budget projected to cause %s and status %s", cause, status)
			}
			var failure *domain.Failure
			if !errors.As(classifyProbeFailure(ctx, FamilyZcode, err, nil), &failure) ||
				failure.Class() != domain.FailureTimeout {
				t.Fatalf("local budget did not retain its qualifier timeout class: %v", failure)
			}
		})
	}
}

func TestZCodeTerminalRuntimeSafetyPolicyBindsInputs(t *testing.T) {
	pkg := fixtureZCodePackage(t, "#!/bin/sh\nexit 0\n")
	runtime := defaultFakeTerminalIdentity(t)
	observed := zcodeFixtureReceipt("/unused").ZCodeTerminalObservation
	baseline, err := RuntimeSafetyPolicyForZCodeTerminal(runtime, pkg, "", observed, "", "")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		bundle, model, effort string
		observed              ZCodeTerminalObservation
	}{
		{bundle: "/Applications/Fixture.app", observed: observed},
		{model: "account:zai-individual-coding-plan/GLM-5.4", observed: observed},
		{effort: "max", observed: observed},
		{observed: ZCodeTerminalObservation{
			AppVersion: observed.AppVersion, CatalogRevision: observed.CatalogRevision + 1,
			CatalogSHA256: observed.CatalogSHA256, AccountIdentitySHA256: observed.AccountIdentitySHA256,
		}},
	} {
		policy, err := RuntimeSafetyPolicyForZCodeTerminal(runtime, pkg, tc.bundle, tc.observed, tc.model, tc.effort)
		if err != nil || policy.Identity() == baseline.Identity() {
			t.Fatalf("changed input did not partition runtime identity: %v", err)
		}
	}
}

func TestZCodeTerminalTamperedCompanionNeverStarts(t *testing.T) {
	profile := zcodeTerminalProfile{pkg: fixtureZCodePackage(t, "#!/bin/sh\nprintf reached > \"$3/launcher-ran\"\n")}
	member := filepath.Join(filepath.Dir(filepath.Dir(profile.pkg.Launcher.Path)), "scripts", "toolchain.sh")
	if err := os.WriteFile(member, []byte("tampered fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	_, err := profile.runPreparation(context.Background(), "/private/var/empty", dir)
	cause, _ := providerRunCauses(err)
	if cause != domain.DiagnosticCauseProviderOwnershipViolation {
		t.Fatalf("package drift lost its protected launch classification: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "launcher-ran")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("tampered package reached launcher: %v", err)
	}
}

func TestZCodeTerminalProjectionBindsAndDrainsIndependentLeases(t *testing.T) {
	ctx := context.Background()
	factory, err := NewNamespaceFactory(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	acquire := func(instance string) *namespaceLease {
		t.Helper()
		value, err := factory.AcquireProviderNamespace(ctx, instance, FamilyZcode)
		if err != nil {
			t.Fatal(err)
		}
		lease := value.(*namespaceLease)
		t.Cleanup(func() {
			if _, err := lease.DrainTerminal(ctx); err != nil {
				t.Errorf("fixture cleanup: %v", err)
			}
		})
		return lease
	}
	first, second := acquire("fixture_first"), acquire("fixture_second")
	project := func(lease *namespaceLease) string {
		t.Helper()
		lease.terminalMu.Lock()
		dir, err := retainZCodeProjectionDirectory(lease)
		lease.terminalMu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
		auth := filepath.Join(dir.Name(), "auth.json")
		if err := os.WriteFile(auth, []byte(zcodeFixtureAuth), 0o600); err != nil {
			t.Fatal(err)
		}
		return auth
	}
	firstAuth := project(first)
	profile := fixtureZCodeTerminalProfile(t)
	f := newTerminalTestFixture(t)
	binding := terminalProfileInvocation{
		Definition: RuntimeDefinition{
			family: FamilyZcode, executable: profile.pkg.Launcher.Path, executableSHA256: profile.pkg.Launcher.SHA256,
		},
		Namespace: second, NamespaceRoot: second.root, NativeHome: f.nativeHome,
	}
	matching := binding
	if _, err := profile.PrepareHost(ctx, &matching); err != nil {
		t.Fatalf("matching namespace control failed: %v", err)
	}
	secondAuth := fixtureFlagValue(matching.HostArgs, "--auth-file")
	mismatched := binding
	mismatched.NamespaceRoot = first.root
	if _, err := profile.PrepareHost(ctx, &mismatched); !isProtectedQualificationSecurityFailure(err) {
		t.Fatalf("cross-namespace input did not fail closed: %v", err)
	}
	other := zcodeFixtureReceipt(filepath.Dir(secondAuth))
	receipt, err := json.Marshal(other)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := profile.validatePreparationReceipt(receipt, filepath.Dir(firstAuth)); !isProtectedQualificationSecurityFailure(err) {
		t.Fatalf("cross-namespace receipt did not fail closed: %v", err)
	}
	if _, err := first.DrainTerminal(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(firstAuth); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("first projection survived its drain")
	}
	if data, err := os.ReadFile(secondAuth); err != nil || string(data) != zcodeFixtureAuth {
		t.Fatal("first drain touched the second projection")
	}
}

func TestZCodeTerminalDrainRefusesUnsafeAuthLinks(t *testing.T) {
	for _, link := range []struct {
		name string
		make func(string, string) error
	}{{"symlink", os.Symlink}, {"hardlink", os.Link}} {
		t.Run(link.name, func(t *testing.T) {
			ctx := context.Background()
			factory, err := NewNamespaceFactory(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			value, err := factory.AcquireProviderNamespace(ctx, "fixture_forbidden", FamilyZcode)
			if err != nil {
				t.Fatal(err)
			}
			lease := value.(*namespaceLease)
			t.Cleanup(func() { _, _ = lease.DrainTerminal(ctx) })
			lease.terminalMu.Lock()
			dir, err := retainZCodeProjectionDirectory(lease)
			lease.terminalMu.Unlock()
			if err != nil {
				t.Fatal(err)
			}
			outside := filepath.Join(t.TempDir(), "unowned-auth")
			if err := os.WriteFile(outside, []byte(zcodeFixtureAuth), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := link.make(outside, filepath.Join(dir.Name(), "auth.json")); err != nil {
				t.Fatal(err)
			}
			if _, err := lease.DrainTerminal(ctx); !isProtectedQualificationSecurityFailure(err) {
				t.Fatalf("unsafe drain link was not rejected: %v", err)
			}
			if data, err := os.ReadFile(outside); err != nil || string(data) != zcodeFixtureAuth {
				t.Fatal("drain modified the linked foreign inode")
			}
		})
	}
}
