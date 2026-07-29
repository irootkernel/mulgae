//go:build darwin && arm64

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/adapters/cli"
	adapterconfig "github.com/irootkernel/mulgae/internal/adapters/config"
	"github.com/irootkernel/mulgae/internal/adapters/filesystem"
	"github.com/irootkernel/mulgae/internal/adapters/gittarget"
	"github.com/irootkernel/mulgae/internal/adapters/providercli"
	"github.com/irootkernel/mulgae/internal/app/reviewrun"
	"github.com/irootkernel/mulgae/internal/builtin"
	"github.com/irootkernel/mulgae/internal/domain"
	mulgaeentry "github.com/irootkernel/mulgae/internal/entrypoint/mulgae"
	"github.com/irootkernel/mulgae/internal/ports"
)

func TestChildPublicationRootUsesPrivateMulgaeNamespace(t *testing.T) {
	projectPath := filepath.Join(t.TempDir(), "project")
	project, err := ports.NewAnchoredRoot(projectPath)
	if err != nil {
		t.Fatal(err)
	}
	root, err := childPublicationRoot(project)
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(projectPath, ".mulgae"); root.String() != want {
		t.Fatalf("child publication root = %q, want %q", root.String(), want)
	}
}

func TestConfiguredQualificationRolesFollowPrimaryAndFallbackMatrix(t *testing.T) {
	config, err := adapterconfig.CanonicalRolesConfig([]string{"kimi", "zcode", "agy"})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		family reviewrun.Family
		roles  []domain.Role
		base   domain.Role
	}{
		{reviewrun.FamilyKimi, []domain.Role{domain.RoleLogic}, domain.RoleLogic},
		{reviewrun.FamilyZCode, domain.CoreRoleOrder(), domain.RoleSecurity},
		{reviewrun.FamilyAGY, []domain.Role{domain.RoleSecurity, domain.RoleMaintainability, domain.RoleProduct, domain.RoleDocumentation, domain.RoleTesting}, domain.RoleDocumentation},
	}
	for _, test := range tests {
		roles, base := configuredQualificationRoles(config, domain.CoreRoleOrder(), test.family)
		if !slices.Equal(roles, test.roles) || base != test.base {
			t.Fatalf("%s qualification roles/base = %v/%s, want %v/%s", test.family, roles, base, test.roles, test.base)
		}
	}
}

type childContextDetector struct{ err error }

func (detector childContextDetector) DetectReviewInput(context.Context, ports.ReviewInputChannel, string, []byte) (ports.ReviewInputDetection, error) {
	return ports.ReviewInputDetection{}, detector.err
}

type childObservedProvider struct{ calls int }

func (provider *childObservedProvider) Observe(context.Context, ports.ProviderInvocation) (ports.ProviderExecutionObservation, error) {
	provider.calls++
	return ports.ProviderExecutionObservation{}, nil
}

func TestChildPacketScreeningProviderPreservesContextTermination(t *testing.T) {
	for _, detectorErr := range []error{context.Canceled, context.DeadlineExceeded} {
		t.Run(detectorErr.Error(), func(t *testing.T) {
			provider := &childObservedProvider{}
			screened := newChildPacketScreeningProvider(provider, childContextDetector{err: detectorErr})
			_, err := screened.Observe(context.Background(), ports.ProviderInvocation{})
			if !errors.Is(err, detectorErr) || screened.blocked || provider.calls != 0 {
				t.Fatal("context termination was converted into a packet-security rejection")
			}
		})
	}
}

type reviewConfigMutatingAttestor struct {
	path    string
	mutated bool
}

func (attestor *reviewConfigMutatingAttestor) Attest(context.Context, ports.ConfigLocalityRequest) (ports.ConfigLocalityContext, error) {
	return ports.ConfigLocalityContext{}, nil
}
func (attestor *reviewConfigMutatingAttestor) Revalidate(context.Context, ports.ConfigLocalityRequest, ports.ConfigLocalityContext) error {
	if attestor.mutated {
		return nil
	}
	attestor.mutated = true
	return os.WriteFile(attestor.path, []byte("version: 2\n"), 0o600)
}

type recordingReviewSpawnVerifier struct{ called bool }

type writeFunc func([]byte) (int, error)

func (function writeFunc) Write(value []byte) (int, error) { return function(value) }

func (verifier *recordingReviewSpawnVerifier) VerifyProviderSpawn(context.Context, providercli.RuntimeDefinition) error {
	verifier.called = true
	return nil
}

func TestBuildIdentityFrom(t *testing.T) {
	const commit = "0123456789abcdef0123456789abcdef01234567"
	release := &debug.BuildInfo{
		Main: debug.Module{Path: modulePath, Version: "v1.4.2"},
		Settings: []debug.BuildSetting{
			{Key: "vcs.revision", Value: commit},
			{Key: "vcs.modified", Value: "false"},
		},
	}
	identity, err := buildIdentityFrom(release, "", "")
	if err != nil {
		t.Fatalf("release metadata rejected: %v", err)
	}
	if want := "mulgae"; identity.Product != want {
		t.Fatalf("product = %q, want %q", identity.Product, want)
	}
	if want := "v1.4.2"; identity.Version != want {
		t.Fatalf("version = %q, want %q", identity.Version, want)
	}
	if identity.VCSRevision != commit {
		t.Fatalf("VCS revision = %q, want %q", identity.VCSRevision, commit)
	}

	for name, info := range map[string]*debug.BuildInfo{
		"devel":              {Main: debug.Module{Path: modulePath, Version: "(devel)"}, Settings: release.Settings},
		"missing provenance": {Main: debug.Module{Path: modulePath, Version: "v1.4.2"}},
		"wrong module":       {Main: debug.Module{Path: "example.com/wrong", Version: "v1.4.2", Sum: "h1:sum"}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := buildIdentityFrom(info, "", ""); err == nil {
				t.Fatal("production metadata accepted")
			}
		})
	}

	linked, err := buildIdentityFrom(
		&debug.BuildInfo{Main: debug.Module{Path: modulePath, Version: "(devel)"}},
		"v1.4.2",
		commit,
	)
	if err != nil {
		t.Fatalf("explicit linker metadata rejected: %v", err)
	}
	if linked != identity {
		t.Fatalf("linked identity = %#v, want %#v", linked, identity)
	}

	moduleRelease := &debug.BuildInfo{
		Main: debug.Module{Path: modulePath, Version: "v0.1.0", Sum: "h1:module-sum"},
	}
	moduleIdentity, err := buildIdentityFrom(moduleRelease, "", "")
	if err != nil {
		t.Fatalf("tagged module metadata rejected: %v", err)
	}
	if moduleIdentity.ModuleSum != "h1:module-sum" || moduleIdentity.VCSRevision != "" ||
		moduleIdentity.ImmutableReference() != "h1:module-sum" {
		t.Fatalf("tagged module identity = %#v", moduleIdentity)
	}
}

func TestVersionOutputDoesNotRequireProjectOrReleaseMetadata(t *testing.T) {
	info := &debug.BuildInfo{Main: debug.Module{Path: modulePath, Version: "(devel)"}}
	var stdout, stderr bytes.Buffer
	handled, exitCode := handleVersion([]string{"--version"}, &stdout, &stderr, info)
	if !handled || exitCode != 0 || stdout.String() != "mulgae (devel)\n" || stderr.Len() != 0 {
		t.Fatalf("version result = handled:%t exit:%d stdout:%q stderr:%q", handled, exitCode, stdout.String(), stderr.String())
	}

	stdout.Reset()
	handled, exitCode = handleVersion([]string{"version", "--json"}, &stdout, &stderr, info)
	if !handled || exitCode != 0 {
		t.Fatalf("JSON version result = handled:%t exit:%d stderr:%q", handled, exitCode, stderr.String())
	}
	var got versionInfo
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.SchemaVersion != "mulgae-version.v1" || got.Product != productName ||
		got.Version != "(devel)" || got.Module != modulePath ||
		got.ModuleSum != nil || got.VCSRevision != nil {
		t.Fatalf("JSON version = %#v", got)
	}

	stdout.Reset()
	stderr.Reset()
	handled, exitCode = handleVersion([]string{"version", "--output", "json"}, &stdout, &stderr, info)
	if !handled || exitCode != 2 || stdout.Len() != 0 ||
		stderr.String() != "mulgae: usage: mulgae version [--json]\n" {
		t.Fatalf("legacy JSON version result = handled:%t exit:%d stdout:%q stderr:%q", handled, exitCode, stdout.String(), stderr.String())
	}
}
func TestStartupTempRootCanonicalizesDarwinEnvironmentValue(t *testing.T) {
	root := canonicalTestTempDir(t)
	link := filepath.Join(canonicalTestTempDir(t), "temp-link")
	if err := os.Symlink(root, link); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", link+string(filepath.Separator))
	got, err := startupTempRoot()
	if err != nil {
		t.Fatal(err)
	}
	if got != root {
		t.Fatalf("startup temp root = %q, want %q", got, root)
	}

	t.Setenv("TMPDIR", "")
	got, err = startupTempRoot()
	if err != nil {
		t.Fatal(err)
	}
	if got != "" {
		t.Fatalf("empty startup temp root = %q", got)
	}
}

func TestProductionLaneLockRootUsesStableRuntimeNamespace(t *testing.T) {
	writer := filesystem.NewSecureWriter()
	uid := uint64(os.Geteuid())

	t.Run("xdg runtime directory", func(t *testing.T) {
		xdg := canonicalTestTempDir(t)
		fallback := canonicalTestTempDir(t)
		t.Setenv("XDG_RUNTIME_DIR", xdg)
		t.Setenv("TMPDIR", fallback)

		first, err := productionLaneLockRoot(writer, uid)
		if err != nil {
			t.Fatal(err)
		}
		second, err := productionLaneLockRoot(writer, uid)
		if err != nil {
			t.Fatal(err)
		}
		want := filepath.Join(xdg, "mulgae")
		if first.String() != want || second != first {
			t.Fatalf("production lane lock roots = %q/%q, want stable %q", first.String(), second.String(), want)
		}
		assertPrivateRuntimeDirectory(t, want)
		if _, err := os.Lstat(filepath.Join(fallback, "mulgae-"+strconv.FormatUint(uid, 10))); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("TMPDIR fallback used while XDG_RUNTIME_DIR was available: %v", err)
		}
	})

	t.Run("TMPDIR fallback", func(t *testing.T) {
		temp := canonicalTestTempDir(t)
		t.Setenv("XDG_RUNTIME_DIR", "")
		t.Setenv("TMPDIR", temp)

		root, err := productionLaneLockRoot(writer, uid)
		if err != nil {
			t.Fatal(err)
		}
		want := filepath.Join(temp, "mulgae-"+strconv.FormatUint(uid, 10))
		if root.String() != want {
			t.Fatalf("production lane lock root = %q, want %q", root.String(), want)
		}
		assertPrivateRuntimeDirectory(t, want)
	})
}

func TestProductionLaneLockRootFailsClosedWithoutSafeRuntimeBase(t *testing.T) {
	writer := filesystem.NewSecureWriter()
	uid := uint64(os.Geteuid())

	for _, test := range []struct {
		name string
		xdg  string
		temp string
	}{
		{name: "missing", xdg: "", temp: ""},
		{name: "relative XDG", xdg: "relative/runtime", temp: canonicalTestTempDir(t)},
		{name: "unavailable XDG", xdg: filepath.Join(canonicalTestTempDir(t), "missing"), temp: canonicalTestTempDir(t)},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("XDG_RUNTIME_DIR", test.xdg)
			t.Setenv("TMPDIR", test.temp)
			if root, err := productionLaneLockRoot(writer, uid); err == nil || root.Valid() {
				t.Fatalf("unsafe runtime base produced root %#v, error %v", root, err)
			}
		})
	}

	t.Run("world writable XDG", func(t *testing.T) {
		xdg := canonicalTestTempDir(t)
		if err := os.Chmod(xdg, 0o777); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(xdg, 0o700) })
		t.Setenv("XDG_RUNTIME_DIR", xdg)
		t.Setenv("TMPDIR", canonicalTestTempDir(t))
		if root, err := productionLaneLockRoot(writer, uid); err == nil || root.Valid() {
			t.Fatalf("world-writable runtime base produced root %#v, error %v", root, err)
		}
	})
}

func assertPrivateRuntimeDirectory(t *testing.T, path string) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		t.Fatalf("private runtime directory %q = %#v, %v", path, info, err)
	}
}

func assertNoProjectLaneLocks(t *testing.T, project string) {
	t.Helper()
	if _, err := os.Lstat(filepath.Join(project, "locks")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Mulgae created a lane-lock namespace in the review target: %v", err)
	}
}

func TestReviewCompositionPolicyReadFailuresFailClosed(t *testing.T) {
	root, err := ports.NewAnchoredRoot(canonicalTestTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	reader, readerErr := gittarget.New(gittarget.NewExecRunner())
	if readerErr != nil {
		t.Fatal(readerErr)
	}
	_, err = resolveProductionRunPolicy(context.Background(), root, reader)
	var failure *domain.Failure
	if !errors.As(err, &failure) || failure.Class() != domain.FailureConfiguration {
		t.Fatalf("missing local configuration = %#v, want configuration failure", err)
	}
}
func TestProductionConfigCredentialFailuresRemainSecurityFailures(t *testing.T) {
	for _, test := range []struct {
		name, yaml, reason string
	}{
		{name: "credential key", yaml: "api_key: redacted\n", reason: string(adapterconfig.ReasonCredentialKeyDetected)},
		{name: "credential value", yaml: "note: \"Bearer abcdefghijklmnop\"\n", reason: string(adapterconfig.ReasonCredentialValueDetected)},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, admissionErr := adapterconfig.Decode([]byte(test.yaml))
			if admissionErr == nil {
				t.Fatal("credential-bearing configuration was accepted")
			}
			classified := productionConfigResolutionFailure(admissionErr)
			var failure *domain.Failure
			if !errors.As(classified, &failure) || failure.Class() != domain.FailureSecurityPolicy || failure.Reason() != test.reason {
				t.Fatalf("credential failure = %#v, want security/%s", classified, test.reason)
			}
		})
	}
}

func TestProviderSpawnRejectsConfigMutationAfterLocalityAttestation(t *testing.T) {
	rootPath := canonicalTestTempDir(t)
	if err := os.Mkdir(filepath.Join(rootPath, ".mulgae"), 0o700); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(rootPath, ".mulgae", "config.yaml")
	if err := os.WriteFile(configPath, []byte("version: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := ports.NewAnchoredRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	source, err := adapterconfig.NewLocalConfigSource(root, false)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := source.Observation().Proof()
	if err != nil {
		t.Fatal(err)
	}
	request, err := ports.NewConfigLocalityRequest(root, proof, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	attestor := &reviewConfigMutatingAttestor{path: configPath}
	inner := &recordingReviewSpawnVerifier{}
	verifier := localitySpawnVerifier{inner: inner, source: source, attestor: attestor, request: request}
	if err := verifier.VerifyProviderSpawn(context.Background(), providercli.RuntimeDefinition{}); err == nil {
		t.Fatal("provider spawn accepted config mutation")
	}
	if !attestor.mutated || inner.called {
		t.Fatalf("mutated=%t inner_called=%t", attestor.mutated, inner.called)
	}
}
func TestReviewCompositionConstructorFailureCleansTemporaryRoots(t *testing.T) {
	workspace, err := ports.NewAnchoredRoot(canonicalTestTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	namespace, err := ports.NewAnchoredRoot(canonicalTestTempDir(t))
	if err != nil {
		t.Fatal(err)
	}

	if err := cleanupReviewCompositionRoots(true, namespace, workspace); err != nil {
		t.Fatal(err)
	}

	for _, root := range []ports.AnchoredRoot{workspace, namespace} {
		if _, err := os.Lstat(root.String()); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("constructor failure retained temporary root %q: %v", root.String(), err)
		}
	}
}

type failingReviewRunService struct{ err error }

func (service failingReviewRunService) StartReviewRun(context.Context, mulgaeentry.ReviewRequest, ports.AnchoredRoot) (mulgaeentry.ReviewRunResult, error) {
	return mulgaeentry.ReviewRunResult{}, service.err
}

func TestReviewCompositionCleanupFailureIsArtifactFailureAndPreservesPrimaryError(t *testing.T) {
	lockedParent := t.TempDir()
	lockedPath := filepath.Join(lockedParent, "namespace")
	if err := os.Mkdir(lockedPath, 0o700); err != nil {
		t.Fatal(err)
	}
	lockedRoot, err := ports.NewAnchoredRoot(lockedPath)
	if err != nil {
		t.Fatal(err)
	}
	removablePath := canonicalTestTempDir(t)
	removableRoot, err := ports.NewAnchoredRoot(removablePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(lockedParent, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(lockedParent, 0o700) })

	primary := errors.New("injected review failure")
	service := &rootCleaningReviewRunService{
		inner: failingReviewRunService{err: primary},
		graph: &productionRuntimeGraph{namespaceRoot: lockedRoot, workspaceRoot: removableRoot},
	}
	_, err = service.StartReviewRun(context.Background(), mulgaeentry.ReviewRequest{}, ports.AnchoredRoot{})
	if !errors.Is(err, primary) {
		t.Fatalf("cleanup error lost primary failure: %v", err)
	}
	var failure *domain.Failure
	if !errors.As(err, &failure) || failure.Class() != domain.FailureArtifact {
		t.Fatalf("cleanup error = %#v, want joined artifact failure", err)
	}
	if _, statErr := os.Lstat(removablePath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("cleanup stopped after first root failure; second root status: %v", statErr)
	}
	if _, statErr := os.Lstat(lockedPath); statErr != nil {
		t.Fatalf("injected failing root unexpectedly removed: %v", statErr)
	}
}

func TestUnavailableBuildMetadataIsArtifactFailure(t *testing.T) {
	cause := errors.New("missing release provenance")
	err := unavailableBuildMetadata(cause)
	if !errors.Is(err, cause) {
		t.Fatalf("build metadata failure = %v, want wrapped cause", err)
	}
	var failure *domain.Failure
	if !errors.As(err, &failure) || failure.Class() != domain.FailureArtifact {
		t.Fatalf("build metadata failure = %#v, want artifact failure", err)
	}
}

func TestDeferredReviewRunServiceDoesNotComposeAtConstruction(t *testing.T) {
	sentinel := errors.New("composed on demand")
	compositions := 0
	service := newDeferredReviewRunService(func(context.Context, ports.AnchoredRoot) (mulgaeentry.ReviewRunService, error) {
		compositions++
		return nil, sentinel
	})
	if _, ok := service.(mulgaeentry.ReviewRunServicePreparer); !ok {
		t.Fatal("deferred review service does not expose preparation boundary")
	}
	if compositions != 0 {
		t.Fatalf("review compositions at construction = %d, want 0", compositions)
	}
	_, err := service.StartReviewRun(context.Background(), mulgaeentry.ReviewRequest{}, ports.AnchoredRoot{})
	if !errors.Is(err, sentinel) || compositions != 1 {
		t.Fatalf("deferred review = error %v compositions %d, want sentinel/1", err, compositions)
	}
}

func TestDeliverOutputClassifiesInitCommitDeliveryFailure(t *testing.T) {
	for _, test := range []struct {
		name       string
		writer     writeFunc
		argv       []string
		wantExit   int
		wantStderr string
	}{
		{name: "init short write", writer: func(value []byte) (int, error) { return len(value) - 1, nil }, argv: []string{"init", "--output", "json"}, wantExit: 7, wantStderr: "mulgae: init committed .mulgae/config.yaml; result delivery failed\n"},
		{name: "init write error", writer: func([]byte) (int, error) { return 0, syscall.EPIPE }, argv: []string{"init"}, wantExit: 7, wantStderr: "mulgae: init committed .mulgae/config.yaml; result delivery failed\n"},
		{name: "other command", writer: func([]byte) (int, error) { return 0, syscall.EPIPE }, argv: []string{"help"}, wantExit: 10, wantStderr: "mulgae: standard output write failed\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var stderr bytes.Buffer
			if got := deliverOutput(test.writer, &stderr, []byte("result\n"), nil, 0, test.argv); got != test.wantExit || stderr.String() != test.wantStderr {
				t.Fatalf("delivery = exit %d stderr %q", got, stderr.String())
			}
		})
	}
}

func TestIntegrationMulgaeBinaryBoundary(t *testing.T) {
	root := repositoryRoot(t)
	binary := buildMulgaeBinary(t, root)

	t.Run("version outside project", func(t *testing.T) {
		directory := t.TempDir()
		human := runMulgaeBinary(t, binary, directory, "--version")
		if human.exitCode != 0 || string(human.stdout) != "mulgae v1.4.2\n" || len(human.stderr) != 0 {
			t.Fatalf("human version = exit %d stdout %q stderr %q", human.exitCode, human.stdout, human.stderr)
		}
		machine := runMulgaeBinary(t, binary, directory, "version", "--json")
		if machine.exitCode != 0 || len(machine.stderr) != 0 {
			t.Fatalf("JSON version = exit %d stdout %q stderr %q", machine.exitCode, machine.stdout, machine.stderr)
		}
		var version versionInfo
		if err := json.Unmarshal(machine.stdout, &version); err != nil {
			t.Fatal(err)
		}
		if version.Product != productName || version.Version != "v1.4.2" || version.Module != modulePath ||
			version.ModuleSum != nil || version.VCSRevision == nil ||
			*version.VCSRevision != "0123456789abcdef0123456789abcdef01234567" {
			t.Fatalf("JSON version = %#v", version)
		}
	})

	t.Run("authoritative help", func(t *testing.T) {
		catalog := builtin.NewCatalog()
		for _, topic := range []string{
			"quickstart", "config", "providers", "lanes", "prompts",
			"workflows", "artifacts", "validation", "ci", "exit-codes", "security",
		} {
			t.Run(topic, func(t *testing.T) {
				id := mustAssetID(t, "help:"+topic)
				_, authoritative, err := catalog.Read(context.Background(), id)
				if err != nil {
					t.Fatalf("read authoritative help: %v", err)
				}

				got := runMulgaeBinary(t, binary, t.TempDir(), "help", topic)
				if got.exitCode != 0 || len(got.stderr) != 0 {
					t.Fatalf("help %q = exit %d stdout %q stderr %q", topic, got.exitCode, got.stdout, got.stderr)
				}
				want := terminalLF(authoritative)
				if !bytes.Equal(got.stdout, want) {
					t.Fatalf("help %q bytes differ from authoritative asset\n got: %q\nwant: %q", topic, got.stdout, want)
				}
			})
		}
	})

	t.Run("help never opens project config", func(t *testing.T) {
		workingDirectory := t.TempDir()
		privateDirectory := filepath.Join(workingDirectory, ".mulgae")
		if err := os.Mkdir(privateDirectory, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := syscall.Mkfifo(filepath.Join(privateDirectory, "config.yaml"), 0o600); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, binary, "help", "quickstart")
		command.Dir = workingDirectory
		command.Env = isolatedMulgaeEnv(t)
		output, err := command.CombinedOutput()
		if ctx.Err() != nil {
			t.Fatal("help blocked while opening project config")
		}
		if err != nil {
			t.Fatalf("help failed: %v: %s", err, output)
		}
		if len(output) == 0 {
			t.Fatal("help returned no embedded documentation")
		}
	})

	t.Run("all provider subsets use canonical order", func(t *testing.T) {
		installed, err := user.Current()
		if err != nil || installed == nil {
			t.Fatalf("current native account unavailable: %#v %v", installed, err)
		}
		providerDirectory := canonicalTestTempDir(t)
		paths := map[string]string{
			"kimi":  filepath.Join(providerDirectory, "kimi"),
			"zcode": filepath.Join(providerDirectory, "zcode-node"),
			"agy":   filepath.Join(providerDirectory, "agy"),
		}
		for _, path := range paths {
			mustWriteTestFile(t, path, []byte("#!/bin/sh\nexit 0\n"))
			if err := os.Chmod(path, 0o700); err != nil {
				t.Fatal(err)
			}
		}
		launcher := filepath.Join(providerDirectory, "zcode-launcher.cjs")
		mustWriteTestFile(t, launcher, []byte("module.exports = {};\n"))
		environment := isolatedMulgaeEnvWith(t, installed.HomeDir, providerDirectory)
		for _, test := range []struct {
			name     string
			input    string
			expected []string
		}{
			{name: "kimi", input: "kimi", expected: []string{"kimi"}},
			{name: "zcode", input: "zcode", expected: []string{"zcode"}},
			{name: "agy", input: "agy", expected: []string{"agy"}},
			{name: "kimi zcode", input: "zcode,kimi", expected: []string{"kimi", "zcode"}},
			{name: "kimi agy", input: "agy,kimi", expected: []string{"kimi", "agy"}},
			{name: "zcode agy", input: "agy,zcode", expected: []string{"zcode", "agy"}},
			{name: "all", input: "agy,zcode,kimi", expected: []string{"kimi", "zcode", "agy"}},
		} {
			t.Run(test.name, func(t *testing.T) {
				project := canonicalTestTempDir(t)
				initializeReviewGitRepository(t, project)
				arguments := []string{"init", "--providers", test.input, "--output", "json"}
				for _, family := range test.expected {
					switch family {
					case "kimi":
						arguments = append(arguments, "--kimi-executable", paths[family])
					case "zcode":
						arguments = append(arguments, "--zcode-node-executable", paths[family], "--zcode-launcher", launcher)
					case "agy":
						arguments = append(arguments, "--agy-executable", paths[family], "--agy-permission-mode", "safe")
					}
				}
				result := runMulgaeBinaryWithEnv(t, binary, project, environment, arguments...)
				if result.exitCode != 0 || len(result.stderr) != 0 {
					t.Fatalf("init subset %q = exit %d stdout %q stderr %q", test.input, result.exitCode, result.stdout, result.stderr)
				}
				var envelope struct {
					Request struct {
						Selection struct {
							ProviderIDs []string `json:"provider_ids"`
						} `json:"selection"`
					} `json:"request"`
					Result struct {
						Selected   []string `json:"selected_provider_ids"`
						Candidates []string `json:"candidate_provider_ids"`
						Configured []string `json:"configured_provider_ids"`
					} `json:"result"`
				}
				if err := json.Unmarshal(result.stdout, &envelope); err != nil {
					t.Fatal(err)
				}
				if !slices.Equal(envelope.Request.Selection.ProviderIDs, test.expected) || !slices.Equal(envelope.Result.Selected, test.expected) || !slices.Equal(envelope.Result.Candidates, test.expected) || !slices.Equal(envelope.Result.Configured, test.expected) {
					t.Fatalf("canonical provider order = request %v selected %v candidates %v configured %v, want %v", envelope.Request.Selection.ProviderIDs, envelope.Result.Selected, envelope.Result.Candidates, envelope.Result.Configured, test.expected)
				}
				data, err := os.ReadFile(filepath.Join(project, ".mulgae", "config.yaml"))
				if err != nil {
					t.Fatal(err)
				}
				config, err := (adapterconfig.YAMLCodec{}).Decode(data)
				if err != nil {
					t.Fatal(err)
				}
				if got := config.Providers.Families(); !slices.Equal(got, test.expected) {
					t.Fatalf("config provider order = %v, want %v", got, test.expected)
				}
			})
		}
	})

	t.Run("auto discovery covers zero through three providers in human and json modes", func(t *testing.T) {
		installed, err := user.Current()
		if err != nil || installed == nil {
			t.Fatalf("current native account unavailable: %#v %v", installed, err)
		}
		overrideDirectory := canonicalTestTempDir(t)
		emptyPATH := canonicalTestTempDir(t)
		paths := map[string]string{
			"kimi":     filepath.Join(overrideDirectory, "kimi-override"),
			"node":     filepath.Join(overrideDirectory, "node-override"),
			"launcher": filepath.Join(overrideDirectory, "zcode-launcher.cjs"),
			"agy":      filepath.Join(overrideDirectory, "agy-override"),
			"data":     filepath.Join(overrideDirectory, "kimi-data"),
		}
		for _, path := range []string{paths["kimi"], paths["node"], paths["agy"]} {
			mustWriteTestFile(t, path, []byte("#!/bin/sh\nexit 0\n"))
			if err := os.Chmod(path, 0o700); err != nil {
				t.Fatal(err)
			}
		}
		mustWriteTestFile(t, paths["launcher"], []byte("module.exports = {};\n"))
		if err := os.Mkdir(paths["data"], 0o700); err != nil {
			t.Fatal(err)
		}
		environment := isolatedMulgaeEnvWith(t, installed.HomeDir, emptyPATH)
		for _, providerCount := range []int{0, 1, 2, 3} {
			for _, format := range []string{"human", "json"} {
				t.Run(fmt.Sprintf("%d_%s", providerCount, format), func(t *testing.T) {
					project := canonicalTestTempDir(t)
					initializeReviewGitRepository(t, project)
					arguments := []string{"init", "--providers", "auto", "--name", "auto-project"}
					expected := []string{}
					if providerCount >= 1 {
						arguments = append(arguments, "--agy-executable", paths["agy"])
						expected = append(expected, "agy")
					}
					if providerCount >= 2 {
						arguments = append(arguments, "--kimi-executable", paths["kimi"], "--kimi-model", "kimi-code/kimi-for-coding", "--kimi-data-home", paths["data"])
						expected = []string{"kimi", "agy"}
					}
					if providerCount >= 3 {
						arguments = append(arguments, "--zcode-node-executable", paths["node"], "--zcode-launcher", paths["launcher"], "--agy-permission-mode", "safe", "--native-home", installed.HomeDir)
						expected = []string{"kimi", "zcode", "agy"}
					}
					if format == "json" {
						arguments = append(arguments, "--output", "json")
					}
					result := runMulgaeBinaryWithEnv(t, binary, project, environment, arguments...)
					if providerCount == 0 {
						if result.exitCode != 4 || len(result.stderr) != 0 || len(result.stdout) == 0 {
							t.Fatalf("auto zero = exit %d stdout %q stderr %q", result.exitCode, result.stdout, result.stderr)
						}
						if _, err := os.Lstat(filepath.Join(project, ".mulgae")); !errors.Is(err, os.ErrNotExist) {
							t.Fatalf("auto zero mutated project: %v", err)
						}
						return
					}
					if result.exitCode != 0 || len(result.stderr) != 0 || len(result.stdout) == 0 {
						t.Fatalf("auto %d = exit %d stdout %q stderr %q", providerCount, result.exitCode, result.stdout, result.stderr)
					}
					data, err := os.ReadFile(filepath.Join(project, ".mulgae", "config.yaml"))
					if err != nil {
						t.Fatal(err)
					}
					config, err := (adapterconfig.YAMLCodec{}).Decode(data)
					if err != nil || !slices.Equal(config.Providers.Families(), expected) {
						t.Fatalf("auto config families = %v err=%v, want %v", config.Providers.Families(), err, expected)
					}
					if format == "json" {
						var envelope struct {
							Request struct {
								Selection struct {
									Mode string `json:"mode"`
								} `json:"selection"`
							} `json:"request"`
							Result struct {
								Candidates []string `json:"candidate_provider_ids"`
								Configured []string `json:"configured_provider_ids"`
							} `json:"result"`
						}
						if err := json.Unmarshal(result.stdout, &envelope); err != nil || envelope.Request.Selection.Mode != "auto" || !slices.Equal(envelope.Result.Candidates, expected) || !slices.Equal(envelope.Result.Configured, expected) {
							t.Fatalf("auto JSON projection = %#v err=%v", envelope, err)
						}
					}
				})
			}
		}
	})

	t.Run("agy safe omission equals explicit safe and init never overwrites", func(t *testing.T) {
		installed, err := user.Current()
		if err != nil || installed == nil {
			t.Fatalf("current native account unavailable: %#v %v", installed, err)
		}
		providerDirectory := canonicalTestTempDir(t)
		agy := filepath.Join(providerDirectory, "agy")
		mustWriteTestFile(t, agy, []byte("#!/bin/sh\nexit 0\n"))
		if err := os.Chmod(agy, 0o700); err != nil {
			t.Fatal(err)
		}
		environment := isolatedMulgaeEnvWith(t, installed.HomeDir, providerDirectory)
		projects := []string{canonicalTestTempDir(t), canonicalTestTempDir(t)}
		for _, project := range projects {
			initializeReviewGitRepository(t, project)
		}
		base := []string{"init", "--name", "safe-project", "--providers", "agy", "--agy-executable", agy, "--output", "json"}
		omitted := runMulgaeBinaryWithEnv(t, binary, projects[0], environment, base...)
		explicitArguments := append(append([]string(nil), base...), "--agy-permission-mode", "safe")
		explicit := runMulgaeBinaryWithEnv(t, binary, projects[1], environment, explicitArguments...)
		if omitted.exitCode != 0 || explicit.exitCode != 0 {
			t.Fatalf("safe init exits = omitted %d explicit %d", omitted.exitCode, explicit.exitCode)
		}
		omittedConfig, err := os.ReadFile(filepath.Join(projects[0], ".mulgae", "config.yaml"))
		if err != nil {
			t.Fatal(err)
		}
		explicitConfig, err := os.ReadFile(filepath.Join(projects[1], ".mulgae", "config.yaml"))
		if err != nil || !bytes.Equal(omittedConfig, explicitConfig) {
			t.Fatalf("safe omission and explicit bytes differ: %v", err)
		}
		repeated := runMulgaeBinaryWithEnv(t, binary, projects[1], environment, explicitArguments...)
		if repeated.exitCode != 2 || len(repeated.stderr) != 0 {
			t.Fatalf("repeat init = exit %d stdout %q stderr %q", repeated.exitCode, repeated.stdout, repeated.stderr)
		}
		after, err := os.ReadFile(filepath.Join(projects[1], ".mulgae", "config.yaml"))
		if err != nil || !bytes.Equal(after, explicitConfig) {
			t.Fatalf("repeat init changed config: %v", err)
		}
	})

	t.Run("closed stdout preserves committed init", func(t *testing.T) {
		installed, err := user.Current()
		if err != nil || installed == nil {
			t.Fatalf("current native account unavailable: %#v %v", installed, err)
		}
		project := canonicalTestTempDir(t)
		initializeReviewGitRepository(t, project)
		providerDirectory := canonicalTestTempDir(t)
		agy := filepath.Join(providerDirectory, "agy")
		mustWriteTestFile(t, agy, []byte("#!/bin/sh\nexit 0\n"))
		if err := os.Chmod(agy, 0o700); err != nil {
			t.Fatal(err)
		}
		readPipe, writePipe, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		if err := readPipe.Close(); err != nil {
			t.Fatal(err)
		}
		command := exec.Command(binary, "init", "--providers", "agy", "--agy-executable", agy, "--output", "json")
		command.Dir = project
		command.Env = isolatedMulgaeEnvWith(t, installed.HomeDir, providerDirectory)
		command.Stdout = writePipe
		var stderr bytes.Buffer
		command.Stderr = &stderr
		runErr := command.Run()
		_ = writePipe.Close()
		var exitError *exec.ExitError
		if !errors.As(runErr, &exitError) || exitError.ExitCode() != 7 {
			t.Fatalf("closed stdout init = %v stderr %q", runErr, stderr.String())
		}
		if stderr.String() != "mulgae: init committed .mulgae/config.yaml; result delivery failed\n" {
			t.Fatalf("closed stdout stderr = %q", stderr.String())
		}
		if _, err := os.Stat(filepath.Join(project, ".mulgae", "config.yaml")); err != nil {
			t.Fatalf("committed config missing after delivery failure: %v", err)
		}
	})

	t.Run("command census", func(t *testing.T) {
		const runID = "r_019f596a-cf80-7c67-b265-f37053d51ccf"
		const attemptID = "a_019f596a-cf80-7c67-b265-f37053d51ccf"
		cases := []struct {
			command string
			argv    []string
			exit    int
		}{
			{"init", []string{"init"}, 4},
			{"doctor", []string{"doctor"}, 4},
			{"review", []string{"review", "--dirty", "--output", "json"}, 2},
			{"followup", []string{"followup", "--run", runID, "--finding", "F001", "--dirty"}, 2},
			{"delta", []string{"delta", "--since-run", runID, "--dirty", "--roles", "logic"}, 2},
			{"rerun", []string{"rerun", "--run", runID, "--attempt", attemptID}, 2},
			{"status", []string{"status", "--run", runID}, 7},
			{"report", []string{"report", "--run", runID, "--output-path", "report.md"}, 7},
			{"findings", []string{"findings", "--run", runID, "--severity", "low"}, 7},
			{"excerpt", []string{"excerpt", "--run", runID, "--finding", "F001", "--current-target-sha256", "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}, 7},
			{"providers", []string{"providers", "--include-unverified"}, 4},
			{"roles", []string{"roles"}, 0},
			{"config", []string{"config"}, 2},
			{"schema", []string{"schema", "list"}, 0},
			{"clean", []string{"clean"}, 7},
			{"export", []string{"export", "--run", runID, "--output-path", "review.zip"}, 7},
			{"help", []string{"help"}, 0},
		}
		if got, want := len(cases), 17; got != want {
			t.Fatalf("documented command census = %d, want %d", got, want)
		}
		specs := cli.CommandSpecs()
		if got, want := len(specs), len(cases); got != want {
			t.Fatalf("canonical command registry count = %d, want %d", got, want)
		}
		for index, spec := range specs {
			if got, want := string(spec.Command()), cases[index].command; got != want {
				t.Fatalf("canonical command registry[%d] = %q, want %q", index, got, want)
			}
		}
		seen := make(map[string]bool, len(cases))
		for _, test := range cases {
			t.Run(test.command, func(t *testing.T) {
				if seen[test.command] {
					t.Fatalf("duplicate command %q", test.command)
				}
				seen[test.command] = true
				got := runMulgaeBinary(t, binary, t.TempDir(), test.argv...)
				if got.exitCode != test.exit {
					t.Fatalf("%s exit = %d, want %d; stdout %q stderr %q", test.command, got.exitCode, test.exit, got.stdout, got.stderr)
				}
			})
		}
	})

	t.Run("usage streams", func(t *testing.T) {
		for _, argv := range [][]string{
			{"not-a-command"},
			{"prompt", "--run", "r_019f596a-cf80-7c67-b265-f37053d51ccf", "--attempt", "a_019f596a-cf80-7c67-b265-f37053d51ccf"},
			{"review", "--diff"},
			{"review", "--dirty", "--ci"},
		} {
			got := runMulgaeBinary(t, binary, t.TempDir(), argv...)
			if got.exitCode != 2 || len(got.stdout) != 0 || !bytes.Equal(got.stderr, []byte("mulgae: invalid command usage\n")) {
				t.Fatalf("usage %q = exit %d stdout %q stderr %q", argv, got.exitCode, got.stdout, got.stderr)
			}
		}
	})

	t.Run("schema list formats", func(t *testing.T) {
		human := runMulgaeBinary(t, binary, t.TempDir(), "schema", "list")
		if human.exitCode != 0 || len(human.stdout) == 0 || len(human.stderr) != 0 {
			t.Fatalf("schema list human = exit %d stdout %q stderr %q", human.exitCode, human.stdout, human.stderr)
		}
		json := runMulgaeBinary(t, binary, t.TempDir(), "schema", "list", "--output", "json")
		if json.exitCode != 2 || len(json.stdout) != 0 || !bytes.Equal(json.stderr, []byte("mulgae: invalid command usage\n")) {
			t.Fatalf("schema list JSON = exit %d stdout %q stderr %q", json.exitCode, json.stdout, json.stderr)
		}
	})

	t.Run("authority absent envelopes", func(t *testing.T) {
		cases := []struct {
			name       string
			argv       []string
			exit       int
			check      func(*testing.T, commandEnvelope)
			nullFields []string
		}{
			{
				name:       "review",
				argv:       []string{"review", "--dirty", "--output", "json"},
				exit:       2,
				nullFields: []string{"session_id", "run_id", "run_manifest_uri", "review_artifact_uri"},
				check: func(t *testing.T, envelope commandEnvelope) {
					if envelope.Command != "review" || envelope.Result.Kind != "review_started" ||
						envelope.Result.SessionID != nil || envelope.Result.RunID != nil ||
						envelope.Result.RunManifestURI != nil || envelope.Result.ReviewArtifactURI != nil ||
						envelope.Exit.Code != 2 || envelope.Exit.Kind != "usage" {
						t.Fatalf("review authority-absent envelope = %#v", envelope)
					}
				},
			},
		}
		for _, test := range cases {
			t.Run(test.name, func(t *testing.T) {
				got := runMulgaeBinary(t, binary, t.TempDir(), test.argv...)
				if got.exitCode != test.exit || len(got.stderr) != 0 {
					t.Fatalf("%s = exit %d stdout %q stderr %q", test.name, got.exitCode, got.stdout, got.stderr)
				}
				var envelope commandEnvelope
				if err := json.Unmarshal(got.stdout, &envelope); err != nil {
					t.Fatalf("decode %s envelope: %v", test.name, err)
				}
				var raw struct {
					Result map[string]json.RawMessage `json:"result"`
				}
				if err := json.Unmarshal(got.stdout, &raw); err != nil {
					t.Fatalf("decode %s result: %v", test.name, err)
				}
				assertNullResultFields(t, raw.Result, test.nullFields)
				test.check(t, envelope)
			})
		}
	})
}
func TestIntegrationMulgaeProductionReviewSubprocessKimiSecurityNonAdmission(t *testing.T) {
	root := repositoryRoot(t)
	binary := buildMulgaeBinary(t, root)
	project := canonicalTestTempDir(t)
	initializeReviewGitRepository(t, project)

	home := canonicalTestTempDir(t)
	seedKimiCredentials(t, home)
	providerDirectory := canonicalTestTempDir(t)
	logPath := filepath.Join(canonicalTestTempDir(t), "kimi-observations.jsonl")
	buildFakeKimi(t, root, filepath.Join(providerDirectory, "kimi"), logPath)
	environment := isolatedMulgaeEnvWith(t, home, providerDirectory)
	initialized := runMulgaeBinaryWithEnv(t, binary, project, environment,
		"init", "--providers", "kimi", "--roles", "security", "--kimi-executable", filepath.Join(providerDirectory, "kimi"), "--kimi-data-home", filepath.Join(home, ".kimi-code"))
	if initialized.exitCode != 0 {
		t.Fatalf("initialize Kimi local config: exit=%d stdout=%q stderr=%q", initialized.exitCode, initialized.stdout, initialized.stderr)
	}

	review := runMulgaeBinaryWithEnv(t, binary, project, environment,
		"review", "--dirty", "--objective", "@roadmap.md review the changed behavior without rewriting this objective", "--roles", "logic,security", "--output", "json")
	if review.exitCode != 8 || len(review.stderr) != 0 {
		t.Fatalf("Kimi security non-admission = exit %d stdout %q stderr %q", review.exitCode, review.stdout, review.stderr)
	}
	var envelope commandEnvelope
	if err := json.Unmarshal(review.stdout, &envelope); err != nil {
		t.Fatalf("decode Kimi security envelope: %v", err)
	}
	if envelope.Command != "review" || envelope.Exit.Code != 8 || envelope.Exit.Kind != "security" ||
		envelope.Result.Kind != "review_started" || envelope.Result.SessionID != nil ||
		envelope.Result.RunID != nil || envelope.Result.RunManifestURI != nil || envelope.Result.ReviewArtifactURI != nil ||
		len(envelope.Reasons) != 1 || envelope.Reasons[0].Category != "security" || envelope.Reasons[0].ArtifactURI == nil ||
		envelope.Reasons[0].Code != "provider_qualification_failed" || envelope.Reasons[0].Retryable {
		t.Fatalf("Kimi security envelope = %#v", envelope)
	}
	entries, err := os.ReadDir(filepath.Join(project, ".mulgae"))
	if err != nil {
		t.Fatalf("read Kimi security artifact directory: %v", err)
	}
	if len(entries) != 2 || entries[0].Name() != "config.yaml" || entries[1].Name() != "diagnostics" || !entries[1].IsDir() {
		t.Fatalf("Kimi security rejection created unexpected artifacts: %v", entries)
	}
	diagnosticRuns, err := filepath.Glob(filepath.Join(project, ".mulgae", "diagnostics", "s_*", "r_*"))
	if err != nil || len(diagnosticRuns) != 1 {
		t.Fatalf("Kimi security diagnostics = %v, %v", diagnosticRuns, err)
	}
	wantDiagnosticURI, err := filepath.Rel(project, diagnosticRuns[0])
	if err != nil || filepath.ToSlash(wantDiagnosticURI) != *envelope.Reasons[0].ArtifactURI {
		t.Fatalf("Kimi diagnostic URI = %v, want %q (rel err %v)", envelope.Reasons[0].ArtifactURI, filepath.ToSlash(wantDiagnosticURI), err)
	}
	logBytes, err := os.ReadFile(filepath.Join(diagnosticRuns[0], "mulgae-runtime.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(string(logBytes), "\n"), "\n")
	var terminal struct {
		Event domain.RuntimeDiagnosticEventCode `json:"event"`
	}
	if len(lines) == 0 || json.Unmarshal([]byte(lines[len(lines)-1]), &terminal) != nil || terminal.Event != domain.DiagnosticRuntimeClosed {
		t.Fatalf("Kimi security diagnostics were not finalized: %q", logBytes)
	}
	observations := readFakeKimiObservations(t, logPath)
	if len(observations) == 0 || len(observations) > 2 {
		t.Fatalf("Kimi qualification launch count = %d, want 1..2: %#v", len(observations), observations)
	}
	lastRoleOrdinal := -1
	for index, observation := range observations {
		roleOrdinal := -1
		for ordinal, role := range []string{"logic", "security"} {
			if strings.Contains(observation.Prompt, "role must be "+role+".") {
				roleOrdinal = ordinal
				break
			}
		}
		if !strings.Contains(observation.Prompt, "The object must contain exactly root, link, and role string fields.") ||
			roleOrdinal <= lastRoleOrdinal {
			t.Fatalf("Kimi executed outside ordered qualification at launch %d: %#v", index+1, observations)
		}
		lastRoleOrdinal = roleOrdinal
	}
}

func TestIntegrationMulgaeProductionReviewSubprocessAGY(t *testing.T) {
	root := repositoryRoot(t)
	binary := buildMulgaeBinary(t, root)
	project := canonicalTestTempDir(t)
	initializeReviewGitRepository(t, project)

	installedUser, err := user.Current()
	if err != nil || installedUser == nil || !filepath.IsAbs(installedUser.HomeDir) || filepath.Clean(installedUser.HomeDir) != installedUser.HomeDir {
		t.Fatalf("current native home unavailable: user=%#v err=%v", installedUser, err)
	}
	uid, err := strconv.ParseUint(installedUser.Uid, 10, 32)
	if err != nil || int(uid) != os.Geteuid() {
		t.Fatalf("current native user identity is not effective UID: uid=%q euid=%d err=%v", installedUser.Uid, os.Geteuid(), err)
	}

	providerDirectory := canonicalTestTempDir(t)
	logPath := filepath.Join(canonicalTestTempDir(t), "agy-observations.jsonl")
	buildFakeAGY(t, root, filepath.Join(providerDirectory, "agy"), logPath)
	environment := isolatedMulgaeEnvWith(t, installedUser.HomeDir, providerDirectory)
	environment = append(environment, "MULGAE_FAKE_AGY_LOG="+logPath)
	initialized := runMulgaeBinaryWithEnv(t, binary, project, environment,
		"init", "--providers", "agy", "--roles", "security", "--agy-executable", filepath.Join(providerDirectory, "agy"), "--agy-permission-mode", "dangerously-skip-permissions")
	if initialized.exitCode != 0 {
		t.Fatalf("initialize AGY local config: exit=%d stdout=%q stderr=%q", initialized.exitCode, initialized.stdout, initialized.stderr)
	}

	const objective = "@roadmap.md review the changed behavior without rewriting this objective"
	review := runMulgaeBinaryWithEnv(t, binary, project, environment,
		"review", "--dirty", "--objective", objective, "--roles", "logic,security", "--output", "json")
	if review.exitCode != 0 || len(review.stderr) != 0 {
		var failed commandEnvelope
		if err := json.Unmarshal(review.stdout, &failed); err == nil {
			t.Logf("AGY production review reasons: %#v", failed.Reasons)
		}
		observations := readFakeAGYObservations(t, logPath)
		argv := make([][]string, 0, len(observations))
		for _, observation := range observations {
			argv = append(argv, observation.Argv)
		}
		if diagnosticRuns, _ := filepath.Glob(filepath.Join(project, ".mulgae", "diagnostics", "s_*", "r_*")); len(diagnosticRuns) == 1 {
			if diagnosticLog, readErr := os.ReadFile(filepath.Join(diagnosticRuns[0], "mulgae-runtime.jsonl")); readErr == nil {
				t.Logf("AGY runtime diagnostics:\n%s", diagnosticLog)
			}
		}
		t.Fatalf("AGY production review failed: exit=%d launches=%d argv=%v stdout=%q stderr=%q", review.exitCode, len(observations), argv, review.stdout, review.stderr)
	}
	var reviewEnvelope commandEnvelope
	if err := json.Unmarshal(review.stdout, &reviewEnvelope); err != nil {
		t.Fatalf("decode AGY review envelope: %v", err)
	}
	if reviewEnvelope.Result.Kind != "review_started" ||
		reviewEnvelope.Exit.Code != 0 || reviewEnvelope.Exit.Kind != "success" ||
		reviewEnvelope.Result.SessionID == nil || reviewEnvelope.Result.RunID == nil ||
		reviewEnvelope.Result.RunManifestURI == nil || reviewEnvelope.Result.ReviewArtifactURI == nil {
		t.Fatalf("AGY review did not publish a successful P2 result: %#v", reviewEnvelope)
	}
	for _, uri := range []string{*reviewEnvelope.Result.RunManifestURI, *reviewEnvelope.Result.ReviewArtifactURI} {
		if !strings.HasPrefix(uri, ".mulgae/") {
			t.Fatalf("published URI %q is not a P2 project URI", uri)
		}
		if _, err := os.Stat(filepath.Join(project, uri)); err != nil {
			t.Fatalf("published URI %q is not reopenable: %v", uri, err)
		}
	}
	diagnosticLog, err := os.ReadFile(filepath.Join(project, ".mulgae", "diagnostics", *reviewEnvelope.Result.SessionID, *reviewEnvelope.Result.RunID, "mulgae-runtime.jsonl"))
	if err != nil {
		t.Fatalf("read AGY runtime diagnostics: %v", err)
	}
	wantDiagnosticOrder := []domain.RuntimeDiagnosticEventCode{
		domain.DiagnosticQualificationStarted,
		domain.DiagnosticQualificationCandidateChecked,
		domain.DiagnosticQualificationSucceeded,
		domain.DiagnosticReviewPlanCreated,
		domain.DiagnosticAssignmentResolved,
		domain.DiagnosticAssignmentResolved,
		domain.DiagnosticRunBudgetAccepted,
		domain.DiagnosticRunStarted,
		domain.DiagnosticInvocationPrepared,
		domain.DiagnosticProcessStarted,
		domain.DiagnosticOutputParsed,
		domain.DiagnosticValidationSucceeded,
		domain.DiagnosticReductionCompleted,
		domain.DiagnosticNamespaceDrainStarted,
		domain.DiagnosticNamespaceDrained,
		domain.DiagnosticWorkspaceCleanupStarted,
		domain.DiagnosticWorkspaceCleanupCompleted,
		domain.DiagnosticPublicationPreparationStarted,
		domain.DiagnosticPublicationStaged,
		domain.DiagnosticPublicationInstalled,
		domain.DiagnosticPublicationCommitted,
		domain.DiagnosticRuntimeClosed,
	}
	diagnosticPosition := 0
	var previousSequence uint64
	for _, line := range strings.Split(strings.TrimSuffix(string(diagnosticLog), "\n"), "\n") {
		var event struct {
			Sequence uint64                            `json:"seq"`
			Code     domain.RuntimeDiagnosticEventCode `json:"event"`
		}
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatalf("decode AGY runtime diagnostic: %v", err)
		}
		if diagnosticPosition < len(wantDiagnosticOrder) && event.Code == wantDiagnosticOrder[diagnosticPosition] {
			diagnosticPosition++
		}
		if event.Sequence <= previousSequence {
			t.Fatalf("AGY diagnostic sequence %d followed %d", event.Sequence, previousSequence)
		}
		previousSequence = event.Sequence
	}
	if diagnosticPosition != len(wantDiagnosticOrder) {
		t.Fatalf("AGY runtime diagnostic order missing %v:\n%s", wantDiagnosticOrder[diagnosticPosition:], diagnosticLog)
	}
	statusBytes, err := os.ReadFile(filepath.Join(project, ".mulgae", "diagnostics", *reviewEnvelope.Result.SessionID, *reviewEnvelope.Result.RunID, "status.json"))
	if err != nil {
		t.Fatalf("read AGY runtime diagnostic status: %v", err)
	}
	var diagnosticStatus struct {
		State         domain.RunState `json:"state"`
		LaneTotal     int             `json:"lane_total"`
		LaneCompleted int             `json:"lane_completed"`
		LaneFailed    int             `json:"lane_failed"`
		P2URI         string          `json:"p2_uri"`
	}
	if err := json.Unmarshal(statusBytes, &diagnosticStatus); err != nil {
		t.Fatalf("decode AGY runtime diagnostic status: %v", err)
	}
	if diagnosticStatus.State != domain.RunCompleted || diagnosticStatus.LaneTotal != 2 || diagnosticStatus.LaneCompleted != 2 || diagnosticStatus.LaneFailed != 0 || diagnosticStatus.P2URI != *reviewEnvelope.Result.RunManifestURI {
		t.Fatalf("AGY runtime diagnostic status = %#v, want completed 2/2 lanes linked to %q", diagnosticStatus, *reviewEnvelope.Result.RunManifestURI)
	}
	rawStreams, err := filepath.Glob(filepath.Join(project, ".mulgae", "diagnostics", *reviewEnvelope.Result.SessionID, *reviewEnvelope.Result.RunID, "attempts", "a_*", "invocations", "*", "*.raw"))
	if err != nil || len(rawStreams) < 2 {
		t.Fatalf("AGY raw diagnostic streams = %v, %v", rawStreams, err)
	}

	status := runMulgaeBinaryWithEnv(t, binary, project, environment,
		"status", "--run", *reviewEnvelope.Result.RunID, "--output", "json")
	if status.exitCode != 0 || len(status.stderr) != 0 {
		t.Fatalf("published status = exit %d stdout %q stderr %q", status.exitCode, status.stdout, status.stderr)
	}
	var statusEnvelope struct {
		Exit struct {
			Code int    `json:"code"`
			Kind string `json:"kind"`
		} `json:"exit"`
		Result struct {
			RunID             string  `json:"run_id"`
			PublicationStatus string  `json:"publication_status"`
			FinalArtifactURI  *string `json:"final_artifact_uri"`
		} `json:"result"`
	}
	if err := json.Unmarshal(status.stdout, &statusEnvelope); err != nil {
		t.Fatalf("decode status envelope: %v", err)
	}
	if statusEnvelope.Exit.Code != 0 || statusEnvelope.Exit.Kind != "success" ||
		statusEnvelope.Result.RunID != *reviewEnvelope.Result.RunID ||
		statusEnvelope.Result.PublicationStatus != "committed" ||
		statusEnvelope.Result.FinalArtifactURI == nil ||
		!strings.HasPrefix(*statusEnvelope.Result.FinalArtifactURI, ".mulgae/") {
		t.Fatalf("published status is not a successful committed P2 reopening: %#v", statusEnvelope)
	}
	if _, err := os.Stat(filepath.Join(project, *statusEnvelope.Result.FinalArtifactURI)); err != nil {
		t.Fatalf("reopened P2 final artifact %q is unavailable: %v", *statusEnvelope.Result.FinalArtifactURI, err)
	}

	observations := readFakeAGYObservations(t, logPath)
	versionChecks := make([]fakeAGYObservation, 0, 2)
	qualificationRuns := make([]fakeAGYObservation, 0, 2)
	reviewRuns := make([]fakeAGYObservation, 0, 2)
	for _, observation := range observations {
		switch {
		case len(observation.Argv) == 1 && observation.Argv[0] == "--version":
			versionChecks = append(versionChecks, observation)
		case observation.Prompt == "@roadmap.md":
			qualificationRuns = append(qualificationRuns, observation)
		default:
			reviewRuns = append(reviewRuns, observation)
		}
	}
	// Version observation is diagnostic-only and may time out before the fake
	// process starts on a heavily instrumented race run. Qualification and role
	// execution are the authoritative launches and remain exact.
	if len(versionChecks) > 2 || len(qualificationRuns) != 2 || len(reviewRuns) != 2 {
		argv := make([][]string, 0, len(observations))
		for _, observation := range observations {
			argv = append(argv, observation.Argv)
		}
		t.Fatalf("AGY launches = versions:%d qualifications:%d reviews:%d argv=%v, want at most two diagnostic version checks and exactly two qualification and review launches", len(versionChecks), len(qualificationRuns), len(reviewRuns), argv)
	}
	for _, observation := range observations {
		if observation.Home != installedUser.HomeDir || observation.CWD == "" {
			t.Fatalf("AGY native-home/CWD contract = %#v", observation)
		}
		if len(observation.Argv) == 1 && observation.Argv[0] == "--version" {
			continue
		}
		for _, value := range []string{observation.XDGConfigHome, observation.XDGCacheHome, observation.TempDir, observation.Scratch} {
			if value == "" || value == installedUser.HomeDir || strings.HasPrefix(value, installedUser.HomeDir+string(filepath.Separator)) {
				t.Fatalf("AGY disposable environment escaped native home: %#v", observation)
			}
		}
	}
	for _, observation := range qualificationRuns {
		if observation.CWD != observation.Snapshot || observation.Prompt != "@roadmap.md" {
			t.Fatalf("AGY qualification snapshot/control contract = %#v", observation)
		}
	}
	for _, observation := range reviewRuns {
		if observation.CWD != observation.Snapshot || !strings.Contains(observation.Prompt, objective) {
			t.Fatalf("AGY review snapshot/control contract = %#v", observation)
		}
	}
}

func TestIntegrationMulgaeOfflineDiagnosticFailureWorkflows(t *testing.T) {
	repository := repositoryRoot(t)
	binary := buildMulgaeBinary(t, repository)
	installedUser, err := user.Current()
	if err != nil || installedUser == nil {
		t.Fatalf("current user unavailable: %#v, %v", installedUser, err)
	}

	t.Run("primary rate limit falls back and publishes linked diagnostics", func(t *testing.T) {
		project := canonicalTestTempDir(t)
		initializeReviewGitRepository(t, project)
		providerDirectory := canonicalTestTempDir(t)
		zcodeLog := filepath.Join(canonicalTestTempDir(t), "zcode.jsonl")
		agyLog := filepath.Join(canonicalTestTempDir(t), "agy.jsonl")
		zcodeNode := filepath.Join(providerDirectory, "node")
		zcodeLauncher := filepath.Join(providerDirectory, "zcode.cjs")
		buildFakeZCode(t, repository, zcodeNode, zcodeLauncher, zcodeLog, "rate_limit_review")
		buildFakeAGY(t, repository, filepath.Join(providerDirectory, "agy"), agyLog)
		environment := isolatedMulgaeEnvWith(t, installedUser.HomeDir, providerDirectory)
		environment = append(environment, "MULGAE_FAKE_AGY_LOG="+agyLog)
		initializeOfflineProviders(t, binary, project, environment, "zcode,agy", zcodeNode, zcodeLauncher, filepath.Join(providerDirectory, "agy"))

		result := runMulgaeBinaryWithEnv(t, binary, project, environment, "review", "--dirty", "--roles", "security", "--output", "json")
		var envelope commandEnvelope
		if err := json.Unmarshal(result.stdout, &envelope); err != nil {
			t.Fatal(err)
		}
		if result.exitCode != 0 || envelope.Result.RunManifestURI == nil || envelope.Result.SessionID == nil || envelope.Result.RunID == nil {
			observations, _ := os.ReadFile(zcodeLog)
			agyObservations, _ := os.ReadFile(agyLog)
			var diagnostics []byte
			if len(envelope.Reasons) != 0 && envelope.Reasons[0].ArtifactURI != nil {
				diagnostics, _ = os.ReadFile(filepath.Join(project, filepath.FromSlash(*envelope.Reasons[0].ArtifactURI), "mulgae-runtime.jsonl"))
			}
			t.Fatalf("fallback review = exit %d envelope %#v stderr %q zcode observations %s agy observations %s diagnostics %s", result.exitCode, envelope, result.stderr, observations, agyObservations, diagnostics)
		}
		log := readRuntimeDiagnosticLog(t, project, *envelope.Result.SessionID, *envelope.Result.RunID)
		for _, event := range []domain.RuntimeDiagnosticEventCode{domain.DiagnosticAttemptFailed, domain.DiagnosticFallbackEligible, domain.DiagnosticFallbackScheduled, domain.DiagnosticFallbackStarted, domain.DiagnosticFallbackCompleted, domain.DiagnosticPublicationCommitted, domain.DiagnosticRuntimeClosed} {
			if !bytes.Contains(log, []byte(`"event":"`+string(event)+`"`)) {
				t.Fatalf("fallback diagnostic omitted %s:\n%s", event, log)
			}
		}
		assertRuntimeDiagnosticStatus(t, project, *envelope.Result.SessionID, *envelope.Result.RunID, domain.RunCompleted, *envelope.Result.RunManifestURI)
	})

	for _, testCase := range []struct {
		name       string
		mode       string
		wantExit   int
		wantReason string
	}{
		{name: "login required is terminal without fallback", mode: "login_review", wantExit: 4, wantReason: "provider_login_required"},
		{name: "non P2 execution failure remains inspectable", mode: "fail_review", wantExit: 10, wantReason: "provider_execution_failed"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			project := canonicalTestTempDir(t)
			initializeReviewGitRepository(t, project)
			providerDirectory := canonicalTestTempDir(t)
			zcodeNode := filepath.Join(providerDirectory, "node")
			zcodeLauncher := filepath.Join(providerDirectory, "zcode.cjs")
			buildFakeZCode(t, repository, zcodeNode, zcodeLauncher, filepath.Join(canonicalTestTempDir(t), "zcode.jsonl"), testCase.mode)
			environment := isolatedMulgaeEnvWith(t, installedUser.HomeDir, providerDirectory)
			initializeOfflineProviders(t, binary, project, environment, "zcode", zcodeNode, zcodeLauncher, "")

			result := runMulgaeBinaryWithEnv(t, binary, project, environment, "review", "--dirty", "--roles", "security", "--output", "json")
			var envelope commandEnvelope
			if err := json.Unmarshal(result.stdout, &envelope); err != nil {
				t.Fatal(err)
			}
			if result.exitCode != testCase.wantExit || len(envelope.Reasons) != 1 || envelope.Reasons[0].Code != testCase.wantReason || envelope.Reasons[0].ArtifactURI == nil || envelope.Result.RunManifestURI != nil {
				t.Fatalf("terminal review = exit %d envelope %#v stderr %q", result.exitCode, envelope, result.stderr)
			}
			diagnosticRoot := filepath.Join(project, filepath.FromSlash(*envelope.Reasons[0].ArtifactURI))
			statusBytes, err := os.ReadFile(filepath.Join(diagnosticRoot, "status.json"))
			if err != nil {
				t.Fatal(err)
			}
			var status struct {
				State domain.RunState `json:"state"`
				P2URI string          `json:"p2_uri"`
			}
			if err := json.Unmarshal(statusBytes, &status); err != nil || status.State != domain.RunFailed || status.P2URI != "" {
				t.Fatalf("terminal diagnostic status = %#v, %v", status, err)
			}
			if log, err := os.ReadFile(filepath.Join(diagnosticRoot, "mulgae-runtime.jsonl")); err != nil || !bytes.Contains(log, []byte(`"event":"`+string(domain.DiagnosticRuntimeClosed)+`"`)) {
				t.Fatalf("terminal diagnostic log = %q, %v", log, err)
			}
			raw, err := filepath.Glob(filepath.Join(diagnosticRoot, "attempts", "a_*", "invocations", "*", "*.raw"))
			if err != nil || len(raw) == 0 {
				t.Fatalf("terminal raw diagnostics = %v, %v", raw, err)
			}
		})
	}

	t.Run("diagnostic open failure stops before provider spawn", func(t *testing.T) {
		project := canonicalTestTempDir(t)
		initializeReviewGitRepository(t, project)
		providerDirectory := canonicalTestTempDir(t)
		zcodeLog := filepath.Join(canonicalTestTempDir(t), "zcode.jsonl")
		zcodeNode := filepath.Join(providerDirectory, "node")
		zcodeLauncher := filepath.Join(providerDirectory, "zcode.cjs")
		buildFakeZCode(t, repository, zcodeNode, zcodeLauncher, zcodeLog, "success")
		environment := isolatedMulgaeEnvWith(t, installedUser.HomeDir, providerDirectory)
		initializeOfflineProviders(t, binary, project, environment, "zcode", zcodeNode, zcodeLauncher, "")
		diagnosticsRoot := filepath.Join(project, ".mulgae", "diagnostics")
		if err := os.Mkdir(diagnosticsRoot, 0o500); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(diagnosticsRoot, 0o700) })

		result := runMulgaeBinaryWithEnv(t, binary, project, environment, "review", "--dirty", "--roles", "security", "--output", "json")
		var envelope commandEnvelope
		if err := json.Unmarshal(result.stdout, &envelope); err != nil {
			t.Fatal(err)
		}
		if result.exitCode != 7 || len(envelope.Reasons) != 1 || envelope.Reasons[0].Code != "artifact_unavailable" || envelope.Reasons[0].ArtifactURI != nil {
			t.Fatalf("diagnostic persistence failure = exit %d envelope %#v stderr %q", result.exitCode, envelope, result.stderr)
		}
		if observations, err := os.ReadFile(zcodeLog); err == nil && len(bytes.TrimSpace(observations)) != 0 {
			t.Fatalf("provider spawned after diagnostic open failure: %s", observations)
		}
	})
}

func initializeOfflineProviders(t *testing.T, binary, project string, environment []string, providers, zcodeNode, zcodeLauncher, agy string) {
	t.Helper()
	arguments := []string{"init", "--providers", providers, "--roles", "security", "--zcode-node-executable", zcodeNode, "--zcode-launcher", zcodeLauncher}
	if agy != "" {
		arguments = append(arguments, "--agy-executable", agy, "--agy-permission-mode", "dangerously-skip-permissions")
	}
	initialized := runMulgaeBinaryWithEnv(t, binary, project, environment, arguments...)
	if initialized.exitCode != 0 {
		t.Fatalf("initialize offline providers: exit=%d stdout=%q stderr=%q", initialized.exitCode, initialized.stdout, initialized.stderr)
	}
}

func readRuntimeDiagnosticLog(t *testing.T, project, session, run string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(project, ".mulgae", "diagnostics", session, run, "mulgae-runtime.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func assertRuntimeDiagnosticStatus(t *testing.T, project, session, run string, wantState domain.RunState, wantP2 string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(project, ".mulgae", "diagnostics", session, run, "status.json"))
	if err != nil {
		t.Fatal(err)
	}
	var status struct {
		State domain.RunState `json:"state"`
		P2URI string          `json:"p2_uri"`
	}
	if err := json.Unmarshal(data, &status); err != nil || status.State != wantState || status.P2URI != wantP2 {
		t.Fatalf("runtime diagnostic status = %#v, %v; want %s/%q", status, err, wantState, wantP2)
	}
}

type commandEnvelope struct {
	Command string `json:"command"`
	Exit    struct {
		Code int    `json:"code"`
		Kind string `json:"kind"`
	} `json:"exit"`
	Result struct {
		Kind              string  `json:"kind"`
		SessionID         *string `json:"session_id"`
		RunID             *string `json:"run_id"`
		RunManifestURI    *string `json:"run_manifest_uri"`
		ReviewArtifactURI *string `json:"review_artifact_uri"`
		PromptManifestURI *string `json:"prompt_manifest_uri"`
	} `json:"result"`
	Reasons []struct {
		Category    string  `json:"category"`
		Code        string  `json:"code"`
		Message     string  `json:"message"`
		Retryable   bool    `json:"retryable"`
		ArtifactURI *string `json:"artifact_uri"`
	} `json:"reasons"`
}
type fakeKimiObservation struct {
	CWD    string `json:"cwd"`
	Prompt string `json:"prompt"`
}
type fakeAGYObservation struct {
	Argv          []string `json:"argv"`
	CWD           string   `json:"cwd"`
	Home          string   `json:"home"`
	XDGConfigHome string   `json:"xdg_config_home"`
	XDGCacheHome  string   `json:"xdg_cache_home"`
	TempDir       string   `json:"tmpdir"`
	Scratch       string   `json:"scratch"`
	Snapshot      string   `json:"snapshot"`
	Prompt        string   `json:"prompt"`
}

func initializeReviewGitRepository(t *testing.T, directory string) {
	t.Helper()
	mustWriteTestFile(t, filepath.Join(directory, "roadmap.md"), []byte("# Roadmap\nReview the linked design.\n"))
	mustWriteTestFile(t, filepath.Join(directory, "docs", "linked.md"), []byte("# Linked design\nThe review must preserve immutable inputs.\n"))
	mustWriteTestFile(t, filepath.Join(directory, "review.go"), []byte("package review\n\nconst state = \"before\"\n"))
	runTestCommand(t, directory, "git", "init")
	runTestCommand(t, directory, "git", "add", ".")
	runTestCommand(t, directory, "git", "-c", "user.name=Mulgae E2E", "-c", "user.email=mulgae-e2e@example.invalid", "commit", "-m", "baseline")
	mustWriteTestFile(t, filepath.Join(directory, "review.go"), []byte("package review\n\nconst state = \"after\"\n"))
}

func seedKimiCredentials(t *testing.T, home string) {
	t.Helper()
	for path, contents := range map[string][]byte{
		".kimi-code/config.toml":                []byte("endpoint = \"offline\"\n"),
		".kimi-code/credentials/kimi-code.json": []byte("{\"token\":\"offline\"}\n"),
		".kimi/config.toml":                     []byte("endpoint = \"offline\"\n"),
		".kimi/credentials/kimi-code.json":      []byte("{\"token\":\"offline\"}\n"),
	} {
		mustWriteTestFile(t, filepath.Join(home, path), contents)
	}
}

func buildFakeKimi(t *testing.T, root, binary, logPath string) {
	t.Helper()
	source := filepath.Join(t.TempDir(), "main.go")
	program := `package main

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
)

type observation struct {
	CWD string
	Prompt string
}

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--version" {
		fmt.Println("0.28.0")
		return
	}
	if len(os.Args) != 7 || os.Args[1] != "--model" ||
		os.Args[2] != "kimi-code/kimi-for-coding" || os.Args[3] != "--prompt" ||
		os.Args[5] != "--output-format" || os.Args[6] != "stream-json" {
		panic("non-canonical Kimi invocation")
	}
	prompt := os.Args[4]
	cwd, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	log, err := os.OpenFile("__FAKE_KIMI_LOG__", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		panic(err)
	}
	if err := json.NewEncoder(log).Encode(observation{CWD: cwd, Prompt: prompt}); err != nil {
		panic(err)
	}
	if err := log.Close(); err != nil {
		panic(err)
	}
	content := "{\"schema_version\":\"mulgae-provider-review-output.v1\",\"summary\":\"No findings.\",\"completeness\":\"complete\",\"limitations\":[],\"findings\":[]}"
	if prompt == "@roadmap.md" {
		roadmap, err := os.ReadFile("roadmap.md")
		if err != nil {
			panic(err)
		}
		root := regexp.MustCompile("root must be ([0-9a-f]{64});").FindStringSubmatch(string(roadmap))
		role := regexp.MustCompile("role must be ([a-z]+)\\.").FindStringSubmatch(string(roadmap))
		link, err := os.ReadFile("docs/linked.md")
		if err != nil || len(root) != 2 || len(role) != 2 {
			panic("native qualification reference did not resolve")
		}
		content = fmt.Sprintf("{\"root\":%q,\"link\":%q,\"missing\":\"denied\",\"mulgae\":\"denied\",\"outside\":\"denied\",\"role\":%q,\"command\":\"denied\",\"write\":\"denied\",\"network\":\"denied\",\"browser\":\"denied\",\"mcp\":\"denied\"}", root[1], strings.TrimSpace(string(link)), role[1])
	}
	if err := json.NewEncoder(os.Stdout).Encode(map[string]string{"role": "assistant", "content": content}); err != nil {
		panic(err)
	}
}
`
	mustWriteTestFile(t, source, []byte(strings.ReplaceAll(program, "__FAKE_KIMI_LOG__", logPath)))
	build := exec.Command("go", "build", "-o", binary, source)
	build.Dir = root
	build.Env = append(os.Environ(), "GOPROXY=off", "GOSUMDB=off", "GOCACHE="+t.TempDir())
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build fake Kimi: %v\n%s", err, output)
	}
}

func buildFakeZCode(t *testing.T, root, binary, launcher, logPath, mode string) {
	t.Helper()
	mustWriteTestFile(t, launcher, []byte("// offline fake ZCode launcher\n"))
	source := filepath.Join(t.TempDir(), "main.go")
	program := `package main

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
)

type observation struct {
	Argv []string ` + "`json:\"argv\"`" + `
	CWD string ` + "`json:\"cwd\"`" + `
	Prompt string ` + "`json:\"prompt\"`" + `
}

func main() {
	argv := append([]string(nil), os.Args[1:]...)
	if len(argv) == 2 && argv[1] == "--version" {
		fmt.Println("22.14.0")
		return
	}
	prompt := ""
	for index := range argv {
		if argv[index] == "--prompt" && index+1 < len(argv) {
			prompt = argv[index+1]
		}
	}
	if prompt == "" {
		panic("non-canonical ZCode invocation")
	}
	cwd, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	log, err := os.OpenFile("__FAKE_ZCODE_LOG__", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		panic(err)
	}
	if err := json.NewEncoder(log).Encode(observation{Argv: argv, CWD: cwd, Prompt: prompt}); err != nil {
		panic(err)
	}
	if err := log.Close(); err != nil {
		panic(err)
	}
	if strings.Contains(prompt, "The object must contain exactly root, link, and role string fields.") {
		root := regexp.MustCompile("root must be ([0-9a-f]{64});").FindStringSubmatch(prompt)
		link := regexp.MustCompile("link must be ([^;]+);").FindStringSubmatch(prompt)
		role := regexp.MustCompile("role must be ([a-z]+)\\.").FindStringSubmatch(prompt)
		if len(root) != 2 || len(link) != 2 || len(role) != 2 {
			panic("native qualification reference did not resolve")
		}
		fmt.Printf("{\"root\":%q,\"link\":%q,\"role\":%q}", root[1], link[1], role[1])
		return
	}
	switch "__FAKE_ZCODE_MODE__" {
	case "rate_limit_review":
		fmt.Fprintln(os.Stderr, "rate_limit")
		os.Exit(1)
	case "login_review":
		fmt.Fprintln(os.Stderr, "zcode login required")
		os.Exit(1)
	case "fail_review":
		fmt.Fprintln(os.Stderr, "provider execution failed")
		os.Exit(1)
	}
	fmt.Print("{\"schema_version\":\"mulgae-provider-review-output.v1\",\"summary\":\"No findings.\",\"completeness\":\"complete\",\"limitations\":[],\"findings\":[]}")
}
`
	program = strings.ReplaceAll(program, "__FAKE_ZCODE_LOG__", logPath)
	program = strings.ReplaceAll(program, "__FAKE_ZCODE_MODE__", mode)
	mustWriteTestFile(t, source, []byte(program))
	build := exec.Command("go", "build", "-o", binary, source)
	build.Dir = root
	build.Env = append(os.Environ(), "GOPROXY=off", "GOSUMDB=off", "GOCACHE="+t.TempDir())
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build fake ZCode: %v\n%s", err, output)
	}
}

func buildFakeAGY(t *testing.T, root, binary, logPath string) {
	buildFakeAGYWithReviewOutput(t, root, binary, logPath, "")
}

func buildFakeAGYWithReviewOutput(t *testing.T, root, binary, logPath, reviewOutput string) {
	t.Helper()
	source := filepath.Join(t.TempDir(), "main.go")
	program := `package main

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"
)

type observation struct {
	Argv []string ` + "`json:\"argv\"`" + `
	CWD string ` + "`json:\"cwd\"`" + `
	Home string ` + "`json:\"home\"`" + `
	XDGConfigHome string ` + "`json:\"xdg_config_home\"`" + `
	XDGCacheHome string ` + "`json:\"xdg_cache_home\"`" + `
	TempDir string ` + "`json:\"tmpdir\"`" + `
	Scratch string ` + "`json:\"scratch\"`" + `
	Snapshot string ` + "`json:\"snapshot\"`" + `
	Prompt string ` + "`json:\"prompt\"`" + `
}

func main() {
	cwd, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	argv := append([]string(nil), os.Args[1:]...)
	observation := observation{
		Argv: argv, CWD: cwd, Home: os.Getenv("HOME"),
		XDGConfigHome: os.Getenv("XDG_CONFIG_HOME"), XDGCacheHome: os.Getenv("XDG_CACHE_HOME"),
		TempDir: os.Getenv("TMPDIR"), Scratch: os.Getenv("MULGAE_PROVIDER_SCRATCH"),
	}
	if len(argv) == 1 && argv[0] == "--version" {
		write(observation)
		fmt.Println("1.1.4")
		return
	}
	if len(argv) != 13 || argv[0] != "--new-project" || argv[1] != "--sandbox" ||
		argv[2] != "--dangerously-skip-permissions" || argv[3] != "--add-dir" ||
		argv[5] != "--mode" || argv[6] != "plan" || argv[7] != "--effort" || argv[8] != "low" ||
		argv[9] != "--print-timeout" || argv[10] != "3m55s" || argv[11] != "--print" || argv[4] != cwd {
		panic("non-canonical AGY invocation")
	}
	observation.Snapshot, observation.Prompt = argv[4], argv[12]
	write(observation)
	if observation.Prompt == "@roadmap.md" {
		roadmap, err := os.ReadFile("roadmap.md")
		if err != nil {
			panic(err)
		}
		link, err := os.ReadFile("docs/linked.md")
		root := regexp.MustCompile("root must be ([0-9a-f]{64});").FindStringSubmatch(string(roadmap))
		role := regexp.MustCompile("role must be ([a-z]+)\\.").FindStringSubmatch(string(roadmap))
		if err != nil || len(root) != 2 || len(role) != 2 {
			panic("native qualification reference did not resolve")
		}
		fmt.Printf("{\"root\":%q,\"link\":%q,\"role\":%q}", root[1], strings.TrimSpace(string(link)), role[1])
		_ = os.Stdout.Close()
		for { time.Sleep(time.Hour) }
	}
	content := __FAKE_AGY_REVIEW_OUTPUT__
	if content == "" {
		content = "{\"schema_version\":\"mulgae-provider-review-output.v1\",\"summary\":\"No findings.\",\"completeness\":\"complete\",\"limitations\":[],\"findings\":[]}"
	}
	fmt.Print(content)
	_ = os.Stdout.Close()
	for { time.Sleep(time.Hour) }
}

func write(observation observation) {
	log, err := os.OpenFile("__FAKE_AGY_LOG__", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		panic(err)
	}
	defer log.Close()
	if err := json.NewEncoder(log).Encode(observation); err != nil {
		panic(err)
	}
}`
	program = strings.ReplaceAll(program, "__FAKE_AGY_LOG__", logPath)
	program = strings.ReplaceAll(program, "__FAKE_AGY_REVIEW_OUTPUT__", strconv.Quote(reviewOutput))
	mustWriteTestFile(t, source, []byte(program))
	build := exec.Command("go", "build", "-o", binary, source)
	build.Dir = root
	build.Env = append(os.Environ(), "GOPROXY=off", "GOSUMDB=off", "GOCACHE="+t.TempDir())
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build fake AGY: %v\n%s", err, output)
	}
}

func readFakeAGYObservations(t *testing.T, path string) []fakeAGYObservation {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fake AGY observations: %v", err)
	}
	var observations []fakeAGYObservation
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var observation fakeAGYObservation
		if err := json.Unmarshal([]byte(line), &observation); err != nil {
			t.Fatalf("decode fake AGY observation %q: %v", line, err)
		}
		observations = append(observations, observation)
	}
	return observations
}

func readFakeKimiObservations(t *testing.T, path string) []fakeKimiObservation {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fake Kimi observations: %v", err)
	}
	var observations []fakeKimiObservation
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var observation fakeKimiObservation
		if err := json.Unmarshal([]byte(line), &observation); err != nil {
			t.Fatalf("decode fake Kimi observation %q: %v", line, err)
		}
		observations = append(observations, observation)
	}
	return observations
}

func mustWriteTestFile(t *testing.T, path string, contents []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatalf("create test file directory %q: %v", path, err)
	}
	if err := os.WriteFile(path, contents, 0600); err != nil {
		t.Fatalf("write test file %q: %v", path, err)
	}
}

func runTestCommand(t *testing.T, directory, name string, arguments ...string) {
	t.Helper()
	command := exec.Command(name, arguments...)
	command.Dir = directory
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("run %s %q: %v\n%s", name, arguments, err, output)
	}
}

func assertNullResultFields(t *testing.T, result map[string]json.RawMessage, fields []string) {
	t.Helper()
	for _, field := range fields {
		if got, present := result[field]; !present || !bytes.Equal(got, []byte("null")) {
			t.Fatalf("result.%s = %s, want exact null", field, got)
		}
	}
}
func buildMulgaeBinary(t *testing.T, root string) string {
	t.Helper()
	if binary := os.Getenv("MULGAE_E2E_BINARY"); binary != "" {
		if info, err := os.Stat(binary); err != nil || info.IsDir() || info.Mode()&0o111 == 0 {
			t.Fatalf("MULGAE_E2E_BINARY is not an executable file: %q: %v", binary, err)
		}
		return binary
	}
	binary := filepath.Join(t.TempDir(), "mulgae")
	build := exec.Command("go", "build", "-ldflags", "-X main.buildVersion=v1.4.2 -X main.buildRevision=0123456789abcdef0123456789abcdef01234567", "-o", binary, ".")
	build.Dir = root
	build.Env = append(os.Environ(), "GOPROXY=off", "GOSUMDB=off", "GOCACHE="+t.TempDir())
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build Mulgae binary: %v\n%s", err, output)
	}
	return binary
}

func mustAssetID(t *testing.T, value string) ports.AssetID {
	t.Helper()
	id, err := ports.ParseAssetID(value)
	if err != nil {
		t.Fatalf("parse asset ID %q: %v", value, err)
	}
	return id
}

func terminalLF(value []byte) []byte {
	return append(bytes.TrimRight(append([]byte(nil), value...), "\n"), '\n')
}

type binaryResult struct {
	stdout   []byte
	stderr   []byte
	exitCode int
}

func runMulgaeBinary(t *testing.T, binary, workingDirectory string, arguments ...string) binaryResult {
	t.Helper()
	return runMulgaeBinaryWithEnv(t, binary, workingDirectory, isolatedMulgaeEnv(t), arguments...)
}

func runMulgaeBinaryWithEnv(t *testing.T, binary, workingDirectory string, environment []string, arguments ...string) binaryResult {
	t.Helper()
	command := exec.Command(binary, arguments...)
	command.Dir = workingDirectory
	command.Env = environment
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	result := binaryResult{stdout: stdout.Bytes(), stderr: stderr.Bytes()}
	if err == nil {
		return result
	}
	var exitError *exec.ExitError
	if !errors.As(err, &exitError) {
		t.Fatalf("run Mulgae %q: %v", arguments, err)
	}
	result.exitCode = exitError.ExitCode()
	return result
}

func isolatedMulgaeEnv(t *testing.T) []string {
	t.Helper()
	root := t.TempDir()
	return []string{
		"HOME=" + root,
		"TMPDIR=" + root,
		"XDG_CACHE_HOME=" + root,
		"XDG_CONFIG_HOME=" + root,
		"PATH=/usr/bin:/bin:/usr/sbin:/sbin",
		"NO_PROXY=*",
		"GOPROXY=off",
		"GOSUMDB=off",
	}
}
func isolatedMulgaeEnvWith(t *testing.T, home, providerDirectory string) []string {
	t.Helper()
	return []string{
		"HOME=" + home,
		"TMPDIR=" + canonicalTestTempDir(t),
		"XDG_CACHE_HOME=" + canonicalTestTempDir(t),
		"XDG_CONFIG_HOME=" + canonicalTestTempDir(t),
		"PATH=" + providerDirectory + ":/usr/bin",
		"NO_PROXY=*",
		"GOPROXY=off",
		"GOSUMDB=off",
	}
}

func canonicalTestTempDir(t *testing.T) string {
	t.Helper()
	path, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Clean(path)
}
func repositoryRoot(t *testing.T) string {
	t.Helper()
	workingDirectory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	root, err := filepath.Abs(workingDirectory)
	if err != nil {
		t.Fatal(err)
	}
	return root
}

type compositionProjectReader struct {
	commit  ports.GitObjectID
	readErr error
	reads   int
}

func (reader *compositionProjectReader) ResolveCommit(context.Context, ports.AnchoredRoot, string) (ports.GitObjectID, error) {
	return reader.commit, nil
}

func (reader *compositionProjectReader) ReadFileAtCommit(context.Context, ports.AnchoredRoot, ports.GitObjectID, ports.SafeRelativePath) ([]byte, error) {
	reader.reads++
	return nil, reader.readErr
}
