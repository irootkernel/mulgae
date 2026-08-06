//go:build darwin && arm64

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"reflect"
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
	"github.com/irootkernel/mulgae/internal/app"
	appconfig "github.com/irootkernel/mulgae/internal/app/config"
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

func TestProductionRunPolicyPropagatesConfiguredProviderTimeouts(t *testing.T) {
	roles, err := adapterconfig.CanonicalRolesConfig([]string{"zcode", "agy"})
	if err != nil {
		t.Fatal(err)
	}
	raw := adapterconfig.Config{
		Version:    adapterconfig.ConfigVersion,
		Project:    adapterconfig.ProjectConfig{Name: "timeout-policy"},
		NativeUser: adapterconfig.NativeUserConfig{Home: "/Users/test"},
		Providers: adapterconfig.ProvidersConfig{
			ZCode: &adapterconfig.ZCodeProviderConfig{NodeExecutable: "/bin/node", Launcher: "/opt/zcode/launcher.cjs", Timeout: "30m"},
			AGY:   &adapterconfig.AGYProviderConfig{Executable: "/bin/agy", PermissionMode: "safe"},
		},
		Execution: adapterconfig.ExecutionConfig{WorkspaceAccess: "readonly_snapshot"},
		Roles:     roles,
		Review: adapterconfig.ReviewConfig{
			RequiredRoles:    []string{"logic", "security", "maintainability", "product", "documentation", "testing"},
			RequestChangesOn: []string{"high", "critical", "blocker"},
		},
		Validation: adapterconfig.ValidationConfig{
			Evidence: adapterconfig.EvidenceConfig{RequireVerifiedFor: []string{"high", "critical", "blocker"}},
			Repair:   adapterconfig.RepairConfig{Enabled: true, MaxAttempts: 1, SameProvider: true},
		},
		Resources: adapterconfig.ResourcesConfig{
			MaxActiveLanes: 3, PrimaryRepairAttempts: 1, FallbackRepairAttempts: 1,
			RoleMaxInvocations: 4, RunMaxInvocations: 28, RunTotalOutputCap: "64MiB",
		},
		CI: adapterconfig.CIConfig{FailOnSeverity: []string{"high", "critical", "blocker"}, DegradedReviewFails: true},
	}
	resolved, err := appconfig.ResolveConfiguration(raw)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := deriveProductionRunPolicy(resolved)
	if err != nil {
		t.Fatal(err)
	}
	want := map[reviewrun.Family]time.Duration{
		reviewrun.FamilyKimi:  appconfig.DefaultProviderTimeout,
		reviewrun.FamilyZCode: 30 * time.Minute,
		reviewrun.FamilyAGY:   appconfig.DefaultProviderTimeout,
	}
	if !reflect.DeepEqual(policy.providerTimeouts, want) {
		t.Fatalf("production provider timeouts = %#v, want %#v", policy.providerTimeouts, want)
	}
	if policy.agyPermissionMode != adapterconfig.SafeAGYPermissionMode {
		t.Fatalf("production AGY permission mode = %q, want explicit safe", policy.agyPermissionMode)
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
	if stdout.String() != "{\"name\":\"mulgae\",\"version\":\"(devel)\"}\n" {
		t.Fatalf("JSON version = %q", stdout.String())
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

type failingReviewPreflightService struct{ err error }

func (service failingReviewPreflightService) PreflightReview(context.Context, mulgaeentry.ReviewRequest, ports.AnchoredRoot) (mulgaeentry.ReviewPreflightResult, error) {
	return mulgaeentry.ReviewPreflightResult{}, service.err
}

func TestReviewPreflightCompositionCleansTemporaryRootAfterMaterializationFailure(t *testing.T) {
	workspacePath := canonicalTestTempDir(t)
	workspaceRoot, err := ports.NewAnchoredRoot(workspacePath)
	if err != nil {
		t.Fatal(err)
	}
	materializationErr := errors.New("injected materialization failure")
	service := &rootCleaningReviewPreflightService{
		inner:         failingReviewPreflightService{err: materializationErr},
		workspaceRoot: workspaceRoot,
	}
	_, err = service.PreflightReview(context.Background(), mulgaeentry.ReviewRequest{}, ports.AnchoredRoot{})
	if !errors.Is(err, materializationErr) {
		t.Fatalf("preflight error = %v, want materialization failure", err)
	}
	if _, statErr := os.Lstat(workspacePath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("preflight retained temporary root %q: %v", workspacePath, statErr)
	}
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
		var version versionOutput
		if err := json.Unmarshal(machine.stdout, &version); err != nil {
			t.Fatal(err)
		}
		if version.Name != productName || version.Version != "v1.4.2" {
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

	t.Run("auto discovery requires zcode and agy while ignoring ambient kimi", func(t *testing.T) {
		installed, err := user.Current()
		if err != nil || installed == nil {
			t.Fatalf("current native account unavailable: %#v %v", installed, err)
		}
		overrideDirectory := canonicalTestTempDir(t)
		emptyPATH := canonicalTestTempDir(t)
		paths := map[string]string{
			"kimi":     filepath.Join(emptyPATH, "kimi"),
			"node":     filepath.Join(overrideDirectory, "node-override"),
			"launcher": filepath.Join(overrideDirectory, "zcode-launcher.cjs"),
			"agy":      filepath.Join(overrideDirectory, "agy-override"),
		}
		for _, path := range []string{paths["kimi"], paths["node"], paths["agy"]} {
			mustWriteTestFile(t, path, []byte("#!/bin/sh\nexit 0\n"))
			if err := os.Chmod(path, 0o700); err != nil {
				t.Fatal(err)
			}
		}
		mustWriteTestFile(t, paths["launcher"], []byte("module.exports = {};\n"))
		environment := isolatedMulgaeEnvWith(t, installed.HomeDir, emptyPATH)
		for _, test := range []struct {
			name       string
			arguments  []string
			shouldPass bool
			candidates []string
		}{
			{name: "neither", candidates: []string{}},
			{name: "zcode only", arguments: []string{"--zcode-node-executable", paths["node"], "--zcode-launcher", paths["launcher"]}, candidates: []string{"zcode"}},
			{name: "agy only", arguments: []string{"--agy-executable", paths["agy"]}, candidates: []string{"agy"}},
			{name: "zcode and agy", arguments: []string{"--zcode-node-executable", paths["node"], "--zcode-launcher", paths["launcher"], "--agy-executable", paths["agy"], "--agy-permission-mode", "safe", "--native-home", installed.HomeDir}, shouldPass: true, candidates: []string{"zcode", "agy"}},
		} {
			for _, format := range []string{"human", "json"} {
				t.Run(fmt.Sprintf("%s_%s", test.name, format), func(t *testing.T) {
					project := canonicalTestTempDir(t)
					initializeReviewGitRepository(t, project)
					arguments := []string{"init", "--providers", "auto", "--name", "auto-project"}
					arguments = append(arguments, test.arguments...)
					if format == "json" {
						arguments = append(arguments, "--output", "json")
					}
					result := runMulgaeBinaryWithEnv(t, binary, project, environment, arguments...)
					if !test.shouldPass {
						if result.exitCode != 4 || len(result.stderr) != 0 || len(result.stdout) == 0 {
							t.Fatalf("auto %s = exit %d stdout %q stderr %q", test.name, result.exitCode, result.stdout, result.stderr)
						}
						if _, err := os.Lstat(filepath.Join(project, ".mulgae")); !errors.Is(err, os.ErrNotExist) {
							t.Fatalf("auto %s mutated project: %v", test.name, err)
						}
						return
					}
					if result.exitCode != 0 || len(result.stderr) != 0 || len(result.stdout) == 0 {
						t.Fatalf("auto %s = exit %d stdout %q stderr %q", test.name, result.exitCode, result.stdout, result.stderr)
					}
					data, err := os.ReadFile(filepath.Join(project, ".mulgae", "config.yaml"))
					if err != nil {
						t.Fatal(err)
					}
					config, err := (adapterconfig.YAMLCodec{}).Decode(data)
					if err != nil || !slices.Equal(config.Providers.Families(), test.candidates) {
						t.Fatalf("auto config families = %v err=%v, want %v", config.Providers.Families(), err, test.candidates)
					}
					if config.Roles.Logic.PrimaryProvider != "zcode" || config.Roles.Logic.FallbackProvider != "agy" {
						t.Fatalf("auto logic assignment = %#v", config.Roles.Logic)
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
						if err := json.Unmarshal(result.stdout, &envelope); err != nil || envelope.Request.Selection.Mode != "auto" || !slices.Equal(envelope.Result.Candidates, test.candidates) || !slices.Equal(envelope.Result.Configured, test.candidates) {
							t.Fatalf("auto JSON projection = %#v err=%v", envelope, err)
						}
					}
				})
			}
		}
	})

	t.Run("agy omission selects headless default while safe remains explicit", func(t *testing.T) {
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
		projects := []string{canonicalTestTempDir(t), canonicalTestTempDir(t), canonicalTestTempDir(t)}
		for _, project := range projects {
			initializeReviewGitRepository(t, project)
		}
		base := []string{"init", "--name", "headless-project", "--providers", "agy", "--agy-executable", agy, "--output", "json"}
		omitted := runMulgaeBinaryWithEnv(t, binary, projects[0], environment, base...)
		explicitHeadlessArguments := append(append([]string(nil), base...), "--agy-permission-mode", "dangerously-skip-permissions")
		explicitHeadless := runMulgaeBinaryWithEnv(t, binary, projects[1], environment, explicitHeadlessArguments...)
		safeArguments := append(append([]string(nil), base...), "--agy-permission-mode", "safe")
		safe := runMulgaeBinaryWithEnv(t, binary, projects[2], environment, safeArguments...)
		if omitted.exitCode != 0 || explicitHeadless.exitCode != 0 || safe.exitCode != 0 {
			t.Fatalf("AGY init exits = omitted %d explicit-headless %d safe %d", omitted.exitCode, explicitHeadless.exitCode, safe.exitCode)
		}
		omittedConfig, err := os.ReadFile(filepath.Join(projects[0], ".mulgae", "config.yaml"))
		if err != nil {
			t.Fatal(err)
		}
		explicitHeadlessConfig, err := os.ReadFile(filepath.Join(projects[1], ".mulgae", "config.yaml"))
		if err != nil {
			t.Fatal(err)
		}
		safeConfig, err := os.ReadFile(filepath.Join(projects[2], ".mulgae", "config.yaml"))
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(omittedConfig, []byte("permission_mode:")) ||
			!bytes.Contains(explicitHeadlessConfig, []byte(`permission_mode: "dangerously-skip-permissions"`)) ||
			!bytes.Contains(safeConfig, []byte(`permission_mode: "safe"`)) {
			t.Fatalf("AGY canonical modes = omitted:\n%s\nexplicit headless:\n%s\nsafe:\n%s", omittedConfig, explicitHeadlessConfig, safeConfig)
		}
		repeated := runMulgaeBinaryWithEnv(t, binary, projects[2], environment, safeArguments...)
		if repeated.exitCode != 2 || len(repeated.stderr) != 0 {
			t.Fatalf("repeat init = exit %d stdout %q stderr %q", repeated.exitCode, repeated.stdout, repeated.stderr)
		}
		after, err := os.ReadFile(filepath.Join(projects[2], ".mulgae", "config.yaml"))
		if err != nil || !bytes.Equal(after, safeConfig) {
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

// Unbound capability evidence is an operational qualification rejection:
// exit 4 readiness, retryable, one family probe, and no publication artifacts.
func TestIntegrationMulgaeProductionReviewSubprocessKimiQualificationNonAdmission(t *testing.T) {
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
	if review.exitCode != 4 || len(review.stderr) != 0 {
		t.Fatalf("Kimi qualification non-admission = exit %d stdout %q stderr %q", review.exitCode, review.stdout, review.stderr)
	}
	var envelope commandEnvelope
	if err := json.Unmarshal(review.stdout, &envelope); err != nil {
		t.Fatalf("decode Kimi qualification envelope: %v", err)
	}
	if envelope.Command != "review" || envelope.Exit.Code != 4 || envelope.Exit.Kind != "readiness" ||
		envelope.Result.Kind != "review_started" || envelope.Result.SessionID == nil ||
		envelope.Result.RunID == nil || envelope.Result.RunManifestURI != nil || envelope.Result.ReviewArtifactURI != nil ||
		len(envelope.Reasons) != 1 || envelope.Reasons[0].Category != "readiness" || envelope.Reasons[0].ArtifactURI == nil ||
		envelope.Reasons[0].Code != "provider_qualification_failed" || !envelope.Reasons[0].Retryable {
		t.Fatalf("Kimi qualification envelope = %#v", envelope)
	}
	if _, err := domain.ParseSessionID(*envelope.Result.SessionID); err != nil {
		t.Fatalf("Kimi qualification session ID = %q: %v", *envelope.Result.SessionID, err)
	}
	if _, err := domain.ParseRunID(*envelope.Result.RunID); err != nil {
		t.Fatalf("Kimi qualification run ID = %q: %v", *envelope.Result.RunID, err)
	}
	entries, err := os.ReadDir(filepath.Join(project, ".mulgae"))
	if err != nil {
		t.Fatalf("read Kimi qualification artifact directory: %v", err)
	}
	if len(entries) != 2 || entries[0].Name() != "config.yaml" || entries[1].Name() != "diagnostics" || !entries[1].IsDir() {
		t.Fatalf("Kimi qualification rejection created unexpected artifacts: %v", entries)
	}
	diagnosticRuns, err := filepath.Glob(filepath.Join(project, ".mulgae", "diagnostics", "s_*", "r_*"))
	if err != nil || len(diagnosticRuns) != 1 {
		t.Fatalf("Kimi qualification diagnostics = %v, %v", diagnosticRuns, err)
	}
	wantDiagnosticURI, err := filepath.Rel(project, diagnosticRuns[0])
	if err != nil || filepath.ToSlash(wantDiagnosticURI) != *envelope.Reasons[0].ArtifactURI {
		t.Fatalf("Kimi diagnostic URI = %v, want %q (rel err %v)", envelope.Reasons[0].ArtifactURI, filepath.ToSlash(wantDiagnosticURI), err)
	}
	if !strings.Contains(*envelope.Reasons[0].ArtifactURI, "/"+*envelope.Result.SessionID+"/"+*envelope.Result.RunID) {
		t.Fatalf("Kimi diagnostic URI %q does not bind returned identity", *envelope.Reasons[0].ArtifactURI)
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
		t.Fatalf("Kimi qualification diagnostics were not finalized: %q", logBytes)
	}
	observations := readFakeKimiObservations(t, logPath)
	if len(observations) != 1 {
		t.Fatalf("Kimi qualification launch count = %d, want 1 family probe: %#v", len(observations), observations)
	}
	observation := observations[0]
	if !strings.Contains(observation.Prompt, "Prove readiness by binding the immutable fixture values below.") &&
		!strings.Contains(observation.Prompt, "The object must contain exactly root, link, and role string fields.") {
		t.Fatalf("Kimi qualification prompt missing readiness binding: %#v", observation)
	}
	if !strings.Contains(observation.Prompt, "role=logic") && !strings.Contains(observation.Prompt, "role must be logic") {
		t.Fatalf("Kimi family qualification did not probe base role: %#v", observation)
	}
}

func TestIntegrationMulgaeProductionReviewSubprocessAGY(t *testing.T) {
	root := repositoryRoot(t)
	binary := buildMulgaeBinary(t, root)
	project := canonicalTestTempDir(t)
	initializeReviewGitRepository(t, project)
	mustWriteTestFile(t, filepath.Join(project, "security-fixtures.txt"), []byte(strings.Join([]string{
		"changePassword: vi.fn()",
		"Authorization: Bearer abcdefghijklmnop",
		"api_key=placeholder-api-key",
		"-----BEGIN RSA PRIVATE KEY-----",
		"placeholder",
		"-----END RSA PRIVATE KEY-----",
	}, "\n")+"\n"))
	runTestCommand(t, project, "git", "add", "security-fixtures.txt")

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
	const credentialLikeSummary = "Reviewed changePassword: vi.fn() with Authorization: Bearer abcdefghijklmnop and password=development-only fixtures."
	credentialLikeOutput := fmt.Sprintf(
		`{"schema_version":"mulgae-provider-review-output.v1","summary":"One informational fixture finding.","completeness":"complete","limitations":[],"findings":[{"severity":"info","title":"Credential-like fixture remains reviewable","description":%q,"evidence":[{"current":{"path":"security-fixtures.txt","side":"index","line_start":2,"line_end":2,"quote":"Authorization: Bearer abcdefghijklmnop\n"}}],"recommendation":%q,"confidence":"high"}]}`,
		credentialLikeSummary, credentialLikeSummary,
	)
	buildFakeAGYWithReviewOutput(t, root, filepath.Join(providerDirectory, "agy"), logPath, credentialLikeOutput)
	environment := isolatedMulgaeEnvWith(t, installedUser.HomeDir, providerDirectory)
	environment = append(environment, "MULGAE_FAKE_AGY_LOG="+logPath)
	initialized := runMulgaeBinaryWithEnv(t, binary, project, environment,
		"init", "--providers", "agy", "--roles", "security", "--agy-executable", filepath.Join(providerDirectory, "agy"))
	if initialized.exitCode != 0 {
		t.Fatalf("initialize AGY local config: exit=%d stdout=%q stderr=%q", initialized.exitCode, initialized.stdout, initialized.stderr)
	}
	configBytes, err := os.ReadFile(filepath.Join(project, ".mulgae", "config.yaml"))
	if err != nil || bytes.Contains(configBytes, []byte("permission_mode:")) {
		t.Fatalf("default AGY config should omit permission mode: err=%v\n%s", err, configBytes)
	}

	const objective = "@roadmap.md review the changed behavior without rewriting this objective"
	review := runMulgaeBinaryWithEnv(t, binary, project, environment,
		"review", "--stage", "--objective", objective, "--roles", "logic,security", "--output", "json")
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
	finalBytes, err := os.ReadFile(filepath.Join(project, *reviewEnvelope.Result.ReviewArtifactURI))
	if err != nil || !bytes.Contains(finalBytes, []byte(credentialLikeSummary)) {
		t.Fatalf("published final omitted credential-like reviewed evidence: err=%v\n%s", err, finalBytes)
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
	if err != nil || len(rawStreams) != 0 {
		t.Fatalf("credential-like AGY raw diagnostics should be dropped without blocking publication: %v, %v", rawStreams, err)
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
	// AGY control evidence is instance-bound, so each configured AGY role route
	// performs its own qualification probe within the command.
	if len(versionChecks) > 2 || len(qualificationRuns) != 2 || len(reviewRuns) != 2 {
		argv := make([][]string, 0, len(observations))
		for _, observation := range observations {
			argv = append(argv, observation.Argv)
		}
		t.Fatalf("AGY launches = versions:%d qualifications:%d reviews:%d argv=%v, want at most two diagnostic version checks, two instance qualifications, and two review launches", len(versionChecks), len(qualificationRuns), len(reviewRuns), argv)
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

func TestIntegrationMulgaeProductionSixRoleReviewPublishesAndReopens(t *testing.T) {
	root := repositoryRoot(t)
	binary := buildMulgaeBinary(t, root)
	project := canonicalTestTempDir(t)
	initializeReviewGitRepository(t, project)

	installedUser, err := user.Current()
	if err != nil || installedUser == nil || !filepath.IsAbs(installedUser.HomeDir) {
		t.Fatalf("current native home unavailable: user=%#v err=%v", installedUser, err)
	}
	providerDirectory := canonicalTestTempDir(t)
	logDirectory := canonicalTestTempDir(t)
	zcodeNode := filepath.Join(providerDirectory, "node")
	zcodeLauncher := filepath.Join(providerDirectory, "zcode.cjs")
	agyExecutable := filepath.Join(providerDirectory, "agy")
	buildFakeZCode(t, root, zcodeNode, zcodeLauncher, filepath.Join(logDirectory, "zcode.jsonl"), "success")
	buildFakeAGY(t, root, agyExecutable, filepath.Join(logDirectory, "agy.jsonl"))
	environment := isolatedMulgaeEnvWith(t, installedUser.HomeDir, providerDirectory)

	initialized := runMulgaeBinaryWithEnv(t, binary, project, environment,
		"init", "--providers", "zcode,agy",
		"--roles", "logic,security,maintainability,product,documentation,testing",
		"--zcode-node-executable", zcodeNode, "--zcode-launcher", zcodeLauncher,
		"--agy-executable", agyExecutable)
	if initialized.exitCode != 0 {
		t.Fatalf("initialize six-role config: exit=%d stdout=%q stderr=%q", initialized.exitCode, initialized.stdout, initialized.stderr)
	}

	review := runMulgaeBinaryWithEnv(t, binary, project, environment,
		"review", "--dirty",
		"--roles", "logic,security,maintainability,product,documentation,testing",
		"--objective", "Review the changed behavior and report only captured-target findings.",
		"--output", "json")
	if review.exitCode != 0 || len(review.stderr) != 0 {
		t.Fatalf("six-role production review: exit=%d stdout=%q stderr=%q", review.exitCode, review.stdout, review.stderr)
	}
	var envelope commandEnvelope
	if err := json.Unmarshal(review.stdout, &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Result.SessionID == nil || envelope.Result.RunID == nil ||
		envelope.Result.RunManifestURI == nil || envelope.Result.ReviewArtifactURI == nil {
		t.Fatalf("six-role publication omitted identity or artifacts: %#v", envelope)
	}
	for _, uri := range []*string{envelope.Result.RunManifestURI, envelope.Result.ReviewArtifactURI} {
		if _, err := os.Stat(filepath.Join(project, *uri)); err != nil {
			t.Fatalf("six-role publication artifact %q is unreadable: %v", *uri, err)
		}
	}
	assertCommandRoleReportInventory(t, project, envelope)
	diagnosticBytes, err := os.ReadFile(filepath.Join(
		project, ".mulgae", "diagnostics", *envelope.Result.SessionID, *envelope.Result.RunID, "status.json",
	))
	if err != nil {
		t.Fatal(err)
	}
	var diagnostic struct {
		State         domain.RunState `json:"state"`
		LaneTotal     int             `json:"lane_total"`
		LaneCompleted int             `json:"lane_completed"`
		LaneFailed    int             `json:"lane_failed"`
		P2URI         string          `json:"p2_uri"`
	}
	if err := json.Unmarshal(diagnosticBytes, &diagnostic); err != nil {
		t.Fatal(err)
	}
	if diagnostic.State != domain.RunCompleted || diagnostic.LaneTotal != 6 || diagnostic.LaneCompleted != 6 ||
		diagnostic.LaneFailed != 0 || diagnostic.P2URI != *envelope.Result.RunManifestURI {
		t.Fatalf("six-role diagnostic status = %#v", diagnostic)
	}

	status := runMulgaeBinaryWithEnv(t, binary, project, environment,
		"status", "--run", *envelope.Result.RunID, "--output", "json")
	if status.exitCode != 0 || len(status.stderr) != 0 {
		t.Fatalf("six-role status: exit=%d stdout=%q stderr=%q", status.exitCode, status.stdout, status.stderr)
	}
	var statusEnvelope commandEnvelope
	if err := json.Unmarshal(status.stdout, &statusEnvelope); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(statusEnvelope.Result.RoleReportURIs, envelope.Result.RoleReportURIs) {
		t.Fatalf("six-role status role_report_uris = %#v, want %#v", statusEnvelope.Result.RoleReportURIs, envelope.Result.RoleReportURIs)
	}
	findings := runMulgaeBinaryWithEnv(t, binary, project, environment,
		"findings", "--run", *envelope.Result.RunID, "--severity", "low", "--output", "json")
	if findings.exitCode != 0 || len(findings.stderr) != 0 {
		t.Fatalf("six-role findings: exit=%d stdout=%q stderr=%q", findings.exitCode, findings.stdout, findings.stderr)
	}
}

func TestIntegrationMulgaeProductionReviewPreflightIsExecutionFreeAndPreservesPNG(t *testing.T) {
	root := repositoryRoot(t)
	binary := buildMulgaeBinary(t, root)
	project := canonicalTestTempDir(t)
	initializeReviewGitRepository(t, project)

	providerDirectory := canonicalTestTempDir(t)
	logDirectory := canonicalTestTempDir(t)
	zcodeLog, agyLog := filepath.Join(logDirectory, "zcode.jsonl"), filepath.Join(logDirectory, "agy.jsonl")
	zcodeNode, zcodeLauncher := filepath.Join(providerDirectory, "node"), filepath.Join(providerDirectory, "zcode.cjs")
	agyExecutable := filepath.Join(providerDirectory, "agy")
	buildFakeZCode(t, root, zcodeNode, zcodeLauncher, zcodeLog, "success")
	buildFakeAGY(t, root, agyExecutable, agyLog)
	home := canonicalTestTempDir(t)
	environment := isolatedMulgaeEnvWith(t, home, providerDirectory)
	initialized := runMulgaeBinaryWithEnv(t, binary, project, environment,
		"init", "--providers", "zcode,agy", "--roles", "logic,security,artist", "--project-kind", "ui",
		"--artist-brief", "roadmap.md", "--artist-design-specs", "screenshots/**/*.png",
		"--zcode-node-executable", zcodeNode, "--zcode-launcher", zcodeLauncher, "--agy-executable", agyExecutable)
	if initialized.exitCode != 0 {
		t.Fatalf("initialize first-project integration config: exit=%d stdout=%q stderr=%q", initialized.exitCode, initialized.stdout, initialized.stderr)
	}

	configPath := filepath.Join(project, ".mulgae", "config.yaml")
	configBytes, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	launcherLine := "    launcher: \"" + zcodeLauncher + "\"\n"
	if !bytes.Contains(configBytes, []byte(launcherLine)) {
		t.Fatalf("config omits ZCode launcher line:\n%s", configBytes)
	}
	configBytes = bytes.Replace(configBytes, []byte(launcherLine), []byte(launcherLine+"    timeout: \"30m\"\n"), 1)
	mustWriteTestFile(t, configPath, configBytes)

	pngBytes, err := base64.StdEncoding.DecodeString("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=")
	if err != nil {
		t.Fatal(err)
	}
	worktreePNG := append(append([]byte(nil), pngBytes...), []byte("worktree-only-drift")...)
	mustWriteTestFile(t, filepath.Join(project, "screenshots", "staged.png"), pngBytes)
	credentialFixtures := []byte(strings.Join([]string{
		"changePassword: vi.fn()",
		"Authorization: Bearer abcdefghijklmnop",
		"api_key=placeholder-api-key",
		"-----BEGIN RSA PRIVATE KEY-----",
		"placeholder-private-key",
		"-----END RSA PRIVATE KEY-----",
		"database_password=development-only",
	}, "\n") + "\n")
	mustWriteTestFile(t, filepath.Join(project, "security-fixtures.txt"), credentialFixtures)
	mustWriteTestFile(t, filepath.Join(project, "ignored.txt"), []byte("must not be transmitted\n"))
	mustWriteTestFile(t, filepath.Join(project, ".mulgaeignore"), []byte("ignored.txt\n"))
	runTestCommand(t, project, "git", "add", "review.go", "screenshots/staged.png", "security-fixtures.txt", ".mulgaeignore")
	mustWriteTestFile(t, filepath.Join(project, "screenshots", "staged.png"), worktreePNG)

	beforeMulgae := snapshotTestTree(t, filepath.Join(project, ".mulgae"))
	tempRoot := environmentValue(t, environment, "TMPDIR")
	beforeTemp := snapshotTestTree(t, tempRoot)
	first := runMulgaeBinaryWithEnv(t, binary, project, environment, "review", "--stage", "--roles", "logic,security,artist", "--preflight", "--output", "json")
	second := runMulgaeBinaryWithEnv(t, binary, project, environment, "review", "--stage", "--roles", "logic,security,artist", "--preflight", "--output", "json")
	if first.exitCode != 0 || second.exitCode != 0 || len(first.stderr) != 0 || len(second.stderr) != 0 {
		t.Fatalf("preflight exits = %d/%d stderr=%q/%q stdout=%q", first.exitCode, second.exitCode, first.stderr, second.stderr, first.stdout)
	}
	if got := snapshotTestTree(t, filepath.Join(project, ".mulgae")); !reflect.DeepEqual(got, beforeMulgae) {
		t.Fatalf("preflight mutated .mulgae: before=%v after=%v", beforeMulgae, got)
	}
	if got := snapshotTestTree(t, tempRoot); !reflect.DeepEqual(got, beforeTemp) {
		t.Fatalf("preflight leaked temporary workspace: before=%v after=%v", beforeTemp, got)
	}
	for _, logPath := range []string{zcodeLog, agyLog} {
		if observed, readErr := os.ReadFile(logPath); readErr == nil && len(bytes.TrimSpace(observed)) != 0 {
			t.Fatalf("preflight invoked provider %s: %s", logPath, observed)
		} else if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
			t.Fatal(readErr)
		}
	}

	type preflightEnvelope struct {
		Result struct {
			Kind      string                            `json:"kind"`
			Preflight mulgaeentry.ReviewPreflightResult `json:"preflight"`
		} `json:"result"`
	}
	decode := func(raw []byte) mulgaeentry.ReviewPreflightResult {
		t.Helper()
		var envelope preflightEnvelope
		if err := json.Unmarshal(raw, &envelope); err != nil {
			t.Fatal(err)
		}
		if envelope.Result.Kind != "review_preflight" {
			t.Fatalf("result kind = %q", envelope.Result.Kind)
		}
		return envelope.Result.Preflight
	}
	firstResult, secondResult := decode(first.stdout), decode(second.stdout)
	if !reflect.DeepEqual(firstResult, secondResult) {
		t.Fatalf("preflight projection is nondeterministic:\n%#v\n%#v", firstResult, secondResult)
	}
	wantRoutes := []string{
		"logic/primary/zcode/zcode-logic/30m/not_applicable/prompt",
		"logic/fallback/agy/agy-logic/15m/safe/prompt",
		"security/primary/zcode/zcode-security/30m/not_applicable/prompt",
		"security/fallback/agy/agy-security/15m/safe/prompt",
		"artist/primary/agy/agy-artist/15m/safe/prompt",
		"artist/fallback/zcode/zcode-artist/30m/not_applicable/prompt",
	}
	gotRoutes := make([]string, 0, len(firstResult.Transmissions))
	if len(firstResult.FileSets) != 1 || firstResult.FileSets[0].ID == "" {
		t.Fatalf("preflight file sets = %#v, want one identified exact transmission set", firstResult.FileSets)
	}
	fileSetID := firstResult.FileSets[0].ID
	for _, route := range firstResult.Transmissions {
		gotRoutes = append(gotRoutes, strings.Join([]string{route.Role, route.RouteKind, route.ProviderFamily, route.ProviderInstance, route.ConfiguredTimeout, route.PermissionMode, route.TargetChannel}, "/"))
		if route.FileSetID != fileSetID {
			t.Fatalf("preflight routes do not share the exact file set: %#v", firstResult.Transmissions)
		}
	}
	if firstResult.AGYPermissionMode != "safe" || !slices.Equal(gotRoutes, wantRoutes) {
		t.Fatalf("preflight routes = mode %q %v, want %v", firstResult.AGYPermissionMode, gotRoutes, wantRoutes)
	}
	wantLanes := []mulgaeentry.ReviewPreflightLaneDeadline{
		{ConcurrencyKey: "agy-artist", InvocationCount: 2, TransitionCount: 2, InvocationTimeouts: "30m0s", Deadline: "30m4s"},
		{ConcurrencyKey: "agy-logic", InvocationCount: 2, TransitionCount: 1, InvocationTimeouts: "30m0s", Deadline: "30m2s"},
		{ConcurrencyKey: "agy-security", InvocationCount: 2, TransitionCount: 1, InvocationTimeouts: "30m0s", Deadline: "30m2s"},
		{ConcurrencyKey: "zcode-artist", InvocationCount: 2, TransitionCount: 1, InvocationTimeouts: "1h0m0s", Deadline: "1h0m2s"},
		{ConcurrencyKey: "zcode-logic", InvocationCount: 2, TransitionCount: 2, InvocationTimeouts: "1h0m0s", Deadline: "1h0m4s"},
		{ConcurrencyKey: "zcode-security", InvocationCount: 2, TransitionCount: 2, InvocationTimeouts: "1h0m0s", Deadline: "1h0m4s"},
	}
	if budget := firstResult.Budget; budget.ReasonCode != "eligible" || budget.MaxActiveLanes != 3 || budget.TotalInvocations != 12 ||
		budget.TotalOutputCapBytes != 6<<20 || budget.CriticalPathDeadline != "1h30m6s" || budget.RunDeadline != "2h30m15s" ||
		budget.Ceilings.ProviderTimeout != "60m" || budget.Ceilings.LaneDeadline != "28h0m42s" || budget.Ceilings.RunDeadline != "28h0m47s" ||
		budget.Ceilings.MaxInvocationsPerRole != 4 || budget.Ceilings.MaxInvocationsPerRun != 12 || budget.Ceilings.MaxTotalOutputBytes != 64<<20 ||
		!reflect.DeepEqual(budget.Lanes, wantLanes) {
		t.Fatalf("preflight budget = %#v, want exact first-project capacity envelope", budget)
	}
	wantPNGHash := sha256.Sum256(pngBytes)
	wantPNG := "sha256:" + hex.EncodeToString(wantPNGHash[:])
	seenPNG, seenIgnored := false, false
	paths := make([]string, 0, len(firstResult.FileSets[0].Files))
	for _, file := range firstResult.FileSets[0].Files {
		paths = append(paths, file.Path)
		if file.Path == "ignored.txt" {
			seenIgnored = true
		}
		if file.Path == "screenshots/staged.png" {
			seenPNG = file.MediaType == "image/png" && file.Disposition == "binary_preserved" && file.Size == int64(len(pngBytes)) && file.SHA256 == wantPNG
		}
	}
	if !seenPNG || seenIgnored {
		t.Fatalf("preflight file catalog PNG/ignored = %t/%t: %#v", seenPNG, seenIgnored, firstResult.FileSets)
	}
	wantPaths := []string{".mulgaeignore", "docs/linked.md", "review.go", "roadmap.md", "screenshots/staged.png", "security-fixtures.txt"}
	if !slices.Equal(paths, wantPaths) {
		t.Fatalf("exact transmitted source paths = %v, want %v", paths, wantPaths)
	}

	actual := runMulgaeBinaryWithEnv(t, binary, project, environment,
		"review", "--stage", "--roles", "logic,security,artist", "--output", "json")
	var actualEnvelope commandEnvelope
	if err := json.Unmarshal(actual.stdout, &actualEnvelope); err != nil || actual.exitCode != 0 || len(actual.stderr) != 0 ||
		actualEnvelope.Result.Kind != "review_started" || actualEnvelope.Result.SessionID == nil || actualEnvelope.Result.RunID == nil ||
		actualEnvelope.Result.RunManifestURI == nil || actualEnvelope.Result.ReviewArtifactURI == nil {
		t.Fatalf("actual first-project review = exit %d envelope %#v decode=%v stdout=%q stderr=%q", actual.exitCode, actualEnvelope, err, actual.stdout, actual.stderr)
	}
	type zcodeObservation struct {
		CWD    string `json:"cwd"`
		Prompt string `json:"prompt"`
	}
	zcodeBytes, err := os.ReadFile(zcodeLog)
	if err != nil {
		t.Fatal(err)
	}
	var zcodeQualification, zcodeReviews int
	for _, line := range strings.Split(strings.TrimSpace(string(zcodeBytes)), "\n") {
		var observation zcodeObservation
		if err := json.Unmarshal([]byte(line), &observation); err != nil {
			t.Fatal(err)
		}
		if observation.CWD == project || !strings.HasPrefix(observation.CWD, tempRoot+string(filepath.Separator)) {
			t.Fatalf("ZCode escaped the bounded snapshot: %#v", observation)
		}
		if strings.Contains(observation.Prompt, "Prove readiness by binding the immutable fixture values below.") ||
			strings.Contains(observation.Prompt, "The object must contain exactly root, link, and role string fields.") {
			zcodeQualification++
		} else {
			zcodeReviews++
		}
	}
	if zcodeQualification != 1 || zcodeReviews != 2 {
		t.Fatalf("ZCode launches = qualification:%d reviews:%d, want 1/2", zcodeQualification, zcodeReviews)
	}
	agyObservations := readFakeAGYObservations(t, agyLog)
	var agyQualification, agyReviews int
	for _, observation := range agyObservations {
		if len(observation.Argv) == 1 && observation.Argv[0] == "--version" {
			continue
		}
		if observation.CWD != observation.Snapshot || observation.CWD == project || !strings.HasPrefix(observation.CWD, tempRoot+string(filepath.Separator)) {
			t.Fatalf("AGY bounded snapshot contract = %#v", observation)
		}
		if observation.Prompt == "@roadmap.md" {
			agyQualification++
			continue
		}
		agyReviews++
		if observation.Fixture != string(credentialFixtures) || observation.PNG != wantPNG ||
			!slices.Contains(observation.Argv, "--sandbox") || slices.Contains(observation.Argv, "--dangerously-skip-permissions") ||
			!slices.Contains(observation.Argv, "--add-dir") {
			t.Fatalf("AGY did not read the exact bounded fixture and raster evidence: %#v", observation)
		}
	}
	// logic/security/artist each admit an AGY candidate; only artist executes on AGY.
	if agyQualification != 3 || agyReviews != 1 {
		t.Fatalf("AGY launches = qualification:%d reviews:%d, want 3/1: %#v", agyQualification, agyReviews, agyObservations)
	}
	archivePath := filepath.Join(project, ".mulgae", *actualEnvelope.Result.SessionID, *actualEnvelope.Result.RunID, "target", "captured-review.json")
	archiveBytes, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	archive, err := ports.UnmarshalCapturedReviewMaterial(archiveBytes)
	if err != nil {
		t.Fatal(err)
	}
	assertExactPNG := func(label string, files []ports.WorkspaceSnapshotFile) {
		t.Helper()
		for _, file := range files {
			if file.Path().String() == "screenshots/staged.png" {
				if file.MediaType() != "image/png" || file.SHA256() != wantPNG || !bytes.Equal(file.Bytes(), pngBytes) {
					t.Fatalf("%s PNG = media=%q hash=%q bytes=%x", label, file.MediaType(), file.SHA256(), file.Bytes())
				}
				return
			}
		}
		t.Fatalf("%s omitted staged PNG", label)
	}
	assertExactPNG("archive snapshot", archive.Snapshot().Files())
	indexEvidence, ok := archive.Evidence().Files(ports.CapturedEvidenceIndex)
	if !ok {
		t.Fatal("archive omitted index evidence")
	}
	assertExactPNG("archive index evidence", indexEvidence)
	if observed, err := os.ReadFile(filepath.Join(project, "screenshots", "staged.png")); err != nil || !bytes.Equal(observed, worktreePNG) {
		t.Fatalf("actual review mutated the divergent worktree PNG: err=%v bytes=%x", err, observed)
	}
	agyBytes, err := os.ReadFile(agyLog)
	if err != nil {
		t.Fatal(err)
	}
	providerLogBaseline := map[string][]byte{zcodeLog: append([]byte(nil), zcodeBytes...), agyLog: append([]byte(nil), agyBytes...)}
	assertProviderLogsUnchanged := func(stage string) {
		t.Helper()
		for path, baseline := range providerLogBaseline {
			observed, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(observed, baseline) {
				t.Fatalf("%s preflight invoked a provider: path=%s err=%v\nbefore=%s\nafter=%s", stage, path, err, baseline, observed)
			}
		}
	}

	beforeMulgae = snapshotTestTree(t, filepath.Join(project, ".mulgae"))
	beforeTemp = snapshotTestTree(t, tempRoot)

	mustWriteTestFile(t, filepath.Join(project, "screenshots", "staged.png"), []byte("not-a-png"))
	runTestCommand(t, project, "git", "add", "screenshots/staged.png")
	failed := runMulgaeBinaryWithEnv(t, binary, project, environment, "review", "--stage", "--roles", "security", "--preflight", "--output", "json")
	if failed.exitCode != int(app.ExitCodeArtifact) || !bytes.Contains(failed.stdout, []byte(`"kind":"review_preflight_failed"`)) ||
		!bytes.Contains(failed.stdout, []byte(`"code":"unsupported_content"`)) {
		t.Fatalf("capture failure = exit %d stdout=%q stderr=%q", failed.exitCode, failed.stdout, failed.stderr)
	}
	if got := snapshotTestTree(t, tempRoot); !reflect.DeepEqual(got, beforeTemp) {
		t.Fatalf("capture failure leaked temporary workspace: before=%v after=%v", beforeTemp, got)
	}
	if got := snapshotTestTree(t, filepath.Join(project, ".mulgae")); !reflect.DeepEqual(got, beforeMulgae) {
		t.Fatalf("capture failure mutated .mulgae: before=%v after=%v", beforeMulgae, got)
	}
	assertProviderLogsUnchanged("capture-failure")
	runTestCommand(t, project, "git", "reset")
	mustWriteTestFile(t, filepath.Join(project, "screenshots", "staged.png"), pngBytes)
	noChange := runMulgaeBinaryWithEnv(t, binary, project, environment, "review", "--stage", "--roles", "security", "--preflight", "--output", "json")
	if noChange.exitCode != 0 {
		t.Fatalf("no-change preflight = exit %d stdout=%q stderr=%q", noChange.exitCode, noChange.stdout, noChange.stderr)
	}
	noChangeResult := decode(noChange.stdout)
	if noChangeResult.Status != "no_change" || len(noChangeResult.Transmissions) != 0 || noChangeResult.Budget.TotalInvocations != 0 || len(noChangeResult.Budget.Lanes) != 0 {
		t.Fatalf("no-change projection = %#v", noChangeResult)
	}
	if got := snapshotTestTree(t, tempRoot); !reflect.DeepEqual(got, beforeTemp) {
		t.Fatalf("no-change preflight leaked temporary workspace: before=%v after=%v", beforeTemp, got)
	}
	if got := snapshotTestTree(t, filepath.Join(project, ".mulgae")); !reflect.DeepEqual(got, beforeMulgae) {
		t.Fatalf("no-change preflight mutated .mulgae: before=%v after=%v", beforeMulgae, got)
	}
	assertProviderLogsUnchanged("no-change")
}

func snapshotTestTree(t *testing.T, root string) []string {
	t.Helper()
	var paths []string
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == root {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		paths = append(paths, filepath.ToSlash(relative))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return paths
}

func environmentValue(t *testing.T, environment []string, name string) string {
	t.Helper()
	prefix := name + "="
	for _, value := range environment {
		if strings.HasPrefix(value, prefix) {
			return strings.TrimPrefix(value, prefix)
		}
	}
	t.Fatalf("environment omits %s", name)
	return ""
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
		arguments = append(arguments, "--agy-executable", agy)
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

type commandRoleReportURI struct {
	Role string `json:"role"`
	URI  string `json:"uri"`
}

type commandEnvelope struct {
	Command string `json:"command"`
	Exit    struct {
		Code int    `json:"code"`
		Kind string `json:"kind"`
	} `json:"exit"`
	Result struct {
		Kind              string                 `json:"kind"`
		SessionID         *string                `json:"session_id"`
		RunID             *string                `json:"run_id"`
		RunManifestURI    *string                `json:"run_manifest_uri"`
		ReviewArtifactURI *string                `json:"review_artifact_uri"`
		PromptManifestURI *string                `json:"prompt_manifest_uri"`
		RoleReportURIs    []commandRoleReportURI `json:"role_report_uris"`
	} `json:"result"`
	Reasons []struct {
		Category    string  `json:"category"`
		Code        string  `json:"code"`
		Message     string  `json:"message"`
		Retryable   bool    `json:"retryable"`
		ArtifactURI *string `json:"artifact_uri"`
	} `json:"reasons"`
}

func assertCommandRoleReportInventory(t *testing.T, project string, envelope commandEnvelope) {
	t.Helper()
	if envelope.Result.SessionID == nil || envelope.Result.RunID == nil || envelope.Result.RunManifestURI == nil || envelope.Result.ReviewArtifactURI == nil {
		t.Fatalf("command envelope lacks committed identity for role-report checks: %#v", envelope.Result)
	}
	manifestBytes, err := os.ReadFile(filepath.Join(project, *envelope.Result.RunManifestURI))
	if err != nil {
		t.Fatal(err)
	}
	reviewBytes, err := os.ReadFile(filepath.Join(project, *envelope.Result.ReviewArtifactURI))
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		RoleReports []struct {
			Role             string `json:"role"`
			Path             string `json:"path"`
			SHA256           string `json:"sha256"`
			ByteLength       int    `json:"byte_length"`
			ProviderInstance string `json:"provider_instance"`
			AttemptID        string `json:"attempt_id"`
			ContentType      string `json:"content_type"`
		} `json:"role_reports"`
	}
	var review struct {
		RoleOutcomes []struct {
			Role             string  `json:"role"`
			Outcome          string  `json:"outcome"`
			AttemptID        *string `json:"attempt_id"`
			ProviderInstance *string `json:"provider_instance"`
		} `json:"role_outcomes"`
	}
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatalf("decode manifest for role reports: %v", err)
	}
	if err := json.Unmarshal(reviewBytes, &review); err != nil {
		t.Fatalf("decode review for role reports: %v", err)
	}
	expectedRoles := make([]string, 0, len(review.RoleOutcomes))
	outcomesByRole := make(map[string]struct {
		AttemptID        *string
		ProviderInstance *string
	}, len(review.RoleOutcomes))
	for _, outcome := range review.RoleOutcomes {
		outcomesByRole[outcome.Role] = struct {
			AttemptID        *string
			ProviderInstance *string
		}{AttemptID: outcome.AttemptID, ProviderInstance: outcome.ProviderInstance}
		if outcome.Outcome == "completed" || outcome.Outcome == "degraded" {
			expectedRoles = append(expectedRoles, outcome.Role)
		}
	}
	if len(manifest.RoleReports) != len(expectedRoles) || len(envelope.Result.RoleReportURIs) != len(expectedRoles) {
		t.Fatalf("role report cardinality mismatch: outcomes=%v manifest=%d uris=%d", expectedRoles, len(manifest.RoleReports), len(envelope.Result.RoleReportURIs))
	}
	prefix := ".mulgae/" + *envelope.Result.SessionID + "/" + *envelope.Result.RunID + "/role-reports/"
	for index, role := range expectedRoles {
		report := manifest.RoleReports[index]
		uri := envelope.Result.RoleReportURIs[index]
		outcome := outcomesByRole[role]
		if report.Role != role || uri.Role != role || report.Path != "role-reports/"+role+".md" ||
			report.ContentType != "text/markdown" || report.ByteLength <= 0 ||
			outcome.AttemptID == nil || outcome.ProviderInstance == nil ||
			report.AttemptID != *outcome.AttemptID || report.ProviderInstance != *outcome.ProviderInstance ||
			uri.URI != prefix+role+".md" {
			t.Fatalf("role report identity mismatch at %d: role=%q report=%#v uri=%#v outcome=%#v", index, role, report, uri, outcome)
		}
		content, err := os.ReadFile(filepath.Join(project, uri.URI))
		if err != nil {
			t.Fatalf("read role report %q: %v", uri.URI, err)
		}
		if len(content) != report.ByteLength {
			t.Fatalf("role report %q byte length = %d, want %d", role, len(content), report.ByteLength)
		}
		sum := sha256.Sum256(content)
		digest := "sha256:" + hex.EncodeToString(sum[:])
		if digest != report.SHA256 {
			t.Fatalf("role report %q digest = %q, want %q", role, digest, report.SHA256)
		}
	}
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
	Fixture       string   `json:"fixture,omitempty"`
	PNG           string   `json:"png_sha256,omitempty"`
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
		root := regexp.MustCompile("(?:root must be |root=)([0-9a-f]{64})").FindStringSubmatch(string(roadmap))
		role := regexp.MustCompile("(?:role must be |role=)([a-z]+)").FindStringSubmatch(string(roadmap))
		link, err := os.ReadFile("docs/linked.md")
		if err != nil || len(root) != 2 || len(role) != 2 {
			panic("native qualification reference did not resolve")
		}
		content = fmt.Sprintf("{\"root\":%q,\"link\":%q,\"role\":%q}", root[1], strings.TrimSpace(string(link)), role[1])
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
	mode := ""
	disallowed := ""
	for index := range argv {
		switch argv[index] {
		case "--prompt":
			if index+1 < len(argv) {
				prompt = argv[index+1]
			}
		case "--mode":
			if index+1 < len(argv) {
				mode = argv[index+1]
			}
		case "--disallowed-tools":
			if index+1 < len(argv) {
				disallowed = argv[index+1]
			}
		}
	}
	if prompt == "" || mode != "plan" || disallowed == "" {
		panic("non-canonical ZCode invocation")
	}
	capability := strings.Contains(prompt, "Prove readiness by binding the immutable fixture values below.")
	if capability {
		if disallowed != "*" {
			panic("non-canonical ZCode capability invocation")
		}
	} else if !strings.Contains(disallowed, "Bash") || !strings.Contains(disallowed, "Write") {
		panic("non-canonical ZCode review invocation")
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
	if strings.Contains(prompt, "Prove readiness by binding the immutable fixture values below.") ||
		strings.Contains(prompt, "The object must contain exactly root, link, and role string fields.") {
		root := regexp.MustCompile("(?:root must be |root=)([0-9a-f]{64})").FindStringSubmatch(prompt)
		link := regexp.MustCompile("(?:link must be |link=)([^\\s;]+)").FindStringSubmatch(prompt)
		role := regexp.MustCompile("(?:role must be |role=)([a-z]+)").FindStringSubmatch(prompt)
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
	"crypto/sha256"
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
	Fixture string ` + "`json:\"fixture,omitempty\"`" + `
	PNG string ` + "`json:\"png_sha256,omitempty\"`" + `
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
	printTimeout := ""
	switch {
	case len(argv) == 12 && argv[0] == "--new-project" && argv[1] == "--sandbox" &&
		argv[2] == "--add-dir" && argv[3] == cwd && argv[4] == "--mode" && argv[5] == "plan" &&
		argv[6] == "--effort" && argv[7] == "low" && argv[8] == "--print-timeout" &&
		argv[10] == "--print":
		printTimeout = argv[9]
		observation.Snapshot, observation.Prompt = argv[3], argv[11]
	case len(argv) == 13 && argv[0] == "--new-project" && argv[1] == "--sandbox" &&
		argv[2] == "--dangerously-skip-permissions" && argv[3] == "--add-dir" && argv[4] == cwd &&
		argv[5] == "--mode" && argv[6] == "plan" && argv[7] == "--effort" && argv[8] == "low" &&
		argv[9] == "--print-timeout" && argv[11] == "--print":
		printTimeout = argv[10]
		observation.Snapshot, observation.Prompt = argv[4], argv[12]
	default:
		panic("non-canonical AGY invocation")
	}
	// Qualification probes stay inside the bounded 30s probe deadline; reviews
	// keep the full configured runtime deadline.
	if observation.Prompt == "@roadmap.md" {
		if printTimeout != "25s" {
			panic("non-canonical AGY qualification print timeout")
		}
	} else if printTimeout != "14m55s" {
		panic("non-canonical AGY review print timeout")
	}
	if observation.Prompt != "@roadmap.md" {
		fixture, fixtureErr := os.ReadFile("security-fixtures.txt")
		png, pngErr := os.ReadFile("screenshots/staged.png")
		if fixtureErr == nil && pngErr == nil {
			observation.Fixture = string(fixture)
			digest := sha256.Sum256(png)
			observation.PNG = fmt.Sprintf("sha256:%x", digest[:])
		} else if fixtureErr != nil && !os.IsNotExist(fixtureErr) || pngErr != nil && !os.IsNotExist(pngErr) {
			panic("partial review inspection fixture")
		}
	}
	write(observation)
	if observation.Prompt == "@roadmap.md" {
		roadmap, err := os.ReadFile("roadmap.md")
		if err != nil {
			panic(err)
		}
		link, err := os.ReadFile("docs/linked.md")
		root := regexp.MustCompile("(?:root must be |root=)([0-9a-f]{64})").FindStringSubmatch(string(roadmap))
		role := regexp.MustCompile("(?:role must be |role=)([a-z]+)").FindStringSubmatch(string(roadmap))
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
