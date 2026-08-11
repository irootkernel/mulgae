//go:build darwin && arm64

package composition

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime/debug"
	"slices"
	"syscall"
	"testing"
	"time"

	adapterconfig "github.com/irootkernel/mulgae/internal/adapters/config"
	"github.com/irootkernel/mulgae/internal/adapters/gittarget"
	"github.com/irootkernel/mulgae/internal/adapters/providercli"
	appconfig "github.com/irootkernel/mulgae/internal/app/config"
	"github.com/irootkernel/mulgae/internal/app/reviewrun"
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

// TestConfiguredQualificationRolesFollowTheProviderMatrix proves qualification
// probes only the roles a family actually owns. Each role takes the first
// configured family from its own preference order, so the families partition the
// roles rather than overlapping on a primary/fallback pair.
func TestConfiguredQualificationRolesFollowTheProviderMatrix(t *testing.T) {
	config, err := adapterconfig.CanonicalRolesConfig(testRoleDefaults(), []string{"kimi", "zcode", "agy"})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		family reviewrun.Family
		roles  []domain.Role
		base   domain.Role
	}{
		{reviewrun.FamilyKimi, []domain.Role{domain.RoleLogic}, domain.RoleLogic},
		{reviewrun.FamilyZCode, []domain.Role{domain.RoleSecurity, domain.RoleMaintainability, domain.RoleProduct, domain.RoleTesting}, domain.RoleSecurity},
		{reviewrun.FamilyAGY, []domain.Role{domain.RoleDocumentation}, domain.RoleDocumentation},
	}
	for _, test := range tests {
		roles, base := configuredQualificationRoles(config, domain.CoreRoleOrder(), test.family)
		if !slices.Equal(roles, test.roles) || base != test.base {
			t.Fatalf("%s qualification roles/base = %v/%s, want %v/%s", test.family, roles, base, test.roles, test.base)
		}
	}
}

func TestProductionRunPolicyPropagatesConfiguredProviderTimeouts(t *testing.T) {
	roles, err := adapterconfig.CanonicalRolesConfig(testRoleDefaults(), []string{"zcode", "agy"})
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
			MaxActiveLanes: 3, PrimaryRepairAttempts: 1, RoleMaxInvocations: 2, RunMaxInvocations: 14, RunTotalOutputCap: "64MiB",
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
func canonicalTestTempDir(t *testing.T) string {
	t.Helper()
	path, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Clean(path)
}
