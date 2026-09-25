package init

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	adapterconfig "github.com/irootkernel/mulgae/internal/adapters/config"
	"github.com/irootkernel/mulgae/internal/adapters/filesystem"
	appconfig "github.com/irootkernel/mulgae/internal/app/config"
	"github.com/irootkernel/mulgae/internal/app/reviewrun"
	"github.com/irootkernel/mulgae/internal/builtin"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

type testClock struct{}

func (testClock) Now() time.Time { return time.Date(2026, 7, 20, 0, 0, 0, 0, time.UTC) }

type testResultPrevalidator struct{ err error }

func (validator testResultPrevalidator) PrevalidateInitOutcome(_ context.Context, outcome PrevalidatedOutcome) error {
	if validator.err != nil {
		return validator.err
	}
	return outcome.Result.Validate()
}

type testInspector struct{ absent bool }

type kimiHomeInspector struct {
	testInspector
	home string
}

func (inspector kimiHomeInspector) KimiCodeHome() (string, error) { return inspector.home, nil }

func (testInspector) ObservePlatform(context.Context) (ports.PlatformObservation, error) {
	return ports.NewPlatformObservation("darwin", "arm64")
}
func (inspector testInspector) ObserveExecutable(_ context.Context, name string) (ports.ExecutableObservation, error) {
	if inspector.absent || name == "kimi" || name == "node" || name == "grok" || !filepath.IsAbs(name) {
		return ports.NewExecutableObservation(name, false, "", "", "")
	}
	return ports.NewExecutableObservation(name, true, name, "", "")
}
func (inspector testInspector) ObserveExecutableIdentity(ctx context.Context, name string) (ports.ExecutableObservation, error) {
	return inspector.ObserveExecutable(ctx, name)
}
func (inspector testInspector) ObserveReadableFileIdentity(_ context.Context, name string) (ports.FileIdentityObservation, error) {
	if inspector.absent || !filepath.IsAbs(name) {
		return ports.NewFileIdentityObservation(name, false, "", "")
	}
	return ports.NewFileIdentityObservation(name, true, name, "")
}
func (inspector testInspector) ObserveApplicationMetadata(_ context.Context, name string) (ports.ApplicationMetadataObservation, error) {
	if inspector.absent || !filepath.IsAbs(name) {
		return ports.ApplicationMetadataObservation{}, ports.NewIdentityObservationError(ports.IdentityObservationUnavailable, "application metadata unavailable")
	}
	return ports.NewApplicationMetadataObservation(name, "sha256:"+strings.Repeat("b", 64), "3.12.3")
}

func (testInspector) ObserveNativeHomeIdentity(context.Context, string) (ports.NativeHomeLaunchAuthority, error) {
	return ports.NativeHomeLaunchAuthority{}, nil
}
func (testInspector) ObservePermission(context.Context, ports.AnchoredRoot, ports.SafeRelativePath) (ports.PermissionObservation, error) {
	return ports.PermissionObservation{}, errors.New("unused")
}

type scopedDiscoveryInspector struct {
	calls                   []string
	readableCalls           []string
	legacyCalls             []string
	observations            map[string]ports.ExecutableObservation
	fileObservations        map[string]ports.FileIdentityObservation
	applicationObservations map[string]ports.ApplicationMetadataObservation
	errors                  map[string]error
	kimiHomeErr             error
}

func (inspector *scopedDiscoveryInspector) ObservePlatform(context.Context) (ports.PlatformObservation, error) {
	return ports.NewPlatformObservation("darwin", "arm64")
}
func (inspector *scopedDiscoveryInspector) ObserveExecutable(_ context.Context, name string) (ports.ExecutableObservation, error) {
	inspector.legacyCalls = append(inspector.legacyCalls, name)
	return ports.ExecutableObservation{}, errors.New("legacy executable observation must not run")
}
func (inspector *scopedDiscoveryInspector) ObserveExecutableIdentity(_ context.Context, name string) (ports.ExecutableObservation, error) {
	inspector.calls = append(inspector.calls, name)
	if err := inspector.errors[name]; err != nil {
		return ports.ExecutableObservation{}, err
	}
	if observation, ok := inspector.observations[name]; ok {
		return observation, nil
	}
	return ports.NewExecutableObservation(name, false, "", "", "")
}
func (inspector *scopedDiscoveryInspector) ObserveReadableFileIdentity(_ context.Context, name string) (ports.FileIdentityObservation, error) {
	inspector.readableCalls = append(inspector.readableCalls, name)
	if err := inspector.errors[name]; err != nil {
		return ports.FileIdentityObservation{}, err
	}
	if observation, ok := inspector.fileObservations[name]; ok {
		return observation, nil
	}
	return ports.NewFileIdentityObservation(name, false, "", "")
}
func (inspector *scopedDiscoveryInspector) ObserveApplicationMetadata(_ context.Context, name string) (ports.ApplicationMetadataObservation, error) {
	if err := inspector.errors[name]; err != nil {
		return ports.ApplicationMetadataObservation{}, err
	}
	if observation, ok := inspector.applicationObservations[name]; ok {
		return observation, nil
	}
	return ports.NewApplicationMetadataObservation(name, "sha256:"+strings.Repeat("b", 64), "3.12.3")
}

func (*scopedDiscoveryInspector) ObserveNativeHomeIdentity(context.Context, string) (ports.NativeHomeLaunchAuthority, error) {
	return ports.NativeHomeLaunchAuthority{}, nil
}
func (inspector *scopedDiscoveryInspector) KimiCodeHome() (string, error) {
	return "", inspector.kimiHomeErr
}
func (*scopedDiscoveryInspector) ObservePermission(context.Context, ports.AnchoredRoot, ports.SafeRelativePath) (ports.PermissionObservation, error) {
	return ports.PermissionObservation{}, errors.New("unused")
}

func availableDiscoveryObservation(t *testing.T, name, resolved string) ports.ExecutableObservation {
	t.Helper()
	observation, err := ports.NewExecutableObservation(name, true, resolved, "", "")
	if err != nil {
		t.Fatal(err)
	}
	return observation
}

func availableFileObservation(t *testing.T, name, resolved string) ports.FileIdentityObservation {
	t.Helper()
	observation, err := ports.NewFileIdentityObservation(name, true, resolved, "")
	if err != nil {
		t.Fatal(err)
	}
	return observation
}

type testAttestor struct{}

func (testAttestor) Attest(_ context.Context, request ports.ConfigLocalityRequest) (ports.ConfigLocalityContext, error) {
	device, inode, uid, mode := request.Config().RootIdentity()
	return ports.NewConfigLocalityContext("repo", device, inode, uid, mode, "head", "tree", "sha256:index", 0, false, []string{"head"}, request.Config(), ports.ParsedTargetProof{SHA256: "sha256:target", PrivatePathFree: true})
}

type scriptedAttestor struct {
	attestCalls      int
	revalidateCalls  int
	failAttestAt     int
	failRevalidateAt int
}

type finalConfigMutatingAttestor struct {
	path    string
	mutated bool
}

func (attestor *finalConfigMutatingAttestor) Attest(ctx context.Context, request ports.ConfigLocalityRequest) (ports.ConfigLocalityContext, error) {
	return (testAttestor{}).Attest(ctx, request)
}
func (attestor *finalConfigMutatingAttestor) Revalidate(ctx context.Context, request ports.ConfigLocalityRequest, expected ports.ConfigLocalityContext) error {
	if err := (testAttestor{}).Revalidate(ctx, request, expected); err != nil {
		return err
	}
	if request.Config().Present() && !attestor.mutated {
		attestor.mutated = true
		return os.WriteFile(attestor.path, []byte("version: 3\n"), 0o600)
	}
	return nil
}

func (attestor *scriptedAttestor) Attest(ctx context.Context, request ports.ConfigLocalityRequest) (ports.ConfigLocalityContext, error) {
	attestor.attestCalls++
	if attestor.attestCalls == attestor.failAttestAt {
		return ports.ConfigLocalityContext{}, errors.New("injected attest failure")
	}
	return (testAttestor{}).Attest(ctx, request)
}
func (attestor *scriptedAttestor) Revalidate(ctx context.Context, request ports.ConfigLocalityRequest, expected ports.ConfigLocalityContext) error {
	attestor.revalidateCalls++
	if attestor.revalidateCalls == attestor.failRevalidateAt {
		return errors.New("injected revalidation failure")
	}
	return (testAttestor{}).Revalidate(ctx, request, expected)
}
func (attestor testAttestor) Revalidate(ctx context.Context, request ports.ConfigLocalityRequest, expected ports.ConfigLocalityContext) error {
	actual, err := attestor.Attest(ctx, request)
	if err != nil {
		return err
	}
	if !actual.Equal(expected) {
		return errors.New("drift")
	}
	return nil
}

type testInstaller struct {
	rootError         bool
	existing          bool
	installError      error
	localInstallError error
	prepareCalls      int
	installCalls      int
}

type afterInstallTestInstaller struct {
	delegate *testInstaller
	after    func(ports.AnchoredRoot, []byte) error
}

type afterPrepareTestInstaller struct {
	delegate *testInstaller
	after    func(ports.AnchoredRoot) error
}

func (installer *afterPrepareTestInstaller) PrepareConfigDirectory(ctx context.Context, root ports.AnchoredRoot) (ports.ConfigDirectoryReceipt, error) {
	receipt, err := installer.delegate.PrepareConfigDirectory(ctx, root)
	if err == nil && installer.after != nil {
		err = installer.after(root)
	}
	return receipt, err
}
func (installer *afterPrepareTestInstaller) InstallConfig(ctx context.Context, root ports.AnchoredRoot, prepared ports.ConfigDirectoryReceipt, data []byte) (ports.ConfigInstallReceipt, error) {
	return installer.delegate.InstallConfig(ctx, root, prepared, data)
}
func (installer *afterPrepareTestInstaller) InstallConfigBundle(ctx context.Context, root ports.AnchoredRoot, prepared ports.ConfigDirectoryReceipt, project, local []byte) (ports.ConfigInstallReceipt, error) {
	return installer.delegate.InstallConfigBundle(ctx, root, prepared, project, local)
}
func (installer *afterPrepareTestInstaller) InstallLocalConfig(ctx context.Context, root ports.AnchoredRoot, prepared ports.ConfigDirectoryReceipt, data []byte) (ports.ConfigInstallReceipt, error) {
	return installer.delegate.InstallLocalConfig(ctx, root, prepared, data)
}
func (installer *afterPrepareTestInstaller) RefreshLocalConfig(ctx context.Context, root ports.AnchoredRoot, prepared ports.ConfigDirectoryReceipt, data []byte) (ports.ConfigInstallReceipt, error) {
	return installer.delegate.RefreshLocalConfig(ctx, root, prepared, data)
}

func (installer *afterInstallTestInstaller) PrepareConfigDirectory(ctx context.Context, root ports.AnchoredRoot) (ports.ConfigDirectoryReceipt, error) {
	return installer.delegate.PrepareConfigDirectory(ctx, root)
}
func (installer *afterInstallTestInstaller) InstallConfig(ctx context.Context, root ports.AnchoredRoot, prepared ports.ConfigDirectoryReceipt, data []byte) (ports.ConfigInstallReceipt, error) {
	receipt, err := installer.delegate.InstallConfig(ctx, root, prepared, data)
	if err == nil && installer.after != nil {
		err = installer.after(root, data)
	}
	return receipt, err
}
func (installer *afterInstallTestInstaller) InstallConfigBundle(ctx context.Context, root ports.AnchoredRoot, prepared ports.ConfigDirectoryReceipt, project, local []byte) (ports.ConfigInstallReceipt, error) {
	receipt, err := installer.delegate.InstallConfigBundle(ctx, root, prepared, project, local)
	if err == nil && installer.after != nil {
		err = installer.after(root, local)
	}
	return receipt, err
}
func (installer *afterInstallTestInstaller) InstallLocalConfig(ctx context.Context, root ports.AnchoredRoot, prepared ports.ConfigDirectoryReceipt, data []byte) (ports.ConfigInstallReceipt, error) {
	receipt, err := installer.delegate.InstallLocalConfig(ctx, root, prepared, data)
	if err == nil && installer.after != nil {
		err = installer.after(root, data)
	}
	return receipt, err
}
func (installer *afterInstallTestInstaller) RefreshLocalConfig(ctx context.Context, root ports.AnchoredRoot, prepared ports.ConfigDirectoryReceipt, data []byte) (ports.ConfigInstallReceipt, error) {
	return installer.delegate.RefreshLocalConfig(ctx, root, prepared, data)
}

func (installer *testInstaller) PrepareConfigDirectory(_ context.Context, root ports.AnchoredRoot) (ports.ConfigDirectoryReceipt, error) {
	installer.prepareCalls++
	created := !installer.existing
	if created {
		if err := os.Mkdir(filepath.Join(root.String(), ".mulgae"), 0o700); err != nil {
			return ports.ConfigDirectoryReceipt{}, err
		}
	}
	source, err := adapterconfig.NewLocalConfigSource(root, true)
	if err != nil {
		return ports.ConfigDirectoryReceipt{}, err
	}
	identity, err := source.Observation().DirectoryIdentity()
	if err != nil {
		return ports.ConfigDirectoryReceipt{}, err
	}
	receipt, err := ports.NewVerifiedConfigDirectoryReceipt(created, identity)
	if err != nil {
		return ports.ConfigDirectoryReceipt{}, err
	}
	if installer.rootError {
		return receipt, ports.NewConfigInstallError(ports.ConfigInstallStageRootSync, ports.ConfigDestinationAbsent, errors.New("sync"))
	}
	return receipt, nil
}
func (installer *testInstaller) InstallConfig(_ context.Context, root ports.AnchoredRoot, prepared ports.ConfigDirectoryReceipt, data []byte) (ports.ConfigInstallReceipt, error) {
	installer.installCalls++
	expected, ok := prepared.Identity()
	if !ok {
		return ports.ConfigInstallReceipt{}, errors.New("missing prepared identity")
	}
	source, err := adapterconfig.NewLocalConfigSource(root, true)
	if err != nil {
		return ports.ConfigInstallReceipt{}, err
	}
	actual, err := source.Observation().DirectoryIdentity()
	if err != nil || !actual.Equal(expected) {
		return ports.ConfigInstallReceipt{}, errors.New("prepared identity changed")
	}
	if installer.installError != nil {
		return ports.ConfigInstallReceipt{}, installer.installError
	}
	path := filepath.Join(root.String(), ".mulgae", "config.yaml")
	if _, err := os.Lstat(path); err == nil {
		return ports.ConfigInstallReceipt{}, ports.NewConfigInstallError(ports.ConfigInstallStageCollision, ports.ConfigDestinationPresent, os.ErrExist)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return ports.ConfigInstallReceipt{}, err
	}
	installed, err := adapterconfig.NewLocalConfigSource(root, false)
	if err != nil {
		return ports.ConfigInstallReceipt{}, err
	}
	configIdentity, err := installed.Observation().InstalledConfigIdentity()
	if err != nil {
		return ports.ConfigInstallReceipt{}, err
	}
	return ports.NewVerifiedConfigInstallReceipt(expected, configIdentity)
}

func (installer *testInstaller) InstallConfigBundle(ctx context.Context, root ports.AnchoredRoot, prepared ports.ConfigDirectoryReceipt, project, local []byte) (ports.ConfigInstallReceipt, error) {
	if installer.installError != nil {
		return ports.ConfigInstallReceipt{}, installer.installError
	}
	if err := os.WriteFile(filepath.Join(root.String(), ".mulgae", "config.yaml"), project, 0o600); err != nil {
		return ports.ConfigInstallReceipt{}, err
	}
	directory, ok := prepared.Identity()
	if !ok {
		return ports.ConfigInstallReceipt{}, errors.New("missing prepared identity")
	}
	_, _, uid, _ := directory.PrivateDirectory()
	sum := sha256.Sum256(project)
	projectIdentity, err := ports.NewConfigFileIdentity(1, 1, uid, 0o600, 1, int64(len(project)), fmt.Sprintf("sha256:%x", sum))
	if err != nil {
		return ports.ConfigInstallReceipt{}, err
	}
	projectReceipt, err := ports.NewVerifiedConfigInstallReceipt(directory, projectIdentity)
	if err != nil {
		return ports.ConfigInstallReceipt{}, err
	}
	localReceipt, err := installer.InstallLocalConfig(ctx, root, prepared, local)
	if err == nil || localReceipt.Installed() {
		return localReceipt, err
	}
	return projectReceipt, ports.NewConfigInstallError(ports.ConfigInstallStageBundlePartial, ports.ConfigDestinationPresent, err)
}

func (installer *testInstaller) InstallLocalConfig(_ context.Context, root ports.AnchoredRoot, prepared ports.ConfigDirectoryReceipt, data []byte) (ports.ConfigInstallReceipt, error) {
	installer.installCalls++
	if installer.localInstallError != nil {
		return ports.ConfigInstallReceipt{}, installer.localInstallError
	}
	if installer.installError != nil {
		return ports.ConfigInstallReceipt{}, installer.installError
	}
	path := filepath.Join(root.String(), ".mulgae", "local.yaml")
	if _, err := os.Lstat(path); err == nil {
		return ports.ConfigInstallReceipt{}, ports.NewConfigInstallError(ports.ConfigInstallStageCollision, ports.ConfigDestinationPresent, os.ErrExist)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return ports.ConfigInstallReceipt{}, err
	}
	installed, err := adapterconfig.NewLocalConfigSource(root, false)
	if err != nil {
		return ports.ConfigInstallReceipt{}, err
	}
	identity, err := installed.Observation().InstalledConfigIdentity()
	if err != nil {
		return ports.ConfigInstallReceipt{}, err
	}
	expected, _ := prepared.Identity()
	return ports.NewVerifiedConfigInstallReceipt(expected, identity)
}

func (installer *testInstaller) RefreshLocalConfig(ctx context.Context, root ports.AnchoredRoot, prepared ports.ConfigDirectoryReceipt, data []byte) (ports.ConfigInstallReceipt, error) {
	if err := os.Remove(filepath.Join(root.String(), ".mulgae", "local.yaml")); err != nil {
		return ports.ConfigInstallReceipt{}, err
	}
	return installer.InstallLocalConfig(ctx, root, prepared, data)
}

func TestInitializeProjectReportsAndRecoversSharedOnlyPartialInstall(t *testing.T) {
	rootPath := t.TempDir()
	if err := os.Chmod(rootPath, 0o700); err != nil {
		t.Fatal(err)
	}
	root, err := ports.NewAnchoredRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	installer := &testInstaller{localInstallError: ports.NewConfigInstallError(ports.ConfigInstallStagePreinstall, ports.ConfigDestinationAbsent, errors.New("injected local write failure"))}
	service, err := NewService(installer, testInspector{}, testAttestor{}, testResultPrevalidator{}, testClock{}, adapterconfig.SourceFactory{}, adapterconfig.YAMLCodec{}, builtin.NewCatalog())
	if err != nil {
		t.Fatal(err)
	}
	result, initErr := service.InitializeProject(context.Background(), grokInitRequest(root))
	var failure *Failure
	if initErr == nil || !errors.As(initErr, &failure) || failure.Code() != "init_local_write_failed" || failure.Class() != domain.FailureArtifact || !failure.Retryable() {
		t.Fatalf("failure = %#v, %v", failure, initErr)
	}
	if result.WriteState != "project_committed_local_missing" || result.DestinationState != ports.ConfigDestinationPresent || result.Committed {
		t.Fatalf("partial result = %#v", result)
	}
	if _, err := os.Stat(filepath.Join(rootPath, ".mulgae", "config.yaml")); err != nil {
		t.Fatalf("shared project policy missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(rootPath, ".mulgae", "local.yaml")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("local config exists after partial install: %v", err)
	}

	installer.localInstallError = nil
	installer.existing = true
	recovered, recoverErr := service.InitializeProject(context.Background(), grokInitRequest(root))
	if recoverErr != nil || !recovered.Committed || recovered.WriteState != "committed" {
		t.Fatalf("shared-only recovery = %#v, %v", recovered, recoverErr)
	}
	if _, err := os.Stat(filepath.Join(rootPath, ".mulgae", "local.yaml")); err != nil {
		t.Fatalf("recovered local config missing: %v", err)
	}
}

func TestInitializeProjectPrevalidationFailureDoesNotMutateFilesystem(t *testing.T) {
	rootPath := t.TempDir()
	if err := os.Chmod(rootPath, 0o700); err != nil {
		t.Fatal(err)
	}
	root, err := ports.NewAnchoredRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	installer := &testInstaller{}
	service, err := NewService(installer, testInspector{}, testAttestor{}, testResultPrevalidator{err: errors.New("schema rejected result")}, testClock{}, adapterconfig.SourceFactory{}, adapterconfig.YAMLCodec{}, builtin.NewCatalog())
	if err != nil {
		t.Fatal(err)
	}
	result, initErr := service.InitializeProject(context.Background(), InitializeProjectRequest{
		ProjectRoot: root,
		ProjectName: "project",
		NativeHome:  "/Users/test",
		Selection:   Selection{Mode: SelectionSelected, ProviderIDs: []string{"grok"}},
		Overrides:   Overrides{GrokExecutable: "/bin/grok"},
	})
	if initErr == nil {
		t.Fatal("prevalidation failure was accepted")
	}
	var failure *Failure
	if !errors.As(initErr, &failure) || failure.Code() != "init_result_prevalidation_failed" {
		t.Fatalf("error = %v", initErr)
	}
	if result.WriteState != "not_attempted" || result.DestinationState != ports.ConfigDestinationNotObserved {
		t.Fatalf("result = %#v", result)
	}
	if installer.prepareCalls != 0 || installer.installCalls != 0 {
		t.Fatalf("installer calls = prepare %d install %d", installer.prepareCalls, installer.installCalls)
	}
	if _, err := os.Lstat(filepath.Join(rootPath, ".mulgae")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("prevalidation mutated .mulgae: %v", err)
	}
}

func TestInitializeProjectSupportsAllSevenSelectedSubsets(t *testing.T) {
	appBundle := filepath.Join(t.TempDir(), "ZCode.app")
	for mask := 1; mask < 8; mask++ {
		rootPath := t.TempDir()
		_ = os.Chmod(rootPath, 0o700)
		root, _ := ports.NewAnchoredRoot(rootPath)
		ids := []string{}
		overrides := Overrides{}
		if mask&1 != 0 {
			ids = append(ids, "zcode")
			overrides.ZCodeAppBundle = appBundle
		}
		if mask&2 != 0 {
			ids = append(ids, "grok")
			overrides.GrokExecutable = "/bin/grok"
		}
		if mask&4 != 0 {
			ids = append(ids, "codex")
			overrides.CodexExecutable = "/bin/codex"
		}
		service, err := NewService(&testInstaller{}, testInspector{}, testAttestor{}, testResultPrevalidator{}, testClock{}, adapterconfig.SourceFactory{}, adapterconfig.YAMLCodec{}, builtin.NewCatalog())
		if err != nil {
			t.Fatal(err)
		}
		result, err := service.InitializeProject(context.Background(), InitializeProjectRequest{ProjectRoot: root, ProjectName: "project", NativeHome: "/Users/test", Selection: Selection{Mode: SelectionSelected, ProviderIDs: ids}, Overrides: overrides})
		if err != nil {
			t.Fatalf("mask %d: %v", mask, err)
		}
		if !result.Committed || result.WriteState != "committed" || !reflect.DeepEqual(result.ConfiguredProviderIDs, ids) {
			t.Fatalf("mask %d result=%#v", mask, result)
		}
		decoded, err := readInstalledConfig(rootPath)
		if err != nil || decoded.Version != adapterconfig.ConfigVersion {
			t.Fatalf("mask %d decode config: version=%d err=%v", mask, decoded.Version, err)
		}
		wantRoles, _ := adapterconfig.CanonicalRolesConfigForSelection(testRoleDefaults(), ids, []string{"logic"})
		if !reflect.DeepEqual(decoded.Roles, wantRoles) {
			t.Fatalf("mask %d roles=%#v, want %#v", mask, decoded.Roles, wantRoles)
		}
		for _, family := range ids {
			var timeout string
			switch family {
			case "zcode":
				timeout = decoded.Providers.ZCode.Timeout
			case "grok":
				timeout = decoded.Providers.Grok.Timeout
			case "codex":
				timeout = decoded.Providers.Codex.Timeout
			}
			if timeout != "60m" {
				t.Fatalf("mask %d %s timeout=%q", mask, family, timeout)
			}
		}
		if decoded.Providers.Grok != nil && (decoded.Providers.Grok.Model != defaultGrokModel || decoded.Providers.Grok.ReasoningEffort != defaultGrokReasoningEffort) {
			t.Fatalf("mask %d Grok defaults=%#v", mask, decoded.Providers.Grok)
		}
	}
}

func TestInitializeProjectDefaultsNewGrokPolicyIndependently(t *testing.T) {
	tests := []struct {
		name         string
		overrides    Overrides
		wantModel    string
		wantEffort   string
		modelSource  string
		effortSource string
	}{
		{name: "both defaults", overrides: Overrides{GrokExecutable: "/bin/grok"}, wantModel: defaultGrokModel, wantEffort: defaultGrokReasoningEffort, modelSource: "mulgae_default", effortSource: "mulgae_default"},
		{name: "model override", overrides: Overrides{GrokExecutable: "/bin/grok", GrokModel: "custom-model", GrokModelSet: true}, wantModel: "custom-model", wantEffort: defaultGrokReasoningEffort, modelSource: "override", effortSource: "mulgae_default"},
		{name: "effort override", overrides: Overrides{GrokExecutable: "/bin/grok", GrokReasoningEffort: "low", GrokReasoningEffortSet: true}, wantModel: defaultGrokModel, wantEffort: "low", modelSource: "mulgae_default", effortSource: "override"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rootPath := t.TempDir()
			_ = os.Chmod(rootPath, 0o700)
			root, _ := ports.NewAnchoredRoot(rootPath)
			service, err := NewService(&testInstaller{}, testInspector{}, testAttestor{}, testResultPrevalidator{}, testClock{}, adapterconfig.SourceFactory{}, adapterconfig.YAMLCodec{}, builtin.NewCatalog())
			if err != nil {
				t.Fatal(err)
			}
			result, err := service.InitializeProject(context.Background(), InitializeProjectRequest{
				ProjectRoot: root, ProjectName: "project", NativeHome: "/Users/test",
				Selection: Selection{Mode: SelectionSelected, ProviderIDs: []string{"grok"}}, Overrides: test.overrides,
			})
			if err != nil {
				t.Fatal(err)
			}
			config, err := readInstalledConfig(rootPath)
			if err != nil {
				t.Fatal(err)
			}
			if config.Providers.Grok.Model != test.wantModel || config.Providers.Grok.ReasoningEffort != test.wantEffort {
				t.Fatalf("Grok policy=%#v", config.Providers.Grok)
			}
			row := result.Discovery[1]
			if row.ModelSource != test.modelSource || row.ReasoningEffortSource != test.effortSource {
				t.Fatalf("Grok provenance=%#v", row)
			}
		})
	}
}

func TestInitializeProjectWritesSelectedProjectRolesAndScalesResourceDefaults(t *testing.T) {
	t.Parallel()
	selections := [][]string{
		{"logic"},
		{"logic", "security"},
		{"logic", "security", "documentation"},
		{"logic", "security", "maintainability", "product", "testing"},
	}
	for _, selected := range selections {
		selected := selected
		t.Run(strings.Join(selected, "-"), func(t *testing.T) {
			rootPath := t.TempDir()
			if err := os.Chmod(rootPath, 0o700); err != nil {
				t.Fatal(err)
			}
			root, err := ports.NewAnchoredRoot(rootPath)
			if err != nil {
				t.Fatal(err)
			}
			service, err := NewService(&testInstaller{}, testInspector{}, testAttestor{}, testResultPrevalidator{}, testClock{}, adapterconfig.SourceFactory{}, adapterconfig.YAMLCodec{}, builtin.NewCatalog())
			if err != nil {
				t.Fatal(err)
			}
			result, err := service.InitializeProject(context.Background(), InitializeProjectRequest{
				ProjectRoot: root, ProjectName: "project", NativeHome: "/Users/test", RoleIDs: selected,
				Selection: Selection{Mode: SelectionSelected, ProviderIDs: []string{"grok"}},
				Overrides: Overrides{GrokExecutable: "/bin/grok"},
			})
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(result.ConfiguredRoleIDs, selected) {
				t.Fatalf("configured roles = %v, want %v", result.ConfiguredRoleIDs, selected)
			}
			config, err := readInstalledConfig(rootPath)
			if err != nil {
				t.Fatal(err)
			}
			if config.Resources.MaxActiveLanes != len(selected) || config.Resources.RoleMaxInvocations != 2 || config.Resources.RunMaxInvocations != 2*len(selected) {
				t.Fatalf("resource defaults = %#v", config.Resources)
			}
			selectedSet := make(map[string]bool, len(selected))
			for _, role := range selected {
				selectedSet[role] = true
			}
			for index, role := range domain.CoreRoleOrder() {
				if got, want := config.Roles.Ordered()[index].Enabled, selectedSet[string(role)]; got != want {
					t.Errorf("role %s enabled = %t, want %t", role, got, want)
				}
			}
		})
	}
}

func TestCandidateUIConfigUsesArtistBriefDefaultAndExplicitPath(t *testing.T) {
	selectedRoles := []string{"logic", "security", "maintainability", "product", "documentation", "testing", "artist"}
	providers := candidates{zcode: &adapterconfig.ZCodeProviderConfig{AppBundle: reviewrun.ZCodeAppBundle}}
	defaults := testRoleDefaults()
	artistDefault, ok := defaults.Role(domain.RoleArtist)
	if !ok {
		t.Fatal("artist defaults are absent")
	}
	configured, err := candidateConfig(InitializeProjectRequest{ProjectName: "project", NativeHome: "/Users/test", ProjectKind: adapterconfig.ProjectKindUI, RoleIDs: selectedRoles}, defaults, providers)
	if err != nil {
		t.Fatalf("candidate config: %v", err)
	}
	if configured.Roles.Artist.Inputs == nil || configured.Roles.Artist.Inputs.TaskPath != artistDefault.ArtistTaskPath {
		t.Fatalf("default artist inputs = %#v, want task path %q", configured.Roles.Artist.Inputs, artistDefault.ArtistTaskPath)
	}
	if !reflect.DeepEqual(configured.Roles.Artist.Inputs.DesignSpecGlobs, artistDefault.ArtistDesignSpecGlobs) {
		t.Fatalf("default artist globs = %#v, want %#v", configured.Roles.Artist.Inputs.DesignSpecGlobs, artistDefault.ArtistDesignSpecGlobs)
	}
	explicit, err := candidateConfig(InitializeProjectRequest{ProjectName: "project", NativeHome: "/Users/test", ProjectKind: adapterconfig.ProjectKindUI, RoleIDs: selectedRoles, ArtistBriefPath: "docs/artist-brief.md"}, defaults, providers)
	if err != nil {
		t.Fatalf("candidate config with explicit brief: %v", err)
	}
	if explicit.Roles.Artist.Inputs == nil || explicit.Roles.Artist.Inputs.TaskPath != "docs/artist-brief.md" {
		t.Fatalf("explicit artist brief path = %#v", explicit.Roles.Artist.Inputs)
	}
}

func TestCandidateUIConfigDoesNotConfigureUnselectedArtist(t *testing.T) {
	providers := candidates{zcode: &adapterconfig.ZCodeProviderConfig{AppBundle: reviewrun.ZCodeAppBundle}}
	configured, err := candidateConfig(InitializeProjectRequest{
		ProjectName: "project", NativeHome: "/Users/test", ProjectKind: adapterconfig.ProjectKindUI,
		RoleIDs: []string{"logic"},
	}, testRoleDefaults(), providers)
	if err != nil {
		t.Fatalf("candidate config: %v", err)
	}
	if configured.Roles.Artist.Enabled || configured.Roles.Artist.PrimaryProvider != "" || configured.Roles.Artist.Inputs != nil {
		t.Fatalf("unselected UI artist role = %#v", configured.Roles.Artist)
	}
	if _, err := RenderConfigYAML(adapterconfig.YAMLCodec{}, configured); err != nil {
		t.Fatalf("render UI config without artist: %v", err)
	}
}

func TestInitializeProjectZCodeAppBundleDiscovery(t *testing.T) {
	const overrideBundle = "/opt/custom/ZCode.app"
	for _, test := range []struct {
		name             string
		overrides        Overrides
		bundle           string
		wantBundleSource string
	}{
		{name: "standard bundle", bundle: reviewrun.ZCodeAppBundle, wantBundleSource: "standard"},
		{name: "override bundle", overrides: Overrides{ZCodeAppBundle: overrideBundle}, bundle: overrideBundle, wantBundleSource: "override"},
	} {
		t.Run(test.name, func(t *testing.T) {
			executable := filepath.Join(test.bundle, filepath.FromSlash(reviewrun.ZCodeExecutableRelativePath))
			launcher := filepath.Join(test.bundle, filepath.FromSlash(reviewrun.ZCodeLauncherRelativePath))
			providerConfig := filepath.Join(test.bundle, filepath.FromSlash(reviewrun.ZCodeProviderConfigRelativePath))
			rootPath := t.TempDir()
			_ = os.Chmod(rootPath, 0o700)
			root, _ := ports.NewAnchoredRoot(rootPath)
			inspector := &scopedDiscoveryInspector{
				observations: map[string]ports.ExecutableObservation{
					executable: availableDiscoveryObservation(t, executable, executable),
				},
				fileObservations: map[string]ports.FileIdentityObservation{
					executable:     availableFileObservation(t, executable, executable),
					launcher:       availableFileObservation(t, launcher, launcher),
					providerConfig: availableFileObservation(t, providerConfig, providerConfig),
				},
				errors: map[string]error{},
			}
			service, err := NewService(&testInstaller{}, inspector, testAttestor{}, testResultPrevalidator{}, testClock{}, adapterconfig.SourceFactory{}, adapterconfig.YAMLCodec{}, builtin.NewCatalog())
			if err != nil {
				t.Fatal(err)
			}
			result, err := service.InitializeProject(context.Background(), InitializeProjectRequest{
				ProjectRoot: root, ProjectName: "project", NativeHome: "/Users/test",
				Selection: Selection{Mode: SelectionSelected, ProviderIDs: []string{"zcode"}}, Overrides: test.overrides,
			})
			if err != nil {
				t.Fatal(err)
			}
			row := result.Discovery[0]
			if !result.Committed || !reflect.DeepEqual(inspector.calls, []string{executable}) || !reflect.DeepEqual(inspector.readableCalls, []string{executable, launcher, providerConfig}) || row.AppBundleSource != test.wantBundleSource {
				t.Fatalf("result=%#v calls=%v readable=%v", result, inspector.calls, inspector.readableCalls)
			}
		})
	}
}

func TestInitializeProjectDoesNotAdmitIneligibleZCodeApplication(t *testing.T) {
	bundle := reviewrun.ZCodeAppBundle
	executable := filepath.Join(bundle, filepath.FromSlash(reviewrun.ZCodeExecutableRelativePath))
	launcher := filepath.Join(bundle, filepath.FromSlash(reviewrun.ZCodeLauncherRelativePath))
	providerConfig := filepath.Join(bundle, filepath.FromSlash(reviewrun.ZCodeProviderConfigRelativePath))
	metadata := filepath.Join(bundle, filepath.FromSlash(reviewrun.ZCodeApplicationMetadataRelativePath))
	belowMinimum, err := ports.NewApplicationMetadataObservation(metadata, "sha256:"+strings.Repeat("b", 64), "3.12.2")
	if err != nil {
		t.Fatal(err)
	}
	inspector := &scopedDiscoveryInspector{
		observations: map[string]ports.ExecutableObservation{executable: availableDiscoveryObservation(t, executable, executable)},
		fileObservations: map[string]ports.FileIdentityObservation{
			executable: availableFileObservation(t, executable, executable), launcher: availableFileObservation(t, launcher, launcher), providerConfig: availableFileObservation(t, providerConfig, providerConfig),
		},
		applicationObservations: map[string]ports.ApplicationMetadataObservation{metadata: belowMinimum}, errors: map[string]error{},
	}
	service, err := NewService(&testInstaller{}, inspector, testAttestor{}, testResultPrevalidator{}, testClock{}, adapterconfig.SourceFactory{}, adapterconfig.YAMLCodec{}, builtin.NewCatalog())
	if err != nil {
		t.Fatal(err)
	}
	found, rows, err := service.discover(context.Background(), InitializeProjectRequest{Selection: Selection{Mode: SelectionSelected, ProviderIDs: []string{"zcode"}}})
	if err == nil {
		t.Fatal("ineligible selected ZCode application was accepted")
	}
	if found.zcode != nil || len(rows) != 3 || rows[0].Candidate || rows[0].Status != "unavailable" {
		t.Fatalf("ineligible ZCode discovery = found %#v rows %#v", found.zcode, rows)
	}
}

func TestInitializeProjectDiscoveryFailureStillReturnsThreeRows(t *testing.T) {
	rootPath := t.TempDir()
	_ = os.Chmod(rootPath, 0o700)
	root, _ := ports.NewAnchoredRoot(rootPath)
	inspector := &scopedDiscoveryInspector{errors: map[string]error{"grok": errors.New("injected Grok discovery failure")}}
	service, _ := NewService(&testInstaller{}, inspector, testAttestor{}, testResultPrevalidator{}, testClock{}, adapterconfig.SourceFactory{}, adapterconfig.YAMLCodec{}, builtin.NewCatalog())
	result, err := service.InitializeProject(context.Background(), InitializeProjectRequest{
		ProjectRoot: root, ProjectName: "project", NativeHome: "/Users/test",
		Selection: Selection{Mode: SelectionSelected, ProviderIDs: []string{"grok"}},
	})
	if err == nil {
		t.Fatal("selected provider discovery failure accepted")
	}
	if len(result.Discovery) != 3 || result.Discovery[0].Status != "not_selected" || result.Discovery[1].Status != "unavailable" || result.Discovery[2].Status != "not_selected" {
		t.Fatalf("discovery=%#v", result.Discovery)
	}
}

func readInstalledConfig(root string) (adapterconfig.Config, error) {
	project, err := os.ReadFile(filepath.Join(root, ".mulgae", "config.yaml"))
	if err != nil {
		return adapterconfig.Config{}, err
	}
	local, err := os.ReadFile(filepath.Join(root, ".mulgae", "local.yaml"))
	if err != nil {
		return adapterconfig.Config{}, err
	}
	return adapterconfig.DecodeSplit(project, local)
}

func TestInitializeProjectBootstrapsAndRefreshesMachineLocalConfig(t *testing.T) {
	rootPath := t.TempDir()
	_ = os.Chmod(rootPath, 0o700)
	_ = os.Mkdir(filepath.Join(rootPath, ".mulgae"), 0o755)
	baseRequest := InitializeProjectRequest{ProjectName: "project", NativeHome: "/Users/test", Selection: Selection{Mode: SelectionSelected, ProviderIDs: []string{"grok"}}, Overrides: Overrides{GrokExecutable: "/bin/grok"}}
	config, err := candidateConfig(baseRequest, testRoleDefaults(), candidates{grok: &adapterconfig.GrokProviderConfig{Executable: "/bin/grok", Timeout: "60m"}})
	if err != nil {
		t.Fatal(err)
	}
	project, _, err := adapterconfig.EncodeSplit(config)
	if err != nil {
		t.Fatal(err)
	}
	projectPath := filepath.Join(rootPath, ".mulgae", "config.yaml")
	if err := os.WriteFile(projectPath, project, 0o644); err != nil {
		t.Fatal(err)
	}
	root, _ := ports.NewAnchoredRoot(rootPath)
	service, err := NewService(filesystem.NewSecureWriter(), testInspector{}, testAttestor{}, testResultPrevalidator{}, testClock{}, adapterconfig.SourceFactory{}, adapterconfig.YAMLCodec{}, builtin.NewCatalog())
	if err != nil {
		t.Fatal(err)
	}
	request := InitializeProjectRequest{ProjectRoot: root, ProjectName: "project", NativeHome: "/Users/test", Selection: Selection{Mode: SelectionAuto}, Overrides: Overrides{GrokExecutable: "/bin/grok"}}
	request.ProjectPolicyOptions = true
	if result, err := service.InitializeProject(context.Background(), request); err == nil || result.Committed {
		t.Fatalf("bootstrap with project-policy options = %#v, %v", result, err)
	}
	if _, err := os.Lstat(filepath.Join(rootPath, ".mulgae", "local.yaml")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rejected bootstrap created local config: %v", err)
	}
	request.ProjectPolicyOptions = false
	result, err := service.InitializeProject(context.Background(), request)
	if err != nil || !result.Committed {
		t.Fatalf("bootstrap = %#v, %v", result, err)
	}
	if info, err := os.Stat(filepath.Join(rootPath, ".mulgae")); err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("private directory = %v, %v", info, err)
	}
	if current, _ := os.ReadFile(projectPath); !bytes.Equal(current, project) {
		t.Fatal("bootstrap changed project policy")
	}
	if result.Discovery[1].ModelSource != "provider_default" || result.Discovery[1].ReasoningEffortSource != "provider_default" {
		t.Fatalf("existing project Grok provenance=%#v", result.Discovery[1])
	}
	request.RefreshLocal = true
	request.Overrides.GrokExecutable = "/opt/grok"
	result, err = service.InitializeProject(context.Background(), request)
	if err != nil || !result.Committed {
		t.Fatalf("refresh = %#v, %v", result, err)
	}
	resolved, err := readInstalledConfig(rootPath)
	if err != nil || resolved.Providers.Grok.Executable != "/opt/grok" {
		t.Fatalf("refreshed config = %#v, %v", resolved, err)
	}
	if current, _ := os.ReadFile(projectPath); !bytes.Equal(current, project) {
		t.Fatal("refresh changed project policy")
	}
}

func TestInitializeProjectReportsFamilySpecificDiscoverySources(t *testing.T) {
	appBundle := filepath.Join(t.TempDir(), "ZCode.app")
	rootPath := t.TempDir()
	_ = os.Chmod(rootPath, 0o700)
	root, _ := ports.NewAnchoredRoot(rootPath)
	inspector := testInspector{}
	service, err := NewService(&testInstaller{}, inspector, testAttestor{}, testResultPrevalidator{}, testClock{}, adapterconfig.SourceFactory{}, adapterconfig.YAMLCodec{}, builtin.NewCatalog())
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.InitializeProject(context.Background(), InitializeProjectRequest{
		ProjectRoot: root, ProjectName: "project", NativeHome: "/Users/test", NativeHomeAsserted: true,
		Selection: Selection{Mode: SelectionSelected, ProviderIDs: []string{"zcode", "grok"}},
		Overrides: Overrides{
			ZCodeAppBundle: appBundle,
			GrokExecutable: "/bin/grok", GrokModel: "grok-4.5", GrokReasoningEffort: "high-precision",
			GrokModelSet: true, GrokReasoningEffortSet: true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []DiscoveryRow{
		{Family: "zcode", Selected: true, Candidate: true, Configured: true, Status: "candidate", AppBundleSource: "override", ModelSource: "provider_default", ReasoningEffortSource: "provider_default"},
		{Family: "grok", Selected: true, Candidate: true, Configured: true, Status: "candidate", ExecutableSource: "override", ModelSource: "override", ReasoningEffortSource: "override"},
		{Family: "codex", Status: "not_selected", ExecutableSource: "not_selected", ModelSource: "not_selected", ReasoningEffortSource: "not_selected"},
	}
	if !reflect.DeepEqual(result.Discovery, want) {
		t.Fatalf("discovery=%#v, want %#v", result.Discovery, want)
	}
}

func TestInitializeProjectReportsCreatedAndExistingRootBarrierTruthfully(t *testing.T) {
	for _, test := range []struct {
		name     string
		existing bool
		want     string
	}{{"created", false, "private_dir_created_unconfirmed"}, {"existing", true, "private_dir_existing_unconfirmed"}} {
		t.Run(test.name, func(t *testing.T) {
			rootPath := t.TempDir()
			_ = os.Chmod(rootPath, 0o700)
			if test.existing {
				_ = os.Mkdir(filepath.Join(rootPath, ".mulgae"), 0o700)
			}
			root, _ := ports.NewAnchoredRoot(rootPath)
			installer := &testInstaller{rootError: true, existing: test.existing}
			service, _ := NewService(installer, testInspector{}, testAttestor{}, testResultPrevalidator{}, testClock{}, adapterconfig.SourceFactory{}, adapterconfig.YAMLCodec{}, builtin.NewCatalog())
			result, err := service.InitializeProject(context.Background(), InitializeProjectRequest{ProjectRoot: root, ProjectName: "project", NativeHome: "/Users/test", Selection: Selection{Mode: SelectionSelected, ProviderIDs: []string{"grok"}}, Overrides: Overrides{GrokExecutable: "/bin/grok"}})
			if err == nil || result.WriteState != test.want || result.Committed {
				t.Fatalf("result=%#v err=%v", result, err)
			}
		})
	}
}

func TestPrepareFailureWithReplacementConfigPreservesRootBarrierState(t *testing.T) {
	receipt := ports.ConfigDirectoryReceipt{}
	state, destination, code := prepareFailure(receipt, ports.NewConfigInstallError(ports.ConfigInstallStageRootReattestation, ports.ConfigDestinationPresent, errors.New("identity drift")))
	if state != "private_dir_existing_unconfirmed" || destination != ports.ConfigDestinationPresent || code != "config_locality_drifted" {
		t.Fatalf("prepare failure = %s/%s/%s", state, destination, code)
	}
}

func TestPrepareRootSyncWithConcurrentDestinationUsesPrevalidatedArtifactOutcome(t *testing.T) {
	for _, test := range []struct {
		name, code string
		created    bool
	}{
		{name: "created", code: "init_private_dir_commit_unconfirmed", created: true},
		{name: "existing", code: "init_existing_private_dir_commit_unconfirmed"},
	} {
		t.Run(test.name, func(t *testing.T) {
			identity, err := ports.NewConfigDirectoryIdentity(1, 2, 501, 0o700, 1, 3, 501, 0o700)
			if err != nil {
				t.Fatal(err)
			}
			receipt, err := ports.NewVerifiedConfigDirectoryReceipt(test.created, identity)
			if err != nil {
				t.Fatal(err)
			}
			state, destination, code := prepareFailure(receipt, ports.NewConfigInstallError(ports.ConfigInstallStageRootSync, ports.ConfigDestinationPresent, errors.New("sync")))
			wantState := "private_dir_existing_unconfirmed"
			if test.created {
				wantState = "private_dir_created_unconfirmed"
			}
			if state != wantState || destination != ports.ConfigDestinationPresent || code != test.code {
				t.Fatalf("prepare failure = %s/%s/%s", state, destination, code)
			}
			base := InitializeProjectResult{WriteState: "not_attempted", DestinationState: ports.ConfigDestinationAbsent}
			_, failureErr := mutationFailure(base, state, destination, code, errors.New("sync"))
			var failure *Failure
			if !errors.As(failureErr, &failure) || failure.Class() != "artifact_failure" || !failure.Retryable() {
				t.Fatalf("failure = %#v, %v", failure, failureErr)
			}
		})
	}
}

func TestInitializeProjectRejectsExistingConfigBeforeDiscovery(t *testing.T) {
	rootPath := t.TempDir()
	_ = os.Chmod(rootPath, 0o700)
	_ = os.Mkdir(filepath.Join(rootPath, ".mulgae"), 0o700)
	roles, _ := adapterconfig.CanonicalRolesConfig(testRoleDefaults(), []string{"grok"})
	config := adapterconfig.Config{Version: adapterconfig.ConfigVersion, Project: adapterconfig.ProjectConfig{Name: "project"}, NativeUser: adapterconfig.NativeUserConfig{Home: "/Users/test"}, Providers: adapterconfig.ProvidersConfig{Grok: &adapterconfig.GrokProviderConfig{Executable: "/bin/grok", Timeout: "60m"}}, Execution: adapterconfig.ExecutionConfig{WorkspaceAccess: "none"}, Roles: roles, Review: adapterconfig.ReviewConfig{RequiredRoles: []string{"logic"}, RequestChangesOn: []string{"high", "critical", "blocker"}}, Validation: adapterconfig.ValidationConfig{Evidence: adapterconfig.EvidenceConfig{RequireVerifiedFor: []string{"high", "critical", "blocker"}}, Repair: adapterconfig.RepairConfig{Enabled: true, MaxAttempts: 1, SameProvider: true}}, Resources: adapterconfig.ResourcesConfig{MaxActiveLanes: 1, PrimaryRepairAttempts: 1, RoleMaxInvocations: 2, RunMaxInvocations: 12}, CI: adapterconfig.CIConfig{FailOnSeverity: []string{"high", "critical", "blocker"}, DegradedReviewFails: true}}
	project, local, _ := adapterconfig.EncodeSplit(config)
	_ = os.WriteFile(filepath.Join(rootPath, ".mulgae", "config.yaml"), project, 0o600)
	_ = os.WriteFile(filepath.Join(rootPath, ".mulgae", "local.yaml"), local, 0o600)
	root, _ := ports.NewAnchoredRoot(rootPath)
	service, _ := NewService(&testInstaller{existing: true}, testInspector{absent: true}, testAttestor{}, testResultPrevalidator{}, testClock{}, adapterconfig.SourceFactory{}, adapterconfig.YAMLCodec{}, builtin.NewCatalog())
	result, err := service.InitializeProject(context.Background(), InitializeProjectRequest{ProjectRoot: root, ProjectName: "project", NativeHome: "/Users/test", Selection: Selection{Mode: SelectionAuto}})
	if err == nil || result.WriteState != "existing_untouched" || result.DestinationState != ports.ConfigDestinationPresent || len(result.Discovery) != 0 {
		t.Fatalf("result=%#v err=%v", result, err)
	}
}

func TestInitializeProjectReportsPostBarrierLocalityFailureByDirectoryOwnership(t *testing.T) {
	for _, test := range []struct {
		name, want string
		existing   bool
	}{{name: "created", want: "private_dir_created_unconfirmed"}, {name: "existing", want: "private_dir_existing_unconfirmed", existing: true}} {
		t.Run(test.name, func(t *testing.T) {
			rootPath := t.TempDir()
			_ = os.Chmod(rootPath, 0o700)
			if test.existing {
				_ = os.Mkdir(filepath.Join(rootPath, ".mulgae"), 0o700)
			}
			root, _ := ports.NewAnchoredRoot(rootPath)
			attestor := &scriptedAttestor{failAttestAt: 2}
			service, _ := NewService(&testInstaller{existing: test.existing}, testInspector{}, attestor, testResultPrevalidator{}, testClock{}, adapterconfig.SourceFactory{}, adapterconfig.YAMLCodec{}, builtin.NewCatalog())
			result, err := service.InitializeProject(context.Background(), grokInitRequest(root))
			if err == nil || result.WriteState != test.want || result.DestinationState != ports.ConfigDestinationAbsent || result.Committed {
				t.Fatalf("result=%#v err=%v", result, err)
			}
		})
	}
}

func TestInitializeProjectReportsPreparedIdentityDriftByDirectoryOwnership(t *testing.T) {
	for _, test := range []struct {
		name, want  string
		existing    bool
		destination ports.ConfigDestinationState
	}{{name: "created", want: "private_dir_created_unconfirmed", destination: ports.ConfigDestinationAbsent}, {name: "existing", want: "private_dir_existing_unconfirmed", existing: true, destination: ports.ConfigDestinationAbsent}, {name: "replacement config present", want: "existing_untouched", destination: ports.ConfigDestinationPresent}} {
		t.Run(test.name, func(t *testing.T) {
			rootPath := t.TempDir()
			_ = os.Chmod(rootPath, 0o700)
			if test.existing {
				_ = os.Mkdir(filepath.Join(rootPath, ".mulgae"), 0o700)
			}
			root, _ := ports.NewAnchoredRoot(rootPath)
			installError := ports.NewConfigInstallError(ports.ConfigInstallStagePreparedIdentity, test.destination, errors.New("injected identity drift"))
			service, _ := NewService(&testInstaller{existing: test.existing, installError: installError}, testInspector{}, testAttestor{}, testResultPrevalidator{}, testClock{}, adapterconfig.SourceFactory{}, adapterconfig.YAMLCodec{}, builtin.NewCatalog())
			result, err := service.InitializeProject(context.Background(), grokInitRequest(root))
			var failure *Failure
			if !errors.As(err, &failure) || failure.Class() != "security_policy_violation" || failure.Code() != "config_locality_drifted" || failure.Retryable() ||
				result.WriteState != test.want || result.DestinationState != test.destination || result.Committed {
				t.Fatalf("result=%#v err=%v", result, err)
			}
		})
	}
}

func TestInitializeProjectClassifiesReplacementConfigAsLocalityDrift(t *testing.T) {
	rootPath := t.TempDir()
	_ = os.Chmod(rootPath, 0o700)
	root, _ := ports.NewAnchoredRoot(rootPath)
	installer := &afterPrepareTestInstaller{delegate: &testInstaller{}, after: func(root ports.AnchoredRoot) error {
		original := filepath.Join(root.String(), ".mulgae")
		if err := os.Rename(original, original+"-original"); err != nil {
			return err
		}
		if err := os.Mkdir(original, 0o700); err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(original, "config.yaml"), []byte("replacement\n"), 0o600)
	}}
	service, _ := NewService(installer, testInspector{}, testAttestor{}, testResultPrevalidator{}, testClock{}, adapterconfig.SourceFactory{}, adapterconfig.YAMLCodec{}, builtin.NewCatalog())
	result, err := service.InitializeProject(context.Background(), grokInitRequest(root))
	var failure *Failure
	if !errors.As(err, &failure) || failure.Code() != "config_locality_drifted" || failure.Retryable() ||
		result.WriteState != "private_dir_created_unconfirmed" || result.DestinationState != ports.ConfigDestinationAbsent || installer.delegate.installCalls != 0 {
		t.Fatalf("result=%#v err=%v install_calls=%d", result, err, installer.delegate.installCalls)
	}
}

func TestInitializeProjectRejectsSameByteConfigIdentitySubstitution(t *testing.T) {
	rootPath := t.TempDir()
	_ = os.Chmod(rootPath, 0o700)
	root, _ := ports.NewAnchoredRoot(rootPath)
	installer := &afterInstallTestInstaller{delegate: &testInstaller{}, after: func(root ports.AnchoredRoot, data []byte) error {
		path := filepath.Join(root.String(), ".mulgae", "local.yaml")
		if err := os.Rename(path, path+".original"); err != nil {
			return err
		}
		return os.WriteFile(path, data, 0o600)
	}}
	service, _ := NewService(installer, testInspector{}, testAttestor{}, testResultPrevalidator{}, testClock{}, adapterconfig.SourceFactory{}, adapterconfig.YAMLCodec{}, builtin.NewCatalog())
	result, err := service.InitializeProject(context.Background(), grokInitRequest(root))
	var failure *Failure
	if err == nil || !errors.As(err, &failure) || failure.Code() != "config_locality_drifted" || failure.Class() != "security_policy_violation" || failure.Retryable() || result.WriteState != "installed_unconfirmed" || result.DestinationState != ports.ConfigDestinationPresent || result.Committed {
		t.Fatalf("result=%#v err=%v", result, err)
	}
}

func TestInitializeProjectNormalizesInstalledGenericErrorToCommitUnconfirmed(t *testing.T) {
	rootPath := t.TempDir()
	_ = os.Chmod(rootPath, 0o700)
	root, _ := ports.NewAnchoredRoot(rootPath)
	installer := &afterInstallTestInstaller{delegate: &testInstaller{}, after: func(ports.AnchoredRoot, []byte) error {
		return errors.New("injected post-install confirmation failure")
	}}
	service, _ := NewService(installer, testInspector{}, testAttestor{}, testResultPrevalidator{}, testClock{}, adapterconfig.SourceFactory{}, adapterconfig.YAMLCodec{}, builtin.NewCatalog())
	result, err := service.InitializeProject(context.Background(), grokInitRequest(root))
	var failure *Failure
	if err == nil || !errors.As(err, &failure) || failure.Code() != "init_commit_unconfirmed" || failure.Class() != "artifact_failure" || !failure.Retryable() || result.WriteState != "installed_unconfirmed" || result.DestinationState != ports.ConfigDestinationNotObserved || result.Committed {
		t.Fatalf("result=%#v err=%v", result, err)
	}
}

func TestInitializeProjectRequiresTerminalLocalityRevalidation(t *testing.T) {
	rootPath := t.TempDir()
	_ = os.Chmod(rootPath, 0o700)
	root, _ := ports.NewAnchoredRoot(rootPath)
	attestor := &scriptedAttestor{failRevalidateAt: 5}
	service, _ := NewService(&testInstaller{}, testInspector{}, attestor, testResultPrevalidator{}, testClock{}, adapterconfig.SourceFactory{}, adapterconfig.YAMLCodec{}, builtin.NewCatalog())
	result, err := service.InitializeProject(context.Background(), grokInitRequest(root))
	_, statErr := os.Lstat(filepath.Join(rootPath, ".mulgae", "config.yaml"))
	if err == nil || result.WriteState != "installed_unconfirmed" || statErr != nil || result.Committed {
		t.Fatalf("result=%#v err=%v", result, err)
	}
}

func TestInitializeProjectRejectsConfigMutationAfterTerminalAttestation(t *testing.T) {
	rootPath := t.TempDir()
	_ = os.Chmod(rootPath, 0o700)
	root, _ := ports.NewAnchoredRoot(rootPath)
	attestor := &finalConfigMutatingAttestor{path: filepath.Join(rootPath, ".mulgae", "config.yaml")}
	service, _ := NewService(&testInstaller{}, testInspector{}, attestor, testResultPrevalidator{}, testClock{}, adapterconfig.SourceFactory{}, adapterconfig.YAMLCodec{}, builtin.NewCatalog())
	result, err := service.InitializeProject(context.Background(), grokInitRequest(root))
	if err == nil || !attestor.mutated || result.WriteState != "installed_unconfirmed" || result.DestinationState != ports.ConfigDestinationPresent || result.Committed {
		t.Fatalf("result=%#v mutated=%t err=%v", result, attestor.mutated, err)
	}
	contents, readErr := os.ReadFile(attestor.path)
	if readErr != nil || string(contents) != "version: 3\n" {
		t.Fatalf("mutated destination=%q err=%v", contents, readErr)
	}
}

func TestInitializeProjectNormalizesUninstalledPresentFailureToCollision(t *testing.T) {
	rootPath := t.TempDir()
	_ = os.Chmod(rootPath, 0o700)
	root, _ := ports.NewAnchoredRoot(rootPath)
	installer := &testInstaller{installError: ports.NewConfigInstallError(ports.ConfigInstallStagePreinstall, ports.ConfigDestinationPresent, context.Canceled)}
	service, _ := NewService(installer, testInspector{}, testAttestor{}, testResultPrevalidator{}, testClock{}, adapterconfig.SourceFactory{}, adapterconfig.YAMLCodec{}, builtin.NewCatalog())
	result, err := service.InitializeProject(context.Background(), grokInitRequest(root))
	var failure *Failure
	if err == nil || !errors.As(err, &failure) || failure.Class() != "configuration_violation" || failure.Code() != "init_destination_exists" || failure.Retryable() {
		t.Fatalf("failure=%#v err=%v", failure, err)
	}
	if result.WriteState != "existing_untouched" || result.DestinationState != ports.ConfigDestinationPresent || result.Committed {
		t.Fatalf("result=%#v", result)
	}
}

type recordingPrevalidator struct{ outcomes []PrevalidatedOutcome }

func (validator *recordingPrevalidator) PrevalidateInitOutcome(_ context.Context, outcome PrevalidatedOutcome) error {
	validator.outcomes = append(validator.outcomes, outcome)
	return outcome.Result.Validate()
}

func admittedGrokDiscoveryRows() []DiscoveryRow {
	grok := DiscoveryRow{
		Family: "grok", Selected: true, Candidate: true, Configured: true, Status: "candidate",
		ExecutableSource: "override", ModelSource: "provider_default", ReasoningEffortSource: "provider_default",
	}
	return []DiscoveryRow{notSelectedDiscoveryRow("zcode"), grok, notSelectedDiscoveryRow("codex")}
}

func TestPrevalidateMutationResultsCoversExactFailureEnvelopes(t *testing.T) {
	validator := &recordingPrevalidator{}
	service := &Service{prevalidator: validator}
	base := InitializeProjectResult{
		Kind: "initialization_failed", ConfigURI: ".mulgae/config.yaml", ConfigSHA256: appconfig.BundleSHA256([]byte("config"), nil),
		SelectedProviderIDs: []string{"grok"}, CandidateProviderIDs: []string{"grok"}, ConfiguredProviderIDs: []string{"grok"},
		ConfiguredRoleIDs: []string{"logic", "security", "maintainability", "product", "documentation", "testing"},
		WriteState:        "not_attempted", DestinationState: ports.ConfigDestinationAbsent,
		Discovery: admittedGrokDiscoveryRows(),
	}
	if err := service.prevalidateMutationResults(context.Background(), base); err != nil {
		t.Fatal(err)
	}
	if len(validator.outcomes) != len(MutationOutcomeSpecs()) {
		t.Fatalf("prevalidated outcomes = %d, want %d", len(validator.outcomes), len(MutationOutcomeSpecs()))
	}
	seen := map[string]bool{}
	for _, outcome := range validator.outcomes {
		key := outcome.Result.WriteState + "/" + string(outcome.Result.DestinationState)
		if outcome.Failure != nil {
			key += "/" + outcome.Failure.Code() + "/" + string(outcome.Failure.Class())
		} else if !outcome.Result.Committed {
			t.Fatalf("noncommitted outcome has no failure: %#v", outcome)
		}
		if seen[key] {
			t.Fatalf("duplicate prevalidated outcome %q", key)
		}
		seen[key] = true
	}
	for _, code := range []string{"init_destination_exists", "init_write_failed", "init_local_write_failed", "init_private_dir_raced", "init_private_dir_commit_unconfirmed", "init_existing_private_dir_commit_unconfirmed", "init_commit_unconfirmed", "config_locality_drifted", "target_private_config_forbidden", "target_private_namespace_forbidden", "init_result_delivery_failed"} {
		found := false
		for key := range seen {
			if strings.Contains(key, "/"+code+"/") {
				found = true
			}
		}
		if !found {
			t.Fatalf("prevalidation omitted %q", code)
		}
	}
}

func TestPrevalidatedOutcomeRejectsContradictoryFailureTuple(t *testing.T) {
	result := InitializeProjectResult{
		Kind: "initialization_failed", ConfigURI: ".mulgae/config.yaml", ConfigSHA256: appconfig.BundleSHA256([]byte("config"), nil),
		SelectedProviderIDs: []string{"grok"}, CandidateProviderIDs: []string{"grok"}, ConfiguredProviderIDs: []string{"grok"},
		ConfiguredRoleIDs: []string{"logic", "security", "maintainability", "product", "documentation", "testing"},
		WriteState:        "installed_unconfirmed", DestinationState: ports.ConfigDestinationPresent,
		Discovery: admittedGrokDiscoveryRows(),
	}
	contradictory := PrevalidatedOutcome{
		Result:  result,
		Failure: &Failure{class: domain.FailureConfiguration, code: "init_destination_exists", message: initFailureMessage("init_destination_exists")},
	}
	if err := contradictory.Validate(); err == nil {
		t.Fatal("contradictory post-mutation failure tuple was accepted")
	}
}

func TestMutationOutcomeSpecsIncludeExactDeliveryFailure(t *testing.T) {
	matches := 0
	for _, spec := range MutationOutcomeSpecs() {
		if spec.Code != "init_result_delivery_failed" {
			continue
		}
		matches++
		if spec.Kind != "initialized" || spec.WriteState != "committed" || !spec.Committed || spec.Destination != ports.ConfigDestinationPresent || spec.Class != domain.FailureArtifact || spec.Message != "The init result could not be delivered after commit." || !spec.Retryable || !spec.DeliveryOnly {
			t.Fatalf("delivery outcome = %#v", spec)
		}
	}
	if matches != 1 {
		t.Fatalf("delivery outcomes = %d, want 1", matches)
	}
}

func TestMutationOutcomeGoldenMatchesContractTable(t *testing.T) {
	want, err := os.ReadFile(filepath.Join("testdata", "mutation-outcomes.v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := json.MarshalIndent(MutationOutcomeSpecs(), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	if !bytes.Equal(got, want) {
		t.Fatal("generated mutation outcome golden is stale")
	}
}

func grokInitRequest(root ports.AnchoredRoot) InitializeProjectRequest {
	return InitializeProjectRequest{ProjectRoot: root, ProjectName: "project", NativeHome: "/Users/test", Selection: Selection{Mode: SelectionSelected, ProviderIDs: []string{"grok"}}, Overrides: Overrides{GrokExecutable: "/bin/grok"}}
}
