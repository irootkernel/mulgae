package doctor

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	adapterconfig "github.com/irootkernel/mulgae/internal/adapters/config"
	appconfig "github.com/irootkernel/mulgae/internal/app/config"
	"github.com/irootkernel/mulgae/internal/ports"
)

type localDoctorFixture struct {
	service                            *LocalService
	root                               ports.AnchoredRoot
	trace                              []string
	nativeCalls                        int
	nativeErr                          map[int]error
	replacement                        bool
	versionState                       ports.ProviderVersionState
	version                            string
	terminalState                      ports.TerminalRuntimeAvailabilityState
	terminalErr                        error
	openErr, errorAttest, errorConfirm error
	sourceCalls                        int
	sourceFailAt                       int
}
type localDoctorClock struct{ fixture *localDoctorFixture }

func (clock localDoctorClock) Now() time.Time {
	clock.fixture.trace = append(clock.fixture.trace, "clock")
	return time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
}

type localDoctorFactory struct{ fixture *localDoctorFixture }

func (factory localDoctorFactory) OpenConfigSource(root ports.AnchoredRoot, missing bool) (ports.ConfigSource, error) {
	f := factory.fixture
	f.trace = append(f.trace, "open")
	if f.openErr != nil {
		return nil, f.openErr
	}
	source, err := adapterconfig.SourceFactory{}.OpenConfigSource(root, missing)
	if err != nil {
		return nil, err
	}
	return localDoctorSource{SplitConfigSource: source.(ports.SplitConfigSource), fixture: f}, nil
}

type localDoctorSource struct {
	ports.SplitConfigSource
	fixture *localDoctorFixture
}

func (source localDoctorSource) Proof() (ports.ConfigFileProof, error) {
	source.fixture.trace = append(source.fixture.trace, "proof")
	return source.SplitConfigSource.Proof()
}
func (source localDoctorSource) Read() ([]byte, ports.ConfigFileIdentity, error) {
	source.fixture.trace = append(source.fixture.trace, "read")
	return source.SplitConfigSource.Read()
}
func (source localDoctorSource) Revalidate() error {
	f := source.fixture
	f.trace = append(f.trace, "source")
	f.sourceCalls++
	if f.sourceCalls == f.sourceFailAt {
		return errors.New("source drift")
	}
	return source.SplitConfigSource.Revalidate()
}

type localDoctorCodec struct {
	appconfig.SplitCodec
	fixture *localDoctorFixture
}

func (codec localDoctorCodec) Decode(data []byte) (appconfig.Config, error) {
	codec.fixture.trace = append(codec.fixture.trace, "decode")
	return codec.SplitCodec.Decode(data)
}

type localDoctorAccount struct{ fixture *localDoctorFixture }

func (account localDoctorAccount) ObserveAccount() appconfig.AccountObservation {
	account.fixture.trace = append(account.fixture.trace, "account")
	return appconfig.AccountObservation{Available: true, Home: "/synthetic/home", UID: "501", EffectiveUID: 501}
}

type localDoctorAttestor struct{ fixture *localDoctorFixture }

func (attestor localDoctorAttestor) Attest(_ context.Context, request ports.ConfigLocalityRequest) (ports.ConfigLocalityContext, error) {
	f := attestor.fixture
	f.trace = append(f.trace, "attest")
	if f.errorAttest != nil {
		return ports.ConfigLocalityContext{}, f.errorAttest
	}
	device, inode, uid, mode := request.Config().RootIdentity()
	return ports.NewConfigLocalityContext("local-doctor-test", device, inode, uid, mode, "", "", "sha256:"+strings.Repeat("b", 64), 0, false, nil, request.Config(), ports.ParsedTargetProof{SHA256: "sha256:" + strings.Repeat("c", 64), PrivatePathFree: true})
}
func (attestor localDoctorAttestor) Revalidate(context.Context, ports.ConfigLocalityRequest, ports.ConfigLocalityContext) error {
	f := attestor.fixture
	f.trace = append(f.trace, "locality")
	return f.errorConfirm
}

type localDoctorInspector struct {
	ports.EnvironmentInspector
	fixture *localDoctorFixture
}

func (inspector localDoctorInspector) ObserveNativeHomeIdentity(_ context.Context, path string) (ports.NativeHomeLaunchAuthority, error) {
	f := inspector.fixture
	f.nativeCalls++
	f.trace = append(f.trace, fmt.Sprintf("native.%d", f.nativeCalls))
	if err := f.nativeErr[f.nativeCalls]; err != nil {
		return ports.NativeHomeLaunchAuthority{}, err
	}
	inode := uint64(10)
	if f.replacement && f.nativeCalls == 2 {
		inode++
	}
	return ports.NewNativeHomeLaunchAuthority(path, 1, inode, 501)
}
func (inspector localDoctorInspector) ObserveExecutableIdentity(_ context.Context, path string) (ports.ExecutableObservation, error) {
	inspector.fixture.trace = append(inspector.fixture.trace, "binary")
	return ports.NewExecutableObservation(path, true, path, "", "sha256:"+strings.Repeat("a", 64))
}
func (localDoctorInspector) ObservePlatform(context.Context) (ports.PlatformObservation, error) {
	panic("local diagnosis must use injected platform metadata")
}
func (localDoctorInspector) ObservePermission(context.Context, ports.AnchoredRoot, ports.SafeRelativePath) (ports.PermissionObservation, error) {
	panic("local diagnosis must not enter recorded-evidence inspection")
}

type localDoctorVersions struct{ fixture *localDoctorFixture }

func (versions localDoctorVersions) ObserveProviderVersion(_ context.Context, family string, argv []string, identity ports.ProviderVersionIdentity) (ports.ProviderVersionObservation, error) {
	f := versions.fixture
	f.trace = append(f.trace, "version")
	if family != "grok" || !reflect.DeepEqual(argv, []string{"/synthetic/grok", "--version"}) || identity.ExecutableSHA256 != "sha256:"+strings.Repeat("a", 64) {
		return ports.ProviderVersionObservation{}, errors.New("version authority changed")
	}
	return ports.NewProviderVersionObservation(f.versionState, f.version)
}

type localDoctorTerminalRuntime struct{ fixture *localDoctorFixture }

func (observer localDoctorTerminalRuntime) ObserveTerminalRuntime(_ context.Context, _ string, _ ...string) (ports.TerminalRuntimeExecutableObservation, error) {
	f := observer.fixture
	if f.terminalErr != nil {
		return ports.TerminalRuntimeExecutableObservation{}, f.terminalErr
	}
	if f.terminalState == ports.TerminalRuntimeAvailable {
		return ports.NewTerminalRuntimeExecutableObservation(
			ports.TerminalRuntimeAvailable,
			"/opt/homebrew/bin/hc",
			"sha256:"+strings.Repeat("d", 64),
		)
	}
	return ports.NewTerminalRuntimeExecutableObservation(f.terminalState, "", "")
}

func newLocalDoctorFixture(t *testing.T) *localDoctorFixture {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, ".mulgae"), 0o700); err != nil {
		t.Fatal(err)
	}
	project, err := os.ReadFile("../../builtin/assets/examples/project-config.yaml")
	if err != nil {
		t.Fatal(err)
	}
	local, err := os.ReadFile("../../builtin/assets/examples/local-config.yaml")
	if err != nil {
		t.Fatal(err)
	}
	config, err := adapterconfig.DecodeSplit(project, local)
	if err != nil {
		t.Fatal(err)
	}
	config.NativeUser.Home = "/synthetic/home"
	config.Providers = appconfig.ProvidersConfig{Grok: &appconfig.GrokProviderConfig{Executable: "/synthetic/grok"}}
	for _, role := range []*appconfig.RoleConfig{&config.Roles.Logic, &config.Roles.Security, &config.Roles.Maintainability, &config.Roles.Product, &config.Roles.Documentation, &config.Roles.Testing} {
		role.PrimaryProvider = "grok"
	}
	project, local, err = adapterconfig.EncodeSplit(config)
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{"config.yaml": project, "local.yaml": local} {
		if err := os.WriteFile(filepath.Join(root, ".mulgae", name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	anchored, _ := ports.NewAnchoredRoot(root)
	f := &localDoctorFixture{root: anchored, versionState: ports.ProviderVersionObserved, version: "1.0.89", terminalState: ports.TerminalRuntimeAvailable}
	f.service = NewLocalService(LocalDependencies{Clock: localDoctorClock{f}, Sources: localDoctorFactory{f}, Codec: localDoctorCodec{adapterconfig.YAMLCodec{}, f}, Accounts: localDoctorAccount{f}, Locality: localDoctorAttestor{f}, Inspector: localDoctorInspector{fixture: f}, Versions: localDoctorVersions{f}, TerminalRuntime: localDoctorTerminalRuntime{f}, Platform: LocalPlatformEvidence{Cell: "darwin-arm64", Native: true}})
	if len(f.trace) != 0 {
		t.Fatalf("construction observed effects: %v", f.trace)
	}
	return f
}

var localDoctorReadyTrace = []string{"clock", "open", "proof", "attest", "source", "locality", "source", "read", "decode", "source", "locality", "source", "account", "native.1", "binary", "version", "native.2"}

func TestLocalDoctorAdmissionSequence(t *testing.T) {
	f := newLocalDoctorFixture(t)
	result, err := f.service.DiagnoseLocal(context.Background(), f.root)
	if err != nil || result.Readiness.ExitCode != 0 || !reflect.DeepEqual(f.trace, localDoctorReadyTrace) {
		t.Fatalf("diagnosis=%+v err=%v trace=%v", result, err, f.trace)
	}
	for _, test := range []struct {
		name   string
		setup  func(*localDoctorFixture)
		want   []string
		status string
	}{
		{"missing source", func(f *localDoctorFixture) { f.openErr = fs.ErrNotExist }, []string{"clock", "open"}, "missing"},
		{"attestor rejection", func(f *localDoctorFixture) { f.errorAttest = errors.New("rejected") }, []string{"clock", "open", "proof", "attest"}, "unsafe"},
		{"first source drift", func(f *localDoctorFixture) { f.sourceFailAt = 1 }, []string{"clock", "open", "proof", "attest", "source"}, "drifted"},
		{"attestor drift", func(f *localDoctorFixture) { f.errorConfirm = errors.New("drift") }, []string{"clock", "open", "proof", "attest", "source", "locality"}, "drifted"},
		{"trailing source drift", func(f *localDoctorFixture) { f.sourceFailAt = 2 }, []string{"clock", "open", "proof", "attest", "source", "locality", "source"}, "drifted"},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newLocalDoctorFixture(t)
			test.setup(f)
			result, err := f.service.DiagnoseLocal(context.Background(), f.root)
			if err != nil || result.Config.Status != test.status || !reflect.DeepEqual(f.trace, test.want) {
				t.Fatalf("status=%s err=%v trace=%v", result.Config.Status, err, f.trace)
			}
		})
	}
}
func TestLocalDoctorReadinessCompatibility(t *testing.T) {
	for _, test := range []struct {
		name, version string
		state         ports.ProviderVersionState
		exit          int
		reason        string
	}{
		{"supported", "1.0.89", ports.ProviderVersionObserved, 0, "provider_cli_version_supported"},
		{"newer", "9.9.9", ports.ProviderVersionObserved, 0, "provider_cli_version_newer_than_verified"},
		{"below_prior_verified", "1.0.40", ports.ProviderVersionObserved, 4, "provider_cli_version_below_minimum"},
		{"below", "0.1.0", ports.ProviderVersionObserved, 4, "provider_cli_version_below_minimum"},
		{"malformed", "", ports.ProviderVersionMalformed, 4, "provider_cli_version_malformed"},
		{"timeout", "", ports.ProviderVersionTimedOut, 4, "provider_cli_version_timeout"},
		{"failed", "", ports.ProviderVersionExecutionFailed, 4, "provider_cli_version_command_failed"},
		{"unsafe", "", ports.ProviderVersionUnsafeIdentity, 8, "provider_cli_version_unsafe_identity"},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newLocalDoctorFixture(t)
			f.version, f.versionState = test.version, test.state
			result, err := f.service.DiagnoseLocal(context.Background(), f.root)
			if err != nil || result.Readiness.ExitCode != test.exit || result.ProviderInventory[1].CLICompatible.ReasonCode != test.reason || !reflect.DeepEqual(f.trace, localDoctorReadyTrace) {
				t.Fatalf("result=%+v err=%v trace=%v", result, err, f.trace)
			}
		})
	}
	f := newLocalDoctorFixture(t)
	f.service.dependencies.Versions = nil
	result, err := f.service.DiagnoseLocal(context.Background(), f.root)
	want := append(append([]string{}, localDoctorReadyTrace[:15]...), "native.2")
	if err != nil || result.Readiness.ExitCode != 4 || !reflect.DeepEqual(f.trace, want) {
		t.Fatalf("optional version observer=%+v err=%v trace=%v", result, err, f.trace)
	}
}

func TestLocalDoctorGrokTerminalRuntimeReadiness(t *testing.T) {
	for _, tc := range []struct {
		name       string
		state      ports.TerminalRuntimeAvailabilityState
		obsErr     error
		nilObs     bool
		wantExit   int
		wantState  string
		wantReason string
	}{
		{name: "missing", state: ports.TerminalRuntimeMissing, wantExit: 4, wantState: "unverified", wantReason: "herdr_core_missing"},
		{name: "unsafe_identity", state: ports.TerminalRuntimeUnsafeIdentity, wantExit: 8, wantState: "unsafe", wantReason: "herdr_core_unsafe_identity"},
		{name: "observation_error", obsErr: errors.New("stat failed"), wantExit: 4, wantState: "unverified", wantReason: "herdr_core_observation_failed"},
		{name: "nil_observer", nilObs: true, wantExit: 4, wantState: "unverified", wantReason: "herdr_core_observation_failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newLocalDoctorFixture(t)
			f.terminalState = tc.state
			f.terminalErr = tc.obsErr
			if tc.nilObs {
				f.service.dependencies.TerminalRuntime = nil
			}
			result, err := f.service.DiagnoseLocal(context.Background(), f.root)
			if err != nil {
				t.Fatalf("DiagnoseLocal() err = %v", err)
			}
			if result.Readiness.ExitCode != tc.wantExit || result.Readiness.State != tc.wantState {
				t.Fatalf("readiness = %+v, want state=%s exit=%d", result.Readiness, tc.wantState, tc.wantExit)
			}
			grokRow := result.ProviderInventory[1]
			if grokRow.State != "unavailable" || grokRow.Reason != tc.wantReason {
				t.Fatalf("grok row = %+v, want unavailable/%s", grokRow, tc.wantReason)
			}
			if !reflect.DeepEqual(grokRow.BinaryAvailable.ReasonCodes, []string{tc.wantReason}) {
				t.Fatalf("grok binary reasons = %v, want [%s]", grokRow.BinaryAvailable.ReasonCodes, tc.wantReason)
			}
		})
	}
	for _, cancelErr := range []error{context.Canceled, context.DeadlineExceeded} {
		t.Run("cancel/"+cancelErr.Error(), func(t *testing.T) {
			f := newLocalDoctorFixture(t)
			f.terminalErr = cancelErr
			_, err := f.service.DiagnoseLocal(context.Background(), f.root)
			if !errors.Is(err, cancelErr) {
				t.Fatalf("DiagnoseLocal() err = %v, want %v", err, cancelErr)
			}
		})
	}
}
func TestLocalDoctorRejectsNativeHomeReplacement(t *testing.T) {
	for _, cause := range []string{"replacement", "identity error"} {
		t.Run(cause, func(t *testing.T) {
			f := newLocalDoctorFixture(t)
			f.replacement = cause == "replacement"
			if cause == "identity error" {
				f.nativeErr = map[int]error{2: errors.New("changed")}
			}
			result, err := f.service.DiagnoseLocal(context.Background(), f.root)
			if err != nil || result.Config.Status != "unsafe" || result.Config.NativeHomeIdentity != "mismatch" || len(result.ConfiguredProviderIDs) != 0 || result.Assignment != (LocalAssignmentProjection{State: "not_observed", Resilience: "not_observed"}) || !reflect.DeepEqual(f.trace, localDoctorReadyTrace) {
				t.Fatalf("rejection=%+v err=%v trace=%v", result, err, f.trace)
			}
			for _, row := range result.ProviderInventory {
				if row.State != "not_observed" || row.Reason != "config_not_ready" {
					t.Fatalf("observed rejected provider: %+v", row)
				}
			}
		})
	}
}
func TestLocalDoctorCancellationAndEffects(t *testing.T) {
	for _, call := range []int{1, 2} {
		for _, cause := range []error{context.Canceled, context.DeadlineExceeded} {
			t.Run(fmt.Sprintf("native.%d/%v", call, cause), func(t *testing.T) {
				f := newLocalDoctorFixture(t)
				f.nativeErr = map[int]error{call: cause}
				_, err := f.service.DiagnoseLocal(context.Background(), f.root)
				want := localDoctorReadyTrace
				if call == 1 {
					want = localDoctorReadyTrace[:14]
				}
				if err != cause || !reflect.DeepEqual(f.trace, want) {
					t.Fatalf("cancellation=%v trace=%v want=%v", err, f.trace, want)
				}
			})
		}
	}
}
