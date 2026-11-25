//go:build darwin && arm64

package mulgae

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

	"github.com/irootkernel/mulgae/internal/adapters/environment"
	"github.com/irootkernel/mulgae/internal/app"
	"github.com/irootkernel/mulgae/internal/app/doctor"
	"github.com/irootkernel/mulgae/internal/ports"
)

// The before JSON remains the immutable 41ad32a predecessor evidence. Q1/Q3
// use separate corrected expectations under the approved M3 decision.
type doctorBefore struct {
	Exit   app.ExitCode `json:"exit"`
	Stdout string       `json:"stdout"`
	Stderr string       `json:"stderr"`
	Trace  []string     `json:"trace"`
}

type doctorBeforeFixture struct {
	foundationFixture
	root    string
	spy     *doctorBeforeSpy
	reader  *doctorBeforeReader
	live    *heartbeatServiceStub
	reviews *reviewRunFake
}

type doctorBeforeSpy struct {
	trace                []string
	nativeCalls          int
	nativeErrors         map[int]error
	replaceNative        bool
	identityErrors       map[string]error
	missing              map[string]bool
	appVersion           string
	desktopMinimum       string
	companionFailedStage string
	versionState         ports.ProviderVersionState
	version              string
	versionErr           error
	afterVersion         func()
	discoveryErr         error
	realExecutable       bool
}

func (spy *doctorBeforeSpy) record(value string) { spy.trace = append(spy.trace, value) }

func (spy *doctorBeforeSpy) ObserveNativeHomeIdentity(_ context.Context, path string) (ports.NativeHomeLaunchAuthority, error) {
	spy.nativeCalls++
	spy.record(fmt.Sprintf("native.%d", spy.nativeCalls))
	if err := spy.nativeErrors[spy.nativeCalls]; err != nil {
		return ports.NativeHomeLaunchAuthority{}, err
	}
	inode := uint64(10)
	if spy.replaceNative && spy.nativeCalls == 2 {
		inode++
	}
	return ports.NewNativeHomeLaunchAuthority(path, 1, inode, uint32(os.Geteuid()))
}

func (spy *doctorBeforeSpy) ObserveExecutableIdentity(ctx context.Context, name string) (ports.ExecutableObservation, error) {
	spy.record("binary." + filepath.Base(name))
	if spy.realExecutable {
		return environment.NewInspector().ObserveExecutableIdentity(ctx, name)
	}
	if spy.discoveryErr != nil {
		return ports.ExecutableObservation{}, spy.discoveryErr
	}
	if err := spy.identityErrors[filepath.Base(name)]; err != nil {
		return ports.ExecutableObservation{}, err
	}
	if spy.missing[filepath.Base(name)] {
		return ports.NewExecutableObservation(name, false, "", "", "")
	}
	return ports.NewExecutableObservation(name, true, name, "", "sha256:"+strings.Repeat("a", 64))
}

func (spy *doctorBeforeSpy) ObserveExecutable(ctx context.Context, name string) (ports.ExecutableObservation, error) {
	spy.record("discover." + filepath.Base(name))
	return ports.NewExecutableObservation(name, true, name, "1.0.89", "sha256:"+strings.Repeat("a", 64))
}

func (spy *doctorBeforeSpy) ObserveReadableFileIdentity(_ context.Context, name string) (ports.FileIdentityObservation, error) {
	spy.record("file." + filepath.Base(name))
	if err := spy.identityErrors[filepath.Base(name)]; err != nil {
		return ports.FileIdentityObservation{}, err
	}
	if spy.missing[filepath.Base(name)] {
		return ports.NewFileIdentityObservation(name, false, "", "")
	}
	return ports.NewFileIdentityObservation(name, true, name, "sha256:"+strings.Repeat("a", 64))
}

func (spy *doctorBeforeSpy) ObserveZCodeCompanion(ctx context.Context, bundle string, _ ...string) (ports.ZCodeCompanionObservation, error) {
	spy.record("companion.zcode")
	if err := ctx.Err(); err != nil {
		return ports.ZCodeCompanionObservation{}, err
	}
	if err := spy.identityErrors["herdr-zcode"]; err != nil {
		return ports.ZCodeCompanionObservation{}, err
	}
	if spy.missing["herdr-zcode"] {
		return ports.ZCodeCompanionObservation{}, nil
	}
	desktop := spy.appVersion
	minimum := spy.desktopMinimum
	if minimum == "" {
		minimum = "3.18.2"
	}
	observation := ports.ZCodeCompanionObservation{
		Executable: "/synthetic/herdr-zcode", ExecutableSHA256: "sha256:" + strings.Repeat("a", 64), PackageSHA256: strings.Repeat("b", 64),
		Version: "0.2.0", AppVersion: desktop, AppBundle: bundle, BundleOverride: bundle, MinimumAppVersion: minimum,
		DesktopBelowMinimum: desktop == "4.0.0" && minimum == "4.1.0",
	}
	if spy.companionFailedStage == "" {
		return observation, nil
	}
	if spy.companionFailedStage == "version" {
		observation.Version = ""
	}
	observation.AppVersion, observation.AppBundle, observation.MinimumAppVersion = "", "", ""
	return observation, ports.NewIdentityObservationError(ports.IdentityObservationUnavailable, "test companion diagnostic failed")
}

func (spy *doctorBeforeSpy) ObservePlatform(context.Context) (ports.PlatformObservation, error) {
	spy.record("platform")
	return ports.NewPlatformObservation("darwin", "arm64")
}

func (spy *doctorBeforeSpy) ObservePermission(_ context.Context, _ ports.AnchoredRoot, path ports.SafeRelativePath) (ports.PermissionObservation, error) {
	spy.record("permission")
	return ports.NewPermissionObservation(path, true, true, true)
}

func (spy *doctorBeforeSpy) ObserveProviderVersion(_ context.Context, family string, argv []string, identity ports.ProviderVersionIdentity) (ports.ProviderVersionObservation, error) {
	spy.record("version." + family)
	if len(argv) < 2 || argv[len(argv)-1] != "--version" || identity.ExecutableSHA256 != "sha256:"+strings.Repeat("a", 64) {
		return ports.ProviderVersionObservation{}, errors.New("unexpected version authority")
	}
	if spy.afterVersion != nil {
		spy.afterVersion()
	}
	if spy.versionErr != nil {
		return ports.ProviderVersionObservation{}, spy.versionErr
	}
	return ports.NewProviderVersionObservation(spy.versionState, spy.version)
}

type doctorBeforeReader struct {
	ports.TrustedProjectReader
	spy        *doctorBeforeSpy
	attests    int
	rechecks   int
	onAttest   func()
	onRecheck  func(int)
	attestErr  error
	recheckErr map[int]error
}

type doctorBeforeEvidence struct {
	foundationEvidenceReader
	spy *doctorBeforeSpy
}

func (reader *doctorBeforeEvidence) ProviderEvidence(ctx context.Context, family string) (doctor.ProviderEvidenceRecord, error) {
	reader.spy.record("evidence." + family)
	return reader.foundationEvidenceReader.ProviderEvidence(ctx, family)
}

func (reader *doctorBeforeEvidence) PlatformEvidence(ctx context.Context, cell doctor.PlatformCell) (doctor.PlatformEvidenceRecord, error) {
	reader.spy.record("evidence.platform")
	return reader.foundationEvidenceReader.PlatformEvidence(ctx, cell)
}

func (reader *doctorBeforeEvidence) ToolsLock(ctx context.Context) (doctor.ToolsLockObservation, error) {
	reader.spy.record("evidence.tools")
	return reader.foundationEvidenceReader.ToolsLock(ctx)
}

func (reader *doctorBeforeReader) Attest(_ context.Context, request ports.ConfigLocalityRequest) (ports.ConfigLocalityContext, error) {
	reader.attests++
	reader.spy.record(fmt.Sprintf("attest.%d", reader.attests))
	if reader.attestErr != nil {
		return ports.ConfigLocalityContext{}, reader.attestErr
	}
	device, inode, uid, mode := request.Config().RootIdentity()
	result, err := ports.NewConfigLocalityContext("synthetic-before", device, inode, uid, mode, "", "", "sha256:"+strings.Repeat("b", 64), 0, false, nil, request.Config(), ports.ParsedTargetProof{SHA256: "sha256:" + strings.Repeat("c", 64), PrivatePathFree: true})
	if reader.onAttest != nil {
		reader.onAttest()
	}
	return result, err
}

func (reader *doctorBeforeReader) Revalidate(_ context.Context, _ ports.ConfigLocalityRequest, _ ports.ConfigLocalityContext) error {
	reader.rechecks++
	reader.spy.record(fmt.Sprintf("locality.%d", reader.rechecks))
	if reader.onRecheck != nil {
		reader.onRecheck(reader.rechecks)
	}
	return reader.recheckErr[reader.rechecks]
}

func newDoctorBeforeFixture(t *testing.T, families string) *doctorBeforeFixture {
	t.Helper()
	base := newFoundationFixtureWithWriter(t, newConfigFaultWriter())
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	runFoundationGit(t, root, "init", "-q")
	spy := &doctorBeforeSpy{appVersion: "4.0.0", versionState: ports.ProviderVersionObserved, version: "1.0.89"}
	reader := &doctorBeforeReader{TrustedProjectReader: base.application.projectReader, spy: spy}
	base.application.inspector, base.application.versionObserver, base.application.projectReader = spy, spy, reader
	live, reviews := &heartbeatServiceStub{}, &reviewRunFake{}
	base.application.heartbeats, base.application.reviewRuns = live, reviews
	fixture := &doctorBeforeFixture{foundationFixture: base, root: root, spy: spy, reader: reader, live: live, reviews: reviews}
	if families != "" {
		argv := []string{"init", "--providers", families, "--roles", "logic", "--output", "json"}
		for _, family := range strings.Split(families, ",") {
			if family == "zcode" {
				argv = append(argv, "--zcode-app-bundle", "/synthetic/ZCode.app")
			} else {
				argv = append(argv, "--"+family+"-executable", "/synthetic/"+family)
			}
		}
		result := base.application.Run(context.Background(), argv, root)
		if result.ExitCode() != 0 {
			t.Fatalf("synthetic init: %d %s %s", result.ExitCode(), result.Stdout(), result.Stderr())
		}
	}
	fixture.reset()
	return fixture
}

func (fixture *doctorBeforeFixture) reset() {
	fixture.spy.trace = []string{}
	fixture.spy.nativeCalls, fixture.reader.attests, fixture.reader.rechecks = 0, 0, 0
	fixture.writer.requests, fixture.writer.receipts = nil, nil
	fixture.writer.ensureCalls = 0
	faults := fixture.writer.delegate.(*configFaultWriter)
	faults.prepareCalls, faults.installCalls = 0, 0
}

func (fixture *doctorBeforeFixture) projectPath() string {
	return filepath.Join(fixture.root, ".mulgae", "config.yaml")
}

func doctorBeforeWrite(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func doctorBeforeEdit(t *testing.T, path string, edit func([]byte) []byte) {
	t.Helper()
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	after := edit(before)
	if bytes.Equal(before, after) {
		t.Fatal("characterization mutation did not change input")
	}
	doctorBeforeWrite(t, path, after)
}

func doctorBeforeReplace(t *testing.T, path string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, path+".held"); err != nil {
		t.Fatal(err)
	}
	doctorBeforeWrite(t, path, data)
}

func doctorBeforeCapture(t *testing.T, fixture *doctorBeforeFixture, ctx context.Context, argv ...string) doctorBefore {
	t.Helper()
	local, localErr := os.ReadFile(filepath.Join(fixture.root, ".mulgae", "local.yaml"))
	localDigest := fmt.Sprintf("sha256:%x", sha256.Sum256(local))
	result := fixture.application.Run(ctx, argv, fixture.root)
	faults := fixture.writer.delegate.(*configFaultWriter)
	if fixture.live.calls != 0 || fixture.reviews.calls != 0 || fixture.reviews.preflightCalls != 0 || len(fixture.writer.requests) != 0 || fixture.writer.ensureCalls != 0 || faults.prepareCalls != 0 || faults.installCalls != 0 {
		t.Fatal("inspection crossed a live/review/publication boundary")
	}
	stdout := string(result.Stdout())
	if argv[len(argv)-1] == "json" {
		assertFoundationEnvelope(t, fixture.foundationFixture, result, result.ExitCode())
	}
	if strings.Contains(stdout, `"sha256":"sha256:`) {
		var envelope struct {
			Result struct {
				Doctor *doctor.LocalDoctorResult `json:"doctor"`
			} `json:"result"`
		}
		if err := json.Unmarshal(result.Stdout(), &envelope); err != nil || envelope.Result.Doctor == nil {
			t.Fatalf("doctor identity projection: %v", err)
		}
		digest := envelope.Result.Doctor.Config.SHA256
		if localErr != nil || digest != localDigest {
			t.Fatalf("configuration identity %q does not bind admitted local bytes %q: %v", digest, localDigest, localErr)
		}
		// Only this machine-path-dependent member is normalized; field order and
		// every other byte of the command/doctor envelope remain frozen.
		stdout = strings.Replace(stdout, `"sha256":"`+digest+`"`, `"sha256":"<local-config-sha256>"`, 1)
	}
	rootJSON, err := json.Marshal(fixture.root)
	if err != nil {
		t.Fatal(err)
	}
	stdout = strings.Replace(stdout, `"project_root":`+string(rootJSON), `"project_root":"<project-root>"`, 1)
	return doctorBefore{Exit: result.ExitCode(), Stdout: stdout, Stderr: string(result.Stderr()), Trace: append([]string{}, fixture.spy.trace...)}
}

func assertDoctorBefore(t *testing.T, key string, actual doctorBefore) {
	t.Helper()
	data, err := os.ReadFile("testdata/task063-doctor-before.json")
	if err != nil {
		t.Fatal(err)
	}
	var snapshots map[string]doctorBefore
	if err := json.Unmarshal(data, &snapshots); err != nil {
		t.Fatal(err)
	}
	want, exists := snapshots[key]
	want = currentDoctorPortfolioExpectation(currentDoctorGrokMinimumExpectation(currentDoctorTransportExpectation(want)))
	if !exists || !reflect.DeepEqual(actual, want) {
		raw, _ := json.MarshalIndent(actual, "", "  ")
		t.Fatalf("predecessor %s changed (exists=%t):\n%s\nwant: %+v", key, exists, raw, want)
	}
}

func TestDoctorV7Characterization(t *testing.T) {
	type scenario struct {
		name, families string
		configure      func(*testing.T, *doctorBeforeFixture)
	}
	tests := []scenario{
		{name: "missing"},
		{name: "ready", families: "grok"},
		{name: "unsafe_root_mode", families: "grok", configure: func(t *testing.T, f *doctorBeforeFixture) {
			if err := os.Chmod(f.root, 0o777); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "empty_project", families: "grok", configure: func(t *testing.T, f *doctorBeforeFixture) {
			doctorBeforeWrite(t, f.projectPath(), nil)
		}},
		{name: "oversized_project", families: "grok", configure: func(t *testing.T, f *doctorBeforeFixture) {
			doctorBeforeWrite(t, f.projectPath(), bytes.Repeat([]byte("x"), (1<<20)+1))
		}},
		{name: "provider_timeout", families: "grok", configure: func(t *testing.T, f *doctorBeforeFixture) {
			doctorBeforeEdit(t, f.projectPath(), func(b []byte) []byte {
				return bytes.Replace(b, []byte("grok:\n"), []byte("grok:\n    timeout: nonsense\n"), 1)
			})
		}},
		{name: "local_missing", families: "grok", configure: func(t *testing.T, f *doctorBeforeFixture) {
			if err := os.Remove(filepath.Join(f.root, ".mulgae", "local.yaml")); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "invalid_yaml", families: "grok", configure: func(t *testing.T, f *doctorBeforeFixture) { doctorBeforeWrite(t, f.projectPath(), []byte("[\n")) }},
		{name: "unsupported_version", families: "grok", configure: func(t *testing.T, f *doctorBeforeFixture) {
			doctorBeforeEdit(t, f.projectPath(), func(b []byte) []byte { return bytes.Replace(b, []byte("version: 5"), []byte("version: 3"), 1) })
		}},
		{name: "local_missing_unsupported_version", families: "grok", configure: func(t *testing.T, f *doctorBeforeFixture) {
			doctorBeforeEdit(t, f.projectPath(), func(b []byte) []byte { return bytes.Replace(b, []byte("version: 5"), []byte("version: 3"), 1) })
			if err := os.Remove(filepath.Join(f.root, ".mulgae", "local.yaml")); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "credential_key", families: "grok", configure: func(t *testing.T, f *doctorBeforeFixture) {
			doctorBeforeEdit(t, f.projectPath(), func(b []byte) []byte { return append(b, []byte("api_key: redacted-do-not-emit\n")...) })
		}},
		{name: "credential_value", families: "grok", configure: func(t *testing.T, f *doctorBeforeFixture) {
			doctorBeforeEdit(t, f.projectPath(), func(b []byte) []byte { return append(b, []byte("note: 'Bearer abcdefghijklmnop'\n")...) })
		}},
		{name: "provider_identity", families: "grok", configure: func(t *testing.T, f *doctorBeforeFixture) {
			doctorBeforeEdit(t, f.projectPath(), func(b []byte) []byte { return bytes.Replace(b, []byte("grok:"), []byte("unknown:"), 1) })
		}},
		{name: "retired_provider", families: "grok", configure: func(t *testing.T, f *doctorBeforeFixture) {
			doctorBeforeEdit(t, f.projectPath(), func(b []byte) []byte { return bytes.Replace(b, []byte("grok:"), []byte("kimi:"), 1) })
		}},
		{name: "role_mapping", families: "grok", configure: func(t *testing.T, f *doctorBeforeFixture) {
			doctorBeforeEdit(t, f.projectPath(), func(b []byte) []byte {
				return bytes.Replace(b, []byte(`primary_provider: "grok"`), []byte(`primary_provider: "zcode"`), 1)
			})
		}},
		{name: "unsafe_local_mode", families: "grok", configure: func(t *testing.T, f *doctorBeforeFixture) {
			if err := os.Chmod(filepath.Join(f.root, ".mulgae", "local.yaml"), 0o644); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "unsafe_private_mode", families: "grok", configure: func(t *testing.T, f *doctorBeforeFixture) {
			if err := os.Chmod(filepath.Join(f.root, ".mulgae"), 0o755); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "unsafe_project_symlink", families: "grok", configure: func(t *testing.T, f *doctorBeforeFixture) {
			path := f.projectPath()
			if err := os.Rename(path, path+".held"); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(path+".held", path); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "unsafe_project_hardlink", families: "grok", configure: func(t *testing.T, f *doctorBeforeFixture) {
			if err := os.Link(f.projectPath(), f.projectPath()+".alias"); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "attestation_rejection", families: "grok", configure: func(_ *testing.T, f *doctorBeforeFixture) {
			f.reader.attestErr = ports.NewConfigLocalityViolation(ports.ConfigLocalityTargetPrivateNamespaceForbidden, nil)
		}},
		{name: "attestation_cancelled", families: "grok", configure: func(_ *testing.T, f *doctorBeforeFixture) { f.reader.attestErr = context.Canceled }},
		{name: "same_byte_replacement", families: "grok", configure: func(t *testing.T, f *doctorBeforeFixture) {
			f.reader.onAttest = func() { doctorBeforeReplace(t, f.projectPath()) }
		}},
		{name: "trailing_source_recheck", families: "grok", configure: func(t *testing.T, f *doctorBeforeFixture) {
			f.reader.onRecheck = func(n int) {
				if n == 1 {
					doctorBeforeReplace(t, f.projectPath())
				}
			}
		}},
		{name: "second_locality_drift", families: "grok", configure: func(_ *testing.T, f *doctorBeforeFixture) {
			f.reader.recheckErr = map[int]error{2: errors.New("injected drift")}
		}},
		{name: "first_locality_drift", families: "grok", configure: func(_ *testing.T, f *doctorBeforeFixture) {
			f.reader.recheckErr = map[int]error{1: errors.New("injected drift")}
		}},
		{name: "locality_deadline", families: "grok", configure: func(_ *testing.T, f *doctorBeforeFixture) {
			f.reader.recheckErr = map[int]error{1: context.DeadlineExceeded}
		}},
		{name: "native_account_mismatch", families: "grok", configure: func(t *testing.T, f *doctorBeforeFixture) {
			path := filepath.Join(f.root, ".mulgae", "local.yaml")
			doctorBeforeEdit(t, path, func(b []byte) []byte {
				start := bytes.Index(b, []byte("home: "))
				end := bytes.IndexByte(b[start:], '\n') + start
				return append(append(append([]byte{}, b[:start]...), []byte("home: /synthetic/foreign-home")...), b[end:]...)
			})
		}},
		{name: "same_length_config_drift", families: "grok", configure: func(t *testing.T, f *doctorBeforeFixture) {
			f.reader.onRecheck = func(n int) {
				if n == 2 {
					doctorBeforeEdit(t, f.projectPath(), func(b []byte) []byte { return bytes.Replace(b, []byte("version: 5"), []byte("version: 4"), 1) })
				}
			}
		}},
		{name: "native_first_unsafe", families: "grok", configure: func(_ *testing.T, f *doctorBeforeFixture) {
			f.spy.nativeErrors = map[int]error{1: errors.New("native identity unavailable")}
		}},
		{name: "native_first_cancelled", families: "grok", configure: func(_ *testing.T, f *doctorBeforeFixture) { f.spy.nativeErrors = map[int]error{1: context.Canceled} }},
		{name: "native_final_cancelled", families: "grok", configure: func(_ *testing.T, f *doctorBeforeFixture) {
			f.spy.nativeErrors = map[int]error{2: context.DeadlineExceeded}
		}},
		{name: "discovery_cancelled", families: "grok", configure: func(_ *testing.T, f *doctorBeforeFixture) { f.spy.discoveryErr = context.Canceled }},
		{name: "binary_missing", families: "grok", configure: func(_ *testing.T, f *doctorBeforeFixture) { f.spy.missing = map[string]bool{"grok": true} }},
		{name: "binary_unsafe", families: "grok", configure: func(_ *testing.T, f *doctorBeforeFixture) {
			f.spy.identityErrors = map[string]error{"grok": ports.NewIdentityObservationError(ports.IdentityObservationSecurity, "unsafe binary")}
		}},
		{name: "config_drift_after_version_not_rechecked", families: "grok", configure: func(t *testing.T, f *doctorBeforeFixture) {
			f.spy.afterVersion = func() { doctorBeforeReplace(t, f.projectPath()) }
		}},
	}
	for _, version := range []struct {
		name, value string
		state       ports.ProviderVersionState
	}{
		{"newer", "9.9.9", ports.ProviderVersionObserved}, {"below_minimum", "0.1.0", ports.ProviderVersionObserved}, {"malformed", "", ports.ProviderVersionMalformed}, {"timeout", "", ports.ProviderVersionTimedOut}, {"command_failed", "", ports.ProviderVersionExecutionFailed}, {"unsafe_identity", "", ports.ProviderVersionUnsafeIdentity},
	} {
		tests = append(tests, scenario{name: "version_" + version.name, families: "grok", configure: func(_ *testing.T, f *doctorBeforeFixture) {
			f.spy.version, f.spy.versionState = version.value, version.state
		}})
	}
	tests = append(tests, scenario{name: "version_observer_error", families: "grok", configure: func(_ *testing.T, f *doctorBeforeFixture) { f.spy.versionErr = context.Canceled }}, scenario{name: "version_observer_missing", families: "grok", configure: func(_ *testing.T, f *doctorBeforeFixture) { f.application.versionObserver = nil }})
	for _, test := range []struct {
		name, family, component string
		kind                    ports.IdentityObservationFailureKind
		reason                  ports.IdentityObservationFailureReason
		missing                 bool
	}{
		{name: "binary_not_executable", family: "grok", component: "grok", kind: ports.IdentityObservationUnavailable, reason: ports.IdentityObservationReasonNonExecutable},
		{name: "binary_observation_failed", family: "grok", component: "grok", kind: ports.IdentityObservationUnavailable},
	} {
		tests = append(tests, scenario{name: test.name, families: test.family, configure: func(_ *testing.T, f *doctorBeforeFixture) {
			f.spy.version = "0.16.5"
			if test.missing {
				f.spy.missing = map[string]bool{test.component: true}
			} else if test.reason != "" {
				f.spy.identityErrors = map[string]error{test.component: ports.NewIdentityObservationErrorWithReason(test.kind, test.reason, "synthetic observation failure")}
			} else {
				f.spy.identityErrors = map[string]error{test.component: ports.NewIdentityObservationError(test.kind, "synthetic observation failure")}
			}
		}})
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for _, format := range []string{"json", "human"} {
				f := newDoctorBeforeFixture(t, test.families)
				if test.configure != nil {
					test.configure(t, f)
				}
				got := doctorBeforeCapture(t, f, context.Background(), "doctor", "--output", format)
				assertDoctorBefore(t, test.name+"/"+format, got)
			}
		})
	}
}

func TestDoctorZCodeCompanionUsesObservedDesktopFloor(t *testing.T) {
	fixture := newDoctorBeforeFixture(t, "zcode")
	fixture.spy.appVersion = "4.0.0"
	fixture.spy.desktopMinimum = "4.1.0"
	root, _ := ports.NewAnchoredRoot(fixture.root)
	diagnosis, err := fixture.application.diagnoseLocalDoctor(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	row := diagnosis.ProviderInventory[0]
	if row.Reason != "zcode_application_version_below_minimum" ||
		row.ApplicationCompatible.MinimumVersion != "4.1.0" || row.ApplicationCompatible.ObservedVersion != "4.0.0" ||
		row.CLICompatible.ObservedVersion != "0.2.0" {
		t.Fatalf("companion-derived readiness = %+v", row)
	}
	if got := fixture.spy.trace; !reflect.DeepEqual(got, []string{"attest.1", "locality.1", "locality.2", "native.1", "companion.zcode", "native.2"}) {
		t.Fatalf("ZCode doctor made unexpected observations: %v", got)
	}
}

func TestDoctorZCodeRetainsVerifiedBinaryAfterDiagnosticFailure(t *testing.T) {
	for _, stage := range []string{"version", "desktop"} {
		t.Run(stage, func(t *testing.T) {
			fixture := newDoctorBeforeFixture(t, "zcode")
			fixture.spy.companionFailedStage = stage
			fixture.application.terminalRuntimeObserver = doctorTerminalRuntimeObserver{}
			root, _ := ports.NewAnchoredRoot(fixture.root)
			diagnosis, err := fixture.application.diagnoseLocalDoctor(t.Context(), root)
			if err != nil {
				t.Fatal(err)
			}
			row := diagnosis.ProviderInventory[0]
			if err := diagnosis.Validate(); err != nil {
				t.Fatalf("invalid v9 diagnosis: %v", err)
			}
			if row.State != "unavailable" || row.BinaryAvailable.Status != "verified" ||
				row.ApplicationCompatible.ReasonCode != "herdr_zcode_desktop_observation_failed" {
				t.Fatalf("independent diagnostic dimensions = %+v", row)
			}
			switch stage {
			case "version":
				if row.CLICompatible.Status != "unverifiable" || row.Reason != "herdr_zcode_cli_observation_failed" {
					t.Fatalf("unavailable companion version = %+v", row)
				}
			case "desktop":
				if row.CLICompatible.Status != "verified" || row.CLICompatible.ObservedVersion != "0.2.0" ||
					row.Reason != "herdr_zcode_desktop_observation_failed" {
					t.Fatalf("verified companion version with unavailable Desktop = %+v", row)
				}
			}
		})
	}
}

func TestDoctorProvidersConformanceCompatibility(t *testing.T) {
	testDoctorProvidersConformanceCompatibility(t)
}

func testDoctorProvidersConformanceCompatibility(t *testing.T) {
	for _, command := range []string{"doctor", "providers"} {
		for _, cause := range []string{"replacement", "identity_error"} {
			for _, format := range []string{"json", "human"} {
				f := newDoctorBeforeFixture(t, "grok")
				f.spy.replaceNative = cause == "replacement"
				if cause == "identity_error" {
					f.spy.nativeErrors = map[int]error{2: errors.New("native home changed")}
				}
				root, _ := ports.NewAnchoredRoot(f.root)
				diagnosis, err := f.application.diagnoseLocalDoctor(context.Background(), root)
				if err != nil {
					t.Fatal(err)
				}
				assertRejectedNativeHome(t, diagnosis)
				f.reset()
				got := doctorBeforeCapture(t, f, context.Background(), command, "--output", format)
				expectedTrace := []string{"attest.1", "locality.1", "locality.2", "native.1", "binary.grok", "version.grok", "native.2"}
				if command == "providers" {
					expectedTrace = append(expectedTrace, "platform", "permission")
				}
				if !reflect.DeepEqual(got.Trace, expectedTrace) {
					t.Fatalf("Q1 earlier permitted effects: %v", got.Trace)
				}
				assertDoctorCorrected(t, "q1/"+command+"/"+cause+"/"+format, got)
			}
		}
	}
}

func TestAdmissionSequenceCharacterization(t *testing.T) {
	for _, command := range []string{"init", "config", "doctor"} {
		for _, state := range []string{"missing", "ready", "cancelled", "attestation_rejected"} {
			f := newDoctorBeforeFixture(t, map[bool]string{true: "grok"}[state != "missing"])
			ctx := context.Background()
			if state == "cancelled" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if state == "attestation_rejected" {
				f.reader.attestErr = errors.New("attestation rejected")
			}
			argv := []string{command, "--output", "json"}
			if command == "init" {
				argv = append(argv, "--providers", "grok", "--grok-executable", "/synthetic/grok", "--roles", "logic")
			}
			// Successful init is the only operation in this matrix authorized to write.
			result := f.application.Run(ctx, argv, f.root)
			got := doctorBefore{Exit: result.ExitCode(), Trace: append([]string{}, f.spy.trace...)}
			assertDoctorBefore(t, "admission/"+command+"/"+state, got)
		}
	}
}

func TestProvidersCharacterization(t *testing.T) {
	for _, configured := range []bool{false, true} {
		for _, evidence := range []bool{false, true} {
			for _, include := range []bool{false, true} {
				for _, format := range []string{"json", "human"} {
					families := ""
					if configured {
						families = "grok"
					}
					f := newDoctorBeforeFixture(t, families)
					if evidence {
						f.application.evidenceReader = &doctorBeforeEvidence{spy: f.spy}
					}
					argv := []string{"providers", "--output", format}
					if include {
						argv = append(argv, "--include-unverified")
					}
					got := doctorBeforeCapture(t, f, context.Background(), argv...)
					assertDoctorBefore(t, fmt.Sprintf("providers/configured=%t/evidence=%t/include=%t/%s", configured, evidence, include, format), got)
				}
			}
		}
	}
}

// The frozen predecessor stays intact. Project only its reviewed outer
// transport marker; all payload bytes, traces, exits and human output stay exact.
func currentDoctorTransportExpectation(want doctorBefore) doctorBefore {
	historicalPrefix := `{"schema_version":"mulgae-command-result.v21",`
	if strings.HasPrefix(want.Stdout, historicalPrefix) {
		want.Stdout = `{"schema_version":"mulgae-command-result.v25",` + strings.TrimPrefix(want.Stdout, historicalPrefix)
	}
	return want
}

// Project Grok's reviewed minimum/verified_latest baseline bump (1.0.34/1.0.40 -> 1.0.89)
// without modifying the immutable predecessor fixture.
func currentDoctorGrokMinimumExpectation(want doctorBefore) doctorBefore {
	replacer := strings.NewReplacer(
		`"minimum_version":"1.0.34"`, `"minimum_version":"1.0.89"`,
		`"verified_latest":"1.0.40"`, `"verified_latest":"1.0.89"`,
		`"observed_version":"1.0.40"`, `"observed_version":"1.0.89"`,
		`cli=1.0.40`, `cli=1.0.89`,
		`version=1.0.40`, `version=1.0.89`,
	)
	want.Stdout = replacer.Replace(want.Stdout)
	return want
}

// Project Cursor, Codex, and AGY retirement from the active provider portfolio
// (doctor v7 -> v9, two-family inventory, and two static-evidence families)
// without mutating the immutable predecessor fixture.
func currentDoctorPortfolioExpectation(want doctorBefore) doctorBefore {
	replacer := strings.NewReplacer(
		`"schema_version":"mulgae-doctor-result.v7"`, `"schema_version":"mulgae-doctor-result.v9"`,
		`,{"application_compatible":{"compatibility":"not_observed","eligibility":"not_evaluated","minimum_version":"","observed_version":"","reason_code":"","status":"not_applicable","verified_latest":""},"binary_available":{"reason_codes":[],"status":"not_applicable"},"cli_compatible":{"compatibility":"not_observed","eligibility":"not_evaluated","minimum_version":"","observed_version":"","reason_code":"","status":"not_applicable","verified_latest":""},"configured":false,"family":"codex","reason":"config_not_ready","referenced_by_roles":[],"state":"not_observed"}`, ``,
		`,{"application_compatible":{"compatibility":"not_observed","eligibility":"not_evaluated","minimum_version":"","observed_version":"","reason_code":"","status":"not_applicable","verified_latest":""},"binary_available":{"reason_codes":[],"status":"not_applicable"},"cli_compatible":{"compatibility":"not_observed","eligibility":"not_evaluated","minimum_version":"","observed_version":"","reason_code":"","status":"not_applicable","verified_latest":""},"configured":false,"family":"codex","reason":"not_configured","referenced_by_roles":[],"state":"not_configured"}`, ``,
		`,{"application_compatible":{"compatibility":"not_observed","eligibility":"not_evaluated","minimum_version":"","observed_version":"","reason_code":"","status":"not_applicable","verified_latest":""},"binary_available":{"reason_codes":[],"status":"not_applicable"},"cli_compatible":{"compatibility":"not_observed","eligibility":"not_evaluated","minimum_version":"","observed_version":"","reason_code":"","status":"not_applicable","verified_latest":""},"configured":false,"family":"cursor","reason":"config_not_ready","referenced_by_roles":[],"state":"not_observed"}`, ``,
		`,{"application_compatible":{"compatibility":"not_observed","eligibility":"not_evaluated","minimum_version":"","observed_version":"","reason_code":"","status":"not_applicable","verified_latest":""},"binary_available":{"reason_codes":[],"status":"not_applicable"},"cli_compatible":{"compatibility":"not_observed","eligibility":"not_evaluated","minimum_version":"","observed_version":"","reason_code":"","status":"not_applicable","verified_latest":""},"configured":false,"family":"cursor","reason":"not_configured","referenced_by_roles":[],"state":"not_configured"}`, ``,
		`,{"application_compatible":{"compatibility":"not_observed","eligibility":"not_evaluated","minimum_version":"","observed_version":"","reason_code":"","status":"not_applicable","verified_latest":""},"binary_available":{"reason_codes":[],"status":"not_applicable"},"cli_compatible":{"compatibility":"not_observed","eligibility":"not_evaluated","minimum_version":"","observed_version":"","reason_code":"","status":"not_applicable","verified_latest":""},"configured":false,"family":"agy","reason":"config_not_ready","referenced_by_roles":[],"state":"not_observed"}`, ``,
		`,{"application_compatible":{"compatibility":"not_observed","eligibility":"not_evaluated","minimum_version":"","observed_version":"","reason_code":"","status":"not_applicable","verified_latest":""},"binary_available":{"reason_codes":[],"status":"not_applicable"},"cli_compatible":{"compatibility":"not_observed","eligibility":"not_evaluated","minimum_version":"","observed_version":"","reason_code":"","status":"not_applicable","verified_latest":""},"configured":false,"family":"agy","reason":"not_configured","referenced_by_roles":[],"state":"not_configured"}`, ``,
		"- codex: not_observed (config_not_ready)\n", "",
		"- codex: not_configured (not_configured)\n", "",
		"- cursor: not_observed (config_not_ready)\n", "",
		"- cursor: not_configured (not_configured)\n", "",
		"- agy: not_observed (config_not_ready)\n", "",
		"- agy: not_configured (not_configured)\n", "",
		"family=codex profile=codex-default support=unverified evidence=unverified assignment=intended_but_unverified\n", "",
		"family=codex profile=codex-default support=supported evidence=pass assignment=eligible evidence_uri=https://evidence.example.test/providers/authority.json evidence_sha256=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n", "",
		"family=cursor profile=cursor-default support=unverified evidence=unverified assignment=intended_but_unverified\n", "",
		"family=cursor profile=cursor-default support=supported evidence=pass assignment=eligible evidence_uri=https://evidence.example.test/providers/authority.json evidence_sha256=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n", "",
		"family=agy profile=agy-default support=unverified evidence=unverified assignment=intended_but_unverified\n", "",
		"family=agy profile=agy-default support=supported evidence=pass assignment=eligible evidence_uri=https://evidence.example.test/providers/authority.json evidence_sha256=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n", "",
		`"static_evidence_ready_provider_count":4`, `"static_evidence_ready_provider_count":2`,
	)
	want.Stdout = replacer.Replace(want.Stdout)
	if len(want.Trace) > 0 {
		filtered := make([]string, 0, len(want.Trace))
		for _, entry := range want.Trace {
			if entry == "evidence.codex" || entry == "evidence.cursor" || entry == "evidence.agy" {
				continue
			}
			filtered = append(filtered, entry)
		}
		want.Trace = filtered
	}
	return want
}

func TestDoctorTransportExpectationChangesOnlyOuterVersionPrefix(t *testing.T) {
	original := doctorBefore{Stdout: `{"schema_version":"mulgae-command-result.v21","nested":{"schema_version":"mulgae-command-result.v21"},"payload":"exact"}`, Stderr: "exact stderr", Trace: []string{"exact effect"}}
	want := original
	want.Stdout = `{"schema_version":"mulgae-command-result.v25","nested":{"schema_version":"mulgae-command-result.v21"},"payload":"exact"}`
	if got := currentDoctorTransportExpectation(original); !reflect.DeepEqual(got, want) {
		t.Fatal("version projection changed non-version evidence")
	}
	for _, text := range []string{"human output", `{"schema_version":"mulgae-command-result.v22","payload":"exact"}`, `prefix {"schema_version":"mulgae-command-result.v21",`} {
		original.Stdout = text
		if got := currentDoctorTransportExpectation(original); !reflect.DeepEqual(got, original) {
			t.Fatal("unexpected envelope/body normalized")
		}
	}
}
