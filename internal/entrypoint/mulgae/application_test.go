//go:build darwin && arm64

package mulgae

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
	"strings"
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/adapters/cli"
	adapterconfig "github.com/irootkernel/mulgae/internal/adapters/config"
	"github.com/irootkernel/mulgae/internal/adapters/environment"
	"github.com/irootkernel/mulgae/internal/adapters/filesystem"
	"github.com/irootkernel/mulgae/internal/adapters/gittarget"
	"github.com/irootkernel/mulgae/internal/adapters/jsonschema"
	"github.com/irootkernel/mulgae/internal/app"
	appconfig "github.com/irootkernel/mulgae/internal/app/config"
	appdelta "github.com/irootkernel/mulgae/internal/app/delta"
	"github.com/irootkernel/mulgae/internal/app/doctor"
	appexport "github.com/irootkernel/mulgae/internal/app/export"
	appfollowup "github.com/irootkernel/mulgae/internal/app/followup"
	appinit "github.com/irootkernel/mulgae/internal/app/init"
	appreplay "github.com/irootkernel/mulgae/internal/app/rerun"
	"github.com/irootkernel/mulgae/internal/app/review"
	"github.com/irootkernel/mulgae/internal/app/reviewrun"
	appschema "github.com/irootkernel/mulgae/internal/app/schema"
	"github.com/irootkernel/mulgae/internal/builtin"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

const (
	foundationRequestID           = "i_019f596a-cf80-7c67-b265-f37053d51ccf"
	commandSchemaID               = "https://mulgae.local/schemas/mulgae-command-result.v2.schema.json"
	foundationProviderEvidenceURI = "https://evidence.example.test/providers/authority.json"
	globalConfigAssetID           = "test:legacy-config-source"
)

type foundationFixture struct {
	application *Application
	catalog     *builtin.Catalog
	validator   *jsonschema.Validator
	writer      *receiptCapturingFoundationWriter
}

type fixedFoundationClock struct{ now time.Time }

func (clock fixedFoundationClock) Now() time.Time { return clock.now }

type fixedFoundationRequestIDs struct{}

func (fixedFoundationRequestIDs) NewRequestID(time.Time) (string, error) {
	return foundationRequestID, nil
}

type doctorIdentityInspector struct {
	delegate         ports.EnvironmentInspector
	executableErrors map[string]error
	nativeHomeErr    error
	nativeHomeErrors []error
	nativeHomeCalls  int
}

func (inspector *doctorIdentityInspector) ObservePlatform(ctx context.Context) (ports.PlatformObservation, error) {
	return inspector.delegate.ObservePlatform(ctx)
}
func (inspector *doctorIdentityInspector) ObserveExecutable(ctx context.Context, name string) (ports.ExecutableObservation, error) {
	return inspector.delegate.ObserveExecutable(ctx, name)
}
func (inspector *doctorIdentityInspector) ObserveExecutableIdentity(ctx context.Context, name string) (ports.ExecutableObservation, error) {
	if err := inspector.executableErrors[name]; err != nil {
		return ports.ExecutableObservation{}, err
	}
	return inspector.delegate.ObserveExecutableIdentity(ctx, name)
}
func (inspector *doctorIdentityInspector) ObserveReadableFileIdentity(ctx context.Context, name string) (ports.FileIdentityObservation, error) {
	return inspector.delegate.ObserveReadableFileIdentity(ctx, name)
}
func (inspector *doctorIdentityInspector) ObserveNativeHomeIdentity(ctx context.Context, path string) (ports.NativeHomeLaunchAuthority, error) {
	inspector.nativeHomeCalls++
	if inspector.nativeHomeCalls <= len(inspector.nativeHomeErrors) {
		if err := inspector.nativeHomeErrors[inspector.nativeHomeCalls-1]; err != nil {
			return ports.NativeHomeLaunchAuthority{}, err
		}
	}
	if inspector.nativeHomeErr != nil {
		return ports.NativeHomeLaunchAuthority{}, inspector.nativeHomeErr
	}
	return inspector.delegate.ObserveNativeHomeIdentity(ctx, path)
}
func (inspector *doctorIdentityInspector) ObservePermission(ctx context.Context, root ports.AnchoredRoot, path ports.SafeRelativePath) (ports.PermissionObservation, error) {
	return inspector.delegate.ObservePermission(ctx, root, path)
}

type receiptCapturingFoundationWriter struct {
	delegate    ports.SecureFileWriter
	requests    []ports.SecureWriteRequest
	receipts    []ports.SecureWriteReceipt
	afterWrite  func()
	ensureCalls int
}

func (writer *receiptCapturingFoundationWriter) EnsurePrivateDir(root ports.AnchoredRoot, directory ports.SafeRelativePath) error {
	writer.ensureCalls++
	return writer.delegate.EnsurePrivateDir(root, directory)
}

func (writer *receiptCapturingFoundationWriter) Write(ctx context.Context, request ports.SecureWriteRequest) (ports.SecureWriteReceipt, *ports.DropMetadata, error) {
	writer.requests = append(writer.requests, request)
	receipt, drop, err := writer.delegate.Write(ctx, request)
	if drop == nil && err == nil {
		writer.receipts = append(writer.receipts, receipt)
	}
	if writer.afterWrite != nil {
		writer.afterWrite()
	}
	return receipt, drop, err
}

func (writer *receiptCapturingFoundationWriter) PrepareConfigDirectory(ctx context.Context, root ports.AnchoredRoot) (ports.ConfigDirectoryReceipt, error) {
	installer, ok := writer.delegate.(ports.ConfigInstaller)
	if !ok {
		return ports.ConfigDirectoryReceipt{}, errors.New("config installer unavailable")
	}
	return installer.PrepareConfigDirectory(ctx, root)
}

func (writer *receiptCapturingFoundationWriter) InstallConfig(ctx context.Context, root ports.AnchoredRoot, prepared ports.ConfigDirectoryReceipt, data []byte) (ports.ConfigInstallReceipt, error) {
	installer, ok := writer.delegate.(ports.ConfigInstaller)
	if !ok {
		return ports.ConfigInstallReceipt{}, errors.New("config installer unavailable")
	}
	receipt, err := installer.InstallConfig(ctx, root, prepared, data)
	if writer.afterWrite != nil {
		writer.afterWrite()
	}
	return receipt, err
}

func (writer *receiptCapturingFoundationWriter) reset() {
	writer.requests = nil
	writer.receipts = nil
}

type foundationEvidenceReader struct {
	providerCalls        []string
	providerEvidenceURIs map[string]string
	platformCalls        []doctor.PlatformCell
	toolsCalls           int
}

func (reader *foundationEvidenceReader) ProviderEvidence(_ context.Context, providerID string) (doctor.ProviderEvidenceRecord, error) {
	reader.providerCalls = append(reader.providerCalls, providerID)
	probes := []doctor.ProbeObservation{
		{ID: "PV-VERSION", Status: doctor.EvidenceStatusPass},
		{ID: "PV-NONINTERACTIVE", Status: doctor.EvidenceStatusPass},
		{ID: "PV-PROMPT-TRANSPORT", Status: doctor.EvidenceStatusPass},
		{ID: "PV-JSON-ONLY", Status: doctor.EvidenceStatusPass},
		{ID: "PV-STDOUT-STDERR", Status: doctor.EvidenceStatusPass},
		{ID: "PV-CANCELLATION", Status: doctor.EvidenceStatusPass},
		{ID: "PV-OUTPUT-CAP", Status: doctor.EvidenceStatusPass},
		{ID: "PV-AUTH-CACHE-CONCURRENCY", Status: doctor.EvidenceStatusPass},
		{ID: "PV-EXIT-CLASSIFICATION", Status: doctor.EvidenceStatusPass},
		{ID: "PV-CWD-ISOLATION", Status: doctor.EvidenceStatusPass},
		{ID: "PV-ROLE-FIT-logic", Status: doctor.EvidenceStatusPass},
		{ID: "PV-ROLE-FIT-security", Status: doctor.EvidenceStatusPass},
		{ID: "PV-ROLE-FIT-maintainability", Status: doctor.EvidenceStatusPass},
		{ID: "PV-ROLE-FIT-product", Status: doctor.EvidenceStatusPass},
		{ID: "PV-ROLE-FIT-documentation", Status: doctor.EvidenceStatusPass},
		{ID: "PV-ROLE-FIT-testing", Status: doctor.EvidenceStatusPass},
	}
	uri := foundationProviderEvidenceURI
	if configuredURI, configured := reader.providerEvidenceURIs[providerID]; configured {
		uri = configuredURI
	}
	return doctor.ProviderEvidenceRecord{
		SchemaID:                "https://mulgae.local/schemas/mulgae-provider-contract-evidence.v1.schema.json",
		ProviderID:              providerID,
		URI:                     uri,
		SHA256:                  strings.Repeat("a", 64),
		Probes:                  probes,
		SecureWriterIndexStatus: doctor.EvidenceStatusPass,
		AssignmentStatus:        doctor.EvidenceStatusPass,
	}, nil
}

func (reader *foundationEvidenceReader) PlatformEvidence(_ context.Context, cell doctor.PlatformCell) (doctor.PlatformEvidenceRecord, error) {
	reader.platformCalls = append(reader.platformCalls, cell)
	return doctor.PlatformEvidenceRecord{}, errors.New("platform evidence was not injected")
}

func (reader *foundationEvidenceReader) ToolsLock(context.Context) (doctor.ToolsLockObservation, error) {
	reader.toolsCalls++
	return doctor.ToolsLockObservation{}, errors.New("tools lock was not injected")
}

type typedNilFoundationEvidenceReader struct{}

func (*typedNilFoundationEvidenceReader) ProviderEvidence(context.Context, string) (doctor.ProviderEvidenceRecord, error) {
	return doctor.ProviderEvidenceRecord{}, nil
}

func (*typedNilFoundationEvidenceReader) PlatformEvidence(context.Context, doctor.PlatformCell) (doctor.PlatformEvidenceRecord, error) {
	return doctor.PlatformEvidenceRecord{}, nil
}

func (*typedNilFoundationEvidenceReader) ToolsLock(context.Context) (doctor.ToolsLockObservation, error) {
	return doctor.ToolsLockObservation{}, nil
}

type controlledFoundationWriter struct {
	drop        *ports.DropMetadata
	writeErr    error
	abortCause  error
	invokeAbort bool
	abortCalls  int
}

type configFaultWriter struct {
	writer             ports.SecureFileWriter
	installer          ports.ConfigInstaller
	failPrepare        bool
	failInstall        bool
	prepareCalls       int
	installCalls       int
	lastPrepareReceipt ports.ConfigDirectoryReceipt
}

func newConfigFaultWriter() *configFaultWriter {
	writer := filesystem.NewSecureWriter()
	return &configFaultWriter{writer: writer, installer: writer}
}

func (writer *configFaultWriter) EnsurePrivateDir(root ports.AnchoredRoot, directory ports.SafeRelativePath) error {
	return writer.writer.EnsurePrivateDir(root, directory)
}

func (writer *configFaultWriter) Write(ctx context.Context, request ports.SecureWriteRequest) (ports.SecureWriteReceipt, *ports.DropMetadata, error) {
	return writer.writer.Write(ctx, request)
}

func (writer *configFaultWriter) PrepareConfigDirectory(ctx context.Context, root ports.AnchoredRoot) (ports.ConfigDirectoryReceipt, error) {
	writer.prepareCalls++
	receipt, err := writer.installer.PrepareConfigDirectory(ctx, root)
	writer.lastPrepareReceipt = receipt
	if err == nil && writer.failPrepare {
		writer.failPrepare = false
		return receipt, ports.NewConfigInstallError(ports.ConfigInstallStageRootSync, ports.ConfigDestinationAbsent, errors.New("injected root sync failure"))
	}
	return receipt, err
}

func (writer *configFaultWriter) InstallConfig(ctx context.Context, root ports.AnchoredRoot, prepared ports.ConfigDirectoryReceipt, data []byte) (ports.ConfigInstallReceipt, error) {
	writer.installCalls++
	receipt, err := writer.installer.InstallConfig(ctx, root, prepared, data)
	if err == nil && writer.failInstall {
		writer.failInstall = false
		return receipt, ports.NewConfigInstallError(ports.ConfigInstallStageDirectorySync, ports.ConfigDestinationPresent, errors.New("injected private directory sync failure"))
	}
	return receipt, err
}

func (writer *controlledFoundationWriter) EnsurePrivateDir(ports.AnchoredRoot, ports.SafeRelativePath) error {
	return nil
}

func (writer *controlledFoundationWriter) Write(_ context.Context, request ports.SecureWriteRequest) (ports.SecureWriteReceipt, *ports.DropMetadata, error) {
	if writer.invokeAbort {
		writer.abortCalls++
		request.Abort()(writer.abortCause)
	}
	return ports.SecureWriteReceipt{}, writer.drop, writer.writeErr
}

func TestNewApplicationRejectsMissingDependencies(t *testing.T) {
	if _, err := NewApplication(Dependencies{}); err == nil {
		t.Fatal("NewApplication accepted missing dependencies")
	}
}
func TestApplicationCommandHandlersMatchCanonicalRegistry(t *testing.T) {
	specs := cli.CommandSpecs()
	handlers := applicationCommandHandlers()

	if len(specs) != 17 {
		t.Fatalf("canonical registry has %d commands, want 17", len(specs))
	}
	if err := validateApplicationCommandHandlers(specs, handlers); err != nil {
		t.Fatalf("application handler map is not complete: %v", err)
	}
}

func TestNewApplicationRejectsIncompleteOrDriftedCommandComposition(t *testing.T) {
	tests := []struct {
		name     string
		specs    []cli.CommandSpec
		handlers map[app.CommandName]applicationCommandHandler
	}{
		{
			name:  "missing handler",
			specs: cli.CommandSpecs(),
			handlers: func() map[app.CommandName]applicationCommandHandler {
				handlers := applicationCommandHandlers()
				delete(handlers, app.CommandReview)
				return handlers
			}(),
		},
		{
			name: "registry metadata order drift",
			specs: func() []cli.CommandSpec {
				specs := cli.CommandSpecs()
				specs[0], specs[1] = specs[1], specs[0]
				return specs
			}(),
			handlers: applicationCommandHandlers(),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := newApplication(Dependencies{}, test.specs, test.handlers); err == nil {
				t.Fatal("newApplication accepted invalid command composition")
			}
		})
	}
}

func TestApplicationExecuteDispatchesEveryCanonicalCommand(t *testing.T) {
	specs := cli.CommandSpecs()
	called := make(map[app.CommandName]int, len(specs))
	handlers := make(map[app.CommandName]applicationCommandHandler, len(specs))
	for _, spec := range specs {
		command := spec.Command()
		handlers[command] = func(_ *Application, _ context.Context, invocation Invocation, _ string) execution {
			called[command]++
			if invocation.Command() != command {
				t.Fatalf("handler for %q received %q", command, invocation.Command())
			}
			return execution{}
		}
	}
	application := &Application{handlers: handlers}
	for _, spec := range specs {
		command := spec.Command()
		result := application.execute(context.Background(), Invocation{command: command}, "/canonical/root")
		if result.failure != nil {
			t.Fatalf("execute %q failed: %v", command, result.failure)
		}
	}
	for _, spec := range specs {
		if called[spec.Command()] != 1 {
			t.Fatalf("handler %q calls = %d, want 1", spec.Command(), called[spec.Command()])
		}
	}
}

func TestApplicationHelpAndUsageOutput(t *testing.T) {
	fixture := newFoundationFixture(t)
	root := testAnchoredRoot(t)
	ctx := context.Background()

	human := fixture.application.Run(ctx, nil, root)
	if human.ExitCode() != app.ExitCodeSuccess || len(human.Stderr()) != 0 {
		t.Fatalf("no-argument help result = exit %d stderr %q", human.ExitCode(), human.Stderr())
	}
	helpID := mustFoundationAssetID(t, "help:quickstart")
	_, rendered, err := fixture.catalog.Read(ctx, helpID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(human.Stdout(), expectedTextOutput(rendered)) {
		t.Fatal("no-argument help did not render the embedded help asset")
	}

	machine := fixture.application.Run(ctx, []string{"help", "security", "--output", "json"}, root)
	assertFoundationEnvelope(t, fixture, machine, app.ExitCodeSuccess)
	if len(machine.Stderr()) != 0 {
		t.Fatalf("JSON help stderr = %q, want empty", machine.Stderr())
	}
	machineOutput := machine.Stdout()
	machineOutput[0] = '!'
	if machine.Stdout()[0] == '!' {
		t.Fatal("Result.Stdout exposed mutable application-owned bytes")
	}

	malformed := fixture.application.Run(ctx, []string{"help", "unsupported-topic"}, root)
	if malformed.ExitCode() != app.ExitCodeUsage || len(malformed.Stdout()) != 0 || !bytes.Equal(malformed.Stderr(), []byte("mulgae: invalid command usage\nhint: run mulgae help workflows\n")) {
		t.Fatalf("malformed usage result = %#v", malformed)
	}
	removedRolesTopic := fixture.application.Run(ctx, []string{"help", "roles"}, root)
	if removedRolesTopic.ExitCode() != app.ExitCodeUsage || len(removedRolesTopic.Stdout()) != 0 {
		t.Fatalf("removed help roles result = %#v", removedRolesTopic)
	}

	unavailable := fixture.application.Run(ctx, []string{"review", "--dirty"}, root)
	if unavailable.ExitCode() != app.ExitCodeReadiness || len(unavailable.Stdout()) != 0 || len(unavailable.Stderr()) == 0 {
		t.Fatalf("authority-absent review result = %#v", unavailable)
	}
}

func TestResultWriteToDeliversOwnedStreams(t *testing.T) {
	result := newResult([]byte("result\n"), []byte("diagnostic\n"), app.ExitCodePolicy)
	var stdout, stderr bytes.Buffer
	if err := result.WriteTo(&stdout, &stderr); err != nil {
		t.Fatalf("WriteTo() error = %v", err)
	}
	if stdout.String() != "result\n" || stderr.String() != "diagnostic\n" || result.ExitCode() != app.ExitCodePolicy {
		t.Fatalf("delivered stdout=%q stderr=%q exit=%d", stdout.String(), stderr.String(), result.ExitCode())
	}
	if err := result.WriteTo(nil, &stderr); err == nil {
		t.Fatal("nil stdout writer accepted")
	} else {
		var writeErr *ResultWriteError
		if !errors.As(err, &writeErr) || writeErr.Stream() != ResultStreamStdout {
			t.Fatalf("nil stdout error = %v", err)
		}
	}
}

func TestApplicationRolesListsStaticInventory(t *testing.T) {
	fixture := newFoundationFixture(t)
	root := testAnchoredRoot(t)

	human := fixture.application.Run(context.Background(), []string{"roles"}, root)
	wantHuman := "Roles:\n- logic (mandatory)\n- security\n- maintainability\n- product\n- documentation\n- testing\n- artist (UI only)\n"
	if human.ExitCode() != app.ExitCodeSuccess || string(human.Stdout()) != wantHuman || len(human.Stderr()) != 0 {
		t.Fatalf("roles human result = exit %d stdout %q stderr %q", human.ExitCode(), human.Stdout(), human.Stderr())
	}

	machine := fixture.application.Run(context.Background(), []string{"roles", "--output", "json"}, root)
	assertFoundationEnvelope(t, fixture, machine, app.ExitCodeSuccess)
	var envelope struct {
		Result struct {
			Kind  string `json:"kind"`
			Roles []struct {
				ID           string `json:"id"`
				Mandatory    bool   `json:"mandatory"`
				Availability string `json:"availability"`
			} `json:"roles"`
		} `json:"result"`
	}
	if err := json.Unmarshal(machine.Stdout(), &envelope); err != nil {
		t.Fatal(err)
	}
	wantIDs := []string{"logic", "security", "maintainability", "product", "documentation", "testing", "artist"}
	if envelope.Result.Kind != "roles_listed" || len(envelope.Result.Roles) != len(wantIDs) {
		t.Fatalf("roles JSON result = %#v", envelope.Result)
	}
	for index, role := range envelope.Result.Roles {
		wantAvailability := "all_projects"
		if role.ID == "artist" {
			wantAvailability = "ui_projects"
		}
		if role.ID != wantIDs[index] || role.Mandatory != (role.ID == "logic") || role.Availability != wantAvailability {
			t.Fatalf("roles JSON row %d = %#v", index, role)
		}
	}
}

func TestApplicationRejectedInitJSONUsesInvalidRequestContract(t *testing.T) {
	fixture := newFoundationFixture(t)
	root := testAnchoredRoot(t)
	for _, test := range []struct {
		name string
		argv []string
	}{
		{name: "unknown provider", argv: []string{"init", "--providers", "other", "--output", "json"}},
		{name: "empty provider", argv: []string{"init", "--providers", "", "--output", "json"}},
		{name: "duplicate provider", argv: []string{"init", "--providers", "kimi,kimi", "--output", "json"}},
		{name: "mixed auto", argv: []string{"init", "--providers", "auto,kimi", "--output", "json"}},
		{name: "Kimi override in auto mode", argv: []string{"init", "--kimi-model", "k3", "--output", "json"}},
		{name: "absent override", argv: []string{"init", "--providers", "agy", "--kimi-model", "k3", "--output", "json"}},
		{name: "duplicate JSON output", argv: []string{"init", "--providers", "agy", "--output", "json", "--output", "json"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := fixture.application.Run(context.Background(), test.argv, root)
			assertFoundationEnvelope(t, fixture, result, app.ExitCodeUsage)
			if len(result.Stderr()) != 0 {
				t.Fatalf("rejected JSON stderr = %q, want empty", result.Stderr())
			}
			var envelope struct {
				Request struct {
					RequestID    string `json:"request_id"`
					Command      string `json:"command"`
					RequestState string `json:"request_state"`
					OutputFormat string `json:"output_format"`
				} `json:"request"`
				Reasons []struct {
					Category  string `json:"category"`
					Code      string `json:"code"`
					Message   string `json:"message"`
					Retryable bool   `json:"retryable"`
				} `json:"reasons"`
				Result appinit.InitializeProjectResult `json:"result"`
			}
			if err := json.Unmarshal(result.Stdout(), &envelope); err != nil {
				t.Fatal(err)
			}
			if envelope.Request.RequestID != foundationRequestID || envelope.Request.Command != "init" || envelope.Request.RequestState != "invalid" || envelope.Request.OutputFormat != "json" {
				t.Fatalf("rejected request = %#v", envelope.Request)
			}
			if len(envelope.Reasons) != 1 || envelope.Reasons[0].Category != "usage" || envelope.Reasons[0].Code != "init_selection_invalid" || envelope.Reasons[0].Message != "The init selection is invalid." || envelope.Reasons[0].Retryable {
				t.Fatalf("rejected reasons = %#v", envelope.Reasons)
			}
			if err := envelope.Result.Validate(); err != nil || envelope.Result.WriteState != "not_attempted" || envelope.Result.Committed || envelope.Result.DestinationState != ports.ConfigDestinationNotObserved || len(envelope.Result.SelectedProviderIDs) != 0 || len(envelope.Result.CandidateProviderIDs) != 0 || len(envelope.Result.ConfiguredProviderIDs) != 0 || len(envelope.Result.Discovery) != 0 {
				t.Fatalf("rejected result = %#v, validation = %v", envelope.Result, err)
			}
			wantRequest := `"request":{"request_id":"` + foundationRequestID + `","command":"init","request_state":"invalid","output_format":"json"}`
			if !bytes.Contains(result.Stdout(), []byte(wantRequest)) || !bytes.HasSuffix(result.Stdout(), []byte("\n")) {
				t.Fatalf("rejected envelope bytes = %q", result.Stdout())
			}
		})
	}

	for _, argv := range [][]string{
		{"init", "--providers", "other", "--output", "human"},
		{"init", "--providers", "other", "--output"},
		{"init", "--providers", "other", "--output", "json", "--output", "human"},
	} {
		result := fixture.application.Run(context.Background(), argv, root)
		if result.ExitCode() != app.ExitCodeUsage || len(result.Stdout()) != 0 || !bytes.Equal(result.Stderr(), []byte("mulgae: invalid command usage\nhint: run mulgae help workflows\n")) {
			t.Fatalf("ambiguous rejected usage = %#v", result)
		}
	}
}

func TestApplicationSchemaListShowAndExport(t *testing.T) {
	fixture := newFoundationFixture(t)
	root := testAnchoredRoot(t)
	ctx := context.Background()

	listed := fixture.application.Run(ctx, []string{"schema", "list"}, root)
	if listed.ExitCode() != app.ExitCodeSuccess || len(listed.Stderr()) != 0 {
		t.Fatalf("schema list result = exit %d stderr %q", listed.ExitCode(), listed.Stderr())
	}
	service := appschema.NewService(fixture.catalog, filesystem.NewSecureWriter())
	metadata, err := service.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var expected strings.Builder
	for _, schema := range metadata {
		expected.WriteString(schema.Source().String())
		expected.WriteByte('\n')
	}
	if !bytes.Equal(listed.Stdout(), expectedTextOutput([]byte(expected.String()))) {
		t.Fatalf("schema list = %q, want exact embedded source names", listed.Stdout())
	}

	listJSON := fixture.application.Run(ctx, []string{"schema", "list", "--output", "json"}, root)
	if listJSON.ExitCode() != app.ExitCodeUsage || len(listJSON.Stdout()) != 0 || !bytes.Equal(listJSON.Stderr(), []byte("mulgae: invalid command usage\nhint: run mulgae help workflows\n")) {
		t.Fatalf("schema list JSON result = %#v; want usage rejection without a fabricated command-result envelope", listJSON)
	}

	show := fixture.application.Run(ctx, []string{"schema", "show", commandSchemaID}, root)
	if show.ExitCode() != app.ExitCodeSuccess || len(show.Stderr()) != 0 {
		t.Fatalf("schema show result = exit %d stderr %q", show.ExitCode(), show.Stderr())
	}
	id := mustFoundationAssetID(t, commandSchemaID)
	_, raw, err := fixture.catalog.Read(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(show.Stdout(), expectedTextOutput(raw)) {
		t.Fatal("schema show did not preserve embedded schema bytes")
	}
	showJSON := fixture.application.Run(ctx, []string{"schema", "show", commandSchemaID, "--output", "json"}, root)
	assertFoundationEnvelope(t, fixture, showJSON, app.ExitCodeSuccess)

	export := fixture.application.Run(ctx, []string{"schema", "export", commandSchemaID, "contracts/result.schema.json", "--output", "json"}, root)
	assertFoundationEnvelope(t, fixture, export, app.ExitCodeSuccess)
	persisted, err := os.ReadFile(filepath.Join(root, "contracts", "result.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(persisted, raw) {
		t.Fatal("schema export bytes differ from the embedded schema")
	}
}

func TestApplicationInitCreateOnceAndJSONFailureSeparation(t *testing.T) {
	fixture := newFoundationFixture(t)
	root := testAnchoredRoot(t)
	ctx := context.Background()
	argv := []string{"init", "--providers", "agy", "--agy-executable", "/bin/sh", "--output", "json"}
	if _, ok := fixture.application.writer.(ports.ConfigInstaller); !ok {
		t.Fatal("fixture writer does not implement ConfigInstaller")
	}
	if _, ok := fixture.application.projectReader.(ports.ConfigLocalityAttestor); !ok {
		t.Fatal("fixture project reader does not implement ConfigLocalityAttestor")
	}

	first := fixture.application.Run(ctx, argv, root)
	assertFoundationEnvelope(t, fixture, first, app.ExitCodeSuccess)
	if _, err := os.Stat(filepath.Join(root, ".mulgae", "config.yaml")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, ".gitignore")); !os.IsNotExist(err) {
		t.Fatalf("init mutated .gitignore or stat failed: %v", err)
	}

	second := fixture.application.Run(ctx, argv, root)
	assertFoundationEnvelope(t, fixture, second, app.ExitCodeUsage)
	if len(second.Stderr()) != 0 || len(second.Stdout()) == 0 {
		t.Fatalf("JSON initialization failure streams = stdout %q stderr %q", second.Stdout(), second.Stderr())
	}
	var failureEnvelope struct {
		Reasons []struct {
			Category  string `json:"category"`
			Code      string `json:"code"`
			Message   string `json:"message"`
			Retryable bool   `json:"retryable"`
		} `json:"reasons"`
		Result appinit.InitializeProjectResult `json:"result"`
	}
	if err := json.Unmarshal(second.Stdout(), &failureEnvelope); err != nil {
		t.Fatal(err)
	}
	if len(failureEnvelope.Reasons) != 1 || failureEnvelope.Reasons[0].Category != "configuration" ||
		failureEnvelope.Reasons[0].Code != "init_destination_exists" ||
		failureEnvelope.Reasons[0].Message != "The project-local Mulgae configuration already exists." ||
		failureEnvelope.Reasons[0].Retryable {
		t.Fatalf("init reason = %#v", failureEnvelope.Reasons)
	}
	if failureEnvelope.Result.WriteState != "existing_untouched" || failureEnvelope.Result.DestinationState != ports.ConfigDestinationPresent || len(failureEnvelope.Result.Discovery) != 0 {
		t.Fatalf("existing init result = %#v", failureEnvelope.Result)
	}
}

func TestIntegrationApplicationInitRootBarrierFailureRetryAndDirectorySync(t *testing.T) {
	for _, test := range []struct {
		name        string
		preexisting bool
		wantState   string
		wantReason  string
		wantCreated bool
	}{
		{name: "new private directory", wantState: "private_dir_created_unconfirmed", wantReason: "init_private_dir_commit_unconfirmed", wantCreated: true},
		{name: "existing private directory", preexisting: true, wantState: "private_dir_existing_unconfirmed", wantReason: "init_existing_private_dir_commit_unconfirmed"},
	} {
		t.Run(test.name, func(t *testing.T) {
			writer := newConfigFaultWriter()
			writer.failPrepare = true
			fixture := newFoundationFixtureWithWriter(t, writer)
			root := testAnchoredRoot(t)
			if test.preexisting {
				if err := os.Mkdir(filepath.Join(root, ".mulgae"), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			argv := []string{"init", "--providers", "agy", "--agy-executable", "/bin/sh", "--output", "json"}
			failed := fixture.application.Run(context.Background(), argv, root)
			assertFoundationEnvelope(t, fixture, failed, app.ExitCodeArtifact)
			var envelope struct {
				Reasons []struct {
					Code string `json:"code"`
				} `json:"reasons"`
				Result appinit.InitializeProjectResult `json:"result"`
			}
			if err := json.Unmarshal(failed.Stdout(), &envelope); err != nil {
				t.Fatal(err)
			}
			if len(envelope.Reasons) != 1 || envelope.Reasons[0].Code != test.wantReason || envelope.Result.WriteState != test.wantState || envelope.Result.DestinationState != ports.ConfigDestinationAbsent || envelope.Result.Committed || writer.installCalls != 0 || writer.prepareCalls != 1 || writer.lastPrepareReceipt.CreatedByInvocation() != test.wantCreated {
				t.Fatalf("root barrier failure = reasons %#v result %#v prepare=%d install=%d created=%t", envelope.Reasons, envelope.Result, writer.prepareCalls, writer.installCalls, writer.lastPrepareReceipt.CreatedByInvocation())
			}
			entries, err := os.ReadDir(filepath.Join(root, ".mulgae"))
			if err != nil || len(entries) != 0 {
				t.Fatalf("root barrier failure left config or temp entries: %v err=%v", entries, err)
			}

			retried := fixture.application.Run(context.Background(), argv, root)
			assertFoundationEnvelope(t, fixture, retried, app.ExitCodeSuccess)
			if writer.prepareCalls != 2 || writer.installCalls != 1 {
				t.Fatalf("retry barriers = prepare %d install %d", writer.prepareCalls, writer.installCalls)
			}
			if _, err := os.Stat(filepath.Join(root, ".mulgae", "config.yaml")); err != nil {
				t.Fatalf("retry did not commit config: %v", err)
			}
		})
	}

	t.Run("private directory sync remains installed unconfirmed", func(t *testing.T) {
		writer := newConfigFaultWriter()
		writer.failInstall = true
		fixture := newFoundationFixtureWithWriter(t, writer)
		root := testAnchoredRoot(t)
		result := fixture.application.Run(context.Background(), []string{"init", "--providers", "agy", "--agy-executable", "/bin/sh", "--output", "json"}, root)
		assertFoundationEnvelope(t, fixture, result, app.ExitCodeArtifact)
		var envelope struct {
			Reasons []struct {
				Code string `json:"code"`
			} `json:"reasons"`
			Result appinit.InitializeProjectResult `json:"result"`
		}
		if err := json.Unmarshal(result.Stdout(), &envelope); err != nil {
			t.Fatal(err)
		}
		if len(envelope.Reasons) != 1 || envelope.Reasons[0].Code != "init_commit_unconfirmed" || envelope.Result.WriteState != "installed_unconfirmed" || envelope.Result.DestinationState != ports.ConfigDestinationPresent || envelope.Result.Committed || writer.installCalls != 1 {
			t.Fatalf("directory sync failure = reasons %#v result %#v", envelope.Reasons, envelope.Result)
		}
		if _, err := os.Stat(filepath.Join(root, ".mulgae", "config.yaml")); err != nil {
			t.Fatalf("installed-unconfirmed config was removed: %v", err)
		}
	})
}

func TestApplicationInitAndDoctorPreserveExactPrivateTargetReason(t *testing.T) {
	for _, test := range []struct {
		name   string
		reason string
		setup  func(*testing.T, foundationFixture, string)
	}{
		{
			name:   "exact config",
			reason: string(ports.ConfigLocalityTargetPrivateConfigForbidden),
			setup: func(t *testing.T, _ foundationFixture, root string) {
				if err := os.Mkdir(filepath.Join(root, ".mulgae"), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(root, ".mulgae", "config.yaml"), []byte("version: 1\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				runFoundationGit(t, root, "add", "-f", ".mulgae/config.yaml")
			},
		},
		{
			name:   "private namespace",
			reason: string(ports.ConfigLocalityTargetPrivateNamespaceForbidden),
			setup: func(t *testing.T, fixture foundationFixture, root string) {
				initialized := fixture.application.Run(context.Background(), []string{"init", "--providers", "agy", "--agy-executable", "/bin/sh", "--output", "json"}, root)
				assertFoundationEnvelope(t, fixture, initialized, app.ExitCodeSuccess)
				cache := filepath.Join(root, ".mulgae", "cache")
				if err := os.Mkdir(cache, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(cache, "do-not-leak-private-entry"), []byte("private\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				runFoundationGit(t, root, "add", "-f", ".mulgae/cache/do-not-leak-private-entry")
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newFoundationFixture(t)
			root := testAnchoredRoot(t)
			test.setup(t, fixture, root)

			initialized := fixture.application.Run(context.Background(), []string{"init", "--providers", "agy", "--agy-executable", "/bin/sh", "--output", "json"}, root)
			assertFoundationEnvelope(t, fixture, initialized, app.ExitCodeSecurity)
			var initEnvelope struct {
				Reasons []struct {
					Code string `json:"code"`
				} `json:"reasons"`
			}
			if err := json.Unmarshal(initialized.Stdout(), &initEnvelope); err != nil {
				t.Fatal(err)
			}
			if len(initEnvelope.Reasons) != 1 || initEnvelope.Reasons[0].Code != test.reason {
				t.Fatalf("init reasons = %#v, want %q", initEnvelope.Reasons, test.reason)
			}

			diagnosed := fixture.application.Run(context.Background(), []string{"doctor", "--output", "json"}, root)
			assertFoundationEnvelope(t, fixture, diagnosed, app.ExitCodeSecurity)
			var doctorEnvelope struct {
				Result struct {
					Doctor *doctor.LocalDoctorResult `json:"doctor"`
				} `json:"result"`
			}
			if err := json.Unmarshal(diagnosed.Stdout(), &doctorEnvelope); err != nil {
				t.Fatal(err)
			}
			if doctorEnvelope.Result.Doctor == nil || !reflect.DeepEqual(doctorEnvelope.Result.Doctor.Config.ReasonCodes, []string{test.reason}) || !reflect.DeepEqual(doctorEnvelope.Result.Doctor.Readiness.ReasonCodes, []string{test.reason}) || len(doctorEnvelope.Result.Doctor.Diagnostics) != 1 || doctorEnvelope.Result.Doctor.Diagnostics[0].Code != test.reason {
				t.Fatalf("doctor exact locality projection = %#v, want %q", doctorEnvelope.Result.Doctor, test.reason)
			}
			if bytes.Contains(initialized.Stdout(), []byte("do-not-leak-private-entry")) || bytes.Contains(diagnosed.Stdout(), []byte("do-not-leak-private-entry")) {
				t.Fatal("private target path leaked into command output")
			}
		})
	}
}

func TestApplicationPreservesCommittedSuccessWhenContextCancelsAfterWrite(t *testing.T) {
	fixture := newFoundationFixture(t)
	root := testAnchoredRoot(t)
	ctx, cancel := context.WithCancel(context.Background())
	fixture.writer.afterWrite = cancel

	result := fixture.application.Run(ctx, []string{"init", "--providers", "agy", "--agy-executable", "/bin/sh", "--output", "json"}, root)
	assertFoundationEnvelope(t, fixture, result, app.ExitCodeSecurity)
	if _, err := os.Stat(filepath.Join(root, ".mulgae", "config.yaml")); err != nil {
		t.Fatalf("committed config is absent: %v", err)
	}
}

func TestApplicationConfigNoProjectAndCommittedProject(t *testing.T) {
	fixture := newFoundationFixture(t)
	ctx := context.Background()
	projectRoot := testAnchoredRoot(t)
	initialized := fixture.application.Run(ctx, []string{"init", "--name", "project", "--providers", "agy", "--agy-executable", "/bin/sh"}, projectRoot)
	if initialized.ExitCode() != app.ExitCodeSuccess {
		t.Fatalf("initialization = exit %d stdout %q stderr %q", initialized.ExitCode(), initialized.Stdout(), initialized.Stderr())
	}
	withProject := fixture.application.Run(ctx, []string{"config", "--mode", "provenance"}, projectRoot)
	if withProject.ExitCode() != app.ExitCodeSuccess {
		t.Fatalf("local configuration = exit %d stdout %q stderr %q", withProject.ExitCode(), withProject.Stdout(), withProject.Stderr())
	}
	var document struct {
		Mode       string                    `json:"mode"`
		ConfigURI  string                    `json:"config_uri"`
		Provenance []appconfig.ProvenanceRow `json:"provenance"`
	}
	if err := json.Unmarshal(withProject.Stdout(), &document); err != nil {
		t.Fatal(err)
	}
	if document.Mode != "provenance" || document.ConfigURI != ".mulgae/config.yaml" || len(document.Provenance) == 0 {
		t.Fatalf("local configuration provenance = %#v", document)
	}
}

func TestAdmitConfiguredNativeAccount(t *testing.T) {
	wantHome := "/Users/example"
	for _, test := range []struct {
		name       string
		configured string
		installed  *user.User
		lookupErr  error
		euid       int
		wantErr    bool
	}{
		{name: "matching", configured: wantHome, installed: &user.User{Uid: "501", HomeDir: wantHome}, euid: 501},
		{name: "lookup unavailable", configured: wantHome, lookupErr: errors.New("unavailable"), euid: 501, wantErr: true},
		{name: "missing account", configured: wantHome, euid: 501, wantErr: true},
		{name: "invalid uid", configured: wantHome, installed: &user.User{Uid: "invalid", HomeDir: wantHome}, euid: 501, wantErr: true},
		{name: "uid mismatch", configured: wantHome, installed: &user.User{Uid: "502", HomeDir: wantHome}, euid: 501, wantErr: true},
		{name: "home mismatch", configured: "/Users/other", installed: &user.User{Uid: "501", HomeDir: wantHome}, euid: 501, wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			home, uid, err := admitConfiguredNativeAccount(test.configured, test.installed, test.lookupErr, test.euid)
			if (err != nil) != test.wantErr {
				t.Fatalf("admission error = %v, wantErr %t", err, test.wantErr)
			}
			if !test.wantErr && (home != wantHome || uid != 501) {
				t.Fatalf("admission = %q/%d", home, uid)
			}
		})
	}
}

func TestApplicationConfigRejectsNativeAccountAndIdentityMismatch(t *testing.T) {
	fixture := newFoundationFixture(t)
	ctx := context.Background()
	root := testAnchoredRoot(t)
	initialized := fixture.application.Run(ctx, []string{"init", "--providers", "agy", "--agy-executable", "/bin/sh", "--output", "json"}, root)
	assertFoundationEnvelope(t, fixture, initialized, app.ExitCodeSuccess)

	configPath := filepath.Join(root, ".mulgae", "config.yaml")
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	codec := adapterconfig.YAMLCodec{}
	config, err := codec.Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	config.NativeUser.Home = filepath.Join(t.TempDir(), "different-native-home")
	data, err = codec.EncodeCanonical(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, data, 0o600); err != nil {
		t.Fatal(err)
	}

	mismatch := fixture.application.Run(ctx, []string{"config", "--output", "json"}, root)
	assertFoundationEnvelope(t, fixture, mismatch, app.ExitCodeReadiness)
	var mismatchEnvelope struct {
		Reasons []struct {
			Code string `json:"code"`
		} `json:"reasons"`
		Result struct {
			Kind         string `json:"kind"`
			ConfigSHA256 string `json:"config_sha256"`
		} `json:"result"`
	}
	if err := json.Unmarshal(mismatch.Stdout(), &mismatchEnvelope); err != nil {
		t.Fatal(err)
	}
	if len(mismatchEnvelope.Reasons) != 1 || mismatchEnvelope.Reasons[0].Code != "provider_unavailable" || mismatchEnvelope.Result.Kind != "configuration_failed" || mismatchEnvelope.Result.ConfigSHA256 != "" {
		t.Fatalf("native account mismatch = %#v", mismatchEnvelope)
	}

	installed, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	config.NativeUser.Home = installed.HomeDir
	data, err = codec.EncodeCanonical(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	fixture.application.inspector = &doctorIdentityInspector{delegate: fixture.application.inspector, nativeHomeErr: ports.NewIdentityObservationError(ports.IdentityObservationSecurity, "native home identity changed")}
	unsafe := fixture.application.Run(ctx, []string{"config", "--output", "json"}, root)
	assertFoundationEnvelope(t, fixture, unsafe, app.ExitCodeSecurity)
}

func TestApplicationNativeHomeCancellationUsesExitNine(t *testing.T) {
	tests := []struct {
		name    string
		command string
		failAt  int
		cause   error
	}{
		{name: "init first observation cancelled", command: "init", failAt: 1, cause: context.Canceled},
		{name: "init revalidation deadline", command: "init", failAt: 2, cause: context.DeadlineExceeded},
		{name: "config first observation cancelled", command: "config", failAt: 1, cause: context.Canceled},
		{name: "config revalidation deadline", command: "config", failAt: 2, cause: context.DeadlineExceeded},
		{name: "doctor first observation cancelled", command: "doctor", failAt: 1, cause: context.Canceled},
		{name: "doctor revalidation deadline", command: "doctor", failAt: 2, cause: context.DeadlineExceeded},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newFoundationFixture(t)
			root := testAnchoredRoot(t)
			if test.command != "init" {
				initialized := fixture.application.Run(context.Background(), []string{"init", "--providers", "agy", "--agy-executable", "/bin/sh", "--output", "json"}, root)
				assertFoundationEnvelope(t, fixture, initialized, app.ExitCodeSuccess)
			}
			errorsByCall := make([]error, test.failAt)
			errorsByCall[test.failAt-1] = test.cause
			fixture.application.inspector = &doctorIdentityInspector{delegate: fixture.application.inspector, nativeHomeErrors: errorsByCall}
			argv := []string{test.command, "--output", "json"}
			if test.command == "init" {
				argv = []string{"init", "--providers", "agy", "--agy-executable", "/bin/sh", "--output", "json"}
			}
			result := fixture.application.Run(context.Background(), argv, root)
			assertFoundationEnvelope(t, fixture, result, app.ExitCodeCancellation)
			if len(result.Stderr()) != 0 {
				t.Fatalf("cancellation stderr = %q", result.Stderr())
			}
			var envelope struct {
				Exit struct {
					Code int    `json:"code"`
					Kind string `json:"kind"`
				} `json:"exit"`
				Reasons []struct {
					Category  string `json:"category"`
					Code      string `json:"code"`
					Message   string `json:"message"`
					Retryable bool   `json:"retryable"`
				} `json:"reasons"`
				Result json.RawMessage `json:"result"`
			}
			if err := json.Unmarshal(result.Stdout(), &envelope); err != nil {
				t.Fatal(err)
			}
			if len(envelope.Reasons) != 1 {
				t.Fatalf("cancellation envelope = %#v", envelope)
			}
			specificCancellation := envelope.Reasons[0].Message == "The command was cancelled."
			actionableFallback := strings.Contains(envelope.Reasons[0].Message, "stage cli."+test.command) &&
				strings.Contains(envelope.Reasons[0].Message, "code request_cancelled") &&
				strings.Contains(envelope.Reasons[0].Message, "hint: retry the command when ready")
			if envelope.Exit.Code != 9 || envelope.Exit.Kind != "cancellation" || envelope.Reasons[0].Category != "cancellation" || envelope.Reasons[0].Code != "request_cancelled" ||
				(!specificCancellation && !actionableFallback) || envelope.Reasons[0].Retryable {
				t.Fatalf("cancellation envelope = %#v", envelope)
			}
			switch test.command {
			case "init":
				var projection appinit.InitializeProjectResult
				if err := json.Unmarshal(envelope.Result, &projection); err != nil || projection.WriteState != "not_attempted" || projection.DestinationState != ports.ConfigDestinationAbsent || projection.Committed || projection.ConfigSHA256 != "" || !reflect.DeepEqual(projection.SelectedProviderIDs, []string{"agy"}) || len(projection.CandidateProviderIDs) != 0 || len(projection.ConfiguredProviderIDs) != 0 || len(projection.Discovery) != 0 {
					t.Fatalf("cancelled init projection = %#v err=%v", projection, err)
				}
				if _, err := os.Lstat(filepath.Join(root, ".mulgae")); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("cancelled init mutated private directory: %v", err)
				}
			case "config":
				var projection struct {
					Kind         string `json:"kind"`
					ConfigSHA256 string `json:"config_sha256"`
				}
				if err := json.Unmarshal(envelope.Result, &projection); err != nil || projection.Kind != "configuration_failed" || projection.ConfigSHA256 != "" {
					t.Fatalf("cancelled config projection = %#v err=%v", projection, err)
				}
			case "doctor":
				var projection struct {
					Doctor    any    `json:"doctor"`
					Readiness string `json:"readiness"`
				}
				if err := json.Unmarshal(envelope.Result, &projection); err != nil || projection.Doctor != nil || projection.Readiness != "unverified" {
					t.Fatalf("cancelled doctor projection = %#v err=%v", projection, err)
				}
			}
		})
	}
}

func TestApplicationNativeHomeCancellationHumanOutput(t *testing.T) {
	for _, command := range []string{"init", "config", "doctor"} {
		t.Run(command, func(t *testing.T) {
			fixture := newFoundationFixture(t)
			root := testAnchoredRoot(t)
			if command != "init" {
				initialized := fixture.application.Run(context.Background(), []string{"init", "--providers", "agy", "--agy-executable", "/bin/sh", "--output", "json"}, root)
				assertFoundationEnvelope(t, fixture, initialized, app.ExitCodeSuccess)
			}
			fixture.application.inspector = &doctorIdentityInspector{delegate: fixture.application.inspector, nativeHomeErr: context.Canceled}
			argv := []string{command}
			if command == "init" {
				argv = []string{"init", "--providers", "agy", "--agy-executable", "/bin/sh"}
			}
			result := fixture.application.Run(context.Background(), argv, root)
			want := "mulgae: request was cancelled\ncode: request_cancelled\nstage: cli." + command + "\nhint: retry the command when ready\n"
			if result.ExitCode() != app.ExitCodeCancellation || len(result.Stdout()) != 0 || string(result.Stderr()) != want {
				t.Fatalf("human cancellation = exit %d stdout %q stderr %q", result.ExitCode(), result.Stdout(), result.Stderr())
			}
		})
	}
}

func TestApplicationHelpRemainsRepositoryIndependent(t *testing.T) {
	fixture := newFoundationFixture(t)
	for _, test := range []struct {
		name   string
		unborn bool
	}{{name: "non-git"}, {name: "unborn", unborn: true}} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.Chmod(root, 0o700); err != nil {
				t.Fatal(err)
			}
			if test.unborn {
				command := exec.Command("/usr/bin/git", "init", "--quiet")
				command.Dir = root
				if output, err := command.CombinedOutput(); err != nil {
					t.Fatalf("git init: %v: %s", err, output)
				}
			}
			result := fixture.application.Run(context.Background(), []string{"help"}, root)
			if result.ExitCode() != app.ExitCodeSuccess || len(result.Stdout()) == 0 || len(result.Stderr()) != 0 {
				t.Fatalf("help = exit %d stdout=%q stderr=%q", result.ExitCode(), result.Stdout(), result.Stderr())
			}
		})
	}
}
func TestPersistJSONFailsClosedOnInconsistentAbortCallback(t *testing.T) {
	abortCause := errors.New("writer signaled abort")
	writer := &controlledFoundationWriter{
		abortCause:  abortCause,
		invokeAbort: true,
	}
	fixture := newFoundationFixtureWithWriter(t, writer)
	root := testAnchoredRoot(t)
	anchoredRoot, err := ports.NewAnchoredRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	directory, err := ports.NewSafeRelativePath(".mulgae/config")
	if err != nil {
		t.Fatal(err)
	}
	destination, err := ports.NewSafeRelativePath(".mulgae/config/callback.json")
	if err != nil {
		t.Fatal(err)
	}

	_, err = fixture.application.persistJSON(context.Background(), anchoredRoot, directory, destination, "config_resolution", []string{globalConfigAssetID, "config:resolved-policy:v1"}, []byte(`{"policy":true}`))
	var failure *domain.Failure
	if !errors.As(err, &failure) || failure.Class() != domain.FailureInternal || !errors.Is(err, abortCause) {
		t.Fatalf("callback-only write failure = %v, want internal failure wrapping abort cause", err)
	}
	if writer.abortCalls != 1 {
		t.Fatalf("abort calls = %d, want 1", writer.abortCalls)
	}

	result := fixture.application.Run(context.Background(), []string{"config", "--output", "json"}, root)
	assertFoundationEnvelope(t, fixture, result, app.ExitCodeUsage)
}

func TestPersistJSONClassifiesReturnedSecureWriterRejection(t *testing.T) {
	writeErr := errors.New("writer rejected output")
	drop, err := ports.NewDropMetadata("config_resolution", "test_rejection", 1, []string{globalConfigAssetID, "config:resolved-policy:v1"})
	if err != nil {
		t.Fatal(err)
	}
	writer := &controlledFoundationWriter{
		drop:        &drop,
		writeErr:    writeErr,
		abortCause:  errors.New("writer stopped producer"),
		invokeAbort: true,
	}
	fixture := newFoundationFixtureWithWriter(t, writer)
	root := testAnchoredRoot(t)
	anchoredRoot, err := ports.NewAnchoredRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	directory, err := ports.NewSafeRelativePath(".mulgae/config")
	if err != nil {
		t.Fatal(err)
	}
	destination, err := ports.NewSafeRelativePath(".mulgae/config/rejected.json")
	if err != nil {
		t.Fatal(err)
	}

	_, err = fixture.application.persistJSON(context.Background(), anchoredRoot, directory, destination, "config_resolution", []string{globalConfigAssetID, "config:resolved-policy:v1"}, []byte(`{"policy":true}`))
	var failure *domain.Failure
	if !errors.As(err, &failure) || failure.Class() != domain.FailureSecurityPolicy || !errors.Is(err, writeErr) {
		t.Fatalf("returned rejection failure = %v, want security failure wrapping writer error", err)
	}
	if writer.abortCalls != 1 {
		t.Fatalf("abort calls = %d, want 1", writer.abortCalls)
	}
}

func TestApplicationProjectsFailuresToSamePermittedExitsInHumanAndJSON(t *testing.T) {
	fixture := newFoundationFixture(t)
	root := testAnchoredRoot(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	tests := []struct {
		name string
		argv []string
		exit app.ExitCode
	}{
		{name: "help", argv: []string{"help", "security"}, exit: app.ExitCodeUsage},
		{name: "init", argv: []string{"init"}, exit: app.ExitCodeCancellation},
		{name: "doctor", argv: []string{"doctor"}, exit: app.ExitCodeCancellation},
		{name: "config", argv: []string{"config"}, exit: app.ExitCodeCancellation},
		{name: "schema", argv: []string{"schema", "show", commandSchemaID}, exit: app.ExitCodeArtifact},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			jsonArgs := append(append([]string(nil), test.argv...), "--output", "json")
			jsonResult := fixture.application.Run(ctx, jsonArgs, root)
			assertFoundationEnvelope(t, fixture, jsonResult, test.exit)
			if len(jsonResult.Stderr()) != 0 {
				t.Fatalf("JSON failure stderr = %q, want empty", jsonResult.Stderr())
			}

			humanResult := fixture.application.Run(ctx, test.argv, root)
			if humanResult.ExitCode() != test.exit || len(humanResult.Stdout()) != 0 || len(humanResult.Stderr()) == 0 {
				t.Fatalf("human failure = exit %d stdout %q stderr %q, want exit %d and stderr only", humanResult.ExitCode(), humanResult.Stdout(), humanResult.Stderr(), test.exit)
			}
		})
	}
}

func TestLocalDoctorHumanOutputIsANSIFreeAndUsesFixedInventory(t *testing.T) {
	diagnosis := doctor.LocalDoctorResult{
		Readiness: doctor.LocalReadiness{State: "degraded", ExitCode: 0},
		ProviderInventory: []doctor.LocalProviderInventoryRow{
			{Family: "kimi", State: "eligible", Reason: "identity_admitted"},
			{Family: "zcode", State: "not_configured", Reason: "not_configured"},
			{Family: "agy", State: "not_configured", Reason: "not_configured"},
		},
	}
	output := string(localDoctorHumanOutput(diagnosis))
	if strings.Contains(output, "\x1b[") || strings.Count(output, "- ") != 3 {
		t.Fatalf("doctor human output = %q, want ANSI-free fixed inventory", output)
	}
}

func TestLocalProviderAdmissionRequiresCompletePassAndFlagsSecurityFailure(t *testing.T) {
	reader := &foundationEvidenceReader{}
	evidence, err := reader.ProviderEvidence(context.Background(), "kimi")
	if err != nil {
		t.Fatal(err)
	}
	if admitted, unsafe := localProviderAdmission(evidence, "kimi"); !admitted || unsafe {
		t.Fatalf("complete provider evidence = admitted %t unsafe %t", admitted, unsafe)
	}
	evidence.Probes[3].Status = doctor.EvidenceStatusNotRun
	if admitted, unsafe := localProviderAdmission(evidence, "kimi"); admitted || unsafe {
		t.Fatalf("incomplete provider evidence = admitted %t unsafe %t", admitted, unsafe)
	}
	evidence.Probes[3].Status = doctor.EvidenceStatusPass
	evidence.Probes[9].Status = doctor.EvidenceStatusFail
	if admitted, unsafe := localProviderAdmission(evidence, "kimi"); admitted || !unsafe {
		t.Fatalf("security-failed provider evidence = admitted %t unsafe %t", admitted, unsafe)
	}
}

func TestApplicationDoctorReturnsInlineValidatedUnverifiedResult(t *testing.T) {
	fixture := newFoundationFixture(t)
	root := testAnchoredRoot(t)
	result := fixture.application.Run(context.Background(), []string{"doctor", "--output", "json"}, root)
	assertFoundationEnvelope(t, fixture, result, app.ExitCodeReadiness)
	if len(result.Stderr()) != 0 {
		t.Fatalf("doctor JSON stderr = %q, want empty", result.Stderr())
	}
	if strings.Contains(string(result.Stdout()), "\x1b[") {
		t.Fatalf("doctor JSON stdout contains ANSI color: %q", result.Stdout())
	}
	human := fixture.application.Run(context.Background(), []string{"doctor"}, root)
	if human.ExitCode() != app.ExitCodeReadiness {
		t.Fatalf("doctor human exit = %d, want %d", human.ExitCode(), app.ExitCodeReadiness)
	}
	if strings.Contains(string(human.Stdout()), "\x1b[") {
		t.Fatalf("doctor human stdout contains ANSI colors: %q", human.Stdout())
	}
	if len(human.Stderr()) != 0 {
		t.Fatalf("doctor human stderr = %q, want empty", human.Stderr())
	}
	if !strings.Contains(string(human.Stdout()), "Readiness: unverified\nConfiguration: missing\nProviders:\n") {
		t.Fatalf("doctor human stdout omitted readiness and provider heading: %q", human.Stdout())
	}

	var envelope struct {
		Reasons []struct {
			Code string `json:"code"`
		} `json:"reasons"`
		Result struct {
			DoctorResultURI *string                   `json:"doctor_result_uri"`
			Doctor          *doctor.LocalDoctorResult `json:"doctor"`
		} `json:"result"`
	}
	if err := json.Unmarshal(result.Stdout(), &envelope); err != nil {
		t.Fatal(err)
	}
	if len(envelope.Reasons) != 1 || envelope.Reasons[0].Code != "readiness_unverified" ||
		envelope.Result.DoctorResultURI != nil || envelope.Result.Doctor == nil {
		t.Fatalf("doctor result = %#v, want inline artifact and null URI", envelope.Result)
	}
	contents, err := json.Marshal(envelope.Result.Doctor)
	if err != nil {
		t.Fatal(err)
	}
	doctorSchema := mustFoundationAssetID(t, doctorResultSchema)
	if err := fixture.validator.Validate(context.Background(), doctorSchema, contents); err != nil {
		t.Fatalf("persisted doctor result is not schema-valid: %v", err)
	}
}

func TestApplicationDoctorClassifiesCredentialAdmissionAsSecurity(t *testing.T) {
	for _, test := range []struct {
		name, injected, reason, secret string
	}{
		{name: "credential key", injected: "api_key: redacted-do-not-emit\n", reason: "config_credential_key_detected", secret: "redacted-do-not-emit"},
		{name: "credential value", injected: "note: \"Bearer abcdefghijklmnop\"\n", reason: "config_credential_value_detected", secret: "abcdefghijklmnop"},
	} {
		t.Run(test.name, func(t *testing.T) {
			evidence := &foundationEvidenceReader{}
			fixture := newFoundationFixtureWithEvidence(t, evidence)
			root := testAnchoredRoot(t)
			initialized := fixture.application.Run(context.Background(), []string{"init", "--providers", "agy", "--agy-executable", "/bin/sh", "--output", "json"}, root)
			assertFoundationEnvelope(t, fixture, initialized, app.ExitCodeSuccess)

			configPath := filepath.Join(root, ".mulgae", "config.yaml")
			contents, err := os.ReadFile(configPath)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(configPath, append(contents, []byte(test.injected)...), 0o600); err != nil {
				t.Fatal(err)
			}

			result := fixture.application.Run(context.Background(), []string{"doctor", "--output", "json"}, root)
			assertFoundationEnvelope(t, fixture, result, app.ExitCodeSecurity)
			if bytes.Contains(result.Stdout(), []byte(test.secret)) {
				t.Fatalf("doctor leaked rejected credential material: %q", result.Stdout())
			}
			var envelope struct {
				Reasons []struct {
					Code string `json:"code"`
				} `json:"reasons"`
				Result struct {
					Doctor *doctor.LocalDoctorResult `json:"doctor"`
				} `json:"result"`
			}
			if err := json.Unmarshal(result.Stdout(), &envelope); err != nil {
				t.Fatal(err)
			}
			if len(envelope.Reasons) != 1 || envelope.Reasons[0].Code != "security_rejected" || envelope.Result.Doctor == nil ||
				envelope.Result.Doctor.Config.Status != "unsafe" || envelope.Result.Doctor.Config.Locality != "verified" ||
				!reflect.DeepEqual(envelope.Result.Doctor.Config.ReasonCodes, []string{test.reason}) ||
				envelope.Result.Doctor.Readiness.State != "unsafe" || envelope.Result.Doctor.Readiness.ExitCode != int(app.ExitCodeSecurity) ||
				!reflect.DeepEqual(envelope.Result.Doctor.Readiness.ReasonCodes, []string{test.reason}) || len(evidence.providerCalls) != 0 {
				t.Fatalf("doctor credential result = %#v, reasons=%#v provider_calls=%v", envelope.Result.Doctor, envelope.Reasons, evidence.providerCalls)
			}

			human := fixture.application.Run(context.Background(), []string{"doctor"}, root)
			if human.ExitCode() != app.ExitCodeSecurity || bytes.Contains(human.Stdout(), []byte(test.secret)) || bytes.Contains(human.Stderr(), []byte(test.secret)) {
				t.Fatalf("doctor human credential result = exit %d stdout %q stderr %q", human.ExitCode(), human.Stdout(), human.Stderr())
			}
		})
	}
}

func TestApplicationDoctorUsesConfiguredFamiliesAndInjectedAuthorityEvidence(t *testing.T) {
	tests := []struct {
		name          string
		initArguments []string
		wantState     string
		wantProviders []string
	}{
		{
			// Every role runs on exactly one provider, so a single eligible
			// family is a complete configuration rather than a degraded one.
			name:          "one configured family is ready",
			initArguments: []string{"init", "--providers", "agy", "--agy-executable", "/bin/sh", "--output", "json"},
			wantState:     "ready",
			wantProviders: []string{"agy"},
		},
		{
			name: "two configured families are ready",
			initArguments: []string{
				"init", "--providers", "kimi,agy", "--kimi-executable", "/bin/sh", "--agy-executable", "/bin/sh", "--output", "json",
			},
			wantState:     "ready",
			wantProviders: []string{"kimi", "agy"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			evidence := &foundationEvidenceReader{}
			fixture := newFoundationFixtureWithEvidence(t, evidence)
			root := testAnchoredRoot(t)
			initialized := fixture.application.Run(context.Background(), test.initArguments, root)
			assertFoundationEnvelope(t, fixture, initialized, app.ExitCodeSuccess)

			result := fixture.application.Run(context.Background(), []string{"doctor", "--output", "json"}, root)
			assertFoundationEnvelope(t, fixture, result, app.ExitCodeSuccess)
			var envelope struct {
				Result struct {
					Doctor *doctor.LocalDoctorResult `json:"doctor"`
				} `json:"result"`
			}
			if err := json.Unmarshal(result.Stdout(), &envelope); err != nil {
				t.Fatal(err)
			}
			if envelope.Result.Doctor == nil || envelope.Result.Doctor.Readiness.State != test.wantState ||
				!reflect.DeepEqual(envelope.Result.Doctor.ConfiguredProviderIDs, test.wantProviders) {
				t.Fatalf("doctor result = %#v, want %s with providers %v", envelope.Result.Doctor, test.wantState, test.wantProviders)
			}
			if !reflect.DeepEqual(evidence.providerCalls, test.wantProviders) {
				t.Fatalf("evidence calls = %v, want configured families only %v", evidence.providerCalls, test.wantProviders)
			}
			for _, row := range envelope.Result.Doctor.ProviderInventory {
				configured := false
				for _, family := range test.wantProviders {
					configured = configured || row.Family == family
				}
				if configured && (row.State != "eligible" || row.Reason != "identity_admitted") {
					t.Fatalf("configured row = %#v, want eligible", row)
				}
				if !configured && (row.State != "not_configured" || row.Reason != "not_configured") {
					t.Fatalf("omitted row = %#v, want not_configured", row)
				}
			}
		})
	}
}

// TestApplicationDoctorStaysReadyWhenOneOfTwoConfiguredProviderIdentitiesIsUnavailable
// proves an unusable family does not degrade readiness on its own. The roles it
// owns will fail and be reported; the roles on the eligible family are unaffected.
func TestApplicationDoctorStaysReadyWhenOneOfTwoConfiguredProviderIdentitiesIsUnavailable(t *testing.T) {
	evidence := &foundationEvidenceReader{}
	fixture := newFoundationFixtureWithEvidence(t, evidence)
	root := testAnchoredRoot(t)
	initialized := fixture.application.Run(context.Background(), []string{
		"init", "--providers", "kimi,agy", "--kimi-executable", "/bin/sh", "--agy-executable", "/bin/bash", "--output", "json",
	}, root)
	assertFoundationEnvelope(t, fixture, initialized, app.ExitCodeSuccess)
	fixture.application.inspector = &doctorIdentityInspector{
		delegate: fixture.application.inspector,
		executableErrors: map[string]error{
			"/bin/sh": ports.NewIdentityObservationError(ports.IdentityObservationUnavailable, "executable is unavailable"),
		},
	}

	result := fixture.application.Run(context.Background(), []string{"doctor", "--output", "json"}, root)
	assertFoundationEnvelope(t, fixture, result, app.ExitCodeSuccess)
	var envelope struct {
		Result struct {
			Doctor *doctor.LocalDoctorResult `json:"doctor"`
		} `json:"result"`
	}
	if err := json.Unmarshal(result.Stdout(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Result.Doctor == nil || envelope.Result.Doctor.Readiness.State != "ready" || envelope.Result.Doctor.Readiness.ExitCode != 0 ||
		envelope.Result.Doctor.ProviderInventory[0].State != "unavailable" || envelope.Result.Doctor.ProviderInventory[2].State != "eligible" ||
		!reflect.DeepEqual(evidence.providerCalls, []string{"agy"}) {
		t.Fatalf("doctor result = %#v, provider calls = %v", envelope.Result.Doctor, evidence.providerCalls)
	}
}

func TestApplicationDoctorRejectsNativeHomeIdentityFailureBeforeProviderObservation(t *testing.T) {
	evidence := &foundationEvidenceReader{}
	fixture := newFoundationFixtureWithEvidence(t, evidence)
	root := testAnchoredRoot(t)
	initialized := fixture.application.Run(context.Background(), []string{"init", "--providers", "agy", "--agy-executable", "/bin/sh", "--output", "json"}, root)
	assertFoundationEnvelope(t, fixture, initialized, app.ExitCodeSuccess)
	fixture.application.inspector = &doctorIdentityInspector{
		delegate:      fixture.application.inspector,
		nativeHomeErr: ports.NewIdentityObservationError(ports.IdentityObservationSecurity, "native home identity changed"),
	}

	result := fixture.application.Run(context.Background(), []string{"doctor", "--output", "json"}, root)
	assertFoundationEnvelope(t, fixture, result, app.ExitCodeSecurity)
	var envelope struct {
		Result struct {
			Doctor *doctor.LocalDoctorResult `json:"doctor"`
		} `json:"result"`
	}
	if err := json.Unmarshal(result.Stdout(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Result.Doctor == nil || envelope.Result.Doctor.Config.NativeHomeIdentity != "mismatch" ||
		!reflect.DeepEqual(envelope.Result.Doctor.Readiness.ReasonCodes, []string{"native_home_mismatch"}) || len(evidence.providerCalls) != 0 {
		t.Fatalf("doctor result = %#v, provider calls = %v", envelope.Result.Doctor, evidence.providerCalls)
	}
}

func TestApplicationDoctorScopesProviderIdentitySecurityFailureToAffectedFamily(t *testing.T) {
	evidence := &foundationEvidenceReader{}
	fixture := newFoundationFixtureWithEvidence(t, evidence)
	root := testAnchoredRoot(t)
	initialized := fixture.application.Run(context.Background(), []string{
		"init", "--providers", "kimi,agy", "--kimi-executable", "/bin/sh", "--agy-executable", "/bin/bash", "--output", "json",
	}, root)
	assertFoundationEnvelope(t, fixture, initialized, app.ExitCodeSuccess)
	fixture.application.inspector = &doctorIdentityInspector{
		delegate: fixture.application.inspector,
		executableErrors: map[string]error{
			"/bin/sh": ports.NewIdentityObservationError(ports.IdentityObservationSecurity, "executable identity changed"),
		},
	}

	result := fixture.application.Run(context.Background(), []string{"doctor", "--output", "json"}, root)
	assertFoundationEnvelope(t, fixture, result, app.ExitCodeSecurity)
	var envelope struct {
		Result struct {
			Doctor *doctor.LocalDoctorResult `json:"doctor"`
		} `json:"result"`
	}
	if err := json.Unmarshal(result.Stdout(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Result.Doctor == nil || envelope.Result.Doctor.ProviderInventory[0].Reason != "provider_security_admission_failed" ||
		envelope.Result.Doctor.ProviderInventory[2].State != "eligible" ||
		!reflect.DeepEqual(evidence.providerCalls, []string{"agy"}) {
		t.Fatalf("doctor result = %#v, provider calls = %v", envelope.Result.Doctor, evidence.providerCalls)
	}
}

func TestApplicationDoctorKeepsConfiguredProvidersUnverifiedWithoutAuthorityEvidence(t *testing.T) {
	fixture := newFoundationFixture(t)
	root := testAnchoredRoot(t)
	initialized := fixture.application.Run(context.Background(), []string{"init", "--providers", "agy", "--agy-executable", "/bin/sh", "--output", "json"}, root)
	assertFoundationEnvelope(t, fixture, initialized, app.ExitCodeSuccess)
	result := fixture.application.Run(context.Background(), []string{"doctor", "--output", "json"}, root)
	assertFoundationEnvelope(t, fixture, result, app.ExitCodeReadiness)
	var envelope struct {
		Result struct {
			Doctor *doctor.LocalDoctorResult `json:"doctor"`
		} `json:"result"`
	}
	if err := json.Unmarshal(result.Stdout(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Result.Doctor == nil || envelope.Result.Doctor.Readiness.State != "unverified" ||
		envelope.Result.Doctor.Readiness.ExitCode != int(app.ExitCodeReadiness) ||
		envelope.Result.Doctor.ProviderInventory[2].Reason != "provider_static_admission_unverified" {
		t.Fatalf("doctor result = %#v, want explicit unverified authority", envelope.Result.Doctor)
	}
}

func TestApplicationProvidersListsOnlyUnverifiedProfilesWithoutProbing(t *testing.T) {
	fixture := newFoundationFixture(t)
	root := testAnchoredRoot(t)

	human := fixture.application.Run(context.Background(), []string{"providers", "--include-unverified"}, root)
	if human.ExitCode() != app.ExitCodeReadiness || len(human.Stderr()) != 0 {
		t.Fatalf("providers human result = exit %d stdout %q stderr %q", human.ExitCode(), human.Stdout(), human.Stderr())
	}
	lines := strings.Split(strings.TrimSuffix(string(human.Stdout()), "\n"), "\n")
	wantFamilies := []string{"kimi", "zcode", "agy"}
	if len(lines) != len(wantFamilies)+3 || lines[3] != "code: readiness_unverified" || lines[4] != "stage: cli.providers" || lines[5] != "hint: run mulgae doctor" {
		t.Fatalf("providers human rows = %q, want provider rows plus actionable failure details", human.Stdout())
	}
	for index, family := range wantFamilies {
		if !strings.Contains(lines[index], "family="+family+" ") ||
			!strings.Contains(lines[index], "support=unverified evidence=unverified assignment=intended_but_unverified") {
			t.Fatalf("providers row %d = %q, want unverified %s profile", index, lines[index], family)
		}
	}
	if strings.Contains(string(human.Stdout()), "token") || strings.Contains(string(human.Stdout()), "secret") {
		t.Fatalf("providers human output disclosed raw secret-like text: %q", human.Stdout())
	}

	filtered := fixture.application.Run(context.Background(), []string{"providers"}, root)
	if filtered.ExitCode() != app.ExitCodeReadiness ||
		!strings.Contains(string(filtered.Stdout()), "no evidence-qualified provider profiles\n") ||
		!strings.Contains(string(filtered.Stdout()), "code: readiness_unverified\nstage: cli.providers\nhint: run mulgae doctor\n") ||
		len(filtered.Stderr()) != 0 {
		t.Fatalf("filtered providers result = exit %d stdout %q stderr %q", filtered.ExitCode(), filtered.Stdout(), filtered.Stderr())
	}

	machine := fixture.application.Run(context.Background(), []string{"providers", "--include-unverified", "--output", "json"}, root)
	assertFoundationEnvelope(t, fixture, machine, app.ExitCodeReadiness)
	var envelope struct {
		Result struct {
			Kind                string  `json:"kind"`
			ProviderEvidenceURI *string `json:"provider_evidence_uri"`
			ReadyProviderCount  int     `json:"ready_provider_count"`
		} `json:"result"`
	}
	if err := json.Unmarshal(machine.Stdout(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Result.Kind != "providers_listed" ||
		envelope.Result.ProviderEvidenceURI != nil ||
		envelope.Result.ReadyProviderCount != 0 {
		t.Fatalf("providers JSON result = %#v, want unverified readiness projection", envelope.Result)
	}
}
func TestApplicationInjectedEvidenceReaderDrivesDoctorAndProvidersWithoutDiscovery(t *testing.T) {
	evidence := &foundationEvidenceReader{}
	fixture := newFoundationFixtureWithEvidence(t, evidence)
	root := testAnchoredRoot(t)

	providersResult := fixture.application.Run(context.Background(), []string{"providers", "--output", "json"}, root)
	assertFoundationEnvelope(t, fixture, providersResult, app.ExitCodeSuccess)
	var providersEnvelope struct {
		Result struct {
			ProviderEvidenceURI *string `json:"provider_evidence_uri"`
			ReadyProviderCount  int     `json:"ready_provider_count"`
		} `json:"result"`
	}
	if err := json.Unmarshal(providersResult.Stdout(), &providersEnvelope); err != nil {
		t.Fatal(err)
	}
	if providersEnvelope.Result.ReadyProviderCount != 3 ||
		providersEnvelope.Result.ProviderEvidenceURI == nil ||
		*providersEnvelope.Result.ProviderEvidenceURI != foundationProviderEvidenceURI {
		t.Fatalf("providers result = %#v, want 3 ready profiles with authority URI %q", providersEnvelope.Result, foundationProviderEvidenceURI)
	}

	doctorResult := fixture.application.Run(context.Background(), []string{"doctor", "--output", "json"}, root)
	assertFoundationEnvelope(t, fixture, doctorResult, app.ExitCodeReadiness)
	var doctorEnvelope struct {
		Result struct {
			DoctorResultURI *string                   `json:"doctor_result_uri"`
			Doctor          *doctor.LocalDoctorResult `json:"doctor"`
		} `json:"result"`
	}
	if err := json.Unmarshal(doctorResult.Stdout(), &doctorEnvelope); err != nil {
		t.Fatal(err)
	}
	if doctorEnvelope.Result.DoctorResultURI != nil || doctorEnvelope.Result.Doctor == nil {
		t.Fatalf("doctor envelope = %#v, want inline project-local result", doctorEnvelope.Result)
	}
	if got := doctorEnvelope.Result.Doctor.Config.Status; got != "missing" {
		t.Fatalf("doctor config status = %q, want missing", got)
	}

	wantCalls := []string{"kimi", "zcode", "agy"}
	if !reflect.DeepEqual(evidence.providerCalls, wantCalls) ||
		len(evidence.platformCalls) != 1 || evidence.toolsCalls != 1 {
		t.Fatalf("evidence reader calls = providers %#v platforms %#v tools %d, want only shared reader observations", evidence.providerCalls, evidence.platformCalls, evidence.toolsCalls)
	}
}
func TestApplicationProvidersRejectsMismatchedSupportedEvidenceURIs(t *testing.T) {
	evidence := &foundationEvidenceReader{
		providerEvidenceURIs: map[string]string{
			"zcode": "https://evidence.example.test/providers/zcode-authority.json",
		},
	}
	fixture := newFoundationFixtureWithEvidence(t, evidence)
	result := fixture.application.Run(context.Background(), []string{"providers", "--output", "json"}, testAnchoredRoot(t))
	assertFoundationEnvelope(t, fixture, result, app.ExitCodeArtifact)

	var envelope struct {
		Result struct {
			ProviderEvidenceURI *string `json:"provider_evidence_uri"`
			ReadyProviderCount  int     `json:"ready_provider_count"`
		} `json:"result"`
	}
	if err := json.Unmarshal(result.Stdout(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Result.ProviderEvidenceURI != nil || envelope.Result.ReadyProviderCount != 0 {
		t.Fatalf("failed providers result = %#v, want no authority URI or ready profiles", envelope.Result)
	}
}

func TestApplicationAbsentAndTypedNilEvidenceReadersRemainUnverified(t *testing.T) {
	var typedNil *typedNilFoundationEvidenceReader
	for _, test := range []struct {
		name    string
		fixture func(*testing.T) foundationFixture
	}{
		{name: "absent", fixture: newFoundationFixture},
		{name: "typed nil", fixture: func(t *testing.T) foundationFixture {
			return newFoundationFixtureWithEvidence(t, typedNil)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := test.fixture(t)
			if fixture.application.evidenceReader != nil {
				t.Fatalf("application evidence reader = %#v, want nil", fixture.application.evidenceReader)
			}
			result := fixture.application.Run(context.Background(), []string{"providers", "--include-unverified"}, testAnchoredRoot(t))
			if result.ExitCode() != app.ExitCodeReadiness ||
				!strings.Contains(string(result.Stdout()), "support=unverified evidence=unverified assignment=intended_but_unverified") {
				t.Fatalf("providers result = exit %d stdout %q, want unverified profiles", result.ExitCode(), result.Stdout())
			}
		})
	}
}

func TestApplicationReviewFailsClosedAndPromptIsNotACommand(t *testing.T) {
	fixture := newFoundationFixture(t)
	root := testAnchoredRoot(t)
	tests := []struct {
		name string
		argv []string
		exit app.ExitCode
	}{
		{name: "review", argv: []string{"review", "--dirty"}, exit: app.ExitCodeReadiness},
		{name: "prompt", argv: []string{"prompt", "--run", testRunID, "--attempt", testAttemptID}, exit: app.ExitCodeUsage},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := fixture.application.Run(context.Background(), test.argv, root)
			if result.ExitCode() != test.exit || len(result.Stdout()) != 0 || len(result.Stderr()) == 0 {
				t.Fatalf("%s result = exit %d stdout %q stderr %q", test.name, result.ExitCode(), result.Stdout(), result.Stderr())
			}
		})
	}
}

type reviewRunFake struct {
	result          ReviewRunResult
	err             error
	calls           int
	preflightResult ReviewPreflightResult
	preflightErr    error
	preflightCalls  int
	ctx             context.Context
	request         ReviewRequest
	root            ports.AnchoredRoot
}

func (fake *reviewRunFake) StartReviewRun(ctx context.Context, request ReviewRequest, root ports.AnchoredRoot) (ReviewRunResult, error) {
	fake.calls++
	fake.ctx = ctx
	fake.request = request
	fake.root = root
	if fake.err != nil {
		return ReviewRunResult{}, fake.err
	}
	return fake.result, nil
}

func (fake *reviewRunFake) PreflightReview(ctx context.Context, request ReviewRequest, root ports.AnchoredRoot) (ReviewPreflightResult, error) {
	fake.preflightCalls++
	fake.ctx = ctx
	fake.request = request
	fake.root = root
	return fake.preflightResult, fake.preflightErr
}

type reviewRunInputSourceFactoryFake struct {
	calls   int
	ctx     context.Context
	request reviewrun.InputCaptureRequest
	source  reviewrun.ImmutableInputSource
	err     error
	events  *[]string
}

func (fake *reviewRunInputSourceFactoryFake) NewImmutableInputSource(
	ctx context.Context,
	request reviewrun.InputCaptureRequest,
) (reviewrun.ImmutableInputSource, error) {
	fake.calls++
	fake.ctx = ctx
	fake.request = request
	if fake.events != nil {
		*fake.events = append(*fake.events, "factory")
	}
	return fake.source, fake.err
}

type typedNilReviewRunInputSourceFactory struct{}

func (*typedNilReviewRunInputSourceFactory) NewImmutableInputSource(
	context.Context,
	reviewrun.InputCaptureRequest,
) (reviewrun.ImmutableInputSource, error) {
	return nil, nil
}

type reviewRunInputSourceFake struct {
	calls  int
	err    error
	events *[]string
}

func (fake *reviewRunInputSourceFake) Capture(context.Context, reviewrun.Request) (reviewrun.CapturedRunInput, error) {
	fake.calls++
	if fake.events != nil {
		*fake.events = append(*fake.events, "capture")
	}
	return reviewrun.CapturedRunInput{}, fake.err
}

func testReviewRunAnchoredRoot(t *testing.T) ports.AnchoredRoot {
	t.Helper()
	root, err := ports.NewAnchoredRoot(testAnchoredRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func TestNewReviewRunServicePreservesNilDependencies(t *testing.T) {
	factory := &reviewRunInputSourceFactoryFake{}
	if got := NewReviewRunService(nil, factory); got != nil {
		t.Fatalf("nil service adapter = %#v, want nil", got)
	}
	if got := NewReviewRunService(new(reviewrun.Service), nil); got != nil {
		t.Fatalf("nil factory adapter = %#v, want nil", got)
	}
	var typedNil *typedNilReviewRunInputSourceFactory
	if got := NewReviewRunService(new(reviewrun.Service), typedNil); got != nil {
		t.Fatalf("typed-nil factory adapter = %#v, want nil", got)
	}
}

func TestPolicyReviewRunServiceUsesProjectDefaultOrExactExplicitSubset(t *testing.T) {
	t.Parallel()
	enabled := map[domain.Role]bool{
		domain.RoleLogic: true, domain.RoleSecurity: true, domain.RoleDocumentation: true,
	}
	root := testReviewRunAnchoredRoot(t)
	for _, test := range []struct {
		name     string
		request  ReviewRequest
		want     []string
		wantCall bool
	}{
		{name: "project default", request: ReviewRequest{roles: []string{"logic", "security", "maintainability", "product", "documentation", "testing"}}, want: []string{"logic", "security", "documentation"}, wantCall: true},
		{name: "explicit optional only", request: ReviewRequest{roles: []string{"documentation"}, rolesExplicit: true}, want: []string{"documentation"}, wantCall: true},
		{name: "disabled explicit role", request: ReviewRequest{roles: []string{"testing"}, rolesExplicit: true}},
	} {
		t.Run(test.name, func(t *testing.T) {
			fake := &reviewRunFake{}
			service := NewPolicyReviewRunService(fake, []domain.Role{domain.RoleLogic, domain.RoleSecurity}, enabled)
			_, err := service.StartReviewRun(context.Background(), test.request, root)
			if test.wantCall {
				if err != nil || fake.calls != 1 || !reflect.DeepEqual(fake.request.Roles(), test.want) || !fake.request.RolesExplicit() {
					t.Fatalf("result err=%v calls=%d roles=%v explicit=%t", err, fake.calls, fake.request.Roles(), fake.request.RolesExplicit())
				}
			} else if err == nil || fake.calls != 0 {
				t.Fatalf("disabled role err=%v calls=%d", err, fake.calls)
			}
		})
	}
}

func TestPolicyReviewRunServiceResolvesArtistOverridesAgainstConfigV1Defaults(t *testing.T) {
	defaults, err := ports.NewArtistReviewInputs("ux-ui-info.md", []string{"design-specs/**/*.png"})
	if err != nil {
		t.Fatal(err)
	}
	enabled := map[domain.Role]bool{domain.RoleLogic: true, domain.RoleArtist: true}
	fake := &reviewRunFake{}
	service := NewPolicyReviewRunServiceWithArtistInputs(fake, nil, enabled, defaults)
	request := ReviewRequest{
		roles: []string{"artist"}, rolesExplicit: true,
		artistBriefPath: "docs/roadmap.md", hasArtistBrief: true,
	}
	if _, err := service.StartReviewRun(context.Background(), request, testReviewRunAnchoredRoot(t)); err != nil {
		t.Fatal(err)
	}
	brief, present := fake.request.ArtistBrief()
	if fake.calls != 1 || !present || brief != "docs/roadmap.md" || !reflect.DeepEqual(fake.request.ArtistDesignSpecs(), []string{"design-specs/**/*.png"}) {
		t.Fatalf("resolved artist request = %#v", fake.request)
	}
	if fake.request.ArtistAutomatic() {
		t.Fatal("explicit artist selection was marked automatic")
	}

	automaticFake := &reviewRunFake{}
	automaticService := NewPolicyReviewRunServiceWithArtistInputs(automaticFake, nil, enabled, defaults)
	if _, err := automaticService.StartReviewRun(context.Background(), ReviewRequest{roles: coreRoleNames()}, testReviewRunAnchoredRoot(t)); err != nil {
		t.Fatal(err)
	}
	if !automaticFake.request.ArtistAutomatic() || !containsString(automaticFake.request.Roles(), "artist") {
		t.Fatalf("project-default artist selection = %#v", automaticFake.request)
	}

	missing := NewPolicyReviewRunService(&reviewRunFake{}, nil, enabled)
	if _, err := missing.StartReviewRun(context.Background(), ReviewRequest{roles: []string{"artist"}, rolesExplicit: true}, testReviewRunAnchoredRoot(t)); err == nil {
		t.Fatal("artist selection without resolved inputs was accepted")
	}
}

func TestReviewRunAdapterCapturesOnceBeforeServiceAndPropagatesRequest(t *testing.T) {
	root := testReviewRunAnchoredRoot(t)
	ctx := context.WithValue(context.Background(), "review-run-adapter", "context")
	request := ReviewRequest{
		target:          TargetRequest{kind: "diff", value: "HEAD~1"},
		objective:       "review only the request adapter",
		hasObjective:    true,
		roles:           []string{"artist"},
		artistBriefPath: "docs/roadmap.md", hasArtistBrief: true,
		artistDesignGlobs: []string{"design-specs/**/*.png"},
		sessionID:         g006SessionID,
		hasSessionID:      true,
	}
	captureErr := errors.New("capture failed")
	events := []string{}
	source := &reviewRunInputSourceFake{err: captureErr, events: &events}
	factory := &reviewRunInputSourceFactoryFake{source: source, events: &events}
	service := NewReviewRunService(new(reviewrun.Service), factory)

	_, err := service.StartReviewRun(ctx, request, root)
	if !errors.Is(err, captureErr) {
		t.Fatalf("StartReviewRun error = %v, want capture error", err)
	}
	if factory.calls != 1 || source.calls != 1 {
		t.Fatalf("factory calls = %d, source captures = %d, want 1 each", factory.calls, source.calls)
	}
	if !reflect.DeepEqual(events, []string{"factory", "capture"}) {
		t.Fatalf("call order = %#v, want factory before service capture", events)
	}
	capturedObjective, hasObjective := factory.request.Objective()
	artistInputs, hasArtistInputs := factory.request.ArtistInputs()
	if factory.ctx != ctx || factory.request.Root() != root || factory.request.Target().Kind() != ports.ReviewTargetDiff ||
		factory.request.Target().Value() != "HEAD~1" || !hasObjective || string(capturedObjective) != request.objective ||
		!hasArtistInputs || artistInputs.BriefPath() != "docs/roadmap.md" || !reflect.DeepEqual(artistInputs.DesignSpecGlobs(), []string{"design-specs/**/*.png"}) {
		t.Fatalf("factory input = %#v, want exact typed context/request/root", factory.request)
	}
}

func TestReviewRunAdapterRejectsMalformedRequestBeforeCapture(t *testing.T) {
	factory := &reviewRunInputSourceFactoryFake{}
	service := NewReviewRunService(new(reviewrun.Service), factory)

	_, err := service.StartReviewRun(context.Background(), ReviewRequest{}, testReviewRunAnchoredRoot(t))
	if err == nil {
		t.Fatal("StartReviewRun accepted malformed request")
	}
	if factory.calls != 0 {
		t.Fatalf("factory calls = %d, want 0", factory.calls)
	}
}

func TestReviewRunAdapterPropagatesFactoryError(t *testing.T) {
	factoryErr := errors.New("factory failed")
	factory := &reviewRunInputSourceFactoryFake{err: factoryErr}
	service := NewReviewRunService(new(reviewrun.Service), factory)
	request := ReviewRequest{target: TargetRequest{kind: "diff", value: "HEAD"}, roles: []string{"logic"}}

	_, err := service.StartReviewRun(context.Background(), request, testReviewRunAnchoredRoot(t))
	if !errors.Is(err, factoryErr) {
		t.Fatalf("StartReviewRun error = %v, want factory error", err)
	}
	if factory.calls != 1 {
		t.Fatalf("factory calls = %d, want 1", factory.calls)
	}
}

func TestApplicationReviewRunServiceSeam(t *testing.T) {
	root := testAnchoredRoot(t)
	valid := NewReviewRunResult(
		g006SessionID,
		"r_019f596a-d050-79e7-b2b7-59822f012273",
		".mulgae/runs/manifest.json",
		g006ReviewArtifactURI,
		g008CommittedTerminalExit(t, domain.ExitCommittedPass),
	)
	classified, err := domain.NewFailure("test.review", domain.FailureArtifact, "review artifact unavailable", nil)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name      string
		service   ReviewRunService
		result    ReviewRunResult
		err       error
		wantExit  app.ExitCode
		wantCalls int
	}{
		{name: "absent", wantExit: app.ExitCodeReadiness},
		{name: "typed nil", service: (*reviewRunFake)(nil), wantExit: app.ExitCodeReadiness},
		{name: "success", result: valid, wantExit: app.ExitCodeSuccess, wantCalls: 1},
		{name: "malformed result", result: ReviewRunResult{}, wantExit: app.ExitCodeInternal, wantCalls: 1},
		{name: "classified failure", err: classified, wantExit: app.ExitCodeArtifact, wantCalls: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newFoundationFixture(t)
			fake := &reviewRunFake{result: test.result, err: test.err}
			if test.service != nil {
				fixture.application.reviewRuns = test.service
			} else if test.wantCalls != 0 {
				fixture.application.reviewRuns = fake
			}
			ctx := context.WithValue(context.Background(), "review-context", test.name)
			argv := []string{"review", "--dirty"}
			if test.wantCalls != 0 {
				argv = append(argv, "--output", "json")
			}
			result := fixture.application.Run(ctx, argv, root)
			if result.ExitCode() != test.wantExit {
				t.Fatalf("exit = %d, want %d; stdout = %q stderr = %q", result.ExitCode(), test.wantExit, result.Stdout(), result.Stderr())
			}
			if fake.calls != test.wantCalls {
				t.Fatalf("service calls = %d, want %d", fake.calls, test.wantCalls)
			}
			if test.wantCalls == 0 {
				if len(result.Stdout()) != 0 || len(result.Stderr()) == 0 {
					t.Fatalf("unavailable result = stdout %q stderr %q", result.Stdout(), result.Stderr())
				}
				return
			}
			if fake.ctx != ctx {
				t.Fatal("service did not receive the invocation context")
			}
			expectedRoot, err := ports.NewAnchoredRoot(root)
			if err != nil {
				t.Fatal(err)
			}
			if fake.root != expectedRoot {
				t.Fatalf("service root = %#v, want %#v", fake.root, expectedRoot)
			}
			if got := fake.request.Roles(); !reflect.DeepEqual(got, []string{"logic", "security", "maintainability", "product", "documentation", "testing"}) {
				t.Fatalf("service review roles = %#v", got)
			}
			if test.name == "success" {
				assertFoundationEnvelope(t, fixture, result, app.ExitCodeSuccess)
				var envelope struct {
					Result struct {
						Kind              string `json:"kind"`
						SessionID         string `json:"session_id"`
						RunID             string `json:"run_id"`
						RunManifestURI    string `json:"run_manifest_uri"`
						ReviewArtifactURI string `json:"review_artifact_uri"`
					} `json:"result"`
				}
				if err := json.Unmarshal(result.Stdout(), &envelope); err != nil {
					t.Fatal(err)
				}
				if envelope.Result.Kind != "review_started" ||
					envelope.Result.SessionID != g006SessionID ||
					envelope.Result.RunID != "r_019f596a-d050-79e7-b2b7-59822f012273" ||
					envelope.Result.RunManifestURI != ".mulgae/runs/manifest.json" ||
					envelope.Result.ReviewArtifactURI != g006ReviewArtifactURI {
					t.Fatalf("review result = %#v", envelope.Result)
				}
				return
			}
		})
	}
}

func TestApplicationReviewPreflightUsesOnlyExecutionFreeService(t *testing.T) {
	fixture := newFoundationFixture(t)
	fake := &reviewRunFake{preflightResult: loadReviewPreflightExample(t)}
	fixture.application.reviewRuns = fake
	beforeEnsures, beforeWrites := fixture.writer.ensureCalls, len(fixture.writer.requests)
	result := fixture.application.Run(context.Background(), []string{"review", "--stage", "--preflight", "--output", "json"}, testAnchoredRoot(t))
	if result.ExitCode() != app.ExitCodeSuccess {
		t.Fatalf("exit = %d stderr = %q", result.ExitCode(), result.Stderr())
	}
	if fake.preflightCalls != 1 || fake.calls != 0 || !fake.request.Preflight() {
		t.Fatalf("service calls preflight/start/request = %d/%d/%t", fake.preflightCalls, fake.calls, fake.request.Preflight())
	}
	if fixture.writer.ensureCalls != beforeEnsures || len(fixture.writer.requests) != beforeWrites {
		t.Fatalf("preflight mutated writer: ensure %d->%d writes %d->%d", beforeEnsures, fixture.writer.ensureCalls, beforeWrites, len(fixture.writer.requests))
	}
	assertFoundationEnvelope(t, fixture, result, app.ExitCodeSuccess)
	if !bytes.Contains(result.Stdout(), []byte(`"kind":"review_preflight"`)) || bytes.Contains(result.Stdout(), []byte(`"kind":"review_started"`)) {
		t.Fatalf("preflight result = %s", result.Stdout())
	}
}

func TestApplicationReviewPreflightAcceptsLargeProjection(t *testing.T) {
	result := loadReviewPreflightExample(t)
	files := make([]ReviewPreflightFile, 33)
	for index := range files {
		files[index] = ReviewPreflightFile{
			Path: fmt.Sprintf("files/%05d.png", index), MediaType: "image/png",
			Size:        4 << 20,
			SHA256:      "sha256:0000000000000000000000000000000000000000000000000000000000000000",
			Disposition: "binary_preserved",
		}
	}
	setReviewPreflightFiles(t, &result, "index;layout=ordinary-directories-v1", files)
	fixture := newFoundationFixture(t)
	fixture.application.reviewRuns = &reviewRunFake{preflightResult: result}
	machine := fixture.application.Run(context.Background(), []string{"review", "--stage", "--preflight", "--output", "json"}, testAnchoredRoot(t))
	if machine.ExitCode() != app.ExitCodeSuccess || len(machine.Stderr()) != 0 {
		t.Fatalf("large preflight exit = %d stderr=%q stdout=%q", machine.ExitCode(), machine.Stderr(), machine.Stdout())
	}
	var envelope struct {
		Reasons []struct {
			Category    string  `json:"category"`
			Code        string  `json:"code"`
			Message     string  `json:"message"`
			ArtifactURI *string `json:"artifact_uri"`
		} `json:"reasons"`
	}
	if err := json.Unmarshal(machine.Stdout(), &envelope); err != nil {
		t.Fatal(err)
	}
	if len(envelope.Reasons) != 0 || !bytes.Contains(machine.Stdout(), []byte(`"kind":"review_preflight"`)) {
		t.Fatalf("large preflight projection failed = %#v", envelope)
	}
}

func TestApplicationHumanFailuresAlwaysIncludeSafeCodeStageAndHint(t *testing.T) {
	fixture := newFoundationFixture(t)
	fixture.application.reviewRuns = &reviewRunFake{err: errors.New("private adapter detail")}
	result := fixture.application.Run(context.Background(), []string{"review", "--dirty"}, testAnchoredRoot(t))
	stderr := string(result.Stderr())
	if result.ExitCode() == app.ExitCodeSuccess || !strings.Contains(stderr, "code: provider_unavailable") ||
		!strings.Contains(stderr, "stage: cli.review") || !strings.Contains(stderr, "hint: run mulgae doctor") ||
		strings.Contains(stderr, "private adapter detail") {
		t.Fatalf("actionable human failure = exit %d stderr=%q", result.ExitCode(), stderr)
	}

	usage := fixture.application.Run(context.Background(), []string{"review", "--dirty", "--stage"}, testAnchoredRoot(t))
	if usage.ExitCode() != app.ExitCodeUsage || !strings.Contains(string(usage.Stderr()), "hint: run mulgae help workflows") {
		t.Fatalf("actionable usage failure = exit %d stderr=%q", usage.ExitCode(), usage.Stderr())
	}
}

func TestApplicationReviewReportsProviderLoginRequiredFailClosed(t *testing.T) {
	cause, err := domain.NewFailure(
		"reviewrun.current.capability",
		domain.FailureAuthentication,
		"provider login required",
		ports.ErrProviderLoginRequired,
	)
	if err != nil {
		t.Fatal(err)
	}
	loginErr := reviewrun.NewProviderLoginRequiredError([]string{"zcode-default", "kimi-default", "kimi-default"}, cause)
	diagnosticURI, err := ports.NewSafeRelativePath(".mulgae/diagnostics/s_test/r_test")
	if err != nil {
		t.Fatal(err)
	}
	loginErr = reviewrun.NewRuntimeDiagnosticReferenceError(diagnosticURI, loginErr)

	fixture := newFoundationFixture(t)
	fixture.application.reviewRuns = &reviewRunFake{err: loginErr}
	machine := fixture.application.Run(
		context.Background(),
		[]string{"review", "--dirty", "--output", "json"},
		testAnchoredRoot(t),
	)
	assertFoundationEnvelope(t, fixture, machine, app.ExitCodeReadiness)
	if len(machine.Stderr()) != 0 {
		t.Fatalf("machine stderr = %q", machine.Stderr())
	}
	var envelope struct {
		Exit struct {
			Code int `json:"code"`
		} `json:"exit"`
		Reasons []struct {
			Code        string  `json:"code"`
			Message     string  `json:"message"`
			Retryable   bool    `json:"retryable"`
			ArtifactURI *string `json:"artifact_uri"`
		} `json:"reasons"`
		Result struct {
			Kind              string  `json:"kind"`
			SessionID         *string `json:"session_id"`
			RunID             *string `json:"run_id"`
			RunManifestURI    *string `json:"run_manifest_uri"`
			ReviewArtifactURI *string `json:"review_artifact_uri"`
		} `json:"result"`
	}
	if err := json.Unmarshal(machine.Stdout(), &envelope); err != nil {
		t.Fatal(err)
	}
	if len(envelope.Reasons) != 1 || envelope.Reasons[0].Code != "provider_login_required" ||
		envelope.Reasons[0].Retryable ||
		envelope.Reasons[0].ArtifactURI == nil || *envelope.Reasons[0].ArtifactURI != diagnosticURI.String() ||
		envelope.Reasons[0].Message != "Login is required for provider kimi-default, zcode-default. Authenticate outside Mulgae, then rerun the command." ||
		envelope.Result.Kind != "review_started" || envelope.Result.SessionID != nil || envelope.Result.RunID != nil ||
		envelope.Result.RunManifestURI != nil || envelope.Result.ReviewArtifactURI != nil {
		t.Fatalf("login-required envelope = %#v", envelope)
	}

	humanFixture := newFoundationFixture(t)
	humanFixture.application.reviewRuns = &reviewRunFake{err: loginErr}
	human := humanFixture.application.Run(context.Background(), []string{"review", "--dirty"}, testAnchoredRoot(t))
	if human.ExitCode() != app.ExitCodeReadiness || len(human.Stdout()) != 0 ||
		!strings.Contains(string(human.Stderr()), "code: provider_login_required\nstage: cli.review\nhint: run mulgae doctor") ||
		!strings.Contains(string(human.Stderr()), "diagnostic_uri: "+diagnosticURI.String()) {
		t.Fatalf("human login-required result = exit %d stdout %q stderr %q", human.ExitCode(), human.Stdout(), human.Stderr())
	}
}

func TestApplicationReviewFailurePreservesAllocatedRunIdentity(t *testing.T) {
	cause, err := domain.NewFailure(
		"publication.install",
		domain.FailureArtifact,
		"publication installation failed",
		errors.New("injected installation failure"),
	)
	if err != nil {
		t.Fatal(err)
	}
	diagnosticURI, err := ports.NewSafeRelativePath(".mulgae/diagnostics/" + g006SessionID + "/" + testRunID)
	if err != nil {
		t.Fatal(err)
	}
	sessionID, _ := domain.ParseSessionID(g006SessionID)
	runID, _ := domain.ParseRunID(testRunID)
	terminalErr := reviewrun.NewRuntimeDiagnosticReferenceErrorWithIdentity(diagnosticURI, sessionID, runID, cause)

	fixture := newFoundationFixture(t)
	fixture.application.reviewRuns = &reviewRunFake{err: terminalErr}
	result := fixture.application.Run(
		context.Background(),
		[]string{"review", "--dirty", "--output", "json"},
		testAnchoredRoot(t),
	)
	assertFoundationEnvelope(t, fixture, result, app.ExitCodeArtifact)
	var envelope struct {
		Result struct {
			SessionID         *string `json:"session_id"`
			RunID             *string `json:"run_id"`
			RunManifestURI    *string `json:"run_manifest_uri"`
			ReviewArtifactURI *string `json:"review_artifact_uri"`
		} `json:"result"`
	}
	if err := json.Unmarshal(result.Stdout(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Result.SessionID == nil || *envelope.Result.SessionID != g006SessionID ||
		envelope.Result.RunID == nil || *envelope.Result.RunID != testRunID ||
		envelope.Result.RunManifestURI != nil || envelope.Result.ReviewArtifactURI != nil {
		t.Fatalf("failed review identity = %#v", envelope.Result)
	}
}

func TestApplicationReviewDoesNotProjectUninstalledRuntimeDiagnosticURI(t *testing.T) {
	cause, err := domain.NewFailure("reviewrun.current.capability", domain.FailureAuthentication, "provider login required", ports.ErrProviderLoginRequired)
	if err != nil {
		t.Fatal(err)
	}
	loginErr := reviewrun.NewProviderLoginRequiredError([]string{"kimi-default"}, cause)
	fixture := newFoundationFixture(t)
	fixture.application.reviewRuns = &reviewRunFake{err: loginErr}
	result := fixture.application.Run(context.Background(), []string{"review", "--dirty", "--output", "json"}, testAnchoredRoot(t))
	var envelope struct {
		Reasons []struct {
			ArtifactURI *string `json:"artifact_uri"`
		} `json:"reasons"`
	}
	if err := json.Unmarshal(result.Stdout(), &envelope); err != nil {
		t.Fatal(err)
	}
	if len(envelope.Reasons) != 1 || envelope.Reasons[0].ArtifactURI != nil {
		t.Fatalf("uninstalled diagnostic projection = %#v", envelope.Reasons)
	}
}

func TestApplicationReviewReportsAttributedQualificationFailures(t *testing.T) {
	invalid, err := domain.NewFailure("capability", domain.FailureInvalidOutput, "invalid capability output", nil)
	if err != nil {
		t.Fatal(err)
	}
	timedOut, err := domain.NewFailure("capability", domain.FailureTimeout, "capability timed out", nil)
	if err != nil {
		t.Fatal(err)
	}
	zcode, err := reviewrun.NewProviderQualificationFailure("zcode-default", reviewrun.FamilyZCode, string(domain.FailureTimeout), timedOut)
	if err != nil {
		t.Fatal(err)
	}
	kimi, err := reviewrun.NewProviderQualificationFailure("kimi-default", reviewrun.FamilyKimi, string(domain.FailureInvalidOutput), invalid)
	if err != nil {
		t.Fatal(err)
	}
	qualificationErr := reviewrun.NewProviderQualificationFailuresError([]reviewrun.ProviderQualificationFailure{zcode, kimi})

	fixture := newFoundationFixture(t)
	fixture.application.reviewRuns = &reviewRunFake{err: qualificationErr}
	machine := fixture.application.Run(
		context.Background(),
		[]string{"review", "--dirty", "--output", "json"},
		testAnchoredRoot(t),
	)
	assertFoundationEnvelope(t, fixture, machine, app.ExitCodeReadiness)
	var envelope struct {
		Reasons []struct {
			Code      string `json:"code"`
			Message   string `json:"message"`
			Retryable bool   `json:"retryable"`
		} `json:"reasons"`
		Result struct {
			RunID             *string `json:"run_id"`
			RunManifestURI    *string `json:"run_manifest_uri"`
			ReviewArtifactURI *string `json:"review_artifact_uri"`
		} `json:"result"`
	}
	if err := json.Unmarshal(machine.Stdout(), &envelope); err != nil {
		t.Fatal(err)
	}
	wantMessage := "Provider qualification failed: kimi-default=invalid_provider_output, zcode-default=timeout. Retry the command after resolving provider readiness."
	if len(envelope.Reasons) != 1 || envelope.Reasons[0].Code != "provider_qualification_failed" ||
		!envelope.Reasons[0].Retryable || envelope.Reasons[0].Message != wantMessage ||
		envelope.Result.RunID != nil || envelope.Result.RunManifestURI != nil || envelope.Result.ReviewArtifactURI != nil {
		t.Fatalf("qualification failure envelope = %#v", envelope)
	}

	humanFixture := newFoundationFixture(t)
	humanFixture.application.reviewRuns = &reviewRunFake{err: qualificationErr}
	human := humanFixture.application.Run(context.Background(), []string{"review", "--dirty"}, testAnchoredRoot(t))
	if human.ExitCode() != app.ExitCodeReadiness || len(human.Stdout()) != 0 ||
		!strings.Contains(string(human.Stderr()), "code: provider_qualification_failed\nstage: cli.review\nhint: run mulgae doctor") {
		t.Fatalf("human qualification failure = exit %d stdout %q stderr %q", human.ExitCode(), human.Stdout(), human.Stderr())
	}
}

func TestApplicationReviewReportsQualificationPermissionDenialByActualCause(t *testing.T) {
	permissionCause, err := ports.NewProviderRuntimeError(
		domain.DiagnosticCausePermissionDenied,
		errors.New("closed provider permission detail"),
	)
	if err != nil {
		t.Fatal(err)
	}
	agy, err := reviewrun.NewProviderQualificationFailure(
		"agy-security", reviewrun.FamilyAGY, string(domain.FailureAuthentication), permissionCause,
	)
	if err != nil {
		t.Fatal(err)
	}
	qualificationErr := reviewrun.NewProviderQualificationFailuresError([]reviewrun.ProviderQualificationFailure{agy})

	fixture := newFoundationFixture(t)
	fixture.application.reviewRuns = &reviewRunFake{err: qualificationErr}
	machine := fixture.application.Run(
		context.Background(),
		[]string{"review", "--dirty", "--output", "json"},
		testAnchoredRoot(t),
	)
	assertFoundationEnvelope(t, fixture, machine, app.ExitCodeReadiness)
	var envelope struct {
		Reasons []struct {
			Code      string `json:"code"`
			Message   string `json:"message"`
			Retryable bool   `json:"retryable"`
		} `json:"reasons"`
	}
	if err := json.Unmarshal(machine.Stdout(), &envelope); err != nil {
		t.Fatal(err)
	}
	if len(envelope.Reasons) != 1 || envelope.Reasons[0].Code != "provider_permission_denied" ||
		envelope.Reasons[0].Retryable ||
		!strings.Contains(envelope.Reasons[0].Message, "Provider permission denied during qualification for agy-security") ||
		strings.Contains(envelope.Reasons[0].Message, "provider_output_decode_failed") {
		t.Fatalf("qualification permission envelope = %#v", envelope.Reasons)
	}
}

func TestApplicationReviewPreservesQualificationPermissionDenialInMixedAggregate(t *testing.T) {
	permissionCause, err := ports.NewProviderRuntimeError(
		domain.DiagnosticCausePermissionDenied,
		errors.New("closed provider permission detail"),
	)
	if err != nil {
		t.Fatal(err)
	}
	permission, err := reviewrun.NewProviderQualificationFailure(
		"agy-security", reviewrun.FamilyAGY, string(domain.FailureAuthentication), permissionCause,
	)
	if err != nil {
		t.Fatal(err)
	}
	timeoutCause, err := ports.NewProviderRuntimeError(
		domain.DiagnosticCauseTimedOut,
		errors.New("closed provider timeout detail"),
	)
	if err != nil {
		t.Fatal(err)
	}
	timeout, err := reviewrun.NewProviderQualificationFailure(
		"zcode-logic", reviewrun.FamilyZCode, string(domain.FailureTimeout), timeoutCause,
	)
	if err != nil {
		t.Fatal(err)
	}
	qualificationErr := reviewrun.NewProviderQualificationFailuresError([]reviewrun.ProviderQualificationFailure{permission, timeout})

	fixture := newFoundationFixture(t)
	fixture.application.reviewRuns = &reviewRunFake{err: qualificationErr}
	machine := fixture.application.Run(
		context.Background(),
		[]string{"review", "--dirty", "--output", "json"},
		testAnchoredRoot(t),
	)
	assertFoundationEnvelope(t, fixture, machine, app.ExitCodeReadiness)
	var envelope struct {
		Reasons []struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"reasons"`
	}
	if err := json.Unmarshal(machine.Stdout(), &envelope); err != nil {
		t.Fatal(err)
	}
	if len(envelope.Reasons) != 1 || envelope.Reasons[0].Code != "provider_permission_denied" ||
		!strings.Contains(envelope.Reasons[0].Message, "agy-security") ||
		!strings.Contains(envelope.Reasons[0].Message, "Other qualification failures: zcode-logic=timeout") ||
		strings.Contains(envelope.Reasons[0].Message, "agy-security=auth") {
		t.Fatalf("mixed qualification envelope = %#v", envelope.Reasons)
	}

	humanFixture := newFoundationFixture(t)
	humanFixture.application.reviewRuns = &reviewRunFake{err: qualificationErr}
	human := humanFixture.application.Run(context.Background(), []string{"review", "--dirty"}, testAnchoredRoot(t))
	if human.ExitCode() != app.ExitCodeReadiness || len(human.Stdout()) != 0 ||
		!strings.Contains(string(human.Stderr()), "code: provider_permission_denied\nstage: provider.qualify\nhint: run mulgae config --mode effective") {
		t.Fatalf("mixed human qualification failure = exit %d stdout %q stderr %q", human.ExitCode(), human.Stdout(), human.Stderr())
	}
}

func TestApplicationReviewReportsAttributedProviderExecutionFailure(t *testing.T) {
	execution, err := reviewrun.NewProviderExecutionFailure(
		"zcode-default",
		domain.RoleSecurity,
		"security_violation",
		domain.FailureSecurityPolicy,
	)
	if err != nil {
		t.Fatal(err)
	}
	aggregate := reviewrun.NewProviderExecutionFailuresError([]reviewrun.ProviderExecutionFailure{execution})
	executionErr, err := domain.NewFailure(
		"reviewrun.execute",
		domain.FailureSecurityPolicy,
		"coordinator terminated with a non-publishable provider outcome",
		aggregate,
	)
	if err != nil {
		t.Fatal(err)
	}
	diagnosticURI, err := ports.NewSafeRelativePath(".mulgae/diagnostics/s_test/r_test")
	if err != nil {
		t.Fatal(err)
	}
	referencedExecutionErr := reviewrun.NewRuntimeDiagnosticReferenceError(diagnosticURI, executionErr)

	fixture := newFoundationFixture(t)
	fixture.application.reviewRuns = &reviewRunFake{err: referencedExecutionErr}
	machine := fixture.application.Run(
		context.Background(),
		[]string{"review", "--dirty", "--output", "json"},
		testAnchoredRoot(t),
	)
	assertFoundationEnvelope(t, fixture, machine, app.ExitCodeSecurity)
	var envelope struct {
		Reasons []struct {
			Code        string  `json:"code"`
			Message     string  `json:"message"`
			Retryable   bool    `json:"retryable"`
			ArtifactURI *string `json:"artifact_uri"`
		} `json:"reasons"`
	}
	if err := json.Unmarshal(machine.Stdout(), &envelope); err != nil {
		t.Fatal(err)
	}
	if len(envelope.Reasons) != 1 || envelope.Reasons[0].Code != "provider_execution_failed" ||
		envelope.Reasons[0].Retryable ||
		envelope.Reasons[0].ArtifactURI == nil || *envelope.Reasons[0].ArtifactURI != diagnosticURI.String() ||
		!strings.Contains(envelope.Reasons[0].Message, "stage provider.execute") ||
		!strings.Contains(envelope.Reasons[0].Message, "role=security provider=zcode-default reason=security_violation") {
		t.Fatalf("provider execution failure envelope = %#v", envelope)
	}

	humanFixture := newFoundationFixture(t)
	humanFixture.application.reviewRuns = &reviewRunFake{err: referencedExecutionErr}
	human := humanFixture.application.Run(context.Background(), []string{"review", "--dirty"}, testAnchoredRoot(t))
	if human.ExitCode() != app.ExitCodeSecurity || len(human.Stdout()) != 0 ||
		!strings.Contains(string(human.Stderr()), "code: provider_execution_failed\nstage: provider.execute\nhint: run mulgae doctor") ||
		!strings.Contains(string(human.Stderr()), "diagnostic_uri: "+diagnosticURI.String()) {
		t.Fatalf("human provider execution failure = exit %d stdout %q stderr %q", human.ExitCode(), human.Stdout(), human.Stderr())
	}
}

func TestApplicationReviewReportsCaptureStageAndSubtype(t *testing.T) {
	capture, err := ports.NewReviewCaptureFailure(
		ports.ReviewCaptureUnsupported,
		"client/e2e/screenshots/example.png",
		domain.RoleLogic,
		"use role-aware binary capture",
		errors.New("binary input is not supported by the selected path"),
	)
	if err != nil {
		t.Fatal(err)
	}
	fixture := newFoundationFixture(t)
	fixture.application.reviewRuns = &reviewRunFake{err: capture}
	result := fixture.application.Run(context.Background(), []string{"review", "--dirty", "--output", "json"}, testAnchoredRoot(t))
	assertFoundationEnvelope(t, fixture, result, app.ExitCodeArtifact)
	var envelope struct {
		Reasons []struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"reasons"`
	}
	if err := json.Unmarshal(result.Stdout(), &envelope); err != nil {
		t.Fatal(err)
	}
	if len(envelope.Reasons) != 1 || envelope.Reasons[0].Code != "unsupported_content" ||
		!strings.Contains(envelope.Reasons[0].Message, "stage review.capture") ||
		!strings.Contains(envelope.Reasons[0].Message, "role: logic") || !strings.Contains(envelope.Reasons[0].Message, "client/e2e/screenshots/example.png") ||
		!strings.Contains(envelope.Reasons[0].Message, "use role-aware binary capture") {
		t.Fatalf("capture envelope = %#v", envelope)
	}
}

func TestApplicationReviewFailureTaxonomyReportsTheActualPipelineStage(t *testing.T) {
	providerFailure := func(condition review.AttemptCondition, class domain.FailureClass) error {
		t.Helper()
		fact, err := reviewrun.NewProviderExecutionFailure("zcode-logic", domain.RoleLogic, string(condition), class)
		if err != nil {
			t.Fatal(err)
		}
		aggregate := reviewrun.NewProviderExecutionFailuresError([]reviewrun.ProviderExecutionFailure{fact})
		failure, err := domain.NewFailure("reviewrun.execute", class, "provider execution failed", aggregate)
		if err != nil {
			t.Fatal(err)
		}
		return failure
	}
	unsupported, err := ports.NewReviewCaptureFailure(
		ports.ReviewCaptureUnsupported, "screenshots/invalid.png", domain.RoleLogic,
		"use role-aware binary capture", errors.New("invalid PNG signature"),
	)
	if err != nil {
		t.Fatal(err)
	}
	policyBlocked, err := ports.NewReviewCapturePolicyFailure(
		"fixtures/policy.txt", domain.RoleSecurity, "test-policy", "content-policy-v1", errors.New("policy rejected capture"),
	)
	if err != nil {
		t.Fatal(err)
	}
	manifestLarge, err := ports.NewReviewCaptureManifestFailure(9<<20, 8<<20, errors.New("manifest too large"))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name, code, stage, messageFact string
		exit                           app.ExitCode
		err                            error
		provider                       bool
		policyConfig                   bool
	}{
		{name: "capture failed", code: "capture_failed", stage: "review.capture", exit: app.ExitCodeArtifact, err: ports.WrapReviewCaptureFailure(errors.New("snapshot unavailable"))},
		{name: "unsupported content", code: "unsupported_content", stage: "review.capture", exit: app.ExitCodeArtifact, err: unsupported},
		{name: "capture manifest too large", code: "capture_manifest_too_large", stage: "review.capture", exit: app.ExitCodeArtifact, err: manifestLarge},
		{name: "content policy blocked", code: "content_policy_blocked", stage: "review.capture", exit: app.ExitCodeSecurity, err: policyBlocked, policyConfig: true},
		{name: "provider timeout", code: "provider_timeout", stage: "provider.execute", exit: app.ExitCodeReadiness, err: providerFailure(review.AttemptConditionProviderTimeout, domain.FailureTimeout), provider: true},
		{name: "provider permission denied", code: "provider_permission_denied", stage: "provider.execute", exit: app.ExitCodeReadiness, err: providerFailure(review.AttemptConditionProviderPermissionDenied, domain.FailureAuthentication), provider: true},
		{name: "provider output missing", code: "provider_output_missing", stage: "provider.execute", exit: app.ExitCodeReadiness, err: providerFailure(review.AttemptConditionProviderOutputMissing, domain.FailureInvalidOutput), provider: true},
		{name: "provider output decode failed", code: "provider_output_decode_failed", stage: "provider.execute", exit: app.ExitCodeReadiness, err: providerFailure(review.AttemptConditionProviderOutputDecodeFailed, domain.FailureInvalidOutput), provider: true},
		{name: "candidate validation failed", code: "candidate_validation_failed", stage: "provider.execute", exit: app.ExitCodeReadiness, err: providerFailure(review.AttemptConditionSemanticContradiction, domain.FailureInvalidOutput), provider: true},
		{name: "provider spawn failed", code: "provider_spawn_failed", stage: "provider.execute", exit: app.ExitCodeReadiness, err: providerFailure(review.AttemptConditionProviderSpawnFailed, domain.FailureProviderUnavailable), provider: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newFoundationFixture(t)
			fixture.application.reviewRuns = &reviewRunFake{err: test.err}
			result := fixture.application.Run(context.Background(), []string{"review", "--dirty", "--output", "json"}, testAnchoredRoot(t))
			assertFoundationEnvelope(t, fixture, result, test.exit)
			var envelope struct {
				Reasons []struct {
					Code    string `json:"code"`
					Message string `json:"message"`
				} `json:"reasons"`
			}
			if err := json.Unmarshal(result.Stdout(), &envelope); err != nil {
				t.Fatal(err)
			}
			if len(envelope.Reasons) != 1 {
				t.Fatalf("failure taxonomy = %#v, want one reason", envelope.Reasons)
			}
			message := envelope.Reasons[0].Message
			if envelope.Reasons[0].Code != test.code ||
				envelope.Reasons[0].Code == "readiness_unverified" || !strings.Contains(message, "stage "+test.stage) || !strings.Contains(message, "hint:") ||
				test.provider && (!strings.Contains(message, "role=logic") || !strings.Contains(message, "provider=zcode-logic")) ||
				test.policyConfig && !strings.Contains(message, "effective configuration: detector_policy=content-policy-v1; detector_code=test-policy") ||
				test.messageFact != "" && !strings.Contains(message, test.messageFact) {
				t.Fatalf("failure taxonomy = %#v, want code %q at stage %q", envelope.Reasons, test.code, test.stage)
			}
		})
	}
}

func TestCommittedProviderFailureReasonsPreserveEveryTerminalRole(t *testing.T) {
	logic, err := reviewrun.NewProviderExecutionFailure(
		"zcode-logic", domain.RoleLogic, string(review.AttemptConditionProviderOutputMissing), domain.FailureInvalidOutput,
	)
	if err != nil {
		t.Fatal(err)
	}
	security, err := reviewrun.NewProviderExecutionFailure(
		"agy-security", domain.RoleSecurity, string(review.AttemptConditionProviderPermissionDenied), domain.FailureAuthentication,
	)
	if err != nil {
		t.Fatal(err)
	}
	reasons, err := committedProviderFailureReasons([]reviewrun.ProviderExecutionFailure{logic, security})
	if err != nil {
		t.Fatal(err)
	}
	if len(reasons) != 2 || reasons[0].Code() != "provider_output_missing" ||
		!strings.Contains(reasons[0].Message(), "role logic; provider zcode-logic") ||
		reasons[1].Code() != "provider_permission_denied" ||
		!strings.Contains(reasons[1].Message(), "role security; provider agy-security") {
		t.Fatalf("committed provider reasons = %#v", reasons)
	}
}

func TestCommittedProviderTimeoutReasonIncludesConfiguredAndElapsedFacts(t *testing.T) {
	facts, err := review.NewProviderTimeoutFacts(30*time.Minute, 30*time.Minute+125*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	failure, err := reviewrun.NewProviderExecutionFailureWithTimeoutFacts(
		"zcode-logic", domain.RoleLogic, string(review.AttemptConditionProviderTimeout), domain.FailureTimeout, facts,
	)
	if err != nil {
		t.Fatal(err)
	}
	reasons, err := committedProviderFailureReasons([]reviewrun.ProviderExecutionFailure{failure})
	if err != nil {
		t.Fatal(err)
	}
	if len(reasons) != 1 || reasons[0].Code() != "provider_timeout" ||
		!strings.Contains(reasons[0].Message(), "configured timeout 30m") ||
		!strings.Contains(reasons[0].Message(), "elapsed 30m0.125s") ||
		strings.Contains(reasons[0].Message(), "stderr") {
		t.Fatalf("provider timeout reason = %#v", reasons)
	}
}

func TestMergeCommittedReasonDetailsPreservesPolicyAndDuplicateProviderFailures(t *testing.T) {
	first, err := app.NewCommittedReason("provider_output_missing", "first attributed provider failure")
	if err != nil {
		t.Fatal(err)
	}
	second, err := app.NewCommittedReason("provider_output_missing", "second attributed provider failure")
	if err != nil {
		t.Fatal(err)
	}
	merged, err := mergeCommittedReasonDetails(
		[]string{"provider_output_missing", "request_changes_threshold", "provider_output_missing"},
		[]app.CommittedReason{first, second},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(merged) != 3 || merged[0].Message() != first.Message() ||
		merged[1].Code() != "request_changes_threshold" || merged[1].Message() != "" ||
		merged[2].Message() != second.Message() {
		t.Fatalf("merged committed reasons = %#v", merged)
	}
}

func TestApplicationReviewCommittedIncompleteCoveragePreservesEveryTerminalProviderFailure(t *testing.T) {
	logic, err := reviewrun.NewProviderExecutionFailure(
		"zcode-logic", domain.RoleLogic, string(review.AttemptConditionProviderOutputMissing), domain.FailureInvalidOutput,
	)
	if err != nil {
		t.Fatal(err)
	}
	security, err := reviewrun.NewProviderExecutionFailure(
		"agy-security", domain.RoleSecurity, string(review.AttemptConditionProviderPermissionDenied), domain.FailureAuthentication,
	)
	if err != nil {
		t.Fatal(err)
	}
	result := newReviewRunResultWithFailures(
		g006SessionID,
		"r_019f596a-d050-79e7-b2b7-59822f012273",
		".mulgae/runs/manifest.json",
		g006ReviewArtifactURI,
		g008CommittedTerminalExit(t, domain.ExitIncompleteCoverage),
		[]reviewrun.ProviderExecutionFailure{logic, security},
		nil,
	)
	fixture := newFoundationFixture(t)
	fixture.application.reviewRuns = &reviewRunFake{result: result}
	command := fixture.application.Run(context.Background(), []string{"review", "--dirty", "--output", "json"}, testAnchoredRoot(t))
	assertFoundationEnvelope(t, fixture, command, app.ExitCodeReadiness)
	var envelope struct {
		Reasons []struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"reasons"`
	}
	if err := json.Unmarshal(command.Stdout(), &envelope); err != nil {
		t.Fatal(err)
	}
	if len(envelope.Reasons) != 3 || envelope.Reasons[0].Code != "required_role_incomplete" ||
		envelope.Reasons[1].Code != "provider_output_missing" ||
		!strings.Contains(envelope.Reasons[1].Message, "role logic; provider zcode-logic") ||
		envelope.Reasons[2].Code != "provider_permission_denied" ||
		!strings.Contains(envelope.Reasons[2].Message, "role security; provider agy-security") {
		t.Fatalf("committed incomplete reasons = %#v", envelope.Reasons)
	}
}

const (
	g006SessionID         = "s_019f596a-cfe4-7c9c-b82e-7149158243ba"
	g006ReviewArtifactURI = ".mulgae/s_019f596a-cfe4-7c9c-b82e-7149158243ba/r_019f596a-cf80-7c67-b265-f37053d51ccf/review_019f596a-d048-79e7-b2b7-59822f012273.json"
)

type g006QueryFake struct {
	status       RunStatusView
	statusErr    error
	findings     FindingsView
	findingsErr  error
	excerpt      []byte
	excerptErr   error
	resolveErr   error
	resolveRoots []ports.AnchoredRoot
}

type diagnosticQueryFake struct {
	status ports.RuntimeDiagnosticRunStatus
	err    error
}

func (fake diagnosticQueryFake) ReadRunStatus(context.Context, ports.AnchoredRoot, domain.RunID) (ports.RuntimeDiagnosticRunStatus, error) {
	return fake.status, fake.err
}

type g008FollowupFake struct{}

func (g008FollowupFake) StartFollowupRun(context.Context, appfollowup.Request) (StartedRun, error) {
	return StartedRun{}, errors.New("unexpected followup call")
}

type g008DeltaFake struct{}

func (g008DeltaFake) StartDeltaRun(context.Context, appdelta.StartRequest) (StartedRun, error) {
	return StartedRun{}, errors.New("unexpected delta call")
}

type g008RerunFake struct{}

func (g008RerunFake) StartRerun(context.Context, appreplay.Request) (StartedRun, error) {
	return StartedRun{}, errors.New("unexpected rerun call")
}

func g008Dependencies() (FollowupRunService, DeltaRunService, RerunService, RetentionService, RedactedExportService) {
	return g008FollowupFake{}, g008DeltaFake{}, g008RerunFake{},
		RetentionServiceFunc(func(context.Context, RetentionRequest) (RetentionResult, error) {
			return RetentionResult{}, errors.New("unexpected clean call")
		}),
		RedactedExportServiceFunc(func(context.Context, RedactedExportRequest) (RedactedExportResult, error) {
			return RedactedExportResult{}, errors.New("unexpected export call")
		})
}

type g008ResolverFake struct {
	runCalls     []string
	attemptCalls []g008AttemptResolution
	targetCalls  int
	err          error
}

type g008AttemptResolution struct {
	runID    string
	role     string
	provider string
}

func (fake *g008ResolverFake) ResolveRun(_ context.Context, selector string) (string, error) {
	fake.runCalls = append(fake.runCalls, selector)
	if fake.err != nil {
		return "", fake.err
	}
	return testRunID, nil
}

func (fake *g008ResolverFake) ResolveAttempt(_ context.Context, runID, role, provider string) (string, error) {
	fake.attemptCalls = append(fake.attemptCalls, g008AttemptResolution{runID: runID, role: role, provider: provider})
	if fake.err != nil {
		return "", fake.err
	}
	return testAttemptID, nil
}

func (fake *g008ResolverFake) CaptureTarget(context.Context) (string, error) {
	fake.targetCalls++
	if fake.err != nil {
		return "", fake.err
	}
	return "stdin-capture-v1-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", nil
}

func TestApplicationPreservesResolverOperationalFailures(t *testing.T) {
	artifact, err := domain.NewFailure("resolver.read", domain.FailureArtifact, "artifact read failed", errors.New("read failed"))
	if err != nil {
		t.Fatal(err)
	}
	security, err := domain.NewFailure("resolver.read", domain.FailureSecurityPolicy, "resolver policy rejected", errors.New("policy rejected"))
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		err  error
		exit app.ExitCode
	}{
		{name: "cancelled", err: context.Canceled, exit: app.ExitCodeCancellation},
		{name: "artifact", err: artifact, exit: app.ExitCodeArtifact},
		{name: "security", err: security, exit: app.ExitCodeSecurity},
		{name: "internal", err: errors.New("resolver failed"), exit: app.ExitCodeInternal},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newFoundationFixture(t)
			fixture.application.requestResolver = &g008ResolverFake{err: test.err}
			result := fixture.application.Run(context.Background(), []string{"export", "--run", "latest", "--output-path", "export.zip"}, testAnchoredRoot(t))
			if result.ExitCode() != test.exit || len(result.Stdout()) != 0 || len(result.Stderr()) == 0 {
				t.Fatalf("resolver failure result = exit %d stdout %q stderr %q, want exit %d", result.ExitCode(), result.Stdout(), result.Stderr(), test.exit)
			}
		})
	}
}

type g008FollowupE2EFake struct {
	requests                   []appfollowup.Request
	err                        error
	terminalExit               domain.OperationalExitDecision
	resolution                 *domain.FollowupResolution
	structuredExtractionStatus domain.StructuredExtractionStatus
}

func (fake *g008FollowupE2EFake) StartFollowupRun(_ context.Context, request appfollowup.Request) (StartedRun, error) {
	fake.requests = append(fake.requests, request)
	if fake.err != nil {
		return StartedRun{}, fake.err
	}
	runID := "r_019f596a-d050-79e7-b2b7-59822f012273"
	status := fake.structuredExtractionStatus
	if status == "" {
		status = domain.StructuredExtractionStructured
	}
	return StartedRun{
		SessionID:                  g006SessionID,
		RunID:                      runID,
		ArtifactURI:                ".mulgae/followup/new-review.json",
		FollowupResolution:         fake.resolution,
		StructuredExtractionStatus: status,
		TerminalExit:               fake.terminalExit,
		RoleReportURIs: []RoleReportURI{{
			Role: "logic",
			URI:  ".mulgae/" + g006SessionID + "/" + runID + "/role-reports/logic.md",
		}},
	}, nil
}

type g008DeltaE2EFake struct {
	requests     []appdelta.StartRequest
	err          error
	terminalExit domain.OperationalExitDecision
}

func (fake *g008DeltaE2EFake) StartDeltaRun(_ context.Context, request appdelta.StartRequest) (StartedRun, error) {
	fake.requests = append(fake.requests, request)
	if fake.err != nil {
		return StartedRun{}, fake.err
	}
	return StartedRun{
		SessionID:    g006SessionID,
		RunID:        "r_019f596a-d051-79e7-b2b7-59822f012273",
		ArtifactURI:  ".mulgae/delta/new-review.json",
		TerminalExit: fake.terminalExit,
	}, nil
}

type g008RerunE2EFake struct {
	requests     []appreplay.Request
	err          error
	terminalExit domain.OperationalExitDecision
}

func (fake *g008RerunE2EFake) StartRerun(_ context.Context, request appreplay.Request) (StartedRun, error) {
	fake.requests = append(fake.requests, request)
	if fake.err != nil {
		return StartedRun{}, fake.err
	}
	return StartedRun{
		SessionID:    g006SessionID,
		RunID:        "r_019f596a-d052-79e7-b2b7-59822f012273",
		ArtifactURI:  ".mulgae/rerun/prompt-manifest.json",
		TerminalExit: fake.terminalExit,
	}, nil
}

type g008RetentionE2EFake struct {
	requests []RetentionRequest
	err      error
}

func (fake *g008RetentionE2EFake) CleanRuns(_ context.Context, request RetentionRequest) (RetentionResult, error) {
	fake.requests = append(fake.requests, request)
	if fake.err != nil {
		return RetentionResult{}, fake.err
	}
	return RetentionResult{
		DryRun:           request.DryRun,
		AffectedRunCount: 3,
		AffectedBytes:    8192,
	}, nil
}

type g008ExportE2EFake struct {
	requests []RedactedExportRequest
	err      error
}

func (fake *g008ExportE2EFake) ExportRedactedRun(_ context.Context, request RedactedExportRequest) (RedactedExportResult, error) {
	fake.requests = append(fake.requests, request)
	if fake.err != nil {
		return RedactedExportResult{}, fake.err
	}
	return RedactedExportResult{
		ExportManifestURI: ".mulgae/exports/manifest.json",
		BundleURI:         request.OutputPath,
		Redacted:          true,
	}, nil
}

type g008WorkflowFakes struct {
	resolver  *g008ResolverFake
	followup  *g008FollowupE2EFake
	delta     *g008DeltaE2EFake
	rerun     *g008RerunE2EFake
	retention *g008RetentionE2EFake
	export    *g008ExportE2EFake
}

func newG008WorkflowFakes(t *testing.T) g008WorkflowFakes {
	t.Helper()
	stillOpen := domain.FollowupStillOpen
	return g008WorkflowFakes{
		resolver: &g008ResolverFake{},
		followup: &g008FollowupE2EFake{
			resolution:                 &stillOpen,
			structuredExtractionStatus: domain.StructuredExtractionStructured,
			terminalExit:               g008CommittedTerminalExit(t, domain.ExitCommittedCIRejected),
		},
		delta:     &g008DeltaE2EFake{terminalExit: g008CommittedTerminalExit(t, domain.ExitCommittedPass)},
		rerun:     &g008RerunE2EFake{terminalExit: g008CommittedTerminalExit(t, domain.ExitIncompleteCoverage)},
		retention: &g008RetentionE2EFake{},
		export:    &g008ExportE2EFake{},
	}
}

func g008CommittedTerminalExit(t *testing.T, code domain.OperationalExitCode) domain.OperationalExitDecision {
	t.Helper()
	reasonCode := "policy_evaluated"
	switch code {
	case domain.ExitCommittedCIRejected:
		reasonCode = "request_changes_threshold"
	case domain.ExitIncompleteCoverage:
		reasonCode = "required_role_incomplete"
	}
	reason, err := domain.NewExitReason(code, reasonCode)
	if err != nil {
		t.Fatal(err)
	}
	input, err := domain.NewOperationalExitInput([]domain.ExitReason{reason})
	if err != nil {
		t.Fatal(err)
	}
	decision, err := domain.ReduceOperationalExit(input)
	if err != nil {
		t.Fatal(err)
	}
	return decision
}

type g008RequestResolver struct{}

func (g008RequestResolver) ResolveRun(context.Context, string) (string, error) {
	return testRunID, nil
}

func (g008RequestResolver) ResolveAttempt(context.Context, string, string, string) (string, error) {
	return "a_019f596a-cf80-7c67-b265-f37053d51ccf", nil
}

func (g008RequestResolver) CaptureTarget(context.Context) (string, error) {
	return "stdin-capture-v1-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", nil
}

func (fake *g006QueryFake) ResolveRun(_ context.Context, root ports.AnchoredRoot, runID domain.RunID) (ports.PublicationRun, error) {
	fake.resolveRoots = append(fake.resolveRoots, root)
	if fake.resolveErr != nil {
		return ports.PublicationRun{}, fake.resolveErr
	}
	sessionID, err := domain.ParseSessionID(g006SessionID)
	if err != nil {
		return ports.PublicationRun{}, err
	}
	return ports.NewPublicationRun(root, sessionID, runID)
}

func (fake *g006QueryFake) ReadRunStatus(_ context.Context, _ ports.PublicationRun) (RunStatusView, error) {
	return fake.status, fake.statusErr
}

func (fake *g006QueryFake) ListFindings(_ context.Context, _ ports.PublicationRun, _ domain.Severity) (FindingsView, error) {
	return fake.findings, fake.findingsErr
}

func (fake *g006QueryFake) RenderExcerpt(_ context.Context, _ ports.PublicationRun, _ string, _ string) ([]byte, error) {
	return cloneApplicationBytes(fake.excerpt), fake.excerptErr
}

type g006ReportFake struct {
	rendered RenderedReport
	err      error
	calls    int
}

func (fake *g006ReportFake) Render(_ context.Context, _ ports.PublicationRun) (RenderedReport, error) {
	fake.calls++
	return RenderedReport{
		Markdown:  cloneApplicationBytes(fake.rendered.Markdown),
		RunID:     fake.rendered.RunID,
		SourceIDs: cloneApplicationStrings(fake.rendered.SourceIDs),
	}, fake.err
}

func TestApplicationG006CommandsHumanAndJSON(t *testing.T) {
	query := newG006QueryFake()
	report := newG006ReportFake()
	fixture := newG006Fixture(t, query, report)
	root := testAnchoredRoot(t)

	human := []struct {
		name string
		argv []string
		want []byte
	}{
		{
			name: "status",
			argv: []string{"status", "--run", testRunID},
			want: expectedTextOutput([]byte(
				"run_id: " + testRunID +
					"\nrun_state: completed" +
					"\npublication_status: committed" +
					"\nrecovery_action: reconstruct_completed_status" +
					"\nfinal_artifact_uri: " + g006ReviewArtifactURI +
					"\ncontent_verdict: request_changes" +
					"\ncoverage_status: complete" +
					"\nci_decision: fail",
			)),
		},
		{
			name: "report",
			argv: []string{"report", "--run", testRunID, "--output-path", "reports/human.md"},
			want: expectedTextOutput([]byte("report rendered: reports/human.md")),
		},
		{
			name: "findings",
			argv: []string{"findings", "--run", testRunID, "--severity", "high"},
			want: expectedTextOutput([]byte(
				"review_artifact_uri: " + g006ReviewArtifactURI +
					"\nfinding_count: 2" +
					"\nF002 [high] Second in query order" +
					"\nF001 [critical] First in query order",
			)),
		},
		{
			name: "excerpt",
			argv: []string{"excerpt", "--run", testRunID, "--finding", "F001", "--current-target-sha256", testCurrentTargetSHA256},
			want: []byte("line one\nline two\n\n"),
		},
	}
	for _, test := range human {
		t.Run(test.name+"_human", func(t *testing.T) {
			result := fixture.application.Run(context.Background(), test.argv, root)
			if result.ExitCode() != app.ExitCodeSuccess || len(result.Stderr()) != 0 || !bytes.Equal(result.Stdout(), test.want) {
				t.Fatalf("%s human result = exit %d stdout %q stderr %q", test.name, result.ExitCode(), result.Stdout(), result.Stderr())
			}
		})
	}

	machine := []struct {
		name string
		argv []string
		kind string
	}{
		{name: "status", argv: []string{"status", "--run", testRunID, "--output", "json"}, kind: "status_read"},
		{name: "report", argv: []string{"report", "--run", testRunID, "--output-path", "reports/machine.md", "--output", "json"}, kind: "report_rendered"},
		{name: "findings", argv: []string{"findings", "--run", testRunID, "--severity", "high", "--output", "json"}, kind: "findings_listed"},
		{name: "excerpt", argv: []string{"excerpt", "--run", testRunID, "--finding", "F001", "--current-target-sha256", testCurrentTargetSHA256, "--output", "json"}, kind: "excerpt_rendered"},
	}
	for _, test := range machine {
		t.Run(test.name+"_json", func(t *testing.T) {
			result := fixture.application.Run(context.Background(), test.argv, root)
			assertFoundationEnvelope(t, fixture, result, app.ExitCodeSuccess)
			if got := commandResultKind(t, result.Stdout()); got != test.kind {
				t.Fatalf("%s JSON kind = %q, want %q", test.name, got, test.kind)
			}
			if test.name == "status" {
				assertG006StatusAxes(t, result.Stdout())
			}
			if test.name == "excerpt" {
				assertG006ExcerptBytes(t, result.Stdout(), []byte("line one\nline two\n\n"))
			}
		})
	}

	for _, artifactRoot := range query.resolveRoots {
		if got, want := artifactRoot.String(), filepath.Join(root, ".mulgae"); got != want {
			t.Fatalf("publication root = %q, want %q", got, want)
		}
	}
}

func TestApplicationStatusReadsDiagnosticOnlyRunWhenPublicationIsAbsent(t *testing.T) {
	query := &g006QueryFake{resolveErr: ports.ErrPublicationRunNotFound}
	fixture := newG006Fixture(t, query, &g006ReportFake{})
	sessionID, _ := domain.ParseSessionID(g006SessionID)
	runID, _ := domain.ParseRunID(testRunID)
	now := time.Date(2026, time.July, 23, 6, 0, 0, 0, time.UTC)
	status, err := ports.NewRuntimeDiagnosticRunStatus(ports.RuntimeDiagnosticRunStatusInput{
		SessionID: sessionID, RunID: runID, State: domain.RunFailed, StartedAt: now, UpdatedAt: now.Add(time.Second),
		CompletedAt: now.Add(time.Second), HasCompletedAt: true, SelectedRoles: []domain.Role{domain.RoleTesting},
		RolePathTotal: 1, RolePathFailed: 1, LastSequence: 12, TerminalCause: domain.DiagnosticCauseProviderSpawnFailed,
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture.application.diagnosticQueries = diagnosticQueryFake{status: status}
	result := fixture.application.Run(context.Background(), []string{"status", "--run", testRunID, "--output", "json"}, testAnchoredRoot(t))
	assertFoundationEnvelope(t, fixture, result, app.ExitCodeSuccess)
	if got := commandResultKind(t, result.Stdout()); got != "diagnostic_status_read" {
		t.Fatalf("diagnostic status kind = %q", got)
	}
	var envelope struct {
		Result struct {
			DiagnosticOnly       bool    `json:"diagnostic_only"`
			PublicationAuthority bool    `json:"publication_authority"`
			TerminalCause        *string `json:"terminal_cause"`
			TerminalPhase        *string `json:"terminal_phase"`
			RecoveryAction       string  `json:"recovery_action"`
		} `json:"result"`
	}
	if err := json.Unmarshal(result.Stdout(), &envelope); err != nil {
		t.Fatal(err)
	}
	if !envelope.Result.DiagnosticOnly || envelope.Result.PublicationAuthority ||
		envelope.Result.TerminalCause == nil || *envelope.Result.TerminalCause != string(domain.DiagnosticCauseProviderSpawnFailed) ||
		envelope.Result.TerminalPhase != nil || envelope.Result.RecoveryAction != "rerun_review" {
		t.Fatalf("diagnostic status envelope = %#v", envelope.Result)
	}
}

func TestApplicationG006StatusDoesNotDiscloseNonP2Paths(t *testing.T) {
	tests := []struct {
		name   string
		status RunStatusView
		err    error
		exit   app.ExitCode
	}{
		{
			name: "P0 staged",
			status: RunStatusView{
				RunID: testRunID, PublicationState: domain.PublicationStaged,
				RecoveryAction: domain.RecoveryActionInstallStagedFinal,
			},
			exit: app.ExitCodeSuccess,
		},
		{
			name: "P1 installed",
			status: RunStatusView{
				RunID: testRunID, PublicationState: domain.PublicationInstalled,
				RecoveryAction: domain.RecoveryActionCommitCompositeEpoch,
			},
			exit: app.ExitCodeSuccess,
		},
		{
			name: "corrupt",
			status: RunStatusView{
				RunID: testRunID, PublicationState: domain.PublicationCorrupt,
				RecoveryAction: domain.RecoveryActionEmitImmutableCorruptionDiagnostic,
			},
			err:  mustG006ArtifactFailure(t),
			exit: app.ExitCodeArtifact,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			query := newG006QueryFake()
			query.status = test.status
			query.statusErr = test.err
			fixture := newG006Fixture(t, query, newG006ReportFake())
			root := testAnchoredRoot(t)

			human := fixture.application.Run(context.Background(), []string{"status", "--run", testRunID}, root)
			if human.ExitCode() != test.exit || strings.Contains(string(human.Stdout()), "review_") ||
				strings.Contains(string(human.Stdout()), "content_verdict") {
				t.Fatalf("human status = exit %d stdout %q", human.ExitCode(), human.Stdout())
			}
			machine := fixture.application.Run(context.Background(), []string{"status", "--run", testRunID, "--output", "json"}, root)
			assertFoundationEnvelope(t, fixture, machine, test.exit)
			if strings.Contains(string(machine.Stdout()), "review_") || strings.Contains(string(machine.Stdout()), "content_verdict") {
				t.Fatalf("JSON status disclosed P2 data: %q", machine.Stdout())
			}
			if test.err != nil {
				assertG006StatusFailureHasNoAuthority(t, machine.Stdout())
			}
		})
	}
}

func TestStatusResultDataRejectsIncoherentPublicationPairs(t *testing.T) {
	invocation := mustParse(t, []string{"status", "--run", testRunID})
	request, ok := invocation.Status()
	if !ok {
		t.Fatal("parsed invocation omitted status request")
	}
	committedCancelled := newG006QueryFake().status
	committedCancelled.RunState = domain.RunCancelled
	tests := []struct {
		name   string
		status RunStatusView
	}{
		{
			name: "not published with none",
			status: RunStatusView{
				RunID: testRunID, PublicationState: domain.PublicationNotPublished,
				RecoveryAction: domain.RecoveryActionNone,
			},
		},
		{
			name: "staged with resume",
			status: RunStatusView{
				RunID: testRunID, PublicationState: domain.PublicationStaged,
				RecoveryAction: domain.RecoveryActionResumeCollection,
			},
		},
		{
			name: "installed with none",
			status: RunStatusView{
				RunID: testRunID, PublicationState: domain.PublicationInstalled,
				RecoveryAction: domain.RecoveryActionNone,
			},
		},
		{name: "committed cancelled run", status: committedCancelled},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := statusResultData(request, test.status); err == nil {
				t.Fatal("statusResultData accepted an incoherent publication projection")
			}
		})
	}
}

func TestStatusResultDataUsesSessionScopedRoleReportURIs(t *testing.T) {
	t.Parallel()
	invocation := mustParse(t, []string{"status", "--run", testRunID})
	request, ok := invocation.Status()
	if !ok {
		t.Fatal("parsed invocation omitted status request")
	}
	uri := ".mulgae/" + g006SessionID + "/" + testRunID + "/role-reports/logic.md"
	status := newG006QueryFake().status
	status.RoleReportURIs = []RoleReportURI{{Role: "logic", URI: uri}}
	data, err := statusResultData(request, status)
	if err != nil {
		t.Fatalf("statusResultData() error = %v", err)
	}
	if !bytes.Contains(data, []byte(`"role_report_uris"`)) || !bytes.Contains(data, []byte(uri)) {
		t.Fatalf("P2 status omitted session-scoped role report URIs: %s", data)
	}
	status.SessionID = ""
	if _, err := statusResultData(request, status); err == nil {
		t.Fatal("statusResultData accepted P2 role report URIs without SessionID")
	}
	status = newG006QueryFake().status
	status.PublicationState = domain.PublicationStaged
	status.RecoveryAction = domain.RecoveryActionInstallStagedFinal
	status.HasRunState = false
	status.RunState = ""
	status.HasFinalArtifact = false
	status.FinalArtifactURI = ""
	status.HasAxes = false
	status.ContentVerdict = ""
	status.CoverageStatus = ""
	status.CIDecision = ""
	status.RoleReportURIs = []RoleReportURI{{Role: "logic", URI: uri}}
	if _, err := statusResultData(request, status); err == nil {
		t.Fatal("statusResultData accepted role report URIs on non-P2 status")
	}
	status.RoleReportURIs = nil
	data, err = statusResultData(request, status)
	if err != nil {
		t.Fatalf("non-P2 statusResultData() error = %v", err)
	}
	if bytes.Contains(data, []byte(`"role_report_uris"`)) {
		t.Fatalf("non-P2 status exposed role_report_uris: %s", data)
	}
}

func TestApplicationG006ReportWritesOnceAndDoesNotReplace(t *testing.T) {
	query := newG006QueryFake()
	report := newG006ReportFake()
	fixture := newG006Fixture(t, query, report)
	root := testAnchoredRoot(t)
	argv := []string{"report", "--run", testRunID, "--output-path", "reports/review.md"}

	first := fixture.application.Run(context.Background(), argv, root)
	if first.ExitCode() != app.ExitCodeSuccess {
		t.Fatalf("first report = exit %d stdout %q stderr %q", first.ExitCode(), first.Stdout(), first.Stderr())
	}
	contents, err := os.ReadFile(filepath.Join(root, "reports", "review.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(contents, report.rendered.Markdown) {
		t.Fatalf("report bytes = %q, want %q", contents, report.rendered.Markdown)
	}
	if len(fixture.writer.requests) != 1 || len(fixture.writer.receipts) != 1 {
		t.Fatalf("first report writes = requests %d receipts %d", len(fixture.writer.requests), len(fixture.writer.receipts))
	}

	second := fixture.application.Run(context.Background(), argv, root)
	if second.ExitCode() != app.ExitCodeArtifact || len(second.Stdout()) != 0 || len(second.Stderr()) == 0 {
		t.Fatalf("second report = exit %d stdout %q stderr %q", second.ExitCode(), second.Stdout(), second.Stderr())
	}
	if len(fixture.writer.requests) != 2 || len(fixture.writer.receipts) != 1 {
		t.Fatalf("replacement report writes = requests %d receipts %d", len(fixture.writer.requests), len(fixture.writer.receipts))
	}
}

func TestApplicationG006ReportRejectsReservedControlNamespaces(t *testing.T) {
	for _, outputPath := range []string{
		".mulgae/reports/review.md",
		".Mulgae/reports/review.md",
		".git/reports/review.md",
		".Git/reports/review.md",
		".gjc/reports/review.md",
		".GJC/reports/review.md",
	} {
		t.Run(outputPath, func(t *testing.T) {
			query := newG006QueryFake()
			report := newG006ReportFake()
			fixture := newG006Fixture(t, query, report)

			result := fixture.application.Run(
				context.Background(),
				[]string{"report", "--run", testRunID, "--output-path", outputPath},
				testAnchoredRoot(t),
			)
			if result.ExitCode() != app.ExitCodeUsage || len(result.Stdout()) != 0 || len(result.Stderr()) == 0 {
				t.Fatalf("reserved report destination = exit %d stdout %q stderr %q", result.ExitCode(), result.Stdout(), result.Stderr())
			}
			if report.calls != 0 || len(fixture.writer.requests) != 0 {
				t.Fatalf("reserved report destination invoked report=%d writes=%d", report.calls, len(fixture.writer.requests))
			}
		})
	}
}

func TestPersistReportMarkdownRejectsReservedDestinationWithoutWriterIO(t *testing.T) {
	fixture := newG006Fixture(t, newG006QueryFake(), newG006ReportFake())
	root, err := ports.NewAnchoredRoot(testAnchoredRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	destination, err := ports.NewSafeRelativePath(".Mulgae/reports/review.md")
	if err != nil {
		t.Fatal(err)
	}
	_, err = fixture.application.persistReportMarkdown(
		context.Background(),
		root,
		destination,
		[]string{"report:test"},
		[]byte("# report\n"),
	)
	var failure *domain.Failure
	if !errors.As(err, &failure) || failure.Class() != domain.FailureConfiguration {
		t.Fatalf("reserved direct report failure = %v", err)
	}
	if len(fixture.writer.requests) != 0 {
		t.Fatalf("reserved direct report writes = %d, want 0", len(fixture.writer.requests))
	}
}

func TestPersistReportMarkdownPreservesDualWriterFailurePrecedence(t *testing.T) {
	sourceIDs := []string{"report:test"}
	drop, err := ports.NewDropMetadata("report_markdown", "test_rejection", 1, sourceIDs)
	if err != nil {
		t.Fatal(err)
	}
	writer := &controlledFoundationWriter{
		drop:        &drop,
		writeErr:    mustG006Failure(t, domain.FailureArtifact),
		abortCause:  mustG006Failure(t, domain.FailureInternal),
		invokeAbort: true,
	}
	fixture := newFoundationFixtureWithWriter(t, writer)
	root, err := ports.NewAnchoredRoot(testAnchoredRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	destination, err := ports.NewSafeRelativePath("reports/review.md")
	if err != nil {
		t.Fatal(err)
	}
	_, err = fixture.application.persistReportMarkdown(
		context.Background(),
		root,
		destination,
		sourceIDs,
		[]byte("# report\n"),
	)
	projected := executionFailureFor(app.CommandReport, err, domain.FailureArtifact)
	if projected.class != domain.FailureInternal || projected.exit != app.ExitCodeInternal {
		t.Fatalf("dual writer failure = %s/exit %d, want internal/10", projected.class, projected.exit)
	}
}

func TestG006OperationalFailureExitsAreNotCoerced(t *testing.T) {
	cases := []struct {
		command app.CommandName
		class   domain.FailureClass
		exit    app.ExitCode
	}{
		{command: app.CommandStatus, class: domain.FailureSecurityPolicy, exit: app.ExitCodeSecurity},
		{command: app.CommandReport, class: domain.FailureCancelled, exit: app.ExitCodeCancellation},
		{command: app.CommandFindings, class: domain.FailureInternal, exit: app.ExitCodeInternal},
		{command: app.CommandExcerpt, class: domain.FailureSecurityPolicy, exit: app.ExitCodeSecurity},
	}
	for _, test := range cases {
		t.Run(string(test.command), func(t *testing.T) {
			err, createErr := domain.NewFailure("test.G006", test.class, "operational failure", nil)
			if createErr != nil {
				t.Fatal(createErr)
			}
			if failure := executionFailureFor(test.command, err, domain.FailureArtifact); failure.exit != test.exit {
				t.Fatalf("executionFailureFor(%s, %s) exit = %d, want %d", test.command, test.class, failure.exit, test.exit)
			}
		})
	}
}

func TestProjectLocalCommandCancellationExitsAreNotCoerced(t *testing.T) {
	for _, command := range []app.CommandName{app.CommandInit, app.CommandConfig, app.CommandDoctor} {
		for _, cancellation := range []error{context.Canceled, context.DeadlineExceeded} {
			t.Run(string(command)+"/"+cancellation.Error(), func(t *testing.T) {
				failure := executionFailureFor(command, cancellation, domain.FailureSecurityPolicy)
				if failure.class != domain.FailureCancelled || failure.exit != app.ExitCodeCancellation || !permittedFailureExit(command, failure.exit) || projectedFailureExit(command, failure.exit) != app.ExitCodeCancellation {
					t.Fatalf("cancellation projection = class %s exit %d", failure.class, failure.exit)
				}
			})
		}
	}
}

func TestExecutionFailurePreservesClosedLocalityReason(t *testing.T) {
	cause := ports.NewConfigLocalityViolation(ports.ConfigLocalityTargetPrivateConfigForbidden, nil)
	err, createErr := domain.NewFailure("review.composition", domain.FailureSecurityPolicy, string(ports.ConfigLocalityTargetPrivateConfigForbidden), cause)
	if createErr != nil {
		t.Fatal(createErr)
	}
	failure := executionFailureFor(app.CommandReview, err, domain.FailureArtifact)
	if failure.code != string(ports.ConfigLocalityTargetPrivateConfigForbidden) || failure.exit != app.ExitCodeSecurity {
		t.Fatalf("failure = %s/exit %d", failure.code, failure.exit)
	}
}

func TestLiveFailureReductionUsesOperationalPrecedenceInBothJoinOrders(t *testing.T) {
	classes := []domain.FailureClass{
		domain.FailureInternal,
		domain.FailureSecurityPolicy,
		domain.FailureArtifact,
		domain.FailureCancelled,
		domain.FailureConfiguration,
		domain.FailureProviderUnavailable,
		domain.FailureTimeout,
		domain.FailureAuthentication,
		domain.FailureQuota,
		domain.FailureRateLimit,
		domain.FailureInvalidOutput,
	}
	for firstIndex, first := range classes {
		for _, second := range classes[firstIndex+1:] {
			firstRank := app.FailurePrecedence(first)
			secondRank := app.FailurePrecedence(second)
			if firstRank == secondRank {
				continue
			}
			want := first
			if secondRank > firstRank {
				want = second
			}
			for _, failures := range [][]error{
				{mustG006Failure(t, first), mustG006Failure(t, second)},
				{mustG006Failure(t, second), mustG006Failure(t, first)},
			} {
				got := reducedFailureClass(errors.Join(failures...), domain.FailureArtifact)
				if got != want {
					t.Errorf("reduced class for %q/%q = %q, want %q", first, second, got, want)
				}
			}
		}
	}
}

func TestG006OperationalFailureExitPrecedence(t *testing.T) {
	internal := mustG006Failure(t, domain.FailureInternal)
	artifact := mustG006Failure(t, domain.FailureArtifact)
	security := mustG006Failure(t, domain.FailureSecurityPolicy)
	configuration := mustG006Failure(t, domain.FailureConfiguration)
	readiness := mustG006Failure(t, domain.FailureProviderUnavailable)
	tests := []struct {
		name string
		err  error
		exit app.ExitCode
	}{
		{name: "internal over all", err: errors.Join(context.Canceled, security, artifact, internal), exit: app.ExitCodeInternal},
		{name: "security over artifact and cancellation", err: errors.Join(context.Canceled, security, artifact), exit: app.ExitCodeSecurity},
		{name: "raw cleanup observation over cancellation", err: errors.Join(context.Canceled, errors.New("temporary cleanup durability observation failed")), exit: app.ExitCodeArtifact},
		{name: "security over cancellation", err: errors.Join(context.Canceled, security), exit: app.ExitCodeSecurity},
		{name: "cancellation over configuration", err: errors.Join(configuration, context.Canceled), exit: app.ExitCodeCancellation},
		{name: "configuration over readiness", err: errors.Join(readiness, configuration), exit: app.ExitCodeUsage},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			failure := executionFailureFor(app.CommandExcerpt, test.err, domain.FailureArtifact)
			if failure.exit != test.exit {
				t.Fatalf("exit = %d, want %d", failure.exit, test.exit)
			}
		})
	}
}
func TestApplicationG006FailureParityAcrossCommands(t *testing.T) {
	failures := []struct {
		name  string
		class domain.FailureClass
		err   func(*testing.T) error
		exit  app.ExitCode
	}{
		{
			name:  "artifact",
			class: domain.FailureArtifact,
			err: func(t *testing.T) error {
				return mustG006Failure(t, domain.FailureArtifact)
			},
			exit: app.ExitCodeArtifact,
		},
		{
			name:  "security",
			class: domain.FailureSecurityPolicy,
			err: func(t *testing.T) error {
				return mustG006Failure(t, domain.FailureSecurityPolicy)
			},
			exit: app.ExitCodeSecurity,
		},
		{
			name:  "cancellation",
			class: domain.FailureCancelled,
			err: func(*testing.T) error {
				return context.Canceled
			},
			exit: app.ExitCodeCancellation,
		},
		{
			name:  "joined_internal",
			class: domain.FailureInternal,
			err: func(t *testing.T) error {
				return errors.Join(context.Canceled, mustG006Failure(t, domain.FailureInternal))
			},
			exit: app.ExitCodeInternal,
		},
	}
	commands := []struct {
		name           string
		command        app.CommandName
		argv           []string
		failedKind     string
		redactedFields []string
		inject         func(*g006QueryFake, *g006ReportFake, error)
	}{
		{
			name:           "status",
			command:        app.CommandStatus,
			argv:           []string{"status", "--run", testRunID},
			failedKind:     "status_failed",
			redactedFields: []string{"run_state", "publication_status", "recovery_action", "final_artifact_uri"},
			inject: func(query *g006QueryFake, _ *g006ReportFake, err error) {
				query.statusErr = err
			},
		},
		{
			name:           "report",
			command:        app.CommandReport,
			argv:           []string{"report", "--run", testRunID, "--output-path", "reports/failure.md"},
			failedKind:     "report_failed",
			redactedFields: []string{"report_uri"},
			inject: func(_ *g006QueryFake, report *g006ReportFake, err error) {
				report.err = err
			},
		},
		{
			name:           "findings",
			command:        app.CommandFindings,
			argv:           []string{"findings", "--run", testRunID, "--severity", "high"},
			failedKind:     "findings_failed",
			redactedFields: []string{"finding_count", "review_artifact_uri"},
			inject: func(query *g006QueryFake, _ *g006ReportFake, err error) {
				query.findingsErr = err
			},
		},
		{
			name:           "excerpt",
			command:        app.CommandExcerpt,
			argv:           []string{"excerpt", "--run", testRunID, "--finding", "F001", "--current-target-sha256", testCurrentTargetSHA256},
			failedKind:     "excerpt_failed",
			redactedFields: []string{"excerpt_uri", "excerpt_base64", "excerpt_sha256"},
			inject: func(query *g006QueryFake, _ *g006ReportFake, err error) {
				query.excerptErr = err
			},
		},
	}
	for _, command := range commands {
		for _, failure := range failures {
			t.Run(command.name+"_"+failure.name, func(t *testing.T) {
				query := newG006QueryFake()
				report := newG006ReportFake()
				command.inject(query, report, failure.err(t))
				fixture := newG006Fixture(t, query, report)
				root := testAnchoredRoot(t)

				human := fixture.application.Run(context.Background(), command.argv, root)
				if human.ExitCode() != failure.exit || len(human.Stdout()) != 0 ||
					!strings.Contains(string(human.Stderr()), humanFailureMessage(failure.class)) ||
					!strings.Contains(string(human.Stderr()), "stage: cli."+string(command.command)) ||
					!strings.Contains(string(human.Stderr()), "hint:") {
					t.Fatalf("human failure = exit %d stdout %q stderr %q", human.ExitCode(), human.Stdout(), human.Stderr())
				}

				jsonArguments := append(cloneApplicationStrings(command.argv), "--output", "json")
				machine := fixture.application.Run(context.Background(), jsonArguments, root)
				assertFoundationEnvelope(t, fixture, machine, failure.exit)
				if len(machine.Stderr()) != 0 {
					t.Fatalf("JSON failure stderr = %q, want empty", machine.Stderr())
				}
				if got := commandResultKind(t, machine.Stdout()); got != command.failedKind {
					t.Fatalf("failure kind = %q, want %q", got, command.failedKind)
				}
				assertG006FailureProjectionRedacted(t, machine.Stdout(), command.redactedFields)
				if !permittedFailureExit(command.command, machine.ExitCode()) {
					t.Fatalf("exit %d is not permitted for %s", machine.ExitCode(), command.command)
				}
			})
		}
	}
}

func TestApplicationG006ResolveRunPreservesTypedFailures(t *testing.T) {
	tests := []struct {
		name string
		err  error
		exit app.ExitCode
	}{
		{name: "cancellation", err: context.Canceled, exit: app.ExitCodeCancellation},
		{name: "security", err: mustG006Failure(t, domain.FailureSecurityPolicy), exit: app.ExitCodeSecurity},
		{name: "configuration", err: mustG006Failure(t, domain.FailureConfiguration), exit: app.ExitCodeUsage},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			query := newG006QueryFake()
			query.resolveErr = test.err
			fixture := newG006Fixture(t, query, newG006ReportFake())
			root := testAnchoredRoot(t)

			human := fixture.application.Run(context.Background(), []string{"status", "--run", testRunID}, root)
			if human.ExitCode() != test.exit {
				t.Fatalf("human exit = %d, want %d", human.ExitCode(), test.exit)
			}
			machine := fixture.application.Run(
				context.Background(),
				[]string{"status", "--run", testRunID, "--output", "json"},
				root,
			)
			assertFoundationEnvelope(t, fixture, machine, test.exit)
			if got := commandResultKind(t, machine.Stdout()); got != "status_failed" {
				t.Fatalf("failure kind = %q, want status_failed", got)
			}
		})
	}
}

func TestApplicationG006ReportWriteCancellationUsesExitNine(t *testing.T) {
	writer := &controlledFoundationWriter{
		writeErr:    errors.Join(context.Canceled, filesystem.ErrContextCancelled),
		abortCause:  context.Canceled,
		invokeAbort: true,
	}
	fixture := newG006FixtureWithWriter(t, newG006QueryFake(), newG006ReportFake(), writer)
	root := testAnchoredRoot(t)
	for _, test := range []struct {
		name string
		argv []string
		json bool
	}{
		{name: "human", argv: []string{"report", "--run", testRunID, "--output-path", "reports/cancelled.md"}},
		{name: "json", argv: []string{"report", "--run", testRunID, "--output-path", "reports/cancelled.md", "--output", "json"}, json: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := fixture.application.Run(context.Background(), test.argv, root)
			if result.ExitCode() != app.ExitCodeCancellation {
				t.Fatalf("exit = %d, want %d; stdout = %q; stderr = %q", result.ExitCode(), app.ExitCodeCancellation, result.Stdout(), result.Stderr())
			}
			if test.json {
				assertFoundationEnvelope(t, fixture, result, app.ExitCodeCancellation)
				if got := commandResultKind(t, result.Stdout()); got != "report_failed" {
					t.Fatalf("failure kind = %q, want report_failed", got)
				}
			}
		})
	}
	if writer.abortCalls != 2 {
		t.Fatalf("abort calls = %d, want 2", writer.abortCalls)
	}
}
func TestApplicationG006ReportWriteCancellationWithCleanupFailureUsesExitSeven(t *testing.T) {
	writer := &controlledFoundationWriter{
		writeErr:    errors.Join(context.Canceled, errors.New("temporary cleanup durability observation failed")),
		abortCause:  context.Canceled,
		invokeAbort: true,
	}
	fixture := newG006FixtureWithWriter(t, newG006QueryFake(), newG006ReportFake(), writer)
	root := testAnchoredRoot(t)
	for _, test := range []struct {
		name string
		argv []string
		json bool
	}{
		{name: "human", argv: []string{"report", "--run", testRunID, "--output-path", "reports/cleanup-failed.md"}},
		{name: "json", argv: []string{"report", "--run", testRunID, "--output-path", "reports/cleanup-failed.md", "--output", "json"}, json: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := fixture.application.Run(context.Background(), test.argv, root)
			if result.ExitCode() != app.ExitCodeArtifact {
				t.Fatalf("exit = %d, want %d; stdout = %q; stderr = %q", result.ExitCode(), app.ExitCodeArtifact, result.Stdout(), result.Stderr())
			}
			if test.json {
				assertFoundationEnvelope(t, fixture, result, app.ExitCodeArtifact)
				if got := commandResultKind(t, result.Stdout()); got != "report_failed" {
					t.Fatalf("failure kind = %q, want report_failed", got)
				}
			}
		})
	}
	if writer.abortCalls != 2 {
		t.Fatalf("abort calls = %d, want 2", writer.abortCalls)
	}
}

func TestG006CommandSchemaRejectsAuthorityAndBase64Lies(t *testing.T) {
	query := newG006QueryFake()
	fixture := newG006Fixture(t, query, newG006ReportFake())
	root := testAnchoredRoot(t)
	committedStatus := fixture.application.Run(
		context.Background(),
		[]string{"status", "--run", testRunID, "--output", "json"},
		root,
	)
	assertFoundationEnvelope(t, fixture, committedStatus, app.ExitCodeSuccess)
	query.status = RunStatusView{
		RunID:            testRunID,
		PublicationState: domain.PublicationStaged,
		RecoveryAction:   domain.RecoveryActionInstallStagedFinal,
	}
	status := fixture.application.Run(
		context.Background(),
		[]string{"status", "--run", testRunID, "--output", "json"},
		root,
	)
	assertFoundationEnvelope(t, fixture, status, app.ExitCodeSuccess)
	excerpt := fixture.application.Run(
		context.Background(),
		[]string{"excerpt", "--run", testRunID, "--finding", "F001", "--current-target-sha256", testCurrentTargetSHA256, "--output", "json"},
		root,
	)
	assertFoundationEnvelope(t, fixture, excerpt, app.ExitCodeSuccess)
	schema := mustFoundationAssetID(t, commandSchemaID)

	mutate := func(raw []byte, change func(map[string]any)) []byte {
		t.Helper()
		var document map[string]any
		if err := json.Unmarshal(raw, &document); err != nil {
			t.Fatal(err)
		}
		change(document["result"].(map[string]any))
		changed, err := json.Marshal(document)
		if err != nil {
			t.Fatal(err)
		}
		return changed
	}
	cases := []struct {
		name string
		raw  []byte
	}{
		{
			name: "non-P2 final URI",
			raw: mutate(status.Stdout(), func(result map[string]any) {
				result["final_artifact_uri"] = g006ReviewArtifactURI
			}),
		},
		{
			name: "exit-zero corrupt status",
			raw: mutate(status.Stdout(), func(result map[string]any) {
				result["publication_status"] = string(domain.PublicationCorrupt)
				result["recovery_action"] = string(domain.RecoveryActionEmitImmutableCorruptionDiagnostic)
			}),
		},
		{
			name: "staged with resume action",
			raw: mutate(status.Stdout(), func(result map[string]any) {
				result["recovery_action"] = string(domain.RecoveryActionResumeCollection)
			}),
		},
		{
			name: "installed with none action",
			raw: mutate(status.Stdout(), func(result map[string]any) {
				result["publication_status"] = string(domain.PublicationInstalled)
				result["recovery_action"] = string(domain.RecoveryActionNone)
			}),
		},
		{
			name: "not published with commit action",
			raw: mutate(status.Stdout(), func(result map[string]any) {
				result["publication_status"] = string(domain.PublicationNotPublished)
				result["recovery_action"] = string(domain.RecoveryActionCommitCompositeEpoch)
			}),
		},
		{
			name: "committed cancelled run",
			raw: mutate(committedStatus.Stdout(), func(result map[string]any) {
				result["run_state"] = string(domain.RunCancelled)
			}),
		},
	}
	for _, malformed := range []string{"A===", "AAAA=", "AA=A", "AB==", "AAB="} {
		cases = append(cases, struct {
			name string
			raw  []byte
		}{
			name: "malformed base64 " + malformed,
			raw: mutate(excerpt.Stdout(), func(result map[string]any) {
				result["excerpt_base64"] = malformed
			}),
		})
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if err := fixture.validator.Validate(context.Background(), schema, test.raw); err == nil {
				t.Fatal("command result schema accepted a false G006 projection")
			}
		})
	}
}
func TestNewApplicationValidatesG006DependencyGroup(t *testing.T) {
	fixture := newFoundationFixture(t)
	if fixture.application == nil {
		t.Fatal("all-absent G006 dependency group was rejected")
	}
	reader, err := gittarget.New(gittarget.NewExecRunner())
	if err != nil {
		t.Fatal(err)
	}
	followup, delta, rerun, retention, exports := g008Dependencies()
	resolver := g008RequestResolver{}
	dependencies := Dependencies{
		Clock:                fixedFoundationClock{now: time.Date(2026, time.July, 14, 12, 0, 0, 0, time.UTC)},
		RequestIDGenerator:   fixedFoundationRequestIDs{},
		Catalog:              fixture.catalog,
		JSONSchemaValidator:  fixture.validator,
		SecureWriter:         fixture.writer,
		TrustedProjectReader: reader,
		EnvironmentInspector: environment.NewInspector(),
		RequestResolver:      resolver,
		FollowupRuns:         followup,
		DeltaRuns:            delta,
		Reruns:               rerun,
		Retention:            retention,
		Exports:              exports,
	}
	query := newG006QueryFake()
	report := newG006ReportFake()
	dependencies.PublicationQueries = query
	if _, err := NewApplication(dependencies); err == nil {
		t.Fatal("NewApplication accepted a partial G006 query dependency group")
	}
	dependencies.PublicationQueries = nil
	dependencies.PublicationReports = report
	if _, err := NewApplication(dependencies); err == nil {
		t.Fatal("NewApplication accepted a partial G006 report dependency group")
	}
	dependencies.PublicationReports = nil
	dependencies.RequestResolver = nil
	dependencies.FollowupRuns = nil
	dependencies.DeltaRuns = nil
	dependencies.Reruns = nil
	dependencies.Retention = nil
	dependencies.Exports = nil
	standalone, err := NewApplication(dependencies)
	if err != nil {
		t.Fatalf("NewApplication rejected absent G008 dependency group: %v", err)
	}
	result := standalone.Run(context.Background(), []string{"clean", "--all", "--output", "json"}, testAnchoredRoot(t))
	if result.ExitCode() != app.ExitCodeArtifact {
		t.Fatalf("absent G008 clean exit = %d, want %d; stdout=%q stderr=%q", result.ExitCode(), app.ExitCodeArtifact, result.Stdout(), result.Stderr())
	}
	schemaID, err := ports.ParseAssetID(commandSchemaID)
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.validator.Validate(context.Background(), schemaID, result.Stdout()); err != nil {
		t.Fatalf("absent G008 clean JSON is not schema-valid: %v", err)
	}
	dependencies.RequestResolver = resolver
	dependencies.Exports = newG008WorkflowFakes(t).export
	resolvedStandalone, err := NewApplication(dependencies)
	if err != nil {
		t.Fatalf("NewApplication rejected an independent request resolver: %v", err)
	}
	for _, argv := range [][]string{
		{"followup", "--run", "latest", "--finding", "F001", "--stdin", "--output", "json"},
		{"delta", "--since-run", "latest", "--stdin", "--roles", "logic", "--output", "json"},
		{"rerun", "--run", "latest", "--attempt", testAttemptID, "--output", "json"},
	} {
		result := resolvedStandalone.Run(context.Background(), argv, testAnchoredRoot(t))
		if result.ExitCode() != app.ExitCodeReadiness {
			t.Fatalf("standalone %v exit = %d, want %d; stdout=%q stderr=%q", argv, result.ExitCode(), app.ExitCodeReadiness, result.Stdout(), result.Stderr())
		}
	}
	export := resolvedStandalone.Run(context.Background(), []string{"export", "--run", "latest", "--output-path", "exports/redacted.zip", "--output", "json"}, testAnchoredRoot(t))
	if export.ExitCode() != app.ExitCodeSuccess {
		t.Fatalf("offline export/latest exit = %d, want %d; stdout=%q stderr=%q", export.ExitCode(), app.ExitCodeSuccess, export.Stdout(), export.Stderr())
	}
	dependencies.FollowupRuns = followup
	if _, err := NewApplication(dependencies); err == nil {
		t.Fatal("NewApplication accepted a partial online G008 dependency group")
	}
}
func TestIntegrationApplicationG008FakeWorkflow(t *testing.T) {
	tests := []struct {
		name   string
		argv   []string
		human  string
		kind   string
		exit   app.ExitCode
		json   bool
		reason string
	}{
		{name: "followup human", argv: []string{"followup", "--run", "latest", "--finding", "F001", "--stdin", "--objective", "verify fix", "--role", "security"}, human: "followup started: r_019f596a-d050-79e7-b2b7-59822f012273\nresolution: still_open\nstructured_extraction_status: structured", kind: "followup_started", exit: app.ExitCodePolicy},
		{name: "followup JSON", argv: []string{"followup", "--run", "latest", "--finding", "F001", "--stdin", "--objective", "verify fix", "--role", "security", "--output", "json"}, kind: "followup_started", exit: app.ExitCodePolicy, json: true, reason: "request_changes_threshold"},
		{name: "delta human", argv: []string{"delta", "--since-run", "latest", "--stdin", "--roles", "logic,testing"}, human: "delta started: r_019f596a-d051-79e7-b2b7-59822f012273", kind: "delta_started"},
		{name: "delta JSON", argv: []string{"delta", "--since-run", "latest", "--stdin", "--roles", "logic,testing", "--output", "json"}, kind: "delta_started", json: true},
		{name: "rerun human", argv: []string{"rerun", "--run", "latest", "--role", "logic", "--provider", "testing", "--replay", "recompose"}, human: "rerun started: r_019f596a-d052-79e7-b2b7-59822f012273", kind: "rerun_started", exit: app.ExitCodeReadiness},
		{name: "rerun JSON", argv: []string{"rerun", "--run", "latest", "--role", "logic", "--provider", "testing", "--replay", "recompose", "--output", "json"}, kind: "rerun_started", exit: app.ExitCodeReadiness, json: true, reason: "required_role_incomplete"},
		{name: "clean human", argv: []string{"clean", "--older-than", "30d"}, human: "clean completed: removed 3 runs and 8192 bytes", kind: "clean_completed"},
		{name: "clean JSON", argv: []string{"clean", "--all", "--dry-run", "--output", "json"}, kind: "clean_completed", json: true},
		{name: "export human", argv: []string{"export", "--run", "latest"}, human: "export created: .mulgae/exports/" + testRunID + ".zip", kind: "export_created"},
		{name: "export JSON", argv: []string{"export", "--run", "latest", "--output", "json"}, kind: "export_created", json: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fakes := newG008WorkflowFakes(t)
			fixture := newG008Fixture(t, fakes)
			canonicalRoot := testAnchoredRoot(t)
			result := fixture.application.Run(context.Background(), test.argv, canonicalRoot)
			if test.json {
				assertFoundationEnvelope(t, fixture, result, test.exit)
				if got := commandResultKind(t, result.Stdout()); got != test.kind {
					t.Fatalf("JSON result kind = %q, want %q", got, test.kind)
				}
				if test.reason != "" {
					assertCommittedOutcomeEnvelope(t, result, test.exit, test.reason)
				}
			} else if result.ExitCode() != test.exit || len(result.Stderr()) != 0 || !bytes.Equal(result.Stdout(), expectedTextOutput([]byte(test.human))) {
				t.Fatalf("human result = exit %d stdout %q stderr %q", result.ExitCode(), result.Stdout(), result.Stderr())
			}
			output := result.Stdout()
			output[0] = '!'
			if result.Stdout()[0] == '!' {
				t.Fatal("Result.Stdout exposed mutable application-owned bytes")
			}
			assertG008FakeRequest(t, test.name, fakes)
			if strings.HasPrefix(test.name, "export") && fakes.export.requests[0].ProjectRoot.String() != canonicalRoot {
				t.Fatalf("export project root = %q, want %q", fakes.export.requests[0].ProjectRoot.String(), canonicalRoot)
			}
		})
	}
}
func TestApplicationG008FollowupRendersEveryResolutionExactly(t *testing.T) {
	for _, resolution := range []domain.FollowupResolution{
		domain.FollowupResolved,
		domain.FollowupPartiallyResolved,
		domain.FollowupStillOpen,
		domain.FollowupUnclear,
	} {
		t.Run(string(resolution), func(t *testing.T) {
			for _, output := range []string{"human", "json"} {
				t.Run(output, func(t *testing.T) {
					fakes := newG008WorkflowFakes(t)
					value := resolution
					fakes.followup.resolution = &value
					fakes.followup.structuredExtractionStatus = domain.StructuredExtractionStructured
					argv := []string{"followup", "--run", "latest", "--finding", "F001", "--stdin", "--objective", "verify fix", "--role", "security"}
					if output == "json" {
						argv = append(argv, "--output", "json")
					}
					result := newG008Fixture(t, fakes).application.Run(context.Background(), argv, testAnchoredRoot(t))
					if output == "human" {
						want := "followup started: r_019f596a-d050-79e7-b2b7-59822f012273\nresolution: " + string(resolution) + "\nstructured_extraction_status: structured"
						if result.ExitCode() != app.ExitCodePolicy || !bytes.Equal(result.Stdout(), expectedTextOutput([]byte(want))) || len(result.Stderr()) != 0 {
							t.Fatalf("human result = exit %d stdout %q stderr %q", result.ExitCode(), result.Stdout(), result.Stderr())
						}
						return
					}
					var envelope struct {
						Result struct {
							Resolution                 string `json:"resolution"`
							StructuredExtractionStatus string `json:"structured_extraction_status"`
						} `json:"result"`
					}
					if result.ExitCode() != app.ExitCodePolicy {
						t.Fatalf("JSON exit = %d, want %d", result.ExitCode(), app.ExitCodePolicy)
					}
					if err := json.Unmarshal(result.Stdout(), &envelope); err != nil ||
						envelope.Result.Resolution != string(resolution) ||
						envelope.Result.StructuredExtractionStatus != "structured" {
						t.Fatalf("JSON result = stdout %q error %v", result.Stdout(), err)
					}
				})
			}
		})
	}
}

func TestApplicationG008FollowupRendersReportsOnlyWithNullResolution(t *testing.T) {
	for _, output := range []string{"human", "json"} {
		t.Run(output, func(t *testing.T) {
			fakes := newG008WorkflowFakes(t)
			fakes.followup.resolution = nil
			fakes.followup.structuredExtractionStatus = domain.StructuredExtractionReportsOnly
			fakes.followup.terminalExit = g008CommittedTerminalExit(t, domain.ExitCommittedPass)
			argv := []string{"followup", "--run", "latest", "--finding", "F001", "--stdin", "--objective", "verify fix", "--role", "security"}
			if output == "json" {
				argv = append(argv, "--output", "json")
			}
			result := newG008Fixture(t, fakes).application.Run(context.Background(), argv, testAnchoredRoot(t))
			if output == "human" {
				want := "followup started: r_019f596a-d050-79e7-b2b7-59822f012273\nresolution: null\nstructured_extraction_status: reports_only"
				if result.ExitCode() != app.ExitCodeSuccess || !bytes.Equal(result.Stdout(), expectedTextOutput([]byte(want))) || len(result.Stderr()) != 0 {
					t.Fatalf("human result = exit %d stdout %q stderr %q", result.ExitCode(), result.Stdout(), result.Stderr())
				}
				return
			}
			var envelope struct {
				Result struct {
					Resolution                 *string `json:"resolution"`
					StructuredExtractionStatus string  `json:"structured_extraction_status"`
					RoleReportURIs             []struct {
						Role string `json:"role"`
						URI  string `json:"uri"`
					} `json:"role_report_uris"`
				} `json:"result"`
			}
			if result.ExitCode() != app.ExitCodeSuccess {
				t.Fatalf("JSON exit = %d, want %d stdout %q", result.ExitCode(), app.ExitCodeSuccess, result.Stdout())
			}
			if err := json.Unmarshal(result.Stdout(), &envelope); err != nil {
				t.Fatal(err)
			}
			if envelope.Result.Resolution != nil ||
				envelope.Result.StructuredExtractionStatus != "reports_only" ||
				len(envelope.Result.RoleReportURIs) != 1 {
				t.Fatalf("JSON reports-only result = %#v", envelope.Result)
			}
		})
	}
}

func TestApplicationG008FailureCancellationAndTypedExits(t *testing.T) {
	security := mustG006Failure(t, domain.FailureSecurityPolicy)
	mutation, err := domain.NewFailure("child.source_reobservation", domain.FailureSecurityPolicy, "source changed during child execution", errors.New("source mutation"))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		argv []string
		exit app.ExitCode
		set  func(g008WorkflowFakes)
	}{
		{
			name: "cancelled followup",
			argv: []string{"followup", "--run", "latest", "--finding", "F001", "--stdin", "--objective", "verify fix", "--role", "security", "--output", "json"},
			exit: app.ExitCodeCancellation,
			set:  func(fakes g008WorkflowFakes) { fakes.followup.err = context.Canceled },
		},
		{
			name: "delta cancellation",
			argv: []string{"delta", "--since-run", "latest", "--stdin", "--roles", "logic,testing", "--output", "json"},
			exit: app.ExitCodeCancellation,
			set:  func(fakes g008WorkflowFakes) { fakes.delta.err = context.Canceled },
		},
		{
			name: "rerun cancellation",
			argv: []string{"rerun", "--run", "latest", "--role", "logic", "--provider", "testing", "--replay", "recompose", "--output", "json"},
			exit: app.ExitCodeCancellation,
			set:  func(fakes g008WorkflowFakes) { fakes.rerun.err = context.Canceled },
		},
		{
			name: "followup missing terminal exit authority",
			argv: []string{"followup", "--run", "latest", "--finding", "F001", "--stdin", "--objective", "verify fix", "--role", "security", "--output", "json"},
			exit: app.ExitCodeInternal,
			set:  func(fakes g008WorkflowFakes) { fakes.followup.terminalExit = domain.OperationalExitDecision{} },
		},
		{
			name: "typed security delta",
			argv: []string{"delta", "--since-run", "latest", "--stdin", "--roles", "logic,testing", "--output", "json"},
			exit: app.ExitCodeSecurity,
			set:  func(fakes g008WorkflowFakes) { fakes.delta.err = security },
		},
		{
			name: "followup source mutation",
			argv: []string{"followup", "--run", "latest", "--finding", "F001", "--stdin", "--objective", "verify fix", "--role", "security", "--output", "json"},
			exit: app.ExitCodeSecurity,
			set:  func(fakes g008WorkflowFakes) { fakes.followup.err = mutation },
		},
		{
			name: "delta source mutation",
			argv: []string{"delta", "--since-run", "latest", "--stdin", "--roles", "logic,testing", "--output", "json"},
			exit: app.ExitCodeSecurity,
			set:  func(fakes g008WorkflowFakes) { fakes.delta.err = mutation },
		},
		{
			name: "rerun source mutation",
			argv: []string{"rerun", "--run", "latest", "--role", "logic", "--provider", "testing", "--replay", "recompose", "--output", "json"},
			exit: app.ExitCodeSecurity,
			set:  func(fakes g008WorkflowFakes) { fakes.rerun.err = mutation },
		},
		{
			name: "followup source corruption",
			argv: []string{"followup", "--run", "latest", "--finding", "F001", "--stdin", "--objective", "verify fix", "--role", "security", "--output", "json"},
			exit: app.ExitCodeArtifact,
			set: func(fakes g008WorkflowFakes) {
				fakes.followup.err = &appfollowup.Error{Kind: appfollowup.ErrorSource, Stage: "source", Err: errors.New("source corrupt")}
			},
		},
		{
			name: "delta source corruption",
			argv: []string{"delta", "--since-run", "latest", "--stdin", "--roles", "logic,testing", "--output", "json"},
			exit: app.ExitCodeArtifact,
			set:  func(fakes g008WorkflowFakes) { fakes.delta.err = errors.New("source corrupt") },
		},
		{
			name: "rerun source corruption",
			argv: []string{"rerun", "--run", "latest", "--role", "logic", "--provider", "testing", "--replay", "recompose", "--output", "json"},
			exit: app.ExitCodeArtifact,
			set:  func(fakes g008WorkflowFakes) { fakes.rerun.err = appreplay.ErrSourceCorrupt },
		},
		{
			name: "typed artifact clean",
			argv: []string{"clean", "--all", "--dry-run", "--output", "json"},
			exit: app.ExitCodeArtifact,
			set:  func(fakes g008WorkflowFakes) { fakes.retention.err = mustG006ArtifactFailure(t) },
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fakes := newG008WorkflowFakes(t)
			test.set(fakes)
			fixture := newG008Fixture(t, fakes)
			result := fixture.application.Run(context.Background(), test.argv, testAnchoredRoot(t))
			assertFoundationEnvelope(t, fixture, result, test.exit)
			assertG008FakeRequest(t, test.name, fakes)
		})
	}
}

func TestApplicationG008ProviderExecutionFailuresAreNonSuccess(t *testing.T) {
	tests := []struct {
		name      string
		argv      []string
		class     domain.FailureClass
		condition review.AttemptCondition
		set       func(g008WorkflowFakes, error)
	}{
		{
			name:      "followup provider unavailable",
			argv:      []string{"followup", "--run", "latest", "--finding", "F001", "--stdin", "--objective", "verify fix", "--role", "security", "--output", "json"},
			class:     domain.FailureProviderUnavailable,
			condition: review.AttemptConditionProviderUnavailable,
			set:       func(fakes g008WorkflowFakes, err error) { fakes.followup.err = err },
		},
		{
			name:      "delta invalid output",
			argv:      []string{"delta", "--since-run", "latest", "--stdin", "--roles", "logic,testing", "--output", "json"},
			class:     domain.FailureInvalidOutput,
			condition: review.AttemptConditionInvalidProviderOutput,
			set:       func(fakes g008WorkflowFakes, err error) { fakes.delta.err = err },
		},
		{
			name:      "rerun exact timeout",
			argv:      []string{"rerun", "--run", "latest", "--attempt", testAttemptID, "--output", "json"},
			class:     domain.FailureTimeout,
			condition: review.AttemptConditionTimeout,
			set:       func(fakes g008WorkflowFakes, err error) { fakes.rerun.err = err },
		},
		{
			name:      "rerun recomposed authentication",
			argv:      []string{"rerun", "--run", "latest", "--role", "logic", "--provider", "testing", "--replay", "recompose", "--output", "json"},
			class:     domain.FailureAuthentication,
			condition: review.AttemptConditionAuthentication,
			set:       func(fakes g008WorkflowFakes, err error) { fakes.rerun.err = err },
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fact, err := reviewrun.NewProviderExecutionFailure("zcode-security", domain.RoleSecurity, string(test.condition), test.class)
			if err != nil {
				t.Fatal(err)
			}
			aggregate := reviewrun.NewProviderExecutionFailuresError([]reviewrun.ProviderExecutionFailure{fact})
			failure, err := domain.NewFailure("childrun.execute", test.class, "provider execution failed", aggregate)
			if err != nil {
				t.Fatal(err)
			}
			fakes := newG008WorkflowFakes(t)
			test.set(fakes, failure)
			fixture := newG008Fixture(t, fakes)
			result := fixture.application.Run(context.Background(), test.argv, testAnchoredRoot(t))
			assertFoundationEnvelope(t, fixture, result, app.ExitCodeReadiness)
			var envelope struct {
				OK      bool `json:"ok"`
				Reasons []struct {
					Code      string `json:"code"`
					Retryable bool   `json:"retryable"`
				} `json:"reasons"`
			}
			if err := json.Unmarshal(result.Stdout(), &envelope); err != nil {
				t.Fatal(err)
			}
			wantCode := "provider_execution_failed"
			switch test.condition {
			case review.AttemptConditionInvalidProviderOutput:
				wantCode = "candidate_validation_failed"
			case review.AttemptConditionTimeout:
				wantCode = "execution_timeout"
			}
			if envelope.OK || len(envelope.Reasons) != 1 || envelope.Reasons[0].Code != wantCode || envelope.Reasons[0].Retryable {
				t.Fatalf("provider execution envelope = %#v", envelope)
			}
			if test.name == "rerun exact timeout" {
				if len(fakes.rerun.requests) != 1 || fakes.rerun.requests[0].ReplayMode != appreplay.ExactReplay {
					t.Fatalf("exact rerun requests = %#v", fakes.rerun.requests)
				}
			} else {
				assertG008FakeRequest(t, test.name, fakes)
			}
		})
	}
}

func TestApplicationG008ExportSecurityFailureRedactsSuccessFields(t *testing.T) {
	fakes := newG008WorkflowFakes(t)
	fakes.export.err = mustG006Failure(t, domain.FailureSecurityPolicy)
	fixture := newG008Fixture(t, fakes)

	result := fixture.application.Run(context.Background(), []string{
		"export", "--run", "latest", "--output-path", "exports/redacted.zip", "--output", "json",
	}, testAnchoredRoot(t))
	assertFoundationEnvelope(t, fixture, result, app.ExitCodeSecurity)

	var envelope struct {
		Result struct {
			ExportManifestURI *string `json:"export_manifest_uri"`
			BundleURI         *string `json:"bundle_uri"`
			Redacted          bool    `json:"redacted"`
		} `json:"result"`
	}
	if err := json.Unmarshal(result.Stdout(), &envelope); err != nil {
		t.Fatal(err)
	}
	if !envelope.Result.Redacted || envelope.Result.ExportManifestURI != nil || envelope.Result.BundleURI != nil {
		t.Fatalf("security export result disclosed success fields: %#v", envelope.Result)
	}
	if bytes.Contains(result.Stdout(), []byte(".mulgae/exports/manifest.json")) {
		t.Fatalf("security export result contained success URI bytes: %q", result.Stdout())
	}
	if len(fakes.export.requests) != 1 || len(fakes.resolver.runCalls) != 1 || fakes.resolver.runCalls[0] != "latest" {
		t.Fatalf("security export calls = requests %#v runs %#v", fakes.export.requests, fakes.resolver.runCalls)
	}
}

func TestApplicationG008FollowupPreservesNonNumericFindingID(t *testing.T) {
	fakes := newG008WorkflowFakes(t)
	fixture := newG008Fixture(t, fakes)

	result := fixture.application.Run(context.Background(), []string{
		"followup", "--run", "latest", "--finding", "F_SOURCE-1", "--stdin",
		"--objective", "verify fix", "--role", "security", "--output", "json",
	}, testAnchoredRoot(t))
	assertFoundationEnvelope(t, fixture, result, app.ExitCodePolicy)

	if len(fakes.followup.requests) != 1 {
		t.Fatalf("followup requests = %#v", fakes.followup.requests)
	}
	if got := fakes.followup.requests[0].FindingID; got != "F_SOURCE-1" {
		t.Fatalf("followup finding ID = %q, want %q", got, "F_SOURCE-1")
	}
}
func TestApplicationG008HumanFailureDefensivelyCopiesStderr(t *testing.T) {
	fakes := newG008WorkflowFakes(t)
	fakes.followup.err = context.Canceled
	fixture := newG008Fixture(t, fakes)
	result := fixture.application.Run(context.Background(), []string{
		"followup", "--run", "latest", "--finding", "F001", "--stdin",
		"--objective", "verify fix", "--role", "security",
	}, testAnchoredRoot(t))
	if result.ExitCode() != app.ExitCodeCancellation || len(result.Stdout()) != 0 {
		t.Fatalf("human cancellation = exit %d stdout %q stderr %q", result.ExitCode(), result.Stdout(), result.Stderr())
	}
	stderr := result.Stderr()
	stderr[0] = '!'
	if result.Stderr()[0] == '!' {
		t.Fatal("Result.Stderr exposed mutable application-owned bytes")
	}
	assertG008FakeRequest(t, "cancelled followup", fakes)
}

func assertG008FakeRequest(t *testing.T, name string, fakes g008WorkflowFakes) {
	t.Helper()
	switch {
	case strings.HasPrefix(name, "followup"), strings.HasPrefix(name, "cancelled followup"):
		if len(fakes.followup.requests) != 1 || len(fakes.resolver.runCalls) != 1 || fakes.resolver.runCalls[0] != "latest" || fakes.resolver.targetCalls != 1 {
			t.Fatalf("followup calls = requests %#v runs %#v target calls %d", fakes.followup.requests, fakes.resolver.runCalls, fakes.resolver.targetCalls)
		}
		request := fakes.followup.requests[0]
		if request.SourceRunID.String() != testRunID || request.FindingID != "F001" || string(request.Target.Kind) != "stdin" || request.Target.Value != "stdin-capture-v1-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" ||
			request.Objective == nil || *request.Objective != "verify fix" || request.Role == nil || *request.Role != domain.RoleSecurity {
			t.Fatalf("followup request = %#v", request)
		}
		if request.SourceRunID.String() == "r_019f596a-d050-79e7-b2b7-59822f012273" {
			t.Fatal("followup source run ID equals returned child run ID")
		}
	case strings.HasPrefix(name, "delta"), strings.HasPrefix(name, "typed security delta"):
		if len(fakes.delta.requests) != 1 || len(fakes.resolver.runCalls) != 1 || fakes.resolver.runCalls[0] != "latest" || fakes.resolver.targetCalls != 1 {
			t.Fatalf("delta calls = requests %#v runs %#v target calls %d", fakes.delta.requests, fakes.resolver.runCalls, fakes.resolver.targetCalls)
		}
		request := fakes.delta.requests[0]
		if request.SourceRunID.String() != testRunID || string(request.Target.Kind) != "stdin" || request.Target.Value != "stdin-capture-v1-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" ||
			!reflect.DeepEqual(request.Roles, []domain.Role{domain.RoleLogic, domain.RoleTesting}) {
			t.Fatalf("delta request = %#v", request)
		}
		if request.SourceRunID.String() == "r_019f596a-d051-79e7-b2b7-59822f012273" {
			t.Fatal("delta source run ID equals returned child run ID")
		}
	case strings.HasPrefix(name, "rerun"):
		if len(fakes.rerun.requests) != 1 || len(fakes.resolver.runCalls) != 1 || len(fakes.resolver.attemptCalls) != 1 {
			t.Fatalf("rerun calls = requests %#v runs %#v attempts %#v", fakes.rerun.requests, fakes.resolver.runCalls, fakes.resolver.attemptCalls)
		}
		request := fakes.rerun.requests[0]
		if request.SourceRunID.String() != testRunID || request.SourceAttemptID.String() != testAttemptID || request.ReplayMode != appreplay.RecomposeReplay ||
			!reflect.DeepEqual(fakes.resolver.attemptCalls[0], g008AttemptResolution{runID: testRunID, role: "logic", provider: "testing"}) {
			t.Fatalf("rerun request = %#v, resolutions = %#v", request, fakes.resolver.attemptCalls)
		}
		if request.SourceRunID.String() == "r_019f596a-d052-79e7-b2b7-59822f012273" {
			t.Fatal("rerun source run ID equals returned child run ID")
		}
	case strings.HasPrefix(name, "clean"), strings.HasPrefix(name, "typed artifact clean"):
		if len(fakes.retention.requests) != 1 {
			t.Fatalf("clean requests = %#v", fakes.retention.requests)
		}
		request := fakes.retention.requests[0]
		if strings.HasPrefix(name, "typed artifact") {
			if !request.All || !request.DryRun || request.OlderThanDays != 0 {
				t.Fatalf("clean failure request = %#v", request)
			}
			return
		}
		if name == "clean JSON" {
			if !request.All || !request.DryRun || request.OlderThanDays != 0 {
				t.Fatalf("clean dry-run request = %#v", request)
			}
			return
		}
		if request.OlderThanDays != 30 || request.All || request.DryRun {
			t.Fatalf("clean request = %#v", request)
		}
	case strings.HasPrefix(name, "export"):
		if len(fakes.export.requests) != 1 || len(fakes.resolver.runCalls) != 1 || fakes.resolver.runCalls[0] != "latest" {
			t.Fatalf("export calls = requests %#v runs %#v", fakes.export.requests, fakes.resolver.runCalls)
		}
		request := fakes.export.requests[0]
		if request.RunID != testRunID || request.OutputPath != ".mulgae/exports/"+testRunID+".zip" || !request.Redacted ||
			!request.ProjectRoot.Valid() || request.ArtifactRoot.String() != filepath.Join(request.ProjectRoot.String(), ".mulgae") {
			t.Fatalf("export request = %#v", request)
		}
	default:
		t.Fatalf("uncovered G008 fake assertion %q", name)
	}
}
func newG008Fixture(t *testing.T, fakes g008WorkflowFakes) foundationFixture {
	t.Helper()
	fixture := newFoundationFixture(t)
	reader, err := gittarget.New(gittarget.NewExecRunner())
	if err != nil {
		t.Fatal(err)
	}
	application, err := NewApplication(Dependencies{
		Clock:                fixedFoundationClock{now: time.Date(2026, time.July, 14, 12, 0, 0, 0, time.UTC)},
		RequestIDGenerator:   fixedFoundationRequestIDs{},
		Catalog:              fixture.catalog,
		JSONSchemaValidator:  fixture.validator,
		SecureWriter:         fixture.writer,
		TrustedProjectReader: reader,
		EnvironmentInspector: environment.NewInspector(),
		RequestResolver:      fakes.resolver,
		FollowupRuns:         fakes.followup,
		DeltaRuns:            fakes.delta,
		Reruns:               fakes.rerun,
		Retention:            fakes.retention,
		Exports:              fakes.export,
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture.application = application
	return fixture
}
func TestIntegrationProductionMulgaeCompositionFailsClosedAtLiveBoundaries(t *testing.T) {
	repositoryRoot, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	binary := os.Getenv("MULGAE_E2E_BINARY")
	if binary == "" {
		binary = filepath.Join(t.TempDir(), "mulgae")
		build := exec.Command(
			"go", "build", "-trimpath",
			"-ldflags", "-X main.buildVersion=v1.4.2 -X main.buildRevision=0123456789abcdef0123456789abcdef01234567",
			"-o", binary, ".",
		)
		build.Dir = repositoryRoot
		if output, err := build.CombinedOutput(); err != nil {
			t.Fatalf("build production mulgae: %v: %s", err, output)
		}
	}

	fixture := newFoundationFixture(t)
	runAt := func(root string, argv ...string) ([]byte, []byte, app.ExitCode) {
		command := exec.Command(binary, argv...)
		command.Dir = root
		stdout, err := command.Output()
		if err == nil {
			return stdout, nil, app.ExitCodeSuccess
		}
		exitError, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatalf("run production mulgae %v: %v", argv, err)
		}
		return stdout, exitError.Stderr, app.ExitCode(exitError.ExitCode())
	}
	run := func(argv ...string) ([]byte, []byte, app.ExitCode) {
		return runAt(t.TempDir(), argv...)
	}
	for _, argv := range [][]string{
		{"help", "security", "--output", "json"},
		{"schema", "show", commandSchemaID},
	} {
		if _, stderr, exit := run(argv...); exit != app.ExitCodeSuccess {
			t.Fatalf("production G001-G007 command %v exit = %d stderr %q", argv, exit, stderr)
		}
	}
	for _, test := range []struct {
		name string
		argv []string
		exit app.ExitCode
	}{
		{name: "review", argv: []string{"review", "--dirty", "--output", "json"}, exit: app.ExitCodeUsage},
	} {
		if stdout, stderr, exit := run(test.argv...); exit != test.exit || len(stdout) == 0 || len(stderr) != 0 {
			t.Fatalf("production fail-closed command %s = exit %d stdout %q stderr %q", test.name, exit, stdout, stderr)
		} else {
			schema := mustFoundationAssetID(t, commandSchemaID)
			if err := fixture.validator.Validate(context.Background(), schema, stdout); err != nil {
				t.Fatalf("production fail-closed envelope %s is invalid: %v", test.name, err)
			}
		}
	}
	if stdout, stderr, exit := run("prompt", "--run", testRunID, "--attempt", testAttemptID); exit != app.ExitCodeUsage || len(stdout) != 0 || !bytes.Equal(stderr, []byte("mulgae: invalid command usage\nhint: run mulgae help workflows\n")) {
		t.Fatalf("removed production prompt command = exit %d stdout %q stderr %q", exit, stdout, stderr)
	}
	for _, argv := range [][]string{
		{"followup", "--run", testRunID, "--finding", "F001", "--dirty", "--output", "json"},
		{"delta", "--since-run", testRunID, "--dirty", "--roles", "logic", "--output", "json"},
		{"rerun", "--run", testRunID, "--attempt", testAttemptID, "--output", "json"},
	} {
		stdout, stderr, exit := run(argv...)
		if exit != app.ExitCodeUsage || len(stderr) != 0 {
			t.Fatalf("production config-gated G008 command %v = exit %d stderr %q", argv, exit, stderr)
		}
		assertFoundationEnvelope(t, fixture, newResult(stdout, stderr, exit), app.ExitCodeUsage)
	}
	exportRoot := t.TempDir()
	if err := os.Mkdir(filepath.Join(exportRoot, ".mulgae"), 0o700); err != nil {
		t.Fatal(err)
	}
	stdout, stderr, exit := runAt(exportRoot, "export", "--run", testRunID, "--output-path", "exports/redacted.zip", "--output", "json")
	if exit != app.ExitCodeArtifact || len(stderr) != 0 {
		t.Fatalf("production export = exit %d stderr %q", exit, stderr)
	}
	assertFoundationEnvelope(t, fixture, newResult(stdout, stderr, exit), app.ExitCodeArtifact)
	if _, err := os.Lstat(filepath.Join(exportRoot, "store")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("production export project-root store stat error = %v, want not exist", err)
	}
	if _, err := os.Stat(filepath.Join(exportRoot, ".mulgae", "store", "locks", "store.lock")); err != nil {
		t.Fatalf("production export artifact-root publication lock: %v", err)
	}
	cleanRoot := t.TempDir()
	if err := os.Mkdir(filepath.Join(cleanRoot, ".mulgae"), 0o700); err != nil {
		t.Fatal(err)
	}
	stdout, stderr, exit = runAt(cleanRoot, "clean", "--all", "--dry-run", "--output", "json")
	if exit != app.ExitCodeSuccess || len(stderr) != 0 {
		t.Fatalf("production clean = exit %d stderr %q", exit, stderr)
	}
	assertFoundationEnvelope(t, fixture, newResult(stdout, stderr, exit), app.ExitCodeSuccess)
	if entries, err := os.ReadDir(filepath.Join(cleanRoot, ".mulgae")); err != nil || len(entries) != 0 {
		t.Fatalf("production clean dry-run mutated .mulgae: entries=%#v err=%v", entries, err)
	}
}
func TestIntegrationProductionRedactedExportAcceptsCommittedNoFindingsAndRejectsUnboundSource(t *testing.T) {
	fixture := newG008RealE2EFixture(t)
	fixture.provider.logicNoFindings = true
	root := fixture.executeAndPublishRoot(t)
	installer := mustG008RealExportInstaller(t, fixture)
	service, err := NewRedactedExportService(fixture.queries, installer, fixture.clock, fixture.ids)
	if err != nil {
		t.Fatal(err)
	}
	projectRoot, err := ports.NewAnchoredRoot(filepath.Dir(fixture.root.String()))
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.ExportRedactedRun(context.Background(), RedactedExportRequest{
		ProjectRoot: projectRoot, ArtifactRoot: fixture.root, RunID: root.RunID.String(), OutputPath: ".mulgae/exports/" + root.RunID.String() + ".zip", Redacted: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Redacted || result.BundleURI != ".mulgae/exports/"+root.RunID.String()+".zip" || result.ExportManifestURI != ".mulgae/exports/"+root.RunID.String()+".manifest.json" {
		t.Fatalf("no-findings export result = %#v", result)
	}
	if _, err := os.Stat(filepath.Join(projectRoot.String(), result.BundleURI)); err != nil {
		t.Fatalf("read no-findings export bundle: %v", err)
	}
	if _, err := os.Stat(filepath.Join(fixture.root.String(), "store", "locks", "export-install.lock")); err != nil {
		t.Fatalf("artifact-root export lock: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(projectRoot.String(), "store")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("project-root store stat error = %v, want not exist", err)
	}
	manifestBytes, err := os.ReadFile(filepath.Join(projectRoot.String(), result.ExportManifestURI))
	if err != nil {
		t.Fatalf("read no-findings export manifest: %v", err)
	}
	exportManifestSchema := mustFoundationAssetID(t, "https://mulgae.local/schemas/mulgae-export-manifest.v1.schema.json")
	if err := fixture.validator.Validate(context.Background(), exportManifestSchema, manifestBytes); err != nil {
		t.Fatalf("no-findings export manifest is not schema-valid: %v", err)
	}
	var manifest appexport.ExportManifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatalf("decode no-findings export manifest: %v", err)
	}
	if manifest.ImmutableSource.SessionID != root.SessionID.String() ||
		manifest.ImmutableSource.RunID != root.RunID.String() ||
		manifest.ImmutableSource.ReviewID != root.ReviewID.String() {
		t.Fatalf("no-findings selected immutable source = %#v", manifest.ImmutableSource)
	}
	var manifestFields struct {
		SourceIdentity  map[string]json.RawMessage `json:"source_identity"`
		CurrentIdentity map[string]json.RawMessage `json:"current_identity"`
	}
	if err := json.Unmarshal(manifestBytes, &manifestFields); err != nil {
		t.Fatalf("decode no-findings export identity fields: %v", err)
	}
	if manifest.SourceIdentity.FindingID != "" ||
		manifest.SourceIdentity.SourceExcerptSHA256 != "" ||
		manifest.CurrentIdentity.TargetSHA256 == "" ||
		manifest.CurrentIdentity.CurrentExcerptSHA256 != "" ||
		manifest.CurrentIdentity.Path != "" ||
		manifest.CurrentIdentity.Side != "" ||
		manifest.CurrentIdentity.LineStart != 0 ||
		manifest.CurrentIdentity.LineEnd != 0 ||
		manifest.CurrentIdentity.Verification != "" ||
		manifestFields.SourceIdentity["finding_id"] != nil ||
		manifestFields.SourceIdentity["source_excerpt_sha256"] != nil ||
		len(manifestFields.CurrentIdentity) != 1 ||
		manifestFields.CurrentIdentity["target_sha256"] == nil {
		t.Fatalf("no-findings manifest identities = %#v/%#v", manifest.SourceIdentity, manifest.CurrentIdentity)
	}
	run, err := fixture.queries.ResolveRun(context.Background(), fixture.root, root.RunID)
	if err != nil {
		t.Fatal(err)
	}
	committed, err := fixture.queries.ReadCommitted(context.Background(), run)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.SourceIdentity.SourceTargetSHA256 != committed.TargetSHA256() ||
		manifest.CurrentIdentity.TargetSHA256 != committed.TargetSHA256() {
		t.Fatalf("no-findings manifest target identities = %#v/%#v", manifest.SourceIdentity, manifest.CurrentIdentity)
	}
	projection, err := (p2ExportProjectionReader{committed: committed}).ReadCommittedProjection(context.Background(), appexport.ExportSource{
		SessionID: root.SessionID.String(), RunID: root.RunID.String(), ReviewID: root.ReviewID.String(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(projection.Findings) != 0 || len(projection.Evidence) != 0 || projection.SourceIdentity.SourceTargetSHA256 != committed.TargetSHA256() || projection.CurrentIdentity.TargetSHA256 != committed.TargetSHA256() {
		t.Fatalf("no-findings projection = %#v", projection)
	}
	_, err = (p2ExportProjectionReader{committed: committed}).ReadCommittedProjection(context.Background(), appexport.ExportSource{
		SessionID: root.SessionID.String(), RunID: root.RunID.String(), ReviewID: "malformed",
	})
	if err == nil {
		t.Fatal("unbound export source was accepted")
	}
}

func newG006QueryFake() *g006QueryFake {
	return &g006QueryFake{
		status: RunStatusView{
			SessionID: g006SessionID, RunID: testRunID, RunState: domain.RunCompleted, HasRunState: true,
			PublicationState: domain.PublicationCommitted,
			RecoveryAction:   domain.RecoveryActionReconstructCompletedStatus,
			FinalArtifactURI: g006ReviewArtifactURI, HasFinalArtifact: true,
			ContentVerdict: domain.ContentRequestChanges, CoverageStatus: domain.CoverageComplete,
			CIDecision: domain.CIFail, HasAxes: true, RoleReportURIs: []RoleReportURI{},
		},
		findings: FindingsView{
			RunID:             testRunID,
			ReviewArtifactURI: g006ReviewArtifactURI,
			Findings: []FindingView{
				{ID: "F002", Severity: domain.SeverityHigh, Title: "Second in query order"},
				{ID: "F001", Severity: domain.SeverityCritical, Title: "First in query order"},
			},
		},
		excerpt: []byte("line one\nline two\n\n"),
	}
}

func newG006ReportFake() *g006ReportFake {
	return &g006ReportFake{
		rendered: RenderedReport{
			Markdown: []byte("# Review report\n"),
			RunID:    testRunID,
			SourceIDs: []string{
				"report:review:019f596a-d048-79e7-b2b7-59822f012273",
				"report:final:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				"report:manifest:sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
				"report:lineage:sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
				"report:epoch:1",
			},
		},
	}
}

func newG006Fixture(t *testing.T, query PublicationQueryService, report PublicationReportService) foundationFixture {
	t.Helper()
	return newG006FixtureWithWriter(t, query, report, filesystem.NewSecureWriter())
}

func newG006FixtureWithWriter(
	t *testing.T,
	query PublicationQueryService,
	report PublicationReportService,
	writer ports.SecureFileWriter,
) foundationFixture {
	t.Helper()
	fixture := newFoundationFixtureWithWriter(t, writer)
	reader, err := gittarget.New(gittarget.NewExecRunner())
	if err != nil {
		t.Fatal(err)
	}
	followup, delta, rerun, retention, exports := g008Dependencies()
	resolver := g008RequestResolver{}
	application, err := NewApplication(Dependencies{
		Clock:                fixedFoundationClock{now: time.Date(2026, time.July, 14, 12, 0, 0, 0, time.UTC)},
		RequestIDGenerator:   fixedFoundationRequestIDs{},
		Catalog:              fixture.catalog,
		JSONSchemaValidator:  fixture.validator,
		SecureWriter:         fixture.writer,
		TrustedProjectReader: reader,
		EnvironmentInspector: environment.NewInspector(),
		RequestResolver:      resolver,
		PublicationQueries:   query,
		PublicationReports:   report,
		FollowupRuns:         followup,
		DeltaRuns:            delta,
		Reruns:               rerun,
		Retention:            retention,
		Exports:              exports,
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture.application = application
	return fixture
}

func commandResultKind(t *testing.T, envelope []byte) string {
	t.Helper()
	var document struct {
		Result struct {
			Kind string `json:"kind"`
		} `json:"result"`
	}
	if err := json.Unmarshal(envelope, &document); err != nil {
		t.Fatal(err)
	}
	return document.Result.Kind
}
func assertG006FailureProjectionRedacted(t *testing.T, envelope []byte, fields []string) {
	t.Helper()
	var document struct {
		Result map[string]any `json:"result"`
	}
	if err := json.Unmarshal(envelope, &document); err != nil {
		t.Fatal(err)
	}
	for _, field := range fields {
		value, present := document.Result[field]
		if !present || value != nil {
			t.Fatalf("failure result disclosed %s = %#v", field, value)
		}
	}
}

func assertG006StatusAxes(t *testing.T, envelope []byte) {
	t.Helper()
	var document struct {
		Result struct {
			ContentVerdict string `json:"content_verdict"`
			CoverageStatus string `json:"coverage_status"`
			CIDecision     string `json:"ci_decision"`
		} `json:"result"`
	}
	if err := json.Unmarshal(envelope, &document); err != nil {
		t.Fatal(err)
	}
	if document.Result.ContentVerdict != string(domain.ContentRequestChanges) ||
		document.Result.CoverageStatus != string(domain.CoverageComplete) ||
		document.Result.CIDecision != string(domain.CIFail) {
		t.Fatalf("P2 status axes = %#v", document.Result)
	}
}

func assertG006ExcerptBytes(t *testing.T, envelope, expected []byte) {
	t.Helper()
	var document struct {
		Result struct {
			EvidenceState string  `json:"evidence_state"`
			ExcerptURI    *string `json:"excerpt_uri"`
			ExcerptBase64 *string `json:"excerpt_base64"`
			ExcerptSHA256 *string `json:"excerpt_sha256"`
		} `json:"result"`
	}
	if err := json.Unmarshal(envelope, &document); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(expected)
	expectedSHA256 := "sha256:" + hex.EncodeToString(digest[:])
	expectedBase64 := base64.StdEncoding.EncodeToString(expected)
	if document.Result.EvidenceState != "verified" || document.Result.ExcerptURI != nil ||
		document.Result.ExcerptBase64 == nil || *document.Result.ExcerptBase64 != expectedBase64 ||
		document.Result.ExcerptSHA256 == nil || *document.Result.ExcerptSHA256 != expectedSHA256 {
		t.Fatalf("excerpt projection = %#v", document.Result)
	}
}

func assertG006StatusFailureHasNoAuthority(t *testing.T, envelope []byte) {
	t.Helper()
	var document struct {
		Result struct {
			RunState          *string `json:"run_state"`
			PublicationStatus *string `json:"publication_status"`
			RecoveryAction    *string `json:"recovery_action"`
			FinalArtifactURI  *string `json:"final_artifact_uri"`
		} `json:"result"`
	}
	if err := json.Unmarshal(envelope, &document); err != nil {
		t.Fatal(err)
	}
	if document.Result.RunState != nil || document.Result.PublicationStatus != nil ||
		document.Result.RecoveryAction != nil || document.Result.FinalArtifactURI != nil {
		t.Fatalf("errored status exposed authority = %#v", document.Result)
	}
}

func mustG006Failure(t *testing.T, class domain.FailureClass) error {
	t.Helper()
	failure, err := domain.NewFailure("test.G006", class, "failure", nil)
	if err != nil {
		t.Fatal(err)
	}
	return failure
}
func mustG006ArtifactFailure(t *testing.T) error {
	t.Helper()
	failure, err := domain.NewFailure("test.G006", domain.FailureArtifact, "corrupt publication", nil)
	if err != nil {
		t.Fatal(err)
	}
	return failure
}

func newFoundationFixture(t *testing.T) foundationFixture {
	t.Helper()
	return newFoundationFixtureWithWriter(t, filesystem.NewSecureWriter())
}

func newFoundationFixtureWithEvidence(t *testing.T, evidence doctor.EvidenceReader) foundationFixture {
	t.Helper()
	fixture := newFoundationFixture(t)
	reader, err := gittarget.New(gittarget.NewExecRunner())
	if err != nil {
		t.Fatal(err)
	}
	followup, delta, rerun, retention, exports := g008Dependencies()
	resolver := g008RequestResolver{}
	application, err := NewApplication(Dependencies{
		Clock:                fixedFoundationClock{now: time.Date(2026, time.July, 14, 12, 0, 0, 0, time.UTC)},
		RequestIDGenerator:   fixedFoundationRequestIDs{},
		Catalog:              fixture.catalog,
		JSONSchemaValidator:  fixture.validator,
		SecureWriter:         fixture.writer,
		TrustedProjectReader: reader,
		EnvironmentInspector: environment.NewInspector(),
		RequestResolver:      resolver,
		EvidenceReader:       evidence,
		FollowupRuns:         followup,
		DeltaRuns:            delta,
		Reruns:               rerun,
		Retention:            retention,
		Exports:              exports,
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture.application = application
	return fixture
}
func newFoundationFixtureWithWriter(t *testing.T, secureWriter ports.SecureFileWriter) foundationFixture {
	t.Helper()
	ctx := context.Background()
	catalog := builtin.NewCatalog()
	validator, err := jsonschema.New(ctx, catalog)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := gittarget.New(gittarget.NewExecRunner())
	if err != nil {
		t.Fatal(err)
	}
	writer := &receiptCapturingFoundationWriter{delegate: secureWriter}
	followup, delta, rerun, retention, exports := g008Dependencies()
	resolver := g008RequestResolver{}
	application, err := NewApplication(Dependencies{
		Clock:                fixedFoundationClock{now: time.Date(2026, time.July, 14, 12, 0, 0, 0, time.UTC)},
		RequestIDGenerator:   fixedFoundationRequestIDs{},
		Catalog:              catalog,
		JSONSchemaValidator:  validator,
		SecureWriter:         writer,
		TrustedProjectReader: reader,
		EnvironmentInspector: environment.NewInspector(),
		RequestResolver:      resolver,
		FollowupRuns:         followup,
		DeltaRuns:            delta,
		Reruns:               rerun,
		Retention:            retention,
		Exports:              exports,
	})
	if err != nil {
		t.Fatal(err)
	}
	return foundationFixture{application: application, catalog: catalog, validator: validator, writer: writer}
}

func testAnchoredRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root = filepath.Clean(root)
	if _, err := ports.NewAnchoredRoot(root); err != nil {
		t.Fatal(err)
	}
	runFoundationGit(t, root, "init", "-q")
	runFoundationGit(t, root, "-c", "user.name=Mulgae Test", "-c", "user.email=mulgae@example.test", "commit", "--allow-empty", "-q", "-m", "initial")
	return root
}

func assertFoundationEnvelope(t *testing.T, fixture foundationFixture, result Result, wantExit app.ExitCode) {
	t.Helper()
	if result.ExitCode() != wantExit {
		t.Fatalf("exit = %d, want %d; stdout = %q; stderr = %q", result.ExitCode(), wantExit, result.Stdout(), result.Stderr())
	}
	if len(result.Stdout()) == 0 {
		t.Fatalf("exit %d omitted JSON envelope; stderr = %q", wantExit, result.Stderr())
	}
	if !bytes.HasSuffix(result.Stdout(), []byte("\n")) || bytes.HasSuffix(result.Stdout(), []byte("\n\n")) {
		t.Fatalf("JSON output does not have exactly one terminal LF: %q", result.Stdout())
	}
	schema := mustFoundationAssetID(t, commandSchemaID)
	if err := fixture.validator.Validate(context.Background(), schema, result.Stdout()); err != nil {
		t.Fatalf("command envelope is not schema-valid: %v", err)
	}
}
func assertCommittedOutcomeEnvelope(t *testing.T, result Result, wantExit app.ExitCode, wantReason string) {
	t.Helper()
	var envelope struct {
		Exit struct {
			Code int    `json:"code"`
			Kind string `json:"kind"`
		} `json:"exit"`
		Reasons []struct {
			Code string `json:"code"`
		} `json:"reasons"`
	}
	if err := json.Unmarshal(result.Stdout(), &envelope); err != nil {
		t.Fatal(err)
	}
	wantKind := "policy"
	if wantExit == app.ExitCodeReadiness {
		wantKind = "readiness"
	}
	if envelope.Exit.Code != int(wantExit) || envelope.Exit.Kind != wantKind {
		t.Fatalf("committed envelope exit = %#v, want code %d kind %q", envelope.Exit, wantExit, wantKind)
	}
	if len(envelope.Reasons) != 1 || envelope.Reasons[0].Code != wantReason {
		t.Fatalf("committed envelope reasons = %#v, want %q", envelope.Reasons, wantReason)
	}
}

func assertPersistedConfiguration(t *testing.T, root string, result Result) {
	t.Helper()
	uri := commandResultURI(t, result.Stdout(), "resolved_policy_uri")
	if uri == "" {
		t.Fatal("configuration envelope omitted output URI")
	}
	contents, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(uri)))
	if err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		Result struct {
			PolicySHA256 string `json:"policy_sha256"`
		} `json:"result"`
	}
	if err := json.Unmarshal(result.Stdout(), &envelope); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(contents)
	if got, want := envelope.Result.PolicySHA256, "sha256:"+hex.EncodeToString(sum[:]); got != want {
		t.Fatalf("configuration hash = %q, want %q", got, want)
	}
}
func assertFoundationConfigReceipt(t *testing.T, writer *receiptCapturingFoundationWriter, wantSourceIDs []string) {
	t.Helper()
	if len(writer.requests) != 1 || len(writer.receipts) != 1 {
		t.Fatalf("config writes = requests %d receipts %d, want one accepted write", len(writer.requests), len(writer.receipts))
	}
	request := writer.requests[0]
	receipt := writer.receipts[0]
	if request.Channel() != "config_resolution" {
		t.Fatalf("config request channel = %q, want config_resolution", request.Channel())
	}
	if !reflect.DeepEqual(request.SourceIDs(), wantSourceIDs) {
		t.Fatalf("config request source IDs = %#v, want %#v", request.SourceIDs(), wantSourceIDs)
	}
	if receipt.Destination() != request.Destination() || !reflect.DeepEqual(receipt.SourceIDs(), request.SourceIDs()) {
		t.Fatalf("config receipt identity = destination %q source IDs %#v, want destination %q source IDs %#v", receipt.Destination().String(), receipt.SourceIDs(), request.Destination().String(), request.SourceIDs())
	}
}

func commandResultURI(t *testing.T, envelope []byte, field string) string {
	t.Helper()
	var document struct {
		Result map[string]json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(envelope, &document); err != nil {
		t.Fatal(err)
	}
	raw, available := document.Result[field]
	if !available {
		t.Fatalf("envelope result has no %q", field)
	}
	var uri string
	if err := json.Unmarshal(raw, &uri); err != nil {
		t.Fatal(err)
	}
	return uri
}

func expectedTextOutput(value []byte) []byte {
	trimmed := bytes.TrimRight(value, "\n")
	return append(append([]byte(nil), trimmed...), '\n')
}

func mustFoundationAssetID(t *testing.T, value string) ports.AssetID {
	t.Helper()
	id, err := ports.ParseAssetID(value)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func runFoundationGit(t *testing.T, root string, arguments ...string) {
	t.Helper()
	command := exec.Command("git", arguments...)
	command.Dir = root
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git %v failed: %v: %s", arguments, err, output)
	}
}
func foundationGitOutput(t *testing.T, root string, arguments ...string) string {
	t.Helper()
	command := exec.Command("git", arguments...)
	command.Dir = root
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v failed: %v: %s", arguments, err, output)
	}
	return strings.TrimSpace(string(output))
}

// TestProviderFailureHintRoutesByRemediation pins which command a provider
// failure sends the operator to. Mulgae never substitutes a provider for a
// failed role, so this hint plus the report's "Provider issues" section are the
// whole recovery path; sending someone to `mulgae doctor` for a provider that
// is perfectly healthy and merely failed once wastes their time and hides the
// real next step. It also keeps the CLI and the report saying the same thing.
func TestProviderFailureHintRoutesByRemediation(t *testing.T) {
	t.Parallel()

	const (
		doctor = "mulgae doctor"
		rerun  = "mulgae rerun"
		config = "mulgae config --mode effective"
	)
	want := map[review.AttemptCondition]string{
		// The provider itself must be fixed before it can review anything.
		review.AttemptConditionProviderUnavailable: doctor,
		review.AttemptConditionProviderSpawnFailed: doctor,
		review.AttemptConditionAuthentication:      doctor,
		review.AttemptConditionLoginRequired:       doctor,
		review.AttemptConditionQuota:               doctor,
		// Permission is configuration, not provider health.
		review.AttemptConditionProviderPermissionDenied: config,
		// The provider failed once; running the role again is the next step.
		review.AttemptConditionRateLimit:                  rerun,
		review.AttemptConditionTimeout:                    rerun,
		review.AttemptConditionProviderTimeout:            rerun,
		review.AttemptConditionProviderOutputMissing:      rerun,
		review.AttemptConditionProviderOutputDecodeFailed: rerun,
		review.AttemptConditionInvalidProviderOutput:      rerun,
		review.AttemptConditionSemanticContradiction:      rerun,
		// Not the provider's fault; doctor stays the conservative entry point.
		review.AttemptConditionSecurityViolation: doctor,
		review.AttemptConditionArtifactFailure:   doctor,
		review.AttemptConditionInternalInvariant: doctor,
	}
	for condition, expected := range want {
		if got := providerFailureHint(condition); got != expected {
			t.Errorf("providerFailureHint(%q) = %q, want %q", condition, got, expected)
		}
	}

	// Every condition the coordinator can produce must route somewhere, and a
	// provider that is merely at fault must never be sent to doctor.
	for _, condition := range review.AttemptConditions() {
		hint := providerFailureHint(condition)
		if hint == "" {
			t.Errorf("condition %q has no remediation hint", condition)
		}
		if review.ConditionProviderFault(condition) && !review.ConditionProviderUnusable(condition) &&
			condition != review.AttemptConditionProviderPermissionDenied && hint != rerun {
			t.Errorf("recoverable provider fault %q routes to %q, want %q", condition, hint, rerun)
		}
	}
}
