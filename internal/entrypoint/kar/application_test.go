//go:build darwin && arm64

package kar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/irootkernel/kkachi-agent-review/internal/adapters/environment"
	"github.com/irootkernel/kkachi-agent-review/internal/adapters/filesystem"
	"github.com/irootkernel/kkachi-agent-review/internal/adapters/gittarget"
	"github.com/irootkernel/kkachi-agent-review/internal/adapters/jsonschema"
	"github.com/irootkernel/kkachi-agent-review/internal/app"
	appschema "github.com/irootkernel/kkachi-agent-review/internal/app/schema"
	"github.com/irootkernel/kkachi-agent-review/internal/builtin"
	"github.com/irootkernel/kkachi-agent-review/internal/domain"
	"github.com/irootkernel/kkachi-agent-review/internal/ports"
)

const foundationRequestID = "i_019f596a-cf80-7c67-b265-f37053d51ccf"
const commandSchemaID = "https://kar.local/schemas/kar-command-result.v1.schema.json"

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

type receiptCapturingFoundationWriter struct {
	delegate   ports.SecureFileWriter
	requests   []ports.SecureWriteRequest
	receipts   []ports.SecureWriteReceipt
	afterWrite func()
}

func (writer *receiptCapturingFoundationWriter) EnsurePrivateDir(root ports.AnchoredRoot, directory ports.SafeRelativePath) error {
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

func (writer *receiptCapturingFoundationWriter) reset() {
	writer.requests = nil
	writer.receipts = nil
}

type controlledFoundationWriter struct {
	drop        *ports.DropMetadata
	writeErr    error
	abortCause  error
	invokeAbort bool
	abortCalls  int
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
	if malformed.ExitCode() != app.ExitCodeUsage || len(malformed.Stdout()) != 0 || !bytes.Equal(malformed.Stderr(), []byte("kar: invalid command usage\n")) {
		t.Fatalf("malformed usage result = %#v", malformed)
	}

	future := fixture.application.Run(ctx, []string{"review"}, root)
	if future.ExitCode() != app.ExitCodeUsage || len(future.Stdout()) != 0 || !bytes.Equal(future.Stderr(), []byte("kar: command is unavailable in this foundation milestone\n")) {
		t.Fatalf("future command result = %#v", future)
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
	if listJSON.ExitCode() != app.ExitCodeUsage || len(listJSON.Stdout()) != 0 || !bytes.Equal(listJSON.Stderr(), []byte("kar: invalid command usage\n")) {
		t.Fatalf("schema list JSON result = %#v", listJSON)
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
	argv := []string{"init", "--output", "json"}

	first := fixture.application.Run(ctx, argv, root)
	assertFoundationEnvelope(t, fixture, first, app.ExitCodeSuccess)
	if _, err := os.Stat(filepath.Join(root, ".kar.yaml")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, ".gitignore")); !os.IsNotExist(err) {
		t.Fatalf("init mutated .gitignore or stat failed: %v", err)
	}

	second := fixture.application.Run(ctx, argv, root)
	assertFoundationEnvelope(t, fixture, second, app.ExitCodeArtifact)
	if len(second.Stderr()) != 0 || len(second.Stdout()) == 0 {
		t.Fatalf("JSON initialization failure streams = stdout %q stderr %q", second.Stdout(), second.Stderr())
	}
}

func TestApplicationPreservesCommittedSuccessWhenContextCancelsAfterWrite(t *testing.T) {
	fixture := newFoundationFixture(t)
	root := testAnchoredRoot(t)
	ctx, cancel := context.WithCancel(context.Background())
	fixture.writer.afterWrite = cancel

	result := fixture.application.Run(ctx, []string{"init", "--output", "json"}, root)
	assertFoundationEnvelope(t, fixture, result, app.ExitCodeSuccess)
	if _, err := os.Stat(filepath.Join(root, ".kar.yaml")); err != nil {
		t.Fatalf("committed config is absent: %v", err)
	}
}

func TestApplicationConfigNoProjectAndCommittedProject(t *testing.T) {
	fixture := newFoundationFixture(t)
	ctx := context.Background()

	withoutProjectRoot := testAnchoredRoot(t)
	withoutProject := fixture.application.Run(ctx, []string{"config", "--project-config", "none", "--output", "json"}, withoutProjectRoot)
	assertFoundationEnvelope(t, fixture, withoutProject, app.ExitCodeSuccess)
	assertPersistedConfiguration(t, withoutProjectRoot, withoutProject)
	assertFoundationConfigReceipt(t, fixture.writer, []string{globalConfigAssetID, "config:resolved-policy:v1"})
	fixture.writer.reset()

	projectRoot := testAnchoredRoot(t)
	runFoundationGit(t, projectRoot, "init")
	initialized := fixture.application.Run(ctx, []string{"init", "--name", "project"}, projectRoot)
	if initialized.ExitCode() != app.ExitCodeSuccess {
		t.Fatalf("initialization for committed config = exit %d stderr %q", initialized.ExitCode(), initialized.Stderr())
	}
	runFoundationGit(t, projectRoot, "add", ".kar.yaml")
	runFoundationGit(t, projectRoot, "-c", "user.name=KAR Test", "-c", "user.email=kar@example.test", "commit", "-m", "add project config")
	commit := foundationGitOutput(t, projectRoot, "rev-parse", "HEAD")
	if err := os.WriteFile(filepath.Join(projectRoot, ".kar.yaml"), []byte("not: trusted\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fixture.writer.reset()

	withProject := fixture.application.Run(ctx, []string{"config", "--project-config", ".kar.yaml", "--ref", commit, "--mode", "provenance"}, projectRoot)
	if withProject.ExitCode() != app.ExitCodeSuccess {
		t.Fatalf("committed configuration = exit %d stdout %q stderr %q", withProject.ExitCode(), withProject.Stdout(), withProject.Stderr())
	}
	if len(fixture.writer.requests) != 0 || len(fixture.writer.receipts) != 0 {
		t.Fatalf("human configuration unexpectedly persisted output: requests %d receipts %d", len(fixture.writer.requests), len(fixture.writer.receipts))
	}

	var document struct {
		Mode              string `json:"mode"`
		ProjectProvenance *struct {
			Commit string `json:"commit"`
			Path   string `json:"path"`
		} `json:"project_provenance"`
	}
	if err := json.Unmarshal(withProject.Stdout(), &document); err != nil {
		t.Fatal(err)
	}
	if document.Mode != "provenance" || document.ProjectProvenance == nil || document.ProjectProvenance.Commit != commit || document.ProjectProvenance.Path != ".kar.yaml" {
		t.Fatalf("committed configuration provenance = %#v", document)
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
	directory, err := ports.NewSafeRelativePath(".kar/config")
	if err != nil {
		t.Fatal(err)
	}
	destination, err := ports.NewSafeRelativePath(".kar/config/callback.json")
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

	result := fixture.application.Run(context.Background(), []string{"config", "--project-config", "none", "--output", "json"}, root)
	assertFoundationEnvelope(t, fixture, result, app.ExitCodeSecurity)
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
	directory, err := ports.NewSafeRelativePath(".kar/config")
	if err != nil {
		t.Fatal(err)
	}
	destination, err := ports.NewSafeRelativePath(".kar/config/rejected.json")
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
		{name: "init", argv: []string{"init"}, exit: app.ExitCodeArtifact},
		{name: "doctor", argv: []string{"doctor"}, exit: app.ExitCodeArtifact},
		{name: "config", argv: []string{"config", "--project-config", "none"}, exit: app.ExitCodeSecurity},
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

func TestApplicationDoctorPersistsValidatedUnverifiedResult(t *testing.T) {
	fixture := newFoundationFixture(t)
	root := testAnchoredRoot(t)
	result := fixture.application.Run(context.Background(), []string{"doctor", "--output", "json"}, root)
	assertFoundationEnvelope(t, fixture, result, app.ExitCodeReadiness)
	if len(result.Stderr()) != 0 {
		t.Fatalf("doctor JSON stderr = %q, want empty", result.Stderr())
	}

	uri := commandResultURI(t, result.Stdout(), "doctor_result_uri")
	if uri == "" {
		t.Fatal("doctor envelope omitted persisted primary output URI")
	}
	contents, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(uri)))
	if err != nil {
		t.Fatal(err)
	}
	doctorSchema := mustFoundationAssetID(t, doctorResultSchema)
	if err := fixture.validator.Validate(context.Background(), doctorSchema, contents); err != nil {
		t.Fatalf("persisted doctor result is not schema-valid: %v", err)
	}
}

func newFoundationFixture(t *testing.T) foundationFixture {
	t.Helper()
	return newFoundationFixtureWithWriter(t, filesystem.NewSecureWriter())
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
	application, err := NewApplication(Dependencies{
		Clock:                fixedFoundationClock{now: time.Date(2026, time.July, 14, 12, 0, 0, 0, time.UTC)},
		RequestIDGenerator:   fixedFoundationRequestIDs{},
		Catalog:              catalog,
		JSONSchemaValidator:  validator,
		SecureWriter:         writer,
		TrustedProjectReader: reader,
		EnvironmentInspector: environment.NewInspector(),
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
