//go:build darwin && arm64

package kar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
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
	"github.com/irootkernel/kkachi-agent-review/internal/app/doctor"
	appschema "github.com/irootkernel/kkachi-agent-review/internal/app/schema"
	"github.com/irootkernel/kkachi-agent-review/internal/builtin"
	"github.com/irootkernel/kkachi-agent-review/internal/domain"
	"github.com/irootkernel/kkachi-agent-review/internal/ports"
)

const (
	foundationRequestID           = "i_019f596a-cf80-7c67-b265-f37053d51ccf"
	commandSchemaID               = "https://kar.local/schemas/kar-command-result.v1.schema.json"
	foundationProviderEvidenceURI = "https://evidence.example.test/providers/authority.json"
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

type foundationEvidenceReader struct {
	providerCalls        []string
	providerEvidenceURIs map[string]string
	platformCalls        []doctor.PlatformCell
	toolsCalls           int
}

func (reader *foundationEvidenceReader) ProviderEvidence(_ context.Context, providerID string) (doctor.ProviderV2Evidence, error) {
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
	return doctor.ProviderV2Evidence{
		SchemaID:                "https://kar.local/schemas/kar-provider-contract-evidence.v2.schema.json",
		ProviderID:              providerID,
		URI:                     uri,
		SHA256:                  strings.Repeat("a", 64),
		Probes:                  probes,
		SecureWriterIndexStatus: doctor.EvidenceStatusPass,
		AssignmentStatus:        doctor.EvidenceStatusPass,
	}, nil
}

func (reader *foundationEvidenceReader) PlatformEvidence(_ context.Context, cell doctor.PlatformCell) (doctor.PlatformV2Evidence, error) {
	reader.platformCalls = append(reader.platformCalls, cell)
	return doctor.PlatformV2Evidence{}, errors.New("platform evidence was not injected")
}

func (reader *foundationEvidenceReader) ToolsLock(context.Context) (doctor.ToolsLockObservation, error) {
	reader.toolsCalls++
	return doctor.ToolsLockObservation{}, errors.New("tools lock was not injected")
}

type typedNilFoundationEvidenceReader struct{}

func (*typedNilFoundationEvidenceReader) ProviderEvidence(context.Context, string) (doctor.ProviderV2Evidence, error) {
	return doctor.ProviderV2Evidence{}, nil
}

func (*typedNilFoundationEvidenceReader) PlatformEvidence(context.Context, doctor.PlatformCell) (doctor.PlatformV2Evidence, error) {
	return doctor.PlatformV2Evidence{}, nil
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
func TestApplicationProvidersListsOnlyUnverifiedProfilesWithoutProbing(t *testing.T) {
	fixture := newFoundationFixture(t)
	root := testAnchoredRoot(t)

	human := fixture.application.Run(context.Background(), []string{"providers", "--include-unverified"}, root)
	if human.ExitCode() != app.ExitCodeReadiness || len(human.Stderr()) != 0 {
		t.Fatalf("providers human result = exit %d stdout %q stderr %q", human.ExitCode(), human.Stdout(), human.Stderr())
	}
	lines := strings.Split(strings.TrimSuffix(string(human.Stdout()), "\n"), "\n")
	wantFamilies := []string{"kimi", "zcode", "agy"}
	if len(lines) != len(wantFamilies) {
		t.Fatalf("providers human rows = %q, want %d rows", human.Stdout(), len(wantFamilies))
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
		!bytes.Equal(filtered.Stdout(), []byte("no evidence-qualified provider profiles\n")) ||
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
	uri := commandResultURI(t, doctorResult.Stdout(), "doctor_result_uri")
	contents, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(uri)))
	if err != nil {
		t.Fatal(err)
	}
	var diagnosis struct {
		ProviderEvidence []struct {
			ProviderID    string `json:"provider_id"`
			EvidenceState string `json:"evidence_state"`
			EvidenceURI   string `json:"evidence_uri"`
		} `json:"provider_evidence"`
	}
	if err := json.Unmarshal(contents, &diagnosis); err != nil {
		t.Fatal(err)
	}
	if len(diagnosis.ProviderEvidence) != 3 {
		t.Fatalf("doctor provider evidence rows = %d, want 3", len(diagnosis.ProviderEvidence))
	}
	for _, provider := range diagnosis.ProviderEvidence {
		if provider.EvidenceState != "pass" || provider.EvidenceURI != foundationProviderEvidenceURI {
			t.Fatalf("doctor provider evidence = %#v, want injected PASS evidence", provider)
		}
	}

	wantCalls := []string{"kimi", "zcode", "agy", "kimi", "zcode", "agy"}
	if !reflect.DeepEqual(evidence.providerCalls, wantCalls) ||
		len(evidence.platformCalls) != 2 || evidence.toolsCalls != 2 {
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

func TestApplicationProvidersLeavesFutureCommandsUnavailable(t *testing.T) {
	fixture := newFoundationFixture(t)
	root := testAnchoredRoot(t)
	for _, command := range []string{"review", "followup", "delta", "rerun", "prompt", "clean", "export"} {
		t.Run(command, func(t *testing.T) {
			result := fixture.application.Run(context.Background(), []string{command}, root)
			if result.ExitCode() != app.ExitCodeUsage || len(result.Stdout()) != 0 ||
				!bytes.Equal(result.Stderr(), []byte("kar: command is unavailable in this foundation milestone\n")) {
				t.Fatalf("%s result = exit %d stdout %q stderr %q", command, result.ExitCode(), result.Stdout(), result.Stderr())
			}
		})
	}
}

const (
	g006SessionID         = "s_019f596a-cfe4-7c9c-b82e-7149158243ba"
	g006ReviewArtifactURI = ".kar/s_019f596a-cfe4-7c9c-b82e-7149158243ba/r_019f596a-cf80-7c67-b265-f37053d51ccf/review_019f596a-d048-79e7-b2b7-59822f012273.json"
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
		if got, want := artifactRoot.String(), filepath.Join(root, ".kar"); got != want {
			t.Fatalf("publication root = %q, want %q", got, want)
		}
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
		".kar/reports/review.md",
		".KAR/reports/review.md",
		".git/reports/review.md",
		".Git/reports/review.md",
		".gjc/reports/review.md",
		".GJC/reports/review.md",
		".kar.yaml",
		".KAR.YML",
		".kar.yaml/reports/review.md",
		".KAR.YML/reports/review.md",
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
	destination, err := ports.NewSafeRelativePath(".KAR.YAML/reports/review.md")
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
		{name: "artifact over security and cancellation", err: errors.Join(context.Canceled, security, artifact), exit: app.ExitCodeArtifact},
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
					!bytes.Equal(human.Stderr(), terminalOutput([]byte(humanFailureMessage(failure.class)))) {
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
	dependencies := Dependencies{
		Clock:                fixedFoundationClock{now: time.Date(2026, time.July, 14, 12, 0, 0, 0, time.UTC)},
		RequestIDGenerator:   fixedFoundationRequestIDs{},
		Catalog:              fixture.catalog,
		JSONSchemaValidator:  fixture.validator,
		SecureWriter:         fixture.writer,
		TrustedProjectReader: reader,
		EnvironmentInspector: environment.NewInspector(),
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
}

func newG006QueryFake() *g006QueryFake {
	return &g006QueryFake{
		status: RunStatusView{
			RunID: testRunID, RunState: domain.RunCompleted, HasRunState: true, PublicationState: domain.PublicationCommitted,
			RecoveryAction:   domain.RecoveryActionReconstructCompletedStatus,
			FinalArtifactURI: g006ReviewArtifactURI, HasFinalArtifact: true,
			ContentVerdict: domain.ContentRequestChanges, CoverageStatus: domain.CoverageComplete,
			CIDecision: domain.CIFail, HasAxes: true,
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
	application, err := NewApplication(Dependencies{
		Clock:                fixedFoundationClock{now: time.Date(2026, time.July, 14, 12, 0, 0, 0, time.UTC)},
		RequestIDGenerator:   fixedFoundationRequestIDs{},
		Catalog:              fixture.catalog,
		JSONSchemaValidator:  fixture.validator,
		SecureWriter:         fixture.writer,
		TrustedProjectReader: reader,
		EnvironmentInspector: environment.NewInspector(),
		PublicationQueries:   query,
		PublicationReports:   report,
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
	application, err := NewApplication(Dependencies{
		Clock:                fixedFoundationClock{now: time.Date(2026, time.July, 14, 12, 0, 0, 0, time.UTC)},
		RequestIDGenerator:   fixedFoundationRequestIDs{},
		Catalog:              fixture.catalog,
		JSONSchemaValidator:  fixture.validator,
		SecureWriter:         fixture.writer,
		TrustedProjectReader: reader,
		EnvironmentInspector: environment.NewInspector(),
		EvidenceReader:       evidence,
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
