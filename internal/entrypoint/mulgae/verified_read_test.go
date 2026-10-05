package mulgae

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/irootkernel/mulgae/internal/app"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/adapters/gittarget"
	"github.com/irootkernel/mulgae/internal/app/query"
	"github.com/irootkernel/mulgae/internal/app/recovery"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

func (fake *g006QueryFake) Inspect(ctx context.Context, run ports.PublicationRun, binding domain.ProjectBinding, request query.InspectionRequest) (query.Inspection, error) {
	view, err := fake.ListFindings(ctx, run, request.MinimumSeverity)
	if err != nil {
		return query.Inspection{}, err
	}
	page := query.Inspection{FailedRunRecovery: recovery.UnavailableStatus("published_review"), RunID: view.RunID, ReviewArtifactURI: view.ReviewArtifactURI, FindingCount: len(view.Findings), ReturnedCount: len(view.Findings), Findings: []query.FindingSummary{}, RoleReports: []query.InspectionRoleReport{}}
	for _, f := range view.Findings {
		page.Findings = append(page.Findings, query.FindingSummary{ID: f.ID, Title: f.Title, Severity: string(f.Severity), Evidence: []query.FindingEvidenceReference{}})
	}
	return page, nil
}
func (fake *g006QueryFake) ReadFinding(context.Context, ports.PublicationRun, domain.ProjectBinding, string, query.ContentContinuation) (query.ContentChunk, error) {
	return query.ContentChunk{}, errors.New("unexpected finding detail read")
}

func mustVerifiedReadContexts(t *testing.T) *query.ProjectContextService {
	t.Helper()
	service, err := query.NewProjectContextService(gittarget.ProjectBindingObserver{})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func TestVerifiedReadParserSelectors(t *testing.T) {
	digest := "sha256:" + strings.Repeat("1", 64)
	invocation, err := Parse([]string{"inspect", "--run", testRunID, "--limit", "2", "--cursor", "opaque", "--expected-project-binding", digest, "--expected-publication-receipt", digest, "--output", "json"}, "/project", "i_01234567-89ab-7cde-8f01-23456789abcd")
	if err != nil {
		t.Fatal(err)
	}
	if invocation.verifiedRead.Page.Limit != 2 || invocation.verifiedRead.Page.MinimumSeverity != domain.SeverityLow || invocation.verifiedRead.Page.Cursor != "opaque" || invocation.verifiedRead.ExpectedProjectBinding != digest {
		t.Fatalf("lost selectors: %+v", invocation.verifiedRead)
	}
	for _, arguments := range [][]string{
		{"inspect", "--run", testRunID, "--limit", "1001"},
		{"inspect", "--run", "latest"},
		{"read-finding", "--run", testRunID, "--finding", "F001", "--offset", "01"},
		{"read-finding", "--run", testRunID, "--finding", "F001", "--offset", "9223372036854775808"},
		{"findings", "--run", testRunID},
	} {
		if _, err := Parse(arguments, "/project", "i_01234567-89ab-7cde-8f01-23456789abcd"); err == nil {
			t.Fatalf("accepted %v", arguments)
		}
	}
	invocation, err = Parse([]string{"read-finding", "--run", testRunID, "--finding", "F1000", "--offset", "9223372036854775807", "--expected-publication-receipt", digest, "--expected-content-sha256", digest}, "/project", "i_01234567-89ab-7cde-8f01-23456789abcd")
	if err != nil || invocation.verifiedRead.Continuation.Offset != math.MaxInt64 {
		t.Fatalf("64-bit offset: %v", err)
	}
}

func TestLiveEvidenceRequestPreservesZeroIndex(t *testing.T) {
	digest := "sha256:" + strings.Repeat("1", 64)
	invocation, err := Parse([]string{"excerpt", "--run", testRunID, "--finding", "F001", "--source-identity-sha256", digest, "--evidence-index", "0"}, "/project", "i_01234567-89ab-7cde-8f01-23456789abcd")
	if err != nil {
		t.Fatal(err)
	}
	var request map[string]any
	if err := json.Unmarshal(invocation.requestJSON, &request); err != nil {
		t.Fatal(err)
	}
	index, present := request["evidence_index"]
	if !present || index != float64(0) || request["source_identity_sha256"] != digest {
		t.Fatalf("first live evidence selector lost its canonical zero index: %s", invocation.requestJSON)
	}
}

func TestVerifiedReadBindingAndContinuationRejectBeforeQuery(t *testing.T) {
	fake := newG006QueryFake()
	fixture := newG006Fixture(t, fake, newG006ReportFake())
	root := testAnchoredRoot(t)
	result := fixture.application.Run(context.Background(), []string{"inspect", "--run", testRunID, "--expected-project-binding", "sha256:" + strings.Repeat("9", 64), "--output", "json"}, root)
	assertFoundationEnvelope(t, fixture, result, app.ExitCodeUsage)
	if len(fake.resolveRoots) != 0 || !bytes.Contains(result.Stdout(), []byte("project_binding_mismatch")) {
		t.Fatalf("binding guard did not precede query: %s", result.Stdout())
	}
	result = fixture.application.Run(context.Background(), []string{"read-finding", "--run", testRunID, "--finding", "F001", "--offset", "16384"}, root)
	if result.ExitCode() != app.ExitCodeUsage || !bytes.Contains(result.Stderr(), []byte("read_continuation_incomplete")) || len(fake.resolveRoots) != 0 {
		t.Fatalf("incomplete continuation: %d %s", result.ExitCode(), result.Stderr())
	}
}

func TestInspectionDiagnosticFallbackDoesNotHideCorruption(t *testing.T) {
	fake := &g006QueryFake{resolveErr: ports.ErrPublicationRunNotFound}
	fixture := newG006Fixture(t, fake, newG006ReportFake())
	root := testAnchoredRoot(t)
	session, _ := domain.ParseSessionID(g006SessionID)
	run, _ := domain.ParseRunID(testRunID)
	now := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	status, err := ports.NewRuntimeDiagnosticRunStatus(ports.RuntimeDiagnosticRunStatusInput{SessionID: session, RunID: run, State: domain.RunFailed, StartedAt: now, UpdatedAt: now, CompletedAt: now, HasCompletedAt: true, SelectedRoles: []domain.Role{domain.RoleLogic}, RolePathTotal: 1, RolePathFailed: 1, LastSequence: 1, TerminalCause: domain.DiagnosticCauseProviderSpawnFailed})
	if err != nil {
		t.Fatal(err)
	}
	fixture.application.diagnosticQueries = diagnosticQueryFake{status: status}
	argv := []string{"inspect", "--run", testRunID, "--output", "json"}
	result := fixture.application.Run(context.Background(), argv, root)
	assertFoundationEnvelope(t, fixture, result, app.ExitCodeSuccess)
	if commandResultKind(t, result.Stdout()) != "diagnostic_status_read" || bytes.Contains(result.Stdout(), []byte("publication_receipt")) {
		t.Fatalf("diagnostic authority: %s", result.Stdout())
	}
	fake.resolveErr = errors.Join(ports.ErrPublicationRunNotFound, errors.New("corrupt publication"))
	result = fixture.application.Run(context.Background(), argv, root)
	assertFoundationEnvelope(t, fixture, result, app.ExitCodeArtifact)
	if commandResultKind(t, result.Stdout()) == "diagnostic_status_read" {
		t.Fatal("corruption fell back to diagnostic status")
	}
}

// FindingView is one finding in the query service's preserved final order.
type FindingView struct {
	ID          string
	Severity    domain.Severity
	Title       string
	HasEvidence bool
}

// FindingsView is a committed finding selection and its committed review URI.
type FindingsView struct {
	RunID             string
	Findings          []FindingView
	ReviewArtifactURI string
	TargetSHA256      string
}

func TestVerifiedReadEnvelopeRejectsUnknownContractFields(t *testing.T) {
	fixture := newFoundationFixture(t)
	schema := mustFoundationAssetID(t, "https://mulgae.local/schemas/mulgae-command-result.v16.schema.json")
	exampleID := mustFoundationAssetID(t, "example:command-result.v16.valid.json")
	_, raw, err := fixture.catalog.Read(context.Background(), exampleID)
	if err != nil {
		t.Fatal(err)
	}
	if err = fixture.validator.Validate(context.Background(), schema, raw); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(map[string]any){
		"unknown page field": func(doc map[string]any) { doc["result"].(map[string]any)["raw_final"] = map[string]any{} },
		"unimplemented capability": func(doc map[string]any) {
			doc["result"].(map[string]any)["capabilities"].(map[string]any)["report_content"] = "v1"
		},
		"unknown receipt version": func(doc map[string]any) {
			doc["result"].(map[string]any)["receipt"].(map[string]any)["schema_version"] = "mulgae-publication-receipt.v999"
		},
		"oversized page": func(doc map[string]any) { doc["request"].(map[string]any)["limit"] = 1001 },
	} {
		t.Run(name, func(t *testing.T) {
			var doc map[string]any
			if err := json.Unmarshal(raw, &doc); err != nil {
				t.Fatal(err)
			}
			mutate(doc)
			changed, err := json.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
			if err = fixture.validator.Validate(context.Background(), schema, changed); err == nil {
				t.Fatal("invalid public contract accepted")
			}
		})
	}
}

func (fake *g006QueryFake) ReadReport(context.Context, ports.PublicationRun, domain.ProjectBinding, string, query.ContentContinuation) (query.ContentChunk, error) {
	return query.ContentChunk{}, errors.New("unexpected report content read")
}
func (fake *g006QueryFake) ReadEvidence(context.Context, ports.PublicationRun, domain.ProjectBinding, string, string, int, query.ContentContinuation) (query.ContentChunk, error) {
	return query.ContentChunk{}, errors.New("unexpected indexed evidence read")
}

func (fake *g006QueryFake) ReadSourceEvidence(context.Context, ports.PublicationRun, domain.ProjectBinding, string, string, int, query.ContentContinuation) (query.ContentChunk, error) {
	return query.ContentChunk{}, errors.New("unexpected source evidence read")
}

func (fake *g006QueryFake) ReadSourceImage(context.Context, ports.PublicationRun, domain.ProjectBinding, string, string, string, query.ContentContinuation) (query.ContentChunk, error) {
	return query.ContentChunk{}, errors.New("unexpected source image read")
}

func TestVerifiedContentParserPreservesSelectorsAndLegacyExcerpt(t *testing.T) {
	digest := "sha256:" + strings.Repeat("1", 64)
	requestID := "i_01234567-89ab-7cde-8f01-23456789abcd"
	base := []string{"excerpt", "--run", testRunID, "--finding", "F001", "--current-target-sha256", digest}
	legacy, err := Parse(base, "/project", requestID)
	if err != nil || legacy.verifiedRead != nil || legacy.excerpt == nil {
		t.Fatalf("legacy excerpt changed: %v", err)
	}
	for _, index := range []string{"0", "19"} {
		arguments := append(append([]string{}, base...), "--evidence-index", index)
		invocation, err := Parse(arguments, "/project", requestID)
		if err != nil || invocation.verifiedRead == nil || invocation.verifiedRead.TargetSHA256 != digest {
			t.Fatalf("lost indexed selector: %v", err)
		}
	}
	for _, arguments := range [][]string{
		append(append([]string{}, base...), "--evidence-index", "20"),
		append(append([]string{}, base...), "--evidence-index", "01"),
		append(append([]string{}, base...), "--offset", "16384"),
		{"read-report", "--run", testRunID, "--role", "unknown"},
		{"read-report", "--run", testRunID, "--output-path", "report.md"},
		{"read-report", "--run", testRunID, "--offset", "16384"},
	} {
		if _, err := Parse(arguments, "/project", requestID); err == nil {
			t.Fatalf("accepted %v", arguments)
		}
	}
	invocation, err := Parse([]string{"read-report", "--run", testRunID, "--role", "logic", "--offset", "16384", "--expected-publication-receipt", digest, "--expected-content-sha256", digest}, "/project", requestID)
	if err != nil || invocation.verifiedRead.Role != "logic" || invocation.verifiedRead.Continuation.Offset != 16384 {
		t.Fatalf("lost report selectors: %v", err)
	}
}

func TestVerifiedContentEnvelopeRejectsInvalidSelectorsAndFields(t *testing.T) {
	fixture := newFoundationFixture(t)
	schema := mustFoundationAssetID(t, "https://mulgae.local/schemas/mulgae-command-result.v18.schema.json")
	_, raw, err := fixture.catalog.Read(context.Background(), mustFoundationAssetID(t, "example:command-result.v18.valid.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.validator.Validate(context.Background(), schema, raw); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(map[string]any){
		"unknown report role":  func(doc map[string]any) { doc["request"].(map[string]any)["role"] = "unknown" },
		"write selector":       func(doc map[string]any) { doc["request"].(map[string]any)["output_path"] = "report.md" },
		"unknown result field": func(doc map[string]any) { doc["result"].(map[string]any)["raw_final"] = true },
		"oversized chunk":      func(doc map[string]any) { doc["result"].(map[string]any)["returned_bytes"] = 16385 },
	} {
		t.Run(name, func(t *testing.T) {
			var doc map[string]any
			if err := json.Unmarshal(raw, &doc); err != nil {
				t.Fatal(err)
			}
			mutate(doc)
			changed, err := json.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
			if err := fixture.validator.Validate(context.Background(), schema, changed); err == nil {
				t.Fatal("invalid content contract accepted")
			}
		})
	}
}

func TestHumanOutputEscapesTerminalControlsPreservesJSON(t *testing.T) {
	title := "Finding \x1b[31mspoof\x1b[0m \x1b]8;;https://example.invalid\x07link\x1b]8;;\x07 \u009b31m"
	fake := newG006QueryFake()
	fake.findings.Findings[0].Title = title
	fixture := newG006Fixture(t, fake, newG006ReportFake())
	root := testAnchoredRoot(t)
	human := fixture.application.Run(context.Background(), []string{"inspect", "--run", testRunID}, root)
	if human.ExitCode() != app.ExitCodeSuccess {
		t.Fatalf("synthetic fixture did not reach human output: exit=%d", human.ExitCode())
	}
	var stdout, stderr bytes.Buffer
	if err := human.WriteTo(&stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if bytes.ContainsAny(stdout.Bytes(), "\x1b\x07\u009b") {
		t.Fatal("human inspection delivers executable terminal control characters")
	}
	for _, expected := range []string{`\x1b[31m`, `\x07`, `\x9b31m`} {
		if !strings.Contains(stdout.String(), expected) {
			t.Fatal("human output did not visibly escape terminal controls")
		}
	}
	machine := fixture.application.Run(context.Background(), []string{"inspect", "--run", testRunID, "--output", "json"}, root)
	if machine.ExitCode() != app.ExitCodeSuccess {
		t.Fatal("machine fixture failed")
	}
	var envelope struct {
		Result struct {
			Findings []struct {
				Title string `json:"title"`
			} `json:"findings"`
		} `json:"result"`
	}
	if err := json.Unmarshal(machine.Stdout(), &envelope); err != nil {
		t.Fatal(err)
	}
	if len(envelope.Result.Findings) == 0 || envelope.Result.Findings[0].Title != title {
		t.Fatal("machine finding text changed")
	}
}

func TestHumanExcerptEscapesControlsPreservesExactMachineBytes(t *testing.T) {
	fake := newG006QueryFake()
	fake.excerpt = []byte("plain\ttext\n\x1b[2J\x00\r\x7f\u009d title\n\n")
	fixture := newG006Fixture(t, fake, newG006ReportFake())
	root := testAnchoredRoot(t)
	argv := []string{"excerpt", "--run", testRunID, "--finding", "F001", "--current-target-sha256", testCurrentTargetSHA256}
	human := fixture.application.Run(context.Background(), argv, root)
	if human.ExitCode() != app.ExitCodeSuccess {
		t.Fatal("excerpt fixture failed")
	}
	for _, value := range []byte{0x1b, 0, 0x0d, 0x7f} {
		if bytes.Contains(human.Stdout(), []byte{value}) {
			t.Fatal("human excerpt delivers executable terminal controls")
		}
	}
	if !bytes.HasPrefix(human.Stdout(), []byte("plain\ttext\n")) || !bytes.HasSuffix(human.Stdout(), []byte("\n\n")) {
		t.Fatal("human excerpt changed ordinary whitespace")
	}
	machine := fixture.application.Run(context.Background(), append(argv, "--output", "json"), root)
	var envelope struct {
		Result struct {
			ExcerptBase64 string `json:"excerpt_base64"`
		} `json:"result"`
	}
	if machine.ExitCode() != app.ExitCodeSuccess {
		t.Fatal("machine excerpt fixture failed")
	}
	if err := json.Unmarshal(machine.Stdout(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Result.ExcerptBase64 != base64.StdEncoding.EncodeToString(fake.excerpt) {
		t.Fatal("machine excerpt did not retain exact evidence bytes")
	}
}
