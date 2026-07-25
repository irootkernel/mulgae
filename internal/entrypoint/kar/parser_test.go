package kar

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/irootkernel/kkachi-agent-review/internal/app"
	"github.com/irootkernel/kkachi-agent-review/internal/domain"
)

const (
	testProjectRoot         = "/work/project"
	testRequestID           = "i_01234567-89ab-7cde-8f01-23456789abcd"
	testSchemaID            = "https://kar.local/schemas/kar-command-result.v1.schema.json"
	testCommitID            = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testRunID               = "r_019f596a-cf80-7c67-b265-f37053d51ccf"
	testCurrentTargetSHA256 = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testAttemptID           = "a_019f596a-cf80-7c67-b265-f37053d51ccf"
	testSessionID           = "s_019f596a-cf80-7c67-b265-f37053d51ccf"
)

func TestParseHelpForms(t *testing.T) {
	for _, arguments := range [][]string{nil, {"--help"}, {"help"}} {
		invocation := mustParse(t, arguments)
		if got, want := invocation.Command(), app.CommandHelp; got != want {
			t.Fatalf("Parse(%v) command = %q, want %q", arguments, got, want)
		}
		help, ok := invocation.Help()
		if !ok || help.Topic() != "quickstart" {
			t.Fatalf("Parse(%v) help = %#v, %t; want quickstart", arguments, help, ok)
		}
		assertRequestJSON(t, invocation, `{"request_id":"i_01234567-89ab-7cde-8f01-23456789abcd","command":"help","topic":"quickstart","output_format":"human"}`)
	}

	invocation := mustParse(t, []string{"help", "security", "--output", "json"})
	if got, want := invocation.OutputFormat(), OutputFormatJSON; got != want {
		t.Fatalf("help output format = %q, want %q", got, want)
	}
	assertRequestJSON(t, invocation, `{"request_id":"i_01234567-89ab-7cde-8f01-23456789abcd","command":"help","topic":"security","output_format":"json"}`)
}

func TestParseInitForms(t *testing.T) {
	defaults := mustParse(t, []string{"init"})
	request, ok := defaults.Init()
	if !ok {
		t.Fatal("init invocation has no init request")
	}
	if got, want := request.ProjectRoot(), testProjectRoot; got != want {
		t.Fatalf("default init project root = %q, want %q", got, want)
	}
	if got, want := request.ProjectName(), "project"; got != want {
		t.Fatalf("default init project name = %q, want %q", got, want)
	}
	if _, present := request.ContextPath(); present {
		t.Fatal("default init context path is present")
	}
	if mode, providers := request.Selection(); mode != "auto" || len(providers) != 0 {
		t.Fatalf("default selection = %s/%v, want auto/[]", mode, providers)
	}
	if request.Overwrite() {
		t.Fatal("init overwrite must remain false")
	}
	assertRequestJSON(t, defaults, `{"request_id":"i_01234567-89ab-7cde-8f01-23456789abcd","command":"init","project_root":"/work/project","project_name":"project","context":null,"selection":{"mode":"auto"},"roles":["logic","security","maintainability","product","documentation","testing"],"overrides":{},"overwrite":false,"output_format":"human"}`)

	invocation := mustParse(t, []string{
		"init", "--project-root", "/work/other", "--name", "other-project",
		"--context", "src/review", "--providers", "zcode,kimi", "--output", "human",
	})
	request, ok = invocation.Init()
	if !ok {
		t.Fatal("explicit init invocation has no init request")
	}
	if got, want := request.ProjectName(), "other-project"; got != want {
		t.Fatalf("init project name = %q, want %q", got, want)
	}
	if got, present := request.ContextPath(); !present || got != "src/review" {
		t.Fatalf("init context = %q, %t; want src/review, true", got, present)
	}
	_, got := request.Selection()
	if want := []string{"kimi", "zcode"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("init intended providers = %v, want %v", got, want)
	}
	assertRequestJSON(t, invocation, `{"request_id":"i_01234567-89ab-7cde-8f01-23456789abcd","command":"init","project_root":"/work/other","project_name":"other-project","context":"src/review","selection":{"mode":"selected","provider_ids":["kimi","zcode"]},"roles":["logic","security","maintainability","product","documentation","testing"],"overrides":{},"overwrite":false,"output_format":"human"}`)

	subset := mustParse(t, []string{"init", "--roles", "testing,security,logic"})
	subsetRequest, ok := subset.Init()
	if !ok || !reflect.DeepEqual(subsetRequest.Roles(), []string{"logic", "security", "testing"}) {
		t.Fatalf("init roles = %#v, %t", subsetRequest, ok)
	}
	assertRequestJSON(t, subset, `{"request_id":"i_01234567-89ab-7cde-8f01-23456789abcd","command":"init","project_root":"/work/project","project_name":"project","context":null,"selection":{"mode":"auto"},"roles":["logic","security","testing"],"overrides":{},"overwrite":false,"output_format":"human"}`)

	ui := mustParse(t, []string{"init", "--project-kind", "ui", "--artist-task", "TASK.md", "--artist-design-specs", "design-specs/**/*.png,design-specs/**/*.webp"})
	uiRequest, ok := ui.Init()
	if !ok || !reflect.DeepEqual(uiRequest.Roles(), []string{"logic", "security", "maintainability", "product", "documentation", "testing", "artist"}) {
		t.Fatalf("UI init roles = %#v, %t", uiRequest, ok)
	}
	assertRequestJSON(t, ui, `{"request_id":"i_01234567-89ab-7cde-8f01-23456789abcd","command":"init","project_root":"/work/project","project_name":"project","context":null,"project_kind":"ui","artist_task":"TASK.md","artist_design_specs":["design-specs/**/*.png","design-specs/**/*.webp"],"selection":{"mode":"auto"},"roles":["logic","security","maintainability","product","documentation","testing","artist"],"overrides":{},"overwrite":false,"output_format":"human"}`)
	for _, roles := range []string{"logic", "security,testing", "logic,documentation"} {
		if _, err := Parse([]string{"init", "--roles", roles}, testProjectRoot, testRequestID); !errors.Is(err, ErrUsage) {
			t.Errorf("init --roles %q error = %v, want usage", roles, err)
		}
	}
}

func TestParseDoctorAndConfigForms(t *testing.T) {
	doctor := mustParse(t, []string{"doctor", "--project-root", "/work/doctor", "--output", "json"})
	doctorRequest, ok := doctor.Doctor()
	if !ok || doctorRequest.ProjectRoot() != "/work/doctor" || !doctorRequest.CheckProviders() || !doctorRequest.CheckPlatform() {
		t.Fatalf("doctor request = %#v, %t; want canonical all-check request", doctorRequest, ok)
	}
	assertRequestJSON(t, doctor, `{"request_id":"i_01234567-89ab-7cde-8f01-23456789abcd","command":"doctor","project_root":"/work/doctor","check_providers":true,"check_platform":true,"output_format":"json"}`)

	defaults := mustParse(t, []string{"config"})
	configRequest, ok := defaults.Config()
	if !ok {
		t.Fatal("config invocation has no config request")
	}
	if got, want := configRequest.Mode(), ConfigModeEffective; got != want {
		t.Fatalf("default config mode = %q, want %q", got, want)
	}
	assertRequestJSON(t, defaults, `{"request_id":"i_01234567-89ab-7cde-8f01-23456789abcd","command":"config","project_root":"/work/project","mode":"effective","output_format":"human"}`)

	invocation := mustParse(t, []string{"config", "--mode", "provenance", "--output", "json"})
	configRequest, ok = invocation.Config()
	if !ok {
		t.Fatal("explicit config invocation has no config request")
	}
	if got, want := configRequest.Mode(), ConfigModeProvenance; got != want {
		t.Fatalf("config mode = %q, want %q", got, want)
	}
	assertRequestJSON(t, invocation, `{"request_id":"i_01234567-89ab-7cde-8f01-23456789abcd","command":"config","project_root":"/work/project","mode":"provenance","output_format":"json"}`)
}

func TestParseSchemaForms(t *testing.T) {
	list := mustParse(t, []string{"schema", "list", "--output", "json"})
	request, ok := list.Schema()
	if !ok || request.Operation() != SchemaOperationList {
		t.Fatalf("schema list = %#v, %t; want list request", request, ok)
	}
	if _, available := list.RequestJSON(); available {
		t.Fatal("schema list supplied a fabricated schema request JSON object despite having no v1 list variant")
	}

	show := mustParse(t, []string{"schema", "show", testSchemaID})
	request, ok = show.Schema()
	if !ok || request.Operation() != SchemaOperationShow {
		t.Fatalf("schema show = %#v, %t; want show request", request, ok)
	}
	if got, present := request.SchemaID(); !present || got != testSchemaID {
		t.Fatalf("schema show ID = %q, %t; want %q, true", got, present, testSchemaID)
	}
	assertRequestJSON(t, show, `{"request_id":"i_01234567-89ab-7cde-8f01-23456789abcd","command":"schema","schema_id":"https://kar.local/schemas/kar-command-result.v1.schema.json","export_path":null,"output_format":"human"}`)

	export := mustParse(t, []string{"schema", "export", testSchemaID, "contracts/result.json", "--project-root", "/work/export", "--output", "human"})
	request, ok = export.Schema()
	if !ok || request.Operation() != SchemaOperationExport || request.ProjectRoot() != "/work/export" {
		t.Fatalf("schema export = %#v, %t; want export request", request, ok)
	}
	if got, present := request.ExportPath(); !present || got != "contracts/result.json" {
		t.Fatalf("schema export path = %q, %t; want contracts/result.json, true", got, present)
	}
	assertRequestJSON(t, export, `{"request_id":"i_01234567-89ab-7cde-8f01-23456789abcd","command":"schema","schema_id":"https://kar.local/schemas/kar-command-result.v1.schema.json","export_path":"contracts/result.json","output_format":"human"}`)
}
func TestParsePublicationQueryForms(t *testing.T) {
	status := mustParse(t, []string{"status", "--run", testRunID, "--output", "json"})
	statusRequest, ok := status.Status()
	if !ok || statusRequest.RunID() != testRunID {
		t.Fatalf("status request = %#v, %t; want %q", statusRequest, ok, testRunID)
	}
	assertRequestJSON(t, status, `{"request_id":"i_01234567-89ab-7cde-8f01-23456789abcd","command":"status","run_id":"r_019f596a-cf80-7c67-b265-f37053d51ccf","output_format":"json"}`)

	report := mustParse(t, []string{"report", "--run", testRunID, "--output-path", "reports/run.json"})
	reportRequest, ok := report.Report()
	if !ok || reportRequest.RunID() != testRunID || reportRequest.OutputPath() != "reports/run.json" {
		t.Fatalf("report request = %#v, %t; want run and output path", reportRequest, ok)
	}
	assertRequestJSON(t, report, `{"request_id":"i_01234567-89ab-7cde-8f01-23456789abcd","command":"report","run_id":"r_019f596a-cf80-7c67-b265-f37053d51ccf","output_path":"reports/run.json","output_format":"human"}`)

	findings := mustParse(t, []string{"findings", "--run", testRunID, "--severity", "critical", "--output", "json"})
	findingsRequest, ok := findings.Findings()
	if !ok || findingsRequest.RunID() != testRunID || findingsRequest.MinimumSeverity() != domain.SeverityCritical {
		t.Fatalf("findings request = %#v, %t; want critical threshold", findingsRequest, ok)
	}
	assertRequestJSON(t, findings, `{"request_id":"i_01234567-89ab-7cde-8f01-23456789abcd","command":"findings","run_id":"r_019f596a-cf80-7c67-b265-f37053d51ccf","minimum_severity":"critical","output_format":"json"}`)

	excerpt := mustParse(t, []string{"excerpt", "--run", testRunID, "--finding", "F_SOURCE-1", "--current-target-sha256", testCurrentTargetSHA256})
	excerptRequest, ok := excerpt.Excerpt()
	if !ok ||
		excerptRequest.RunID() != testRunID ||
		excerptRequest.FindingID() != "F_SOURCE-1" ||
		excerptRequest.CurrentTargetSHA256() != testCurrentTargetSHA256 {
		t.Fatalf("excerpt request = %#v, %t; want immutable excerpt fields", excerptRequest, ok)
	}
	assertRequestJSON(t, excerpt, `{"request_id":"i_01234567-89ab-7cde-8f01-23456789abcd","command":"excerpt","run_id":"r_019f596a-cf80-7c67-b265-f37053d51ccf","finding_id":"F_SOURCE-1","current_target_sha256":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","output_format":"human"}`)
}
func TestParseG008RequestForms(t *testing.T) {
	followup := mustParse(t, []string{"followup", "--run", testRunID, "--finding", "F_SOURCE-1", "--dirty", "--output", "json"})
	followupRequest, ok := followup.Followup()
	if !ok || followupRequest.SourceRunID() != testRunID || followupRequest.FindingID() != "F_SOURCE-1" ||
		followupRequest.Target().Kind() != "dirty" || followupRequest.Target().Value() != "dirty" {
		t.Fatalf("followup request = %#v, %t; want literal source and target fields", followupRequest, ok)
	}
	if _, present := followupRequest.Objective(); present {
		t.Fatal("default followup objective must be null")
	}
	if _, present := followupRequest.Role(); present {
		t.Fatal("default followup role must be null")
	}
	assertRequestJSON(t, followup, `{"request_id":"i_01234567-89ab-7cde-8f01-23456789abcd","command":"followup","source_run_id":"r_019f596a-cf80-7c67-b265-f37053d51ccf","finding_id":"F_SOURCE-1","target":{"kind":"dirty","value":"dirty"},"objective":null,"role":null,"output_format":"json"}`)

	delta := mustParse(t, []string{"delta", "--since-run", testRunID, "--patch", "changes.patch", "--roles", "logic,security"})
	deltaRequest, ok := delta.Delta()
	if !ok || deltaRequest.SourceRunID() != testRunID || deltaRequest.Target().Kind() != "patch" ||
		!reflect.DeepEqual(deltaRequest.Roles(), []string{"logic", "security"}) {
		t.Fatalf("delta request = %#v, %t; want literal source, target, and roles", deltaRequest, ok)
	}
	roles := deltaRequest.Roles()
	roles[0] = "mutated"
	if got := deltaRequest.Roles()[0]; got != "logic" {
		t.Fatalf("delta roles mutated through accessor = %q", got)
	}
	assertRequestJSON(t, delta, `{"request_id":"i_01234567-89ab-7cde-8f01-23456789abcd","command":"delta","source_run_id":"r_019f596a-cf80-7c67-b265-f37053d51ccf","target":{"kind":"patch","value":"changes.patch"},"roles":["logic","security"],"output_format":"human"}`)

	rerun := mustParse(t, []string{"rerun", "--run", testRunID, "--attempt", testAttemptID})
	rerunRequest, ok := rerun.Rerun()
	if !ok || rerunRequest.SourceRunID() != testRunID || rerunRequest.SourceAttemptID() != testAttemptID || rerunRequest.ReplayMode() != ReplayModeExact {
		t.Fatalf("rerun request = %#v, %t; want exact replay default", rerunRequest, ok)
	}
	assertRequestJSON(t, rerun, `{"request_id":"i_01234567-89ab-7cde-8f01-23456789abcd","command":"rerun","source_run_id":"r_019f596a-cf80-7c67-b265-f37053d51ccf","source_attempt_id":"a_019f596a-cf80-7c67-b265-f37053d51ccf","replay_mode":"exact","output_format":"human"}`)

	clean := mustParse(t, []string{"clean"})
	cleanRequest, ok := clean.Clean()
	if !ok || cleanRequest.Mode() != CleanModePlan {
		t.Fatalf("clean request = %#v, %t; want plan default", cleanRequest, ok)
	}
	if _, present := cleanRequest.ExpectedPlanSHA256(); present {
		t.Fatal("clean plan hash must be null")
	}
	assertRequestJSON(t, clean, `{"request_id":"i_01234567-89ab-7cde-8f01-23456789abcd","command":"clean","mode":"plan","expected_plan_sha256":null,"output_format":"human"}`)

	planHash := "sha256:" + strings.Repeat("b", 64)
	apply := mustParse(t, []string{"clean", "--mode", "apply", "--expected-plan-sha256", planHash})
	applyRequest, ok := apply.Clean()
	if !ok || applyRequest.Mode() != CleanModeApply {
		t.Fatalf("clean apply request = %#v, %t", applyRequest, ok)
	}
	if got, present := applyRequest.ExpectedPlanSHA256(); !present || got != planHash {
		t.Fatalf("clean apply hash = %q, %t; want %q, true", got, present, planHash)
	}

	export := mustParse(t, []string{"export", "--run", testRunID, "--output-path", "exports/review.zip"})
	exportRequest, ok := export.Export()
	if !ok || exportRequest.RunID() != testRunID || exportRequest.OutputPath() != "exports/review.zip" || !exportRequest.Redacted() {
		t.Fatalf("export request = %#v, %t; want fixed redacted export", exportRequest, ok)
	}
	assertRequestJSON(t, export, `{"request_id":"i_01234567-89ab-7cde-8f01-23456789abcd","command":"export","run_id":"r_019f596a-cf80-7c67-b265-f37053d51ccf","output_path":"exports/review.zip","redacted":true,"output_format":"human"}`)
}

type parserTestResolver struct {
	runID     string
	attemptID string
	target    string
	err       error
}

func (resolver parserTestResolver) ResolveRun(context.Context, string) (string, error) {
	return resolver.runID, resolver.err
}

func (resolver parserTestResolver) ResolveAttempt(context.Context, string, string, string) (string, error) {
	return resolver.attemptID, resolver.err
}

func (resolver parserTestResolver) CaptureTarget(context.Context) (string, error) {
	return resolver.target, resolver.err
}

func TestParseResolvedFreezesCanonicalG008Requests(t *testing.T) {
	resolver := parserTestResolver{runID: testRunID, attemptID: testAttemptID, target: "stdin-capture-v1-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	followup := []string{"followup", "--run", "latest", "--finding", "F001", "--stdin", "--output", "json"}
	invocation, err := ParseResolved(context.Background(), followup, testProjectRoot, testRequestID, resolver)
	if err != nil {
		t.Fatalf("ParseResolved followup error = %v", err)
	}
	assertRequestJSON(t, invocation, `{"request_id":"i_01234567-89ab-7cde-8f01-23456789abcd","command":"followup","source_run_id":"r_019f596a-cf80-7c67-b265-f37053d51ccf","finding_id":"F001","target":{"kind":"stdin","value":"stdin-capture-v1-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"objective":null,"role":null,"output_format":"json"}`)
	if followup[2] != "latest" {
		t.Fatal("ParseResolved mutated caller arguments")
	}
	first, available := invocation.RequestJSON()
	if !available {
		t.Fatal("resolved request JSON unavailable")
	}
	first[0] = 'X'
	second, available := invocation.RequestJSON()
	if !available || second[0] != '{' {
		t.Fatal("resolved request JSON was not defensively copied")
	}

	delta, err := ParseResolved(context.Background(), []string{"delta", "--since-run", "latest", "--dirty", "--roles", "logic"}, testProjectRoot, testRequestID, resolver)
	if err != nil {
		t.Fatalf("ParseResolved delta error = %v", err)
	}
	assertRequestJSON(t, delta, `{"request_id":"i_01234567-89ab-7cde-8f01-23456789abcd","command":"delta","source_run_id":"r_019f596a-cf80-7c67-b265-f37053d51ccf","target":{"kind":"dirty","value":"dirty"},"roles":["logic"],"output_format":"human"}`)

	rerun, err := ParseResolved(context.Background(), []string{"rerun", "--run", "latest", "--role", "logic", "--provider", "kimi"}, testProjectRoot, testRequestID, resolver)
	if err != nil {
		t.Fatalf("ParseResolved rerun error = %v", err)
	}
	assertRequestJSON(t, rerun, `{"request_id":"i_01234567-89ab-7cde-8f01-23456789abcd","command":"rerun","source_run_id":"r_019f596a-cf80-7c67-b265-f37053d51ccf","source_attempt_id":"a_019f596a-cf80-7c67-b265-f37053d51ccf","replay_mode":"exact","output_format":"human"}`)

	export, err := ParseResolved(context.Background(), []string{"export", "--run", "latest", "--output-path", "exports/review.zip"}, testProjectRoot, testRequestID, resolver)
	if err != nil {
		t.Fatalf("ParseResolved export error = %v", err)
	}
	assertRequestJSON(t, export, `{"request_id":"i_01234567-89ab-7cde-8f01-23456789abcd","command":"export","run_id":"r_019f596a-cf80-7c67-b265-f37053d51ccf","output_path":"exports/review.zip","redacted":true,"output_format":"human"}`)
}
func TestParseReviewAndPromptRequests(t *testing.T) {
	defaults := mustParse(t, []string{"review", "--dirty"})
	defaultRequest, ok := defaults.Review()
	if !ok || !reflect.DeepEqual(defaultRequest.Roles(), []string{"logic", "security", "maintainability", "product", "documentation", "testing"}) {
		t.Fatalf("default review roles = %#v, %t; want fixed role order", defaultRequest, ok)
	}
	assertRequestJSON(t, defaults, `{"request_id":"i_01234567-89ab-7cde-8f01-23456789abcd","command":"review","target":{"kind":"dirty","value":"dirty"},"objective":null,"roles":["logic","security","maintainability","product","documentation","testing"],"role_selection":"project_default","session_id":null,"output_format":"human"}`)
	review := mustParse(t, []string{"review", "--patch", "changes.patch", "--objective", "Review changes.", "--roles", "testing,logic", "--session", testSessionID, "--output", "json"})
	request, ok := review.Review()
	if !ok {
		t.Fatal("review invocation has no review request")
	}
	if got, want := request.Roles(), []string{"logic", "testing"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("review roles = %v, want %v", got, want)
	}
	roles := request.Roles()
	roles[0] = "mutated"
	if got := request.Roles()[0]; got != "logic" {
		t.Fatalf("review roles mutated through accessor = %q", got)
	}
	if got, present := request.SessionID(); !present || got != testSessionID {
		t.Fatalf("review session = %q, %t; want %q, true", got, present, testSessionID)
	}
	assertRequestJSON(t, review, `{"request_id":"i_01234567-89ab-7cde-8f01-23456789abcd","command":"review","target":{"kind":"patch","value":"changes.patch"},"objective":"Review changes.","roles":["logic","testing"],"role_selection":"explicit","session_id":"s_019f596a-cf80-7c67-b265-f37053d51ccf","output_format":"json"}`)

	prompt := mustParse(t, []string{"prompt", "--run", testRunID, "--attempt", testAttemptID, "--include-guarded-bytes"})
	promptRequest, ok := prompt.Prompt()
	if !ok || !promptRequest.IncludeGuardedBytes() || promptRequest.RunID() != testRunID || promptRequest.AttemptID() != testAttemptID {
		t.Fatalf("prompt request = %#v, %t; want guarded canonical request", promptRequest, ok)
	}
	assertRequestJSON(t, prompt, `{"request_id":"i_01234567-89ab-7cde-8f01-23456789abcd","command":"prompt","run_id":"r_019f596a-cf80-7c67-b265-f37053d51ccf","attempt_id":"a_019f596a-cf80-7c67-b265-f37053d51ccf","include_guarded_bytes":true,"output_format":"human"}`)
}

func TestParseReviewProjectTargetModes(t *testing.T) {
	for _, test := range []struct {
		arguments   []string
		kind, value string
	}{
		{[]string{"review", "--workspace"}, "workspace", "workspace"},
		{[]string{"review", "--stage"}, "stage", "stage"},
		{[]string{"review", "--dirty"}, "dirty", "dirty"},
		{[]string{"review", "--diff", "main"}, "diff", "main"},
		{[]string{"review", "--diff", "main..topic"}, "diff", "main..topic"},
		{[]string{"review", "--diff", "main...topic"}, "diff", "main...topic"},
	} {
		invocation, err := Parse(test.arguments, testProjectRoot, testRequestID)
		if err != nil {
			t.Fatalf("Parse(%v): %v", test.arguments, err)
		}
		request, ok := invocation.Review()
		if !ok || request.Target().Kind() != test.kind || request.Target().Value() != test.value {
			t.Fatalf("Parse(%v) target = %#v", test.arguments, request.Target())
		}
	}
	if _, err := Parse([]string{"review", "--diff", "git"}, testProjectRoot, testRequestID); err == nil {
		t.Fatal("deprecated --diff git was accepted")
	}
	if _, err := Parse([]string{"review", "--workspace", "--dirty"}, testProjectRoot, testRequestID); err == nil {
		t.Fatal("multiple project target modes were accepted")
	}
}

func TestParseResolvedReviewStdin(t *testing.T) {
	arguments := []string{"review", "--stdin", "--roles", "security,logic"}
	invocation, err := ParseResolved(context.Background(), arguments, testProjectRoot, testRequestID, parserTestResolver{target: "stdin-capture-v1-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"})
	if err != nil {
		t.Fatalf("ParseResolved review error = %v", err)
	}
	assertRequestJSON(t, invocation, `{"request_id":"i_01234567-89ab-7cde-8f01-23456789abcd","command":"review","target":{"kind":"stdin","value":"stdin-capture-v1-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"objective":null,"roles":["logic","security"],"role_selection":"explicit","session_id":null,"output_format":"human"}`)
	if arguments[2] != "--roles" {
		t.Fatal("ParseResolved mutated review arguments")
	}
}
func TestParseStdinOpaqueTokenBoundary(t *testing.T) {
	token := "stdin-capture-v1-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if _, err := Parse([]string{"review", "--stdin", token}, testProjectRoot, testRequestID); err != nil {
		t.Fatalf("Parse opaque token: %v", err)
	}
	if _, err := Parse([]string{"review", "--stdin", "first line\nsecond line"}, testProjectRoot, testRequestID); !errors.Is(err, ErrUsage) {
		t.Fatalf("Parse raw multiline stdin error = %v, want usage error", err)
	}
	if _, err := ParseResolved(context.Background(), []string{"review", "--stdin"}, testProjectRoot, testRequestID, parserTestResolver{target: "first line\nsecond line"}); !errors.Is(err, ErrUsage) {
		t.Fatalf("ParseResolved raw multiline capture error = %v, want usage error", err)
	}
}
func TestParseDocumentedG008CommandGoldens(t *testing.T) {
	resolver := parserTestResolver{
		runID:     testRunID,
		attemptID: testAttemptID,
		target:    "stdin-capture-v1-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}
	const planHash = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	for _, test := range []struct {
		name      string
		arguments []string
		want      string
	}{
		{
			name:      "followup valueless stdin with nonnumeric finding ID",
			arguments: []string{"followup", "--run", "latest", "--finding", "F_SOURCE-1", "--stdin", "--objective", "Verify only whether the original issue is resolved."},
			want:      `{"request_id":"i_01234567-89ab-7cde-8f01-23456789abcd","command":"followup","source_run_id":"r_019f596a-cf80-7c67-b265-f37053d51ccf","finding_id":"F_SOURCE-1","target":{"kind":"stdin","value":"stdin-capture-v1-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"objective":"Verify only whether the original issue is resolved.","role":null,"output_format":"human"}`,
		},
		{
			name:      "lineage followup",
			arguments: []string{"followup", "--run", "latest", "--finding", "F001", "--dirty"},
			want:      `{"request_id":"i_01234567-89ab-7cde-8f01-23456789abcd","command":"followup","source_run_id":"r_019f596a-cf80-7c67-b265-f37053d51ccf","finding_id":"F001","target":{"kind":"dirty","value":"dirty"},"objective":null,"role":null,"output_format":"human"}`,
		},
		{
			name:      "followup role",
			arguments: []string{"followup", "--run", testRunID, "--finding", "F003", "--dirty", "--role", "logic"},
			want:      `{"request_id":"i_01234567-89ab-7cde-8f01-23456789abcd","command":"followup","source_run_id":"r_019f596a-cf80-7c67-b265-f37053d51ccf","finding_id":"F003","target":{"kind":"dirty","value":"dirty"},"objective":null,"role":"logic","output_format":"human"}`,
		},
		{
			name:      "delta since run",
			arguments: []string{"delta", "--since-run", "latest", "--dirty", "--roles", "logic,security"},
			want:      `{"request_id":"i_01234567-89ab-7cde-8f01-23456789abcd","command":"delta","source_run_id":"r_019f596a-cf80-7c67-b265-f37053d51ccf","target":{"kind":"dirty","value":"dirty"},"roles":["logic","security"],"output_format":"human"}`,
		},
		{
			name:      "lineage delta",
			arguments: []string{"delta", "--since-run", "latest", "--dirty", "--roles", "logic,security"},
			want:      `{"request_id":"i_01234567-89ab-7cde-8f01-23456789abcd","command":"delta","source_run_id":"r_019f596a-cf80-7c67-b265-f37053d51ccf","target":{"kind":"dirty","value":"dirty"},"roles":["logic","security"],"output_format":"human"}`,
		},
		{
			name:      "rerun role provider selector",
			arguments: []string{"rerun", "--run", "latest", "--role", "documentation", "--provider", "kimi-main"},
			want:      `{"request_id":"i_01234567-89ab-7cde-8f01-23456789abcd","command":"rerun","source_run_id":"r_019f596a-cf80-7c67-b265-f37053d51ccf","source_attempt_id":"a_019f596a-cf80-7c67-b265-f37053d51ccf","replay_mode":"exact","output_format":"human"}`,
		},
		{
			name:      "rerun exact attempt",
			arguments: []string{"rerun", "--run", "latest", "--attempt", testAttemptID, "--replay", "exact"},
			want:      `{"request_id":"i_01234567-89ab-7cde-8f01-23456789abcd","command":"rerun","source_run_id":"r_019f596a-cf80-7c67-b265-f37053d51ccf","source_attempt_id":"a_019f596a-cf80-7c67-b265-f37053d51ccf","replay_mode":"exact","output_format":"human"}`,
		},
		{
			name:      "clean plan",
			arguments: []string{"clean", "--mode", "plan"},
			want:      `{"request_id":"i_01234567-89ab-7cde-8f01-23456789abcd","command":"clean","mode":"plan","expected_plan_sha256":null,"output_format":"human"}`,
		},
		{
			name:      "clean hash bound apply",
			arguments: []string{"clean", "--mode", "apply", "--expected-plan-sha256", planHash},
			want:      `{"request_id":"i_01234567-89ab-7cde-8f01-23456789abcd","command":"clean","mode":"apply","expected_plan_sha256":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","output_format":"human"}`,
		},
		{
			name:      "export output path",
			arguments: []string{"export", "--run", "latest", "--output-path", "exports/kar-review.zip", "--output", "human"},
			want:      `{"request_id":"i_01234567-89ab-7cde-8f01-23456789abcd","command":"export","run_id":"r_019f596a-cf80-7c67-b265-f37053d51ccf","output_path":"exports/kar-review.zip","redacted":true,"output_format":"human"}`,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			invocation, err := ParseResolved(context.Background(), test.arguments, testProjectRoot, testRequestID, resolver)
			if err != nil {
				t.Fatalf("ParseResolved(%v) error = %v", test.arguments, err)
			}
			assertRequestJSON(t, invocation, test.want)
		})
	}
}

func TestParseResolvedDistinguishesSelectorUsageFromOperationalFailures(t *testing.T) {
	for _, message := range []string{"zero matches", "ambiguous matches"} {
		selectorErr := fmt.Errorf("%w: %s", ErrSelectorUnavailable, message)
		resolver := parserTestResolver{err: selectorErr}
		if _, err := ParseResolved(context.Background(), []string{"export", "--run", "latest", "--output-path", "exports/review.zip"}, testProjectRoot, testRequestID, resolver); !errors.Is(err, ErrUsage) {
			t.Errorf("ParseResolved selector error = %v, want usage error", err)
		}
	}
	operational := errors.New("resolver failed")
	if _, err := ParseResolved(context.Background(), []string{"export", "--run", "latest", "--output-path", "exports/review.zip"}, testProjectRoot, testRequestID, parserTestResolver{err: operational}); !errors.Is(err, operational) || errors.Is(err, ErrUsage) {
		t.Errorf("ParseResolved operational error = %v, want preserved non-usage cause", err)
	}
	if _, err := ParseResolved(context.Background(), []string{"rerun", "--run", testRunID, "--role", "logic", "--provider", "kimi"}, testProjectRoot, testRequestID, parserTestResolver{}); !errors.Is(err, ErrUsage) {
		t.Errorf("ParseResolved zero attempt selector error = %v, want usage error", err)
	}
}

func TestParseRejectsMalformedG008Requests(t *testing.T) {
	planHash := "sha256:" + strings.Repeat("b", 64)
	for _, arguments := range [][]string{
		{"followup", "--run", testRunID, "--finding", "F001", "--dirty", "--patch", "changes.patch"},
		{"followup", "--run", testRunID, "--finding", "lowercase", "--dirty"},
		{"followup", "--run", testRunID, "--finding", "F001", "--dirty", "--role", "Logic"},
		{"delta", "--run", testRunID, "--dirty", "--roles", "logic"},
		{"clean", "--older-than", "30d"},
		{"delta", "--since-run", testRunID, "--stdin", "capture", "--roles", "logic,logic"},
		{"delta", "--since-run", testRunID, "--stdin", "capture", "--roles", "logic,security,testing,docs,ops,release,extra"},
		{"rerun", "--run", testRunID, "--attempt", "a_019f596a-cf80-6c67-b265-f37053d51ccf"},
		{"rerun", "--run", testRunID, "--attempt", testAttemptID, "--replay", "wire"},
		{"clean", "--mode", "apply"},
		{"clean", "--expected-plan-sha256", planHash},
		{"clean", "--mode", "plan", "--expected-plan-sha256", planHash},
		{"clean", "--mode", "apply", "--expected-plan-sha256", "sha256:" + strings.Repeat("B", 64)},
		{"export", "--run", testRunID, "--output-path", "../review.zip"},
		{"export", "--run", testRunID, "--output-path", "review.zip", "--redacted", "false"},
	} {
		if _, err := Parse(arguments, testProjectRoot, testRequestID); !errors.Is(err, ErrUsage) {
			t.Errorf("Parse(%v) error = %v, want usage error", arguments, err)
		}
	}
}

func TestParseProvidersForms(t *testing.T) {
	defaults := mustParse(t, []string{"providers"})
	request, ok := defaults.Providers()
	if !ok {
		t.Fatal("providers invocation has no typed request")
	}
	if got, want := request.ProjectRoot(), testProjectRoot; got != want {
		t.Fatalf("default providers project root = %q, want %q", got, want)
	}
	if request.IncludeUnverified() {
		t.Fatal("default providers include unverified must be false")
	}
	if got, want := defaults.OutputFormat(), OutputFormatHuman; got != want {
		t.Fatalf("default providers output = %q, want %q", got, want)
	}
	assertRequestJSON(t, defaults, `{"request_id":"i_01234567-89ab-7cde-8f01-23456789abcd","command":"providers","project_root":"/work/project","include_unverified":false,"output_format":"human"}`)

	invocation := mustParse(t, []string{
		"providers", "--project-root", "/work/providers", "--include-unverified", "--output", "json",
	})
	request, ok = invocation.Providers()
	if !ok {
		t.Fatal("explicit providers invocation has no typed request")
	}
	if got, want := request.ProjectRoot(), "/work/providers"; got != want {
		t.Fatalf("providers project root = %q, want %q", got, want)
	}
	if !request.IncludeUnverified() {
		t.Fatal("explicit providers include unverified must be true")
	}
	assertRequestJSON(t, invocation, `{"request_id":"i_01234567-89ab-7cde-8f01-23456789abcd","command":"providers","project_root":"/work/providers","include_unverified":true,"output_format":"json"}`)

	firstJSON, available := invocation.RequestJSON()
	if !available {
		t.Fatal("providers request JSON unavailable")
	}
	firstJSON[0] = 'X'
	secondJSON, available := invocation.RequestJSON()
	if !available || secondJSON[0] != '{' {
		t.Fatalf("providers request JSON mutated through getter = %q, %t", secondJSON, available)
	}
}

func TestParseRejectsJSONOptionsOutsideFrozenRequestVariants(t *testing.T) {
	for _, arguments := range [][]string{
		{"config", "--project-config", ".kar.yaml", "--ref", strings.Repeat("a", 40), "--output", "json"},
		{"schema", "export", testSchemaID, "contract.json", "--project-root", "/work/export", "--output", "json"},
	} {
		if _, err := Parse(arguments, testProjectRoot, testRequestID); err == nil {
			t.Errorf("Parse(%v) succeeded for an unrepresentable JSON request", arguments)
		}
	}
}

func TestParseRecognizesExactExecutableCommandSurface(t *testing.T) {
	commands := []app.CommandName{
		app.CommandInit,
		app.CommandDoctor,
		app.CommandReview,
		app.CommandFollowup,
		app.CommandDelta,
		app.CommandRerun,
		app.CommandStatus,
		app.CommandReport,
		app.CommandFindings,
		app.CommandExcerpt,
		app.CommandProviders,
		app.CommandConfig,
		app.CommandPrompt,
		app.CommandSchema,
		app.CommandClean,
		app.CommandExport,
		app.CommandHelp,
	}
	foundation := map[app.CommandName][]string{
		app.CommandInit:      {"init"},
		app.CommandDoctor:    {"doctor"},
		app.CommandReview:    {"review", "--dirty"},
		app.CommandFollowup:  {"followup", "--run", testRunID, "--finding", "F001", "--dirty"},
		app.CommandDelta:     {"delta", "--since-run", testRunID, "--dirty", "--roles", "logic"},
		app.CommandRerun:     {"rerun", "--run", testRunID, "--attempt", testAttemptID},
		app.CommandPrompt:    {"prompt", "--run", testRunID, "--attempt", testAttemptID},
		app.CommandClean:     {"clean"},
		app.CommandExport:    {"export", "--run", testRunID, "--output-path", "exports/review.zip"},
		app.CommandStatus:    {"status", "--run", testRunID},
		app.CommandReport:    {"report", "--run", testRunID, "--output-path", "reports/run.json"},
		app.CommandFindings:  {"findings", "--run", testRunID, "--severity", "low"},
		app.CommandExcerpt:   {"excerpt", "--run", testRunID, "--finding", "F001", "--current-target-sha256", testCurrentTargetSHA256},
		app.CommandProviders: {"providers"},
		app.CommandConfig:    {"config"},
		app.CommandSchema:    {"schema", "list"},
		app.CommandHelp:      {"help"},
	}
	for _, command := range commands {
		arguments, executable := foundation[command]
		if !executable {
			t.Fatalf("command %q has no executable request surface", command)
		}
		invocation := mustParse(t, arguments)
		if got := invocation.Command(); got != command {
			t.Errorf("Parse(%v) command = %q, want %q", arguments, got, command)
		}
		if invocation.FutureMilestone() || invocation.Availability() != AvailabilityFoundation {
			t.Errorf("Parse(%v) availability = %q, future = %t; want executable foundation command", arguments, invocation.Availability(), invocation.FutureMilestone())
		}
		if _, available := invocation.RequestJSON(); !available && command != app.CommandSchema {
			t.Errorf("executable command %q supplied no request JSON object", command)
		}
	}
}

func TestParseRejectsMalformedInput(t *testing.T) {
	tests := []struct {
		name      string
		arguments []string
		root      string
		requestID string
	}{
		{name: "unknown command", arguments: []string{"unknown"}},
		{name: "review extra positional", arguments: []string{"review", "extra"}},
		{name: "review duplicate target", arguments: []string{"review", "--dirty", "--patch", "changes.patch"}},
		{name: "review duplicate roles", arguments: []string{"review", "--dirty", "--roles", "logic,logic"}},
		{name: "review invalid session", arguments: []string{"review", "--dirty", "--session", "s_invalid"}},
		{name: "prompt missing run", arguments: []string{"prompt", "--attempt", testAttemptID}},
		{name: "prompt missing attempt", arguments: []string{"prompt", "--run", testRunID}},
		{name: "prompt boolean value", arguments: []string{"prompt", "--run", testRunID, "--attempt", testAttemptID, "--include-guarded-bytes", "true"}},
		{name: "prompt duplicate guarded bytes", arguments: []string{"prompt", "--run", testRunID, "--attempt", testAttemptID, "--include-guarded-bytes", "--include-guarded-bytes"}},
		{name: "providers positional", arguments: []string{"providers", "extra"}},
		{name: "providers duplicate project root", arguments: []string{"providers", "--project-root", testProjectRoot, "--project-root", testProjectRoot}},
		{name: "providers duplicate include unverified", arguments: []string{"providers", "--include-unverified", "--include-unverified"}},
		{name: "providers boolean value", arguments: []string{"providers", "--include-unverified", "true"}},
		{name: "providers unknown flag", arguments: []string{"providers", "--unknown"}},
		{name: "providers missing output", arguments: []string{"providers", "--output"}},
		{name: "providers invalid output", arguments: []string{"providers", "--output", "yaml"}},
		{name: "status missing run", arguments: []string{"status"}},
		{name: "status missing run value", arguments: []string{"status", "--run"}},
		{name: "status duplicate run", arguments: []string{"status", "--run", testRunID, "--run", testRunID}},
		{name: "status extra positional", arguments: []string{"status", "--run", testRunID, "extra"}},
		{name: "status extra option", arguments: []string{"status", "--run", testRunID, "--project-root", testProjectRoot}},
		{name: "status noncanonical run", arguments: []string{"status", "--run", "r_019f596a-cf80-6c67-b265-f37053d51ccf"}},
		{name: "status zero-form run", arguments: []string{"status", "--run", "r_00000000-0000-7000-8000-000000000000"}},
		{name: "report missing output path", arguments: []string{"report", "--run", testRunID}},
		{name: "report traversal output path", arguments: []string{"report", "--run", testRunID, "--output-path", "../report.json"}},
		{name: "report backslash output path", arguments: []string{"report", "--run", testRunID, "--output-path", "reports\\report.json"}},
		{name: "findings missing severity", arguments: []string{"findings", "--run", testRunID}},
		{name: "findings unsupported severity", arguments: []string{"findings", "--run", testRunID, "--severity", "info"}},
		{name: "excerpt missing finding", arguments: []string{"excerpt", "--run", testRunID, "--current-target-sha256", testCurrentTargetSHA256}},
		{name: "excerpt invalid finding", arguments: []string{"excerpt", "--run", testRunID, "--finding", "f_SOURCE-1", "--current-target-sha256", testCurrentTargetSHA256}},
		{name: "excerpt invalid digest", arguments: []string{"excerpt", "--run", testRunID, "--finding", "F003", "--current-target-sha256", "sha256:" + strings.Repeat("A", 64)}},
		{name: "excerpt unsupported output", arguments: []string{"excerpt", "--run", testRunID, "--finding", "F003", "--current-target-sha256", testCurrentTargetSHA256, "--output", "yaml"}},
		{name: "duplicate flag", arguments: []string{"doctor", "--output", "json", "--output", "human"}},
		{name: "unknown flag", arguments: []string{"doctor", "--verbose", "true"}},
		{name: "single dash unknown flag", arguments: []string{"doctor", "-v"}},
		{name: "missing flag value", arguments: []string{"doctor", "--output"}},
		{name: "extra positional", arguments: []string{"doctor", "extra"}},
		{name: "init positional", arguments: []string{"init", "extra"}},
		{name: "repeated intended provider", arguments: []string{"init", "--providers", "kimi,kimi"}},
		{name: "empty intended provider", arguments: []string{"init", "--providers", "kimi,"}},
		{name: "unsupported intended provider codex", arguments: []string{"init", "--providers", "codex"}},
		{name: "unsupported intended provider claude", arguments: []string{"init", "--providers", "claude"}},
		{name: "unsupported intended provider unknown", arguments: []string{"init", "--providers", "unknown"}},
		{name: "removed optional providers flag", arguments: []string{"init", "--optional-providers", "codex"}},
		{name: "unsafe context", arguments: []string{"init", "--context", "../outside"}},
		{name: "unsupported help topic", arguments: []string{"help", "unknown"}},
		{name: "invalid output", arguments: []string{"help", "--output", "yaml"}},
		{name: "unsafe root", arguments: []string{"doctor", "--project-root", "/work/../other"}},
		{name: "relative root", arguments: []string{"doctor", "--project-root", "work/project"}},
		{name: "newline root", arguments: []string{"doctor", "--project-root", "/work\nproject"}},
		{name: "unsafe ref", arguments: []string{"config", "--ref", " refs/heads/main"}},
		{name: "option looking ref", arguments: []string{"config", "--ref", "-unsafe"}},
		{name: "newline ref", arguments: []string{"config", "--ref", "refs/heads/main\n"}},
		{name: "unsafe config path", arguments: []string{"config", "--project-config", "config/../project.yaml"}},
		{name: "mutable project ref", arguments: []string{"config", "--ref", "refs/heads/main", "--project-config", ".kar.yaml"}},
		{name: "project config without expected commit", arguments: []string{"config", "--project-config", ".kar.yaml"}},
		{name: "ref without project config", arguments: []string{"config", "--ref", testCommitID}},
		{name: "unsupported config mode", arguments: []string{"config", "--mode", "raw"}},
		{name: "schema missing operation", arguments: []string{"schema"}},
		{name: "schema list extra", arguments: []string{"schema", "list", "extra"}},
		{name: "schema show missing ID", arguments: []string{"schema", "show"}},
		{name: "schema invalid ID", arguments: []string{"schema", "show", "urn:kar:schema:broken"}},
		{name: "schema export missing path", arguments: []string{"schema", "export", testSchemaID}},
		{name: "schema unsafe export", arguments: []string{"schema", "export", testSchemaID, "../out.json"}},
		{name: "invalid default root", arguments: nil, root: "relative"},
		{name: "invalid request ID", arguments: nil, requestID: "i_not-a-uuid"},
		{name: "combined help", arguments: []string{"--help", "extra"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := test.root
			if root == "" {
				root = testProjectRoot
			}
			requestID := test.requestID
			if requestID == "" {
				requestID = testRequestID
			}
			if _, err := Parse(test.arguments, root, requestID); !errors.Is(err, ErrUsage) {
				t.Fatalf("Parse(%v) error = %v, want usage error", test.arguments, err)
			}
		})
	}
}

func TestParseAcceptsSafeRelativePathsAndLocalConfigMode(t *testing.T) {
	init := mustParse(t, []string{"init", "--context", "src/review"})
	initRequest, ok := init.Init()
	if !ok {
		t.Fatal("init has no typed request")
	}
	if got, present := initRequest.ContextPath(); !present || got != "src/review" {
		t.Fatalf("safe init context = %q, %t; want src/review, true", got, present)
	}

	config := mustParse(t, []string{"config", "--project-root", "/work/config", "--mode", "provenance"})
	configRequest, ok := config.Config()
	if !ok {
		t.Fatal("config has no typed request")
	}
	if configRequest.ProjectRoot() != "/work/config" || configRequest.Mode() != ConfigModeProvenance {
		t.Fatalf("local config request = %#v", configRequest)
	}
}

func TestParseReturnsDefensiveCopies(t *testing.T) {
	invocation := mustParse(t, []string{"init", "--providers", "kimi,zcode"})
	first, ok := invocation.Init()
	if !ok {
		t.Fatal("init has no typed request")
	}
	_, intended := first.Selection()
	intended[0] = "changed"
	second, ok := invocation.Init()
	if !ok {
		t.Fatal("init request disappeared")
	}
	_, got := second.Selection()
	if want := []string{"kimi", "zcode"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("intended providers mutated through getter = %v, want %v", got, want)
	}

	firstJSON, available := invocation.RequestJSON()
	if !available {
		t.Fatal("init request JSON unavailable")
	}
	firstJSON[0] = 'X'
	secondJSON, available := invocation.RequestJSON()
	if !available || secondJSON[0] != '{' {
		t.Fatalf("request JSON mutated through getter = %q, %t", secondJSON, available)
	}
}

func TestParseCLIExamplesAndCommandSurfaceGoldens(t *testing.T) {
	resolver := parserTestResolver{
		runID:     testRunID,
		attemptID: testAttemptID,
		target:    "stdin-capture-v1-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}
	tests := []struct {
		name      string
		arguments []string
		resolved  bool
		command   app.CommandName
		wantError bool
	}{
		{name: "init success", arguments: []string{"init"}, command: app.CommandInit},
		{name: "init error", arguments: []string{"init", "--unknown"}, wantError: true},
		{name: "doctor success", arguments: []string{"doctor"}, command: app.CommandDoctor},
		{name: "doctor error", arguments: []string{"doctor", "--json"}, wantError: true},
		{name: "review success", arguments: []string{"review", "--dirty"}, command: app.CommandReview},
		{name: "review error", arguments: []string{"review"}, wantError: true},
		{name: "readme followup", arguments: []string{"followup", "--run", "latest", "--finding", "F001", "--dirty", "--objective", "Verify only whether the original issue is resolved."}, resolved: true, command: app.CommandFollowup},
		{name: "followup error", arguments: []string{"followup", "--run", testRunID, "--finding", "F001"}, wantError: true},
		{name: "delta success", arguments: []string{"delta", "--since-run", "latest", "--dirty", "--roles", "logic"}, resolved: true, command: app.CommandDelta},
		{name: "delta error", arguments: []string{"delta", "--since-run", testRunID, "--dirty"}, wantError: true},
		{name: "rerun success", arguments: []string{"rerun", "--run", "latest", "--role", "documentation", "--provider", "kimi-main"}, resolved: true, command: app.CommandRerun},
		{name: "rerun error", arguments: []string{"rerun", "--run", testRunID}, wantError: true},
		{name: "status json example", arguments: []string{"status", "--run", testRunID, "--output", "json"}, command: app.CommandStatus},
		{name: "status error", arguments: []string{"status", "--json"}, wantError: true},
		{name: "readme report", arguments: []string{"report", "--run", testRunID, "--output-path", "reports/review.md", "--output", "json"}, command: app.CommandReport},
		{name: "report error", arguments: []string{"report", "--run", testRunID}, wantError: true},
		{name: "readme findings", arguments: []string{"findings", "--run", testRunID, "--severity", "high", "--output", "json"}, command: app.CommandFindings},
		{name: "findings critical example", arguments: []string{"findings", "--run", testRunID, "--severity", "critical"}, command: app.CommandFindings},
		{name: "findings error", arguments: []string{"findings", "--run", testRunID}, wantError: true},
		{name: "excerpt json example", arguments: []string{"excerpt", "--run", testRunID, "--finding", "F001", "--current-target-sha256", testCurrentTargetSHA256, "--output", "json"}, command: app.CommandExcerpt},
		{name: "excerpt error", arguments: []string{"excerpt", "--run", testRunID, "--finding", "F001"}, wantError: true},
		{name: "providers success", arguments: []string{"providers"}, command: app.CommandProviders},
		{name: "providers error", arguments: []string{"providers", "--unknown"}, wantError: true},
		{name: "config success", arguments: []string{"config"}, command: app.CommandConfig},
		{name: "config error", arguments: []string{"config", "--mode", "raw"}, wantError: true},
		{name: "prompt success", arguments: []string{"prompt", "--run", testRunID, "--attempt", testAttemptID}, command: app.CommandPrompt},
		{name: "prompt error", arguments: []string{"prompt", "extra"}, wantError: true},
		{name: "schema success", arguments: []string{"schema", "list"}, command: app.CommandSchema},
		{name: "schema error", arguments: []string{"schema"}, wantError: true},
		{name: "clean success", arguments: []string{"clean", "--mode", "plan"}, command: app.CommandClean},
		{name: "clean error", arguments: []string{"clean", "--mode", "apply"}, wantError: true},
		{name: "reporting export", arguments: []string{"export", "--run", "latest", "--output-path", "exports/kar-review.zip", "--output", "json"}, resolved: true, command: app.CommandExport},
		{name: "export error", arguments: []string{"export", "--run", testRunID, "--redacted"}, wantError: true},
		{name: "help success", arguments: []string{"help"}, command: app.CommandHelp},
		{name: "help error", arguments: []string{"help", "unknown"}, wantError: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var (
				invocation Invocation
				err        error
			)
			if test.resolved {
				invocation, err = ParseResolved(context.Background(), test.arguments, testProjectRoot, testRequestID, resolver)
			} else {
				invocation, err = Parse(test.arguments, testProjectRoot, testRequestID)
			}
			if test.wantError {
				if !errors.Is(err, ErrUsage) {
					t.Fatalf("Parse(%v) error = %v, want usage error", test.arguments, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Parse(%v) error = %v", test.arguments, err)
			}
			if got := invocation.Command(); got != test.command {
				t.Fatalf("Parse(%v) command = %q, want %q", test.arguments, got, test.command)
			}
		})
	}
}
func TestParseReviewRejectsUnsupportedCIFlag(t *testing.T) {
	for _, arguments := range [][]string{
		{"review", "--dirty", "--ci"},
		{"review", "--ci", "--dirty"},
	} {
		_, err := Parse(arguments, testProjectRoot, testRequestID)
		if !errors.Is(err, ErrUsage) {
			t.Fatalf("Parse(%v) error = %v, want usage error", arguments, err)
		}
	}
}
func mustParse(t *testing.T, arguments []string) Invocation {
	t.Helper()
	invocation, err := Parse(arguments, testProjectRoot, testRequestID)
	if err != nil {
		t.Fatalf("Parse(%v): %v", arguments, err)
	}
	return invocation
}

func assertRequestJSON(t *testing.T, invocation Invocation, want string) {
	t.Helper()
	got, available := invocation.RequestJSON()
	if !available {
		t.Fatal("request JSON is unavailable")
	}
	if string(got) != want {
		t.Fatalf("request JSON = %s, want %s", got, want)
	}
}
