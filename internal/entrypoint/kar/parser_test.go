package kar

import (
	"errors"
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
	if got, want := request.IntendedProviderIDs(), []string{"kimi", "zcode", "agy"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("default intended providers = %v, want %v", got, want)
	}
	if request.Overwrite() {
		t.Fatal("init overwrite must remain false")
	}
	assertRequestJSON(t, defaults, `{"request_id":"i_01234567-89ab-7cde-8f01-23456789abcd","command":"init","project_root":"/work/project","intended_provider_ids":["kimi","zcode","agy"],"overwrite":false,"output_format":"human"}`)

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
	if got, want := request.IntendedProviderIDs(), []string{"zcode", "kimi"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("init intended providers = %v, want %v", got, want)
	}
	assertRequestJSON(t, invocation, `{"request_id":"i_01234567-89ab-7cde-8f01-23456789abcd","command":"init","project_root":"/work/other","intended_provider_ids":["zcode","kimi"],"overwrite":false,"output_format":"human"}`)
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
	if got := configRequest.Reference(); got != "" {
		t.Fatalf("default config reference = %q, want empty", got)
	}
	if got, present := configRequest.ProjectConfigPath(); present || got != "" {
		t.Fatalf("default config path = %q, %t; want disabled", got, present)
	}
	if got, want := configRequest.Mode(), ConfigModeEffective; got != want {
		t.Fatalf("default config mode = %q, want %q", got, want)
	}
	assertRequestJSON(t, defaults, `{"request_id":"i_01234567-89ab-7cde-8f01-23456789abcd","command":"config","project_root":"/work/project","mode":"effective","output_format":"human"}`)

	invocation := mustParse(t, []string{"config", "--project-config", "none", "--mode", "provenance", "--output", "json"})
	configRequest, ok = invocation.Config()
	if !ok {
		t.Fatal("explicit config invocation has no config request")
	}
	if got := configRequest.Reference(); got != "" {
		t.Fatalf("disabled project config reference = %q, want empty", got)
	}
	if _, present := configRequest.ProjectConfigPath(); present {
		t.Fatal("config project path remains enabled after --project-config none")
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
		t.Fatal("schema list supplied a fabricated schema request JSON object")
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

	excerpt := mustParse(t, []string{"excerpt", "--run", testRunID, "--finding", "F003", "--current-target-sha256", testCurrentTargetSHA256})
	excerptRequest, ok := excerpt.Excerpt()
	if !ok ||
		excerptRequest.RunID() != testRunID ||
		excerptRequest.FindingID() != "F003" ||
		excerptRequest.CurrentTargetSHA256() != testCurrentTargetSHA256 {
		t.Fatalf("excerpt request = %#v, %t; want immutable excerpt fields", excerptRequest, ok)
	}
	assertRequestJSON(t, excerpt, `{"request_id":"i_01234567-89ab-7cde-8f01-23456789abcd","command":"excerpt","run_id":"r_019f596a-cf80-7c67-b265-f37053d51ccf","finding_id":"F003","current_target_sha256":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","output_format":"human"}`)
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
		{"init", "--name", "named", "--output", "json"},
		{"init", "--context", "src/review", "--output", "json"},
		{"config", "--project-config", ".kar.yaml", "--ref", strings.Repeat("a", 40), "--output", "json"},
		{"schema", "export", testSchemaID, "contract.json", "--project-root", "/work/export", "--output", "json"},
	} {
		if _, err := Parse(arguments, testProjectRoot, testRequestID); err == nil {
			t.Errorf("Parse(%v) succeeded for an unrepresentable JSON request", arguments)
		}
	}
}

func TestParseRecognizesExactCommandSurfaceAndClassifiesFutureCommands(t *testing.T) {
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
			arguments = []string{string(command)}
		}
		invocation := mustParse(t, arguments)
		if got := invocation.Command(); got != command {
			t.Errorf("Parse(%v) command = %q, want %q", arguments, got, command)
		}
		if got := invocation.FutureMilestone(); got == executable {
			t.Errorf("Parse(%v) future = %t, want %t", arguments, got, !executable)
		}
		if !executable {
			if got, want := invocation.Availability(), AvailabilityFutureMilestone; got != want {
				t.Errorf("Parse(%v) availability = %q, want %q", arguments, got, want)
			}
			if _, available := invocation.RequestJSON(); available {
				t.Errorf("future command %q supplied a request JSON object", command)
			}
		}
	}
}
func TestParseKeepsOtherUnfinishedCommandsUnavailable(t *testing.T) {
	futureCommands := []app.CommandName{
		app.CommandReview,
		app.CommandFollowup,
		app.CommandDelta,
		app.CommandRerun,
		app.CommandPrompt,
		app.CommandClean,
		app.CommandExport,
	}
	for _, command := range futureCommands {
		t.Run(string(command), func(t *testing.T) {
			invocation := mustParse(t, []string{string(command)})
			if !invocation.FutureMilestone() || invocation.Availability() != AvailabilityFutureMilestone {
				t.Fatalf("%q availability = %q, future = %t; want future milestone", command, invocation.Availability(), invocation.FutureMilestone())
			}
			if _, available := invocation.RequestJSON(); available {
				t.Fatalf("future command %q supplied a request JSON object", command)
			}
			if _, err := Parse([]string{string(command), "extra"}, testProjectRoot, testRequestID); !errors.Is(err, ErrUsage) {
				t.Fatalf("Parse(%q with arguments) error = %v, want usage error", command, err)
			}
		})
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
		{name: "future command arguments", arguments: []string{"review", "extra"}},
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
		{name: "excerpt invalid finding", arguments: []string{"excerpt", "--run", testRunID, "--finding", "F03", "--current-target-sha256", testCurrentTargetSHA256}},
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
		{name: "invalid project name", arguments: []string{"init", "--name", "Project"}},
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

func TestParseAcceptsSafeRelativePathsAndReference(t *testing.T) {
	init := mustParse(t, []string{"init", "--context", "src/review"})
	initRequest, ok := init.Init()
	if !ok {
		t.Fatal("init has no typed request")
	}
	if got, present := initRequest.ContextPath(); !present || got != "src/review" {
		t.Fatalf("safe init context = %q, %t; want src/review, true", got, present)
	}

	config := mustParse(t, []string{"config", "--ref", testCommitID, "--project-config", "policy/project.yaml"})
	configRequest, ok := config.Config()
	if !ok {
		t.Fatal("config has no typed request")
	}
	if got, want := configRequest.Reference(), testCommitID; got != want {
		t.Fatalf("safe config ref = %q, want %q", got, want)
	}
	if got, present := configRequest.ProjectConfigPath(); !present || got != "policy/project.yaml" {
		t.Fatalf("safe config path = %q, %t; want policy/project.yaml, true", got, present)
	}
}

func TestParseReturnsDefensiveCopies(t *testing.T) {
	invocation := mustParse(t, []string{"init", "--providers", "kimi,zcode"})
	first, ok := invocation.Init()
	if !ok {
		t.Fatal("init has no typed request")
	}
	intended := first.IntendedProviderIDs()
	intended[0] = "changed"
	second, ok := invocation.Init()
	if !ok {
		t.Fatal("init request disappeared")
	}
	if got, want := second.IntendedProviderIDs(), []string{"kimi", "zcode"}; !reflect.DeepEqual(got, want) {
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
