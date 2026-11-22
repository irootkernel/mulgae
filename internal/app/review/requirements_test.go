package review

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/adapters/jsonschema"
	"github.com/irootkernel/mulgae/internal/app/evidence"
	"github.com/irootkernel/mulgae/internal/app/prompt"
	"github.com/irootkernel/mulgae/internal/app/validation"
	"github.com/irootkernel/mulgae/internal/builtin"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

type requirementsTestPrompts struct{ explicitRuntimePromptSource }

func (s requirementsTestPrompts) ExtractionPrompt(context.Context, InvocationJob, InvocationExtractionInput) (RuntimePrompt, error) {
	return s.material, nil
}
func requirementsRuntimeFixture(t *testing.T, responses ...[]byte) (*ProviderInvocationRuntime, InvocationJob, *recordingObservedProvider) {
	t.Helper()
	selector, _ := ports.NewLiveSourceSelector(domain.LiveSourceWorkspace, "")
	path, _ := ports.NewSafeRelativePath("source.go")
	target, _ := ports.NewLiveSourceTarget(selector, ports.GitObjectID{}, ports.GitObjectID{}, false, []ports.LiveSourceChange{{Kind: "included", After: path}})
	root, _ := ports.NewAnchoredRoot("/source")
	neutral, _ := ports.NewAnchoredRoot("/neutral")
	credential, _ := ports.NewAnchoredRoot("/credentials")
	reader := &runtimeLiveReader{coordinatorLiveReader: coordinatorLiveReader{target}, binding: ports.ProjectBindingObservation{Root: root, RootIdentity: ports.ProjectDirectoryIdentity{Device: 1, Inode: 2}}}
	execution, err := ports.NewLiveReviewExecution(context.Background(), reader, runtimeLiveHome{root: neutral}, []ports.AnchoredRoot{credential})
	if err != nil {
		t.Fatal(err)
	}
	identity, _ := evidence.NewLiveSourceIdentity(target)
	_, job, material := providerRuntimeExplicitFixture(t, nil)
	job.target, _ = identity.RunTarget()
	compiler, _ := prompt.NewCompiler(material.Prompt.TrustedTemplate(), explicitRuntimeTestIssuer{source: material.Prompt.Scope().SourceInvocationID(), execution: material.Prompt.Scope().ExecutionInvocationID()})
	material.Target = identity.Bytes()
	material.Prompt, err = compiler.Compile(prompt.CompileInput{Scope: material.Prompt.Scope().FrameScope().Coordinates(), ReviewTarget: prompt.NewPayload(material.Target)})
	if err != nil {
		t.Fatal(err)
	}
	provider := &recordingObservedProvider{t: t}
	for _, raw := range responses {
		provider.responses = append(provider.responses, providerRuntimeObservation{stdout: raw})
	}
	runtime, err := NewObservedProviderInvocationRuntimeInLiveSource(provider, requirementsTestPrompts{explicitRuntimePromptSource{material}}, execution, newReviewValidator(t), providerRuntimeDiagnosticResolver{runID: job.RunID(), sink: &providerRuntimeRawSink{}})
	if err != nil {
		t.Fatal(err)
	}
	input, err := validation.DecodeRequirementsInput([]byte(`{"schema_version":"mulgae-requirements-input.v1","requirements":[{"id":"A","text":"description","acceptance_criteria":["criterion"],"owner_role":"logic"},{"id":"B","text":"description","acceptance_criteria":["criterion"],"owner_role":"logic"},{"id":"C","text":"description","acceptance_criteria":["criterion"],"owner_role":"logic"}]}`), []domain.Role{domain.RoleLogic})
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.BindRequirements(input, "requirements.json"); err != nil {
		t.Fatal(err)
	}
	return runtime, job, provider
}
func requirementsRuntimeRow(id string) map[string]any {
	return map[string]any{"requirement_id": id, "verdict": "met", "rationale": "Source supports the criterion.", "examined_scope": "source.go", "limitations": []string{"No execution."}, "reason": "", "evidence": []any{map[string]any{"current": map[string]any{"path": "source.go", "side": "worktree", "line_start": 1, "line_end": 1, "quote": "observed\n"}}}}
}
func requirementsRuntimeResponse(findings any, rows ...map[string]any) []byte {
	object := map[string]any{"schema_version": validation.RequirementsProviderOutputVersion, "summary": "Primary role report.", "completeness": "complete", "limitations": []string{}, "findings": findings}
	if rows != nil {
		object["requirements"] = map[string]any{"schema_version": "mulgae-provider-requirements.v1", "assessments": rows}
	}
	raw, _ := json.Marshal(object)
	return raw
}
func TestRequirementsRuntimePreservesIndependentInitialSections(t *testing.T) {
	for _, test := range []struct {
		name        string
		findings    any
		rows        []map[string]any
		reportsOnly bool
		evaluated   int
		reason      domain.AssessmentReason
	}{
		{"valid with disabled extraction", []any{}, []map[string]any{requirementsRuntimeRow("A")}, false, 1, domain.AssessmentAnswerOmitted},
		{"assessment only", "invalid findings", []map[string]any{requirementsRuntimeRow("A")}, true, 1, domain.AssessmentAnswerOmitted},
		{"duplicate assessment", []any{}, []map[string]any{requirementsRuntimeRow("A"), requirementsRuntimeRow("A")}, false, 0, domain.AssessmentInvalidContent},
		{"absent section", []any{}, nil, false, 0, domain.AssessmentExtractionDisabled},
	} {
		t.Run(test.name, func(t *testing.T) {
			runtime, job, provider := requirementsRuntimeFixture(t, requirementsRuntimeResponse(test.findings, test.rows...))
			outcome := runtime.Invoke(context.Background(), job)
			output, ok := outcome.Output()
			if !ok || !outcome.Succeeded() || output.ReportsOnly() != test.reportsOnly {
				t.Fatalf("independent section output: %+v", outcome)
			}
			result, err := runtime.RequirementsResult(false)
			if err != nil {
				t.Fatal(err)
			}
			selected, evaluated, _ := result.Evaluation().Counts()
			if selected != 3 || evaluated != test.evaluated || result.Evaluation().Assessments()[2].Reason() != test.reason || len(provider.invocations) != 1 {
				t.Fatalf("counts/reason/calls: %+v", result.Evaluation())
			}
		})
	}
}
func TestRequirementsRuntimeExtractionRetainsValidPeerAndPrimaryReport(t *testing.T) {
	initial := requirementsRuntimeResponse([]any{})
	second := requirementsRuntimeResponse("invalid findings", requirementsRuntimeRow("A"))
	runtime, job, provider := requirementsRuntimeFixture(t, initial, second)
	first := runtime.Invoke(context.Background(), job)
	prior, _ := first.Output()
	if !prior.assessmentPending || prior.ReportsOnly() {
		t.Fatal("missing section did not preserve finding axis")
	}
	job.purpose = domain.InvocationExtract
	outcome := runtime.Invoke(context.Background(), job)
	output, ok := outcome.Output()
	if !ok || output.ReportsOnly() || string(output.ReportMarkdown()) != string(prior.ReportMarkdown()) {
		t.Fatal("ordinary extraction peer failure erased initial findings/report")
	}
	result, err := runtime.RequirementsResult(true)
	if err != nil {
		t.Fatal(err)
	}
	_, evaluated, _ := result.Evaluation().Counts()
	if evaluated != 1 || len(provider.invocations) != 2 {
		t.Fatal("extraction lost assessment or exceeded shared calls")
	}
}

func TestRequirementsMarkdownExtractionPreservesEveryVerdict(t *testing.T) {
	for _, verdict := range []domain.RequirementVerdict{domain.RequirementMet, domain.RequirementPartiallyMet, domain.RequirementUnmet, domain.RequirementUnverified} {
		t.Run(string(verdict), func(t *testing.T) {
			report := []byte("# Logic review\n\nA: " + string(verdict) + ". Examined source.go:1 (observed). No execution evidence.\n")
			row := requirementsRuntimeRow("A")
			row["verdict"] = string(verdict)
			if verdict == domain.RequirementUnverified {
				row["reason"] = "insufficient_evidence"
				row["evidence"] = []any{}
			}
			runtime, job, provider := requirementsRuntimeFixture(t, report, requirementsRuntimeResponse([]any{}, row))
			if !runtime.Invoke(context.Background(), job).Succeeded() {
				t.Fatal("primary Markdown report was rejected")
			}
			job.purpose = domain.InvocationExtract
			outcome := runtime.Invoke(context.Background(), job)
			output, ok := outcome.Output()
			if !ok || string(output.ReportMarkdown()) != string(report) {
				t.Fatal("extraction replaced the original report")
			}
			result, err := runtime.RequirementsResult(true)
			if err != nil {
				t.Fatal(err)
			}
			selected, evaluated, _ := result.Evaluation().Counts()
			rows := result.Evaluation().Assessments()
			if selected != 3 || evaluated != 1 || len(provider.invocations) != 2 || rows[0].Verdict() != verdict || rows[0].Origin() != domain.AssessmentProvider {
				t.Fatalf("lost verdict/origin/counts or exceeded shared budget: %+v", result.Evaluation())
			}
			for _, omitted := range rows[1:] {
				if omitted.Verdict() != domain.RequirementUnverified || omitted.Origin() != domain.AssessmentDerived || omitted.Reason() != domain.AssessmentAnswerOmitted {
					t.Fatal("extraction invented an unsupported answer")
				}
			}
		})
	}
}
func TestRequirementsRuntimeExtractionInvalidAssessmentRetainsAcceptedFindings(t *testing.T) {
	finding := map[string]any{
		"severity": "high", "title": "Accepted source defect", "description": "The observed source demonstrates the defect.",
		"evidence":       []any{map[string]any{"current": map[string]any{"path": "source.go", "side": "worktree", "line_start": 1, "line_end": 1, "quote": "observed\n"}}},
		"recommendation": "Correct the defect.", "confidence": "high",
	}
	replacement := make(map[string]any, len(finding))
	for key, value := range finding {
		replacement[key] = value
	}
	replacement["title"] = "Extraction replacement finding"
	initial := requirementsRuntimeResponse([]any{finding})
	second := requirementsRuntimeResponse([]any{replacement}, requirementsRuntimeRow("A"), requirementsRuntimeRow("A"))
	second = []byte(strings.Replace(string(second), "Primary role report.", "Extraction replacement report.", 1))
	runtime, job, provider := requirementsRuntimeFixture(t, initial, second)
	first := runtime.Invoke(context.Background(), job)
	prior, ok := first.Output()
	if !first.Succeeded() || !ok || prior.ReportsOnly() || !prior.assessmentPending || len(prior.Findings()) != 1 {
		t.Fatal("initial findings/report were not accepted with an absent assessment")
	}
	extract, err := newCoordinatorInvocationJob(job.SessionID(), job.RunID(), job.Role(), job.Route(), job.Target(), job.Limits(), job.AttemptID(), domain.InvocationExtract, 2)
	if err != nil {
		t.Fatal(err)
	}
	outcome := runtime.Invoke(context.Background(), extract)
	output, ok := outcome.Output()
	if !outcome.Succeeded() || !ok || output.ReportsOnly() || output.assessmentPending || len(output.Findings()) != 1 ||
		!sameCoordinatorFinding(output.Findings()[0], prior.Findings()[0]) || string(output.ReportMarkdown()) != string(prior.ReportMarkdown()) {
		t.Fatal("ordinary invalid extraction assessment replaced accepted findings/report or left another extraction pending")
	}
	result, err := runtime.RequirementsResult(true)
	if err != nil {
		t.Fatal(err)
	}
	selected, evaluated, known := result.Evaluation().Counts()
	rows := result.Evaluation().Assessments()
	if !known || selected != 3 || evaluated != 0 || len(rows) != 3 {
		t.Fatal("invalid owning section supplied provider rows or dishonest counts")
	}
	for i, id := range []string{"A", "B", "C"} {
		row := rows[i]
		if row.RequirementID() != id || row.OwnerRole() != domain.RoleLogic || row.Verdict() != domain.RequirementUnverified ||
			row.Origin() != domain.AssessmentDerived || row.Reason() != domain.AssessmentInvalidContent {
			t.Fatalf("invalid extraction section row %d: %+v", i, row)
		}
	}
	if len(provider.invocations) != 2 || len(runtime.pending) != 0 {
		t.Fatal("ordinary invalid assessment requested repair or exceeded the shared two-call allowance")
	}
	for i, purpose := range []ports.ProviderInvocationPurpose{ports.ProviderInvocationInitial, ports.ProviderInvocationExtract} {
		invocation := provider.invocations[i]
		if invocation.Purpose() != purpose || invocation.ProviderInstance() != job.Route().ProviderInstance() || invocation.Role() != job.Role() {
			t.Fatal("inverse extraction changed invocation purpose, provider or role")
		}
	}
}

func TestRequirementsRuntimeSpentAllowanceAndProtectedFailure(t *testing.T) {
	runtime, job, provider := requirementsRuntimeFixture(t, requirementsRuntimeResponse([]any{}))
	job.purpose = domain.InvocationRetry
	outcome := runtime.Invoke(context.Background(), job)
	if !outcome.Succeeded() {
		t.Fatal("retry report was lost")
	}
	result, err := runtime.RequirementsResult(true)
	if err != nil || result.Evaluation().Assessments()[0].Reason() != domain.AssessmentExtractionAllowanceSpent || len(provider.invocations) != 1 {
		t.Fatal("spent reason/count")
	}
	row := requirementsRuntimeRow("A")
	row["origin"] = "provider"
	runtime, job, provider = requirementsRuntimeFixture(t, requirementsRuntimeResponse([]any{}, row))
	outcome = runtime.Invoke(context.Background(), job)
	condition, _ := outcome.Condition()
	if outcome.Succeeded() || condition != AttemptConditionSecurityViolation || len(provider.invocations) != 1 {
		t.Fatal("protected field accepted")
	}
}

func TestRequirementsCoordinatorSharesAdditionalSlot(t *testing.T) {
	for _, test := range []struct {
		name                  string
		admit, pending, retry bool
		want                  int
	}{
		{"disabled", false, true, false, 1}, {"valid section omissions", true, false, false, 1}, {"missing section", true, true, false, 2}, {"retry already consumed", true, true, true, 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			assignments, receipt := coordinatorTestPlan(t)
			var purposes []domain.InvocationPurpose
			var instances []string
			runtime := &coordinatorTestRuntime{invoke: func(_ context.Context, job InvocationJob) AttemptOutcome {
				if job.Role() != domain.RoleLogic {
					return coordinatorSuccessOutcome(t, job)
				}
				purposes = append(purposes, job.Purpose())
				instances = append(instances, job.Route().ProviderInstance())
				if test.retry && job.Purpose() == domain.InvocationInitial {
					return coordinatorConditionOutcome(t, job, AttemptConditionProviderUnavailable)
				}
				output, err := NewValidatedRoleOutput(job.Role(), job.Route().ProviderInstance(), job.Target(), nil, "complete", nil)
				if err != nil {
					t.Fatal(err)
				}
				output.assessmentPending = test.pending
				return coordinatorOutputOutcome(job, output)
			}}
			result := coordinatorExtractionExecute(t, assignments, receipt, runtime, test.admit)
			if len(purposes) != test.want || len(purposes) > 2 {
				t.Fatalf("additional slot changed: %v", purposes)
			}
			for _, instance := range instances {
				if instance != instances[0] {
					t.Fatal("provider substituted")
				}
			}
			if test.retry && purposes[1] != domain.InvocationRetry {
				t.Fatal("retry allowance reused for assessment")
			}
			if !test.retry && test.want == 2 && purposes[1] != domain.InvocationExtract {
				t.Fatal("missing section did not share existing transcription slot")
			}
			summary := coordinatorRoleSummary(t, result, domain.RoleLogic)
			if summary.ReportsOnly() || summary.State() != domain.RoleTaskSucceeded {
				t.Fatal("assessment availability changed finding/role axes")
			}
		})
	}
}

func TestRequirementsRuntimeAvailableSectionReasonPriority(t *testing.T) {
	for _, test := range []struct {
		name       string
		raw        []byte
		purpose    domain.InvocationPurpose
		extraction bool
		reason     domain.AssessmentReason
	}{
		{"valid section disabled", requirementsRuntimeResponse([]any{}, requirementsRuntimeRow("A")), domain.InvocationInitial, false, domain.AssessmentAnswerOmitted},
		{"invalid section disabled", requirementsRuntimeResponse([]any{}, requirementsRuntimeRow("A"), requirementsRuntimeRow("A")), domain.InvocationInitial, false, domain.AssessmentInvalidContent},
		{"invalid section spent", requirementsRuntimeResponse([]any{}, requirementsRuntimeRow("A"), requirementsRuntimeRow("A")), domain.InvocationRetry, true, domain.AssessmentInvalidContent},
		{"valid section spent", requirementsRuntimeResponse([]any{}, requirementsRuntimeRow("A")), domain.InvocationRetry, true, domain.AssessmentAnswerOmitted},
		{"disabled before spent absence", requirementsRuntimeResponse([]any{}), domain.InvocationRetry, false, domain.AssessmentExtractionDisabled},
	} {
		t.Run(test.name, func(t *testing.T) {
			runtime, job, _ := requirementsRuntimeFixture(t, test.raw)
			job.purpose = test.purpose
			if !runtime.Invoke(context.Background(), job).Succeeded() {
				t.Fatal("accepted primary report lost")
			}
			result, err := runtime.RequirementsResult(test.extraction)
			if err != nil || result.Evaluation().Assessments()[2].Reason() != test.reason {
				t.Fatalf("reason priority: %v / %v", result.Evaluation().Assessments(), err)
			}
		})
	}
}

type requirementsFaultReader struct {
	ports.LiveSourceReader
	err error
}

func (r requirementsFaultReader) Read(context.Context, domain.LiveSourceSide, ports.SafeRelativePath) (ports.LiveSourceFile, error) {
	return ports.LiveSourceFile{}, r.err
}

func TestRequirementsRuntimePreservesProtectedSourceFailureClasses(t *testing.T) {
	internal, _ := domain.NewFailure("source.fixture", domain.FailureInternal, "internal source failure", nil)
	artifact, _ := domain.NewFailure("source.fixture", domain.FailureArtifact, "artifact source failure", nil)
	for _, test := range []struct {
		name string
		err  error
		want AttemptCondition
	}{
		{"cancelled", context.Canceled, AttemptConditionCancelled},
		{"deadline", context.DeadlineExceeded, AttemptConditionCancelled},
		{"source unavailable", ports.NewLiveSourceError(ports.LiveSourceUnavailable, nil), AttemptConditionArtifactFailure},
		{"artifact", artifact, AttemptConditionArtifactFailure},
		{"internal", internal, AttemptConditionInternalInvariant},
		{"unsafe", ports.NewLiveSourceError(ports.LiveSourceUnsafe, nil), AttemptConditionSecurityViolation},
	} {
		t.Run(test.name, func(t *testing.T) {
			runtime, job, provider := requirementsRuntimeFixture(t, requirementsRuntimeResponse([]any{}, requirementsRuntimeRow("A")))
			runtime.verifier, _ = evidence.NewLiveVerifier(requirementsFaultReader{LiveSourceReader: runtime.liveExecution.SourceReader(), err: test.err})
			outcome := runtime.Invoke(context.Background(), job)
			condition, _ := outcome.Condition()
			if outcome.Succeeded() || condition != test.want || len(provider.invocations) != 1 || len(runtime.pendingExtraction) != 0 {
				t.Fatalf("protected source failure was relabeled/accepted: got %s want %s", condition, test.want)
			}
		})
	}
}

func TestRequirementsRuntimeReportsHonestExtractionStates(t *testing.T) {
	for _, test := range []struct {
		name       string
		raw        []byte
		parse      domain.ParseState
		validation domain.ValidationState
	}{
		{"free form", []byte("# Primary review\n\nProse only.\n"), domain.ParseNotStarted, domain.ValidationNotStarted},
		{"valid JSON invalid peer", requirementsRuntimeResponse("invalid findings", requirementsRuntimeRow("A")), domain.ParseValid, domain.ValidationInvalid},
	} {
		t.Run(test.name, func(t *testing.T) {
			runtime, job, provider := requirementsRuntimeFixture(t, test.raw)
			outcome := runtime.Invoke(context.Background(), job)
			output, ok := outcome.Output()
			if !ok || !output.ReportsOnly() || output.ParseState() != test.parse || output.ValidationState() != test.validation || len(provider.invocations) != 1 {
				t.Fatalf("report axes: succeeded=%v reportsOnly=%v parse=%s validation=%s", outcome.Succeeded(), output.ReportsOnly(), output.ParseState(), output.ValidationState())
			}
			if test.parse == domain.ParseNotStarted {
				capture, _ := runtime.Capture(job.AttemptID(), 1)
				for _, artifact := range capture.Artifacts() {
					if artifact.Kind() == ports.AttemptArtifactInitialCandidate {
						t.Fatal("free-form prose became a structured candidate")
					}
				}
			}
		})
	}
	runtime, job, provider := requirementsRuntimeFixture(t, []byte(`{"schema_version":"mulgae-provider-review-output.v3","requirements":{`), []byte("No structured repair."))
	first := runtime.Invoke(context.Background(), job)
	if first.Succeeded() {
		t.Fatal("malformed whole response supplied a section")
	}
	job.purpose = domain.InvocationRepair
	second := runtime.Invoke(context.Background(), job)
	output, ok := second.Output()
	if !ok || !output.ReportsOnly() || output.ParseState() != domain.ParseInvalidJSON || output.ValidationState() != domain.ValidationRepairExhausted || len(provider.invocations) != 2 {
		t.Fatalf("malformed/repair axes: parse=%s validation=%s", output.ParseState(), output.ValidationState())
	}
	result, err := runtime.RequirementsResult(true)
	if err != nil {
		t.Fatal(err)
	}
	_, evaluated, _ := result.Evaluation().Counts()
	if evaluated != 0 || result.Evaluation().Assessments()[0].Reason() != domain.AssessmentExtractionAllowanceSpent {
		t.Fatal("unparseable response supplied independent assessment")
	}
}

type requirementsInfrastructureDiagnostic struct{}

func (requirementsInfrastructureDiagnostic) Error() string           { return "schema infrastructure failure" }
func (requirementsInfrastructureDiagnostic) DocumentViolation() bool { return false }

type requirementsFaultSchema struct{ err error }

func (s requirementsFaultSchema) Validate(context.Context, ports.AssetID, []byte) error { return s.err }
func TestRequirementsRuntimeDoesNotAcceptTrustedValidatorFailures(t *testing.T) {
	artifact, _ := domain.NewFailure("schema.fixture", domain.FailureArtifact, "artifact unavailable", nil)
	internal, _ := domain.NewFailure("schema.fixture", domain.FailureInternal, "internal schema failure", nil)
	for _, test := range []struct {
		name string
		err  error
		want AttemptCondition
	}{
		{"cancelled", context.Canceled, AttemptConditionCancelled}, {"deadline", context.DeadlineExceeded, AttemptConditionCancelled}, {"artifact", artifact, AttemptConditionArtifactFailure}, {"internal", internal, AttemptConditionInternalInvariant}, {"native infrastructure marker", requirementsInfrastructureDiagnostic{}, AttemptConditionInternalInvariant},
	} {
		t.Run(test.name, func(t *testing.T) {
			runtime, job, provider := requirementsRuntimeFixture(t, requirementsRuntimeResponse([]any{}, requirementsRuntimeRow("A")))
			id, _ := ports.ParseAssetID(validation.ProviderReviewSchemaID)
			runtime.validator, _ = validation.NewReviewValidator(requirementsFaultSchema{test.err}, id)
			outcome := runtime.Invoke(context.Background(), job)
			condition, _ := outcome.Condition()
			if outcome.Succeeded() || condition != test.want || len(provider.invocations) != 1 || len(runtime.pendingExtraction) != 0 {
				t.Fatalf("trusted validator failure accepted or relabeled: %s", condition)
			}
		})
	}
}

func TestRequirementsRuntimeSelectsJoinedProtectedSourceFailures(t *testing.T) {
	internal, _ := domain.NewFailure("source.fixture", domain.FailureInternal, "internal", nil)
	artifact, _ := domain.NewFailure("source.fixture", domain.FailureArtifact, "artifact", nil)
	seed, job, _ := requirementsRuntimeFixture(t)
	row := requirementsRuntimeRow("A")
	row["origin"] = "provider"
	raw, _ := json.Marshal(map[string]any{"schema_version": "mulgae-provider-requirements.v1", "assessments": []any{row}})
	_, ownership := validation.DecodeProviderRequirements(context.Background(), raw, seed.requirements.Requirements(), job.Role(), seed.liveIdentity, seed.verifier, nil, "requirements.json", seed.requirements.SHA256())
	invalid := ports.NewLiveSourceError(ports.LiveSourceInvalid, nil)
	for _, test := range []struct {
		name string
		err  error
		want AttemptCondition
	}{
		{"invalid then internal", errors.Join(invalid, internal), AttemptConditionInternalInvariant},
		{"internal then invalid", errors.Join(internal, invalid), AttemptConditionInternalInvariant},
		{"artifact then internal", errors.Join(artifact, internal), AttemptConditionInternalInvariant},
		{"internal then artifact", errors.Join(internal, artifact), AttemptConditionInternalInvariant},
		{"ownership then internal", errors.Join(ownership, internal), AttemptConditionInternalInvariant},
		{"invalid then cancellation", errors.Join(invalid, context.Canceled), AttemptConditionCancelled},
		{"artifact under cancellation", errors.Join(context.Canceled, artifact), AttemptConditionArtifactFailure},
	} {
		t.Run(test.name, func(t *testing.T) {
			runtime, job, provider := requirementsRuntimeFixture(t, requirementsRuntimeResponse([]any{}, requirementsRuntimeRow("A")))
			runtime.verifier, _ = evidence.NewLiveVerifier(requirementsFaultReader{LiveSourceReader: runtime.liveExecution.SourceReader(), err: test.err})
			outcome := runtime.Invoke(context.Background(), job)
			condition, _ := outcome.Condition()
			if outcome.Succeeded() || condition != test.want || len(provider.invocations) != 1 {
				t.Fatalf("joined source precedence: got %s want %s", condition, test.want)
			}
		})
	}
}

func TestRequirementsRuntimeMaterializesTrustedNormalizedV3(t *testing.T) {
	runtime, job, _ := requirementsRuntimeFixture(t, requirementsRuntimeResponse([]any{}, requirementsRuntimeRow("A")))
	if !runtime.Invoke(context.Background(), job).Succeeded() {
		t.Fatal("initial sections rejected")
	}
	output, ok := runtime.NormalizedRequirementsOutput(job.Role())
	if !ok || output.SchemaVersion() != validation.RequirementsProviderOutputVersion {
		t.Fatal("trusted normalized v3 composition absent")
	}
	raw, err := output.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	schema, err := jsonschema.New(context.Background(), builtin.NewCatalog())
	if err != nil {
		t.Fatal(err)
	}
	id, _ := ports.ParseAssetID("https://mulgae.local/schemas/mulgae-provider-review-output.v3.schema.json")
	if err := schema.Validate(context.Background(), id, raw); err != nil {
		t.Fatalf("actual trusted v3 serialization: %v", err)
	}
	var document struct {
		Schema       string `json:"schema_version"`
		Requirements struct {
			Answers []struct {
				Evidence []struct {
					Current validation.RequirementCurrentEvidence `json:"current"`
				} `json:"evidence"`
			} `json:"assessments"`
		} `json:"requirements"`
	}
	if json.Unmarshal(raw, &document) != nil || document.Schema != validation.RequirementsProviderOutputVersion || len(document.Requirements.Answers) != 1 {
		t.Fatal("normalized shape changed")
	}
	current := document.Requirements.Answers[0].Evidence[0].Current
	if current.SourceIdentitySHA256 != runtime.liveIdentity.SHA256() || current.CurrentExcerptSHA256 == "" || current.Verification != "verified" {
		t.Fatal("v3 echoed provider claims instead of verified content")
	}
	runtime, job, _ = requirementsRuntimeFixture(t, requirementsRuntimeResponse("invalid findings", requirementsRuntimeRow("A")))
	if !runtime.Invoke(context.Background(), job).Succeeded() {
		t.Fatal("accepted assessment/report lost")
	}
	if _, ok := runtime.NormalizedRequirementsOutput(job.Role()); ok {
		t.Fatal("partial section fabricated complete finding envelope")
	}
}

func TestRequirementsRuntimeSerializesUnboundedNormalizedV3(t *testing.T) {
	row := requirementsRuntimeRow("A")
	row["rationale"] = strings.Repeat("r", 9<<20)
	runtime, job, _ := requirementsRuntimeFixture(t, requirementsRuntimeResponse([]any{}, row))
	outcome := runtime.Invoke(context.Background(), job)
	if !outcome.Succeeded() {
		t.Fatal("large initial assessment rejected")
	}
	output, ok := runtime.NormalizedRequirementsOutput(job.Role())
	if !ok {
		t.Fatal("large trusted composition absent")
	}
	raw, err := output.Bytes()
	if err != nil || len(raw) <= 8<<20 {
		t.Fatalf("large v3 serialization clipped or bounded: %v", err)
	}
	result, err := runtime.RequirementsResult(false)
	if err != nil || len(result.Contents()[0]) <= 8<<20 {
		t.Fatal("large normalized support content lost")
	}
}

type requirementsRecordingSink struct {
	providerRuntimeInvocationStatusSink
	inputs          []domain.RuntimeDiagnosticEventInput
	statuses        []ports.RuntimeDiagnosticInvocationStatus
	rawPersistCalls int
	rawStreams      []map[domain.RuntimeDiagnosticStream][]byte
}

func (sink *requirementsRecordingSink) Emit(ctx context.Context, draft domain.RuntimeDiagnosticEventDraft) (domain.RuntimeDiagnosticEvent, error) {
	sink.inputs = append(sink.inputs, draft.Input())
	return sink.providerRuntimeInvocationStatusSink.Emit(ctx, draft)
}

func (sink *requirementsRecordingSink) PersistRaw(ctx context.Context, request ports.RuntimeDiagnosticRawRequest) (ports.RuntimeDiagnosticRawResult, error) {
	sink.rawPersistCalls++
	res, err := sink.providerRuntimeInvocationStatusSink.PersistRaw(ctx, request)
	if err == nil {
		cp := make(map[domain.RuntimeDiagnosticStream][]byte, len(sink.streams))
		for k, v := range sink.streams {
			cp[k] = append([]byte(nil), v...)
		}
		sink.rawStreams = append(sink.rawStreams, cp)
	}
	return res, err
}

func (sink *requirementsRecordingSink) ReplaceInvocationStatus(ctx context.Context, status ports.RuntimeDiagnosticInvocationStatus) error {
	sink.statuses = append(sink.statuses, status)
	return sink.providerRuntimeInvocationStatusSink.ReplaceInvocationStatus(ctx, status)
}

func requirementsRuntimeFixtureWithScopeAndSink(t *testing.T, scope domain.LiveSourceScope, responses ...[]byte) (*ProviderInvocationRuntime, InvocationJob, *recordingObservedProvider, *requirementsRecordingSink) {
	t.Helper()
	selector, err := ports.NewLiveSourceSelector(scope, "")
	if err != nil {
		t.Fatal(err)
	}
	path, _ := ports.NewSafeRelativePath("source.go")
	var base ports.GitObjectID
	changes := []ports.LiveSourceChange{{Kind: "included", After: path}}
	if scope == domain.LiveSourceStage {
		base, _ = ports.ParseGitObjectID(strings.Repeat("a", 40))
		changes = []ports.LiveSourceChange{{Kind: "modified", Before: path, After: path}}
	}
	target, err := ports.NewLiveSourceTarget(selector, base, ports.GitObjectID{}, false, changes)
	if err != nil {
		t.Fatal(err)
	}
	root, _ := ports.NewAnchoredRoot("/source")
	neutral, _ := ports.NewAnchoredRoot("/neutral")
	credential, _ := ports.NewAnchoredRoot("/credentials")
	reader := &runtimeLiveReader{coordinatorLiveReader: coordinatorLiveReader{target}, binding: ports.ProjectBindingObservation{Root: root, RootIdentity: ports.ProjectDirectoryIdentity{Device: 1, Inode: 2}}}
	execution, err := ports.NewLiveReviewExecution(context.Background(), reader, runtimeLiveHome{root: neutral}, []ports.AnchoredRoot{credential})
	if err != nil {
		t.Fatal(err)
	}
	identity, _ := evidence.NewLiveSourceIdentity(target)
	_, job, material := providerRuntimeExplicitFixture(t, nil)
	job.target, _ = identity.RunTarget()
	compiler, _ := prompt.NewCompiler(material.Prompt.TrustedTemplate(), explicitRuntimeTestIssuer{source: material.Prompt.Scope().SourceInvocationID(), execution: material.Prompt.Scope().ExecutionInvocationID()})
	material.Target = identity.Bytes()
	material.Prompt, err = compiler.Compile(prompt.CompileInput{Scope: material.Prompt.Scope().FrameScope().Coordinates(), ReviewTarget: prompt.NewPayload(material.Target)})
	if err != nil {
		t.Fatal(err)
	}
	provider := &recordingObservedProvider{t: t}
	for _, raw := range responses {
		provider.responses = append(provider.responses, providerRuntimeObservation{stdout: raw})
	}
	sink := &requirementsRecordingSink{}
	runtime, err := NewObservedProviderInvocationRuntimeInLiveSource(provider, requirementsTestPrompts{explicitRuntimePromptSource{material}}, execution, newReviewValidator(t), providerRuntimeDiagnosticResolver{runID: job.RunID(), sink: sink})
	if err != nil {
		t.Fatal(err)
	}
	input, err := validation.DecodeRequirementsInput([]byte(`{"schema_version":"mulgae-requirements-input.v1","requirements":[{"id":"A","text":"description","acceptance_criteria":["criterion"],"owner_role":"logic"},{"id":"B","text":"description","acceptance_criteria":["criterion"],"owner_role":"logic"},{"id":"C","text":"description","acceptance_criteria":["criterion"],"owner_role":"logic"}]}`), []domain.Role{domain.RoleLogic})
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.BindRequirements(input, "requirements.json"); err != nil {
		t.Fatal(err)
	}
	return runtime, job, provider, sink
}

func TestRequirementsRuntime2COwnershipAndOrdinaryUnknownKeys(t *testing.T) {
	t.Run("ordinary unknown key in requirements section stays bounded invalid_assessment", func(t *testing.T) {
		row := requirementsRuntimeRow("A")
		row["extra_note"] = "harmless provider note"
		runtime, job, _, sink := requirementsRuntimeFixtureWithScopeAndSink(t, domain.LiveSourceWorkspace, requirementsRuntimeResponse([]any{}, row))
		outcome := runtime.Invoke(context.Background(), job)
		if !outcome.Succeeded() {
			t.Fatalf("ordinary unknown key aborted invocation: %+v", outcome)
		}
		if sink.rawPersistCalls != 1 {
			t.Fatalf("rawPersistCalls = %d, want 1 (non-security persists streams normally)", sink.rawPersistCalls)
		}
		result, err := runtime.RequirementsResult(false)
		if err != nil {
			t.Fatal(err)
		}
		if got := result.Evaluation().Assessments()[0].Reason(); got != domain.AssessmentInvalidContent {
			t.Fatalf("assessment reason = %q, want %q", got, domain.AssessmentInvalidContent)
		}
	})

	t.Run("protected key mixed with ordinary unknown key fails closed with provider_ownership_violation", func(t *testing.T) {
		row := requirementsRuntimeRow("A")
		row["aaa_extra_note"] = "ordinary"
		row["owner_role"] = "logic"
		runtime, job, _, sink := requirementsRuntimeFixtureWithScopeAndSink(t, domain.LiveSourceWorkspace, requirementsRuntimeResponse([]any{}, row))
		outcome := runtime.Invoke(context.Background(), job)
		cond, ok := outcome.Condition()
		if outcome.Succeeded() || !ok || cond != AttemptConditionSecurityViolation || outcome.diagnosticCause != domain.DiagnosticCauseProviderOwnershipViolation {
			t.Fatalf("protected ownership attack = cond:%q cause:%q, want security_violation/provider_ownership_violation", cond, outcome.diagnosticCause)
		}
		if sink.rawPersistCalls != 0 {
			t.Fatalf("security-rejected invocation persisted raw streams (%d calls)", sink.rawPersistCalls)
		}
		capRec, captured := runtime.Capture(job.AttemptID(), 1)
		if !captured || len(capRec.Artifacts()) == 0 {
			t.Fatal("security-rejected invocation missing capture markers")
		}
		for _, artifact := range capRec.Artifacts() {
			if !artifact.SecurityRejected() || len(artifact.Bytes()) != 0 {
				t.Fatalf("security-rejected artifact leaked bytes or lost marker: %+v", artifact)
			}
		}
	})

	t.Run("outer unknown key or earlier invalid row cannot mask nested protected key at runtime", func(t *testing.T) {
		badFirst := requirementsRuntimeRow("A")
		badFirst["extra_note"] = "ordinary unknown"
		secondProtected := requirementsRuntimeRow("B")
		secondProtected["evidence"].([]any)[0].(map[string]any)["current"].(map[string]any)["verification"] = "verified"
		raw, _ := json.Marshal(map[string]any{
			"schema_version": validation.RequirementsProviderOutputVersion,
			"summary":        "Report.",
			"completeness":   "complete",
			"limitations":    []string{},
			"findings":       []any{},
			"requirements": map[string]any{
				"schema_version": "mulgae-provider-requirements.v1",
				"outer_note":     "ordinary unknown outer key",
				"assessments":    []any{badFirst, secondProtected},
			},
		})
		runtime, job, _, sink := requirementsRuntimeFixtureWithScopeAndSink(t, domain.LiveSourceWorkspace, raw)
		outcome := runtime.Invoke(context.Background(), job)
		cond, ok := outcome.Condition()
		if outcome.Succeeded() || !ok || cond != AttemptConditionSecurityViolation || outcome.diagnosticCause != domain.DiagnosticCauseProviderOwnershipViolation {
			t.Fatalf("masked nested protected key = cond:%q cause:%q, want security_violation/provider_ownership_violation", cond, outcome.diagnosticCause)
		}
		if sink.rawPersistCalls != 0 {
			t.Fatalf("masked nested protected key leaked raw streams: %d", sink.rawPersistCalls)
		}
	})
}

func TestRequirementsRuntimeM1CitationFaultVsRealSourceDrift(t *testing.T) {
	for _, scope := range []domain.LiveSourceScope{domain.LiveSourceWorkspace, domain.LiveSourceStage} {
		side := "worktree"
		if scope == domain.LiveSourceStage {
			side = "index"
		}
		t.Run(string(scope)+"/citation-fault-in-requirements-is-bounded", func(t *testing.T) {
			for _, code := range []ports.LiveSourceErrorCode{ports.LiveSourceUnavailable, ports.LiveSourceUnsafe} {
				row := requirementsRuntimeRow("A")
				row["evidence"].([]any)[0].(map[string]any)["current"].(map[string]any)["side"] = side
				runtime, job, _, sink := requirementsRuntimeFixtureWithScopeAndSink(t, scope, requirementsRuntimeResponse([]any{}, row))
				runtime.verifier, _ = evidence.NewLiveVerifier(requirementsFaultReader{
					LiveSourceReader: runtime.liveExecution.SourceReader(),
					err:              ports.NewLiveSourceCitationError(code, errors.New("hallucinated path")),
				})
				outcome := runtime.Invoke(context.Background(), job)
				if !outcome.Succeeded() {
					t.Fatalf("citation fault %q aborted requirements invocation: %+v", code, outcome)
				}
				if sink.rawPersistCalls != 1 {
					t.Fatalf("citation fault %q rawPersistCalls = %d, want 1", code, sink.rawPersistCalls)
				}
				result, err := runtime.RequirementsResult(false)
				if err != nil {
					t.Fatal(err)
				}
				if got := result.Evaluation().Assessments()[0].Reason(); got != domain.AssessmentInvalidContent {
					t.Fatalf("citation fault %q reason = %q, want invalid_assessment", code, got)
				}
			}
		})

		t.Run(string(scope)+"/citation-fault-in-findings-is-bounded", func(t *testing.T) {
			finding := map[string]any{
				"severity": "high", "title": "Cited finding", "description": "References an absent path.",
				"evidence":       []any{map[string]any{"current": map[string]any{"path": "source.go", "side": side, "line_start": 1, "line_end": 1, "quote": "observed\n"}}},
				"recommendation": "Check citation.", "confidence": "high",
			}
			runtime, job, _, sink := requirementsRuntimeFixtureWithScopeAndSink(t, scope, requirementsRuntimeResponse([]any{finding}))
			runtime.verifier, _ = evidence.NewLiveVerifier(requirementsFaultReader{
				LiveSourceReader: runtime.liveExecution.SourceReader(),
				err:              ports.NewLiveSourceCitationError(ports.LiveSourceUnavailable, errors.New("absent path")),
			})
			outcome := runtime.Invoke(context.Background(), job)
			output, ok := outcome.Output()
			if !outcome.Succeeded() || !ok || !output.ReportsOnly() {
				t.Fatalf("citation fault in findings did not stay bounded reports-only: %+v", outcome)
			}
			if sink.rawPersistCalls != 1 {
				t.Fatalf("citation fault in findings rawPersistCalls = %d, want 1", sink.rawPersistCalls)
			}
		})

		t.Run(string(scope)+"/real-drift-unsafe-fails-closed-with-live-source-unsafe", func(t *testing.T) {
			row := requirementsRuntimeRow("A")
			row["evidence"].([]any)[0].(map[string]any)["current"].(map[string]any)["side"] = side
			runtime, job, _, sink := requirementsRuntimeFixtureWithScopeAndSink(t, scope, requirementsRuntimeResponse([]any{}, row))
			runtime.verifier, _ = evidence.NewLiveVerifier(requirementsFaultReader{
				LiveSourceReader: runtime.liveExecution.SourceReader(),
				err:              ports.NewLiveSourceError(ports.LiveSourceUnsafe, errors.New("admitted file replaced by symlink")),
			})
			outcome := runtime.Invoke(context.Background(), job)
			cond, ok := outcome.Condition()
			if outcome.Succeeded() || !ok || cond != AttemptConditionSecurityViolation || outcome.diagnosticCause != domain.DiagnosticCauseLiveSourceUnsafe {
				t.Fatalf("real unsafe drift = cond:%q cause:%q, want security_violation/live_source_unsafe", cond, outcome.diagnosticCause)
			}
			if sink.rawPersistCalls != 0 {
				t.Fatalf("real unsafe drift persisted raw streams (%d)", sink.rawPersistCalls)
			}
		})
	}
}

func TestRequirementsRuntimeP5M3DiagnosticsAndCaptureAcrossPurposes(t *testing.T) {
	hasEvent := func(events []domain.RuntimeDiagnosticEventCode, want domain.RuntimeDiagnosticEventCode) bool {
		for _, e := range events {
			if e == want {
				return true
			}
		}
		return false
	}
	countEvents := func(events []domain.RuntimeDiagnosticEventCode, want domain.RuntimeDiagnosticEventCode) int {
		n := 0
		for _, e := range events {
			if e == want {
				n++
			}
		}
		return n
	}

	statusStates := func(status ports.RuntimeDiagnosticInvocationStatus) (domain.ParseState, domain.ValidationState) {
		_, p, v := status.States()
		return p, v
	}

	t.Run("pure prose skips parse/validation diagnostics and records ParseNotStarted/ValidationNotStarted", func(t *testing.T) {
		runtime, job, _, sink := requirementsRuntimeFixtureWithScopeAndSink(t, domain.LiveSourceWorkspace, []byte("# Prose review\n\nNo JSON.\n"))
		outcome := runtime.Invoke(context.Background(), job)
		if !outcome.Succeeded() {
			t.Fatal("pure prose failed")
		}
		for _, forbidden := range []domain.RuntimeDiagnosticEventCode{
			domain.DiagnosticOutputParseStarted,
			domain.DiagnosticValidationStarted,
			domain.DiagnosticOutputParsed,
			domain.DiagnosticValidationSucceeded,
			domain.DiagnosticValidationFailed,
		} {
			if hasEvent(sink.events, forbidden) {
				t.Fatalf("pure prose emitted %q: %v", forbidden, sink.events)
			}
		}
		if len(sink.statuses) != 1 {
			t.Fatalf("pure prose status count = %d, want 1", len(sink.statuses))
		}
		if p, v := statusStates(sink.statuses[0]); p != domain.ParseNotStarted || v != domain.ValidationNotStarted {
			t.Fatalf("pure prose invocation status = %s/%s, want not_started/not_started", p, v)
		}
		if sink.rawPersistCalls != 1 {
			t.Fatalf("pure prose rawPersistCalls = %d, want 1 (no double capture)", sink.rawPersistCalls)
		}
	})

	t.Run("valid initial emits parse/validation/discarded diagnostics and captures once", func(t *testing.T) {
		rawObj := map[string]any{
			"schema_version": validation.RequirementsProviderOutputVersion,
			"summary":        "Complete.",
			"completeness":   "complete",
			"limitations":    []string{},
			"findings":       []any{},
			"extra_top":      "discarded by findings projection",
			"requirements":   map[string]any{"schema_version": "mulgae-provider-requirements.v1", "assessments": []any{requirementsRuntimeRow("A")}},
		}
		raw, _ := json.Marshal(rawObj)
		runtime, job, _, sink := requirementsRuntimeFixtureWithScopeAndSink(t, domain.LiveSourceWorkspace, raw)
		outcome := runtime.Invoke(context.Background(), job)
		if !outcome.Succeeded() {
			t.Fatal("valid initial failed")
		}
		for _, want := range []domain.RuntimeDiagnosticEventCode{
			domain.DiagnosticOutputParseStarted,
			domain.DiagnosticValidationStarted,
			domain.DiagnosticOutputParsed,
			domain.DiagnosticProviderFieldsDiscarded,
			domain.DiagnosticValidationSucceeded,
		} {
			if !hasEvent(sink.events, want) {
				t.Fatalf("valid initial missing %q in %v", want, sink.events)
			}
		}
		if countEvents(sink.events, domain.DiagnosticValidationSucceeded)+countEvents(sink.events, domain.DiagnosticValidationFailed) != 1 {
			t.Fatalf("expected exactly one terminal validation event, got %v", sink.events)
		}
		if len(sink.statuses) != 1 {
			t.Fatalf("valid initial status count = %d, want 1", len(sink.statuses))
		}
		if p, v := statusStates(sink.statuses[0]); p != domain.ParseValid || v != domain.ValidationValid {
			t.Fatalf("valid initial invocation status = %s/%s, want valid/valid", p, v)
		}
		if sink.rawPersistCalls != 1 || string(sink.streams[domain.DiagnosticStdout]) != string(raw) {
			t.Fatalf("raw capture count=%d or stdout mismatch", sink.rawPersistCalls)
		}
	})

	t.Run("malformed initial emits OutputParseFailed and ValidationFailed then repair succeeded/failed", func(t *testing.T) {
		malformed := []byte(`{"schema_version":"mulgae-provider-review-output.v3","requirements":{`)
		repairedOK := requirementsRuntimeResponse([]any{}, requirementsRuntimeRow("A"))
		runtime, job, _, sink := requirementsRuntimeFixtureWithScopeAndSink(t, domain.LiveSourceWorkspace, malformed, repairedOK)
		first := runtime.Invoke(context.Background(), job)
		if first.Succeeded() {
			t.Fatal("malformed initial succeeded")
		}
		if !hasEvent(sink.events, domain.DiagnosticOutputParseFailed) || !hasEvent(sink.events, domain.DiagnosticValidationFailed) {
			t.Fatalf("malformed initial missing parse/validation failure events: %v", sink.events)
		}
		if len(sink.statuses) != 1 {
			t.Fatalf("malformed initial status count = %d, want 1", len(sink.statuses))
		}
		if p, v := statusStates(sink.statuses[0]); p != domain.ParseInvalidJSON || v != domain.ValidationInvalid {
			t.Fatalf("malformed initial invocation status = %s/%s, want invalid_json/invalid", p, v)
		}

		repairJob, err := newCoordinatorInvocationJob(job.SessionID(), job.RunID(), job.Role(), job.Route(), job.Target(), job.Limits(), job.AttemptID(), domain.InvocationRepair, 2)
		if err != nil {
			t.Fatal(err)
		}
		second := runtime.Invoke(context.Background(), repairJob)
		if !second.Succeeded() {
			t.Fatalf("succeeded repair failed: %+v", second)
		}
		if !hasEvent(sink.events, domain.DiagnosticRepairCompleted) {
			t.Fatalf("succeeded repair missing DiagnosticRepairCompleted: %v", sink.events)
		}
		if len(sink.statuses) != 2 {
			t.Fatalf("succeeded repair status count = %d, want 2", len(sink.statuses))
		}
		if p, v := statusStates(sink.statuses[1]); p != domain.ParseValid || v != domain.ValidationRepairedValid {
			t.Fatalf("succeeded repair invocation status = %s/%s, want valid/repaired_valid", p, v)
		}
		if len(runtime.pending) != 0 {
			t.Fatal("pending repair was not cleaned up")
		}
		if sink.rawPersistCalls != 2 {
			t.Fatalf("rawPersistCalls = %d, want 2 (1 initial + 1 repair)", sink.rawPersistCalls)
		}
	})

	t.Run("failed repair emits DiagnosticRepairExhausted and passes nil repaired candidate", func(t *testing.T) {
		malformed := []byte(`{"schema_version":"mulgae-provider-review-output.v3","requirements":{`)
		badRepair := []byte(`{"schema_version":"mulgae-provider-review-output.v3","findings":"still-bad","requirements":{"schema_version":"mulgae-provider-requirements.v1","assessments":[]}}`)
		runtime, job, _, sink := requirementsRuntimeFixtureWithScopeAndSink(t, domain.LiveSourceWorkspace, malformed, badRepair)
		if runtime.Invoke(context.Background(), job).Succeeded() {
			t.Fatal("malformed initial succeeded")
		}
		repairJob, _ := newCoordinatorInvocationJob(job.SessionID(), job.RunID(), job.Role(), job.Route(), job.Target(), job.Limits(), job.AttemptID(), domain.InvocationRepair, 2)
		second := runtime.Invoke(context.Background(), repairJob)
		if !second.Succeeded() {
			t.Fatalf("failed repair fallback did not preserve primary report: %+v", second)
		}
		if !hasEvent(sink.events, domain.DiagnosticRepairExhausted) {
			t.Fatalf("failed repair missing DiagnosticRepairExhausted: %v", sink.events)
		}
		if len(sink.statuses) != 2 {
			t.Fatalf("failed repair status count = %d, want 2", len(sink.statuses))
		}
		if p, v := statusStates(sink.statuses[1]); p != domain.ParseValid || v != domain.ValidationRepairExhausted {
			t.Fatalf("failed repair invocation status = %s/%s, want valid/repair_exhausted", p, v)
		}
		capRec, ok := runtime.Capture(job.AttemptID(), 2)
		if !ok {
			t.Fatal("failed repair was not captured")
		}
		for _, artifact := range capRec.Artifacts() {
			if artifact.Kind() == ports.AttemptArtifactRepairedCandidate {
				t.Fatal("failed repair created a repaired_candidate artifact")
			}
		}
		if sink.rawPersistCalls != 2 {
			t.Fatalf("failed repair rawPersistCalls = %d, want 2 (no double capture)", sink.rawPersistCalls)
		}
	})

	t.Run("extract hasPrior fallback captures raw streams and cleans up pendingExtraction", func(t *testing.T) {
		initial := requirementsRuntimeResponse([]any{})
		extractBad := requirementsRuntimeResponse("invalid findings", requirementsRuntimeRow("A"))
		runtime, job, _, sink := requirementsRuntimeFixtureWithScopeAndSink(t, domain.LiveSourceWorkspace, initial, extractBad)
		if !runtime.Invoke(context.Background(), job).Succeeded() {
			t.Fatal("initial failed")
		}
		if len(runtime.pendingExtraction) != 1 {
			t.Fatal("initial did not populate pendingExtraction")
		}
		extractJob, _ := newCoordinatorInvocationJob(job.SessionID(), job.RunID(), job.Role(), job.Route(), job.Target(), job.Limits(), job.AttemptID(), domain.InvocationExtract, 2)
		second := runtime.Invoke(context.Background(), extractJob)
		if !second.Succeeded() {
			t.Fatalf("extract fallback failed: %+v", second)
		}
		if len(runtime.pendingExtraction) != 0 {
			t.Fatal("extract did not clean up pendingExtraction")
		}
		if sink.rawPersistCalls != 2 {
			t.Fatalf("extract hasPrior fallback rawPersistCalls = %d, want 2", sink.rawPersistCalls)
		}
		if string(sink.streams[domain.DiagnosticStdout]) != string(extractBad) {
			t.Fatal("extract hasPrior fallback did not capture raw stdout")
		}
		capRec, ok := runtime.Capture(job.AttemptID(), 2)
		if !ok || len(capRec.Artifacts()) == 0 {
			t.Fatal("extract hasPrior fallback missing AttemptCapture")
		}
		if len(sink.statuses) != 2 {
			t.Fatalf("extract fallback status count = %d, want 2", len(sink.statuses))
		}
		if p, v := statusStates(sink.statuses[1]); p != domain.ParseValid || v != domain.ValidationInvalid {
			t.Fatalf("extract fallback invocation status = %s/%s, want valid/invalid", p, v)
		}
	})

	t.Run("protected acceptExtraction failure runs capture reject=true and cleans up pendingExtraction", func(t *testing.T) {
		finding := map[string]any{
			"severity": "high", "title": "Observed defect", "description": "Defect in source.go.",
			"evidence":       []any{map[string]any{"current": map[string]any{"path": "source.go", "side": "worktree", "line_start": 1, "line_end": 1, "quote": "observed\n"}}},
			"recommendation": "Fix it.", "confidence": "high",
		}
		initial := []byte("# Prose report\n\nObserved defect in source.go.\n")
		extractResp := requirementsRuntimeResponse([]any{finding})
		runtime, job, _, sink := requirementsRuntimeFixtureWithScopeAndSink(t, domain.LiveSourceWorkspace, initial, extractResp)
		if !runtime.Invoke(context.Background(), job).Succeeded() {
			t.Fatal("initial prose failed")
		}
		// Inject real source drift (unmarked LiveSourceUnsafe) during extraction findings verification.
		runtime.verifier, _ = evidence.NewLiveVerifier(requirementsFaultReader{
			LiveSourceReader: runtime.liveExecution.SourceReader(),
			err:              ports.NewLiveSourceError(ports.LiveSourceUnsafe, errors.New("root replaced")),
		})
		extractJob, _ := newCoordinatorInvocationJob(job.SessionID(), job.RunID(), job.Role(), job.Route(), job.Target(), job.Limits(), job.AttemptID(), domain.InvocationExtract, 2)
		second := runtime.Invoke(context.Background(), extractJob)
		cond, ok := second.Condition()
		if second.Succeeded() || !ok || cond != AttemptConditionSecurityViolation || second.diagnosticCause != domain.DiagnosticCauseLiveSourceUnsafe {
			t.Fatalf("protected acceptExtraction = cond:%q cause:%q, want security_violation/live_source_unsafe", cond, second.diagnosticCause)
		}
		if len(runtime.pendingExtraction) != 0 {
			t.Fatal("protected acceptExtraction did not clean up pendingExtraction")
		}
		// Only initial persisted raw; extraction was security-rejected so rawPersistCalls must stay 1.
		if sink.rawPersistCalls != 1 {
			t.Fatalf("protected acceptExtraction leaked raw streams: rawPersistCalls=%d, want 1", sink.rawPersistCalls)
		}
		capRec, captured := runtime.Capture(job.AttemptID(), 2)
		if !captured || len(capRec.Artifacts()) == 0 {
			t.Fatal("protected acceptExtraction missing security-rejected capture markers")
		}
		for _, artifact := range capRec.Artifacts() {
			if !artifact.SecurityRejected() || len(artifact.Bytes()) != 0 {
				t.Fatalf("protected acceptExtraction artifact not security-rejected: %+v", artifact)
			}
		}
	})

	t.Run("initial quote mismatch fallback clears pending repair and records ValidationInvalid/ValidationFailed", func(t *testing.T) {
		mismatchFinding := map[string]any{
			"severity": "high", "title": "Quote mismatch", "description": "Quote differs from source.go.",
			"evidence":       []any{map[string]any{"current": map[string]any{"path": "source.go", "side": "worktree", "line_start": 1, "line_end": 1, "quote": "wrong quote\n"}}},
			"recommendation": "Fix quote.", "confidence": "high",
		}
		raw := requirementsRuntimeResponse([]any{mismatchFinding}, requirementsRuntimeRow("A"))
		runtime, job, _, sink := requirementsRuntimeFixtureWithScopeAndSink(t, domain.LiveSourceWorkspace, raw)
		outcome := runtime.Invoke(context.Background(), job)
		if !outcome.Succeeded() {
			t.Fatalf("initial quote mismatch fallback failed: %+v", outcome)
		}
		out, _ := outcome.Output()
		if !out.ReportsOnly() {
			t.Fatal("initial quote mismatch did not fall back to reports_only")
		}
		if len(runtime.pending) != 0 {
			t.Fatalf("initial quote mismatch leaked runtime.pending (%d entries)", len(runtime.pending))
		}
		if hasEvent(sink.events, domain.DiagnosticValidationSucceeded) {
			t.Fatalf("initial quote mismatch falsely emitted DiagnosticValidationSucceeded: %v", sink.events)
		}
		if !hasEvent(sink.events, domain.DiagnosticValidationFailed) {
			t.Fatalf("initial quote mismatch missing DiagnosticValidationFailed: %v", sink.events)
		}
		if len(sink.statuses) != 1 {
			t.Fatalf("status count = %d, want 1", len(sink.statuses))
		}
		if p, v := statusStates(sink.statuses[0]); p != domain.ParseValid || v != domain.ValidationInvalid {
			t.Fatalf("initial quote mismatch status = %s/%s, want valid/invalid", p, v)
		}
	})

	t.Run("repair bounded evidence failure fallback records ValidationRepairExhausted without DiagnosticRepairCompleted", func(t *testing.T) {
		malformed := []byte(`{"schema_version":"mulgae-provider-review-output.v3","requirements":{`)
		mismatchFinding := map[string]any{
			"severity": "high", "title": "Quote mismatch", "description": "Quote differs from source.go.",
			"evidence":       []any{map[string]any{"current": map[string]any{"path": "source.go", "side": "worktree", "line_start": 1, "line_end": 1, "quote": "wrong quote\n"}}},
			"recommendation": "Fix quote.", "confidence": "high",
		}
		repairResp := requirementsRuntimeResponse([]any{mismatchFinding}, requirementsRuntimeRow("A"))
		runtime, job, _, sink := requirementsRuntimeFixtureWithScopeAndSink(t, domain.LiveSourceWorkspace, malformed, repairResp)
		if runtime.Invoke(context.Background(), job).Succeeded() {
			t.Fatal("malformed initial succeeded")
		}
		repairJob, _ := newCoordinatorInvocationJob(job.SessionID(), job.RunID(), job.Role(), job.Route(), job.Target(), job.Limits(), job.AttemptID(), domain.InvocationRepair, 2)
		second := runtime.Invoke(context.Background(), repairJob)
		if !second.Succeeded() {
			t.Fatalf("repair bounded evidence fallback failed: %+v", second)
		}
		if len(runtime.pending) != 0 {
			t.Fatalf("repair bounded evidence failure leaked runtime.pending (%d entries)", len(runtime.pending))
		}
		if hasEvent(sink.events, domain.DiagnosticValidationSucceeded) || hasEvent(sink.events, domain.DiagnosticRepairCompleted) {
			t.Fatalf("repair bounded evidence fallback falsely emitted success/repair_completed: %v", sink.events)
		}
		if !hasEvent(sink.events, domain.DiagnosticRepairExhausted) {
			t.Fatalf("repair bounded evidence fallback missing DiagnosticRepairExhausted: %v", sink.events)
		}
		if len(sink.statuses) != 2 {
			t.Fatalf("status count = %d, want 2", len(sink.statuses))
		}
		if p, v := statusStates(sink.statuses[1]); p != domain.ParseValid || v != domain.ValidationRepairExhausted {
			t.Fatalf("repair bounded evidence status = %s/%s, want valid/repair_exhausted", p, v)
		}
	})
}

func requirementsRuntimeOmittedFindingsResponse(rows ...map[string]any) []byte {
	object := map[string]any{
		"schema_version": validation.RequirementsProviderOutputVersion,
		"summary":        "Transcribed verified requirements; findings omitted due to missing verbatim excerpt.",
		"completeness":   "complete",
		"limitations":    []string{},
	}
	if rows != nil {
		object["requirements"] = map[string]any{"schema_version": "mulgae-provider-requirements.v1", "assessments": rows}
	}
	raw, _ := json.Marshal(object)
	return raw
}

func TestRequirementsRuntimeOmittedFindingsExtractionSeam(t *testing.T) {
	hasCandidateArtifact := func(capRec AttemptCapture) bool {
		for _, a := range capRec.Artifacts() {
			switch a.Kind() {
			case ports.AttemptArtifactInitialCandidate, ports.AttemptArtifactExtractedCandidate, ports.AttemptArtifactRepairedCandidate, ports.AttemptArtifactRetryCandidate:
				return true
			}
		}
		return false
	}

	t.Run("extract omitting findings retains verified requirements and keeps reports_only without false no_findings", func(t *testing.T) {
		report := []byte("# Logic review\n\nHigh defect claimed in source.go without verbatim excerpt.\n")
		extractResp := requirementsRuntimeOmittedFindingsResponse(requirementsRuntimeRow("A"))
		runtime, job, _, sink := requirementsRuntimeFixtureWithScopeAndSink(t, domain.LiveSourceWorkspace, report, extractResp)
		first := runtime.Invoke(context.Background(), job)
		if !first.Succeeded() {
			t.Fatalf("initial prose failed: %+v", first)
		}
		extractJob, err := newCoordinatorInvocationJob(job.SessionID(), job.RunID(), job.Role(), job.Route(), job.Target(), job.Limits(), job.AttemptID(), domain.InvocationExtract, 2)
		if err != nil {
			t.Fatal(err)
		}
		second := runtime.Invoke(context.Background(), extractJob)
		out, ok := second.Output()
		if !second.Succeeded() || !ok || !out.ReportsOnly() || string(out.ReportMarkdown()) != string(report) {
			t.Fatalf("omitted-findings extract did not stay reports_only with original report: %+v", second)
		}
		if len(runtime.pendingExtraction) != 0 || len(runtime.pending) != 0 {
			t.Fatalf("omitted-findings extract leaked pending state: extract=%d repair=%d", len(runtime.pendingExtraction), len(runtime.pending))
		}
		capRec, captured := runtime.Capture(job.AttemptID(), 2)
		if !captured || hasCandidateArtifact(capRec) {
			t.Fatalf("omitted-findings extract unexpectedly created candidate artifact: captured=%t artifacts=%+v", captured, capRec.Artifacts())
		}
		if sink.rawPersistCalls != 2 || string(sink.streams[domain.DiagnosticStdout]) != string(extractResp) {
			t.Fatalf("omitted-findings extract did not preserve complete stdout.raw (calls=%d)", sink.rawPersistCalls)
		}
		result, err := runtime.RequirementsResult(true)
		if err != nil {
			t.Fatal(err)
		}
		selected, evaluated, _ := result.Evaluation().Counts()
		rows := result.Evaluation().Assessments()
		if selected != 3 || evaluated != 1 || rows[0].Origin() != domain.AssessmentProvider || rows[0].Verdict() != domain.RequirementMet || rows[1].Reason() != domain.AssessmentAnswerOmitted || rows[2].Reason() != domain.AssessmentAnswerOmitted {
			t.Fatalf("verified requirements lost on omitted-findings extract: %+v", result.Evaluation())
		}
		if _, hasNorm := runtime.NormalizedRequirementsOutput(job.Role()); hasNorm {
			t.Fatal("reports_only role fabricated NormalizedRequirementsOutput")
		}
	})

	t.Run("extract omitting findings after assessmentPending preserves prior verified findings and merges requirements", func(t *testing.T) {
		finding := map[string]any{
			"severity": "high", "title": "Initial defect", "description": "Verified in initial.",
			"evidence":       []any{map[string]any{"current": map[string]any{"path": "source.go", "side": "worktree", "line_start": 1, "line_end": 1, "quote": "observed\n"}}},
			"recommendation": "Fix it.", "confidence": "high",
		}
		initial := requirementsRuntimeResponse([]any{finding})
		extractResp := requirementsRuntimeOmittedFindingsResponse(requirementsRuntimeRow("B"), requirementsRuntimeRow("A"))
		runtime, job, _, _ := requirementsRuntimeFixtureWithScopeAndSink(t, domain.LiveSourceWorkspace, initial, extractResp)
		first := runtime.Invoke(context.Background(), job)
		prior, ok := first.Output()
		if !first.Succeeded() || !ok || prior.ReportsOnly() || !prior.assessmentPending || len(prior.Findings()) != 1 {
			t.Fatalf("initial findings with absent requirements unexpected: %+v", first)
		}
		extractJob, _ := newCoordinatorInvocationJob(job.SessionID(), job.RunID(), job.Role(), job.Route(), job.Target(), job.Limits(), job.AttemptID(), domain.InvocationExtract, 2)
		second := runtime.Invoke(context.Background(), extractJob)
		out, ok := second.Output()
		if !second.Succeeded() || !ok || out.ReportsOnly() || out.assessmentPending || len(out.Findings()) != 1 {
			t.Fatalf("omitted-findings extract lost prior verified findings: %+v", second)
		}
		capRec, captured := runtime.Capture(job.AttemptID(), 2)
		if !captured || hasCandidateArtifact(capRec) {
			t.Fatalf("omitted-findings extract created candidate artifact: captured=%t artifacts=%+v", captured, capRec.Artifacts())
		}
		normOut, hasNorm := runtime.NormalizedRequirementsOutput(job.Role())
		if !hasNorm {
			t.Fatal("expected NormalizedRequirementsOutput after resolving pending requirements with prior findings")
		}
		normBytes, err := normOut.Bytes()
		if err != nil {
			t.Fatal(err)
		}
		var doc struct {
			Requirements struct {
				Assessments []struct {
					ID string `json:"requirement_id"`
				} `json:"assessments"`
			} `json:"requirements"`
		}
		if err := json.Unmarshal(normBytes, &doc); err != nil {
			t.Fatal(err)
		}
		if len(doc.Requirements.Assessments) != 2 || doc.Requirements.Assessments[0].ID != "A" || doc.Requirements.Assessments[1].ID != "B" {
			t.Fatalf("NormalizedRequirementsOutput ordering not input-ordered: %+v", doc.Requirements.Assessments)
		}
	})

	t.Run("initial omitting findings stays reports_only with nil candidate and preserves verified requirements", func(t *testing.T) {
		initial := requirementsRuntimeOmittedFindingsResponse(requirementsRuntimeRow("A"))
		runtime, job, _, sink := requirementsRuntimeFixtureWithScopeAndSink(t, domain.LiveSourceWorkspace, initial)
		first := runtime.Invoke(context.Background(), job)
		out, ok := first.Output()
		if !first.Succeeded() || !ok || !out.ReportsOnly() {
			t.Fatalf("initial omitted-findings did not fall back to reports_only: %+v", first)
		}
		if len(runtime.pending) != 0 {
			t.Fatalf("initial omitted-findings leaked repair plan: %d", len(runtime.pending))
		}
		capRec, captured := runtime.Capture(job.AttemptID(), 1)
		if !captured || hasCandidateArtifact(capRec) {
			t.Fatalf("initial omitted-findings created candidate artifact: captured=%t artifacts=%+v", captured, capRec.Artifacts())
		}
		if sink.rawPersistCalls != 1 {
			t.Fatalf("initial omitted-findings rawPersistCalls = %d, want 1", sink.rawPersistCalls)
		}
		result, err := runtime.RequirementsResult(false)
		if err != nil {
			t.Fatal(err)
		}
		if _, evaluated, _ := result.Evaluation().Counts(); evaluated != 1 {
			t.Fatalf("initial omitted-findings lost verified requirement: %+v", result.Evaluation())
		}
	})

	t.Run("omitted findings still runs validator unconditionally and fails closed on protected validator errors", func(t *testing.T) {
		raw := requirementsRuntimeOmittedFindingsResponse(requirementsRuntimeRow("A"))
		runtime, job, _, _ := requirementsRuntimeFixtureWithScopeAndSink(t, domain.LiveSourceWorkspace, raw)
		id, _ := ports.ParseAssetID(validation.ProviderReviewSchemaID)
		runtime.validator, _ = validation.NewReviewValidator(requirementsFaultSchema{requirementsInfrastructureDiagnostic{}}, id)
		outcome := runtime.Invoke(context.Background(), job)
		cond, ok := outcome.Condition()
		if outcome.Succeeded() || !ok || cond != AttemptConditionInternalInvariant {
			t.Fatalf("protected validator error under omitted findings = cond:%q ok:%t, want internal_invariant", cond, ok)
		}
	})

	t.Run("omitted findings fails closed when validator is misconfigured or scope is invalid", func(t *testing.T) {
		raw := requirementsRuntimeOmittedFindingsResponse(requirementsRuntimeRow("A"))

		// 1. Misconfigured ReviewValidator (&validation.ReviewValidator{}) via runtime.Invoke.
		runtime, job, _, _ := requirementsRuntimeFixtureWithScopeAndSink(t, domain.LiveSourceWorkspace, raw)
		runtime.validator = &validation.ReviewValidator{}
		outcome := runtime.Invoke(context.Background(), job)
		cond, ok := outcome.Condition()
		if outcome.Succeeded() || !ok || cond != AttemptConditionInternalInvariant {
			t.Fatalf("misconfigured validator under omitted findings = cond:%q ok:%t, want internal_invariant", cond, ok)
		}

		// 2. Invalid scope.Role via invokeRequirements.
		rtInvalidRole, jobRole, _, _ := requirementsRuntimeFixtureWithScopeAndSink(t, domain.LiveSourceWorkspace, raw)
		badRoleScope := validation.ReviewValidationScope{
			LiveSource:       rtInvalidRole.liveIdentity,
			Role:             domain.Role("invalid_role"),
			ProviderInstance: jobRole.Route().ProviderInstance(),
		}
		outRole, _, _ := rtInvalidRole.invokeRequirements(context.Background(), jobRole, raw, raw, raw, nil, ports.ProviderOutputTransportStdout, badRoleScope)
		cond, ok = outRole.Condition()
		if outRole.Succeeded() || !ok || cond != AttemptConditionInternalInvariant {
			t.Fatalf("invalid scope.Role under omitted findings = cond:%q ok:%t, want internal_invariant", cond, ok)
		}

		// 3. Unsupported scope.SourceBearing == true via invokeRequirements.
		rtSourceBearing, jobSB, _, _ := requirementsRuntimeFixtureWithScopeAndSink(t, domain.LiveSourceWorkspace, raw)
		sourceBearingScope := validation.ReviewValidationScope{
			LiveSource:       rtSourceBearing.liveIdentity,
			Role:             jobSB.Role(),
			ProviderInstance: jobSB.Route().ProviderInstance(),
			SourceBearing:    true,
		}
		outSB, _, _ := rtSourceBearing.invokeRequirements(context.Background(), jobSB, raw, raw, raw, nil, ports.ProviderOutputTransportStdout, sourceBearingScope)
		cond, ok = outSB.Condition()
		if outSB.Succeeded() || !ok || cond != AttemptConditionInternalInvariant {
			t.Fatalf("scope.SourceBearing under omitted findings = cond:%q ok:%t, want internal_invariant", cond, ok)
		}

		// 4. Nil verifier decode authority in DecodeProviderRequirements fails closed as protected InternalInvariant.
		rtNilVerifier, jobNV, _, _ := requirementsRuntimeFixtureWithScopeAndSink(t, domain.LiveSourceWorkspace, raw)
		rtNilVerifier.verifier = nil
		outNV := rtNilVerifier.Invoke(context.Background(), jobNV)
		cond, ok = outNV.Condition()
		if outNV.Succeeded() || !ok || cond != AttemptConditionInternalInvariant {
			t.Fatalf("nil verifier decode authority = cond:%q ok:%t, want internal_invariant", cond, ok)
		}
	})
}

func TestRequirementsRuntimePerItemIsolationOptionAAndMonotoneMerge(t *testing.T) {
	badRow := func(id string) map[string]any {
		r := requirementsRuntimeRow(id)
		r["evidence"].([]any)[0].(map[string]any)["current"].(map[string]any)["quote"] = "mismatched\n"
		return r
	}
	unverifiedRow := func(id string) map[string]any {
		r := requirementsRuntimeRow(id)
		r["verdict"] = "unverified"
		r["reason"] = "insufficient_evidence"
		r["evidence"] = []any{}
		return r
	}
	verdictRow := func(id, verdict string) map[string]any {
		r := requirementsRuntimeRow(id)
		r["verdict"] = verdict
		return r
	}

	t.Run("per-item isolation yields A=provider B=invalid_assessment C=answer_omitted, triggers Option A assessmentPending, and emits ValidationFailed", func(t *testing.T) {
		initial := requirementsRuntimeResponse([]any{}, requirementsRuntimeRow("A"), badRow("B"))
		runtime, job, _, sink := requirementsRuntimeFixtureWithScopeAndSink(t, domain.LiveSourceWorkspace, initial)
		first := runtime.Invoke(context.Background(), job)
		out, ok := first.Output()
		if !first.Succeeded() || !ok || out.ReportsOnly() || !out.assessmentPending {
			t.Fatalf("partial-invalid initial = succeeded:%t reportsOnly:%t assessmentPending:%t, want true/false/true", first.Succeeded(), out.ReportsOnly(), out.assessmentPending)
		}
		if _, hasNorm := runtime.NormalizedRequirementsOutput(job.Role()); hasNorm {
			t.Fatal("partial-invalid initial falsely populated NormalizedRequirementsOutput")
		}
		var sawFailed, sawSucceeded bool
		for _, ev := range sink.events {
			if ev == domain.DiagnosticValidationFailed {
				sawFailed = true
			}
			if ev == domain.DiagnosticValidationSucceeded {
				sawSucceeded = true
			}
		}
		if !sawFailed || sawSucceeded {
			t.Fatalf("partial-invalid diagnostics = failed:%t succeeded:%t, want true/false (events=%v)", sawFailed, sawSucceeded, sink.events)
		}
		if _, p, v := sink.statuses[0].States(); p != domain.ParseValid || v != domain.ValidationInvalid {
			t.Fatalf("partial-invalid status = %s/%s, want valid/invalid", p, v)
		}
		result, err := runtime.RequirementsResult(false)
		if err != nil {
			t.Fatal(err)
		}
		rows := result.Evaluation().Assessments()
		if rows[0].Origin() != domain.AssessmentProvider || rows[0].Verdict() != domain.RequirementMet {
			t.Fatalf("row A = %+v, want provider/met", rows[0])
		}
		if rows[1].Origin() != domain.AssessmentDerived || rows[1].Reason() != domain.AssessmentInvalidContent {
			t.Fatalf("row B = %+v, want derived/invalid_assessment", rows[1])
		}
		if rows[2].Origin() != domain.AssessmentDerived || rows[2].Reason() != domain.AssessmentAnswerOmitted {
			t.Fatalf("row C = %+v, want derived/answer_omitted", rows[2])
		}
	})

	t.Run("valid initial with clean omissions keeps assessmentPending=false (1-call preservation)", func(t *testing.T) {
		initial := requirementsRuntimeResponse([]any{}, requirementsRuntimeRow("A"))
		runtime, job, _, _ := requirementsRuntimeFixtureWithScopeAndSink(t, domain.LiveSourceWorkspace, initial)
		first := runtime.Invoke(context.Background(), job)
		out, ok := first.Output()
		if !first.Succeeded() || !ok || out.assessmentPending {
			t.Fatalf("clean omissions set assessmentPending=%t, want false", out.assessmentPending)
		}
		if _, hasNorm := runtime.NormalizedRequirementsOutput(job.Role()); !hasNorm {
			t.Fatal("clean omissions did not populate NormalizedRequirementsOutput")
		}
	})

	t.Run("section-invalid initial sets assessmentPending=true and extract can recover", func(t *testing.T) {
		initial := requirementsRuntimeResponse([]any{}, requirementsRuntimeRow("A"), requirementsRuntimeRow("A"))
		extractResp := requirementsRuntimeResponse([]any{}, requirementsRuntimeRow("A"), badRow("B"))
		runtime, job, _, _ := requirementsRuntimeFixtureWithScopeAndSink(t, domain.LiveSourceWorkspace, initial, extractResp)
		first := runtime.Invoke(context.Background(), job)
		out, ok := first.Output()
		if !first.Succeeded() || !ok || !out.assessmentPending {
			t.Fatalf("section-invalid initial assessmentPending=%t, want true", out.assessmentPending)
		}
		extractJob, _ := newCoordinatorInvocationJob(job.SessionID(), job.RunID(), job.Role(), job.Route(), job.Target(), job.Limits(), job.AttemptID(), domain.InvocationExtract, 2)
		second := runtime.Invoke(context.Background(), extractJob)
		if !second.Succeeded() {
			t.Fatalf("extract recovery failed: %+v", second)
		}
		result, err := runtime.RequirementsResult(true)
		if err != nil {
			t.Fatal(err)
		}
		rows := result.Evaluation().Assessments()
		if rows[0].Origin() != domain.AssessmentProvider || rows[1].Reason() != domain.AssessmentInvalidContent || rows[2].Reason() != domain.AssessmentAnswerOmitted {
			t.Fatalf("recovered rows = %+v", rows)
		}
	})

	t.Run("monotone merge preserves decisive rows, upgrades provider unverified, clears resolved invalidIDs, and keeps deterministic input order", func(t *testing.T) {
		// Initial: C=met (decisive), A=unverified (provider), B=invalid.
		initial := requirementsRuntimeResponse([]any{}, verdictRow("C", "met"), unverifiedRow("A"), badRow("B"))
		// Extract: tries to downgrade C to unverified, upgrades A to partially_met, fixes B to unmet.
		extractResp := requirementsRuntimeResponse([]any{}, unverifiedRow("C"), verdictRow("B", "unmet"), verdictRow("A", "partially_met"))
		runtime, job, _, _ := requirementsRuntimeFixtureWithScopeAndSink(t, domain.LiveSourceWorkspace, initial, extractResp)
		first := runtime.Invoke(context.Background(), job)
		out, _ := first.Output()
		if !first.Succeeded() || !out.assessmentPending {
			t.Fatalf("initial partial failed or missed assessmentPending: %+v", first)
		}
		extractJob, _ := newCoordinatorInvocationJob(job.SessionID(), job.RunID(), job.Role(), job.Route(), job.Target(), job.Limits(), job.AttemptID(), domain.InvocationExtract, 2)
		second := runtime.Invoke(context.Background(), extractJob)
		if !second.Succeeded() {
			t.Fatalf("extract merge failed: %+v", second)
		}
		result, err := runtime.RequirementsResult(true)
		if err != nil {
			t.Fatal(err)
		}
		rows := result.Evaluation().Assessments()
		if rows[0].Verdict() != domain.RequirementPartiallyMet || rows[1].Verdict() != domain.RequirementUnmet || rows[2].Verdict() != domain.RequirementMet {
			t.Fatalf("monotone verdicts wrong: A=%s B=%s C=%s", rows[0].Verdict(), rows[1].Verdict(), rows[2].Verdict())
		}
		normOut, ok := runtime.NormalizedRequirementsOutput(job.Role())
		if !ok {
			t.Fatal("expected NormalizedRequirementsOutput after all invalidIDs resolved")
		}
		normBytes, err := normOut.Bytes()
		if err != nil {
			t.Fatal(err)
		}
		var doc struct {
			Requirements struct {
				Assessments []struct {
					ID      string `json:"requirement_id"`
					Verdict string `json:"verdict"`
				} `json:"assessments"`
			} `json:"requirements"`
		}
		if err := json.Unmarshal(normBytes, &doc); err != nil {
			t.Fatal(err)
		}
		if len(doc.Requirements.Assessments) != 3 ||
			doc.Requirements.Assessments[0].ID != "A" || doc.Requirements.Assessments[0].Verdict != "partially_met" ||
			doc.Requirements.Assessments[1].ID != "B" || doc.Requirements.Assessments[1].Verdict != "unmet" ||
			doc.Requirements.Assessments[2].ID != "C" || doc.Requirements.Assessments[2].Verdict != "met" {
			t.Fatalf("NormalizedRequirementsOutput order/verdicts wrong: %+v", doc.Requirements.Assessments)
		}
	})

	t.Run("monotone merge never overwrites decisive row with different decisive verdict or invalid row", func(t *testing.T) {
		initial := requirementsRuntimeResponse([]any{}, verdictRow("A", "met"), verdictRow("C", "partially_met"), badRow("B"))
		extractResp := requirementsRuntimeResponse([]any{}, badRow("A"), verdictRow("C", "unmet"), verdictRow("B", "partially_met"))
		runtime, job, _, _ := requirementsRuntimeFixtureWithScopeAndSink(t, domain.LiveSourceWorkspace, initial, extractResp)
		if !runtime.Invoke(context.Background(), job).Succeeded() {
			t.Fatal("initial failed")
		}
		extractJob, _ := newCoordinatorInvocationJob(job.SessionID(), job.RunID(), job.Role(), job.Route(), job.Target(), job.Limits(), job.AttemptID(), domain.InvocationExtract, 2)
		if !runtime.Invoke(context.Background(), extractJob).Succeeded() {
			t.Fatal("extract failed")
		}
		result, err := runtime.RequirementsResult(true)
		if err != nil {
			t.Fatal(err)
		}
		rows := result.Evaluation().Assessments()
		if rows[0].Origin() != domain.AssessmentProvider || rows[0].Verdict() != domain.RequirementMet ||
			rows[1].Origin() != domain.AssessmentProvider || rows[1].Verdict() != domain.RequirementPartiallyMet ||
			rows[2].Origin() != domain.AssessmentProvider || rows[2].Verdict() != domain.RequirementPartiallyMet {
			t.Fatalf("extract overwrote prior decisive rows (want A=met, B=partially_met, C=partially_met): %+v", rows)
		}
	})

	t.Run("initial partial valid survives extract section-wide failure, wrong version, malformed JSON, and absent section untouched", func(t *testing.T) {
		for _, tc := range []struct {
			name    string
			extract []byte
		}{
			{"section-wide duplicate IDs", requirementsRuntimeResponse([]any{}, requirementsRuntimeRow("A"), requirementsRuntimeRow("A"))},
			{"wrong schema_version with requirements", []byte(`{"schema_version":"mulgae-provider-review-output.v1","requirements":{"schema_version":"mulgae-provider-requirements.v1","assessments":[]}}`)},
			{"malformed JSON", []byte(`{"schema_version":"mulgae-provider-review-output.v3","requirements":{`)},
			{"absent requirements section", requirementsRuntimeResponse([]any{})},
			{"pure prose refusal", []byte("Cannot transcribe findings without verbatim excerpts.")},
		} {
			t.Run(tc.name, func(t *testing.T) {
				initial := requirementsRuntimeResponse([]any{}, requirementsRuntimeRow("A"), badRow("B"))
				runtime, job, _, _ := requirementsRuntimeFixtureWithScopeAndSink(t, domain.LiveSourceWorkspace, initial, tc.extract)
				if !runtime.Invoke(context.Background(), job).Succeeded() {
					t.Fatal("initial failed")
				}
				extractJob, _ := newCoordinatorInvocationJob(job.SessionID(), job.RunID(), job.Role(), job.Route(), job.Target(), job.Limits(), job.AttemptID(), domain.InvocationExtract, 2)
				if !runtime.Invoke(context.Background(), extractJob).Succeeded() {
					t.Fatalf("extract fallback failed: %s", tc.name)
				}
				result, err := runtime.RequirementsResult(true)
				if err != nil {
					t.Fatal(err)
				}
				rows := result.Evaluation().Assessments()
				if rows[0].Origin() != domain.AssessmentProvider || rows[0].Verdict() != domain.RequirementMet {
					t.Fatalf("%s erased accepted row A: %+v", tc.name, rows[0])
				}
				if rows[1].Origin() != domain.AssessmentDerived || rows[1].Reason() != domain.AssessmentInvalidContent {
					t.Fatalf("%s changed invalid row B: %+v", tc.name, rows[1])
				}
				if rows[2].Origin() != domain.AssessmentDerived || rows[2].Reason() != domain.AssessmentAnswerOmitted {
					t.Fatalf("%s flipped clean omission C to %q", tc.name, rows[2].Reason())
				}
			})
		}
	})

	t.Run("initial section-invalid stays section-invalid when extract omits requirements", func(t *testing.T) {
		initial := requirementsRuntimeResponse([]any{}, requirementsRuntimeRow("A"), requirementsRuntimeRow("A"))
		extractResp := requirementsRuntimeResponse([]any{})
		runtime, job, _, _ := requirementsRuntimeFixtureWithScopeAndSink(t, domain.LiveSourceWorkspace, initial, extractResp)
		if !runtime.Invoke(context.Background(), job).Succeeded() {
			t.Fatal("initial failed")
		}
		extractJob, _ := newCoordinatorInvocationJob(job.SessionID(), job.RunID(), job.Role(), job.Route(), job.Target(), job.Limits(), job.AttemptID(), domain.InvocationExtract, 2)
		if !runtime.Invoke(context.Background(), extractJob).Succeeded() {
			t.Fatal("extract failed")
		}
		result, err := runtime.RequirementsResult(true)
		if err != nil {
			t.Fatal(err)
		}
		for i, row := range result.Evaluation().Assessments() {
			if row.Reason() != domain.AssessmentInvalidContent {
				t.Fatalf("row %d reason = %q, want invalid_assessment", i, row.Reason())
			}
		}
	})
}

func nonRequirementsLiveFixture(t *testing.T, responses ...[]byte) (*ProviderInvocationRuntime, InvocationJob, *recordingObservedProvider) {
	t.Helper()
	selector, _ := ports.NewLiveSourceSelector(domain.LiveSourceWorkspace, "")
	path, _ := ports.NewSafeRelativePath("source.go")
	target, _ := ports.NewLiveSourceTarget(selector, ports.GitObjectID{}, ports.GitObjectID{}, false, []ports.LiveSourceChange{{Kind: "included", After: path}})
	root, _ := ports.NewAnchoredRoot("/source")
	neutral, _ := ports.NewAnchoredRoot("/neutral")
	credential, _ := ports.NewAnchoredRoot("/credentials")
	reader := &runtimeLiveReader{coordinatorLiveReader: coordinatorLiveReader{target}, binding: ports.ProjectBindingObservation{Root: root, RootIdentity: ports.ProjectDirectoryIdentity{Device: 1, Inode: 2}}}
	execution, err := ports.NewLiveReviewExecution(context.Background(), reader, runtimeLiveHome{root: neutral}, []ports.AnchoredRoot{credential})
	if err != nil {
		t.Fatal(err)
	}
	identity, _ := evidence.NewLiveSourceIdentity(target)
	_, job, material := providerRuntimeExplicitFixture(t, nil)
	job.target, _ = identity.RunTarget()
	compiler, _ := prompt.NewCompiler(material.Prompt.TrustedTemplate(), explicitRuntimeTestIssuer{source: material.Prompt.Scope().SourceInvocationID(), execution: material.Prompt.Scope().ExecutionInvocationID()})
	material.Target = identity.Bytes()
	material.Prompt, err = compiler.Compile(prompt.CompileInput{Scope: material.Prompt.Scope().FrameScope().Coordinates(), ReviewTarget: prompt.NewPayload(material.Target)})
	if err != nil {
		t.Fatal(err)
	}
	provider := &recordingObservedProvider{t: t}
	for _, raw := range responses {
		provider.responses = append(provider.responses, providerRuntimeObservation{stdout: raw})
	}
	runtime, err := NewObservedProviderInvocationRuntimeInLiveSource(provider, requirementsTestPrompts{explicitRuntimePromptSource{material}}, execution, newReviewValidator(t), providerRuntimeDiagnosticResolver{runID: job.RunID(), sink: &providerRuntimeRawSink{}})
	if err != nil {
		t.Fatal(err)
	}
	return runtime, job, provider
}

func TestNonRequirementsExtractionPlainTextRefusalPreservesReportsOnlyAndAllOrNothingFindings(t *testing.T) {
	t.Run("plain-text refusal keeps reports_only without fabricating no_findings", func(t *testing.T) {
		report := []byte("# Logic review\n\nHigh-severity defect in source.go without verbatim target excerpt.\n")
		refusal := []byte("Refusing structured transcription: claimed defect lacks an exact verbatim target excerpt in the accepted report.")
		runtime, job, provider := nonRequirementsLiveFixture(t, report, refusal)
		first := runtime.Invoke(context.Background(), job)
		prior, ok := first.Output()
		if !first.Succeeded() || !ok || !prior.ReportsOnly() {
			t.Fatalf("initial report failed: %+v", first)
		}
		extractJob, err := newCoordinatorInvocationJob(job.SessionID(), job.RunID(), job.Role(), job.Route(), job.Target(), job.Limits(), job.AttemptID(), domain.InvocationExtract, 2)
		if err != nil {
			t.Fatal(err)
		}
		// Runtime rejects plain-text refusal with AttemptConditionInvalidProviderOutput,
		// leaving the coordinator's accepted reports_only output intact rather than
		// fabricating findings:[].
		second := runtime.Invoke(context.Background(), extractJob)
		cond, hasCond := second.Condition()
		if second.Succeeded() || !hasCond || cond != AttemptConditionInvalidProviderOutput {
			t.Fatalf("plain-text refusal outcome = succeeded:%t cond:%q, want false/invalid_provider_output", second.Succeeded(), cond)
		}
		if len(provider.invocations) != 2 || len(runtime.pending) != 0 || len(runtime.pendingExtraction) != 0 {
			t.Fatalf("plain-text refusal left unexpected state: invocations=%d pending=%d pendingExtraction=%d", len(provider.invocations), len(runtime.pending), len(runtime.pendingExtraction))
		}
	})

	t.Run("coordinator absorbs non-requirements plain-text refusal as reports_only rather than no_findings", func(t *testing.T) {
		report := []byte("# Logic review\n\nHigh-severity defect in source.go without verbatim target excerpt.\n")
		refusal := []byte("Refusing structured transcription: claimed defect lacks an exact verbatim target excerpt.")
		runtime, job, provider := nonRequirementsLiveFixture(t, report, refusal)
		assignments, receipt := coordinatorTestPlan(t)
		runtime.source = requirementsTestDynamicPrompts{material: runtime.source.(requirementsTestPrompts).material}
		runtime.diagnostics = anyRunDiagnosticResolver{sink: &providerRuntimeRawSink{}}
		coordinator := coordinatorTestCoordinator(t, &coordinatorTestRuntime{invoke: func(ctx context.Context, cJob InvocationJob) AttemptOutcome {
			if cJob.Role() != domain.RoleLogic {
				return coordinatorSuccessOutcome(t, cJob)
			}
			return runtime.Invoke(ctx, cJob)
		}}, len(assignments), receipt)
		if err := coordinator.AdmitStructuredExtraction(); err != nil {
			t.Fatal(err)
		}
		res, err := coordinator.Execute(context.Background(), job.Target(), assignments, domain.SeverityHigh, nil)
		if err != nil {
			t.Fatal(err)
		}
		summary := coordinatorRoleSummary(t, res, domain.RoleLogic)
		if summary.State() != domain.RoleTaskSucceeded || !summary.ReportsOnly() {
			t.Fatalf("coordinator plain-text refusal summary = state:%s reportsOnly:%t, want succeeded/true", summary.State(), summary.ReportsOnly())
		}
		if res.OutcomeAxes().ContentVerdict() != domain.ContentReportsOnly {
			t.Fatalf("coordinator plain-text refusal content verdict = %q, want %q (not no_findings)", res.OutcomeAxes().ContentVerdict(), domain.ContentReportsOnly)
		}
		if len(provider.invocations) != 2 {
			t.Fatalf("expected 2 invocations (initial + extract), got %d", len(provider.invocations))
		}
	})

	t.Run("findings extraction remains strictly all-or-nothing when one finding has mismatched quote", func(t *testing.T) {
		report := []byte("# Logic review\n\nTwo defects in source.go.\n")
		goodFinding := map[string]any{
			"severity": "high", "title": "Good finding", "description": "Valid quote.",
			"evidence":       []any{map[string]any{"current": map[string]any{"path": "source.go", "side": "worktree", "line_start": 1, "line_end": 1, "quote": "observed\n"}}},
			"recommendation": "Fix good.", "confidence": "high",
		}
		badFinding := map[string]any{
			"severity": "high", "title": "Bad finding", "description": "Mismatched quote.",
			"evidence":       []any{map[string]any{"current": map[string]any{"path": "source.go", "side": "worktree", "line_start": 1, "line_end": 1, "quote": "wrong\n"}}},
			"recommendation": "Fix bad.", "confidence": "high",
		}
		extractJSON, _ := json.Marshal(map[string]any{
			"schema_version": "mulgae-provider-review-output.v1",
			"summary":        "Two findings.",
			"completeness":   "complete",
			"limitations":    []string{},
			"findings":       []any{goodFinding, badFinding},
		})
		runtime, job, _ := nonRequirementsLiveFixture(t, report, extractJSON)
		if !runtime.Invoke(context.Background(), job).Succeeded() {
			t.Fatal("initial report failed")
		}
		extractJob, _ := newCoordinatorInvocationJob(job.SessionID(), job.RunID(), job.Role(), job.Route(), job.Target(), job.Limits(), job.AttemptID(), domain.InvocationExtract, 2)
		second := runtime.Invoke(context.Background(), extractJob)
		cond, hasCond := second.Condition()
		if second.Succeeded() || !hasCond || cond != AttemptConditionUnrepairableEvidence {
			t.Fatalf("partial-bad findings extraction = succeeded:%t cond:%q, want false/unrepairable_evidence (all-or-nothing)", second.Succeeded(), cond)
		}
	})
}

type anyRunDiagnosticResolver struct {
	sink ports.RuntimeDiagnosticSink
}

func (resolver anyRunDiagnosticResolver) RuntimeDiagnosticSink(domain.RunID) (ports.RuntimeDiagnosticSink, bool) {
	return resolver.sink, resolver.sink != nil
}

type requirementsTestDynamicPrompts struct {
	material RuntimePrompt
}

func (s requirementsTestDynamicPrompts) Prompt(_ context.Context, job InvocationJob, _ *InvocationRepairInput) (RuntimePrompt, error) {
	return s.compileForJob(job)
}

func (s requirementsTestDynamicPrompts) ExtractionPrompt(_ context.Context, job InvocationJob, _ InvocationExtractionInput) (RuntimePrompt, error) {
	return s.compileForJob(job)
}

func (s requirementsTestDynamicPrompts) compileForJob(job InvocationJob) (RuntimePrompt, error) {
	roleTask, err := prompt.ParseRoleTaskID("rt_019f5a09-5eec-7001-8001-000000000001")
	if err != nil {
		return RuntimePrompt{}, err
	}
	coords, err := prompt.NewScopeCoordinates(job.SessionID(), job.RunID(), roleTask, job.AttemptID())
	if err != nil {
		return RuntimePrompt{}, err
	}
	compiler, err := prompt.NewCompiler(s.material.Prompt.TrustedTemplate(), explicitRuntimeTestIssuer{
		source:    s.material.Prompt.Scope().SourceInvocationID(),
		execution: s.material.Prompt.Scope().ExecutionInvocationID(),
	})
	if err != nil {
		return RuntimePrompt{}, err
	}
	compiled, err := compiler.Compile(prompt.CompileInput{
		Scope:        coords,
		ReviewTarget: prompt.NewPayload(s.material.Target),
	})
	if err != nil {
		return RuntimePrompt{}, err
	}
	out := s.material
	out.Prompt = compiled
	return out, nil
}

type requirementsPathFuncReader struct {
	ports.LiveSourceReader
	onRead func(ctx context.Context, side domain.LiveSourceSide, path ports.SafeRelativePath) (ports.LiveSourceFile, error)
}

func (r requirementsPathFuncReader) Read(ctx context.Context, side domain.LiveSourceSide, path ports.SafeRelativePath) (ports.LiveSourceFile, error) {
	return r.onRead(ctx, side, path)
}

func TestRequirementsRuntimeJoinedCitationAndOpaqueFailsClosed(t *testing.T) {
	citationErr := ports.NewLiveSourceCitationError(ports.LiveSourceUnavailable, errors.New("absent cited path"))
	joinedOpaque := errors.Join(citationErr, errors.New("opaque reader failure"))

	t.Run("initial requirements verification aborts with InternalInvariant on joined citation+opaque after earlier row isolation", func(t *testing.T) {
		rowA := requirementsRuntimeRow("A")
		rowA["evidence"].([]any)[0].(map[string]any)["current"].(map[string]any)["path"] = "missing.go"
		rowB := requirementsRuntimeRow("B")
		rowB["evidence"].([]any)[0].(map[string]any)["current"].(map[string]any)["path"] = "broken.go"
		runtime, job, _, _ := requirementsRuntimeFixtureWithScopeAndSink(t, domain.LiveSourceWorkspace, requirementsRuntimeResponse([]any{}, rowA, rowB))
		runtime.verifier, _ = evidence.NewLiveVerifier(requirementsPathFuncReader{
			LiveSourceReader: runtime.liveExecution.SourceReader(),
			onRead: func(_ context.Context, _ domain.LiveSourceSide, path ports.SafeRelativePath) (ports.LiveSourceFile, error) {
				if path.String() == "missing.go" {
					return ports.LiveSourceFile{}, citationErr
				}
				return ports.LiveSourceFile{}, joinedOpaque
			},
		})
		outcome := runtime.Invoke(context.Background(), job)
		cond, ok := outcome.Condition()
		if outcome.Succeeded() || !ok || cond != AttemptConditionInternalInvariant {
			t.Fatalf("initial joined citation+opaque = succeeded:%t cond:%q, want false/internal_invariant", outcome.Succeeded(), cond)
		}
		res, err := runtime.RequirementsResult(false)
		if err != nil {
			t.Fatal(err)
		}
		if _, evaluated, _ := res.Evaluation().Counts(); evaluated != 0 {
			t.Fatalf("failed initial leaked evaluated requirements: %+v", res.Evaluation())
		}
	})

	t.Run("extract requirements verification aborts with InternalInvariant on joined citation+opaque while preserving initial section", func(t *testing.T) {
		badB := requirementsRuntimeRow("B")
		badB["evidence"].([]any)[0].(map[string]any)["current"].(map[string]any)["quote"] = "wrong\n"
		initial := requirementsRuntimeResponse([]any{}, requirementsRuntimeRow("A"), badB)
		extractRowB := requirementsRuntimeRow("B")
		extractRowB["evidence"].([]any)[0].(map[string]any)["current"].(map[string]any)["path"] = "broken.go"
		extractResp := requirementsRuntimeResponse([]any{}, extractRowB)

		runtime, job, _, _ := requirementsRuntimeFixtureWithScopeAndSink(t, domain.LiveSourceWorkspace, initial, extractResp)
		if !runtime.Invoke(context.Background(), job).Succeeded() {
			t.Fatal("initial partial failed")
		}
		runtime.verifier, _ = evidence.NewLiveVerifier(requirementsPathFuncReader{
			LiveSourceReader: runtime.liveExecution.SourceReader(),
			onRead: func(_ context.Context, _ domain.LiveSourceSide, path ports.SafeRelativePath) (ports.LiveSourceFile, error) {
				if path.String() == "broken.go" {
					return ports.LiveSourceFile{}, joinedOpaque
				}
				return ports.NewLiveSourceFile(path, []byte("observed\n"), "text/plain")
			},
		})
		extractJob, _ := newCoordinatorInvocationJob(job.SessionID(), job.RunID(), job.Role(), job.Route(), job.Target(), job.Limits(), job.AttemptID(), domain.InvocationExtract, 2)
		second := runtime.Invoke(context.Background(), extractJob)
		cond, ok := second.Condition()
		if second.Succeeded() || !ok || cond != AttemptConditionInternalInvariant {
			t.Fatalf("extract joined citation+opaque = succeeded:%t cond:%q, want false/internal_invariant", second.Succeeded(), cond)
		}
		res, err := runtime.RequirementsResult(true)
		if err != nil {
			t.Fatal(err)
		}
		rows := res.Evaluation().Assessments()
		if rows[0].Origin() != domain.AssessmentProvider || rows[1].Reason() != domain.AssessmentInvalidContent || rows[2].Reason() != domain.AssessmentAnswerOmitted {
			t.Fatalf("failed extract corrupted prior requirement section: %+v", rows)
		}
	})

	t.Run("requirements-mode findings verification aborts with InternalInvariant on joined citation+opaque", func(t *testing.T) {
		finding := map[string]any{
			"severity": "high", "title": "Finding", "description": "References broken.go.",
			"evidence":       []any{map[string]any{"current": map[string]any{"path": "broken.go", "side": "worktree", "line_start": 1, "line_end": 1, "quote": "observed\n"}}},
			"recommendation": "Fix it.", "confidence": "high",
		}
		raw := requirementsRuntimeResponse([]any{finding}, requirementsRuntimeRow("A"))
		runtime, job, _, _ := requirementsRuntimeFixtureWithScopeAndSink(t, domain.LiveSourceWorkspace, raw)
		runtime.verifier, _ = evidence.NewLiveVerifier(requirementsPathFuncReader{
			LiveSourceReader: runtime.liveExecution.SourceReader(),
			onRead: func(_ context.Context, _ domain.LiveSourceSide, path ports.SafeRelativePath) (ports.LiveSourceFile, error) {
				if path.String() == "broken.go" {
					return ports.LiveSourceFile{}, joinedOpaque
				}
				return ports.NewLiveSourceFile(path, []byte("observed\n"), "text/plain")
			},
		})
		outcome := runtime.Invoke(context.Background(), job)
		cond, ok := outcome.Condition()
		if outcome.Succeeded() || !ok || cond != AttemptConditionInternalInvariant {
			t.Fatalf("findings joined citation+opaque = succeeded:%t cond:%q, want false/internal_invariant", outcome.Succeeded(), cond)
		}
		// Transactional commit: requirement A from the failed invocation must NOT leak.
		res, err := runtime.RequirementsResult(false)
		if err != nil {
			t.Fatal(err)
		}
		if _, evaluated, _ := res.Evaluation().Counts(); evaluated != 0 {
			t.Fatalf("failed findings verification leaked requirement A: %+v", res.Evaluation())
		}
	})
}

func TestRequirementsRuntimeTransactionalCommitPreservesPreInvocationStateOnFailure(t *testing.T) {
	timeoutFailure, err := domain.NewFailure("source.fixture", domain.FailureTimeout, "source verification timed out", nil)
	if err != nil {
		t.Fatal(err)
	}
	findingOnFaultPath := map[string]any{
		"severity": "high", "title": "Faulting finding", "description": "Triggers fault on finding verify.",
		"evidence":       []any{map[string]any{"current": map[string]any{"path": "fault.go", "side": "worktree", "line_start": 1, "line_end": 1, "quote": "observed\n"}}},
		"recommendation": "Fix it.", "confidence": "high",
	}
	badRowB := requirementsRuntimeRow("B")
	badRowB["evidence"].([]any)[0].(map[string]any)["current"].(map[string]any)["quote"] = "wrong\n"

	failureModes := []struct {
		name     string
		setup    func(t *testing.T, rt *ProviderInvocationRuntime)
		wantCond AttemptCondition
		withFind bool
	}{
		{
			name: "LiveSourceUnsafe during findings verification",
			setup: func(_ *testing.T, rt *ProviderInvocationRuntime) {
				rt.verifier, _ = evidence.NewLiveVerifier(requirementsPathFuncReader{
					LiveSourceReader: rt.liveExecution.SourceReader(),
					onRead: func(_ context.Context, _ domain.LiveSourceSide, path ports.SafeRelativePath) (ports.LiveSourceFile, error) {
						if path.String() == "fault.go" {
							return ports.LiveSourceFile{}, ports.NewLiveSourceError(ports.LiveSourceUnsafe, errors.New("drift"))
						}
						return ports.NewLiveSourceFile(path, []byte("observed\n"), "text/plain")
					},
				})
			},
			wantCond: AttemptConditionSecurityViolation,
			withFind: true,
		},
		{
			name: "requirementsInfrastructureDiagnostic during findings validation",
			setup: func(_ *testing.T, rt *ProviderInvocationRuntime) {
				id, _ := ports.ParseAssetID(validation.ProviderReviewSchemaID)
				rt.validator, _ = validation.NewReviewValidator(requirementsFaultSchema{requirementsInfrastructureDiagnostic{}}, id)
			},
			wantCond: AttemptConditionInternalInvariant,
			withFind: false,
		},
		{
			name: "context.Canceled during findings verification",
			setup: func(_ *testing.T, rt *ProviderInvocationRuntime) {
				rt.verifier, _ = evidence.NewLiveVerifier(requirementsPathFuncReader{
					LiveSourceReader: rt.liveExecution.SourceReader(),
					onRead: func(_ context.Context, _ domain.LiveSourceSide, path ports.SafeRelativePath) (ports.LiveSourceFile, error) {
						if path.String() == "fault.go" {
							return ports.LiveSourceFile{}, context.Canceled
						}
						return ports.NewLiveSourceFile(path, []byte("observed\n"), "text/plain")
					},
				})
			},
			wantCond: AttemptConditionCancelled,
			withFind: true,
		},
		{
			name: "typed domain.FailureTimeout during findings verification",
			setup: func(_ *testing.T, rt *ProviderInvocationRuntime) {
				rt.verifier, _ = evidence.NewLiveVerifier(requirementsPathFuncReader{
					LiveSourceReader: rt.liveExecution.SourceReader(),
					onRead: func(_ context.Context, _ domain.LiveSourceSide, path ports.SafeRelativePath) (ports.LiveSourceFile, error) {
						if path.String() == "fault.go" {
							return ports.LiveSourceFile{}, timeoutFailure
						}
						return ports.NewLiveSourceFile(path, []byte("observed\n"), "text/plain")
					},
				})
			},
			wantCond: AttemptConditionTimeout,
			withFind: true,
		},
	}

	for _, mode := range failureModes {
		t.Run("initial/"+mode.name, func(t *testing.T) {
			findings := []any{}
			if mode.withFind {
				findings = []any{findingOnFaultPath}
			}
			raw := requirementsRuntimeResponse(findings, requirementsRuntimeRow("A"))
			runtime, job, _, _ := requirementsRuntimeFixtureWithScopeAndSink(t, domain.LiveSourceWorkspace, raw)
			mode.setup(t, runtime)
			outcome := runtime.Invoke(context.Background(), job)
			cond, ok := outcome.Condition()
			if outcome.Succeeded() || !ok || cond != mode.wantCond {
				t.Fatalf("initial %s = succeeded:%t cond:%q, want false/%s", mode.name, outcome.Succeeded(), cond, mode.wantCond)
			}
			res, resErr := runtime.RequirementsResult(false)
			if resErr != nil {
				t.Fatal(resErr)
			}
			if _, evaluated, _ := res.Evaluation().Counts(); evaluated != 0 {
				t.Fatalf("failed initial %s leaked provider rows: %+v", mode.name, res.Evaluation())
			}
			for _, row := range res.Evaluation().Assessments() {
				if row.Origin() != domain.AssessmentDerived || row.Reason() != domain.AssessmentExtractionDisabled {
					t.Fatalf("failed initial %s mutated pre-invocation state: %+v", mode.name, row)
				}
			}
		})

		t.Run("extract/"+mode.name, func(t *testing.T) {
			// Initial prose with partial requirements (A valid, B invalid, C omitted) -> reports_only so extract runs findings verification!
			initial := requirementsRuntimeResponse("invalid findings", requirementsRuntimeRow("A"), badRowB)
			extractFindings := []any{}
			if mode.withFind {
				extractFindings = []any{findingOnFaultPath}
			}
			extractResp := requirementsRuntimeResponse(extractFindings, requirementsRuntimeRow("B"), requirementsRuntimeRow("C"))
			runtime, job, _, _ := requirementsRuntimeFixtureWithScopeAndSink(t, domain.LiveSourceWorkspace, initial, extractResp)
			if !runtime.Invoke(context.Background(), job).Succeeded() {
				t.Fatal("initial failed")
			}
			mode.setup(t, runtime)
			extractJob, _ := newCoordinatorInvocationJob(job.SessionID(), job.RunID(), job.Role(), job.Route(), job.Target(), job.Limits(), job.AttemptID(), domain.InvocationExtract, 2)
			second := runtime.Invoke(context.Background(), extractJob)
			cond, ok := second.Condition()
			if second.Succeeded() || !ok || cond != mode.wantCond {
				t.Fatalf("extract %s = succeeded:%t cond:%q, want false/%s", mode.name, second.Succeeded(), cond, mode.wantCond)
			}
			res, resErr := runtime.RequirementsResult(true)
			if resErr != nil {
				t.Fatal(resErr)
			}
			rows := res.Evaluation().Assessments()
			if rows[0].Origin() != domain.AssessmentProvider || rows[0].Verdict() != domain.RequirementMet ||
				rows[1].Origin() != domain.AssessmentDerived || rows[1].Reason() != domain.AssessmentInvalidContent ||
				rows[2].Origin() != domain.AssessmentDerived || rows[2].Reason() != domain.AssessmentAnswerOmitted {
				t.Fatalf("failed extract %s leaked B/C or altered pre-extract state: %+v", mode.name, rows)
			}
		})
	}

	persistenceModes := []struct {
		name     string
		makeSink func() *failingRecordingSink
		wantCond AttemptCondition
	}{
		{
			name: "PersistRaw storage failure",
			makeSink: func() *failingRecordingSink {
				return &failingRecordingSink{
					requirementsRecordingSink: &requirementsRecordingSink{},
					persistRawErr:             errors.New("raw storage down"),
				}
			},
			wantCond: AttemptConditionArtifactFailure,
		},
		{
			name: "ReplaceInvocationStatus storage failure",
			makeSink: func() *failingRecordingSink {
				return &failingRecordingSink{
					requirementsRecordingSink: &requirementsRecordingSink{},
					replaceErr:                errors.New("status storage down"),
				}
			},
			wantCond: AttemptConditionArtifactFailure,
		},
	}

	for _, pMode := range persistenceModes {
		t.Run("initial-structured/"+pMode.name, func(t *testing.T) {
			raw := requirementsRuntimeResponse([]any{}, requirementsRuntimeRow("A"))
			runtime, job, _, _ := requirementsRuntimeFixtureWithScopeAndSink(t, domain.LiveSourceWorkspace, raw)
			runtime.diagnostics = providerRuntimeDiagnosticResolver{runID: job.RunID(), sink: pMode.makeSink()}
			outcome := runtime.Invoke(context.Background(), job)
			cond, ok := outcome.Condition()
			if outcome.Succeeded() || !ok || cond != pMode.wantCond {
				t.Fatalf("initial-structured %s = succeeded:%t cond:%q, want false/%s", pMode.name, outcome.Succeeded(), cond, pMode.wantCond)
			}
			if len(runtime.pendingExtraction) != 0 {
				t.Fatalf("initial-structured %s leaked pendingExtraction: %d", pMode.name, len(runtime.pendingExtraction))
			}
			if _, hasNorm := runtime.NormalizedRequirementsOutput(job.Role()); hasNorm {
				t.Fatalf("initial-structured %s leaked NormalizedRequirementsOutput", pMode.name)
			}
			if _, hasOut := runtime.requirementOutputs[job.Role()]; hasOut {
				t.Fatalf("initial-structured %s leaked requirementOutputs", pMode.name)
			}
			res, resErr := runtime.RequirementsResult(false)
			if resErr != nil {
				t.Fatal(resErr)
			}
			if _, evaluated, _ := res.Evaluation().Counts(); evaluated != 0 {
				t.Fatalf("initial-structured %s leaked requirementSections: %+v", pMode.name, res.Evaluation())
			}
		})

		t.Run("initial-prose-fallback/"+pMode.name, func(t *testing.T) {
			prose := []byte("# Prose report\n\nNo structured JSON.\n")
			runtime, job, _, _ := requirementsRuntimeFixtureWithScopeAndSink(t, domain.LiveSourceWorkspace, prose)
			runtime.diagnostics = providerRuntimeDiagnosticResolver{runID: job.RunID(), sink: pMode.makeSink()}
			outcome := runtime.Invoke(context.Background(), job)
			cond, ok := outcome.Condition()
			if outcome.Succeeded() || !ok || cond != pMode.wantCond {
				t.Fatalf("initial-prose-fallback %s = succeeded:%t cond:%q, want false/%s", pMode.name, outcome.Succeeded(), cond, pMode.wantCond)
			}
			if len(runtime.pendingExtraction) != 0 {
				t.Fatalf("initial-prose-fallback %s leaked pendingExtraction: %d", pMode.name, len(runtime.pendingExtraction))
			}
			if _, hasOut := runtime.requirementOutputs[job.Role()]; hasOut {
				t.Fatalf("initial-prose-fallback %s leaked requirementOutputs", pMode.name)
			}
		})

		t.Run("extract/"+pMode.name, func(t *testing.T) {
			initial := requirementsRuntimeResponse("invalid findings", requirementsRuntimeRow("A"), badRowB)
			extractResp := requirementsRuntimeResponse([]any{}, requirementsRuntimeRow("B"), requirementsRuntimeRow("C"))
			runtime, job, _, _ := requirementsRuntimeFixtureWithScopeAndSink(t, domain.LiveSourceWorkspace, initial, extractResp)
			if !runtime.Invoke(context.Background(), job).Succeeded() {
				t.Fatal("initial failed")
			}
			runtime.diagnostics = providerRuntimeDiagnosticResolver{runID: job.RunID(), sink: pMode.makeSink()}
			extractJob, _ := newCoordinatorInvocationJob(job.SessionID(), job.RunID(), job.Role(), job.Route(), job.Target(), job.Limits(), job.AttemptID(), domain.InvocationExtract, 2)
			second := runtime.Invoke(context.Background(), extractJob)
			cond, ok := second.Condition()
			if second.Succeeded() || !ok || cond != pMode.wantCond {
				t.Fatalf("extract %s = succeeded:%t cond:%q, want false/%s", pMode.name, second.Succeeded(), cond, pMode.wantCond)
			}
			if _, hasNorm := runtime.NormalizedRequirementsOutput(job.Role()); hasNorm {
				t.Fatalf("extract %s leaked NormalizedRequirementsOutput", pMode.name)
			}
			res, resErr := runtime.RequirementsResult(true)
			if resErr != nil {
				t.Fatal(resErr)
			}
			rows := res.Evaluation().Assessments()
			if rows[0].Origin() != domain.AssessmentProvider || rows[0].Verdict() != domain.RequirementMet ||
				rows[1].Origin() != domain.AssessmentDerived || rows[1].Reason() != domain.AssessmentInvalidContent ||
				rows[2].Origin() != domain.AssessmentDerived || rows[2].Reason() != domain.AssessmentAnswerOmitted {
				t.Fatalf("extract %s leaked B/C or altered pre-extract state: %+v", pMode.name, rows)
			}
		})

		t.Run("repairable-malformed-initial/"+pMode.name, func(t *testing.T) {
			malformed := []byte(`{"schema_version":"mulgae-provider-review-output.v3","requirements":{`)
			runtime, job, _, _ := requirementsRuntimeFixtureWithScopeAndSink(t, domain.LiveSourceWorkspace, malformed)
			runtime.diagnostics = providerRuntimeDiagnosticResolver{runID: job.RunID(), sink: pMode.makeSink()}
			outcome := runtime.Invoke(context.Background(), job)
			cond, ok := outcome.Condition()
			if outcome.Succeeded() || !ok || cond != pMode.wantCond {
				t.Fatalf("repairable-malformed-initial %s = succeeded:%t cond:%q, want false/%s", pMode.name, outcome.Succeeded(), cond, pMode.wantCond)
			}
			if len(runtime.pending) != 0 {
				t.Fatalf("repairable-malformed-initial %s leaked runtime.pending (%d entries)", pMode.name, len(runtime.pending))
			}
		})
	}
}

func TestRequirementsCoordinatorEndToEndOmittedFindingsAndOptionAMerge(t *testing.T) {
	t.Run("prose initial plus omitted-findings extract keeps reports_only and preserves verified requirements", func(t *testing.T) {
		report := []byte("# Logic review\n\nHigh defect claimed in source.go without verbatim target excerpt.\n")
		extractResp := requirementsRuntimeOmittedFindingsResponse(requirementsRuntimeRow("A"))
		runtime, job, provider, _ := requirementsRuntimeFixtureWithScopeAndSink(t, domain.LiveSourceWorkspace, report, extractResp)
		assignments, receipt := coordinatorTestPlan(t)
		runtime.source = requirementsTestDynamicPrompts{material: runtime.source.(requirementsTestPrompts).material}
		runtime.diagnostics = anyRunDiagnosticResolver{sink: &providerRuntimeRawSink{}}
		coordinator := coordinatorTestCoordinator(t, &coordinatorTestRuntime{invoke: func(ctx context.Context, cJob InvocationJob) AttemptOutcome {
			if cJob.Role() != domain.RoleLogic {
				return coordinatorSuccessOutcome(t, cJob)
			}
			return runtime.Invoke(ctx, cJob)
		}}, len(assignments), receipt)
		if err := coordinator.AdmitStructuredExtraction(); err != nil {
			t.Fatal(err)
		}
		res, err := coordinator.Execute(context.Background(), job.Target(), assignments, domain.SeverityHigh, nil)
		if err != nil {
			t.Fatal(err)
		}
		summary := coordinatorRoleSummary(t, res, domain.RoleLogic)
		if summary.State() != domain.RoleTaskSucceeded || !summary.ReportsOnly() {
			t.Fatalf("coordinator omitted-findings summary = state:%s reportsOnly:%t, want succeeded/true", summary.State(), summary.ReportsOnly())
		}
		if res.OutcomeAxes().ContentVerdict() != domain.ContentReportsOnly {
			t.Fatalf("coordinator omitted-findings content verdict = %q, want reports_only (not no_findings)", res.OutcomeAxes().ContentVerdict())
		}
		if len(provider.invocations) != 2 {
			t.Fatalf("expected 2 invocations (initial + extract), got %d", len(provider.invocations))
		}
		reqRes, err := runtime.RequirementsResult(true)
		if err != nil {
			t.Fatal(err)
		}
		rows := reqRes.Evaluation().Assessments()
		if rows[0].Origin() != domain.AssessmentProvider || rows[0].Verdict() != domain.RequirementMet ||
			rows[1].Reason() != domain.AssessmentAnswerOmitted || rows[2].Reason() != domain.AssessmentAnswerOmitted {
			t.Fatalf("coordinator omitted-findings lost verified requirements: %+v", rows)
		}
	})

	t.Run("Option A partial-invalid initial schedules extract through Coordinator and merges monotonically", func(t *testing.T) {
		badB := requirementsRuntimeRow("B")
		badB["evidence"].([]any)[0].(map[string]any)["current"].(map[string]any)["quote"] = "mismatched\n"
		unverifiedA := requirementsRuntimeRow("A")
		unverifiedA["verdict"] = "unverified"
		unverifiedA["reason"] = "insufficient_evidence"
		unverifiedA["evidence"] = []any{}
		fixedB := requirementsRuntimeRow("B")
		fixedB["verdict"] = "partially_met"

		initial := requirementsRuntimeResponse([]any{}, requirementsRuntimeRow("A"), badB)
		extractResp := requirementsRuntimeResponse([]any{}, unverifiedA, fixedB)
		runtime, job, provider, _ := requirementsRuntimeFixtureWithScopeAndSink(t, domain.LiveSourceWorkspace, initial, extractResp)
		assignments, receipt := coordinatorTestPlan(t)
		runtime.source = requirementsTestDynamicPrompts{material: runtime.source.(requirementsTestPrompts).material}
		runtime.diagnostics = anyRunDiagnosticResolver{sink: &providerRuntimeRawSink{}}
		coordinator := coordinatorTestCoordinator(t, &coordinatorTestRuntime{invoke: func(ctx context.Context, cJob InvocationJob) AttemptOutcome {
			if cJob.Role() != domain.RoleLogic {
				return coordinatorSuccessOutcome(t, cJob)
			}
			return runtime.Invoke(ctx, cJob)
		}}, len(assignments), receipt)
		if err := coordinator.AdmitStructuredExtraction(); err != nil {
			t.Fatal(err)
		}
		res, err := coordinator.Execute(context.Background(), job.Target(), assignments, domain.SeverityHigh, nil)
		if err != nil {
			t.Fatal(err)
		}
		summary := coordinatorRoleSummary(t, res, domain.RoleLogic)
		if summary.State() != domain.RoleTaskSucceeded || summary.ReportsOnly() {
			t.Fatalf("coordinator Option A summary = state:%s reportsOnly:%t, want succeeded/false", summary.State(), summary.ReportsOnly())
		}
		if len(provider.invocations) != 2 {
			t.Fatalf("Option A did not schedule extract through coordinator: invocations=%d", len(provider.invocations))
		}
		reqRes, err := runtime.RequirementsResult(true)
		if err != nil {
			t.Fatal(err)
		}
		rows := reqRes.Evaluation().Assessments()
		if rows[0].Origin() != domain.AssessmentProvider || rows[0].Verdict() != domain.RequirementMet ||
			rows[1].Origin() != domain.AssessmentProvider || rows[1].Verdict() != domain.RequirementPartiallyMet ||
			rows[2].Origin() != domain.AssessmentDerived || rows[2].Reason() != domain.AssessmentAnswerOmitted {
			t.Fatalf("coordinator Option A monotone merge wrong: %+v", rows)
		}
		normOut, hasNorm := runtime.NormalizedRequirementsOutput(domain.RoleLogic)
		if !hasNorm {
			t.Fatal("coordinator Option A merge did not populate NormalizedRequirementsOutput")
		}
		normBytes, err := normOut.Bytes()
		if err != nil {
			t.Fatal(err)
		}
		var doc struct {
			Requirements struct {
				Assessments []struct {
					ID      string `json:"requirement_id"`
					Verdict string `json:"verdict"`
				} `json:"assessments"`
			} `json:"requirements"`
		}
		if err := json.Unmarshal(normBytes, &doc); err != nil {
			t.Fatal(err)
		}
		if len(doc.Requirements.Assessments) != 2 ||
			doc.Requirements.Assessments[0].ID != "A" || doc.Requirements.Assessments[0].Verdict != "met" ||
			doc.Requirements.Assessments[1].ID != "B" || doc.Requirements.Assessments[1].Verdict != "partially_met" {
			t.Fatalf("NormalizedRequirementsOutput order/verdicts = %+v, want [A=met, B=partially_met]", doc.Requirements.Assessments)
		}
	})

	t.Run("requirements mode keeps findings strictly all-or-nothing when one finding fails while retaining valid requirements", func(t *testing.T) {
		goodFinding := map[string]any{
			"severity": "high", "title": "Valid finding", "description": "Matches source.go.",
			"evidence":       []any{map[string]any{"current": map[string]any{"path": "source.go", "side": "worktree", "line_start": 1, "line_end": 1, "quote": "observed\n"}}},
			"recommendation": "Fix valid.", "confidence": "high",
		}
		badFinding := map[string]any{
			"severity": "high", "title": "Bad finding", "description": "Mismatched quote.",
			"evidence":       []any{map[string]any{"current": map[string]any{"path": "source.go", "side": "worktree", "line_start": 1, "line_end": 1, "quote": "wrong\n"}}},
			"recommendation": "Fix bad.", "confidence": "high",
		}
		raw := requirementsRuntimeResponse([]any{goodFinding, badFinding}, requirementsRuntimeRow("A"))
		runtime, job, _, _ := requirementsRuntimeFixtureWithScopeAndSink(t, domain.LiveSourceWorkspace, raw)
		outcome := runtime.Invoke(context.Background(), job)
		out, ok := outcome.Output()
		if !outcome.Succeeded() || !ok || !out.ReportsOnly() || len(out.Findings()) != 0 {
			t.Fatalf("requirements-mode mixed findings = succeeded:%t reportsOnly:%t findings:%d, want true/true/0", outcome.Succeeded(), out.ReportsOnly(), len(out.Findings()))
		}
		if _, hasNorm := runtime.NormalizedRequirementsOutput(job.Role()); hasNorm {
			t.Fatal("reports_only mixed findings falsely populated NormalizedRequirementsOutput")
		}
		reqRes, err := runtime.RequirementsResult(false)
		if err != nil {
			t.Fatal(err)
		}
		rows := reqRes.Evaluation().Assessments()
		if rows[0].Origin() != domain.AssessmentProvider || rows[0].Verdict() != domain.RequirementMet {
			t.Fatalf("requirements-mode mixed findings dropped valid requirement A: %+v", rows)
		}
	})
}
