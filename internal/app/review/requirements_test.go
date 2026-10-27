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
