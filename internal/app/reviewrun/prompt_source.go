package reviewrun

import (
	"context"
	"fmt"
	"strings"

	"github.com/irootkernel/kkachi-agent-review/internal/app/prompt"
	"github.com/irootkernel/kkachi-agent-review/internal/app/review"
)

// ProductionPromptSource is the shared current-template prompt authority for
// root, delta, recomposed rerun, and exact replay execution.
type ProductionPromptSource = promptSource

// NewProductionPromptSource constructs a child-workflow prompt authority from
// one P2- or capture-bound immutable target.
func NewProductionPromptSource(input ImmutableReviewInput, templates review.TemplateSet, ids prompt.InvocationIDIssuer, roleTask func() (prompt.RoleTaskID, error)) (*ProductionPromptSource, error) {
	return newPromptSource(input, templates, ids, roleTask)
}

type promptSource struct {
	input     ImmutableReviewInput
	templates review.TemplateSet
	ids       prompt.InvocationIDIssuer
	roleTask  func() (prompt.RoleTaskID, error)
	objective *prompt.Objective
}

func newPromptSource(input ImmutableReviewInput, templates review.TemplateSet, ids prompt.InvocationIDIssuer, roleTask func() (prompt.RoleTaskID, error)) (*promptSource, error) {
	if nilInterface(ids) || roleTask == nil {
		return nil, fmt.Errorf("review run: nil prompt identity issuer")
	}
	var objective *prompt.Objective
	if input.HasObjective() {
		bytes := input.Objective()
		candidate := prompt.NewObjective(bytes)
		if err := candidate.Lint().Err(); err != nil {
			return nil, fmt.Errorf("review run: objective: %w", err)
		}
		objective = &candidate
	}
	captured, err := NewImmutableReviewInputWithProjectContext(input.Target(), input.Objective(), input.HasObjective(), input.ProjectContext(), input.HasProjectContext())
	if err != nil {
		return nil, err
	}
	return &promptSource{input: captured, templates: templates, ids: ids, roleTask: roleTask, objective: objective}, nil
}

func (source *promptSource) Prompt(ctx context.Context, job review.InvocationJob, repair *review.InvocationRepairInput) (review.RuntimePrompt, error) {
	if source == nil || ctx == nil {
		return review.RuntimePrompt{}, fmt.Errorf("review run: prompt source is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return review.RuntimePrompt{}, err
	}
	template, err := source.templates.ComposeRootReview(job.Role(), source.objective)
	if err != nil {
		return review.RuntimePrompt{}, err
	}
	if repair != nil {
		template, err = source.templates.ComposeRootReviewRepair(template, repair.Plan())
		if err != nil {
			return review.RuntimePrompt{}, err
		}
	}
	manifest, err := template.TrustedLayerManifestJSON()
	if err != nil {
		return review.RuntimePrompt{}, fmt.Errorf("review run: trusted layer manifest: %w", err)
	}
	compiler, err := prompt.NewCompiler(template, source.ids)
	if err != nil {
		return review.RuntimePrompt{}, err
	}
	roleTask, err := source.roleTask()
	if err != nil {
		return review.RuntimePrompt{}, err
	}
	scope, err := prompt.NewScopeCoordinates(job.SessionID(), job.RunID(), roleTask, job.AttemptID())
	if err != nil {
		return review.RuntimePrompt{}, err
	}
	compileInput := compileInputForReview(scope, source.input)
	if repair != nil {
		prior := prompt.NewPayload(repair.InitialCandidate())
		compileInput.PriorProviderOutput = &prior
	}
	compiled, err := compiler.Compile(compileInput)
	if err != nil {
		return review.RuntimePrompt{}, err
	}
	return review.RuntimePrompt{
		Prompt: compiled, Target: source.input.Target().Bytes(), AdapterProfile: "root-review",
		AdapterParameters: map[string]string{prompt.TrustedLayerManifestAdapterParameter: manifest},
	}, nil
}

// DeltaPrompt binds source bytes, current bytes, and comparator-owned A-to-B
// material into distinct canonical untrusted frames.
func (source *promptSource) DeltaPrompt(ctx context.Context, job review.InvocationJob, material review.DeltaInvocationMaterial, repair *review.InvocationRepairInput) (review.RuntimePrompt, error) {
	if source == nil || ctx == nil || material.CurrentTargetIdentity != job.Target() {
		return review.RuntimePrompt{}, fmt.Errorf("review run: delta prompt source is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return review.RuntimePrompt{}, err
	}
	template, err := source.templates.ComposeRootReview(job.Role(), source.objective)
	if err != nil {
		return review.RuntimePrompt{}, err
	}
	if repair != nil {
		template, err = source.templates.ComposeRootReviewRepair(template, repair.Plan())
		if err != nil {
			return review.RuntimePrompt{}, err
		}
	}
	manifest, err := template.TrustedLayerManifestJSON()
	if err != nil {
		return review.RuntimePrompt{}, err
	}
	compiler, err := prompt.NewCompiler(template, source.ids)
	if err != nil {
		return review.RuntimePrompt{}, err
	}
	roleTask, err := source.roleTask()
	if err != nil {
		return review.RuntimePrompt{}, err
	}
	scope, err := prompt.NewScopeCoordinates(job.SessionID(), job.RunID(), roleTask, job.AttemptID())
	if err != nil {
		return review.RuntimePrompt{}, err
	}
	sourcePayload := prompt.NewPayload(material.SourceTarget)
	deltaPayload := prompt.NewPayload(material.Delta)
	input := prompt.CompileInput{Scope: scope, ProjectContext: &sourcePayload, ReviewTarget: prompt.NewPayload(material.CurrentTarget), PriorReport: &deltaPayload}
	if repair != nil {
		prior := prompt.NewPayload(repair.InitialCandidate())
		input.PriorProviderOutput = &prior
	}
	compiled, err := compiler.Compile(input)
	if err != nil {
		return review.RuntimePrompt{}, err
	}
	return review.RuntimePrompt{Prompt: compiled, Target: append([]byte(nil), material.CurrentTarget...), AdapterProfile: "root-review", AdapterParameters: map[string]string{prompt.TrustedLayerManifestAdapterParameter: manifest}}, nil
}

// ExactReplayPrompt validates persisted stdin as a canonical packet and mints
// only the fresh execution identity required by exact replay.
func (source *promptSource) ExactReplayPrompt(ctx context.Context, job review.InvocationJob, input review.ExactReplayInput) (review.RuntimePrompt, error) {
	if source == nil || ctx == nil || job.Role() != input.Role || job.Route().ProviderInstance() != input.SourceProviderInstance {
		return review.RuntimePrompt{}, fmt.Errorf("review run: exact replay prompt authority mismatch")
	}
	if err := ctx.Err(); err != nil {
		return review.RuntimePrompt{}, err
	}
	marker := []byte("\nKAR-FRAMES/1\n")
	index := strings.Index(string(input.Stdin), string(marker))
	if index <= 0 {
		return review.RuntimePrompt{}, fmt.Errorf("review run: exact replay stored template boundary is absent")
	}
	template, err := prompt.NewTrustedTemplate(input.TemplateID, input.TemplateVersion, input.Stdin[:index])
	if err != nil {
		return review.RuntimePrompt{}, err
	}
	if template.SHA256() != input.TemplateSHA256 {
		return review.RuntimePrompt{}, fmt.Errorf("review run: exact replay template digest mismatch")
	}
	compiler, err := prompt.NewCompiler(template, source.ids)
	if err != nil {
		return review.RuntimePrompt{}, err
	}
	priorExecution, err := prompt.ParseExecutionInvocationID(input.SourceExecutionInvocationID)
	if err != nil {
		return review.RuntimePrompt{}, err
	}
	replayed, err := compiler.ReplayStored(input.Stdin, priorExecution)
	if err != nil {
		return review.RuntimePrompt{}, err
	}
	return review.RuntimePrompt{Prompt: replayed, Target: source.input.Target().Bytes(), AdapterProfile: input.AdapterProfile, AdapterParameters: input.AdapterParameters}, nil
}
func compileInputForReview(scope prompt.ScopeCoordinates, input ImmutableReviewInput) prompt.CompileInput {
	compileInput := prompt.CompileInput{Scope: scope, ReviewTarget: prompt.NewPayload(input.Target().Bytes())}
	if input.HasProjectContext() {
		project := prompt.NewPayload(input.ProjectContext())
		compileInput.ProjectContext = &project
	}
	return compileInput
}
