package reviewrun

import (
	"context"
	"fmt"

	"github.com/irootkernel/kkachi-agent-review/internal/app/prompt"
	"github.com/irootkernel/kkachi-agent-review/internal/app/review"
)

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
func compileInputForReview(scope prompt.ScopeCoordinates, input ImmutableReviewInput) prompt.CompileInput {
	compileInput := prompt.CompileInput{Scope: scope, ReviewTarget: prompt.NewPayload(input.Target().Bytes())}
	if input.HasProjectContext() {
		project := prompt.NewPayload(input.ProjectContext())
		compileInput.ProjectContext = &project
	}
	return compileInput
}
