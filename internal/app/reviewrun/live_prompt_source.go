package reviewrun

import (
	"context"
	"fmt"

	"github.com/irootkernel/mulgae/internal/app/evidence"
	"github.com/irootkernel/mulgae/internal/app/prompt"
	"github.com/irootkernel/mulgae/internal/app/review"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

type livePromptSource struct {
	execution      ports.LiveReviewExecution
	identity       evidence.LiveSourceIdentity
	templates      review.TemplateSet
	common         prompt.TrustedLayer
	objective      *prompt.Objective
	ids            prompt.InvocationIDIssuer
	roleTask       func() (prompt.RoleTaskID, error)
	artist         liveArtistContext
	projectContext []byte
}

func newLivePromptSource(execution ports.LiveReviewExecution, templates review.TemplateSet, common prompt.TrustedLayer, objective []byte, hasObjective bool, ids prompt.InvocationIDIssuer, roleTask func() (prompt.RoleTaskID, error)) (*livePromptSource, error) {
	if !execution.Valid() || nilInterface(ids) || roleTask == nil || !hasObjective && len(objective) != 0 {
		return nil, fmt.Errorf("live review: invalid prompt source")
	}
	identity, err := evidence.NewLiveSourceIdentity(execution.Target())
	if err != nil {
		return nil, err
	}
	source := &livePromptSource{execution: execution, identity: identity, templates: templates, common: common, ids: ids, roleTask: roleTask}
	if hasObjective {
		value := prompt.NewObjective(objective)
		if err := value.Lint().Err(); err != nil {
			return nil, err
		}
		source.objective = &value
	}
	return source, nil
}

func (source *livePromptSource) Prompt(ctx context.Context, job review.InvocationJob, repair *review.InvocationRepairInput) (review.RuntimePrompt, error) {
	return source.compile(ctx, job, repair, nil)
}

func (source *livePromptSource) ExtractionPrompt(ctx context.Context, job review.InvocationJob, extraction review.InvocationExtractionInput) (review.RuntimePrompt, error) {
	report := extraction.AcceptedReport()
	if len(report) == 0 {
		return review.RuntimePrompt{}, fmt.Errorf("live review: extraction requires an accepted report")
	}
	return source.compile(ctx, job, nil, report)
}

func (source *livePromptSource) compile(ctx context.Context, job review.InvocationJob, repair *review.InvocationRepairInput, report []byte) (review.RuntimePrompt, error) {
	if source == nil || ctx == nil {
		return review.RuntimePrompt{}, fmt.Errorf("live review: prompt source unavailable")
	}
	if err := ctx.Err(); err != nil {
		return review.RuntimePrompt{}, err
	}
	target, err := source.identity.RunTarget()
	if err != nil || job.Target() != target {
		return review.RuntimePrompt{}, fmt.Errorf("live review: prompt target mismatch")
	}
	template, err := source.templates.ComposeLiveRootReview(ctx, source.common, source.execution, job.Role(), source.objective)
	if err != nil {
		return review.RuntimePrompt{}, err
	}
	if repair != nil {
		template, err = source.templates.ComposeRootReviewRepair(template, repair.Plan())
	} else if report != nil {
		template, err = source.templates.ComposeRootReviewExtraction(template)
	}
	if err != nil {
		return review.RuntimePrompt{}, err
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
	// The target frame contains only declared source metadata. Source bytes are
	// read from admitted native paths or resolved Git objects during review.
	input := prompt.CompileInput{Scope: scope, ReviewTarget: prompt.NewPayload(source.identity.Bytes())}
	if len(source.projectContext) != 0 {
		context := prompt.NewPayload(source.projectContext)
		input.ProjectContext = &context
	}
	if job.Role() == domain.RoleArtist && len(source.artist.manifest) != 0 {
		task, visual := prompt.NewPayload(source.artist.task), prompt.NewPayload(source.artist.manifest)
		input.TaskRequirements, input.VisualAssetsManifest = &task, &visual
	}
	if repair != nil {
		prior := prompt.NewPayload(repair.InitialCandidate())
		input.PriorProviderOutput = &prior
	}
	if report != nil {
		prior := prompt.NewPayload(report)
		input.PriorReport = &prior
	}
	compiled, err := compiler.Compile(input)
	if err != nil {
		return review.RuntimePrompt{}, err
	}
	return review.RuntimePrompt{Prompt: compiled, Target: source.identity.Bytes(), AdapterProfile: "live-review", AdapterParameters: map[string]string{prompt.TrustedLayerManifestAdapterParameter: manifest}}, nil
}
