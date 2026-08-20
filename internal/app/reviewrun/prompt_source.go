package reviewrun

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/irootkernel/mulgae/internal/app/prompt"
	"github.com/irootkernel/mulgae/internal/app/review"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

// ProductionPromptSource is the shared current-template prompt authority for
// root, delta, recomposed rerun, and exact replay execution.
type ProductionPromptSource = promptSource

// NewProductionPromptSource constructs a child-workflow prompt authority from
// one P2- or capture-bound immutable target. It grants no staging authority, so
// every launch it composes keeps the stdout transport.
func NewProductionPromptSource(input ImmutableReviewInput, templates review.TemplateSet, ids prompt.InvocationIDIssuer, roleTask func() (prompt.RoleTaskID, error)) (*ProductionPromptSource, error) {
	return newPromptSource(input, templates, ids, roleTask, nil)
}

// NewProductionPromptSourceWithStaging constructs the same child-workflow
// prompt authority bound to the adapter-owned staging locator. Every staged
// launch states its own resolved destination; exact replay preserves stored
// frames while rebinding only that Mulgae-owned per-launch transport layer.
func NewProductionPromptSourceWithStaging(input ImmutableReviewInput, templates review.TemplateSet, ids prompt.InvocationIDIssuer, roleTask func() (prompt.RoleTaskID, error), staging ports.ProviderOutputStagingLocator) (*ProductionPromptSource, error) {
	if nilInterface(staging) {
		return newPromptSource(input, templates, ids, roleTask, nil)
	}
	return newPromptSource(input, templates, ids, roleTask, staging)
}

type promptSource struct {
	input     ImmutableReviewInput
	templates review.TemplateSet
	ids       prompt.InvocationIDIssuer
	roleTask  func() (prompt.RoleTaskID, error)
	objective *prompt.Objective
	// staging is the adapter-owned locator that decides, per launch, whether the
	// provider must write its report to a Mulgae-chosen staged file. It is nil
	// for every stdout composition, which leaves the trusted template untouched.
	staging ports.ProviderOutputStagingLocator
}

func newPromptSource(input ImmutableReviewInput, templates review.TemplateSet, ids prompt.InvocationIDIssuer, roleTask func() (prompt.RoleTaskID, error), staging ports.ProviderOutputStagingLocator) (*promptSource, error) {
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
	captured, err := NewImmutableReviewInputWithCapturedArchive(input.Target(), input.Objective(), input.HasObjective(), input.ProjectContext(), input.HasProjectContext(), input.CapturedArchive())
	if err != nil {
		return nil, err
	}
	return &promptSource{input: captured, templates: templates, ids: ids, roleTask: roleTask, objective: objective, staging: staging}, nil
}

// composeOutputDestination appends the Mulgae-owned output destination layer as
// the last trusted layer whenever the locator declares the staged_file transport
// for this exact launch. Separate launches of one attempt resolve to different
// absolute paths, so each launch states its own.
func (source *promptSource) composeOutputDestination(template prompt.TrustedTemplate, job review.InvocationJob) (prompt.TrustedTemplate, error) {
	destination, staged := review.ResolveStagedOutputDestination(source.staging, job)
	if !staged {
		return template, nil
	}
	return review.ComposeRootReviewOutputDestination(template, destination)
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
	if template, err = source.composeOutputDestination(template, job); err != nil {
		return review.RuntimePrompt{}, err
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
	compileInput := compileInputForReview(scope, source.input, job.Role())
	if repair != nil {
		prior := prompt.NewPayload(repair.InitialCandidate())
		compileInput.PriorProviderOutput = &prior
	}
	compiled, err := compiler.Compile(compileInput)
	if err != nil {
		return review.RuntimePrompt{}, err
	}
	return review.RuntimePrompt{
		Prompt: compiled, Target: source.input.Target().Bytes(), CapturedArchive: source.input.CapturedArchive(), AdapterProfile: "root-review",
		AdapterParameters: map[string]string{prompt.TrustedLayerManifestAdapterParameter: manifest},
	}, nil
}

// ExtractionPrompt composes the structured extraction trailer for one already
// accepted role report. The report travels as an untrusted prior-report frame,
// never as a trusted layer, and the immutable review-target frame is retained so
// the provider can re-read exact target bytes for every evidence quote. The
// trailer always uses stdout, so no output-destination layer is appended.
func (source *promptSource) ExtractionPrompt(ctx context.Context, job review.InvocationJob, extraction review.InvocationExtractionInput) (review.RuntimePrompt, error) {
	if source == nil || ctx == nil {
		return review.RuntimePrompt{}, fmt.Errorf("review run: extraction prompt source is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return review.RuntimePrompt{}, err
	}
	report := extraction.AcceptedReport()
	if len(report) == 0 {
		return review.RuntimePrompt{}, fmt.Errorf("review run: extraction requires an accepted role report")
	}
	template, err := source.templates.ComposeRootReview(job.Role(), source.objective)
	if err != nil {
		return review.RuntimePrompt{}, err
	}
	template, err = source.templates.ComposeRootReviewExtraction(template)
	if err != nil {
		return review.RuntimePrompt{}, err
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
	compileInput := compileInputForReview(scope, source.input, job.Role())
	prior := prompt.NewPayload(report)
	compileInput.PriorReport = &prior
	compiled, err := compiler.Compile(compileInput)
	if err != nil {
		return review.RuntimePrompt{}, err
	}
	return review.RuntimePrompt{
		Prompt: compiled, Target: source.input.Target().Bytes(), CapturedArchive: source.input.CapturedArchive(), AdapterProfile: "root-review",
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
	if template, err = source.composeOutputDestination(template, job); err != nil {
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
	sourcePayload := prompt.NewPayload(material.SourceTarget)
	deltaPayload := prompt.NewPayload(material.Delta)
	input := prompt.CompileInput{Scope: scope, ProjectContext: &sourcePayload, ReviewTarget: prompt.NewPayload(reviewTargetReferenceIdentity(job.Target(), len(material.CurrentTarget))), PriorReport: &deltaPayload}
	_, _, artistContext := splitArtistPromptContext(source.input)
	applyArtistPromptInputs(&input, artistContext, job.Role())
	if repair != nil {
		prior := prompt.NewPayload(repair.InitialCandidate())
		input.PriorProviderOutput = &prior
	}
	compiled, err := compiler.Compile(input)
	if err != nil {
		return review.RuntimePrompt{}, err
	}
	return review.RuntimePrompt{Prompt: compiled, Target: append([]byte(nil), material.CurrentTarget...), CapturedArchive: source.input.CapturedArchive(), AdapterProfile: "root-review", AdapterParameters: map[string]string{prompt.TrustedLayerManifestAdapterParameter: manifest}}, nil
}

// ExactReplayPrompt validates persisted stdin as a canonical packet, preserves
// its framed source authority, and mints a fresh execution identity. A staged
// provider also receives a freshly rebound Mulgae-owned output destination
// because the source attempt's isolated directory no longer exists.
func (source *promptSource) ExactReplayPrompt(ctx context.Context, job review.InvocationJob, input review.ExactReplayInput) (review.RuntimePrompt, error) {
	if source == nil || ctx == nil || job.Role() != input.Role || job.Route().ProviderInstance() != input.SourceProviderInstance {
		return review.RuntimePrompt{}, fmt.Errorf("review run: exact replay prompt authority mismatch")
	}
	if err := ctx.Err(); err != nil {
		return review.RuntimePrompt{}, err
	}
	marker := []byte("\nMulgae-FRAMES/1\n")
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
	priorExecution, err := prompt.ParseExecutionInvocationID(input.SourceExecutionInvocationID)
	if err != nil {
		return review.RuntimePrompt{}, err
	}
	adapterParameters := make(map[string]string, len(input.AdapterParameters))
	for key, value := range input.AdapterParameters {
		adapterParameters[key] = value
	}
	replayTemplate := template
	destination, staged := review.ResolveStagedOutputDestination(source.staging, job)
	if staged {
		persistedManifest, ok := adapterParameters[prompt.TrustedLayerManifestAdapterParameter]
		if !ok {
			return review.RuntimePrompt{}, fmt.Errorf("review run: exact replay staged source has no trusted layer manifest")
		}
		template, err = prompt.RestoreTrustedLayerManifest(template, persistedManifest)
		if err != nil {
			return review.RuntimePrompt{}, err
		}
		replayTemplate, err = review.RebindRootReviewOutputDestination(template, destination)
		if err != nil {
			return review.RuntimePrompt{}, err
		}
		manifest, manifestErr := replayTemplate.TrustedLayerManifestJSON()
		if manifestErr != nil {
			return review.RuntimePrompt{}, fmt.Errorf("review run: exact replay trusted layer manifest: %w", manifestErr)
		}
		adapterParameters[prompt.TrustedLayerManifestAdapterParameter] = manifest
	}
	compiler, err := prompt.NewCompiler(replayTemplate, source.ids)
	if err != nil {
		return review.RuntimePrompt{}, err
	}
	var replayed prompt.CompiledPrompt
	if staged {
		replayed, err = compiler.ReplayStoredWithReboundTemplate(template, input.Stdin, priorExecution)
	} else {
		replayed, err = compiler.ReplayStored(input.Stdin, priorExecution)
	}
	if err != nil {
		return review.RuntimePrompt{}, err
	}
	return review.RuntimePrompt{Prompt: replayed, Target: source.input.Target().Bytes(), CapturedArchive: source.input.CapturedArchive(), AdapterProfile: input.AdapterProfile, AdapterParameters: adapterParameters}, nil
}
func compileInputForReview(scope prompt.ScopeCoordinates, input ImmutableReviewInput, role domain.Role) prompt.CompileInput {
	compileInput := prompt.CompileInput{Scope: scope, ReviewTarget: prompt.NewPayload(reviewTargetReference(input.Target()))}
	projectContext, hasProjectContext, artistContext := splitArtistPromptContext(input)
	if hasProjectContext {
		project := prompt.NewPayload(projectContext)
		compileInput.ProjectContext = &project
	}
	applyArtistPromptInputs(&compileInput, artistContext, role)
	return compileInput
}

func reviewTargetReference(target ports.CapturedReviewTarget) []byte {
	if target.NoChange() {
		return nil
	}
	return reviewTargetReferenceIdentity(target.Identity(), len(target.Bytes()))
}

func reviewTargetReferenceIdentity(identity domain.TargetIdentity, size int) []byte {
	wire := struct {
		SchemaVersion string `json:"schema_version"`
		Path          string `json:"path"`
		SHA256        string `json:"sha256"`
		Size          int    `json:"size"`
	}{
		SchemaVersion: "mulgae-review-target-reference.v1",
		Path:          ports.WorkspaceReviewTargetName,
		SHA256:        "sha256:" + identity.SHA256(),
		Size:          size,
	}
	bytes, _ := json.Marshal(wire)
	return bytes
}

type artistPromptManifest struct {
	SchemaVersion string          `json:"schema_version"`
	Status        string          `json:"status"`
	TaskPath      string          `json:"task_path"`
	Task          string          `json:"task"`
	VisualAssets  json.RawMessage `json:"visual_assets"`
}

func splitArtistPromptContext(input ImmutableReviewInput) (project []byte, hasProject bool, artist []byte) {
	if !input.HasProjectContext() {
		return nil, false, nil
	}
	raw := input.ProjectContext()
	index := bytes.LastIndexByte(raw, '\n')
	candidate := raw
	if index >= 0 {
		candidate = raw[index+1:]
	}
	var manifest artistPromptManifest
	if json.Unmarshal(candidate, &manifest) != nil || manifest.SchemaVersion != "mulgae-artist-inputs.v1" {
		return raw, true, nil
	}
	if index < 0 {
		return nil, false, candidate
	}
	return append([]byte(nil), raw[:index]...), index > 0, append([]byte(nil), candidate...)
}

func applyArtistPromptInputs(compileInput *prompt.CompileInput, raw []byte, role domain.Role) {
	if compileInput == nil || role != domain.RoleArtist || len(raw) == 0 {
		return
	}
	var manifest artistPromptManifest
	if json.Unmarshal(raw, &manifest) != nil || manifest.SchemaVersion != "mulgae-artist-inputs.v1" {
		return
	}
	task := prompt.NewPayload([]byte(manifest.Task))
	compileInput.TaskRequirements = &task
	visual, err := json.Marshal(struct {
		SchemaVersion string          `json:"schema_version"`
		Status        string          `json:"status"`
		TaskPath      string          `json:"task_path"`
		VisualAssets  json.RawMessage `json:"visual_assets"`
	}{manifest.SchemaVersion, manifest.Status, manifest.TaskPath, manifest.VisualAssets})
	if err == nil {
		payload := prompt.NewPayload(visual)
		compileInput.VisualAssetsManifest = &payload
	}
}
