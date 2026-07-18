package kar

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"crypto/sha256"
	"encoding/hex"
	appdelta "github.com/irootkernel/kkachi-agent-review/internal/app/delta"
	appfollowup "github.com/irootkernel/kkachi-agent-review/internal/app/followup"
	appquery "github.com/irootkernel/kkachi-agent-review/internal/app/query"
	apprerun "github.com/irootkernel/kkachi-agent-review/internal/app/rerun"
	"github.com/irootkernel/kkachi-agent-review/internal/app/review"
	"github.com/irootkernel/kkachi-agent-review/internal/domain"
	"github.com/irootkernel/kkachi-agent-review/internal/ports"
)

// G008RunResolver resolves an already-canonical source ID beneath the current
// anchored artifact root. It intentionally has no filesystem or selector
// authority of its own.
type G008RunResolver interface {
	ResolvePublicationRun(context.Context, ports.AnchoredRoot, domain.RunID) (ports.PublicationRun, error)
}

// G008Sources is the root-bound P2 source authority shared by G008 wiring.
// It has no mutable target, provider-output, or publication-write fallback.
type G008Sources struct {
	root     ports.AnchoredRoot
	resolver G008RunResolver
	query    *appquery.Service
}

func NewG008Sources(root ports.AnchoredRoot, resolver G008RunResolver, query *appquery.Service) (*G008Sources, error) {
	if !root.Valid() || resolver == nil || query == nil {
		return nil, fmt.Errorf("g008 sources: root, resolver, and query are required")
	}
	return &G008Sources{root: root, resolver: resolver, query: query}, nil
}

// G008RuntimePromptSource is the production prompt-source seam for child
// delta and exact replay execution. Prompt construction is supplied explicitly;
// this source verifies all persisted P2 authority before forwarding it.
type G008RuntimePromptSource struct {
	sources *G008Sources
	prompts review.InvocationPromptSource
	delta   review.DeltaInvocationPromptSource
	replay  review.ExactReplayPromptSource
}

// NewG008RuntimePromptSource requires distinct ordinary, delta-aware, and
// exact-replay prompt authorities. No mode falls back to another authority.
func NewG008RuntimePromptSource(
	sources *G008Sources,
	prompts review.InvocationPromptSource,
	delta review.DeltaInvocationPromptSource,
	replay review.ExactReplayPromptSource,
) (*G008RuntimePromptSource, error) {
	if sources == nil || prompts == nil || delta == nil || replay == nil {
		return nil, fmt.Errorf("g008 runtime prompt source: all prompt authorities are required")
	}
	return &G008RuntimePromptSource{sources: sources, prompts: prompts, delta: delta, replay: replay}, nil
}

func (source *G008RuntimePromptSource) Prompt(ctx context.Context, job review.InvocationJob, repair *review.InvocationRepairInput) (review.RuntimePrompt, error) {
	if source == nil || source.prompts == nil {
		return review.RuntimePrompt{}, fmt.Errorf("g008 runtime prompt source: ordinary prompt authority is required")
	}
	return source.prompts.Prompt(ctx, job, repair)
}

func (source *G008RuntimePromptSource) DeltaPrompt(ctx context.Context, job review.InvocationJob, material review.DeltaInvocationMaterial, repair *review.InvocationRepairInput) (review.RuntimePrompt, error) {
	if source == nil || source.sources == nil || source.delta == nil {
		return review.RuntimePrompt{}, fmt.Errorf("g008 runtime prompt source: delta prompt authority is required")
	}
	snapshot, err := source.sources.ReadSource(ctx, material.SourceRunID)
	if err != nil {
		return review.RuntimePrompt{}, fmt.Errorf("g008 runtime prompt source: read delta source: %w", err)
	}
	if snapshot.Target.Identity() != material.SourceTargetIdentity ||
		string(snapshot.Target.Bytes()) != string(material.SourceTarget) ||
		material.CurrentTargetIdentity != job.Target() {
		return review.RuntimePrompt{}, fmt.Errorf("g008 runtime prompt source: delta authority mismatch")
	}
	return source.delta.DeltaPrompt(ctx, job, material, repair)
}

func (source *G008RuntimePromptSource) ExactReplayPrompt(ctx context.Context, job review.InvocationJob, input review.ExactReplayInput) (review.RuntimePrompt, error) {
	if source == nil || source.sources == nil || source.replay == nil {
		return review.RuntimePrompt{}, fmt.Errorf("g008 runtime prompt source: exact replay authority is required")
	}
	stored, err := source.sources.ReadRerunSource(ctx, input.SourceRunID, input.SourceAttemptID)
	if err != nil {
		return review.RuntimePrompt{}, fmt.Errorf("g008 runtime prompt source: read replay source: %w", err)
	}
	if stored.Prompt.Role != string(input.Role) ||
		stored.Prompt.CompleteStdinSHA256 != input.CompleteStdinSHA256 ||
		string(stored.Prompt.ComposedStdin) != string(input.Stdin) ||
		stored.Prompt.SourceInvocationID != input.SourceInvocationID ||
		stored.Prompt.AdapterProfile != input.AdapterProfile ||
		!g008ParametersMatch(stored.Prompt.Parameters, input.AdapterParameters) {
		return review.RuntimePrompt{}, fmt.Errorf("g008 runtime prompt source: exact replay authority mismatch")
	}
	material, err := source.replay.ExactReplayPrompt(ctx, job, input)
	if err != nil {
		return review.RuntimePrompt{}, err
	}
	if material.Prompt.Scope().SourceInvocationID().String() != stored.Prompt.SourceInvocationID ||
		material.Prompt.Scope().ExecutionInvocationID().String() == stored.Prompt.ExecutionInvocationID {
		return review.RuntimePrompt{}, fmt.Errorf("g008 runtime prompt source: replay execution identity mismatch")
	}
	return material, nil
}

func g008ParametersMatch(stored []apprerun.Parameter, supplied map[string]string) bool {
	if len(stored) != len(supplied) {
		return false
	}
	for _, parameter := range stored {
		if supplied[parameter.Name] != parameter.Value {
			return false
		}
	}
	return true
}

var _ review.InvocationPromptSource = (*G008RuntimePromptSource)(nil)
var _ review.DeltaInvocationPromptSource = (*G008RuntimePromptSource)(nil)
var _ review.ExactReplayPromptSource = (*G008RuntimePromptSource)(nil)

func (sources *G008Sources) ReadRerunSource(ctx context.Context, runID domain.RunID, attemptID domain.AttemptID) (apprerun.SourceAttempt, error) {
	if sources == nil || sources.resolver == nil || sources.query == nil {
		return apprerun.SourceAttempt{}, fmt.Errorf("g008 sources: dependencies are required")
	}
	run, err := sources.resolver.ResolvePublicationRun(ctx, sources.root, runID)
	if err != nil {
		return apprerun.SourceAttempt{}, fmt.Errorf("g008 rerun source: resolve run: %w", err)
	}
	attempt, err := sources.query.ReadCommittedAttempt(ctx, run, attemptID)
	if err != nil {
		return apprerun.SourceAttempt{}, fmt.Errorf("g008 rerun source: committed attempt: %w", err)
	}
	if attempt.RunID() != runID || attempt.AttemptID() != attemptID {
		return apprerun.SourceAttempt{}, fmt.Errorf("g008 rerun source: resolved identity mismatch")
	}
	target := attempt.Target()
	prompt := attempt.Prompt()
	source := apprerun.SourceAttempt{
		SessionID: attempt.SessionID(), RunID: attempt.RunID(), ReviewID: attempt.ReviewID(), AttemptID: attempt.AttemptID(), ProviderInstance: attempt.Provider(),
		Target: apprerun.Target{Identity: target.Identity(), Bytes: target.Bytes(), SHA256: target.Identity().SHA256()},
		Prompt: apprerun.PromptManifest{URI: prompt.ManifestPath().String(), SHA256: strings.TrimPrefix(prompt.ManifestSHA256(), "sha256:"),
			ComposedStdin: prompt.Stdin(), ComposedStdinSHA256: strings.TrimPrefix(prompt.StdinSHA256(), "sha256:"),
			CompleteStdinSHA256: prompt.CompleteStdinSHA256(),
			SourceInvocationID:  prompt.SourceInvocationID(), ExecutionInvocationID: prompt.ExecutionInvocationID(),
			AdapterProfile: prompt.AdapterProfile(), Scope: prompt.Scope(), Role: string(prompt.Role())},
	}
	for name, value := range prompt.AdapterParameters() {
		source.Prompt.Parameters = append(source.Prompt.Parameters, apprerun.Parameter{Name: name, Value: value})
	}
	sort.Slice(source.Prompt.Parameters, func(left, right int) bool {
		return source.Prompt.Parameters[left].Name < source.Prompt.Parameters[right].Name
	})
	source.ImmutableSHA256 = apprerun.SourceAttemptSHA256(source)
	return source, nil
}

var _ apprerun.SourceReader = (*G008Sources)(nil)

func (sources *G008Sources) ReadFollowupSource(ctx context.Context, runID domain.RunID, findingID string) (appfollowup.VerifiedSource, error) {
	run, err := sources.resolve(ctx, runID)
	if err != nil {
		return appfollowup.VerifiedSource{}, err
	}
	committed, err := sources.query.ReadCommittedFindingSource(ctx, run, findingID)
	if err != nil {
		return appfollowup.VerifiedSource{}, fmt.Errorf("g008 followup source: %w", err)
	}
	review, finding := committed.Review(), committed.Finding()
	target, err := sources.query.ReadRuntimeTarget(ctx, run)
	if err != nil {
		return appfollowup.VerifiedSource{}, fmt.Errorf("g008 followup target: %w", err)
	}
	confirmed, err := sources.query.ReadCommitted(context.WithoutCancel(ctx), run)
	if err != nil {
		return appfollowup.VerifiedSource{}, fmt.Errorf("g008 followup confirmation: %w", err)
	}
	if confirmed.Epoch() != review.Epoch() ||
		confirmed.FinalSHA256() != review.FinalSHA256() ||
		confirmed.ManifestSHA256() != review.ManifestSHA256() ||
		confirmed.TargetSHA256() != review.TargetSHA256() ||
		strings.TrimPrefix(review.TargetSHA256(), "sha256:") != target.Identity().SHA256() {
		return appfollowup.VerifiedSource{}, fmt.Errorf("g008 followup source: committed P2 identity changed during read")
	}
	return appfollowup.VerifiedSource{
		P2Verified: true, SessionID: review.SessionID(), RunID: review.RunID(), ReviewID: review.ReviewID(),
		Target: target.Identity(), Finding: appfollowup.SourceFinding{ID: finding.ID(), Role: finding.Role(), Normalized: committed.Normalized(), Excerpt: committed.Excerpt()},
		Final: review.FinalBytes(), Manifest: review.ManifestBytes(),
		Receipt: appfollowup.SourceReceipt{
			FinalSHA256: sourceDigest(review.FinalBytes()), ManifestSHA256: sourceDigest(review.ManifestBytes()),
			FindingSHA256: sourceDigest(committed.Normalized()), ExcerptSHA256: sourceDigest(committed.Excerpt()),
		},
	}, nil
}

func (sources *G008Sources) ReadSource(ctx context.Context, runID domain.RunID) (appdelta.SourceSnapshot, error) {
	run, err := sources.resolve(ctx, runID)
	if err != nil {
		return appdelta.SourceSnapshot{}, err
	}
	review, err := sources.query.ReadCommitted(ctx, run)
	if err != nil {
		return appdelta.SourceSnapshot{}, fmt.Errorf("g008 delta source: %w", err)
	}
	target, err := sources.query.ReadRuntimeTarget(ctx, run)
	if err != nil {
		return appdelta.SourceSnapshot{}, fmt.Errorf("g008 delta target: %w", err)
	}
	immutable, err := appdelta.NewP2ImmutableTarget(target.Identity(), target.Bytes())
	if err != nil {
		return appdelta.SourceSnapshot{}, fmt.Errorf("g008 delta target: %w", err)
	}
	roles, err := deltaRoles(review.Roles())
	if err != nil {
		return appdelta.SourceSnapshot{}, err
	}
	return appdelta.SourceSnapshot{
		SessionID: review.SessionID(), RunID: review.RunID(), ReviewID: review.ReviewID(), Roles: roles, Target: immutable,
		FinalSHA256:    strings.TrimPrefix(review.FinalSHA256(), "sha256:"),
		ManifestSHA256: strings.TrimPrefix(review.ManifestSHA256(), "sha256:"),
		Receipt:        strings.Join([]string{review.FinalSHA256(), review.ManifestSHA256(), target.Identity().SHA256()}, "|"),
	}, nil
}

func (sources *G008Sources) resolve(ctx context.Context, runID domain.RunID) (ports.PublicationRun, error) {
	if sources == nil || sources.resolver == nil || sources.query == nil {
		return ports.PublicationRun{}, fmt.Errorf("g008 sources: dependencies are required")
	}
	run, err := sources.resolver.ResolvePublicationRun(ctx, sources.root, runID)
	if err != nil {
		return ports.PublicationRun{}, fmt.Errorf("g008 source: resolve run: %w", err)
	}
	return run, nil
}

func deltaRoles(roles []appquery.Role) ([]domain.RoleTask, error) {
	result := make([]domain.RoleTask, 0, len(roles))
	for _, role := range roles {
		provider, ok := role.ProviderInstance()
		if !ok {
			return nil, fmt.Errorf("g008 delta source: role %q has no persisted provider", role.Name())
		}
		task, err := domain.NewRoleTask(role.Name(), role.Required(), provider, nil)
		if err != nil {
			return nil, fmt.Errorf("g008 delta source: role %q: %w", role.Name(), err)
		}
		result = append(result, task)
	}
	return result, nil
}

func sourceDigest(bytes []byte) string {
	sum := sha256.Sum256(bytes)
	return hex.EncodeToString(sum[:])
}

var _ appfollowup.SourceReader = (*G008Sources)(nil)
var _ appdelta.SourceReader = (*G008Sources)(nil)
