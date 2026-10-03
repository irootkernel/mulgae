package ports

import (
	"context"
	"fmt"
	"strings"

	"github.com/irootkernel/mulgae/internal/domain"
)

// LiveSourceRead names an admitted native read without carrying source bytes.
type LiveSourceRead struct {
	side    domain.LiveSourceSide
	path    SafeRelativePath
	command string
}

func (read LiveSourceRead) Side() domain.LiveSourceSide { return read.side }
func (read LiveSourceRead) Path() SafeRelativePath      { return read.path }
func (read LiveSourceRead) GitCommand() string          { return read.command }

// LiveReviewExecution keeps source and neutral launch authority separate. Its
// target is a selection of original state, never a captured workspace identity.
type LiveReviewExecution struct {
	source      LiveSourceReader
	home        ReviewerHome
	binding     ProjectBindingObservation
	neutral     AnchoredRoot
	target      LiveSourceTarget
	credentials []AnchoredRoot
	reads       []LiveSourceRead
}

func NewLiveReviewExecution(ctx context.Context, source LiveSourceReader, home ReviewerHome, credentials []AnchoredRoot) (LiveReviewExecution, error) {
	if ctx == nil || source == nil || home == nil || !home.Root().Valid() || len(credentials) == 0 {
		return LiveReviewExecution{}, fmt.Errorf("live review execution: missing authority")
	}
	binding, err := source.RevalidateExecution(ctx)
	if err != nil {
		return LiveReviewExecution{}, err
	}
	if !binding.Root.Valid() || binding.Root != source.Root() || binding.RootIdentity.Inode == 0 {
		return LiveReviewExecution{}, fmt.Errorf("live review execution: invalid source binding")
	}
	for _, root := range []AnchoredRoot{binding.Root, home.Root(), binding.GitDirectory, binding.CommonDirectory} {
		if root.Valid() && !validLivePolicyRoot(root) {
			return LiveReviewExecution{}, fmt.Errorf("live review execution: invalid policy root")
		}
	}
	for _, root := range credentials {
		if !validLivePolicyRoot(root) || binding.Root == root || strings.HasPrefix(binding.Root.String(), root.String()+"/") || home.Root() == root || strings.HasPrefix(home.Root().String(), root.String()+"/") {
			return LiveReviewExecution{}, fmt.Errorf("live review execution: invalid credential boundary")
		}
	}
	if err := home.Revalidate(); err != nil {
		return LiveReviewExecution{}, err
	}
	target := source.Target()
	var reads []LiveSourceRead
	afterSide := domain.LiveSourceAfter
	switch target.Selector().Scope() {
	case domain.LiveSourceWorkspace:
		afterSide = domain.LiveSourceWorktree
	case domain.LiveSourceStage:
		afterSide = domain.LiveSourceIndex
	}
	for _, side := range []domain.LiveSourceSide{domain.LiveSourceBefore, afterSide} {
		object := target.Head().String()
		workspace := target.Selector().Scope() == domain.LiveSourceWorkspace
		if side == domain.LiveSourceBefore {
			if workspace || target.EmptyBase() || !target.Base().Valid() {
				continue
			}
			object = target.Base().String()
		} else if target.Selector().Scope() == domain.LiveSourceStage {
			object = ""
		}
		paths, err := source.List(ctx, side)
		if err != nil {
			return LiveReviewExecution{}, err
		}
		for _, path := range paths {
			command := ""
			if !workspace {
				operand := object + ":" + path.String()
				command = "git --no-pager show '" + strings.ReplaceAll(operand, "'", "'\"'\"'") + "'"
			}
			reads = append(reads, LiveSourceRead{side: side, path: path, command: command})
		}
	}
	execution := LiveReviewExecution{source: source, home: home, binding: binding, neutral: home.Root(), target: target, credentials: append([]AnchoredRoot(nil), credentials...), reads: reads}
	if err := execution.Revalidate(ctx); err != nil {
		return LiveReviewExecution{}, err
	}
	return execution, nil
}

func (execution LiveReviewExecution) Valid() bool {
	return execution.source != nil && execution.home != nil && execution.binding.Root.Valid() && execution.neutral.Valid() && len(execution.credentials) != 0
}
func (execution LiveReviewExecution) Binding() ProjectBindingObservation { return execution.binding }
func (execution LiveReviewExecution) ReviewerHome() ReviewerHome         { return execution.home }
func (execution LiveReviewExecution) Target() LiveSourceTarget           { return execution.target }
func (execution LiveReviewExecution) CredentialRoots() []AnchoredRoot {
	return append([]AnchoredRoot(nil), execution.credentials...)
}

func (execution LiveReviewExecution) SourceReader() LiveSourceReader { return execution.source }
func (execution LiveReviewExecution) Reads() []LiveSourceRead {
	return append([]LiveSourceRead(nil), execution.reads...)
}

func (execution LiveReviewExecution) Revalidate(ctx context.Context) error {
	if !execution.Valid() {
		return fmt.Errorf("live review execution: invalid authority")
	}
	binding, err := execution.source.RevalidateExecution(ctx)
	if err != nil {
		return err
	}
	if binding != execution.binding || execution.home.Root() != execution.neutral {
		return fmt.Errorf("live review execution: replaced binding")
	}
	return execution.home.Revalidate()
}

// NewProviderInvocationInLiveSource attaches only already admitted authority.
// It cannot carry the captured-workspace or staged-file execution contracts.
func NewProviderInvocationInLiveSource(invocation ProviderInvocation, execution LiveReviewExecution) (ProviderInvocation, error) {
	if !execution.Valid() || invocation.hasWorkspace || invocation.hasStagedOutput || invocation.hasLiveExecution {
		return ProviderInvocation{}, fmt.Errorf("live provider invocation: incompatible execution authority")
	}
	canonical, err := canonicalProviderInvocation(invocation)
	if err != nil {
		return ProviderInvocation{}, err
	}
	canonical.liveExecution = execution
	canonical.hasLiveExecution = true
	return canonical, nil
}

func (invocation ProviderInvocation) LiveExecution() (LiveReviewExecution, bool) {
	return invocation.liveExecution, invocation.hasLiveExecution
}
