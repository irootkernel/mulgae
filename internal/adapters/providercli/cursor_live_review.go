package providercli

import (
	"context"
	"fmt"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

// cursorLiveReadAuthority admits Cursor reads from the app-owned live plan.
// Git execution is limited to the exact GitCommand strings on that plan.
// Workspace paths are admitted without body reads only for LiveSourceWorkspace.
type cursorLiveReadAuthority struct {
	execution   ports.LiveReviewExecution
	gitCommands map[string]bool
}

func newCursorLiveReadAuthority(ctx context.Context, execution ports.LiveReviewExecution) (*cursorLiveReadAuthority, error) {
	if err := execution.Revalidate(ctx); err != nil {
		return nil, err
	}
	authority := &cursorLiveReadAuthority{execution: execution, gitCommands: liveReadPlanGitCommands(execution.Reads())}
	return authority, nil
}

func (authority *cursorLiveReadAuthority) allowGit(command string) error {
	if authority == nil || !authority.gitCommands[command] {
		return fmt.Errorf("cursor git command is outside the live read plan")
	}
	return nil
}

func (authority *cursorLiveReadAuthority) allowWorkspacePath(ctx context.Context, path string) error {
	if authority == nil {
		return fmt.Errorf("missing cursor live read authority")
	}
	if err := authority.execution.Revalidate(ctx); err != nil {
		return err
	}
	if authority.execution.Target().Selector().Scope() != domain.LiveSourceWorkspace || !validCanonicalAbsolute(path) {
		return fmt.Errorf("cursor path is outside the workspace read plan")
	}
	return admitLiveWorkspaceFile(ctx, authority.execution, path)
}
