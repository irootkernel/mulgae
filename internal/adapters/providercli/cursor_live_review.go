package providercli

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

// cursorLiveReadAuthority admits Cursor reads from the app-owned live plan.
// Git execution is limited to the exact GitCommand strings on that plan.
// Workspace bytes are read only for LiveSourceWorkspace.
type cursorLiveReadAuthority struct {
	execution   ports.LiveReviewExecution
	gitCommands map[string]bool
}

func newCursorLiveReadAuthority(ctx context.Context, execution ports.LiveReviewExecution) (*cursorLiveReadAuthority, error) {
	if err := execution.Revalidate(ctx); err != nil {
		return nil, err
	}
	authority := &cursorLiveReadAuthority{execution: execution, gitCommands: map[string]bool{}}
	for _, read := range execution.Reads() {
		if command := read.GitCommand(); command != "" {
			authority.gitCommands[command] = true
		}
	}
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
	relative, err := filepath.Rel(authority.execution.Binding().Root.String(), path)
	if err != nil {
		return err
	}
	selected, err := ports.NewSafeRelativePath(filepath.ToSlash(relative))
	if err != nil {
		return err
	}
	_, err = authority.execution.SourceReader().Read(ctx, domain.LiveSourceWorktree, selected)
	return err
}
