package providercli

import (
	"context"
	"path/filepath"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

func liveReadPlanGitCommands(reads []ports.LiveSourceRead) map[string]bool {
	commands := make(map[string]bool)
	for _, read := range reads {
		if command := read.GitCommand(); command != "" {
			commands[command] = true
		}
	}
	return commands
}

// admitLiveWorkspaceFile follows the caller's family-specific authority,
// revalidation, scope and canonical-path checks. The source reader owns path
// safety and final validation; this translation never reads the file body.
func admitLiveWorkspaceFile(ctx context.Context, execution ports.LiveReviewExecution, absolutePath string) error {
	relative, err := filepath.Rel(execution.Binding().Root.String(), absolutePath)
	if err != nil {
		return err
	}
	selected, err := ports.NewSafeRelativePath(filepath.ToSlash(relative))
	if err != nil {
		return err
	}
	return execution.SourceReader().AdmitPath(ctx, domain.LiveSourceWorktree, selected)
}
