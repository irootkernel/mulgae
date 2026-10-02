package domain

// LiveSourceScope describes source selection without claiming a captured tree.
type LiveSourceScope string

const (
	LiveSourceWorkspace LiveSourceScope = "workspace"
	LiveSourceStage     LiveSourceScope = "stage"
	LiveSourceHead      LiveSourceScope = "head"
	LiveSourceCommit    LiveSourceScope = "commit"
	LiveSourceDiff      LiveSourceScope = "diff"
)

func (scope LiveSourceScope) Valid() bool {
	switch scope {
	case LiveSourceWorkspace, LiveSourceStage, LiveSourceHead, LiveSourceCommit, LiveSourceDiff:
		return true
	default:
		return false
	}
}

// LiveSourceSide names the evidence source rather than a materialized directory.
type LiveSourceSide string

const (
	LiveSourceWorktree LiveSourceSide = "worktree"
	LiveSourceIndex    LiveSourceSide = "index"
	LiveSourceBefore   LiveSourceSide = "before"
	LiveSourceAfter    LiveSourceSide = "after"
)
