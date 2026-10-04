//go:build darwin && arm64

package e2e

func liveEvidenceReport() string {
	return "# __ROLE__ role report\n\n```json\n" +
		`{"schema_version":"mulgae-provider-review-output.v1","summary":"Two retained evidence indices.","completeness":"complete","limitations":[],"findings":[{"severity":"low","title":"__ROLE__ fixture finding","description":"Preserve the complete original finding.","evidence":[{"current":{"path":"review.go","line_start":1,"line_end":1,"side":"worktree","quote":"package review\n"}},{"current":{"path":"review.go","line_start":3,"line_end":3,"side":"worktree","quote":"const state = \"after\"\n"}}],"recommendation":"Inspect both immutable excerpts.","confidence":"high"}]}` + "\n```\n"
}
