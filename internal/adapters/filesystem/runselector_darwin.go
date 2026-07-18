//go:build darwin && arm64

package filesystem

import (
	"context"
	"fmt"
	"sort"

	"github.com/irootkernel/kkachi-agent-review/internal/domain"
	"github.com/irootkernel/kkachi-agent-review/internal/ports"
)

// RunCandidate is a canonical session/run directory pair. Its presence says
// only that the namespace is safe to inspect; it grants no publication
// authority.
type RunCandidate struct {
	SessionID domain.SessionID
	RunID     domain.RunID
}

// RunSelectorDiagnostic records an entry the selector deliberately excluded.
// Diagnostics are stable-sorted by path and reason.
type RunSelectorDiagnostic struct {
	Path   string
	Reason string
}

// RunSelector enumerates safe, canonical run directory candidates beneath an
// anchored root. It intentionally does not inspect publication state or decide
// whether a candidate is P2 committed.
type RunSelector struct{}

// NewRunSelector constructs a root-confined candidate enumerator. The optional
// root is accepted for callers that bind construction to a root; Enumerate
// always receives and validates the root used for the operation.
func NewRunSelector(_ ...ports.AnchoredRoot) *RunSelector { return &RunSelector{} }

// Enumerate returns every canonical session/run directory that can be reached
// without following links. Unsafe and malformed entries are excluded and
// reported as diagnostics; an unsafe root or unreadable namespace is an error.
func (selector *RunSelector) Enumerate(ctx context.Context, root ports.AnchoredRoot) ([]RunCandidate, []RunSelectorDiagnostic, error) {
	if selector == nil {
		return nil, nil, fmt.Errorf("run selector: nil selector")
	}
	if ctx == nil {
		return nil, nil, fmt.Errorf("run selector: nil context")
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if !root.Valid() {
		return nil, nil, fmt.Errorf("run selector: invalid root")
	}

	sessionNames, err := listPublicationRoot(root)
	if err != nil {
		return nil, nil, fmt.Errorf("run selector: list root: %w", err)
	}
	candidates := make([]RunCandidate, 0)
	diagnostics := make([]RunSelectorDiagnostic, 0)
	for _, sessionName := range sessionNames {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		sessionID, err := domain.ParseSessionID(sessionName)
		if err != nil {
			diagnostics = append(diagnostics, RunSelectorDiagnostic{Path: sessionName, Reason: "malformed session ID"})
			continue
		}
		runNames, present, err := listPublicationDirectory(root, mustPublicationSafePath(sessionName))
		if err != nil {
			diagnostics = append(diagnostics, RunSelectorDiagnostic{Path: sessionName, Reason: "unsafe session directory"})
			continue
		}
		if !present {
			diagnostics = append(diagnostics, RunSelectorDiagnostic{Path: sessionName, Reason: "missing session directory"})
			continue
		}
		for _, runName := range runNames {
			runPath := sessionName + "/" + runName
			runID, err := domain.ParseRunID(runName)
			if err != nil {
				diagnostics = append(diagnostics, RunSelectorDiagnostic{Path: runPath, Reason: "malformed run ID"})
				continue
			}
			// Opening the child directory verifies both its no-follow traversal and
			// private ownership/mode before it becomes a candidate.
			_, present, err := listPublicationDirectory(root, mustPublicationSafePath(runPath))
			if err != nil {
				diagnostics = append(diagnostics, RunSelectorDiagnostic{Path: runPath, Reason: "unsafe run directory"})
				continue
			}
			if !present {
				diagnostics = append(diagnostics, RunSelectorDiagnostic{Path: runPath, Reason: "missing run directory"})
				continue
			}
			candidates = append(candidates, RunCandidate{SessionID: sessionID, RunID: runID})
		}
	}
	sort.Slice(candidates, func(left, right int) bool {
		if candidates[left].SessionID.String() == candidates[right].SessionID.String() {
			return candidates[left].RunID.String() < candidates[right].RunID.String()
		}
		return candidates[left].SessionID.String() < candidates[right].SessionID.String()
	})
	sort.Slice(diagnostics, func(left, right int) bool {
		if diagnostics[left].Path == diagnostics[right].Path {
			return diagnostics[left].Reason < diagnostics[right].Reason
		}
		return diagnostics[left].Path < diagnostics[right].Path
	})
	return candidates, diagnostics, nil
}
