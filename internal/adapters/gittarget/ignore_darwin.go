//go:build darwin && arm64

package gittarget

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/irootkernel/mulgae/internal/ports"
)

// capturedIgnoreSet binds the exact Git ignore decision that determined which
// untracked files were admitted into a dirty capture.
type capturedIgnoreSet struct {
	eligible map[string]bool
	identity string
}

// capturedIgnorePaths obtains Git's ignore decision once, before worktree
// capture. Its digest is recorded with the snapshot policy so a later ignore
// configuration change cannot be mistaken for the captured decision.
func (adapter *ReviewTargetAdapter) capturedIgnorePaths(ctx context.Context, root ports.AnchoredRoot) (capturedIgnoreSet, error) {
	result, err := adapter.run(ctx, (Command{Dir: root.String(), Args: []string{"-c", "core.attributesFile=/dev/null", "ls-files", "--others", "--exclude-standard", "-z"}}).withSourceSizedStdout())
	if err != nil {
		return capturedIgnoreSet{}, err
	}
	eligible := make(map[string]bool)
	for _, path := range strings.Split(string(result.Stdout), "\x00") {
		if path == "" {
			continue
		}
		if _, err := ports.NewSafeRelativePath(path); err != nil || !utf8.ValidString(path) {
			return capturedIgnoreSet{}, fmt.Errorf("non-canonical untracked path")
		}
		if reservedReviewPath(path) {
			continue
		}
		if eligible[path] {
			return capturedIgnoreSet{}, fmt.Errorf("duplicate untracked path")
		}
		eligible[path] = true
	}
	if err := validateCapturedPathSet(eligible); err != nil {
		return capturedIgnoreSet{}, err
	}
	digest := sha256.Sum256(result.Stdout)
	return capturedIgnoreSet{
		eligible: eligible,
		identity: "git-ls-files-exclude-standard-v1-sha256:" + hex.EncodeToString(digest[:]),
	}, nil
}
