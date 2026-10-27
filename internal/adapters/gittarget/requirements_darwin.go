//go:build darwin && arm64

package gittarget

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/irootkernel/mulgae/internal/ports"
)

var _ ports.RequirementsInputReader = (*liveSourceReader)(nil)

// ReadRequirementsInput uses the local project descriptor, independently of
// index/commit membership. Only ignore configuration is bounded; the selected
// input body has no product byte ceiling and is read once.
func (reader *liveSourceReader) ReadRequirementsInput(ctx context.Context, path ports.SafeRelativePath) ([]byte, error) {
	reader.mu.Lock()
	defer reader.mu.Unlock()
	if ctx == nil || !path.Valid() {
		return nil, sourceError(ports.LiveSourceInvalid, fmt.Errorf("invalid requirements path"))
	}
	if _, err := livePath(path.String()); err != nil {
		return nil, err
	}
	if err := reader.revalidate(ctx); err != nil {
		return nil, err
	}
	if reader.excluded(path.String()) {
		return nil, sourceError(ports.LiveSourceUnsafe, fmt.Errorf("protected requirements input"))
	}
	var rules []workspaceIgnoreRule
	addRules := func(data []byte, base string) error {
		if !utf8.Valid(data) || strings.IndexByte(string(data), 0) >= 0 {
			return fmt.Errorf("invalid requirements ignore configuration")
		}
		if reader.gitDir.Valid() {
			return nil
		}
		nested, err := compileWorkspaceIgnore(data, base)
		rules = append(rules, nested...)
		return err
	}
	if reader.gitDir.Valid() {
		if err := reader.checkGitMetadata(); err != nil {
			return nil, sourceError(ports.LiveSourceUnsafe, err)
		}
		data, err := readCanonicalGitMetadata(filepath.Join(reader.lease.Observation().CommonDirectory.String(), "info", "exclude"))
		if err == nil {
			if err := addRules(data, ""); err != nil {
				return nil, sourceError(ports.LiveSourceUnsafe, err)
			}
		} else if !os.IsNotExist(err) {
			return nil, sourceError(ports.LiveSourceUnsafe, err)
		}
	}
	parts := strings.Split(path.String(), "/")
	relative := ""
	var input []byte
	inputRead := false
	for index, part := range parts {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		ignore, err := ports.NewSafeRelativePath(filepath.ToSlash(filepath.Join(relative, ".gitignore")))
		if err != nil {
			return nil, sourceError(ports.LiveSourceUnsafe, err)
		}
		data, err := reader.readRegularWithLimit(ignore, 256<<10)
		if err == nil {
			if ignore == path {
				input, inputRead = data, true
			}
			if err := addRules(data, relative); err != nil {
				return nil, sourceError(ports.LiveSourceUnsafe, err)
			}
		} else if !os.IsNotExist(err) {
			return nil, sourceError(ports.LiveSourceUnsafe, err)
		}
		relative = filepath.ToSlash(filepath.Join(relative, part))
		if reader.excluded(relative) {
			return nil, sourceError(ports.LiveSourceUnsafe, fmt.Errorf("excluded requirements input"))
		}
		ignored, err := reader.requirementsIgnored(ctx, relative, index < len(parts)-1, rules)
		if err != nil {
			return nil, sourceError(ports.LiveSourceUnsafe, err)
		}
		if ignored {
			return nil, sourceError(ports.LiveSourceUnsafe, fmt.Errorf("ignored requirements input"))
		}
	}
	if !inputRead {
		var err error
		input, err = reader.readRegular(path)
		if err != nil {
			return nil, sourceError(ports.LiveSourceUnsafe, err)
		}
	}
	if err := reader.revalidate(ctx); err != nil {
		return nil, err
	}
	return input, nil
}

func (reader *liveSourceReader) requirementsIgnored(ctx context.Context, path string, directory bool, rules []workspaceIgnoreRule) (bool, error) {
	if !reader.gitDir.Valid() {
		return workspaceIgnored(path, directory, rules), nil
	}
	// check-ignore rejects Git's literal-pathspec switch. Prefixing the operand
	// with './' keeps a leading ':' literal; Git owns ignoreCase and negation.
	operand := "./" + path
	if directory {
		operand += "/"
	}
	_, err := reader.run(ctx, "--no-literal-pathspecs", "check-ignore", "--quiet", "--no-index", "--", operand)
	if err == nil {
		return true, nil
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) && exit.ExitCode() == 1 {
		return false, nil
	}
	return false, err
}
