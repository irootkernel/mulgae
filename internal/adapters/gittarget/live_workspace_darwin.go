//go:build darwin && arm64

package gittarget

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/irootkernel/mulgae/internal/ports"
)

// Non-Git workspace selection preserves local .gitignore interpretation.
// .mulgaeignore is ordinary content in this dark path, never selection policy.
func (reader *liveSourceReader) workspacePaths(ctx context.Context) ([]ports.SafeRelativePath, error) {
	paths := make(map[string]ports.GitObjectID)
	var walk func(string, []workspaceIgnoreRule) error
	walk = func(relative string, rules []workspaceIgnoreRule) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		ignorePath, err := ports.NewSafeRelativePath(filepath.ToSlash(filepath.Join(relative, ".gitignore")))
		if err != nil {
			return sourceError(ports.LiveSourceUnsafe, err)
		}
		// Ignore configuration is bounded independently of source bodies.
		data, ignoreErr := reader.readRegularWithLimit(ignorePath, 256<<10)
		if ignoreErr == nil {
			if !utf8.Valid(data) || strings.IndexByte(string(data), 0) >= 0 {
				return sourceError(ports.LiveSourceUnsafe, fmt.Errorf("invalid workspace ignore configuration"))
			}
			nested, err := compileWorkspaceIgnore(data, relative)
			if err != nil {
				return sourceError(ports.LiveSourceInvalid, err)
			}
			rules = append(append([]workspaceIgnoreRule(nil), rules...), nested...)
		} else if !os.IsNotExist(ignoreErr) {
			return sourceError(ports.LiveSourceUnsafe, ignoreErr)
		}
		fd, err := reader.openPath(relative, true)
		if err != nil {
			return sourceError(ports.LiveSourceUnsafe, err)
		}
		directory := os.NewFile(uintptr(fd), relative)
		defer directory.Close()
		var directories []string
		for {
			entries, readErr := directory.ReadDir(256)
			if readErr != nil && !errors.Is(readErr, io.EOF) {
				return sourceError(ports.LiveSourceUnavailable, readErr)
			}
			for _, entry := range entries {
				if err := ctx.Err(); err != nil {
					return err
				}
				value := filepath.ToSlash(filepath.Join(relative, entry.Name()))
				if reader.excluded(value) {
					continue
				}
				ignored := workspaceIgnored(value, rules)
				if entry.Type()&os.ModeSymlink != 0 {
					if !ignored {
						return sourceError(ports.LiveSourceUnsafe, fmt.Errorf("selected workspace symlink"))
					}
					continue
				}
				if entry.IsDir() {
					directories = append(directories, value)
					continue
				}
				if ignored {
					continue
				}
				if !entry.Type().IsRegular() {
					return sourceError(ports.LiveSourceUnsafe, fmt.Errorf("selected workspace special file"))
				}
				if _, err := livePath(value); err != nil {
					return err
				}
				paths[value] = ports.GitObjectID{}
			}
			if errors.Is(readErr, io.EOF) {
				break
			}
		}
		if err := directory.Close(); err != nil {
			return sourceError(ports.LiveSourceUnavailable, err)
		}
		for _, value := range directories {
			if err := walk(value, rules); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk("", nil); err != nil {
		return nil, err
	}
	return liveSortedPaths(paths)
}
