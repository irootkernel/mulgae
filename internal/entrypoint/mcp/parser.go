package mcpentry

import (
	"errors"
	"fmt"
	"path/filepath"
)

// ErrUsage marks an invalid MCP command invocation.
var ErrUsage = errors.New("mulgae mcp usage error")

// Command is the parsed MCP command.
type Command struct {
	projectRoot string
}

// ProjectRoot returns the explicitly selected project root, when present.
func (command Command) ProjectRoot() (string, bool) {
	return command.projectRoot, command.projectRoot != ""
}

// Parse parses arguments following the mcp command name.
func Parse(arguments []string) (Command, error) {
	if len(arguments) == 0 {
		return Command{}, nil
	}
	if len(arguments) != 2 || arguments[0] != "--project-root" {
		return Command{}, fmt.Errorf("%w: expected [--project-root ABSOLUTE_PATH]", ErrUsage)
	}
	root := arguments[1]
	if root == "" || !filepath.IsAbs(root) {
		return Command{}, fmt.Errorf("%w: project root must be absolute", ErrUsage)
	}
	return Command{projectRoot: root}, nil
}
