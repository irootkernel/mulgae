package init

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/irootkernel/kkachi-agent-review/internal/ports"
)

// RenderProjectYAML renders the complete strict project configuration created
// by init. Provider configuration deliberately belongs to the global layer and
// therefore cannot appear in this document.
func RenderProjectYAML(projectName string, contextPath *ports.SafeRelativePath) ([]byte, error) {
	if err := validateProjectName(projectName); err != nil {
		return nil, fmt.Errorf("render project YAML: project name: %w", err)
	}
	if contextPath != nil && !contextPath.Valid() {
		return nil, fmt.Errorf("render project YAML: invalid context path")
	}

	var document strings.Builder
	document.Grow(len(projectName) + 96)
	document.WriteString("version: 1\n")
	document.WriteString("trusted_base: true\n")
	document.WriteString("project:\n")
	document.WriteString("  name: ")
	document.WriteString(yamlQuote(projectName))
	document.WriteString("\n  root: \".\"\n")
	if contextPath != nil {
		document.WriteString("  context: ")
		document.WriteString(yamlQuote(contextPath.String()))
		document.WriteByte('\n')
	}
	return []byte(document.String()), nil
}

// yamlQuote uses the YAML-supported JSON double-quoted scalar form so values
// cannot become YAML syntax, aliases, tags, booleans, or collection nodes.
func yamlQuote(value string) string {
	return strconv.Quote(value)
}
