//go:build darwin && arm64

package mulgae

import (
	"encoding/json"
	"fmt"
	"io"
)

type versionOutput struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// HandleVersion handles the project-independent executable version command.
func HandleVersion(
	arguments []string,
	stdout io.Writer,
	stderr io.Writer,
	product string,
	version string,
) (bool, int) {
	jsonOutput := false
	switch {
	case len(arguments) == 1 && arguments[0] == "--version":
	case len(arguments) == 1 && arguments[0] == "version":
	case len(arguments) == 2 && arguments[0] == "version" && arguments[1] == "--json":
		jsonOutput = true
	case len(arguments) > 0 && (arguments[0] == "version" || arguments[0] == "--version"):
		_, _ = io.WriteString(stderr, "mulgae: usage: mulgae version [--json]\n")
		return true, 2
	default:
		return false, 0
	}

	if jsonOutput {
		encoder := json.NewEncoder(stdout)
		encoder.SetEscapeHTML(false)
		if err := encoder.Encode(versionOutput{Name: product, Version: version}); err != nil {
			_, _ = io.WriteString(stderr, "mulgae: version output failed\n")
			return true, 10
		}
		return true, 0
	}
	if _, err := fmt.Fprintf(stdout, "%s %s\n", product, version); err != nil {
		_, _ = io.WriteString(stderr, "mulgae: version output failed\n")
		return true, 10
	}
	return true, 0
}
