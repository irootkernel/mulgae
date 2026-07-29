//go:build darwin && arm64

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"runtime/debug"
)

const (
	productName = "mulgae"
	modulePath  = "github.com/irootkernel/mulgae"
)

type versionInfo struct {
	SchemaVersion string  `json:"schema_version"`
	Product       string  `json:"product"`
	Version       string  `json:"version"`
	Module        string  `json:"module"`
	ModuleSum     *string `json:"module_sum"`
	VCSRevision   *string `json:"vcs_revision"`
}

func handleVersion(
	arguments []string,
	stdout io.Writer,
	stderr io.Writer,
	info *debug.BuildInfo,
) (bool, int) {
	jsonOutput := false
	switch {
	case len(arguments) == 1 && arguments[0] == "--version":
	case len(arguments) == 1 && arguments[0] == "version":
	case len(arguments) == 3 && arguments[0] == "version" && arguments[1] == "--output" && arguments[2] == "json":
		jsonOutput = true
	case len(arguments) > 0 && (arguments[0] == "version" || arguments[0] == "--version"):
		_, _ = io.WriteString(stderr, "mulgae: usage: mulgae version [--output json]\n")
		return true, 2
	default:
		return false, 0
	}

	version := versionInfoFrom(info, buildVersion, buildRevision)
	if jsonOutput {
		encoder := json.NewEncoder(stdout)
		encoder.SetEscapeHTML(false)
		if err := encoder.Encode(version); err != nil {
			_, _ = io.WriteString(stderr, "mulgae: version output failed\n")
			return true, 10
		}
		return true, 0
	}
	if _, err := fmt.Fprintf(stdout, "%s %s\n", version.Product, version.Version); err != nil {
		_, _ = io.WriteString(stderr, "mulgae: version output failed\n")
		return true, 10
	}
	return true, 0
}

func versionInfoFrom(info *debug.BuildInfo, versionOverride, revisionOverride string) versionInfo {
	result := versionInfo{
		SchemaVersion: "mulgae-version.v1",
		Product:       productName,
		Version:       "(devel)",
		Module:        modulePath,
	}
	if info != nil {
		if info.Main.Version != "" {
			result.Version = info.Main.Version
		}
		if info.Main.Path != "" {
			result.Module = info.Main.Path
		}
		if info.Main.Sum != "" {
			moduleSum := info.Main.Sum
			result.ModuleSum = &moduleSum
		}
		if revision := buildSetting(info, "vcs.revision"); revision != "" &&
			buildSetting(info, "vcs.modified") == "false" {
			result.VCSRevision = &revision
		}
	}
	if versionOverride != "" {
		result.Version = versionOverride
	}
	if revisionOverride != "" {
		result.VCSRevision = &revisionOverride
	}
	return result
}
