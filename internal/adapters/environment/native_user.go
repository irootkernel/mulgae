package environment

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
)

// buildNativeHomeOverride is empty in production builds. Non-release
// integration binaries may set it with -ldflags so provider fixtures never
// inspect credentials from the installed user's real home.
var buildNativeHomeOverride string

// InstalledUser returns the process owner and its build-bound native home.
func InstalledUser() (*user.User, error) {
	installed, err := user.Current()
	if err != nil || installed == nil || buildNativeHomeOverride == "" {
		return installed, err
	}
	info, statErr := os.Stat(buildNativeHomeOverride)
	if statErr != nil || !info.IsDir() || !filepath.IsAbs(buildNativeHomeOverride) || filepath.Clean(buildNativeHomeOverride) != buildNativeHomeOverride {
		return nil, fmt.Errorf("invalid build native home override")
	}
	copy := *installed
	copy.HomeDir = buildNativeHomeOverride
	return &copy, nil
}
