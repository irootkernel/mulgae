// Package zcodefixture builds opaque synthetic inputs for offline tests.
package zcodefixture

import (
	"os"
	"path/filepath"
)

// Create builds the Desktop directory and the companion's package tree.
// The caller supplies the executable launcher at the returned path.
func Create(root string) (bundle, launcher string, err error) {
	bundle, launcher = filepath.Join(root, "ZCode.app"), filepath.Join(root, "bin", "herdr-zcode")
	if err := os.MkdirAll(bundle, 0o700); err != nil {
		return "", "", err
	}
	for _, member := range []string{
		"bin/herdr-zcode-app.mjs", "lib/app-server-client.mjs", "lib/app-server-controller.mjs",
		"lib/desktop-account.mjs", "lib/desktop-catalog.mjs", "lib/desktop-keychain.mjs",
		"lib/desktop-runtime.mjs", "lib/error-classification.mjs", "lib/herdr-reporter.mjs",
		"lib/osc7501-reporter.mjs", "lib/prepare-isolated.mjs", "lib/runtime-profile.mjs",
		"lib/toolchain.mjs", "package.json", "scripts/desktop-bootstrap.pl",
		"scripts/tool-bin/npm", "scripts/tool-bin/npx", "scripts/toolchain.sh", "toolchains.env",
	} {
		path := filepath.Join(root, member)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return "", "", err
		}
		if err := os.WriteFile(path, []byte("offline companion fixture\n"), 0o600); err != nil {
			return "", "", err
		}
	}
	return bundle, launcher, nil
}
