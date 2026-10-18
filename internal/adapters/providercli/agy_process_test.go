//go:build !liveprovider && darwin && arm64

package providercli

import (
	"os"
	"testing"

	processadapter "github.com/irootkernel/mulgae/internal/adapters/process"
)

// The deterministic AGY kernel fixture uses the same trusted launch trampoline
// as production. Live-provider tests already supply this entrypoint.
func TestMain(m *testing.M) {
	handled, err := processadapter.ExecInheritedDirectory(os.Args)
	if handled {
		if err != nil {
			os.Exit(125)
		}
		os.Exit(126)
	}
	os.Exit(m.Run())
}
