//go:build darwin && arm64 && (liveprovider || live_zcode_herdr)

package providercli_test

import (
	"os"
	"testing"

	"github.com/irootkernel/mulgae/internal/adapters/herdr"
	"github.com/irootkernel/mulgae/internal/adapters/process"
)

func TestMain(m *testing.M) {
	if handled, err := process.ExecInheritedDirectory(os.Args); handled {
		if err != nil {
			os.Exit(125)
		}
		os.Exit(126)
	}
	if handled, err := herdr.RunWatchdogMode(os.Args); handled {
		if err != nil {
			os.Exit(10)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}
