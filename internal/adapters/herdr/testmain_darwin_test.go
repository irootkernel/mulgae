//go:build darwin && arm64

package herdr

import (
	"os"
	"testing"

	processadapter "github.com/irootkernel/mulgae/internal/adapters/process"
)

var testMainHook func(argv []string) (bool, int)

func TestMain(m *testing.M) {
	handled, err := processadapter.ExecInheritedDirectory(os.Args)
	if handled {
		if err != nil {
			os.Exit(125)
		}
		os.Exit(126)
	}
	if handled, err := RunWatchdogMode(os.Args); handled {
		if err != nil {
			os.Exit(10)
		}
		os.Exit(0)
	}
	if testMainHook != nil {
		if hooked, code := testMainHook(os.Args); hooked {
			os.Exit(code)
		}
	}
	os.Exit(m.Run())
}
