//go:build darwin && arm64

package main

import (
	"os"

	"github.com/irootkernel/mulgae/internal/composition"
)

var (
	buildVersion  string
	buildRevision string
)

func main() {
	os.Exit(composition.Run(
		os.Args,
		os.Stdin,
		os.Stdout,
		os.Stderr,
		composition.BuildOverrides{Version: buildVersion, Revision: buildRevision},
	))
}
