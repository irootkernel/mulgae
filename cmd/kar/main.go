//go:build darwin && arm64

package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/irootkernel/kkachi-agent-review/internal/adapters/environment"
	"github.com/irootkernel/kkachi-agent-review/internal/adapters/filesystem"
	"github.com/irootkernel/kkachi-agent-review/internal/adapters/gittarget"
	"github.com/irootkernel/kkachi-agent-review/internal/adapters/jsonschema"
	runtimeadapter "github.com/irootkernel/kkachi-agent-review/internal/adapters/runtime"
	"github.com/irootkernel/kkachi-agent-review/internal/builtin"
	"github.com/irootkernel/kkachi-agent-review/internal/entrypoint/kar"
	"github.com/irootkernel/kkachi-agent-review/internal/ports"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	root, err := currentRoot()
	if err != nil {
		fmt.Fprint(os.Stderr, "kar: current directory is unavailable\n")
		os.Exit(10)
	}

	catalog := builtin.NewCatalog()
	validator, err := jsonschema.New(ctx, catalog)
	if err != nil {
		fmt.Fprint(os.Stderr, "kar: embedded contract catalog is unavailable\n")
		os.Exit(10)
	}
	gitAdapter, err := gittarget.New(gittarget.NewExecRunner())
	if err != nil {
		fmt.Fprint(os.Stderr, "kar: trusted project reader is unavailable\n")
		os.Exit(10)
	}
	application, err := kar.NewApplication(kar.Dependencies{
		Clock:                runtimeadapter.SystemClock{},
		RequestIDGenerator:   runtimeadapter.NewUUIDv7Generator(),
		Catalog:              catalog,
		JSONSchemaValidator:  validator,
		SecureWriter:         filesystem.NewSecureWriter(),
		TrustedProjectReader: gitAdapter,
		EnvironmentInspector: environment.NewInspector(),
	})
	if err != nil {
		fmt.Fprint(os.Stderr, "kar: application is unavailable\n")
		os.Exit(10)
	}

	result := application.Run(ctx, os.Args[1:], root.String())
	if _, err := os.Stdout.Write(result.Stdout()); err != nil {
		fmt.Fprint(os.Stderr, "kar: standard output write failed\n")
		os.Exit(10)
	}
	if _, err := os.Stderr.Write(result.Stderr()); err != nil {
		os.Exit(10)
	}
	os.Exit(int(result.ExitCode()))
}

func currentRoot() (ports.AnchoredRoot, error) {
	workingDirectory, err := os.Getwd()
	if err != nil {
		return ports.AnchoredRoot{}, err
	}
	resolved, err := filepath.EvalSymlinks(workingDirectory)
	if err != nil {
		return ports.AnchoredRoot{}, err
	}
	absolute, err := filepath.Abs(resolved)
	if err != nil {
		return ports.AnchoredRoot{}, err
	}
	return ports.NewAnchoredRoot(filepath.Clean(absolute))
}
