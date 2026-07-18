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
	appquery "github.com/irootkernel/kkachi-agent-review/internal/app/query"
	appreport "github.com/irootkernel/kkachi-agent-review/internal/app/report"
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
	clock := runtimeadapter.SystemClock{}
	ids := runtimeadapter.NewUUIDv7Generator()
	writer := filesystem.NewSecureWriter()
	publicationStore, err := filesystem.NewPublicationStore(validator, clock, ids, writer)
	if err != nil {
		fmt.Fprint(os.Stderr, "kar: publication store is unavailable\n")
		os.Exit(10)
	}
	queryService, err := appquery.NewService(publicationStore, validator, nil, 8<<20)
	if err != nil {
		fmt.Fprint(os.Stderr, "kar: publication query service is unavailable\n")
		os.Exit(10)
	}
	reportService, err := appreport.NewService(queryService)
	if err != nil {
		fmt.Fprint(os.Stderr, "kar: publication report service is unavailable\n")
		os.Exit(10)
	}
	application, err := kar.NewApplication(kar.Dependencies{
		Clock:                clock,
		RequestIDGenerator:   ids,
		Catalog:              catalog,
		JSONSchemaValidator:  validator,
		SecureWriter:         writer,
		TrustedProjectReader: gitAdapter,
		EnvironmentInspector: environment.NewInspector(),
		// SOT defines no canonical non-hidden production evidence source, so standalone
		// KAR remains fail-closed until one is standardized.
		EvidenceReader:     nil,
		PublicationQueries: kar.NewPublicationQueryService(queryService),
		PublicationReports: kar.NewPublicationReportService(reportService),
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
