//go:build darwin && arm64

package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"syscall"

	"github.com/irootkernel/mulgae/internal/adapters/environment"
	"github.com/irootkernel/mulgae/internal/adapters/filesystem"
	"github.com/irootkernel/mulgae/internal/adapters/gittarget"
	"github.com/irootkernel/mulgae/internal/adapters/jsonschema"
	processadapter "github.com/irootkernel/mulgae/internal/adapters/process"
	runtimeadapter "github.com/irootkernel/mulgae/internal/adapters/runtime"
	appquery "github.com/irootkernel/mulgae/internal/app/query"
	appreport "github.com/irootkernel/mulgae/internal/app/report"
	"github.com/irootkernel/mulgae/internal/app/reviewrun"
	"github.com/irootkernel/mulgae/internal/builtin"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/entrypoint/mulgae"
	"github.com/irootkernel/mulgae/internal/ports"
)

var (
	buildVersion  string
	buildRevision string
)

func main() {
	info, _ := debug.ReadBuildInfo()
	if handled, exitCode := handleVersion(os.Args[1:], os.Stdout, os.Stderr, info); handled {
		os.Exit(exitCode)
	}
	handled, err := processadapter.ExecInheritedDirectory(os.Args)
	if handled {
		fmt.Fprint(os.Stderr, "mulgae: descriptor-bound provider launch failed\n")
		if err != nil {
			os.Exit(10)
		}
		return
	}
	signal.Ignore(syscall.SIGPIPE)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	root, err := currentRoot()
	if err != nil {
		fmt.Fprint(os.Stderr, "mulgae: current directory is unavailable\n")
		os.Exit(10)
	}

	catalog := builtin.NewCatalog()
	validator, err := jsonschema.New(ctx, catalog)
	if err != nil {
		fmt.Fprint(os.Stderr, "mulgae: embedded contract catalog is unavailable\n")
		os.Exit(10)
	}
	gitAdapter, err := gittarget.New(gittarget.NewExecRunner())
	if err != nil {
		fmt.Fprint(os.Stderr, "mulgae: trusted project reader is unavailable\n")
		os.Exit(10)
	}
	clock := runtimeadapter.SystemClock{}
	ids := runtimeadapter.NewUUIDv7Generator()
	writer := filesystem.NewSecureWriter()
	publicationStore, err := filesystem.NewPublicationStore(validator, clock, ids, writer)
	if err != nil {
		fmt.Fprint(os.Stderr, "mulgae: publication store is unavailable\n")
		os.Exit(10)
	}
	queryService, err := appquery.NewService(publicationStore, validator, nil, 8<<20)
	if err != nil {
		fmt.Fprint(os.Stderr, "mulgae: publication query service is unavailable\n")
		os.Exit(10)
	}
	reportService, err := appreport.NewService(queryService)
	if err != nil {
		fmt.Fprint(os.Stderr, "mulgae: publication report service is unavailable\n")
		os.Exit(10)
	}
	exportInstaller, err := filesystem.NewExportInstaller(writer)
	if err != nil {
		fmt.Fprint(os.Stderr, "mulgae: export installer is unavailable\n")
		os.Exit(10)
	}
	runSelector := filesystem.NewRunSelector(root)
	requestResolver, err := mulgae.NewG008RequestResolver(root, queryService, runSelector, os.Stdin)
	if err != nil {
		fmt.Fprint(os.Stderr, "mulgae: G008 request resolver is unavailable\n")
		os.Exit(10)
	}
	g008Dependencies, err := mulgae.NewG008Dependencies(mulgae.G008Composition{
		Root:                 root,
		Queries:              queryService,
		RequestResolver:      requestResolver,
		Clock:                clock,
		IDs:                  ids,
		ExportInstaller:      exportInstaller,
		PublicationAuthority: publicationStore,
	})
	if err != nil {
		fmt.Fprint(os.Stderr, "mulgae: G008 offline services are unavailable\n")
		os.Exit(10)
	}
	build, buildErr := executableBuildIdentity()
	childArtifactRoot, err := childPublicationRoot(root)
	if err != nil {
		fmt.Fprint(os.Stderr, "mulgae: child workflow artifact root is unavailable\n")
		os.Exit(10)
	}
	childSources, err := mulgae.NewG008Sources(childArtifactRoot, productionChildRunResolver{queries: queryService}, queryService)
	if err != nil {
		fmt.Fprint(os.Stderr, "mulgae: child workflow sources are unavailable\n")
		os.Exit(10)
	}
	childComposer := productionChildComposer{
		build: build, root: root, artifactRoot: childArtifactRoot, catalog: catalog, validator: validator, projectReader: gitAdapter,
		clock: clock, ids: ids, writer: writer, publicationStore: publicationStore, stdin: requestResolver, sources: childSources,
	}
	startupKimiCodeHome := os.Getenv("KIMI_CODE_HOME")
	startupInspector := environment.NewStartupDiscoveryInspector(os.Getenv("PATH"), startupKimiCodeHome, root)
	reviewRuns := newDeferredReviewRunServiceWithPreflight(func(reviewContext context.Context, reviewRoot ports.AnchoredRoot) (mulgae.ReviewRunService, error) {
		if buildErr != nil {
			return nil, unavailableBuildMetadata(buildErr)
		}
		return composeReviewRuns(reviewContext, build, reviewRoot, catalog, validator, gitAdapter, clock, ids, writer, publicationStore, requestResolver)
	}, func(reviewContext context.Context, reviewRoot ports.AnchoredRoot) (mulgae.ReviewPreflightService, error) {
		return composeReviewPreflight(reviewContext, reviewRoot, gitAdapter, requestResolver)
	})
	application, err := mulgae.NewApplication(mulgae.Dependencies{
		Clock:                clock,
		RequestIDGenerator:   ids,
		RequestResolver:      g008Dependencies.RequestResolver,
		Catalog:              catalog,
		JSONSchemaValidator:  validator,
		SecureWriter:         writer,
		TrustedProjectReader: gitAdapter,
		EnvironmentInspector: startupInspector,
		// SOT defines no canonical non-hidden production evidence source, so standalone
		// Mulgae remains fail-closed until one is standardized.
		EvidenceReader:     nil,
		ReviewRuns:         reviewRuns,
		FollowupRuns:       deferredFollowupRunService{composer: childComposer},
		DeltaRuns:          deferredDeltaRunService{composer: childComposer},
		Reruns:             deferredRerunService{composer: childComposer},
		PublicationQueries: mulgae.NewPublicationQueryService(queryService),
		DiagnosticQueries:  filesystem.NewDiagnosticStatusReader(),
		PublicationReports: mulgae.NewPublicationReportService(reportService),
		Retention:          g008Dependencies.Retention,
		Exports:            g008Dependencies.Exports,
	})
	if err != nil {
		fmt.Fprint(os.Stderr, "mulgae: application is unavailable\n")
		os.Exit(10)
	}

	result := application.Run(ctx, os.Args[1:], root.String())
	os.Exit(deliverResult(os.Stdout, os.Stderr, result, os.Args[1:]))
}

type productionChildRunResolver struct{ queries *appquery.Service }

func (resolver productionChildRunResolver) ResolvePublicationRun(ctx context.Context, root ports.AnchoredRoot, runID domain.RunID) (ports.PublicationRun, error) {
	if resolver.queries == nil {
		return ports.PublicationRun{}, fmt.Errorf("production child run resolver: query service is required")
	}
	return resolver.queries.ResolveRun(ctx, root, runID)
}

func childPublicationRoot(projectRoot ports.AnchoredRoot) (ports.AnchoredRoot, error) {
	if !projectRoot.Valid() {
		return ports.AnchoredRoot{}, fmt.Errorf("child publication root: invalid project root")
	}
	return ports.NewAnchoredRoot(filepath.Join(projectRoot.String(), ".mulgae"))
}

func deliverResult(stdout, stderr io.Writer, result mulgae.Result, argv []string) int {
	return deliverOutput(stdout, stderr, result.Stdout(), result.Stderr(), int(result.ExitCode()), argv)
}

func deliverOutput(stdout, stderr io.Writer, output, diagnostic []byte, exitCode int, argv []string) int {
	if written, err := stdout.Write(output); err != nil || written != len(output) {
		if len(argv) > 0 && argv[0] == "init" && exitCode == 0 {
			_, _ = io.WriteString(stderr, "mulgae: init committed .mulgae/config.yaml; result delivery failed\n")
			return 7
		}
		_, _ = io.WriteString(stderr, "mulgae: standard output write failed\n")
		return 10
	}
	if _, err := stderr.Write(diagnostic); err != nil {
		return 10
	}
	return exitCode
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

func executableBuildIdentity() (reviewrun.BuildIdentity, error) {
	info, ok := debug.ReadBuildInfo()
	if !ok || info == nil {
		return reviewrun.BuildIdentity{}, fmt.Errorf("build information is unavailable")
	}
	return buildIdentityFrom(info, buildVersion, buildRevision)
}

func buildIdentityFrom(info *debug.BuildInfo, versionOverride, revisionOverride string) (reviewrun.BuildIdentity, error) {
	version := versionInfoFrom(info, versionOverride, revisionOverride)
	if version.Product != productName || version.Module != modulePath {
		return reviewrun.BuildIdentity{}, fmt.Errorf("module metadata is unavailable")
	}
	if version.Version == "" || version.Version == "(devel)" {
		return reviewrun.BuildIdentity{}, fmt.Errorf("release version metadata is unavailable")
	}
	moduleSum := ""
	if version.ModuleSum != nil {
		moduleSum = *version.ModuleSum
	}
	vcsRevision := ""
	if version.VCSRevision != nil {
		vcsRevision = *version.VCSRevision
	}
	identity := reviewrun.BuildIdentity{
		Product:     version.Product,
		Version:     version.Version,
		Module:      version.Module,
		ModuleSum:   moduleSum,
		VCSRevision: vcsRevision,
	}
	if !identity.Valid() {
		return reviewrun.BuildIdentity{}, fmt.Errorf("build metadata is invalid")
	}
	return identity, nil
}

func buildSetting(info *debug.BuildInfo, key string) string {
	for _, setting := range info.Settings {
		if setting.Key == key {
			return setting.Value
		}
	}
	return ""
}
