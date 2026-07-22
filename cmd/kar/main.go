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
	"strings"
	"syscall"

	"github.com/irootkernel/kkachi-agent-review/internal/adapters/environment"
	"github.com/irootkernel/kkachi-agent-review/internal/adapters/filesystem"
	"github.com/irootkernel/kkachi-agent-review/internal/adapters/gittarget"
	"github.com/irootkernel/kkachi-agent-review/internal/adapters/jsonschema"
	processadapter "github.com/irootkernel/kkachi-agent-review/internal/adapters/process"
	runtimeadapter "github.com/irootkernel/kkachi-agent-review/internal/adapters/runtime"
	appquery "github.com/irootkernel/kkachi-agent-review/internal/app/query"
	appreport "github.com/irootkernel/kkachi-agent-review/internal/app/report"
	"github.com/irootkernel/kkachi-agent-review/internal/app/reviewrun"
	"github.com/irootkernel/kkachi-agent-review/internal/builtin"
	"github.com/irootkernel/kkachi-agent-review/internal/entrypoint/kar"
	"github.com/irootkernel/kkachi-agent-review/internal/ports"
)

var (
	buildProduct string
	buildVersion string
	buildCommit  string
)

func main() {
	handled, err := processadapter.ExecInheritedDirectory(os.Args)
	if handled {
		fmt.Fprint(os.Stderr, "kar: descriptor-bound provider launch failed\n")
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
	exportInstaller, err := filesystem.NewExportInstaller(writer)
	if err != nil {
		fmt.Fprint(os.Stderr, "kar: export installer is unavailable\n")
		os.Exit(10)
	}
	runSelector := filesystem.NewRunSelector(root)
	requestResolver, err := kar.NewG008RequestResolver(root, queryService, runSelector, os.Stdin)
	if err != nil {
		fmt.Fprint(os.Stderr, "kar: G008 request resolver is unavailable\n")
		os.Exit(10)
	}
	g008Dependencies, err := kar.NewG008Dependencies(kar.G008Composition{
		Root:                 root,
		Queries:              queryService,
		RequestResolver:      requestResolver,
		Clock:                clock,
		IDs:                  ids,
		ExportInstaller:      exportInstaller,
		PublicationAuthority: publicationStore,
	})
	if err != nil {
		fmt.Fprint(os.Stderr, "kar: G008 offline services are unavailable\n")
		os.Exit(10)
	}
	build, buildErr := executableBuildIdentity()
	childSources, err := kar.NewG008Sources(root, requestResolver, queryService)
	if err != nil {
		fmt.Fprint(os.Stderr, "kar: child workflow sources are unavailable\n")
		os.Exit(10)
	}
	childComposer := productionChildComposer{
		build: build, root: root, catalog: catalog, validator: validator, projectReader: gitAdapter,
		clock: clock, ids: ids, writer: writer, publicationStore: publicationStore, stdin: requestResolver, sources: childSources,
	}
	startupKimiCodeHome := os.Getenv("KIMI_CODE_HOME")
	startupInspector := environment.NewStartupDiscoveryInspector(os.Getenv("PATH"), startupKimiCodeHome, root)
	reviewRuns := newDeferredReviewRunService(func(reviewContext context.Context, reviewRoot ports.AnchoredRoot) (kar.ReviewRunService, error) {
		if buildErr != nil {
			return nil, unavailableBuildMetadata(buildErr)
		}
		return composeReviewRuns(reviewContext, build, reviewRoot, catalog, validator, gitAdapter, clock, ids, writer, publicationStore, requestResolver)
	})
	application, err := kar.NewApplication(kar.Dependencies{
		Clock:                clock,
		RequestIDGenerator:   ids,
		RequestResolver:      g008Dependencies.RequestResolver,
		Catalog:              catalog,
		JSONSchemaValidator:  validator,
		SecureWriter:         writer,
		TrustedProjectReader: gitAdapter,
		EnvironmentInspector: startupInspector,
		// SOT defines no canonical non-hidden production evidence source, so standalone
		// KAR remains fail-closed until one is standardized.
		EvidenceReader:     nil,
		ReviewRuns:         reviewRuns,
		FollowupRuns:       deferredFollowupRunService{composer: childComposer},
		DeltaRuns:          deferredDeltaRunService{composer: childComposer},
		Reruns:             deferredRerunService{composer: childComposer},
		PublicationQueries: kar.NewPublicationQueryService(queryService),
		PublicationReports: kar.NewPublicationReportService(reportService),
		Retention:          g008Dependencies.Retention,
		Exports:            g008Dependencies.Exports,
	})
	if err != nil {
		fmt.Fprint(os.Stderr, "kar: application is unavailable\n")
		os.Exit(10)
	}

	result := application.Run(ctx, os.Args[1:], root.String())
	os.Exit(deliverResult(os.Stdout, os.Stderr, result, os.Args[1:]))
}

func deliverResult(stdout, stderr io.Writer, result kar.Result, argv []string) int {
	return deliverOutput(stdout, stderr, result.Stdout(), result.Stderr(), int(result.ExitCode()), argv)
}

func deliverOutput(stdout, stderr io.Writer, output, diagnostic []byte, exitCode int, argv []string) int {
	if written, err := stdout.Write(output); err != nil || written != len(output) {
		if len(argv) > 0 && argv[0] == "init" && exitCode == 0 {
			_, _ = io.WriteString(stderr, "kar: init committed .kar/config.yaml; result delivery failed\n")
			return 7
		}
		_, _ = io.WriteString(stderr, "kar: standard output write failed\n")
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
	return buildIdentityFrom(info, buildProduct, buildVersion, buildCommit)
}

func buildIdentityFrom(info *debug.BuildInfo, product, version, commit string) (reviewrun.BuildIdentity, error) {
	if info == nil || strings.TrimSpace(product) != product || product == "" {
		return reviewrun.BuildIdentity{}, fmt.Errorf("product metadata is unavailable")
	}
	if version == "" {
		version = info.Main.Version
	}
	if version == "" || version == "(devel)" || strings.TrimSpace(version) != version {
		return reviewrun.BuildIdentity{}, fmt.Errorf("release version metadata is unavailable")
	}
	if commit == "" {
		commit = buildSetting(info, "vcs.revision")
		if commit == "" || buildSetting(info, "vcs.modified") != "false" {
			return reviewrun.BuildIdentity{}, fmt.Errorf("clean VCS revision metadata is unavailable")
		}
	}
	if strings.TrimSpace(commit) != commit || commit == "" {
		return reviewrun.BuildIdentity{}, fmt.Errorf("commit metadata is unavailable")
	}
	identity := reviewrun.BuildIdentity{Product: product, Version: version, Commit: commit}
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
