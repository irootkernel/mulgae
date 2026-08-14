//go:build darwin && arm64

package composition

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strings"
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
	mcpentry "github.com/irootkernel/mulgae/internal/entrypoint/mcp"
	"github.com/irootkernel/mulgae/internal/entrypoint/mulgae"
	"github.com/irootkernel/mulgae/internal/ports"
)

const (
	productName = "mulgae"
	modulePath  = "github.com/irootkernel/mulgae"
)

// BuildOverrides carries release metadata injected into the executable by the
// release build.
type BuildOverrides struct {
	Version  string
	Revision string
}

// Run composes and executes the production command, returning its process exit
// code to the thin package-main wrapper.
func Run(argv []string, stdin io.Reader, stdout, stderr io.Writer, overrides BuildOverrides) int {
	arguments := []string(nil)
	if len(argv) > 0 {
		arguments = argv[1:]
	}
	info, _ := debug.ReadBuildInfo()
	version := versionInfoFrom(info, overrides.Version, overrides.Revision)
	if handled, exitCode := mulgae.HandleVersion(arguments, stdout, stderr, version.Product, version.Version); handled {
		return exitCode
	}
	handled, err := processadapter.ExecInheritedDirectory(argv)
	if handled {
		writeDiagnostic(stderr, "mulgae: descriptor-bound provider launch failed\n")
		if err != nil {
			return 10
		}
		return 0
	}
	signal.Ignore(syscall.SIGPIPE)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	mcpMode := len(arguments) > 0 && arguments[0] == "mcp"
	root, err := currentRoot()
	if mcpMode {
		command, parseErr := mcpentry.Parse(arguments[1:])
		if parseErr != nil {
			writeDiagnostic(stderr, "mulgae: usage: mulgae mcp [--project-root ABSOLUTE_PATH]\n")
			return 2
		}
		if explicit, present := command.ProjectRoot(); present {
			root, err = canonicalRoot(explicit)
		}
	}
	if err != nil {
		if mcpMode {
			writeDiagnostic(stderr, "mulgae: MCP project root is unavailable\n")
			return 2
		}
		writeDiagnostic(stderr, "mulgae: current directory is unavailable\n")
		return 10
	}
	if err := ports.ValidateResourceLimits(); err != nil {
		writeDiagnostic(stderr, "mulgae: runtime resource limits are incompatible\n")
		return 10
	}

	catalog := builtin.NewCatalog()
	validator, err := jsonschema.New(ctx, catalog)
	if err != nil {
		writeDiagnostic(stderr, "mulgae: embedded contract catalog is unavailable\n")
		return 10
	}
	gitAdapter, err := gittarget.New(gittarget.NewExecRunner())
	if err != nil {
		writeDiagnostic(stderr, "mulgae: trusted project reader is unavailable\n")
		return 10
	}
	clock := runtimeadapter.SystemClock{}
	ids := runtimeadapter.NewUUIDv7Generator()
	writer := filesystem.NewSecureWriter()
	publicationStore, err := filesystem.NewPublicationStore(validator, clock, ids, writer)
	if err != nil {
		writeDiagnostic(stderr, "mulgae: publication store is unavailable\n")
		return 10
	}
	queryService, err := appquery.NewService(publicationStore, validator, nil, ports.PublicationStructuredMemberMaxBytes)
	if err != nil {
		writeDiagnostic(stderr, "mulgae: publication query service is unavailable\n")
		return 10
	}
	reportService, err := appreport.NewService(queryService)
	if err != nil {
		writeDiagnostic(stderr, "mulgae: publication report service is unavailable\n")
		return 10
	}
	exportInstaller, err := filesystem.NewExportInstaller(writer)
	if err != nil {
		writeDiagnostic(stderr, "mulgae: export installer is unavailable\n")
		return 10
	}
	artifactRoot, err := publicationArtifactRoot(root)
	if err != nil {
		writeDiagnostic(stderr, "mulgae: artifact root is unavailable\n")
		return 10
	}
	runSelector := filesystem.NewRunSelector(artifactRoot)
	requestInput := stdin
	if mcpMode {
		requestInput = strings.NewReader("")
	}
	requestResolver, err := mulgae.NewG008RequestResolver(artifactRoot, queryService, runSelector, requestInput)
	if err != nil {
		writeDiagnostic(stderr, "mulgae: G008 request resolver is unavailable\n")
		return 10
	}
	cleanupStore, err := filesystem.NewCleanupStore(artifactRoot, publicationStore, clock)
	if err != nil {
		writeDiagnostic(stderr, "mulgae: cleanup store is unavailable\n")
		return 10
	}
	g008Dependencies, err := mulgae.NewG008Dependencies(mulgae.G008Composition{
		ArtifactRoot:         artifactRoot,
		Queries:              queryService,
		RequestResolver:      requestResolver,
		Clock:                clock,
		IDs:                  ids,
		ExportInstaller:      exportInstaller,
		PublicationAuthority: publicationStore,
		CleanStore:           cleanupStore,
		CleanValidator:       validator,
	})
	if err != nil {
		writeDiagnostic(stderr, "mulgae: G008 offline services are unavailable\n")
		return 10
	}
	build, buildErr := buildIdentityFrom(info, overrides.Version, overrides.Revision)
	childSources, err := mulgae.NewG008Sources(artifactRoot, productionChildRunResolver{queries: queryService}, queryService)
	if err != nil {
		writeDiagnostic(stderr, "mulgae: child workflow sources are unavailable\n")
		return 10
	}
	childComposer := productionChildComposer{
		build: build, root: root, artifactRoot: artifactRoot, catalog: catalog, validator: validator, projectReader: gitAdapter,
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
	publicationQueries := mulgae.NewPublicationQueryService(queryService)
	publicationReports := mulgae.NewPublicationReportService(reportService)
	diagnosticQueries := filesystem.NewDiagnosticStatusReader()
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
		PublicationQueries: publicationQueries,
		DiagnosticQueries:  diagnosticQueries,
		PublicationReports: publicationReports,
		Retention:          g008Dependencies.Retention,
		Exports:            g008Dependencies.Exports,
	})
	if err != nil {
		writeDiagnostic(stderr, "mulgae: application is unavailable\n")
		return 10
	}
	if mcpMode {
		backend, err := newMCPBackend(root, artifactRoot, application, publicationQueries, diagnosticQueries, publicationReports, runSelector)
		if err != nil {
			writeDiagnostic(stderr, "mulgae: MCP application services are unavailable\n")
			return 10
		}
		schemaID, err := ports.ParseAssetID("https://mulgae.local/schemas/mulgae-mcp-tool-result.v1.schema.json")
		if err != nil {
			writeDiagnostic(stderr, "mulgae: MCP result contract is unavailable\n")
			return 10
		}
		_, resultSchema, err := catalog.Read(ctx, schemaID)
		if err != nil {
			writeDiagnostic(stderr, "mulgae: MCP result contract is unavailable\n")
			return 10
		}
		return runMCP(ctx, stdin, stdout, stderr, mcpentry.Config{
			Name: productName, Version: version.Version, ProjectRoot: root.String(), Backend: backend,
			NewRequestID:     func() (string, error) { return ids.NewRequestID(clock.Now()) },
			ToolResultSchema: resultSchema,
		})
	}

	result := application.Run(ctx, arguments, root.String())
	return deliverResult(stdout, stderr, result, arguments)
}

func runMCP(ctx context.Context, stdin io.Reader, stdout, stderr io.Writer, config mcpentry.Config) int {
	if err := mcpentry.Serve(ctx, stdin, stdout, config); err != nil {
		if ctx.Err() != nil {
			return 9
		}
		writeDiagnostic(stderr, "mulgae: MCP transport failed\n")
		return 10
	}
	return 0
}

func writeDiagnostic(stderr io.Writer, message string) {
	_, _ = io.WriteString(stderr, message)
}

type productionChildRunResolver struct{ queries *appquery.Service }

func (resolver productionChildRunResolver) ResolvePublicationRun(ctx context.Context, root ports.AnchoredRoot, runID domain.RunID) (ports.PublicationRun, error) {
	if resolver.queries == nil {
		return ports.PublicationRun{}, fmt.Errorf("production child run resolver: query service is required")
	}
	return resolver.queries.ResolveRun(ctx, root, runID)
}

func publicationArtifactRoot(projectRoot ports.AnchoredRoot) (ports.AnchoredRoot, error) {
	if !projectRoot.Valid() {
		return ports.AnchoredRoot{}, fmt.Errorf("publication artifact root: invalid project root")
	}
	return ports.NewAnchoredRoot(filepath.Join(projectRoot.String(), ".mulgae"))
}

func deliverResult(stdout, stderr io.Writer, result mulgae.Result, argv []string) int {
	if err := result.WriteTo(stdout, stderr); err != nil {
		var writeErr *mulgae.ResultWriteError
		if errors.As(err, &writeErr) && writeErr.Stream() == mulgae.ResultStreamStdout {
			if len(argv) > 0 && argv[0] == "init" && result.ExitCode() == 0 {
				_, _ = io.WriteString(stderr, "mulgae: init committed .mulgae/config.yaml; result delivery failed\n")
				return 7
			}
			_, _ = io.WriteString(stderr, "mulgae: standard output write failed\n")
		}
		return 10
	}
	return int(result.ExitCode())
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
	return canonicalRoot(workingDirectory)
}

func canonicalRoot(root string) (ports.AnchoredRoot, error) {
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		return ports.AnchoredRoot{}, err
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.IsDir() {
		return ports.AnchoredRoot{}, fmt.Errorf("canonical root is not a directory")
	}
	absolute, err := filepath.Abs(resolved)
	if err != nil {
		return ports.AnchoredRoot{}, err
	}
	return ports.NewAnchoredRoot(filepath.Clean(absolute))
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

type versionInfo struct {
	Product     string
	Version     string
	Module      string
	ModuleSum   *string
	VCSRevision *string
}

func versionInfoFrom(info *debug.BuildInfo, versionOverride, revisionOverride string) versionInfo {
	result := versionInfo{Product: productName, Version: "(devel)", Module: modulePath}
	if info != nil {
		if info.Main.Version != "" {
			result.Version = info.Main.Version
		}
		if info.Main.Path != "" {
			result.Module = info.Main.Path
		}
		if info.Main.Sum != "" {
			moduleSum := info.Main.Sum
			result.ModuleSum = &moduleSum
		}
		if revision := buildSetting(info, "vcs.revision"); revision != "" &&
			buildSetting(info, "vcs.modified") == "false" {
			result.VCSRevision = &revision
		}
	}
	if versionOverride != "" {
		result.Version = versionOverride
	}
	if revisionOverride != "" {
		result.VCSRevision = &revisionOverride
	}
	return result
}

func buildSetting(info *debug.BuildInfo, key string) string {
	for _, setting := range info.Settings {
		if setting.Key == key {
			return setting.Value
		}
	}
	return ""
}
