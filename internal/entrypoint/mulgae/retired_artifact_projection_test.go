//go:build darwin && arm64

package mulgae

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	adapterconfig "github.com/irootkernel/mulgae/internal/adapters/config"
	"github.com/irootkernel/mulgae/internal/adapters/environment"
	"github.com/irootkernel/mulgae/internal/adapters/filesystem"
	"github.com/irootkernel/mulgae/internal/adapters/gittarget"
	"github.com/irootkernel/mulgae/internal/app"
	appclean "github.com/irootkernel/mulgae/internal/app/clean"
	"github.com/irootkernel/mulgae/internal/app/doctor"
	appinit "github.com/irootkernel/mulgae/internal/app/init"
	appquery "github.com/irootkernel/mulgae/internal/app/query"
	appreport "github.com/irootkernel/mulgae/internal/app/report"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
	"github.com/irootkernel/mulgae/internal/testsupport/historical"
)

func TestRetiredProviderArtifactCLIReadsAndExportsFailClosedWithCodeAndCleanSucceeds(t *testing.T) {
	corpus, err := historical.Load()
	if err != nil {
		t.Fatal(err)
	}
	var retiredCase historical.Case
	found := false
	for _, candidate := range corpus.Cases {
		if candidate.ID == "composite-mixed-v1" {
			retiredCase = candidate
			found = true
			break
		}
	}
	if !found {
		t.Fatal("historical retired-provider fixture composite-mixed-v1 is missing")
	}

	projectPath := testAnchoredRoot(t)
	artifactPath := filepath.Join(projectPath, ".mulgae")
	if err := os.Mkdir(artifactPath, 0700); err != nil {
		t.Fatal(err)
	}
	if err := retiredCase.Materialize(artifactPath); err != nil {
		t.Fatal(err)
	}
	artifactRoot, err := ports.NewAnchoredRoot(artifactPath)
	if err != nil {
		t.Fatal(err)
	}

	catalog, validator := mustSharedFoundationAssets(t)
	clock := fixedFoundationClock{now: time.Date(2026, time.October, 24, 0, 0, 0, 0, time.UTC)}
	ids := historicalIDs{}
	writer := filesystem.NewSecureWriter()
	store, err := filesystem.NewPublicationStore(validator, clock, ids, writer)
	if err != nil {
		t.Fatal(err)
	}
	queries, err := appquery.NewService(store, validator, nil, 8<<20)
	if err != nil {
		t.Fatal(err)
	}
	reports, err := appreport.NewService(queries)
	if err != nil {
		t.Fatal(err)
	}
	installer, err := filesystem.NewExportInstaller(writer)
	if err != nil {
		t.Fatal(err)
	}
	exports, err := NewRedactedExportService(queries, installer, clock, ids)
	if err != nil {
		t.Fatal(err)
	}
	cleanupStore, err := filesystem.NewCleanupStore(artifactRoot, store, clock)
	if err != nil {
		t.Fatal(err)
	}
	cleanService, err := appclean.NewService(clock, validator, cleanupStore)
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := NewG008RequestResolver(artifactRoot, queries, filesystem.NewRunSelector(artifactRoot))
	if err != nil {
		t.Fatal(err)
	}
	reader, err := gittarget.New(gittarget.NewExecRunner())
	if err != nil {
		t.Fatal(err)
	}

	application, err := NewApplication(Dependencies{
		NewLocalDoctor:       doctor.NewLocalService,
		DoctorPlatform:       doctor.LocalPlatformEvidence{Cell: "darwin-arm64", Native: true},
		ConfigSources:        adapterconfig.SourceFactory{},
		ConfigCodec:          adapterconfig.YAMLCodec{},
		Accounts:             environment.AccountObserver{},
		SelectConfigLocality: adapterconfig.SelectLocality,
		NewInitService:       appinit.NewService,
		Clock:                clock,
		RequestIDGenerator:   fixedFoundationRequestIDs{},
		Catalog:              catalog,
		JSONSchemaValidator:  validator,
		SecureWriter:         writer,
		TrustedProjectReader: reader,
		EnvironmentInspector: environment.NewInspector(),
		RequestResolver:      resolver,
		PublicationQueries:   NewPublicationQueryService(queries),
		ProjectContexts:      mustVerifiedReadContexts(t),
		PublicationReports:   NewPublicationReportService(reports),
		Retention:            NewRetentionService(cleanService),
		Exports:              exports,
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture := foundationFixture{application: application, catalog: catalog, validator: validator}
	runID := retiredCase.RunID

	commands := []struct {
		name string
		args []string
	}{
		{"inspect", []string{"inspect", "--run", runID}},
		{"status", []string{"status", "--run", runID}},
		{"findings", []string{"findings", "--run", runID, "--severity", "low"}},
		{"report", []string{"report", "--run", runID, "--output-path", "report.md"}},
		{"export", []string{"export", "--run", runID, "--output-path", "export.zip"}},
		{"read-report", []string{"read-report", "--run", runID}},
		{"read-finding", []string{"read-finding", "--run", runID, "--finding", "F001"}},
	}

	for _, test := range commands {
		t.Run(test.name+"/json", func(t *testing.T) {
			args := append(append([]string(nil), test.args...), "--output", "json")
			result := application.Run(context.Background(), args, projectPath)
			assertFoundationEnvelope(t, fixture, result, app.ExitCodeArtifact)
			var envelope struct {
				Exit struct {
					Code int    `json:"code"`
					Kind string `json:"kind"`
				} `json:"exit"`
				Reasons []struct {
					Category  string `json:"category"`
					Code      string `json:"code"`
					Message   string `json:"message"`
					Retryable bool   `json:"retryable"`
				} `json:"reasons"`
			}
			if err := json.Unmarshal(result.Stdout(), &envelope); err != nil {
				t.Fatalf("unmarshal envelope: %v", err)
			}
			if envelope.Exit.Code != int(app.ExitCodeArtifact) || envelope.Exit.Kind != "artifact" {
				t.Fatalf("exit = %+v, want code=7 kind=artifact", envelope.Exit)
			}
			if len(envelope.Reasons) != 1 || envelope.Reasons[0].Category != "artifact" ||
				envelope.Reasons[0].Code != "retired_provider_artifact" || envelope.Reasons[0].Retryable {
				t.Fatalf("reasons = %+v, want single non-retryable artifact retired_provider_artifact", envelope.Reasons)
			}
			if !strings.Contains(envelope.Reasons[0].Message, "mulgae clean --dry-run") ||
				strings.Contains(envelope.Reasons[0].Message, "mulgae doctor") {
				t.Fatalf("unexpected message hint: %q", envelope.Reasons[0].Message)
			}
		})
		t.Run(test.name+"/human", func(t *testing.T) {
			result := application.Run(context.Background(), test.args, projectPath)
			if result.ExitCode() != app.ExitCodeArtifact || len(result.Stdout()) != 0 {
				t.Fatalf("exit=%d stdout=%q stderr=%q, want exit=7 empty stdout", result.ExitCode(), result.Stdout(), result.Stderr())
			}
			stderr := string(result.Stderr())
			if !strings.Contains(stderr, "code: retired_provider_artifact") ||
				!strings.Contains(stderr, "hint: run mulgae clean --dry-run") ||
				strings.Contains(stderr, "mulgae doctor") {
				t.Fatalf("human stderr = %q, want retired_provider_artifact code and clean hint", stderr)
			}
		})
	}

	t.Run("export/latest", func(t *testing.T) {
		result := application.Run(context.Background(), []string{"export", "--run", "latest", "--output-path", "export.zip"}, projectPath)
		if result.ExitCode() != app.ExitCodeArtifact {
			t.Fatalf("exit=%d stdout=%q stderr=%q, want exit=7", result.ExitCode(), result.Stdout(), result.Stderr())
		}
		stderr := string(result.Stderr())
		if !strings.Contains(stderr, "code: retired_provider_artifact") ||
			!strings.Contains(stderr, "hint: run mulgae clean --dry-run") {
			t.Fatalf("export --run latest stderr = %q, want retired_provider_artifact", stderr)
		}
	})

	for _, forbidden := range []string{"report.md", "export.zip", "export.manifest.json"} {
		if _, err := os.Stat(filepath.Join(projectPath, forbidden)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("rejected retired-provider command created %s: %v", forbidden, err)
		}
	}

	t.Run("clean/dry-run-and-apply", func(t *testing.T) {
		dryRun := application.Run(context.Background(), []string{"clean", "--dry-run", "--all", "--output", "json"}, projectPath)
		assertFoundationEnvelope(t, fixture, dryRun, app.ExitCodeSuccess)
		apply := application.Run(context.Background(), []string{"clean", "--all", "--output", "json"}, projectPath)
		assertFoundationEnvelope(t, fixture, apply, app.ExitCodeSuccess)
	})
}

func TestRetiredProviderArtifactCLIFailurePrecedenceAndWrapping(t *testing.T) {
	retired, err := domain.NewFailure("query.read_committed", domain.FailureArtifact, "retired_provider_artifact", nil)
	if err != nil {
		t.Fatal(err)
	}
	nestedArtifact, err := domain.NewFailure("query.read_status", domain.FailureArtifact, "failed-run recovery source is invalid", retired)
	if err != nil {
		t.Fatal(err)
	}
	genericArtifact, err := domain.NewFailure("query.read_committed", domain.FailureArtifact, "corrupt manifest", nil)
	if err != nil {
		t.Fatal(err)
	}
	securityErr, err := domain.NewFailure("query.context", domain.FailureSecurityPolicy, "path escaped", nil)
	if err != nil {
		t.Fatal(err)
	}
	internalErr, err := domain.NewFailure("query.read_committed", domain.FailureInternal, "internal invariant", nil)
	if err != nil {
		t.Fatal(err)
	}
	wrongClass, err := domain.NewFailure("query.read_committed", domain.FailureConfiguration, "retired_provider_artifact", nil)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name      string
		err       error
		wantClass domain.FailureClass
		wantCode  string
		wantExit  app.ExitCode
	}{
		{"direct", retired, domain.FailureArtifact, "retired_provider_artifact", app.ExitCodeArtifact},
		{"nested artifact wrapper", nestedArtifact, domain.FailureArtifact, "retired_provider_artifact", app.ExitCodeArtifact},
		{"multi-error wrap", fmt.Errorf("%w: %w", errors.New("unverified"), retired), domain.FailureArtifact, "retired_provider_artifact", app.ExitCodeArtifact},
		{"joined with generic artifact", errors.Join(genericArtifact, retired), domain.FailureArtifact, "retired_provider_artifact", app.ExitCodeArtifact},
		{"non-retired artifact", genericArtifact, domain.FailureArtifact, "artifact_unavailable", app.ExitCodeArtifact},
		{"security precedence", errors.Join(retired, securityErr), domain.FailureSecurityPolicy, "security_rejected", app.ExitCodeSecurity},
		{"internal precedence", errors.Join(retired, internalErr), domain.FailureInternal, "internal_failure", app.ExitCodeInternal},
		{"wrong class ignored", wrongClass, domain.FailureConfiguration, "configuration_rejected", app.ExitCodeUsage},
		{"untyped string ignored", errors.New("retired_provider_artifact"), domain.FailureArtifact, "artifact_unavailable", app.ExitCodeArtifact},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := normalizeExecutionFailure(app.CommandInspect, *executionFailureFor(app.CommandInspect, test.err, domain.FailureArtifact))
			if got.class != test.wantClass || got.code != test.wantCode || got.exit != test.wantExit {
				t.Fatalf("got class=%s code=%q exit=%d, want class=%s code=%q exit=%d",
					got.class, got.code, got.exit, test.wantClass, test.wantCode, test.wantExit)
			}
			if test.wantCode == "retired_provider_artifact" {
				if got.recommendedNextCommand != "mulgae clean --dry-run" || !got.hasRetryable || got.retryable {
					t.Fatalf("retired projection metadata = %+v", got)
				}
			}
		})
	}
}
