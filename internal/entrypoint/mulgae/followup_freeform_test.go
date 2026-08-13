package mulgae

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/adapters/environment"
	"github.com/irootkernel/mulgae/internal/adapters/filesystem"
	"github.com/irootkernel/mulgae/internal/adapters/gittarget"
	"github.com/irootkernel/mulgae/internal/app"
	"github.com/irootkernel/mulgae/internal/app/childrun"
	"github.com/irootkernel/mulgae/internal/app/validation"
	"github.com/irootkernel/mulgae/internal/builtin"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

func TestFollowupFreeFormPrimaryPublishesReportsOnlyAndStructuredPaths(t *testing.T) {
	validStructured := []byte(`{"schema_version":"mulgae-provider-followup-output.v1","summary":"F001 remains open.","resolution":"still_open","rationale":"The current target preserves the source finding.","evidence":[{"current":{"path":"internal/app/coordinator.go","line_start":1,"line_end":1,"side":"head","quote":"queueFallback(task)"}}],"new_findings":[],"limitations":[]}`)
	invalidStructured := []byte(`{"schema_version":"mulgae-provider-followup-output.v1","summary":"broken","resolution":"still_open","rationale":"The issue remains.","evidence":[{"current":{"path":"missing.go","line_start":1,"line_end":1,"side":"head","quote":"nope"}}],"new_findings":[],"limitations":[]}`)
	prose := []byte("# Follow-up\n\nThe finding still looks open after the patch.\n")
	stillOpen := "still_open"

	tests := []struct {
		name                     string
		stdout                   []byte
		disableRepair            bool
		observeErr               error
		wantExit                 app.ExitCode
		wantResolution           *string
		wantStructuredExtraction string
		wantFail                 bool
	}{
		{
			name:                     "free-form report",
			stdout:                   prose,
			disableRepair:            true,
			wantExit:                 app.ExitCodeSuccess,
			wantStructuredExtraction: "reports_only",
		},
		{
			name:                     "optional valid structured resolution",
			stdout:                   validStructured,
			disableRepair:            true,
			wantExit:                 app.ExitCodePolicy,
			wantResolution:           &stillOpen,
			wantStructuredExtraction: "structured",
		},
		{
			name:                     "invalid structured candidate demotes to reports-only",
			stdout:                   invalidStructured,
			disableRepair:            true,
			wantExit:                 app.ExitCodeSuccess,
			wantStructuredExtraction: "reports_only",
		},
		{
			name:       "provider process failure fails closed",
			stdout:     prose,
			observeErr: errors.New("provider process failed"),
			wantFail:   true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newG008RealE2EFixture(t)
			root := fixture.executeAndPublishRoot(t)
			fixture.followupPrompts = g008RealE2EFollowupPromptSource{
				provider:      fixture.provider,
				fixedStdout:   append([]byte(nil), test.stdout...),
				disableRepair: test.disableRepair,
			}
			fixture.provider.observeErr = test.observeErr
			followupSchema, err := ports.ParseAssetID(validation.ProviderFollowupSchemaID)
			if err != nil {
				t.Fatal(err)
			}
			followupValidator, err := validation.NewFollowupValidator(fixture.validator, followupSchema)
			if err != nil {
				t.Fatal(err)
			}
			fixture.followupExecutor, err = childrun.NewFollowupExecutor(
				fixture.clock, fixture.ids, fixture.provider, fixture.followupPrompts, followupValidator, fixture.publisher, fixture.root,
				childrun.FollowupExecutorConfig{
					ProviderInstance: "g008.logic", SeverityThreshold: domain.SeverityHigh,
					MulgaeVersion: "g008-test", MulgaeCommit: "g008-test",
				},
			)
			if err != nil {
				t.Fatal(err)
			}

			resolver, err := NewG008RequestResolver(fixture.root, fixture.queries, filesystem.NewRunSelector(fixture.root), strings.NewReader("current.patch"))
			if err != nil {
				t.Fatal(err)
			}
			dependencies, err := NewG008Dependencies(G008Composition{
				ArtifactRoot: fixture.root, Queries: fixture.queries, RequestResolver: resolver, Clock: fixture.clock, IDs: fixture.ids,
				PublicationAuthority: fixture.store, ExportInstaller: mustG008RealExportInstaller(t, fixture),
				Online: &G008OnlineAuthority{
					FollowupTargetCapturer: g008RealFollowupCapturer{},
					FollowupExecutor:       fixture.followupExecutor,
					ChildExecutor:          fixture.childExecutor,
					DeltaTargetCapturer:    g008RealDeltaCapturer{target: fixture.deltaTarget},
					DeltaComparator:        g008RealComparator{},
					RerunAssignments:       fixture.assignments[:1],
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			reader, err := gittarget.New(gittarget.NewExecRunner())
			if err != nil {
				t.Fatal(err)
			}
			application, err := NewApplication(Dependencies{
				Clock: fixture.clock, RequestIDGenerator: fixture.ids, RequestResolver: dependencies.RequestResolver,
				Catalog: builtin.NewCatalog(), JSONSchemaValidator: fixture.validator, SecureWriter: fixture.writer,
				TrustedProjectReader: reader, EnvironmentInspector: environment.NewInspector(),
				PublicationQueries: NewPublicationQueryService(fixture.queries),
				PublicationReports: mustG008RealReportService(t, fixture),
				ReviewRuns: &reviewRunFake{result: NewReviewRunResult(
					root.SessionID.String(), root.RunID.String(), root.RunManifestURI, root.ReviewArtifactURI, root.TerminalExit,
				)},
				FollowupRuns: dependencies.FollowupRuns, DeltaRuns: dependencies.DeltaRuns,
				Reruns: dependencies.Reruns, Exports: dependencies.Exports,
			})
			if err != nil {
				t.Fatal(err)
			}
			projectRoot := filepath.Dir(fixture.root.String())
			result := application.Run(context.Background(), []string{
				"followup", "--run", root.RunID.String(), "--finding", "F001", "--patch", "current.patch", "--output", "json",
			}, projectRoot)
			if test.wantFail {
				if result.ExitCode() == app.ExitCodeSuccess || result.ExitCode() == app.ExitCodePolicy {
					t.Fatalf("provider failure exited as success path: exit=%d stdout=%q", result.ExitCode(), result.Stdout())
				}
				if strings.Contains(string(result.Stdout()), `"role_report_uris"`) ||
					strings.Contains(string(result.Stdout()), `"session_id":"s_`) ||
					strings.Contains(string(result.Stdout()), `"run_id":"r_`) {
					t.Fatalf("failed followup leaked success identities: %s", result.Stdout())
				}
				return
			}
			if result.ExitCode() != test.wantExit {
				t.Fatalf("exit=%d want %d stdout=%q stderr=%q", result.ExitCode(), test.wantExit, result.Stdout(), result.Stderr())
			}
			var envelope struct {
				Result struct {
					Kind                       string  `json:"kind"`
					SessionID                  string  `json:"session_id"`
					RunID                      string  `json:"run_id"`
					FollowupArtifactURI        string  `json:"followup_artifact_uri"`
					Resolution                 *string `json:"resolution"`
					StructuredExtractionStatus string  `json:"structured_extraction_status"`
					RoleReportURIs             []struct {
						Role string `json:"role"`
						URI  string `json:"uri"`
					} `json:"role_report_uris"`
				} `json:"result"`
			}
			if err := json.Unmarshal(result.Stdout(), &envelope); err != nil {
				t.Fatal(err)
			}
			if envelope.Result.Kind != "followup_started" ||
				envelope.Result.SessionID != root.SessionID.String() ||
				envelope.Result.RunID == "" || envelope.Result.RunID == root.RunID.String() ||
				envelope.Result.FollowupArtifactURI == "" ||
				envelope.Result.StructuredExtractionStatus != test.wantStructuredExtraction {
				t.Fatalf("followup projection = %#v", envelope.Result)
			}
			if test.wantResolution == nil {
				if envelope.Result.Resolution != nil {
					t.Fatalf("reports-only invented resolution %q", *envelope.Result.Resolution)
				}
			} else if envelope.Result.Resolution == nil || *envelope.Result.Resolution != *test.wantResolution {
				t.Fatalf("resolution = %#v, want %q", envelope.Result.Resolution, *test.wantResolution)
			}
			if len(envelope.Result.RoleReportURIs) != 1 {
				t.Fatalf("role_report_uris = %#v", envelope.Result.RoleReportURIs)
			}
			reportURI := envelope.Result.RoleReportURIs[0].URI
			if !strings.HasPrefix(reportURI, ".mulgae/") || !strings.HasSuffix(reportURI, "/role-reports/logic.md") {
				t.Fatalf("role report URI = %q", reportURI)
			}
			reportPath := filepath.Join(projectRoot, reportURI)
			reportBytes, err := os.ReadFile(reportPath)
			if err != nil {
				t.Fatalf("read published role report: %v", err)
			}
			if string(reportBytes) != string(test.stdout) {
				t.Fatalf("published role report = %q, want exact assistant content", reportBytes)
			}
			childRunID, err := domain.ParseRunID(envelope.Result.RunID)
			if err != nil {
				t.Fatal(err)
			}
			childRun, err := fixture.queries.ResolveRun(context.Background(), fixture.root, childRunID)
			if err != nil {
				t.Fatal(err)
			}
			committed, err := fixture.queries.ReadCommitted(context.Background(), childRun)
			if err != nil {
				t.Fatal(err)
			}
			lineage := committed.Lineage()
			parent, hasParent := lineage.ParentRunID()
			source, hasSource := lineage.SourceRunID()
			reviewID, hasReview := lineage.SourceReviewID()
			finding, hasFinding := lineage.SourceFindingRef()
			if !hasParent || parent != root.RunID || !hasSource || source != root.RunID ||
				!hasReview || reviewID != root.ReviewID || !hasFinding || finding != "F001" {
				t.Fatalf("followup lineage = %#v", lineage)
			}
			if committed.StructuredExtractionStatus() != domain.StructuredExtractionStatus(test.wantStructuredExtraction) {
				t.Fatalf("committed structured_extraction_status = %q", committed.StructuredExtractionStatus())
			}
			_, hasOutcome := committed.FollowupOutcome()
			if hasOutcome != (test.wantStructuredExtraction == "structured") {
				t.Fatalf("followup outcome presence = %t for %s", hasOutcome, test.wantStructuredExtraction)
			}
			sum := sha256.Sum256(reportBytes)
			digest := "sha256:" + hex.EncodeToString(sum[:])
			foundReport := false
			for _, report := range committed.RoleReports() {
				if report.Path() == "role-reports/logic.md" {
					foundReport = true
					if report.SHA256() != digest || report.ByteLength() != len(reportBytes) {
						t.Fatalf("manifest role report digest mismatch: path=%s sha=%s len=%d want %s/%d",
							report.Path(), report.SHA256(), report.ByteLength(), digest, len(reportBytes))
					}
				}
			}
			if !foundReport {
				t.Fatal("committed manifest omitted role-reports/logic.md inventory entry")
			}
			if err := os.WriteFile(reportPath, append(append([]byte(nil), reportBytes...), []byte("\n# tampered\n")...), 0o600); err != nil {
				t.Fatal(err)
			}
			status := application.Run(context.Background(), []string{
				"status", "--run", childRunID.String(), "--output", "json",
			}, projectRoot)
			if status.ExitCode() == app.ExitCodeSuccess && strings.Contains(string(status.Stdout()), reportURI) {
				t.Fatalf("tampered role report remained projectable: exit=%d stdout=%q", status.ExitCode(), status.Stdout())
			}
		})
	}
}
