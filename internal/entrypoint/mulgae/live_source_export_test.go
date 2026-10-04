package mulgae

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/adapters/gittarget"
	"github.com/irootkernel/mulgae/internal/app/evidence"
	appexport "github.com/irootkernel/mulgae/internal/app/export"
	"github.com/irootkernel/mulgae/internal/app/publication"
	"github.com/irootkernel/mulgae/internal/app/query"
	"github.com/irootkernel/mulgae/internal/app/review"
	"github.com/irootkernel/mulgae/internal/app/validation"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

type liveExportRuntime struct {
	t         *testing.T
	validator *validation.ReviewValidator
	identity  evidence.LiveSourceIdentity
}

func (runtime liveExportRuntime) Invoke(ctx context.Context, job review.InvocationJob) review.AttemptOutcome {
	validated, plan, err := runtime.validator.Validate(ctx, []byte(`{"schema_version":"mulgae-provider-review-output.v1","summary":"No defects in the selected source.","completeness":"complete","limitations":[],"findings":[]}`), validation.ReviewValidationScope{LiveSource: runtime.identity, Role: job.Role(), ProviderInstance: job.Route().ProviderInstance()})
	if err != nil || plan != nil {
		runtime.t.Fatalf("validate export fixture: %v", err)
	}
	output, err := review.NewEvidenceValidatedRoleOutput(job.Role(), job.Route().ProviderInstance(), job.Target(), validated.Findings(), validated.Completeness(), validated.Limitations(), nil)
	if err != nil {
		runtime.t.Fatal(err)
	}
	outcome, err := review.NewAttemptOutcome(job, &output, nil)
	if err != nil {
		runtime.t.Fatal(err)
	}
	return outcome
}

func TestIntegrationLiveRasterExportReadsRetainedBytesAfterSourceRemoval(t *testing.T) {
	ctx := context.Background()
	fixture := newG008RealE2EFixture(t)
	sourceRoot, _ := ports.NewAnchoredRoot(t.TempDir())
	imageBytes := []byte{137, 80, 78, 71, 13, 10, 26, 10, 0}
	if err := os.WriteFile(filepath.Join(sourceRoot.String(), "diagram.png"), imageBytes, 0600); err != nil {
		t.Fatal(err)
	}
	opener, err := gittarget.NewLiveSourceAdapter(gittarget.ExecRunner{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	selector, _ := ports.NewLiveSourceSelector(domain.LiveSourceWorkspace, "")
	source, err := opener.OpenLiveSource(ctx, sourceRoot, selector)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	identity, _ := evidence.NewLiveSourceIdentity(source.Target())
	target, _ := identity.RunTarget()
	schemaID, _ := ports.ParseAssetID(validation.ProviderReviewSchemaID)
	validator, err := validation.NewReviewValidator(fixture.validator, schemaID)
	if err != nil {
		t.Fatal(err)
	}
	route, _ := ports.NewProviderRoute("live-export.logic")
	assignment, _ := review.NewScheduledAssignment(domain.RoleLogic, true, route)
	limits, _ := review.NewInvocationLimits(time.Second)
	routeBudget, _ := review.NewRouteBudget(route, limits)
	roleBudget, _ := review.NewRoleBudget(domain.RoleLogic, routeBudget)
	budget, err := review.PreflightRunBudgetWithCapacity([]review.RoleBudget{roleBudget}, review.DefaultHarnessCeilings(), 1)
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := review.NewCoordinator(fixture.clock, fixture.ids, liveExportRuntime{t, validator, identity}, 1, budget)
	if err != nil {
		t.Fatal(err)
	}
	result, err := coordinator.Execute(ctx, target, []review.Assignment{assignment}, domain.SeverityHigh, nil)
	if err != nil {
		t.Fatal(err)
	}
	verifier, _ := evidence.NewLiveVerifier(source)
	imagePath, _ := ports.NewSafeRelativePath("diagram.png")
	file, _ := ports.NewLiveSourceFile(imagePath, imageBytes, "image/png")
	image, err := verifier.VerifyBinary(ctx, evidence.SideWorktree, imagePath, file.SHA256())
	if err != nil {
		t.Fatal(err)
	}
	receipt := "sha256:" + strings.Repeat("b", 64)
	candidate, err := publication.PrepareLiveCandidate(publication.LiveCandidateInput{Result: result, Target: source.Target(), SeverityThreshold: domain.SeverityHigh, BinaryEvidence: []evidence.LiveBinaryReceipt{image}, Provenance: publication.LiveProductionProvenance{
		BuildProduct: "mulgae", BuildVersion: "test", BuildCommit: "0123456789abcdef", SourceIdentitySHA256: identity.SHA256(), SourceTerminalReceipt: "source-terminal:v1:" + receipt,
		Providers: []publication.ProductionProviderProvenance{{Family: "zcode", Instance: route.ProviderInstance(), Version: "test", Executable: "fixture-provider", ExecutableSHA256: receipt, ProfileGeneration: "test", AdapterProfile: "test", QualificationReceiptIDs: []string{receipt}, PacketTransportReceiptIDs: []string{receipt}, NamespaceTerminalReceipt: receipt}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := source.Close(); err != nil {
		t.Fatal(err)
	}
	published, err := fixture.publisher.PublishLiveNext(ctx, fixture.root, candidate)
	if err != nil || published.Decision().Authority() != domain.PublicationAuthorityP2 {
		t.Fatalf("publish selected image: %v", err)
	}
	if err := os.RemoveAll(sourceRoot.String()); err != nil {
		t.Fatal(err)
	}
	run, _ := ports.NewPublicationRun(fixture.root, candidate.SessionID(), candidate.RunID())
	committed, err := fixture.queries.ReadCommitted(ctx, run)
	if err != nil {
		t.Fatal(err)
	}
	binding, _ := domain.ParseProjectBinding("sha256:" + strings.Repeat("a", 64))
	content, err := NewPublicationQueryService(fixture.queries).ReadSourceImage(ctx, run, binding, identity.SHA256(), "worktree", "diagram.png", query.ContentContinuation{})
	if err != nil {
		t.Fatalf("offline source image transport: %v", err)
	}
	decodedImage, err := base64.StdEncoding.Strict().DecodeString(content.Content)
	if err != nil || content.MediaType != "image/png" || content.Encoding != "base64" || !bytes.Equal(decodedImage, imageBytes) || content.RunID != run.RunID().String() {
		t.Fatal("offline source image transport changed selected raster bytes")
	}
	if _, err := (p2ExportProjectionReader{committed: committed}).ReadCommittedProjection(ctx, appexport.ExportSource{SessionID: committed.SessionID().String(), RunID: committed.RunID().String(), ReviewID: committed.ReviewID().String()}); err == nil {
		t.Fatal("selected images exported without a verified artifact reader")
	}
	exports, err := NewRedactedExportService(fixture.queries, mustG008RealExportInstaller(t, fixture), fixture.clock, fixture.ids)
	if err != nil {
		t.Fatal(err)
	}
	projectRoot, _ := ports.NewAnchoredRoot(filepath.Dir(fixture.root.String()))
	exported, err := exports.ExportRedactedRun(ctx, RedactedExportRequest{ProjectRoot: projectRoot, ArtifactRoot: fixture.root, RunID: candidate.RunID().String(), OutputPath: "exports/raster.zip", Redacted: true})
	if err != nil {
		t.Fatal(err)
	}
	manifestBytes, err := os.ReadFile(filepath.Join(projectRoot.String(), exported.ExportManifestURI))
	if err != nil {
		t.Fatal(err)
	}
	var manifest appexport.ExportManifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.SchemaVersion != "mulgae-export-manifest.v2" || manifest.SourceIdentity.SourceIdentitySHA256 != identity.SHA256() || manifest.ImmutableSource.ReviewID != committed.ReviewID().String() {
		t.Fatal("retained image export lost its live publication identity")
	}
	manifestSchema, _ := ports.ParseAssetID("https://mulgae.local/schemas/mulgae-export-manifest.v2.schema.json")
	if err := fixture.validator.Validate(ctx, manifestSchema, manifestBytes); err != nil {
		t.Fatal(err)
	}
	reader, err := zip.OpenReader(filepath.Join(projectRoot.String(), exported.BundleURI))
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	wantPath := "evidence/images/sha256-" + strings.TrimPrefix(file.SHA256(), "sha256:") + ".png"
	for _, member := range reader.File {
		if member.Name != wantPath {
			continue
		}
		body, err := member.Open()
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(body)
		body.Close()
		if err != nil || !bytes.Equal(data, imageBytes) {
			t.Fatal("native export changed the retained PNG")
		}
		return
	}
	t.Fatal("native export omitted the selected PNG")
}

func TestIntegrationLiveNoChangeExportUsesVerifiedP2AndNativeSecureWriter(t *testing.T) {
	ctx := context.Background()
	fixture := newG008RealE2EFixture(t)
	session, _ := domain.ParseSessionID("s_018f0d1a-0000-7000-8000-000000000001")
	runID, _ := domain.ParseRunID("r_018f0d1a-0000-7000-8000-000000000002")
	selector, _ := ports.NewLiveSourceSelector(domain.LiveSourceWorkspace, "")
	target, _ := ports.NewLiveSourceTarget(selector, ports.GitObjectID{}, ports.GitObjectID{}, false, nil)
	identity, _ := evidence.NewLiveSourceIdentity(target)
	candidate, err := publication.PrepareLiveNoChangeCandidate(session, runID, target, []domain.Role{domain.RoleLogic, domain.RoleSecurity}, domain.SeverityHigh, publication.LiveProductionProvenance{
		BuildProduct: "mulgae", BuildVersion: "test", BuildCommit: "0123456789abcdef", SourceIdentitySHA256: identity.SHA256(), SourceTerminalReceipt: "source-terminal:v1:sha256:" + strings.Repeat("b", 64),
	})
	if err != nil {
		t.Fatal(err)
	}
	published, err := fixture.publisher.PublishLiveNext(ctx, fixture.root, candidate)
	if err != nil {
		t.Fatal(err)
	}
	final, ok := published.Final()
	if !ok || published.Decision().Authority() != domain.PublicationAuthorityP2 {
		t.Fatal("live result is not committed")
	}
	exports, err := NewRedactedExportService(fixture.queries, mustG008RealExportInstaller(t, fixture), fixture.clock, fixture.ids)
	if err != nil {
		t.Fatal(err)
	}
	projectRoot, _ := ports.NewAnchoredRoot(filepath.Dir(fixture.root.String()))
	result, err := exports.ExportRedactedRun(ctx, RedactedExportRequest{ProjectRoot: projectRoot, ArtifactRoot: fixture.root, RunID: runID.String(), OutputPath: "exports/live.zip", Redacted: true})
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(projectRoot.String(), result.ExportManifestURI))
	if err != nil {
		t.Fatal(err)
	}
	var manifest appexport.ExportManifest
	if err := json.Unmarshal(body, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.SchemaVersion != "mulgae-export-manifest.v2" || manifest.ImmutableSource.ReviewID != final.ReviewID().String() || manifest.SourceIdentity.SourceIdentitySHA256 != identity.SHA256() || manifest.CurrentIdentity.SourceIdentitySHA256 != identity.SHA256() || manifest.SourceIdentity.SourceTargetSHA256 != "" || manifest.CurrentIdentity.TargetSHA256 != "" || manifest.SourceIdentity.FindingID != "" {
		t.Fatal("live export fabricated captured content or finding identity")
	}
	schemaID, _ := ports.ParseAssetID("https://mulgae.local/schemas/mulgae-export-manifest.v2.schema.json")
	if err := fixture.validator.Validate(ctx, schemaID, body); err != nil {
		t.Fatalf("native export manifest is not schema-valid: %v", err)
	}
	reader, err := zip.OpenReader(filepath.Join(projectRoot.String(), result.BundleURI))
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	metadata := false
	for _, member := range reader.File {
		metadata = metadata || member.Name == "live-source.json"
		if strings.Contains(member.Name, "capture") || strings.Contains(member.Name, "target") {
			t.Fatal("live export retained source capture")
		}
	}
	if !metadata {
		t.Fatal("live export omitted source selection metadata")
	}
}
