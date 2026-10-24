//go:build darwin && arm64

package reviewrun

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/adapters/filesystem"
	"github.com/irootkernel/mulgae/internal/adapters/gittarget"
	"github.com/irootkernel/mulgae/internal/adapters/jsonschema"
	adapterruntime "github.com/irootkernel/mulgae/internal/adapters/runtime"
	"github.com/irootkernel/mulgae/internal/app/publication"
	"github.com/irootkernel/mulgae/internal/app/query"
	"github.com/irootkernel/mulgae/internal/app/report"
	"github.com/irootkernel/mulgae/internal/app/review"
	"github.com/irootkernel/mulgae/internal/app/validation"
	"github.com/irootkernel/mulgae/internal/builtin"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

// A head-scope whole-tree no-change review (an empty-tree HEAD commit)
// acquires no qualification, provider or source-content authority, and
// publishes the provider-free no-change result through the committed P2 path.
func TestIntegrationLiveServicePublishesWholeTreeNoChange(t *testing.T) {
	ctx := context.Background()
	rootPath, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root, _ := ports.NewAnchoredRoot(rootPath)
	git := func(args ...string) string {
		command := exec.Command("git", append([]string{"-C", root.String(), "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false"}, args...)...)
		raw, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("fixture Git: %v: %s", err, raw)
		}
		return strings.TrimSpace(string(raw))
	}
	git("init", "-q")
	git("commit", "-q", "--allow-empty", "-m", "Empty tree")
	selector, _ := ports.NewLiveSourceSelector(domain.LiveSourceHead, "")
	opener, _ := gittarget.NewLiveSourceAdapter(gittarget.ExecRunner{}, nil)
	reader, err := opener.OpenLiveSource(ctx, root, selector)
	if err != nil {
		t.Fatal(err)
	}
	if !reader.Target().NoChange() {
		t.Fatal("empty-tree HEAD commit was not a whole-tree no-change target")
	}
	source := &integratedLiveSource{LiveSourceReader: reader}
	defer source.Close()
	neutral, _ := ports.NewAnchoredRoot(t.TempDir())
	credential, _ := ports.NewAnchoredRoot(t.TempDir())
	artifacts, _ := ports.NewAnchoredRoot(t.TempDir())
	catalog := builtin.NewCatalog()
	schema, err := jsonschema.New(ctx, catalog)
	if err != nil {
		t.Fatal(err)
	}
	ids := adapterruntime.NewUUIDv7Generator()
	clock := adapterruntime.SystemClock{}
	store, err := filesystem.NewPublicationStore(schema, clock, ids, filesystem.NewSecureWriter())
	if err != nil {
		t.Fatal(err)
	}
	publicationService, _ := publication.NewService(store, schema, clock, ports.PublicationStructuredMemberMaxBytes)
	plan := reviewRunPlan(t, []domain.Role{domain.RoleLogic})
	plan.Threshold = domain.SeverityHigh
	plan.Ceilings = review.DefaultHarnessCeilings()
	build := BuildIdentity{Product: "mulgae", Version: "1.0.0", Module: "github.com/irootkernel/mulgae", VCSRevision: strings.Repeat("a", 40)}
	provider := &integratedLiveProvider{t: t, root: root, neutral: neutral, side: domain.LiveSourceAfter}
	terminal := serviceQualifiedTerminal(t)
	for index := range terminal.providers {
		terminal.providers[index].identity.ExecutableSHA256 = "sha256:" + strings.Repeat("b", 64)
		terminal.providers[index].identity.LauncherSHA256 = "sha256:" + strings.Repeat("c", 64)
		terminal.providers[index].qualificationReceiptIDs = []string{"qualification:v1:" + strings.Repeat("d", 64)}
		terminal.providers[index].packetTransportReceiptIDs = []string{"transport:v1:" + strings.Repeat("e", 64)}
	}
	authority := &integratedLiveAuthority{provider: provider, plan: plan, build: build, terminal: terminal}
	factory := &integratedLiveFactory{authority: authority}
	publisher := &integratedLivePublisher{t: t, source: source, authority: authority, service: publicationService}
	wire, _ := ports.ParseAssetID(validation.ProviderReviewSchemaID)
	validator, _ := validation.NewReviewValidator(schema, wire)
	common, _ := LoadLiveReviewCommon(ctx, catalog)
	calls := []string{}
	diagnostics := &serviceDiagnosticFactory{calls: &calls}
	service, err := NewLiveService(LiveDependencies{Sources: integratedLiveOpener{source}, ReviewerHome: promptLiveHome{root: neutral}, CredentialRoots: []ports.AnchoredRoot{credential}, Admission: serviceLiveAdmission{plan}, Clock: clock, IDs: ids, Build: build, Authority: factory, Validator: validator, Publication: publisher, Templates: mustServiceTemplates(t), Common: common, Diagnostics: diagnostics, Detector: filesystem.NewContentDetector()})
	if err != nil {
		t.Fatal(err)
	}
	selection, _ := NewRunSelection([]domain.Role{domain.RoleLogic}, nil)
	result, err := service.Execute(ctx, LiveRequest{ProjectRoot: root, ArtifactRoot: artifacts, Target: selector, Selection: selection})
	if err != nil {
		for cause := err; cause != nil; cause = errors.Unwrap(cause) {
			t.Logf("%T: %v", cause, cause)
		}
		t.Fatal(err)
	}
	if !source.closed || publisher.calls != 1 || !result.Final().Valid() || result.SourceIdentitySHA256() == "" {
		t.Fatal("missing terminal P2/source authority")
	}
	for _, input := range diagnostics.inputs {
		if input.Event == domain.DiagnosticQualificationStarted || input.Event == domain.DiagnosticQualificationCandidateChecked || input.Event == domain.DiagnosticQualificationSucceeded || input.Event == domain.DiagnosticQualificationRejected {
			t.Fatalf("whole-tree no-change acquired qualification authority: %+v", input)
		}
	}
	if factory.calls != 0 || provider.calls != 0 || source.reads != 0 {
		t.Fatal("whole-tree no-change acquired provider/source-content authority")
	}
	run, _ := ports.NewPublicationRun(artifacts, result.SessionID(), result.RunID())
	queries, _ := query.NewService(store, schema, nil, ports.PublicationStructuredMemberMaxBytes)
	status, err := queries.ReadRunStatus(ctx, run)
	if err != nil || status.PublicationStatus() != domain.PublicationCommitted {
		t.Fatalf("verified P2: %v / %v", status, err)
	}
	renderer, err := report.NewService(queries)
	if err != nil {
		t.Fatal(err)
	}
	rendered, err := renderer.Render(ctx, run)
	if err != nil {
		t.Fatalf("render retained live evidence after source closure: %v", err)
	}
	if !bytes.Contains(rendered.Bytes(), []byte(result.SourceIdentitySHA256())) || bytes.Contains(rendered.Bytes(), []byte("Current target SHA-256")) {
		t.Fatal("rendered live report lost source selection identity")
	}
	if _, err := os.Stat(filepath.Join(artifacts.String(), result.SessionID().String(), result.RunID().String(), "source", "capture.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("no-change publication retained a captured archive")
	}
}
