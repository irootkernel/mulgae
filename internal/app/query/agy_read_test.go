package query

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/app/evidence"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

func liveAgyCommittedFixture(t *testing.T) (*Service, *queryStore, ports.PublicationRun, domain.ProjectBinding) {
	t.Helper()
	run, snapshot, _, artifacts, _ := queryStatusRoleReportFixture(t)
	final, err := decodeFinalDTO(snapshot.Final().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := decodeManifestDTO(snapshot.Manifest().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	item := &final.Findings[0].Evidence[0]
	path := mustQueryPath(t, item.Current.Path)
	selector, err := ports.NewLiveSourceSelector(domain.LiveSourceWorkspace, "")
	if err != nil {
		t.Fatal(err)
	}
	target, err := ports.NewLiveSourceTarget(selector, ports.GitObjectID{}, ports.GitObjectID{}, false, []ports.LiveSourceChange{{Kind: "included", After: path}})
	if err != nil {
		t.Fatal(err)
	}
	identity, err := evidence.NewLiveSourceIdentity(target)
	if err != nil {
		t.Fatal(err)
	}
	claim, err := evidence.NewLiveClaim(identity, evidence.SideWorktree, path.String(), item.Current.LineStart, item.Current.LineEnd, item.Current.Quote)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := claim.ExcerptSHA256([]byte(item.Current.Quote))
	if err != nil {
		t.Fatal(err)
	}
	item.Current.TargetSHA256, item.Source.SourceTargetSHA256 = "", ""
	item.Current.SourceIdentitySHA256, item.Source.SourceIdentitySHA256 = identity.SHA256(), identity.SHA256()
	item.Current.CurrentExcerptSHA256, item.Source.SourceExcerptSHA256 = digest, digest
	final.SchemaVersion = "mulgae-review-artifact.v3"
	final.Target.ContentSHA256, final.Target.ManifestPath = "", "source/source.json"
	final.Target.BaseOID, final.Target.HeadOID = nil, nil
	final.Target.LiveSource = &evidence.LiveSourceMetadata{Identity: identity.Bytes(), SourceIdentitySHA256: identity.SHA256(), Changes: []evidence.LiveSourceChange{{Kind: "included", After: path.String()}}, Consistency: "caller_maintained", ReplayAvailability: "unsupported", BinaryEvidence: []evidence.LiveBinaryObservation{}}
	productionFinal := queryProductionFinalDTO()
	final.Mulgae = productionFinal.Mulgae
	production := productionFinal.Provenance.Production
	providers := production.Providers
	for i, role := range []string{"logic", "security"} {
		providers[i].Family, providers[i].Instance, providers[i].Version = "agy", "agy-"+role, "1.4.2"
	}
	final.Provenance.Production = nil
	final.Provenance.LiveProduction = &liveProductionProvenanceDTO{BuildProduct: production.BuildProduct, BuildVersion: production.BuildVersion, BuildCommit: production.BuildCommit, ObjectiveSHA256: production.ObjectiveSHA256, ObjectivePresent: production.ObjectivePresent, SourceIdentitySHA256: identity.SHA256(), SourceTerminalReceipt: "source-terminal:v1:sha256:" + strings.Repeat("b", 64), Providers: providers}
	for i := range final.RoleOutcomes {
		instance := "agy-" + final.RoleOutcomes[i].Role
		final.RoleOutcomes[i].ProviderInstance = &instance
	}
	final.Findings[0].ProviderInstance = "agy-logic"
	manifest.SchemaVersion = "mulgae-run-manifest.v3"
	manifest.Target.ContentSHA256, manifest.Target.ManifestPath, manifest.Target.SourceIdentitySHA256 = "", "source/source.json", identity.SHA256()
	for i := range manifest.Attempts {
		manifest.Attempts[i].ProviderInstance = "agy-" + manifest.Attempts[i].Role
	}
	for i := range manifest.RoleReports {
		manifest.RoleReports[i].ProviderInstance = "agy-" + manifest.RoleReports[i].Role
		manifest.RoleReports[i].Transport = "stdout"
	}
	prefix := run.SessionID().String() + "/" + run.RunID().String() + "/"
	support := map[string]ports.ImmutablePublicationArtifact{}
	for _, report := range manifest.RoleReports {
		support[prefix+report.Path] = artifacts[prefix+report.Path]
	}
	sourcePath := mustQueryPath(t, prefix+"source/source.json")
	support[sourcePath.String()] = mustQueryArtifact(t, sourcePath, identity.Bytes())
	findingBytes, err := json.Marshal(final.Findings[0])
	if err != nil {
		t.Fatal(err)
	}
	for relative, body := range map[string][]byte{"excerpts/F001.json": findingBytes, "excerpts/F001_1.md": []byte(item.Current.Quote)} {
		p := mustQueryPath(t, prefix+relative)
		support[p.String()] = mustQueryArtifact(t, p, body)
	}
	index := runtimeSupportIndexDTO{SchemaVersion: "mulgae-run-support-index.v3"}
	for name, artifact := range support {
		index.Artifacts = append(index.Artifacts, artifactIdentityDTO{Path: name, SHA256: artifact.SHA256()})
	}
	sort.Slice(index.Artifacts, func(i, j int) bool { return index.Artifacts[i].Path < index.Artifacts[j].Path })
	indexBytes, err := json.Marshal(index)
	if err != nil {
		t.Fatal(err)
	}
	indexPath := mustQueryPath(t, prefix+"support/index.json")
	support[indexPath.String()] = mustQueryArtifact(t, indexPath, indexBytes)
	manifest.CompositeIdentity.SupportIndex = &artifactIdentityDTO{Path: indexPath.String(), SHA256: querySHA(indexBytes)}
	store := &queryStore{snapshot: snapshot, auxiliaryArtifacts: support}
	rebindInspection(t, store, run, final, manifest)
	binding, err := domain.ParseProjectBinding("sha256:" + strings.Repeat("1", 64))
	if err != nil {
		t.Fatal(err)
	}
	return mustQueryService(t, store, &queryValidator{}, nil), store, run, binding
}

func TestLiveAgyCommittedReadInspectionAndReports(t *testing.T) {
	service, _, run, binding := liveAgyCommittedFixture(t)
	review, err := service.ReadCommitted(context.Background(), run)
	if err != nil {
		t.Fatalf("full committed read: %v", err)
	}
	if _, live := review.LiveSource(); !live || review.SourceIdentitySHA256() == "" || len(review.RoleReports()) != 2 {
		t.Fatal("current AGY read lost live identity or reports")
	}
	page, err := service.Inspect(context.Background(), run, binding, InspectionRequest{QueryKind: "inspect", MinimumSeverity: domain.SeverityLow, Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	if page.CaptureAvailability != "not_captured" || page.SourceIdentitySHA256 != review.SourceIdentitySHA256() || len(page.Findings) != 1 || page.Findings[0].Provider != "agy-logic" || page.Findings[0].Evidence[0].Availability != "verified" {
		t.Fatalf("live inspection: %#v", page)
	}
	if body, err := service.RenderExcerpt(context.Background(), run, "F001", ""); err != nil || !strings.Contains(string(body), "line one") {
		t.Fatalf("live excerpt: %q %v", body, err)
	}
	if report, err := service.ReadReport(context.Background(), run, binding, "logic", ContentContinuation{}, nil); err != nil || string(report.Content) != "# logic\n\nreport\n" {
		t.Fatalf("live report: %#v %v", report, err)
	}
}

func TestLiveAgyCommittedReadRejectsKimiAndDamagedSupport(t *testing.T) {
	for _, damage := range []string{"kimi", "source bytes"} {
		t.Run(damage, func(t *testing.T) {
			service, store, run, _ := liveAgyCommittedFixture(t)
			if damage == "kimi" {
				final, _ := decodeFinalDTO(store.snapshot.Final().Bytes())
				manifest, _ := decodeManifestDTO(store.snapshot.Manifest().Bytes())
				final.Provenance.LiveProduction.Providers[0].Family = "kimi"
				rebindInspection(t, store, run, final, manifest)
			} else {
				p := mustQueryPath(t, run.SessionID().String()+"/"+run.RunID().String()+"/source/source.json")
				store.auxiliaryArtifacts[p.String()] = mustQueryArtifact(t, p, []byte("damaged"))
			}
			_, err := service.ReadCommitted(context.Background(), run)
			var failure *domain.Failure
			if !errors.As(err, &failure) || failure.Class() != domain.FailureArtifact || damage == "kimi" && failure.Reason() != retiredProviderArtifactReason {
				t.Fatalf("damage escaped full read boundary: %v", err)
			}
		})
	}
}
