package publication

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/app/evidence"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

func livePublicationEmptyTarget(t *testing.T) ports.LiveSourceTarget {
	t.Helper()
	selector, err := ports.NewLiveSourceSelector(domain.LiveSourceWorkspace, "")
	if err != nil {
		t.Fatal(err)
	}
	target, err := ports.NewLiveSourceTarget(selector, ports.GitObjectID{}, ports.GitObjectID{}, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	return target
}

func livePublicationNoChange(t *testing.T) PreparedLiveCandidate {
	t.Helper()
	legacy := publicationTestCandidate(t, false)
	target := livePublicationEmptyTarget(t)
	identity, err := evidence.NewLiveSourceIdentity(target)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := PrepareLiveNoChangeCandidate(legacy.SessionID(), legacy.RunID(), target, []domain.Role{domain.RoleLogic, domain.RoleSecurity}, domain.SeverityHigh, LiveProductionProvenance{
		BuildProduct: "mulgae", BuildVersion: "test", BuildCommit: "0123456789abcdef", SourceIdentitySHA256: identity.SHA256(), SourceTerminalReceipt: "source-terminal:v1:sha256:" + strings.Repeat("b", 64),
	})
	if err != nil {
		t.Fatal(err)
	}
	return candidate
}

func TestLiveNoChangeBuildUsesSourceMetadataWithoutCapturedContent(t *testing.T) {
	candidate := livePublicationNoChange(t)
	validator := &publicationTestValidator{}
	bundle, err := candidate.Build(context.Background(), validator, publicationTestReviewID(t), publicationTestTime(), 1)
	if err != nil {
		t.Fatal(err)
	}
	var final finalReviewWire
	var manifest runManifestWire
	if err := unmarshalCanonicalPublicationRecord(bundle.Final().Bytes(), &final, "final"); err != nil {
		t.Fatal(err)
	}
	if err := unmarshalCanonicalPublicationRecord(bundle.Manifest().Bytes(), &manifest, "manifest"); err != nil {
		t.Fatal(err)
	}
	if final.SchemaVersion != "mulgae-review-artifact.v3" || manifest.SchemaVersion != "mulgae-run-manifest.v3" || final.Target.ContentSHA256 != "" || manifest.Target.ContentSHA256 != "" || final.Target.LiveSource == nil || !final.Target.LiveSource.NoChange {
		t.Fatal("live no-change publication claimed captured contents")
	}
	if final.Provenance.Production != nil || final.Provenance.LiveProduction == nil || len(final.Provenance.LiveProduction.Providers) != 0 || len(manifest.Attempts) != 0 || len(manifest.RoleReports) != 0 || len(final.Findings) != 0 {
		t.Fatal("no-change publication contained capture or provider work")
	}
	for _, data := range [][]byte{bundle.Final().Bytes(), bundle.Manifest().Bytes()} {
		if bytes.Contains(data, []byte("content_sha256")) || bytes.Contains(data, []byte("snapshot_manifest_sha256")) || bytes.Contains(data, []byte("workspace_terminal_receipt")) {
			t.Fatal("live result contained an immutable-source claim")
		}
	}
	if len(validator.ids) != 2 || validator.ids[0].String() != strings.Replace(finalReviewSchemaAsset, ".v1.", ".v3.", 1) || validator.ids[1].String() != strings.Replace(runManifestSchemaAsset, ".v1.", ".v3.", 1) {
		t.Fatal("live format validated against a historical schema")
	}
	if len(bundle.Excerpts()) != 2 {
		t.Fatal("empty selection retained source contents or prompts")
	}
	var index runSupportIndexWire
	if err := json.Unmarshal(bundle.Excerpts()[1].Bytes(), &index); err != nil {
		t.Fatal(err)
	}
	if index.SchemaVersion != "mulgae-run-support-index.v3" || len(index.Artifacts) != 1 {
		t.Fatal("live support index claimed capture support")
	}
	if final.Target.LiveSource.Consistency != "caller_maintained" || final.Target.LiveSource.ReplayAvailability != "unsupported" {
		t.Fatal("mutable consistency or replay claims were lost")
	}
}

func TestLiveCandidateRejectsCapturedMaterialAndBindsSourceClosure(t *testing.T) {
	first := livePublicationNoChange(t)
	second := livePublicationNoChange(t)
	if first.ValidatedCandidateSHA256() == "" || first.ValidatedCandidateSHA256() != second.ValidatedCandidateSHA256() {
		t.Fatal("live candidate identity is not deterministic")
	}
	second.candidate.target.live.provenance.SourceTerminalReceipt = "source-terminal:v1:sha256:" + strings.Repeat("c", 64)
	if !second.Valid() || first.ValidatedCandidateSHA256() == second.ValidatedCandidateSHA256() {
		t.Fatal("source terminal closure did not bind candidate identity")
	}
	second.candidate.capturedArchive = []byte("retired capture")
	if second.Valid() {
		t.Fatal("captured archive entered a live candidate")
	}
	if _, err := second.Build(context.Background(), &publicationTestValidator{}, publicationTestReviewID(t), publicationTestTime(), 1); err == nil {
		t.Fatal("invalid live candidate reached publication")
	}
}

func TestPublicationRejectsMixedCapturedAndLiveTargetAuthority(t *testing.T) {
	for _, live := range []bool{false, true} {
		for _, field := range []string{"source identity", "production provenance"} {
			t.Run(field+"/live="+strconv.FormatBool(live), func(t *testing.T) {
				candidate := publicationTestCandidate(t, false)
				if live {
					candidate = livePublicationNoChange(t).candidate
				}
				bundle, err := candidate.Build(context.Background(), &publicationTestValidator{}, publicationTestReviewID(t), publicationTestTime(), 1)
				if err != nil {
					t.Fatal(err)
				}
				var final finalReviewWire
				var manifest runManifestWire
				if err := json.Unmarshal(bundle.Final().Bytes(), &final); err != nil {
					t.Fatal(err)
				}
				if err := json.Unmarshal(bundle.Manifest().Bytes(), &manifest); err != nil {
					t.Fatal(err)
				}
				if err := validatePublicationTargetFormats(final, manifest); err != nil {
					t.Fatalf("valid publication fixture: %v", err)
				}
				if field == "source identity" {
					if live {
						manifest.Target.ContentSHA256 = "sha256:" + strings.Repeat("a", 64)
					} else {
						manifest.Target.SourceIdentitySHA256 = "sha256:" + strings.Repeat("a", 64)
					}
				} else if live {
					final.Provenance.Production = &productionProvenanceWire{}
				} else {
					final.Provenance.LiveProduction = &liveProductionProvenanceWire{}
				}
				if err := validatePublicationTargetFormats(final, manifest); err == nil {
					t.Fatal("mixed target authority accepted")
				}
			})
		}
	}
}

func TestHistoricalPublicationRejectsManifestBoundLiveSupport(t *testing.T) {
	fixture := newPublicationServiceFixture(t)
	for _, suffix := range []string{"source/source.json", "evidence/images/sha256-" + strings.Repeat("a", 64) + ".png"} {
		t.Run(suffix, func(t *testing.T) {
			prefix := fixture.run.SessionID().String() + "/" + fixture.run.RunID().String() + "/"
			path, _ := ports.NewSafeRelativePath(prefix + suffix)
			artifact, err := immutableArtifact(path, []byte("adversarial live support"))
			if err != nil {
				t.Fatal(err)
			}
			indexPath, _ := ports.NewSafeRelativePath(prefix + "support/index.json")
			indexBytes, _ := marshalCanonical(runSupportIndexWire{SchemaVersion: "mulgae-run-support-index.v1", Artifacts: []artifactIdentityWire{{Path: path.String(), SHA256: artifact.SHA256()}}})
			index, err := immutableArtifact(indexPath, indexBytes)
			if err != nil {
				t.Fatal(err)
			}
			identity := artifactIdentityWire{Path: index.Path().String(), SHA256: index.SHA256()}
			if err := validateBundleSupportIndex([]ports.ImmutablePublicationArtifact{artifact, index}, identity, fixture.run.SessionID(), fixture.run.RunID(), fixture.candidate.target.sha256, nil, nil); err == nil {
				t.Fatal("captured bundle admitted live support")
			}
			var manifest runManifestWire
			if err := json.Unmarshal(fixture.bundle.Manifest().Bytes(), &manifest); err != nil {
				t.Fatal(err)
			}
			manifest.CompositeIdentity.SupportIndex = identity
			manifestBytes, _ := marshalCanonical(manifest)
			boundManifest, err := immutableArtifact(fixture.bundle.Manifest().Path(), manifestBytes)
			if err != nil {
				t.Fatal(err)
			}
			snapshot, err := ports.NewCommittedPublicationSnapshot(fixture.bundle.Final(), boundManifest, fixture.bundle.LineageEdge(), fixture.bundle.Epoch())
			if err != nil {
				t.Fatal(err)
			}
			store := newPublicationServiceHappyStore(t, fixture)
			store.readAuxiliary = func(request ports.ReadAuxiliaryArtifactRequest) (ports.ImmutablePublicationArtifact, error) {
				if request.Path() == index.Path() {
					return index, nil
				}
				if request.Path() == artifact.Path() {
					return artifact, nil
				}
				return ports.ImmutablePublicationArtifact{}, errors.New("unexpected fixture path")
			}
			service, err := NewService(store, publicationServiceValidator{}, publicationServiceClock{now: publicationTestTime()}, 8<<20)
			if err != nil {
				t.Fatal(err)
			}
			_, err = service.readManifestBoundSupportArtifacts(context.Background(), fixture.run, snapshot)
			var failure *domain.Failure
			if !errors.As(err, &failure) || failure.Class() != domain.FailureArtifact || len(store.calls) != 2 {
				t.Fatalf("historical live support admission: %v, reads %v", err, store.calls)
			}
		})
	}
}

func TestLivePublicationRejectsReboundResolvedOperands(t *testing.T) {
	bundle, err := livePublicationNoChange(t).Build(context.Background(), &publicationTestValidator{}, publicationTestReviewID(t), publicationTestTime(), 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"base", "head"} {
		t.Run(field, func(t *testing.T) {
			var final finalReviewWire
			var manifest runManifestWire
			if err := json.Unmarshal(bundle.Final().Bytes(), &final); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(bundle.Manifest().Bytes(), &manifest); err != nil {
				t.Fatal(err)
			}
			if err := validatePublicationTargetFormats(final, manifest); err != nil {
				t.Fatalf("valid live publication: %v", err)
			}
			oid := strings.Repeat("a", 40)
			if field == "base" {
				final.Target.BaseOID = &oid
			} else {
				final.Target.HeadOID = &oid
			}
			if err := validatePublicationTargetFormats(final, manifest); err == nil {
				t.Fatal("resolved operands disagree with source selection")
			}
		})
	}
}
