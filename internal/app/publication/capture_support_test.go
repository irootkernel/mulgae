package publication

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/app/capture"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

func TestNoChangePublicationRetainsCompleteCaptureSupport(t *testing.T) {
	session, _ := domain.ParseSessionID("s_019f596a-cf80-7c67-b265-f37053d51ccf")
	run, _ := domain.ParseRunID("r_019f596a-cfe4-7c9c-b82e-7149158243ba")
	oid, _ := ports.ParseGitObjectID(strings.Repeat("a", 40))
	target, err := ports.NewCapturedReviewGitTarget("repository:test", oid, oid, oid, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	path, _ := ports.NewSafeRelativePath("unchanged.txt")
	file, err := ports.NewWorkspaceSnapshotFile(path, []byte("unchanged support"), sha256Identifier([]byte("unchanged support")))
	if err != nil {
		t.Fatal(err)
	}
	files := []ports.WorkspaceSnapshotFile{file}
	snapshot, err := ports.NewWorkspaceSnapshotRequest(files, "capture-support-test")
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := ports.NewCapturedTargetEvidence(map[ports.CapturedEvidenceSide][]ports.WorkspaceSnapshotFile{ports.CapturedEvidenceBase: files, ports.CapturedEvidenceHead: files})
	if err != nil {
		t.Fatal(err)
	}
	material, err := ports.NewCapturedReviewMaterialWithEvidence(target, snapshot, nil, evidence)
	if err != nil {
		t.Fatal(err)
	}
	archive, err := ports.MarshalCapturedReviewMaterial(material)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := PrepareNoChangeCandidate(session, run, target.Identity(), []domain.Role{domain.RoleLogic}, domain.SeverityHigh, NoChangeProvenance{BuildProduct: "mulgae", BuildVersion: "test", BuildCommit: "0123456789abcdef", SnapshotManifestSHA256: "sha256:" + strings.Repeat("a", 64), WorkspaceTerminalReceipt: "workspace-terminal:v1:sha256:" + strings.Repeat("b", 64)})
	if err != nil {
		t.Fatal(err)
	}
	candidate, err = candidate.WithCapturedMaterial(archive)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := candidate.Build(context.Background(), &publicationTestValidator{}, publicationTestReviewID(t), publicationTestTime(), 1)
	if err != nil {
		t.Fatal(err)
	}
	artifacts := map[string]ports.ImmutablePublicationArtifact{}
	var index runSupportIndexWire
	for _, artifact := range bundle.SupportArtifacts() {
		artifacts[artifact.Path().String()] = artifact
		if strings.HasSuffix(artifact.Path().String(), "/support/index.json") {
			if err := json.Unmarshal(artifact.Bytes(), &index); err != nil {
				t.Fatal(err)
			}
		}
	}
	if index.SchemaVersion != "mulgae-run-support-index.v2" {
		t.Fatalf("index version = %q", index.SchemaVersion)
	}
	if _, err := capture.VerifySupport(session, run, "sha256:"+target.Identity().SHA256(), &candidate.target.baseOID, &candidate.target.headOID, artifacts); err != nil {
		t.Fatal(err)
	}

	wrongOID := strings.Repeat("b", 40)
	if _, err := capture.VerifySupport(session, run, candidate.target.sha256, &wrongOID, &candidate.target.headOID, artifacts); err == nil {
		t.Fatal("capture support accepted a different final base OID")
	}
	var final finalReviewWire
	if err := json.Unmarshal(bundle.Final().Bytes(), &final); err != nil {
		t.Fatal(err)
	}
	if final.RoleOutcomes[0].AttemptID != nil || final.RoleOutcomes[0].ProviderInstance != nil {
		t.Fatal("no-change acquired provider evidence")
	}

	// A correctly rehashed v1 index must not downgrade new capture support.
	index.SchemaVersion = "mulgae-run-support-index.v1"
	downgradedBytes, err := json.Marshal(index)
	if err != nil {
		t.Fatal(err)
	}
	downgraded := append([]ports.ImmutablePublicationArtifact(nil), bundle.SupportArtifacts()...)
	var downgradedIdentity artifactIdentityWire
	for i, artifact := range downgraded {
		if strings.HasSuffix(artifact.Path().String(), "/support/index.json") {
			downgraded[i], err = immutableArtifact(artifact.Path(), downgradedBytes)
			if err != nil {
				t.Fatal(err)
			}
			downgradedIdentity = artifactIdentityWire{Path: artifact.Path().String(), SHA256: downgraded[i].SHA256()}
		}
	}
	if err := validateBundleSupportIndex(downgraded, downgradedIdentity, session, run, "sha256:"+target.Identity().SHA256(), &candidate.target.baseOID, &candidate.target.headOID); err == nil {
		t.Fatal("capture support accepted a v1 downgrade")
	}
	for name, artifact := range artifacts {
		if strings.Contains(name, "/target/") {
			delete(artifacts, name)
			if _, err := capture.VerifySupport(session, run, "sha256:"+target.Identity().SHA256(), &candidate.target.baseOID, &candidate.target.headOID, artifacts); err == nil {
				t.Fatalf("missing %s accepted", name)
			}
			artifacts[name] = artifact
		}
	}
}

func TestChildPublicationDerivesCaptureSupportFromRetainedRuntime(t *testing.T) {
	for _, kind := range []domain.RunType{domain.RunTypeFollowup, domain.RunTypeDelta, domain.RunTypeRerun} {
		t.Run(string(kind), func(t *testing.T) {
			candidate := publicationRuntimeCandidate(t)
			candidate.lineage.runType = kind
			target, err := ports.NewCapturedReviewPatchTarget([]byte("reviewed line\n"))
			if err != nil {
				t.Fatal(err)
			}
			snapshot, err := ports.NewWorkspaceSnapshotRequest(nil, "child-capture-test")
			if err != nil {
				t.Fatal(err)
			}
			evidence, err := ports.NewCapturedTargetEvidence(map[ports.CapturedEvidenceSide][]ports.WorkspaceSnapshotFile{ports.CapturedEvidenceHead: nil})
			if err != nil {
				t.Fatal(err)
			}
			material, err := ports.NewCapturedReviewMaterialWithEvidence(target, snapshot, nil, evidence)
			if err != nil {
				t.Fatal(err)
			}
			archive, err := ports.MarshalCapturedReviewMaterial(material)
			if err != nil {
				t.Fatal(err)
			}
			for ri := range candidate.roles {
				for ai := range candidate.roles[ri].attempts {
					for ii := range candidate.roles[ri].attempts[ai].invocations {
						candidate.roles[ri].attempts[ai].invocations[ii].runtime.capturedArchive = archive
					}
				}
			}
			artifacts, err := candidate.buildRuntimeArtifacts()
			if err != nil {
				t.Fatal(err)
			}
			artifacts, err = candidate.buildCaptureSupport(artifacts)
			if err != nil {
				t.Fatal(err)
			}
			byPath := make(map[string]ports.ImmutablePublicationArtifact)
			for _, artifact := range artifacts {
				byPath[artifact.Path().String()] = artifact
			}
			if _, err := capture.VerifySupport(candidate.sessionID, candidate.runID, candidate.target.sha256, &candidate.target.baseOID, &candidate.target.headOID, byPath); err != nil {
				t.Fatal(err)
			}
		})
	}
}
