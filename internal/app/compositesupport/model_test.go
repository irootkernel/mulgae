package compositesupport

import (
	"encoding/json"
	"testing"

	"github.com/irootkernel/mulgae/internal/app/evidence"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

func supportFixture(t *testing.T, recovery bool) (domain.SessionID, domain.RunID, Material, []byte) {
	t.Helper()
	session, _ := domain.ParseSessionID("s_019f596a-cf80-7c67-b265-f37053d51ccf")
	run, _ := domain.ParseRunID("r_019f596a-cfe4-7c9c-b82e-7149158243ba")
	source := Source{Role: domain.RoleLogic, SessionID: session.String(), RunID: "r_019f596a-cfe5-7c9c-b82e-7149158243ba", ReviewID: "019f596a-d175-7321-b920-c2d312c82cc2", AttemptID: "a_019f596a-d048-79e7-b2b7-59822f012273", FinalSHA256: SHA256([]byte("final")), ManifestSHA256: SHA256([]byte("manifest")), SupportSHA256: SHA256([]byte("support")), LineageSHA256: SHA256([]byte("lineage")), Epoch: 1, TargetSHA256: SHA256([]byte("patch\n")), ProviderIdentities: []string{"codex-primary"}, CaptureAvailability: "capture_identity_unavailable"}
	if recovery {
		source.RecoveryManifestSHA256 = SHA256([]byte("recovery"))
		source.ReviewID = ""
		source.FinalSHA256 = ""
		source.ManifestSHA256 = ""
		source.SupportSHA256 = ""
		source.LineageSHA256 = ""
		source.Epoch = 0
	}
	finding := map[string]any{"id": "F007", "role": "logic", "severity": "low", "title": "Original title", "description": "Original description", "recommendation": "Retain every claim", "confidence": "high", "lifecycle": "open", "fingerprint": SHA256([]byte("finding"))}
	item := FindingMaterial{Finding: Finding{ID: "F001", Role: domain.RoleLogic, SourceFindingID: "F007", Evidence: []Evidence{}}, Excerpts: [][]byte{}}
	claims := []any{}
	for i, quote := range []string{"first quote\n", "second quote\n"} {
		claim, err := evidence.NewCurrentClaim(evidence.CurrentClaimInput{TargetSHA256: source.TargetSHA256, Side: evidence.SideHead, Path: "a.go", LineStart: i + 1, LineEnd: i + 1, Quote: quote})
		if err != nil {
			t.Fatal(err)
		}
		digest, err := claim.ExcerptSHA256([]byte(quote))
		if err != nil {
			t.Fatal(err)
		}
		ref := Evidence{Index: i, Availability: "verified", TargetSHA256: source.TargetSHA256, Side: evidence.SideHead, Path: "a.go", LineStart: i + 1, LineEnd: i + 1, ExcerptSHA256: digest, ContentSHA256: SHA256([]byte(quote))}
		item.Finding.Evidence = append(item.Finding.Evidence, ref)
		item.Excerpts = append(item.Excerpts, []byte(quote))
		wire := map[string]any{"target_sha256": source.TargetSHA256, "side": "head", "path": "a.go", "line_start": i + 1, "line_end": i + 1, "quote": quote}
		if recovery {
			wire["excerpt_sha256"] = digest
			claims = append(claims, wire)
		} else {
			wire["current_excerpt_sha256"] = digest
			claims = append(claims, map[string]any{"current": wire})
		}
	}
	finding["evidence"] = claims
	original, err := json.Marshal(finding)
	if err != nil {
		t.Fatal(err)
	}
	item.Original = original
	item.Finding.OriginalSHA256 = SHA256(original)
	origin := map[string]any{"run_id": source.RunID, "review_id": source.ReviewID, "recovery_manifest_sha256": source.RecoveryManifestSHA256, "attempt_id": source.AttemptID, "finding_id": "F007"}
	finding["id"] = "F001"
	finding["source"] = origin
	delete(finding, "evidence")
	final, err := json.Marshal(map[string]any{"role_outcomes": []any{map[string]any{"role": "logic", "provider_instance": "codex-primary"}}, "review_composition": map[string]any{"sources": []any{map[string]any{"role": "logic", "run_id": source.RunID, "review_id": source.ReviewID, "recovery_manifest_sha256": source.RecoveryManifestSHA256, "attempt_id": source.AttemptID}}}, "findings": []any{finding}})
	if err != nil {
		t.Fatal(err)
	}
	return session, run, Material{Source: source, Findings: []FindingMaterial{item}}, final
}

func replaceArtifact(t *testing.T, artifacts map[string]ports.ImmutablePublicationArtifact, path string, raw []byte) {
	t.Helper()
	safe, err := ports.NewSafeRelativePath(path)
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := ports.NewImmutablePublicationArtifact(safe, SHA256(raw), raw)
	if err != nil {
		t.Fatal(err)
	}
	artifacts[path] = artifact
}

func attachCapture(t *testing.T, material *Material, context string) {
	t.Helper()
	attachCaptureWithSupport(t, material, context, "unchanged support\n")
}

func attachCaptureWithSupport(t *testing.T, material *Material, context, support string) {
	t.Helper()
	target, err := ports.NewCapturedReviewPatchTarget([]byte("patch\n"))
	if err != nil {
		t.Fatal(err)
	}
	path, _ := ports.NewSafeRelativePath("a.go")
	file, err := ports.NewWorkspaceSnapshotFile(path, []byte("first quote\nsecond quote\n"), SHA256([]byte("first quote\nsecond quote\n")))
	if err != nil {
		t.Fatal(err)
	}
	supportPath, _ := ports.NewSafeRelativePath("unchanged.go")
	supportFile, err := ports.NewWorkspaceSnapshotFile(supportPath, []byte(support), SHA256([]byte(support)))
	if err != nil {
		t.Fatal(err)
	}
	request, err := ports.NewWorkspaceSnapshotRequest([]ports.WorkspaceSnapshotFile{file, supportFile}, "copied-support-test")
	if err != nil {
		t.Fatal(err)
	}
	sides, err := ports.NewCapturedTargetEvidence(map[ports.CapturedEvidenceSide][]ports.WorkspaceSnapshotFile{ports.CapturedEvidenceHead: {file, supportFile}})
	if err != nil {
		t.Fatal(err)
	}
	captured, err := ports.NewCapturedReviewMaterialWithEvidence(target, request, []byte(context), sides)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := ports.MarshalCapturedReviewMaterial(captured)
	if err != nil {
		t.Fatal(err)
	}
	if err := RetainCapture(material, raw); err != nil {
		t.Fatal(err)
	}
}
