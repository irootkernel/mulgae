package compositesupport

import (
	"bytes"
	"encoding/json"
	"strings"
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

func supportArtifacts(t *testing.T, session domain.SessionID, run domain.RunID, materials ...Material) map[string]ports.ImmutablePublicationArtifact {
	t.Helper()
	built, err := Build(session, run, materials)
	if err != nil {
		t.Fatal(err)
	}
	result := map[string]ports.ImmutablePublicationArtifact{}
	for _, a := range built {
		result[a.Path().String()] = a
	}
	return result
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

func TestCopiedSupportRetainsEveryEvidenceAndSourceKind(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		name := "published"
		if recovery {
			name = "recovery"
		}
		t.Run(name, func(t *testing.T) {
			session, run, material, final := supportFixture(t, recovery)
			artifacts := supportArtifacts(t, session, run, material)
			doc, err := Verify(session, run, material.Source.TargetSHA256, artifacts)
			if err != nil {
				t.Fatal(err)
			}
			if err := VerifyFinal(doc, session, run, final, artifacts); err != nil {
				t.Fatal(err)
			}
			prefix := session.String() + "/" + run.String() + "/"
			if !bytes.Equal(artifacts[prefix+FindingPath("F001")].Bytes(), material.Findings[0].Original) {
				t.Fatal("original finding was rewritten during remapping")
			}
			for i, want := range material.Findings[0].Excerpts {
				if !bytes.Equal(artifacts[prefix+ExcerptPath("F001", i)].Bytes(), want) {
					t.Fatalf("evidence %d was lost", i)
				}
			}
			if recovery && (doc.Sources[0].ReviewID != "" || doc.Sources[0].Epoch != 0 || doc.Sources[0].FinalSHA256 != "") {
				t.Fatal("recovery source fabricated P2 receipt")
			}
			for _, forbidden := range []string{"project_binding", "canonical_root"} {
				if bytes.Contains(artifacts[prefix+DocumentPath].Bytes(), []byte(forbidden)) {
					t.Fatal("portable source includes local binding")
				}
			}
		})
	}
}

func TestCopiedSupportRejectsCorruptIncompleteOrExtraArtifacts(t *testing.T) {
	for _, kind := range []string{"missing original", "changed original", "missing second evidence", "changed second evidence", "extra evidence", "extra source finding", "swapped evidence"} {
		t.Run(kind, func(t *testing.T) {
			session, run, material, _ := supportFixture(t, false)
			artifacts := supportArtifacts(t, session, run, material)
			prefix := session.String() + "/" + run.String() + "/"
			switch kind {
			case "missing original":
				delete(artifacts, prefix+FindingPath("F001"))
			case "changed original":
				replaceArtifact(t, artifacts, prefix+FindingPath("F001"), []byte(`{"id":"F007","title":"changed"}`))
			case "missing second evidence":
				delete(artifacts, prefix+ExcerptPath("F001", 1))
			case "changed second evidence":
				replaceArtifact(t, artifacts, prefix+ExcerptPath("F001", 1), []byte("changed\n"))
			case "extra evidence":
				replaceArtifact(t, artifacts, prefix+ExcerptPath("F001", 2), []byte("extra\n"))
			case "extra source finding":
				replaceArtifact(t, artifacts, prefix+FindingPath("F002"), material.Findings[0].Original)
			case "swapped evidence":
				replaceArtifact(t, artifacts, prefix+ExcerptPath("F001", 1), material.Findings[0].Excerpts[0])
			}
			if _, err := Verify(session, run, material.Source.TargetSHA256, artifacts); err == nil {
				t.Fatal("accepted invalid copied support")
			}
		})
	}
}

func TestCopiedSupportBindsSourceFindingAndFinalRemapping(t *testing.T) {
	for _, mutation := range []string{"source run", "source finding", "content", "provider", "missing finding", "claim range"} {
		t.Run(mutation, func(t *testing.T) {
			session, run, material, final := supportFixture(t, false)
			artifacts := supportArtifacts(t, session, run, material)
			doc, err := Verify(session, run, material.Source.TargetSHA256, artifacts)
			if err != nil {
				t.Fatal(err)
			}
			var decoded map[string]any
			if err := json.Unmarshal(final, &decoded); err != nil {
				t.Fatal(err)
			}
			finding := decoded["findings"].([]any)[0].(map[string]any)
			switch mutation {
			case "source run":
				finding["source"].(map[string]any)["run_id"] = run.String()
			case "source finding":
				finding["source"].(map[string]any)["finding_id"] = "F008"
			case "content":
				finding["description"] = "Altered after selection"
			case "provider":
				decoded["role_outcomes"].([]any)[0].(map[string]any)["provider_instance"] = "other-provider"
			case "missing finding":
				decoded["findings"] = []any{}
			case "claim range":
				doc.Findings[0].Evidence[1].LineStart++
			}
			raw, err := json.Marshal(decoded)
			if err != nil {
				t.Fatal(err)
			}
			if err := VerifyFinal(doc, session, run, raw, artifacts); err == nil {
				t.Fatal("accepted mismatched final/support")
			}
		})
	}
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

func TestCommonCaptureIncludesRolesWithoutFindings(t *testing.T) {
	for _, mode := range []string{"equal", "different context", "different support file", "unavailable"} {
		t.Run(mode, func(t *testing.T) {
			session, run, logic, _ := supportFixture(t, false)
			attachCapture(t, &logic, "same context")
			documentation := Clone(logic)
			documentation.Source.Role = domain.RoleDocumentation
			documentation.Findings = nil
			switch mode {
			case "different context":
				attachCapture(t, &documentation, "different context")
			case "different support file":
				attachCaptureWithSupport(t, &documentation, "same context", "changed unchanged support\n")
			case "unavailable":
				documentation.Source.CaptureAvailability = "capture_identity_unavailable"
				documentation.Source.CaptureIdentity = ""
				documentation.CapturedArchive = nil
				documentation.CaptureManifest = nil
			}
			artifacts := supportArtifacts(t, session, run, logic, documentation)
			doc, err := Verify(session, run, logic.Source.TargetSHA256, artifacts)
			if err != nil {
				t.Fatal(err)
			}
			want := ""
			if mode == "equal" {
				want = logic.Source.CaptureIdentity
			}
			if got := doc.CommonCapture(); got != want {
				t.Fatalf("common capture = %q, want %q", got, want)
			}
			if len(doc.Sources) != 2 || len(doc.Findings) != 1 {
				t.Fatal("no-findings role disappeared from source inventory")
			}
		})
	}
}

func TestCopiedCaptureRejectsLostBlobAndUnlistedSourceMaterial(t *testing.T) {
	for _, extra := range []bool{false, true} {
		name := "missing"
		if extra {
			name = "extra"
		}
		t.Run(name, func(t *testing.T) {
			session, run, material, _ := supportFixture(t, false)
			attachCapture(t, &material, "context")
			artifacts := supportArtifacts(t, session, run, material)
			prefix := session.String() + "/" + run.String() + "/" + SourcePrefix(domain.RoleLogic)
			if extra {
				replaceArtifact(t, artifacts, prefix+"blobs/sha256-"+strings.Repeat("a", 64), []byte("extra"))
			} else {
				removed := false
				for path := range artifacts {
					if strings.HasPrefix(path, prefix+"blobs/") {
						delete(artifacts, path)
						removed = true
						break
					}
				}
				if !removed {
					t.Fatal("fixture contains no source blob")
				}
			}
			if _, err := Verify(session, run, material.Source.TargetSHA256, artifacts); err == nil {
				t.Fatal("accepted invalid source capture inventory")
			}
		})
	}
}

func TestCopiedSupportRejectsRecoveryPublicationAndUnavailableBytes(t *testing.T) {
	for _, kind := range []string{"recovery P2", "unavailable evidence", "unavailable capture", "wrong index"} {
		t.Run(kind, func(t *testing.T) {
			session, run, material, _ := supportFixture(t, true)
			switch kind {
			case "recovery P2":
				material.Source.Epoch = 1
			case "unavailable evidence":
				material.Findings[0].Finding.Evidence[1].Availability = "evidence_unavailable"
				material.Findings[0].Finding.Evidence[1].ContentSHA256 = ""
			case "unavailable capture":
				material.CapturedArchive = []byte("unexpected")
			case "wrong index":
				material.Findings[0].Finding.Evidence[1].Index = 0
			}
			if _, err := Build(session, run, []Material{material}); err == nil {
				t.Fatal("accepted inconsistent source support")
			}
		})
	}
}

func TestCopiedSupportPreservesExplicitUnavailableEvidence(t *testing.T) {
	session, run, material, final := supportFixture(t, false)
	material.Findings[0].Finding.Evidence[1].Availability = "evidence_unavailable"
	material.Findings[0].Finding.Evidence[1].ContentSHA256 = ""
	material.Findings[0].Excerpts[1] = nil
	artifacts := supportArtifacts(t, session, run, material)
	doc, err := Verify(session, run, material.Source.TargetSHA256, artifacts)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyFinal(doc, session, run, final, artifacts); err != nil {
		t.Fatal(err)
	}
	path := session.String() + "/" + run.String() + "/" + ExcerptPath("F001", 1)
	if _, ok := artifacts[path]; ok {
		t.Fatal("unavailable historical evidence manufactured a quote")
	}
	if len(doc.Findings[0].Evidence) != 2 || doc.Findings[0].Evidence[1].Availability != "evidence_unavailable" {
		t.Fatal("unavailable index lost")
	}
}
