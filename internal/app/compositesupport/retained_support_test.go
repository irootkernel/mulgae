package compositesupport

import (
	"bytes"
	"encoding/json"
	"sort"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
	"github.com/irootkernel/mulgae/internal/testsupport/historical"
)

// Assemble untrusted input, including inconsistent graphs. In particular this
// helper never calls Build, Verify, VerifyFinal or a domain acceptance policy.
func retainedSupportArtifacts(t *testing.T, session domain.SessionID, run domain.RunID, materials ...Material) map[string]ports.ImmutablePublicationArtifact {
	t.Helper()
	prefix := session.String() + "/" + run.String() + "/"
	artifacts := map[string]ports.ImmutablePublicationArtifact{}
	add := func(path string, raw []byte) { replaceArtifact(t, artifacts, prefix+path, raw) }
	doc := Document{SchemaVersion: Version, Sources: []Source{}, Findings: []Finding{}}
	for _, material := range materials {
		doc.Sources = append(doc.Sources, material.Source)
		if len(material.CaptureManifest) != 0 {
			add(SourcePrefix(material.Source.Role)+"capture-manifest.json", material.CaptureManifest)
		}
		if len(material.CapturedArchive) != 0 {
			// Valid archive transport is unpacked, but malformed bytes are also
			// admitted to the graph so the actual verifier must refuse them.
			captured, err := ports.UnmarshalCapturedReviewMaterial(material.CapturedArchive)
			if err != nil {
				add(SourcePrefix(material.Source.Role)+"captured-review.json", material.CapturedArchive)
			} else {
				archive, err := ports.NewCapturedReviewArchive(captured)
				if err != nil {
					t.Fatal(err)
				}
				add(SourcePrefix(material.Source.Role)+"captured-review.json", archive.Manifest())
				for _, blob := range archive.Blobs() {
					add(SourcePrefix(material.Source.Role)+blob.Path().String(), blob.Bytes())
				}
			}
		}
		for _, item := range material.Findings {
			doc.Findings = append(doc.Findings, item.Finding)
			add(FindingPath(item.Finding.ID), item.Original)
			for i, raw := range item.Excerpts {
				if len(raw) != 0 {
					add(ExcerptPath(item.Finding.ID, i), raw)
				}
			}
		}
	}
	sort.Slice(doc.Sources, func(i, j int) bool { return roleIndex(doc.Sources[i].Role) < roleIndex(doc.Sources[j].Role) })
	sort.Slice(doc.Findings, func(i, j int) bool { return doc.Findings[i].ID < doc.Findings[j].ID })
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	add(DocumentPath, append(raw, '\n'))
	return artifacts
}

func TestRetainCaptureUsesFrozenManifestBytes(t *testing.T) {
	corpus, err := historical.Load()
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, c := range corpus.Cases {
		if c.ID != "composite-copied-v1" && c.ID != "composite-copied-v2" {
			continue
		}
		t.Run(c.ID, func(t *testing.T) {
			files := c.Artifacts()
			prefix := c.SessionID + "/" + c.RunID + "/"
			var doc Document
			if err := json.Unmarshal(files[prefix+DocumentPath], &doc); err != nil {
				t.Fatal(err)
			}
			for _, source := range doc.Sources {
				t.Run(string(source.Role), func(t *testing.T) {
					base := prefix + SourcePrefix(source.Role)
					manifest := files[base+"captured-review.json"]
					refs, err := ports.CapturedReviewArchiveBlobReferences(manifest)
					if err != nil {
						t.Fatal(err)
					}
					var blobs []ports.CapturedReviewArchiveBlob
					for _, ref := range refs {
						blob, err := ports.NewCapturedReviewArchiveBlob(ref.Path(), files[base+ref.Path().String()])
						if err != nil {
							t.Fatal(err)
						}
						blobs = append(blobs, blob)
					}
					captured, err := ports.RestoreCapturedReviewArchive(manifest, blobs)
					if err != nil {
						t.Fatal(err)
					}
					raw, err := ports.MarshalCapturedReviewMaterial(captured)
					if err != nil {
						t.Fatal(err)
					}
					if SHA256(raw) != c.Expected.ArchiveSHA256 {
						t.Fatal("transport differs from frozen corpus output digest")
					}
					var got Material
					if err := RetainCapture(&got, raw); err != nil {
						t.Fatal(err)
					}
					if got.Source.CaptureAvailability != "verified" || got.Source.CaptureIdentity != source.CaptureIdentity || !bytes.Equal(got.CaptureManifest, files[base+"capture-manifest.json"]) || !bytes.Equal(got.CapturedArchive, raw) {
						t.Fatal("retained encoder changed frozen manifest bytes, identity or availability")
					}
					raw[0] ^= 1
					if bytes.Equal(got.CapturedArchive, raw) {
						t.Fatal("retained archive aliases caller bytes")
					}
				})
			}
		})
		seen++
	}
	if seen != 2 {
		t.Fatalf("fixed manifest families=%d, want 2", seen)
	}
}

func TestRetainCaptureDistinguishesAbsentIncompleteAndMalformed(t *testing.T) {
	for _, kind := range []string{"absent", "incomplete", "malformed"} {
		t.Run(kind, func(t *testing.T) {
			var raw []byte
			if kind == "incomplete" {
				// The original capture contract admits historical no-change Git
				// material without evidence, while refusing capture identity.
				oid, err := ports.ParseGitObjectID(strings.Repeat("a", 40))
				if err != nil {
					t.Fatal(err)
				}
				target, err := ports.NewCapturedReviewGitTarget("local-repository", oid, oid, oid, nil, nil)
				if err != nil {
					t.Fatal(err)
				}
				snapshot, err := ports.NewWorkspaceSnapshotRequest(nil, "legacy-incomplete")
				if err != nil {
					t.Fatal(err)
				}
				material, err := ports.NewCapturedReviewMaterial(target, snapshot, nil)
				if err != nil {
					t.Fatal(err)
				}
				raw, err = ports.MarshalCapturedReviewMaterial(material)
				if err != nil {
					t.Fatal(err)
				}
				if len(raw) == 0 {
					t.Fatal("incomplete control collapsed into absent input")
				}
			} else if kind == "malformed" {
				raw = []byte("{invalid}")
			}
			var got Material
			err := RetainCapture(&got, raw)
			if (err != nil) != (kind == "malformed") {
				t.Fatalf("availability %s: %v", kind, err)
			}
			if got.Source.CaptureAvailability != "capture_identity_unavailable" || got.Source.CaptureIdentity != "" || len(got.CaptureManifest) != 0 || len(got.CapturedArchive) != 0 {
				t.Fatal("unavailable capture manufactured authority")
			}
		})
	}
}

func TestRetainedCopiedSupportRetainsEveryEvidenceAndSourceKind(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		name := "published"
		if recovery {
			name = "recovery"
		}
		t.Run(name, func(t *testing.T) {
			session, run, material, final := supportFixture(t, recovery)
			artifacts := retainedSupportArtifacts(t, session, run, material)
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

func TestRetainedCopiedSupportRejectsCorruptIncompleteOrExtraArtifacts(t *testing.T) {
	for _, kind := range []string{"missing original", "changed original", "missing second evidence", "changed second evidence", "extra evidence", "extra source finding", "swapped evidence"} {
		t.Run(kind, func(t *testing.T) {
			session, run, material, _ := supportFixture(t, false)
			artifacts := retainedSupportArtifacts(t, session, run, material)
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

func TestRetainedCopiedSupportBindsSourceFindingAndFinalRemapping(t *testing.T) {
	for _, mutation := range []string{"source run", "source finding", "content", "provider", "missing finding", "claim range"} {
		t.Run(mutation, func(t *testing.T) {
			session, run, material, final := supportFixture(t, false)
			artifacts := retainedSupportArtifacts(t, session, run, material)
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

func TestRetainedCommonCaptureIncludesRolesWithoutFindings(t *testing.T) {
	for _, mode := range []string{"equal", "different context", "different support file", "unavailable"} {
		t.Run(mode, func(t *testing.T) {
			session, run, logic, _ := supportFixture(t, false)
			attachCapture(t, &logic, "same context")
			documentation := logic
			documentation.Source.ProviderIdentities = append([]string(nil), logic.Source.ProviderIdentities...)
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
			artifacts := retainedSupportArtifacts(t, session, run, logic, documentation)
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

func TestRetainedCopiedCaptureRejectsLostBlobAndUnlistedSourceMaterial(t *testing.T) {
	for _, extra := range []bool{false, true} {
		name := "missing"
		if extra {
			name = "extra"
		}
		t.Run(name, func(t *testing.T) {
			session, run, material, _ := supportFixture(t, false)
			attachCapture(t, &material, "context")
			artifacts := retainedSupportArtifacts(t, session, run, material)
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

func TestRetainedCopiedSupportRejectsRecoveryPublicationAndUnavailableBytes(t *testing.T) {
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
			artifacts := retainedSupportArtifacts(t, session, run, material)
			if _, err := Verify(session, run, material.Source.TargetSHA256, artifacts); err == nil {
				t.Fatal("accepted inconsistent source support")
			}
		})
	}
}

func TestRetainedCopiedSupportPreservesExplicitUnavailableEvidence(t *testing.T) {
	session, run, material, final := supportFixture(t, false)
	material.Findings[0].Finding.Evidence[1].Availability = "evidence_unavailable"
	material.Findings[0].Finding.Evidence[1].ContentSHA256 = ""
	material.Findings[0].Excerpts[1] = nil
	artifacts := retainedSupportArtifacts(t, session, run, material)
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
