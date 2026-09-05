package export

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestEvidenceAndCurrentIdentityMarshalDistinctExcerptDigests(t *testing.T) {
	sourceDigest := testHash("e")
	currentDigest := testHash("0")

	body, err := json.Marshal(struct {
		Evidence        Evidence        `json:"evidence"`
		CurrentIdentity CurrentIdentity `json:"current_identity"`
	}{
		Evidence: Evidence{
			SourceExcerptSHA256:  sourceDigest,
			CurrentExcerptSHA256: currentDigest,
		},
		CurrentIdentity: CurrentIdentity{CurrentExcerptSHA256: currentDigest},
	})
	if err != nil {
		t.Fatal(err)
	}

	var decoded struct {
		Evidence struct {
			SourceExcerptSHA256  string `json:"source_excerpt_sha256"`
			CurrentExcerptSHA256 string `json:"current_excerpt_sha256"`
		} `json:"evidence"`
		CurrentIdentity struct {
			CurrentExcerptSHA256 string `json:"current_excerpt_sha256"`
		} `json:"current_identity"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Evidence.SourceExcerptSHA256 != sourceDigest || decoded.Evidence.CurrentExcerptSHA256 != currentDigest || decoded.CurrentIdentity.CurrentExcerptSHA256 != currentDigest {
		t.Fatalf("excerpt digest mapping = %#v", decoded)
	}
}

func TestCompositeFindingsExportWithoutExcerptEvidence(t *testing.T) {
	for _, test := range []struct {
		name      string
		mutate    func(*VerifiedSourceProjection)
		wantError bool
	}{
		{name: "composite findings"},
		{name: "ordinary missing evidence", mutate: func(source *VerifiedSourceProjection) {
			source.Review.SchemaVersion = "mulgae-review-artifact.v1"
			source.Run.SchemaVersion = "mulgae-run-manifest.v1"
		}, wantError: true},
		{name: "mixed schema pair", mutate: func(source *VerifiedSourceProjection) { source.Run.SchemaVersion = "mulgae-run-manifest.v1" }, wantError: true},
		{name: "incomplete composite", mutate: func(source *VerifiedSourceProjection) { source.Review.CoverageStatus = "incomplete" }, wantError: true},
		{name: "different source run", mutate: func(source *VerifiedSourceProjection) {
			source.SourceIdentity.RunID = "r_018f0d1a-0000-7000-8000-000000000009"
		}, wantError: true},
		{name: "different source target", mutate: func(source *VerifiedSourceProjection) { source.SourceIdentity.SourceTargetSHA256 = testHash("d") }, wantError: true},
		{name: "unbound current excerpt", mutate: func(source *VerifiedSourceProjection) { source.CurrentIdentity = validProjection().CurrentIdentity }, wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			source := validProjection()
			source.Review.SchemaVersion = "mulgae-composite-review-artifact.v1"
			source.Run.SchemaVersion = "mulgae-composite-run-manifest.v1"
			source.SchemaVersions = []string{source.Review.SchemaVersion, source.Run.SchemaVersion}
			source.Review.CoverageStatus = "complete"
			source.SourceIdentity = SourceIdentity{SessionID: source.SessionID, RunID: source.RunID, ReviewID: source.ReviewID, SourceTargetSHA256: testHash("f")}
			source.CurrentIdentity = CurrentIdentity{TargetSHA256: testHash("f")}
			source.Evidence = nil
			if test.mutate != nil {
				test.mutate(&source)
			}
			bundle, manifest, err := BuildRedactedBundle(source, validOptions())
			if test.wantError {
				if !errors.Is(err, ErrMalformedProjection) {
					t.Fatalf("invalid projection error = %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("export valid composite findings: %v", err)
			}
			var findings []Finding
			decodeBundleMember(t, bundle, "findings.json", &findings)
			if len(findings) != 1 || findings[0].ID != source.Findings[0].ID {
				t.Fatalf("exported findings = %#v", findings)
			}
			var evidence []Evidence
			decodeBundleMember(t, bundle, "evidence.json", &evidence)
			if len(evidence) != 0 || manifest.SourceIdentity != source.SourceIdentity || manifest.CurrentIdentity != source.CurrentIdentity {
				t.Fatal("composite export fabricated excerpt evidence or changed its identity")
			}
		})
	}
}
