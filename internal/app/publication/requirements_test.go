package publication

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/app/validation"
	"github.com/irootkernel/mulgae/internal/artifactwire"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

func requirementsNoChangeCandidate(t *testing.T, large bool) PreparedLiveCandidate {
	t.Helper()
	candidate := livePublicationNoChange(t)
	description := "description"
	if large {
		description = strings.Repeat("r", 9<<20)
	}
	raw, _ := json.Marshal(map[string]any{"schema_version": "mulgae-requirements-input.v1", "requirements": []any{map[string]any{"id": "A", "text": description, "acceptance_criteria": []string{"criterion"}, "owner_role": "logic"}}})
	input, err := validation.DecodeRequirementsInput(raw, []domain.Role{domain.RoleLogic})
	if err != nil {
		t.Fatal(err)
	}
	result, err := validation.NormalizeRequirements(input, nil, nil, candidate.candidate.target.sha256, true)
	if err != nil {
		t.Fatal(err)
	}
	with, err := WithRequirements(candidate, result)
	if err != nil {
		t.Fatal(err)
	}
	if with.ValidatedCandidateSHA256() == candidate.ValidatedCandidateSHA256() {
		t.Fatal("requirements missing from candidate identity")
	}
	return with
}
func TestRequirementsPublicationBindsExactInputAndNoChangeRows(t *testing.T) {
	candidate := requirementsNoChangeCandidate(t, true)
	bundle, err := candidate.Build(context.Background(), &publicationTestValidator{}, publicationTestReviewID(t), publicationTestTime(), 1)
	if err != nil {
		t.Fatal(err)
	}
	var final finalReviewWire
	var manifest runManifestWire
	_ = json.Unmarshal(bundle.Final().Bytes(), &final)
	_ = json.Unmarshal(bundle.Manifest().Bytes(), &manifest)
	if final.SchemaVersion != artifactwire.ReviewArtifactV4 || manifest.SchemaVersion != artifactwire.RunManifestV4 || final.RequirementsSupport == nil || *final.RequirementsSupport != *manifest.RequirementsSupport || len(manifest.Attempts) != 0 || len(manifest.RoleReports) != 0 || len(final.Findings) != 0 {
		t.Fatal("invalid v4 no-change projection")
	}
	if err := validatePublicationBundleSize(bundle, 8<<20); err != nil {
		t.Fatalf("unbounded input entered bounded envelope: %v", err)
	}
	prefix := candidate.SessionID().String() + "/" + candidate.RunID().String() + "/"
	artifacts := map[string]ports.ImmutablePublicationArtifact{}
	for _, artifact := range bundle.Excerpts() {
		artifacts[artifact.Path().String()] = artifact
	}
	if err := validatePublishedRequirements(final, artifacts); err != nil {
		t.Fatal(err)
	}
	input := artifacts[prefix+RequirementsInputPath]
	if len(input.Bytes()) <= 8<<20 || string(input.Bytes()) != string(candidate.candidate.requirements.result.Input().Bytes()) {
		t.Fatal("input altered")
	}
	var metadata requirementsSupportWire
	_ = json.Unmarshal(artifacts[prefix+RequirementsSupportPath].Bytes(), &metadata)
	if metadata.SelectedCount != 1 || metadata.EvaluatedCount != 0 || metadata.Availability != domain.AssessmentNotRun || metadata.Items[0].Reason != domain.AssessmentNoChangeTarget || metadata.InputSHA256 != input.SHA256() {
		t.Fatal("no-change counts/origin")
	}
	delete(artifacts, prefix+metadata.Items[0].ContentPath)
	if err := validatePublishedRequirements(final, artifacts); err == nil {
		t.Fatal("missing bound content accepted")
	}
}
func TestRequirementsPublicationRejectsInputAndBindingTamper(t *testing.T) {
	candidate := requirementsNoChangeCandidate(t, false)
	bundle, err := candidate.Build(context.Background(), &publicationTestValidator{}, publicationTestReviewID(t), publicationTestTime(), 1)
	if err != nil {
		t.Fatal(err)
	}
	var final finalReviewWire
	_ = json.Unmarshal(bundle.Final().Bytes(), &final)
	artifacts := map[string]ports.ImmutablePublicationArtifact{}
	for _, artifact := range bundle.Excerpts() {
		artifacts[artifact.Path().String()] = artifact
	}
	prefix := final.SessionID + "/" + final.RunID + "/"
	path, _ := ports.NewSafeRelativePath(prefix + RequirementsInputPath)
	bad, _ := immutableArtifact(path, []byte("{}"))
	artifacts[path.String()] = bad
	if err := validatePublishedRequirements(final, artifacts); err == nil {
		t.Fatal("changed exact input accepted")
	}
	final.SchemaVersion = artifactwire.ReviewArtifactV3
	if err := validatePublishedRequirements(final, artifacts); err == nil {
		t.Fatal("v3 accepted v4 support")
	}
}

func TestRequirementsPublicationVisualBindingRejectsMissingOrOtherSideImage(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	content := validation.RequirementContent{Evidence: []validation.RequirementContentEvidence{{Current: validation.RequirementCurrentEvidence{Side: validation.CurrentEvidenceSideIndex}, Visual: &artifactwire.VisualEvidence{Path: "design.png", SHA256: digest}}}}
	if err := validateRequirementImages(content, map[string]string{"index\x00design.png": digest}); err != nil {
		t.Fatal(err)
	}
	for _, images := range []map[string]string{nil, {"head\x00design.png": digest}, {"index\x00design.png": "sha256:" + strings.Repeat("b", 64)}} {
		if err := validateRequirementImages(content, images); err == nil {
			t.Fatal("unbound visual accepted")
		}
	}
}
