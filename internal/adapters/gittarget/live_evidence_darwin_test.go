//go:build darwin && arm64

package gittarget

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/irootkernel/mulgae/internal/adapters/jsonschema"
	"github.com/irootkernel/mulgae/internal/app/evidence"
	"github.com/irootkernel/mulgae/internal/app/review"
	"github.com/irootkernel/mulgae/internal/app/validation"
	"github.com/irootkernel/mulgae/internal/builtin"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

func TestIntegrationLiveEvidenceVerifiesIndexDeletionRenameAndRetainsSelectedBytes(t *testing.T) {
	root := reviewCaptureRepository(t)
	writeReviewFile(t, filepath.Join(root, "support.txt"), "unchanged support\n")
	writeReviewFile(t, filepath.Join(root, "deleted.txt"), "deleted before\n")
	writeReviewFile(t, filepath.Join(root, "old.txt"), "renamed before\n")
	reviewGit(t, root, "add", "support.txt", "deleted.txt", "old.txt")
	reviewGit(t, root, "commit", "-m", "evidence fixtures")
	writeReviewFile(t, filepath.Join(root, "tracked.txt"), "index observation\n")
	reviewGit(t, root, "add", "tracked.txt")
	writeReviewFile(t, filepath.Join(root, "tracked.txt"), "divergent worktree\n")
	writeReviewFile(t, filepath.Join(root, "support.txt"), "divergent support\n")
	reviewGit(t, root, "rm", "deleted.txt")
	reviewGit(t, root, "mv", "old.txt", "new.txt")
	image := []byte{137, 80, 78, 71, 13, 10, 26, 10, 0}
	if err := os.WriteFile(filepath.Join(root, "diagram.png"), image, 0600); err != nil {
		t.Fatal(err)
	}
	reviewGit(t, root, "add", "diagram.png")
	if err := os.WriteFile(filepath.Join(root, "diagram.png"), append(image, 1), 0600); err != nil {
		t.Fatal(err)
	}
	source := openTestLiveSource(t, root, domain.LiveSourceStage, "")
	verifier, err := evidence.NewLiveVerifier(source)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := evidence.NewLiveSourceIdentity(source.Target())
	if err != nil {
		t.Fatal(err)
	}
	schema, err := jsonschema.New(context.Background(), builtin.NewCatalog())
	if err != nil {
		t.Fatal(err)
	}
	schemaID, _ := ports.ParseAssetID(validation.ProviderReviewSchemaID)
	validator, err := validation.NewReviewValidator(schema, schemaID)
	if err != nil {
		t.Fatal(err)
	}
	var retained []evidence.CurrentReceipt
	for _, test := range []struct {
		side        evidence.Side
		path, quote string
	}{
		{evidence.SideIndex, "tracked.txt", "index observation\n"},
		{evidence.SideIndex, "support.txt", "unchanged support\n"},
		{evidence.SideBase, "deleted.txt", "deleted before\n"},
		{evidence.SideBase, "old.txt", "renamed before\n"},
		{evidence.SideIndex, "new.txt", "renamed before\n"},
	} {
		raw, err := json.Marshal(map[string]any{
			"schema_version": "mulgae-provider-review-output.v1", "summary": "A concrete observation.", "completeness": "complete", "limitations": []string{},
			"findings": []any{map[string]any{
				"severity": "high", "title": "Observe selected source", "description": "The selected source contains the cited statement.", "recommendation": "Review the cited statement.", "confidence": "high",
				"evidence": []any{map[string]any{"current": map[string]any{"path": test.path, "side": test.side, "line_start": 1, "line_end": 1, "quote": test.quote}}},
			}},
		})
		if err != nil {
			t.Fatal(err)
		}
		validated, plan, err := validator.Validate(context.Background(), raw, validation.ReviewValidationScope{LiveSource: identity, Role: domain.RoleLogic, ProviderInstance: "fake/live"})
		if err != nil || plan != nil {
			t.Fatalf("%s validation: %v", test.path, err)
		}
		groups, err := review.VerifyValidatedEvidence(context.Background(), verifier, validated.EvidenceClaims())
		if err != nil {
			t.Fatalf("%s verification: %v", test.path, err)
		}
		findings, err := review.ReduceVerifiedFindingEvidence(validated.Findings(), groups, review.DefaultEvidencePolicy())
		if err != nil || len(findings) != 1 || findings[0].EvidenceState() != domain.EvidenceVerified {
			t.Fatalf("%s reduction: %v", test.path, err)
		}
		retained = append(retained, groups[0].Receipts()[0])
	}
	wrong, _ := evidence.NewLiveClaim(identity, evidence.SideIndex, "tracked.txt", 1, 1, "divergent worktree\n")
	if receipt, err := verifier.VerifyCurrent(context.Background(), wrong); err != nil || receipt.Status() != evidence.ReceiptInvalid {
		t.Fatal("index verification substituted worktree bytes")
	}
	imagePath, _ := ports.NewSafeRelativePath("diagram.png")
	selectedImage, err := source.Read(context.Background(), domain.LiveSourceIndex, imagePath)
	if err != nil {
		t.Fatal(err)
	}
	binary, err := verifier.VerifyBinary(context.Background(), evidence.SideIndex, imagePath, selectedImage.SHA256())
	if err != nil || !bytes.Equal(binary.Bytes(), image) {
		t.Fatalf("selected index image: %v", err)
	}
	if err := source.Close(); err != nil {
		t.Fatal(err)
	}
	writeReviewFile(t, filepath.Join(root, "tracked.txt"), "later unrelated observation\n")
	if err := os.Remove(filepath.Join(root, "diagram.png")); err != nil {
		t.Fatal(err)
	}
	if string(retained[0].Excerpt()) != "index observation\n" || !bytes.Equal(binary.Bytes(), image) {
		t.Fatal("retained evidence changed with the original source")
	}
}
