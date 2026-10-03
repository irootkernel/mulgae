package validation

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/app/evidence"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

func liveValidationScope(t *testing.T) ReviewValidationScope {
	t.Helper()
	selector, err := ports.NewLiveSourceSelector(domain.LiveSourceHead, "")
	if err != nil {
		t.Fatal(err)
	}
	head, _ := ports.ParseGitObjectID(strings.Repeat("b", 40))
	target, err := ports.NewLiveSourceTarget(selector, ports.GitObjectID{}, head, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := evidence.NewLiveSourceIdentity(target)
	if err != nil {
		t.Fatal(err)
	}
	return ReviewValidationScope{LiveSource: identity, Role: domain.RoleSecurity, ProviderInstance: "fake/security"}
}

func TestValidateLiveReviewInjectsSelectionIdentityWithoutCapturedContentClaim(t *testing.T) {
	schema := &recordingSchemaValidator{}
	scope := liveValidationScope(t)
	raw := providerReviewWith(t, func(document map[string]any) {
		current := document["findings"].([]any)[0].(map[string]any)["evidence"].([]any)[0].(map[string]any)["current"].(map[string]any)
		current["source_identity_sha256"] = "sha256:" + strings.Repeat("e", 64)
		current["target_sha256"] = "sha256:" + strings.Repeat("f", 64)
		current["verification"] = "verified"
	})
	validated, plan, err := testReviewValidator(t, schema).Validate(context.Background(), raw, scope)
	if err != nil || plan != nil {
		t.Fatalf("validation: %v", err)
	}
	if len(schema.calls) != 2 || schema.calls[0].id.String() != ProviderReviewWireSchemaID || schema.calls[1].id.String() != LiveProviderReviewSchemaID {
		t.Fatalf("schemas: %+v", schema.calls)
	}
	var document map[string]any
	if err := json.Unmarshal(schema.calls[1].raw, &document); err != nil {
		t.Fatal(err)
	}
	current := document["findings"].([]any)[0].(map[string]any)["evidence"].([]any)[0].(map[string]any)["current"].(map[string]any)
	if current["source_identity_sha256"] != scope.LiveSource.SHA256() || current["verification"] != "claimed" || document["schema_version"] != "mulgae-provider-review-output.v2" {
		t.Fatal("provider controlled trusted live fields")
	}
	if _, exists := current["target_sha256"]; exists {
		t.Fatal("live normalization claimed captured-content identity")
	}
	groups := validated.EvidenceClaims()
	if len(groups) != 1 || !groups[0].MatchesFinding(validated.Findings()[0]) {
		t.Fatal("lost exact finding proof")
	}
	claim := groups[0].Claims()[0]
	if claim.TargetSHA256() != "" || claim.SourceIdentitySHA256() != scope.LiveSource.SHA256() || !claim.LiveSource().Valid() {
		t.Fatal("live claim became a historical content claim")
	}
	if validated.Findings()[0].ProviderInstance() != scope.ProviderInstance || validated.Findings()[0].Role() != scope.Role || validated.Findings()[0].EvidenceState() != domain.EvidenceUnverified {
		t.Fatal("trusted finding ownership changed")
	}
}

func TestValidateLiveReviewRejectsMixedIdentityBeforeSchemaOrRepair(t *testing.T) {
	schema := &recordingSchemaValidator{}
	scope := liveValidationScope(t)
	scope.TargetSHA256 = strings.Repeat("a", 64)
	_, plan, err := testReviewValidator(t, schema).Validate(context.Background(), validProviderReview(), scope)
	if err == nil || plan != nil || len(schema.calls) != 0 {
		t.Fatal("mixed live/captured scope reached provider validation or repair")
	}
}
