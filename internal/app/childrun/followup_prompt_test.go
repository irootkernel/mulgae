package childrun

import (
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/domain"
)

func TestProductionFollowupTemplateDefinesProviderOwnedEvidenceShape(t *testing.T) {
	for _, required := range []string{
		`"evidence":[{"current":`,
		"Every evidence item must contain only current.",
		"Mulgae injects source identity, target_sha256, and verification",
		"including the final selected line",
		"never reuse line numbers or quotes",
		"instead of fabricating evidence",
		`Do not say "issue remains"`,
	} {
		if !strings.Contains(productionFollowupTemplate+productionFollowupResolvedRationaleRule, required) {
			t.Fatalf("production followup template does not contain %q", required)
		}
	}
}

func TestProductionFollowupEvidenceSideMatchesCapturedTarget(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name     string
		identity domain.TargetIdentity
		want     string
	}{
		{name: "dirty", identity: followupPromptGitTarget(t, domain.GitTargetDirty), want: "worktree"},
		{name: "stage", identity: followupPromptGitTarget(t, domain.GitTargetStage), want: "index"},
		{name: "diff", identity: followupPromptGitTarget(t, domain.GitTargetDiff), want: "head"},
		{name: "patch", identity: followupPromptPatchTarget(t), want: "head"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, err := productionFollowupEvidenceSide(test.identity)
			if err != nil || got != test.want {
				t.Fatalf("productionFollowupEvidenceSide() = %q, %v; want %q", got, err, test.want)
			}
			template, err := productionFollowupTrustedTemplate(test.identity)
			if err != nil || !strings.Contains(string(template.Bytes()), `current.side MUST be "`+test.want+`"`) {
				t.Fatalf("trusted template does not bind side %q: %v", test.want, err)
			}
		})
	}
}

func followupPromptGitTarget(t *testing.T, mode domain.GitTargetMode) domain.TargetIdentity {
	t.Helper()
	identity, err := domain.NewTargetIdentity(domain.TargetIdentityInput{
		Kind: domain.TargetGit, SHA256: strings.Repeat("a", 64), RepositoryID: "repository:test",
		BaseObjectID: strings.Repeat("b", 40), HeadObjectID: strings.Repeat("c", 40),
		HeadTreeObjectID: strings.Repeat("d", 40), IndexTreeObjectID: strings.Repeat("e", 40), GitMode: mode,
	})
	if err != nil {
		t.Fatal(err)
	}
	return identity
}

func followupPromptPatchTarget(t *testing.T) domain.TargetIdentity {
	t.Helper()
	identity, err := domain.NewTargetIdentity(domain.TargetIdentityInput{Kind: domain.TargetPatch, SHA256: strings.Repeat("a", 64)})
	if err != nil {
		t.Fatal(err)
	}
	return identity
}
