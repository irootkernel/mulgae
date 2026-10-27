//go:build darwin && arm64

package validation

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/adapters/gittarget"
	"github.com/irootkernel/mulgae/internal/app/evidence"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

func TestRequirementsProviderAdmitsGitImplementationAtLocalInputPath(t *testing.T) {
	for _, scope := range []domain.LiveSourceScope{domain.LiveSourceStage, domain.LiveSourceHead, domain.LiveSourceCommit, domain.LiveSourceWorkspace} {
		t.Run(string(scope), func(t *testing.T) {
			ctx := context.Background()
			directory, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			root, _ := ports.NewAnchoredRoot(directory)
			git := func(args ...string) {
				command := exec.Command("git", append([]string{"-C", directory, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false"}, args...)...)
				if raw, err := command.CombinedOutput(); err != nil {
					t.Fatalf("fixture Git: %v %s", err, raw)
				}
			}
			git("init", "-q")
			path := filepath.Join(directory, "reader.go")
			if err := os.WriteFile(path, []byte("baseline\n"), 0600); err != nil {
				t.Fatal(err)
			}
			git("add", "reader.go")
			git("commit", "-qm", "Baseline")
			if err := os.WriteFile(path, []byte("readIndex(path)\n"), 0600); err != nil {
				t.Fatal(err)
			}
			git("add", "reader.go")
			if scope != domain.LiveSourceStage {
				git("commit", "-qm", "Implementation")
			}
			raw := []byte(`{"schema_version":"mulgae-requirements-input.v1","requirements":[{"id":"A","text":"Local prose differs from selected implementation","acceptance_criteria":["criterion"],"owner_role":"logic"}]}`)
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			operand := ""
			if scope == domain.LiveSourceCommit {
				operand = "HEAD"
			}
			selector, _ := ports.NewLiveSourceSelector(scope, operand)
			opener, _ := gittarget.NewLiveSourceAdapter(gittarget.ExecRunner{}, nil)
			source, err := opener.OpenLiveSource(ctx, root, selector)
			if err != nil {
				t.Fatal(err)
			}
			defer source.Close()
			safe, _ := ports.NewSafeRelativePath("reader.go")
			admittedRaw, err := source.(ports.RequirementsInputReader).ReadRequirementsInput(ctx, safe)
			if err != nil || string(admittedRaw) != string(raw) {
				t.Fatalf("local input admission: %v", err)
			}
			input, err := DecodeRequirementsInput(admittedRaw, []domain.Role{domain.RoleLogic})
			if err != nil {
				t.Fatal(err)
			}
			identity, _ := evidence.NewLiveSourceIdentity(source.Target())
			verifier, _ := evidence.NewLiveVerifier(source)
			row := assessmentRow("A", "met")
			side := "index"
			if scope != domain.LiveSourceStage {
				side = "head"
			}
			if scope == domain.LiveSourceWorkspace {
				side = "worktree"
				row["evidence"].([]any)[0].(map[string]any)["current"].(map[string]any)["quote"] = string(raw)
			}
			row["evidence"].([]any)[0].(map[string]any)["current"].(map[string]any)["side"] = side
			answers, err := DecodeProviderRequirements(ctx, assessmentSection(row), input.Requirements(), domain.RoleLogic, identity, verifier, nil, "reader.go", input.SHA256())
			if scope == domain.LiveSourceWorkspace {
				if err == nil {
					t.Fatal("local input prose established met")
				}
				return
			}
			if err != nil || len(answers) != 1 {
				t.Fatalf("selected %s implementation at invocation-local input path rejected: %v", side, err)
			}
			if !strings.Contains(string(answers[0].Content()), "readIndex(path)") {
				t.Fatal("selected source evidence was replaced by local prose")
			}
		})
	}
}
