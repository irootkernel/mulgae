//go:build darwin && arm64

package composition

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/adapters/gittarget"
	"github.com/irootkernel/mulgae/internal/app/reviewrun"
	"github.com/irootkernel/mulgae/internal/builtin"
	mulgaeentry "github.com/irootkernel/mulgae/internal/entrypoint/mulgae"
	"github.com/irootkernel/mulgae/internal/ports"
)

type admissionNoStdin struct{}

func (admissionNoStdin) TakeCapturedStdin(context.Context, string) ([]byte, error) {
	return nil, errors.New("unexpected stdin capture")
}

func TestProductionLivePreflightAllowsVerifiedUnbornWorkspaceAndStage(t *testing.T) {
	rootPath := canonicalTestTempDir(t)
	command := exec.Command("/usr/bin/git", "-C", rootPath, "init", "--quiet")
	if raw, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git fixture: %v %s", err, raw)
	}
	if err := os.Mkdir(filepath.Join(rootPath, ".mulgae"), 0700); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string]string{"config.yaml": compositionProjectConfig, "local.yaml": compositionLocalConfig} {
		if err := os.WriteFile(filepath.Join(rootPath, ".mulgae", name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	root, _ := ports.NewAnchoredRoot(rootPath)
	adapter, err := gittarget.New(gittarget.NewExecRunner())
	if err != nil {
		t.Fatal(err)
	}
	for _, scope := range []string{"--workspace", "--stage"} {
		t.Run(scope, func(t *testing.T) {
			invocation, err := mulgaeentry.Parse([]string{"review", scope, "--preflight"}, rootPath, "i_019f596a-e201-7a4b-8d76-1cf503a1849e")
			if err != nil {
				t.Fatal(err)
			}
			request, _ := invocation.Review()
			service, err := composeReviewPreflight(context.Background(), builtin.NewCatalog(), root, adapter)
			if err != nil {
				t.Fatalf("unborn preflight composition: %v", err)
			}
			result, err := service.PreflightReview(context.Background(), request, root)
			if err != nil {
				t.Fatalf("unborn preflight: %v", err)
			}
			if result.Status != "no_change" || result.ProjectBinding == "" || result.CandidateCount != 0 {
				t.Fatalf("unborn preflight = %+v", result)
			}
		})
	}
}

func TestProductionLivePreflightPreservesIndependentBindingAndConfigIdentity(t *testing.T) {
	rootPath := canonicalTestTempDir(t)
	git := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", rootPath}, args...)...)
		if raw, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git fixture: %v %s", err, raw)
		}
	}
	git("init", "--quiet")
	if err := os.WriteFile(filepath.Join(rootPath, "source.txt"), []byte("stable\n"), 0600); err != nil {
		t.Fatal(err)
	}
	git("add", "source.txt")
	git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "--quiet", "-m", "Fixture")
	if err := os.Mkdir(filepath.Join(rootPath, ".mulgae"), 0700); err != nil {
		t.Fatal(err)
	}
	projectPath := filepath.Join(rootPath, ".mulgae", "config.yaml")
	if err := os.WriteFile(projectPath, []byte(compositionProjectConfig), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rootPath, ".mulgae", "local.yaml"), []byte(compositionLocalConfig), 0600); err != nil {
		t.Fatal(err)
	}
	root, _ := ports.NewAnchoredRoot(rootPath)
	adapter, err := gittarget.New(gittarget.NewExecRunner())
	if err != nil {
		t.Fatal(err)
	}
	preflight := func(extra ...string) (mulgaeentry.ReviewPreflightResult, error) {
		invocation, err := mulgaeentry.Parse(append([]string{"review", "--stage", "--preflight"}, extra...), rootPath, "i_019f596a-e201-7a4b-8d76-1cf503a1849e")
		if err != nil {
			return mulgaeentry.ReviewPreflightResult{}, err
		}
		request, _ := invocation.Review()
		service, err := composeReviewPreflight(context.Background(), builtin.NewCatalog(), root, adapter)
		if err != nil {
			return mulgaeentry.ReviewPreflightResult{}, err
		}
		return service.PreflightReview(context.Background(), request, root)
	}
	baseline, err := preflight()
	if err != nil {
		t.Fatal(err)
	}
	if err := baseline.Validate(); err != nil {
		t.Fatal(err)
	}
	if baseline.Status != "no_change" || baseline.SourceIdentitySHA256 == "" || baseline.ProjectBinding == "" {
		t.Fatalf("incomplete preflight: %+v", baseline)
	}
	same, err := preflight("--expected-project-binding", baseline.ProjectBinding)
	if err != nil {
		t.Fatal(err)
	}
	if same.SourceIdentitySHA256 != baseline.SourceIdentitySHA256 {
		t.Fatal("stable preflight changed identity")
	}
	explicit, err := preflight("--roles", "logic")
	if err != nil {
		t.Fatal(err)
	}
	if explicit.SourceIdentitySHA256 != baseline.SourceIdentitySHA256 || explicit.ProjectBinding != baseline.ProjectBinding {
		t.Fatal("default/explicit selection not preserved")
	}
	if err := os.WriteFile(projectPath, []byte(compositionProjectConfig+"# admitted formatting change\n"), 0600); err != nil {
		t.Fatal(err)
	}
	changed, err := preflight()
	if err != nil {
		t.Fatal(err)
	}
	if changed.ConfigurationSHA256 == baseline.ConfigurationSHA256 || changed.SourceIdentitySHA256 != baseline.SourceIdentitySHA256 {
		t.Fatal("raw configuration identity lost")
	}
	if _, err := preflight("--expected-project-binding", "sha256:"+strings.Repeat("a", 64)); !errors.Is(err, reviewrun.ErrProjectBindingMismatch) {
		t.Fatalf("binding mismatch: %v", err)
	}
	entries, err := os.ReadDir(filepath.Join(rootPath, ".mulgae"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatal("preflight created runtime state")
	}
}
