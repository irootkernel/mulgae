//go:build darwin && arm64

package providercli

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	gittargetadapter "github.com/irootkernel/mulgae/internal/adapters/gittarget"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

// countingLiveSource counts body reads and path admissions against the
// production reader. Scripted driver conversations are single-goroutine.
type countingLiveSource struct {
	ports.LiveSourceReader
	reads, admits int
}

func (source *countingLiveSource) Read(ctx context.Context, side domain.LiveSourceSide, path ports.SafeRelativePath) (ports.LiveSourceFile, error) {
	source.reads++
	return source.LiveSourceReader.Read(ctx, side, path)
}

func (source *countingLiveSource) AdmitPath(ctx context.Context, side domain.LiveSourceSide, path ports.SafeRelativePath) error {
	source.admits++
	return source.LiveSourceReader.AdmitPath(ctx, side, path)
}

func countingLiveFixture(t *testing.T, scope domain.LiveSourceScope) (*countingLiveSource, ports.LiveReviewExecution, string) {
	t.Helper()
	ctx := context.Background()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	project := filepath.Join(base, "project")
	operator := filepath.Join(base, "operator")
	credentials := filepath.Join(base, "credentials")
	for _, path := range []string{project, operator, credentials} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	target := filepath.Join(project, "target.txt")
	if err := os.WriteFile(target, []byte("committed\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(credentials, "auth.txt"), []byte("SECRET"), 0600); err != nil {
		t.Fatal(err)
	}
	git := func(args ...string) {
		t.Helper()
		command := exec.Command("/usr/bin/git", append([]string{"-C", project}, args...)...)
		command.Env = []string{"PATH=/usr/bin:/bin", "HOME=/var/empty", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1"}
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("fixture git %v: %v (%s)", args, err, output)
		}
	}
	git("init", "--quiet")
	git("add", "target.txt")
	git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "Baseline")
	operatorRoot, _ := ports.NewAnchoredRoot(operator)
	home, err := OpenReviewerHome(operatorRoot, []byte("shared guide\n"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = home.Close() })
	credentialRoot, _ := ports.NewAnchoredRoot(credentials)
	adapter, err := gittargetadapter.NewLiveSourceAdapter(gittargetadapter.NewExecRunner(), []ports.AnchoredRoot{credentialRoot})
	if err != nil {
		t.Fatal(err)
	}
	projectRoot, _ := ports.NewAnchoredRoot(project)
	selector, _ := ports.NewLiveSourceSelector(scope, "")
	source, err := adapter.OpenLiveSource(ctx, projectRoot, selector)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = source.Close() })
	counted := &countingLiveSource{LiveSourceReader: source}
	execution, err := ports.NewLiveReviewExecution(ctx, counted, home, []ports.AnchoredRoot{credentialRoot})
	if err != nil {
		t.Fatal(err)
	}
	return counted, execution, project
}
