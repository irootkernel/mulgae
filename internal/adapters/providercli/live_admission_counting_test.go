//go:build darwin && arm64

package providercli

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	gittargetadapter "github.com/irootkernel/mulgae/internal/adapters/gittarget"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
	"golang.org/x/sys/unix"
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

// A scripted Cursor live-review read tool performs one path admission per
// admission event — the permission probe, the completed tool and the
// end-turn finish — and never reads the file body.
func TestCursorLiveToolAdmissionReadsNoBody(t *testing.T) {
	ctx := context.Background()
	counted, execution, project := countingLiveFixture(t, domain.LiveSourceWorkspace)
	authority, err := newCursorLiveReadAuthority(ctx, execution)
	if err != nil {
		t.Fatal(err)
	}
	exact := filepath.Join(project, "target.txt")
	session := cursorMatrixSession(t, authority)
	frames := cursorMatrixAppend(cursorMatrixPrefix(true),
		cursorMatrixUpdate(map[string]any{"sessionUpdate": "tool_call", "toolCallId": "tool-read", "kind": "read", "status": "pending", "rawInput": map[string]any{"path": exact}}),
		cursorMatrixPermission("permission-read", "tool-read", "read", nil, []map[string]string{
			{"optionId": "once-read", "kind": "allow_once"},
			{"optionId": "reject-read", "kind": "reject_once"},
		}),
		cursorMatrixUpdate(map[string]any{"sessionUpdate": "tool_call_update", "toolCallId": "tool-read", "kind": "read", "status": "completed"}),
		cursorMatrixMessage("reviewed target"),
		cursorMatrixEndTurn(),
	)
	exchange, err := cursorMatrixDrive(session, frames...)
	if err != nil {
		t.Fatal(err)
	}
	if outcome, optionID := cursorMatrixReply(t, exchange.sent, "permission-read"); outcome != "selected" || optionID != "reject-read" {
		t.Fatalf("planned read permission = %s %s", outcome, optionID)
	}
	if counted.reads != 0 || counted.admits != 3 {
		t.Fatalf("body reads during admission = %d, admissions = %d; want 0 reads and 3 admissions (permission probe, completion, end turn)", counted.reads, counted.admits)
	}
}

// Unsafe Cursor read targets keep the unplanned-read rejection: the driver
// answers the permission non-authoritatively and fails the turn.
func TestCursorLiveToolAdmissionRejectsUnsafeTargets(t *testing.T) {
	ctx := context.Background()
	counted, execution, project := countingLiveFixture(t, domain.LiveSourceWorkspace)
	authority, err := newCursorLiveReadAuthority(ctx, execution)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, ".gitignore"), []byte("ignored-link\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("target.txt", filepath.Join(project, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("target.txt", filepath.Join(project, "ignored-link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(project, "folder"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(filepath.Join(project, "pipe"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct{ name, target string }{
		{"symlink", filepath.Join(project, "link")},
		{"ignored-symlink", filepath.Join(project, "ignored-link")},
		{"directory", filepath.Join(project, "folder")},
		{"fifo", filepath.Join(project, "pipe")},
	} {
		t.Run(test.name, func(t *testing.T) {
			session := cursorMatrixSession(t, authority)
			frames := cursorMatrixAppend(cursorMatrixPrefix(true),
				cursorMatrixUpdate(map[string]any{"sessionUpdate": "tool_call", "toolCallId": "tool-read", "kind": "read", "status": "pending", "rawInput": map[string]any{"path": test.target}}),
				cursorMatrixPermission("permission-read", "tool-read", "read", nil, []map[string]string{
					{"optionId": "once-read", "kind": "allow_once"},
					{"optionId": "reject-read", "kind": "reject_once"},
				}),
				cursorMatrixMessage("unplanned report"),
				cursorMatrixEndTurn(),
			)
			exchange, err := cursorMatrixDrive(session, frames...)
			if err == nil || strings.Contains(err.Error(), "EOF") || !strings.Contains(err.Error(), "unplanned read") {
				t.Fatalf("unsafe target = %v", err)
			}
			if cursorPermissionCause(t, err) != domain.DiagnosticCausePermissionDenied {
				t.Fatalf("unsafe cause = %v", err)
			}
			if outcome, optionID := cursorMatrixReply(t, exchange.sent, "permission-read"); outcome != "selected" || optionID != "reject-read" {
				t.Fatalf("unsafe target permission = %s %s", outcome, optionID)
			}
			cursorMatrixAssertNoReport(t, session)
		})
	}
	if counted.reads != 0 {
		t.Fatalf("body reads during unsafe-target admission = %d", counted.reads)
	}
}

// The Cursor execute tool is admitted through its exact-command map and
// never consults the source reader.
func TestCursorLiveGitCommandAdmitsWithoutSourceCalls(t *testing.T) {
	ctx := context.Background()
	counted, execution, _ := countingLiveFixture(t, domain.LiveSourceStage)
	authority, err := newCursorLiveReadAuthority(ctx, execution)
	if err != nil {
		t.Fatal(err)
	}
	command := ""
	for _, read := range execution.Reads() {
		if read.GitCommand() != "" {
			command = read.GitCommand()
			break
		}
	}
	if command == "" {
		t.Fatal("stage plan lacked a Git read command")
	}
	session := cursorMatrixSession(t, authority)
	frames := cursorMatrixAppend(cursorMatrixPrefix(true),
		cursorMatrixUpdate(map[string]any{"sessionUpdate": "tool_call", "toolCallId": "tool-execute", "kind": "execute", "status": "pending", "rawInput": map[string]any{"command": command}}),
		cursorMatrixPermission("permission-execute", "tool-execute", "execute", nil, []map[string]string{
			{"optionId": "always-execute", "kind": "allow_always"},
			{"optionId": "once-execute", "kind": "allow_once"},
		}),
		cursorMatrixUpdate(map[string]any{"sessionUpdate": "tool_call_update", "toolCallId": "tool-execute", "kind": "execute", "status": "completed"}),
		cursorMatrixMessage("reviewed command output"),
		cursorMatrixEndTurn(),
	)
	exchange, err := cursorMatrixDrive(session, frames...)
	if err != nil {
		t.Fatal(err)
	}
	if outcome, optionID := cursorMatrixReply(t, exchange.sent, "permission-execute"); outcome != "selected" || optionID != "once-execute" {
		t.Fatalf("planned command permission = %s %s", outcome, optionID)
	}
	if counted.reads != 0 || counted.admits != 0 {
		t.Fatalf("Git-command admission read = %d, admitted = %d; want 0/0", counted.reads, counted.admits)
	}
}
