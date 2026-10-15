//go:build darwin && arm64

package providercli

import (
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/ports"
)

func TestCursorNoGitLaunchSetsNeutralWorkTree(t *testing.T) {
	neutral, err := ports.NewAnchoredRoot("/neutral/reviewer")
	if err != nil {
		t.Fatal(err)
	}
	base, err := liveGitEnvironment(ports.ProjectBindingObservation{})
	if err != nil {
		t.Fatal(err)
	}
	environment, err := cursorNeutralWorkTree(base, neutral)
	if err != nil {
		t.Fatal(err)
	}
	assertCursorNeutralWorkTree(t, environment, neutral.String())
	qualified, err := withLiveGitEnvironment(nil)
	if err != nil {
		t.Fatal(err)
	}
	qualified, err = cursorNeutralWorkTree(qualified, neutral)
	if err != nil {
		t.Fatal(err)
	}
	assertCursorNeutralWorkTree(t, qualified, neutral.String())
}

func assertCursorNeutralWorkTree(t *testing.T, environment []ports.EnvironmentVariable, neutral string) {
	t.Helper()
	values := map[string]string{}
	for _, variable := range environment {
		values[variable.Name()] = variable.Value()
	}
	if values["GIT_WORK_TREE"] != neutral {
		t.Fatalf("GIT_WORK_TREE = %q", values["GIT_WORK_TREE"])
	}
	if _, ok := values["GIT_DIR"]; ok {
		t.Fatal("non-git Cursor launch set GIT_DIR")
	}
}

func TestCursorGitCommandStaysExactUnderNeutralWorkTree(t *testing.T) {
	stage := cursorMatrixStage(t)
	raw := stage.command
	if !strings.HasPrefix(raw, "git --no-pager show ':") || strings.Contains(raw, "--git-dir=") || strings.Contains(raw, "--work-tree=") || strings.Contains(raw, "echo") || strings.Contains(raw, ">") {
		t.Fatalf("plan command = %s", raw)
	}
	authority, err := newCursorLiveReadAuthority(t.Context(), stage.execution)
	if err != nil {
		t.Fatal(err)
	}
	if err := authority.allowGit(raw); err != nil {
		t.Fatal(err)
	}
	for _, rejected := range []string{
		raw + " 2>/dev/null",
		raw + " && echo '---SEPARATOR---'",
		raw + "; echo EXIT",
	} {
		if err := authority.allowGit(rejected); err == nil {
			t.Fatalf("admitted %s", rejected)
		}
	}
	session, err := newCursorACPProtocolSession("/neutral", []byte("Run "+raw+"\n"), protocolPurposeLiveReview, authority)
	if err != nil {
		t.Fatal(err)
	}
	if session.prompt != "Run "+raw+"\n" {
		t.Fatalf("prompt copy = %s", session.prompt)
	}
	request := cursorLiveLaunchRequest(t, stage.execution, ports.ProviderInvocationInitial)
	values := credentialSourceEnvironment(request.Environment())
	if values["GIT_DIR"] != stage.execution.Binding().GitDirectory.String() || values["GIT_WORK_TREE"] != stage.execution.ReviewerHome().Root().String() || values["GIT_WORK_TREE"] == stage.execution.Binding().Root.String() {
		t.Fatalf("cursor git binding = %#v", values)
	}
	if values["TMPPREFIX"] != values["CURSOR_DATA_DIR"]+"/zsh" || strings.HasPrefix(values["TMPPREFIX"], "/var/folders/") || values["TMPPREFIX"] == "/tmp/zsh" {
		t.Fatalf("TMPPREFIX = %s", values["TMPPREFIX"])
	}
}
