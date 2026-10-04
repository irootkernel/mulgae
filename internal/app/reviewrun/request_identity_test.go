package reviewrun

import (
	"errors"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

func contractProjectBinding(t *testing.T, rootPath string, inode uint64) domain.ProjectBinding {
	t.Helper()
	root, err := ports.NewAnchoredRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	git, err := ports.NewAnchoredRoot(rootPath + "/.git")
	if err != nil {
		t.Fatal(err)
	}
	id, err := NewProjectBinding(root, git, git, ports.ProjectDirectoryIdentity{Device: 1, Inode: inode, BirthSeconds: 100}, ports.ProjectDirectoryIdentity{Device: 1, Inode: 10, BirthSeconds: 100}, ports.ProjectDirectoryIdentity{Device: 1, Inode: 10, BirthSeconds: 100})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestProjectBindingSeparatesRootsAndDescriptorReplacement(t *testing.T) {
	first := contractProjectBinding(t, "/project/one", 1)
	if first != contractProjectBinding(t, "/project/one", 1) {
		t.Fatal("canonical aliases diverged")
	}
	for _, changed := range []domain.ProjectBinding{contractProjectBinding(t, "/project/two", 1), contractProjectBinding(t, "/project/one", 2)} {
		if first == changed {
			t.Fatal("different or replaced root matched")
		}
	}
	if strings.Contains(first.String(), "project") || len(first.String()) != 71 {
		t.Fatal("binding exposes private identity")
	}
	root, err := ports.NewAnchoredRoot("/project/one")
	if err != nil {
		t.Fatal(err)
	}
	a := ports.ProjectDirectoryIdentity{Device: 1, Inode: 1, BirthSeconds: 100}
	b := a
	b.BirthNanoseconds++
	before, err := NewProjectBinding(root, root, root, a, a, a)
	if err != nil {
		t.Fatal(err)
	}
	after, err := NewProjectBinding(root, root, root, b, a, a)
	if err != nil || before == after {
		t.Fatal("inode reuse did not change binding")
	}
	_, err = NewProjectBinding(root, root, root, ports.ProjectDirectoryIdentity{}, a, a)
	if err == nil {
		t.Fatal("missing descriptor facts accepted")
	}
}

func TestLiveProjectBindingKeepsNonGitWorkspaceUnguarded(t *testing.T) {
	root, _ := ports.NewAnchoredRoot("/project")
	observed := ports.ProjectBindingObservation{Root: root, RootIdentity: ports.ProjectDirectoryIdentity{Device: 1, Inode: 2}}
	workspace, _ := ports.NewLiveSourceSelector(domain.LiveSourceWorkspace, "")
	binding, err := AdmitLiveProjectBinding(observed, workspace, domain.ProjectBinding{})
	if err != nil || binding.String() != "" {
		t.Fatalf("non-Git workspace fabricated or required a Git binding: %v", err)
	}
	expected := contractProjectBinding(t, "/project", 2)
	if _, err := AdmitLiveProjectBinding(observed, workspace, expected); !errors.Is(err, ErrContractUnsupported) {
		t.Fatalf("expected binding was silently ignored: %v", err)
	}
	head, _ := ports.NewLiveSourceSelector(domain.LiveSourceHead, "")
	if _, err := AdmitLiveProjectBinding(observed, head, domain.ProjectBinding{}); !errors.Is(err, ErrContractUnsupported) {
		t.Fatalf("Git source was admitted without Git authority: %v", err)
	}
	observed.GitDirectory = root
	if _, err := AdmitLiveProjectBinding(observed, workspace, domain.ProjectBinding{}); err == nil {
		t.Fatal("partial Git authority was admitted as a non-Git workspace")
	}
}
