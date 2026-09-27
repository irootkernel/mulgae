package reviewrun

import (
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

func contractRequestInput(t *testing.T) RequestIdentityInput {
	t.Helper()
	input := RequestIdentityInput{Roles: []domain.Role{domain.RoleLogic}}
	for name, destination := range map[string]*string{"target_selection": &input.TargetSelectionSHA256, "policy": &input.PolicySHA256, "routes": &input.RoutesSHA256, "assets": &input.AssetsSHA256, "budget": &input.BudgetSHA256, "workflow": &input.WorkflowSHA256} {
		digest, err := RequestComponentDigest(name, []byte(`{}`))
		if err != nil {
			t.Fatal(err)
		}
		*destination = digest
	}
	return input
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

func TestRequestIdentitySeparatesRequestOnlyInputsFromCapture(t *testing.T) {
	manifest, err := NewCaptureManifest(captureContractMaterial(t, "support", "policy", "", false))
	if err != nil {
		t.Fatal(err)
	}
	capture, err := manifest.Identity()
	if err != nil {
		t.Fatal(err)
	}
	project := contractProjectBinding(t, "/project/one", 1)
	input := contractRequestInput(t)
	base, err := NewRequestReceipt(project, capture, input)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*RequestIdentityInput){
		"explicit empty objective": func(i *RequestIdentityInput) { i.ObjectivePresent = true },
		"objective":                func(i *RequestIdentityInput) { i.ObjectivePresent = true; i.Objective = []byte("new objective") },
		"explicit roles":           func(i *RequestIdentityInput) { i.RolesExplicit = true },
		"roles":                    func(i *RequestIdentityInput) { i.Roles = []domain.Role{domain.RoleLogic, domain.RoleSecurity} },
		"model policy":             func(i *RequestIdentityInput) { i.PolicySHA256 = identitySHA256([]byte("changed")) },
		"profile route":            func(i *RequestIdentityInput) { i.RoutesSHA256 = identitySHA256([]byte("changed")) },
		"assets":                   func(i *RequestIdentityInput) { i.AssetsSHA256 = identitySHA256([]byte("changed")) },
		"budget":                   func(i *RequestIdentityInput) { i.BudgetSHA256 = identitySHA256([]byte("changed")) },
		"workflow":                 func(i *RequestIdentityInput) { i.WorkflowSHA256 = identitySHA256([]byte("changed")) },
		"requested selector":       func(i *RequestIdentityInput) { i.TargetSelectionSHA256 = identitySHA256([]byte("changed")) },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := input
			mutate(&candidate)
			got, err := NewRequestReceipt(project, capture, candidate)
			if err != nil {
				t.Fatal(err)
			}
			if got.RequestDigest == base.RequestDigest || got.CaptureIdentity != base.CaptureIdentity {
				t.Fatal("request and capture identities were conflated")
			}
		})
	}
	base.RequestDigest = identitySHA256(nil)
	if _, err := base.Identity(); err == nil {
		t.Fatal("tampered request digest accepted")
	}
	input.Roles = []domain.Role{domain.RoleLogic, domain.RoleLogic}
	if _, err := NewRequestReceipt(project, capture, input); err == nil {
		t.Fatal("duplicate roles accepted")
	}
}

func TestExecutionGuardRejectsIncompleteUnsupportedAndMismatchedInput(t *testing.T) {
	project := contractProjectBinding(t, "/project/one", 1)
	request, err := domain.ParseRequestIdentity(identitySHA256([]byte("request")))
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		project, request string
		want             error
	}{{project.String(), "", ErrGuardIncomplete}, {"", request.String(), ErrGuardIncomplete}, {"bad", request.String(), ErrGuardInvalid}} {
		if _, err := NewExecutionGuard(test.project, test.request); err != test.want {
			t.Fatalf("guard error = %v, want %v", err, test.want)
		}
	}
	guard, err := NewExecutionGuard(project.String(), request.String())
	if err != nil {
		t.Fatal(err)
	}
	if !guard.Guarded() || guard.CheckProject(project, true) != nil || guard.CheckRequest(request) != nil {
		t.Fatal("matching guard rejected")
	}
	if guard.CheckProject(project, false) != ErrContractUnsupported {
		t.Fatal("unsupported guard accepted")
	}
	if guard.CheckProject(contractProjectBinding(t, "/project/two", 1), true) != ErrProjectBindingMismatch {
		t.Fatal("foreign root accepted")
	}
	if guard.CheckRequest(domain.RequestIdentity{}) != ErrRequestDigestMismatch {
		t.Fatal("missing request accepted")
	}
	legacy, err := NewExecutionGuard("", "")
	if err != nil || legacy.Guarded() || legacy.CheckProject(domain.ProjectBinding{}, false) != nil || legacy.CheckRequest(domain.RequestIdentity{}) != nil {
		t.Fatal("legacy behavior changed")
	}
}
