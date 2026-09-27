package reviewrun

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

type admissionObserver struct{ lease *admissionLease }

func (observer admissionObserver) ObserveProjectBinding(context.Context, ports.AnchoredRoot) (ports.ProjectBindingLease, error) {
	return observer.lease, nil
}

type admissionLease struct {
	observation   ports.ProjectBindingObservation
	closed        bool
	revalidations int
	failAt        int
	failure       error
}

func (lease *admissionLease) Observation() ports.ProjectBindingObservation { return lease.observation }
func (lease *admissionLease) Revalidate(ctx context.Context) error {
	lease.revalidations++
	if lease.revalidations == lease.failAt {
		return lease.failure
	}
	return ctx.Err()
}
func (lease *admissionLease) Close() error { lease.closed = true; return nil }

type receiptAdmission struct {
	receipt      RequestReceipt
	beforeReturn func()
}

func (admission receiptAdmission) Admit(context.Context, Request, CapturedRunInput, domain.ProjectBinding) (AdmittedRequest, error) {
	if admission.beforeReturn != nil {
		admission.beforeReturn()
	}
	return AdmittedRequest{Receipt: admission.receipt}, nil
}

func TestExecutionGuardRejectsBeforeAllocationAndProviders(t *testing.T) {
	for _, phase := range []string{"unsupported", "project", "request", "replacement", "cancelled"} {
		t.Run(phase, func(t *testing.T) {
			calls := []string{}
			workspaceLease := newServiceLease(t, &calls)
			source := &serviceCapture{captured: serviceCapturedChanged(t, workspaceLease)}
			service := serviceForLifecycle(t, &calls, source, &serviceAuthorityFactory{calls: &calls})
			request := serviceRequest(t, source)
			root, _ := ports.NewAnchoredRoot("/private/admitted-project")
			git, _ := ports.NewAnchoredRoot("/private/admitted-project/.git")
			fileIdentity := ports.ProjectDirectoryIdentity{Device: 1, Inode: 2, BirthSeconds: 3}
			lease := &admissionLease{observation: ports.ProjectBindingObservation{Root: root, GitDirectory: git, CommonDirectory: git, RootIdentity: fileIdentity, GitIdentity: fileIdentity, CommonIdentity: fileIdentity}}
			binding, err := observedProjectBinding(lease)
			if err != nil {
				t.Fatal(err)
			}
			manifest, err := NewCaptureManifest(captureContractMaterial(t, "support", "policy", "", false))
			if err != nil {
				t.Fatal(err)
			}
			captureIdentity, err := manifest.Identity()
			if err != nil {
				t.Fatal(err)
			}
			d := "sha256:" + strings.Repeat("a", 64)
			receipt, err := NewRequestReceipt(binding, captureIdentity, RequestIdentityInput{Roles: []domain.Role{domain.RoleLogic}, TargetSelectionSHA256: d, PolicySHA256: d, RoutesSHA256: d, AssetsSHA256: d, BudgetSHA256: d, WorkflowSHA256: d})
			if err != nil {
				t.Fatal(err)
			}
			expectedBinding, expectedDigest := binding.String(), receipt.RequestDigest
			if phase == "project" {
				expectedBinding = d
			}
			if phase == "request" || phase == "replacement" || phase == "cancelled" {
				expectedDigest = d
			}
			request.Guard, err = NewExecutionGuard(expectedBinding, expectedDigest)
			if err != nil {
				t.Fatal(err)
			}
			var want error = ErrContractUnsupported
			if phase != "unsupported" {
				service.dependencies.ProjectBindings = admissionObserver{lease}
				service.dependencies.Admission = receiptAdmission{receipt: receipt}
				want = ErrProjectBindingMismatch
			}
			if phase == "request" {
				want = ErrRequestDigestMismatch
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if phase == "replacement" {
				want = errors.New("fixture directory replaced")
				lease.failAt, lease.failure = 2, want
			}
			if phase == "cancelled" {
				want = context.Canceled
				service.dependencies.Admission = receiptAdmission{receipt: receipt, beforeReturn: cancel}
			}
			_, err = service.Execute(ctx, request)
			if !errors.Is(err, want) {
				t.Fatalf("error=%v, want %v", err, want)
			}
			expected := []string{}
			if phase == "request" || phase == "replacement" || phase == "cancelled" {
				expected = []string{"capture", "abort"}
			}
			assertServiceCalls(t, calls, expected)
			if phase != "unsupported" && !lease.closed {
				t.Fatal("binding descriptor leaked")
			}
		})
	}
}

func TestNoChangeInputAcceptsCanonicalEmptyArchiveBytes(t *testing.T) {
	oid, _ := ports.ParseGitObjectID(strings.Repeat("a", 40))
	target, err := ports.NewCapturedReviewGitTargetWithMode(domain.GitTargetStage, "repository:test", oid, oid, oid, &oid, nil)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, _ := ports.NewWorkspaceSnapshotRequest(nil, "test")
	evidence, _ := ports.NewCapturedTargetEvidence(map[ports.CapturedEvidenceSide][]ports.WorkspaceSnapshotFile{ports.CapturedEvidenceBase: nil, ports.CapturedEvidenceIndex: nil})
	material, err := ports.NewCapturedReviewMaterialWithEvidence(target, snapshot, nil, evidence)
	if err != nil {
		t.Fatal(err)
	}
	archive, err := ports.MarshalCapturedReviewMaterial(material)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewImmutableReviewInputWithCapturedArchive(target, nil, false, nil, false, archive); err != nil {
		t.Fatal(err)
	}
}

type admissionInspectFactory struct {
	inspect func(CapturedRunInput)
	err     error
}

func (factory admissionInspectFactory) NewQualifiedRun(_ context.Context, captured CapturedRunInput, _ RunSelection) (RunAuthority, error) {
	factory.inspect(captured)
	return nil, factory.err
}

func TestAdmissionPassesOriginalCaptureAfterLiveTreeEdit(t *testing.T) {
	livePath := filepath.Join(t.TempDir(), "support.txt")
	if err := os.WriteFile(livePath, []byte("before admission"), 0600); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(livePath)
	if err != nil {
		t.Fatal(err)
	}
	material := captureContractMaterial(t, string(original), "policy", "", false)
	archive, err := ports.MarshalCapturedReviewMaterial(material)
	if err != nil {
		t.Fatal(err)
	}
	input, err := NewImmutableReviewInputWithCapturedArchive(material.Target(), nil, false, nil, false, archive)
	if err != nil {
		t.Fatal(err)
	}
	calls := []string{}
	workspace := newServiceLease(t, &calls)
	captured, err := NewCapturedRunInput(input, workspace, serviceReader{}, &packetDetectorFake{})
	if err != nil {
		t.Fatal(err)
	}
	source := &serviceCapture{captured: captured}
	root, _ := ports.NewAnchoredRoot(filepath.Dir(livePath))
	git, _ := ports.NewAnchoredRoot(filepath.Join(root.String(), ".git"))
	directory := ports.ProjectDirectoryIdentity{Device: 1, Inode: 2, BirthSeconds: 3}
	lease := &admissionLease{observation: ports.ProjectBindingObservation{Root: root, GitDirectory: git, CommonDirectory: git, RootIdentity: directory, GitIdentity: directory, CommonIdentity: directory}}
	binding, err := observedProjectBinding(lease)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := NewCaptureManifest(material)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := manifest.Identity()
	if err != nil {
		t.Fatal(err)
	}
	digest := "sha256:" + strings.Repeat("a", 64)
	receipt, err := NewRequestReceipt(binding, identity, RequestIdentityInput{Roles: []domain.Role{domain.RoleLogic}, TargetSelectionSHA256: digest, PolicySHA256: digest, RoutesSHA256: digest, AssetsSHA256: digest, BudgetSHA256: digest, WorkflowSHA256: digest})
	if err != nil {
		t.Fatal(err)
	}
	stopped := errors.New("fixture stops after execution handoff")
	inspected := false
	factory := admissionInspectFactory{err: stopped, inspect: func(actual CapturedRunInput) {
		inspected = true
		live, err := os.ReadFile(livePath)
		if err != nil || string(live) != "after admission" {
			t.Fatalf("live edit missing: %q %v", live, err)
		}
		retained, err := ports.UnmarshalCapturedReviewMaterial(actual.Input().CapturedArchive())
		if err != nil {
			t.Fatal(err)
		}
		if err := VerifyCaptureManifest(mustAdmissionManifestBytes(t, manifest), retained, identity); err != nil {
			t.Fatal(err)
		}
		for _, file := range retained.Snapshot().Files() {
			if file.Path().String() == "support.txt" && string(file.Bytes()) != string(original) {
				t.Fatal("execution recaptured live bytes")
			}
		}
	}}
	service := serviceForLifecycle(t, &calls, source, factory)
	service.dependencies.ProjectBindings = admissionObserver{lease}
	service.dependencies.Admission = receiptAdmission{receipt: receipt, beforeReturn: func() {
		if err := os.WriteFile(livePath, []byte("after admission"), 0600); err != nil {
			t.Fatal(err)
		}
	}}
	request := serviceRequest(t, source)
	request.Guard, err = NewExecutionGuard(binding.String(), receipt.RequestDigest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Execute(context.Background(), request); !errors.Is(err, stopped) {
		t.Fatalf("execution: %v", err)
	}
	if !inspected || !lease.closed {
		t.Fatal("execution handoff or descriptor cleanup missing")
	}
	captures := 0
	for _, call := range calls {
		if call == "capture" {
			captures++
		}
	}
	if captures != 1 {
		t.Fatalf("captures=%d", captures)
	}
}

func mustAdmissionManifestBytes(t *testing.T, manifest CaptureManifest) []byte {
	t.Helper()
	raw, err := manifest.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
