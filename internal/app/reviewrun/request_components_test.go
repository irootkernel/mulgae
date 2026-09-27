package reviewrun

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/builtin"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

func TestPlannedRequestReceiptBindsAllAdmittedDimensions(t *testing.T) {
	catalog := builtin.NewCatalog()
	templates, err := LoadDefaultTemplateSet(context.Background(), catalog)
	if err != nil {
		t.Fatal(err)
	}
	roles := []domain.Role{domain.RoleLogic}
	assets, contracts, err := PlannedRequestAssets(context.Background(), catalog, templates, roles, false)
	if err != nil {
		t.Fatal(err)
	}
	planner := DefaultPlannerPolicy()
	assignment, err := NewRoleProviderAssignment(domain.RoleLogic, FamilyZCode)
	if err != nil {
		t.Fatal(err)
	}
	planner.Assignments = []RoleProviderAssignment{assignment}
	_, budget, err := PreflightConfiguredPlan(planner, map[Family]time.Duration{FamilyZCode: 15 * time.Minute, FamilyGrok: 15 * time.Minute, FamilyCodex: 15 * time.Minute}, roles)
	if err != nil {
		t.Fatal(err)
	}
	d := "sha256:" + strings.Repeat("a", 64)
	binding, err := domain.ParseProjectBinding(d)
	if err != nil {
		t.Fatal(err)
	}
	root, _ := ports.NewAnchoredRoot("/private/receipt-project")
	selector, _ := ports.NewReviewTargetSelector(ports.ReviewTargetStage, "stage")
	request, _ := NewInputCaptureRequest(root, selector, nil, false)
	material := captureContractMaterial(t, "support", "policy", "", false)
	policy := RequestPolicyInputs{ConfigurationSHA256: d, Routes: []RequestRoute{{Role: "logic", ProviderInstance: "zcode-logic", ProviderFamily: "zcode", ConfiguredTimeoutNS: int64(15 * time.Minute)}}, Assets: assets, Contracts: contracts, Exclusions: []RequestExclusion{}}
	baseline, err := NewPlannedRequestReceipt(binding, material, request, roles, false, policy, budget)
	if err != nil {
		t.Fatal(err)
	}
	for _, dimension := range []string{"target", "binary", "budget", "support", "context", "configuration", "exclusion", "model", "effort", "profile", "launcher", "asset", "objective", "explicit_roles"} {
		t.Run(dimension, func(t *testing.T) {
			changedMaterial, changedRequest, changedPolicy := material, request, policy
			changedBudget := budget
			changedPolicy.Routes = append([]RequestRoute{}, policy.Routes...)
			changedPolicy.Assets = append([]RequestAsset{}, policy.Assets...)
			explicit := false
			switch dimension {
			case "target", "binary":
				target := material.Target()
				files := material.Snapshot().Files()
				if dimension == "target" {
					oid, _ := ports.ParseGitObjectID(strings.Repeat("1", 40))
					target, err = ports.NewCapturedReviewGitTarget("local-repository", oid, oid, oid, nil, []byte("different patch bytes\n"))
				} else {
					for i, file := range files {
						if file.MediaType() == "image/png" {
							data := append(file.Bytes(), byte(1))
							files[i], err = ports.NewWorkspaceVisualAsset(file.Path(), data, identitySHA256(data), file.MediaType())
						}
					}
				}
				if err != nil {
					t.Fatal(err)
				}
				snapshot, err := ports.NewWorkspaceSnapshotRequest(files, material.Snapshot().PolicyIdentity())
				if err != nil {
					t.Fatal(err)
				}
				evidence, err := ports.NewCapturedTargetEvidence(map[ports.CapturedEvidenceSide][]ports.WorkspaceSnapshotFile{ports.CapturedEvidenceBase: files, ports.CapturedEvidenceHead: files})
				if err != nil {
					t.Fatal(err)
				}
				changedMaterial, err = ports.NewCapturedReviewMaterialWithEvidence(target, snapshot, nil, evidence)
				if err != nil {
					t.Fatal(err)
				}
			case "budget":
				_, changedBudget, err = PreflightConfiguredPlan(planner, map[Family]time.Duration{FamilyZCode: 16 * time.Minute, FamilyGrok: 15 * time.Minute, FamilyCodex: 15 * time.Minute}, roles)
				if err != nil {
					t.Fatal(err)
				}
			case "support":
				changedMaterial = captureContractMaterial(t, "different support", "policy", "", false)
			case "context":
				changedMaterial = captureContractMaterial(t, "support", "policy", "context", true)
			case "configuration":
				changedPolicy.ConfigurationSHA256 = "sha256:" + strings.Repeat("b", 64)
			case "exclusion":
				changedPolicy.Exclusions = []RequestExclusion{{Path: "ignored.txt", Reason: "mulgaeignore"}}
			case "model":
				changedPolicy.Routes[0].Model = RequestSelectedString{true, "model"}
			case "effort":
				changedPolicy.Routes[0].Effort = RequestSelectedString{true, "high"}
			case "profile":
				changedPolicy.Routes[0].EffectiveProfile = "work"
			case "launcher":
				changedPolicy.Routes[0].LauncherPath = "/different/launcher"
			case "asset":
				changedPolicy.Assets[0].SHA256 = "sha256:" + strings.Repeat("b", 64)
			case "objective":
				changedRequest, _ = NewInputCaptureRequest(root, selector, []byte("inspect carefully"), true)
			case "explicit_roles":
				explicit = true
			}
			actual, err := NewPlannedRequestReceipt(binding, changedMaterial, changedRequest, roles, explicit, changedPolicy, changedBudget)
			if err != nil {
				t.Fatal(err)
			}
			if actual.RequestDigest == baseline.RequestDigest {
				t.Fatalf("%s did not change request", dimension)
			}
			if dimension != "target" && dimension != "binary" && dimension != "support" && dimension != "context" && actual.CaptureIdentity != baseline.CaptureIdentity {
				t.Fatal("request-only change altered capture")
			}
			guard, _ := NewExecutionGuard(binding.String(), baseline.RequestDigest)
			identity, _ := actual.Identity()
			if guard.CheckRequest(identity) != ErrRequestDigestMismatch {
				t.Fatal("changed receipt passed guard")
			}
		})
	}
}

func TestRequestComponentCanonicalEncodingPreservesNanoseconds(t *testing.T) {
	raw, err := canonicalRequestComponent(map[string]any{"z": int64(9007199254740993), "a": map[string]any{"z": false, "a": []string{}}})
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != `{"a":{"a":[],"z":false},"z":9007199254740993}` {
		t.Fatalf("canonical encoding: %s", raw)
	}
}
