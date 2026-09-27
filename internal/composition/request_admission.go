//go:build darwin && arm64

package composition

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/irootkernel/mulgae/internal/app/review"
	"github.com/irootkernel/mulgae/internal/app/reviewrun"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

type productionRequestAdmission struct {
	policy    productionRunPolicy
	templates review.TemplateSet
	catalog   ports.ContractCatalog
}

func (admission productionRequestAdmission) Admit(ctx context.Context, request reviewrun.Request, captured reviewrun.CapturedRunInput, binding domain.ProjectBinding) (reviewrun.AdmittedRequest, error) {
	material, err := ports.UnmarshalCapturedReviewMaterial(captured.Input().CapturedArchive())
	if err != nil {
		return reviewrun.AdmittedRequest{}, err
	}
	exclusions, present := captured.CaptureExclusions()
	if !present {
		return reviewrun.AdmittedRequest{}, fmt.Errorf("request admission: capture policy unavailable")
	}
	material, err = material.WithExclusions(exclusions)
	if err != nil {
		return reviewrun.AdmittedRequest{}, err
	}
	return admission.plan(ctx, material, request.CaptureRequest, request.Selection.Roles(), request.RolesExplicit, binding)
}

func (admission productionRequestAdmission) plan(ctx context.Context, material ports.CapturedReviewMaterial, request reviewrun.InputCaptureRequest, roles []domain.Role, explicit bool, binding domain.ProjectBinding) (reviewrun.AdmittedRequest, error) {
	if err := revalidateProductionLocality(ctx, admission.policy.source, admission.policy.attestor, admission.policy.localityRequest, admission.policy.locality); err != nil {
		return reviewrun.AdmittedRequest{}, reviewCompositionFailure(domain.FailureSecurityPolicy, "config locality drifted", err)
	}
	plan, budget, err := reviewrun.PreflightConfiguredPlan(admission.policy.planner, admission.policy.providerTimeouts, roles)
	if err != nil {
		return reviewrun.AdmittedRequest{}, err
	}
	policy, err := admission.inputs(ctx, material, plan)
	if err != nil {
		return reviewrun.AdmittedRequest{}, err
	}
	receipt, err := reviewrun.NewPlannedRequestReceipt(binding, material, request, roles, explicit, policy, budget)
	if err != nil {
		return reviewrun.AdmittedRequest{}, err
	}
	return reviewrun.AdmittedRequest{Receipt: receipt, Plan: plan}, nil
}

func (admission productionRequestAdmission) inputs(ctx context.Context, material ports.CapturedReviewMaterial, plan reviewrun.ExecutionPlan) (reviewrun.RequestPolicyInputs, error) {
	result := reviewrun.RequestPolicyInputs{ConfigurationSHA256: admission.policy.configurationSHA256, Routes: []reviewrun.RequestRoute{}, Exclusions: []reviewrun.RequestExclusion{}}
	exclusions, present := material.Exclusions()
	if !present {
		return result, fmt.Errorf("request admission: capture exclusions unavailable")
	}
	for _, row := range exclusions {
		result.Exclusions = append(result.Exclusions, reviewrun.RequestExclusion{Path: row.Path, Reason: row.Reason})
	}
	roles := make([]domain.Role, 0, len(plan.Assignments))
	rawRoles := admission.policy.config.Roles.Ordered()
	for _, assignment := range plan.Assignments {
		role := assignment.Role()
		roles = append(roles, role)
		var route reviewrun.RequestRoute
		for index, candidate := range domain.FixedRoleOrder() {
			if candidate == role {
				raw := rawRoles[index]
				route = reviewrun.RequestRoute{Role: string(role), ProviderInstance: assignment.ProviderInstance(), ProviderFamily: raw.PrimaryProvider, Profile: selectedRequestString(raw.CredentialProfile), PermissionMode: reviewrun.PreflightPermissionMode, TargetChannel: reviewrun.PreflightTargetChannel}
				break
			}
		}
		route.ConfiguredTimeoutNS = int64(admission.policy.providerTimeouts[reviewrun.Family(route.ProviderFamily)])
		switch reviewrun.Family(route.ProviderFamily) {
		case reviewrun.FamilyZCode:
			provider := admission.policy.config.Providers.ZCode
			route.Model, route.Effort = selectedRequestString(provider.Model), selectedRequestString(provider.ReasoningEffort)
			route.LauncherPath = filepath.Join(provider.AppBundle, reviewrun.ZCodeLauncherRelativePath)
		case reviewrun.FamilyGrok:
			provider := admission.policy.config.Providers.Grok
			route.Model, route.Effort = selectedRequestString(provider.Model), selectedRequestString(provider.ReasoningEffort)
			route.LauncherPath = provider.Executable
		case reviewrun.FamilyCodex:
			provider := admission.policy.config.Providers.Codex
			route.Model, route.Effort = selectedRequestString(provider.Model), selectedRequestString(provider.ReasoningEffort)
			route.LauncherPath = provider.Executable
			route.EffectiveProfile = route.Profile.Value
			if route.EffectiveProfile == "" {
				route.EffectiveProfile = provider.DefaultCredentialProfile
			}
			route.ProfilePath, _ = provider.CredentialHome(route.EffectiveProfile)
		default:
			return result, fmt.Errorf("request admission: unsupported configured route")
		}
		route.EffectiveModel, route.EffectiveEffort = route.Model.Value, route.Effort.Value
		result.Routes = append(result.Routes, route)
	}
	var err error
	result.Assets, result.Contracts, err = reviewrun.PlannedRequestAssets(ctx, admission.catalog, admission.templates, roles, plan.Extraction)
	return result, err
}

func selectedRequestString(value string) reviewrun.RequestSelectedString {
	return reviewrun.RequestSelectedString{Explicit: value != "", Value: value}
}
