package reviewrun

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/irootkernel/mulgae/internal/app/review"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

type RequestSelectedString struct {
	Explicit bool   `json:"explicit"`
	Value    string `json:"value"`
}

type RequestRoute struct {
	Role                string                `json:"role"`
	ProviderInstance    string                `json:"provider_instance"`
	ProviderFamily      string                `json:"provider_family"`
	Model               RequestSelectedString `json:"model"`
	Effort              RequestSelectedString `json:"effort"`
	Profile             RequestSelectedString `json:"profile"`
	EffectiveModel      string                `json:"effective_model"`
	EffectiveEffort     string                `json:"effective_effort"`
	EffectiveProfile    string                `json:"effective_profile"`
	LauncherPath        string                `json:"launcher_path"`
	ProfilePath         string                `json:"profile_path"`
	PermissionMode      string                `json:"permission_mode"`
	TargetChannel       string                `json:"target_channel"`
	ConfiguredTimeoutNS int64                 `json:"configured_timeout_ns"`
}

type RequestAsset struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
}
type RequestContract struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}
type RequestExclusion struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

// RequestPolicyInputs contains admitted configuration and selected executable
// policy, not provider-home contents or discovered credentials. Only component
// digests leave the application boundary.
type RequestPolicyInputs struct {
	ConfigurationSHA256 string
	Routes              []RequestRoute
	Assets              []RequestAsset
	Contracts           []RequestContract
	Exclusions          []RequestExclusion
}

// NewPlannedRequestReceipt shares the exact ordinary preflight/admission
// encoding. Request-only inputs never enter the capture manifest.
func NewPlannedRequestReceipt(binding domain.ProjectBinding, material ports.CapturedReviewMaterial, request InputCaptureRequest, roles []domain.Role, rolesExplicit bool, policy RequestPolicyInputs, budget review.RunBudgetReceipt) (RequestReceipt, error) {
	if !request.Valid() || !identityDigestValid(policy.ConfigurationSHA256) || policy.Routes == nil || policy.Assets == nil || policy.Contracts == nil || policy.Exclusions == nil {
		return RequestReceipt{}, fmt.Errorf("request receipt: incomplete admitted policy")
	}
	manifest, err := NewCaptureManifest(material)
	if err != nil {
		return RequestReceipt{}, err
	}
	captureIdentity, err := manifest.Identity()
	if err != nil {
		return RequestReceipt{}, err
	}
	target := material.Target().Identity()
	base, head := RequestSelectedString{}, RequestSelectedString{}
	if request.Target().Kind() == ports.ReviewTargetDiff {
		value := request.Target().Value()
		left, right, found := strings.Cut(value, "...")
		if !found {
			left, right, found = strings.Cut(value, "..")
		}
		base = RequestSelectedString{true, left}
		if found {
			head = RequestSelectedString{true, right}
		}
	}
	routes := append([]RequestRoute{}, policy.Routes...)
	slices.SortFunc(routes, func(a, b RequestRoute) int { return strings.Compare(a.Role, b.Role) })
	if len(routes) != len(roles) {
		return RequestReceipt{}, fmt.Errorf("request receipt: route coverage mismatch")
	}
	for i, route := range routes {
		if !slices.Contains(roles, domain.Role(route.Role)) || route.ProviderInstance == "" || !Family(route.ProviderFamily).Valid() || route.ConfiguredTimeoutNS <= 0 || i > 0 && routes[i-1].Role == route.Role {
			return RequestReceipt{}, fmt.Errorf("request receipt: invalid route")
		}
	}
	assets := append([]RequestAsset{}, policy.Assets...)
	slices.SortFunc(assets, func(a, b RequestAsset) int { return strings.Compare(a.Name, b.Name) })
	for i, asset := range assets {
		if asset.Name == "" || !identityDigestValid(asset.SHA256) || i > 0 && assets[i-1].Name == asset.Name {
			return RequestReceipt{}, fmt.Errorf("request receipt: invalid asset")
		}
	}
	contracts := append([]RequestContract{}, policy.Contracts...)
	slices.SortFunc(contracts, func(a, b RequestContract) int { return strings.Compare(a.Name, b.Name) })
	for i, contract := range contracts {
		if contract.Name == "" || contract.Version == "" || i > 0 && contracts[i-1].Name == contract.Name {
			return RequestReceipt{}, fmt.Errorf("request receipt: invalid contract")
		}
	}
	exclusions := append([]RequestExclusion{}, policy.Exclusions...)
	slices.SortFunc(exclusions, func(a, b RequestExclusion) int {
		if c := strings.Compare(a.Path, b.Path); c != 0 {
			return c
		}
		return strings.Compare(a.Reason, b.Reason)
	})
	for i, excluded := range exclusions {
		if _, err := ports.NewSafeRelativePath(excluded.Path); err != nil || excluded.Reason == "" || i > 0 && exclusions[i-1] == excluded {
			return RequestReceipt{}, fmt.Errorf("request receipt: invalid exclusion")
		}
	}
	paths := make([]map[string]any, 0, len(budget.RolePathDeadlines()))
	for _, path := range budget.RolePathDeadlines() {
		paths = append(paths, map[string]any{"role": string(path.Role()), "provider_instance": path.ProviderInstance(), "invocation_count": path.InvocationCount(), "transition_count": path.TransitionCount(), "invocation_timeouts_ns": int64(path.InvocationTimeouts()), "deadline_ns": int64(path.Deadline())})
	}
	slices.SortFunc(paths, func(a, b map[string]any) int { return strings.Compare(a["role"].(string), b["role"].(string)) })
	ceilings := budget.Ceilings()
	artist := map[string]any{"present": false, "automatic": false, "brief_path": "", "design_spec_globs": []string{}}
	if inputs, present := request.ArtistInputs(); present {
		artist = map[string]any{"present": true, "automatic": inputs.Automatic(), "brief_path": inputs.BriefPath(), "design_spec_globs": append([]string{}, inputs.DesignSpecGlobs()...)}
	}
	components := map[string]any{
		"target_selection": map[string]any{"requested_kind": string(request.Target().Kind()), "captured_kind": string(target.Kind()), "git_mode": string(target.GitMode()), "base": base, "head": head, "resolved": map[string]any{"base_object_id": target.BaseObjectID(), "head_object_id": target.HeadObjectID(), "head_tree_object_id": target.HeadTreeObjectID(), "index_tree_object_id": target.IndexTreeObjectID()}},
		"policy":           map[string]any{"configuration_sha256": policy.ConfigurationSHA256, "snapshot_policy": material.Snapshot().PolicyIdentity(), "exclusions": exclusions},
		"routes":           map[string]any{"roles": routes},
		"assets":           map[string]any{"contracts": contracts, "contents": assets},
		"budget":           map[string]any{"eligible": budget.Eligible(), "reason_code": string(budget.ReasonCode()), "max_active_lanes": budget.MaxActiveLanes(), "total_invocations": budget.TotalInvocations(), "critical_path_deadline_ns": int64(budget.CriticalPathDeadline()), "run_deadline_ns": int64(budget.RunDeadline()), "ceilings": map[string]any{"provider_timeout_ns": int64(ceilings.MaxTimeout()), "role_path_deadline_ns": int64(ceilings.MaxRolePathDeadline()), "run_deadline_ns": int64(ceilings.MaxRunDeadline()), "max_invocations_per_role": ceilings.MaxInvocationsPerRole(), "max_invocations_per_run": ceilings.MaxInvocationsPerRun()}, "role_paths": paths},
		"workflow":         map[string]any{"kind": "review", "sources": []any{}, "prompt_inputs": []any{}, "artist": artist},
	}
	digests := map[string]string{}
	for name, component := range components {
		encoded, err := canonicalRequestComponent(component)
		if err != nil {
			return RequestReceipt{}, err
		}
		digest, err := RequestComponentDigest(name, encoded)
		if err != nil {
			return RequestReceipt{}, err
		}
		digests[name] = digest
	}
	objective, present := request.Objective()
	return NewRequestReceipt(binding, captureIdentity, RequestIdentityInput{ObjectivePresent: present, Objective: objective, RolesExplicit: rolesExplicit, Roles: roles, TargetSelectionSHA256: digests["target_selection"], PolicySHA256: digests["policy"], RoutesSHA256: digests["routes"], AssetsSHA256: digests["assets"], BudgetSHA256: digests["budget"], WorkflowSHA256: digests["workflow"]})
}

func canonicalRequestComponent(value any) ([]byte, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.UseNumber()
	var canonical any
	if err := decoder.Decode(&canonical); err != nil {
		return nil, err
	}
	return json.Marshal(canonical)
}
