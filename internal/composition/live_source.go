//go:build darwin && arm64

package composition

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/irootkernel/mulgae/internal/adapters/gittarget"
	appconfig "github.com/irootkernel/mulgae/internal/app/config"
	"github.com/irootkernel/mulgae/internal/app/reviewrun"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

// Credential boundaries include every machine-owned profile, including profiles
// that are not selected for this review. Missing default directories still have
// deny authority; existing aliases also exclude their resolved source roots.
func liveSourceBoundaries(config appconfig.Config, project ports.AnchoredRoot, runtimeRoots ...ports.AnchoredRoot) (credentials, protected []ports.AnchoredRoot, err error) {
	paths := []string{filepath.Join(config.NativeUser.Home, ".codex"), filepath.Join(config.NativeUser.Home, ".grok"), filepath.Join(config.NativeUser.Home, ".zcode")}
	if config.Providers.Codex != nil {
		for _, profile := range config.Providers.Codex.CredentialHomes {
			paths = append(paths, profile.Home)
		}
	}
	seenCredentials, seenProtected := map[string]bool{}, map[string]bool{}
	addExisting := func(path string, credential bool) error {
		canonical, resolveErr := filepath.EvalSymlinks(path)
		if errors.Is(resolveErr, os.ErrNotExist) {
			return nil
		}
		if resolveErr != nil {
			return resolveErr
		}
		root, rootErr := ports.NewAnchoredRoot(canonical)
		if rootErr != nil {
			return rootErr
		}
		if !seenProtected[canonical] {
			protected = append(protected, root)
			seenProtected[canonical] = true
		}
		if credential && !seenCredentials[canonical] {
			credentials = append(credentials, root)
			seenCredentials[canonical] = true
		}
		return nil
	}
	for _, path := range paths {
		root, rootErr := ports.NewAnchoredRoot(path)
		if rootErr != nil {
			return nil, nil, rootErr
		}
		if !seenCredentials[path] {
			credentials = append(credentials, root)
			seenCredentials[path] = true
		}
		if err := addExisting(path, true); err != nil {
			return nil, nil, err
		}
	}
	for _, path := range []string{filepath.Join(config.NativeUser.Home, ".mulgae"), filepath.Join(project.String(), ".mulgae"), filepath.Join(project.String(), ".gaori"), filepath.Join(project.String(), ".podway"), filepath.Join(project.String(), ".ouroboros")} {
		if err := addExisting(path, false); err != nil {
			return nil, nil, err
		}
	}
	for _, root := range runtimeRoots {
		if !root.Valid() {
			return nil, nil, fmt.Errorf("live source: invalid runtime root")
		}
		if err := addExisting(root.String(), false); err != nil {
			return nil, nil, err
		}
	}
	return credentials, protected, nil
}

func productionLiveSources(config appconfig.Config, project ports.AnchoredRoot, runtimeRoots ...ports.AnchoredRoot) (ports.LiveSourceOpener, []ports.AnchoredRoot, error) {
	credentials, protected, err := liveSourceBoundaries(config, project, runtimeRoots...)
	if err != nil {
		return nil, nil, reviewCompositionFailure(domain.FailureSecurityPolicy, "live source boundaries unavailable", err)
	}
	opener, err := gittarget.NewLiveSourceAdapter(gittarget.NewExecRunner(), protected)
	if err != nil {
		return nil, nil, reviewCompositionFailure(domain.FailureSecurityPolicy, "live source boundaries unavailable", err)
	}
	return opener, credentials, nil
}

type productionLiveRequestAdmission struct{ policy productionRunPolicy }

func (admission productionLiveRequestAdmission) AdmitLive(ctx context.Context, request reviewrun.LiveRequest, source ports.LiveSourceReader, binding domain.ProjectBinding) (reviewrun.ExecutionPlan, error) {
	if ctx == nil || source == nil || source.Root() != request.ProjectRoot || source.Target().Selector() != request.Target {
		return reviewrun.ExecutionPlan{}, fmt.Errorf("live request admission: invalid source authority")
	}
	if (binding.String() == "") != admission.policy.bindingUnsupported || admission.policy.bindingUnsupported && (request.Target.Scope() != domain.LiveSourceWorkspace || request.ExpectedProjectBinding.String() != "") {
		return reviewrun.ExecutionPlan{}, reviewCompositionFailure(domain.FailureConfiguration, "contract_unsupported", reviewrun.ErrContractUnsupported)
	}
	var commits []ports.GitObjectID
	for _, object := range []ports.GitObjectID{source.Target().Base(), source.Target().Head()} {
		if object.Valid() {
			commits = append(commits, object)
		}
	}
	locality, err := bindProductionLocality(ctx, admission.policy.source, admission.policy.attestor, admission.policy.localityRequest, admission.policy.locality, admission.policy.config, commits, nil)
	if err != nil {
		return reviewrun.ExecutionPlan{}, reviewCompositionFailure(domain.FailureSecurityPolicy, "live target locality rejected", err)
	}
	if err := revalidateProductionLocality(ctx, locality.source, locality.attestor, locality.request, locality.expected); err != nil {
		return reviewrun.ExecutionPlan{}, reviewCompositionFailure(domain.FailureSecurityPolicy, "live target locality drifted", err)
	}
	plan, _, err := reviewrun.PreflightConfiguredPlan(admission.policy.planner, admission.policy.providerTimeouts, request.Selection.Roles())
	return plan, err
}
