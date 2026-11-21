//go:build darwin && arm64

package composition

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/irootkernel/mulgae/internal/adapters/gittarget"
	appconfig "github.com/irootkernel/mulgae/internal/app/config"
	"github.com/irootkernel/mulgae/internal/app/reviewrun"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

const (
	maxLiveSourceSymlinkHops    = 40
	maxLiveSourcePathComponents = 4096
	macOSDataVolumePrefix       = "/System/Volumes/Data"
)

// rejectProjectAncestorOfReviewerHome fails closed when the project root equals
// or contains ~/.mulgae/home (lexically, through existing or dangling symlinks,
// macOS APFS Data-volume firmlinks, or case-insensitive APFS aliases), so
// reviewing a project can never expose or collide with the neutral reviewer home.
func rejectProjectAncestorOfReviewerHome(project ports.AnchoredRoot, nativeHome string) error {
	if !project.Valid() || nativeHome == "" || !filepath.IsAbs(nativeHome) || filepath.Clean(nativeHome) != nativeHome {
		return fmt.Errorf("live source: invalid project root or native user home")
	}
	resolvedProject, err := resolvePathComponentsMissingTolerant(project.String())
	if err != nil {
		return fmt.Errorf("live source: resolve project root: %w", err)
	}
	projectForms := uniqueCleanPaths(project.String(), resolvedProject)

	mulgaeDir := filepath.Join(nativeHome, ".mulgae")
	reviewerHome := filepath.Join(mulgaeDir, "home")

	resolvedHome, err := resolvePathComponentsMissingTolerant(nativeHome)
	if err != nil {
		return fmt.Errorf("live source: resolve native user home: %w", err)
	}
	resolvedMulgae, err := resolvePathComponentsMissingTolerant(mulgaeDir)
	if err != nil {
		return fmt.Errorf("live source: resolve mulgae state root: %w", err)
	}
	resolvedReviewerHome, err := resolvePathComponentsMissingTolerant(reviewerHome)
	if err != nil {
		return fmt.Errorf("live source: resolve reviewer home: %w", err)
	}

	candidates := uniqueCleanPaths(
		reviewerHome,
		resolvedReviewerHome,
		filepath.Join(resolvedMulgae, "home"),
		filepath.Join(resolvedHome, ".mulgae", "home"),
	)

	// Expand macOS APFS Data-volume firmlink aliases so ancestors of
	// /System/Volumes/Data (including /System/Volumes/Data, /System/Volumes,
	// and /System) are rejected when reviewer home resides on a firmlinked path.
	dataAliases := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		existing, existingInfo, ok, walkErr := deepestExistingNoFollowPrefix(candidate)
		if walkErr != nil {
			return fmt.Errorf("live source: inspect reviewer home ancestor: %w", walkErr)
		}
		if !ok || existing == "/" || existing == macOSDataVolumePrefix || strings.HasPrefix(existing, macOSDataVolumePrefix+"/") {
			continue
		}
		dataAlias := filepath.Join(macOSDataVolumePrefix, existing)
		dataAliasInfo, lstatErr := os.Lstat(dataAlias)
		if lstatErr != nil {
			if errors.Is(lstatErr, os.ErrNotExist) || errors.Is(lstatErr, syscall.ENOTDIR) {
				continue
			}
			return fmt.Errorf("live source: inspect data-volume alias: %w", lstatErr)
		}
		if os.SameFile(existingInfo, dataAliasInfo) {
			dataAliases = append(dataAliases, filepath.Join(macOSDataVolumePrefix, candidate))
		}
	}
	candidates = uniqueCleanPaths(append(candidates, dataAliases...)...)

	for _, projectPath := range projectForms {
		for _, candidate := range candidates {
			if pathIsAncestorOrEqual(projectPath, candidate) {
				return fmt.Errorf("live source: project root must not be an ancestor of reviewer home")
			}
		}
		// Compare kernel (dev, ino) via os.SameFile against every existing
		// ancestor of each reviewerHome candidate up to "/", closing macOS
		// firmlinks (/System/Volumes/Data/Users/...), APFS case-insensitivity,
		// and symlinked project roots.
		projectInfo, statErr := os.Stat(projectPath)
		if statErr != nil {
			continue
		}
		for _, candidate := range candidates {
			for ancestor := candidate; ; {
				if ancestorInfo, err := os.Stat(ancestor); err == nil && os.SameFile(projectInfo, ancestorInfo) {
					return fmt.Errorf("live source: project root must not be an ancestor of reviewer home")
				}
				parent := filepath.Dir(ancestor)
				if parent == ancestor {
					break
				}
				ancestor = parent
			}
		}
	}
	return nil
}

// deepestExistingNoFollowPrefix walks path downward from "/" via os.Lstat,
// stopping at the first missing component (ENOENT/ENOTDIR) or at the first
// symlink (returning that symlink path and its Lstat FileInfo). Fails closed on
// any other Lstat error (such as EACCES).
func deepestExistingNoFollowPrefix(path string) (string, os.FileInfo, bool, error) {
	clean := filepath.Clean(path)
	if !filepath.IsAbs(clean) {
		return "", nil, false, fmt.Errorf("path must be absolute")
	}
	parts := splitPathComponents(clean)
	if len(parts) > maxLiveSourcePathComponents {
		return "", nil, false, fmt.Errorf("resolved path exceeds component bound")
	}
	current := "/"
	var lastPath string
	var lastInfo os.FileInfo
	for _, seg := range parts {
		next := filepath.Join(current, seg)
		info, err := os.Lstat(next)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ENOTDIR) {
				return lastPath, lastInfo, lastInfo != nil, nil
			}
			return "", nil, false, err
		}
		lastPath = next
		lastInfo = info
		if info.Mode()&os.ModeSymlink != 0 {
			return lastPath, lastInfo, true, nil
		}
		current = next
	}
	return lastPath, lastInfo, lastInfo != nil, nil
}

func resolvePathComponentsMissingTolerant(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("path must be absolute")
	}
	current := "/"
	missingDepth := 0
	hops := 0
	queue := splitPathComponents(path)
	if len(queue) > maxLiveSourcePathComponents {
		return "", fmt.Errorf("resolved path exceeds component bound")
	}

	for len(queue) > 0 {
		seg := queue[0]
		queue = queue[1:]
		if seg == "" || seg == "." {
			continue
		}
		if seg == ".." {
			if current != "/" {
				current = filepath.Dir(current)
				if missingDepth > 0 {
					missingDepth--
				}
			}
			continue
		}
		next := filepath.Join(current, seg)
		if missingDepth > 0 {
			current = next
			missingDepth++
			continue
		}
		info, err := os.Lstat(next)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ENOTDIR) {
				current = next
				missingDepth = 1
				continue
			}
			return "", err
		}
		if info.Mode()&os.ModeSymlink == 0 {
			current = next
			continue
		}
		hops++
		if hops > maxLiveSourceSymlinkHops {
			return "", fmt.Errorf("too many symlink hops")
		}
		target, err := os.Readlink(next)
		if err != nil {
			return "", err
		}
		if target == "" {
			return "", fmt.Errorf("empty symlink target")
		}
		if strings.HasPrefix(target, "/") {
			current = "/"
			missingDepth = 0
		}
		targetParts := splitPathComponents(target)
		if len(targetParts)+len(queue) > maxLiveSourcePathComponents {
			return "", fmt.Errorf("resolved path exceeds component bound")
		}
		newQueue := make([]string, 0, len(targetParts)+len(queue))
		newQueue = append(newQueue, targetParts...)
		newQueue = append(newQueue, queue...)
		queue = newQueue
	}
	return current, nil
}

func splitPathComponents(path string) []string {
	raw := strings.Split(path, "/")
	out := make([]string, 0, len(raw))
	for _, part := range raw {
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func uniqueCleanPaths(paths ...string) []string {
	seen := make(map[string]struct{}, len(paths))
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		if p == "" {
			continue
		}
		clean := filepath.Clean(p)
		if _, ok := seen[clean]; ok {
			continue
		}
		seen[clean] = struct{}{}
		out = append(out, clean)
	}
	return out
}

func pathIsAncestorOrEqual(ancestor, descendant string) bool {
	ancestor = filepath.Clean(ancestor)
	descendant = filepath.Clean(descendant)
	if ancestor == descendant {
		return true
	}
	if ancestor == string(filepath.Separator) {
		return strings.HasPrefix(descendant, string(filepath.Separator))
	}
	return strings.HasPrefix(descendant, ancestor+string(filepath.Separator))
}

// Credential boundaries include every machine-owned profile, including profiles
// that are not selected for this review. Missing default directories still have
// deny authority; existing aliases also exclude their resolved source roots.
func liveSourceBoundaries(config appconfig.Config, project ports.AnchoredRoot, runtimeRoots ...ports.AnchoredRoot) (credentials, protected []ports.AnchoredRoot, err error) {
	if err := rejectProjectAncestorOfReviewerHome(project, config.NativeUser.Home); err != nil {
		return nil, nil, err
	}
	paths := []string{
		filepath.Join(config.NativeUser.Home, ".codex"),
		filepath.Join(config.NativeUser.Home, ".grok"),
		filepath.Join(config.NativeUser.Home, ".zcode"),
		filepath.Join(config.NativeUser.Home, ".gemini"),
		filepath.Join(config.NativeUser.Home, ".cursor"),
		filepath.Join(config.NativeUser.Home, ".config", "cursor"),
	}
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

// productionLiveControlPlanePaths computes the shared herdr-core control-plane
// roots and literal socket denials applied to every live provider boundary
// (ZCode, Codex, Cursor, AGY, and Grok).
func productionLiveControlPlanePaths(nativeHome string) ([]ports.AnchoredRoot, []ports.AnchoredRoot, error) {
	homeRoot, err := ports.NewAnchoredRoot(nativeHome)
	if err != nil {
		return nil, nil, fmt.Errorf("live control-plane boundaries: invalid native home: %w", err)
	}
	uid := uint32(os.Geteuid())
	roots, err := ports.DefaultControlPlaneRoots(homeRoot, uid)
	if err != nil {
		return nil, nil, fmt.Errorf("live control-plane boundaries: %w", err)
	}
	var resolvedExtras []ports.AnchoredRoot
	for _, root := range roots {
		resolved, resolveErr := resolvePathComponentsMissingTolerant(root.String())
		if resolveErr != nil {
			return nil, nil, fmt.Errorf("live control-plane boundaries: default root (%q): %w", root.String(), resolveErr)
		}
		if resolved != root.String() {
			resolvedRoot, rootErr := ports.NewAnchoredRoot(resolved)
			if rootErr != nil {
				return nil, nil, fmt.Errorf("live control-plane boundaries: resolved default root (%q -> %q): %w", root.String(), resolved, rootErr)
			}
			resolvedExtras = append(resolvedExtras, resolvedRoot)
		}
	}
	if len(resolvedExtras) > 0 {
		roots, err = ports.DefaultControlPlaneRoots(homeRoot, uid, resolvedExtras...)
		if err != nil {
			return nil, nil, fmt.Errorf("live control-plane boundaries: validate resolved default roots: %w", err)
		}
	}
	var literals []ports.AnchoredRoot
	for _, envName := range []string{"HC_SOCKET", "HC_TERMINAL_SOCKET"} {
		raw := os.Getenv(envName)
		if raw == "" {
			continue
		}
		if strings.TrimSpace(raw) != raw || !filepath.IsAbs(raw) || filepath.Clean(raw) != raw {
			return nil, nil, fmt.Errorf("live control-plane boundaries: %s (%q) must be a clean absolute path without surrounding whitespace", envName, raw)
		}
		rawRoots, rawLiterals, rawErr := ports.ControlPlanePathsForSocket(raw, homeRoot)
		if rawErr != nil {
			return nil, nil, fmt.Errorf("live control-plane boundaries: %s (%q): %w", envName, raw, rawErr)
		}
		roots = append(roots, rawRoots...)
		literals = append(literals, rawLiterals...)
		resolved, resolveErr := resolvePathComponentsMissingTolerant(raw)
		if resolveErr != nil {
			return nil, nil, fmt.Errorf("live control-plane boundaries: %s (%q): %w", envName, raw, resolveErr)
		}
		if resolved != raw {
			resolvedRoots, resolvedLiterals, resolvedErr := ports.ControlPlanePathsForSocket(resolved, homeRoot)
			if resolvedErr != nil {
				return nil, nil, fmt.Errorf("live control-plane boundaries: %s (%q -> %q): %w", envName, raw, resolved, resolvedErr)
			}
			roots = append(roots, resolvedRoots...)
			literals = append(literals, resolvedLiterals...)
		}
	}
	return uniqueAnchoredRoots(roots), uniqueAnchoredRoots(literals), nil
}

func uniqueAnchoredRoots(items []ports.AnchoredRoot) []ports.AnchoredRoot {
	if len(items) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(items))
	out := make([]ports.AnchoredRoot, 0, len(items))
	for _, item := range items {
		if !item.Valid() {
			continue
		}
		if _, exists := seen[item.String()]; exists {
			continue
		}
		seen[item.String()] = struct{}{}
		out = append(out, item)
	}
	return out
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
