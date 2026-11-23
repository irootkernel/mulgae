package providercli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

func liveGitEnvironment(binding ports.ProjectBindingObservation) ([]ports.EnvironmentVariable, error) {
	values := map[string]string{
		"PATH": "/usr/bin:/bin", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1",
		"GIT_ATTR_NOSYSTEM": "1", "GIT_OPTIONAL_LOCKS": "0", "GIT_NO_LAZY_FETCH": "1", "GIT_NO_REPLACE_OBJECTS": "1",
		"GIT_CONFIG_COUNT": "5", "GIT_CONFIG_KEY_0": "core.fsmonitor", "GIT_CONFIG_VALUE_0": "false",
		"GIT_CONFIG_KEY_1": "core.hooksPath", "GIT_CONFIG_VALUE_1": "/dev/null",
		"GIT_CONFIG_KEY_2": "core.attributesFile", "GIT_CONFIG_VALUE_2": "/dev/null",
		"GIT_CONFIG_KEY_3": "core.excludesFile", "GIT_CONFIG_VALUE_3": "/dev/null",
		"GIT_CONFIG_KEY_4": "protocol.allow", "GIT_CONFIG_VALUE_4": "never",
		"GIT_PAGER": "cat", "PAGER": "cat", "GIT_TERMINAL_PROMPT": "0",
	}
	if binding.GitDirectory.Valid() {
		values["GIT_DIR"] = binding.GitDirectory.String()
		values["GIT_WORK_TREE"] = binding.Root.String()
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	variables := make([]ports.EnvironmentVariable, 0, len(keys))
	for _, key := range keys {
		variable, err := ports.NewEnvironmentVariable(key, values[key])
		if err != nil {
			return nil, err
		}
		variables = append(variables, variable)
	}
	return variables, nil
}

func liveReviewArgv(definition definition) ([]string, error) {
	if definition.transport.channel != ports.ProviderPacketChannelProtocol {
		return nil, fmt.Errorf("live execution requires a native protocol")
	}
	base := append([]string(nil), definition.baseArgv...)
	switch definition.family {
	case FamilyZcode:
		return appendZcodeProtocolServerArgv(base), nil
	default:
		return nil, fmt.Errorf("unsupported live provider family")
	}
}

func (r *Registry) runInLiveSource(ctx context.Context, definition definition, invocation ports.ProviderInvocation, execution ports.LiveReviewExecution, packet ports.ProviderPacket, namespace ports.ProviderNamespaceLease) (observation ports.ProcessObservation, report []byte, err error) {
	if definition.transport.channel == ports.ProviderPacketChannelTerminal {
		return r.runInLiveTerminal(ctx, definition, invocation, execution, packet, namespace)
	}
	fail := func(cause error) error {
		return providerRuntimeFailure(domain.DiagnosticCauseWorkspaceRevalidationFailed, fmt.Errorf("provider registry: live execution boundary: %w", cause))
	}
	if err := execution.Revalidate(ctx); err != nil {
		return observation, nil, fail(err)
	}
	defer func() {
		// Cancellation ends provider work, but must not masquerade as a changed
		// filesystem boundary during the independent terminal integrity check.
		if postErr := execution.Revalidate(context.WithoutCancel(ctx)); postErr != nil {
			report = nil
			err = fail(postErr)
		}
	}()
	if definition.family == FamilyZcode {
		concrete, ok := namespace.(*namespaceLease)
		if !ok {
			return observation, nil, fail(fmt.Errorf("missing ZCode namespace authority"))
		}
		if _, err := concrete.liveRuntimeTempRoot(); err != nil {
			return observation, nil, fail(err)
		}
		defer func() {
			if _, postErr := concrete.liveRuntimeTempRoot(); postErr != nil {
				report, err = nil, fail(postErr)
			}
		}()
	}
	gitEnvironment, err := liveGitEnvironment(execution.Binding())
	if err != nil {
		return observation, nil, fail(err)
	}
	configured := make([]ports.EnvironmentVariable, 0, len(definition.environment)+len(gitEnvironment))
	for _, variable := range definition.environment {
		if variable.Name() != "PATH" && variable.Name() != "PWD" && variable.Name() != "PAGER" && !strings.HasPrefix(variable.Name(), "GIT_") {
			configured = append(configured, variable)
		}
	}
	configured = append(configured, gitEnvironment...)
	environment, err := isolatedProcessEnvironment(definition.family, configured, namespace.Environment())
	if err != nil {
		return observation, nil, fail(err)
	}
	extraction := invocation.Purpose() == ports.ProviderInvocationExtract
	argv, err := liveReviewArgv(definition)
	if err != nil {
		return observation, nil, fail(err)
	}
	binding, err := ports.NewProtocolProviderPacketBinding(packet)
	if err != nil {
		return observation, nil, fail(err)
	}
	request, err := ports.NewProviderProtocolProcessRequest(definition.executable, argv, environment, execution.ReviewerHome().Root().String(), binding, definition.timeout)
	if err != nil {
		return observation, nil, fail(err)
	}
	configuration, err := protocolConfigurationForNamespace(ctx, RuntimeDefinition(definition), namespace)
	if err != nil {
		return observation, nil, fail(err)
	}
	if definition.family == FamilyZcode && !extraction {
		scope := execution.Target().Selector().Scope()
		if !scope.Valid() {
			return observation, nil, fail(fmt.Errorf("invalid live source scope"))
		}
		configuration.liveSourceScope = scope
	}
	purpose := protocolPurposeLiveReview
	if extraction {
		purpose = protocolPurposeLiveExtraction
	}
	if definition.family == FamilyZcode {
		concrete, ok := namespace.(*namespaceLease)
		if !ok {
			return observation, nil, fail(fmt.Errorf("missing native namespace authority"))
		}
		writable, err := ports.NewAnchoredRoot(concrete.root)
		if err != nil {
			return observation, nil, fail(err)
		}
		roots := []ports.AnchoredRoot{execution.Binding().Root, execution.ReviewerHome().Root()}
		for _, root := range []ports.AnchoredRoot{execution.Binding().GitDirectory, execution.Binding().CommonDirectory} {
			if root.Valid() {
				roots = append(roots, root)
			}
		}
		runtimeTemp, runtimeErr := concrete.liveRuntimeTempRoot()
		if runtimeErr != nil {
			return observation, nil, fail(runtimeErr)
		}
		boundary, err := ports.NewLiveReadOnlyBoundaryWithRuntimeTemp(roots, execution.CredentialRoots(), writable, runtimeTemp)
		if err != nil {
			return observation, nil, fail(err)
		}
		cpRoots, cpLiterals, cpErr := liveExecutionControlPlanePaths(execution)
		if cpErr != nil {
			return observation, nil, fail(cpErr)
		}
		if len(cpRoots) > 0 || len(cpLiterals) > 0 {
			boundary, err = ports.NewLiveReadOnlyBoundaryWithControlPlane(boundary, cpRoots, cpLiterals)
			if err != nil {
				return observation, nil, fail(err)
			}
		}
		request, err = ports.NewLiveReadOnlyProcessRequest(request, boundary)
		if err != nil {
			return observation, nil, fail(err)
		}
	}
	if definition.requiresSpawnVerification {
		if r.spawnVerifier == nil {
			return observation, nil, fail(fmt.Errorf("missing spawn verifier"))
		}
		if err := r.spawnVerifier.VerifyProviderSpawn(ctx, RuntimeDefinition(definition)); err != nil {
			return observation, nil, spawnRevalidationFailure("live spawn revalidation", err)
		}
	}
	if err := namespace.ValidateForSpawn(); err != nil {
		return observation, nil, fail(err)
	}
	launch, err := execution.ReviewerHome().DuplicateLaunchDirectory()
	if err != nil {
		return observation, nil, fail(err)
	}
	request, err = ports.NewNeutralBoundProcessRequest(request, execution.ReviewerHome().Root(), launch)
	if err != nil {
		_ = launch.Close()
		return observation, nil, fail(err)
	}
	return r.executeProtocolProviderProcess(ctx, definition, packet, request, purpose, nil, configuration)
}

func (lease *namespaceLease) liveRuntimeTempRoot() (ports.AnchoredRoot, error) {
	if lease == nil || lease.zcodeRuntimeTempInfo == nil || !validCanonicalAbsolute(lease.zcodeRuntimeTemp) {
		return ports.AnchoredRoot{}, fmt.Errorf("missing native runtime directory identity")
	}
	return revalidateLiveRuntimeTempRoot(zcodeRuntimeTempDirectory, lease.zcodeRuntimeTemp, lease.zcodeRuntimeTempInfo)
}

func revalidateLiveRuntimeTempRoot(nativePath, expected string, retained os.FileInfo) (ports.AnchoredRoot, error) {
	canonical, err := filepath.EvalSymlinks(nativePath)
	if err != nil || canonical != expected {
		return ports.AnchoredRoot{}, fmt.Errorf("native runtime directory path drift")
	}
	info, err := os.Lstat(canonical)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 || !os.SameFile(retained, info) {
		return ports.AnchoredRoot{}, fmt.Errorf("native runtime directory identity drift")
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); !ok || int(stat.Uid) != os.Getuid() {
		return ports.AnchoredRoot{}, fmt.Errorf("native runtime directory ownership drift")
	}
	return ports.NewAnchoredRoot(canonical)
}

func liveExecutionControlPlanePaths(execution ports.LiveReviewExecution) ([]ports.AnchoredRoot, []ports.AnchoredRoot, error) {
	roots := execution.ControlPlaneRoots()
	literals := execution.ControlPlaneLiterals()
	if len(roots) > 0 || len(literals) > 0 {
		return roots, literals, nil
	}
	operatorHome := filepath.Dir(filepath.Dir(execution.ReviewerHome().Root().String()))
	homeRoot, err := ports.NewAnchoredRoot(operatorHome)
	if err != nil {
		return nil, nil, fmt.Errorf("control-plane paths: invalid operator home: %w", err)
	}
	return defaultControlPlanePathsForHome(homeRoot)
}

func (r *Registry) runInLiveTerminal(
	ctx context.Context,
	definition definition,
	invocation ports.ProviderInvocation,
	execution ports.LiveReviewExecution,
	packet ports.ProviderPacket,
	namespace ports.ProviderNamespaceLease,
) (observation ports.ProcessObservation, report []byte, err error) {
	fail := func(cause error) error {
		return providerRuntimeFailure(domain.DiagnosticCauseWorkspaceRevalidationFailed, fmt.Errorf("provider registry: live terminal boundary: %w", cause))
	}
	if err := execution.Revalidate(ctx); err != nil {
		return observation, nil, fail(err)
	}
	defer func() {
		if postErr := execution.Revalidate(context.WithoutCancel(ctx)); postErr != nil {
			report = nil
			err = fail(postErr)
		}
	}()
	authority, authorityErr := adapterAuthorityForFamily(definition.family)
	if authorityErr != nil || authority.terminalProfile == nil {
		return observation, nil, providerRuntimeFailure(domain.DiagnosticCauseProviderSpawnFailed, fmt.Errorf("provider registry: terminal profile unavailable"))
	}
	if nilTerminalSessionRunner(r.terminalRunner) {
		return observation, nil, providerRuntimeFailure(domain.DiagnosticCauseProviderSpawnFailed, fmt.Errorf("provider registry: terminal session runner is unavailable"))
	}
	concrete, ok := namespace.(*namespaceLease)
	if !ok {
		return observation, nil, fail(fmt.Errorf("missing native namespace authority"))
	}

	nativeHomePath := concrete.grokRuntimeHome
	if !validCanonicalAbsolute(nativeHomePath) {
		nativeHomePath = filepath.Dir(filepath.Dir(execution.ReviewerHome().Root().String()))
	}
	nativeHome, homeErr := ports.NewAnchoredRoot(nativeHomePath)
	if homeErr != nil {
		return observation, nil, fail(homeErr)
	}

	gitEnvironment, gitErr := liveGitEnvironment(execution.Binding())
	if gitErr != nil {
		return observation, nil, fail(gitErr)
	}
	extraEnv := make([]ports.EnvironmentVariable, 0, len(definition.environment)+len(gitEnvironment))
	for _, variable := range definition.environment {
		if variable.Name() == "PATH" || variable.Name() == "PWD" || variable.Name() == "PAGER" ||
			strings.HasPrefix(variable.Name(), "GIT_") || unsafeNamespaceEnvironmentName(variable.Name()) ||
			variable.Name() == ports.TerminalPaneIDEnvName {
			continue
		}
		extraEnv = append(extraEnv, variable)
	}
	extraEnv = append(extraEnv, gitEnvironment...)

	readOnlyRoots := make([]ports.AnchoredRoot, 0, 2)
	for _, root := range []ports.AnchoredRoot{execution.Binding().GitDirectory, execution.Binding().CommonDirectory} {
		if root.Valid() {
			readOnlyRoots = append(readOnlyRoots, root)
		}
	}
	cpRoots, cpLiterals, cpErr := liveExecutionControlPlanePaths(execution)
	if cpErr != nil {
		return observation, nil, fail(cpErr)
	}

	if definition.requiresSpawnVerification {
		if r.spawnVerifier == nil {
			return observation, nil, fail(fmt.Errorf("missing spawn verifier"))
		}
		if err := r.spawnVerifier.VerifyProviderSpawn(ctx, RuntimeDefinition(definition)); err != nil {
			return observation, nil, spawnRevalidationFailure("live spawn revalidation", err)
		}
	}
	if err := namespace.ValidateForSpawn(); err != nil {
		return observation, nil, fail(err)
	}
	launchDir, launchErr := execution.ReviewerHome().DuplicateLaunchDirectory()
	if launchErr != nil {
		return observation, nil, fail(launchErr)
	}

	purpose := terminalPurposeReview
	if invocation.Purpose() == ports.ProviderInvocationExtract {
		purpose = terminalPurposeExtraction
	}

	r.terminalUsed.Store(true)
	termRes, termErr := executeTerminalInvocation(ctx, r.terminalRunner, authority.terminalProfile, terminalDriverRequest{
		Definition:           RuntimeDefinition(definition),
		Purpose:              purpose,
		LiveScope:            execution.Target().Selector().Scope(),
		HasLiveScope:         true,
		Packet:               packet,
		NamespaceRoot:        concrete.root,
		NamespaceEnvironment: namespace.Environment(),
		ExtraEnvironment:     extraEnv,
		NeutralCWD:           execution.ReviewerHome().Root(),
		LaunchDirectory:      launchDir,
		NativeHome:           nativeHome,
		SourceRoot:           execution.Binding().Root,
		ReadOnlyRoots:        readOnlyRoots,
		CredentialRoots:      execution.CredentialRoots(),
		ControlPlaneRoots:    cpRoots,
		ControlPlaneLiterals: cpLiterals,
		Timeout:              definition.timeout,
		RegistryGeneration:   r.terminalGeneration,
	})
	if termRes.RuntimeIdentity.Valid() {
		if bindErr := concrete.bindGrokTerminalRuntimeIdentity(termRes.RuntimeIdentity); bindErr != nil {
			return termRes.Process, nil, fail(bindErr)
		}
	}
	if termErr != nil {
		return termRes.Process, nil, termErr
	}
	return termRes.Process, termRes.OutputBytes, nil
}
