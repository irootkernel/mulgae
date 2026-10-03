package providercli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

func liveGitEnvironment(binding ports.ProjectBindingObservation) ([]ports.EnvironmentVariable, error) {
	values := map[string]string{
		"PATH": "/usr/bin:/bin", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1",
		"GIT_ATTR_NOSYSTEM": "1", "GIT_OPTIONAL_LOCKS": "0", "GIT_NO_LAZY_FETCH": "1", "GIT_NO_REPLACE_OBJECTS": "1",
		"GIT_CONFIG_COUNT": "2", "GIT_CONFIG_KEY_0": "core.fsmonitor", "GIT_CONFIG_VALUE_0": "false",
		"GIT_CONFIG_KEY_1": "core.hooksPath", "GIT_CONFIG_VALUE_1": "/dev/null",
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

func liveReviewArgv(definition definition, execution ports.LiveReviewExecution, gitEnvironment []ports.EnvironmentVariable, extraction bool) ([]string, error) {
	if definition.transport.channel != ports.ProviderPacketChannelProtocol {
		return nil, fmt.Errorf("live execution requires a native protocol")
	}
	base := append([]string(nil), definition.baseArgv...)
	switch definition.family {
	case FamilyZcode:
		return appendZcodeProtocolServerArgv(base), nil
	case FamilyGrok:
		tools := "read_file,Bash"
		if extraction {
			tools = ""
		}
		// This argv is consumed only by runInLiveSource, which must attach the
		// app-owned Seatbelt boundary before launching. There is no fallback.
		return []string{definition.executable, "--no-auto-update", "--sandbox", "off", "--disable-web-search", "--no-subagents", "--permission-mode", "plan", "--tools", tools, "--deny", "MCPTool", "agent", "--no-leader", "stdio"}, nil
	case FamilyCodex:
		argv := appendCodexProtocolServerArgv(base, definition.codexModel, definition.codexReasoningEffort)
		filesystem := []string{`"~/.codex"="deny"`}
		for _, root := range execution.CredentialRoots() {
			filesystem = append(filesystem, strconv.Quote(root.String())+`="deny"`)
		}
		argv = append(argv, "-c", `permissions.mulgae={extends=":read-only",filesystem={`+strings.Join(filesystem, ",")+`}}`)
		settings := make([]string, 0, len(gitEnvironment))
		for _, variable := range gitEnvironment {
			settings = append(settings, variable.Name()+"="+strconv.Quote(variable.Value()))
		}
		return append(argv, "-c", "shell_environment_policy.set={"+strings.Join(settings, ",")+"}"), nil
	default:
		return nil, fmt.Errorf("unsupported live provider family")
	}
}

func (r *Registry) runInLiveSource(ctx context.Context, definition definition, invocation ports.ProviderInvocation, execution ports.LiveReviewExecution, packet ports.ProviderPacket, namespace ports.ProviderNamespaceLease) (observation ports.ProcessObservation, report []byte, err error) {
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
		if variable.Name() != "PATH" && variable.Name() != "PWD" && !strings.HasPrefix(variable.Name(), "GIT_") {
			configured = append(configured, variable)
		}
	}
	configured = append(configured, gitEnvironment...)
	environment, err := isolatedProcessEnvironment(definition.family, configured, namespace.Environment())
	if err != nil {
		return observation, nil, fail(err)
	}
	extraction := invocation.Purpose() == ports.ProviderInvocationExtract
	argv, err := liveReviewArgv(definition, execution, gitEnvironment, extraction)
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
	configuration, err := protocolConfigurationForNamespace(RuntimeDefinition(definition), namespace)
	if err != nil {
		return observation, nil, fail(err)
	}
	purpose := protocolPurposeLiveReview
	if extraction {
		purpose = protocolPurposeLiveExtraction
	}
	if definition.family == FamilyGrok || definition.family == FamilyZcode {
		concrete, ok := namespace.(*namespaceLease)
		if !ok {
			return observation, nil, fail(fmt.Errorf("missing native namespace authority"))
		}
		if definition.family == FamilyGrok && concrete.grokBoundary == nil {
			return observation, nil, fail(fmt.Errorf("missing sterile Grok namespace authority"))
		}
		if definition.family == FamilyGrok && !extraction {
			configuration.grokLiveReads, err = newGrokLiveReadAuthority(ctx, execution)
			if err != nil {
				return observation, nil, fail(err)
			}
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
		boundary, err := ports.NewLiveReadOnlyBoundary(roots, execution.CredentialRoots(), writable)
		if err != nil {
			return observation, nil, fail(err)
		}
		if definition.family == FamilyZcode {
			runtimeTemp, runtimeErr := concrete.liveRuntimeTempRoot()
			if runtimeErr != nil {
				return observation, nil, fail(runtimeErr)
			}
			boundary, err = ports.NewLiveReadOnlyBoundaryWithRuntimeTemp(roots, execution.CredentialRoots(), writable, runtimeTemp)
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
