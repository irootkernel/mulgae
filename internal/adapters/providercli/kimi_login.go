package providercli

import (
	"context"
	"fmt"
	"time"

	"github.com/irootkernel/mulgae/internal/ports"
)

const (
	kimiLoginTimeout   = 10 * time.Minute
	kimiLoginOutputCap = int64(64 << 10)
)

// KimiLoginAuthenticator runs Kimi's native browser/device login against the
// configured native data home. Qualification namespaces remain isolated and
// receive the refreshed credentials only when a new registry is constructed.
type KimiLoginAuthenticator struct {
	runner     ports.ProcessRunner
	verifier   SpawnVerifier
	nativeHome string
	dataHome   string
}

var _ ports.ProviderLoginAuthenticator = (*KimiLoginAuthenticator)(nil)

func NewKimiLoginAuthenticator(runner ports.ProcessRunner, verifier SpawnVerifier, nativeHome, dataHome string) (*KimiLoginAuthenticator, error) {
	if nilRunner(runner) || nilSpawnVerifier(verifier) || !validCanonicalAbsolute(nativeHome) || !validCanonicalAbsolute(dataHome) {
		return nil, fmt.Errorf("kimi login: invalid dependencies")
	}
	return &KimiLoginAuthenticator{runner: runner, verifier: verifier, nativeHome: nativeHome, dataHome: dataHome}, nil
}

func (authenticator *KimiLoginAuthenticator) LoginProvider(ctx context.Context, definition ports.ProviderRuntimeDefinition) error {
	if authenticator == nil || ctx == nil || definition == nil || definition.Family() != FamilyKimi {
		return fmt.Errorf("kimi login: invalid request")
	}
	runtime, ok := definition.(RuntimeDefinition)
	if !ok || runtime.Instance() != definition.Instance() {
		return fmt.Errorf("kimi login: unsupported runtime definition")
	}
	if err := authenticator.verifier.VerifyProviderSpawn(ctx, runtime); err != nil {
		return fmt.Errorf("kimi login: spawn verification: %w", err)
	}
	environment, err := kimiLoginEnvironment(authenticator.nativeHome, authenticator.dataHome)
	if err != nil {
		return err
	}
	request, err := ports.NewProcessRequest(
		runtime.Executable(), []string{runtime.Executable(), "login"}, environment,
		authenticator.nativeHome, nil, kimiLoginTimeout, kimiLoginOutputCap, kimiLoginOutputCap,
	)
	if err != nil {
		return fmt.Errorf("kimi login: process request: %w", err)
	}
	observation, err := authenticator.runner.Run(ctx, request)
	if err != nil {
		return fmt.Errorf("kimi login: process execution: %w", err)
	}
	if !observation.Succeeded() {
		return fmt.Errorf("kimi login: process did not succeed")
	}
	return nil
}

func kimiLoginEnvironment(nativeHome, dataHome string) ([]ports.EnvironmentVariable, error) {
	values := [][2]string{
		{"HOME", nativeHome},
		{"KIMI_CODE_HOME", dataHome},
		{"PATH", "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"},
	}
	environment := make([]ports.EnvironmentVariable, 0, len(values))
	for _, value := range values {
		variable, err := ports.NewEnvironmentVariable(value[0], value[1])
		if err != nil {
			return nil, fmt.Errorf("kimi login: environment: %w", err)
		}
		environment = append(environment, variable)
	}
	return environment, nil
}
