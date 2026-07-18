//go:build liveprovider

package providercli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	processadapter "github.com/irootkernel/kkachi-agent-review/internal/adapters/process"
	runtimeadapter "github.com/irootkernel/kkachi-agent-review/internal/adapters/runtime"
	"github.com/irootkernel/kkachi-agent-review/internal/domain"
	"github.com/irootkernel/kkachi-agent-review/internal/ports"
)

func TestLiveKimiExactTuple(t *testing.T) {
	binaryPath := os.Getenv("KAR_LIVE_KIMI_BIN")
	version := os.Getenv("KAR_LIVE_KIMI_VERSION")
	expectedSHA256 := os.Getenv("KAR_LIVE_KIMI_SHA256")
	if binaryPath == "" || version == "" || expectedSHA256 == "" {
		t.Skip("live Kimi tuple is not configured")
	}

	resolvedBinary, err := filepath.EvalSymlinks(binaryPath)
	if err != nil {
		t.Fatalf("resolve live Kimi executable: %v", err)
	}
	if !filepath.IsAbs(resolvedBinary) || filepath.Clean(resolvedBinary) != resolvedBinary {
		t.Fatal("live Kimi executable did not resolve to a canonical absolute path")
	}
	binaryBytes, err := os.ReadFile(resolvedBinary)
	if err != nil {
		t.Fatalf("read live Kimi executable: %v", err)
	}
	sum := sha256.Sum256(binaryBytes)
	actualSHA256 := hex.EncodeToString(sum[:])
	if actualSHA256 != expectedSHA256 {
		t.Fatal("live Kimi executable digest does not match KAR_LIVE_KIMI_SHA256")
	}

	key, err := ports.ParseConcurrencyKey("kimi-default")
	if err != nil {
		t.Fatal(err)
	}
	baseArgv := []string{resolvedBinary}
	environment := liveKimiEnvironment(t)
	candidate, err := NewRuntimeDefinitionCandidate(
		FamilyKimi,
		"local-default",
		version,
		resolvedBinary,
		actualSHA256,
		key,
		"kimi-default",
		baseArgv,
		environment,
		t.TempDir(),
		30*time.Second,
		1<<20,
		1<<20,
	)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	runner, err := processadapter.NewRunner(runtimeadapter.SystemClock{})
	if err != nil {
		t.Fatal(err)
	}
	registry, err := NewAuthorizedRegistry(ctx, runner, liveKimiAuthorizer{expectedSHA256: expectedSHA256}, candidate)
	if err != nil {
		t.Fatal(err)
	}

	const marker = "kar-live-kimi-exact-tuple-v1"
	prompt := []byte(`Return exactly this JSON object and no markdown or explanation: {"marker":"` + marker + `"}`)
	invocation := liveKimiInvocation(t, prompt)
	observation, err := registry.Observe(ctx, invocation)
	if err != nil {
		t.Fatalf("observe live Kimi: %v", err)
	}
	if !observation.Succeeded() {
		t.Fatalf("live Kimi did not succeed: status=%q termination=%q diagnostic=%q", observation.Status(), observation.Termination(), observation.DiagnosticCode())
	}
	result, ok := observation.Result()
	if !ok {
		t.Fatal("successful live Kimi observation has no result")
	}
	var document struct {
		Marker string `json:"marker"`
	}
	decoder := json.NewDecoder(bytes.NewReader(result.Stdout()))
	if err := decoder.Decode(&document); err != nil {
		t.Fatalf("live Kimi result is not JSON: %v", err)
	}
	var extra json.RawMessage
	if err := decoder.Decode(&extra); err != io.EOF {
		t.Fatal("live Kimi result contains more than one JSON document")
	}
	if document.Marker != marker {
		t.Fatal("live Kimi result marker did not match")
	}
}

type liveKimiAuthorizer struct {
	expectedSHA256 string
}

func (a liveKimiAuthorizer) Authorize(_ context.Context, candidate RuntimeDefinitionCandidate) error {
	resolvedExecutable, err := filepath.EvalSymlinks(candidate.Executable())
	if err != nil {
		return fmt.Errorf("resolve candidate executable: %w", err)
	}
	if resolvedExecutable != candidate.Executable() {
		return fmt.Errorf("candidate executable is not independently resolved")
	}
	executableBytes, err := os.ReadFile(resolvedExecutable)
	if err != nil {
		return fmt.Errorf("read candidate executable: %w", err)
	}
	sum := sha256.Sum256(executableBytes)
	actualSHA256 := hex.EncodeToString(sum[:])
	if actualSHA256 != a.expectedSHA256 || actualSHA256 != candidate.ExecutableSHA256() {
		return fmt.Errorf("candidate executable digest is not authorized")
	}
	return nil
}

func liveKimiEnvironment(t *testing.T) []ports.EnvironmentVariable {
	t.Helper()
	var environment []ports.EnvironmentVariable
	for _, name := range []string{"HOME", "PATH"} {
		value, ok := os.LookupEnv(name)
		if !ok {
			continue
		}
		variable, err := ports.NewEnvironmentVariable(name, value)
		if err != nil {
			t.Fatalf("construct live Kimi %s environment: %v", name, err)
		}
		environment = append(environment, variable)
	}
	return environment
}

func liveKimiInvocation(t *testing.T, prompt []byte) ports.ProviderInvocation {
	t.Helper()
	attempt, err := domain.ParseAttemptID("a_019f596a-cf80-7c67-b265-f37053d51ccf")
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.New()
	_, _ = digest.Write([]byte("KAR-PROVIDER-STDIN/1"))
	_, _ = digest.Write([]byte{0})
	_, _ = digest.Write(prompt)
	invocation, err := ports.NewProviderInvocation(
		domain.RoleSecurity,
		"local-default",
		attempt,
		ports.ProviderInvocationInitial,
		prompt,
		"i_019f596a-cf80-7c67-b265-f37053d51ccd",
		"019f596a-cf80-7c67-b265-f37053d51cce",
		hex.EncodeToString(digest.Sum(nil)),
	)
	if err != nil {
		t.Fatal(err)
	}
	return invocation
}
