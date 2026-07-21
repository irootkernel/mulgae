//go:build liveprovider

package providercli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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

func TestLiveKimiCapabilityProfile(t *testing.T) {
	binaryPath := os.Getenv("KAR_LIVE_KIMI_BIN")
	if binaryPath == "" {
		t.Skip("KAR_LIVE_KIMI_BIN is not configured")
	}
	if !filepath.IsAbs(binaryPath) || filepath.Clean(binaryPath) != binaryPath {
		t.Fatal("live Kimi executable must be a canonical absolute path")
	}
	version := os.Getenv("KAR_LIVE_KIMI_VERSION")

	key, err := ports.ParseConcurrencyKey("kimi-default")
	if err != nil {
		t.Fatal(err)
	}
	environment := liveKimiEnvironment(t)
	profile, err := NewRuntimeDefinition(
		FamilyKimi,
		"local-default",
		version,
		binaryPath,
		"",
		key,
		"kimi-default",
		[]string{binaryPath},
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
	registry, err := NewRegistry(runner, profile)
	if err != nil {
		t.Fatal(err)
	}

	const marker = "kar-live-kimi-capability-v1"
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
	receipt := observation.StdinWriteReceipt()
	if receipt.IntendedByteLength() != 0 || receipt.WrittenByteCount() != 0 || !receipt.Complete() ||
		receipt.SHA256() != liveKimiDigest(nil) {
		t.Fatalf("live Kimi stdin receipt is not a complete zero-byte fact: %#v", receipt)
	}
	transport, ok := observation.ProcessObservation().ProviderPacketTransportReceipt()
	if !ok || transport.Channel() != ports.ProviderPacketChannelArgvLiteral ||
		transport.PacketIdentity() != invocation.InputIdentity() {
		t.Fatalf("live Kimi transport receipt = %#v, present=%t", transport, ok)
	}
	if result.InputIdentity() != invocation.InputIdentity() {
		t.Fatal("live Kimi result input identity did not match invocation")
	}
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
	digest := liveKimiDigest(prompt)
	invocation, err := ports.NewProviderInvocation(
		domain.RoleSecurity,
		"local-default",
		attempt,
		ports.ProviderInvocationInitial,
		prompt,
		"i_019f596a-cf80-7c67-b265-f37053d51ccd",
		"019f596a-cf80-7c67-b265-f37053d51cce",
		digest,
	)
	if err != nil {
		t.Fatal(err)
	}
	return invocation
}
func liveKimiDigest(value []byte) string {
	digest := sha256.New()
	_, _ = digest.Write([]byte("KAR-PROVIDER-STDIN/1"))
	_, _ = digest.Write([]byte{0})
	_, _ = digest.Write(value)
	return hex.EncodeToString(digest.Sum(nil))
}
