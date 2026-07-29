package ports

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/domain"
)

const (
	providerTestAttemptID    = "a_019f596a-cf80-7c67-b265-f37053d51ccf"
	providerTestSourceID     = "i_019f596a-cf80-7c67-b265-f37053d51ccd"
	providerTestExecutionID  = "019f596a-cf80-7c67-b265-f37053d51cce"
	providerTestResultSHA256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

func TestNewProviderInvocationRetainsTrustedIdentityAndCopiesStdin(t *testing.T) {
	stdin := []byte("complete provider stdin")
	invocation := newProviderInvocation(t, stdin)

	if invocation.Role() != domain.RoleSecurity {
		t.Fatalf("Role() = %q, want %q", invocation.Role(), domain.RoleSecurity)
	}
	if invocation.ProviderInstance() != "kimi-main" {
		t.Fatalf("ProviderInstance() = %q, want kimi-main", invocation.ProviderInstance())
	}
	if invocation.AttemptID().String() != providerTestAttemptID {
		t.Fatalf("AttemptID() = %q, want %q", invocation.AttemptID(), providerTestAttemptID)
	}
	if invocation.Purpose() != ProviderInvocationInitial {
		t.Fatalf("Purpose() = %q, want %q", invocation.Purpose(), ProviderInvocationInitial)
	}
	if invocation.SourceInvocationID() != providerTestSourceID {
		t.Fatalf("SourceInvocationID() = %q, want %q", invocation.SourceInvocationID(), providerTestSourceID)
	}
	if invocation.ExecutionInvocationID() != providerTestExecutionID {
		t.Fatalf("ExecutionInvocationID() = %q, want %q", invocation.ExecutionInvocationID(), providerTestExecutionID)
	}
	if want := providerTestDigest([]byte("complete provider stdin")); invocation.CompleteStdinSHA256() != want {
		t.Fatalf("CompleteStdinSHA256() = %q, want %q", invocation.CompleteStdinSHA256(), want)
	}

	stdin[0] = 'x'
	if got := invocation.Stdin(); !bytes.Equal(got, []byte("complete provider stdin")) {
		t.Fatalf("Stdin() after source mutation = %q", got)
	}
	copy := invocation.Stdin()
	copy[0] = 'y'
	if got := invocation.Stdin(); !bytes.Equal(got, []byte("complete provider stdin")) {
		t.Fatalf("Stdin() after getter mutation = %q", got)
	}
}

func TestNewProviderInvocationRejectsInvalidInputs(t *testing.T) {
	attempt := providerTestAttempt(t)
	stdin := []byte("stdin")
	digest := providerTestDigest(stdin)
	validStdin := []byte("complete provider stdin")
	validDigest := providerTestDigest(validStdin)
	valid := func() error {
		_, err := NewProviderInvocation(
			domain.RoleSecurity,
			"kimi-main",
			attempt,
			ProviderInvocationInitial,
			validStdin,
			providerTestSourceID,
			providerTestExecutionID,
			validDigest,
		)
		return err
	}
	if err := valid(); err != nil {
		t.Fatalf("valid invocation error = %v", err)
	}

	tests := []struct {
		name string
		call func() error
	}{
		{
			name: "invalid role",
			call: func() error {
				_, err := NewProviderInvocation(domain.Role("unknown"), "kimi-main", attempt, ProviderInvocationInitial, stdin, providerTestSourceID, providerTestExecutionID, digest)
				return err
			},
		},
		{
			name: "noncanonical provider instance",
			call: func() error {
				_, err := NewProviderInvocation(domain.RoleSecurity, "Kimi Main", attempt, ProviderInvocationInitial, stdin, providerTestSourceID, providerTestExecutionID, digest)
				return err
			},
		},
		{
			name: "invalid attempt",
			call: func() error {
				_, err := NewProviderInvocation(domain.RoleSecurity, "kimi-main", domain.AttemptID{}, ProviderInvocationInitial, stdin, providerTestSourceID, providerTestExecutionID, digest)
				return err
			},
		},
		{
			name: "invalid purpose",
			call: func() error {
				_, err := NewProviderInvocation(domain.RoleSecurity, "kimi-main", attempt, ProviderInvocationPurpose("retry"), stdin, providerTestSourceID, providerTestExecutionID, digest)
				return err
			},
		},
		{
			name: "empty stdin",
			call: func() error {
				_, err := NewProviderInvocation(domain.RoleSecurity, "kimi-main", attempt, ProviderInvocationInitial, nil, providerTestSourceID, providerTestExecutionID, providerTestDigest(nil))
				return err
			},
		},
		{
			name: "invalid source invocation ID",
			call: func() error {
				_, err := NewProviderInvocation(domain.RoleSecurity, "kimi-main", attempt, ProviderInvocationInitial, stdin, "i_not-a-uuid", providerTestExecutionID, digest)
				return err
			},
		},
		{
			name: "invalid execution invocation ID",
			call: func() error {
				_, err := NewProviderInvocation(domain.RoleSecurity, "kimi-main", attempt, ProviderInvocationInitial, stdin, providerTestSourceID, "i_"+providerTestExecutionID, digest)
				return err
			},
		},
		{
			name: "nonraw stdin digest",
			call: func() error {
				_, err := NewProviderInvocation(domain.RoleSecurity, "kimi-main", attempt, ProviderInvocationInitial, stdin, providerTestSourceID, providerTestExecutionID, "sha256:"+digest)
				return err
			},
		},
		{
			name: "mismatched stdin digest",
			call: func() error {
				_, err := NewProviderInvocation(domain.RoleSecurity, "kimi-main", attempt, ProviderInvocationInitial, stdin, providerTestSourceID, providerTestExecutionID, providerTestDigest([]byte("different")))
				return err
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.call(); err == nil {
				t.Fatal("NewProviderInvocation() succeeded")
			}
		})
	}
}

func TestNewProviderResultCopiesStdoutAndValidatesStdinIdentity(t *testing.T) {
	stdout := []byte(`{"findings":[]}`)
	result, err := NewProviderResult(stdout, 23, providerTestResultSHA256)
	if err != nil {
		t.Fatal(err)
	}
	stdout[0] = 'x'
	if got := result.Stdout(); !bytes.Equal(got, []byte(`{"findings":[]}`)) {
		t.Fatalf("Stdout() after source mutation = %q", got)
	}
	copy := result.Stdout()
	copy[0] = 'y'
	if got := result.Stdout(); !bytes.Equal(got, []byte(`{"findings":[]}`)) {
		t.Fatalf("Stdout() after getter mutation = %q", got)
	}
	if result.StdinByteLength() != 23 {
		t.Fatalf("StdinByteLength() = %d, want 23", result.StdinByteLength())
	}
	if result.CompleteStdinSHA256() != providerTestResultSHA256 {
		t.Fatalf("CompleteStdinSHA256() = %q, want %q", result.CompleteStdinSHA256(), providerTestResultSHA256)
	}

	for _, test := range []struct {
		name            string
		stdinByteLength int
		digest          string
	}{
		{name: "zero byte length", stdinByteLength: 0, digest: providerTestResultSHA256},
		{name: "negative byte length", stdinByteLength: -1, digest: providerTestResultSHA256},
		{name: "uppercase digest", stdinByteLength: 1, digest: strings.ToUpper(providerTestResultSHA256)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewProviderResult([]byte("stdout"), test.stdinByteLength, test.digest); err == nil {
				t.Fatal("NewProviderResult() succeeded")
			}
		})
	}
}

func newProviderInvocation(t *testing.T, stdin []byte) ProviderInvocation {
	t.Helper()
	invocation, err := NewProviderInvocation(
		domain.RoleSecurity,
		"kimi-main",
		providerTestAttempt(t),
		ProviderInvocationInitial,
		stdin,
		providerTestSourceID,
		providerTestExecutionID,
		providerTestDigest(stdin),
	)
	if err != nil {
		t.Fatal(err)
	}
	return invocation
}

func providerTestAttempt(t *testing.T) domain.AttemptID {
	t.Helper()
	attempt, err := domain.ParseAttemptID(providerTestAttemptID)
	if err != nil {
		t.Fatal(err)
	}
	return attempt
}
func providerTestDigest(stdin []byte) string {
	hash := sha256.New()
	_, _ = hash.Write([]byte("Mulgae-PROVIDER-STDIN/1"))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write(stdin)
	return hex.EncodeToString(hash.Sum(nil))
}
func TestProviderPacketContractPreservesV1IdentityAndLegacyAliases(t *testing.T) {
	packetBytes := []byte("packet transport payload")
	digest := providerTestDigest(packetBytes)
	packet, err := NewProviderPacket(packetBytes, digest)
	if err != nil {
		t.Fatal(err)
	}
	packetBytes[0] = 'x'
	if got, want := packet.Bytes(), []byte("packet transport payload"); !bytes.Equal(got, want) {
		t.Fatalf("Packet.Bytes() after source mutation = %q, want %q", got, want)
	}
	copy := packet.Bytes()
	copy[0] = 'y'
	if got, want := packet.Bytes(), []byte("packet transport payload"); !bytes.Equal(got, want) {
		t.Fatalf("Packet.Bytes() after getter mutation = %q, want %q", got, want)
	}
	if got := packet.Identity(); !got.Valid() || got.ByteLength() != len(packetBytes) || got.CompleteSHA256() != digest {
		t.Fatalf("Packet.Identity() = %#v", got)
	}

	invocation, err := NewProviderInvocationWithPacket(
		domain.RoleSecurity, "kimi-main", providerTestAttempt(t), ProviderInvocationInitial, packet,
		providerTestSourceID, providerTestExecutionID,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(invocation.PacketBytes(), invocation.Stdin()) || invocation.InputIdentity() != packet.Identity() ||
		invocation.CompleteStdinSHA256() != packet.Identity().CompleteSHA256() {
		t.Fatal("packet-native invocation and stdin aliases diverged")
	}

	result, err := NewProviderResultForInput([]byte("result"), packet.Identity())
	if err != nil {
		t.Fatal(err)
	}
	legacyResult, err := NewProviderResult([]byte("result"), packet.Identity().ByteLength(), packet.Identity().CompleteSHA256())
	if err != nil {
		t.Fatal(err)
	}
	if result.InputIdentity() != packet.Identity() || result.InputIdentity() != legacyResult.InputIdentity() ||
		result.InputByteLength() != result.StdinByteLength() ||
		result.CompleteInputSHA256() != result.CompleteStdinSHA256() {
		t.Fatal("packet-native result and stdin aliases diverged")
	}

	for _, test := range []struct {
		name string
		call func() error
	}{
		{name: "zero identity length", call: func() error {
			_, err := NewProviderPacketIdentity(0, digest)
			return err
		}},
		{name: "uppercase identity hash", call: func() error {
			_, err := NewProviderPacketIdentity(1, strings.ToUpper(digest))
			return err
		}},
		{name: "empty packet", call: func() error {
			_, err := NewProviderPacket(nil, providerTestDigest(nil))
			return err
		}},
		{name: "packet hash mismatch", call: func() error {
			_, err := NewProviderPacket([]byte("packet"), digest)
			return err
		}},
		{name: "result invalid identity", call: func() error {
			_, err := NewProviderResultForInput([]byte("result"), ProviderPacketIdentity{})
			return err
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := test.call(); err == nil {
				t.Fatal("packet contract constructor succeeded")
			}
		})
	}
}
