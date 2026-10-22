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
	// providerTestStagingDirectory is a canonical absolute per-invocation
	// staging directory. Destination validation is pure computation, so no
	// staging directory is ever created on disk by these tests.
	providerTestStagingDirectory = "/private/tmp/mulgae-staging/019f596a-cf80-7c67-b265-f37053d51cce"
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
				_, err := NewProviderInvocation(domain.RoleSecurity, "kimi-main", attempt, ProviderInvocationPurpose("unknown"), stdin, providerTestSourceID, providerTestExecutionID, digest)
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

func TestStagedOutputDestinationRejectsUnsafeValues(t *testing.T) {
	destination, err := NewStagedOutputDestination(providerTestStagingDirectory, "report.md")
	if err != nil {
		t.Fatal(err)
	}
	if destination.Directory() != providerTestStagingDirectory || destination.Filename() != "report.md" {
		t.Fatalf("destination = %#v", destination)
	}
	if got, want := destination.AbsolutePath(), providerTestStagingDirectory+"/report.md"; got != want {
		t.Fatalf("AbsolutePath() = %q, want %q", got, want)
	}
	if !destination.Valid() {
		t.Fatal("valid staged output destination reports itself invalid")
	}
	if (StagedOutputDestination{}).Valid() {
		t.Fatal("zero staged output destination is valid")
	}

	for _, test := range []struct {
		name      string
		directory string
		filename  string
	}{
		{name: "relative directory", directory: "mulgae-staging/019f596a", filename: "report.md"},
		{name: "uncleaned directory", directory: "/a/../b", filename: "report.md"},
		{name: "filesystem root directory", directory: "/", filename: "report.md"},
		{name: "empty directory", directory: "", filename: "report.md"},
		{name: "directory with NUL", directory: providerTestStagingDirectory + "\x00", filename: "report.md"},
		{name: "absolute filename", directory: providerTestStagingDirectory, filename: "/report.md"},
		{name: "filename with separator", directory: providerTestStagingDirectory, filename: "reports/report.md"},
		{name: "nested filename", directory: providerTestStagingDirectory, filename: "a/b"},
		{name: "dotdot filename", directory: providerTestStagingDirectory, filename: ".."},
		{name: "dot filename", directory: providerTestStagingDirectory, filename: "."},
		{name: "empty filename", directory: providerTestStagingDirectory, filename: ""},
		{name: "filename with NUL", directory: providerTestStagingDirectory, filename: "report.md\x00"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewStagedOutputDestination(test.directory, test.filename); err == nil {
				t.Fatal("NewStagedOutputDestination() succeeded")
			}
		})
	}
}

func TestProviderOutputTransportValid(t *testing.T) {
	for _, transport := range []ProviderOutputTransport{
		ProviderOutputTransportStdout,
		ProviderOutputTransportStagedFile,
	} {
		if !transport.Valid() {
			t.Fatalf("transport %q is invalid", transport)
		}
	}
	for _, transport := range []ProviderOutputTransport{"", "staged", "stagedfile", "STDOUT", "file"} {
		if transport.Valid() {
			t.Fatalf("transport %q is valid", transport)
		}
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

func TestProviderPacketValidAvoidsRehashAfterConstruction(t *testing.T) {
	payload := []byte("complete provider stdin")
	wantDigest := providerTestDigest(payload)

	scope := beginVerificationCounting(t)
	packet, err := NewProviderPacketFromBytes(payload)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := scope.packetDigests(), int64(1); got != want {
		t.Errorf("NewProviderPacketFromBytes digests = %d, want %d", got, want)
	}
	if got, want := scope.copies(), int64(1); got != want {
		t.Errorf("NewProviderPacketFromBytes copies = %d, want %d", got, want)
	}
	if got := packet.Identity(); got.ByteLength() != len(payload) || got.CompleteSHA256() != wantDigest {
		t.Fatalf("packet identity = %#v, want length %d digest %q", got, len(payload), wantDigest)
	}

	// The digest is verified over the retained clone, so mutating the caller's
	// input slice cannot change the packet's bytes, identity, or validity.
	payload[0] = 'x'
	if got := packet.Bytes(); !bytes.Equal(got, []byte("complete provider stdin")) {
		t.Fatalf("Bytes() after source mutation = %q", got)
	}
	if got := packet.Identity(); got.ByteLength() != len(payload) || got.CompleteSHA256() != wantDigest {
		t.Fatalf("identity after source mutation = %#v", got)
	}
	if !packet.Valid() {
		t.Fatal("valid packet reports itself invalid after source mutation")
	}
	payload[0] = 'c'

	scope.reset()
	if !packet.Valid() {
		t.Fatal("constructed packet reports itself invalid")
	}
	if got, want := scope.packetDigests(), int64(0); got != want {
		t.Errorf("Valid() digests = %d, want %d", got, want)
	}

	scope.reset()
	invocation, err := NewProviderInvocationWithPacket(
		domain.RoleSecurity, "kimi-main", providerTestAttempt(t), ProviderInvocationInitial, packet,
		providerTestSourceID, providerTestExecutionID,
	)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := scope.packetDigests(), int64(0); got != want {
		t.Errorf("NewProviderInvocationWithPacket digests = %d, want %d", got, want)
	}
	if got, want := scope.copies(), int64(0); got != want {
		t.Errorf("NewProviderInvocationWithPacket copies = %d, want %d", got, want)
	}

	scope.reset()
	returned := invocation.Packet()
	if got, want := scope.packetDigests(), int64(0); got != want {
		t.Errorf("Packet() digests = %d, want %d", got, want)
	}
	if got, want := scope.copies(), int64(0); got != want {
		t.Errorf("Packet() copies = %d, want %d", got, want)
	}
	if got := returned.Bytes(); !bytes.Equal(got, []byte("complete provider stdin")) {
		t.Fatalf("Packet().Bytes() = %q", got)
	}

	// In-package literals are never proof-carrying: they keep the full
	// exact-byte verification, paying exactly one packet digest.
	literalBytes := []byte("unproven literal payload")
	coherentIdentity, err := NewProviderPacketIdentity(len(literalBytes), providerTestDigest(literalBytes))
	if err != nil {
		t.Fatal(err)
	}
	mismatchedIdentity, err := NewProviderPacketIdentity(len(literalBytes), providerTestDigest([]byte("different bytes")))
	if err != nil {
		t.Fatal(err)
	}
	scope.reset()
	mismatched := ProviderPacket{bytes: literalBytes, identity: mismatchedIdentity}
	if mismatched.Valid() {
		t.Fatal("mismatched unproven packet literal is valid")
	}
	if got, want := scope.packetDigests(), int64(1); got != want {
		t.Errorf("mismatched literal Valid() digests = %d, want %d", got, want)
	}
	scope.reset()
	coherent := ProviderPacket{bytes: literalBytes, identity: coherentIdentity}
	if !coherent.Valid() {
		t.Fatal("coherent unproven packet literal is invalid")
	}
	if got, want := scope.packetDigests(), int64(1); got != want {
		t.Errorf("coherent literal Valid() digests = %d, want %d", got, want)
	}
	scope.reset()
	if _, err := NewProviderInvocationWithPacket(
		domain.RoleSecurity, "kimi-main", providerTestAttempt(t), ProviderInvocationInitial, mismatched,
		providerTestSourceID, providerTestExecutionID,
	); err == nil {
		t.Fatal("NewProviderInvocationWithPacket accepted a mismatched unproven packet literal")
	}
	if got, want := scope.packetDigests(), int64(1); got != want {
		t.Errorf("NewProviderInvocationWithPacket rejection digests = %d, want %d", got, want)
	}

	if (ProviderPacket{}).Valid() {
		t.Fatal("zero packet is valid")
	}
}

func TestProviderPacketEqualComparesExactBytesWithoutCopying(t *testing.T) {
	payload := []byte("exact packet payload")
	otherPayload := []byte("exact packet payloaX")

	scope := beginVerificationCounting(t)
	left, err := NewProviderPacketFromBytes(payload)
	if err != nil {
		t.Fatal(err)
	}
	sameContent, err := NewProviderPacketFromBytes([]byte("exact packet payload"))
	if err != nil {
		t.Fatal(err)
	}
	changed, err := NewProviderPacketFromBytes(otherPayload)
	if err != nil {
		t.Fatal(err)
	}
	scope.reset()

	if !left.Equal(sameContent) {
		t.Fatal("packets built from the same bytes are not equal")
	}
	if left.Equal(changed) {
		t.Fatal("packets with different bytes are equal")
	}
	if !(ProviderPacket{}).Equal(ProviderPacket{}) {
		t.Fatal("zero packets are not equal")
	}

	// Equal is pinned on identity and bytes separately; the literals are
	// deliberately unproven because Equal never consults validity.
	firstIdentity, err := NewProviderPacketIdentity(4, providerTestDigest([]byte("aaaa")))
	if err != nil {
		t.Fatal(err)
	}
	secondIdentity, err := NewProviderPacketIdentity(4, providerTestDigest([]byte("bbbb")))
	if err != nil {
		t.Fatal(err)
	}
	sameIdentityDifferentBytes := ProviderPacket{bytes: []byte("bbbb"), identity: firstIdentity}
	if (ProviderPacket{bytes: []byte("aaaa"), identity: firstIdentity}).Equal(sameIdentityDifferentBytes) {
		t.Fatal("packets with the same identity but different bytes are equal")
	}
	sameBytesDifferentIdentity := ProviderPacket{bytes: []byte("aaaa"), identity: secondIdentity}
	if (ProviderPacket{bytes: []byte("aaaa"), identity: firstIdentity}).Equal(sameBytesDifferentIdentity) {
		t.Fatal("packets with the same bytes but different identities are equal")
	}
	if got, want := scope.packetDigests(), int64(0); got != want {
		t.Errorf("Equal digests = %d, want %d", got, want)
	}
	if got, want := scope.copies(), int64(0); got != want {
		t.Errorf("Equal copies = %d, want %d", got, want)
	}
}
