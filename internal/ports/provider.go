package ports

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"reflect"

	"github.com/irootkernel/mulgae/internal/domain"
)

// ProviderInvocationPurpose identifies the bounded stage of an attempt sent to
// a review provider.
type ProviderInvocationPurpose string

const (
	ProviderInvocationInitial ProviderInvocationPurpose = "initial"
	ProviderInvocationRepair  ProviderInvocationPurpose = "repair"
)

// Valid reports whether purpose is a supported provider invocation purpose.
func (purpose ProviderInvocationPurpose) Valid() bool {
	return purpose == ProviderInvocationInitial || purpose == ProviderInvocationRepair
}

// ProviderOutputTransport identifies how one provider invocation is expected to
// deliver its reviewable output. It records a transport fact only; it grants no
// finding, validation, or publication authority.
type ProviderOutputTransport string

const (
	ProviderOutputTransportStdout     ProviderOutputTransport = "stdout"
	ProviderOutputTransportStagedFile ProviderOutputTransport = "staged_file"
)

// Valid reports whether transport is a supported provider output transport.
func (transport ProviderOutputTransport) Valid() bool {
	return transport == ProviderOutputTransportStdout || transport == ProviderOutputTransportStagedFile
}

// StagedOutputDestination is the immutable Mulgae-chosen location of the single
// file a staged_file provider invocation may write. Both components are owned
// by Mulgae: provider output never selects the directory or the file name.
type StagedOutputDestination struct {
	directory string
	filename  string
}

// NewStagedOutputDestination validates a canonical absolute staging directory
// and the single safe base name Mulgae requires the provider to write.
func NewStagedOutputDestination(directory, filename string) (StagedOutputDestination, error) {
	if err := validateStagedOutputDirectory(directory); err != nil {
		return StagedOutputDestination{}, fmt.Errorf("staged output destination: directory %w", err)
	}
	if err := validateStagedOutputFilename(filename); err != nil {
		return StagedOutputDestination{}, fmt.Errorf("staged output destination: filename %w", err)
	}
	return StagedOutputDestination{directory: directory, filename: filename}, nil
}

// Directory returns the canonical absolute per-invocation staging directory.
func (destination StagedOutputDestination) Directory() string { return destination.directory }

// Filename returns the safe base name Mulgae requires the provider to write.
func (destination StagedOutputDestination) Filename() string { return destination.filename }

// AbsolutePath returns the exact absolute path the provider is instructed to
// write. It is always the join of the canonical directory and the base name.
func (destination StagedOutputDestination) AbsolutePath() string {
	return filepath.Join(destination.directory, destination.filename)
}

// Valid reports whether destination is a complete canonical staging location.
func (destination StagedOutputDestination) Valid() bool {
	_, err := NewStagedOutputDestination(destination.directory, destination.filename)
	return err == nil
}

// ProviderPacketIdentity is the immutable v1 identity of the complete provider
// packet. Its digest algorithm is retained for continuity, not transport claims.
type ProviderPacketIdentity struct {
	byteLength     int
	completeSHA256 string
}

// NewProviderPacketIdentity validates a non-empty complete packet identity.
func NewProviderPacketIdentity(byteLength int, completeSHA256 string) (ProviderPacketIdentity, error) {
	if byteLength <= 0 {
		return ProviderPacketIdentity{}, fmt.Errorf("provider packet identity: byte length must be positive")
	}
	if err := validateRawSHA256(completeSHA256); err != nil {
		return ProviderPacketIdentity{}, fmt.Errorf("provider packet identity: invalid complete SHA-256: %w", err)
	}
	return ProviderPacketIdentity{byteLength: byteLength, completeSHA256: completeSHA256}, nil
}

func (identity ProviderPacketIdentity) ByteLength() int        { return identity.byteLength }
func (identity ProviderPacketIdentity) CompleteSHA256() string { return identity.completeSHA256 }
func (identity ProviderPacketIdentity) Valid() bool {
	_, err := NewProviderPacketIdentity(identity.byteLength, identity.completeSHA256)
	return err == nil
}

// ProviderPacket is immutable complete provider input.
type ProviderPacket struct {
	bytes    []byte
	identity ProviderPacketIdentity
}

// NewProviderPacketFromBytes constructs the canonical v1 packet identity from
// the complete bytes. Callers that do not already possess a trusted v1 digest
// should use this constructor rather than reproducing the domain separator.
func NewProviderPacketFromBytes(bytes []byte) (ProviderPacket, error) {
	return NewProviderPacket(bytes, providerPacketDigest(bytes))
}

// NewProviderPacket retains a defensive copy and validates its v1 identity.
func NewProviderPacket(bytes []byte, completeSHA256 string) (ProviderPacket, error) {
	identity, err := NewProviderPacketIdentity(len(bytes), completeSHA256)
	if err != nil {
		return ProviderPacket{}, err
	}
	if providerPacketDigest(bytes) != identity.completeSHA256 {
		return ProviderPacket{}, fmt.Errorf("provider packet: complete SHA-256 does not match bytes")
	}
	return ProviderPacket{bytes: cloneBytes(bytes), identity: identity}, nil
}

func (packet ProviderPacket) Bytes() []byte                    { return cloneBytes(packet.bytes) }
func (packet ProviderPacket) Identity() ProviderPacketIdentity { return packet.identity }
func (packet ProviderPacket) Valid() bool {
	canonical, err := NewProviderPacket(packet.bytes, packet.identity.completeSHA256)
	return err == nil && canonical.identity == packet.identity
}

// ProviderInvocation is immutable trusted input to a review provider.
type ProviderInvocation struct {
	role                  domain.Role
	providerInstance      string
	attemptID             domain.AttemptID
	purpose               ProviderInvocationPurpose
	packet                ProviderPacket
	sourceInvocationID    string
	executionInvocationID string
	workspace             WorkspaceExecutionAuthority
	workspaceIdentity     WorkspaceSnapshotIdentity
	hasWorkspace          bool
	stagedOutput          StagedOutputDestination
	hasStagedOutput       bool
}

// NewProviderInvocationWithPacket validates trusted provider invocation identity.
func NewProviderInvocationWithPacket(
	role domain.Role, providerInstance string, attemptID domain.AttemptID,
	purpose ProviderInvocationPurpose, packet ProviderPacket,
	sourceInvocationID, executionInvocationID string,
) (ProviderInvocation, error) {
	if !role.Valid() || !validProviderInstanceID(providerInstance) {
		return ProviderInvocation{}, fmt.Errorf("provider invocation: invalid role or provider instance")
	}
	if _, err := domain.ParseAttemptID(attemptID.String()); err != nil || !purpose.Valid() || !packet.Valid() {
		return ProviderInvocation{}, fmt.Errorf("provider invocation: invalid attempt ID, purpose, or packet")
	}
	if err := validateProviderInvocationID(sourceInvocationID, "i_"); err != nil {
		return ProviderInvocation{}, fmt.Errorf("provider invocation: invalid source invocation ID: %w", err)
	}
	if err := validateProviderInvocationID(executionInvocationID, ""); err != nil {
		return ProviderInvocation{}, fmt.Errorf("provider invocation: invalid execution invocation ID: %w", err)
	}
	canonicalPacket, _ := NewProviderPacket(packet.Bytes(), packet.Identity().CompleteSHA256())
	return ProviderInvocation{role: role, providerInstance: providerInstance, attemptID: attemptID, purpose: purpose, packet: canonicalPacket, sourceInvocationID: sourceInvocationID, executionInvocationID: executionInvocationID}, nil
}

// NewProviderInvocationWithPacketInWorkspace binds a provider invocation to the
// capture-owned workspace authority. The authority's immutable identity is
// captured once; execution consumers must not infer authority from prompt paths.
func NewProviderInvocationWithPacketInWorkspace(
	role domain.Role, providerInstance string, attemptID domain.AttemptID,
	purpose ProviderInvocationPurpose, packet ProviderPacket,
	sourceInvocationID, executionInvocationID string, workspace WorkspaceExecutionAuthority,
) (ProviderInvocation, error) {
	if nilWorkspaceExecutionAuthority(workspace) {
		return ProviderInvocation{}, fmt.Errorf("provider invocation: nil workspace authority")
	}
	identity := workspace.WorkspaceSnapshotIdentity()
	if !identity.Valid() {
		return ProviderInvocation{}, fmt.Errorf("provider invocation: invalid workspace identity")
	}
	invocation, err := NewProviderInvocationWithPacket(
		role, providerInstance, attemptID, purpose, packet, sourceInvocationID, executionInvocationID,
	)
	if err != nil {
		return ProviderInvocation{}, err
	}
	invocation.workspace = workspace
	invocation.workspaceIdentity = identity
	invocation.hasWorkspace = true
	return invocation, nil
}

// NewProviderInvocationWithStagedOutput binds the Mulgae-owned staged output
// destination to an already validated invocation. Every other constructor
// leaves the destination absent, which keeps the implicit stdout transport.
func NewProviderInvocationWithStagedOutput(invocation ProviderInvocation, destination StagedOutputDestination) (ProviderInvocation, error) {
	canonical, err := canonicalProviderInvocation(invocation)
	if err != nil {
		return ProviderInvocation{}, fmt.Errorf("provider invocation: %w", err)
	}
	return withStagedOutputDestination(canonical, destination)
}

// withStagedOutputDestination attaches a validated destination without
// re-canonicalizing, so canonicalization itself can re-attach without recursion.
func withStagedOutputDestination(invocation ProviderInvocation, destination StagedOutputDestination) (ProviderInvocation, error) {
	if !destination.Valid() {
		return ProviderInvocation{}, fmt.Errorf("provider invocation: invalid staged output destination")
	}
	invocation.stagedOutput = destination
	invocation.hasStagedOutput = true
	return invocation, nil
}

// NewProviderInvocation is the source-compatible stdin-named packet wrapper.
func NewProviderInvocation(role domain.Role, providerInstance string, attemptID domain.AttemptID, purpose ProviderInvocationPurpose, stdin []byte, sourceInvocationID, executionInvocationID, completeStdinSHA256 string) (ProviderInvocation, error) {
	packet, err := NewProviderPacket(stdin, completeStdinSHA256)
	if err != nil {
		return ProviderInvocation{}, fmt.Errorf("provider invocation: %w", err)
	}
	return NewProviderInvocationWithPacket(role, providerInstance, attemptID, purpose, packet, sourceInvocationID, executionInvocationID)
}

func (invocation ProviderInvocation) Role() domain.Role                  { return invocation.role }
func (invocation ProviderInvocation) ProviderInstance() string           { return invocation.providerInstance }
func (invocation ProviderInvocation) AttemptID() domain.AttemptID        { return invocation.attemptID }
func (invocation ProviderInvocation) Purpose() ProviderInvocationPurpose { return invocation.purpose }
func (invocation ProviderInvocation) Packet() ProviderPacket {
	packet, _ := NewProviderPacket(invocation.packet.Bytes(), invocation.packet.Identity().CompleteSHA256())
	return packet
}
func (invocation ProviderInvocation) PacketBytes() []byte { return invocation.packet.Bytes() }
func (invocation ProviderInvocation) InputIdentity() ProviderPacketIdentity {
	return invocation.packet.Identity()
}

// Stdin is a deprecated packet alias retained for source compatibility.
func (invocation ProviderInvocation) Stdin() []byte { return invocation.PacketBytes() }
func (invocation ProviderInvocation) SourceInvocationID() string {
	return invocation.sourceInvocationID
}
func (invocation ProviderInvocation) ExecutionInvocationID() string {
	return invocation.executionInvocationID
}

// ExecutionWorkspace returns the capture-owned execution authority when this
// invocation was created for a production workspace.
func (invocation ProviderInvocation) ExecutionWorkspace() (WorkspaceExecutionAuthority, bool) {
	return invocation.workspace, invocation.hasWorkspace
}

// WorkspaceSnapshotIdentity returns the immutable identity captured with the
// execution authority, without exposing execution authority through prompt data.
func (invocation ProviderInvocation) WorkspaceSnapshotIdentity() (WorkspaceSnapshotIdentity, bool) {
	return invocation.workspaceIdentity, invocation.hasWorkspace
}

// StagedOutputDestination returns the Mulgae-chosen staged output location when
// this invocation was created for the staged_file transport. An absent
// destination means the invocation delivers its output through stdout.
func (invocation ProviderInvocation) StagedOutputDestination() (StagedOutputDestination, bool) {
	return invocation.stagedOutput, invocation.hasStagedOutput
}

// CompleteStdinSHA256 is a deprecated packet identity alias.
func (invocation ProviderInvocation) CompleteStdinSHA256() string {
	return invocation.InputIdentity().CompleteSHA256()
}

// ProviderResult is immutable raw provider output bound to a complete packet identity.
type ProviderResult struct {
	stdout        []byte
	inputIdentity ProviderPacketIdentity
}

func NewProviderResultForInput(stdout []byte, identity ProviderPacketIdentity) (ProviderResult, error) {
	if !identity.Valid() {
		return ProviderResult{}, fmt.Errorf("provider result: invalid input identity")
	}
	return ProviderResult{stdout: cloneBytes(stdout), inputIdentity: identity}, nil
}

// NewProviderResult is the source-compatible stdin-named identity wrapper.
func NewProviderResult(stdout []byte, stdinByteLength int, completeStdinSHA256 string) (ProviderResult, error) {
	identity, err := NewProviderPacketIdentity(stdinByteLength, completeStdinSHA256)
	if err != nil {
		return ProviderResult{}, err
	}
	return NewProviderResultForInput(stdout, identity)
}

func (result ProviderResult) Stdout() []byte                        { return cloneBytes(result.stdout) }
func (result ProviderResult) InputIdentity() ProviderPacketIdentity { return result.inputIdentity }
func (result ProviderResult) InputByteLength() int                  { return result.inputIdentity.ByteLength() }
func (result ProviderResult) CompleteInputSHA256() string {
	return result.inputIdentity.CompleteSHA256()
}

// StdinByteLength is a deprecated packet identity alias.
func (result ProviderResult) StdinByteLength() int { return result.InputByteLength() }

// CompleteStdinSHA256 is a deprecated packet identity alias.
func (result ProviderResult) CompleteStdinSHA256() string { return result.CompleteInputSHA256() }

// ReviewProvider is the only boundary used to invoke a review provider.
type ReviewProvider interface {
	Invoke(context.Context, ProviderInvocation) (ProviderResult, error)
}

func validProviderInstanceID(value string) bool {
	if len(value) == 0 || len(value) > 64 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for index := 1; index < len(value); index++ {
		character := value[index]
		if (character >= 'a' && character <= 'z') ||
			(character >= '0' && character <= '9') ||
			character == '.' || character == '_' || character == '-' {
			continue
		}
		return false
	}
	return true
}
func nilWorkspaceExecutionAuthority(authority WorkspaceExecutionAuthority) bool {
	if authority == nil {
		return true
	}
	value := reflect.ValueOf(authority)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

// validateStagedOutputDirectory accepts the canonical absolute directory rules
// already required of an anchored root, and additionally refuses the filesystem
// root so a per-invocation staging area is always a dedicated subdirectory.
func validateStagedOutputDirectory(value string) error {
	if err := validateAnchoredRoot(value); err != nil {
		return err
	}
	if value == string(filepath.Separator) {
		return fmt.Errorf("must not be the filesystem root")
	}
	return nil
}

// validateStagedOutputFilename accepts exactly one safe, traversal-free base
// name inside the staging directory.
func validateStagedOutputFilename(value string) error {
	if err := validateSafeRelativePath(value); err != nil {
		return err
	}
	if filepath.Base(value) != value {
		return fmt.Errorf("must be a single base name")
	}
	return nil
}

func validateProviderInvocationID(value, prefix string) error {
	if len(value) < len(prefix) || value[:len(prefix)] != prefix {
		return fmt.Errorf("must start with %q", prefix)
	}
	return validateProviderUUIDv7(value[len(prefix):])
}

func validateProviderUUIDv7(value string) error {
	if len(value) != 36 {
		return fmt.Errorf("must contain 36 canonical UUID characters")
	}
	for index, character := range value {
		switch index {
		case 8, 13, 18, 23:
			if character != '-' {
				return fmt.Errorf("hyphen at byte %d is missing", index)
			}
		default:
			if !isLowerHex(character) {
				return fmt.Errorf("byte %d is not lowercase hexadecimal", index)
			}
		}
	}
	if value[14] != '7' {
		return fmt.Errorf("version nibble is not 7")
	}
	if value[19] != '8' && value[19] != '9' && value[19] != 'a' && value[19] != 'b' {
		return fmt.Errorf("variant nibble is not RFC 9562")
	}
	if value == "00000000-0000-7000-8000-000000000000" {
		return fmt.Errorf("zero-form UUIDv7 is not an issued identifier")
	}
	return nil
}

func validateRawSHA256(value string) error {
	if len(value) != 64 {
		return fmt.Errorf("must contain 64 lowercase hexadecimal characters")
	}
	for _, character := range value {
		if !isLowerHex(character) {
			return fmt.Errorf("must contain 64 lowercase hexadecimal characters")
		}
	}
	return nil
}
func providerPacketDigest(packet []byte) string {
	hash := sha256.New()
	_, _ = hash.Write([]byte("Mulgae-PROVIDER-STDIN/1"))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write(packet)
	return hex.EncodeToString(hash.Sum(nil))
}
