package ports

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/irootkernel/kkachi-agent-review/internal/domain"
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

// ProviderInvocation is the immutable trusted input to a review provider.
// Stdin returns caller-owned bytes.
type ProviderInvocation struct {
	role                  domain.Role
	providerInstance      string
	attemptID             domain.AttemptID
	purpose               ProviderInvocationPurpose
	stdin                 []byte
	sourceInvocationID    string
	executionInvocationID string
	completeStdinSHA256   string
}

// NewProviderInvocation validates trusted provider invocation identity and
// retains a defensive copy of stdin.
func NewProviderInvocation(
	role domain.Role,
	providerInstance string,
	attemptID domain.AttemptID,
	purpose ProviderInvocationPurpose,
	stdin []byte,
	sourceInvocationID string,
	executionInvocationID string,
	completeStdinSHA256 string,
) (ProviderInvocation, error) {
	if !role.Valid() {
		return ProviderInvocation{}, fmt.Errorf("provider invocation: invalid role %q", role)
	}
	if !validProviderInstanceID(providerInstance) {
		return ProviderInvocation{}, fmt.Errorf("provider invocation: invalid provider instance %q", providerInstance)
	}
	if _, err := domain.ParseAttemptID(attemptID.String()); err != nil {
		return ProviderInvocation{}, fmt.Errorf("provider invocation: invalid attempt ID: %w", err)
	}
	if !purpose.Valid() {
		return ProviderInvocation{}, fmt.Errorf("provider invocation: invalid purpose %q", purpose)
	}
	if len(stdin) == 0 {
		return ProviderInvocation{}, fmt.Errorf("provider invocation: stdin must be non-empty")
	}
	if err := validateProviderInvocationID(sourceInvocationID, "i_"); err != nil {
		return ProviderInvocation{}, fmt.Errorf("provider invocation: invalid source invocation ID: %w", err)
	}
	if err := validateProviderInvocationID(executionInvocationID, ""); err != nil {
		return ProviderInvocation{}, fmt.Errorf("provider invocation: invalid execution invocation ID: %w", err)
	}
	if err := validateRawSHA256(completeStdinSHA256); err != nil {
		return ProviderInvocation{}, fmt.Errorf("provider invocation: invalid complete stdin SHA-256: %w", err)
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte("KAR-PROVIDER-STDIN/1"))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write(stdin)
	if completeStdinSHA256 != hex.EncodeToString(hash.Sum(nil)) {
		return ProviderInvocation{}, fmt.Errorf("provider invocation: complete stdin SHA-256 does not match stdin bytes")
	}
	return ProviderInvocation{
		role:                  role,
		providerInstance:      providerInstance,
		attemptID:             attemptID,
		purpose:               purpose,
		stdin:                 cloneBytes(stdin),
		sourceInvocationID:    sourceInvocationID,
		executionInvocationID: executionInvocationID,
		completeStdinSHA256:   completeStdinSHA256,
	}, nil
}

// Role returns the coordinator-selected review role.
func (invocation ProviderInvocation) Role() domain.Role { return invocation.role }

// ProviderInstance returns the coordinator-selected provider instance ID.
func (invocation ProviderInvocation) ProviderInstance() string { return invocation.providerInstance }

// AttemptID returns the coordinator-created attempt ID.
func (invocation ProviderInvocation) AttemptID() domain.AttemptID { return invocation.attemptID }

// Purpose returns the coordinator-selected invocation purpose.
func (invocation ProviderInvocation) Purpose() ProviderInvocationPurpose { return invocation.purpose }

// Stdin returns a caller-owned copy of the exact provider stdin bytes.
func (invocation ProviderInvocation) Stdin() []byte { return cloneBytes(invocation.stdin) }

// SourceInvocationID returns the fresh source invocation ID.
func (invocation ProviderInvocation) SourceInvocationID() string {
	return invocation.sourceInvocationID
}

// ExecutionInvocationID returns the fresh execution invocation ID.
func (invocation ProviderInvocation) ExecutionInvocationID() string {
	return invocation.executionInvocationID
}

// CompleteStdinSHA256 returns the raw SHA-256 identity of the complete stdin stream.
func (invocation ProviderInvocation) CompleteStdinSHA256() string {
	return invocation.completeStdinSHA256
}

// ProviderResult is the immutable raw result returned by a review provider.
// Stdout returns caller-owned bytes. It deliberately carries no role, attempt,
// or final-outcome authority.
type ProviderResult struct {
	stdout              []byte
	stdinByteLength     int
	completeStdinSHA256 string
}

// NewProviderResult validates raw provider result identity and retains a
// defensive copy of stdout.
func NewProviderResult(stdout []byte, stdinByteLength int, completeStdinSHA256 string) (ProviderResult, error) {
	if stdinByteLength <= 0 {
		return ProviderResult{}, fmt.Errorf("provider result: stdin byte length must be positive")
	}
	if err := validateRawSHA256(completeStdinSHA256); err != nil {
		return ProviderResult{}, fmt.Errorf("provider result: invalid complete stdin SHA-256: %w", err)
	}
	return ProviderResult{
		stdout:              cloneBytes(stdout),
		stdinByteLength:     stdinByteLength,
		completeStdinSHA256: completeStdinSHA256,
	}, nil
}

// Stdout returns a caller-owned copy of the raw provider stdout bytes.
func (result ProviderResult) Stdout() []byte { return cloneBytes(result.stdout) }

// StdinByteLength returns the exact number of bytes written to provider stdin.
func (result ProviderResult) StdinByteLength() int { return result.stdinByteLength }

// CompleteStdinSHA256 returns the raw SHA-256 identity of the written stdin stream.
func (result ProviderResult) CompleteStdinSHA256() string { return result.completeStdinSHA256 }

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
