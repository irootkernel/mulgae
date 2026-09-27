package domain

import (
	"fmt"
	"strings"
)

// These identities answer different questions and cannot be interchanged by
// application callers. Their SHA-256 preimages are versioned by their owners.
type ProjectBinding struct{ value string }
type CaptureIdentity struct{ value string }
type RequestIdentity struct{ value string }
type PublicationReceipt struct{ value string }

func ParseProjectBinding(value string) (ProjectBinding, error) {
	if !reviewIdentityValid(value) {
		return ProjectBinding{}, fmt.Errorf("project binding: %w", ErrInvariant)
	}
	return ProjectBinding{value}, nil
}
func ParseCaptureIdentity(value string) (CaptureIdentity, error) {
	if !reviewIdentityValid(value) {
		return CaptureIdentity{}, fmt.Errorf("capture identity: %w", ErrInvariant)
	}
	return CaptureIdentity{value}, nil
}
func ParseRequestIdentity(value string) (RequestIdentity, error) {
	if !reviewIdentityValid(value) {
		return RequestIdentity{}, fmt.Errorf("request identity: %w", ErrInvariant)
	}
	return RequestIdentity{value}, nil
}
func ParsePublicationReceipt(value string) (PublicationReceipt, error) {
	if !reviewIdentityValid(value) {
		return PublicationReceipt{}, fmt.Errorf("publication receipt: %w", ErrInvariant)
	}
	return PublicationReceipt{value}, nil
}
func (id ProjectBinding) String() string     { return id.value }
func (id CaptureIdentity) String() string    { return id.value }
func (id RequestIdentity) String() string    { return id.value }
func (id PublicationReceipt) String() string { return id.value }
func (id ProjectBinding) Valid() bool        { return reviewIdentityValid(id.value) }
func (id CaptureIdentity) Valid() bool       { return reviewIdentityValid(id.value) }
func (id RequestIdentity) Valid() bool       { return reviewIdentityValid(id.value) }
func (id PublicationReceipt) Valid() bool    { return reviewIdentityValid(id.value) }

func reviewIdentityValid(value string) bool {
	return strings.HasPrefix(value, "sha256:") && lowerSHA256Pattern.MatchString(value[7:]) && !allZeroHex(value[7:])
}
