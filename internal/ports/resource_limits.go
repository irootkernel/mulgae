package ports

import "fmt"

const (
	// PublicationStructuredMemberMaxBytes bounds manifests and other structured control members.
	// Provider-authored role reports are explicitly exempt and have no fixed size ceiling.
	PublicationStructuredMemberMaxBytes int64 = 8 << 20
	// PublicationStoreMaxReadBytes bounds fixed-size store reads and exceeds every structured member.
	PublicationStoreMaxReadBytes int64 = 32 << 20
)

// ValidateResourceLimits proves that capture admission, provider views,
// publication members, and fixed-size storage reads are mutually compatible.
func ValidateResourceLimits() error {
	if PublicationStructuredMemberMaxBytes <= 0 ||
		PublicationStoreMaxReadBytes < PublicationStructuredMemberMaxBytes {
		return fmt.Errorf("resource limits are incompatible")
	}
	return nil
}
