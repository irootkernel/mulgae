package ports

import "fmt"

const (
	// ReviewTargetMaxBytes bounds patch/stdin/diff framing carried in prompts.
	ReviewTargetMaxBytes = 180_000

	// WorkspaceSnapshotMaxFiles bounds one captured source tree.
	WorkspaceSnapshotMaxFiles = 10_000
	// WorkspaceSnapshotMaxBytes bounds the total bytes in one captured source tree.
	WorkspaceSnapshotMaxBytes int64 = 64 << 20
	// WorkspaceSnapshotMaxFileBytes bounds one captured source file and therefore one source blob.
	WorkspaceSnapshotMaxFileBytes int64 = 4 << 20

	// WorkspaceProviderViewMaxFiles admits both sides of one maximum Git comparison.
	WorkspaceProviderViewMaxFiles = 2 * WorkspaceSnapshotMaxFiles
	// WorkspaceProviderViewMaxBytes admits both sides of one maximum Git comparison.
	WorkspaceProviderViewMaxBytes int64 = 2 * WorkspaceSnapshotMaxBytes

	// PublicationStructuredMemberMaxBytes bounds manifests and other structured control members.
	// Provider-authored role reports are explicitly exempt and have no fixed size ceiling.
	PublicationStructuredMemberMaxBytes int64 = 8 << 20
	// CapturedReviewManifestMaxBytes guarantees the reference manifest fits publication admission.
	CapturedReviewManifestMaxBytes int64 = PublicationStructuredMemberMaxBytes
	// PublicationStoreMaxReadBytes bounds fixed-size store reads and exceeds every structured member.
	PublicationStoreMaxReadBytes int64 = 32 << 20
)

// ValidateResourceLimits proves that capture admission, provider views,
// publication members, and fixed-size storage reads are mutually compatible.
func ValidateResourceLimits() error {
	if ReviewTargetMaxBytes <= 0 || WorkspaceSnapshotMaxFiles <= 0 || WorkspaceSnapshotMaxBytes <= 0 ||
		WorkspaceSnapshotMaxFileBytes <= 0 || WorkspaceProviderViewMaxFiles < 2*WorkspaceSnapshotMaxFiles ||
		WorkspaceProviderViewMaxBytes < 2*WorkspaceSnapshotMaxBytes || PublicationStructuredMemberMaxBytes <= 0 ||
		CapturedReviewManifestMaxBytes <= 0 || CapturedReviewManifestMaxBytes > PublicationStructuredMemberMaxBytes ||
		WorkspaceSnapshotMaxFileBytes > PublicationStructuredMemberMaxBytes ||
		ReviewTargetMaxBytes > PublicationStructuredMemberMaxBytes || PublicationStoreMaxReadBytes < PublicationStructuredMemberMaxBytes {
		return fmt.Errorf("resource limits are incompatible")
	}
	return nil
}
