package ports

import (
	"context"
	"fmt"
	"io"
	"reflect"
)

// ContentIdentity is the immutable integrity identity of file-backed content.
// ByteLength is descriptive, not a product admission limit.
type ContentIdentity struct {
	sha256     string
	byteLength int64
	mediaType  string
}

// NewContentIdentity validates an immutable content identity.
func NewContentIdentity(sha256 string, byteLength int64, mediaType string) (ContentIdentity, error) {
	if err := validateSHA256(sha256); err != nil {
		return ContentIdentity{}, fmt.Errorf("content identity: %w", err)
	}
	if byteLength < 0 {
		return ContentIdentity{}, fmt.Errorf("content identity: byte length must not be negative")
	}
	if err := validateMediaType(mediaType); err != nil {
		return ContentIdentity{}, fmt.Errorf("content identity: media type: %w", err)
	}
	return ContentIdentity{sha256: sha256, byteLength: byteLength, mediaType: mediaType}, nil
}

// SHA256 returns the canonical sha256:<lowercase-hex> integrity identifier.
func (identity ContentIdentity) SHA256() string { return identity.sha256 }

// ByteLength returns the exact content byte length.
func (identity ContentIdentity) ByteLength() int64 { return identity.byteLength }

// MediaType returns the admitted media type.
func (identity ContentIdentity) MediaType() string { return identity.mediaType }

// Valid reports whether identity is complete and canonical.
func (identity ContentIdentity) Valid() bool {
	_, err := NewContentIdentity(identity.sha256, identity.byteLength, identity.mediaType)
	return err == nil
}

// ContentArtifact is immutable content that can be reopened without exposing a
// native path through application boundaries.
type ContentArtifact interface {
	Identity() ContentIdentity
	Open(context.Context) (io.ReadCloser, error)
}

// ContentLease owns temporary content and must be closed after all readers have
// been closed. Close must not remove a path whose identity has drifted.
type ContentLease interface {
	ContentArtifact
	Close() error
}

// ContentSpoolRequest describes one unbounded stream that must become an
// immutable, reopenable artifact.
type ContentSpoolRequest struct {
	source    io.Reader
	mediaType string
}

// NewContentSpoolRequest validates a file-backed spool request.
func NewContentSpoolRequest(source io.Reader, mediaType string) (ContentSpoolRequest, error) {
	if isNilReader(source) {
		return ContentSpoolRequest{}, fmt.Errorf("content spool request: source must be non-nil")
	}
	if err := validateMediaType(mediaType); err != nil {
		return ContentSpoolRequest{}, fmt.Errorf("content spool request: media type: %w", err)
	}
	return ContentSpoolRequest{source: source, mediaType: mediaType}, nil
}

// Source returns the one-shot stream consumed by ContentSpooler.
func (request ContentSpoolRequest) Source() io.Reader { return request.source }

// MediaType returns the content media type.
func (request ContentSpoolRequest) MediaType() string { return request.mediaType }

// ContentSpooler writes a stream to private temporary storage through EOF.
type ContentSpooler interface {
	Spool(context.Context, ContentSpoolRequest) (ContentLease, error)
}

// ContentInstallRequest installs an exact artifact beneath an approved root.
type ContentInstallRequest struct {
	root        AnchoredRoot
	destination SafeRelativePath
	channel     string
	artifact    ContentArtifact
	identity    ContentIdentity
	sourceIDs   []string
}

// NewContentInstallRequest validates an exact artifact install request.
func NewContentInstallRequest(
	root AnchoredRoot,
	destination SafeRelativePath,
	channel string,
	artifact ContentArtifact,
	sourceIDs []string,
) (ContentInstallRequest, error) {
	if !root.Valid() {
		return ContentInstallRequest{}, fmt.Errorf("content install request: invalid root")
	}
	if !destination.Valid() {
		return ContentInstallRequest{}, fmt.Errorf("content install request: invalid destination")
	}
	if err := validateAuditToken(channel, 128); err != nil {
		return ContentInstallRequest{}, fmt.Errorf("content install request: channel must be non-empty and safe")
	}
	if isNilContentArtifact(artifact) {
		return ContentInstallRequest{}, fmt.Errorf("content install request: invalid artifact")
	}
	identity := artifact.Identity()
	if !identity.Valid() {
		return ContentInstallRequest{}, fmt.Errorf("content install request: invalid artifact")
	}
	if err := validateSourceIDs(sourceIDs); err != nil {
		return ContentInstallRequest{}, fmt.Errorf("content install request: %w", err)
	}
	return ContentInstallRequest{
		root: root, destination: destination, channel: channel,
		artifact: artifact, identity: identity, sourceIDs: cloneStrings(sourceIDs),
	}, nil
}

// Root returns the approved destination root.
func (request ContentInstallRequest) Root() AnchoredRoot { return request.root }

// Destination returns the canonical destination beneath Root.
func (request ContentInstallRequest) Destination() SafeRelativePath { return request.destination }

// Channel returns the audited content channel.
func (request ContentInstallRequest) Channel() string { return request.channel }

// Artifact returns the immutable content source.
func (request ContentInstallRequest) Artifact() ContentArtifact { return request.artifact }

// Identity returns the artifact identity bound when the request was admitted.
func (request ContentInstallRequest) Identity() ContentIdentity { return request.identity }

// SourceIDs returns a caller-owned copy of redacted source identifiers.
func (request ContentInstallRequest) SourceIDs() []string { return cloneStrings(request.sourceIDs) }

// ContentInstaller atomically installs an artifact only when its streamed bytes
// match the declared identity exactly.
type ContentInstaller interface {
	InstallContent(context.Context, ContentInstallRequest) (SecureWriteReceipt, error)
}

func isNilContentArtifact(artifact ContentArtifact) bool {
	if artifact == nil {
		return true
	}
	value := reflect.ValueOf(artifact)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}
