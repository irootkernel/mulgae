package ports

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"path"
	"path/filepath"
	"reflect"
	"strings"
	"unicode"
	"unicode/utf8"
)

// AssetID is the stable, opaque identifier of a built-in contract asset.
type AssetID struct{ value string }

// ParseAssetID validates a stable contract asset identifier.
func ParseAssetID(value string) (AssetID, error) {
	if err := validateAssetID(value); err != nil {
		return AssetID{}, fmt.Errorf("asset ID: %w", err)
	}
	return AssetID{value: value}, nil
}

// String returns the canonical asset identifier.
func (id AssetID) String() string { return id.value }

// Valid reports whether id is a valid stable asset identifier.
func (id AssetID) Valid() bool { return validateAssetID(id.value) == nil }

// AssetKind classifies a contract asset by the consumer-facing surface it serves.
type AssetKind string

const (
	AssetKindSOT      AssetKind = "sot"
	AssetKindSchema   AssetKind = "schema"
	AssetKindExample  AssetKind = "example"
	AssetKindHelp     AssetKind = "help"
	AssetKindDefaults AssetKind = "defaults"
)

// Valid reports whether kind is a known contract asset kind.
func (kind AssetKind) Valid() bool {
	switch kind {
	case AssetKindSOT, AssetKindSchema, AssetKindExample, AssetKindHelp, AssetKindDefaults:
		return true
	default:
		return false
	}
}

// AssetMetadata is the immutable identity, source, media type, and integrity
// metadata of one catalog asset.
type AssetMetadata struct {
	id         AssetID
	kind       AssetKind
	source     SafeRelativePath
	mediaType  string
	sha256     string
	byteLength int64
}

// NewAssetMetadata validates immutable asset metadata.
func NewAssetMetadata(id AssetID, kind AssetKind, source SafeRelativePath, mediaType, sha256 string, byteLength int64) (AssetMetadata, error) {
	if !id.Valid() {
		return AssetMetadata{}, fmt.Errorf("asset metadata: invalid asset ID")
	}
	if !kind.Valid() {
		return AssetMetadata{}, fmt.Errorf("asset metadata: unknown asset kind %q", kind)
	}
	if !source.Valid() {
		return AssetMetadata{}, fmt.Errorf("asset metadata: invalid source")
	}
	if err := validateMediaType(mediaType); err != nil {
		return AssetMetadata{}, fmt.Errorf("asset metadata: media type: %w", err)
	}
	if err := validateSHA256(sha256); err != nil {
		return AssetMetadata{}, fmt.Errorf("asset metadata: %w", err)
	}
	if byteLength < 0 {
		return AssetMetadata{}, fmt.Errorf("asset metadata: byte length must not be negative")
	}
	return AssetMetadata{
		id:         id,
		kind:       kind,
		source:     source,
		mediaType:  mediaType,
		sha256:     sha256,
		byteLength: byteLength,
	}, nil
}

// ID returns the stable asset identifier.
func (metadata AssetMetadata) ID() AssetID { return metadata.id }

// Kind returns the asset kind.
func (metadata AssetMetadata) Kind() AssetKind { return metadata.kind }

// Source returns the canonical contract-relative asset source path.
func (metadata AssetMetadata) Source() SafeRelativePath { return metadata.source }

// MediaType returns the canonical media type of the asset bytes.
func (metadata AssetMetadata) MediaType() string { return metadata.mediaType }

// SHA256 returns the canonical sha256:<lowercase-hex> integrity identifier.
func (metadata AssetMetadata) SHA256() string { return metadata.sha256 }

// ByteLength returns the exact asset byte length.
func (metadata AssetMetadata) ByteLength() int64 { return metadata.byteLength }

// ContractCatalog reads contract assets. Read must return newly allocated bytes
// owned by the caller. List must return every asset exactly once in ascending
// AssetID.String() order; callers must not infer order from map iteration.
// The List slice is newly allocated and caller-owned.
type ContractCatalog interface {
	Read(context.Context, AssetID) (AssetMetadata, []byte, error)
	List(context.Context) ([]AssetMetadata, error)
}

// AnchoredRoot is a canonical absolute filesystem root approved by a caller.
type AnchoredRoot struct{ value string }

// NewAnchoredRoot validates an absolute, canonical root. It deliberately
// rejects backslashes so the portable port contract has one separator syntax.
func NewAnchoredRoot(value string) (AnchoredRoot, error) {
	if err := validateAnchoredRoot(value); err != nil {
		return AnchoredRoot{}, fmt.Errorf("anchored root: %w", err)
	}
	return AnchoredRoot{value: value}, nil
}

// String returns the canonical absolute root.
func (root AnchoredRoot) String() string { return root.value }

// Valid reports whether root is an absolute canonical root.
func (root AnchoredRoot) Valid() bool { return validateAnchoredRoot(root.value) == nil }

// SafeRelativePath is a canonical, non-empty path beneath an AnchoredRoot.
type SafeRelativePath struct{ value string }

// NewSafeRelativePath validates a portable relative path that cannot traverse
// or use an alternate separator.
func NewSafeRelativePath(value string) (SafeRelativePath, error) {
	if err := validateSafeRelativePath(value); err != nil {
		return SafeRelativePath{}, fmt.Errorf("safe relative path: %w", err)
	}
	return SafeRelativePath{value: value}, nil
}

// String returns the canonical relative path.
func (relative SafeRelativePath) String() string { return relative.value }

// Valid reports whether relative is a canonical, traversal-free relative path.
func (relative SafeRelativePath) Valid() bool { return validateSafeRelativePath(relative.value) == nil }

// SecureWriteRequest streams untrusted bytes through the mandatory
// scan-before-write boundary. SourceIDs returns a defensive copy.
type SecureWriteRequest struct {
	root        AnchoredRoot
	destination SafeRelativePath
	channel     string
	source      io.Reader
	maxBytes    int64
	sourceIDs   []string
	abort       func(error)
}

// NewSecureWriteRequest validates a streaming secure write request. Source is
// consumed by SecureFileWriter, MaxBytes is an exact positive cap, and Abort
// must terminate the producer when scanning rejects or overflows the stream.
func NewSecureWriteRequest(
	root AnchoredRoot,
	destination SafeRelativePath,
	channel string,
	source io.Reader,
	maxBytes int64,
	sourceIDs []string,
	abort func(error),
) (SecureWriteRequest, error) {
	if !root.Valid() {
		return SecureWriteRequest{}, fmt.Errorf("secure write request: invalid root")
	}
	if !destination.Valid() {
		return SecureWriteRequest{}, fmt.Errorf("secure write request: invalid destination")
	}
	if err := validateAuditToken(channel, 128); err != nil {
		return SecureWriteRequest{}, fmt.Errorf("secure write request: channel must be non-empty and safe")
	}
	if isNilReader(source) {
		return SecureWriteRequest{}, fmt.Errorf("secure write request: source must be non-nil")
	}
	if maxBytes <= 0 {
		return SecureWriteRequest{}, fmt.Errorf("secure write request: max bytes must be positive")
	}
	if err := validateSourceIDs(sourceIDs); err != nil {
		return SecureWriteRequest{}, fmt.Errorf("secure write request: %w", err)
	}
	if abort == nil {
		return SecureWriteRequest{}, fmt.Errorf("secure write request: abort must be non-nil")
	}
	return SecureWriteRequest{
		root:        root,
		destination: destination,
		channel:     channel,
		source:      source,
		maxBytes:    maxBytes,
		sourceIDs:   cloneStrings(sourceIDs),
		abort:       abort,
	}, nil
}

// Root returns the approved destination root.
func (request SecureWriteRequest) Root() AnchoredRoot { return request.root }

// Destination returns the canonical destination beneath Root.
func (request SecureWriteRequest) Destination() SafeRelativePath { return request.destination }

// Channel returns the audited untrusted-byte channel name.
func (request SecureWriteRequest) Channel() string { return request.channel }

// Source returns the one-shot untrusted input stream owned by SecureFileWriter.
func (request SecureWriteRequest) Source() io.Reader { return request.source }

// MaxBytes returns the exact positive scan and persistence cap.
func (request SecureWriteRequest) MaxBytes() int64 { return request.maxBytes }

// SourceIDs returns a caller-owned copy of redacted source identifiers.
func (request SecureWriteRequest) SourceIDs() []string { return cloneStrings(request.sourceIDs) }

// Abort returns the producer-cancellation function used on scan rejection.
func (request SecureWriteRequest) Abort() func(error) { return request.abort }

// SecureWriteReceipt records a completed accepted write, its exact approved root,
// and its exact input lineage. A writer must not return a receipt for bytes it
// dropped or rejected.
type SecureWriteReceipt struct {
	root        AnchoredRoot
	destination SafeRelativePath
	sha256      string
	byteLength  int64
	channel     string
	sourceIDs   []string
}

// NewSecureWriteReceipt validates a completed accepted write receipt bound to an
// exact approved root and retains a defensive copy of its non-empty source IDs.
func NewSecureWriteReceipt(root AnchoredRoot, destination SafeRelativePath, sha256 string, byteLength int64, channel string, sourceIDs []string) (SecureWriteReceipt, error) {
	if !root.Valid() {
		return SecureWriteReceipt{}, fmt.Errorf("secure write receipt: invalid root")
	}
	if !destination.Valid() {
		return SecureWriteReceipt{}, fmt.Errorf("secure write receipt: invalid destination")
	}
	if err := validateSHA256(sha256); err != nil {
		return SecureWriteReceipt{}, fmt.Errorf("secure write receipt: %w", err)
	}
	if byteLength < 0 {
		return SecureWriteReceipt{}, fmt.Errorf("secure write receipt: byte length must not be negative")
	}
	if err := validateAuditToken(channel, 128); err != nil {
		return SecureWriteReceipt{}, fmt.Errorf("secure write receipt: channel must be non-empty and safe")
	}
	if err := validateSourceIDs(sourceIDs); err != nil {
		return SecureWriteReceipt{}, fmt.Errorf("secure write receipt: %w", err)
	}
	return SecureWriteReceipt{
		root:        root,
		destination: destination,
		sha256:      sha256,
		byteLength:  byteLength,
		channel:     channel,
		sourceIDs:   cloneStrings(sourceIDs),
	}, nil
}

// Root returns the exact approved root for the accepted destination.
func (receipt SecureWriteReceipt) Root() AnchoredRoot { return receipt.root }

// Destination returns the accepted destination beneath the request root.
func (receipt SecureWriteReceipt) Destination() SafeRelativePath { return receipt.destination }

// SHA256 returns the accepted byte integrity identifier.
func (receipt SecureWriteReceipt) SHA256() string { return receipt.sha256 }

// ByteLength returns the number of accepted bytes.
func (receipt SecureWriteReceipt) ByteLength() int64 { return receipt.byteLength }

// Channel returns the exact audited channel that supplied the accepted bytes.
func (receipt SecureWriteReceipt) Channel() string { return receipt.channel }

// SourceIDs returns a caller-owned copy of the accepted bytes' source IDs.
func (receipt SecureWriteReceipt) SourceIDs() []string { return cloneStrings(receipt.sourceIDs) }

// DropMetadata is the redacted record of a rejected untrusted-byte channel. It
// intentionally cannot hold source bytes, excerpts, or hashes of blocked bytes.
type DropMetadata struct {
	channel   string
	detector  string
	count     int
	sourceIDs []string
}

// NewDropMetadata validates redacted metadata for a rejected write.
func NewDropMetadata(channel, detector string, count int, sourceIDs []string) (DropMetadata, error) {
	if err := validateAuditToken(channel, 128); err != nil {
		return DropMetadata{}, fmt.Errorf("drop metadata: channel must be non-empty and safe")
	}
	if err := validateAuditToken(detector, 128); err != nil {
		return DropMetadata{}, fmt.Errorf("drop metadata: detector must be non-empty and safe")
	}
	if count <= 0 {
		return DropMetadata{}, fmt.Errorf("drop metadata: count must be positive")
	}
	if err := validateSourceIDs(sourceIDs); err != nil {
		return DropMetadata{}, fmt.Errorf("drop metadata: %w", err)
	}
	return DropMetadata{
		channel:   channel,
		detector:  detector,
		count:     count,
		sourceIDs: cloneStrings(sourceIDs),
	}, nil
}

// Channel returns the rejected byte channel.
func (metadata DropMetadata) Channel() string { return metadata.channel }

// Detector returns the detector name, never detector input or matched bytes.
func (metadata DropMetadata) Detector() string { return metadata.detector }

// Count returns the number of detections recorded by the detector.
func (metadata DropMetadata) Count() int { return metadata.count }

// SourceIDs returns a caller-owned copy of redacted source identifiers.
func (metadata DropMetadata) SourceIDs() []string { return cloneStrings(metadata.sourceIDs) }

// SecureFileWriter is the mandatory scan-before-write boundary for untrusted
// bytes. EnsurePrivateDir creates only canonical directories beneath root and
// fails when a newly created parent directory cannot be synced before descent.
// Write fsyncs accepted bytes before atomically creating a destination once and
// never replaces an existing destination. It fsyncs the containing directory
// after installation; a post-install sync failure returns the installed receipt
// with a non-nil error. Receipts bind only accepted bytes to the request root,
// destination, channel, and source IDs. On a scan rejection or cap overflow it
// returns no receipt, redacted drop metadata, and a non-nil error.
type SecureFileWriter interface {
	EnsurePrivateDir(AnchoredRoot, SafeRelativePath) error
	Write(context.Context, SecureWriteRequest) (SecureWriteReceipt, *DropMetadata, error)
}

// GitObjectID is a canonical SHA-1 or SHA-256 Git object identifier.
type GitObjectID struct{ value string }

// ParseGitObjectID validates a lowercase 40- or 64-hex Git object identifier.
func ParseGitObjectID(value string) (GitObjectID, error) {
	if err := validateGitObjectID(value); err != nil {
		return GitObjectID{}, fmt.Errorf("Git object ID: %w", err)
	}
	return GitObjectID{value: value}, nil
}

// String returns the canonical Git object identifier.
func (id GitObjectID) String() string { return id.value }

// Valid reports whether id is a canonical Git object identifier.
func (id GitObjectID) Valid() bool { return validateGitObjectID(id.value) == nil }

// GitCaptureRequest selects a Git target before symbolic references are
// resolved. The resulting CapturedGitTarget, not these references, is the
// immutable target identity.
type GitCaptureRequest struct {
	projectRoot      AnchoredRoot
	baseReference    string
	headReference    string
	includeUntracked bool
}

// NewGitCaptureRequest validates a Git target selection. Both references are
// required so a capture request has an explicit comparison basis.
func NewGitCaptureRequest(projectRoot AnchoredRoot, baseReference, headReference string, includeUntracked bool) (GitCaptureRequest, error) {
	if !projectRoot.Valid() {
		return GitCaptureRequest{}, fmt.Errorf("Git capture request: invalid project root")
	}
	if err := validateGitReference(baseReference); err != nil {
		return GitCaptureRequest{}, fmt.Errorf("Git capture request: invalid base reference: %w", err)
	}
	if err := validateGitReference(headReference); err != nil {
		return GitCaptureRequest{}, fmt.Errorf("Git capture request: invalid head reference: %w", err)
	}
	return GitCaptureRequest{
		projectRoot:      projectRoot,
		baseReference:    baseReference,
		headReference:    headReference,
		includeUntracked: includeUntracked,
	}, nil
}

// ProjectRoot returns the approved project root.
func (request GitCaptureRequest) ProjectRoot() AnchoredRoot { return request.projectRoot }

// BaseReference returns the requested base revision before resolution.
func (request GitCaptureRequest) BaseReference() string { return request.baseReference }

// HeadReference returns the requested head revision before resolution.
func (request GitCaptureRequest) HeadReference() string { return request.headReference }

// IncludeUntracked reports whether the capture must include an untracked manifest.
func (request GitCaptureRequest) IncludeUntracked() bool { return request.includeUntracked }

// CapturedGitTarget is the immutable Git target identity and its canonical
// captured bytes. Bytes returns a defensive copy.
type CapturedGitTarget struct {
	repositoryID string
	baseObjectID GitObjectID
	headObjectID GitObjectID
	headTreeID   GitObjectID
	indexTreeID  *GitObjectID
	sha256       string
	bytes        []byte
}

// NewCapturedGitTarget validates resolved Git identity and takes ownership of
// the canonical captured target bytes. indexTreeID is nil when no index tree
// applies to the selected target mode.
func NewCapturedGitTarget(repositoryID string, baseObjectID, headObjectID, headTreeID GitObjectID, indexTreeID *GitObjectID, bytes []byte) (CapturedGitTarget, error) {
	if err := validateRedactedText(repositoryID, 4096); err != nil || repositoryID == "" {
		return CapturedGitTarget{}, fmt.Errorf("captured Git target: repository ID must be non-empty and safe")
	}
	if !baseObjectID.Valid() || !headObjectID.Valid() || !headTreeID.Valid() {
		return CapturedGitTarget{}, fmt.Errorf("captured Git target: base, head, and head tree object IDs are required")
	}
	if indexTreeID != nil && !indexTreeID.Valid() {
		return CapturedGitTarget{}, fmt.Errorf("captured Git target: invalid index tree object ID")
	}

	target := CapturedGitTarget{
		repositoryID: repositoryID,
		baseObjectID: baseObjectID,
		headObjectID: headObjectID,
		headTreeID:   headTreeID,
		sha256:       sha256Identifier(bytes),
		bytes:        cloneBytes(bytes),
	}
	if indexTreeID != nil {
		indexTreeCopy := *indexTreeID
		target.indexTreeID = &indexTreeCopy
	}
	return target, nil
}

// RepositoryID returns the stable repository identity recorded at capture.
func (target CapturedGitTarget) RepositoryID() string { return target.repositoryID }

// BaseObjectID returns the resolved base object identifier.
func (target CapturedGitTarget) BaseObjectID() GitObjectID { return target.baseObjectID }

// HeadObjectID returns the resolved head object identifier.
func (target CapturedGitTarget) HeadObjectID() GitObjectID { return target.headObjectID }

// HeadTreeID returns the resolved head tree object identifier.
func (target CapturedGitTarget) HeadTreeID() GitObjectID { return target.headTreeID }

// IndexTreeID returns the optional resolved index tree object identifier.
func (target CapturedGitTarget) IndexTreeID() (GitObjectID, bool) {
	if target.indexTreeID == nil {
		return GitObjectID{}, false
	}
	return *target.indexTreeID, true
}

// SHA256 returns the canonical target-byte integrity identifier.
func (target CapturedGitTarget) SHA256() string { return target.sha256 }

// Bytes returns a caller-owned copy of the canonical captured target bytes.
func (target CapturedGitTarget) Bytes() []byte { return cloneBytes(target.bytes) }

// TrustedProjectReader binds project configuration reads to a resolved immutable
// commit. ReadFileAtCommit must return newly allocated bytes owned by the caller.
type TrustedProjectReader interface {
	ResolveCommit(context.Context, AnchoredRoot, string) (GitObjectID, error)
	ReadFileAtCommit(context.Context, AnchoredRoot, GitObjectID, SafeRelativePath) ([]byte, error)
}

// GitTargetCapture resolves revisions and captures immutable Git target bytes.
type GitTargetCapture interface {
	Capture(context.Context, GitCaptureRequest) (CapturedGitTarget, error)
}

// PlatformObservation describes the platform observed by a readiness check.
type PlatformObservation struct {
	operatingSystem string
	architecture    string
}

// NewPlatformObservation validates one observed operating system and architecture.
func NewPlatformObservation(operatingSystem, architecture string) (PlatformObservation, error) {
	if err := validateRedactedText(operatingSystem, 128); err != nil || operatingSystem == "" {
		return PlatformObservation{}, fmt.Errorf("platform observation: operating system must be non-empty and safe")
	}
	if err := validateRedactedText(architecture, 128); err != nil || architecture == "" {
		return PlatformObservation{}, fmt.Errorf("platform observation: architecture must be non-empty and safe")
	}
	return PlatformObservation{operatingSystem: operatingSystem, architecture: architecture}, nil
}

// OperatingSystem returns the observed operating system name.
func (observation PlatformObservation) OperatingSystem() string { return observation.operatingSystem }

// Architecture returns the observed architecture name.
func (observation PlatformObservation) Architecture() string { return observation.architecture }

// ExecutableObservation describes one readiness executable lookup. An absent
// executable is represented by Found false rather than an invented substitute.
type ExecutableObservation struct {
	name         string
	found        bool
	resolvedPath string
	version      string
	sha256       string
}

// NewExecutableObservation validates one executable observation. A found
// executable must have an absolute canonical resolved path; an absent one must
// not claim path, version, or hash provenance.
func NewExecutableObservation(name string, found bool, resolvedPath, version, sha256 string) (ExecutableObservation, error) {
	if err := validateRedactedText(name, 256); err != nil || name == "" {
		return ExecutableObservation{}, fmt.Errorf("executable observation: name must be non-empty and safe")
	}
	if !found {
		if resolvedPath != "" || version != "" || sha256 != "" {
			return ExecutableObservation{}, fmt.Errorf("executable observation: absent executable has provenance")
		}
		return ExecutableObservation{name: name}, nil
	}
	if err := validateAnchoredRoot(resolvedPath); err != nil {
		return ExecutableObservation{}, fmt.Errorf("executable observation: resolved path: %w", err)
	}
	if err := validateRedactedText(version, 1024); err != nil {
		return ExecutableObservation{}, fmt.Errorf("executable observation: version: %w", err)
	}
	if sha256 != "" {
		if err := validateSHA256(sha256); err != nil {
			return ExecutableObservation{}, fmt.Errorf("executable observation: %w", err)
		}
	}
	return ExecutableObservation{
		name:         name,
		found:        true,
		resolvedPath: resolvedPath,
		version:      version,
		sha256:       sha256,
	}, nil
}

// Name returns the executable lookup name.
func (observation ExecutableObservation) Name() string { return observation.name }

// Found reports whether an executable was resolved without substitution.
func (observation ExecutableObservation) Found() bool { return observation.found }

// ResolvedPath returns the canonical resolved executable path, if Found.
func (observation ExecutableObservation) ResolvedPath() string { return observation.resolvedPath }

// Version returns the observed version string, if recorded.
func (observation ExecutableObservation) Version() string { return observation.version }

// SHA256 returns the optional executable provenance hash.
func (observation ExecutableObservation) SHA256() string { return observation.sha256 }

// FileIdentityObservation describes one identity-only readable file lookup.
// A found file has a canonical absolute path and optional content hash, but no
// executable or version semantics.
type FileIdentityObservation struct {
	name         string
	found        bool
	resolvedPath string
	sha256       string
}

// NewFileIdentityObservation validates one readable file identity observation.
func NewFileIdentityObservation(name string, found bool, resolvedPath, sha256 string) (FileIdentityObservation, error) {
	if err := validateRedactedText(name, 256); err != nil || name == "" {
		return FileIdentityObservation{}, fmt.Errorf("file identity observation: name must be non-empty and safe")
	}
	if !found {
		if resolvedPath != "" || sha256 != "" {
			return FileIdentityObservation{}, fmt.Errorf("file identity observation: absent file has provenance")
		}
		return FileIdentityObservation{name: name}, nil
	}
	if err := validateAnchoredRoot(resolvedPath); err != nil {
		return FileIdentityObservation{}, fmt.Errorf("file identity observation: resolved path: %w", err)
	}
	if sha256 != "" {
		if err := validateSHA256(sha256); err != nil {
			return FileIdentityObservation{}, fmt.Errorf("file identity observation: %w", err)
		}
	}
	return FileIdentityObservation{name: name, found: true, resolvedPath: resolvedPath, sha256: sha256}, nil
}

func (observation FileIdentityObservation) Name() string         { return observation.name }
func (observation FileIdentityObservation) Found() bool          { return observation.found }
func (observation FileIdentityObservation) ResolvedPath() string { return observation.resolvedPath }
func (observation FileIdentityObservation) SHA256() string       { return observation.sha256 }

// IdentityObservationFailureKind classifies failures that are safe for
// provider-family scoped admission handling. Unknown failures remain ordinary
// errors and must not be downgraded by callers.
type IdentityObservationFailureKind string

const (
	IdentityObservationUnavailable IdentityObservationFailureKind = "unavailable"
	IdentityObservationSecurity    IdentityObservationFailureKind = "security"
)

// IdentityObservationError is a redacted, typed identity-observation failure.
type IdentityObservationError struct {
	kind IdentityObservationFailureKind
	text string
}

// NewIdentityObservationError constructs a redacted classified failure.
func NewIdentityObservationError(kind IdentityObservationFailureKind, text string) error {
	if kind != IdentityObservationUnavailable && kind != IdentityObservationSecurity {
		return fmt.Errorf("identity observation: invalid failure kind")
	}
	if err := validateRedactedText(text, 256); err != nil || text == "" {
		return fmt.Errorf("identity observation: invalid failure text")
	}
	return &IdentityObservationError{kind: kind, text: text}
}

func (failure *IdentityObservationError) Error() string {
	if failure == nil {
		return "identity observation failed"
	}
	return failure.text
}

// IdentityObservationFailure returns the classified failure kind when err is
// safe for family-scoped admission handling.
func IdentityObservationFailure(err error) (IdentityObservationFailureKind, bool) {
	var failure *IdentityObservationError
	if !errors.As(err, &failure) || failure == nil {
		return "", false
	}
	return failure.kind, true
}

// PermissionObservation records access bits for one approved relative path.
type PermissionObservation struct {
	path       SafeRelativePath
	readable   bool
	writable   bool
	executable bool
}

// NewPermissionObservation validates one permission observation.
func NewPermissionObservation(path SafeRelativePath, readable, writable, executable bool) (PermissionObservation, error) {
	if !path.Valid() {
		return PermissionObservation{}, fmt.Errorf("permission observation: invalid path")
	}
	return PermissionObservation{
		path:       path,
		readable:   readable,
		writable:   writable,
		executable: executable,
	}, nil
}

// Path returns the observed project-relative path.
func (observation PermissionObservation) Path() SafeRelativePath { return observation.path }

// Readable reports whether the path is readable by the inspected process.
func (observation PermissionObservation) Readable() bool { return observation.readable }

// Writable reports whether the path is writable by the inspected process.
func (observation PermissionObservation) Writable() bool { return observation.writable }

// Executable reports whether the path is executable by the inspected process.
func (observation PermissionObservation) Executable() bool { return observation.executable }

// EnvironmentInspector observes platform, executable, and permission readiness
// without importing operating-system or process implementations into the application.
type EnvironmentInspector interface {
	ObservePlatform(context.Context) (PlatformObservation, error)
	ObserveExecutable(context.Context, string) (ExecutableObservation, error)
	ObserveExecutableIdentity(context.Context, string) (ExecutableObservation, error)
	ObserveReadableFileIdentity(context.Context, string) (FileIdentityObservation, error)
	ObserveNativeHomeIdentity(context.Context, string) (NativeHomeLaunchAuthority, error)
	ObservePermission(context.Context, AnchoredRoot, SafeRelativePath) (PermissionObservation, error)
}

func validateAssetID(value string) error {
	if err := validateRedactedText(value, 512); err != nil {
		return err
	}
	if value == "" {
		return fmt.Errorf("must be non-empty")
	}
	if strings.TrimSpace(value) != value {
		return fmt.Errorf("must not have surrounding whitespace")
	}
	if strings.Contains(value, "\\") {
		return fmt.Errorf("must not contain a backslash")
	}
	return nil
}

func validateAnchoredRoot(value string) error {
	if value == "" {
		return fmt.Errorf("must be non-empty")
	}
	if strings.ContainsRune(value, 0) {
		return fmt.Errorf("must not contain NUL")
	}
	if strings.Contains(value, "\\") {
		return fmt.Errorf("must not contain a backslash")
	}
	if !filepath.IsAbs(value) {
		return fmt.Errorf("must be absolute")
	}
	if filepath.Clean(value) != value {
		return fmt.Errorf("must be canonical")
	}
	return nil
}

func validateSafeRelativePath(value string) error {
	if value == "" {
		return fmt.Errorf("must be non-empty")
	}
	if strings.ContainsRune(value, 0) {
		return fmt.Errorf("must not contain NUL")
	}
	if strings.Contains(value, "\\") {
		return fmt.Errorf("must not contain a backslash")
	}
	if path.IsAbs(value) || filepath.IsAbs(value) {
		return fmt.Errorf("must be relative")
	}
	if value == "." || value == ".." {
		return fmt.Errorf("must not be dot or dotdot")
	}
	if path.Clean(value) != value {
		return fmt.Errorf("must be canonical")
	}
	for _, component := range strings.Split(value, "/") {
		if component == "." || component == ".." {
			return fmt.Errorf("must not contain dot or dotdot components")
		}
	}
	return nil
}

func validateMediaType(value string) error {
	if value == "" || strings.Count(value, "/") != 1 {
		return fmt.Errorf("must contain one type/subtype separator")
	}
	typeAndSubtype := strings.SplitN(value, "/", 2)
	if !validMediaToken(typeAndSubtype[0]) || !validMediaToken(typeAndSubtype[1]) {
		return fmt.Errorf("must contain canonical media type tokens")
	}
	return nil
}

func validMediaToken(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' ||
			character >= '0' && character <= '9' ||
			strings.ContainsRune("!#$&^_.+-", character) {
			continue
		}
		return false
	}
	return true
}

func validateSHA256(value string) error {
	const prefix = "sha256:"
	if !strings.HasPrefix(value, prefix) || len(value) != len(prefix)+sha256.Size*2 {
		return fmt.Errorf("must be sha256: followed by 64 lowercase hexadecimal characters")
	}
	for _, character := range value[len(prefix):] {
		if !isLowerHex(character) {
			return fmt.Errorf("must be sha256: followed by 64 lowercase hexadecimal characters")
		}
	}
	return nil
}

func validateGitObjectID(value string) error {
	if len(value) != 40 && len(value) != 64 {
		return fmt.Errorf("must contain 40 or 64 lowercase hexadecimal characters")
	}
	for _, character := range value {
		if !isLowerHex(character) {
			return fmt.Errorf("must contain 40 or 64 lowercase hexadecimal characters")
		}
	}
	return nil
}

func validateGitReference(value string) error {
	if err := validateRedactedText(value, 4096); err != nil {
		return err
	}
	if value == "" {
		return fmt.Errorf("must be non-empty")
	}
	if strings.TrimSpace(value) != value || strings.Contains(value, "\\") {
		return fmt.Errorf("must be canonical and must not contain a backslash")
	}
	return nil
}

func validateRedactedText(value string, maximumLength int) error {
	if len(value) > maximumLength {
		return fmt.Errorf("must contain at most %d bytes", maximumLength)
	}
	if strings.ContainsAny(value, "\x00\r\n") {
		return fmt.Errorf("must not contain NUL or line breaks")
	}
	return nil
}
func validateAuditToken(value string, maximumLength int) error {
	if err := validateRedactedText(value, maximumLength); err != nil {
		return err
	}
	if !utf8.ValidString(value) || value == "" || strings.TrimSpace(value) != value {
		return fmt.Errorf("must be a non-empty canonical token")
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return fmt.Errorf("must not contain control characters")
		}
	}
	return nil
}

func validateSourceIDs(sourceIDs []string) error {
	if len(sourceIDs) == 0 {
		return fmt.Errorf("source IDs must be non-empty")
	}
	seen := make(map[string]struct{}, len(sourceIDs))
	for _, sourceID := range sourceIDs {
		if err := validateAuditToken(sourceID, 256); err != nil {
			return fmt.Errorf("source ID must be non-empty and safe")
		}
		if _, duplicate := seen[sourceID]; duplicate {
			return fmt.Errorf("duplicate source ID %q", sourceID)
		}
		seen[sourceID] = struct{}{}
	}
	return nil
}

func isNilReader(source io.Reader) bool {
	if source == nil {
		return true
	}
	value := reflect.ValueOf(source)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}
func isLowerHex(character rune) bool {
	return character >= '0' && character <= '9' || character >= 'a' && character <= 'f'
}

func sha256Identifier(bytes []byte) string {
	sum := sha256.Sum256(bytes)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func cloneBytes(value []byte) []byte {
	if value == nil {
		return nil
	}
	copyValue := make([]byte, len(value))
	copy(copyValue, value)
	return copyValue
}

func cloneStrings(value []string) []string {
	if value == nil {
		return nil
	}
	copyValue := make([]string, len(value))
	copy(copyValue, value)
	return copyValue
}
