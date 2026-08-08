package ports

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/irootkernel/mulgae/internal/domain"
)

const capturedReviewArchiveManifestVersion = "mulgae-captured-review-archive.v2"

const capturedReviewBundleMagic = "MULGAE-CAPTURE-BUNDLE-V2\n"

type capturedReviewArchiveManifestWire struct {
	SchemaVersion     string                     `json:"schema_version"`
	TargetIdentity    capturedTargetIdentityWire `json:"target_identity"`
	Target            capturedContentRefWire     `json:"target"`
	SnapshotPolicy    string                     `json:"snapshot_policy"`
	Snapshot          []capturedFileRefWire      `json:"snapshot"`
	ProjectContext    *capturedContentRefWire    `json:"project_context,omitempty"`
	HasProjectContext bool                       `json:"has_project_context"`
	Evidence          []capturedEvidenceRefWire  `json:"evidence"`
}

type capturedContentRefWire struct {
	SHA256 string `json:"sha256"`
	Blob   string `json:"blob"`
}

type capturedFileRefWire struct {
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
	Blob      string `json:"blob"`
	MediaType string `json:"media_type,omitempty"`
}

type capturedEvidenceRefWire struct {
	Side  string                `json:"side"`
	Files []capturedFileRefWire `json:"files"`
}

// CapturedReviewArchiveBlob is one content-addressed member of a captured
// review archive. Its path is local to the target directory.
type CapturedReviewArchiveBlob struct {
	path   SafeRelativePath
	sha256 string
	bytes  []byte
}

// NewCapturedReviewArchiveBlob validates the canonical blob name and its exact
// byte identity.
func NewCapturedReviewArchiveBlob(path SafeRelativePath, bytes []byte) (CapturedReviewArchiveBlob, error) {
	digest := sha256Identifier(bytes)
	blob := CapturedReviewArchiveBlob{path: path, sha256: digest, bytes: cloneBytes(bytes)}
	if !blob.Valid() {
		return CapturedReviewArchiveBlob{}, fmt.Errorf("captured review archive blob: invalid path or identity")
	}
	return blob, nil
}

func (blob CapturedReviewArchiveBlob) Path() SafeRelativePath { return blob.path }
func (blob CapturedReviewArchiveBlob) SHA256() string         { return blob.sha256 }
func (blob CapturedReviewArchiveBlob) Bytes() []byte          { return cloneBytes(blob.bytes) }
func (blob CapturedReviewArchiveBlob) Valid() bool {
	return blob.path.Valid() && blob.path.String() == capturedBlobPath(blob.sha256) &&
		blob.sha256 == sha256Identifier(blob.bytes)
}

// CapturedReviewArchiveBlobReference identifies one blob required by a v2
// capture manifest.
type CapturedReviewArchiveBlobReference struct {
	path   SafeRelativePath
	sha256 string
}

func (reference CapturedReviewArchiveBlobReference) Path() SafeRelativePath { return reference.path }
func (reference CapturedReviewArchiveBlobReference) SHA256() string         { return reference.sha256 }

// CapturedReviewArchive contains deterministic v2 manifest bytes and the
// unique content-addressed blobs referenced by them.
type CapturedReviewArchive struct {
	manifest []byte
	blobs    []CapturedReviewArchiveBlob
}

func (archive CapturedReviewArchive) Manifest() []byte { return cloneBytes(archive.manifest) }
func (archive CapturedReviewArchive) Blobs() []CapturedReviewArchiveBlob {
	result := make([]CapturedReviewArchiveBlob, len(archive.blobs))
	for index, blob := range archive.blobs {
		result[index] = CapturedReviewArchiveBlob{path: blob.path, sha256: blob.sha256, bytes: cloneBytes(blob.bytes)}
	}
	return result
}

// NewCapturedReviewArchive projects a capture into a reference-only manifest
// and deduplicated SHA-256 blobs.
func NewCapturedReviewArchive(material CapturedReviewMaterial) (CapturedReviewArchive, error) {
	if !material.Valid() {
		return CapturedReviewArchive{}, fmt.Errorf("captured review archive: invalid material")
	}
	blobs := make(map[string]CapturedReviewArchiveBlob)
	add := func(contents []byte) (capturedContentRefWire, error) {
		digest := sha256Identifier(contents)
		if len(contents) == 0 {
			return capturedContentRefWire{SHA256: digest}, nil
		}
		path, err := NewSafeRelativePath(capturedBlobPath(digest))
		if err != nil {
			return capturedContentRefWire{}, err
		}
		if existing, ok := blobs[path.String()]; ok {
			if !bytes.Equal(existing.bytes, contents) {
				return capturedContentRefWire{}, fmt.Errorf("captured review archive: SHA-256 collision")
			}
		} else {
			blob, blobErr := NewCapturedReviewArchiveBlob(path, contents)
			if blobErr != nil {
				return capturedContentRefWire{}, blobErr
			}
			blobs[path.String()] = blob
		}
		return capturedContentRefWire{SHA256: digest, Blob: path.String()}, nil
	}
	files := func(source []WorkspaceSnapshotFile) ([]capturedFileRefWire, error) {
		result := make([]capturedFileRefWire, len(source))
		for index, file := range source {
			ref, err := add(file.Bytes())
			if err != nil {
				return nil, err
			}
			if ref.SHA256 != file.SHA256() {
				return nil, fmt.Errorf("captured review archive: file identity mismatch")
			}
			result[index] = capturedFileRefWire{Path: file.Path().String(), SHA256: ref.SHA256, Blob: ref.Blob, MediaType: file.MediaType()}
		}
		return result, nil
	}

	identity := material.Target().Identity()
	target, err := add(material.Target().Bytes())
	if err != nil {
		return CapturedReviewArchive{}, err
	}
	snapshot, err := files(material.Snapshot().Files())
	if err != nil {
		return CapturedReviewArchive{}, err
	}
	wire := capturedReviewArchiveManifestWire{
		SchemaVersion: capturedReviewArchiveManifestVersion,
		TargetIdentity: capturedTargetIdentityWire{
			Kind: string(identity.Kind()), SHA256: identity.SHA256(), RepositoryID: identity.RepositoryID(),
			BaseObjectID: identity.BaseObjectID(), HeadObjectID: identity.HeadObjectID(),
			HeadTreeObjectID: identity.HeadTreeObjectID(), IndexTreeObjectID: identity.IndexTreeObjectID(), GitMode: string(identity.GitMode()),
		},
		Target: target, SnapshotPolicy: material.Snapshot().PolicyIdentity(), Snapshot: snapshot,
		HasProjectContext: material.HasProjectContext(),
	}
	if material.HasProjectContext() {
		contextRef, contextErr := add(material.ProjectContext())
		if contextErr != nil {
			return CapturedReviewArchive{}, contextErr
		}
		wire.ProjectContext = &contextRef
	}
	for _, side := range []CapturedEvidenceSide{CapturedEvidenceBase, CapturedEvidenceHead, CapturedEvidenceIndex, CapturedEvidenceWorktree} {
		if source, ok := material.Evidence().Files(side); ok {
			projected, projectErr := files(source)
			if projectErr != nil {
				return CapturedReviewArchive{}, projectErr
			}
			wire.Evidence = append(wire.Evidence, capturedEvidenceRefWire{Side: string(side), Files: projected})
		}
	}
	manifest, err := json.Marshal(wire)
	if err != nil {
		return CapturedReviewArchive{}, fmt.Errorf("captured review archive: encode manifest: %w", err)
	}
	if int64(len(manifest)) > CapturedReviewManifestMaxBytes {
		cause := fmt.Errorf("captured-review.json byte length %d exceeds limit %d", len(manifest), CapturedReviewManifestMaxBytes)
		failure, failureErr := NewReviewCaptureManifestFailure(int64(len(manifest)), CapturedReviewManifestMaxBytes, cause)
		if failureErr != nil {
			return CapturedReviewArchive{}, errors.Join(cause, failureErr)
		}
		return CapturedReviewArchive{}, failure
	}
	result := CapturedReviewArchive{manifest: manifest, blobs: make([]CapturedReviewArchiveBlob, 0, len(blobs))}
	for _, blob := range blobs {
		result.blobs = append(result.blobs, blob)
	}
	sort.Slice(result.blobs, func(i, j int) bool { return result.blobs[i].path.String() < result.blobs[j].path.String() })
	return result, nil
}

// CapturedReviewArchiveBlobReferences validates a persisted capture manifest
// and returns its unique blob inventory. Legacy v1 archives return no refs.
func CapturedReviewArchiveBlobReferences(manifest []byte) ([]CapturedReviewArchiveBlobReference, error) {
	version, err := capturedArchiveSchemaVersion(manifest)
	if err != nil {
		return nil, err
	}
	if version == "mulgae-captured-review-archive.v1" {
		if _, err := UnmarshalCapturedReviewMaterial(manifest); err != nil {
			return nil, err
		}
		return nil, nil
	}
	if version != capturedReviewArchiveManifestVersion {
		return nil, fmt.Errorf("captured review archive: unsupported schema version")
	}
	wire, err := decodeCapturedReviewManifest(manifest)
	if err != nil {
		return nil, err
	}
	refs, err := capturedManifestReferences(wire)
	if err != nil {
		return nil, err
	}
	return refs, nil
}

// CapturedReviewArchiveIsLegacy reports whether manifest is a validated v1
// single-file archive rather than a v2 reference manifest.
func CapturedReviewArchiveIsLegacy(manifest []byte) (bool, error) {
	version, err := capturedArchiveSchemaVersion(manifest)
	if err != nil {
		return false, err
	}
	switch version {
	case "mulgae-captured-review-archive.v1":
		if _, err := unmarshalCapturedReviewMaterialV1(manifest); err != nil {
			return false, err
		}
		return true, nil
	case capturedReviewArchiveManifestVersion:
		if _, err := decodeCapturedReviewManifest(manifest); err != nil {
			return false, err
		}
		return false, nil
	default:
		return false, fmt.Errorf("captured review archive: unsupported schema version")
	}
}

// RestoreCapturedReviewArchive validates a v1 archive or a v2 manifest and its
// exact blob set, then rebuilds constructor-owned capture values.
func RestoreCapturedReviewArchive(manifest []byte, blobs []CapturedReviewArchiveBlob) (CapturedReviewMaterial, error) {
	version, err := capturedArchiveSchemaVersion(manifest)
	if err != nil {
		return CapturedReviewMaterial{}, err
	}
	if version == "mulgae-captured-review-archive.v1" {
		if len(blobs) != 0 {
			return CapturedReviewMaterial{}, fmt.Errorf("captured review archive: legacy archive has unexpected blobs")
		}
		return UnmarshalCapturedReviewMaterial(manifest)
	}
	if version != capturedReviewArchiveManifestVersion {
		return CapturedReviewMaterial{}, fmt.Errorf("captured review archive: unsupported schema version")
	}
	wire, err := decodeCapturedReviewManifest(manifest)
	if err != nil {
		return CapturedReviewMaterial{}, err
	}
	references, err := capturedManifestReferences(wire)
	if err != nil {
		return CapturedReviewMaterial{}, err
	}
	contents := make(map[string][]byte, len(blobs))
	for _, blob := range blobs {
		if !blob.Valid() {
			return CapturedReviewMaterial{}, fmt.Errorf("captured review archive: invalid blob")
		}
		if _, duplicate := contents[blob.path.String()]; duplicate {
			return CapturedReviewMaterial{}, fmt.Errorf("captured review archive: duplicate blob")
		}
		contents[blob.path.String()] = blob.Bytes()
	}
	if len(contents) != len(references) {
		return CapturedReviewMaterial{}, fmt.Errorf("captured review archive: blob inventory mismatch")
	}
	for _, reference := range references {
		body, ok := contents[reference.path.String()]
		if !ok || sha256Identifier(body) != reference.sha256 {
			return CapturedReviewMaterial{}, fmt.Errorf("captured review archive: missing or mismatched blob %q", reference.path.String())
		}
	}
	resolve := func(ref capturedContentRefWire) ([]byte, error) {
		if ref.Blob == "" && ref.SHA256 == sha256Identifier(nil) {
			return []byte{}, nil
		}
		body, ok := contents[ref.Blob]
		if !ok || sha256Identifier(body) != ref.SHA256 {
			return nil, fmt.Errorf("captured review archive: unresolved content")
		}
		return cloneBytes(body), nil
	}

	identity, err := domain.NewTargetIdentity(domain.TargetIdentityInput{
		Kind: domain.TargetKind(wire.TargetIdentity.Kind), SHA256: wire.TargetIdentity.SHA256,
		RepositoryID: wire.TargetIdentity.RepositoryID, BaseObjectID: wire.TargetIdentity.BaseObjectID,
		HeadObjectID: wire.TargetIdentity.HeadObjectID, HeadTreeObjectID: wire.TargetIdentity.HeadTreeObjectID,
		IndexTreeObjectID: wire.TargetIdentity.IndexTreeObjectID, GitMode: domain.GitTargetMode(wire.TargetIdentity.GitMode),
	})
	if err != nil {
		return CapturedReviewMaterial{}, fmt.Errorf("captured review archive: target identity: %w", err)
	}
	targetBytes, err := resolve(wire.Target)
	if err != nil {
		return CapturedReviewMaterial{}, err
	}
	target, err := NewCapturedReviewTargetFromIdentity(identity, targetBytes)
	if err != nil {
		return CapturedReviewMaterial{}, fmt.Errorf("captured review archive: target: %w", err)
	}
	snapshotFiles, err := capturedRefsToFiles(wire.Snapshot, resolve)
	if err != nil {
		return CapturedReviewMaterial{}, err
	}
	snapshot, err := NewWorkspaceSnapshotRequest(snapshotFiles, wire.SnapshotPolicy)
	if err != nil {
		return CapturedReviewMaterial{}, fmt.Errorf("captured review archive: snapshot: %w", err)
	}
	sides := make(map[CapturedEvidenceSide][]WorkspaceSnapshotFile, len(wire.Evidence))
	for _, item := range wire.Evidence {
		side := CapturedEvidenceSide(item.Side)
		if !side.Valid() {
			return CapturedReviewMaterial{}, fmt.Errorf("captured review archive: invalid evidence side")
		}
		if _, duplicate := sides[side]; duplicate {
			return CapturedReviewMaterial{}, fmt.Errorf("captured review archive: duplicate evidence side")
		}
		files, fileErr := capturedRefsToFiles(item.Files, resolve)
		if fileErr != nil {
			return CapturedReviewMaterial{}, fileErr
		}
		sides[side] = files
	}
	var evidence CapturedTargetEvidence
	if len(sides) > 0 {
		evidence, err = NewCapturedTargetEvidence(sides)
		if err != nil {
			return CapturedReviewMaterial{}, fmt.Errorf("captured review archive: evidence: %w", err)
		}
	}
	var projectContext []byte
	if wire.HasProjectContext {
		if wire.ProjectContext == nil {
			return CapturedReviewMaterial{}, fmt.Errorf("captured review archive: project context reference is absent")
		}
		projectContext, err = resolve(*wire.ProjectContext)
		if err != nil {
			return CapturedReviewMaterial{}, err
		}
	} else if wire.ProjectContext != nil {
		return CapturedReviewMaterial{}, fmt.Errorf("captured review archive: unexpected project context reference")
	}
	return NewCapturedReviewMaterialWithEvidenceAndProjectContext(target, snapshot, projectContext, wire.HasProjectContext, evidence)
}

func capturedRefsToFiles(files []capturedFileRefWire, resolve func(capturedContentRefWire) ([]byte, error)) ([]WorkspaceSnapshotFile, error) {
	result := make([]WorkspaceSnapshotFile, len(files))
	for index, file := range files {
		path, err := NewSafeRelativePath(file.Path)
		if err != nil {
			return nil, fmt.Errorf("captured review archive: file path: %w", err)
		}
		body, err := resolve(capturedContentRefWire{SHA256: file.SHA256, Blob: file.Blob})
		if err != nil {
			return nil, err
		}
		if file.MediaType == "" || file.MediaType == "text/plain" {
			result[index], err = NewWorkspaceSnapshotFile(path, body, file.SHA256)
		} else {
			result[index], err = NewWorkspaceVisualAsset(path, body, file.SHA256, file.MediaType)
		}
		if err != nil {
			return nil, fmt.Errorf("captured review archive: file: %w", err)
		}
	}
	return result, nil
}

func capturedManifestReferences(wire capturedReviewArchiveManifestWire) ([]CapturedReviewArchiveBlobReference, error) {
	refs := make(map[string]CapturedReviewArchiveBlobReference)
	add := func(ref capturedContentRefWire) error {
		if ref.Blob == "" && ref.SHA256 == sha256Identifier(nil) {
			return nil
		}
		path, err := NewSafeRelativePath(ref.Blob)
		if err != nil || path.String() != capturedBlobPath(ref.SHA256) {
			return fmt.Errorf("captured review archive: invalid blob reference")
		}
		refs[path.String()] = CapturedReviewArchiveBlobReference{path: path, sha256: ref.SHA256}
		return nil
	}
	if err := add(wire.Target); err != nil {
		return nil, err
	}
	if wire.ProjectContext != nil {
		if err := add(*wire.ProjectContext); err != nil {
			return nil, err
		}
	}
	addFiles := func(files []capturedFileRefWire) error {
		for _, file := range files {
			if err := add(capturedContentRefWire{SHA256: file.SHA256, Blob: file.Blob}); err != nil {
				return err
			}
		}
		return nil
	}
	if err := addFiles(wire.Snapshot); err != nil {
		return nil, err
	}
	for _, side := range wire.Evidence {
		if err := addFiles(side.Files); err != nil {
			return nil, err
		}
	}
	result := make([]CapturedReviewArchiveBlobReference, 0, len(refs))
	for _, ref := range refs {
		result = append(result, ref)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].path.String() < result[j].path.String() })
	return result, nil
}

func decodeCapturedReviewManifest(manifest []byte) (capturedReviewArchiveManifestWire, error) {
	var wire capturedReviewArchiveManifestWire
	decoder := json.NewDecoder(bytes.NewReader(manifest))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil || decoder.Decode(&struct{}{}) != io.EOF || wire.SchemaVersion != capturedReviewArchiveManifestVersion {
		return capturedReviewArchiveManifestWire{}, fmt.Errorf("captured review archive: invalid manifest encoding")
	}
	return wire, nil
}

func capturedArchiveSchemaVersion(manifest []byte) (string, error) {
	var header struct {
		SchemaVersion string `json:"schema_version"`
	}
	if err := json.Unmarshal(manifest, &header); err != nil || header.SchemaVersion == "" {
		return "", fmt.Errorf("captured review archive: invalid encoding")
	}
	return header.SchemaVersion, nil
}

func capturedBlobPath(sha256 string) string {
	if validateSHA256(sha256) != nil {
		return ""
	}
	digest := strings.TrimPrefix(sha256, "sha256:")
	return "blobs/sha256-" + digest
}

func marshalCapturedReviewBundle(material CapturedReviewMaterial) ([]byte, error) {
	archive, err := NewCapturedReviewArchive(material)
	if err != nil {
		return nil, err
	}
	manifest := archive.Manifest()
	blobs := archive.Blobs()
	var buffer bytes.Buffer
	buffer.Grow(len(capturedReviewBundleMagic) + 8 + len(manifest) + 4)
	buffer.WriteString(capturedReviewBundleMagic)
	if err := binary.Write(&buffer, binary.BigEndian, uint64(len(manifest))); err != nil {
		return nil, fmt.Errorf("captured review archive: encode bundle manifest length: %w", err)
	}
	buffer.Write(manifest)
	if len(blobs) > int(^uint32(0)) {
		return nil, fmt.Errorf("captured review archive: too many blobs")
	}
	if err := binary.Write(&buffer, binary.BigEndian, uint32(len(blobs))); err != nil {
		return nil, fmt.Errorf("captured review archive: encode bundle blob count: %w", err)
	}
	for _, blob := range blobs {
		body := blob.Bytes()
		if err := binary.Write(&buffer, binary.BigEndian, uint64(len(body))); err != nil {
			return nil, fmt.Errorf("captured review archive: encode bundle blob length: %w", err)
		}
		buffer.Write(body)
	}
	return buffer.Bytes(), nil
}

func isCapturedReviewBundle(contents []byte) bool {
	return bytes.HasPrefix(contents, []byte(capturedReviewBundleMagic))
}

func unmarshalCapturedReviewBundle(contents []byte) (CapturedReviewMaterial, error) {
	reader := bytes.NewReader(contents[len(capturedReviewBundleMagic):])
	var manifestLength uint64
	if err := binary.Read(reader, binary.BigEndian, &manifestLength); err != nil || manifestLength > uint64(reader.Len()) {
		return CapturedReviewMaterial{}, fmt.Errorf("captured review archive: invalid bundle manifest length")
	}
	manifest := make([]byte, int(manifestLength))
	if _, err := io.ReadFull(reader, manifest); err != nil {
		return CapturedReviewMaterial{}, fmt.Errorf("captured review archive: read bundle manifest: %w", err)
	}
	references, err := CapturedReviewArchiveBlobReferences(manifest)
	if err != nil {
		return CapturedReviewMaterial{}, err
	}
	var blobCount uint32
	if err := binary.Read(reader, binary.BigEndian, &blobCount); err != nil || int(blobCount) != len(references) {
		return CapturedReviewMaterial{}, fmt.Errorf("captured review archive: invalid bundle blob count")
	}
	blobs := make([]CapturedReviewArchiveBlob, len(references))
	for index, reference := range references {
		var blobLength uint64
		if err := binary.Read(reader, binary.BigEndian, &blobLength); err != nil || blobLength > uint64(reader.Len()) {
			return CapturedReviewMaterial{}, fmt.Errorf("captured review archive: invalid bundle blob length")
		}
		body := make([]byte, int(blobLength))
		if _, err := io.ReadFull(reader, body); err != nil {
			return CapturedReviewMaterial{}, fmt.Errorf("captured review archive: read bundle blob: %w", err)
		}
		blob, err := NewCapturedReviewArchiveBlob(reference.Path(), body)
		if err != nil || blob.SHA256() != reference.SHA256() {
			return CapturedReviewMaterial{}, fmt.Errorf("captured review archive: bundle blob identity mismatch")
		}
		blobs[index] = blob
	}
	if reader.Len() != 0 {
		return CapturedReviewMaterial{}, fmt.Errorf("captured review archive: trailing bundle bytes")
	}
	return RestoreCapturedReviewArchive(manifest, blobs)
}
