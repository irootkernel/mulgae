package recovery

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

var ErrUnavailable = errors.New("failed-run recovery manifest is absent")

type SchemaValidator interface {
	Validate(context.Context, ports.AssetID, []byte) error
}

// RetentionMetadata identifies a manifest and its optional parent for cleanup.
// It does not verify blob content and cannot authorize replay or publication.
type RetentionMetadata struct {
	manifest ports.ImmutablePublicationArtifact
	parent   domain.SourceReference
}

func (metadata RetentionMetadata) Manifest() ports.ImmutablePublicationArtifact {
	return metadata.manifest
}
func (metadata RetentionMetadata) Parent() (domain.SourceReference, bool) {
	return metadata.parent, metadata.parent.Valid()
}

// ReadRetentionMetadata verifies bounded manifest metadata and confirms that it
// remains unchanged. It never reads the source-sized input or report blobs.
func ReadRetentionMetadata(ctx context.Context, store ports.RunSupportArtifactStore, validator SchemaValidator, run ports.PublicationRun, maxManifestBytes int64) (RetentionMetadata, error) {
	document, manifest, err := readManifest(ctx, store, validator, run, maxManifestBytes)
	if err != nil {
		return RetentionMetadata{}, err
	}
	var parent domain.SourceReference
	if document.Source != nil {
		parent, err = document.Source.Reference()
		if err != nil {
			return RetentionMetadata{}, err
		}
	}
	if err := confirmManifest(ctx, store, run, manifest, maxManifestBytes); err != nil {
		return RetentionMetadata{}, err
	}
	return RetentionMetadata{manifest: manifest, parent: parent}, nil
}

// Read verifies the manifest, all original input and report blobs, captured
// evidence, and an unchanged manifest before returning replay authority.
func Read(ctx context.Context, store ports.RunSupportArtifactStore, validator SchemaValidator, run ports.PublicationRun, maxManifestBytes int64) (Snapshot, error) {
	document, manifest, err := readManifest(ctx, store, validator, run, maxManifestBytes)
	if err != nil {
		return Snapshot{}, err
	}
	blobs := make(map[string][]byte)
	for _, blob := range document.Blobs() {
		path, err := BlobPath(run, blob)
		if err != nil {
			return Snapshot{}, err
		}
		artifact, err := readArtifact(ctx, store, run, path, blob.SHA256, blob.ByteLength)
		if err != nil {
			return Snapshot{}, err
		}
		content := artifact.Bytes()
		if int64(len(content)) != blob.ByteLength {
			return Snapshot{}, fmt.Errorf("recovery read: content length mismatch")
		}
		blobs[blob.SHA256] = content
	}
	snapshot, err := Restore(ctx, manifest.Bytes(), blobs)
	if err != nil {
		return Snapshot{}, err
	}
	if err := confirmManifest(ctx, store, run, manifest, maxManifestBytes); err != nil {
		return Snapshot{}, err
	}
	return snapshot, nil
}

func readManifest(ctx context.Context, store ports.RunSupportArtifactStore, validator SchemaValidator, run ports.PublicationRun, maximum int64) (Document, ports.ImmutablePublicationArtifact, error) {
	if ctx == nil || store == nil || validator == nil || !run.Valid() || maximum <= 0 {
		return Document{}, ports.ImmutablePublicationArtifact{}, fmt.Errorf("recovery read: invalid dependencies")
	}
	path, err := ManifestPath(run)
	if err != nil {
		return Document{}, ports.ImmutablePublicationArtifact{}, err
	}
	manifest, err := readArtifact(ctx, store, run, path, "", maximum)
	if errors.Is(err, fs.ErrNotExist) {
		return Document{}, ports.ImmutablePublicationArtifact{}, ErrUnavailable
	}
	if err != nil {
		return Document{}, ports.ImmutablePublicationArtifact{}, err
	}
	schema, err := ports.ParseAssetID(SchemaURI)
	if err != nil {
		return Document{}, ports.ImmutablePublicationArtifact{}, err
	}
	if err := validator.Validate(ctx, schema, manifest.Bytes()); err != nil {
		return Document{}, ports.ImmutablePublicationArtifact{}, err
	}
	document, err := DecodeManifest(manifest.Bytes())
	if err != nil {
		return Document{}, ports.ImmutablePublicationArtifact{}, err
	}
	if document.SessionID != run.SessionID().String() || document.RunID != run.RunID().String() {
		return Document{}, ports.ImmutablePublicationArtifact{}, fmt.Errorf("recovery read: run identity mismatch")
	}
	if err := validateMetadata(ctx, document, true); err != nil {
		return Document{}, ports.ImmutablePublicationArtifact{}, err
	}
	return document, manifest, nil
}

func confirmManifest(ctx context.Context, store ports.RunSupportArtifactStore, run ports.PublicationRun, manifest ports.ImmutablePublicationArtifact, maximum int64) error {
	confirmed, err := readArtifact(ctx, store, run, manifest.Path(), manifest.SHA256(), maximum)
	if err != nil {
		return err
	}
	if !bytes.Equal(confirmed.Bytes(), manifest.Bytes()) {
		return fmt.Errorf("recovery read: manifest changed")
	}
	return nil
}

func readArtifact(ctx context.Context, store ports.RunSupportArtifactStore, run ports.PublicationRun, path ports.SafeRelativePath, hash string, maximum int64) (ports.ImmutablePublicationArtifact, error) {
	if err := ctx.Err(); err != nil {
		return ports.ImmutablePublicationArtifact{}, err
	}
	if maximum == 0 {
		maximum = 1
	}
	request, err := ports.NewReadRunSupportArtifactRequest(run, path, hash, maximum)
	if err != nil {
		return ports.ImmutablePublicationArtifact{}, err
	}
	artifact, err := store.ReadAuxiliaryArtifact(ctx, request)
	if err != nil {
		return ports.ImmutablePublicationArtifact{}, err
	}
	if artifact.Path() != path || !artifact.Valid() || hash != "" && artifact.SHA256() != hash || int64(len(artifact.Bytes())) > maximum {
		return ports.ImmutablePublicationArtifact{}, fmt.Errorf("recovery read: artifact identity or size mismatch")
	}
	return artifact, nil
}
