// Package schema exposes the embedded schema catalog through application ports.
package schema

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"reflect"

	"github.com/irootkernel/kkachi-agent-review/internal/domain"
	"github.com/irootkernel/kkachi-agent-review/internal/ports"
)

const (
	listStage   = "schema.list"
	showStage   = "schema.show"
	exportStage = "schema.export"

	exportChannel = "schema_export"
)

// Service exposes schema assets from the immutable contract catalog. A writer is
// optional because listing and showing schemas never need a durable effect.
type Service struct {
	catalog ports.ContractCatalog
	writer  ports.SecureFileWriter
}

// NewService constructs a schema service over the supplied inward ports.
func NewService(catalog ports.ContractCatalog, writer ports.SecureFileWriter) *Service {
	return &Service{catalog: catalog, writer: writer}
}

// List returns schema metadata only, ordered by stable AssetID.
func (service *Service) List(ctx context.Context) ([]ports.AssetMetadata, error) {
	assets, err := service.listAssets(ctx, listStage)
	if err != nil {
		return nil, err
	}

	schemas := make([]ports.AssetMetadata, 0, len(assets))
	for _, metadata := range assets {
		if metadata.Kind() == ports.AssetKindSchema {
			schemas = append(schemas, metadata)
		}
	}
	return schemas, nil
}

// Show returns a schema's immutable metadata and a caller-owned exact copy of
// its authoritative embedded bytes.
func (service *Service) Show(ctx context.Context, id ports.AssetID) (ports.AssetMetadata, []byte, error) {
	return service.readSchema(ctx, id, showStage)
}

// Export streams one schema's exact embedded bytes through the secure writer.
// It returns a receipt only when the writer accepted bytes bound to the requested
// destination and catalog integrity metadata.
func (service *Service) Export(ctx context.Context, id ports.AssetID, root ports.AnchoredRoot, destination ports.SafeRelativePath) (ports.SecureWriteReceipt, error) {
	metadata, contents, err := service.readSchema(ctx, id, exportStage)
	if err != nil {
		return ports.SecureWriteReceipt{}, err
	}
	if !root.Valid() || !destination.Valid() {
		return ports.SecureWriteReceipt{}, typedFailure(exportStage, domain.FailureConfiguration, "invalid schema export destination", nil)
	}
	if missingPort(service.writer) {
		return ports.SecureWriteReceipt{}, typedFailure(exportStage, domain.FailureArtifact, "schema export writer is unavailable", nil)
	}
	if metadata.ByteLength() <= 0 {
		return ports.SecureWriteReceipt{}, typedFailure(exportStage, domain.FailureArtifact, "schema export has an invalid byte length", nil)
	}

	aborted := false
	var abortCause error
	request, err := ports.NewSecureWriteRequest(
		root,
		destination,
		exportChannel,
		bytes.NewReader(contents),
		metadata.ByteLength(),
		[]string{metadata.ID().String()},
		func(cause error) {
			aborted = true
			abortCause = cause
		},
	)
	if err != nil {
		return ports.SecureWriteReceipt{}, typedFailure(exportStage, domain.FailureArtifact, "schema export request is invalid", err)
	}

	receipt, drop, writeErr := service.writer.Write(ctx, request)
	if drop != nil || aborted {
		return ports.SecureWriteReceipt{}, typedFailure(exportStage, domain.FailureSecurityPolicy, "schema export was rejected by the secure writer", firstError(writeErr, abortCause))
	}
	if writeErr != nil {
		return ports.SecureWriteReceipt{}, typedFailure(exportStage, domain.FailureArtifact, "schema export write failed", writeErr)
	}
	sourceIDs := receipt.SourceIDs()
	if receipt.Root() != root ||
		receipt.Destination() != destination ||
		receipt.Channel() != exportChannel ||
		len(sourceIDs) != 1 ||
		sourceIDs[0] != metadata.ID().String() ||
		receipt.SHA256() != metadata.SHA256() ||
		receipt.ByteLength() != metadata.ByteLength() {
		return ports.SecureWriteReceipt{}, typedFailure(exportStage, domain.FailureArtifact, "schema export receipt does not match authoritative bytes", nil)
	}
	return receipt, nil
}

func (service *Service) readSchema(ctx context.Context, id ports.AssetID, stage string) (ports.AssetMetadata, []byte, error) {
	if !id.Valid() {
		return ports.AssetMetadata{}, nil, typedFailure(stage, domain.FailureConfiguration, "invalid schema ID", nil)
	}

	listed, err := service.listAssets(ctx, stage)
	if err != nil {
		return ports.AssetMetadata{}, nil, err
	}
	var expected ports.AssetMetadata
	found := false
	for _, metadata := range listed {
		if metadata.ID().String() != id.String() {
			continue
		}
		if metadata.Kind() != ports.AssetKindSchema {
			return ports.AssetMetadata{}, nil, typedFailure(stage, domain.FailureConfiguration, "requested asset is not a schema", nil)
		}
		expected = metadata
		found = true
		break
	}
	if !found {
		return ports.AssetMetadata{}, nil, typedFailure(stage, domain.FailureConfiguration, "unknown schema ID", nil)
	}
	if err := contextError(ctx, stage); err != nil {
		return ports.AssetMetadata{}, nil, err
	}

	metadata, contents, err := service.catalog.Read(ctx, id)
	if err != nil {
		if contextErr := contextError(ctx, stage); contextErr != nil {
			return ports.AssetMetadata{}, nil, contextErr
		}
		return ports.AssetMetadata{}, nil, typedFailure(stage, domain.FailureArtifact, "schema catalog read failed", err)
	}
	if metadata != expected || metadata.Kind() != ports.AssetKindSchema || !matchesMetadata(metadata, contents) {
		return ports.AssetMetadata{}, nil, typedFailure(stage, domain.FailureArtifact, "schema catalog integrity check failed", nil)
	}
	return metadata, cloneBytes(contents), nil
}

func (service *Service) listAssets(ctx context.Context, stage string) ([]ports.AssetMetadata, error) {
	if missingPort(service) || missingPort(service.catalog) {
		return nil, typedFailure(stage, domain.FailureArtifact, "schema catalog is unavailable", nil)
	}
	if err := contextError(ctx, stage); err != nil {
		return nil, err
	}

	assets, err := service.catalog.List(ctx)
	if err != nil {
		if contextErr := contextError(ctx, stage); contextErr != nil {
			return nil, contextErr
		}
		return nil, typedFailure(stage, domain.FailureArtifact, "schema catalog list failed", err)
	}
	previousID := ""
	seen := make(map[string]struct{}, len(assets))
	for _, metadata := range assets {
		if !metadata.ID().Valid() || !metadata.Kind().Valid() || !metadata.Source().Valid() || metadata.MediaType() == "" || !validSHA256(metadata.SHA256()) || metadata.ByteLength() < 0 {
			return nil, typedFailure(stage, domain.FailureArtifact, "schema catalog metadata is invalid", nil)
		}
		id := metadata.ID().String()
		if _, duplicate := seen[id]; duplicate {
			return nil, typedFailure(stage, domain.FailureArtifact, "schema catalog contains duplicate asset IDs", nil)
		}
		seen[id] = struct{}{}
		if previousID != "" && id <= previousID {
			return nil, typedFailure(stage, domain.FailureArtifact, "schema catalog assets are not strictly ordered", nil)
		}
		previousID = id
	}
	return assets, nil
}

func contextError(ctx context.Context, stage string) error {
	if ctx == nil {
		return typedFailure(stage, domain.FailureConfiguration, "schema request context is nil", nil)
	}
	if err := ctx.Err(); err != nil {
		return typedFailure(stage, domain.FailureCancelled, "schema request was cancelled", err)
	}
	return nil
}

func matchesMetadata(metadata ports.AssetMetadata, contents []byte) bool {
	if int64(len(contents)) != metadata.ByteLength() {
		return false
	}
	sum := sha256.Sum256(contents)
	return "sha256:"+hex.EncodeToString(sum[:]) == metadata.SHA256()
}

func validSHA256(value string) bool {
	const prefix = "sha256:"
	if len(value) != len(prefix)+sha256.Size*2 || value[:len(prefix)] != prefix {
		return false
	}
	for _, character := range value[len(prefix):] {
		if !(character >= '0' && character <= '9' || character >= 'a' && character <= 'f') {
			return false
		}
	}
	return true
}

func cloneBytes(value []byte) []byte {
	if value == nil {
		return nil
	}
	copyValue := make([]byte, len(value))
	copy(copyValue, value)
	return copyValue
}

func firstError(first, second error) error {
	if first != nil {
		return first
	}
	return second
}

func missingPort(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

func typedFailure(stage string, class domain.FailureClass, reason string, cause error) error {
	failure, err := domain.NewFailure(stage, class, reason, cause)
	if err != nil {
		return err
	}
	return failure
}
