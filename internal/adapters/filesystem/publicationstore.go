// Package filesystem provides Darwin filesystem adapters for ports.
package filesystem

import (
	"context"
	"fmt"
	"reflect"
	"sync"
	"time"

	"github.com/irootkernel/kkachi-agent-review/internal/domain"
	"github.com/irootkernel/kkachi-agent-review/internal/ports"
)

const (
	finalReviewSchemaAsset = "https://kar.local/schemas/kar-review-artifact.v2.schema.json"
	runManifestSchemaAsset = "https://kar.local/schemas/kar-run-manifest.v2.schema.json"
)

// PublicationSchemaValidator validates the two consumer-owned publication
// schemas. The concrete JSON Schema adapter satisfies this interface directly.
type PublicationSchemaValidator interface {
	Validate(context.Context, ports.AssetID, []byte) error
}

// ReviewIDGenerator is the narrow identity dependency required by publication.
type ReviewIDGenerator interface {
	NewReviewID(time.Time) (domain.ReviewID, error)
}

// PublicationStore is the Darwin durable publication authority. All filesystem
// access is serialized through the process-wide mutex and an on-disk flock.
type PublicationStore struct {
	validator PublicationSchemaValidator
	clock     ports.Clock
	ids       ReviewIDGenerator
	writer    ports.SecureFileWriter

	finalSchema    ports.AssetID
	manifestSchema ports.AssetID
	operations     publicationStoreOperations
}
type publicationStoreOperations struct {
	fsync       func(int) error
	renameatxNp func(int, string, int, string, uint32) error
}

var publicationStoreProcessMu sync.Mutex

// NewPublicationStore constructs a durable publication adapter. It performs no
// filesystem I/O; roots are validated by each operation's PublicationRun.
func NewPublicationStore(
	validator PublicationSchemaValidator,
	clock ports.Clock,
	ids ReviewIDGenerator,
	writer ports.SecureFileWriter,
) (*PublicationStore, error) {
	if nilInterface(validator) {
		return nil, fmt.Errorf("publication store: nil schema validator")
	}
	if nilInterface(clock) {
		return nil, fmt.Errorf("publication store: nil clock")
	}
	if nilInterface(ids) {
		return nil, fmt.Errorf("publication store: nil review ID generator")
	}
	if nilInterface(writer) {
		return nil, fmt.Errorf("publication store: nil secure file writer")
	}
	finalSchema, err := ports.ParseAssetID(finalReviewSchemaAsset)
	if err != nil {
		return nil, fmt.Errorf("publication store: final schema asset: %w", err)
	}
	manifestSchema, err := ports.ParseAssetID(runManifestSchemaAsset)
	if err != nil {
		return nil, fmt.Errorf("publication store: manifest schema asset: %w", err)
	}
	return &PublicationStore{
		validator:      validator,
		clock:          clock,
		ids:            ids,
		writer:         writer,
		finalSchema:    finalSchema,
		manifestSchema: manifestSchema,
	}, nil
}

func nilInterface(value any) bool {
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
