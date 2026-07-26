// Package help exposes exact embedded help assets through the application layer.
package help

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"

	"github.com/irootkernel/kkachi-agent-review/internal/ports"
)

const (
	// TopicQuickstart is the entry-point help topic.
	TopicQuickstart = "quickstart"
	// TopicConfig documents configuration.
	TopicConfig = "config"
	// TopicProviders documents provider setup and readiness.
	TopicProviders = "providers"
	// TopicLanes documents provider concurrency lanes.
	TopicLanes = "lanes"
	// TopicPrompts documents prompt contracts.
	TopicPrompts = "prompts"
	// TopicWorkflows documents CLI workflows.
	TopicWorkflows = "workflows"
	// TopicArtifacts documents artifact storage and lineage.
	TopicArtifacts = "artifacts"
	// TopicValidation documents output validation.
	TopicValidation = "validation"
	// TopicCI documents CI reporting.
	TopicCI = "ci"
	// TopicExitCodes documents process exit codes.
	TopicExitCodes = "exit-codes"
	// TopicSecurity documents security and trust boundaries.
	TopicSecurity = "security"
)

var (
	// ErrNilCatalog reports construction or use without a ContractCatalog.
	ErrNilCatalog = errors.New("help: nil contract catalog")
	// ErrNilContext reports an invalid nil context.
	ErrNilContext = errors.New("help: nil context")
	// ErrEmptyTopic reports an empty help topic.
	ErrEmptyTopic = errors.New("help: empty topic")
	// ErrUnsafeTopic reports a topic that is not a canonical topic token.
	ErrUnsafeTopic = errors.New("help: unsafe topic")
	// ErrUnknownTopic reports a canonical but unsupported help topic.
	ErrUnknownTopic = errors.New("help: unknown topic")
	// ErrCatalogIncomplete reports a missing, duplicate, or unexpected help asset.
	ErrCatalogIncomplete = errors.New("help: incomplete contract catalog")
	// ErrCatalogInconsistent reports a Read result that differs from its listed asset.
	ErrCatalogInconsistent = errors.New("help: inconsistent contract catalog")
)

// Service lists and renders the fixed help surface from a ContractCatalog.
type Service struct {
	catalog ports.ContractCatalog
}

// NewService constructs a help service over catalog. Catalog completeness is
// checked for each Topics and Render operation with the caller's context.
func NewService(catalog ports.ContractCatalog) (*Service, error) {
	if nilContractCatalog(catalog) {
		return nil, ErrNilCatalog
	}
	return &Service{catalog: catalog}, nil
}

// Topics returns the complete fixed set of help metadata in ascending AssetID
// order. It rejects a catalog whose help inventory is not exactly the required
// application topic set.
func (service *Service) Topics(ctx context.Context) ([]ports.AssetMetadata, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if service == nil || nilContractCatalog(service.catalog) {
		return nil, ErrNilCatalog
	}

	assets, err := service.catalog.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("help: list catalog: %w", err)
	}
	if err := contextError(ctx); err != nil {
		return nil, err
	}

	helpAssets := make([]ports.AssetMetadata, 0, 12)
	seen := make(map[string]struct{}, 12)
	previousID := ""
	for _, asset := range assets {
		id := asset.ID().String()
		if !asset.ID().Valid() || previousID != "" && id <= previousID {
			return nil, fmt.Errorf("%w: catalog assets are not strictly ordered", ErrCatalogInconsistent)
		}
		previousID = id
		if asset.Kind() != ports.AssetKindHelp {
			continue
		}

		if !isRequiredHelpID(id) {
			return nil, fmt.Errorf("%w: unexpected asset %q", ErrCatalogIncomplete, id)
		}
		if _, duplicate := seen[id]; duplicate {
			return nil, fmt.Errorf("%w: duplicate asset %q", ErrCatalogIncomplete, id)
		}
		seen[id] = struct{}{}
		helpAssets = append(helpAssets, asset)
	}

	for _, topic := range requiredHelpTopics() {
		id := "help:" + topic
		if _, present := seen[id]; !present {
			return nil, fmt.Errorf("%w: missing asset %q", ErrCatalogIncomplete, id)
		}
	}

	return helpAssets, nil
}

// Render returns a caller-owned, byte-for-byte copy of the authoritative help
// asset for topic. It never wraps, normalizes, colors, or appends to the asset.
func (service *Service) Render(ctx context.Context, topic string) ([]byte, error) {
	if err := validateTopic(topic); err != nil {
		return nil, err
	}
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if service == nil || nilContractCatalog(service.catalog) {
		return nil, ErrNilCatalog
	}

	id, err := ports.ParseAssetID("help:" + topic)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid asset ID for topic %q", ErrCatalogInconsistent, topic)
	}
	topics, err := service.Topics(ctx)
	if err != nil {
		return nil, err
	}

	var listed ports.AssetMetadata
	for _, metadata := range topics {
		if metadata.ID() == id {
			listed = metadata
			break
		}
	}
	if listed.ID() != id {
		return nil, fmt.Errorf("%w: missing listed asset %q", ErrCatalogInconsistent, id.String())
	}
	if err := contextError(ctx); err != nil {
		return nil, err
	}

	metadata, contents, err := service.catalog.Read(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("help: read asset %q: %w", id.String(), err)
	}
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	sum := sha256.Sum256(contents)
	if metadata != listed ||
		int64(len(contents)) != listed.ByteLength() ||
		listed.SHA256() != "sha256:"+hex.EncodeToString(sum[:]) {
		return nil, fmt.Errorf("%w: asset %q", ErrCatalogInconsistent, id.String())
	}

	result := make([]byte, len(contents))
	copy(result, contents)
	return result, nil
}

func requiredHelpTopics() [11]string {
	return [11]string{
		TopicQuickstart,
		TopicConfig,
		TopicProviders,
		TopicLanes,
		TopicPrompts,
		TopicWorkflows,
		TopicArtifacts,
		TopicValidation,
		TopicCI,
		TopicExitCodes,
		TopicSecurity,
	}
}

func validateTopic(topic string) error {
	if topic == "" {
		return ErrEmptyTopic
	}
	if !safeTopic(topic) {
		return ErrUnsafeTopic
	}
	if !isRequiredHelpID("help:" + topic) {
		return ErrUnknownTopic
	}
	return nil
}

func safeTopic(topic string) bool {
	for index := 0; index < len(topic); index++ {
		character := topic[index]
		if character >= 'a' && character <= 'z' {
			continue
		}
		if character == '-' && index > 0 && index < len(topic)-1 && topic[index-1] != '-' {
			continue
		}
		return false
	}
	return true
}

func isRequiredHelpID(id string) bool {
	for _, topic := range requiredHelpTopics() {
		if id == "help:"+topic {
			return true
		}
	}
	return false
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return ErrNilContext
	}
	return ctx.Err()
}

func nilContractCatalog(catalog ports.ContractCatalog) bool {
	if catalog == nil {
		return true
	}
	value := reflect.ValueOf(catalog)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}
