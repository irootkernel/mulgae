package mulgae

import (
	"fmt"
	"time"

	appclean "github.com/irootkernel/mulgae/internal/app/clean"
	appexport "github.com/irootkernel/mulgae/internal/app/export"
	appquery "github.com/irootkernel/mulgae/internal/app/query"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

// G008IdentityGenerator supplies the distinct identities needed by command
// envelopes and verified export identities.
type G008IdentityGenerator interface {
	RequestIDGenerator
	NewRunID(time.Time) (domain.RunID, error)
}

// G008Composition is the complete input for the G008 Dependencies projection.
// Export and selector resolution remain available without online authority.
type G008Composition struct {
	ArtifactRoot         ports.AnchoredRoot
	Queries              *appquery.Service
	RequestResolver      *G008RequestResolver
	Clock                ports.Clock
	IDs                  G008IdentityGenerator
	ExportInstaller      appexport.ExportInstaller
	PublicationAuthority ports.PublicationStore

	CleanStore     appclean.ApplyStore
	CleanValidator appclean.SchemaValidator
}

// NewG008Dependencies composes only G008 command capabilities. Callers merge
// its result with the independently constructed foundation Dependencies.
func NewG008Dependencies(composition G008Composition) (Dependencies, error) {
	if !composition.ArtifactRoot.Valid() {
		return Dependencies{}, fmt.Errorf("G008 composition: invalid artifact root")
	}
	if composition.Queries == nil {
		return Dependencies{}, fmt.Errorf("G008 composition: query service is required")
	}
	if composition.RequestResolver == nil {
		return Dependencies{}, fmt.Errorf("G008 composition: request resolver is required")
	}
	if composition.RequestResolver.artifactRoot != composition.ArtifactRoot || composition.RequestResolver.queries != composition.Queries {
		return Dependencies{}, fmt.Errorf("G008 composition: request resolver does not match artifact root and query service")
	}
	if nilApplicationDependency(composition.Clock) || nilApplicationDependency(composition.IDs) || nilApplicationDependency(composition.PublicationAuthority) {
		return Dependencies{}, fmt.Errorf("G008 composition: clock, ID generator, and publication authority are required")
	}
	if nilApplicationDependency(composition.ExportInstaller) {
		return Dependencies{}, fmt.Errorf("G008 composition: export installer is required")
	}

	exports, err := NewRedactedExportService(composition.Queries, composition.ExportInstaller, composition.Clock, composition.IDs)
	if err != nil {
		return Dependencies{}, fmt.Errorf("G008 composition: export service: %w", err)
	}
	dependencies := Dependencies{RequestResolver: composition.RequestResolver, Exports: exports}

	storePresent := !nilApplicationDependency(composition.CleanStore)
	validatorPresent := !nilApplicationDependency(composition.CleanValidator)
	if storePresent != validatorPresent {
		return Dependencies{}, fmt.Errorf("G008 composition: incomplete clean authority")
	}
	if storePresent {
		clean, err := appclean.NewService(composition.Clock, composition.CleanValidator, composition.CleanStore)
		if err != nil {
			return Dependencies{}, fmt.Errorf("G008 composition: clean service: %w", err)
		}
		dependencies.Retention = NewRetentionService(clean)
	}

	return dependencies, nil
}
