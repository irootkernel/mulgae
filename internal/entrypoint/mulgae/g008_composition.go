package mulgae

import (
	"fmt"
	"time"

	"github.com/irootkernel/mulgae/internal/app/childrun"
	appclean "github.com/irootkernel/mulgae/internal/app/clean"
	appdelta "github.com/irootkernel/mulgae/internal/app/delta"
	appexport "github.com/irootkernel/mulgae/internal/app/export"
	appfollowup "github.com/irootkernel/mulgae/internal/app/followup"
	appquery "github.com/irootkernel/mulgae/internal/app/query"
	apprerun "github.com/irootkernel/mulgae/internal/app/rerun"
	"github.com/irootkernel/mulgae/internal/app/review"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

// G008IdentityGenerator supplies the distinct identities needed by command
// envelopes, delta children, and rerun children.
type G008IdentityGenerator interface {
	RequestIDGenerator
	NewRunID(time.Time) (domain.RunID, error)
}

// G008OnlineAuthority is the complete, explicit authority required to create
// online child workflows. A nil authority leaves all three workflows absent;
// a partial authority is rejected rather than inferred from adjacent services.
type G008OnlineAuthority struct {
	FollowupTargetCapturer appfollowup.CurrentTargetCapturer
	DeltaTargetCapturer    appdelta.TargetCapturer
	DeltaComparator        appdelta.Comparator
	ChildExecutor          *childrun.Executor
	FollowupExecutor       *childrun.FollowupExecutor
	RerunAssignments       []review.Assignment
}

// G008Composition is the complete input for the G008 Dependencies projection.
// Export and selector resolution remain available without online authority.
type G008Composition struct {
	Root                 ports.AnchoredRoot
	Queries              *appquery.Service
	RequestResolver      *G008RequestResolver
	Clock                ports.Clock
	IDs                  G008IdentityGenerator
	ExportInstaller      appexport.ExportInstaller
	PublicationAuthority ports.PublicationStore

	Online *G008OnlineAuthority

	CleanPolicy    appclean.RetentionPolicySource
	CleanStore     appclean.ApplyStore
	CleanValidator appclean.SchemaValidator
}

// NewG008Dependencies composes only G008 command capabilities. Callers merge
// its result with the independently constructed foundation Dependencies.
func NewG008Dependencies(composition G008Composition) (Dependencies, error) {
	if !composition.Root.Valid() {
		return Dependencies{}, fmt.Errorf("G008 composition: invalid root")
	}
	if composition.Queries == nil {
		return Dependencies{}, fmt.Errorf("G008 composition: query service is required")
	}
	if composition.RequestResolver == nil {
		return Dependencies{}, fmt.Errorf("G008 composition: request resolver is required")
	}
	if composition.RequestResolver.root != composition.Root || composition.RequestResolver.queries != composition.Queries {
		return Dependencies{}, fmt.Errorf("G008 composition: request resolver does not match root and query service")
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

	policyPresent := !nilApplicationDependency(composition.CleanPolicy)
	storePresent := !nilApplicationDependency(composition.CleanStore)
	if policyPresent != storePresent {
		return Dependencies{}, fmt.Errorf("G008 composition: incomplete clean authority")
	}
	if policyPresent {
		if nilApplicationDependency(composition.CleanValidator) {
			return Dependencies{}, fmt.Errorf("G008 composition: clean validator is required")
		}
		clean, err := appclean.NewService(composition.Clock, composition.CleanPolicy, composition.CleanValidator, composition.CleanStore)
		if err != nil {
			return Dependencies{}, fmt.Errorf("G008 composition: clean service: %w", err)
		}
		dependencies.Retention = NewRetentionService(clean)
	}

	if composition.Online == nil {
		return dependencies, nil
	}
	authority := composition.Online
	if nilApplicationDependency(authority.FollowupTargetCapturer) || nilApplicationDependency(authority.DeltaTargetCapturer) || nilApplicationDependency(authority.DeltaComparator) || authority.ChildExecutor == nil || authority.FollowupExecutor == nil || len(authority.RerunAssignments) == 0 {
		return Dependencies{}, fmt.Errorf("G008 composition: incomplete online authority")
	}
	sources, err := NewG008Sources(composition.Root, composition.RequestResolver, composition.Queries)
	if err != nil {
		return Dependencies{}, fmt.Errorf("G008 composition: sources: %w", err)
	}
	followup, err := appfollowup.NewService(sources, authority.FollowupTargetCapturer, authority.FollowupExecutor)
	if err != nil {
		return Dependencies{}, fmt.Errorf("G008 composition: followup service: %w", err)
	}
	delta, err := appdelta.NewService(composition.Clock, composition.IDs, sources, authority.DeltaTargetCapturer, authority.DeltaComparator, authority.ChildExecutor)
	if err != nil {
		return Dependencies{}, fmt.Errorf("G008 composition: delta service: %w", err)
	}
	rerun, err := apprerun.NewService(sources, authority.ChildExecutor, apprerun.Config{
		Clock: composition.Clock, IDs: composition.IDs, Assignments: authority.RerunAssignments,
	})
	if err != nil {
		return Dependencies{}, fmt.Errorf("G008 composition: rerun service: %w", err)
	}
	dependencies.FollowupRuns = NewFollowupRunService(followup)
	dependencies.DeltaRuns = NewDeltaRunService(delta)
	dependencies.Reruns = NewRerunService(rerun)
	return dependencies, nil
}
