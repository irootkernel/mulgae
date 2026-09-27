package query

import (
	"context"
	"errors"

	"github.com/irootkernel/mulgae/internal/app"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

// ProjectContext contains only public identity and implemented capabilities.
type ProjectContext struct {
	ProjectBinding string                   `json:"project_binding"`
	Capabilities   VerifiedReadCapabilities `json:"capabilities"`
}

// ProjectContextService has no configuration, provider, or publication ports.
type ProjectContextService struct{ observer ports.ProjectBindingObserver }

func NewProjectContextService(observer ports.ProjectBindingObserver) (*ProjectContextService, error) {
	if missingDependency(observer) {
		return nil, typedFailure("query.context", domain.FailureInternal, "project binding observer unavailable", nil)
	}
	return &ProjectContextService{observer: observer}, nil
}

// Open pins a server's startup anchors. The owner must close the lease at shutdown.
func (service *ProjectContextService) Open(ctx context.Context, root ports.AnchoredRoot) (ports.ProjectBindingLease, error) {
	if err := contextFailure(ctx, "query.context"); err != nil {
		return nil, err
	}
	lease, err := service.observer.ObserveProjectBinding(ctx, root)
	if err != nil {
		return nil, projectContextFailure(err)
	}
	return lease, nil
}

// Read independently observes the requested root, without retaining server state.
func (service *ProjectContextService) Read(ctx context.Context, root ports.AnchoredRoot) (result ProjectContext, err error) {
	lease, err := service.Open(ctx, root)
	if err != nil {
		return result, err
	}
	defer func() {
		if closeErr := lease.Close(); closeErr != nil {
			result = ProjectContext{}
			err = projectContextFailure(closeErr)
		}
	}()
	return service.ReadLease(ctx, lease)
}

// ReadLease fails closed when the startup anchors have moved or been replaced.
func (service *ProjectContextService) ReadLease(ctx context.Context, lease ports.ProjectBindingLease) (ProjectContext, error) {
	if err := contextFailure(ctx, "query.context"); err != nil {
		return ProjectContext{}, err
	}
	if missingDependency(lease) {
		return ProjectContext{}, projectContextFailure(nil)
	}
	if err := lease.Revalidate(ctx); err != nil {
		return ProjectContext{}, projectContextFailure(err)
	}
	observed := lease.Observation()
	binding, err := app.NewProjectBinding(observed.Root, observed.GitDirectory, observed.CommonDirectory, observed.RootIdentity, observed.GitIdentity, observed.CommonIdentity)
	if err != nil {
		return ProjectContext{}, projectContextFailure(err)
	}
	return ProjectContext{ProjectBinding: binding.String(), Capabilities: VerifiedReadCapabilities{ProjectBinding: "v1", ExecutionGuard: "v1", CaptureIdentity: "v1"}}, nil
}

func projectContextFailure(cause error) error {
	class := domain.FailureSecurityPolicy
	if errors.Is(cause, context.Canceled) || errors.Is(cause, context.DeadlineExceeded) {
		class = domain.FailureCancelled
	}
	return typedFailure("query.context", class, "project binding is unavailable or changed", cause)
}
