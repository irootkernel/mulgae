//go:build darwin && arm64

package composition

import (
	"context"
	"errors"
	"fmt"
	"time"

	appheartbeat "github.com/irootkernel/mulgae/internal/app/heartbeat"
	"github.com/irootkernel/mulgae/internal/app/reviewrun"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

type heartbeatComposer func(context.Context, ports.AnchoredRoot) (*productionRuntimeGraph, error)

type deferredHeartbeatService struct {
	compose heartbeatComposer
	clock   ports.Clock
}

func (service deferredHeartbeatService) ProbeProvider(ctx context.Context, root ports.AnchoredRoot, request appheartbeat.Request) (result appheartbeat.Result, err error) {
	if service.compose == nil {
		return appheartbeat.Result{}, fmt.Errorf("heartbeat composition unavailable")
	}
	graph, err := service.compose(ctx, root)
	if err != nil {
		if service.clock == nil {
			return appheartbeat.Result{}, err
		}
		return heartbeatBaseResult(service.clock.Now(), request), nil
	}
	defer func() {
		if cleanupErr := graph.cleanupRoots(); cleanupErr != nil {
			if result.SchemaVersion == "" {
				result = heartbeatBaseResult(graph.clock.Now(), request)
			}
			result.Status, result.ReasonCode = "execution_failure", "heartbeat_cleanup_failed"
			err = nil
		}
	}()
	return graph.probeHeartbeat(ctx, request)
}

func (graph *productionRuntimeGraph) probeHeartbeat(ctx context.Context, request appheartbeat.Request) (result appheartbeat.Result, err error) {
	result = heartbeatBaseResult(graph.clock.Now(), request)
	family := reviewrun.Family(request.ProviderID)
	if !family.Valid() || graph.fixtures == nil || graph.qualified == nil || graph.candidates == nil {
		return appheartbeat.Result{}, fmt.Errorf("heartbeat graph unavailable")
	}
	if family == reviewrun.FamilyCodex && graph.policy.config.Providers.Codex != nil && graph.policy.config.Providers.Codex.DefaultCredentialProfile != "" {
		if request.CredentialProfile == "" {
			return appheartbeat.Result{}, fmt.Errorf("heartbeat codex credential profile is required")
		}
		if _, ok := graph.policy.config.Providers.Codex.CredentialHome(request.CredentialProfile); !ok {
			return appheartbeat.Result{}, fmt.Errorf("heartbeat codex credential profile is not configured")
		}
	} else if request.CredentialProfile != "" {
		return appheartbeat.Result{}, fmt.Errorf("heartbeat credential profile is not applicable")
	}
	seed, err := graph.fixtures.Acquire(ctx, domain.RoleLogic)
	if err != nil {
		return result, nil
	}
	defer func() {
		if _, cleanupErr := seed.DrainTerminal(context.Background()); cleanupErr != nil {
			result.Status, result.ReasonCode = "execution_failure", "heartbeat_cleanup_failed"
			err = nil
		}
	}()
	candidate, err := graph.candidates.newHeartbeatCandidate(ctx, seed.WorkspaceSnapshotIdentity(), family, request.CredentialProfile)
	if err != nil {
		return result, nil
	}
	run, err := graph.qualified.NewQualifiedRun(ctx, []reviewrun.QualifiedRunCandidate{candidate})
	if err != nil {
		result.Attempted = heartbeatLiveAttempted(err)
		result.Status, result.ReasonCode = heartbeatFailure(err)
		return result, nil
	}
	result.Attempted = true
	if _, err := run.DrainTerminal(ctx); err != nil {
		return result, nil
	}
	result.Status, result.ReasonCode = "succeeded", "heartbeat_succeeded"
	return result, nil
}

func heartbeatLiveAttempted(err error) bool {
	var failure *domain.Failure
	if errors.As(err, &failure) && failure != nil && failure.Stage() == "reviewrun.qualification" && failure.Reason() == "provider version is incompatible" {
		return false
	}
	return true
}

func heartbeatBaseResult(checkedAt time.Time, request appheartbeat.Request) appheartbeat.Result {
	return appheartbeat.Result{
		SchemaVersion: appheartbeat.SchemaVersion, CheckedAt: checkedAt.UTC(), ProviderID: request.ProviderID, CredentialProfile: request.CredentialProfile,
		Status: "execution_failure", ReasonCode: "provider_execution_failed",
		AuthenticationMayOccur: true, NetworkMayOccur: true, CostMayOccur: true, RemoteLoggingMayOccur: true,
	}
}

func heartbeatFailure(err error) (string, string) {
	var failure *domain.Failure
	if errors.As(err, &failure) && failure != nil {
		switch failure.Class() {
		case domain.FailureAuthentication:
			return "authentication_failure", "authentication_required"
		case domain.FailureTimeout:
			return "timeout", "provider_timeout"
		case domain.FailureInvalidOutput:
			return "malformed_response", "heartbeat_response_malformed"
		case domain.FailureProviderUnavailable, domain.FailureQuota, domain.FailureRateLimit:
			return "provider_failure", "provider_failure"
		}
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout", "provider_timeout"
	}
	return "execution_failure", "provider_execution_failed"
}
