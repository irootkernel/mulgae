package mulgae

import (
	"context"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/adapters/filesystem"
	runtimeadapter "github.com/irootkernel/mulgae/internal/adapters/runtime"
	"github.com/irootkernel/mulgae/internal/app/childrun"
	appdelta "github.com/irootkernel/mulgae/internal/app/delta"
	appfollowup "github.com/irootkernel/mulgae/internal/app/followup"
	appquery "github.com/irootkernel/mulgae/internal/app/query"
	"github.com/irootkernel/mulgae/internal/app/review"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

type compositionFollowupCapturer struct{}

func (compositionFollowupCapturer) CaptureFollowupTarget(context.Context, appfollowup.Target) (appfollowup.CurrentTarget, error) {
	return appfollowup.CurrentTarget{}, nil
}

type compositionDeltaCapturer struct{}

func (compositionDeltaCapturer) CaptureTarget(context.Context, appdelta.TargetRequest) (appdelta.ImmutableTarget, error) {
	return appdelta.ImmutableTarget{}, nil
}

type compositionDeltaComparator struct{}

func (compositionDeltaComparator) Compare(context.Context, appdelta.ImmutableTarget, appdelta.ImmutableTarget) (appdelta.Delta, error) {
	return appdelta.Delta{}, nil
}

func TestG008CompositionKeepsOfflineCapabilitiesWithoutOnlineAuthority(t *testing.T) {
	composition := newG008Composition(t)
	dependencies, err := NewG008Dependencies(composition)
	if err != nil {
		t.Fatal(err)
	}
	if dependencies.RequestResolver == nil || dependencies.Exports == nil {
		t.Fatal("offline resolver/export capabilities were not composed")
	}
	if dependencies.FollowupRuns != nil || dependencies.DeltaRuns != nil || dependencies.Reruns != nil {
		t.Fatal("nil online authority composed an online workflow")
	}
	if dependencies.Retention != nil {
		t.Fatal("nil clean policy/store composed retention authority")
	}
}
func TestG008CompositionRejectsMissingPublicationAuthority(t *testing.T) {
	composition := newG008Composition(t)
	composition.PublicationAuthority = nil
	if _, err := NewG008Dependencies(composition); err == nil {
		t.Fatal("missing publication authority was accepted")
	}
}

func TestG008CompositionRejectsResolverForDifferentArtifactRoot(t *testing.T) {
	composition := newG008Composition(t)
	otherRoot, err := ports.NewAnchoredRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	composition.ArtifactRoot = otherRoot
	if _, err := NewG008Dependencies(composition); err == nil {
		t.Fatal("composition accepted a resolver bound to a different artifact root")
	}
}

func TestG008CompositionRejectsPartialOnlineAuthority(t *testing.T) {
	composition := newG008Composition(t)
	composition.Online = &G008OnlineAuthority{FollowupTargetCapturer: compositionFollowupCapturer{}}
	if _, err := NewG008Dependencies(composition); err == nil {
		t.Fatal("partial online authority was accepted")
	}
}

func TestG008CompositionComposesAllOnlineWorkflowServices(t *testing.T) {
	composition := newG008Composition(t)
	route, err := ports.NewProviderRoute("testing")
	if err != nil {
		t.Fatal(err)
	}
	assignment, err := review.NewScheduledAssignment(domain.RoleLogic, true, route)
	if err != nil {
		t.Fatal(err)
	}
	composition.Online = &G008OnlineAuthority{
		FollowupTargetCapturer: compositionFollowupCapturer{},
		DeltaTargetCapturer:    compositionDeltaCapturer{},
		DeltaComparator:        compositionDeltaComparator{},
		ChildExecutor:          &childrun.Executor{},
		FollowupExecutor:       &childrun.FollowupExecutor{},
		RerunAssignments:       []review.Assignment{assignment},
	}
	dependencies, err := NewG008Dependencies(composition)
	if err != nil {
		t.Fatal(err)
	}
	if dependencies.FollowupRuns == nil || dependencies.DeltaRuns == nil || dependencies.Reruns == nil {
		t.Fatal("complete explicit online authority did not compose all workflow services")
	}
}

func TestG008RuntimePromptSourceRejectsMissingExplicitAuthorities(t *testing.T) {
	composition := newG008Composition(t)
	sources, err := NewG008Sources(composition.ArtifactRoot, composition.RequestResolver, composition.Queries)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewG008RuntimePromptSource(sources, nil, nil, nil); err == nil {
		t.Fatal("missing explicit runtime prompt authorities were accepted")
	}
}

func TestG008CompositionRejectsPartialCleanAuthority(t *testing.T) {
	composition := newG008Composition(t)
	composition.CleanValidator = newFoundationFixture(t).validator
	if _, err := NewG008Dependencies(composition); err == nil {
		t.Fatal("partial clean authority was accepted")
	}
}

func newG008Composition(t *testing.T) G008Composition {
	t.Helper()
	fixture := newFoundationFixture(t)
	root, err := ports.NewAnchoredRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	clock := runtimeadapter.SystemClock{}
	ids := runtimeadapter.NewUUIDv7Generator()
	store, err := filesystem.NewPublicationStore(fixture.validator, clock, ids, fixture.writer)
	if err != nil {
		t.Fatal(err)
	}
	queries, err := appquery.NewService(store, fixture.validator, nil, 8<<20)
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := NewG008RequestResolver(root, queries, filesystem.NewRunSelector(root), strings.NewReader("target"))
	if err != nil {
		t.Fatal(err)
	}
	installer, err := filesystem.NewExportInstaller(fixture.writer)
	if err != nil {
		t.Fatal(err)
	}
	return G008Composition{ArtifactRoot: root, Queries: queries, RequestResolver: resolver, Clock: clock, IDs: ids, ExportInstaller: installer, PublicationAuthority: store}
}

var _ ports.Clock = runtimeadapter.SystemClock{}
