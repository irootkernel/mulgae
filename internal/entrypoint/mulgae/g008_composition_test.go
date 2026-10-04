package mulgae

import (
	"testing"

	"github.com/irootkernel/mulgae/internal/adapters/filesystem"
	runtimeadapter "github.com/irootkernel/mulgae/internal/adapters/runtime"
	appquery "github.com/irootkernel/mulgae/internal/app/query"
	"github.com/irootkernel/mulgae/internal/ports"
)

func TestG008CompositionKeepsOfflineCapabilitiesWithoutOnlineAuthority(t *testing.T) {
	composition := newG008Composition(t)
	dependencies, err := NewG008Dependencies(composition)
	if err != nil {
		t.Fatal(err)
	}
	if dependencies.RequestResolver == nil || dependencies.Exports == nil {
		t.Fatal("offline resolver/export capabilities were not composed")
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
	resolver, err := NewG008RequestResolver(root, queries, filesystem.NewRunSelector(root))
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
