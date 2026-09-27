package query

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

type contextObserverFake struct {
	lease *contextLeaseFake
	err   error
}

func (fake contextObserverFake) ObserveProjectBinding(context.Context, ports.AnchoredRoot) (ports.ProjectBindingLease, error) {
	return fake.lease, fake.err
}

type contextLeaseFake struct {
	observation     ports.ProjectBindingObservation
	drift, closeErr error
	closed          bool
}

func (fake *contextLeaseFake) Observation() ports.ProjectBindingObservation { return fake.observation }
func (fake *contextLeaseFake) Revalidate(ctx context.Context) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return fake.drift
}
func (fake *contextLeaseFake) Close() error { fake.closed = true; return fake.closeErr }

func TestProjectContextRedactionCapabilitiesAndFailure(t *testing.T) {
	root, _ := ports.NewAnchoredRoot("/private/project")
	git, _ := ports.NewAnchoredRoot("/private/project/.git")
	identity := ports.ProjectDirectoryIdentity{Device: 1, Inode: 2, BirthSeconds: 3}
	observation := ports.ProjectBindingObservation{Root: root, GitDirectory: git, CommonDirectory: git, RootIdentity: identity, GitIdentity: identity, CommonIdentity: identity}
	for _, failure := range []string{"", "observe", "drift", "close", "cancel", "invalid"} {
		t.Run(failure, func(t *testing.T) {
			lease := &contextLeaseFake{observation: observation}
			observer := contextObserverFake{lease: lease}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			private := errors.New("private /credentials/token")
			switch failure {
			case "observe":
				observer.err = private
			case "drift":
				lease.drift = private
			case "close":
				lease.closeErr = private
			case "cancel":
				cancel()
			case "invalid":
				lease.observation.Root = ports.AnchoredRoot{}
			}
			service, err := NewProjectContextService(observer)
			if err != nil {
				t.Fatal(err)
			}
			result, err := service.Read(ctx, root)
			if failure != "" {
				if err == nil || result.ProjectBinding != "" {
					t.Fatal("failure exposed binding")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !lease.closed {
				t.Fatal("lease leaked")
			}
			if _, err := domain.ParseProjectBinding(result.ProjectBinding); err != nil {
				t.Fatal(err)
			}
			if result.Capabilities != (VerifiedReadCapabilities{ProjectBinding: "v1", ExecutionGuard: "v1", CaptureIdentity: "v1"}) {
				t.Fatal("unexpected capability advertisement")
			}
			data, _ := json.Marshal(result)
			if strings.Contains(string(data), "private") || strings.Contains(string(data), "inode") {
				t.Fatal("private identity exposed")
			}
		})
	}
}
