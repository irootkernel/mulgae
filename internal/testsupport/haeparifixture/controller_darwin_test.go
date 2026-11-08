//go:build darwin && arm64

package haeparifixture_test

import (
	"context"
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/adapters/haepari"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
	"github.com/irootkernel/mulgae/internal/testsupport/haeparifixture"
)

func TestControllerSerializesRealUnixClients(t *testing.T) {
	controller := haeparifixture.New(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	first, second := haepari.NewClient(haepari.Config{RawHome: controller.Home}), haepari.NewClient(haepari.Config{RawHome: controller.Home})
	for _, client := range []*haepari.Client{first, second} {
		if _, err := client.Hello(ctx); err != nil {
			t.Fatal(err)
		}
	}
	session, _ := domain.ParseSessionID("s_019f596a-cf80-7c67-b265-f37053d51ccf")
	run1, _ := domain.ParseRunID("r_019f596a-cfe4-7c9c-b82e-7149158243ba")
	run2, _ := domain.ParseRunID("r_019f596a-cf80-7c67-b265-f37053d51ccf")
	payload1, _ := ports.NewReviewLockRequestPayload(session, run1, nil)
	payload2, _ := ports.NewReviewLockRequestPayload(session, run2, nil)
	grant, err := first.Acquire(ctx, payload1.CanonicalJSON)
	if err != nil {
		t.Fatal(err)
	}
	queued, err := second.Acquire(ctx, payload2.CanonicalJSON)
	if err != nil || queued.Current.State != ports.ReviewLockStateQueued {
		t.Fatalf("queue: %+v / %v", queued, err)
	}
	result := make(chan error, 1)
	go func() {
		reply, err := second.Wait(ctx, queued.Current.RequestID, time.Second)
		if err == nil && reply.Current.State != ports.ReviewLockStateGranted {
			err = context.Canceled
		}
		result <- err
	}()
	if err := controller.WaitFor(ctx, "wait:"); err != nil {
		t.Fatal(err)
	}
	if _, err := first.Release(ctx, grant.Current.GrantID); err != nil {
		t.Fatal(err)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	if _, err := second.Cancel(ctx, queued.Current.RequestID); err != nil {
		t.Fatal(err)
	}
	events := controller.Events()
	if len(events) < 7 {
		t.Fatalf("missing serialized operations: %v", events)
	}
}
