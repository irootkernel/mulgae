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

func TestControllerListLocksAndBorrowedGrantParity(t *testing.T) {
	controller := haeparifixture.New(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	owner := haepari.NewClient(haepari.Config{RawHome: controller.Home})
	if _, err := owner.Hello(ctx); err != nil {
		t.Fatal(err)
	}
	session, _ := domain.ParseSessionID("s_019f596a-cf80-7c67-b265-f37053d51ccf")
	run1, _ := domain.ParseRunID("r_019f596a-cfe4-7c9c-b82e-7149158243ba")
	run2, _ := domain.ParseRunID("r_019f596a-cf80-7c67-b265-f37053d51ccf")
	payload1, _ := ports.NewReviewLockRequestPayload(session, run1, nil)
	payload2, _ := ports.NewReviewLockRequestPayload(session, run2, nil)
	grant, err := owner.Acquire(ctx, payload1.CanonicalJSON)
	if err != nil || grant.Current.State != ports.ReviewLockStateGranted {
		t.Fatalf("Acquire(1): %+v / %v", grant, err)
	}
	if _, err := owner.Acquire(ctx, payload2.CanonicalJSON); err != nil {
		t.Fatalf("Acquire(2): %v", err)
	}
	rawGrant := controller.ActiveGrantJSON()
	if rawGrant == "" {
		t.Fatal("expected ActiveGrantJSON for active grant")
	}

	borrower := haepari.NewClient(haepari.Config{RawHome: controller.Home, HasLockGrant: true, RawLockGrant: rawGrant})
	if _, err := borrower.Hello(ctx); err != nil {
		t.Fatalf("borrower Hello: %v", err)
	}
	page1, err := borrower.ListLocks(ctx, ports.HaepariReviewResourceID, "", 1)
	if err != nil || len(page1.Requests) != 1 || !page1.More || len(page1.NextCursor) <= 128 || len(page1.NextCursor) > 2048 {
		t.Fatalf("page1: %+v (cursor len=%d) / %v", page1, len(page1.NextCursor), err)
	}
	page2, err := borrower.ListLocks(ctx, ports.HaepariReviewResourceID, page1.NextCursor, 1)
	if err != nil || len(page2.Requests) != 1 || page2.More {
		t.Fatalf("page2: %+v / %v", page2, err)
	}

	controller.Disconnect()
	if _, err := owner.Hello(ctx); err == nil {
		t.Fatal("expected Hello to fail while controller is disconnected")
	}
	controller.Restart(t)
	helloAfterRestart, err := owner.Hello(ctx)
	if err != nil || helloAfterRestart.InstallationID != "fixture-installation" {
		t.Fatalf("expected same InstallationID after restart, got %+v / %v", helloAfterRestart, err)
	}
	afterRestartList, err := borrower.ListLocks(ctx, ports.HaepariReviewResourceID, "", 10)
	if err != nil || len(afterRestartList.Requests) != 2 || afterRestartList.Requests[0].GrantID != grant.Current.GrantID || afterRestartList.Requests[0].Generation != grant.Current.Generation {
		t.Fatalf("expected persisted lock rows retained across controller restart, got %+v / %v", afterRestartList, err)
	}

	controller.ExpireActiveGrant()
	if _, err := owner.Renew(ctx, grant.Current.GrantID); err == nil {
		t.Fatal("expected Renew on expired grant to fail with LOCK_EXPIRED")
	}
}
