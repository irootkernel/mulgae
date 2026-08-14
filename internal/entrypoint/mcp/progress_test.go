package mcpentry

import (
	"context"
	"strings"
	"testing"
	"time"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestProgressTokenAdmissionIsBounded(t *testing.T) {
	for _, token := range []any{"", "review-progress", 1, int32(2), int64(3), float64(4)} {
		if !validProgressToken(token) {
			t.Fatalf("valid progress token rejected: %#v", token)
		}
	}
	for _, token := range []any{nil, strings.Repeat("x", maxProgressTokenBytes+1), 1.5, []string{"nested"}} {
		if validProgressToken(token) {
			t.Fatalf("invalid progress token accepted: %#v", token)
		}
	}
}

func TestProgressStreamIsMonotonicAndStopsExactlyOnce(t *testing.T) {
	heartbeats := make(chan time.Time, 2)
	stopped := make(chan struct{}, 1)
	notifications := make(chan mcpsdk.ProgressNotificationParams, 4)
	finish := startProgressStream(
		context.Background(),
		"review-progress",
		heartbeats,
		func() { stopped <- struct{}{} },
		func(_ context.Context, params *mcpsdk.ProgressNotificationParams) error {
			notifications <- *params
			return nil
		},
	)

	assertProgressNotification(t, <-notifications, "review-progress", 0, "Mulgae review admitted.")
	heartbeats <- time.Time{}
	assertProgressNotification(t, <-notifications, "review-progress", 1, "Mulgae review is still running.")
	heartbeats <- time.Time{}
	assertProgressNotification(t, <-notifications, "review-progress", 2, "Mulgae review is still running.")
	finish("Mulgae review completed.")
	finish("must not be sent")
	assertProgressNotification(t, <-notifications, "review-progress", 3, "Mulgae review completed.")
	select {
	case <-stopped:
	default:
		t.Fatal("progress heartbeat was not stopped")
	}
	select {
	case unexpected := <-notifications:
		t.Fatalf("unexpected progress notification = %#v", unexpected)
	default:
	}
}

func TestProgressStreamOmitsTerminalNotificationAfterCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	heartbeats := make(chan time.Time)
	notifications := make(chan mcpsdk.ProgressNotificationParams, 2)
	finish := startProgressStream(ctx, "review-progress", heartbeats, func() {}, func(_ context.Context, params *mcpsdk.ProgressNotificationParams) error {
		notifications <- *params
		return nil
	})
	assertProgressNotification(t, <-notifications, "review-progress", 0, "Mulgae review admitted.")
	cancel()
	finish("must not be sent")
	select {
	case unexpected := <-notifications:
		t.Fatalf("unexpected post-cancellation notification = %#v", unexpected)
	default:
	}
}

func assertProgressNotification(t *testing.T, got mcpsdk.ProgressNotificationParams, token string, progress float64, message string) {
	t.Helper()
	if got.ProgressToken != token || got.Progress != progress || got.Total != 0 || got.Message != message {
		t.Fatalf("progress notification = %#v", got)
	}
}
