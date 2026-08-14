package mcpentry

import (
	"context"
	"math"
	"sync"
	"time"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	reviewProgressHeartbeatInterval = 15 * time.Second
	maxProgressTokenBytes           = 128
)

type progressNotify func(context.Context, *mcpsdk.ProgressNotificationParams) error

func startReviewProgress(ctx context.Context, request *mcpsdk.CallToolRequest) func(string) {
	if ctx == nil || request == nil || request.Params == nil || request.Session == nil {
		return func(string) {}
	}
	token := request.Params.GetProgressToken()
	if !validProgressToken(token) {
		return func(string) {}
	}
	ticker := time.NewTicker(reviewProgressHeartbeatInterval)
	return startProgressStream(ctx, token, ticker.C, ticker.Stop, request.Session.NotifyProgress)
}

func validProgressToken(token any) bool {
	switch value := token.(type) {
	case string:
		return len(value) <= maxProgressTokenBytes
	case int, int32, int64:
		return true
	case float64:
		return value == math.Trunc(value) && math.Abs(value) <= 1<<53
	default:
		return false
	}
}

func startProgressStream(
	ctx context.Context,
	token any,
	heartbeats <-chan time.Time,
	stopHeartbeats func(),
	notify progressNotify,
) func(string) {
	if ctx == nil || token == nil || heartbeats == nil || stopHeartbeats == nil || notify == nil {
		return func(string) {}
	}
	_ = notify(ctx, &mcpsdk.ProgressNotificationParams{
		ProgressToken: token,
		Progress:      0,
		Message:       "Mulgae review admitted.",
	})

	streamCtx, cancel := context.WithCancel(ctx)
	done := make(chan float64, 1)
	go func() {
		defer stopHeartbeats()
		progress := float64(0)
		for {
			select {
			case <-streamCtx.Done():
				done <- progress
				return
			case <-heartbeats:
				progress++
				_ = notify(streamCtx, &mcpsdk.ProgressNotificationParams{
					ProgressToken: token,
					Progress:      progress,
					Message:       "Mulgae review is still running.",
				})
			}
		}
	}()

	var once sync.Once
	return func(message string) {
		once.Do(func() {
			cancel()
			progress := <-done
			if ctx.Err() == nil {
				_ = notify(ctx, &mcpsdk.ProgressNotificationParams{
					ProgressToken: token,
					Progress:      progress + 1,
					Message:       message,
				})
			}
		})
	}
}
