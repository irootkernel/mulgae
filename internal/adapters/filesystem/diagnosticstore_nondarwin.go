//go:build !darwin || !arm64

package filesystem

import (
	"context"
	"errors"

	"github.com/irootkernel/kkachi-agent-review/internal/domain"
	"github.com/irootkernel/kkachi-agent-review/internal/ports"
)

var errDiagnosticStoreUnsupportedPlatform = errors.New("diagnostic store requires darwin/arm64 secure filesystem primitives")

func (*DiagnosticStoreFactory) Open(context.Context, ports.RuntimeDiagnosticOpenRequest) (ports.RuntimeDiagnosticSink, error) {
	return nil, errDiagnosticStoreUnsupportedPlatform
}
func (*DiagnosticStore) Emit(context.Context, domain.RuntimeDiagnosticEventDraft) (domain.RuntimeDiagnosticEvent, error) {
	return domain.RuntimeDiagnosticEvent{}, errDiagnosticStoreUnsupportedPlatform
}
func (*DiagnosticStore) ReplaceRunStatus(context.Context, ports.RuntimeDiagnosticRunStatus) error {
	return errDiagnosticStoreUnsupportedPlatform
}
func (*DiagnosticStore) ReplaceAttemptStatus(context.Context, ports.RuntimeDiagnosticAttemptStatus) error {
	return errDiagnosticStoreUnsupportedPlatform
}
func (*DiagnosticStore) ReplaceInvocationStatus(context.Context, ports.RuntimeDiagnosticInvocationStatus) error {
	return errDiagnosticStoreUnsupportedPlatform
}
func (*DiagnosticStore) Finalize(context.Context, ports.RuntimeDiagnosticFinalizeRequest) (ports.RuntimeDiagnosticFinalizeResult, error) {
	return ports.RuntimeDiagnosticFinalizeResult{}, errDiagnosticStoreUnsupportedPlatform
}
