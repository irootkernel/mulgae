//go:build !darwin || !arm64

package filesystem

import (
	"context"
	"errors"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

func (*DiagnosticStatusReader) ReadRunStatus(context.Context, ports.AnchoredRoot, domain.RunID) (ports.RuntimeDiagnosticRunStatus, error) {
	return ports.RuntimeDiagnosticRunStatus{}, errors.New("diagnostic query requires darwin/arm64 secure filesystem primitives")
}
