package filesystem

import "github.com/irootkernel/mulgae/internal/ports"

// DiagnosticStatusReader exposes only the bounded diagnostic run status. Raw
// provider streams and event logs remain outside the public query boundary.
type DiagnosticStatusReader struct{}

func NewDiagnosticStatusReader() *DiagnosticStatusReader { return &DiagnosticStatusReader{} }

var _ ports.RuntimeDiagnosticQuery = (*DiagnosticStatusReader)(nil)
