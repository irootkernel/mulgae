package report

import (
	"context"

	"github.com/irootkernel/mulgae/internal/app/query"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

// ReadContent reuses rendering against a query-owned, receipt-bound snapshot.
func ReadContent(ctx context.Context, queries *query.Service, run ports.PublicationRun, binding domain.ProjectBinding, role string, continuation query.ContentContinuation) (query.ContentChunk, error) {
	return queries.ReadReport(ctx, run, binding, role, continuation, func(ctx context.Context, reader query.ContentReader) ([]byte, error) {
		service, err := NewService(reader)
		if err != nil {
			return nil, err
		}
		report, err := service.Render(ctx, run)
		if err != nil {
			return nil, err
		}
		return report.Bytes(), nil
	})
}
