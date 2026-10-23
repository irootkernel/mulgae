package report

import (
	"context"

	"github.com/irootkernel/mulgae/internal/app/query"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

// openedSnapshot adapts an already-open query-owned snapshot to the report
// renderer's opener boundary without opening a second verification pass.
type openedSnapshot struct {
	reader query.ContentReader
}

func (snapshot openedSnapshot) WithVerifiedSnapshot(ctx context.Context, _ ports.PublicationRun, use func(context.Context, query.ContentReader) error) error {
	return use(ctx, snapshot.reader)
}

// ReadContent reuses rendering against a query-owned, receipt-bound snapshot.
func ReadContent(ctx context.Context, queries *query.Service, run ports.PublicationRun, binding domain.ProjectBinding, role string, continuation query.ContentContinuation) (query.ContentChunk, error) {
	return queries.ReadReport(ctx, run, binding, role, continuation, func(ctx context.Context, reader query.ContentReader) ([]byte, error) {
		service, err := NewService(openedSnapshot{reader: reader})
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
