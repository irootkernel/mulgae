// Package report renders a human-readable projection of a committed query snapshot.
package report

import (
	"context"
	"fmt"
	"reflect"

	"github.com/irootkernel/kkachi-agent-review/internal/app/query"
	"github.com/irootkernel/kkachi-agent-review/internal/domain"
	"github.com/irootkernel/kkachi-agent-review/internal/ports"
)

const renderStage = "report.render"

// CommittedReader is the report-owned boundary for verified committed review
// data and fresh current-evidence excerpts. *query.Service satisfies it.
type CommittedReader interface {
	ReadCommitted(context.Context, ports.PublicationRun) (query.CommittedReview, error)
	RenderExcerpt(context.Context, ports.PublicationRun, string, string) ([]byte, error)
}

// Service renders a deterministic report from one P2-committed query snapshot.
type Service struct {
	reader CommittedReader
}

// NewService creates a report renderer. The query boundary is required so the
// renderer cannot consult publication artifacts or targets on its own.
func NewService(reader CommittedReader) (*Service, error) {
	if missingDependency(reader) {
		return nil, fmt.Errorf("report service: committed reader is required")
	}
	return &Service{reader: reader}, nil
}

// Report is an immutable derived report and the committed identities from
// which it was rendered.
type Report struct {
	bytes           []byte
	sessionID       domain.SessionID
	runID           domain.RunID
	reviewID        domain.ReviewID
	finalPath       ports.SafeRelativePath
	finalSHA256     string
	manifestPath    ports.SafeRelativePath
	manifestSHA256  string
	lineageEdgePath ports.SafeRelativePath
	lineageEdgeSHA  string
	epoch           uint64
	epochPath       ports.SafeRelativePath
	targetSHA256    string
}

// Bytes returns a caller-owned copy of the rendered Markdown.
func (report Report) Bytes() []byte { return append([]byte(nil), report.bytes...) }

// SessionID returns the committed source session identity.
func (report Report) SessionID() domain.SessionID { return report.sessionID }

// RunID returns the committed source run identity.
func (report Report) RunID() domain.RunID { return report.runID }

// ReviewID returns the committed source review identity.
func (report Report) ReviewID() domain.ReviewID { return report.reviewID }

// FinalPath returns the committed source final artifact path.
func (report Report) FinalPath() ports.SafeRelativePath { return report.finalPath }

// FinalSHA256 returns the committed source final artifact digest.
func (report Report) FinalSHA256() string { return report.finalSHA256 }

// ManifestPath returns the committed source manifest path.
func (report Report) ManifestPath() ports.SafeRelativePath { return report.manifestPath }

// ManifestSHA256 returns the committed source manifest digest.
func (report Report) ManifestSHA256() string { return report.manifestSHA256 }

// LineageEdgePath returns the committed source lineage edge path.
func (report Report) LineageEdgePath() ports.SafeRelativePath { return report.lineageEdgePath }

// LineageEdgeSHA256 returns the committed source lineage edge digest.
func (report Report) LineageEdgeSHA256() string { return report.lineageEdgeSHA }

// Epoch returns the committed source publication epoch.
func (report Report) Epoch() uint64 { return report.epoch }

// EpochPath returns the committed source publication epoch record path.
func (report Report) EpochPath() ports.SafeRelativePath { return report.epochPath }

// TargetSHA256 returns the committed source target digest.
func (report Report) TargetSHA256() string { return report.targetSHA256 }

// Render reads exactly one committed review through the query boundary, checks
// the defensive final bytes against that view, and renders deterministic Markdown.
func (service *Service) Render(ctx context.Context, run ports.PublicationRun) (Report, error) {
	if missingDependency(service) || missingDependency(service.reader) {
		return Report{}, reportFailure(domain.FailureArtifact, "committed reader is unavailable", nil)
	}
	if err := reportContextFailure(ctx); err != nil {
		return Report{}, err
	}
	if !run.Valid() {
		return Report{}, reportFailure(domain.FailureConfiguration, "publication run is invalid", nil)
	}

	review, err := service.reader.ReadCommitted(ctx, run)
	if err != nil {
		return Report{}, err
	}
	if err := reportContextFailure(ctx); err != nil {
		return Report{}, err
	}

	final, err := decodeReportFinal(review.FinalBytes())
	if err != nil {
		return Report{}, reportFailure(domain.FailureArtifact, "committed final report data is invalid", err)
	}
	if err := final.consistentWith(review); err != nil {
		return Report{}, reportFailure(domain.FailureArtifact, "committed final report data is inconsistent", err)
	}

	rendered, err := renderMarkdown(ctx, service.reader, run, review, final)
	if err != nil {
		return Report{}, err
	}
	return Report{
		bytes:           append([]byte(nil), rendered...),
		sessionID:       review.SessionID(),
		runID:           review.RunID(),
		reviewID:        review.ReviewID(),
		finalPath:       review.FinalPath(),
		finalSHA256:     review.FinalSHA256(),
		manifestPath:    review.ManifestPath(),
		manifestSHA256:  review.ManifestSHA256(),
		lineageEdgePath: review.LineageEdgePath(),
		lineageEdgeSHA:  review.LineageEdgeSHA256(),
		epoch:           review.Epoch(),
		epochPath:       review.EpochPath(),
		targetSHA256:    review.TargetSHA256(),
	}, nil
}

func reportContextFailure(ctx context.Context) error {
	if ctx == nil {
		return reportFailure(domain.FailureConfiguration, "report context is nil", nil)
	}
	if err := ctx.Err(); err != nil {
		return reportFailure(domain.FailureCancelled, "report request was cancelled", err)
	}
	return nil
}

func reportFailure(class domain.FailureClass, reason string, cause error) error {
	failure, err := domain.NewFailure(renderStage, class, reason, cause)
	if err != nil {
		return err
	}
	return failure
}

func missingDependency(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
