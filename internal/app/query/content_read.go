package query

import (
	"context"
	"net/url"
	"strconv"
	"strings"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

// ContentReader confines an existing report renderer to one verified snapshot.
type ContentReader interface {
	ReadCommitted(context.Context, ports.PublicationRun) (CommittedReview, error)
	RenderExcerptAt(context.Context, ports.PublicationRun, string, string, int) ([]byte, error)
}

type contentSnapshot struct {
	service *Service
	run     ports.PublicationRun
	review  CommittedReview
	support map[string]string
}

func (snapshot contentSnapshot) ReadCommitted(ctx context.Context, run ports.PublicationRun) (CommittedReview, error) {
	if err := contextFailure(ctx, "query.read_content"); err != nil {
		return CommittedReview{}, err
	}
	if run != snapshot.run {
		return CommittedReview{}, ErrCursorMismatch
	}
	return snapshot.review, nil
}

func (snapshot contentSnapshot) RenderExcerptAt(ctx context.Context, run ports.PublicationRun, findingID, target string, index int) ([]byte, error) {
	if run != snapshot.run {
		return nil, ErrCursorMismatch
	}
	if target != snapshot.review.TargetSHA256() || index < 1 || index > 20 {
		return nil, typedFailure("query.read_content", domain.FailureConfiguration, "evidence selector is invalid", nil)
	}
	for _, finding := range snapshot.review.Findings() {
		if finding.ID() != findingID {
			continue
		}
		items := finding.Evidence()
		if index > len(items) {
			break
		}
		path, err := excerptArtifactPath(run, findingID, index)
		if err != nil {
			return nil, err
		}
		if _, present := snapshot.support[path.String()]; !present {
			return nil, typedFailure("query.read_content", domain.FailureArtifact, "evidence_unavailable", nil)
		}
		return snapshot.service.readCommittedFindingExcerpt(ctx, run, snapshot.review, findingID, index, items[index-1], snapshot.support)
	}
	return nil, typedFailure("query.read_content", domain.FailureConfiguration, "evidence index is not bound to the finding", nil)
}

// ReadReport returns an original role report or renders against the same receipt.
// The callback is the existing report service; query owns all storage observation.
func (service *Service) ReadReport(ctx context.Context, run ports.PublicationRun, binding domain.ProjectBinding, role string, continuation ContentContinuation, render func(context.Context, ContentReader) ([]byte, error)) (ContentChunk, error) {
	if role != "" && !domain.Role(role).Valid() {
		return ContentChunk{}, ErrCursorInvalid
	}
	return service.readContent(ctx, run, binding, continuation, func(snapshot contentSnapshot, identity domain.PublicationReceipt) (ContentChunk, error) {
		var data []byte
		var err error
		if role == "" {
			if render == nil {
				return ContentChunk{}, typedFailure("query.read_content", domain.FailureInternal, "report renderer is unavailable", nil)
			}
			data, err = render(ctx, snapshot)
		} else {
			found := false
			for _, report := range snapshot.review.RoleReports() {
				if report.Role() != role {
					continue
				}
				found = true
				data, err = service.readRoleReportSnapshot(ctx, run, snapshot.review, report, snapshot.support)
				break
			}
			if !found {
				return ContentChunk{}, typedFailure("query.read_content", domain.FailureArtifact, "role report is unavailable", nil)
			}
		}
		if err != nil {
			return ContentChunk{}, err
		}
		chunk, err := NewContentChunk(data, "text/markdown", true, identity, continuation)
		chunk.Role = role
		return chunk, err
	})
}

// ReadEvidence uses public zero-based indices and returns exact committed bytes.
func (service *Service) ReadEvidence(ctx context.Context, run ports.PublicationRun, binding domain.ProjectBinding, findingID, target string, index int, continuation ContentContinuation) (ContentChunk, error) {
	return service.readEvidence(ctx, run, binding, findingID, target, index, continuation, false)
}

// ReadSourceEvidence binds a stored text observation to selection metadata.
func (service *Service) ReadSourceEvidence(ctx context.Context, run ports.PublicationRun, binding domain.ProjectBinding, findingID, source string, index int, continuation ContentContinuation) (ContentChunk, error) {
	return service.readEvidence(ctx, run, binding, findingID, source, index, continuation, true)
}

func (service *Service) readEvidence(ctx context.Context, run ports.PublicationRun, binding domain.ProjectBinding, findingID, target string, index int, continuation ContentContinuation, live bool) (ContentChunk, error) {
	if !validFindingID(findingID) || !readDigestValid(target) || index < 0 || index >= 20 {
		return ContentChunk{}, ErrCursorInvalid
	}
	return service.readContent(ctx, run, binding, continuation, func(snapshot contentSnapshot, identity domain.PublicationReceipt) (ContentChunk, error) {
		if live != (snapshot.review.liveSource != nil) {
			return ContentChunk{}, ErrCursorMismatch
		}
		if live && target != snapshot.review.SourceIdentitySHA256() {
			return ContentChunk{}, ErrCursorMismatch
		}
		selector := target
		if live {
			selector = ""
		}
		data, err := snapshot.RenderExcerptAt(ctx, run, findingID, selector, index+1)
		if err != nil {
			return ContentChunk{}, err
		}
		chunk, err := NewContentChunk(data, "text/plain", true, identity, continuation)
		chunk.FindingID, chunk.EvidenceIndex = findingID, &index
		return chunk, err
	})
}

// ReadSourceImage returns an indexed selected PNG/JPEG/WebP observation as
// binary content. The original source path is never opened on this read path.
func (service *Service) ReadSourceImage(ctx context.Context, run ports.PublicationRun, binding domain.ProjectBinding, source, side, path string, continuation ContentContinuation) (ContentChunk, error) {
	if !readDigestValid(source) {
		return ContentChunk{}, ErrCursorInvalid
	}
	if _, err := ports.NewSafeRelativePath(path); err != nil {
		return ContentChunk{}, ErrCursorInvalid
	}
	return service.readContent(ctx, run, binding, continuation, func(snapshot contentSnapshot, identity domain.PublicationReceipt) (ContentChunk, error) {
		if snapshot.review.liveSource == nil || source != snapshot.review.SourceIdentitySHA256() {
			return ContentChunk{}, ErrCursorMismatch
		}
		for _, image := range snapshot.review.liveSource.BinaryEvidence {
			if image.Side != side || image.Path != path {
				continue
			}
			artifactPath, _ := ports.NewSafeRelativePath(image.ArtifactPath)
			artifact, err := service.readIndexedRuntimeArtifact(ctx, run, snapshot.review, snapshot.support, artifactPath)
			if err != nil {
				return ContentChunk{}, err
			}
			return NewContentChunk(artifact.Bytes(), image.MediaType, false, identity, continuation)
		}
		return ContentChunk{}, typedFailure("query.read_content", domain.FailureArtifact, "source image is unavailable", nil)
	})
}

func (service *Service) readContent(ctx context.Context, run ports.PublicationRun, binding domain.ProjectBinding, continuation ContentContinuation, read func(contentSnapshot, domain.PublicationReceipt) (ContentChunk, error)) (ContentChunk, error) {
	if !binding.Valid() {
		return ContentChunk{}, ErrCursorInvalid
	}
	if err := continuation.Validate(); err != nil {
		return ContentChunk{}, err
	}
	observation, err := service.observe(ctx, run, "query.read_content")
	if err != nil {
		return ContentChunk{}, err
	}
	review, receipt, support, err := service.inspectCommitted(ctx, run, binding, observation)
	if err != nil {
		return ContentChunk{}, err
	}
	identity, err := receipt.Identity()
	if err != nil {
		return ContentChunk{}, err
	}
	chunk, err := read(contentSnapshot{service, run, review, support}, identity)
	if err != nil {
		return ContentChunk{}, err
	}
	if err := service.confirmStableP2Observation(ctx, run, observation, "query.read_content"); err != nil {
		return ContentChunk{}, err
	}
	chunk.RunID = run.RunID().String()
	return chunk, nil
}

func ReportContentURI(runID, role, binding, receipt, digest string, offset int64) string {
	return contentURI("mulgae://runs/"+runID+"/report", [][2]string{{"role", role}, {"project_binding", binding}, {"publication_receipt", receipt}, {"content_sha256", digest}}, offset)
}

func EvidenceContentURI(runID, findingID, target string, index int, binding, receipt, digest string, offset int64) string {
	indexText := ""
	if index != 0 {
		indexText = strconv.Itoa(index)
	}
	return contentURI("mulgae://runs/"+runID+"/findings/"+findingID+"/evidence", [][2]string{{"target_sha256", target}, {"evidence_index", indexText}, {"project_binding", binding}, {"publication_receipt", receipt}, {"content_sha256", digest}}, offset)
}

func SourceEvidenceContentURI(runID, findingID, source string, index int, binding, receipt, digest string, offset int64) string {
	indexText := ""
	if index != 0 {
		indexText = strconv.Itoa(index)
	}
	return contentURI("mulgae://runs/"+runID+"/findings/"+findingID+"/evidence", [][2]string{{"source_identity_sha256", source}, {"evidence_index", indexText}, {"project_binding", binding}, {"publication_receipt", receipt}, {"content_sha256", digest}}, offset)
}

func SourceImageContentURI(runID, source, side, path, binding, receipt, digest string, offset int64) string {
	return contentURI("mulgae://runs/"+runID+"/source-image", [][2]string{{"source_identity_sha256", source}, {"side", side}, {"path", path}, {"project_binding", binding}, {"publication_receipt", receipt}, {"content_sha256", digest}}, offset)
}

func contentURI(base string, fields [][2]string, offset int64) string {
	parts := []string{}
	for _, field := range fields {
		if field[1] != "" {
			parts = append(parts, field[0]+"="+url.QueryEscape(field[1]))
		}
	}
	if offset != 0 {
		parts = append(parts, "offset="+strconv.FormatInt(offset, 10))
	}
	if len(parts) != 0 {
		base += "?" + strings.Join(parts, "&")
	}
	return base
}
