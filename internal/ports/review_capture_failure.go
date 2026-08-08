package ports

import (
	"errors"
	"fmt"
	"strings"

	"github.com/irootkernel/mulgae/internal/domain"
)

// ReviewCaptureFailureCode identifies the capture stage that rejected review
// input. The code is safe to expose in command diagnostics; the wrapped cause
// remains available for local troubleshooting without becoming policy input.
type ReviewCaptureFailureCode string

const (
	ReviewCaptureFailed         ReviewCaptureFailureCode = "capture_failed"
	ReviewCaptureUnsupported    ReviewCaptureFailureCode = "unsupported_content"
	ReviewCapturePolicyBlocked  ReviewCaptureFailureCode = "content_policy_blocked"
	ReviewCaptureManifestLarge  ReviewCaptureFailureCode = "capture_manifest_too_large"
	ReviewCaptureWorkspaceLarge ReviewCaptureFailureCode = "capture_workspace_too_large"
)

func (code ReviewCaptureFailureCode) Valid() bool {
	switch code {
	case ReviewCaptureFailed, ReviewCaptureUnsupported, ReviewCapturePolicyBlocked, ReviewCaptureManifestLarge, ReviewCaptureWorkspaceLarge:
		return true
	default:
		return false
	}
}

// NewReviewCaptureWorkspaceFailure reports bounded workspace admission facts
// without exposing captured paths or bytes.
func NewReviewCaptureWorkspaceFailure(admission *WorkspaceAdmissionFailure) (*ReviewCaptureFailure, error) {
	if admission == nil {
		return nil, fmt.Errorf("review capture failure: invalid workspace admission")
	}
	failure, err := NewReviewCaptureFailure(
		ReviewCaptureWorkspaceLarge,
		"",
		"",
		"reduce captured content with .mulgaeignore; the provider was not invoked",
		admission,
	)
	if err != nil {
		return nil, err
	}
	failure.summary = "the captured workspace exceeds its admission limit"
	failure.effectiveConfiguration = fmt.Sprintf(
		"admission_stage=%s; member=%s; file_count=%d; byte_count=%d; max_files=%d; max_bytes=%d; provider_invoked=false",
		admission.Stage(), admission.Member(), admission.FileCount(), admission.ByteCount(), admission.MaxFiles(), admission.MaxBytes(),
	)
	return failure, nil
}

// NewReviewCaptureManifestFailure reports exact execution-free publication
// feasibility facts without exposing source paths or bytes.
func NewReviewCaptureManifestFailure(actualBytes, limitBytes int64, cause error) (*ReviewCaptureFailure, error) {
	if actualBytes <= limitBytes || limitBytes <= 0 || cause == nil {
		return nil, fmt.Errorf("review capture failure: invalid manifest size facts")
	}
	failure, err := NewReviewCaptureFailure(
		ReviewCaptureManifestLarge,
		"",
		"",
		"reduce captured path metadata with .mulgaeignore; the provider was not invoked",
		cause,
	)
	if err != nil {
		return nil, err
	}
	failure.summary = "the captured review manifest exceeds its publication member limit"
	failure.effectiveConfiguration = fmt.Sprintf(
		"member=captured-review.json; member_bytes=%d; member_limit_bytes=%d; provider_invoked=false",
		actualBytes,
		limitBytes,
	)
	return failure, nil
}

// ReviewCaptureFailure preserves closed, actionable facts about a failed input
// capture. Path and role are optional because repository-wide capture can fail
// before either value is known.
type ReviewCaptureFailure struct {
	code                   ReviewCaptureFailureCode
	path                   string
	role                   domain.Role
	hint                   string
	summary                string
	effectiveConfiguration string
	err                    error
}

func NewReviewCapturePolicyFailure(path string, role domain.Role, detectorCode, policyIdentity string, cause error) (*ReviewCaptureFailure, error) {
	if detectorCode == "" || len(detectorCode) > 128 || strings.ContainsAny(detectorCode, "\x00\r\n") ||
		policyIdentity == "" || len(policyIdentity) > 256 || strings.ContainsAny(policyIdentity, "\x00\r\n") {
		return nil, fmt.Errorf("review capture failure: invalid policy diagnostic facts")
	}
	failure, err := NewReviewCaptureFailure(
		ReviewCapturePolicyBlocked,
		path,
		role,
		"adjust the explicitly enabled content policy or exclude the path with .mulgaeignore",
		cause,
	)
	if err != nil {
		return nil, err
	}
	failure.effectiveConfiguration = "detector_policy=" + policyIdentity + "; detector_code=" + detectorCode
	failure.summary = "the enabled content policy blocked capture"
	return failure, nil
}

func NewReviewCaptureFailure(code ReviewCaptureFailureCode, path string, role domain.Role, hint string, cause error) (*ReviewCaptureFailure, error) {
	if !code.Valid() || strings.ContainsAny(hint, "\x00\r\n") {
		return nil, fmt.Errorf("review capture failure: invalid diagnostic facts")
	}
	if path != "" {
		parsed, err := NewSafeRelativePath(path)
		if err != nil {
			return nil, fmt.Errorf("review capture failure: invalid path")
		}
		path = parsed.String()
	}
	if role != "" && !role.Valid() {
		return nil, fmt.Errorf("review capture failure: invalid role")
	}
	summary := "the capture operation failed"
	if code == ReviewCaptureUnsupported {
		summary = "the selected capture path does not support this content"
	} else if code == ReviewCaptureManifestLarge {
		summary = "the captured review manifest is too large"
	} else if code == ReviewCaptureWorkspaceLarge {
		summary = "the captured workspace is too large"
	}
	return &ReviewCaptureFailure{
		code: code, path: path, role: role, hint: strings.TrimSpace(hint),
		summary: summary, effectiveConfiguration: "capture_policy=bounded_source_capture", err: cause,
	}, nil
}

func (failure *ReviewCaptureFailure) Error() string {
	if failure == nil || !failure.code.Valid() {
		return "review capture failed"
	}
	return "review capture failed: " + string(failure.code)
}

func (failure *ReviewCaptureFailure) Unwrap() error {
	if failure == nil {
		return nil
	}
	return failure.err
}

func (failure *ReviewCaptureFailure) Code() ReviewCaptureFailureCode {
	if failure == nil {
		return ""
	}
	return failure.code
}

func (failure *ReviewCaptureFailure) Path() string {
	if failure == nil {
		return ""
	}
	return failure.path
}

func (failure *ReviewCaptureFailure) Role() domain.Role {
	if failure == nil {
		return ""
	}
	return failure.role
}

func (failure *ReviewCaptureFailure) Hint() string {
	if failure == nil {
		return ""
	}
	return failure.hint
}

func (failure *ReviewCaptureFailure) Summary() string {
	if failure == nil {
		return ""
	}
	return failure.summary
}

func (failure *ReviewCaptureFailure) EffectiveConfiguration() string {
	if failure == nil {
		return ""
	}
	return failure.effectiveConfiguration
}

func ReviewCaptureFailureFromError(err error) (*ReviewCaptureFailure, bool) {
	var failure *ReviewCaptureFailure
	if !errors.As(err, &failure) || failure == nil || !failure.code.Valid() {
		return nil, false
	}
	return failure, true
}

func WrapReviewCaptureFailure(cause error) error {
	if cause == nil {
		return nil
	}
	if _, ok := ReviewCaptureFailureFromError(cause); ok {
		return cause
	}
	if admission, ok := WorkspaceAdmissionFailureFromError(cause); ok {
		failure, err := NewReviewCaptureWorkspaceFailure(admission)
		if err == nil {
			return failure
		}
	}
	failure, err := NewReviewCaptureFailure(ReviewCaptureFailed, "", "", "inspect the capture error and retry after correcting the review target", cause)
	if err != nil {
		return cause
	}
	return failure
}
