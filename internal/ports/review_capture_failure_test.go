package ports

import (
	"errors"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/domain"
)

func TestReviewCaptureFailurePreservesClosedDiagnostics(t *testing.T) {
	cause := errors.New("local capture detail")
	failure, err := NewReviewCaptureFailure(
		ReviewCaptureUnsupported,
		"client/e2e/example.png",
		domain.RoleLogic,
		"use role-aware binary capture",
		cause,
	)
	if err != nil {
		t.Fatal(err)
	}
	observed, ok := ReviewCaptureFailureFromError(failure)
	if !ok || observed.Code() != ReviewCaptureUnsupported || observed.Path() != "client/e2e/example.png" ||
		observed.Role() != domain.RoleLogic || observed.Hint() != "use role-aware binary capture" || !errors.Is(observed, cause) {
		t.Fatalf("capture failure = %#v, present=%t", observed, ok)
	}
}

func TestReviewCapturePolicyFailurePreservesOnlySafePolicyFacts(t *testing.T) {
	failure, err := NewReviewCapturePolicyFailure(
		"fixture.txt",
		"",
		"dangerous_provider_instruction",
		"content-detector.v1",
		errors.New("untrusted bytes are not retained"),
	)
	if err != nil {
		t.Fatal(err)
	}
	if failure.Code() != ReviewCapturePolicyBlocked ||
		failure.EffectiveConfiguration() != "detector_policy=content-detector.v1; detector_code=dangerous_provider_instruction" {
		t.Fatalf("policy failure = %#v", failure)
	}
}

func TestWrapReviewCaptureFailureRetainsExistingSubtype(t *testing.T) {
	typed, err := NewReviewCaptureFailure(ReviewCaptureUnsupported, "image.png", "", "exclude it", errors.New("binary"))
	if err != nil {
		t.Fatal(err)
	}
	if wrapped := WrapReviewCaptureFailure(typed); wrapped != typed {
		t.Fatal("existing capture subtype was replaced")
	}
	generic := WrapReviewCaptureFailure(errors.New("disk failed"))
	failure, ok := ReviewCaptureFailureFromError(generic)
	if !ok || failure.Code() != ReviewCaptureFailed {
		t.Fatalf("generic wrapper = %#v, present=%t", failure, ok)
	}
	if failure.Summary() == "" || failure.EffectiveConfiguration() != "capture_policy=bounded_source_capture" {
		t.Fatalf("generic capture diagnostics = summary %q configuration %q", failure.Summary(), failure.EffectiveConfiguration())
	}
	if strings.Contains(failure.Error()+failure.Summary()+failure.EffectiveConfiguration()+failure.Hint(), "disk failed") {
		t.Fatal("generic capture diagnostics exposed the underlying error")
	}
}

func TestReviewCaptureManifestFailurePreservesFeasibilityFacts(t *testing.T) {
	t.Parallel()

	failure, err := NewReviewCaptureManifestFailure(9<<20, 8<<20, errors.New("too large"))
	if err != nil {
		t.Fatal(err)
	}
	if failure.Code() != ReviewCaptureManifestLarge ||
		failure.EffectiveConfiguration() != "member=captured-review.json; member_bytes=9437184; member_limit_bytes=8388608; provider_invoked=false" ||
		!strings.Contains(failure.Hint(), "provider was not invoked") {
		t.Fatalf("manifest failure = %#v", failure)
	}
}
