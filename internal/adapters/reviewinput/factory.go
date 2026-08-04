// Package reviewinput composes the immutable root-review input boundary.
package reviewinput

import (
	"context"
	"fmt"
	"reflect"
	"sync"

	"github.com/irootkernel/mulgae/internal/app/evidence"
	"github.com/irootkernel/mulgae/internal/app/reviewrun"
	"github.com/irootkernel/mulgae/internal/ports"
)

const objectiveDetectorLabel = "objective"

// Factory captures review input before it can be exposed to a provider.
type Factory struct {
	capturer ports.ReviewTargetCapturer
	detector ports.ReviewInputContentDetector
	leases   ports.WorkspaceSnapshotLeaseFactory
}

var _ reviewrun.ImmutableInputSourceFactory = (*Factory)(nil)

// NewImmutableInputSourceFactory constructs the root-review immutable input factory.
func NewImmutableInputSourceFactory(
	capturer ports.ReviewTargetCapturer,
	detector ports.ReviewInputContentDetector,
	leases ports.WorkspaceSnapshotLeaseFactory,
) (*Factory, error) {
	if nilInterface(capturer) || nilInterface(detector) || nilInterface(leases) {
		return nil, fmt.Errorf("review input: invalid dependencies")
	}
	return &Factory{capturer: capturer, detector: detector, leases: leases}, nil
}

// NewImmutableInputSource validates a capture request and returns a source that
// can transfer exactly one captured input and workspace lease.
func (factory *Factory) NewImmutableInputSource(ctx context.Context, request reviewrun.InputCaptureRequest) (reviewrun.ImmutableInputSource, error) {
	if factory == nil || nilInterface(factory.capturer) || nilInterface(factory.detector) || nilInterface(factory.leases) {
		return nil, fmt.Errorf("review input: invalid factory")
	}
	if ctx == nil || !request.Valid() {
		return nil, fmt.Errorf("review input: invalid capture request")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return &immutableInputSource{factory: factory, request: request}, nil
}

type immutableInputSource struct {
	factory *Factory
	request reviewrun.InputCaptureRequest

	mu               sync.Mutex
	captured         bool
	quarantinedLease ports.WorkspaceSnapshotLease
}

// CaptureArchived reconstructs a P2-verified capture without consulting the
// current project filesystem. The archive itself carries no root authority.
func (factory *Factory) CaptureArchived(ctx context.Context, archive []byte, objective []byte, hasObjective bool) (reviewrun.CapturedRunInput, error) {
	if factory == nil || ctx == nil || len(archive) == 0 || (!hasObjective && len(objective) != 0) {
		return reviewrun.CapturedRunInput{}, fmt.Errorf("review input: invalid archived capture")
	}
	if err := ctx.Err(); err != nil {
		return reviewrun.CapturedRunInput{}, err
	}
	material, err := ports.UnmarshalCapturedReviewMaterial(archive)
	if err != nil {
		return reviewrun.CapturedRunInput{}, fmt.Errorf("review input: archived capture decode failed: %w", ports.WrapReviewCaptureFailure(err))
	}
	if hasObjective {
		detection, detectErr := factory.detector.DetectReviewInput(ctx, ports.ReviewInputObjective, objectiveDetectorLabel, objective)
		if detectErr != nil {
			return reviewrun.CapturedRunInput{}, fmt.Errorf("review input: archived objective detection failed: %w", ports.WrapReviewCaptureFailure(detectErr))
		}
		if !detection.Valid() {
			return reviewrun.CapturedRunInput{}, fmt.Errorf("review input: archived objective detector returned an invalid result: %w", ports.WrapReviewCaptureFailure(fmt.Errorf("invalid detector result")))
		}
		if detection.Verdict() == ports.ReviewInputBlocked {
			identified, ok := factory.detector.(ports.ReviewInputContentDetectorIdentity)
			if !ok {
				return reviewrun.CapturedRunInput{}, fmt.Errorf("review input: archived objective detector has no policy identity: %w", ports.WrapReviewCaptureFailure(fmt.Errorf("unidentified detector")))
			}
			failure, failureErr := ports.NewReviewCapturePolicyFailure("", "", detection.DetectorCode(), identified.ReviewInputDetectorIdentity(), fmt.Errorf("objective rejected by content policy"))
			if failureErr != nil {
				return reviewrun.CapturedRunInput{}, fmt.Errorf("review input: archived objective rejected")
			}
			return reviewrun.CapturedRunInput{}, fmt.Errorf("review input: archived objective rejected: %w", failure)
		}
	}
	lease, err := factory.leases.MaterializeLease(ctx, material.Snapshot())
	if err != nil || nilInterface(lease) {
		if err == nil {
			err = fmt.Errorf("workspace materializer returned no lease")
		}
		return reviewrun.CapturedRunInput{}, fmt.Errorf("review input: archived workspace materialization failed: %w", ports.WrapReviewCaptureFailure(err))
	}
	input, err := reviewrun.NewImmutableReviewInputWithCapturedArchive(material.Target(), objective, hasObjective, material.ProjectContext(), material.HasProjectContext(), archive)
	if err != nil {
		return reviewrun.CapturedRunInput{}, fmt.Errorf("review input: archived immutable input failed: %w", ports.WrapReviewCaptureFailure(err))
	}
	reader, err := newCapturedTargetReader(material)
	if err != nil {
		return reviewrun.CapturedRunInput{}, fmt.Errorf("review input: archived evidence failed: %w", ports.WrapReviewCaptureFailure(err))
	}
	captured, err := reviewrun.NewCapturedRunInput(input, lease, reader, factory.detector)
	if err != nil {
		return reviewrun.CapturedRunInput{}, fmt.Errorf("review input: archived captured input failed: %w", ports.WrapReviewCaptureFailure(err))
	}
	return captured, nil
}

var _ reviewrun.ImmutableInputSource = (*immutableInputSource)(nil)

func (source *immutableInputSource) Capture(ctx context.Context, request reviewrun.Request) (reviewrun.CapturedRunInput, error) {
	if source == nil || source.factory == nil || ctx == nil {
		return reviewrun.CapturedRunInput{}, fmt.Errorf("review input: invalid capture")
	}
	if err := ctx.Err(); err != nil {
		return reviewrun.CapturedRunInput{}, err
	}
	bound, ok := request.InputSource.(*immutableInputSource)
	if !ok || bound != source || request.ProjectRoot != source.request.Root() {
		return reviewrun.CapturedRunInput{}, fmt.Errorf("review input: capture authority mismatch")
	}

	source.mu.Lock()
	if source.captured {
		source.mu.Unlock()
		return reviewrun.CapturedRunInput{}, fmt.Errorf("review input: capture already consumed")
	}
	source.captured = true
	source.mu.Unlock()

	var material ports.CapturedReviewMaterial
	var err error
	if artistInputs, present := source.request.ArtistInputs(); present {
		artistCapturer, ok := source.factory.capturer.(ports.ArtistReviewTargetCapturer)
		if !ok {
			return reviewrun.CapturedRunInput{}, fmt.Errorf("review input: artist capture unavailable")
		}
		material, err = artistCapturer.CaptureReviewTargetWithArtistInputs(ctx, source.request.Root(), source.request.Target(), artistInputs)
	} else {
		material, err = source.factory.capturer.CaptureReviewTarget(ctx, source.request.Root(), source.request.Target())
	}
	if err != nil || !material.Valid() {
		if err == nil {
			err = fmt.Errorf("capturer returned invalid material")
		}
		return reviewrun.CapturedRunInput{}, fmt.Errorf("review input: target capture failed: %w", ports.WrapReviewCaptureFailure(err))
	}

	objective, hasObjective := source.request.Objective()
	if hasObjective {
		detection, detectErr := source.factory.detector.DetectReviewInput(ctx, ports.ReviewInputObjective, objectiveDetectorLabel, objective)
		if detectErr != nil {
			return reviewrun.CapturedRunInput{}, fmt.Errorf("review input: objective detection failed: %w", ports.WrapReviewCaptureFailure(detectErr))
		}
		if !detection.Valid() {
			return reviewrun.CapturedRunInput{}, fmt.Errorf("review input: objective detector returned an invalid result: %w", ports.WrapReviewCaptureFailure(fmt.Errorf("invalid detector result")))
		}
		if detection.Verdict() == ports.ReviewInputBlocked {
			identified, ok := source.factory.detector.(ports.ReviewInputContentDetectorIdentity)
			if !ok {
				return reviewrun.CapturedRunInput{}, fmt.Errorf("review input: objective detector has no policy identity: %w", ports.WrapReviewCaptureFailure(fmt.Errorf("unidentified detector")))
			}
			identity := identified.ReviewInputDetectorIdentity()
			failure, failureErr := ports.NewReviewCapturePolicyFailure("", "", detection.DetectorCode(), identity, fmt.Errorf("objective rejected by content policy"))
			if failureErr != nil {
				return reviewrun.CapturedRunInput{}, fmt.Errorf("review input: objective rejected")
			}
			return reviewrun.CapturedRunInput{}, fmt.Errorf("review input: objective rejected: %w", failure)
		}
	}

	lease, err := source.factory.leases.MaterializeLease(ctx, material.Snapshot())
	if err != nil || nilInterface(lease) {
		if err == nil {
			err = fmt.Errorf("workspace materializer returned no lease")
		}
		return reviewrun.CapturedRunInput{}, fmt.Errorf("review input: workspace materialization failed: %w", ports.WrapReviewCaptureFailure(err))
	}

	archive, err := ports.MarshalCapturedReviewMaterial(material)
	if err != nil {
		source.quarantine(lease)
		return reviewrun.CapturedRunInput{}, fmt.Errorf("review input: captured archive construction failed: %w", ports.WrapReviewCaptureFailure(err))
	}
	input, err := reviewrun.NewImmutableReviewInputWithCapturedArchive(material.Target(), objective, hasObjective, material.ProjectContext(), material.HasProjectContext(), archive)
	if err != nil {
		source.quarantine(lease)
		return reviewrun.CapturedRunInput{}, fmt.Errorf("review input: immutable input construction failed: %w", ports.WrapReviewCaptureFailure(err))
	}
	reader, err := newCapturedTargetReader(material)
	if err != nil {
		source.quarantine(lease)
		return reviewrun.CapturedRunInput{}, fmt.Errorf("review input: immutable evidence construction failed: %w", ports.WrapReviewCaptureFailure(err))
	}
	captured, err := reviewrun.NewCapturedRunInput(input, lease, reader, source.factory.detector)
	if err != nil {
		source.quarantine(lease)
		return reviewrun.CapturedRunInput{}, fmt.Errorf("review input: captured input construction failed: %w", ports.WrapReviewCaptureFailure(err))
	}
	return captured, nil
}

type capturedTargetReader struct {
	targetSHA256 string
	files        map[evidence.Side]map[ports.SafeRelativePath][]byte
}

func newCapturedTargetReader(material ports.CapturedReviewMaterial) (evidence.ImmutableTargetReader, error) {
	if material.Target().NoChange() {
		return nil, nil
	}
	evidenceMaterial := material.Evidence()
	reader := &capturedTargetReader{
		targetSHA256: "sha256:" + material.Target().Identity().SHA256(),
		files:        make(map[evidence.Side]map[ports.SafeRelativePath][]byte),
	}
	for capturedSide, side := range map[ports.CapturedEvidenceSide]evidence.Side{
		ports.CapturedEvidenceBase:     evidence.SideBase,
		ports.CapturedEvidenceHead:     evidence.SideHead,
		ports.CapturedEvidenceWorktree: evidence.SideWorktree,
		ports.CapturedEvidenceIndex:    evidence.SideIndex,
	} {
		files, ok := evidenceMaterial.Files(capturedSide)
		if !ok {
			continue
		}
		reader.files[side] = make(map[ports.SafeRelativePath][]byte, len(files))
		for _, file := range files {
			if !file.IsText() {
				continue
			}
			reader.files[side][file.Path()] = file.Bytes()
		}
	}
	if len(reader.files) == 0 {
		return nil, fmt.Errorf("no captured immutable evidence")
	}
	return reader, nil
}

func (reader *capturedTargetReader) ReadImmutableTarget(_ context.Context, targetSHA256 string, side evidence.Side, path ports.SafeRelativePath) (evidence.ImmutableTargetAvailability, []byte, error) {
	if reader == nil || targetSHA256 != reader.targetSHA256 || !side.Valid() || !path.Valid() {
		return evidence.ImmutableTargetUnavailable, nil, nil
	}
	files, ok := reader.files[side]
	if !ok {
		return evidence.ImmutableTargetUnavailable, nil, nil
	}
	bytes, ok := files[path]
	if !ok {
		return evidence.ImmutableTargetUnavailable, nil, nil
	}
	return evidence.ImmutableTargetAvailable, append([]byte(nil), bytes...), nil
}

var _ evidence.ImmutableTargetReader = (*capturedTargetReader)(nil)

// quarantine retains cleanup authority when no valid durable pre-P2 abort
// evidence exists. It deliberately does not fabricate an abort token.
func (source *immutableInputSource) quarantine(lease ports.WorkspaceSnapshotLease) {
	source.mu.Lock()
	defer source.mu.Unlock()
	source.quarantinedLease = lease
}

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	return (v.Kind() == reflect.Ptr || v.Kind() == reflect.Map || v.Kind() == reflect.Slice || v.Kind() == reflect.Interface || v.Kind() == reflect.Func || v.Kind() == reflect.Chan) && v.IsNil()
}
