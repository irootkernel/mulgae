package followup

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/irootkernel/kkachi-agent-review/internal/domain"
)

// Service starts immutable, finding-scoped child workflows.
type Service struct {
	sources  SourceReader
	capturer CurrentTargetCapturer
	executor ChildExecutor
}

// NewService constructs a followup service with the narrow authorities needed
// to read a committed source, capture a current target, and publish a child.
func NewService(sources SourceReader, capturer CurrentTargetCapturer, executor ChildExecutor) (*Service, error) {
	if nilInterface(sources) {
		return nil, fmt.Errorf("followup: nil source reader")
	}
	if nilInterface(capturer) {
		return nil, fmt.Errorf("followup: nil current target capturer")
	}
	if nilInterface(executor) {
		return nil, fmt.Errorf("followup: nil child executor")
	}
	return &Service{sources: sources, capturer: capturer, executor: executor}, nil
}

// StartFollowupRun reads a verified source finding, captures a fresh target,
// and creates one distinct child run. Before publication it honors cancellation.
// Once the child executor returns a valid committed result, it does not retry;
// it independently re-observes the source with cancellation detached so a late
// caller cancellation cannot obscure the committed effect.
func (service *Service) StartFollowupRun(ctx context.Context, request Request) (Result, error) {
	if service == nil {
		return Result{}, fail(ErrorInvariant, "service", "nil service", nil)
	}
	if ctx == nil {
		return Result{}, fail(ErrorInvalidRequest, "start", "nil context", nil)
	}
	if err := ctx.Err(); err != nil {
		return Result{}, fail(ErrorCancellation, "start", "context cancelled", err)
	}
	if err := validateRequest(request); err != nil {
		return Result{}, fail(ErrorInvalidRequest, "request", err.Error(), nil)
	}

	source, err := service.sources.ReadFollowupSource(ctx, request.SourceRunID, request.FindingID)
	if err != nil {
		return Result{}, classifiedFailure(ctx, ErrorSource, "source", "read verified source", err)
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return Result{}, fail(ErrorCancellation, "source", "context cancelled", ctxErr)
	}
	if err := validateSource(source, request); err != nil {
		return Result{}, fail(ErrorSource, "source", err.Error(), nil)
	}
	source = cloneSource(source)

	current, err := service.capturer.CaptureFollowupTarget(ctx, request.Target)
	if err != nil {
		return Result{}, classifiedFailure(ctx, ErrorExecution, "target", "capture current target", err)
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return Result{}, fail(ErrorCancellation, "target", "context cancelled", ctxErr)
	}
	if err := validateCurrent(current); err != nil {
		return Result{}, fail(ErrorExecution, "target", err.Error(), nil)
	}
	current.Bytes = append([]byte(nil), current.Bytes...)

	execution := Execution{
		SessionID: source.SessionID,
		Source:    cloneSource(source),
		Current: CurrentTarget{
			Identity: current.Identity,
			Bytes:    append([]byte(nil), current.Bytes...),
		},
		Objective: objectiveValue(request.Objective),
		Role:      cloneRole(request.Role),
	}
	result, err := service.executor.ExecuteFollowup(ctx, execution)
	if err != nil {
		return Result{}, classifiedFailure(ctx, ErrorExecution, "execute", "create child run", err)
	}
	if err := validateExecutionResult(result, source); err != nil {
		return Result{}, fail(ErrorInvariant, "execute", err.Error(), nil)
	}

	observed, err := service.sources.ReadFollowupSource(context.WithoutCancel(ctx), request.SourceRunID, request.FindingID)
	if err != nil {
		return Result{}, fail(ErrorMutation, "source_reobservation", "read source after child execution", err)
	}
	if err := validateSource(observed, request); err != nil {
		return Result{}, fail(ErrorMutation, "source_reobservation", err.Error(), nil)
	}
	if !sameSource(source, observed) {
		return Result{}, fail(ErrorMutation, "source_reobservation", "source changed during child execution", nil)
	}
	terminalExit, ok := result.TerminalExit()
	if !ok {
		return Result{}, fail(ErrorInvariant, "execute", "terminal exit is absent", nil)
	}
	bounded, err := NewResult(result.SessionID, result.RunID, result.FollowupArtifactURI, result.ValidatedOutput, terminalExit)
	if err != nil {
		return Result{}, fail(ErrorInvariant, "execute", err.Error(), nil)
	}
	return bounded, nil
}

func validateRequest(request Request) error {
	if _, err := domain.ParseRunID(request.SourceRunID.String()); err != nil {
		return fmt.Errorf("invalid source run ID")
	}
	if !validFindingID(request.FindingID) {
		return fmt.Errorf("invalid finding ID")
	}
	if !request.Target.Kind.valid() || strings.TrimSpace(request.Target.Value) == "" || !utf8.ValidString(request.Target.Value) || strings.ContainsAny(request.Target.Value, "\x00\r\n") {
		return fmt.Errorf("invalid target")
	}
	if request.Objective != nil && (!utf8.ValidString(*request.Objective) || len(*request.Objective) == 0 || len(*request.Objective) > 12000 || strings.ContainsAny(*request.Objective, "\x00\r\n")) {
		return fmt.Errorf("invalid objective")
	}
	if request.Role != nil && !request.Role.Valid() {
		return fmt.Errorf("invalid role")
	}
	return nil
}

func validateSource(source VerifiedSource, request Request) error {
	if !source.P2Verified {
		return fmt.Errorf("source is not P2 verified")
	}
	if source.RunID != request.SourceRunID {
		return fmt.Errorf("reader returned a different source run")
	}
	if _, err := domain.ParseSessionID(source.SessionID.String()); err != nil {
		return fmt.Errorf("invalid source session ID")
	}
	if _, err := domain.ParseRunID(source.RunID.String()); err != nil {
		return fmt.Errorf("invalid source run ID")
	}
	if _, err := domain.ParseReviewID(source.ReviewID.String()); err != nil {
		return fmt.Errorf("invalid source review ID")
	}
	if err := validateTargetIdentity(source.Target); err != nil {
		return fmt.Errorf("invalid source target: %w", err)
	}
	if source.Finding.ID != request.FindingID || !validFindingID(source.Finding.ID) || !source.Finding.Role.Valid() || len(source.Finding.Normalized) == 0 || len(source.Finding.Excerpt) == 0 {
		return fmt.Errorf("invalid source finding")
	}
	if len(source.Final) == 0 || len(source.Manifest) == 0 {
		return fmt.Errorf("source final and manifest are required")
	}
	receipt := source.Receipt
	if !validDigest(receipt.FinalSHA256) || !validDigest(receipt.ManifestSHA256) || !validDigest(receipt.FindingSHA256) || !validDigest(receipt.ExcerptSHA256) {
		return fmt.Errorf("invalid source receipt")
	}
	if receipt.FinalSHA256 != digest(source.Final) || receipt.ManifestSHA256 != digest(source.Manifest) || receipt.FindingSHA256 != digest(source.Finding.Normalized) || receipt.ExcerptSHA256 != digest(source.Finding.Excerpt) {
		return fmt.Errorf("source receipt does not match source bytes")
	}
	return nil
}

func validateCurrent(current CurrentTarget) error {
	if err := validateTargetIdentity(current.Identity); err != nil {
		return err
	}
	if current.Identity.SHA256() != digest(current.Bytes) {
		return fmt.Errorf("current target identity does not match bytes")
	}
	return nil
}

func validateTargetIdentity(identity domain.TargetIdentity) error {
	_, err := domain.NewTargetIdentity(domain.TargetIdentityInput{
		Kind: identity.Kind(), SHA256: identity.SHA256(), RepositoryID: identity.RepositoryID(),
		BaseObjectID: identity.BaseObjectID(), HeadObjectID: identity.HeadObjectID(),
		HeadTreeObjectID: identity.HeadTreeObjectID(), IndexTreeObjectID: identity.IndexTreeObjectID(),
	})
	return err
}

func validateExecutionResult(result ExecutionResult, source VerifiedSource) error {
	if result.SessionID != source.SessionID {
		return fmt.Errorf("child session differs from source session")
	}
	if _, err := domain.ParseRunID(result.RunID.String()); err != nil {
		return fmt.Errorf("invalid child run ID")
	}
	if result.RunID == source.RunID {
		return fmt.Errorf("child run must differ from source run")
	}
	if !validURI(result.FollowupArtifactURI) {
		return fmt.Errorf("invalid followup artifact URI")
	}
	if err := result.ValidateTerminalExit(); err != nil {
		return err
	}
	providerRaw := result.ValidatedOutput.ProviderRaw()
	normalizedRaw := result.ValidatedOutput.NormalizedRaw()
	if len(providerRaw) == 0 || len(normalizedRaw) == 0 ||
		result.ValidatedOutput.ProviderSHA256() != digest(providerRaw) ||
		!result.ValidatedOutput.Resolution().Valid() ||
		!result.ValidatedOutput.Role().Valid() ||
		strings.TrimSpace(result.ValidatedOutput.ProviderInstance()) == "" {
		return fmt.Errorf("missing or invalid validated followup output")
	}
	return nil
}

func validFindingID(value string) bool {
	if len(value) == 0 || len(value) > 64 || value[0] < 'A' || value[0] > 'Z' {
		return false
	}
	for _, character := range value[1:] {
		if (character < 'A' || character > 'Z') &&
			(character < '0' || character > '9') &&
			character != '_' && character != '-' {
			return false
		}
	}
	return true
}
func sameSource(left, right VerifiedSource) bool {
	return left.P2Verified == right.P2Verified &&
		left.SessionID == right.SessionID &&
		left.RunID == right.RunID &&
		left.ReviewID == right.ReviewID &&
		left.Target == right.Target &&
		left.Finding.ID == right.Finding.ID &&
		left.Finding.Role == right.Finding.Role &&
		string(left.Finding.Normalized) == string(right.Finding.Normalized) &&
		string(left.Finding.Excerpt) == string(right.Finding.Excerpt) &&
		string(left.Final) == string(right.Final) &&
		string(left.Manifest) == string(right.Manifest) &&
		left.Receipt == right.Receipt
}

func cloneSource(source VerifiedSource) VerifiedSource {
	source.Final = append([]byte(nil), source.Final...)
	source.Manifest = append([]byte(nil), source.Manifest...)
	source.Finding.Normalized = append([]byte(nil), source.Finding.Normalized...)
	source.Finding.Excerpt = append([]byte(nil), source.Finding.Excerpt...)
	return source
}

func cloneRole(role *domain.Role) *domain.Role {
	if role == nil {
		return nil
	}
	copy := *role
	return &copy
}

func objectiveValue(objective *string) string {
	if objective == nil {
		return ""
	}
	return *objective
}

func classifiedFailure(ctx context.Context, kind ErrorKind, stage, message string, err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || ctx.Err() != nil {
		return fail(ErrorCancellation, stage, message, err)
	}
	return fail(kind, stage, message, err)
}
