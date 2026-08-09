package mulgae

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/irootkernel/mulgae/internal/adapters/cli"
	"github.com/irootkernel/mulgae/internal/app"
	appdelta "github.com/irootkernel/mulgae/internal/app/delta"
	"github.com/irootkernel/mulgae/internal/app/doctor"
	appfollowup "github.com/irootkernel/mulgae/internal/app/followup"
	appinit "github.com/irootkernel/mulgae/internal/app/init"
	apppublication "github.com/irootkernel/mulgae/internal/app/publication"
	appquery "github.com/irootkernel/mulgae/internal/app/query"
	appreport "github.com/irootkernel/mulgae/internal/app/report"
	appreplay "github.com/irootkernel/mulgae/internal/app/rerun"
	"github.com/irootkernel/mulgae/internal/app/review"
	"github.com/irootkernel/mulgae/internal/app/reviewrun"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

// RequestIDGenerator creates the request identifier bound into a parsed command
// request and its command-result envelope.
type RequestIDGenerator interface {
	NewRequestID(time.Time) (string, error)
}

// PublicationQueryService is the command-facing projection of the durable
// G006 query API. It deliberately accepts an already anchored artifact root so
// command handlers cannot discover publication files themselves.
type PublicationQueryService interface {
	ResolveRun(context.Context, ports.AnchoredRoot, domain.RunID) (ports.PublicationRun, error)
	ReadRunStatus(context.Context, ports.PublicationRun) (RunStatusView, error)
	ListFindings(context.Context, ports.PublicationRun, domain.Severity) (FindingsView, error)
	RenderExcerpt(context.Context, ports.PublicationRun, string, string) ([]byte, error)
}

// RunStatusView is the safe status projection returned by PublicationQueryService.
// FinalArtifactURI and the independent outcome axes are present only after a P2
// committed read. HasAxes makes the three axes an all-or-none projection.
// RoleReportURIs are present only after independently verified P2 support checks.
type RunStatusView struct {
	SessionID        string
	RunID            string
	RunState         domain.RunState
	HasRunState      bool
	PublicationState domain.PublicationStatus
	RecoveryAction   domain.RecoveryAction
	FinalArtifactURI string
	HasFinalArtifact bool
	ContentVerdict   domain.ContentVerdict
	CoverageStatus   domain.CoverageStatus
	CIDecision       domain.CIDecision
	HasAxes          bool
	RoleReportURIs   []RoleReportURI
}

// FindingView is one finding in the query service's preserved final order.
type FindingView struct {
	ID       string
	Severity domain.Severity
	Title    string
}

// FindingsView is a committed finding selection and its committed review URI.
type FindingsView struct {
	RunID             string
	Findings          []FindingView
	ReviewArtifactURI string
}

// PublicationReportService is the command-facing projection of the G006 report
// renderer. SourceIDs bind a persisted report to its committed inputs.
type PublicationReportService interface {
	Render(context.Context, ports.PublicationRun) (RenderedReport, error)
}

// RenderedReport is an immutable report projection for one committed run.
type RenderedReport struct {
	Markdown  []byte
	RunID     string
	SourceIDs []string
}

// NewPublicationQueryService adapts the existing query service to the narrow
// command boundary. A nil service remains nil so optional-group validation can
// distinguish an absent service from a complete G006 dependency group.
func NewPublicationQueryService(service *appquery.Service) PublicationQueryService {
	if service == nil {
		return nil
	}
	return publicationQueryAdapter{service: service}
}

type publicationQueryAdapter struct {
	service *appquery.Service
}

func (adapter publicationQueryAdapter) ResolveRun(
	ctx context.Context,
	root ports.AnchoredRoot,
	runID domain.RunID,
) (ports.PublicationRun, error) {
	return adapter.service.ResolveRun(ctx, root, runID)
}

func (adapter publicationQueryAdapter) ReadRunStatus(
	ctx context.Context,
	run ports.PublicationRun,
) (RunStatusView, error) {
	status, err := adapter.service.ReadRunStatus(ctx, run)
	if err != nil {
		return RunStatusView{}, err
	}
	view := RunStatusView{
		SessionID:        status.SessionID().String(),
		RunID:            status.RunID().String(),
		PublicationState: status.PublicationStatus(),
		RecoveryAction:   status.RecoveryAction(),
	}
	if runState, available := status.RunState(); available {
		view.RunState = runState
		view.HasRunState = true
	}
	if status.PublicationStatus() == domain.PublicationCommitted {
		if finalPath, available := status.FinalPath(); available {
			view.FinalArtifactURI = ".mulgae/" + finalPath.String()
			view.HasFinalArtifact = true
		}
		content, hasContent := status.ContentVerdict()
		coverage, hasCoverage := status.CoverageStatus()
		ci, hasCI := status.CIDecision()
		if hasContent && hasCoverage && hasCI && content.Valid() && coverage.Valid() && ci.Valid() {
			view.ContentVerdict = content
			view.CoverageStatus = coverage
			view.CIDecision = ci
			view.HasAxes = true
		}
		for _, report := range status.RoleReportURIs() {
			view.RoleReportURIs = append(view.RoleReportURIs, RoleReportURI{Role: report.Role, URI: report.URI})
		}
	}
	return view, nil
}

func (adapter publicationQueryAdapter) ListFindings(
	ctx context.Context,
	run ports.PublicationRun,
	minimum domain.Severity,
) (FindingsView, error) {
	review, err := adapter.service.ReadCommitted(ctx, run)
	if err != nil {
		return FindingsView{}, err
	}
	findings, err := adapter.service.ListFindings(ctx, run, minimum)
	if err != nil {
		return FindingsView{}, err
	}
	view := FindingsView{
		RunID:             review.RunID().String(),
		Findings:          make([]FindingView, len(findings)),
		ReviewArtifactURI: ".mulgae/" + review.FinalPath().String(),
	}
	for index, finding := range findings {
		view.Findings[index] = FindingView{
			ID:       finding.ID(),
			Severity: finding.Severity(),
			Title:    finding.Title(),
		}
	}
	return view, nil
}

func (adapter publicationQueryAdapter) RenderExcerpt(
	ctx context.Context,
	run ports.PublicationRun,
	findingID string,
	targetSHA256 string,
) ([]byte, error) {
	return adapter.service.RenderExcerpt(ctx, run, findingID, targetSHA256)
}

// NewPublicationReportService adapts the existing report service to the narrow
// command boundary. A nil service remains nil so optional-group validation can
// distinguish an absent service from a complete G006 dependency group.
func NewPublicationReportService(service *appreport.Service) PublicationReportService {
	if service == nil {
		return nil
	}
	return publicationReportAdapter{service: service}
}

type publicationReportAdapter struct {
	service *appreport.Service
}

func (adapter publicationReportAdapter) Render(
	ctx context.Context,
	run ports.PublicationRun,
) (RenderedReport, error) {
	rendered, err := adapter.service.Render(ctx, run)
	if err != nil {
		return RenderedReport{}, err
	}
	return RenderedReport{
		Markdown: cloneApplicationBytes(rendered.Bytes()),
		RunID:    rendered.RunID().String(),
		SourceIDs: []string{
			"report:review:" + rendered.ReviewID().String(),
			"report:final:" + rendered.FinalSHA256(),
			"report:manifest:" + rendered.ManifestSHA256(),
			"report:lineage:" + rendered.LineageEdgeSHA256(),
			"report:epoch:" + strconv.FormatUint(rendered.Epoch(), 10),
		},
	}, nil
}

// StartedRun is the authoritative projection of a newly started child workflow.
type StartedRun struct {
	SessionID                  string
	RunID                      string
	ArtifactURI                string
	FollowupResolution         *domain.FollowupResolution
	StructuredExtractionStatus domain.StructuredExtractionStatus
	RoleReportURIs             []RoleReportURI
	TerminalExit               domain.OperationalExitDecision
}

// FollowupRunService is the command-facing followup workflow boundary.
type FollowupRunService interface {
	StartFollowupRun(context.Context, appfollowup.Request) (StartedRun, error)
}

// DeltaRunService is the command-facing delta workflow boundary.
type DeltaRunService interface {
	StartDeltaRun(context.Context, appdelta.StartRequest) (StartedRun, error)
}

// RerunService is the command-facing rerun workflow boundary.
type RerunService interface {
	StartRerun(context.Context, appreplay.Request) (StartedRun, error)
}

// ReviewRunService is the command-facing independent review workflow boundary.
// It receives the parsed immutable request and an already anchored project root;
// it owns all provider execution and P2 publication authority.
type ReviewRunService interface {
	StartReviewRun(context.Context, ReviewRequest, ports.AnchoredRoot) (ReviewRunResult, error)
}

// ReviewRunServicePreparer is the optional lazy-composition boundary used by
// the standalone binary. Preparation happens only for review, but before the
// handler creates the private publication directory.
type ReviewRunServicePreparer interface {
	PrepareReviewRun(context.Context, ports.AnchoredRoot) (ReviewRunService, error)
}

// RoleReportURI is one project-relative role-report projection.
type RoleReportURI struct {
	Role string
	URI  string
}

// ReviewRunResult is the immutable terminal P2 projection returned by ReviewRunService.
type ReviewRunResult struct {
	sessionID         string
	runID             string
	runManifestURI    string
	reviewArtifactURI string
	roleReportURIs    []RoleReportURI
	terminalExit      domain.OperationalExitDecision
	terminalFailures  []reviewrun.ProviderExecutionFailure
}

// NewReviewRunResult creates an immutable terminal review projection.
func NewReviewRunResult(
	sessionID string,
	runID string,
	runManifestURI string,
	reviewArtifactURI string,
	terminalExit domain.OperationalExitDecision,
) ReviewRunResult {
	return ReviewRunResult{
		sessionID:         sessionID,
		runID:             runID,
		runManifestURI:    runManifestURI,
		reviewArtifactURI: reviewArtifactURI,
		terminalExit:      terminalExit,
	}
}

func newReviewRunResultWithFailures(
	sessionID, runID, runManifestURI, reviewArtifactURI string,
	terminalExit domain.OperationalExitDecision,
	failures []reviewrun.ProviderExecutionFailure,
	roleReportURIs []RoleReportURI,
) ReviewRunResult {
	result := NewReviewRunResult(sessionID, runID, runManifestURI, reviewArtifactURI, terminalExit)
	result.terminalFailures = append([]reviewrun.ProviderExecutionFailure(nil), failures...)
	result.roleReportURIs = append([]RoleReportURI(nil), roleReportURIs...)
	return result
}

// SessionID returns the terminal review session ID.
func (result ReviewRunResult) SessionID() string { return result.sessionID }

// RunID returns the terminal review run ID.
func (result ReviewRunResult) RunID() string { return result.runID }

// RunManifestURI returns the persisted run manifest URI.
func (result ReviewRunResult) RunManifestURI() string { return result.runManifestURI }

// ReviewArtifactURI returns the persisted final review artifact URI.
func (result ReviewRunResult) ReviewArtifactURI() string { return result.reviewArtifactURI }

// RoleReportURIs returns caller-owned project-relative role report URIs.
func (result ReviewRunResult) RoleReportURIs() []RoleReportURI {
	return append([]RoleReportURI(nil), result.roleReportURIs...)
}

// TerminalExit returns the reduced committed P2 exit authority.
func (result ReviewRunResult) TerminalExit() domain.OperationalExitDecision {
	return result.terminalExit
}

func (result ReviewRunResult) TerminalProviderFailures() []reviewrun.ProviderExecutionFailure {
	return append([]reviewrun.ProviderExecutionFailure(nil), result.terminalFailures...)
}

// Validate verifies that the result can safely be represented in the review command envelope.
func (result ReviewRunResult) Validate() error {
	if _, err := domain.ParseSessionID(result.sessionID); err != nil ||
		!validCommandRunID(result.runID) ||
		!validCommandURI(result.runManifestURI) ||
		!validCommandURI(result.reviewArtifactURI) {
		return errors.New("invalid review result")
	}
	seenRoles := make(map[string]struct{}, len(result.roleReportURIs))
	prefix := ".mulgae/" + result.sessionID + "/" + result.runID + "/role-reports/"
	for _, report := range result.roleReportURIs {
		if !validRole(report.Role) || !validCommandURI(report.URI) ||
			report.URI != prefix+report.Role+".md" {
			return errors.New("invalid review role report URI")
		}
		if _, duplicate := seenRoles[report.Role]; duplicate {
			return errors.New("duplicate review role report URI")
		}
		seenRoles[report.Role] = struct{}{}
	}
	if _, _, err := committedTerminalOutcome(result.terminalExit); err != nil {
		return fmt.Errorf("invalid review terminal exit: %w", err)
	}
	for _, failure := range result.terminalFailures {
		var err error
		if facts, ok := failure.ProviderTimeoutFacts(); ok {
			_, err = reviewrun.NewProviderExecutionFailureWithTimeoutFacts(
				failure.ProviderInstance(), failure.Role(), failure.ReasonCode(), failure.FailureClass(), facts,
			)
		} else {
			_, err = reviewrun.NewProviderExecutionFailure(failure.ProviderInstance(), failure.Role(), failure.ReasonCode(), failure.FailureClass())
		}
		if err != nil {
			return fmt.Errorf("invalid review terminal provider failure: %w", err)
		}
	}
	return nil
}

// ReviewRunInputSourceFactory is the application-owned immutable capture
// factory. The entrypoint maps command values into its typed request only.
type ReviewRunInputSourceFactory = reviewrun.ImmutableInputSourceFactory

// NewReviewRunService adapts the provider-neutral review-run service to the
// command boundary. Nil and typed-nil dependencies preserve the optional review
// provider-unavailable path.
func NewReviewRunService(service *reviewrun.Service, factory ReviewRunInputSourceFactory) ReviewRunService {
	if service == nil || nilApplicationDependency(factory) {
		return nil
	}
	return reviewRunAdapter{service: service, factory: factory}
}

// NewUnavailableReviewRunService retains a safe, typed composition diagnostic
// when production review authority could not be composed. It is deliberately a
// service rather than a nil dependency so review failures remain actionable.
func NewUnavailableReviewRunService(cause error) ReviewRunService {
	failure, err := domain.NewFailure(
		"review.composition",
		reducedFailureClass(cause, domain.FailureConfiguration),
		"production review authority is unavailable",
		cause,
	)
	if err != nil {
		return nil
	}
	return unavailableReviewRunService{failure: failure}
}

type unavailableReviewRunService struct{ failure *domain.Failure }

func (service unavailableReviewRunService) StartReviewRun(
	context.Context,
	ReviewRequest,
	ports.AnchoredRoot,
) (ReviewRunResult, error) {
	return ReviewRunResult{}, service.failure
}

// NewPolicyReviewRunService binds the resolved production role policy at the
// command boundary. An omitted --roles selects every enabled project role;
// an explicit --roles selects exactly that enabled non-empty subset.
func NewPolicyReviewRunService(service ReviewRunService, _ []domain.Role, enabled map[domain.Role]bool) ReviewRunService {
	return newPolicyReviewRunService(service, enabled, ports.ArtistReviewInputs{}, false)
}

// NewPolicyReviewRunServiceWithArtistInputs binds Config v1 artist inputs as
// review defaults. Request-scoped values are resolved after role selection.
func NewPolicyReviewRunServiceWithArtistInputs(service ReviewRunService, _ []domain.Role, enabled map[domain.Role]bool, artistInputs ports.ArtistReviewInputs) ReviewRunService {
	return newPolicyReviewRunService(service, enabled, artistInputs, true)
}

func newPolicyReviewRunService(service ReviewRunService, enabled map[domain.Role]bool, artistInputs ports.ArtistReviewInputs, hasArtistInputs bool) ReviewRunService {
	if nilApplicationDependency(service) {
		return nil
	}
	if hasArtistInputs && !artistInputs.Valid() {
		return NewUnavailableReviewRunService(errors.New("production artist defaults are invalid"))
	}
	enabledCopy := make(map[domain.Role]bool, len(enabled))
	for role, allowed := range enabled {
		enabledCopy[role] = allowed
	}
	return policyReviewRunService{service: service, enabled: enabledCopy, artistInputs: artistInputs, hasArtistInputs: hasArtistInputs}
}

type policyReviewRunService struct {
	service         ReviewRunService
	enabled         map[domain.Role]bool
	artistInputs    ports.ArtistReviewInputs
	hasArtistInputs bool
}

func (service policyReviewRunService) StartReviewRun(
	ctx context.Context,
	request ReviewRequest,
	root ports.AnchoredRoot,
) (ReviewRunResult, error) {
	request, err := ResolveReviewPolicyRequest(request, service.enabled, service.artistInputs, service.hasArtistInputs)
	if err != nil {
		reason := "requested role is not enabled by production policy"
		switch {
		case errors.Is(err, errArtistInputsRequired):
			reason = "artist review inputs are required"
		case errors.Is(err, errArtistRoleRequired):
			reason = "artist inputs require the artist role"
		}
		failure, _ := domain.NewFailure("review.policy", domain.FailureConfiguration, reason, err)
		return ReviewRunResult{}, failure
	}
	return service.service.StartReviewRun(ctx, request, root)
}

var (
	errRoleNotEnabled       = errors.New("requested role is not enabled by production policy")
	errArtistInputsRequired = errors.New("artist review inputs are required")
	errArtistRoleRequired   = errors.New("artist inputs require the artist role")
)

// ResolveReviewPolicyRequest is the shared normal-run and preflight authority
// for enabled-role selection plus Config v1 artist defaults and request-scoped
// overrides. The returned request is canonical and explicitly selected.
func ResolveReviewPolicyRequest(request ReviewRequest, enabled map[domain.Role]bool, artistInputs ports.ArtistReviewInputs, hasArtistInputs bool) (ReviewRequest, error) {
	if hasArtistInputs && !artistInputs.Valid() {
		return ReviewRequest{}, errors.New("production artist defaults are invalid")
	}
	selected := make(map[domain.Role]bool, len(request.roles))
	if request.rolesExplicit {
		for _, raw := range request.roles {
			role := domain.Role(raw)
			if !role.Valid() || !enabled[role] {
				return ReviewRequest{}, errRoleNotEnabled
			}
			selected[role] = true
		}
	} else {
		for _, role := range domain.FixedRoleOrder() {
			if enabled[role] {
				selected[role] = true
			}
		}
	}
	request.roles = request.roles[:0]
	for _, role := range domain.FixedRoleOrder() {
		if selected[role] {
			request.roles = append(request.roles, string(role))
		}
	}
	if selected[domain.RoleArtist] {
		briefPath := ""
		var designGlobs []string
		if hasArtistInputs {
			briefPath = artistInputs.BriefPath()
			designGlobs = artistInputs.DesignSpecGlobs()
		}
		if request.hasArtistBrief {
			briefPath = request.artistBriefPath
		}
		if len(request.artistDesignGlobs) != 0 {
			designGlobs = cloneStrings(request.artistDesignGlobs)
		}
		resolved, err := ports.NewArtistReviewInputs(briefPath, designGlobs)
		if err != nil {
			return ReviewRequest{}, errors.Join(errArtistInputsRequired, err)
		}
		request.artistBriefPath, request.hasArtistBrief = resolved.BriefPath(), true
		request.artistDesignGlobs = resolved.DesignSpecGlobs()
	} else if request.hasArtistBrief || len(request.artistDesignGlobs) != 0 {
		return ReviewRequest{}, errArtistRoleRequired
	}
	request.rolesExplicit = true
	return request, nil
}

type reviewRunAdapter struct {
	service *reviewrun.Service
	factory ReviewRunInputSourceFactory
}

func (adapter reviewRunAdapter) StartReviewRun(
	ctx context.Context,
	request ReviewRequest,
	root ports.AnchoredRoot,
) (ReviewRunResult, error) {
	if ctx == nil {
		return ReviewRunResult{}, errors.New("review run: context is required")
	}
	if err := ctx.Err(); err != nil {
		return ReviewRunResult{}, err
	}
	if !validReviewRunRequest(request) || !root.Valid() {
		return ReviewRunResult{}, errors.New("review run: malformed request")
	}

	targetSelector, err := ports.NewReviewTargetSelector(ports.ReviewTargetSelectorKind(request.Target().Kind()), request.Target().Value())
	if err != nil {
		return ReviewRunResult{}, err
	}
	objective, hasObjective := request.Objective()
	var captureRequest reviewrun.InputCaptureRequest
	if containsString(request.roles, string(domain.RoleArtist)) {
		artistInputs, artistErr := ports.NewArtistReviewInputs(request.artistBriefPath, request.artistDesignGlobs)
		if artistErr != nil {
			return ReviewRunResult{}, artistErr
		}
		captureRequest, err = reviewrun.NewInputCaptureRequestWithArtistInputs(root, targetSelector, []byte(objective), hasObjective, artistInputs)
	} else {
		captureRequest, err = reviewrun.NewInputCaptureRequest(root, targetSelector, []byte(objective), hasObjective)
	}
	if err != nil {
		return ReviewRunResult{}, err
	}
	source, err := adapter.factory.NewImmutableInputSource(ctx, captureRequest)
	if err != nil {
		return ReviewRunResult{}, ports.WrapReviewCaptureFailure(err)
	}
	if nilApplicationDependency(source) {
		return ReviewRunResult{}, errors.New("review run: immutable input source is required")
	}
	roles := request.Roles()
	selected := make([]domain.Role, len(roles))
	for index, role := range roles {
		selected[index] = domain.Role(role)
	}
	var session *domain.SessionID
	if value, present := request.SessionID(); present {
		parsed, parseErr := domain.ParseSessionID(value)
		if parseErr != nil {
			return ReviewRunResult{}, fmt.Errorf("review run: invalid session ID: %w", parseErr)
		}
		session = &parsed
	}
	selection, err := reviewrun.NewRunSelection(selected, session)
	if err != nil {
		return ReviewRunResult{}, err
	}
	_, artifactRoot, err := publicationRoots(root.String())
	if err != nil {
		return ReviewRunResult{}, err
	}
	result, err := adapter.service.Execute(ctx, reviewrun.Request{InputSource: source, ProjectRoot: root, ArtifactRoot: artifactRoot, Selection: selection})
	if err != nil {
		return ReviewRunResult{}, err
	}
	return projectReviewRunResult(result)
}

func validReviewRunRequest(request ReviewRequest) bool {
	switch request.target.kind {
	case "workspace", "stage", "dirty", "diff", "patch", "stdin":
	default:
		return false
	}
	if !validTargetValue(request.target.value) || request.hasObjective && !validObjective(request.objective) || len(request.roles) == 0 {
		return false
	}
	if request.hasArtistBrief != (request.artistBriefPath != "") || request.hasArtistBrief && !validRelativePath(request.artistBriefPath) {
		return false
	}
	seenArtistGlobs := make(map[string]struct{}, len(request.artistDesignGlobs))
	for _, pattern := range request.artistDesignGlobs {
		if !validArtistGlob(pattern) {
			return false
		}
		if _, duplicate := seenArtistGlobs[pattern]; duplicate {
			return false
		}
		seenArtistGlobs[pattern] = struct{}{}
	}
	if len(request.artistDesignGlobs) > 16 {
		return false
	}
	if (request.hasArtistBrief || len(request.artistDesignGlobs) != 0) && !containsString(request.roles, "artist") {
		return false
	}
	for _, role := range request.roles {
		if !validRole(role) {
			return false
		}
	}
	if request.hasSessionID {
		if _, err := domain.ParseSessionID(request.sessionID); err != nil {
			return false
		}
	}
	return true
}

func projectReviewRunResult(result reviewrun.Result) (ReviewRunResult, error) {
	sessionID, runID := result.SessionID().String(), result.RunID().String()
	final, snapshot := result.Final(), result.Snapshot()
	if _, err := domain.ParseSessionID(sessionID); err != nil || !validCommandRunID(runID) || !final.Valid() || !snapshot.Valid() ||
		snapshot.Final().Identity() != final {
		return ReviewRunResult{}, errors.New("review run: incomplete P2 result")
	}
	prefix := sessionID + "/" + runID + "/"
	manifestPath, reviewPath := snapshot.Manifest().Path().String(), final.Path().String()
	if !strings.HasPrefix(manifestPath, prefix) || !strings.HasPrefix(reviewPath, prefix) {
		return ReviewRunResult{}, errors.New("review run: incoherent P2 result")
	}
	terminalExit := result.TerminalExit()
	if _, _, err := committedTerminalOutcome(terminalExit); err != nil {
		return ReviewRunResult{}, fmt.Errorf("review run: terminal exit: %w", err)
	}
	failures := make([]reviewrun.ProviderExecutionFailure, 0)
	successful := make(map[string]review.CoordinatorRoleSummary)
	for _, summary := range result.Coordinator().RoleSummaries() {
		if summary.Valid() {
			if len(summary.ReportMarkdown()) == 0 {
				return ReviewRunResult{}, errors.New("review run: successful role missing report")
			}
			successful[string(summary.Role())] = summary
			continue
		}
		attempts := summary.Attempts()
		if len(attempts) == 0 {
			return ReviewRunResult{}, errors.New("review run: terminal role has no attempts")
		}
		terminalAttempt := attempts[len(attempts)-1]
		var failure reviewrun.ProviderExecutionFailure
		var err error
		if facts, ok := terminalAttempt.ProviderTimeoutFacts(); ok {
			failure, err = reviewrun.NewProviderExecutionFailureWithTimeoutFacts(
				terminalAttempt.Route().ProviderInstance(), summary.Role(), summary.ReasonCode(), summary.FailureClass(), facts,
			)
		} else {
			failure, err = reviewrun.NewProviderExecutionFailure(
				terminalAttempt.Route().ProviderInstance(), summary.Role(), summary.ReasonCode(), summary.FailureClass(),
			)
		}
		if err != nil {
			return ReviewRunResult{}, err
		}
		failures = append(failures, failure)
	}
	roleReportURIs, err := projectRoleReportURIsFromReviewRun(result, successful)
	if err != nil {
		return ReviewRunResult{}, err
	}
	return newReviewRunResultWithFailures(
		sessionID,
		runID,
		".mulgae/"+manifestPath,
		".mulgae/"+reviewPath,
		terminalExit,
		failures,
		roleReportURIs,
	), nil
}

// projectRoleReportURIsFromReviewRun copies trusted role-report identities from
// reviewrun.Result. It may cross-check coordinator report bytes but must not
// derive paths from the committed manifest or live directories.
func projectRoleReportURIsFromReviewRun(
	result reviewrun.Result,
	successful map[string]review.CoordinatorRoleSummary,
) ([]RoleReportURI, error) {
	projected := result.RoleReportURIs()
	if len(successful) == 0 {
		if len(projected) != 0 {
			return nil, errors.New("review run: role report URIs present without successful roles")
		}
		return nil, nil
	}
	if len(projected) != len(successful) {
		return nil, errors.New("review run: role report URIs do not match successful roles")
	}
	uris := make([]RoleReportURI, 0, len(projected))
	seen := make(map[string]struct{}, len(projected))
	for _, report := range projected {
		summary, ok := successful[report.Role]
		if !ok {
			return nil, errors.New("review run: role report URI lacks successful role summary")
		}
		markdown := summary.ReportMarkdown()
		if report.ByteLength != len(markdown) || report.SHA256 != sha256HexDigest(markdown) {
			return nil, errors.New("review run: role report URI digest mismatch")
		}
		if _, duplicate := seen[report.Role]; duplicate {
			return nil, errors.New("review run: duplicate role report URI")
		}
		seen[report.Role] = struct{}{}
		uris = append(uris, RoleReportURI{Role: report.Role, URI: report.URI})
	}
	for role := range successful {
		if _, ok := seen[role]; !ok {
			return nil, errors.New("review run: successful role missing role report URI")
		}
	}
	return uris, nil
}

func sha256HexDigest(content []byte) string {
	sum := sha256.Sum256(content)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func followupRoleReportURIs(reports []appfollowup.RoleReportURI) []RoleReportURI {
	uris := make([]RoleReportURI, 0, len(reports))
	for _, report := range reports {
		uris = append(uris, RoleReportURI{Role: report.Role, URI: report.URI})
	}
	return uris
}

func deltaRoleReportURIs(reports []appdelta.RoleReportURI) []RoleReportURI {
	uris := make([]RoleReportURI, 0, len(reports))
	for _, report := range reports {
		uris = append(uris, RoleReportURI{Role: report.Role, URI: report.URI})
	}
	return uris
}

func rerunRoleReportURIs(reports []appreplay.RoleReportURI) []RoleReportURI {
	uris := make([]RoleReportURI, 0, len(reports))
	for _, report := range reports {
		uris = append(uris, RoleReportURI{Role: report.Role, URI: report.URI})
	}
	return uris
}

// RetentionRequest is the complete schema-backed clean command selection.
type RetentionRequest struct {
	Mode               CleanMode
	ExpectedPlanSHA256 *string
}

// RetentionResult is the authoritative mode-specific clean projection. ExplainRows
// preserve the service's deterministic explanation order for human output only;
// the frozen JSON command-result schema intentionally does not expose them.
type RetentionResult struct {
	Mode         CleanMode
	CleanPlanURI string
	PlanSHA256   string
	Applied      bool
	ExplainRows  []string
}

// RetentionService is the command-facing retention workflow boundary.
type RetentionService interface {
	PlanAndApplyRetention(context.Context, RetentionRequest) (RetentionResult, error)
}

// RedactedExportRequest is the complete schema-backed export selection.
type RedactedExportRequest struct {
	RunID       string
	OutputPath  string
	Redacted    bool
	ProjectRoot ports.AnchoredRoot
}

// RedactedExportResult is the authoritative persisted export projection.
type RedactedExportResult struct {
	ExportManifestURI string
	BundleURI         string
	Redacted          bool
}

// RedactedExportService is the command-facing export workflow boundary.
type RedactedExportService interface {
	ExportRedactedRun(context.Context, RedactedExportRequest) (RedactedExportResult, error)
}

// NewFollowupRunService adapts the followup application service to command wiring.
func NewFollowupRunService(service *appfollowup.Service) FollowupRunService {
	if service == nil {
		return nil
	}
	return followupRunAdapter{service: service}
}

type followupRunAdapter struct{ service *appfollowup.Service }

func (adapter followupRunAdapter) StartFollowupRun(ctx context.Context, request appfollowup.Request) (StartedRun, error) {
	result, err := adapter.service.StartFollowupRun(ctx, request)
	if err != nil {
		return StartedRun{}, err
	}
	if err := result.ValidateTerminalExit(); err != nil {
		return StartedRun{}, fmt.Errorf("followup result terminal exit: %w", err)
	}
	terminalExit, available := result.TerminalExit()
	if !available {
		return StartedRun{}, errors.New("followup result terminal exit is unavailable")
	}
	output := result.ValidatedOutput()
	status := output.StructuredExtractionStatus()
	var resolution *domain.FollowupResolution
	switch {
	case output.ReportsOnly() && status == domain.StructuredExtractionReportsOnly:
		if output.Resolution().Valid() {
			return StartedRun{}, errors.New("reports-only followup must not invent a resolution")
		}
	case !output.ReportsOnly() && status == domain.StructuredExtractionStructured && output.Resolution().Valid():
		value := output.Resolution()
		resolution = &value
	default:
		return StartedRun{}, errors.New("followup result extraction authority is inconsistent")
	}
	return StartedRun{
		SessionID:                  result.SessionID().String(),
		RunID:                      result.RunID().String(),
		ArtifactURI:                result.FollowupArtifactURI(),
		FollowupResolution:         resolution,
		StructuredExtractionStatus: status,
		RoleReportURIs:             followupRoleReportURIs(result.RoleReportURIs()),
		TerminalExit:               terminalExit,
	}, nil
}

// NewDeltaRunService adapts the delta application service to command wiring.
func NewDeltaRunService(service *appdelta.Service) DeltaRunService {
	if service == nil {
		return nil
	}
	return deltaRunAdapter{service: service}
}

type deltaRunAdapter struct{ service *appdelta.Service }

func (adapter deltaRunAdapter) StartDeltaRun(ctx context.Context, request appdelta.StartRequest) (StartedRun, error) {
	result, err := adapter.service.StartDeltaRun(ctx, request)
	if err != nil {
		return StartedRun{}, err
	}
	if err := result.ValidateTerminalExit(); err != nil {
		return StartedRun{}, fmt.Errorf("delta result terminal exit: %w", err)
	}
	terminalExit, available := result.TerminalExit()
	if !available {
		return StartedRun{}, errors.New("delta result terminal exit is unavailable")
	}
	return StartedRun{
		SessionID: result.SessionID.String(), RunID: result.RunID.String(), ArtifactURI: result.ReviewArtifactURI,
		RoleReportURIs: deltaRoleReportURIs(result.RoleReportURIs), TerminalExit: terminalExit,
	}, nil
}

// NewRerunService adapts the rerun application service to command wiring.
func NewRerunService(service *appreplay.Service) RerunService {
	if service == nil {
		return nil
	}
	return rerunAdapter{service: service}
}

type rerunAdapter struct{ service *appreplay.Service }

func (adapter rerunAdapter) StartRerun(ctx context.Context, request appreplay.Request) (StartedRun, error) {
	result, err := adapter.service.StartRerun(ctx, request)
	if err != nil {
		return StartedRun{}, err
	}
	if err := result.ValidateTerminalExit(); err != nil {
		return StartedRun{}, fmt.Errorf("rerun result terminal exit: %w", err)
	}
	terminalExit, available := result.TerminalExit()
	if !available {
		return StartedRun{}, errors.New("rerun result terminal exit is unavailable")
	}
	return StartedRun{
		SessionID: result.SessionID.String(), RunID: result.RunID.String(), ArtifactURI: result.PromptManifestURI,
		RoleReportURIs: rerunRoleReportURIs(result.RoleReportURIs), TerminalExit: terminalExit,
	}, nil
}

// RetentionServiceFunc adapts a command retention function to RetentionService.
type RetentionServiceFunc func(context.Context, RetentionRequest) (RetentionResult, error)

func (fn RetentionServiceFunc) PlanAndApplyRetention(ctx context.Context, request RetentionRequest) (RetentionResult, error) {
	return fn(ctx, request)
}

// RedactedExportServiceFunc adapts a command export function to RedactedExportService.
type RedactedExportServiceFunc func(context.Context, RedactedExportRequest) (RedactedExportResult, error)

func (fn RedactedExportServiceFunc) ExportRedactedRun(ctx context.Context, request RedactedExportRequest) (RedactedExportResult, error) {
	return fn(ctx, request)
}

// Dependencies are the explicit inward dependencies required by Application.
// The G006 query/report pair is optional for source compatibility, but it must
// be supplied as one complete pair. EvidenceReader is optional and absent
// authority evidence remains unverified.
type Dependencies struct {
	Clock                ports.Clock
	RequestIDGenerator   RequestIDGenerator
	RequestResolver      RequestResolver
	Catalog              ports.ContractCatalog
	JSONSchemaValidator  cli.SchemaValidator
	SecureWriter         ports.SecureFileWriter
	TrustedProjectReader ports.TrustedProjectReader
	EnvironmentInspector ports.EnvironmentInspector
	PublicationQueries   PublicationQueryService
	DiagnosticQueries    ports.RuntimeDiagnosticQuery
	PublicationReports   PublicationReportService
	FollowupRuns         FollowupRunService
	ReviewRuns           ReviewRunService
	DeltaRuns            DeltaRunService
	Reruns               RerunService
	Retention            RetentionService
	Exports              RedactedExportService
	EvidenceReader       doctor.EvidenceReader
}

// Application is the executable foundation command surface. It owns no mutable
// process state and only reaches the filesystem, Git, and environment through
// the injected ports.
type Application struct {
	clock              ports.Clock
	requestIDs         RequestIDGenerator
	requestResolver    RequestResolver
	catalog            ports.ContractCatalog
	validator          cli.SchemaValidator
	writer             ports.SecureFileWriter
	projectReader      ports.TrustedProjectReader
	inspector          ports.EnvironmentInspector
	publicationQueries PublicationQueryService
	diagnosticQueries  ports.RuntimeDiagnosticQuery
	publicationReports PublicationReportService
	followupRuns       FollowupRunService
	reviewRuns         ReviewRunService
	deltaRuns          DeltaRunService
	reruns             RerunService
	retention          RetentionService
	exports            RedactedExportService
	evidenceReader     doctor.EvidenceReader
	renderer           *cli.EnvelopeRenderer
	handlers           map[app.CommandName]applicationCommandHandler
}

// Result is the complete process projection of one invocation. Stdout and
// Stderr return caller-owned copies so a caller cannot mutate application-owned
// response bytes.
type Result struct {
	stdout []byte
	stderr []byte
	exit   app.ExitCode
}

// ResultStream identifies the process stream whose delivery failed.
type ResultStream string

const (
	// ResultStreamStdout is the command result stream.
	ResultStreamStdout ResultStream = "stdout"
	// ResultStreamStderr is the command diagnostic stream.
	ResultStreamStderr ResultStream = "stderr"
)

// ResultWriteError reports an incomplete command-result delivery.
type ResultWriteError struct {
	stream ResultStream
	cause  error
}

func (err *ResultWriteError) Error() string {
	return fmt.Sprintf("write result %s: %v", err.stream, err.cause)
}

// Unwrap returns the underlying writer failure.
func (err *ResultWriteError) Unwrap() error { return err.cause }

// Stream returns the stream whose delivery failed.
func (err *ResultWriteError) Stream() ResultStream { return err.stream }

// Stdout returns a defensive copy of command standard output.
func (result Result) Stdout() []byte { return cloneApplicationBytes(result.stdout) }

// Stderr returns a defensive copy of command standard error.
func (result Result) Stderr() []byte { return cloneApplicationBytes(result.stderr) }

// WriteTo delivers stdout and stderr without requiring callers to obtain
// defensive byte copies. Future file-backed command projections use this same
// boundary while the existing Result accessors remain compatible.
func (result Result) WriteTo(stdout, stderr io.Writer) error {
	if stdout == nil {
		return &ResultWriteError{stream: ResultStreamStdout, cause: fmt.Errorf("nil result writer")}
	}
	if stderr == nil {
		return &ResultWriteError{stream: ResultStreamStderr, cause: fmt.Errorf("nil result writer")}
	}
	if err := writeCompleteResult(stdout, result.stdout); err != nil {
		return &ResultWriteError{stream: ResultStreamStdout, cause: err}
	}
	if err := writeCompleteResult(stderr, result.stderr); err != nil {
		return &ResultWriteError{stream: ResultStreamStderr, cause: err}
	}
	return nil
}

func writeCompleteResult(destination io.Writer, value []byte) error {
	for len(value) > 0 {
		written, err := destination.Write(value)
		if written < 0 || written > len(value) {
			return io.ErrShortWrite
		}
		value = value[written:]
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

// ExitCode returns the assigned Mulgae process exit code.
func (result Result) ExitCode() app.ExitCode { return result.exit }

// NewApplication constructs the foundation CLI application. Required dependencies
// are rejected before any command can execute. The online workflow trio is one
// authority capability; resolver, review, retention, and export capabilities are
// independently optional. Optional typed-nil dependencies are normalized.
func NewApplication(dependencies Dependencies) (*Application, error) {
	return newApplication(dependencies, cli.CommandSpecs(), applicationCommandHandlers())
}

func newApplication(
	dependencies Dependencies,
	specs []cli.CommandSpec,
	handlers map[app.CommandName]applicationCommandHandler,
) (*Application, error) {
	if err := validateApplicationCommandHandlers(specs, handlers); err != nil {
		return nil, fmt.Errorf("mulgae application: command handlers: %w", err)
	}
	if nilApplicationDependency(dependencies.Clock) {
		return nil, fmt.Errorf("mulgae application: nil clock")
	}
	if nilApplicationDependency(dependencies.RequestIDGenerator) {
		return nil, fmt.Errorf("mulgae application: nil request ID generator")
	}
	if nilApplicationDependency(dependencies.Catalog) {
		return nil, fmt.Errorf("mulgae application: nil contract catalog")
	}
	if nilApplicationDependency(dependencies.JSONSchemaValidator) {
		return nil, fmt.Errorf("mulgae application: nil JSON schema validator")
	}
	if nilApplicationDependency(dependencies.SecureWriter) {
		return nil, fmt.Errorf("mulgae application: nil secure writer")
	}
	if nilApplicationDependency(dependencies.TrustedProjectReader) {
		return nil, fmt.Errorf("mulgae application: nil trusted project reader")
	}
	if nilApplicationDependency(dependencies.EnvironmentInspector) {
		return nil, fmt.Errorf("mulgae application: nil environment inspector")
	}
	if nilApplicationDependency(dependencies.PublicationQueries) != nilApplicationDependency(dependencies.PublicationReports) {
		return nil, fmt.Errorf("mulgae application: incomplete G006 service dependencies")
	}
	onlineDependencies := []any{
		dependencies.FollowupRuns,
		dependencies.DeltaRuns,
		dependencies.Reruns,
	}
	onlinePresent := 0
	for _, dependency := range onlineDependencies {
		if !nilApplicationDependency(dependency) {
			onlinePresent++
		}
	}
	if onlinePresent != 0 && onlinePresent != len(onlineDependencies) {
		return nil, fmt.Errorf("mulgae application: incomplete online G008 service dependencies")
	}
	if nilApplicationDependency(dependencies.RequestResolver) {
		dependencies.RequestResolver = nil
	}
	if nilApplicationDependency(dependencies.ReviewRuns) {
		dependencies.ReviewRuns = nil
	}
	if nilApplicationDependency(dependencies.FollowupRuns) {
		dependencies.FollowupRuns = nil
	}
	if nilApplicationDependency(dependencies.DeltaRuns) {
		dependencies.DeltaRuns = nil
	}
	if nilApplicationDependency(dependencies.Reruns) {
		dependencies.Reruns = nil
	}
	if nilApplicationDependency(dependencies.Retention) {
		dependencies.Retention = nil
	}
	if nilApplicationDependency(dependencies.Exports) {
		dependencies.Exports = nil
	}
	evidenceReader := dependencies.EvidenceReader
	if nilApplicationDependency(evidenceReader) {
		evidenceReader = nil
	}

	renderer, err := cli.NewEnvelopeRenderer(dependencies.Clock, dependencies.JSONSchemaValidator)
	if err != nil {
		return nil, fmt.Errorf("mulgae application: command envelope renderer: %w", err)
	}
	application := &Application{
		clock:              dependencies.Clock,
		requestIDs:         dependencies.RequestIDGenerator,
		requestResolver:    dependencies.RequestResolver,
		catalog:            dependencies.Catalog,
		validator:          dependencies.JSONSchemaValidator,
		writer:             dependencies.SecureWriter,
		projectReader:      dependencies.TrustedProjectReader,
		inspector:          dependencies.EnvironmentInspector,
		publicationQueries: dependencies.PublicationQueries,
		diagnosticQueries:  dependencies.DiagnosticQueries,
		publicationReports: dependencies.PublicationReports,
		followupRuns:       dependencies.FollowupRuns,
		reviewRuns:         dependencies.ReviewRuns,
		deltaRuns:          dependencies.DeltaRuns,
		reruns:             dependencies.Reruns,
		retention:          dependencies.Retention,
		exports:            dependencies.Exports,
		evidenceReader:     evidenceReader,
		renderer:           renderer,
		handlers:           cloneApplicationHandlers(handlers),
	}
	return application, nil
}

// Run parses and executes argv against canonicalDefaultRoot. It never returns
// raw adapter errors: machine output contains a validated envelope when the
// parser supplied a contract-valid request, while human failures use stderr.
func (application *Application) Run(ctx context.Context, argv []string, canonicalDefaultRoot string) Result {
	if application == nil || application.renderer == nil {
		return errorResult(app.ExitCodeInternal, "mulgae: application is unavailable")
	}
	contextUnavailable := ctx == nil

	requestID, err := application.newRequestID()
	if err != nil {
		return errorResult(app.ExitCodeInternal, "mulgae: invocation could not be created")
	}
	var invocation Invocation
	if application.requestResolver != nil {
		invocation, err = ParseResolved(ctx, cloneApplicationStrings(argv), canonicalDefaultRoot, requestID, application.requestResolver)
	} else {
		invocation, err = Parse(cloneApplicationStrings(argv), canonicalDefaultRoot, requestID)
	}
	if err != nil {
		if errors.Is(err, ErrUsage) {
			if rejectedInitJSONIntent(argv) {
				return application.renderRejectedInit(ctx, requestID)
			}
			return errorResult(app.ExitCodeUsage, "mulgae: invalid command usage")
		}
		class := reducedFailureClass(err, domain.FailureInternal)
		return errorResult(requestedExit(class), humanFailureMessage(class))
	}
	if invocation.FutureMilestone() {
		return errorResult(app.ExitCodeUsage, "mulgae: command is unavailable in this foundation milestone")
	}
	if invocation.OutputFormat() == OutputFormatJSON {
		if _, available, err := envelopeRequestJSON(invocation); err != nil {
			return errorResult(app.ExitCodeInternal, "mulgae: command result could not be rendered")
		} else if !available {
			return errorResult(app.ExitCodeUsage, "mulgae: invalid command usage")
		}
	}
	if contextUnavailable {
		return application.renderFailure(context.Background(), invocation, execution{
			failure: executionFailureFor(invocation.Command(), context.Canceled, domain.FailureCancelled),
		})
	}
	if err := ctx.Err(); err != nil {
		return application.renderFailure(envelopeContext(ctx), invocation, execution{
			failure: executionFailureFor(invocation.Command(), err, domain.FailureCancelled),
		})
	}

	execution := application.execute(ctx, invocation, canonicalDefaultRoot)
	if execution.direct != nil {
		return newResult(execution.direct.Stdout(), execution.direct.Stderr(), execution.direct.ExitCode())
	}
	if execution.failure != nil {
		return application.renderFailure(ctx, invocation, execution)
	}
	return application.renderSuccess(ctx, invocation, execution)
}

func (application *Application) renderRejectedInit(ctx context.Context, requestID string) Result {
	if ctx == nil {
		ctx = context.Background()
	}
	requestJSON, err := json.Marshal(struct {
		RequestID    string       `json:"request_id"`
		Command      string       `json:"command"`
		RequestState string       `json:"request_state"`
		OutputFormat OutputFormat `json:"output_format"`
	}{
		RequestID:    requestID,
		Command:      string(app.CommandInit),
		RequestState: "invalid",
		OutputFormat: OutputFormatJSON,
	})
	if err != nil {
		return errorResult(app.ExitCodeInternal, "mulgae: command result could not be rendered")
	}
	resultJSON, err := json.Marshal(appinit.NewRejectedRequestResult())
	if err != nil {
		return errorResult(app.ExitCodeInternal, "mulgae: command result could not be rendered")
	}
	diagnostic, err := app.NewDiagnosticWithRetryable(
		"cli.init",
		domain.FailureConfiguration,
		"init_selection_invalid",
		"The init selection is invalid.",
		false,
	)
	if err != nil {
		return errorResult(app.ExitCodeInternal, "mulgae: command result could not be rendered")
	}
	commandResult, err := app.NewCommandFailure(app.CommandInit, app.ExitCodeUsage, diagnostic)
	if err != nil {
		return errorResult(app.ExitCodeInternal, "mulgae: command result could not be rendered")
	}
	output, err := application.renderer.Render(envelopeContext(ctx), commandResult, requestJSON, resultJSON)
	if err != nil {
		return errorResult(app.ExitCodeInternal, "mulgae: command result could not be rendered")
	}
	return newResult(output, nil, app.ExitCodeUsage)
}

func (application *Application) newRequestID() (requestID string, err error) {
	defer func() {
		if recover() != nil {
			requestID = ""
			err = errors.New("request ID generator failed")
		}
	}()
	now := application.clock.Now()
	if now.IsZero() {
		return "", errors.New("clock returned zero time")
	}
	requestID, err = application.requestIDs.NewRequestID(now)
	if err != nil {
		return "", err
	}
	if !validRequestID(requestID) {
		return "", errors.New("request ID generator returned an invalid ID")
	}
	return requestID, nil
}

type execution struct {
	human                  []byte
	data                   []byte
	failureData            []byte
	failure                *executionFailure
	exit                   app.ExitCode
	committedReasons       []string
	committedReasonDetails []app.CommittedReason
	verbatim               bool
	direct                 *Result
}

type executionFailure struct {
	class                  domain.FailureClass
	code                   string
	message                string
	humanMessage           string
	retryable              bool
	hasRetryable           bool
	stage                  string
	exit                   app.ExitCode
	diagnosticURI          string
	role                   string
	provider               string
	recommendedNextCommand string
}

func (application *Application) renderSuccess(ctx context.Context, invocation Invocation, run execution) Result {
	if invocation.OutputFormat() == OutputFormatHuman {
		if run.verbatim {
			return newResult(run.human, nil, run.exit)
		}
		return newResult(terminalOutput(run.human), nil, run.exit)
	}

	request, available, requestErr := envelopeRequestJSON(invocation)
	if requestErr != nil {
		return errorResult(app.ExitCodeInternal, "mulgae: command result could not be rendered")
	}
	if !available {
		return errorResult(app.ExitCodeUsage, "mulgae: invalid command usage")
	}
	var commandResult app.CommandResult
	var err error
	if len(run.committedReasonDetails) != 0 {
		commandResult, err = app.NewCommittedCommandOutcomeWithReasons(invocation.Command(), run.exit, run.data, run.committedReasonDetails)
	} else if len(run.committedReasons) != 0 {
		commandResult, err = app.NewCommittedCommandOutcome(invocation.Command(), run.exit, run.data, run.committedReasons)
	} else {
		commandResult, err = app.NewCommandSuccess(invocation.Command(), run.data)
	}
	if err != nil {
		return application.renderFailure(context.WithoutCancel(ctx), invocation, execution{
			failure: executionFailureFor(invocation.Command(), err, domain.FailureInternal),
		})
	}
	output, err := application.renderer.Render(context.WithoutCancel(ctx), commandResult, request, nil)
	if err != nil {
		return application.renderFailure(context.WithoutCancel(ctx), invocation, execution{
			failure: executionFailureFor(invocation.Command(), err, domain.FailureInternal),
		})
	}
	return newResult(output, nil, run.exit)
}

func (application *Application) renderFailure(ctx context.Context, invocation Invocation, run execution) Result {
	failure := normalizeExecutionFailure(invocation.Command(), *run.failure)
	exit := projectedFailureExit(invocation.Command(), failure.exit)
	if invocation.OutputFormat() == OutputFormatHuman {
		if len(run.human) != 0 {
			human := appendHumanFailureDetails(run.human, failure)
			return newResult(terminalOutput(appendDiagnosticURI(human, failure.diagnosticURI)), nil, exit)
		}
		if failure.humanMessage != "" {
			human := appendHumanFailureDetails([]byte(failure.humanMessage), failure)
			return errorResult(exit, string(appendDiagnosticURI(human, failure.diagnosticURI)))
		}
		human := appendHumanFailureDetails([]byte(humanFailureMessage(failure.class)), failure)
		return errorResult(exit, string(appendDiagnosticURI(human, failure.diagnosticURI)))
	}
	request, available, requestErr := envelopeRequestJSON(invocation)
	if requestErr != nil {
		return errorResult(app.ExitCodeInternal, "mulgae: command result could not be rendered")
	}
	if !available {
		return errorResult(app.ExitCodeUsage, "mulgae: invalid command usage")
	}
	resultData := run.failureData
	var err error
	if len(resultData) == 0 {
		resultData, err = failureResultJSON(invocation)
		if err != nil {
			return errorResult(app.ExitCodeInternal, "mulgae: command result could not be rendered")
		}
	}
	message := failure.message
	if message == "" {
		message = actionableFallbackMessage(failure)
	}
	var diagnostic app.Diagnostic
	if failure.hasRetryable {
		diagnostic, err = app.NewDiagnosticWithRetryableDetails(
			failure.stage, failure.class, failure.code, message, failure.retryable,
			failure.role, failure.provider, failure.diagnosticURI, failure.recommendedNextCommand,
		)
	} else {
		diagnostic, err = app.NewDiagnostic(
			failure.stage,
			failure.class,
			failure.code,
			message,
			failure.role, failure.provider, domain.AttemptID{}, failure.diagnosticURI, failure.recommendedNextCommand,
		)
	}
	if err != nil {
		return errorResult(app.ExitCodeInternal, "mulgae: command result could not be rendered")
	}
	commandResult, err := app.NewCommandFailure(invocation.Command(), exit, diagnostic)
	if err != nil {
		return errorResult(app.ExitCodeInternal, "mulgae: command result could not be rendered")
	}
	output, err := application.renderer.Render(envelopeContext(ctx), commandResult, request, resultData)
	if err != nil {
		return errorResult(app.ExitCodeInternal, "mulgae: command result could not be rendered")
	}
	return newResult(output, nil, exit)
}

func normalizeExecutionFailure(command app.CommandName, failure executionFailure) executionFailure {
	if failure.code == "" {
		failure.code = "internal_failure"
	}
	if failure.stage == "" {
		failure.stage = "cli." + string(command)
	}
	if failure.recommendedNextCommand == "" {
		switch failure.class {
		case domain.FailureCancelled:
			failure.recommendedNextCommand = "retry the command when ready"
		default:
			failure.recommendedNextCommand = "mulgae doctor"
		}
	}
	return failure
}

func actionableFallbackMessage(failure executionFailure) string {
	return fmt.Sprintf(
		"%s Failure at stage %s with code %s; hint: %s.",
		stableFailureMessage(failure.class), failure.stage, failure.code, humanFailureHint(failure),
	)
}

func appendHumanFailureDetails(message []byte, failure executionFailure) []byte {
	trimmed := bytes.TrimRight(message, "\n")
	details := fmt.Sprintf("\ncode: %s\nstage: %s\nhint: %s", failure.code, failure.stage, humanFailureHint(failure))
	return append(append([]byte(nil), trimmed...), details...)
}

func humanFailureHint(failure executionFailure) string {
	hint := strings.TrimSpace(failure.recommendedNextCommand)
	if strings.HasPrefix(hint, "mulgae ") {
		return "run " + hint
	}
	return hint
}

func failureResultJSON(invocation Invocation) ([]byte, error) {
	switch invocation.Command() {
	case app.CommandHelp:
		request, available := invocation.Help()
		if !available {
			return nil, errors.New("missing help request")
		}
		return json.Marshal(struct {
			Kind     string `json:"kind"`
			Topic    string `json:"topic"`
			Rendered bool   `json:"rendered"`
		}{"help_rendered", request.Topic(), false})
	case app.CommandInit:
		request, available := invocation.Init()
		if !available {
			return nil, errors.New("missing init request")
		}
		mode, ids := request.Selection()
		if mode == "auto" {
			ids = []string{}
		}
		return json.Marshal(struct {
			Kind                  string   `json:"kind"`
			ConfigURI             string   `json:"config_uri"`
			ConfigSHA256          string   `json:"config_sha256"`
			SelectedProviderIDs   []string `json:"selected_provider_ids"`
			CandidateProviderIDs  []string `json:"candidate_provider_ids"`
			ConfiguredProviderIDs []string `json:"configured_provider_ids"`
			ConfiguredRoleIDs     []string `json:"configured_role_ids"`
			WriteState            string   `json:"write_state"`
			Committed             bool     `json:"committed"`
			DestinationState      string   `json:"destination_state"`
			Discovery             []any    `json:"discovery"`
		}{"initialization_failed", ".mulgae/config.yaml", "", ids, []string{}, []string{}, []string{}, "not_attempted", false, "not_observed", []any{}})
	case app.CommandRoles:
		return json.Marshal(struct {
			Kind  string `json:"kind"`
			Roles []any  `json:"roles"`
		}{"roles_listed", []any{}})
	case app.CommandReview:
		if request, available := invocation.Review(); available && request.Preflight() {
			return reviewPreflightFailureJSON(), nil
		}
		return json.Marshal(struct {
			Kind              string  `json:"kind"`
			SessionID         *string `json:"session_id"`
			RunID             *string `json:"run_id"`
			RunManifestURI    *string `json:"run_manifest_uri"`
			ReviewArtifactURI *string `json:"review_artifact_uri"`
		}{"review_started", nil, nil, nil, nil})
	case app.CommandDoctor:
		return json.Marshal(struct {
			Kind            string  `json:"kind"`
			DoctorResultURI *string `json:"doctor_result_uri"`
			Readiness       string  `json:"readiness"`
			Doctor          any     `json:"doctor"`
		}{"diagnosed", nil, "unverified", nil})
	case app.CommandConfig:
		request, available := invocation.Config()
		if !available {
			return nil, errors.New("missing config request")
		}
		return json.Marshal(struct {
			Kind         string     `json:"kind"`
			Mode         ConfigMode `json:"mode"`
			ConfigURI    string     `json:"config_uri"`
			ConfigSHA256 string     `json:"config_sha256"`
		}{"configuration_failed", request.Mode(), ".mulgae/config.yaml", ""})
	case app.CommandSchema:
		request, available := invocation.Schema()
		if !available {
			return nil, errors.New("missing schema request")
		}
		schemaID, available := request.SchemaID()
		if !available {
			return nil, errors.New("missing schema ID")
		}
		return json.Marshal(struct {
			Kind      string  `json:"kind"`
			SchemaID  string  `json:"schema_id"`
			ExportURI *string `json:"export_uri"`
		}{"schema_inspected", schemaID, nil})
	case app.CommandStatus:
		request, available := invocation.Status()
		if !available {
			return nil, errors.New("missing status request")
		}
		return json.Marshal(struct {
			Kind              string  `json:"kind"`
			RunID             string  `json:"run_id"`
			RunState          *string `json:"run_state"`
			PublicationStatus *string `json:"publication_status"`
			RecoveryAction    *string `json:"recovery_action"`
			FinalArtifactURI  *string `json:"final_artifact_uri"`
		}{"status_failed", request.RunID(), nil, nil, nil, nil})
	case app.CommandReport:
		return json.Marshal(struct {
			Kind      string  `json:"kind"`
			ReportURI *string `json:"report_uri"`
		}{"report_failed", nil})
	case app.CommandFindings:
		request, available := invocation.Findings()
		if !available {
			return nil, errors.New("missing findings request")
		}
		return json.Marshal(struct {
			Kind              string  `json:"kind"`
			RunID             string  `json:"run_id"`
			FindingCount      *int    `json:"finding_count"`
			ReviewArtifactURI *string `json:"review_artifact_uri"`
		}{"findings_failed", request.RunID(), nil, nil})
	case app.CommandExcerpt:
		return json.Marshal(struct {
			Kind          string  `json:"kind"`
			EvidenceState string  `json:"evidence_state"`
			ExcerptURI    *string `json:"excerpt_uri"`
			ExcerptBase64 *string `json:"excerpt_base64"`
			ExcerptSHA256 *string `json:"excerpt_sha256"`
		}{"excerpt_failed", "unverifiable", nil, nil, nil})
	case app.CommandFollowup:
		return json.Marshal(struct {
			Kind                string  `json:"kind"`
			SessionID           *string `json:"session_id"`
			RunID               *string `json:"run_id"`
			FollowupArtifactURI *string `json:"followup_artifact_uri"`
			Resolution          *string `json:"resolution"`
		}{"followup_started", nil, nil, nil, nil})
	case app.CommandDelta:
		return json.Marshal(struct {
			Kind              string  `json:"kind"`
			SessionID         *string `json:"session_id"`
			RunID             *string `json:"run_id"`
			ReviewArtifactURI *string `json:"review_artifact_uri"`
		}{"delta_started", nil, nil, nil})
	case app.CommandRerun:
		return json.Marshal(struct {
			Kind              string  `json:"kind"`
			SessionID         *string `json:"session_id"`
			RunID             *string `json:"run_id"`
			PromptManifestURI *string `json:"prompt_manifest_uri"`
		}{"rerun_started", nil, nil, nil})
	case app.CommandClean:
		return json.Marshal(struct {
			Kind         string  `json:"kind"`
			CleanPlanURI *string `json:"clean_plan_uri"`
			PlanSHA256   *string `json:"plan_sha256"`
			Applied      bool    `json:"applied"`
		}{"clean_completed", nil, nil, false})
	case app.CommandExport:
		return json.Marshal(struct {
			Kind              string  `json:"kind"`
			ExportManifestURI *string `json:"export_manifest_uri"`
			BundleURI         *string `json:"bundle_uri"`
			Redacted          bool    `json:"redacted"`
		}{"export_created", nil, nil, true})
	default:
		return nil, errors.New("missing command failure projection")
	}
}

func executionFailureFor(command app.CommandName, err error, fallback domain.FailureClass) (failure *executionFailure) {
	defer func() {
		if failure == nil {
			return
		}
		if uri, ok := reviewrun.RuntimeDiagnosticURIFromError(err); ok {
			failure.diagnosticURI = uri.String()
		}
	}()
	if capture, ok := ports.ReviewCaptureFailureFromError(err); ok {
		class := domain.FailureArtifact
		if capture.Code() == ports.ReviewCapturePolicyBlocked {
			class = domain.FailureSecurityPolicy
		}
		facts := make([]string, 0, 5)
		if capture.Summary() != "" {
			facts = append(facts, "summary: "+capture.Summary())
		}
		if capture.Path() != "" {
			facts = append(facts, "path: "+capture.Path())
		}
		if capture.Role() != "" {
			facts = append(facts, "role: "+string(capture.Role()))
		}
		if capture.EffectiveConfiguration() != "" {
			facts = append(facts, "effective configuration: "+capture.EffectiveConfiguration())
		}
		if capture.Hint() != "" {
			facts = append(facts, "hint: "+capture.Hint())
		}
		message := "Review input capture failed at stage review.capture."
		if len(facts) != 0 {
			message += " " + strings.Join(facts, "; ") + "."
		}
		return &executionFailure{
			class:                  class,
			code:                   string(capture.Code()),
			message:                message,
			humanMessage:           "mulgae: " + string(capture.Code()) + ": " + strings.Join(facts, "; "),
			stage:                  "review.capture",
			exit:                   requestedExit(class),
			recommendedNextCommand: "mulgae doctor",
			role:                   string(capture.Role()),
		}
	}
	if providers, loginRequired := reviewrun.ProviderLoginRequiredProvidersFromError(err); loginRequired {
		providerList := strings.Join(providers, ", ")
		return &executionFailure{
			class:        domain.FailureAuthentication,
			code:         "provider_login_required",
			message:      "Login is required for provider " + providerList + ". Authenticate outside Mulgae, then rerun the command.",
			humanMessage: "mulgae: login required for provider " + providerList + "; authenticate outside Mulgae, then rerun the command",
			retryable:    false,
			hasRetryable: true,
			stage:        "cli." + string(command),
			exit:         app.ExitCodeReadiness,
		}
	}
	if failures, qualificationFailed := reviewrun.ProviderQualificationFailuresFromError(err); qualificationFailed {
		facts := make([]string, 0, len(failures))
		for _, failure := range failures {
			facts = append(facts, failure.ProviderInstance()+"="+failure.ReasonCode())
		}
		failureList := strings.Join(facts, ", ")
		if permissionFailures := qualificationPermissionDeniedFailures(failures); len(permissionFailures) > 0 {
			hint := providerFailureHint(review.AttemptConditionProviderPermissionDenied)
			providers := make([]string, len(permissionFailures))
			for index, failure := range permissionFailures {
				providers[index] = failure.ProviderInstance()
			}
			providerList := strings.Join(providers, ", ")
			message := "Provider permission denied during qualification for " + providerList + "; hint: run " + hint + "."
			humanMessage := "mulgae: provider permission denied during qualification for " + providerList
			if len(permissionFailures) != len(failures) {
				otherFacts := make([]string, 0, len(failures)-len(permissionFailures))
				for _, failure := range failures {
					if failure.DiagnosticCause() != domain.DiagnosticCausePermissionDenied {
						otherFacts = append(otherFacts, failure.ProviderInstance()+"="+failure.ReasonCode())
					}
				}
				otherFailureList := strings.Join(otherFacts, ", ")
				message += " Other qualification failures: " + otherFailureList + "."
				humanMessage += "; other qualification failures: " + otherFailureList
			}
			return &executionFailure{
				class:                  domain.FailureAuthentication,
				code:                   "provider_permission_denied",
				message:                message,
				humanMessage:           humanMessage,
				retryable:              false,
				hasRetryable:           true,
				stage:                  "provider.qualify",
				exit:                   requestedExit(domain.FailureAuthentication),
				provider:               permissionFailures[0].ProviderInstance(),
				recommendedNextCommand: hint,
			}
		}
		class := reducedFailureClass(err, fallback)
		retryable := qualificationFailureRetryable(class)
		message := "Provider qualification failed: " + failureList + ". Resolve provider qualification, then rerun the command."
		if retryable {
			message = "Provider qualification failed: " + failureList + ". Retry the command after resolving provider readiness."
		}
		return &executionFailure{
			class:        class,
			code:         "provider_qualification_failed",
			message:      message,
			humanMessage: "mulgae: provider qualification failed: " + failureList,
			retryable:    retryable,
			hasRetryable: true,
			stage:        "cli." + string(command),
			exit:         requestedExit(class),
		}
	}
	if failures, executionFailed := reviewrun.ProviderExecutionFailuresFromError(err); executionFailed {
		facts := make([]string, 0, len(failures))
		for _, failure := range failures {
			facts = append(facts, fmt.Sprintf("role=%s provider=%s reason=%s", failure.Role(), failure.ProviderInstance(), failure.ReasonCode()))
		}
		failureList := strings.Join(facts, ", ")
		class := reducedFailureClass(err, fallback)
		first := failures[0]
		for _, candidate := range failures {
			if candidate.FailureClass() == class {
				first = candidate
				break
			}
		}
		code := providerExecutionFailureCode(first)
		hint := providerFailureHint(review.AttemptCondition(first.ReasonCode()))
		return &executionFailure{
			class:                  class,
			code:                   code,
			message:                "Provider execution failed at stage provider.execute: " + failureList + "; hint: run " + hint + ".",
			humanMessage:           "mulgae: provider execution failed: " + failureList,
			retryable:              false,
			hasRetryable:           true,
			stage:                  "provider.execute",
			exit:                   requestedExit(class),
			role:                   string(first.Role()),
			provider:               first.ProviderInstance(),
			recommendedNextCommand: hint,
		}
	}
	if diagnostic, ok := apppublication.FailureDiagnosticFromError(err); ok {
		hint := "rerun the review"
		if _, runID, hasIdentity := reviewrun.RuntimeDiagnosticIdentityFromError(err); hasIdentity {
			hint = "mulgae status --run " + runID.String() + " --output json"
		}
		return &executionFailure{
			class:                  domain.FailureArtifact,
			code:                   string(diagnostic.Cause()),
			message:                diagnostic.Failure() + " at phase " + string(diagnostic.Phase()) + "; " + diagnostic.Mitigation() + ".",
			humanMessage:           "mulgae: " + diagnostic.Failure() + " at phase " + string(diagnostic.Phase()),
			retryable:              false,
			hasRetryable:           true,
			stage:                  string(diagnostic.Phase()),
			exit:                   app.ExitCodeArtifact,
			recommendedNextCommand: hint,
		}
	}
	class := reducedFailureClass(err, fallback)
	failure = &executionFailure{
		class: class,
		stage: "cli." + string(command),
		exit:  requestedExit(class),
	}
	switch class {
	case domain.FailureConfiguration:
		failure.code = "configuration_rejected"
	case domain.FailureArtifact:
		failure.code = "artifact_unavailable"
	case domain.FailureSecurityPolicy:
		if reason, ok := ports.ConfigLocalityReasonFromError(err); ok {
			failure.code = string(reason)
		} else {
			failure.code = "security_rejected"
		}
	case domain.FailureCancelled:
		failure.code = "request_cancelled"
	case domain.FailureProviderUnavailable:
		failure.code = "provider_unavailable"
	case domain.FailureTimeout:
		failure.code = "execution_timeout"
	case domain.FailureInvalidOutput:
		failure.code = "invalid_provider_output"
	case domain.FailureAuthentication:
		failure.code = "provider_authentication_failed"
	case domain.FailureQuota:
		failure.code = "provider_quota_exceeded"
	case domain.FailureRateLimit:
		failure.code = "provider_rate_limited"
	default:
		failure.class = domain.FailureInternal
		failure.code = "internal_failure"
		failure.exit = app.ExitCodeInternal
	}
	return failure
}

func qualificationPermissionDeniedFailures(failures []reviewrun.ProviderQualificationFailure) []reviewrun.ProviderQualificationFailure {
	permissionFailures := make([]reviewrun.ProviderQualificationFailure, 0, len(failures))
	for _, failure := range failures {
		if failure.DiagnosticCause() == domain.DiagnosticCausePermissionDenied {
			permissionFailures = append(permissionFailures, failure)
		}
	}
	return permissionFailures
}

func providerExecutionFailureCode(failure reviewrun.ProviderExecutionFailure) string {
	switch failure.ReasonCode() {
	case string(review.AttemptConditionProviderPermissionDenied):
		return "provider_permission_denied"
	case string(review.AttemptConditionProviderTimeout):
		return "provider_timeout"
	case string(review.AttemptConditionProviderSpawnFailed):
		return "provider_spawn_failed"
	case string(review.AttemptConditionTimeout):
		return "execution_timeout"
	case string(review.AttemptConditionProviderOutputMissing):
		return "provider_output_missing"
	case string(review.AttemptConditionProviderOutputDecodeFailed):
		return "provider_output_decode_failed"
	case string(review.AttemptConditionInvalidProviderOutput),
		string(review.AttemptConditionUnrepairableProviderOutput),
		string(review.AttemptConditionSemanticContradiction),
		string(review.AttemptConditionInvalidEvidenceClaim),
		string(review.AttemptConditionUnrepairableEvidence):
		return "candidate_validation_failed"
	}
	return "provider_execution_failed"
}

// providerFailureHint names the command that can actually move a provider
// failure forward. It routes from the coordinator's own condition rather than
// the narrowed public code, because the public code lumps distinct conditions
// together and would send the operator to the wrong command.
//
// A role runs on exactly one provider and Mulgae never substitutes another, so
// recovering a failed role is the operator's decision and this hint is most of
// what they have to make it. `mulgae doctor` is only useful when the provider
// itself is unusable; for a provider that merely failed this once it reports
// "eligible" and wastes the operator's time.
func providerFailureHint(condition review.AttemptCondition) string {
	switch {
	case condition == review.AttemptConditionProviderPermissionDenied:
		// Permission is configuration, not provider health.
		return "mulgae config --mode effective"
	case review.ConditionProviderUnusable(condition):
		// Log in, restore quota, or install the provider before rerunning.
		return "mulgae doctor"
	case review.ConditionProviderFault(condition):
		// The provider failed this once. Run the role again, here or elsewhere.
		return "mulgae rerun"
	default:
		// Not the provider's fault; doctor stays the conservative entry point.
		return "mulgae doctor"
	}
}

func appendDiagnosticURI(message []byte, uri string) []byte {
	if uri == "" {
		return cloneApplicationBytes(message)
	}
	output := bytes.TrimRight(cloneApplicationBytes(message), "\n")
	output = append(output, []byte("\ndiagnostic_uri: ")...)
	return append(output, uri...)
}

func qualificationFailureRetryable(class domain.FailureClass) bool {
	switch class {
	case domain.FailureProviderUnavailable,
		domain.FailureInvalidOutput,
		domain.FailureTimeout,
		domain.FailureAuthentication,
		domain.FailureQuota,
		domain.FailureRateLimit:
		return true
	default:
		return false
	}
}

func reducedFailureClass(err error, fallback domain.FailureClass) domain.FailureClass {
	classes := make([]domain.FailureClass, 0, 3)
	var visit func(error, bool)
	visit = func(current error, suppressRawFallback bool) {
		if current == nil {
			return
		}
		if typed, ok := current.(*domain.Failure); ok && typed != nil && typed.Class().Valid() {
			classes = append(classes, typed.Class())
			visit(typed.Unwrap(), true)
			return
		}
		switch unwrapped := current.(type) {
		case interface{ Unwrap() []error }:
			nested := unwrapped.Unwrap()
			if len(nested) == 0 {
				if !suppressRawFallback {
					classes = append(classes, fallback)
				}
				return
			}
			for _, child := range nested {
				// Every errors.Join child is an independent observation, even
				// when the join is the cause of a typed wrapper.
				visit(child, false)
			}
		case interface{ Unwrap() error }:
			nested := unwrapped.Unwrap()
			if nested == nil {
				if !suppressRawFallback {
					classes = append(classes, fallback)
				}
				return
			}
			visit(nested, suppressRawFallback)
		default:
			if errors.Is(current, context.Canceled) || errors.Is(current, context.DeadlineExceeded) {
				classes = append(classes, domain.FailureCancelled)
				return
			}
			if !suppressRawFallback {
				classes = append(classes, fallback)
			}
		}
	}
	visit(err, false)
	if len(classes) == 0 {
		classes = append(classes, fallback)
	}
	selected := domain.FailureInternal
	selectedRank := -1
	for _, class := range classes {
		if rank := app.FailurePrecedence(class); rank > selectedRank {
			selected = class
			selectedRank = rank
		}
	}
	return selected
}

func requestedExit(class domain.FailureClass) app.ExitCode {
	switch class {
	case domain.FailureConfiguration:
		return app.ExitCodeUsage
	case domain.FailureArtifact:
		return app.ExitCodeArtifact
	case domain.FailureSecurityPolicy:
		return app.ExitCodeSecurity
	case domain.FailureCancelled:
		return app.ExitCodeCancellation
	case domain.FailureProviderUnavailable, domain.FailureInvalidOutput, domain.FailureTimeout, domain.FailureAuthentication, domain.FailureQuota, domain.FailureRateLimit:
		return app.ExitCodeReadiness
	default:
		return app.ExitCodeInternal
	}
}

func permittedFailureExit(command app.CommandName, requested app.ExitCode) bool {
	allowed := map[app.CommandName]map[app.ExitCode]bool{
		app.CommandInit:      {app.ExitCodeUsage: true, app.ExitCodeReadiness: true, app.ExitCodeArtifact: true, app.ExitCodeSecurity: true, app.ExitCodeCancellation: true, app.ExitCodeInternal: true},
		app.CommandDoctor:    {app.ExitCodeUsage: true, app.ExitCodeReadiness: true, app.ExitCodeArtifact: true, app.ExitCodeSecurity: true, app.ExitCodeCancellation: true},
		app.CommandStatus:    {app.ExitCodeUsage: true, app.ExitCodeArtifact: true, app.ExitCodeSecurity: true, app.ExitCodeCancellation: true, app.ExitCodeInternal: true},
		app.CommandReport:    {app.ExitCodeUsage: true, app.ExitCodeArtifact: true, app.ExitCodeSecurity: true, app.ExitCodeCancellation: true, app.ExitCodeInternal: true},
		app.CommandFindings:  {app.ExitCodeUsage: true, app.ExitCodeArtifact: true, app.ExitCodeSecurity: true, app.ExitCodeCancellation: true, app.ExitCodeInternal: true},
		app.CommandExcerpt:   {app.ExitCodeUsage: true, app.ExitCodeReadiness: true, app.ExitCodeArtifact: true, app.ExitCodeSecurity: true, app.ExitCodeCancellation: true, app.ExitCodeInternal: true},
		app.CommandProviders: {app.ExitCodeUsage: true, app.ExitCodeReadiness: true, app.ExitCodeArtifact: true, app.ExitCodeSecurity: true},
		app.CommandRoles:     {app.ExitCodeUsage: true},
		app.CommandReview:    {app.ExitCodePolicy: true, app.ExitCodeUsage: true, app.ExitCodeReadiness: true, app.ExitCodeArtifact: true, app.ExitCodeSecurity: true, app.ExitCodeCancellation: true, app.ExitCodeInternal: true},
		app.CommandFollowup:  {app.ExitCodePolicy: true, app.ExitCodeUsage: true, app.ExitCodeReadiness: true, app.ExitCodeArtifact: true, app.ExitCodeSecurity: true, app.ExitCodeCancellation: true, app.ExitCodeInternal: true},
		app.CommandDelta:     {app.ExitCodePolicy: true, app.ExitCodeUsage: true, app.ExitCodeReadiness: true, app.ExitCodeArtifact: true, app.ExitCodeSecurity: true, app.ExitCodeCancellation: true, app.ExitCodeInternal: true},
		app.CommandRerun:     {app.ExitCodePolicy: true, app.ExitCodeUsage: true, app.ExitCodeReadiness: true, app.ExitCodeArtifact: true, app.ExitCodeSecurity: true, app.ExitCodeCancellation: true, app.ExitCodeInternal: true},
		app.CommandClean:     {app.ExitCodeUsage: true, app.ExitCodeArtifact: true, app.ExitCodeSecurity: true},
		app.CommandExport:    {app.ExitCodeUsage: true, app.ExitCodeArtifact: true, app.ExitCodeSecurity: true},
		app.CommandConfig:    {app.ExitCodeUsage: true, app.ExitCodeReadiness: true, app.ExitCodeArtifact: true, app.ExitCodeSecurity: true, app.ExitCodeCancellation: true, app.ExitCodeInternal: true},
	}
	return allowed[command][requested]
}

// projectedFailureExit preserves the expanded G006 operational exits while
// keeping older foundation commands inside their frozen command-result schema.
func projectedFailureExit(command app.CommandName, requested app.ExitCode) app.ExitCode {
	if permittedFailureExit(command, requested) {
		return requested
	}
	switch command {
	case app.CommandInit, app.CommandDoctor, app.CommandProviders, app.CommandSchema:
		return app.ExitCodeArtifact
	case app.CommandConfig:
		return app.ExitCodeSecurity
	case app.CommandHelp, app.CommandRoles:
		return app.ExitCodeUsage
	default:
		return app.ExitCodeInternal
	}
}

func stableFailureMessage(class domain.FailureClass) string {
	switch class {
	case domain.FailureConfiguration:
		return "The command configuration is invalid."
	case domain.FailureArtifact:
		return "A required artifact could not be read or written."
	case domain.FailureSecurityPolicy:
		return "The secure output policy rejected the command output."
	case domain.FailureCancelled:
		return "The command was cancelled."
	case domain.FailureProviderUnavailable, domain.FailureTimeout, domain.FailureAuthentication, domain.FailureQuota, domain.FailureRateLimit:
		return "Required readiness evidence is unverified."
	default:
		return "The command could not be completed."
	}
}

func humanFailureMessage(class domain.FailureClass) string {
	switch class {
	case domain.FailureConfiguration:
		return "mulgae: configuration could not be resolved"
	case domain.FailureArtifact:
		return "mulgae: a required artifact could not be read or written"
	case domain.FailureSecurityPolicy:
		return "mulgae: secure output policy rejected the command output"
	case domain.FailureCancelled:
		return "mulgae: request was cancelled"
	default:
		return "mulgae: command could not be completed"
	}
}

func newResult(stdout, stderr []byte, exit app.ExitCode) Result {
	return Result{
		stdout: cloneApplicationBytes(stdout),
		stderr: cloneApplicationBytes(stderr),
		exit:   exit,
	}
}
func isG008Command(command app.CommandName) bool {
	switch command {
	case app.CommandFollowup, app.CommandDelta, app.CommandRerun, app.CommandClean, app.CommandExport:
		return true
	default:
		return false
	}
}

func errorResult(exit app.ExitCode, message string) Result {
	trimmed := strings.TrimRight(message, "\n")
	if !strings.Contains(strings.ToLower(trimmed), "hint:") {
		hint := "run mulgae doctor"
		if exit == app.ExitCodeUsage {
			hint = "run mulgae help workflows"
		} else if exit == app.ExitCodeCancellation {
			hint = "retry the command when ready"
		}
		trimmed += "\nhint: " + hint
	}
	return newResult(nil, terminalOutput([]byte(trimmed)), exit)
}

func terminalOutput(value []byte) []byte {
	trimmed := bytes.TrimRight(cloneApplicationBytes(value), "\n")
	return append(trimmed, '\n')
}
func envelopeContext(ctx context.Context) context.Context {
	if ctx != nil && ctx.Err() != nil {
		return context.WithoutCancel(ctx)
	}
	return ctx
}

func cloneApplicationBytes(value []byte) []byte {
	if value == nil {
		return nil
	}
	return append([]byte(nil), value...)
}
func envelopeRequestJSON(invocation Invocation) ([]byte, bool, error) {
	if request, available := invocation.RequestJSON(); available {
		return request, true, nil
	}
	return nil, false, nil
}

func cloneApplicationStrings(value []string) []string {
	if value == nil {
		return nil
	}
	return append([]string(nil), value...)
}

func nilApplicationDependency(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
