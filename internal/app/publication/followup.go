package publication

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"unicode/utf8"

	"github.com/irootkernel/mulgae/internal/app/evidence"
	"github.com/irootkernel/mulgae/internal/app/validation"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

// ErrFollowupStructuredRejected marks structured followup material that failed
// schema/semantic/evidence checks and may demote to reports-only publication.
// Inventory, lineage, identity, and other publication integrity failures must
// not wrap this sentinel.
var ErrFollowupStructuredRejected = errors.New("followup structured material rejected")

// FollowupCandidateInput is the complete trusted input for a one-role followup
// publication. Provider output is accepted only after FollowupValidator has
// normalized it.
type FollowupCandidateInput struct {
	Run                 domain.Run
	SourceSessionID     domain.SessionID
	SourceRunID         domain.RunID
	SourceReviewID      domain.ReviewID
	SourceFindingID     string
	SourceTargetSHA256  string
	SourceExcerptSHA256 string
	AttemptID           domain.AttemptID
	Provider            string
	Output              validation.ValidatedFollowup
	Observation         ports.ProviderExecutionObservation
	Runtime             FollowupRuntimeArtifactInput
	Observations        []ports.ProviderExecutionObservation
	Runtimes            []FollowupRuntimeArtifactInput
	Repaired            bool
	InitialCandidate    []byte
	SeverityThreshold   domain.Severity
	MulgaeVersion       string
	MulgaeCommit        string
}

// PrepareFollowupCandidate builds the regular P2 candidate shape for the
// specialized single-role followup execution. Structured findings/resolution
// are optional; reports-only acceptance still publishes the role report with
// lineage and inventory digests.
func PrepareFollowupCandidate(input FollowupCandidateInput) (PreparedCandidate, error) {
	observations, runtimes, err := followupInvocationInventory(input)
	if err != nil {
		return PreparedCandidate{}, err
	}
	terminalObservation := observations[len(observations)-1]
	terminalRuntime := runtimes[len(runtimes)-1]
	if input.Run.Type() != domain.RunTypeFollowup || !terminalObservation.Succeeded() || terminalObservation.Validate() != nil {
		return PreparedCandidate{}, fmt.Errorf("followup publication: successful followup observation is required")
	}
	parent, hasParent := input.Run.ParentRunID()
	source, hasSource := input.Run.SourceRunID()
	if !hasParent || !hasSource || input.Output.Role() == "" || input.Output.ProviderInstance() != input.Provider {
		return PreparedCandidate{}, fmt.Errorf("followup publication: child lineage or provider identity is invalid")
	}
	if input.SourceRunID != source || input.SourceSessionID != input.Run.SessionID() || input.SourceFindingID == "" ||
		!validSHA256(input.SourceTargetSHA256) || !validSHA256(input.SourceExcerptSHA256) {
		return PreparedCandidate{}, fmt.Errorf("followup publication: immutable source authority is invalid")
	}
	invocation := terminalObservation.Invocation()
	if invocation.AttemptID() != input.AttemptID || invocation.Role() != input.Output.Role() || invocation.ProviderInstance() != input.Provider {
		return PreparedCandidate{}, fmt.Errorf("followup publication: observation identity differs from followup output")
	}
	context, err := NewChildPublicationContext(domain.RunTypeFollowup, parent, source, input.SourceReviewID, &input.SourceFindingID, nil)
	if err != nil {
		return PreparedCandidate{}, err
	}
	threshold := input.SeverityThreshold
	if threshold == "" {
		threshold = domain.SeverityHigh
	}
	if !threshold.Valid() {
		return PreparedCandidate{}, fmt.Errorf("followup publication: invalid severity threshold")
	}
	reportsOnly := input.Output.ReportsOnly()
	if reportsOnly == input.Output.Resolution().Valid() {
		return PreparedCandidate{}, fmt.Errorf("followup publication: structured and reports-only authority conflict")
	}
	for index := range observations {
		var candidate []byte
		switch {
		case index == 1:
			// Repair inventory captures a repaired structured candidate only when
			// structured extraction succeeded. Reports-only keeps stdout/stderr.
			if !reportsOnly {
				candidate = input.Output.NormalizedRaw()
			}
		case reportsOnly:
			candidate = input.InitialCandidate
		default:
			candidate = input.Output.NormalizedRaw()
		}
		if input.Repaired && index == 0 {
			candidate = input.InitialCandidate
		}
		if err := validateFollowupRuntimeCaptures(runtimes[index].Captures(), candidate, observations[index].Stdout(), observations[index].Stderr(), index == 1); err != nil {
			return PreparedCandidate{}, err
		}
	}
	input.Observation, input.Runtime = terminalObservation, terminalRuntime
	reportMarkdown := input.Output.ProviderRaw()
	if len(bytes.TrimSpace(reportMarkdown)) == 0 || !utf8.Valid(reportMarkdown) {
		return PreparedCandidate{}, fmt.Errorf("followup publication: provider assistant content is missing or invalid")
	}
	preparedInvocations := make([]preparedInvocation, len(observations))
	for index, observation := range observations {
		preparedInvocations[index] = preparedInvocation{sequence: uint64(index + 1), purpose: domain.InvocationPurpose(observation.Invocation().Purpose()), state: domain.InvocationSucceeded}
	}
	var (
		findings []preparedFinding
		followup *preparedFollowupOutcome
		axes     preparedAxes
		reasons  []string
		exitCode int
		limits   []string
	)
	if reportsOnly {
		axes, reasons, exitCode, limits, err = reduceFollowupReportsOnlyAxes(input.Output.Role(), threshold)
		if err != nil {
			return PreparedCandidate{}, err
		}
	} else {
		var outcome preparedFollowupOutcome
		findings, outcome, err = prepareFollowupFindings(input, "sha256:"+input.Run.Target().SHA256())
		if err != nil {
			return PreparedCandidate{}, fmt.Errorf("%w: %v", ErrFollowupStructuredRejected, err)
		}
		followup = &outcome
		axes, reasons, exitCode, limits, err = reduceFollowupAxes(findings, input.Output.Resolution(), input.Output.Role(), threshold)
		if err != nil {
			return PreparedCandidate{}, err
		}
		axes.structuredExtraction = domain.StructuredExtractionStructured
	}
	parseState := input.Output.ParseState()
	validationState := input.Output.ValidationState()
	if !reportsOnly && input.Repaired && validationState == domain.ValidationValid {
		validationState = domain.ValidationRepairedValid
	}
	if reportsOnly, ok := domain.ClassifySuccessfulAttemptExtraction(parseState, validationState); !ok || reportsOnly != input.Output.ReportsOnly() {
		return PreparedCandidate{}, fmt.Errorf("followup publication: extraction states disagree with output authority")
	}
	role := preparedRole{
		role: input.Output.Role(), required: true, state: domain.RoleTaskSucceeded, valid: true, repaired: input.Repaired && !reportsOnly,
		outcome: "completed", limitations: []string{}, reportsOnly: reportsOnly,
		attempts: []preparedAttempt{{
			id: input.AttemptID, kind: "primary", provider: input.Provider, state: domain.AttemptSucceeded,
			parseState: parseState, validationState: validationState,
			invocations: preparedInvocations,
		}},
		reportMarkdown: append([]byte(nil), reportMarkdown...),
	}
	for _, finding := range findings {
		role.validFindingIDs = append(role.validFindingIDs, finding.id)
	}
	candidate := PreparedCandidate{
		sessionID: input.Run.SessionID(), runID: input.Run.ID(), runState: domain.RunCompleted,
		target:    preparedTarget{sha256: "sha256:" + input.Run.Target().SHA256(), baseOID: input.Run.Target().BaseObjectID(), headOID: input.Run.Target().HeadObjectID()},
		threshold: threshold, mulgae: preparedMulgae{version: input.MulgaeVersion, commit: input.MulgaeCommit}, axes: axes,
		roles: []preparedRole{role}, findings: findings, failures: []preparedFailure{}, limits: limits, reasons: reasons, exitCode: exitCode, lineage: context.immutableLineage(), followup: followup,
	}
	inventories := make([]runtimeArtifactInventory, len(runtimes))
	for index := range runtimes {
		inventories[index] = runtimes[index]
	}
	if err := candidate.bindRuntimeArtifactInventories(inventories); err != nil {
		return PreparedCandidate{}, fmt.Errorf("followup publication: runtime inventory: %w", err)
	}
	if err := candidate.validate(); err != nil {
		return PreparedCandidate{}, err
	}
	return candidate, nil
}

func followupInvocationInventory(input FollowupCandidateInput) ([]ports.ProviderExecutionObservation, []FollowupRuntimeArtifactInput, error) {
	observations := append([]ports.ProviderExecutionObservation(nil), input.Observations...)
	runtimes := append([]FollowupRuntimeArtifactInput(nil), input.Runtimes...)
	if len(observations) == 0 {
		observations = []ports.ProviderExecutionObservation{input.Observation}
	}
	if len(runtimes) == 0 {
		runtimes = []FollowupRuntimeArtifactInput{input.Runtime}
	}
	if len(observations) != len(runtimes) || len(observations) < 1 || len(observations) > 2 || input.Repaired != (len(observations) == 2) || input.Repaired && len(input.InitialCandidate) == 0 {
		return nil, nil, fmt.Errorf("followup publication: invalid bounded invocation inventory")
	}
	for index := range observations {
		invocation := observations[index].Invocation()
		wantPurpose := ports.ProviderInvocationInitial
		if index == 1 {
			wantPurpose = ports.ProviderInvocationRepair
		}
		if !observations[index].Succeeded() || observations[index].Validate() != nil || invocation.AttemptID() != input.AttemptID || invocation.ProviderInstance() != input.Provider || invocation.Purpose() != wantPurpose || runtimes[index].Sequence() != uint64(index+1) || runtimes[index].Purpose() != domain.InvocationPurpose(wantPurpose) {
			return nil, nil, fmt.Errorf("followup publication: invocation inventory identity mismatch")
		}
	}
	return observations, runtimes, nil
}

type followupOutputWire struct {
	Resolution  domain.FollowupResolution `json:"resolution"`
	Rationale   string                    `json:"rationale"`
	Evidence    []followupEvidenceWire    `json:"evidence"`
	NewFindings []followupFindingWire     `json:"new_findings"`
}

type followupFindingWire struct {
	Severity       domain.Severity        `json:"severity"`
	Title          string                 `json:"title"`
	Description    string                 `json:"description"`
	Evidence       []followupEvidenceWire `json:"evidence"`
	Recommendation string                 `json:"recommendation"`
	Confidence     domain.Confidence      `json:"confidence"`
}

type followupEvidenceWire struct {
	Source struct {
		SessionID           string `json:"session_id"`
		RunID               string `json:"run_id"`
		ReviewID            string `json:"review_id"`
		FindingID           string `json:"finding_id"`
		SourceTargetSHA256  string `json:"source_target_sha256"`
		SourceExcerptSHA256 string `json:"source_excerpt_sha256"`
	} `json:"source"`
	Current struct {
		TargetSHA256 string `json:"target_sha256"`
		Path         string `json:"path"`
		LineStart    int    `json:"line_start"`
		LineEnd      int    `json:"line_end"`
		Side         string `json:"side"`
		Quote        string `json:"quote"`
		Verification string `json:"verification"`
	} `json:"current"`
}

func prepareFollowupFindings(input FollowupCandidateInput, currentTargetSHA256 string) ([]preparedFinding, preparedFollowupOutcome, error) {
	var output followupOutputWire
	if err := json.Unmarshal(input.Output.NormalizedRaw(), &output); err != nil {
		return nil, preparedFollowupOutcome{}, fmt.Errorf("followup publication: decode validated output: %w", err)
	}
	if output.Resolution != input.Output.Resolution() || !output.Resolution.Valid() {
		return nil, preparedFollowupOutcome{}, fmt.Errorf("followup publication: output resolution is invalid or tampered")
	}
	reader, err := newFollowupCurrentTargetReader(currentTargetSHA256, input.Runtime.Target(), input.Runtime.CapturedArchive())
	if err != nil {
		return nil, preparedFollowupOutcome{}, fmt.Errorf("followup publication: current evidence reader: %w", err)
	}
	verifier, err := evidence.NewVerifier(reader)
	if err != nil {
		return nil, preparedFollowupOutcome{}, fmt.Errorf("followup publication: current evidence verifier: %w", err)
	}
	verify := func(item followupEvidenceWire) (preparedEvidence, error) {
		if item.Source.SessionID != input.SourceSessionID.String() || item.Source.RunID != input.SourceRunID.String() ||
			item.Source.ReviewID != input.SourceReviewID.String() || item.Source.FindingID != input.SourceFindingID ||
			item.Source.SourceTargetSHA256 != input.SourceTargetSHA256 || item.Source.SourceExcerptSHA256 != input.SourceExcerptSHA256 ||
			item.Current.TargetSHA256 != currentTargetSHA256 || item.Current.Verification != "claimed" {
			return preparedEvidence{}, fmt.Errorf("followup publication: evidence is not bound to immutable source and current authority")
		}
		claim, err := evidence.NewCurrentClaim(evidence.CurrentClaimInput{TargetSHA256: currentTargetSHA256, Side: evidence.Side(item.Current.Side), Path: item.Current.Path, LineStart: item.Current.LineStart, LineEnd: item.Current.LineEnd, Quote: item.Current.Quote})
		if err != nil {
			return preparedEvidence{}, fmt.Errorf("followup publication: current evidence claim: %w", err)
		}
		receipt, err := verifier.VerifyCurrent(context.Background(), claim)
		if err != nil || receipt.Status() != evidence.ReceiptVerified || receipt.ReasonCode() != evidence.ReasonVerified {
			return preparedEvidence{}, fmt.Errorf("followup publication: current evidence is not verified: path=%s lines=%d-%d side=%s status=%s reason=%s verifier=%v", claim.Path().String(), claim.LineStart(), claim.LineEnd(), claim.Side(), receipt.Status(), receipt.ReasonCode(), err)
		}
		return preparedEvidence{targetSHA256: claim.TargetSHA256(), side: claim.Side(), path: claim.Path().String(), lineStart: claim.LineStart(), lineEnd: claim.LineEnd(), quote: claim.Quote(), currentExcerptSHA256: receipt.ExcerptSHA256(), excerpt: cloneBytes(receipt.Excerpt()), sourceSessionID: item.Source.SessionID, sourceRunID: item.Source.RunID, sourceReviewID: item.Source.ReviewID, sourceFindingID: item.Source.FindingID, sourceTargetSHA256: item.Source.SourceTargetSHA256, sourceExcerptSHA256: item.Source.SourceExcerptSHA256}, nil
	}
	outcomeEvidence := make([]preparedEvidence, len(output.Evidence))
	for index, item := range output.Evidence {
		prepared, err := verify(item)
		if err != nil {
			return nil, preparedFollowupOutcome{}, err
		}
		outcomeEvidence[index] = prepared
	}
	if err := canonicalizePreparedEvidence(outcomeEvidence); err != nil {
		return nil, preparedFollowupOutcome{}, fmt.Errorf("followup publication: outcome evidence ordering: %w", err)
	}
	findings := make([]preparedFinding, len(output.NewFindings))
	for index, item := range output.NewFindings {
		if len(item.Evidence) == 0 {
			return nil, preparedFollowupOutcome{}, fmt.Errorf("followup publication: finding %d has no evidence", index)
		}
		evidenceItems := make([]preparedEvidence, len(item.Evidence))
		for evidenceIndex, evidenceItem := range item.Evidence {
			prepared, err := verify(evidenceItem)
			if err != nil {
				return nil, preparedFollowupOutcome{}, fmt.Errorf("followup publication: finding %d evidence %d: %w", index, evidenceIndex, err)
			}
			evidenceItems[evidenceIndex] = prepared
		}
		if err := canonicalizePreparedEvidence(evidenceItems); err != nil {
			return nil, preparedFollowupOutcome{}, fmt.Errorf("followup publication: finding %d evidence ordering: %w", index, err)
		}
		finding, err := domain.NewFinding(domain.FindingInput{Severity: item.Severity, Path: evidenceItems[0].path, LineStart: evidenceItems[0].lineStart, Role: input.Output.Role(), ProviderInstance: input.Provider, Title: item.Title, Description: item.Description, Recommendation: item.Recommendation, Confidence: item.Confidence, Lifecycle: domain.FindingOpen, EvidenceState: domain.EvidenceVerified, NormalizedRuleCategory: item.Title, NormalizedEvidenceRegion: evidenceItems[0].quote})
		if err != nil {
			return nil, preparedFollowupOutcome{}, fmt.Errorf("followup publication: finding %d: %w", index, err)
		}
		findings[index] = preparedFinding{id: fmt.Sprintf("F%03d", index+1), fingerprint: "sha256:" + finding.Fingerprint(), role: finding.Role(), provider: finding.ProviderInstance(), severity: finding.Severity(), title: finding.Title(), description: finding.Description(), recommendation: finding.Recommendation(), confidence: finding.Confidence(), lifecycle: finding.Lifecycle(), evidence: evidenceItems}
	}
	return findings, preparedFollowupOutcome{resolution: input.Output.Resolution(), rationale: output.Rationale, evidence: outcomeEvidence}, nil
}

func reduceFollowupAxes(findings []preparedFinding, resolution domain.FollowupResolution, role domain.Role, threshold domain.Severity) (preparedAxes, []string, int, []string, error) {
	domainFindings := make([]domain.Finding, len(findings))
	for index, finding := range findings {
		value, err := domain.NewFinding(domain.FindingInput{Severity: finding.severity, Path: finding.evidence[0].path, LineStart: finding.evidence[0].lineStart, Role: finding.role, ProviderInstance: finding.provider, Title: finding.title, Description: finding.description, Recommendation: finding.recommendation, Confidence: finding.confidence, Lifecycle: finding.lifecycle, EvidenceState: domain.EvidenceVerified, NormalizedRuleCategory: finding.title, NormalizedEvidenceRegion: finding.evidence[0].quote})
		if err != nil {
			return preparedAxes{}, nil, 0, nil, err
		}
		domainFindings[index] = value
	}
	outcomes, err := domain.ComputeOutcomeAxes(domainFindings, []domain.RoleResultSummary{{Role: role, Selected: true, Required: true, Valid: true}}, threshold, domain.PublicationNotPublished, nil)
	if err != nil {
		return preparedAxes{}, nil, 0, nil, err
	}
	content := outcomes.ContentVerdict()
	ci := domain.CIPass
	reasons := []string{"policy_evaluated"}
	exitCode := int(domain.ExitCommittedPass)
	if content == domain.ContentRequestChanges || resolution == domain.FollowupStillOpen {
		content = domain.ContentRequestChanges
		ci = domain.CIFail
		reasons = []string{"request_changes_threshold"}
		exitCode = int(domain.ExitCommittedCIRejected)
	}
	return preparedAxes{content: content, coverage: domain.CoverageComplete, ci: ci}, reasons, exitCode, []string{}, nil
}

func reduceFollowupReportsOnlyAxes(role domain.Role, threshold domain.Severity) (preparedAxes, []string, int, []string, error) {
	outcomes, err := domain.ComputeOutcomeAxes(nil, []domain.RoleResultSummary{{
		Role: role, Selected: true, Required: true, Valid: true, ReportsOnly: true,
	}}, threshold, domain.PublicationNotPublished, nil)
	if err != nil {
		return preparedAxes{}, nil, 0, nil, err
	}
	if outcomes.ContentVerdict() != domain.ContentReportsOnly || outcomes.CIDecision() != domain.CIPass {
		return preparedAxes{}, nil, 0, nil, fmt.Errorf("followup publication: reports-only axes are inconsistent")
	}
	return preparedAxes{
		content:              domain.ContentReportsOnly,
		coverage:             domain.CoverageComplete,
		ci:                   domain.CIPass,
		structuredExtraction: domain.StructuredExtractionReportsOnly,
	}, []string{"policy_evaluated"}, int(domain.ExitCommittedPass), []string{}, nil
}

type followupCurrentTargetReader struct {
	targetSHA256 string
	bytes        []byte
	files        map[evidence.Side]map[ports.SafeRelativePath][]byte
}

func newFollowupCurrentTargetReader(targetSHA256 string, target, archive []byte) (followupCurrentTargetReader, error) {
	reader := followupCurrentTargetReader{targetSHA256: targetSHA256, bytes: append([]byte(nil), target...)}
	if len(archive) == 0 {
		return reader, nil
	}
	material, err := ports.UnmarshalCapturedReviewMaterial(archive)
	if err != nil {
		return followupCurrentTargetReader{}, err
	}
	if "sha256:"+material.Target().Identity().SHA256() != targetSHA256 || string(material.Target().Bytes()) != string(target) {
		return followupCurrentTargetReader{}, fmt.Errorf("captured review archive target identity mismatch")
	}
	reader.files = make(map[evidence.Side]map[ports.SafeRelativePath][]byte)
	for capturedSide, side := range map[ports.CapturedEvidenceSide]evidence.Side{
		ports.CapturedEvidenceBase:     evidence.SideBase,
		ports.CapturedEvidenceHead:     evidence.SideHead,
		ports.CapturedEvidenceWorktree: evidence.SideWorktree,
		ports.CapturedEvidenceIndex:    evidence.SideIndex,
	} {
		files, ok := material.Evidence().Files(capturedSide)
		if !ok {
			continue
		}
		reader.files[side] = make(map[ports.SafeRelativePath][]byte, len(files))
		for _, file := range files {
			if file.IsText() {
				reader.files[side][file.Path()] = file.Bytes()
			}
		}
	}
	if len(reader.files) == 0 {
		return followupCurrentTargetReader{}, fmt.Errorf("captured review archive has no immutable evidence")
	}
	return reader, nil
}

func (reader followupCurrentTargetReader) ReadImmutableTarget(_ context.Context, targetSHA256 string, side evidence.Side, path ports.SafeRelativePath) (evidence.ImmutableTargetAvailability, []byte, error) {
	if targetSHA256 != reader.targetSHA256 || len(reader.bytes) == 0 {
		return evidence.ImmutableTargetUnavailable, nil, nil
	}
	if reader.files != nil {
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
	return evidence.ImmutableTargetAvailable, append([]byte(nil), reader.bytes...), nil
}

func validateFollowupRuntimeCaptures(captures []ports.CapturedAttemptArtifact, candidate, stdout, stderr []byte, repair ...bool) error {
	candidateKind := ports.AttemptArtifactInitialCandidate
	if len(repair) != 0 && repair[0] {
		candidateKind = ports.AttemptArtifactRepairedCandidate
	}
	expected := map[ports.AttemptArtifactKind][]byte{
		candidateKind:               candidate,
		ports.AttemptArtifactStdout: stdout,
		ports.AttemptArtifactStderr: stderr,
	}
	seen := make(map[ports.AttemptArtifactKind]struct{}, len(captures))
	for _, capture := range captures {
		want, known := expected[capture.Kind()]
		if !known || capture.SecurityRejected() || string(capture.Bytes()) != string(want) || len(want) == 0 {
			return fmt.Errorf("followup publication: runtime capture %s does not match observed stream", capture.Kind())
		}
		if _, duplicate := seen[capture.Kind()]; duplicate {
			return fmt.Errorf("followup publication: duplicate runtime capture %s", capture.Kind())
		}
		seen[capture.Kind()] = struct{}{}
	}
	for kind, bytes := range expected {
		_, found := seen[kind]
		if (len(bytes) > 0) != found {
			return fmt.Errorf("followup publication: runtime capture %s is incomplete", kind)
		}
	}
	return nil
}
