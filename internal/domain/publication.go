package domain

import (
	"fmt"
	"strings"
)

// PersistedJournalState is the last fsynced publication-journal hint. It is
// never publication authority.
type PersistedJournalState string

const (
	JournalCollecting         PersistedJournalState = "collecting"
	JournalContentValidated   PersistedJournalState = "content_validated"
	JournalFinalStaged        PersistedJournalState = "final_staged"
	JournalFinalFileInstalled PersistedJournalState = "final_file_installed"
	JournalManifestCommitted  PersistedJournalState = "manifest_committed"
	JournalCompleted          PersistedJournalState = "completed"
)

// Valid reports whether state is one of the closed persisted journal states.
func (state PersistedJournalState) Valid() bool {
	switch state {
	case JournalCollecting,
		JournalContentValidated,
		JournalFinalStaged,
		JournalFinalFileInstalled,
		JournalManifestCommitted,
		JournalCompleted:
		return true
	default:
		return false
	}
}

// DurableObservationClass is the normalized class of durable publication
// facts. It records facts only; the classifier owns recovery policy.
type DurableObservationClass string

const (
	DurableObservationP2Committed         DurableObservationClass = "P2_COMMITTED"
	DurableObservationP1Installed         DurableObservationClass = "P1_INSTALLED"
	DurableObservationP0Staged            DurableObservationClass = "P0_STAGED"
	DurableObservationP0None              DurableObservationClass = "P0_NONE"
	DurableObservationAmbiguousOrMismatch DurableObservationClass = "AMBIGUOUS_OR_MISMATCH"
)

// Valid reports whether class is one of the closed durable observation classes.
func (class DurableObservationClass) Valid() bool {
	switch class {
	case DurableObservationP2Committed,
		DurableObservationP1Installed,
		DurableObservationP0Staged,
		DurableObservationP0None,
		DurableObservationAmbiguousOrMismatch:
		return true
	default:
		return false
	}
}

// PublicationAuthority states which durable level authorizes recovery work.
type PublicationAuthority string

const (
	PublicationAuthorityNone PublicationAuthority = "none"
	PublicationAuthorityP0   PublicationAuthority = "P0"
	PublicationAuthorityP1   PublicationAuthority = "P1"
	PublicationAuthorityP2   PublicationAuthority = "P2"
)

// Valid reports whether authority is one of the closed durable authorities.
func (authority PublicationAuthority) Valid() bool {
	switch authority {
	case PublicationAuthorityNone,
		PublicationAuthorityP0,
		PublicationAuthorityP1,
		PublicationAuthorityP2:
		return true
	default:
		return false
	}
}

// RecoveryAction is the next app-owned publication recovery action.
type RecoveryAction string

const (
	RecoveryActionNone                              RecoveryAction = "none"
	RecoveryActionResumeCollection                  RecoveryAction = "resume_collection"
	RecoveryActionRestageValidatedCandidate         RecoveryAction = "restage_validated_candidate"
	RecoveryActionInstallStagedFinal                RecoveryAction = "install_staged_final"
	RecoveryActionCommitCompositeEpoch              RecoveryAction = "commit_composite_epoch"
	RecoveryActionReconstructCompletedStatus        RecoveryAction = "reconstruct_completed_status"
	RecoveryActionEmitImmutableCorruptionDiagnostic RecoveryAction = "emit_immutable_corruption_diagnostic"
)

// Valid reports whether action is one of the closed recovery actions.
func (action RecoveryAction) Valid() bool {
	switch action {
	case RecoveryActionNone,
		RecoveryActionResumeCollection,
		RecoveryActionRestageValidatedCandidate,
		RecoveryActionInstallStagedFinal,
		RecoveryActionCommitCompositeEpoch,
		RecoveryActionReconstructCompletedStatus,
		RecoveryActionEmitImmutableCorruptionDiagnostic:
		return true
	default:
		return false
	}
}

// OperationalExitCode is one typed operational exit. Its priority is defined
// only by ReduceOperationalExit.
type OperationalExitCode int

const (
	ExitCommittedPass       OperationalExitCode = 0
	ExitCommittedCIRejected OperationalExitCode = 1
	ExitConfiguration       OperationalExitCode = 2
	ExitIncompleteCoverage  OperationalExitCode = 4
	ExitArtifactFailure     OperationalExitCode = 7
	ExitSecurityViolation   OperationalExitCode = 8
	ExitCancelled           OperationalExitCode = 9
	ExitInternalError       OperationalExitCode = 10
)

// Valid reports whether code is a typed operational exit.
func (code OperationalExitCode) Valid() bool {
	switch code {
	case ExitCommittedPass,
		ExitCommittedCIRejected,
		ExitConfiguration,
		ExitIncompleteCoverage,
		ExitArtifactFailure,
		ExitSecurityViolation,
		ExitCancelled,
		ExitInternalError:
		return true
	default:
		return false
	}
}

func (code OperationalExitCode) priority() int {
	switch code {
	case ExitInternalError:
		return 8
	case ExitArtifactFailure:
		return 7
	case ExitSecurityViolation:
		return 6
	case ExitCancelled:
		return 5
	case ExitConfiguration:
		return 4
	case ExitIncompleteCoverage:
		return 3
	case ExitCommittedCIRejected:
		return 2
	case ExitCommittedPass:
		return 1
	default:
		return 0
	}
}

// PublicationClassifierInput is immutable input to the total durable
// publication classifier. A stored normal exit is required only for P2. An
// ambiguity reason is required only for an ambiguous durable observation.
type PublicationClassifierInput struct {
	journalState     PersistedJournalState
	observation      DurableObservationClass
	storedNormalExit *OperationalExitCode
	ambiguityReasons []string
}

// NewPublicationClassifierInput validates immutable classifier input and takes
// ownership of ambiguityReasons. P2 requires a stored 0, 1, or 4 exit; every
// other observation must not claim one. Only ambiguity carries reason codes.
func NewPublicationClassifierInput(
	journalState PersistedJournalState,
	observation DurableObservationClass,
	storedNormalExit *OperationalExitCode,
	ambiguityReasons []string,
) (PublicationClassifierInput, error) {
	input := PublicationClassifierInput{
		journalState:     journalState,
		observation:      observation,
		ambiguityReasons: clonePublicationStrings(ambiguityReasons),
	}
	if storedNormalExit != nil {
		exitCopy := *storedNormalExit
		input.storedNormalExit = &exitCopy
	}
	if err := input.validate(); err != nil {
		return PublicationClassifierInput{}, fmt.Errorf("publication classifier input: %w", err)
	}
	return input, nil
}

// JournalState returns the persisted journal hint.
func (input PublicationClassifierInput) JournalState() PersistedJournalState {
	return input.journalState
}

// Observation returns the normalized durable observation class.
func (input PublicationClassifierInput) Observation() DurableObservationClass {
	return input.observation
}

// StoredNormalExit returns the stored normal projection when Observation is P2.
func (input PublicationClassifierInput) StoredNormalExit() (OperationalExitCode, bool) {
	if input.storedNormalExit == nil {
		return 0, false
	}
	return *input.storedNormalExit, true
}

// AmbiguityReasons returns a caller-owned copy of ambiguity reason codes.
func (input PublicationClassifierInput) AmbiguityReasons() []string {
	return clonePublicationStrings(input.ambiguityReasons)
}

// Valid reports whether input is a coherent immutable classifier input.
func (input PublicationClassifierInput) Valid() bool { return input.validate() == nil }

func (input PublicationClassifierInput) validate() error {
	if !input.journalState.Valid() {
		return fmt.Errorf("unknown persisted journal state %q", input.journalState)
	}
	if !input.observation.Valid() {
		return fmt.Errorf("unknown durable observation class %q", input.observation)
	}
	if input.observation == DurableObservationP2Committed {
		if input.storedNormalExit == nil || !isStoredNormalExit(*input.storedNormalExit) {
			return fmt.Errorf("P2 requires stored normal exit 0, 1, or 4")
		}
	} else if input.storedNormalExit != nil {
		return fmt.Errorf("non-P2 observation must not claim a stored normal exit")
	}
	if input.observation == DurableObservationAmbiguousOrMismatch {
		if err := validatePublicationReasonCodes(input.ambiguityReasons); err != nil {
			return fmt.Errorf("ambiguity reasons: %w", err)
		}
	} else if len(input.ambiguityReasons) != 0 {
		return fmt.Errorf("non-ambiguous observation must not carry ambiguity reasons")
	}
	return nil
}

func isStoredNormalExit(code OperationalExitCode) bool {
	return code == ExitCommittedPass || code == ExitCommittedCIRejected || code == ExitIncompleteCoverage
}

// PublicationDecision is the immutable result of durable publication
// classification. ExitCode is present only for terminal P2 and corrupt states.
type PublicationDecision struct {
	status    PublicationStatus
	authority PublicationAuthority
	action    RecoveryAction
	exitCode  *OperationalExitCode
	reasons   []string
}

// NewPublicationDecision validates an immutable classifier decision and takes
// ownership of reasons. The allowed fields are the exact classifier matrix.
func NewPublicationDecision(
	status PublicationStatus,
	authority PublicationAuthority,
	action RecoveryAction,
	exitCode *OperationalExitCode,
	reasons []string,
) (PublicationDecision, error) {
	decision := PublicationDecision{
		status:    status,
		authority: authority,
		action:    action,
		reasons:   clonePublicationStrings(reasons),
	}
	if exitCode != nil {
		exitCopy := *exitCode
		decision.exitCode = &exitCopy
	}
	if err := decision.validate(); err != nil {
		return PublicationDecision{}, fmt.Errorf("publication decision: %w", err)
	}
	return decision, nil
}

// Status returns the derived publication status.
func (decision PublicationDecision) Status() PublicationStatus { return decision.status }

// Authority returns the durable authority selected by classification.
func (decision PublicationDecision) Authority() PublicationAuthority { return decision.authority }

// Action returns the exact next recovery action.
func (decision PublicationDecision) Action() RecoveryAction { return decision.action }

// ExitCode returns a terminal exit only for committed or corrupt decisions.
func (decision PublicationDecision) ExitCode() (OperationalExitCode, bool) {
	if decision.exitCode == nil {
		return 0, false
	}
	return *decision.exitCode, true
}

// Reasons returns caller-owned ambiguity diagnostic reasons in stable order.
func (decision PublicationDecision) Reasons() []string {
	return clonePublicationStrings(decision.reasons)
}

// Valid reports whether decision is a coherent classifier result.
func (decision PublicationDecision) Valid() bool { return decision.validate() == nil }

func (decision PublicationDecision) validate() error {
	if !decision.status.Valid() {
		return fmt.Errorf("unknown publication status %q", decision.status)
	}
	if !decision.authority.Valid() {
		return fmt.Errorf("unknown publication authority %q", decision.authority)
	}
	if !decision.action.Valid() {
		return fmt.Errorf("unknown recovery action %q", decision.action)
	}
	switch decision.status {
	case PublicationCommitted:
		if decision.authority != PublicationAuthorityP2 || decision.action != RecoveryActionReconstructCompletedStatus || decision.exitCode == nil || !isStoredNormalExit(*decision.exitCode) || len(decision.reasons) != 0 {
			return fmt.Errorf("committed requires P2 reconstruction and stored normal exit")
		}
	case PublicationInstalled:
		if decision.authority != PublicationAuthorityP1 || decision.action != RecoveryActionCommitCompositeEpoch || decision.exitCode != nil || len(decision.reasons) != 0 {
			return fmt.Errorf("installed requires P1 composite commit without terminal exit")
		}
	case PublicationStaged:
		if decision.authority != PublicationAuthorityP0 || decision.action != RecoveryActionInstallStagedFinal || decision.exitCode != nil || len(decision.reasons) != 0 {
			return fmt.Errorf("staged requires P0 install without terminal exit")
		}
	case PublicationNotPublished:
		if decision.authority != PublicationAuthorityNone || (decision.action != RecoveryActionResumeCollection && decision.action != RecoveryActionRestageValidatedCandidate) || decision.exitCode != nil || len(decision.reasons) != 0 {
			return fmt.Errorf("not published requires no authority and low-hint recovery")
		}
	case PublicationCorrupt:
		if decision.authority != PublicationAuthorityNone || decision.action != RecoveryActionEmitImmutableCorruptionDiagnostic || decision.exitCode == nil || *decision.exitCode != ExitArtifactFailure {
			return fmt.Errorf("corrupt requires diagnostic and artifact exit 7")
		}
		if err := validatePublicationReasonCodes(decision.reasons); err != nil {
			return fmt.Errorf("corrupt reasons: %w", err)
		}
	default:
		return fmt.Errorf("unknown publication status %q", decision.status)
	}
	return nil
}

// ClassifyPublication applies the total durable authority precedence exactly
// once. It never derives authority from the journal hint.
func ClassifyPublication(input PublicationClassifierInput) (PublicationDecision, error) {
	if err := input.validate(); err != nil {
		return PublicationDecision{}, fmt.Errorf("classify publication: %w", err)
	}

	switch input.observation {
	case DurableObservationAmbiguousOrMismatch:
		return NewPublicationDecision(
			PublicationCorrupt,
			PublicationAuthorityNone,
			RecoveryActionEmitImmutableCorruptionDiagnostic,
			exitCodePointer(ExitArtifactFailure),
			input.ambiguityReasons,
		)
	case DurableObservationP2Committed:
		storedExit, _ := input.StoredNormalExit()
		return NewPublicationDecision(
			PublicationCommitted,
			PublicationAuthorityP2,
			RecoveryActionReconstructCompletedStatus,
			exitCodePointer(storedExit),
			nil,
		)
	case DurableObservationP1Installed:
		return NewPublicationDecision(
			PublicationInstalled,
			PublicationAuthorityP1,
			RecoveryActionCommitCompositeEpoch,
			nil,
			nil,
		)
	case DurableObservationP0Staged:
		return NewPublicationDecision(
			PublicationStaged,
			PublicationAuthorityP0,
			RecoveryActionInstallStagedFinal,
			nil,
			nil,
		)
	case DurableObservationP0None:
		switch input.journalState {
		case JournalCollecting:
			return NewPublicationDecision(
				PublicationNotPublished,
				PublicationAuthorityNone,
				RecoveryActionResumeCollection,
				nil,
				nil,
			)
		case JournalContentValidated, JournalFinalStaged:
			return NewPublicationDecision(
				PublicationNotPublished,
				PublicationAuthorityNone,
				RecoveryActionRestageValidatedCandidate,
				nil,
				nil,
			)
		case JournalFinalFileInstalled, JournalManifestCommitted, JournalCompleted:
			return NewPublicationDecision(
				PublicationCorrupt,
				PublicationAuthorityNone,
				RecoveryActionEmitImmutableCorruptionDiagnostic,
				exitCodePointer(ExitArtifactFailure),
				[]string{"missing_required_durable_effect"},
			)
		}
	}
	return PublicationDecision{}, fmt.Errorf("classify publication: unhandled durable observation class %q", input.observation)
}

func exitCodePointer(code OperationalExitCode) *OperationalExitCode {
	copyCode := code
	return &copyCode
}

// ExitReason is one observed typed outcome and its stable reason code.
type ExitReason struct {
	code       OperationalExitCode
	reasonCode string
}

// NewExitReason validates one stable operational reason.
func NewExitReason(code OperationalExitCode, reasonCode string) (ExitReason, error) {
	reason := ExitReason{code: code, reasonCode: reasonCode}
	if err := reason.validate(); err != nil {
		return ExitReason{}, fmt.Errorf("exit reason: %w", err)
	}
	return reason, nil
}

// Code returns the typed operational exit represented by the reason.
func (reason ExitReason) Code() OperationalExitCode { return reason.code }

// ReasonCode returns the stable reason code.
func (reason ExitReason) ReasonCode() string { return reason.reasonCode }

func (reason ExitReason) validate() error {
	if !reason.code.Valid() {
		return fmt.Errorf("unknown exit code %d", reason.code)
	}
	return validatePublicationReasonCode(reason.reasonCode)
}

// OperationalExitInput is immutable input to the pure exit reducer.
type OperationalExitInput struct {
	reasons []ExitReason
}

// NewOperationalExitInput validates and defensively copies every observed
// reason. At least one fact is required because exit selection is not a default.
func NewOperationalExitInput(reasons []ExitReason) (OperationalExitInput, error) {
	input := OperationalExitInput{reasons: cloneExitReasons(reasons)}
	if err := input.validate(); err != nil {
		return OperationalExitInput{}, fmt.Errorf("operational exit input: %w", err)
	}
	return input, nil
}

// Reasons returns caller-owned observed reasons in their original stable order.
func (input OperationalExitInput) Reasons() []ExitReason { return cloneExitReasons(input.reasons) }

func (input OperationalExitInput) validate() error {
	if len(input.reasons) == 0 {
		return fmt.Errorf("must contain at least one exit reason")
	}
	for index, reason := range input.reasons {
		if err := reason.validate(); err != nil {
			return fmt.Errorf("reason %d: %w", index, err)
		}
	}
	return nil
}

// OperationalExitDecision is the selected exit and every original reason. The
// retained ordering lets reporting preserve facts that lost precedence.
type OperationalExitDecision struct {
	code    OperationalExitCode
	reasons []ExitReason
}

// Code returns the selected highest-precedence operational exit.
func (decision OperationalExitDecision) Code() OperationalExitCode { return decision.code }

// Reasons returns caller-owned retained reasons in their original stable order.
func (decision OperationalExitDecision) Reasons() []ExitReason {
	return cloneExitReasons(decision.reasons)
}

// ReduceOperationalExit is a pure reduction with precedence
// 10 > 7 > 8 > 9 > 2 > 4 > 1 > 0. It retains every input reason unchanged.
func ReduceOperationalExit(input OperationalExitInput) (OperationalExitDecision, error) {
	if err := input.validate(); err != nil {
		return OperationalExitDecision{}, fmt.Errorf("reduce operational exit: %w", err)
	}
	selected := input.reasons[0].code
	for _, reason := range input.reasons[1:] {
		if reason.code.priority() > selected.priority() {
			selected = reason.code
		}
	}
	return OperationalExitDecision{code: selected, reasons: cloneExitReasons(input.reasons)}, nil
}

// WithPublicationStatus returns axes with only the publication axis replaced.
func (axes OutcomeAxes) WithPublicationStatus(publication PublicationStatus) (OutcomeAxes, error) {
	if !axes.content.Valid() || !axes.coverage.Valid() || !axes.ci.Valid() {
		return OutcomeAxes{}, fmt.Errorf("outcome axes: invalid existing independent axes")
	}
	if !publication.Valid() {
		return OutcomeAxes{}, fmt.Errorf("outcome axes: invalid publication status %q", publication)
	}
	return OutcomeAxes{
		content:     axes.content,
		coverage:    axes.coverage,
		publication: publication,
		ci:          axes.ci,
	}, nil
}

func validatePublicationReasonCodes(reasons []string) error {
	if len(reasons) == 0 {
		return fmt.Errorf("must contain at least one reason")
	}
	seen := make(map[string]struct{}, len(reasons))
	for _, reason := range reasons {
		if err := validatePublicationReasonCode(reason); err != nil {
			return err
		}
		if _, duplicate := seen[reason]; duplicate {
			return fmt.Errorf("duplicate reason %q", reason)
		}
		seen[reason] = struct{}{}
	}
	return nil
}

func validatePublicationReasonCode(reason string) error {
	if len(reason) == 0 || len(reason) > 64 {
		return fmt.Errorf("must be 1 through 64 bytes")
	}
	for index, character := range reason {
		if index == 0 {
			if character < 'a' || character > 'z' {
				return fmt.Errorf("must begin with lowercase ASCII letter")
			}
			continue
		}
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '_' {
			continue
		}
		return fmt.Errorf("must contain lowercase ASCII letters, digits, or underscores")
	}
	if strings.TrimSpace(reason) != reason {
		return fmt.Errorf("must not have surrounding whitespace")
	}
	return nil
}

func clonePublicationStrings(values []string) []string {
	if values == nil {
		return nil
	}
	cloned := make([]string, len(values))
	copy(cloned, values)
	return cloned
}

func cloneExitReasons(values []ExitReason) []ExitReason {
	if values == nil {
		return nil
	}
	cloned := make([]ExitReason, len(values))
	copy(cloned, values)
	return cloned
}
