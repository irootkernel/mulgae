package reviewrun

import (
	"errors"
	"fmt"

	"github.com/irootkernel/mulgae/internal/domain"
)

const (
	qualificationOutcomeQualified = "qualified"
	qualificationOutcomeRejected  = "rejected"
	qualificationMitigationRetry  = "retry"
	qualificationMitigationLogin  = "login"
)

// ProviderQualificationObservation is one closed, safe probe-attempt fact.
// It retains no native output or free-form provider text.
type ProviderQualificationObservation struct {
	providerInstance string
	outcome          string
	failure          string
	mitigation       string
	cause            domain.RuntimeDiagnosticCause
}

func (observation ProviderQualificationObservation) ProviderInstance() string {
	return observation.providerInstance
}
func (observation ProviderQualificationObservation) Outcome() string { return observation.outcome }
func (observation ProviderQualificationObservation) Failure() string { return observation.failure }
func (observation ProviderQualificationObservation) Mitigation() string {
	return observation.mitigation
}
func (observation ProviderQualificationObservation) Cause() domain.RuntimeDiagnosticCause {
	return observation.cause
}

func newQualificationObservation(provider, outcome, failure, mitigation string, cause domain.RuntimeDiagnosticCause) (ProviderQualificationObservation, error) {
	observation := ProviderQualificationObservation{
		providerInstance: provider,
		outcome:          outcome,
		failure:          failure,
		mitigation:       mitigation,
		cause:            cause,
	}
	if provider == "" || outcome != qualificationOutcomeQualified && outcome != qualificationOutcomeRejected {
		return ProviderQualificationObservation{}, fmt.Errorf("review run: invalid qualification observation")
	}
	if outcome == qualificationOutcomeQualified {
		if failure != "" || mitigation != "" || cause != "" {
			return ProviderQualificationObservation{}, fmt.Errorf("review run: invalid successful qualification observation")
		}
	} else if failure == "" || !cause.Valid() || mitigation != "" && mitigation != qualificationMitigationRetry && mitigation != qualificationMitigationLogin {
		return ProviderQualificationObservation{}, fmt.Errorf("review run: invalid rejected qualification observation")
	}
	return observation, nil
}

func loginMitigatedQualificationObservations(observations []ProviderQualificationObservation) []ProviderQualificationObservation {
	result := append([]ProviderQualificationObservation(nil), observations...)
	if len(result) == 0 {
		return result
	}
	last := &result[len(result)-1]
	if last.outcome == qualificationOutcomeRejected {
		last.mitigation = qualificationMitigationLogin
	}
	return result
}

type qualificationObservationError struct {
	observations []ProviderQualificationObservation
	cause        error
}

func (err *qualificationObservationError) Error() string { return err.cause.Error() }
func (err *qualificationObservationError) Unwrap() error { return err.cause }
func (err *qualificationObservationError) QualificationObservations() []ProviderQualificationObservation {
	return append([]ProviderQualificationObservation(nil), err.observations...)
}

func withQualificationObservations(cause error, observations []ProviderQualificationObservation) error {
	if cause == nil || len(observations) == 0 {
		return cause
	}
	return &qualificationObservationError{observations: append([]ProviderQualificationObservation(nil), observations...), cause: cause}
}

func qualificationObservationsFromError(err error) []ProviderQualificationObservation {
	var source interface {
		QualificationObservations() []ProviderQualificationObservation
	}
	if !errors.As(err, &source) {
		return nil
	}
	return source.QualificationObservations()
}

func qualificationDiagnosticCause(err error) domain.RuntimeDiagnosticCause {
	var source interface {
		Cause() domain.RuntimeDiagnosticCause
	}
	if errors.As(err, &source) && source.Cause().Valid() {
		return source.Cause()
	}
	var failure *domain.Failure
	if errors.As(err, &failure) && failure != nil {
		switch failure.Class() {
		case domain.FailureAuthentication:
			return domain.DiagnosticCauseAuthenticationFailed
		case domain.FailureQuota:
			return domain.DiagnosticCauseQuotaExceeded
		case domain.FailureRateLimit:
			return domain.DiagnosticCauseRateLimited
		case domain.FailureTimeout:
			return domain.DiagnosticCauseTimedOut
		case domain.FailureInvalidOutput:
			return domain.DiagnosticCauseObservationInvalid
		}
	}
	return domain.DiagnosticCauseObservationInvalid
}

func qualificationFailureToken(err error) string {
	var failure *domain.Failure
	if errors.As(err, &failure) && failure != nil && failure.Class().Valid() {
		return string(failure.Class())
	}
	return "qualification_failed"
}

func rejectedQualificationObservation(provider string, err error, retry bool) ProviderQualificationObservation {
	mitigation := ""
	if retry {
		mitigation = qualificationMitigationRetry
	}
	observation, observationErr := newQualificationObservation(provider, qualificationOutcomeRejected, qualificationFailureToken(err), mitigation, qualificationDiagnosticCause(err))
	if observationErr != nil {
		panic(observationErr)
	}
	return observation
}

func qualifiedQualificationObservation(provider string) ProviderQualificationObservation {
	observation, err := newQualificationObservation(provider, qualificationOutcomeQualified, "", "", "")
	if err != nil {
		panic(err)
	}
	return observation
}
