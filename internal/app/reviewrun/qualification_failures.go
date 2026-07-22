package reviewrun

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/irootkernel/kkachi-agent-review/internal/domain"
	"github.com/irootkernel/kkachi-agent-review/internal/ports"
)

// ProviderQualificationFailure is one safe configured-candidate rejection.
// It deliberately retains no native output or free-form provider text.
type ProviderQualificationFailure struct {
	providerInstance string
	family           Family
	reasonCode       string
	cause            error
}

func (failure ProviderQualificationFailure) ProviderInstance() string {
	return failure.providerInstance
}
func (failure ProviderQualificationFailure) Family() Family     { return failure.family }
func (failure ProviderQualificationFailure) ReasonCode() string { return failure.reasonCode }

func newOperationalQualificationFailure(definition ports.ProviderRuntimeDefinition, cause error) (ProviderQualificationFailure, error) {
	var typed *domain.Failure
	if !errors.As(cause, &typed) || typed == nil {
		return ProviderQualificationFailure{}, fmt.Errorf("review run: qualification rejection is not typed")
	}
	family := Family(definition.Family())
	reasonCode := string(typed.Class())
	switch typed.Class() {
	case domain.FailureProviderUnavailable,
		domain.FailureInvalidOutput,
		domain.FailureTimeout,
		domain.FailureAuthentication,
		domain.FailureQuota,
		domain.FailureRateLimit:
	default:
		return ProviderQualificationFailure{}, fmt.Errorf("review run: qualification rejection is not operational")
	}
	return NewProviderQualificationFailure(definition.Instance(), family, reasonCode, cause)
}

// NewProviderQualificationFailure constructs one closed safe candidate fact.
func NewProviderQualificationFailure(providerInstance string, family Family, reasonCode string, cause error) (ProviderQualificationFailure, error) {
	failure := ProviderQualificationFailure{
		providerInstance: providerInstance,
		family:           family,
		reasonCode:       reasonCode,
		cause:            cause,
	}
	if err := failure.validate(); err != nil {
		return ProviderQualificationFailure{}, err
	}
	return failure, nil
}

func (failure ProviderQualificationFailure) validate() error {
	if failure.providerInstance == "" || !failure.family.Valid() || failure.cause == nil {
		return fmt.Errorf("review run: invalid provider qualification failure")
	}
	switch failure.reasonCode {
	case string(domain.FailureProviderUnavailable),
		string(domain.FailureInvalidOutput),
		string(domain.FailureTimeout),
		string(domain.FailureAuthentication),
		string(domain.FailureQuota),
		string(domain.FailureRateLimit),
		string(domain.FailureSecurityPolicy),
		string(domain.FailureConfiguration),
		string(domain.FailureArtifact),
		string(domain.FailureInternal),
		string(domain.FailureCancelled),
		"qualification_failed",
		"qualification_invalid",
		"version_incompatible":
		return nil
	default:
		return fmt.Errorf("review run: invalid provider qualification reason")
	}
}

func providerQualificationBoundaryError(definition ports.ProviderRuntimeDefinition, cause error, reasonCode string) error {
	record, err := NewProviderQualificationFailure(
		definition.Instance(),
		Family(definition.Family()),
		reasonCode,
		cause,
	)
	if err != nil {
		return err
	}
	aggregate := newProviderQualificationFailuresError([]ProviderQualificationFailure{record})
	class := domain.FailureProviderUnavailable
	var typed *domain.Failure
	if errors.As(cause, &typed) && typed != nil && typed.Class().Valid() {
		class = typed.Class()
		if class == domain.FailureInvalidOutput {
			class = domain.FailureProviderUnavailable
		}
	} else if errors.Is(cause, context.DeadlineExceeded) {
		class = domain.FailureTimeout
	} else if errors.Is(cause, context.Canceled) {
		class = domain.FailureCancelled
	}
	failure, failureErr := domain.NewFailure(
		"reviewrun.qualification",
		class,
		"configured provider qualification failed",
		aggregate,
	)
	if failureErr != nil {
		return aggregate
	}
	return failure
}

// ProviderQualificationFailuresError retains only safe candidate identities
// while its wrapped typed causes preserve operational exit precedence.
type ProviderQualificationFailuresError struct {
	failures []ProviderQualificationFailure
	cause    error
}

func newProviderQualificationFailuresError(failures []ProviderQualificationFailure) error {
	return NewProviderQualificationFailuresError(failures)
}

// NewProviderQualificationFailuresError constructs the canonical safe
// aggregate used across qualification, planning, and command projection.
func NewProviderQualificationFailuresError(failures []ProviderQualificationFailure) error {
	canonical := append([]ProviderQualificationFailure(nil), failures...)
	for _, failure := range canonical {
		if err := failure.validate(); err != nil {
			return err
		}
	}
	sort.Slice(canonical, func(left, right int) bool {
		leftOrdinal, _ := familyOrdinal(canonical[left].family)
		rightOrdinal, _ := familyOrdinal(canonical[right].family)
		if leftOrdinal != rightOrdinal {
			return leftOrdinal < rightOrdinal
		}
		return canonical[left].providerInstance < canonical[right].providerInstance
	})
	write := 0
	causes := make([]error, 0, len(canonical))
	for _, failure := range canonical {
		if write > 0 && canonical[write-1].providerInstance == failure.providerInstance {
			continue
		}
		canonical[write] = failure
		write++
		causes = append(causes, failure.cause)
	}
	canonical = canonical[:write]
	if len(canonical) == 0 {
		return fmt.Errorf("review run: provider qualification failure is empty")
	}
	return &ProviderQualificationFailuresError{failures: canonical, cause: errors.Join(causes...)}
}

func (failure *ProviderQualificationFailuresError) Error() string {
	return "review run: configured provider qualification failed"
}

func (failure *ProviderQualificationFailuresError) Unwrap() error {
	if failure == nil {
		return nil
	}
	return failure.cause
}

// ProviderQualificationFailuresFromError returns canonical safe rejection
// records without exposing wrapped native causes.
func ProviderQualificationFailuresFromError(err error) ([]ProviderQualificationFailure, bool) {
	var failure *ProviderQualificationFailuresError
	if !errors.As(err, &failure) || failure == nil || len(failure.failures) == 0 {
		return nil, false
	}
	result := make([]ProviderQualificationFailure, len(failure.failures))
	for index, item := range failure.failures {
		result[index] = ProviderQualificationFailure{
			providerInstance: item.providerInstance,
			family:           item.family,
			reasonCode:       item.reasonCode,
		}
	}
	return result, true
}

func providerQualificationReadinessError(failures []ProviderQualificationFailure) error {
	if len(failures) == 0 {
		failure, err := domain.NewFailure(
			"reviewrun.qualification",
			domain.FailureProviderUnavailable,
			"no provider candidate qualified",
			nil,
		)
		if err == nil {
			return failure
		}
		return fmt.Errorf("review run: no provider candidate qualified")
	}
	aggregate := newProviderQualificationFailuresError(failures)
	if _, ok := aggregate.(*ProviderQualificationFailuresError); !ok {
		return aggregate
	}
	failure, err := domain.NewFailure(
		"reviewrun.qualification",
		domain.FailureProviderUnavailable,
		"configured provider qualification failed",
		aggregate,
	)
	if err != nil {
		return aggregate
	}
	return failure
}
