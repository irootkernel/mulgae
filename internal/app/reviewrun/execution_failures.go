package reviewrun

import (
	"errors"
	"fmt"
	"sort"

	"github.com/irootkernel/mulgae/internal/app/review"
	"github.com/irootkernel/mulgae/internal/domain"
)

// ProviderExecutionFailure is one safe terminal provider fact. It contains no
// native output, path, credential material, or free-form provider text.
type ProviderExecutionFailure struct {
	providerInstance string
	role             domain.Role
	reasonCode       string
	class            domain.FailureClass
	timeoutFacts     review.ProviderTimeoutFacts
	hasTimeoutFacts  bool
}

func (failure ProviderExecutionFailure) ProviderInstance() string { return failure.providerInstance }
func (failure ProviderExecutionFailure) Role() domain.Role        { return failure.role }
func (failure ProviderExecutionFailure) ReasonCode() string       { return failure.reasonCode }
func (failure ProviderExecutionFailure) FailureClass() domain.FailureClass {
	return failure.class
}
func (failure ProviderExecutionFailure) ProviderTimeoutFacts() (review.ProviderTimeoutFacts, bool) {
	return failure.timeoutFacts, failure.hasTimeoutFacts
}

// NewProviderExecutionFailure constructs one closed safe terminal provider fact.
func NewProviderExecutionFailure(
	providerInstance string,
	role domain.Role,
	reasonCode string,
	class domain.FailureClass,
) (ProviderExecutionFailure, error) {
	failure := ProviderExecutionFailure{
		providerInstance: providerInstance,
		role:             role,
		reasonCode:       reasonCode,
		class:            class,
	}
	if err := failure.validate(); err != nil {
		return ProviderExecutionFailure{}, err
	}
	return failure, nil
}

func NewProviderExecutionFailureWithTimeoutFacts(
	providerInstance string,
	role domain.Role,
	reasonCode string,
	class domain.FailureClass,
	facts review.ProviderTimeoutFacts,
) (ProviderExecutionFailure, error) {
	failure := ProviderExecutionFailure{
		providerInstance: providerInstance,
		role:             role,
		reasonCode:       reasonCode,
		class:            class,
		timeoutFacts:     facts,
		hasTimeoutFacts:  true,
	}
	if err := failure.validate(); err != nil {
		return ProviderExecutionFailure{}, err
	}
	return failure, nil
}

func (failure ProviderExecutionFailure) validate() error {
	if failure.providerInstance == "" || !failure.role.Valid() ||
		!failure.class.Valid() ||
		!review.AttemptCondition(failure.reasonCode).Valid() {
		return fmt.Errorf("review run: invalid provider execution failure")
	}
	if failure.hasTimeoutFacts && (!failure.timeoutFacts.Valid() ||
		review.AttemptCondition(failure.reasonCode) != review.AttemptConditionProviderTimeout ||
		failure.class != domain.FailureTimeout) {
		return fmt.Errorf("review run: invalid provider timeout facts")
	}
	return nil
}

type ProviderExecutionFailuresError struct {
	failures []ProviderExecutionFailure
}

func newProviderExecutionFailuresError(failures []ProviderExecutionFailure) error {
	canonical := append([]ProviderExecutionFailure(nil), failures...)
	for _, failure := range canonical {
		if err := failure.validate(); err != nil {
			return err
		}
	}
	sort.Slice(canonical, func(left, right int) bool {
		leftOrdinal := roleOrdinal(canonical[left].role)
		rightOrdinal := roleOrdinal(canonical[right].role)
		if leftOrdinal != rightOrdinal {
			return leftOrdinal < rightOrdinal
		}
		return canonical[left].providerInstance < canonical[right].providerInstance
	})
	if len(canonical) == 0 {
		return fmt.Errorf("review run: provider execution failure is empty")
	}
	return &ProviderExecutionFailuresError{failures: canonical}
}

// NewProviderExecutionFailuresError constructs a canonical safe aggregate.
func NewProviderExecutionFailuresError(failures []ProviderExecutionFailure) error {
	return newProviderExecutionFailuresError(failures)
}

func (failure *ProviderExecutionFailuresError) Error() string {
	return "review run: configured provider execution failed"
}

// ProviderExecutionFailuresFromError returns only closed safe provider facts.
func ProviderExecutionFailuresFromError(err error) ([]ProviderExecutionFailure, bool) {
	var failure *ProviderExecutionFailuresError
	if !errors.As(err, &failure) || failure == nil || len(failure.failures) == 0 {
		return nil, false
	}
	return append([]ProviderExecutionFailure(nil), failure.failures...), true
}
