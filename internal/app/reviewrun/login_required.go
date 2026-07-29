package reviewrun

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/irootkernel/mulgae/internal/app/review"
)

// ProviderLoginRequiredError is the safe provider-attributed application
// failure raised when native authentication requires direct user action.
type ProviderLoginRequiredError struct {
	providers []string
	cause     error
}

func newProviderLoginRequiredError(providers []string, cause error) error {
	return NewProviderLoginRequiredError(providers, cause)
}

// NewProviderLoginRequiredError constructs a safe application error for the
// supplied configured provider instances.
func NewProviderLoginRequiredError(providers []string, cause error) error {
	canonical := append([]string(nil), providers...)
	sort.Strings(canonical)
	write := 0
	for _, provider := range canonical {
		if provider == "" || strings.TrimSpace(provider) != provider {
			continue
		}
		if write > 0 && canonical[write-1] == provider {
			continue
		}
		canonical[write] = provider
		write++
	}
	canonical = canonical[:write]
	if len(canonical) == 0 {
		return fmt.Errorf("review run: provider login requirement has no provider attribution")
	}
	return &ProviderLoginRequiredError{providers: canonical, cause: cause}
}

func (failure *ProviderLoginRequiredError) Error() string {
	if failure == nil {
		return "review run: provider login required"
	}
	return fmt.Sprintf("review run: provider login required for %s", strings.Join(failure.providers, ", "))
}

func (failure *ProviderLoginRequiredError) Unwrap() error {
	if failure == nil {
		return nil
	}
	return failure.cause
}

// ProviderLoginRequiredProvidersFromError returns sorted unique provider
// instances without exposing native stderr or credential material.
func ProviderLoginRequiredProvidersFromError(err error) ([]string, bool) {
	var failure *ProviderLoginRequiredError
	if errors.As(err, &failure) && failure != nil && len(failure.providers) > 0 {
		return append([]string(nil), failure.providers...), true
	}
	executionFailures, ok := ProviderExecutionFailuresFromError(err)
	if !ok {
		return nil, false
	}
	providers := make([]string, 0, len(executionFailures))
	for _, executionFailure := range executionFailures {
		if executionFailure.ReasonCode() == string(review.AttemptConditionLoginRequired) {
			providers = append(providers, executionFailure.ProviderInstance())
		}
	}
	if len(providers) == 0 {
		return nil, false
	}
	sort.Strings(providers)
	unique := providers[:0]
	for _, provider := range providers {
		if len(unique) == 0 || unique[len(unique)-1] != provider {
			unique = append(unique, provider)
		}
	}
	return unique, true
}
