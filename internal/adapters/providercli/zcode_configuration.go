package providercli

import (
	"errors"

	"github.com/irootkernel/mulgae/internal/domain"
)

var (
	errZCodeSelectedModelUnavailable   = errors.New("selected ZCode model is unavailable")
	errZCodeAccountConfigurationFailed = errors.New("ZCode account configuration failed")
)

func zcodeModelSelectionFailure() error {
	failure, err := domain.NewFailure("zcode_model_selection", domain.FailureConfiguration, "selected ZCode model is unavailable", errZCodeSelectedModelUnavailable)
	if err != nil {
		return providerRuntimeFailure(domain.DiagnosticCauseObservationInvalid, err)
	}
	return failure
}

func zcodeAccountConfigurationFailure() error {
	failure, err := domain.NewFailure("zcode_account_configuration", domain.FailureConfiguration, "ZCode account configuration failed", errZCodeAccountConfigurationFailed)
	if err != nil {
		return providerRuntimeFailure(domain.DiagnosticCauseObservationInvalid, err)
	}
	return failure
}
