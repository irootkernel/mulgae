package providercli

import (
	"errors"
	"strings"

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

func validZCodeSettings(model, effort string) bool {
	if model != "" {
		providerID, modelID, found := strings.Cut(model, "/")
		if !found || providerID != zcodeCodingPlanProvider || modelID == "" || strings.Contains(modelID, "//") || len(modelID) > 128 {
			return false
		}
		for _, character := range providerID {
			if !(character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || strings.ContainsRune("._:-", character)) {
				return false
			}
		}
		for _, segment := range strings.Split(modelID, "/") {
			if segment == "" || segment == ".." {
				return false
			}
			for _, character := range segment {
				if !(character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || strings.ContainsRune("._-", character)) {
					return false
				}
			}
		}
	}
	if effort != "" {
		if len(effort) > 128 {
			return false
		}
		for index, character := range effort {
			if !(character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || index > 0 && strings.ContainsRune("._-", character)) {
				return false
			}
		}
	}
	return true
}
