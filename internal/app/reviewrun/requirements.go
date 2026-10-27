package reviewrun

import (
	"context"
	"fmt"

	"github.com/irootkernel/mulgae/internal/app/validation"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

// AdmitRequirementsInput retains exact local invocation bytes for subsequent
// use without reopening the file. Source identity and evidence stay separate.
func AdmitRequirementsInput(ctx context.Context, source ports.LiveSourceReader, path string, roles []domain.Role) (validation.RequirementsInput, error) {
	reader, ok := source.(ports.RequirementsInputReader)
	safe, err := ports.NewSafeRelativePath(path)
	if ctx == nil || nilInterface(source) || !ok || err != nil {
		return validation.RequirementsInput{}, requirementsAdmissionFailure(domain.FailureConfiguration, fmt.Errorf("requirements input authority or path is invalid"))
	}
	raw, err := reader.ReadRequirementsInput(ctx, safe)
	if err != nil {
		return validation.RequirementsInput{}, liveSourceAdmissionFailure(err)
	}
	input, err := validation.DecodeRequirementsInput(raw, roles)
	if err != nil {
		return validation.RequirementsInput{}, requirementsAdmissionFailure(domain.FailureConfiguration, err)
	}
	return input, nil
}

func requirementsAdmissionFailure(class domain.FailureClass, cause error) error {
	failure, _ := domain.NewFailure("requirements.admission", class, "requirements input rejected", cause)
	return failure
}
