package mulgae

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/irootkernel/mulgae/internal/app"
	"github.com/irootkernel/mulgae/internal/app/doctor"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

func (application *Application) handleDoctor(ctx context.Context, invocation Invocation) execution {
	request, available := invocation.Doctor()
	if !available {
		return execution{failure: executionFailureFor(invocation.Command(), errors.New("missing request"), domain.FailureInternal)}
	}
	root, err := ports.NewAnchoredRoot(request.ProjectRoot())
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureConfiguration)}
	}
	diagnosis, err := application.diagnoseLocalDoctor(ctx, root)
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureInternal)}
	}
	raw, err := json.Marshal(diagnosis)
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureInternal)}
	}
	schemaID, err := ports.ParseAssetID(doctorResultSchema)
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureInternal)}
	}
	if err := application.validator.Validate(ctx, schemaID, cloneApplicationBytes(raw)); err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureArtifact)}
	}

	human := localDoctorHumanOutput(diagnosis)
	if invocation.OutputFormat() == OutputFormatHuman {
		if diagnosis.Readiness.ExitCode == 0 {
			return execution{human: human, data: nil}
		}
		class := domain.FailureProviderUnavailable
		code := "readiness_unverified"
		if diagnosis.Readiness.State == "unsafe" {
			class, code = domain.FailureSecurityPolicy, "security_rejected"
		}
		return execution{
			human: human,
			failure: &executionFailure{
				class: class,
				code:  code,
				stage: "cli.doctor",
				exit:  app.ExitCode(diagnosis.Readiness.ExitCode),
			},
		}
	}

	data, err := json.Marshal(struct {
		Kind            string                    `json:"kind"`
		DoctorResultURI *string                   `json:"doctor_result_uri"`
		Readiness       string                    `json:"readiness"`
		Doctor          *doctor.LocalDoctorResult `json:"doctor"`
	}{"diagnosed", nil, diagnosis.Readiness.State, &diagnosis})
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureInternal)}
	}
	if diagnosis.Readiness.ExitCode == 0 {
		return execution{human: human, data: data}
	}
	class := domain.FailureProviderUnavailable
	code := "readiness_unverified"
	if diagnosis.Readiness.State == "unsafe" {
		class, code = domain.FailureSecurityPolicy, "security_rejected"
	}
	return execution{
		human:       human,
		data:        data,
		failureData: data,
		failure: &executionFailure{
			class: class,
			code:  code,
			stage: "cli.doctor",
			exit:  app.ExitCode(diagnosis.Readiness.ExitCode),
		},
	}
}

func (application *Application) diagnoseLocalDoctor(ctx context.Context, root ports.AnchoredRoot) (doctor.LocalDoctorResult, error) {
	attestor, _ := application.projectReader.(ports.ConfigLocalityAttestor)
	service := application.newLocalDoctor(doctor.LocalDependencies{
		Clock: application.clock, Sources: application.configSources, Codec: application.configCodec,
		Accounts: application.accounts, Locality: attestor, Inspector: application.inspector,
		Versions: application.versionObserver, Platform: application.doctorPlatform,
	})
	return service.DiagnoseLocal(ctx, root)
}

func localDoctorHumanOutput(diagnosis doctor.LocalDoctorResult) []byte {
	var output strings.Builder
	fmt.Fprintf(&output, "Readiness: %s\nConfiguration: %s\nProviders:\n", diagnosis.Readiness.State, diagnosis.Config.Status)
	for _, row := range diagnosis.ProviderInventory {
		fmt.Fprintf(&output, "- %s: %s (%s)\n", row.Family, row.State, row.Reason)
	}
	return []byte(output.String())
}
