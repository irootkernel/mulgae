package kar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"

	"github.com/irootkernel/kkachi-agent-review/internal/app"
	appconfig "github.com/irootkernel/kkachi-agent-review/internal/app/config"
	"github.com/irootkernel/kkachi-agent-review/internal/app/doctor"
	apphelp "github.com/irootkernel/kkachi-agent-review/internal/app/help"
	appinit "github.com/irootkernel/kkachi-agent-review/internal/app/init"
	appschema "github.com/irootkernel/kkachi-agent-review/internal/app/schema"
	"github.com/irootkernel/kkachi-agent-review/internal/domain"
	"github.com/irootkernel/kkachi-agent-review/internal/ports"
)

const (
	globalConfigAssetID = "defaults:global-config"
	doctorResultSchema  = "https://kar.local/schemas/kar-doctor-result.v1.schema.json"
)

func (application *Application) execute(ctx context.Context, invocation Invocation) execution {
	switch invocation.Command() {
	case app.CommandHelp:
		return application.handleHelp(ctx, invocation)
	case app.CommandSchema:
		return application.handleSchema(ctx, invocation)
	case app.CommandInit:
		return application.handleInit(ctx, invocation)
	case app.CommandConfig:
		return application.handleConfig(ctx, invocation)
	case app.CommandDoctor:
		return application.handleDoctor(ctx, invocation)
	default:
		return execution{failure: executionFailureFor(invocation.Command(), errors.New("unsupported foundation dispatch"), domain.FailureInternal)}
	}
}

func (application *Application) handleHelp(ctx context.Context, invocation Invocation) execution {
	request, available := invocation.Help()
	if !available {
		return execution{failure: executionFailureFor(invocation.Command(), errors.New("missing request"), domain.FailureInternal)}
	}
	service, err := apphelp.NewService(application.catalog)
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureArtifact)}
	}
	rendered, err := service.Render(ctx, request.Topic())
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureArtifact)}
	}
	data, err := json.Marshal(struct {
		Kind     string `json:"kind"`
		Topic    string `json:"topic"`
		Rendered bool   `json:"rendered"`
	}{"help_rendered", request.Topic(), true})
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureInternal)}
	}
	return execution{human: rendered, data: data}
}

func (application *Application) handleSchema(ctx context.Context, invocation Invocation) execution {
	request, available := invocation.Schema()
	if !available {
		return execution{failure: executionFailureFor(invocation.Command(), errors.New("missing request"), domain.FailureInternal)}
	}
	service := appschema.NewService(application.catalog, application.writer)
	switch request.Operation() {
	case SchemaOperationList:
		metadata, err := service.List(ctx)
		if err != nil {
			return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureArtifact)}
		}
		var output strings.Builder
		for _, schema := range metadata {
			output.WriteString(schema.Source().String())
			output.WriteByte('\n')
		}
		return execution{human: []byte(output.String()), data: nil}
	case SchemaOperationShow:
		schemaID, available := request.SchemaID()
		if !available {
			return execution{failure: executionFailureFor(invocation.Command(), errors.New("missing schema ID"), domain.FailureInternal)}
		}
		id, err := ports.ParseAssetID(schemaID)
		if err != nil {
			return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureConfiguration)}
		}
		_, raw, err := service.Show(ctx, id)
		if err != nil {
			return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureArtifact)}
		}
		data, err := schemaResultData(schemaID, nil)
		if err != nil {
			return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureInternal)}
		}
		return execution{human: raw, data: data}
	case SchemaOperationExport:
		schemaID, available := request.SchemaID()
		if !available {
			return execution{failure: executionFailureFor(invocation.Command(), errors.New("missing schema ID"), domain.FailureInternal)}
		}
		exportPath, available := request.ExportPath()
		if !available {
			return execution{failure: executionFailureFor(invocation.Command(), errors.New("missing export path"), domain.FailureInternal)}
		}
		id, err := ports.ParseAssetID(schemaID)
		if err != nil {
			return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureConfiguration)}
		}
		root, err := ports.NewAnchoredRoot(request.ProjectRoot())
		if err != nil {
			return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureConfiguration)}
		}
		destination, err := ports.NewSafeRelativePath(exportPath)
		if err != nil {
			return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureConfiguration)}
		}
		receipt, err := service.Export(ctx, id, root, destination)
		if err != nil {
			return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureArtifact)}
		}
		if receipt.Destination() != destination {
			return execution{failure: executionFailureFor(invocation.Command(), errors.New("export receipt mismatch"), domain.FailureArtifact)}
		}
		uri := receipt.Destination().String()
		data, err := schemaResultData(schemaID, &uri)
		if err != nil {
			return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureInternal)}
		}
		return execution{human: []byte("exported " + uri), data: data}
	default:
		return execution{failure: executionFailureFor(invocation.Command(), errors.New("unsupported operation"), domain.FailureConfiguration)}
	}
}

func (application *Application) handleInit(ctx context.Context, invocation Invocation) execution {
	request, available := invocation.Init()
	if !available {
		return execution{failure: executionFailureFor(invocation.Command(), errors.New("missing request"), domain.FailureInternal)}
	}
	root, err := ports.NewAnchoredRoot(request.ProjectRoot())
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureConfiguration)}
	}
	var contextPath *ports.SafeRelativePath
	if raw, present := request.ContextPath(); present {
		parsed, err := ports.NewSafeRelativePath(raw)
		if err != nil {
			return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureConfiguration)}
		}
		contextPath = &parsed
	}
	service, err := appinit.NewService(application.writer, application.clock)
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureInternal)}
	}
	initialized, err := service.InitializeProject(ctx, appinit.InitializeProjectRequest{
		ProjectRoot:         root,
		ProjectName:         request.ProjectName(),
		ContextPath:         contextPath,
		IntendedProviderIDs: request.IntendedProviderIDs(),
		OptionalProviderIDs: request.OptionalProviderIDs(),
	})
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureArtifact)}
	}
	if initialized.ConfigReceipt.Destination().String() != ".kar.yaml" {
		return execution{failure: executionFailureFor(invocation.Command(), errors.New("initialization receipt mismatch"), domain.FailureArtifact)}
	}
	for _, provider := range initialized.ProviderStatuses {
		if provider.Status != "unverified" {
			return execution{failure: executionFailureFor(invocation.Command(), errors.New("provider status promoted"), domain.FailureInternal)}
		}
	}
	projectConfigURI := initialized.ConfigReceipt.Destination().String()
	data, err := json.Marshal(struct {
		Kind                string   `json:"kind"`
		ProjectConfigURI    string   `json:"project_config_uri"`
		IntendedProviderIDs []string `json:"intended_provider_ids"`
	}{"initialized", projectConfigURI, request.IntendedProviderIDs()})
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureInternal)}
	}
	var output strings.Builder
	output.WriteString("initialized: ")
	output.WriteString(projectConfigURI)
	for _, provider := range initialized.ProviderStatuses {
		output.WriteByte('\n')
		output.WriteString(provider.ID)
		output.WriteString(": ")
		output.WriteString(provider.Status)
	}
	return execution{human: []byte(output.String()), data: data}
}

func (application *Application) handleConfig(ctx context.Context, invocation Invocation) execution {
	request, available := invocation.Config()
	if !available {
		return execution{failure: executionFailureFor(invocation.Command(), errors.New("missing request"), domain.FailureInternal)}
	}
	root, err := ports.NewAnchoredRoot(request.ProjectRoot())
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureConfiguration)}
	}
	globalID, err := ports.ParseAssetID(globalConfigAssetID)
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureInternal)}
	}
	metadata, globalYAML, err := application.catalog.Read(ctx, globalID)
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureArtifact)}
	}
	globalDigest := sha256.Sum256(globalYAML)
	if metadata.ID() != globalID ||
		metadata.Kind() != ports.AssetKindDefaults ||
		metadata.ByteLength() != int64(len(globalYAML)) ||
		metadata.SHA256() != "sha256:"+hex.EncodeToString(globalDigest[:]) {
		return execution{failure: executionFailureFor(invocation.Command(), errors.New("global default metadata mismatch"), domain.FailureArtifact)}
	}

	resolveRequest := appconfig.ResolveRequest{GlobalYAML: globalYAML}
	if rawPath, enabled := request.ProjectConfigPath(); enabled {
		path, err := ports.NewSafeRelativePath(rawPath)
		if err != nil {
			return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureConfiguration)}
		}
		expectedCommit, err := ports.ParseGitObjectID(request.Reference())
		if err != nil {
			return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureConfiguration)}
		}
		resolveRequest.Project = &appconfig.ProjectConfigRequest{
			Root:           root,
			ExpectedCommit: expectedCommit,
			Reference:      expectedCommit.String(),
			Path:           &path,
		}
	}
	service, err := appconfig.NewService(application.projectReader)
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureInternal)}
	}
	resolved, err := service.Resolve(ctx, resolveRequest)
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureConfiguration)}
	}
	output, err := resolvedConfigOutput(request, resolved)
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureInternal)}
	}

	if invocation.OutputFormat() == OutputFormatHuman {
		return execution{human: output, data: nil}
	}
	destination, err := ports.NewSafeRelativePath(".kar/config/" + invocation.RequestID() + ".json")
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureInternal)}
	}
	directory, err := ports.NewSafeRelativePath(".kar/config")
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureInternal)}
	}
	sourceIDs := configResolutionSourceIDs(resolved)
	receipt, err := application.persistJSON(ctx, root, directory, destination, "config_resolution", sourceIDs, output)
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureArtifact)}
	}
	uri := receipt.Destination().String()
	data, err := json.Marshal(struct {
		Kind              string `json:"kind"`
		ResolvedPolicyURI string `json:"resolved_policy_uri"`
		PolicySHA256      string `json:"policy_sha256"`
	}{"configuration_resolved", uri, receipt.SHA256()})
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureInternal)}
	}
	return execution{human: output, data: data}
}

func (application *Application) handleDoctor(ctx context.Context, invocation Invocation) execution {
	request, available := invocation.Doctor()
	if !available {
		return execution{failure: executionFailureFor(invocation.Command(), errors.New("missing request"), domain.FailureInternal)}
	}
	root, err := ports.NewAnchoredRoot(request.ProjectRoot())
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureConfiguration)}
	}
	service, err := doctor.NewService(application.clock, application.catalog, application.inspector, nil, root)
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureInternal)}
	}
	diagnosis, err := service.DiagnoseEnvironment(ctx)
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureArtifact)}
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

	if invocation.OutputFormat() == OutputFormatHuman {
		if diagnosis.Readiness.State == doctor.ReadinessReady {
			return execution{human: raw, data: nil}
		}
		return execution{
			human: raw,
			failure: &executionFailure{
				class: domain.FailureProviderUnavailable,
				code:  "readiness_unverified",
				stage: "cli.doctor",
				exit:  app.ExitCodeReadiness,
			},
		}
	}

	destination, err := ports.NewSafeRelativePath(".kar/diagnostics/" + invocation.RequestID() + ".json")
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureInternal)}
	}
	directory, err := ports.NewSafeRelativePath(".kar/diagnostics")
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureInternal)}
	}
	receipt, err := application.persistJSON(ctx, root, directory, destination, "doctor_result", []string{doctorResultSchema}, raw)
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureArtifact)}
	}
	uri := receipt.Destination().String()
	data, err := json.Marshal(struct {
		Kind            string `json:"kind"`
		DoctorResultURI string `json:"doctor_result_uri"`
		Readiness       string `json:"readiness"`
	}{"diagnosed", uri, string(diagnosis.Readiness.State)})
	if err != nil {
		return execution{failure: executionFailureFor(invocation.Command(), err, domain.FailureInternal)}
	}
	if diagnosis.Readiness.State == doctor.ReadinessReady {
		return execution{human: raw, data: data}
	}
	return execution{
		human:       raw,
		data:        data,
		failureData: data,
		failure: &executionFailure{
			class: domain.FailureProviderUnavailable,
			code:  "readiness_unverified",
			stage: "cli.doctor",
			exit:  app.ExitCodeReadiness,
		},
	}
}

type configurationOutput struct {
	Mode              ConfigMode                      `json:"mode"`
	Policy            json.RawMessage                 `json:"policy"`
	ProjectProvenance *configurationProjectProvenance `json:"project_provenance"`
}

type configurationProjectProvenance struct {
	Commit string `json:"commit"`
	Path   string `json:"path"`
}

func resolvedConfigOutput(request ConfigRequest, resolved appconfig.Resolution) ([]byte, error) {
	policy := resolved.RedactedJSON()
	if !json.Valid(policy) {
		return nil, errors.New("redacted policy JSON is invalid")
	}
	var provenance *configurationProjectProvenance
	if project, available := resolved.Project(); available {
		provenance = &configurationProjectProvenance{
			Commit: project.Commit().String(),
			Path:   project.Path().String(),
		}
	}
	return json.Marshal(configurationOutput{
		Mode:              request.Mode(),
		Policy:            json.RawMessage(policy),
		ProjectProvenance: provenance,
	})
}
func configResolutionSourceIDs(resolved appconfig.Resolution) []string {
	sourceIDs := []string{globalConfigAssetID, "config:resolved-policy:v1"}
	if project, available := resolved.Project(); available {
		sourceIDs = append(sourceIDs, "config:project:"+project.Commit().String()+":"+project.Path().String())
	}
	return sourceIDs
}

func schemaResultData(schemaID string, exportURI *string) ([]byte, error) {
	return json.Marshal(struct {
		Kind      string  `json:"kind"`
		SchemaID  string  `json:"schema_id"`
		ExportURI *string `json:"export_uri"`
	}{"schema_inspected", schemaID, exportURI})
}

func (application *Application) persistJSON(
	ctx context.Context,
	root ports.AnchoredRoot,
	directory ports.SafeRelativePath,
	destination ports.SafeRelativePath,
	channel string,
	sourceIDs []string,
	contents []byte,
) (ports.SecureWriteReceipt, error) {
	if err := application.writer.EnsurePrivateDir(root, directory); err != nil {
		return ports.SecureWriteReceipt{}, typedHandlerFailure("cli.persist", domain.FailureArtifact, "private output directory unavailable", err)
	}
	aborted := false
	var abortCause error
	request, err := ports.NewSecureWriteRequest(
		root,
		destination,
		channel,
		bytes.NewReader(contents),
		int64(len(contents)),
		sourceIDs,
		func(cause error) {
			aborted = true
			abortCause = cause
		},
	)
	if err != nil {
		return ports.SecureWriteReceipt{}, typedHandlerFailure("cli.persist", domain.FailureInternal, "output request construction failed", err)
	}
	receipt, drop, writeErr := application.writer.Write(ctx, request)
	if drop != nil {
		return ports.SecureWriteReceipt{}, typedHandlerFailure("cli.persist", domain.FailureSecurityPolicy, "secure writer rejected output", firstHandlerError(writeErr, abortCause))
	}
	if writeErr != nil {
		return ports.SecureWriteReceipt{}, typedHandlerFailure("cli.persist", domain.FailureArtifact, "output write failed", writeErr)
	}
	if aborted {
		return ports.SecureWriteReceipt{}, typedHandlerFailure("cli.persist", domain.FailureInternal, "secure writer abort callback was not accompanied by a rejection", abortCause)
	}
	expected := sha256.Sum256(contents)
	if receipt.Root() != root ||
		receipt.Destination() != destination ||
		receipt.ByteLength() != int64(len(contents)) ||
		receipt.SHA256() != "sha256:"+hex.EncodeToString(expected[:]) ||
		receipt.Channel() != channel ||
		!sameStrings(receipt.SourceIDs(), sourceIDs) {
		return ports.SecureWriteReceipt{}, typedHandlerFailure("cli.persist", domain.FailureArtifact, "output receipt did not bind accepted bytes and lineage", nil)
	}
	return receipt, nil
}
func sameStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func firstHandlerError(primary, fallback error) error {
	if primary != nil {
		return primary
	}
	return fallback
}

func typedHandlerFailure(stage string, class domain.FailureClass, reason string, cause error) error {
	failure, err := domain.NewFailure(stage, class, reason, cause)
	if err != nil {
		return errors.New("handler failure invariant")
	}
	return failure
}
