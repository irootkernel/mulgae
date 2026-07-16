package kar

import (
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"path/filepath"
	"strings"

	"github.com/irootkernel/kkachi-agent-review/internal/app"
	"github.com/irootkernel/kkachi-agent-review/internal/domain"
)

const (
	maximumPathLength             = 4096
	maximumSchemaIdentifierLength = 1024
)

// ErrUsage marks an argument error that the CLI must render with exit code 2.
var ErrUsage = errors.New("kar usage error")

// Parse converts command-line arguments into one immutable KAR invocation. The
// caller must supply a canonical default project root and a UUIDv7 request ID.
// Parse does not inspect the filesystem, environment, or service state.
func Parse(arguments []string, defaultProjectRoot, requestID string) (Invocation, error) {
	if !validAbsoluteRoot(defaultProjectRoot) {
		return Invocation{}, usageError("default project root is not canonical")
	}
	if !validRequestID(requestID) {
		return Invocation{}, usageError("request ID is not a UUIDv7 invocation ID")
	}
	if len(arguments) == 0 {
		return parseHelp(nil, requestID)
	}
	if arguments[0] == "--help" {
		if len(arguments) != 1 {
			return Invocation{}, usageError("--help cannot be combined with other arguments")
		}
		return parseHelp(nil, requestID)
	}

	command, err := parseCommand(arguments[0])
	if err != nil {
		return Invocation{}, err
	}
	remaining := arguments[1:]
	switch command {
	case app.CommandHelp:
		return parseHelp(remaining, requestID)
	case app.CommandInit:
		return parseInit(remaining, defaultProjectRoot, requestID)
	case app.CommandDoctor:
		return parseDoctor(remaining, defaultProjectRoot, requestID)
	case app.CommandStatus:
		return parseStatus(remaining, requestID)
	case app.CommandReport:
		return parseReport(remaining, requestID)
	case app.CommandFindings:
		return parseFindings(remaining, requestID)
	case app.CommandExcerpt:
		return parseExcerpt(remaining, requestID)
	case app.CommandConfig:
		return parseConfig(remaining, defaultProjectRoot, requestID)
	case app.CommandSchema:
		return parseSchema(remaining, defaultProjectRoot, requestID)
	default:
		if len(remaining) != 0 {
			return Invocation{}, usageError("future command %q does not accept arguments in this milestone", command)
		}
		return Invocation{
			command:      command,
			availability: AvailabilityFutureMilestone,
			requestID:    requestID,
			outputFormat: OutputFormatHuman,
		}, nil
	}
}

func parseCommand(value string) (app.CommandName, error) {
	command := app.CommandName(value)
	switch command {
	case app.CommandInit,
		app.CommandDoctor,
		app.CommandReview,
		app.CommandFollowup,
		app.CommandDelta,
		app.CommandRerun,
		app.CommandStatus,
		app.CommandReport,
		app.CommandFindings,
		app.CommandExcerpt,
		app.CommandProviders,
		app.CommandConfig,
		app.CommandPrompt,
		app.CommandSchema,
		app.CommandClean,
		app.CommandExport,
		app.CommandHelp:
		return command, nil
	default:
		return "", usageError("unknown command")
	}
}

func parseHelp(arguments []string, requestID string) (Invocation, error) {
	positionals, options, err := parseOptions(arguments, map[string]bool{
		"--output": true,
	})
	if err != nil {
		return Invocation{}, err
	}
	if len(positionals) > 1 {
		return Invocation{}, usageError("help accepts at most one topic")
	}
	topic := "quickstart"
	if len(positionals) == 1 {
		topic = positionals[0]
	}
	if !validHelpTopic(topic) {
		return Invocation{}, usageError("unsupported help topic")
	}
	outputFormat, err := optionOutputFormat(options)
	if err != nil {
		return Invocation{}, err
	}
	requestJSON, err := marshalRequest(struct {
		RequestID    string       `json:"request_id"`
		Command      string       `json:"command"`
		Topic        string       `json:"topic"`
		OutputFormat OutputFormat `json:"output_format"`
	}{
		RequestID:    requestID,
		Command:      string(app.CommandHelp),
		Topic:        topic,
		OutputFormat: outputFormat,
	})
	if err != nil {
		return Invocation{}, err
	}
	return Invocation{
		command:        app.CommandHelp,
		availability:   AvailabilityFoundation,
		requestID:      requestID,
		outputFormat:   outputFormat,
		requestJSON:    requestJSON,
		hasRequestJSON: true,
		help:           &HelpRequest{topic: topic},
	}, nil
}

func parseInit(arguments []string, defaultProjectRoot, requestID string) (Invocation, error) {
	positionals, options, err := parseOptions(arguments, map[string]bool{
		"--project-root":       true,
		"--name":               true,
		"--context":            true,
		"--providers":          true,
		"--optional-providers": true,
		"--output":             true,
	})
	if err != nil {
		return Invocation{}, err
	}
	if len(positionals) != 0 {
		return Invocation{}, usageError("init accepts no positional arguments")
	}
	projectRoot, err := optionProjectRoot(options, defaultProjectRoot)
	if err != nil {
		return Invocation{}, err
	}
	projectName := filepath.Base(projectRoot)
	if value, present := options["--name"]; present {
		projectName = value
	}
	if !validProjectName(projectName) {
		return Invocation{}, usageError("project name is not a canonical token")
	}

	request := InitRequest{
		projectRoot:         projectRoot,
		projectName:         projectName,
		intendedProviderIDs: []string{"kimi", "zcode", "agy"},
		overwrite:           false,
	}
	if value, present := options["--context"]; present {
		if !validRelativePath(value) {
			return Invocation{}, usageError("context path is not a safe relative path")
		}
		request.contextPath = value
		request.hasContextPath = true
	}
	if value, present := options["--providers"]; present {
		providers, parseErr := parseProviderCSV(value, intendedProvider)
		if parseErr != nil {
			return Invocation{}, parseErr
		}
		request.intendedProviderIDs = providers
	}
	if value, present := options["--optional-providers"]; present {
		providers, parseErr := parseProviderCSV(value, optionalProvider)
		if parseErr != nil {
			return Invocation{}, parseErr
		}
		request.optionalProviderIDs = providers
	}
	if hasDuplicateProvider(request.intendedProviderIDs, request.optionalProviderIDs) {
		return Invocation{}, usageError("provider IDs must be unique across provider lists")
	}
	outputFormat, err := optionOutputFormat(options)
	if err != nil {
		return Invocation{}, err
	}
	if outputFormat == OutputFormatJSON {
		if _, present := options["--name"]; present {
			return Invocation{}, usageError("JSON init cannot represent --name")
		}
		if _, present := options["--context"]; present {
			return Invocation{}, usageError("JSON init cannot represent --context")
		}
		if _, present := options["--optional-providers"]; present {
			return Invocation{}, usageError("JSON init cannot represent --optional-providers")
		}
	}
	requestJSON, err := marshalRequest(struct {
		RequestID           string       `json:"request_id"`
		Command             string       `json:"command"`
		ProjectRoot         string       `json:"project_root"`
		IntendedProviderIDs []string     `json:"intended_provider_ids"`
		Overwrite           bool         `json:"overwrite"`
		OutputFormat        OutputFormat `json:"output_format"`
	}{
		RequestID:           requestID,
		Command:             string(app.CommandInit),
		ProjectRoot:         request.projectRoot,
		IntendedProviderIDs: cloneStrings(request.intendedProviderIDs),
		Overwrite:           request.overwrite,
		OutputFormat:        outputFormat,
	})
	if err != nil {
		return Invocation{}, err
	}
	return Invocation{
		command:        app.CommandInit,
		availability:   AvailabilityFoundation,
		requestID:      requestID,
		outputFormat:   outputFormat,
		requestJSON:    requestJSON,
		hasRequestJSON: true,
		init:           &request,
	}, nil
}

func parseDoctor(arguments []string, defaultProjectRoot, requestID string) (Invocation, error) {
	positionals, options, err := parseOptions(arguments, map[string]bool{
		"--project-root": true,
		"--output":       true,
	})
	if err != nil {
		return Invocation{}, err
	}
	if len(positionals) != 0 {
		return Invocation{}, usageError("doctor accepts no positional arguments")
	}
	projectRoot, err := optionProjectRoot(options, defaultProjectRoot)
	if err != nil {
		return Invocation{}, err
	}
	outputFormat, err := optionOutputFormat(options)
	if err != nil {
		return Invocation{}, err
	}
	request := DoctorRequest{
		projectRoot:    projectRoot,
		checkProviders: true,
		checkPlatform:  true,
	}
	requestJSON, err := marshalRequest(struct {
		RequestID      string       `json:"request_id"`
		Command        string       `json:"command"`
		ProjectRoot    string       `json:"project_root"`
		CheckProviders bool         `json:"check_providers"`
		CheckPlatform  bool         `json:"check_platform"`
		OutputFormat   OutputFormat `json:"output_format"`
	}{
		RequestID:      requestID,
		Command:        string(app.CommandDoctor),
		ProjectRoot:    request.projectRoot,
		CheckProviders: request.checkProviders,
		CheckPlatform:  request.checkPlatform,
		OutputFormat:   outputFormat,
	})
	if err != nil {
		return Invocation{}, err
	}
	return Invocation{
		command:        app.CommandDoctor,
		availability:   AvailabilityFoundation,
		requestID:      requestID,
		outputFormat:   outputFormat,
		requestJSON:    requestJSON,
		hasRequestJSON: true,
		doctor:         &request,
	}, nil
}
func parseStatus(arguments []string, requestID string) (Invocation, error) {
	positionals, options, err := parseOptions(arguments, map[string]bool{
		"--run":    true,
		"--output": true,
	})
	if err != nil {
		return Invocation{}, err
	}
	if len(positionals) != 0 {
		return Invocation{}, usageError("status accepts no positional arguments")
	}
	runID, err := optionRunID(options)
	if err != nil {
		return Invocation{}, err
	}
	outputFormat, err := optionOutputFormat(options)
	if err != nil {
		return Invocation{}, err
	}
	request := StatusRequest{runID: runID}
	requestJSON, err := marshalRequest(struct {
		RequestID    string       `json:"request_id"`
		Command      string       `json:"command"`
		RunID        string       `json:"run_id"`
		OutputFormat OutputFormat `json:"output_format"`
	}{
		RequestID:    requestID,
		Command:      string(app.CommandStatus),
		RunID:        request.runID,
		OutputFormat: outputFormat,
	})
	if err != nil {
		return Invocation{}, err
	}
	return Invocation{
		command:        app.CommandStatus,
		availability:   AvailabilityFoundation,
		requestID:      requestID,
		outputFormat:   outputFormat,
		requestJSON:    requestJSON,
		hasRequestJSON: true,
		status:         &request,
	}, nil
}

func parseReport(arguments []string, requestID string) (Invocation, error) {
	positionals, options, err := parseOptions(arguments, map[string]bool{
		"--run":         true,
		"--output-path": true,
		"--output":      true,
	})
	if err != nil {
		return Invocation{}, err
	}
	if len(positionals) != 0 {
		return Invocation{}, usageError("report accepts no positional arguments")
	}
	runID, err := optionRunID(options)
	if err != nil {
		return Invocation{}, err
	}
	outputPath, present := options["--output-path"]
	if !present {
		return Invocation{}, usageError("report requires --output-path")
	}
	if !validRelativePath(outputPath) {
		return Invocation{}, usageError("report output path is not a safe relative path")
	}
	if reportOutputUsesControlNamespace(outputPath) {
		return Invocation{}, usageError("report output path is reserved")
	}
	outputFormat, err := optionOutputFormat(options)
	if err != nil {
		return Invocation{}, err
	}
	request := ReportRequest{
		runID:      runID,
		outputPath: outputPath,
	}
	requestJSON, err := marshalRequest(struct {
		RequestID    string       `json:"request_id"`
		Command      string       `json:"command"`
		RunID        string       `json:"run_id"`
		OutputPath   string       `json:"output_path"`
		OutputFormat OutputFormat `json:"output_format"`
	}{
		RequestID:    requestID,
		Command:      string(app.CommandReport),
		RunID:        request.runID,
		OutputPath:   request.outputPath,
		OutputFormat: outputFormat,
	})
	if err != nil {
		return Invocation{}, err
	}
	return Invocation{
		command:        app.CommandReport,
		availability:   AvailabilityFoundation,
		requestID:      requestID,
		outputFormat:   outputFormat,
		requestJSON:    requestJSON,
		hasRequestJSON: true,
		report:         &request,
	}, nil
}

func parseFindings(arguments []string, requestID string) (Invocation, error) {
	positionals, options, err := parseOptions(arguments, map[string]bool{
		"--run":      true,
		"--severity": true,
		"--output":   true,
	})
	if err != nil {
		return Invocation{}, err
	}
	if len(positionals) != 0 {
		return Invocation{}, usageError("findings accepts no positional arguments")
	}
	runID, err := optionRunID(options)
	if err != nil {
		return Invocation{}, err
	}
	severity, present := options["--severity"]
	if !present {
		return Invocation{}, usageError("findings requires --severity")
	}
	minimumSeverity := domain.Severity(severity)
	if !validMinimumSeverity(minimumSeverity) {
		return Invocation{}, usageError("unsupported minimum severity")
	}
	outputFormat, err := optionOutputFormat(options)
	if err != nil {
		return Invocation{}, err
	}
	request := FindingsRequest{
		runID:           runID,
		minimumSeverity: minimumSeverity,
	}
	requestJSON, err := marshalRequest(struct {
		RequestID       string          `json:"request_id"`
		Command         string          `json:"command"`
		RunID           string          `json:"run_id"`
		MinimumSeverity domain.Severity `json:"minimum_severity"`
		OutputFormat    OutputFormat    `json:"output_format"`
	}{
		RequestID:       requestID,
		Command:         string(app.CommandFindings),
		RunID:           request.runID,
		MinimumSeverity: request.minimumSeverity,
		OutputFormat:    outputFormat,
	})
	if err != nil {
		return Invocation{}, err
	}
	return Invocation{
		command:        app.CommandFindings,
		availability:   AvailabilityFoundation,
		requestID:      requestID,
		outputFormat:   outputFormat,
		requestJSON:    requestJSON,
		hasRequestJSON: true,
		findings:       &request,
	}, nil
}

func parseExcerpt(arguments []string, requestID string) (Invocation, error) {
	positionals, options, err := parseOptions(arguments, map[string]bool{
		"--run":                   true,
		"--finding":               true,
		"--current-target-sha256": true,
		"--output":                true,
	})
	if err != nil {
		return Invocation{}, err
	}
	if len(positionals) != 0 {
		return Invocation{}, usageError("excerpt accepts no positional arguments")
	}
	runID, err := optionRunID(options)
	if err != nil {
		return Invocation{}, err
	}
	findingID, present := options["--finding"]
	if !present {
		return Invocation{}, usageError("excerpt requires --finding")
	}
	if !validFindingID(findingID) {
		return Invocation{}, usageError("finding ID must match Fddd+")
	}
	currentTargetSHA256, present := options["--current-target-sha256"]
	if !present {
		return Invocation{}, usageError("excerpt requires --current-target-sha256")
	}
	if !validSHA256Identifier(currentTargetSHA256) {
		return Invocation{}, usageError("current target SHA-256 is not canonical")
	}
	outputFormat, err := optionOutputFormat(options)
	if err != nil {
		return Invocation{}, err
	}
	request := ExcerptRequest{
		runID:               runID,
		findingID:           findingID,
		currentTargetSHA256: currentTargetSHA256,
	}
	requestJSON, err := marshalRequest(struct {
		RequestID           string       `json:"request_id"`
		Command             string       `json:"command"`
		RunID               string       `json:"run_id"`
		FindingID           string       `json:"finding_id"`
		CurrentTargetSHA256 string       `json:"current_target_sha256"`
		OutputFormat        OutputFormat `json:"output_format"`
	}{
		RequestID:           requestID,
		Command:             string(app.CommandExcerpt),
		RunID:               request.runID,
		FindingID:           request.findingID,
		CurrentTargetSHA256: request.currentTargetSHA256,
		OutputFormat:        outputFormat,
	})
	if err != nil {
		return Invocation{}, err
	}
	return Invocation{
		command:        app.CommandExcerpt,
		availability:   AvailabilityFoundation,
		requestID:      requestID,
		outputFormat:   outputFormat,
		requestJSON:    requestJSON,
		hasRequestJSON: true,
		excerpt:        &request,
	}, nil
}

func parseConfig(arguments []string, defaultProjectRoot, requestID string) (Invocation, error) {
	positionals, options, err := parseOptions(arguments, map[string]bool{
		"--project-root":   true,
		"--ref":            true,
		"--project-config": true,
		"--mode":           true,
		"--output":         true,
	})
	if err != nil {
		return Invocation{}, err
	}
	if len(positionals) != 0 {
		return Invocation{}, usageError("config accepts no positional arguments")
	}
	projectRoot, err := optionProjectRoot(options, defaultProjectRoot)
	if err != nil {
		return Invocation{}, err
	}
	request := ConfigRequest{
		projectRoot: projectRoot,
		mode:        ConfigModeEffective,
	}
	reference, hasReference := options["--ref"]
	if hasReference {
		if !validGitObjectID(reference) {
			return Invocation{}, usageError("reference must be an exact lowercase Git object ID")
		}
		request.reference = reference
	}
	if value, present := options["--project-config"]; present {
		if value == "none" {
			request.projectConfigEnabled = false
		} else if !validRelativePath(value) {
			return Invocation{}, usageError("project configuration path is not a safe relative path")
		} else {
			request.projectConfigPath = value
			request.projectConfigEnabled = true
		}
	}
	if request.projectConfigEnabled && !hasReference {
		return Invocation{}, usageError("project configuration requires an exact --ref object ID")
	}
	if !request.projectConfigEnabled && hasReference {
		return Invocation{}, usageError("--ref requires an enabled --project-config")
	}
	if value, present := options["--mode"]; present {
		switch ConfigMode(value) {
		case ConfigModeEffective, ConfigModeProvenance:
			request.mode = ConfigMode(value)
		default:
			return Invocation{}, usageError("unsupported configuration mode")
		}
	}
	outputFormat, err := optionOutputFormat(options)
	if err != nil {
		return Invocation{}, err
	}
	if outputFormat == OutputFormatJSON && request.projectConfigEnabled {
		return Invocation{}, usageError("JSON config cannot represent immutable project configuration inputs")
	}
	requestJSON, err := marshalRequest(struct {
		RequestID    string       `json:"request_id"`
		Command      string       `json:"command"`
		ProjectRoot  string       `json:"project_root"`
		Mode         ConfigMode   `json:"mode"`
		OutputFormat OutputFormat `json:"output_format"`
	}{
		RequestID:    requestID,
		Command:      string(app.CommandConfig),
		ProjectRoot:  request.projectRoot,
		Mode:         request.mode,
		OutputFormat: outputFormat,
	})
	if err != nil {
		return Invocation{}, err
	}
	return Invocation{
		command:        app.CommandConfig,
		availability:   AvailabilityFoundation,
		requestID:      requestID,
		outputFormat:   outputFormat,
		requestJSON:    requestJSON,
		hasRequestJSON: true,
		config:         &request,
	}, nil
}

func parseSchema(arguments []string, defaultProjectRoot, requestID string) (Invocation, error) {
	positionals, options, err := parseOptions(arguments, map[string]bool{
		"--project-root": true,
		"--output":       true,
	})
	if err != nil {
		return Invocation{}, err
	}
	if len(positionals) == 0 {
		return Invocation{}, usageError("schema requires an operation")
	}
	projectRoot, err := optionProjectRoot(options, defaultProjectRoot)
	if err != nil {
		return Invocation{}, err
	}
	outputFormat, err := optionOutputFormat(options)
	if err != nil {
		return Invocation{}, err
	}
	request := SchemaRequest{
		projectRoot: projectRoot,
	}
	switch positionals[0] {
	case string(SchemaOperationList):
		if len(positionals) != 1 {
			return Invocation{}, usageError("schema list accepts no additional positional arguments")
		}
		request.operation = SchemaOperationList
		return Invocation{
			command:      app.CommandSchema,
			availability: AvailabilityFoundation,
			requestID:    requestID,
			outputFormat: outputFormat,
			schema:       &request,
		}, nil
	case string(SchemaOperationShow):
		if len(positionals) != 2 {
			return Invocation{}, usageError("schema show requires exactly one schema ID")
		}
		request.operation = SchemaOperationShow
		request.schemaID = positionals[1]
		request.hasSchemaID = true
	case string(SchemaOperationExport):
		if len(positionals) != 3 {
			return Invocation{}, usageError("schema export requires a schema ID and export path")
		}
		request.operation = SchemaOperationExport
		request.schemaID = positionals[1]
		request.hasSchemaID = true
		request.exportPath = positionals[2]
		request.hasExportPath = true
	default:
		return Invocation{}, usageError("unsupported schema operation")
	}
	if !validSchemaID(request.schemaID) {
		return Invocation{}, usageError("schema ID does not match the command contract")
	}
	if request.hasExportPath && !validRelativePath(request.exportPath) {
		return Invocation{}, usageError("schema export path is not a safe relative path")
	}
	if outputFormat == OutputFormatJSON && request.hasExportPath {
		if _, present := options["--project-root"]; present {
			return Invocation{}, usageError("JSON schema export cannot represent an explicit project root")
		}
	}
	var exportPath *string
	if request.hasExportPath {
		exportPath = &request.exportPath
	}
	requestJSON, err := marshalRequest(struct {
		RequestID    string       `json:"request_id"`
		Command      string       `json:"command"`
		SchemaID     string       `json:"schema_id"`
		ExportPath   *string      `json:"export_path"`
		OutputFormat OutputFormat `json:"output_format"`
	}{
		RequestID:    requestID,
		Command:      string(app.CommandSchema),
		SchemaID:     request.schemaID,
		ExportPath:   exportPath,
		OutputFormat: outputFormat,
	})
	if err != nil {
		return Invocation{}, err
	}
	return Invocation{
		command:        app.CommandSchema,
		availability:   AvailabilityFoundation,
		requestID:      requestID,
		outputFormat:   outputFormat,
		requestJSON:    requestJSON,
		hasRequestJSON: true,
		schema:         &request,
	}, nil
}

func parseOptions(arguments []string, allowed map[string]bool) ([]string, map[string]string, error) {
	positionals := make([]string, 0, len(arguments))
	options := make(map[string]string, len(allowed))
	for index := 0; index < len(arguments); index++ {
		argument := arguments[index]
		if !strings.HasPrefix(argument, "-") {
			positionals = append(positionals, argument)
			continue
		}
		if !strings.HasPrefix(argument, "--") || argument == "--" || !allowed[argument] {
			return nil, nil, usageError("unknown flag")
		}
		if _, duplicate := options[argument]; duplicate {
			return nil, nil, usageError("duplicate flag")
		}
		if index+1 == len(arguments) || strings.HasPrefix(arguments[index+1], "--") {
			return nil, nil, usageError("flag value is missing")
		}
		options[argument] = arguments[index+1]
		index++
	}
	return positionals, options, nil
}

func optionRunID(options map[string]string) (string, error) {
	value, present := options["--run"]
	if !present {
		return "", usageError("command requires --run")
	}
	runID, err := domain.ParseRunID(value)
	if err != nil {
		return "", usageError("run ID is not a canonical UUIDv7")
	}
	return runID.String(), nil
}

func optionProjectRoot(options map[string]string, defaultProjectRoot string) (string, error) {
	projectRoot := defaultProjectRoot
	if value, present := options["--project-root"]; present {
		projectRoot = value
	}
	if !validAbsoluteRoot(projectRoot) {
		return "", usageError("project root is not canonical")
	}
	return projectRoot, nil
}

func optionOutputFormat(options map[string]string) (OutputFormat, error) {
	if value, present := options["--output"]; present {
		if value == string(OutputFormatJSON) {
			return OutputFormatJSON, nil
		}
		if value == string(OutputFormatHuman) {
			return OutputFormatHuman, nil
		}
		return "", usageError("unsupported output format")
	}
	return OutputFormatHuman, nil
}

func parseProviderCSV(value string, allowed func(string) bool) ([]string, error) {
	if value == "" || strings.ContainsAny(value, "\x00\r\n") {
		return nil, usageError("provider list is malformed")
	}
	values := strings.Split(value, ",")
	providers := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, provider := range values {
		if provider == "" || !allowed(provider) {
			return nil, usageError("provider list contains an unsupported provider")
		}
		if _, duplicate := seen[provider]; duplicate {
			return nil, usageError("provider list contains a duplicate provider")
		}
		seen[provider] = struct{}{}
		providers = append(providers, provider)
	}
	return providers, nil
}

func intendedProvider(value string) bool {
	switch value {
	case "kimi", "zcode", "agy":
		return true
	default:
		return false
	}
}

func optionalProvider(value string) bool {
	switch value {
	case "codex", "claude":
		return true
	default:
		return false
	}
}

func hasDuplicateProvider(intended, optional []string) bool {
	seen := make(map[string]struct{}, len(intended)+len(optional))
	for _, provider := range intended {
		seen[provider] = struct{}{}
	}
	for _, provider := range optional {
		if _, exists := seen[provider]; exists {
			return true
		}
		seen[provider] = struct{}{}
	}
	return false
}

func validHelpTopic(value string) bool {
	switch value {
	case "quickstart", "config", "providers", "roles", "lanes", "prompts",
		"workflows", "artifacts", "validation", "ci", "exit-codes", "security":
		return true
	default:
		return false
	}
}

func validAbsoluteRoot(value string) bool {
	return value != "" &&
		len(value) <= maximumPathLength &&
		!strings.ContainsAny(value, "\x00\r\n") &&
		!strings.Contains(value, "\\") &&
		filepath.IsAbs(value) &&
		filepath.Clean(value) == value
}

func validRelativePath(value string) bool {
	if value == "" || len(value) > maximumPathLength || strings.ContainsAny(value, "\x00\r\n") || strings.Contains(value, "\\") {
		return false
	}
	if path.IsAbs(value) || filepath.IsAbs(value) || value == "." || value == ".." || path.Clean(value) != value {
		return false
	}
	for _, component := range strings.Split(value, "/") {
		if component == "." || component == ".." {
			return false
		}
	}
	return true
}

func validProjectName(value string) bool {
	if len(value) == 0 || len(value) > 64 {
		return false
	}
	for index := range value {
		character := value[index]
		if index == 0 || index == len(value)-1 {
			if !lowerAlphaNumeric(character) {
				return false
			}
			continue
		}
		if !lowerAlphaNumeric(character) && character != '.' && character != '-' && character != '_' {
			return false
		}
	}
	return true
}

func lowerAlphaNumeric(character byte) bool {
	return character >= 'a' && character <= 'z' || character >= '0' && character <= '9'
}

func validMinimumSeverity(value domain.Severity) bool {
	switch value {
	case domain.SeverityLow,
		domain.SeverityMedium,
		domain.SeverityHigh,
		domain.SeverityCritical,
		domain.SeverityBlocker:
		return true
	default:
		return false
	}
}

func validFindingID(value string) bool {
	if len(value) < 4 || len(value) > 64 || value[0] != 'F' {
		return false
	}
	for _, character := range value[1:] {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func validSHA256Identifier(value string) bool {
	const prefix = "sha256:"
	if !strings.HasPrefix(value, prefix) || len(value) != len(prefix)+64 {
		return false
	}
	for _, character := range value[len(prefix):] {
		if character < '0' || character > '9' {
			if character < 'a' || character > 'f' {
				return false
			}
		}
	}
	return true
}
func validGitObjectID(value string) bool {
	if len(value) != 40 && len(value) != 64 {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			if character < 'a' || character > 'f' {
				return false
			}
		}
	}
	return true
}

func validSchemaID(value string) bool {
	const prefix = "https://kar.local/schemas/"
	const suffix = ".schema.json"
	if len(value) == 0 || len(value) > maximumSchemaIdentifierLength || !strings.HasPrefix(value, prefix) || !strings.HasSuffix(value, suffix) {
		return false
	}
	identifier := value[len(prefix) : len(value)-len(suffix)]
	if identifier == "" {
		return false
	}
	for index := range identifier {
		character := identifier[index]
		if (character >= 'a' && character <= 'z') ||
			(character >= '0' && character <= '9') ||
			character == '.' || character == '-' {
			continue
		}
		return false
	}
	return true
}

func validRequestID(value string) bool {
	if len(value) != 38 || !strings.HasPrefix(value, "i_") || value[10] != '-' || value[15] != '-' || value[20] != '-' || value[25] != '-' || value[16] != '7' {
		return false
	}
	if value[21] != '8' && value[21] != '9' && value[21] != 'a' && value[21] != 'b' {
		return false
	}
	for index := 2; index < len(value); index++ {
		if index == 10 || index == 15 || index == 20 || index == 25 {
			continue
		}
		character := value[index]
		if !(character >= '0' && character <= '9' || character >= 'a' && character <= 'f') {
			return false
		}
	}
	return true
}

func marshalRequest(request any) ([]byte, error) {
	encoded, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("kar parser: marshal command request: %w", err)
	}
	return encoded, nil
}

func usageError(format string, arguments ...any) error {
	return fmt.Errorf("%w: %s", ErrUsage, fmt.Sprintf(format, arguments...))
}
