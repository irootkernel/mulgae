package kar

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/irootkernel/kkachi-agent-review/internal/app"
	"github.com/irootkernel/kkachi-agent-review/internal/domain"
	"golang.org/x/text/unicode/norm"
)

const (
	maximumPathLength             = 4096
	maximumSchemaIdentifierLength = 1024
)
const (
	stdinCaptureTokenPrefix = "stdin-capture-v1-"
	stdinCaptureTokenBytes  = 32
)

// ErrUsage marks an argument error that the CLI must render with exit code 2.
var ErrUsage = errors.New("kar usage error")

// ErrSelectorUnavailable marks a syntactically valid selector that has no unique match.
var ErrSelectorUnavailable = errors.New("kar selector unavailable")

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
	case app.CommandReview:
		return parseReview(remaining, requestID)
	case app.CommandStatus:
		return parseStatus(remaining, requestID)
	case app.CommandReport:
		return parseReport(remaining, requestID)
	case app.CommandProviders:
		return parseProviders(remaining, defaultProjectRoot, requestID)
	case app.CommandFindings:
		return parseFindings(remaining, requestID)
	case app.CommandExcerpt:
		return parseExcerpt(remaining, requestID)
	case app.CommandConfig:
		return parseConfig(remaining, defaultProjectRoot, requestID)
	case app.CommandPrompt:
		return parsePrompt(remaining, requestID)
	case app.CommandSchema:
		return parseSchema(remaining, defaultProjectRoot, requestID)
	case app.CommandFollowup:
		return parseFollowup(remaining, requestID)
	case app.CommandDelta:
		return parseDelta(remaining, requestID)
	case app.CommandRerun:
		return parseRerun(remaining, requestID)
	case app.CommandClean:
		return parseClean(remaining, requestID)
	case app.CommandExport:
		return parseExport(remaining, requestID)
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

// ParseResolved resolves documented CLI selectors before freezing the exact schema
// request object. Parse remains the pure canonical-ID entry point.
func ParseResolved(ctx context.Context, arguments []string, defaultProjectRoot, requestID string, resolver RequestResolver) (Invocation, error) {
	if len(arguments) == 0 {
		return Parse(arguments, defaultProjectRoot, requestID)
	}
	normalized := cloneStrings(arguments)
	var err error
	switch normalized[0] {
	case string(app.CommandReview):
		normalized, err = resolveCapturedStdin(ctx, normalized, resolver)
		if err != nil {
			return Invocation{}, err
		}
	case string(app.CommandFollowup):
		if err := resolveRunFlag(ctx, normalized, "--run", resolver); err != nil {
			return Invocation{}, err
		}
		normalized, err = resolveCapturedStdin(ctx, normalized, resolver)
		if err != nil {
			return Invocation{}, err
		}
	case string(app.CommandDelta):
		if err := resolveRunFlag(ctx, normalized, "--since-run", resolver); err != nil {
			return Invocation{}, err
		}
		normalized, err = resolveCapturedStdin(ctx, normalized, resolver)
		if err != nil {
			return Invocation{}, err
		}
	case string(app.CommandRerun):
		if err := resolveRunFlag(ctx, normalized, "--run", resolver); err != nil {
			return Invocation{}, err
		}
		normalized, err = resolveRerunSelector(ctx, normalized, resolver)
		if err != nil {
			return Invocation{}, err
		}
	case string(app.CommandExport):
		if err := resolveRunFlag(ctx, normalized, "--run", resolver); err != nil {
			return Invocation{}, err
		}
	}
	return Parse(normalized, defaultProjectRoot, requestID)
}

func resolveRunFlag(ctx context.Context, arguments []string, flag string, resolver RequestResolver) error {
	for index := 1; index < len(arguments); index++ {
		if arguments[index] != flag {
			continue
		}
		if index+1 == len(arguments) || strings.HasPrefix(arguments[index+1], "--") {
			return nil
		}
		if arguments[index+1] != "latest" {
			return nil
		}
		if resolver == nil {
			return usageError("%s latest selector requires a resolver", flag)
		}
		runID, err := resolver.ResolveRun(ctx, "latest")
		if err != nil {
			if errors.Is(err, ErrSelectorUnavailable) {
				return usageError("resolve latest run: %v", err)
			}
			return fmt.Errorf("resolve latest run: %w", err)
		}
		arguments[index+1] = runID
		return nil
	}
	return nil
}

func resolveCapturedStdin(ctx context.Context, arguments []string, resolver RequestResolver) ([]string, error) {
	stdinCount := 0
	stdinIndex := -1
	for index := 1; index < len(arguments); index++ {
		switch arguments[index] {
		case "--diff", "--patch", "--stdin":
			if arguments[index] == "--stdin" {
				stdinCount++
				stdinIndex = index
			}
		}
	}
	if stdinCount != 1 || stdinIndex == -1 || stdinIndex+1 < len(arguments) && !strings.HasPrefix(arguments[stdinIndex+1], "--") {
		return arguments, nil
	}
	if resolver == nil {
		return nil, usageError("valueless --stdin requires a resolver")
	}
	value, err := resolver.CaptureTarget(ctx)
	if err != nil {
		if errors.Is(err, ErrSelectorUnavailable) {
			return nil, usageError("capture stdin target: %v", err)
		}
		return nil, fmt.Errorf("capture stdin target: %w", err)
	}
	if !validCapturedStdinToken(value) {
		return nil, usageError("captured stdin target is malformed")
	}
	normalized := make([]string, 0, len(arguments)+1)
	normalized = append(normalized, arguments[:stdinIndex+1]...)
	normalized = append(normalized, value)
	return append(normalized, arguments[stdinIndex+1:]...), nil
}

func resolveRerunSelector(ctx context.Context, arguments []string, resolver RequestResolver) ([]string, error) {
	role, hasRole, err := selectorOption(arguments, "--role")
	if err != nil {
		return nil, err
	}
	provider, hasProvider, err := selectorOption(arguments, "--provider")
	if err != nil {
		return nil, err
	}
	_, hasAttempt, err := selectorOption(arguments, "--attempt")
	if err != nil {
		return nil, err
	}
	if !hasRole && !hasProvider {
		return arguments, nil
	}
	if hasAttempt || !hasRole || !hasProvider {
		return nil, usageError("rerun requires either --attempt or exactly one --role and --provider selector")
	}
	if !validRole(role) || !validRole(provider) {
		return nil, usageError("rerun role/provider selector is malformed")
	}
	runID, present, err := selectorOption(arguments, "--run")
	if err != nil {
		return nil, err
	}
	if !present {
		return arguments, nil
	}
	if resolver == nil {
		return nil, usageError("rerun role/provider selector requires a resolver")
	}
	attemptID, err := resolver.ResolveAttempt(ctx, runID, role, provider)
	if err != nil {
		if errors.Is(err, ErrSelectorUnavailable) {
			return nil, usageError("resolve rerun attempt: %v", err)
		}
		return nil, fmt.Errorf("resolve rerun attempt: %w", err)
	}
	normalized := make([]string, 0, len(arguments))
	for index := 0; index < len(arguments); index++ {
		if arguments[index] == "--role" || arguments[index] == "--provider" {
			index++
			continue
		}
		normalized = append(normalized, arguments[index])
	}
	return append(normalized, "--attempt", attemptID), nil
}

func selectorOption(arguments []string, flag string) (string, bool, error) {
	var value string
	present := false
	for index := 1; index < len(arguments); index++ {
		if arguments[index] != flag {
			continue
		}
		if present {
			return "", false, usageError("duplicate flag")
		}
		if index+1 == len(arguments) || strings.HasPrefix(arguments[index+1], "--") {
			return "", false, usageError("flag value is missing")
		}
		value, present = arguments[index+1], true
	}
	return value, present, nil
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
		"--project-root": true, "--name": true, "--context": true, "--providers": true, "--roles": true,
		"--project-kind": true, "--artist-brief": true, "--artist-design-specs": true,
		"--native-home": true, "--kimi-executable": true, "--kimi-model": true, "--kimi-data-home": true,
		"--zcode-node-executable": true, "--zcode-launcher": true,
		"--agy-executable": true, "--agy-permission-mode": true, "--output": true,
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
		projectRoot: projectRoot, projectName: projectName, selectionMode: "auto", roleIDs: coreRoleNames(),
	}
	rolesExplicit := false
	if rolesValue, present := options["--roles"]; present {
		rolesExplicit = true
		request.roleIDs, err = parseCanonicalRolesCSV(rolesValue)
		if err != nil {
			return Invocation{}, err
		}
		if !containsString(request.roleIDs, "logic") || !containsString(request.roleIDs, "security") {
			return Invocation{}, usageError("project roles require logic and security")
		}
	}
	if value, present := options["--project-kind"]; present {
		if value != "ui" && value != "non_ui" {
			return Invocation{}, usageError("project kind must be ui or non_ui")
		}
		request.projectKind, request.hasProjectKind = value, true
	}
	artistBrief, hasArtistBrief := options["--artist-brief"]
	if hasArtistBrief {
		value := artistBrief
		if !validRelativePath(value) {
			return Invocation{}, usageError("artist brief path is not safe")
		}
		request.artistBriefPath = value
	}
	if value, present := options["--artist-design-specs"]; present {
		request.artistDesignGlobs, err = parseArtistGlobsCSV(value)
		if err != nil {
			return Invocation{}, err
		}
	}
	ui := request.hasProjectKind && request.projectKind == "ui"
	if ui {
		if rolesExplicit && !containsString(request.roleIDs, "artist") {
			return Invocation{}, usageError("UI project roles require artist")
		}
		if !containsString(request.roleIDs, "artist") {
			request.roleIDs = append(request.roleIDs, "artist")
		}
	} else if containsString(request.roleIDs, "artist") || request.artistBriefPath != "" || len(request.artistDesignGlobs) != 0 {
		return Invocation{}, usageError("artist requires an explicitly declared UI project")
	}
	if value, present := options["--context"]; present {
		if !validRelativePath(value) {
			return Invocation{}, usageError("context path is not a safe relative path")
		}
		request.contextPath = value
		request.hasContextPath = true
	}
	if value, present := options["--providers"]; present {
		if value != "auto" {
			providers, parseErr := parseProviderCSV(value, intendedProvider)
			if parseErr != nil {
				return Invocation{}, parseErr
			}
			request.selectionMode = "selected"
			request.providerIDs = canonicalProviderOrder(providers)
		}
	}
	for flag, destination := range map[string]*string{"--kimi-executable": &request.kimiExecutable, "--kimi-model": &request.kimiModel, "--kimi-data-home": &request.kimiDataHome, "--zcode-node-executable": &request.zcodeNodeExecutable, "--zcode-launcher": &request.zcodeLauncher, "--agy-executable": &request.agyExecutable, "--agy-permission-mode": &request.agyPermissionMode} {
		if value, present := options[flag]; present {
			*destination = value
		}
	}
	if value, present := options["--native-home"]; present {
		if !validAbsoluteRoot(value) {
			return Invocation{}, usageError("native home is not canonical")
		}
		request.nativeHome = value
		request.hasNativeHome = true
	}
	for _, value := range []string{request.kimiExecutable, request.kimiDataHome, request.zcodeNodeExecutable, request.zcodeLauncher, request.agyExecutable} {
		if value != "" && !validAbsoluteRoot(value) {
			return Invocation{}, usageError("provider path is not canonical")
		}
	}
	if request.agyPermissionMode != "" && request.agyPermissionMode != "safe" && request.agyPermissionMode != "dangerously-skip-permissions" {
		return Invocation{}, usageError("unsupported AGY permission mode")
	}
	if request.selectionMode == "selected" {
		selected := request.providerIDs
		if !containsString(selected, "kimi") && (request.kimiExecutable != "" || request.kimiModel != "" || request.kimiDataHome != "") {
			return Invocation{}, usageError("Kimi override requires Kimi selection")
		}
		if !containsString(selected, "zcode") && (request.zcodeNodeExecutable != "" || request.zcodeLauncher != "") {
			return Invocation{}, usageError("ZCode override requires ZCode selection")
		}
		if !containsString(selected, "agy") && (request.agyExecutable != "" || request.agyPermissionMode != "") {
			return Invocation{}, usageError("AGY override requires AGY selection")
		}
	}
	outputFormat, err := optionOutputFormat(options)
	if err != nil {
		return Invocation{}, err
	}
	type selectionJSON struct {
		Mode        string   `json:"mode"`
		ProviderIDs []string `json:"provider_ids,omitempty"`
	}
	type overridesJSON struct {
		KimiExecutable      string `json:"kimi_executable,omitempty"`
		KimiModel           string `json:"kimi_model,omitempty"`
		KimiDataHome        string `json:"kimi_data_home,omitempty"`
		ZCodeNodeExecutable string `json:"zcode_node_executable,omitempty"`
		ZCodeLauncher       string `json:"zcode_launcher,omitempty"`
		AGYExecutable       string `json:"agy_executable,omitempty"`
		AGYPermissionMode   string `json:"agy_permission_mode,omitempty"`
	}
	requestJSON, err := marshalRequest(struct {
		RequestID    string        `json:"request_id"`
		Command      string        `json:"command"`
		ProjectRoot  string        `json:"project_root"`
		ProjectName  string        `json:"project_name"`
		Context      *string       `json:"context"`
		ProjectKind  *string       `json:"project_kind,omitempty"`
		ArtistBrief  *string       `json:"artist_brief,omitempty"`
		ArtistDesign []string      `json:"artist_design_specs,omitempty"`
		Selection    selectionJSON `json:"selection"`
		Roles        []string      `json:"roles"`
		Overrides    overridesJSON `json:"overrides"`
		Overwrite    bool          `json:"overwrite"`
		OutputFormat OutputFormat  `json:"output_format"`
	}{
		RequestID: requestID, Command: string(app.CommandInit), ProjectRoot: request.projectRoot, ProjectName: request.projectName, Context: optionalString(request.contextPath, request.hasContextPath), ProjectKind: optionalString(request.projectKind, request.hasProjectKind), ArtistBrief: optionalString(request.artistBriefPath, request.artistBriefPath != ""), ArtistDesign: cloneStrings(request.artistDesignGlobs), Selection: selectionJSON{Mode: request.selectionMode, ProviderIDs: cloneStrings(request.providerIDs)}, Roles: cloneStrings(request.roleIDs), Overrides: overridesJSON{request.kimiExecutable, request.kimiModel, request.kimiDataHome, request.zcodeNodeExecutable, request.zcodeLauncher, request.agyExecutable, request.agyPermissionMode}, Overwrite: false, OutputFormat: outputFormat,
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

// rejectedInitJSONIntent reports whether an invalid init argv still expresses
// an unambiguous machine-output request. Duplicate --output json flags remain
// invalid usage, but they do not make the requested representation ambiguous.
func rejectedInitJSONIntent(argv []string) bool {
	if len(argv) == 0 || argv[0] != string(app.CommandInit) {
		return false
	}
	found := false
	for index := 1; index < len(argv); index++ {
		if argv[index] != "--output" {
			continue
		}
		if index+1 >= len(argv) || argv[index+1] != string(OutputFormatJSON) {
			return false
		}
		found = true
		index++
	}
	return found
}

func parseProviders(arguments []string, defaultProjectRoot, requestID string) (Invocation, error) {
	positionals := make([]string, 0, len(arguments))
	options := make(map[string]string, 2)
	includeUnverified := false
	for index := 0; index < len(arguments); index++ {
		argument := arguments[index]
		if !strings.HasPrefix(argument, "-") {
			positionals = append(positionals, argument)
			continue
		}
		switch argument {
		case "--include-unverified":
			if includeUnverified {
				return Invocation{}, usageError("duplicate flag")
			}
			if index+1 < len(arguments) && !strings.HasPrefix(arguments[index+1], "--") {
				return Invocation{}, usageError("boolean flag does not accept a value")
			}
			includeUnverified = true
		case "--project-root", "--output":
			if _, duplicate := options[argument]; duplicate {
				return Invocation{}, usageError("duplicate flag")
			}
			if index+1 == len(arguments) || strings.HasPrefix(arguments[index+1], "--") {
				return Invocation{}, usageError("flag value is missing")
			}
			options[argument] = arguments[index+1]
			index++
		default:
			return Invocation{}, usageError("unknown flag")
		}
	}
	if len(positionals) != 0 {
		return Invocation{}, usageError("providers accepts no positional arguments")
	}
	projectRoot, err := optionProjectRoot(options, defaultProjectRoot)
	if err != nil {
		return Invocation{}, err
	}
	outputFormat, err := optionOutputFormat(options)
	if err != nil {
		return Invocation{}, err
	}
	request := ProvidersRequest{
		projectRoot:       projectRoot,
		includeUnverified: includeUnverified,
	}
	requestJSON, err := marshalRequest(struct {
		RequestID         string       `json:"request_id"`
		Command           string       `json:"command"`
		ProjectRoot       string       `json:"project_root"`
		IncludeUnverified bool         `json:"include_unverified"`
		OutputFormat      OutputFormat `json:"output_format"`
	}{
		RequestID:         requestID,
		Command:           string(app.CommandProviders),
		ProjectRoot:       request.projectRoot,
		IncludeUnverified: request.includeUnverified,
		OutputFormat:      outputFormat,
	})
	if err != nil {
		return Invocation{}, err
	}
	return Invocation{
		command:        app.CommandProviders,
		availability:   AvailabilityFoundation,
		requestID:      requestID,
		outputFormat:   outputFormat,
		requestJSON:    requestJSON,
		hasRequestJSON: true,
		providers:      &request,
	}, nil
}

func parseReview(arguments []string, requestID string) (Invocation, error) {
	positionals, options, err := parseOptions(arguments, map[string]bool{
		"--workspace": false, "--stage": false, "--dirty": false,
		"--diff": true, "--patch": true, "--stdin": true, "--objective": true,
		"--roles": true, "--artist-brief": true, "--artist-design-specs": true,
		"--session": true, "--output": true,
	})
	if err != nil {
		return Invocation{}, err
	}
	if len(positionals) != 0 {
		return Invocation{}, usageError("review accepts no positional arguments")
	}
	target, err := optionTarget(options)
	if err != nil {
		return Invocation{}, err
	}
	request := ReviewRequest{target: target}
	if objective, present := options["--objective"]; present {
		if !validObjective(objective) {
			return Invocation{}, usageError("review objective is malformed")
		}
		request.objective, request.hasObjective = objective, true
	}
	if rolesValue, present := options["--roles"]; present {
		request.roles, err = parseCanonicalRolesCSV(rolesValue)
		if err != nil {
			return Invocation{}, err
		}
		request.rolesExplicit = true
	} else {
		request.roles = coreRoleNames()
	}
	if artistBrief, present := options["--artist-brief"]; present {
		if !validRelativePath(artistBrief) {
			return Invocation{}, usageError("artist brief path is not safe")
		}
		request.artistBriefPath, request.hasArtistBrief = artistBrief, true
	}
	if value, present := options["--artist-design-specs"]; present {
		request.artistDesignGlobs, err = parseArtistGlobsCSV(value)
		if err != nil {
			return Invocation{}, err
		}
	}
	if request.rolesExplicit && !containsString(request.roles, "artist") && (request.hasArtistBrief || len(request.artistDesignGlobs) != 0) {
		return Invocation{}, usageError("artist inputs require the artist role")
	}
	if sessionID, present := options["--session"]; present {
		session, parseErr := domain.ParseSessionID(sessionID)
		if parseErr != nil {
			return Invocation{}, usageError("session ID is not a canonical UUIDv7")
		}
		request.sessionID, request.hasSessionID = session.String(), true
	}
	outputFormat, err := optionOutputFormat(options)
	if err != nil {
		return Invocation{}, err
	}
	var objective, artistBrief, sessionID *string
	if request.hasObjective {
		objective = &request.objective
	}
	if request.hasArtistBrief {
		artistBrief = &request.artistBriefPath
	}
	if request.hasSessionID {
		sessionID = &request.sessionID
	}
	artistDesign := cloneStrings(request.artistDesignGlobs)
	if artistDesign == nil {
		artistDesign = []string{}
	}
	requestJSON, err := marshalRequest(struct {
		RequestID string `json:"request_id"`
		Command   string `json:"command"`
		Target    struct {
			Kind  string `json:"kind"`
			Value string `json:"value"`
		} `json:"target"`
		Objective     *string      `json:"objective"`
		Roles         []string     `json:"roles"`
		RoleSelection string       `json:"role_selection"`
		ArtistBrief   *string      `json:"artist_brief"`
		ArtistDesign  []string     `json:"artist_design_specs"`
		SessionID     *string      `json:"session_id"`
		OutputFormat  OutputFormat `json:"output_format"`
	}{
		requestID, string(app.CommandReview), struct {
			Kind  string `json:"kind"`
			Value string `json:"value"`
		}{request.target.kind, request.target.value}, objective, cloneStrings(request.roles), map[bool]string{true: "explicit", false: "project_default"}[request.rolesExplicit], artistBrief, artistDesign, sessionID, outputFormat,
	})
	if err != nil {
		return Invocation{}, err
	}
	return Invocation{
		command: app.CommandReview, availability: AvailabilityFoundation, requestID: requestID,
		outputFormat: outputFormat, requestJSON: requestJSON, hasRequestJSON: true, review: &request,
	}, nil
}

func parsePrompt(arguments []string, requestID string) (Invocation, error) {
	options := make(map[string]string, 3)
	includeGuardedBytes := false
	for index := 0; index < len(arguments); index++ {
		argument := arguments[index]
		switch argument {
		case "--include-guarded-bytes":
			if includeGuardedBytes {
				return Invocation{}, usageError("duplicate flag")
			}
			if index+1 < len(arguments) && !strings.HasPrefix(arguments[index+1], "--") {
				return Invocation{}, usageError("boolean flag does not accept a value")
			}
			includeGuardedBytes = true
		case "--run", "--attempt", "--output":
			if _, duplicate := options[argument]; duplicate {
				return Invocation{}, usageError("duplicate flag")
			}
			if index+1 == len(arguments) || strings.HasPrefix(arguments[index+1], "--") {
				return Invocation{}, usageError("flag value is missing")
			}
			options[argument] = arguments[index+1]
			index++
		default:
			return Invocation{}, usageError("prompt accepts no positional arguments or unknown flags")
		}
	}
	runID, err := optionRunID(options)
	if err != nil {
		return Invocation{}, err
	}
	attemptValue, present := options["--attempt"]
	if !present {
		return Invocation{}, usageError("prompt requires --attempt")
	}
	attemptID, err := domain.ParseAttemptID(attemptValue)
	if err != nil {
		return Invocation{}, usageError("attempt ID is not a canonical UUIDv7")
	}
	outputFormat, err := optionOutputFormat(options)
	if err != nil {
		return Invocation{}, err
	}
	request := PromptRequest{runID: runID, attemptID: attemptID.String(), includeGuardedBytes: includeGuardedBytes}
	requestJSON, err := marshalRequest(struct {
		RequestID           string       `json:"request_id"`
		Command             string       `json:"command"`
		RunID               string       `json:"run_id"`
		AttemptID           string       `json:"attempt_id"`
		IncludeGuardedBytes bool         `json:"include_guarded_bytes"`
		OutputFormat        OutputFormat `json:"output_format"`
	}{requestID, string(app.CommandPrompt), request.runID, request.attemptID, request.includeGuardedBytes, outputFormat})
	if err != nil {
		return Invocation{}, err
	}
	return Invocation{
		command: app.CommandPrompt, availability: AvailabilityFoundation, requestID: requestID,
		outputFormat: outputFormat, requestJSON: requestJSON, hasRequestJSON: true, prompt: &request,
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
		return Invocation{}, usageError("finding ID is malformed")
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
		"--project-root": true, "--mode": true, "--output": true,
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
func parseFollowup(arguments []string, requestID string) (Invocation, error) {
	positionals, options, err := parseOptions(arguments, map[string]bool{
		"--run": true, "--finding": true, "--workspace": false, "--stage": false, "--dirty": false,
		"--diff": true, "--patch": true, "--stdin": true,
		"--objective": true, "--role": true, "--output": true,
	})
	if err != nil {
		return Invocation{}, err
	}
	if len(positionals) != 0 {
		return Invocation{}, usageError("followup accepts no positional arguments")
	}
	sourceRunID, err := optionRunID(options)
	if err != nil {
		return Invocation{}, err
	}
	findingID, present := options["--finding"]
	if !present || !validCommandFindingID(findingID) {
		return Invocation{}, usageError("followup requires a canonical --finding")
	}
	target, err := optionTarget(options)
	if err != nil {
		return Invocation{}, err
	}
	request := FollowupRequest{sourceRunID: sourceRunID, findingID: findingID, target: target}
	if objective, present := options["--objective"]; present {
		if !validObjective(objective) {
			return Invocation{}, usageError("followup objective is malformed")
		}
		request.objective, request.hasObjective = objective, true
	}
	if role, present := options["--role"]; present {
		if !validRole(role) {
			return Invocation{}, usageError("followup role is malformed")
		}
		request.role, request.hasRole = role, true
	}
	outputFormat, err := optionOutputFormat(options)
	if err != nil {
		return Invocation{}, err
	}
	var objective, role *string
	if request.hasObjective {
		objective = &request.objective
	}
	if request.hasRole {
		role = &request.role
	}
	requestJSON, err := marshalRequest(struct {
		RequestID   string `json:"request_id"`
		Command     string `json:"command"`
		SourceRunID string `json:"source_run_id"`
		FindingID   string `json:"finding_id"`
		Target      struct {
			Kind  string `json:"kind"`
			Value string `json:"value"`
		} `json:"target"`
		Objective    *string      `json:"objective"`
		Role         *string      `json:"role"`
		OutputFormat OutputFormat `json:"output_format"`
	}{requestID, string(app.CommandFollowup), request.sourceRunID, request.findingID, struct {
		Kind  string `json:"kind"`
		Value string `json:"value"`
	}{request.target.kind, request.target.value}, objective, role, outputFormat})
	if err != nil {
		return Invocation{}, err
	}
	return Invocation{command: app.CommandFollowup, availability: AvailabilityFoundation, requestID: requestID, outputFormat: outputFormat, requestJSON: requestJSON, hasRequestJSON: true, followup: &request}, nil
}

func parseDelta(arguments []string, requestID string) (Invocation, error) {
	positionals, options, err := parseOptions(arguments, map[string]bool{
		"--since-run": true, "--workspace": false, "--stage": false, "--dirty": false,
		"--diff": true, "--patch": true, "--stdin": true, "--roles": true, "--output": true,
	})
	if err != nil {
		return Invocation{}, err
	}
	if len(positionals) != 0 {
		return Invocation{}, usageError("delta accepts no positional arguments")
	}
	sourceRunID, err := optionRequiredRunID(options, "--since-run")
	if err != nil {
		return Invocation{}, err
	}
	target, err := optionTarget(options)
	if err != nil {
		return Invocation{}, err
	}
	rolesValue, present := options["--roles"]
	if !present {
		return Invocation{}, usageError("delta requires --roles")
	}
	roles, err := parseCanonicalRolesCSV(rolesValue)
	if err != nil {
		return Invocation{}, err
	}
	outputFormat, err := optionOutputFormat(options)
	if err != nil {
		return Invocation{}, err
	}
	request := DeltaRequest{sourceRunID: sourceRunID, target: target, roles: roles}
	requestJSON, err := marshalRequest(struct {
		RequestID   string `json:"request_id"`
		Command     string `json:"command"`
		SourceRunID string `json:"source_run_id"`
		Target      struct {
			Kind  string `json:"kind"`
			Value string `json:"value"`
		} `json:"target"`
		Roles        []string     `json:"roles"`
		OutputFormat OutputFormat `json:"output_format"`
	}{requestID, string(app.CommandDelta), request.sourceRunID, struct {
		Kind  string `json:"kind"`
		Value string `json:"value"`
	}{request.target.kind, request.target.value}, cloneStrings(request.roles), outputFormat})
	if err != nil {
		return Invocation{}, err
	}
	return Invocation{command: app.CommandDelta, availability: AvailabilityFoundation, requestID: requestID, outputFormat: outputFormat, requestJSON: requestJSON, hasRequestJSON: true, delta: &request}, nil
}

func parseRerun(arguments []string, requestID string) (Invocation, error) {
	positionals, options, err := parseOptions(arguments, map[string]bool{
		"--run": true, "--attempt": true, "--replay": true, "--output": true,
	})
	if err != nil {
		return Invocation{}, err
	}
	if len(positionals) != 0 {
		return Invocation{}, usageError("rerun accepts no positional arguments")
	}
	sourceRunID, err := optionRunID(options)
	if err != nil {
		return Invocation{}, err
	}
	sourceAttemptID, present := options["--attempt"]
	if !present {
		return Invocation{}, usageError("rerun requires --attempt")
	}
	attemptID, err := domain.ParseAttemptID(sourceAttemptID)
	if err != nil {
		return Invocation{}, usageError("attempt ID is not a canonical UUIDv7")
	}
	replayMode := ReplayModeExact
	if value, present := options["--replay"]; present {
		replayMode = ReplayMode(value)
		if replayMode != ReplayModeExact && replayMode != ReplayModeRecompose {
			return Invocation{}, usageError("unsupported replay mode")
		}
	}
	outputFormat, err := optionOutputFormat(options)
	if err != nil {
		return Invocation{}, err
	}
	request := RerunRequest{sourceRunID: sourceRunID, sourceAttemptID: attemptID.String(), replayMode: replayMode}
	requestJSON, err := marshalRequest(struct {
		RequestID       string       `json:"request_id"`
		Command         string       `json:"command"`
		SourceRunID     string       `json:"source_run_id"`
		SourceAttemptID string       `json:"source_attempt_id"`
		ReplayMode      ReplayMode   `json:"replay_mode"`
		OutputFormat    OutputFormat `json:"output_format"`
	}{requestID, string(app.CommandRerun), request.sourceRunID, request.sourceAttemptID, request.replayMode, outputFormat})
	if err != nil {
		return Invocation{}, err
	}
	return Invocation{command: app.CommandRerun, availability: AvailabilityFoundation, requestID: requestID, outputFormat: outputFormat, requestJSON: requestJSON, hasRequestJSON: true, rerun: &request}, nil
}

func parseClean(arguments []string, requestID string) (Invocation, error) {
	positionals, options, err := parseOptions(arguments, map[string]bool{
		"--mode": true, "--expected-plan-sha256": true, "--output": true,
	})
	if err != nil {
		return Invocation{}, err
	}
	if len(positionals) != 0 {
		return Invocation{}, usageError("clean accepts no positional arguments")
	}
	request := CleanRequest{mode: CleanModePlan}
	if value, present := options["--mode"]; present {
		request.mode = CleanMode(value)
		if request.mode != CleanModePlan && request.mode != CleanModeApply && request.mode != CleanModeExplain {
			return Invocation{}, usageError("unsupported clean mode")
		}
	}
	if value, present := options["--expected-plan-sha256"]; present {
		if !validSHA256Identifier(value) {
			return Invocation{}, usageError("expected clean plan SHA-256 is not canonical")
		}
		request.expectedPlanSHA256, request.hasExpectedPlanHash = value, true
	}
	if request.mode == CleanModeApply && !request.hasExpectedPlanHash {
		return Invocation{}, usageError("clean apply requires --expected-plan-sha256")
	}
	if request.mode != CleanModeApply && request.hasExpectedPlanHash {
		return Invocation{}, usageError("only clean apply accepts --expected-plan-sha256")
	}
	outputFormat, err := optionOutputFormat(options)
	if err != nil {
		return Invocation{}, err
	}
	var expectedPlanSHA256 *string
	if request.hasExpectedPlanHash {
		expectedPlanSHA256 = &request.expectedPlanSHA256
	}
	requestJSON, err := marshalRequest(struct {
		RequestID          string       `json:"request_id"`
		Command            string       `json:"command"`
		Mode               CleanMode    `json:"mode"`
		ExpectedPlanSHA256 *string      `json:"expected_plan_sha256"`
		OutputFormat       OutputFormat `json:"output_format"`
	}{requestID, string(app.CommandClean), request.mode, expectedPlanSHA256, outputFormat})
	if err != nil {
		return Invocation{}, err
	}
	return Invocation{command: app.CommandClean, availability: AvailabilityFoundation, requestID: requestID, outputFormat: outputFormat, requestJSON: requestJSON, hasRequestJSON: true, clean: &request}, nil
}

func parseExport(arguments []string, requestID string) (Invocation, error) {
	positionals, options, err := parseOptions(arguments, map[string]bool{
		"--run": true, "--output-path": true, "--output": true,
	})
	if err != nil {
		return Invocation{}, err
	}
	if len(positionals) != 0 {
		return Invocation{}, usageError("export accepts no positional arguments")
	}
	runID, err := optionRunID(options)
	if err != nil {
		return Invocation{}, err
	}
	outputPath, present := options["--output-path"]
	if !present || !validRelativePath(outputPath) {
		return Invocation{}, usageError("export requires a safe relative --output-path")
	}
	outputFormat, err := optionOutputFormat(options)
	if err != nil {
		return Invocation{}, err
	}
	request := ExportRequest{runID: runID, outputPath: outputPath, redacted: true}
	requestJSON, err := marshalRequest(struct {
		RequestID    string       `json:"request_id"`
		Command      string       `json:"command"`
		RunID        string       `json:"run_id"`
		OutputPath   string       `json:"output_path"`
		Redacted     bool         `json:"redacted"`
		OutputFormat OutputFormat `json:"output_format"`
	}{requestID, string(app.CommandExport), request.runID, request.outputPath, request.redacted, outputFormat})
	if err != nil {
		return Invocation{}, err
	}
	return Invocation{command: app.CommandExport, availability: AvailabilityFoundation, requestID: requestID, outputFormat: outputFormat, requestJSON: requestJSON, hasRequestJSON: true, export: &request}, nil
}
func optionTarget(options map[string]string) (TargetRequest, error) {
	var target TargetRequest
	for _, candidate := range []struct {
		kind      string
		flag      string
		valueless bool
	}{
		{kind: "workspace", flag: "--workspace", valueless: true},
		{kind: "stage", flag: "--stage", valueless: true},
		{kind: "dirty", flag: "--dirty", valueless: true},
		{kind: "diff", flag: "--diff"},
		{kind: "patch", flag: "--patch"},
		{kind: "stdin", flag: "--stdin"},
	} {
		value, present := options[candidate.flag]
		if !present {
			continue
		}
		if target.kind != "" {
			return TargetRequest{}, usageError("target kind flags are mutually exclusive")
		}
		if candidate.valueless {
			value = candidate.kind
		}
		if !validTargetValue(value) || candidate.kind == "diff" && value == "git" {
			return TargetRequest{}, usageError("target value is malformed")
		}
		target = TargetRequest{kind: candidate.kind, value: value}
	}
	if target.kind == "" {
		return TargetRequest{}, usageError("command requires one target kind flag")
	}
	return target, nil
}

func parseRolesCSV(value string) ([]string, error) {
	if value == "" || strings.ContainsAny(value, "\x00\r\n") {
		return nil, usageError("role list is malformed")
	}
	roles := strings.Split(value, ",")
	if len(roles) > len(domain.FixedRoleOrder()) {
		return nil, usageError("role list exceeds supported roles")
	}
	seen := make(map[string]struct{}, len(roles))
	for _, role := range roles {
		if !validRole(role) {
			return nil, usageError("role list contains a malformed role")
		}
		if _, duplicate := seen[role]; duplicate {
			return nil, usageError("role list contains a duplicate role")
		}
		seen[role] = struct{}{}
	}
	return roles, nil
}
func fixedRoleNames() []string {
	fixedRoles := domain.FixedRoleOrder()
	roles := make([]string, len(fixedRoles))
	for index, role := range fixedRoles {
		roles[index] = string(role)
	}
	return roles
}

func coreRoleNames() []string {
	fixedRoles := domain.CoreRoleOrder()
	roles := make([]string, len(fixedRoles))
	for index, role := range fixedRoles {
		roles[index] = string(role)
	}
	return roles
}

func validArtistGlob(value string) bool {
	if !validRelativePath(value) || strings.ContainsAny(value, "[]{}!\\") {
		return false
	}
	switch strings.ToLower(path.Ext(value)) {
	case ".png", ".jpg", ".jpeg", ".webp":
		return true
	default:
		return false
	}
}

func parseArtistGlobsCSV(value string) ([]string, error) {
	globs := strings.Split(value, ",")
	if len(globs) == 0 || len(globs) > 16 {
		return nil, usageError("artist design spec list is invalid")
	}
	seen := make(map[string]struct{}, len(globs))
	for _, pattern := range globs {
		if !validArtistGlob(pattern) {
			return nil, usageError("artist design spec glob is not safe")
		}
		if _, duplicate := seen[pattern]; duplicate {
			return nil, usageError("artist design spec list contains a duplicate glob")
		}
		seen[pattern] = struct{}{}
	}
	return globs, nil
}

func parseCanonicalRolesCSV(value string) ([]string, error) {
	roles, err := parseRolesCSV(value)
	if err != nil {
		return nil, err
	}
	selected := make(map[domain.Role]struct{}, len(roles))
	for _, role := range roles {
		parsed := domain.Role(role)
		if !parsed.Valid() {
			return nil, usageError("role list contains an unsupported role")
		}
		selected[parsed] = struct{}{}
	}
	canonical := make([]string, 0, len(roles))
	for _, role := range domain.FixedRoleOrder() {
		if _, present := selected[role]; present {
			canonical = append(canonical, string(role))
		}
	}
	return canonical, nil
}

func validTargetValue(value string) bool {
	return value != "" && len(value) <= maximumPathLength && !strings.ContainsAny(value, "\x00\r\n")
}
func validCapturedStdinToken(value string) bool {
	if len(value) != len(stdinCaptureTokenPrefix)+stdinCaptureTokenBytes*2 || !strings.HasPrefix(value, stdinCaptureTokenPrefix) {
		return false
	}
	for _, character := range value[len(stdinCaptureTokenPrefix):] {
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return false
		}
	}
	return true
}

func validObjective(value string) bool {
	return value != "" && len(value) <= 12000 && !strings.ContainsAny(value, "\x00\r\n")
}

func validRole(value string) bool {
	if len(value) == 0 || len(value) > 64 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, character := range value[1:] {
		if (character < 'a' || character > 'z') &&
			(character < '0' || character > '9') &&
			character != '_' && character != '-' {
			return false
		}
	}
	return true
}

func validCommandFindingID(value string) bool {
	if len(value) == 0 || len(value) > 64 || value[0] < 'A' || value[0] > 'Z' {
		return false
	}
	for _, character := range value[1:] {
		if (character < 'A' || character > 'Z') &&
			(character < '0' || character > '9') &&
			character != '_' && character != '-' {
			return false
		}
	}
	return true
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
		requiresValue, allowedFlag := allowed[argument]
		if !strings.HasPrefix(argument, "--") || argument == "--" || !allowedFlag {
			return nil, nil, usageError("unknown flag")
		}
		if _, duplicate := options[argument]; duplicate {
			return nil, nil, usageError("duplicate flag")
		}
		if !requiresValue {
			options[argument] = "true"
			continue
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
func optionRequiredRunID(options map[string]string, flag string) (string, error) {
	value, present := options[flag]
	if !present {
		return "", usageError("command requires %s", flag)
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
	if value == "" || strings.ContainsAny(value, "\x00\r\n \t") {
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

func canonicalProviderOrder(values []string) []string {
	result := make([]string, 0, len(values))
	for _, family := range []string{"kimi", "zcode", "agy"} {
		if containsString(values, family) {
			result = append(result, family)
		}
	}
	return result
}
func containsString(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}
func optionalString(value string, present bool) *string {
	if !present {
		return nil
	}
	copyValue := value
	return &copyValue
}

func intendedProvider(value string) bool {
	switch value {
	case "kimi", "zcode", "agy":
		return true
	default:
		return false
	}
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
	if !utf8.ValidString(value) || !norm.NFC.IsNormalString(value) {
		return false
	}
	visible := 0
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
		if !unicode.IsSpace(character) {
			visible++
		}
	}
	return visible >= 1 && visible <= 128
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
	return validCommandFindingID(value)
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
