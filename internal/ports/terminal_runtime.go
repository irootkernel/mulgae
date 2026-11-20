package ports

import (
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	// TerminalPaneIDEnvName is the sole inherited environment variable passed
	// through by Mulgae's trusted pane trampoline after strict validation.
	TerminalPaneIDEnvName = "HC_TERMINAL_ID"

	// TerminalPaneIDPassthroughDomainMarker is the deterministic fixed marker
	// hashed into effectiveEnvironmentIdentity for terminal-channel launches so
	// per-pane identifiers never leak into qualification authority receipts.
	TerminalPaneIDPassthroughDomainMarker = "Mulgae-TERMINAL-ENV-PASSTHROUGH/1:HC_TERMINAL_ID"

	terminalInitialInputMaxBytes  = 64 * 1024
	terminalScreenCaptureMaxBytes = 4 * 1024 * 1024
	terminalMaxLabelCount         = 32
	terminalMaxDimension          = 1000
)

var (
	terminalPaneIDRegexp = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	terminalLabelKeyRe   = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,63}$`)
	terminalLabelValRe   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
)

// ValidTerminalPaneID reports whether value matches Mulgae's closed pane ID
// grammar admitted for HC_TERMINAL_ID pass-through.
func ValidTerminalPaneID(value string) bool {
	return terminalPaneIDRegexp.MatchString(value)
}

// TerminalEnvironmentWithPassthroughMarker returns a sorted caller-owned copy
// of environment supplemented with the fixed HC_TERMINAL_ID pass-through domain
// marker. Callers must not supply HC_TERMINAL_ID explicitly in environment.
func TerminalEnvironmentWithPassthroughMarker(environment []EnvironmentVariable) ([]EnvironmentVariable, error) {
	result := make([]EnvironmentVariable, 0, len(environment)+1)
	seen := make(map[string]struct{}, len(environment)+1)
	for _, variable := range environment {
		if !variable.Valid() {
			return nil, fmt.Errorf("terminal environment: invalid variable")
		}
		if variable.Name() == TerminalPaneIDEnvName {
			return nil, fmt.Errorf("terminal environment: %s is reserved for trampoline pass-through", TerminalPaneIDEnvName)
		}
		if _, exists := seen[variable.Name()]; exists {
			return nil, fmt.Errorf("terminal environment: duplicate variable %q", variable.Name())
		}
		seen[variable.Name()] = struct{}{}
		result = append(result, variable)
	}
	marker, err := NewEnvironmentVariable(TerminalPaneIDEnvName, TerminalPaneIDPassthroughDomainMarker)
	if err != nil {
		return nil, err
	}
	result = append(result, marker)
	sort.Slice(result, func(left, right int) bool {
		return result[left].Name() < result[right].Name()
	})
	return result, nil
}

// TerminalProgramStatus is Mulgae's closed terminal program status vocabulary
// mapped at the terminal multiplexer boundary from OSC 7501 / core state.
type TerminalProgramStatus string

const (
	TerminalProgramStatusIdle    TerminalProgramStatus = "idle"
	TerminalProgramStatusWorking TerminalProgramStatus = "working"
	TerminalProgramStatusDone    TerminalProgramStatus = "done"
	TerminalProgramStatusBlocked TerminalProgramStatus = "blocked"
	TerminalProgramStatusError   TerminalProgramStatus = "error"
)

// Valid reports whether status is a closed Mulgae terminal program status.
func (status TerminalProgramStatus) Valid() bool {
	switch status {
	case TerminalProgramStatusIdle,
		TerminalProgramStatusWorking,
		TerminalProgramStatusDone,
		TerminalProgramStatusBlocked,
		TerminalProgramStatusError:
		return true
	default:
		return false
	}
}

// TerminalBlockedKind is Mulgae's closed taxonomy for structured blocked states
// reported by the terminal multiplexer.
type TerminalBlockedKind string

const (
	TerminalBlockedKindAuth       TerminalBlockedKind = "auth"
	TerminalBlockedKindQuota      TerminalBlockedKind = "quota"
	TerminalBlockedKindRateLimit  TerminalBlockedKind = "rate_limit"
	TerminalBlockedKindApproval   TerminalBlockedKind = "approval"
	TerminalBlockedKindPermission TerminalBlockedKind = "permission"
	TerminalBlockedKindInput      TerminalBlockedKind = "input"
	TerminalBlockedKindUnknown    TerminalBlockedKind = "unknown"
)

// Valid reports whether kind is a closed Mulgae terminal blocked kind.
func (kind TerminalBlockedKind) Valid() bool {
	switch kind {
	case TerminalBlockedKindAuth,
		TerminalBlockedKindQuota,
		TerminalBlockedKindRateLimit,
		TerminalBlockedKindApproval,
		TerminalBlockedKindPermission,
		TerminalBlockedKindInput,
		TerminalBlockedKindUnknown:
		return true
	default:
		return false
	}
}

// TerminalRuntimeIdentity binds the verified binary and protocol handshake
// identity of the isolated terminal multiplexer (herdr-core) into qualification
// proofs, safety policies, and doctor readiness diagnostics.
type TerminalRuntimeIdentity struct {
	executable       string
	executableSHA256 string
	version          string
	generation       int
}

// NewTerminalRuntimeIdentity validates an immutable verified terminal runtime
// identity.
func NewTerminalRuntimeIdentity(executable, executableSHA256, version string, generation int) (TerminalRuntimeIdentity, error) {
	root, err := NewAnchoredRoot(executable)
	if err != nil || !validLivePolicyRoot(root) {
		return TerminalRuntimeIdentity{}, fmt.Errorf("terminal runtime identity: invalid executable path")
	}
	if err := validateSHA256(executableSHA256); err != nil {
		return TerminalRuntimeIdentity{}, fmt.Errorf("terminal runtime identity: invalid executable sha256: %w", err)
	}
	if err := validateAuditToken(version, 128); err != nil {
		return TerminalRuntimeIdentity{}, fmt.Errorf("terminal runtime identity: invalid version")
	}
	if generation < 1 {
		return TerminalRuntimeIdentity{}, fmt.Errorf("terminal runtime identity: generation must be positive")
	}
	return TerminalRuntimeIdentity{
		executable:       executable,
		executableSHA256: executableSHA256,
		version:          version,
		generation:       generation,
	}, nil
}

func (identity TerminalRuntimeIdentity) Executable() string       { return identity.executable }
func (identity TerminalRuntimeIdentity) ExecutableSHA256() string { return identity.executableSHA256 }
func (identity TerminalRuntimeIdentity) Version() string          { return identity.version }
func (identity TerminalRuntimeIdentity) Generation() int          { return identity.generation }
func (identity TerminalRuntimeIdentity) Valid() bool {
	_, err := NewTerminalRuntimeIdentity(identity.executable, identity.executableSHA256, identity.version, identity.generation)
	return err == nil
}

// PaneLaunchRequest pairs a validated terminal ProcessRequest with the caller's
// private per-pane control directory where 0400 env and Seatbelt profile files
// are materialized before pane launch. ControlDirectory must lie within one of
// the request's ControlPlaneRoots so the sandboxed provider can never read
// either file.
type PaneLaunchRequest struct {
	process          ProcessRequest
	controlDirectory AnchoredRoot
}

// NewPaneLaunchRequest validates a pane trampoline construction request.
func NewPaneLaunchRequest(process ProcessRequest, controlDirectory AnchoredRoot) (PaneLaunchRequest, error) {
	if !process.Valid() {
		return PaneLaunchRequest{}, fmt.Errorf("pane launch request: invalid process request")
	}
	binding, hasBinding := process.ProviderPacketBinding()
	if !hasBinding || binding.Channel() != ProviderPacketChannelTerminal {
		return PaneLaunchRequest{}, fmt.Errorf("pane launch request: terminal packet binding is required")
	}
	boundary, guarded := process.LiveReadOnlyBoundary()
	if !guarded || !boundary.Valid() || !boundary.PaneTTY() {
		return PaneLaunchRequest{}, fmt.Errorf("pane launch request: pane TTY live read-only boundary is required")
	}
	if !validLivePolicyRoot(controlDirectory) {
		return PaneLaunchRequest{}, fmt.Errorf("pane launch request: invalid control directory")
	}
	if !pathCoveredByRoots(controlDirectory.String(), boundary.ControlPlaneRoots()) {
		return PaneLaunchRequest{}, fmt.Errorf("pane launch request: control directory must be covered by ControlPlaneRoots")
	}
	for _, variable := range process.Environment() {
		if variable.Name() == TerminalPaneIDEnvName {
			return PaneLaunchRequest{}, fmt.Errorf("pane launch request: %s must not be supplied explicitly", TerminalPaneIDEnvName)
		}
	}
	return PaneLaunchRequest{
		process:          process,
		controlDirectory: controlDirectory,
	}, nil
}

func (request PaneLaunchRequest) Process() ProcessRequest        { return request.process }
func (request PaneLaunchRequest) ControlDirectory() AnchoredRoot { return request.controlDirectory }
func (request PaneLaunchRequest) Valid() bool {
	_, err := NewPaneLaunchRequest(request.process, request.controlDirectory)
	return err == nil
}

// PaneLaunchSpec is the immutable integrity-bound launch specification produced
// by PaneLaunchBuilder for execution inside a managed terminal pane. Argv[0] is
// Mulgae's canonical verified executable invoking __mulgae_paneexec_v1.
type PaneLaunchSpec struct {
	executable        string
	argv              []string
	envFilePath       string
	envFileSHA256     string
	profileFilePath   string
	profileFileSHA256 string
}

// NewPaneLaunchSpec validates an immutable pane launch specification.
func NewPaneLaunchSpec(executable string, argv []string, envFilePath, envFileSHA256, profileFilePath, profileFileSHA256 string) (PaneLaunchSpec, error) {
	execRoot, err := NewAnchoredRoot(executable)
	if err != nil || !validLivePolicyRoot(execRoot) {
		return PaneLaunchSpec{}, fmt.Errorf("pane launch spec: invalid executable")
	}
	if len(argv) < 2 || argv[0] != executable || argv[1] == "" {
		return PaneLaunchSpec{}, fmt.Errorf("pane launch spec: argv must start with executable and trampoline mode")
	}
	for index, argument := range argv {
		if strings.ContainsRune(argument, 0) {
			return PaneLaunchSpec{}, fmt.Errorf("pane launch spec: argv[%d] contains NUL", index)
		}
	}
	envRoot, err := NewAnchoredRoot(envFilePath)
	if err != nil || !validLivePolicyRoot(envRoot) {
		return PaneLaunchSpec{}, fmt.Errorf("pane launch spec: invalid env file path")
	}
	if err := validateSHA256(envFileSHA256); err != nil {
		return PaneLaunchSpec{}, fmt.Errorf("pane launch spec: invalid env file sha256: %w", err)
	}
	profileRoot, err := NewAnchoredRoot(profileFilePath)
	if err != nil || !validLivePolicyRoot(profileRoot) {
		return PaneLaunchSpec{}, fmt.Errorf("pane launch spec: invalid profile file path")
	}
	if err := validateSHA256(profileFileSHA256); err != nil {
		return PaneLaunchSpec{}, fmt.Errorf("pane launch spec: invalid profile file sha256: %w", err)
	}
	if envFilePath == profileFilePath {
		return PaneLaunchSpec{}, fmt.Errorf("pane launch spec: env and profile paths must be distinct")
	}
	return PaneLaunchSpec{
		executable:        executable,
		argv:              cloneStrings(argv),
		envFilePath:       envFilePath,
		envFileSHA256:     envFileSHA256,
		profileFilePath:   profileFilePath,
		profileFileSHA256: profileFileSHA256,
	}, nil
}

func (spec PaneLaunchSpec) Executable() string        { return spec.executable }
func (spec PaneLaunchSpec) Argv() []string            { return cloneStrings(spec.argv) }
func (spec PaneLaunchSpec) EnvFilePath() string       { return spec.envFilePath }
func (spec PaneLaunchSpec) EnvFileSHA256() string     { return spec.envFileSHA256 }
func (spec PaneLaunchSpec) ProfileFilePath() string   { return spec.profileFilePath }
func (spec PaneLaunchSpec) ProfileFileSHA256() string { return spec.profileFileSHA256 }
func (spec PaneLaunchSpec) Valid() bool {
	_, err := NewPaneLaunchSpec(spec.executable, spec.argv, spec.envFilePath, spec.envFileSHA256, spec.profileFilePath, spec.profileFileSHA256)
	return err == nil
}

// PaneLaunchBuilder constructs integrity-bound __mulgae_paneexec_v1 launch
// specifications and 0400 private per-pane env/Seatbelt files. Composition
// injects the process adapter's implementation into the terminal session
// adapter so adapters never import one another directly. If
// request.Process().LaunchDirectory() is present, BuildPaneLaunch borrows it
// solely to cross-check its identity without closing it; ownership of closing
// LaunchDirectory() stays with TerminalSessionRunner.RunTerminal.
type PaneLaunchBuilder interface {
	BuildPaneLaunch(ctx context.Context, request PaneLaunchRequest) (PaneLaunchSpec, error)
}

// TerminalExecutionRequestInput holds validated construction inputs for one
// terminal pane execution.
type TerminalExecutionRequestInput struct {
	Process             ProcessRequest
	StartupTimeout      time.Duration
	PromptFilePath      AnchoredRoot
	InitialInput        string
	RequireOSCReporting bool
	CheckInInterval     time.Duration
	Columns             int
	Rows                int
	Labels              map[string]string
}

// TerminalExecutionRequest is the immutable request for one guarded pane
// execution inside an isolated terminal session.
type TerminalExecutionRequest struct {
	process             ProcessRequest
	startupTimeout      time.Duration
	promptFilePath      AnchoredRoot
	initialInput        string
	requireOSCReporting bool
	checkInInterval     time.Duration
	columns             int
	rows                int
	labels              map[string]string
}

// NewTerminalExecutionRequest validates an immutable terminal pane execution
// request. StartupTimeout is carved out of Process.Timeout() and must be
// strictly less than the total family timeout budget.
func NewTerminalExecutionRequest(input TerminalExecutionRequestInput) (TerminalExecutionRequest, error) {
	if !input.Process.Valid() {
		return TerminalExecutionRequest{}, fmt.Errorf("terminal execution request: invalid process request")
	}
	binding, hasBinding := input.Process.ProviderPacketBinding()
	if !hasBinding || binding.Channel() != ProviderPacketChannelTerminal {
		return TerminalExecutionRequest{}, fmt.Errorf("terminal execution request: terminal packet binding is required")
	}
	boundary, guarded := input.Process.LiveReadOnlyBoundary()
	if !guarded || !boundary.Valid() || !boundary.PaneTTY() {
		return TerminalExecutionRequest{}, fmt.Errorf("terminal execution request: pane TTY live read-only boundary is required")
	}
	if _, hasLifecycle := input.Process.PostOutputLifecycle(); hasLifecycle {
		return TerminalExecutionRequest{}, fmt.Errorf("terminal execution request: post-output lifecycle is unsupported")
	}
	if input.StartupTimeout <= 0 || input.StartupTimeout >= input.Process.Timeout() {
		return TerminalExecutionRequest{}, fmt.Errorf("terminal execution request: startup timeout must be positive and less than process timeout")
	}
	if !validLivePolicyRoot(input.PromptFilePath) {
		return TerminalExecutionRequest{}, fmt.Errorf("terminal execution request: invalid prompt file path")
	}
	if !pathCoveredByRoots(filepath.Dir(input.PromptFilePath.String()), boundary.ReadOnlyRoots()) {
		return TerminalExecutionRequest{}, fmt.Errorf("terminal execution request: prompt file directory must be covered by ReadOnlyRoots")
	}
	if len(input.InitialInput) > terminalInitialInputMaxBytes ||
		strings.ContainsRune(input.InitialInput, 0) ||
		!utf8.ValidString(input.InitialInput) {
		return TerminalExecutionRequest{}, fmt.Errorf("terminal execution request: invalid initial input")
	}
	if input.CheckInInterval < 0 || input.CheckInInterval >= input.Process.Timeout() {
		return TerminalExecutionRequest{}, fmt.Errorf("terminal execution request: invalid check-in interval")
	}
	if input.Columns < 0 || input.Columns > terminalMaxDimension || input.Rows < 0 || input.Rows > terminalMaxDimension ||
		(input.Columns == 0) != (input.Rows == 0) {
		return TerminalExecutionRequest{}, fmt.Errorf("terminal execution request: invalid terminal dimensions")
	}
	labels, err := cloneValidatedTerminalLabels(input.Labels)
	if err != nil {
		return TerminalExecutionRequest{}, fmt.Errorf("terminal execution request: %w", err)
	}
	for _, variable := range input.Process.Environment() {
		if variable.Name() == TerminalPaneIDEnvName {
			return TerminalExecutionRequest{}, fmt.Errorf("terminal execution request: %s is reserved for trampoline pass-through", TerminalPaneIDEnvName)
		}
	}
	return TerminalExecutionRequest{
		process:             input.Process,
		startupTimeout:      input.StartupTimeout,
		promptFilePath:      input.PromptFilePath,
		initialInput:        input.InitialInput,
		requireOSCReporting: input.RequireOSCReporting,
		checkInInterval:     input.CheckInInterval,
		columns:             input.Columns,
		rows:                input.Rows,
		labels:              labels,
	}, nil
}

func (request TerminalExecutionRequest) Process() ProcessRequest       { return request.process }
func (request TerminalExecutionRequest) StartupTimeout() time.Duration { return request.startupTimeout }
func (request TerminalExecutionRequest) PromptFilePath() AnchoredRoot  { return request.promptFilePath }
func (request TerminalExecutionRequest) InitialInput() string          { return request.initialInput }
func (request TerminalExecutionRequest) RequireOSCReporting() bool {
	return request.requireOSCReporting
}
func (request TerminalExecutionRequest) CheckInInterval() time.Duration {
	return request.checkInInterval
}
func (request TerminalExecutionRequest) Columns() int { return request.columns }
func (request TerminalExecutionRequest) Rows() int    { return request.rows }
func (request TerminalExecutionRequest) Labels() map[string]string {
	if len(request.labels) == 0 {
		return nil
	}
	copied := make(map[string]string, len(request.labels))
	for key, value := range request.labels {
		copied[key] = value
	}
	return copied
}
func (request TerminalExecutionRequest) Valid() bool {
	_, err := NewTerminalExecutionRequest(TerminalExecutionRequestInput{
		Process:             request.process,
		StartupTimeout:      request.startupTimeout,
		PromptFilePath:      request.promptFilePath,
		InitialInput:        request.initialInput,
		RequireOSCReporting: request.requireOSCReporting,
		CheckInInterval:     request.checkInInterval,
		Columns:             request.columns,
		Rows:                request.rows,
		Labels:              request.labels,
	})
	return err == nil
}

// TerminalExecutionObservationInput holds construction fields for one terminal
// pane execution observation.
type TerminalExecutionObservationInput struct {
	Process            ProcessObservation
	RuntimeIdentity    TerminalRuntimeIdentity
	ProgramStatus      TerminalProgramStatus
	BlockedKind        TerminalBlockedKind
	Reported           bool
	ExitedBeforeReport bool
	TurnCount          int
	ScreenCapture      []byte
	PaneID             string
}

// TerminalExecutionObservation is the immutable neutral execution record from
// one managed terminal pane. ScreenCapture is bounded post-kill diagnostic
// context only and never authorizes skipping staged-output validation.
type TerminalExecutionObservation struct {
	process            ProcessObservation
	runtimeIdentity    TerminalRuntimeIdentity
	programStatus      TerminalProgramStatus
	blockedKind        TerminalBlockedKind
	reported           bool
	exitedBeforeReport bool
	turnCount          int
	screenCapture      []byte
	paneID             string
}

// NewTerminalExecutionObservation validates an immutable terminal pane
// observation.
func NewTerminalExecutionObservation(input TerminalExecutionObservationInput) (TerminalExecutionObservation, error) {
	canonicalProcess, err := canonicalProcessObservation(input.Process)
	if err != nil {
		return TerminalExecutionObservation{}, fmt.Errorf("terminal execution observation: invalid process observation: %w", err)
	}
	transport, hasTransport := canonicalProcess.ProviderPacketTransportReceipt()
	if hasTransport && transport.Channel() != ProviderPacketChannelTerminal {
		return TerminalExecutionObservation{}, fmt.Errorf("terminal execution observation: process observation must use terminal transport channel")
	}
	if !input.RuntimeIdentity.Valid() {
		return TerminalExecutionObservation{}, fmt.Errorf("terminal execution observation: invalid runtime identity")
	}
	if input.ProgramStatus != "" && !input.ProgramStatus.Valid() {
		return TerminalExecutionObservation{}, fmt.Errorf("terminal execution observation: invalid program status")
	}
	if input.ProgramStatus != "" && !input.Reported {
		return TerminalExecutionObservation{}, fmt.Errorf("terminal execution observation: program status requires reported == true")
	}
	if input.BlockedKind != "" {
		if !input.BlockedKind.Valid() || input.ProgramStatus != TerminalProgramStatusBlocked {
			return TerminalExecutionObservation{}, fmt.Errorf("terminal execution observation: blocked kind requires blocked program status")
		}
	}
	if input.Reported && input.ExitedBeforeReport {
		return TerminalExecutionObservation{}, fmt.Errorf("terminal execution observation: cannot be both reported and exited before report")
	}
	if input.TurnCount < 0 {
		return TerminalExecutionObservation{}, fmt.Errorf("terminal execution observation: negative turn count")
	}
	if input.TurnCount > 0 && !input.Reported {
		return TerminalExecutionObservation{}, fmt.Errorf("terminal execution observation: turn count requires reported == true")
	}
	if (input.Reported || input.ProgramStatus != "" || input.TurnCount > 0) &&
		(!hasTransport || transport.Channel() != ProviderPacketChannelTerminal) {
		return TerminalExecutionObservation{}, fmt.Errorf("terminal execution observation: reported terminal progress requires a terminal transport receipt")
	}
	if len(input.ScreenCapture) > terminalScreenCaptureMaxBytes {
		return TerminalExecutionObservation{}, fmt.Errorf("terminal execution observation: screen capture exceeds bound")
	}
	if input.PaneID != "" && !ValidTerminalPaneID(input.PaneID) {
		return TerminalExecutionObservation{}, fmt.Errorf("terminal execution observation: invalid pane ID")
	}
	return TerminalExecutionObservation{
		process:            canonicalProcess,
		runtimeIdentity:    input.RuntimeIdentity,
		programStatus:      input.ProgramStatus,
		blockedKind:        input.BlockedKind,
		reported:           input.Reported,
		exitedBeforeReport: input.ExitedBeforeReport,
		turnCount:          input.TurnCount,
		screenCapture:      cloneBytes(input.ScreenCapture),
		paneID:             input.PaneID,
	}, nil
}

func (observation TerminalExecutionObservation) ProcessObservation() ProcessObservation {
	return cloneProcessObservation(observation.process)
}
func (observation TerminalExecutionObservation) RuntimeIdentity() TerminalRuntimeIdentity {
	return observation.runtimeIdentity
}
func (observation TerminalExecutionObservation) ProgramStatus() (TerminalProgramStatus, bool) {
	return observation.programStatus, observation.programStatus != ""
}
func (observation TerminalExecutionObservation) BlockedKind() (TerminalBlockedKind, bool) {
	return observation.blockedKind, observation.blockedKind != ""
}
func (observation TerminalExecutionObservation) Reported() bool { return observation.reported }
func (observation TerminalExecutionObservation) ExitedBeforeReport() bool {
	return observation.exitedBeforeReport
}
func (observation TerminalExecutionObservation) TurnCount() int { return observation.turnCount }
func (observation TerminalExecutionObservation) ScreenCapture() []byte {
	return cloneBytes(observation.screenCapture)
}
func (observation TerminalExecutionObservation) PaneID() string { return observation.paneID }
func (observation TerminalExecutionObservation) Valid() bool {
	_, err := NewTerminalExecutionObservation(TerminalExecutionObservationInput{
		Process:            observation.process,
		RuntimeIdentity:    observation.runtimeIdentity,
		ProgramStatus:      observation.programStatus,
		BlockedKind:        observation.blockedKind,
		Reported:           observation.reported,
		ExitedBeforeReport: observation.exitedBeforeReport,
		TurnCount:          observation.turnCount,
		ScreenCapture:      observation.screenCapture,
		PaneID:             observation.paneID,
	})
	return err == nil
}

// TerminalSessionRunner manages one isolated per-run terminal multiplexer
// session (herdr-core) and runs guarded provider panes inside it.
//
// Implementations must start the isolated daemon lazily only when first needed,
// never contact or mutate the operator's default session, consume and close
// request.Process().LaunchDirectory() on every RunTerminal return path (while
// PaneLaunchBuilder.BuildPaneLaunch borrows it without closing), drain only
// matching labeled panes in DrainLabeledPanes (without stopping the shared
// daemon), refuse new RunTerminal calls once Close starts, and stop both core
// and holder processes idempotently in Close.
type TerminalSessionRunner interface {
	RunTerminal(ctx context.Context, request TerminalExecutionRequest) (TerminalExecutionObservation, error)
	DrainLabeledPanes(ctx context.Context, labelKey, labelValue string) error
	RuntimeIdentity(ctx context.Context) (TerminalRuntimeIdentity, error)
	Close(ctx context.Context) error
}

// ValidTerminalLabel reports whether key and value satisfy Mulgae's safe
// terminal-pane label grammar used for label-scoped drain isolation.
func ValidTerminalLabel(key, value string) bool {
	return terminalLabelKeyRe.MatchString(key) && terminalLabelValRe.MatchString(value)
}

func cloneValidatedTerminalLabels(labels map[string]string) (map[string]string, error) {
	if len(labels) == 0 {
		return nil, nil
	}
	if len(labels) > terminalMaxLabelCount {
		return nil, fmt.Errorf("too many labels")
	}
	copied := make(map[string]string, len(labels))
	for key, value := range labels {
		if !ValidTerminalLabel(key, value) {
			return nil, fmt.Errorf("invalid label %q", key)
		}
		copied[key] = value
	}
	return copied, nil
}

func pathCoveredByRoots(path string, roots []AnchoredRoot) bool {
	cleanPath := filepath.Clean(path)
	for _, root := range roots {
		if !root.Valid() {
			continue
		}
		cleanRoot := filepath.Clean(root.String())
		if cleanPath == cleanRoot || strings.HasPrefix(cleanPath, cleanRoot+string(filepath.Separator)) {
			return true
		}
	}
	return false
}
