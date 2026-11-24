//go:build darwin

package providercli

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"time"

	"golang.org/x/sys/unix"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

const (
	terminalRegistryLabelKey       = "mulgae_registry"
	terminalPromptParentDirName    = "input"
	terminalPromptFilename         = "prompt.md"
	terminalProfileSentinelEnvName = "MULGAE_TERMINAL_PROFILE_SENTINEL"
	terminalCompletionNoncePrefix  = "MULGAE_COMPLETE:"
)

// terminalInvocationPurpose classifies one managed terminal invocation so
// provider profiles can scope tools, staging filenames, and completion nonces.
type terminalInvocationPurpose string

const (
	terminalPurposeReview        terminalInvocationPurpose = "review"
	terminalPurposeExtraction    terminalInvocationPurpose = "extraction"
	terminalPurposeQualification terminalInvocationPurpose = "qualification"
)

// terminalProfileInvocation carries the Mulgae-owned paths and metadata for one
// terminal execution so provider profiles stay declarative and free of runner
// or teardown details.
type terminalProfileInvocation struct {
	Definition      RuntimeDefinition
	Purpose         terminalInvocationPurpose
	LiveScope       domain.LiveSourceScope
	HasLiveScope    bool
	NamespaceRoot   string
	ScratchDir      string
	HomeDir         string
	PromptPath      string
	OutputPath      string
	NeutralCWD      ports.AnchoredRoot
	NativeHome      ports.AnchoredRoot
	SourceRoot      ports.AnchoredRoot
	CompletionNonce string
	Namespace       *namespaceLease
	HostArgs        []string
}

// terminalProviderProfile abstracts provider-specific CLI flags, disposable
// home setup, OSC vs non-OSC readiness semantics, and boundary overlays over
// the shared terminal_provider execution driver.
type terminalProviderProfile interface {
	Family() string
	RequireOSCReporting() bool
	RequireCompletionNonce(purpose terminalInvocationPurpose) bool
	OutputFilename(purpose terminalInvocationPurpose) string
	StartupTimeout(purpose terminalInvocationPurpose) time.Duration
	CheckInInterval(purpose terminalInvocationPurpose) time.Duration
	TerminalSize() (columns int, rows int)
	// PrepareDisposableHomes prepares one or more disposable home directories
	// inside the invocation's writable namespace and returns environment
	// variables to merge into the pane launch envp.
	PrepareDisposableHomes(inv terminalProfileInvocation) ([]ports.EnvironmentVariable, error)
	// BuildArgv constructs the full provider argv for the invocation.
	BuildArgv(inv terminalProfileInvocation) ([]string, error)
	// BuildInitialInput constructs the bounded terminal.send instruction sent
	// after startup readiness. May be empty for non-OSC CLIs.
	BuildInitialInput(inv terminalProfileInvocation) string
	// BuildPromptTrailer constructs optional adapter instructions appended
	// strictly AFTER packet.Bytes() inside prompt.md so packet.Bytes() remains
	// the exact prefix verified by the terminal runner.
	BuildPromptTrailer(inv terminalProfileInvocation) []byte
	// ConfigureBoundary layers profile-specific PaneTTY / BashGate / extra
	// controls onto the base read-only boundary.
	ConfigureBoundary(base ports.LiveReadOnlyBoundary, inv terminalProfileInvocation) (ports.LiveReadOnlyBoundary, error)
}

type terminalHostPreparation struct {
	readOnlyRoots []ports.AnchoredRoot
	runtimeTemp   ports.AnchoredRoot
	verifySpawn   func() error
}

type terminalHostPreparer interface {
	PrepareHost(context.Context, *terminalProfileInvocation) (terminalHostPreparation, error)
}

type terminalFailureClassifier interface {
	ClassifyFailure(ports.TerminalExecutionObservation, ports.ProcessObservation) *terminalDriverFailure
}

// terminalDriverRequest supplies all validated inputs for one execution of
// executeTerminalInvocation.
type terminalDriverRequest struct {
	Definition           RuntimeDefinition
	Purpose              terminalInvocationPurpose
	LiveScope            domain.LiveSourceScope
	HasLiveScope         bool
	Packet               ports.ProviderPacket
	NamespaceRoot        string
	NamespaceEnvironment []ports.EnvironmentVariable
	ExtraEnvironment     []ports.EnvironmentVariable
	NeutralCWD           ports.AnchoredRoot
	LaunchDirectory      *os.File // consumed on every return path
	NativeHome           ports.AnchoredRoot
	SourceRoot           ports.AnchoredRoot
	ReadOnlyRoots        []ports.AnchoredRoot
	CredentialRoots      []ports.AnchoredRoot
	ControlPlaneRoots    []ports.AnchoredRoot
	ControlPlaneLiterals []ports.AnchoredRoot
	Timeout              time.Duration
	RegistryGeneration   string
	Namespace            *namespaceLease

	// Optional test hooks for deterministic B-1 Control 5 verification.
	SurvivorCheck      func(sentinel string) error
	StabilityWindow    time.Duration
	AfterFirstStatHook func()
}

// terminalDriverResult is returned by executeTerminalInvocation when the pane
// completed cleanly, passed post-ESRCH staged output validation, and (when
// required) passed completion-nonce verification.
type terminalDriverResult struct {
	Process              ports.ProcessObservation
	RuntimeIdentity      ports.TerminalRuntimeIdentity
	OutputBytes          []byte
	StagedReceipt        ports.StagedOutputReceipt
	EffectiveArgv        []string
	EffectiveEnvironment []ports.EnvironmentVariable
}

// terminalDriverFailure carries an exact, closed classification selected by
// terminal_provider.go without allowing post-kill screen capture text to
// override security, launch-boundary, or staging failures.
type terminalDriverFailure struct {
	status       ports.ProviderExecutionStatus
	diagnostic   string
	cause        domain.RuntimeDiagnosticCause
	cleanupCause domain.RuntimeDiagnosticCause
	err          error
}

func (f *terminalDriverFailure) Error() string {
	if f == nil {
		return "terminal provider failed"
	}
	if f.err != nil {
		return fmt.Sprintf("terminal provider failed (%s): %v", f.cause, f.err)
	}
	return fmt.Sprintf("terminal provider failed (%s)", f.cause)
}

func (f *terminalDriverFailure) Unwrap() error {
	if f == nil {
		return nil
	}
	return f.err
}

func (f *terminalDriverFailure) Cause() domain.RuntimeDiagnosticCause {
	if f == nil {
		return ""
	}
	return f.cause
}

func (f *terminalDriverFailure) Status() ports.ProviderExecutionStatus {
	if f == nil {
		return ""
	}
	return f.status
}

func (f *terminalDriverFailure) Diagnostic() string {
	if f == nil {
		return ""
	}
	return f.diagnostic
}

func (f *terminalDriverFailure) CleanupCause() domain.RuntimeDiagnosticCause {
	if f == nil {
		return ""
	}
	return f.cleanupCause
}

func newTerminalDriverFailure(
	status ports.ProviderExecutionStatus,
	diagnostic string,
	cause, cleanupCause domain.RuntimeDiagnosticCause,
	err error,
) *terminalDriverFailure {
	return &terminalDriverFailure{
		status:       status,
		diagnostic:   diagnostic,
		cause:        cause,
		cleanupCause: cleanupCause,
		err:          err,
	}
}

func nilTerminalSessionRunner(runner ports.TerminalSessionRunner) bool {
	if runner == nil {
		return true
	}
	value := reflect.ValueOf(runner)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func terminalRandomHex(byteCount int) (string, error) {
	raw := make([]byte, byteCount)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate terminal entropy: %w", err)
	}
	return hex.EncodeToString(raw), nil
}

// carveTerminalStartupTimeout carves StartupTimeout out of the total family
// timeout budget so StartupTimeout is always strictly positive and strictly
// less than total.
func carveTerminalStartupTimeout(total, requested time.Duration) (time.Duration, error) {
	maxStartup := total / 2
	if total <= 0 || maxStartup <= 0 {
		return 0, fmt.Errorf("terminal timeout %s is too small to carve startup budget", total)
	}
	startup := requested
	if startup <= 0 || startup > maxStartup {
		startup = maxStartup
	}
	if startup <= 0 || startup >= total {
		return 0, fmt.Errorf("invalid carved startup timeout %s for total %s", startup, total)
	}
	return startup, nil
}

// carveTerminalCheckInInterval bounds the check-in interval strictly below
// total timeout (or returns 0 when check-ins are disabled or budget is tiny).
func carveTerminalCheckInInterval(total, requested time.Duration) time.Duration {
	if requested <= 0 || total <= 0 {
		return 0
	}
	if requested < total {
		return requested
	}
	carved := total / 4
	if carved <= 0 || carved >= total {
		return 0
	}
	return carved
}

// stagedPromptLease owns one per-invocation read-only prompt directory
// (<scratch>/input/<invID>/prompt.md, mode 0400) anchored through descriptors.
type stagedPromptLease struct {
	parentDir *os.File
	invDir    *os.File
	invName   string
	path      string
	released  bool
}

func createStagedPromptFile(scratchDir, invID string, packetBytes, trailer []byte) (*stagedPromptLease, string, error) {
	if !validCanonicalAbsolute(scratchDir) || scratchDir == string(filepath.Separator) {
		return nil, "", fmt.Errorf("staged prompt: invalid scratch directory")
	}
	if !validStagedOutputDirectoryName(invID) {
		return nil, "", fmt.Errorf("staged prompt: invalid invocation id")
	}
	parentPath := filepath.Join(scratchDir, terminalPromptParentDirName)
	if err := os.MkdirAll(parentPath, 0o700); err != nil {
		return nil, "", fmt.Errorf("staged prompt: create input parent: %w", err)
	}
	parentFD, err := unix.Open(parentPath, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, "", fmt.Errorf("staged prompt: open input parent: %w", err)
	}
	parentDir := os.NewFile(uintptr(parentFD), "terminal staged prompt parent")
	var parentStat unix.Stat_t
	if err := unix.Fstat(parentFD, &parentStat); err != nil || parentStat.Mode&unix.S_IFMT != unix.S_IFDIR ||
		parentStat.Uid != uint32(unix.Geteuid()) || parentStat.Mode&0o077 != 0 {
		_ = parentDir.Close()
		return nil, "", fmt.Errorf("staged prompt: unsafe input parent directory")
	}
	if err := unix.Mkdirat(parentFD, invID, 0o700); err != nil {
		_ = parentDir.Close()
		return nil, "", fmt.Errorf("staged prompt: create invocation input directory: %w", err)
	}
	invFD, err := unix.Openat(parentFD, invID, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		_ = unix.Unlinkat(parentFD, invID, unix.AT_REMOVEDIR)
		_ = parentDir.Close()
		return nil, "", fmt.Errorf("staged prompt: open invocation input directory: %w", err)
	}
	invDir := os.NewFile(uintptr(invFD), "terminal staged prompt directory")
	fileFD, err := unix.Openat(invFD, terminalPromptFilename, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		_ = invDir.Close()
		_ = unix.Unlinkat(parentFD, invID, unix.AT_REMOVEDIR)
		_ = parentDir.Close()
		return nil, "", fmt.Errorf("staged prompt: create prompt file: %w", err)
	}
	file := os.NewFile(uintptr(fileFD), "terminal staged prompt file")
	writeAll := func(data []byte) error {
		for len(data) > 0 {
			n, werr := file.Write(data)
			if werr != nil {
				return werr
			}
			data = data[n:]
		}
		return nil
	}
	writeErr := writeAll(packetBytes)
	if writeErr == nil && len(trailer) > 0 {
		writeErr = writeAll(trailer)
	}
	chmodErr := error(nil)
	if writeErr == nil {
		chmodErr = unix.Fchmod(int(file.Fd()), 0o400)
	}
	syncErr := error(nil)
	if writeErr == nil && chmodErr == nil {
		syncErr = file.Sync()
	}
	closeErr := file.Close()
	if err := errors.Join(writeErr, chmodErr, syncErr, closeErr); err != nil {
		_ = unix.Unlinkat(invFD, terminalPromptFilename, 0)
		_ = invDir.Close()
		_ = unix.Unlinkat(parentFD, invID, unix.AT_REMOVEDIR)
		_ = parentDir.Close()
		return nil, "", fmt.Errorf("staged prompt: write prompt file: %w", err)
	}
	lease := &stagedPromptLease{
		parentDir: parentDir,
		invDir:    invDir,
		invName:   invID,
		path:      filepath.Join(parentPath, invID, terminalPromptFilename),
	}
	return lease, parentPath, nil
}

func (lease *stagedPromptLease) Cleanup() error {
	if lease == nil || lease.released {
		return nil
	}
	var errs []error
	if lease.invDir != nil {
		if err := unix.Unlinkat(int(lease.invDir.Fd()), terminalPromptFilename, 0); err != nil && !errors.Is(err, unix.ENOENT) {
			errs = append(errs, fmt.Errorf("unlink staged prompt: %w", err))
		}
		if err := lease.invDir.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close staged prompt directory: %w", err))
		}
		lease.invDir = nil
	}
	if lease.parentDir != nil {
		if err := unix.Unlinkat(int(lease.parentDir.Fd()), lease.invName, unix.AT_REMOVEDIR); err != nil && !errors.Is(err, unix.ENOENT) {
			errs = append(errs, fmt.Errorf("remove staged prompt directory: %w", err))
		}
		if err := lease.parentDir.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close staged prompt parent: %w", err))
		}
		lease.parentDir = nil
	}
	lease.released = true
	return errors.Join(errs...)
}

// verifyAndStripCompletionNonce verifies that the final non-empty line of raw
// equals "MULGAE_COMPLETE:<nonce>", strips that marker line cleanly, and
// verifies that non-whitespace content remains before it.
func verifyAndStripCompletionNonce(raw []byte, nonce string) ([]byte, error) {
	if nonce == "" {
		return nil, stagedOutputFileInvalid("missing expected completion nonce")
	}
	trimmed := bytes.TrimRight(raw, " \t\r\n")
	if len(trimmed) == 0 {
		return nil, stagedOutputFileInvalid("staged output is empty")
	}
	expected := []byte(terminalCompletionNoncePrefix + nonce)
	lastNL := bytes.LastIndexByte(trimmed, '\n')
	var lastLine, prefix []byte
	if lastNL < 0 {
		lastLine = trimmed
		prefix = nil
	} else {
		lastLine = bytes.TrimSpace(trimmed[lastNL+1:])
		prefix = trimmed[:lastNL]
	}
	if !bytes.Equal(lastLine, expected) {
		return nil, stagedOutputFileInvalid("staged output missing or mismatched completion nonce")
	}
	body := bytes.TrimRight(prefix, " \t\r\n")
	if len(bytes.TrimSpace(body)) == 0 {
		return nil, stagedOutputFileInvalid("staged output body is empty before completion nonce")
	}
	if bytes.Contains(body, []byte(nonce)) {
		return nil, stagedOutputFileInvalid("staged output leaked completion nonce inside report body")
	}
	result := make([]byte, len(body)+1)
	copy(result, body)
	result[len(body)] = '\n'
	return result, nil
}

func envLookupValue(environment []ports.EnvironmentVariable, name string) (string, bool) {
	for _, variable := range environment {
		if variable.Name() == name {
			return variable.Value(), true
		}
	}
	return "", false
}

func mergeTerminalEnvironment(base, overlays []ports.EnvironmentVariable) ([]ports.EnvironmentVariable, error) {
	merged := make(map[string]ports.EnvironmentVariable, len(base)+len(overlays))
	for _, variable := range base {
		if !variable.Valid() {
			return nil, fmt.Errorf("terminal environment: invalid base variable")
		}
		merged[variable.Name()] = variable
	}
	for _, variable := range overlays {
		if !variable.Valid() {
			return nil, fmt.Errorf("terminal environment: invalid overlay variable")
		}
		if variable.Name() == ports.TerminalPaneIDEnvName {
			return nil, fmt.Errorf("terminal environment: %s must not be supplied explicitly", ports.TerminalPaneIDEnvName)
		}
		merged[variable.Name()] = variable
	}
	names := make([]string, 0, len(merged))
	for name := range merged {
		names = append(names, name)
	}
	sort.Strings(names)
	result := make([]ports.EnvironmentVariable, 0, len(names))
	for _, name := range names {
		result = append(result, merged[name])
	}
	return result, nil
}

// executeTerminalInvocation runs one guarded, provider-agnostic managed
// terminal invocation over ports.TerminalSessionRunner. It owns prompt-file
// staging, parameterized output-file staging, timeout carving, post-ESRCH
// staging + B-1 Control 5 validation, completion-nonce verification/stripping,
// and closed failure classification.
func executeTerminalInvocation(
	ctx context.Context,
	runner ports.TerminalSessionRunner,
	profile terminalProviderProfile,
	req terminalDriverRequest,
) (res terminalDriverResult, retErr error) {
	launchDir := req.LaunchDirectory
	closeLaunchDir := func() {
		if launchDir != nil {
			_ = launchDir.Close()
			launchDir = nil
		}
	}
	defer closeLaunchDir()

	if ctx == nil || nilTerminalSessionRunner(runner) || profile == nil {
		return terminalDriverResult{}, providerRuntimeFailure(
			domain.DiagnosticCauseProviderSpawnFailed,
			fmt.Errorf("terminal provider: missing runner or profile"),
		)
	}
	if err := ctx.Err(); err != nil {
		return terminalDriverResult{}, err
	}
	if !req.Packet.Valid() || !validCanonicalAbsolute(req.NamespaceRoot) ||
		!req.NeutralCWD.Valid() || !req.NativeHome.Valid() || !req.SourceRoot.Valid() ||
		launchDir == nil || launchDir.Fd() == ^uintptr(0) {
		return terminalDriverResult{}, providerRuntimeFailure(
			domain.DiagnosticCauseProviderSpawnFailed,
			fmt.Errorf("terminal provider: invalid invocation authority"),
		)
	}
	scratchDir, hasScratch := envLookupValue(req.NamespaceEnvironment, "MULGAE_PROVIDER_SCRATCH")
	homeDir, hasHome := envLookupValue(req.NamespaceEnvironment, "HOME")
	if !hasScratch || !validCanonicalAbsolute(scratchDir) || !hasHome || !validCanonicalAbsolute(homeDir) {
		return terminalDriverResult{}, providerRuntimeFailure(
			domain.DiagnosticCauseProviderSpawnFailed,
			fmt.Errorf("terminal provider: incomplete namespace environment"),
		)
	}

	invHex, err := terminalRandomHex(12)
	if err != nil {
		return terminalDriverResult{}, providerRuntimeFailure(domain.DiagnosticCauseProviderSpawnFailed, err)
	}
	invID := "term-" + invHex

	completionNonce := ""
	if profile.RequireCompletionNonce(req.Purpose) {
		completionNonce, err = terminalRandomHex(16)
		if err != nil {
			return terminalDriverResult{}, providerRuntimeFailure(domain.DiagnosticCauseProviderSpawnFailed, err)
		}
	}

	outputFilename := profile.OutputFilename(req.Purpose)
	outputLease, err := createStagedOutputDirectoryWithFilename(
		filepath.Join(scratchDir, stagedOutputParentDirectoryName),
		invID,
		outputFilename,
	)
	if err != nil {
		return terminalDriverResult{}, providerRuntimeFailure(stagedOutputCause(err), err)
	}
	defer func() {
		cleanupErr := outputLease.Cleanup()
		if cleanupErr != nil && retErr == nil {
			cause := stagedOutputCause(cleanupErr)
			status, diagnostic := providerFailureProjection(cause)
			res.OutputBytes = nil
			retErr = newTerminalDriverFailure(status, diagnostic, cause, "", cleanupErr)
		}
	}()
	outputDest, err := outputLease.Destination()
	if err != nil {
		return terminalDriverResult{}, providerRuntimeFailure(stagedOutputCause(err), err)
	}

	inv := terminalProfileInvocation{
		Definition:      req.Definition,
		Purpose:         req.Purpose,
		LiveScope:       req.LiveScope,
		HasLiveScope:    req.HasLiveScope,
		NamespaceRoot:   req.NamespaceRoot,
		ScratchDir:      scratchDir,
		HomeDir:         homeDir,
		PromptPath:      filepath.Join(scratchDir, terminalPromptParentDirName, invID, terminalPromptFilename),
		OutputPath:      outputDest.AbsolutePath(),
		NeutralCWD:      req.NeutralCWD,
		NativeHome:      req.NativeHome,
		SourceRoot:      req.SourceRoot,
		CompletionNonce: completionNonce,
		Namespace:       req.Namespace,
	}

	trailer := profile.BuildPromptTrailer(inv)
	promptLease, promptParentPath, err := createStagedPromptFile(scratchDir, invID, req.Packet.Bytes(), trailer)
	if err != nil {
		return terminalDriverResult{}, providerRuntimeFailure(domain.DiagnosticCausePromptFilePreStartFailed, err)
	}
	defer func() {
		_ = promptLease.Cleanup()
	}()
	inv.PromptPath = promptLease.path

	var preparation terminalHostPreparation
	if preparer, ok := profile.(terminalHostPreparer); ok {
		preparation, err = preparer.PrepareHost(ctx, &inv)
		if err != nil {
			return terminalDriverResult{}, err
		}
	}

	profileEnv, err := profile.PrepareDisposableHomes(inv)
	if err != nil {
		return terminalDriverResult{}, providerRuntimeFailure(domain.DiagnosticCauseProviderSpawnFailed, err)
	}

	writableRoot, err := ports.NewAnchoredRoot(req.NamespaceRoot)
	if err != nil {
		return terminalDriverResult{}, providerRuntimeFailure(domain.DiagnosticCauseWorkspaceRevalidationFailed, err)
	}
	promptParentRoot, err := ports.NewAnchoredRoot(promptParentPath)
	if err != nil {
		return terminalDriverResult{}, providerRuntimeFailure(domain.DiagnosticCausePromptFilePreStartFailed, err)
	}
	// Include <scratch>/input in ReadOnlyRoots so Seatbelt's explicit deny on
	// ReadOnlyRoots overrides WritableRoot and protects sibling prompt
	// directories across concurrent roles.
	readOnlyRoots := make([]ports.AnchoredRoot, 0, len(req.ReadOnlyRoots)+3)
	readOnlyRoots = append(readOnlyRoots, req.SourceRoot, req.NeutralCWD, promptParentRoot)
	readOnlyRoots = append(readOnlyRoots, req.ReadOnlyRoots...)
	readOnlyRoots = append(readOnlyRoots, preparation.readOnlyRoots...)

	var boundary ports.LiveReadOnlyBoundary
	if preparation.runtimeTemp.Valid() {
		boundary, err = ports.NewLiveReadOnlyBoundaryWithRuntimeTemp(readOnlyRoots, req.CredentialRoots, writableRoot, preparation.runtimeTemp)
	} else {
		boundary, err = ports.NewLiveReadOnlyBoundary(readOnlyRoots, req.CredentialRoots, writableRoot)
	}
	if err != nil {
		return terminalDriverResult{}, providerRuntimeFailure(domain.DiagnosticCauseWorkspaceRevalidationFailed, err)
	}
	if len(req.ControlPlaneRoots) > 0 || len(req.ControlPlaneLiterals) > 0 {
		boundary, err = ports.NewLiveReadOnlyBoundaryWithControlPlane(boundary, req.ControlPlaneRoots, req.ControlPlaneLiterals)
		if err != nil {
			return terminalDriverResult{}, providerRuntimeFailure(domain.DiagnosticCauseWorkspaceRevalidationFailed, err)
		}
	}
	boundary, err = profile.ConfigureBoundary(boundary, inv)
	if err != nil {
		return terminalDriverResult{}, providerRuntimeFailure(domain.DiagnosticCauseWorkspaceRevalidationFailed, err)
	}

	profileSentinel := ""
	overlays := make([]ports.EnvironmentVariable, 0, len(req.ExtraEnvironment)+len(profileEnv)+1)
	overlays = append(overlays, req.ExtraEnvironment...)
	overlays = append(overlays, profileEnv...)
	if boundary.BashGate() {
		sentinelHex, sErr := terminalRandomHex(16)
		if sErr != nil {
			return terminalDriverResult{}, providerRuntimeFailure(domain.DiagnosticCauseProviderSpawnFailed, sErr)
		}
		profileSentinel = "mulgae-sentinel-" + sentinelHex
		sentinelVar, sErr := ports.NewEnvironmentVariable(terminalProfileSentinelEnvName, profileSentinel)
		if sErr != nil {
			return terminalDriverResult{}, providerRuntimeFailure(domain.DiagnosticCauseProviderSpawnFailed, sErr)
		}
		overlays = append(overlays, sentinelVar)
	}

	effectiveEnv, err := mergeTerminalEnvironment(req.NamespaceEnvironment, overlays)
	if err != nil {
		return terminalDriverResult{}, providerRuntimeFailure(domain.DiagnosticCauseProviderSpawnFailed, err)
	}

	argv, err := profile.BuildArgv(inv)
	if err != nil {
		return terminalDriverResult{}, providerRuntimeFailure(domain.DiagnosticCauseProviderSpawnFailed, err)
	}
	startupTimeout, err := carveTerminalStartupTimeout(req.Timeout, profile.StartupTimeout(req.Purpose))
	if err != nil {
		return terminalDriverResult{}, providerRuntimeFailure(domain.DiagnosticCauseProviderSpawnFailed, err)
	}
	checkIn := carveTerminalCheckInInterval(req.Timeout, profile.CheckInInterval(req.Purpose))
	columns, rows := profile.TerminalSize()

	packetBinding, err := ports.NewTerminalProviderPacketBinding(req.Packet)
	if err != nil {
		return terminalDriverResult{}, providerRuntimeFailure(domain.DiagnosticCauseTransportVerificationFailed, err)
	}
	procReq, err := ports.NewProviderTerminalProcessRequest(
		req.Definition.Executable(),
		argv,
		effectiveEnv,
		req.NeutralCWD.String(),
		packetBinding,
		req.Timeout,
	)
	if err != nil {
		return terminalDriverResult{}, providerRuntimeFailure(domain.DiagnosticCauseProviderSpawnFailed, err)
	}
	procReq, err = ports.NewLiveReadOnlyProcessRequest(procReq, boundary)
	if err != nil {
		return terminalDriverResult{}, providerRuntimeFailure(domain.DiagnosticCauseWorkspaceRevalidationFailed, err)
	}
	procReq, err = ports.NewNeutralBoundProcessRequest(procReq, req.NeutralCWD, launchDir)
	if err != nil {
		return terminalDriverResult{}, providerRuntimeFailure(domain.DiagnosticCauseWorkspaceRevalidationFailed, err)
	}

	promptFileRoot, err := ports.NewAnchoredRoot(inv.PromptPath)
	if err != nil {
		return terminalDriverResult{}, providerRuntimeFailure(domain.DiagnosticCausePromptFilePreStartFailed, err)
	}
	var labels map[string]string
	if req.RegistryGeneration != "" {
		if !ports.ValidTerminalLabel(terminalRegistryLabelKey, req.RegistryGeneration) {
			return terminalDriverResult{}, providerRuntimeFailure(
				domain.DiagnosticCauseProviderSpawnFailed,
				fmt.Errorf("terminal provider: invalid registry label generation"),
			)
		}
		labels = map[string]string{terminalRegistryLabelKey: req.RegistryGeneration}
	}

	termReq, err := ports.NewTerminalExecutionRequest(ports.TerminalExecutionRequestInput{
		Process:             procReq,
		StartupTimeout:      startupTimeout,
		PromptFilePath:      promptFileRoot,
		InitialInput:        profile.BuildInitialInput(inv),
		RequireOSCReporting: profile.RequireOSCReporting(),
		CheckInInterval:     checkIn,
		Columns:             columns,
		Rows:                rows,
		Labels:              labels,
	})
	if err != nil {
		return terminalDriverResult{}, providerRuntimeFailure(domain.DiagnosticCauseProviderSpawnFailed, err)
	}

	if preparation.verifySpawn != nil {
		if err := preparation.verifySpawn(); err != nil {
			return terminalDriverResult{}, err
		}
	}

	// Ownership of launchDir transfers to runner.RunTerminal now.
	launchDir = nil
	termObs, runErr := runner.RunTerminal(ctx, termReq)
	if runErr != nil {
		var procObs ports.ProcessObservation
		var rtIdentity ports.TerminalRuntimeIdentity
		if termObs.Valid() {
			procObs = termObs.ProcessObservation()
			rtIdentity = termObs.RuntimeIdentity()
		}
		return terminalDriverResult{
			Process:              procObs,
			RuntimeIdentity:      rtIdentity,
			EffectiveArgv:        argv,
			EffectiveEnvironment: effectiveEnv,
		}, runErr
	}
	if !termObs.Valid() || !termObs.RuntimeIdentity().Valid() {
		return terminalDriverResult{
			EffectiveArgv:        argv,
			EffectiveEnvironment: effectiveEnv,
		}, providerRuntimeFailure(domain.DiagnosticCauseObservationInvalid, fmt.Errorf("terminal runner returned invalid observation"))
	}

	procObs := termObs.ProcessObservation()
	baseResult := terminalDriverResult{
		Process:              procObs,
		RuntimeIdentity:      termObs.RuntimeIdentity(),
		EffectiveArgv:        argv,
		EffectiveEnvironment: effectiveEnv,
	}

	// Process-level terminal outcomes take precedence over OSC or staging.
	// Evaluate residual process group first as fail-closed security, then
	// strictly pre-start failures, then cancellation/timeout (allowing
	// non-security Cancelled/TimedOut only when ProcessGroupAbsent() is true
	// or no pane ever started).
	_, hasLifecycle := procObs.LifecycleReceipt()
	paneNeverStarted := termObs.PaneID() == "" && !hasLifecycle
	switch procObs.Termination() {
	case ports.ProcessTerminationResidualProcessGroup:
		return baseResult, newTerminalDriverFailure(
			ports.ProviderExecutionStatusSecurityViolation,
			"process_security",
			domain.DiagnosticCauseProcessGroupCleanupFailed,
			domain.DiagnosticCauseProcessGroupCleanupFailed,
			fmt.Errorf("residual terminal process group after teardown"),
		)
	case ports.ProcessTerminationStartSecurity:
		return baseResult, newTerminalDriverFailure(
			ports.ProviderExecutionStatusSecurityViolation,
			"process_security",
			domain.DiagnosticCauseProviderSpawnFailed,
			"",
			fmt.Errorf("terminal pane start refused by security policy"),
		)
	case ports.ProcessTerminationStartConfiguration:
		return baseResult, newTerminalDriverFailure(
			ports.ProviderExecutionStatusConfigurationViolation,
			"process_configuration",
			domain.DiagnosticCauseProviderSpawnFailed,
			"",
			fmt.Errorf("terminal pane start refused by configuration"),
		)
	case ports.ProcessTerminationStartUnavailable:
		return baseResult, newTerminalDriverFailure(
			ports.ProviderExecutionStatusUnavailable,
			"process_unavailable",
			domain.DiagnosticCauseProviderSpawnFailed,
			"",
			fmt.Errorf("terminal pane executable unavailable"),
		)
	case ports.ProcessTerminationStartFailed:
		return baseResult, newTerminalDriverFailure(
			ports.ProviderExecutionStatusInternalFailure,
			"process_internal",
			domain.DiagnosticCauseProviderSpawnFailed,
			"",
			fmt.Errorf("terminal pane failed to start"),
		)
	case ports.ProcessTerminationCancelled:
		if !procObs.ProcessGroupAbsent() && !paneNeverStarted {
			return baseResult, newTerminalDriverFailure(
				ports.ProviderExecutionStatusSecurityViolation,
				"process_security",
				domain.DiagnosticCauseProcessGroupCleanupFailed,
				domain.DiagnosticCauseProcessGroupCleanupFailed,
				fmt.Errorf("cancelled terminal pane process group still present after teardown"),
			)
		}
		return baseResult, newTerminalDriverFailure(
			ports.ProviderExecutionStatusCancelled,
			"process_cancelled",
			domain.DiagnosticCauseProviderExecutionFailed,
			"",
			context.Canceled,
		)
	case ports.ProcessTerminationTimedOut:
		if !procObs.ProcessGroupAbsent() && !paneNeverStarted {
			return baseResult, newTerminalDriverFailure(
				ports.ProviderExecutionStatusSecurityViolation,
				"process_security",
				domain.DiagnosticCauseProcessGroupCleanupFailed,
				domain.DiagnosticCauseProcessGroupCleanupFailed,
				fmt.Errorf("timed-out terminal pane process group still present after teardown"),
			)
		}
		return baseResult, newTerminalDriverFailure(
			ports.ProviderExecutionStatusTimedOut,
			"process_timeout",
			domain.DiagnosticCauseTimedOut,
			"",
			fmt.Errorf("terminal provider timed out"),
		)
	}

	// Never classify OSC/non-OSC outcomes or inspect staged output unless
	// process-group/session teardown was proven absent (ESRCH).
	if !procObs.ProcessGroupAbsent() {
		return baseResult, newTerminalDriverFailure(
			ports.ProviderExecutionStatusSecurityViolation,
			"process_security",
			domain.DiagnosticCauseProcessGroupCleanupFailed,
			domain.DiagnosticCauseProcessGroupCleanupFailed,
			fmt.Errorf("terminal pane process group still present after teardown"),
		)
	}

	if profile.RequireOSCReporting() {
		if classifier, ok := profile.(terminalFailureClassifier); ok {
			if failure := classifier.ClassifyFailure(termObs, procObs); failure != nil {
				return baseResult, failure
			}
		}
		if failure := classifyOSCTerminalOutcome(profile.Family(), termObs, procObs); failure != nil {
			return baseResult, failure
		}
	} else {
		exitCode, exited := procObs.ExitCode()
		if procObs.Termination() != ports.ProcessTerminationExited || !exited || exitCode != 0 || !procObs.TerminalSessionCompleted() {
			status := ports.ProviderExecutionStatusUnavailable
			diagnostic := "provider_execution_failed"
			if procObs.Termination() == ports.ProcessTerminationSignaled && !procObs.TerminalSessionCompleted() {
				status = ports.ProviderExecutionStatusInternalFailure
				diagnostic = "process_internal"
			}
			return baseResult, newTerminalDriverFailure(
				status,
				diagnostic,
				domain.DiagnosticCauseProviderExecutionFailed,
				"",
				fmt.Errorf("non-OSC terminal provider exited abnormally (termination=%s exit=%d)", procObs.Termination(), exitCode),
			)
		}
	}

	// Post-ESRCH staged output validation (+ B-1 Control 5 when BashGate active).
	validateOpts := stagedOutputValidateOptions{
		requireStabilityCheck: boundary.BashGate(),
		profileSentinel:       profileSentinel,
		survivorCheck:         req.SurvivorCheck,
		stabilityWindow:       req.StabilityWindow,
		afterFirstStatHook:    req.AfterFirstStatHook,
	}
	stagedBytes, stagedReceipt, stageErr := outputLease.ValidateWithOptions(validateOpts)
	if stageErr != nil {
		cause := stagedOutputCause(stageErr)
		status, diagnostic := providerFailureProjection(cause)
		return baseResult, newTerminalDriverFailure(status, diagnostic, cause, "", stageErr)
	}

	if profile.RequireCompletionNonce(req.Purpose) {
		stripped, nonceErr := verifyAndStripCompletionNonce(stagedBytes, completionNonce)
		if nonceErr != nil {
			cause := stagedOutputCause(nonceErr)
			status, diagnostic := providerFailureProjection(cause)
			return baseResult, newTerminalDriverFailure(status, diagnostic, cause, "", nonceErr)
		}
		stagedBytes = stripped
		sum := sha256.Sum256(stagedBytes)
		strippedReceipt, receiptErr := ports.NewStagedOutputReceipt("sha256:"+hex.EncodeToString(sum[:]), int64(len(stagedBytes)))
		if receiptErr != nil {
			return baseResult, newTerminalDriverFailure(
				ports.ProviderExecutionStatusArtifactFailure,
				"invalid_provider_output",
				domain.DiagnosticCauseProviderOutputFileInvalid,
				"",
				fmt.Errorf("recompute stripped staged output receipt: %w", receiptErr),
			)
		}
		stagedReceipt = strippedReceipt
	}

	baseResult.OutputBytes = stagedBytes
	baseResult.StagedReceipt = stagedReceipt
	return baseResult, nil
}

// classifyOSCTerminalOutcome enforces structured OSC 7501 / core state
// precedence. Launch-boundary failures (ExitedBeforeReport / !Reported) are
// always classified as DiagnosticCauseProviderSpawnFailed independent of exit
// code (10 vs 125 vs 0) and never let screen tokens override them.
func classifyOSCTerminalOutcome(
	family string,
	termObs ports.TerminalExecutionObservation,
	procObs ports.ProcessObservation,
) *terminalDriverFailure {
	if termObs.ExitedBeforeReport() || !termObs.Reported() {
		status := ports.ProviderExecutionStatusUnavailable
		diagnostic := "provider_spawn_failed"
		if procObs.Termination() == ports.ProcessTerminationSignaled && !procObs.TerminalSessionCompleted() {
			status = ports.ProviderExecutionStatusInternalFailure
			diagnostic = "process_internal"
		}
		return newTerminalDriverFailure(
			status,
			diagnostic,
			domain.DiagnosticCauseProviderSpawnFailed,
			"",
			fmt.Errorf("terminal provider exited before reporting readiness"),
		)
	}
	if procObs.Termination() == ports.ProcessTerminationSignaled && !procObs.TerminalSessionCompleted() {
		return newTerminalDriverFailure(
			ports.ProviderExecutionStatusInternalFailure,
			"process_internal",
			domain.DiagnosticCauseProviderExecutionFailed,
			"",
			fmt.Errorf("terminal provider terminated by unsolicited signal"),
		)
	}
	status, _ := termObs.ProgramStatus()
	blockedKind, _ := termObs.BlockedKind()
	switch status {
	case ports.TerminalProgramStatusBlocked:
		switch blockedKind {
		case ports.TerminalBlockedKindAuth:
			return newTerminalDriverFailure(
				ports.ProviderExecutionStatusAuthentication,
				"login_required",
				domain.DiagnosticCauseLoginRequired,
				"",
				fmt.Errorf("terminal provider blocked on authentication: %w", ports.ErrProviderLoginRequired),
			)
		case ports.TerminalBlockedKindQuota:
			return newTerminalDriverFailure(
				ports.ProviderExecutionStatusQuota,
				"provider_quota",
				domain.DiagnosticCauseQuotaExceeded,
				"",
				fmt.Errorf("terminal provider blocked on quota"),
			)
		case ports.TerminalBlockedKindRateLimit:
			return newTerminalDriverFailure(
				ports.ProviderExecutionStatusRateLimit,
				"provider_rate_limit",
				domain.DiagnosticCauseRateLimited,
				"",
				fmt.Errorf("terminal provider blocked on rate limit"),
			)
		case ports.TerminalBlockedKindPermission:
			return newTerminalDriverFailure(
				ports.ProviderExecutionStatusAuthentication,
				"provider_permission_denied",
				domain.DiagnosticCausePermissionDenied,
				"",
				fmt.Errorf("terminal provider blocked on permission"),
			)
		default:
			return newTerminalDriverFailure(
				ports.ProviderExecutionStatusUnavailable,
				"provider_execution_failed",
				domain.DiagnosticCauseProviderExecutionFailed,
				"",
				fmt.Errorf("terminal provider blocked (%s)", blockedKind),
			)
		}
	case ports.TerminalProgramStatusError:
		// Only on structured core status == error may bounded post-kill screen
		// capture refine into a native auth/quota/rate-limit/timeout taxonomy.
		screen := termObs.ScreenCapture()
		if len(screen) == 0 {
			screen = procObs.Stdout()
		}
		if nativeStatus, nativeDiag, nativeCause, known := nativeProviderOutcome(family, nil, screen); known {
			var causeErr error
			if nativeCause == domain.DiagnosticCauseLoginRequired {
				causeErr = fmt.Errorf("terminal provider error: %w", ports.ErrProviderLoginRequired)
			} else {
				causeErr = fmt.Errorf("terminal provider error (%s)", nativeCause)
			}
			return newTerminalDriverFailure(nativeStatus, nativeDiag, nativeCause, "", causeErr)
		}
		return newTerminalDriverFailure(
			ports.ProviderExecutionStatusUnavailable,
			"provider_execution_failed",
			domain.DiagnosticCauseProviderExecutionFailed,
			"",
			fmt.Errorf("terminal provider reported error status"),
		)
	case ports.TerminalProgramStatusWorking:
		return newTerminalDriverFailure(
			ports.ProviderExecutionStatusUnavailable,
			"provider_turn_failed",
			domain.DiagnosticCauseProviderTurnFailed,
			"",
			fmt.Errorf("terminal provider terminated while still working"),
		)
	case ports.TerminalProgramStatusDone, ports.TerminalProgramStatusIdle:
		if termObs.TurnCount() < 1 {
			return newTerminalDriverFailure(
				ports.ProviderExecutionStatusUnavailable,
				"provider_turn_failed",
				domain.DiagnosticCauseProviderTurnFailed,
				"",
				fmt.Errorf("terminal provider terminated without completing a turn"),
			)
		}
		if !procObs.TerminalSessionCompleted() {
			return newTerminalDriverFailure(
				ports.ProviderExecutionStatusUnavailable,
				"provider_execution_failed",
				domain.DiagnosticCauseProviderExecutionFailed,
				"",
				fmt.Errorf("terminal provider did not complete session teardown"),
			)
		}
		return nil
	default:
		return newTerminalDriverFailure(
			ports.ProviderExecutionStatusUnavailable,
			"provider_execution_failed",
			domain.DiagnosticCauseProviderExecutionFailed,
			"",
			fmt.Errorf("terminal provider reported unknown status %q", status),
		)
	}
}
