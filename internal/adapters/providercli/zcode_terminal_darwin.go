//go:build darwin && arm64

package providercli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/irootkernel/mulgae/internal/adapters/herdr"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
	"golang.org/x/sys/unix"
)

const zcodeCodingPlanProvider = "account:zai-individual-coding-plan"

type zcodeTerminalProfile struct {
	pkg       herdr.ZCodePackage
	desktop   herdr.ZCodeCompanionObservation
	appBundle string
	// The caller may require the exact previously qualified account/catalog.
	expected *ZCodeTerminalObservation
}

var (
	_ terminalProviderProfile   = zcodeTerminalProfile{}
	_ terminalHostPreparer      = zcodeTerminalProfile{}
	_ terminalFailureClassifier = zcodeTerminalProfile{}
)

func (zcodeTerminalProfile) Family() string                                        { return FamilyZcode }
func (zcodeTerminalProfile) RequireOSCReporting() bool                             { return true }
func (zcodeTerminalProfile) RequireCompletionNonce(terminalInvocationPurpose) bool { return true }
func (zcodeTerminalProfile) StartupTimeout(terminalInvocationPurpose) time.Duration {
	return 20 * time.Second
}
func (zcodeTerminalProfile) CheckInInterval(terminalInvocationPurpose) time.Duration {
	return 2 * time.Second
}
func (zcodeTerminalProfile) TerminalSize() (int, int) { return 120, 36 }

func (zcodeTerminalProfile) OutputFilename(purpose terminalInvocationPurpose) string {
	switch purpose {
	case terminalPurposeExtraction:
		return stagedExtractionOutputFilename
	case terminalPurposeQualification:
		return stagedProbeOutputFilename
	default:
		return stagedOutputFilename
	}
}

func (zcodeTerminalProfile) PrepareDisposableHomes(terminalProfileInvocation) ([]ports.EnvironmentVariable, error) {
	pairs := [][2]string{
		{"PATH", "/usr/bin:/bin"},
		{"TERM", "xterm-256color"},
		{"LANG", "en_US.UTF-8"},
		{"TMPDIR", zcodeRuntimeTempDirectory},
		{"TMP", zcodeRuntimeTempDirectory},
		{"TEMP", zcodeRuntimeTempDirectory},
	}
	env := make([]ports.EnvironmentVariable, 0, len(pairs))
	for _, pair := range pairs {
		variable, err := ports.NewEnvironmentVariable(pair[0], pair[1])
		if err != nil {
			return nil, err
		}
		env = append(env, variable)
	}
	return env, nil
}

func (zcodeTerminalProfile) BuildInitialInput(inv terminalProfileInvocation) string {
	return fmt.Sprintf("Use Read to read the entire prompt file at %s through EOF. Follow its delivery instructions and use Write to write the required output to %s.",
		inv.PromptPath, inv.OutputPath)
}

func (zcodeTerminalProfile) BuildPromptTrailer(inv terminalProfileInvocation) []byte {
	description := "the complete Markdown review report"
	if inv.Purpose != terminalPurposeReview {
		description = "the exact requested JSON object, or the refusal only where allowed by the prompt"
	}
	return fmt.Appendf(nil, "\n\n---\nMULGAE TERMINAL DELIVERY CONTRACT:\nWrite %s to %s with Write. After the output, the final non-empty line must be exactly:\n%s%s\n",
		description, inv.OutputPath, terminalCompletionNoncePrefix, inv.CompletionNonce)
}

func (zcodeTerminalProfile) ConfigureBoundary(base ports.LiveReadOnlyBoundary, inv terminalProfileInvocation) (ports.LiveReadOnlyBoundary, error) {
	boundary, err := ports.NewLiveReadOnlyBoundaryWithPaneTTY(base, inv.NativeHome)
	if err != nil {
		return ports.LiveReadOnlyBoundary{}, err
	}
	if inv.Purpose == terminalPurposeReview && inv.HasLiveScope && grokReviewNeedsBashGate(inv.LiveScope) {
		return ports.NewLiveReadOnlyBoundaryWithBashGate(boundary)
	}
	return boundary, nil
}

func (profile zcodeTerminalProfile) BuildArgv(inv terminalProfileInvocation) ([]string, error) {
	executable := inv.Definition.Executable()
	model, effort := inv.Definition.ZCodeModel(), inv.Definition.ZCodeReasoningEffort()
	if len(inv.HostArgs) == 0 || !validCanonicalAbsolute(executable) ||
		(profile.appBundle != "" && !validCanonicalAbsolute(profile.appBundle)) ||
		!validZCodeSettings(model, effort) {
		return nil, fmt.Errorf("zcode terminal: invalid launch arguments or missing host preparation")
	}
	argv := []string{
		executable,
		"--runtime", "core", "--non-interactive", "--interaction-policy", "block",
		"--cwd", inv.NeutralCWD.String(), "--mode", "yolo",
		"--skip-desktop-inspect", "--disable-mcp", "--disable-title-gen",
		"--disable-offpeak", "--disable-dynamic-workflow", "--persistence", "deferred",
	}
	if profile.appBundle != "" {
		argv = append(argv, "--app-bundle", profile.appBundle)
	}
	argv = append(argv, inv.HostArgs...)
	argv = append(argv, "--runtime-dir", filepath.Join(inv.NamespaceRoot, "tmp"))
	var allow, deny string
	switch {
	case inv.Purpose != terminalPurposeReview:
		allow, deny = "Read,Write", "Bash,Grep,Glob"
	case inv.HasLiveScope && grokReviewNeedsBashGate(inv.LiveScope):
		allow, deny = "Read,Bash,Write", "Grep,Glob"
	default:
		allow, deny = "Read,Grep,Glob,Write", "Bash"
	}
	argv = append(argv, "--tool-allowlist", allow, "--tool-denylist", deny+",Edit,Agent,TodoWrite,NotebookEdit,WebSearch,WebFetch,EnterPlanMode,ExitPlanMode")
	if inv.Purpose == terminalPurposeReview {
		argv = append(argv, "--additional-dir", inv.SourceRoot.String())
	}
	argv = append(argv, "--additional-dir", filepath.Dir(inv.PromptPath), "--additional-dir", filepath.Dir(inv.OutputPath))
	if model != "" {
		argv = append(argv, "--model", model)
	}
	if effort != "" {
		argv = append(argv, "--reasoning-effort", effort)
	}
	return argv, nil
}

// ZCodeTerminalObservation carries only the non-credential identity of one
// trusted host preparation. It is suitable for runtime and qualification proofs.
type ZCodeTerminalObservation struct {
	AppVersion            string `json:"appVersion"`
	CatalogRevision       int    `json:"catalogRevision"`
	CatalogSHA256         string `json:"catalogSHA256"`
	AccountIdentitySHA256 string `json:"accountIdentitySHA256"`
}

type zcodePreparationReceipt struct {
	ZCodeTerminalObservation
	AuthFile       string `json:"authFile"`
	CatalogFile    string `json:"catalogFile"`
	CatalogSource  string `json:"catalogSource"`
	MinimumVersion string `json:"minZcodeAppVersion"`
	ProviderID     string `json:"providerId"`
}

func (profile zcodeTerminalProfile) PrepareHost(ctx context.Context, inv *terminalProfileInvocation) (terminalHostPreparation, error) {
	if ctx == nil || inv == nil || inv.Namespace == nil || inv.Namespace.root != inv.NamespaceRoot || !inv.NativeHome.Valid() ||
		profile.pkg.Launcher.Path != inv.Definition.Executable() || profile.pkg.Launcher.SHA256 != inv.Definition.ExecutableSHA256() ||
		profile.desktop.AppVersion == "" || profile.desktop.MinimumVersion == "" || !validCanonicalAbsolute(profile.desktop.AppBundle) ||
		(profile.appBundle != "" && profile.appBundle != profile.desktop.AppBundle) {
		return terminalHostPreparation{}, zcodePreparationSecurityError("invalid host preparation authority")
	}
	lease := inv.Namespace
	runtimeTemp, err := lease.liveRuntimeTempRoot()
	if err != nil {
		return terminalHostPreparation{}, zcodePreparationSecurityError("runtime directory identity drift")
	}

	lease.terminalMu.Lock()
	defer lease.terminalMu.Unlock()
	if lease.cleanupStage != namespaceCleanupInitial || lease.drained {
		return terminalHostPreparation{}, zcodePreparationSecurityError("namespace is closing")
	}

	dir, err := retainZCodeProjectionDirectory(lease)
	if err != nil {
		return terminalHostPreparation{}, err
	}
	dirPath := dir.Name()
	if err := validateZCodeProjectionDirectory(dirPath, dir); err != nil {
		return terminalHostPreparation{}, err
	}

	output, runErr := profile.runPreparation(ctx, inv.NativeHome.String(), dirPath)
	defer zeroBytes(output)
	if runErr != nil {
		return terminalHostPreparation{}, runErr
	}
	if err := validateZCodeProjectionDirectory(dirPath, dir); err != nil {
		return terminalHostPreparation{}, err
	}
	receipt, err := profile.validatePreparationReceipt(output, dirPath)
	if err != nil {
		return terminalHostPreparation{}, err
	}
	authStat, catalogStat, err := validateZCodePreparedFiles(dir, receipt)
	if err != nil {
		return terminalHostPreparation{}, err
	}
	inv.HostArgs = []string{
		"--auth-file", receipt.AuthFile, "--consume-auth-file",
		"--catalog-file", receipt.CatalogFile, "--no-copy-catalog",
	}
	return terminalHostPreparation{
		runtimeTemp: runtimeTemp,
		verifySpawn: func() error {
			lease.terminalMu.Lock()
			defer lease.terminalMu.Unlock()
			if lease.cleanupStage != namespaceCleanupInitial || lease.drained {
				return zcodePreparationSecurityError("namespace is closing")
			}
			if err := profile.pkg.VerifySpawn(); err != nil {
				return zcodePreparationSecurityError("companion package drift")
			}
			if err := validateZCodeProjectionDirectory(dirPath, dir); err != nil {
				return err
			}
			nowAuth, nowCatalog, err := validateZCodePreparedFiles(dir, receipt)
			if err != nil {
				return err
			}
			if !sameZCodeOutputStat(authStat, nowAuth) || !sameZCodeOutputStat(catalogStat, nowCatalog) {
				return zcodePreparationSecurityError("prepared input changed before spawn")
			}
			currentTemp, err := lease.liveRuntimeTempRoot()
			if err != nil || currentTemp != runtimeTemp {
				return zcodePreparationSecurityError("runtime directory changed before spawn")
			}
			return nil
		},
	}, nil
}

// The caller owns the lease's terminal lock until preparation is settled.
func retainZCodeProjectionDirectory(lease *namespaceLease) (*os.File, error) {
	parent, _, err := lease.openCredentialParent("auth/auth.json")
	if err != nil {
		return nil, zcodePreparationSecurityError("invalid projection parent")
	}
	defer parent.Close()
	id, err := terminalRandomHex(12)
	if err != nil {
		return nil, err
	}
	name := "iso-" + id
	if err := unix.Mkdirat(int(parent.Fd()), name, 0o700); err != nil {
		return nil, fmt.Errorf("zcode terminal: create isolated projection directory")
	}
	fd, err := unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, zcodePreparationSecurityError("cannot retain isolated projection directory")
	}
	dir := os.NewFile(uintptr(fd), filepath.Join(lease.root, "auth", name))
	// Arm the drain before the child can create even a partial credential.
	lease.terminalCredentialCleanup = append(lease.terminalCredentialCleanup, func() error {
		return errors.Join(zcodeWipeProjectedAuth(dir), dir.Close())
	})
	return dir, nil
}

func validateZCodeProjectionDirectory(path string, dir *os.File) error {
	info, err := dir.Stat()
	entry, entryErr := os.Lstat(path)
	if err != nil || entryErr != nil || !info.IsDir() || info.Mode().Perm() != 0o700 ||
		!os.SameFile(info, entry) {
		return zcodePreparationSecurityError("isolated projection directory drift")
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); !ok || int(stat.Uid) != os.Geteuid() {
		return zcodePreparationSecurityError("isolated projection directory has wrong owner")
	}
	return nil
}

type zcodePreparationOutput struct {
	buffer   bytes.Buffer
	overflow bool
}

func (output *zcodePreparationOutput) Write(p []byte) (int, error) {
	const limit = 16 * 1024
	if output.buffer.Len()+len(p) > limit {
		output.overflow = true
		return len(p), nil
	}
	return output.buffer.Write(p)
}

func (profile zcodeTerminalProfile) runPreparation(ctx context.Context, home, dir string) ([]byte, error) {
	args := []string{"prepare-isolated", "--out-dir", dir, "--json"}
	if profile.appBundle != "" {
		args = append(args, "--app-bundle", profile.appBundle)
	}
	var output zcodePreparationOutput
	err := profile.pkg.RunOfflineCommand(ctx, 15*time.Second, home, &output, args...)
	data := output.buffer.Bytes()
	if errors.Is(err, herdr.ErrZCodeCompanionTeardown) {
		zeroBytes(data)
		return nil, providerRuntimeFailure(domain.DiagnosticCauseProcessGroupCleanupFailed, err)
	}
	if errors.Is(err, herdr.ErrUnsafeExecutable) {
		return nil, zcodePreparationSecurityError("companion package drift")
	}
	if output.overflow {
		zeroBytes(data)
		return nil, zcodePreparationSecurityError("oversized companion receipt")
	}
	if err == nil {
		return data, nil
	}
	defer zeroBytes(data)
	if errors.Is(err, herdr.ErrZCodeCompanionTimeout) {
		return nil, providerRuntimeFailure(domain.DiagnosticCauseTimedOut, err)
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return nil, err
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) && exit.ExitCode() == 1 {
		var failure struct {
			Reason  string `json:"reason"`
			Message string `json:"message"`
		}
		if decodeZCodePreparationJSON(data, &failure, "reason", "message") != nil || failure.Message == "" {
			return nil, zcodePreparationSecurityError("invalid companion failure receipt")
		}
		return nil, zcodePreparationFailure(failure.Reason)
	}
	return nil, providerRuntimeFailure(domain.DiagnosticCauseProviderSpawnFailed, fmt.Errorf("zcode terminal: companion preparation unavailable"))
}

func decodeZCodePreparationJSON(data []byte, dst any, fields ...string) error {
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return err
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(data, &object) != nil || len(object) != len(fields) {
		return fmt.Errorf("invalid preparation receipt object")
	}
	for _, field := range fields {
		value, present := object[field]
		if !present || bytes.Equal(value, []byte("null")) {
			return fmt.Errorf("invalid preparation receipt field")
		}
	}
	return json.Unmarshal(data, dst)
}

func (profile zcodeTerminalProfile) validatePreparationReceipt(data []byte, dir string) (zcodePreparationReceipt, error) {
	var receipt zcodePreparationReceipt
	if decodeZCodePreparationJSON(data, &receipt, "authFile", "catalogFile", "catalogRevision", "catalogSHA256",
		"catalogSource", "appVersion", "minZcodeAppVersion", "providerId", "accountIdentitySHA256") != nil ||
		receipt.AuthFile != filepath.Join(dir, "auth.json") || receipt.CatalogFile != filepath.Join(dir, "catalog.json") ||
		receipt.AppVersion != profile.desktop.AppVersion || receipt.MinimumVersion != profile.desktop.MinimumVersion ||
		receipt.ProviderID != zcodeCodingPlanProvider ||
		(receipt.CatalogSource != "desktop-cache" && receipt.CatalogSource != "bundled") ||
		!receipt.ZCodeTerminalObservation.valid() {
		return zcodePreparationReceipt{}, zcodePreparationSecurityError("invalid companion preparation receipt")
	}
	if profile.expected != nil && *profile.expected != receipt.ZCodeTerminalObservation {
		return zcodePreparationReceipt{}, zcodePreparationSecurityError("qualified desktop account or catalog identity drift")
	}
	return receipt, nil
}

func (observation ZCodeTerminalObservation) valid() bool {
	return observation.AppVersion != "" && observation.CatalogRevision > 0 &&
		validSHA256Identity("sha256:"+observation.CatalogSHA256) && validSHA256Identity("sha256:"+observation.AccountIdentitySHA256)
}

func zcodePreparationSecurityError(message string) error {
	return providerRuntimeFailure(domain.DiagnosticCauseProviderOwnershipViolation, fmt.Errorf("zcode terminal: %s", message))
}

func zcodePreparationFailure(reason string) error {
	switch reason {
	case "desktop_account_unavailable", "desktop_keychain_unavailable":
		return fmt.Errorf("zcode terminal preparation: %s: %w", reason, zcodeAccountConfigurationFailure())
	case "preparation_timeout":
		return providerRuntimeFailure(domain.DiagnosticCauseTimedOut, herdr.ErrZCodeCompanionTimeout)
	case "preparation_interrupted":
		return providerRuntimeFailure(domain.DiagnosticCauseProviderExecutionFailed, fmt.Errorf("companion reported preparation interrupted"))
	case "output_dir_invalid", "output_exists", "catalog_invalid", "projection_failed":
		return zcodePreparationSecurityError(reason)
	case "app_bundle_missing", "app_bundle_invalid", "app_version_below_minimum", "embedded_runtime_invalid", "invalid_arguments":
		return providerRuntimeFailure(domain.DiagnosticCauseProviderSpawnFailed, fmt.Errorf("zcode terminal preparation: %s", reason))
	default:
		return zcodePreparationSecurityError("unknown companion failure reason")
	}
}

func validateZCodePreparedFiles(dir *os.File, receipt zcodePreparationReceipt) (unix.Stat_t, unix.Stat_t, error) {
	var auth struct {
		ProviderID string `json:"providerId"`
		Identity   string `json:"identity"`
		Access     struct {
			Type        string `json:"type"`
			Mode        string `json:"mode"`
			AccountType string `json:"accountType"`
		} `json:"accountAccess"`
	}
	authBytes, authStat, err := readZCodePreparedFile(dir, "auth.json", 0o600, 64<<10)
	defer zeroBytes(authBytes)
	if err != nil {
		return unix.Stat_t{}, unix.Stat_t{}, err
	}
	if rejectDuplicateJSONKeys(authBytes) != nil || json.Unmarshal(authBytes, &auth) != nil ||
		auth.ProviderID != receipt.ProviderID || auth.Access.Type != "zhipu-account" ||
		auth.Access.Mode != "individual-coding-plan" || auth.Access.AccountType != "zai" ||
		strings.TrimSpace(auth.Identity) == "" {
		return unix.Stat_t{}, unix.Stat_t{}, zcodePreparationSecurityError("invalid projected account binding")
	}
	identity := sha256.Sum256([]byte(auth.Identity))
	if hex.EncodeToString(identity[:]) != receipt.AccountIdentitySHA256 {
		return unix.Stat_t{}, unix.Stat_t{}, zcodePreparationSecurityError("projected account identity mismatch")
	}
	catalog, catalogStat, err := readZCodePreparedFile(dir, "catalog.json", 0o400, 4<<20)
	if err != nil {
		return unix.Stat_t{}, unix.Stat_t{}, err
	}
	sum := sha256.Sum256(catalog)
	var catalogIdentity struct {
		Revision int `json:"revision"`
	}
	if hex.EncodeToString(sum[:]) != receipt.CatalogSHA256 ||
		rejectDuplicateJSONKeys(catalog) != nil || json.Unmarshal(catalog, &catalogIdentity) != nil ||
		catalogIdentity.Revision != receipt.CatalogRevision {
		return unix.Stat_t{}, unix.Stat_t{}, zcodePreparationSecurityError("projected catalog identity mismatch")
	}
	return authStat, catalogStat, nil
}

func readZCodePreparedFile(dir *os.File, name string, mode uint16, maxSize int64) ([]byte, unix.Stat_t, error) {
	fd, err := unix.Openat(int(dir.Fd()), name, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, unix.Stat_t{}, zcodePreparationSecurityError("cannot open prepared input")
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	var before, after unix.Stat_t
	if unix.Fstat(fd, &before) != nil || before.Mode != unix.S_IFREG|mode ||
		before.Nlink != 1 || int(before.Uid) != os.Geteuid() || before.Size <= 0 || before.Size > maxSize {
		return nil, unix.Stat_t{}, zcodePreparationSecurityError("unsafe prepared input identity")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxSize+1))
	if err != nil || int64(len(data)) != before.Size || unix.Fstat(fd, &after) != nil || !sameZCodeOutputStat(before, after) {
		zeroBytes(data)
		return nil, unix.Stat_t{}, zcodePreparationSecurityError("prepared input changed while reading")
	}
	return data, after, nil
}

func sameZCodeOutputStat(before, after unix.Stat_t) bool {
	return sameCredentialStat(before, after) && before.Mode == after.Mode && before.Size == after.Size &&
		before.Nlink == after.Nlink && before.Uid == after.Uid && before.Mtim == after.Mtim && before.Ctim == after.Ctim
}

func zcodeWipeProjectedAuth(dir *os.File) error {
	const name = "auth.json"
	dirFD := int(dir.Fd())
	fd, err := unix.Openat(dirFD, name, unix.O_RDWR|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil // Already consumed by the companion.
	}
	if err != nil {
		return zcodePreparationSecurityError("cannot open projected credential for drain")
	}
	file := os.NewFile(uintptr(fd), "projected credential")
	defer file.Close()
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG ||
		stat.Nlink != 1 || int(stat.Uid) != os.Geteuid() {
		return zcodePreparationSecurityError("refusing to overwrite unsafe projected credential")
	}
	if err := zeroCredentialFile(file, stat.Size); err != nil {
		return zcodePreparationSecurityError("could not zero projected credential")
	}
	entry, err := credentialEntryStat(dir, name)
	if err != nil || !sameCredentialStat(stat, entry) || entry.Nlink != 1 {
		return zcodePreparationSecurityError("projected credential changed before drain unlink")
	}
	if err := unix.Unlinkat(dirFD, name, 0); err != nil {
		return zcodePreparationSecurityError("could not unlink projected credential")
	}
	return dir.Sync()
}

func (zcodeTerminalProfile) ClassifyFailure(term ports.TerminalExecutionObservation, proc ports.ProcessObservation) *terminalDriverFailure {
	if !proc.ProcessGroupAbsent() {
		return nil
	}
	if proc.Termination() == ports.ProcessTerminationSignaled && !proc.TerminalSessionCompleted() {
		return nil
	}
	status, _ := term.ProgramStatus()
	blocked, _ := term.BlockedKind()
	exit, exited := proc.ExitCode()
	preReportFailure := !term.Reported() && proc.Termination() == ports.ProcessTerminationExited && exited && exit != 0
	if !preReportFailure && status != ports.TerminalProgramStatusError &&
		!(status == ports.TerminalProgramStatusBlocked && blocked == ports.TerminalBlockedKindAuth) {
		return nil
	}
	diagnostic := term.ScreenCapture()
	if len(diagnostic) == 0 {
		diagnostic = proc.Stderr()
		if len(diagnostic) == 0 {
			diagnostic = proc.Stdout()
		}
	}
	const maxDiagnostic = 16 * 1024
	diagnostic = diagnostic[max(0, len(diagnostic)-maxDiagnostic):]
	failure := zcodeTerminalConfigurationFailure(status, blocked, diagnostic)
	if failure != nil {
		var typed *domain.Failure
		if errors.As(failure, &typed) {
			return newTerminalDriverFailure(ports.ProviderExecutionStatusConfigurationViolation, typed.Stage(),
				domain.DiagnosticCauseObservationInvalid, "", failure)
		}
	}
	return nil
}

func zcodeTerminalConfigurationFailure(status ports.TerminalProgramStatus, blocked ports.TerminalBlockedKind, screen []byte) error {
	for _, line := range strings.Split(string(screen), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "Requested model is absent from the "),
			line == "Selected model unavailable",
			line == "Selected model was not applied",
			line == "Selected model changed while applying reasoning",
			line == "Selected model changed before subscription",
			line == "Selected reasoning level was not applied":
			return zcodeModelSelectionFailure()
		}
	}
	if status == ports.TerminalProgramStatusBlocked && blocked == ports.TerminalBlockedKindAuth {
		return zcodeAccountConfigurationFailure()
	}
	return nil
}

// RuntimeSafetyPolicyForZCodeTerminal binds the exact verified terminal,
// companion, and prepared desktop account/catalog without retaining credentials.
func RuntimeSafetyPolicyForZCodeTerminal(
	runtime ports.TerminalRuntimeIdentity,
	pkg herdr.ZCodePackage,
	appBundle string,
	prepared ZCodeTerminalObservation,
	model string,
	effort string,
) (RuntimeSafetyPolicy, error) {
	if !runtime.Valid() || !validCanonicalAbsolute(pkg.Launcher.Path) ||
		!validSHA256Identity(pkg.Launcher.SHA256) || !validSHA256Identity("sha256:"+pkg.PackageSHA256) ||
		pkg.Inode() == 0 || !prepared.valid() ||
		(appBundle != "" && !validCanonicalAbsolute(appBundle)) || !validZCodeSettings(model, effort) {
		return RuntimeSafetyPolicy{}, fmt.Errorf("runtime safety policy: invalid ZCode terminal identity")
	}
	payload, err := json.Marshal(struct {
		Family                 string                   `json:"family"`
		Transport              string                   `json:"transport"`
		Terminal               string                   `json:"terminal"`
		TerminalSHA256         string                   `json:"terminal_sha256"`
		TerminalVersion        string                   `json:"terminal_version"`
		Companion              string                   `json:"companion"`
		CompanionDevice        int32                    `json:"companion_device"`
		CompanionInode         uint64                   `json:"companion_inode"`
		CompanionPackageSHA256 string                   `json:"companion_package_sha256"`
		AppBundle              string                   `json:"app_bundle"`
		Prepared               ZCodeTerminalObservation `json:"prepared"`
		Model                  string                   `json:"model"`
		ReasoningEffort        string                   `json:"reasoning_effort"`
	}{
		Family: FamilyZcode, Transport: "isolated-zcode-terminal-v1",
		Terminal: runtime.Executable(), TerminalSHA256: runtime.ExecutableSHA256(), TerminalVersion: runtime.Version(),
		Companion: pkg.Launcher.Path, CompanionDevice: pkg.Device(), CompanionInode: pkg.Inode(),
		CompanionPackageSHA256: pkg.PackageSHA256, AppBundle: appBundle, Prepared: prepared,
		Model: model, ReasoningEffort: effort,
	})
	if err != nil {
		return RuntimeSafetyPolicy{}, fmt.Errorf("runtime safety policy: encode ZCode terminal policy: %w", err)
	}
	return runtimeSafetyPolicyWithIdentity(RuntimeSafetyPolicy{
		family: CredentialSourceZCode,
		bytes:  append(payload, '\n'),
	}), nil
}
