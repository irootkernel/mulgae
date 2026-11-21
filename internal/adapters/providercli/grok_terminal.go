//go:build darwin && arm64

package providercli

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

const (
	grokTerminalStartupTimeout  = 45 * time.Second
	grokTerminalCheckInInterval = 15 * time.Second
	grokTerminalColumns         = 160
	grokTerminalRows            = 48

	grokToolsWorkspaceReview = "read_file,grep,list_dir,Write"
	grokToolsGitReview       = "read_file,grep,list_dir,Write,Bash"
	grokToolsPromptBound     = "read_file,Write"
)

// grokMinimalDisposableRequirementsTOML is written inside disposable GROK_HOME
// (<namespace>/home/.grok/requirements.toml) before each Grok launch. It
// disables external hooks, MCP servers, rules, skills, plugins, managed
// configs, and ambient repo status without embedding any native-home path or
// sandbox.toml file.
const grokMinimalDisposableRequirementsTOML = `fail_closed = true
allow_managed_mcp_servers_only = true
enable_all_project_mcp_servers = false
allowed_mcp_servers = []
plugin_auto_update = false

[compat.claude]
agents = false
hooks = false
mcps = false
rules = false
skills = false

[compat.codex]
hooks = false
skills = false

[compat.cursor]
agents = false
hooks = false
mcps = false
rules = false
skills = false

[features]
campaigns = false
codebase_indexing = false
managed_config = false
mcp_auto_restart = false
mcp_liveness_watchers = false
mcp_recursive_config_watch = false
repo_status_in_system_prompt = false

[paths]
extra_rule_dirs = []
extra_skill_dirs = []

[plugins]
enabled = []
paths = []
`

type grokTerminalProfile struct{}

func (grokTerminalProfile) Family() string { return FamilyGrok }

func (grokTerminalProfile) RequireOSCReporting() bool { return true }

func (grokTerminalProfile) RequireCompletionNonce(purpose terminalInvocationPurpose) bool {
	return purpose == terminalPurposeReview || purpose == terminalPurposeExtraction
}

func (grokTerminalProfile) OutputFilename(purpose terminalInvocationPurpose) string {
	switch purpose {
	case terminalPurposeExtraction:
		return stagedExtractionOutputFilename
	case terminalPurposeQualification:
		return stagedProbeOutputFilename
	default:
		return stagedOutputFilename
	}
}

func (grokTerminalProfile) StartupTimeout(terminalInvocationPurpose) time.Duration {
	return grokTerminalStartupTimeout
}

func (grokTerminalProfile) CheckInInterval(terminalInvocationPurpose) time.Duration {
	return grokTerminalCheckInInterval
}

func (grokTerminalProfile) TerminalSize() (int, int) {
	return grokTerminalColumns, grokTerminalRows
}

func (grokTerminalProfile) PrepareDisposableHomes(inv terminalProfileInvocation) ([]ports.EnvironmentVariable, error) {
	if !validCanonicalAbsolute(inv.HomeDir) || inv.HomeDir == string(filepath.Separator) {
		return nil, fmt.Errorf("grok terminal: invalid disposable home")
	}
	homeFile, err := openAbsoluteDirectory(inv.HomeDir)
	if err != nil {
		return nil, fmt.Errorf("grok terminal: open disposable home: %w", err)
	}
	defer func() { _ = homeFile.Close() }()

	if err := unix.Mkdirat(int(homeFile.Fd()), ".grok", 0o700); err != nil && !errors.Is(err, unix.EEXIST) {
		return nil, fmt.Errorf("grok terminal: create disposable .grok: %w", err)
	}
	grokDir, err := openDirectoryAt(homeFile, ".grok")
	if err != nil {
		return nil, fmt.Errorf("grok terminal: open disposable .grok: %w", err)
	}
	defer func() { _ = grokDir.Close() }()

	var stat unix.Stat_t
	if err := unix.Fstat(int(grokDir.Fd()), &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR ||
		stat.Uid != uint32(unix.Geteuid()) || stat.Mode&0o077 != 0 {
		return nil, fmt.Errorf("grok terminal: unsafe disposable .grok directory")
	}

	if err := writeDisposableGrokRequirementsTOML(grokDir); err != nil {
		return nil, err
	}

	grokHome := filepath.Join(inv.HomeDir, ".grok")
	pairs := [][2]string{
		{"GROK_HOME", grokHome},
		{"PATH", "/usr/bin:/bin"},
		{"TERM", "xterm-256color"},
		{"COLORTERM", "truecolor"},
		{"TERM_PROGRAM", "ghostty"},
		{"LANG", "en_US.UTF-8"},
	}
	env := make([]ports.EnvironmentVariable, 0, len(pairs))
	for _, pair := range pairs {
		v, err := ports.NewEnvironmentVariable(pair[0], pair[1])
		if err != nil {
			return nil, fmt.Errorf("grok terminal: env %s: %w", pair[0], err)
		}
		env = append(env, v)
	}
	return env, nil
}

func writeDisposableGrokRequirementsTOML(grokDir *os.File) error {
	var token [12]byte
	if _, err := rand.Read(token[:]); err != nil {
		return fmt.Errorf("grok terminal: generate requirements temp token: %w", err)
	}
	tmpName := ".requirements-" + hex.EncodeToString(token[:]) + ".toml"
	dirFD := int(grokDir.Fd())
	fd, err := unix.Openat(dirFD, tmpName, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return fmt.Errorf("grok terminal: create requirements.toml candidate: %w", err)
	}
	tmpFile := os.NewFile(uintptr(fd), "grok-requirements-candidate")
	payload := []byte(grokMinimalDisposableRequirementsTOML)
	n, writeErr := tmpFile.Write(payload)
	syncErr := tmpFile.Sync()
	closeErr := tmpFile.Close()
	if err := errors.Join(writeErr, syncErr, closeErr); err != nil || n != len(payload) {
		_ = unix.Unlinkat(dirFD, tmpName, 0)
		return fmt.Errorf("grok terminal: write requirements.toml: %w", err)
	}
	// Reject an attacker-planted symlink or non-regular file at requirements.toml.
	var existing unix.Stat_t
	if err := unix.Fstatat(dirFD, "requirements.toml", &existing, unix.AT_SYMLINK_NOFOLLOW); err == nil {
		if existing.Mode&unix.S_IFMT != unix.S_IFREG || existing.Uid != uint32(unix.Geteuid()) {
			_ = unix.Unlinkat(dirFD, tmpName, 0)
			return fmt.Errorf("grok terminal: unsafe existing requirements.toml")
		}
	} else if !errors.Is(err, unix.ENOENT) {
		_ = unix.Unlinkat(dirFD, tmpName, 0)
		return fmt.Errorf("grok terminal: inspect requirements.toml: %w", err)
	}
	if err := unix.Renameat(dirFD, tmpName, dirFD, "requirements.toml"); err != nil {
		_ = unix.Unlinkat(dirFD, tmpName, 0)
		return fmt.Errorf("grok terminal: install requirements.toml: %w", err)
	}
	return nil
}

func grokReviewNeedsBashGate(scope domain.LiveSourceScope) bool {
	switch scope {
	case domain.LiveSourceStage, domain.LiveSourceHead, domain.LiveSourceCommit, domain.LiveSourceDiff:
		return true
	default:
		return false
	}
}

func grokTerminalTools(purpose terminalInvocationPurpose, liveScope domain.LiveSourceScope, hasLiveScope bool) string {
	switch purpose {
	case terminalPurposeReview:
		if hasLiveScope && grokReviewNeedsBashGate(liveScope) {
			return grokToolsGitReview
		}
		return grokToolsWorkspaceReview
	default:
		return grokToolsPromptBound
	}
}

func grokTerminalBaseArgv(definition RuntimeDefinition, purpose terminalInvocationPurpose, liveScope domain.LiveSourceScope, hasLiveScope bool) ([]string, error) {
	if !validCanonicalAbsolute(definition.Executable()) {
		return nil, fmt.Errorf("grok terminal: invalid executable")
	}
	if !validGrokSettings(definition.GrokModel(), definition.GrokReasoningEffort()) {
		return nil, errInvalidGrokSettings
	}
	argv := []string{
		definition.Executable(),
		"--no-auto-update",
		"--no-leader",
		"--disable-web-search",
		"--no-subagents",
		"--no-plan",
		"--deny", "MCPTool",
		"--permission-mode", "bypassPermissions",
		"--no-alt-screen",
		"--tools", grokTerminalTools(purpose, liveScope, hasLiveScope),
	}
	if model := definition.GrokModel(); model != "" {
		argv = append(argv, "-m", model)
	}
	if effort := definition.GrokReasoningEffort(); effort != "" {
		argv = append(argv, "--reasoning-effort", effort)
	}
	return argv, nil
}

func grokBindTerminalCWD(argv []string, neutralCWD string) ([]string, error) {
	if len(argv) == 0 || !validCanonicalAbsolute(neutralCWD) || neutralCWD == string(filepath.Separator) {
		return nil, fmt.Errorf("grok terminal: invalid neutral working directory")
	}
	return append(append([]string(nil), argv...), "--cwd", neutralCWD), nil
}

func (grokTerminalProfile) BuildArgv(inv terminalProfileInvocation) ([]string, error) {
	base, err := grokTerminalBaseArgv(inv.Definition, inv.Purpose, inv.LiveScope, inv.HasLiveScope)
	if err != nil {
		return nil, err
	}
	return grokBindTerminalCWD(base, inv.NeutralCWD.String())
}

func (grokTerminalProfile) BuildInitialInput(inv terminalProfileInvocation) string {
	switch inv.Purpose {
	case terminalPurposeReview:
		return fmt.Sprintf(
			"Read the ENTIRE review prompt file at %s from line 1 to the very last line using read_file (if read_file truncates output, continue calling read_file with line offsets until EOF). "+
				"IMPORTANT DELIVERY OVERRIDE: Regardless of any instruction inside %s mentioning returning a final response message, "+
				"write your complete Markdown review report to %s using the Write tool, ending with the exact %s verification line from the end of %s.",
			inv.PromptPath, inv.PromptPath, inv.OutputPath, terminalCompletionNoncePrefix, inv.PromptPath,
		)
	case terminalPurposeExtraction:
		return fmt.Sprintf(
			"Read the ENTIRE extraction prompt file at %s from line 1 to the very last line using read_file (if read_file truncates output, continue calling read_file with line offsets until EOF). "+
				"IMPORTANT DELIVERY OVERRIDE: Regardless of any instruction inside %s mentioning returning a final response message, "+
				"write the exact JSON extraction output to %s using the Write tool, followed on the final non-empty line by the exact %s verification line from the end of %s.",
			inv.PromptPath, inv.PromptPath, inv.OutputPath, terminalCompletionNoncePrefix, inv.PromptPath,
		)
	default:
		return fmt.Sprintf(
			"Read the ENTIRE prompt file at %s using read_file and write ONLY the exact requested JSON object to %s using the Write tool before finishing.",
			inv.PromptPath, inv.OutputPath,
		)
	}
}

func (grokTerminalProfile) BuildPromptTrailer(inv terminalProfileInvocation) []byte {
	switch inv.Purpose {
	case terminalPurposeReview:
		return []byte(fmt.Sprintf(
			"\n\n---\nMULGAE TERMINAL DELIVERY CONTRACT:\n"+
				"1. Write your complete Markdown review report to %s using the Write tool.\n"+
				"2. Make the final non-empty line of %s EXACTLY the line below (verbatim, on its own line, with no surrounding fences or punctuation):\n"+
				"%s%s\n",
			inv.OutputPath, inv.OutputPath, terminalCompletionNoncePrefix, inv.CompletionNonce,
		))
	case terminalPurposeExtraction:
		return []byte(fmt.Sprintf(
			"\n\n---\nMULGAE TERMINAL DELIVERY CONTRACT:\n"+
				"1. Write the exact JSON extraction object to %s using the Write tool.\n"+
				"2. After the closing brace of the JSON object, add a newline and make the final non-empty line of %s EXACTLY the line below (verbatim, on its own line, with no surrounding fences or punctuation):\n"+
				"%s%s\n",
			inv.OutputPath, inv.OutputPath, terminalCompletionNoncePrefix, inv.CompletionNonce,
		))
	default:
		return []byte(fmt.Sprintf(
			"\n\n---\nMULGAE TERMINAL DELIVERY CONTRACT:\n"+
				"Write ONLY the exact requested single JSON object (no Markdown fences, no narration, no extra text) to %s using the Write tool.\n",
			inv.OutputPath,
		))
	}
}

func (grokTerminalProfile) ConfigureBoundary(base ports.LiveReadOnlyBoundary, inv terminalProfileInvocation) (ports.LiveReadOnlyBoundary, error) {
	// Grok uses PaneTTY-only (never OwnedPTY).
	boundary, err := ports.NewLiveReadOnlyBoundaryWithPaneTTY(base, inv.NativeHome)
	if err != nil {
		return ports.LiveReadOnlyBoundary{}, err
	}
	if inv.Purpose == terminalPurposeReview && inv.HasLiveScope && grokReviewNeedsBashGate(inv.LiveScope) {
		boundary, err = ports.NewLiveReadOnlyBoundaryWithBashGate(boundary)
		if err != nil {
			return ports.LiveReadOnlyBoundary{}, err
		}
	}
	return boundary, nil
}

// openNeutralQualificationDirectory opens or creates <nativeHome>/.mulgae/home
// descriptor-anchored with owner-only permissions and returns its open launch
// directory descriptor and canonical path without creating or mutating AGENTS.md.
func openNeutralQualificationDirectory(nativeHome string) (*os.File, ports.AnchoredRoot, error) {
	if !validCanonicalAbsolute(nativeHome) || nativeHome == string(filepath.Separator) {
		return nil, ports.AnchoredRoot{}, fmt.Errorf("neutral qualification directory: invalid native home")
	}
	parent, err := openAbsoluteDirectory(nativeHome)
	if err != nil {
		return nil, ports.AnchoredRoot{}, fmt.Errorf("neutral qualification directory: open native home: %w", err)
	}
	var dirs []*os.File
	dirs = append(dirs, parent)
	closeAll := func() {
		for i := len(dirs) - 1; i >= 0; i-- {
			_ = dirs[i].Close()
		}
	}
	euid := uint32(unix.Geteuid())
	var homeStat unix.Stat_t
	if err := unix.Fstat(int(parent.Fd()), &homeStat); err != nil || homeStat.Uid != euid || homeStat.Mode&0o022 != 0 {
		closeAll()
		return nil, ports.AnchoredRoot{}, fmt.Errorf("neutral qualification directory: unsafe native home")
	}
	for _, component := range []string{".mulgae", "home"} {
		if err := unix.Mkdirat(int(parent.Fd()), component, 0o700); err != nil && !errors.Is(err, unix.EEXIST) {
			closeAll()
			return nil, ports.AnchoredRoot{}, fmt.Errorf("neutral qualification directory: create %s: %w", component, err)
		}
		next, err := openDirectoryAt(parent, component)
		if err != nil {
			closeAll()
			return nil, ports.AnchoredRoot{}, fmt.Errorf("neutral qualification directory: open %s: %w", component, err)
		}
		dirs = append(dirs, next)
		var stat unix.Stat_t
		if err := unix.Fstat(int(next.Fd()), &stat); err != nil || stat.Uid != euid || stat.Mode&0o022 != 0 {
			closeAll()
			return nil, ports.AnchoredRoot{}, fmt.Errorf("neutral qualification directory: unsafe %s permissions", component)
		}
		parent = next
	}
	canonicalPath, err := reviewerDescriptorPath(parent)
	if err != nil {
		closeAll()
		return nil, ports.AnchoredRoot{}, fmt.Errorf("neutral qualification directory: resolve path: %w", err)
	}
	anchored, err := ports.NewAnchoredRoot(canonicalPath)
	if err != nil {
		closeAll()
		return nil, ports.AnchoredRoot{}, fmt.Errorf("neutral qualification directory: anchor path: %w", err)
	}
	// Close intermediate parents; return only the leaf descriptor.
	for i := len(dirs) - 2; i >= 0; i-- {
		_ = dirs[i].Close()
	}
	return parent, anchored, nil
}

// defaultControlPlanePathsForHome builds the shared control-plane roots and
// literal denials for nativeHome (DefaultControlPlaneRoots plus any inherited
// HC_SOCKET / HC_TERMINAL_SOCKET paths). Malformed, relative, unclean, or
// whitespace-padded socket variables fail closed, and symlinked ancestor
// prefixes are expanded missing-tolerantly so both raw and canonical paths are
// denied even when the socket leaf does not yet exist.
func defaultControlPlanePathsForHome(nativeHome ports.AnchoredRoot) ([]ports.AnchoredRoot, []ports.AnchoredRoot, error) {
	if !nativeHome.Valid() {
		return nil, nil, fmt.Errorf("control-plane paths: invalid native home")
	}
	uid := uint32(unix.Geteuid())
	roots, err := ports.DefaultControlPlaneRoots(nativeHome, uid)
	if err != nil {
		return nil, nil, err
	}
	var resolvedExtras []ports.AnchoredRoot
	for _, root := range roots {
		resolved, resolveErr := resolveControlPlanePathMissingTolerant(root.String())
		if resolveErr != nil {
			return nil, nil, fmt.Errorf("control-plane paths: default root (%q): %w", root.String(), resolveErr)
		}
		if resolved != root.String() {
			resolvedRoot, rootErr := ports.NewAnchoredRoot(resolved)
			if rootErr != nil {
				return nil, nil, fmt.Errorf("control-plane paths: resolved default root (%q -> %q): %w", root.String(), resolved, rootErr)
			}
			resolvedExtras = append(resolvedExtras, resolvedRoot)
		}
	}
	if len(resolvedExtras) > 0 {
		roots, err = ports.DefaultControlPlaneRoots(nativeHome, uid, resolvedExtras...)
		if err != nil {
			return nil, nil, fmt.Errorf("control-plane paths: validate resolved default roots: %w", err)
		}
	}
	var literals []ports.AnchoredRoot
	for _, envName := range []string{"HC_SOCKET", "HC_TERMINAL_SOCKET"} {
		raw := os.Getenv(envName)
		if raw == "" {
			continue
		}
		if strings.TrimSpace(raw) != raw || !filepath.IsAbs(raw) || filepath.Clean(raw) != raw {
			return nil, nil, fmt.Errorf("control-plane paths: %s (%q) must be a clean absolute path without surrounding whitespace", envName, raw)
		}
		rawRoots, rawLiterals, rawErr := ports.ControlPlanePathsForSocket(raw, nativeHome)
		if rawErr != nil {
			return nil, nil, fmt.Errorf("control-plane paths: %s (%q): %w", envName, raw, rawErr)
		}
		roots = append(roots, rawRoots...)
		literals = append(literals, rawLiterals...)
		resolved, resolveErr := resolveControlPlanePathMissingTolerant(raw)
		if resolveErr != nil {
			return nil, nil, fmt.Errorf("control-plane paths: %s (%q): %w", envName, raw, resolveErr)
		}
		if resolved != raw {
			resolvedRoots, resolvedLiterals, resolvedErr := ports.ControlPlanePathsForSocket(resolved, nativeHome)
			if resolvedErr != nil {
				return nil, nil, fmt.Errorf("control-plane paths: %s (%q -> %q): %w", envName, raw, resolved, resolvedErr)
			}
			roots = append(roots, resolvedRoots...)
			literals = append(literals, resolvedLiterals...)
		}
	}
	return deduplicateAnchoredRoots(roots), deduplicateAnchoredRoots(literals), nil
}

const (
	maxControlPlanePathComponents = 128
	maxControlPlaneSymlinkHops    = 40
)

func resolveControlPlanePathMissingTolerant(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("path must be absolute")
	}
	current := "/"
	missingDepth := 0
	hops := 0
	queue := splitControlPlanePathComponents(path)
	if len(queue) > maxControlPlanePathComponents {
		return "", fmt.Errorf("resolved path exceeds component bound")
	}
	for len(queue) > 0 {
		seg := queue[0]
		queue = queue[1:]
		if seg == "" || seg == "." {
			continue
		}
		if seg == ".." {
			if current != "/" {
				current = filepath.Dir(current)
				if missingDepth > 0 {
					missingDepth--
				}
			}
			continue
		}
		next := filepath.Join(current, seg)
		if missingDepth > 0 {
			current = next
			missingDepth++
			continue
		}
		info, err := os.Lstat(next)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) || errors.Is(err, unix.ENOTDIR) {
				current = next
				missingDepth = 1
				continue
			}
			return "", err
		}
		if info.Mode()&os.ModeSymlink == 0 {
			current = next
			continue
		}
		hops++
		if hops > maxControlPlaneSymlinkHops {
			return "", fmt.Errorf("too many symlink hops")
		}
		target, err := os.Readlink(next)
		if err != nil {
			return "", err
		}
		if target == "" {
			return "", fmt.Errorf("empty symlink target")
		}
		if strings.HasPrefix(target, "/") {
			current = "/"
			missingDepth = 0
		}
		targetParts := splitControlPlanePathComponents(target)
		if len(targetParts)+len(queue) > maxControlPlanePathComponents {
			return "", fmt.Errorf("resolved path exceeds component bound")
		}
		newQueue := make([]string, 0, len(targetParts)+len(queue))
		newQueue = append(newQueue, targetParts...)
		newQueue = append(newQueue, queue...)
		queue = newQueue
	}
	return current, nil
}

func splitControlPlanePathComponents(path string) []string {
	raw := strings.Split(path, "/")
	out := make([]string, 0, len(raw))
	for _, part := range raw {
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func deduplicateAnchoredRoots(roots []ports.AnchoredRoot) []ports.AnchoredRoot {
	if len(roots) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(roots))
	result := make([]ports.AnchoredRoot, 0, len(roots))
	for _, root := range roots {
		if !root.Valid() {
			continue
		}
		if _, exists := seen[root.String()]; exists {
			continue
		}
		seen[root.String()] = struct{}{}
		result = append(result, root)
	}
	return result
}
