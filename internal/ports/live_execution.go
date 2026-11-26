package ports

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"
)

const defaultBashGateMDNSResponderSocket = "/private/var/run/mDNSResponder"

// LiveReadOnlyBoundary carries trusted directory roots for the platform launch
// guard. Filesystem admission remains the process adapter's responsibility.
type LiveReadOnlyBoundary struct {
	managedNamespaces          AnchoredRoot
	managedRuntimeTempParent   AnchoredRoot
	readOnly                   []AnchoredRoot
	credentials                []AnchoredRoot
	controlPlaneRoots          []AnchoredRoot
	controlPlaneLiterals       []AnchoredRoot
	terminalSecretRoots        []AnchoredRoot
	terminalDeniedLiterals     []AnchoredRoot
	writable                   AnchoredRoot
	runtimeTemp                AnchoredRoot
	ownedPTY                   bool
	paneTTY                    bool
	bashGate                   bool
	bashGateAllowedUnixSockets []AnchoredRoot
	present                    bool
}

// NewLiveReadOnlyBoundaryWithManagedNamespaces protects all managed provider
// namespaces except the writable namespace owned by this pane.
func NewLiveReadOnlyBoundaryWithManagedNamespaces(boundary LiveReadOnlyBoundary, parent AnchoredRoot) (LiveReadOnlyBoundary, error) {
	boundary.managedNamespaces = parent
	if !parent.Valid() || !boundary.Valid() {
		return LiveReadOnlyBoundary{}, fmt.Errorf("live read-only boundary: invalid managed namespace parent")
	}
	return boundary, nil
}

func (boundary LiveReadOnlyBoundary) ManagedNamespaceRoot() (AnchoredRoot, bool) {
	return boundary.managedNamespaces, boundary.managedNamespaces.Valid()
}

// NewLiveReadOnlyBoundaryWithManagedRuntimeTemps prevents peer panes from
// reading or connecting to isolated temporary state under the managed parent.
func NewLiveReadOnlyBoundaryWithManagedRuntimeTemps(boundary LiveReadOnlyBoundary, parent AnchoredRoot) (LiveReadOnlyBoundary, error) {
	boundary.managedRuntimeTempParent = parent
	if !parent.Valid() || !boundary.Valid() {
		return LiveReadOnlyBoundary{}, fmt.Errorf("live read-only boundary: invalid managed runtime temp parent")
	}
	return boundary, nil
}

func (boundary LiveReadOnlyBoundary) ManagedRuntimeTempParent() (AnchoredRoot, bool) {
	return boundary.managedRuntimeTempParent, boundary.managedRuntimeTempParent.Valid()
}

// NewLiveReadOnlyBoundaryWithRuntimeTemp adds the existing trusted native
// runtime directory. Explicit protected roots remain denied even on overlap.
func NewLiveReadOnlyBoundaryWithRuntimeTemp(readOnly, credentials []AnchoredRoot, writable, runtimeTemp AnchoredRoot) (LiveReadOnlyBoundary, error) {
	boundary, err := NewLiveReadOnlyBoundary(readOnly, credentials, writable)
	if err != nil {
		return LiveReadOnlyBoundary{}, err
	}
	if !validLivePolicyRoot(runtimeTemp) {
		return LiveReadOnlyBoundary{}, fmt.Errorf("live read-only boundary: invalid runtime directory")
	}
	boundary.runtimeTemp = runtimeTemp
	return boundary, nil
}

func NewLiveReadOnlyBoundary(readOnly, credentials []AnchoredRoot, writable AnchoredRoot) (LiveReadOnlyBoundary, error) {
	boundary := LiveReadOnlyBoundary{
		readOnly:    append([]AnchoredRoot(nil), readOnly...),
		credentials: append([]AnchoredRoot(nil), credentials...),
		writable:    writable,
		present:     true,
	}
	if !boundary.Valid() {
		return LiveReadOnlyBoundary{}, fmt.Errorf("live read-only boundary: invalid protected roots")
	}
	return boundary, nil
}

// NewLiveReadOnlyBoundaryWithOwnedPTY adds the narrowly scoped owned-terminal
// capability to an already valid boundary, with or without a runtime
// directory. The capability admits only the master device and slaves the
// kernel binds to this process through the com.apple.sandbox.pty extension;
// every protected root, hardlink, and ancestor guarantee is unchanged. The
// default constructors never grant it. It composes with PaneTTY when needed.
func NewLiveReadOnlyBoundaryWithOwnedPTY(boundary LiveReadOnlyBoundary) (LiveReadOnlyBoundary, error) {
	if !boundary.Valid() {
		return LiveReadOnlyBoundary{}, fmt.Errorf("live read-only boundary: invalid protected roots")
	}
	boundary = cloneLiveReadOnlyBoundary(boundary)
	boundary.ownedPTY = true
	return boundary, nil
}

// NewLiveReadOnlyBoundaryWithControlPlane layers missing-tolerant control-plane
// roots (subpath denies) and literal control-plane paths (for example an
// inherited HC_SOCKET whose parent is a shared directory) onto a valid
// boundary. Control-plane entries are excluded from hardlink walks so missing
// or live operator control-plane trees never break launches.
func NewLiveReadOnlyBoundaryWithControlPlane(boundary LiveReadOnlyBoundary, roots, literals []AnchoredRoot) (LiveReadOnlyBoundary, error) {
	if !boundary.Valid() {
		return LiveReadOnlyBoundary{}, fmt.Errorf("live read-only boundary: invalid protected roots")
	}
	next := cloneLiveReadOnlyBoundary(boundary)
	var err error
	if next.controlPlaneRoots, err = appendUniqueLivePolicyRoots(next.controlPlaneRoots, roots); err != nil {
		return LiveReadOnlyBoundary{}, fmt.Errorf("live read-only boundary: invalid control-plane root")
	}
	if next.controlPlaneLiterals, err = appendUniqueLivePolicyRoots(next.controlPlaneLiterals, literals); err != nil {
		return LiveReadOnlyBoundary{}, fmt.Errorf("live read-only boundary: invalid control-plane literal")
	}
	if !next.Valid() {
		return LiveReadOnlyBoundary{}, fmt.Errorf("live read-only boundary: invalid control-plane boundary")
	}
	return next, nil
}

// DefaultControlPlaneRoots builds the canonical missing-tolerant herdr-core
// control-plane root list for nativeHome and uid, plus any optional dedicated
// roots (such as a session directory under /private/tmp/mgh-<uid>/<16hex>).
func DefaultControlPlaneRoots(nativeHome AnchoredRoot, uid uint32, extraRoots ...AnchoredRoot) ([]AnchoredRoot, error) {
	if !validLivePolicyRoot(nativeHome) {
		return nil, fmt.Errorf("control-plane roots: invalid native home")
	}
	raw := []string{
		fmt.Sprintf("/private/tmp/mgh-%d", uid),
		filepath.Join(nativeHome.String(), ".local", "state", "herdr-core"),
		filepath.Join(nativeHome.String(), ".config", "herdr-core"),
	}
	roots := make([]AnchoredRoot, 0, len(raw)+len(extraRoots))
	for _, path := range raw {
		root, err := NewAnchoredRoot(path)
		if err != nil || !validLivePolicyRoot(root) {
			return nil, fmt.Errorf("control-plane roots: invalid root %q", path)
		}
		roots = append(roots, root)
	}
	roots, err := appendUniqueLivePolicyRoots(roots, extraRoots)
	if err != nil {
		return nil, fmt.Errorf("control-plane roots: invalid extra root")
	}
	return roots, nil
}

// ControlPlanePathsForSocket classifies an inherited Unix control socket path
// (such as HC_SOCKET) into literal and optional dedicated-parent subpath
// denials. Shared roots such as /private/tmp, /tmp, /private/var/run,
// /private/var/folders/*/*/*, or nativeHome itself are never emitted as parent
// subpath denials. nativeHome must be a valid live policy root so shared
// user-home directories are never misclassified as dedicated.
func ControlPlanePathsForSocket(socketPath string, nativeHome AnchoredRoot) (roots []AnchoredRoot, literals []AnchoredRoot, err error) {
	if !validLivePolicyRoot(nativeHome) {
		return nil, nil, fmt.Errorf("control-plane socket: invalid native home")
	}
	literal, err := NewAnchoredRoot(socketPath)
	if err != nil || !validLivePolicyRoot(literal) {
		return nil, nil, fmt.Errorf("control-plane socket: invalid path")
	}
	literals = []AnchoredRoot{literal}
	parent := filepath.Dir(literal.String())
	if !isDedicatedControlPlaneParent(parent, nativeHome) {
		return nil, literals, nil
	}
	parentRoot, err := NewAnchoredRoot(parent)
	if err != nil || !validLivePolicyRoot(parentRoot) {
		return nil, literals, nil
	}
	return []AnchoredRoot{parentRoot}, literals, nil
}

func isDedicatedControlPlaneParent(parent string, nativeHome AnchoredRoot) bool {
	clean := filepath.Clean(parent)
	if clean == "/" || clean == "." {
		return false
	}
	switch clean {
	case "/tmp", "/private", "/private/tmp",
		"/var", "/private/var", "/var/tmp", "/private/var/tmp",
		"/var/run", "/private/var/run", "/var/folders", "/private/var/folders",
		"/Users", "/Volumes", "/System", "/Library", "/Applications", "/dev",
		"/usr", "/usr/local", "/opt", "/opt/homebrew", "/etc", "/private/etc":
		return false
	}
	// macOS per-user temporary roots (/private/var/folders/<bucket>/<hash>/{T,C,0}
	// and their ancestors) are shared across unrelated processes and must never
	// be subpath-denied.
	for _, prefix := range []string{"/private/var/folders/", "/var/folders/"} {
		if strings.HasPrefix(clean, prefix) {
			rel := strings.TrimPrefix(clean, prefix)
			if len(strings.Split(rel, "/")) <= 3 {
				return false
			}
		}
	}
	if nativeHome.Valid() {
		home := filepath.Clean(nativeHome.String())
		if clean == home || strings.HasPrefix(home, clean+"/") {
			return false
		}
		for _, shared := range []string{
			filepath.Join(home, ".config"),
			filepath.Join(home, ".cache"),
			filepath.Join(home, ".local"),
			filepath.Join(home, ".local", "state"),
			filepath.Join(home, ".local", "share"),
			filepath.Join(home, "Library"),
			filepath.Join(home, "Library", "Caches"),
			filepath.Join(home, "Library", "Application Support"),
		} {
			if clean == shared {
				return false
			}
		}
	}
	return true
}

var (
	terminalSecretRootRelatives = []string{
		".ssh",
		".gnupg",
		".aws",
		filepath.Join(".config", "gh"),
		".docker",
		".kube",
		".netrc",
		".git-credentials",
		".npmrc",
		".pypirc",
		filepath.Join("Library", "Keychains"),
		".claude",
		filepath.Join(".config", "herdr"),
		filepath.Join(".local", "state"),
	}
	terminalDeniedLiteralRelatives = []string{
		"AGENTS.md",
		"CLAUDE.md",
		".mcp.json",
	}
)

// NewLiveReadOnlyBoundaryWithPaneTTY enables parameterized exact-TTY isolation
// (-D PANE_TTY=<slave>) and anchors the terminal secret-root and ancestor-file
// denials to nativeHome. It composes with OwnedPTY, RuntimeTempRoot, and
// ControlPlaneRoots without affecting existing non-PaneTTY boundaries.
func NewLiveReadOnlyBoundaryWithPaneTTY(boundary LiveReadOnlyBoundary, nativeHome AnchoredRoot) (LiveReadOnlyBoundary, error) {
	if !boundary.Valid() {
		return LiveReadOnlyBoundary{}, fmt.Errorf("live read-only boundary: invalid protected roots")
	}
	if !validLivePolicyRoot(nativeHome) {
		return LiveReadOnlyBoundary{}, fmt.Errorf("live read-only boundary: invalid native home")
	}
	next := cloneLiveReadOnlyBoundary(boundary)
	secrets := make([]AnchoredRoot, 0, len(terminalSecretRootRelatives))
	for _, relative := range terminalSecretRootRelatives {
		root, err := NewAnchoredRoot(filepath.Join(nativeHome.String(), relative))
		if err != nil || !validLivePolicyRoot(root) {
			return LiveReadOnlyBoundary{}, fmt.Errorf("live read-only boundary: invalid terminal secret root")
		}
		secrets = append(secrets, root)
	}
	literals := make([]AnchoredRoot, 0, len(terminalDeniedLiteralRelatives))
	for _, relative := range terminalDeniedLiteralRelatives {
		root, err := NewAnchoredRoot(filepath.Join(nativeHome.String(), relative))
		if err != nil || !validLivePolicyRoot(root) {
			return LiveReadOnlyBoundary{}, fmt.Errorf("live read-only boundary: invalid terminal literal denial")
		}
		literals = append(literals, root)
	}
	next.paneTTY = true
	next.terminalSecretRoots = secrets
	next.terminalDeniedLiterals = literals
	if !next.Valid() {
		return LiveReadOnlyBoundary{}, fmt.Errorf("live read-only boundary: invalid pane TTY boundary")
	}
	return next, nil
}

// DefaultBashGateAllowedUnixSockets returns the narrow literal Unix sockets
// allowed when the PaneTTY B-1 Bash-gate default-deny Unix-socket rule is
// active.
func DefaultBashGateAllowedUnixSockets() []AnchoredRoot {
	root, err := NewAnchoredRoot(defaultBashGateMDNSResponderSocket)
	if err != nil {
		return nil
	}
	return []AnchoredRoot{root}
}

// NewLiveReadOnlyBoundaryWithBashGate enables the B-1 Seatbelt controls on a
// PaneTTY boundary: default-deny outbound Unix sockets (with narrow literal
// allows, defaulting to /private/var/run/mDNSResponder when omitted),
// localhost:* network denial, and high-risk local command process-exec denials.
func NewLiveReadOnlyBoundaryWithBashGate(boundary LiveReadOnlyBoundary, allowedUnixSockets ...AnchoredRoot) (LiveReadOnlyBoundary, error) {
	if !boundary.Valid() || !boundary.PaneTTY() {
		return LiveReadOnlyBoundary{}, fmt.Errorf("live read-only boundary: bash gate requires a valid pane TTY boundary")
	}
	next := cloneLiveReadOnlyBoundary(boundary)
	if len(allowedUnixSockets) == 0 {
		allowedUnixSockets = DefaultBashGateAllowedUnixSockets()
	}
	allowed, err := appendUniqueLivePolicyRoots(nil, allowedUnixSockets)
	if err != nil {
		return LiveReadOnlyBoundary{}, fmt.Errorf("live read-only boundary: invalid bash-gate unix socket allowlist")
	}
	next.bashGate = true
	next.bashGateAllowedUnixSockets = allowed
	if !next.Valid() {
		return LiveReadOnlyBoundary{}, fmt.Errorf("live read-only boundary: invalid bash-gate boundary")
	}
	return next, nil
}

func (boundary LiveReadOnlyBoundary) Valid() bool {
	if !boundary.present || len(boundary.readOnly) == 0 || len(boundary.credentials) == 0 || !validLivePolicyRoot(boundary.writable) {
		return false
	}
	for _, roots := range [][]AnchoredRoot{
		boundary.readOnly,
		boundary.credentials,
		boundary.controlPlaneRoots,
		boundary.controlPlaneLiterals,
		boundary.terminalSecretRoots,
		boundary.terminalDeniedLiterals,
		boundary.bashGateAllowedUnixSockets,
	} {
		for _, root := range roots {
			if !validLivePolicyRoot(root) {
				return false
			}
		}
	}
	if boundary.runtimeTemp.Valid() && !validLivePolicyRoot(boundary.runtimeTemp) {
		return false
	}
	if parent := boundary.managedRuntimeTempParent; parent.Valid() {
		if !validLivePolicyRoot(parent) || boundary.runtimeTemp.Valid() && filepath.Dir(boundary.runtimeTemp.String()) != parent.String() {
			return false
		}
	}
	if parent := boundary.managedNamespaces; parent.Valid() {
		if !validLivePolicyRoot(parent) || !strings.HasPrefix(boundary.writable.String(), parent.String()+"/") {
			return false
		}
		for _, root := range boundary.readOnly {
			readOnly := root.String()
			if readOnly == parent.String() || strings.HasPrefix(parent.String(), readOnly+"/") ||
				strings.HasPrefix(readOnly, parent.String()+"/") && !strings.HasPrefix(readOnly, boundary.writable.String()+"/") {
				return false
			}
		}
	}
	if !boundary.paneTTY {
		if len(boundary.terminalSecretRoots) != 0 || len(boundary.terminalDeniedLiterals) != 0 ||
			boundary.bashGate || len(boundary.bashGateAllowedUnixSockets) != 0 {
			return false
		}
	} else if len(boundary.terminalSecretRoots) == 0 || len(boundary.terminalDeniedLiterals) == 0 {
		return false
	}
	if !boundary.bashGate && len(boundary.bashGateAllowedUnixSockets) != 0 {
		return false
	}
	return true
}

func cloneLiveReadOnlyBoundary(boundary LiveReadOnlyBoundary) LiveReadOnlyBoundary {
	boundary.readOnly = append([]AnchoredRoot(nil), boundary.readOnly...)
	boundary.credentials = append([]AnchoredRoot(nil), boundary.credentials...)
	boundary.controlPlaneRoots = append([]AnchoredRoot(nil), boundary.controlPlaneRoots...)
	boundary.controlPlaneLiterals = append([]AnchoredRoot(nil), boundary.controlPlaneLiterals...)
	boundary.terminalSecretRoots = append([]AnchoredRoot(nil), boundary.terminalSecretRoots...)
	boundary.terminalDeniedLiterals = append([]AnchoredRoot(nil), boundary.terminalDeniedLiterals...)
	boundary.bashGateAllowedUnixSockets = append([]AnchoredRoot(nil), boundary.bashGateAllowedUnixSockets...)
	return boundary
}

func appendUniqueLivePolicyRoots(existing, additions []AnchoredRoot) ([]AnchoredRoot, error) {
	seen := make(map[string]struct{}, len(existing)+len(additions))
	result := make([]AnchoredRoot, 0, len(existing)+len(additions))
	for _, root := range existing {
		if !validLivePolicyRoot(root) {
			return nil, fmt.Errorf("invalid policy root")
		}
		if _, exists := seen[root.String()]; exists {
			continue
		}
		seen[root.String()] = struct{}{}
		result = append(result, root)
	}
	for _, root := range additions {
		if !validLivePolicyRoot(root) {
			return nil, fmt.Errorf("invalid policy root")
		}
		if _, exists := seen[root.String()]; exists {
			continue
		}
		seen[root.String()] = struct{}{}
		result = append(result, root)
	}
	return result, nil
}

// Policy roots cross both Seatbelt and native provider configuration grammars.
// Go's escapes for non-printable characters do not name the same Seatbelt path.
// Reject them before any launch rather than silently weakening a denial.
func validLivePolicyRoot(root AnchoredRoot) bool {
	if !root.Valid() || root.String() == "/" || !utf8.ValidString(root.String()) {
		return false
	}
	for _, character := range root.String() {
		if !unicode.IsPrint(character) {
			return false
		}
	}
	return true
}

func (boundary LiveReadOnlyBoundary) ReadOnlyRoots() []AnchoredRoot {
	return append([]AnchoredRoot(nil), boundary.readOnly...)
}

func (boundary LiveReadOnlyBoundary) CredentialRoots() []AnchoredRoot {
	return append([]AnchoredRoot(nil), boundary.credentials...)
}

func (boundary LiveReadOnlyBoundary) ControlPlaneRoots() []AnchoredRoot {
	return append([]AnchoredRoot(nil), boundary.controlPlaneRoots...)
}

func (boundary LiveReadOnlyBoundary) ControlPlaneLiterals() []AnchoredRoot {
	return append([]AnchoredRoot(nil), boundary.controlPlaneLiterals...)
}

func (boundary LiveReadOnlyBoundary) TerminalSecretRoots() []AnchoredRoot {
	return append([]AnchoredRoot(nil), boundary.terminalSecretRoots...)
}

func (boundary LiveReadOnlyBoundary) TerminalDeniedLiterals() []AnchoredRoot {
	return append([]AnchoredRoot(nil), boundary.terminalDeniedLiterals...)
}

// WritableRoot is the caller-owned invocation namespace, never the source or
// neutral reviewer directory.
func (boundary LiveReadOnlyBoundary) WritableRoot() AnchoredRoot { return boundary.writable }

func (boundary LiveReadOnlyBoundary) RuntimeTempRoot() (AnchoredRoot, bool) {
	return boundary.runtimeTemp, boundary.runtimeTemp.Valid()
}

// OwnedPTY reports whether this boundary opts in to the owned-terminal
// capability. It stays false for every default-constructed boundary.
func (boundary LiveReadOnlyBoundary) OwnedPTY() bool {
	return boundary.present && boundary.ownedPTY
}

// PaneTTY reports whether this boundary opts in to exact controlling-PTY
// isolation via sandbox-exec -D PANE_TTY=<slave>.
func (boundary LiveReadOnlyBoundary) PaneTTY() bool {
	return boundary.present && boundary.paneTTY
}

// BashGate reports whether this PaneTTY boundary enables the B-1 Seatbelt
// controls (default-deny outbound Unix sockets with narrow allows, localhost
// TCP/UDP denial, and high-risk local command process-exec denials).
func (boundary LiveReadOnlyBoundary) BashGate() bool {
	return boundary.present && boundary.paneTTY && boundary.bashGate
}

// BashGateAllowedUnixSockets returns the narrow literal Unix sockets allowed
// when BashGate is enabled.
func (boundary LiveReadOnlyBoundary) BashGateAllowedUnixSockets() []AnchoredRoot {
	return append([]AnchoredRoot(nil), boundary.bashGateAllowedUnixSockets...)
}

// NewLiveReadOnlyProcessRequest preserves the provider executable and packet
// identity while requiring an additional platform guard at launch.
func NewLiveReadOnlyProcessRequest(request ProcessRequest, boundary LiveReadOnlyBoundary) (ProcessRequest, error) {
	if !request.Valid() || !boundary.Valid() || request.liveReadOnlyBoundary.present {
		return ProcessRequest{}, fmt.Errorf("live read-only process request: invalid request or boundary")
	}
	request.liveReadOnlyBoundary = boundary
	if err := validateProcessRequest(request); err != nil {
		return ProcessRequest{}, fmt.Errorf("live read-only process request: %w", err)
	}
	return request, nil
}

// WithProcessRequestControlPlane layers missing-tolerant control-plane roots
// and literal paths onto an already guarded ProcessRequest without mutating
// the original request or altering its executable, packet, or launch authority.
func WithProcessRequestControlPlane(request ProcessRequest, roots, literals []AnchoredRoot) (ProcessRequest, error) {
	if !request.Valid() || !request.liveReadOnlyBoundary.present {
		return ProcessRequest{}, fmt.Errorf("live read-only process request: control-plane overlay requires a guarded request")
	}
	updatedBoundary, err := NewLiveReadOnlyBoundaryWithControlPlane(request.liveReadOnlyBoundary, roots, literals)
	if err != nil {
		return ProcessRequest{}, fmt.Errorf("live read-only process request: %w", err)
	}
	request.liveReadOnlyBoundary = updatedBoundary
	if err := validateProcessRequest(request); err != nil {
		return ProcessRequest{}, fmt.Errorf("live read-only process request: %w", err)
	}
	return request, nil
}

func (request ProcessRequest) LiveReadOnlyBoundary() (LiveReadOnlyBoundary, bool) {
	return request.liveReadOnlyBoundary, request.liveReadOnlyBoundary.present
}

// NewNeutralBoundProcessRequest transfers the neutral reviewer directory's
// descriptor to the runner without inventing a source snapshot identity.
func NewNeutralBoundProcessRequest(request ProcessRequest, root AnchoredRoot, directory *os.File) (ProcessRequest, error) {
	if !request.Valid() || request.hasBoundLaunchDirectory || !root.Valid() || root.String() != request.WorkingDirectory() || directory == nil || directory.Fd() == ^uintptr(0) {
		return ProcessRequest{}, fmt.Errorf("neutral bound process request: invalid launch authority")
	}
	request.boundLaunchDirectory = directory
	request.boundNeutralRoot = root
	request.hasBoundLaunchDirectory = true
	if err := validateProcessRequest(request); err != nil {
		return ProcessRequest{}, err
	}
	return request, nil
}

// LaunchDirectory returns either a legacy captured directory or the new
// neutral directory. In both cases the runner consumes the descriptor.
func (request ProcessRequest) LaunchDirectory() (*os.File, AnchoredRoot, bool) {
	if !request.hasBoundLaunchDirectory {
		return nil, AnchoredRoot{}, false
	}
	if request.boundNeutralRoot.Valid() {
		return request.boundLaunchDirectory, request.boundNeutralRoot, true
	}
	root, _ := NewAnchoredRoot(request.boundWorkspaceRoot.Path())
	return request.boundLaunchDirectory, root, true
}
