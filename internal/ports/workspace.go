package ports

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"os"
	"sort"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/irootkernel/mulgae/internal/domain"
)

// WorkspaceSnapshotManifestName is the generated provider-visible manifest
// added beside captured source files in every materialized review snapshot.
const WorkspaceSnapshotManifestName = "._mulgae_workspace_manifest.json"

// WorkspaceSnapshotFile is a captured regular UTF-8 file. Its bytes are copied
// at construction and when returned so callers cannot alter the request later.
type WorkspaceSnapshotFile struct {
	path      SafeRelativePath
	bytes     []byte
	sha256    string
	mediaType string
}

// NewWorkspaceSnapshotFile validates a captured file and its expected identity.
func NewWorkspaceSnapshotFile(path SafeRelativePath, bytes []byte, expectedSHA256 string) (WorkspaceSnapshotFile, error) {
	if !path.Valid() || workspaceReservedPath(path.String()) || !utf8.Valid(bytes) || strings.IndexByte(string(bytes), 0) >= 0 {
		return WorkspaceSnapshotFile{}, fmt.Errorf("workspace snapshot file: path and bytes must be canonical UTF-8 without NUL")
	}
	if !workspaceSHA256(expectedSHA256) {
		return WorkspaceSnapshotFile{}, fmt.Errorf("workspace snapshot file: invalid SHA-256 identity")
	}
	actual := sha256.Sum256(bytes)
	if expectedSHA256 != "sha256:"+hex.EncodeToString(actual[:]) {
		return WorkspaceSnapshotFile{}, fmt.Errorf("workspace snapshot file: expected SHA-256 does not match bytes")
	}
	return WorkspaceSnapshotFile{path: path, bytes: append([]byte(nil), bytes...), sha256: expectedSHA256, mediaType: "text/plain"}, nil
}

// NewWorkspaceVisualAsset validates a bounded raster design reference. Visual
// assets are materialized for UI review but are never passed through text or
// line-evidence readers.
func NewWorkspaceVisualAsset(path SafeRelativePath, bytes []byte, expectedSHA256, mediaType string) (WorkspaceSnapshotFile, error) {
	if !path.Valid() || workspaceReservedPath(path.String()) || !validRasterBytes(bytes, mediaType) {
		return WorkspaceSnapshotFile{}, fmt.Errorf("workspace visual asset: invalid path, media type, or raster bytes")
	}
	if !workspaceSHA256(expectedSHA256) {
		return WorkspaceSnapshotFile{}, fmt.Errorf("workspace visual asset: invalid SHA-256 identity")
	}
	actual := sha256.Sum256(bytes)
	if expectedSHA256 != "sha256:"+hex.EncodeToString(actual[:]) {
		return WorkspaceSnapshotFile{}, fmt.Errorf("workspace visual asset: expected SHA-256 does not match bytes")
	}
	return WorkspaceSnapshotFile{path: path, bytes: append([]byte(nil), bytes...), sha256: expectedSHA256, mediaType: mediaType}, nil
}

func (file WorkspaceSnapshotFile) Path() SafeRelativePath { return file.path }
func (file WorkspaceSnapshotFile) Bytes() []byte          { return append([]byte(nil), file.bytes...) }
func (file WorkspaceSnapshotFile) SHA256() string         { return file.sha256 }
func (file WorkspaceSnapshotFile) MediaType() string {
	if file.mediaType == "" {
		return "text/plain"
	}
	return file.mediaType
}
func (file WorkspaceSnapshotFile) IsText() bool { return file.MediaType() == "text/plain" }

// WorkspaceSnapshotRequest contains only already-captured source bytes. It has
// no live-project-root field by design.
type WorkspaceSnapshotRequest struct {
	files          []WorkspaceSnapshotFile
	policyIdentity string
}

// NewWorkspaceSnapshotRequest validates stable lexicographic, unique captured files.
func NewWorkspaceSnapshotRequest(files []WorkspaceSnapshotFile, policyIdentity string) (WorkspaceSnapshotRequest, error) {
	if policyIdentity == "" || !utf8.ValidString(policyIdentity) || strings.IndexByte(policyIdentity, 0) >= 0 {
		return WorkspaceSnapshotRequest{}, fmt.Errorf("workspace snapshot request: invalid policy identity")
	}
	member := "current"
	if strings.HasSuffix(policyIdentity, ";layout=ordinary-directories-v1") {
		member = "combined"
	}
	if err := ValidateWorkspaceAdmission(policyIdentity, member, len(files), workspaceSnapshotBytes(files)); err != nil {
		return WorkspaceSnapshotRequest{}, err
	}
	copied := append([]WorkspaceSnapshotFile(nil), files...)
	previous := ""
	foldedPaths := make(map[string]struct{}, len(copied))
	for i, file := range copied {
		if file.path.String() == "" || !file.path.Valid() || workspaceReservedPath(file.path.String()) || !validWorkspaceFileBytes(file) || !workspaceSHA256(file.sha256) {
			return WorkspaceSnapshotRequest{}, fmt.Errorf("workspace snapshot request: invalid file %d", i)
		}
		actual := sha256.Sum256(file.bytes)
		if file.sha256 != "sha256:"+hex.EncodeToString(actual[:]) {
			return WorkspaceSnapshotRequest{}, fmt.Errorf("workspace snapshot request: file %q identity mismatch", file.path.String())
		}
		current := file.path.String()
		if i > 0 && (previous >= current || strings.HasPrefix(current, previous+"/")) {
			return WorkspaceSnapshotRequest{}, fmt.Errorf("workspace snapshot request: paths must be strictly lexicographic, unique, and non-colliding")
		}
		folded := strings.ToLower(current)
		if _, exists := foldedPaths[folded]; exists {
			return WorkspaceSnapshotRequest{}, fmt.Errorf("workspace snapshot request: case-fold path collision")
		}
		foldedPaths[folded] = struct{}{}
		previous = current
		if int64(len(file.bytes)) > WorkspaceSnapshotMaxFileBytes {
			return WorkspaceSnapshotRequest{}, fmt.Errorf("workspace snapshot request: size limit exceeded")
		}
		copied[i].bytes = append([]byte(nil), file.bytes...)
	}
	return WorkspaceSnapshotRequest{files: copied, policyIdentity: policyIdentity}, nil
}

func workspaceSnapshotBytes(files []WorkspaceSnapshotFile) int64 {
	var total int64
	for _, file := range files {
		size := int64(len(file.bytes))
		if size > math.MaxInt64-total {
			return math.MaxInt64
		}
		total += size
	}
	return total
}

// WorkspaceAdmissionLimits returns the file-count and aggregate-byte limits
// for one immutable workspace request. Provider comparison views are the only
// requests admitted at the combined before/after limits.
func WorkspaceAdmissionLimits(policyIdentity string) (int, int64) {
	if strings.HasSuffix(policyIdentity, ";layout=ordinary-directories-v1") {
		return WorkspaceProviderViewMaxFiles, WorkspaceProviderViewMaxBytes
	}
	return WorkspaceSnapshotMaxFiles, WorkspaceSnapshotMaxBytes
}

func validWorkspaceFileBytes(file WorkspaceSnapshotFile) bool {
	if file.IsText() {
		return utf8.Valid(file.bytes) && strings.IndexByte(string(file.bytes), 0) < 0
	}
	return validRasterBytes(file.bytes, file.MediaType())
}

func validRasterBytes(bytes []byte, mediaType string) bool {
	if len(bytes) == 0 || int64(len(bytes)) > WorkspaceSnapshotMaxFileBytes {
		return false
	}
	switch mediaType {
	case "image/png":
		return len(bytes) >= 8 && string(bytes[:8]) == "\x89PNG\r\n\x1a\n"
	case "image/jpeg":
		return len(bytes) >= 3 && bytes[0] == 0xff && bytes[1] == 0xd8 && bytes[2] == 0xff
	case "image/webp":
		return len(bytes) >= 12 && string(bytes[:4]) == "RIFF" && string(bytes[8:12]) == "WEBP"
	default:
		return false
	}
}

func (request WorkspaceSnapshotRequest) Files() []WorkspaceSnapshotFile {
	files := append([]WorkspaceSnapshotFile(nil), request.files...)
	for i := range files {
		files[i].bytes = append([]byte(nil), files[i].bytes...)
	}
	return files
}
func (request WorkspaceSnapshotRequest) PolicyIdentity() string { return request.policyIdentity }
func (request WorkspaceSnapshotRequest) Valid() bool {
	_, err := NewWorkspaceSnapshotRequest(request.files, request.policyIdentity)
	return err == nil
}

// WorkspaceContentVerdict is the mandatory pre-write detector result.
type WorkspaceContentVerdict string

const (
	WorkspaceContentClean                        WorkspaceContentVerdict = "clean"
	WorkspaceContentSecret                       WorkspaceContentVerdict = "secret"
	WorkspaceContentDangerousProviderInstruction WorkspaceContentVerdict = "dangerous_provider_instruction"
)

// WorkspaceContentDetector examines every captured file before any destination exists.
type WorkspaceContentDetector interface {
	DetectWorkspaceContent(context.Context, SafeRelativePath, []byte) (WorkspaceContentVerdict, error)
}

// WorkspaceSnapshotReceipt identifies exactly one materialized snapshot.
type WorkspaceSnapshotReceipt struct {
	snapshotPath, snapshotName, manifestSHA256, policyIdentity string
	rootDevice, rootInode, snapshotDevice, snapshotInode       uint64
	files                                                      []WorkspaceSnapshotFile
}

// NewWorkspaceSnapshotReceipt constructs an immutable receipt for an adapter-owned snapshot.
func NewWorkspaceSnapshotReceipt(snapshotPath, snapshotName, manifestSHA256, policyIdentity string, rootDevice, rootInode, snapshotDevice, snapshotInode uint64, files []WorkspaceSnapshotFile) (WorkspaceSnapshotReceipt, error) {
	if snapshotPath == "" || !workspaceSnapshotName(snapshotName) || !workspaceSHA256(manifestSHA256) || policyIdentity == "" || rootDevice == 0 || rootInode == 0 || snapshotDevice == 0 || snapshotInode == 0 {
		return WorkspaceSnapshotReceipt{}, fmt.Errorf("workspace snapshot receipt: invalid identity")
	}
	request, err := NewWorkspaceSnapshotRequest(files, policyIdentity)
	if err != nil {
		return WorkspaceSnapshotReceipt{}, err
	}
	return WorkspaceSnapshotReceipt{snapshotPath: snapshotPath, snapshotName: snapshotName, manifestSHA256: manifestSHA256, policyIdentity: policyIdentity, rootDevice: rootDevice, rootInode: rootInode, snapshotDevice: snapshotDevice, snapshotInode: snapshotInode, files: request.Files()}, nil
}
func (receipt WorkspaceSnapshotReceipt) SnapshotPath() string   { return receipt.snapshotPath }
func (receipt WorkspaceSnapshotReceipt) ManifestSHA256() string { return receipt.manifestSHA256 }
func (receipt WorkspaceSnapshotReceipt) PolicyIdentity() string { return receipt.policyIdentity }
func (receipt WorkspaceSnapshotReceipt) Files() []WorkspaceSnapshotFile {
	return WorkspaceSnapshotRequest{files: receipt.files, policyIdentity: receipt.policyIdentity}.Files()
}
func (receipt WorkspaceSnapshotReceipt) SnapshotIdentity() (string, uint64, uint64, uint64, uint64) {
	return receipt.snapshotName, receipt.rootDevice, receipt.rootInode, receipt.snapshotDevice, receipt.snapshotInode
}
func (receipt WorkspaceSnapshotReceipt) Valid() bool {
	_, err := NewWorkspaceSnapshotReceipt(receipt.snapshotPath, receipt.snapshotName, receipt.manifestSHA256, receipt.policyIdentity, receipt.rootDevice, receipt.rootInode, receipt.snapshotDevice, receipt.snapshotInode, receipt.files)
	return err == nil
}

func workspaceReservedPath(value string) bool {
	for _, part := range strings.Split(value, "/") {
		if strings.EqualFold(part, ".git") || strings.EqualFold(part, ".mulgae") ||
			strings.EqualFold(part, ".gitignore") || strings.EqualFold(part, ".mulgaeignore") {
			return true
		}
	}
	return false
}
func workspaceSnapshotName(value string) bool {
	if !strings.HasPrefix(value, "snapshot-") || len(value) != len("snapshot-")+32 {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "snapshot-"))
	return err == nil
}

func workspaceSHA256(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(value) != len("sha256:")+64 {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil && value == strings.ToLower(value)
}

// SortWorkspaceSnapshotFiles sorts a caller-owned slice by canonical path.
func SortWorkspaceSnapshotFiles(files []WorkspaceSnapshotFile) {
	sort.Slice(files, func(i, j int) bool { return files[i].Path().String() < files[j].Path().String() })
}

// ErrWorkspaceSnapshotDrift indicates that a captured workspace no longer
// matches the immutable snapshot that was authorized.
var ErrWorkspaceSnapshotDrift = errors.New("workspace snapshot drift")

// ErrProviderPacketSecurity indicates that system-owned packet screening
// rejected a provider invocation before process execution.
var ErrProviderPacketSecurity = errors.New("provider packet security rejection")

// WorkspaceSnapshotIdentity is the immutable filesystem and manifest identity
// of one v2 workspace snapshot.
type WorkspaceSnapshotIdentity struct {
	snapshotPath, snapshotName, manifestSHA256, policyIdentity string
	rootDevice, rootInode, snapshotDevice, snapshotInode       uint64
}

func NewWorkspaceSnapshotIdentity(snapshotPath, snapshotName, manifestSHA256, policyIdentity string, rootDevice, rootInode, snapshotDevice, snapshotInode uint64) (WorkspaceSnapshotIdentity, error) {
	if snapshotPath == "" || !workspaceSnapshotName(snapshotName) || !workspaceSHA256(manifestSHA256) || policyIdentity == "" || rootDevice == 0 || rootInode == 0 || snapshotDevice == 0 || snapshotInode == 0 {
		return WorkspaceSnapshotIdentity{}, fmt.Errorf("workspace snapshot identity: invalid identity")
	}
	return WorkspaceSnapshotIdentity{snapshotPath: snapshotPath, snapshotName: snapshotName, manifestSHA256: manifestSHA256, policyIdentity: policyIdentity, rootDevice: rootDevice, rootInode: rootInode, snapshotDevice: snapshotDevice, snapshotInode: snapshotInode}, nil
}
func (identity WorkspaceSnapshotIdentity) SnapshotPath() string   { return identity.snapshotPath }
func (identity WorkspaceSnapshotIdentity) SnapshotName() string   { return identity.snapshotName }
func (identity WorkspaceSnapshotIdentity) ManifestSHA256() string { return identity.manifestSHA256 }
func (identity WorkspaceSnapshotIdentity) PolicyIdentity() string { return identity.policyIdentity }
func (identity WorkspaceSnapshotIdentity) RootIdentity() (uint64, uint64) {
	return identity.rootDevice, identity.rootInode
}
func (identity WorkspaceSnapshotIdentity) SnapshotFSIdentity() (uint64, uint64) {
	return identity.snapshotDevice, identity.snapshotInode
}
func (identity WorkspaceSnapshotIdentity) Valid() bool {
	_, err := NewWorkspaceSnapshotIdentity(identity.snapshotPath, identity.snapshotName, identity.manifestSHA256, identity.policyIdentity, identity.rootDevice, identity.rootInode, identity.snapshotDevice, identity.snapshotInode)
	return err == nil
}

// ValidatedWorkspaceRoot is a read-only root validated with a v2 identity.
type ValidatedWorkspaceRoot struct {
	path     string
	identity WorkspaceSnapshotIdentity
}

func NewValidatedWorkspaceRoot(path string, identity WorkspaceSnapshotIdentity) (ValidatedWorkspaceRoot, error) {
	if path == "" || !identity.Valid() || path != identity.SnapshotPath() {
		return ValidatedWorkspaceRoot{}, fmt.Errorf("validated workspace root: invalid root or identity")
	}
	return ValidatedWorkspaceRoot{path: path, identity: identity}, nil
}
func (root ValidatedWorkspaceRoot) Path() string { return root.path }
func (root ValidatedWorkspaceRoot) SnapshotIdentity() WorkspaceSnapshotIdentity {
	return root.identity
}
func (root ValidatedWorkspaceRoot) Valid() bool {
	_, err := NewValidatedWorkspaceRoot(root.path, root.identity)
	return err == nil
}

// WorkspaceExecutionAuthority can mint one validated guard per process attempt.
// It deliberately has no release or cleanup method.
type WorkspaceExecutionAuthority interface {
	WorkspaceSnapshotIdentity() WorkspaceSnapshotIdentity
	RevalidateForExecution() (WorkspaceExecutionGuard, error)
}

// WorkspaceExecutionGuard is the narrowed per-spawn root capability.
type WorkspaceExecutionGuard interface {
	WorkspaceRoot() ValidatedWorkspaceRoot
	WorkspaceSnapshotIdentity() WorkspaceSnapshotIdentity
	// DuplicateLaunchDirectory returns a caller-owned descriptor for the exact
	// validated workspace root. It rejects closed guards.
	DuplicateLaunchDirectory() (*os.File, error)
	RevalidateAfterExecution() error
	Close() error
}

// WorkspaceSnapshotLeaseFactory materializes captured bytes without receiving
// authority to read the live project root.
type WorkspaceSnapshotLeaseFactory interface {
	MaterializeLease(context.Context, WorkspaceSnapshotRequest) (WorkspaceSnapshotLease, error)
}

// QualificationWorkspaceLeaseFactory materializes an ephemeral immutable
// workspace for qualification inputs. It has no publication or abort authority.
type QualificationWorkspaceLeaseFactory interface {
	MaterializeQualificationLease(context.Context, WorkspaceSnapshotRequest) (QualificationWorkspaceLease, error)
}

// QualificationWorkspaceLease is an ephemeral execution authority. Its terminal
// cleanup is independent of the captured user-workspace lifecycle.
type QualificationWorkspaceLease interface {
	WorkspaceExecutionAuthority
	DrainTerminal(context.Context) (QualificationWorkspaceTerminalReceipt, error)
}

// QualificationWorkspaceTerminalReceipt proves successful removal of one
// qualification workspace.
type QualificationWorkspaceTerminalReceipt struct {
	workspace WorkspaceSnapshotIdentity
}

type QualificationWorkspaceTerminalDrain func(context.Context) (QualificationWorkspaceTerminalReceipt, error)

type qualificationWorkspaceTerminalBindingState struct {
	mu        sync.Mutex
	open      bool
	bound     bool
	acquired  bool
	workspace WorkspaceSnapshotIdentity
	drained   bool
	terminal  QualificationWorkspaceTerminalReceipt
}

// QualificationWorkspaceTerminalBinding is minted only for one acquisition callback.
type QualificationWorkspaceTerminalBinding struct {
	state *qualificationWorkspaceTerminalBindingState
}

// QualificationWorkspaceAcquisition materializes one lease while its terminal
// binding is open.
type QualificationWorkspaceAcquisition func(context.Context, QualificationWorkspaceTerminalBinding) (QualificationWorkspaceLease, error)

// AcquireQualificationWorkspaceLease binds terminal proof to lease acquisition.
func AcquireQualificationWorkspaceLease(ctx context.Context, acquire QualificationWorkspaceAcquisition) (QualificationWorkspaceLease, error) {
	if ctx == nil || acquire == nil {
		return nil, fmt.Errorf("qualification workspace acquisition: invalid context or callback")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	state := &qualificationWorkspaceTerminalBindingState{open: true}
	lease, err := acquire(ctx, QualificationWorkspaceTerminalBinding{state: state})
	state.mu.Lock()
	state.open = false
	bound := state.bound
	workspace := state.workspace
	state.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if lease == nil || !bound || lease.WorkspaceSnapshotIdentity() != workspace {
		return nil, fmt.Errorf("qualification workspace acquisition: lease is not bound to terminal cleanup")
	}
	state.mu.Lock()
	state.acquired = true
	state.mu.Unlock()
	return lease, nil
}

// Bind retains a verified terminal operation and makes its receipt unavailable
// until that operation succeeds.
func (binding QualificationWorkspaceTerminalBinding) Bind(workspace WorkspaceSnapshotIdentity, drainAndVerify func(context.Context) error) (QualificationWorkspaceTerminalDrain, error) {
	if !workspace.Valid() || drainAndVerify == nil || binding.state == nil {
		return nil, fmt.Errorf("qualification workspace terminal binding: invalid workspace or drain")
	}
	state := binding.state
	state.mu.Lock()
	defer state.mu.Unlock()
	if !state.open || state.bound {
		return nil, fmt.Errorf("qualification workspace terminal binding: unavailable")
	}
	state.bound = true
	state.workspace = workspace
	return func(ctx context.Context) (QualificationWorkspaceTerminalReceipt, error) {
		if ctx == nil {
			return QualificationWorkspaceTerminalReceipt{}, fmt.Errorf("qualification workspace drain: invalid context")
		}
		state.mu.Lock()
		defer state.mu.Unlock()
		if !state.acquired || !state.bound {
			return QualificationWorkspaceTerminalReceipt{}, fmt.Errorf("qualification workspace drain: unavailable")
		}
		if state.drained {
			return state.terminal, nil
		}
		if err := drainAndVerify(ctx); err != nil {
			return QualificationWorkspaceTerminalReceipt{}, err
		}
		state.terminal = QualificationWorkspaceTerminalReceipt{workspace: state.workspace}
		state.drained = true
		return state.terminal, nil
	}, nil
}

func (receipt QualificationWorkspaceTerminalReceipt) WorkspaceSnapshotIdentity() WorkspaceSnapshotIdentity {
	return receipt.workspace
}

func (receipt QualificationWorkspaceTerminalReceipt) Valid() bool {
	return receipt.workspace.Valid()
}

// WorkspaceSnapshotLease is capture-owned authority retained through terminal
// cleanup or an explicitly evidenced abort. Execution consumers receive only
// WorkspaceExecutionAuthority.
type WorkspaceSnapshotLease interface {
	WorkspaceExecutionAuthority
	Receipt() WorkspaceSnapshotReceipt
	Release(WorkspaceCompletionEvidence) (WorkspaceTerminalReceipt, error)
	Abort(WorkspaceAbortEvidence) error
}

// WorkspaceCompletionEvidence binds successful workspace cleanup to one
// coordinator run and its complete provider terminal aggregate.
type WorkspaceCompletionEvidence struct {
	workspace WorkspaceSnapshotIdentity
	runID     string
	terminal  ProviderRunTerminalReceipt
}

func NewWorkspaceCompletionEvidence(workspace WorkspaceSnapshotIdentity, runID string, terminal ProviderRunTerminalReceipt) (WorkspaceCompletionEvidence, error) {
	if !workspace.Valid() || !workspaceRunID(runID) || !terminal.Valid() {
		return WorkspaceCompletionEvidence{}, fmt.Errorf("workspace completion evidence: incomplete terminal cleanup evidence")
	}
	return WorkspaceCompletionEvidence{workspace: workspace, runID: runID, terminal: terminal}, nil
}

func (evidence WorkspaceCompletionEvidence) WorkspaceSnapshotIdentity() WorkspaceSnapshotIdentity {
	return evidence.workspace
}

func (evidence WorkspaceCompletionEvidence) RunID() string { return evidence.runID }

func (evidence WorkspaceCompletionEvidence) ProviderRunTerminalReceipt() ProviderRunTerminalReceipt {
	return evidence.terminal
}

func (evidence WorkspaceCompletionEvidence) Valid() bool {
	_, err := NewWorkspaceCompletionEvidence(evidence.workspace, evidence.runID, evidence.terminal)
	return err == nil
}

// WorkspaceTerminalReceipt proves successful revalidation and deletion of the
// exact workspace bound by completion evidence. Its identity is canonical and
// domain-separated from all other SHA-256 identifiers.
type WorkspaceTerminalReceipt struct {
	workspace WorkspaceSnapshotIdentity
	runID     string
	terminal  ProviderRunTerminalReceipt
	receiptID string
}

type WorkspaceTerminalRelease func(WorkspaceCompletionEvidence) (WorkspaceTerminalReceipt, error)

type workspaceTerminalBindingState struct {
	mu        sync.Mutex
	open      bool
	bound     bool
	acquired  bool
	workspace WorkspaceSnapshotIdentity
	released  bool
}

// WorkspaceTerminalBinding is minted only for one acquisition callback.
type WorkspaceTerminalBinding struct {
	state *workspaceTerminalBindingState
}

// WorkspaceSnapshotAcquisition materializes one lease while its terminal
// binding is open.
type WorkspaceSnapshotAcquisition func(context.Context, WorkspaceTerminalBinding) (WorkspaceSnapshotLease, error)

// AcquireWorkspaceSnapshotLease binds terminal proof to lease acquisition.
func AcquireWorkspaceSnapshotLease(ctx context.Context, acquire WorkspaceSnapshotAcquisition) (WorkspaceSnapshotLease, error) {
	if ctx == nil || acquire == nil {
		return nil, fmt.Errorf("workspace acquisition: invalid context or callback")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	state := &workspaceTerminalBindingState{open: true}
	lease, err := acquire(ctx, WorkspaceTerminalBinding{state: state})
	state.mu.Lock()
	state.open = false
	bound := state.bound
	workspace := state.workspace
	state.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if lease == nil || !bound || lease.WorkspaceSnapshotIdentity() != workspace {
		return nil, fmt.Errorf("workspace acquisition: lease is not bound to terminal cleanup")
	}
	state.mu.Lock()
	state.acquired = true
	state.mu.Unlock()
	return lease, nil
}

// Bind retains a verified terminal operation and makes its receipt unavailable
// until that operation succeeds.
func (binding WorkspaceTerminalBinding) Bind(workspace WorkspaceSnapshotIdentity, releaseAndVerify func(WorkspaceCompletionEvidence) error) (WorkspaceTerminalRelease, error) {
	if !workspace.Valid() || releaseAndVerify == nil || binding.state == nil {
		return nil, fmt.Errorf("workspace terminal binding: invalid workspace or release")
	}
	state := binding.state
	state.mu.Lock()
	defer state.mu.Unlock()
	if !state.open || state.bound {
		return nil, fmt.Errorf("workspace terminal binding: unavailable")
	}
	state.bound = true
	state.workspace = workspace
	return func(completion WorkspaceCompletionEvidence) (WorkspaceTerminalReceipt, error) {
		if !completion.Valid() || completion.workspace != state.workspace {
			return WorkspaceTerminalReceipt{}, fmt.Errorf("workspace terminal release: invalid completion evidence")
		}
		state.mu.Lock()
		defer state.mu.Unlock()
		if !state.acquired || !state.bound {
			return WorkspaceTerminalReceipt{}, fmt.Errorf("workspace terminal release: unavailable")
		}
		if state.released {
			return WorkspaceTerminalReceipt{}, fmt.Errorf("workspace terminal release: already consumed")
		}
		if err := releaseAndVerify(completion); err != nil {
			return WorkspaceTerminalReceipt{}, err
		}
		state.released = true
		return newWorkspaceTerminalReceipt(completion), nil
	}, nil
}

func newWorkspaceTerminalReceipt(completion WorkspaceCompletionEvidence) WorkspaceTerminalReceipt {
	receipt := WorkspaceTerminalReceipt{
		workspace: completion.workspace,
		runID:     completion.runID,
		terminal:  completion.terminal,
	}
	receipt.receiptID = workspaceTerminalReceiptID(receipt.workspace, receipt.runID, receipt.terminal)
	return receipt
}

func (receipt WorkspaceTerminalReceipt) WorkspaceSnapshotIdentity() WorkspaceSnapshotIdentity {
	return receipt.workspace
}

func (receipt WorkspaceTerminalReceipt) RunID() string { return receipt.runID }

func (receipt WorkspaceTerminalReceipt) ProviderRunTerminalReceipt() ProviderRunTerminalReceipt {
	return receipt.terminal
}

func (receipt WorkspaceTerminalReceipt) ReceiptID() string { return receipt.receiptID }

func (receipt WorkspaceTerminalReceipt) Valid() bool {
	if !receipt.workspace.Valid() || !workspaceRunID(receipt.runID) || !receipt.terminal.Valid() {
		return false
	}
	return receipt.receiptID == workspaceTerminalReceiptID(receipt.workspace, receipt.runID, receipt.terminal)
}

func workspaceRunID(value string) bool {
	_, err := domain.ParseRunID(value)
	return err == nil
}

func workspaceTerminalReceiptID(workspace WorkspaceSnapshotIdentity, runID string, terminal ProviderRunTerminalReceipt) string {
	hasher := sha256.New()
	write := func(value string) {
		_, _ = fmt.Fprintf(hasher, "%d:%s", len(value), value)
	}
	write("mulgae.workspace-terminal-receipt.v1")
	write(workspace.SnapshotPath())
	write(workspace.SnapshotName())
	write(workspace.ManifestSHA256())
	write(workspace.PolicyIdentity())
	for _, value := range []uint64{workspace.rootDevice, workspace.rootInode, workspace.snapshotDevice, workspace.snapshotInode} {
		write(fmt.Sprintf("%d", value))
	}
	write(runID)
	if terminal.NoNamespaces() {
		write("no-namespaces")
	} else {
		write("namespaces")
		for _, namespace := range terminal.NamespaceReceipts() {
			write(namespace.ProviderInstance())
			write(namespace.Generation())
		}
	}
	return "workspace-terminal:v1:sha256:" + hex.EncodeToString(hasher.Sum(nil))
}

// WorkspaceAbortReason is the closed reason set for deleting a snapshot before
// publication authority exists.
type WorkspaceAbortReason string

const (
	WorkspaceAbortCaptureFailure     WorkspaceAbortReason = "capture_failure"
	WorkspaceAbortPreflightComplete  WorkspaceAbortReason = "preflight_complete"
	WorkspaceAbortPlanningFailure    WorkspaceAbortReason = "planning_failure"
	WorkspaceAbortExecutionFailure   WorkspaceAbortReason = "execution_failure"
	WorkspaceAbortPublicationFailure WorkspaceAbortReason = "publication_failure"
	WorkspaceAbortCancellation       WorkspaceAbortReason = "cancellation"
	WorkspaceAbortSecurityViolation  WorkspaceAbortReason = "security_violation"
	WorkspaceAbortInternalFailure    WorkspaceAbortReason = "internal_failure"
)

func (reason WorkspaceAbortReason) Valid() bool {
	switch reason {
	case WorkspaceAbortCaptureFailure, WorkspaceAbortPreflightComplete, WorkspaceAbortPlanningFailure, WorkspaceAbortExecutionFailure,
		WorkspaceAbortPublicationFailure, WorkspaceAbortCancellation, WorkspaceAbortSecurityViolation,
		WorkspaceAbortInternalFailure:
		return true
	default:
		return false
	}
}

// WorkspaceAbortEvidence authorizes cleanup without fabricating P2 publication.
// It binds complete aggregate terminal cleanup evidence to the workspace.
type WorkspaceAbortEvidence struct {
	workspace WorkspaceSnapshotIdentity
	reason    WorkspaceAbortReason
	terminal  ProviderRunTerminalReceipt
}

func NewWorkspaceAbortEvidence(workspace WorkspaceSnapshotIdentity, reason WorkspaceAbortReason, terminal ProviderRunTerminalReceipt) (WorkspaceAbortEvidence, error) {
	if !workspace.Valid() || !reason.Valid() || !terminal.Valid() {
		return WorkspaceAbortEvidence{}, fmt.Errorf("workspace abort evidence: incomplete terminal cleanup evidence")
	}
	return WorkspaceAbortEvidence{workspace: workspace, reason: reason, terminal: terminal}, nil
}

func (evidence WorkspaceAbortEvidence) WorkspaceSnapshotIdentity() WorkspaceSnapshotIdentity {
	return evidence.workspace
}
func (evidence WorkspaceAbortEvidence) Reason() WorkspaceAbortReason { return evidence.reason }
func (evidence WorkspaceAbortEvidence) TerminalReceipt() ProviderRunTerminalReceipt {
	return evidence.terminal
}
func (evidence WorkspaceAbortEvidence) Valid() bool {
	_, err := NewWorkspaceAbortEvidence(evidence.workspace, evidence.reason, evidence.terminal)
	return err == nil
}

// Equal reports whether two abort authorities bind the same workspace, reason,
// and complete provider-run cleanup.
func (evidence WorkspaceAbortEvidence) Equal(other WorkspaceAbortEvidence) bool {
	return evidence.Valid() &&
		other.Valid() &&
		evidence.workspace == other.workspace &&
		evidence.reason == other.reason &&
		evidence.terminal.Equal(other.terminal)
}
