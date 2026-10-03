package ports

import (
	"fmt"
	"os"
	"unicode"
	"unicode/utf8"
)

// LiveReadOnlyBoundary carries trusted directory roots for the platform launch
// guard. Filesystem admission remains the process adapter's responsibility.
type LiveReadOnlyBoundary struct {
	readOnly    []AnchoredRoot
	credentials []AnchoredRoot
	writable    AnchoredRoot
	runtimeTemp AnchoredRoot
	present     bool
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

func (boundary LiveReadOnlyBoundary) Valid() bool {
	if !boundary.present || len(boundary.readOnly) == 0 || len(boundary.credentials) == 0 || !validLivePolicyRoot(boundary.writable) {
		return false
	}
	for _, roots := range [][]AnchoredRoot{boundary.readOnly, boundary.credentials} {
		for _, root := range roots {
			if !validLivePolicyRoot(root) {
				return false
			}
		}
	}
	if boundary.runtimeTemp.Valid() && !validLivePolicyRoot(boundary.runtimeTemp) {
		return false
	}
	return true
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

// WritableRoot is the caller-owned invocation namespace, never the source or
// neutral reviewer directory.
func (boundary LiveReadOnlyBoundary) WritableRoot() AnchoredRoot { return boundary.writable }

func (boundary LiveReadOnlyBoundary) RuntimeTempRoot() (AnchoredRoot, bool) {
	return boundary.runtimeTemp, boundary.runtimeTemp.Valid()
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
