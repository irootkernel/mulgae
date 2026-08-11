package ports

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

const (
	workspaceAdmissionCaptureSide  = "capture_side"
	workspaceAdmissionProviderView = "provider_view"
)

// WorkspaceAdmissionFailure reports bounded counts without retaining source
// paths or bytes.
type WorkspaceAdmissionFailure struct {
	stage     string
	member    string
	fileCount int
	byteCount int64
	maxFiles  int
	maxBytes  int64
}

// ValidateWorkspaceAdmission retains the v1 fact-validation boundary without
// imposing a source file-count or byte ceiling.
func ValidateWorkspaceAdmission(policyIdentity, member string, fileCount int, byteCount int64) error {
	if policyIdentity == "" || !utf8.ValidString(policyIdentity) || strings.IndexByte(policyIdentity, 0) >= 0 ||
		!validWorkspaceAdmissionMember(member) || fileCount < 0 || byteCount < 0 {
		return fmt.Errorf("workspace admission: invalid facts")
	}
	return nil
}

func validWorkspaceAdmissionMember(member string) bool {
	switch member {
	case "base", "combined", "current", "head", "index", "worktree":
		return true
	default:
		return false
	}
}

func (failure *WorkspaceAdmissionFailure) Error() string {
	if failure == nil {
		return "workspace admission failed"
	}
	return "workspace admission limit exceeded"
}

func (failure *WorkspaceAdmissionFailure) Stage() string {
	if failure == nil {
		return ""
	}
	return failure.stage
}

func (failure *WorkspaceAdmissionFailure) Member() string {
	if failure == nil {
		return ""
	}
	return failure.member
}

func (failure *WorkspaceAdmissionFailure) FileCount() int {
	if failure == nil {
		return 0
	}
	return failure.fileCount
}

func (failure *WorkspaceAdmissionFailure) ByteCount() int64 {
	if failure == nil {
		return 0
	}
	return failure.byteCount
}

func (failure *WorkspaceAdmissionFailure) MaxFiles() int {
	if failure == nil {
		return 0
	}
	return failure.maxFiles
}

func (failure *WorkspaceAdmissionFailure) MaxBytes() int64 {
	if failure == nil {
		return 0
	}
	return failure.maxBytes
}

func WorkspaceAdmissionFailureFromError(err error) (*WorkspaceAdmissionFailure, bool) {
	var failure *WorkspaceAdmissionFailure
	if !errors.As(err, &failure) || failure == nil {
		return nil, false
	}
	return failure, true
}
