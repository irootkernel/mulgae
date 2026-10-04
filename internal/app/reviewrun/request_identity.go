package reviewrun

import (
	"errors"
	"fmt"

	"github.com/irootkernel/mulgae/internal/app"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

// NewProjectBinding retains the review planning API for the shared application identity policy.
func NewProjectBinding(root, gitDirectory, commonDirectory ports.AnchoredRoot, rootIdentity, gitIdentity, commonIdentity ports.ProjectDirectoryIdentity) (domain.ProjectBinding, error) {
	return app.NewProjectBinding(root, gitDirectory, commonDirectory, rootIdentity, gitIdentity, commonIdentity)
}

// AdmitLiveProjectBinding preserves unguarded non-Git workspace reviews without
// inventing a Git binding. An expected binding always requires Git authority.
func AdmitLiveProjectBinding(observed ports.ProjectBindingObservation, selector ports.LiveSourceSelector, expected domain.ProjectBinding) (domain.ProjectBinding, error) {
	if !observed.Root.Valid() || observed.RootIdentity.Inode == 0 || !selector.Valid() || observed.GitDirectory.Valid() != observed.CommonDirectory.Valid() {
		return domain.ProjectBinding{}, projectAdmissionFailure(fmt.Errorf("invalid source binding"))
	}
	if !observed.GitDirectory.Valid() {
		if selector.Scope() != domain.LiveSourceWorkspace || expected.String() != "" {
			return domain.ProjectBinding{}, guardFailure(ErrContractUnsupported)
		}
		return domain.ProjectBinding{}, nil
	}
	binding, err := NewProjectBinding(observed.Root, observed.GitDirectory, observed.CommonDirectory, observed.RootIdentity, observed.GitIdentity, observed.CommonIdentity)
	if err != nil {
		return domain.ProjectBinding{}, projectAdmissionFailure(err)
	}
	if expected.String() != "" && expected != binding {
		return domain.ProjectBinding{}, guardFailure(ErrProjectBindingMismatch)
	}
	return binding, nil
}

type GuardError string

func (err GuardError) Error() string { return string(err) }

const (
	ErrGuardInvalid           GuardError = "guard_invalid"
	ErrProjectBindingMismatch GuardError = "project_binding_mismatch"
	ErrContractUnsupported    GuardError = "contract_unsupported"
)

// GuardReason returns only a closed admission reason, never untrusted input.
func GuardReason(err error) (string, bool) {
	for _, reason := range []GuardError{ErrGuardInvalid, ErrContractUnsupported, ErrProjectBindingMismatch} {
		if errors.Is(err, reason) {
			return string(reason), true
		}
	}
	return "", false
}
