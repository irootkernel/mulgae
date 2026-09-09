package recovery

import "fmt"

import "github.com/irootkernel/mulgae/internal/domain"

// Status exposes replay admission without granting final-review authority.
type Status struct {
	Available         bool           `json:"available"`
	SourceKind        *string        `json:"source_kind"`
	RunID             *string        `json:"run_id"`
	ManifestSHA256    *string        `json:"manifest_sha256"`
	AcceptedRoles     []domain.Role  `json:"accepted_roles"`
	RetryAttempts     []RetryAttempt `json:"retry_attempts"`
	UnavailableReason *string        `json:"unavailable_reason"`
}

type RetryAttempt struct {
	Role      domain.Role `json:"role"`
	AttemptID string      `json:"attempt_id"`
}

func UnavailableStatus(reason string) Status {
	return Status{AcceptedRoles: []domain.Role{}, RetryAttempts: []RetryAttempt{}, UnavailableReason: &reason}
}

func (snapshot Snapshot) Status() Status {
	kind, runID, hash := "failed_run_recovery", snapshot.document.RunID, Digest(snapshot.manifest)
	status := Status{Available: true, SourceKind: &kind, RunID: &runID, ManifestSHA256: &hash, AcceptedRoles: []domain.Role{}, RetryAttempts: []RetryAttempt{}}
	for _, role := range snapshot.document.Roles {
		if role.Outcome == "failed" {
			status.RetryAttempts = append(status.RetryAttempts, RetryAttempt{role.Role, role.AttemptID})
		} else {
			status.AcceptedRoles = append(status.AcceptedRoles, role.Role)
		}
	}
	return status
}

func (status Status) ValidateFor(runID domain.RunID) error {
	if !status.Available {
		if status.SourceKind != nil || status.RunID != nil || status.ManifestSHA256 != nil || len(status.AcceptedRoles) != 0 || len(status.RetryAttempts) != 0 || status.UnavailableReason == nil {
			return fmt.Errorf("recovery status: inconsistent unavailable source")
		}
		switch *status.UnavailableReason {
		case "source_not_retained", "source_invalid", "publication_in_progress", "published_review":
			return nil
		default:
			return fmt.Errorf("recovery status: unknown unavailable reason")
		}
	}
	if status.SourceKind == nil || *status.SourceKind != "failed_run_recovery" || status.RunID == nil || *status.RunID != runID.String() || status.ManifestSHA256 == nil || status.UnavailableReason != nil {
		return fmt.Errorf("recovery status: source identity mismatch")
	}
	if _, err := domain.NewRecoverySourceReference(runID, *status.ManifestSHA256); err != nil {
		return err
	}
	if len(status.RetryAttempts) == 0 || len(status.AcceptedRoles)+len(status.RetryAttempts) > len(domain.FixedRoleOrder()) {
		return fmt.Errorf("recovery status: invalid role inventory")
	}
	roles := map[domain.Role]bool{}
	attempts := map[string]bool{}
	for _, role := range status.AcceptedRoles {
		if !role.Valid() || roles[role] {
			return fmt.Errorf("recovery status: invalid accepted role")
		}
		roles[role] = true
	}
	for _, attempt := range status.RetryAttempts {
		if !attempt.Role.Valid() || roles[attempt.Role] || attempts[attempt.AttemptID] {
			return fmt.Errorf("recovery status: invalid retry role")
		}
		if _, err := domain.ParseAttemptID(attempt.AttemptID); err != nil {
			return err
		}
		roles[attempt.Role] = true
		attempts[attempt.AttemptID] = true
	}
	return nil
}
