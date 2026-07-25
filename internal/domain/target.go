package domain

import (
	"fmt"
	"regexp"
	"strings"
)

type TargetKind string

type GitTargetMode string

const (
	TargetGit       TargetKind = "git"
	TargetWorkspace TargetKind = "workspace"
	TargetPatch     TargetKind = "patch"
	TargetStdin     TargetKind = "stdin"
)

const (
	GitTargetDiff  GitTargetMode = "diff"
	GitTargetStage GitTargetMode = "stage"
	GitTargetDirty GitTargetMode = "dirty"
)

func (mode GitTargetMode) Valid() bool {
	return mode == GitTargetDiff || mode == GitTargetStage || mode == GitTargetDirty
}

var (
	lowerSHA256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
	gitOIDPattern      = regexp.MustCompile(`^(?:[0-9a-f]{40}|[0-9a-f]{64})$`)
)

type TargetIdentityInput struct {
	Kind              TargetKind
	SHA256            string
	RepositoryID      string
	BaseObjectID      string
	HeadObjectID      string
	HeadTreeObjectID  string
	IndexTreeObjectID string
	GitMode           GitTargetMode
}

// TargetIdentity binds a run to immutable target bytes and, for Git targets,
// to the resolved object identities captured at run start.
type TargetIdentity struct {
	kind              TargetKind
	sha256            string
	repositoryID      string
	baseObjectID      string
	headObjectID      string
	headTreeObjectID  string
	indexTreeObjectID string
	gitMode           GitTargetMode
}

func NewTargetIdentity(input TargetIdentityInput) (TargetIdentity, error) {
	if !lowerSHA256Pattern.MatchString(input.SHA256) {
		return TargetIdentity{}, fmt.Errorf("target identity: %w: SHA-256 must be canonical lowercase hexadecimal", ErrInvariant)
	}
	if allZeroHex(input.SHA256) {
		return TargetIdentity{}, fmt.Errorf("target identity: %w: SHA-256 cannot be the zero digest", ErrInvariant)
	}
	identity := TargetIdentity{
		kind: input.Kind, sha256: input.SHA256, repositoryID: input.RepositoryID,
		baseObjectID: input.BaseObjectID, headObjectID: input.HeadObjectID,
		headTreeObjectID: input.HeadTreeObjectID, indexTreeObjectID: input.IndexTreeObjectID,
		gitMode: input.GitMode,
	}
	switch input.Kind {
	case TargetGit:
		if identity.gitMode == "" {
			identity.gitMode = GitTargetDiff
		}
		if !identity.gitMode.Valid() {
			return TargetIdentity{}, fmt.Errorf("target identity: %w: invalid Git target mode", ErrInvariant)
		}
		if strings.TrimSpace(input.RepositoryID) == "" {
			return TargetIdentity{}, fmt.Errorf("target identity: %w: Git repository identity is required", ErrInvariant)
		}
		objects := [...]struct {
			name  string
			value string
		}{
			{"base object", input.BaseObjectID},
			{"head object", input.HeadObjectID},
			{"head tree", input.HeadTreeObjectID},
		}
		for _, object := range objects {
			if !gitOIDPattern.MatchString(object.value) || allZeroHex(object.value) {
				return TargetIdentity{}, fmt.Errorf("target identity: %w: %s is not a canonical nonzero Git object ID", ErrInvariant, object.name)
			}
		}
		if input.IndexTreeObjectID != "" && (!gitOIDPattern.MatchString(input.IndexTreeObjectID) || allZeroHex(input.IndexTreeObjectID)) {
			return TargetIdentity{}, fmt.Errorf("target identity: %w: index tree is not a canonical nonzero Git object ID", ErrInvariant)
		}
	case TargetWorkspace, TargetPatch, TargetStdin:
		if input.RepositoryID != "" || input.BaseObjectID != "" || input.HeadObjectID != "" || input.HeadTreeObjectID != "" || input.IndexTreeObjectID != "" || input.GitMode != "" {
			return TargetIdentity{}, fmt.Errorf("target identity: %w: non-Git target cannot carry Git object identities", ErrInvariant)
		}
	default:
		return TargetIdentity{}, fmt.Errorf("target identity: %w: unknown kind %q", ErrInvariant, input.Kind)
	}
	return identity, nil
}

func allZeroHex(value string) bool {
	if value == "" {
		return false
	}
	for _, char := range value {
		if char != '0' {
			return false
		}
	}
	return true
}

func (identity TargetIdentity) Kind() TargetKind          { return identity.kind }
func (identity TargetIdentity) SHA256() string            { return identity.sha256 }
func (identity TargetIdentity) RepositoryID() string      { return identity.repositoryID }
func (identity TargetIdentity) BaseObjectID() string      { return identity.baseObjectID }
func (identity TargetIdentity) HeadObjectID() string      { return identity.headObjectID }
func (identity TargetIdentity) HeadTreeObjectID() string  { return identity.headTreeObjectID }
func (identity TargetIdentity) IndexTreeObjectID() string { return identity.indexTreeObjectID }
func (identity TargetIdentity) GitMode() GitTargetMode    { return identity.gitMode }
