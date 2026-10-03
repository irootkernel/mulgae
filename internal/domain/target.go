package domain

import (
	"fmt"
	"regexp"
	"strings"
)

type TargetKind string

type GitTargetMode string

const (
	TargetGit        TargetKind = "git"
	TargetWorkspace  TargetKind = "workspace"
	TargetPatch      TargetKind = "patch"
	TargetStdin      TargetKind = "stdin"
	TargetLiveSource TargetKind = "live_source"
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

// TargetIdentity binds a run either to captured bytes or to a declared live
// source selection. A live source digest makes no content identity claim.
type TargetIdentity struct {
	kind                 TargetKind
	sha256               string
	sourceIdentitySHA256 string
	repositoryID         string
	baseObjectID         string
	headObjectID         string
	headTreeObjectID     string
	indexTreeObjectID    string
	gitMode              GitTargetMode
}

// NewLiveTargetIdentity accepts a selection-metadata digest and resolved object
// operands. It intentionally leaves the captured-content SHA256 empty.
func NewLiveTargetIdentity(sourceIdentitySHA256, baseObjectID, headObjectID string) (TargetIdentity, error) {
	if !lowerSHA256Pattern.MatchString(sourceIdentitySHA256) || allZeroHex(sourceIdentitySHA256) {
		return TargetIdentity{}, fmt.Errorf("live target identity: %w: invalid source identity digest", ErrInvariant)
	}
	for _, value := range []string{baseObjectID, headObjectID} {
		if value != "" && (!gitOIDPattern.MatchString(value) || allZeroHex(value)) {
			return TargetIdentity{}, fmt.Errorf("live target identity: %w: invalid resolved object ID", ErrInvariant)
		}
	}
	return TargetIdentity{kind: TargetLiveSource, sourceIdentitySHA256: sourceIdentitySHA256, baseObjectID: baseObjectID, headObjectID: headObjectID}, nil
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

func (identity TargetIdentity) Kind() TargetKind             { return identity.kind }
func (identity TargetIdentity) SHA256() string               { return identity.sha256 }
func (identity TargetIdentity) SourceIdentitySHA256() string { return identity.sourceIdentitySHA256 }
func (identity TargetIdentity) RepositoryID() string         { return identity.repositoryID }
func (identity TargetIdentity) BaseObjectID() string         { return identity.baseObjectID }
func (identity TargetIdentity) HeadObjectID() string         { return identity.headObjectID }
func (identity TargetIdentity) HeadTreeObjectID() string     { return identity.headTreeObjectID }
func (identity TargetIdentity) IndexTreeObjectID() string    { return identity.indexTreeObjectID }
func (identity TargetIdentity) GitMode() GitTargetMode       { return identity.gitMode }
