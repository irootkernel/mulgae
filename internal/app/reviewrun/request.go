// Package reviewrun owns transport-independent review requests and admission.
package reviewrun

import (
	"errors"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

// RequestInput contains fields already admitted by a transport's grammar. Byte
// bounds and representation stay at that entrypoint; configured policy is
// resolved separately. Construction allocates no execution identity or resource.
type RequestInput struct {
	Target                 ports.LiveSourceSelector
	Objective              string
	HasObjective           bool
	Roles                  []string
	RolesExplicit          bool
	ArtistBriefPath        string
	HasArtistBrief         bool
	ArtistDesignGlobs      []string
	SessionID              *domain.SessionID
	Preflight              bool
	ExpectedProjectBinding domain.ProjectBinding
}

// NewRequest freezes transport-admitted fields and owns every mutable input.
func NewRequest(input RequestInput) Request {
	request := Request{
		target:    TargetRequest{kind: string(input.Target.Scope()), value: input.Target.Value()},
		objective: input.Objective, hasObjective: input.HasObjective,
		roles: append([]string(nil), input.Roles...), rolesExplicit: input.RolesExplicit,
		artistBriefPath: input.ArtistBriefPath, hasArtistBrief: input.HasArtistBrief,
		artistDesignGlobs: append([]string(nil), input.ArtistDesignGlobs...),
		preflight:         input.Preflight, expectedProjectBinding: input.ExpectedProjectBinding.String(),
	}
	if input.SessionID != nil {
		request.sessionID, request.hasSessionID = input.SessionID.String(), true
	}
	return request
}

// AdmittedRequest records resolved project roles and artist input defaults. It
// confers no source, provider or publication authority.
type AdmittedRequest struct{ request Request }

func (request AdmittedRequest) Request() Request { return request.request }

// TargetRequest contains one literal command-request target.
type TargetRequest struct {
	kind  string
	value string
}

// Kind returns the selected live source scope: workspace, stage, head, commit, or diff.
func (request TargetRequest) Kind() string { return request.kind }

// Value returns the target value.
func (request TargetRequest) Value() string { return request.value }

// Request contains the immutable independent-review fields.
type Request struct {
	expectedProjectBinding string
	target                 TargetRequest
	objective              string
	hasObjective           bool
	roles                  []string
	rolesExplicit          bool
	rolesDefaulted         bool
	artistAutomatic        bool
	artistBriefPath        string
	hasArtistBrief         bool
	artistDesignGlobs      []string
	sessionID              string
	hasSessionID           bool
	preflight              bool
}

// Target returns the literal target request.
func (request Request) Target() TargetRequest { return request.target }

// Objective returns the optional review objective.
func (request Request) Objective() (string, bool) {
	return request.objective, request.hasObjective
}

// Roles returns a caller-owned copy of the requested roles.
func (request Request) Roles() []string { return append([]string(nil), request.roles...) }

// RolesExplicit reports whether --roles was supplied by the caller.
func (request Request) RolesExplicit() bool { return request.rolesExplicit }

// RequestedRolesExplicit preserves caller intent after policy selection.
func (request Request) RequestedRolesExplicit() bool {
	return request.rolesExplicit && !request.rolesDefaulted
}

// ArtistBrief returns the optional review-scoped artist brief path.
func (request Request) ArtistBrief() (string, bool) {
	return request.artistBriefPath, request.hasArtistBrief
}

// ArtistDesignSpecs returns a caller-owned copy of the optional review-scoped
// visual asset globs.
func (request Request) ArtistDesignSpecs() []string {
	return append([]string(nil), request.artistDesignGlobs...)
}
func (request Request) ArtistAutomatic() bool { return request.artistAutomatic }

// SessionID returns the optional imported workflow session ID.
func (request Request) SessionID() (string, bool) {
	return request.sessionID, request.hasSessionID
}

// Preflight reports whether the review is an provider-free live source, routing,
// and budget projection.
func (request Request) Preflight() bool { return request.preflight }

func (request Request) ExpectedProjectBinding() string { return request.expectedProjectBinding }

var (
	ErrRoleNotEnabled       = errors.New("requested role is not enabled by production policy")
	ErrArtistInputsRequired = errors.New("artist review inputs are required")
	ErrArtistRoleRequired   = errors.New("artist inputs require the artist role")
)

// ResolveRequest is the shared normal-run and preflight authority
// for enabled-role selection plus Config v1 artist defaults and request-scoped
// overrides. The returned request is canonical and explicitly selected.
func ResolveRequest(request Request, enabled map[domain.Role]bool, artistInputs ports.ArtistReviewInputs, hasArtistInputs bool) (AdmittedRequest, error) {
	if hasArtistInputs && !artistInputs.Valid() {
		return AdmittedRequest{}, errors.New("production artist defaults are invalid")
	}
	automaticRoles := !request.rolesExplicit || request.rolesDefaulted
	selected := make(map[domain.Role]bool, len(request.roles))
	if request.rolesExplicit {
		for _, raw := range request.roles {
			role := domain.Role(raw)
			if !role.Valid() || !enabled[role] {
				return AdmittedRequest{}, ErrRoleNotEnabled
			}
			selected[role] = true
		}
	} else {
		for _, role := range domain.FixedRoleOrder() {
			if enabled[role] {
				selected[role] = true
			}
		}
	}
	request.roles = nil
	for _, role := range domain.FixedRoleOrder() {
		if selected[role] {
			request.roles = append(request.roles, string(role))
		}
	}
	if selected[domain.RoleArtist] {
		briefPath := ""
		var designGlobs []string
		if hasArtistInputs {
			briefPath = artistInputs.BriefPath()
			designGlobs = artistInputs.DesignSpecGlobs()
		}
		if request.hasArtistBrief {
			briefPath = request.artistBriefPath
		}
		if len(request.artistDesignGlobs) != 0 {
			designGlobs = append([]string(nil), request.artistDesignGlobs...)
		}
		resolved, err := ports.NewArtistReviewInputs(briefPath, designGlobs)
		if err != nil {
			return AdmittedRequest{}, errors.Join(ErrArtistInputsRequired, err)
		}
		request.artistBriefPath, request.hasArtistBrief = resolved.BriefPath(), true
		request.artistDesignGlobs = resolved.DesignSpecGlobs()
		request.artistAutomatic = automaticRoles
	} else if request.hasArtistBrief || len(request.artistDesignGlobs) != 0 {
		return AdmittedRequest{}, ErrArtistRoleRequired
	}
	request.rolesDefaulted = automaticRoles
	request.rolesExplicit = true
	return AdmittedRequest{request: request}, nil
}
