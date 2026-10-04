package mulgae

import (
	"context"
	"fmt"

	"github.com/irootkernel/mulgae/internal/app/reviewrun"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

type liveReviewRunAdapter struct{ service *reviewrun.LiveService }

func NewLiveReviewRunService(service *reviewrun.LiveService) ReviewRunService {
	if service == nil {
		return nil
	}
	return liveReviewRunAdapter{service}
}

func (adapter liveReviewRunAdapter) StartReviewRun(ctx context.Context, request ReviewRequest, root ports.AnchoredRoot) (ReviewRunResult, error) {
	if ctx == nil || !root.Valid() || !validReviewRunRequest(request) {
		return ReviewRunResult{}, fmt.Errorf("live review: malformed request")
	}
	value := request.Target().Value()
	scope := domain.LiveSourceScope(request.Target().Kind())
	if scope == domain.LiveSourceWorkspace || scope == domain.LiveSourceStage || scope == domain.LiveSourceHead {
		value = ""
	}
	target, err := ports.NewLiveSourceSelector(scope, value)
	if err != nil {
		return ReviewRunResult{}, err
	}
	roles := request.Roles()
	selected := make([]domain.Role, len(roles))
	for index, role := range roles {
		selected[index] = domain.Role(role)
	}
	var session *domain.SessionID
	if value, present := request.SessionID(); present {
		parsed, err := domain.ParseSessionID(value)
		if err != nil {
			return ReviewRunResult{}, err
		}
		session = &parsed
	}
	selection, err := reviewrun.NewRunSelection(selected, session)
	if err != nil {
		return ReviewRunResult{}, err
	}
	_, artifactRoot, err := publicationRoots(root.String())
	if err != nil {
		return ReviewRunResult{}, err
	}
	var binding domain.ProjectBinding
	if request.ExpectedProjectBinding() != "" {
		binding, err = domain.ParseProjectBinding(request.ExpectedProjectBinding())
		if err != nil {
			return ReviewRunResult{}, err
		}
	}
	objective, present := request.Objective()
	liveRequest := reviewrun.LiveRequest{ProjectRoot: root, ArtifactRoot: artifactRoot, Target: target, Selection: selection, Objective: []byte(objective), HasObjective: present, ExpectedProjectBinding: binding}
	if containsString(request.Roles(), string(domain.RoleArtist)) {
		brief, _ := request.ArtistBrief()
		if request.ArtistAutomatic() {
			liveRequest.ArtistInputs, err = ports.NewAutomaticArtistReviewInputs(brief, request.ArtistDesignSpecs())
		} else {
			liveRequest.ArtistInputs, err = ports.NewArtistReviewInputs(brief, request.ArtistDesignSpecs())
		}
		if err != nil {
			return ReviewRunResult{}, err
		}
		liveRequest.HasArtistInputs = true
	}
	result, err := adapter.service.Execute(ctx, liveRequest)
	if err != nil {
		return ReviewRunResult{}, err
	}
	return projectReviewRunResult(result)
}
