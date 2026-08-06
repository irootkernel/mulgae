package childrun

import (
	"fmt"

	"github.com/irootkernel/mulgae/internal/app/delta"
	appfollowup "github.com/irootkernel/mulgae/internal/app/followup"
	"github.com/irootkernel/mulgae/internal/app/publication"
	"github.com/irootkernel/mulgae/internal/app/rerun"
)

func projectFollowupRoleReportURIs(published publication.PublicationResult) ([]appfollowup.RoleReportURI, error) {
	projected, err := publication.ProjectRoleReportURIs(published)
	if err != nil {
		return nil, fmt.Errorf("project followup role report URIs: %w", err)
	}
	uris := make([]appfollowup.RoleReportURI, 0, len(projected))
	for _, report := range projected {
		uris = append(uris, appfollowup.RoleReportURI{Role: report.Role, URI: report.URI})
	}
	return uris, nil
}

func projectDeltaRoleReportURIs(published publication.PublicationResult) ([]delta.RoleReportURI, error) {
	projected, err := publication.ProjectRoleReportURIs(published)
	if err != nil {
		return nil, fmt.Errorf("project delta role report URIs: %w", err)
	}
	uris := make([]delta.RoleReportURI, 0, len(projected))
	for _, report := range projected {
		uris = append(uris, delta.RoleReportURI{Role: report.Role, URI: report.URI})
	}
	return uris, nil
}

func projectRerunRoleReportURIs(published publication.PublicationResult) ([]rerun.RoleReportURI, error) {
	projected, err := publication.ProjectRoleReportURIs(published)
	if err != nil {
		return nil, fmt.Errorf("project rerun role report URIs: %w", err)
	}
	uris := make([]rerun.RoleReportURI, 0, len(projected))
	for _, report := range projected {
		uris = append(uris, rerun.RoleReportURI{Role: report.Role, URI: report.URI})
	}
	return uris, nil
}
