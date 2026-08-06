package publication

import (
	"fmt"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

// CommittedRoleReport is one verified role-report identity from a committed
// publication manifest. It never invents source_invocation_id.
type CommittedRoleReport struct {
	Role             string
	Path             string
	SHA256           string
	ByteLength       int
	ProviderInstance string
	AttemptID        string
	ContentType      string
}

// RoleReportURI is one project-relative role-report identity projected from a
// committed publication snapshot and its verified support inventory.
type RoleReportURI struct {
	Role       string
	URI        string
	SHA256     string
	ByteLength int
}

// ProjectCommittedRoleReports reopens role-report inventory from the already
// schema/semantic-verified committed manifest and cross-checks each entry
// against final role outcome and attempt authority. Callers must not invent
// paths from coordinator summaries.
func ProjectCommittedRoleReports(snapshot ports.CommittedPublicationSnapshot) ([]CommittedRoleReport, error) {
	if !snapshot.Valid() {
		return nil, fmt.Errorf("publication role reports: committed snapshot is invalid")
	}
	var manifest runManifestWire
	if err := unmarshalCanonicalPublicationRecord(snapshot.Manifest().Bytes(), &manifest, "committed manifest"); err != nil {
		return nil, fmt.Errorf("publication role reports: %w", err)
	}
	var final finalReviewWire
	if err := unmarshalCanonicalPublicationRecord(snapshot.Final().Bytes(), &final, "committed final review"); err != nil {
		return nil, fmt.Errorf("publication role reports: %w", err)
	}
	if err := validateManifestRoleReports(manifest, final); err != nil {
		return nil, fmt.Errorf("publication role reports: %w", err)
	}
	reports := make([]CommittedRoleReport, 0, len(manifest.RoleReports))
	for _, report := range manifest.RoleReports {
		if _, err := domain.ParseAttemptID(report.AttemptID); err != nil {
			return nil, fmt.Errorf("publication role reports: invalid attempt_id")
		}
		reports = append(reports, CommittedRoleReport(report))
	}
	return reports, nil
}

// ProjectRoleReportURIs projects canonical project-relative role-report URIs
// from a P2 PublicationResult. Each URI is bound to the committed manifest
// inventory and the exact support artifact identities re-read before commit.
// Callers must not query the live directory or invent paths.
func ProjectRoleReportURIs(result PublicationResult) ([]RoleReportURI, error) {
	if result.Decision().Authority() != domain.PublicationAuthorityP2 {
		return nil, fmt.Errorf("publication role report URIs: P2 authority is required")
	}
	snapshot, ok := result.Snapshot()
	if !ok || !snapshot.Valid() {
		return nil, fmt.Errorf("publication role report URIs: committed snapshot is required")
	}
	reports, err := ProjectCommittedRoleReports(snapshot)
	if err != nil {
		return nil, err
	}
	var manifest runManifestWire
	if err := unmarshalCanonicalPublicationRecord(snapshot.Manifest().Bytes(), &manifest, "committed manifest"); err != nil {
		return nil, fmt.Errorf("publication role report URIs: %w", err)
	}
	sessionID, err := domain.ParseSessionID(manifest.SessionID)
	if err != nil {
		return nil, fmt.Errorf("publication role report URIs: invalid session identity")
	}
	runID, err := domain.ParseRunID(manifest.RunID)
	if err != nil {
		return nil, fmt.Errorf("publication role report URIs: invalid run identity")
	}
	supportByPath := make(map[string]RunSupportArtifactIdentity, len(result.PersistedRunSupportArtifacts()))
	for _, identity := range result.PersistedRunSupportArtifacts() {
		if !identity.valid() {
			return nil, fmt.Errorf("publication role report URIs: invalid support identity")
		}
		path := identity.Path()
		kind, classifyErr := ports.ClassifyRunSupportArtifactPath(sessionID, runID, path)
		if classifyErr != nil {
			return nil, fmt.Errorf("publication role report URIs: support path is not canonical: %w", classifyErr)
		}
		if kind != ports.RunSupportArtifactRoleReport {
			continue
		}
		if _, duplicate := supportByPath[path.String()]; duplicate {
			return nil, fmt.Errorf("publication role report URIs: duplicate support identity")
		}
		supportByPath[path.String()] = identity
	}
	uris := make([]RoleReportURI, 0, len(reports))
	seen := make(map[string]struct{}, len(reports))
	for _, report := range reports {
		if report.ContentType != "text/markdown" || report.Path != "role-reports/"+report.Role+".md" || report.ByteLength <= 0 {
			return nil, fmt.Errorf("publication role report URIs: invalid report metadata for %q", report.Role)
		}
		fullPath := sessionID.String() + "/" + runID.String() + "/" + report.Path
		identity, ok := supportByPath[fullPath]
		if !ok || identity.SHA256() != report.SHA256 {
			return nil, fmt.Errorf("publication role report URIs: support identity mismatch for %q", report.Role)
		}
		if _, duplicate := seen[report.Role]; duplicate {
			return nil, fmt.Errorf("publication role report URIs: duplicate role %q", report.Role)
		}
		seen[report.Role] = struct{}{}
		delete(supportByPath, fullPath)
		uris = append(uris, RoleReportURI{
			Role:       report.Role,
			URI:        ".mulgae/" + fullPath,
			SHA256:     report.SHA256,
			ByteLength: report.ByteLength,
		})
	}
	if len(supportByPath) != 0 {
		return nil, fmt.Errorf("publication role report URIs: support inventory has unbound role reports")
	}
	return uris, nil
}
