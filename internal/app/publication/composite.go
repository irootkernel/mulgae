package publication

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

const (
	compositeFinalSchemaAsset    = "https://mulgae.local/schemas/mulgae-composite-review-artifact.v1.schema.json"
	compositeManifestSchemaAsset = "https://mulgae.local/schemas/mulgae-composite-run-manifest.v1.schema.json"
)

type CompositeSourceInput struct {
	Kind             string
	Role             domain.Role
	RunID            domain.RunID
	ReviewID         domain.ReviewID
	AttemptID        domain.AttemptID
	RoleReportSHA256 string
}

type CompositeRoleInput struct {
	Role             domain.Role
	Required         bool
	Outcome          string
	AttemptID        domain.AttemptID
	ProviderInstance string
	ValidFindingIDs  []string
	SourceRunID      domain.RunID
	SourceReviewID   domain.ReviewID
	ReportsOnly      bool
}

type CompositeFindingInput struct {
	ID, Fingerprint                    string
	Role                               domain.Role
	Severity                           domain.Severity
	Title, Description, Recommendation string
	Confidence                         domain.Confidence
	Lifecycle                          domain.FindingLifecycle
	SourceRunID                        domain.RunID
	SourceReviewID                     domain.ReviewID
	SourceAttemptID                    domain.AttemptID
	SourceFindingID                    string
}

type CompositeRoleReportInput struct {
	Role             domain.Role
	AttemptID        domain.AttemptID
	ProviderInstance string
	SHA256           string
	Bytes            []byte
	SourceRunID      domain.RunID
}

type CompositeCandidateInput struct {
	SessionID        domain.SessionID
	RunID            domain.RunID
	Fingerprint      domain.CompositionFingerprint
	RootRunID        domain.RunID
	RootReviewID     domain.ReviewID
	Target           domain.TargetIdentity
	TargetBytes      []byte
	CapturedArchive  []byte
	Threshold        domain.Severity
	Sources          []CompositeSourceInput
	Roles            []CompositeRoleInput
	RoleReports      []CompositeRoleReportInput
	Findings         []CompositeFindingInput
	ContentVerdict   domain.ContentVerdict
	CoverageStatus   domain.CoverageStatus
	ExtractionStatus domain.StructuredExtractionStatus
	CIDecision       domain.CIDecision
	CIReasonCodes    []string
}

type PreparedCompositeCandidate struct{ input CompositeCandidateInput }

func PrepareCompositeCandidate(input CompositeCandidateInput) (PreparedCompositeCandidate, error) {
	input.TargetBytes = cloneBytes(input.TargetBytes)
	input.CapturedArchive = cloneBytes(input.CapturedArchive)
	input.Sources = append([]CompositeSourceInput(nil), input.Sources...)
	input.Roles = append([]CompositeRoleInput(nil), input.Roles...)
	input.RoleReports = append([]CompositeRoleReportInput(nil), input.RoleReports...)
	for index := range input.RoleReports {
		input.RoleReports[index].Bytes = cloneBytes(input.RoleReports[index].Bytes)
	}
	input.Findings = append([]CompositeFindingInput(nil), input.Findings...)
	input.CIReasonCodes = append([]string(nil), input.CIReasonCodes...)
	for index := range input.Roles {
		input.Roles[index].ValidFindingIDs = append([]string(nil), input.Roles[index].ValidFindingIDs...)
	}
	candidate := PreparedCompositeCandidate{input: input}
	if err := candidate.validate(); err != nil {
		return PreparedCompositeCandidate{}, fmt.Errorf("publication composite candidate: %w", err)
	}
	return candidate, nil
}

func (candidate PreparedCompositeCandidate) SessionID() domain.SessionID {
	return candidate.input.SessionID
}
func (candidate PreparedCompositeCandidate) RunID() domain.RunID { return candidate.input.RunID }
func (candidate PreparedCompositeCandidate) Valid() bool         { return candidate.validate() == nil }

func (candidate PreparedCompositeCandidate) validate() error {
	in := candidate.input
	expected, err := in.Fingerprint.RunID()
	if err != nil || expected != in.RunID {
		return fmt.Errorf("run ID does not match composition fingerprint")
	}
	if _, err := domain.ParseSessionID(in.SessionID.String()); err != nil {
		return fmt.Errorf("session ID: %w", err)
	}
	if _, err := domain.ParseRunID(in.RootRunID.String()); err != nil {
		return fmt.Errorf("root run ID: %w", err)
	}
	if _, err := domain.ParseReviewID(in.RootReviewID.String()); err != nil {
		return fmt.Errorf("root review ID: %w", err)
	}
	if err := validateTarget(in.Target); err != nil || len(in.TargetBytes) == 0 || sha256Identifier(in.TargetBytes) != "sha256:"+in.Target.SHA256() {
		return fmt.Errorf("target material is invalid")
	}
	if !in.Threshold.Valid() || !in.ContentVerdict.Valid() || in.CoverageStatus != domain.CoverageComplete || !in.ExtractionStatus.Valid() || !in.CIDecision.Valid() || validateReasonCodes(in.CIReasonCodes) != nil {
		return fmt.Errorf("outcome axes are invalid")
	}
	if len(in.Sources) == 0 || len(in.Sources) != len(in.Roles) || len(in.Roles) > len(domain.FixedRoleOrder()) {
		return fmt.Errorf("source and role inventories are incomplete")
	}
	recoveryCoordinates := make([]domain.CompositionSource, 0, len(in.Sources))
	sources := make(map[domain.Role]CompositeSourceInput, len(in.Sources))
	for index, source := range in.Sources {
		if !source.Role.Valid() || index > 0 && roleOrdinal(in.Sources[index-1].Role) >= roleOrdinal(source.Role) || source.Kind != "root" && source.Kind != "recovery" || !validSHA256(source.RoleReportSHA256) {
			return fmt.Errorf("source inventory is invalid")
		}
		if _, duplicate := sources[source.Role]; duplicate {
			return fmt.Errorf("source role is duplicated")
		}
		if _, err := domain.ParseRunID(source.RunID.String()); err != nil {
			return err
		}
		if _, err := domain.ParseReviewID(source.ReviewID.String()); err != nil {
			return err
		}
		if _, err := domain.ParseAttemptID(source.AttemptID.String()); err != nil {
			return err
		}
		sources[source.Role] = source
		if source.Kind == "recovery" {
			coordinate, err := domain.NewCompositionSource(source.Role, source.RunID, source.ReviewID, source.AttemptID)
			if err != nil {
				return err
			}
			recoveryCoordinates = append(recoveryCoordinates, coordinate)
		}
	}
	recomputed, err := domain.NewCompositionFingerprint(in.RootRunID, recoveryCoordinates)
	if err != nil || recomputed != in.Fingerprint {
		return fmt.Errorf("fingerprint does not match selected recoveries")
	}
	reports := make(map[domain.Role]CompositeRoleReportInput, len(in.Roles))
	for _, report := range in.RoleReports {
		if _, duplicate := reports[report.Role]; duplicate || !report.Role.Valid() || len(report.Bytes) == 0 || !utf8.Valid(report.Bytes) || len(strings.TrimSpace(string(report.Bytes))) == 0 || sha256Identifier(report.Bytes) != report.SHA256 {
			return fmt.Errorf("role report is invalid")
		}
		reports[report.Role] = report
	}
	for index, role := range in.Roles {
		if !role.Role.Valid() || index > 0 && roleOrdinal(in.Roles[index-1].Role) >= roleOrdinal(role.Role) || role.Outcome != "completed" && role.Outcome != "degraded" || !validProviderInstance(role.ProviderInstance) {
			return fmt.Errorf("role inventory is invalid")
		}
		if _, err := domain.ParseAttemptID(role.AttemptID.String()); err != nil {
			return err
		}
		report, ok := reports[role.Role]
		source, sourceOK := sources[role.Role]
		if !ok || !sourceOK || report.AttemptID != role.AttemptID || report.ProviderInstance != role.ProviderInstance || report.SourceRunID != role.SourceRunID || source.RunID != role.SourceRunID || source.ReviewID != role.SourceReviewID || source.AttemptID != role.AttemptID || source.RoleReportSHA256 != report.SHA256 {
			return fmt.Errorf("role report binding is invalid")
		}
	}
	roleFindingIDs := make(map[domain.Role]map[string]struct{}, len(in.Roles))
	for _, role := range in.Roles {
		ids := make(map[string]struct{}, len(role.ValidFindingIDs))
		for _, id := range role.ValidFindingIDs {
			if !validFindingID(id) {
				return fmt.Errorf("role finding identity is invalid")
			}
			ids[id] = struct{}{}
		}
		roleFindingIDs[role.Role] = ids
	}
	for _, finding := range in.Findings {
		ids, ok := roleFindingIDs[finding.Role]
		if !ok || !validFindingID(finding.ID) || !validSHA256(finding.Fingerprint) || !finding.Severity.Valid() || !finding.Confidence.Valid() || !finding.Lifecycle.Valid() {
			return fmt.Errorf("finding inventory is invalid")
		}
		if _, selected := ids[finding.ID]; !selected {
			return fmt.Errorf("finding is not selected by its role")
		}
		delete(ids, finding.ID)
		source := sources[finding.Role]
		if finding.SourceRunID != source.RunID || finding.SourceReviewID != source.ReviewID || finding.SourceAttemptID != source.AttemptID || !validFindingID(finding.SourceFindingID) {
			return fmt.Errorf("finding source binding is invalid")
		}
	}
	for _, ids := range roleFindingIDs {
		if len(ids) != 0 {
			return fmt.Errorf("role references an absent finding")
		}
	}
	return nil
}

func (candidate PreparedCompositeCandidate) ValidatedCandidateSHA256() string {
	if !candidate.Valid() {
		return ""
	}
	digest := sha256.New()
	write := func(value string) {
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(value)))
		_, _ = digest.Write(size[:])
		_, _ = digest.Write([]byte(value))
	}
	write("Mulgae-COMPOSITE-PUBLICATION-CANDIDATE/1")
	write(candidate.input.Fingerprint.String())
	write(candidate.input.SessionID.String())
	write(candidate.input.RunID.String())
	write(candidate.input.RootRunID.String())
	write(candidate.input.RootReviewID.String())
	write(string(candidate.input.Target.Kind()))
	write(candidate.input.Target.SHA256())
	write(candidate.input.Target.RepositoryID())
	write(candidate.input.Target.BaseObjectID())
	write(candidate.input.Target.HeadObjectID())
	write(candidate.input.Target.HeadTreeObjectID())
	write(candidate.input.Target.IndexTreeObjectID())
	write(string(candidate.input.Target.GitMode()))
	write(string(candidate.input.TargetBytes))
	write(string(candidate.input.CapturedArchive))
	write(string(candidate.input.Threshold))
	write(string(candidate.input.ContentVerdict))
	write(string(candidate.input.CoverageStatus))
	write(string(candidate.input.ExtractionStatus))
	write(string(candidate.input.CIDecision))
	for _, reason := range candidate.input.CIReasonCodes {
		write(reason)
	}
	for _, source := range candidate.input.Sources {
		write(source.Kind)
		write(string(source.Role))
		write(source.RunID.String())
		write(source.ReviewID.String())
		write(source.AttemptID.String())
		write(source.RoleReportSHA256)
	}
	for _, report := range candidate.input.RoleReports {
		write(string(report.Role))
		write(report.AttemptID.String())
		write(report.ProviderInstance)
		write(report.SHA256)
		write(string(report.Bytes))
		write(report.SourceRunID.String())
	}
	for _, role := range candidate.input.Roles {
		write(string(role.Role))
		write(fmt.Sprintf("%t", role.Required))
		write(role.Outcome)
		write(role.AttemptID.String())
		write(role.ProviderInstance)
		write(role.SourceRunID.String())
		write(role.SourceReviewID.String())
		write(fmt.Sprintf("%t", role.ReportsOnly))
		for _, findingID := range role.ValidFindingIDs {
			write(findingID)
		}
	}
	for _, finding := range candidate.input.Findings {
		write(finding.ID)
		write(finding.Fingerprint)
		write(string(finding.Role))
		write(string(finding.Severity))
		write(finding.Title)
		write(finding.Description)
		write(finding.Recommendation)
		write(string(finding.Confidence))
		write(string(finding.Lifecycle))
		write(finding.SourceRunID.String())
		write(finding.SourceReviewID.String())
		write(finding.SourceAttemptID.String())
		write(finding.SourceFindingID)
	}
	return "sha256:" + fmt.Sprintf("%x", digest.Sum(nil))
}

type compositeSourceWire struct {
	Kind             string `json:"kind"`
	Role             string `json:"role"`
	RunID            string `json:"run_id"`
	ReviewID         string `json:"review_id"`
	AttemptID        string `json:"attempt_id"`
	RoleReportSHA256 string `json:"role_report_sha256"`
}

type compositeCompositionWire struct {
	Fingerprint  string                `json:"fingerprint"`
	RootRunID    string                `json:"root_run_id"`
	RootReviewID string                `json:"root_review_id"`
	Sources      []compositeSourceWire `json:"sources"`
}

type compositeRoleWire struct {
	Role                                 string
	Required                             bool
	Outcome, AttemptID, ProviderInstance string
	ValidFindingIDs                      []string
	SourceRunID, SourceReviewID          string
}

func (value compositeRoleWire) MarshalJSON() ([]byte, error) {
	type wire struct {
		Role             string   `json:"role"`
		Required         bool     `json:"required"`
		Outcome          string   `json:"outcome"`
		AttemptID        string   `json:"attempt_id"`
		ProviderInstance string   `json:"provider_instance"`
		ValidFindingIDs  []string `json:"valid_finding_ids"`
		SourceRunID      string   `json:"source_run_id"`
		SourceReviewID   string   `json:"source_review_id"`
	}
	return marshalCanonical(wire(value))
}

type compositeFindingSourceWire struct{ RunID, ReviewID, AttemptID, FindingID string }
type compositeFindingWire struct {
	ID, Fingerprint, Role, Severity, Title, Description, Recommendation, Confidence, Lifecycle string
	Source                                                                                     compositeFindingSourceWire
}

func (value compositeFindingWire) MarshalJSON() ([]byte, error) {
	type source struct {
		RunID     string `json:"run_id"`
		ReviewID  string `json:"review_id"`
		AttemptID string `json:"attempt_id"`
		FindingID string `json:"finding_id"`
	}
	type wire struct {
		ID             string `json:"id"`
		Fingerprint    string `json:"fingerprint"`
		Role           string `json:"role"`
		Severity       string `json:"severity"`
		Title          string `json:"title"`
		Description    string `json:"description"`
		Recommendation string `json:"recommendation"`
		Confidence     string `json:"confidence"`
		Lifecycle      string `json:"lifecycle"`
		Source         source `json:"source"`
	}
	return marshalCanonical(wire{value.ID, value.Fingerprint, value.Role, value.Severity, value.Title, value.Description, value.Recommendation, value.Confidence, value.Lifecycle, source(value.Source)})
}

type compositeFinalWire struct {
	SchemaVersion, SessionID, RunID, ReviewID, RunType, CreatedAt                             string
	Target                                                                                    compositeTargetWire
	ReviewComposition                                                                         compositeCompositionWire
	ContentVerdict, CoverageStatus, StructuredExtractionStatus, PublicationStatus, CIDecision string
	CIReasonCodes                                                                             []string
	SeverityThreshold                                                                         severityThresholdWire
	RoleOutcomes                                                                              []compositeRoleWire
	Findings                                                                                  []compositeFindingWire
	Limitations                                                                               []string
}

type compositeTargetWire struct {
	ContentSHA256 string `json:"content_sha256"`
	ManifestPath  string `json:"manifest_path"`
}

func (value compositeFinalWire) MarshalJSON() ([]byte, error) {
	type wire struct {
		SchemaVersion              string                   `json:"schema_version"`
		SessionID                  string                   `json:"session_id"`
		RunID                      string                   `json:"run_id"`
		ReviewID                   string                   `json:"review_id"`
		RunType                    string                   `json:"run_type"`
		CreatedAt                  string                   `json:"created_at"`
		Target                     compositeTargetWire      `json:"target"`
		ReviewComposition          compositeCompositionWire `json:"review_composition"`
		ContentVerdict             string                   `json:"content_verdict"`
		CoverageStatus             string                   `json:"coverage_status"`
		StructuredExtractionStatus string                   `json:"structured_extraction_status"`
		PublicationStatus          string                   `json:"publication_status"`
		CIDecision                 string                   `json:"ci_decision"`
		CIReasonCodes              []string                 `json:"ci_reason_codes"`
		SeverityThreshold          severityThresholdWire    `json:"severity_threshold"`
		RoleOutcomes               []compositeRoleWire      `json:"role_outcomes"`
		Findings                   []compositeFindingWire   `json:"findings"`
		Limitations                []string                 `json:"limitations"`
	}
	return marshalCanonical(wire(value))
}

type compositeManifestRoleWire struct {
	Role        string `json:"role"`
	Path        string `json:"path"`
	SHA256      string `json:"sha256"`
	ByteLength  int    `json:"byte_length"`
	AttemptID   string `json:"attempt_id"`
	SourceRunID string `json:"source_run_id"`
}

type compositeManifestWire struct {
	SchemaVersion              string                      `json:"schema_version"`
	SessionID                  string                      `json:"session_id"`
	RunID                      string                      `json:"run_id"`
	RunType                    string                      `json:"run_type"`
	State                      string                      `json:"state"`
	Sealed                     bool                        `json:"sealed"`
	CreatedAt                  string                      `json:"created_at"`
	CompletedAt                string                      `json:"completed_at"`
	Target                     manifestTargetWire          `json:"target"`
	ImmutableLineage           immutableLineageWire        `json:"immutable_lineage"`
	ReviewComposition          compositeCompositionWire    `json:"review_composition"`
	SelectedRoles              []string                    `json:"selected_roles"`
	RequiredRoles              []string                    `json:"required_roles"`
	ContentVerdict             string                      `json:"content_verdict"`
	CoverageStatus             string                      `json:"coverage_status"`
	StructuredExtractionStatus string                      `json:"structured_extraction_status"`
	PublicationStatus          string                      `json:"publication_status"`
	CIDecision                 string                      `json:"ci_decision"`
	CIReasonCodes              []string                    `json:"ci_reason_codes"`
	PersistedJournalState      string                      `json:"persisted_journal_state"`
	DurableObservationClass    string                      `json:"durable_observation_class"`
	DerivedPublicationStatus   string                      `json:"derived_publication_status"`
	PublicationAuthority       string                      `json:"publication_authority"`
	RecoveryJournal            recoveryJournalWire         `json:"recovery_journal"`
	CompositeIdentity          compositeIdentityWire       `json:"composite_identity"`
	RecoveryAction             string                      `json:"recovery_action"`
	FinalReview                finalReviewIdentityWire     `json:"final_review"`
	RoleReports                []compositeManifestRoleWire `json:"role_reports"`
	ExitCode                   int                         `json:"exit_code"`
}

func (candidate PreparedCompositeCandidate) compositionWire() compositeCompositionWire {
	sources := make([]compositeSourceWire, len(candidate.input.Sources))
	for i, source := range candidate.input.Sources {
		sources[i] = compositeSourceWire{source.Kind, string(source.Role), source.RunID.String(), source.ReviewID.String(), source.AttemptID.String(), source.RoleReportSHA256}
	}
	return compositeCompositionWire{candidate.input.Fingerprint.String(), candidate.input.RootRunID.String(), candidate.input.RootReviewID.String(), sources}
}

func (candidate PreparedCompositeCandidate) Build(ctx context.Context, validator SchemaValidator, reviewID domain.ReviewID, createdAt time.Time, epoch uint64) (PublicationBundle, error) {
	if ctx == nil || nilSchemaValidator(validator) || epoch == 0 || !candidate.Valid() {
		return PublicationBundle{}, fmt.Errorf("publication composite build: invalid input")
	}
	if err := ctx.Err(); err != nil {
		return PublicationBundle{}, err
	}
	created, err := canonicalTime(createdAt)
	if err != nil {
		return PublicationBundle{}, err
	}
	paths, err := publicationPaths(candidate.input.SessionID, candidate.input.RunID, reviewID, epoch)
	if err != nil {
		return PublicationBundle{}, err
	}
	edgeBytes, err := marshalCanonical(lineageEdgeWire{SchemaVersion: lineageEdgeV1, EdgeID: "e_" + reviewID.String(), Child: lineageChildWire{SessionID: candidate.input.SessionID.String(), RunID: candidate.input.RunID.String(), ReviewID: reviewID.String()}})
	if err != nil {
		return PublicationBundle{}, err
	}
	edge, err := immutableArtifact(paths.lineageEdge, edgeBytes)
	if err != nil {
		return PublicationBundle{}, err
	}
	support, reportWires, err := candidate.buildCompositeSupport(paths)
	if err != nil {
		return PublicationBundle{}, err
	}
	index, err := buildRunSupportIndex(paths.supportIndex, support)
	if err != nil {
		return PublicationBundle{}, err
	}
	support = append(support, index)
	roles := make([]compositeRoleWire, len(candidate.input.Roles))
	selected := make([]string, len(roles))
	required := make([]string, 0, len(roles))
	for i, role := range candidate.input.Roles {
		findingIDs := append([]string(nil), role.ValidFindingIDs...)
		if findingIDs == nil {
			findingIDs = []string{}
		}
		roles[i] = compositeRoleWire{string(role.Role), role.Required, role.Outcome, role.AttemptID.String(), role.ProviderInstance, findingIDs, role.SourceRunID.String(), role.SourceReviewID.String()}
		selected[i] = string(role.Role)
		if role.Required {
			required = append(required, string(role.Role))
		}
	}
	findings := make([]compositeFindingWire, len(candidate.input.Findings))
	for i, finding := range candidate.input.Findings {
		findings[i] = compositeFindingWire{finding.ID, finding.Fingerprint, string(finding.Role), string(finding.Severity), finding.Title, finding.Description, finding.Recommendation, string(finding.Confidence), string(finding.Lifecycle), compositeFindingSourceWire{finding.SourceRunID.String(), finding.SourceReviewID.String(), finding.SourceAttemptID.String(), finding.SourceFindingID}}
	}
	composition := candidate.compositionWire()
	finalBytes, err := marshalCanonical(compositeFinalWire{"mulgae-composite-review-artifact.v1", candidate.input.SessionID.String(), candidate.input.RunID.String(), reviewID.String(), string(domain.RunTypeComposite), created, compositeTargetWire{ContentSHA256: "sha256:" + candidate.input.Target.SHA256(), ManifestPath: targetManifestPath}, composition, string(candidate.input.ContentVerdict), string(candidate.input.CoverageStatus), string(candidate.input.ExtractionStatus), string(domain.PublicationCommitted), string(candidate.input.CIDecision), candidate.input.CIReasonCodes, severityThresholdWire{RequestChangesAtOrAbove: string(candidate.input.Threshold), PolicySource: "root_review"}, roles, findings, []string{}})
	if err != nil {
		return PublicationBundle{}, err
	}
	finalSchema, _ := ports.ParseAssetID(compositeFinalSchemaAsset)
	if err := validator.Validate(ctx, finalSchema, cloneBytes(finalBytes)); err != nil {
		return PublicationBundle{}, fmt.Errorf("publication composite final schema: %w", err)
	}
	finalIdentity, err := ports.NewFinalReviewIdentity(reviewID, paths.final, sha256Identifier(finalBytes))
	if err != nil {
		return PublicationBundle{}, err
	}
	final, err := ports.NewFinalReviewArtifact(finalIdentity, finalBytes)
	if err != nil {
		return PublicationBundle{}, err
	}
	staged, err := immutableArtifact(paths.staged, finalBytes)
	if err != nil {
		return PublicationBundle{}, err
	}
	exit := int(domain.ExitCommittedPass)
	if candidate.input.CIDecision == domain.CIFail {
		exit = int(domain.ExitCommittedCIRejected)
	}
	recovery := recoveryJournalWire{ExpectedStaged: artifactIdentityWire{paths.staged.String(), final.Identity().SHA256()}, ExpectedFinal: artifactIdentityWire{final.Identity().Path().String(), final.Identity().SHA256()}, ValidatedCandidateSHA256: candidate.ValidatedCandidateSHA256()}
	identity := compositeIdentityWire{pathPointerWire{paths.manifest.String()}, artifactIdentityWire{edge.Path().String(), edge.SHA256()}, pathPointerWire{paths.epoch.String()}, artifactIdentityWire{index.Path().String(), index.SHA256()}}
	lineage := immutableLineageWire{LineageEdgePath: edge.Path().String(), LineageEdgeSHA256: edge.SHA256()}
	manifestBytes, err := marshalCanonical(compositeManifestWire{"mulgae-composite-run-manifest.v1", candidate.input.SessionID.String(), candidate.input.RunID.String(), string(domain.RunTypeComposite), string(domain.RunCompleted), true, created, created, manifestTargetWire{targetManifestPath, "sha256:" + candidate.input.Target.SHA256()}, lineage, composition, selected, required, string(candidate.input.ContentVerdict), string(candidate.input.CoverageStatus), string(candidate.input.ExtractionStatus), string(domain.PublicationCommitted), string(candidate.input.CIDecision), candidate.input.CIReasonCodes, string(domain.JournalManifestCommitted), string(domain.DurableObservationP2Committed), string(domain.PublicationCommitted), string(domain.PublicationAuthorityP2), recovery, identity, string(domain.RecoveryActionReconstructCompletedStatus), finalReviewIdentityWire{reviewID.String(), final.Identity().Path().String(), final.Identity().SHA256()}, reportWires, exit})
	if err != nil {
		return PublicationBundle{}, err
	}
	manifestSchema, _ := ports.ParseAssetID(compositeManifestSchemaAsset)
	if err := validator.Validate(ctx, manifestSchema, cloneBytes(manifestBytes)); err != nil {
		return PublicationBundle{}, fmt.Errorf("publication composite manifest schema: %w", err)
	}
	manifest, err := immutableArtifact(paths.manifest, manifestBytes)
	if err != nil {
		return PublicationBundle{}, err
	}
	epochBytes, _ := marshalCanonical(publicationEpochWire{publicationEpochV1, epoch, artifactIdentityWire{manifest.Path().String(), manifest.SHA256()}, artifactIdentityWire{edge.Path().String(), edge.SHA256()}, artifactIdentityWire{final.Identity().Path().String(), final.Identity().SHA256()}})
	epochArtifact, err := immutableArtifact(paths.epoch, epochBytes)
	if err != nil {
		return PublicationBundle{}, err
	}
	publicationEpoch, err := ports.NewPublicationEpoch(epoch, epochArtifact)
	if err != nil {
		return PublicationBundle{}, err
	}
	restart := restartStateWire{candidate.input.SessionID.String(), candidate.input.RunID.String(), string(domain.JournalManifestCommitted), recovery.ExpectedStaged, recovery.ExpectedFinal, candidate.ValidatedCandidateSHA256(), epoch, exit, manifest.Path().String(), edge.Path().String(), epochArtifact.Path().String()}
	journalBytes, _ := marshalCanonical(publicationJournalWire{publicationJournalV1, restart})
	journal, _ := mutableDocument(paths.journal, journalBytes)
	statusBytes, _ := marshalCanonical(publicationStatusWire{publicationStatusV1, string(domain.PublicationCommitted), string(domain.PublicationAuthorityP2), restart})
	status, _ := mutableDocument(paths.status, statusBytes)
	return PublicationBundle{final: final, manifest: manifest, lineageEdge: edge, epoch: publicationEpoch, staged: staged, journal: journal, status: status, excerpts: support}, nil
}

func (candidate PreparedCompositeCandidate) buildCompositeSupport(paths publicationPathsSet) ([]ports.ImmutablePublicationArtifact, []compositeManifestRoleWire, error) {
	prefix := candidate.input.SessionID.String() + "/" + candidate.input.RunID.String() + "/"
	targetPath, _ := ports.NewSafeRelativePath(prefix + "target/target.bytes")
	target, err := immutableArtifact(targetPath, candidate.input.TargetBytes)
	if err != nil {
		return nil, nil, err
	}
	artifacts := []ports.ImmutablePublicationArtifact{target}
	var archiveIdentity *artifactIdentityWire
	if len(candidate.input.CapturedArchive) > 0 {
		material, err := ports.UnmarshalCapturedReviewMaterial(candidate.input.CapturedArchive)
		if err != nil {
			return nil, nil, err
		}
		archive, err := ports.NewCapturedReviewArchive(material)
		if err != nil {
			return nil, nil, err
		}
		path, _ := ports.NewSafeRelativePath(prefix + "target/captured-review.json")
		artifact, _ := immutableArtifact(path, archive.Manifest())
		artifacts = append(artifacts, artifact)
		value := artifactIdentityWire{artifact.Path().String(), artifact.SHA256()}
		archiveIdentity = &value
		for _, blob := range archive.Blobs() {
			path, _ := ports.NewSafeRelativePath(prefix + "target/" + blob.Path().String())
			artifact, _ := immutableArtifact(path, blob.Bytes())
			artifacts = append(artifacts, artifact)
		}
	}
	manifestPath, _ := ports.NewSafeRelativePath(prefix + targetManifestPath)
	manifestBytes, err := marshalCanonical(runtimeTargetManifestWire{SchemaVersion: "mulgae-runtime-target-manifest.v1", Target: artifactIdentityWire{target.Path().String(), target.SHA256()}, CapturedArchive: archiveIdentity, TargetKind: string(candidate.input.Target.Kind()), RepositoryID: candidate.input.Target.RepositoryID(), BaseObjectID: candidate.input.Target.BaseObjectID(), HeadObjectID: candidate.input.Target.HeadObjectID(), HeadTreeObjectID: candidate.input.Target.HeadTreeObjectID(), IndexTreeObjectID: candidate.input.Target.IndexTreeObjectID(), GitMode: string(candidate.input.Target.GitMode()), Prompts: []artifactIdentityWire{}, SelectedReplayPrompts: []selectedReplayPromptWire{}})
	if err != nil {
		return nil, nil, err
	}
	targetManifest, _ := immutableArtifact(manifestPath, manifestBytes)
	artifacts = append(artifacts, targetManifest)
	reports := append([]CompositeRoleReportInput(nil), candidate.input.RoleReports...)
	sort.Slice(reports, func(i, j int) bool { return roleOrdinal(reports[i].Role) < roleOrdinal(reports[j].Role) })
	wires := make([]compositeManifestRoleWire, len(reports))
	for i, report := range reports {
		relative := "role-reports/" + string(report.Role) + ".md"
		path, _ := ports.NewSafeRelativePath(prefix + relative)
		artifact, _ := immutableArtifact(path, report.Bytes)
		artifacts = append(artifacts, artifact)
		wires[i] = compositeManifestRoleWire{string(report.Role), relative, artifact.SHA256(), len(report.Bytes), report.AttemptID.String(), report.SourceRunID.String()}
	}
	return artifacts, wires, nil
}

func validateCompositeBundleSemantics(bundle PublicationBundle) error {
	if !bundle.final.Valid() || !bundle.manifest.Valid() || !bundle.lineageEdge.Valid() || !bundle.epoch.Valid() || !bundle.staged.Valid() || !bundle.journal.Valid() || !bundle.status.Valid() {
		return fmt.Errorf("invalid composite publication member")
	}
	if !bytes.Equal(bundle.final.Bytes(), bundle.staged.Bytes()) || bundle.final.Identity().SHA256() != bundle.staged.SHA256() {
		return fmt.Errorf("composite staged final mismatch")
	}
	var final struct {
		SchemaVersion string `json:"schema_version"`
		SessionID     string `json:"session_id"`
		RunID         string `json:"run_id"`
		ReviewID      string `json:"review_id"`
		RunType       string `json:"run_type"`
	}
	if err := json.Unmarshal(bundle.final.Bytes(), &final); err != nil {
		return err
	}
	if final.SchemaVersion != "mulgae-composite-review-artifact.v1" || final.RunType != string(domain.RunTypeComposite) {
		return fmt.Errorf("invalid composite final")
	}
	var manifest struct {
		SchemaVersion     string                  `json:"schema_version"`
		SessionID         string                  `json:"session_id"`
		RunID             string                  `json:"run_id"`
		RunType           string                  `json:"run_type"`
		FinalReview       finalReviewIdentityWire `json:"final_review"`
		CompositeIdentity compositeIdentityWire   `json:"composite_identity"`
		RecoveryJournal   recoveryJournalWire     `json:"recovery_journal"`
		ExitCode          int                     `json:"exit_code"`
	}
	if err := json.Unmarshal(bundle.manifest.Bytes(), &manifest); err != nil {
		return err
	}
	if manifest.SchemaVersion != "mulgae-composite-run-manifest.v1" || manifest.SessionID != final.SessionID || manifest.RunID != final.RunID || manifest.RunType != final.RunType || manifest.FinalReview.SHA256 != bundle.final.Identity().SHA256() || manifest.CompositeIdentity.SupportIndex.SHA256 == "" {
		return fmt.Errorf("invalid composite manifest binding")
	}
	return nil
}

func validateCompositeSnapshot(run ports.PublicationRun, snapshot ports.CommittedPublicationSnapshot) (domain.OperationalExitCode, error) {
	var final struct {
		SchemaVersion string `json:"schema_version"`
		SessionID     string `json:"session_id"`
		RunID         string `json:"run_id"`
		ReviewID      string `json:"review_id"`
		RunType       string `json:"run_type"`
	}
	if err := json.Unmarshal(snapshot.Final().Bytes(), &final); err != nil {
		return 0, err
	}
	var manifest struct {
		SchemaVersion        string                  `json:"schema_version"`
		SessionID            string                  `json:"session_id"`
		RunID                string                  `json:"run_id"`
		RunType              string                  `json:"run_type"`
		PublicationAuthority string                  `json:"publication_authority"`
		FinalReview          finalReviewIdentityWire `json:"final_review"`
		CompositeIdentity    compositeIdentityWire   `json:"composite_identity"`
		ExitCode             int                     `json:"exit_code"`
	}
	if err := json.Unmarshal(snapshot.Manifest().Bytes(), &manifest); err != nil {
		return 0, err
	}
	var edge lineageEdgeWire
	if err := json.Unmarshal(snapshot.LineageEdge().Bytes(), &edge); err != nil {
		return 0, err
	}
	var epoch publicationEpochWire
	if err := json.Unmarshal(snapshot.Epoch().Record().Bytes(), &epoch); err != nil {
		return 0, err
	}
	if final.SchemaVersion != "mulgae-composite-review-artifact.v1" || manifest.SchemaVersion != "mulgae-composite-run-manifest.v1" || final.SessionID != run.SessionID().String() || final.RunID != run.RunID().String() || manifest.SessionID != final.SessionID || manifest.RunID != final.RunID || final.RunType != string(domain.RunTypeComposite) || manifest.RunType != final.RunType || manifest.PublicationAuthority != string(domain.PublicationAuthorityP2) || manifest.FinalReview.SHA256 != snapshot.Final().Identity().SHA256() || manifest.FinalReview.Path != snapshot.Final().Identity().Path().String() || manifest.CompositeIdentity.Manifest.Path != snapshot.Manifest().Path().String() || manifest.CompositeIdentity.LineageEdge.SHA256 != snapshot.LineageEdge().SHA256() || manifest.CompositeIdentity.Epoch.Path != snapshot.Epoch().Record().Path().String() || edge.Child.ReviewID != final.ReviewID || edge.ParentRunID != nil || edge.SourceRunID != nil || epoch.StoreEpoch != snapshot.Epoch().Value() || epoch.Manifest.SHA256 != snapshot.Manifest().SHA256() || epoch.FinalReview.SHA256 != snapshot.Final().Identity().SHA256() {
		return 0, fmt.Errorf("composite committed snapshot bindings are invalid")
	}
	exit := domain.OperationalExitCode(manifest.ExitCode)
	if exit != domain.ExitCommittedPass && exit != domain.ExitCommittedCIRejected {
		return 0, fmt.Errorf("composite exit is invalid")
	}
	return exit, nil
}
