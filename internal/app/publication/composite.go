package publication

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/irootkernel/mulgae/internal/app/compositesupport"
	"github.com/irootkernel/mulgae/internal/artifactwire"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

type compositeSourceWire = artifactwire.CompositeSource

type compositeCompositionWire = artifactwire.CompositeComposition

type compositeTargetWire struct {
	ContentSHA256 string `json:"content_sha256"`
	ManifestPath  string `json:"manifest_path"`
}

type compositeManifestRoleWire = artifactwire.CompositeManifestRole

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

func validateCompositeBundleSemantics(bundle PublicationBundle) error {
	if !bundle.final.Valid() || !bundle.manifest.Valid() || !bundle.lineageEdge.Valid() || !bundle.epoch.Valid() || !bundle.staged.Valid() || !bundle.journal.Valid() || !bundle.status.Valid() {
		return fmt.Errorf("invalid composite publication member")
	}
	if !bytes.Equal(bundle.final.Bytes(), bundle.staged.Bytes()) || bundle.final.Identity().SHA256() != bundle.staged.SHA256() {
		return fmt.Errorf("composite staged final mismatch")
	}
	var final struct {
		SchemaVersion string              `json:"schema_version"`
		SessionID     string              `json:"session_id"`
		RunID         string              `json:"run_id"`
		ReviewID      string              `json:"review_id"`
		RunType       string              `json:"run_type"`
		Target        compositeTargetWire `json:"target"`
	}
	if err := json.Unmarshal(bundle.final.Bytes(), &final); err != nil {
		return err
	}
	if (final.SchemaVersion != artifactwire.CompositeReviewArtifactV1 && final.SchemaVersion != artifactwire.CompositeReviewArtifactV2) || final.RunType != string(domain.RunTypeComposite) {
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
	if (final.SchemaVersion == artifactwire.CompositeReviewArtifactV1) != (manifest.SchemaVersion == artifactwire.CompositeRunManifestV1) {
		return fmt.Errorf("composite final and manifest versions differ")
	}
	if (manifest.SchemaVersion != artifactwire.CompositeRunManifestV1 && manifest.SchemaVersion != artifactwire.CompositeRunManifestV2) || manifest.SessionID != final.SessionID || manifest.RunID != final.RunID || manifest.RunType != final.RunType || manifest.FinalReview.SHA256 != bundle.final.Identity().SHA256() || manifest.CompositeIdentity.SupportIndex.SHA256 == "" {
		return fmt.Errorf("invalid composite manifest binding")
	}
	session, err := domain.ParseSessionID(final.SessionID)
	if err != nil {
		return err
	}
	run, err := domain.ParseRunID(final.RunID)
	if err != nil {
		return err
	}
	artifacts := make(map[string]ports.ImmutablePublicationArtifact, len(bundle.excerpts))
	for _, artifact := range bundle.excerpts {
		if !artifact.Valid() {
			return fmt.Errorf("invalid composite support artifact")
		}
		if _, exists := artifacts[artifact.Path().String()]; exists {
			return fmt.Errorf("duplicate composite support artifact")
		}
		artifacts[artifact.Path().String()] = artifact
	}
	indexIdentity := manifest.CompositeIdentity.SupportIndex
	index, ok := artifacts[indexIdentity.Path]
	if !ok || index.SHA256() != indexIdentity.SHA256 {
		return fmt.Errorf("composite support index differs")
	}
	var support runSupportIndexWire
	if err := unmarshalCanonicalPublicationRecord(index.Bytes(), &support, "composite support index"); err != nil {
		return err
	}
	if support.SchemaVersion != artifactwire.SupportIndexV1 && support.SchemaVersion != artifactwire.SupportIndexV2 {
		return fmt.Errorf("invalid composite support version")
	}
	seen := map[string]bool{indexIdentity.Path: true}
	for _, identity := range support.Artifacts {
		artifact, ok := artifacts[identity.Path]
		if !ok || seen[identity.Path] || artifact.SHA256() != identity.SHA256 {
			return fmt.Errorf("composite support binding differs")
		}
		seen[identity.Path] = true
		kind, err := ports.ClassifyRunSupportArtifactPath(session, run, artifact.Path())
		if err != nil {
			return err
		}
		if support.SchemaVersion == artifactwire.SupportIndexV1 && (kind == ports.RunSupportArtifactCaptureManifest || kind == ports.RunSupportArtifactCompositeMetadata || kind == ports.RunSupportArtifactSourceFinding) {
			return fmt.Errorf("composite provenance requires support v2")
		}
	}
	if len(seen) != len(artifacts) {
		return fmt.Errorf("unbound composite support artifact")
	}
	if support.SchemaVersion == artifactwire.SupportIndexV2 {
		doc, err := compositesupport.Verify(session, run, final.Target.ContentSHA256, artifacts)
		if err != nil {
			return err
		}
		return compositesupport.VerifyFinal(doc, session, run, bundle.final.Bytes(), artifacts)
	}
	return nil
}

func validateCompositeMaterial(
	run ports.PublicationRun,
	finalArtifact ports.FinalReviewArtifact,
	manifestArtifact ports.ImmutablePublicationArtifact,
	lineageArtifact ports.ImmutablePublicationArtifact,
	epochArtifact ports.PublicationEpoch,
) (domain.OperationalExitCode, error) {
	var final struct {
		SchemaVersion string `json:"schema_version"`
		SessionID     string `json:"session_id"`
		RunID         string `json:"run_id"`
		ReviewID      string `json:"review_id"`
		RunType       string `json:"run_type"`
	}
	if err := json.Unmarshal(finalArtifact.Bytes(), &final); err != nil {
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
	if err := json.Unmarshal(manifestArtifact.Bytes(), &manifest); err != nil {
		return 0, err
	}
	var edge lineageEdgeWire
	if err := json.Unmarshal(lineageArtifact.Bytes(), &edge); err != nil {
		return 0, err
	}
	var epoch publicationEpochWire
	if err := json.Unmarshal(epochArtifact.Record().Bytes(), &epoch); err != nil {
		return 0, err
	}
	if (final.SchemaVersion == artifactwire.CompositeReviewArtifactV1) != (manifest.SchemaVersion == artifactwire.CompositeRunManifestV1) {
		return 0, fmt.Errorf("composite final and manifest versions differ")
	}
	if (final.SchemaVersion != artifactwire.CompositeReviewArtifactV1 && final.SchemaVersion != artifactwire.CompositeReviewArtifactV2) || (manifest.SchemaVersion != artifactwire.CompositeRunManifestV1 && manifest.SchemaVersion != artifactwire.CompositeRunManifestV2) || final.SessionID != run.SessionID().String() || final.RunID != run.RunID().String() || manifest.SessionID != final.SessionID || manifest.RunID != final.RunID || final.RunType != string(domain.RunTypeComposite) || manifest.RunType != final.RunType || manifest.PublicationAuthority != string(domain.PublicationAuthorityP2) || manifest.FinalReview.SHA256 != finalArtifact.Identity().SHA256() || manifest.FinalReview.Path != finalArtifact.Identity().Path().String() || manifest.CompositeIdentity.Manifest.Path != manifestArtifact.Path().String() || manifest.CompositeIdentity.LineageEdge.SHA256 != lineageArtifact.SHA256() || manifest.CompositeIdentity.Epoch.Path != epochArtifact.Record().Path().String() || edge.Child.ReviewID != final.ReviewID || edge.ParentRunID != nil || edge.SourceRunID != nil || epoch.StoreEpoch != epochArtifact.Value() || epoch.Manifest.SHA256 != manifestArtifact.SHA256() || epoch.FinalReview.SHA256 != finalArtifact.Identity().SHA256() {
		return 0, fmt.Errorf("composite committed snapshot bindings are invalid")
	}
	exit := domain.OperationalExitCode(manifest.ExitCode)
	if exit != domain.ExitCommittedPass && exit != domain.ExitCommittedCIRejected {
		return 0, fmt.Errorf("composite exit is invalid")
	}
	return exit, nil
}
