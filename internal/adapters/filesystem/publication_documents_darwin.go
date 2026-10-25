//go:build darwin && arm64

package filesystem

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/irootkernel/mulgae/internal/artifactwire"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

type publicationArtifactWire artifactwire.ArtifactIdentity

type publicationRestartWire = artifactwire.RestartState

type publicationJournalWire = artifactwire.PublicationJournal

type publicationEpochWire = artifactwire.PublicationEpoch

type publicationLineageChildWire = artifactwire.LineageChild

type publicationLineageWire = artifactwire.LineageEdge

type publicationJournalFacts struct {
	state                    domain.PersistedJournalState
	sessionID                string
	runID                    string
	reviewID                 domain.ReviewID
	stagedPath               ports.SafeRelativePath
	finalPath                ports.SafeRelativePath
	manifest                 ports.SafeRelativePath
	lineageEdge              ports.SafeRelativePath
	epoch                    ports.SafeRelativePath
	finalSHA256              string
	validatedCandidateSHA256 string
	storeEpoch               uint64
	normalExit               domain.OperationalExitCode
}

type publicationManifestFacts struct {
	sessionID     string
	runID         string
	finalReviewID string
	finalPath     string
	finalSHA256   string
	lineagePath   string
	lineageSHA256 string
	manifestPath  string
	epochPath     string
	exitCode      int
	committed     bool
}

func parsePublicationJournal(run ports.PublicationRun, path ports.SafeRelativePath, documentBytes []byte) (ports.ObservedMutablePublicationDocument, publicationJournalFacts, error) {
	var wire publicationJournalWire
	if err := strictDecodePublicationJSON(documentBytes, &wire); err != nil {
		return ports.ObservedMutablePublicationDocument{}, publicationJournalFacts{}, err
	}
	if wire.SchemaVersion != artifactwire.PublicationJournalV1 {
		return ports.ObservedMutablePublicationDocument{}, publicationJournalFacts{}, errors.New("unknown journal schema")
	}
	facts, err := parsePublicationRestart(run, wire.RestartState)
	if err != nil {
		return ports.ObservedMutablePublicationDocument{}, publicationJournalFacts{}, err
	}
	document, err := ports.NewObservedMutablePublicationDocument(ports.MutablePublicationJournal, path, publicationSHA256(documentBytes), documentBytes)
	if err != nil {
		return ports.ObservedMutablePublicationDocument{}, publicationJournalFacts{}, err
	}
	return document, facts, nil
}

func parsePublicationRestart(run ports.PublicationRun, wire publicationRestartWire) (publicationJournalFacts, error) {
	if wire.SessionID != run.SessionID().String() || wire.RunID != run.RunID().String() {
		return publicationJournalFacts{}, errors.New("restart IDs do not match run")
	}
	state := domain.PersistedJournalState(wire.PersistedJournalState)
	if !state.Valid() || wire.StoreEpoch == 0 {
		return publicationJournalFacts{}, errors.New("invalid restart state or epoch")
	}
	if !validPublicationSHA256(wire.ExpectedStaged.SHA256) || !validPublicationSHA256(wire.ExpectedFinal.SHA256) ||
		!validPublicationSHA256(wire.ValidatedCandidateSHA256) || wire.ExpectedStaged.SHA256 != wire.ExpectedFinal.SHA256 {
		return publicationJournalFacts{}, errors.New("restart hashes do not agree")
	}
	stagedPath, err := ports.NewSafeRelativePath(wire.ExpectedStaged.Path)
	if err != nil {
		return publicationJournalFacts{}, fmt.Errorf("staged path: %w", err)
	}
	finalPath, err := ports.NewSafeRelativePath(wire.ExpectedFinal.Path)
	if err != nil {
		return publicationJournalFacts{}, fmt.Errorf("final path: %w", err)
	}
	manifestPath, err := ports.NewSafeRelativePath(wire.ManifestPath)
	if err != nil {
		return publicationJournalFacts{}, fmt.Errorf("manifest path: %w", err)
	}
	lineagePath, err := ports.NewSafeRelativePath(wire.LineageEdgePath)
	if err != nil {
		return publicationJournalFacts{}, fmt.Errorf("lineage path: %w", err)
	}
	epochPath, err := ports.NewSafeRelativePath(wire.EpochPath)
	if err != nil {
		return publicationJournalFacts{}, fmt.Errorf("epoch path: %w", err)
	}
	reviewID, err := reviewIDFromFinalPath(run, finalPath)
	if err != nil {
		return publicationJournalFacts{}, err
	}
	if stagedPath != mustPublicationSafePath(artifactwire.StagedFinalPath(run.SessionID().String(), run.RunID().String(), reviewID.String())) ||
		manifestPath != publicationManifestPath(run) ||
		lineagePath != mustPublicationSafePath(artifactwire.LineageEdgePath(reviewID.String())) ||
		epochPath != mustPublicationSafePath(artifactwire.EpochPath(wire.StoreEpoch)) {
		return publicationJournalFacts{}, errors.New("restart path is not canonical")
	}
	normalExit := domain.OperationalExitCode(wire.NormalExit)
	if normalExit != domain.ExitCommittedPass && normalExit != domain.ExitCommittedCIRejected && normalExit != domain.ExitIncompleteCoverage {
		return publicationJournalFacts{}, errors.New("invalid stored normal exit")
	}
	return publicationJournalFacts{
		state: state, sessionID: wire.SessionID, runID: wire.RunID, reviewID: reviewID, stagedPath: stagedPath, finalPath: finalPath,
		manifest: manifestPath, lineageEdge: lineagePath, epoch: epochPath, finalSHA256: wire.ExpectedFinal.SHA256,
		validatedCandidateSHA256: wire.ValidatedCandidateSHA256, storeEpoch: wire.StoreEpoch, normalExit: normalExit,
	}, nil
}

func reviewIDFromFinalPath(run ports.PublicationRun, finalPath ports.SafeRelativePath) (domain.ReviewID, error) {
	prefix := run.SessionID().String() + "/" + run.RunID().String() + "/review_"
	if !strings.HasPrefix(finalPath.String(), prefix) || !strings.HasSuffix(finalPath.String(), ".json") {
		return domain.ReviewID{}, errors.New("final path is not canonical")
	}
	value := strings.TrimSuffix(strings.TrimPrefix(finalPath.String(), prefix), ".json")
	if strings.Contains(value, "/") {
		return domain.ReviewID{}, errors.New("final path contains extra component")
	}
	return domain.ParseReviewID(value)
}
func strictDecodePublicationJSON(document []byte, destination any) error {
	if len(document) == 0 {
		return errors.New("empty JSON document")
	}
	if err := rejectDuplicatePublicationJSONKeys(document); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := requirePublicationJSONEOF(decoder); err != nil {
		return err
	}
	return nil
}

func rejectDuplicatePublicationJSONKeys(document []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(document))
	if err := consumePublicationJSONValue(decoder); err != nil {
		return err
	}
	return requirePublicationJSONEOF(decoder)
}

func consumePublicationJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, objectOrArray := token.(json.Delim)
	if !objectOrArray {
		return nil
	}
	var closing json.Delim
	switch delimiter {
	case '{':
		closing = '}'
		seen := make(map[string]struct{})
		for decoder.More() {
			token, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := token.(string)
			if !ok {
				return errors.New("JSON object key is not a string")
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("duplicate JSON key %q", key)
			}
			seen[key] = struct{}{}
			if err := consumePublicationJSONValue(decoder); err != nil {
				return err
			}
		}
	case '[':
		closing = ']'
		for decoder.More() {
			if err := consumePublicationJSONValue(decoder); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("invalid JSON delimiter %q", delimiter)
	}
	end, err := decoder.Token()
	if err != nil {
		return err
	}
	if end != closing {
		return errors.New("unbalanced JSON document")
	}
	return nil
}

func requirePublicationJSONEOF(decoder *json.Decoder) error {
	var extra any
	err := decoder.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return errors.New("trailing JSON value")
	}
	return err
}

func publicationJSONObject(document []byte) (map[string]json.RawMessage, error) {
	if err := rejectDuplicatePublicationJSONKeys(document); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	var object map[string]json.RawMessage
	if err := decoder.Decode(&object); err != nil {
		return nil, err
	}
	if err := requirePublicationJSONEOF(decoder); err != nil {
		return nil, err
	}
	if object == nil {
		return nil, errors.New("JSON object is required")
	}
	return object, nil
}

func requiredPublicationJSON[T any](object map[string]json.RawMessage, key string) (T, error) {
	var value T
	raw, exists := object[key]
	if !exists {
		return value, fmt.Errorf("missing JSON field %q", key)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := decoder.Decode(&value); err != nil {
		return value, fmt.Errorf("JSON field %q: %w", key, err)
	}
	if err := requirePublicationJSONEOF(decoder); err != nil {
		return value, fmt.Errorf("JSON field %q: %w", key, err)
	}
	return value, nil
}

type publicationFinalFacts struct {
	sessionID string
	runID     string
	reviewID  string
}

func parsePublicationFinalFacts(document []byte) (publicationFinalFacts, error) {
	object, err := publicationJSONObject(document)
	if err != nil {
		return publicationFinalFacts{}, err
	}
	schema, err := requiredPublicationJSON[string](object, "schema_version")
	if err != nil || schema != artifactwire.ReviewArtifactV1 && schema != artifactwire.ReviewArtifactV2 && schema != artifactwire.ReviewArtifactV3 && (schema != artifactwire.CompositeReviewArtifactV1 && schema != artifactwire.CompositeReviewArtifactV2) {
		return publicationFinalFacts{}, errors.New("invalid final review schema version")
	}
	sessionID, err := requiredPublicationJSON[string](object, "session_id")
	if err != nil {
		return publicationFinalFacts{}, err
	}
	runID, err := requiredPublicationJSON[string](object, "run_id")
	if err != nil {
		return publicationFinalFacts{}, err
	}
	reviewID, err := requiredPublicationJSON[string](object, "review_id")
	if err != nil {
		return publicationFinalFacts{}, err
	}
	if _, err := domain.ParseSessionID(sessionID); err != nil {
		return publicationFinalFacts{}, err
	}
	if _, err := domain.ParseRunID(runID); err != nil {
		return publicationFinalFacts{}, err
	}
	if _, err := domain.ParseReviewID(reviewID); err != nil {
		return publicationFinalFacts{}, err
	}
	return publicationFinalFacts{sessionID: sessionID, runID: runID, reviewID: reviewID}, nil
}

func parsePublicationManifestFacts(document []byte) (publicationManifestFacts, error) {
	object, err := publicationJSONObject(document)
	if err != nil {
		return publicationManifestFacts{}, err
	}
	schema, err := requiredPublicationJSON[string](object, "schema_version")
	if err != nil || schema != artifactwire.RunManifestV1 && schema != artifactwire.RunManifestV2 && schema != artifactwire.RunManifestV3 && (schema != artifactwire.CompositeRunManifestV1 && schema != artifactwire.CompositeRunManifestV2) {
		return publicationManifestFacts{}, errors.New("invalid manifest schema version")
	}
	sessionID, err := requiredPublicationJSON[string](object, "session_id")
	if err != nil {
		return publicationManifestFacts{}, err
	}
	runID, err := requiredPublicationJSON[string](object, "run_id")
	if err != nil {
		return publicationManifestFacts{}, err
	}
	publicationStatus, err := requiredPublicationJSON[string](object, "publication_status")
	if err != nil {
		return publicationManifestFacts{}, err
	}
	durableClass, err := requiredPublicationJSON[string](object, "durable_observation_class")
	if err != nil {
		return publicationManifestFacts{}, err
	}
	derivedStatus, err := requiredPublicationJSON[string](object, "derived_publication_status")
	if err != nil {
		return publicationManifestFacts{}, err
	}
	authority, err := requiredPublicationJSON[string](object, "publication_authority")
	if err != nil {
		return publicationManifestFacts{}, err
	}
	finalReview, err := requiredPublicationJSON[struct {
		ReviewID string `json:"review_id"`
		Path     string `json:"path"`
		SHA256   string `json:"sha256"`
	}](object, "final_review")
	if err != nil {
		return publicationManifestFacts{}, err
	}
	lineage, err := requiredPublicationJSON[struct {
		LineageEdgePath   string `json:"lineage_edge_path"`
		LineageEdgeSHA256 string `json:"lineage_edge_sha256"`
	}](object, "immutable_lineage")
	if err != nil {
		return publicationManifestFacts{}, err
	}
	composite, err := requiredPublicationJSON[struct {
		Manifest struct {
			Path string `json:"path"`
		} `json:"manifest"`
		LineageEdge publicationArtifactWire `json:"lineage_edge"`
		Epoch       struct {
			Path string `json:"path"`
		} `json:"epoch"`
	}](object, "composite_identity")
	if err != nil {
		return publicationManifestFacts{}, err
	}
	exitCode, err := requiredPublicationJSON[int](object, "exit_code")
	if err != nil {
		return publicationManifestFacts{}, err
	}
	if _, err := domain.ParseSessionID(sessionID); err != nil {
		return publicationManifestFacts{}, err
	}
	if _, err := domain.ParseRunID(runID); err != nil {
		return publicationManifestFacts{}, err
	}
	if _, err := domain.ParseReviewID(finalReview.ReviewID); err != nil {
		return publicationManifestFacts{}, err
	}
	if !validPublicationSHA256(finalReview.SHA256) || !validPublicationSHA256(lineage.LineageEdgeSHA256) ||
		composite.LineageEdge.Path != lineage.LineageEdgePath || composite.LineageEdge.SHA256 != lineage.LineageEdgeSHA256 {
		return publicationManifestFacts{}, errors.New("manifest artifact identities are invalid")
	}
	committed := publicationStatus == string(domain.PublicationCommitted) &&
		durableClass == string(domain.DurableObservationP2Committed) &&
		derivedStatus == string(domain.PublicationCommitted) &&
		authority == string(domain.PublicationAuthorityP2)
	return publicationManifestFacts{
		sessionID: sessionID, runID: runID, finalReviewID: finalReview.ReviewID, finalPath: finalReview.Path,
		finalSHA256: finalReview.SHA256, lineagePath: lineage.LineageEdgePath, lineageSHA256: lineage.LineageEdgeSHA256,
		manifestPath: composite.Manifest.Path, epochPath: composite.Epoch.Path, exitCode: exitCode, committed: committed,
	}, nil
}

func parsePublicationLineage(document []byte) (publicationLineageWire, error) {
	var wire publicationLineageWire
	if err := strictDecodePublicationJSON(document, &wire); err != nil {
		return publicationLineageWire{}, err
	}
	if (wire.SchemaVersion != artifactwire.LineageEdgeV1 && wire.SchemaVersion != artifactwire.LineageEdgeV2) || wire.EdgeID == "" ||
		wire.Child.SessionID == "" || wire.Child.RunID == "" || wire.Child.ReviewID == "" {
		return publicationLineageWire{}, errors.New("invalid lineage edge")
	}
	if wire.SchemaVersion == artifactwire.LineageEdgeV2 {
		if wire.SourceRunID == nil || wire.SourceReviewID != nil || wire.SourceRecoveryManifestSHA256 == nil || !validPublicationSHA256(*wire.SourceRecoveryManifestSHA256) || wire.SourceKind != "failed_run_recovery" || wire.SourceAttemptID == nil {
			return publicationLineageWire{}, errors.New("invalid recovery lineage edge")
		}
	} else if wire.SourceRecoveryManifestSHA256 != nil || wire.SourceKind != "" {
		return publicationLineageWire{}, errors.New("v1 lineage edge contains recovery fields")
	}
	if _, err := domain.ParseSessionID(wire.Child.SessionID); err != nil {
		return publicationLineageWire{}, err
	}
	if _, err := domain.ParseRunID(wire.Child.RunID); err != nil {
		return publicationLineageWire{}, err
	}
	if _, err := domain.ParseReviewID(wire.Child.ReviewID); err != nil {
		return publicationLineageWire{}, err
	}
	return wire, nil
}

func parsePublicationEpoch(document []byte) (publicationEpochWire, error) {
	var wire publicationEpochWire
	if err := strictDecodePublicationJSON(document, &wire); err != nil {
		return publicationEpochWire{}, err
	}
	if wire.SchemaVersion != artifactwire.PublicationEpochV1 || wire.StoreEpoch == 0 ||
		!validPublicationSHA256(wire.Manifest.SHA256) || !validPublicationSHA256(wire.LineageEdge.SHA256) || !validPublicationSHA256(wire.FinalReview.SHA256) {
		return publicationEpochWire{}, errors.New("invalid epoch record")
	}
	for _, artifact := range []artifactwire.ArtifactIdentity{wire.Manifest, wire.LineageEdge, wire.FinalReview} {
		if _, err := ports.NewSafeRelativePath(artifact.Path); err != nil {
			return publicationEpochWire{}, err
		}
	}
	return wire, nil
}
