package query

import (
	"fmt"
	"reflect"

	"github.com/irootkernel/mulgae/internal/domain"
)

func compositeReference(runValue, reviewValue, hash, kind string) (domain.SourceReference, error) {
	run, err := domain.ParseRunID(runValue)
	if err != nil {
		return domain.SourceReference{}, err
	}
	if kind == "failed_run_recovery" && reviewValue == "" {
		return domain.NewRecoverySourceReference(run, hash)
	}
	if kind == "published_review" && hash == "" {
		review, err := domain.ParseReviewID(reviewValue)
		if err != nil {
			return domain.SourceReference{}, err
		}
		return domain.NewPublishedSourceReference(run, review)
	}
	return domain.SourceReference{}, fmt.Errorf("composite source reference is ambiguous")
}

func validateCompositeSourceReferences(final compositeFinalDTO, manifest compositeManifestDTO) error {
	if final.SchemaVersion == "mulgae-composite-review-artifact.v1" {
		if manifest.SchemaVersion != "mulgae-composite-run-manifest.v1" {
			return fmt.Errorf("composite schema versions differ")
		}
		return nil
	}
	if final.SchemaVersion != "mulgae-composite-review-artifact.v2" || manifest.SchemaVersion != "mulgae-composite-run-manifest.v2" {
		return fmt.Errorf("composite schema version is invalid")
	}
	composition := final.ReviewComposition
	if !reflect.DeepEqual(composition, manifest.ReviewComposition) {
		return fmt.Errorf("composite source inventories differ")
	}
	root, err := compositeReference(composition.RootRunID, composition.RootReviewID, composition.RootRecoveryManifestSHA256, composition.RootSourceKind)
	if err != nil || root.Kind() != "failed_run_recovery" {
		return fmt.Errorf("composite recovery root is invalid")
	}
	if len(composition.Sources) == 0 || len(composition.Sources) != len(final.RoleOutcomes) || len(composition.Sources) != len(manifest.RoleReports) || len(manifest.SelectedRoles) != len(final.RoleOutcomes) {
		return fmt.Errorf("composite role source inventory is incomplete")
	}
	sources := make(map[string]compositeSourceDTO)
	references := make(map[string]domain.SourceReference)
	coordinates := make([]domain.CompositionSource, 0)
	required := []string{}
	for index, source := range composition.Sources {
		role := domain.Role(source.Role)
		if !role.Valid() {
			return fmt.Errorf("composite source role is invalid")
		}
		if _, exists := sources[source.Role]; exists {
			return fmt.Errorf("composite source role is duplicated")
		}
		reference, err := compositeReference(source.RunID, source.ReviewID, source.RecoveryManifestSHA256, source.SourceKind)
		if err != nil {
			return err
		}
		attempt, err := domain.ParseAttemptID(source.AttemptID)
		if err != nil {
			return err
		}
		switch source.Kind {
		case "root":
			if reference != root {
				return fmt.Errorf("composite root role source differs")
			}
		case "recovery":
			if reference.Kind() != "published_review" {
				return fmt.Errorf("composite selected recovery is not published")
			}
			coordinate, err := domain.NewCompositionSource(role, reference.RunID(), reference.ReviewID(), attempt)
			if err != nil {
				return err
			}
			coordinates = append(coordinates, coordinate)
		default:
			return fmt.Errorf("composite source selection kind is invalid")
		}
		outcome := final.RoleOutcomes[index]
		report := manifest.RoleReports[index]
		roleReference, err := compositeReference(outcome.SourceRunID, outcome.SourceReviewID, outcome.SourceRecoveryManifestSHA256, outcome.SourceKind)
		if err != nil || roleReference != reference || outcome.Role != source.Role || outcome.AttemptID != source.AttemptID || report.Role != source.Role || report.AttemptID != source.AttemptID || report.SourceRunID != source.RunID || report.SHA256 != source.RoleReportSHA256 || manifest.SelectedRoles[index] != source.Role {
			return fmt.Errorf("composite role reference binding differs")
		}
		if outcome.Required {
			required = append(required, outcome.Role)
		}
		sources[source.Role] = source
		references[source.Role] = reference
	}
	if !reflect.DeepEqual(required, manifest.RequiredRoles) {
		return fmt.Errorf("composite required policy differs")
	}
	fingerprint, err := domain.NewRecoveryCompositionFingerprint(root, coordinates)
	if err != nil {
		return err
	}
	run, err := fingerprint.RunID()
	if err != nil || fingerprint.String() != composition.Fingerprint || run.String() != final.RunID {
		return fmt.Errorf("composite fingerprint does not bind recovery mapping")
	}
	for _, finding := range final.Findings {
		source, exists := sources[finding.Role]
		if !exists {
			return fmt.Errorf("composite finding role is absent")
		}
		reference, err := compositeReference(finding.Source.RunID, finding.Source.ReviewID, finding.Source.RecoveryManifestSHA256, finding.Source.SourceKind)
		if err != nil || reference != references[finding.Role] || finding.Source.AttemptID != source.AttemptID || !validFindingID(finding.Source.FindingID) {
			return fmt.Errorf("composite finding source binding differs")
		}
	}
	return nil
}
