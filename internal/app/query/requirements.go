package query

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/irootkernel/mulgae/internal/app/evidence"
	"github.com/irootkernel/mulgae/internal/app/validation"
	"github.com/irootkernel/mulgae/internal/artifactwire"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

const RequirementsReadVersion = "mulgae-requirements-read.v1"
const requirementsCursorVersion = "mulgae-requirements-cursor.v1"

type verifiedRequirements struct {
	evaluation  domain.RequirementEvaluation
	inputSHA256 string
	references  []validation.RequirementContentReference
}

type RequirementItem struct {
	RequirementID     string                    `json:"requirement_id"`
	OwnerRole         domain.Role               `json:"owner_role"`
	Verdict           domain.RequirementVerdict `json:"verdict"`
	Origin            domain.AssessmentOrigin   `json:"origin"`
	Reason            domain.AssessmentReason   `json:"reason"`
	ContentPath       string                    `json:"content_path"`
	ContentSHA256     string                    `json:"content_sha256"`
	ContentByteLength int64                     `json:"content_byte_length"`
}

type RequirementsRead struct {
	SchemaVersion  string                        `json:"schema_version"`
	Receipt        InspectionReceipt             `json:"receipt"`
	Availability   domain.AssessmentAvailability `json:"availability"`
	InputSHA256    *string                       `json:"input_sha256"`
	SelectedCount  *int                          `json:"selected_count"`
	EvaluatedCount *int                          `json:"evaluated_count"`
	Items          []RequirementItem             `json:"items"`
	NextCursor     *string                       `json:"next_cursor"`
}

func (review CommittedReview) RequirementsEvaluation() domain.RequirementEvaluation {
	if review.requirements != nil {
		return review.requirements.evaluation
	}
	value, _ := domain.NewRequirementEvaluation(domain.AssessmentUnavailable, nil, nil)
	return value
}

func decodeRequirementsBinding(raw json.RawMessage) (*artifactIdentityDTO, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("requirements support declaration is absent")
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, nil
	}
	var value artifactIdentityDTO
	if err := decodeStrictDTO(raw, &value); err != nil || value.Path != validation.RequirementsSupportPath || !validSHA256(value.SHA256) {
		return nil, fmt.Errorf("requirements support declaration is invalid")
	}
	return &value, nil
}

func validateRequirementsBinding(final finalDTO, manifest manifestDTO) error {
	if final.SchemaVersion != artifactwire.ReviewArtifactV4 {
		if len(final.RequirementsSupport) != 0 || len(manifest.RequirementsSupport) != 0 {
			return fmt.Errorf("legacy publication declares requirements support")
		}
		return nil
	}
	left, err := decodeRequirementsBinding(final.RequirementsSupport)
	if err != nil {
		return err
	}
	right, err := decodeRequirementsBinding(manifest.RequirementsSupport)
	if err != nil {
		return err
	}
	if (left == nil) != (right == nil) || left != nil && *left != *right {
		return fmt.Errorf("requirements final/manifest bindings disagree")
	}
	return nil
}

func verifyRequirementsSupport(ctx context.Context, validator SchemaValidator, run ports.PublicationRun, review CommittedReview, artifacts map[string]ports.ImmutablePublicationArtifact, indexVersion string) (*verifiedRequirements, error) {
	final, err := decodeFinalDTO(review.FinalBytes())
	if err != nil {
		return nil, err
	}
	v4 := final.SchemaVersion == artifactwire.ReviewArtifactV4
	if v4 != (indexVersion == artifactwire.SupportIndexV4) {
		return nil, fmt.Errorf("requirements support index version mismatch")
	}
	availability := domain.AssessmentUnavailable
	var binding *artifactIdentityDTO
	if v4 {
		availability = domain.AssessmentNotRequested
		binding, err = decodeRequirementsBinding(final.RequirementsSupport)
		if err != nil {
			return nil, err
		}
	}
	evaluation, _ := domain.NewRequirementEvaluation(availability, nil, nil)
	result := &verifiedRequirements{evaluation: evaluation}
	prefix := run.SessionID().String() + "/" + run.RunID().String() + "/"
	expected := map[string]bool{}
	if binding != nil {
		metadata, ok := artifacts[prefix+binding.Path]
		if !ok || metadata.SHA256() != binding.SHA256 {
			return nil, fmt.Errorf("requirements support metadata is missing or changed")
		}
		input, ok := artifacts[prefix+validation.RequirementsInputPath]
		if !ok {
			return nil, fmt.Errorf("requirements input is missing")
		}
		roles := make([]domain.Role, len(final.RoleOutcomes))
		for i, role := range final.RoleOutcomes {
			roles[i] = domain.Role(role.Role)
		}
		admitted, err := validation.DecodeRequirementsInput(input.Bytes(), roles)
		if err != nil {
			return nil, err
		}
		evaluation, refs, err := validation.DecodeRequirementsSupport(ctx, validator, metadata.Bytes(), input.Bytes(), admitted.Requirements(), review.liveSource.NoChange)
		if err != nil {
			return nil, err
		}
		result = &verifiedRequirements{evaluation: evaluation, inputSHA256: admitted.SHA256(), references: refs}
		expected[prefix+binding.Path], expected[prefix+validation.RequirementsInputPath] = true, true
		images := map[string]string{}
		for _, image := range review.liveSource.BinaryEvidence {
			images[image.Side+"\x00"+image.Path] = image.SHA256
		}
		rows := evaluation.Assessments()
		for i, ref := range refs {
			artifact, ok := artifacts[prefix+ref.Path()]
			if !ok || !ref.Matches(artifact.Bytes()) {
				return nil, fmt.Errorf("requirements content is missing or changed")
			}
			content, err := validation.DecodeRequirementContent(artifact.Bytes(), rows[i], review.SourceIdentitySHA256())
			if err != nil {
				return nil, err
			}
			for _, item := range content.Evidence {
				current := item.Current
				claim, err := evidence.NewLiveClaim(review.liveSource.Identity, evidence.Side(current.Side), current.Path, current.LineStart, current.LineEnd, current.Quote)
				if err != nil {
					return nil, err
				}
				digest, err := claim.ExcerptSHA256([]byte(current.Quote))
				if err != nil || digest != current.CurrentExcerptSHA256 {
					return nil, fmt.Errorf("requirements evidence is rebound")
				}
				if item.Visual != nil && (rows[i].OwnerRole() != domain.RoleArtist || images[string(current.Side)+"\x00"+item.Visual.Path] != item.Visual.SHA256) {
					return nil, fmt.Errorf("requirements visual lacks selected retained binary")
				}
			}
			expected[prefix+ref.Path()] = true
		}
	}
	for name := range artifacts {
		if strings.HasPrefix(name, prefix+"requirements/") && !expected[name] {
			return nil, fmt.Errorf("unbound requirements support")
		}
	}
	return result, nil
}

type requirementsCursor struct {
	SchemaVersion      string `json:"schema_version"`
	ProjectBinding     string `json:"project_binding"`
	PublicationReceipt string `json:"publication_receipt"`
	RunID              string `json:"run_id"`
	Limit              int    `json:"limit"`
	Offset             int    `json:"offset"`
}

func (review CommittedReview) requirementsPage(receipt InspectionReceipt, limit int, cursor string) (RequirementsRead, error) {
	if limit == 0 {
		limit = 100
	}
	if limit < 1 || limit > 100 || len(cursor) > 4096 {
		return RequirementsRead{}, ErrCursorInvalid
	}
	identity, err := receipt.Identity()
	if err != nil {
		return RequirementsRead{}, err
	}
	scope := requirementsCursor{requirementsCursorVersion, receipt.ProjectBinding, identity.String(), receipt.RunID, limit, 0}
	if cursor != "" {
		parts := strings.Split(cursor, ".")
		if len(parts) != 2 {
			return RequirementsRead{}, ErrCursorInvalid
		}
		data, err := base64.RawURLEncoding.Strict().DecodeString(parts[0])
		var value requirementsCursor
		if err != nil || decodeStrictDTO(data, &value) != nil || readContractDigest(requirementsCursorVersion, data) != "sha256:"+parts[1] {
			return RequirementsRead{}, ErrCursorInvalid
		}
		canonical, _ := json.Marshal(value)
		if !bytes.Equal(canonical, data) || base64.RawURLEncoding.EncodeToString(data) != parts[0] || value.SchemaVersion != requirementsCursorVersion || value.Limit < 1 || value.Limit > 100 || value.Offset < 1 || value.Offset%value.Limit != 0 {
			return RequirementsRead{}, ErrCursorInvalid
		}
		offset := value.Offset
		value.Offset = 0
		if value != scope {
			return RequirementsRead{}, ErrCursorMismatch
		}
		scope.Offset = offset
	}
	evaluation := review.RequirementsEvaluation()
	result := RequirementsRead{SchemaVersion: RequirementsReadVersion, Receipt: receipt, Availability: evaluation.Availability(), Items: []RequirementItem{}}
	selected, evaluated, known := evaluation.Counts()
	if known {
		result.SelectedCount, result.EvaluatedCount = &selected, &evaluated
	}
	if review.requirements != nil && review.requirements.inputSHA256 != "" {
		digest := review.requirements.inputSHA256
		result.InputSHA256 = &digest
	}
	rows := evaluation.Assessments()
	if cursor != "" && scope.Offset >= len(rows) {
		return RequirementsRead{}, ErrCursorInvalid
	}
	end := min(scope.Offset+limit, len(rows))
	for i := scope.Offset; i < end; i++ {
		row, ref := rows[i], review.requirements.references[i]
		result.Items = append(result.Items, RequirementItem{row.RequirementID(), row.OwnerRole(), row.Verdict(), row.Origin(), row.Reason(), ref.Path(), ref.SHA256(), ref.ByteLength()})
	}
	if end < len(rows) {
		scope.Offset = end
		data, _ := json.Marshal(scope)
		next := base64.RawURLEncoding.EncodeToString(data) + "." + strings.TrimPrefix(readContractDigest(requirementsCursorVersion, data), "sha256:")
		result.NextCursor = &next
	}
	return result, nil
}

func RequirementContentURI(runID, id, binding, receipt, digest string, offset int64) string {
	return contentURI("mulgae://runs/"+runID+"/requirements/"+id, [][2]string{{"project_binding", binding}, {"publication_receipt", receipt}, {"content_sha256", digest}}, offset)
}

func (context *readContext) requirementContent(ctx context.Context, node *contextRun, id string) ([]byte, error) {
	for i, row := range node.review.RequirementsEvaluation().Assessments() {
		if row.RequirementID() != id {
			continue
		}
		ref := node.review.requirements.references[i]
		path, _ := ports.NewSafeRelativePath(node.run.SessionID().String() + "/" + node.run.RunID().String() + "/" + ref.Path())
		artifact, err := context.indexedArtifact(ctx, node, path)
		if err != nil {
			return nil, err
		}
		body := artifact.Bytes()
		if !ref.Matches(body) {
			return nil, typedFailure("query.read_requirement", domain.FailureArtifact, "requirements content identity changed", nil)
		}
		return body, nil
	}
	return nil, typedFailure("query.read_requirement", domain.FailureConfiguration, "requirement is unavailable in this publication", nil)
}

func (service *Service) ReadRequirement(ctx context.Context, run ports.PublicationRun, binding domain.ProjectBinding, id string, continuation ContentContinuation) (ContentChunk, error) {
	if !domain.ValidRequirementID(id) {
		return ContentChunk{}, ErrCursorInvalid
	}
	return service.readContent(ctx, run, binding, continuation, func(snapshot contentSnapshot, identity domain.PublicationReceipt) (ContentChunk, error) {
		body, err := snapshot.context.requirementContent(ctx, snapshot.node, id)
		if err != nil {
			return ContentChunk{}, err
		}
		chunk, err := NewContentChunk(body, "application/json", true, identity, continuation)
		chunk.RequirementID = id
		return chunk, err
	})
}
