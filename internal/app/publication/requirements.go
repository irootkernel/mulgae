package publication

import (
	"fmt"

	"github.com/irootkernel/mulgae/internal/app/validation"
	"github.com/irootkernel/mulgae/internal/artifactwire"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

type preparedRequirements struct {
	result   validation.RequirementResults
	metadata []byte
}

// WithRequirements is the internal v4 producer boundary. Public objective-only
// requests retain v3 until the verified-read activation in TASK-029.
func WithRequirements(live PreparedLiveCandidate, result validation.RequirementResults) (PreparedLiveCandidate, error) {
	candidate := live.candidate
	if !candidate.Valid() || candidate.requirements != nil || !result.Valid() || result.SourceIdentitySHA256() != candidate.target.sha256 || candidate.noChange != (result.Evaluation().Availability() == domain.AssessmentNotRun) {
		return PreparedLiveCandidate{}, fmt.Errorf("requirements publication: invalid candidate binding")
	}
	roles := make([]domain.Role, len(candidate.roles))
	for i, r := range candidate.roles {
		roles[i] = r.role
	}
	if err := domain.ValidateRequirements(result.Input().Requirements(), roles); err != nil {
		return PreparedLiveCandidate{}, err
	}
	selected, evaluated, _ := result.Evaluation().Counts()
	wire := requirementsSupportWire{SchemaVersion: RequirementsSupportVersion, InputPath: RequirementsInputPath, InputSHA256: result.Input().SHA256(), InputByteLength: int64(len(result.Input().Bytes())), Availability: result.Evaluation().Availability(), SelectedCount: selected, EvaluatedCount: evaluated, Items: make([]requirementSupportItemWire, selected)}
	content := result.Contents()
	images := make(map[string]string)
	for _, image := range candidate.target.live.binary {
		images[string(image.Side())+"\x00"+image.Path().String()] = image.FileSHA256()
	}
	for i, row := range result.Evaluation().Assessments() {
		decoded, err := validation.DecodeRequirementContent(content[i], row, candidate.target.sha256)
		if err != nil {
			return PreparedLiveCandidate{}, err
		}
		if err := validateRequirementImages(decoded, images); err != nil {
			return PreparedLiveCandidate{}, err
		}
		wire.Items[i] = requirementSupportItemWire{RequirementID: row.RequirementID(), OwnerRole: row.OwnerRole(), Verdict: row.Verdict(), Origin: row.Origin(), Reason: row.Reason(), ContentPath: fmt.Sprintf("requirements/items/%03d.json", i), ContentSHA256: sha256Identifier(content[i]), ContentByteLength: int64(len(content[i]))}
	}
	metadata, err := marshalCanonical(wire)
	if err != nil {
		return PreparedLiveCandidate{}, err
	}
	candidate.requirements = &preparedRequirements{result: result, metadata: metadata}
	return PreparedLiveCandidate{candidate: candidate}, nil
}
func (candidate PreparedCandidate) requirementsBinding() *artifactIdentityWire {
	if candidate.requirements == nil {
		return nil
	}
	return &artifactIdentityWire{Path: RequirementsSupportPath, SHA256: sha256Identifier(candidate.requirements.metadata)}
}
func (candidate PreparedCandidate) buildRequirementsSupport(existing []ports.ImmutablePublicationArtifact) ([]ports.ImmutablePublicationArtifact, error) {
	if candidate.requirements == nil {
		return existing, nil
	}
	prefix := candidate.sessionID.String() + "/" + candidate.runID.String() + "/"
	add := func(path string, body []byte) error {
		safe, err := ports.NewSafeRelativePath(prefix + path)
		if err != nil {
			return err
		}
		artifact, err := immutableArtifact(safe, body)
		if err == nil {
			existing = append(existing, artifact)
		}
		return err
	}
	result := candidate.requirements.result
	if err := add(RequirementsInputPath, result.Input().Bytes()); err != nil {
		return nil, err
	}
	for i, body := range result.Contents() {
		if err := add(fmt.Sprintf("requirements/items/%03d.json", i), body); err != nil {
			return nil, err
		}
	}
	if err := add(RequirementsSupportPath, candidate.requirements.metadata); err != nil {
		return nil, err
	}
	return existing, nil
}

func validatePublishedRequirements(final finalReviewWire, artifacts map[string]ports.ImmutablePublicationArtifact) error {
	v4 := final.SchemaVersion == artifactwire.ReviewArtifactV4
	prefix := final.SessionID + "/" + final.RunID + "/"
	binding := final.RequirementsSupport
	expected := make(map[string]bool)
	if !v4 && binding != nil {
		return fmt.Errorf("requirements publication: legacy binding")
	}
	if binding != nil {
		if binding.Path != RequirementsSupportPath || !validSHA256(binding.SHA256) {
			return fmt.Errorf("requirements publication: invalid binding")
		}
		metadata, ok := artifacts[prefix+RequirementsSupportPath]
		if !ok || metadata.SHA256() != binding.SHA256 {
			return fmt.Errorf("requirements publication: missing or changed metadata")
		}
		input, ok := artifacts[prefix+RequirementsInputPath]
		if !ok {
			return fmt.Errorf("requirements publication: missing input")
		}
		roles := make([]domain.Role, len(final.RoleOutcomes))
		for i, r := range final.RoleOutcomes {
			roles[i] = domain.Role(r.Role)
		}
		admitted, err := validation.DecodeRequirementsInput(input.Bytes(), roles)
		if err != nil {
			return err
		}
		// Strict metadata decoding remains bounded; prose is kept in separate files.
		var wire requirementsSupportWire
		if err := unmarshalCanonicalPublicationRecord(metadata.Bytes(), &wire, "requirements support"); err != nil {
			return err
		}
		evaluation, references, err := decodeRequirementsSupport(metadata.Bytes(), input.Bytes(), admitted.Requirements(), final.Target.LiveSource.NoChange)
		if err != nil {
			return err
		}
		expected[prefix+RequirementsSupportPath] = true
		expected[prefix+RequirementsInputPath] = true
		images := make(map[string]string)
		for _, image := range final.Target.LiveSource.BinaryEvidence {
			images[image.Side+"\x00"+image.Path] = image.SHA256
		}
		for i, ref := range references {
			body, ok := artifacts[prefix+ref.Path()]
			if !ok || !ref.Matches(body.Bytes()) {
				return fmt.Errorf("requirements publication: missing or changed content")
			}
			decoded, err := validation.DecodeRequirementContent(body.Bytes(), evaluation.Assessments()[i], final.Target.LiveSource.SourceIdentitySHA256)
			if err != nil {
				return err
			}
			if err := validateRequirementImages(decoded, images); err != nil {
				return err
			}
			expected[prefix+ref.Path()] = true
		}
	}
	for path := range artifacts {
		if len(path) >= len(prefix+"requirements/") && path[:len(prefix+"requirements/")] == prefix+"requirements/" && !expected[path] {
			return fmt.Errorf("requirements publication: unbound support")
		}
	}
	return nil
}

func validateRequirementImages(content validation.RequirementContent, images map[string]string) error {
	for _, item := range content.Evidence {
		if item.Visual != nil && images[string(item.Current.Side)+"\x00"+item.Visual.Path] != item.Visual.SHA256 {
			return fmt.Errorf("requirements publication: visual reference lacks selected binary")
		}
	}
	return nil
}
