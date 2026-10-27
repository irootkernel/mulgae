package validation

import (
	"encoding/json"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/irootkernel/mulgae/internal/artifactwire"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

const RequirementContentVersion = "mulgae-requirement-content.v1"

// RequirementContent is the separately retained, unbounded content of one
// normalized assessment. Bounded support/read envelopes contain its hash and
// path, not its prose. Decoding does not verify source bytes or publication.
type RequirementContent struct {
	SchemaVersion string                       `json:"schema_version"`
	RequirementID string                       `json:"requirement_id"`
	Rationale     string                       `json:"rationale"`
	Evidence      []RequirementContentEvidence `json:"evidence"`
	ExaminedScope string                       `json:"examined_scope"`
	Limitations   []string                     `json:"limitations"`
}

type RequirementContentEvidence struct {
	Current RequirementCurrentEvidence   `json:"current"`
	Visual  *artifactwire.VisualEvidence `json:"visual,omitempty"`
}

type RequirementCurrentEvidence struct {
	SourceIdentitySHA256 string              `json:"source_identity_sha256"`
	CurrentExcerptSHA256 string              `json:"current_excerpt_sha256"`
	Side                 CurrentEvidenceSide `json:"side"`
	Path                 string              `json:"path"`
	LineStart            int                 `json:"line_start"`
	LineEnd              int                 `json:"line_end"`
	Quote                string              `json:"quote"`
	Verification         string              `json:"verification"`
}

// DecodeRequirementContent is the prose-bearing semantic boundary. It reuses
// strict JSON admission without the structured-envelope schema adapter's byte
// ceiling. Evidence binding still requires the existing source verifier.
func DecodeRequirementContent(raw []byte, assessment domain.RequirementAssessment, sourceIdentitySHA256 string) (RequirementContent, error) {
	object, err := decodeJSONObject(raw, "requirement content")
	if err != nil || !requirementObjectFields(object, "schema_version", "requirement_id", "rationale", "evidence", "examined_scope", "limitations") {
		return RequirementContent{}, fmt.Errorf("requirement content: invalid JSON fields")
	}
	evidenceRows, ok := object["evidence"].([]any)
	if !ok || len(evidenceRows) > 32 {
		return RequirementContent{}, fmt.Errorf("requirement content: invalid evidence count")
	}
	for _, rawEvidence := range evidenceRows {
		evidenceObject, ok := rawEvidence.(map[string]any)
		if !ok || !(requirementObjectFields(evidenceObject, "current") || requirementObjectFields(evidenceObject, "current", "visual")) {
			return RequirementContent{}, fmt.Errorf("requirement content: invalid evidence fields")
		}
		current, ok := evidenceObject["current"].(map[string]any)
		if !ok || !requirementObjectFields(current, "source_identity_sha256", "current_excerpt_sha256", "side", "path", "line_start", "line_end", "quote", "verification") {
			return RequirementContent{}, fmt.Errorf("requirement content: invalid current evidence fields")
		}
		if visual, present := evidenceObject["visual"]; present {
			if !validRequirementVisualFields(visual) {
				return RequirementContent{}, fmt.Errorf("requirement content: invalid visual evidence fields")
			}
		}
	}
	var content RequirementContent
	if err := json.Unmarshal(raw, &content); err != nil || content.SchemaVersion != RequirementContentVersion || content.RequirementID != assessment.RequirementID() || !assessment.OwnerRole().Valid() || !assessment.Verdict().Valid() || !requirementContentText(content.Rationale, false) || !requirementContentText(content.ExaminedScope, true) || content.Limitations == nil || len(content.Limitations) > 20 {
		return RequirementContent{}, fmt.Errorf("requirement content: invalid identity or text")
	}
	for _, limitation := range content.Limitations {
		if !requirementContentText(limitation, false) {
			return RequirementContent{}, fmt.Errorf("requirement content: invalid limitation")
		}
	}
	for _, evidence := range content.Evidence {
		if err := validateRequirementContentEvidence(evidence.Current, sourceIdentitySHA256); err != nil {
			return RequirementContent{}, err
		}
		if visual := evidence.Visual; visual != nil {
			_, pathErr := ports.NewSafeRelativePath(visual.Path)
			digest, digestErr := canonicalTargetSHA256(visual.SHA256)
			if pathErr != nil || utf8.RuneCountInString(visual.Path) > 4096 || digestErr != nil || digest != visual.SHA256 || visual.Verification != "verified" || visual.BBox.X < 0 || visual.BBox.Y < 0 || visual.BBox.Width < 1 || visual.BBox.Height < 1 {
				return RequirementContent{}, fmt.Errorf("requirement content: invalid visual evidence")
			}
		}
	}
	if assessment.Origin() == domain.AssessmentDerived && (len(content.Evidence) != 0 || content.ExaminedScope != "") {
		return RequirementContent{}, fmt.Errorf("requirement content: derived assessment invents examined evidence")
	}
	if (assessment.Verdict() == domain.RequirementMet || assessment.Verdict() == domain.RequirementPartiallyMet) && len(content.Evidence) == 0 {
		return RequirementContent{}, fmt.Errorf("requirement content: supported verdict needs source evidence")
	}
	if assessment.Verdict() == domain.RequirementUnmet && len(content.Evidence) == 0 && (strings.TrimSpace(content.ExaminedScope) == "" || len(content.Limitations) == 0) {
		return RequirementContent{}, fmt.Errorf("requirement content: absence claim needs examined scope and limitations")
	}
	return content, nil
}

func validRequirementVisualFields(value any) bool {
	visual, ok := value.(map[string]any)
	if !ok || !requirementObjectFields(visual, "path", "sha256", "bbox", "verification") {
		return false
	}
	bbox, ok := visual["bbox"].(map[string]any)
	return ok && requirementObjectFields(bbox, "x", "y", "width", "height")
}

func requirementObjectFields(value map[string]any, fields ...string) bool {
	if len(value) != len(fields) {
		return false
	}
	for _, field := range fields {
		if _, ok := value[field]; !ok {
			return false
		}
	}
	return true
}

func requirementContentText(value string, empty bool) bool {
	return utf8.ValidString(value) && !strings.ContainsRune(value, 0) && (empty || strings.TrimSpace(value) != "")
}

func validateRequirementContentEvidence(current RequirementCurrentEvidence, identity string) error {
	_, pathErr := ports.NewSafeRelativePath(current.Path)
	canonicalIdentity, identityErr := canonicalTargetSHA256(identity)
	canonicalExcerpt, excerptErr := canonicalTargetSHA256(current.CurrentExcerptSHA256)
	if pathErr != nil || utf8.RuneCountInString(current.Path) > 4096 || identityErr != nil || canonicalIdentity != identity || excerptErr != nil || canonicalExcerpt != current.CurrentExcerptSHA256 || current.SourceIdentitySHA256 != identity || !current.Side.Valid() || current.LineStart < 1 || current.LineEnd < current.LineStart || !requirementContentText(current.Quote, false) || utf8.RuneCountInString(current.Quote) > 8000 || current.Verification != "verified" {
		return fmt.Errorf("requirement content: invalid source evidence binding")
	}
	return nil
}
