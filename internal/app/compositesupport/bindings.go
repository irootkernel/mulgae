package compositesupport

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

// VerifyFinal binds copied provenance and original content to the existing
// composite final format without rewriting that compatibility-sensitive format.
func VerifyFinal(doc Document, session domain.SessionID, run domain.RunID, raw []byte, artifacts map[string]ports.ImmutablePublicationArtifact) error {
	var final struct {
		RoleOutcomes []struct {
			Role     domain.Role `json:"role"`
			Provider string      `json:"provider_instance"`
		} `json:"role_outcomes"`
		ReviewComposition struct {
			Sources []struct {
				Role      domain.Role `json:"role"`
				RunID     string      `json:"run_id"`
				ReviewID  string      `json:"review_id"`
				Recovery  string      `json:"recovery_manifest_sha256"`
				AttemptID string      `json:"attempt_id"`
			} `json:"sources"`
		} `json:"review_composition"`
		Findings []json.RawMessage `json:"findings"`
	}
	if err := json.Unmarshal(raw, &final); err != nil {
		return err
	}
	if len(final.ReviewComposition.Sources) != len(doc.Sources) || len(final.Findings) != len(doc.Findings) || len(final.RoleOutcomes) != len(doc.Sources) {
		return fmt.Errorf("composite support/final inventories differ")
	}
	sources := map[domain.Role]Source{}
	for _, s := range doc.Sources {
		sources[s.Role] = s
	}
	for _, s := range final.ReviewComposition.Sources {
		copy, ok := sources[s.Role]
		if !ok || copy.RunID != s.RunID || copy.ReviewID != s.ReviewID || copy.RecoveryManifestSHA256 != s.Recovery || copy.AttemptID != s.AttemptID {
			return fmt.Errorf("copied source differs from final")
		}
	}
	for _, r := range final.RoleOutcomes {
		s, ok := sources[r.Role]
		if !ok {
			return fmt.Errorf("role source absent")
		}
		found := false
		for _, p := range s.ProviderIdentities {
			found = found || p == r.Provider
		}
		if !found {
			return fmt.Errorf("selected provider absent from provenance")
		}
	}
	findings := map[string]json.RawMessage{}
	for _, raw := range final.Findings {
		var id struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(raw, &id); err != nil {
			return err
		}
		findings[id.ID] = raw
	}
	prefix := session.String() + "/" + run.String() + "/"
	for _, f := range doc.Findings {
		raw, ok := findings[f.ID]
		if !ok {
			return fmt.Errorf("copied finding absent from final")
		}
		var selected map[string]json.RawMessage
		if err := json.Unmarshal(raw, &selected); err != nil {
			return err
		}
		var origin struct {
			RunID     string `json:"run_id"`
			ReviewID  string `json:"review_id"`
			Recovery  string `json:"recovery_manifest_sha256"`
			AttemptID string `json:"attempt_id"`
			FindingID string `json:"finding_id"`
		}
		if err := json.Unmarshal(selected["source"], &origin); err != nil {
			return err
		}
		s := sources[f.Role]
		if origin.RunID != s.RunID || origin.ReviewID != s.ReviewID || origin.Recovery != s.RecoveryManifestSHA256 || origin.AttemptID != s.AttemptID || origin.FindingID != f.SourceFindingID {
			return fmt.Errorf("finding source remapping differs")
		}
		var original map[string]json.RawMessage
		if err := json.Unmarshal(artifacts[prefix+FindingPath(f.ID)].Bytes(), &original); err != nil {
			return err
		}
		for _, key := range []string{"role", "severity", "title", "description", "recommendation", "confidence", "lifecycle", "fingerprint"} {
			var before, after string
			if json.Unmarshal(original[key], &before) != nil || json.Unmarshal(selected[key], &after) != nil {
				return fmt.Errorf("copied finding field absent")
			}
			if key == "fingerprint" {
				before = strings.TrimPrefix(before, "sha256:")
				after = strings.TrimPrefix(after, "sha256:")
			}
			if before != after {
				return fmt.Errorf("copied finding content differs")
			}
		}
		var claims []json.RawMessage
		if err := json.Unmarshal(original["evidence"], &claims); err != nil {
			return err
		}
		if len(claims) != len(f.Evidence) {
			return fmt.Errorf("source evidence count differs")
		}
		for i, ref := range f.Evidence {
			var nested struct {
				Current json.RawMessage `json:"current"`
			}
			if err := json.Unmarshal(claims[i], &nested); err != nil {
				return err
			}
			claimRaw := claims[i]
			if len(nested.Current) > 0 {
				claimRaw = nested.Current
			}
			var claim struct {
				Target         string `json:"target_sha256"`
				Side           string `json:"side"`
				Path           string `json:"path"`
				Start          int    `json:"line_start"`
				End            int    `json:"line_end"`
				Quote          string `json:"quote"`
				Digest         string `json:"current_excerpt_sha256"`
				RecoveryDigest string `json:"excerpt_sha256"`
			}
			if err := json.Unmarshal(claimRaw, &claim); err != nil {
				return err
			}
			if claim.Digest == "" {
				claim.Digest = claim.RecoveryDigest
			}
			if claim.Target != ref.TargetSHA256 || claim.Side != string(ref.Side) || claim.Path != ref.Path || claim.Start != ref.LineStart || claim.End != ref.LineEnd || claim.Digest != ref.ExcerptSHA256 {
				return fmt.Errorf("source evidence identity differs")
			}
			if ref.Availability == "verified" && claim.Quote != string(artifacts[prefix+ExcerptPath(f.ID, i)].Bytes()) {
				return fmt.Errorf("source evidence bytes differ")
			}
		}
	}
	return nil
}
