package reviewrun

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// PreflightFile is the existing v5 file-set row. Keep its JSON field order:
// the historical file-set identity hashes this exact encoding.
type PreflightFile struct {
	Path        string `json:"path"`
	MediaType   string `json:"media_type"`
	Size        int64  `json:"size"`
	SHA256      string `json:"sha256"`
	Disposition string `json:"disposition"`
}

// PreflightFileSetID preserves the historical preflight identity. It is not a
// complete capture identity: logical sides and project context are separate.
func PreflightFileSetID(policy string, files []PreflightFile) (string, error) {
	data, err := json.Marshal(struct {
		Policy string          `json:"policy"`
		Files  []PreflightFile `json:"files"`
	}{policy, files})
	if err != nil {
		return "", fmt.Errorf("review preflight: file set identity: %w", err)
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
