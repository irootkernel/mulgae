package export

import (
	"encoding/json"
	"testing"
)

func TestEvidenceAndCurrentIdentityMarshalDistinctExcerptDigests(t *testing.T) {
	sourceDigest := testHash("e")
	currentDigest := testHash("0")

	body, err := json.Marshal(struct {
		Evidence        Evidence        `json:"evidence"`
		CurrentIdentity CurrentIdentity `json:"current_identity"`
	}{
		Evidence: Evidence{
			SourceExcerptSHA256:  sourceDigest,
			CurrentExcerptSHA256: currentDigest,
		},
		CurrentIdentity: CurrentIdentity{CurrentExcerptSHA256: currentDigest},
	})
	if err != nil {
		t.Fatal(err)
	}

	var decoded struct {
		Evidence struct {
			SourceExcerptSHA256  string `json:"source_excerpt_sha256"`
			CurrentExcerptSHA256 string `json:"current_excerpt_sha256"`
		} `json:"evidence"`
		CurrentIdentity struct {
			CurrentExcerptSHA256 string `json:"current_excerpt_sha256"`
		} `json:"current_identity"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Evidence.SourceExcerptSHA256 != sourceDigest || decoded.Evidence.CurrentExcerptSHA256 != currentDigest || decoded.CurrentIdentity.CurrentExcerptSHA256 != currentDigest {
		t.Fatalf("excerpt digest mapping = %#v", decoded)
	}
}
