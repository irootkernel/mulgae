package reviewrun

import (
	"context"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/irootkernel/mulgae/internal/app/prompt"
	"github.com/irootkernel/mulgae/internal/ports"
)

// LoadDefaultReviewerGuide supplies the generation-time default only. An
// existing safe operator guide remains the reviewer-home adapter's authority.
func LoadDefaultReviewerGuide(ctx context.Context, catalog ports.ContractCatalog) ([]byte, error) {
	return readLivePromptAsset(ctx, catalog, "prompts/live-review/reviewer-guide.v1.txt")
}

func LoadLiveReviewCommon(ctx context.Context, catalog ports.ContractCatalog) (prompt.TrustedLayer, error) {
	raw, err := readLivePromptAsset(ctx, catalog, "prompts/live-review/common.v1.txt")
	if err != nil {
		return prompt.TrustedLayer{}, err
	}
	return prompt.NewTrustedLayer("builtin:review/live-common", "1", []byte(strings.TrimRight(string(raw), "\n")))
}

func readLivePromptAsset(ctx context.Context, catalog ports.ContractCatalog, source string) ([]byte, error) {
	if ctx == nil || catalog == nil {
		return nil, fmt.Errorf("live review templates: missing catalog or context")
	}
	id, err := ports.ParseAssetID("sot:" + source)
	if err != nil {
		return nil, err
	}
	metadata, raw, err := catalog.Read(ctx, id)
	if err != nil {
		return nil, err
	}
	if metadata.ID() != id || metadata.Source().String() != source || metadata.MediaType() != "text/plain" || len(raw) == 0 || !utf8.Valid(raw) || strings.ContainsAny(string(raw), "\x00\r") {
		return nil, fmt.Errorf("live review templates: invalid asset")
	}
	return raw, nil
}
