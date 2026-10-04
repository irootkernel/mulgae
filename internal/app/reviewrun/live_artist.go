package reviewrun

import (
	"context"
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/irootkernel/mulgae/internal/app/evidence"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

type liveArtistContext struct {
	task     []byte
	manifest []byte
	images   []evidence.LiveBinaryReceipt
	ready    bool
}

// ValidateLiveArtistInputs checks selected artist content during provider-free
// admission. It reads the brief and selected raster evidence without retaining
// an archive, creating execution state, or invoking a provider.
func ValidateLiveArtistInputs(ctx context.Context, source ports.LiveSourceReader, inputs ports.ArtistReviewInputs) error {
	_, err := prepareLiveArtistContext(ctx, source, inputs)
	return err
}

func prepareLiveArtistContext(ctx context.Context, source ports.LiveSourceReader, inputs ports.ArtistReviewInputs) (liveArtistContext, error) {
	if ctx == nil || source == nil || !inputs.Valid() {
		return liveArtistContext{}, fmt.Errorf("live artist: invalid inputs")
	}
	brief, err := ports.NewSafeRelativePath(inputs.BriefPath())
	if err != nil {
		return liveArtistContext{}, err
	}
	patterns := make([]*regexp.Regexp, 0, len(inputs.DesignSpecGlobs()))
	for _, pattern := range inputs.DesignSpecGlobs() {
		compiled, err := compileLiveArtistGlob(pattern)
		if err != nil {
			return liveArtistContext{}, err
		}
		patterns = append(patterns, compiled)
	}
	current, currentEvidence := domain.LiveSourceAfter, evidence.SideHead
	switch source.Target().Selector().Scope() {
	case domain.LiveSourceWorkspace:
		current, currentEvidence = domain.LiveSourceWorktree, evidence.SideWorktree
	case domain.LiveSourceStage:
		current, currentEvidence = domain.LiveSourceIndex, evidence.SideIndex
	}
	paths, err := source.List(ctx, current)
	if err != nil {
		return liveArtistContext{}, err
	}
	available := make(map[string]bool, len(paths))
	for _, item := range paths {
		available[item.String()] = true
	}
	result := liveArtistContext{images: []evidence.LiveBinaryReceipt{}}
	if available[brief.String()] {
		file, err := source.Read(ctx, current, brief)
		if err != nil {
			return liveArtistContext{}, err
		}
		if !file.IsText() {
			return liveArtistContext{}, fmt.Errorf("live artist: brief is not text")
		}
		result.task = file.Bytes()
	}
	if len(result.task) == 0 && !inputs.Automatic() {
		return liveArtistContext{}, fmt.Errorf("live artist: brief is missing or empty")
	}
	verifier, err := evidence.NewLiveVerifier(source)
	if err != nil {
		return liveArtistContext{}, err
	}
	basePaths := map[string]bool{}
	if source.Target().Base().Valid() && !source.Target().EmptyBase() {
		paths, err := source.List(ctx, domain.LiveSourceBefore)
		if err != nil {
			return liveArtistContext{}, err
		}
		for _, item := range paths {
			basePaths[item.String()] = true
		}
	}
	appendImage := func(side evidence.Side, file ports.LiveSourceFile) error {
		receipt, err := verifier.VerifyBinary(ctx, side, file.Path(), file.SHA256())
		if err == nil {
			result.images = append(result.images, receipt)
		}
		return err
	}
	for _, change := range source.Target().Changes() {
		if !change.After.Valid() || inputs.Automatic() && source.Target().Selector().Scope() == domain.LiveSourceWorkspace {
			continue
		}
		matched := false
		for _, pattern := range patterns {
			matched = matched || pattern.MatchString(change.After.String())
		}
		extension := strings.ToLower(path.Ext(change.After.String()))
		if !matched || extension != ".png" && extension != ".jpg" && extension != ".jpeg" && extension != ".webp" {
			continue
		}
		if !available[change.After.String()] {
			return liveArtistContext{}, fmt.Errorf("live artist: selected image is unavailable")
		}
		file, err := source.Read(ctx, current, change.After)
		if err != nil {
			return liveArtistContext{}, err
		}
		if change.Before.Valid() && basePaths[change.Before.String()] {
			prior, err := source.Read(ctx, domain.LiveSourceBefore, change.Before)
			if err != nil {
				return liveArtistContext{}, err
			}
			if prior.SHA256() == file.SHA256() {
				continue
			}
			if prior.MediaType() == file.MediaType() {
				if err := appendImage(evidence.SideBase, prior); err != nil {
					return liveArtistContext{}, err
				}
			}
		}
		if err := appendImage(currentEvidence, file); err != nil {
			return liveArtistContext{}, err
		}
	}
	type visual struct {
		Path      string        `json:"path"`
		Side      evidence.Side `json:"side"`
		SHA256    string        `json:"sha256"`
		MediaType string        `json:"media_type"`
	}
	assets := make([]visual, 0, len(result.images))
	for _, image := range result.images {
		assets = append(assets, visual{Path: image.Path().String(), Side: image.Side(), SHA256: image.FileSHA256(), MediaType: image.MediaType()})
	}
	status := "missing"
	if len(result.task) != 0 {
		status = "code_only"
	}
	result.ready = len(result.task) != 0 && len(result.images) != 0
	if result.ready {
		status = "ready"
	}
	identity, err := evidence.NewLiveSourceIdentity(source.Target())
	if err != nil {
		return liveArtistContext{}, err
	}
	result.manifest, err = json.Marshal(struct {
		SchemaVersion        string   `json:"schema_version"`
		SourceIdentitySHA256 string   `json:"source_identity_sha256"`
		Status               string   `json:"status"`
		TaskPath             string   `json:"task_path"`
		VisualAssets         []visual `json:"visual_assets"`
	}{"mulgae-live-artist-inputs.v1", identity.SHA256(), status, brief.String(), assets})
	return result, err
}

func compileLiveArtistGlob(pattern string) (*regexp.Regexp, error) {
	if strings.ContainsAny(pattern, "[]{}\\\x00\r\n") {
		return nil, fmt.Errorf("live artist: invalid image glob")
	}
	if _, err := ports.NewSafeRelativePath(strings.NewReplacer("*", "a", "?", "a").Replace(pattern)); err != nil {
		return nil, err
	}
	var expression strings.Builder
	expression.WriteByte('^')
	for index := 0; index < len(pattern); {
		switch pattern[index] {
		case '*':
			if index+1 < len(pattern) && pattern[index+1] == '*' {
				index += 2
				if index < len(pattern) && pattern[index] == '/' {
					expression.WriteString("(?:.*/)?")
					index++
				} else {
					expression.WriteString(".*")
				}
			} else {
				expression.WriteString("[^/]*")
				index++
			}
		case '?':
			expression.WriteString("[^/]")
			index++
		default:
			expression.WriteString(regexp.QuoteMeta(pattern[index : index+1]))
			index++
		}
	}
	expression.WriteByte('$')
	return regexp.Compile(expression.String())
}
