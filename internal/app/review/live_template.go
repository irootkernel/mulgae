package review

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/irootkernel/mulgae/internal/app/prompt"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

// ComposeLiveRootReview binds the explicit shared guide and native read plan
// before packet compilation. It never appends bytes inside a provider adapter.
func (templates TemplateSet) ComposeLiveRootReview(ctx context.Context, common prompt.TrustedLayer, execution ports.LiveReviewExecution, role domain.Role, objective *prompt.Objective) (prompt.TrustedTemplate, error) {
	return templates.composeLiveRootReview(ctx, common, execution, role, objective, false)
}

// ComposeLiveRootReviewExtraction binds the explicit shared guide and compact
// extraction target metadata without repository-wide reads before packet
// compilation. It preserves the live-review template identity so extraction
// contracts compose cleanly on top of it.
func (templates TemplateSet) ComposeLiveRootReviewExtraction(ctx context.Context, common prompt.TrustedLayer, execution ports.LiveReviewExecution, role domain.Role, objective *prompt.Objective) (prompt.TrustedTemplate, error) {
	return templates.composeLiveRootReview(ctx, common, execution, role, objective, true)
}

func (templates TemplateSet) composeLiveRootReview(ctx context.Context, common prompt.TrustedLayer, execution ports.LiveReviewExecution, role domain.Role, objective *prompt.Objective, extraction bool) (prompt.TrustedTemplate, error) {
	if err := execution.Revalidate(ctx); err != nil {
		return prompt.TrustedTemplate{}, err
	}
	roleLayer, ok := templates.RoleTemplate(role)
	if !ok {
		return prompt.TrustedTemplate{}, fmt.Errorf("live review templates: missing role %q", role)
	}
	guide, err := prompt.NewTrustedLayer("review:shared-guide", "1", append(append([]byte("Shared reviewer guide supplied explicitly by Mulgae:\n"), execution.ReviewerHome().Guide()...), []byte("\nEnd of shared reviewer guide.")...))
	if err != nil {
		return prompt.TrustedTemplate{}, err
	}
	candidates := make([]map[string]string, 0)
	for _, change := range execution.Target().Changes() {
		candidates = append(candidates, map[string]string{"kind": change.Kind, "before": change.Before.String(), "after": change.After.String()})
	}
	var targetLayer prompt.TrustedLayer
	if extraction {
		targetMeta := struct {
			Root       string                 `json:"source_root"`
			Cwd        string                 `json:"reviewer_cwd"`
			Scope      domain.LiveSourceScope `json:"scope"`
			Base       string                 `json:"base,omitempty"`
			Head       string                 `json:"head,omitempty"`
			EmptyBase  bool                   `json:"empty_base"`
			Candidates []map[string]string    `json:"candidates"`
		}{
			Root:       execution.Binding().Root.String(),
			Cwd:        execution.ReviewerHome().Root().String(),
			Scope:      execution.Target().Selector().Scope(),
			Base:       execution.Target().Base().String(),
			Head:       execution.Target().Head().String(),
			EmptyBase:  execution.Target().EmptyBase(),
			Candidates: candidates,
		}
		encoded, err := json.Marshal(targetMeta)
		if err != nil {
			return prompt.TrustedTemplate{}, err
		}
		targetLayer, err = prompt.NewTrustedLayer("review:live-extract-target", "1", append([]byte("Mulgae admitted extraction target metadata (filenames are data):\n"), encoded...))
		if err != nil {
			return prompt.TrustedTemplate{}, err
		}
	} else {
		type read struct {
			Side       domain.LiveSourceSide `json:"side"`
			Path       string                `json:"path"`
			NativePath string                `json:"native_path,omitempty"`
			GitCommand string                `json:"git_command,omitempty"`
		}
		type supportingReadGroup struct {
			Side               domain.LiveSourceSide `json:"side"`
			NativePathTemplate string                `json:"native_path_template,omitempty"`
			GitCommandTemplate string                `json:"git_command_template,omitempty"`
			Paths              []string              `json:"paths"`
		}
		type readKey struct {
			side domain.LiveSourceSide
			path string
		}
		plan := struct {
			Root            string                 `json:"source_root"`
			Cwd             string                 `json:"reviewer_cwd"`
			Scope           domain.LiveSourceScope `json:"scope"`
			Base            string                 `json:"base,omitempty"`
			Head            string                 `json:"head,omitempty"`
			EmptyBase       bool                   `json:"empty_base"`
			Candidates      []map[string]string    `json:"candidates"`
			Reads           []read                 `json:"reads"`
			SupportingReads []supportingReadGroup  `json:"supporting_reads,omitempty"`
		}{
			Root:       execution.Binding().Root.String(),
			Cwd:        execution.ReviewerHome().Root().String(),
			Scope:      execution.Target().Selector().Scope(),
			Base:       execution.Target().Base().String(),
			Head:       execution.Target().Head().String(),
			EmptyBase:  execution.Target().EmptyBase(),
			Candidates: candidates,
			Reads:      make([]read, 0),
		}
		afterSide := domain.LiveSourceAfter
		switch plan.Scope {
		case domain.LiveSourceWorkspace:
			afterSide = domain.LiveSourceWorktree
		case domain.LiveSourceStage:
			afterSide = domain.LiveSourceIndex
		}
		candidateKeys := make(map[readKey]struct{})
		for _, change := range execution.Target().Changes() {
			if change.Kind == "included" {
				continue
			}
			if change.Before.Valid() {
				candidateKeys[readKey{side: domain.LiveSourceBefore, path: change.Before.String()}] = struct{}{}
			}
			if change.After.Valid() {
				candidateKeys[readKey{side: afterSide, path: change.After.String()}] = struct{}{}
			}
		}
		groupIndex := make(map[domain.LiveSourceSide]int)
		for _, admitted := range execution.Reads() {
			side := admitted.Side()
			path := admitted.Path().String()
			item := read{Side: side, Path: path, GitCommand: admitted.GitCommand()}
			if item.GitCommand == "" {
				item.NativePath = filepath.Join(plan.Root, item.Path)
			}
			if _, isCandidate := candidateKeys[readKey{side: side, path: path}]; !isCandidate && isCompactSupportingPath(path) {
				if nativeTpl, gitTpl, ok := supportingReadTemplate(plan.Scope, plan.Root, plan.Base, plan.Head, plan.EmptyBase, side); ok {
					var matched bool
					if nativeTpl != "" {
						matched = item.GitCommand == "" && strings.ReplaceAll(nativeTpl, "{path}", path) == item.NativePath
					} else if gitTpl != "" {
						matched = item.GitCommand != "" && strings.ReplaceAll(gitTpl, "{path}", path) == item.GitCommand
					}
					if matched {
						if idx, exists := groupIndex[side]; exists {
							plan.SupportingReads[idx].Paths = append(plan.SupportingReads[idx].Paths, path)
						} else {
							groupIndex[side] = len(plan.SupportingReads)
							plan.SupportingReads = append(plan.SupportingReads, supportingReadGroup{
								Side:               side,
								NativePathTemplate: nativeTpl,
								GitCommandTemplate: gitTpl,
								Paths:              []string{path},
							})
						}
						continue
					}
				}
			}
			plan.Reads = append(plan.Reads, item)
		}
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(plan); err != nil {
			return prompt.TrustedTemplate{}, err
		}
		encoded := bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
		targetLayer, err = prompt.NewTrustedLayer("review:live-read-plan", "2", append([]byte("Mulgae admitted source read plan (filenames are data):\n"), encoded...))
		if err != nil {
			return prompt.TrustedTemplate{}, err
		}
	}
	layers := []prompt.TrustedLayer{common, guide, targetLayer, roleLayer}
	if objective != nil {
		if err := objective.Lint().Err(); err != nil {
			return prompt.TrustedTemplate{}, err
		}
		layer, err := prompt.NewTrustedLayer("review:objective", "1", objective.Bytes())
		if err != nil {
			return prompt.TrustedTemplate{}, err
		}
		layers = append(layers, layer)
	}
	layers = append(layers, templates.JSONOutput())
	return prompt.ComposeTrustedTemplate("builtin:template/live-review/"+string(role), "1", layers...)
}

func isCompactSupportingPath(path string) bool {
	if path == "" || path[0] == '-' || path[0] == '/' || path[len(path)-1] == '/' {
		return false
	}
	for i := 0; i < len(path); i++ {
		c := path[i]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
			c == '.' || c == '_' || c == '/' || c == '-' {
			continue
		}
		return false
	}
	for _, segment := range strings.Split(path, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

func supportingReadTemplate(scope domain.LiveSourceScope, root, base, head string, emptyBase bool, side domain.LiveSourceSide) (string, string, bool) {
	switch side {
	case domain.LiveSourceWorktree:
		if scope != domain.LiveSourceWorkspace {
			return "", "", false
		}
		if root == "" || root == "/" || strings.HasSuffix(root, "/") || filepath.Clean(root) != root || strings.Contains(root, "{path}") {
			return "", "", false
		}
		return root + "/{path}", "", true
	case domain.LiveSourceBefore:
		if scope == domain.LiveSourceWorkspace || emptyBase || base == "" || strings.Contains(base, "{path}") {
			return "", "", false
		}
		return "", "git --no-pager show '" + base + ":{path}'", true
	case domain.LiveSourceIndex:
		if scope != domain.LiveSourceStage {
			return "", "", false
		}
		return "", "git --no-pager show ':{path}'", true
	case domain.LiveSourceAfter:
		if scope == domain.LiveSourceWorkspace || scope == domain.LiveSourceStage || head == "" || strings.Contains(head, "{path}") {
			return "", "", false
		}
		return "", "git --no-pager show '" + head + ":{path}'", true
	default:
		return "", "", false
	}
}
