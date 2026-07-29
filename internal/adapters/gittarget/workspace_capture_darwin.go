//go:build darwin && arm64

package gittarget

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/irootkernel/mulgae/internal/ports"
	"golang.org/x/text/unicode/norm"
)

type workspaceIgnoreRule struct {
	base    string
	pattern *regexp.Regexp
	negate  bool
}

type workspaceTargetDescriptor struct {
	SchemaVersion  string `json:"schema_version"`
	ManifestSHA256 string `json:"manifest_sha256"`
	FileCount      int    `json:"file_count"`
	TotalBytes     int64  `json:"total_bytes"`
}

func (adapter *ReviewTargetAdapter) captureWorkspace(ctx context.Context, root ports.AnchoredRoot) (ports.CapturedReviewMaterial, error) {
	mulgaeRules, mulgaeBytes, err := readWorkspaceIgnore(root, ".mulgaeignore", "")
	if err != nil {
		return ports.CapturedReviewMaterial{}, err
	}
	files := make([]ports.WorkspaceSnapshotFile, 0)
	manifest := sha256.New()
	manifest.Write([]byte("Mulgae-WORKSPACE-MANIFEST/v1\x00"))
	manifest.Write(mulgaeBytes)
	var total int64
	if err := adapter.walkWorkspace(ctx, root, "", nil, mulgaeRules, &files, manifest, &total); err != nil {
		return ports.CapturedReviewMaterial{}, err
	}
	if len(files) == 0 {
		return ports.CapturedReviewMaterial{}, fmt.Errorf("workspace target has no eligible files")
	}
	files, err = sortFiles(files)
	if err != nil {
		return ports.CapturedReviewMaterial{}, err
	}
	digest := "sha256:" + hex.EncodeToString(manifest.Sum(nil))
	descriptor, err := json.Marshal(workspaceTargetDescriptor{
		SchemaVersion: "mulgae-workspace-target.v1", ManifestSHA256: digest,
		FileCount: len(files), TotalBytes: total,
	})
	if err != nil {
		return ports.CapturedReviewMaterial{}, err
	}
	descriptor = append(descriptor, '\n')
	if err := adapter.clean(ctx, ports.ReviewInputTarget, "workspace", descriptor); err != nil {
		return ports.CapturedReviewMaterial{}, err
	}
	return adapter.materialize(descriptor, files, map[ports.CapturedEvidenceSide][]ports.WorkspaceSnapshotFile{
		ports.CapturedEvidenceWorktree: files,
	}, "workspace;ignore=gitignore+mulgaeignore-v1-"+strings.TrimPrefix(digest, "sha256:")+";detector="+adapter.detectorPolicy, func() (ports.CapturedReviewTarget, error) {
		return ports.NewCapturedReviewWorkspaceTarget(descriptor)
	})
}

func (adapter *ReviewTargetAdapter) walkWorkspace(
	ctx context.Context,
	root ports.AnchoredRoot,
	directory string,
	gitRules, mulgaeRules []workspaceIgnoreRule,
	files *[]ports.WorkspaceSnapshotFile,
	manifest interface{ Write([]byte) (int, error) },
	total *int64,
) error {
	nested, raw, err := readWorkspaceIgnore(root, filepath.ToSlash(filepath.Join(directory, ".gitignore")), directory)
	if err != nil {
		return err
	}
	if len(raw) > 0 {
		if _, err := manifest.Write([]byte("ignore\x00" + directory + "\x00")); err != nil {
			return fmt.Errorf("workspace manifest: write ignore identity: %w", err)
		}
		if _, err := manifest.Write(raw); err != nil {
			return fmt.Errorf("workspace manifest: write ignore content: %w", err)
		}
	}
	gitRules = append(append([]workspaceIgnoreRule(nil), gitRules...), nested...)
	full := root.String()
	if directory != "" {
		full = filepath.Join(full, filepath.FromSlash(directory))
	}
	entries, err := os.ReadDir(full)
	if err != nil {
		return err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, entry := range entries {
		relative := filepath.ToSlash(filepath.Join(directory, entry.Name()))
		if reservedReviewPath(relative) {
			continue
		}
		ignored := workspaceIgnored(relative, gitRules) || workspaceIgnored(relative, mulgaeRules)
		if entry.Type()&os.ModeSymlink != 0 {
			if !ignored {
				return fmt.Errorf("workspace path %q is a symlink; add it to .mulgaeignore or replace it with a regular file", relative)
			}
			continue
		}
		if entry.IsDir() {
			// Descend even when the directory is ignored so a later negation can
			// re-include a child, as Git ignore syntax permits.
			if err := adapter.walkWorkspace(ctx, root, relative, gitRules, mulgaeRules, files, manifest, total); err != nil {
				return err
			}
			continue
		}
		if ignored {
			continue
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("workspace path %q is not a regular file; add it to .mulgaeignore", relative)
		}
		read := readStableRegular
		if adapter.artistMediaType(relative) != "" {
			read = readStableRegularBinary
		}
		data, err := read(root.String(), relative, int(ports.WorkspaceSnapshotMaxFileBytes))
		if err != nil {
			return fmt.Errorf("workspace path %q: %w; add it to .mulgaeignore if it is not reviewable", relative, err)
		}
		if adapter.artistMediaType(relative) == "" && (!utf8.Valid(data) || strings.IndexByte(string(data), 0) >= 0) {
			return fmt.Errorf("workspace path %q is not UTF-8 text; add it to .mulgaeignore", relative)
		}
		path, err := ports.NewSafeRelativePath(relative)
		if err != nil || norm.NFC.String(relative) != relative {
			return fmt.Errorf("workspace path %q is not canonical", relative)
		}
		digest := sha256.Sum256(data)
		file, err := adapter.newCapturedFile(ctx, path, data)
		if err != nil {
			return err
		}
		*files = append(*files, file)
		*total += int64(len(data))
		if len(*files) > ports.WorkspaceSnapshotMaxFiles || *total > ports.WorkspaceSnapshotMaxBytes {
			return fmt.Errorf("workspace snapshot exceeds its bounded file or byte limit; add generated content to .mulgaeignore")
		}
		if _, err := manifest.Write([]byte("file\x00" + relative + "\x00" + strconv.FormatInt(int64(len(data)), 10) + "\x00")); err != nil {
			return fmt.Errorf("workspace manifest: write file identity: %w", err)
		}
		if _, err := manifest.Write(digest[:]); err != nil {
			return fmt.Errorf("workspace manifest: write file digest: %w", err)
		}
	}
	return nil
}

func readWorkspaceIgnore(root ports.AnchoredRoot, relative, base string) ([]workspaceIgnoreRule, []byte, error) {
	full := filepath.Join(root.String(), filepath.FromSlash(relative))
	info, err := os.Lstat(full)
	if os.IsNotExist(err) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("ignore file %q must be a regular file", relative)
	}
	data, err := readStableRegular(root.String(), relative, 256<<10)
	if err != nil {
		return nil, nil, err
	}
	if !utf8.Valid(data) || strings.IndexByte(string(data), 0) >= 0 {
		return nil, nil, fmt.Errorf("ignore file %q must be UTF-8 text", relative)
	}
	rules, err := compileWorkspaceIgnore(data, base)
	return rules, data, err
}

func compileWorkspaceIgnore(data []byte, base string) ([]workspaceIgnoreRule, error) {
	var rules []workspaceIgnoreRule
	for number, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSuffix(raw, "\r")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		negate := strings.HasPrefix(line, "!")
		if negate {
			line = strings.TrimPrefix(line, "!")
		}
		anchored := strings.HasPrefix(line, "/")
		line = strings.TrimPrefix(line, "/")
		line = strings.TrimSuffix(line, "/")
		if line == "" {
			return nil, fmt.Errorf("ignore rule %d is malformed", number+1)
		}
		pattern, err := regexp.Compile(workspaceIgnoreRegexp(line, anchored))
		if err != nil {
			return nil, fmt.Errorf("ignore rule %d: %w", number+1, err)
		}
		rules = append(rules, workspaceIgnoreRule{base: filepath.ToSlash(base), pattern: pattern, negate: negate})
	}
	return rules, nil
}

func workspaceIgnoreRegexp(pattern string, anchored bool) string {
	var expression strings.Builder
	if anchored || strings.Contains(pattern, "/") {
		expression.WriteString("^")
	} else {
		expression.WriteString("(?:^|/)")
	}
	for index := 0; index < len(pattern); index++ {
		switch pattern[index] {
		case '*':
			if index+1 < len(pattern) && pattern[index+1] == '*' {
				expression.WriteString(".*")
				index++
			} else {
				expression.WriteString("[^/]*")
			}
		case '?':
			expression.WriteString("[^/]")
		default:
			expression.WriteString(regexp.QuoteMeta(string(pattern[index])))
		}
	}
	expression.WriteString("(?:$|/)")
	return expression.String()
}

func workspaceIgnored(path string, rules []workspaceIgnoreRule) bool {
	ignored := false
	for _, rule := range rules {
		relative := path
		if rule.base != "" {
			prefix := rule.base + "/"
			if !strings.HasPrefix(path, prefix) {
				continue
			}
			relative = strings.TrimPrefix(path, prefix)
		}
		if rule.pattern.MatchString(relative) {
			ignored = !rule.negate
		}
	}
	return ignored
}

func capturedMulgaeIgnore(root ports.AnchoredRoot) ([]workspaceIgnoreRule, string, error) {
	rules, data, err := readWorkspaceIgnore(root, ".mulgaeignore", "")
	if err != nil {
		return nil, "", err
	}
	digest := sha256.Sum256(data)
	return rules, hex.EncodeToString(digest[:]), nil
}

func filterMulgaeIgnoredSnapshot(files []ports.WorkspaceSnapshotFile, rules []workspaceIgnoreRule) []ports.WorkspaceSnapshotFile {
	filtered := make([]ports.WorkspaceSnapshotFile, 0, len(files))
	for _, file := range files {
		if !workspaceIgnored(file.Path().String(), rules) {
			filtered = append(filtered, file)
		}
	}
	return filtered
}

func filterMulgaeIgnoredPatch(patch []byte, rules []workspaceIgnoreRule) ([]byte, error) {
	if len(rules) == 0 || len(patch) == 0 {
		return append([]byte(nil), patch...), nil
	}
	starts := []int{0}
	for offset := 0; ; {
		index := strings.Index(string(patch[offset:]), "\ndiff --git ")
		if index < 0 {
			break
		}
		offset += index + 1
		starts = append(starts, offset)
	}
	var filtered []byte
	for index, start := range starts {
		end := len(patch)
		if index+1 < len(starts) {
			end = starts[index+1]
		}
		section := patch[start:end]
		lineEnd := strings.IndexByte(string(section), '\n')
		if lineEnd < 0 || !strings.HasPrefix(string(section[:lineEnd]), "diff --git ") {
			return nil, fmt.Errorf("cannot apply .mulgaeignore to malformed Git patch")
		}
		left, right, ok := parseDiffGitPaths(strings.TrimPrefix(string(section[:lineEnd]), "diff --git "))
		if !ok {
			return nil, fmt.Errorf("cannot apply .mulgaeignore to non-canonical Git path")
		}
		left = strings.TrimPrefix(left, "a/")
		right = strings.TrimPrefix(right, "b/")
		if workspaceIgnored(left, rules) || workspaceIgnored(right, rules) {
			continue
		}
		filtered = append(filtered, section...)
	}
	return filtered, nil
}
