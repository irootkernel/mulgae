//go:build darwin && arm64

package gittarget

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"

	adapterconfig "github.com/irootkernel/mulgae/internal/adapters/config"
	"github.com/irootkernel/mulgae/internal/ports"
)

type GitLocalityAttestor struct{ adapter *Adapter }

var _ ports.ConfigLocalityAttestor = (*GitLocalityAttestor)(nil)
var _ ports.ConfigLocalityAttestor = (*Adapter)(nil)

func (adapter *Adapter) Attest(ctx context.Context, request ports.ConfigLocalityRequest) (ports.ConfigLocalityContext, error) {
	return (&GitLocalityAttestor{adapter: adapter}).Attest(ctx, request)
}
func (adapter *Adapter) Revalidate(ctx context.Context, request ports.ConfigLocalityRequest, expected ports.ConfigLocalityContext) error {
	return (&GitLocalityAttestor{adapter: adapter}).Revalidate(ctx, request, expected)
}

func NewGitLocalityAttestor(runner Runner) (*GitLocalityAttestor, error) {
	adapter, err := New(runner)
	if err != nil {
		return nil, err
	}
	return &GitLocalityAttestor{adapter: adapter}, nil
}

func (attestor *GitLocalityAttestor) Attest(ctx context.Context, request ports.ConfigLocalityRequest) (result ports.ConfigLocalityContext, attestErr error) {
	if attestor == nil || attestor.adapter == nil || ctx == nil || !request.Root().Valid() {
		return ports.ConfigLocalityContext{}, fmt.Errorf("config locality: invalid request")
	}
	if err := revalidateLiveConfigProof(request); err != nil {
		return ports.ConfigLocalityContext{}, err
	}
	references := []string{"HEAD"}
	for _, oid := range request.ApplicableCommits() {
		references = append(references, oid.String())
	}
	repository, cleanup, err := attestor.adapter.newCanonicalRepository(request.Root(), references...)
	if err != nil {
		return ports.ConfigLocalityContext{}, fmt.Errorf("config locality: canonical repository: %w", err)
	}
	defer finalizeCanonicalCleanup(cleanup, "config locality", &attestErr, func() { result = ports.ConfigLocalityContext{} })
	head, err := attestor.adapter.resolveCommit(ctx, repository, "HEAD")
	if err != nil {
		return ports.ConfigLocalityContext{}, fmt.Errorf("config locality: HEAD: %w", err)
	}
	headTree, err := attestor.adapter.headTree(ctx, repository, head)
	if err != nil {
		return ports.ConfigLocalityContext{}, fmt.Errorf("config locality: HEAD tree: %w", err)
	}
	indexResult, err := attestor.adapter.run(ctx, repository.sourceCommand("ls-files", "--stage", "-z"))
	if err != nil {
		return ports.ConfigLocalityContext{}, fmt.Errorf("config locality: index: %w", err)
	}
	indexDigest, indexCount, hasUnmerged, privateInIndex, err := canonicalIndex(indexResult.Stdout)
	if err != nil {
		return ports.ConfigLocalityContext{}, err
	}
	if hasUnmerged {
		return ports.ConfigLocalityContext{}, fmt.Errorf("config locality: unmerged index")
	}
	if privateInIndex {
		return ports.ConfigLocalityContext{}, ports.NewConfigLocalityViolation(privateIndexReason(indexResult.Stdout), nil)
	}
	commits := []string{head.String()}
	seen := map[string]struct{}{head.String(): {}}
	for _, candidate := range request.ApplicableCommits() {
		if _, ok := seen[candidate.String()]; ok {
			continue
		}
		commits = append(commits, candidate.String())
		seen[candidate.String()] = struct{}{}
	}
	for _, commit := range commits {
		listed, err := attestor.adapter.run(ctx, repository.sourceCommand("ls-tree", "-r", "-z", "--name-only", commit))
		if err != nil {
			return ports.ConfigLocalityContext{}, fmt.Errorf("config locality: commit tree: %w", err)
		}
		for _, name := range splitNUL(listed.Stdout) {
			if reason := privatePathReason(name); reason.Valid() {
				return ports.ConfigLocalityContext{}, ports.NewConfigLocalityViolation(reason, nil)
			}
		}
	}
	targetBytes := request.TargetBytes()
	targetDigest := sha256.Sum256(targetBytes)
	parsed, free := parseUnifiedDiffPrivatePathFree(targetBytes)
	if parsed && !free {
		return ports.ConfigLocalityContext{}, ports.NewConfigLocalityViolation(parsedUnifiedDiffPrivateReason(targetBytes), nil)
	}
	if err := revalidateLiveConfigProof(request); err != nil {
		return ports.ConfigLocalityContext{}, err
	}
	rootDevice, rootInode, rootUID, rootMode := request.Config().RootIdentity()
	return ports.NewConfigLocalityContext(repository.repositoryID, rootDevice, rootInode, rootUID, rootMode, head.String(), headTree.String(), fmt.Sprintf("sha256:%x", indexDigest), indexCount, hasUnmerged, commits, request.Config(), ports.ParsedTargetProof{SHA256: fmt.Sprintf("sha256:%x", targetDigest), Parsed: parsed, PrivatePathFree: free})
}

func revalidateLiveConfigProof(request ports.ConfigLocalityRequest) error {
	source, err := adapterconfig.NewLocalConfigSource(request.Root(), true)
	if err != nil {
		return fmt.Errorf("config locality: live config: %w", err)
	}
	actual, err := source.Observation().Proof()
	if err != nil {
		return fmt.Errorf("config locality: live config proof: %w", err)
	}
	if !actual.Equal(request.Config()) {
		return fmt.Errorf("config locality: live config drifted")
	}
	return nil
}

func (attestor *GitLocalityAttestor) Revalidate(ctx context.Context, request ports.ConfigLocalityRequest, expected ports.ConfigLocalityContext) error {
	actual, err := attestor.Attest(ctx, request)
	if err != nil {
		return err
	}
	if !actual.Equal(expected) {
		return fmt.Errorf("config locality: drifted")
	}
	return nil
}

type indexEntry struct {
	path, oid string
	stage     int
	mode      string
}

func canonicalIndex(data []byte) ([sha256.Size]byte, int, bool, bool, error) {
	entries := make([]indexEntry, 0)
	hasUnmerged, private := false, false
	for _, record := range splitNUL(data) {
		separator := strings.IndexByte(record, '\t')
		if separator < 0 {
			return [sha256.Size]byte{}, 0, false, false, fmt.Errorf("config locality: malformed index")
		}
		fields := strings.Fields(record[:separator])
		if len(fields) != 3 {
			return [sha256.Size]byte{}, 0, false, false, fmt.Errorf("config locality: malformed index")
		}
		stage, err := strconv.Atoi(fields[2])
		if err != nil || stage < 0 || stage > 3 {
			return [sha256.Size]byte{}, 0, false, false, fmt.Errorf("config locality: malformed index stage")
		}
		name := record[separator+1:]
		if !canonicalGitPath(name) {
			return [sha256.Size]byte{}, 0, false, false, fmt.Errorf("config locality: malformed index path")
		}
		if stage != 0 {
			hasUnmerged = true
		}
		if privatePath(name) {
			private = true
		}
		entries = append(entries, indexEntry{name, fields[1], stage, fields[0]})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].path != entries[j].path {
			return entries[i].path < entries[j].path
		}
		if entries[i].stage != entries[j].stage {
			return entries[i].stage < entries[j].stage
		}
		if entries[i].mode != entries[j].mode {
			return entries[i].mode < entries[j].mode
		}
		return entries[i].oid < entries[j].oid
	})
	var canonical bytes.Buffer
	canonical.WriteString("Mulgae-INDEX/v1\x00")
	for _, entry := range entries {
		fmt.Fprintf(&canonical, "%s\x00%d\x00%s\x00%s\x00", entry.path, entry.stage, entry.mode, entry.oid)
	}
	return sha256.Sum256(canonical.Bytes()), len(entries), hasUnmerged, private, nil
}

func splitNUL(data []byte) []string {
	if len(data) == 0 {
		return nil
	}
	parts := bytes.Split(data, []byte{0})
	if len(parts) > 0 && len(parts[len(parts)-1]) == 0 {
		parts = parts[:len(parts)-1]
	}
	result := make([]string, len(parts))
	for i := range parts {
		result[i] = string(parts[i])
	}
	return result
}
func canonicalGitPath(value string) bool {
	return value != "" && !path.IsAbs(value) && path.Clean(value) == value && !strings.Contains(value, "\\") && !strings.ContainsRune(value, 0) && value != ".." && !strings.HasPrefix(value, "../")
}
func privatePath(value string) bool {
	return value == ".mulgae" || strings.HasPrefix(value, ".mulgae/")
}

func privatePathReason(value string) ports.ConfigLocalityReason {
	if value == ".mulgae/config.yaml" {
		return ports.ConfigLocalityTargetPrivateConfigForbidden
	}
	if privatePath(value) {
		return ports.ConfigLocalityTargetPrivateNamespaceForbidden
	}
	return ""
}

func dominantPrivateReason(current, candidate ports.ConfigLocalityReason) ports.ConfigLocalityReason {
	if candidate == ports.ConfigLocalityTargetPrivateConfigForbidden || !current.Valid() {
		return candidate
	}
	return current
}

func privateIndexReason(data []byte) ports.ConfigLocalityReason {
	reason := ports.ConfigLocalityReason("")
	for _, record := range splitNUL(data) {
		if separator := strings.IndexByte(record, '\t'); separator >= 0 {
			reason = dominantPrivateReason(reason, privatePathReason(record[separator+1:]))
		}
	}
	if reason.Valid() {
		return reason
	}
	return ports.ConfigLocalityTargetPrivateNamespaceForbidden
}

func parsedUnifiedDiffPrivateReason(data []byte) ports.ConfigLocalityReason {
	reason := ports.ConfigLocalityReason("")
	for _, line := range strings.Split(string(data), "\n") {
		var candidates []string
		switch {
		case strings.HasPrefix(line, "diff --git "):
			left, right, ok := parseDiffGitPaths(strings.TrimPrefix(line, "diff --git "))
			if ok {
				candidates = []string{stripAB(left), stripAB(right)}
			}
		case strings.HasPrefix(line, "--- "):
			if value, ok := parseHeaderPath(strings.TrimPrefix(line, "--- "), "a/"); ok {
				candidates = []string{value}
			}
		case strings.HasPrefix(line, "+++ "):
			if value, ok := parseHeaderPath(strings.TrimPrefix(line, "+++ "), "b/"); ok {
				candidates = []string{value}
			}
		case strings.HasPrefix(line, "rename from "):
			if value, ok := decodeGitPath(strings.TrimPrefix(line, "rename from ")); ok {
				candidates = []string{value}
			}
		case strings.HasPrefix(line, "rename to "):
			if value, ok := decodeGitPath(strings.TrimPrefix(line, "rename to ")); ok {
				candidates = []string{value}
			}
		case strings.HasPrefix(line, "copy from "):
			if value, ok := decodeGitPath(strings.TrimPrefix(line, "copy from ")); ok {
				candidates = []string{value}
			}
		case strings.HasPrefix(line, "copy to "):
			if value, ok := decodeGitPath(strings.TrimPrefix(line, "copy to ")); ok {
				candidates = []string{value}
			}
		}
		for _, candidate := range candidates {
			if candidate != "/dev/null" {
				reason = dominantPrivateReason(reason, privatePathReason(candidate))
			}
		}
	}
	if reason.Valid() {
		return reason
	}
	return ports.ConfigLocalityTargetPrivateNamespaceForbidden
}

var (
	hunkHeader         = regexp.MustCompile(`^@@ -([0-9]+)(?:,([0-9]+))? \+([0-9]+)(?:,([0-9]+))? @@(?: .*)?$`)
	indexMetadata      = regexp.MustCompile(`^index ([0-9a-f]{4,64})\.\.([0-9a-f]{4,64})(?: (100644|100755|120000|160000))?$`)
	modeMetadata       = regexp.MustCompile(`^(new file mode|deleted file mode|old mode|new mode) (100644|100755|120000|160000)$`)
	similarityMetadata = regexp.MustCompile(`^(similarity|dissimilarity) index (0|[1-9][0-9]?|100)%$`)
)

// parseUnifiedDiffPrivatePathFree returns parsed=false for prose and every
// malformed patch-like input, so no substring mention can become authority.
func parseUnifiedDiffPrivatePathFree(data []byte) (bool, bool) {
	if len(data) == 0 || data[len(data)-1] != '\n' {
		return false, true
	}
	lines := strings.Split(string(data[:len(data)-1]), "\n")
	if len(lines) == 0 {
		return false, true
	}
	type sectionState struct {
		started                      bool
		git                          bool
		gitOld, gitNew               string
		oldPath, newPath             string
		oldSeen, newSeen, hunkSeen   bool
		renameFrom, renameTo         string
		copyFrom, copyTo             string
		renameFromSeen, renameToSeen bool
		copyFromSeen, copyToSeen     bool
		indexSeen                    bool
		newFileModeSeen              bool
		deletedFileModeSeen          bool
		oldModeSeen, newModeSeen     bool
		oldMode, newMode             string
		similaritySeen               bool
		dissimilaritySeen            bool
	}
	validSection := func(section sectionState) bool {
		if !section.started {
			return false
		}
		rename := section.renameFromSeen || section.renameToSeen
		copySection := section.copyFromSeen || section.copyToSeen
		if rename && copySection || rename != (section.renameFromSeen && section.renameToSeen) || copySection != (section.copyFromSeen && section.copyToSeen) {
			return false
		}
		if (rename || copySection) != section.similaritySeen {
			return false
		}
		if section.hunkSeen && (!section.oldSeen || !section.newSeen) {
			return false
		}
		if section.oldSeen != section.newSeen {
			return false
		}
		if section.newFileModeSeen && section.deletedFileModeSeen || section.oldModeSeen != section.newModeSeen || section.oldModeSeen && section.oldMode == section.newMode || section.similaritySeen && section.dissimilaritySeen {
			return false
		}
		if section.oldSeen && !section.hunkSeen {
			return false
		}
		metadataOnlyChange := section.newFileModeSeen || section.deletedFileModeSeen || section.oldModeSeen && section.newModeSeen
		if !section.oldSeen && !rename && !copySection && !metadataOnlyChange {
			return false
		}
		if !section.git && (!section.oldSeen || rename || copySection) {
			return false
		}
		if section.git {
			oldGit, newGit := stripAB(section.gitOld), stripAB(section.gitNew)
			if section.oldSeen {
				if section.oldPath != "/dev/null" && section.oldPath != oldGit || section.newPath != "/dev/null" && section.newPath != newGit {
					return false
				}
				oldNull, newNull := section.oldPath == "/dev/null", section.newPath == "/dev/null"
				if oldNull && newNull || section.newFileModeSeen != oldNull || section.deletedFileModeSeen != newNull {
					return false
				}
			}
			if rename && (section.renameFrom != oldGit || section.renameTo != newGit) {
				return false
			}
			if copySection && (section.copyFrom != oldGit || section.copyTo != newGit) {
				return false
			}
		} else if section.oldSeen && section.oldPath == "/dev/null" && section.newPath == "/dev/null" {
			return false
		}
		return true
	}
	section := sectionState{}
	sections := 0
	privateFound := false
	for index := 0; index < len(lines); index++ {
		line := lines[index]
		switch {
		case strings.HasPrefix(line, "diff --git "):
			if section.started && !validSection(section) {
				return false, true
			}
			if section.started {
				sections++
			}
			left, right, ok := parseDiffGitPaths(strings.TrimPrefix(line, "diff --git "))
			if !ok || !strings.HasPrefix(left, "a/") || !strings.HasPrefix(right, "b/") || !canonicalGitPath(left) || !canonicalGitPath(right) {
				return false, true
			}
			if privatePath(stripAB(left)) || privatePath(stripAB(right)) {
				privateFound = true
			}
			section = sectionState{started: true, git: true, gitOld: left, gitNew: right}
		case strings.HasPrefix(line, "--- "):
			if section.started && section.oldSeen {
				if !section.git && validSection(section) {
					sections++
					section = sectionState{started: true}
				} else {
					return false, true
				}
			} else if !section.started {
				section = sectionState{started: true}
			}
			if section.oldSeen {
				return false, true
			}
			value, ok := parseHeaderPath(strings.TrimPrefix(line, "--- "), "a/")
			if !ok {
				return false, true
			}
			if value != "/dev/null" && privatePath(value) {
				privateFound = true
			}
			section.oldPath, section.oldSeen = value, true
		case strings.HasPrefix(line, "+++ "):
			value, ok := parseHeaderPath(strings.TrimPrefix(line, "+++ "), "b/")
			if !ok || !section.oldSeen || section.newSeen {
				return false, true
			}
			if value != "/dev/null" && privatePath(value) {
				privateFound = true
			}
			section.newPath, section.newSeen = value, true
		case strings.HasPrefix(line, "rename from ") || strings.HasPrefix(line, "rename to ") || strings.HasPrefix(line, "copy from ") || strings.HasPrefix(line, "copy to "):
			if !section.started || !section.git || section.oldSeen || section.hunkSeen {
				return false, true
			}
			separator := strings.IndexByte(line, ' ')
			value := line[separator+1:]
			value = value[strings.IndexByte(value, ' ')+1:]
			decoded, ok := decodeGitPath(value)
			if !ok || !canonicalGitPath(decoded) {
				return false, true
			}
			if privatePath(decoded) {
				privateFound = true
			}
			switch {
			case strings.HasPrefix(line, "rename from "):
				if section.renameFromSeen || section.copyFromSeen || section.copyToSeen {
					return false, true
				}
				section.renameFrom, section.renameFromSeen = decoded, true
			case strings.HasPrefix(line, "rename to "):
				if !section.renameFromSeen || section.renameToSeen || section.copyFromSeen || section.copyToSeen {
					return false, true
				}
				section.renameTo, section.renameToSeen = decoded, true
			case strings.HasPrefix(line, "copy from "):
				if section.copyFromSeen || section.renameFromSeen || section.renameToSeen {
					return false, true
				}
				section.copyFrom, section.copyFromSeen = decoded, true
			case strings.HasPrefix(line, "copy to "):
				if !section.copyFromSeen || section.copyToSeen || section.renameFromSeen || section.renameToSeen {
					return false, true
				}
				section.copyTo, section.copyToSeen = decoded, true
			}
		case strings.HasPrefix(line, "@@ "):
			if !section.oldSeen || !section.newSeen {
				return false, true
			}
			match := hunkHeader.FindStringSubmatch(line)
			if match == nil {
				return false, true
			}
			oldCount, newCount := rangeCount(match[2]), rangeCount(match[4])
			if oldCount < 0 || newCount < 0 {
				return false, true
			}
			section.hunkSeen = true
			bodySeen, markerAfterLastBody := false, false
			for oldCount > 0 || newCount > 0 {
				index++
				if index >= len(lines) {
					return false, true
				}
				body := lines[index]
				if body == "\\ No newline at end of file" {
					if !bodySeen || markerAfterLastBody {
						return false, true
					}
					markerAfterLastBody = true
					continue
				}
				if body == "" {
					return false, true
				}
				switch body[0] {
				case ' ':
					oldCount--
					newCount--
				case '-':
					oldCount--
				case '+':
					newCount--
				default:
					return false, true
				}
				if oldCount < 0 || newCount < 0 {
					return false, true
				}
				bodySeen, markerAfterLastBody = true, false
			}
			if index+1 < len(lines) && lines[index+1] == "\\ No newline at end of file" {
				if !bodySeen || markerAfterLastBody {
					return false, true
				}
				index++
			}
		case line == "":
			if index != len(lines)-1 {
				return false, true
			}
		case strings.HasPrefix(line, "index ") || strings.HasPrefix(line, "new file mode ") || strings.HasPrefix(line, "deleted file mode ") || strings.HasPrefix(line, "old mode ") || strings.HasPrefix(line, "new mode ") || strings.HasPrefix(line, "similarity index ") || strings.HasPrefix(line, "dissimilarity index "):
			if !section.started || !section.git || section.oldSeen || section.newSeen || section.hunkSeen || section.renameFromSeen || section.renameToSeen || section.copyFromSeen || section.copyToSeen {
				return false, true
			}
			switch {
			case strings.HasPrefix(line, "index "):
				match := indexMetadata.FindStringSubmatch(line)
				if section.indexSeen || match == nil || len(match[1]) != len(match[2]) {
					return false, true
				}
				section.indexSeen = true
			case strings.HasPrefix(line, "similarity index "):
				if section.similaritySeen || section.dissimilaritySeen || !similarityMetadata.MatchString(line) {
					return false, true
				}
				section.similaritySeen = true
			case strings.HasPrefix(line, "dissimilarity index "):
				if section.dissimilaritySeen || section.similaritySeen || !similarityMetadata.MatchString(line) {
					return false, true
				}
				section.dissimilaritySeen = true
			default:
				match := modeMetadata.FindStringSubmatch(line)
				if match == nil {
					return false, true
				}
				switch match[1] {
				case "new file mode":
					if section.newFileModeSeen || section.deletedFileModeSeen || section.oldModeSeen || section.newModeSeen {
						return false, true
					}
					section.newFileModeSeen = true
				case "deleted file mode":
					if section.deletedFileModeSeen || section.newFileModeSeen || section.oldModeSeen || section.newModeSeen {
						return false, true
					}
					section.deletedFileModeSeen = true
				case "old mode":
					if section.oldModeSeen || section.newFileModeSeen || section.deletedFileModeSeen {
						return false, true
					}
					section.oldModeSeen = true
					section.oldMode = match[2]
				case "new mode":
					if !section.oldModeSeen || section.newModeSeen || section.newFileModeSeen || section.deletedFileModeSeen {
						return false, true
					}
					section.newModeSeen = true
					section.newMode = match[2]
				}
			}
		default:
			return false, true
		}
	}
	if !validSection(section) {
		return false, true
	}
	sections++
	if sections == 0 {
		return false, true
	}
	return true, !privateFound
}

func rangeCount(value string) int {
	if value == "" {
		return 1
	}
	count, err := strconv.Atoi(value)
	if err != nil {
		return -1
	}
	return count
}
func stripAB(value string) string {
	if strings.HasPrefix(value, "a/") || strings.HasPrefix(value, "b/") {
		return value[2:]
	}
	return value
}
func parseHeaderPath(value, prefix string) (string, bool) {
	if tab := strings.IndexByte(value, '\t'); tab >= 0 {
		value = value[:tab]
	}
	decoded, ok := decodeGitPath(value)
	if !ok {
		return "", false
	}
	if decoded == "/dev/null" {
		return decoded, true
	}
	decoded = strings.TrimPrefix(decoded, prefix)
	return decoded, canonicalGitPath(decoded)
}
func parseDiffGitPaths(value string) (string, string, bool) {
	first, rest, ok := nextGitPath(value)
	if !ok {
		return "", "", false
	}
	second, tail, ok := nextGitPath(strings.TrimLeft(rest, " "))
	return first, second, ok && strings.TrimSpace(tail) == ""
}
func nextGitPath(value string) (string, string, bool) {
	if value == "" {
		return "", "", false
	}
	if value[0] == '"' {
		escaped := false
		for index := 1; index < len(value); index++ {
			if value[index] == '"' && !escaped {
				decoded, err := strconv.Unquote(value[:index+1])
				return decoded, value[index+1:], err == nil
			}
			if value[index] == '\\' && !escaped {
				escaped = true
			} else {
				escaped = false
			}
		}
		return "", "", false
	}
	if separator := strings.IndexByte(value, ' '); separator >= 0 {
		return value[:separator], value[separator:], true
	}
	return value, "", true
}
func decodeGitPath(value string) (string, bool) {
	if strings.HasPrefix(value, "\"") {
		decoded, err := strconv.Unquote(value)
		return decoded, err == nil
	}
	return value, true
}
