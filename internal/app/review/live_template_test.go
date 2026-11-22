package review

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/app/prompt"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

type templateLiveReader struct {
	binding ports.ProjectBindingObservation
	target  ports.LiveSourceTarget
	bySide  map[domain.LiveSourceSide][]ports.SafeRelativePath
}

func (reader *templateLiveReader) Root() ports.AnchoredRoot       { return reader.binding.Root }
func (reader *templateLiveReader) Target() ports.LiveSourceTarget { return reader.target }
func (reader *templateLiveReader) RevalidateExecution(context.Context) (ports.ProjectBindingObservation, error) {
	return reader.binding, nil
}
func (reader *templateLiveReader) List(_ context.Context, side domain.LiveSourceSide) ([]ports.SafeRelativePath, error) {
	return append([]ports.SafeRelativePath(nil), reader.bySide[side]...), nil
}
func (*templateLiveReader) Read(context.Context, domain.LiveSourceSide, ports.SafeRelativePath) (ports.LiveSourceFile, error) {
	return ports.LiveSourceFile{}, fmt.Errorf("unexpected live read during template composition")
}
func (*templateLiveReader) AdmitPath(context.Context, domain.LiveSourceSide, ports.SafeRelativePath) error {
	return fmt.Errorf("unexpected live path admission during template composition")
}
func (*templateLiveReader) Close() error { return nil }

type templateLiveHome struct {
	ports.ReviewerHome
	root ports.AnchoredRoot
}

func (home templateLiveHome) Root() ports.AnchoredRoot { return home.root }
func (templateLiveHome) Revalidate() error             { return nil }
func (templateLiveHome) Guide() []byte                 { return []byte("Shared reviewer guide fixture.") }

func liveTemplateTestSet(t *testing.T) (TemplateSet, prompt.TrustedLayer) {
	t.Helper()
	layer := func(id, text string) prompt.TrustedLayer {
		t.Helper()
		value, err := prompt.NewTrustedLayer(id, "1", []byte(text))
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	roles := map[domain.Role]prompt.TrustedLayer{
		domain.RoleLogic: layer("builtin:review/role/logic", "Review logic defects."),
	}
	templates, err := NewTemplateSet(
		layer("builtin:review/common", "Common root review instructions."),
		layer("builtin:review/run", "Run instructions."),
		layer("builtin:review/json-output", "Return JSON only."),
		layer("builtin:review/repair", "Repair instructions."),
		layer("builtin:review/extract", "Extract instructions."),
		roles,
	)
	if err != nil {
		t.Fatal(err)
	}
	common := layer("builtin:review/live-common", "Live common review instructions.")
	return templates, common
}

func mustSafePath(t *testing.T, raw string) ports.SafeRelativePath {
	t.Helper()
	path, err := ports.NewSafeRelativePath(raw)
	if err != nil {
		t.Fatalf("NewSafeRelativePath(%q): %v", raw, err)
	}
	return path
}

func mustSafePaths(t *testing.T, values ...string) []ports.SafeRelativePath {
	t.Helper()
	out := make([]ports.SafeRelativePath, 0, len(values))
	for _, value := range values {
		out = append(out, mustSafePath(t, value))
	}
	return out
}

func mustLiveExecutionForTemplateTest(t *testing.T, rootPath string, target ports.LiveSourceTarget, bySide map[domain.LiveSourceSide][]ports.SafeRelativePath) ports.LiveReviewExecution {
	t.Helper()
	root, err := ports.NewAnchoredRoot(rootPath)
	if err != nil {
		t.Fatalf("NewAnchoredRoot(%q): %v", rootPath, err)
	}
	neutral, err := ports.NewAnchoredRoot("/neutral")
	if err != nil {
		t.Fatal(err)
	}
	credential, err := ports.NewAnchoredRoot("/credentials")
	if err != nil {
		t.Fatal(err)
	}
	reader := &templateLiveReader{
		target: target,
		bySide: bySide,
		binding: ports.ProjectBindingObservation{
			Root:         root,
			RootIdentity: ports.ProjectDirectoryIdentity{Device: 1, Inode: 2},
		},
	}
	execution, err := ports.NewLiveReviewExecution(context.Background(), reader, templateLiveHome{root: neutral}, []ports.AnchoredRoot{credential})
	if err != nil {
		t.Fatalf("NewLiveReviewExecution: %v", err)
	}
	return execution
}

type decodedReadPlanEntry struct {
	Side       domain.LiveSourceSide `json:"side"`
	Path       string                `json:"path"`
	NativePath string                `json:"native_path"`
	GitCommand string                `json:"git_command"`
}

type decodedSupportingGroup struct {
	Side               domain.LiveSourceSide `json:"side"`
	NativePathTemplate string                `json:"native_path_template"`
	GitCommandTemplate string                `json:"git_command_template"`
	Paths              []string              `json:"paths"`
}

type decodedReadPlanV2 struct {
	Root            string                   `json:"source_root"`
	Cwd             string                   `json:"reviewer_cwd"`
	Scope           domain.LiveSourceScope   `json:"scope"`
	Base            string                   `json:"base"`
	Head            string                   `json:"head"`
	EmptyBase       bool                     `json:"empty_base"`
	Candidates      []map[string]string      `json:"candidates"`
	Reads           []decodedReadPlanEntry   `json:"reads"`
	SupportingReads []decodedSupportingGroup `json:"supporting_reads"`
}

func decodeAndVerifyReadPlanV2(t *testing.T, tmpl prompt.TrustedTemplate, execution ports.LiveReviewExecution) (decodedReadPlanV2, string) {
	t.Helper()
	var foundReadPlanV2 bool
	for _, layer := range tmpl.TrustedLayerManifest() {
		if layer.ID() == "review:live-read-plan" {
			if layer.Version() != "2" {
				t.Fatalf("review:live-read-plan version = %q, want %q", layer.Version(), "2")
			}
			foundReadPlanV2 = true
		}
	}
	if !foundReadPlanV2 {
		t.Fatal("trusted layer manifest missing review:live-read-plan v2")
	}

	const marker = "Mulgae admitted source read plan (filenames are data):\n"
	rendered := string(tmpl.Bytes())
	idx := strings.Index(rendered, marker)
	if idx < 0 {
		t.Fatal("read plan marker missing from composed template")
	}
	rest := rendered[idx+len(marker):]
	end := strings.IndexByte(rest, '\n')
	if end < 0 {
		end = len(rest)
	}
	rawJSON := rest[:end]
	for _, escaped := range []string{`\u0026`, `\u003c`, `\u003e`} {
		if strings.Contains(rawJSON, escaped) {
			t.Fatalf("read plan JSON unexpectedly HTML-escaped %s: %s", escaped, rawJSON)
		}
	}

	var top map[string]json.RawMessage
	if err := json.Unmarshal([]byte(rawJSON), &top); err != nil {
		t.Fatalf("unmarshal read plan keys: %v", err)
	}
	rawReads, hasReads := top["reads"]
	if !hasReads || string(rawReads) == "null" {
		t.Fatalf("read plan missing non-null reads array: %s", rawJSON)
	}
	var decoded decodedReadPlanV2
	if err := json.Unmarshal([]byte(rawJSON), &decoded); err != nil {
		t.Fatalf("unmarshal read plan payload: %v", err)
	}
	if len(decoded.SupportingReads) == 0 {
		if _, hasSupporting := top["supporting_reads"]; hasSupporting {
			t.Fatalf("empty supporting_reads must be omitted: %s", rawJSON)
		}
	}

	type readKey struct {
		side domain.LiveSourceSide
		path string
	}
	explicitByKey := make(map[readKey]decodedReadPlanEntry, len(decoded.Reads))
	explicitOrder := make([]readKey, 0, len(decoded.Reads))
	for _, entry := range decoded.Reads {
		key := readKey{side: entry.Side, path: entry.Path}
		if _, dup := explicitByKey[key]; dup {
			t.Fatalf("duplicate explicit read entry: %+v", entry)
		}
		explicitByKey[key] = entry
		explicitOrder = append(explicitOrder, key)
	}

	expandedByKey := make(map[readKey]decodedReadPlanEntry)
	seenSides := make(map[domain.LiveSourceSide]bool)
	supportingSideOrder := make([]domain.LiveSourceSide, 0, len(decoded.SupportingReads))
	supportingPathsBySide := make(map[domain.LiveSourceSide][]string, len(decoded.SupportingReads))
	for _, group := range decoded.SupportingReads {
		if len(group.Paths) == 0 {
			t.Fatalf("empty supporting_reads group emitted: %+v", group)
		}
		if seenSides[group.Side] {
			t.Fatalf("duplicate supporting_reads side %q", group.Side)
		}
		seenSides[group.Side] = true
		supportingSideOrder = append(supportingSideOrder, group.Side)
		hasNative := group.NativePathTemplate != ""
		hasGit := group.GitCommandTemplate != ""
		if hasNative == hasGit {
			t.Fatalf("supporting_reads group must set exactly one template: %+v", group)
		}
		for _, p := range group.Paths {
			key := readKey{side: group.Side, path: p}
			if _, dup := expandedByKey[key]; dup {
				t.Fatalf("duplicate supporting_reads entry: %+v", key)
			}
			if _, overlap := explicitByKey[key]; overlap {
				t.Fatalf("entry present in both reads and supporting_reads: %+v", key)
			}
			entry := decodedReadPlanEntry{Side: group.Side, Path: p}
			if hasNative {
				entry.NativePath = strings.ReplaceAll(group.NativePathTemplate, "{path}", p)
			} else {
				entry.GitCommand = strings.ReplaceAll(group.GitCommandTemplate, "{path}", p)
			}
			expandedByKey[key] = entry
			supportingPathsBySide[group.Side] = append(supportingPathsBySide[group.Side], p)
		}
	}

	admittedReads := execution.Reads()
	if len(explicitByKey)+len(expandedByKey) != len(admittedReads) {
		t.Fatalf("reconstructed read count = %d (explicit=%d, supporting=%d), want %d", len(explicitByKey)+len(expandedByKey), len(explicitByKey), len(expandedByKey), len(admittedReads))
	}

	afterSide := domain.LiveSourceAfter
	switch execution.Target().Selector().Scope() {
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

	wantExplicitOrder := make([]readKey, 0, len(explicitOrder))
	wantSupportingSides := make([]domain.LiveSourceSide, 0, len(supportingSideOrder))
	wantSupportingSideSeen := make(map[domain.LiveSourceSide]bool)
	wantSupportingPaths := make(map[domain.LiveSourceSide][]string)

	for _, admitted := range admittedReads {
		key := readKey{side: admitted.Side(), path: admitted.Path().String()}
		wantNative := ""
		if admitted.GitCommand() == "" {
			wantNative = filepath.Join(execution.Binding().Root.String(), key.path)
		}
		entry, inExplicit := explicitByKey[key]
		if !inExplicit {
			var inSupporting bool
			entry, inSupporting = expandedByKey[key]
			if !inSupporting {
				t.Fatalf("admitted read missing from read plan v2: %+v", key)
			}
			if !wantSupportingSideSeen[key.side] {
				wantSupportingSideSeen[key.side] = true
				wantSupportingSides = append(wantSupportingSides, key.side)
			}
			wantSupportingPaths[key.side] = append(wantSupportingPaths[key.side], key.path)
		} else {
			wantExplicitOrder = append(wantExplicitOrder, key)
		}
		if entry.Side != admitted.Side() || entry.Path != key.path || entry.NativePath != wantNative || entry.GitCommand != admitted.GitCommand() {
			t.Fatalf("lossless parity mismatch for %+v:\ngot:  %+v\nwant: native=%q git=%q", key, entry, wantNative, admitted.GitCommand())
		}

		_, isCandidate := candidateKeys[key]
		if isCandidate && !inExplicit {
			t.Fatalf("changed candidate %+v was compacted into supporting_reads instead of explicit reads", key)
		}
		if !isCandidate && !isCompactSupportingPath(key.path) && !inExplicit {
			t.Fatalf("non-allowlisted supporting path %+v was compacted into supporting_reads", key)
		}
	}

	if !slices.Equal(explicitOrder, wantExplicitOrder) {
		t.Fatalf("explicit reads order drifted:\ngot:  %v\nwant: %v", explicitOrder, wantExplicitOrder)
	}
	if !slices.Equal(supportingSideOrder, wantSupportingSides) {
		t.Fatalf("supporting_reads side order drifted:\ngot:  %v\nwant: %v", supportingSideOrder, wantSupportingSides)
	}
	for side, wantPaths := range wantSupportingPaths {
		if !slices.Equal(supportingPathsBySide[side], wantPaths) {
			t.Fatalf("supporting_reads paths order drifted for side %s", side)
		}
	}
	return decoded, rawJSON
}

func TestIsCompactSupportingPath(t *testing.T) {
	t.Parallel()
	valid := []string{
		"a",
		"0",
		"README.md",
		".hidden",
		".github/workflows/ci.yml",
		"a..b.txt",
		"pkg/..internal/file..go",
		"dir/-flag.txt",
		"src/Main_01-v2.go",
		"a/b/c",
	}
	for _, path := range valid {
		if !isCompactSupportingPath(path) {
			t.Errorf("isCompactSupportingPath(%q) = false, want true", path)
		}
	}
	invalid := []string{
		"",
		".",
		"..",
		"./a.go",
		"../a.go",
		"a/./b.go",
		"a/../b.go",
		"a/.",
		"a/..",
		"a//b.go",
		"a///b.go",
		"/abs.go",
		"/",
		"dir/",
		"a/b/",
		"-",
		"-flag.txt",
		"-dir/a.go",
		"a b.txt",
		"a'b.txt",
		`a"b.txt`,
		"a&b.txt",
		"a<b.txt",
		"a>b.txt",
		"한글.txt",
		"café.txt",
		"a(b).txt",
		"a:b.txt",
		"{path}",
		"dir/{path}/a.go",
		`a\b.txt`,
		"a\tb.txt",
		"a\nb.txt",
		"a;b.txt",
		"$a.txt",
		"`a`.txt",
	}
	for _, path := range invalid {
		if isCompactSupportingPath(path) {
			t.Errorf("isCompactSupportingPath(%q) = true, want false", path)
		}
	}
}

func TestSupportingReadTemplateGuards(t *testing.T) {
	t.Parallel()
	base := strings.Repeat("a", 40)
	head := strings.Repeat("b", 40)

	for _, root := range []string{"", "/", "/source/", "/source/../other", "/source/{path}/repo"} {
		if _, _, ok := supportingReadTemplate(domain.LiveSourceWorkspace, root, "", "", false, domain.LiveSourceWorktree); ok {
			t.Errorf("worktree template accepted unsafe root %q", root)
		}
	}
	for _, root := range []string{"/source", "/source/my project (v2)", "/source/a&b<c>d"} {
		nativeTpl, gitTpl, ok := supportingReadTemplate(domain.LiveSourceWorkspace, root, "", "", false, domain.LiveSourceWorktree)
		if !ok || nativeTpl != root+"/{path}" || gitTpl != "" {
			t.Errorf("worktree template(%q) = (%q, %q, %t)", root, nativeTpl, gitTpl, ok)
		}
	}
	if _, _, ok := supportingReadTemplate(domain.LiveSourceStage, "/source", base, "", false, domain.LiveSourceWorktree); ok {
		t.Error("worktree template accepted non-workspace scope")
	}
	if _, _, ok := supportingReadTemplate(domain.LiveSourceStage, "/source", "", "", true, domain.LiveSourceBefore); ok {
		t.Error("before template accepted emptyBase")
	}
	if _, _, ok := supportingReadTemplate(domain.LiveSourceCommit, "/source", base, head, false, domain.LiveSourceIndex); ok {
		t.Error("index template accepted non-stage scope")
	}
	if _, _, ok := supportingReadTemplate(domain.LiveSourceStage, "/source", base, "", false, domain.LiveSourceAfter); ok {
		t.Error("after template accepted stage scope")
	}
	if _, _, ok := supportingReadTemplate(domain.LiveSourceDiff, "/source", base, head, false, domain.LiveSourceSide("unknown")); ok {
		t.Error("template accepted unknown side")
	}
}

func TestComposeLiveRootReviewReadPlanV2LosslessParityAcrossScopes(t *testing.T) {
	t.Parallel()
	templates, common := liveTemplateTestSet(t)
	baseOID, _ := ports.ParseGitObjectID(strings.Repeat("a", 40))
	headOID, _ := ports.ParseGitObjectID(strings.Repeat("b", 40))

	adversarialPaths := []string{
		"dir/a'b.txt",
		"dir/my file.txt",
		"dir/a&b<c>d.txt",
		"dir/한글_café.txt",
		"-leading.txt",
		"dir/file (copy).txt",
		"dir/a:b.txt",
		"dir/{path}/file.txt",
	}
	allowlistedSupporting := []string{
		".hidden",
		"a..b.txt",
		"pkg/sub/file_1-2.go",
	}

	t.Run("workspace whole-tree all allowlisted keeps reads empty array", func(t *testing.T) {
		selector, _ := ports.NewLiveSourceSelector(domain.LiveSourceWorkspace, "")
		paths := mustSafePaths(t, allowlistedSupporting...)
		changes := make([]ports.LiveSourceChange, 0, len(paths))
		for _, p := range paths {
			changes = append(changes, ports.LiveSourceChange{Kind: "included", After: p})
		}
		target, err := ports.NewLiveSourceTarget(selector, ports.GitObjectID{}, ports.GitObjectID{}, false, changes)
		if err != nil {
			t.Fatal(err)
		}
		exec := mustLiveExecutionForTemplateTest(t, "/source", target, map[domain.LiveSourceSide][]ports.SafeRelativePath{
			domain.LiveSourceWorktree: paths,
		})
		tmpl, err := templates.ComposeLiveRootReview(context.Background(), common, exec, domain.RoleLogic, nil)
		if err != nil {
			t.Fatal(err)
		}
		decoded, rawJSON := decodeAndVerifyReadPlanV2(t, tmpl, exec)
		if len(decoded.Reads) != 0 || !strings.Contains(rawJSON, `"reads":[]`) {
			t.Fatalf("expected empty explicit reads array for whole-tree workspace, got: %s", rawJSON)
		}
		if len(decoded.SupportingReads) != 1 || decoded.SupportingReads[0].Side != domain.LiveSourceWorktree || decoded.SupportingReads[0].NativePathTemplate != "/source/{path}" || len(decoded.SupportingReads[0].Paths) != len(allowlistedSupporting) {
			t.Fatalf("unexpected workspace supporting_reads: %+v", decoded.SupportingReads)
		}
	})

	t.Run("workspace mixed allowlisted and adversarial paths", func(t *testing.T) {
		selector, _ := ports.NewLiveSourceSelector(domain.LiveSourceWorkspace, "")
		allRaw := append(append([]string(nil), allowlistedSupporting...), adversarialPaths...)
		paths := mustSafePaths(t, allRaw...)
		changes := make([]ports.LiveSourceChange, 0, len(paths))
		for _, p := range paths {
			changes = append(changes, ports.LiveSourceChange{Kind: "included", After: p})
		}
		target, err := ports.NewLiveSourceTarget(selector, ports.GitObjectID{}, ports.GitObjectID{}, false, changes)
		if err != nil {
			t.Fatal(err)
		}
		exec := mustLiveExecutionForTemplateTest(t, "/source", target, map[domain.LiveSourceSide][]ports.SafeRelativePath{
			domain.LiveSourceWorktree: paths,
		})
		tmpl, err := templates.ComposeLiveRootReview(context.Background(), common, exec, domain.RoleLogic, nil)
		if err != nil {
			t.Fatal(err)
		}
		decoded, rawJSON := decodeAndVerifyReadPlanV2(t, tmpl, exec)
		if len(decoded.Reads) != len(adversarialPaths) {
			t.Fatalf("explicit fallback count = %d, want %d", len(decoded.Reads), len(adversarialPaths))
		}
		if !strings.Contains(rawJSON, "dir/a&b<c>d.txt") {
			t.Fatalf("HTML chars were not preserved verbatim: %s", rawJSON)
		}
		if len(decoded.SupportingReads) != 1 || len(decoded.SupportingReads[0].Paths) != len(allowlistedSupporting) {
			t.Fatalf("unexpected supporting_reads: %+v", decoded.SupportingReads)
		}
	})

	t.Run("head whole-tree mixed allowlisted and adversarial paths", func(t *testing.T) {
		selector, _ := ports.NewLiveSourceSelector(domain.LiveSourceHead, "")
		allRaw := append(append([]string(nil), allowlistedSupporting...), adversarialPaths...)
		paths := mustSafePaths(t, allRaw...)
		changes := make([]ports.LiveSourceChange, 0, len(paths))
		for _, p := range paths {
			changes = append(changes, ports.LiveSourceChange{Kind: "included", After: p})
		}
		target, err := ports.NewLiveSourceTarget(selector, ports.GitObjectID{}, headOID, false, changes)
		if err != nil {
			t.Fatal(err)
		}
		exec := mustLiveExecutionForTemplateTest(t, "/source", target, map[domain.LiveSourceSide][]ports.SafeRelativePath{
			domain.LiveSourceAfter: paths,
		})
		tmpl, err := templates.ComposeLiveRootReview(context.Background(), common, exec, domain.RoleLogic, nil)
		if err != nil {
			t.Fatal(err)
		}
		decoded, _ := decodeAndVerifyReadPlanV2(t, tmpl, exec)
		if len(decoded.Reads) != len(adversarialPaths) {
			t.Fatalf("head explicit reads = %d, want %d", len(decoded.Reads), len(adversarialPaths))
		}
		wantTpl := "git --no-pager show '" + headOID.String() + ":{path}'"
		if len(decoded.SupportingReads) != 1 || decoded.SupportingReads[0].Side != domain.LiveSourceAfter || decoded.SupportingReads[0].GitCommandTemplate != wantTpl {
			t.Fatalf("unexpected head supporting_reads: %+v", decoded.SupportingReads)
		}
	})

	transitionScopes := []struct {
		name      string
		scope     domain.LiveSourceScope
		operand   string
		base      ports.GitObjectID
		head      ports.GitObjectID
		emptyBase bool
		afterSide domain.LiveSourceSide
	}{
		{name: "stage normal", scope: domain.LiveSourceStage, base: baseOID, afterSide: domain.LiveSourceIndex},
		{name: "stage emptyBase", scope: domain.LiveSourceStage, emptyBase: true, afterSide: domain.LiveSourceIndex},
		{name: "commit normal", scope: domain.LiveSourceCommit, operand: "HEAD", base: baseOID, head: headOID, afterSide: domain.LiveSourceAfter},
		{name: "commit emptyBase", scope: domain.LiveSourceCommit, operand: "HEAD", head: headOID, emptyBase: true, afterSide: domain.LiveSourceAfter},
		{name: "diff", scope: domain.LiveSourceDiff, operand: "HEAD~1..HEAD", base: baseOID, head: headOID, afterSide: domain.LiveSourceAfter},
	}

	for _, tc := range transitionScopes {
		t.Run(tc.name, func(t *testing.T) {
			selector, err := ports.NewLiveSourceSelector(tc.scope, tc.operand)
			if err != nil {
				t.Fatal(err)
			}
			added := mustSafePath(t, "cand/added.go")
			modified := mustSafePath(t, "cand/modified.go")
			deleted := mustSafePath(t, "cand/deleted.go")
			renameOld := mustSafePath(t, "cand/old_name.go")
			renameNew := mustSafePath(t, "cand/new_name.go")
			quotedCand := mustSafePath(t, "cand/it's & <changed>.go")

			var changes []ports.LiveSourceChange
			var beforePaths []ports.SafeRelativePath
			afterPaths := []ports.SafeRelativePath{added, quotedCand}

			if tc.emptyBase {
				changes = []ports.LiveSourceChange{
					{Kind: "added", After: added},
					{Kind: "added", After: quotedCand},
				}
			} else {
				changes = []ports.LiveSourceChange{
					{Kind: "modified", Before: modified, After: modified},
					{Kind: "added", After: added},
					{Kind: "deleted", Before: deleted},
					{Kind: "renamed", Before: renameOld, After: renameNew},
					{Kind: "modified", Before: quotedCand, After: quotedCand},
				}
				beforePaths = append(beforePaths, modified, deleted, renameOld, quotedCand)
				beforePaths = append(beforePaths, mustSafePaths(t, allowlistedSupporting...)...)
				beforePaths = append(beforePaths, mustSafePaths(t, adversarialPaths...)...)
				afterPaths = append(afterPaths, modified, renameNew)
			}
			afterPaths = append(afterPaths, mustSafePaths(t, allowlistedSupporting...)...)
			afterPaths = append(afterPaths, mustSafePaths(t, adversarialPaths...)...)

			target, err := ports.NewLiveSourceTarget(selector, tc.base, tc.head, tc.emptyBase, changes)
			if err != nil {
				t.Fatal(err)
			}
			bySide := map[domain.LiveSourceSide][]ports.SafeRelativePath{
				tc.afterSide: afterPaths,
			}
			if !tc.emptyBase {
				bySide[domain.LiveSourceBefore] = beforePaths
			}
			exec := mustLiveExecutionForTemplateTest(t, "/source", target, bySide)
			tmpl, err := templates.ComposeLiveRootReview(context.Background(), common, exec, domain.RoleLogic, nil)
			if err != nil {
				t.Fatal(err)
			}
			decoded, _ := decodeAndVerifyReadPlanV2(t, tmpl, exec)

			wantGroups := 2
			if tc.emptyBase {
				wantGroups = 1
			}
			if len(decoded.SupportingReads) != wantGroups {
				t.Fatalf("supporting_reads groups = %d, want %d: %+v", len(decoded.SupportingReads), wantGroups, decoded.SupportingReads)
			}
			for _, g := range decoded.SupportingReads {
				if len(g.Paths) != len(allowlistedSupporting) {
					t.Fatalf("supporting group %s paths = %d, want %d", g.Side, len(g.Paths), len(allowlistedSupporting))
				}
			}
			// Verify single-side candidates were never synthesized on the absent side.
			for _, r := range decoded.Reads {
				if r.Path == added.String() && r.Side == domain.LiveSourceBefore {
					t.Fatal("added candidate was synthesized on before side")
				}
				if r.Path == deleted.String() && r.Side == tc.afterSide {
					t.Fatal("deleted candidate was synthesized on after side")
				}
			}
		})
	}

	t.Run("all candidates with zero supporting omits supporting_reads", func(t *testing.T) {
		selector, _ := ports.NewLiveSourceSelector(domain.LiveSourceStage, "")
		only := mustSafePath(t, "only.go")
		target, err := ports.NewLiveSourceTarget(selector, baseOID, ports.GitObjectID{}, false, []ports.LiveSourceChange{
			{Kind: "modified", Before: only, After: only},
		})
		if err != nil {
			t.Fatal(err)
		}
		exec := mustLiveExecutionForTemplateTest(t, "/source", target, map[domain.LiveSourceSide][]ports.SafeRelativePath{
			domain.LiveSourceBefore: {only},
			domain.LiveSourceIndex:  {only},
		})
		tmpl, err := templates.ComposeLiveRootReview(context.Background(), common, exec, domain.RoleLogic, nil)
		if err != nil {
			t.Fatal(err)
		}
		decoded, _ := decodeAndVerifyReadPlanV2(t, tmpl, exec)
		if len(decoded.Reads) != 2 || len(decoded.SupportingReads) != 0 {
			t.Fatalf("expected 2 explicit reads and 0 supporting groups, got reads=%d supporting=%d", len(decoded.Reads), len(decoded.SupportingReads))
		}
	})
}

func TestComposeLiveRootReviewReadPlanV2AdversarialRoots(t *testing.T) {
	t.Parallel()
	templates, common := liveTemplateTestSet(t)

	t.Run("workspace root containing {path} falls back all reads to explicit", func(t *testing.T) {
		selector, _ := ports.NewLiveSourceSelector(domain.LiveSourceWorkspace, "")
		paths := mustSafePaths(t, "a.go", "pkg/b.go")
		target, err := ports.NewLiveSourceTarget(selector, ports.GitObjectID{}, ports.GitObjectID{}, false, []ports.LiveSourceChange{
			{Kind: "included", After: paths[0]},
			{Kind: "included", After: paths[1]},
		})
		if err != nil {
			t.Fatal(err)
		}
		exec := mustLiveExecutionForTemplateTest(t, "/source/{path}/repo", target, map[domain.LiveSourceSide][]ports.SafeRelativePath{
			domain.LiveSourceWorktree: paths,
		})
		tmpl, err := templates.ComposeLiveRootReview(context.Background(), common, exec, domain.RoleLogic, nil)
		if err != nil {
			t.Fatal(err)
		}
		decoded, _ := decodeAndVerifyReadPlanV2(t, tmpl, exec)
		if len(decoded.Reads) != 2 || len(decoded.SupportingReads) != 0 {
			t.Fatalf("root containing {path} must fall back all worktree reads: reads=%d supporting=%d", len(decoded.Reads), len(decoded.SupportingReads))
		}
	})

	t.Run("workspace root with spaces and parentheses compacts losslessly", func(t *testing.T) {
		selector, _ := ports.NewLiveSourceSelector(domain.LiveSourceWorkspace, "")
		paths := mustSafePaths(t, "pkg/clean.go", "dir/it's & <raw>.txt")
		target, err := ports.NewLiveSourceTarget(selector, ports.GitObjectID{}, ports.GitObjectID{}, false, []ports.LiveSourceChange{
			{Kind: "included", After: paths[0]},
			{Kind: "included", After: paths[1]},
		})
		if err != nil {
			t.Fatal(err)
		}
		root := "/source/my project (v2) & <live>"
		exec := mustLiveExecutionForTemplateTest(t, root, target, map[domain.LiveSourceSide][]ports.SafeRelativePath{
			domain.LiveSourceWorktree: paths,
		})
		tmpl, err := templates.ComposeLiveRootReview(context.Background(), common, exec, domain.RoleLogic, nil)
		if err != nil {
			t.Fatal(err)
		}
		decoded, rawJSON := decodeAndVerifyReadPlanV2(t, tmpl, exec)
		if !strings.Contains(rawJSON, root) {
			t.Fatalf("root with HTML characters was escaped or altered: %s", rawJSON)
		}
		if len(decoded.Reads) != 1 || len(decoded.SupportingReads) != 1 || decoded.SupportingReads[0].NativePathTemplate != root+"/{path}" {
			t.Fatalf("unexpected compaction for special root: reads=%+v supporting=%+v", decoded.Reads, decoded.SupportingReads)
		}
	})
}

func TestComposeLiveRootReviewReadPlanV2HasNoPathOrByteCeiling(t *testing.T) {
	t.Parallel()
	templates, common := liveTemplateTestSet(t)
	selector, _ := ports.NewLiveSourceSelector(domain.LiveSourceStage, "")
	baseOID, _ := ports.ParseGitObjectID(strings.Repeat("a", 40))

	cand1 := mustSafePath(t, "changed/one.go")
	cand2 := mustSafePath(t, "changed/two.go")
	const supportingCount = 1600
	files := make([]ports.SafeRelativePath, 0, supportingCount+2)
	files = append(files, cand1, cand2)
	for i := 0; i < supportingCount; i++ {
		files = append(files, mustSafePath(t, fmt.Sprintf("pkg/mod%04d/file_%04d.go", i, i)))
	}
	target, err := ports.NewLiveSourceTarget(selector, baseOID, ports.GitObjectID{}, false, []ports.LiveSourceChange{
		{Kind: "modified", Before: cand1, After: cand1},
		{Kind: "modified", Before: cand2, After: cand2},
	})
	if err != nil {
		t.Fatal(err)
	}
	exec := mustLiveExecutionForTemplateTest(t, "/source", target, map[domain.LiveSourceSide][]ports.SafeRelativePath{
		domain.LiveSourceBefore: files,
		domain.LiveSourceIndex:  files,
	})
	tmpl, err := templates.ComposeLiveRootReview(context.Background(), common, exec, domain.RoleLogic, nil)
	if err != nil {
		t.Fatal(err)
	}
	decoded, _ := decodeAndVerifyReadPlanV2(t, tmpl, exec)
	if len(decoded.Reads) != 4 {
		t.Fatalf("explicit candidate reads = %d, want 4", len(decoded.Reads))
	}
	if len(decoded.SupportingReads) != 2 || len(decoded.SupportingReads[0].Paths) != supportingCount || len(decoded.SupportingReads[1].Paths) != supportingCount {
		t.Fatalf("supporting_reads truncated or misgrouped: %d groups", len(decoded.SupportingReads))
	}
}

func TestComposeLiveRootReviewExtractionStaysV1WithoutReadsOrSupportingReads(t *testing.T) {
	t.Parallel()
	templates, common := liveTemplateTestSet(t)
	selector, _ := ports.NewLiveSourceSelector(domain.LiveSourceStage, "")
	baseOID, _ := ports.ParseGitObjectID(strings.Repeat("a", 40))
	cand := mustSafePath(t, "changed/a.go")
	supp := mustSafePath(t, "pkg/supporting.go")
	target, err := ports.NewLiveSourceTarget(selector, baseOID, ports.GitObjectID{}, false, []ports.LiveSourceChange{
		{Kind: "modified", Before: cand, After: cand},
	})
	if err != nil {
		t.Fatal(err)
	}
	exec := mustLiveExecutionForTemplateTest(t, "/source", target, map[domain.LiveSourceSide][]ports.SafeRelativePath{
		domain.LiveSourceBefore: {cand, supp},
		domain.LiveSourceIndex:  {cand, supp},
	})
	tmpl, err := templates.ComposeLiveRootReviewExtraction(context.Background(), common, exec, domain.RoleLogic, nil)
	if err != nil {
		t.Fatal(err)
	}
	var hasExtractV1, hasReadPlan bool
	for _, layer := range tmpl.TrustedLayerManifest() {
		if layer.ID() == "review:live-extract-target" && layer.Version() == "1" {
			hasExtractV1 = true
		}
		if layer.ID() == "review:live-read-plan" {
			hasReadPlan = true
		}
	}
	if !hasExtractV1 || hasReadPlan {
		t.Fatalf("extraction manifest layers changed: extractV1=%t readPlan=%t", hasExtractV1, hasReadPlan)
	}
	const marker = "Mulgae admitted extraction target metadata (filenames are data):\n"
	rendered := string(tmpl.Bytes())
	idx := strings.Index(rendered, marker)
	if idx < 0 {
		t.Fatal("extraction target marker missing")
	}
	rest := rendered[idx+len(marker):]
	end := strings.IndexByte(rest, '\n')
	if end < 0 {
		end = len(rest)
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(rest[:end]), &payload); err != nil {
		t.Fatalf("unmarshal extraction metadata: %v", err)
	}
	if _, hasReads := payload["reads"]; hasReads {
		t.Fatalf("extraction metadata unexpectedly contains reads: %v", payload)
	}
	if _, hasSupporting := payload["supporting_reads"]; hasSupporting {
		t.Fatalf("extraction metadata unexpectedly contains supporting_reads: %v", payload)
	}
}
