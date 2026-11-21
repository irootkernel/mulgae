//go:build darwin && arm64

package composition

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	appconfig "github.com/irootkernel/mulgae/internal/app/config"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

func TestProductionLiveSourcesExcludeAllCredentialProfilesAndRuntimeRoots(t *testing.T) {
	fixture := canonicalTestTempDir(t)
	project, _ := ports.NewAnchoredRoot(filepath.Join(fixture, "project"))
	home := filepath.Join(fixture, "operator")
	profile := filepath.Join(project.String(), "arbitrary-profile")
	for _, directory := range []string{project.String(), home, profile, filepath.Join(project.String(), ".podway"), filepath.Join(project.String(), ".gaori")} {
		if err := os.MkdirAll(directory, 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, relative := range []string{"source.txt", "arbitrary-profile/auth.json", ".podway/private.json", ".gaori/private.json"} {
		if err := os.WriteFile(filepath.Join(project.String(), relative), []byte("fixture\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	command := exec.Command("git", "-C", project.String(), "init", "--quiet")
	if raw, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git init: %v %s", err, raw)
	}
	config := appconfig.Config{NativeUser: appconfig.NativeUserConfig{Home: home}, Providers: appconfig.ProvidersConfig{Codex: &appconfig.CodexProviderConfig{CredentialHomes: []appconfig.CodexCredentialHomeConfig{{Profile: "unused", Home: profile}}}}}
	opener, credentials, err := productionLiveSources(config, project)
	if err != nil {
		t.Fatal(err)
	}
	wantCredentials := []string{
		filepath.Join(home, ".codex"),
		filepath.Join(home, ".grok"),
		filepath.Join(home, ".zcode"),
		filepath.Join(home, ".gemini"),
		filepath.Join(home, ".cursor"),
		filepath.Join(home, ".config", "cursor"),
		profile,
	}
	gotCredentials := make(map[string]bool, len(credentials))
	for _, root := range credentials {
		gotCredentials[root.String()] = true
	}
	if len(credentials) != len(wantCredentials) {
		t.Fatalf("all default and configured homes must remain denied: got %v, want %v", credentials, wantCredentials)
	}
	for _, want := range wantCredentials {
		if !gotCredentials[want] {
			t.Fatalf("missing credential boundary %q in %v", want, credentials)
		}
	}
	selector, _ := ports.NewLiveSourceSelector(domain.LiveSourceWorkspace, "")
	source, err := opener.OpenLiveSource(context.Background(), project, selector)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	paths, err := source.List(context.Background(), domain.LiveSourceWorktree)
	if err != nil || len(paths) != 1 || paths[0].String() != "source.txt" {
		t.Fatalf("private roots entered source inventory: %v %v", paths, err)
	}
	for _, change := range source.Target().Changes() {
		if strings.Contains(change.After.String(), "private") || strings.Contains(change.After.String(), "auth") {
			t.Fatalf("private root entered candidate: %v", change)
		}
	}
	credentialProject, _ := ports.NewAnchoredRoot(profile)
	if rejected, err := opener.OpenLiveSource(context.Background(), credentialProject, selector); err == nil {
		rejected.Close()
		t.Fatal("credential-owned project was admitted")
	}
}

func TestLiveSourceBoundariesRejectProjectAncestorOfReviewerHome(t *testing.T) {
	fixture := canonicalTestTempDir(t)
	home := filepath.Join(fixture, "operator")
	mulgaeDir := filepath.Join(home, ".mulgae")
	reviewerHome := filepath.Join(mulgaeDir, "home")
	for _, dir := range []string{
		reviewerHome,
		filepath.Join(home, "projects", "repo"),
		filepath.Join(home, ".mulgae-other"),
	} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	cfg := appconfig.Config{NativeUser: appconfig.NativeUserConfig{Home: home}}

	for _, test := range []struct {
		name    string
		project string
	}{
		{name: "filesystem root", project: "/"},
		{name: "parent of native home", project: fixture},
		{name: "native home itself", project: home},
		{name: "mulgae state directory", project: mulgaeDir},
		{name: "reviewer home itself", project: reviewerHome},
	} {
		t.Run("reject/"+test.name, func(t *testing.T) {
			root, err := ports.NewAnchoredRoot(test.project)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := liveSourceBoundaries(cfg, root); err == nil {
				t.Fatalf("liveSourceBoundaries accepted project root %q as ancestor of %q", test.project, reviewerHome)
			}
			if _, _, err := productionLiveSources(cfg, root); err == nil {
				t.Fatalf("productionLiveSources accepted project root %q as ancestor of %q", test.project, reviewerHome)
			}
		})
	}

	// Symlinked ~/.mulgae pointing inside a project root must also be rejected.
	t.Run("reject/symlinked reviewer home inside project", func(t *testing.T) {
		symlinkHome := filepath.Join(fixture, "symlink-operator")
		targetProject := filepath.Join(fixture, "target-project")
		targetMulgae := filepath.Join(targetProject, "embedded-mulgae")
		for _, dir := range []string{symlinkHome, targetMulgae} {
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.Symlink(targetMulgae, filepath.Join(symlinkHome, ".mulgae")); err != nil {
			t.Fatal(err)
		}
		symlinkCfg := appconfig.Config{NativeUser: appconfig.NativeUserConfig{Home: symlinkHome}}
		projectRoot, err := ports.NewAnchoredRoot(targetProject)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := liveSourceBoundaries(symlinkCfg, projectRoot); err == nil {
			t.Fatalf("liveSourceBoundaries accepted project %q containing symlinked ~/.mulgae", targetProject)
		}
	})

	// Symlinked project root pointing at nativeHome or ~/.mulgae must also be rejected.
	t.Run("reject/symlinked project root pointing to native home", func(t *testing.T) {
		symlinkProject := filepath.Join(fixture, "project-link")
		if err := os.Symlink(home, symlinkProject); err != nil {
			t.Fatal(err)
		}
		projectRoot, err := ports.NewAnchoredRoot(symlinkProject)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := liveSourceBoundaries(cfg, projectRoot); err == nil {
			t.Fatalf("liveSourceBoundaries accepted symlinked project %q -> %q", symlinkProject, home)
		}
	})

	// On case-insensitive filesystems (default APFS on macOS), case-variant paths
	// to home, .mulgae, and .mulgae/home must also be rejected via SameFile.
	t.Run("reject/case-variant ancestor on case-insensitive filesystem", func(t *testing.T) {
		homeInfo, err := os.Stat(home)
		if err != nil {
			t.Fatal(err)
		}
		upperHome := filepath.Join(fixture, "OPERATOR")
		upperInfo, err := os.Stat(upperHome)
		if err != nil || !os.SameFile(homeInfo, upperInfo) {
			t.Skip("filesystem is case-sensitive")
		}
		for _, variant := range []string{
			upperHome,
			filepath.Join(upperHome, ".MULGAE"),
			filepath.Join(upperHome, ".MULGAE", "HOME"),
		} {
			root, err := ports.NewAnchoredRoot(variant)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := liveSourceBoundaries(cfg, root); err == nil {
				t.Fatalf("liveSourceBoundaries accepted case-variant ancestor %q of %q", variant, reviewerHome)
			}
		}
	})

	// Dangling absolute symlink at ~/.mulgae/home pointing inside a project root must be rejected.
	t.Run("reject/dangling absolute symlink at reviewer home inside project", func(t *testing.T) {
		danglingHome := filepath.Join(fixture, "dangling-abs-operator")
		targetProject := filepath.Join(fixture, "dangling-abs-project")
		for _, dir := range []string{filepath.Join(danglingHome, ".mulgae"), targetProject} {
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
		}
		// Target does NOT exist yet (dangling symlink).
		if err := os.Symlink(filepath.Join(targetProject, "reviewer-home"), filepath.Join(danglingHome, ".mulgae", "home")); err != nil {
			t.Fatal(err)
		}
		danglingCfg := appconfig.Config{NativeUser: appconfig.NativeUserConfig{Home: danglingHome}}
		projectRoot, err := ports.NewAnchoredRoot(targetProject)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := liveSourceBoundaries(danglingCfg, projectRoot); err == nil {
			t.Fatalf("liveSourceBoundaries accepted project %q containing dangling ~/.mulgae/home target", targetProject)
		}
	})

	// Dangling relative symlink at ~/.mulgae pointing inside a project root must be rejected.
	t.Run("reject/dangling relative symlink at mulgae state inside project", func(t *testing.T) {
		danglingHome := filepath.Join(fixture, "dangling-rel-operator")
		targetProject := filepath.Join(fixture, "dangling-rel-project")
		for _, dir := range []string{danglingHome, targetProject} {
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
		}
		relTarget := filepath.Join("..", "dangling-rel-project", "mulgae-state")
		if err := os.Symlink(relTarget, filepath.Join(danglingHome, ".mulgae")); err != nil {
			t.Fatal(err)
		}
		danglingCfg := appconfig.Config{NativeUser: appconfig.NativeUserConfig{Home: danglingHome}}
		projectRoot, err := ports.NewAnchoredRoot(targetProject)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := liveSourceBoundaries(danglingCfg, projectRoot); err == nil {
			t.Fatalf("liveSourceBoundaries accepted project %q containing dangling relative ~/.mulgae target", targetProject)
		}
	})

	// Symlink loops at ~/.mulgae or ~/.mulgae/home must fail closed.
	t.Run("reject/symlink loop at mulgae state and reviewer home", func(t *testing.T) {
		validProject := filepath.Join(fixture, "loop-unrelated-project")
		if err := os.MkdirAll(validProject, 0o700); err != nil {
			t.Fatal(err)
		}
		projectRoot, err := ports.NewAnchoredRoot(validProject)
		if err != nil {
			t.Fatal(err)
		}

		loopMulgaeHome := filepath.Join(fixture, "loop-mulgae-operator")
		if err := os.MkdirAll(loopMulgaeHome, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(loopMulgaeHome, ".mulgae"), filepath.Join(loopMulgaeHome, ".mulgae")); err != nil {
			t.Fatal(err)
		}
		if _, _, err := liveSourceBoundaries(appconfig.Config{NativeUser: appconfig.NativeUserConfig{Home: loopMulgaeHome}}, projectRoot); err == nil {
			t.Fatal("liveSourceBoundaries accepted symlink loop at ~/.mulgae")
		}

		loopReviewerHome := filepath.Join(fixture, "loop-reviewer-operator")
		if err := os.MkdirAll(filepath.Join(loopReviewerHome, ".mulgae"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("loop-b", filepath.Join(loopReviewerHome, ".mulgae", "home")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("home", filepath.Join(loopReviewerHome, ".mulgae", "loop-b")); err != nil {
			t.Fatal(err)
		}
		if _, _, err := liveSourceBoundaries(appconfig.Config{NativeUser: appconfig.NativeUserConfig{Home: loopReviewerHome}}, projectRoot); err == nil {
			t.Fatal("liveSourceBoundaries accepted symlink loop at ~/.mulgae/home")
		}
	})

	// APFS Data-volume firmlink ancestors (/System/Volumes/Data, /System/Volumes, /System)
	// must be rejected when nativeHome resides on a firmlinked macOS Data-volume path.
	t.Run("reject/apfs data-volume firmlink ancestors", func(t *testing.T) {
		homeInfo, err := os.Stat(home)
		if err != nil {
			t.Fatal(err)
		}
		dataAliasInfo, err := os.Stat(filepath.Join(macOSDataVolumePrefix, home))
		if err != nil || !os.SameFile(homeInfo, dataAliasInfo) {
			t.Skip("nativeHome is not on a firmlinked /System/Volumes/Data path")
		}
		for _, ancestor := range []string{"/System/Volumes/Data", "/System/Volumes", "/System"} {
			root, err := ports.NewAnchoredRoot(ancestor)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := liveSourceBoundaries(cfg, root); err == nil {
				t.Fatalf("liveSourceBoundaries accepted firmlink ancestor %q of %q", ancestor, reviewerHome)
			}
		}
		// Valid child repository under nativeHome remains allowed.
		validRepo, err := ports.NewAnchoredRoot(filepath.Join(home, "projects", "repo"))
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := liveSourceBoundaries(cfg, validRepo); err != nil {
			t.Fatalf("liveSourceBoundaries rejected valid child repo %q under firmlinked home: %v", validRepo, err)
		}

		// Even when ~/.mulgae/home is an existing relative symlink pointing to a
		// non-Data-volume target (e.g. /usr/bin), the symlink itself resides on
		// the firmlinked Data volume so /System/Volumes/Data, /System/Volumes,
		// and /System must still be rejected via the downward Lstat walk.
		symHome := filepath.Join(fixture, "firmlink-symlink-operator")
		symMulgae := filepath.Join(symHome, ".mulgae")
		if err := os.MkdirAll(symMulgae, 0o700); err != nil {
			t.Fatal(err)
		}
		relUsrBin, err := filepath.Rel(symMulgae, "/usr/bin")
		if err != nil {
			t.Fatal(err)
		}
		symReviewerHome := filepath.Join(symMulgae, "home")
		if err := os.Symlink(relUsrBin, symReviewerHome); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(symReviewerHome); err != nil {
			t.Fatalf("expected symlinked reviewer home %q -> %q to resolve: %v", symReviewerHome, relUsrBin, err)
		}
		symCfg := appconfig.Config{NativeUser: appconfig.NativeUserConfig{Home: symHome}}
		for _, ancestor := range []string{"/System/Volumes/Data", "/System/Volumes", "/System"} {
			root, err := ports.NewAnchoredRoot(ancestor)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := liveSourceBoundaries(symCfg, root); err == nil {
				t.Fatalf("liveSourceBoundaries accepted firmlink ancestor %q when ~/.mulgae/home is relative symlink -> %q", ancestor, relUsrBin)
			}
		}
	})

	// EACCES while inspecting ~/.mulgae/home must fail closed.
	t.Run("reject/eacces on mulgae state directory", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root bypasses 0000 directory permissions")
		}
		lockedHome := filepath.Join(fixture, "locked-operator")
		lockedMulgae := filepath.Join(lockedHome, ".mulgae")
		if err := os.MkdirAll(lockedMulgae, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(lockedMulgae, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(lockedMulgae, 0o700) })

		validRepo, err := ports.NewAnchoredRoot(filepath.Join(home, "projects", "repo"))
		if err != nil {
			t.Fatal(err)
		}
		lockedCfg := appconfig.Config{NativeUser: appconfig.NativeUserConfig{Home: lockedHome}}
		if _, _, _, err := deepestExistingNoFollowPrefix(filepath.Join(lockedMulgae, "home")); err == nil {
			t.Fatal("deepestExistingNoFollowPrefix accepted unreadable 0000 ~/.mulgae directory instead of failing closed")
		}
		if _, _, err := liveSourceBoundaries(lockedCfg, validRepo); err == nil {
			t.Fatal("liveSourceBoundaries accepted unreadable 0000 ~/.mulgae directory instead of failing closed")
		}
	})

	// Initial path component count above maxLiveSourcePathComponents must fail closed.
	t.Run("reject/path exceeding initial component bound", func(t *testing.T) {
		overlong := "/" + strings.Repeat("a/", maxLiveSourcePathComponents+1) + "leaf"
		if _, err := resolvePathComponentsMissingTolerant(overlong); err == nil {
			t.Fatal("resolvePathComponentsMissingTolerant accepted path exceeding component bound")
		}
		if _, _, _, err := deepestExistingNoFollowPrefix(overlong); err == nil {
			t.Fatal("deepestExistingNoFollowPrefix accepted path exceeding component bound")
		}
		overlongRoot, err := ports.NewAnchoredRoot(overlong)
		if err != nil {
			t.Fatal(err)
		}
		if err := rejectProjectAncestorOfReviewerHome(overlongRoot, home); err == nil {
			t.Fatal("rejectProjectAncestorOfReviewerHome accepted project path exceeding component bound")
		}
	})

	// Regular file occupying an ancestor (~/.mulgae) produces ENOTDIR and must be
	// tolerated for unrelated valid repos while still rejecting the enclosing home.
	t.Run("allow/enotdir when regular file occupies mulgae state path", func(t *testing.T) {
		fileHome := filepath.Join(fixture, "enotdir-operator")
		if err := os.MkdirAll(fileHome, 0o700); err != nil {
			t.Fatal(err)
		}
		regMulgae := filepath.Join(fileHome, ".mulgae")
		if err := os.WriteFile(regMulgae, []byte("not-a-dir"), 0o600); err != nil {
			t.Fatal(err)
		}
		childPath := filepath.Join(regMulgae, "home", "nested")
		resolved, err := resolvePathComponentsMissingTolerant(childPath)
		if err != nil {
			t.Fatalf("resolvePathComponentsMissingTolerant(%q) error = %v, want ENOTDIR tolerance", childPath, err)
		}
		if resolved != childPath {
			t.Fatalf("resolvePathComponentsMissingTolerant(%q) = %q, want %q", childPath, resolved, childPath)
		}
		prefix, info, ok, err := deepestExistingNoFollowPrefix(childPath)
		if err != nil || !ok || info == nil || prefix != regMulgae {
			t.Fatalf("deepestExistingNoFollowPrefix(%q) = (%q, %v, %t, %v), want (%q, non-nil, true, nil)", childPath, prefix, info != nil, ok, err, regMulgae)
		}
		validRepo, err := ports.NewAnchoredRoot(filepath.Join(home, "projects", "repo"))
		if err != nil {
			t.Fatal(err)
		}
		fileCfg := appconfig.Config{NativeUser: appconfig.NativeUserConfig{Home: fileHome}}
		if _, _, err := liveSourceBoundaries(fileCfg, validRepo); err != nil {
			t.Fatalf("liveSourceBoundaries rejected valid repo under ENOTDIR ~/.mulgae: %v", err)
		}
		enclosingHome, err := ports.NewAnchoredRoot(fileHome)
		if err != nil {
			t.Fatal(err)
		}
		if err := rejectProjectAncestorOfReviewerHome(enclosingHome, fileHome); err == nil {
			t.Fatal("rejectProjectAncestorOfReviewerHome accepted enclosing home when ~/.mulgae is a regular file")
		}
	})

	// Ordinary repositories under native home or sibling prefix directories stay allowed.
	for _, test := range []struct {
		name    string
		project string
	}{
		{name: "repository under native home", project: filepath.Join(home, "projects", "repo")},
		{name: "sibling dot-mulgae-other prefix", project: filepath.Join(home, ".mulgae-other")},
	} {
		t.Run("allow/"+test.name, func(t *testing.T) {
			root, err := ports.NewAnchoredRoot(test.project)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := liveSourceBoundaries(cfg, root); err != nil {
				t.Fatalf("liveSourceBoundaries rejected valid project %q: %v", test.project, err)
			}
		})
	}
}

func TestProductionLiveControlPlanePathsIncludesDefaultsAndInheritedSockets(t *testing.T) {
	home := canonicalTestTempDir(t)
	privateSubdir := filepath.Join(home, "custom-herdr")
	if err := os.MkdirAll(privateSubdir, 0o700); err != nil {
		t.Fatal(err)
	}
	customSocket := filepath.Join(privateSubdir, "server.sock")
	tmpSocket := "/private/tmp/mulgae-inherited-test.sock"
	t.Setenv("HC_SOCKET", customSocket)
	t.Setenv("HC_TERMINAL_SOCKET", tmpSocket)

	roots, literals, err := productionLiveControlPlanePaths(home)
	if err != nil {
		t.Fatalf("productionLiveControlPlanePaths() error = %v", err)
	}
	rootSet := make(map[string]bool, len(roots))
	for _, root := range roots {
		rootSet[root.String()] = true
	}
	literalSet := make(map[string]bool, len(literals))
	for _, literal := range literals {
		literalSet[literal.String()] = true
	}
	for _, expectedRoot := range []string{
		filepath.Join(home, ".local", "state", "herdr-core"),
		filepath.Join(home, ".config", "herdr-core"),
		privateSubdir,
	} {
		if !rootSet[expectedRoot] {
			t.Fatalf("missing expected control-plane root %q in %v", expectedRoot, roots)
		}
	}
	if rootSet["/private/tmp"] || rootSet["/tmp"] {
		t.Fatalf("shared /private/tmp must never be emitted as a subpath control-plane root: %v", roots)
	}
	if !literalSet[tmpSocket] {
		t.Fatalf("missing inherited /private/tmp HC_TERMINAL_SOCKET %q in literals: %v", tmpSocket, literals)
	}
}

func TestProductionLiveControlPlanePathsFailsClosedAndExpandsMissingLeafSymlinks(t *testing.T) {
	home := canonicalTestTempDir(t)

	for _, envName := range []string{"HC_SOCKET", "HC_TERMINAL_SOCKET"} {
		for _, tc := range []struct {
			name string
			val  string
		}{
			{"leading_space", " /private/tmp/mgh-live/s.sock"},
			{"trailing_space", "/private/tmp/mgh-live/s.sock "},
			{"relative", "relative/s.sock"},
			{"unclean", "/private/tmp/a/../b/s.sock"},
			{"non_printable", "/private/tmp/bad\tpath/s.sock"},
		} {
			t.Run(envName+"/"+tc.name, func(t *testing.T) {
				t.Setenv("HC_SOCKET", "")
				t.Setenv("HC_TERMINAL_SOCKET", "")
				t.Setenv(envName, tc.val)
				if _, _, err := productionLiveControlPlanePaths(home); err == nil {
					t.Fatalf("productionLiveControlPlanePaths accepted malformed %s=%q", envName, tc.val)
				}
			})
		}
	}

	t.Run("missing-leaf /tmp socket emits both raw and /private/tmp canonical roots and literals", func(t *testing.T) {
		t.Setenv("HC_SOCKET", "/tmp/mulgae-missing-live-cp/core.sock")
		t.Setenv("HC_TERMINAL_SOCKET", "")
		roots, literals, err := productionLiveControlPlanePaths(home)
		if err != nil {
			t.Fatalf("productionLiveControlPlanePaths error = %v", err)
		}
		rootSet := make(map[string]bool, len(roots))
		for _, r := range roots {
			rootSet[r.String()] = true
		}
		literalSet := make(map[string]bool, len(literals))
		for _, l := range literals {
			literalSet[l.String()] = true
		}
		for _, wantRoot := range []string{"/tmp/mulgae-missing-live-cp", "/private/tmp/mulgae-missing-live-cp"} {
			if !rootSet[wantRoot] {
				t.Fatalf("missing expected root %q in %v", wantRoot, roots)
			}
		}
		for _, wantLit := range []string{"/tmp/mulgae-missing-live-cp/core.sock", "/private/tmp/mulgae-missing-live-cp/core.sock"} {
			if !literalSet[wantLit] {
				t.Fatalf("missing expected literal %q in %v", wantLit, literals)
			}
		}
	})

	t.Run("symlinked ~/.config and ~/.local/state expand missing-tolerantly for default control-plane roots", func(t *testing.T) {
		t.Setenv("HC_SOCKET", "")
		t.Setenv("HC_TERMINAL_SOCKET", "")
		base := canonicalTestTempDir(t)
		dotfilesConfig := filepath.Join(base, "dotfiles", "config")
		dotfilesState := filepath.Join(base, "dotfiles", "state")
		symHome := filepath.Join(base, "home")
		for _, dir := range []string{dotfilesConfig, dotfilesState, filepath.Join(symHome, ".local")} {
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.Symlink(dotfilesConfig, filepath.Join(symHome, ".config")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(dotfilesState, filepath.Join(symHome, ".local", "state")); err != nil {
			t.Fatal(err)
		}
		roots, _, err := productionLiveControlPlanePaths(symHome)
		if err != nil {
			t.Fatalf("productionLiveControlPlanePaths(symlinked dotfiles) error = %v", err)
		}
		rootSet := make(map[string]bool, len(roots))
		for _, r := range roots {
			rootSet[r.String()] = true
		}
		for _, want := range []string{
			filepath.Join(symHome, ".config", "herdr-core"),
			filepath.Join(dotfilesConfig, "herdr-core"),
			filepath.Join(symHome, ".local", "state", "herdr-core"),
			filepath.Join(dotfilesState, "herdr-core"),
		} {
			if !rootSet[want] {
				t.Fatalf("missing expected default control-plane root %q in %v", want, roots)
			}
		}
	})

	t.Run("symlinked ~/.config/herdr-core -> / fails closed via validLivePolicyRoot", func(t *testing.T) {
		t.Setenv("HC_SOCKET", "")
		t.Setenv("HC_TERMINAL_SOCKET", "")
		base := canonicalTestTempDir(t)
		badHome := filepath.Join(base, "bad-home")
		if err := os.MkdirAll(filepath.Join(badHome, ".config"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("/", filepath.Join(badHome, ".config", "herdr-core")); err != nil {
			t.Fatal(err)
		}
		if _, _, err := productionLiveControlPlanePaths(badHome); err == nil {
			t.Fatal("productionLiveControlPlanePaths accepted ~/.config/herdr-core -> /")
		}
	})
}
