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
	if len(credentials) != 4 {
		t.Fatalf("all default and configured homes must remain denied: %v", credentials)
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
