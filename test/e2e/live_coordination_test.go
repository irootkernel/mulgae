//go:build darwin && arm64 && live_e2e

package e2e

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/adapters/haepari"
)

func prepareLiveReviewCoordination(t *testing.T) {
	t.Helper()
	if os.Getenv("HAEPARI_HOME") != "" {
		return
	}
	if _, borrowed := os.LookupEnv("HAEPARI_LOCK_GRANT"); borrowed || os.Getenv("HAEPARI_PARENT_CONTEXT") != "" {
		t.Fatal("live E2E requires the selected HAEPARI_HOME when inheriting Haepari context")
	}
	binary, err := exec.LookPath("haepari")
	if err != nil {
		t.Fatal("live E2E requires haepari on PATH or an explicitly selected usable HAEPARI_HOME")
	}
	home, err := os.MkdirTemp("/tmp", "mulgae-live-haepari.")
	if err != nil {
		t.Fatal(err)
	}
	home, err = filepath.EvalSymlinks(home)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := os.Stat(home)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		current, err := os.Stat(home)
		if err != nil || !os.SameFile(current, identity) {
			t.Error("live controller root changed; cleanup refused")
			return
		}
		if err := os.RemoveAll(home); err != nil {
			t.Error(err)
		}
	})
	t.Setenv("HAEPARI_HOME", home)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	vmStartController(t, ctx, binary, home, os.Environ())
	resource := filepath.Join(home, "review-resource.json")
	if err := os.WriteFile(resource, []byte(`{"schema":"haepari.resource/v1","id":"mulgae-review","kind":"lock","capacity":1}`), 0600); err != nil {
		t.Fatal(err)
	}
	registerCtx, registerCancel := context.WithTimeout(ctx, 10*time.Second)
	defer registerCancel()
	command := exec.CommandContext(registerCtx, binary, "resource", "register", "--file", resource, "--json")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("prepare isolated live review resource: %v: %s", err, output)
	}
	t.Log("[test-e2e] prepared isolated native Haepari review controller")
}

func TestLiveReviewCoordinationPreparesAndCleansController(t *testing.T) {
	t.Setenv("HAEPARI_HOME", "")
	t.Setenv("HAEPARI_PARENT_CONTEXT", "")
	t.Setenv("MULGAE_E2E_PROJECT_ROOT", "")
	// An absent grant, rather than a present empty grant, selects owned execution.
	grant, hadGrant := os.LookupEnv("HAEPARI_LOCK_GRANT")
	if err := os.Unsetenv("HAEPARI_LOCK_GRANT"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if hadGrant {
			if err := os.Setenv("HAEPARI_LOCK_GRANT", grant); err != nil {
				t.Error(err)
			}
		}
	})
	var home string
	t.Run("standalone", func(t *testing.T) {
		initializeLiveE2ERepository(t)
		home = os.Getenv("HAEPARI_HOME")
		if home == "" {
			t.Fatal("live E2E did not prepare its Haepari controller")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		client := haepari.NewClient(haepari.Config{RawHome: home})
		if _, err := client.Hello(ctx); err != nil {
			t.Fatal(err)
		}
		resource, err := client.InspectResource(ctx, "mulgae-review")
		if err != nil || resource.Capacity != 1 {
			t.Fatalf("live review resource is not ready: %#v, %v", resource, err)
		}
		t.Run("selected installation", func(t *testing.T) {
			initializeLiveE2ERepository(t)
			if os.Getenv("HAEPARI_HOME") != home {
				t.Fatal("live E2E replaced the selected Installation")
			}
		})
		if _, err := os.Stat(filepath.Join(home, "control.sock")); err != nil {
			t.Fatalf("nested fixture stopped the selected controller: %v", err)
		}
	})
	if home != "" {
		if _, err := os.Stat(home); !os.IsNotExist(err) {
			t.Fatalf("live controller root survived fixture cleanup: %v", err)
		}
	}
}
