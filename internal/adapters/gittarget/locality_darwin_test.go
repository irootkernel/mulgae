//go:build darwin && arm64

package gittarget

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	adapterconfig "github.com/irootkernel/kkachi-agent-review/internal/adapters/config"
	"github.com/irootkernel/kkachi-agent-review/internal/ports"
)

func TestUnifiedDiffPrivatePathGuard(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		parsed bool
		free   bool
	}{
		{"ordinary diff", "diff --git a/main.go b/main.go\n--- a/main.go\n+++ b/main.go\n@@ -1 +1 @@\n-old\n+new\n", true, true},
		{"ordinary raw unified diff", "--- a/main.go\n+++ b/main.go\n@@ -1 +1 @@\n-old\n+new\n", true, true},
		{"new file diff", "diff --git a/new.go b/new.go\nnew file mode 100644\n--- /dev/null\n+++ b/new.go\n@@ -0,0 +1 @@\n+new\n", true, true},
		{"deleted file diff", "diff --git a/old.go b/old.go\ndeleted file mode 100644\n--- a/old.go\n+++ /dev/null\n@@ -1 +0,0 @@\n-old\n", true, true},
		{"quoted ordinary path", "diff --git \"a/file with space.go\" \"b/file with space.go\"\n--- \"a/file with space.go\"\n+++ \"b/file with space.go\"\n@@ -1 +1 @@\n-old\n+new\n", true, true},
		{"quoted private path", "diff --git \"a/.kar/file with space\" \"b/.kar/file with space\"\n--- \"a/.kar/file with space\"\n+++ \"b/.kar/file with space\"\n@@ -1 +1 @@\n-old\n+new\n", true, false},
		{"raw private diff", "--- a/.kar/config.yaml\n+++ b/.kar/config.yaml\n@@ -1 +1 @@\n-old\n+new\n", true, false},
		{"config path", "diff --git a/.kar/config.yaml b/.kar/config.yaml\n--- a/.kar/config.yaml\n+++ b/.kar/config.yaml\n@@ -1 +1 @@\n-old\n+new\n", true, false},
		{"private descendant", "diff --git a/.kar/cache/x b/.kar/cache/x\n--- a/.kar/cache/x\n+++ b/.kar/cache/x\n@@ -1 +1 @@\n-old\n+new\n", true, false},
		{"rename only", "diff --git a/old.go b/new.go\nsimilarity index 100%\nrename from old.go\nrename to new.go\n", true, true},
		{"rename only into private namespace", "diff --git a/old.go b/.kar/cache/x\nsimilarity index 100%\nrename from old.go\nrename to .kar/cache/x\n", true, false},
		{"copy only into private namespace", "diff --git a/old.go b/.kar/cache/x\nsimilarity index 100%\ncopy from old.go\ncopy to .kar/cache/x\n", true, false},
		{"mode only", "diff --git a/main.go b/main.go\nold mode 100644\nnew mode 100755\n", true, true},
		{"mode only private", "diff --git a/.kar/config.yaml b/.kar/config.yaml\nold mode 100644\nnew mode 100755\n", true, false},
		{"no-op private mode is malformed", "diff --git a/.kar/config.yaml b/.kar/config.yaml\nold mode 100644\nnew mode 100644\n", false, true},
		{"empty new file", "diff --git a/empty b/empty\nnew file mode 100644\nindex 0000000..e69de29\n", true, true},
		{"prose mention", "do not edit .kar/config.yaml\n", false, true},
		{"incomplete diff", "diff --git a/.kar/config.yaml b/.kar/config.yaml", false, true},
		{"private header followed by malformed input", "diff --git a/.kar/config.yaml b/.kar/config.yaml\ngarbage\n", false, true},
		{"valid file followed by incomplete section", "diff --git a/main.go b/main.go\n--- a/main.go\n+++ b/main.go\n@@ -1 +1 @@\n-old\n+new\ndiff --git a/other.go b/other.go\n", false, true},
		{"incomplete private rename pair", "diff --git a/main.go b/.kar/main.go\nrename from main.go\n", false, true},
		{"mismatched git and unified headers", "diff --git a/main.go b/main.go\n--- a/other.go\n+++ b/main.go\n@@ -1 +1 @@\n-old\n+new\n", false, true},
		{"duplicate new header", "diff --git a/main.go b/main.go\n--- a/main.go\n+++ b/main.go\n+++ b/main.go\n@@ -1 +1 @@\n-old\n+new\n", false, true},
		{"no newline marker", "diff --git a/main.go b/main.go\n--- a/main.go\n+++ b/main.go\n@@ -1 +1 @@\n-old\n+new\n\\ No newline at end of file\n", true, true},
		{"malformed private mode", "diff --git a/.kar/config.yaml b/.kar/config.yaml\nnew file mode garbage\n--- /dev/null\n+++ b/.kar/config.yaml\n@@ -0,0 +1 @@\n+new\n", false, true},
		{"malformed index", "diff --git a/.kar/config.yaml b/.kar/config.yaml\nindex nope..bad\n--- a/.kar/config.yaml\n+++ b/.kar/config.yaml\n@@ -1 +1 @@\n-old\n+new\n", false, true},
		{"mixed hash lengths", "diff --git a/.kar/config.yaml b/.kar/config.yaml\nindex aaaa..bbbbbbbb\n--- a/.kar/config.yaml\n+++ b/.kar/config.yaml\n@@ -1 +1 @@\n-old\n+new\n", false, true},
		{"invalid git mode", "diff --git a/.kar/config.yaml b/.kar/config.yaml\nold mode 100600\nnew mode 100644\n", false, true},
		{"invalid similarity", "diff --git a/old.go b/.kar/new.go\nsimilarity index 101%\nrename from old.go\nrename to .kar/new.go\n", false, true},
		{"duplicate metadata", "diff --git a/.kar/config.yaml b/.kar/config.yaml\nindex aaaa..bbbb\nindex aaaa..bbbb\n--- a/.kar/config.yaml\n+++ b/.kar/config.yaml\n@@ -1 +1 @@\n-old\n+new\n", false, true},
		{"misplaced no newline marker", "diff --git a/.kar/config.yaml b/.kar/config.yaml\n--- a/.kar/config.yaml\n+++ b/.kar/config.yaml\n@@ -1 +1 @@\n\\ No newline at end of file\n-old\n+new\n", false, true},
		{"both sides null", "--- /dev/null\n+++ /dev/null\n@@ -0,0 +0,0 @@\n", false, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			parsed, free := parseUnifiedDiffPrivatePathFree([]byte(test.input))
			if parsed != test.parsed || free != test.free {
				t.Fatalf("guard = parsed %t free %t, want %t/%t", parsed, free, test.parsed, test.free)
			}
		})
	}
}

func TestUnifiedDiffPrivatePathReason(t *testing.T) {
	for _, test := range []struct {
		name, input string
		want        ports.ConfigLocalityReason
	}{
		{"exact config", "diff --git a/.kar/config.yaml b/.kar/config.yaml\n--- a/.kar/config.yaml\n+++ b/.kar/config.yaml\n@@ -1 +1 @@\n-old\n+new\n", ports.ConfigLocalityTargetPrivateConfigForbidden},
		{"private descendant", "diff --git a/old.go b/.kar/cache/x\nsimilarity index 100%\nrename from old.go\nrename to .kar/cache/x\n", ports.ConfigLocalityTargetPrivateNamespaceForbidden},
		{"config dominates mixed section", "diff --git a/.kar/cache/x b/.kar/cache/x\nold mode 100644\nnew mode 100755\ndiff --git a/.kar/config.yaml b/.kar/config.yaml\nold mode 100644\nnew mode 100755\n", ports.ConfigLocalityTargetPrivateConfigForbidden},
	} {
		t.Run(test.name, func(t *testing.T) {
			parsed, free := parseUnifiedDiffPrivatePathFree([]byte(test.input))
			if !parsed || free {
				t.Fatalf("parse = %t/%t", parsed, free)
			}
			if got := parsedUnifiedDiffPrivateReason([]byte(test.input)); got != test.want {
				t.Fatalf("reason = %q, want %q", got, test.want)
			}
		})
	}
}

func TestGitLocalityAttestorRejectsLiveConfigAndRepositoryDrift(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*testing.T, string)
	}{
		{
			name: "config bytes",
			mutate: func(t *testing.T, root string) {
				writeReviewFile(t, filepath.Join(root, ".kar", "config.yaml"), "version: 2\n")
			},
		},
		{
			name: "private directory identity",
			mutate: func(t *testing.T, root string) {
				if err := os.Rename(filepath.Join(root, ".kar"), filepath.Join(root, ".kar-old")); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(filepath.Join(root, ".kar"), 0o700); err != nil {
					t.Fatal(err)
				}
				writeReviewFile(t, filepath.Join(root, ".kar", "config.yaml"), "version: 1\n")
			},
		},
		{
			name: "checkout",
			mutate: func(t *testing.T, root string) {
				writeReviewFile(t, filepath.Join(root, "head-drift.txt"), "drift\n")
				reviewGit(t, root, "add", "head-drift.txt")
				reviewGit(t, root, "commit", "-m", "drift")
			},
		},
		{
			name: "index",
			mutate: func(t *testing.T, root string) {
				writeReviewFile(t, filepath.Join(root, "index-drift.txt"), "drift\n")
				reviewGit(t, root, "add", "index-drift.txt")
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			root, attestor, request, expected := localityFixture(t)
			test.mutate(t, root)
			if err := attestor.Revalidate(context.Background(), request, expected); err == nil {
				t.Fatal("locality drift was accepted")
			}
		})
	}
}

func TestGitLocalityAttestorRejectsPrivateIndexStagesAndApplicableCommit(t *testing.T) {
	t.Run("private index stage zero", func(t *testing.T) {
		root, attestor, request, _ := localityFixture(t)
		writeReviewFile(t, filepath.Join(root, ".kar", "indexed"), "private\n")
		reviewGit(t, root, "add", ".kar/indexed")
		_, err := attestor.Attest(context.Background(), request)
		requireLocalityReason(t, err, ports.ConfigLocalityTargetPrivateNamespaceForbidden)
	})

	t.Run("config index stage zero", func(t *testing.T) {
		root, attestor, request, _ := localityFixture(t)
		reviewGit(t, root, "add", "-f", ".kar/config.yaml")
		_, err := attestor.Attest(context.Background(), request)
		requireLocalityReason(t, err, ports.ConfigLocalityTargetPrivateConfigForbidden)
	})

	t.Run("config target diff", func(t *testing.T) {
		_, attestor, request, _ := localityFixture(t)
		target := []byte("diff --git a/.kar/config.yaml b/.kar/config.yaml\nold mode 100644\nnew mode 100755\n")
		request, err := ports.NewConfigLocalityRequest(request.Root(), request.Config(), nil, target)
		if err != nil {
			t.Fatal(err)
		}
		_, err = attestor.Attest(context.Background(), request)
		requireLocalityReason(t, err, ports.ConfigLocalityTargetPrivateConfigForbidden)
	})

	t.Run("unmerged stages", func(t *testing.T) {
		root, attestor, request, _ := localityFixture(t)
		blob := reviewGitOutput(t, root, "hash-object", "-w", "tracked.txt")
		command := exec.Command("/usr/bin/git", "update-index", "--index-info")
		command.Dir = root
		command.Stdin = strings.NewReader("100644 " + blob + " 1\t.kar/conflict.txt\n100644 " + blob + " 2\t.kar/conflict.txt\n100644 " + blob + " 3\t.kar/conflict.txt\n")
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("seed unmerged index: %v: %s", err, output)
		}
		if _, err := attestor.Attest(context.Background(), request); err == nil {
			t.Fatal("unmerged index stages were accepted")
		}
	})

	t.Run("applicable private commit", func(t *testing.T) {
		root, attestor, _, _ := localityFixture(t)
		base := reviewGitOutput(t, root, "rev-parse", "HEAD")
		writeReviewFile(t, filepath.Join(root, ".kar", "committed"), "private\n")
		reviewGit(t, root, "add", ".kar/committed")
		reviewGit(t, root, "commit", "-m", "private applicable commit")
		privateCommit := reviewGitOutput(t, root, "rev-parse", "HEAD")
		reviewGit(t, root, "checkout", "--detach", base)
		source, err := adapterconfig.NewLocalConfigSource(mustAnchoredRoot(t, root), false)
		if err != nil {
			t.Fatal(err)
		}
		proof, err := source.Observation().Proof()
		if err != nil {
			t.Fatal(err)
		}
		oid, err := ports.ParseGitObjectID(privateCommit)
		if err != nil {
			t.Fatal(err)
		}
		request, err := ports.NewConfigLocalityRequest(mustAnchoredRoot(t, root), proof, []ports.GitObjectID{oid}, nil)
		if err != nil {
			t.Fatal(err)
		}
		_, err = attestor.Attest(context.Background(), request)
		requireLocalityReason(t, err, ports.ConfigLocalityTargetPrivateNamespaceForbidden)
	})
}

func requireLocalityReason(t *testing.T, err error, want ports.ConfigLocalityReason) {
	t.Helper()
	got, ok := ports.ConfigLocalityReasonFromError(err)
	if !ok || got != want {
		t.Fatalf("locality error = %v, reason %q/%t, want %q", err, got, ok, want)
	}
}

func localityFixture(t *testing.T) (string, *GitLocalityAttestor, ports.ConfigLocalityRequest, ports.ConfigLocalityContext) {
	t.Helper()
	root := reviewCaptureRepository(t)
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, ".kar"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeReviewFile(t, filepath.Join(root, ".kar", "config.yaml"), "version: 1\n")
	anchored := mustAnchoredRoot(t, root)
	source, err := adapterconfig.NewLocalConfigSource(anchored, false)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := source.Observation().Proof()
	if err != nil {
		t.Fatal(err)
	}
	request, err := ports.NewConfigLocalityRequest(anchored, proof, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	attestor, err := NewGitLocalityAttestor(NewExecRunner())
	if err != nil {
		t.Fatal(err)
	}
	expected, err := attestor.Attest(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	return root, attestor, request, expected
}
