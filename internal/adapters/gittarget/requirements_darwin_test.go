//go:build darwin && arm64

package gittarget

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
	"golang.org/x/sys/unix"
)

func TestRequirementsLocalInputPreservesSelectedSourceSides(t *testing.T) {
	root := reviewCaptureRepository(t)
	writeReviewFile(t, filepath.Join(root, "tracked.txt"), "index\n")
	reviewGit(t, root, "add", "tracked.txt")
	writeReviewFile(t, filepath.Join(root, "tracked.txt"), "worktree\n")
	const input = `{"schema_version":"mulgae-requirements-input.v1","requirements":[{"id":"R","text":"Preserve selected source.","acceptance_criteria":["Use the selected side."],"owner_role":"logic"}]}` + "\n"
	writeReviewFile(t, filepath.Join(root, "requirements.json"), input)
	path, _ := ports.NewSafeRelativePath("requirements.json")
	for _, scope := range []domain.LiveSourceScope{domain.LiveSourceStage, domain.LiveSourceHead, domain.LiveSourceCommit, domain.LiveSourceDiff} {
		t.Run(string(scope), func(t *testing.T) {
			value := ""
			if scope == domain.LiveSourceCommit {
				value = "HEAD"
			} else if scope == domain.LiveSourceDiff {
				value = "HEAD~1..HEAD"
			}
			reader := openTestLiveSource(t, root, scope, value)
			before := reader.Target().Changes()
			local := reader.(ports.RequirementsInputReader)
			raw, err := local.ReadRequirementsInput(context.Background(), path)
			if err != nil || string(raw) != input {
				t.Fatalf("untracked invocation input: %q %v", raw, err)
			}
			if !reflect.DeepEqual(before, reader.Target().Changes()) {
				t.Fatal("local input expanded the selected target")
			}
			if _, err := reader.Read(context.Background(), domain.LiveSourceWorktree, path); err == nil {
				t.Fatal("local input granted a worktree evidence side")
			}
			if scope == domain.LiveSourceStage {
				readTestLiveSource(t, reader, domain.LiveSourceIndex, "tracked.txt", "index\n")
			} else {
				readTestLiveSource(t, reader, domain.LiveSourceAfter, "tracked.txt", "second\n")
			}
		})
	}
}

func TestRequirementsLocalInputKeepsBodyAndControlBoundsSeparate(t *testing.T) {
	root := reviewCaptureRepository(t)
	raw := []byte(`{"schema_version":"mulgae-requirements-input.v1","requirements":[{"id":"R","text":"` + strings.Repeat("prose ", 1500000) + `","acceptance_criteria":["Preserve behavior."],"owner_role":"logic"}]}`)
	if len(raw) <= 8<<20 {
		t.Fatal("fixture does not exceed the structured-envelope bound")
	}
	if err := os.WriteFile(filepath.Join(root, "requirements.json"), raw, 0644); err != nil {
		t.Fatal(err)
	}
	reader := openTestLiveSource(t, root, domain.LiveSourceStage, "")
	path, _ := ports.NewSafeRelativePath("requirements.json")
	got, err := reader.(ports.RequirementsInputReader).ReadRequirementsInput(context.Background(), path)
	if err != nil || !bytes.Equal(got, raw) {
		t.Fatalf("large requirements body rejected: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, ".gitignore"), raw, 0644); err != nil {
		t.Fatal(err)
	}
	path, _ = ports.NewSafeRelativePath(".gitignore")
	_, err = reader.(ports.RequirementsInputReader).ReadRequirementsInput(context.Background(), path)
	assertLiveError(t, err, ports.LiveSourceUnsafe)
}

func TestRequirementsLocalInputHonorsLinkedWorktreeCommonExcludes(t *testing.T) {
	main := reviewCaptureRepository(t)
	linked := filepath.Join(t.TempDir(), "linked")
	reviewGit(t, main, "worktree", "add", "--quiet", "-b", "requirements-worktree", linked, "HEAD")
	writeReviewFile(t, filepath.Join(main, ".git", "info", "exclude"), "requirements.json\n")
	writeReviewFile(t, filepath.Join(linked, "requirements.json"), `{"schema_version":"mulgae-requirements-input.v1","requirements":[]}`)
	reader := openTestLiveSource(t, linked, domain.LiveSourceStage, "")
	observation, err := reader.RevalidateExecution(context.Background())
	if err != nil || observation.GitDirectory == observation.CommonDirectory {
		t.Fatalf("fixture lacks distinct Git/common directories: %+v %v", observation, err)
	}
	path, _ := ports.NewSafeRelativePath("requirements.json")
	_, err = reader.(ports.RequirementsInputReader).ReadRequirementsInput(context.Background(), path)
	if err == nil {
		t.Fatal("linked-worktree input bypassed shared info/exclude")
	}
	assertLiveError(t, err, ports.LiveSourceUnsafe)
}

func TestRequirementsLocalInputMatchesAdmittedGitIgnoreCasePolicy(t *testing.T) {
	for _, test := range []struct {
		name, pattern, path string
		ignoreCase, ignored bool
	}{
		{"uppercase basename", "requirements.json\n", "REQUIREMENTS.JSON", true, true},
		{"uppercase parent", "blocked/\n", "BLOCKED/requirements.json", true, true},
		{"case-folded negation", "*.json\n!KEEP.JSON\n", "keep.json", true, false},
		{"case-sensitive policy", "requirements.json\n", "REQUIREMENTS.JSON", false, false},
		{"literal leading dash", "requirements.json\n", "-requirements.json", true, false},
		{"literal leading colon", "requirements.json\n", ":(glob)requirements.json", true, false},
		{"literal brackets", "literal1.json\n", "literal[1].json", true, false},
		{"literal wildcard", "literal\\*.json\n", "literal*.json", true, true},
		{"Unicode filename", "requirements.json\n", "café-🌊.json", true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := reviewCaptureRepository(t)
			setting := "false"
			if test.ignoreCase {
				setting = "true"
			}
			reviewGit(t, root, "config", "core.ignoreCase", setting)
			writeReviewFile(t, filepath.Join(root, ".gitignore"), test.pattern)
			if err := os.MkdirAll(filepath.Dir(filepath.Join(root, test.path)), 0755); err != nil {
				t.Fatal(err)
			}
			const raw = `{"schema_version":"mulgae-requirements-input.v1","requirements":[{"id":"R","text":"Preserve behavior.","acceptance_criteria":["Use selected code."],"owner_role":"logic"}]}`
			writeReviewFile(t, filepath.Join(root, test.path), raw)
			reader := openTestLiveSource(t, root, domain.LiveSourceStage, "")
			_, referenceErr := reader.(*liveSourceReader).run(context.Background(), "--no-literal-pathspecs", "check-ignore", "--quiet", "--no-index", "--", "./"+test.path)
			if referenceErr != nil {
				var exit *exec.ExitError
				if !errors.As(referenceErr, &exit) || exit.ExitCode() != 1 {
					var command *CommandError
					if errors.As(referenceErr, &command) {
						t.Fatalf("reference Git failed: %v: %s", referenceErr, command.Stderr())
					}
					t.Fatalf("reference Git failed: %v", referenceErr)
				}
			}
			if (referenceErr == nil) != test.ignored {
				t.Fatal("reference Git does not exhibit the expected configured ignore policy")
			}
			t.Logf("admitted Git ignore policy: core.ignoreCase=%t reference_ignored=%t", test.ignoreCase, referenceErr == nil)
			recorder := &requirementsQueryRecorder{Runner: reader.(*liveSourceReader).runner}
			reader.(*liveSourceReader).runner = recorder
			path, _ := ports.NewSafeRelativePath(test.path)
			got, err := reader.(ports.RequirementsInputReader).ReadRequirementsInput(context.Background(), path)
			if len(recorder.queries) == 0 {
				t.Fatal("local input did not consult admitted Git ignore policy")
			}
			for _, command := range recorder.queries {
				separator := -1
				excludesDisabled := false
				for index, arg := range command.Args {
					if arg == "--" {
						separator = index
					}
					excludesDisabled = excludesDisabled || arg == "core.excludesFile=/dev/null"
				}
				if !excludesDisabled || separator < 0 || len(command.Args) != separator+2 {
					t.Fatalf("ignore query changed overrides or widened operands: %v", command.Args)
				}
				operand := command.Args[separator+1]
				if operand != "./"+test.path && !(strings.HasSuffix(operand, "/") && strings.HasPrefix("./"+test.path, operand)) {
					t.Fatalf("ignore query escaped the selected path: %q", operand)
				}
			}
			if test.ignored {
				if err == nil {
					t.Fatal("local input admitted a path ignored by the actual Git policy")
				}
				assertLiveError(t, err, ports.LiveSourceUnsafe)
			} else if err != nil || string(got) != raw {
				t.Fatalf("local input rejected a path admitted by the actual Git policy: %v", err)
			}
		})
	}
}

type requirementsQueryRecorder struct {
	Runner
	queries []Command
}

func (recorder *requirementsQueryRecorder) Run(ctx context.Context, command Command) (Result, error) {
	for _, arg := range command.Args {
		if arg == "check-ignore" {
			recorder.queries = append(recorder.queries, command.Clone())
			break
		}
	}
	return recorder.Runner.Run(ctx, command)
}

func TestRequirementsLocalInputRejectsUnsafeFilesystemPaths(t *testing.T) {
	for _, name := range []string{"missing", "directory", "fifo", "symlink", "parent symlink", "ignored", "ignored parent", "metadata exclude", "protected", "decomposed Unicode", "invalid ignore"} {
		t.Run(name, func(t *testing.T) {
			root := reviewCaptureRepository(t)
			path := "requirements.json"
			var protected []ports.AnchoredRoot
			switch name {
			case "directory":
				if err := os.Mkdir(filepath.Join(root, path), 0755); err != nil {
					t.Fatal(err)
				}
			case "fifo":
				if err := unix.Mkfifo(filepath.Join(root, path), 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Symlink("tracked.txt", filepath.Join(root, path)); err != nil {
					t.Fatal(err)
				}
			case "parent symlink":
				if err := os.Symlink(root, filepath.Join(root, "alias")); err != nil {
					t.Fatal(err)
				}
				path = "alias/tracked.txt"
			case "ignored", "invalid ignore":
				pattern := "requirements.json\n"
				if name == "invalid ignore" {
					pattern = "bad\x00ignore"
				}
				writeReviewFile(t, filepath.Join(root, ".gitignore"), pattern)
				writeReviewFile(t, filepath.Join(root, path), "{}")
			case "ignored parent":
				if err := os.Mkdir(filepath.Join(root, "docs"), 0755); err != nil {
					t.Fatal(err)
				}
				writeReviewFile(t, filepath.Join(root, ".gitignore"), "docs/\n")
				writeReviewFile(t, filepath.Join(root, "docs", ".gitignore"), "!requirements.json\n")
				path = "docs/requirements.json"
				writeReviewFile(t, filepath.Join(root, path), "{}")
			case "metadata exclude":
				writeReviewFile(t, filepath.Join(root, ".git", "info", "exclude"), "requirements.json\n")
				writeReviewFile(t, filepath.Join(root, path), "{}")
			case "protected":
				if err := os.Mkdir(filepath.Join(root, "private"), 0755); err != nil {
					t.Fatal(err)
				}
				protected = []ports.AnchoredRoot{mustAnchoredRoot(t, filepath.Join(root, "private"))}
				path = "private/requirements.json"
				writeReviewFile(t, filepath.Join(root, path), "{}")
			case "decomposed Unicode":
				path = "cafe\u0301.json"
				writeReviewFile(t, filepath.Join(root, path), "{}")
			}
			adapter, err := NewLiveSourceAdapter(NewExecRunner(), protected)
			if err != nil {
				t.Fatal(err)
			}
			selector, _ := ports.NewLiveSourceSelector(domain.LiveSourceStage, "")
			reader, err := adapter.OpenLiveSource(context.Background(), mustAnchoredRoot(t, root), selector)
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			safe, err := ports.NewSafeRelativePath(path)
			if err != nil {
				t.Fatal(err)
			}
			_, err = reader.(ports.RequirementsInputReader).ReadRequirementsInput(context.Background(), safe)
			if err == nil {
				t.Fatal("unsafe invocation input accepted")
			}
			assertLiveError(t, err, ports.LiveSourceUnsafe)
		})
	}
}

func TestRequirementsLocalInputUsesProjectPermissionsAndIgnoreNegation(t *testing.T) {
	root := reviewCaptureRepository(t)
	if err := os.Chmod(root, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "docs"), 0755); err != nil {
		t.Fatal(err)
	}
	writeReviewFile(t, filepath.Join(root, ".gitignore"), "docs/*.json\n!docs/requirements.json\n")
	const raw = `{"schema_version":"mulgae-requirements-input.v1","requirements":[{"id":"R","text":"Preserve behavior.","acceptance_criteria":["Use selected code."],"owner_role":"logic"}]}`
	if err := os.WriteFile(filepath.Join(root, "docs", "requirements.json"), []byte(raw), 0644); err != nil {
		t.Fatal(err)
	}
	reader := openTestLiveSource(t, root, domain.LiveSourceStage, "")
	path, _ := ports.NewSafeRelativePath("docs/requirements.json")
	got, err := reader.(ports.RequirementsInputReader).ReadRequirementsInput(context.Background(), path)
	if err != nil || string(got) != raw {
		t.Fatalf("ordinary project input rejected: %v", err)
	}
	// A selected ignore file is already read as control metadata. Reuse those
	// exact bytes rather than opening its body a second time as invocation data.
	writeReviewFile(t, filepath.Join(root, ".gitignore"), raw)
	path, _ = ports.NewSafeRelativePath(".gitignore")
	got, err = reader.(ports.RequirementsInputReader).ReadRequirementsInput(context.Background(), path)
	if err != nil || string(got) != raw {
		t.Fatalf("selected control input rejected: %v", err)
	}
}
