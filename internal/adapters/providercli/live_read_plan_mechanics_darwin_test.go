//go:build darwin && arm64

package providercli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
	"golang.org/x/sys/unix"
)

// Keep the production reader underneath the trace: path denials and namespace
// changes must come from its descriptor checks, not a replacement admission rule.
type task064AdmissionTrace struct {
	ports.LiveSourceReader
	paths         []string
	revalidations int
	admitError    error
	emptyList     bool
	duplicateList bool
}

func (source *task064AdmissionTrace) List(ctx context.Context, side domain.LiveSourceSide) ([]ports.SafeRelativePath, error) {
	paths, err := source.LiveSourceReader.List(ctx, side)
	if err != nil || source.emptyList {
		return nil, err
	}
	if source.duplicateList {
		return append(paths, paths...), nil
	}
	return paths, nil
}

func (source *task064AdmissionTrace) AdmitPath(ctx context.Context, side domain.LiveSourceSide, path ports.SafeRelativePath) error {
	source.paths = append(source.paths, string(side)+":"+path.String())
	if source.admitError != nil {
		return source.admitError
	}
	return source.LiveSourceReader.AdmitPath(ctx, side, path)
}

func (source *task064AdmissionTrace) RevalidateExecution(ctx context.Context) (ports.ProjectBindingObservation, error) {
	source.revalidations++
	return source.LiveSourceReader.RevalidateExecution(ctx)
}

func task064TraceExecution(t *testing.T, original ports.LiveReviewExecution) (*task064AdmissionTrace, ports.LiveReviewExecution) {
	t.Helper()
	source := &task064AdmissionTrace{LiveSourceReader: original.SourceReader()}
	execution, err := ports.NewLiveReviewExecution(context.Background(), source, original.ReviewerHome(), original.CredentialRoots())
	if err != nil {
		t.Fatal(err)
	}
	source.revalidations = 0
	return source, execution
}

func TestLiveReadPlanMechanics(t *testing.T) {
	ctx := context.Background()
	t.Run("missing authority stays rejected", func(t *testing.T) {
		if _, err := newAgyLiveReadAuthority(ctx, ports.LiveReviewExecution{}); err == nil {
			t.Fatal("AGY constructed missing execution authority")
		}
		var agy *agyLiveReadAuthority
		if err := agy.allow(ctx, "view_file", "/source/a"); err == nil || err.Error() != "missing live read authority" {
			t.Fatalf("missing-authority boundary: %v, want %q", err, "missing live read authority")
		}
	})
	t.Run("empty and duplicate read enumerations", func(t *testing.T) {
		for _, empty := range []bool{false, true} {
			counted, original, _ := countingLiveFixture(t, domain.LiveSourceStage)
			source := &task064AdmissionTrace{LiveSourceReader: counted, emptyList: empty, duplicateList: true}
			execution, err := ports.NewLiveReviewExecution(ctx, source, original.ReviewerHome(), original.CredentialRoots())
			if err != nil {
				t.Fatal(err)
			}
			if empty && len(execution.Reads()) != 0 || !empty && len(execution.Reads()) != 2*len(original.Reads()) {
				t.Fatal("enumeration fixture did not reach its intended read-plan class")
			}
			agy, err := newAgyLiveReadAuthority(ctx, execution)
			if err != nil {
				t.Fatal(err)
			}
			want := make(map[string]bool)
			if !empty {
				for _, read := range original.Reads() {
					want[read.GitCommand()] = true
				}
			}
			if len(agy.gitCommands) != len(want) || counted.reads != 0 || counted.admits != 0 {
				t.Fatalf("empty=%t duplicate plan changed command sets or read source bodies", empty)
			}
		}
	})
	t.Run("constructor command sets and family normalization", func(t *testing.T) {
		for _, scope := range []domain.LiveSourceScope{domain.LiveSourceWorkspace, domain.LiveSourceStage, domain.LiveSourceHead} {
			t.Run(string(scope), func(t *testing.T) {
				counted, original, project := countingLiveFixture(t, scope)
				trace, execution := task064TraceExecution(t, original)
				agy, err := newAgyLiveReadAuthority(ctx, execution)
				if err != nil || trace.revalidations != 1 {
					t.Fatalf("constructors: revalidations=%d error=%v", trace.revalidations, err)
				}
				raw, guarded := map[string]bool{}, map[string]bool{}
				for _, read := range execution.Reads() {
					if command := read.GitCommand(); command != "" {
						raw[command] = true
						// The family guard is an independent byte contract.
						guarded["MULGAE_READ_GUARD[1]=1 "+command] = true
					}
				}
				if !reflect.DeepEqual(agy.gitCommands, guarded) {
					t.Fatalf("command sets differ: AGY=%v want=%v", agy.gitCommands, guarded)
				}
				if (len(raw) == 0) != (scope == domain.LiveSourceWorkspace) || raw[""] || guarded[""] {
					t.Fatal("workspace/non-workspace command partition changed")
				}
				for command := range raw {
					for _, test := range []struct {
						name, command string
					}{
						{"exact", command}, {"outer whitespace", " \t" + command + "\n"},
						{"extra operand", command + " 'HEAD:other.txt'"}, {"compound", command + "; true"},
						{"changed spacing", strings.Replace(command, " show ", "  show ", 1)},
						{"changed quoting", strings.ReplaceAll(command, "'", "\"")}, {"empty", ""},
					} {
						trace.revalidations = 0
						wantAgy := test.name == "exact"
						if err := agy.allow(ctx, "run_command", "MULGAE_READ_GUARD[1]=1 "+test.command); (err == nil) != wantAgy {
							t.Fatalf("AGY %s: %v", test.name, err)
						}
					}
					if err := agy.allow(ctx, "run_command", command); err == nil {
						t.Fatal("AGY unguarded command gained authority")
					}
				}
				if scope != domain.LiveSourceWorkspace {
					file := filepath.Join(project, "target.txt")
					if agy.allow(ctx, "view_file", file) == nil {
						t.Fatal("non-workspace scope admitted a worktree substitute")
					}
				}
				plan, err := agyLiveReadPlan(ctx, execution, false)
				if err != nil {
					t.Fatal(err)
				}
				if scope == domain.LiveSourceWorkspace {
					if len(plan.commands) != 0 || len(plan.files) != len(execution.Reads()) {
						t.Fatal("AGY workspace grants differ from the read plan")
					}
					for i, read := range execution.Reads() {
						if plan.files[i] != filepath.Join(project, read.Path().String()) {
							t.Fatal("AGY workspace operand changed")
						}
					}
				} else if len(plan.files) != 0 || len(plan.commands) != len(execution.Reads()) {
					t.Fatal("AGY Git grants differ from the read plan")
				}
				extraction, err := agyLiveReadPlan(ctx, execution, true)
				if err != nil || len(extraction.files) != 0 || len(extraction.commands) != 0 {
					t.Fatalf("extraction gained native grants: %+v, %v", extraction, err)
				}
				if counted.reads != 0 || counted.admits != 0 || len(trace.paths) != 0 {
					t.Fatalf("plan/command translation read=%d admit=%d trace=%v", counted.reads, counted.admits, trace.paths)
				}
			})
		}
	})

	t.Run("body-free path classes and original errors", func(t *testing.T) {
		counted, original, project := countingLiveFixture(t, domain.LiveSourceWorkspace)
		trace, execution := task064TraceExecution(t, original)
		agy, err := newAgyLiveReadAuthority(ctx, execution)
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"quoted '물개'.txt", "mislabeled.png"} {
			if err := os.WriteFile(filepath.Join(project, name), []byte("ordinary text\n"), 0600); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.Mkdir(filepath.Join(project, ".mulgae"), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(project, ".mulgae", "state"), []byte("private"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(filepath.Join(project, "folder"), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("target.txt", filepath.Join(project, "link")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("folder", filepath.Join(project, "alias")); err != nil {
			t.Fatal(err)
		}
		if err := unix.Mkfifo(filepath.Join(project, "pipe"), 0600); err != nil {
			t.Fatal(err)
		}
		families := []struct {
			name  string
			allow func(context.Context, string) error
		}{
			{"agy", func(ctx context.Context, path string) error { return agy.allow(ctx, "view_file", path) }},
		}
		for _, family := range families {
			t.Run(family.name, func(t *testing.T) {
				for _, test := range []struct {
					name, path string
					admit      bool
					readerCall int
					code       ports.LiveSourceErrorCode
				}{
					{"regular", filepath.Join(project, "target.txt"), true, 1, ""},
					{"quoted Unicode", filepath.Join(project, "quoted '물개'.txt"), true, 1, ""},
					{"mislabeled raster", filepath.Join(project, "mislabeled.png"), true, 1, ""},
					{"empty", "", false, 0, ""}, {"relative", "target.txt", false, 0, ""},
					{"NUL", project + "/target\x00.txt", false, 0, ""}, {"noncanonical", project + "/./target.txt", false, 0, ""},
					{"root itself", project, false, 0, ""},
					{"outside credential", filepath.Join(filepath.Dir(project), "credentials", "auth.txt"), false, 0, ""},
					{"sibling prefix", project + "-sibling/target.txt", false, 0, ""},
					{"symlink", filepath.Join(project, "link"), false, 1, ports.LiveSourceUnsafe},
					{"symlinked ancestor", filepath.Join(project, "alias", "inner.txt"), false, 1, ports.LiveSourceUnsafe},
					{"directory", filepath.Join(project, "folder"), false, 1, ports.LiveSourceUnsafe},
					{"FIFO", filepath.Join(project, "pipe"), false, 1, ports.LiveSourceUnsafe},
					{"absent", filepath.Join(project, "absent"), false, 1, ports.LiveSourceUnavailable},
					{"runtime namespace", filepath.Join(project, ".mulgae", "state"), false, 1, ports.LiveSourceUnsafe},
					{"Git namespace", filepath.Join(project, ".git", "config"), false, 1, ports.LiveSourceUnsafe},
				} {
					t.Run(test.name, func(t *testing.T) {
						before := counted.admits
						err := family.allow(ctx, test.path)
						if (err == nil) != test.admit || counted.admits-before != test.readerCall || counted.reads != 0 {
							t.Fatalf("error=%v reads=%d admissions=%d; want admitted=%t admissions=%d", err, counted.reads, counted.admits-before, test.admit, test.readerCall)
						}
						var sourceError *ports.LiveSourceError
						if test.code != "" && (!errors.As(err, &sourceError) || sourceError.Code() != test.code) {
							t.Fatalf("lost source error %s: %v", test.code, err)
						}
					})
				}
				sentinel := ports.NewLiveSourceError(ports.LiveSourceUnavailable, errors.New("task064 admission sentinel"))
				trace.admitError = sentinel
				err := family.allow(ctx, filepath.Join(project, "target.txt"))
				trace.admitError = nil
				if err != sentinel || !errors.Is(err, sentinel) || counted.reads != 0 {
					t.Fatalf("original admission error changed: %v", err)
				}
			})
		}
		path, err := ports.NewSafeRelativePath("mislabeled.png")
		if err != nil {
			t.Fatal(err)
		}
		_, err = counted.Read(ctx, domain.LiveSourceWorktree, path)
		var sourceError *ports.LiveSourceError
		if !errors.As(err, &sourceError) || sourceError.Code() != ports.LiveSourceUnsupported || counted.reads != 1 {
			t.Fatalf("evidence read lost content validation: reads=%d error=%v", counted.reads, err)
		}
	})

	t.Run("authority lifetime between admission events", func(t *testing.T) {
		for _, family := range []string{"agy"} {
			for _, mutation := range []string{"regular replacement", "symlink replacement", "removed path", "closed source", "replaced project", "replaced neutral home", "cancelled"} {
				t.Run(family+"/"+mutation, func(t *testing.T) {
					counted, execution, project := countingLiveFixture(t, domain.LiveSourceWorkspace)
					agy, err := newAgyLiveReadAuthority(ctx, execution)
					if err != nil {
						t.Fatal(err)
					}
					allow := func(callContext context.Context, path string) error {
						return agy.allow(callContext, "view_file", path)
					}
					path := filepath.Join(project, "target.txt")
					if err := allow(ctx, path); err != nil || counted.admits != 1 || counted.reads != 0 {
						t.Fatalf("initial admission: %v", err)
					}
					callContext := ctx
					switch mutation {
					case "regular replacement":
						replacement := filepath.Join(project, "replacement.txt")
						if err := os.WriteFile(replacement, []byte("replacement"), 0600); err != nil {
							t.Fatal(err)
						}
						if err := os.Rename(replacement, path); err != nil {
							t.Fatal(err)
						}
					case "symlink replacement", "removed path":
						if err := os.Remove(path); err != nil {
							t.Fatal(err)
						}
						if mutation == "symlink replacement" {
							if err := os.Symlink(".git/config", path); err != nil {
								t.Fatal(err)
							}
						}
					case "closed source":
						if err := counted.Close(); err != nil {
							t.Fatal(err)
						}
					case "replaced project", "replaced neutral home":
						root := project
						if mutation == "replaced neutral home" {
							root = execution.ReviewerHome().Root().String()
						}
						if err := os.Rename(root, root+"-retained"); err != nil {
							t.Fatal(err)
						}
						if err := os.Mkdir(root, 0700); err != nil {
							t.Fatal(err)
						}
					case "cancelled":
						var cancel context.CancelFunc
						callContext, cancel = context.WithCancel(ctx)
						cancel()
					}
					err = allow(callContext, path)
					if (err == nil) != (mutation == "regular replacement") || counted.reads != 0 {
						t.Fatalf("second admission: error=%v body reads=%d", err, counted.reads)
					}
					if mutation == "cancelled" && !errors.Is(err, context.Canceled) {
						t.Fatalf("lost original cancellation: %v", err)
					}
				})
			}
		}
	})
}
