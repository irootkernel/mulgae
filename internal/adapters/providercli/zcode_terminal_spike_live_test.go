//go:build darwin && arm64 && live_zcode_herdr

package providercli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/adapters/filesystem"
	"github.com/irootkernel/mulgae/internal/adapters/herdr"
	"github.com/irootkernel/mulgae/internal/adapters/process"
	"github.com/irootkernel/mulgae/internal/adapters/runtime"
	"github.com/irootkernel/mulgae/internal/adapters/workspace"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
	"golang.org/x/sys/unix"
)

const spikeZCodePackageSHA256 = "e23505b5eac11bac202461fad2c1882e61347edfc21c9e658a499510bc794111"

const spikeZCodeModel = zcodeCodingPlanProvider + "/GLM-5.4"
const spikeZCodeTurnTimeout = 3 * time.Minute

var spikeZCodeSelected = regexp.MustCompile(`Selected: ([a-zA-Z0-9._:/-]+)(?: \(reasoning: ([a-z_]+)\))?`)

type zcodeSpike struct {
	profile                     zcodeTerminalProfile
	nativeHome, neutral, source ports.AnchoredRoot
	base                        string
	factory                     *NamespaceFactory
	session                     *herdr.Session
	cleanupUnverified           *bool
}

type zcodeSpikePane struct {
	*herdr.Session
	source             ports.AnchoredRoot
	nativeHome         ports.AnchoredRoot
	noPrompt           bool
	observation        ports.TerminalExecutionObservation
	authConsumed       bool
	catalogRevision    int
	started            bool
	duration           time.Duration
	endInterval        time.Duration
	working            bool
	selection          string
	effort             string
	kernelVerified     bool
	gitScope           bool
	tools              string
	endpointObserved   bool
	teardownUnverified bool
	coreStatus         string
	trackSelection     bool
}

func TestLiveZCodeHerdrSpike(t *testing.T) {
	ctx := t.Context()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	home, err = filepath.EvalSymlinks(home)
	if err != nil {
		t.Fatal(err)
	}
	var spike zcodeSpike
	spike.nativeHome = zcodeSpikeRoot(t, home)
	if !t.Run("01_package", func(t *testing.T) {
		pkg, err := herdr.ResolveZCodePackage(herdr.DefaultZCodeResolveOptions(home))
		if err != nil {
			t.Fatal(err)
		}
		if pkg.PackageSHA256 != spikeZCodePackageSHA256 {
			t.Fatalf("unexpected companion package aggregate: %s", pkg.PackageSHA256)
		}
		const bundle = "/Applications/ZCode.app"
		desktop, err := herdr.ObserveZCodeCompanion(ctx, pkg, bundle)
		if err != nil {
			t.Fatal(err)
		}
		if desktop.Version != "0.2.0" || desktop.AppVersion != "4.0.0" {
			t.Fatalf("unexpected companion/desktop versions: %s / %s", desktop.Version, desktop.AppVersion)
		}
		spike.profile = zcodeTerminalProfile{pkg: pkg, desktop: desktop, appBundle: bundle}
		t.Logf("verified %s with companion %s and Desktop %s", pkg.PackageSHA256, desktop.Version, desktop.AppVersion)
	}) {
		return
	}

	sessionBase := fmt.Sprintf("/private/tmp/mgh-%d", os.Geteuid())
	if entries, err := os.ReadDir(sessionBase); err == nil && len(entries) != 0 || err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal("isolated core base must be empty before the spike")
	}
	before := zcodeSpikeSnapshot(t, home)

	base, err := os.MkdirTemp("/private/tmp", "mz95.")
	if err != nil {
		t.Fatal(err)
	}
	spike.base = base
	var cleanupUnverified bool
	spike.cleanupUnverified = &cleanupUnverified
	t.Cleanup(func() {
		if cleanupUnverified {
			t.Errorf("preserving owned fixture pending teardown verification: %s", base)
			return
		}
		if err := os.RemoveAll(base); err != nil {
			t.Errorf("remove owned spike fixture: %v", err)
		}
		if _, err := os.Lstat(base); !errors.Is(err, os.ErrNotExist) {
			t.Error("owned spike fixture still present")
		}
	})
	for _, name := range []string{"cwd", "source"} {
		if err := os.Mkdir(filepath.Join(base, name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	spike.neutral, spike.source = zcodeSpikeRoot(t, filepath.Join(base, "cwd")), zcodeSpikeRoot(t, filepath.Join(base, "source"))
	if err := os.WriteFile(filepath.Join(spike.source.String(), "protected.txt"), []byte("read-only fixture\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	spike.factory, err = NewNamespaceFactory(filepath.Join(base, "ns"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = spike.factory.rootDirectory.Close() })
	spike.session, err = herdr.NewSession(herdr.SessionOptions{
		Clock: runtime.SystemClock{}, LaunchBuilder: process.NewPaneLaunchBuilder(),
		NativeHome: spike.nativeHome, DisableStaleReaper: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	closeCore := func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		return spike.session.Close(ctx)
	}
	t.Cleanup(func() {
		sessionDir := spike.session.SessionDir()
		if err := closeCore(); err != nil {
			cleanupUnverified = true
			t.Errorf("close isolated core: %v", err)
		}
		if entries, err := os.ReadDir(sessionBase); err != nil || len(entries) != 0 {
			t.Errorf("isolated core base is not empty after close")
		}
		if after := zcodeSpikeSnapshot(t, home); !slices.Equal(before, after) {
			t.Error("native state or operator/provider process baseline changed")
		}
		if err := assertZCodeSpikeOwnedProcessesAbsent(base, sessionDir); err != nil {
			t.Error(err)
		}
	})
	core, err := spike.session.RuntimeIdentity(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if core.Version() != "0.1.20" {
		t.Fatalf("unexpected isolated core version: %s", core.Version())
	}
	t.Logf("isolated core version=%s digest=%s generation=%d", core.Version(), core.ExecutableSHA256(), core.Generation())
	t.Run("02_host_and_consume", func(t *testing.T) {
		_, pane, err := spike.invoke(t, terminalPurposeReview, domain.LiveSourceWorkspace, spikeZCodeModel, "max", []byte("No prompt is sent in this readiness probe."), true)
		status, _ := pane.observation.ProgramStatus()
		if !zcodeSpikeExpectedReadiness(err) || !pane.authConsumed || !pane.kernelVerified || pane.catalogRevision < 48 || status != ports.TerminalProgramStatusIdle ||
			pane.observation.TurnCount() != 0 || !pane.observation.ProcessObservation().ProcessGroupAbsent() {
			t.Fatalf("no-input readiness failed: %s consumed=%t revision=%d", zcodeSpikeOutcome(pane, err), pane.authConsumed, pane.catalogRevision)
		}
		t.Logf("idle with zero turns, catalog revision=%d, zero-filled unlinked auth and four kernel denials", pane.catalogRevision)
	})
	var teardownBound time.Duration
	t.Run("03_explicit_model", func(t *testing.T) {
		res, pane, err := spike.selectionTurn(t, spikeZCodeModel, "max")
		teardownBound = pane.endInterval
		if pane.selection != spikeZCodeModel || pane.effort != "max" || pane.tools != "Read,Grep,Glob,Write" {
			t.Fatalf("explicit model and effort not verified: %s", zcodeSpikeOutcome(pane, err))
		}
		assessZCodeSpikeTurn(t, res, pane, err)
	})
	var defaultSelection zcodeSpikeSelection
	t.Run("04_omitted_model_effort", func(t *testing.T) {
		res, pane, err := spike.selectionTurn(t, "", "")
		assessZCodeSpikeTurn(t, res, pane, err)
		defaultSelection = zcodeSpikeSelection{pane.selection, pane.effort}
		if slices.Contains(res.EffectiveArgv, "--model") || slices.Contains(res.EffectiveArgv, "--reasoning-effort") || !defaultSelection.complete() {
			t.Fatal("native default model was not selected with both flags omitted")
		}
	})
	t.Run("05_effort_only", func(t *testing.T) {
		res, pane, err := spike.selectionTurn(t, "", "low")
		assessZCodeSpikeTurn(t, res, pane, err)
		if slices.Contains(res.EffectiveArgv, "--model") || fixtureFlagValue(res.EffectiveArgv, "--reasoning-effort") != "low" ||
			!defaultSelection.matchesEffort(zcodeSpikeSelection{pane.selection, pane.effort}, "low") {
			t.Fatal("effort-only invocation did not retain the observed default model")
		}
	})
	t.Run("06_invalid_model", func(t *testing.T) {
		res, pane, err := spike.selectionTurn(t, zcodeCodingPlanProvider+"/GLM-NONEXISTENT", "max")
		var failure *terminalDriverFailure
		if !errors.As(err, &failure) || failure.Diagnostic() != "zcode_model_selection" || pane.observation.TurnCount() != 0 ||
			!res.Process.ProcessGroupAbsent() || len(res.OutputBytes) != 0 || res.StagedReceipt.Valid() {
			t.Fatalf("unknown model did not fail closed: %s", zcodeSpikeOutcome(pane, err))
		}
		t.Logf("diagnostic=%s %s", failure.Diagnostic(), zcodeSpikeOutcome(pane, err))
	})
	t.Run("07_workspace", func(t *testing.T) {
		t.Run("text", func(t *testing.T) {
			fixture := filepath.Join(spike.source.String(), "workspace.txt")
			const marker = "MULGAE_7D7A03D5_WORKSPACE"
			if err := os.WriteFile(fixture, []byte(marker+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			prompt := fmt.Sprintf("Use only Read for %s. Write its single line to the staged output and follow the delivery contract.", fixture)
			res, pane, err := spike.invoke(t, terminalPurposeReview, domain.LiveSourceWorkspace, spikeZCodeModel, "max", []byte(prompt), false)
			assessZCodeSpikeTurn(t, res, pane, err)
			if strings.TrimSpace(string(res.OutputBytes)) != marker || pane.tools != "Read,Grep,Glob,Write" {
				t.Fatal("response did not contain the workspace-only marker")
			}
		})
		t.Run("artist_png", func(t *testing.T) {
			spike.artistTurn(t, domain.LiveSourceWorkspace)
		})
	})
	t.Run("08_git", func(t *testing.T) {
		const marker = "MULGAE_ZCODE_SPIKE_GIT_OBJECT"
		zcodeSpikeGit(t, spike.source.String(), "init", "-q")
		fixture := filepath.Join(spike.source.String(), "marker.txt")
		if err := os.WriteFile(fixture, []byte(marker+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		zcodeSpikeGit(t, spike.source.String(), "add", "--", "marker.txt")
		zcodeSpikeGit(t, spike.source.String(), "-c", "user.name=Mulgae Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", "Synthetic fixture")
		if err := os.WriteFile(fixture, []byte("WORKTREE_DECOY\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		prompt := []byte("Use Bash to run precisely `/usr/bin/git show HEAD:marker.txt`. Write only the returned line to the staged output and follow the delivery contract.")
		t.Run("git_show", func(t *testing.T) {
			res, pane, err := spike.invoke(t, terminalPurposeReview, domain.LiveSourceHead, spikeZCodeModel, "max", prompt, false)
			assessZCodeSpikeTurn(t, res, pane, err)
			if strings.TrimSpace(string(res.OutputBytes)) != marker || pane.tools != "Read,Bash,Write" {
				t.Fatal("response did not contain the Git-object-only marker")
			}
			if !pane.endpointObserved {
				t.Fatal("no ZCode endpoint socket observed during the Git turn")
			}
		})
		t.Run("artist_png", func(t *testing.T) {
			spike.artistTurn(t, domain.LiveSourceHead)
		})
	})
	t.Run("09_staging", func(t *testing.T) {
		t.Run("extraction", func(t *testing.T) {
			const prompt = `Extract the value from "fixture_item: kelp" into a JSON object with the single string key "item". Follow the delivery contract.`
			res, pane, err := spike.invoke(t, terminalPurposeExtraction, "", spikeZCodeModel, "max", []byte(prompt), false)
			assessZCodeSpikeTurn(t, res, pane, err)
			var output map[string]string
			if err := json.Unmarshal(res.OutputBytes, &output); err != nil || len(output) != 1 || output["item"] != "kelp" || pane.tools != "Read,Write" {
				t.Fatal("incorrect extraction JSON")
			}
		})
		t.Run("qualification", func(t *testing.T) {
			materializer, err := workspace.NewMaterializer(zcodeSpikeRoot(t, spike.base), filesystem.NewContentDetector())
			if err != nil {
				t.Fatal(err)
			}
			factory, err := NewProbeFixtureLeaseFactory(materializer, SecureProbeNonceGenerator{})
			if err != nil {
				t.Fatal(err)
			}
			fixture, err := factory.Acquire(t.Context(), domain.RoleLogic)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				if _, err := fixture.DrainTerminal(ctx); err != nil {
					t.Errorf("drain qualification fixture: %v", err)
				}
			})
			policy := fixture.WorkspaceSnapshotIdentity().PolicyIdentity()
			if policy != "current-qualification-fixture-v4" {
				t.Fatal("unable to bind exact qualification fixture policy")
			}
			guard, err := fixture.RevalidateForExecution()
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := guard.Close(); err != nil {
					t.Errorf("close qualification guard: %v", err)
				}
			})
			qual := spike
			qual.source = zcodeSpikeRoot(t, guard.WorkspaceRoot().Path())
			res, pane, err := qual.invoke(t, terminalPurposeQualification, "", spikeZCodeModel, "max", fixture.Packet(), false)
			assessZCodeSpikeTurn(t, res, pane, err)
			if pane.tools != "Read,Write" {
				t.Fatal("qualification was given an unexpected tool")
			}
			if err := guard.RevalidateAfterExecution(); err != nil {
				t.Fatal(err)
			}
			if err := validateProbeEvidence(res.OutputBytes, fixture); err != nil {
				t.Fatal(err)
			}
			t.Logf("qualification policy=%s", policy)
		})
	})
	t.Run("10_teardown_and_side_effects", func(t *testing.T) {
		if teardownBound <= 0 || teardownBound > time.Second {
			t.Errorf("terminal.kill through verified ESRCH was not bounded by 1s: %s", teardownBound)
		}
	})
}

func (s zcodeSpike) selectionTurn(t *testing.T, model, effort string) (terminalDriverResult, *zcodeSpikePane, error) {
	t.Helper()
	prompt := []byte("Write the single line MULGAE_ZCODE_SPIKE_READY to the staged output and follow the delivery contract.")
	result, pane, err := s.invoke(t, terminalPurposeReview, domain.LiveSourceWorkspace, model, effort, prompt, false)
	if err == nil && strings.TrimSpace(string(result.OutputBytes)) != "MULGAE_ZCODE_SPIKE_READY" {
		t.Fatal("selection response missing staged fixture marker")
	}
	return result, pane, err
}

func (s zcodeSpike) artistTurn(t *testing.T, scope domain.LiveSourceScope) {
	t.Helper()
	fixture := filepath.Join(s.source.String(), "figure.png")
	img := image.NewRGBA(image.Rect(0, 0, 256, 256))
	draw.Draw(img, img.Bounds(), image.White, image.Point{}, draw.Src)
	draw.Draw(img, image.Rect(48, 48, 208, 208), image.NewUniform(color.RGBA{R: 0x23, G: 0x42, B: 0xe5, A: 0xff}), image.Point{}, draw.Src)
	f, err := os.OpenFile(fixture, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := errors.Join(png.Encode(f, img), f.Close()); err != nil {
		t.Fatal(err)
	}
	prompt := fmt.Sprintf("You are the artist reviewer. Use only Read to inspect the binary PNG at %s. Do not use Bash or encode/decode with commands. Write only the color of the central square and follow the delivery contract.", fixture)
	result, pane, err := s.invoke(t, terminalPurposeReview, scope, spikeZCodeModel, "max", []byte(prompt), false)
	assessZCodeSpikeTurn(t, result, pane, err)
	if !strings.EqualFold(strings.TrimSpace(string(result.OutputBytes)), "blue") {
		t.Fatal("Read-only artist response did not identify the hidden PNG feature")
	}
}

func assessZCodeSpikeTurn(t *testing.T, result terminalDriverResult, pane *zcodeSpikePane, err error) {
	t.Helper()
	status, _ := pane.observation.ProgramStatus()
	transport, hasTransport := result.Process.ProviderPacketTransportReceipt()
	if err != nil || !pane.authConsumed || !pane.working || status != ports.TerminalProgramStatusDone ||
		pane.observation.TurnCount() != 1 || !result.Process.TerminalSessionCompleted() || !result.Process.ProcessGroupAbsent() ||
		!result.StagedReceipt.Valid() || !hasTransport || transport.PreStartIdentity() != transport.PostTerminationIdentity() {
		t.Fatalf("staged turn failed: %s", zcodeSpikeOutcome(pane, err))
	}
	if pane.endInterval > time.Second {
		t.Fatalf("measured upper bound %s did not establish teardown within one second", pane.endInterval)
	}
	t.Logf("%s staged=%s prompt=%s teardown_upper_bound=%s endpoint_socket_observed=%t",
		zcodeSpikeOutcome(pane, err), result.StagedReceipt.SHA256(),
		transport.PreStartIdentity().CompleteSHA256(), pane.endInterval, pane.endpointObserved)
}

func zcodeSpikeGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	env, err := liveGitEnvironment(ports.ProjectBindingObservation{})
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(t.Context(), "/usr/bin/git", args...)
	cmd.Dir = dir
	for _, variable := range env {
		cmd.Env = append(cmd.Env, variable.Name()+"="+variable.Value())
	}
	if err := cmd.Run(); err != nil {
		t.Fatalf("Git fixture setup %s: %v", args[0], err)
	}
}

func zcodeSpikeSnapshot(t *testing.T, home string) []string {
	t.Helper()
	var snapshot []string
	paths := []string{filepath.Join(home, ".zcode/v2/setting.json"), filepath.Join(home, ".zcode/v2/credentials.json"), filepath.Join(home, ".zcode/v2/provider_config.json")}
	catalogs, err := filepath.Glob(filepath.Join(home, ".zcode/v2/runtime/provider/darwin-aarch64/4.0.0/endpoint-*/zcode-builtin.json"))
	if err != nil || len(catalogs) == 0 {
		t.Fatal("no version-scoped Desktop catalog baseline")
	}
	for _, path := range append(paths, catalogs...) {
		file, err := os.Open(path)
		if err != nil {
			t.Fatal("open native baseline file")
		}
		info, statErr := file.Stat()
		hash := sha256.New()
		_, readErr := io.Copy(hash, file)
		if err := errors.Join(statErr, readErr, file.Close()); err != nil {
			t.Fatal("hash native baseline file")
		}
		snapshot = append(snapshot, fmt.Sprintf("%s:%x:%s:%d:%d", path, hash.Sum(nil), info.Mode(), info.Size(), info.ModTime().UnixNano()))
	}
	ps, err := exec.Command("/bin/ps", "-axww", "-o", "pid=,lstart=,command=").Output()
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(ps), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 7 {
			continue
		}
		command := strings.Join(fields[6:], " ")
		if strings.Contains(command, "--hc-launchd") || strings.Contains(command, "/default/default.holder.") ||
			strings.Contains(command, "/ZCode.app/Contents/") || strings.Contains(command, "/herdr-zcode-") ||
			strings.Contains(command, "/zcode-official-") {
			snapshot = append(snapshot, strings.Join(fields[:6], " "))
		}
	}
	slices.Sort(snapshot)
	return snapshot
}

func assertZCodeSpikeOwnedProcessesAbsent(base, sessionDir string) error {
	ps, err := exec.Command("/bin/ps", "-axww", "-o", "pid=,command=").Output()
	if err != nil {
		return fmt.Errorf("check owned spike processes: %w", err)
	}
	for _, line := range strings.Split(string(ps), "\n") {
		pid, command, ok := strings.Cut(strings.TrimSpace(line), " ")
		if ok && zcodeSpikeOwnedCommand(command, base, sessionDir) {
			return fmt.Errorf("owned spike process %s survived session close", pid)
		}
	}
	return nil
}

func zcodeSpikeOwnedCommand(command, base, sessionDir string) bool {
	return (base != "" && strings.Contains(command, base+"/")) ||
		(sessionDir != "" && strings.Contains(command, sessionDir+"/"))
}

func TestZCodeSpikeLocalObservations(t *testing.T) {
	t.Run("startup_selection", func(t *testing.T) {
		var baseline zcodeSpikeSelection
		baseline.remember([]byte("Selected: account:zai-individual-coding-plan/GLM"))
		if baseline.complete() {
			t.Fatal("selection without effort established a baseline")
		}
		baseline.remember([]byte("Selected: " + spikeZCodeModel + " (reasoning: max)"))
		baseline.remember([]byte("turn completed without startup banner"))
		if !baseline.matchesEffort(zcodeSpikeSelection{spikeZCodeModel, "low"}, "low") ||
			baseline.matchesEffort(zcodeSpikeSelection{"different", "low"}, "low") ||
			baseline.matchesEffort(zcodeSpikeSelection{spikeZCodeModel, "max"}, "low") {
			t.Fatal("startup selection did not survive final capture or match the effort-only request")
		}
	})
	t.Run("owned_process", func(t *testing.T) {
		const base, session = "/private/tmp/mz95.owned", "/private/tmp/core/owned"
		if !zcodeSpikeOwnedCommand("node "+base+"/ns/runtime.js", base, session) ||
			!zcodeSpikeOwnedCommand("watchdog --socket "+session+"/core.sock", base, session) ||
			zcodeSpikeOwnedCommand("herdr-core --socket /private/tmp/core/default/core.sock", base, session) {
			t.Fatal("owned command must match the invocation or session path")
		}
	})
	t.Run("readiness_disposition", func(t *testing.T) {
		expected := newTerminalDriverFailure(ports.ProviderExecutionStatusUnavailable, "provider_turn_failed",
			domain.DiagnosticCauseProviderTurnFailed, "", errors.New("no turn requested"))
		withCleanup := newTerminalDriverFailure(ports.ProviderExecutionStatusUnavailable, "provider_turn_failed",
			domain.DiagnosticCauseProviderTurnFailed, domain.DiagnosticCauseProcessGroupCleanupFailed, errors.New("cleanup failed"))
		if !zcodeSpikeExpectedReadiness(expected) || zcodeSpikeExpectedReadiness(withCleanup) ||
			zcodeSpikeExpectedReadiness(errors.New("runtime temp entry survived")) || zcodeSpikeExpectedReadiness(nil) {
			t.Fatal("only clean zero-turn disposition may satisfy readiness")
		}
	})
	t.Run("auth_consumption", func(t *testing.T) {
		for _, tc := range []struct {
			name   string
			bytes  []byte
			unlink bool
			expect bool
		}{
			{"wiped_unlinked", []byte{0, 0}, true, true},
			{"truncated", nil, true, false},
			{"nonzero", []byte{0, 1}, true, false},
			{"still_linked", []byte{0, 0}, false, false},
		} {
			t.Run(tc.name, func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "synthetic-auth")
				if err := os.WriteFile(path, []byte{1, 1}, 0o600); err != nil {
					t.Fatal(err)
				}
				file, err := os.Open(path)
				if err != nil {
					t.Fatal(err)
				}
				defer file.Close()
				if err := os.WriteFile(path, tc.bytes, 0o600); err != nil {
					t.Fatal(err)
				}
				if tc.unlink {
					if err := os.Remove(path); err != nil {
						t.Fatal(err)
					}
				}
				if got := zcodeSpikeAuthConsumed(file, path, 2); got != tc.expect {
					t.Fatalf("auth consumption = %t, want %t", got, tc.expect)
				}
			})
		}
	})
}

func (s zcodeSpike) invoke(t *testing.T, purpose terminalInvocationPurpose, scope domain.LiveSourceScope, model, effort string, content []byte, noPrompt bool) (terminalDriverResult, *zcodeSpikePane, error) {
	t.Helper()
	if *s.cleanupUnverified {
		t.Skip("prior pane teardown or namespace drain is unverified")
	}
	ctx := t.Context()
	ns, err := s.factory.AcquireProviderNamespace(ctx, "zcode_spike", FamilyZcode)
	if err != nil {
		t.Fatal(err)
	}
	lease := ns.(*namespaceLease)
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := ns.DrainTerminal(cleanup); err != nil {
			*s.cleanupUnverified = true
			t.Errorf("drain invocation namespace: %v", err)
		} else if _, err := os.Lstat(lease.root); !errors.Is(err, os.ErrNotExist) {
			*s.cleanupUnverified = true
			t.Error("owned invocation namespace still present after drain")
		}
	})
	launcher := s.profile.pkg.Launcher
	def, err := NewRuntimeDefinition(FamilyZcode, "zcode_spike", s.profile.desktop.Version, launcher.Path, launcher.SHA256, "zcode_spike", []string{launcher.Path}, nil, s.neutral.String(), spikeZCodeTurnTimeout)
	if err != nil {
		t.Fatal(err)
	}
	def.zcodeModel, def.zcodeReasoningEffort = model, effort
	packet, err := ports.NewProviderPacketFromBytes(content)
	if err != nil {
		t.Fatal(err)
	}
	roots, literals, err := defaultControlPlanePathsForHome(s.nativeHome)
	if err != nil {
		t.Fatal(err)
	}
	var extra []ports.EnvironmentVariable
	if grokReviewNeedsBashGate(scope) {
		extra, err = liveGitEnvironment(ports.ProjectBindingObservation{
			Root: s.source, GitDirectory: zcodeSpikeRoot(t, filepath.Join(s.source.String(), ".git")),
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	launch, err := os.Open(s.neutral.String())
	if err != nil {
		t.Fatal(err)
	}
	pane := &zcodeSpikePane{
		Session: s.session, noPrompt: noPrompt, source: s.source, nativeHome: s.nativeHome,
		gitScope: grokReviewNeedsBashGate(scope), trackSelection: model == "" && !noPrompt,
	}
	res, err := executeTerminalInvocation(ctx, pane, s.profile, terminalDriverRequest{
		Definition: def, Purpose: purpose, LiveScope: scope, HasLiveScope: purpose == terminalPurposeReview,
		Packet: packet, NamespaceRoot: lease.root, NamespaceEnvironment: lease.Environment(), Namespace: lease, ExtraEnvironment: extra,
		NeutralCWD: s.neutral, LaunchDirectory: launch, NativeHome: s.nativeHome, SourceRoot: s.source,
		CredentialRoots: []ports.AnchoredRoot{
			zcodeSpikeRoot(t, filepath.Join(s.nativeHome.String(), ".zcode")),
			zcodeSpikeRoot(t, filepath.Join(s.nativeHome.String(), "Library", "Keychains")),
		},
		ControlPlaneRoots: roots, ControlPlaneLiterals: literals,
		Timeout: spikeZCodeTurnTimeout, RegistryGeneration: "zcode-spike",
	})
	if pane.teardownUnverified {
		*s.cleanupUnverified = true
	}
	if noPrompt && zcodeSpikeExpectedReadiness(err) {
		scratch, ok := envLookupValue(lease.Environment(), "MULGAE_PROVIDER_SCRATCH")
		if !ok {
			return res, pane, errors.New("no-input probe missing staging directory")
		}
		for _, parent := range []string{terminalPromptParentDirName, stagedOutputParentDirectoryName} {
			entries, readErr := os.ReadDir(filepath.Join(scratch, parent))
			if len(entries) != 0 || (readErr != nil && !errors.Is(readErr, os.ErrNotExist)) {
				*s.cleanupUnverified = true
				return res, pane, errors.New("no-input probe retained a staging entry")
			}
		}
	}
	return res, pane, err
}

func zcodeSpikeExpectedReadiness(err error) bool {
	var failure *terminalDriverFailure
	return errors.As(err, &failure) && failure.Status() == ports.ProviderExecutionStatusUnavailable &&
		failure.Diagnostic() == "provider_turn_failed" && failure.Cause() == domain.DiagnosticCauseProviderTurnFailed &&
		failure.CleanupCause() == ""
}

func (p *zcodeSpikePane) RunTerminal(ctx context.Context, req ports.TerminalExecutionRequest) (ports.TerminalExecutionObservation, error) {
	p.started = true
	if dir, _, ok := req.Process().LaunchDirectory(); ok {
		defer dir.Close()
	}
	if p.noPrompt {
		var err error
		req, err = ports.NewTerminalExecutionRequest(ports.TerminalExecutionRequestInput{
			Process: req.Process(), StartupTimeout: req.StartupTimeout(), PromptFilePath: req.PromptFilePath(),
			RequireOSCReporting: true, CheckInInterval: req.CheckInInterval(),
			Columns: req.Columns(), Rows: req.Rows(), Labels: req.Labels(),
		})
		if err != nil {
			return ports.TerminalExecutionObservation{}, err
		}
	}
	argv := req.Process().Argv()
	p.tools = fixtureFlagValue(argv, "--tool-allowlist")
	boundary, hasBoundary := req.Process().LiveReadOnlyBoundary()
	if !hasBoundary || !boundary.PaneTTY() || boundary.BashGate() != p.gitScope {
		return ports.TerminalExecutionObservation{}, errors.New("unexpected spike pane boundary")
	}
	runtimeTemp, hasTemp := boundary.RuntimeTempRoot()
	if !hasTemp {
		return ports.TerminalExecutionObservation{}, errors.New("missing short runtime temp")
	}
	beforeEndpoints, err := zcodeSpikeEndpoints(runtimeTemp.String())
	if err != nil {
		return ports.TerminalExecutionObservation{}, err
	}
	promptInfo, err := os.Lstat(req.PromptFilePath().String())
	if err != nil || promptInfo.Mode() != 0o400 {
		return ports.TerminalExecutionObservation{}, errors.New("prompt staged file is not read-only")
	}
	authPath, catalogPath := fixtureFlagValue(argv, "--auth-file"), fixtureFlagValue(argv, "--catalog-file")
	fd, err := unix.Open(authPath, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return ports.TerminalExecutionObservation{}, fmt.Errorf("open prepared auth descriptor: %w", err)
	}
	auth := os.NewFile(uintptr(fd), "spike projected auth")
	defer auth.Close()
	authInfo, err := auth.Stat()
	if err != nil || authInfo.Mode().Perm() != 0o600 || authInfo.Size() <= 0 {
		return ports.TerminalExecutionObservation{}, errors.New("invalid auth mode or size")
	}
	catalog, err := os.ReadFile(catalogPath)
	if err != nil {
		return ports.TerminalExecutionObservation{}, fmt.Errorf("read prepared catalog: %w", err)
	}
	info, err := os.Stat(catalogPath)
	var metadata struct{ Revision int }
	if err != nil || info.Mode().Perm() != 0o400 || json.Unmarshal(catalog, &metadata) != nil ||
		metadata.Revision < 48 || !bytes.Contains(catalog, []byte(`"GLM-5.4"`)) {
		return ports.TerminalExecutionObservation{}, errors.New("invalid prepared catalog mode, revision, or model")
	}
	p.catalogRevision = metadata.Revision
	observations := make(chan zcodeSpikeOSC, 1)
	observeCtx, finishObservation := context.WithCancel(ctx)
	defer finishObservation()
	go observeZCodeSpikeOSC(observeCtx, p.SocketPath(), req.Labels(), runtimeTemp.String(), beforeEndpoints, p.trackSelection, observations)
	start := time.Now()
	p.observation, err = p.Session.RunTerminal(ctx, req)
	p.teardownUnverified = !p.observation.ProcessObservation().ProcessGroupAbsent()
	end := time.Now()
	p.duration = end.Sub(start)
	finishObservation()
	osc := <-observations
	p.working = !osc.lastWorking.IsZero()
	p.endpointObserved = osc.endpointSocket
	p.coreStatus = osc.status
	if p.working {
		if lifecycle, ok := p.observation.ProcessObservation().LifecycleReceipt(); ok {
			for _, signal := range lifecycle.SignalRequests() {
				if signal.Reason() == ports.ProcessGroupSignalRequestTerminalTeardown {
					p.endInterval = end.Sub(osc.lastWorking)
					break
				}
			}
		}
	}
	selected := osc.selection
	selected.remember(p.observation.ScreenCapture())
	p.selection, p.effort = selected.model, selected.effort
	p.authConsumed = zcodeSpikeAuthConsumed(auth, authPath, authInfo.Size())
	if p.noPrompt && err == nil && p.authConsumed && !p.teardownUnverified {
		if err := p.verifyKernelDenials(ctx, req); err != nil {
			return p.observation, err
		}
		p.kernelVerified = true
	}
	if afterEndpoints, entriesErr := zcodeSpikeEndpoints(runtimeTemp.String()); entriesErr != nil || !slices.Equal(beforeEndpoints, afterEndpoints) {
		p.teardownUnverified = true
		return p.observation, errors.New("short runtime root entry left after pane teardown")
	}
	return p.observation, err
}

func zcodeSpikeAuthConsumed(auth *os.File, path string, size int64) bool {
	var stat unix.Stat_t
	_, pathErr := os.Lstat(path)
	if size <= 0 || unix.Fstat(int(auth.Fd()), &stat) != nil || stat.Size != size ||
		stat.Nlink != 0 || !errors.Is(pathErr, os.ErrNotExist) {
		return false
	}
	var buf [1024]byte
	defer clear(buf[:])
	var total int64
	for {
		n, err := auth.Read(buf[:])
		total += int64(n)
		for _, b := range buf[:n] {
			if b != 0 {
				return false
			}
		}
		if err != nil || total > size {
			return errors.Is(err, io.EOF) && total == size
		}
	}
}

func (p *zcodeSpikePane) verifyKernelDenials(ctx context.Context, req ports.TerminalExecutionRequest) error {
	parent := req.Process()
	boundary, hasBoundary := parent.LiveReadOnlyBoundary()
	if !hasBoundary || boundary.BashGate() {
		return errors.New("kernel probe requires the shell-free pane boundary")
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return err
	}
	argv := []string{exe, "-test.run=^TestZCodeSpikeKernelProbe$", "--", "--zcode-spike-kernel-probe",
		filepath.Join(p.source.String(), "protected.txt"),
		filepath.Join(p.nativeHome.String(), ".zcode", "v2", "setting.json"),
		filepath.Join(p.nativeHome.String(), "Library", "Keychains", "login.keychain-db"),
	}
	binding, _ := parent.ProviderPacketBinding()
	proc, err := ports.NewProviderTerminalProcessRequest(exe, argv, parent.Environment(), parent.WorkingDirectory(), binding, 15*time.Second)
	if err != nil {
		return err
	}
	proc, err = ports.NewLiveReadOnlyProcessRequest(proc, boundary)
	if err != nil {
		return err
	}
	cwd, err := ports.NewAnchoredRoot(parent.WorkingDirectory())
	if err != nil {
		return err
	}
	dir, err := os.Open(cwd.String())
	if err != nil {
		return err
	}
	defer dir.Close()
	proc, err = ports.NewNeutralBoundProcessRequest(proc, cwd, dir)
	if err != nil {
		return err
	}
	probe, err := ports.NewTerminalExecutionRequest(ports.TerminalExecutionRequestInput{
		Process: proc, StartupTimeout: 2 * time.Second, PromptFilePath: req.PromptFilePath(),
		Columns: req.Columns(), Rows: req.Rows(), Labels: req.Labels(),
	})
	if err != nil {
		return err
	}
	obs, err := p.Session.RunTerminal(ctx, probe)
	p.teardownUnverified = !obs.ProcessObservation().ProcessGroupAbsent()
	if err != nil {
		return err
	}
	process := obs.ProcessObservation()
	code, exited := process.ExitCode()
	if !exited || code != 0 || !process.ProcessGroupAbsent() || !bytes.Contains(obs.ScreenCapture(), []byte("SPIKE_KERNEL_DENIALS_VERIFIED")) {
		return errors.New("kernel probe did not establish four EPERM denials")
	}
	return nil
}

func TestZCodeSpikeKernelProbe(t *testing.T) {
	i := slices.Index(os.Args, "--zcode-spike-kernel-probe")
	if i == -1 {
		t.Skip("guarded spike child only")
	}
	paths := os.Args[i+1:]
	if len(paths) != 3 {
		t.Fatal("incomplete spike child authority")
	}
	for _, probe := range []struct {
		path  string
		flags int
	}{
		{paths[0], unix.O_WRONLY}, {paths[1], unix.O_WRONLY},
		{paths[1], unix.O_RDONLY}, {paths[2], unix.O_RDONLY},
	} {
		// No read, write, truncation or creation even if the rule is absent.
		fd, err := unix.Open(probe.path, probe.flags|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err == nil {
			_ = unix.Close(fd)
		}
		if !errors.Is(err, unix.EPERM) {
			t.Fatalf("expected EPERM from open, got %v", err)
		}
	}
	fmt.Println("SPIKE_KERNEL_DENIALS_VERIFIED")
}

type zcodeSpikeOSC struct {
	lastWorking    time.Time
	endpointSocket bool
	status         string
	selection      zcodeSpikeSelection
}

type zcodeSpikeSelection struct {
	model, effort string
}

func (s *zcodeSpikeSelection) remember(screen []byte) {
	selected := spikeZCodeSelected.FindSubmatch(screen)
	if selected == nil {
		return
	}
	model, effort := string(selected[1]), string(selected[2])
	if s.model == "" || (s.effort == "" && effort != "") {
		s.model, s.effort = model, effort
	}
}

func (s zcodeSpikeSelection) complete() bool { return s.model != "" && s.effort != "" }

func (s zcodeSpikeSelection) matchesEffort(current zcodeSpikeSelection, effort string) bool {
	return s.complete() && current.model == s.model && current.effort == effort
}

func observeZCodeSpikeOSC(ctx context.Context, socket string, labels map[string]string, tempRoot string, before []string, trackSelection bool, out chan<- zcodeSpikeOSC) {
	var observed zcodeSpikeOSC
	defer func() { out <- observed }()
	rpc, err := herdr.NewRPCClient(socket, time.Second)
	if err != nil {
		return
	}
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	const maxStartupReads = 6
	startupReads := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			if !observed.endpointSocket {
				entries, _ := zcodeSpikeEndpoints(tempRoot)
				for _, name := range entries {
					if !slices.Contains(before, name) {
						info, err := os.Lstat(filepath.Join(tempRoot, name, "endpoint.sock"))
						observed.endpointSocket = err == nil && info.Mode()&os.ModeSocket != 0
						if observed.endpointSocket {
							break
						}
					}
				}
			}
			// The time before the request is a conservative bound on when the
			// still-working state was observed, hence also on when kill began.
			now := time.Now()
			list, err := rpc.TerminalList(ctx, herdr.ListParams{All: true, Labels: labels})
			if err != nil {
				continue
			}
			for _, pane := range list.Terminals {
				if !pane.Reported || pane.Status == nil {
					continue
				}
				switch pane.Status.State {
				case "idle", "working", "done", "blocked", "error":
					observed.status = pane.Status.State
				}
				if pane.Status.State == "working" && pane.State != "finished" {
					observed.lastWorking = now
				}
				if trackSelection && startupReads < maxStartupReads && !observed.selection.complete() && pane.State != "finished" &&
					(pane.Status.State == "idle" || pane.Status.State == "working") {
					startupReads++
					screen, err := rpc.TerminalRead(ctx, herdr.ReadParams{Terminal: pane.Address, Lines: 36})
					if err == nil {
						observed.selection.remember([]byte(screen.Text))
					}
				}
			}
		}
	}
}

func zcodeSpikeEndpoints(root string) ([]string, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, entry := range entries {
		if entry.IsDir() && strings.HasPrefix(entry.Name(), "zcode-official-") {
			names = append(names, entry.Name())
		}
	}
	return names, nil
}

func zcodeSpikeRoot(t *testing.T, path string) ports.AnchoredRoot {
	t.Helper()
	root, err := ports.NewAnchoredRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func zcodeSpikeOutcome(pane *zcodeSpikePane, err error) string {
	cause := "none"
	diagnostic := ""
	var failure *terminalDriverFailure
	if errors.As(err, &failure) {
		cause = string(failure.Cause())
		diagnostic = failure.Diagnostic()
	} else if err != nil {
		cause = fmt.Sprintf("%T", err)
	}
	var staged *providerOutputFailure
	stagingDetail := ""
	if errors.As(err, &staged) && staged.Cause() == domain.DiagnosticCauseProviderOutputFileInvalid {
		switch detail := staged.Unwrap().Error(); detail {
		case "provider staged output: staged file is empty",
			"provider staged output: staged file contains a NUL byte",
			"provider staged output: staged file is not valid UTF-8",
			"provider staged output: staged file contains only whitespace",
			"provider staged output: staged output missing or mismatched completion nonce",
			"provider staged output: staged output body is empty before completion nonce",
			"provider staged output: staged output leaked completion nonce inside report body":
			stagingDetail = detail
		default:
			stagingDetail = "other closed staging failure"
		}
	}
	status, _ := pane.observation.ProgramStatus()
	blocked, _ := pane.observation.BlockedKind()
	proc := pane.observation.ProcessObservation()
	exit, hasExit := proc.ExitCode()
	screen := string(pane.observation.ScreenCapture())
	markers := []string{}
	for _, marker := range []string{
		"Operation not permitted", "EPERM", "EACCES", "endpoint.sock", "App-server", "app-server",
		"startup or transport failed", "Requested model is absent from the ", "no fallback model.",
		"Selected model unavailable", "Selected model changed", "not confirmed",
	} {
		if strings.Contains(screen, marker) {
			markers = append(markers, marker)
		}
	}
	return fmt.Sprintf("cause=%s diagnostic=%s staging_detail=%q started=%t reported=%t working=%t status=%s core_status=%s blocked=%s turns=%d termination=%s exit=%d has_exit=%t group_absent=%t elapsed=%s model=%q effort=%q markers=%q",
		cause, diagnostic, stagingDetail, pane.started, pane.observation.Reported(), pane.working, status, pane.coreStatus, blocked,
		pane.observation.TurnCount(), proc.Termination(), exit, hasExit, proc.ProcessGroupAbsent(), pane.duration, pane.selection, pane.effort, markers)
}
