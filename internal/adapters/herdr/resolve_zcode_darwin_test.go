//go:build darwin && arm64

package herdr

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func makeZCodePackageFixture(t *testing.T, root, script string) string {
	t.Helper()
	for _, file := range zcodeRuntimeFiles {
		content, mode := file, os.FileMode(0o600)
		if file == "bin/herdr-zcode" {
			content, mode = script, 0o700
		}
		writeFakeBinary(t, filepath.Join(root, file), mode, []byte(content))
	}
	return filepath.Join(root, "bin", "herdr-zcode")
}

func TestResolveZCodePackageIdentity(t *testing.T) {
	base := canonicalTempDir(t)
	root := filepath.Join(base, "package")
	launcher := makeZCodePackageFixture(t, root, "#!/bin/sh\nexit 0\n")
	localBin := filepath.Join(base, "home", ".local", "bin")
	if err := os.MkdirAll(localBin, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(localBin, "herdr-zcode")
	if err := os.Symlink(launcher, link); err != nil {
		t.Fatal(err)
	}
	pathBin := filepath.Join(base, "path")
	pathLauncher := makeZCodePackageFixture(t, pathBin, "#!/bin/sh\nexit 0\n")
	opts := ResolveOptions{NativeHome: filepath.Join(base, "home"), PathEnv: filepath.Dir(pathLauncher)}
	found, err := ResolveZCodePackage(opts)
	if err != nil || found.Launcher.Path != pathLauncher {
		t.Fatalf("PATH result = %v, %v", found, err)
	}
	opts.PathEnv = "."
	found, err = ResolveZCodePackage(opts)
	if err != nil || found.Launcher.Path != launcher || found.Inode() == 0 || found.VerifySpawn() != nil {
		t.Fatalf("fallback result = %v, %v", found, err)
	}
	if len(zcodeRuntimeFiles) != 20 || !slices.IsSorted(zcodeRuntimeFiles[:]) {
		t.Fatal("companion manifest must have 20 byte-ordered files")
	}
	hash := sha256.New()
	for _, path := range zcodeRuntimeFiles {
		data, err := os.ReadFile(filepath.Join(root, path))
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(hash, "%s\t%d\t%x\n", path, len(data), sha256.Sum256(data))
	}
	if want := fmt.Sprintf("%x", hash.Sum(nil)); found.PackageSHA256 != want {
		t.Fatalf("package digest = %s, want %s", found.PackageSHA256, want)
	}
	opts.HasOverride, opts.OverridePath = true, link
	opts.ExcludedRoots = []string{root}
	opts.PathEnv = filepath.Dir(pathLauncher)
	if _, err := ResolveZCodePackage(opts); !errors.Is(err, ErrUnsafeExecutable) {
		t.Fatalf("excluded explicit override must fail closed: %v", err)
	}
}

func TestResolveZCodePackageRejectsTamper(t *testing.T) {
	cases := map[string]func(string) error{
		"changed bytes": func(path string) error { return os.WriteFile(path, []byte("changed"), 0o600) },
		"symlink": func(path string) error {
			if err := os.Rename(path, path+".original"); err != nil {
				return err
			}
			return os.Symlink(path+".original", path)
		},
		"hardlink":       func(path string) error { return os.Link(path, path+".alias") },
		"group writable": func(path string) error { return os.Chmod(path, 0o664) },
		"world writable": func(path string) error { return os.Chmod(path, 0o666) },
		"missing":        os.Remove,
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			root := canonicalTempDir(t)
			path := makeZCodePackageFixture(t, root, "#!/bin/sh\nexit 0\n")
			pkg, err := ResolveZCodePackage(ResolveOptions{OverridePath: path, HasOverride: true})
			if err != nil {
				t.Fatal(err)
			}
			if err := mutate(filepath.Join(root, "scripts", "desktop-bootstrap.pl")); err != nil {
				t.Fatal(err)
			}
			if err := pkg.VerifySpawn(); !errors.Is(err, ErrUnsafeExecutable) {
				t.Fatalf("post-discovery tamper not rejected: %v", err)
			}
		})
	}
	for _, member := range []string{"scripts/toolchain.sh", "lib/prepare-isolated.mjs", "scripts/desktop-bootstrap.pl"} {
		t.Run("same length edit "+member, func(t *testing.T) {
			root := canonicalTempDir(t)
			path := makeZCodePackageFixture(t, root, "#!/bin/sh\nexit 0\n")
			pkg, err := ResolveZCodePackage(ResolveOptions{OverridePath: path, HasOverride: true})
			if err != nil {
				t.Fatal(err)
			}
			file := filepath.Join(root, member)
			data, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			data[0] ^= 1
			if err := os.WriteFile(file, data, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := pkg.VerifySpawn(); !errors.Is(err, ErrUnsafeExecutable) {
				t.Fatalf("same-length runtime edit was accepted: %v", err)
			}
		})
	}
	t.Run("same bytes new launcher inode", func(t *testing.T) {
		root := canonicalTempDir(t)
		script := "#!/bin/sh\nexit 0\n"
		path := makeZCodePackageFixture(t, root, script)
		pkg, err := ResolveZCodePackage(ResolveOptions{OverridePath: path, HasOverride: true})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(path, path+".previous"); err != nil {
			t.Fatal(err)
		}
		writeFakeBinary(t, path, 0o700, []byte(script))
		if err := pkg.VerifySpawn(); !errors.Is(err, ErrUnsafeExecutable) {
			t.Fatalf("launcher inode replacement not rejected: %v", err)
		}
	})
}

func TestResolveZCodePackageExplicitEnvironment(t *testing.T) {
	base := canonicalTempDir(t)
	overrideRoot := filepath.Join(base, "override")
	override := makeZCodePackageFixture(t, overrideRoot, "#!/bin/sh\nexit 0\n")
	pathLauncher := makeZCodePackageFixture(t, filepath.Join(base, "path"), "#!/bin/sh\nexit 0\n")
	t.Setenv("PATH", filepath.Dir(pathLauncher))
	t.Setenv(EnvHerdrZCodeBin, override)
	home := filepath.Join(base, "home")
	pkg, err := ResolveZCodePackage(DefaultZCodeResolveOptions(home))
	if err != nil || pkg.Launcher.Path != override {
		t.Fatalf("explicit environment override = %+v, %v", pkg, err)
	}
	badPath := filepath.Join(base, "not-package", "herdr-zcode")
	writeFakeBinary(t, badPath, 0o700, []byte("#!/bin/sh\nexit 0\n"))
	for _, invalid := range []string{"", "relative", badPath} {
		t.Setenv(EnvHerdrZCodeBin, invalid)
		if _, err := ResolveZCodePackage(DefaultZCodeResolveOptions(home)); !errors.Is(err, ErrUnsafeExecutable) {
			t.Fatalf("invalid override %q fell back: %v", invalid, err)
		}
	}
	for _, dir := range []string{overrideRoot, filepath.Join(overrideRoot, "scripts", "tool-bin")} {
		t.Setenv(EnvHerdrZCodeBin, override)
		if err := os.Chmod(dir, 0o770); err != nil {
			t.Fatal(err)
		}
		_, err := ResolveZCodePackage(DefaultZCodeResolveOptions(home))
		if resetErr := os.Chmod(dir, 0o700); resetErr != nil {
			t.Fatal(resetErr)
		}
		if !errors.Is(err, ErrUnsafeExecutable) {
			t.Fatalf("group-writable package directory %q accepted: %v", dir, err)
		}
	}
	if _, err := ResolveZCodePackage(ResolveOptions{NativeHome: home}); !errors.Is(err, ErrExecutableNotFound) {
		t.Fatalf("missing package did not return missing reason: %v", err)
	}
}

func TestObserveZCodeCompanionRejectsInvalidOutput(t *testing.T) {
	const version = `{"name":"herdr-zcode","version":"0.2.0","runtimes":["tui","core"],"osc7501":true,"capabilities":["core","osc7501","catalogFile","prepareIsolated","checkDesktop"]}`
	const desktop = `{"compatible":true,"appVersion":"4.0.0","minZcodeAppVersion":"3.18.2","appBundle":"/Applications/Test.app"}`
	for _, tc := range []struct{ name, version, desktop string }{
		{"missing capability", strings.Replace(version, `,"checkDesktop"`, "", 1), desktop},
		{"incompatible desktop", version, strings.Replace(desktop, "true", "false", 1)},
		{"mismatched bundle", version, strings.Replace(desktop, "Test.app", "Other.app", 1)},
		{"noncanonical bundle", version, strings.Replace(desktop, "Test.app", "./Test.app", 1)},
		{"malformed json", "{", desktop},
		{"oversized json", version + strings.Repeat(" ", 128*1024), desktop},
	} {
		t.Run(tc.name, func(t *testing.T) {
			script := fmt.Sprintf("#!/bin/sh\ncase \"$1\" in --version) printf '%%s\\n' '%s';; --check-desktop) printf '%%s\\n' '%s';; esac\n", tc.version, tc.desktop)
			launcher := makeZCodePackageFixture(t, canonicalTempDir(t), script)
			pkg, err := ResolveZCodePackage(ResolveOptions{HasOverride: true, OverridePath: launcher})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if _, err := ObserveZCodeCompanion(ctx, pkg, "/Applications/Test.app"); err == nil {
				t.Fatal("invalid companion output was accepted")
			}
			if ctx.Err() != nil {
				t.Fatalf("invalid diagnostic output consumed the caller deadline: %v", ctx.Err())
			}
		})
	}
}

func TestZCodeCompanionCancellationReapsDetachedWorker(t *testing.T) {
	const fixture = `#!/usr/bin/perl
use strict;
use POSIX qw(setsid);
use Errno qw(EINTR);
my $child;
$SIG{TERM} = sub { kill 'TERM', $child if $child; };
$child = fork();
die "fork failed" unless defined $child;
if (!$child) {
    setsid() >= 0 or die "setsid failed";
    $SIG{TERM} = sub { exit 0; };
    open(my $ready, '>', $ARGV[0]) or die "open fixture marker";
    print $ready "$$\n";
    close $ready or die "close fixture marker";
    sleep 30;
    exit 4;
}
my $waited;
do { $waited = waitpid($child, 0); } while ($waited < 0 && $! == EINTR);
exit($waited == $child ? 1 : 3);
`
	dir := canonicalTempDir(t)
	pp := makeZCodePackageFixture(t, filepath.Join(dir, "fixture"), fixture)
	pkg, err := ResolveZCodePackage(ResolveOptions{HasOverride: true, OverridePath: pp})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	marker := filepath.Join(dir, "child-pid")
	done := make(chan error, 1)
	go func() {
		var stdout zcodeDiagnosticCapture
		done <- pkg.RunOfflineCommand(ctx, 8*time.Second, "/private/var/empty", &stdout, marker)
	}()
	var pid int
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
		if raw, err := os.ReadFile(marker); err == nil {
			pid, _ = strconv.Atoi(strings.TrimSpace(string(raw)))
			if pid > 0 {
				break
			}
		}
	}
	if pid <= 0 {
		t.Fatal("detached fixture did not report its owned PID")
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("cooperative cancellation = %v", err)
	}
	if err := syscall.Kill(pid, 0); !errors.Is(err, syscall.ESRCH) {
		// This synthetic child is owned solely by the fixture.
		_ = syscall.Kill(pid, syscall.SIGKILL)
		t.Fatalf("launcher did not reap its detached fixture worker: %v", err)
	}
}

func TestZCodeCompanionForcedExitIsUnverified(t *testing.T) {
	launcher := makeZCodePackageFixture(t, canonicalTempDir(t), "#!/usr/bin/perl\nkill 'KILL', $$;\n")
	pkg, err := ResolveZCodePackage(ResolveOptions{HasOverride: true, OverridePath: launcher})
	if err != nil {
		t.Fatal(err)
	}
	var stdout zcodeDiagnosticCapture
	if err := pkg.RunOfflineCommand(context.Background(), 5*time.Second, "/private/var/empty", &stdout, "--version"); !errors.Is(err, ErrZCodeCompanionTeardown) {
		t.Fatalf("forced exit incorrectly proved teardown: %v", err)
	}
}

func TestZCodeCompanionForcesVerifiedSurvivorGroup(t *testing.T) {
	const fixture = `#!/usr/bin/perl
use strict;
$SIG{TERM} = 'IGNORE';
my $child = fork();
die "fork failed" unless defined $child;
if (!$child) {
    open(my $ready, '>', $ARGV[0]) or die "open fixture marker";
    print $ready "$$\n";
    close $ready or die "close fixture marker";
    sleep 30;
    exit 4;
}
sleep 30;
exit 3;
`
	dir := canonicalTempDir(t)
	launcher := makeZCodePackageFixture(t, filepath.Join(dir, "fixture"), fixture)
	pkg, err := ResolveZCodePackage(ResolveOptions{HasOverride: true, OverridePath: launcher})
	if err != nil {
		t.Fatal(err)
	}
	var stdout zcodeDiagnosticCapture
	marker := filepath.Join(dir, "worker-pid")
	err = pkg.RunOfflineCommand(context.Background(), 3*time.Second, "/private/var/empty", &stdout, marker)
	if !errors.Is(err, ErrZCodeCompanionTeardown) || errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("uncooperative launcher classified incorrectly: %v", err)
	}
	data, err := os.ReadFile(marker)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || !validTargetPID(pid) {
		t.Fatal("fixture did not report its owned worker")
	}
	info, err := inspectProcess(pid)
	if err != nil || (info.Exists && !info.Zombie) {
		if err == nil && info.Exists {
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
		t.Fatalf("same-group worker survived verified escalation: %v", err)
	}
}

func TestZCodeCompanionDistinguishesCommandAndParentDeadlines(t *testing.T) {
	const fixture = "#!/usr/bin/perl\n$SIG{TERM} = sub { exit 1; }; sleep 30;\n"
	launcher := makeZCodePackageFixture(t, canonicalTempDir(t), fixture)
	pkg, err := ResolveZCodePackage(ResolveOptions{HasOverride: true, OverridePath: launcher})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name           string
		parentDeadline bool
		want           error
	}{
		{"local", false, ErrZCodeCompanionTimeout},
		{"parent", true, context.DeadlineExceeded},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			limit := 2500 * time.Millisecond
			if tc.parentDeadline {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 500*time.Millisecond)
				defer cancel()
				limit = 5 * time.Second
			}
			var stdout zcodeDiagnosticCapture
			err := pkg.RunOfflineCommand(ctx, limit, "/private/var/empty", &stdout, "--version")
			if !errors.Is(err, tc.want) || (!tc.parentDeadline && errors.Is(err, context.DeadlineExceeded)) {
				t.Fatalf("command interruption = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestObserveZCodeCompanionOffline(t *testing.T) {
	script := `#!/bin/sh
[ "$PWD" = /private/var/empty ] && [ "$HOME" = /private/var/empty ] && [ "$PATH" = /usr/bin:/bin ] &&
[ -z "${NVM_DIR+x}${HC_SOCKET+x}${HERDR_SOCKET+x}${DYLD_LIBRARY_PATH+x}${NODE_OPTIONS+x}" ] || exit 2
case "$0" in /*/bin/herdr-zcode) ;; *) exit 2 ;; esac
[ "$2" = --json ] || exit 2
if [ "$#" -eq 2 ]; then
  bundle=/Applications/ZCode.app
  version=0.2.0
elif [ "$#" -eq 4 ] && [ "$3" = --app-bundle ] && [ "$4" = '/Applications/Fixture ZCode.app' ]; then
  bundle=$4
  version=0.2.1
else
  exit 2
fi
case "$1" in
  --version) printf '{"name":"herdr-zcode","version":"%s","runtimes":["tui","core"],"osc7501":true,"capabilities":["core","osc7501","catalogFile","prepareIsolated","checkDesktop"]}\n' "$version" ;;
  --check-desktop) printf '{"compatible":true,"appVersion":"4.0.0","minZcodeAppVersion":"3.18.2","appBundle":"%s"}\n' "$bundle" ;;
  *) exit 2 ;;
esac
`
	t.Setenv("NVM_DIR", "/ambient")
	t.Setenv("HC_SOCKET", "/ambient")
	t.Setenv("HERDR_SOCKET", "/ambient")
	t.Setenv("DYLD_LIBRARY_PATH", "/ambient")
	t.Setenv("NODE_OPTIONS", "--ambient")
	path := makeZCodePackageFixture(t, canonicalTempDir(t), script)
	pkg, err := ResolveZCodePackage(ResolveOptions{OverridePath: path, HasOverride: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, appBundle, wantBundle, wantVersion string
	}{
		{"omitted bundle", "", "/Applications/ZCode.app", "0.2.0"},
		{"explicit bundle", "/Applications/Fixture ZCode.app", "/Applications/Fixture ZCode.app", "0.2.1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			observed, err := ObserveZCodeCompanion(context.Background(), pkg, tc.appBundle)
			if err != nil || observed.Version != tc.wantVersion || observed.AppVersion != "4.0.0" ||
				observed.AppBundle != tc.wantBundle || observed.MinimumVersion != "3.18.2" {
				t.Fatalf("offline observation = %+v, %v", observed, err)
			}
		})
	}
}
