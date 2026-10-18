//go:build darwin && arm64

package process

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/irootkernel/mulgae/internal/ports"
	"golang.org/x/sys/unix"
)

func TestLiveNeutralDescriptorConsumedOnEarlyReturn(t *testing.T) {
	for _, scenario := range []string{"run-cancelled", "run-clock", "converse-clock", "converse-nil-driver"} {
		t.Run(scenario, func(t *testing.T) {
			neutral, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			directory, err := os.Open(neutral)
			if err != nil {
				t.Fatal(err)
			}
			defer directory.Close()
			packet, _ := ports.NewProviderPacketFromBytes([]byte("fixture packet"))
			binding, _ := ports.NewProtocolProviderPacketBinding(packet)
			request, err := ports.NewProviderProtocolProcessRequest("/bin/sh", []string{"/bin/sh", "-c", "exit 0"}, nil, neutral, binding, time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			root, _ := ports.NewAnchoredRoot(neutral)
			request, err = ports.NewNeutralBoundProcessRequest(request, root, directory)
			if err != nil {
				t.Fatal(err)
			}
			clock := &runnerTestClock{times: []time.Time{time.Now().UTC()}}
			if strings.HasSuffix(scenario, "clock") {
				clock.times[0] = time.Time{}
			}
			runner, err := NewRunner(clock)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if scenario == "run-cancelled" {
				cancel()
			}
			if strings.HasPrefix(scenario, "run-") {
				_, err = runner.Run(ctx, request)
			} else {
				var driver ports.ProviderSessionDriver = &conversationSingleResponseDriver{}
				if scenario == "converse-nil-driver" {
					driver = nil
				}
				_, err = runner.Converse(ctx, request, driver)
			}
			if scenario != "run-cancelled" && err == nil {
				t.Fatal("fixture did not reach the expected early failure")
			}
			if _, err := directory.Stat(); !errors.Is(err, os.ErrClosed) {
				t.Fatalf("early return retained the consumed neutral descriptor: %v", err)
			}
		})
	}
}

func TestLiveBoundaryDeniesWritesReadsAndAncestorRename(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// Quotes and Scheme-shaped text must remain literal path operands.
	source := filepath.Join(base, "source\" ) (allow file-write*)")
	gitCommon := filepath.Join(base, "common-git")
	neutral := filepath.Join(base, "neutral")
	credentials := filepath.Join(base, "credentials")
	namespace := filepath.Join(base, "invocation")
	for _, path := range []string{source, gitCommon, neutral, credentials, namespace} {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(path, "value"), []byte("ORIGINAL"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Link(filepath.Join(source, "value"), filepath.Join(base, "existing-source-alias")); err != nil {
		t.Fatal(err)
	}
	script := `set -eu
cat "$1/value"
cat "$2/value"
cat "$3/value"
if cat "$4/value"; then exit 21; fi
for path in "$1" "$2" "$3"; do
  if printf MUTATION > "$path/value"; then exit 22; fi
  if touch "$path/new"; then exit 23; fi
done
if ln "$1/value" "$5/source-alias"; then exit 27; fi
if ln "$4/value" "$5/credential-alias"; then exit 28; fi
if ln "$6/existing-source-alias" "$5/indirect-source-alias"; then exit 29; fi
if mv "$1" "$1-moved"; then exit 24; fi
if mv "$6" "$6-moved"; then exit 25; fi
if printf MUTATION > "$6/unrelated"; then exit 26; fi
printf SCRATCH > "$5/scratch"
printf DISCARD > /dev/null
printf 'PROTECTED\n'
`
	request := liveBoundaryTestRequest(t, neutral, source, gitCommon, credentials, namespace,
		[]string{"/bin/sh", "-c", script, "fixture", source, gitCommon, neutral, credentials, namespace, base})
	child, launch, _, err := assembleDirectChild(context.Background(), request, nil, nil)
	if launch != nil {
		defer launch.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	child.Stdout, child.Stderr = nil, nil
	output, err := child.CombinedOutput()
	if err != nil || strings.Count(string(output), "ORIGINAL") != 3 || !strings.Contains(string(output), "PROTECTED") {
		t.Fatalf("protected launch: %v, %s", err, output)
	}
	for _, path := range []string{source, gitCommon, neutral, credentials} {
		data, err := os.ReadFile(filepath.Join(path, "value"))
		if err != nil || string(data) != "ORIGINAL" {
			t.Fatalf("protected bytes: %v, %q", err, data)
		}
		entries, err := os.ReadDir(path)
		if err != nil || len(entries) != 1 {
			t.Fatalf("protected inventory: %v, %v", err, entries)
		}
	}
	data, err := os.ReadFile(filepath.Join(namespace, "scratch"))
	if err != nil || string(data) != "SCRATCH" {
		t.Fatalf("owned scratch: %v, %q", err, data)
	}
}

func TestLiveBoundaryDeniesCredentialSymlinksToOutsideTargets(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	source, neutral := filepath.Join(base, "source"), filepath.Join(base, "neutral")
	credentials, namespace := filepath.Join(base, "credentials"), filepath.Join(base, "invocation")
	for _, path := range []string{source, neutral, credentials, namespace} {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	outside := filepath.Join(base, "outside")
	if err := os.WriteFile(outside, []byte("OUTSIDE_CONTROL"), 0600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(credentials, "outward-alias")
	if err := os.Symlink(outside, alias); err != nil {
		t.Fatal(err)
	}
	script := `set -eu
cat "$1"
if cat "$2"; then exit 21; fi
printf 'DENIED\n'
`
	request := liveBoundaryTestRequest(t, neutral, source, source, credentials, namespace,
		[]string{"/bin/sh", "-c", script, "fixture", outside, alias})
	child, launch, _, err := assembleDirectChild(context.Background(), request, nil, nil)
	if launch != nil {
		defer launch.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	child.Stdout, child.Stderr = nil, nil
	output, err := child.CombinedOutput()
	if err != nil || strings.Count(string(output), "OUTSIDE_CONTROL") != 1 || !strings.Contains(string(output), "Operation not permitted") || !strings.Contains(string(output), "DENIED") {
		t.Fatalf("outward credential alias: %v, %s", err, output)
	}
}

func TestLiveBoundaryProtectsExoticCredentialPaths(t *testing.T) {
	for _, name := range []string{"credentials", "credentials 한글 \"quoted\"", "credentials\a", "credentials\u2028"} {
		t.Run(fmt.Sprintf("%q", name), func(t *testing.T) {
			base, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			source, neutral := filepath.Join(base, "source"), filepath.Join(base, "neutral")
			credentials, namespace := filepath.Join(base, name), filepath.Join(base, "invocation")
			for _, path := range []string{source, neutral, credentials, namespace} {
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(filepath.Join(credentials, "value"), []byte("PRIVATE_EXOTIC_FIXTURE"), 0600); err != nil {
				t.Fatal(err)
			}
			script := `if cat "$1/value"; then exit 21; fi; printf 'DENIED\n'`
			if strings.ContainsAny(name, "\a\u2028") {
				readOnly, _ := ports.NewAnchoredRoot(source)
				credential, _ := ports.NewAnchoredRoot(credentials)
				writable, _ := ports.NewAnchoredRoot(namespace)
				if _, err := ports.NewLiveReadOnlyBoundary([]ports.AnchoredRoot{readOnly}, []ports.AnchoredRoot{credential}, writable); err == nil {
					t.Fatal("exotic credential root reached launch authority")
				}
				return
			}
			request := liveBoundaryTestRequest(t, neutral, source, source, credentials, namespace,
				[]string{"/bin/sh", "-c", script, "fixture", credentials})
			child, launch, _, err := assembleDirectChild(context.Background(), request, nil, nil)
			if launch != nil {
				defer launch.Close()
			}
			if err != nil {
				t.Fatal(err)
			}
			child.Stdout, child.Stderr = nil, nil
			output, err := child.CombinedOutput()
			if strings.Contains(string(output), "PRIVATE_EXOTIC_FIXTURE") {
				t.Fatalf("exotic credential path disclosed fixture: %v, %s", err, output)
			}
			if err != nil || !strings.Contains(string(output), "Operation not permitted") || !strings.Contains(string(output), "DENIED") {
				t.Fatalf("exotic credential denial: %v, %s", err, output)
			}
		})
	}
}

func TestLiveBoundaryRejectsSymlinkAndMissingRootsBeforeLaunch(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	real := filepath.Join(base, "real")
	if err := os.Mkdir(real, 0700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(base, "alias")
	if err := os.Symlink(real, alias); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{alias, filepath.Join(alias, "child"), filepath.Join(base, "missing")} {
		t.Run(filepath.Base(path), func(t *testing.T) {
			request := liveBoundaryTestRequest(t, real, path, real, real, real, []string{"/bin/sh", "-c", "exit 0"})
			child, launch, _, err := assembleDirectChild(context.Background(), request, nil, nil)
			if child != nil || launch != nil || err == nil {
				t.Fatal("unsafe boundary admitted")
			}
		})
	}
}

func TestLiveBoundaryRejectsPreexistingCredentialHardlink(t *testing.T) {
	for _, nested := range []bool{false, true} {
		t.Run(map[bool]string{false: "root-file", true: "nested-file"}[nested], func(t *testing.T) {
			base, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			source, neutral := filepath.Join(base, "source"), filepath.Join(base, "neutral")
			credentials, namespace := filepath.Join(base, "credentials"), filepath.Join(base, "invocation")
			for _, path := range []string{source, neutral, credentials, namespace} {
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			}
			parent := credentials
			if nested {
				parent = filepath.Join(credentials, "nested")
				if err := os.Mkdir(parent, 0700); err != nil {
					t.Fatal(err)
				}
			}
			secret := filepath.Join(parent, "value")
			if err := os.WriteFile(secret, []byte("PRIVATE_FIXTURE"), 0600); err != nil {
				t.Fatal(err)
			}
			alias := filepath.Join(source, "existing-alias")
			if err := os.Link(secret, alias); err != nil {
				t.Fatal(err)
			}
			request := liveBoundaryTestRequest(t, neutral, source, source, credentials, namespace, []string{"/bin/sh", "-c", "cat \"$1\"", "fixture", alias})
			child, launch, _, err := assembleDirectChild(context.Background(), request, nil, nil)
			if err == nil || child != nil || launch != nil || !strings.Contains(err.Error(), "hardlink alias") {
				t.Fatalf("preexisting credential alias reached spawn: %v", err)
			}
		})
	}
}

func TestLiveBoundaryDeniesProtectedUnixSockets(t *testing.T) {
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	// Keep native socket paths short and canonical while honoring TMPDIR.
	temporaryBase, err := os.MkdirTemp("", "s")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(temporaryBase) })
	base, err := filepath.EvalSymlinks(temporaryBase)
	if err != nil {
		t.Fatal(err)
	}
	source, credentials, namespace := filepath.Join(base, "source"), filepath.Join(base, "credentials"), filepath.Join(base, "invocation")
	runtimeTemp := filepath.Join(base, "runtime")
	for _, path := range []string{source, credentials, namespace, runtimeTemp} {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, root := range []string{source, credentials, namespace, runtimeTemp} {
		path := filepath.Join(root, "service.sock")
		listener, err := net.Listen("unix", path)
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		paths := []string{path}
		if root != namespace && root != runtimeTemp {
			alias := filepath.Join(namespace, filepath.Base(root)+"-alias.sock")
			if err := os.Symlink(path, alias); err != nil {
				t.Fatal(err)
			}
			paths = append(paths, alias)
		}
		for _, selected := range paths {
			request := liveBoundaryTestRequest(t, source, source, source, credentials, namespace, []string{"/bin/sh", "-c", "exec \"$1\" -test.run=^TestLiveBoundarySocketChild$ -- socket \"$2\"", "fixture", binary, selected}, runtimeTemp)
			child, launch, _, err := assembleDirectChild(context.Background(), request, nil, nil)
			if launch != nil {
				defer launch.Close()
			}
			if err != nil {
				t.Fatal(err)
			}
			child.Stdout, child.Stderr = nil, nil
			output, err := child.CombinedOutput()
			if root == namespace || root == runtimeTemp {
				if err != nil {
					t.Fatalf("owned native socket rejected: %v, %s", err, output)
				}
			} else if err == nil || !strings.Contains(strings.ToLower(string(output)), "operation not permitted") && !strings.Contains(strings.ToLower(string(output)), "permission denied") {
				t.Fatalf("protected socket reached through %s: %v, %s", selected, err, output)
			}
		}
	}
}

func TestLiveBoundarySocketChild(t *testing.T) {
	arguments := helperArguments()
	if len(arguments) != 2 || arguments[0] != "socket" {
		return
	}
	connection, err := net.DialTimeout("unix", arguments[1], time.Second)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	_ = connection.Close()
	os.Exit(0)
}

func TestLiveBoundaryCredentialAdmissionHonorsCancellation(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	request := liveBoundaryTestRequest(t, base, base, base, base, base, []string{"/bin/sh", "-c", "exit 0"})
	child, launch, _, err := assembleDirectChild(ctx, request, nil, nil)
	if child != nil || launch != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled credential admission reached spawn: %v", err)
	}
	for _, mode := range []string{"run", "converse"} {
		t.Run(mode, func(t *testing.T) {
			runner, err := NewRunner(&runnerTestClock{times: []time.Time{time.Now().UTC()}})
			if err != nil {
				t.Fatal(err)
			}
			var observation ports.ProcessObservation
			if mode == "run" {
				observation, err = runner.Run(ctx, request)
			} else {
				observation, err = runner.Converse(ctx, request, &conversationSingleResponseDriver{})
			}
			if err != nil || observation.Termination() != ports.ProcessTerminationCancelled {
				t.Fatalf("credential admission cancellation lost its typed outcome: %v, %s", err, observation.Termination())
			}
		})
	}
}

func TestLiveBoundaryCredentialAdmissionHonorsDeadline(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	for _, mode := range []string{"run", "converse"} {
		t.Run(mode, func(t *testing.T) {
			request := liveBoundaryTestRequest(t, base, base, base, base, base, []string{"/bin/sh", "-c", "exit 0"})
			child, launch, _, err := assembleDirectChild(ctx, request, nil, nil)
			if child != nil || launch != nil || !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("expired admission reached spawn: %v", err)
			}
			directory, err := os.Open(base)
			if err != nil {
				t.Fatal(err)
			}
			defer directory.Close()
			root, _ := ports.NewAnchoredRoot(base)
			request, err = ports.NewNeutralBoundProcessRequest(request, root, directory)
			if err != nil {
				t.Fatal(err)
			}
			runner, err := NewRunner(&runnerTestClock{times: []time.Time{time.Now().UTC()}})
			if err != nil {
				t.Fatal(err)
			}
			var observation ports.ProcessObservation
			if mode == "run" {
				observation, err = runner.Run(ctx, request)
			} else {
				observation, err = runner.Converse(ctx, request, &conversationSingleResponseDriver{})
			}
			if err != nil || observation.Termination() != ports.ProcessTerminationTimedOut {
				t.Fatalf("admission deadline lost typed outcome: %v, %s", err, observation.Termination())
			}
			if _, err := directory.Stat(); !errors.Is(err, os.ErrClosed) {
				t.Fatalf("expired request retained neutral descriptor: %v", err)
			}
		})
	}
}

func TestLiveBoundaryRejectsPreexistingWritableHardlink(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	source, neutral := filepath.Join(base, "source"), filepath.Join(base, "neutral")
	credentials, namespace, runtimeTemp := filepath.Join(base, "credentials"), filepath.Join(base, "invocation"), filepath.Join(base, "runtime")
	for _, path := range []string{source, neutral, credentials, namespace, runtimeTemp} {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	file := filepath.Join(source, "value")
	if err := os.WriteFile(file, []byte("ORIGINAL"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(file, filepath.Join(runtimeTemp, "source-alias")); err != nil {
		t.Fatal(err)
	}
	request := liveBoundaryTestRequest(t, neutral, source, source, credentials, namespace, []string{"/bin/sh", "-c", "exit 0"}, runtimeTemp)
	child, launch, _, err := assembleDirectChild(context.Background(), request, nil, nil)
	if err == nil || child != nil || launch != nil || !strings.Contains(err.Error(), "hardlink alias") {
		t.Fatalf("writable source alias reached spawn: %v", err)
	}
}

func TestLiveBoundaryRuntimeTempKeepsOverlappingRootsProtected(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	runtimeTemp := filepath.Join(base, "runtime")
	source := filepath.Join(runtimeTemp, "source")
	credentials := filepath.Join(runtimeTemp, "credentials")
	neutral, namespace := filepath.Join(base, "neutral"), filepath.Join(base, "invocation")
	for _, path := range []string{runtimeTemp, source, credentials, neutral, namespace} {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, path := range []string{source, credentials} {
		if err := os.WriteFile(filepath.Join(path, "value"), []byte("ORIGINAL"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	script := `set -eu
cat "$1/value"
if cat "$2/value"; then exit 21; fi
for path in "$1" "$2"; do
  if printf MUTATION > "$path/value"; then exit 22; fi
  if touch "$path/new"; then exit 23; fi
  if ln "$path/value" "$3/alias"; then exit 24; fi
done
if mv "$3" "$3-moved"; then exit 25; fi
if touch "$5/outside"; then exit 26; fi
printf RUNTIME > "$3/scratch"
printf NAMESPACE > "$4/scratch"
printf 'PROTECTED\n'
`
	request := liveBoundaryTestRequest(t, neutral, source, source, credentials, namespace,
		[]string{"/bin/sh", "-c", script, "fixture", source, credentials, runtimeTemp, namespace, base}, runtimeTemp)
	child, launch, _, err := assembleDirectChild(context.Background(), request, nil, nil)
	if launch != nil {
		defer launch.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	child.Stdout, child.Stderr = nil, nil
	output, err := child.CombinedOutput()
	if err != nil || strings.Count(string(output), "ORIGINAL") != 1 || !strings.Contains(string(output), "PROTECTED") {
		t.Fatalf("runtime boundary: %v, %s", err, output)
	}
	for _, path := range []string{source, credentials} {
		data, err := os.ReadFile(filepath.Join(path, "value"))
		entries, inventoryErr := os.ReadDir(path)
		if err != nil || string(data) != "ORIGINAL" || inventoryErr != nil || len(entries) != 1 {
			t.Fatalf("protected overlap changed: %v, %v, %q", err, inventoryErr, data)
		}
	}
	for path, expected := range map[string]string{runtimeTemp: "RUNTIME", namespace: "NAMESPACE"} {
		data, err := os.ReadFile(filepath.Join(path, "scratch"))
		if err != nil || string(data) != expected {
			t.Fatalf("admitted scratch: %v, %q", err, data)
		}
	}
}

func TestLiveNeutralLaunchRejectsWrongAndReplacedDescriptor(t *testing.T) {
	for _, scenario := range []string{"wrong-directory", "replaced-directory"} {
		t.Run(scenario, func(t *testing.T) {
			base, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			neutral, other := filepath.Join(base, "neutral"), filepath.Join(base, "other")
			for _, path := range []string{neutral, other} {
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			}
			path := other
			if scenario == "replaced-directory" {
				path = neutral
			}
			directory, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer directory.Close()
			packet, _ := ports.NewProviderPacketFromBytes([]byte("neutral fixture"))
			binding, _ := ports.NewProtocolProviderPacketBinding(packet)
			request, err := ports.NewProviderProtocolProcessRequest("/bin/sh", []string{"/bin/sh", "-c", "exit 0"}, nil, neutral, binding, time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			root, _ := ports.NewAnchoredRoot(neutral)
			request, err = ports.NewNeutralBoundProcessRequest(request, root, directory)
			if err != nil {
				t.Fatal(err)
			}
			if scenario == "replaced-directory" {
				if err := os.Rename(neutral, neutral+"-old"); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(neutral, 0700); err != nil {
					t.Fatal(err)
				}
			}
			child, duplicate, _, err := assembleDirectChild(context.Background(), request, nil, nil)
			if err == nil || child != nil || duplicate != nil {
				t.Fatal("invalid neutral directory reached child assembly")
			}
		})
	}
}

func liveBoundaryTestRequest(t *testing.T, neutral, source, gitCommon, credentials, namespace string, argv []string, runtimeTemp ...string) ports.ProcessRequest {
	t.Helper()
	root := func(path string) ports.AnchoredRoot {
		value, err := ports.NewAnchoredRoot(path)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	packet, err := ports.NewProviderPacketFromBytes([]byte("boundary fixture"))
	if err != nil {
		t.Fatal(err)
	}
	binding, err := ports.NewProtocolProviderPacketBinding(packet)
	if err != nil {
		t.Fatal(err)
	}
	environment, err := ports.NewEnvironmentVariable("PATH", "/usr/bin:/bin")
	if err != nil {
		t.Fatal(err)
	}
	request, err := ports.NewProviderProtocolProcessRequest("/bin/sh", argv, []ports.EnvironmentVariable{environment}, neutral, binding, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	boundary, err := ports.NewLiveReadOnlyBoundary([]ports.AnchoredRoot{root(source), root(gitCommon), root(neutral)}, []ports.AnchoredRoot{root(credentials)}, root(namespace))
	if len(runtimeTemp) != 0 {
		boundary, err = ports.NewLiveReadOnlyBoundaryWithRuntimeTemp(boundary.ReadOnlyRoots(), boundary.CredentialRoots(), boundary.WritableRoot(), root(runtimeTemp[0]))
	}
	if err != nil {
		t.Fatal(err)
	}
	request, err = ports.NewLiveReadOnlyProcessRequest(request, boundary)
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func TestLiveBoundaryProtectsMissingOptionalCredentialHomes(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	source, neutral, namespace := filepath.Join(base, "source"), filepath.Join(base, "neutral"), filepath.Join(base, "invocation")
	for _, path := range []string{source, neutral, namespace} {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	credentials := filepath.Join(base, "absent-provider", "credentials")
	request := liveBoundaryTestRequest(t, neutral, source, source, credentials, namespace, []string{"/bin/sh", "-c", "printf MISSING_PROTECTED"})
	child, launch, _, err := assembleDirectChild(context.Background(), request, nil, nil)
	if launch != nil {
		defer launch.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	// Create the optional home after policy assembly. The installed deny rule
	// must apply even though no credential inode existed during admission.
	if err := os.MkdirAll(credentials, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(credentials, "value"), []byte("CREDENTIAL_FIXTURE"), 0600); err != nil {
		t.Fatal(err)
	}
	child.Stdout, child.Stderr = nil, nil
	child.Args[len(child.Args)-1] = "if cat " + strconv.Quote(filepath.Join(credentials, "value")) + "; then exit 21; fi; printf MISSING_PROTECTED"
	output, err := child.CombinedOutput()
	if err != nil || !bytes.Contains(output, []byte("MISSING_PROTECTED")) || bytes.Contains(output, []byte("CREDENTIAL_FIXTURE")) {
		t.Fatalf("missing credential guard: %v, %s", err, output)
	}
	if err := os.Remove(filepath.Join(credentials, "value")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(credentials); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(namespace, credentials); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := assembleDirectChild(context.Background(), request, nil, nil); err == nil {
		t.Fatal("credential symlink admitted")
	}
}

// openSyntheticPTY allocates one fresh terminal pair through the kernel
// master device, mirroring the diagnostic probe: grant, unlock, name, then a
// nonblocking slave open. It is used outside the sandbox and by the sandboxed
// helper child; the slave belongs to whoever allocated the pair.
func openSyntheticPTY() (int, int, string, error) {
	master, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		return -1, -1, "", err
	}
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(master), uintptr(unix.TIOCPTYGRANT), 0); errno != 0 {
		_ = unix.Close(master)
		return -1, -1, "", errno
	}
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(master), uintptr(unix.TIOCPTYUNLK), 0); errno != 0 {
		_ = unix.Close(master)
		return -1, -1, "", errno
	}
	var name [128]byte
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(master), uintptr(unix.TIOCPTYGNAME), uintptr(unsafe.Pointer(&name[0]))); errno != 0 {
		_ = unix.Close(master)
		return -1, -1, "", errno
	}
	end := bytes.IndexByte(name[:], 0)
	if end <= 0 {
		_ = unix.Close(master)
		return -1, -1, "", errors.New("synthetic pty has no slave name")
	}
	path := string(name[:end])
	slave, err := unix.Open(path, unix.O_RDWR|unix.O_NOCTTY|unix.O_NONBLOCK, 0)
	if err != nil {
		_ = unix.Close(master)
		return -1, -1, "", err
	}
	return master, slave, path, nil
}

// readSyntheticPTYUntil polls a nonblocking master descriptor until marker
// appears or the bounded deadline passes.
func readSyntheticPTYUntil(master int, marker []byte) ([]byte, bool) {
	_ = unix.SetNonblock(master, true)
	deadline := time.Now().Add(3 * time.Second)
	var collected []byte
	for time.Now().Before(deadline) {
		chunk := make([]byte, 1024)
		count, err := unix.Read(master, chunk)
		if count > 0 {
			collected = append(collected, chunk[:count]...)
			if bytes.Contains(collected, marker) {
				return collected, true
			}
		}
		if err != nil && err != unix.EAGAIN {
			return collected, false
		}
		time.Sleep(5 * time.Millisecond)
	}
	return collected, false
}

// TestLiveBoundaryPtyChild is the sandboxed helper process for the owned
// terminal capability tests. It only ever touches terminals it allocated
// itself or the explicitly passed synthetic foreign pair.
func TestLiveBoundaryPtyChild(t *testing.T) {
	arguments := helperArguments()
	if len(arguments) < 2 || arguments[0] != "pty" {
		return
	}
	switch arguments[1] {
	case "controlling-alias":
		if _, err := unix.Setsid(); err != nil {
			fmt.Fprintln(os.Stderr, "synthetic session", err)
			os.Exit(67)
		}
		master, slave, _, err := openSyntheticPTY()
		if err != nil {
			fmt.Fprintln(os.Stderr, "synthetic controlling terminal", err)
			os.Exit(68)
		}
		if err := unix.IoctlSetInt(slave, unix.TIOCSCTTY, 0); err != nil {
			fmt.Fprintln(os.Stderr, "assign synthetic controlling terminal", err)
			os.Exit(69)
		}
		if descriptor, err := unix.Open("/dev/tty", unix.O_RDONLY|unix.O_NONBLOCK, 0); err != unix.EPERM {
			if err == nil {
				_ = unix.Close(descriptor)
			}
			fmt.Fprintln(os.Stderr, "controlling terminal alias", err)
			os.Exit(70)
		}
		if _, err := unix.Write(slave, []byte("OWN_TERMINAL_STILL_USABLE\n")); err != nil {
			os.Exit(71)
		}
		if _, ok := readSyntheticPTYUntil(master, []byte("OWN_TERMINAL_STILL_USABLE")); !ok {
			os.Exit(72)
		}
		fmt.Fprintln(os.Stdout, "CONTROLLING_ALIAS_DENIED")
		os.Exit(0)
	case "deny":
		if len(arguments) != 2 {
			os.Exit(2)
		}
		if _, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY, 0); err == nil || err != unix.EPERM {
			fmt.Fprintln(os.Stderr, "ptmx open", err)
			os.Exit(41)
		}
		fmt.Fprintln(os.Stdout, "PTMX_DENIED")
		os.Exit(0)
	case "own":
		if len(arguments) != 5 {
			os.Exit(2)
		}
		master, slave, _, err := openSyntheticPTY()
		if err != nil {
			fmt.Fprintln(os.Stderr, "own pty", err)
			os.Exit(43)
		}
		if _, err := unix.Write(slave, []byte("PTY_OWN_WRITE\n")); err != nil {
			fmt.Fprintln(os.Stderr, "own slave write", err)
			os.Exit(44)
		}
		if _, err := unix.IoctlGetWinsize(slave, unix.TIOCGWINSZ); err != nil {
			fmt.Fprintln(os.Stderr, "own slave ioctl", err)
			os.Exit(45)
		}
		if _, ok := readSyntheticPTYUntil(master, []byte("PTY_OWN_WRITE")); !ok {
			fmt.Fprintln(os.Stderr, "own pty readback missing")
			os.Exit(46)
		}
		// A real read-only Git command runs with the owned slave as its
		// terminal, matching the provider tool pattern the capability exists
		// for.
		terminal := os.NewFile(uintptr(slave), "owned-pty-slave")
		git := exec.Command("/usr/bin/git", "hash-object", "--no-filters", "--", arguments[2])
		git.Stdin, git.Stdout, git.Stderr = terminal, terminal, terminal
		if err := git.Run(); err != nil {
			fmt.Fprintln(os.Stderr, "git", err)
			os.Exit(47)
		}
		// Git's SHA-1 object identity for the fixture's exact ORIGINAL bytes.
		if _, ok := readSyntheticPTYUntil(master, []byte("0ee48e9dd23abe6953a9877eaa1ccf44519a2c8b")); !ok {
			fmt.Fprintln(os.Stderr, "git output missing on owned pty")
			os.Exit(48)
		}
		// The capability must not weaken any neighboring guarantee.
		if _, err := unix.Open(arguments[2], unix.O_WRONLY|unix.O_APPEND, 0); err == nil || err != unix.EPERM {
			fmt.Fprintln(os.Stderr, "source write", err)
			os.Exit(49)
		}
		if _, err := unix.Open(arguments[3], unix.O_WRONLY|unix.O_APPEND, 0); err == nil || err != unix.EPERM {
			fmt.Fprintln(os.Stderr, "git metadata write", err)
			os.Exit(56)
		}
		if _, err := unix.Open(arguments[4], unix.O_RDONLY, 0); err == nil || err != unix.EPERM {
			fmt.Fprintln(os.Stderr, "credential read", err)
			os.Exit(50)
		}
		fmt.Fprintln(os.Stdout, "PTY_OWN_OK")
		os.Exit(0)
	case "foreign":
		if len(arguments) != 3 {
			os.Exit(2)
		}
		var winsize unix.Winsize
		// Darwin mediates terminal mutations such as TIOCSWINSZ through
		// file-ioctl on the explicitly passed synthetic descriptor. Data
		// reads and writes on an already-open descriptor are not revoked by
		// path policy, so this probe makes no inherited data-operation claim;
		// denial is proven through separate path opens below.
		if _, _, errno := unix.Syscall(unix.SYS_IOCTL, 3, uintptr(unix.TIOCSWINSZ), uintptr(unsafe.Pointer(&winsize))); errno == 0 || errno != unix.EPERM {
			fmt.Fprintln(os.Stderr, "foreign slave ioctl", errno)
			os.Exit(51)
		}
		if descriptor, err := unix.Open(arguments[2], unix.O_RDONLY|unix.O_NOCTTY|unix.O_NONBLOCK, 0); err == nil || err != unix.EPERM {
			if err == nil {
				_ = unix.Close(descriptor)
			}
			fmt.Fprintln(os.Stderr, "foreign slave read open", err)
			os.Exit(53)
		}
		if descriptor, err := unix.Open(arguments[2], unix.O_WRONLY|unix.O_NOCTTY|unix.O_NONBLOCK, 0); err == nil || err != unix.EPERM {
			if err == nil {
				_ = unix.Close(descriptor)
			}
			fmt.Fprintln(os.Stderr, "foreign slave write open", err)
			os.Exit(54)
		}
		fmt.Fprintln(os.Stdout, "PTY_FOREIGN_DENIED")
		os.Exit(0)
	}
	os.Exit(2)
}

// liveBoundaryPTYTestRequest mirrors liveBoundaryTestRequest with the owned
// terminal capability applied through its typed constructor.
func liveBoundaryPTYTestRequest(t *testing.T, neutral, source, credentials, namespace string, argv []string, ownedPTY bool) ports.ProcessRequest {
	t.Helper()
	root := func(path string) ports.AnchoredRoot {
		value, err := ports.NewAnchoredRoot(path)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	packet, err := ports.NewProviderPacketFromBytes([]byte("pty boundary fixture"))
	if err != nil {
		t.Fatal(err)
	}
	binding, err := ports.NewProtocolProviderPacketBinding(packet)
	if err != nil {
		t.Fatal(err)
	}
	environment, err := ports.NewEnvironmentVariable("PATH", "/usr/bin:/bin")
	if err != nil {
		t.Fatal(err)
	}
	request, err := ports.NewProviderProtocolProcessRequest("/bin/sh", argv, []ports.EnvironmentVariable{environment}, neutral, binding, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	boundary, err := ports.NewLiveReadOnlyBoundary([]ports.AnchoredRoot{root(source), root(filepath.Join(source, ".git")), root(neutral)}, []ports.AnchoredRoot{root(credentials)}, root(namespace))
	if err != nil {
		t.Fatal(err)
	}
	if ownedPTY {
		boundary, err = ports.NewLiveReadOnlyBoundaryWithOwnedPTY(boundary)
		if err != nil {
			t.Fatal(err)
		}
	}
	request, err = ports.NewLiveReadOnlyProcessRequest(request, boundary)
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func TestLiveBoundaryOwnedPTYCapability(t *testing.T) {
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	source, credentials := filepath.Join(base, "source"), filepath.Join(base, "credentials")
	neutral, namespace := filepath.Join(base, "neutral"), filepath.Join(base, "invocation")
	for _, path := range []string{source, credentials, neutral, namespace} {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	sourceFile := filepath.Join(source, "value")
	gitDirectory := filepath.Join(source, ".git")
	if err := os.Mkdir(gitDirectory, 0700); err != nil {
		t.Fatal(err)
	}
	gitFile := filepath.Join(gitDirectory, "value")
	credentialFile := filepath.Join(credentials, "value")
	if err := os.WriteFile(sourceFile, []byte("ORIGINAL"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(credentialFile, []byte("PRIVATE_PTY_FIXTURE"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(gitFile, []byte("GIT_ORIGINAL"), 0600); err != nil {
		t.Fatal(err)
	}
	runChild := func(t *testing.T, ownedPTY bool, argv []string) string {
		t.Helper()
		request := liveBoundaryPTYTestRequest(t, neutral, source, credentials, namespace, argv, ownedPTY)
		child, launch, _, err := assembleDirectChild(context.Background(), request, nil, nil)
		if launch != nil {
			defer launch.Close()
		}
		if err != nil {
			t.Fatal(err)
		}
		child.Stdout, child.Stderr = nil, nil
		output, err := child.CombinedOutput()
		if err != nil {
			t.Fatalf("pty boundary fixture: %v, %s", err, output)
		}
		return string(output)
	}

	t.Run("default boundary denies the master device", func(t *testing.T) {
		output := runChild(t, false, []string{"/bin/sh", "-c", `exec "$1" -test.run=^TestLiveBoundaryPtyChild$ -- pty deny`, "fixture", binary})
		if !strings.Contains(output, "PTMX_DENIED") {
			t.Fatalf("default boundary output = %q, want master denial", output)
		}
	})

	t.Run("owned capability admits own terminal and read-only git", func(t *testing.T) {
		output := runChild(t, true, []string{"/bin/sh", "-c", `exec "$1" -test.run=^TestLiveBoundaryPtyChild$ -- pty own "$2" "$3" "$4"`, "fixture", binary, sourceFile, gitFile, credentialFile})
		if !strings.Contains(output, "PTY_OWN_OK") {
			t.Fatalf("owned capability output = %q, want own terminal success", output)
		}
		data, err := os.ReadFile(sourceFile)
		if err != nil || string(data) != "ORIGINAL" {
			t.Fatalf("protected source bytes: %v, %q", err, data)
		}
		if data, err = os.ReadFile(credentialFile); err != nil || string(data) != "PRIVATE_PTY_FIXTURE" {
			t.Fatalf("protected credential bytes: %v, %q", err, data)
		}
		if data, err = os.ReadFile(gitFile); err != nil || string(data) != "GIT_ORIGINAL" {
			t.Fatalf("protected Git bytes: %v, %q", err, data)
		}
	})

	t.Run("owned capability denies the controlling terminal alias", func(t *testing.T) {
		request := liveBoundaryPTYTestRequest(t, neutral, source, credentials, namespace,
			[]string{"/bin/sh", "-c", `exec "$1" -test.run=^TestLiveBoundaryPtyChild$ -- pty controlling-alias`, "fixture", binary}, true)
		executable, argv, err := liveBoundaryArgv(context.Background(), request)
		if err != nil {
			t.Fatal(err)
		}
		// This separate child creates its own session and controlling terminal.
		// It never uses the caller's terminal or changes the caller's session.
		child := &exec.Cmd{Path: executable, Args: argv, Dir: neutral, Env: explicitEnvironment(request.Environment())}
		output, err := child.CombinedOutput()
		if err != nil || !strings.Contains(string(output), "CONTROLLING_ALIAS_DENIED") {
			t.Fatalf("controlling terminal alias fixture: %v, %s", err, output)
		}
	})

	t.Run("owned capability denies a foreign synthetic terminal", func(t *testing.T) {
		master, slave, slavePath, err := openSyntheticPTY()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = unix.Close(master) })
		foreignSlave := os.NewFile(uintptr(slave), slavePath)
		t.Cleanup(func() { _ = foreignSlave.Close() })
		// Deliberately bypass assembleDirectChild and its descriptor
		// handling: this raw sandbox-exec invocation of the generated
		// profile keeps the synthetic inherited descriptor, so the policy
		// itself is what denies foreign terminal use. Launch sanitization is
		// proven separately by the guarded bound/unbound launch regressions.
		request := liveBoundaryPTYTestRequest(t, neutral, source, credentials, namespace,
			[]string{"/bin/sh", "-c", `exec "$1" -test.run=^TestLiveBoundaryPtyChild$ -- pty foreign "$2"`, "fixture", binary, slavePath}, true)
		executable, argv, err := liveBoundaryArgv(context.Background(), request)
		if err != nil {
			t.Fatal(err)
		}
		child := &exec.Cmd{
			Path:       executable,
			Args:       argv,
			Dir:        request.WorkingDirectory(),
			Env:        explicitEnvironment(request.Environment()),
			ExtraFiles: []*os.File{foreignSlave},
		}
		output, err := child.CombinedOutput()
		if err != nil {
			t.Fatalf("foreign terminal policy fixture: %v, %s", err, output)
		}
		if !strings.Contains(string(output), "PTY_FOREIGN_DENIED") {
			t.Fatalf("owned capability output = %q, want foreign terminal denial", output)
		}
	})
}

// inheritedCanaryFixture is the canary object a sanitized launch must never
// expose to the provider child.
var inheritedCanaryFixture = []byte("PRIVATE_INHERITANCE_CANARY")

// inheritedCanaryDescriptors holds parent-owned canary descriptors opened
// deliberately without close-on-exec, including one forced far past the
// former sweep caps when the platform's resource limit permits it.
type inheritedCanaryDescriptors struct {
	fd     int
	highFD int
	device uint64
	inode  uint64
}

func openInheritedCanary(t *testing.T, directory string) inheritedCanaryDescriptors {
	t.Helper()
	path := filepath.Join(directory, "inherited-canary")
	if err := os.WriteFile(path, inheritedCanaryFixture, 0600); err != nil {
		t.Fatal(err)
	}
	// Deliberately opened without O_CLOEXEC: this is exactly the ambient
	// descriptor shape a guarded launch must not pass through.
	fd, err := unix.Open(path, unix.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	canary := inheritedCanaryDescriptors{fd: fd, highFD: -1}
	t.Cleanup(func() {
		_ = unix.Close(canary.fd)
		if canary.highFD >= 0 {
			_ = unix.Close(canary.highFD)
		}
	})
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		t.Fatal(err)
	}
	canary.device, canary.inode = uint64(stat.Dev), stat.Ino
	// F_DUPFD clears close-on-exec on the duplicate; never adjust the host
	// resource limit to force a high number.
	if high, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD, 5000); err == nil {
		canary.highFD = high
	} else {
		t.Logf("high-number descriptor unavailable under the current limit (%v); skipping high coverage", err)
	}
	return canary
}

// arguments names the canary objects by descriptor identity so the child
// proves absence through fstat dev+ino, tolerating legitimate fd reuse.
func (canary inheritedCanaryDescriptors) arguments() []string {
	highDevice, highInode := uint64(0), uint64(0)
	if canary.highFD >= 0 {
		highDevice, highInode = canary.device, canary.inode
	}
	return []string{
		strconv.FormatUint(canary.device, 10), strconv.FormatUint(canary.inode, 10),
		strconv.FormatUint(highDevice, 10), strconv.FormatUint(highInode, 10),
	}
}

// assertParentPreserved proves the launch boundary left the caller's own
// descriptor flags and readability untouched.
func (canary inheritedCanaryDescriptors) assertParentPreserved(t *testing.T) {
	t.Helper()
	descriptors := []int{canary.fd}
	if canary.highFD >= 0 {
		descriptors = append(descriptors, canary.highFD)
	}
	for _, fd := range descriptors {
		flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
		if err != nil {
			t.Fatalf("parent canary fd %d flags: %v", fd, err)
		}
		if flags&unix.FD_CLOEXEC != 0 {
			t.Fatalf("parent canary fd %d was marked close-on-exec", fd)
		}
		buffer := make([]byte, len(inheritedCanaryFixture))
		read, err := unix.Pread(fd, buffer, 0)
		if err != nil || read != len(buffer) || !bytes.Equal(buffer, inheritedCanaryFixture) {
			t.Fatalf("parent canary fd %d unreadable: (%d, %v)", fd, read, err)
		}
	}
}

// guardedCanaryLaunchRequest builds one guarded protocol request whose
// provider is the helper scenario proving canary absence by identity.
func guardedCanaryLaunchRequest(t *testing.T, binary, neutral, source, credentials, namespace string, canaryArguments []string) ports.ProcessRequest {
	t.Helper()
	root := func(path string) ports.AnchoredRoot {
		value, err := ports.NewAnchoredRoot(path)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	packet, err := ports.NewProviderPacketFromBytes([]byte("descriptor boundary fixture"))
	if err != nil {
		t.Fatal(err)
	}
	binding, err := ports.NewProtocolProviderPacketBinding(packet)
	if err != nil {
		t.Fatal(err)
	}
	argv := append([]string{binary, "-test.run=^TestRunnerHelperProcess$", "--", "inherited-canary"}, canaryArguments...)
	request, err := ports.NewProviderProtocolProcessRequest(
		binary, argv,
		[]ports.EnvironmentVariable{
			mustEnvironment(t, "MULGAE_PROCESS_RUNNER_HELPER", "1"),
			mustEnvironment(t, "GOCOVERDIR", t.TempDir()),
			mustEnvironment(t, "MULGAE_DESCRIPTOR_ENV", "preserved"),
		},
		neutral, binding, time.Minute,
	)
	if err != nil {
		t.Fatal(err)
	}
	boundary, err := ports.NewLiveReadOnlyBoundary([]ports.AnchoredRoot{root(source), root(neutral)}, []ports.AnchoredRoot{root(credentials)}, root(namespace))
	if err != nil {
		t.Fatal(err)
	}
	request, err = ports.NewLiveReadOnlyProcessRequest(request, boundary)
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func TestGuardedUnboundLaunchSanitizesInheritedDescriptors(t *testing.T) {
	binary := helperBinary(t)
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	neutral, source := filepath.Join(base, "neutral"), filepath.Join(base, "source")
	credentials, namespace := filepath.Join(base, "credentials"), filepath.Join(base, "invocation")
	for _, path := range []string{neutral, source, credentials, namespace} {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	canary := openInheritedCanary(t, base)
	request := guardedCanaryLaunchRequest(t, binary, neutral, source, credentials, namespace, canary.arguments())
	child, launch, _, err := assembleDirectChild(context.Background(), request, nil, nil)
	if launch != nil {
		defer launch.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	child.Stdout, child.Stderr = nil, nil
	output, err := child.CombinedOutput()
	if err != nil {
		t.Fatalf("guarded unbound launch leaked an inherited descriptor: %v, %s", err, output)
	}
	if !strings.Contains(string(output), "CANARY_ABSENT") {
		t.Fatalf("guarded unbound launch output = %q, want canary absence", output)
	}
	canary.assertParentPreserved(t)
}

func TestGuardedBoundLaunchSanitizesInheritedDescriptors(t *testing.T) {
	binary := helperBinary(t)
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	neutral, source := filepath.Join(base, "neutral"), filepath.Join(base, "source")
	credentials, namespace := filepath.Join(base, "credentials"), filepath.Join(base, "invocation")
	for _, path := range []string{neutral, source, credentials, namespace} {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	canary := openInheritedCanary(t, base)
	request := guardedCanaryLaunchRequest(t, binary, neutral, source, credentials, namespace, canary.arguments())
	neutralRoot, err := ports.NewAnchoredRoot(neutral)
	if err != nil {
		t.Fatal(err)
	}
	directory, err := os.Open(neutral)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	request, err = ports.NewNeutralBoundProcessRequest(request, neutralRoot, directory)
	if err != nil {
		t.Fatal(err)
	}
	child, launch, _, err := assembleDirectChild(context.Background(), request, nil, nil)
	if launch != nil {
		defer launch.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	child.Stdout, child.Stderr = nil, nil
	output, err := child.CombinedOutput()
	if err != nil {
		t.Fatalf("guarded bound launch leaked an inherited descriptor: %v, %s", err, output)
	}
	if !strings.Contains(string(output), "CANARY_ABSENT") {
		t.Fatalf("guarded bound launch output = %q, want canary absence", output)
	}
	canary.assertParentPreserved(t)
}

func TestGuardedBoundLaunchDuplicateIsCloseOnExec(t *testing.T) {
	binary := helperBinary(t)
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	neutral, source := filepath.Join(base, "neutral"), filepath.Join(base, "source")
	credentials, namespace := filepath.Join(base, "credentials"), filepath.Join(base, "invocation")
	for _, path := range []string{neutral, source, credentials, namespace} {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	request := guardedCanaryLaunchRequest(t, binary, neutral, source, credentials, namespace,
		[]string{"0", "0", "0", "0"})
	neutralRoot, err := ports.NewAnchoredRoot(neutral)
	if err != nil {
		t.Fatal(err)
	}
	directory, err := os.Open(neutral)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	originalFlags, err := unix.FcntlInt(directory.Fd(), unix.F_GETFD, 0)
	if err != nil {
		t.Fatal(err)
	}
	request, err = ports.NewNeutralBoundProcessRequest(request, neutralRoot, directory)
	if err != nil {
		t.Fatal(err)
	}
	child, launch, _, err := assembleDirectChild(context.Background(), request, nil, nil)
	if err != nil || child == nil {
		t.Fatalf("bound child assembly: %v", err)
	}
	t.Cleanup(func() { _ = launch.Close() })
	duplicateFlags, err := unix.FcntlInt(launch.Fd(), unix.F_GETFD, 0)
	if err != nil {
		t.Fatalf("inspect bound duplicate: %v", err)
	}
	if duplicateFlags&unix.FD_CLOEXEC == 0 {
		t.Fatal("bound launch duplicate is not close-on-exec: a parent-side leak window remains")
	}
	flags, err := unix.FcntlInt(directory.Fd(), unix.F_GETFD, 0)
	if err != nil || flags != originalFlags {
		t.Fatalf("original neutral descriptor flags = (%d, %v), want %d unchanged", flags, err, originalFlags)
	}
	if _, err := directory.Stat(); err != nil {
		t.Fatalf("original neutral descriptor unusable: %v", err)
	}
}
