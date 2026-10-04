//go:build darwin && arm64

package process

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/ports"
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
	base, err := os.MkdirTemp("/private/tmp", "mulgae-socket-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
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
