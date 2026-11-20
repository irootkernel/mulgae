package ports

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func mustLiveExecRoot(t *testing.T, path string) AnchoredRoot {
	t.Helper()
	r, err := NewAnchoredRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestNeutralBoundProcessRequestRejectsInvalidAuthority(t *testing.T) {
	root, err := NewAnchoredRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	directory, err := os.Open(root.String())
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	closed, err := os.Open(root.String())
	if err != nil {
		t.Fatal(err)
	}
	if err := closed.Close(); err != nil {
		t.Fatal(err)
	}
	packet, err := NewProviderPacketFromBytes([]byte("fixture packet"))
	if err != nil {
		t.Fatal(err)
	}
	binding, err := NewProtocolProviderPacketBinding(packet)
	if err != nil {
		t.Fatal(err)
	}
	request, err := NewProviderProtocolProcessRequest("/provider", []string{"/provider"}, nil, root.String(), binding, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	bound, err := NewNeutralBoundProcessRequest(request, root, directory)
	if err != nil || !bound.Valid() {
		t.Fatal("valid neutral authority rejected", err)
	}
	if actual, actualRoot, present := bound.LaunchDirectory(); !present || actual != directory || actualRoot != root {
		t.Fatal("neutral launch authority changed")
	}
	wrongRoot, _ := NewAnchoredRoot(root.String() + "-other")
	for _, test := range []struct {
		name      string
		request   ProcessRequest
		root      AnchoredRoot
		directory *os.File
	}{
		{"nil descriptor", request, root, nil},
		{"closed descriptor", request, root, closed},
		{"different cwd", request, wrongRoot, directory},
		{"already bound", bound, root, directory},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewNeutralBoundProcessRequest(test.request, test.root, test.directory); err == nil {
				t.Fatal("invalid neutral authority accepted")
			}
		})
	}
	if _, _, present := request.LaunchDirectory(); present {
		t.Fatal("constructor mutated the original request")
	}
}

func TestLivePolicyRootsRejectUnrepresentablePaths(t *testing.T) {
	root, _ := NewAnchoredRoot("/root")
	for _, suffix := range []string{"\a", "\t", "\n", "\u2028", "\u2029", "\x7f", string([]byte{0xff})} {
		t.Run(fmt.Sprintf("%q", suffix), func(t *testing.T) {
			unsafe, err := NewAnchoredRoot("/root" + suffix)
			if err != nil {
				t.Fatal(err)
			}
			for _, role := range []string{"source", "credential", "writable", "runtime"} {
				readOnly, credentials, writable := []AnchoredRoot{root}, []AnchoredRoot{root}, root
				switch role {
				case "source":
					readOnly[0] = unsafe
				case "credential":
					credentials[0] = unsafe
				case "writable":
					writable = unsafe
				}
				if role == "runtime" {
					_, err = NewLiveReadOnlyBoundaryWithRuntimeTemp(readOnly, credentials, writable, unsafe)
				} else {
					_, err = NewLiveReadOnlyBoundary(readOnly, credentials, writable)
				}
				if err == nil {
					t.Fatalf("unrepresentable %s policy root admitted", role)
				}
			}
		})
	}
}

func TestLiveReadOnlyBoundaryPreservesProviderIdentityAndCopiesRoots(t *testing.T) {
	source, _ := NewAnchoredRoot("/source")
	credential, _ := NewAnchoredRoot("/credentials")
	writable, _ := NewAnchoredRoot("/invocation")
	readOnly := []AnchoredRoot{source}
	credentials := []AnchoredRoot{credential}
	boundary, err := NewLiveReadOnlyBoundary(readOnly, credentials, writable)
	if err != nil {
		t.Fatal(err)
	}
	readOnly[0], credentials[0] = AnchoredRoot{}, AnchoredRoot{}
	boundary.ReadOnlyRoots()[0] = AnchoredRoot{}
	boundary.CredentialRoots()[0] = AnchoredRoot{}
	packet, err := NewProviderPacketFromBytes([]byte("exact provider packet"))
	if err != nil {
		t.Fatal(err)
	}
	binding, err := NewProtocolProviderPacketBinding(packet)
	if err != nil {
		t.Fatal(err)
	}
	request, err := NewProviderProtocolProcessRequest("/provider", []string{"/provider", "--native"}, nil, "/neutral", binding, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	guarded, err := NewLiveReadOnlyProcessRequest(request, boundary)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := guarded.LiveReadOnlyBoundary()
	if !ok || !guarded.Valid() || got.ReadOnlyRoots()[0] != source || got.CredentialRoots()[0] != credential || got.WritableRoot() != writable {
		t.Fatal("boundary roots were lost or mutated")
	}
	actual, ok := guarded.ProviderPacketBinding()
	if !ok || actual.Packet().Identity() != packet.Identity() || guarded.Executable() != request.Executable() || guarded.Argv()[1] != "--native" || guarded.WorkingDirectory() != "/neutral" {
		t.Fatal("guard changed native invocation identity")
	}
	if _, err := NewLiveReadOnlyProcessRequest(guarded, boundary); err == nil {
		t.Fatal("duplicate guard accepted")
	}
	if _, present := request.LiveReadOnlyBoundary(); present {
		t.Fatal("original request mutated")
	}
}

func TestLiveReadOnlyBoundaryRejectsInvalidAuthority(t *testing.T) {
	root, _ := NewAnchoredRoot("/root")
	filesystem, _ := NewAnchoredRoot("/")
	for _, test := range []struct {
		name                  string
		readOnly, credentials []AnchoredRoot
		writable              AnchoredRoot
	}{
		{"missing source", nil, []AnchoredRoot{root}, root},
		{"missing credentials", []AnchoredRoot{root}, nil, root},
		{"invalid source", []AnchoredRoot{{}}, []AnchoredRoot{root}, root},
		{"filesystem source", []AnchoredRoot{filesystem}, []AnchoredRoot{root}, root},
		{"invalid credentials", []AnchoredRoot{root}, []AnchoredRoot{{}}, root},
		{"filesystem credentials", []AnchoredRoot{root}, []AnchoredRoot{filesystem}, root},
		{"missing namespace", []AnchoredRoot{root}, []AnchoredRoot{root}, AnchoredRoot{}},
		{"filesystem namespace", []AnchoredRoot{root}, []AnchoredRoot{root}, filesystem},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewLiveReadOnlyBoundary(test.readOnly, test.credentials, test.writable); err == nil {
				t.Fatal("invalid authority accepted")
			}
		})
	}
	boundary, err := NewLiveReadOnlyBoundary([]AnchoredRoot{root}, []AnchoredRoot{root}, root)
	if err != nil {
		t.Fatal(err)
	}
	request, err := NewProcessRequest("/provider", []string{"/provider"}, nil, "/neutral", nil, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewLiveReadOnlyProcessRequest(request, boundary); err == nil {
		t.Fatal("non-protocol process accepted")
	}
}

func TestLiveReadOnlyBoundaryRuntimeRootPreservesProtectedAuthority(t *testing.T) {
	source, _ := NewAnchoredRoot("/source")
	credential, _ := NewAnchoredRoot("/credentials")
	writable, _ := NewAnchoredRoot("/invocation")
	runtimeTemp, _ := NewAnchoredRoot("/runtime")
	boundary, err := NewLiveReadOnlyBoundaryWithRuntimeTemp([]AnchoredRoot{source}, []AnchoredRoot{credential}, writable, runtimeTemp)
	if err != nil || !boundary.Valid() {
		t.Fatal(err)
	}
	if root, present := boundary.RuntimeTempRoot(); !present || root != runtimeTemp || boundary.WritableRoot() != writable || boundary.ReadOnlyRoots()[0] != source || boundary.CredentialRoots()[0] != credential {
		t.Fatal("runtime root changed protected or invocation authority")
	}
	filesystem, _ := NewAnchoredRoot("/")
	for _, invalid := range []AnchoredRoot{{}, filesystem} {
		if _, err := NewLiveReadOnlyBoundaryWithRuntimeTemp([]AnchoredRoot{source}, []AnchoredRoot{credential}, writable, invalid); err == nil {
			t.Fatal("invalid runtime root admitted")
		}
	}
}

func TestLiveReadOnlyBoundaryOwnedPTYCapabilityComposesWithExistingAuthority(t *testing.T) {
	source, _ := NewAnchoredRoot("/source")
	credential, _ := NewAnchoredRoot("/credentials")
	writable, _ := NewAnchoredRoot("/invocation")
	runtimeTemp, _ := NewAnchoredRoot("/runtime")

	boundary, err := NewLiveReadOnlyBoundary([]AnchoredRoot{source}, []AnchoredRoot{credential}, writable)
	if err != nil {
		t.Fatal(err)
	}
	if boundary.OwnedPTY() {
		t.Fatal("default boundary claims the owned-terminal capability")
	}
	owned, err := NewLiveReadOnlyBoundaryWithOwnedPTY(boundary)
	if err != nil || !owned.Valid() || !owned.OwnedPTY() {
		t.Fatalf("owned boundary = (%t, %v), want valid and capable", owned.OwnedPTY(), err)
	}
	if owned.WritableRoot() != writable || owned.ReadOnlyRoots()[0] != source || owned.CredentialRoots()[0] != credential {
		t.Fatal("capability changed protected or invocation authority")
	}
	if _, present := owned.RuntimeTempRoot(); present {
		t.Fatal("capability invented a runtime root")
	}
	if boundary.OwnedPTY() {
		t.Fatal("capability constructor mutated the original boundary")
	}

	withRuntime, err := NewLiveReadOnlyBoundaryWithRuntimeTemp([]AnchoredRoot{source}, []AnchoredRoot{credential}, writable, runtimeTemp)
	if err != nil {
		t.Fatal(err)
	}
	ownedWithRuntime, err := NewLiveReadOnlyBoundaryWithOwnedPTY(withRuntime)
	if err != nil || !ownedWithRuntime.OwnedPTY() {
		t.Fatalf("runtime-owning boundary = (%t, %v), want capable", ownedWithRuntime.OwnedPTY(), err)
	}
	if root, present := ownedWithRuntime.RuntimeTempRoot(); !present || root != runtimeTemp {
		t.Fatal("capability dropped the composed runtime root")
	}

	if _, err := NewLiveReadOnlyBoundaryWithOwnedPTY(LiveReadOnlyBoundary{}); err == nil {
		t.Fatal("invalid boundary admitted for the owned-terminal capability")
	}
}

func TestLiveReadOnlyBoundaryControlPlanePaneTTYAndBashGate(t *testing.T) {
	source, _ := NewAnchoredRoot("/source")
	credential, _ := NewAnchoredRoot("/credentials")
	writable, _ := NewAnchoredRoot("/invocation")
	nativeHome, _ := NewAnchoredRoot("/Users/alice")

	base, err := NewLiveReadOnlyBoundary([]AnchoredRoot{source}, []AnchoredRoot{credential}, writable)
	if err != nil {
		t.Fatal(err)
	}
	if base.PaneTTY() || base.BashGate() || len(base.ControlPlaneRoots()) != 0 || len(base.ControlPlaneLiterals()) != 0 ||
		len(base.TerminalSecretRoots()) != 0 || len(base.TerminalDeniedLiterals()) != 0 {
		t.Fatal("default boundary unexpectedly populated terminal/control-plane fields")
	}

	// Default control-plane roots.
	sessionRoot, _ := NewAnchoredRoot("/private/tmp/mgh-501/0123456789abcdef")
	cpRoots, err := DefaultControlPlaneRoots(nativeHome, 501, sessionRoot)
	if err != nil {
		t.Fatalf("DefaultControlPlaneRoots: %v", err)
	}
	wantCP := []string{
		"/private/tmp/mgh-501",
		"/Users/alice/.local/state/herdr-core",
		"/Users/alice/.config/herdr-core",
		"/private/tmp/mgh-501/0123456789abcdef",
	}
	if len(cpRoots) != len(wantCP) {
		t.Fatalf("cpRoots = %v, want %v", cpRoots, wantCP)
	}
	for i, want := range wantCP {
		if cpRoots[i].String() != want {
			t.Fatalf("cpRoots[%d] = %q, want %q", i, cpRoots[i].String(), want)
		}
	}

	// ControlPlanePathsForSocket fails closed when nativeHome is invalid.
	if _, _, err := ControlPlanePathsForSocket("/private/tmp/my-hc/s.sock", AnchoredRoot{}); err == nil {
		t.Fatal("ControlPlanePathsForSocket accepted zero nativeHome")
	}
	fsRoot, _ := NewAnchoredRoot("/")
	if _, _, err := ControlPlanePathsForSocket("/private/tmp/my-hc/s.sock", fsRoot); err == nil {
		t.Fatal("ControlPlanePathsForSocket accepted / as nativeHome")
	}

	// ControlPlanePathsForSocket distinguishes shared parents from dedicated parents.
	for _, sharedSock := range []string{
		"/private/tmp/custom.sock",
		"/Users/alice/hc.sock",
		"/Users/alice/.local/share/hc.sock",
		"/Users/alice/.cache/hc.sock",
		"/private/var/folders/aa/hc.sock",
		"/private/var/folders/aa/bb/hc.sock",
		"/private/var/folders/aa/bb/T/hc.sock",
		"/private/var/folders/aa/bb/C/hc.sock",
		"/private/var/folders/aa/bb/0/hc.sock",
		"/usr/local/hc.sock",
		"/opt/homebrew/hc.sock",
		"/private/etc/hc.sock",
	} {
		roots, lits, err := ControlPlanePathsForSocket(sharedSock, nativeHome)
		if err != nil || len(roots) != 0 || len(lits) != 1 || lits[0].String() != sharedSock {
			t.Fatalf("shared parent socket %q = (%v, %v, %v), want literal only", sharedSock, roots, lits, err)
		}
	}
	sharedLits := []AnchoredRoot{mustLiveExecRoot(t, "/private/tmp/custom.sock")}
	for _, dedSock := range []string{
		"/private/tmp/my-hc-dir/s.sock",
		"/private/var/folders/aa/bb/T/mulgae-hc-1/s.sock",
		"/Users/alice/.local/state/herdr-core/s.sock",
	} {
		dedRoots, dedLits, err := ControlPlanePathsForSocket(dedSock, nativeHome)
		if err != nil || len(dedRoots) != 1 || dedRoots[0].String() != filepath.Dir(dedSock) || len(dedLits) != 1 {
			t.Fatalf("dedicated parent socket %q = (%v, %v, %v)", dedSock, dedRoots, dedLits, err)
		}
	}

	// WithProcessRequestControlPlane layers control-plane roots/literals without mutating the original request.
	packet, _ := NewProviderPacketFromBytes([]byte("overlay packet"))
	binding, _ := NewProtocolProviderPacketBinding(packet)
	protoReq, err := NewProviderProtocolProcessRequest("/provider", []string{"/provider"}, nil, "/neutral", binding, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := WithProcessRequestControlPlane(protoReq, cpRoots, sharedLits); err == nil {
		t.Fatal("WithProcessRequestControlPlane accepted unguarded request")
	}
	guardedProto, err := NewLiveReadOnlyProcessRequest(protoReq, base)
	if err != nil {
		t.Fatal(err)
	}
	overlaid, err := WithProcessRequestControlPlane(guardedProto, cpRoots, sharedLits)
	if err != nil {
		t.Fatalf("WithProcessRequestControlPlane: %v", err)
	}
	origB, _ := guardedProto.LiveReadOnlyBoundary()
	overB, _ := overlaid.LiveReadOnlyBoundary()
	if len(origB.ControlPlaneRoots()) != 0 || len(overB.ControlPlaneRoots()) != len(cpRoots) || len(overB.ControlPlaneLiterals()) != 1 {
		t.Fatalf("WithProcessRequestControlPlane overlay failed: orig=%v overlaid=%v", origB.ControlPlaneRoots(), overB.ControlPlaneRoots())
	}

	withCP, err := NewLiveReadOnlyBoundaryWithControlPlane(base, cpRoots, sharedLits)
	if err != nil || !withCP.Valid() {
		t.Fatalf("NewLiveReadOnlyBoundaryWithControlPlane: %v", err)
	}
	if len(base.ControlPlaneRoots()) != 0 {
		t.Fatal("control-plane constructor mutated original boundary")
	}

	// BashGate requires PaneTTY.
	if _, err := NewLiveReadOnlyBoundaryWithBashGate(withCP); err == nil {
		t.Fatal("BashGate accepted non-PaneTTY boundary")
	}

	withPaneTTY, err := NewLiveReadOnlyBoundaryWithPaneTTY(withCP, nativeHome)
	if err != nil || !withPaneTTY.Valid() || !withPaneTTY.PaneTTY() {
		t.Fatalf("NewLiveReadOnlyBoundaryWithPaneTTY: %v", err)
	}
	if len(withPaneTTY.TerminalSecretRoots()) != 14 {
		t.Fatalf("TerminalSecretRoots count = %d, want 14: %v", len(withPaneTTY.TerminalSecretRoots()), withPaneTTY.TerminalSecretRoots())
	}
	if len(withPaneTTY.TerminalDeniedLiterals()) != 3 {
		t.Fatalf("TerminalDeniedLiterals count = %d, want 3: %v", len(withPaneTTY.TerminalDeniedLiterals()), withPaneTTY.TerminalDeniedLiterals())
	}

	// PaneTTY composes cleanly with OwnedPTY in both orders.
	composedA, err := NewLiveReadOnlyBoundaryWithOwnedPTY(withPaneTTY)
	if err != nil || !composedA.OwnedPTY() || !composedA.PaneTTY() || len(composedA.ControlPlaneRoots()) != len(cpRoots) {
		t.Fatalf("OwnedPTY(PaneTTY) failed: %v", err)
	}
	ownedFirst, err := NewLiveReadOnlyBoundaryWithOwnedPTY(withCP)
	if err != nil {
		t.Fatal(err)
	}
	composedB, err := NewLiveReadOnlyBoundaryWithPaneTTY(ownedFirst, nativeHome)
	if err != nil || !composedB.OwnedPTY() || !composedB.PaneTTY() {
		t.Fatalf("PaneTTY(OwnedPTY) failed: %v", err)
	}

	// BashGate default and custom allowed sockets.
	withGate, err := NewLiveReadOnlyBoundaryWithBashGate(withPaneTTY)
	if err != nil || !withGate.Valid() || !withGate.BashGate() {
		t.Fatalf("NewLiveReadOnlyBoundaryWithBashGate: %v", err)
	}
	allowed := withGate.BashGateAllowedUnixSockets()
	if len(allowed) != 1 || allowed[0].String() != "/private/var/run/mDNSResponder" {
		t.Fatalf("default BashGateAllowedUnixSockets = %v", allowed)
	}
	if withPaneTTY.BashGate() {
		t.Fatal("BashGate constructor mutated original boundary")
	}
	customSock, _ := NewAnchoredRoot("/private/var/run/custom.sock")
	withCustomGate, err := NewLiveReadOnlyBoundaryWithBashGate(withPaneTTY, customSock)
	if err != nil || len(withCustomGate.BashGateAllowedUnixSockets()) != 1 || withCustomGate.BashGateAllowedUnixSockets()[0] != customSock {
		t.Fatalf("custom BashGate = (%v, %v)", withCustomGate.BashGateAllowedUnixSockets(), err)
	}
}
