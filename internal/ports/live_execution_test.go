package ports

import (
	"fmt"
	"os"
	"testing"
	"time"
)

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
