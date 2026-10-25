//go:build darwin && arm64

package environment

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/app/reviewrun"
	"github.com/irootkernel/mulgae/internal/ports"
)

func TestProviderVersionObserverCursorTupleAndGenericNormalization(t *testing.T) {
	root := canonicalBootstrapTempDir(t)
	marker := filepath.Join(root, "launches")
	path := filepath.Join(root, "cursor")
	contents := []byte("#!/bin/sh\n[ \"$#\" = 1 ] && [ \"$1\" = --version ] || exit 91\nprintf x >> '" + marker + "'\nprintf '2026.10.14-0f9edde\\n'\n")
	writeExecutable(t, path, contents)
	identity := ports.ProviderVersionIdentity{ExecutableSHA256: testDigest(contents), LauncherSHA256: testDigest(contents)}
	// A real descriptor observation establishes that the Cursor fixture is safe.
	admitted, err := NewInspector().ObserveExecutableIdentity(context.Background(), path)
	if err != nil || !admitted.Found() || admitted.SHA256() != identity.ExecutableSHA256 {
		t.Fatalf("safe Cursor fixture: %+v %v", admitted, err)
	}
	observation, err := NewProviderVersionObserver().ObserveProviderVersion(context.Background(), "cursor", []string{path, "--version"}, identity)
	// M_test=1: the approved Q3 correction admits the complete tuple. The
	// historical public result stays frozen in task063-doctor-before.json.
	if err != nil || observation.State() != ports.ProviderVersionObserved || observation.Version() != "2026.10.14-0f9edde" {
		t.Fatalf("Cursor compatibility: %q/%q, %v", observation.State(), observation.Version(), err)
	}
	launches, err := os.ReadFile(marker)
	if err != nil || string(launches) != "x" {
		t.Fatalf("Cursor launches=%q err=%v", launches, err)
	}
	for _, test := range []struct{ output, want string }{
		{"2026.10.14-0f9edde\n", ""},
		{"Cursor 2026.10.14-0f9edde\n", ""},
		{"2026.10.14\n", "2026.10.14"},
		{"grok 1.0.40\n", "1.0.40"},
		{"1.0.40-malformed\n", ""},
	} {
		if got := safeExecutableVersion([]byte(test.output)); got != test.want {
			t.Fatalf("predecessor normalization %q = %q, want %q", test.output, got, test.want)
		}
	}
	if reviewrun.ClassifyVersion(reviewrun.FamilyCursor, "2026.10.14-0f9edde") != reviewrun.VersionGreen {
		t.Fatal("the established application policy must accept the complete tuple")
	}
}

func TestProviderVersionObserverFailureDriftPrecedence(t *testing.T) {
	for _, test := range []struct {
		name, terminal string
		want           ports.ProviderVersionState
	}{
		{"success", "printf 'grok 1.0.40\\n'", ports.ProviderVersionUnsafeIdentity},
		{"failure", "exit 7", ports.ProviderVersionExecutionFailed},
		{"timeout", "sleep 30", ports.ProviderVersionTimedOut},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := canonicalBootstrapTempDir(t)
			path, marker := filepath.Join(root, "grok"), filepath.Join(root, "launches")
			contents := []byte("#!/bin/sh\n[ \"$#\" = 1 ] && [ \"$1\" = --version ] || exit 91\nprintf x >> '" + marker + "'\nprintf '\\n# drift\\n' >> '" + path + "'\n" + test.terminal + "\n")
			writeExecutable(t, path, contents)
			identity := ports.ProviderVersionIdentity{ExecutableSHA256: testDigest(contents), LauncherSHA256: testDigest(contents)}
			observation, err := NewProviderVersionObserver().ObserveProviderVersion(context.Background(), "grok", []string{path, "--version"}, identity)
			if err != nil || observation.State() != test.want || observation.Version() != "" {
				t.Fatalf("%s with drift: %q/%q %v", test.name, observation.State(), observation.Version(), err)
			}
			launches, err := os.ReadFile(marker)
			if err != nil || string(launches) != "x" {
				t.Fatalf("expected exactly one version process: %q %v", launches, err)
			}
			current, err := os.ReadFile(path)
			if err != nil || testDigest(current) == identity.ExecutableSHA256 || !strings.HasSuffix(string(current), "# drift\n") {
				t.Fatalf("drift did not occur: %v", err)
			}
		})
	}
}
