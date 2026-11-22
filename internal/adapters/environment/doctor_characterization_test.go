//go:build darwin && arm64

package environment

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/ports"
)

func TestProviderVersionObserverGenericNormalizationAndRetiredCursorRejection(t *testing.T) {
	root := canonicalBootstrapTempDir(t)
	path := filepath.Join(root, "retired")
	contents := []byte("#!/bin/sh\nprintf '2026.10.14-0f9edde\\n'\n")
	writeExecutable(t, path, contents)
	identity := ports.ProviderVersionIdentity{ExecutableSHA256: testDigest(contents), LauncherSHA256: testDigest(contents)}
	if _, err := NewProviderVersionObserver().ObserveProviderVersion(context.Background(), "cursor", []string{path, "--version"}, identity); err == nil {
		t.Fatal("retired cursor family was accepted by provider version observer")
	}
	for _, test := range []struct{ output, want string }{
		{"2026.10.14-0f9edde\n", ""},
		{"2026.10.14\n", "2026.10.14"},
		{"grok 1.0.89\n", "1.0.89"},
		{"1.0.89-malformed\n", ""},
	} {
		if got := safeExecutableVersion([]byte(test.output)); got != test.want {
			t.Fatalf("normalization %q = %q, want %q", test.output, got, test.want)
		}
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
