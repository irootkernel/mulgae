//go:build darwin && arm64

package environment

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/ports"
)

func TestProviderVersionObserverCursorCompatibility(t *testing.T) {
	for _, test := range []struct {
		name        string
		output      []byte
		terminal    string
		state       ports.ProviderVersionState
		version     string
		badIdentity bool
		argvExtra   bool
	}{
		{name: "verified", output: []byte("2026.10.14-0f9edde\n"), state: ports.ProviderVersionObserved, version: "2026.10.14-0f9edde"},
		{name: "prefix", output: []byte("Cursor 2026.10.14-0f9edde\n"), state: ports.ProviderVersionObserved, version: "2026.10.14-0f9edde"},
		{name: "same day different hash", output: []byte("2026.10.14-deadbeef"), state: ports.ProviderVersionObserved, version: "2026.10.14-deadbeef"},
		{name: "future", output: []byte("2026.10.15-abc"), state: ports.ProviderVersionObserved, version: "2026.10.15-abc"},
		{name: "below minimum", output: []byte("2026.10.13-abc"), state: ports.ProviderVersionObserved, version: "2026.10.13-abc"},
		{name: "invalid calendar", output: []byte("2026.02.30-abc"), state: ports.ProviderVersionObserved, version: "2026.02.30-abc"},
		{name: "unpadded", output: []byte("2026.1.2-abc"), state: ports.ProviderVersionMalformed},
		{name: "empty hash", output: []byte("2026.10.14-"), state: ports.ProviderVersionMalformed},
		{name: "uppercase hash", output: []byte("2026.10.14-0F9edde"), state: ports.ProviderVersionMalformed},
		{name: "non hex hash", output: []byte("2026.10.14-xyz"), state: ports.ProviderVersionMalformed},
		{name: "ambiguous", output: []byte("2026.10.14-abc 2026.10.15-def"), state: ports.ProviderVersionMalformed},
		{name: "extra version", output: []byte("2026.10.14-abc 1.2.3"), state: ports.ProviderVersionMalformed},
		{name: "embedded prefix", output: []byte("x2026.10.14-abc"), state: ports.ProviderVersionMalformed},
		{name: "embedded suffix", output: []byte("2026.10.14-abcxyz"), state: ports.ProviderVersionMalformed},
		{name: "invalid UTF8", output: []byte{0xff}, state: ports.ProviderVersionMalformed},
		{name: "control", output: []byte("Cursor\x012026.10.14-abc"), state: ports.ProviderVersionMalformed},
		{name: "format control", output: []byte("Cursor\u200b2026.10.14-abc"), state: ports.ProviderVersionMalformed},
		{name: "overflow", output: bytes.Repeat([]byte("x"), maximumVersionOutputBytes+1), state: ports.ProviderVersionMalformed},
		{name: "failure", terminal: "exit 7", state: ports.ProviderVersionExecutionFailed},
		{name: "timeout", terminal: "/bin/sleep 30", state: ports.ProviderVersionTimedOut},
		{name: "replacement", terminal: "printf '\\n# drift\\n' >> SELF\nprintf '2026.10.14-0f9edde'", state: ports.ProviderVersionUnsafeIdentity},
		{name: "failure plus replacement", terminal: "printf '\\n# drift\\n' >> SELF\nexit 7", state: ports.ProviderVersionExecutionFailed},
		{name: "timeout plus replacement", terminal: "printf '\\n# drift\\n' >> SELF\n/bin/sleep 30", state: ports.ProviderVersionTimedOut},
		{name: "unsafe before launch", badIdentity: true, state: ports.ProviderVersionUnsafeIdentity},
		{name: "exact argv", argvExtra: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := canonicalBootstrapTempDir(t)
			t.Setenv("TMPDIR", root)
			path, marker := filepath.Join(root, "cursor"), filepath.Join(root, "launches")
			var encoded strings.Builder
			for _, b := range test.output {
				fmt.Fprintf(&encoded, "\\%03o", b)
			}
			terminal := test.terminal
			if terminal == "" {
				terminal = "printf '" + encoded.String() + "'"
			}
			terminal = strings.ReplaceAll(terminal, "SELF", "'"+path+"'")
			contents := []byte("#!/bin/sh\n[ \"$#\" = 1 ] && [ \"$1\" = --version ] || exit 91\n[ \"$PWD\" = \"$HOME\" ] && [ \"$HOME\" = \"$TMPDIR\" ] || exit 92\n[ -z \"$(/bin/ls -A \"$HOME\")\" ] || exit 93\n[ -z \"${CURSOR_AUTH_TOKEN+x}${OPENAI_API_KEY+x}\" ] || exit 94\nprintf x >> '" + marker + "'\n" + terminal + "\n")
			writeExecutable(t, path, contents)
			identity := ports.ProviderVersionIdentity{ExecutableSHA256: testDigest(contents), LauncherSHA256: testDigest(contents)}
			if test.badIdentity {
				identity.ExecutableSHA256 = "sha256:" + strings.Repeat("0", 64)
			}
			argv := []string{path, "--version"}
			if test.argvExtra {
				argv = []string{path, "extra", "--version"}
			}
			t.Setenv("CURSOR_AUTH_TOKEN", "synthetic-not-for-child")
			t.Setenv("OPENAI_API_KEY", "synthetic-not-for-child")
			got, err := NewProviderVersionObserver().ObserveProviderVersion(context.Background(), "cursor", argv, identity)
			if test.argvExtra {
				if err == nil || err.Error() != "provider version observation: invalid direct argv" {
					t.Fatalf("argv admission: %v", err)
				}
			} else if err != nil || got.State() != test.state || got.Version() != test.version {
				t.Fatalf("Cursor observation=%q/%q err=%v want=%q/%q", got.State(), got.Version(), err, test.state, test.version)
			}
			launches, readErr := os.ReadFile(marker)
			if test.badIdentity || test.argvExtra {
				if !os.IsNotExist(readErr) {
					t.Fatalf("rejected Cursor launched: %q %v", launches, readErr)
				}
			} else if readErr != nil || string(launches) != "x" {
				t.Fatalf("launches=%q err=%v", launches, readErr)
			}
		})
	}
}
