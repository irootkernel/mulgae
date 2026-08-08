//go:build darwin && arm64

package mulgae

import (
	"bytes"
	"testing"
)

func TestVersionOutputDoesNotRequireProjectOrReleaseMetadata(t *testing.T) {
	var stdout, stderr bytes.Buffer
	handled, exitCode := HandleVersion([]string{"--version"}, &stdout, &stderr, "mulgae", "(devel)")
	if !handled || exitCode != 0 || stdout.String() != "mulgae (devel)\n" || stderr.Len() != 0 {
		t.Fatalf("version result = handled:%t exit:%d stdout:%q stderr:%q", handled, exitCode, stdout.String(), stderr.String())
	}

	stdout.Reset()
	handled, exitCode = HandleVersion([]string{"version", "--json"}, &stdout, &stderr, "mulgae", "(devel)")
	if !handled || exitCode != 0 {
		t.Fatalf("JSON version result = handled:%t exit:%d stderr:%q", handled, exitCode, stderr.String())
	}
	if stdout.String() != "{\"name\":\"mulgae\",\"version\":\"(devel)\"}\n" {
		t.Fatalf("JSON version = %q", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	handled, exitCode = HandleVersion([]string{"version", "--output", "json"}, &stdout, &stderr, "mulgae", "(devel)")
	if !handled || exitCode != 2 || stdout.Len() != 0 ||
		stderr.String() != "mulgae: usage: mulgae version [--json]\n" {
		t.Fatalf("legacy JSON version result = handled:%t exit:%d stdout:%q stderr:%q", handled, exitCode, stdout.String(), stderr.String())
	}
}
