package ports

import (
	"strings"
	"testing"
)

func TestCompositeSupportPathsStayInsideTypedNamespaces(t *testing.T) {
	run := publicationTestRun(t)
	prefix := run.SessionID().String() + "/" + run.RunID().String() + "/"
	for _, test := range []struct {
		path string
		kind RunSupportArtifactKind
	}{
		{"support/composite.json", RunSupportArtifactCompositeMetadata},
		{"support/findings/F001.json", RunSupportArtifactSourceFinding},
		{"support/sources/logic/target/capture-manifest.json", RunSupportArtifactCaptureManifest},
		{"support/sources/documentation/target/captured-review.json", RunSupportArtifactCapturedArchive},
		{"support/sources/security/target/blobs/sha256-" + strings.Repeat("a", 64), RunSupportArtifactCapturedBlob},
		{"support/findings/F001_1.json", ""},
		{"support/findings/F001.md", ""},
		{"support/sources/unknown/target/captured-review.json", ""},
		{"support/sources/logic/target/target.bytes", ""},
		{"support/sources/logic/support/composite.json", ""},
		{"support/sources/logic/target/blobs/sha256-" + strings.Repeat("A", 64), ""},
	} {
		t.Run(test.path, func(t *testing.T) {
			path, err := NewSafeRelativePath(prefix + test.path)
			if err != nil {
				t.Fatal(err)
			}
			kind, err := ClassifyRunSupportArtifactPath(run.SessionID(), run.RunID(), path)
			if test.kind == "" {
				if err == nil {
					t.Fatalf("accepted %q as %q", test.path, kind)
				}
			} else if err != nil || kind != test.kind {
				t.Fatalf("got %q, %v; want %q", kind, err, test.kind)
			}
		})
	}
}
