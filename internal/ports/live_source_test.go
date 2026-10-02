package ports

import (
	"bytes"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/domain"
)

func TestLiveSourceSelectorRejectsRetiredAndMalformedInputs(t *testing.T) {
	for _, test := range []struct {
		scope domain.LiveSourceScope
		value string
	}{
		{"dirty", ""}, {"patch", "file.patch"}, {"stdin", ""},
		{domain.LiveSourceWorkspace, "HEAD"}, {domain.LiveSourceHead, "HEAD"},
		{domain.LiveSourceCommit, ""}, {domain.LiveSourceCommit, "HEAD\n"},
		{domain.LiveSourceDiff, "HEAD"}, {domain.LiveSourceDiff, "..HEAD"},
		{domain.LiveSourceDiff, "HEAD....HEAD"}, {domain.LiveSourceDiff, "A..B..C"},
	} {
		if _, err := NewLiveSourceSelector(test.scope, test.value); err == nil {
			t.Errorf("accepted %q %q", test.scope, test.value)
		}
	}
	for _, value := range []string{"HEAD~1..HEAD", "topic...main"} {
		selector, err := NewLiveSourceSelector(domain.LiveSourceDiff, value)
		if err != nil || !selector.Valid() {
			t.Fatalf("valid range %q: %v", value, err)
		}
		left, right, operator := selector.RangeOperands()
		if left+operator+right != value {
			t.Fatalf("lost range operator: %q %q %q", left, operator, right)
		}
	}
}

func TestLiveSourceTargetOwnsCandidateMetadataWithoutCaptureIdentity(t *testing.T) {
	selector, _ := NewLiveSourceSelector(domain.LiveSourceStage, "")
	base, _ := ParseGitObjectID(strings.Repeat("a", 40))
	path, _ := NewSafeRelativePath("source.go")
	changes := []LiveSourceChange{{Kind: "modified", Before: path, After: path}}
	target, err := NewLiveSourceTarget(selector, base, GitObjectID{}, false, changes)
	if err != nil {
		t.Fatal(err)
	}
	changes[0].Kind = "deleted"
	returned := target.Changes()
	returned[0].Kind = "added"
	if target.Changes()[0].Kind != "modified" || target.NoChange() || target.Head().Valid() {
		t.Fatal("target metadata was mutable or invented a committed index")
	}
	if _, err := NewLiveSourceTarget(selector, base, GitObjectID{}, true, nil); err == nil {
		t.Fatal("accepted a base together with empty-base identity")
	}
	if _, err := NewLiveSourceTarget(selector, GitObjectID{}, GitObjectID{}, false, nil); err == nil {
		t.Fatal("accepted an absent index base without the unborn marker")
	}
}

func TestLiveSourceFilePreservesBinaryAndOwnsObservedBytes(t *testing.T) {
	path, _ := NewSafeRelativePath("image.png")
	data := []byte("\x89PNG\r\n\x1a\n\x00\xff")
	file, err := NewLiveSourceFile(path, data, "image/png")
	if err != nil {
		t.Fatal(err)
	}
	original := append([]byte(nil), data...)
	data[0] = 'x'
	returned := file.Bytes()
	returned[0] = 'y'
	if !bytes.Equal(file.Bytes(), original) || file.IsText() || file.SHA256() != "sha256:d44c4eee8f72efac76c1f294e7260408825c8dad42adaaf6e9bee7e7ef4c7de3" {
		t.Fatal("binary evidence was decoded, changed, or lacked an observation digest")
	}
	for _, mediaType := range []string{"image/png", "image/jpeg", "image/webp", "text/plain", "unknown"} {
		if _, err := NewLiveSourceFile(path, []byte{0, 0xff}, mediaType); err == nil {
			t.Errorf("accepted malformed %s content", mediaType)
		}
	}
}
