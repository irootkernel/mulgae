package evidence

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

func TestLiveSupportRejectsMixedAuthorityAndReboundArtifactPaths(t *testing.T) {
	selector, _ := ports.NewLiveSourceSelector(domain.LiveSourceWorkspace, "")
	target, _ := ports.NewLiveSourceTarget(selector, ports.GitObjectID{}, ports.GitObjectID{}, false, nil)
	identity, _ := NewLiveSourceIdentity(target)
	live := LiveSourceMetadata{Identity: json.RawMessage(identity.Bytes()), SourceIdentitySHA256: identity.SHA256(), Changes: []LiveSourceChange{}, NoChange: true, Consistency: "caller_maintained", ReplayAvailability: "unsupported", BinaryEvidence: []LiveBinaryObservation{}}
	session, _ := domain.ParseSessionID("s_018f0d1a-0000-7000-8000-000000000001")
	run, _ := domain.ParseRunID("r_018f0d1a-0000-7000-8000-000000000002")
	prefix := session.String() + "/" + run.String() + "/"
	path, _ := ports.NewSafeRelativePath(prefix + "source/source.json")
	metadata, _ := ports.NewImmutablePublicationArtifact(path, identity.SHA256(), identity.Bytes())
	artifacts := map[string]ports.ImmutablePublicationArtifact{path.String(): metadata}
	if err := VerifyLiveSourceArtifacts(&live, session, run, artifacts); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(map[string]ports.ImmutablePublicationArtifact){
		"missing metadata": func(a map[string]ports.ImmutablePublicationArtifact) { delete(a, path.String()) },
		"invalid artifact": func(a map[string]ports.ImmutablePublicationArtifact) {
			a[path.String()] = ports.ImmutablePublicationArtifact{}
		},
		"rebound path": func(a map[string]ports.ImmutablePublicationArtifact) { a[prefix+"excerpts/F001.md"] = metadata },
		"captured support": func(a map[string]ports.ImmutablePublicationArtifact) {
			p, _ := ports.NewSafeRelativePath(prefix + "target/target.json")
			v, _ := ports.NewImmutablePublicationArtifact(p, fmt.Sprintf("sha256:%x", sha256.Sum256([]byte("retired target"))), []byte("retired target"))
			a[p.String()] = v
		},
	} {
		t.Run(name, func(t *testing.T) {
			bad := map[string]ports.ImmutablePublicationArtifact{path.String(): metadata}
			mutate(bad)
			if err := VerifyLiveSourceArtifacts(&live, session, run, bad); err == nil {
				t.Fatal("accepted invalid live support")
			}
		})
	}
	for name, mutate := range map[string]func(*LiveSourceMetadata){
		"content digest":      func(v *LiveSourceMetadata) { v.SourceIdentitySHA256 = "sha256:" + strings.Repeat("a", 64) },
		"replay claim":        func(v *LiveSourceMetadata) { v.ReplayAvailability = "verified" },
		"immutable workspace": func(v *LiveSourceMetadata) { v.Consistency = "resolved_git_objects" },
		"wrong no-change":     func(v *LiveSourceMetadata) { v.NoChange = false },
		"duplicate selection": func(v *LiveSourceMetadata) {
			v.NoChange = false
			v.Changes = []LiveSourceChange{{Kind: "included", After: "file.go"}, {Kind: "included", After: "file.go"}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			bad := live
			mutate(&bad)
			if _, err := ValidateLiveSourceMetadata(&bad); err == nil {
				t.Fatal("accepted invalid live source claims")
			}
		})
	}
}

func TestLiveSupportRejectsAmbiguousBinaryOrderingAndNoChangeImages(t *testing.T) {
	selector, _ := ports.NewLiveSourceSelector(domain.LiveSourceWorkspace, "")
	selected, _ := ports.NewSafeRelativePath("a.png")
	target, _ := ports.NewLiveSourceTarget(selector, ports.GitObjectID{}, ports.GitObjectID{}, false, []ports.LiveSourceChange{{Kind: "included", After: selected}})
	identity, _ := NewLiveSourceIdentity(target)
	session, _ := domain.ParseSessionID("s_018f0d1a-0000-7000-8000-000000000001")
	run, _ := domain.ParseRunID("r_018f0d1a-0000-7000-8000-000000000002")
	metadataPath, _ := ports.NewSafeRelativePath(session.String() + "/" + run.String() + "/source/source.json")
	metadata, _ := ports.NewImmutablePublicationArtifact(metadataPath, identity.SHA256(), identity.Bytes())
	data := []byte{137, 80, 78, 71, 13, 10, 26, 10, 0}
	file := liveEvidenceFile(t, "a.png", data, "image/png")
	imagePath, _ := SourceImageArtifactPath(session, run, file.SHA256(), file.MediaType())
	image, _ := ports.NewImmutablePublicationArtifact(imagePath, file.SHA256(), data)
	artifacts := map[string]ports.ImmutablePublicationArtifact{metadataPath.String(): metadata, imagePath.String(): image}
	first := LiveBinaryObservation{Side: "worktree", Path: "a.png", SHA256: file.SHA256(), MediaType: file.MediaType(), ByteLength: len(data), ArtifactPath: imagePath.String()}
	second := first
	second.Path = "b.png"
	live := LiveSourceMetadata{Identity: identity.Bytes(), SourceIdentitySHA256: identity.SHA256(), Changes: []LiveSourceChange{{Kind: "included", After: "a.png"}}, Consistency: "caller_maintained", ReplayAvailability: "unsupported", BinaryEvidence: []LiveBinaryObservation{first, second}}
	if err := VerifyLiveSourceArtifacts(&live, session, run, artifacts); err != nil {
		t.Fatalf("ordered observations sharing retained bytes: %v", err)
	}
	for name, mutate := range map[string]func(*LiveSourceMetadata){
		"unsupported media type": func(v *LiveSourceMetadata) {
			v.BinaryEvidence = []LiveBinaryObservation{first}
			v.BinaryEvidence[0].MediaType = "image/gif"
		},
		"reverse order":               func(v *LiveSourceMetadata) { v.BinaryEvidence = []LiveBinaryObservation{second, first} },
		"duplicate side and path":     func(v *LiveSourceMetadata) { v.BinaryEvidence = []LiveBinaryObservation{first, first} },
		"empty selection with images": func(v *LiveSourceMetadata) { v.NoChange = true; v.Changes = []LiveSourceChange{} },
	} {
		t.Run(name, func(t *testing.T) {
			bad := live
			mutate(&bad)
			if err := VerifyLiveSourceArtifacts(&bad, session, run, artifacts); err == nil {
				t.Fatal("invalid binary observation inventory accepted")
			}
		})
	}
}
