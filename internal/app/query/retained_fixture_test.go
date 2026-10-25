package query

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/app/prompt"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

// Only the admitted historical fixtures used by these M1 cases are rebound.
// Content hashes (target/capture/excerpt identity) are never substituted. The
// leaf reference's path chooses its bytes, even when two paths share a digest.
func retainedQueryRebind(t *testing.T, entries map[string]*queryRuntimeFixtureEntry, prefix string) {
	t.Helper()
	leaf := regexp.MustCompile(`\{[^{}]*"path":"[^"\\]+"[^{}]*\}`)
	sha := regexp.MustCompile(`"sha256":"[^"]*"`)
	length := regexp.MustCompile(`"byte_length":[0-9]+`)
	complete := regexp.MustCompile(`"complete_stdin_sha256":"[^"]*"`)
	lineage := regexp.MustCompile(`"lineage_edge_path":"([^"]+)","lineage_edge_sha256":"[^"]*"`)
	for pass := 0; pass < 16; pass++ {
		changed := false
		for path, entry := range entries {
			// Do not touch archives, capture manifests, blobs or framed stdin.
			if !(strings.HasSuffix(path, "/manifest.json") || strings.HasSuffix(path, "/target-manifest.json") || strings.HasSuffix(path, "/index.json") || strings.Contains(path, "/epochs/") || strings.Contains(path, "/lineage-edges/") || strings.Contains(path, "/review_") || strings.HasSuffix(path, ".manifest.json")) {
				continue
			}
			updated := leaf.ReplaceAllFunc(entry.bytes, func(object []byte) []byte {
				var ref struct {
					Path string `json:"path"`
				}
				if err := json.Unmarshal(object, &ref); err != nil {
					t.Fatal(err)
				}
				source := entries[ref.Path]
				if source == nil {
					source = entries[prefix+ref.Path]
				}
				if source == nil && strings.Contains(ref.Path, "/publication/staged/review_") {
					finalPath := strings.Replace(ref.Path, "/publication/staged/", "/", 1)
					source = entries[strings.TrimSuffix(finalPath, ".tmp")]
				}
				if source == nil {
					return object
				}
				object = sha.ReplaceAllLiteral(object, []byte(`"sha256":"`+querySHA(source.bytes)+`"`))
				return length.ReplaceAllLiteral(object, []byte(`"byte_length":`+strconv.Itoa(len(source.bytes))))
			})
			updated = lineage.ReplaceAllFunc(updated, func(pair []byte) []byte {
				match := lineage.FindSubmatch(pair)
				if source := entries[string(match[1])]; source != nil {
					return []byte(`"lineage_edge_path":"` + string(match[1]) + `","lineage_edge_sha256":"` + querySHA(source.bytes) + `"`)
				}
				return pair
			})
			if strings.HasSuffix(path, ".manifest.json") && bytes.Contains(updated, []byte(`"complete_stdin_sha256"`)) {
				var wire struct {
					Stdin struct {
						Path string `json:"path"`
					} `json:"stdin"`
				}
				if err := json.Unmarshal(updated, &wire); err != nil {
					t.Fatal(err)
				}
				if stdin := entries[wire.Stdin.Path]; stdin != nil {
					updated = complete.ReplaceAllLiteral(updated, []byte(`"complete_stdin_sha256":"`+prompt.CompleteStdinSHA256(stdin.bytes)+`"`))
				}
			}
			if !bytes.Equal(updated, entry.bytes) {
				entry.bytes = updated
				changed = true
			}
		}
		if !changed {
			return
		}
	}
	t.Fatal("M1 fixture reference edges did not converge")
}

// Preserve the stored epoch from construction onwards. The original generic
// helper is intentionally unchanged for its original epoch-1 callers.
func retainedQuerySnapshot(t *testing.T, run ports.PublicationRun, base ports.CommittedPublicationSnapshot, artifacts map[string]ports.ImmutablePublicationArtifact, entries map[string]*queryRuntimeFixtureEntry, exit domain.OperationalExitCode) (ports.CommittedPublicationSnapshot, ports.PublicationObservation, map[string]ports.ImmutablePublicationArtifact) {
	t.Helper()
	immutable := func(path ports.SafeRelativePath) ports.ImmutablePublicationArtifact {
		entry := entries[path.String()]
		if entry == nil {
			t.Fatalf("M1 artifact absent: %s", path)
		}
		value, err := ports.NewImmutablePublicationArtifact(path, querySHA(entry.bytes), entry.bytes)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	finalBytes := entries[base.Final().Identity().Path().String()].bytes
	id, err := ports.NewFinalReviewIdentity(base.Final().Identity().ReviewID(), base.Final().Identity().Path(), querySHA(finalBytes))
	if err != nil {
		t.Fatal(err)
	}
	final, err := ports.NewFinalReviewArtifact(id, finalBytes)
	if err != nil {
		t.Fatal(err)
	}
	epoch, err := ports.NewPublicationEpoch(base.Epoch().Value(), immutable(base.Epoch().Record().Path()))
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := ports.NewCommittedPublicationSnapshot(final, immutable(base.Manifest().Path()), immutable(base.LineageEdge().Path()), epoch)
	if err != nil {
		t.Fatal(err)
	}
	updated := make(map[string]ports.ImmutablePublicationArtifact, len(artifacts))
	for path, artifact := range artifacts {
		updated[path] = immutable(artifact.Path())
	}
	// New prompt-inventory entries are explicit fixture additions.
	for path, entry := range entries {
		if !strings.Contains(path, "/prompts/") {
			continue
		}
		safe, err := ports.NewSafeRelativePath(path)
		if err != nil {
			t.Fatal(err)
		}
		updated[path], err = ports.NewImmutablePublicationArtifact(safe, querySHA(entry.bytes), entry.bytes)
		if err != nil {
			t.Fatal(err)
		}
	}
	return snapshot, queryP2Observation(t, run, snapshot, domain.JournalCompleted, exit, epoch.Value()), updated
}
