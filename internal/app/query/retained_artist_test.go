package query

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/artifactwire"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
	"github.com/irootkernel/mulgae/internal/testsupport/historical"
)

// Match the filesystem port's exact-read cap; queryStore alone ignores it.
type retainedArtistStore struct {
	*queryStore
	capRefusals int
}

func (store *retainedArtistStore) ReadAuxiliaryArtifact(ctx context.Context, request ports.ReadAuxiliaryArtifactRequest) (ports.ImmutablePublicationArtifact, error) {
	artifact, err := store.queryStore.ReadAuxiliaryArtifact(ctx, request)
	if err == nil && int64(len(artifact.Bytes())) > request.MaxReadBytes() {
		store.capRefusals++
		return ports.ImmutablePublicationArtifact{}, fmt.Errorf("artifact exceeds configured exact-read cap")
	}
	return artifact, err
}

func TestRuntimeTargetRetainsArtistPresenceAndConfiguredLargeBriefBytes(t *testing.T) {
	corpus, err := historical.Load()
	if err != nil {
		t.Fatal(err)
	}
	validator := mustSharedQueryTestValidator(t)
	for _, c := range corpus.Cases {
		if c.ID != "artist" {
			continue
		}
		for _, mode := range []string{"ready", "code_only", "missing", "large brief"} {
			t.Run(mode, func(t *testing.T) {
				store, run := historicalQueryStore(t, c)
				snapshot := store.snapshotsByRun[c.RunID]
				base := store.auxiliaryArtifacts
				identity := func(s string) string { return s }
				entries := queryRuntimeFixtureEntries(t, snapshot, base, identity, func(b []byte) []byte { return bytes.Clone(b) })
				prefix := c.SessionID + "/" + c.RunID + "/"
				path := prefix + "target/target-manifest.json"
				var target artifactwire.RuntimeTargetManifest
				if err := json.Unmarshal(entries[path].bytes, &target); err != nil {
					t.Fatal(err)
				}
				wantBrief := c.Artifacts()[target.ArtistBrief.Path]
				wantVisual := c.Artifacts()[target.ArtistVisualAssets.Path]
				switch mode {
				case "code_only":
					target.ArtistVisualAssets = nil
					wantVisual = nil
				case "missing":
					target.ArtistBrief = nil
					wantBrief = nil
				case "large brief":
					wantBrief = bytes.Repeat([]byte("Retain source-sized artist input.\n"), 400000)
					entries[target.ArtistBrief.Path].bytes = wantBrief
				}
				raw, err := json.Marshal(target)
				if err != nil {
					t.Fatal(err)
				}
				entries[path].bytes = raw
				// Rebind actual artifact, support-index, manifest and epoch hashes.
				// Former ready/code_only/missing derivation is a retired writer
				// property; the retained reader consumes explicit stored presence.
				retainedQueryRebind(t, entries, c.SessionID+"/"+c.RunID+"/")
				// The brief aliases a frozen blob by digest, but not by path.
				// Keep the archive and every capture member byte-identical.
				shared := 0
				for member, original := range base {
					if strings.Contains(member, "/target/") {
						if !bytes.Equal(entries[member].bytes, original.Bytes()) && member != path {
							t.Fatalf("unrelated capture member changed: %s", member)
						}
						if mode == "large brief" && target.ArtistBrief != nil && original.SHA256() == base[target.ArtistBrief.Path].SHA256() && member != target.ArtistBrief.Path {
							shared++
						}
					}
				}
				if mode == "large brief" && shared == 0 {
					t.Fatal("shared-digest/different-path control was not exercised")
				}
				updated, observation, artifacts := retainedQuerySnapshot(t, run, snapshot, base, entries, domain.OperationalExitCode(c.Expected.Exit))
				store.snapshotsByRun[c.RunID] = updated
				store.observationsByRun[c.RunID] = observation
				store.auxiliaryArtifacts = artifacts
				faithful := &retainedArtistStore{queryStore: store}
				// The service port accepts an explicit positive read bound. This
				// large-content case uses 32 MiB, not the default 8 MiB reader.
				service, err := NewService(faithful, validator, nil, 32<<20)
				if err != nil {
					t.Fatal(err)
				}
				if mode == "large brief" {
					limited, err := NewService(faithful, validator, nil, 8<<20)
					if err != nil {
						t.Fatal(err)
					}
					if _, err := limited.ReadRuntimeTarget(context.Background(), run); err == nil || faithful.capRefusals != 1 {
						t.Fatal("8 MiB exact-read boundary was ignored")
					}
				}
				got, err := service.ReadRuntimeTarget(context.Background(), run)
				if err != nil {
					t.Fatal(err)
				}
				if querySHA(got.CapturedArchive()) != c.Expected.ArchiveSHA256 {
					t.Fatal("unchanged capture reconstruction differs from frozen expected bytes")
				}
				if mode == "large brief" {
					found := false
					for _, request := range store.auxiliaryRequests {
						if request.Path().String() == target.ArtistBrief.Path && request.MaxReadBytes() == 32<<20 {
							found = true
						}
					}
					if !found || faithful.capRefusals != 1 {
						t.Fatal("large brief did not cross the configured 32 MiB read boundary")
					}
				}
				brief, hasBrief := got.ArtistBrief()
				visual, hasVisual := got.ArtistVisualAssets()
				if hasBrief != (mode != "missing") || hasVisual != (mode != "code_only") || !bytes.Equal(brief, wantBrief) || !bytes.Equal(visual, wantVisual) {
					t.Fatal("stored artist presence or exact bytes changed")
				}
			})
		}
		return
	}
	t.Fatal("fixed artist input absent")
}
