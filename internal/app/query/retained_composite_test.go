package query

import (
	"bytes"
	"context"
	"encoding/json"
	"sort"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/adapters/jsonschema"
	"github.com/irootkernel/mulgae/internal/app/compositesupport"
	"github.com/irootkernel/mulgae/internal/artifactwire"
	"github.com/irootkernel/mulgae/internal/builtin"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
	"github.com/irootkernel/mulgae/internal/testsupport/historical"
)

func TestCompositeRuntimeTargetPreservesDiffStageAndDirtyMetadata(t *testing.T) {
	corpus, err := historical.Load()
	if err != nil {
		t.Fatal(err)
	}
	validator, err := jsonschema.New(context.Background(), builtin.NewCatalog())
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range corpus.Cases {
		if c.ID != "composite-legacy-v1" {
			continue
		}
		for _, mode := range []domain.GitTargetMode{domain.GitTargetDiff, domain.GitTargetStage, domain.GitTargetDirty} {
			t.Run(string(mode), func(t *testing.T) {
				store, run := historicalQueryStore(t, c)
				snapshot := store.snapshotsByRun[c.RunID]
				identity := func(s string) string { return s }
				entries := queryRuntimeFixtureEntries(t, snapshot, store.auxiliaryArtifacts, identity, bytes.Clone)
				path := c.SessionID + "/" + c.RunID + "/target/target-manifest.json"
				var target artifactwire.RuntimeTargetManifest
				if err := json.Unmarshal(entries[path].bytes, &target); err != nil {
					t.Fatal(err)
				}
				target.TargetKind = "git"
				target.RepositoryID = "fixture"
				target.GitMode = string(mode)
				target.BaseObjectID = strings.Repeat("1", 40)
				target.HeadObjectID = strings.Repeat("2", 40)
				target.HeadTreeObjectID = strings.Repeat("3", 40)
				target.IndexTreeObjectID = strings.Repeat("4", 40)
				raw, err := json.Marshal(target)
				if err != nil {
					t.Fatal(err)
				}
				entries[path].bytes = raw
				retainedQueryRebind(t, entries, c.SessionID+"/"+c.RunID+"/")
				updated, observation, artifacts := retainedQuerySnapshot(t, run, snapshot, store.auxiliaryArtifacts, entries, domain.OperationalExitCode(c.Expected.Exit))
				store.snapshotsByRun[c.RunID] = updated
				store.observationsByRun[c.RunID] = observation
				store.auxiliaryArtifacts = artifacts
				got, err := mustQueryService(t, store, validator, nil).ReadRuntimeTarget(context.Background(), run)
				if err != nil {
					t.Fatal(err)
				}
				id := got.Identity()
				if id.Kind() != domain.TargetGit || id.GitMode() != mode || id.RepositoryID() != "fixture" || id.BaseObjectID() != target.BaseObjectID || id.HeadObjectID() != target.HeadObjectID || id.HeadTreeObjectID() != target.HeadTreeObjectID || id.IndexTreeObjectID() != target.IndexTreeObjectID {
					t.Fatal("composite Git metadata was lost")
				}
			})
		}
		return
	}
	t.Fatal("fixed composite input absent")
}

func TestCopiedCompositeRetainsProviderRetirementWithoutSourceRuns(t *testing.T) {
	corpus, err := historical.Load()
	if err != nil {
		t.Fatal(err)
	}
	validator, err := jsonschema.New(context.Background(), builtin.NewCatalog())
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range corpus.Cases {
		if c.ID != "composite-copied-v1" {
			continue
		}
		store, run := historicalQueryStore(t, c)
		if _, err := mustQueryService(t, store, validator, nil).ReadCommitted(context.Background(), run); err != nil {
			t.Fatalf("valid copied provenance before retirement: %v", err)
		}
		snapshot := store.snapshotsByRun[c.RunID]
		identity := func(s string) string { return s }
		entries := queryRuntimeFixtureEntries(t, snapshot, store.auxiliaryArtifacts, identity, bytes.Clone)
		prefix := c.SessionID + "/" + c.RunID + "/"
		path := prefix + compositesupport.DocumentPath
		var doc compositesupport.Document
		if err := json.Unmarshal(entries[path].bytes, &doc); err != nil {
			t.Fatal(err)
		}
		doc.Sources[0].ProviderIdentities = append(doc.Sources[0].ProviderIdentities, "kimi-retired")
		sort.Strings(doc.Sources[0].ProviderIdentities)
		raw, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		entries[path].bytes = append(raw, '\n')
		retainedQueryRebind(t, entries, c.SessionID+"/"+c.RunID+"/")
		updated, observation, artifacts := retainedQuerySnapshot(t, run, snapshot, store.auxiliaryArtifacts, entries, domain.OperationalExitCode(c.Expected.Exit))
		store.snapshotsByRun[c.RunID] = updated
		store.observationsByRun[c.RunID] = observation
		// Keep only the self-contained composite run and its store receipts.
		for name := range artifacts {
			if !strings.HasPrefix(name, prefix) && !strings.HasPrefix(name, "store/") {
				delete(artifacts, name)
			}
		}
		store.auxiliaryArtifacts = artifacts
		store.snapshotsByRun = map[string]ports.CommittedPublicationSnapshot{c.RunID: updated}
		store.observationsByRun = map[string]ports.PublicationObservation{c.RunID: store.observationsByRun[c.RunID]}
		store.resolutionsByRun = map[string]ports.PublicationRun{c.RunID: run}
		_, err = mustQueryService(t, store, validator, nil).ReadCommitted(context.Background(), run)
		historicalReason(t, err, "retired_provider_artifact")
		return
	}
	t.Fatal("fixed copied composite input absent")
}
