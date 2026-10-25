package publication

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/app/capture"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
	"github.com/irootkernel/mulgae/internal/testsupport/historical"
)

// Adapt immutable corpus members to recovery ports; no candidate is produced.
func retainedHistoricalFixture(t *testing.T, caseID string) publicationServiceFixture {
	t.Helper()
	corpus, err := historical.Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range corpus.Cases {
		if c.ID != caseID {
			continue
		}
		run, snapshot := retainedHistoricalSnapshot(t, c)
		status, journal, err := completedRecoveryDocuments(run, snapshot)
		if err != nil {
			t.Fatal(err)
		}
		var header struct {
			RecoveryJournal   recoveryJournalWire   `json:"recovery_journal"`
			CompositeIdentity compositeIdentityWire `json:"composite_identity"`
		}
		if err := json.Unmarshal(snapshot.Manifest().Bytes(), &header); err != nil {
			t.Fatal(err)
		}
		staged, err := immutableArtifact(mustPublicationPath(header.RecoveryJournal.ExpectedStaged.Path), snapshot.Final().Bytes())
		if err != nil {
			t.Fatal(err)
		}
		files := c.Artifacts()
		indexPath := header.CompositeIdentity.SupportIndex.Path
		var index runSupportIndexWire
		if err := json.Unmarshal(files[indexPath], &index); err != nil {
			t.Fatal(err)
		}
		var support []ports.ImmutablePublicationArtifact
		for _, member := range append(index.Artifacts, artifactIdentityWire{Path: indexPath}) {
			artifact, err := immutableArtifact(mustPublicationPath(member.Path), files[member.Path])
			if err != nil {
				t.Fatal(err)
			}
			support = append(support, artifact)
		}
		issued, err := ports.NewIssuedReviewID(snapshot.Final().Identity().ReviewID(), header.RecoveryJournal.ValidatedCandidateSHA256)
		if err != nil {
			t.Fatal(err)
		}
		bundle := PublicationBundle{final: snapshot.Final(), manifest: snapshot.Manifest(), lineageEdge: snapshot.LineageEdge(), epoch: snapshot.Epoch(), staged: staged, status: status, journal: journal, excerpts: support}
		return publicationServiceFixture{root: run.Root(), run: run, issued: issued, bundle: bundle}
	}
	t.Fatalf("fixed historical fixture absent: %s", caseID)
	return publicationServiceFixture{}
}

// Adapt fixed store members to ports. This helper has no writer, acceptance,
// replay or recovery implementation; the retained code makes those decisions.
func retainedHistoricalSnapshot(t *testing.T, c historical.Case) (ports.PublicationRun, ports.CommittedPublicationSnapshot) {
	t.Helper()
	files := c.Artifacts()
	root, err := ports.NewAnchoredRoot("/private/retained-historical-input")
	if err != nil {
		t.Fatal(err)
	}
	session, err := domain.ParseSessionID(c.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	id, err := domain.ParseRunID(c.RunID)
	if err != nil {
		t.Fatal(err)
	}
	run, err := ports.NewPublicationRun(root, session, id)
	if err != nil {
		t.Fatal(err)
	}
	prefix := c.SessionID + "/" + c.RunID + "/"
	var manifest runManifestWire
	if err := json.Unmarshal(files[prefix+"manifest.json"], &manifest); err != nil {
		t.Fatal(err)
	}
	artifact := func(path string) ports.ImmutablePublicationArtifact {
		raw, ok := files[path]
		if !ok {
			t.Fatalf("fixed member absent: %s", path)
		}
		got, err := immutableArtifact(mustPublicationPath(path), raw)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	review, err := domain.ParseReviewID(manifest.FinalReview.ReviewID)
	if err != nil {
		t.Fatal(err)
	}
	rawFinal := files[manifest.FinalReview.Path]
	identity, err := ports.NewFinalReviewIdentity(review, mustPublicationPath(manifest.FinalReview.Path), sha256Identifier(rawFinal))
	if err != nil {
		t.Fatal(err)
	}
	final, err := ports.NewFinalReviewArtifact(identity, rawFinal)
	if err != nil {
		t.Fatal(err)
	}
	epochArtifact := artifact(manifest.CompositeIdentity.Epoch.Path)
	var epochValue publicationEpochWire
	if err := json.Unmarshal(epochArtifact.Bytes(), &epochValue); err != nil {
		t.Fatal(err)
	}
	epoch, err := ports.NewPublicationEpoch(epochValue.StoreEpoch, epochArtifact)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := ports.NewCommittedPublicationSnapshot(final, artifact(prefix+"manifest.json"), artifact(manifest.CompositeIdentity.LineageEdge.Path), epoch)
	if err != nil {
		t.Fatal(err)
	}
	return run, snapshot
}

// Rebind the outer manifest/epoch hashes so a semantic or canonicality mutation
// reaches recovery's inner check rather than failing a stale digest first.
func retainedSnapshotWithManifest(t *testing.T, snapshot ports.CommittedPublicationSnapshot, raw []byte) ports.CommittedPublicationSnapshot {
	t.Helper()
	manifest, err := immutableArtifact(snapshot.Manifest().Path(), raw)
	if err != nil {
		t.Fatal(err)
	}
	var value publicationEpochWire
	if err := json.Unmarshal(snapshot.Epoch().Record().Bytes(), &value); err != nil {
		t.Fatal(err)
	}
	value.Manifest.SHA256 = manifest.SHA256()
	encoded, err := marshalCanonical(value)
	if err != nil {
		t.Fatal(err)
	}
	record, err := immutableArtifact(snapshot.Epoch().Record().Path(), encoded)
	if err != nil {
		t.Fatal(err)
	}
	epoch, err := ports.NewPublicationEpoch(snapshot.Epoch().Value(), record)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ports.NewCommittedPublicationSnapshot(snapshot.Final(), manifest, snapshot.LineageEdge(), epoch)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func TestCompositeRecoveryReencodesFrozenCanonicalManifest(t *testing.T) {
	corpus, err := historical.Load()
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, c := range corpus.Cases {
		if c.ID != "composite-legacy-v1" && c.ID != "composite-copied-v1" && c.ID != "composite-mixed-v1" && c.ID != "composite-copied-v2" {
			continue
		}
		t.Run(c.ID, func(t *testing.T) {
			run, snapshot := retainedHistoricalSnapshot(t, c)
			status, journal, err := completedRecoveryDocuments(run, snapshot)
			if err != nil {
				t.Fatal(err)
			}
			files := c.Artifacts()
			prefix := c.SessionID + "/" + c.RunID + "/"
			if !bytes.Equal(status.Bytes(), files[prefix+"status.json"]) || !bytes.Equal(journal.Bytes(), files[prefix+"publication/journal.json"]) {
				t.Fatal("actual recovery encoding changed frozen mutable bytes")
			}
			// Insignificant JSON whitespace is semantically decodable but cannot
			// authorize a different canonical committed representation.
			noncanonical := retainedSnapshotWithManifest(t, snapshot, append([]byte(" "), snapshot.Manifest().Bytes()...))
			if _, _, err := completedRecoveryDocuments(run, noncanonical); err == nil || !strings.Contains(err.Error(), "committed manifest is not canonical") {
				t.Fatalf("noncanonical manifest missed intended recovery guard: %v", err)
			}
			var m compositeManifestWire
			if err := json.Unmarshal(snapshot.Manifest().Bytes(), &m); err != nil {
				t.Fatal(err)
			}
			if strings.HasSuffix(m.SchemaVersion, ".v1") {
				m.SchemaVersion = "mulgae-composite-run-manifest.v2"
			} else {
				m.SchemaVersion = "mulgae-composite-run-manifest.v1"
			}
			changed, err := marshalCanonical(m)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := completedRecoveryDocuments(run, retainedSnapshotWithManifest(t, snapshot, changed)); err == nil {
				t.Fatal("final/manifest version mismatch acquired recovery authority")
			}
		})
		seen++
	}
	if seen != 4 {
		t.Fatalf("canonical composite families=%d, want 4", seen)
	}
}

func TestFrozenCaptureSupportRejectsMissingMembersAndDowngrade(t *testing.T) {
	corpus, err := historical.Load()
	if err != nil {
		t.Fatal(err)
	}
	seen := false
	for _, c := range corpus.Cases {
		if c.ID != "ordinary-v2" {
			continue
		}
		seen = true
		run, snapshot := retainedHistoricalSnapshot(t, c)
		artifacts := map[string]ports.ImmutablePublicationArtifact{}
		for path, raw := range c.Artifacts() {
			artifact, err := immutableArtifact(mustPublicationPath(path), raw)
			if err != nil {
				t.Fatal(err)
			}
			artifacts[path] = artifact
		}
		var manifest runManifestWire
		if err := json.Unmarshal(snapshot.Manifest().Bytes(), &manifest); err != nil {
			t.Fatal(err)
		}
		target := manifest.Target.ContentSHA256
		if _, err := capture.VerifySupport(run.SessionID(), run.RunID(), target, nil, nil, artifacts); err != nil {
			t.Fatal(err)
		}
		wrong := strings.Repeat("b", 40)
		if _, err := capture.VerifySupport(run.SessionID(), run.RunID(), target, &wrong, nil, artifacts); err == nil {
			t.Fatal("wrong object ID accepted")
		}
		for path, artifact := range artifacts {
			if !strings.Contains(path, "/target/") || strings.HasSuffix(path, "target-manifest.json") || strings.HasSuffix(path, "target.bytes") {
				continue
			}
			t.Run("missing/"+path, func(t *testing.T) {
				delete(artifacts, path)
				defer func() { artifacts[path] = artifact }()
				if _, err := capture.VerifySupport(run.SessionID(), run.RunID(), target, nil, nil, artifacts); err == nil {
					t.Fatal("missing capture member accepted")
				}
			})
		}
		prefix := c.SessionID + "/" + c.RunID + "/"
		var index runSupportIndexWire
		indexArtifact := artifacts[prefix+"support/index.json"]
		if err := json.Unmarshal(indexArtifact.Bytes(), &index); err != nil {
			t.Fatal(err)
		}
		var support []ports.ImmutablePublicationArtifact
		for _, member := range index.Artifacts {
			a, ok := artifacts[member.Path]
			if !ok {
				t.Fatalf("fixed indexed support absent: %s", member.Path)
			}
			support = append(support, a)
		}
		support = append(support, indexArtifact)
		if err := validateBundleSupportIndex(support, artifactIdentityWire{Path: indexArtifact.Path().String(), SHA256: indexArtifact.SHA256()}, run.SessionID(), run.RunID(), target, nil, nil); err != nil {
			t.Fatalf("positive support control: %v", err)
		}
		index.SchemaVersion = "mulgae-run-support-index.v1"
		raw, err := marshalCanonical(index)
		if err != nil {
			t.Fatal(err)
		}
		downgraded, err := immutableArtifact(indexArtifact.Path(), raw)
		if err != nil {
			t.Fatal(err)
		}
		support[len(support)-1] = downgraded
		if err := validateBundleSupportIndex(support, artifactIdentityWire{Path: downgraded.Path().String(), SHA256: downgraded.SHA256()}, run.SessionID(), run.RunID(), target, nil, nil); err == nil {
			t.Fatal("correctly rehashed support downgrade accepted")
		}
	}
	if !seen {
		t.Fatal("fixed capture family absent")
	}
}

func TestFrozenFinalProductionProvenanceRejectsEachMutatedField(t *testing.T) {
	t.Parallel()

	corpus, err := historical.Load()
	if err != nil {
		t.Fatal(err)
	}
	var snapshot ports.CommittedPublicationSnapshot
	for _, c := range corpus.Cases {
		if c.ID == "ordinary-v2" {
			_, snapshot = retainedHistoricalSnapshot(t, c)
		}
	}
	if !snapshot.Valid() {
		t.Fatal("fixed provenance input absent")
	}
	var baseline finalReviewWire
	if err := unmarshalExact(snapshot.Final().Bytes(), &baseline); err != nil {
		t.Fatal(err)
	}
	// Independent populated historical input: model_test.go publicationTestCandidate
	// literals, without invoking that retired producer or changing frozen bytes.
	if err := json.Unmarshal([]byte(`{"build_product":"mulgae","build_version":"0.1.0","build_commit":"0123456789abcdef","objective_sha256":"sha256:d454bec656d32723404961023ed9cb3c37221687c40b498a57b3eefa93c4c5f4","objective_present":true,"snapshot_manifest_sha256":"sha256:16a0eeb0791b6c92451fd284dd9f599e0a7dbe7f6ebea6e2d2d06c7f74aec112","workspace_terminal_receipt":"sha256:b9679aeab74e67efe0ea30f14498f825a20298bc62496213bfcb1b3a78b57d6f","providers":[{"family":"grok","instance":"grok-security","version":"1.0.30","executable":"/private/bin/grok","executable_sha256":"sha256:add92b9cde2bdbf3daaf65a0db79e9b1a7fa428b71b4d6ce38c742eb6dca0c1c","launcher":"/private/bin/grok","launcher_sha256":"sha256:add92b9cde2bdbf3daaf65a0db79e9b1a7fa428b71b4d6ce38c742eb6dca0c1c","profile_generation":"generation-1","adapter_profile":"grok-default","qualification_receipt_ids":["sha256:80f74d71f5365d6ef18a86dd0b2d3690bfe26d6de3691a6f824eb8bb68b57f6f"],"packet_transport_receipt_ids":["sha256:e03c84a5246970c29d11ba1eb517fb975a9110ac5110ca7fe127241d1561c6bb"],"namespace_terminal_receipt":"sha256:0e5e94b55ab259f38684501bc96659d8128e26362c3f74fef4f3f1c2144d2d31"},{"family":"zcode","instance":"zcode-logic","version":"0.16.5","executable":"/usr/bin/node","executable_sha256":"sha256:545ea538461003efdc8c81c244531b003f6f26cfccf6c0073b3239fdedf49446","launcher":"/private/bin/zcode.cjs","launcher_sha256":"sha256:b159d6b0709474962d2f3746d75665744adf4f557eab580900207d2f86d9c153","profile_generation":"generation-1","adapter_profile":"zcode-default","qualification_receipt_ids":["sha256:2a7b9c918f55c9a4d31b344826fb4595312f85e7c37be0d348084c6d58cfa180"],"packet_transport_receipt_ids":["sha256:4bede0e99d1f4417954dd79df27b473efba0e867878f7effeb376d418865654d"],"namespace_terminal_receipt":"sha256:e59e80b52c9fb91abbd4df0ece52e6d32dac3b6b696eaf248ba3be6d1b9447cb"}]}`), &baseline.Provenance.Production); err != nil {
		t.Fatal(err)
	}
	baseline.Mulgae.Version = "0.1.0"
	commit := "0123456789abcdef"
	baseline.Mulgae.Commit = &commit
	if baseline.Provenance.Production == nil || len(baseline.Provenance.Production.Providers) != 2 || !baseline.Provenance.Production.ObjectivePresent {
		t.Fatal("populated provenance positive input absent")
	}
	if err := validateFinalProductionProvenance(baseline); err != nil {
		t.Fatalf("fixed provenance positive control: %v", err)
	}
	cases := []struct {
		name   string
		mutate func(*finalReviewWire)
	}{
		{"build product", func(f *finalReviewWire) { f.Provenance.Production.BuildProduct = "" }},
		{"build version", func(f *finalReviewWire) { f.Provenance.Production.BuildVersion = "9.9.9" }},
		{"build commit", func(f *finalReviewWire) { f.Provenance.Production.BuildCommit = "other" }},
		{"objective presence", func(f *finalReviewWire) { f.Provenance.Production.ObjectivePresent = false }},
		{"objective digest", func(f *finalReviewWire) { value := ""; f.Provenance.Production.ObjectiveSHA256 = &value }},
		{"snapshot digest", func(f *finalReviewWire) { f.Provenance.Production.SnapshotManifestSHA256 = "" }},
		{"workspace receipt", func(f *finalReviewWire) { f.Provenance.Production.WorkspaceTerminalReceipt = "" }},
		{"family", func(f *finalReviewWire) { f.Provenance.Production.Providers[0].Family = "" }},
		{"instance", func(f *finalReviewWire) { f.Provenance.Production.Providers[0].Instance = "" }},
		{"provider version", func(f *finalReviewWire) { f.Provenance.Production.Providers[0].Version = "" }},
		{"executable", func(f *finalReviewWire) { f.Provenance.Production.Providers[0].Executable = "" }},
		{"executable digest", func(f *finalReviewWire) { f.Provenance.Production.Providers[0].ExecutableSHA256 = "" }},
		{"launcher", func(f *finalReviewWire) { f.Provenance.Production.Providers[0].Launcher = "" }},
		{"launcher digest", func(f *finalReviewWire) { f.Provenance.Production.Providers[0].LauncherSHA256 = "" }},
		{"profile generation", func(f *finalReviewWire) { f.Provenance.Production.Providers[0].ProfileGeneration = "" }},
		{"adapter profile", func(f *finalReviewWire) { f.Provenance.Production.Providers[0].AdapterProfile = "" }},
		{"qualification receipt", func(f *finalReviewWire) { f.Provenance.Production.Providers[0].QualificationReceiptIDs[0] = "" }},
		{"packet receipt", func(f *finalReviewWire) { f.Provenance.Production.Providers[0].PacketTransportReceiptIDs[0] = "" }},
		{"namespace receipt", func(f *finalReviewWire) { f.Provenance.Production.Providers[0].NamespaceTerminalReceipt = "" }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			final := baseline
			final.Provenance.Production = cloneProductionWire(baseline.Provenance.Production)
			test.mutate(&final)
			if err := validateFinalProductionProvenance(final); err == nil {
				t.Fatal("reader accepted mutated production provenance")
			}
		})
	}
}
