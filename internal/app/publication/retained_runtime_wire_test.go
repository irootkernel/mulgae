package publication

import (
	"encoding/json"
	"testing"

	"github.com/irootkernel/mulgae/internal/artifactwire"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

func retainedRuntimeWireOutputs(t *testing.T) map[string]string {
	t.Helper()
	outputs := map[string]string{}
	encode := func(name string, value any) {
		raw, err := marshalCanonical(value)
		if err != nil {
			t.Fatal(err)
		}
		outputs[name] = string(raw)
	}
	identity := artifactIdentityWire{Path: "café/é/<&>\r\n", SHA256: "sha256:literal"}
	encode("identity", identity)
	encode("support-null", runSupportIndexWire{SchemaVersion: "mulgae-run-support-index.v1"})
	encode("support-empty", runSupportIndexWire{SchemaVersion: "mulgae-run-support-index.v1", Artifacts: []artifactIdentityWire{}})
	encode("target-absent", artifactwire.RuntimeTargetManifest{SchemaVersion: "mulgae-runtime-target-manifest.v1"})
	encode("target-present", artifactwire.RuntimeTargetManifest{
		SchemaVersion: "mulgae-runtime-target-manifest.v1", Target: identity, CapturedArchive: &identity,
		ArtistBrief: &identity, ArtistVisualAssets: &identity, TargetKind: "patch", RepositoryID: "repo",
		BaseObjectID: "base", HeadObjectID: "head", HeadTreeObjectID: "head-tree", IndexTreeObjectID: "index-tree", GitMode: "dirty",
		Prompts: []artifactIdentityWire{}, SelectedReplayPrompts: []artifactwire.SelectedReplayPrompt{},
	})
	encode("selected-prompt", artifactwire.SelectedReplayPrompt{AttemptID: "attempt", Sequence: 2, Purpose: "repair", Artifact: identity})
	encode("prompt-null", artifactwire.RuntimePromptManifest{SchemaVersion: "mulgae-runtime-prompt-manifest.v1"})
	encode("prompt-present", artifactwire.RuntimePromptManifest{SchemaVersion: "mulgae-runtime-prompt-manifest.v1", Target: identity, Stdin: identity,
		CompleteStdinSHA256: "complete", TemplateID: "review", TemplateVersion: "v1", TemplateSHA256: "template", SourceInvocationID: "source",
		ExecutionInvocationID: "execution", Scope: "repository", Role: "logic", AdapterProfile: "default", AdapterParameters: map[string]string{"z": "<&>", "a": "한글"}})
	prefix := "s_019f596a-cf80-7c67-b265-f37053d51ccf/r_019f596a-cfe4-7c9c-b82e-7149158243ba/"
	for _, c := range []struct{ name, path string }{
		{"v1", "target/target.bytes"}, {"v2", "target/capture-manifest.json"}, {"v3", "source/source.json"},
	} {
		artifact, err := immutableArtifact(mustPublicationPath(prefix+c.path), []byte("<&> café\r\n"))
		if err != nil {
			t.Fatal(err)
		}
		index, err := buildRunSupportIndex(mustPublicationPath(prefix+"support/index.json"), []ports.ImmutablePublicationArtifact{artifact})
		if err != nil {
			t.Fatal(err)
		}
		if c.name == "v3" {
			var current runSupportIndexWire
			if err := json.Unmarshal(index.Bytes(), &current); err != nil || current.SchemaVersion != artifactwire.SupportIndexV4 {
				t.Fatal("current live support producer did not cut over to v4")
			}
			// Retain the v3 DTO encoder, without restoring its retired producer.
			encode("built-support-v3", runSupportIndexWire{SchemaVersion: artifactwire.SupportIndexV3, Artifacts: []artifactIdentityWire{{Path: artifact.Path().String(), SHA256: artifact.SHA256()}}})
		} else {
			outputs["built-support-"+c.name] = string(index.Bytes())
		}
	}
	return outputs
}

func retainedPublicationWireOutputs(t *testing.T) map[string]string {
	t.Helper()
	result := map[string]string{}
	encode := func(name string, value any) {
		raw, err := marshalCanonical(value)
		if err != nil {
			t.Fatal(err)
		}
		result[name] = string(raw)
	}
	identity := artifactIdentityWire{Path: "café é 한글 <&>\r\n", SHA256: "sha256:literal"}
	restart := restartStateWire{SessionID: "session", RunID: "run", ExpectedStaged: identity, ExpectedFinal: identity, ValidatedCandidateSHA256: "candidate", StoreEpoch: 42, NormalExit: 4, ManifestPath: "manifest", LineageEdgePath: "lineage", EpochPath: "epoch"}
	for _, state := range []domain.PersistedJournalState{domain.JournalCollecting, domain.JournalContentValidated, domain.JournalFinalStaged, domain.JournalFinalFileInstalled, domain.JournalManifestCommitted, domain.JournalCompleted} {
		restart.PersistedJournalState = string(state)
		encode("journal/"+string(state), publicationJournalWire{SchemaVersion: publicationJournalV1, RestartState: restart})
		for _, authority := range []domain.PublicationAuthority{domain.PublicationAuthorityNone, domain.PublicationAuthorityP0, domain.PublicationAuthorityP1, domain.PublicationAuthorityP2} {
			encode("status/"+string(state)+"/"+string(authority), publicationStatusWire{SchemaVersion: publicationStatusV1, PublicationStatus: "committed", PublicationAuthority: string(authority), RestartState: restart})
		}
	}
	for _, reasons := range [][]string{nil, {}, {"missing_final", "candidate_mismatch"}} {
		encode("corruption/"+retainedMustJSON(reasons), publicationCorruptionDiagnosticWire{SchemaVersion: "mulgae-publication-corruption.v1", SessionID: "session", RunID: "run", ObservationEpoch: 42, ReasonCodes: reasons})
	}
	// Exercise custom selection with optional fields both absent and present.
	for _, present := range []bool{false, true} {
		role := artifactwire.CompositeRole{Role: "logic", ValidFindingIDs: []string{}}
		finding := artifactwire.CompositeFinding{ID: "F001", Title: "café é 한글 <&>\r\n", Source: artifactwire.CompositeFindingSource{RunID: "run", AttemptID: "attempt", FindingID: "F007"}}
		composition := artifactwire.CompositeComposition{Fingerprint: "fingerprint", RootRunID: "run", Sources: []artifactwire.CompositeSource{}}
		if present {
			role.SourceReviewID = "review"
			role.SourceRecoveryManifestSHA256 = "recovery"
			role.SourceKind = "recovery"
			finding.Source.ReviewID = "review"
			finding.Source.RecoveryManifestSHA256 = "recovery"
			finding.Source.SourceKind = "recovery"
			composition.RootReviewID = "review"
			composition.RootRecoveryManifestSHA256 = "recovery"
			composition.RootSourceKind = "recovery"
			composition.Sources = []artifactwire.CompositeSource{{Role: "logic", ReviewID: "review", RecoveryManifestSHA256: "recovery", SourceKind: "recovery"}}
		}
		encode("custom-role/"+retainedMustJSON(present), role)
		encode("custom-finding/"+retainedMustJSON(present), finding)
		encode("composition/"+retainedMustJSON(present), composition)
	}
	return result
}

func retainedMustJSON(value any) string {
	raw, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return string(raw)
}
