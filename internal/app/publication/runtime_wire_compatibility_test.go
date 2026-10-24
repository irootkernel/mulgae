package publication

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/irootkernel/mulgae/internal/ports"
)

func runtimeWireGoldenOutputs(t *testing.T) map[string]string {
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
	encode("target-absent", runtimeTargetManifestWire{SchemaVersion: "mulgae-runtime-target-manifest.v1"})
	encode("target-present", runtimeTargetManifestWire{
		SchemaVersion: "mulgae-runtime-target-manifest.v1", Target: identity, CapturedArchive: &identity,
		ArtistBrief: &identity, ArtistVisualAssets: &identity, TargetKind: "patch", RepositoryID: "repo",
		BaseObjectID: "base", HeadObjectID: "head", HeadTreeObjectID: "head-tree", IndexTreeObjectID: "index-tree", GitMode: "dirty",
		Prompts: []artifactIdentityWire{}, SelectedReplayPrompts: []selectedReplayPromptWire{},
	})
	encode("selected-prompt", selectedReplayPromptWire{AttemptID: "attempt", Sequence: 2, Purpose: "repair", Artifact: identity})
	encode("prompt-null", runtimePromptManifestWire{SchemaVersion: "mulgae-runtime-prompt-manifest.v1"})
	encode("prompt-present", runtimePromptManifestWire{SchemaVersion: "mulgae-runtime-prompt-manifest.v1", Target: identity, Stdin: identity,
		CompleteStdinSHA256: "complete", TemplateID: "review", TemplateVersion: "v1", TemplateSHA256: "template", SourceInvocationID: "source",
		ExecutionInvocationID: "execution", Scope: "repository", Role: "logic", AdapterProfile: "default", AdapterParameters: map[string]string{"z": "<&>", "a": "한글"}})
	candidate := publicationRuntimeCandidate(t)
	artifacts, err := candidate.buildRuntimeArtifacts()
	if err != nil {
		t.Fatal(err)
	}
	for _, artifact := range artifacts {
		outputs["runtime/"+artifact.Path().String()] = string(artifact.Bytes())
	}
	prefix := candidate.sessionID.String() + "/" + candidate.runID.String() + "/"
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
		outputs["built-support-"+c.name] = string(index.Bytes())
	}
	return outputs
}

func TestRuntimeWireGoldenCompatibility(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "m1-runtime-wire.json"))
	if err != nil {
		t.Fatal(err)
	}
	var expected map[string]string
	if err := json.Unmarshal(raw, &expected); err != nil {
		t.Fatal(err)
	}
	actual := runtimeWireGoldenOutputs(t)
	if len(actual) != len(expected) {
		t.Fatalf("member count=%d want %d", len(actual), len(expected))
	}
	for name, want := range expected {
		t.Run(name, func(t *testing.T) {
			got, present := actual[name]
			if !present || !bytes.Equal([]byte(got), []byte(want)) {
				t.Fatalf("bytes=%q; want %q", got, want)
			}
		})
	}
}
