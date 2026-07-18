package review

import (
	"reflect"
	"testing"

	"github.com/irootkernel/kkachi-agent-review/internal/domain"
	"github.com/irootkernel/kkachi-agent-review/internal/ports"
)

func TestAttemptCaptureArtifactsAreDefensive(t *testing.T) {
	attemptID, err := domain.ParseAttemptID("a_019f5a09-5eec-7001-8001-000000000001")
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := ports.NewCapturedAttemptArtifact(ports.AttemptArtifactStdout, []byte("candidate"), false)
	if err != nil {
		t.Fatal(err)
	}
	capture := AttemptCapture{attemptID: attemptID, sequence: 1, artifacts: []ports.CapturedAttemptArtifact{artifact}}
	artifacts := capture.Artifacts()
	artifacts[0] = ports.CapturedAttemptArtifact{}
	if got := capture.Artifacts(); len(got) != 1 || string(got[0].Bytes()) != "candidate" {
		t.Fatal("attempt capture exposed mutable artifact slice")
	}
}

func TestReplayAndDeltaInputsDefensivelyBindBytesAndParameters(t *testing.T) {
	delta := DeltaInvocationMaterial{SourceTarget: []byte("source"), CurrentTarget: []byte("current"), Delta: []byte("delta")}
	replay := ExactReplayInput{SourceProviderInstance: "fake.logic", Stdin: []byte("stdin"), AdapterParameters: map[string]string{"model": "fixed"}}
	deltaCopy := cloneDeltaInvocationMaterial(delta)
	replayCopy := cloneExactReplayInput(replay)
	delta.SourceTarget[0] = 'X'
	replay.Stdin[0] = 'X'
	replay.AdapterParameters["model"] = "other"
	if replayCopy.SourceProviderInstance != "fake.logic" || string(deltaCopy.SourceTarget) != "source" ||
		string(replayCopy.Stdin) != "stdin" ||
		!reflect.DeepEqual(replayCopy.AdapterParameters, map[string]string{"model": "fixed"}) {
		t.Fatal("explicit invocation input exposed caller mutation")
	}
	if sameAdapterParameters(replayCopy.AdapterParameters, replay.AdapterParameters) {
		t.Fatal("adapter tuple mismatch was accepted")
	}
}
