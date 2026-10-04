package review

import (
	"context"
	"errors"
	"testing"

	"github.com/irootkernel/mulgae/internal/app/evidence"
	"github.com/irootkernel/mulgae/internal/app/prompt"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

type runtimeLiveReader struct {
	coordinatorLiveReader
	binding ports.ProjectBindingObservation
	err     error
}

func (reader *runtimeLiveReader) Root() ports.AnchoredRoot { return reader.binding.Root }
func (reader *runtimeLiveReader) RevalidateExecution(context.Context) (ports.ProjectBindingObservation, error) {
	return reader.binding, reader.err
}

type runtimeLiveHome struct {
	ports.ReviewerHome
	root ports.AnchoredRoot
}

func (home runtimeLiveHome) Root() ports.AnchoredRoot { return home.root }
func (runtimeLiveHome) Revalidate() error             { return nil }

func TestProviderRuntimeLiveSourceBindsNativeExecutionAndEvidence(t *testing.T) {
	for _, test := range []struct {
		name    string
		rebound bool
		closed  bool
	}{
		{name: "verified live evidence"},
		{name: "changed source binding", closed: true},
		{name: "captured source bytes rejected", rebound: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			selector, _ := ports.NewLiveSourceSelector(domain.LiveSourceWorkspace, "")
			path, _ := ports.NewSafeRelativePath("source.go")
			target, _ := ports.NewLiveSourceTarget(selector, ports.GitObjectID{}, ports.GitObjectID{}, false, []ports.LiveSourceChange{{Kind: "included", After: path}})
			root, _ := ports.NewAnchoredRoot("/source")
			neutral, _ := ports.NewAnchoredRoot("/neutral")
			credential, _ := ports.NewAnchoredRoot("/credentials")
			reader := &runtimeLiveReader{coordinatorLiveReader: coordinatorLiveReader{target}, binding: ports.ProjectBindingObservation{Root: root, RootIdentity: ports.ProjectDirectoryIdentity{Device: 1, Inode: 2}}}
			execution, err := ports.NewLiveReviewExecution(context.Background(), reader, runtimeLiveHome{root: neutral}, []ports.AnchoredRoot{credential})
			if err != nil {
				t.Fatal(err)
			}
			identity, _ := evidence.NewLiveSourceIdentity(target)
			_, job, material := providerRuntimeExplicitFixture(t, nil)
			job.target, err = identity.RunTarget()
			if err != nil {
				t.Fatal(err)
			}
			compiler, _ := prompt.NewCompiler(material.Prompt.TrustedTemplate(), explicitRuntimeTestIssuer{source: material.Prompt.Scope().SourceInvocationID(), execution: material.Prompt.Scope().ExecutionInvocationID()})
			coordinates := material.Prompt.Scope().FrameScope().Coordinates()
			material.Target = identity.Bytes()
			material.Prompt, err = compiler.Compile(prompt.CompileInput{Scope: coordinates, ReviewTarget: prompt.NewPayload(material.Target)})
			if err != nil {
				t.Fatal(err)
			}
			raw := []byte(`{"schema_version":"mulgae-provider-review-output.v1","summary":"Live observation.","completeness":"complete","limitations":[],"findings":[{"severity":"high","title":"Observed defect","description":"The observed source demonstrates the defect.","evidence":[{"current":{"path":"source.go","side":"worktree","line_start":1,"line_end":1,"quote":"observed\n"}}],"recommendation":"Correct the defect.","confidence":"high"}]}`)
			provider := &recordingObservedProvider{t: t, responses: []providerRuntimeObservation{{stdout: raw}}}
			runtime, err := NewObservedProviderInvocationRuntimeInLiveSource(provider, explicitRuntimePromptSource{material}, execution, newReviewValidator(t), providerRuntimeDiagnosticResolver{runID: job.RunID(), sink: &providerRuntimeRawSink{}})
			if err != nil {
				t.Fatal(err)
			}
			if test.rebound {
				material.CapturedArchive = []byte("captured source archive")
				runtime.source = explicitRuntimePromptSource{material}
			}
			if test.closed {
				reader.err = errors.New("source directory identity changed")
			}
			outcome := runtime.Invoke(context.Background(), job)
			if test.rebound || test.closed {
				if outcome.Succeeded() || len(provider.invocations) != 0 {
					t.Fatalf("unbound source reached provider: %#v", outcome)
				}
				return
			}
			output, ok := outcome.Output()
			if !outcome.Succeeded() || !ok || len(output.Findings()) != 1 || outcome.runtimeArtifactsExpected {
				t.Fatalf("live output or archive expectation: %#v", outcome)
			}
			invocation := provider.invocations[0]
			if _, live := invocation.LiveExecution(); !live {
				t.Fatal("live launch authority missing")
			}
			if _, captured := invocation.ExecutionWorkspace(); captured {
				t.Fatal("live invocation acquired snapshot authority")
			}
			if claim := output.evidence[0].Receipts()[0].Claim(); claim.SourceIdentitySHA256() != identity.SHA256() || claim.TargetSHA256() != "" {
				t.Fatal("source evidence became captured evidence")
			}
		})
	}
}
