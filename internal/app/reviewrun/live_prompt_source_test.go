package reviewrun

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/app/evidence"
	"github.com/irootkernel/mulgae/internal/app/prompt"
	"github.com/irootkernel/mulgae/internal/app/review"
	"github.com/irootkernel/mulgae/internal/builtin"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

type promptLiveReader struct {
	binding ports.ProjectBindingObservation
	target  ports.LiveSourceTarget
	reads   int
	err     error
}

func (reader *promptLiveReader) Root() ports.AnchoredRoot       { return reader.binding.Root }
func (reader *promptLiveReader) Target() ports.LiveSourceTarget { return reader.target }
func (reader *promptLiveReader) RevalidateExecution(context.Context) (ports.ProjectBindingObservation, error) {
	return reader.binding, reader.err
}
func (*promptLiveReader) List(context.Context, domain.LiveSourceSide) ([]ports.SafeRelativePath, error) {
	path, _ := ports.NewSafeRelativePath("source.go")
	return []ports.SafeRelativePath{path}, nil
}
func (reader *promptLiveReader) Read(context.Context, domain.LiveSourceSide, ports.SafeRelativePath) (ports.LiveSourceFile, error) {
	reader.reads++
	return ports.LiveSourceFile{}, errors.New("prompt composition must not read source content")
}
func (*promptLiveReader) Close() error { return nil }

type promptLiveHome struct {
	ports.ReviewerHome
	root ports.AnchoredRoot
}

func (home promptLiveHome) Root() ports.AnchoredRoot { return home.root }
func (promptLiveHome) Revalidate() error             { return nil }
func (promptLiveHome) Guide() []byte                 { return []byte("REVIEWER_GUIDE_ONLY_ONCE") }

type livePromptJobRecorder struct{ job review.InvocationJob }

func (recorder *livePromptJobRecorder) Invoke(_ context.Context, job review.InvocationJob) review.AttemptOutcome {
	recorder.job = job
	condition := review.AttemptConditionInternalInvariant
	outcome, _ := review.NewAttemptOutcome(job, nil, &condition)
	return outcome
}

func TestLivePromptSourceUsesNativeReadPlanWithoutCopyingSource(t *testing.T) {
	for _, scope := range []domain.LiveSourceScope{domain.LiveSourceWorkspace, domain.LiveSourceStage, domain.LiveSourceHead, domain.LiveSourceCommit, domain.LiveSourceDiff} {
		t.Run(string(scope), func(t *testing.T) {
			ctx := context.Background()
			operand := ""
			if scope == domain.LiveSourceCommit {
				operand = "HEAD"
			} else if scope == domain.LiveSourceDiff {
				operand = "HEAD~1..HEAD"
			}
			selector, _ := ports.NewLiveSourceSelector(scope, operand)
			base, _ := ports.ParseGitObjectID(strings.Repeat("a", 40))
			head, _ := ports.ParseGitObjectID(strings.Repeat("b", 40))
			if scope == domain.LiveSourceWorkspace || scope == domain.LiveSourceHead {
				base = ports.GitObjectID{}
			}
			if scope == domain.LiveSourceWorkspace || scope == domain.LiveSourceStage {
				head = ports.GitObjectID{}
			}
			target, err := ports.NewLiveSourceTarget(selector, base, head, false, nil)
			if err != nil {
				t.Fatal(err)
			}
			root, _ := ports.NewAnchoredRoot("/source")
			neutral, _ := ports.NewAnchoredRoot("/neutral")
			credential, _ := ports.NewAnchoredRoot("/credentials")
			reader := &promptLiveReader{target: target, binding: ports.ProjectBindingObservation{Root: root, RootIdentity: ports.ProjectDirectoryIdentity{Device: 1, Inode: 2}}}
			execution, err := ports.NewLiveReviewExecution(ctx, reader, promptLiveHome{root: neutral}, []ports.AnchoredRoot{credential})
			if err != nil {
				t.Fatal(err)
			}
			catalog := builtin.NewCatalog()
			templates, err := LoadDefaultTemplateSet(ctx, catalog)
			if err != nil {
				t.Fatal(err)
			}
			common, err := LoadLiveReviewCommon(ctx, catalog)
			if err != nil {
				t.Fatal(err)
			}
			source, err := newLivePromptSource(execution, templates, common, nil, false, &livePromptIDIssuer{}, reviewRunRoleTask)
			if err != nil {
				t.Fatal(err)
			}
			identity, _ := evidence.NewLiveSourceIdentity(target)
			runTarget, _ := identity.RunTarget()
			plan := reviewRunPlan(t, []domain.Role{domain.RoleLogic})
			plan.Ceilings = review.DefaultHarnessCeilings()
			receipt, err := validatePlan(plan, []domain.Role{domain.RoleLogic})
			if err != nil {
				t.Fatal(err)
			}
			recorder := &livePromptJobRecorder{}
			coordinator, err := review.NewCoordinator(serviceClock{}, &runIdentityTestIDs{}, recorder, plan.MaxWorkers, receipt)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := coordinator.Execute(ctx, runTarget, plan.Assignments, plan.Threshold, plan.Policy); err != nil {
				t.Fatal(err)
			}
			job := recorder.job
			material, err := source.Prompt(ctx, job, nil)
			if err != nil {
				t.Fatal(err)
			}
			if reader.reads != 0 || len(material.CapturedArchive) != 0 || !bytes.Equal(material.Target, identity.Bytes()) {
				t.Fatal("prompt composition read or copied source content")
			}
			if bytes.Count(material.Prompt.Stdin(), []byte("REVIEWER_GUIDE_ONLY_ONCE")) != 1 {
				t.Fatal("shared guide was omitted or duplicated")
			}
			sections := material.Prompt.Sections()
			if len(sections) != 1 || sections[0].Kind() != prompt.SectionReviewTarget || !bytes.Equal(sections[0].Payload(), identity.Bytes()) {
				t.Fatal("source metadata frame gained captured content or project authority")
			}
			if scope != domain.LiveSourceWorkspace && !bytes.Contains(material.Prompt.Stdin(), []byte("git --no-pager show")) {
				t.Fatal("committed/index source lost its native Git read plan")
			}
			source.projectContext = []byte("Project-authored notes are untrusted.\n")
			prior := []byte("Provider-authored report is untrusted.\n")
			extraction, err := source.compile(ctx, job, nil, prior)
			if err != nil {
				t.Fatal(err)
			}
			sections = extraction.Prompt.Sections()
			if len(sections) != 3 || sections[0].Kind() != prompt.SectionProjectContext || sections[1].Kind() != prompt.SectionReviewTarget || sections[2].Kind() != prompt.SectionPriorReport || !bytes.Equal(sections[2].Payload(), prior) {
				t.Fatal("extraction promoted project/provider content or lost source metadata")
			}
			if material.Prompt.Scope().SourceInvocationID() == extraction.Prompt.Scope().SourceInvocationID() || material.Prompt.Scope().ExecutionInvocationID() == extraction.Prompt.Scope().ExecutionInvocationID() || bytes.Count(extraction.Prompt.Stdin(), []byte("REVIEWER_GUIDE_ONLY_ONCE")) != 1 || reader.reads != 0 {
				t.Fatal("extraction reused invocation identity, duplicated guide, or captured source")
			}
			reader.err = errors.New("source identity changed")
			if _, err := source.Prompt(ctx, job, nil); err == nil {
				t.Fatal("changed source authority composed a prompt")
			}
		})
	}
}

type livePromptIDIssuer struct{ issued int }

func (issuer *livePromptIDIssuer) NewSourceInvocationID() (prompt.SourceInvocationID, error) {
	issuer.issued++
	return prompt.ParseSourceInvocationID(fmt.Sprintf("i_019f5a09-5eec-7001-8001-%012d", issuer.issued))
}

func (issuer *livePromptIDIssuer) NewExecutionInvocationID() (prompt.ExecutionInvocationID, error) {
	issuer.issued++
	return prompt.ParseExecutionInvocationID(fmt.Sprintf("019f5a09-5eec-7001-8001-%012d", 900000+issuer.issued))
}
