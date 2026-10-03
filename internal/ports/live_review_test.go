package ports

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/domain"
)

type liveExecutionSource struct {
	binding ProjectBindingObservation
	target  LiveSourceTarget
	sides   []domain.LiveSourceSide
	err     error
}

func (source *liveExecutionSource) Root() AnchoredRoot       { return source.binding.Root }
func (source *liveExecutionSource) Target() LiveSourceTarget { return source.target }
func (source *liveExecutionSource) RevalidateExecution(context.Context) (ProjectBindingObservation, error) {
	return source.binding, source.err
}
func (source *liveExecutionSource) List(_ context.Context, side domain.LiveSourceSide) ([]SafeRelativePath, error) {
	source.sides = append(source.sides, side)
	path, _ := NewSafeRelativePath("file 'quoted'.go")
	return []SafeRelativePath{path}, nil
}
func (*liveExecutionSource) Read(context.Context, domain.LiveSourceSide, SafeRelativePath) (LiveSourceFile, error) {
	return LiveSourceFile{}, errors.New("unexpected file read")
}
func (*liveExecutionSource) Close() error { return nil }

type liveExecutionHome struct {
	ReviewerHome
	root AnchoredRoot
	err  error
}

func (home *liveExecutionHome) Root() AnchoredRoot { return home.root }
func (home *liveExecutionHome) Revalidate() error  { return home.err }

func TestLiveReviewExecutionReadsExactSidesAndPreservesInvocation(t *testing.T) {
	for _, scope := range []domain.LiveSourceScope{domain.LiveSourceWorkspace, domain.LiveSourceStage, domain.LiveSourceHead, domain.LiveSourceCommit, domain.LiveSourceDiff} {
		t.Run(string(scope), func(t *testing.T) {
			value := ""
			if scope == domain.LiveSourceCommit {
				value = "HEAD"
			}
			if scope == domain.LiveSourceDiff {
				value = "HEAD~1..HEAD"
			}
			selector, _ := NewLiveSourceSelector(scope, value)
			oid, _ := ParseGitObjectID(strings.Repeat("a", 40))
			base, head := oid, oid
			switch scope {
			case domain.LiveSourceWorkspace:
				base, head = GitObjectID{}, GitObjectID{}
			case domain.LiveSourceStage:
				head = GitObjectID{}
			case domain.LiveSourceHead:
				base = GitObjectID{}
			}
			target, err := NewLiveSourceTarget(selector, base, head, false, nil)
			if err != nil {
				t.Fatal(err)
			}
			root, _ := NewAnchoredRoot("/source")
			neutral, _ := NewAnchoredRoot("/neutral")
			credential, _ := NewAnchoredRoot("/credentials")
			source := &liveExecutionSource{target: target, binding: ProjectBindingObservation{Root: root, RootIdentity: ProjectDirectoryIdentity{Device: 1, Inode: 2}}}
			home := &liveExecutionHome{root: neutral}
			credentials := []AnchoredRoot{credential}
			execution, err := NewLiveReviewExecution(context.Background(), source, home, credentials)
			if err != nil {
				t.Fatal(err)
			}
			wanted := []domain.LiveSourceSide{domain.LiveSourceBefore, domain.LiveSourceAfter}
			switch scope {
			case domain.LiveSourceWorkspace:
				wanted = []domain.LiveSourceSide{domain.LiveSourceWorktree}
			case domain.LiveSourceStage:
				wanted[1] = domain.LiveSourceIndex
			case domain.LiveSourceHead:
				wanted = []domain.LiveSourceSide{domain.LiveSourceAfter}
			}
			if !reflect.DeepEqual(source.sides, wanted) {
				t.Fatalf("read plan sides=%v want=%v", source.sides, wanted)
			}
			for _, read := range execution.Reads() {
				if scope == domain.LiveSourceWorkspace && read.GitCommand() != "" {
					t.Fatal("workspace acquired committed read")
				}
				if scope != domain.LiveSourceWorkspace && !strings.Contains(read.GitCommand(), "'\"'\"'") {
					t.Fatal("quoted Git operand was not safely encoded")
				}
				if read.Side() == domain.LiveSourceIndex && !strings.HasPrefix(read.GitCommand(), "git --no-pager show ':") {
					t.Fatal("stage read substituted committed bytes")
				}
			}
			credentials[0] = AnchoredRoot{}
			execution.CredentialRoots()[0] = AnchoredRoot{}
			reads := execution.Reads()
			reads[0] = LiveSourceRead{}
			if execution.CredentialRoots()[0] != credential || !execution.Reads()[0].Path().Valid() {
				t.Fatal("execution exposed mutable authority")
			}
			original := newProviderInvocation(t, []byte("sealed live packet"))
			invocation, err := NewProviderInvocationInLiveSource(original, execution)
			if err != nil {
				t.Fatal(err)
			}
			canonical, err := canonicalProviderInvocation(invocation)
			if err != nil {
				t.Fatal(err)
			}
			retained, ok := canonical.LiveExecution()
			if !ok || retained.Binding() != execution.Binding() || canonical.InputIdentity() != original.InputIdentity() || canonical.ExecutionInvocationID() != original.ExecutionInvocationID() || canonical.SourceInvocationID() != original.SourceInvocationID() {
				t.Fatal("canonical invocation lost live or packet identity")
			}
			if _, ok := original.LiveExecution(); ok {
				t.Fatal("original invocation mutated")
			}
			if _, err := NewProviderInvocationInLiveSource(invocation, execution); err == nil {
				t.Fatal("duplicate live authority admitted")
			}
			source.binding.RootIdentity.Inode++
			if execution.Revalidate(context.Background()) == nil {
				t.Fatal("replaced source binding admitted")
			}
		})
	}
}

func TestLiveReviewExecutionRejectsCredentialOverlap(t *testing.T) {
	for _, test := range []struct{ name, source, home, credential string }{
		{"source-equal", "/parent/source", "/parent/home", "/parent/source"},
		{"source-contained", "/parent/source/sub", "/parent/home", "/parent/source"},
		{"home-equal", "/parent/source", "/parent/home", "/parent/home"},
		{"home-contained", "/parent/source", "/parent/home/sub", "/parent/home"},
	} {
		t.Run(test.name, func(t *testing.T) {
			root, _ := NewAnchoredRoot(test.source)
			neutral, _ := NewAnchoredRoot(test.home)
			credentials, _ := NewAnchoredRoot(test.credential)
			source := &liveExecutionSource{binding: ProjectBindingObservation{Root: root, RootIdentity: ProjectDirectoryIdentity{Device: 1, Inode: 2}}}
			home := &liveExecutionHome{root: neutral}
			if _, err := NewLiveReviewExecution(context.Background(), source, home, []AnchoredRoot{credentials}); err == nil || !strings.Contains(err.Error(), "credential boundary") {
				t.Fatalf("overlapping credential root admitted: %v", err)
			}
			if len(source.sides) != 0 {
				t.Fatal("invalid credential authority reached source reads")
			}
		})
	}
}

func TestLiveReviewExecutionRejectsMissingAndIncompatibleAuthority(t *testing.T) {
	if _, err := NewLiveReviewExecution(context.Background(), nil, nil, nil); err == nil {
		t.Fatal("missing authority admitted")
	}
	if _, err := NewProviderInvocationInLiveSource(newProviderInvocation(t, []byte("packet")), LiveReviewExecution{}); err == nil {
		t.Fatal("zero live execution admitted")
	}
}

func TestLiveReviewExecutionRejectsUnrepresentablePolicyRoots(t *testing.T) {
	root, _ := NewAnchoredRoot("/source")
	neutral, _ := NewAnchoredRoot("/neutral")
	credential, _ := NewAnchoredRoot("/credentials")
	unsafe, _ := NewAnchoredRoot("/unsafe\u2028")
	for _, role := range []string{"source", "neutral", "credential", "git", "common"} {
		t.Run(role, func(t *testing.T) {
			source := &liveExecutionSource{binding: ProjectBindingObservation{Root: root, RootIdentity: ProjectDirectoryIdentity{Device: 1, Inode: 2}}}
			home := &liveExecutionHome{root: neutral}
			credentials := []AnchoredRoot{credential}
			switch role {
			case "source":
				source.binding.Root = unsafe
			case "neutral":
				home.root = unsafe
			case "credential":
				credentials[0] = unsafe
			case "git":
				source.binding.GitDirectory = unsafe
			case "common":
				source.binding.CommonDirectory = unsafe
			}
			if _, err := NewLiveReviewExecution(context.Background(), source, home, credentials); err == nil {
				t.Fatal("unrepresentable root reached provider-independent execution authority")
			}
			if len(source.sides) != 0 {
				t.Fatal("unsafe policy input reached source reads")
			}
		})
	}
}
