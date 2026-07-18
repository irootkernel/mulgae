package kar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/irootkernel/kkachi-agent-review/internal/adapters/environment"
	"github.com/irootkernel/kkachi-agent-review/internal/adapters/filesystem"
	"github.com/irootkernel/kkachi-agent-review/internal/adapters/gittarget"
	"github.com/irootkernel/kkachi-agent-review/internal/app"
	appdelta "github.com/irootkernel/kkachi-agent-review/internal/app/delta"
	appfollowup "github.com/irootkernel/kkachi-agent-review/internal/app/followup"
	"github.com/irootkernel/kkachi-agent-review/internal/builtin"
	"github.com/irootkernel/kkachi-agent-review/internal/domain"
)

func TestG008RealCompositionApplicationChildWorkflows(t *testing.T) {
	fixture := newG008RealE2EFixture(t)
	root := fixture.executeAndPublishRoot(t)
	before := fixture.inventorySnapshot(t)
	resolver, err := NewG008RequestResolver(fixture.root, fixture.queries, filesystem.NewRunSelector(fixture.root), bytes.NewBufferString("current.patch"))
	if err != nil {
		t.Fatal(err)
	}
	dependencies, err := NewG008Dependencies(G008Composition{
		Root: fixture.root, Queries: fixture.queries, RequestResolver: resolver, Clock: fixture.clock, IDs: fixture.ids, PublicationAuthority: fixture.store,
		ExportInstaller: mustG008RealExportInstaller(t, fixture),
		Online: &G008OnlineAuthority{
			FollowupTargetCapturer: g008RealFollowupCapturer{}, DeltaTargetCapturer: g008RealDeltaCapturer{}, DeltaComparator: g008RealComparator{},
			ChildExecutor: fixture.childExecutor, FollowupExecutor: fixture.followupExecutor, RerunAssignments: fixture.assignments[:1],
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	reader, err := gittarget.New(gittarget.NewExecRunner())
	if err != nil {
		t.Fatal(err)
	}
	application, err := NewApplication(Dependencies{
		Clock: fixture.clock, RequestIDGenerator: fixture.ids, RequestResolver: dependencies.RequestResolver, Catalog: builtin.NewCatalog(), JSONSchemaValidator: fixture.validator,
		SecureWriter: fixture.writer, TrustedProjectReader: reader, EnvironmentInspector: environment.NewInspector(),
		FollowupRuns: dependencies.FollowupRuns, DeltaRuns: dependencies.DeltaRuns, Reruns: dependencies.Reruns, Exports: dependencies.Exports,
	})
	if err != nil {
		t.Fatal(err)
	}
	childExits := make(map[string]app.ExitCode, 4)
	recomposeChildren := make(map[string]struct{})
	for _, test := range []struct {
		argv []string
		exit app.ExitCode
	}{
		{argv: []string{"followup", "--run", root.RunID.String(), "--finding", "F001", "--patch", "current.patch"}, exit: app.ExitCodePolicy},
		{argv: []string{"delta", "--since-run", root.RunID.String(), "--patch", "current.patch", "--roles", "logic,security"}, exit: app.ExitCodePolicy},
		{argv: []string{"rerun", "--run", root.RunID.String(), "--attempt", root.AttemptID.String(), "--replay", "exact"}, exit: app.ExitCodeReadiness},
		{argv: []string{"rerun", "--run", root.RunID.String(), "--attempt", root.AttemptID.String(), "--replay", "recompose"}, exit: app.ExitCodePolicy},
	} {
		result := application.Run(context.Background(), test.argv, fixture.root.String())
		if result.ExitCode() != test.exit {
			t.Fatalf("%v exit=%d, want %d; stdout=%q stderr=%q", test.argv, result.ExitCode(), test.exit, result.Stdout(), result.Stderr())
		}
		firstLine := strings.SplitN(strings.TrimSpace(string(result.Stdout())), "\n", 2)[0]
		separator := strings.LastIndex(firstLine, " ")
		if separator < 0 {
			t.Fatalf("%v omitted child run ID: %q", test.argv, firstLine)
		}
		runID := firstLine[separator+1:]
		if _, err := domain.ParseRunID(runID); err != nil {
			t.Fatalf("%v returned invalid child run ID %q: %v", test.argv, runID, err)
		}
		childExits[runID] = test.exit
		if test.argv[len(test.argv)-1] == "recompose" {
			recomposeChildren[runID] = struct{}{}
		}
	}
	after := fixture.inventorySnapshot(t)
	if len(after) <= len(before) {
		t.Fatal("child workflows did not install P2 artifacts")
	}
	for _, entry := range before {
		found := false
		for _, candidate := range after {
			if candidate.Path == entry.Path && candidate.SHA256 == entry.SHA256 && candidate.Bytes == entry.Bytes {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("root inventory entry changed: %#v", entry)
		}
	}
	transcript := fixture.provider.Transcript()
	if len(transcript) != 11 {
		t.Fatalf("provider calls=%d, want root(6), followup(1), delta(2), exact rerun(1), recompose rerun(1)", len(transcript))
	}
	wantPurposes := []string{
		"initial", "initial", "initial", "initial", "initial", "initial",
		"initial",
		"initial", "initial",
		"initial", "initial",
	}
	for index, want := range wantPurposes {
		if string(transcript[index].Purpose) != want || transcript[index].AttemptID.String() == "" || transcript[index].StdinSHA256 == "" {
			t.Fatalf("transcript[%d]=%#v, want purpose %q with actual identity", index, transcript[index], want)
		}
	}
	if transcript[1].AttemptID == root.AttemptID || transcript[6].AttemptID == root.AttemptID ||
		transcript[9].AttemptID == root.AttemptID || transcript[10].AttemptID == root.AttemptID {
		t.Fatal("security, followup, exact replay child, or recomposed replay child reused the root logic attempt identity")
	}
	if transcript[9].StdinSHA256 != transcript[0].StdinSHA256 {
		t.Fatal("exact replay child did not invoke the persisted source prompt exactly once")
	}
	if transcript[10].StdinSHA256 == transcript[0].StdinSHA256 {
		t.Fatal("recomposed replay child reused the persisted source prompt")
	}

	// Every returned child is a new P2 publication. Resolve the IDs from their
	// immutable run directories rather than relying on a scripted result value.
	candidates, _, err := filesystem.NewRunSelector(fixture.root).Enumerate(context.Background(), fixture.root)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 5 {
		t.Fatalf("P2 run count=%d, want root plus four children", len(candidates))
	}
	for _, candidate := range candidates {
		run, err := fixture.queries.ResolveRun(context.Background(), fixture.root, candidate.RunID)
		if err != nil {
			t.Fatal(err)
		}
		committed, err := fixture.queries.ReadCommitted(context.Background(), run)
		if err != nil {
			t.Fatalf("run %s committed read: %v", candidate.RunID, err)
		}
		if expectedExit, child := childExits[candidate.RunID.String()]; child {
			switch expectedExit {
			case app.ExitCodePolicy:
				if committed.ContentVerdict() != domain.ContentRequestChanges || committed.CIDecision() != domain.CIFail {
					t.Fatalf("followup child axes = (%q, %q), want request_changes/failed", committed.ContentVerdict(), committed.CIDecision())
				}
			case app.ExitCodeReadiness:
				if committed.CoverageStatus() != domain.CoverageIncomplete {
					t.Fatalf("rerun child coverage = %q, want incomplete", committed.CoverageStatus())
				}
			}
		}
		if _, recompose := recomposeChildren[candidate.RunID.String()]; recompose {
			roles := committed.Roles()
			if committed.CoverageStatus() != domain.CoverageComplete || len(roles) != 1 || roles[0].Name() != domain.RoleLogic {
				t.Fatalf("recompose child coverage/roles = (%q, %#v), want complete with one logic role", committed.CoverageStatus(), roles)
			}
			attempt, err := fixture.queries.ResolveCommittedAttempt(
				context.Background(), run, domain.RoleLogic, fixture.assignments[0].ProviderInstance(),
			)
			if err != nil {
				t.Fatalf("recompose child prompt receipt: %v", err)
			}
			receipt := attempt.Prompt()
			if receipt.Role() != domain.RoleLogic || receipt.ManifestPath().String() == "" ||
				receipt.ManifestSHA256() == "" || receipt.ExecutionInvocationID() == "" {
				t.Fatalf("recompose child persisted prompt receipt = %#v", receipt)
			}
		}
		if committed.FinalPath().String() == "" || committed.ManifestPath().String() == "" || committed.LineageEdgePath().String() == "" {
			t.Fatalf("run %s lacks real P2 receipt URIs", candidate.RunID)
		}
	}
}

func mustG008RealExportInstaller(t *testing.T, fixture *g008RealE2EFixture) *filesystem.ExportInstaller {
	t.Helper()
	installer, err := filesystem.NewExportInstaller(fixture.writer)
	if err != nil {
		t.Fatal(err)
	}
	return installer
}

type g008RealFollowupCapturer struct{}

func (g008RealFollowupCapturer) CaptureFollowupTarget(context.Context, appfollowup.Target) (appfollowup.CurrentTarget, error) {
	identity, err := domain.NewTargetIdentity(domain.TargetIdentityInput{Kind: domain.TargetPatch, SHA256: g008RealTargetHash([]byte("queueFallback(task)"))})
	if err != nil {
		return appfollowup.CurrentTarget{}, err
	}
	return appfollowup.CurrentTarget{Identity: identity, Bytes: []byte("queueFallback(task)")}, nil
}

type g008RealDeltaCapturer struct{}

func (g008RealDeltaCapturer) CaptureTarget(context.Context, appdelta.TargetRequest) (appdelta.ImmutableTarget, error) {
	return appdelta.NewByteImmutableTarget(appdelta.TargetPatch, "current.patch", []byte("queueFallback(task)"))
}

type g008RealComparator struct{}

func (g008RealComparator) Compare(context.Context, appdelta.ImmutableTarget, appdelta.ImmutableTarget) (appdelta.Delta, error) {
	return appdelta.Delta{Bytes: []byte("A/B")}, nil
}
func g008RealTargetHash(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}
