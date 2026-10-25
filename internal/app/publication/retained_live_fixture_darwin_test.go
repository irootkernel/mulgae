//go:build darwin && arm64

package publication

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/adapters/gittarget"
	"github.com/irootkernel/mulgae/internal/adapters/jsonschema"
	"github.com/irootkernel/mulgae/internal/app/evidence"
	"github.com/irootkernel/mulgae/internal/app/review"
	"github.com/irootkernel/mulgae/internal/builtin"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

func retainedLiveChangedInput(t *testing.T, source ports.LiveSourceReader, schema *jsonschema.Validator) (LiveCandidateInput, *livePublicationRuntime) {
	t.Helper()
	identity, err := evidence.NewLiveSourceIdentity(source.Target())
	if err != nil {
		t.Fatal(err)
	}
	target, _ := identity.RunTarget()
	var assignments []review.Assignment
	var budgets []review.RoleBudget
	for i, role := range []domain.Role{domain.RoleLogic, domain.RoleSecurity} {
		route, _ := ports.NewProviderRoute([]string{"zcode-logic", "grok-security"}[i])
		assignment, _ := review.NewScheduledAssignment(role, true, route)
		assignments = append(assignments, assignment)
		limits, _ := review.NewInvocationLimits(time.Second)
		routeBudget, _ := review.NewRouteBudget(route, limits)
		budget, _ := review.NewRoleBudget(role, routeBudget)
		budgets = append(budgets, budget)
	}
	budget, err := review.PreflightRunBudgetWithCapacity(budgets, review.DefaultHarnessCeilings(), 1)
	if err != nil {
		t.Fatal(err)
	}
	runtime := &livePublicationRuntime{source: source, schema: schema, testing: t}
	coordinator, err := review.NewCoordinator(publicationServiceClock{now: publicationTestTime()}, &failedRecoveryIDs{}, runtime, 1, budget)
	if err != nil {
		t.Fatal(err)
	}
	result, err := coordinator.Execute(context.Background(), target, assignments, domain.SeverityHigh, nil)
	if err != nil {
		t.Fatal(err)
	}
	verifier, _ := evidence.NewLiveVerifier(source)
	imagePath, _ := ports.NewSafeRelativePath("diagram.png")
	image, err := verifier.VerifyBinary(context.Background(), evidence.SideWorktree, imagePath, sha256Identifier([]byte{137, 80, 78, 71, 13, 10, 26, 10, 0}))
	if err != nil {
		t.Fatal(err)
	}
	return LiveCandidateInput{Result: result, Target: source.Target(), SeverityThreshold: domain.SeverityHigh, BinaryEvidence: []evidence.LiveBinaryReceipt{image}, Provenance: LiveProductionProvenance{BuildProduct: "mulgae", BuildVersion: "0.1.0", BuildCommit: "0123456789abcdef", SourceIdentitySHA256: identity.SHA256(), SourceTerminalReceipt: "source-terminal:v1:" + sha256Identifier([]byte("closed source")), Providers: retainedProviderProvenance()}}, runtime
}

func retainedLiveChangedFixture(t *testing.T) PreparedLiveCandidate {
	t.Helper()
	rootPath := t.TempDir()
	for path, data := range map[string][]byte{
		"source.go":   []byte("observed\n"),
		"diagram.png": {137, 80, 78, 71, 13, 10, 26, 10, 0},
	} {
		if err := os.WriteFile(filepath.Join(rootPath, path), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	root, err := ports.NewAnchoredRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	opener, err := gittarget.NewLiveSourceAdapter(gittarget.ExecRunner{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	selector, err := ports.NewLiveSourceSelector(domain.LiveSourceWorkspace, "")
	if err != nil {
		t.Fatal(err)
	}
	source, err := opener.OpenLiveSource(context.Background(), root, selector)
	if err != nil {
		t.Fatal(err)
	}
	schema, err := jsonschema.New(context.Background(), builtin.NewCatalog())
	if err != nil {
		t.Fatal(err)
	}
	input, _ := retainedLiveChangedInput(t, source, schema)
	candidate, err := PrepareLiveCandidate(input)
	if err != nil {
		t.Fatal(err)
	}
	if err := source.Close(); err != nil {
		t.Fatal(err)
	}
	return candidate
}

func retainedLiveChangedWithAttemptsFixture(t *testing.T) PreparedLiveCandidate {
	t.Helper()
	rootPath := t.TempDir()
	for path, data := range map[string][]byte{
		"source.go":   []byte("observed\n"),
		"diagram.png": {137, 80, 78, 71, 13, 10, 26, 10, 0},
	} {
		if err := os.WriteFile(filepath.Join(rootPath, path), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	root, err := ports.NewAnchoredRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	opener, err := gittarget.NewLiveSourceAdapter(gittarget.ExecRunner{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	selector, err := ports.NewLiveSourceSelector(domain.LiveSourceWorkspace, "")
	if err != nil {
		t.Fatal(err)
	}
	source, err := opener.OpenLiveSource(context.Background(), root, selector)
	if err != nil {
		t.Fatal(err)
	}
	schema, err := jsonschema.New(context.Background(), builtin.NewCatalog())
	if err != nil {
		t.Fatal(err)
	}
	input, _ := retainedLiveChangedInput(t, source, schema)
	base, err := PrepareLiveCandidate(input)
	if err != nil {
		t.Fatal(err)
	}
	var attempts []AttemptArtifactInput
	for _, role := range base.candidate.roles {
		for _, attempt := range role.attempts {
			for _, invocation := range attempt.invocations {
				stdout, err := ports.NewCapturedAttemptArtifact(ports.AttemptArtifactStdout, []byte("provider stdout for "+string(role.role)+"\n"), false)
				if err != nil {
					t.Fatal(err)
				}
				attempts = append(attempts, AttemptArtifactInput{AttemptID: attempt.id, InvocationSequence: invocation.sequence, Artifact: stdout})
				if invocation.purpose == domain.InvocationInitial {
					initial, err := ports.NewCapturedAttemptArtifact(ports.AttemptArtifactInitialCandidate, []byte(`{"candidate":"`+string(role.role)+`"}`), false)
					if err != nil {
						t.Fatal(err)
					}
					attempts = append(attempts, AttemptArtifactInput{AttemptID: attempt.id, InvocationSequence: invocation.sequence, Artifact: initial})
				}
			}
		}
	}
	if len(attempts) == 0 {
		t.Fatal("live fixture produced no attempt invocations to bind")
	}
	input.AttemptArtifacts = attempts
	candidate, err := PrepareLiveCandidate(input)
	if err != nil {
		t.Fatal(err)
	}
	if err := source.Close(); err != nil {
		t.Fatal(err)
	}
	return candidate
}
