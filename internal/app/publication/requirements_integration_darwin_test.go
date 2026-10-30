//go:build darwin && arm64

package publication

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/adapters/filesystem"
	"github.com/irootkernel/mulgae/internal/adapters/gittarget"
	"github.com/irootkernel/mulgae/internal/app/evidence"
	"github.com/irootkernel/mulgae/internal/app/validation"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

func TestIntegrationRequirementsPublicationRecoversAndDetectsCorruption(t *testing.T) {
	ctx := context.Background()
	rootPath := os.Getenv("MULGAE_TEST_REQUIREMENTS_PUBLICATION_ROOT")
	child := rootPath != ""
	if !child {
		rootPath = t.TempDir()
	}
	rootPath, err := filepath.EvalSymlinks(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	root, _ := ports.NewAnchoredRoot(rootPath)
	schema := mustSharedPublicationTestValidator(t)
	clock := publicationServiceClock{now: publicationTestTime()}
	id := publicationTestReviewID(t)
	store, err := filesystem.NewPublicationStore(schema, clock, compositeTestIDs{id}, filesystem.NewSecureWriter())
	if err != nil {
		t.Fatal(err)
	}
	candidate := requirementsNoChangeCandidate(t, true)
	if _, err := candidate.Build(ctx, schema, id, clock.now, 1); err != nil {
		for cause := err; cause != nil; cause = errors.Unwrap(cause) {
			t.Logf("%T: %v", cause, cause)
		}
		t.Fatalf("build v4 candidate: %v", err)
	}
	if child {
		service, _ := NewService(&compositeInterruptedStore{PublicationStore: store, after: -2}, schema, clock, 8<<20)
		_, err := service.PublishLiveNext(ctx, root, candidate)
		t.Fatalf("expected process interruption: %v", err)
	}
	command := exec.Command(os.Args[0], "-test.run=^TestIntegrationRequirementsPublicationRecoversAndDetectsCorruption$")
	command.Env = append(os.Environ(), "MULGAE_TEST_REQUIREMENTS_PUBLICATION_ROOT="+rootPath)
	output, err := command.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 73 {
		t.Fatalf("interrupted publisher: %v\n%s", err, output)
	}
	service, _ := NewService(store, schema, clock, 8<<20)
	run, _ := ports.NewPublicationRun(root, candidate.SessionID(), candidate.RunID())
	result, err := service.Recover(ctx, run)
	if err != nil {
		t.Fatalf("restart recovery: %v", err)
	}
	final, ok := result.Final()
	if !ok || result.Decision().Authority() != domain.PublicationAuthorityP2 {
		t.Fatal("missing P2")
	}
	again, err := service.Recover(ctx, run)
	same, _ := again.Final()
	if err != nil || same != final {
		t.Fatal("restart changed the one final")
	}
	prefix := filepath.Join(root.String(), candidate.SessionID().String(), candidate.RunID().String())
	matches, err := filepath.Glob(filepath.Join(prefix, "review*.json"))
	if err != nil || len(matches) != 1 {
		t.Fatalf("final count: %v %v", matches, err)
	}
	if err := os.Remove(filepath.Join(prefix, "requirements", "items", "000.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Recover(ctx, run); err == nil {
		t.Fatal("missing hash-bound content downgraded to historical absence")
	}
}

func TestIntegrationRequirementsOrdinaryPublicationRecoversWithoutSource(t *testing.T) {
	ctx := context.Background()
	directory := os.Getenv("MULGAE_TEST_REQUIREMENTS_ORDINARY_ROOT")
	child := directory != ""
	if !child {
		directory = t.TempDir()
		if err := os.Mkdir(filepath.Join(directory, "source"), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, "source", "source.go"), []byte("observed\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, "source", "diagram.png"), []byte{137, 80, 78, 71, 13, 10, 26, 10, 0}, 0600); err != nil {
			t.Fatal(err)
		}
	}
	directory, err := filepath.EvalSymlinks(directory)
	if err != nil {
		t.Fatal(err)
	}
	sourceRoot, _ := ports.NewAnchoredRoot(filepath.Join(directory, "source"))
	selector, _ := ports.NewLiveSourceSelector(domain.LiveSourceWorkspace, "")
	opener, _ := gittarget.NewLiveSourceAdapter(gittarget.ExecRunner{}, nil)
	source, err := opener.OpenLiveSource(ctx, sourceRoot, selector)
	if err != nil {
		t.Fatal(err)
	}
	schema := mustSharedPublicationTestValidator(t)
	candidateInput, _ := livePublicationChangedInput(t, source, schema)
	candidate, err := PrepareLiveCandidate(candidateInput)
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte(`{"schema_version":"mulgae-requirements-input.v1","requirements":[{"id":"A","text":"Explicit requirement","acceptance_criteria":["criterion"],"owner_role":"logic"}]}`)
	admitted, err := validation.DecodeRequirementsInput(raw, []domain.Role{domain.RoleLogic})
	if err != nil {
		t.Fatal(err)
	}
	identity, _ := evidence.NewLiveSourceIdentity(source.Target())
	verifier, _ := evidence.NewLiveVerifier(source)
	section, _ := json.Marshal(map[string]any{"schema_version": "mulgae-provider-requirements.v1", "assessments": []any{map[string]any{"requirement_id": "A", "verdict": "met", "rationale": strings.Repeat("r", 9<<20), "evidence": []any{map[string]any{"current": map[string]any{"path": "source.go", "side": "worktree", "line_start": 1, "line_end": 1, "quote": "observed\n"}}}, "examined_scope": "source.go", "limitations": []string{"Runtime behavior was not executed."}, "reason": ""}}})
	answers, err := validation.DecodeProviderRequirements(ctx, section, admitted.Requirements(), domain.RoleLogic, identity, verifier, nil, "requirements.json", admitted.SHA256())
	if err != nil {
		t.Fatal(err)
	}
	normalized, err := validation.NormalizeRequirements(admitted, answers, nil, identity.SHA256(), false)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err = WithRequirements(candidate, normalized)
	if err != nil {
		t.Fatal(err)
	}
	if err := source.Close(); err != nil {
		t.Fatal(err)
	}
	artifactDirectory := filepath.Join(directory, "artifacts")
	if err := os.MkdirAll(artifactDirectory, 0700); err != nil {
		t.Fatal(err)
	}
	root, _ := ports.NewAnchoredRoot(artifactDirectory)
	clock := publicationServiceClock{now: publicationTestTime()}
	id := publicationTestReviewID(t)
	store, err := filesystem.NewPublicationStore(schema, clock, compositeTestIDs{id}, filesystem.NewSecureWriter())
	if err != nil {
		t.Fatal(err)
	}
	if child {
		publisher, _ := NewService(&compositeInterruptedStore{PublicationStore: store, after: -2}, schema, clock, 8<<20)
		_, err := publisher.PublishLiveNext(ctx, root, candidate)
		t.Fatalf("expected process interruption: %v", err)
	}
	command := exec.Command(os.Args[0], "-test.run=^TestIntegrationRequirementsOrdinaryPublicationRecoversWithoutSource$")
	command.Env = append(os.Environ(), "MULGAE_TEST_REQUIREMENTS_ORDINARY_ROOT="+directory)
	output, err := command.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 73 {
		t.Fatalf("interrupted ordinary publisher: %v\n%s", err, output)
	}
	if err := os.RemoveAll(sourceRoot.String()); err != nil {
		t.Fatal(err)
	}
	publisher, _ := NewService(store, schema, clock, 8<<20)
	run, _ := ports.NewPublicationRun(root, candidate.SessionID(), candidate.RunID())
	result, err := publisher.Recover(ctx, run)
	if err != nil {
		t.Fatalf("ordinary restart with source unavailable: %v", err)
	}
	first, ok := result.Final()
	if !ok || result.Decision().Authority() != domain.PublicationAuthorityP2 {
		t.Fatal("ordinary recovery omitted P2")
	}
	again, err := publisher.Recover(ctx, run)
	second, _ := again.Final()
	if err != nil || first != second {
		t.Fatal("ordinary restart changed the one final")
	}
	path := filepath.Join(root.String(), candidate.SessionID().String(), candidate.RunID().String(), "requirements", "items", "000.json")
	content, err := os.ReadFile(path)
	if err != nil || len(content) <= 8<<20 {
		t.Fatal("large verified content was lost")
	}
	if err := os.WriteFile(path, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.Recover(ctx, run); err == nil {
		t.Fatal("ordinary content tamper accepted or reconstructed from current source")
	}
}
