package kar

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/irootkernel/kkachi-agent-review/internal/adapters/filesystem"
	"github.com/irootkernel/kkachi-agent-review/internal/app/publication"
	"github.com/irootkernel/kkachi-agent-review/internal/domain"
)

func TestG008RequestResolverCaptureTargetFreezesOneBoundedRead(t *testing.T) {
	reader := &countingReader{Reader: bytes.NewBufferString("captured target")}
	resolver := &G008RequestResolver{reader: reader, stdinLimit: 64}
	first, err := resolver.CaptureTarget(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	readsAfterFirst := reader.reads
	second, err := resolver.CaptureTarget(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if first != "captured target" || second != first || readsAfterFirst == 0 || reader.reads != readsAfterFirst {
		t.Fatalf("captures = %q, %q; reads = %d", first, second, reader.reads)
	}
	frozen, ok := resolver.CapturedStdin()
	if !ok || string(frozen) != first {
		t.Fatalf("frozen stdin = %q, present = %v", frozen, ok)
	}
	frozen[0] = 'X'
	again, ok := resolver.CapturedStdin()
	if !ok || string(again) != first {
		t.Fatalf("captured stdin was mutable: %q", again)
	}
}

func TestG008RequestResolverCaptureTargetRejectsInvalidInput(t *testing.T) {
	for name, reader := range map[string]io.Reader{
		"empty":      bytes.NewReader(nil),
		"oversize":   bytes.NewBufferString("12345"),
		"read error": errorReader{},
	} {
		t.Run(name, func(t *testing.T) {
			maximum := int64(4)
			if name == "empty" || name == "read error" {
				maximum = 64
			}
			resolver := &G008RequestResolver{reader: reader, stdinLimit: maximum}
			if _, err := resolver.CaptureTarget(context.Background()); err == nil {
				t.Fatal("CaptureTarget succeeded")
			}
		})
	}
	resolver := &G008RequestResolver{reader: bytes.NewBufferString("input"), stdinLimit: 64}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := resolver.CaptureTarget(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("CaptureTarget error = %v, want cancellation", err)
	}
}
func TestG008RequestResolverLatestUsesCommittedManifestSelection(t *testing.T) {
	fixture := newG008RealE2EFixture(t)
	first := publishG008ResolverRun(t, fixture, 2)
	second := publishG008ResolverRun(t, fixture, 1)

	resolver, err := NewG008RequestResolver(fixture.root, fixture.queries, filesystem.NewRunSelector(fixture.root), strings.NewReader("target"))
	if err != nil {
		t.Fatal(err)
	}
	selected, err := resolver.ResolveRun(context.Background(), "latest")
	if err != nil {
		t.Fatal(err)
	}
	if selected != second.RunID.String() {
		t.Fatalf("latest = %s, want UUIDv7 tiebreak winner %s", selected, second.RunID)
	}

	manifestTime, err := committedCreatedAt(mustG008CommittedManifest(t, fixture, second))
	if err != nil {
		t.Fatal(err)
	}
	if !manifestTime.Equal(fixture.clock.now) {
		t.Fatalf("manifest created_at = %s, want %s", manifestTime, fixture.clock.now)
	}
	newer := latestCommittedRun{runID: first.RunID, createdAt: manifestTime.Add(time.Second)}
	current := latestCommittedRun{runID: second.RunID, createdAt: manifestTime}
	if !newer.after(current) {
		t.Fatal("newer manifest timestamp did not outrank UUIDv7")
	}

	for _, arguments := range [][]string{
		{"followup", "--run", "latest", "--finding", "F001", "--diff", "git"},
		{"delta", "--since-run", "latest", "--diff", "git", "--roles", "logic"},
		{"rerun", "--run", "latest", "--attempt", second.AttemptID.String()},
		{"export", "--run", "latest", "--output-path", "exports/review.zip"},
	} {
		invocation, parseErr := ParseResolved(context.Background(), arguments, testProjectRoot, testRequestID, resolver)
		if parseErr != nil {
			t.Fatalf("ParseResolved(%v): %v", arguments, parseErr)
		}
		request, ok := invocation.RequestJSON()
		if !ok || !strings.Contains(string(request), second.RunID.String()) {
			t.Fatalf("ParseResolved(%v) did not freeze selected run %s: %s", arguments, second.RunID, request)
		}
	}
}

func TestG008RequestResolverLatestSkipsCorruptP2Manifest(t *testing.T) {
	fixture := newG008RealE2EFixture(t)
	first := publishG008ResolverRun(t, fixture, 2)
	second := publishG008ResolverRun(t, fixture, 1)
	corruptG008Manifest(t, fixture, second)

	resolver, err := NewG008RequestResolver(fixture.root, fixture.queries, filesystem.NewRunSelector(fixture.root), strings.NewReader("target"))
	if err != nil {
		t.Fatal(err)
	}
	selected, err := resolver.ResolveRun(context.Background(), "latest")
	if err != nil {
		t.Fatal(err)
	}
	if selected != first.RunID.String() {
		t.Fatalf("latest = %s, want surviving P2 run %s", selected, first.RunID)
	}
	if len(resolver.Diagnostics()) == 0 {
		t.Fatal("corrupt P2 candidate was excluded without a diagnostic")
	}

	corruptG008Manifest(t, fixture, first)
	if _, err := resolver.ResolveRun(context.Background(), "latest"); err == nil || !strings.Contains(err.Error(), "no P2 committed candidates") {
		t.Fatalf("ResolveRun with only corrupt manifests error = %v", err)
	}
}

func TestCommittedCreatedAtRejectsNoncanonicalManifestTimestamp(t *testing.T) {
	for _, timestamp := range []string{
		"2026-07-14T12:00:00+00:00",
		"2026-07-14T12:00:00.1000Z",
		"2026-07-14T12:00:00Z ",
		"not-a-timestamp",
	} {
		if _, err := committedCreatedAt([]byte(`{"created_at":"` + timestamp + `"}`)); err == nil {
			t.Fatalf("committedCreatedAt(%q) succeeded", timestamp)
		}
	}
	if _, err := committedCreatedAt([]byte(`{"created_at":"2026-07-14T12:00:00.1Z"}`)); err != nil {
		t.Fatalf("canonical manifest timestamp rejected: %v", err)
	}
}

func mustG008CommittedManifest(t *testing.T, fixture *g008RealE2EFixture, result g008RealE2ERootResult) []byte {
	t.Helper()
	run, err := fixture.queries.ResolveRun(context.Background(), fixture.root, result.RunID)
	if err != nil {
		t.Fatal(err)
	}
	review, err := fixture.queries.ReadCommitted(context.Background(), run)
	if err != nil {
		t.Fatal(err)
	}
	return review.ManifestBytes()
}

func corruptG008Manifest(t *testing.T, fixture *g008RealE2EFixture, result g008RealE2ERootResult) {
	t.Helper()
	path := filepath.Join(fixture.root.String(), result.SessionID.String(), result.RunID.String(), "manifest.json")
	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
}
func publishG008ResolverRun(t *testing.T, fixture *g008RealE2EFixture, epoch uint64) g008RealE2ERootResult {
	t.Helper()
	result, err := fixture.coordinator.Execute(context.Background(), fixture.target, fixture.assignments, domain.SeverityHigh, nil)
	if err != nil {
		t.Fatal(err)
	}
	inventory := fixture.runtime.DrainRuntimeArtifactsForRun(result.RunID())
	candidate, err := publication.PrepareCandidateWithRuntimeArtifacts(result, fixture.target, domain.SeverityHigh, "g008-test", "g008-test", publication.RunPublicationContext{}, inventory)
	if err != nil {
		t.Fatal(err)
	}
	published, err := fixture.publisher.Publish(context.Background(), fixture.root, candidate, epoch)
	if err != nil {
		t.Fatal(err)
	}
	issued, ok := published.IssuedReviewID()
	if !ok {
		t.Fatal("root publication did not issue a review ID")
	}
	transcript := fixture.provider.Transcript()
	if len(transcript) == 0 {
		t.Fatal("root publication did not invoke a provider")
	}
	return g008RealE2ERootResult{
		SessionID: result.SessionID(),
		RunID:     result.RunID(),
		ReviewID:  issued.ReviewID(),
		AttemptID: transcript[0].AttemptID,
		Queries:   fixture.queries,
	}
}

type countingReader struct {
	io.Reader
	reads int
}

func (reader *countingReader) Read(value []byte) (int, error) {
	reader.reads++
	return reader.Reader.Read(value)
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, errors.New("read failed") }
