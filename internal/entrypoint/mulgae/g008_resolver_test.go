package mulgae

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/adapters/filesystem"
	"github.com/irootkernel/mulgae/internal/app/publication"
	"github.com/irootkernel/mulgae/internal/domain"
)

func TestG008RequestResolverCapturedStdinTransfersOnceAndZerosOwnedBytes(t *testing.T) {
	input := []byte("first line\nsecond line\n")
	reader := &countingReader{Reader: bytes.NewReader(input)}
	resolver := &G008RequestResolver{reader: reader}

	token, err := resolver.CaptureTarget(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !validCapturedStdinToken(token) || strings.Contains(token, string(input)) || strings.Contains(token, fmtHex(input)) {
		t.Fatalf("token is not opaque: %q", token)
	}
	readsAfterCapture := reader.reads
	if repeated, err := resolver.CaptureTarget(context.Background()); err != nil || repeated != token || reader.reads != readsAfterCapture {
		t.Fatalf("repeated capture = %q, %v; reads = %d, want %q and %d", repeated, err, reader.reads, token, readsAfterCapture)
	}

	owned := resolver.captured
	transferred, err := resolver.TakeCapturedStdin(context.Background(), token)
	if err != nil {
		t.Fatal(err)
	}
	if string(transferred) != string(input) {
		t.Fatalf("transferred stdin = %q, want %q", transferred, input)
	}
	transferred[0] = 'X'
	if string(input) != "first line\nsecond line\n" {
		t.Fatalf("transfer mutated input: %q", input)
	}
	if resolver.captured != nil || resolver.captureToken != "" {
		t.Fatal("resolver retained captured stdin after transfer")
	}
	for _, byte := range owned {
		if byte != 0 {
			t.Fatal("resolver-owned stdin was not zeroed")
		}
	}
	if _, err := resolver.TakeCapturedStdin(context.Background(), token); err == nil {
		t.Fatal("reused token succeeded")
	}
	if _, err := resolver.TakeCapturedStdin(context.Background(), "stdin-capture-v1-"+strings.Repeat("0", 64)); err == nil {
		t.Fatal("unknown token succeeded")
	}
}

func TestG008RequestResolverCaptureTargetAcceptsBeyondLegacyMaximum(t *testing.T) {
	resolver := &G008RequestResolver{reader: bytes.NewReader(bytes.Repeat([]byte("x"), 180001))}
	token, err := resolver.CaptureTarget(context.Background())
	if err != nil || !validCapturedStdinToken(token) {
		t.Fatalf("CaptureTarget = %q, %v", token, err)
	}
}

func TestG008RequestResolverCaptureTargetRejectsInvalidInput(t *testing.T) {
	for name, reader := range map[string]io.Reader{
		"empty":         bytes.NewReader(nil),
		"NUL":           bytes.NewBufferString("one\x00two"),
		"invalid UTF-8": bytes.NewReader([]byte{0xff}),
		"read error":    errorReader{},
	} {
		t.Run(name, func(t *testing.T) {
			resolver := &G008RequestResolver{reader: reader}
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

func TestG008RequestResolverCapturedStdinTokensAreFreshPerResolver(t *testing.T) {
	first := &G008RequestResolver{reader: strings.NewReader("same input"), stdinLimit: 64}
	second := &G008RequestResolver{reader: strings.NewReader("same input"), stdinLimit: 64}
	firstToken, err := first.CaptureTarget(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	secondToken, err := second.CaptureTarget(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if firstToken == secondToken {
		t.Fatal("separate resolver instances reused a token")
	}
}

func fmtHex(bytes []byte) string {
	sum := sha256.Sum256(bytes)
	return fmt.Sprintf("%x", sum)
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
	explicit, err := resolver.ResolveRun(context.Background(), first.RunID.String())
	if err != nil || explicit != first.RunID.String() {
		t.Fatalf("explicit run = %q, %v; want %s", explicit, err, first.RunID)
	}
	projectStore := filepath.Join(filepath.Dir(fixture.root.String()), "store")
	if _, err := os.Lstat(projectStore); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("project-root store stat error = %v, want not exist", err)
	}
	if _, err := os.Stat(filepath.Join(fixture.root.String(), "store", "locks", "store.lock")); err != nil {
		t.Fatalf("artifact-root publication lock: %v", err)
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
		{"followup", "--run", "latest", "--finding", "F001", "--dirty"},
		{"delta", "--since-run", "latest", "--dirty", "--roles", "logic"},
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
