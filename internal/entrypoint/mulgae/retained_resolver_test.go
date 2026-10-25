package mulgae

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/adapters/filesystem"
	"github.com/irootkernel/mulgae/internal/adapters/jsonschema"
	"github.com/irootkernel/mulgae/internal/app/prompt"
	"github.com/irootkernel/mulgae/internal/app/query"
	"github.com/irootkernel/mulgae/internal/builtin"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
	"github.com/irootkernel/mulgae/internal/testsupport/historical"
)

type retainedResolverClock struct{}

func (retainedResolverClock) Now() time.Time { return time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC) }

type retainedResolverIDs struct{}

func (retainedResolverIDs) NewReviewID(time.Time) (domain.ReviewID, error) {
	return domain.ReviewID{}, errors.New("fixed resolver input cannot issue a review")
}

// Only this resolver fixture's run/review/time/epoch coordinates are rebound.
// Rehash references transitively; this does not construct or accept a review.
func retainedResolverFiles(t *testing.T, c historical.Case, run, review string, epoch int) map[string][]byte {
	t.Helper()
	files := c.Artifacts()
	var manifest struct {
		CreatedAt string `json:"created_at"`
	}
	if err := json.Unmarshal(files[c.SessionID+"/"+c.RunID+"/manifest.json"], &manifest); err != nil {
		t.Fatal(err)
	}
	replace := strings.NewReplacer(c.RunID, run, c.ReviewID, review, manifest.CreatedAt, "2026-07-14T12:00:00Z", "epoch_00000000000000000001.json", fmt.Sprintf("epoch_%020d.json", epoch), `"store_epoch":1`, fmt.Sprintf(`"store_epoch":%d`, epoch))
	result := map[string][]byte{}
	digest := func(raw []byte) string { sum := sha256.Sum256(raw); return "sha256:" + hex.EncodeToString(sum[:]) }
	for path, raw := range files {
		result[replace.Replace(path)] = []byte(replace.Replace(string(raw)))
	}
	prefix := c.SessionID + "/" + run + "/"
	leaf := regexp.MustCompile(`\{[^{}]*"path":"[^"\\]+"[^{}]*\}`)
	sha := regexp.MustCompile(`"sha256":"[^"]*"`)
	complete := regexp.MustCompile(`"complete_stdin_sha256":"[^"]*"`)
	lineage := regexp.MustCompile(`"lineage_edge_path":"([^"]+)","lineage_edge_sha256":"[^"]*"`)
	// Preserve original JSON ordering/canonical LF. Rebind only declared path
	// references, never every occurrence of an equal content digest.
	for pass := 0; pass < 16; pass++ {
		changed := false
		for path, raw := range result {
			if !(strings.HasSuffix(path, "/manifest.json") || strings.HasSuffix(path, "/target-manifest.json") || strings.HasSuffix(path, "/index.json") || strings.Contains(path, "/epochs/") || strings.Contains(path, "/lineage-edges/") || strings.Contains(path, "/review_") || strings.HasSuffix(path, ".manifest.json") || strings.HasSuffix(path, "/journal.json") || strings.HasSuffix(path, "/status.json")) {
				continue
			}
			updated := leaf.ReplaceAllFunc(raw, func(object []byte) []byte {
				var ref struct {
					Path string `json:"path"`
				}
				if err := json.Unmarshal(object, &ref); err != nil {
					t.Fatal(err)
				}
				source, ok := result[ref.Path]
				if !ok {
					source, ok = result[prefix+ref.Path]
				}
				if !ok && strings.Contains(ref.Path, "/publication/staged/review_") {
					source, ok = result[strings.TrimSuffix(strings.Replace(ref.Path, "/publication/staged/", "/", 1), ".tmp")]
				}
				if !ok {
					return object
				}
				return sha.ReplaceAllLiteral(object, []byte(`"sha256":"`+digest(source)+`"`))
			})
			updated = lineage.ReplaceAllFunc(updated, func(pair []byte) []byte {
				match := lineage.FindSubmatch(pair)
				if source, ok := result[string(match[1])]; ok {
					return []byte(`"lineage_edge_path":"` + string(match[1]) + `","lineage_edge_sha256":"` + digest(source) + `"`)
				}
				return pair
			})
			if strings.HasSuffix(path, ".manifest.json") && bytes.Contains(updated, []byte(`"complete_stdin_sha256"`)) {
				var wire struct {
					Stdin struct {
						Path string `json:"path"`
					} `json:"stdin"`
				}
				if err := json.Unmarshal(updated, &wire); err != nil {
					t.Fatal(err)
				}
				stdin, ok := result[wire.Stdin.Path]
				if !ok {
					t.Fatal("resolver stdin path absent")
				}
				updated = complete.ReplaceAllLiteral(updated, []byte(`"complete_stdin_sha256":"`+prompt.CompleteStdinSHA256(stdin)+`"`))
			}
			if !bytes.Equal(updated, raw) {
				result[path] = updated
				changed = true
			}
		}
		if !changed {
			return result
		}
	}
	t.Fatal("resolver fixture reference hashes did not converge")
	return nil
}

func retainedResolverFixture(t *testing.T) (ports.AnchoredRoot, *query.Service, string, string) {
	t.Helper()
	corpus, err := historical.Load()
	if err != nil {
		t.Fatal(err)
	}
	var input historical.Case
	for _, c := range corpus.Cases {
		if c.ID == "ordinary-v2" {
			input = c
		}
	}
	if input.ID == "" {
		t.Fatal("fixed resolver input absent")
	}
	rootPath, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root, err := ports.NewAnchoredRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	first := "r_019f596a-cfe4-7c9c-b82e-7149158243b1"
	second := "r_019f596a-cfe4-7c9c-b82e-7149158243b2"
	for i, id := range []string{first, second} {
		review := fmt.Sprintf("019f596a-d174-7321-b920-c2d312c82cc%d", i+1)
		for path, raw := range retainedResolverFiles(t, input, id, review, 2-i) {
			destination := filepath.Join(rootPath, filepath.FromSlash(path))
			if err := os.MkdirAll(filepath.Dir(destination), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(destination, raw, 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	validator, err := jsonschema.New(context.Background(), builtin.NewCatalog())
	if err != nil {
		t.Fatal(err)
	}
	store, err := filesystem.NewPublicationStore(validator, retainedResolverClock{}, retainedResolverIDs{}, filesystem.NewSecureWriter())
	if err != nil {
		t.Fatal(err)
	}
	queries, err := query.NewService(store, validator, nil, 8<<20)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{first, second} {
		id, err := domain.ParseRunID(value)
		if err != nil {
			t.Fatal(err)
		}
		run, err := queries.ResolveRun(context.Background(), root, id)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := queries.ReadCommitted(context.Background(), run); err != nil {
			t.Fatalf("fixed resolver positive control %s: %v", value, err)
		}
	}
	return root, queries, first, second
}

func TestRequestResolverUsesFrozenCommittedSelection(t *testing.T) {
	root, queries, first, second := retainedResolverFixture(t)
	resolver, err := NewG008RequestResolver(root, queries, filesystem.NewRunSelector(root))
	if err != nil {
		t.Fatal(err)
	}
	selected, err := resolver.ResolveRun(context.Background(), "latest")
	if err != nil || selected != second {
		t.Fatalf("UUIDv7 tiebreak=%q, %v", selected, err)
	}
	explicit, err := resolver.ResolveRun(context.Background(), first)
	if err != nil || explicit != first {
		t.Fatalf("explicit selector=%q, %v", explicit, err)
	}
	id, err := domain.ParseRunID(first)
	if err != nil {
		t.Fatal(err)
	}
	newer := latestCommittedRun{runID: id, createdAt: retainedResolverClock{}.Now().Add(time.Second)}
	other, err := domain.ParseRunID(second)
	if err != nil {
		t.Fatal(err)
	}
	if !newer.after(latestCommittedRun{runID: other, createdAt: retainedResolverClock{}.Now()}) {
		t.Fatal("newer timestamp did not outrank UUIDv7")
	}
	invocation, err := ParseResolved(context.Background(), []string{"export", "--run", "latest", "--output-path", "exports/review.zip"}, testProjectRoot, testRequestID, resolver)
	if err != nil {
		t.Fatal(err)
	}
	request, ok := invocation.RequestJSON()
	if !ok || !strings.Contains(string(request), second) {
		t.Fatal("parse did not freeze the committed selector")
	}
}

func TestRequestResolverExcludesCorruptFrozenCandidatesWithDiagnostics(t *testing.T) {
	root, queries, first, second := retainedResolverFixture(t)
	resolver, err := NewG008RequestResolver(root, queries, filesystem.NewRunSelector(root))
	if err != nil {
		t.Fatal(err)
	}
	session := "s_019f596a-cf80-7c67-b265-f37053d51ccf"
	corrupt := func(id string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(root.String(), session, id, "manifest.json"), []byte("{"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	corrupt(second)
	selected, err := resolver.ResolveRun(context.Background(), "latest")
	if err != nil || selected != first || len(resolver.Diagnostics()) == 0 {
		t.Fatalf("corrupt-candidate exclusion=%q, %v", selected, err)
	}
	corrupt(first)
	if _, err := resolver.ResolveRun(context.Background(), "latest"); err == nil || !strings.Contains(err.Error(), "no P2 committed candidates") {
		t.Fatalf("all-corrupt selector=%v", err)
	}
}
