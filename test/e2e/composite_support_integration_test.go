//go:build darwin && arm64

package e2e

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"math"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/irootkernel/mulgae/internal/adapters/filesystem"
	"github.com/irootkernel/mulgae/internal/adapters/jsonschema"
	runtimeadapter "github.com/irootkernel/mulgae/internal/adapters/runtime"
	"github.com/irootkernel/mulgae/internal/app/clean"
	"github.com/irootkernel/mulgae/internal/builtin"
	"github.com/irootkernel/mulgae/internal/ports"
)

func compositeEvidenceReport() string {
	return "# __ROLE__ role report\n\n```json\n" +
		`{"schema_version":"mulgae-provider-review-output.v1","summary":"Two retained evidence indices.","completeness":"complete","limitations":[],"findings":[{"severity":"low","title":"__ROLE__ fixture finding","description":"Preserve the complete original finding.","evidence":[{"current":{"path":"review.go","line_start":1,"line_end":1,"side":"worktree","quote":"package review\n"}},{"current":{"path":"review.go","line_start":3,"line_end":3,"side":"worktree","quote":"const state = \"after\"\n"}}],"recommendation":"Inspect both immutable excerpts.","confidence":"high"}]}` + "\n```\n"
}

// These assertions run inside both release-binary composition fixtures, so the
// ordinary and unpublished recovery source paths exercise the same consumers.
func assertCompositePortableContent(t *testing.T, binary, project string, environment []string, run string, expectedFindings int, wantRecoverySource bool) {
	t.Helper()
	command := func(args ...string) map[string]any {
		t.Helper()
		result := runMulgaeBinaryWithEnv(t, binary, project, environment, append(args, "--output", "json")...)
		if result.exitCode != 0 {
			t.Fatalf("%v: exit=%d stdout=%s stderr=%s", args, result.exitCode, result.stdout, result.stderr)
		}
		var envelope struct {
			Result map[string]any `json:"result"`
		}
		if err := json.Unmarshal(result.stdout, &envelope); err != nil {
			t.Fatal(err)
		}
		return envelope.Result
	}
	inspection := command("inspect", "--run", run)
	capture, ok := inspection["capture_identity"].(string)
	if !ok || !strings.HasPrefix(capture, "sha256:") || inspection["capture_availability"] != "verified" {
		t.Fatalf("composite has no verified common capture: %#v", inspection)
	}
	receipt := inspection["publication_receipt"].(string)
	binding := inspection["receipt"].(map[string]any)["project_binding"].(string)
	target := inspection["receipt"].(map[string]any)["target_sha256"].(string)
	read := func(args ...string) []byte {
		t.Helper()
		base := append(append([]string{}, args...), "--expected-project-binding", binding, "--expected-publication-receipt", receipt)
		next := base
		var content []byte
		var digest string
		for {
			chunk := command(next...)
			part := []byte(chunk["content"].(string))
			if chunk["publication_receipt"] != receipt || chunk["encoding"] != "utf8" || chunk["offset"] != float64(len(content)) || chunk["returned_bytes"] != float64(len(part)) || len(part) > 16384 || !utf8.Valid(part) {
				t.Fatalf("fixture content chunk lost its receipt, offset, or byte boundary: %#v", chunk)
			}
			if digest == "" {
				digest = chunk["content_sha256"].(string)
			} else if chunk["content_sha256"] != digest {
				t.Fatal("fixture content digest changed across continuation")
			}
			content = append(content, part...)
			if chunk["next_offset"] == nil {
				sum := sha256.Sum256(content)
				if digest != "sha256:"+hex.EncodeToString(sum[:]) || chunk["total_bytes"] != float64(len(content)) {
					t.Fatal("fixture content is incomplete or differs from its digest")
				}
				return content
			}
			if len(part) == 0 || chunk["next_offset"] != float64(len(content)) {
				t.Fatal("fixture content continuation did not advance exactly")
			}
			next = append(append([]string{}, base...), "--offset", strconv.Itoa(len(content)), "--expected-content-sha256", digest)
		}
	}
	renderedReport := read("read-report", "--run", run)
	if len(renderedReport) == 0 {
		t.Fatal("composite rendered report is empty")
	}
	roleReports := map[string][]byte{}
	for _, value := range inspection["role_reports"].([]any) {
		role := value.(map[string]any)["role"].(string)
		body := read("read-report", "--run", run, "--role", role)
		expected := []byte(strings.ReplaceAll(compositeEvidenceReport(), "__ROLE__", role))
		if !bytes.Equal(body, expected) {
			t.Fatalf("composite original %s report differs from the provider's complete bytes", role)
		}
		roleReports[role] = body
	}
	if len(roleReports) != expectedFindings {
		t.Fatalf("composite original reports = %d, want %d", len(roleReports), expectedFindings)
	}
	findings := inspection["findings"].([]any)
	if len(findings) != expectedFindings {
		t.Fatalf("composite findings = %d, want %d", len(findings), expectedFindings)
	}
	before := map[string][]byte{}
	sourceRuns := map[string]bool{}
	sawRecovery := false
	for _, row := range findings {
		finding := row.(map[string]any)
		if !bytes.Contains(renderedReport, []byte(finding["title"].(string))) {
			t.Fatal("composite rendered report omitted a selected finding")
		}
		id := finding["id"].(string)
		body := read("read-finding", "--run", run, "--finding", id)
		if bytes.Contains(body, []byte(`"project_binding"`)) || bytes.Contains(body, []byte(project)) {
			t.Fatal("portable source receipt exposed local project identity")
		}
		before[id] = body
		var detail struct {
			SourceFinding json.RawMessage `json:"source_finding"`
			SourceReceipt struct {
				RunID                  string `json:"run_id"`
				ReviewID               string `json:"review_id"`
				AttemptID              string `json:"attempt_id"`
				RecoveryManifestSHA256 string `json:"recovery_manifest_sha256"`
				FinalSHA256            string `json:"final_sha256"`
				ManifestSHA256         string `json:"manifest_sha256"`
				SupportSHA256          string `json:"support_sha256"`
				Epoch                  uint64 `json:"epoch"`
				CaptureIdentity        string `json:"capture_identity"`
			} `json:"source_receipt"`
		}
		if err := json.Unmarshal(body, &detail); err != nil {
			t.Fatal(err)
		}
		source := detail.SourceReceipt
		if source.RunID == "" || source.AttemptID == "" || source.CaptureIdentity != capture {
			t.Fatalf("source identity or common capture missing: %s", body)
		}
		sourceRuns[source.RunID] = source.RecoveryManifestSHA256 != ""
		var original struct {
			ID          string            `json:"id"`
			Description string            `json:"description"`
			Evidence    []json.RawMessage `json:"evidence"`
		}
		if err := json.Unmarshal(detail.SourceFinding, &original); err != nil {
			t.Fatal(err)
		}
		if original.ID == "" || original.Description != "Preserve the complete original finding." || len(original.Evidence) != 2 {
			t.Fatalf("original finding was reduced: %s", detail.SourceFinding)
		}
		if source.RecoveryManifestSHA256 != "" {
			sawRecovery = true
			if source.ReviewID != "" || source.FinalSHA256 != "" || source.ManifestSHA256 != "" || source.SupportSHA256 != "" || source.Epoch != 0 {
				t.Fatalf("failed source claimed a committed publication: %s", body)
			}
		} else {
			if source.ReviewID == "" || source.FinalSHA256 == "" || source.ManifestSHA256 == "" || source.SupportSHA256 == "" || source.Epoch == 0 {
				t.Fatalf("ordinary source portable receipt incomplete: %s", body)
			}
			originalChunk := command("read-finding", "--run", source.RunID, "--finding", original.ID)
			if !bytes.Equal(detail.SourceFinding, []byte(originalChunk["content"].(string))) {
				t.Fatal("composite original finding differs from source publication")
			}
		}
		indices := finding["evidence"].([]any)
		if len(indices) != 2 {
			t.Fatalf("composite exposed %d evidence indices, want 2", len(indices))
		}
		quotes := map[string]bool{}
		for i := range indices {
			content := read("excerpt", "--run", run, "--finding", id, "--current-target-sha256", target, "--evidence-index", strconv.Itoa(i))
			before[id+"/"+strconv.Itoa(i)] = content
			quotes[string(content)] = true
		}
		if !quotes["package review\n"] || !quotes["const state = \"after\"\n"] {
			t.Fatalf("copied evidence lost an index: %#v", quotes)
		}
	}
	if sawRecovery != wantRecoverySource {
		t.Fatalf("failed recovery provenance = %t, want %t", sawRecovery, wantRecoverySource)
	}

	// Change the live file after capture. Reads must continue using retained bytes.
	mustWriteTestFile(t, filepath.Join(project, "review.go"), []byte("package changed\n\nconst state = \"unrelated live content\"\n"))
	cleanCompositeSources(t, project, run, sourceRuns)
	if got := read("read-report", "--run", run); !bytes.Equal(got, renderedReport) {
		t.Fatal("composite rendered report changed after live edit and source cleanup")
	}
	for role, expected := range roleReports {
		if got := read("read-report", "--run", run, "--role", role); !bytes.Equal(got, expected) {
			t.Fatalf("composite original %s report changed after live edit and source cleanup", role)
		}
	}
	for key, expected := range before {
		id, index, excerpt := strings.Cut(key, "/")
		args := []string{"read-finding", "--run", run, "--finding", id}
		if excerpt {
			args = []string{"excerpt", "--run", run, "--finding", id, "--current-target-sha256", target, "--evidence-index", index}
		}
		if got := read(args...); !bytes.Equal(got, expected) {
			t.Fatalf("retained composite content changed after live edit and cleanup: %s", key)
		}
	}
	if got := command("inspect", "--run", run); got["capture_identity"] != capture || !reflect.DeepEqual(got["findings"], inspection["findings"]) {
		t.Fatal("composite inspection changed after live edit and cleanup")
	}

	exported := command("export", "--run", run)
	archive, err := zip.OpenReader(filepath.Join(project, filepath.FromSlash(exported["bundle_uri"].(string))))
	if err != nil {
		t.Fatal(err)
	}
	defer archive.Close()
	for _, member := range archive.File {
		if strings.HasPrefix(member.Name, "support/") || strings.HasPrefix(member.Name, "excerpts/") {
			t.Fatalf("export leaked private composite member %q", member.Name)
		}
		reader, err := member.Open()
		if err != nil {
			t.Fatal(err)
		}
		data, readErr := io.ReadAll(reader)
		closeErr := reader.Close()
		if readErr != nil || closeErr != nil {
			t.Fatalf("read export member: %v %v", readErr, closeErr)
		}
		for _, private := range []string{project, "package review", `const state =`, `"source_finding"`, `"source_receipt"`, `"project_binding"`} {
			if bytes.Contains(data, []byte(private)) {
				t.Fatalf("export member %q leaked %q", member.Name, private)
			}
		}
	}
}

// The CLI has no keep-run selector. Exercise its native cleanup planner and
// journaled filesystem adapter with an explicit retained composite instead.
func cleanCompositeSources(t *testing.T, project, composite string, sources map[string]bool) {
	t.Helper()
	ctx := context.Background()
	root, err := ports.NewAnchoredRoot(filepath.Join(project, ".mulgae"))
	if err != nil {
		t.Fatal(err)
	}
	validator, err := jsonschema.New(ctx, builtin.NewCatalog())
	if err != nil {
		t.Fatal(err)
	}
	clock := runtimeadapter.SystemClock{}
	publication, err := filesystem.NewPublicationStore(validator, clock, runtimeadapter.NewUUIDv7Generator(), filesystem.NewSecureWriter())
	if err != nil {
		t.Fatal(err)
	}
	store, err := filesystem.NewCleanupStore(root, publication, clock)
	if err != nil {
		t.Fatal(err)
	}
	var plan clean.CleanPlan
	err = store.WithCleanupTransaction(ctx, func(transaction clean.CleanupTransaction) error {
		snapshot, err := transaction.Snapshot(ctx)
		if err != nil {
			return err
		}
		snapshot.Policy = clean.Policy{TargetBytes: math.MaxInt64, ExplicitKeepRunIDs: []string{composite}}
		raw, err := json.Marshal(snapshot.Policy)
		if err != nil {
			return err
		}
		digest := sha256.Sum256(raw)
		snapshot.InputPolicySHA256 = "sha256:" + hex.EncodeToString(digest[:])
		plan, err = clean.Plan(snapshot)
		if err != nil {
			return err
		}
		return transaction.PersistDryRunPlan(ctx, plan)
	})
	if err != nil {
		t.Fatal(err)
	}
	apply, err := clean.ApplyPlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	if err := clean.ExecuteApply(ctx, store, apply); err != nil {
		t.Fatal(err)
	}
	for run, recovery := range sources {
		matches, err := filepath.Glob(filepath.Join(root.String(), "s_*", run))
		if err != nil {
			t.Fatal(err)
		}
		if !recovery && len(matches) != 0 {
			t.Fatalf("native cleanup retained ordinary source %s: %#v", run, plan.RunDecisions)
		}
		if recovery {
			matches, err = filepath.Glob(filepath.Join(root.String(), "diagnostics", "s_*", run))
			if err != nil || len(matches) != 1 {
				t.Fatalf("native cleanup failed to retain recovery source %s: %v", run, err)
			}
		}
	}
}
