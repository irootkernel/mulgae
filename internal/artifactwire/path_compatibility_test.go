package artifactwire_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/app/compositesupport"
	"github.com/irootkernel/mulgae/internal/app/recovery"
	"github.com/irootkernel/mulgae/internal/artifactwire"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

func TestArtifactPathGrammarCompatibility(t *testing.T) {
	t.Run("leaf fixed owner vectors", testLeafPathVectors)
	t.Run("other spelling vectors", testLeafSpellings)
	session, _ := domain.ParseSessionID("s_019f596a-cf80-7c67-b265-f37053d51ccf")
	runID, _ := domain.ParseRunID("r_019f596a-cfe4-7c9c-b82e-7149158243ba")
	root, err := ports.NewAnchoredRoot("/tmp/mulgae-path-contract")
	if err != nil {
		t.Fatal(err)
	}
	run, err := ports.NewPublicationRun(root, session, runID)
	if err != nil {
		t.Fatal(err)
	}
	prefix := session.String() + "/" + runID.String() + "/"
	manifest, err := recovery.ManifestPath(run)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := manifest.String(), prefix+"recovery/manifest.json"; got != want {
		t.Fatalf("manifest=%q want %q", got, want)
	}
	digest := "sha256:" + strings.Repeat("a", 64)
	blob, err := recovery.BlobPath(run, recovery.Blob{SHA256: digest})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := blob.String(), prefix+"recovery/blobs/sha256-"+strings.Repeat("a", 64); got != want {
		t.Fatalf("blob=%q want %q", got, want)
	}
	if _, err := recovery.BlobPath(run, recovery.Blob{SHA256: "invalid"}); err == nil || err.Error() != "recovery: invalid blob digest" {
		t.Fatalf("invalid digest guard=%v", err)
	}
	if got := compositesupport.SourcePrefix(domain.RoleLogic); got != "support/sources/logic/target/" {
		t.Fatal(got)
	}
	if got := compositesupport.FindingPath("F001"); got != "support/findings/F001.json" {
		t.Fatal(got)
	}
	if got := compositesupport.ExcerptPath("F001", 0); got != "excerpts/F001_1.md" {
		t.Fatal(got)
	}
}

// These fixed vectors were captured through the ports owners before path moves.
func testLeafPathVectors(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "m2-publication-paths.json"))
	if err != nil {
		t.Fatal(err)
	}
	var want map[string]string
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatal(err)
	}
	session := "s_019f596a-cf80-7c67-b265-f37053d51ccf"
	run := "r_019f596a-cfe4-7c9c-b82e-7149158243ba"
	review := "019f596a-d174-7321-b920-c2d312c82cc2"
	for key, expected := range want {
		t.Run(key, func(t *testing.T) {
			var got string
			switch {
			case strings.HasPrefix(key, "decimal/"):
				got = fmt.Sprint(artifactwire.DecimalIdentifier(strings.TrimPrefix(key, "decimal/"), 3))
			case strings.HasPrefix(key, "digits/"):
				got = fmt.Sprint(artifactwire.DecimalDigits(strings.TrimPrefix(key, "digits/"), 1))
			case strings.HasPrefix(key, "excerpt/"):
				got = fmt.Sprint(artifactwire.CanonicalExcerptName(strings.TrimPrefix(key, "excerpt/")))
			case strings.HasPrefix(key, "invocation/"):
				got = fmt.Sprint(artifactwire.CanonicalInvocationDirectory(strings.TrimPrefix(key, "invocation/")))
			case strings.HasPrefix(key, "composite/"):
				parts := strings.Split(key, "/")
				epoch, err := strconv.ParseUint(parts[1], 10, 64)
				if err != nil {
					t.Fatal(err)
				}
				switch parts[2] {
				case "manifest":
					got = artifactwire.RunPath(session, run, artifactwire.ManifestPath)
				case "lineage":
					got = artifactwire.LineageEdgePath(review)
				case "epoch":
					got = artifactwire.EpochPath(epoch)
				default:
					t.Fatal(key)
				}
			case strings.HasPrefix(key, "diagnostic/"):
				epoch, err := strconv.ParseUint(strings.TrimPrefix(key, "diagnostic/"), 10, 64)
				if err != nil {
					t.Fatal(err)
				}
				got = artifactwire.CorruptionDiagnosticPath(session, run, epoch)
			default:
				switch key {
				case "final":
					got = artifactwire.FinalPath(session, run, review)
				case "validated", "validated-for-final":
					got = artifactwire.RunPath(session, run, artifactwire.ValidatedCandidatePath)
				case "staged", "staged-for-final":
					got = artifactwire.StagedFinalPath(session, run, review)
				case "mutable/journal", "mutable-for-final/journal":
					got = artifactwire.RunPath(session, run, artifactwire.JournalPath)
				case "mutable/status", "mutable-for-final/status":
					got = artifactwire.RunPath(session, run, artifactwire.StatusPath)
				case "prepared/manifest":
					got = artifactwire.PreparedCompositePath(session, run, "manifest")
				case "prepared/lineage":
					got = artifactwire.PreparedCompositePath(session, run, "lineage-edge")
				case "prepared/epoch":
					got = artifactwire.PreparedCompositePath(session, run, "epoch")
				default:
					t.Fatalf("unaccounted vector %s", key)
				}
			}
			if got != expected {
				t.Fatalf("got %q want %q", got, expected)
			}
		})
	}
}
func testLeafSpellings(t *testing.T) {
	for _, c := range []struct{ name, got, want string }{
		{"support", artifactwire.RunPath("s", "r", artifactwire.SupportIndexPath), "s/r/support/index.json"},
		{"raw arguments", artifactwire.RunPath("s", "r", "../x"), "s/r/../x"},
		{"prompt base", artifactwire.PromptBase(1, "initial"), "001-initial"},
		{"wide prompt", artifactwire.PromptBase(1000, "repair"), "1000-repair"},
		{"stdin", artifactwire.PromptPath("attempt", 2, "retry", ".stdin"), "prompts/attempt/002-retry.stdin"},
		{"prompt manifest", artifactwire.PromptPath("attempt", 3, "repair", ".manifest.json"), "prompts/attempt/003-repair.manifest.json"},
		{"attempt status", artifactwire.AttemptPath("attempt", "status.json"), "attempts/attempt/status.json"},
		{"initial candidate", artifactwire.AttemptPath("attempt", "candidate.initial.json"), "attempts/attempt/candidate.initial.json"},
		{"retry", artifactwire.CandidateName("retry", 1), "candidate.retry.001.json"},
		{"repair", artifactwire.CandidateName("repaired", 2), "candidate.repaired.002.json"},
		{"extract", artifactwire.CandidateName("extracted", 1000), "candidate.extracted.1000.json"},
		{"stdout", artifactwire.InvocationPath(1, "initial", "stdout"), "invocations/001-initial/stdout.raw"},
		{"stderr", artifactwire.InvocationPath(2, "extract", "stderr"), "invocations/002-extract/stderr.raw"},
		{"excerpt", artifactwire.EvidenceExcerptName("F001", 1), "F001_1.md"},
		{"finding", artifactwire.FindingName("F001"), "F001.json"},
		{"role report", artifactwire.RoleReportPath("logic"), "role-reports/logic.md"},
		{"recovery blob", artifactwire.RecoveryBlobPath("sha256:abc"), "recovery/blobs/sha256-abc"},
		{"captured blob", artifactwire.CapturedBlobPath("sha256:abc"), "blobs/sha256-abc"},
		{"copied source", artifactwire.CompositeSourcePrefix("logic"), "support/sources/logic/target/"},
		{"copied finding", artifactwire.CompositeFindingPath("F001"), "support/findings/F001.json"},
		{"composite document", artifactwire.CompositeSupportPath, "support/composite.json"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if c.got != c.want {
				t.Fatalf("got %q want %q", c.got, c.want)
			}
		})
	}
}
