package query

import (
	"reflect"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/app/recovery"
	"github.com/irootkernel/mulgae/internal/domain"
)

func TestDecodeFinalDTORejectsDuplicateUnknownAndTrailingJSON(t *testing.T) {
	t.Parallel()
	for name, raw := range map[string]string{
		"duplicate": `{"schema_version":"mulgae-review-artifact.v1","schema_version":"mulgae-review-artifact.v1"}`,
		"unknown":   `{"unexpected":true}`,
		"trailing":  `{} {}`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := decodeFinalDTO([]byte(raw)); err == nil {
				t.Fatalf("decodeFinalDTO(%q) succeeded", raw)
			}
		})
	}
}

func TestCommittedReviewAndFindingViewsDefendCallerMutations(t *testing.T) {
	t.Parallel()
	review := CommittedReview{
		roles: []Role{{
			role: domain.RoleLogic, findingIDs: []string{"F001"}, limitations: []string{"limited"},
		}},
		findings: []Finding{{
			id: "F001", evidence: []Evidence{{quote: "verified quote"}},
		}},
		finalBytes: []byte("final"), manifestBytes: []byte("manifest"),
	}

	roles := review.Roles()
	roles[0].findingIDs[0] = "F999"
	roles[0].limitations[0] = "changed"
	if got := review.Roles()[0].ValidFindingIDs()[0]; got != "F001" {
		t.Fatalf("role finding IDs leaked mutation: %q", got)
	}
	if got := review.Roles()[0].Limitations()[0]; got != "limited" {
		t.Fatalf("role limitations leaked mutation: %q", got)
	}

	findings := review.Findings()
	findings[0].evidence[0].quote = "changed"
	if got := review.Findings()[0].Evidence()[0].quote; got != "verified quote" {
		t.Fatalf("finding evidence leaked mutation: %q", got)
	}
	final := review.FinalBytes()
	final[0] = 'X'
	if got := string(review.FinalBytes()); got != "final" {
		t.Fatalf("final bytes leaked mutation: %q", got)
	}
	manifest := review.ManifestBytes()
	manifest[0] = 'X'
	if got := string(review.ManifestBytes()); got != "manifest" {
		t.Fatalf("manifest bytes leaked mutation: %q", got)
	}

	if strings.Contains(review.Findings()[0].Evidence()[0].quote, "changed") {
		t.Fatal("defensive evidence copy retained caller mutation")
	}
}

func TestCommittedReviewExposesVerifiedCompositionPolicy(t *testing.T) {
	t.Parallel()
	review := CommittedReview{runType: domain.RunTypeRerun, severityThreshold: domain.SeverityCritical}
	if review.RunType() != domain.RunTypeRerun || review.RequestChangesThreshold() != domain.SeverityCritical {
		t.Fatalf("composition policy projection = (%q, %q)", review.RunType(), review.RequestChangesThreshold())
	}
}

func TestCommittedLineageDefensivelyExposesSourceAttempt(t *testing.T) {
	t.Parallel()
	attempt, err := domain.ParseAttemptID("a_019f596a-d048-79e7-b2b7-59822f012273")
	if err != nil {
		t.Fatal(err)
	}
	lineage := CommittedLineage{sourceAttemptID: &attempt}
	want := attempt
	got, ok := lineage.SourceAttemptID()
	if !ok || got != attempt {
		t.Fatalf("source attempt = %q, %t", got, ok)
	}
	cloned := lineage.clone()
	*lineage.sourceAttemptID = domain.AttemptID{}
	if got, ok := cloned.SourceAttemptID(); !ok || got != want {
		t.Fatalf("cloned source attempt leaked mutation: %q, %t", got, ok)
	}
}

func TestCompositionStatusRequiresExactP2AndCompleteRoleReports(t *testing.T) {
	t.Parallel()
	session, err := domain.ParseSessionID("s_019f596a-cf80-7c67-b265-f37053d51ccf")
	if err != nil {
		t.Fatal(err)
	}
	run, err := domain.ParseRunID("r_019f596a-cfe4-7c9c-b82e-7149158243ba")
	if err != nil {
		t.Fatal(err)
	}
	review := CommittedReview{sessionID: session, runID: run, roleReports: []RoleReport{{role: "logic"}}}
	valid := RunStatus{sessionID: session, runID: run, publication: domain.PublicationCommitted, authority: domain.PublicationAuthorityP2, roleReportURIs: []RoleReportURI{{Role: "logic"}}}
	if err := validateCompositionStatus(review, valid); err != nil {
		t.Fatalf("valid composition status rejected: %v", err)
	}
	invalid := valid
	invalid.authority = domain.PublicationAuthorityP1
	if err := validateCompositionStatus(review, invalid); err == nil {
		t.Fatal("P1 composition support status was accepted")
	}
	invalid = valid
	invalid.roleReportURIs = nil
	if err := validateCompositionStatus(review, invalid); err == nil {
		t.Fatal("incomplete role-report support status was accepted")
	}
}

func TestRunStatusRecoveryDefendsCallerMutations(t *testing.T) {
	kind, run, hash, reason := "failed_run_recovery", "run", "hash", "source_not_retained"
	for _, original := range []recovery.Status{
		{Available: true, SourceKind: &kind, RunID: &run, ManifestSHA256: &hash, AcceptedRoles: []domain.Role{domain.RoleLogic}, RetryAttempts: []recovery.RetryAttempt{{Role: domain.RoleSecurity, AttemptID: "attempt"}}},
		recovery.UnavailableStatus(reason),
	} {
		status := RunStatus{failedRunRecovery: original}
		got := status.FailedRunRecovery()
		for _, value := range []*string{got.SourceKind, got.RunID, got.ManifestSHA256, got.UnavailableReason} {
			if value != nil {
				*value = "changed"
			}
		}
		if len(got.AcceptedRoles) != 0 {
			got.AcceptedRoles[0] = domain.RoleArtist
		}
		if len(got.RetryAttempts) != 0 {
			got.RetryAttempts[0].AttemptID = "changed"
		}
		if next := status.FailedRunRecovery(); reflect.DeepEqual(next, got) {
			t.Fatal("recovery status retained caller mutation")
		}
		if kind != "failed_run_recovery" || run != "run" || hash != "hash" || (len(original.AcceptedRoles) != 0 && original.AcceptedRoles[0] != domain.RoleLogic) || (len(original.RetryAttempts) != 0 && original.RetryAttempts[0].AttemptID != "attempt") || (original.UnavailableReason != nil && *original.UnavailableReason != reason) {
			t.Fatal("recovery status mutated original references")
		}
	}
}
