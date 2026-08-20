package report

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"

	coreapp "github.com/irootkernel/mulgae/internal/app"
	"github.com/irootkernel/mulgae/internal/app/evidence"
	"github.com/irootkernel/mulgae/internal/app/query"
	"github.com/irootkernel/mulgae/internal/app/review"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

func TestRenderIsDeterministicAndCoversCommittedReview(t *testing.T) {
	run, review := reportCommittedFixture(t)
	reader := &reportReader{review: review, excerpt: []byte("line one\nline two")}
	service := mustReportService(t, reader)

	first, err := service.Render(context.Background(), run)
	if err != nil {
		t.Fatalf("first Render() error = %v", err)
	}
	second, err := service.Render(context.Background(), run)
	if err != nil {
		t.Fatalf("second Render() error = %v", err)
	}
	if string(first.Bytes()) != string(second.Bytes()) {
		t.Fatalf("repeated Render() bytes differ:\nfirst:\n%s\nsecond:\n%s", first.Bytes(), second.Bytes())
	}
	if reader.readCalls != 2 || reader.excerptCalls != 2 {
		t.Fatalf("reader calls = read %d, excerpt %d; want exactly one of each per render", reader.readCalls, reader.excerptCalls)
	}
	if len(reader.excerptIndexes) != 2 || reader.excerptIndexes[0] != 1 || reader.excerptIndexes[1] != 1 {
		t.Fatalf("excerpt indexes = %v, want canonical index 1 for each render", reader.excerptIndexes)
	}
	for _, target := range reader.excerptTargets {
		if target != review.TargetSHA256() {
			t.Fatalf("RenderExcerpt target SHA-256 = %q, want %q", target, review.TargetSHA256())
		}
	}

	output := string(first.Bytes())
	assertReportSectionsInOrder(t, output)
	for _, expected := range []string{
		"s_019f596a-cf80-7c67-b265-f37053d51ccf",
		"r_019f596a-cfe4-7c9c-b82e-7149158243ba",
		"019f596a-d174-7321-b920-c2d312c82cc2",
		"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"request_changes",
		"incomplete",
		"structured",
		"committed",
		"fail",
		"logic-provider",
		"security-provider",
		"maintainability-fallback",
		"a_019f596a-d048-79e7-b2b7-59822f012273",
		"fallback",
		"provider_unavailable",
		"logic evidence was restricted to changed files",
		"optional role did not complete",
		"repaired_valid",
		"passed_with_warnings",
		"request_changes_threshold, required_role_incomplete",
		"F001",
		"high",
		"description",
		"recommendation",
		review.Findings()[0].Evidence()[0].SourceExcerptSHA256(),
		review.Findings()[0].Evidence()[0].CurrentExcerptSHA256(),
		"worktree",
		"internal/example.go",
		"verified",
		base64.StdEncoding.EncodeToString([]byte("line one\nline two")),
		"provider telemetry was unavailable",
		"aggregation.json",
		"validation/final-validation.json",
		"0.1.0",
	} {
		if !strings.Contains(output, expected) {
			t.Errorf("rendered report does not contain %q", expected)
		}
	}
	if !strings.Contains(output, "Verified excerpt (base64, exact bytes):") {
		t.Fatal("rendered report does not label the exact base64 excerpt")
	}
	for _, forbidden := range []string{"approval", "approved", "authorize", "authorization", "waiver"} {
		if strings.Contains(strings.ToLower(output), forbidden) {
			t.Errorf("rendered report contains prohibited authority wording %q", forbidden)
		}
	}
	if strings.Contains(output, "\r") || !strings.HasSuffix(output, "\n") {
		t.Fatal("rendered report is not LF-terminated UTF-8 text")
	}

	mutable := first.Bytes()
	mutable[0] = '!'
	if first.Bytes()[0] == '!' {
		t.Fatal("Report exposed mutable rendered bytes")
	}
	if first.SessionID() != review.SessionID() || first.RunID() != review.RunID() || first.ReviewID() != review.ReviewID() ||
		first.FinalPath() != review.FinalPath() || first.FinalSHA256() != review.FinalSHA256() ||
		first.ManifestPath() != review.ManifestPath() || first.ManifestSHA256() != review.ManifestSHA256() ||
		first.LineageEdgePath() != review.LineageEdgePath() || first.LineageEdgeSHA256() != review.LineageEdgeSHA256() ||
		first.Epoch() != review.Epoch() || first.EpochPath() != review.EpochPath() || first.TargetSHA256() != review.TargetSHA256() {
		t.Fatal("Report source identities do not match the committed review")
	}
}
func TestCanonicalReportEvidenceItemsSupportsBoundedDeterministicEvidence(t *testing.T) {
	makeEvidence := func(index int) reportEvidenceDTO {
		quote := fmt.Sprintf("excerpt %02d\n", index)
		return reportEvidenceDTO{
			Source: reportSourceEvidenceDTO{
				SessionID:           "s_019f596a-cf80-7c67-b265-f37053d51ccf",
				RunID:               "r_019f596a-cfe4-7c9c-b82e-7149158243ba",
				ReviewID:            "019f596a-d174-7321-b920-c2d312c82cc2",
				FindingID:           "F001",
				SourceTargetSHA256:  "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				SourceExcerptSHA256: fmt.Sprintf("sha256:%064x", index+1),
			},
			Current: reportCurrentEvidenceDTO{
				TargetSHA256:         "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				Side:                 "worktree",
				Path:                 fmt.Sprintf("internal/example-%02d.go", index),
				LineStart:            index + 1,
				LineEnd:              index + 1,
				Quote:                quote,
				CurrentExcerptSHA256: reportCurrentExcerptDigest(t, "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "worktree", fmt.Sprintf("internal/example-%02d.go", index), index+1, index+1, []byte(quote)),
				Verification:         "verified",
			},
		}
	}
	for _, count := range []int{1, 2, 20} {
		items := make([]reportEvidenceDTO, count)
		for index := range items {
			items[index] = makeEvidence(index + 1)
		}
		ordered, err := canonicalReportEvidenceItems(items)
		if err != nil || len(ordered) != count {
			t.Fatalf("canonicalReportEvidenceItems(%d) = %d items, %v", count, len(ordered), err)
		}
		for index := 1; index < len(ordered); index++ {
			if canonicalReportEvidenceKey(ordered[index-1]) >= canonicalReportEvidenceKey(ordered[index]) {
				t.Fatalf("canonical report evidence order is not strict at %d", index)
			}
		}
	}
	collision := makeEvidence(1)
	if _, err := canonicalReportEvidenceItems([]reportEvidenceDTO{collision, collision}); err == nil {
		t.Fatal("canonicalReportEvidenceItems accepted a full-tuple collision")
	}

	distinctExcerpt := makeEvidence(2)
	distinctExcerpt.Source = collision.Source
	distinctExcerpt.Current.Path = collision.Current.Path
	distinctExcerpt.Current.LineStart = collision.Current.LineStart
	distinctExcerpt.Current.LineEnd = collision.Current.LineEnd
	distinctExcerpt.Current.CurrentExcerptSHA256 = reportCurrentExcerptDigest(
		t,
		distinctExcerpt.Current.TargetSHA256,
		distinctExcerpt.Current.Side,
		distinctExcerpt.Current.Path,
		distinctExcerpt.Current.LineStart,
		distinctExcerpt.Current.LineEnd,
		[]byte(distinctExcerpt.Current.Quote),
	)
	items := []reportEvidenceDTO{collision, distinctExcerpt}
	if canonicalReportEvidenceKey(items[1]) < canonicalReportEvidenceKey(items[0]) {
		items[0], items[1] = items[1], items[0]
	}
	ordered, err := canonicalReportEvidenceItems(items)
	if err != nil {
		t.Fatalf("canonicalReportEvidenceItems() rejected distinct excerpts: %v", err)
	}
	if len(ordered) != 2 || ordered[0].Current.CurrentExcerptSHA256 == ordered[1].Current.CurrentExcerptSHA256 {
		t.Fatalf("canonicalReportEvidenceItems() did not retain distinct excerpt identities: %#v", ordered)
	}
}
func TestRenderIncludesCommittedFollowupOutcome(t *testing.T) {
	outcome := `"followup_outcome":{"resolution":"partially_resolved","rationale":"some remediation is verified","evidence":[{"source":{"session_id":"s_019f596a-cf80-7c67-b265-f37053d51ccf","run_id":"r_019f596a-cfe4-7c9c-b82e-7149158243bc","review_id":"019f596a-d174-7321-b920-c2d312c82cc3","finding_id":"F001","source_target_sha256":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","source_excerpt_sha256":%q},"current":{"target_sha256":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","side":"worktree","path":"internal/example.go","line_start":1,"line_end":2,"quote":"line one\nline two","current_excerpt_sha256":%q,"verification":"verified"}}]},`
	mutate := func(value string) string {
		value = strings.ReplaceAll(value, `"run_type":"review"`, `"run_type":"followup"`)
		value = strings.Replace(value,
			`"parent_run_id":null,"source_run_id":null,"source_review_id":null,"source_finding_ref":null,"replay_mode":null`,
			`"parent_run_id":"r_019f596a-cfe4-7c9c-b82e-7149158243bb","source_run_id":"r_019f596a-cfe4-7c9c-b82e-7149158243bc","source_review_id":"019f596a-d174-7321-b920-c2d312c82cc3","source_finding_ref":"F001","replay_mode":null`,
			1,
		)
		value = strings.Replace(value,
			`"run_id":"r_019f596a-cfe4-7c9c-b82e-7149158243ba","review_id":"019f596a-d174-7321-b920-c2d312c82cc2","finding_id":"F001"`,
			`"run_id":"r_019f596a-cfe4-7c9c-b82e-7149158243bc","review_id":"019f596a-d174-7321-b920-c2d312c82cc3","finding_id":"F001"`,
			1,
		)
		return strings.Replace(value, `"target":{`, fmt.Sprintf(outcome, reportSHA([]byte("historical source excerpt")), reportCurrentExcerptDigest(t, "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "worktree", "internal/example.go", 1, 2, []byte("line one\nline two")))+`"target":{`, 1)
	}
	run, review := reportCommittedFixtureWithMutations(t, mutate, mutate)
	rendered, err := mustReportService(t, &reportReader{review: review, excerpt: []byte("line one\nline two")}).Render(context.Background(), run)
	if err != nil {
		t.Fatalf("Render() error = %v: %v", err, errors.Unwrap(err))
	}
	if !strings.Contains(string(rendered.Bytes()), "# Follow-up outcome\n\n- **Resolution:** `partially_resolved`\n") ||
		!strings.Contains(string(rendered.Bytes()), "some remediation is verified") {
		t.Fatalf("rendered followup outcome = %q", rendered.Bytes())
	}
}

func TestRenderReadinessFailureRecordsStateWithoutExcerptBytes(t *testing.T) {
	run, review := reportCommittedFixture(t)
	reader := &reportReader{
		review:     review,
		excerptErr: mustReportFailure(t, domain.FailureProviderUnavailable, "current evidence is stale"),
	}
	report, err := mustReportService(t, reader).Render(context.Background(), run)
	if err != nil {
		t.Fatalf("Render() error = %v", err)
	}
	output := string(report.Bytes())
	if !strings.Contains(output, "Re-read verification state:** `stale`") {
		t.Fatalf("readiness state was not rendered:\n%s", output)
	}
	if strings.Contains(output, "Verified excerpt:") || strings.Contains(output, "\nline one\n") {
		t.Fatalf("readiness result fabricated excerpt bytes:\n%s", output)
	}
	if reader.readCalls != 1 || reader.excerptCalls != 1 {
		t.Fatalf("reader calls = read %d, excerpt %d; want one injected read and one excerpt request", reader.readCalls, reader.excerptCalls)
	}
}
func TestRenderRejectsMixedReadinessErrorsInBothJoinOrders(t *testing.T) {
	run, review := reportCommittedFixture(t)
	readiness := mustReportFailure(t, domain.FailureProviderUnavailable, "current evidence is stale")
	raw := errors.New("raw excerpt failure")
	cancelled := context.Canceled
	configuration := mustReportFailure(t, domain.FailureConfiguration, "excerpt configuration is invalid")
	unknownReadiness := mustReportFailure(t, domain.FailureProviderUnavailable, "unexpected readiness reason")
	cases := []struct {
		name    string
		sibling error
	}{
		{name: "raw artifact fallback", sibling: raw},
		{name: "cancellation", sibling: cancelled},
		{name: "configuration", sibling: configuration},
		{name: "unknown readiness", sibling: unknownReadiness},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			for _, readinessFirst := range []bool{true, false} {
				order := "sibling-first"
				errorsToJoin := []error{test.sibling, readiness}
				if readinessFirst {
					order = "readiness-first"
					errorsToJoin = []error{readiness, test.sibling}
				}
				t.Run(order, func(t *testing.T) {
					joined := errors.Join(errorsToJoin...)
					reader := &reportReader{review: review, excerptErr: joined}

					report, err := mustReportService(t, reader).Render(context.Background(), run)
					if err == nil {
						t.Fatalf("Render() returned a report that hid %v", test.sibling)
					}
					if !errors.Is(err, test.sibling) {
						t.Fatalf("Render() error = %v, does not retain %v", err, test.sibling)
					}
					if len(report.Bytes()) != 0 {
						t.Fatalf("Render() returned report bytes for mixed error %v", test.sibling)
					}
					if reader.readCalls != 1 || reader.excerptCalls != 1 {
						t.Fatalf("reader calls = read %d, excerpt %d; want one of each", reader.readCalls, reader.excerptCalls)
					}
				})
			}
		})
	}
}

func TestRenderPropagatesFatalTypedExcerptFailures(t *testing.T) {
	run, review := reportCommittedFixture(t)
	for _, class := range []domain.FailureClass{
		domain.FailureArtifact,
		domain.FailureSecurityPolicy,
		domain.FailureInternal,
		domain.FailureCancelled,
	} {
		t.Run(string(class), func(t *testing.T) {
			fatal := mustReportFailure(t, class, "fatal test failure")
			reader := &reportReader{review: review, excerptErr: fatal}
			_, err := mustReportService(t, reader).Render(context.Background(), run)
			if !errors.Is(err, fatal) {
				t.Fatalf("Render() error = %v, want propagated %v", err, fatal)
			}
			if reader.readCalls != 1 || reader.excerptCalls != 1 {
				t.Fatalf("reader calls = read %d, excerpt %d; want one injected read and one excerpt request", reader.readCalls, reader.excerptCalls)
			}
		})
	}
}

func TestRenderPreservesExcerptFailureOverConcurrentCancellation(t *testing.T) {
	run, review := reportCommittedFixture(t)
	for _, class := range []domain.FailureClass{
		domain.FailureInternal,
		domain.FailureArtifact,
		domain.FailureSecurityPolicy,
	} {
		t.Run(string(class), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			reader := &reportReader{
				review:       review,
				excerptErr:   mustReportFailure(t, class, "excerpt failed"),
				afterExcerpt: cancel,
			}
			_, err := mustReportService(t, reader).Render(ctx, run)
			var failure *domain.Failure
			if !errors.As(err, &failure) || failure.Class() != class {
				t.Fatalf("failure = %#v, want %q", failure, class)
			}
		})
	}
}

func TestReportFailureReductionUsesOperationalPrecedenceInBothJoinOrders(t *testing.T) {
	classes := []domain.FailureClass{
		domain.FailureInternal,
		domain.FailureSecurityPolicy,
		domain.FailureArtifact,
		domain.FailureCancelled,
		domain.FailureConfiguration,
		domain.FailureProviderUnavailable,
		domain.FailureTimeout,
		domain.FailureAuthentication,
		domain.FailureQuota,
		domain.FailureRateLimit,
		domain.FailureInvalidOutput,
	}
	for firstIndex, first := range classes {
		for _, second := range classes[firstIndex+1:] {
			firstRank := coreapp.FailurePrecedence(first)
			secondRank := coreapp.FailurePrecedence(second)
			if firstRank == secondRank {
				continue
			}
			wantRank := max(firstRank, secondRank)
			for _, failures := range [][]error{
				{mustReportFailure(t, first, "first failure"), mustReportFailure(t, second, "second failure")},
				{mustReportFailure(t, second, "second failure"), mustReportFailure(t, first, "first failure")},
			} {
				selection := reduceReportFailure(errors.Join(failures...))
				if selection.rank != wantRank {
					t.Errorf("reduced rank for %q/%q = %d, want %d", first, second, selection.rank, wantRank)
				}
			}
		}
	}
}

func TestRenderPropagatesUnknownProviderUnavailableReason(t *testing.T) {
	run, review := reportCommittedFixture(t)
	reader := &reportReader{
		review:     review,
		excerptErr: mustReportFailure(t, domain.FailureProviderUnavailable, "unexpected readiness reason"),
	}
	_, err := mustReportService(t, reader).Render(context.Background(), run)
	var failure *domain.Failure
	if !errors.As(err, &failure) ||
		failure.Class() != domain.FailureProviderUnavailable ||
		failure.Reason() != "unexpected readiness reason" {
		t.Fatalf("unknown readiness failure = %#v", failure)
	}
}

func TestRenderPropagatesCommittedReadFailureWithoutExcerpt(t *testing.T) {
	run, review := reportCommittedFixture(t)
	fatal := mustReportFailure(t, domain.FailureArtifact, "committed review is unavailable")
	reader := &reportReader{review: review, readErr: fatal}
	_, err := mustReportService(t, reader).Render(context.Background(), run)
	if !errors.Is(err, fatal) {
		t.Fatalf("Render() error = %v, want propagated %v", err, fatal)
	}
	if reader.readCalls != 1 || reader.excerptCalls != 0 {
		t.Fatalf("reader calls = read %d, excerpt %d; want one injected committed read and no excerpt", reader.readCalls, reader.excerptCalls)
	}
}
func TestDecodeReportFinalRequiresStructuredExtractionStatusAxis(t *testing.T) {
	t.Parallel()
	_, review := reportCommittedFixture(t)
	final, err := decodeReportFinal(review.FinalBytes())
	if err != nil {
		t.Fatalf("decodeReportFinal() error = %v", err)
	}
	if final.StructuredExtractionStatus != string(domain.StructuredExtractionStructured) ||
		review.StructuredExtractionStatus() != domain.StructuredExtractionStructured {
		t.Fatalf("structured_extraction_status = final %q view %q, want structured",
			final.StructuredExtractionStatus, review.StructuredExtractionStatus())
	}
	if err := final.consistentWith(review); err != nil {
		t.Fatalf("consistentWith() error = %v", err)
	}
	final.StructuredExtractionStatus = string(domain.StructuredExtractionMixed)
	if err := final.consistentWith(review); err == nil {
		t.Fatal("consistentWith() accepted structured_extraction_status mismatch")
	}
	omitted, err := decodeReportFinal([]byte(replaceReportFixtureString(t, string(review.FinalBytes()),
		`"structured_extraction_status":"structured",`,
		``,
	)))
	if err != nil {
		t.Fatalf("decodeReportFinal() error = %v", err)
	}
	if omitted.StructuredExtractionStatus != "" {
		t.Fatalf("omitted SES decoded as %q", omitted.StructuredExtractionStatus)
	}
	if err := omitted.consistentWith(review); err == nil {
		t.Fatal("consistentWith() accepted omitted structured_extraction_status")
	}
}

func TestRenderMarkdownRejectsFinalViewMismatchesBeforeExcerptAccess(t *testing.T) {
	t.Parallel()

	run, review := reportCommittedFixture(t)
	cases := []struct {
		name   string
		mutate func(*reportFinalDTO)
	}{
		{
			name: "target identity",
			mutate: func(value *reportFinalDTO) {
				value.Target.ContentSHA256 = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
			},
		},
		{
			name: "structured extraction status",
			mutate: func(value *reportFinalDTO) {
				value.StructuredExtractionStatus = string(domain.StructuredExtractionReportsOnly)
			},
		},
		{
			name: "role binding",
			mutate: func(value *reportFinalDTO) {
				value.RoleOutcomes[0].ProviderInstance = reportString("other-provider")
			},
		},
		{
			name: "evidence identity",
			mutate: func(value *reportFinalDTO) {
				value.Findings[0].Evidence[0].Source.SourceExcerptSHA256 = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
			},
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			mismatched, err := decodeReportFinal(review.FinalBytes())
			if err != nil {
				t.Fatal(err)
			}
			test.mutate(&mismatched)
			reader := &reportReader{excerpt: []byte("line one\nline two\n")}
			_, err = renderMarkdown(context.Background(), reader, run, review, mismatched)
			assertReportArtifactFailure(t, err)
			if reader.excerptCalls != 0 {
				t.Fatalf("RenderExcerpt calls = %d, want no read for final/view mismatch", reader.excerptCalls)
			}
		})
	}
}

func reportString(value string) *string {
	return &value
}
func TestRenderValidatesProductionProvenance(t *testing.T) {
	validProduction := reportProductionProvenanceJSON()
	run, review := reportCommittedFixtureWithFinal(t, func(final string) string {
		return replaceReportFixtureString(t, final,
			`"manifest_path":"manifest.json"}`,
			`"manifest_path":"manifest.json","production":`+validProduction+`}`,
		)
	})
	reader := &reportReader{review: review, excerpt: []byte("line one\nline two")}
	rendered, err := mustReportService(t, reader).Render(context.Background(), run)
	if err != nil {
		t.Fatalf("Render() with valid production provenance error = %v", err)
	}
	if strings.Contains(string(rendered.Bytes()), "/private/bin/provider") {
		t.Fatal("rendered report exposed production executable path")
	}

	cases := []struct {
		name        string
		replacement string
		decodeFails bool
	}{
		{name: "build metadata mismatch", replacement: strings.Replace(validProduction, `"build_commit":"abc123"`, `"build_commit":"other"`, 1)},
		{name: "objective pairing mismatch", replacement: strings.Replace(validProduction, `"objective_present":true`, `"objective_present":false`, 1)},
		{name: "invalid executable digest", replacement: strings.Replace(validProduction, `"executable_sha256":"sha256:`, `"executable_sha256":"sha512:`, 1)},
		{name: "launcher pair mismatch", replacement: strings.Replace(validProduction,
			`"launcher":"","launcher_sha256":""`, `"launcher":"/private/bin/launcher","launcher_sha256":""`, 1)},
		{name: "invalid provider instance", replacement: strings.Replace(validProduction, `"instance":"alpha-1"`, `"instance":"Alpha-1"`, 1)},
		{name: "unordered providers", replacement: strings.Replace(validProduction,
			`}]}`, `},`+reportProductionProviderJSON("alpha", "alpha-0")+`]}`, 1)},
		{name: "unordered receipts", replacement: strings.Replace(validProduction,
			`"qualification_receipt_ids":["qualification:a`, `"qualification_receipt_ids":["qualification:c`, 1)},
		{name: "invalid receipt grammar", replacement: strings.Replace(validProduction,
			`"workspace_terminal_receipt":"workspace:`, `"workspace_terminal_receipt":"Workspace:`, 1)},
		{name: "unknown production field", replacement: strings.Replace(validProduction, `{"build_product"`, `{"unknown":true,"build_product"`, 1), decodeFails: true},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			_, review := reportCommittedFixture(t)
			raw := replaceReportFixtureString(t, string(review.FinalBytes()),
				`"manifest_path":"manifest.json"}`,
				`"manifest_path":"manifest.json","production":`+test.replacement+`}`,
			)
			final, err := decodeReportFinal([]byte(raw))
			if test.decodeFails {
				if err == nil {
					t.Fatal("decodeReportFinal() accepted malformed production provenance")
				}
				return
			}
			if err != nil {
				t.Fatalf("decodeReportFinal() error = %v", err)
			}
			if err := final.consistentWith(review); err == nil {
				t.Fatal("consistentWith() accepted invalid production provenance")
			}
		})
	}
}

func TestRenderAllowsAbsentProductionProvenanceForNonProductionReview(t *testing.T) {
	run, review := reportCommittedFixture(t)
	_, err := mustReportService(t, &reportReader{review: review, excerpt: []byte("line one\nline two")}).Render(context.Background(), run)
	if err != nil {
		t.Fatalf("Render() without production provenance error = %v", err)
	}
}
func TestValidateReportProductionProvenanceRejectsChildAndNoChangeRoots(t *testing.T) {
	_, review := reportCommittedFixture(t)
	raw := replaceReportFixtureString(t, string(review.FinalBytes()),
		`"manifest_path":"manifest.json"}`,
		`"manifest_path":"manifest.json","production":`+reportProductionProvenanceJSON()+`}`,
	)
	final, err := decodeReportFinal([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*reportFinalDTO)
	}{
		{name: "child", mutate: func(value *reportFinalDTO) { value.RunType = "followup" }},
		{name: "no change", mutate: func(value *reportFinalDTO) {
			value.Target.ContentSHA256 = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := final
			test.mutate(&candidate)
			if err := validateReportProductionProvenance(candidate); err == nil {
				t.Fatal("validateReportProductionProvenance() accepted prohibited production provenance")
			}
		})
	}
}

func reportProductionProvenanceJSON() string {
	const digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const receiptA = "qualification:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const receiptB = "qualification:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	const transport = "transport:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	const namespace = "namespace:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	const workspace = "workspace:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	return `{"build_product":"mulgae","build_version":"0.1.0","build_commit":"abc123","objective_sha256":"` + digest +
		`","objective_present":true,"snapshot_manifest_sha256":"` + digest +
		`","workspace_terminal_receipt":"` + workspace +
		`","providers":[{"family":"alpha","instance":"alpha-1","version":"1.0.0","executable":"/private/bin/provider","executable_sha256":"` + digest +
		`","launcher":"","launcher_sha256":"","profile_generation":"generation-1","adapter_profile":"profile-1","qualification_receipt_ids":["` + receiptA + `","` + receiptB +
		`"],"packet_transport_receipt_ids":["` + transport + `"],"namespace_terminal_receipt":"` + namespace + `"}]}`
}
func reportProductionProviderJSON(family, instance string) string {
	const digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const receipt = "qualification:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	const transport = "transport:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	const namespace = "namespace:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	return `{"family":"` + family + `","instance":"` + instance +
		`","version":"1.0.0","executable":"/private/bin/provider","executable_sha256":"` + digest +
		`","launcher":"","launcher_sha256":"","profile_generation":"generation-1","adapter_profile":"profile-1","qualification_receipt_ids":["` + receipt +
		`"],"packet_transport_receipt_ids":["` + transport + `"],"namespace_terminal_receipt":"` + namespace + `"}`
}
func TestRenderRejectsInvalidProvenanceReferences(t *testing.T) {
	testCases := []struct {
		name        string
		current     string
		replacement string
	}{
		{
			name:        "manifest mismatch",
			current:     `"manifest_path":"manifest.json"`,
			replacement: `"manifest_path":"other-manifest.json"`,
		},
		{
			name:        "aggregation traversal",
			current:     `"aggregation_path":"aggregation.json"`,
			replacement: `"aggregation_path":"../aggregation.json"`,
		},
		{
			name:        "final validation mismatch",
			current:     `"final_validation_path":"validation/final-validation.json"`,
			replacement: `"final_validation_path":"validation/other.json"`,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			run, review := reportCommittedFixtureWithFinal(t, func(final string) string {
				return replaceReportFixtureString(t, final, testCase.current, testCase.replacement)
			})
			reader := &reportReader{review: review, excerpt: []byte("line one\nline two")}

			_, err := mustReportService(t, reader).Render(context.Background(), run)
			assertReportArtifactFailure(t, err)
			if reader.excerptCalls != 0 {
				t.Fatalf("RenderExcerpt calls = %d, want no read for invalid provenance", reader.excerptCalls)
			}
		})
	}
}

func TestRenderRejectsExcerptThatDoesNotMatchCurrentIdentity(t *testing.T) {
	run, review := reportCommittedFixture(t)
	reader := &reportReader{review: review, excerpt: []byte("different excerpt\n")}

	_, err := mustReportService(t, reader).Render(context.Background(), run)
	assertReportArtifactFailure(t, err)
	if reader.excerptCalls != 1 {
		t.Fatalf("RenderExcerpt calls = %d, want one read", reader.excerptCalls)
	}
}
func TestRenderMarkdownRejectsWrongCurrentExcerptDigest(t *testing.T) {
	run, review := reportCommittedFixture(t)
	final, err := decodeReportFinal(review.FinalBytes())
	if err != nil {
		t.Fatal(err)
	}
	final.Findings[0].Evidence[0].Current.CurrentExcerptSHA256 = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"

	reader := &reportReader{excerpt: []byte("line one\nline two")}
	_, err = renderMarkdown(context.Background(), reader, run, review, final)
	assertReportArtifactFailure(t, err)
	if reader.excerptCalls != 0 {
		t.Fatalf("RenderExcerpt calls = %d, want no read for invalid current excerpt digest", reader.excerptCalls)
	}
}
func TestRenderPreservesExactVerifiedExcerptBytes(t *testing.T) {
	t.Parallel()

	defaultExcerpt := []byte("line one\nline two")
	for _, test := range []struct {
		name    string
		excerpt []byte
	}{
		{name: "CRLF", excerpt: []byte("line one\r\nline two\r\n")},
		{name: "no final LF", excerpt: []byte("line one\nline two")},
	} {
		t.Run(test.name, func(t *testing.T) {
			excerptDigest := reportCurrentExcerptDigest(t, "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "worktree", "internal/example.go", 1, 2, test.excerpt)
			run, review := reportCommittedFixtureWithFinal(t, func(final string) string {
				const prefix = `"current_excerpt_sha256":"`
				start := strings.Index(final, prefix)
				if start < 0 {
					t.Fatal("fixture has no current excerpt digest")
				}
				valueStart := start + len(prefix)
				valueEnd := strings.IndexByte(final[valueStart:], '"')
				if valueEnd < 0 {
					t.Fatal("fixture current excerpt digest is unterminated")
				}
				final = final[:valueStart] + excerptDigest + final[valueStart+valueEnd:]
				if bytes.Equal(test.excerpt, defaultExcerpt) {
					return final
				}
				return replaceReportFixtureString(
					t,
					final,
					fmt.Sprintf(`"quote":%q`, string(defaultExcerpt)),
					fmt.Sprintf(`"quote":%q`, string(test.excerpt)),
				)
			})
			reader := &reportReader{review: review, excerpt: test.excerpt}
			report, err := mustReportService(t, reader).Render(context.Background(), run)
			if err != nil {
				t.Fatalf("Render() error = %v", err)
			}
			output := string(report.Bytes())
			encoded := base64.StdEncoding.EncodeToString(test.excerpt)
			if !strings.Contains(output, "Verified excerpt (base64, exact bytes):\n```base64\n"+encoded+"\n```") {
				t.Fatalf("rendered report did not preserve an exact encoded excerpt:\n%s", output)
			}
			if strings.Contains(output, "\r") {
				t.Fatalf("rendered report normalized or emitted CR excerpt bytes:\n%s", output)
			}
		})
	}
}

func TestRenderSafelyBoundsProviderMarkdownAndHTML(t *testing.T) {
	title := "<script>alert(1)</script> ``` [run](javascript:alert(1))"
	description := "<img src=x onerror=alert(1)> ``` **bold**"
	recommendation := "<a href=\"javascript:alert(1)\">follow</a> ```"
	// Provider instances are grammar-constrained by committed role-report
	// authority; fence finding prose that may still carry Markdown/HTML.
	run, review := reportCommittedFixtureWithMutations(
		t,
		func(final string) string {
			final = replaceReportFixtureString(t, final, `"title":"title"`, fmt.Sprintf(`"title":%q`, title))
			final = replaceReportFixtureString(t, final, `"description":"description"`, fmt.Sprintf(`"description":%q`, description))
			return replaceReportFixtureString(t, final, `"recommendation":"recommendation"`, fmt.Sprintf(`"recommendation":%q`, recommendation))
		},
		nil,
	)
	reader := &reportReader{review: review, excerpt: []byte("line one\nline two")}

	report, err := mustReportService(t, reader).Render(context.Background(), run)
	if err != nil {
		t.Fatalf("Render() error = %v", err)
	}
	output := string(report.Bytes())

	for _, expected := range []string{
		"## ````F001 — " + title + "````",
		"````text\n" + description + "\n````",
		"````text\n" + recommendation + "\n````",
		"**Provider instance:** `logic-provider`",
	} {
		if !strings.Contains(output, expected) {
			t.Errorf("rendered report does not safely delimit %q", expected)
		}
	}
	if strings.Contains(output, "## F001 — "+title) || strings.Contains(output, "  > "+description) {
		t.Fatalf("provider Markdown was rendered outside a safe code boundary:\n%s", output)
	}
}

func TestRenderRendersSkippedRoleProvenanceAsAbsent(t *testing.T) {
	const completed = `{"role":"maintainability","required":false,"outcome":"failed","attempt_id":"a_019f596a-d0ad-77c2-8b68-0bd73e911b2e","provider_instance":"maintainability-fallback","selected_via":"fallback","valid_finding_ids":[],"failure_reason":"provider_unavailable","limitations":["optional role did not complete"]}`
	const skipped = `{"role":"maintainability","required":false,"outcome":"skipped","attempt_id":null,"provider_instance":null,"selected_via":null,"valid_finding_ids":[],"failure_reason":null,"limitations":["optional role did not complete"]}`
	const maintainabilityAttempt = `,{"attempt_id":"a_019f596a-d0ad-77c2-8b68-0bd73e911b2e","role":"maintainability","provider_instance":"maintainability-fallback","selected_as":"fallback","state":"failed","parse_state":"valid","validation_state":"valid","path":"attempts/a_019f596a-d0ad-77c2-8b68-0bd73e911b2e/status.json","invocation_count":1}`
	const maintainabilityPrimaryAttempt = `,{"attempt_id":"a_019f596a-d0ae-7c12-8b68-0bd73e911b2e","role":"maintainability","provider_instance":"maintainability-primary","selected_as":"primary","state":"failed","parse_state":"valid","validation_state":"valid","path":"attempts/a_019f596a-d0ae-7c12-8b68-0bd73e911b2e/status.json","invocation_count":1}`
	const maintainabilityPrimaryFailure = `{"class":"provider_unavailable","stage":"review","reason_code":"provider_unavailable","attempt_id":"a_019f596a-d0ae-7c12-8b68-0bd73e911b2e"}`
	const maintainabilityFailure = `{"class":"provider_unavailable","stage":"review","reason_code":"provider_unavailable","attempt_id":"a_019f596a-d0ad-77c2-8b68-0bd73e911b2e"}`
	run, review := reportCommittedFixtureWithMutations(
		t,
		func(final string) string {
			return replaceReportFixtureString(t, final, completed, skipped)
		},
		func(manifest string) string {
			withoutFallback := replaceReportFixtureString(t, manifest, maintainabilityAttempt, "")
			withoutPrimary := replaceReportFixtureString(t, withoutFallback, maintainabilityPrimaryAttempt, "")
			withoutFallbackFailure := replaceReportFixtureString(t, withoutPrimary, maintainabilityFailure, "")
			return replaceReportFixtureString(t, withoutFallbackFailure, maintainabilityPrimaryFailure+",", "")
		},
	)
	reader := &reportReader{review: review, excerpt: []byte("line one\nline two")}

	report, err := mustReportService(t, reader).Render(context.Background(), run)
	if err != nil {
		t.Fatalf("Render() error = %v", err)
	}
	output := string(report.Bytes())
	for _, expected := range []string{
		"**Role provider:** `maintainability: absent`",
		"**Role attempt:** `maintainability: absent`",
	} {
		if !strings.Contains(output, expected) {
			t.Errorf("rendered report does not preserve skipped-role absence %q", expected)
		}
	}
}

// TestRenderReportsProviderIssuesForFailedRoles proves the report tells the
// operator what to do about a role that produced no review: which provider it
// ran on, why it stopped, and the command to run it again. Mulgae no
// longer picks a replacement provider, so this section is the whole recovery
// path and must never silently go missing.
func TestRenderReportsProviderIssuesForFailedRoles(t *testing.T) {
	run, review := reportCommittedFixture(t)
	reader := &reportReader{review: review, excerpt: []byte("line one\nline two")}

	report, err := mustReportService(t, reader).Render(context.Background(), run)
	if err != nil {
		t.Fatalf("Render() error = %v", err)
	}
	output := string(report.Bytes())

	failed := make([]query.Role, 0, len(review.Roles()))
	for _, role := range review.Roles() {
		if role.Outcome() == "failed" {
			failed = append(failed, role)
		}
	}
	if len(failed) == 0 {
		t.Fatal("fixture has no failed role to report on")
	}
	if !strings.Contains(output, "Provider issues") {
		t.Fatalf("report omitted the provider issues section:\n%s", output)
	}
	for _, role := range failed {
		reason, ok := role.FailureReason()
		if !ok {
			t.Fatalf("failed role %q carries no failure reason", role.Name())
		}
		if !strings.Contains(output, reason) {
			t.Errorf("report omitted the failure reason %q for role %q", reason, role.Name())
		}
		provider, present := role.ProviderInstance()
		if !present {
			t.Fatalf("failed role %q carries no provider instance", role.Name())
		}
		want := "mulgae rerun --run " + review.RunID().String() + " --role " + string(role.Name()) + " --provider " + provider
		if !strings.Contains(output, want) {
			t.Errorf("report omitted the rerun command %q:\n%s", want, output)
		}
		// A rerun alone cannot recover a provider that must be fixed first, so
		// the report must say which case this is rather than leaving the
		// operator to infer it from the reason code.
		wantRemediation := providerIssueRemediation(reason)
		if !strings.Contains(output, wantRemediation) {
			t.Errorf("report omitted the remediation %q for role %q:\n%s", wantRemediation, role.Name(), output)
		}
		if !strings.Contains(output, provider) {
			t.Errorf("report omitted the failed role's provider %q", provider)
		}
	}
	// Roles that produced a review must never be offered a rerun command.
	for _, role := range review.Roles() {
		if role.Outcome() == "failed" {
			continue
		}
		unwanted := "--role " + string(role.Name()) + " --provider"
		if strings.Contains(output, unwanted) {
			t.Errorf("report offered a rerun command for the successful role %q", role.Name())
		}
	}
	if strings.Contains(output, "<family>") {
		t.Fatalf("report retained provider-family placeholder:\n%s", output)
	}
}

func assertReportArtifactFailure(t *testing.T, err error) {
	t.Helper()
	var failure *domain.Failure
	if !errors.As(err, &failure) || failure.Class() != domain.FailureArtifact {
		t.Fatalf("Render() error = %v, want artifact failure", err)
	}
}

func replaceReportFixtureString(t *testing.T, value, current, replacement string) string {
	t.Helper()
	replaced := strings.Replace(value, current, replacement, 1)
	if replaced == value {
		t.Fatalf("fixture does not contain %q", current)
	}
	return replaced
}

func duplicateReportFindingEvidence(t *testing.T, value string) string {
	t.Helper()
	const opening = `"evidence":[`
	const closing = `],"recommendation":`
	start := strings.Index(value, opening)
	if start < 0 {
		t.Fatal("fixture is missing finding evidence")
	}
	start += len(opening)
	end := strings.Index(value[start:], closing)
	if end < 0 {
		t.Fatal("fixture evidence has no recommendation boundary")
	}
	end += start
	return value[:end] + "," + value[start:end] + value[end:]
}

func assertReportSectionsInOrder(t *testing.T, output string) {
	t.Helper()
	sections := []string{
		"# Run summary",
		"# Target and lineage",
		"# Outcome axes",
		"# Role coverage",
		"# Validation and repair",
		"# Findings by severity",
		"# Limitations/degradation",
		"# Artifact references",
		"# Provider/runtime provenance",
		"# CI interpretation",
	}
	previous := -1
	for _, section := range sections {
		index := strings.Index(output, section)
		if index < 0 {
			t.Errorf("rendered report is missing section %q", section)
			continue
		}
		if index <= previous {
			t.Errorf("section %q is out of order", section)
		}
		previous = index
	}
}

type reportReader struct {
	review         query.CommittedReview
	readErr        error
	excerpt        []byte
	excerptErr     error
	readCalls      int
	excerptCalls   int
	excerptTargets []string
	excerptIndexes []int
	afterExcerpt   func()
}

func (reader *reportReader) ReadCommitted(context.Context, ports.PublicationRun) (query.CommittedReview, error) {
	reader.readCalls++
	return reader.review, reader.readErr
}

func (reader *reportReader) RenderExcerpt(_ context.Context, _ ports.PublicationRun, _ string, targetSHA256 string) ([]byte, error) {
	reader.excerptCalls++
	reader.excerptTargets = append(reader.excerptTargets, targetSHA256)
	if reader.afterExcerpt != nil {
		reader.afterExcerpt()
	}
	return append([]byte(nil), reader.excerpt...), reader.excerptErr
}

func (reader *reportReader) RenderExcerptAt(
	ctx context.Context,
	run ports.PublicationRun,
	findingID string,
	targetSHA256 string,
	evidenceIndex int,
) ([]byte, error) {
	reader.excerptIndexes = append(reader.excerptIndexes, evidenceIndex)
	return reader.RenderExcerpt(ctx, run, findingID, targetSHA256)
}

func mustReportService(t *testing.T, reader CommittedReader) *Service {
	t.Helper()
	service, err := NewService(reader)
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func mustReportFailure(t *testing.T, class domain.FailureClass, reason string) *domain.Failure {
	t.Helper()
	failure, err := domain.NewFailure("report-test", class, reason, nil)
	if err != nil {
		t.Fatal(err)
	}
	return failure
}

func reportCommittedFixture(t *testing.T) (ports.PublicationRun, query.CommittedReview) {
	return reportCommittedFixtureWithFinal(t, nil)
}

func reportCommittedFixtureWithFinal(
	t *testing.T,
	mutate func(string) string,
) (ports.PublicationRun, query.CommittedReview) {
	return reportCommittedFixtureWithMutations(t, mutate, nil)
}

func reportCommittedFixtureWithMutations(
	t *testing.T,
	finalMutate func(string) string,
	manifestMutate func(string) string,
) (ports.PublicationRun, query.CommittedReview) {
	t.Helper()
	root, err := ports.NewAnchoredRoot("/private/report-test")
	if err != nil {
		t.Fatal(err)
	}
	sessionID, err := domain.ParseSessionID("s_019f596a-cf80-7c67-b265-f37053d51ccf")
	if err != nil {
		t.Fatal(err)
	}
	runID, err := domain.ParseRunID("r_019f596a-cfe4-7c9c-b82e-7149158243ba")
	if err != nil {
		t.Fatal(err)
	}
	reviewID, err := domain.ParseReviewID("019f596a-d174-7321-b920-c2d312c82cc2")
	if err != nil {
		t.Fatal(err)
	}
	run, err := ports.NewPublicationRun(root, sessionID, runID)
	if err != nil {
		t.Fatal(err)
	}

	prefix := sessionID.String() + "/" + runID.String()
	finalPath := reportPath(t, prefix+"/review_"+reviewID.String()+".json")
	manifestPath := reportPath(t, prefix+"/manifest.json")
	edgePath := reportPath(t, prefix+"/lineage/edge.json")
	epochPath := reportPath(t, prefix+"/epochs/epoch_000001.json")
	edge := reportArtifact(t, edgePath, []byte(`{"schema_version":"mulgae-lineage-edge.v1"}`))
	epochRecord := reportArtifact(t, epochPath, []byte(`{"schema_version":"mulgae-publication-epoch.v1"}`))
	epoch, err := ports.NewPublicationEpoch(1, epochRecord)
	if err != nil {
		t.Fatal(err)
	}

	excerptBytes := []byte("line one\nline two")
	currentExcerptSHA256 := reportCurrentExcerptDigest(t, "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "worktree", "internal/example.go", 1, 2, excerptBytes)
	finalBytes := []byte(fmt.Sprintf(`{
		"schema_version":"mulgae-review-artifact.v1","session_id":%q,"run_id":%q,"review_id":%q,"run_type":"review","created_at":"2026-07-13T03:00:00Z",
		"mulgae":{"version":"0.1.0","commit":"abc123"},
		"immutable_lineage":{"parent_run_id":null,"source_run_id":null,"source_review_id":null,"source_finding_ref":null,"replay_mode":null,"lineage_edge_path":%q,"lineage_edge_sha256":%q},
		"target":{"content_sha256":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","manifest_path":"target/target-manifest.json","base_oid":"1111111111111111111111111111111111111111","head_oid":"2222222222222222222222222222222222222222"},
		"validation":{"status":"repaired_valid","schema_validation":"passed","semantic_validation":"passed","evidence_validation":"passed_with_warnings"},
		"content_verdict":"request_changes","coverage_status":"incomplete","structured_extraction_status":"structured","publication_status":"committed","ci_decision":"fail","ci_reason_codes":["request_changes_threshold","required_role_incomplete"],
		"severity_threshold":{"request_changes_at_or_above":"high","policy_source":"project_local"},
		"role_outcomes":[
			{"role":"logic","required":true,"outcome":"completed","attempt_id":"a_019f596a-d048-79e7-b2b7-59822f012273","provider_instance":"logic-provider","selected_via":"primary","valid_finding_ids":["F001"],"failure_reason":null,"limitations":["logic evidence was restricted to changed files"]},
			{"role":"security","required":true,"outcome":"completed","attempt_id":"a_019f596a-d0ac-7c12-8b68-0bd73e911b2e","provider_instance":"security-provider","selected_via":"primary","valid_finding_ids":[],"failure_reason":null,"limitations":[]},
			{"role":"maintainability","required":false,"outcome":"failed","attempt_id":"a_019f596a-d0ad-77c2-8b68-0bd73e911b2e","provider_instance":"maintainability-fallback","selected_via":"fallback","valid_finding_ids":[],"failure_reason":"provider_unavailable","limitations":["optional role did not complete"]}
		],
		"findings":[{"id":"F001","fingerprint":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","role":"logic","provider_instance":"logic-provider","severity":"high","title":"title","description":"description","evidence":[{"source":{"session_id":%q,"run_id":%q,"review_id":%q,"finding_id":"F001","source_target_sha256":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","source_excerpt_sha256":%q},"current":{"target_sha256":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","side":"worktree","path":"internal/example.go","line_start":1,"line_end":2,"quote":"line one\nline two","current_excerpt_sha256":%q,"verification":"verified"}}],"recommendation":"recommendation","confidence":"high","lifecycle":"open"}],
		"limitations":["provider telemetry was unavailable"],"provenance":{"aggregation_path":"aggregation.json","final_validation_path":"validation/final-validation.json","manifest_path":"manifest.json"}
	}`, sessionID.String(), runID.String(), reviewID.String(), edgePath.String(), edge.SHA256(), sessionID.String(), runID.String(), reviewID.String(), reportSHA([]byte("historical source excerpt")), currentExcerptSHA256))
	if finalMutate != nil {
		finalBytes = []byte(finalMutate(string(finalBytes)))
	}
	finalIdentity, err := ports.NewFinalReviewIdentity(reviewID, finalPath, reportSHA(finalBytes))
	if err != nil {
		t.Fatal(err)
	}
	final, err := ports.NewFinalReviewArtifact(finalIdentity, finalBytes)
	if err != nil {
		t.Fatal(err)
	}

	manifestBytes := []byte(fmt.Sprintf(`{
		"schema_version":"mulgae-run-manifest.v1","session_id":%q,"run_id":%q,"run_type":"review","state":"failed","sealed":true,"created_at":"2026-07-13T03:00:00Z","started_at":null,"completed_at":"2026-07-13T03:01:00Z","mulgae_version":"0.1.0",
		"immutable_lineage":{"parent_run_id":null,"source_run_id":null,"source_review_id":null,"source_finding_ref":null,"replay_mode":null,"lineage_edge_path":%q,"lineage_edge_sha256":%q},
		"target":{"manifest_path":"target/target-manifest.json","content_sha256":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"selected_roles":["logic","security","maintainability"],"required_roles":["logic","security"],"attempts":[{"attempt_id":"a_019f596a-d048-79e7-b2b7-59822f012273","role":"logic","provider_instance":"logic-provider","selected_as":"primary","state":"succeeded","parse_state":"valid","validation_state":"valid","path":"attempts/a_019f596a-d048-79e7-b2b7-59822f012273/status.json","invocation_count":1},{"attempt_id":"a_019f596a-d0ac-7c12-8b68-0bd73e911b2e","role":"security","provider_instance":"security-provider","selected_as":"primary","state":"succeeded","parse_state":"valid","validation_state":"valid","path":"attempts/a_019f596a-d0ac-7c12-8b68-0bd73e911b2e/status.json","invocation_count":1},{"attempt_id":"a_019f596a-d0ae-7c12-8b68-0bd73e911b2e","role":"maintainability","provider_instance":"maintainability-primary","selected_as":"primary","state":"failed","parse_state":"valid","validation_state":"valid","path":"attempts/a_019f596a-d0ae-7c12-8b68-0bd73e911b2e/status.json","invocation_count":1},{"attempt_id":"a_019f596a-d0ad-77c2-8b68-0bd73e911b2e","role":"maintainability","provider_instance":"maintainability-fallback","selected_as":"fallback","state":"failed","parse_state":"valid","validation_state":"valid","path":"attempts/a_019f596a-d0ad-77c2-8b68-0bd73e911b2e/status.json","invocation_count":1}],
		"content_verdict":"request_changes","coverage_status":"incomplete","structured_extraction_status":"structured","publication_status":"committed","ci_decision":"fail","ci_reason_codes":["request_changes_threshold","required_role_incomplete"],"persisted_journal_state":"completed","durable_observation_class":"P2_COMMITTED","derived_publication_status":"committed","publication_authority":"P2",
		"recovery_journal":{"expected_staged":null,"expected_final":{"path":%q,"sha256":%q},"validated_candidate_sha256":%q},
		"composite_identity":{"manifest":{"path":%q},"lineage_edge":{"path":%q,"sha256":%q},"epoch":{"path":%q}},"recovery_action":"reconstruct_completed_status",
		"final_review":{"review_id":%q,"path":%q,"sha256":%q},
		"role_reports":[
			{"role":"logic","path":"role-reports/logic.md","sha256":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","byte_length":12,"provider_instance":"logic-provider","attempt_id":"a_019f596a-d048-79e7-b2b7-59822f012273","content_type":"text/markdown"},
			{"role":"security","path":"role-reports/security.md","sha256":"sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","byte_length":16,"provider_instance":"security-provider","attempt_id":"a_019f596a-d0ac-7c12-8b68-0bd73e911b2e","content_type":"text/markdown"}
		],
		"failures":[{"class":"provider_unavailable","stage":"review","reason_code":"provider_unavailable","attempt_id":"a_019f596a-d0ae-7c12-8b68-0bd73e911b2e"},{"class":"provider_unavailable","stage":"review","reason_code":"provider_unavailable","attempt_id":"a_019f596a-d0ad-77c2-8b68-0bd73e911b2e"}],"warnings":[],"exit_code":4
	}`, sessionID.String(), runID.String(), edgePath.String(), edge.SHA256(), finalPath.String(), finalIdentity.SHA256(), finalIdentity.SHA256(), manifestPath.String(), edgePath.String(), edge.SHA256(), epochPath.String(), reviewID.String(), finalPath.String(), finalIdentity.SHA256()))
	if manifestMutate != nil {
		manifestBytes = []byte(manifestMutate(string(manifestBytes)))
	}
	manifest := reportArtifact(t, manifestPath, manifestBytes)
	snapshot, err := ports.NewCommittedPublicationSnapshot(final, manifest, edge, epoch)
	if err != nil {
		t.Fatal(err)
	}
	exit := domain.ExitIncompleteCoverage
	journalPath := reportPath(t, prefix+"/publication/journal.json")
	journal, err := ports.NewMissingMutablePublicationDocument(ports.MutablePublicationJournal, journalPath)
	if err != nil {
		t.Fatal(err)
	}
	statusPath := reportPath(t, prefix+"/status.json")
	status, err := ports.NewMissingMutablePublicationDocument(ports.MutablePublicationStatus, statusPath)
	if err != nil {
		t.Fatal(err)
	}
	material, err := ports.NewPublicationRecoveryMaterialWithCommittedSnapshot(final, journal, status, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	observation, err := ports.NewPublicationObservationWithRecovery(
		domain.JournalCompleted,
		domain.DurableObservationP2Committed,
		&exit,
		nil,
		1,
		material,
	)
	if err != nil {
		t.Fatal(err)
	}
	service, err := query.NewService(
		&reportQueryStore{observation: observation, snapshot: snapshot},
		reportValidator{},
		&reportTargetReader{availability: evidence.ImmutableTargetAvailable, bytes: []byte("line one\nline two")},
		1<<20,
	)
	if err != nil {
		t.Fatal(err)
	}
	review, err := service.ReadCommitted(context.Background(), run)
	if err != nil {
		t.Fatalf("%v: %v", err, errors.Unwrap(err))
	}
	return run, review
}

type reportQueryStore struct {
	observation ports.PublicationObservation
	snapshot    ports.CommittedPublicationSnapshot
}

func (store *reportQueryStore) IssueReviewID(context.Context, ports.IssueReviewIDRequest) (ports.IssuedReviewID, error) {
	return ports.IssuedReviewID{}, errors.New("not implemented")
}

func (store *reportQueryStore) ResolveRun(context.Context, ports.ResolvePublicationRunRequest) (ports.PublicationRun, error) {
	return ports.PublicationRun{}, errors.New("not implemented")
}

func (store *reportQueryStore) ObserveRun(context.Context, ports.ObserveRunRequest) (ports.PublicationObservation, error) {
	return store.observation, nil
}

func (store *reportQueryStore) PersistValidatedCandidate(context.Context, ports.PersistValidatedCandidateRequest) (ports.PersistValidatedCandidateResult, error) {
	return ports.PersistValidatedCandidateResult{}, errors.New("not implemented")
}

func (store *reportQueryStore) PersistAuxiliaryArtifact(context.Context, ports.PersistAuxiliaryArtifactRequest) (ports.PersistAuxiliaryArtifactResult, error) {
	return ports.PersistAuxiliaryArtifactResult{}, errors.New("not implemented")
}

func (store *reportQueryStore) ReadAuxiliaryArtifact(context.Context, ports.ReadAuxiliaryArtifactRequest) (ports.ImmutablePublicationArtifact, error) {
	return ports.ImmutablePublicationArtifact{}, errors.New("not implemented")
}

func (store *reportQueryStore) PrepareComposite(context.Context, ports.PrepareCompositeRequest) (ports.PreparedComposite, error) {
	return ports.PreparedComposite{}, errors.New("not implemented")
}

func (store *reportQueryStore) StageFinal(context.Context, ports.StageFinalRequest) (ports.StageFinalResult, error) {
	return ports.StageFinalResult{}, errors.New("not implemented")
}

func (store *reportQueryStore) AdoptStagedFinal(context.Context, ports.AdoptStagedFinalRequest) (ports.StageFinalResult, error) {
	return ports.StageFinalResult{}, errors.New("not implemented")
}

func (store *reportQueryStore) InstallFinal(context.Context, ports.InstallFinalRequest) (ports.InstallFinalResult, error) {
	return ports.InstallFinalResult{}, errors.New("not implemented")
}

func (store *reportQueryStore) ReplaceMutable(context.Context, ports.MutableReplaceRequest) (ports.MutableReplaceResult, error) {
	return ports.MutableReplaceResult{}, errors.New("not implemented")
}

func (store *reportQueryStore) CommitPreparedComposite(context.Context, ports.PreparedComposite) (ports.CompositeCommitResult, error) {
	return ports.CompositeCommitResult{}, errors.New("not implemented")
}

func (store *reportQueryStore) ReadCommittedSnapshot(context.Context, ports.ReadCommittedSnapshotRequest) (ports.CommittedPublicationSnapshot, error) {
	return store.snapshot, nil
}

func (store *reportQueryStore) WriteCorruptionDiagnostic(context.Context, ports.CorruptionDiagnosticRequest) (ports.CorruptionDiagnosticResult, error) {
	return ports.CorruptionDiagnosticResult{}, errors.New("not implemented")
}

type reportValidator struct{}

func (reportValidator) Validate(context.Context, ports.AssetID, []byte) error { return nil }

type reportTargetReader struct {
	availability evidence.ImmutableTargetAvailability
	bytes        []byte
}

func (reader *reportTargetReader) ReadImmutableTarget(context.Context, string, evidence.Side, ports.SafeRelativePath) (evidence.ImmutableTargetAvailability, []byte, error) {
	return reader.availability, append([]byte(nil), reader.bytes...), nil
}

func reportPath(t *testing.T, value string) ports.SafeRelativePath {
	t.Helper()
	path, err := ports.NewSafeRelativePath(value)
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func reportArtifact(t *testing.T, path ports.SafeRelativePath, value []byte) ports.ImmutablePublicationArtifact {
	t.Helper()
	artifact, err := ports.NewImmutablePublicationArtifact(path, reportSHA(value), value)
	if err != nil {
		t.Fatal(err)
	}
	return artifact
}

func reportSHA(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}
func reportCurrentExcerptDigest(
	t *testing.T,
	targetSHA256 string,
	side string,
	path string,
	lineStart int,
	lineEnd int,
	excerpt []byte,
) string {
	t.Helper()
	claim, err := evidence.NewCurrentClaim(evidence.CurrentClaimInput{
		TargetSHA256: targetSHA256,
		Side:         evidence.Side(side),
		Path:         path,
		LineStart:    lineStart,
		LineEnd:      lineEnd,
		Quote:        string(excerpt),
	})
	if err != nil {
		t.Fatal(err)
	}
	digest, err := claim.ExcerptSHA256(excerpt)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

// TestProviderIssueRemediationSeparatesFixableFromRetryable proves the report
// distinguishes a provider that must be fixed from one that merely failed once.
// It reads the coordinator's closed policy, so it stays aligned with the CLI's
// failure hint instead of drifting into its own opinion.
func TestProviderIssueRemediationSeparatesFixableFromRetryable(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		reason review.AttemptCondition
		want   string
	}{
		{review.AttemptConditionLoginRequired, "fix this provider"},
		{review.AttemptConditionAuthentication, "fix this provider"},
		{review.AttemptConditionQuota, "fix this provider"},
		{review.AttemptConditionProviderUnavailable, "may succeed"},
		{review.AttemptConditionProviderTurnFailed, "may succeed"},
		{review.AttemptConditionRateLimit, "may succeed"},
		{review.AttemptConditionProviderTimeout, "may succeed"},
		{review.AttemptConditionProviderOutputMissing, "may succeed"},
		{review.AttemptConditionSemanticContradiction, "may succeed"},
		{review.AttemptConditionInternalInvariant, "not a provider failure"},
		{"not_a_condition", "unknown failure reason"},
	} {
		t.Run(string(test.reason), func(t *testing.T) {
			if got := providerIssueRemediation(string(test.reason)); !strings.Contains(got, test.want) {
				t.Fatalf("providerIssueRemediation(%q) = %q, want it to mention %q", test.reason, got, test.want)
			}
		})
	}
}
