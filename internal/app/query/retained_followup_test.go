package query

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/adapters/jsonschema"
	"github.com/irootkernel/mulgae/internal/app/validation"
	"github.com/irootkernel/mulgae/internal/builtin"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
	"github.com/irootkernel/mulgae/internal/testsupport/historical"
)

func TestHistoricalFollowupPreservesEveryResolutionAndSourceTuple(t *testing.T) {
	corpus, err := historical.Load()
	if err != nil {
		t.Fatal(err)
	}
	validator, err := jsonschema.New(context.Background(), builtin.NewCatalog())
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, c := range corpus.Cases {
		if !strings.HasPrefix(c.ID, "followup-") {
			continue
		}
		t.Run(c.ID, func(t *testing.T) {
			store, run := historicalQueryStore(t, c)
			service := mustQueryService(t, store, validator, nil)
			got, err := service.ReadCommitted(context.Background(), run)
			if err != nil {
				t.Fatal(err)
			}
			outcome, present := got.FollowupOutcome()
			if !present || string(outcome.Resolution()) != strings.TrimPrefix(c.ID, "followup-") || outcome.Rationale() != "The current target preserves the source finding." || len(outcome.Evidence()) != 1 {
				t.Fatal("stored resolution, rationale or evidence lost")
			}
			item := outcome.Evidence()[0]
			if string(item.Verification()) != "verified" {
				t.Fatal("stored current evidence lost verified status")
			}
			if item.SourceSessionID().String() != "s_019f5a09-5eec-7001-8001-000000000001" || item.SourceRunID().String() != "r_019f5a09-5eec-7002-8002-000000000002" || item.SourceReviewID().String() != "019f5a09-5eec-7009-8009-000000000009" || item.SourceFindingID() != "F001" || item.SourceTargetSHA256() != "sha256:5c7f970ed608861857c192b4980ae15da74b648be991b3250e9a0657d2b87599" || item.SourceExcerptSHA256() != "sha256:29cecbc78c021415a2f486b0e795fff51891f90328cc8581ebc5d10e0e05aef6" || item.TargetSHA256() != "sha256:29cecbc78c021415a2f486b0e795fff51891f90328cc8581ebc5d10e0e05aef6" || item.CurrentExcerptSHA256() != "sha256:98eda608f19bb2c314adba81f4a31062238c104b18b4af6517fc6cc2db0c487f" || string(item.Side()) != "head" || item.Quote() != "queueFallback(task)" || item.Path().String() != "internal/app/coordinator.go" || item.LineStart() != 1 || item.LineEnd() != 1 {
				t.Fatal("stored source/current evidence tuple changed")
			}
			if string(got.ContentVerdict()) != c.Expected.Content || string(got.CoverageStatus()) != c.Expected.Coverage || string(got.CIDecision()) != c.Expected.CI || len(got.Findings()) != c.Expected.Findings {
				t.Fatal("zero-finding resolution distinction changed")
			}
			copy := outcome.Evidence()
			copy[0] = FollowupEvidence{}
			if !reflect.DeepEqual(got.followupOutcome.evidence[0], item) {
				t.Fatal("outcome evidence aliases caller storage")
			}
		})
		seen++
	}
	if seen != 4 {
		t.Fatalf("followup resolutions=%d, want 4", seen)
	}
}

func TestRetainedFollowupValidationUsesRealSchemaAndTrustedScope(t *testing.T) {
	schema, err := jsonschema.New(context.Background(), builtin.NewCatalog())
	if err != nil {
		t.Fatal(err)
	}
	id, err := ports.ParseAssetID(validation.ProviderFollowupSchemaID)
	if err != nil {
		t.Fatal(err)
	}
	validator, err := validation.NewFollowupValidator(schema, id)
	if err != nil {
		t.Fatal(err)
	}
	session, err := domain.ParseSessionID("s_019f5a09-5eec-7001-8001-000000000001")
	if err != nil {
		t.Fatal(err)
	}
	run, err := domain.ParseRunID("r_019f5a09-5eec-7002-8002-000000000002")
	if err != nil {
		t.Fatal(err)
	}
	review, err := domain.ParseReviewID("019f5a09-5eec-7009-8009-000000000009")
	if err != nil {
		t.Fatal(err)
	}
	scope := validation.FollowupValidationScope{SessionID: session, SourceRunID: run, ReviewID: review, FindingID: "F001", SourceTargetSHA256: "sha256:" + strings.Repeat("a", 64), SourceExcerptSHA256: "sha256:" + strings.Repeat("b", 64), CurrentTargetSHA256: "sha256:" + strings.Repeat("c", 64), Role: domain.RoleLogic, ProviderInstance: "test-provider"}
	for _, resolution := range []string{"resolved", "partially_resolved", "still_open", "unclear"} {
		t.Run(resolution, func(t *testing.T) {
			raw := []byte(`{"schema_version":"mulgae-provider-followup-output.v1","summary":"Followup observation.","resolution":"` + resolution + `","rationale":"A meaningful retained observation.","evidence":[{"source":{"finding_id":"F999"},"current":{"target_sha256":"untrusted","path":"src/a.go","side":"head","line_start":1,"line_end":1,"quote":"line one\n","verification":"verified"}}],"new_findings":[],"limitations":[]}`)
			got, err := validator.Validate(context.Background(), raw, scope)
			if err != nil || string(got.Resolution()) != resolution || got.ReportsOnly() {
				t.Fatalf("real-schema followup: %v", err)
			}
			var normalized struct {
				Evidence []finalEvidenceDTO `json:"evidence"`
			}
			if err := json.Unmarshal(got.NormalizedRaw(), &normalized); err != nil {
				t.Fatal(err)
			}
			if len(normalized.Evidence) != 1 {
				t.Fatal("normalized evidence absent")
			}
			e := normalized.Evidence[0]
			if e.Source.RunID != run.String() || e.Source.ReviewID != review.String() || e.Source.FindingID != "F001" || e.Source.SourceTargetSHA256 != scope.SourceTargetSHA256 || e.Source.SourceExcerptSHA256 != scope.SourceExcerptSHA256 || e.Current.TargetSHA256 != scope.CurrentTargetSHA256 || e.Current.Verification != "claimed" {
				t.Fatal("provider claimed trusted identity or verification")
			}
		})
	}
}

func TestRetainedFollowupVerifierRejectsReboundSourceAndCurrentAuthority(t *testing.T) {
	corpus, err := historical.Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range corpus.Cases {
		if c.ID != "followup-still_open" {
			continue
		}
		files := c.Artifacts()
		prefix := c.SessionID + "/" + c.RunID + "/"
		for _, field := range []string{"source run", "source review", "source finding", "current target", "verification"} {
			t.Run(field, func(t *testing.T) {
				final, err := decodeFinalDTO(files[prefix+"review_"+c.ReviewID+".json"])
				if err != nil {
					t.Fatal(err)
				}
				manifest, err := decodeManifestDTO(files[prefix+"manifest.json"])
				if err != nil {
					t.Fatal(err)
				}
				if err := validateFollowupOutcome(final, manifest); err != nil {
					t.Fatal(err)
				}
				item := &final.FollowupOutcome.Evidence[0]
				switch field {
				case "source run":
					item.Source.RunID = c.RunID
				case "source review":
					item.Source.ReviewID = c.ReviewID
				case "source finding":
					item.Source.FindingID = "F999"
				case "current target":
					item.Current.TargetSHA256 = "sha256:" + strings.Repeat("a", 64)
				case "verification":
					item.Current.Verification = "claimed"
				}
				// Both envelopes agree, so their equality guard cannot mask the
				// retained tuple verifier being exercised directly here.
				raw, err := json.Marshal(final.FollowupOutcome)
				if err != nil {
					t.Fatal(err)
				}
				if err := json.Unmarshal(raw, &manifest.FollowupOutcome); err != nil {
					t.Fatal(err)
				}
				if err := validateFollowupOutcome(final, manifest); err == nil || err.Error() != "followup outcome evidence 0 is invalid" {
					t.Fatalf("missed intended tuple verifier: %v", err)
				}
			})
		}
		return
	}
	t.Fatal("fixed followup input absent")
}
